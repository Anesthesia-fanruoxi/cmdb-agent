package plugins

import (
	"cmdb-agent/common"
	"encoding/json"
	"fmt"
	"go.uber.org/zap"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
)

// UpdateRequest 插件配置更新请求
type UpdateRequest struct {
	Name         string                 `json:"name"`          // 插件名称（必填）
	ConfigSet    map[string]interface{} `json:"config_set"`    // 新增或修改的配置项（upsert）
	ConfigDelete []string               `json:"config_delete"` // 要删除的配置 key 列表
}

// PluginUpdateHandler 插件配置更新接口
func PluginUpdateHandler(w http.ResponseWriter, r *http.Request) {
	realClientIP := getRealClientIP(r)
	if realClientIP == "" {
		if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
			realClientIP = host
		} else {
			realClientIP = r.RemoteAddr
		}
	}

	common.Info("收到插件配置更新请求",
		zap.String("method", r.Method),
		zap.String("client_ip", realClientIP))

	if r.Method != http.MethodPut {
		common.RespondMethodNotAllowed(w, "只允许PUT请求")
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "读取请求体失败: "+err.Error())
		return
	}
	defer r.Body.Close()

	var req UpdateRequest
	if err := json.Unmarshal(body, &req); err != nil {
		common.RespondError(w, http.StatusBadRequest, "解析JSON失败: "+err.Error())
		return
	}

	if req.Name == "" {
		common.RespondError(w, http.StatusBadRequest, "插件名称不能为空")
		return
	}
	if len(req.ConfigSet) == 0 && len(req.ConfigDelete) == 0 {
		common.RespondError(w, http.StatusBadRequest, "config_set 和 config_delete 不能同时为空")
		return
	}

	record, err := GetPluginRecord(req.Name)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "查询插件记录失败: "+err.Error())
		return
	}
	if record == nil {
		common.RespondError(w, http.StatusNotFound, "插件不存在: "+req.Name)
		return
	}

	// 合并配置：在原配置基础上 upsert + delete
	newConfig := mergeConfig(record.Config, req.ConfigSet, req.ConfigDelete)

	common.Info("配置变更",
		zap.String("name", req.Name),
		zap.Any("set", maskSensitiveConfigForLog(req.ConfigSet)),
		zap.Strings("delete", req.ConfigDelete))

	var result map[string]interface{}
	switch record.Category {
	case "container":
		result, err = updateContainerConfig(record, newConfig)
	case "binary":
		result, err = updateBinaryConfig(record, newConfig)
	default:
		common.RespondError(w, http.StatusBadRequest, "不支持的插件类型: "+record.Category)
		return
	}

	if err != nil {
		common.Error("配置更新失败", zap.String("name", req.Name), zap.Error(err))
		common.RespondError(w, http.StatusInternalServerError, "配置更新失败: "+err.Error())
		return
	}

	common.RespondSuccess(w, result)
}

// mergeConfig 在原配置基础上执行 upsert 和 delete
func mergeConfig(base map[string]interface{}, set map[string]interface{}, delKeys []string) map[string]interface{} {
	result := make(map[string]interface{})

	// 复制原配置
	for k, v := range base {
		result[k] = v
	}

	// upsert
	for k, v := range set {
		result[k] = v
	}

	// delete
	for _, k := range delKeys {
		delete(result, k)
	}

	return result
}

// updateContainerConfig 更新容器配置（停止 -> 删除 -> 重建）
func updateContainerConfig(record *PluginRecord, newConfig map[string]interface{}) (map[string]interface{}, error) {
	oldContainerID := record.ContainerID

	common.Info("更新容器配置: 停止 -> 删除 -> 重建", zap.String("name", record.Name))

	if _, err := operateContainer(record, "stop"); err != nil {
		common.Warn("停止旧容器失败，继续执行", zap.Error(err))
	}

	if err := uninstallContainer(record); err != nil {
		common.Warn("删除旧容器失败，继续执行", zap.Error(err))
	}

	containerID, err := startContainerService(record.Name, record.Image, record.Port, "", newConfig, record.Parameters)
	if err != nil {
		// 回滚
		if rollbackID, rollbackErr := startContainerService(record.Name, record.Image, record.Port, "", record.Config, record.Parameters); rollbackErr == nil {
			record.ContainerID = rollbackID
			AddPluginRecord(record)
			common.Info("已回滚到旧配置")
		}
		return nil, fmt.Errorf("重建容器失败: %v", err)
	}

	record.Config = newConfig
	record.ContainerID = containerID
	if err := AddPluginRecord(record); err != nil {
		common.Warn("更新插件记录失败", zap.Error(err))
	}

	common.Info("容器配置更新完成",
		zap.String("name", record.Name),
		zap.String("old_container_id", oldContainerID[:12]),
		zap.String("new_container_id", containerID[:12]))

	return map[string]interface{}{
		"name":         record.Name,
		"version":      record.Version,
		"container_id": containerID,
		"config":       maskSensitiveConfigForLog(newConfig),
		"status":       "running",
		"message":      "配置更新成功，容器已重启",
	}, nil
}

// updateBinaryConfig 更新二进制配置（更新记录 -> 清空日志 -> 重启服务）
func updateBinaryConfig(record *PluginRecord, newConfig map[string]interface{}) (map[string]interface{}, error) {
	common.Info("更新二进制配置: 更新记录 -> 清空日志 -> 重启", zap.String("name", record.Name))

	record.Config = newConfig
	if err := AddPluginRecord(record); err != nil {
		return nil, fmt.Errorf("更新插件记录失败: %v", err)
	}

	// 清空日志
	pluginDir := filepath.Dir(record.BinaryPath)
	logFile := filepath.Join(pluginDir, record.Name+".log")
	if err := os.Truncate(logFile, 0); err != nil {
		common.Warn("清空日志文件失败", zap.String("log_file", logFile), zap.Error(err))
	}

	result, err := operateBinary(record, "restart")
	if err != nil {
		return nil, fmt.Errorf("重启服务失败: %v", err)
	}

	common.Info("二进制配置更新完成",
		zap.String("name", record.Name),
		zap.String("service", common.GetServiceName(record.Name)),
		zap.String("restart_result", result))

	return map[string]interface{}{
		"name":    record.Name,
		"version": record.Version,
		"service": common.GetServiceName(record.Name),
		"config":  maskSensitiveConfigForLog(newConfig),
		"status":  "running",
		"message": "配置更新成功，服务已重启",
	}, nil
}
