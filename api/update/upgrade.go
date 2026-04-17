package update

import (
	"cmdb-agent/api/operator"
	"cmdb-agent/api/proxy"
	"cmdb-agent/common"
	"encoding/json"
	"fmt"
	"go.uber.org/zap"
	"io"
	"net"
	"net/http"
	"os"
)

// UpgradeRequest 插件版本升级请求
type UpgradeRequest struct {
	Name        string `json:"name"`         // 插件名称（必填）
	Version     string `json:"version"`      // 新版本号（必填）
	Image       string `json:"image"`        // 完整镜像地址（container 类型必填）
	DownloadURL string `json:"download_url"` // 下载地址（binary 类型必填）
}

// UpgradeHandler 插件版本升级接口
func UpgradeHandler(w http.ResponseWriter, r *http.Request) {
	realClientIP := proxy.GetRealClientIP(r.Header.Get("X-Real-IP"), r.Header.Get("X-Forwarded-For"))
	if realClientIP == "" {
		if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
			realClientIP = host
		} else {
			realClientIP = r.RemoteAddr
		}
	}

	common.Info("收到插件版本升级请求",
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
	defer func() { _ = r.Body.Close() }()

	var req UpgradeRequest
	if err := json.Unmarshal(body, &req); err != nil {
		common.RespondError(w, http.StatusBadRequest, "解析JSON失败: "+err.Error())
		return
	}

	if req.Name == "" {
		common.RespondError(w, http.StatusBadRequest, "插件名称不能为空")
		return
	}
	if req.Version == "" {
		common.RespondError(w, http.StatusBadRequest, "版本号不能为空")
		return
	}

	record, err := proxy.GetPluginRecord(req.Name)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "查询插件记录失败: "+err.Error())
		return
	}
	if record == nil {
		common.RespondError(w, http.StatusNotFound, "插件不存在: "+req.Name)
		return
	}

	if record.Version == req.Version {
		common.RespondError(w, http.StatusBadRequest, "当前已是该版本: "+req.Version)
		return
	}

	var result map[string]interface{}
	switch record.Category {
	case "container":
		result, err = UpgradeContainer(record, req)
	case "binary":
		result, err = UpgradeBinary(record, req)
	default:
		common.RespondError(w, http.StatusBadRequest, "不支持的插件类型: "+record.Category)
		return
	}

	if err != nil {
		common.Error("版本升级失败", zap.String("name", req.Name), zap.Error(err))
		common.RespondError(w, http.StatusInternalServerError, "升级失败: "+err.Error())
		return
	}

	common.Info("插件版本升级成功",
		zap.String("name", req.Name),
		zap.String("old_version", record.Version),
		zap.String("new_version", req.Version))

	common.RespondSuccess(w, result)
}

// UpgradeContainer 升级容器类型插件版本（公开，供 autoupdate 调用）
func UpgradeContainer(record *proxy.PluginRecord, req UpgradeRequest) (map[string]interface{}, error) {
	if req.Image == "" {
		return nil, fmt.Errorf("容器类型升级必须提供 image 参数")
	}

	common.Info("开始升级容器版本",
		zap.String("name", req.Name),
		zap.String("old_image", record.Image),
		zap.String("new_image", req.Image))

	if err := operator.PullDockerImage(req.Image); err != nil {
		return nil, fmt.Errorf("拉取新镜像失败，取消升级: %v", err)
	}

	if _, err := operator.OperateContainer(record, "stop"); err != nil {
		common.Warn("停止旧容器失败，继续执行", zap.Error(err))
	}

	if err := operator.UninstallContainer(record); err != nil {
		common.Warn("删除旧容器失败，继续执行", zap.Error(err))
	}

	containerID, err := operator.StartContainerService(req.Name, req.Image, record.Port, "", record.Config, record.Parameters)
	if err != nil {
		return nil, fmt.Errorf("启动新容器失败: %v", err)
	}

	oldVersion := record.Version
	record.Version = req.Version
	record.Image = req.Image
	record.ContainerID = containerID
	if err := proxy.AddPluginRecord(record); err != nil {
		common.Warn("更新插件记录失败", zap.Error(err))
	}

	return map[string]interface{}{
		"name":         req.Name,
		"old_version":  oldVersion,
		"new_version":  req.Version,
		"image":        req.Image,
		"container_id": containerID,
		"port":         record.Port,
		"status":       "running",
		"message":      "容器版本升级成功",
	}, nil
}

// UpgradeBinary 升级二进制类型插件版本（公开，供 autoupdate 调用）
func UpgradeBinary(record *proxy.PluginRecord, req UpgradeRequest) (map[string]interface{}, error) {
	downloadURL := req.DownloadURL
	if downloadURL == "" {
		downloadURL = record.DownloadURL
	}
	if downloadURL == "" {
		return nil, fmt.Errorf("二进制类型升级必须提供 download_url 参数")
	}

	common.Info("开始升级二进制版本",
		zap.String("name", req.Name),
		zap.String("old_version", record.Version),
		zap.String("new_version", req.Version))

	if _, err := operator.OperateBinary(record, "stop"); err != nil {
		common.Warn("停止旧进程失败，继续执行", zap.Error(err))
	}

	backupPath := record.BinaryPath + ".backup"
	if err := os.Rename(record.BinaryPath, backupPath); err != nil {
		common.Warn("备份旧文件失败", zap.Error(err))
	}

	newBinaryPath, err := operator.DownloadBinary(req.Name, downloadURL)
	if err != nil {
		if renameErr := os.Rename(backupPath, record.BinaryPath); renameErr != nil {
			common.Warn("恢复备份文件失败", zap.Error(renameErr))
		}
		return nil, fmt.Errorf("下载新版本失败: %v", err)
	}
	if err := os.Remove(backupPath); err != nil {
		common.Warn("删除备份文件失败", zap.Error(err))
	}

	if err := operator.StartBinaryService(req.Name, newBinaryPath, record.Port, record.Command, record.Config, "", record.Parameters); err != nil {
		return nil, fmt.Errorf("启动新服务失败: %v", err)
	}

	oldVersion := record.Version
	record.Version = req.Version
	record.BinaryPath = newBinaryPath
	record.DownloadURL = downloadURL
	if err := proxy.AddPluginRecord(record); err != nil {
		common.Warn("更新插件记录失败", zap.Error(err))
	}

	return map[string]interface{}{
		"name":        req.Name,
		"old_version": oldVersion,
		"new_version": req.Version,
		"binary_path": newBinaryPath,
		"service":     common.GetServiceName(req.Name),
		"port":        record.Port,
		"status":      "running",
		"message":     "二进制版本升级成功",
	}, nil
}
