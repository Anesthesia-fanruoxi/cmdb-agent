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

// UpdateRequest 插件更新请求
type UpdateRequest struct {
	Name        string                 `json:"name"`         // 插件名称（必填）
	Version     string                 `json:"version"`      // 新版本号（可选，不填则保持原版本）
	Image       string                 `json:"image"`        // 完整镜像地址（可选，优先级高于Version）
	Config      map[string]interface{} `json:"config"`       // 新配置（可选）
	Parameters  Parameters             `json:"parameters"`   // 新参数（可选）
	Port        int                    `json:"port"`         // 新端口（可选）
	Command     string                 `json:"command"`      // 启动命令（可选）
	DownloadURL string                 `json:"download_url"` // 下载地址（可选）
}

// PluginUpdateHandler 插件更新接口
func PluginUpdateHandler(w http.ResponseWriter, r *http.Request) {
	// 获取真实客户端IP
	realClientIP := getRealClientIP(r)
	if realClientIP == "" {
		if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
			realClientIP = host
		} else {
			realClientIP = r.RemoteAddr
		}
	}

	common.Info("收到插件更新请求",
		zap.String("method", r.Method),
		zap.String("path", r.URL.Path),
		zap.String("client_ip", realClientIP))

	// 只允许PUT请求
	if r.Method != http.MethodPut {
		common.RespondMethodNotAllowed(w, "只允许PUT请求")
		return
	}

	// 解析请求体
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

	common.Info("解析更新参数",
		zap.String("name", req.Name),
		zap.String("version", req.Version),
		zap.Int("port", req.Port))

	// 参数校验
	if req.Name == "" {
		common.RespondError(w, http.StatusBadRequest, "插件名称不能为空")
		return
	}

	// 查询插件记录
	record, err := GetPluginRecord(req.Name)
	if err != nil {
		common.Error("查询插件记录失败", zap.Error(err))
		common.RespondError(w, http.StatusInternalServerError,
			"查询插件记录失败: "+err.Error())
		return
	}

	if record == nil {
		common.RespondError(w, http.StatusNotFound, "插件不存在: "+req.Name)
		return
	}

	// 根据类型执行更新
	var result map[string]interface{}
	if record.Category == "container" {
		result, err = updateContainerPlugin(record, req)
	} else if record.Category == "binary" {
		result, err = updateBinaryPlugin(record, req)
	} else {
		common.RespondError(w, http.StatusBadRequest, "不支持的插件类型: "+record.Category)
		return
	}

	if err != nil {
		common.Error("更新插件失败",
			zap.String("name", req.Name),
			zap.Error(err))
		common.RespondError(w, http.StatusInternalServerError,
			"更新失败: "+err.Error())
		return
	}

	common.Info("插件更新成功",
		zap.String("name", req.Name),
		zap.String("category", record.Category))

	common.RespondSuccess(w, result)
}

// updateContainerPlugin 更新容器类型插件
func updateContainerPlugin(oldRecord *PluginRecord, req UpdateRequest) (map[string]interface{}, error) {
	// 判断是版本升级还是仅配置更新
	isVersionUpgrade := req.Version != "" && req.Version != oldRecord.Version

	if isVersionUpgrade {
		common.Info("执行版本升级",
			zap.String("name", req.Name),
			zap.String("old_version", oldRecord.Version),
			zap.String("new_version", req.Version))
		return upgradeContainerVersion(oldRecord, req)
	} else {
		common.Info("执行配置更新",
			zap.String("name", req.Name),
			zap.String("version", oldRecord.Version))
		return updateContainerConfigOnly(oldRecord, req)
	}
}

// upgradeContainerVersion 升级容器版本（拉取新镜像并重建）
func upgradeContainerVersion(oldRecord *PluginRecord, req UpdateRequest) (map[string]interface{}, error) {
	common.Info("开始升级容器插件版本",
		zap.String("name", req.Name),
		zap.String("old_version", oldRecord.Version),
		zap.String("new_version", req.Version))

	// 直接使用新配置（CMDB发送的是最终完整配置）
	newConfig := req.Config
	if newConfig == nil {
		newConfig = make(map[string]interface{})
	}

	// 确定新镜像
	var newImage string
	if req.Image != "" {
		// 优先使用完整的镜像地址
		newImage = req.Image
		common.Info("使用完整镜像地址",
			zap.String("old_image", oldRecord.Image),
			zap.String("new_image", newImage))
	} else if req.Version != "" && req.Version != oldRecord.Version {
		// 如果没有提供完整镜像地址，则使用版本号拼接
		imageWithoutTag := oldRecord.Image
		// 找到最后一个冒号的位置
		for i := len(oldRecord.Image) - 1; i >= 0; i-- {
			if oldRecord.Image[i] == ':' {
				imageWithoutTag = oldRecord.Image[:i]
				break
			}
		}
		newImage = fmt.Sprintf("%s:%s", imageWithoutTag, req.Version)
		common.Info("镜像版本更新",
			zap.String("old_image", oldRecord.Image),
			zap.String("new_image", newImage))
	} else {
		// 保持原镜像不变
		newImage = oldRecord.Image
	}

	// 确定新端口
	newPort := req.Port
	if newPort == 0 {
		newPort = oldRecord.Port // 保持原端口
	}

	// 合并参数
	newParams := oldRecord.Parameters
	if req.Parameters.ContainerPort != 0 {
		newParams.ContainerPort = req.Parameters.ContainerPort
	}

	common.Info("升级策略: 拉取镜像 -> 停止 -> 删除 -> 重建")

	// 步骤1: 先拉取新镜像
	common.Info("步骤1: 拉取新镜像", zap.String("image", newImage))
	if err := pullDockerImage(newImage); err != nil {
		return nil, fmt.Errorf("拉取新镜像失败，取消升级: %v", err)
	}
	common.Info("新镜像拉取成功，开始升级容器")

	// 步骤2: 停止旧容器
	common.Info("步骤2: 停止旧容器")
	if _, err := operateContainer(oldRecord, "stop"); err != nil {
		common.Warn("停止旧容器失败，继续执行", zap.Error(err))
	}

	// 步骤3: 删除旧容器
	common.Info("步骤3: 删除旧容器")
	if err := uninstallContainer(oldRecord); err != nil {
		common.Warn("删除旧容器失败，继续执行", zap.Error(err))
	}

	// 步骤4: 使用新配置启动容器
	common.Info("步骤4: 启动新容器",
		zap.String("image", newImage),
		zap.Int("port", newPort))

	containerID, err := startContainerService(req.Name, newImage, newPort, "", newConfig, newParams)
	if err != nil {
		return nil, fmt.Errorf("启动新容器失败: %v", err)
	}

	// 步骤5: 更新注册表记录
	common.Info("步骤5: 更新注册表记录")
	newRecord := &PluginRecord{
		Name:          req.Name,
		Version:       req.Version,
		Category:      "container",
		Image:         newImage,
		ContainerID:   containerID,
		Port:          newPort,
		ContainerPort: newParams.ContainerPort,
		Config:        newConfig,
		Parameters:    newParams,
	}

	if err := AddPluginRecord(newRecord); err != nil {
		common.Warn("更新插件记录失败", zap.Error(err))
	}

	return map[string]interface{}{
		"name":         req.Name,
		"old_version":  oldRecord.Version,
		"new_version":  req.Version,
		"old_image":    oldRecord.Image,
		"new_image":    newImage,
		"container_id": containerID,
		"port":         newPort,
		"status":       "running",
		"message":      "插件版本升级成功",
	}, nil
}

// updateContainerConfigOnly 仅更新容器配置（不升级版本）
func updateContainerConfigOnly(oldRecord *PluginRecord, req UpdateRequest) (map[string]interface{}, error) {
	common.Info("开始更新容器配置",
		zap.String("name", req.Name),
		zap.Any("old_config", maskSensitiveConfigForLog(oldRecord.Config)),
		zap.Any("new_config", maskSensitiveConfigForLog(req.Config)))

	// 直接使用新配置替换旧配置（完全替换，不保留旧配置中的键）
	newConfig := req.Config
	if newConfig == nil {
		newConfig = make(map[string]interface{})
	}

	// 保存旧容器ID用于回滚
	oldContainerID := oldRecord.ContainerID

	common.Info("更新策略: 停止 -> 删除 -> 重建（仅配置变化）")

	// 步骤1: 停止旧容器
	common.Info("步骤1: 停止旧容器")
	if _, err := operateContainer(oldRecord, "stop"); err != nil {
		common.Warn("停止旧容器失败，继续执行", zap.Error(err))
	}

	// 步骤2: 删除旧容器
	common.Info("步骤2: 删除旧容器")
	if err := uninstallContainer(oldRecord); err != nil {
		common.Warn("删除旧容器失败，继续执行", zap.Error(err))
	}

	// 步骤3: 使用新配置重新创建容器（使用原镜像）
	common.Info("步骤3: 使用新配置重新创建容器",
		zap.String("image", oldRecord.Image),
		zap.Int("port", oldRecord.Port))

	containerID, err := startContainerService(
		req.Name,
		oldRecord.Image,
		oldRecord.Port,
		"",
		newConfig,
		oldRecord.Parameters,
	)
	if err != nil {
		common.Error("创建新容器失败", zap.Error(err))
		// 回滚：尝试用旧配置重新创建容器
		if rollbackID, rollbackErr := startContainerService(
			req.Name,
			oldRecord.Image,
			oldRecord.Port,
			"",
			oldRecord.Config,
			oldRecord.Parameters,
		); rollbackErr == nil {
			oldRecord.ContainerID = rollbackID
			AddPluginRecord(oldRecord)
			common.Info("已回滚到旧配置")
		}
		return nil, fmt.Errorf("创建新容器失败: %v", err)
	}

	// 步骤4: 更新注册表记录
	common.Info("步骤4: 更新注册表记录")
	oldRecord.Config = newConfig
	oldRecord.ContainerID = containerID
	if err := AddPluginRecord(oldRecord); err != nil {
		common.Warn("更新插件记录失败", zap.Error(err))
	}

	common.Info("容器配置更新完成",
		zap.String("name", req.Name),
		zap.String("old_container_id", oldContainerID[:12]),
		zap.String("new_container_id", containerID[:12]))

	return map[string]interface{}{
		"name":         req.Name,
		"version":      oldRecord.Version,
		"category":     "container",
		"container_id": containerID,
		"config":       maskSensitiveConfigForLog(newConfig),
		"status":       "running",
		"message":      "配置更新成功，容器已重启",
	}, nil
}

// updateBinaryPlugin 更新二进制类型插件
func updateBinaryPlugin(oldRecord *PluginRecord, req UpdateRequest) (map[string]interface{}, error) {
	// 判断是版本升级还是仅配置更新
	isVersionUpgrade := req.Version != "" && req.Version != oldRecord.Version

	if isVersionUpgrade {
		common.Info("执行版本升级",
			zap.String("name", req.Name),
			zap.String("old_version", oldRecord.Version),
			zap.String("new_version", req.Version))
		return upgradeBinaryVersion(oldRecord, req)
	} else {
		common.Info("执行配置更新",
			zap.String("name", req.Name),
			zap.String("version", oldRecord.Version))
		return updateBinaryConfigOnly(oldRecord, req)
	}
}

// upgradeBinaryVersion 升级二进制版本（下载新版本文件）
func upgradeBinaryVersion(oldRecord *PluginRecord, req UpdateRequest) (map[string]interface{}, error) {
	common.Info("开始升级二进制插件版本",
		zap.String("name", req.Name),
		zap.String("old_version", oldRecord.Version),
		zap.String("new_version", req.Version))

	// 直接使用新配置（CMDB发送的是最终完整配置）
	newConfig := req.Config
	if newConfig == nil {
		newConfig = make(map[string]interface{})
	}

	// 确定新端口
	newPort := req.Port
	if newPort == 0 {
		newPort = oldRecord.Port
	}

	// 合并参数
	newParams := oldRecord.Parameters

	common.Info("升级策略: 停止 -> 备份 -> 下载 -> 启动")

	// 步骤1: 停止旧进程
	common.Info("步骤1: 停止旧进程")
	if _, err := operateBinary(oldRecord, "stop"); err != nil {
		common.Warn("停止旧进程失败，继续执行", zap.Error(err))
	}

	// 步骤2: 备份旧二进制文件
	common.Info("步骤2: 备份旧二进制文件")
	backupPath := oldRecord.BinaryPath + ".backup"
	if err := os.Rename(oldRecord.BinaryPath, backupPath); err != nil {
		common.Warn("备份旧文件失败",
			zap.String("path", oldRecord.BinaryPath),
			zap.Error(err))
	} else {
		common.Info("旧文件已备份",
			zap.String("backup", backupPath))
	}

	// 步骤3: 下载新版本
	common.Info("步骤3: 下载新版本二进制文件")
	// 使用新的下载URL（如果提供），否则使用旧的
	downloadURL := req.DownloadURL
	if downloadURL == "" {
		downloadURL = oldRecord.DownloadURL
	}
	newBinaryPath, err := downloadBinary(req.Name, downloadURL)
	if err != nil {
		// 下载失败，恢复备份
		if _, restoreErr := os.Stat(backupPath); restoreErr == nil {
			os.Rename(backupPath, oldRecord.BinaryPath)
			common.Info("下载失败，已恢复备份")
		}
		return nil, fmt.Errorf("下载新版本失败: %v", err)
	}

	// 下载成功，删除备份
	os.Remove(backupPath)
	common.Info("新版本下载成功，备份已删除")

	// 步骤4: 启动新服务（使用systemd）
	common.Info("步骤4: 启动新服务(systemd)")
	// 使用新的command（如果提供），否则使用旧的
	command := req.Command
	if command == "" {
		command = oldRecord.Command
	}
	// 更新时不重新创建配置文件，传递空字符串
	if err := startBinaryService(req.Name, newBinaryPath, newPort, command, newConfig, "", newParams); err != nil {
		return nil, fmt.Errorf("启动新服务失败: %v", err)
	}

	// 步骤5: 更新注册表记录
	common.Info("步骤5: 更新注册表记录")
	newRecord := &PluginRecord{
		Name:        req.Name,
		Version:     req.Version,
		Category:    "binary",
		DownloadURL: downloadURL, // 使用最新的下载URL
		Command:     command,     // 使用最新的启动命令
		BinaryPath:  newBinaryPath,
		Port:        newPort,
		Config:      newConfig,
		Parameters:  newParams,
	}

	if err := AddPluginRecord(newRecord); err != nil {
		common.Warn("更新插件记录失败", zap.Error(err))
	}

	return map[string]interface{}{
		"name":        req.Name,
		"old_version": oldRecord.Version,
		"new_version": req.Version,
		"binary_path": newBinaryPath,
		"service":     common.GetServiceName(req.Name),
		"port":        newPort,
		"status":      "running",
		"message":     "插件版本升级成功",
	}, nil
}

// updateBinaryConfigOnly 仅更新二进制插件配置（不升级版本）
func updateBinaryConfigOnly(oldRecord *PluginRecord, req UpdateRequest) (map[string]interface{}, error) {
	common.Info("开始更新二进制插件配置",
		zap.String("name", req.Name),
		zap.Any("old_config", maskSensitiveConfigForLog(oldRecord.Config)),
		zap.Any("new_config", maskSensitiveConfigForLog(req.Config)))

	// 直接使用新配置替换旧配置（完全替换，不保留旧配置中的键）
	newConfig := req.Config
	if newConfig == nil {
		newConfig = make(map[string]interface{})
	}

	common.Info("更新策略: 更新配置 -> 清空日志 -> 重启服务")

	// 步骤1: 更新注册表记录
	common.Info("步骤1: 更新注册表记录")
	oldRecord.Config = newConfig
	if err := AddPluginRecord(oldRecord); err != nil {
		common.Error("更新插件记录失败", zap.Error(err))
		return nil, fmt.Errorf("更新插件记录失败: %v", err)
	}

	// 步骤2: 清空日志文件
	common.Info("步骤2: 清空日志文件")
	pluginDir := filepath.Dir(oldRecord.BinaryPath)
	logFile := filepath.Join(pluginDir, req.Name+".log")
	if err := os.Truncate(logFile, 0); err != nil {
		common.Warn("清空日志文件失败",
			zap.String("log_file", logFile),
			zap.Error(err))
	} else {
		common.Info("日志文件已清空", zap.String("log_file", logFile))
	}

	// 步骤3: 重启服务应用新配置（systemctl restart）
	common.Info("步骤3: 重启服务应用配置", zap.String("method", "systemctl restart"))
	result, err := operateBinary(oldRecord, "restart")
	if err != nil {
		common.Error("重启服务失败", zap.Error(err))
		return nil, fmt.Errorf("重启服务失败: %v", err)
	}

	common.Info("二进制插件配置更新完成",
		zap.String("name", req.Name),
		zap.String("service", common.GetServiceName(req.Name)),
		zap.String("restart_result", result))

	return map[string]interface{}{
		"name":     req.Name,
		"version":  oldRecord.Version,
		"category": "binary",
		"service":  common.GetServiceName(req.Name),
		"config":   maskSensitiveConfigForLog(newConfig),
		"status":   "running",
		"message":  "配置更新成功，服务已重启",
	}, nil
}
