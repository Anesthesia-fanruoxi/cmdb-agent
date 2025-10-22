package plugins

import (
	"cmdb-agent/common"
	"encoding/json"
	"fmt"
	"go.uber.org/zap"
	"io"
	"net/http"
)

// UpdateRequest 插件更新请求
type UpdateRequest struct {
	Name       string                 `json:"name"`       // 插件名称（必填）
	Version    string                 `json:"version"`    // 新版本号（可选，不填则保持原版本）
	Config     map[string]interface{} `json:"config"`     // 新配置（可选）
	Parameters Parameters             `json:"parameters"` // 新参数（可选）
	Port       int                    `json:"port"`       // 新端口（可选）
}

// PluginUpdateHandler 插件更新接口
func PluginUpdateHandler(w http.ResponseWriter, r *http.Request) {
	common.Info("收到插件更新请求",
		zap.String("method", r.Method),
		zap.String("path", r.URL.Path),
		zap.String("remote", r.RemoteAddr))

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
	common.Info("开始更新容器插件",
		zap.String("name", req.Name),
		zap.String("old_version", oldRecord.Version),
		zap.String("new_version", req.Version))

	// 合并配置（新配置覆盖旧配置）
	newConfig := make(map[string]interface{})
	for k, v := range oldRecord.Config {
		newConfig[k] = v
	}
	for k, v := range req.Config {
		newConfig[k] = v
	}

	// 确定新版本和镜像
	newVersion := req.Version
	if newVersion == "" {
		newVersion = oldRecord.Version // 保持原版本
	}

	// 构建新镜像地址（替换tag）
	newImage := oldRecord.Image
	if newVersion != "" && newVersion != oldRecord.Version {
		// 解析镜像名称，替换tag
		// 例如: hub.hzbxhd.com/test/sql-plugs:2.0 -> hub.hzbxhd.com/test/sql-plugs:3.0
		imageWithoutTag := oldRecord.Image
		if lastColon := len(oldRecord.Image) - 1; lastColon > 0 {
			for i := len(oldRecord.Image) - 1; i >= 0; i-- {
				if oldRecord.Image[i] == ':' {
					imageWithoutTag = oldRecord.Image[:i]
					break
				}
			}
		}
		newImage = fmt.Sprintf("%s:%s", imageWithoutTag, newVersion)
		common.Info("镜像版本更新",
			zap.String("old_image", oldRecord.Image),
			zap.String("new_image", newImage))
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

	common.Info("更新策略: 拉取镜像 -> 停止 -> 删除 -> 重建")

	// 步骤1: 先拉取新镜像（如果版本变化）
	if newImage != oldRecord.Image {
		common.Info("步骤1: 拉取新镜像", zap.String("image", newImage))
		if err := pullDockerImage(newImage); err != nil {
			return nil, fmt.Errorf("拉取新镜像失败，取消更新: %v", err)
		}
		common.Info("新镜像拉取成功，开始更新容器")
	} else {
		common.Info("步骤1: 版本未变化，跳过拉取镜像")
	}

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
		Version:       newVersion,
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
		"new_version":  newVersion,
		"old_image":    oldRecord.Image,
		"new_image":    newImage,
		"container_id": containerID,
		"port":         newPort,
		"status":       "running",
		"message":      "插件更新成功",
	}, nil
}

// updateBinaryPlugin 更新二进制类型插件
func updateBinaryPlugin(oldRecord *PluginRecord, req UpdateRequest) (map[string]interface{}, error) {
	common.Info("开始更新二进制插件",
		zap.String("name", req.Name),
		zap.String("old_version", oldRecord.Version),
		zap.String("new_version", req.Version))

	// 合并配置
	newConfig := make(map[string]interface{})
	for k, v := range oldRecord.Config {
		newConfig[k] = v
	}
	for k, v := range req.Config {
		newConfig[k] = v
	}

	// 确定新版本
	newVersion := req.Version
	if newVersion == "" {
		newVersion = oldRecord.Version
	}

	// 确定新端口
	newPort := req.Port
	if newPort == 0 {
		newPort = oldRecord.Port
	}

	// 合并参数
	newParams := oldRecord.Parameters
	if req.Parameters.ConfigDir != "" {
		newParams.ConfigDir = req.Parameters.ConfigDir
	}
	if req.Parameters.ConfigFile != "" {
		newParams.ConfigFile = req.Parameters.ConfigFile
	}

	common.Info("更新策略: 停止 -> 删除 -> 下载 -> 启动")

	// 步骤1: 停止旧进程
	common.Info("步骤1: 停止旧进程")
	if _, err := operateBinary(oldRecord, "stop"); err != nil {
		common.Warn("停止旧进程失败，继续执行", zap.Error(err))
	}

	// 步骤2: 如果版本变化，重新下载
	newBinaryPath := oldRecord.BinaryPath
	if newVersion != oldRecord.Version && oldRecord.DownloadURL != "" {
		common.Info("步骤2: 下载新版本二进制文件")

		// 删除旧文件
		if err := uninstallBinary(oldRecord); err != nil {
			common.Warn("删除旧文件失败", zap.Error(err))
		}

		// 下载新版本
		var err error
		newBinaryPath, err = downloadBinary(req.Name, oldRecord.DownloadURL)
		if err != nil {
			return nil, fmt.Errorf("下载新版本失败: %v", err)
		}
	} else {
		common.Info("步骤2: 版本未变化，使用原二进制文件")
	}

	// 步骤3: 启动新服务（使用systemd）
	common.Info("步骤3: 启动新服务(systemd)")
	if err := startBinaryService(req.Name, newBinaryPath, newPort, "", newConfig, newParams); err != nil {
		return nil, fmt.Errorf("启动新服务失败: %v", err)
	}

	// 步骤4: 更新注册表记录
	common.Info("步骤4: 更新注册表记录")
	newRecord := &PluginRecord{
		Name:        req.Name,
		Version:     newVersion,
		Category:    "binary",
		DownloadURL: oldRecord.DownloadURL,
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
		"new_version": newVersion,
		"binary_path": newBinaryPath,
		"service":     common.GetServiceName(req.Name),
		"port":        newPort,
		"status":      "running",
		"message":     "插件更新成功",
	}, nil
}
