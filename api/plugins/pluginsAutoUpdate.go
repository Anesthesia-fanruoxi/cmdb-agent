package plugins

import (
	"cmdb-agent/common"
	"cmdb-agent/config"
	"context"
	"encoding/json"
	"fmt"
	"go.uber.org/zap"
	"io"
	"net/http"
	"time"
)

// PluginVersionInfo CMDB返回的插件版本信息
type PluginVersionInfo struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	PluginType  string `json:"plugin_type"`
	DisplayName string `json:"display_name"`
}

// AgentVersionInfo CMDB返回的agent版本信息
type AgentVersionInfo struct {
	Version     string `json:"version"`
	DownloadURL string `json:"download_url"`
}

// PluginVersionsResponse CMDB返回的版本列表响应
type PluginVersionsResponse struct {
	Plugins []PluginVersionInfo `json:"plugins"`
	Total   int                 `json:"total"`
	Agent   *AgentVersionInfo   `json:"agent"` // Agent版本信息（包含下载地址）
}

// EncryptedResponse 加密的响应体
type EncryptedResponse struct {
	Data string `json:"data"`
}

// StartAutoUpdateTask 启动插件自动更新任务（同时检查agent更新）
func StartAutoUpdateTask() {
	cfg := config.GetConfig()

	// 检查是否启用自动更新
	if !cfg.CMDB.EnableAutoUpdate {
		common.Info("插件自动更新已禁用")
		return
	}

	interval := time.Duration(cfg.CMDB.AutoUpdateInterval) * time.Minute
	common.Info("启动插件自动更新任务（包含Agent更新检查）",
		zap.Int("interval_minutes", cfg.CMDB.AutoUpdateInterval))

	// 计算到下一个整点的等待时间
	now := time.Now()
	nextTick := now.Truncate(interval).Add(interval)
	waitDuration := nextTick.Sub(now)

	common.Info("等待到整点开始执行",
		zap.Duration("wait_duration", waitDuration),
		zap.String("next_execution", nextTick.Format("2006-01-02 15:04:05")))

	// 等待到整点
	time.Sleep(waitDuration)

	// 整点执行第一次
	common.Info("开始首次自动更新检查")
	checkAndUpdatePlugins()

	// 创建定时器，之后每个整点执行
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// 定时执行
	for range ticker.C {
		checkAndUpdatePlugins()
	}
}

// checkAndUpdatePlugins 检查并更新插件
func checkAndUpdatePlugins() {
	// 获取最新版本信息
	versionsResp, err := fetchPluginVersions()
	if err != nil {
		common.Error("获取插件版本失败", zap.Error(err))
		return
	}

	// 获取本地已安装的插件
	localPlugins, err := ListPluginRecords()
	if err != nil {
		common.Error("获取本地插件列表失败", zap.Error(err))
		return
	}

	// 创建本地插件映射
	localPluginMap := make(map[string]*PluginRecord)
	for _, plugin := range localPlugins {
		localPluginMap[plugin.Name] = plugin
	}

	// 检查每个插件是否需要更新
	updateCount := 0
	for _, remotePlugin := range versionsResp.Plugins {
		localPlugin, exists := localPluginMap[remotePlugin.Name]
		if !exists {
			common.Debug("插件未安装，跳过",
				zap.String("name", remotePlugin.Name))
			continue
		}

		// 比对版本号
		if localPlugin.Version == remotePlugin.Version {
			continue
		}

		// 执行更新
		if err := updatePlugin(localPlugin, remotePlugin); err != nil {
			common.Error("自动更新插件失败",
				zap.String("name", remotePlugin.Name),
				zap.Error(err))
		} else {
			updateCount++
			common.Info("插件更新成功",
				zap.String("name", remotePlugin.Name),
				zap.String("version", localPlugin.Version+" -> "+remotePlugin.Version))
		}
	}

	// 最后更新Agent（会重启服务，所以放在最后）
	if versionsResp.Agent != nil && versionsResp.Agent.Version != "" {
		checkAndUpdateAgent(versionsResp.Agent)
	}
}

// getAgentVersionStr 获取agent版本字符串（用于日志）
func getAgentVersionStr(agentInfo *AgentVersionInfo) string {
	if agentInfo == nil {
		return "未提供"
	}
	return agentInfo.Version
}

// checkAndUpdateAgent 检查并更新agent
func checkAndUpdateAgent(agentInfo *AgentVersionInfo) {
	currentVersion := common.GetVersion()

	// 版本不同则更新（不校验版本号大小，直接更新）
	if currentVersion == agentInfo.Version {
		return
	}

	// 执行agent更新（单线程，同步执行）
	if err := updateAgent(agentInfo); err != nil {
		common.Error("Agent更新失败", zap.Error(err))
	} else {
		common.Info("Agent更新成功，服务即将重启")
	}
}

// updateAgent 更新agent（和二进制插件一样的逻辑）
func updateAgent(agentInfo *AgentVersionInfo) error {

	// 获取当前执行文件路径
	currentBinary, err := common.GetExecutablePath()
	if err != nil {
		return fmt.Errorf("获取当前执行文件路径失败: %v", err)
	}

	backupPath := currentBinary + ".old"
	// 从CMDB返回的完整下载URL（和插件一样，直接使用）
	downloadURL := agentInfo.DownloadURL
	tmpFile := "/tmp/cmdb-agent.new"

	// 备份当前版本
	if err := common.BackupFile(currentBinary, backupPath); err != nil {
		return fmt.Errorf("备份当前版本失败: %v", err)
	}

	// 下载新版本
	if err := common.DownloadFile(downloadURL, tmpFile); err != nil {
		common.RestoreFile(backupPath, currentBinary)
		return fmt.Errorf("下载新版本失败: %v", err)
	}

	// 设置执行权限
	if err := common.SetExecutable(tmpFile); err != nil {
		common.RestoreFile(backupPath, currentBinary)
		return fmt.Errorf("设置执行权限失败: %v", err)
	}

	// 替换二进制文件
	if err := common.ReplaceFile(tmpFile, currentBinary); err != nil {
		common.RestoreFile(backupPath, currentBinary)
		return fmt.Errorf("替换二进制文件失败: %v", err)
	}

	// 使用systemd重启服务
	serviceName := "cmdb-agent" // Agent服务名固定为cmdb-agent
	if err := common.RestartSystemdService(serviceName); err != nil {
		common.Error("重启服务失败", zap.Error(err))
		// 重启失败，尝试恢复备份
		common.RestoreFile(backupPath, currentBinary)
		return fmt.Errorf("重启服务失败: %v", err)
	}

	// 删除备份文件
	common.RemoveFile(backupPath)

	common.Info("Agent更新成功",
		zap.String("version", common.GetVersion()+" -> "+agentInfo.Version))

	// 注意：代码执行到这里后，进程会被systemd重启，不会继续执行
	return nil
}

// fetchPluginVersions 从CMDB获取插件版本信息（包含agent版本）
func fetchPluginVersions() (*PluginVersionsResponse, error) {
	cfg := config.GetConfig()

	// 构建请求URL
	url := cfg.GetCMDBURL(cfg.CMDB.PluginVersionsPath)

	// 创建HTTP客户端
	client := &http.Client{
		Timeout: time.Duration(cfg.CMDB.Timeout) * time.Second,
	}

	// 创建请求
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.CMDB.Timeout)*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %v", err)
	}

	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求失败: %v", err)
	}
	defer resp.Body.Close()

	// 读取响应体
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应体失败: %v", err)
	}

	// 检查HTTP状态码
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP状态码: %d, 响应: %s", resp.StatusCode, string(body))
	}

	// 解析加密响应
	var encryptedResp EncryptedResponse
	if err := json.Unmarshal(body, &encryptedResp); err != nil {
		return nil, fmt.Errorf("解析加密响应失败: %v", err)
	}

	// 解密数据
	decryptedData, err := common.DecryptAndDecompress(encryptedResp.Data, cfg.Security.AgentSalt)
	if err != nil {
		return nil, fmt.Errorf("解密响应数据失败: %v", err)
	}

	// 解析JSON
	var versionsResp PluginVersionsResponse
	if err := json.Unmarshal(decryptedData, &versionsResp); err != nil {
		return nil, fmt.Errorf("解析版本信息失败: %v", err)
	}

	return &versionsResp, nil
}

// updatePlugin 更新单个插件
func updatePlugin(localPlugin *PluginRecord, remotePlugin PluginVersionInfo) error {
	// 构建更新请求
	updateReq := UpdateRequest{
		Name:    remotePlugin.Name,
		Version: remotePlugin.Version,
		Config:  localPlugin.Config, // 保持现有配置
		Port:    localPlugin.Port,
		Command: localPlugin.Command, // 保持原启动命令
		Parameters: Parameters{
			ContainerPort: localPlugin.Parameters.ContainerPort,
		},
		// 注意：DownloadURL由CMDB在安装时提供，更新时使用旧记录中的URL
	}

	// 根据插件类型执行更新
	if localPlugin.Category == "container" {
		_, err := updateContainerPlugin(localPlugin, updateReq)
		return err
	} else if localPlugin.Category == "binary" {
		_, err := updateBinaryPlugin(localPlugin, updateReq)
		return err
	}

	return fmt.Errorf("不支持的插件类型: %s", localPlugin.Category)
}
