package update

import (
	"cmdb-agent/api/proxy"
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
	Image       string `json:"image"` // 完整镜像地址（容器类插件）
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
	Agent   *AgentVersionInfo   `json:"agent"`
}

// EncryptedResponse 加密的响应体
type EncryptedResponse struct {
	Data string `json:"data"`
}

// StartAutoUpdateTask 启动插件自动更新任务（同时检查agent更新）
func StartAutoUpdateTask() {
	cfg := config.GetConfig()

	if !cfg.CMDB.EnableAutoUpdate {
		common.Info("插件自动更新已禁用")
		return
	}

	interval := time.Duration(cfg.CMDB.AutoUpdateInterval) * time.Minute
	common.Info("启动插件自动更新任务（包含Agent更新检查）",
		zap.Int("interval_minutes", cfg.CMDB.AutoUpdateInterval))

	now := time.Now()
	nextTick := now.Truncate(interval).Add(interval)
	waitDuration := nextTick.Sub(now)

	common.Info("等待到整点开始执行",
		zap.Duration("wait_duration", waitDuration),
		zap.String("next_execution", nextTick.Format("2006-01-02 15:04:05")))

	time.Sleep(waitDuration)

	common.Info("开始首次自动更新检查")
	checkAndUpdatePlugins()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		checkAndUpdatePlugins()
	}
}

// checkAndUpdatePlugins 检查并更新插件
func checkAndUpdatePlugins() {
	versionsResp, err := fetchPluginVersions()
	if err != nil {
		common.Error("获取插件版本失败", zap.Error(err))
		return
	}

	localPlugins, err := proxy.ListPluginRecords()
	if err != nil {
		common.Error("获取本地插件列表失败", zap.Error(err))
		return
	}

	localPluginMap := make(map[string]*proxy.PluginRecord)
	for _, plugin := range localPlugins {
		localPluginMap[plugin.Name] = plugin
	}

	updateCount := 0
	for _, remotePlugin := range versionsResp.Plugins {
		localPlugin, exists := localPluginMap[remotePlugin.Name]
		if !exists {
			common.Debug("插件未安装，跳过", zap.String("name", remotePlugin.Name))
			continue
		}

		if localPlugin.Version == remotePlugin.Version {
			continue
		}

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

	if versionsResp.Agent != nil && versionsResp.Agent.Version != "" {
		checkAndUpdateAgent(versionsResp.Agent)
	}
}

// checkAndUpdateAgent 检查并更新agent
func checkAndUpdateAgent(agentInfo *AgentVersionInfo) {
	currentVersion := common.GetVersion()

	if currentVersion == agentInfo.Version {
		return
	}

	if err := updateAgent(agentInfo); err != nil {
		common.Error("Agent更新失败", zap.Error(err))
	} else {
		common.Info("Agent更新成功，服务即将重启")
	}
}

// updateAgent 更新agent
func updateAgent(agentInfo *AgentVersionInfo) error {
	currentBinary, err := common.GetExecutablePath()
	if err != nil {
		return fmt.Errorf("获取当前执行文件路径失败: %v", err)
	}

	backupPath := currentBinary + ".old"
	downloadURL := agentInfo.DownloadURL
	tmpFile := "/tmp/cmdb-agent.new"

	if err := common.BackupFile(currentBinary, backupPath); err != nil {
		return fmt.Errorf("备份当前版本失败: %v", err)
	}

	if err := common.DownloadFile(downloadURL, tmpFile); err != nil {
		if restoreErr := common.RestoreFile(backupPath, currentBinary); restoreErr != nil {
			common.Warn("恢复备份失败", zap.Error(restoreErr))
		}
		return fmt.Errorf("下载新版本失败: %v", err)
	}

	if err := common.SetExecutable(tmpFile); err != nil {
		if restoreErr := common.RestoreFile(backupPath, currentBinary); restoreErr != nil {
			common.Warn("恢复备份失败", zap.Error(restoreErr))
		}
		return fmt.Errorf("设置执行权限失败: %v", err)
	}

	if err := common.ReplaceFile(tmpFile, currentBinary); err != nil {
		if restoreErr := common.RestoreFile(backupPath, currentBinary); restoreErr != nil {
			common.Warn("恢复备份失败", zap.Error(restoreErr))
		}
		return fmt.Errorf("替换二进制文件失败: %v", err)
	}

	serviceName := "cmdb-agent"
	if err := common.RestartSystemdService(serviceName); err != nil {
		common.Error("重启服务失败", zap.Error(err))
		if restoreErr := common.RestoreFile(backupPath, currentBinary); restoreErr != nil {
			common.Warn("恢复备份失败", zap.Error(restoreErr))
		}
		return fmt.Errorf("重启服务失败: %v", err)
	}

	if err := common.RemoveFile(backupPath); err != nil {
		common.Warn("删除备份文件失败", zap.Error(err))
	}

	common.Info("Agent更新成功",
		zap.String("version", common.GetVersion()+" -> "+agentInfo.Version))

	return nil
}

// fetchPluginVersions 从CMDB获取插件版本信息（包含agent版本）
func fetchPluginVersions() (*PluginVersionsResponse, error) {
	cfg := config.GetConfig()

	url := cfg.GetCMDBURL(cfg.CMDB.PluginVersionsPath)

	client := &http.Client{
		Timeout: time.Duration(cfg.CMDB.Timeout) * time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.CMDB.Timeout)*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求失败: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应体失败: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP状态码: %d, 响应: %s", resp.StatusCode, string(body))
	}

	var encryptedResp EncryptedResponse
	if err := json.Unmarshal(body, &encryptedResp); err != nil {
		return nil, fmt.Errorf("解析加密响应失败: %v", err)
	}

	decryptedData, err := common.DecryptAndDecompress(encryptedResp.Data, cfg.Security.AgentSalt)
	if err != nil {
		return nil, fmt.Errorf("解密响应数据失败: %v", err)
	}

	var versionsResp PluginVersionsResponse
	if err := json.Unmarshal(decryptedData, &versionsResp); err != nil {
		return nil, fmt.Errorf("解析版本信息失败: %v", err)
	}

	return &versionsResp, nil
}

// updatePlugin 更新单个插件（只升级版本，保留原配置）
func updatePlugin(localPlugin *proxy.PluginRecord, remotePlugin PluginVersionInfo) error {
	upgradeReq := UpgradeRequest{
		Name:    remotePlugin.Name,
		Version: remotePlugin.Version,
		Image:   remotePlugin.Image,
	}

	switch localPlugin.Category {
	case "container":
		_, err := UpgradeContainer(localPlugin, upgradeReq)
		return err
	case "binary":
		_, err := UpgradeBinary(localPlugin, upgradeReq)
		return err
	}

	return fmt.Errorf("不支持的插件类型: %s", localPlugin.Category)
}
