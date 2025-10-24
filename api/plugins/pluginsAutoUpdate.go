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

// PluginVersionsResponse CMDB返回的版本列表响应
type PluginVersionsResponse struct {
	Plugins []PluginVersionInfo `json:"plugins"`
	Total   int                 `json:"total"`
}

// EncryptedResponse 加密的响应体
type EncryptedResponse struct {
	Data string `json:"data"`
}

// StartAutoUpdateTask 启动插件自动更新任务
func StartAutoUpdateTask() {
	cfg := config.GetConfig()

	// 检查是否启用自动更新
	if !cfg.CMDB.EnableAutoUpdate {
		common.Info("插件自动更新已禁用")
		return
	}

	interval := time.Duration(cfg.CMDB.AutoUpdateInterval) * time.Minute
	common.Info("启动插件自动更新任务",
		zap.Int("interval_minutes", cfg.CMDB.AutoUpdateInterval))

	// 计算到下一个整点的等待时间
	now := time.Now()
	nextTick := now.Truncate(interval).Add(interval)
	waitDuration := nextTick.Sub(now)

	common.Info("等待到整点开始执行",
		zap.Duration("wait_duration", waitDuration),
		zap.Time("next_execution", nextTick))

	// 等待到整点
	time.Sleep(waitDuration)

	// 整点执行第一次
	common.Info("开始首次自动更新检查")
	go checkAndUpdatePlugins()

	// 创建定时器，之后每个整点执行
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// 启动时立即执行一次
	go checkAndUpdatePlugins()

	// 定时执行
	for range ticker.C {
		go checkAndUpdatePlugins()
	}
}

// checkAndUpdatePlugins 检查并更新插件
func checkAndUpdatePlugins() {
	common.Info("开始检查插件更新")

	// 获取最新版本信息
	versions, err := fetchPluginVersions()
	if err != nil {
		common.Error("获取插件版本失败", zap.Error(err))
		return
	}

	common.Info("获取到插件版本信息", zap.Int("total", len(versions)))

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
	for _, remotePlugin := range versions {
		localPlugin, exists := localPluginMap[remotePlugin.Name]
		if !exists {
			common.Debug("插件未安装，跳过",
				zap.String("name", remotePlugin.Name))
			continue
		}

		// 比对版本号
		if localPlugin.Version == remotePlugin.Version {
			common.Debug("插件已是最新版本",
				zap.String("name", remotePlugin.Name),
				zap.String("version", remotePlugin.Version))
			continue
		}

		common.Info("发现插件需要更新",
			zap.String("name", remotePlugin.Name),
			zap.String("current_version", localPlugin.Version),
			zap.String("latest_version", remotePlugin.Version))

		// 执行更新
		if err := updatePlugin(localPlugin, remotePlugin); err != nil {
			common.Error("自动更新插件失败",
				zap.String("name", remotePlugin.Name),
				zap.Error(err))
		} else {
			updateCount++
			common.Info("自动更新插件成功",
				zap.String("name", remotePlugin.Name),
				zap.String("old_version", localPlugin.Version),
				zap.String("new_version", remotePlugin.Version))
		}
	}

	common.Info("插件自动更新检查完成",
		zap.Int("total_checked", len(versions)),
		zap.Int("updated", updateCount))
}

// fetchPluginVersions 从CMDB获取插件版本信息
func fetchPluginVersions() ([]PluginVersionInfo, error) {
	cfg := config.GetConfig()

	// 构建请求URL
	url := cfg.GetCMDBURL(cfg.CMDB.PluginVersionsPath)

	common.Debug("请求CMDB插件版本",
		zap.String("url", url))

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

	return versionsResp.Plugins, nil
}

// updatePlugin 更新单个插件
func updatePlugin(localPlugin *PluginRecord, remotePlugin PluginVersionInfo) error {
	// 构建更新请求
	updateReq := UpdateRequest{
		Name:    remotePlugin.Name,
		Version: remotePlugin.Version,
		Config:  localPlugin.Config, // 保持现有配置
		Port:    localPlugin.Port,
		Parameters: Parameters{
			ConfigDir:     localPlugin.Parameters.ConfigDir,
			ConfigFile:    localPlugin.Parameters.ConfigFile,
			ContainerPort: localPlugin.Parameters.ContainerPort,
		},
	}

	// 根据插件类型执行更新
	var result map[string]interface{}
	var err error

	if localPlugin.Category == "container" {
		result, err = updateContainerPlugin(localPlugin, updateReq)
	} else if localPlugin.Category == "binary" {
		result, err = updateBinaryPlugin(localPlugin, updateReq)
	} else {
		return fmt.Errorf("不支持的插件类型: %s", localPlugin.Category)
	}

	if err != nil {
		return err
	}

	common.Info("插件更新结果",
		zap.String("name", remotePlugin.Name),
		zap.Any("result", result))

	return nil
}
