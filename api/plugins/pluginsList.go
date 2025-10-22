package plugins

import (
	"cmdb-agent/common"
	"context"
	"fmt"
	"go.uber.org/zap"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

// PluginInfo 插件信息（用于接口返回）
type PluginInfo struct {
	Name          string                 `json:"name"`
	Version       string                 `json:"version"`
	Category      string                 `json:"category"`
	Status        string                 `json:"status"` // running, stopped, error, not_found
	Port          int                    `json:"port"`
	ContainerPort int                    `json:"container_port,omitempty"`
	Uptime        string                 `json:"uptime,omitempty"`
	Config        map[string]interface{} `json:"config,omitempty"` // 敏感字段已脱敏
	InstalledAt   time.Time              `json:"installed_at"`
}

// PluginsListHandler 查询插件列表
func PluginsListHandler(w http.ResponseWriter, r *http.Request) {
	common.Info("收到查询插件列表请求",
		zap.String("method", r.Method),
		zap.String("path", r.URL.Path))

	// 只允许GET请求
	if r.Method != http.MethodGet {
		common.RespondMethodNotAllowed(w, "只允许GET请求")
		return
	}

	// 查询参数
	category := r.URL.Query().Get("category") // container, binary
	status := r.URL.Query().Get("status")     // running, stopped
	name := r.URL.Query().Get("name")         // 名称搜索

	// 读取插件注册表
	records, err := ListPluginRecords()
	if err != nil {
		common.Error("读取插件注册表失败", zap.Error(err))
		common.RespondError(w, http.StatusInternalServerError,
			"读取插件列表失败: "+err.Error())
		return
	}

	// 转换为带状态的插件信息
	var plugins []*PluginInfo
	for _, record := range records {
		// 过滤：类型
		if category != "" && record.Category != category {
			continue
		}

		// 过滤：名称
		if name != "" && !strings.Contains(record.Name, name) {
			continue
		}

		// 查询实时状态
		info := &PluginInfo{
			Name:          record.Name,
			Version:       record.Version,
			Category:      record.Category,
			Port:          record.Port,
			ContainerPort: record.ContainerPort,
			Config:        maskSensitiveConfig(record.Config), // 脱敏处理
			InstalledAt:   record.InstalledAt,
		}

		// 根据类型查询状态
		if record.Category == "container" {
			info.Status, info.Uptime = getContainerStatus(record.ContainerID)
		} else if record.Category == "binary" {
			info.Status = getBinaryStatusFromSystemd(record.Name)
		}

		// 过滤：状态
		if status != "" && info.Status != status {
			continue
		}

		plugins = append(plugins, info)
	}

	// 返回结果
	common.Info("查询插件列表成功",
		zap.Int("total", len(plugins)))

	common.RespondSuccess(w, map[string]interface{}{
		"total":   len(plugins),
		"plugins": plugins,
	})
}

// getContainerStatus 查询容器状态
func getContainerStatus(containerID string) (string, string) {
	if containerID == "" {
		return "not_found", ""
	}

	// 创建超时上下文（3秒超时）
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// 查询容器状态
	cmd := exec.CommandContext(ctx, "docker", "inspect",
		"--format", "{{.State.Status}}|{{.State.StartedAt}}", containerID)

	output, err := cmd.Output()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			common.Warn("查询容器状态超时",
				zap.String("container_id", containerID))
			return "error", ""
		}
		common.Debug("查询容器状态失败",
			zap.String("container_id", containerID),
			zap.Error(err))
		return "not_found", ""
	}

	parts := strings.Split(strings.TrimSpace(string(output)), "|")
	if len(parts) != 2 {
		return "error", ""
	}

	status := parts[0]
	startedAt := parts[1]

	// 计算运行时间
	var uptime string
	if status == "running" {
		startTime, err := time.Parse(time.RFC3339Nano, startedAt)
		if err == nil {
			duration := time.Since(startTime)
			uptime = formatDuration(duration)
		}
	}

	// Docker状态映射
	switch status {
	case "running":
		return "running", uptime
	case "exited", "dead":
		return "stopped", ""
	case "paused":
		return "paused", uptime
	default:
		return "error", ""
	}
}

// getBinaryStatusFromSystemd 从systemd查询二进制插件状态
func getBinaryStatusFromSystemd(pluginName string) string {
	if common.SystemctlIsActive(pluginName) {
		return "running"
	}
	return "stopped"
}

// getBinaryStatus 查询二进制进程状态（已废弃，保留用于兼容）
func getBinaryStatus(pid int) string {
	if pid == 0 {
		return "stopped"
	}

	// 查找进程
	process, err := os.FindProcess(pid)
	if err != nil {
		return "not_found"
	}

	// 发送信号0检查进程是否存在
	err = process.Signal(os.Signal(nil))
	if err != nil {
		return "stopped"
	}

	return "running"
}

// formatDuration 格式化时间间隔
func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	} else if d < time.Hour {
		return fmt.Sprintf("%dm%ds", int(d.Minutes()), int(d.Seconds())%60)
	} else if d < 24*time.Hour {
		return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
	} else {
		return fmt.Sprintf("%dd%dh", int(d.Hours())/24, int(d.Hours())%24)
	}
}

// maskSensitiveConfig 对配置中的敏感字段进行脱敏
func maskSensitiveConfig(config map[string]interface{}) map[string]interface{} {
	if config == nil {
		return nil
	}

	// 敏感字段关键词列表（不区分大小写）
	sensitiveKeywords := []string{
		"password", "passwd", "pwd",
		"secret", "token", "key",
		"credential", "auth",
		"apikey", "api_key",
		"access_key", "secret_key",
	}

	masked := make(map[string]interface{})
	for key, value := range config {
		keyLower := strings.ToLower(key)
		isSensitive := false

		// 检查是否包含敏感关键词
		for _, keyword := range sensitiveKeywords {
			if strings.Contains(keyLower, keyword) {
				isSensitive = true
				break
			}
		}

		if isSensitive {
			// 脱敏处理：统一使用6个星号
			masked[key] = "******"
		} else {
			// 非敏感字段，检查是否为嵌套map
			if mapValue, ok := value.(map[string]interface{}); ok {
				masked[key] = maskSensitiveConfig(mapValue)
			} else {
				masked[key] = value
			}
		}
	}

	return masked
}
