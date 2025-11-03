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
	Config        map[string]interface{} `json:"config,omitempty"`
	InstalledAt   time.Time              `json:"installed_at"`
}

// PluginDetailHandler 查询单一插件详情
func PluginDetailHandler(w http.ResponseWriter, r *http.Request) {
	common.Info("收到查询插件详情请求",
		zap.String("method", r.Method),
		zap.String("path", r.URL.Path))

	// 只允许GET请求
	if r.Method != http.MethodGet {
		common.RespondMethodNotAllowed(w, "只允许GET请求")
		return
	}

	// 获取插件名称参数
	name := r.URL.Query().Get("name")
	if name == "" {
		common.RespondError(w, http.StatusBadRequest, "缺少插件名称参数")
		return
	}

	// 查询插件记录
	record, err := GetPluginRecord(name)
	if err != nil {
		common.Error("查询插件记录失败", zap.Error(err))
		common.RespondError(w, http.StatusInternalServerError,
			"查询插件记录失败: "+err.Error())
		return
	}

	if record == nil {
		common.RespondError(w, http.StatusNotFound,
			fmt.Sprintf("插件不存在: %s", name))
		return
	}

	// 构建插件信息
	info := &PluginInfo{
		Name:          record.Name,
		Version:       record.Version,
		Category:      record.Category,
		Port:          record.Port,
		ContainerPort: record.ContainerPort,
		Config:        record.Config,
		InstalledAt:   record.InstalledAt,
	}

	// 根据类型查询状态
	if record.Category == "container" {
		info.Status, info.Uptime = getContainerStatus(record.ContainerID)
	} else if record.Category == "binary" {
		info.Status, info.Uptime = getBinaryStatusFromSystemd(record.Name)
	}

	// 返回结果
	common.Info("查询插件详情成功",
		zap.String("name", name),
		zap.String("status", info.Status))

	common.RespondSuccess(w, info)
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
			Config:        record.Config,
			InstalledAt:   record.InstalledAt,
		}

		// 根据类型查询状态
		if record.Category == "container" {
			info.Status, info.Uptime = getContainerStatus(record.ContainerID)
		} else if record.Category == "binary" {
			info.Status, info.Uptime = getBinaryStatusFromSystemd(record.Name)
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
		"total":         len(plugins),
		"plugins":       plugins,
		"agent_version": common.GetVersion(),
		"eip":           common.GetPublicIP(),
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

// getBinaryStatusFromSystemd 从systemd查询二进制插件状态和运行时间
func getBinaryStatusFromSystemd(pluginName string) (string, string) {
	if !common.SystemctlIsActive(pluginName) {
		return "stopped", ""
	}

	// 服务运行中，获取启动时间
	uptime := getServiceUptime(pluginName)
	return "running", uptime
}

// getServiceUptime 获取systemd服务的运行时间
func getServiceUptime(pluginName string) string {
	serviceName := common.GetServiceName(pluginName)

	// 使用systemctl show获取服务属性
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "systemctl", "show", serviceName, "--property=ActiveEnterTimestamp")
	output, err := cmd.Output()
	if err != nil {
		common.Debug("获取服务启动时间失败",
			zap.String("service", serviceName),
			zap.Error(err))
		return ""
	}

	// 解析输出：ActiveEnterTimestamp=Thu 2025-10-24 14:00:55 CST
	line := strings.TrimSpace(string(output))
	if !strings.HasPrefix(line, "ActiveEnterTimestamp=") {
		return ""
	}

	timestampStr := strings.TrimPrefix(line, "ActiveEnterTimestamp=")
	if timestampStr == "" || timestampStr == "n/a" {
		return ""
	}

	// 解析时间格式：Thu 2025-10-24 14:00:55 CST
	// systemd使用的是RFC1123Z类似格式
	layouts := []string{
		"Mon 2006-01-02 15:04:05 MST",
		time.RFC1123Z,
		time.RFC1123,
	}

	var startTime time.Time
	for _, layout := range layouts {
		if t, err := time.Parse(layout, timestampStr); err == nil {
			startTime = t
			break
		}
	}

	if startTime.IsZero() {
		common.Debug("解析服务启动时间失败",
			zap.String("service", serviceName),
			zap.String("timestamp", timestampStr))
		return ""
	}

	// 计算运行时间
	duration := time.Since(startTime)
	return formatDuration(duration)
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
