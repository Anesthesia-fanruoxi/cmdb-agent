package operator

import (
	"cmdb-agent/api/proxy"
	"cmdb-agent/common"
	"context"
	"fmt"
	"go.uber.org/zap"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

// safeContainerID 安全截取容器ID前12位，避免空字符串panic
func safeContainerID(id string) string {
	if len(id) <= 12 {
		return id
	}
	return id[:12]
}

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

// OperatorHandler 插件操作接口（启动/停止/重启）
func OperatorHandler(w http.ResponseWriter, r *http.Request) {
	common.Info("收到插件操作请求",
		zap.String("method", r.Method),
		zap.String("path", r.URL.Path))

	if r.Method != http.MethodPut {
		common.RespondMethodNotAllowed(w, "只允许PUT请求")
		return
	}

	name := r.URL.Query().Get("name")
	action := r.URL.Query().Get("action")

	if name == "" {
		common.RespondError(w, http.StatusBadRequest, "缺少插件名称参数")
		return
	}
	if action == "" || (action != "start" && action != "stop" && action != "restart") {
		common.RespondError(w, http.StatusBadRequest, "无效的操作类型，支持: start, stop, restart")
		return
	}

	record, err := proxy.GetPluginRecord(name)
	if err != nil {
		common.Error("查询插件记录失败", zap.Error(err))
		common.RespondError(w, http.StatusInternalServerError,
			"查询插件记录失败: "+err.Error())
		return
	}
	if record == nil {
		common.RespondError(w, http.StatusNotFound, "插件不存在: "+name)
		return
	}

	var result string
	if record.Category == "container" {
		result, err = OperateContainer(record, action)
	} else if record.Category == "binary" {
		result, err = OperateBinary(record, action)
	} else {
		common.RespondError(w, http.StatusBadRequest, "不支持的插件类型: "+record.Category)
		return
	}

	if err != nil {
		common.Error("插件操作失败",
			zap.String("name", name),
			zap.String("action", action),
			zap.Error(err))
		common.RespondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if err := proxy.AddPluginRecord(record); err != nil {
		common.Warn("更新插件操作时间失败",
			zap.String("name", name),
			zap.Error(err))
	}

	common.Info("插件操作成功",
		zap.String("name", name),
		zap.String("action", action))

	common.RespondSuccess(w, map[string]interface{}{
		"name":    name,
		"action":  action,
		"result":  result,
		"message": fmt.Sprintf("插件 %s 操作成功", action),
	})
}

// OperateContainer 操作容器类型插件（公开，供 update 调用）
func OperateContainer(record *proxy.PluginRecord, action string) (string, error) {
	containerName := fmt.Sprintf("cmdb-%s", record.Name)

	common.Info("开始操作容器",
		zap.String("container", containerName),
		zap.String("action", action))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var cmd *exec.Cmd
	switch action {
	case "start":
		cmd = exec.CommandContext(ctx, "docker", "start", containerName)
	case "stop":
		cmd = exec.CommandContext(ctx, "docker", "stop", containerName)
	case "restart":
		cmd = exec.CommandContext(ctx, "docker", "restart", containerName)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("操作超时: %s", action)
		}
		return "", fmt.Errorf("执行 docker %s 失败: %v, 输出: %s", action, err, string(output))
	}

	result := strings.TrimSpace(string(output))
	time.Sleep(500 * time.Millisecond)

	common.Info("容器操作完成",
		zap.String("container", containerName),
		zap.String("action", action),
		zap.String("result", result))

	return result, nil
}

// OperateBinary 操作二进制类型插件（公开，供 update 调用）
func OperateBinary(record *proxy.PluginRecord, action string) (string, error) {
	serviceName := common.GetServiceName(record.Name)

	common.Info("开始操作二进制插件(systemd)",
		zap.String("name", record.Name),
		zap.String("service", serviceName),
		zap.String("action", action))

	var err error
	switch action {
	case "start":
		err = common.SystemctlStart(record.Name)
	case "stop":
		err = common.SystemctlStop(record.Name)
	case "restart":
		err = common.SystemctlRestart(record.Name)
	default:
		return "", fmt.Errorf("不支持的操作: %s", action)
	}

	if err != nil {
		return "", err
	}

	time.Sleep(500 * time.Millisecond)

	isActive := common.SystemctlIsActive(record.Name)
	status := "stopped"
	if isActive {
		status = "running"
	}

	common.Info("二进制插件操作完成",
		zap.String("name", record.Name),
		zap.String("action", action),
		zap.String("status", status))

	return fmt.Sprintf("服务 %s 操作成功，当前状态: %s", serviceName, status), nil
}

// DetailHandler 查询单一插件详情
func DetailHandler(w http.ResponseWriter, r *http.Request) {
	common.Info("收到查询插件详情请求",
		zap.String("method", r.Method),
		zap.String("path", r.URL.Path))

	if r.Method != http.MethodGet {
		common.RespondMethodNotAllowed(w, "只允许GET请求")
		return
	}

	name := r.URL.Query().Get("name")
	if name == "" {
		common.RespondError(w, http.StatusBadRequest, "缺少插件名称参数")
		return
	}

	record, err := proxy.GetPluginRecord(name)
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

	info := &PluginInfo{
		Name:          record.Name,
		Version:       record.Version,
		Category:      record.Category,
		Port:          record.Port,
		ContainerPort: record.ContainerPort,
		Config:        record.Config,
		InstalledAt:   record.InstalledAt,
	}

	if record.Category == "container" {
		info.Status, info.Uptime = getContainerStatus(record.ContainerID)
	} else if record.Category == "binary" {
		info.Status, info.Uptime = getBinaryStatusFromSystemd(record.Name)
	}

	common.Info("查询插件详情成功",
		zap.String("name", name),
		zap.String("status", info.Status))

	common.RespondSuccess(w, info)
}

// ListHandler 查询插件列表
func ListHandler(w http.ResponseWriter, r *http.Request) {
	common.Info("收到查询插件列表请求",
		zap.String("method", r.Method),
		zap.String("path", r.URL.Path))

	if r.Method != http.MethodGet {
		common.RespondMethodNotAllowed(w, "只允许GET请求")
		return
	}

	category := r.URL.Query().Get("category")
	status := r.URL.Query().Get("status")
	name := r.URL.Query().Get("name")

	records, err := proxy.ListPluginRecords()
	if err != nil {
		common.Error("读取插件注册表失败", zap.Error(err))
		common.RespondError(w, http.StatusInternalServerError,
			"读取插件列表失败: "+err.Error())
		return
	}

	var plugins []*PluginInfo
	for _, record := range records {
		if category != "" && record.Category != category {
			continue
		}
		if name != "" && !strings.Contains(record.Name, name) {
			continue
		}

		info := &PluginInfo{
			Name:          record.Name,
			Version:       record.Version,
			Category:      record.Category,
			Port:          record.Port,
			ContainerPort: record.ContainerPort,
			Config:        record.Config,
			InstalledAt:   record.InstalledAt,
		}

		if record.Category == "container" {
			info.Status, info.Uptime = getContainerStatus(record.ContainerID)
		} else if record.Category == "binary" {
			info.Status, info.Uptime = getBinaryStatusFromSystemd(record.Name)
		}

		if status != "" && info.Status != status {
			continue
		}

		plugins = append(plugins, info)
	}

	common.Info("查询插件列表成功", zap.Int("total", len(plugins)))

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

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "docker", "inspect",
		"--format", "{{.State.Status}}|{{.State.StartedAt}}", containerID)

	output, err := cmd.Output()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			common.Warn("查询容器状态超时", zap.String("container_id", containerID))
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

	var uptime string
	if status == "running" {
		startTime, err := time.Parse(time.RFC3339Nano, startedAt)
		if err == nil {
			uptime = proxy.FormatDuration(time.Since(startTime))
		}
	}

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
	uptime := getServiceUptime(pluginName)
	return "running", uptime
}

// getServiceUptime 获取systemd服务的运行时间
func getServiceUptime(pluginName string) string {
	serviceName := common.GetServiceName(pluginName)

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

	line := strings.TrimSpace(string(output))
	if !strings.HasPrefix(line, "ActiveEnterTimestamp=") {
		return ""
	}

	timestampStr := strings.TrimPrefix(line, "ActiveEnterTimestamp=")
	if timestampStr == "" || timestampStr == "n/a" {
		return ""
	}

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

	return proxy.FormatDuration(time.Since(startTime))
}
