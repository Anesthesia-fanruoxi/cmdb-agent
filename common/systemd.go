package common

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"text/template"

	"go.uber.org/zap"
)

// SystemdService systemd服务配置
type SystemdService struct {
	Name        string            // 服务名称（不含cmdb-plugin-前缀）
	Description string            // 服务描述
	User        string            // 运行用户
	WorkDir     string            // 工作目录
	BinaryPath  string            // 二进制文件路径
	Args        []string          // 启动参数
	Environment map[string]string // 环境变量
	LogPath     string            // 日志文件路径
	Restart     string            // 重启策略 (always, on-failure, no)
	RestartSec  int               // 重启间隔（秒）
	MemoryLimit string            // 内存限制 (如 "1G")
	CPUQuota    string            // CPU限制 (如 "200%")
	LimitNOFILE int               // 文件描述符限制
	After       []string          // 依赖服务
	Wants       []string          // 弱依赖服务
}

// ServiceTemplate systemd service文件模板
const ServiceTemplate = `[Unit]
Description={{.Description}}
{{- if .After}}
After={{join .After " "}}
{{- else}}
After=network.target
{{- end}}
{{- if .Wants}}
Wants={{join .Wants " "}}
{{- end}}

[Service]
Type=simple
{{- if .User}}
User={{.User}}
{{- end}}
WorkingDirectory={{.WorkDir}}
ExecStart={{.BinaryPath}}{{range .Args}} {{.}}{{end}}
Restart={{if .Restart}}{{.Restart}}{{else}}always{{end}}
RestartSec={{if .RestartSec}}{{.RestartSec}}{{else}}10{{end}}
StandardOutput=append:{{.LogPath}}
StandardError=append:{{.LogPath}}

# 环境变量
{{- range $key, $value := .Environment}}
Environment="{{$key}}={{$value}}"
{{- end}}

# 资源限制
{{- if .LimitNOFILE}}
LimitNOFILE={{.LimitNOFILE}}
{{- else}}
LimitNOFILE=65536
{{- end}}
{{- if .MemoryLimit}}
MemoryLimit={{.MemoryLimit}}
{{- end}}
{{- if .CPUQuota}}
CPUQuota={{.CPUQuota}}
{{- end}}

[Install]
WantedBy=multi-user.target
`

// GenerateServiceFile 生成systemd service文件内容
func GenerateServiceFile(service *SystemdService) (string, error) {
	// 创建模板函数
	funcMap := template.FuncMap{
		"join": strings.Join,
	}

	// 解析模板
	tmpl, err := template.New("service").Funcs(funcMap).Parse(ServiceTemplate)
	if err != nil {
		return "", fmt.Errorf("解析模板失败: %v", err)
	}

	// 执行模板
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, service); err != nil {
		return "", fmt.Errorf("执行模板失败: %v", err)
	}

	return buf.String(), nil
}

// GetServiceName 获取完整的服务名
func GetServiceName(pluginName string) string {
	return fmt.Sprintf("cmdb-%s", pluginName)
}

// GetServicePath 获取service文件路径
func GetServicePath(pluginName string) string {
	return fmt.Sprintf("/etc/systemd/system/%s.service", GetServiceName(pluginName))
}

// CreateSystemdService 创建systemd service
func CreateSystemdService(service *SystemdService) error {
	Info("创建systemd service",
		zap.String("name", service.Name),
		zap.String("binary", service.BinaryPath))

	// 1. 生成service文件内容
	content, err := GenerateServiceFile(service)
	if err != nil {
		return fmt.Errorf("生成service文件失败: %v", err)
	}

	Info("生成的service文件内容",
		zap.String("content", content))

	// 2. 写入service文件（使用sudo tee）
	servicePath := GetServicePath(service.Name)
	cmd := exec.Command("sudo", "tee", servicePath)
	cmd.Stdin = strings.NewReader(content)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("写入service文件失败: %v, output: %s", err, string(output))
	}

	Info("Service文件写入成功",
		zap.String("path", servicePath))

	// 3. 重载systemd配置
	if err := SystemctlDaemonReload(); err != nil {
		return fmt.Errorf("重载systemd配置失败: %v", err)
	}

	return nil
}

// SystemctlDaemonReload 重载systemd配置
func SystemctlDaemonReload() error {
	cmd := exec.Command("sudo", "systemctl", "daemon-reload")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("daemon-reload失败: %v, output: %s", err, string(output))
	}
	Info("Systemd配置已重载")
	return nil
}

// SystemctlEnable 启用服务（开机自启）
func SystemctlEnable(pluginName string) error {
	serviceName := GetServiceName(pluginName)
	cmd := exec.Command("sudo", "systemctl", "enable", serviceName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("enable失败: %v, output: %s", err, string(output))
	}
	Info("服务已启用", zap.String("service", serviceName))
	return nil
}

// SystemctlDisable 禁用服务
func SystemctlDisable(pluginName string) error {
	serviceName := GetServiceName(pluginName)
	cmd := exec.Command("sudo", "systemctl", "disable", serviceName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("disable失败: %v, output: %s", err, string(output))
	}
	Info("服务已禁用", zap.String("service", serviceName))
	return nil
}

// SystemctlStart 启动服务
func SystemctlStart(pluginName string) error {
	serviceName := GetServiceName(pluginName)
	cmd := exec.Command("sudo", "systemctl", "start", serviceName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("start失败: %v, output: %s", err, string(output))
	}
	Info("服务已启动", zap.String("service", serviceName))
	return nil
}

// SystemctlStop 停止服务
func SystemctlStop(pluginName string) error {
	serviceName := GetServiceName(pluginName)
	cmd := exec.Command("sudo", "systemctl", "stop", serviceName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("stop失败: %v, output: %s", err, string(output))
	}
	Info("服务已停止", zap.String("service", serviceName))
	return nil
}

// SystemctlRestart 重启服务
func SystemctlRestart(pluginName string) error {
	serviceName := GetServiceName(pluginName)
	cmd := exec.Command("sudo", "systemctl", "restart", serviceName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("restart失败: %v, output: %s", err, string(output))
	}
	Info("服务已重启", zap.String("service", serviceName))
	return nil
}

// SystemctlStatus 查询服务状态
func SystemctlStatus(pluginName string) (string, error) {
	serviceName := GetServiceName(pluginName)
	cmd := exec.Command("systemctl", "status", serviceName)
	output, err := cmd.CombinedOutput()
	// status命令在服务未运行时也会返回错误，所以不检查err
	return string(output), err
}

// SystemctlIsActive 检查服务是否活跃
func SystemctlIsActive(pluginName string) bool {
	serviceName := GetServiceName(pluginName)
	cmd := exec.Command("systemctl", "is-active", serviceName)
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(output)) == "active"
}

// DeleteSystemdService 删除systemd service
func DeleteSystemdService(pluginName string) error {
	serviceName := GetServiceName(pluginName)
	servicePath := GetServicePath(pluginName)

	Info("删除systemd service",
		zap.String("service", serviceName),
		zap.String("path", servicePath))

	// 1. 停止服务
	SystemctlStop(pluginName) // 忽略错误

	// 2. 禁用服务
	SystemctlDisable(pluginName) // 忽略错误

	// 3. 删除service文件
	cmd := exec.Command("sudo", "rm", "-f", servicePath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("删除service文件失败: %v, output: %s", err, string(output))
	}

	// 4. 删除logrotate配置
	DeleteLogrotateConfig(pluginName) // 忽略错误

	// 5. 重载systemd配置
	if err := SystemctlDaemonReload(); err != nil {
		return fmt.Errorf("重载systemd配置失败: %v", err)
	}

	Info("Service已删除", zap.String("service", serviceName))
	return nil
}

// LogrotateTemplate logrotate配置模板
const LogrotateTemplate = `# Logrotate configuration for CMDB plugin: {{.PluginName}}
{{.LogPath}} {
    daily              # 每天轮转
    rotate 7           # 保留7天日志
    missingok          # 日志文件不存在不报错
    notifempty         # 空文件不轮转
    compress           # 压缩旧日志
    delaycompress      # 延迟压缩（下次轮转时压缩）
    copytruncate       # 截断而非移动（适合持续写入的日志）
    dateext            # 使用日期作为后缀
    dateformat -%Y%m%d # 日期格式：20231020
}
`

// CreateLogrotateConfig 创建logrotate配置
func CreateLogrotateConfig(pluginName, logPath string) error {
	Info("创建logrotate配置",
		zap.String("plugin", pluginName),
		zap.String("log", logPath))

	// 1. 生成配置内容
	tmpl, err := template.New("logrotate").Parse(LogrotateTemplate)
	if err != nil {
		return fmt.Errorf("解析logrotate模板失败: %v", err)
	}

	var buf bytes.Buffer
	data := map[string]string{
		"PluginName": pluginName,
		"LogPath":    logPath,
	}
	if err := tmpl.Execute(&buf, data); err != nil {
		return fmt.Errorf("生成logrotate配置失败: %v", err)
	}

	// 2. 写入配置文件
	configPath := fmt.Sprintf("/etc/logrotate.d/cmdb-%s", pluginName)
	cmd := exec.Command("sudo", "tee", configPath)
	cmd.Stdin = strings.NewReader(buf.String())

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("写入logrotate配置失败: %v, output: %s", err, string(output))
	}

	Info("Logrotate配置已创建", zap.String("path", configPath))
	return nil
}

// DeleteLogrotateConfig 删除logrotate配置
func DeleteLogrotateConfig(pluginName string) error {
	configPath := fmt.Sprintf("/etc/logrotate.d/cmdb-%s", pluginName)

	cmd := exec.Command("sudo", "rm", "-f", configPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("删除logrotate配置失败: %v, output: %s", err, string(output))
	}

	Info("Logrotate配置已删除", zap.String("path", configPath))
	return nil
}
