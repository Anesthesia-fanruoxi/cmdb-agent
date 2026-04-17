package operator

import (
	"cmdb-agent/api/proxy"
	"cmdb-agent/common"
	"fmt"
	"go.uber.org/zap"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// DownloadBinary 下载二进制文件
func DownloadBinary(name, downloadURL string) (string, error) {
	common.Info("步骤1: 开始下载二进制文件",
		zap.String("name", name),
		zap.String("url", downloadURL))

	pluginDir := filepath.Join("./plugins", name)
	if err := os.MkdirAll(pluginDir, 0755); err != nil {
		return "", fmt.Errorf("创建插件目录失败: %v", err)
	}

	common.Info("插件目录创建成功", zap.String("path", pluginDir))

	var binaryPath string
	if runtime.GOOS == "windows" {
		binaryPath = filepath.Join(pluginDir, name+".exe")
	} else {
		binaryPath = filepath.Join(pluginDir, name)
	}

	common.Info("开始下载文件",
		zap.String("url", downloadURL),
		zap.String("target", binaryPath))

	resp, err := http.Get(downloadURL)
	if err != nil {
		return "", fmt.Errorf("下载请求失败: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("下载失败，HTTP状态码: %d", resp.StatusCode)
	}

	outFile, err := os.Create(binaryPath)
	if err != nil {
		return "", fmt.Errorf("创建文件失败: %v", err)
	}
	defer func() { _ = outFile.Close() }()

	size, err := io.Copy(outFile, resp.Body)
	if err != nil {
		return "", fmt.Errorf("写入文件失败: %v", err)
	}

	common.Info("文件下载完成",
		zap.String("path", binaryPath),
		zap.Int64("size", size))

	if runtime.GOOS != "windows" {
		if err := os.Chmod(binaryPath, 0755); err != nil {
			return "", fmt.Errorf("设置执行权限失败: %v", err)
		}
		common.Info("已设置执行权限", zap.String("path", binaryPath))
	}

	return binaryPath, nil
}

// StartBinaryService 启动二进制服务（使用systemd管理）
func StartBinaryService(name, binaryPath string, _ int, command string, _ map[string]interface{}, configFile string, _ proxy.Parameters) error {
	common.Info("步骤2: 开始启动二进制服务(systemd)",
		zap.String("name", name),
		zap.String("binary", binaryPath))

	pluginDir := filepath.Dir(binaryPath)

	if configFile != "" {
		configDir := "config"
		configFileName := "config.yaml"

		configPath := filepath.Join(pluginDir, configDir)
		if err := os.MkdirAll(configPath, 0755); err != nil {
			return fmt.Errorf("创建配置目录失败: %v", err)
		}

		configFilePath := filepath.Join(configPath, configFileName)
		if err := os.WriteFile(configFilePath, []byte(configFile), 0644); err != nil {
			return fmt.Errorf("写入配置文件失败: %v", err)
		}

		common.Info("配置文件创建成功",
			zap.String("path", configFilePath),
			zap.Int("size", len(configFile)))
	}

	var cmdArgs []string
	if command != "" {
		cmdArgs = strings.Fields(command)
		common.Info("使用command启动参数",
			zap.String("command", command),
			zap.Strings("args", cmdArgs))
	} else {
		common.Info("无启动参数，直接启动二进制")
	}

	absBinaryPath, err := filepath.Abs(binaryPath)
	if err != nil {
		return fmt.Errorf("获取绝对路径失败: %v", err)
	}

	absPluginDir, err := filepath.Abs(pluginDir)
	if err != nil {
		return fmt.Errorf("获取插件目录绝对路径失败: %v", err)
	}
	logFile := filepath.Join(absPluginDir, name+".log")

	env := map[string]string{
		"HOME":       "/root",
		"KUBECONFIG": "/root/.kube/config",
		"PATH":       "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	}

	service := &common.SystemdService{
		Name:        name,
		Description: fmt.Sprintf("CMDB Plugin: %s", name),
		WorkDir:     absPluginDir,
		BinaryPath:  absBinaryPath,
		Args:        cmdArgs,
		LogPath:     logFile,
		Restart:     "always",
		RestartSec:  10,
		MemoryLimit: "2G",
		CPUQuota:    "200%",
		LimitNOFILE: 65536,
		Environment: env,
		Wants:       []string{"cmdb-agent.service"},
	}

	common.Info("创建systemd service",
		zap.String("service_name", common.GetServiceName(name)),
		zap.String("binary", absBinaryPath),
		zap.String("workdir", absPluginDir),
		zap.String("logfile", logFile),
		zap.Strings("args", cmdArgs))

	if err := common.CreateSystemdService(service); err != nil {
		return fmt.Errorf("创建systemd service失败: %v", err)
	}

	if err := common.CreateLogrotateConfig(name, logFile); err != nil {
		common.Warn("创建logrotate配置失败，日志不会自动清理",
			zap.String("name", name),
			zap.Error(err))
	}

	if err := common.SystemctlEnable(name); err != nil {
		return fmt.Errorf("启用systemd service失败: %v", err)
	}

	if err := common.SystemctlStart(name); err != nil {
		return fmt.Errorf("启动systemd service失败: %v", err)
	}

	time.Sleep(2 * time.Second)
	if !common.SystemctlIsActive(name) {
		return fmt.Errorf("服务启动失败，未检测到运行状态")
	}

	common.Info("二进制服务启动成功(systemd)",
		zap.String("service", common.GetServiceName(name)),
		zap.String("log", logFile))

	return nil
}
