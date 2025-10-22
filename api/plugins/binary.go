package plugins

import (
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

// downloadBinary 下载二进制文件
func downloadBinary(name, downloadURL string) (string, error) {
	common.Info("步骤1: 开始下载二进制文件",
		zap.String("name", name),
		zap.String("url", downloadURL))

	// 创建插件目录
	pluginDir := filepath.Join("./plugins", name)
	if err := os.MkdirAll(pluginDir, 0755); err != nil {
		return "", fmt.Errorf("创建插件目录失败: %v", err)
	}

	common.Info("插件目录创建成功", zap.String("path", pluginDir))

	// 确定二进制文件路径（根据操作系统）
	var binaryPath string
	if runtime.GOOS == "windows" {
		binaryPath = filepath.Join(pluginDir, name+".exe")
	} else {
		binaryPath = filepath.Join(pluginDir, name)
	}

	common.Info("开始下载文件",
		zap.String("url", downloadURL),
		zap.String("target", binaryPath))

	// 发起HTTP请求下载文件
	resp, err := http.Get(downloadURL)
	if err != nil {
		return "", fmt.Errorf("下载请求失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("下载失败，HTTP状态码: %d", resp.StatusCode)
	}

	// 创建目标文件
	outFile, err := os.Create(binaryPath)
	if err != nil {
		return "", fmt.Errorf("创建文件失败: %v", err)
	}
	defer outFile.Close()

	// 写入文件内容
	size, err := io.Copy(outFile, resp.Body)
	if err != nil {
		return "", fmt.Errorf("写入文件失败: %v", err)
	}

	common.Info("文件下载完成",
		zap.String("path", binaryPath),
		zap.Int64("size", size))

	// 设置执行权限（Unix系统）
	if runtime.GOOS != "windows" {
		if err := os.Chmod(binaryPath, 0755); err != nil {
			return "", fmt.Errorf("设置执行权限失败: %v", err)
		}
		common.Info("已设置执行权限", zap.String("path", binaryPath))
	}

	return binaryPath, nil
}

// startBinaryService 启动二进制服务（使用systemd管理）
func startBinaryService(name, binaryPath string, port int, command string, config map[string]interface{}, params Parameters) error {
	common.Info("步骤2: 开始启动二进制服务(systemd)",
		zap.String("name", name),
		zap.String("binary", binaryPath))

	pluginDir := filepath.Dir(binaryPath)

	// 构建启动命令（仅支持command参数）
	var cmdArgs []string
	if command != "" {
		// 使用command指定的启动参数
		cmdArgs = strings.Fields(command)
		common.Info("使用command启动参数",
			zap.String("command", command),
			zap.Strings("args", cmdArgs))
	} else {
		// 无command时，直接启动，不传参数
		common.Info("无启动参数，直接启动二进制")
	}

	// 将二进制路径转换为绝对路径
	absBinaryPath, err := filepath.Abs(binaryPath)
	if err != nil {
		return fmt.Errorf("获取绝对路径失败: %v", err)
	}

	// 日志文件路径
	absPluginDir, _ := filepath.Abs(pluginDir)
	logFile := filepath.Join(absPluginDir, name+".log")

	// 构建systemd service配置
	service := &common.SystemdService{
		Name:        name,
		Description: fmt.Sprintf("CMDB Plugin: %s", name),
		// User字段留空，不指定用户（不要设置为空字符串）
		WorkDir:     absPluginDir,
		BinaryPath:  absBinaryPath,
		Args:        cmdArgs, // config已转为命令行参数
		LogPath:     logFile,
		Restart:     "always",
		RestartSec:  10,
		MemoryLimit: "1G",   // TODO: 从参数配置
		CPUQuota:    "200%", // TODO: 从参数配置
		LimitNOFILE: 65536,
		Environment: make(map[string]string), // 二进制插件不使用环境变量
		Wants:       []string{"cmdb-agent.service"},
	}

	common.Info("创建systemd service",
		zap.String("service_name", common.GetServiceName(name)),
		zap.String("binary", absBinaryPath),
		zap.String("workdir", absPluginDir),
		zap.String("logfile", logFile),
		zap.Strings("args", cmdArgs))

	// 1. 创建systemd service文件
	if err := common.CreateSystemdService(service); err != nil {
		return fmt.Errorf("创建systemd service失败: %v", err)
	}

	// 2. 创建logrotate配置（自动清理日志）
	if err := common.CreateLogrotateConfig(name, logFile); err != nil {
		common.Warn("创建logrotate配置失败，日志不会自动清理",
			zap.String("name", name),
			zap.Error(err))
		// 不返回错误，继续执行
	}

	// 3. 启用服务（开机自启）
	if err := common.SystemctlEnable(name); err != nil {
		return fmt.Errorf("启用systemd service失败: %v", err)
	}

	// 4. 启动服务
	if err := common.SystemctlStart(name); err != nil {
		return fmt.Errorf("启动systemd service失败: %v", err)
	}

	// 5. 等待服务启动并验证
	time.Sleep(2 * time.Second)
	if !common.SystemctlIsActive(name) {
		return fmt.Errorf("服务启动失败，未检测到运行状态")
	}

	common.Info("二进制服务启动成功(systemd)",
		zap.String("service", common.GetServiceName(name)),
		zap.String("log", logFile))

	return nil
}
