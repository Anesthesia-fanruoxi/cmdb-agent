package plugins

import (
	"cmdb-agent/common"
	"encoding/json"
	"fmt"
	"go.uber.org/zap"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Parameters 插件参数配置
type Parameters struct {
	// 容器类型参数
	ContainerPort int `json:"container_port"` // 容器内服务端口（可选，默认和port相同）

	// 二进制类型参数
	ConfigDir  string `json:"config_dir"`  // 配置目录名称，默认"config"
	ConfigFile string `json:"config_file"` // 配置文件名称，默认"config.json"
}

// InstallRequest 插件安装请求参数
type InstallRequest struct {
	Name        string                 `json:"name"`
	Version     string                 `json:"version"`
	Category    string                 `json:"category"`     // container 或 binary
	Image       string                 `json:"image"`        // 容器类型：镜像地址
	DownloadURL string                 `json:"download_url"` // 二进制类型：下载地址
	Command     string                 `json:"command"`      // 执行命令
	Port        int                    `json:"port"`         // 端口
	Config      map[string]interface{} `json:"config"`       // 环境变量/配置参数
	Parameters  Parameters             `json:"parameters"`   // 类型特定参数
}

// InstallHandler 插件安装处理函数
func InstallHandler(w http.ResponseWriter, r *http.Request) {
	// 只允许POST请求
	if r.Method != http.MethodPost {
		common.Warn("请求方法不允许",
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path))
		common.RespondMethodNotAllowed(w, "只允许POST请求")
		return
	}

	common.Info("收到插件安装请求",
		zap.String("remote", r.RemoteAddr),
		zap.String("user_agent", r.UserAgent()))

	// 读取请求体
	body, err := io.ReadAll(r.Body)
	if err != nil {
		common.Error("读取请求体失败", zap.Error(err))
		common.RespondBadRequest(w, "读取请求体失败")
		return
	}
	defer r.Body.Close()

	common.Debug("请求体内容", zap.String("body", string(body)))

	// 解析JSON
	var req InstallRequest
	if err := json.Unmarshal(body, &req); err != nil {
		common.Error("解析JSON失败",
			zap.Error(err),
			zap.String("body", string(body)))
		common.RespondBadRequest(w, "JSON格式错误")
		return
	}

	// 打印解析后的参数
	common.Info("解析插件安装参数",
		zap.String("name", req.Name),
		zap.String("version", req.Version),
		zap.String("category", req.Category),
		zap.String("image", req.Image),
		zap.String("download_url", req.DownloadURL),
		zap.String("command", req.Command),
		zap.Int("port", req.Port),
		zap.Any("config", req.Config),
		zap.Any("parameters", req.Parameters))

	// 验证必填参数
	if req.Name == "" {
		common.Warn("缺少必填参数: name")
		common.RespondBadRequest(w, "缺少必填参数: name")
		return
	}

	if req.Version == "" {
		common.Warn("缺少必填参数: version")
		common.RespondBadRequest(w, "缺少必填参数: version")
		return
	}

	if req.Category == "" {
		common.Warn("缺少必填参数: category")
		common.RespondBadRequest(w, "缺少必填参数: category")
		return
	}

	// 验证category类型
	if req.Category != "container" && req.Category != "binary" {
		common.Warn("不支持的插件类型",
			zap.String("category", req.Category))
		common.RespondBadRequest(w, "category必须是 container 或 binary")
		return
	}

	// 验证容器类型必填参数
	if req.Category == "container" && req.Image == "" {
		common.Warn("容器类型缺少image参数")
		common.RespondBadRequest(w, "容器类型必须提供image参数")
		return
	}

	// 验证二进制类型必填参数
	if req.Category == "binary" && req.DownloadURL == "" {
		common.Warn("二进制类型缺少download_url参数")
		common.RespondBadRequest(w, "二进制类型必须提供download_url参数")
		return
	}

	// 验证或提取端口号（二进制插件优先从command提取）
	var finalPort int

	if req.Category == "binary" && req.Command != "" {
		// 二进制插件：优先从command中提取端口
		extractedPort := extractPortFromCommand(req.Command)
		if extractedPort > 0 {
			finalPort = extractedPort
			common.Info("从command参数中提取端口号（优先）",
				zap.String("command", req.Command),
				zap.Int("port", finalPort))
		} else if req.Port > 0 && req.Port <= 65535 {
			// command中没有端口，使用port参数
			finalPort = req.Port
			common.Info("使用port参数",
				zap.Int("port", finalPort))
		}
	} else {
		// 容器插件或二进制无command：直接使用port参数
		finalPort = req.Port
	}

	// 验证最终端口号
	if finalPort <= 0 || finalPort > 65535 {
		common.Warn("端口号无效",
			zap.Int("port", finalPort),
			zap.String("command", req.Command))
		common.RespondBadRequest(w, "必须提供有效的port参数（1-65535），或在command中指定端口")
		return
	}

	// 更新请求中的端口号
	req.Port = finalPort

	// 检查端口是否被占用
	if isPortInUse(req.Port) {
		common.Warn("端口已被占用",
			zap.Int("port", req.Port))
		common.RespondBadRequest(w, fmt.Sprintf("端口 %d 已被占用", req.Port))
		return
	}
	common.Info("端口检查通过", zap.Int("port", req.Port))

	// 设置默认值
	if req.Category == "binary" {
		// 二进制类型默认值
		if req.Parameters.ConfigDir == "" {
			req.Parameters.ConfigDir = "config"
		}
		if req.Parameters.ConfigFile == "" {
			req.Parameters.ConfigFile = "config.json"
		}
	}

	common.Info("参数验证通过，准备安装插件",
		zap.String("name", req.Name),
		zap.String("category", req.Category))

	// 根据类型执行安装
	var (
		result     map[string]interface{}
		installErr error
	)

	if req.Category == "container" {
		result, installErr = installContainerPlugin(req)
	} else if req.Category == "binary" {
		result, installErr = installBinaryPlugin(req)
	}

	if installErr != nil {
		common.Error("插件安装失败",
			zap.String("name", req.Name),
			zap.String("category", req.Category),
			zap.Error(installErr))
		common.RespondInternalError(w, "安装失败: "+installErr.Error())
		return
	}

	common.Info("插件安装成功",
		zap.String("name", req.Name),
		zap.String("category", req.Category))

	// 返回成功响应
	common.RespondSuccess(w, result)
}

// installBinaryPlugin 安装二进制类型插件
func installBinaryPlugin(req InstallRequest) (map[string]interface{}, error) {
	common.Info("开始安装二进制插件",
		zap.String("name", req.Name),
		zap.String("download_url", req.DownloadURL))

	// 步骤1: 下载二进制文件
	binaryPath, err := downloadBinary(req.Name, req.DownloadURL)
	if err != nil {
		return nil, err
	}

	common.Info("二进制文件下载成功",
		zap.String("path", binaryPath))

	// 步骤2: 启动二进制服务（使用systemd）
	if err := startBinaryService(req.Name, binaryPath, req.Port, req.Command, req.Config, req.Parameters); err != nil {
		return nil, err
	}

	common.Info("二进制服务启动成功(systemd)",
		zap.String("name", req.Name),
		zap.String("service", common.GetServiceName(req.Name)))

	// 保存插件记录到注册表
	record := &PluginRecord{
		Name:        req.Name,
		Version:     req.Version,
		Category:    "binary",
		DownloadURL: req.DownloadURL,
		BinaryPath:  binaryPath,
		Port:        req.Port,
		Config:      req.Config,
		Parameters:  req.Parameters,
	}

	if err := AddPluginRecord(record); err != nil {
		common.Warn("保存插件记录失败", zap.Error(err))
	}

	return map[string]interface{}{
		"name":        req.Name,
		"version":     req.Version,
		"category":    "binary",
		"binary_path": binaryPath,
		"service":     common.GetServiceName(req.Name),
		"port":        req.Port,
		"status":      "running",
	}, nil
}

// installContainerPlugin 安装容器类型插件
func installContainerPlugin(req InstallRequest) (map[string]interface{}, error) {
	common.Info("开始安装容器插件",
		zap.String("name", req.Name),
		zap.String("image", req.Image))

	// 步骤1: 拉取镜像
	if err := pullDockerImage(req.Image); err != nil {
		return nil, err
	}

	common.Info("镜像拉取成功",
		zap.String("image", req.Image))

	// 步骤2: 启动容器服务
	containerID, err := startContainerService(req.Name, req.Image, req.Port, req.Command, req.Config, req.Parameters)
	if err != nil {
		return nil, err
	}

	common.Info("容器服务启动成功",
		zap.String("name", req.Name),
		zap.String("container_id", containerID))

	// 保存插件记录到注册表
	record := &PluginRecord{
		Name:          req.Name,
		Version:       req.Version,
		Category:      "container",
		Image:         req.Image,
		ContainerID:   containerID,
		Port:          req.Port,
		ContainerPort: req.Parameters.ContainerPort,
		Config:        req.Config,
		Parameters:    req.Parameters,
	}

	if err := AddPluginRecord(record); err != nil {
		common.Warn("保存插件记录失败", zap.Error(err))
	}

	return map[string]interface{}{
		"name":         req.Name,
		"version":      req.Version,
		"category":     "container",
		"image":        req.Image,
		"container_id": containerID,
		"port":         req.Port,
		"status":       "running",
	}, nil
}

// isPortInUse 检查端口是否被占用
func isPortInUse(port int) bool {
	address := fmt.Sprintf(":%d", port)
	listener, err := net.Listen("tcp", address)
	if err != nil {
		// 端口被占用
		return true
	}
	listener.Close()
	return false
}

// checkPortWithTimeout 带超时的端口连接检查
func checkPortWithTimeout(port int, timeout time.Duration) bool {
	address := fmt.Sprintf("localhost:%d", port)
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// maskSensitiveConfigForLog 对日志中的配置进行脱敏（与pluginsList中的函数相同）
func maskSensitiveConfigForLog(config map[string]interface{}) map[string]interface{} {
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
				masked[key] = maskSensitiveConfigForLog(mapValue)
			} else {
				masked[key] = value
			}
		}
	}

	return masked
}

// extractPortFromCommand 从command参数中提取端口号
// 支持格式：-port 3037, --port 3037, -port=3037, --port=3037, -p 3037, -p=3037
func extractPortFromCommand(command string) int {
	// 去除首尾空格
	command = strings.TrimSpace(command)
	if command == "" {
		return 0
	}

	// 分割命令行参数
	parts := strings.Fields(command)

	// 端口参数的可能形式
	portFlags := []string{"-port", "--port", "-p"}

	for i, part := range parts {
		// 情况1: -port=3037 或 --port=3037
		for _, flag := range portFlags {
			if strings.HasPrefix(part, flag+"=") {
				portStr := strings.TrimPrefix(part, flag+"=")
				if port, err := strconv.Atoi(portStr); err == nil && port > 0 && port <= 65535 {
					return port
				}
			}
		}

		// 情况2: -port 3037 或 --port 3037（下一个参数是端口号）
		for _, flag := range portFlags {
			if part == flag && i+1 < len(parts) {
				if port, err := strconv.Atoi(parts[i+1]); err == nil && port > 0 && port <= 65535 {
					return port
				}
			}
		}
	}

	return 0
}
