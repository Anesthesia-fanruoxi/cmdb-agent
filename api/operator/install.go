package operator

import (
	"cmdb-agent/api/proxy"
	"cmdb-agent/common"
	"encoding/json"
	"fmt"
	"go.uber.org/zap"
	"io"
	"net"
	"net/http"
)

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
	ConfigFile  string                 `json:"config_file"`  // 配置文件内容（二进制插件）
	Parameters  proxy.Parameters       `json:"parameters"`   // 类型特定参数
}

// InstallHandler 插件安装处理函数
func InstallHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		common.Warn("请求方法不允许",
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path))
		common.RespondMethodNotAllowed(w, "只允许POST请求")
		return
	}

	realClientIP := proxy.GetRealClientIP(r.Header.Get("X-Real-IP"), r.Header.Get("X-Forwarded-For"))
	if realClientIP == "" {
		if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
			realClientIP = host
		} else {
			realClientIP = r.RemoteAddr
		}
	}

	common.Info("收到插件安装请求",
		zap.String("client_ip", realClientIP),
		zap.String("remote_addr", r.RemoteAddr))

	body, err := io.ReadAll(r.Body)
	if err != nil {
		common.Error("读取请求体失败", zap.Error(err))
		common.RespondBadRequest(w, "读取请求体失败")
		return
	}
	defer func() { _ = r.Body.Close() }()

	var req InstallRequest
	if err := json.Unmarshal(body, &req); err != nil {
		common.Error("解析JSON失败",
			zap.Error(err),
			zap.String("body", string(body)))
		common.RespondBadRequest(w, "JSON格式错误")
		return
	}

	common.Info("解析插件安装参数",
		zap.String("name", req.Name),
		zap.String("version", req.Version),
		zap.String("category", req.Category),
		zap.String("image", req.Image),
		zap.String("download_url", req.DownloadURL),
		zap.String("command", req.Command),
		zap.Int("port", req.Port),
		zap.Any("config", req.Config),
		zap.Int("config_file_length", len(req.ConfigFile)),
		zap.Any("parameters", req.Parameters))

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
	if req.Category != "container" && req.Category != "binary" {
		common.Warn("不支持的插件类型", zap.String("category", req.Category))
		common.RespondBadRequest(w, "category必须是 container 或 binary")
		return
	}
	if req.Category == "container" && req.Image == "" {
		common.Warn("容器类型缺少image参数")
		common.RespondBadRequest(w, "容器类型必须提供image参数")
		return
	}
	if req.Category == "binary" && req.DownloadURL == "" {
		common.Warn("二进制类型缺少download_url参数")
		common.RespondBadRequest(w, "二进制类型必须提供download_url参数")
		return
	}

	var finalPort int
	if req.Category == "binary" && req.Command != "" {
		extractedPort := proxy.ExtractPortFromCommand(req.Command)
		if extractedPort > 0 {
			finalPort = extractedPort
			common.Info("从command参数中提取端口号（优先）",
				zap.String("command", req.Command),
				zap.Int("port", finalPort))
		} else if req.Port > 0 && req.Port <= 65535 {
			finalPort = req.Port
			common.Info("使用port参数", zap.Int("port", finalPort))
		}
	} else {
		finalPort = req.Port
	}

	if finalPort <= 0 || finalPort > 65535 {
		common.Warn("端口号无效",
			zap.Int("port", finalPort),
			zap.String("command", req.Command))
		common.RespondBadRequest(w, "必须提供有效的port参数（1-65535），或在command中指定端口")
		return
	}

	req.Port = finalPort

	if proxy.IsPortInUse(req.Port) {
		common.Warn("端口已被占用", zap.Int("port", req.Port))
		common.RespondBadRequest(w, fmt.Sprintf("端口 %d 已被占用", req.Port))
		return
	}
	common.Info("端口检查通过", zap.Int("port", req.Port))

	common.Info("参数验证通过，准备安装插件",
		zap.String("name", req.Name),
		zap.String("category", req.Category))

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

	common.RespondSuccess(w, result)
}

// installBinaryPlugin 安装二进制类型插件
func installBinaryPlugin(req InstallRequest) (map[string]interface{}, error) {
	common.Info("开始安装二进制插件",
		zap.String("name", req.Name),
		zap.String("download_url", req.DownloadURL))

	binaryPath, err := DownloadBinary(req.Name, req.DownloadURL)
	if err != nil {
		return nil, err
	}

	common.Info("二进制文件下载成功", zap.String("path", binaryPath))

	if err := StartBinaryService(req.Name, binaryPath, req.Port, req.Command, req.Config, req.ConfigFile, req.Parameters); err != nil {
		return nil, err
	}

	common.Info("二进制服务启动成功(systemd)",
		zap.String("name", req.Name),
		zap.String("service", common.GetServiceName(req.Name)))

	record := &proxy.PluginRecord{
		Name:        req.Name,
		Version:     req.Version,
		Category:    "binary",
		DownloadURL: req.DownloadURL,
		BinaryPath:  binaryPath,
		Command:     req.Command,
		Port:        req.Port,
		Config:      req.Config,
		Parameters:  req.Parameters,
	}

	if err := proxy.AddPluginRecord(record); err != nil {
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

	if err := PullDockerImage(req.Image); err != nil {
		return nil, err
	}

	common.Info("镜像拉取成功", zap.String("image", req.Image))

	containerID, err := StartContainerService(req.Name, req.Image, req.Port, req.Command, req.Config, req.Parameters)
	if err != nil {
		return nil, err
	}

	common.Info("容器服务启动成功",
		zap.String("name", req.Name),
		zap.String("container_id", containerID))

	record := &proxy.PluginRecord{
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

	if err := proxy.AddPluginRecord(record); err != nil {
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
