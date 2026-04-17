package proxy

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// GetRealClientIP 从请求头获取真实客户端IP
func GetRealClientIP(realIP, forwardedFor string) string {
	if realIP != "" {
		return strings.TrimSpace(realIP)
	}

	if forwardedFor != "" {
		ips := strings.Split(forwardedFor, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	return ""
}

// IsHopByHopHeader 判断是否为hop-by-hop header，这些header不应该在代理时转发
func IsHopByHopHeader(header string) bool {
	hopByHopHeaders := []string{
		"Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Te",
		"Trailers",
		"Transfer-Encoding",
		"Upgrade",
	}

	headerLower := strings.ToLower(header)
	for _, h := range hopByHopHeaders {
		if strings.ToLower(h) == headerLower {
			return true
		}
	}
	return false
}

// IsPlainTextRequest 判断请求路径是否为明文（不需要解密）
func IsPlainTextRequest(path string) bool {
	plainTextPaths := []string{
		"/update",
		"/health",
		"/ping",
		"/api/upload",
	}

	for _, plainPath := range plainTextPaths {
		if path == plainPath ||
			strings.HasPrefix(path, plainPath+"/") ||
			strings.HasPrefix(path, plainPath+"?") {
			return true
		}
	}

	return false
}

// MaskSensitiveConfigForLog 对日志中的配置进行脱敏
func MaskSensitiveConfigForLog(config map[string]interface{}) map[string]interface{} {
	if config == nil {
		return nil
	}

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

		for _, keyword := range sensitiveKeywords {
			if strings.Contains(keyLower, keyword) {
				isSensitive = true
				break
			}
		}

		if isSensitive {
			masked[key] = "******"
		} else {
			if mapValue, ok := value.(map[string]interface{}); ok {
				masked[key] = MaskSensitiveConfigForLog(mapValue)
			} else {
				masked[key] = value
			}
		}
	}

	return masked
}

// ExtractPortFromCommand 从command参数中提取端口号
// 支持格式：-port 3037, --port 3037, -port=3037, --port=3037, -p 3037, -p=3037
func ExtractPortFromCommand(command string) int {
	command = strings.TrimSpace(command)
	if command == "" {
		return 0
	}

	parts := strings.Fields(command)
	portFlags := []string{"-port", "--port", "-p"}

	for i, part := range parts {
		for _, flag := range portFlags {
			if strings.HasPrefix(part, flag+"=") {
				portStr := strings.TrimPrefix(part, flag+"=")
				if port, err := strconv.Atoi(portStr); err == nil && port > 0 && port <= 65535 {
					return port
				}
			}
		}

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

// IsPortInUse 检查端口是否被占用
func IsPortInUse(port int) bool {
	address := fmt.Sprintf(":%d", port)
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return true
	}
	_ = listener.Close()
	return false
}

// FormatDuration 格式化时间间隔
func FormatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	} else if d < time.Hour {
		return fmt.Sprintf("%dm%ds", int(d.Minutes()), int(d.Seconds())%60)
	} else if d < 24*time.Hour {
		return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
	}
	return fmt.Sprintf("%dd%dh", int(d.Hours())/24, int(d.Hours())%24)
}

// Min 返回两个整数中的最小值
func Min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
