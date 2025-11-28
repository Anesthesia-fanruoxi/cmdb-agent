package plugins

import (
	"bytes"
	"cmdb-agent/common"
	"cmdb-agent/config"
	"encoding/json"
	"fmt"
	"go.uber.org/zap"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// PluginProxyHandler 插件代理接口
// 路径格式: /proxy/{plugin-name}/{real-path}
// 例如: /proxy/sql-plugs/search -> http://localhost:3308/search
func PluginProxyHandler(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	// 获取真实客户端IP
	realClientIP := getRealClientIP(r)
	if realClientIP == "" {
		// 如果没有代理头，从RemoteAddr获取IP（去掉端口）
		if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
			realClientIP = host
		} else {
			realClientIP = r.RemoteAddr
		}
	}

	common.Info("收到代理请求",
		zap.String("method", r.Method),
		zap.String("path", r.URL.Path),
		zap.String("real_client_ip", realClientIP),
		zap.String("remote_addr", r.RemoteAddr))

	// 解析路径: /proxy/{plugin-name}/{real-path}
	path := strings.TrimPrefix(r.URL.Path, "/proxy/")
	parts := strings.SplitN(path, "/", 2)

	if len(parts) < 2 {
		common.RespondError(w, http.StatusBadRequest,
			"无效的代理路径格式，正确格式: /proxy/{plugin-name}/{real-path}")
		return
	}

	pluginName := parts[0]
	realPath := "/" + parts[1]

	common.Info("解析代理路径",
		zap.String("plugin", pluginName),
		zap.String("real_path", realPath))

	// 查询插件信息
	record, err := GetPluginRecord(pluginName)
	if err != nil {
		common.Error("查询插件记录失败", zap.Error(err))
		common.RespondError(w, http.StatusInternalServerError,
			"查询插件记录失败: "+err.Error())
		return
	}

	if record == nil {
		common.RespondError(w, http.StatusNotFound,
			fmt.Sprintf("插件不存在: %s", pluginName))
		return
	}

	// 构建目标URL
	targetURL := fmt.Sprintf("http://localhost:%d%s", record.Port, realPath)
	if r.URL.RawQuery != "" {
		targetURL += "?" + r.URL.RawQuery
	}

	// 检查是否为明文路径（不需要解密）
	isPlainTextPath := isPlainTextRequest(realPath)

	// 读取并处理请求体
	var plainRequestBody []byte
	if r.Body != nil {
		requestBody, err := io.ReadAll(r.Body)
		if err != nil {
			common.Error("读取请求体失败", zap.Error(err))
			common.RespondError(w, http.StatusBadRequest, "读取请求体失败: "+err.Error())
			return
		}
		defer r.Body.Close()

		// 如果有请求体，根据路径决定是否解密
		if len(requestBody) > 0 {
			if isPlainTextPath {
				// 明文路径，直接使用原始请求体
				plainRequestBody = requestBody

				// 对于 multipart 请求，记录 Content-Type 信息用于调试
				contentType := r.Header.Get("Content-Type")
				if strings.Contains(strings.ToLower(contentType), "multipart") {
					// multipart 请求完整转发
				} else {
					common.Info("明文请求，跳过解密",
						zap.String("path", realPath),
						zap.Int("body_size", len(requestBody)))
				}
			} else {
				// 加密路径，需要解密
				// 解析加密数据结构 {"data": "encrypted_base64"}
				var encryptedData struct {
					Data string `json:"data"`
				}

				if err := json.Unmarshal(requestBody, &encryptedData); err != nil {
					common.Error("解析加密请求体失败", zap.Error(err))
					common.RespondError(w, http.StatusBadRequest, "请求体格式错误: "+err.Error())
					return
				}

				// 解密数据
				cfg := config.GetConfig()
				plainRequestBody, err = common.DecryptAndDecompress(encryptedData.Data, cfg.Security.AgentSalt)
				if err != nil {
					common.Error("解密请求体失败", zap.Error(err))
					common.RespondError(w, http.StatusBadRequest, "解密请求体失败: "+err.Error())
					return
				}

				common.Info("解密请求成功",
					zap.Int("encrypted_size", len(requestBody)),
					zap.Int("decrypted_size", len(plainRequestBody)))

				// 修改callback_url，让插件回调到agent进行加密（其他内容保持不变）
				plainRequestBody, err = modifyCallbackURL(plainRequestBody, pluginName, r)
				if err != nil {
					common.Warn("修改callback_url失败，继续使用原始请求体", zap.Error(err))
				}
			}
		}
	}

	common.Info("转发请求",
		zap.String("plugin", pluginName),
		zap.String("target_url", targetURL),
		zap.String("method", r.Method),
		zap.Int("body_size", len(plainRequestBody)))

	// 创建代理请求（使用明文请求体）
	proxyReq, err := http.NewRequest(r.Method, targetURL, bytes.NewReader(plainRequestBody))
	if err != nil {
		common.Error("创建代理请求失败", zap.Error(err))
		common.RespondError(w, http.StatusInternalServerError,
			"创建代理请求失败: "+err.Error())
		return
	}

	// 复制请求头（排除hop-by-hop headers和将要重新设置的headers）
	for key, values := range r.Header {
		keyLower := strings.ToLower(key)
		// 跳过hop-by-hop headers和将要重新设置的headers
		if isHopByHopHeader(key) || keyLower == "x-real-ip" || keyLower == "x-forwarded-for" || keyLower == "x-forwarded-host" {
			continue
		}
		for _, value := range values {
			proxyReq.Header.Add(key, value)
		}
	}

	// 设置X-Forwarded-For 和 X-Real-IP，传递真实客户端IP给插件
	proxyReq.Header.Set("X-Real-IP", realClientIP)
	proxyReq.Header.Set("X-Forwarded-For", realClientIP)
	proxyReq.Header.Set("X-Forwarded-Host", r.Host)

	// 对于非 multipart/form-data 请求，设置 JSON 格式和 UTF-8 字符集
	contentType := r.Header.Get("Content-Type")
	if !strings.Contains(strings.ToLower(contentType), "multipart/form-data") {
		proxyReq.Header.Set("Content-Type", "application/json; charset=utf-8")
	}
	// multipart/form-data 请求已经在前面复制头部时保留了原始 Content-Type

	common.Debug("转发真实客户端IP",
		zap.String("real_client_ip", realClientIP),
		zap.String("remote_addr", r.RemoteAddr))

	// 发送请求 - 增加超时支持慢查询
	client := &http.Client{
		Timeout: 600 * time.Second, // 10分钟超时，与Server配置一致
	}

	resp, err := client.Do(proxyReq)
	if err != nil {
		common.Error("转发请求失败",
			zap.String("plugin", pluginName),
			zap.String("target_url", targetURL),
			zap.Error(err))
		common.RespondError(w, http.StatusBadGateway,
			fmt.Sprintf("转发请求到插件失败: %v", err))
		return
	}
	defer resp.Body.Close()

	// 读取响应体（来自plugin的明文响应）
	plainResponseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		common.Error("读取响应体失败", zap.Error(err))
		common.RespondError(w, http.StatusInternalServerError, "读取响应体失败: "+err.Error())
		return
	}

	// 加密整个响应体
	cfg := config.GetConfig()
	encryptedData, err := common.CompressAndEncrypt(plainResponseBody, cfg.Security.AgentSalt)
	if err != nil {
		common.Error("加密响应体失败", zap.Error(err))
		common.RespondError(w, http.StatusInternalServerError, "加密响应体失败: "+err.Error())
		return
	}

	// 构建加密响应结构 {"data": "encrypted_base64"}
	encryptedResponse := map[string]interface{}{
		"data": encryptedData,
	}

	encryptedResponseBody, err := json.Marshal(encryptedResponse)
	if err != nil {
		common.Error("序列化加密响应失败", zap.Error(err))
		common.RespondError(w, http.StatusInternalServerError, "序列化响应失败: "+err.Error())
		return
	}

	common.Info("加密响应成功",
		zap.Int("plain_size", len(plainResponseBody)),
		zap.Int("encrypted_size", len(encryptedResponseBody)))

	// 设置响应头
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(encryptedResponseBody)))

	// 复制其他响应头（排除hop-by-hop headers、Content-Type和Content-Length）
	for key, values := range resp.Header {
		keyLower := strings.ToLower(key)
		if isHopByHopHeader(key) || keyLower == "content-type" || keyLower == "content-length" {
			continue
		}
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// 写入响应状态码和加密后的响应体
	w.WriteHeader(resp.StatusCode)
	written, err := w.Write(encryptedResponseBody)
	if err != nil {
		common.Error("写入响应体失败", zap.Error(err))
		return
	}

	if written != len(encryptedResponseBody) {
		common.Warn("响应体未完全写入",
			zap.Int("expected", len(encryptedResponseBody)),
			zap.Int("written", written))
	}

	duration := time.Since(startTime)
	common.Info("代理请求完成",
		zap.String("plugin", pluginName),
		zap.String("target_url", targetURL),
		zap.Int("status", resp.StatusCode),
		zap.Int("response_size", len(encryptedResponseBody)),
		zap.Duration("duration", duration))
}

// getRealClientIP 从请求头获取真实客户端IP
func getRealClientIP(r *http.Request) string {
	// 优先使用 X-Real-IP
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		return strings.TrimSpace(realIP)
	}

	// 其次使用 X-Forwarded-For 的第一个IP
	if forwardedFor := r.Header.Get("X-Forwarded-For"); forwardedFor != "" {
		ips := strings.Split(forwardedFor, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	return ""
}

// isHopByHopHeader 判断是否为hop-by-hop header
// 这些header不应该在代理时转发
func isHopByHopHeader(header string) bool {
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

// isPlainTextRequest 判断请求路径是否为明文（不需要解密）
func isPlainTextRequest(path string) bool {
	// 定义不需要解密的路径列表
	plainTextPaths := []string{
		"/update",     // cicd插件的更新接口
		"/health",     // 健康检查接口
		"/ping",       // ping接口
		"/api/upload", // 文件上传接口
	}

	// 检查路径是否匹配
	for _, plainPath := range plainTextPaths {
		if path == plainPath || strings.HasPrefix(path, plainPath+"/") || strings.HasPrefix(path, plainPath+"?") {
			return true
		}
	}

	return false
}

// modifyCallbackURL 修改请求体中的callback_url，让插件回调到agent
func modifyCallbackURL(requestBody []byte, pluginName string, r *http.Request) ([]byte, error) {
	// 解析JSON请求体
	var data map[string]interface{}
	if err := json.Unmarshal(requestBody, &data); err != nil {
		return requestBody, fmt.Errorf("解析JSON失败: %v", err)
	}

	// 检查是否有callback_url字段
	originalCallbackURL, ok := data["callback_url"].(string)
	if !ok || originalCallbackURL == "" {
		// 没有callback_url，无需修改
		return requestBody, nil
	}

	// 构建agent的callback URL (使用localhost，因为插件和agent在同一台机器)
	// 插件回调agent固定用http，agent转发给CMDB时使用原始URL
	cfg := config.GetConfig()
	agentCallbackURL := fmt.Sprintf("http://localhost:%d/api/plugins/callback/%s?original_url=%s",
		cfg.Server.Port, pluginName, originalCallbackURL)

	// 替换callback_url
	data["callback_url"] = agentCallbackURL

	common.Info("修改callback_url",
		zap.String("plugin", pluginName),
		zap.String("original", originalCallbackURL),
		zap.String("modified", agentCallbackURL))

	// 重新序列化JSON - 不转义 Unicode 和 HTML
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false) // 不转义 HTML 字符

	if err := encoder.Encode(data); err != nil {
		return requestBody, fmt.Errorf("序列化JSON失败: %v", err)
	}

	// Encoder.Encode 会自动添加换行符，需要去掉
	modifiedBody := bytes.TrimSpace(buf.Bytes())

	return modifiedBody, nil
}

// PluginCallbackHandler 处理插件回调请求（加密后转发给CMDB）
func PluginCallbackHandler(w http.ResponseWriter, r *http.Request) {
	// 解析路径，获取插件名称
	// 路径格式: /api/plugins/callback/{plugin_name}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 4 {
		common.RespondError(w, http.StatusBadRequest, "无效的callback路径")
		return
	}
	pluginName := parts[3]

	// 获取原始callback URL
	originalURL := r.URL.Query().Get("original_url")
	if originalURL == "" {
		common.RespondError(w, http.StatusBadRequest, "缺少original_url参数")
		return
	}

	common.Info("收到插件回调",
		zap.String("plugin", pluginName),
		zap.String("original_url", originalURL),
		zap.String("method", r.Method))

	// 读取插件回调的明文请求体
	plainBody, err := io.ReadAll(r.Body)
	if err != nil {
		common.Error("读取回调请求体失败", zap.Error(err))
		common.RespondError(w, http.StatusBadRequest, "读取请求体失败")
		return
	}
	defer r.Body.Close()

	common.Info("读取插件回调请求体",
		zap.Int("size", len(plainBody)))

	// 加密请求体
	cfg := config.GetConfig()
	encryptedData, err := common.CompressAndEncrypt(plainBody, cfg.Security.AgentSalt)
	if err != nil {
		common.Error("加密回调请求体失败", zap.Error(err))
		common.RespondError(w, http.StatusInternalServerError, "加密失败")
		return
	}

	// 构建加密请求体 {"data": "encrypted_base64"}
	encryptedBody, err := json.Marshal(map[string]string{
		"data": encryptedData,
	})
	if err != nil {
		common.Error("序列化加密数据失败", zap.Error(err))
		common.RespondError(w, http.StatusInternalServerError, "序列化失败")
		return
	}

	common.Info("加密回调请求成功",
		zap.Int("plain_size", len(plainBody)),
		zap.Int("encrypted_size", len(encryptedBody)))

	// 转发到原始callback URL
	callbackReq, err := http.NewRequest(r.Method, originalURL, bytes.NewReader(encryptedBody))
	if err != nil {
		common.Error("创建回调请求失败", zap.Error(err))
		common.RespondError(w, http.StatusInternalServerError, "创建请求失败")
		return
	}

	// 复制请求头（排除hop-by-hop headers和将要重新设置的headers）
	callbackReq.Header.Set("Content-Type", "application/json")
	for key, values := range r.Header {
		keyLower := strings.ToLower(key)
		// 跳过hop-by-hop headers、Content-Length和将要重新设置的headers
		if isHopByHopHeader(key) || keyLower == "content-length" || keyLower == "x-real-ip" || keyLower == "x-forwarded-for" || keyLower == "x-forwarded-host" {
			continue
		}
		for _, value := range values {
			callbackReq.Header.Add(key, value)
		}
	}

	// 获取真实客户端IP并传递给CMDB
	realClientIP := getRealClientIP(r)
	if realClientIP == "" {
		// 如果插件回调时没有代理头，从RemoteAddr获取IP（去掉端口）
		if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
			realClientIP = host
		} else {
			realClientIP = r.RemoteAddr
		}
	}
	callbackReq.Header.Set("X-Real-IP", realClientIP)
	callbackReq.Header.Set("X-Forwarded-For", realClientIP)
	callbackReq.Header.Set("X-Forwarded-Host", r.Host)

	// 发送请求
	client := &http.Client{Timeout: 600 * time.Second} // 10分钟超时
	resp, err := client.Do(callbackReq)
	if err != nil {
		common.Error("转发回调请求失败",
			zap.String("url", originalURL),
			zap.Error(err))
		common.RespondError(w, http.StatusBadGateway, "转发失败: "+err.Error())
		return
	}
	defer resp.Body.Close()

	// 读取CMDB响应
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		common.Error("读取回调响应失败", zap.Error(err))
		common.RespondError(w, http.StatusBadGateway, "读取响应失败")
		return
	}

	common.Info("回调转发成功",
		zap.String("url", originalURL),
		zap.Int("status", resp.StatusCode),
		zap.Int("response_size", len(respBody)))

	// 返回CMDB的响应给插件
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}
