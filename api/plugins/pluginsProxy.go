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

	// 提取远程IP（去掉端口）
	remoteIP := r.RemoteAddr
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		remoteIP = host
	}

	common.Info("收到代理请求",
		zap.String("method", r.Method),
		zap.String("path", r.URL.Path),
		zap.String("remote", remoteIP))

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
				common.Info("明文请求，跳过解密",
					zap.String("path", realPath),
					zap.Int("body_size", len(requestBody)))
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

				// 修改callback_url，让插件回调到agent而不是直接回调CMDB
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

	// 复制请求头（排除hop-by-hop headers）
	for key, values := range r.Header {
		// 跳过hop-by-hop headers
		if isHopByHopHeader(key) {
			continue
		}
		for _, value := range values {
			proxyReq.Header.Add(key, value)
		}
	}

	// 设置X-Forwarded-For 和 X-Real-IP（只传IP，不带端口）
	if clientIP, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		proxyReq.Header.Set("X-Forwarded-For", clientIP)
		proxyReq.Header.Set("X-Real-IP", clientIP)
	} else {
		// 如果解析失败，直接使用原始值
		proxyReq.Header.Set("X-Forwarded-For", r.RemoteAddr)
		proxyReq.Header.Set("X-Real-IP", r.RemoteAddr)
	}
	proxyReq.Header.Set("X-Forwarded-Host", r.Host)

	// 发送请求
	client := &http.Client{
		Timeout: 30 * time.Second,
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
		"/update", // cicd插件的更新接口
		"/health", // 健康检查接口
		"/ping",   // ping接口
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

	// 构建agent的callback URL
	// 格式: http://agent_host:agent_port/api/plugins/callback/{plugin_name}?original_url=xxx
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}

	agentCallbackURL := fmt.Sprintf("%s://%s/api/plugins/callback/%s?original_url=%s",
		scheme, r.Host, pluginName, originalCallbackURL)

	// 替换callback_url
	data["callback_url"] = agentCallbackURL

	common.Info("修改callback_url",
		zap.String("plugin", pluginName),
		zap.String("original", originalCallbackURL),
		zap.String("modified", agentCallbackURL))

	// 重新序列化JSON
	modifiedBody, err := json.Marshal(data)
	if err != nil {
		return requestBody, fmt.Errorf("序列化JSON失败: %v", err)
	}

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

	// 复制请求头
	callbackReq.Header.Set("Content-Type", "application/json")
	for key, values := range r.Header {
		if !isHopByHopHeader(key) && key != "Content-Length" {
			for _, value := range values {
				callbackReq.Header.Add(key, value)
			}
		}
	}

	// 发送请求
	client := &http.Client{Timeout: 30 * time.Second}
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
