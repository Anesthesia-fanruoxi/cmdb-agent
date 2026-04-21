package proxy

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

// ProxyHandler 插件代理入口
// 路径格式: /proxy/{plugin-name}/{real-path}
func ProxyHandler(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	realClientIP := GetRealClientIP(r.Header.Get("X-Real-IP"), r.Header.Get("X-Forwarded-For"))
	if realClientIP == "" {
		if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
			realClientIP = host
		} else {
			realClientIP = r.RemoteAddr
		}
	}

	common.Info("收到代理请求",
		zap.String("method", r.Method),
		zap.String("path", r.URL.Path),
		zap.String("real_client_ip", realClientIP))

	// 解析插件名和真实路径
	path := strings.TrimPrefix(r.URL.Path, "/proxy/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) < 2 {
		common.RespondError(w, http.StatusBadRequest,
			"无效的代理路径格式，正确格式: /proxy/{plugin-name}/{real-path}")
		return
	}

	pluginName := parts[0]
	realPath := "/" + parts[1]

	// 查询插件记录
	record, err := GetPluginRecord(pluginName)
	if err != nil {
		common.Error("查询插件记录失败", zap.Error(err))
		common.RespondError(w, http.StatusInternalServerError, "查询插件记录失败: "+err.Error())
		return
	}
	if record == nil {
		common.RespondError(w, http.StatusNotFound, fmt.Sprintf("插件不存在: %s", pluginName))
		return
	}

	// 构建目标 URL
	targetURL := fmt.Sprintf("http://localhost:%d%s", record.Port, realPath)
	if r.URL.RawQuery != "" {
		targetURL += "?" + r.URL.RawQuery
	}

	// 读取并处理请求体
	plainBody, err := readAndDecryptBody(r, realPath, pluginName)
	if err != nil {
		common.Error("处理请求体失败", zap.Error(err))
		common.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	// 构建并发送代理请求
	resp, err := forwardRequest(r, targetURL, plainBody, realClientIP)
	if err != nil {
		common.Error("转发请求失败",
			zap.String("plugin", pluginName),
			zap.String("target_url", targetURL),
			zap.Error(err))
		common.RespondError(w, http.StatusBadGateway, fmt.Sprintf("转发请求到插件失败: %v", err))
		return
	}
	defer func() { _ = resp.Body.Close() }()

	// 根据响应类型分发处理
	respContentType := resp.Header.Get("Content-Type")
	copyResponseHeaders(w, resp)

	cfg := config.GetConfig()

	switch {
	case strings.Contains(respContentType, "text/event-stream"):
		common.Info("检测到SSE响应，启用SSE流式加密转发", zap.String("plugin", pluginName))
		handleSSEProxy(w, resp, pluginName, cfg.Security.AgentSalt, startTime)

	case strings.Contains(respContentType, "application/x-ndjson"),
		strings.Contains(respContentType, "application/ndjson"):
		common.Info("检测到NDJSON响应，启用流式加密转发", zap.String("plugin", pluginName))
		handleNDJSONProxy(w, resp, pluginName, cfg.Security.AgentSalt, startTime)

	default:
		handleNormalProxy(w, resp, pluginName, targetURL, cfg.Security.AgentSalt, startTime)
	}
}

// readAndDecryptBody 读取请求体，明文路径直接返回，加密路径解密后返回
func readAndDecryptBody(r *http.Request, realPath, pluginName string) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	defer func() { _ = r.Body.Close() }()

	requestBody, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("读取请求体失败: %v", err)
	}

	if len(requestBody) == 0 {
		return nil, nil
	}

	// 明文路径直接返回
	if IsPlainTextRequest(realPath) {
		contentType := r.Header.Get("Content-Type")
		if !strings.Contains(strings.ToLower(contentType), "multipart") {
			common.Info("明文请求，跳过解密",
				zap.String("path", realPath),
				zap.Int("body_size", len(requestBody)))
		}
		return requestBody, nil
	}

	// 解密请求体
	var encryptedData struct {
		Data string `json:"data"`
	}
	if err := json.Unmarshal(requestBody, &encryptedData); err != nil {
		return nil, fmt.Errorf("请求体格式错误: %v", err)
	}

	cfg := config.GetConfig()
	plainBody, err := common.DecryptAndDecompress(encryptedData.Data, cfg.Security.AgentSalt)
	if err != nil {
		return nil, fmt.Errorf("解密请求体失败: %v", err)
	}

	common.Info("解密请求成功",
		zap.Int("encrypted_size", len(requestBody)),
		zap.Int("decrypted_size", len(plainBody)))

	// 修改 callback_url
	plainBody, err = modifyCallbackURL(plainBody, pluginName, r)
	if err != nil {
		common.Warn("修改callback_url失败，继续使用原始请求体", zap.Error(err))
	}

	return plainBody, nil
}

// forwardRequest 构建并发送代理请求
func forwardRequest(r *http.Request, targetURL string, body []byte, realClientIP string) (*http.Response, error) {
	proxyReq, err := http.NewRequest(r.Method, targetURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("创建代理请求失败: %v", err)
	}

	// 复制请求头（过滤 hop-by-hop 和 IP 相关头）
	for key, values := range r.Header {
		keyLower := strings.ToLower(key)
		if IsHopByHopHeader(key) || keyLower == "x-real-ip" ||
			keyLower == "x-forwarded-for" || keyLower == "x-forwarded-host" {
			continue
		}
		for _, value := range values {
			proxyReq.Header.Add(key, value)
		}
	}

	// 设置真实 IP 头
	proxyReq.Header.Set("X-Real-IP", realClientIP)
	proxyReq.Header.Set("X-Forwarded-For", realClientIP)
	proxyReq.Header.Set("X-Forwarded-Host", r.Host)

	// 非 multipart 请求统一设置 JSON Content-Type
	contentType := r.Header.Get("Content-Type")
	if !strings.Contains(strings.ToLower(contentType), "multipart/form-data") {
		proxyReq.Header.Set("Content-Type", "application/json; charset=utf-8")
	}

	client := &http.Client{Timeout: 600 * time.Second}
	return client.Do(proxyReq)
}

// copyResponseHeaders 复制响应头（过滤 hop-by-hop、content-type、content-length）
func copyResponseHeaders(w http.ResponseWriter, resp *http.Response) {
	for key, values := range resp.Header {
		keyLower := strings.ToLower(key)
		if IsHopByHopHeader(key) || keyLower == "content-type" || keyLower == "content-length" {
			continue
		}
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
}

// modifyCallbackURL 修改请求体中的 callback_url，让插件回调到 agent
func modifyCallbackURL(requestBody []byte, pluginName string, _ *http.Request) ([]byte, error) {
	var data map[string]interface{}
	if err := json.Unmarshal(requestBody, &data); err != nil {
		return requestBody, fmt.Errorf("解析JSON失败: %v", err)
	}

	originalCallbackURL, ok := data["callback_url"].(string)
	if !ok || originalCallbackURL == "" {
		return requestBody, nil
	}

	cfg := config.GetConfig()
	agentCallbackURL := fmt.Sprintf("http://localhost:%d/api/plugins/callback/%s?original_url=%s",
		cfg.Server.Port, pluginName, originalCallbackURL)

	data["callback_url"] = agentCallbackURL

	common.Info("修改callback_url",
		zap.String("plugin", pluginName),
		zap.String("original", originalCallbackURL),
		zap.String("modified", agentCallbackURL))

	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(data); err != nil {
		return requestBody, fmt.Errorf("序列化JSON失败: %v", err)
	}

	return bytes.TrimSpace(buf.Bytes()), nil
}

// CallbackHandler 处理插件回调请求（加密后转发给CMDB）
func CallbackHandler(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 4 {
		common.RespondError(w, http.StatusBadRequest, "无效的callback路径")
		return
	}
	pluginName := parts[3]

	originalURL := r.URL.Query().Get("original_url")
	if originalURL == "" {
		common.RespondError(w, http.StatusBadRequest, "缺少original_url参数")
		return
	}

	common.Info("收到插件回调",
		zap.String("plugin", pluginName),
		zap.String("original_url", originalURL),
		zap.String("method", r.Method))

	plainBody, err := io.ReadAll(r.Body)
	if err != nil {
		common.Error("读取回调请求体失败", zap.Error(err))
		common.RespondError(w, http.StatusBadRequest, "读取请求体失败")
		return
	}
	defer func() { _ = r.Body.Close() }()

	cfg := config.GetConfig()
	encryptedData, err := common.CompressAndEncrypt(plainBody, cfg.Security.AgentSalt)
	if err != nil {
		common.Error("加密回调请求体失败", zap.Error(err))
		common.RespondError(w, http.StatusInternalServerError, "加密失败")
		return
	}

	encryptedBody, err := json.Marshal(map[string]string{"data": encryptedData})
	if err != nil {
		common.Error("序列化加密数据失败", zap.Error(err))
		common.RespondError(w, http.StatusInternalServerError, "序列化失败")
		return
	}

	callbackReq, err := http.NewRequest(r.Method, originalURL, bytes.NewReader(encryptedBody))
	if err != nil {
		common.Error("创建回调请求失败", zap.Error(err))
		common.RespondError(w, http.StatusInternalServerError, "创建请求失败")
		return
	}

	callbackReq.Header.Set("Content-Type", "application/json")
	for key, values := range r.Header {
		keyLower := strings.ToLower(key)
		if IsHopByHopHeader(key) || keyLower == "content-length" ||
			keyLower == "x-real-ip" || keyLower == "x-forwarded-for" || keyLower == "x-forwarded-host" {
			continue
		}
		for _, value := range values {
			callbackReq.Header.Add(key, value)
		}
	}

	realClientIP := GetRealClientIP(r.Header.Get("X-Real-IP"), r.Header.Get("X-Forwarded-For"))
	if realClientIP == "" {
		if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
			realClientIP = host
		} else {
			realClientIP = r.RemoteAddr
		}
	}
	callbackReq.Header.Set("X-Real-IP", realClientIP)
	callbackReq.Header.Set("X-Forwarded-For", realClientIP)
	callbackReq.Header.Set("X-Forwarded-Host", r.Host)

	client := &http.Client{Timeout: 600 * time.Second}
	resp, err := client.Do(callbackReq)
	if err != nil {
		common.Error("转发回调请求失败", zap.String("url", originalURL), zap.Error(err))
		common.RespondError(w, http.StatusBadGateway, "转发失败: "+err.Error())
		return
	}
	defer func() { _ = resp.Body.Close() }()

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

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	if _, err := w.Write(respBody); err != nil {
		common.Warn("写入回调响应失败", zap.Error(err))
	}
}
