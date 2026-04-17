package proxy

import (
	"bufio"
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

// ProxyHandler 插件代理接口
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
		zap.String("real_client_ip", realClientIP),
		zap.String("remote_addr", r.RemoteAddr))

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

	targetURL := fmt.Sprintf("http://localhost:%d%s", record.Port, realPath)
	if r.URL.RawQuery != "" {
		targetURL += "?" + r.URL.RawQuery
	}

	isPlainTextPath := IsPlainTextRequest(realPath)

	var plainRequestBody []byte
	if r.Body != nil {
		requestBody, err := io.ReadAll(r.Body)
		if err != nil {
			common.Error("读取请求体失败", zap.Error(err))
			common.RespondError(w, http.StatusBadRequest, "读取请求体失败: "+err.Error())
			return
		}
		defer func() { _ = r.Body.Close() }()

		if len(requestBody) > 0 {
			if isPlainTextPath {
				plainRequestBody = requestBody
				contentType := r.Header.Get("Content-Type")
				if !strings.Contains(strings.ToLower(contentType), "multipart") {
					common.Info("明文请求，跳过解密",
						zap.String("path", realPath),
						zap.Int("body_size", len(requestBody)))
				}
			} else {
				var encryptedData struct {
					Data string `json:"data"`
				}

				if err := json.Unmarshal(requestBody, &encryptedData); err != nil {
					common.Error("解析加密请求体失败", zap.Error(err))
					common.RespondError(w, http.StatusBadRequest, "请求体格式错误: "+err.Error())
					return
				}

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

	proxyReq, err := http.NewRequest(r.Method, targetURL, bytes.NewReader(plainRequestBody))
	if err != nil {
		common.Error("创建代理请求失败", zap.Error(err))
		common.RespondError(w, http.StatusInternalServerError,
			"创建代理请求失败: "+err.Error())
		return
	}

	for key, values := range r.Header {
		keyLower := strings.ToLower(key)
		if IsHopByHopHeader(key) || keyLower == "x-real-ip" || keyLower == "x-forwarded-for" || keyLower == "x-forwarded-host" {
			continue
		}
		for _, value := range values {
			proxyReq.Header.Add(key, value)
		}
	}

	proxyReq.Header.Set("X-Real-IP", realClientIP)
	proxyReq.Header.Set("X-Forwarded-For", realClientIP)
	proxyReq.Header.Set("X-Forwarded-Host", r.Host)

	contentType := r.Header.Get("Content-Type")
	if !strings.Contains(strings.ToLower(contentType), "multipart/form-data") {
		proxyReq.Header.Set("Content-Type", "application/json; charset=utf-8")
	}

	common.Debug("转发真实客户端IP",
		zap.String("real_client_ip", realClientIP),
		zap.String("remote_addr", r.RemoteAddr))

	client := &http.Client{
		Timeout: 600 * time.Second,
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
	defer func() { _ = resp.Body.Close() }()

	for key, values := range resp.Header {
		keyLower := strings.ToLower(key)
		if IsHopByHopHeader(key) || keyLower == "content-type" || keyLower == "content-length" {
			continue
		}
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	respContentType := resp.Header.Get("Content-Type")
	isNDJSON := strings.Contains(respContentType, "application/x-ndjson") ||
		strings.Contains(respContentType, "application/ndjson")

	cfg := config.GetConfig()

	if isNDJSON {
		common.Info("检测到NDJSON流式响应，启用流式加密转发",
			zap.String("plugin", pluginName))

		flusher, ok := w.(http.Flusher)
		if !ok {
			common.Error("响应不支持流式传输")
			common.RespondError(w, http.StatusInternalServerError, "不支持流式传输")
			return
		}

		w.Header().Set("Content-Type", "application/x-ndjson")
		w.WriteHeader(resp.StatusCode)

		scanner := bufio.NewScanner(resp.Body)
		scanner.Buffer(make([]byte, 4*1024*1024), 4*1024*1024)

		lineCount := 0
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}

			encryptedData, err := common.CompressAndEncrypt([]byte(line), cfg.Security.AgentSalt)
			if err != nil {
				common.Warn("加密行数据失败，跳过该行",
					zap.Int("line", lineCount),
					zap.Error(err))
				continue
			}

			_, err = fmt.Fprintf(w, `{"data":"%s"}`+"\n", encryptedData)
			if err != nil {
				common.Warn("写入流数据失败，客户端可能已断开",
					zap.Int("line", lineCount),
					zap.Error(err))
				break
			}
			flusher.Flush()
			lineCount++

			if lineCount%1000 == 0 {
				common.Info("流式传输进度",
					zap.String("plugin", pluginName),
					zap.Int("lines", lineCount))
			}
		}

		if err := scanner.Err(); err != nil {
			common.Error("读取流式响应出错",
				zap.String("plugin", pluginName),
				zap.Error(err))
		}

		duration := time.Since(startTime)
		common.Info("流式代理完成",
			zap.String("plugin", pluginName),
			zap.Int("total_lines", lineCount),
			zap.Duration("duration", duration))

	} else {
		plainResponseBody, err := io.ReadAll(resp.Body)
		if err != nil {
			common.Error("读取响应体失败", zap.Error(err))
			common.RespondError(w, http.StatusInternalServerError, "读取响应体失败: "+err.Error())
			return
		}

		encryptedData, err := common.CompressAndEncrypt(plainResponseBody, cfg.Security.AgentSalt)
		if err != nil {
			common.Error("加密响应体失败", zap.Error(err))
			common.RespondError(w, http.StatusInternalServerError, "加密响应体失败: "+err.Error())
			return
		}

		encryptedResponseBody, err := json.Marshal(map[string]interface{}{"data": encryptedData})
		if err != nil {
			common.Error("序列化加密响应失败", zap.Error(err))
			common.RespondError(w, http.StatusInternalServerError, "序列化响应失败: "+err.Error())
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(encryptedResponseBody)))
		w.WriteHeader(resp.StatusCode)
		if _, err := w.Write(encryptedResponseBody); err != nil {
			common.Warn("写入响应体失败", zap.Error(err))
		}

		duration := time.Since(startTime)
		common.Info("代理请求完成",
			zap.String("plugin", pluginName),
			zap.String("target_url", targetURL),
			zap.Int("status", resp.StatusCode),
			zap.Int("plain_size", len(plainResponseBody)),
			zap.Int("encrypted_size", len(encryptedResponseBody)),
			zap.Duration("duration", duration))
	}
}

// modifyCallbackURL 修改请求体中的callback_url，让插件回调到agent
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

	common.Info("读取插件回调请求体", zap.Int("size", len(plainBody)))

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

	common.Info("加密回调请求成功",
		zap.Int("plain_size", len(plainBody)),
		zap.Int("encrypted_size", len(encryptedBody)))

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
		common.Error("转发回调请求失败",
			zap.String("url", originalURL),
			zap.Error(err))
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
