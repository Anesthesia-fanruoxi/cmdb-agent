package proxy

import (
	"bufio"
	"cmdb-agent/common"
	"fmt"
	"go.uber.org/zap"
	"net/http"
	"strings"
	"time"
)

// handleNDJSONProxy 处理 NDJSON 流式响应：逐行加密推送
// 响应格式：{"data":"<encrypted>"}\n
func handleNDJSONProxy(w http.ResponseWriter, resp *http.Response, pluginName, salt string, startTime time.Time) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		common.Error("响应不支持流式传输")
		common.RespondError(w, http.StatusInternalServerError, "不支持流式传输")
		return
	}

	w.Header().Set("Content-Type", "application/x-ndjson")
	w.WriteHeader(resp.StatusCode)

	lineCount := streamEncryptedLines(w, flusher, resp, pluginName, salt, func(encrypted string) string {
		return fmt.Sprintf(`{"data":"%s"}`, encrypted)
	})

	common.Info("NDJSON流式代理完成",
		zap.String("plugin", pluginName),
		zap.Int("total_lines", lineCount),
		zap.Duration("duration", time.Since(startTime)))
}

// handleSSEProxy 处理 SSE 流式响应：逐行加密推送
// 响应格式：data: {"data":"<encrypted>"}\n\n
func handleSSEProxy(w http.ResponseWriter, resp *http.Response, pluginName, salt string, startTime time.Time) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		common.Error("响应不支持SSE流式传输")
		common.RespondError(w, http.StatusInternalServerError, "不支持流式传输")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(resp.StatusCode)

	lineCount := streamEncryptedLines(w, flusher, resp, pluginName, salt, func(encrypted string) string {
		return fmt.Sprintf(`data: {"data":"%s"}`, encrypted)
	})

	common.Info("SSE流式代理完成",
		zap.String("plugin", pluginName),
		zap.Int("total_lines", lineCount),
		zap.Duration("duration", time.Since(startTime)))
}

// streamEncryptedLines 通用流式加密推送
// formatLine 负责将加密后的字符串格式化为对应协议的行格式
func streamEncryptedLines(w http.ResponseWriter, flusher http.Flusher, resp *http.Response,
	pluginName, salt string, formatLine func(encrypted string) string) int {

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 4*1024*1024), 4*1024*1024)

	lineCount := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		encrypted, err := common.CompressAndEncrypt([]byte(line), salt)
		if err != nil {
			common.Warn("加密行数据失败，跳过该行",
				zap.Int("line", lineCount),
				zap.Error(err))
			continue
		}

		if _, err := fmt.Fprintln(w, formatLine(encrypted)); err != nil {
			common.Warn("写入流数据失败，客户端可能已断开",
				zap.String("plugin", pluginName),
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

	return lineCount
}
