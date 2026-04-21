package proxy

import (
	"cmdb-agent/common"
	"encoding/json"
	"fmt"
	"go.uber.org/zap"
	"io"
	"net/http"
	"time"
)

// handleNormalProxy 处理普通 REST 响应：读取完整响应体，加密后返回
func handleNormalProxy(w http.ResponseWriter, resp *http.Response, pluginName, targetURL, salt string, startTime time.Time) {
	plainBody, err := io.ReadAll(resp.Body)
	if err != nil {
		common.Error("读取响应体失败", zap.Error(err))
		common.RespondError(w, http.StatusInternalServerError, "读取响应体失败: "+err.Error())
		return
	}

	encryptedData, err := common.CompressAndEncrypt(plainBody, salt)
	if err != nil {
		common.Error("加密响应体失败", zap.Error(err))
		common.RespondError(w, http.StatusInternalServerError, "加密响应体失败: "+err.Error())
		return
	}

	encryptedBody, err := json.Marshal(map[string]interface{}{"data": encryptedData})
	if err != nil {
		common.Error("序列化加密响应失败", zap.Error(err))
		common.RespondError(w, http.StatusInternalServerError, "序列化响应失败: "+err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(encryptedBody)))
	w.WriteHeader(resp.StatusCode)

	if _, err := w.Write(encryptedBody); err != nil {
		common.Warn("写入响应体失败", zap.Error(err))
	}

	common.Info("普通代理完成",
		zap.String("plugin", pluginName),
		zap.String("target_url", targetURL),
		zap.Int("status", resp.StatusCode),
		zap.Int("plain_size", len(plainBody)),
		zap.Int("encrypted_size", len(encryptedBody)),
		zap.Duration("duration", time.Since(startTime)))
}
