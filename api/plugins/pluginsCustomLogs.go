package plugins

import (
	"bytes"
	"cmdb-agent/common"
	"cmdb-agent/config"
	"encoding/json"
	"fmt"
	"github.com/gorilla/websocket"
	"go.uber.org/zap"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// min 返回两个整数中的最小值
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// taskLogConnection 任务日志WebSocket连接管理
type taskLogConnection struct {
	conn        *websocket.Conn
	taskID      string
	stepType    string
	logFilePath string
	mu          sync.Mutex
	closeChan   chan struct{}
	lastFilePos int64
	logBuffer   []string
	bufferSize  int
	flushTicker *time.Ticker
	maxLines    int
}

// PluginCustomLogHandler 任务日志WebSocket处理函数
// 客户端示例：
// const ws = new WebSocket(`ws://agent地址/ws/cicd/logs?data=加密参数`);
// ws.onmessage = function(event) { console.log(event.data); };
func PluginCustomLogHandler(w http.ResponseWriter, r *http.Request) {
	// 获取真实客户端IP
	realClientIP := getRealClientIP(r)
	if realClientIP == "" {
		if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
			realClientIP = host
		} else {
			realClientIP = r.RemoteAddr
		}
	}

	common.Info("收到cicd日志WebSocket请求",
		zap.String("client_ip", realClientIP),
		zap.String("url", r.URL.String()))

	// 获取加密的参数
	encryptedData := r.URL.Query().Get("data")
	if encryptedData == "" {
		common.Warn("缺少加密参数data")
		common.RespondBadRequest(w, "缺少加密参数")
		return
	}

	common.Debug("接收到加密参数",
		zap.String("encrypted_data_length", fmt.Sprintf("%d字节", len(encryptedData))))

	// 解密参数（使用common中的解密方法）
	cfg := config.GetConfig()
	common.Debug("准备解密参数",
		zap.String("salt_length", fmt.Sprintf("%d字节", len(cfg.Security.AgentSalt))))

	decryptedData, err := common.DecryptAndDecompress(encryptedData, cfg.Security.AgentSalt)
	if err != nil {
		common.Error("解密参数失败",
			zap.Error(err),
			zap.String("encrypted_data_prefix", encryptedData[:min(50, len(encryptedData))]))
		common.RespondBadRequest(w, "解密参数失败")
		return
	}

	common.Debug("解密成功",
		zap.String("decrypted_data", string(decryptedData)))

	// 解析解密后的参数
	var params struct {
		TaskID   string `json:"taskId"`
		StepType string `json:"stepType"`
	}

	if err := json.Unmarshal(decryptedData, &params); err != nil {
		common.Error("解析参数失败",
			zap.Error(err),
			zap.String("decrypted_data", string(decryptedData)))
		common.RespondBadRequest(w, "解析参数失败")
		return
	}

	taskID := params.TaskID
	stepType := params.StepType

	common.Info("解析参数成功",
		zap.String("task_id", taskID),
		zap.String("step_type", stepType))

	if taskID == "" {
		common.Warn("taskId参数为空")
		common.RespondBadRequest(w, "缺少任务ID参数")
		return
	}
	if stepType == "" {
		common.Warn("stepType参数为空")
		common.RespondBadRequest(w, "缺少步骤名称参数")
		return
	}

	common.Info("收到任务日志请求",
		zap.String("task_id", taskID),
		zap.String("step_type", stepType))

	// 升级HTTP连接为WebSocket连接
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		common.Error("升级WebSocket连接失败", zap.Error(err))
		return
	}

	common.Info("WebSocket连接升级成功",
		zap.String("task_id", taskID),
		zap.String("step_type", stepType),
		zap.String("client_ip", realClientIP))

	// 构建日志文件路径
	logFilePath := buildLogFilePath(taskID, stepType)

	common.Info("构建日志文件路径",
		zap.String("task_id", taskID),
		zap.String("step_type", stepType),
		zap.String("log_file_path", logFilePath))

	// 创建连接管理对象
	tc := &taskLogConnection{
		conn:        conn,
		taskID:      taskID,
		stepType:    stepType,
		logFilePath: logFilePath,
		closeChan:   make(chan struct{}),
		lastFilePos: 0,
		logBuffer:   make([]string, 0, 100),
		bufferSize:  0,
		flushTicker: time.NewTicker(200 * time.Millisecond),
		maxLines:    1000,
	}

	common.Info("开始处理任务日志",
		zap.String("task_id", taskID),
		zap.String("step_type", stepType))

	// 发送当前日志
	tc.sendCurrentLogs()

	// 启动监听任务日志的goroutine
	go tc.watchTaskLogs()

	// 启动缓冲区刷新goroutine
	go tc.flushBufferRoutine()

	// 处理客户端消息
	go tc.handleMessages()
}

// buildLogFilePath 构建日志文件路径
func buildLogFilePath(taskID, stepType string) string {
	// 日志文件名映射
	var logFileName string
	switch stepType {
	case "console":
		logFileName = "console.log"
	case "pullOnline":
		logFileName = "pullOnline.log"
	case "tagImages":
		logFileName = "tagImages.log"
	case "pushLocal":
		logFileName = "pushLocal.log"
	case "checkImage":
		logFileName = "checkImage.log"
	case "deployService":
		logFileName = "deployService.log"
	case "checkService":
		logFileName = "checkService.log"
	case "trafficSwitching":
		logFileName = "trafficSwitching.log"
	case "cleanupOldVersion":
		logFileName = "cleanupOldVersion.log"
	default:
		logFileName = stepType + ".log"
	}

	// 构建完整的日志文件路径: logs/{任务ID}/{日志文件名}
	return filepath.Join("plugins/cicd-agent/logs", taskID, logFileName)
}

// sendCurrentLogs 发送当前日志
func (tc *taskLogConnection) sendCurrentLogs() {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	common.Debug("检查日志文件是否存在",
		zap.String("task_id", tc.taskID),
		zap.String("log_file_path", tc.logFilePath))

	// 检查日志文件是否存在
	if _, err := os.Stat(tc.logFilePath); os.IsNotExist(err) {
		common.Info("日志文件不存在",
			zap.String("task_id", tc.taskID),
			zap.String("log_file_path", tc.logFilePath))
		err := tc.conn.WriteMessage(websocket.TextMessage, []byte("日志文件不存在或尚未生成"))
		if err != nil {
			common.Error("发送消息失败", zap.Error(err))
		}
		return
	}

	common.Info("日志文件存在，开始读取",
		zap.String("task_id", tc.taskID),
		zap.String("log_file_path", tc.logFilePath))

	// 读取日志文件内容
	content, err := os.ReadFile(tc.logFilePath)
	if err != nil {
		common.Warn("读取日志文件失败",
			zap.String("task_id", tc.taskID),
			zap.Error(err))
		return
	}

	common.Info("读取日志文件成功",
		zap.String("task_id", tc.taskID),
		zap.Int("file_size", len(content)))

	// 发送日志内容（限制行数）
	if len(content) > 0 {
		// 按行分割内容
		lines := splitLines(string(content))

		// 如果行数超过限制，只取最后maxLines行
		if len(lines) > tc.maxLines {
			sendLines := lines[len(lines)-tc.maxLines:]
			// 添加提示信息
			prefixMsg := fmt.Sprintf("[日志过长，仅显示最后%d行，总共%d行]\n", tc.maxLines, len(lines))
			sendContent := prefixMsg + strings.Join(sendLines, "\n")

			common.Info("发送部分日志（超过限制）",
				zap.String("task_id", tc.taskID),
				zap.Int("total_lines", len(lines)),
				zap.Int("send_lines", len(sendLines)))

			err := tc.conn.WriteMessage(websocket.TextMessage, []byte(sendContent))
			if err != nil {
				common.Error("发送日志失败", zap.Error(err))
				return
			}
		} else {
			common.Info("发送完整日志",
				zap.String("task_id", tc.taskID),
				zap.Int("total_lines", len(lines)))

			// 发送全部内容
			err := tc.conn.WriteMessage(websocket.TextMessage, content)
			if err != nil {
				common.Error("发送日志失败", zap.Error(err))
				return
			}
		}
		// 设置文件位置为实际文件大小
		tc.lastFilePos = int64(len(content))

		common.Debug("初始日志发送完成",
			zap.String("task_id", tc.taskID),
			zap.Int64("file_pos", tc.lastFilePos))
	}
}

// watchTaskLogs 监听任务日志更新
func (tc *taskLogConnection) watchTaskLogs() {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-tc.closeChan:
			return
		case <-ticker.C:
			// 检查日志文件是否有更新
			fileInfo, err := os.Stat(tc.logFilePath)
			if err != nil {
				// 日志文件不存在时静默等待
				continue
			}

			// 如果文件大小有变化，读取新增内容
			if fileInfo.Size() > tc.lastFilePos {
				file, err := os.Open(tc.logFilePath)
				if err != nil {
					common.Error("打开日志文件失败", zap.Error(err))
					continue
				}

				// 从上次位置开始读取
				file.Seek(tc.lastFilePos, 0)
				buffer := make([]byte, fileInfo.Size()-tc.lastFilePos)
				n, err := file.Read(buffer)
				file.Close()

				if err != nil {
					common.Error("读取日志文件失败", zap.Error(err))
					continue
				}

				if n > 0 {
					// 解析新增日志
					newContent := string(buffer[:n])
					newLogs := splitLines(newContent)

					// 添加到缓冲区
					tc.mu.Lock()
					for _, log := range newLogs {
						if log == "" {
							continue
						}
						tc.logBuffer = append(tc.logBuffer, log)
						tc.bufferSize++
					}
					tc.mu.Unlock()
				}

				// 更新文件位置
				tc.lastFilePos = fileInfo.Size()
			}
		}
	}
}

// flushBufferRoutine 定期刷新缓冲区
func (tc *taskLogConnection) flushBufferRoutine() {
	defer tc.flushTicker.Stop()

	for {
		select {
		case <-tc.closeChan:
			return
		case <-tc.flushTicker.C:
			tc.flushBuffer()
		}
	}
}

// flushBuffer 刷新缓冲区，发送积累的日志
func (tc *taskLogConnection) flushBuffer() {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	if tc.bufferSize == 0 {
		return
	}

	// 构建批量消息
	var buffer bytes.Buffer
	for _, log := range tc.logBuffer {
		buffer.WriteString(log + "\n")
	}

	// 发送批量消息
	err := tc.conn.WriteMessage(websocket.TextMessage, buffer.Bytes())
	if err != nil {
		common.Error("批量发送日志失败", zap.Error(err))
		return
	}

	// 清空缓冲区
	tc.logBuffer = tc.logBuffer[:0]
	tc.bufferSize = 0
}

// handleMessages 处理客户端消息
func (tc *taskLogConnection) handleMessages() {
	defer tc.close()

	for {
		// 读取客户端消息
		_, _, err := tc.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				common.Error("WebSocket读取错误", zap.Error(err))
			}
			break
		}
		// 目前不处理客户端发送的消息
	}
}

// close 关闭连接
func (tc *taskLogConnection) close() {
	select {
	case <-tc.closeChan:
		// 已经关闭
		return
	default:
		// 关闭前发送剩余的日志
		tc.flushBuffer()

		close(tc.closeChan)
		tc.conn.Close()
	}
}

// splitLines 按行分割字符串
func splitLines(s string) []string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.Split(s, "\n")
}
