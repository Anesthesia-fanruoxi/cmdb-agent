package proxy

import (
	"bufio"
	"cmdb-agent/common"
	"context"
	"fmt"
	"github.com/gorilla/websocket"
	"go.uber.org/zap"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// upgrader WebSocket升级器
var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

// LogsHandler WebSocket日志查看接口
func LogsHandler(w http.ResponseWriter, r *http.Request) {
	realClientIP := GetRealClientIP(r.Header.Get("X-Real-IP"), r.Header.Get("X-Forwarded-For"))
	if realClientIP == "" {
		if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
			realClientIP = host
		} else {
			realClientIP = r.RemoteAddr
		}
	}

	common.Info("收到WebSocket日志查看请求",
		zap.String("client_ip", realClientIP),
		zap.String("path", r.URL.Path))

	pluginName := r.URL.Query().Get("name")
	if pluginName == "" {
		common.Warn("缺少插件名称参数")
		http.Error(w, "缺少name参数", http.StatusBadRequest)
		return
	}

	tail := "1000"
	follow := "true"

	record, err := GetPluginRecord(pluginName)
	if err != nil {
		common.Error("查询插件记录失败", zap.Error(err))
		http.Error(w, "查询插件失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if record == nil {
		common.Warn("插件不存在", zap.String("name", pluginName))
		http.Error(w, "插件不存在: "+pluginName, http.StatusNotFound)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		common.Error("WebSocket升级失败", zap.Error(err))
		return
	}
	defer func() { _ = conn.Close() }()

	common.Info("WebSocket连接已建立",
		zap.String("plugin", pluginName),
		zap.String("category", record.Category))

	if record.Category == "container" {
		if err := streamContainerLogs(conn, record.ContainerID, tail, follow); err != nil {
			common.Error("容器日志流失败",
				zap.String("plugin", pluginName),
				zap.Error(err))
		}
	} else if record.Category == "binary" {
		if err := streamBinaryLogs(conn, record.BinaryPath, tail, follow); err != nil {
			common.Error("二进制日志流失败",
				zap.String("plugin", pluginName),
				zap.Error(err))
		}
	} else {
		common.Error("不支持的插件类型", zap.String("category", record.Category))
		if err := conn.WriteMessage(websocket.TextMessage, []byte("[ERROR] 不支持的插件类型")); err != nil {
			common.Warn("发送错误消息失败", zap.Error(err))
		}
	}

	common.Info("WebSocket连接已关闭", zap.String("plugin", pluginName))
}

// streamContainerLogs 流式传输容器日志
func streamContainerLogs(conn *websocket.Conn, containerID, tail, follow string) error {
	args := []string{"logs"}

	if tail != "" && tail != "all" {
		args = append(args, "--tail", tail)
	}
	if follow == "true" {
		args = append(args, "-f")
	}
	args = append(args, containerID)

	common.Info("执行docker logs命令", zap.Strings("args", args))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cmd := exec.CommandContext(ctx, "docker", args...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("创建stdout管道失败: %v", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("创建stderr管道失败: %v", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("启动docker logs命令失败: %v", err)
	}

	common.Info("docker logs命令已启动")

	done := make(chan struct{})
	errChan := make(chan error, 1)
	var writeMutex sync.Mutex

	go func() {
		for {
			_, _, err := conn.ReadMessage()
			if err != nil {
				common.Info("客户端断开连接", zap.Error(err))
				cancel()
				close(done)
				return
			}
		}
	}()

	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			writeMutex.Lock()
			err := conn.WriteMessage(websocket.TextMessage, []byte(line))
			writeMutex.Unlock()
			if err != nil {
				errChan <- fmt.Errorf("发送消息失败: %v", err)
				return
			}
		}
		if err := scanner.Err(); err != nil {
			errChan <- fmt.Errorf("读取stdout失败: %v", err)
		}
	}()

	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := scanner.Text()
			message := fmt.Sprintf("[ERROR] %s", line)
			writeMutex.Lock()
			err := conn.WriteMessage(websocket.TextMessage, []byte(message))
			writeMutex.Unlock()
			if err != nil {
				errChan <- fmt.Errorf("发送错误消息失败: %v", err)
				return
			}
		}
		if err := scanner.Err(); err != nil {
			errChan <- fmt.Errorf("读取stderr失败: %v", err)
		}
	}()

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				writeMutex.Lock()
				err := conn.WriteControl(websocket.PingMessage, []byte{}, time.Now().Add(10*time.Second))
				writeMutex.Unlock()
				if err != nil {
					common.Warn("发送ping消息失败", zap.Error(err))
					return
				}
			}
		}
	}()

	select {
	case <-done:
		common.Info("客户端主动断开")
	case err := <-errChan:
		common.Error("日志流错误", zap.Error(err))
		return err
	}

	if err := cmd.Wait(); err != nil {
		if !strings.Contains(err.Error(), "signal: killed") {
			common.Warn("docker logs命令异常退出", zap.Error(err))
		}
	}

	return nil
}

// streamBinaryLogs 流式传输二进制插件日志（从文件读取）
func streamBinaryLogs(conn *websocket.Conn, binaryPath, tailLines, follow string) error {
	pluginDir := filepath.Dir(binaryPath)
	pluginName := filepath.Base(binaryPath)
	logFile := filepath.Join(pluginDir, pluginName+".log")

	common.Info("读取二进制插件日志文件",
		zap.String("log_file", logFile),
		zap.String("tail", tailLines),
		zap.String("follow", follow))

	if _, err := os.Stat(logFile); os.IsNotExist(err) {
		return fmt.Errorf("日志文件不存在: %s", logFile)
	}

	args := []string{}
	if tailLines != "" && tailLines != "all" {
		args = append(args, "-n", tailLines)
	} else {
		args = append(args, "-n", "100")
	}
	if follow == "true" {
		args = append(args, "-f")
	}
	args = append(args, logFile)

	common.Info("执行tail命令",
		zap.String("log", logFile),
		zap.Strings("args", args))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cmd := exec.CommandContext(ctx, "tail", args...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("创建stdout管道失败: %v", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("启动tail命令失败: %v", err)
	}

	common.Info("tail命令已启动")

	done := make(chan struct{})
	errChan := make(chan error, 1)
	var writeMutex sync.Mutex

	go func() {
		for {
			_, _, err := conn.ReadMessage()
			if err != nil {
				common.Info("客户端断开连接", zap.Error(err))
				cancel()
				close(done)
				return
			}
		}
	}()

	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			writeMutex.Lock()
			err := conn.WriteMessage(websocket.TextMessage, []byte(scanner.Text()))
			writeMutex.Unlock()
			if err != nil {
				errChan <- fmt.Errorf("发送消息失败: %v", err)
				return
			}
		}
		if err := scanner.Err(); err != nil {
			errChan <- fmt.Errorf("读取stdout失败: %v", err)
		}
	}()

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				writeMutex.Lock()
				err := conn.WriteControl(websocket.PingMessage, []byte{}, time.Now().Add(10*time.Second))
				writeMutex.Unlock()
				if err != nil {
					common.Warn("发送ping消息失败", zap.Error(err))
					return
				}
			}
		}
	}()

	select {
	case <-done:
		common.Info("客户端主动断开")
	case err := <-errChan:
		common.Error("日志流错误", zap.Error(err))
		return err
	}

	if err := cmd.Wait(); err != nil {
		if !strings.Contains(err.Error(), "signal: killed") {
			common.Warn("tail命令异常退出", zap.Error(err))
		}
	}

	return nil
}
