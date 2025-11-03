package plugins

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

// WebSocket升级器
var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	// 允许跨域
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

// PluginLogsHandler WebSocket日志查看接口
func PluginLogsHandler(w http.ResponseWriter, r *http.Request) {
	// 获取真实客户端IP
	realClientIP := getRealClientIP(r)
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

	// 获取插件名称
	pluginName := r.URL.Query().Get("name")
	if pluginName == "" {
		common.Warn("缺少插件名称参数")
		http.Error(w, "缺少name参数", http.StatusBadRequest)
		return
	}

	// 固定配置：1000行，实时跟踪
	tail := "1000"
	follow := "true"

	// 查询插件信息
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

	// 升级为WebSocket连接
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		common.Error("WebSocket升级失败", zap.Error(err))
		return
	}
	defer conn.Close()

	common.Info("WebSocket连接已建立",
		zap.String("plugin", pluginName),
		zap.String("category", record.Category))

	// 根据插件类型选择日志流方式
	if record.Category == "container" {
		// 容器日志：使用docker logs
		if err := streamContainerLogs(conn, record.ContainerID, tail, follow); err != nil {
			common.Error("容器日志流失败",
				zap.String("plugin", pluginName),
				zap.Error(err))
		}
	} else if record.Category == "binary" {
		// 二进制日志：读取插件目录下的日志文件
		if err := streamBinaryLogs(conn, record.BinaryPath, tail, follow); err != nil {
			common.Error("二进制日志流失败",
				zap.String("plugin", pluginName),
				zap.Error(err))
		}
	} else {
		common.Error("不支持的插件类型", zap.String("category", record.Category))
		conn.WriteMessage(websocket.TextMessage, []byte("[ERROR] 不支持的插件类型"))
	}

	common.Info("WebSocket连接已关闭",
		zap.String("plugin", pluginName))
}

// streamContainerLogs 流式传输容器日志
func streamContainerLogs(conn *websocket.Conn, containerID, tail, follow string) error {
	// 构建docker logs命令
	args := []string{"logs"}

	// 添加tail参数
	if tail != "" && tail != "all" {
		args = append(args, "--tail", tail)
	}

	// 添加follow参数
	if follow == "true" {
		args = append(args, "-f")
	}

	// 添加容器ID
	args = append(args, containerID)

	common.Info("执行docker logs命令",
		zap.Strings("args", args))

	// 创建上下文，用于取消命令
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 创建命令
	cmd := exec.CommandContext(ctx, "docker", args...)

	// 获取标准输出管道
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("创建stdout管道失败: %v", err)
	}

	// 获取标准错误管道
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("创建stderr管道失败: %v", err)
	}

	// 启动命令
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("启动docker logs命令失败: %v", err)
	}

	common.Info("docker logs命令已启动")

	// 创建通道用于goroutine通信
	done := make(chan struct{})
	errChan := make(chan error, 1)

	// 创建互斥锁保护WebSocket写入
	var writeMutex sync.Mutex

	// 启动goroutine读取客户端消息（用于检测断开）
	go func() {
		for {
			_, _, err := conn.ReadMessage()
			if err != nil {
				common.Info("客户端断开连接", zap.Error(err))
				cancel() // 取消docker logs命令
				close(done)
				return
			}
		}
	}()

	// 启动goroutine读取标准输出
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()

			// 加锁保护WebSocket写入
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

	// 启动goroutine读取标准错误
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := scanner.Text()

			// 发送错误日志到WebSocket客户端（添加[ERROR]前缀）
			message := fmt.Sprintf("[ERROR] %s", line)

			// 加锁保护WebSocket写入
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

	// 启动goroutine发送心跳
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				// 加锁保护WebSocket写入
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

	// 等待完成或错误
	select {
	case <-done:
		common.Info("客户端主动断开")
	case err := <-errChan:
		common.Error("日志流错误", zap.Error(err))
		return err
	}

	// 等待命令结束
	if err := cmd.Wait(); err != nil {
		// 如果是被取消的，不算错误
		if !strings.Contains(err.Error(), "signal: killed") {
			common.Warn("docker logs命令异常退出", zap.Error(err))
		}
	}

	return nil
}

// streamSystemdLogs 流式传输systemd日志
func streamSystemdLogs(conn *websocket.Conn, pluginName, tail, follow string) error {
	serviceName := common.GetServiceName(pluginName)

	// 构建journalctl命令
	args := []string{"-u", serviceName}

	// 添加tail参数
	if tail != "" && tail != "all" {
		args = append(args, "-n", tail)
	}

	// 添加follow参数
	if follow == "true" {
		args = append(args, "-f")
	}

	// 添加输出格式
	args = append(args, "--output=short-iso", "--no-pager")

	common.Info("执行journalctl命令",
		zap.String("service", serviceName),
		zap.Strings("args", args))

	// 创建上下文，用于取消命令
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 创建命令（使用sudo）
	cmdArgs := append([]string{"journalctl"}, args...)
	cmd := exec.CommandContext(ctx, "sudo", cmdArgs...)

	// 获取标准输出管道
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("创建stdout管道失败: %v", err)
	}

	// 获取标准错误管道
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("创建stderr管道失败: %v", err)
	}

	// 启动命令
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("启动journalctl命令失败: %v", err)
	}

	common.Info("journalctl命令已启动")

	// 创建通道用于goroutine通信
	done := make(chan struct{})
	errChan := make(chan error, 1)

	// 启动goroutine读取客户端消息（用于检测断开）
	go func() {
		for {
			_, _, err := conn.ReadMessage()
			if err != nil {
				common.Info("客户端断开连接", zap.Error(err))
				cancel() // 取消journalctl命令
				close(done)
				return
			}
		}
	}()

	// 启动goroutine读取标准输出
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()

			// 发送日志到WebSocket客户端
			if err := conn.WriteMessage(websocket.TextMessage, []byte(line)); err != nil {
				errChan <- fmt.Errorf("发送消息失败: %v", err)
				return
			}
		}

		if err := scanner.Err(); err != nil {
			errChan <- fmt.Errorf("读取stdout失败: %v", err)
		}
	}()

	// 启动goroutine读取标准错误
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := scanner.Text()

			// 发送错误日志到WebSocket客户端（添加[ERROR]前缀）
			message := fmt.Sprintf("[ERROR] %s", line)
			if err := conn.WriteMessage(websocket.TextMessage, []byte(message)); err != nil {
				errChan <- fmt.Errorf("发送错误消息失败: %v", err)
				return
			}
		}

		if err := scanner.Err(); err != nil {
			errChan <- fmt.Errorf("读取stderr失败: %v", err)
		}
	}()

	// 启动goroutine发送心跳
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				// 发送ping消息保持连接
				if err := conn.WriteControl(websocket.PingMessage, []byte{}, time.Now().Add(10*time.Second)); err != nil {
					common.Warn("发送ping消息失败", zap.Error(err))
					return
				}
			}
		}
	}()

	// 等待完成或错误
	select {
	case <-done:
		common.Info("客户端主动断开")
	case err := <-errChan:
		common.Error("日志流错误", zap.Error(err))
		return err
	}

	// 等待命令结束
	if err := cmd.Wait(); err != nil {
		// 如果是被取消的，不算错误
		if !strings.Contains(err.Error(), "signal: killed") {
			common.Warn("journalctl命令异常退出", zap.Error(err))
		}
	}

	return nil
}

// streamBinaryLogs 流式传输二进制插件日志（从文件读取）
func streamBinaryLogs(conn *websocket.Conn, binaryPath, tailLines, follow string) error {
	// 获取日志文件路径
	pluginDir := filepath.Dir(binaryPath)
	pluginName := filepath.Base(binaryPath)
	logFile := filepath.Join(pluginDir, pluginName+".log")

	common.Info("读取二进制插件日志文件",
		zap.String("log_file", logFile),
		zap.String("tail", tailLines),
		zap.String("follow", follow))

	// 检查日志文件是否存在
	if _, err := os.Stat(logFile); os.IsNotExist(err) {
		return fmt.Errorf("日志文件不存在: %s", logFile)
	}

	// 构建tail命令
	args := []string{}

	// 添加tail参数
	if tailLines != "" && tailLines != "all" {
		args = append(args, "-n", tailLines)
	} else {
		args = append(args, "-n", "100") // 默认显示100行
	}

	// 添加follow参数
	if follow == "true" {
		args = append(args, "-f")
	}

	// 添加日志文件路径
	args = append(args, logFile)

	common.Info("执行tail命令",
		zap.String("log", logFile),
		zap.Strings("args", args))

	// 创建上下文，用于取消命令
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 创建命令
	cmd := exec.CommandContext(ctx, "tail", args...)

	// 获取标准输出管道
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("创建stdout管道失败: %v", err)
	}

	// 启动命令
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("启动tail命令失败: %v", err)
	}

	common.Info("tail命令已启动")

	// 创建通道用于goroutine通信
	done := make(chan struct{})
	errChan := make(chan error, 1)

	// 创建互斥锁保护WebSocket写入
	var writeMutex sync.Mutex

	// 启动goroutine读取客户端消息（用于检测断开）
	go func() {
		for {
			_, _, err := conn.ReadMessage()
			if err != nil {
				common.Info("客户端断开连接", zap.Error(err))
				cancel() // 取消tail命令
				close(done)
				return
			}
		}
	}()

	// 启动goroutine读取标准输出
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()

			// 加锁保护WebSocket写入
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

	// 启动goroutine发送心跳
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				// 加锁保护WebSocket写入
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

	// 等待完成或错误
	select {
	case <-done:
		common.Info("客户端主动断开")
	case err := <-errChan:
		common.Error("日志流错误", zap.Error(err))
		return err
	}

	// 等待命令结束
	if err := cmd.Wait(); err != nil {
		// 如果是被取消的，不算错误
		if !strings.Contains(err.Error(), "signal: killed") {
			common.Warn("tail命令异常退出", zap.Error(err))
		}
	}

	return nil
}
