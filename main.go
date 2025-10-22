package main

import (
	"cmdb-agent/common"
	"cmdb-agent/config"
	"cmdb-agent/router"
	"context"
	"fmt"
	"go.uber.org/zap"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	// 初始化配置
	if err := config.Init(); err != nil {
		fmt.Printf("初始化配置失败: %v\n", err)
		os.Exit(1)
	}
	cfg := config.GetConfig()

	// 初始化日志系统
	logConfig := &common.LogConfig{
		Level:      cfg.Log.Level,
		FilePath:   cfg.Log.FilePath,
		MaxSize:    cfg.Log.MaxSize,
		MaxBackups: cfg.Log.MaxBackups,
		MaxAge:     cfg.Log.MaxAge,
		Compress:   cfg.Log.Compress,
	}

	if err := common.Init(logConfig); err != nil {
		fmt.Printf("初始化日志系统失败: %v\n", err)
		os.Exit(1)
	}
	defer common.Sync()

	common.Info("CMDB Agent启动")

	// 设置路由
	mux := router.SetupRouter()

	// 创建HTTP服务器
	server := &http.Server{
		Addr:         cfg.GetServerAddr(),
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	// 启动服务器
	go func() {
		common.Info("启动HTTP服务器", zap.String("address", cfg.GetServerAddr()))
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			common.Error("HTTP服务器启动失败", zap.Error(err))
		}
	}()

	common.Info("服务器启动完成", zap.String("address", cfg.GetServerAddr()))

	// 等待中断信号
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	common.Info("收到停止信号，开始关闭服务器...")

	// 优雅关闭
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		common.Error("服务器关闭失败", zap.Error(err))
	}

	common.Info("服务器已退出")
}
