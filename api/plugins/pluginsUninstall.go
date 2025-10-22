package plugins

import (
	"cmdb-agent/common"
	"context"
	"fmt"
	"go.uber.org/zap"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// PluginUninstallHandler 卸载插件接口
func PluginUninstallHandler(w http.ResponseWriter, r *http.Request) {
	common.Info("收到卸载插件请求",
		zap.String("method", r.Method),
		zap.String("path", r.URL.Path))

	// 只允许DELETE请求
	if r.Method != http.MethodDelete {
		common.RespondMethodNotAllowed(w, "只允许DELETE请求")
		return
	}

	// 获取插件名称
	name := r.URL.Query().Get("name")
	if name == "" {
		common.RespondError(w, http.StatusBadRequest, "缺少插件名称参数")
		return
	}

	// 查询插件记录
	record, err := GetPluginRecord(name)
	if err != nil {
		common.Error("查询插件记录失败", zap.Error(err))
		common.RespondError(w, http.StatusInternalServerError,
			"查询插件记录失败: "+err.Error())
		return
	}

	if record == nil {
		common.RespondError(w, http.StatusNotFound, "插件不存在: "+name)
		return
	}

	// 根据类型执行卸载
	var uninstallErr error
	if record.Category == "container" {
		uninstallErr = uninstallContainer(record)
	} else if record.Category == "binary" {
		uninstallErr = uninstallBinary(record)
	} else {
		common.RespondError(w, http.StatusBadRequest, "不支持的插件类型: "+record.Category)
		return
	}

	if uninstallErr != nil {
		common.Error("卸载插件失败",
			zap.String("name", name),
			zap.Error(uninstallErr))
		common.RespondError(w, http.StatusInternalServerError,
			"卸载失败: "+uninstallErr.Error())
		return
	}

	// 从注册表中删除记录
	if err := RemovePluginRecord(name); err != nil {
		common.Warn("删除插件记录失败", zap.Error(err))
		// 继续执行，不中断
	}

	common.Info("卸载插件成功",
		zap.String("name", name),
		zap.String("category", record.Category))

	common.RespondSuccess(w, map[string]interface{}{
		"name":     name,
		"category": record.Category,
		"message":  fmt.Sprintf("插件 %s 卸载成功", name),
	})
}

// uninstallContainer 卸载容器类型插件
func uninstallContainer(record *PluginRecord) error {
	containerName := fmt.Sprintf("cmdb-%s", record.Name)

	common.Info("开始卸载容器插件",
		zap.String("name", record.Name),
		zap.String("container", containerName))

	// 创建超时上下文
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 步骤1: 停止容器
	common.Info("停止容器", zap.String("container", containerName))
	stopCmd := exec.CommandContext(ctx, "docker", "stop", containerName)
	if output, err := stopCmd.CombinedOutput(); err != nil {
		common.Warn("停止容器失败",
			zap.String("container", containerName),
			zap.String("output", string(output)),
			zap.Error(err))
		// 继续执行删除
	} else {
		common.Info("容器已停止", zap.String("container", containerName))
	}

	// 等待容器停止
	time.Sleep(1 * time.Second)

	// 步骤2: 删除容器
	common.Info("删除容器", zap.String("container", containerName))
	rmCmd := exec.CommandContext(ctx, "docker", "rm", "-f", containerName)
	output, err := rmCmd.CombinedOutput()
	if err != nil {
		// 检查是否因为容器不存在而失败
		if strings.Contains(string(output), "No such container") ||
			strings.Contains(string(output), "Error: No such container") {
			common.Info("容器不存在，跳过删除", zap.String("container", containerName))
		} else {
			return fmt.Errorf("删除容器失败: %v, 输出: %s", err, string(output))
		}
	} else {
		common.Info("容器已删除",
			zap.String("container", containerName),
			zap.String("output", strings.TrimSpace(string(output))))
	}

	return nil
}

// uninstallBinary 卸载二进制类型插件（使用systemd）
func uninstallBinary(record *PluginRecord) error {
	serviceName := common.GetServiceName(record.Name)

	common.Info("开始卸载二进制插件(systemd)",
		zap.String("name", record.Name),
		zap.String("service", serviceName),
		zap.String("binary_path", record.BinaryPath))

	// 步骤1: 删除systemd service（会自动停止服务）
	common.Info("删除systemd service", zap.String("service", serviceName))
	if err := common.DeleteSystemdService(record.Name); err != nil {
		common.Warn("删除systemd service失败",
			zap.String("service", serviceName),
			zap.Error(err))
		// 不返回错误，继续执行文件删除
	} else {
		common.Info("Systemd service已删除", zap.String("service", serviceName))
	}

	// 等待服务完全停止
	time.Sleep(2 * time.Second)

	// 步骤2: 删除插件目录
	if record.BinaryPath != "" {
		pluginDir := filepath.Dir(record.BinaryPath)

		// 确保路径在plugins目录下，避免误删
		if strings.Contains(pluginDir, "plugins") && pluginDir != "plugins" {
			common.Info("删除插件目录", zap.String("dir", pluginDir))

			if err := os.RemoveAll(pluginDir); err != nil {
				common.Warn("删除插件目录失败",
					zap.String("dir", pluginDir),
					zap.Error(err))
				// 不返回错误，继续执行
			} else {
				common.Info("插件目录已删除", zap.String("dir", pluginDir))
			}
		}
	}

	return nil
}
