package plugins

import (
	"cmdb-agent/common"
	"context"
	"fmt"
	"go.uber.org/zap"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

// PluginOperatorHandler 插件操作接口（启动/停止/重启）
func PluginOperatorHandler(w http.ResponseWriter, r *http.Request) {
	common.Info("收到插件操作请求",
		zap.String("method", r.Method),
		zap.String("path", r.URL.Path))

	// 只允许PUT请求
	if r.Method != http.MethodPut {
		common.RespondMethodNotAllowed(w, "只允许PUT请求")
		return
	}

	// 获取插件名称和操作类型
	name := r.URL.Query().Get("name")
	action := r.URL.Query().Get("action") // start, stop, restart

	if name == "" {
		common.RespondError(w, http.StatusBadRequest, "缺少插件名称参数")
		return
	}

	if action == "" || (action != "start" && action != "stop" && action != "restart") {
		common.RespondError(w, http.StatusBadRequest, "无效的操作类型，支持: start, stop, restart")
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

	// 根据类型执行操作
	var result string
	if record.Category == "container" {
		result, err = operateContainer(record, action)
	} else if record.Category == "binary" {
		result, err = operateBinary(record, action)
	} else {
		common.RespondError(w, http.StatusBadRequest, "不支持的插件类型: "+record.Category)
		return
	}

	if err != nil {
		common.Error("插件操作失败",
			zap.String("name", name),
			zap.String("action", action),
			zap.Error(err))
		common.RespondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	common.Info("插件操作成功",
		zap.String("name", name),
		zap.String("action", action))

	common.RespondSuccess(w, map[string]interface{}{
		"name":    name,
		"action":  action,
		"result":  result,
		"message": fmt.Sprintf("插件 %s 操作成功", action),
	})
}

// operateContainer 操作容器类型插件
func operateContainer(record *PluginRecord, action string) (string, error) {
	containerName := fmt.Sprintf("cmdb-%s", record.Name)

	common.Info("开始操作容器",
		zap.String("container", containerName),
		zap.String("action", action))

	// 创建超时上下文（30秒超时）
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var cmd *exec.Cmd
	switch action {
	case "start":
		cmd = exec.CommandContext(ctx, "docker", "start", containerName)
	case "stop":
		cmd = exec.CommandContext(ctx, "docker", "stop", containerName)
	case "restart":
		cmd = exec.CommandContext(ctx, "docker", "restart", containerName)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("操作超时: %s", action)
		}
		return "", fmt.Errorf("执行 docker %s 失败: %v, 输出: %s", action, err, string(output))
	}

	result := strings.TrimSpace(string(output))

	// 等待状态稳定
	time.Sleep(500 * time.Millisecond)

	common.Info("容器操作完成",
		zap.String("container", containerName),
		zap.String("action", action),
		zap.String("result", result))

	return result, nil
}

// operateBinary 操作二进制类型插件（使用systemd）
func operateBinary(record *PluginRecord, action string) (string, error) {
	serviceName := common.GetServiceName(record.Name)

	common.Info("开始操作二进制插件(systemd)",
		zap.String("name", record.Name),
		zap.String("service", serviceName),
		zap.String("action", action))

	var err error
	switch action {
	case "start":
		err = common.SystemctlStart(record.Name)
	case "stop":
		err = common.SystemctlStop(record.Name)
	case "restart":
		err = common.SystemctlRestart(record.Name)
	default:
		return "", fmt.Errorf("不支持的操作: %s", action)
	}

	if err != nil {
		return "", err
	}

	// 等待状态稳定
	time.Sleep(500 * time.Millisecond)

	// 检查服务状态
	isActive := common.SystemctlIsActive(record.Name)
	status := "stopped"
	if isActive {
		status = "running"
	}

	common.Info("二进制插件操作完成",
		zap.String("name", record.Name),
		zap.String("action", action),
		zap.String("status", status))

	return fmt.Sprintf("服务 %s 操作成功，当前状态: %s", serviceName, status), nil
}
