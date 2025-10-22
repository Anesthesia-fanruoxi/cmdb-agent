package plugins

import (
	"cmdb-agent/common"
	"fmt"
	"go.uber.org/zap"
	"os/exec"
	"strings"
	"time"
)

// pullDockerImage 拉取Docker镜像
func pullDockerImage(image string) error {
	common.Info("步骤1: 开始拉取Docker镜像",
		zap.String("image", image))

	// 检查Docker是否可用
	checkCmd := exec.Command("docker", "version")
	if err := checkCmd.Run(); err != nil {
		return fmt.Errorf("Docker不可用，请确保Docker已安装并运行: %v", err)
	}

	common.Info("Docker环境检查通过")

	// 拉取镜像
	pullCmd := exec.Command("docker", "pull", image)
	output, err := pullCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("拉取镜像失败: %v, 输出: %s", err, string(output))
	}

	common.Info("镜像拉取完成",
		zap.String("image", image),
		zap.String("output", string(output)))

	return nil
}

// startContainerService 启动容器服务
func startContainerService(name, image string, port int, command string, config map[string]interface{}, params Parameters) (string, error) {
	common.Info("步骤2: 开始启动容器服务",
		zap.String("name", name),
		zap.String("image", image))

	// 生成容器名称 - 统一格式: cmdb-{name}
	containerName := fmt.Sprintf("cmdb-%s", name)

	// 检查是否已存在同名容器
	checkCmd := exec.Command("docker", "ps", "-a", "--filter", fmt.Sprintf("name=%s", containerName), "--format", "{{.Names}}")
	checkOutput, _ := checkCmd.Output()
	if strings.TrimSpace(string(checkOutput)) == containerName {
		common.Warn("发现同名容器，将先删除",
			zap.String("container", containerName))

		// 停止并删除旧容器
		exec.Command("docker", "stop", containerName).Run()
		exec.Command("docker", "rm", containerName).Run()

		common.Info("旧容器已删除", zap.String("container", containerName))
	}

	// 构建docker run命令参数
	dockerArgs := []string{
		"run",
		"-d", // 后台运行
		"--name", containerName,
		"--restart", "unless-stopped", // 自动重启
	}

	// 添加端口映射
	if port > 0 {
		// 确定容器内端口
		containerPort := params.ContainerPort
		if containerPort == 0 {
			containerPort = port // 默认容器端口和宿主机端口相同
		}

		portMapping := fmt.Sprintf("%d:%d", port, containerPort)
		dockerArgs = append(dockerArgs, "-p", portMapping)
		common.Info("配置端口映射",
			zap.Int("host_port", port),
			zap.Int("container_port", containerPort),
			zap.String("mapping", portMapping))
	}

	// 添加环境变量（从config中）
	for key, value := range config {
		if strValue, ok := value.(string); ok {
			envVar := fmt.Sprintf("%s=%s", key, strValue)
			dockerArgs = append(dockerArgs, "-e", envVar)
			common.Debug("添加环境变量", zap.String("env", envVar))
		}
	}

	// 添加镜像名称
	dockerArgs = append(dockerArgs, image)

	// 如果有自定义命令，添加到参数末尾
	if command != "" {
		cmdParts := strings.Fields(command)
		dockerArgs = append(dockerArgs, cmdParts...)
		common.Info("使用自定义容器命令", zap.String("command", command))
	}

	common.Info("准备启动容器",
		zap.String("container", containerName),
		zap.Strings("args", dockerArgs))

	// 启动容器
	runCmd := exec.Command("docker", dockerArgs...)
	output, err := runCmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("启动容器失败: %v, 输出: %s", err, string(output))
	}

	containerID := strings.TrimSpace(string(output))
	common.Info("容器启动成功",
		zap.String("container_id", containerID[:12]),
		zap.String("container_name", containerName))

	// 等待容器完全启动
	common.Info("等待容器就绪...")
	time.Sleep(2 * time.Second)

	// 检查容器状态
	statusCmd := exec.Command("docker", "ps", "--filter", fmt.Sprintf("name=%s", containerName), "--format", "{{.Status}}")
	statusOutput, err := statusCmd.Output()
	if err != nil {
		common.Warn("无法获取容器状态", zap.Error(err))
	} else {
		common.Info("容器状态",
			zap.String("container", containerName),
			zap.String("status", strings.TrimSpace(string(statusOutput))))
	}

	return containerID, nil
}
