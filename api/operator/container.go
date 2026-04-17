package operator

import (
	"cmdb-agent/api/proxy"
	"cmdb-agent/common"
	"fmt"
	"go.uber.org/zap"
	"os/exec"
	"strings"
	"time"
)

// PullDockerImage 拉取Docker镜像
func PullDockerImage(image string) error {
	common.Info("步骤1: 开始拉取Docker镜像",
		zap.String("image", image))

	checkCmd := exec.Command("docker", "version")
	if err := checkCmd.Run(); err != nil {
		return fmt.Errorf("Docker不可用，请确保Docker已安装并运行: %v", err)
	}

	common.Info("Docker环境检查通过")

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

// StartContainerService 启动容器服务
func StartContainerService(name, image string, port int, command string, config map[string]interface{}, params proxy.Parameters) (string, error) {
	common.Info("步骤2: 开始启动容器服务",
		zap.String("name", name),
		zap.String("image", image))

	containerName := fmt.Sprintf("cmdb-%s", name)

	checkCmd := exec.Command("docker", "ps", "-a", "--filter", fmt.Sprintf("name=%s", containerName), "--format", "{{.Names}}")
	checkOutput, _ := checkCmd.Output()
	if strings.TrimSpace(string(checkOutput)) == containerName {
		common.Warn("发现同名容器，将先删除",
			zap.String("container", containerName))

		if err := exec.Command("docker", "stop", containerName).Run(); err != nil {
			common.Warn("停止旧容器失败，继续执行", zap.String("container", containerName), zap.Error(err))
		}
		if err := exec.Command("docker", "rm", containerName).Run(); err != nil {
			common.Warn("删除旧容器失败，继续执行", zap.String("container", containerName), zap.Error(err))
		}

		common.Info("旧容器已删除", zap.String("container", containerName))
	}

	dockerArgs := []string{
		"run",
		"-d",
		"--name", containerName,
		"--restart", "unless-stopped",
	}

	if port > 0 {
		containerPort := params.ContainerPort
		if containerPort == 0 {
			containerPort = port
		}

		portMapping := fmt.Sprintf("%d:%d", port, containerPort)
		dockerArgs = append(dockerArgs, "-p", portMapping)
		common.Info("配置端口映射",
			zap.Int("host_port", port),
			zap.Int("container_port", containerPort),
			zap.String("mapping", portMapping))
	}

	for key, value := range config {
		if strValue, ok := value.(string); ok {
			envVar := fmt.Sprintf("%s=%s", key, strValue)
			dockerArgs = append(dockerArgs, "-e", envVar)
			common.Debug("添加环境变量", zap.String("env", envVar))
		}
	}

	dockerArgs = append(dockerArgs, image)

	if command != "" {
		cmdParts := strings.Fields(command)
		dockerArgs = append(dockerArgs, cmdParts...)
		common.Info("使用自定义容器命令", zap.String("command", command))
	}

	common.Info("准备启动容器",
		zap.String("container", containerName),
		zap.Strings("args", dockerArgs))

	runCmd := exec.Command("docker", dockerArgs...)
	output, err := runCmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("启动容器失败: %v, 输出: %s", err, string(output))
	}

	containerID := strings.TrimSpace(string(output))
	common.Info("容器启动成功",
		zap.String("container_id", containerID[:12]),
		zap.String("container_name", containerName))

	common.Info("等待容器就绪...")
	time.Sleep(2 * time.Second)

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
