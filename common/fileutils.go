package common

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"go.uber.org/zap"
)

// GetExecutablePath 获取当前可执行文件路径
func GetExecutablePath() (string, error) {
	exePath, err := os.Executable()
	if err != nil {
		return "", err
	}
	// 解析符号链接
	return filepath.EvalSymlinks(exePath)
}

// BackupFile 备份文件
func BackupFile(src, dst string) error {
	return CopyFile(src, dst)
}

// RestoreFile 恢复备份文件
func RestoreFile(backup, target string) error {
	if _, err := os.Stat(backup); os.IsNotExist(err) {
		return fmt.Errorf("备份文件不存在: %s", backup)
	}
	return os.Rename(backup, target)
}

// ReplaceFile 替换文件
func ReplaceFile(src, dst string) error {
	return os.Rename(src, dst)
}

// RemoveFile 删除文件
func RemoveFile(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil // 文件不存在，无需删除
	}
	return os.Remove(path)
}

// CopyFile 复制文件
func CopyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	if err != nil {
		return err
	}

	// 复制文件权限
	sourceInfo, err := os.Stat(src)
	if err != nil {
		return err
	}
	return os.Chmod(dst, sourceInfo.Mode())
}

// SetExecutable 设置文件为可执行
func SetExecutable(path string) error {
	return os.Chmod(path, 0755)
}

// DownloadFile 下载文件
func DownloadFile(url, filepath string) error {
	Info("开始下载文件",
		zap.String("url", url),
		zap.String("save_to", filepath))

	// 创建HTTP客户端
	client := &http.Client{
		Timeout: 5 * time.Minute, // 下载超时5分钟
	}

	// 创建请求
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("请求失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("下载失败，HTTP状态码: %d", resp.StatusCode)
	}

	// 创建文件
	out, err := os.Create(filepath)
	if err != nil {
		return fmt.Errorf("创建文件失败: %v", err)
	}
	defer out.Close()

	// 写入文件
	written, err := io.Copy(out, resp.Body)
	if err != nil {
		return fmt.Errorf("写入文件失败: %v", err)
	}

	Info("文件下载完成",
		zap.String("file", filepath),
		zap.Int64("size_bytes", written))

	return nil
}

// RestartSystemdService 重启systemd服务
func RestartSystemdService(serviceName string) error {
	Info("重启systemd服务", zap.String("service", serviceName))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "systemctl", "restart", serviceName)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("重启服务失败: %v", err)
	}

	Info("服务重启成功", zap.String("service", serviceName))
	return nil
}
