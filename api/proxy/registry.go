package proxy

import (
	"cmdb-agent/common"
	"encoding/json"
	"go.uber.org/zap"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var (
	registryMutex sync.RWMutex
	registryPath  = "plugins/.plugins.json"
	initOnce      sync.Once
)

// Parameters 插件参数配置
type Parameters struct {
	ContainerPort int `json:"container_port"` // 容器内服务端口（可选，默认和port相同）
}

// PluginRecord 插件记录
type PluginRecord struct {
	Name          string                 `json:"name"`
	Version       string                 `json:"version"`
	Category      string                 `json:"category"`
	Image         string                 `json:"image,omitempty"`        // 容器：镜像地址
	ContainerID   string                 `json:"container_id,omitempty"` // 容器：容器ID
	DownloadURL   string                 `json:"download_url,omitempty"` // 二进制：下载地址
	BinaryPath    string                 `json:"binary_path,omitempty"`  // 二进制：可执行文件路径
	Command       string                 `json:"command,omitempty"`      // 二进制：启动命令
	ProcessID     int                    `json:"process_id,omitempty"`   // 二进制：进程ID
	Port          int                    `json:"port"`
	ContainerPort int                    `json:"container_port,omitempty"` // 容器内端口
	Config        map[string]interface{} `json:"config,omitempty"`
	Parameters    Parameters             `json:"parameters,omitempty"`
	InstalledAt   time.Time              `json:"installed_at"`
	UpdatedAt     time.Time              `json:"updated_at"`
}

// PluginRegistry 插件注册表
type PluginRegistry struct {
	Version   string          `json:"version"`
	UpdatedAt time.Time       `json:"updated_at"`
	Plugins   []*PluginRecord `json:"plugins"`
}

// initRegistry 初始化插件注册表文件
func initRegistry() error {
	var initErr error

	initOnce.Do(func() {
		pluginsDir := filepath.Dir(registryPath)
		if err := os.MkdirAll(pluginsDir, 0755); err != nil {
			initErr = err
			return
		}

		if _, err := os.Stat(registryPath); os.IsNotExist(err) {
			registry := &PluginRegistry{
				Version:   "1.0",
				UpdatedAt: time.Now(),
				Plugins:   []*PluginRecord{},
			}

			data, err := json.MarshalIndent(registry, "", "  ")
			if err != nil {
				initErr = err
				return
			}

			initErr = os.WriteFile(registryPath, data, 0644)
			if initErr == nil {
				common.Info("插件注册表初始化完成", zap.String("path", registryPath))
			}
		}
	})

	return initErr
}

// loadRegistry 加载插件注册表
func loadRegistry() (*PluginRegistry, error) {
	if err := initRegistry(); err != nil {
		return nil, err
	}

	registryMutex.RLock()
	defer registryMutex.RUnlock()

	data, err := os.ReadFile(registryPath)
	if err != nil {
		return nil, err
	}

	var registry PluginRegistry
	if err := json.Unmarshal(data, &registry); err != nil {
		backupPath := registryPath + ".backup"
		if renameErr := os.Rename(registryPath, backupPath); renameErr != nil {
			common.Warn("备份损坏的注册表文件失败", zap.String("backup", backupPath), zap.Error(renameErr))
		}
		common.Warn("注册表文件损坏，已备份",
			zap.String("backup", backupPath))

		registry = PluginRegistry{
			Version:   "1.0",
			UpdatedAt: time.Now(),
			Plugins:   []*PluginRecord{},
		}
	}

	return &registry, nil
}

// saveRegistry 保存插件注册表
func saveRegistry(registry *PluginRegistry) error {
	registryMutex.Lock()
	defer registryMutex.Unlock()

	registry.UpdatedAt = time.Now()

	data, err := json.MarshalIndent(registry, "", "  ")
	if err != nil {
		return err
	}

	pluginsDir := filepath.Dir(registryPath)
	if err := os.MkdirAll(pluginsDir, 0755); err != nil {
		return err
	}

	return os.WriteFile(registryPath, data, 0644)
}

// AddPluginRecord 添加插件记录
func AddPluginRecord(record *PluginRecord) error {
	registry, err := loadRegistry()
	if err != nil {
		return err
	}

	for i, p := range registry.Plugins {
		if p.Name == record.Name {
			record.InstalledAt = time.Now()
			record.UpdatedAt = time.Now()
			registry.Plugins[i] = record
			common.Info("更新插件记录", zap.String("name", record.Name))
			return saveRegistry(registry)
		}
	}

	record.InstalledAt = time.Now()
	record.UpdatedAt = time.Now()
	registry.Plugins = append(registry.Plugins, record)

	common.Info("添加插件记录",
		zap.String("name", record.Name),
		zap.String("category", record.Category))

	return saveRegistry(registry)
}

// RemovePluginRecord 删除插件记录
func RemovePluginRecord(name string) error {
	registry, err := loadRegistry()
	if err != nil {
		return err
	}

	for i, p := range registry.Plugins {
		if p.Name == name {
			registry.Plugins = append(registry.Plugins[:i], registry.Plugins[i+1:]...)
			common.Info("删除插件记录", zap.String("name", name))
			return saveRegistry(registry)
		}
	}

	return nil
}

// GetPluginRecord 获取插件记录
func GetPluginRecord(name string) (*PluginRecord, error) {
	registry, err := loadRegistry()
	if err != nil {
		return nil, err
	}

	for _, p := range registry.Plugins {
		if p.Name == name {
			return p, nil
		}
	}

	return nil, nil
}

// ListPluginRecords 列出所有插件记录
func ListPluginRecords() ([]*PluginRecord, error) {
	registry, err := loadRegistry()
	if err != nil {
		return nil, err
	}

	return registry.Plugins, nil
}
