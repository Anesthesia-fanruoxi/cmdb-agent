package plugins

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

// PluginRecord 插件记录
type PluginRecord struct {
	Name          string                 `json:"name"`
	Version       string                 `json:"version"`
	Category      string                 `json:"category"`
	Image         string                 `json:"image,omitempty"`        // 容器：镜像地址
	ContainerID   string                 `json:"container_id,omitempty"` // 容器：容器ID
	DownloadURL   string                 `json:"download_url,omitempty"` // 二进制：下载地址
	BinaryPath    string                 `json:"binary_path,omitempty"`  // 二进制：可执行文件路径
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
		// 创建plugins目录
		pluginsDir := filepath.Dir(registryPath)
		if err := os.MkdirAll(pluginsDir, 0755); err != nil {
			initErr = err
			return
		}

		// 检查文件是否存在
		if _, err := os.Stat(registryPath); os.IsNotExist(err) {
			// 创建空注册表（直接写文件，不调用saveRegistry避免死锁）
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
	// 先确保文件存在（不持有锁）
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
		// 文件损坏，备份并创建新文件
		backupPath := registryPath + ".backup"
		os.Rename(registryPath, backupPath)
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

	// 确保目录存在
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

	// 检查是否已存在
	for i, p := range registry.Plugins {
		if p.Name == record.Name {
			// 更新已存在的记录
			record.UpdatedAt = time.Now()
			registry.Plugins[i] = record
			common.Info("更新插件记录", zap.String("name", record.Name))
			return saveRegistry(registry)
		}
	}

	// 添加新记录
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

	// 查找并删除
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
