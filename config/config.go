package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

// Config 应用配置结构
type Config struct {
	Server   ServerConfig   `mapstructure:"server"`
	CMDB     CMDBConfig     `mapstructure:"cmdb"`
	Agent    AgentConfig    `mapstructure:"agent"`
	Log      LogConfig      `mapstructure:"log"`
	Security SecurityConfig `mapstructure:"security"`
}

// ServerConfig API服务器配置
type ServerConfig struct {
	Port         int    `mapstructure:"port"`
	Host         string `mapstructure:"host"`
	ReadTimeout  int    `mapstructure:"read_timeout"`
	WriteTimeout int    `mapstructure:"write_timeout"`
}

// CMDBConfig CMDB平台配置
type CMDBConfig struct {
	URL               string `mapstructure:"url"`
	RegisterPath      string `mapstructure:"register_path"`
	HeartbeatPath     string `mapstructure:"heartbeat_path"`
	Timeout           int    `mapstructure:"timeout"`
	HeartbeatInterval int    `mapstructure:"heartbeat_interval"`
}

// AgentConfig 代理配置
type AgentConfig struct {
	Project string `mapstructure:"project"`
	URL     string `mapstructure:"url"`
}

// LogConfig 日志配置
type LogConfig struct {
	Level      string `mapstructure:"level"`
	FilePath   string `mapstructure:"file_path"`
	MaxSize    int    `mapstructure:"max_size"`
	MaxBackups int    `mapstructure:"max_backups"`
	MaxAge     int    `mapstructure:"max_age"`
	Compress   bool   `mapstructure:"compress"`
}

// SecurityConfig 安全配置
type SecurityConfig struct {
	AgentSalt string `mapstructure:"agent_salt"` // 代理加解密盐
}

var globalConfig *Config

// Init 初始化配置
func Init() error {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")

	// 添加配置文件搜索路径
	viper.AddConfigPath("./config")
	viper.AddConfigPath("./")
	viper.AddConfigPath("$HOME/.cmdb-agent")

	// 设置默认值
	setDefaults()

	// 支持环境变量
	viper.AutomaticEnv()
	viper.SetEnvPrefix("CMDB_AGENT")

	// 读取配置文件
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// 配置文件不存在，使用默认配置
			fmt.Printf("警告: 配置文件未找到，使用默认配置\n")
		} else {
			return fmt.Errorf("读取配置文件失败: %v", err)
		}
	}

	// 解析配置到结构体
	globalConfig = &Config{}
	if err := viper.Unmarshal(globalConfig); err != nil {
		return fmt.Errorf("解析配置失败: %v", err)
	}

	// 验证配置
	if err := validateConfig(globalConfig); err != nil {
		return fmt.Errorf("配置验证失败: %v", err)
	}

	return nil
}

// setDefaults 设置默认配置值
func setDefaults() {
	// 服务器默认配置
	viper.SetDefault("server.port", 8080)
	viper.SetDefault("server.host", "0.0.0.0")
	viper.SetDefault("server.read_timeout", 30)
	viper.SetDefault("server.write_timeout", 30)

	// CMDB平台默认配置
	viper.SetDefault("cmdb.url", "http://localhost:8080")
	viper.SetDefault("cmdb.register_path", "/api/agent/register")
	viper.SetDefault("cmdb.heartbeat_path", "/api/agent/heartbeat")
	viper.SetDefault("cmdb.timeout", 10)
	viper.SetDefault("cmdb.heartbeat_interval", 30)

	// 代理默认配置
	hostname, _ := os.Hostname()
	viper.SetDefault("agent.project", "default")
	viper.SetDefault("agent.url", fmt.Sprintf("http://%s:8080", hostname))

	// 日志默认配置
	viper.SetDefault("log.level", "info")
	viper.SetDefault("log.file_path", "./logs/cmdb-agent.log")
	viper.SetDefault("log.max_size", 100)
	viper.SetDefault("log.max_backups", 10)
	viper.SetDefault("log.max_age", 30)
	viper.SetDefault("log.compress", true)

	// 安全默认配置
	viper.SetDefault("security.enable_tls", false)
}

// validateConfig 验证配置
func validateConfig(cfg *Config) error {
	if cfg.Server.Port <= 0 || cfg.Server.Port > 65535 {
		return fmt.Errorf("无效的服务器端口: %d", cfg.Server.Port)
	}

	if cfg.CMDB.URL == "" {
		return fmt.Errorf("CMDB平台URL不能为空")
	}

	if cfg.Agent.Project == "" {
		return fmt.Errorf("代理项目不能为空")
	}

	if cfg.CMDB.HeartbeatInterval <= 0 {
		return fmt.Errorf("心跳间隔必须大于0")
	}

	// 确保日志目录存在
	if cfg.Log.FilePath != "" {
		logDir := filepath.Dir(cfg.Log.FilePath)
		if err := os.MkdirAll(logDir, 0755); err != nil {
			return fmt.Errorf("创建日志目录失败: %v", err)
		}
	}

	return nil
}

// GetConfig 获取全局配置
func GetConfig() *Config {
	return globalConfig
}

// GetServerAddr 获取服务器地址
func (c *Config) GetServerAddr() string {
	return fmt.Sprintf("%s:%d", c.Server.Host, c.Server.Port)
}

// GetCMDBURL 获取CMDB完整URL
func (c *Config) GetCMDBURL(path string) string {
	return c.CMDB.URL + path
}
