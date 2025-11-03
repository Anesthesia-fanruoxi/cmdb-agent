package common

import "fmt"

// 版本信息，编译时通过 -ldflags 注入
var (
	Version   = "1.0.0"      // 版本号
	BuildTime = "2025-10-24" // 编译时间
)

// GetVersion 获取版本号
func GetVersion() string {
	return Version
}

// GetFullVersion 获取完整版本信息
func GetFullVersion() string {
	return fmt.Sprintf("v%s (build: %s)", Version, BuildTime)
}

// GetBuildInfo 获取构建信息
func GetBuildInfo() map[string]string {
	return map[string]string{
		"version":    Version,
		"build_time": BuildTime,
	}
}
