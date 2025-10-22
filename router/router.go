package router

import (
	"cmdb-agent/api/plugins"
	"cmdb-agent/common"
	"go.uber.org/zap"
	"net/http"
)

// SetupRouter 设置路由
func SetupRouter() *http.ServeMux {
	mux := http.NewServeMux()

	// 插件安装接口
	mux.HandleFunc("/api/plugins/install", plugins.InstallHandler)

	// 插件列表接口
	mux.HandleFunc("/api/plugins/list", plugins.PluginsListHandler)

	// 插件操作接口（启动/停止/重启）
	mux.HandleFunc("/api/plugins/operate", plugins.PluginOperatorHandler)

	// 插件更新接口
	mux.HandleFunc("/api/plugins/update", plugins.PluginUpdateHandler)

	// 插件卸载接口
	mux.HandleFunc("/api/plugins/uninstall", plugins.PluginUninstallHandler)

	// 插件日志查看接口（WebSocket）
	mux.HandleFunc("/api/plugins/logs", plugins.PluginLogsHandler)

	// 健康检查接口
	mux.HandleFunc("/health", healthHandler)

	// 插件代理接口（使用 /proxy/ 前缀，避免与 /api/ 混淆）
	// 格式: /proxy/{plugin-name}/{real-path}
	mux.HandleFunc("/proxy/", plugins.PluginProxyHandler)

	// 插件回调接口（插件执行完成后回调agent，agent加密后转发给CMDB）
	// 格式: /api/plugins/callback/{plugin-name}?original_url=xxx
	mux.HandleFunc("/api/plugins/callback/", plugins.PluginCallbackHandler)

	common.Info("路由设置完成")
	return mux
}

// healthHandler 健康检查
func healthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		common.RespondMethodNotAllowed(w, "只允许GET请求")
		return
	}

	common.Debug("健康检查", zap.String("remote", r.RemoteAddr))

	common.RespondSuccess(w, map[string]string{
		"status": "ok",
	})
}
