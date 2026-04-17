package router

import (
	"cmdb-agent/api/operator"
	"cmdb-agent/api/proxy"
	"cmdb-agent/api/update"
	"cmdb-agent/common"
	"go.uber.org/zap"
	"net/http"
)

// SetupRouter 设置路由
func SetupRouter() *http.ServeMux {
	mux := http.NewServeMux()

	// 插件安装接口
	mux.HandleFunc("/api/plugins/install", operator.InstallHandler)

	// 插件列表接口
	mux.HandleFunc("/api/plugins/list", operator.ListHandler)

	// 插件详情接口
	mux.HandleFunc("/api/plugins/detail", operator.DetailHandler)

	// 插件操作接口（启动/停止/重启）
	mux.HandleFunc("/api/plugins/operate", operator.OperatorHandler)

	// 插件配置更新接口（config_set upsert + config_delete 删除）
	mux.HandleFunc("/api/plugins/update", update.UpdateHandler)

	// 插件版本升级接口（只升级版本，不触发配置变动）
	mux.HandleFunc("/api/plugins/upgrade", update.UpgradeHandler)

	// 插件卸载接口
	mux.HandleFunc("/api/plugins/uninstall", operator.UninstallHandler)

	// 插件日志查看接口（WebSocket）
	mux.HandleFunc("/ws/plugins/logs", proxy.LogsHandler)

	// 插件任务日志查看接口（WebSocket）- 用于读取cicd任务日志
	mux.HandleFunc("/ws/cicd/logs", proxy.CustomLogHandler)

	// 健康检查接口
	mux.HandleFunc("/health", healthHandler)

	// 插件代理接口（使用 /proxy/ 前缀，避免与 /api/ 混淆）
	mux.HandleFunc("/proxy/", proxy.ProxyHandler)

	// 插件回调接口（插件执行完成后回调agent，agent加密后转发给CMDB）
	mux.HandleFunc("/api/plugins/callback/", proxy.CallbackHandler)

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
