package common

import (
	"fmt"
	"go.uber.org/zap"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

var (
	// 全局公网IP缓存
	publicIP string
	// IP缓存锁
	ipMutex sync.RWMutex
	// 定时刷新间隔
	refreshInterval = 1 * time.Hour
	// 初始化标志
	ipInitialized = false
)

// InitPublicIPRefresh 初始化公网IP定时刷新任务
// 应在程序启动时调用一次
func InitPublicIPRefresh() {
	// 立即获取一次IP
	ip := fetchPublicIP()
	if ip != "" {
		ipMutex.Lock()
		publicIP = ip
		ipMutex.Unlock()
		Info("初始化公网IP成功", zap.String("ip", ip))
	} else {
		Warn("初始化公网IP失败，将在后台定时重试")
	}

	ipMutex.Lock()
	ipInitialized = true
	ipMutex.Unlock()

	// 启动定时刷新任务
	go func() {
		ticker := time.NewTicker(refreshInterval)
		defer ticker.Stop()

		for range ticker.C {
			newIP := fetchPublicIP()
			if newIP != "" {
				ipMutex.Lock()
				oldIP := publicIP
				publicIP = newIP
				ipMutex.Unlock()

				if oldIP != newIP {
					Info("公网IP已更新",
						zap.String("old_ip", oldIP),
						zap.String("new_ip", newIP))
				} else {
					Debug("公网IP未变化", zap.String("ip", newIP))
				}
			} else {
				Warn("定时刷新公网IP失败，保持旧值")
			}
		}
	}()

	Info("公网IP定时刷新任务已启动", zap.Duration("interval", refreshInterval))
}

// GetPublicIP 获取公网IP地址
// 直接返回内存中的缓存值，不会阻塞
func GetPublicIP() string {
	ipMutex.RLock()
	defer ipMutex.RUnlock()

	// 如果未初始化，返回空字符串
	if !ipInitialized {
		return ""
	}

	return publicIP
}

// fetchPublicIP 从第三方接口获取公网IP
// 通过并发请求多个IP查询服务来提高获取成功率
func fetchPublicIP() string {
	urls := []string{
		"https://ident.me",
		"https://ipv4.icanhazip.com",
		"https://api.ipify.org",
	}

	var wg sync.WaitGroup
	results := make(chan string, len(urls))

	for _, url := range urls {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()

			client := &http.Client{
				Timeout: 10 * time.Second,
				Transport: &http.Transport{
					DisableKeepAlives: true,
				},
			}

			req, err := http.NewRequest("GET", u, nil)
			if err != nil {
				return
			}

			req.Header.Set("Cache-Control", "no-cache, no-store, must-revalidate")
			req.Header.Set("Pragma", "no-cache")
			req.Header.Set("Expires", "0")
			req.Header.Set("User-Agent", fmt.Sprintf("IP-Reporter-%d", time.Now().Unix()))

			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return
			}

			ip := strings.TrimSpace(string(body))
			if ip != "" {
				results <- ip
			}
		}(url)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	// 收集所有成功的IP，去重后返回第一个
	ipSet := make(map[string]bool)
	for ip := range results {
		ipSet[ip] = true
	}

	for ip := range ipSet {
		return ip
	}

	return ""
}
