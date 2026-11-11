package doctor

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/sixban6/security-sentinel/internal/heal/ai"
	"github.com/sixban6/security-sentinel/internal/infra/config"
	"github.com/sixban6/security-sentinel/internal/infra/store"
	"github.com/sixban6/security-sentinel/internal/infra/model"
	"github.com/sixban6/security-sentinel/internal/ops/scheduler"
	"github.com/sixban6/security-sentinel/internal/infra/secrets"
	"github.com/sixban6/security-sentinel/internal/infra/transport"
)

// RunAll performs concurrent diagnostic checks across local config, network feeds, credentials, AI, scheduler, and all SSH hosts.
func RunAll(ctx context.Context, cfg config.Config, mem *store.Store) []model.DoctorItem {
	var items []model.DoctorItem

	// 1. Config check
	if cfg.SourcePath != "" {
		items = append(items, model.DoctorItem{
			Category: "local",
			Name:     "配置文件 (sentinel.yaml)",
			Status:   "ok",
			Summary:  fmt.Sprintf("已加载 %s (纳管 %d 台主机)", cfg.SourcePath, len(cfg.ConfiguredHosts())),
		})
	} else {
		items = append(items, model.DoctorItem{
			Category:   "local",
			Name:       "配置文件 (sentinel.yaml)",
			Status:     "warn",
			Summary:    "未找到 sentinel.yaml，当前仅守护本机",
			Suggestion: "运行 `security-sentinel init --global` 或在桌面端使用向导一键导入 ~/.ssh/config",
		})
	}

	// 2. OSV & Advisory network reachability
	httpCli := &http.Client{Timeout: 5 * time.Second}
	t0 := time.Now()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.osv.dev/v1/querybatch", nil)
	if resp, err := httpCli.Do(req); err == nil {
		_ = resp.Body.Close()
		items = append(items, model.DoctorItem{
			Category:  "intel",
			Name:      "Google OSV 漏洞库连通性",
			Status:    "ok",
			LatencyMS: time.Since(t0).Milliseconds(),
			Summary:   "在线可达，全量存量漏洞比对引擎正常",
		})
	} else {
		items = append(items, model.DoctorItem{
			Category:   "intel",
			Name:       "Google OSV 漏洞库连通性",
			Status:     "warn",
			Summary:    fmt.Sprintf("连接超时或离线: %v", err),
			Suggestion: "请检查本机外网或代理连通性",
		})
	}

	// 3. GitHub Token quota check
	if gh := secrets.Get(secrets.KeyGitHubToken); gh != "" {
		items = append(items, model.DoctorItem{
			Category: "intel",
			Name:     "GitHub API 授权配额",
			Status:   "ok",
			Summary:  "已配置 Token (5,000 次/小时高配额)",
		})
	} else {
		items = append(items, model.DoctorItem{
			Category:   "intel",
			Name:       "GitHub API 授权配额",
			Status:     "warn",
			Summary:    "使用匿名配额 (60 次/小时)",
			Suggestion: "可在设置页钥匙串保存 GITHUB_TOKEN 或登录 `gh auth login`",
		})
	}

	// 4. Telegram check
	tgTok := secrets.Get(secrets.KeyTelegramBotToken)
	tgChat := secrets.Get(secrets.KeyTelegramChatID)
	switch {
	case tgTok != "" && tgChat != "":
		items = append(items, model.DoctorItem{
			Category: "notify",
			Name:     "Telegram 移动端推送",
			Status:   "ok",
			Summary:  fmt.Sprintf("已安全配对绑定 (Chat ID: %s)", tgChat),
		})
	case tgTok != "":
		items = append(items, model.DoctorItem{
			Category:   "notify",
			Name:       "Telegram 移动端推送",
			Status:     "warn",
			Summary:    "已配置 Bot Token，但尚未完成 Chat ID 配对绑定",
			Suggestion: "在桌面端设置页或执行 `security-sentinel telegram-pair` 使用 6 位配对码绑定",
		})
	default:
		items = append(items, model.DoctorItem{
			Category:   "notify",
			Name:       "Telegram 移动端推送",
			Status:     "warn",
			Summary:    "未配置 Telegram Bot (仅启用本机桌面通知)",
			Suggestion: "在设置页钥匙串填入 Bot Token 即可开启手机端实时卡片",
		})
	}

	// 5. AI Provider check
	aiEng := ai.NewEngine(cfg.AIRemediation, mem)
	prov, provDesc := aiEng.ResolveProvider()
	if prov != "" {
		items = append(items, model.DoctorItem{
			Category: "ai",
			Name:     "AI 智能研判引擎",
			Status:   "ok",
			Summary:  fmt.Sprintf("已就绪 [%s] (%s)", prov, provDesc),
		})
	} else {
		st := "ok"
		if cfg.AIRemediation.Enabled {
			st = "warn"
		}
		items = append(items, model.DoctorItem{
			Category:   "ai",
			Name:       "AI 智能研判引擎",
			Status:     st,
			Summary:    provDesc,
			Suggestion: "可在设置页钥匙串配置 Gemini / OpenAI / Anthropic API Key 或安装本地 agy",
		})
	}

	// 6. Scheduler check (macOS uses built-in Menu Bar App smart scheduler; Linux uses cron)
	scheds := scheduler.Status()
	if runtime.GOOS == "darwin" {
		if _, err := os.Stat("/Applications/Security Sentinel.app"); err == nil {
			modeDesc := fmt.Sprintf("每 %d 小时自动巡检", max(1, cfg.Notifications.AutoScanHours))
			switch cfg.Notifications.ScanMode {
			case "twice_daily":
				modeDesc = fmt.Sprintf("每日双点巡检 (%s 对称 12h 锚点)", cfg.Notifications.DailyScanTime)
			case "daily":
				modeDesc = fmt.Sprintf("每日 %s 定点巡检", cfg.Notifications.DailyScanTime)
			case "manual":
				modeDesc = "仅手动触发巡检"
			}
			items = append(items, model.DoctorItem{
				Category: "schedule",
				Name:     "自动巡检调度引擎",
				Status:   "ok",
				Summary:  fmt.Sprintf("菜单栏原生守护内置调度 (%s · 支持唤醒补跑与热点省流)", modeDesc),
			})
		} else if len(scheds) > 0 && scheds[0].Active {
			items = append(items, model.DoctorItem{
				Category: "schedule",
				Name:     "后台定时巡检计划",
				Status:   "ok",
				Summary:  fmt.Sprintf("%s · %s", scheds[0].Engine, scheds[0].HumanReadable),
			})
		} else {
			items = append(items, model.DoctorItem{
				Category:   "schedule",
				Name:       "自动巡检调度引擎",
				Status:     "warn",
				Summary:    "未安装桌面守护应用或定时计划",
				Suggestion: "推荐安装 Security Sentinel.app 常驻菜单栏自动守护",
			})
		}
	} else if len(scheds) > 0 && scheds[0].Active {
		items = append(items, model.DoctorItem{
			Category: "schedule",
			Name:     "后台定时巡检计划",
			Status:   "ok",
			Summary:  fmt.Sprintf("%s · %s", scheds[0].Engine, scheds[0].HumanReadable),
		})
	} else {
		items = append(items, model.DoctorItem{
			Category:   "schedule",
			Name:       "后台定时巡检计划",
			Status:     "warn",
			Summary:    "未配置系统 crontab 定时巡检任务",
			Suggestion: "服务器无头环境可执行 `sectl sched 09:00` 开启每日巡检",
		})
	}

	// 7. Concurrent SSH & Privilege probes across all configured hosts
	hosts := cfg.ConfiguredHosts()
	hostItems := make([]model.DoctorItem, len(hosts))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 6)

	for idx, h := range hosts {
		wg.Add(1)
		go func(i int, target model.HostTarget) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			exec := transport.New(target)
			probe := `echo "UID:$(id -u)"; if [ "$(id -u)" = "0" ] || sudo -n true 2>/dev/null; then echo "PRIV:OK"; else echo "PRIV:LIMITED"; fi; uname -s -r`
			res, err := exec.Run(ctx, probe, 8*time.Second)
			if err != nil || res.Code != 0 {
				errMsg := res.Stderr
				if errMsg == "" && err != nil {
					errMsg = err.Error()
				}
				hostItems[i] = model.DoctorItem{
					Category:   "host",
					Name:       fmt.Sprintf("主机连通性 [%s]", target.Name),
					Status:     "fail",
					LatencyMS:  res.LatencyMS,
					Summary:    fmt.Sprintf("SSH 免密连接失败: %s", errMsg),
					Suggestion: fmt.Sprintf("请执行 `ssh-copy-id %s` 或检查端口/密钥配置", target.SSHHost),
				}
				return
			}
			privOK := target.IsLocal() || containsLine(res.Stdout, "PRIV:OK")
			status := "ok"
			sug := ""
			privTag := "免密管理员权限就绪"
			if !privOK {
				status = "warn"
				privTag = "普通用户 (只读审计正常，自动打补丁受限)"
				sug = "如需自动安装系统安全补丁，请使用 root 或配置 sudo NOPASSWD"
			}
			hostItems[i] = model.DoctorItem{
				Category:   "host",
				Name:       fmt.Sprintf("主机健康 [%s]", target.Name),
				Status:     status,
				LatencyMS:  res.LatencyMS,
				Summary:    fmt.Sprintf("连通正常 (%dms) · %s", res.LatencyMS, privTag),
				Suggestion: sug,
			}
		}(idx, h)
	}
	wg.Wait()

	items = append(items, hostItems...)
	return items
}

func containsLine(s, sub string) bool {
	for _, l := range splitLines(s) {
		if l == sub {
			return true
		}
	}
	return false
}

func splitLines(s string) []string {
	var out []string
	cur := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			line := s[cur:i]
			if len(line) > 0 && line[len(line)-1] == '\r' {
				line = line[:len(line)-1]
			}
			out = append(out, line)
			cur = i + 1
		}
	}
	if cur < len(s) {
		out = append(out, s[cur:])
	}
	return out
}
