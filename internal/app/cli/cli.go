package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/sixban6/security-sentinel/internal/scan/auditor"
	"github.com/sixban6/security-sentinel/internal/infra/config"
	"github.com/sixban6/security-sentinel/internal/ops/doctor"
	"github.com/sixban6/security-sentinel/internal/ops/pipeline"
	"github.com/sixban6/security-sentinel/internal/heal/ha"
	"github.com/sixban6/security-sentinel/internal/scan/intel"
	"github.com/sixban6/security-sentinel/internal/scan/inventory"
	"github.com/sixban6/security-sentinel/internal/scan/inventory/lockfile"
	"github.com/sixban6/security-sentinel/internal/infra/store"
	"github.com/sixban6/security-sentinel/internal/infra/model"
	"github.com/sixban6/security-sentinel/internal/ops/notify"
	"github.com/sixban6/security-sentinel/internal/heal/patch"
	"github.com/sixban6/security-sentinel/internal/ops/report"
	"github.com/sixban6/security-sentinel/internal/ops/scheduler"
	"github.com/sixban6/security-sentinel/internal/infra/secrets"
	"github.com/sixban6/security-sentinel/internal/ops/updater"
	"gopkg.in/yaml.v3"
)

func Main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	globalCfgPath, subcmd, restArgs := extractGlobalConfigAndSubcommand(os.Args[1:])

	switch subcmd {
	case "", "help", "-h", "--help":
		printMainUsage()
	case "version", "ver", "-v", "--version":
		fmt.Printf("sectl (Security-Sentinel) v%s (Pure Go Engine)\n", model.Version)
	case "audit", "scan":
		runAudit(ctx, globalCfgPath, restArgs)
	case "fix":
		runFix(ctx, globalCfgPath, restArgs)
	case "rollback", "rb":
		runRollback(ctx, globalCfgPath, restArgs)
	case "doctor", "doc":
		runDoctor(ctx, globalCfgPath, restArgs)
	case "advisories", "adv", "cve", "cves":
		runAdvisories(ctx, globalCfgPath, restArgs)
	case "inventory", "inv":
		runInventory(ctx, globalCfgPath, restArgs)
	case "reboot-sync", "rs":
		runRebootSync(ctx, globalCfgPath, restArgs)
	case "notify":
		runNotify(ctx, globalCfgPath, restArgs)
	case "status", "st":
		runStatus(restArgs)
	case "init":
		runInit(ctx, globalCfgPath, restArgs)
	case "config", "cfg":
		runConfig(globalCfgPath)
	case "schedule", "sched":
		runSchedule(globalCfgPath, restArgs)
	case "memory", "mem":
		runMemory(restArgs)
	case "report", "rep":
		runReport(restArgs)
	case "telegram-pair", "pair":
		runTelegramPair(ctx, restArgs)
	case "upgrade", "up", "self-update", "update":
		runUpgrade(ctx, restArgs)
	case "deps", "ws", "workspace":
		runWorkspaceDeps(ctx, restArgs)
	case "clean-venvs", "clean-venv":
		runCleanOrphanedVenvs(restArgs)
	case "mute", "ignore":
		runMute(restArgs)
	case "unmute":
		runUnmute(restArgs)
	case "assets":
		runAssets(restArgs)
	default:
		fmt.Fprintf(os.Stderr, "❌ 未知子命令: %s\n\n", subcmd)
		printMainUsage()
		os.Exit(1)
	}
}

func extractGlobalConfigAndSubcommand(args []string) (cfgPath string, subcmd string, rest []string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if (a == "--config" || a == "-c") && i+1 < len(args) {
			cfgPath = args[i+1]
			i++
			continue
		}
		if strings.HasPrefix(a, "--config=") {
			cfgPath = strings.TrimPrefix(a, "--config=")
			continue
		}
		if strings.HasPrefix(a, "-c=") {
			cfgPath = strings.TrimPrefix(a, "-c=")
			continue
		}
		if subcmd == "" && !strings.HasPrefix(a, "-") {
			subcmd = a
			continue
		}
		rest = append(rest, a)
	}
	if subcmd == "" && len(rest) > 0 {
		subcmd = rest[0]
		rest = rest[1:]
	}
	return cfgPath, subcmd, rest
}

func printMainUsage() {
	fmt.Printf(`🛡️ sectl (Security-Sentinel v%s) — 多主机主动漏洞监控、AI 动态自愈与零中断高可用管家

用法:
  sectl [--config <path>] <子命令> [参数]     (兼容旧版命令别名: security-sentinel)

核心子命令 (含极速简写):
  audit / scan     执行端到端安全巡检 (含 Apple macOS 系统更新、Linux 多分支内核与运行态服务闭环)
  deps / ws        查看按「活跃项目 ➔ 待升级包」两级折叠的开发工作区依赖体检 (--all 含归档, --fix 一键升级)
  assets           查看五层全景资产清单浏览器 (--layer brew|docker|tools|os|workspace -q <关键词>)
  mute / unmute    对暂不想升级的项目配置「跳过当前版本 / 暂缓 N 天 / 永久豁免」或恢复监控
  clean-venvs      检测原项目已删除或闲置多年的孤儿僵尸虚拟环境 (--apply 安全移入系统废纸篓)
  doctor / doc     一键并发诊断全集群 SSH 免密、提权能力、网络情报源与钥匙串状态
  fix              定向执行操作系统与基础库安全修补 (支持 --dry-run 变更预览)
  rollback / rb    一键远程回滚已归档的 AI 现场规避脚本 (--host <node> --cve <CVE-ID>)
  upgrade / up     从 GitHub Actions 最新 Release 下载预编译包、校验 SHA-256 并原子升级 (--check / --app)
  status / st      查看最近一次巡检落盘结论与集群健康分
  report / rep     导出零外部依赖的深色主题单文件 HTML 审计战报 (--html report.html)
  cve / adv        查看按「语言环境 / OS / 内核 / 重要性」分类的每日最新 CVE (--push 单独推送 Telegram 日报)
  inventory / inv  极速采集全集群系统包、内核、容器与项目依赖画像 (YAML / --json)
  reboot-sync / rs 零中断 Clash/Mihomo 旁路切流、串行滚动重启与节点强同步
  init             一键生成配置文件或从 ~/.ssh/config 自动筛查导入在线主机 (--global --discover)
  config / cfg     查看当前生效的配置文件与已纳管主机列表
  schedule / sched 一键安装、查看或卸载系统定时巡检任务 (macOS launchd / Linux crontab)
  memory / mem     查看或清理分层决策记忆库与熔断账本 (status / clean)
  telegram-pair    使用 6 位一次性安全配对码绑定 Telegram 机器人 (简写: pair)

桌面原生客户端 (MyGo GPU UI):
  打开 /Applications/Security Sentinel.app 启用菜单栏三色盾牌悬浮窗 (⌘⇧S) 与全景安全指挥台。
`, model.Version)
}

func loadCfgOrWarn(cfgPath string) config.Config {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠️ 配置文件读取警告: %v (已使用安全默认配置)\n", err)
	}
	return cfg
}

func runAudit(ctx context.Context, cfgPath string, args []string) {
	fs := flag.NewFlagSet("audit", flag.ExitOnError)
	scheduleExpr := fs.String("schedule", "", "将该 audit 命令注册为定时任务 (如 '0 9 * * *' 或 '09:00')")
	cronAlias := fs.String("cron", "", "同 --schedule")
	forceCron := fs.Bool("force-cron", false, "在 macOS 上强制使用 crontab")
	days := fs.Int("days", 0, "检索近 N 天增量通告 (默认读取配置或 3 天)")
	doFix := fs.Bool("fix", false, "安装满足安全护栏的操作系统安全补丁")
	fixOSAlias := fs.Bool("fix-os", false, "同 --fix")
	noFix := fs.Bool("no-fix", false, "强制只读审计，不执行任何自动修补")
	autoReboot := fs.Bool("auto-reboot", false, "若存在 /var/run/reboot-required 自动执行平滑滚动重启")
	aiHeal := fs.Bool("ai-heal", false, "启用 AI 无补丁漏洞现场研判并自动执行加固")
	aiRemAlias := fs.Bool("ai-remediate", false, "同 --ai-heal")
	aiModel := fs.String("ai-model", "", "覆盖指定 AI 模型名称")
	maxFixes := fs.Int("max-fixes", 0, "单台主机单轮最多处理的 AI 规避漏洞数")
	freshAI := fs.Bool("fresh-ai", false, "跳过本地 AI 研判记忆缓存")
	freshInv := fs.Bool("fresh-inventory", false, "跳过资产指纹缓存强制重新 SSH 采集")
	freshAdv := fs.Bool("fresh-advisories", false, "跳过漏洞通告缓存强制实时拉取")
	noCache := fs.Bool("no-cache", false, "完全停用所有本地缓存冷启动运行")
	htmlOut := fs.String("html", "", "同时导出单文件 HTML 安全审计战报到指定路径")
	asJSON := fs.Bool("json", false, "以 JSON 格式打印完整审计报告")
	statusFile := fs.String("status-file", config.PrimaryStatusFile(), "状态落盘 JSON 路径")
	_ = fs.Parse(args)

	sched := *scheduleExpr
	if sched == "" {
		sched = *cronAlias
	}
	if sched != "" {
		st, err := scheduler.Install(scheduler.InstallOptions{
			ScheduleExpr: sched,
			AutoFix:      *doFix || *fixOSAlias,
			AutoReboot:   *autoReboot,
			AIHeal:       *aiHeal || *aiRemAlias,
			ConfigPath:   cfgPath,
			Days:         *days,
			ForceCron:    *forceCron,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ 配置定时计划失败: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("🎉 成功配置 audit 定时巡检计划！\n  • 调度引擎: %s\n  • 执行规则: %s\n  • 执行命令: %s\n",
			st.Engine, st.HumanReadable, st.Command)
		return
	}

	cfg := loadCfgOrWarn(cfgPath)
	mem := store.New("")
	runner := pipeline.NewRunner(mem)

	applyOS := (*doFix || *fixOSAlias || cfg.AutoFix.Enabled) && !*noFix
	enableAI := *aiHeal || *aiRemAlias || cfg.AIRemediation.Enabled
	autoExecAI := *aiHeal || *aiRemAlias || cfg.AIRemediation.AutoExecute

	rep, err := runner.RunAudit(ctx, pipeline.AuditParams{
		Config:          cfg,
		Days:            *days,
		ApplyOSFixes:    applyOS,
		AutoReboot:      *autoReboot,
		EnableAITriage:  enableAI,
		AutoExecuteAI:   autoExecAI,
		AIModelOverride: *aiModel,
		MaxFixesPerHost: *maxFixes,
		UseAdvCache:     !*noCache && !*freshAdv,
		UseInvCache:     !*noCache && !*freshInv,
		UseAICache:      !*noCache && !*freshAI,
		StatusFile:      *statusFile,
		QuietNotify:     *asJSON,
		OnLog: func(line string) {
			if !*asJSON {
				fmt.Println(line)
			}
		},
		OnHostProgress: func(host model.HostTarget, stage string, inv *model.HostInventory) {
			if !*asJSON && stage == "done" && inv != nil {
				if inv.Error != "" {
					fmt.Printf("    ⚠️ [%s] %s\n", host.Name, inv.Error)
				} else {
					fmt.Printf("    ✓ [%s] %s · %d 资产 (%dms)\n", host.Name, inv.OSContext.OSPretty, len(inv.Assets), inv.LatencyMS)
				}
			}
		},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ 巡检执行失败: %v\n", err)
		os.Exit(1)
	}

	if *htmlOut != "" {
		if err := report.WriteHTML(rep, *htmlOut); err == nil && !*asJSON {
			fmt.Printf("📊 已导出可视化 HTML 审计战报: %s\n", *htmlOut)
		}
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
		return
	}

	fmt.Println("\n" + strings.Repeat("=", 58))
	fmt.Printf("🛡️ 集群安全健康分: %d / 100 (耗时 %.1fs)\n", rep.ClusterScore, float64(rep.DurationMS)/1000.0)
	fmt.Println(strings.Repeat("-", 58))
	for _, line := range notify.FormatStatusLines(rep.Hosts) {
		fmt.Println(line)
	}
	fmt.Println(strings.Repeat("=", 58))
	fmt.Printf("✅ 状态已保存至: %s\n", *statusFile)
}

func runFix(ctx context.Context, cfgPath string, args []string) {
	fs := flag.NewFlagSet("fix", flag.ExitOnError)
	hostsFilter := fs.String("hosts", "", "指定待修补主机名或别名 (逗号分隔)")
	dryRun := fs.Bool("dry-run", false, "仅预览将要执行的安全修补命令，不执行写入")
	_ = fs.Parse(args)

	cfg := loadCfgOrWarn(cfgPath)
	mem := store.New("")
	intelCli := intel.NewClient(mem)

	fmt.Println("🔍 [1/3] 并发探测各主机操作系统安全补丁与硬件防变砖护栏...")
	invs := inventory.CollectAll(ctx, inventory.CollectOptions{
		Config:   cfg,
		Mem:      mem,
		Intel:    intelCli,
		UseCache: false,
	})

	var filters []string
	if *hostsFilter != "" {
		for _, p := range strings.Split(*hostsFilter, ",") {
			if strings.TrimSpace(p) != "" {
				filters = append(filters, strings.TrimSpace(p))
			}
		}
	}

	var candidates []model.HostInventory
	for _, inv := range invs {
		if len(filters) > 0 {
			matched := false
			for _, f := range filters {
				if strings.Contains(inv.Target.Name, f) || strings.Contains(inv.Target.EffectiveKey(), f) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		if len(inv.OSSecurity.Updates) > 0 {
			candidates = append(candidates, inv)
		}
	}

	if len(candidates) == 0 {
		fmt.Println("✅ 未发现任何待安装的操作系统安全补丁，全集群基础组件均处于安全状态。")
		return
	}

	fmt.Printf("\n📋 [2/3] 发现 %d 台主机存在可用官方安全更新:\n", len(candidates))
	for _, inv := range candidates {
		fmt.Printf("\n  🖥️ %s (%s)\n", inv.Target.Name, inv.OSContext.OSPretty)
		for _, u := range inv.OSSecurity.Updates {
			cveStr := ""
			if u.CVEID != "" {
				cveStr = "[" + u.CVEID + "] "
			}
			fmt.Printf("    • %s%s: %s ➔ %s\n", cveStr, u.Package, u.InstalledVersion, u.CandidateVersion)
		}
		plan := inv.OSSecurity.RemediationPlan
		if !plan.SafeToExecute {
			fmt.Printf("    ⛔ 安全护栏熔断保护: %s\n    💡 建议: %s\n", plan.Warning, plan.Description)
		} else {
			fmt.Printf("    🛠️ 变更命令预览: %s\n", strings.Join(plan.Commands, " && "))
		}
	}

	if *dryRun {
		fmt.Println("\n💡 当前为 --dry-run 预览模式，未对任何主机执行写入。")
		return
	}

	fmt.Println("\n🚀 [3/3] 执行定向安全修补...")
	for _, inv := range candidates {
		plan := inv.OSSecurity.RemediationPlan
		if !plan.SafeToExecute {
			fmt.Printf("  ⏭️ 跳过 [%s]: %s\n", inv.Target.Name, plan.Warning)
			continue
		}
		ok, out := patch.ApplyOSPlan(ctx, inv.Target, plan)
		if ok {
			fmt.Printf("  ✅ [%s] 定向修补完成！\n", inv.Target.Name)
		} else {
			fmt.Printf("  ⚠️ [%s] 修补异常: %s\n", inv.Target.Name, out)
		}
	}
}

func runRollback(ctx context.Context, cfgPath string, args []string) {
	fs := flag.NewFlagSet("rollback", flag.ExitOnError)
	hostFlag := fs.String("host", "", "目标主机名称或 SSH 地址 (必填，或使用 --list 查看记录)")
	cveFlag := fs.String("cve", "", "待回滚的 CVE 编号 (如 CVE-2025-12345)")
	listOnly := fs.Bool("list", false, "列出所有可回滚的历史加固记录")
	_ = fs.Parse(args)

	mem := store.New("")
	if *listOnly || (*hostFlag == "" && *cveFlag == "") {
		hist := mem.ListHistory()
		if len(hist) == 0 {
			fmt.Println("ℹ️ 当前尚无已记录的现场规避加固历史。")
			return
		}
		fmt.Println("⏪ 历史修复与现场规避账本:")
		for _, r := range hist {
			rbTag := ""
			if r.CanRollback {
				rbTag = " [支持一键回滚]"
			}
			fmt.Printf("  • [%s] %s · %s (%s) — %s%s\n", r.UpdatedAt, r.HostName, r.CVEID, r.Kind, r.Status, rbTag)
		}
		fmt.Println("\n💡 执行一键回滚示例: sectl rb --host <主机名> --cve <CVE编号>")
		return
	}

	if *hostFlag == "" || *cveFlag == "" {
		fmt.Fprintln(os.Stderr, "❌ 请同时指定 --host <主机> 与 --cve <CVE编号>")
		os.Exit(1)
	}

	cfg := loadCfgOrWarn(cfgPath)
	var matchedTarget *model.HostTarget
	for _, t := range cfg.ConfiguredHosts() {
		if strings.EqualFold(t.Name, *hostFlag) || strings.EqualFold(t.SSHHost, *hostFlag) || strings.Contains(t.EffectiveKey(), *hostFlag) {
			cp := t
			matchedTarget = &cp
			break
		}
	}
	if matchedTarget == nil {
		t := config.NormalizeStringHost(*hostFlag)
		matchedTarget = &t
	}

	inv := inventory.CollectSingle(ctx, *matchedTarget, nil, inventory.CollectOptions{Config: cfg, UseCache: true, Mem: mem})
	ok, msg := patch.RollbackMitigation(ctx, *matchedTarget, inv.OSContext, *cveFlag, mem)
	if !ok {
		fmt.Fprintf(os.Stderr, "❌ 回滚失败: %s\n", msg)
		os.Exit(1)
	}
	fmt.Printf("✅ [%s] %s\n", matchedTarget.Name, msg)
}

func runDoctor(ctx context.Context, cfgPath string, args []string) {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "以 JSON 格式输出诊断结果")
	_ = fs.Parse(args)

	cfg := loadCfgOrWarn(cfgPath)
	mem := store.New("")
	items := doctor.RunAll(ctx, cfg, mem)

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(items)
		return
	}

	fmt.Println("🩺 sectl 全链路环境与集群健康体检:")
	fmt.Println(strings.Repeat("-", 62))
	okCount, warnCount, failCount := 0, 0, 0
	for _, it := range items {
		icon := "✅"
		switch it.Status {
		case "ok":
			okCount++
		case "warn":
			icon = "⚠️"
			warnCount++
		case "fail":
			icon = "❌"
			failCount++
		}
		fmt.Printf("  %s %-26s %s\n", icon, it.Name, it.Summary)
		if it.Suggestion != "" {
			fmt.Printf("     💡 %s\n", it.Suggestion)
		}
	}
	fmt.Println(strings.Repeat("-", 62))
	fmt.Printf("诊断汇总: %d 正常 · %d 提醒 · %d 异常\n", okCount, warnCount, failCount)
	if failCount > 0 {
		os.Exit(1)
	}
}

func runAdvisories(ctx context.Context, cfgPath string, args []string) {
	fs := flag.NewFlagSet("cve", flag.ExitOnError)
	days := fs.Int("days", 0, "检索近 N 天通告 (默认 3 天)")
	category := fs.String("category", "all", "领域分类过滤: all | language | os | kernel")
	severity := fs.String("severity", "all", "重要性分级过滤: all | CRITICAL | HIGH | MEDIUM")
	eco := fs.String("eco", "", "按具体生态或发行版过滤 (如 PyPI, npm, Maven, Go, Debian, Ubuntu, RHEL)")
	query := fs.String("q", "", "按 CVE 编号、包名或关键词搜索")
	limit := fs.Int("limit", 40, "终端每个分区或列表最多展示条数")
	pushTG := fs.Bool("push", false, "将每日最新 CVE 按分类单独推送一条日报卡片至 Telegram 机器人")
	asJSON := fs.Bool("json", false, "输出 JSON")
	fresh := fs.Bool("fresh", false, "跳过本地缓存强制实时拉取")
	_ = fs.Parse(args)

	cfg := loadCfgOrWarn(cfgPath)
	d := *days
	if d <= 0 {
		d = cfg.Advisories.Days
	}
	mem := store.New("")
	cli := intel.NewClient(mem)
	advs, _ := cli.FetchAllAdvisories(ctx, d, true, !*fresh)

	catNorm := strings.ToLower(strings.TrimSpace(*category))
	if catNorm == "lang" || catNorm == "languages" {
		catNorm = "language"
	}
	list := notify.FilterAdvisories(advs, catNorm, *severity, *eco, *query)

	if *pushTG {
		sent, err := notify.SendDailyCVEDigest(ctx, advs, d, true)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Telegram 推送失败: %v\n", err)
			os.Exit(1)
		}
		if !sent {
			fmt.Fprintln(os.Stderr, "⚠️ 未检测到 Telegram Bot 配置，请先运行 `sectl pair` 或在桌面端设置页绑定。")
			os.Exit(1)
		}
		fmt.Printf("✈️ 已成功将近 %d 天的分类 CVE 情报日报单独推送至 Telegram！(共 %d 条)\n", d, len(list))
		if !*asJSON && *category == "all" && *severity == "all" && *eco == "" && *query == "" {
			return
		}
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(list)
		return
	}

	fmt.Printf("📡 每日最新 CVE 情报雷达 (近 %d 天 · 匹配 %d 条)\n", d, len(list))
	fmt.Println(strings.Repeat("=", 72))

	if catNorm == "all" && *eco == "" && *query == "" {
		sections := []struct {
			code  string
			title string
		}{
			{"kernel", "🐧 一、Linux 内核 (Kernel)"},
			{"os", "🖥️ 二、操作系统发行版 (OS)"},
			{"language", "💻 三、开发语言供应链 (Languages)"},
		}
		for _, sec := range sections {
			secItems := notify.FilterAdvisories(advs, sec.code, *severity, "", "")
			fmt.Printf("\n%s (%d 条):\n", sec.title, len(secItems))
			if len(secItems) == 0 {
				fmt.Println("  (暂无匹配条目)")
				continue
			}
			perSec := max(5, *limit/3)
			for i, it := range secItems {
				if i >= perSec {
					fmt.Printf("  ... 另有 %d 条 (可用 `sectl cve --category %s --limit 50` 查看完整列表)\n", len(secItems)-perSec, sec.code)
					break
				}
				printCVECliLine(it)
			}
		}
		return
	}

	for i, it := range list {
		if i >= *limit {
			fmt.Printf("  ... 另有 %d 条未展示 (可增大 --limit)\n", len(list)-*limit)
			break
		}
		printCVECliLine(it)
	}
}

func printCVECliLine(it model.Advisory) {
	sum := it.Summary
	if len(sum) > 68 {
		sum = sum[:68] + "..."
	}
	cvssStr := ""
	if it.CVSS > 0 {
		cvssStr = fmt.Sprintf(" %.1f", it.CVSS)
	}
	fmt.Printf("  • [%-8s%s] %-12s %-18s %s\n", it.Severity, cvssStr, it.Ecosystem, it.DisplayID(), sum)
}

func runInventory(ctx context.Context, cfgPath string, args []string) {
	fs := flag.NewFlagSet("inventory", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "输出 JSON (默认输出 YAML)")
	fresh := fs.Bool("fresh", false, "跳过指纹缓存强制重新采集")
	_ = fs.Parse(args)

	cfg := loadCfgOrWarn(cfgPath)
	mem := store.New("")
	intelCli := intel.NewClient(mem)
	invs := inventory.CollectAll(ctx, inventory.CollectOptions{
		Config:   cfg,
		Mem:      mem,
		Intel:    intelCli,
		UseCache: !*fresh,
	})

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(invs)
		return
	}
	out, _ := yaml.Marshal(invs)
	fmt.Print(string(out))
}

func runRebootSync(ctx context.Context, cfgPath string, args []string) {
	fs := flag.NewFlagSet("reboot-sync", flag.ExitOnError)
	targets := fs.String("targets", "", "指定待重启节点 ID (逗号分隔)")
	auto := fs.Bool("auto", false, "自动检测 /var/run/reboot-required")
	forceGW := fs.Bool("force-gateway", false, "强制执行网关重载与测速")
	_ = fs.Parse(args)

	cfg := loadCfgOrWarn(cfgPath)
	mgr := ha.NewManager(cfg, func(ev model.HAProgressEvent) {
		fmt.Printf("[%s] [%s] (%s) %s\n", ev.Timestamp, ev.Level, ev.NodeID, ev.Message)
	})

	var list []string
	if *targets != "" {
		for _, t := range strings.Split(*targets, ",") {
			if strings.TrimSpace(t) != "" {
				list = append(list, strings.TrimSpace(t))
			}
		}
	} else if *auto {
		for nid := range cfg.RollingNodesMap() {
			if mgr.CheckRebootRequired(ctx, nid) {
				list = append(list, nid)
			}
		}
	} else if !*forceGW {
		fmt.Println("💡 请指定 --targets <node1,node2>、--auto 自动检测或 --force-gateway")
		return
	}

	if err := mgr.ExecuteRollingReboot(ctx, list, *forceGW); err != nil {
		fmt.Fprintf(os.Stderr, "❌ 平滑滚动重启异常: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("🎉 零中断滚动重启与节点强同步流程已完成！")
}

func runNotify(ctx context.Context, cfgPath string, args []string) {
	fs := flag.NewFlagSet("notify", flag.ExitOnError)
	statusFile := fs.String("status-file", "", "状态文件路径")
	_ = fs.Parse(args)

	cfg := loadCfgOrWarn(cfgPath)
	cfg.Notifications.Policy = "always"
	rep, err := notify.LoadReport(*statusFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ 读取状态文件失败: %v\n", err)
		os.Exit(1)
	}
	msg, err := notify.SaveAndNotify(ctx, rep, *statusFile, cfg.Notifications)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ 通知发送异常: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(msg)
}

func runStatus(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	statusFile := fs.String("status-file", "", "状态文件路径")
	asJSON := fs.Bool("json", false, "输出原始 JSON")
	_ = fs.Parse(args)

	rep, err := notify.LoadReport(*statusFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ℹ️ 尚未找到巡检记录 (%v)，请先运行 `sectl audit`\n", err)
		return
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
		return
	}
	fmt.Printf("⏱️ 最近巡检: %s · 集群健康分: %d/100\n", rep.Timestamp, rep.ClusterScore)
	for _, line := range notify.FormatStatusLines(rep.Hosts) {
		fmt.Println(line)
	}
}

func runInit(ctx context.Context, cfgPath string, args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	global := fs.Bool("global", false, "生成到 ~/.config/sentinel/sentinel.yaml")
	force := fs.Bool("force", false, "覆盖已有配置文件")
	discover := fs.Bool("discover", false, "自动扫描 ~/.ssh/config、剔除无效节点并导入在线服务器")
	_ = fs.Parse(args)

	dest := "./sentinel.yaml"
	if cfgPath != "" {
		dest = cfgPath
	} else if *global {
		dest = config.GlobalConfigFile()
	}

	if _, err := os.Stat(dest); err == nil && !*force && !*discover {
		fmt.Printf("⚠️ 配置文件已存在: %s (追加 --force 覆盖，或追加 --discover 自动导入 ~/.ssh/config 在线主机)\n", dest)
		return
	}

	if *discover {
		cfg := loadCfgOrWarn(dest)
		fmt.Println("🔍 正在扫描 ~/.ssh/config 并并发探测免密连通性 (自动筛除离线与无效节点)...")
		candidates := config.DiscoverSSHConfigHosts(cfg.ConfiguredHosts())
		valid, filtered := config.ProbeValidSSHHosts(ctx, candidates)
		added := 0
		for _, d := range valid {
			if !d.AlreadyAdded {
				cfg.Hosts = append(cfg.Hosts, config.HostEntry{Target: d.ToHostTarget()})
				added++
				fmt.Printf("  ✅ 发现有效在线节点: %s (%s · %dms)\n", d.Alias, d.RemoteOS, d.LatencyMS)
			}
		}
		savedPath, err := config.Save(cfg, dest)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ 保存配置失败: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("🎉 已自动筛除 %d 个无效/离线节点，成功导入 %d 台新主机至: %s\n", filtered, added, savedPath)
		return
	}

	if err := os.MkdirAll(config.ExpandHome(strings.TrimSuffix(dest, "/sentinel.yaml")), 0o755); err != nil && *global {
		_ = os.MkdirAll(config.ConfigDir(), 0o755)
	}
	if *global {
		_ = os.MkdirAll(config.ConfigDir(), 0o755)
	}
	if err := os.WriteFile(dest, []byte(config.EmbeddedExampleYAML), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "❌ 写入配置模板失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("🎉 成功初始化配置文件: %s\n💡 也可执行 `sectl init --discover` 自动从 ~/.ssh/config 一键导入主机！\n", dest)
}

func runConfig(cfgPath string) {
	found := config.FindConfigFile(cfgPath)
	if found != "" {
		fmt.Printf("📍 当前生效配置文件: %s\n", found)
	} else {
		fmt.Println("⚠️ 未找到自定义配置文件，当前使用内置安全默认配置 (仅本机只读巡检)")
	}
	cfg := loadCfgOrWarn(cfgPath)
	hosts := cfg.ConfiguredHosts()
	fmt.Printf("\n📋 已纳管守护主机 (%d 台):\n", len(hosts))
	for i, h := range hosts {
		portInfo := ""
		if h.Port > 0 && h.Port != 22 {
			portInfo = fmt.Sprintf(":%d", h.Port)
		}
		sshStr := h.SSHHost + portInfo
		if h.IsLocal() {
			sshStr = "local"
		}
		fmt.Printf("  %d. [%s] %s (Target: %s)\n", i+1, h.Type, h.Name, sshStr)
	}
}

func runSchedule(cfgPath string, args []string) {
	fs := flag.NewFlagSet("schedule", flag.ExitOnError)
	install := fs.Bool("install", false, "安装定时任务")
	uninstall := fs.Bool("uninstall", false, "卸载定时任务")
	removeAlias := fs.Bool("remove", false, "卸载定时任务")
	statusOnly := fs.Bool("status", false, "查看定时状态")
	timeExpr := fs.String("time", "", "时间或 5 段 crontab 表达式")
	cronExpr := fs.String("cron", "", "5 段 crontab 表达式")
	forceCron := fs.Bool("force-cron", false, "强制使用系统 crontab")
	noReboot := fs.Bool("no-reboot", false, "不追加 --auto-reboot")
	aiHeal := fs.Bool("ai-heal", false, "追加 --ai-heal")
	doFix := fs.Bool("fix", false, "追加 --fix")
	_ = fs.Parse(args)

	isUninst := *uninstall || *removeAlias
	expr := *cronExpr
	if expr == "" {
		expr = *timeExpr
	}
	for _, p := range fs.Args() {
		switch p {
		case "uninstall", "remove", "disable":
			isUninst = true
		case "status", "list", "audit":
		default:
			if expr == "" {
				expr = p
			}
		}
	}

	if isUninst {
		_ = scheduler.Uninstall()
		fmt.Println("✅ 已卸载并清理所有 Security-Sentinel 系统定时巡检任务。")
		return
	}

	if expr != "" || *install && !*statusOnly {
		if expr == "" {
			expr = "09:00"
		}
		st, err := scheduler.Install(scheduler.InstallOptions{
			ScheduleExpr: expr,
			AutoFix:      *doFix,
			AutoReboot:   !*noReboot,
			AIHeal:       *aiHeal,
			ConfigPath:   cfgPath,
			ForceCron:    *forceCron,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ 安装定时计划失败: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("🎉 定时巡检任务已就绪！\n  • 调度引擎: %s\n  • 执行规则: %s\n  • 执行指令: %s\n",
			st.Engine, st.HumanReadable, st.Command)
		return
	}

	sts := scheduler.Status()
	if len(sts) == 0 {
		fmt.Println("ℹ️ 当前未安装系统级定时任务 (可执行 `sectl schedule '0 9 * * *'` 一键开启)。")
		return
	}
	for _, st := range sts {
		fmt.Printf("⏰ [%s] 状态: %v · 规则: %s\n", st.Engine, st.Active, st.HumanReadable)
	}
}

func runMemory(args []string) {
	fs := flag.NewFlagSet("memory", flag.ExitOnError)
	cleanTarget := fs.String("clean", "", "清理指定缓存: all | ai | inventory | advisories")
	_ = fs.Parse(args)

	mem := store.New("")
	action := "status"
	if len(fs.Args()) > 0 {
		action = fs.Args()[0]
	}
	if action == "clean" || *cleanTarget != "" {
		t := *cleanTarget
		if t == "" {
			t = "all"
		}
		n := mem.Clean(t)
		fmt.Printf("🧹 已清理本地决策记忆缓存 (%s): %d 个文件。\n", t, n)
		return
	}

	st := mem.Status()
	fmt.Printf(`🧠 Sentinel 分层记忆与熔断账本状态:
  • 存储目录: %s (%.1f KB, %d 个文件)
  • L1 资产指纹缓存: %d 台主机 (静态 TTL 6h / 系统补丁 TTL 2h)
  • L2 漏洞情报缓存: %v (TTL 4h + OSV 详情 TTL 24h)
  • L3 AI 研判档案库: %d 份 Markdown (🛡️ 可规避 %d · ⏳ 等补丁 %d · ⚠️ 异常 %d)
  • L4 修复与时光机账本: %d 条状态 · %d 条历史记录 · 熔断锁定中 %d 项
`,
		st.MemoryDir, st.TotalSizeKB, st.FileCount,
		st.InventoriesCount, st.AdvisoriesCached,
		st.TriageTotal, st.TriageMitigable, st.TriageAwaitingPatch, st.TriageFailed,
		st.LedgerEntries, st.HistoryEntries, len(st.LockedEntries),
	)
}

func runReport(args []string) {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	statusFile := fs.String("status-file", "", "输入状态 JSON")
	htmlOut := fs.String("html", "sentinel_report.html", "输出单文件 HTML 报告路径")
	_ = fs.Parse(args)

	rep, err := notify.LoadReport(*statusFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ 未找到最近巡检数据 (%v)，请先运行 `sectl audit`\n", err)
		os.Exit(1)
	}
	if err := report.WriteHTML(rep, *htmlOut); err != nil {
		fmt.Fprintf(os.Stderr, "❌ 导出 HTML 失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("📊 已生成单文件深色主题安全审计战报: %s\n", *htmlOut)
}

func runTelegramPair(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("telegram-pair", flag.ExitOnError)
	tokenFlag := fs.String("token", "", "Telegram Bot Token (留空则读取钥匙串/环境变量)")
	_ = fs.Parse(args)

	tok := strings.TrimSpace(*tokenFlag)
	if tok == "" {
		tok = secrets.Get(secrets.KeyTelegramBotToken)
	}
	reader := bufio.NewReader(os.Stdin)
	if tok == "" {
		fmt.Print("请输入您的 Telegram Bot Token: ")
		line, _ := reader.ReadString('\n')
		tok = strings.TrimSpace(line)
	}
	if tok == "" {
		fmt.Fprintln(os.Stderr, "❌ Bot Token 不能为空")
		os.Exit(1)
	}

	code := notify.GeneratePairCode()
	fmt.Printf("\n🔐 安全配对码已生成: 【 %s 】\n", code)
	fmt.Println("👉 请立即在手机 Telegram 中向您的机器人发送上面这 6 位数字，随后按回车键验证绑定...")
	_, _ = reader.ReadString('\n')

	verifyCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	chatID, who, err := notify.VerifyTelegramPairCode(verifyCtx, tok, code)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ 配对验证未通过: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("🎉 配对成功！已将 Chat ID %s (%s) 安全加密保存至系统钥匙串！\n", chatID, who)
	_, _ = notify.SendTelegram(ctx, "🛡️ <b>Security-Sentinel</b> 已通过一次性配对码完成安全绑定！", tok, chatID)
}

func runUpgrade(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("upgrade", flag.ExitOnError)
	checkOnly := fs.Bool("check", false, "仅检查 GitHub Releases 最新版本，不执行下载替换")
	force := fs.Bool("force", false, "即使当前已是最新版本，也强制重新下载替换")
	upgradeApp := fs.Bool("app", false, "(macOS) 同步下载并更新 /Applications/Security Sentinel.app 桌面应用")
	_ = fs.Parse(args)

	cli := updater.NewClient()
	fmt.Printf("🔍 当前版本: v%s · 正在查询 GitHub Releases (%s) 最新预编译版本...\n", model.Version, cli.Repo)
	rel, err := cli.CheckLatest(ctx, model.Version)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ 检查更新失败: %v\n", err)
		os.Exit(1)
	}

	if !rel.HasUpdate && !*force {
		fmt.Printf("✅ 当前已是最新版本 (v%s，远端最新 Release: %s)！\n", model.Version, rel.TagName)
		return
	}

	fmt.Printf("🚀 发现可用版本: %s (%s)\n", rel.TagName, rel.HTMLURL)
	if *checkOnly {
		if strings.TrimSpace(rel.Body) != "" {
			fmt.Printf("\n📝 更新说明:\n%s\n", strings.TrimSpace(rel.Body))
		}
		fmt.Println("\n💡 执行 `sectl up` (macOS 桌面端可加 `--app`) 即可一键更新。")
		return
	}

	fmt.Println("⬇️  正在下载适配当前系统的 GitHub Actions 编译二进制并核验 SHA-256 签名...")
	binPath, err := cli.UpgradeCLI(ctx, rel, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ CLI 升级失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("✅ CLI 已安全原子升级至 %s: %s\n", rel.TagName, binPath)

	if *upgradeApp {
		fmt.Println("🖥️  正在下载并更新 macOS 原生 GPU 桌面端 (Security Sentinel.app)...")
		appPath, err := cli.UpgradeMacOSApp(ctx, rel, "")
		if err != nil {
			fmt.Fprintf(os.Stderr, "⚠️ 桌面端更新失败: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✅ 桌面应用已更新至: %s\n", appPath)
	}
}

func runWorkspaceDeps(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("deps", flag.ExitOnError)
	showAll := fs.Bool("all", false, "同时展示超过 90 天未修改的历史归档仓库")
	doFix := fs.Bool("fix", false, "对近期活跃项目自动执行依赖升级命令")
	statusFile := fs.String("status-file", "", "状态文件路径")
	_ = fs.Parse(args)

	rep, err := notify.LoadReport(*statusFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ℹ️ 未找到最近巡检快照，请先执行 `sectl audit`\n")
		os.Exit(1)
	}

	var projects []model.WorkspaceProjectAudit
	for _, h := range rep.Hosts {
		for _, wp := range h.WorkspaceProjects {
			if wp.Archived && !*showAll {
				continue
			}
			projects = append(projects, wp)
		}
	}

	if len(projects) == 0 {
		fmt.Println("✅ 近期活跃的开发项目零高危依赖！(追加 `--all` 可查看 >90 天未修改的历史归档仓库)")
		return
	}

	fmt.Printf("💻 开发工作区依赖升级建议 (共 %d 个项目):\n", len(projects))
	for _, wp := range projects {
		tag := fmt.Sprintf("🔥 %d天前活跃", wp.LastActiveDays)
		if wp.Archived {
			tag = fmt.Sprintf("🧊 归档 · %d天未改", wp.LastActiveDays)
		}
		fmt.Printf("\n📁 %s [%s · %s] — 仅需升级 %d 个包即可消除 %d 个关联 CVE\n",
			wp.ProjectName, wp.ManifestKind, tag, len(wp.Packages), wp.TotalCVEs)
		for _, pf := range wp.Packages {
			arrow := pf.InstalledVersion
			if pf.FixedVersion != "" {
				arrow = fmt.Sprintf("%s ➔ %s", pf.InstalledVersion, pf.FixedVersion)
			}
			fmt.Printf("   ├─ 📦 %-22s %-20s [%s · %d CVEs]\n", pf.Package, arrow, pf.Severity, len(pf.CVEIDs))
		}
		batchCmd := auditor.BuildProjectBatchUpgradeCmd(wp)
		if batchCmd != "" && !strings.HasPrefix(batchCmd, "#") {
			fmt.Printf("   └─ 🛠️ 一键升级指令: (cd %q && %s)\n", wp.ProjectDir, batchCmd)
			if *doFix && !wp.Archived {
				fmt.Printf("      🚀 正在自动升级 %s...\n", wp.ProjectName)
				cmd := exec.CommandContext(ctx, "/bin/sh", "-c", batchCmd)
				cmd.Dir = wp.ProjectDir
				if out, err := cmd.CombinedOutput(); err != nil {
					fmt.Printf("      ⚠️ 升级返回错误: %v (%s)\n", err, strings.TrimSpace(string(out)))
				} else {
					fmt.Printf("      ✅ %s 依赖升级完成！\n", wp.ProjectName)
				}
			}
		}
	}
}

func runCleanOrphanedVenvs(args []string) {
	fs := flag.NewFlagSet("clean-venvs", flag.ExitOnError)
	apply := fs.Bool("apply", false, "将检测到的孤儿僵尸虚拟环境安全移入系统废纸篓")
	_ = fs.Parse(args)

	orphans := lockfile.DetectOrphanedVenvs()
	if len(orphans) == 0 {
		fmt.Println("✨ 未发现任何孤儿或长期闲置的僵尸 Python 虚拟环境！")
		return
	}

	var totalMB float64
	fmt.Printf("🧹 发现 %d 个孤儿/僵尸 Python 虚拟环境:\n", len(orphans))
	for _, ov := range orphans {
		totalMB += ov.SizeMB
		fmt.Printf("  • %-44s %6.1f MB · %s (%s)\n", ov.Name, ov.SizeMB, ov.Reason, ov.Path)
	}
	fmt.Printf("合计可释放磁盘空间: %.1f MB\n", totalMB)

	if !*apply {
		fmt.Println("\n💡 追加 `--apply` 参数即可将上述环境安全移入系统废纸篓 (支持随时从废纸篓恢复): `sectl clean-venvs --apply`")
		return
	}

	moved := 0
	for _, ov := range orphans {
		dest, err := lockfile.MoveVenvToTrash(ov.Path)
		if err != nil {
			fmt.Printf("  ⚠️ 跳过 %s: %v\n", ov.Name, err)
			continue
		}
		moved++
		fmt.Printf("  🗑️ 已移入废纸篓: %s -> %s\n", ov.Name, dest)
	}
	fmt.Printf("🎉 成功清理 %d 个孤儿虚拟环境！\n", moved)
}
