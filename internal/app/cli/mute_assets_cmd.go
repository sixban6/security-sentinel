package cli

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/sixban6/security-sentinel/internal/infra/model"
	"github.com/sixban6/security-sentinel/internal/infra/store"
	"github.com/sixban6/security-sentinel/internal/scan/inventory"
)

func runMute(args []string) {
	fs := flag.NewFlagSet("mute", flag.ExitOnError)
	hostKey := fs.String("host", "*", "目标主机名或 SSH 标识 (默认 * 代表全集群通用)")
	vulnID := fs.String("id", "", "CVE 编号或更新标识 (如 CVE-2025-xxxx)")
	pkgName := fs.String("pkg", "", "对应软件包名 (如 openssl)")
	mode := fs.String("mode", "permanent", "静默模式: skip_version | snooze | permanent")
	ver := fs.String("version", "", "skip_version 模式下要跳过的目标版本号")
	days := fs.Int("days", 30, "snooze 模式下暂缓提醒的天数 (默认 30 天)")
	listOnly := fs.Bool("list", false, "列出当前生效的全部豁免/暂缓规则")
	_ = fs.Parse(args)

	mem := store.New("")
	if *listOnly || (*vulnID == "" && *pkgName == "") {
		rules := mem.ListIgnoreRules()
		if len(rules) == 0 {
			fmt.Println("ℹ️ 当前没有已配置的静默豁免或暂缓规则。")
			return
		}
		fmt.Printf("🔕 当前生效的豁免 / 暂缓规则 (%d 条):\n", len(rules))
		for _, r := range rules {
			fmt.Printf("  • [%s] Key=%s | %s (%s) — %s\n", r.Mode, r.Key, r.VulnID, r.Package, r.Reason)
		}
		fmt.Println("\n💡 恢复监控命令: sectl unmute --key \"<Key>\"")
		return
	}

	if *vulnID == "" || *pkgName == "" {
		fmt.Fprintln(os.Stderr, "❌ 添加豁免规则请指定 --id <编号> 与 --pkg <包名> (例如: sectl mute --id CVE-2025-1234 --pkg openssl --mode snooze --days 30)")
		os.Exit(1)
	}

	rule := mem.AddIgnoreRule(model.IgnoreRule{
		HostKey:        *hostKey,
		HostName:       *hostKey,
		VulnID:         *vulnID,
		Package:        *pkgName,
		Mode:           *mode,
		SkippedVersion: *ver,
	}, *days)
	fmt.Printf("🔕 已添加静默规则: [%s] %s (%s) — %s (Key: %s)\n", rule.Mode, rule.VulnID, rule.Package, rule.Reason, rule.Key)
}

func runUnmute(args []string) {
	fs := flag.NewFlagSet("unmute", flag.ExitOnError)
	key := fs.String("key", "", "待移除的规则 Key (可通过 `sectl mute --list` 查看)")
	_ = fs.Parse(args)

	if strings.TrimSpace(*key) == "" && len(fs.Args()) > 0 {
		*key = fs.Args()[0]
	}
	if strings.TrimSpace(*key) == "" {
		fmt.Fprintln(os.Stderr, "❌ 请提供 --key \"<规则Key>\" (可运行 `sectl mute --list` 查看)")
		os.Exit(1)
	}
	mem := store.New("")
	if !mem.RemoveIgnoreRule(*key) {
		fmt.Fprintf(os.Stderr, "⚠️ 未找到匹配的豁免规则: %s\n", *key)
		os.Exit(1)
	}
	fmt.Printf("🔔 已移除豁免规则并恢复主动监控: %s\n", *key)
}

func runAssets(args []string) {
	fs := flag.NewFlagSet("assets", flag.ExitOnError)
	hostFilter := fs.String("host", "", "按主机名过滤")
	layer := fs.String("layer", "all", "按五层模型过滤: all | brew | docker | tools | os | workspace")
	query := fs.String("q", "", "按软件名、镜像名或版本关键词搜索")
	limit := fs.Int("limit", 60, "最多展示行数")
	_ = fs.Parse(args)

	snap := inventory.LoadDiscoveredInventories()
	if len(snap) == 0 {
		fmt.Println("ℹ️ 尚未生成全景资产快照，请先执行一次 `sectl audit`。")
		return
	}

	var hostNames []string
	for k := range snap {
		hostNames = append(hostNames, k)
	}
	sort.Strings(hostNames)

	qLow := strings.ToLower(strings.TrimSpace(*query))
	layerLow := strings.ToLower(strings.TrimSpace(*layer))
	shown := 0
	total := 0

	for _, hName := range hostNames {
		if *hostFilter != "" && !strings.Contains(strings.ToLower(hName), strings.ToLower(*hostFilter)) {
			continue
		}
		inv := snap[hName]
		es := inv.EcosystemSummary
		fmt.Printf("\n🖥️ %s — Homebrew(%d Formula/%d Cask) · Docker(%d 容器/%d 镜像) · 全局工具(%d) · 工具链 %v\n",
			hName, es.HomebrewFormulae, es.HomebrewCasks, es.DockerContainers, es.DockerImages, es.GlobalTools, es.Toolchains)
		fmt.Println(strings.Repeat("-", 74))

		for _, a := range inv.Assets {
			lCode := matchCLILayer(a)
			if layerLow != "all" && layerLow != "" && lCode != layerLow {
				continue
			}
			if qLow != "" {
				hay := strings.ToLower(a.Name + " " + a.Version + " " + a.Ecosystem + " " + a.Location + " " + a.ProjectName)
				if !strings.Contains(hay, qLow) {
					continue
				}
			}
			total++
			if shown < *limit {
				shown++
				fmt.Printf("  • [%-16s] %-32s %-18s (%s)\n", a.Ecosystem, a.Name, a.Version, a.Location)
			}
		}
	}
	if total > shown {
		fmt.Printf("\n... 共匹配 %d 项资产 (当前展示前 %d 项，可追加 --limit 或 -q 过滤)\n", total, shown)
	}
}

func matchCLILayer(a model.AssetItem) string {
	loc := strings.ToLower(a.Location)
	switch {
	case strings.HasPrefix(loc, "homebrew"):
		return "brew"
	case strings.HasPrefix(loc, "docker") || loc == "container-engine" || a.Ecosystem == model.EcoDocker:
		return "docker"
	case strings.HasPrefix(loc, "global-") || a.Kind == "binary":
		return "tools"
	case a.Kind == "venv" || a.Kind == "lockfile":
		return "workspace"
	default:
		return "os"
	}
}
