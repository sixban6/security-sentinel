package gui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
	"github.com/sixban6/security-sentinel/internal/ops/notify"
)

// renderDailyCVEFeedPage renders the multi-dimensional Daily Latest CVE Intelligence Center
// categorized by Language Ecosystems, OS Distributions, Linux Kernel, and Severity.
func (s *AppState) renderDailyCVEFeedPage(c *ui.Context) {
	t := c.Theme()

	// Lazy-trigger initial live fetch if empty when user visits this tab
	if len(s.DailyAdvisories) == 0 && !s.CVEFeedLoading && !s.Headless {
		s.RefreshDailyCVEsAsync(false)
	}

	catCode := "all"
	switch s.CVECategoryTab {
	case 1:
		catCode = "language"
	case 2:
		catCode = "os"
	case 3:
		catCode = "kernel"
	}

	sevCode := "all"
	switch s.CVESeverityTab {
	case 1:
		sevCode = "CRITICAL"
	case 2:
		sevCode = "HIGH"
	case 3:
		sevCode = "MEDIUM"
	}

	// Memoize breakdown counts, ecosystem options, and filtered sorted list across frames!
	sig := fmt.Sprintf("%d|%d|%s|%s|%s|%s|%s",
		s.cveCacheGen, len(s.DailyAdvisories), s.CVEDaysChoice, catCode, sevCode, s.CVEEcosystemChoice, s.CVESearchQuery)
	if s.cveCacheSig != sig {
		sourceAdvs := s.DailyAdvisories
		if s.CVEDaysChoice == "" || s.CVEDaysChoice == "今日" {
			sourceAdvs = notify.FilterAdvisoriesToday(s.DailyAdvisories, time.Now())
		}
		allDedup := notify.FilterAdvisories(sourceAdvs, "all", "all", "all", "")
		langTotal, osTotal, krnTotal := 0, 0, 0
		ecoSet := make(map[string]bool)
		for _, a := range allDedup {
			cType := a.EffectiveCategory()
			switch cType {
			case "kernel":
				krnTotal++
			case "os":
				osTotal++
			default:
				langTotal++
			}
			if (catCode == "all" || catCode == cType) && a.Ecosystem != "" {
				ecoSet[a.Ecosystem] = true
			}
		}

		ecoOptions := []string{"全部生态"}
		var sortedEcos []string
		for k := range ecoSet {
			sortedEcos = append(sortedEcos, k)
		}
		sort.Strings(sortedEcos)
		ecoOptions = append(ecoOptions, sortedEcos...)
		validChoice := false
		for _, opt := range ecoOptions {
			if opt == s.CVEEcosystemChoice {
				validChoice = true
				break
			}
		}
		if !validChoice {
			s.CVEEcosystemChoice = "全部生态"
		}

		s.cveCachedAllCount = len(allDedup)
		s.cveCachedLangCount = langTotal
		s.cveCachedOSCount = osTotal
		s.cveCachedKernelCount = krnTotal
		s.cveCachedEcoOptions = ecoOptions
		s.cveCachedFiltered = notify.FilterAdvisories(sourceAdvs, catCode, sevCode, s.CVEEcosystemChoice, s.CVESearchQuery)
		s.cveCacheSig = fmt.Sprintf("%d|%d|%s|%s|%s|%s|%s",
			s.cveCacheGen, len(s.DailyAdvisories), s.CVEDaysChoice, catCode, sevCode, s.CVEEcosystemChoice, s.CVESearchQuery)
	}

	allTotal := s.cveCachedAllCount
	langTotal := s.cveCachedLangCount
	osTotal := s.cveCachedOSCount
	krnTotal := s.cveCachedKernelCount
	ecoOptions := s.cveCachedEcoOptions
	filtered := s.cveCachedFiltered

	ui.Column(c).Fill().Padding(22).Gap(12).Children(func() {
		// 1. Header Row: Title + Counts + Time Window + Refresh + Standalone Telegram Push
		ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
			ui.Column(c).Grow(1).Gap(2).Children(func() {
				ui.Text(c, "📡 每日最新 CVE 全球安全情报中心").FontSize(18).Bold()
				ui.Text(c, fmt.Sprintf("全网总计 %d 条 · 💻 语言环境 %d · 🖥️ 操作系统 %d · 🐧 Linux 内核 %d (当前筛选命中 %d 条)",
					allTotal, langTotal, osTotal, krnTotal, len(filtered))).
					FontSize(12).TextColor(t.TextMuted)
			})

			prevDays := s.CVEDaysChoice
			if ui.Select(c.Key("cve-days-sel"), &s.CVEDaysChoice,
				[]string{"今日", "近 2 天", "近 3 天", "近 7 天", "近 14 天"}).
				Width(115).Label("时间窗口").Changed() && s.CVEDaysChoice != prevDays {
				s.RefreshDailyCVEsAsync(false)
			}

			ui.Button(c.Key("btn-cve-refresh"), "实时刷新").
				Disabled(s.CVEFeedLoading).
				OnClick(func() {
					s.RefreshDailyCVEsAsync(true)
					c.Toast("正在实时抓取 GHSA、Debian/Ubuntu/RHEL 与 NVD 内核通告…")
				})

			tgBtnText := "推送分类日报至 Telegram"
			if s.CVEPushingTG {
				tgBtnText = "推送中…"
			}
			ui.PrimaryButton(c.Key("btn-cve-push-tg"), tgBtnText).
				Disabled(s.CVEPushingTG || s.CVEFeedLoading).
				OnClick(func() {
					s.PushDailyCVEDigestToTelegramAsync()
					c.Toast("✈️ 正在单独发送分类 CVE 情报卡片至 Telegram…")
				})
		})

		// 2. Multi-Dimensional Filter Bar (Category + Severity + Sub-Ecosystem + Search)
		ui.Row(c).Gap(10).Wrap().AlignItems(ui.Center).Children(func() {
			ui.Segmented(c.Key("cve-cat-seg"), &s.CVECategoryTab,
				"全部领域", "语言环境", "操作系统", "Linux内核").Label("领域分类")

			ui.Segmented(c.Key("cve-sev-seg"), &s.CVESeverityTab,
				"全部等级", "CRITICAL", "HIGH", "MEDIUM").Label("重要性分级")

			if len(ecoOptions) > 1 {
				ui.Select(c.Key("cve-eco-sel"), &s.CVEEcosystemChoice, ecoOptions).
					Width(135).Label("具体生态")
			}

			ui.TextInput(c.Key("cve-search-in"), &s.CVESearchQuery).
				Placeholder("搜索 CVE 编号、包名或关键词…").Grow(1).MinWidth(180).Label("关键词过滤")
		})

		if s.CVEFeedLoading {
			ui.Column(c).Grow(1).Center().Gap(10).Children(func() {
				ui.Spinner(c).Size(28, 28).Label("抓取最新 CVE 中")
				ui.Text(c, "正在并发同步 GitHub 12 大语言生态、Debian/Ubuntu/RHEL 安全通告与 NVD Linux 内核漏洞流…").
					FontSize(12).TextColor(t.TextMuted)
			})
			return
		}

		if len(filtered) == 0 {
			ui.Column(c).Grow(1).Center().Gap(8).
				Radius(12).Background(t.Surface).Border(1, t.Border).
				Children(func() {
					ui.Text(c, "当前筛选条件下暂无匹配的 CVE 通告").FontSize(14).Bold()
					ui.Text(c, "可切换上方「领域分类 / 重要性分级 / 时间窗口」或点击右上角「实时刷新」").
						FontSize(12).TextColor(t.TextMuted)
				})
			return
		}

		// 3. Virtualized High-Density CVE Intelligence List (120fps smooth scrolling for hundreds of items)
		s.CVEListState.Key = func(i int) any {
			if i >= 0 && i < len(filtered) {
				return filtered[i].DisplayID() + "|" + filtered[i].Ecosystem + "|" + filtered[i].Package
			}
			return i
		}
		ui.List(c, &s.CVEListState, len(filtered), func(idx int) {
			adv := filtered[idx]
			rowKey := fmt.Sprintf("cve-row-%d-%s", idx, adv.DisplayID())

			sevBg, sevFg := ui.Hex("#f59e0b").Alpha(0.18), ui.Hex("#d97706")
			switch adv.Severity {
			case "CRITICAL":
				sevBg, sevFg = ui.Hex("#ef4444").Alpha(0.20), ui.Hex("#ef4444")
			case "MEDIUM":
				sevBg, sevFg = ui.Hex("#3b82f6").Alpha(0.16), ui.Hex("#3b82f6")
			}

			catLabel := "语言 · " + adv.Ecosystem
			switch adv.EffectiveCategory() {
			case "kernel":
				catLabel = "内核 · Linux"
			case "os":
				catLabel = "OS · " + adv.Ecosystem
			}

			sevPill := adv.Severity
			if adv.CVSS > 0 {
				sevPill = fmt.Sprintf("%s · %.1f", adv.Severity, adv.CVSS)
			}

			pubDate := adv.PublishedAt
			if len(pubDate) >= 16 {
				pubDate = strings.Replace(pubDate[:16], "T", " ", 1)
			}

			ui.Column(c.Key(rowKey)).Padding(12, 16).Radius(10).Gap(6).
				Background(t.Surface).Border(1, t.Border).
				Children(func() {
					ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
						ui.Badge(c, sevPill).Background(sevBg).TextColor(sevFg)
						ui.Badge(c, catLabel)
						ui.Text(c, adv.DisplayID()).FontSize(14).Bold()
						if adv.Package != "" {
							verNote := adv.Package
							if len(adv.FixedIn) > 0 && adv.FixedIn[0] != "" {
								verNote = fmt.Sprintf("%s (修复于 %s)", adv.Package, adv.FixedIn[0])
							} else if adv.VulnerableRange != "" {
								verNote = fmt.Sprintf("%s (%s)", adv.Package, adv.VulnerableRange)
							}
							ui.Text(c, verNote).FontSize(12).TextColor(t.Accent).SingleLine()
						}
						ui.Spacer(c)
						if pubDate != "" {
							ui.Text(c, pubDate).FontSize(11).TextColor(t.TextMuted)
						}
						ui.Button(c.Key(rowKey+"-cp"), "复制").OnClick(func() {
							if !s.Headless {
								mygo.Clipboard.WriteText(adv.DisplayID())
							}
							c.Toast("已复制 " + adv.DisplayID())
						})
						if adv.URL != "" {
							u := adv.URL
							ui.Button(c.Key(rowKey+"-open"), "官方详情").OnClick(func() {
								if !s.Headless {
									_ = mygo.Shell.OpenExternal(u)
								}
							})
						}
					})
					ui.Text(c, firstNonEmptyStr(adv.Summary, "详见官方安全通告")).FontSize(12)
				})
		}).Grow(1).Gap(8)
	})
}
