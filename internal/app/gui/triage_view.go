package gui

import (
	"fmt"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
	"github.com/egoist/mygo/ui/editor"
	"github.com/egoist/mygo/ui/markdown"
	"github.com/sixban6/security-sentinel/internal/infra/model"
)

// renderTriageDiffPage renders the Vulnerability Surgical Workbench, Side-by-Side GPU DiffViewer,
// and 3-tier Risk Exemption / Skip-Version / Snooze management.
func (s *AppState) renderTriageDiffPage(c *ui.Context) {
	t := c.Theme()
	entries := s.FilteredVulnEntries()
	ignoreRules := s.IgnoreRules

	var selected *SelectedVulnEntry
	for i := range entries {
		if vulnEntryKey(entries[i]) == s.SelectedVulnKey {
			selected = &entries[i]
			break
		}
	}
	if selected == nil && len(entries) > 0 {
		selected = &entries[0]
		s.SelectedVulnKey = vulnEntryKey(entries[0])
	}
	if selected != nil {
		s.syncDiffBuffersForEntry(*selected)
	}

	ignoredLabel := "已豁免/暂缓"
	if len(ignoreRules) > 0 {
		ignoredLabel = fmt.Sprintf("已豁免/暂缓 (%d)", len(ignoreRules))
	}

	ui.Column(c).Fill().Children(func() {
		// Top Filter Toolbar
		ui.Row(c).Padding(12, 20).Gap(10).AlignItems(ui.Center).
			BorderWidth(0, 0, 1, 0).BorderColor(t.Border).
			Children(func() {
				ui.Segmented(c.Key("triage-filter"), &s.TriageFilter,
					"全部待处置", "系统安全更新", "代码与内核 CVE", "已免疫闭环", ignoredLabel,
				).Label("漏洞筛选")
				ui.Spacer(c)
				if s.TriageFilter == 4 {
					ui.Text(c, fmt.Sprintf("当前生效豁免规则 %d 条", len(ignoreRules))).FontSize(12).TextColor(t.TextMuted)
				} else {
					ui.Text(c, fmt.Sprintf("共 %d 项条目", len(entries))).FontSize(12).TextColor(t.TextMuted)
				}
			})

		// Tab 4: Dedicated Active Exemption / Snooze / Skip-Version Rules Manager
		if s.TriageFilter == 4 {
			s.renderIgnoredRulesManager(c, ignoreRules)
			return
		}

		if len(entries) == 0 {
			ui.Column(c).Grow(1).Center().Gap(10).Children(func() {
				ui.Icon(c, IconShield).FontSize(40).TextColor(ui.Hex("#10b981"))
				ui.Text(c, "当前筛选条件下零待处置风险，全集群运行健康！").FontSize(15).Bold()
				ui.Text(c, "所有主机内核、系统安全源与运行态容器均已核验通过").FontSize(12).TextColor(t.TextMuted)
			})
			return
		}

		// Master-Detail Split: Left Vulnerability List | Right Markdown + Mute Controls + GPU DiffView
		ui.Split(c, &s.TriageSplit,
			func() {
				ui.Scroll(c.Key("triage-left-scroll")).Fill().Padding(10).Gap(6).Children(func() {
					for i := range entries {
						e := entries[i]
						k := vulnEntryKey(e)
						isSel := k == s.SelectedVulnKey
						itemBox := ui.Column(c.Key("ve-"+k)).Padding(10, 12).Radius(10).Gap(4).
							Cursor(ui.CursorPointer).Border(1, t.Border)
						if isSel {
							itemBox.Background(t.Accent.Alpha(0.14)).BorderColor(t.Accent)
						} else if itemBox.Hovered() {
							itemBox.Background(t.SurfaceHover)
						} else {
							itemBox.Background(t.Surface)
						}
						itemBox.OnClick(func() {
							s.SelectedVulnKey = k
						})
						itemBox.Children(func() {
							ui.Row(c).Gap(6).AlignItems(ui.Center).Children(func() {
								sevColor := ui.Hex("#f59e0b")
								if e.Vuln.Severity == "CRITICAL" {
									sevColor = ui.Hex("#ef4444")
								}
								ui.Badge(c, e.Vuln.Severity).Background(sevColor.Alpha(0.18)).TextColor(sevColor)
								ui.Text(c, e.Vuln.EffectiveID()).Bold().FontSize(12).Grow(1).SingleLine()
							})
							ui.Text(c, fmt.Sprintf("%s · %s (%s)", e.Host.Host, e.Vuln.Package, e.Vuln.InstalledVersion)).
								FontSize(11).TextColor(t.TextMuted).SingleLine()
						})
					}
				})
			},
			func() {
				if selected == nil {
					return
				}
				sel := *selected
				v := sel.Vuln
				ui.Column(c).Fill().Padding(16, 20).Gap(10).Children(func() {
					// 1. Detail Header & Primary Fix Action Buttons
					ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
						ui.Column(c).Grow(1).Gap(2).Children(func() {
							ui.Text(c, fmt.Sprintf("%s — %s (%s)", v.EffectiveID(), v.Package, sel.Host.Host)).FontSize(16).Bold()
							locStr := v.Location
							if locStr == "" {
								locStr = sel.Host.OSContext.OSPretty
							}
							ui.Text(c, fmt.Sprintf("位置: %s · 当前版本: %s · 修复版本: %s",
								locStr, v.InstalledVersion, firstNonEmptyStr(v.FixedVersion, "待确认"))).
								FontSize(12).TextColor(t.TextMuted)
						})

						if !sel.IsFixed {
							if v.Package == "macos-system" {
								ui.PrimaryButton(c.Key("tri-open-mac-su"), "打开 macOS 软件更新").OnClick(func() {
									OpenAppleSoftwareUpdate()
									c.Toast("已打开 macOS 系统设置 ➔ 软件更新")
								})
							} else if v.IsOSPackage && sel.Host.OSSecurity.RemediationPlan.SafeToExecute {
								ui.PrimaryButton(c.Key("tri-apply-os"), "安装此主机安全补丁").
									Disabled(s.FixingHost != "").
									OnClick(func() {
										s.ApplyHostOSFixesAsync(sel.Host.Target.EffectiveKey())
										c.Toast("正在执行定向安全补丁安装…")
									})
							} else if !v.IsOSPackage {
								ui.Button(c.Key("tri-ask-ai"), "").Disabled(s.AIRunning).Children(func() {
									ui.Icon(c, IconSpark)
									ui.Text(c, "AI 研判生成双脚本").SingleLine()
								}).OnClick(func() {
									s.GenerateAITriageForSelectedAsync(sel)
									c.Toast("正在调用 AI 研判可行性与配对回滚脚本…")
								})

								if v.MitigateScript != "" && v.RollbackScript != "" {
									ui.PrimaryButton(c.Key("tri-approve-exec"), "批准并远程执行").
										Disabled(s.AIRunning).
										OnClick(func() {
											s.ApproveAndExecuteSelectedMitigation(sel)
											c.Toast("正在下发加固脚本并进行多节点网络探活…")
										})
								}
							}
						}

						ui.Button(c.Key("tri-copy-script"), "复制处方").OnClick(func() {
							if !s.Headless {
								mygo.Clipboard.WriteText(s.DiffState.New.String())
							}
							c.Toast("已复制到剪贴板")
						})
					})

					// 2. User Exemption / Skip-Version / Snooze Bar ("我不想升这个，别烦我")
					if !sel.IsFixed {
						ui.Row(c).Padding(6, 12).Radius(8).Gap(8).AlignItems(ui.Center).
							Background(t.Surface).Border(1, t.Border).
							Children(func() {
								ui.Text(c, "🔕 暂不升级？可一键静默:").FontSize(12).TextColor(t.TextMuted)
								if v.FixedVersion != "" {
									ui.Button(c.Key("mute-skip-ver"), fmt.Sprintf("跳过此版本 (%s)", v.FixedVersion)).OnClick(func() {
										s.MuteSelectedVulnerability(sel, "skip_version", 0)
										c.Toast(fmt.Sprintf("已跳过 %s 版本 %s (未来发布新版本时将自动恢复提醒)", v.Package, v.FixedVersion))
									})
								}
								ui.Button(c.Key("mute-snooze-30"), "暂缓 30 天").OnClick(func() {
									s.MuteSelectedVulnerability(sel, "snooze", 30)
									c.Toast("已暂缓提醒 30 天，菜单栏与健康分已同步更新")
								})
								ui.Button(c.Key("mute-perm"), "永久豁免此项").OnClick(func() {
									s.MuteSelectedVulnerability(sel, "permanent", 0)
									c.Toast("已永久豁免此项 (随时可在「已豁免/暂缓」标签页恢复)")
								})
							})
					}

					// 3. Markdown Vulnerability Brief
					mdDoc := fmt.Sprintf("**漏洞摘要**: %s\n\n- **状态提示**: %s\n- **安全承诺**: 所有远程变更均配备断网自动秒级回滚与本地熔断保护。",
						firstNonEmptyStr(v.Summary, "详见官方通告"),
						firstNonEmptyStr(v.Reason, firstNonEmptyStr(v.Action, "先审阅下方处方 Diff，确认无误后再执行")),
					)
					ui.Scroll(c.Key("tri-md-scroll")).MaxHeight(105).Padding(10, 14).Radius(10).
						Background(t.Surface).Border(1, t.Border).
						Children(func() {
							markdown.View(c, mdDoc, &s.MDOpts)
						})

					// 4. Side-by-Side GPU Code Diff Viewer
					ui.Text(c, "处方对比台 (左: 基准状态 / 应急回滚脚本  |  右: 拟执行命令 / 可编辑加固脚本)").
						FontSize(12).Bold().TextColor(t.TextMuted)
					ui.Box(c).Grow(1).FillWidth().Radius(10).Clip().Border(1, t.Border).Children(func() {
						editor.DiffView(c, s.DiffState).Fill()
					})
				})
			},
		).Grow(1).FillWidth()
	})
}

func (s *AppState) renderIgnoredRulesManager(c *ui.Context, rules []model.IgnoreRule) {
	t := c.Theme()
	if len(rules) == 0 {
		ui.Column(c).Grow(1).Center().Gap(8).Children(func() {
			ui.Text(c, "当前没有处于静默豁免或暂缓状态的条目").FontSize(14).Bold()
			ui.Text(c, "在漏洞手术台中对不想升级的条目点击「跳过此版本 / 暂缓 30 天 / 永久豁免」后将在此统一管理").
				FontSize(12).TextColor(t.TextMuted)
		})
		return
	}

	ui.Scroll(c.Key("ignored-rules-scroll")).Grow(1).Padding(20).Gap(10).Children(func() {
		for idx, r := range rules {
			ruleCopy := r
			modeBadge := "永久豁免"
			switch ruleCopy.Mode {
			case "skip_version":
				modeBadge = "跳过版本 " + ruleCopy.SkippedVersion
			case "snooze":
				modeBadge = "暂缓提醒"
			}

			ui.Row(c.Key(fmt.Sprintf("ig-rule-%d-%s", idx, ruleCopy.Key))).
				Padding(14, 18).Radius(10).Gap(12).AlignItems(ui.Center).
				Background(t.Surface).Border(1, t.Border).
				Children(func() {
					ui.Column(c).Grow(1).Gap(4).Children(func() {
						ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
							ui.Badge(c, modeBadge).Background(ui.Hex("#f59e0b").Alpha(0.18)).TextColor(ui.Hex("#d97706"))
							ui.Text(c, fmt.Sprintf("%s · %s (%s)",
								firstNonEmptyStr(ruleCopy.HostName, ruleCopy.HostKey),
								ruleCopy.VulnID,
								ruleCopy.Package,
							)).Bold()
							ui.Text(c, "创建于 "+ruleCopy.CreatedAt).FontSize(11).TextColor(t.TextMuted)
						})
						ui.Text(c, ruleCopy.Reason).FontSize(12).TextColor(t.TextMuted)
					})

					ui.PrimaryButton(c.Key(fmt.Sprintf("btn-unmute-%d", idx)), "恢复监控").OnClick(func() {
						s.UnmuteRuleByKey(ruleCopy.Key)
						c.Toast("🔔 已恢复监控: " + ruleCopy.Package)
					})
				})
		}
	})
}
