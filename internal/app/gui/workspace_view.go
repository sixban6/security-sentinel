package gui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
	"github.com/sixban6/security-sentinel/internal/scan/auditor"
	"github.com/sixban6/security-sentinel/internal/infra/model"
)

func formatProjectTimestamps(wp model.WorkspaceProjectAudit) string {
	var parts []string
	if wp.ModifiedUnix > 0 {
		parts = append(parts, "最近修改 "+time.Unix(wp.ModifiedUnix, 0).Local().Format("2006-01-02 15:04"))
	}
	if wp.CreatedUnix > 0 {
		parts = append(parts, "创建于 "+time.Unix(wp.CreatedUnix, 0).Local().Format("2006-01-02"))
	}
	if len(parts) == 0 {
		if wp.LastActiveDays == 0 {
			return "今日活跃"
		}
		return fmt.Sprintf("%d天前活跃", wp.LastActiveDays)
	}
	return strings.Join(parts, " · ")
}

// renderWorkspacePage renders the clean 2-level Dev Workspace Dependency Advisor & Zombie Virtualenv Cleaner:
// - A: Top 1-click batch upgrade across all visible upgradable projects
// - B: Immediate button disable + Spinner + <1s single-project OSV status refresh
// - C: Per-project safe OS Trash removal with confirmation dialog
// - D: Sorted by ModifiedUnix DESC, then CreatedUnix ASC ("最近修改的排前面，然后才是创建时间靠前的排前面")
func (s *AppState) renderWorkspacePage(c *ui.Context) {
	t := c.Theme()

	var allProjects []model.WorkspaceProjectAudit
	var allOrphans []model.OrphanedVenv
	for _, h := range s.Report.Hosts {
		allProjects = append(allProjects, h.WorkspaceProjects...)
		allOrphans = append(allOrphans, h.OrphanedVenvs...)
	}

	// Enforce deterministic sort: ModifiedUnix DESC -> CreatedUnix ASC
	sort.Slice(allProjects, func(i, j int) bool {
		if allProjects[i].Archived != allProjects[j].Archived {
			return !allProjects[i].Archived
		}
		if allProjects[i].ModifiedUnix != allProjects[j].ModifiedUnix {
			return allProjects[i].ModifiedUnix > allProjects[j].ModifiedUnix
		}
		if allProjects[i].CreatedUnix > 0 && allProjects[j].CreatedUnix > 0 && allProjects[i].CreatedUnix != allProjects[j].CreatedUnix {
			return allProjects[i].CreatedUnix < allProjects[j].CreatedUnix
		}
		return allProjects[i].ProjectName < allProjects[j].ProjectName
	})

	activeProjCount, activePkgCount, activeCVECount := 0, 0, 0
	archivedProjCount, archivedPkgCount := 0, 0
	var visibleProjects []model.WorkspaceProjectAudit
	var upgradableVisible []model.WorkspaceProjectAudit

	for _, wp := range allProjects {
		if wp.Archived {
			archivedProjCount++
			archivedPkgCount += len(wp.Packages)
			if s.ShowArchivedProjects {
				visibleProjects = append(visibleProjects, wp)
			}
		} else {
			activeProjCount++
			activePkgCount += len(wp.Packages)
			activeCVECount += wp.TotalCVEs
			visibleProjects = append(visibleProjects, wp)
		}
	}
	for _, wp := range visibleProjects {
		cmd := auditor.BuildProjectBatchUpgradeCmd(wp)
		if cmd != "" && !strings.HasPrefix(cmd, "#") {
			upgradableVisible = append(upgradableVisible, wp)
		}
	}

	var totalOrphanMB float64
	for _, ov := range allOrphans {
		totalOrphanMB += ov.SizeMB
	}

	ui.Column(c).Fill().Padding(22).Gap(12).Children(func() {
		// 1. Header Bar + 90-Day Switch + [A: 1-Click Upgrade All Projects]
		ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
			ui.Column(c).Grow(1).Gap(2).Children(func() {
				ui.Text(c, "开发工作区依赖体检与孤儿环境清理").FontSize(18).Bold()
				ui.Text(c, fmt.Sprintf("按「最近修改优先 ➔ 创建时间靠前优先」排序 · 近期活跃项目 %d 个 (%d 个待升级包，可消除 %d 个关联 CVE)",
					activeProjCount, activePkgCount, activeCVECount)).
					FontSize(12).TextColor(t.TextMuted)
			})

			if archivedProjCount > 0 {
				ui.Row(c).Gap(6).AlignItems(ui.Center).Children(func() {
					ui.Text(c, fmt.Sprintf("含 >90天 归档仓库 (%d)", archivedProjCount)).FontSize(12).TextColor(t.TextMuted)
					ui.Switch(c.Key("sw-show-archived"), &s.ShowArchivedProjects).Label("显示归档旧仓库")
				})
			}

			if len(upgradableVisible) > 0 {
				if s.BatchUpgradeRunning {
					ui.Row(c).Gap(6).Padding(6, 12).Radius(8).Background(t.Accent.Alpha(0.12)).AlignItems(ui.Center).Children(func() {
						ui.Spinner(c).Label("批量并发升级中")
						ui.Text(c, fmt.Sprintf("并发升级中 %d/%d", s.BatchUpgradeDone, s.BatchUpgradeTotal)).FontSize(12).Bold()
					})
				} else {
					ui.PrimaryButton(c.Key("btn-upg-all-ws"), fmt.Sprintf("一键升级全部项目 (%d)", len(upgradableVisible))).
						OnClick(func() {
							s.UpgradeAllWorkspaceProjectsAsync(upgradableVisible)
							c.Toast(fmt.Sprintf("🚀 已启动 6 路 Go 协程并发升级 %d 个项目…", len(upgradableVisible)))
						})
				}
			}
		})

		// Live Concurrent Worker Pool Progress Bar
		if s.BatchUpgradeRunning && s.BatchUpgradeTotal > 0 {
			ui.Column(c).Padding(10, 14).Radius(10).Gap(6).
				Background(t.Accent.Alpha(0.10)).Border(1, t.Accent.Alpha(0.35)).
				Children(func() {
					activeStr := strings.Join(s.BatchActiveProjects, ", ")
					ui.Row(c).AlignItems(ui.Center).Children(func() {
						ui.Text(c, fmt.Sprintf("🚀 Go 6路并发升级中 (已完成 %d/%d) · 正在并行处理: %s",
							s.BatchUpgradeDone, s.BatchUpgradeTotal, activeStr)).
							FontSize(12).Bold().Grow(1).SingleLine()
					})
					ui.Progress(c, float64(s.BatchUpgradeDone)/float64(max(1, s.BatchUpgradeTotal))).Label("并发升级进度")
				})
		}

		// Clear hint when >90d archived repositories (including older IntelliJ Java repos) are collapsed
		if archivedProjCount > 0 && !s.ShowArchivedProjects {
			ui.Row(c).Padding(8, 14).Radius(8).Gap(8).AlignItems(ui.Center).
				Background(t.Surface).Border(1, t.Border).
				Children(func() {
					ui.Text(c, fmt.Sprintf("🧊 已自动折叠 %d 个超过 90 天未改的历史仓库 (%d 个待升级包，含早期 Java / 归档项目)",
						archivedProjCount, archivedPkgCount)).FontSize(12).TextColor(t.TextMuted).Grow(1)
					if ui.Button(c.Key("btn-expand-arch"), "展开查看历史项目").Clicked() {
						s.ShowArchivedProjects = true
					}
				})
		}

		ui.Scroll(c.Key("workspace-scroll")).Grow(1).Gap(12).Children(func() {
			// 2. Orphaned / Zombie Virtualenv Safe Cleaner Card
			if len(allOrphans) > 0 {
				ui.Column(c.Key("orphan-venvs-card")).
					Padding(16, 20).Radius(12).Gap(10).
					Background(ui.Hex("#f59e0b").Alpha(0.10)).Border(1, ui.Hex("#f59e0b").Alpha(0.38)).
					Children(func() {
						ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
							ui.Column(c).Grow(1).Gap(2).Children(func() {
								ui.Text(c, fmt.Sprintf("🧹 发现 %d 个孤儿/僵尸 Python 虚拟环境 (共占用 %.1f MB)", len(allOrphans), totalOrphanMB)).
									FontSize(15).Bold()
								ui.Text(c, "原项目代码目录已删除或长期闲置，已自动排除在漏洞告警之外；移入系统废纸篓可安全释放空间").
									FontSize(12).TextColor(t.TextMuted)
							})
							ui.PrimaryButton(c.Key("btn-trash-all-venvs"), fmt.Sprintf("一键全部移入废纸篓 (%.0f MB)", totalOrphanMB)).
								OnClick(func() {
									cnt, mb := s.TrashAllOrphanedVenvs()
									c.Toast(fmt.Sprintf("已将 %d 个孤儿虚拟环境安全移入废纸篓 (释放 %.1f MB)", cnt, mb))
								})
						})

						for idx, ov := range allOrphans {
							ovCopy := ov
							ui.Row(c.Key(fmt.Sprintf("ov-%d-%s", idx, ovCopy.Name))).
								Padding(8, 12).Radius(8).Gap(10).AlignItems(ui.Center).
								Background(t.Surface).Border(1, t.Border).
								Children(func() {
									ui.Column(c).Grow(1).Gap(2).Children(func() {
										ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
											ui.Text(c, ovCopy.Name).FontSize(13).Bold()
											ui.Badge(c, fmt.Sprintf("%.1f MB", ovCopy.SizeMB))
											ui.Badge(c, ovCopy.Reason).Background(ui.Hex("#f59e0b").Alpha(0.18)).TextColor(ui.Hex("#d97706"))
										})
										ui.Text(c, ovCopy.Path).FontSize(11).TextColor(t.TextMuted).SingleLine()
									})
									ui.Button(c.Key(fmt.Sprintf("btn-ov-trash-%d", idx)), "移入废纸篓").OnClick(func() {
										if err := s.TrashOrphanedVenv(ovCopy.Path); err != nil {
											c.Toast("移入废纸篓失败: " + err.Error())
										} else {
											c.Toast("已移入废纸篓: " + ovCopy.Name)
										}
									})
								})
						}
					})
			}

			// 3. Empty State when all active projects are clean
			if len(visibleProjects) == 0 {
				ui.Column(c).Padding(48, 20).Center().Gap(8).
					Radius(12).Background(t.Surface).Border(1, t.Border).
					Children(func() {
						ui.Icon(c, IconShield).FontSize(36).TextColor(ui.Hex("#10b981"))
						ui.Text(c, "近期活跃的开发项目零高危依赖，干干净净！").FontSize(15).Bold()
						if archivedProjCount > 0 {
							ui.Text(c, fmt.Sprintf("另有 %d 个超过 90 天未修改的历史仓库已自动折叠静默 (%d 个旧依赖包)，可打开右上角开关查看。",
								archivedProjCount, archivedPkgCount)).FontSize(12).TextColor(t.TextMuted)
						}
					})
				return
			}

			// 4. Two-Level Collapsed Cards: Project -> Unique Package
			for pi, proj := range visibleProjects {
				pCopy := proj
				batchCmd := auditor.BuildProjectBatchUpgradeCmd(pCopy)
				pKey := fmt.Sprintf("ws-proj-%d-%s", pi, pCopy.ProjectDir)
				jobSt := s.WorkspaceJobStatus[pCopy.ProjectDir]
				isRunning := jobSt == "running"
				isQueued := jobSt == "queued"
				cardBusy := isRunning || isQueued

				ui.Column(c.Key(pKey)).Padding(16, 20).Radius(12).Gap(10).
					Background(t.Surface).Border(1, t.Border).
					Children(func() {
						ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
							ui.Icon(c, IconFolder).FontSize(18).TextColor(t.Accent)
							ui.Text(c, pCopy.ProjectName).FontSize(15).Bold()
							ui.Badge(c, pCopy.ManifestKind)
							if pCopy.Archived {
								ui.Badge(c, "归档旧仓库")
							} else {
								ui.Badge(c, "活跃").Background(ui.Hex("#10b981").Alpha(0.16)).TextColor(ui.Hex("#10b981"))
							}
							ui.Text(c, fmt.Sprintf("升级 %d 个包即可消除 %d 个关联 CVE", len(pCopy.Packages), pCopy.TotalCVEs)).
								FontSize(12).TextColor(t.TextMuted).Grow(1)

							if batchCmd != "" && !strings.HasPrefix(batchCmd, "#") {
								ui.Button(c.Key(pKey+"-copy"), "复制命令").OnClick(func() {
									if !s.Headless {
										mygo.Clipboard.WriteText(fmt.Sprintf("cd %q && %s", pCopy.ProjectDir, batchCmd))
									}
									c.Toast("已复制项目批量升级命令")
								})

								btnLabel := "一键升级本项目"
								if isRunning {
									btnLabel = "⏳ 正在升级中…"
								} else if isQueued {
									btnLabel = "排队等待中…"
								}
								ui.PrimaryButton(c.Key(pKey+"-upg"), btnLabel).
									Disabled(cardBusy).
									OnClick(func() {
										s.UpgradeWorkspaceCmdAsync(pCopy.ProjectDir, batchCmd, pCopy.ProjectName)
										c.Toast("🚀 正在后台并发升级「" + pCopy.ProjectName + "」并实时复核状态…")
									})
							}

							if pCopy.ProjectDir != "" && pCopy.ProjectDir != "global-pip" {
								ui.Button(c.Key(pKey+"-trash"), "删除本项目").
									Disabled(cardBusy).
									OnClick(func() {
										cp := pCopy
										s.PendingTrashProject = &cp
										s.ConfirmTrashProject = true
									})
							}
						})

						// Subtitle: Timestamps + Path
						ui.Text(c, formatProjectTimestamps(pCopy)+" · "+pCopy.ProjectDir).
							FontSize(11).TextColor(t.TextMuted).SingleLine()

						// Inline live status feedback banner for this project!
						if isRunning {
							ui.Row(c).Padding(8, 12).Radius(8).Gap(8).AlignItems(ui.Center).
								Background(t.Accent.Alpha(0.12)).
								Children(func() {
									ui.Spinner(c).Label("Upgrading")
									ui.Text(c, "正在执行依赖安全升级并重新扫描验证，完成后卡片将自动刷新…").FontSize(12)
								})
						} else if strings.HasPrefix(jobSt, "partial:") {
							ui.Text(c, "✅ "+strings.TrimPrefix(jobSt, "partial:")).
								FontSize(12).TextColor(ui.Hex("#10b981"))
						} else if strings.HasPrefix(jobSt, "warn:") {
							ui.Text(c, "⚠️ "+strings.TrimPrefix(jobSt, "warn:")).
								FontSize(12).TextColor(ui.Hex("#d97706"))
						}

						ui.Divider(c)

						// Unique Packages list inside this project
						for ki, pkg := range pCopy.Packages {
							pf := pkg
							rowKey := fmt.Sprintf("%s-pkg-%d-%s", pKey, ki, pf.Package)
							sevColor := ui.Hex("#f59e0b")
							if pf.Severity == "CRITICAL" {
								sevColor = ui.Hex("#ef4444")
							}
							ui.Row(c.Key(rowKey)).Padding(6, 10).Radius(8).Gap(10).AlignItems(ui.Center).
								Background(t.Background).Border(1, t.Border).
								Children(func() {
									ui.Badge(c, pf.Severity).Background(sevColor.Alpha(0.18)).TextColor(sevColor)
									verArrow := pf.InstalledVersion
									if pf.FixedVersion != "" {
										verArrow = fmt.Sprintf("%s ➔ %s", pf.InstalledVersion, pf.FixedVersion)
									}
									ui.Text(c, fmt.Sprintf("%s (%s)", pf.Package, verArrow)).FontSize(13).Bold()
									if pf.UpgradeHint != "" {
										hintColor := ui.Hex("#6366f1")
										if pf.FixedVersion == "" {
											hintColor = ui.Hex("#64748b")
										} else if pf.MajorUpgrade {
											hintColor = ui.Hex("#d97706")
										}
										ui.Badge(c, pf.UpgradeHint).Background(hintColor.Alpha(0.15)).TextColor(hintColor)
									}
									cvePreview := strings.Join(pf.CVEIDs, ", ")
									if len(pf.CVEIDs) > 3 {
										cvePreview = fmt.Sprintf("%s 等 %d 个 CVE", strings.Join(pf.CVEIDs[:2], ", "), len(pf.CVEIDs))
									}
									ui.Text(c, cvePreview).FontSize(11).TextColor(t.TextMuted).Grow(1).SingleLine()

									if pf.FixedVersion == "" {
										ui.Button(c.Key(rowKey+"-up"), "暂无补丁").Disabled(true)
									} else if !strings.HasPrefix(pf.UpgradeCmd, "#") {
										pkgBtnLbl := "升级此包"
										if isRunning {
											pkgBtnLbl = "升级中…"
										}
										ui.Button(c.Key(rowKey+"-up"), pkgBtnLbl).
											Disabled(cardBusy).
											OnClick(func() {
												s.UpgradeWorkspaceCmdAsync(pCopy.ProjectDir, pf.UpgradeCmd, pCopy.ProjectName+"/"+pf.Package)
												c.Toast("🚀 正在升级 " + pf.Package + "…")
											})
									}
								})
						}
					})
			}
		})
	})
}
