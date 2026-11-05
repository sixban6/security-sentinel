package gui

import (
	"context"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
	"github.com/egoist/mygo/ui/chart"
	"github.com/egoist/mygo/ui/editor"
	"github.com/egoist/mygo/ui/markdown"
	"github.com/sixban6/security-sentinel/internal/infra/config"
	"github.com/sixban6/security-sentinel/internal/infra/model"
	"github.com/sixban6/security-sentinel/internal/ops/notify"
	"github.com/sixban6/security-sentinel/internal/infra/secrets"
)

// MissionControlView renders the full native GPU Security Sentinel desktop workbench.
func (s *AppState) MissionControlView(c *ui.Context) {
	t := c.Theme()

	// Keyboard shortcuts
	if c.Shortcut(ui.Cmd, ui.KeyR) && !s.Scanning {
		s.StartAuditAsync(s.AutoFixEnabled, s.AIEnabled)
	}

	totalUnmit, _, retirable := s.PendingCounts()

	ui.Split(c, &s.SidebarWidth,
		func() {
			s.renderSidebar(c, totalUnmit, retirable)
		},
		func() {
			ui.Column(c).Fill().Background(t.Background).Children(func() {
				s.renderTopBanner(c)
				switch s.ActivePage {
				case "hosts":
					s.renderHostsAndDoctorPage(c)
				case "triage":
					s.renderTriageDiffPage(c)
				case "cves":
					s.renderDailyCVEFeedPage(c)
				case "workspace":
					s.renderWorkspacePage(c)
				case "ha":
					s.renderZeroDowntimeHAPage(c)
				case "history":
					s.renderHistoryRollbackPage(c)
				case "settings":
					s.renderSettingsVaultPage(c)
				default:
					s.renderOverviewPage(c)
				}
			})
		},
	).Fill()

	// SSH Config Auto-Discovery Onboarding Modal
	s.renderSSHOnboardingModal(c)
	s.renderManualAddHostModal(c)

	// Safety Confirmation AlertDialog before Remote Rollback
	if s.PendingRollback != nil {
		rec := *s.PendingRollback
		ans := ui.AlertDialog(c, &s.ConfirmRollback,
			fmt.Sprintf("确认远程回滚 %s？", rec.CVEID),
			fmt.Sprintf("将在主机 [%s] 上执行归档脚本 %s 并移除生效标记。", rec.HostName, rec.RollbackPath),
			"取消", "确认回滚",
		)
		if ans == 1 {
			s.PendingRollback = nil
			s.ExecuteRollbackAsync(rec.HostKey, rec.CVEID)
			c.Toast("正在远程执行回滚脚本…")
		} else if !s.ConfirmRollback {
			s.PendingRollback = nil
		}
	}

	// Safety Confirmation AlertDialog before Moving Project to OS Trash
	if s.PendingTrashProject != nil {
		proj := *s.PendingTrashProject
		ans := ui.AlertDialog(c, &s.ConfirmTrashProject,
			fmt.Sprintf("将项目「%s」移入系统废纸篓？", proj.ProjectName),
			fmt.Sprintf("完整路径: %s\n该项目将被安全移入废纸篓（不会永久删除，随时可在废纸篓「放回原处」还原）。", proj.ProjectDir),
			"取消", "移入废纸篓",
		)
		if ans == 1 {
			s.PendingTrashProject = nil
			if err := s.TrashWorkspaceProject(proj.ProjectDir, proj.ProjectName); err != nil {
				c.Toast("移入废纸篓失败: " + err.Error())
			} else {
				c.Toast("🗑️ 已移入系统废纸篓: " + proj.ProjectName)
			}
		} else if !s.ConfirmTrashProject {
			s.PendingTrashProject = nil
		}
	}
}

func (s *AppState) renderSidebar(c *ui.Context, totalUnmit int, retirable int) {
	t := c.Theme()
	ui.Column(c).Fill().Background(t.Surface).Children(func() {
		// App Brand Header
		ui.Row(c).Padding(16, 16, 8, 16).Gap(10).AlignItems(ui.Center).Children(func() {
			ui.Icon(c, IconShield).FontSize(22).TextColor(t.Accent)
			ui.Column(c).Gap(1).Children(func() {
				ui.Text(c, "Security Sentinel").FontSize(14).Bold()
				ui.Text(c, "v"+model.Version+" Native GPU").FontSize(11).TextColor(t.TextMuted)
			})
		})

		activeWSPkgs, _, orphanVenvs := s.WorkspaceCounts()
		wsBadgeTotal := activeWSPkgs + orphanVenvs

		ui.Sidebar(c.Key("main-nav"), &s.ActivePage, func() {
			ui.SidebarSection(c, "态势与处置", nil, func() {
				ui.SidebarItem(c, "overview", IconGrid, "全景安全大盘")
				ui.SidebarItem(c, "hosts", IconServer, "主机矩阵与体检").Children(func() {
					ui.Badge(c, fmt.Sprint(len(s.Report.Hosts)))
				})
				ui.SidebarItem(c, "triage", IconBug, "漏洞审阅手术台").Children(func() {
					if totalUnmit > 0 {
						ui.Badge(c, fmt.Sprint(totalUnmit)).Background(ui.Hex("#ef4444")).TextColor(ui.Hex("#ffffff"))
					}
				})
				ui.SidebarItem(c, "cves", IconRadar, "每日最新 CVE").Children(func() {
					if len(s.DailyAdvisories) > 0 {
						ui.Badge(c, fmt.Sprint(len(s.DailyAdvisories)))
					}
				})
				ui.SidebarItem(c, "workspace", IconFolder, "开发依赖与清理").Children(func() {
					if wsBadgeTotal > 0 {
						ui.Badge(c, fmt.Sprint(wsBadgeTotal))
					}
				})
			})
			ui.SidebarSection(c, "高可用与时光机", nil, func() {
				ui.SidebarItem(c, "ha", IconSync, "零中断切流重启")
				ui.SidebarItem(c, "history", IconClock, "时光机与回滚").Children(func() {
					if retirable > 0 {
						ui.Badge(c, fmt.Sprint(retirable)).Background(ui.Hex("#f59e0b")).TextColor(ui.Hex("#ffffff"))
					}
				})
				ui.SidebarItem(c, "settings", IconKey, "钥匙串与智能策略")
			})
		}).Grow(1).FillWidth()

		ui.Divider(c)
		ui.Column(c).Padding(12, 14).Gap(6).Children(func() {
			if s.Scanning {
				ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
					ui.Spinner(c).Label("Scanning")
					ui.Text(c, fmt.Sprintf("巡检中 (%d/%d)", s.ScanStep, s.ScanTotal)).FontSize(12).Bold()
				})
				ui.Progress(c, float64(s.ScanStep)/float64(max(1, s.ScanTotal))).Label("Scan progress")
			} else {
				netTag := "🟢 网络在线 · 守护就绪"
				if !s.Online {
					netTag = "🔴 网络离线 · 等待重连"
				} else if s.MeteredNetwork {
					netTag = "🟡 手机热点 · 省流保护中"
				}
				ui.Text(c, netTag).FontSize(11).TextColor(t.TextMuted)
			}
		})
	})
}

func (s *AppState) renderTopBanner(c *ui.Context) {
	if s.StatusBanner == "" {
		return
	}
	t := c.Theme()
	ui.Row(c).Padding(8, 20).Gap(10).AlignItems(ui.Center).
		Background(t.Accent.Alpha(0.10)).BorderWidth(0, 0, 1, 0).BorderColor(t.Border).
		Children(func() {
			ui.Icon(c, IconBolt).TextColor(t.Accent)
			ui.Text(c, s.StatusBanner).Grow(1).FontSize(12).SingleLine()
			if ui.Button(c.Key("dismiss-banner"), "知道了").Clicked() {
				s.StatusBanner = ""
			}
		})
}

// ============================================================================
// Page 1: Overview Dashboard (KPIs + Native GPU Bar Chart + Supply-Chain Radar)
// ============================================================================
func (s *AppState) renderOverviewPage(c *ui.Context) {
	t := c.Theme()
	totalAssets, totalFixed, totalUnmit, osUpdates := 0, 0, 0, 0
	var ecoAgg model.EcosystemSummary

	for _, h := range s.Report.Hosts {
		totalAssets += max(h.AssetsCount, h.PackagesCount)
		totalFixed += len(h.FixedItems)
		totalUnmit += len(h.Vulnerabilities)
		for _, v := range h.Vulnerabilities {
			if v.IsOSPackage {
				osUpdates++
			}
		}
		ecoAgg.PythonVenvs += h.EcosystemSummary.PythonVenvs
		ecoAgg.NodeProjects += h.EcosystemSummary.NodeProjects
		ecoAgg.GoModules += h.EcosystemSummary.GoModules
		ecoAgg.RustCrates += h.EcosystemSummary.RustCrates
		ecoAgg.JavaJDKs += h.EcosystemSummary.JavaJDKs
		ecoAgg.JavaProjects += h.EcosystemSummary.JavaProjects
		ecoAgg.PHPProjects += h.EcosystemSummary.PHPProjects
		ecoAgg.DockerContainers += h.EcosystemSummary.DockerContainers
	}

	posture := s.ClusterPosture()
	heroColor := ui.Hex("#10b981")
	if posture == "danger" {
		heroColor = ui.Hex("#ef4444")
	} else if posture == "warn" {
		heroColor = ui.Hex("#f59e0b")
	}

	ui.Scroll(c.Key("overview-scroll")).Grow(1).Padding(24).Gap(18).Children(func() {
		// 1. Hero Score & Action Bar
		ui.Row(c).Padding(20, 24).Radius(14).Gap(16).AlignItems(ui.Center).
			Background(t.Surface).Border(1, t.Border).
			Children(func() {
				ui.Column(c).Grow(1).Gap(6).Children(func() {
					ui.Row(c).Gap(10).AlignItems(ui.Baseline).Children(func() {
						ui.Text(c, fmt.Sprintf("%d", s.Report.ClusterScore)).FontSize(42).Bold().TextColor(heroColor)
						ui.Text(c, "/ 100 集群安全健康分").FontSize(14).TextColor(t.TextMuted)
					})
					desc := "OSV 全量存量库 + GitHub GHSA 12 大生态 + Linux 内核多 LTS 分支实时闭环守护"
					if !s.LastScanAt.IsZero() {
						desc = fmt.Sprintf("最近巡检: %s · 覆盖 %d 条最新通告", s.LastScanAt.Format("2006-01-02 15:04:05"), s.Report.AdvisoriesCount)
					}
					ui.Text(c, desc).FontSize(12).TextColor(t.TextMuted)
				})

				ui.Row(c).Gap(8).Children(func() {
					if osUpdates > 0 {
						ui.Button(c.Key("ov-fix-os"), fmt.Sprintf("一键安装安全补丁 (%d)", osUpdates)).
							Disabled(s.FixingHost != "").
							OnClick(func() {
								s.ApplyHostOSFixesAsync("")
								c.Toast("已启动全集群官方安全补丁无损热升级…")
							})
					}
					ui.Button(c.Key("ov-export-html"), "导出 HTML 战报").OnClick(func() {
						if p := s.ExportHTMLReport(); p != "" {
							c.Toast("已生成并打开可视化 HTML 审计战报")
						}
					})
					ui.PrimaryButton(c.Key("ov-scan-now"), "立即全量巡检").
						Disabled(s.Scanning).
						OnClick(func() { s.StartAuditAsync(s.AutoFixEnabled, s.AIEnabled) })
				})
			})

		// 2. 4 KPI Cards
		ui.Row(c).Gap(12).Children(func() {
			renderKPICard(c, "守护主机节点", fmt.Sprint(len(s.Report.Hosts)), "本机 + SSH 免密集群", t.Text)
			renderKPICard(c, "深度扫描资产", fmt.Sprint(totalAssets), "系统包 / 内核 / 锁文件 / 容器", t.Accent)
			renderKPICard(c, "已闭环免疫", fmt.Sprint(totalFixed), "官方升级与 AI 规避加固", ui.Hex("#10b981"))
			unmitColor := t.Text
			if totalUnmit > 0 {
				unmitColor = ui.Hex("#ef4444")
			}
			renderKPICard(c, "待处置风险", fmt.Sprint(totalUnmit), "点击进入手术台审阅 Diff", unmitColor)
		})

		// 3. Per-Host Health Score GPU Chart (ui/chart)
		if len(s.Report.Hosts) > 0 {
			ui.Column(c).Padding(18, 20).Radius(12).Gap(12).Background(t.Surface).Border(1, t.Border).Children(func() {
				ui.Row(c).AlignItems(ui.Center).Children(func() {
					ui.Text(c, "各主机安全健康度评分分布").FontSize(15).Bold().Grow(1)
					ui.Text(c, "点击柱状条可直达对应主机详情").FontSize(11).TextColor(t.TextMuted)
				})

				labels := make([]string, len(s.Report.Hosts))
				scores := make([]float64, len(s.Report.Hosts))
				for i, h := range s.Report.Hosts {
					labels[i] = h.Host
					scores[i] = float64(h.HealthScore)
				}
				xScale := chart.NewBand(labels...).Padding(0.32, 0.16)
				yScale := chart.NewLinear(0, 100)
				ticks := yScale.Ticks(4)
				axisLabel := func(side chart.Side, tick chart.Tick) {
					ui.Text(c, tick.Label).NoWrap().FontSize(11).TextColor(t.TextMuted)
				}

				chart.Plot(c, chart.Axes{Left: ticks, Bottom: xScale.Ticks(), Label: axisLabel}, func(area ui.Element) {
					area.Draw(func(p *ui.Painter, r ui.Rect) {
						for _, tk := range ticks {
							y := chart.Y(r, tk.At)
							p.Line(r.X, y, r.X+r.W, y, 1, t.Border)
						}
					})
					for i, sc := range scores {
						hostItem := s.Report.Hosts[i]
						_, barColor := statusColors(hostItem.Status)
						bar := chart.Rect(c.Key("bar-"+hostItem.Target.EffectiveKey()), xScale.Band(i), yScale.Span(0, sc)).
							Radius(6).Background(barColor).Cursor(ui.CursorPointer).
							Tooltip(fmt.Sprintf("%s: %d分 (%s)", hostItem.Host, hostItem.HealthScore, hostItem.Status))
						bar.OnClick(func() {
							if len(hostItem.Vulnerabilities) > 0 {
								s.ActivePage = "triage"
							} else {
								s.ActivePage = "hosts"
							}
						})
					}
				}).Label("主机健康度图表").Height(180).Gap(8)
			})
		}

		// 4. Workspace & Container Supply-Chain Radar
		ui.Column(c).Padding(18, 20).Radius(12).Gap(10).Background(t.Surface).Border(1, t.Border).Children(func() {
			ui.Text(c, "多语言生态隔离环境与容器供应链覆盖").FontSize(15).Bold()
			ui.Row(c).Gap(10).Wrap().Children(func() {
				renderPillStat(c, "Python 虚拟环境 (.venv)", ecoAgg.PythonVenvs)
				renderPillStat(c, "Java 工程 (Maven/Gradle)", ecoAgg.JavaProjects)
				renderPillStat(c, "Java JDK 实例", ecoAgg.JavaJDKs)
				renderPillStat(c, "前端工程 (npm/pnpm/yarn)", ecoAgg.NodeProjects)
				renderPillStat(c, "Go 模块 (go.mod)", ecoAgg.GoModules)
				renderPillStat(c, "Rust 工程 (Cargo.lock)", ecoAgg.RustCrates)
				renderPillStat(c, "活跃 Docker 容器", ecoAgg.DockerContainers)
			})
		})
	})
}

func renderKPICard(c *ui.Context, title, val, sub string, valColor ui.Color) {
	t := c.Theme()
	ui.Column(c).Grow(1).Padding(16, 18).Radius(12).Gap(4).
		Background(t.Surface).Border(1, t.Border).
		Children(func() {
			ui.Text(c, title).FontSize(12).TextColor(t.TextMuted)
			ui.Text(c, val).FontSize(28).Bold().TextColor(valColor)
			ui.Text(c, sub).FontSize(11).TextColor(t.TextMuted).SingleLine()
		})
}

func renderPillStat(c *ui.Context, label string, count int) {
	t := c.Theme()
	ui.Row(c).Padding(8, 12).Radius(8).Gap(8).AlignItems(ui.Center).
		Background(t.Background).Border(1, t.Border).
		Children(func() {
			ui.Text(c, label).FontSize(12)
			ui.Badge(c, fmt.Sprint(count)).Background(t.Accent.Alpha(0.15)).TextColor(t.Accent)
		})
}

// ============================================================================
// Page 2: Host Matrix, Hardware Meters, SSH Onboarding & Doctor Diagnostics
// ============================================================================
func (s *AppState) renderHostsAndDoctorPage(c *ui.Context) {
	t := c.Theme()
	ui.Column(c).Fill().Padding(22).Gap(14).Children(func() {
		ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
			ui.Segmented(c.Key("hosts-seg"), &s.HostsSubTab, "主机硬件与安全矩阵", "Doctor 全链路体检").Label("视图切换")
			ui.Spacer(c)
			ui.Button(c.Key("btn-discover-ssh"), "从 ~/.ssh/config 一键导入").OnClick(func() {
				s.OpenSSHOnboardingModalAsync()
			})
			ui.Button(c.Key("btn-add-host"), "手动添加主机").OnClick(func() {
				s.ShowAddModal = true
			})
			ui.PrimaryButton(c.Key("btn-run-doctor"), "运行一键体检").
				Disabled(s.DoctorRunning).
				OnClick(func() { s.StartDoctorAsync() })
		})

		if s.HostsSubTab == 1 {
			s.renderDoctorResults(c)
			return
		}

		ui.Scroll(c.Key("hosts-matrix-scroll")).Grow(1).Gap(12).Children(func() {
			for idx := range s.Report.Hosts {
				h := s.Report.Hosts[idx]
				hKey := firstNonEmptyStr(h.Target.EffectiveKey(), firstNonEmptyStr(h.Host, fmt.Sprint(idx)))
				uniq := fmt.Sprintf("%d-%s", idx, hKey)
				displayName := firstNonEmptyStr(h.Host, firstNonEmptyStr(h.Target.Name, h.Target.SSHHost))

				ui.Column(c.Key("host-card-"+uniq)).
					Padding(16, 20).Radius(12).Gap(10).
					Background(t.Surface).Border(1, t.Border).
					Children(func() {
						ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
							ui.Icon(c, IconServer).FontSize(18).TextColor(t.Accent)
							ui.Text(c, displayName).FontSize(16).Bold()
							if !h.Target.IsLocal() {
								sshLabel := firstNonEmptyStr(h.Target.SSHHost, displayName)
								if h.Target.Port > 0 && h.Target.Port != 22 {
									sshLabel = fmt.Sprintf("%s:%d", sshLabel, h.Target.Port)
								}
								ui.Badge(c, sshLabel)
							}
							if h.OSContext.RebootRequired {
								ui.Badge(c, "待平滑重启").Background(ui.Hex("#f59e0b").Alpha(0.2)).TextColor(ui.Hex("#d97706"))
							}
							ui.Spacer(c)
							if h.LatencyMS > 0 {
								ui.Text(c, fmt.Sprintf("延迟 %dms", h.LatencyMS)).FontSize(12).TextColor(t.TextMuted)
							}
							stBg, stFg := statusColors(h.Status)
							ui.Badge(c, h.Status).Background(stBg).TextColor(stFg)
						})

						metaLine := fmt.Sprintf("系统: %s · 内核: %s · 架构: %s · 包管理器: %s · 已发现资产: %d 项",
							firstNonEmptyStr(h.OSContext.OSPretty, "待探测"),
							firstNonEmptyStr(h.OSContext.KernelRelease, "-"),
							firstNonEmptyStr(h.OSContext.Arch, "-"),
							firstNonEmptyStr(h.OSContext.PkgMgr, "-"),
							max(h.AssetsCount, h.PackagesCount),
						)
						ui.Text(c, metaLine).FontSize(12).TextColor(t.TextMuted)
						ui.Text(c, h.Detail).FontSize(13)

						// OpenWrt / Linux Hardware Safety Headroom Meters
						if h.OSContext.OSFamily == "openwrt" || h.OSContext.IsFlashStorage {
							ui.Row(c).Gap(16).AlignItems(ui.Center).Children(func() {
								ui.Text(c, fmt.Sprintf("可用内存 %.0fMB", h.OSContext.MemAvailableMB)).FontSize(11).TextColor(t.TextMuted)
								ui.Meter(c, h.OSContext.MemAvailableMB, 0, max(128, h.OSContext.MemTotalMB),
									&ui.MeterLevels{Warning: 64, Critical: 32}).Width(140).Label("可用内存")

								ui.Text(c, fmt.Sprintf("Overlay 闪存余量 %.0fMB", h.OSContext.OverlayAvailMB)).FontSize(11).TextColor(t.TextMuted)
								ui.Meter(c, h.OSContext.OverlayAvailMB, 0, max(64, h.OSContext.OverlayTotalMB),
									&ui.MeterLevels{Warning: 50, Critical: 30}).Width(140).Label("Overlay闪存")
							})
						}

						// Host Action Buttons
						ui.Row(c).Gap(8).Children(func() {
							if HasMacOSSystemUpdate(h) {
								ui.PrimaryButton(c.Key("mac-su-"+uniq), "打开 macOS 软件更新").OnClick(func() {
									OpenAppleSoftwareUpdate()
									c.Toast("已为您打开 macOS 系统设置 ➔ 软件更新")
								})
							}
							if len(h.OSSecurity.Updates) > 0 && h.OSSecurity.RemediationPlan.SafeToExecute {
								ui.PrimaryButton(c.Key("fix-h-"+uniq),
									fmt.Sprintf("定向安装系统补丁 (%d)", len(h.OSSecurity.Updates))).
									OnClick(func() {
										s.ApplyHostOSFixesAsync(hKey)
										c.Toast("正在为 " + displayName + " 安装安全补丁…")
									})
							}
							if h.Target.IsLocal() && (len(h.WorkspaceProjects) > 0 || len(h.OrphanedVenvs) > 0) {
								ui.Button(c.Key("ws-h-"+uniq), "查看开发依赖与僵尸清理").OnClick(func() {
									s.ActivePage = "workspace"
								})
							}
							if len(h.Vulnerabilities) > 0 {
								ui.Button(c.Key("tri-h-"+uniq), "前往漏洞手术台").OnClick(func() {
									s.ActivePage = "triage"
								})
							}
							if !h.Target.IsLocal() {
								ui.Button(c.Key("term-h-"+uniq), "").Children(func() {
									ui.Icon(c, IconTerm)
									ui.Text(c, "打开 SSH 终端").SingleLine()
								}).OnClick(func() {
									targetToOpen := h.Target
									if targetToOpen.SSHHost == "" && displayName != "" {
										targetToOpen = config.NormalizeStringHost(displayName)
									}
									termUsed, err := OpenSSHTerminal(targetToOpen, s.PreferredTerminal)
									if err != nil {
										c.Toast("打开终端失败: " + err.Error())
									} else {
										c.Toast(fmt.Sprintf("已在 %s 中打开 %s 会话", termUsed, displayName))
									}
								})
								ui.Spacer(c)
								ui.Button(c.Key("rm-h-"+uniq), "移除纳管").OnClick(func() {
									s.removeHost(hKey, displayName)
									c.Toast("已从守护配置移除 " + displayName)
								})
							}
						})
					})
			}
		})
	})
}

func (s *AppState) renderDoctorResults(c *ui.Context) {
	t := c.Theme()
	if s.DoctorRunning {
		ui.Column(c).Grow(1).Center().Gap(10).Children(func() {
			ui.Spinner(c).Size(28, 28).Label("Doctor running")
			ui.Text(c, "正在并发检验全集群 SSH 免密连通性、提权能力与情报源接口…").TextColor(t.TextMuted)
		})
		return
	}
	if len(s.DoctorItems) == 0 {
		ui.Column(c).Grow(1).Center().Gap(10).Children(func() {
			ui.Text(c, "点击右上角「运行一键体检」对所有主机与环境配置进行全链路诊断").TextColor(t.TextMuted)
		})
		return
	}
	ui.Scroll(c.Key("doctor-scroll")).Grow(1).Gap(8).Children(func() {
		for i, it := range s.DoctorItems {
			badgeBg, badgeFg := ui.Hex("#10b981").Alpha(0.18), ui.Hex("#10b981")
			badgeTxt := "正常"
			if it.Status == "warn" {
				badgeBg, badgeFg = ui.Hex("#f59e0b").Alpha(0.20), ui.Hex("#d97706")
				badgeTxt = "提醒"
			} else if it.Status == "fail" {
				badgeBg, badgeFg = ui.Hex("#ef4444").Alpha(0.20), ui.Hex("#ef4444")
				badgeTxt = "异常"
			}
			ui.Column(c.Key(fmt.Sprintf("doc-%d", i))).Padding(12, 16).Radius(10).Gap(4).
				Background(t.Surface).Border(1, t.Border).
				Children(func() {
					ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
						ui.Badge(c, badgeTxt).Background(badgeBg).TextColor(badgeFg)
						ui.Text(c, it.Name).Bold().Grow(1)
						if it.LatencyMS > 0 {
							ui.Text(c, fmt.Sprintf("%dms", it.LatencyMS)).FontSize(11).TextColor(t.TextMuted)
						}
					})
					ui.Text(c, it.Summary).FontSize(12)
					if it.Suggestion != "" {
						ui.Text(c, "💡 建议: "+it.Suggestion).FontSize(11).TextColor(t.Accent)
					}
				})
		}
	})
}

func (s *AppState) renderSSHOnboardingModal(c *ui.Context) {
	t := c.Theme()
	ui.Modal(c, &s.ShowSSHModal, func() {
		ui.Column(c).Width(580).Gap(12).Children(func() {
			ui.Text(c, "从 ~/.ssh/config 一键导入在线有效服务器").FontSize(18).Bold()
			ui.Text(c, "自动融合 `ssh -G` 真实配置与免密探测 (自动尝试 root@ 回退与隧道握手)，已连接的在线机器实时流式上屏：").
				FontSize(12).TextColor(t.TextMuted)

			if s.SSHProbing {
				ui.Column(c).Padding(10, 12).Radius(8).Gap(6).Background(t.Accent.Alpha(0.10)).Children(func() {
					ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
						ui.Spinner(c).Label("探测 SSH 节点中")
						ui.Text(c, fmt.Sprintf("正在并发探测免密连通性 (%d / %d 已完成，已发现 %d 台在线有效主机)…",
							s.SSHProbeDone, s.SSHProbeTotal, len(s.DiscoveredSSH))).FontSize(12).Bold()
					})
					if s.SSHProbeTotal > 0 {
						ui.Progress(c, float64(s.SSHProbeDone)/float64(max(1, s.SSHProbeTotal))).Label("SSH探测进度")
					}
				})
			}

			if !s.SSHProbing && len(s.DiscoveredSSH) == 0 {
				msg := "未在 ~/.ssh/config 中发现可免密直连的在线服务器，可使用「手动添加主机」。"
				if s.SSHFilteredOutCount > 0 {
					msg = fmt.Sprintf("已自动筛除 %d 个离线或不可免密访问的无效节点，暂无其他可导入节点。", s.SSHFilteredOutCount)
				}
				ui.Text(c, msg).Padding(16, 0).TextColor(t.TextMuted)
			} else if len(s.DiscoveredSSH) > 0 {
				ui.Scroll(c.Key("ssh-modal-scroll")).MaxHeight(300).Gap(6).Children(func() {
					for _, d := range s.DiscoveredSSH {
						alias := d.Alias
						checked := s.SelectedSSH[alias] || d.AlreadyAdded
						row := ui.Row(c.Key("disc-"+alias)).Padding(8, 10).Radius(8).Gap(10).
							Background(t.Surface).Border(1, t.Border).AlignItems(ui.Center)
						row.Children(func() {
							label := fmt.Sprintf("%s (%s@%s)", d.Alias, firstNonEmptyStr(d.User, "root"), d.HostName)
							if d.Port > 0 && d.Port != 22 {
								label += fmt.Sprintf(":%d", d.Port)
							}
							cb := ui.Checkbox(c.Key("cb-"+alias), &checked, label).Disabled(d.AlreadyAdded)
							if cb.Changed() && !d.AlreadyAdded {
								s.SelectedSSH[alias] = checked
							}
							ui.Spacer(c)
							if d.RemoteOS != "" {
								ui.Text(c, fmt.Sprintf("%s · %dms", d.RemoteOS, d.LatencyMS)).FontSize(11).TextColor(t.TextMuted)
							}
							if d.AlreadyAdded {
								ui.Badge(c, "已纳管")
							} else {
								ui.Badge(c, "在线有效").Background(ui.Hex("#10b981").Alpha(0.18)).TextColor(ui.Hex("#10b981"))
							}
						})
					}
				})
				if !s.SSHProbing && s.SSHFilteredOutCount > 0 {
					ui.Text(c, fmt.Sprintf("✨ 检测完毕：共发现 %d 台在线服务器，已自动剔除 %d 个离线、超时或未免密的无效条目",
						len(s.DiscoveredSSH), s.SSHFilteredOutCount)).
						FontSize(11).TextColor(t.TextMuted)
				}
			}

			ui.Row(c).Gap(8).Justify(ui.End).Children(func() {
				if ui.Button(c.Key("ssh-cancel"), "取消").Clicked() {
					s.ShowSSHModal = false
				}
				if ui.PrimaryButton(c.Key("ssh-import"), "导入所选在线主机").Disabled(len(s.DiscoveredSSH) == 0).Clicked() {
					added := 0
					for _, d := range s.DiscoveredSSH {
						if !d.AlreadyAdded && s.SelectedSSH[d.Alias] {
							target := d.ToHostTarget()
							s.Cfg.Hosts = append(s.Cfg.Hosts, config.HostEntry{Target: target})
							s.Report.Hosts = append(s.Report.Hosts, model.HostAuditResult{
								Target:      target,
								Host:        target.Name,
								Status:      model.StatusClean,
								Detail:      "刚导入，等待首次扫描",
								HealthScore: 100,
								LatencyMS:   d.LatencyMS,
								Reachable:   true,
							})
							added++
						}
					}
					if added > 0 {
						saved, _ := config.Save(s.Cfg, s.CfgPath)
						s.CfgPath = saved
						_ = notify.SaveReport(s.Report, "")
						c.Toast(fmt.Sprintf("成功导入 %d 台有效在线主机！", added))
						s.StartAuditAsync(false, false)
					}
					s.ShowSSHModal = false
				}
			})
		})
	})
}

func (s *AppState) renderManualAddHostModal(c *ui.Context) {
	ui.Modal(c, &s.ShowAddModal, func() {
		ui.Column(c).Width(420).Gap(10).Children(func() {
			ui.Text(c, "添加守护主机").FontSize(18).Bold()
			ui.TextInput(c.Key("add-ssh"), &s.NewHostSSH).Placeholder("SSH 地址，如 root@1.2.3.4 或 ubuntu@vps").Label("SSH 地址").AutoFocus()
			ui.TextInput(c.Key("add-name"), &s.NewHostName).Placeholder("可选显示别名，如 生产 Web 节点").Label("显示名称")
			ui.TextInput(c.Key("add-port"), &s.NewHostPortStr).Placeholder("默认 22，非标端口如 2222").Label("SSH 端口")

			ui.Row(c).Gap(8).Justify(ui.End).Children(func() {
				if ui.Button(c.Key("add-cancel"), "取消").Clicked() {
					s.ShowAddModal = false
				}
				if ui.PrimaryButton(c.Key("add-confirm"), "保存并纳管").Disabled(strings.TrimSpace(s.NewHostSSH) == "").Clicked() {
					target := config.NormalizeStringHost(s.NewHostSSH)
					if strings.TrimSpace(s.NewHostName) != "" {
						target.Name = strings.TrimSpace(s.NewHostName)
					}
					if p, err := strconv.Atoi(strings.TrimSpace(s.NewHostPortStr)); err == nil && p > 0 {
						target.Port = p
					}
					target.ID = target.EffectiveKey()
					s.Cfg.Hosts = append(s.Cfg.Hosts, config.HostEntry{Target: target})
					s.Report.Hosts = append(s.Report.Hosts, model.HostAuditResult{
						Target:      target,
						Host:        target.Name,
						Status:      model.StatusClean,
						Detail:      "刚添加，点击巡检采集资产",
						HealthScore: 100,
						Reachable:   true,
					})
					saved, _ := config.Save(s.Cfg, s.CfgPath)
					s.CfgPath = saved
					s.NewHostSSH, s.NewHostName, s.NewHostPortStr = "", "", ""
					s.ShowAddModal = false
					c.Toast("已添加主机 " + target.Name)
				}
			})
		})
	})
}

func (s *AppState) removeHost(hostKey string, displayName string) {
	matchesEntry := func(t model.HostTarget, hostLabel string) bool {
		if t.IsLocal() {
			return false
		}
		if hostKey != "" && (strings.EqualFold(t.EffectiveKey(), hostKey) || strings.EqualFold(t.SSHHost, hostKey) || strings.EqualFold(t.Name, hostKey)) {
			return true
		}
		if displayName != "" && (strings.EqualFold(hostLabel, displayName) || strings.EqualFold(t.Name, displayName) || strings.EqualFold(t.SSHHost, displayName)) {
			return true
		}
		return false
	}

	var nextCfg []config.HostEntry
	for _, e := range s.Cfg.Hosts {
		if !matchesEntry(e.Target, e.Target.Name) {
			nextCfg = append(nextCfg, e)
		}
	}
	s.Cfg.Hosts = nextCfg
	savedPath, err := config.Save(s.Cfg, s.CfgPath)
	if err == nil {
		s.CfgPath = savedPath
		s.Cfg.SourcePath = savedPath
	}

	var nextRep []model.HostAuditResult
	for _, h := range s.Report.Hosts {
		if !matchesEntry(h.Target, h.Host) {
			nextRep = append(nextRep, h)
		}
	}
	s.Report.Hosts = nextRep
	_ = notify.SaveReport(s.Report, "")
}

// ============================================================================
// Page 3: Vulnerability Triage & Side-by-Side GPU Diff Surgery Center
// ============================================================================
func (s *AppState) renderTriageDiffPage(c *ui.Context) {
	t := c.Theme()
	entries := s.FilteredVulnEntries()

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

	ui.Column(c).Fill().Children(func() {
		// Top Filter Toolbar
		ui.Row(c).Padding(12, 20).Gap(10).AlignItems(ui.Center).
			BorderWidth(0, 0, 1, 0).BorderColor(t.Border).
			Children(func() {
				ui.Segmented(c.Key("triage-filter"), &s.TriageFilter,
					"全部待处置", "系统安全更新", "代码与内核 CVE", "已免疫闭环",
				).Label("漏洞筛选")
				ui.Spacer(c)
				ui.Text(c, fmt.Sprintf("共 %d 项条目", len(entries))).FontSize(12).TextColor(t.TextMuted)
			})

		if len(entries) == 0 {
			ui.Column(c).Grow(1).Center().Gap(10).Children(func() {
				ui.Icon(c, IconShield).FontSize(40).TextColor(ui.Hex("#10b981"))
				ui.Text(c, "当前筛选条件下零待处置风险，全集群运行健康！").FontSize(15).Bold()
				ui.Text(c, "可点击左侧或顶部「立即全量巡检」拉取最新 OSV 与内核安全通告").FontSize(12).TextColor(t.TextMuted)
			})
			return
		}

		// Master-Detail Split: Left Vulnerability List | Right Markdown + GPU DiffView
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
				ui.Column(c).Fill().Padding(16, 20).Gap(12).Children(func() {
					// Detail Header & Action Buttons
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
						ui.Button(c.Key("tri-copy-script"), "复制右侧脚本").OnClick(func() {
							if !s.Headless {
								mygo.Clipboard.WriteText(s.DiffState.New.String())
							}
							c.Toast("已复制到剪贴板")
						})
					})

					// Markdown Vulnerability Brief (ui/markdown)
					mdDoc := fmt.Sprintf("**漏洞摘要**: %s\n\n- **状态提示**: %s\n- **安全承诺**: 所有远程变更均配备断网自动秒级回滚与本地熔断保护。",
						firstNonEmptyStr(v.Summary, "详见官方通告"),
						firstNonEmptyStr(v.Reason, firstNonEmptyStr(v.Action, "先审阅下方处方 Diff，确认无误后再执行")),
					)
					ui.Scroll(c.Key("tri-md-scroll")).MaxHeight(115).Padding(10, 14).Radius(10).
						Background(t.Surface).Border(1, t.Border).
						Children(func() {
							markdown.View(c, mdDoc, &s.MDOpts)
						})

					// Side-by-Side GPU Code Diff Viewer (ui/editor.DiffView)
					ui.Row(c).AlignItems(ui.Center).Children(func() {
						ui.Text(c, "处方对比台 (左: 基准状态 / 应急回滚脚本  |  右: 拟执行命令 / 可编辑加固脚本)").
							FontSize(12).Bold().TextColor(t.TextMuted)
					})
					ui.Box(c).Grow(1).FillWidth().Radius(10).Clip().Border(1, t.Border).Children(func() {
						editor.DiffView(c, s.DiffState).Fill()
					})
				})
			},
		).Grow(1).FillWidth()
	})
}

// ============================================================================
// Page 4: Zero-Downtime High Availability (Clash/Mihomo Drain & Rolling Reboot)
// ============================================================================
func (s *AppState) renderZeroDowntimeHAPage(c *ui.Context) {
	t := c.Theme()
	gw := s.Cfg.Gateway

	ui.Column(c).Fill().Padding(22).Gap(14).Children(func() {
		ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
			ui.Column(c).Grow(1).Gap(2).Children(func() {
				ui.Text(c, "零中断旁路切流与平滑滚动重启 (Zero-Downtime HA)").FontSize(18).Bold()
				ui.Text(c, "流量前置排空 ➔ 单机串行重启 ➔ 节点凭据强同步 ➔ 网关热重载探活 (全程防休眠锁保护)").
					FontSize(12).TextColor(t.TextMuted)
			})
			ui.Button(c.Key("ha-probe-gw"), "刷新网关节点延迟").
				Disabled(!gw.Enabled).
				OnClick(func() { s.RefreshHAGatewayAsync() })
			ui.Button(c.Key("ha-reload-gw"), "仅重载网关").
				Disabled(!gw.Enabled || s.HARunning).
				OnClick(func() { s.StartRollingRebootAsync(nil, true) })
			ui.PrimaryButton(c.Key("ha-auto-roll"), "自动检测并滚动重启").
				Disabled(s.HARunning).
				OnClick(func() { s.StartRollingRebootAsync(nil, false) })
		})

		// Gateway Status Card
		ui.Column(c).Padding(16, 20).Radius(12).Gap(8).Background(t.Surface).Border(1, t.Border).Children(func() {
			if !gw.Enabled {
				ui.Text(c, "当前未启用 Clash/Mihomo 网关切流 (gateway.enabled = false)，滚动重启将直接按单机串行模式执行。").
					FontSize(13).TextColor(t.TextMuted)
			} else {
				ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
					ui.Text(c, fmt.Sprintf("边缘路由网关: %s · 策略组 [%s]", gw.ClashAPIURL, gw.SelectorGroup)).Bold().Grow(1)
					if s.GatewayActiveNode != "" {
						ui.Badge(c, "当前承载: "+s.GatewayActiveNode).Background(ui.Hex("#10b981").Alpha(0.18)).TextColor(ui.Hex("#10b981"))
					}
				})
				if len(s.GatewayAllNodes) > 0 {
					ui.Row(c).Gap(8).Wrap().Children(func() {
						for _, n := range s.GatewayAllNodes {
							nodeName := n
							d := s.GatewayNodeDelays[nodeName]
							lbl := nodeName
							if d > 0 {
								lbl = fmt.Sprintf("%s (%dms)", nodeName, d)
							}
							if nodeName == s.GatewayActiveNode {
								ui.PrimaryButton(c.Key("gwn-"+nodeName), lbl).OnClick(func() {})
							} else {
								ui.Button(c.Key("gwn-"+nodeName), lbl).OnClick(func() {})
							}
						}
					})
				}
			}
		})

		// Rolling Nodes Peer Mapping Cards
		if len(s.Cfg.RollingNodes) > 0 {
			ui.Row(c).Gap(10).Wrap().Children(func() {
				for _, rn := range s.Cfg.RollingNodes {
					nodeCfg := rn
					ui.Column(c.Key("rn-"+nodeCfg.ID)).Width(280).Padding(14, 16).Radius(10).Gap(6).
						Background(t.Surface).Border(1, t.Border).
						Children(func() {
							ui.Row(c).AlignItems(ui.Center).Children(func() {
								ui.Text(c, nodeCfg.ID).Bold().Grow(1)
								if nodeCfg.Peer != "" {
									ui.Badge(c, "互备 ⇄ "+nodeCfg.Peer)
								}
							})
							ui.Text(c, "SSH: "+nodeCfg.SSHHost).FontSize(11).TextColor(t.TextMuted)
							ui.Button(c.Key("roll-one-"+nodeCfg.ID), "平滑切流重启此节点").
								Disabled(s.HARunning).
								OnClick(func() {
									s.StartRollingRebootAsync([]string{nodeCfg.ID}, false)
								})
						})
				}
			})
		}

		// Live Streaming HA Event Console
		ui.Text(c, "实时执行流水线日志").FontSize(13).Bold()
		if s.HALogScroll.Y >= s.HALogScroll.MaxY {
			s.HALogScroll.Y = math.MaxFloat32
		}
		ui.Scroll(c.Key("ha-log-scroll")).TrackScroll(&s.HALogScroll).Grow(1).Padding(12, 14).Radius(10).
			Background(t.Surface).Border(1, t.Border).Gap(4).
			Children(func() {
				if len(s.HAEvents) == 0 {
					ui.Text(c, "尚无滚动维护任务运行记录。执行重启期间系统将自动挂载防休眠锁 (Power.KeepAwake)。").
						FontSize(12).TextColor(t.TextMuted)
				}
				for i, ev := range s.HAEvents {
					col := t.Text
					switch ev.Level {
					case "SUCCESS":
						col = ui.Hex("#10b981")
					case "WARN":
						col = ui.Hex("#f59e0b")
					case "ERROR":
						col = ui.Hex("#ef4444")
					}
					ui.Text(c.Key(fmt.Sprintf("ha-ev-%d", i)),
						fmt.Sprintf("[%s] [%s] (%s) %s", ev.Timestamp, ev.Level, ev.NodeID, ev.Message)).
						Font("monospace").FontSize(12).TextColor(col)
				}
			})
	})
}

// ============================================================================
// Page 5: Time Machine Ledger & 1-Click Remote Rollback
// ============================================================================
func (s *AppState) renderHistoryRollbackPage(c *ui.Context) {
	t := c.Theme()
	ui.Column(c).Fill().Padding(22).Gap(14).Children(func() {
		ui.Row(c).AlignItems(ui.Center).Children(func() {
			ui.Column(c).Grow(1).Gap(2).Children(func() {
				ui.Text(c, "修复账本时光机与一键远程回滚").FontSize(18).Bold()
				ui.Text(c, "所有下发至 /etc/sentinel/remediations/ 的规避脚本均永久保留配对回滚能力").
					FontSize(12).TextColor(t.TextMuted)
			})
			ui.Button(c.Key("hist-refresh"), "刷新账本").OnClick(func() {
				s.HistoryItems = s.Mem.ListHistory()
			})
		})

		// Auto-Retirement Prompts when official patches have landed!
		for _, h := range s.Report.Hosts {
			hostCopy := h
			for _, cveID := range hostCopy.RetirableMitigations {
				cid := cveID
				ui.Row(c.Key("retire-"+hostCopy.Target.EffectiveKey()+cid)).
					Padding(12, 16).Radius(10).Gap(10).AlignItems(ui.Center).
					Background(ui.Hex("#f59e0b").Alpha(0.14)).Border(1, ui.Hex("#f59e0b").Alpha(0.4)).
					Children(func() {
						ui.Text(c, fmt.Sprintf("🧹 [%s] 官方补丁已覆盖 %s，建议一键回滚退役此前的临时规避脚本", hostCopy.Host, cid)).
							Grow(1).FontSize(13).Bold()
						ui.PrimaryButton(c.Key("btn-retire-"+hostCopy.Target.EffectiveKey()+cid), "一键清理临时规避").OnClick(func() {
							s.ExecuteRollbackAsync(hostCopy.Target.EffectiveKey(), cid)
							c.Toast("正在清理过时临时规避规则…")
						})
					})
			}
		}

		if len(s.HistoryItems) == 0 {
			ui.Column(c).Grow(1).Center().Gap(8).Children(func() {
				ui.Text(c, "暂无历史修复或现场规避账本记录").FontSize(14).TextColor(t.TextMuted)
			})
			return
		}

		ui.Scroll(c.Key("history-scroll")).Grow(1).Gap(8).Children(func() {
			for i := range s.HistoryItems {
				rec := s.HistoryItems[i]
				ui.Row(c.Key("hist-"+rec.ID)).Padding(14, 18).Radius(10).Gap(12).AlignItems(ui.Center).
					Background(t.Surface).Border(1, t.Border).
					Children(func() {
						ui.Column(c).Grow(1).Gap(4).Children(func() {
							ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
								ui.Badge(c, rec.Kind)
								ui.Text(c, fmt.Sprintf("%s · %s", rec.HostName, rec.CVEID)).Bold()
								ui.Text(c, rec.UpdatedAt).FontSize(11).TextColor(t.TextMuted)
							})
							ui.Text(c, fmt.Sprintf("状态: %s · %s", rec.Status, firstNonEmptyStr(rec.Strategy, rec.Log))).
								FontSize(12).TextColor(t.TextMuted)
						})

						if rec.CanRollback && rec.Status == "success" {
							recCopy := rec
							ui.Button(c.Key("rb-btn-"+rec.ID), "一键远程回滚").OnClick(func() {
								s.PendingRollback = &recCopy
								s.ConfirmRollback = true
							})
						}
					})
			}
		})
	})
}

// ============================================================================
// Page 6: OS Keychain Vault (mygo.Secrets) & Smart Desktop Policies
// ============================================================================
func (s *AppState) renderSettingsVaultPage(c *ui.Context) {
	t := c.Theme()
	ui.Scroll(c.Key("settings-scroll")).Grow(1).Padding(22).Gap(16).Children(func() {
		ui.Row(c).AlignItems(ui.Center).Children(func() {
			ui.Column(c).Grow(1).Gap(2).Children(func() {
				ui.Text(c, "系统钥匙串保险箱与智能守护策略").FontSize(18).Bold()
				ui.Text(c, "所有 API Token 均直接加密托管于操作系统原生钥匙串 (macOS Keychain / Secret Service)，配置文件零明文").
					FontSize(12).TextColor(t.TextMuted)
			})
			ui.PrimaryButton(c.Key("btn-save-settings"), "保存全部设置").OnClick(func() {
				s.SaveSettings()
				c.Toast("设置与钥匙串凭据已安全保存")
			})
		})

		// 0. Version & GitHub Actions Prebuilt Self-Updater Card
		ui.Column(c).Padding(16, 20).Radius(12).Gap(10).Background(t.Surface).Border(1, t.Border).Children(func() {
			ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
				ui.Column(c).Grow(1).Gap(2).Children(func() {
					ui.Text(c, fmt.Sprintf("版本更新与自动升级 (当前版本 v%s)", model.Version)).FontSize(15).Bold()
					sub := firstNonEmptyStr(s.UpdateMessage, "直接从 GitHub Actions 官方 Release 下载预编译包并校验 SHA-256 原子热更新")
					ui.Text(c, sub).FontSize(12).TextColor(t.TextMuted)
				})
				ui.Button(c.Key("btn-chk-upd"), "检查新版本").
					Disabled(s.UpdateChecking || s.UpdateApplying).
					OnClick(func() { s.CheckForUpdatesAsync() })
				if s.LatestRelease != nil && s.LatestRelease.HasUpdate {
					ui.PrimaryButton(c.Key("btn-apply-upd"), "一键升级至 "+s.LatestRelease.TagName).
						Disabled(s.UpdateApplying).
						OnClick(func() { s.ApplySelfUpgradeAsync() })
				}
			})
		})

		// 1. Built-in Smart Scan Schedule & Advisory Time-Window Card
		_, _, nextScanSummary := s.NextScheduledScanInfo(time.Now())
		ui.Column(c).Padding(16, 20).Radius(12).Gap(12).Background(t.Surface).Border(1, t.Border).Children(func() {
			ui.Row(c).AlignItems(ui.Center).Children(func() {
				ui.Text(c, "⏰ 自动巡检频率与情报回溯时间窗").FontSize(15).Bold().Grow(1)
				ui.Badge(c, nextScanSummary).Background(t.Accent.Alpha(0.14)).TextColor(t.Accent)
			})
			ui.Text(c, "由菜单栏哨兵内置协程精准调度（无需外部 launchd 脚本，支持开盖补跑与热点省流保护）：").
				FontSize(12).TextColor(t.TextMuted)

			ui.Row(c).Gap(12).AlignItems(ui.Center).Children(func() {
				ui.Text(c, "自动巡检模式").Grow(1)
				ui.Select(c.Key("sel-scan-mode"), &s.ScanModeLabel,
					[]string{"定频间隔巡检", "每日定点巡检", "仅手动巡检"}).
					Width(180).Label("自动巡检模式")

				if s.ScanModeLabel == "定频间隔巡检" {
					ui.Select(c.Key("sel-scan-iv"), &s.ScanIntervalLabel,
						[]string{"每 4 小时", "每 8 小时", "每 12 小时", "每 24 小时"}).
						Width(150).Label("巡检间隔")
				} else if s.ScanModeLabel == "每日定点巡检" {
					ui.TextInput(c.Key("in-daily-time"), &s.DailyScanTimeStr).
						Placeholder("如 09:00").Width(130).Label("每日巡检时间")
				}
			})

			ui.Row(c).Gap(12).AlignItems(ui.Center).Children(func() {
				ui.Column(c).Grow(1).Gap(2).Children(func() {
					ui.Text(c, "增量漏洞通告回溯时间窗口 (GHSA + Linux CNA)")
					ui.Text(c, "注：Google OSV 存量库、Linux 发行版安全源与 Apple 系统更新始终 100% 全量覆盖，不受此天数限制").
						FontSize(11).TextColor(t.TextMuted)
				})
				ui.Select(c.Key("sel-adv-days"), &s.AdvisoryDaysLabel,
					[]string{"近 1 天", "近 3 天 (推荐)", "近 7 天", "近 14 天", "近 30 天"}).
					Width(180).Label("增量时间窗")
			})
		})

		// 2. Desktop & Smart Power / Network Policies
		ui.Column(c).Padding(16, 20).Radius(12).Gap(12).Background(t.Surface).Border(1, t.Border).Children(func() {
			ui.Text(c, "智能桌面感知与自动化护栏").FontSize(15).Bold()

			ui.Row(c).AlignItems(ui.Center).Children(func() {
				ui.Text(c, "登录系统时自动在右上角菜单栏启动守护哨兵 (Open at Login)").Grow(1)
				ui.Switch(c.Key("sw-login"), &s.OpenAtLogin).Label("开机自启")
			})
			ui.Row(c).AlignItems(ui.Center).Children(func() {
				ui.Text(c, "电脑合盖休眠唤醒后自动检测并补跑错过的每日巡检 (Power.OnResume)").Grow(1)
				ui.Switch(c.Key("sw-power"), &s.SmartPower).Label("唤醒智能补跑")
			})
			ui.Row(c).AlignItems(ui.Center).Children(func() {
				ui.Text(c, "连接手机个人热点时自动启用省流巡检模式 (Network.Metered)").Grow(1)
				ui.Switch(c.Key("sw-hotspot"), &s.RespectHotspot).Label("热点流量保护")
			})
			ui.Row(c).AlignItems(ui.Center).Children(func() {
				ui.Text(c, "巡检时自动无损安装官方安全源补丁 (auto_fix)").Grow(1)
				ui.Switch(c.Key("sw-autofix"), &s.AutoFixEnabled).Label("自动安全补丁")
			})
			ui.Row(c).Gap(12).AlignItems(ui.Center).Children(func() {
				ui.Text(c, "告警降噪推送策略").Grow(1)
				ui.Select(c.Key("sel-notify-pol"), &s.NotifyPolicy, []string{"always", "on_change", "critical_only"}).
					Width(180).Label("推送策略")
			})
			ui.Row(c).Gap(12).AlignItems(ui.Center).Children(func() {
				ui.Text(c, fmt.Sprintf("SSH 终端应用偏好 (auto 当前识别为: %s)", ResolvePreferredTerminal("auto"))).Grow(1)
				ui.Select(c.Key("sel-pref-term"), &s.PreferredTerminal,
					[]string{"auto", "wezterm", "ghostty", "iterm2", "kitty", "alacritty", "terminal"}).
					Width(180).Label("SSH终端偏好")
			})
		})

		// 2. Telegram Secure 6-Digit Pairing & Bot Token
		ui.Column(c).Padding(16, 20).Radius(12).Gap(10).Background(t.Surface).Border(1, t.Border).Children(func() {
			ui.Row(c).AlignItems(ui.Center).Children(func() {
				ui.Text(c, "Telegram 移动端机器人 (防劫持配对绑定)").FontSize(15).Bold().Grow(1)
				ui.Badge(c, "当前状态: "+secrets.Masked(secrets.Get(secrets.KeyTelegramChatID)))
			})
			ui.TextInput(c.Key("in-tg-tok"), &s.TGTokenDraft).Password().
				Placeholder("粘贴新 Bot Token 更新钥匙串 (当前: " + secrets.Masked(secrets.Get(secrets.KeyTelegramBotToken)) + ")").
				Label("Telegram Bot Token")

			ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
				ui.Button(c.Key("btn-gen-pair"), "1. 生成 6 位安全配对码").OnClick(func() {
					s.TGPairCode = notify.GeneratePairCode()
					s.TGPairStatus = fmt.Sprintf("请向您的 Bot 发送数字 【 %s 】，然后点击右侧验证按钮", s.TGPairCode)
				})
				if s.TGPairCode != "" {
					ui.PrimaryButton(c.Key("btn-ver-pair"), "2. 我已发送，立即验证绑定").OnClick(func() {
						tok := strings.TrimSpace(s.TGTokenDraft)
						if tok == "" {
							tok = secrets.Get(secrets.KeyTelegramBotToken)
						}
						go func() {
							ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
							defer cancel()
							cid, who, err := notify.VerifyTelegramPairCode(ctx, tok, s.TGPairCode)
							s.uiSync(func() {
								if err != nil {
									s.TGPairStatus = "验证未通过: " + err.Error()
								} else {
									s.TGTokenDraft = ""
									s.TGPairCode = ""
									s.TGPairStatus = fmt.Sprintf("🎉 绑定成功！Chat ID: %s (%s) 已锁入系统钥匙串", cid, who)
								}
							})
						}()
					})
				}
				ui.Button(c.Key("btn-test-tg"), "发送测试卡片").OnClick(func() {
					go func() {
						ok, err := notify.SendTelegram(context.Background(), "🛡️ <b>Security-Sentinel v2.0</b> 桌面端测试推送正常！", "", "")
						s.uiSync(func() {
							if err != nil {
								s.TGPairStatus = "发送失败: " + err.Error()
							} else if !ok {
								s.TGPairStatus = "请先配置 Bot Token 并完成配对绑定"
							} else {
								s.TGPairStatus = "✅ 测试卡片已成功送达您的手机 Telegram！"
							}
						})
					}()
				})
			})
			if s.TGPairStatus != "" {
				ui.Text(c, s.TGPairStatus).FontSize(12).TextColor(t.Accent)
			}
		})

		// 3. AI Provider & GitHub / Clash Keychain Vault
		ui.Column(c).Padding(16, 20).Radius(12).Gap(10).Background(t.Surface).Border(1, t.Border).Children(func() {
			ui.Text(c, "多模型 AI 自愈引擎与第三方接口钥匙串").FontSize(15).Bold()
			ui.Row(c).AlignItems(ui.Center).Children(func() {
				ui.Text(c, "启用无官方补丁高危漏洞的 AI 现场规避研判").Grow(1)
				ui.Switch(c.Key("sw-ai-en"), &s.AIEnabled).Label("启用 AI 研判")
			})
			ui.Row(c).AlignItems(ui.Center).Children(func() {
				ui.Text(c, "允许 AI 方案通过静态门禁后全自动下发 (关闭则在手术台等待人工批准)").Grow(1)
				ui.Switch(c.Key("sw-ai-auto"), &s.AIAutoExec).Label("自动下发 AI 脚本")
			})
			ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
				ui.Text(c, "AI 推理后端").Width(110)
				ui.Select(c.Key("sel-ai-prov"), &s.AIProvider, []string{"gemini", "agy", "openai", "anthropic", "auto"}).
					Width(160).Label("AI Provider")
				ui.TextInput(c.Key("in-ai-model"), &s.AIModel).Placeholder("如 gemini-2.5-flash").Grow(1).Label("AI 模型")
			})

			ui.TextInput(c.Key("in-gemini-k"), &s.GeminiKeyDraft).Password().
				Placeholder("Google Gemini API Key (当前: " + secrets.Masked(secrets.Get(secrets.KeyGeminiAPIKey)) + ")").Label("Gemini Key")
			ui.TextInput(c.Key("in-openai-k"), &s.OpenAIKeyDraft).Password().
				Placeholder("OpenAI / 兼容 API Key (当前: " + secrets.Masked(secrets.Get(secrets.KeyOpenAIAPIKey)) + ")").Label("OpenAI Key")
			ui.TextInput(c.Key("in-anth-k"), &s.AnthropicKeyDraft).Password().
				Placeholder("Anthropic Claude API Key (当前: " + secrets.Masked(secrets.Get(secrets.KeyAnthropicAPIKey)) + ")").Label("Anthropic Key")
			ui.TextInput(c.Key("in-gh-tok"), &s.GHTokenDraft).Password().
				Placeholder("GitHub Token 提升配额至 5000次/h (当前: " + secrets.Masked(secrets.Get(secrets.KeyGitHubToken)) + ")").Label("GitHub Token")
			ui.TextInput(c.Key("in-clash-sec"), &s.ClashSecretDraft).Password().
				Placeholder("Clash / Mihomo REST API Secret (当前: " + secrets.Masked(secrets.Get(secrets.KeyClashAPISecret)) + ")").Label("Clash Secret")
		})
	})
}
