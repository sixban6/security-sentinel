package gui

import (
	"fmt"
	"runtime"
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
	"github.com/sixban6/security-sentinel/internal/infra/model"
)

// FlyoutView builds the native GPU Menu Bar Sentinel popover (380x490).
func (s *AppState) FlyoutView(c *ui.Context) {
	t := c.Theme()
	c.Root().Background(ui.Transparent)

	root := ui.Column(c).Fill()
	switch {
	case c.Vibrancy():
		// Frosted native macOS popover material shines through
	case runtime.GOOS == "windows":
		root.Background(t.Surface)
	default:
		root.Background(t.Background).Radius(12).Border(1, t.Border)
	}

	posture := s.ClusterPosture()
	scoreColor := ui.Hex("#10b981")
	switch posture {
	case "danger":
		scoreColor = ui.Hex("#ef4444")
	case "warn":
		scoreColor = ui.Hex("#f59e0b")
	}

	totalUnmit, osUpdates, retirable := s.PendingCounts()

	root.Padding(16).Gap(10).Children(func() {
		// 1. Header Row: Brand + Cluster Health Score + Quick Scan Button
		ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
			ui.Icon(c, IconShield).FontSize(22).TextColor(scoreColor)
			ui.Column(c).Grow(1).Gap(2).Children(func() {
				ui.Row(c).Gap(6).AlignItems(ui.Center).Children(func() {
					ui.Text(c, "Security Sentinel").FontSize(15).Bold()
					ui.Badge(c, fmt.Sprintf("%d分", s.Report.ClusterScore)).
						Background(scoreColor.Alpha(0.18)).TextColor(scoreColor)
				})
				_, _, schedDesc := s.NextScheduledScanInfo(time.Now())
				subText := schedDesc
				if s.MeteredNetwork {
					subText = "热点省流守护 · " + schedDesc
				}
				ui.Text(c, subText).FontSize(11).TextColor(t.TextMuted).SingleLine()
			})

			if s.Scanning {
				ui.Row(c).Gap(6).AlignItems(ui.Center).Children(func() {
					ui.Spinner(c).Label("巡检中")
					ui.Text(c, fmt.Sprintf("%d/%d", s.ScanStep, s.ScanTotal)).FontSize(11).TextColor(t.TextMuted)
				})
			} else {
				ui.PrimaryButton(c.Key("flyout-scan"), "立即巡检").OnClick(func() {
					s.StartAuditAsync(s.AutoFixEnabled, s.AIEnabled)
				})
			}
		})

		if s.Scanning && s.ScanMessage != "" {
			ui.Progress(c, float64(s.ScanStep)/float64(max(1, s.ScanTotal))).Label("巡检进度")
			ui.Text(c, s.ScanMessage).SingleLine().FontSize(11).TextColor(t.TextMuted)
		}

		// 2. Actionable Quick Remediation Banner (only shown when attention is needed)
		if !s.Scanning && (osUpdates > 0 || totalUnmit > 0 || retirable > 0) {
			banner := ui.Column(c).Padding(10, 12).Radius(10).Gap(6).
				Background(scoreColor.Alpha(0.12)).Border(1, scoreColor.Alpha(0.35))
			banner.Children(func() {
						if osUpdates > 0 {
					ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
						ui.Text(c, fmt.Sprintf("发现 %d 项官方安全补丁可无损升级", osUpdates)).Grow(1).FontSize(12).Bold()
						ui.PrimaryButton(c.Key("flyout-fix-os"), "一键修复").
							Disabled(s.FixingHost != "").
							OnClick(func() { s.ApplyHostOSFixesAsync("") })
					})
				} else if totalUnmit > 0 {
					hasMacOSUpd := len(s.Report.Hosts) > 0 && HasMacOSSystemUpdate(s.Report.Hosts[0])
					ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
						if hasMacOSUpd && totalUnmit == 1 {
							ui.Text(c, "检测到 Apple macOS 系统安全更新").Grow(1).FontSize(12).Bold()
							ui.PrimaryButton(c.Key("flyout-open-macsu"), "系统更新").OnClick(func() {
								OpenAppleSoftwareUpdate()
							})
						} else {
							ui.Text(c, fmt.Sprintf("检测到 %d 项待处置安全项", totalUnmit)).Grow(1).FontSize(12).Bold()
							ui.Button(c.Key("flyout-open-triage"), "审阅处方").OnClick(func() {
								s.OpenMissionControl("triage")
							})
						}
					})
				} else if retirable > 0 {
					ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
						ui.Text(c, fmt.Sprintf("%d 项临时规避规则已可退役清理", retirable)).Grow(1).FontSize(12)
						ui.Button(c.Key("flyout-open-hist"), "去清理").OnClick(func() {
							s.OpenMissionControl("history")
						})
					})
				}
			})
		}

		ui.Divider(c)

		// 3. Scrollable Compact Host Matrix
		ui.Scroll(c.Key("flyout-hosts-scroll")).Grow(1).Gap(8).Children(func() {
			for i := range s.Report.Hosts {
				h := s.Report.Hosts[i]
				cardKey := fmt.Sprintf("fh-%d-%s", i, firstNonEmptyStr(h.Target.EffectiveKey(), h.Host))
				card := ui.Column(c.Key(cardKey)).
					Padding(10, 12).Radius(10).Gap(4).
					Background(t.Surface.Alpha(0.82)).Border(1, t.Border).
					Cursor(ui.CursorPointer)
				if card.Hovered() {
					card.Background(t.SurfaceHover)
				}
				card.OnClick(func() {
					targetPage := "hosts"
					if len(h.Vulnerabilities) > 0 {
						targetPage = "triage"
					}
					s.OpenMissionControl(targetPage)
				})
				card.Children(func() {
					ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
						hostTitle := firstNonEmptyStr(h.Host, h.Target.Name)
						ui.Text(c, hostTitle).Grow(1).FontSize(13).Bold().SingleLine()
						if h.LatencyMS > 0 {
							ui.Text(c, fmt.Sprintf("%dms", h.LatencyMS)).FontSize(11).TextColor(t.TextMuted)
						}
						stBg, stFg := statusColors(h.Status)
						ui.Badge(c, h.Status).Background(stBg).TextColor(stFg)
					})
					sub := h.Detail
					if h.OSContext.OSPretty != "" {
						sub = h.OSContext.OSPretty + " · " + h.Detail
					}
					ui.Text(c, sub).SingleLine().FontSize(11).TextColor(t.TextMuted)
				})
			}
		})

		ui.Divider(c)

		// 4. Footer Bar
		ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
			ui.Button(c.Key("flyout-open-main"), "打开全景指挥台").OnClick(func() {
				s.OpenMissionControl("overview")
			})
			ui.Spacer(c)
			ui.Button(c.Key("flyout-settings"), "设置").OnClick(func() {
				s.OpenMissionControl("settings")
			})
			if !s.Headless {
				ui.Button(c.Key("flyout-quit"), "退出").OnClick(mygo.App.Quit)
			}
		})
	})
}

func statusColors(status string) (bg ui.Color, fg ui.Color) {
	switch status {
	case model.StatusClean:
		return ui.Hex("#10b981").Alpha(0.18), ui.Hex("#10b981")
	case model.StatusImmunized:
		return ui.Hex("#3b82f6").Alpha(0.18), ui.Hex("#3b82f6")
	case model.StatusPendingUpdate, model.StatusAwaitingPatch:
		return ui.Hex("#f59e0b").Alpha(0.20), ui.Hex("#d97706")
	default:
		return ui.Hex("#ef4444").Alpha(0.20), ui.Hex("#ef4444")
	}
}
