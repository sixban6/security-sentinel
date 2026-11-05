package gui

import (
	"context"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
	"github.com/sixban6/security-sentinel/internal/infra/config"
	"github.com/sixban6/security-sentinel/internal/ops/notify"
	"github.com/sixban6/security-sentinel/internal/ops/scheduler"
	"github.com/sixban6/security-sentinel/internal/infra/secrets"
	"github.com/sixban6/security-sentinel/internal/infra/transport"
)

type mygoSecretsAdapter struct{}

func (mygoSecretsAdapter) Get(key string) (string, error) {
	b, err := mygo.Secrets.Service(secrets.ServiceName).Get(key)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (mygoSecretsAdapter) Set(key, val string) error {
	return mygo.Secrets.Service(secrets.ServiceName).Set(key, []byte(val))
}

func (mygoSecretsAdapter) Delete(key string) error {
	return mygo.Secrets.Service(secrets.ServiceName).Delete(key)
}

// RunDesktopApp launches the native GPU Menu Bar Sentinel + Mission Control application.
func RunDesktopApp(cfgPath string, openMainImmediately bool) error {
	transport.EnsureStandardUserPATH()
	if !mygo.App.RequestSingleInstanceLock() {
		return nil
	}

	// Automatically retire any leftover v1 macOS launchd plist so there is never dual-scheduler conflict!
	_ = scheduler.RetireLegacyMacOSLaunchd()

	secrets.RegisterNativeBackend(mygoSecretsAdapter{})
	s := NewAppState(cfgPath, false)

	mygo.App.SetName("Security Sentinel")
	if runtime.GOOS == "darwin" && !openMainImmediately {
		mygo.App.SetActivationPolicy(mygo.ActivationPolicyAccessory)
	}

	// Keep running in the menu bar when Mission Control window is closed!
	mygo.App.OnWindowAllClosed(func() {})
	mygo.App.OnBeforeQuit(func(*mygo.QuitEvent) {
		s.IsQuitting = true
	})
	mygo.App.OnSecondInstance(func(args []string, _ string) {
		s.OpenMissionControl("overview")
	})
	mygo.App.OnActivate(func(hasVisibleWindows bool) {
		if !hasVisibleWindows {
			s.OpenMissionControl("overview")
		}
	})
	mygo.App.OnDidBecomeActive(func() {
		if mygo.NotificationsSupported() {
			mygo.ClearNotifications()
		}
	})

	// Click on any desktop notification opens Mission Control directly at Triage / Overview!
	mygo.App.OnNotificationClick(func(id string) {
		if strings.HasPrefix(id, "vuln:") || s.ClusterPosture() != "clean" {
			s.OpenMissionControl("triage")
		} else {
			s.OpenMissionControl("overview")
		}
	})

	notify.RegisterDesktopHook(func(id, title, subtitle, body string) {
		if !mygo.NotificationsSupported() {
			return
		}
		n := mygo.NewNotification(mygo.NotificationOptions{
			ID:       firstNonEmptyStr(id, "sentinel-audit"),
			Group:    "security-sentinel",
			Title:    title,
			Subtitle: subtitle,
			Body:     body,
		})
		n.OnClick(func() {
			if s.ClusterPosture() != "clean" {
				s.OpenMissionControl("triage")
			} else {
				s.OpenMissionControl("overview")
			}
			n.Close()
		})
		_ = n.Show()
	})

	mygo.App.WhenReady(func() {
		s.OpenAtLogin = mygo.App.OpenAtLogin()
		netSt := mygo.Network.Status()
		s.Online = netSt.Online
		s.MeteredNetwork = netSt.Metered

		s.setupTray()
		s.setupSmartLifecycle()

		// Open Mission Control immediately if launched explicitly with --window or no config exists yet
		if openMainImmediately || s.CfgPath == "" && !mygo.App.WasOpenedAtLogin() {
			s.OpenMissionControl("overview")
		}

		// Trigger initial gateway status refresh & first background scan if stale
		if s.Cfg.Gateway.Enabled {
			s.RefreshHAGatewayAsync()
		}
		if _, dueNow, _ := s.NextScheduledScanInfo(time.Now()); dueNow {
			s.StartAuditAsync(s.AutoFixEnabled, s.AIEnabled)
		}
	})

	return mygo.App.Run()
}

func (s *AppState) setupTray() {
	posture := s.ClusterPosture()
	useTemplate := runtime.GOOS == "darwin" && posture == "clean"
	tray, err := mygo.NewTray(mygo.TrayOptions{
		Icon:           RenderShieldPNG(64, posture, useTemplate),
		IconIsTemplate: useTemplate,
		ToolTip:        fmt.Sprintf("Security Sentinel — 健康分 %d/100", s.Report.ClusterScore),
	})
	if err != nil {
		// Fallback if desktop lacks system tray: open main window directly
		s.OpenMissionControl("overview")
		return
	}
	s.Tray = tray
	s.refreshTrayAppearance()

	menu := s.buildTrayMenu()
	if runtime.GOOS == "linux" {
		s.Tray.SetMenu(menu)
	} else {
		s.Tray.OnClick(s.ToggleFlyout)
		s.Tray.OnRightClick(func() {
			if s.FlyoutWin != nil {
				s.FlyoutWin.Close()
			}
			m := s.buildTrayMenu()
			s.Tray.SetMenu(m)
			defer s.Tray.SetMenu(nil)
			s.Tray.PopUpMenu()
		})
	}

	// Global hotkey Cmd+Shift+S / Ctrl+Shift+S toggles Menu Bar Flyout from anywhere!
	_ = mygo.GlobalShortcut.Register("CmdOrCtrl+Shift+S", func() {
		s.ToggleFlyout()
	})

	mygo.App.OnWillQuit(func(*mygo.QuitEvent) {
		mygo.GlobalShortcut.UnregisterAll()
		if s.Tray != nil {
			s.Tray.Destroy()
		}
	})
}

func (s *AppState) buildTrayMenu() *mygo.Menu {
	return mygo.NewMenu([]*mygo.MenuItem{
		{
			Label: fmt.Sprintf("集群安全健康分: %d / 100", s.Report.ClusterScore),
			Click: func(*mygo.MenuItem, *mygo.Window) { s.OpenMissionControl("overview") },
		},
		mygo.Separator(),
		{
			Label: "立即执行全量巡检",
			Click: func(*mygo.MenuItem, *mygo.Window) { s.StartAuditAsync(s.AutoFixEnabled, s.AIEnabled) },
		},
		{
			Label: "打开全景安全指挥台",
			Click: func(*mygo.MenuItem, *mygo.Window) { s.OpenMissionControl("overview") },
		},
		{
			Label: "打开漏洞审阅手术台",
			Click: func(*mygo.MenuItem, *mygo.Window) { s.OpenMissionControl("triage") },
		},
		{
			Label: "钥匙串与偏好设置…",
			Click: func(*mygo.MenuItem, *mygo.Window) { s.OpenMissionControl("settings") },
		},
		{
			Label: "检查新版本更新…",
			Click: func(*mygo.MenuItem, *mygo.Window) {
				s.OpenMissionControl("settings")
				s.CheckForUpdatesAsync()
			},
		},
		mygo.Separator(),
		{Role: mygo.RoleQuit, Label: "退出 Security Sentinel"},
	})
}

func (s *AppState) refreshTrayAppearance() {
	if s.Tray == nil || s.Headless {
		return
	}
	posture := s.ClusterPosture()
	useTemplate := runtime.GOOS == "darwin" && posture == "clean" && !s.Scanning
	_ = s.Tray.SetIcon(RenderShieldPNG(64, posture, useTemplate), useTemplate)

	unmit, _, _ := s.PendingCounts()
	switch {
	case s.Scanning:
		s.Tray.SetTitle(" …")
		s.Tray.SetToolTip("Security Sentinel — 正在巡检集群安全状态…")
	case unmit > 0:
		s.Tray.SetTitle(fmt.Sprintf(" %d", unmit))
		s.Tray.SetToolTip(fmt.Sprintf("Security Sentinel — %d 项待处置风险 (健康分 %d/100)", unmit, s.Report.ClusterScore))
	default:
		s.Tray.SetTitle("")
		s.Tray.SetToolTip(fmt.Sprintf("Security Sentinel — 全集群安全 (%d/100)", s.Report.ClusterScore))
	}
}

// ToggleFlyout opens or dismisses the frosted Menu Bar Flyout popover.
func (s *AppState) ToggleFlyout() {
	if s.FlyoutWin != nil {
		s.FlyoutWin.Close()
		s.FlyoutWin = nil
		return
	}
	if s.Tray == nil {
		s.OpenMissionControl("overview")
		return
	}
	s.FlyoutWin = mygo.NewFlyout(mygo.FlyoutOptions{
		Tray:      s.Tray,
		Placement: mygo.PlacementBottom,
		Gap:       4,
		Width:     390,
		Height:    480,
		Focusable: true,
		Shadow:    true,
		Popover:   true,
		Content:   ui.View(s.FlyoutView),
	})
	s.FlyoutWin.OnClosed(func() {
		s.FlyoutWin = nil
	})
}

// OpenMissionControl opens (or focuses) the full Mission Control window and navigates to page.
func (s *AppState) OpenMissionControl(page string) {
	if page != "" {
		s.ActivePage = page
	}
	if s.Headless {
		return
	}
	if s.FlyoutWin != nil {
		s.FlyoutWin.Close()
		s.FlyoutWin = nil
	}
	if runtime.GOOS == "darwin" {
		mygo.App.SetActivationPolicy(mygo.ActivationPolicyRegular)
	}
	if s.MainWin != nil {
		s.MainWin.Show()
		s.MainWin.Focus()
		s.MainWin.Invalidate()
		return
	}

	s.MainWin = mygo.NewWindow(mygo.WindowOptions{
		Title:     "Security Sentinel — 全景安全指挥台",
		Width:     1140,
		Height:    740,
		MinWidth:  900,
		MinHeight: 600,
		Content:   ui.View(s.MissionControlView),
	})
	s.MainWin.OnClose(func(e *mygo.CloseEvent) {
		if !s.IsQuitting {
			e.PreventDefault()
			s.MainWin.Hide()
			if runtime.GOOS == "darwin" {
				mygo.App.SetActivationPolicy(mygo.ActivationPolicyAccessory)
			}
		}
	})
	s.MainWin.OnClosed(func() {
		s.MainWin = nil
	})
}

func (s *AppState) setupSmartLifecycle() {
	// 1. Live Network & Metered Hotspot Watcher
	mygo.Network.OnChanged(func(st mygo.NetworkStatus) {
		s.Online = st.Online
		s.MeteredNetwork = st.Metered
		if s.MainWin != nil {
			s.MainWin.Invalidate()
		}
	})

	// 2. Wake-from-Sleep Missed Audit Catch-Up (Power.OnResume)
	mygo.Power.OnResume(func() {
		if !s.SmartPower || s.Scanning {
			return
		}
		if _, dueNow, _ := s.NextScheduledScanInfo(time.Now()); !dueNow {
			return
		}
		go func() {
			for i := 0; i < 10; i++ {
				if mygo.Network.Status().Online {
					break
				}
				time.Sleep(500 * time.Millisecond)
			}
			if !mygo.Network.Status().Online {
				return
			}
			s.uiSync(func() {
				if _, stillDue, _ := s.NextScheduledScanInfo(time.Now()); stillDue && !s.Scanning {
					s.StartAuditAsync(s.AutoFixEnabled, s.AIEnabled)
				}
			})
		}()
	})

	// 3. Real-time File Watcher: CLI `security-sentinel audit` immediately syncs GUI & Tray!
	watchCtx := context.Background()
	stateDir := config.StateDir()
	if w, err := mygo.WatchFiles(watchCtx, stateDir, mygo.FileWatchOptions{}); err == nil {
		go func() {
			defer w.Close()
			for {
				evs, err := w.Next(watchCtx)
				if err != nil {
					return
				}
				for _, ev := range evs {
					if filepath.Base(ev.Path) == "latest_status.json" || ev.Path == "." {
						if rep, err := notify.LoadReport(""); err == nil && len(rep.Hosts) > 0 {
							hist := s.Mem.ListHistory()
							s.uiSync(func() {
								if !s.Scanning {
									s.Report = reconcileReportWithConfig(rep, s.Cfg)
									s.HistoryItems = hist
									if t, err := time.Parse(time.RFC3339, rep.Timestamp); err == nil {
										s.LastScanAt = t
									}
								}
							})
						}
					}
				}
			}
		}()
	}

	// 4. Precision 1-minute background scheduler while resident in menu bar
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for now := range ticker.C {
			if s.Scanning || !mygo.Network.Status().Online {
				continue
			}
			if _, dueNow, _ := s.NextScheduledScanInfo(now); dueNow {
				s.uiSync(func() {
					if !s.Scanning {
						s.StartAuditAsync(s.AutoFixEnabled, s.AIEnabled)
					}
				})
			}
		}
	}()
}
