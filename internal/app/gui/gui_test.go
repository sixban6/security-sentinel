package gui

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/egoist/mygo/ui"
	"github.com/sixban6/security-sentinel/internal/infra/model"
)

func TestFlyoutAndMissionControlViewsRenderAndNavigateCleanly(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SENTINEL_DISABLE_KEYCHAIN", "1")

	state := NewAppState("", true)
	state.Report = model.AuditReport{
		ClusterScore:    82,
		AdvisoriesCount: 14,
		Hosts: []model.HostAuditResult{
			{
				Target:      model.HostTarget{ID: "local", Name: "本机研发环境", Type: "local"},
				Host:        "本机研发环境",
				Status:      model.StatusClean,
				Detail:      "系统与运行态服务 100% 安全",
				HealthScore: 100,
				AssetsCount: 128,
				LatencyMS:   4,
				OSContext:   model.OSContext{OSFamily: "darwin", OSPretty: "macOS 15.3", Arch: "arm64"},
				WorkspaceProjects: []model.WorkspaceProjectAudit{
					{
						ProjectName:  "proj-older-created",
						ProjectDir:   "/tmp/proj-older-created",
						ManifestKind: "maven",
						ModifiedUnix: 1700001000,
						CreatedUnix:  1600000000,
						TotalCVEs:    2,
						Packages: []model.WorkspacePackageFix{
							{Package: "org.apache.logging.log4j:log4j-core", InstalledVersion: "2.13.3", FixedVersion: "2.17.1", Severity: "CRITICAL", CVEIDs: []string{"CVE-2021-44228"}, UpgradeCmd: "mvn versions:use-dep-version"},
						},
					},
					{
						ProjectName:  "demo-ai",
						ProjectDir:   "/tmp/demo-ai",
						ManifestKind: "uv",
						ModifiedUnix: 1700002000,
						CreatedUnix:  1650000000,
						TotalCVEs:    3,
						Packages: []model.WorkspacePackageFix{
							{Package: "httpx", InstalledVersion: "0.22.0", FixedVersion: "0.28.1", Severity: "HIGH", CVEIDs: []string{"CVE-2021-41945"}, UpgradeCmd: "uv lock --upgrade-package httpx"},
						},
					},
				},
				OrphanedVenvs: []model.OrphanedVenv{
					{Name: "old-proj-1234abcd", Path: "/tmp/old-proj-1234abcd", SizeMB: 120.5, Reason: "原项目目录已删除"},
				},
				Reachable: true,
			},
			{
				Target:      model.HostTarget{ID: "root@node-alpha", Name: "新加坡节点", Type: "remote", SSHHost: "root@node-alpha"},
				Host:        "新加坡节点",
				Status:      model.StatusVulnerable,
				Detail:      "命中 1 项高危风险: CVE-2025-40001 linux(6.1.120)",
				HealthScore: 64,
				AssetsCount: 310,
				LatencyMS:   42,
				OSContext:   model.OSContext{OSFamily: "debian", OSPretty: "Debian 12", KernelRelease: "6.1.120", Arch: "x86_64"},
				Vulnerabilities: []model.VulnerabilityMatch{
					{
						ID:               "CVE-2025-40001",
						CVE:              "CVE-2025-40001",
						Package:          "linux",
						InstalledVersion: "6.1.120",
						FixedVersion:     "6.1.130",
						Severity:         "CRITICAL",
						Summary:          "TCP SYN use-after-free in Linux kernel",
						MitigateScript:   "#!/bin/sh\nsysctl -w net.ipv4.tcp_syncookies=1",
						RollbackScript:   "#!/bin/sh\nsysctl -w net.ipv4.tcp_syncookies=1",
						Strategy:         "Enable strict TCP syncookies",
					},
				},
				RetirableMitigations: []string{"CVE-2024-9999"},
				Reachable:            true,
			},
		},
	}

	state.DailyAdvisories = map[string]model.Advisory{
		"CVE-2026-9901": {
			ID:        "CVE-2026-9901",
			CVEID:     "CVE-2026-9901",
			Category:  "kernel",
			Ecosystem: model.EcoLinux,
			Severity:  "CRITICAL",
			CVSS:      9.8,
			Package:   "linux",
			Summary:   "RCU UAF in coredump",
		},
	}

	// 1. Test Menu Bar Flyout View
	ft := ui.NewTester(state.FlyoutView, 390, 480)
	if !ft.HasText("Security Sentinel") || !ft.HasText("新加坡节点") || !ft.HasText("82分") {
		t.Fatalf("FlyoutView missing expected elements, texts=%v", ft.Texts())
	}

	// 2. Test Mission Control Main Window across all 6 Sidebar Tabs!
	mt := ui.NewTester(state.MissionControlView, 1140, 740)
	if !mt.HasText("集群安全健康分") {
		t.Fatalf("Overview page failed to render: %v", mt.Texts())
	}

	// Navigate to Triage & Diff Surgery Center
	if err := mt.Click("漏洞审阅手术台"); err != nil {
		t.Fatalf("click triage tab: %v", err)
	}
	if !mt.HasText("处方对比台") || !mt.HasText("批准并远程执行") {
		t.Fatalf("Triage & DiffView page missing surgical controls: %v", mt.Texts())
	}

	// Navigate to Daily Latest CVE Intelligence Center
	if err := mt.Click("每日最新 CVE"); err != nil {
		t.Fatalf("click cves tab: %v", err)
	}
	if !mt.HasText("CVE-2026-9901") || !mt.HasText("推送分类日报至 Telegram") {
		t.Fatalf("Daily CVE page missing advisory card or Telegram push button: %v", mt.Texts())
	}

	// Navigate to Workspace Dependencies & Orphaned Venv Cleaner
	if err := mt.Click("开发依赖与清理"); err != nil {
		t.Fatalf("click workspace tab: %v", err)
	}
	if !mt.HasText("一键升级全部项目 (2)") || !mt.HasText("一键升级本项目") || !mt.HasText("删除本项目") || !mt.HasText("old-proj-1234abcd") {
		t.Fatalf("Workspace page missing batch upgrade, trash button, or orphan cleaner: %v", mt.Texts())
	}

	// Navigate to Hosts & Doctor
	if err := mt.Click("主机矩阵与体检"); err != nil {
		t.Fatalf("click hosts tab: %v", err)
	}
	if !mt.HasText("从 ~/.ssh/config 一键导入") {
		t.Fatalf("Hosts page missing SSH onboarding button: %v", mt.Texts())
	}

	// Navigate to Zero-Downtime HA
	if err := mt.Click("零中断切流重启"); err != nil {
		t.Fatalf("click HA tab: %v", err)
	}
	if !mt.HasText("实时执行流水线日志") {
		t.Fatalf("HA page failed to render: %v", mt.Texts())
	}

	// Navigate to History & Time Machine (check retirable prompt!)
	if err := mt.Click("时光机与回滚"); err != nil {
		t.Fatalf("click History tab: %v", err)
	}
	if !mt.HasText("一键清理临时规避") {
		t.Fatalf("History page missing auto-retire banner: %v", mt.Texts())
	}

	// Navigate to Keychain Vault & Settings
	if err := mt.Click("钥匙串与智能策略"); err != nil {
		t.Fatalf("click Settings tab: %v", err)
	}
	if !mt.HasText("1. 生成 6 位安全配对码") || !mt.HasText("自动巡检模式") || !mt.HasText("增量漏洞通告回溯时间窗口") {
		t.Fatalf("Settings page missing pairing flow or visual schedule controls: %v", mt.Texts())
	}
}

func TestRenderShieldPNGProducesValidPNG(t *testing.T) {
	for _, p := range []string{"clean", "warn", "danger"} {
		pngBytes := RenderShieldPNG(64, p, false)
		if len(pngBytes) < 100 {
			t.Fatalf("expected non-empty PNG for posture %s", p)
		}
	}
}

func TestLegacyStatusReconciliationImmediateRemoveAndGeminiDefault(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(tmpHome, ".config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(tmpHome, ".local", "state"))
	t.Setenv("SENTINEL_DISABLE_KEYCHAIN", "1")

	// Write sentinel.yaml with 2 remote hosts
	cfgDir := filepath.Join(tmpHome, ".config", "sentinel")
	_ = os.MkdirAll(cfgDir, 0o755)
	cfgFile := filepath.Join(cfgDir, "sentinel.yaml")
	_ = os.WriteFile(cfgFile, []byte("hosts:\n  - root@vps_alpha\n  - root@vps_beta\n"), 0o600)

	// Write legacy v1 latest_status.json using `"name"` without `"host"` or `"target"`!
	legacyDir := filepath.Join(tmpHome, ".gemini", "logs", "security_audit")
	_ = os.MkdirAll(legacyDir, 0o755)
	_ = os.WriteFile(filepath.Join(legacyDir, "latest_status.json"), []byte(`{
  "hosts": [
    {"name": "本机(macOS)", "status": "一切安全", "detail": "ok"},
    {"name": "root@vps_alpha", "status": "已经免疫", "detail": "patched"}
  ]
}`), 0o600)

	state := NewAppState(cfgFile, true)

	// Default AI provider must be "gemini"
	if state.AIProvider != "gemini" {
		t.Fatalf("expected default AIProvider='gemini', got %q", state.AIProvider)
	}

	// All 3 configured hosts (local + vps_alpha + vps_beta) must immediately have non-empty Host names AND valid Target.SSHHost!
	if len(state.Report.Hosts) != 3 {
		t.Fatalf("expected 3 reconciled hosts on startup, got %d: %+v", len(state.Report.Hosts), state.Report.Hosts)
	}
	if state.Report.Hosts[1].Host != "root@vps_alpha" || state.Report.Hosts[1].Target.SSHHost != "root@vps_alpha" {
		t.Fatalf("expected legacy host to be reconciled with SSHHost, got %+v", state.Report.Hosts[1])
	}
	if state.Report.Hosts[2].Host != "root@vps_beta" || state.Report.Hosts[2].Target.SSHHost != "root@vps_beta" {
		t.Fatalf("expected newly configured host vps_beta to appear immediately, got %+v", state.Report.Hosts[2])
	}

	// Test clicking "移除纳管" immediately at startup BEFORE any scan runs!
	mt := ui.NewTester(state.MissionControlView, 1140, 740)
	if err := mt.Click("主机矩阵与体检"); err != nil {
		t.Fatal(err)
	}
	if !mt.HasText("root@vps_alpha") || !mt.HasText("root@vps_beta") {
		t.Fatalf("expected both remote hostnames visible immediately on startup, texts=%v", mt.Texts())
	}

	state.removeHost("root@vps_alpha", "root@vps_alpha")
	mt.Frame()
	if len(state.Report.Hosts) != 2 || mt.HasText("root@vps_alpha") {
		t.Fatalf("expected root@vps_alpha to be removed immediately without waiting for scan, hosts=%+v", state.Report.Hosts)
	}
}
