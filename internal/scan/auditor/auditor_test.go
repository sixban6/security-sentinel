package auditor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sixban6/security-sentinel/internal/infra/model"
)

func TestAuditSeparatesHostRuntimeFromAggregatedWorkspaceProjects(t *testing.T) {
	advs := map[string]model.Advisory{
		"CVE-2025-10001": {
			ID:              "CVE-2025-10001",
			CVEID:           "CVE-2025-10001",
			Ecosystem:       model.EcoPyPI,
			Severity:        "HIGH",
			Package:         "litellm",
			VulnerableRange: "< 1.34.0",
			FixedIn:         []string{"1.34.0"},
			Summary:         "Auth bypass in litellm",
		},
		"CVE-2025-10002": {
			ID:              "CVE-2025-10002",
			CVEID:           "CVE-2025-10002",
			Ecosystem:       model.EcoPyPI,
			Severity:        "CRITICAL",
			Package:         "litellm",
			VulnerableRange: "< 1.35.0",
			FixedIn:         []string{"1.35.0"},
			Summary:         "RCE in litellm",
		},
		"CVE-2025-20002": {
			ID:           "CVE-2025-20002",
			CVEID:        "CVE-2025-20002",
			Ecosystem:    model.EcoLinux,
			Severity:     "HIGH",
			Package:      "linux",
			IntroducedIn: "5.15",
			FixedIn:      []string{"6.1.130"},
			Summary:      "Kernel netfilter bug",
		},
	}

	invs := []model.HostInventory{
		{
			Target: model.HostTarget{ID: "local", Name: "本机研发环境", Type: "local"},
			OSContext: model.OSContext{
				OSFamily: "darwin",
				OSPretty: "macOS 15.3",
			},
			Assets: []model.AssetItem{
				{
					Ecosystem:      model.EcoPyPI,
					Name:           "litellm",
					Version:        "1.30.0",
					Location:       "/Users/dev/ai-proj/uv.lock",
					Kind:           "lockfile",
					ProjectName:    "ai-proj",
					ProjectDir:     "/Users/dev/ai-proj",
					ManifestKind:   "uv",
					LastActiveDays: 5,
					Archived:       false,
				},
			},
			Packages: map[string]string{"openssl@3": "3.4.0"},
		},
		{
			Target: model.HostTarget{ID: "root@node-1", Name: "root@node-1", Type: "remote", SSHHost: "root@node-1"},
			OSContext: model.OSContext{
				OSFamily:      "debian",
				KernelRelease: "6.1.135",
			},
			Assets: []model.AssetItem{
				{Ecosystem: model.EcoLinux, Name: "linux", Version: "6.1.135", Location: "kernel", Kind: "kernel"},
			},
			AppliedMitigations: map[string]string{
				"CVE-2025-20002": "APPLIED",
			},
		},
	}

	rep := AuditHosts(context.Background(), AuditOptions{
		Advisories:  advs,
		Inventories: invs,
		Days:        3,
	})

	if len(rep.Hosts) != 2 {
		t.Fatalf("expected 2 host results, got %d", len(rep.Hosts))
	}

	// Local host runtime must stay 100/100 StatusClean!
	localRes := rep.Hosts[0]
	if localRes.Status != model.StatusClean || localRes.HealthScore != 100 || len(localRes.Vulnerabilities) != 0 {
		t.Fatalf("expected local host runtime to be 100/100 Clean, got status=%s score=%d vulns=%+v",
			localRes.Status, localRes.HealthScore, localRes.Vulnerabilities)
	}

	// Both CVEs on litellm must be collapsed into 1 WorkspaceProjectAudit -> 1 WorkspacePackageFix targeting >= 1.35.0!
	if len(localRes.WorkspaceProjects) != 1 || len(localRes.WorkspaceProjects[0].Packages) != 1 {
		t.Fatalf("expected 1 grouped project with 1 package fix, got %+v", localRes.WorkspaceProjects)
	}
	pkgFix := localRes.WorkspaceProjects[0].Packages[0]
	if pkgFix.FixedVersion != "1.35.0" || len(pkgFix.CVEIDs) != 2 || pkgFix.Severity != "CRITICAL" {
		t.Fatalf("expected collapsed package fix (1.35.0, 2 CVEs, CRITICAL), got %+v", pkgFix)
	}

	if len(rep.Hosts[1].RetirableMitigations) != 1 || rep.Hosts[1].RetirableMitigations[0] != "CVE-2025-20002" {
		t.Fatalf("expected CVE-2025-20002 workaround to be flagged as retirable, got %+v", rep.Hosts[1])
	}
}

func TestAuditHybridWorkspaceProjectGoAndPythonVenv(t *testing.T) {
	projDir := t.TempDir()

	hits := []wsRawHit{
		{
			asset: model.AssetItem{
				Ecosystem:    model.EcoGo,
				Name:         "golang.org/x/net",
				Version:      "0.59.0",
				Location:     projDir + "/go.mod",
				Kind:         "lockfile",
				ProjectName:  "hybrid-app",
				ProjectDir:   projDir,
				ManifestKind: "gomod",
			},
			adv: model.Advisory{
				ID:        "GHSA-1111",
				Severity:  "HIGH",
				FixedIn:   []string{"0.62.0"},
				Summary:   "Go net vuln",
				Ecosystem: model.EcoGo,
			},
		},
		{
			asset: model.AssetItem{
				Ecosystem:    model.EcoPyPI,
				Name:         "pillow",
				Version:      "12.3.0",
				Location:     projDir + "/.venv/lib/python3.12/site-packages",
				Kind:         "venv",
				ProjectName:  "hybrid-app",
				ProjectDir:   projDir,
				ManifestKind: "venv",
			},
			adv: model.Advisory{
				ID:        "CVE-2026-97687",
				Severity:  "CRITICAL",
				FixedIn:   []string{"13.0.0"},
				Summary:   "Pillow buffer overflow",
				Ecosystem: model.EcoPyPI,
			},
		},
	}

	projs := buildWorkspaceProjectAudits(hits)
	if len(projs) != 1 {
		t.Fatalf("expected 1 hybrid project audit, got %d", len(projs))
	}

	p := projs[0]
	if p.ManifestKind != "gomod+venv" {
		t.Errorf("expected ManifestKind 'gomod+venv', got %q", p.ManifestKind)
	}
	if len(p.Packages) != 2 {
		t.Fatalf("expected 2 packages, got %d", len(p.Packages))
	}

	var goFix, pyFix *model.WorkspacePackageFix
	for i := range p.Packages {
		if p.Packages[i].Package == "golang.org/x/net" {
			goFix = &p.Packages[i]
		}
		if p.Packages[i].Package == "pillow" {
			pyFix = &p.Packages[i]
		}
	}

	if goFix == nil || pyFix == nil {
		t.Fatalf("expected both Go and Python package fixes, got %+v", p.Packages)
	}

	// Verify Go package fix
	if goFix.ManifestKind != "gomod" {
		t.Errorf("expected Go fix ManifestKind 'gomod', got %q", goFix.ManifestKind)
	}
	if !strings.Contains(goFix.UpgradeCmd, "go get golang.org/x/net@v0.62.0") {
		t.Errorf("expected Go fix UpgradeCmd to contain go get, got %q", goFix.UpgradeCmd)
	}

	// Verify Python package fix: MUST NOT use go get!
	if pyFix.ManifestKind != "venv" {
		t.Errorf("expected Python fix ManifestKind 'venv', got %q", pyFix.ManifestKind)
	}
	if strings.Contains(pyFix.UpgradeCmd, "go get") {
		t.Errorf("FATAL: Python package pillow was assigned go get command: %q", pyFix.UpgradeCmd)
	}
	if !strings.Contains(pyFix.UpgradeCmd, "uv pip install") {
		t.Errorf("expected Python fix UpgradeCmd to use uv pip / python venv upgrade, got %q", pyFix.UpgradeCmd)
	}

	// Verify Batch Upgrade Command: MUST NOT run "go get pillow"
	batchCmd := BuildProjectBatchUpgradeCmd(p)
	if strings.Contains(batchCmd, "go get pillow") {
		t.Errorf("FATAL: batch command contains 'go get pillow': %q", batchCmd)
	}
	if !strings.Contains(batchCmd, "go get golang.org/x/net") {
		t.Errorf("expected batch command to contain Go upgrade: %q", batchCmd)
	}
	if !strings.Contains(batchCmd, "uv pip install") {
		t.Errorf("expected batch command to contain uv pip upgrade: %q", batchCmd)
	}
}

func TestBuildPackageUpgradeCmdSafetyGuard(t *testing.T) {
	tmp := t.TempDir()
	// Fake a .venv in tmp
	if err := os.Mkdir(filepath.Join(tmp, ".venv"), 0o755); err != nil {
		t.Fatal(err)
	}

	// Direct call with mistaken "gomod" manifestKind for "pillow"
	cmd := BuildPackageUpgradeCmd("gomod", tmp, "pillow", "13.0.0")
	if strings.Contains(cmd, "go get pillow") {
		t.Fatalf("safety guard failed: BuildPackageUpgradeCmd produced go get for Python package: %q", cmd)
	}
	if !strings.Contains(cmd, "uv pip install") {
		t.Fatalf("expected safety guard to fallback to Python venv upgrade, got %q", cmd)
	}
}

func TestDiagnoseWorkspaceUpgradeOutcomeAndPreHints(t *testing.T) {
	projDir := t.TempDir()
	pkgJSON := `{"name":"demo","devDependencies":{"vitest":"^2.1.9"}}`
	if err := os.WriteFile(filepath.Join(projDir, "package.json"), []byte(pkgJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	rem := []model.WorkspacePackageFix{
		{
			Package:          "vitest",
			Ecosystem:        model.EcoNPM,
			ManifestKind:     "npm",
			InstalledVersion: "2.1.9",
			FixedVersion:     "4.1.0",
			Severity:         "CRITICAL",
		},
		{
			Package:          "tinypool",
			Ecosystem:        model.EcoNPM,
			ManifestKind:     "npm",
			InstalledVersion: "1.1.1",
			FixedVersion:     "2.1.2",
			Severity:         "CRITICAL",
		},
		{
			Package:          "zero-day-pkg",
			Ecosystem:        model.EcoNPM,
			ManifestKind:     "npm",
			InstalledVersion: "1.0.0",
			FixedVersion:     "",
			Severity:         "HIGH",
		},
	}

	for i := range rem {
		populatePackageUpgradeDiagnostics(&rem[i], projDir)
	}

	if !rem[0].MajorUpgrade || rem[0].Transitive || rem[0].UpgradeHint != "需跨大版本 v2➔v4" {
		t.Fatalf("unexpected vitest diagnostics: %+v", rem[0])
	}
	if !rem[1].MajorUpgrade || !rem[1].Transitive || rem[1].UpgradeHint != "间接依赖·跨v1➔v2" {
		t.Fatalf("unexpected tinypool diagnostics: %+v", rem[1])
	}
	if rem[2].UpgradeHint != "官方未出补丁" {
		t.Fatalf("unexpected zero-day-pkg hint: %+v", rem[2])
	}

	msg := DiagnoseWorkspaceUpgradeOutcome(projDir, "npm", 3, rem, []byte("npm error ERESOLVE unable to resolve dependency tree"), nil)
	for _, want := range []string{
		"ERESOLVE",
		"[需跨大版本] vitest(2.1.9➔4.1.0)",
		"[间接依赖·跨大版本被锁死] tinypool(1.1.1➔2.1.2)",
		"[官方尚未发布修复补丁] zero-day-pkg(1.0.0)",
		"overrides",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("expected diagnostic message %q to contain %q", msg, want)
		}
	}
}
