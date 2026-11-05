package auditor

import (
	"context"
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
