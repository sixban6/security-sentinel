package store

import (
	"os"
	"strings"
	"testing"

	"github.com/sixban6/security-sentinel/internal/infra/model"
)

func TestMarkdownTriageManualEditAndCircuitBreaker(t *testing.T) {
	store := New(t.TempDir())
	vuln := model.VulnerabilityMatch{
		CVE:              "CVE-2025-12345",
		Package:          "linux",
		InstalledVersion: "6.1.120",
	}
	osCtx := model.OSContext{
		OSPretty:      "Debian GNU/Linux 12",
		DistroVersion: "12",
		KernelRelease: "6.1.120",
		Arch:          "x86_64",
		Shell:         "/bin/sh",
		PkgMgr:        "apt",
	}

	mdPath, err := store.SaveAITriage(vuln, osCtx, model.AITriageResult{
		Success:       true,
		HasWorkaround: true,
		Strategy:      "Disable vulnerable sysctl",
		Reason:        "Kernel module sysctl toggle available",
		Script:        "#!/bin/sh\nsysctl -w net.ipv4.tcp_rfc1337=1",
		Rollback:      "#!/bin/sh\nsysctl -w net.ipv4.tcp_rfc1337=0",
	}, "gemini-2.5-flash")
	if err != nil {
		t.Fatalf("SaveAITriage failed: %v", err)
	}

	// Simulate admin manually editing the script inside the Markdown file
	raw, _ := os.ReadFile(mdPath)
	edited := strings.ReplaceAll(string(raw), "tcp_rfc1337=1", "tcp_rfc1337=1\n# manual-verified")
	_ = os.WriteFile(mdPath, []byte(edited), 0o600)

	got, ok := store.GetAITriage(vuln, osCtx, "gemini-2.5-flash")
	if !ok || !got.Cached || !strings.Contains(got.Script, "# manual-verified") {
		t.Fatalf("expected cached triage to reflect manual Markdown edit, got %+v", got)
	}

	// Test circuit breaker: transient error does not lock, 2 reverts lock for 24h
	store.RecordRemediation(model.RemediationRecord{HostKey: "vps1", CVEID: "CVE-2025-12345", Status: "transient_error"})
	if locked, _ := store.CheckCircuitBreaker("vps1", "CVE-2025-12345"); locked {
		t.Fatal("transient error must not trigger circuit breaker")
	}
	store.RecordRemediation(model.RemediationRecord{HostKey: "vps1", CVEID: "CVE-2025-12345", Status: "reverted"})
	store.RecordRemediation(model.RemediationRecord{HostKey: "vps1", CVEID: "CVE-2025-12345", Status: "reverted"})
	if locked, _ := store.CheckCircuitBreaker("vps1", "CVE-2025-12345"); !locked {
		t.Fatal("expected 2 consecutive reverts to trigger 24h circuit breaker lockout")
	}
}
