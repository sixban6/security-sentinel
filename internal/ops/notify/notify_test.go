package notify

import (
	"strings"
	"testing"

	"github.com/sixban6/security-sentinel/internal/infra/model"
)

func TestStateDiffShouldNotifyAndTelegramHTML(t *testing.T) {
	rep1 := model.AuditReport{
		ClusterScore: 100,
		Hosts: []model.HostAuditResult{
			{Host: "vps1", Status: model.StatusClean, Detail: "OK"},
		},
	}
	if ShouldNotify(&rep1, rep1, "on_change") {
		t.Fatal("expected identical report to be suppressed under on_change policy")
	}

	rep2 := model.AuditReport{
		ClusterScore: 78,
		Hosts: []model.HostAuditResult{
			{
				Host:   "vps1",
				Status: model.StatusVulnerable,
				UnmitigatedItems: []model.VulnerabilityMatch{
					{CVE: "CVE-2025-1234", Package: "openssl", InstalledVersion: "3.0.1", FixedVersion: "3.0.2", Summary: "Buffer <overflow>"},
				},
			},
		},
	}
	if !ShouldNotify(&rep1, rep2, "on_change") {
		t.Fatal("expected changed report to trigger notification")
	}

	html := FormatTelegramHTML(rep2, 5)
	if !strings.Contains(html, "<code>CVE-2025-1234</code>") || !strings.Contains(html, "&lt;overflow&gt;") {
		t.Fatalf("unexpected Telegram HTML output:\n%s", html)
	}
}

func TestFormatDailyCVETelegramHTMLGroupsByKernelOSLanguageAndSeverity(t *testing.T) {
	advs := map[string]model.Advisory{
		"CVE-2026-9001": {
			ID:        "CVE-2026-9001",
			CVEID:     "CVE-2026-9001",
			Category:  "kernel",
			Ecosystem: model.EcoLinux,
			Severity:  "CRITICAL",
			CVSS:      9.8,
			Package:   "linux",
			Summary:   "Kernel RCU use-after-free",
		},
		"DSA-6611-1": {
			ID:        "CVE-2026-9002",
			CVEID:     "CVE-2026-9002",
			Category:  "os",
			Ecosystem: "Debian",
			Severity:  "HIGH",
			Package:   "imagemagick",
			Summary:   "[DSA-6611-1] Heap overflow in imagemagick",
		},
		"CVE-2026-9003": {
			ID:        "CVE-2026-9003",
			CVEID:     "CVE-2026-9003",
			Category:  "language",
			Ecosystem: model.EcoNPM,
			Severity:  "CRITICAL",
			CVSS:      9.1,
			Package:   "next",
			FixedIn:   []string{"16.4.1"},
			Summary:   "SSR auth bypass",
		},
	}

	msg := FormatDailyCVETelegramHTML(advs, 3, 5)
	for _, mustHave := range []string{
		"每日最新 CVE 情报日报",
		"一、内核安全 (Linux Kernel) (1 条)",
		"二、操作系统发行版 (OS) (1 条)",
		"三、语言环境供应链 (Languages) (1 条)",
		"CVE-2026-9001",
		"Debian",
		"npm",
	} {
		if !strings.Contains(msg, mustHave) {
			t.Fatalf("daily CVE Telegram message missing %q:\n%s", mustHave, msg)
		}
	}
}
