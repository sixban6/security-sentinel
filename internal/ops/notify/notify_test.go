package notify

import (
	"context"
	"strings"
	"testing"
	"time"

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

func TestFilterAdvisoriesTodayAndYesterdayAcrossTimezonesAndFormats(t *testing.T) {
	cst := time.FixedZone("CST", 8*3600)
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, cst) // Local today: 2026-11-06, yesterday: 2026-11-05

	advs := map[string]model.Advisory{
		// UTC 2026-11-05 18:07Z -> CST 2026-11-06 02:07 (Today -> KEEP)
		"today-ghsa": {ID: "CVE-2026-1001", CVEID: "CVE-2026-1001", Ecosystem: model.EcoNPM, Severity: "HIGH", PublishedAt: "2026-11-05T18:07:30Z"},
		// UTC 2026-11-04 17:02Z -> CST 2026-11-05 01:02 (Yesterday -> KEEP)
		"yesterday-ghsa": {ID: "CVE-2026-1002", CVEID: "CVE-2026-1002", Ecosystem: model.EcoGo, Severity: "CRITICAL", PublishedAt: "2026-11-04T17:02:37Z"},
		// UTC 2026-11-03 17:53Z -> CST 2026-11-04 01:53 (2 days ago -> DROP)
		"two-days-ago-ghsa": {ID: "CVE-2026-1003", CVEID: "CVE-2026-1003", Ecosystem: model.EcoNPM, Severity: "HIGH", PublishedAt: "2026-11-03T17:53:42Z"},
		// NVD timestamp without trailing Z (UTC 2026-11-05 22:17 -> CST 2026-11-06 06:17 -> KEEP)
		"nvd-kernel-today": {ID: "CVE-2026-1004", CVEID: "CVE-2026-1004", Ecosystem: model.EcoLinux, Severity: "HIGH", PublishedAt: "2026-11-05T22:17:41.803"},
		// NVD timestamp from 2026-11-03 -> DROP
		"nvd-kernel-old": {ID: "CVE-2026-1005", CVEID: "CVE-2026-1005", Ecosystem: model.EcoLinux, Severity: "HIGH", PublishedAt: "2026-11-03T12:17:30.710"},
		// Debian pure date yesterday -> KEEP
		"debian-yesterday": {ID: "CVE-2026-1006", CVEID: "CVE-2026-1006", Ecosystem: "Debian", Severity: "HIGH", PublishedAt: "2026-11-05"},
		// Debian pure date old -> DROP
		"debian-old": {ID: "CVE-2026-1007", CVEID: "CVE-2026-1007", Ecosystem: "Debian", Severity: "HIGH", PublishedAt: "2026-11-04"},
		// RHEL midnight UTC date -> KEEP even in negative UTC offsets
		"rhel-yesterday": {ID: "CVE-2026-1008", CVEID: "CVE-2026-1008", Ecosystem: "RHEL", Severity: "HIGH", PublishedAt: "2026-11-05T00:00:00Z"},
	}

	got := FilterAdvisoriesTodayAndYesterday(advs, now)
	for _, keepKey := range []string{"today-ghsa", "yesterday-ghsa", "nvd-kernel-today", "debian-yesterday", "rhel-yesterday"} {
		if _, ok := got[keepKey]; !ok {
			t.Fatalf("expected %q to be kept in today+yesterday filter, got keys=%v", keepKey, got)
		}
	}
	for _, dropKey := range []string{"two-days-ago-ghsa", "nvd-kernel-old", "debian-old"} {
		if _, ok := got[dropKey]; ok {
			t.Fatalf("expected %q to be excluded from today+yesterday filter", dropKey)
		}
	}

	// Verify RHEL midnight UTC date stays on 2026-11-05 even in UTC-8
	pst := time.FixedZone("PST", -8*3600)
	nowPST := time.Date(2026, 11, 6, 9, 0, 0, 0, pst)
	gotPST := FilterAdvisoriesTodayAndYesterday(advs, nowPST)
	if _, ok := gotPST["rhel-yesterday"]; !ok {
		t.Fatalf("expected RHEL calendar date 2026-11-05 to be preserved in PST")
	}
}

func TestSendDailyCVEDigestOncePerDayIdempotencyAndWindowHeader(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())

	var sentMessages []string
	origSend := sendTGFunc
	sendTGFunc = func(_ context.Context, msg, _, _ string) (bool, error) {
		sentMessages = append(sentMessages, msg)
		return true, nil
	}
	defer func() { sendTGFunc = origSend }()

	cst := time.FixedZone("CST", 8*3600)
	morning := time.Date(2026, 11, 6, 9, 0, 0, 0, cst)
	noon := time.Date(2026, 11, 6, 12, 10, 0, 0, cst)
	nextDay := time.Date(2026, 11, 7, 9, 0, 0, 0, cst)

	advsMorning := map[string]model.Advisory{
		"CVE-2026-2001": {
			ID: "CVE-2026-2001", CVEID: "CVE-2026-2001", Category: "language", Ecosystem: model.EcoPyPI,
			Severity: "CRITICAL", CVSS: 9.8, Package: "urllib3", Summary: "Yesterday vuln", PublishedAt: "2026-11-05T08:00:00Z",
		},
		"CVE-2026-1999": {
			ID: "CVE-2026-1999", CVEID: "CVE-2026-1999", Category: "language", Ecosystem: model.EcoPyPI,
			Severity: "HIGH", Package: "oldpkg", Summary: "Old 3-day vuln", PublishedAt: "2026-11-03T08:00:00Z",
		},
	}

	// 1. First automated run in the morning: sends ONLY today+yesterday (excludes 11-03) with "11-05 ~ 11-06 · 昨今两日" header
	sent, err := sendDailyCVEDigestAt(context.Background(), advsMorning, morning, 0, false)
	if err != nil || !sent || len(sentMessages) != 1 {
		t.Fatalf("expected morning digest to send once: sent=%v err=%v count=%d", sent, err, len(sentMessages))
	}
	if !strings.Contains(sentMessages[0], "11-05 ~ 11-06 · 昨今两日") || !strings.Contains(sentMessages[0], "CVE-2026-2001") {
		t.Fatalf("unexpected morning digest content:\n%s", sentMessages[0])
	}
	if strings.Contains(sentMessages[0], "CVE-2026-1999") {
		t.Fatalf("digest must exclude advisories older than yesterday:\n%s", sentMessages[0])
	}

	// 2. Noon run on the SAME day with NEW CVEs added AND different days arg: must NOT duplicate push!
	advsNoon := map[string]model.Advisory{
		"CVE-2026-2001": advsMorning["CVE-2026-2001"],
		"CVE-2026-2002": {
			ID: "CVE-2026-2002", CVEID: "CVE-2026-2002", Category: "kernel", Ecosystem: model.EcoLinux,
			Severity: "CRITICAL", Package: "linux", Summary: "Brand new noon CVE", PublishedAt: "2026-11-06T03:00:00Z",
		},
	}
	sent2, err2 := sendDailyCVEDigestAt(context.Background(), advsNoon, noon, 7, false)
	if err2 != nil || sent2 || len(sentMessages) != 1 {
		t.Fatalf("expected same-day automated run to be suppressed even when CVE signature changed: sent=%v err=%v count=%d", sent2, err2, len(sentMessages))
	}

	// 3. Explicit manual push (force=true) on the same day IS allowed
	sentForce, errForce := sendDailyCVEDigestAt(context.Background(), advsNoon, noon, 0, true)
	if errForce != nil || !sentForce || len(sentMessages) != 2 {
		t.Fatalf("expected manual force=true push to succeed: sent=%v err=%v count=%d", sentForce, errForce, len(sentMessages))
	}

	// 4. Next calendar day automated run sends again cleanly
	advsNextDay := map[string]model.Advisory{
		"CVE-2026-2002": advsNoon["CVE-2026-2002"], // 2026-11-06 is now yesterday on 11-07!
	}
	sentNext, errNext := sendDailyCVEDigestAt(context.Background(), advsNextDay, nextDay, 0, false)
	if errNext != nil || !sentNext || len(sentMessages) != 3 {
		t.Fatalf("expected next calendar day automated run to send: sent=%v err=%v count=%d", sentNext, errNext, len(sentMessages))
	}
	if !strings.Contains(sentMessages[2], "11-06 ~ 11-07 · 昨今两日") {
		t.Fatalf("expected updated window header on next day:\n%s", sentMessages[2])
	}
}
