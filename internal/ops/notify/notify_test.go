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

func TestFilterAdvisoriesTodayAcrossTimezonesAndFormats(t *testing.T) {
	cst := time.FixedZone("CST", 8*3600)
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, cst) // Local today: 2026-11-06

	advs := map[string]model.Advisory{
		// UTC 2026-11-05 18:07Z -> CST 2026-11-06 02:07 (Today -> KEEP)
		"today-ghsa": {ID: "CVE-2026-1001", CVEID: "CVE-2026-1001", Ecosystem: model.EcoNPM, Severity: "HIGH", PublishedAt: "2026-11-05T18:07:30Z"},
		// UTC 2026-11-04 17:02Z -> CST 2026-11-05 01:02 (Yesterday -> DROP)
		"yesterday-ghsa": {ID: "CVE-2026-1002", CVEID: "CVE-2026-1002", Ecosystem: model.EcoGo, Severity: "CRITICAL", PublishedAt: "2026-11-04T17:02:37Z"},
		// UTC 2026-11-03 17:53Z -> CST 2026-11-04 01:53 (2 days ago -> DROP)
		"two-days-ago-ghsa": {ID: "CVE-2026-1003", CVEID: "CVE-2026-1003", Ecosystem: model.EcoNPM, Severity: "HIGH", PublishedAt: "2026-11-03T17:53:42Z"},
		// NVD timestamp without trailing Z (UTC 2026-11-05 22:17 -> CST 2026-11-06 06:17 -> KEEP)
		"nvd-kernel-today": {ID: "CVE-2026-1004", CVEID: "CVE-2026-1004", Ecosystem: model.EcoLinux, Severity: "HIGH", PublishedAt: "2026-11-05T22:17:41.803"},
		// NVD timestamp from yesterday -> DROP
		"nvd-kernel-yesterday": {ID: "CVE-2026-1005", CVEID: "CVE-2026-1005", Ecosystem: model.EcoLinux, Severity: "HIGH", PublishedAt: "2026-11-04T20:17:30.710"},
		// Debian pure date today -> KEEP
		"debian-today": {ID: "CVE-2026-1006", CVEID: "CVE-2026-1006", Ecosystem: "Debian", Severity: "HIGH", PublishedAt: "2026-11-06"},
		// Debian pure date yesterday -> DROP
		"debian-yesterday": {ID: "CVE-2026-1007", CVEID: "CVE-2026-1007", Ecosystem: "Debian", Severity: "HIGH", PublishedAt: "2026-11-05"},
		// RHEL midnight UTC date today -> KEEP even in negative UTC offsets
		"rhel-today": {ID: "CVE-2026-1008", CVEID: "CVE-2026-1008", Ecosystem: "RHEL", Severity: "HIGH", PublishedAt: "2026-11-06T00:00:00Z"},
	}

	got := FilterAdvisoriesToday(advs, now)
	for _, keepKey := range []string{"today-ghsa", "nvd-kernel-today", "debian-today", "rhel-today"} {
		if _, ok := got[keepKey]; !ok {
			t.Fatalf("expected %q to be kept in today filter, got keys=%v", keepKey, got)
		}
	}
	for _, dropKey := range []string{"yesterday-ghsa", "two-days-ago-ghsa", "nvd-kernel-yesterday", "debian-yesterday"} {
		if _, ok := got[dropKey]; ok {
			t.Fatalf("expected %q to be excluded from today filter", dropKey)
		}
	}

	// Verify RHEL midnight UTC date stays on 2026-11-06 even in UTC-8
	pst := time.FixedZone("PST", -8*3600)
	nowPST := time.Date(2026, 11, 6, 9, 0, 0, 0, pst)
	gotPST := FilterAdvisoriesToday(advs, nowPST)
	if _, ok := gotPST["rhel-today"]; !ok {
		t.Fatalf("expected RHEL calendar date 2026-11-06 to be preserved in PST")
	}
}

func TestSendDailyCVEDigestTodayIncrementalAndExpiredContextResilience(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())

	var sentMessages []string
	origSend := sendTGFunc
	sendTGFunc = func(ctx context.Context, msg, _, _ string) (bool, error) {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		sentMessages = append(sentMessages, msg)
		return true, nil
	}
	defer func() { sendTGFunc = origSend }()

	cst := time.FixedZone("CST", 8*3600)
	midnight := time.Date(2026, 11, 6, 0, 2, 0, 0, cst)
	morning := time.Date(2026, 11, 6, 9, 0, 0, 0, cst)
	noon := time.Date(2026, 11, 6, 12, 10, 0, 0, cst)
	evening := time.Date(2026, 11, 6, 20, 0, 0, 0, cst)
	nextDay := time.Date(2026, 11, 7, 12, 0, 0, 0, cst)

	// 0. Midnight scan right after 00:00 only sees yesterday's CVEs -> 0 Today CVEs, stays silent without locking out the day!
	onlyYesterday := map[string]model.Advisory{
		"CVE-2026-1999": {
			ID: "CVE-2026-1999", CVEID: "CVE-2026-1999", Category: "language", Ecosystem: model.EcoPyPI,
			Severity: "HIGH", Package: "oldpkg", Summary: "Yesterday vuln", PublishedAt: "2026-11-05T10:00:00Z",
		},
	}
	if sent0, err0 := sendDailyCVEDigestAt(context.Background(), onlyYesterday, midnight, 0, false); err0 != nil || sent0 {
		t.Fatalf("expected 0-today-CVE midnight scan to stay silent: sent=%v err=%v", sent0, err0)
	}

	// 1. Morning scan with first Today CVE AND an already-expired scan context: must allocate fresh delivery ctx and send "11-06 · 今日"!
	expiredCtx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-10*time.Minute))
	cancel()

	advsMorning := map[string]model.Advisory{
		"CVE-2026-1999": onlyYesterday["CVE-2026-1999"],
		"CVE-2026-2001": {
			ID: "CVE-2026-2001", CVEID: "CVE-2026-2001", Category: "language", Ecosystem: model.EcoPyPI,
			Severity: "CRITICAL", CVSS: 9.8, Package: "urllib3", Summary: "Today morning vuln", PublishedAt: "2026-11-05T20:00:00Z", // 2026-11-06 04:00 CST
		},
	}
	sent1, err1 := sendDailyCVEDigestAt(expiredCtx, advsMorning, morning, 0, false)
	if err1 != nil || !sent1 || len(sentMessages) != 1 {
		t.Fatalf("expected morning Today digest to succeed even with expired caller ctx: sent=%v err=%v count=%d", sent1, err1, len(sentMessages))
	}
	if !strings.Contains(sentMessages[0], "11-06 · 今日)") || !strings.Contains(sentMessages[0], "CVE-2026-2001") {
		t.Fatalf("unexpected morning Today digest content:\n%s", sentMessages[0])
	}
	if strings.Contains(sentMessages[0], "CVE-2026-1999") {
		t.Fatalf("Today digest must exclude yesterday's CVE:\n%s", sentMessages[0])
	}

	// 2. Noon scan with NO new Today CVEs: must stay silent (no duplicate spam)!
	if sent2, err2 := sendDailyCVEDigestAt(context.Background(), advsMorning, noon, 0, false); err2 != nil || sent2 || len(sentMessages) != 1 {
		t.Fatalf("expected unchanged Today set at noon to be suppressed: sent=%v err=%v count=%d", sent2, err2, len(sentMessages))
	}

	// 3. Evening scan with 1 NEW Today CVE: pushes ONLY the incremental delta ("11-06 · 今日新增") without repeating CVE-2026-2001!
	advsEvening := map[string]model.Advisory{
		"CVE-2026-2001": advsMorning["CVE-2026-2001"],
		"CVE-2026-2002": {
			ID: "CVE-2026-2002", CVEID: "CVE-2026-2002", Category: "kernel", Ecosystem: model.EcoLinux,
			Severity: "CRITICAL", Package: "linux", Summary: "Brand new afternoon kernel CVE", PublishedAt: "2026-11-06T06:00:00Z", // 2026-11-06 14:00 CST
		},
	}
	sent3, err3 := sendDailyCVEDigestAt(context.Background(), advsEvening, evening, 0, false)
	if err3 != nil || !sent3 || len(sentMessages) != 2 {
		t.Fatalf("expected incremental Today delta push in evening: sent=%v err=%v count=%d", sent3, err3, len(sentMessages))
	}
	if !strings.Contains(sentMessages[1], "11-06 · 今日新增") || !strings.Contains(sentMessages[1], "CVE-2026-2002") || !strings.Contains(sentMessages[1], "今日累计 <code>2</code> 条") {
		t.Fatalf("unexpected incremental delta content:\n%s", sentMessages[1])
	}
	if strings.Contains(sentMessages[1], "CVE-2026-2001") {
		t.Fatalf("incremental delta must NOT repeat already-sent CVE-2026-2001:\n%s", sentMessages[1])
	}

	// 4. Next calendar day starts fresh cleanly with "11-07 · 今日"
	advsNextDay := map[string]model.Advisory{
		"CVE-2026-2002": advsEvening["CVE-2026-2002"], // Now yesterday on 11-07 -> excluded
		"CVE-2026-3001": {
			ID: "CVE-2026-3001", CVEID: "CVE-2026-3001", Category: "os", Ecosystem: "Debian",
			Severity: "HIGH", Package: "openssh", Summary: "New day DSA", PublishedAt: "2026-11-07",
		},
	}
	sent4, err4 := sendDailyCVEDigestAt(context.Background(), advsNextDay, nextDay, 0, false)
	if err4 != nil || !sent4 || len(sentMessages) != 3 {
		t.Fatalf("expected next calendar day Today digest to send: sent=%v err=%v count=%d", sent4, err4, len(sentMessages))
	}
	if !strings.Contains(sentMessages[2], "11-07 · 今日)") || !strings.Contains(sentMessages[2], "CVE-2026-3001") || strings.Contains(sentMessages[2], "CVE-2026-2002") {
		t.Fatalf("unexpected next day Today digest:\n%s", sentMessages[2])
	}
}
