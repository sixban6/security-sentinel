package notify

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sixban6/security-sentinel/internal/infra/config"
	"github.com/sixban6/security-sentinel/internal/infra/model"
)

func advSeverityRank(sev string) int {
	switch strings.ToUpper(strings.TrimSpace(sev)) {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM", "MODERATE":
		return 2
	default:
		return 1
	}
}

func severityDot(sev string) string {
	switch strings.ToUpper(strings.TrimSpace(sev)) {
	case "CRITICAL":
		return "🔴"
	case "HIGH":
		return "🟠"
	default:
		return "🟡"
	}
}

// SortAdvisories sorts advisories by Severity DESC -> CVSS DESC -> PublishedAt DESC -> ID.
func SortAdvisories(list []model.Advisory) {
	sort.SliceStable(list, func(i, j int) bool {
		ri := advSeverityRank(list[i].Severity)
		rj := advSeverityRank(list[j].Severity)
		if ri != rj {
			return ri > rj
		}
		if list[i].CVSS != list[j].CVSS {
			return list[i].CVSS > list[j].CVSS
		}
		if list[i].PublishedAt != list[j].PublishedAt {
			return list[i].PublishedAt > list[j].PublishedAt
		}
		return list[i].DisplayID() < list[j].DisplayID()
	})
}

// FilterAdvisories filters and sorts advisories across the 4 product dimensions:
// Category ("all" | "language" | "os" | "kernel"), Severity ("all" | "CRITICAL" | "HIGH" | "MEDIUM"),
// Ecosystem ("all" / "全部生态" / specific name), and free-text query.
func FilterAdvisories(
	advMap map[string]model.Advisory,
	categoryFilter string,
	severityFilter string,
	ecosystemFilter string,
	query string,
) []model.Advisory {
	catF := strings.ToLower(strings.TrimSpace(categoryFilter))
	sevF := strings.ToUpper(strings.TrimSpace(severityFilter))
	ecoF := strings.TrimSpace(ecosystemFilter)
	qLow := strings.ToLower(strings.TrimSpace(query))

	seen := make(map[string]bool)
	var out []model.Advisory

	for _, adv := range advMap {
		cat := adv.EffectiveCategory()
		if catF != "" && catF != "all" && cat != catF {
			continue
		}
		sev := strings.ToUpper(strings.TrimSpace(adv.Severity))
		if sev == "MODERATE" {
			sev = "MEDIUM"
		}
		adv.Severity = sev
		if sevF != "" && sevF != "ALL" && sev != sevF {
			continue
		}
		if ecoF != "" && ecoF != "all" && ecoF != "全部生态" && !strings.EqualFold(adv.Ecosystem, ecoF) {
			continue
		}
		if qLow != "" {
			hay := strings.ToLower(adv.DisplayID() + " " + adv.GHSAID + " " + adv.Package + " " + adv.Ecosystem + " " + adv.Summary)
			if !strings.Contains(hay, qLow) {
				continue
			}
		}

		dedupKey := adv.DisplayID() + "|" + adv.Ecosystem
		if seen[dedupKey] {
			continue
		}
		seen[dedupKey] = true
		out = append(out, adv)
	}

	SortAdvisories(out)
	return out
}

// parseAdvisoryLocalDate normalizes diverse upstream PublishedAt formats (RFC3339, NVD UTC, Debian YYYY-MM-DD, RHEL midnight UTC)
// into a local calendar date string "YYYY-MM-DD" in loc.
func parseAdvisoryLocalDate(adv model.Advisory, loc *time.Location) (string, bool) {
	if loc == nil {
		loc = time.Local
	}
	pub := strings.TrimSpace(adv.PublishedAt)
	if pub == "" {
		return "", false
	}

	// Date-granularity feeds (e.g. Debian DSA "2026-11-05", RHEL "2026-11-05T00:00:00Z") represent a calendar date directly.
	if len(pub) == 10 || (strings.EqualFold(adv.Ecosystem, "RHEL") && len(pub) >= 10 && strings.HasSuffix(pub, "T00:00:00Z")) {
		datePart := pub[:10]
		if _, err := time.Parse("2006-01-02", datePart); err == nil {
			return datePart, true
		}
	}

	if t, err := time.Parse(time.RFC3339Nano, pub); err == nil {
		return t.In(loc).Format("2006-01-02"), true
	}

	// NVD 2.0 timestamps omit trailing 'Z' (e.g. "2026-11-05T15:15:12.345") and are always in UTC.
	for _, layout := range []string{
		"2006-01-02T15:04:05.999999999",
		"2006-01-02 15:04:05.999999999",
	} {
		if t, err := time.ParseInLocation(layout, pub, time.UTC); err == nil {
			return t.In(loc).Format("2006-01-02"), true
		}
	}

	for _, layout := range []string{time.RFC1123Z, time.RFC1123} {
		if t, err := time.Parse(layout, pub); err == nil {
			return t.In(loc).Format("2006-01-02"), true
		}
	}

	if len(pub) >= 10 {
		if _, err := time.Parse("2006-01-02", pub[:10]); err == nil {
			return pub[:10], true
		}
	}
	return "", false
}

// FilterAdvisoriesTodayAndYesterday strictly retains only advisories published on `now`'s local calendar date
// or the immediately preceding local calendar date (昨天 + 当天).
func FilterAdvisoriesTodayAndYesterday(advMap map[string]model.Advisory, now time.Time) map[string]model.Advisory {
	out := make(map[string]model.Advisory)
	if len(advMap) == 0 {
		return out
	}
	loc := now.Location()
	if loc == nil {
		loc = time.Local
	}
	nowLocal := now.In(loc)
	todayStart := time.Date(nowLocal.Year(), nowLocal.Month(), nowLocal.Day(), 0, 0, 0, 0, loc)
	todayStr := todayStart.Format("2006-01-02")
	yesterdayStr := todayStart.AddDate(0, 0, -1).Format("2006-01-02")

	for k, adv := range advMap {
		dStr, ok := parseAdvisoryLocalDate(adv, loc)
		if !ok {
			continue
		}
		if dStr == todayStr || dStr == yesterdayStr {
			out[k] = adv
		}
	}
	return out
}

// FormatDailyCVETelegramHTML formats a dedicated standalone Telegram message categorized by
// Kernel, OS Distributions, Language Ecosystems, and Importance (Critical / High / Medium).
// When days <= 0, the header displays the exact Today + Yesterday local calendar range.
func FormatDailyCVETelegramHTML(advMap map[string]model.Advisory, days int, maxPerSection int) string {
	return FormatDailyCVETelegramDigestHTML(advMap, time.Now(), days, maxPerSection)
}

// FormatDailyCVETelegramDigestHTML formats the categorized Telegram CVE digest relative to `now`.
// When days <= 0, it labels the report with the exact local yesterday~today range (e.g. "11-05 ~ 11-06 · 昨今两日").
func FormatDailyCVETelegramDigestHTML(advMap map[string]model.Advisory, now time.Time, days int, maxPerSection int) string {
	if maxPerSection <= 0 {
		maxPerSection = 8
	}

	all := FilterAdvisories(advMap, "all", "all", "all", "")
	var kernels, osList, langs []model.Advisory
	critCnt, highCnt, medCnt := 0, 0, 0

	for _, a := range all {
		switch a.Severity {
		case "CRITICAL":
			critCnt++
		case "HIGH":
			highCnt++
		default:
			medCnt++
		}
		switch a.EffectiveCategory() {
		case "kernel":
			kernels = append(kernels, a)
		case "os":
			osList = append(osList, a)
		default:
			langs = append(langs, a)
		}
	}

	nowLocal := now.Local()
	if now.Location() != nil {
		nowLocal = now
	}
	nowStr := nowLocal.Format("2006-01-02 15:04")
	windowTitle := ""
	if days <= 0 {
		todayStart := time.Date(nowLocal.Year(), nowLocal.Month(), nowLocal.Day(), 0, 0, 0, 0, nowLocal.Location())
		yesterdayStart := todayStart.AddDate(0, 0, -1)
		windowTitle = fmt.Sprintf("%s ~ %s · 昨今两日", yesterdayStart.Format("01-02"), todayStart.Format("01-02"))
	} else {
		windowTitle = fmt.Sprintf("近 %d 天", days)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "📡 <b>Security-Sentinel 每日最新 CVE 情报日报 (%s)</b>\n", windowTitle)
	fmt.Fprintf(&b, "⏱️ <b>更新时间</b>: <code>%s</code>\n", nowStr)
	fmt.Fprintf(&b, "📊 <b>情报总览</b>: 共 <code>%d</code> 条 (🔴 严重 <code>%d</code> · 🟠 高危 <code>%d</code> · 🟡 中危 <code>%d</code>)\n",
		len(all), critCnt, highCnt, medCnt)

	renderSection := func(icon, title string, items []model.Advisory, showEco bool) {
		fmt.Fprintf(&b, "\n%s <b>%s (%d 条)</b>\n", icon, EscapeHTML(title), len(items))
		if len(items) == 0 {
			b.WriteString("  └ <i>近期待披露窗口内暂无新增高危条目</i>\n")
			return
		}
		shown := items
		rem := 0
		if len(items) > maxPerSection {
			shown = items[:maxPerSection]
			rem = len(items) - maxPerSection
		}
		for _, it := range shown {
			dot := severityDot(it.Severity)
			idEsc := EscapeHTML(it.DisplayID())
			idTag := fmt.Sprintf("<code>%s</code>", idEsc)
			if it.URL != "" {
				idTag = fmt.Sprintf(`<a href="%s">%s</a>`, EscapeHTML(it.URL), idEsc)
			}
			ecoTag := ""
			if showEco && it.Ecosystem != "" {
				ecoTag = fmt.Sprintf("[<b>%s</b>] ", EscapeHTML(it.Ecosystem))
			}
			pkgTag := ""
			if it.Package != "" && !strings.EqualFold(it.Package, "linux") && !strings.EqualFold(it.Package, it.Ecosystem) {
				if len(it.FixedIn) > 0 && it.FixedIn[0] != "" {
					pkgTag = fmt.Sprintf("(<code>%s</code> ➔ %s) ", EscapeHTML(it.Package), EscapeHTML(it.FixedIn[0]))
				} else {
					pkgTag = fmt.Sprintf("(<code>%s</code>) ", EscapeHTML(it.Package))
				}
			}
			cvssTag := ""
			if it.CVSS >= 7.0 {
				cvssTag = fmt.Sprintf("[CVSS %.1f] ", it.CVSS)
			}
			sum := EscapeHTML(truncate(it.Summary, 68))
			fmt.Fprintf(&b, "  • %s %s%s %s%s— %s\n", dot, ecoTag, idTag, pkgTag, cvssTag, sum)
		}
		if rem > 0 {
			fmt.Fprintf(&b, "  • <i>... 另有 %d 条可在桌面端「每日最新 CVE」或 `sectl cve` 查看</i>\n", rem)
		}
	}

	renderSection("🐧", "一、内核安全 (Linux Kernel)", kernels, false)
	renderSection("🖥️", "二、操作系统发行版 (OS)", osList, true)
	renderSection("💻", "三、语言环境供应链 (Languages)", langs, true)

	return strings.TrimSpace(b.String())
}

type digestLedger struct {
	Date      string `json:"date"`
	SentAt    string `json:"sent_at,omitempty"`
	Count     int    `json:"count,omitempty"`
	Signature string `json:"signature"`
}

var (
	digestMu   sync.Mutex
	sendTGFunc = SendTelegram
)

func digestLedgerPath() string {
	return filepath.Join(config.StateDir(), "last_cve_digest.json")
}

func acquireDigestLock(staleAfter time.Duration) func() {
	lockPath := filepath.Join(config.StateDir(), "last_cve_digest.lock")
	_ = os.MkdirAll(filepath.Dir(lockPath), 0o755)
	deadline := time.Now().Add(15 * time.Second)
	for {
		f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			_, _ = fmt.Fprintf(f, "%d\n", os.Getpid())
			_ = f.Close()
			return func() { _ = os.Remove(lockPath) }
		}
		if info, statErr := os.Stat(lockPath); statErr == nil && time.Since(info.ModTime()) > staleAfter {
			_ = os.Remove(lockPath)
			continue
		}
		if time.Now().After(deadline) {
			return func() {}
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// SendDailyCVEDigest pushes the standalone categorized Daily CVE Digest message to Telegram.
// When days <= 0 (default), advMap is strictly filtered to [yesterday, today] in local calendar time.
// When force is false (automated audit runs), it enforces strict once-per-calendar-day idempotency
// so multiple scans or newly published CVEs on the same day never trigger duplicate pushes.
func SendDailyCVEDigest(ctx context.Context, advMap map[string]model.Advisory, days int, force bool) (bool, error) {
	return sendDailyCVEDigestAt(ctx, advMap, time.Now(), days, force)
}

func sendDailyCVEDigestAt(ctx context.Context, advMap map[string]model.Advisory, now time.Time, days int, force bool) (bool, error) {
	digestMu.Lock()
	defer digestMu.Unlock()

	releaseLock := acquireDigestLock(2 * time.Minute)
	defer releaseLock()

	nowLocal := now.Local()
	if now.Location() != nil {
		nowLocal = now
	}
	today := nowLocal.Format("2006-01-02")

	if !force {
		if b, err := os.ReadFile(digestLedgerPath()); err == nil {
			var prev digestLedger
			if json.Unmarshal(b, &prev) == nil && prev.Date == today {
				return false, nil
			}
		}
	}

	targetMap := advMap
	if days <= 0 {
		targetMap = FilterAdvisoriesTodayAndYesterday(advMap, nowLocal)
	}

	all := FilterAdvisories(targetMap, "all", "all", "all", "")
	if len(all) == 0 && !force {
		return false, nil
	}

	var ids []string
	for _, a := range all {
		ids = append(ids, a.DisplayID())
	}
	sort.Strings(ids)
	sum := sha256.Sum256([]byte(strings.Join(ids, ",")))
	sig := hex.EncodeToString(sum[:16])

	msg := FormatDailyCVETelegramDigestHTML(targetMap, nowLocal, days, 8)
	sent, err := sendTGFunc(ctx, msg, "", "")
	if err != nil || !sent {
		return sent, err
	}

	if raw, err := json.Marshal(digestLedger{
		Date:      today,
		SentAt:    nowLocal.Format(time.RFC3339),
		Count:     len(all),
		Signature: sig,
	}); err == nil {
		_ = writeAtomic(digestLedgerPath(), raw)
	}
	return true, nil
}
