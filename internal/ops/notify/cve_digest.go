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

// FormatDailyCVETelegramHTML formats a dedicated standalone Telegram message categorized by
// Kernel, OS Distributions, Language Ecosystems, and Importance (Critical / High / Medium).
func FormatDailyCVETelegramHTML(advMap map[string]model.Advisory, days int, maxPerSection int) string {
	if days <= 0 {
		days = 3
	}
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

	nowStr := time.Now().Format("2006-01-02 15:04")
	var b strings.Builder
	fmt.Fprintf(&b, "📡 <b>Security-Sentinel 每日最新 CVE 情报日报 (近 %d 天)</b>\n", days)
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
	Signature string `json:"signature"`
}

func digestLedgerPath() string {
	return filepath.Join(config.StateDir(), "last_cve_digest.json")
}

// SendDailyCVEDigest pushes the standalone categorized Daily CVE Digest message to Telegram.
// When force is false (automated audit runs), it deduplicates so identical digests are never spammed repeatedly on the same day.
func SendDailyCVEDigest(ctx context.Context, advMap map[string]model.Advisory, days int, force bool) (bool, error) {
	if len(advMap) == 0 {
		return false, nil
	}

	all := FilterAdvisories(advMap, "all", "all", "all", "")
	if len(all) == 0 {
		return false, nil
	}

	// Compute deterministic digest signature over top CVE IDs
	var ids []string
	for _, a := range all {
		ids = append(ids, a.DisplayID())
	}
	sort.Strings(ids)
	sum := sha256.Sum256([]byte(strings.Join(ids, ",")))
	sig := hex.EncodeToString(sum[:16])
	today := time.Now().Format("2006-01-02")

	if !force {
		if b, err := os.ReadFile(digestLedgerPath()); err == nil {
			var prev digestLedger
			if json.Unmarshal(b, &prev) == nil && prev.Date == today && prev.Signature == sig {
				return false, nil
			}
		}
	}

	msg := FormatDailyCVETelegramHTML(advMap, days, 8)
	sent, err := SendTelegram(ctx, msg, "", "")
	if err != nil || !sent {
		return sent, err
	}

	if raw, err := json.Marshal(digestLedger{Date: today, Signature: sig}); err == nil {
		_ = writeAtomic(digestLedgerPath(), raw)
	}
	return true, nil
}
