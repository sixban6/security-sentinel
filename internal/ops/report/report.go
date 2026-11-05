package report

import (
	"fmt"
	"html"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sixban6/security-sentinel/internal/infra/model"
)

// WriteHTML generates a self-contained, zero-external-asset dark-mode HTML security report.
func WriteHTML(rep model.AuditReport, outPath string) error {
	content := RenderHTML(rep)
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return err
	}
	return os.WriteFile(outPath, []byte(content), 0o644)
}

func RenderHTML(rep model.AuditReport) string {
	ts := rep.Timestamp
	if t, err := time.Parse(time.RFC3339, rep.Timestamp); err == nil {
		ts = t.Local().Format("2006-01-02 15:04:05")
	}

	totalAssets, totalUnmit, totalFixed := 0, 0, 0
	for _, h := range rep.Hosts {
		totalAssets += h.AssetsCount
		totalUnmit += len(h.Vulnerabilities)
		totalFixed += len(h.FixedItems)
	}

	scoreColor := "#10b981"
	if rep.ClusterScore < 70 {
		scoreColor = "#ef4444"
	} else if rep.ClusterScore < 90 {
		scoreColor = "#f59e0b"
	}

	var hostCards strings.Builder
	for _, h := range rep.Hosts {
		pillBg := "#065f46"
		pillFg := "#6ee7b7"
		switch h.Status {
		case model.StatusVulnerable, model.StatusManualRequired:
			pillBg, pillFg = "#7f1d1d", "#fca5a5"
		case model.StatusPendingUpdate, model.StatusAwaitingPatch:
			pillBg, pillFg = "#78350f", "#fcd34d"
		case model.StatusImmunized:
			pillBg, pillFg = "#1e3a8a", "#93c5fd"
		}

		fmt.Fprintf(&hostCards, `<div class="card">
  <div class="card-head">
    <div>
      <h3>%s</h3>
      <div class="muted">%s · 内核 %s · 资产 %d 项 · 延迟 %dms</div>
    </div>
    <span class="pill" style="background:%s;color:%s">%s (%d分)</span>
  </div>
  <p class="detail">%s</p>`,
			html.EscapeString(h.Host),
			html.EscapeString(h.OSContext.OSPretty),
			html.EscapeString(h.OSContext.KernelRelease),
			h.AssetsCount,
			h.LatencyMS,
			pillBg, pillFg,
			html.EscapeString(h.Status),
			h.HealthScore,
			html.EscapeString(h.Detail),
		)

		if len(h.FixedItems) > 0 {
			hostCards.WriteString(`<div class="sec-title ok">已修复 / 已规避闭环</div><ul>`)
			for _, f := range h.FixedItems {
				fmt.Fprintf(&hostCards, `<li><code>%s</code> <b>%s</b> (%s) — %s</li>`,
					html.EscapeString(f.EffectiveID()),
					html.EscapeString(f.Package),
					html.EscapeString(f.InstalledVersion),
					html.EscapeString(f.Action),
				)
			}
			hostCards.WriteString(`</ul>`)
		}
		if len(h.Vulnerabilities) > 0 {
			hostCards.WriteString(`<div class="sec-title warn">待处置风险明细</div><ul>`)
			for _, v := range h.Vulnerabilities {
				fixHint := ""
				if v.FixedVersion != "" {
					fixHint = " ➔ 修复版本 " + v.FixedVersion
				}
				fmt.Fprintf(&hostCards, `<li><code>%s</code> [%s] <b>%s</b> (%s%s) — %s</li>`,
					html.EscapeString(v.EffectiveID()),
					html.EscapeString(v.Severity),
					html.EscapeString(v.Package),
					html.EscapeString(v.InstalledVersion),
					html.EscapeString(fixHint),
					html.EscapeString(v.Summary),
				)
			}
			hostCards.WriteString(`</ul>`)
		}
		hostCards.WriteString(`</div>`)
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8"/>
<title>Security-Sentinel 安全巡检战报</title>
<style>
  body{margin:0;padding:32px;background:#0b0f19;color:#e5e7eb;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
  .wrap{max-width:1040px;margin:0 auto}
  .hero{display:flex;justify-content:space-between;align-items:center;background:#111827;border:1px solid #1f2937;border-radius:16px;padding:24px 28px;margin-bottom:24px}
  .score{font-size:44px;font-weight:800;color:%s}
  .kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:24px}
  .kpi{background:#111827;border:1px solid #1f2937;border-radius:12px;padding:16px}
  .kpi .v{font-size:26px;font-weight:700;margin-top:4px}
  .card{background:#111827;border:1px solid #1f2937;border-radius:14px;padding:20px 24px;margin-bottom:16px}
  .card-head{display:flex;justify-content:space-between;align-items:flex-start}
  h1,h3{margin:0 0 6px 0}
  .muted{color:#9ca3af;font-size:13px}
  .pill{padding:5px 12px;border-radius:999px;font-size:13px;font-weight:600}
  .detail{color:#d1d5db;font-size:14px;margin:12px 0}
  .sec-title{font-size:13px;font-weight:700;margin-top:12px}
  .sec-title.ok{color:#34d399}.sec-title.warn{color:#fbbf24}
  ul{margin:6px 0 0 0;padding-left:20px;font-size:13px;line-height:1.7}
  code{background:#1f2937;padding:2px 6px;border-radius:5px;color:#93c5fd}
</style>
</head>
<body>
<div class="wrap">
  <div class="hero">
    <div>
      <h1>🛡️ Security-Sentinel 集群安全审计战报</h1>
      <div class="muted">生成时间: %s · 耗时: %dms · 情报源覆盖: OSV 全量库 + GHSA + Linux CNA (%d 条增量)</div>
    </div>
    <div style="text-align:right">
      <div class="muted">集群安全健康分</div>
      <div class="score">%d<span style="font-size:18px;color:#6b7280">/100</span></div>
    </div>
  </div>
  <div class="kpis">
    <div class="kpi"><div class="muted">守护主机总数</div><div class="v">%d</div></div>
    <div class="kpi"><div class="muted">扫描软件与依赖资产</div><div class="v">%d</div></div>
    <div class="kpi"><div class="muted">已闭环修复 / 规避</div><div class="v" style="color:#34d399">%d</div></div>
    <div class="kpi"><div class="muted">待处置高危隐患</div><div class="v" style="color:#fbbf24">%d</div></div>
  </div>
  %s
</div>
</body>
</html>`,
		scoreColor,
		html.EscapeString(ts), rep.DurationMS, rep.AdvisoriesCount,
		rep.ClusterScore,
		len(rep.Hosts), totalAssets, totalFixed, totalUnmit,
		hostCards.String(),
	)
}
