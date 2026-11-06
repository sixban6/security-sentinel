package pipeline

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/sixban6/security-sentinel/internal/heal/ai"
	"github.com/sixban6/security-sentinel/internal/scan/auditor"
	"github.com/sixban6/security-sentinel/internal/infra/config"
	"github.com/sixban6/security-sentinel/internal/heal/ha"
	"github.com/sixban6/security-sentinel/internal/scan/intel"
	"github.com/sixban6/security-sentinel/internal/scan/inventory"
	"github.com/sixban6/security-sentinel/internal/infra/store"
	"github.com/sixban6/security-sentinel/internal/infra/model"
	"github.com/sixban6/security-sentinel/internal/ops/notify"
	"github.com/sixban6/security-sentinel/internal/heal/patch"
)

type AuditParams struct {
	Config          config.Config
	Days            int
	ApplyOSFixes    bool
	AutoReboot      bool
	EnableAITriage  bool
	AutoExecuteAI   bool
	AIModelOverride string
	MaxFixesPerHost int
	UseAdvCache     bool
	UseInvCache     bool
	UseAICache      bool
	SkipOSV         bool // set true when metered hotspot protection wants light scan
	StatusFile      string
	QuietNotify     bool
	OnPhase         func(step int, total int, message string)
	OnHostProgress  inventory.ProgressFunc
	OnLog           func(line string)
}

type Runner struct {
	Mem   *store.Store
	Intel *intel.Client
}

func NewRunner(mem *store.Store) *Runner {
	if mem == nil {
		mem = store.New("")
	}
	return &Runner{
		Mem:   mem,
		Intel: intel.NewClient(mem),
	}
}

func (r *Runner) logf(p AuditParams, format string, args ...any) {
	if p.OnLog != nil {
		p.OnLog(fmt.Sprintf(format, args...))
	}
}

func (r *Runner) phase(p AuditParams, step, total int, msg string) {
	if p.OnPhase != nil {
		p.OnPhase(step, total, msg)
	}
	r.logf(p, "[%d/%d] %s", step, total, msg)
}

// RunAudit executes the complete end-to-end audit (and optional remediation/HA/notification) pipeline.
func (r *Runner) RunAudit(ctx context.Context, p AuditParams) (model.AuditReport, error) {
	started := time.Now()
	days := p.Days
	if days <= 0 {
		days = p.Config.Advisories.Days
	}
	if days <= 0 {
		days = 3
	}

	r.phase(p, 1, 4, fmt.Sprintf("拉取近 %d 天业界严重/高危漏洞通告 (GitHub GHSA + Linux CNA)...", days))
	advs, _ := r.Intel.FetchAllAdvisories(ctx, days, p.Config.Advisories.IncludeKernel, p.UseAdvCache)
	r.logf(p, "    获取到 %d 条增量通告。", len(advs))

	hosts := p.Config.ConfiguredHosts()
	r.phase(p, 2, 4, fmt.Sprintf("并发探测 %d 台主机资产画像与系统安全补丁...", len(hosts)))
	var intelForInv *intel.Client
	if !p.SkipOSV && p.Config.Advisories.OSVEnabled {
		intelForInv = r.Intel
	}
	invs := inventory.CollectAll(ctx, inventory.CollectOptions{
		Config:     p.Config,
		Mem:        r.Mem,
		Intel:      intelForInv,
		UseCache:   p.UseInvCache,
		OnProgress: p.OnHostProgress,
	})
	invByKey := make(map[string]model.HostInventory, len(invs))
	for _, inv := range invs {
		invByKey[inv.Target.EffectiveKey()] = inv
	}

	r.phase(p, 3, 4, "执行多分支内核研判与 OSV 全量存量依赖交叉比对...")
	rep := auditor.AuditHosts(ctx, auditor.AuditOptions{
		Advisories:  advs,
		Inventories: invs,
		Intel:       intelForInv,
		Mem:         r.Mem,
		EnableOSV:   !p.SkipOSV && p.Config.Advisories.OSVEnabled,
		Days:        days,
		StartedAt:   started,
	})

	// Optional Step 3a: Apply safe OS-level security updates
	if p.ApplyOSFixes {
		for i := range rep.Hosts {
			h := &rep.Hosts[i]
			updates := h.OSSecurity.Updates
			plan := h.OSSecurity.RemediationPlan
			if len(updates) == 0 {
				continue
			}
			if !plan.SafeToExecute {
				r.logf(p, "  ⛔ [%s] 安全护栏拦截自动更新: %s", h.Host, plan.Warning)
				continue
			}
			r.logf(p, "  🛠️ [%s] 正在安装官方安全补丁 (%s)...", h.Host, strings.Join(plan.Packages, ", "))
			ok, out := patch.ApplyOSPlan(ctx, h.Target, plan)
			if ok {
				r.logf(p, "  ✅ [%s] 官方安全补丁安装完成", h.Host)
				var remaining []model.VulnerabilityMatch
				for _, v := range h.Vulnerabilities {
					if !v.IsOSPackage {
						remaining = append(remaining, v)
					}
				}
				for _, u := range updates {
					cid := u.CVEID
					if cid == "" {
						cid = u.Package
					}
					h.CVEs = appendUnique(h.CVEs, cid)
					h.FixedItems = append(h.FixedItems, model.VulnerabilityMatch{
						ID:               cid,
						CVE:              cid,
						Package:          u.Package,
						InstalledVersion: u.InstalledVersion,
						FixedVersion:     u.CandidateVersion,
						Action:           "官方安全补丁已自动安装并热载",
						Summary:          u.Summary,
					})
					r.Mem.RecordRemediation(model.RemediationRecord{
						HostKey:  h.Target.EffectiveKey(),
						HostName: h.Host,
						CVEID:    cid,
						Package:  u.Package,
						Kind:     "os_patch",
						Status:   "success",
						Strategy: fmt.Sprintf("%s %s -> %s", u.Package, u.InstalledVersion, u.CandidateVersion),
						Log:      "OS security update applied",
					})
				}
				h.Vulnerabilities = remaining
				h.UnmitigatedItems = remaining
				if len(remaining) == 0 {
					h.Status = model.StatusImmunized
					h.HealthScore = 100
					h.Detail = fmt.Sprintf("已完成官方安全更新 (%s · 平滑热载完成)", strings.Join(plan.Packages, ", "))
				} else {
					h.Detail = fmt.Sprintf("已完成系统安全更新 (%s) · 另有 %d 项待处置", strings.Join(plan.Packages, ", "), len(remaining))
				}
			} else {
				r.logf(p, "  ⚠️ [%s] 安全更新未成功: %s", h.Host, out)
			}
		}
	}

	// Optional Step 3b: AI Triage & Runtime Workaround Remediation
	if p.EnableAITriage {
		aiCfg := p.Config.AIRemediation
		if p.AIModelOverride != "" {
			aiCfg.Model = p.AIModelOverride
		}
		aiEng := ai.NewEngine(aiCfg, r.Mem)
		prov, provMsg := aiEng.ResolveProvider()
		if prov == "" {
			r.logf(p, "  ⚠️ [AI 研判跳过] %s", provMsg)
		} else {
			for i := range rep.Hosts {
				h := &rep.Hosts[i]
				if len(h.Vulnerabilities) == 0 {
					continue
				}
				inv := invByKey[h.Target.EffectiveKey()]
				r.runAIForHost(ctx, p, aiEng, h, inv)
			}
		}
	}

	// Optional Step 3c: Zero-Downtime Rolling Reboot if /var/run/reboot-required
	if p.AutoReboot {
		haMgr := ha.NewManager(p.Config, func(ev model.HAProgressEvent) {
			r.logf(p, "  [HA %s] %s", ev.NodeID, ev.Message)
		})
		nodes := p.Config.RollingNodesMap()
		var toReboot []string
		for nid := range nodes {
			if haMgr.CheckRebootRequired(ctx, nid) {
				toReboot = append(toReboot, nid)
			}
		}
		if len(toReboot) > 0 {
			r.logf(p, "  🔄 启动零中断平滑滚动重启 (%s)...", strings.Join(toReboot, ", "))
			if err := haMgr.ExecuteRollingReboot(ctx, toReboot, false); err == nil {
				for i := range rep.Hosts {
					for _, nid := range toReboot {
						if strings.Contains(rep.Hosts[i].Target.EffectiveKey(), nid) || strings.Contains(rep.Hosts[i].Host, nid) {
							rep.Hosts[i].OSContext.RebootRequired = false
							if len(rep.Hosts[i].Vulnerabilities) == 0 {
								rep.Hosts[i].Status = model.StatusImmunized
								rep.Hosts[i].HealthScore = 100
								rep.Hosts[i].Detail = "已完成零中断滚动重启与节点凭据强同步"
							}
						}
					}
				}
			} else {
				r.logf(p, "  ⚠️ 滚动重启异常: %v", err)
			}
		}
	}

	// Recompute cluster score after remediations
	totalScore := 0
	for _, h := range rep.Hosts {
		totalScore += h.HealthScore
	}
	if len(rep.Hosts) > 0 {
		rep.ClusterScore = totalScore / len(rep.Hosts)
	}
	rep.DurationMS = time.Since(started).Milliseconds()

	r.phase(p, 4, 4, "落盘状态快照并推送主机报告与每日最新 CVE 分类情报...")
	if p.QuietNotify {
		_ = notify.SaveReport(rep, p.StatusFile)
	} else {
		_, _ = notify.SaveAndNotify(ctx, rep, p.StatusFile, p.Config.Notifications)
		if p.Config.Notifications.Policy != "critical_only" {
			digestAdvs := advs
			if days < 2 {
				if wider, err := r.Intel.FetchAllAdvisories(ctx, 2, p.Config.Advisories.IncludeKernel, p.UseAdvCache); err == nil && len(wider) > 0 {
					digestAdvs = wider
				}
			}
			_, _ = notify.SendDailyCVEDigest(ctx, digestAdvs, 0, false)
		}
	}
	return rep, nil
}

func isEligibleForRuntimeAIWorkaround(h *model.HostAuditResult, v model.VulnerabilityMatch) bool {
	if v.IsOSPackage {
		return false
	}
	// Pure user-space library packages in project lockfiles / venvs cannot be fixed by OS sysctl/firewall rules;
	// their proper fix is bumping the package version in the project environment.
	switch v.Ecosystem {
	case model.EcoPyPI, model.EcoNPM, model.EcoGo, model.EcoCrates, model.EcoMaven,
		model.EcoPackagist, model.EcoRubyGems, model.EcoNuGet, model.EcoSwift, model.EcoPub, model.EcoHex, model.EcoActions:
		return false
	}
	if h.OSContext.OSFamily == "darwin" && !v.IsKernel {
		return false
	}
	return v.IsKernel || v.Ecosystem == model.EcoLinux || v.Ecosystem == model.EcoBinary || v.Ecosystem == model.EcoDocker
}

func (r *Runner) runAIForHost(ctx context.Context, p AuditParams, aiEng *ai.Engine, h *model.HostAuditResult, inv model.HostInventory) {
	maxFixes := p.MaxFixesPerHost
	if maxFixes <= 0 {
		maxFixes = p.Config.AIRemediation.MaxFixesPerHost
	}
	if maxFixes <= 0 {
		maxFixes = 5 // Safe per-host default cap per scan round
	}

	processed := 0
	seenCVE := make(map[string]bool)
	var remaining []model.VulnerabilityMatch
	awaitingCount := 0
	mitigatedNow := 0

	for _, v := range h.Vulnerabilities {
		if !isEligibleForRuntimeAIWorkaround(h, v) {
			if v.FixedVersion != "" && v.Reason == "" {
				v.Reason = "建议升级组件至安全版本 " + v.FixedVersion
			}
			remaining = append(remaining, v)
			continue
		}
		cveID := v.EffectiveID()
		if seenCVE[cveID] || (maxFixes > 0 && processed >= maxFixes) {
			remaining = append(remaining, v)
			continue
		}
		seenCVE[cveID] = true
		processed++

		if locked, reason := r.Mem.CheckCircuitBreaker(h.Target.EffectiveKey(), cveID); locked {
			v.Reason = reason
			v.Status = "熔断冷却中"
			remaining = append(remaining, v)
			r.logf(p, "    🚨 [%s] %s: %s", h.Host, cveID, reason)
			continue
		}

		r.logf(p, "    🤖 [%s] AI 研判 %s (%s)...", h.Host, cveID, v.Package)
		triage := aiEng.AssessAndMitigate(ctx, v, inv, p.UseAICache)
		if !triage.Success {
			v.Reason = triage.Error
			v.Status = "AI 研判未完成"
			remaining = append(remaining, v)
			r.logf(p, "    ⚠️ [%s] %s: %s", h.Host, cveID, triage.Error)
			continue
		}
		if !triage.HasWorkaround {
			v.Reason = "待官方补丁 (" + triage.Reason + ")"
			v.Status = model.StatusAwaitingPatch
			awaitingCount++
			remaining = append(remaining, v)
			r.logf(p, "    ⏳ [%s] %s 需等待上游补丁: %s", h.Host, cveID, triage.Reason)
			continue
		}

		// Attach scripts to VulnerabilityMatch so GUI DiffViewer can display & edit them!
		v.MitigateScript = triage.Script
		v.RollbackScript = triage.Rollback
		v.Strategy = triage.Strategy

		if !p.AutoExecuteAI {
			v.Reason = "AI 规避与回滚脚本已生成，待审阅批准执行"
			v.Status = "待人工批准"
			remaining = append(remaining, v)
			r.logf(p, "    📝 [%s] %s 已生成双脚本方案 (%s)，处于待审阅模式", h.Host, cveID, triage.Strategy)
			continue
		}

		ok, msg, rolledBack := patch.DeployAndExecuteMitigation(
			ctx, h.Target, inv.OSContext, cveID, triage.Script, triage.Rollback, triage.Strategy, r.Mem,
		)
		if ok {
			mitigatedNow++
			h.CVEs = appendUnique(h.CVEs, cveID)
			v.Mitigated = true
			v.Action = fmt.Sprintf("AI 规避加固已生效 (%s)", triage.Strategy)
			h.FixedItems = append(h.FixedItems, v)
			r.logf(p, "    ✅ [%s] %s 加固成功: %s", h.Host, cveID, msg)
			continue
		}

		if rolledBack {
			r.logf(p, "    🔄 [%s] %s 探活触发自动回滚，正在请求 AI 自我诊断修正...", h.Host, cveID)
			revised := aiEng.DiagnoseAndFix(ctx, v, inv, triage.Script, msg)
			if revised.Success && revised.HasWorkaround {
				ok2, msg2, _ := patch.DeployAndExecuteMitigation(
					ctx, h.Target, inv.OSContext, cveID, revised.Script, revised.Rollback, revised.Strategy, r.Mem,
				)
				if ok2 {
					mitigatedNow++
					h.CVEs = appendUnique(h.CVEs, cveID)
					v.Mitigated = true
					v.MitigateScript = revised.Script
					v.RollbackScript = revised.Rollback
					v.Action = fmt.Sprintf("AI 二次诊断加固已生效 (%s)", revised.Strategy)
					h.FixedItems = append(h.FixedItems, v)
					r.logf(p, "    ✅ [%s] %s 二次诊断加固成功: %s", h.Host, cveID, msg2)
					continue
				}
				msg = msg2
			}
		}

		v.Reason = msg
		v.Status = "加固未通过"
		remaining = append(remaining, v)
		r.logf(p, "    ⚠️ [%s] %s 未通过: %s", h.Host, cveID, msg)
	}

	h.Vulnerabilities = remaining
	h.UnmitigatedItems = remaining
	switch {
	case len(remaining) == 0 && mitigatedNow > 0:
		h.Status = model.StatusImmunized
		h.HealthScore = 100
		h.Detail = fmt.Sprintf("已规避加固 %s (双脚本已归档 · 网络正常)", strings.Join(h.CVEs, ", "))
	case len(remaining) > 0 && awaitingCount == len(remaining):
		h.Status = model.StatusAwaitingPatch
		h.Detail = fmt.Sprintf("%d 项底层代码缺陷需等待上游发布二进制补丁", awaitingCount)
	}
}

func appendUnique(list []string, item string) []string {
	for _, x := range list {
		if x == item {
			return list
		}
	}
	return append(list, item)
}
