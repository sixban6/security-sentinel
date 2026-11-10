package auditor

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sixban6/security-sentinel/internal/scan/intel"
	"github.com/sixban6/security-sentinel/internal/infra/store"
	"github.com/sixban6/security-sentinel/internal/infra/model"
	"github.com/sixban6/security-sentinel/internal/scan/version"
)

func normalizePkgName(eco, name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	if strings.EqualFold(eco, model.EcoPyPI) {
		n = strings.ReplaceAll(n, "_", "-")
	}
	return n
}

func ecosystemsCompatible(assetEco, advEco string) bool {
	if assetEco == "" || advEco == "" {
		return true
	}
	ae := strings.ToLower(assetEco)
	ve := strings.ToLower(advEco)
	if ae == ve {
		return true
	}
	if ae == strings.ToLower(model.EcoBinary) || ae == strings.ToLower(model.EcoHomebrew) {
		return ve != strings.ToLower(model.EcoLinux)
	}
	return false
}

// isWorkspaceDevAsset distinguishes static developer project/library dependencies from live host runtime exposure.
func isWorkspaceDevAsset(a model.AssetItem) bool {
	return a.Kind == "venv" || a.Kind == "lockfile" || a.Kind == "runtime"
}

// AuditOptions controls vulnerability matching across inventories.
type AuditOptions struct {
	Advisories  map[string]model.Advisory
	Inventories []model.HostInventory
	Intel       *intel.Client
	Mem         *store.Store
	EnableOSV   bool
	Days        int
	StartedAt   time.Time
}

// AuditHosts separates Host Runtime Security (affecting HealthScore & Status) from Dev Workspace Dependencies
// (aggregated into clean 2-level Project -> Package cards with 90-day activity filtering).
func AuditHosts(ctx context.Context, opts AuditOptions) model.AuditReport {
	if opts.StartedAt.IsZero() {
		opts.StartedAt = time.Now()
	}

	var osvHits map[string][]model.Advisory
	if opts.EnableOSV && opts.Intel != nil {
		var queries []intel.OSVQuery
		for _, inv := range opts.Inventories {
			for _, a := range inv.Assets {
				if isOSVQueryableAsset(a) {
					qName := a.Name
					if a.SourcePackage != "" && (strings.HasPrefix(a.Ecosystem, "Debian:") || strings.HasPrefix(a.Ecosystem, "Ubuntu:")) {
						qName = a.SourcePackage
					}
					queries = append(queries, intel.OSVQuery{
						Ecosystem: a.Ecosystem,
						Name:      qName,
						Version:   a.Version,
					})
				}
			}
		}
		if len(queries) > 0 {
			osvHits = opts.Intel.QueryOSVAssets(ctx, queries)
		}
	}

	var hostResults []model.HostAuditResult
	totalScore := 0

	for _, inv := range opts.Inventories {
		hr := auditSingleHost(inv, opts.Advisories, osvHits, opts.Mem)
		totalScore += hr.HealthScore
		hostResults = append(hostResults, hr)
	}

	clusterScore := 100
	if len(hostResults) > 0 {
		clusterScore = totalScore / len(hostResults)
	}

	return model.AuditReport{
		Timestamp:       time.Now().Format(time.RFC3339),
		DurationMS:      time.Since(opts.StartedAt).Milliseconds(),
		ClusterScore:    clusterScore,
		AdvisoriesCount: len(opts.Advisories),
		Days:            opts.Days,
		Hosts:           hostResults,
	}
}

func isOSVQueryableAsset(a model.AssetItem) bool {
	if a.Version == "" || a.Version == "unknown" {
		return false
	}
	switch a.Kind {
	case "venv", "lockfile", "runtime":
		return a.Ecosystem != "" && a.Ecosystem != model.EcoHomebrew && a.Ecosystem != model.EcoBinary && a.Ecosystem != model.EcoDocker
	default:
		return false
	}
}

type wsRawHit struct {
	asset model.AssetItem
	adv   model.Advisory
}

func auditSingleHost(
	inv model.HostInventory,
	advisories map[string]model.Advisory,
	osvHits map[string][]model.Advisory,
	mem *store.Store,
) model.HostAuditResult {
	res := model.HostAuditResult{
		Target:           inv.Target,
		Host:             inv.Target.Name,
		LatencyMS:        inv.LatencyMS,
		PackagesCount:    len(inv.Packages),
		AssetsCount:      len(inv.Assets),
		OSContext:        inv.OSContext,
		OSSecurity:       inv.OSSecurity,
		EcosystemSummary: inv.EcosystemSummary,
		OrphanedVenvs:    inv.OrphanedVenvs,
		Reachable:        inv.Error == "",
		Error:            inv.Error,
	}

	if inv.Error != "" {
		res.Status = model.StatusManualRequired
		res.Detail = inv.Error
		res.HealthScore = 40
		return res
	}

	seenRuntimeMatch := make(map[string]bool)
	var runtimeMatches []model.VulnerabilityMatch
	var wsHits []wsRawHit
	seenWSHit := make(map[string]bool)

	addRuntimeMatch := func(m model.VulnerabilityMatch) {
		dedupKey := fmt.Sprintf("%s|%s|%s", strings.ToUpper(m.EffectiveID()), strings.ToLower(m.Package), m.Location)
		if seenRuntimeMatch[dedupKey] {
			return
		}
		seenRuntimeMatch[dedupKey] = true
		runtimeMatches = append(runtimeMatches, m)
	}

	addWSHit := func(asset model.AssetItem, adv model.Advisory) {
		k := fmt.Sprintf("%s|%s|%s|%s", asset.ProjectDir, asset.Location, strings.ToLower(asset.Name), strings.ToUpper(adv.DisplayID()))
		if seenWSHit[k] {
			return
		}
		seenWSHit[k] = true
		wsHits = append(wsHits, wsRawHit{asset: asset, adv: adv})
	}

	assetsByPkg := make(map[string][]model.AssetItem)
	for _, a := range inv.Assets {
		key := normalizePkgName(a.Ecosystem, a.Name)
		assetsByPkg[key] = append(assetsByPkg[key], a)
	}

	// 1. Match incremental GHSA + Linux Kernel CNA advisories
	for _, adv := range advisories {
		isKernelAdv := strings.EqualFold(adv.Ecosystem, model.EcoLinux) || strings.EqualFold(adv.Package, "linux")
		if isKernelAdv {
			if inv.OSContext.OSFamily == "darwin" {
				continue
			}
			for _, kAsset := range assetsByPkg["linux"] {
				if kAsset.Kind == "kernel" && version.IsKernelVulnerable(kAsset.Version, adv) {
					fixedVer := ""
					if len(adv.FixedIn) > 0 {
						fixedVer = strings.Join(adv.FixedIn, " / ")
					}
					addRuntimeMatch(model.VulnerabilityMatch{
						ID:               adv.DisplayID(),
						AdvisoryID:       adv.ID,
						CVEID:            adv.CVEID,
						GHSAID:           adv.GHSAID,
						CVE:              adv.DisplayID(),
						Package:          "linux",
						Ecosystem:        model.EcoLinux,
						Location:         "kernel",
						InstalledVersion: kAsset.Version,
						FixedVersion:     fixedVer,
						VulnerableRange:  adv.VulnerableRange,
						FixedIn:          adv.FixedIn,
						Severity:         adv.Severity,
						CVSS:             adv.CVSS,
						Summary:          adv.Summary,
						URL:              adv.URL,
						IsKernel:         true,
					})
				}
			}
			continue
		}

		normAdvPkg := normalizePkgName(adv.Ecosystem, adv.Package)
		for _, asset := range assetsByPkg[normAdvPkg] {
			if asset.Kind == "os" || asset.Kind == "kernel" {
				continue
			}
			if !ecosystemsCompatible(asset.Ecosystem, adv.Ecosystem) {
				continue
			}
			if adv.VulnerableRange != "" && version.IsVersionVulnerable(adv.Ecosystem, asset.Version, adv.VulnerableRange) {
				if isWorkspaceDevAsset(asset) {
					addWSHit(asset, adv)
					continue
				}
				fixedVer := ""
				if len(adv.FixedIn) > 0 {
					fixedVer = adv.FixedIn[0]
				}
				addRuntimeMatch(model.VulnerabilityMatch{
					ID:               adv.DisplayID(),
					AdvisoryID:       adv.ID,
					CVEID:            adv.CVEID,
					GHSAID:           adv.GHSAID,
					CVE:              adv.DisplayID(),
					Package:          asset.Name,
					Ecosystem:        asset.Ecosystem,
					Location:         shortenLocation(asset.Location),
					InstalledVersion: asset.Version,
					FixedVersion:     fixedVer,
					VulnerableRange:  adv.VulnerableRange,
					FixedIn:          adv.FixedIn,
					Severity:         adv.Severity,
					CVSS:             adv.CVSS,
					Summary:          adv.Summary,
					URL:              adv.URL,
				})
			}
		}
	}

	// 2. Match OSV Batch hits (grouped cleanly into Dev Workspace Projects)
	for _, asset := range inv.Assets {
		if !isOSVQueryableAsset(asset) {
			continue
		}
		qk := intel.QueryKey(asset.Ecosystem, asset.Name, asset.Version)
		for _, adv := range osvHits[qk] {
			if adv.Severity != "CRITICAL" && adv.Severity != "HIGH" {
				if !(asset.Ecosystem == model.EcoMaven && adv.Severity == "MEDIUM") {
					continue
				}
			}
			addWSHit(asset, adv)
		}
	}

	// Build 2-level aggregated WorkspaceProjects (Project -> Unique Package)!
	res.WorkspaceProjects = buildWorkspaceProjectAudits(wsHits)

	// 3. Merge OS-level security updates (Debian/Ubuntu *-security, RHEL, OpenWrt, Darwin Homebrew security whitelist)
	for _, u := range inv.OSSecurity.Updates {
		cveTag := u.CVEID
		if cveTag == "" {
			cveTag = "SEC-UPDATE-" + u.Package
		}
		urlStr := ""
		if strings.HasPrefix(cveTag, "CVE-") && inv.OSContext.OSFamily == "debian" {
			urlStr = "https://security-tracker.debian.org/tracker/" + cveTag
		} else if strings.HasPrefix(cveTag, "CVE-") {
			urlStr = "https://cve.org/CVERecord/?id=" + cveTag
		}
		addRuntimeMatch(model.VulnerabilityMatch{
			ID:               cveTag,
			AdvisoryID:       cveTag,
			CVEID:            u.CVEID,
			CVE:              cveTag,
			Package:          u.Package,
			SourcePackage:    u.SourcePackage,
			Ecosystem:        inv.OSContext.OSFamily,
			Location:         inv.OSContext.PkgMgr,
			InstalledVersion: u.InstalledVersion,
			FixedVersion:     u.CandidateVersion,
			VulnerableRange:  "< " + u.CandidateVersion,
			FixedIn:          []string{u.CandidateVersion},
			Severity:         u.Severity,
			CVSS:             u.CVSS,
			Summary:          u.Summary,
			URL:              urlStr,
			IsOSPackage:      true,
			IsKernel:         u.IsKernel,
			RemediationCmd:   u.RemediationCmd,
			LockdownWarning:  u.LockdownWarning,
		})
	}

	sort.SliceStable(runtimeMatches, func(i, j int) bool {
		ri := severityRank(runtimeMatches[i].Severity)
		rj := severityRank(runtimeMatches[j].Severity)
		if ri != rj {
			return ri > rj
		}
		if runtimeMatches[i].IsOSPackage != runtimeMatches[j].IsOSPackage {
			return runtimeMatches[i].IsOSPackage
		}
		return runtimeMatches[i].EffectiveID() < runtimeMatches[j].EffectiveID()
	})

	// 4. Reconcile applied mitigations & detect retirable workarounds
	appliedSet := make(map[string]bool)
	for k := range inv.AppliedMitigations {
		appliedSet[strings.ToUpper(strings.ReplaceAll(k, "_", "-"))] = true
	}
	if mem != nil {
		for k := range mem.AppliedMitigationsForHost(inv.Target.EffectiveKey()) {
			appliedSet[strings.ToUpper(strings.ReplaceAll(k, "_", "-"))] = true
		}
	}

	matchedCVESet := make(map[string]bool)
	var unmitigated, mitigated, ignored []model.VulnerabilityMatch
	hostKey := inv.Target.EffectiveKey()
	for _, m := range runtimeMatches {
		key := strings.ToUpper(strings.ReplaceAll(m.EffectiveID(), "_", "-"))
		matchedCVESet[key] = true
		if appliedSet[key] {
			m.Mitigated = true
			m.Action = "现场规避加固已生效"
			mitigated = append(mitigated, m)
			continue
		}
		if mem != nil {
			if isMuted, muteNote := mem.MatchIgnoreRule(hostKey, m); isMuted {
				m.Status = "已豁免/忽略"
				m.Reason = muteNote
				ignored = append(ignored, m)
				continue
			}
		}
		unmitigated = append(unmitigated, m)
	}

	for appliedCVE := range inv.AppliedMitigations {
		norm := strings.ToUpper(strings.ReplaceAll(appliedCVE, "_", "-"))
		if strings.HasPrefix(norm, "CVE-") && !matchedCVESet[norm] {
			if adv, known := advisories[norm]; known {
				isPatchedNow := false
				if strings.EqualFold(adv.Ecosystem, model.EcoLinux) && inv.OSContext.KernelRelease != "" {
					isPatchedNow = !version.IsKernelVulnerable(inv.OSContext.KernelRelease, adv)
				}
				if isPatchedNow {
					res.RetirableMitigations = append(res.RetirableMitigations, norm)
				}
			}
		}
	}
	sort.Strings(res.RetirableMitigations)

	res.Vulnerabilities = unmitigated
	res.UnmitigatedItems = unmitigated
	res.MitigatedVulnerabilities = mitigated
	res.FixedItems = mitigated
	res.IgnoredItems = ignored

	// Count active vs archived workspace projects for calm, non-alarmist summary note
	activeProjCount, activePkgCount := 0, 0
	for _, wp := range res.WorkspaceProjects {
		if !wp.Archived {
			activeProjCount++
			activePkgCount += len(wp.Packages)
		}
	}

	// 5. Compute host runtime status, detail summary, and 0-100 health score
	switch {
	case len(unmitigated) > 0:
		allOSUpdates := true
		for _, v := range unmitigated {
			if !v.IsOSPackage {
				allOSUpdates = false
				break
			}
		}
		if inv.OSContext.LockdownMode && allOSUpdates {
			res.Status = model.StatusManualRequired
			res.Detail = fmt.Sprintf("硬件安全熔断: %s", inv.OSContext.LockdownReason)
		} else if allOSUpdates {
			res.Status = model.StatusPendingUpdate
			var tags []string
			for i, v := range unmitigated {
				if i >= 3 {
					break
				}
				tags = append(tags, fmt.Sprintf("%s(%s➔%s)", v.Package, v.InstalledVersion, v.FixedVersion))
			}
			res.Detail = fmt.Sprintf("发现 %d 项官方安全补丁待安装: %s", len(unmitigated), strings.Join(tags, ", "))
		} else {
			res.Status = model.StatusVulnerable
			var tags []string
			for i, v := range unmitigated {
				if i >= 3 {
					break
				}
				tags = append(tags, fmt.Sprintf("%s %s(%s)", v.EffectiveID(), v.Package, v.InstalledVersion))
			}
			res.Detail = fmt.Sprintf("命中 %d 项系统/运行面高危风险: %s", len(unmitigated), strings.Join(tags, ", "))
		}
	case len(mitigated) > 0:
		res.Status = model.StatusImmunized
		var ids []string
		for _, m := range mitigated {
			ids = append(ids, m.EffectiveID())
		}
		res.CVEs = ids
		res.Detail = fmt.Sprintf("已规避加固 %s (加固与回滚脚本已归档 · 网络正常)", strings.Join(ids, ", "))
	case inv.OSContext.RebootRequired:
		res.Status = model.StatusPendingUpdate
		res.Detail = "内核或底层安全更新已就绪，待平滑滚动重启生效"
	default:
		res.Status = model.StatusClean
		res.Detail = fmt.Sprintf("系统、内核与运行态服务 100%% 安全 (%d 项组件已核验)", maxInt(len(inv.Packages), 1))
		if inv.OSContext.OptionalMajorUpgrade != "" {
			res.Detail += fmt.Sprintf(" · ℹ️ 可选跨代升级 %s", inv.OSContext.OptionalMajorUpgrade)
		}
		if len(ignored) > 0 {
			res.Detail += fmt.Sprintf(" · 🔕 已豁免/暂缓 %d 项", len(ignored))
		}
		if activeProjCount > 0 {
			res.Detail += fmt.Sprintf(" · 💡 %d 个近期活跃开发项目有 %d 个依赖包建议升级", activeProjCount, activePkgCount)
		}
		if len(inv.OrphanedVenvs) > 0 {
			res.Detail += fmt.Sprintf(" · 🧹 发现 %d 个可清理孤儿虚拟环境", len(inv.OrphanedVenvs))
		}
	}

	if len(res.RetirableMitigations) > 0 {
		res.Detail += fmt.Sprintf(" · 💡 %s 官方补丁已就位，可一键退役临时规避规则", strings.Join(res.RetirableMitigations, ","))
	}

	res.HealthScore = computeHostScore(unmitigated, inv.OSContext.RebootRequired)
	return res
}

func buildWorkspaceProjectAudits(hits []wsRawHit) []model.WorkspaceProjectAudit {
	if len(hits) == 0 {
		return nil
	}

	type projAccum struct {
		proj          model.WorkspaceProjectAudit
		pkgs          map[string]*model.WorkspacePackageFix
		manifestKinds map[string]bool
	}
	byProj := make(map[string]*projAccum)

	for _, h := range hits {
		a := h.asset
		adv := h.adv

		projDir := a.ProjectDir
		projName := a.ProjectName
		mKind := a.ManifestKind
		if projDir == "" {
			if a.Location == "global-pip" {
				projDir = "global-pip"
				projName = "本机全局 Python pip"
				mKind = "global-pip"
			} else {
				projDir = filepath.Dir(a.Location)
				projName = filepath.Base(projDir)
				mKind = a.Kind
			}
		}

		acc, exists := byProj[projDir]
		if !exists {
			acc = &projAccum{
				proj: model.WorkspaceProjectAudit{
					ProjectName:    projName,
					ProjectDir:     projDir,
					LastActiveDays: a.LastActiveDays,
					ModifiedUnix:   a.ModifiedUnix,
					CreatedUnix:    a.CreatedUnix,
					Archived:       a.Archived,
				},
				pkgs:          make(map[string]*model.WorkspacePackageFix),
				manifestKinds: make(map[string]bool),
			}
			byProj[projDir] = acc
		}

		resolvedKind := resolvePackageManifestKind(mKind, a.Ecosystem, projDir)
		if resolvedKind != "" {
			acc.manifestKinds[resolvedKind] = true
		}

		pkgKey := strings.ToLower(a.Name)
		pf, ok := acc.pkgs[pkgKey]
		if !ok {
			pf = &model.WorkspacePackageFix{
				Package:          a.Name,
				Ecosystem:        a.Ecosystem,
				ManifestKind:     resolvedKind,
				InstalledVersion: a.Version,
				Severity:         adv.Severity,
				Summary:          adv.Summary,
			}
			acc.pkgs[pkgKey] = pf
		} else if pf.ManifestKind == "" && resolvedKind != "" {
			pf.ManifestKind = resolvedKind
		}

		// Merge CVE IDs
		cid := adv.DisplayID()
		hasCVE := false
		for _, existingID := range pf.CVEIDs {
			if existingID == cid {
				hasCVE = true
				break
			}
		}
		if cid != "" && !hasCVE {
			pf.CVEIDs = append(pf.CVEIDs, cid)
			acc.proj.TotalCVEs++
		}

		// Keep highest severity
		if severityRank(adv.Severity) > severityRank(pf.Severity) {
			pf.Severity = adv.Severity
			if adv.Summary != "" {
				pf.Summary = adv.Summary
			}
		}

		// Keep highest fixed version belonging to THIS exact package (avoid cross-polluting stdlib versions onto Go modules!)
		candFixes := adv.FixedIn
		if len(adv.FixedByPkg) > 0 {
			if specific, ok := adv.FixedByPkg[strings.ToLower(a.Name)]; ok && len(specific) > 0 {
				candFixes = specific
			}
		}
		for _, fv := range candFixes {
			fv = strings.TrimSpace(fv)
			if fv == "" {
				continue
			}
			if pf.FixedVersion == "" || version.Compare(a.Ecosystem, fv, pf.FixedVersion) > 0 {
				pf.FixedVersion = fv
			}
		}
	}

	var out []model.WorkspaceProjectAudit
	for _, acc := range byProj {
		// Calculate project's combined ManifestKind (e.g. "gomod+venv" or "gomod")
		var kinds []string
		for k := range acc.manifestKinds {
			kinds = append(kinds, k)
		}
		sort.Strings(kinds)
		if len(kinds) > 0 {
			acc.proj.ManifestKind = strings.Join(kinds, "+")
		}

		for _, pf := range acc.pkgs {
			sort.Strings(pf.CVEIDs)
			pkgKind := pf.ManifestKind
			if pkgKind == "" {
				pkgKind = resolvePackageManifestKind(acc.proj.ManifestKind, pf.Ecosystem, acc.proj.ProjectDir)
				pf.ManifestKind = pkgKind
			}
			pf.UpgradeCmd = BuildPackageUpgradeCmd(pkgKind, acc.proj.ProjectDir, pf.Package, pf.FixedVersion)
			populatePackageUpgradeDiagnostics(pf, acc.proj.ProjectDir)
			acc.proj.Packages = append(acc.proj.Packages, *pf)
		}
		sort.Slice(acc.proj.Packages, func(i, j int) bool {
			ri := severityRank(acc.proj.Packages[i].Severity)
			rj := severityRank(acc.proj.Packages[j].Severity)
			if ri != rj {
				return ri > rj
			}
			if len(acc.proj.Packages[i].CVEIDs) != len(acc.proj.Packages[j].CVEIDs) {
				return len(acc.proj.Packages[i].CVEIDs) > len(acc.proj.Packages[j].CVEIDs)
			}
			return acc.proj.Packages[i].Package < acc.proj.Packages[j].Package
		})
		out = append(out, acc.proj)
	}

	// Sort order:
	// 1. Active projects (!Archived) before Archived
	// 2. Most recently modified first (ModifiedUnix DESC)
	// 3. Earlier creation time first (CreatedUnix ASC, "创建时间靠前的排前面")
	sort.Slice(out, func(i, j int) bool {
		if out[i].Archived != out[j].Archived {
			return !out[i].Archived
		}
		if out[i].ModifiedUnix != out[j].ModifiedUnix {
			return out[i].ModifiedUnix > out[j].ModifiedUnix
		}
		if out[i].CreatedUnix != out[j].CreatedUnix {
			if out[i].CreatedUnix > 0 && out[j].CreatedUnix > 0 {
				return out[i].CreatedUnix < out[j].CreatedUnix
			}
		}
		if out[i].LastActiveDays != out[j].LastActiveDays {
			return out[i].LastActiveDays < out[j].LastActiveDays
		}
		return out[i].ProjectName < out[j].ProjectName
	})
	return out
}

// AuditSingleWorkspaceProject quickly re-audits ONLY one project's assets via OSV (<1s after 1-click GUI upgrade!).
func AuditSingleWorkspaceProject(ctx context.Context, assets []model.AssetItem, intelCli *intel.Client) *model.WorkspaceProjectAudit {
	if len(assets) == 0 || intelCli == nil {
		return nil
	}
	var queries []intel.OSVQuery
	for _, a := range assets {
		if isOSVQueryableAsset(a) {
			queries = append(queries, intel.OSVQuery{
				Ecosystem: a.Ecosystem,
				Name:      a.Name,
				Version:   a.Version,
			})
		}
	}
	if len(queries) == 0 {
		return nil
	}
	osvHits := intelCli.QueryOSVAssets(ctx, queries)
	var hits []wsRawHit
	for _, a := range assets {
		qk := intel.QueryKey(a.Ecosystem, a.Name, a.Version)
		for _, adv := range osvHits[qk] {
			if adv.Severity == "CRITICAL" || adv.Severity == "HIGH" || (a.Ecosystem == model.EcoMaven && adv.Severity == "MEDIUM") {
				hits = append(hits, wsRawHit{asset: a, adv: adv})
			}
		}
	}
	projs := buildWorkspaceProjectAudits(hits)
	if len(projs) == 0 {
		return nil
	}
	return &projs[0]
}

// resolvePackageManifestKind returns the guaranteed correct package manifest type for a given package,
// preventing multi-stack / hybrid projects (such as Go desktop apps containing a Python worker in .venv)
// from confusing tools like `go get` with Python packages.
func resolvePackageManifestKind(mKind, ecosystem, projectDir string) string {
	switch ecosystem {
	case model.EcoGo:
		return "gomod"
	case model.EcoPyPI:
		if mKind == "uv" || mKind == "poetry" || mKind == "venv" || mKind == "global-pip" {
			return mKind
		}
		if projectDir == "global-pip" {
			return "global-pip"
		}
		if projectDir != "" {
			if _, err := os.Stat(filepath.Join(projectDir, "uv.lock")); err == nil {
				return "uv"
			}
			if _, err := os.Stat(filepath.Join(projectDir, "poetry.lock")); err == nil {
				return "poetry"
			}
		}
		return "venv"
	case model.EcoNPM:
		if mKind == "npm" || mKind == "pnpm" || mKind == "yarn" {
			return mKind
		}
		if projectDir != "" {
			if _, err := os.Stat(filepath.Join(projectDir, "pnpm-lock.yaml")); err == nil {
				return "pnpm"
			}
			if _, err := os.Stat(filepath.Join(projectDir, "yarn.lock")); err == nil {
				return "yarn"
			}
		}
		return "npm"
	case model.EcoCrates:
		return "cargo"
	case model.EcoMaven:
		if mKind == "maven" || mKind == "gradle" {
			return mKind
		}
		if projectDir != "" {
			if _, err := os.Stat(filepath.Join(projectDir, "build.gradle")); err == nil {
				return "gradle"
			}
			if _, err := os.Stat(filepath.Join(projectDir, "build.gradle.kts")); err == nil {
				return "gradle"
			}
		}
		return "maven"
	case model.EcoPackagist:
		return "composer"
	case model.EcoRubyGems:
		return "bundler"
	case model.EcoNuGet:
		return "nuget"
	case model.EcoSwift:
		return "swift"
	default:
		if mKind != "" {
			return mKind
		}
		return ""
	}
}

// BuildPackageUpgradeCmd builds the exact non-destructive CLI command to upgrade a single project dependency.
func BuildPackageUpgradeCmd(manifestKind, projectDir, pkg, fixedVer string) string {
	// Guard against composite manifestKind (e.g. "gomod+venv")
	if strings.Contains(manifestKind, "+") {
		if strings.Contains(pkg, "/") && strings.Contains(manifestKind, "gomod") {
			manifestKind = "gomod"
		} else if strings.Contains(manifestKind, "venv") {
			manifestKind = "venv"
		} else if strings.Contains(manifestKind, "uv") {
			manifestKind = "uv"
		} else if strings.Contains(manifestKind, "npm") {
			manifestKind = "npm"
		} else {
			parts := strings.Split(manifestKind, "+")
			manifestKind = parts[0]
		}
	}

	// Safety Guard: A Go module path in go.mod always contains a domain dot or slash (e.g. "golang.org/x/net").
	// Plain package names (like "pillow", "urllib3", "requests", "express") can NEVER be upgraded by "go get".
	// If misclassified as gomod, auto-resolve to venv/npm if present in projectDir!
	if manifestKind == "gomod" && !strings.Contains(pkg, "/") && !strings.Contains(pkg, ".") {
		if projectDir != "" {
			if _, err := os.Stat(filepath.Join(projectDir, ".venv")); err == nil {
				manifestKind = "venv"
			} else if _, err := os.Stat(filepath.Join(projectDir, "venv")); err == nil {
				manifestKind = "venv"
			} else if _, err := os.Stat(filepath.Join(projectDir, "uv.lock")); err == nil {
				manifestKind = "uv"
			} else if _, err := os.Stat(filepath.Join(projectDir, "package.json")); err == nil {
				manifestKind = "npm"
			}
		}
	}

	switch manifestKind {
	case "uv":
		return fmt.Sprintf("uv lock --upgrade-package %s && uv sync", pkg)
	case "poetry":
		return fmt.Sprintf("poetry update %s", pkg)
	case "venv":
		return buildSmartPythonVenvUpgradeCmd([]string{fmt.Sprintf("%q", pkg)})
	case "global-pip":
		return fmt.Sprintf("python3 -m pip install -q -U %q", pkg)
	case "npm":
		if fixedVer != "" {
			return fmt.Sprintf("npm install %s@^%s || npm update %s", pkg, fixedVer, pkg)
		}
		return fmt.Sprintf("npm update %s", pkg)
	case "pnpm":
		return fmt.Sprintf("pnpm up %s", pkg)
	case "yarn":
		return fmt.Sprintf("yarn upgrade %s", pkg)
	case "gomod":
		verSpec := "latest"
		if fixedVer != "" {
			verSpec = "v" + strings.TrimPrefix(fixedVer, "v")
		}
		return fmt.Sprintf("(go get %s@%s || go get -u %s) && go mod tidy", pkg, verSpec, pkg)
	case "cargo":
		return fmt.Sprintf("cargo update -p %s", pkg)
	case "composer":
		return fmt.Sprintf("composer update %s --with-all-dependencies", pkg)
	case "bundler":
		return fmt.Sprintf("bundle update %s", pkg)
	case "maven":
		if fixedVer != "" {
			return fmt.Sprintf("mvn versions:use-dep-version -Dincludes=%s -DdepVersion=%s -DforceVersion=true", pkg, fixedVer)
		}
		return fmt.Sprintf("mvn versions:use-latest-releases -Dincludes=%s", pkg)
	case "gradle":
		return fmt.Sprintf("./gradlew dependencyUpdates || gradle dependencies")
	default:
		return fmt.Sprintf("# 请在 %s 中将 %s 升级至 %s", projectDir, pkg, fixedVer)
	}
}

// BuildProjectBatchUpgradeCmd builds a single fast batch command to upgrade all vulnerable packages in one project.
// In hybrid / multi-stack projects (e.g. Go backend + Python .venv worker, or Node + Go), packages are
// grouped by their own manifest kind so each tool (go get, uv pip, npm, etc.) runs cleanly without cross-contaminating!
func BuildProjectBatchUpgradeCmd(proj model.WorkspaceProjectAudit) string {
	if len(proj.Packages) == 0 {
		return ""
	}

	pkgsByKind := make(map[string][]model.WorkspacePackageFix)
	for _, p := range proj.Packages {
		k := p.ManifestKind
		if k == "" {
			k = resolvePackageManifestKind(proj.ManifestKind, p.Ecosystem, proj.ProjectDir)
		}
		if k == "" {
			k = proj.ManifestKind
		}
		pkgsByKind[k] = append(pkgsByKind[k], p)
	}

	var kinds []string
	for k := range pkgsByKind {
		kinds = append(kinds, k)
	}
	sort.Slice(kinds, func(i, j int) bool {
		if kinds[i] == "gomod" {
			return true
		}
		if kinds[j] == "gomod" {
			return false
		}
		return kinds[i] < kinds[j]
	})

	var subCmds []string
	for _, k := range kinds {
		cmd := buildManifestBatchUpgradeCmd(k, proj.ProjectDir, pkgsByKind[k])
		if cmd != "" {
			subCmds = append(subCmds, cmd)
		}
	}
	return strings.Join(subCmds, " && ")
}

func buildManifestBatchUpgradeCmd(manifestKind, projectDir string, pkgs []model.WorkspacePackageFix) string {
	if len(pkgs) == 0 {
		return ""
	}
	var names []string
	var quotedNames []string
	for _, p := range pkgs {
		names = append(names, p.Package)
		quotedNames = append(quotedNames, fmt.Sprintf("%q", p.Package))
	}
	switch manifestKind {
	case "uv":
		var flags []string
		for _, n := range names {
			flags = append(flags, "--upgrade-package "+n)
		}
		return "uv lock " + strings.Join(flags, " ") + " && uv sync"
	case "poetry":
		return "poetry update " + strings.Join(names, " ")
	case "venv":
		return buildSmartPythonVenvUpgradeCmd(quotedNames)
	case "global-pip":
		return "python3 -m pip install -q -U " + strings.Join(quotedNames, " ")
	case "npm":
		return "npm update " + strings.Join(names, " ")
	case "pnpm":
		return "pnpm up " + strings.Join(names, " ")
	case "yarn":
		return "yarn upgrade " + strings.Join(names, " ")
	case "cargo":
		var flags []string
		for _, n := range names {
			flags = append(flags, "-p "+n)
		}
		return "cargo update " + strings.Join(flags, " ")
	case "gomod":
		var gets []string
		for _, p := range pkgs {
			verSpec := "latest"
			if p.FixedVersion != "" {
				verSpec = "v" + strings.TrimPrefix(p.FixedVersion, "v")
			}
			gets = append(gets, fmt.Sprintf("(go get %s@%s || go get -u %s)", p.Package, verSpec, p.Package))
		}
		return strings.Join(gets, " && ") + " && go mod tidy"
	case "composer":
		return "composer update " + strings.Join(names, " ") + " --with-all-dependencies"
	case "bundler":
		return "bundle update " + strings.Join(names, " ")
	default:
		var cmds []string
		for _, p := range pkgs {
			if p.UpgradeCmd != "" {
				cmds = append(cmds, p.UpgradeCmd)
			} else {
				cmds = append(cmds, BuildPackageUpgradeCmd(manifestKind, projectDir, p.Package, p.FixedVersion))
			}
		}
		return strings.Join(cmds, " && ")
	}
}

func buildSmartPythonVenvUpgradeCmd(quotedPkgs []string) string {
	pkgList := strings.Join(quotedPkgs, " ")
	// 1. Prefer `uv pip install --python "$PY" -U` (10-20x faster AND supports `uv venv` environments that have no `pip` module!)
	// 2. Fallback to `"$PY" -m pip install -q -U`
	// 3. Self-heal via `"$PY" -m ensurepip` if neither `uv` nor `pip` is present
	return fmt.Sprintf(
		`PY="./.venv/bin/python"; [ -x "$PY" ] || PY="./venv/bin/python"; `+
			`if command -v uv >/dev/null 2>&1; then uv pip install --python "$PY" -U %s; `+
			`elif "$PY" -m pip --version >/dev/null 2>&1; then "$PY" -m pip install -q -U %s; `+
			`else "$PY" -m ensurepip >/dev/null 2>&1 && "$PY" -m pip install -q -U %s; fi`,
		pkgList, pkgList, pkgList,
	)
}

func parseSemverMajor(ver string) (int, bool) {
	v := strings.TrimSpace(ver)
	v = strings.TrimPrefix(strings.TrimPrefix(v, "v"), "V")
	if v == "" {
		return 0, false
	}
	dotIdx := strings.IndexAny(v, ".-+")
	head := v
	if dotIdx >= 0 {
		head = v[:dotIdx]
	}
	n, err := strconv.Atoi(head)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

func isMajorVersionUpgrade(manifestKind, installedVer, fixedVer string) (isMajor bool, instMajor, fixMajor int) {
	if installedVer == "" || fixedVer == "" {
		return false, 0, 0
	}
	// Unconstrained pip/uv venv installs (`pip install -U`) automatically cross major versions without SemVer `^` lock
	if manifestKind == "venv" || manifestKind == "global-pip" {
		return false, 0, 0
	}
	im, ok1 := parseSemverMajor(installedVer)
	fm, ok2 := parseSemverMajor(fixedVer)
	if !ok1 || !ok2 {
		return false, 0, 0
	}
	if manifestKind == "gomod" {
		// In Go modules, v0 -> v1 uses the same import path; v2+ requires module path suffix changes (e.g. /v2, /v5)
		if fm > im && fm >= 2 {
			return true, im, fm
		}
		return false, im, fm
	}
	if fm > im && fm >= 1 {
		return true, im, fm
	}
	return false, im, fm
}

func isPackageTransitiveInProject(projectDir, manifestKind, pkgName string) bool {
	if projectDir == "" || projectDir == "global-pip" || pkgName == "" {
		return false
	}
	switch manifestKind {
	case "npm", "pnpm", "yarn":
		data, err := os.ReadFile(filepath.Join(projectDir, "package.json"))
		if err != nil {
			return false
		}
		var doc struct {
			Dependencies         map[string]any `json:"dependencies"`
			DevDependencies      map[string]any `json:"devDependencies"`
			PeerDependencies     map[string]any `json:"peerDependencies"`
			OptionalDependencies map[string]any `json:"optionalDependencies"`
		}
		if err := json.Unmarshal(data, &doc); err != nil {
			return false
		}
		if _, ok := doc.Dependencies[pkgName]; ok {
			return false
		}
		if _, ok := doc.DevDependencies[pkgName]; ok {
			return false
		}
		if _, ok := doc.PeerDependencies[pkgName]; ok {
			return false
		}
		if _, ok := doc.OptionalDependencies[pkgName]; ok {
			return false
		}
		return true

	case "gomod":
		data, err := os.ReadFile(filepath.Join(projectDir, "go.mod"))
		if err != nil {
			return false
		}
		for _, line := range strings.Split(string(data), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") || trimmed == "" {
				continue
			}
			trimmed = strings.TrimSpace(strings.TrimPrefix(trimmed, "require "))
			fields := strings.Fields(trimmed)
			if len(fields) >= 2 && fields[0] == pkgName {
				return strings.Contains(line, "// indirect")
			}
		}
		return true

	case "uv", "poetry":
		data, err := os.ReadFile(filepath.Join(projectDir, "pyproject.toml"))
		if err != nil {
			return false
		}
		normPkg := strings.ToLower(strings.ReplaceAll(pkgName, "_", "-"))
		normDoc := strings.ToLower(strings.ReplaceAll(string(data), "_", "-"))
		return !strings.Contains(normDoc, normPkg)

	case "cargo":
		data, err := os.ReadFile(filepath.Join(projectDir, "Cargo.toml"))
		if err != nil {
			return false
		}
		normPkg := strings.ToLower(strings.ReplaceAll(pkgName, "_", "-"))
		normDoc := strings.ToLower(strings.ReplaceAll(string(data), "_", "-"))
		return !strings.Contains(normDoc, normPkg)
	}
	return false
}

func populatePackageUpgradeDiagnostics(pf *model.WorkspacePackageFix, projectDir string) {
	if pf == nil {
		return
	}
	isMaj, instMaj, fixMaj := isMajorVersionUpgrade(pf.ManifestKind, pf.InstalledVersion, pf.FixedVersion)
	isTrans := isPackageTransitiveInProject(projectDir, pf.ManifestKind, pf.Package)
	pf.MajorUpgrade = isMaj
	pf.Transitive = isTrans

	switch {
	case pf.FixedVersion == "":
		pf.UpgradeHint = "官方未出补丁"
	case pf.ManifestKind == "gomod" && isMaj && fixMaj >= 2:
		if isTrans {
			pf.UpgradeHint = fmt.Sprintf("间接依赖·跨v%d➔v%d", instMaj, fixMaj)
		} else {
			pf.UpgradeHint = fmt.Sprintf("跨v%d➔v%d·需改import路径", instMaj, fixMaj)
		}
	case isMaj && isTrans:
		pf.UpgradeHint = fmt.Sprintf("间接依赖·跨v%d➔v%d", instMaj, fixMaj)
	case isMaj:
		pf.UpgradeHint = fmt.Sprintf("需跨大版本 v%d➔v%d", instMaj, fixMaj)
	case isTrans:
		pf.UpgradeHint = "间接依赖"
	}
}

func formatDiagPkgList(items []string, limit int) string {
	if len(items) == 0 {
		return ""
	}
	if len(items) <= limit {
		return strings.Join(items, ", ")
	}
	return fmt.Sprintf("%s 等 %d 个包", strings.Join(items[:limit], ", "), len(items))
}

// DiagnoseWorkspaceUpgradeOutcome analyzes pre/post upgrade package states, manifest constraints, and command output
// to provide a concrete, human-friendly explanation when some or all packages remain vulnerable after 1-click upgrade.
func DiagnoseWorkspaceUpgradeOutcome(
	projectDir, manifestKind string,
	prevPkgCount int,
	remPkgs []model.WorkspacePackageFix,
	outBytes []byte,
	cmdErr error,
) string {
	remCount := len(remPkgs)
	if remCount == 0 {
		return "closed"
	}

	outStr := string(outBytes)
	conflictNote := ""
	switch {
	case strings.Contains(outStr, "ERESOLVE") || strings.Contains(outStr, "Conflicting peer dependency") || strings.Contains(outStr, "peer dep"):
		conflictNote = "依赖树版本冲突 (ERESOLVE peer dependency)"
	case strings.Contains(outStr, "ResolutionImpossible") || strings.Contains(outStr, "NoSolutionFound") || strings.Contains(outStr, "version solving failed"):
		conflictNote = "Python 依赖解析器检测到版本上下限冲突"
	case strings.Contains(outStr, "module path must match major version") || strings.Contains(outStr, "invalid version"):
		conflictNote = "Go v2+ 大版本要求模块路径带 /vN 后缀"
	case strings.Contains(outStr, "requires go >="):
		conflictNote = "目标安全版本要求的 Go 版本高于当前 go.mod"
	case strings.Contains(outStr, "ETIMEDOUT") || strings.Contains(outStr, "ECONNRESET") || strings.Contains(outStr, "EAI_AGAIN") || strings.Contains(outStr, "TLS handshake timeout") || strings.Contains(outStr, "dial tcp"):
		conflictNote = "包管理器连接生态镜像源超时或网络不可达"
	}

	var unfixedList []string
	var majorDirectList []string
	var majorTransList []string
	var transList []string
	var constrainedList []string

	for i := range remPkgs {
		p := remPkgs[i]
		if p.UpgradeHint == "" && !p.MajorUpgrade && !p.Transitive {
			populatePackageUpgradeDiagnostics(&p, projectDir)
		}
		label := p.Package
		if p.FixedVersion != "" {
			label = fmt.Sprintf("%s(%s➔%s)", p.Package, p.InstalledVersion, p.FixedVersion)
		} else {
			label = fmt.Sprintf("%s(%s)", p.Package, p.InstalledVersion)
		}

		switch {
		case p.FixedVersion == "":
			unfixedList = append(unfixedList, label)
		case p.MajorUpgrade && p.Transitive:
			majorTransList = append(majorTransList, label)
		case p.MajorUpgrade:
			majorDirectList = append(majorDirectList, label)
		case p.Transitive:
			transList = append(transList, label)
		default:
			constrainedList = append(constrainedList, label)
		}
	}

	var reasons []string
	if conflictNote != "" {
		reasons = append(reasons, conflictNote)
	}
	if len(majorDirectList) > 0 {
		reasons = append(reasons, fmt.Sprintf("[需跨大版本] %s", formatDiagPkgList(majorDirectList, 2)))
	}
	if len(majorTransList) > 0 {
		reasons = append(reasons, fmt.Sprintf("[间接依赖·跨大版本被锁死] %s", formatDiagPkgList(majorTransList, 2)))
	}
	if len(transList) > 0 {
		reasons = append(reasons, fmt.Sprintf("[间接子依赖被上层包锁死] %s", formatDiagPkgList(transList, 2)))
	}
	if len(unfixedList) > 0 {
		reasons = append(reasons, fmt.Sprintf("[官方尚未发布修复补丁] %s", formatDiagPkgList(unfixedList, 2)))
	}
	if len(constrainedList) > 0 {
		reasons = append(reasons, fmt.Sprintf("[受项目版本上限约束] %s", formatDiagPkgList(constrainedList, 2)))
	}

	var actionTip string
	switch {
	case len(unfixedList) == remCount:
		actionTip = "建议点击「暂缓 30 天」或豁免等待官方发版"
	case strings.Contains(manifestKind, "npm") || strings.Contains(manifestKind, "pnpm") || strings.Contains(manifestKind, "yarn"):
		if len(majorTransList) > 0 || len(transList) > 0 {
			actionTip = "需在 package.json 配置 overrides 强制覆盖子依赖，或升级顶层包"
		} else if len(majorDirectList) > 0 {
			actionTip = "默认 update 不跨主版本，请修改 package.json 版本范围后执行 npm i"
		}
	case strings.Contains(manifestKind, "gomod"):
		if len(majorDirectList) > 0 || len(majorTransList) > 0 {
			actionTip = "Go v2+ 需修改 import 路径后缀 (如 /v5) 或升级上层依赖"
		}
	case strings.Contains(manifestKind, "uv") || strings.Contains(manifestKind, "poetry") || strings.Contains(manifestKind, "venv"):
		if len(majorDirectList) > 0 || len(majorTransList) > 0 || len(transList) > 0 || len(constrainedList) > 0 {
			actionTip = "请放宽 pyproject.toml 版本上限约束或升级锁定它的上层包"
		}
	}

	detail := strings.Join(reasons, "；")
	if actionTip != "" {
		detail += " — " + actionTip
	}

	if prevPkgCount > remCount {
		return fmt.Sprintf("partial:已成功升级修复 %d 个包！剩余 %d 项未升：%s", prevPkgCount-remCount, remCount, detail)
	}
	if cmdErr != nil && conflictNote == "" {
		tail := strings.TrimSpace(outStr)
		if lines := strings.Split(tail, "\n"); len(lines) > 0 {
			tail = strings.TrimSpace(lines[len(lines)-1])
		}
		if len(tail) > 75 {
			tail = tail[:75] + "..."
		}
		if tail != "" {
			return fmt.Sprintf("warn:命令返回报错 (%s)，剩余 %d 项：%s", tail, remCount, detail)
		}
	}
	return fmt.Sprintf("warn:未自动闭环 (共 %d 项)：%s", remCount, detail)
}

func computeHostScore(unmitigated []model.VulnerabilityMatch, rebootReq bool) int {
	score := 100
	for _, v := range unmitigated {
		switch v.Severity {
		case "CRITICAL":
			score -= 22
		case "HIGH":
			score -= 12
		default:
			score -= 6
		}
	}
	if rebootReq {
		score -= 5
	}
	if score < 15 && len(unmitigated) > 0 {
		score = 15
	}
	return score
}

func severityRank(sev string) int {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	default:
		return 1
	}
}

func shortenLocation(loc string) string {
	if loc == "" || !strings.Contains(loc, string(filepath.Separator)) {
		return loc
	}
	dir := filepath.Dir(loc)
	base := filepath.Base(loc)
	if base == ".venv" || base == "venv" || strings.HasSuffix(base, ".json") || strings.HasSuffix(base, ".yaml") || strings.HasSuffix(base, ".lock") || base == "go.mod" {
		return filepath.Base(dir) + "/" + base
	}
	return base
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// FormatRemediationDetail ensures CVE IDs are always explicitly cited in status banners.
func FormatRemediationDetail(cves []string, actionDesc string) string {
	var clean []string
	seen := make(map[string]bool)
	for _, c := range cves {
		c = strings.TrimSpace(c)
		if c != "" && !seen[c] {
			seen[c] = true
			clean = append(clean, c)
		}
	}
	cveStr := "已知高危漏洞"
	if len(clean) > 0 {
		cveStr = strings.Join(clean, ", ")
	}
	if actionDesc != "" {
		return fmt.Sprintf("修复 %s (%s)", cveStr, actionDesc)
	}
	return "修复 " + cveStr
}
