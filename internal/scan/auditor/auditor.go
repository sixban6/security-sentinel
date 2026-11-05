package auditor

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
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
	var unmitigated, mitigated []model.VulnerabilityMatch
	for _, m := range runtimeMatches {
		key := strings.ToUpper(strings.ReplaceAll(m.EffectiveID(), "_", "-"))
		matchedCVESet[key] = true
		if appliedSet[key] {
			m.Mitigated = true
			m.Action = "现场规避加固已生效"
			mitigated = append(mitigated, m)
		} else {
			unmitigated = append(unmitigated, m)
		}
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
		proj model.WorkspaceProjectAudit
		pkgs map[string]*model.WorkspacePackageFix
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
					ManifestKind:   mKind,
					LastActiveDays: a.LastActiveDays,
					ModifiedUnix:   a.ModifiedUnix,
					CreatedUnix:    a.CreatedUnix,
					Archived:       a.Archived,
				},
				pkgs: make(map[string]*model.WorkspacePackageFix),
			}
			byProj[projDir] = acc
		}

		pkgKey := strings.ToLower(a.Name)
		pf, ok := acc.pkgs[pkgKey]
		if !ok {
			pf = &model.WorkspacePackageFix{
				Package:          a.Name,
				Ecosystem:        a.Ecosystem,
				InstalledVersion: a.Version,
				Severity:         adv.Severity,
				Summary:          adv.Summary,
			}
			acc.pkgs[pkgKey] = pf
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
		for _, pf := range acc.pkgs {
			sort.Strings(pf.CVEIDs)
			pf.UpgradeCmd = BuildPackageUpgradeCmd(acc.proj.ManifestKind, acc.proj.ProjectDir, pf.Package, pf.FixedVersion)
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

// BuildPackageUpgradeCmd builds the exact non-destructive CLI command to upgrade a single project dependency.
func BuildPackageUpgradeCmd(manifestKind, projectDir, pkg, fixedVer string) string {
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
func BuildProjectBatchUpgradeCmd(proj model.WorkspaceProjectAudit) string {
	if len(proj.Packages) == 0 {
		return ""
	}
	var names []string
	var quotedNames []string
	for _, p := range proj.Packages {
		names = append(names, p.Package)
		quotedNames = append(quotedNames, fmt.Sprintf("%q", p.Package))
	}
	switch proj.ManifestKind {
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
	case "cargo":
		var flags []string
		for _, n := range names {
			flags = append(flags, "-p "+n)
		}
		return "cargo update " + strings.Join(flags, " ")
	case "gomod":
		var gets []string
		for _, p := range proj.Packages {
			verSpec := "latest"
			if p.FixedVersion != "" {
				verSpec = "v" + strings.TrimPrefix(p.FixedVersion, "v")
			}
			gets = append(gets, fmt.Sprintf("(go get %s@%s || go get -u %s)", p.Package, verSpec, p.Package))
		}
		return strings.Join(gets, " && ") + " && go mod tidy"
	default:
		var cmds []string
		for _, p := range proj.Packages {
			cmds = append(cmds, p.UpgradeCmd)
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
