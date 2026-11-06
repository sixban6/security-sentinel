package gui

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
	"github.com/egoist/mygo/ui/editor"
	"github.com/egoist/mygo/ui/markdown"
	"github.com/sixban6/security-sentinel/internal/heal/ai"
	"github.com/sixban6/security-sentinel/internal/scan/auditor"
	"github.com/sixban6/security-sentinel/internal/infra/config"
	"github.com/sixban6/security-sentinel/internal/ops/doctor"
	"github.com/sixban6/security-sentinel/internal/ops/pipeline"
	"github.com/sixban6/security-sentinel/internal/heal/ha"
	"github.com/sixban6/security-sentinel/internal/scan/inventory/lockfile"
	"github.com/sixban6/security-sentinel/internal/infra/store"
	"github.com/sixban6/security-sentinel/internal/infra/model"
	"github.com/sixban6/security-sentinel/internal/ops/notify"
	"github.com/sixban6/security-sentinel/internal/heal/patch"
	"github.com/sixban6/security-sentinel/internal/ops/report"
	"github.com/sixban6/security-sentinel/internal/infra/secrets"
	"github.com/sixban6/security-sentinel/internal/infra/transport"
	"github.com/sixban6/security-sentinel/internal/ops/updater"
)

// SelectedVulnEntry flattens host + vulnerability for the Triage & Diff surgical workbench.
type SelectedVulnEntry struct {
	HostIndex int
	Host      model.HostAuditResult
	Vuln      model.VulnerabilityMatch
	IsFixed   bool
}

// AppState holds all application & UI state read/mutated on the UI main thread.
type AppState struct {
	Cfg      config.Config
	CfgPath  string
	Mem      *store.Store
	Runner   *pipeline.Runner
	Headless bool // true during ui.NewTester unit tests

	// Windows & Tray
	Tray       *mygo.Tray
	FlyoutWin  *mygo.Window
	MainWin    *mygo.Window
	IsQuitting bool

	// Navigation & Layout
	ActivePage   string
	SidebarWidth float32
	TriageSplit  float32
	HostsSubTab  int // 0: Host Matrix, 1: Doctor Diagnostics
	TriageFilter int // 0: All Pending, 1: OS Patches, 2: Code/Kernel CVE, 3: Fixed/Immunized

	// Core Domain Snapshots
	Report       model.AuditReport
	DoctorItems  []model.DoctorItem
	HistoryItems []model.RemediationRecord
	LastScanAt   time.Time

	// Async Activity Indicators
	Scanning       bool
	ScanStep       int
	ScanTotal      int
	ScanMessage    string
	DoctorRunning  bool
	FixingHost     string
	AIRunning      bool
	HARunning      bool
	Online         bool
	MeteredNetwork bool

	// Triage & DiffViewer State
	SelectedVulnKey string
	LoadedDiffKey   string
	DiffState       *editor.DiffState
	MDOpts          markdown.Options

	// HA Gateway State
	GatewayActiveNode string
	GatewayAllNodes   []string
	GatewayNodeDelays map[string]int
	HAEvents          []model.HAProgressEvent
	HALogScroll       ui.ScrollState

	// Onboarding & Add Host Modals
	ShowSSHModal        bool
	SSHProbing          bool
	SSHProbeDone        int
	SSHProbeTotal       int
	DiscoveredSSH       []config.DiscoveredSSHHost
	SSHFilteredOutCount int
	SelectedSSH         map[string]bool
	ShowAddModal        bool
	NewHostName         string
	NewHostSSH          string
	NewHostPortStr      string

	// Rollback & Trash Project Safety AlertDialogs
	ConfirmRollback     bool
	PendingRollback     *model.RemediationRecord
	ConfirmTrashProject bool
	PendingTrashProject *model.WorkspaceProjectAudit

	// Workspace Dependencies & Zombie Venv Cleaner State
	ShowArchivedProjects bool
	WorkspaceJobStatus   map[string]string // projectDir -> "running" | "queued" | "partial:..." | "warn:..."
	BatchUpgradeRunning  bool
	BatchUpgradeDone     int
	BatchUpgradeTotal    int
	BatchActiveProjects  []string

	// Daily Live CVE Radar State
	DailyAdvisories    map[string]model.Advisory
	CVEFeedLoading     bool
	CVEPushingTG       bool
	CVECategoryTab     int    // 0: All, 1: Language, 2: OS, 3: Kernel
	CVESeverityTab     int    // 0: All, 1: CRITICAL, 2: HIGH, 3: MEDIUM
	CVEEcosystemChoice string // "全部生态" or specific ecosystem
	CVESearchQuery     string
	CVEDaysChoice      string // "昨今两日", "近 1 天", "近 3 天", "近 7 天", "近 14 天"
	CVEListState       ui.ListState

	// Panorama 5-Layer Asset Explorer Modal State
	ShowAssetExplorer     bool
	AssetExplorerLayerTab int
	AssetExplorerHost     string
	AssetExplorerQuery    string
	AssetExplorerList     ui.ListState
	DiscoveredAssetsMap   map[string]model.HostInventory

	// Self-Updater State
	UpdateChecking bool
	UpdateApplying bool
	LatestRelease  *updater.ReleaseInfo
	UpdateMessage  string

	// Settings & Keychain Vault State
	OpenAtLogin       bool
	ScanModeLabel     string
	ScanIntervalLabel string
	DailyScanTimeStr  string
	AdvisoryDaysLabel string
	AutoFixEnabled    bool
	AIEnabled         bool
	AIAutoExec        bool
	AIProvider        string
	AIModel           string
	NotifyPolicy      string
	PreferredTerminal string
	SmartPower        bool
	RespectHotspot    bool
	TGTokenDraft      string
	TGPairCode        string
	TGPairStatus      string
	GHTokenDraft      string
	GeminiKeyDraft    string
	OpenAIKeyDraft    string
	AnthropicKeyDraft string
	ClashSecretDraft  string
	StatusBanner      string
}

func NewAppState(cfgPath string, headless bool) *AppState {
	cfg, _ := config.Load(cfgPath)
	mem := store.New("")
	runner := pipeline.NewRunner(mem)

	shLang := editor.LanguageFor("mitigate.sh")
	oldBuf := editor.NewBuffer("# 选择左侧任意漏洞或待装补丁，即可在此并排审阅变更命令与应急回滚脚本\n")
	newBuf := editor.NewBuffer("# 右侧脚本支持直接在 GPU 编辑器内微调修改后批准下发\n")
	oldBuf.SetLanguage(shLang)
	newBuf.SetLanguage(shLang)

	aiProv := cfg.AIRemediation.Provider
	if aiProv == "" {
		aiProv = "gemini"
	}
	prefTerm := cfg.Notifications.PreferredTerminal
	if prefTerm == "" {
		prefTerm = "auto"
	}

	s := &AppState{
		Cfg:               cfg,
		CfgPath:           cfg.SourcePath,
		Mem:               mem,
		Runner:            runner,
		Headless:          headless,
		ActivePage:        "overview",
		SidebarWidth:      224,
		TriageSplit:       340,
		Online:            true,
		DiffState:         &editor.DiffState{Old: oldBuf, New: newBuf, Editable: true, HunkActions: true},
		GatewayNodeDelays:  make(map[string]int),
		SelectedSSH:        make(map[string]bool),
		WorkspaceJobStatus: make(map[string]string),
		DailyAdvisories:    make(map[string]model.Advisory),
		CVEEcosystemChoice: "全部生态",
		CVEDaysChoice:      "昨今两日",
		ScanModeLabel:     scanModeToLabel(cfg.Notifications.ScanMode),
		ScanIntervalLabel: hoursToIntervalLabel(cfg.Notifications.AutoScanHours),
		DailyScanTimeStr:  firstNonEmptyStr(cfg.Notifications.DailyScanTime, "09:00"),
		AdvisoryDaysLabel: daysToWindowLabel(cfg.Advisories.Days),
		AutoFixEnabled:    cfg.AutoFix.Enabled,
		AIEnabled:         cfg.AIRemediation.Enabled,
		AIAutoExec:        cfg.AIRemediation.AutoExecute,
		AIProvider:        aiProv,
		AIModel:           cfg.AIRemediation.Model,
		NotifyPolicy:      cfg.Notifications.Policy,
		PreferredTerminal: prefTerm,
		SmartPower:        cfg.Notifications.SmartPower,
		RespectHotspot:    cfg.Notifications.RespectHotspot,
	}

	loadedRep, err := notify.LoadReport("")
	if err == nil && len(loadedRep.Hosts) > 0 {
		if t, err := time.Parse(time.RFC3339, loadedRep.Timestamp); err == nil {
			s.LastScanAt = t
		}
		s.Report = reconcileReportWithConfig(loadedRep, cfg)
	} else {
		s.Report = reconcileReportWithConfig(model.AuditReport{ClusterScore: 100}, cfg)
	}
	s.HistoryItems = mem.ListHistory()
	if cachedAdvs, ok := mem.GetAdvisories(cfg.Advisories.Days, cfg.Advisories.IncludeKernel); ok {
		s.DailyAdvisories = cachedAdvs
	}
	return s
}

func parseDaysChoice(lbl string) int {
	switch lbl {
	case "近 1 天":
		return 1
	case "近 7 天":
		return 7
	case "近 14 天":
		return 14
	default:
		return 3
	}
}

// parseDigestDaysChoice returns 0 for "昨今两日" (so SendDailyCVEDigest filters strictly to [yesterday, today]),
// or explicit day count otherwise.
func parseDigestDaysChoice(lbl string) int {
	switch lbl {
	case "", "昨今两日":
		return 0
	case "近 1 天":
		return 1
	case "近 7 天":
		return 7
	case "近 14 天":
		return 14
	default:
		return 3
	}
}

// RefreshDailyCVEsAsync fetches fresh live CVEs across Language, OS, and Kernel feeds.
func (s *AppState) RefreshDailyCVEsAsync(forceFresh bool) {
	if s.CVEFeedLoading {
		return
	}
	s.CVEFeedLoading = true
	days := parseDaysChoice(s.CVEDaysChoice)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
		advs, err := s.Runner.Intel.FetchAllAdvisories(ctx, days, true, !forceFresh)
		s.uiSync(func() {
			s.CVEFeedLoading = false
			if err == nil && len(advs) > 0 {
				s.DailyAdvisories = advs
			}
		})
	}()
}

// MuteSelectedVulnerability adds a Skip-Version / Snooze / Permanent Exemption rule
// and immediately updates host status, cluster score, menu bar shield, and disk snapshot in 0ms!
func (s *AppState) MuteSelectedVulnerability(entry SelectedVulnEntry, mode string, snoozeDays int) {
	rule := s.Mem.AddIgnoreRule(model.IgnoreRule{
		HostKey:        entry.Host.Target.EffectiveKey(),
		HostName:       entry.Host.Host,
		VulnID:         entry.Vuln.EffectiveID(),
		Package:        entry.Vuln.Package,
		Mode:           mode,
		SkippedVersion: entry.Vuln.FixedVersion,
	}, snoozeDays)

	for hi := range s.Report.Hosts {
		h := &s.Report.Hosts[hi]
		if h.Target.EffectiveKey() != entry.Host.Target.EffectiveKey() {
			continue
		}
		var kept []model.VulnerabilityMatch
		for _, v := range h.Vulnerabilities {
			if strings.EqualFold(v.EffectiveID(), entry.Vuln.EffectiveID()) && strings.EqualFold(v.Package, entry.Vuln.Package) {
				v.Status = "已豁免/暂缓"
				v.Reason = rule.Reason
				h.IgnoredItems = append(h.IgnoredItems, v)
				continue
			}
			kept = append(kept, v)
		}
		h.Vulnerabilities = kept
		h.UnmitigatedItems = kept
		recalculateHostPostureAfterMuteChange(h)
	}

	s.recalculateClusterScore()
	_ = notify.SaveReport(s.Report, "")
	if !s.Headless {
		s.refreshTrayAppearance()
	}
}

// UnmuteRuleByKey removes an IgnoreRule and restores any matching IgnoredItems back into active monitoring immediately!
func (s *AppState) UnmuteRuleByKey(ruleKey string) {
	s.Mem.RemoveIgnoreRule(ruleKey)
	for hi := range s.Report.Hosts {
		h := &s.Report.Hosts[hi]
		var stillIgnored []model.IgnoreRule
		_ = stillIgnored
		var keptIgnored []model.VulnerabilityMatch
		for _, v := range h.IgnoredItems {
			if ok, _ := s.Mem.MatchIgnoreRule(h.Target.EffectiveKey(), v); ok {
				keptIgnored = append(keptIgnored, v)
			} else {
				v.Status = ""
				h.Vulnerabilities = append(h.Vulnerabilities, v)
			}
		}
		h.IgnoredItems = keptIgnored
		h.UnmitigatedItems = h.Vulnerabilities
		recalculateHostPostureAfterMuteChange(h)
	}
	s.recalculateClusterScore()
	_ = notify.SaveReport(s.Report, "")
	if !s.Headless {
		s.refreshTrayAppearance()
	}
}

func recalculateHostPostureAfterMuteChange(h *model.HostAuditResult) {
	if len(h.Vulnerabilities) == 0 {
		if len(h.FixedItems) > 0 {
			h.Status = model.StatusImmunized
		} else if h.OSContext.RebootRequired {
			h.Status = model.StatusPendingUpdate
		} else {
			h.Status = model.StatusClean
			h.Detail = fmt.Sprintf("系统、内核与运行态服务 100%% 安全 · 🔕 已豁免/暂缓 %d 项", len(h.IgnoredItems))
		}
		h.HealthScore = 100
		if h.OSContext.RebootRequired {
			h.HealthScore = 95
		}
		return
	}
	score := 100
	allOS := true
	for _, v := range h.Vulnerabilities {
		if !v.IsOSPackage {
			allOS = false
		}
		switch v.Severity {
		case "CRITICAL":
			score -= 22
		case "HIGH":
			score -= 12
		default:
			score -= 6
		}
	}
	if score < 15 {
		score = 15
	}
	h.HealthScore = score
	if allOS {
		h.Status = model.StatusPendingUpdate
	} else {
		h.Status = model.StatusVulnerable
	}
}

func (s *AppState) recalculateClusterScore() {
	if len(s.Report.Hosts) == 0 {
		s.Report.ClusterScore = 100
		return
	}
	tot := 0
	for _, h := range s.Report.Hosts {
		tot += h.HealthScore
	}
	s.Report.ClusterScore = tot / len(s.Report.Hosts)
}

// PushDailyCVEDigestToTelegramAsync sends the standalone categorized CVE digest message to Telegram on demand.
func (s *AppState) PushDailyCVEDigestToTelegramAsync() {
	if s.CVEPushingTG {
		return
	}
	s.CVEPushingTG = true
	fetchDays := parseDaysChoice(s.CVEDaysChoice)
	digestDays := parseDigestDaysChoice(s.CVEDaysChoice)
	advSnap := make(map[string]model.Advisory, len(s.DailyAdvisories))
	for k, v := range s.DailyAdvisories {
		advSnap[k] = v
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
		if len(advSnap) == 0 {
			advSnap, _ = s.Runner.Intel.FetchAllAdvisories(ctx, fetchDays, true, true)
		}
		sent, err := notify.SendDailyCVEDigest(ctx, advSnap, digestDays, true)
		s.uiSync(func() {
			s.CVEPushingTG = false
			if len(advSnap) > 0 && len(s.DailyAdvisories) == 0 {
				s.DailyAdvisories = advSnap
			}
			switch {
			case err != nil:
				s.StatusBanner = "推送每日 CVE 情报失败: " + err.Error()
			case !sent:
				s.StatusBanner = "未发送：请先在「钥匙串与智能策略」页配置并配对 Telegram 机器人"
			case digestDays <= 0:
				s.StatusBanner = "✈️ 已将昨今两日分类 CVE 情报日报单独推送至您的 Telegram！"
			default:
				s.StatusBanner = fmt.Sprintf("✈️ 已将近 %d 天分类 CVE 情报日报单独推送至您的 Telegram！", digestDays)
			}
		})
	}()
}

// reconcileReportWithConfig guarantees every host in Report has a valid populated HostTarget, non-empty Host name,
// reflects newly added hosts immediately, and NEVER resurrects hosts removed from sentinel.yaml!
func reconcileReportWithConfig(rep model.AuditReport, cfg config.Config) model.AuditReport {
	configured := cfg.ConfiguredHosts()
	if len(configured) == 0 {
		return rep
	}

	matchHost := func(target model.HostTarget) (model.HostAuditResult, bool) {
		for _, h := range rep.Hosts {
			if target.IsLocal() && (h.Target.IsLocal() || strings.Contains(h.Host, "本机") || strings.Contains(strings.ToLower(h.Host), "local")) {
				return h, true
			}
			if h.Target.EffectiveKey() != "" && strings.EqualFold(h.Target.EffectiveKey(), target.EffectiveKey()) {
				return h, true
			}
			if target.SSHHost != "" && (strings.EqualFold(h.Host, target.SSHHost) || strings.EqualFold(h.Target.SSHHost, target.SSHHost)) {
				return h, true
			}
			if target.Name != "" && strings.EqualFold(h.Host, target.Name) {
				return h, true
			}
		}
		return model.HostAuditResult{}, false
	}

	var aligned []model.HostAuditResult
	totalScore := 0
	for _, target := range configured {
		if existing, ok := matchHost(target); ok {
			existing.Target = target
			if strings.TrimSpace(existing.Host) == "" || (existing.Target.IsLocal() && strings.Contains(existing.Host, "macOS")) {
				existing.Host = target.Name
			}
			if existing.HealthScore == 0 && existing.Status == model.StatusClean {
				existing.HealthScore = 100
			}
			totalScore += existing.HealthScore
			aligned = append(aligned, existing)
		} else {
			seeded := model.HostAuditResult{
				Target:      target,
				Host:        target.Name,
				Status:      model.StatusClean,
				Detail:      "点击「立即巡检」采集实时资产与安全状态",
				HealthScore: 100,
				Reachable:   true,
			}
			totalScore += 100
			aligned = append(aligned, seeded)
		}
	}

	rep.Hosts = aligned
	if len(aligned) > 0 && rep.ClusterScore == 0 {
		rep.ClusterScore = totalScore / len(aligned)
	}
	return rep
}

// uiSync safely applies state mutations on the UI main thread and schedules frame invalidation.
func (s *AppState) uiSync(fn func()) {
	if s.Headless {
		fn()
		return
	}
	mygo.RunOnMain(func() {
		fn()
		if s.MainWin != nil {
			s.MainWin.Invalidate()
		}
		if s.FlyoutWin != nil {
			s.FlyoutWin.Invalidate()
		}
		s.refreshTrayAppearance()
	})
}

// ClusterPosture returns "clean", "warn", or "danger" for Tray shield color & UI hero accents.
func (s *AppState) ClusterPosture() string {
	hasWarn := false
	for _, h := range s.Report.Hosts {
		switch h.Status {
		case model.StatusVulnerable, model.StatusManualRequired:
			return "danger"
		case model.StatusPendingUpdate, model.StatusAwaitingPatch:
			hasWarn = true
		}
		if len(h.RetirableMitigations) > 0 {
			hasWarn = true
		}
	}
	if hasWarn {
		return "warn"
	}
	return "clean"
}

func (s *AppState) PendingCounts() (totalUnmit int, osUpdates int, retirable int) {
	for _, h := range s.Report.Hosts {
		totalUnmit += len(h.Vulnerabilities)
		for _, v := range h.Vulnerabilities {
			if v.IsOSPackage && v.Package != "macos-system" {
				osUpdates++
			}
		}
		retirable += len(h.RetirableMitigations)
	}
	return
}

// WorkspaceCounts returns active (<=90d) package fix count, archived project count, and orphaned venv count.
func (s *AppState) WorkspaceCounts() (activePkgs int, archivedProjs int, orphans int) {
	for _, h := range s.Report.Hosts {
		orphans += len(h.OrphanedVenvs)
		for _, wp := range h.WorkspaceProjects {
			if wp.Archived {
				archivedProjs++
			} else {
				activePkgs += len(wp.Packages)
			}
		}
	}
	return
}

// HasMacOSSystemUpdate reports whether a host has a pending Apple macOS OS/RSR update.
func HasMacOSSystemUpdate(h model.HostAuditResult) bool {
	for _, u := range h.OSSecurity.Updates {
		if u.Package == "macos-system" {
			return true
		}
	}
	for _, v := range h.Vulnerabilities {
		if v.Package == "macos-system" {
			return true
		}
	}
	return false
}

// OpenAppleSoftwareUpdate opens macOS System Settings -> General -> Software Update directly.
func OpenAppleSoftwareUpdate() {
	if runtime.GOOS == "darwin" {
		_ = exec.Command("open", "x-apple.systempreferences:com.apple.Software-Update-Settings.extension").Start()
	}
}

// TrashOrphanedVenv safely moves one orphaned virtualenv into the OS Trash and updates state immediately.
func (s *AppState) TrashOrphanedVenv(venvPath string) error {
	var err error
	if !s.Headless {
		err = mygo.Shell.TrashItem(venvPath)
	}
	if s.Headless || err != nil {
		_, err = lockfile.MoveVenvToTrash(venvPath)
	}
	if err != nil {
		return err
	}
	for hi := range s.Report.Hosts {
		var kept []model.OrphanedVenv
		for _, ov := range s.Report.Hosts[hi].OrphanedVenvs {
			if ov.Path != venvPath {
				kept = append(kept, ov)
			}
		}
		s.Report.Hosts[hi].OrphanedVenvs = kept
	}
	_ = notify.SaveReport(s.Report, "")
	return nil
}

// TrashAllOrphanedVenvs moves all detected orphaned virtualenvs safely into OS Trash.
func (s *AppState) TrashAllOrphanedVenvs() (count int, freedMB float64) {
	var all []model.OrphanedVenv
	for _, h := range s.Report.Hosts {
		all = append(all, h.OrphanedVenvs...)
	}
	for _, ov := range all {
		if err := s.TrashOrphanedVenv(ov.Path); err == nil {
			count++
			freedMB += ov.SizeMB
		}
	}
	return count, freedMB
}

// TrashWorkspaceProject safely moves a local project directory into the OS Trash and removes it from UI state immediately.
func (s *AppState) TrashWorkspaceProject(projectDir, projectName string) error {
	if projectDir == "" || projectDir == "global-pip" {
		return fmt.Errorf("全局环境不支持删除目录")
	}
	var err error
	if !s.Headless {
		err = mygo.Shell.TrashItem(projectDir)
	}
	if s.Headless || err != nil {
		_, err = lockfile.MoveDirectoryToTrash(projectDir)
	}
	if err != nil {
		return err
	}
	delete(s.WorkspaceJobStatus, projectDir)
	for hi := range s.Report.Hosts {
		var kept []model.WorkspaceProjectAudit
		for _, wp := range s.Report.Hosts[hi].WorkspaceProjects {
			if wp.ProjectDir != projectDir {
				kept = append(kept, wp)
			}
		}
		s.Report.Hosts[hi].WorkspaceProjects = kept
	}
	_ = notify.SaveReport(s.Report, "")
	s.StatusBanner = fmt.Sprintf("🗑️ 已将项目「%s」安全移入系统废纸篓 (随时可在废纸篓还原)", projectName)
	return nil
}

// UpgradeWorkspaceCmdAsync immediately marks ONLY projectDir as "running" (non-blocking: other cards remain clickable in parallel!),
// executes cmdStr with full user PATH, and performs a fast <1s single-project OSV re-audit!
func (s *AppState) UpgradeWorkspaceCmdAsync(projectDir, cmdStr, projectName string) {
	st := s.WorkspaceJobStatus[projectDir]
	if st == "running" || st == "queued" {
		return
	}
	s.WorkspaceJobStatus[projectDir] = "running"

	var prevPkgCount int
	var fixesSnap []model.WorkspacePackageFix
	var manifestSnap string
	for _, h := range s.Report.Hosts {
		for _, wp := range h.WorkspaceProjects {
			if wp.ProjectDir == projectDir {
				prevPkgCount = len(wp.Packages)
				manifestSnap = wp.ManifestKind
				fixesSnap = append([]model.WorkspacePackageFix(nil), wp.Packages...)
			}
		}
	}

	go func() {
		transport.EnsureStandardUserPATH()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		outcomeMsg, updatedProj := s.runAndVerifySingleProjectUpgrade(ctx, projectDir, cmdStr, manifestSnap, fixesSnap, prevPkgCount)
		s.uiSync(func() {
			s.applySingleProjectUpgradeOutcome(projectDir, projectName, outcomeMsg, updatedProj)
		})
	}()
}

// UpgradeAllWorkspaceProjectsAsync upgrades all visible upgradable projects in parallel using a 6-worker Go goroutine pool!
func (s *AppState) UpgradeAllWorkspaceProjectsAsync(projects []model.WorkspaceProjectAudit) {
	if s.BatchUpgradeRunning || len(projects) == 0 {
		return
	}
	var queue []model.WorkspaceProjectAudit
	for _, p := range projects {
		if s.WorkspaceJobStatus[p.ProjectDir] == "running" {
			continue
		}
		cmd := auditor.BuildProjectBatchUpgradeCmd(p)
		if cmd != "" && !strings.HasPrefix(cmd, "#") {
			queue = append(queue, p)
			s.WorkspaceJobStatus[p.ProjectDir] = "queued"
		}
	}
	if len(queue) == 0 {
		return
	}

	s.BatchUpgradeRunning = true
	s.BatchUpgradeDone = 0
	s.BatchUpgradeTotal = len(queue)
	s.BatchActiveProjects = nil

	go func() {
		transport.EnsureStandardUserPATH()
		const maxWorkers = 6
		sem := make(chan struct{}, maxWorkers)
		var wg sync.WaitGroup
		var doneAtomic int32
		var closedAtomic int32
		var activeMu sync.Mutex
		activeSet := make(map[string]bool)

		snapshotActive := func() []string {
			activeMu.Lock()
			defer activeMu.Unlock()
			var list []string
			for k := range activeSet {
				list = append(list, k)
			}
			return list
		}

		for _, proj := range queue {
			wg.Add(1)
			go func(p model.WorkspaceProjectAudit) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				activeMu.Lock()
				activeSet[p.ProjectName] = true
				activeMu.Unlock()

				actNow := snapshotActive()
				s.uiSync(func() {
					s.WorkspaceJobStatus[p.ProjectDir] = "running"
					s.BatchActiveProjects = actNow
				})

				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
				cmdStr := auditor.BuildProjectBatchUpgradeCmd(p)
				outcomeMsg, updatedProj := s.runAndVerifySingleProjectUpgrade(ctx, p.ProjectDir, cmdStr, p.ManifestKind, p.Packages, len(p.Packages))
				cancel()

				if updatedProj == nil || len(updatedProj.Packages) == 0 {
					atomic.AddInt32(&closedAtomic, 1)
				}
				doneNow := int(atomic.AddInt32(&doneAtomic, 1))

				activeMu.Lock()
				delete(activeSet, p.ProjectName)
				activeMu.Unlock()
				actAfter := snapshotActive()

				s.uiSync(func() {
					s.BatchUpgradeDone = doneNow
					s.BatchActiveProjects = actAfter
					s.applySingleProjectUpgradeOutcome(p.ProjectDir, p.ProjectName, outcomeMsg, updatedProj)
				})
			}(proj)
		}

		wg.Wait()
		fullyClosed := int(atomic.LoadInt32(&closedAtomic))
		s.uiSync(func() {
			s.BatchUpgradeRunning = false
			s.BatchActiveProjects = nil
			s.StatusBanner = fmt.Sprintf("🎉 Go 并发批量升级完成！共并行处理 %d 个项目，其中 %d 个项目已 100%% 消除全部风险包", len(queue), fullyClosed)
		})
	}()
}

func (s *AppState) runAndVerifySingleProjectUpgrade(
	ctx context.Context,
	projectDir, cmdStr, manifestKind string,
	existingFixes []model.WorkspacePackageFix,
	prevPkgCount int,
) (statusNote string, remaining *model.WorkspaceProjectAudit) {
	var outBytes []byte
	var cmdErr error
	if (manifestKind == "maven" || manifestKind == "gradle") && len(existingFixes) > 0 {
		updatedFiles, jErr := lockfile.UpgradeJavaProjectFiles(projectDir, existingFixes)
		if jErr != nil || updatedFiles == 0 {
			shCmd := exec.CommandContext(ctx, "/bin/sh", "-c", cmdStr)
			shCmd.Dir = projectDir
			outBytes, cmdErr = shCmd.CombinedOutput()
		}
	} else {
		shCmd := exec.CommandContext(ctx, "/bin/sh", "-c", cmdStr)
		if projectDir != "" && projectDir != "global-pip" {
			shCmd.Dir = projectDir
		}
		outBytes, cmdErr = shCmd.CombinedOutput()
	}

	// Immediately re-scan ONLY this single project directory (<50ms) + re-check OSV (<500ms)!
	var refreshed *model.WorkspaceProjectAudit
	if projectDir != "" && projectDir != "global-pip" {
		newAssets := lockfile.ScanSingleProject(projectDir)
		refreshed = auditor.AuditSingleWorkspaceProject(ctx, newAssets, s.Runner.Intel)
	}

	if refreshed == nil || len(refreshed.Packages) == 0 {
		return "closed", nil
	}

	remCount := len(refreshed.Packages)
	if cmdErr != nil {
		tail := strings.TrimSpace(string(outBytes))
		if lines := strings.Split(tail, "\n"); len(lines) > 0 {
			tail = strings.TrimSpace(lines[len(lines)-1])
		}
		if len(tail) > 90 {
			tail = tail[:90] + "..."
		}
		return fmt.Sprintf("warn:命令返回提示 (%s)，剩余 %d 个包受版本约束待手动处理", tail, remCount), refreshed
	}
	if prevPkgCount > remCount {
		return fmt.Sprintf("partial:已成功升级修复 %d 个包！剩余 %d 个包受项目版本上限约束需手动调整", prevPkgCount-remCount, remCount), refreshed
	}
	return fmt.Sprintf("warn:当前生态源最高兼容版本仍存在 %d 个上游未修复项或受限于版本约束", remCount), refreshed
}

func (s *AppState) applySingleProjectUpgradeOutcome(
	projectDir, projectName, outcome string,
	updatedProj *model.WorkspaceProjectAudit,
) {
	if outcome == "closed" || updatedProj == nil || len(updatedProj.Packages) == 0 {
		delete(s.WorkspaceJobStatus, projectDir)
		for hi := range s.Report.Hosts {
			if !s.Report.Hosts[hi].Target.IsLocal() {
				continue
			}
			var kept []model.WorkspaceProjectAudit
			for _, wp := range s.Report.Hosts[hi].WorkspaceProjects {
				if wp.ProjectDir != projectDir {
					kept = append(kept, wp)
				}
			}
			s.Report.Hosts[hi].WorkspaceProjects = kept
		}
		_ = notify.SaveReport(s.Report, "")
		if !s.BatchUpgradeRunning {
			s.StatusBanner = fmt.Sprintf("🎉 项目「%s」依赖已全部升至安全版本并闭环移除！", projectName)
		}
		return
	}

	s.WorkspaceJobStatus[projectDir] = outcome
	for hi := range s.Report.Hosts {
		if !s.Report.Hosts[hi].Target.IsLocal() {
			continue
		}
		for pi := range s.Report.Hosts[hi].WorkspaceProjects {
			if s.Report.Hosts[hi].WorkspaceProjects[pi].ProjectDir == projectDir {
				s.Report.Hosts[hi].WorkspaceProjects[pi] = *updatedProj
			}
		}
	}
	_ = notify.SaveReport(s.Report, "")
	if !s.BatchUpgradeRunning {
		cleanNote := strings.TrimPrefix(strings.TrimPrefix(outcome, "partial:"), "warn:")
		s.StatusBanner = fmt.Sprintf("[%s] %s", projectName, cleanNote)
	}
}

func (s *AppState) FilteredVulnEntries() []SelectedVulnEntry {
	var out []SelectedVulnEntry
	for hi, h := range s.Report.Hosts {
		if s.TriageFilter == 3 {
			for _, f := range h.FixedItems {
				out = append(out, SelectedVulnEntry{HostIndex: hi, Host: h, Vuln: f, IsFixed: true})
			}
			continue
		}
		for _, v := range h.Vulnerabilities {
			switch s.TriageFilter {
			case 1:
				if !v.IsOSPackage {
					continue
				}
			case 2:
				if v.IsOSPackage {
					continue
				}
			}
			out = append(out, SelectedVulnEntry{HostIndex: hi, Host: h, Vuln: v})
		}
	}
	return out
}

func vulnEntryKey(e SelectedVulnEntry) string {
	return fmt.Sprintf("%s::%s::%s", e.Host.Target.EffectiveKey(), e.Vuln.EffectiveID(), e.Vuln.Package)
}

func (s *AppState) syncDiffBuffersForEntry(entry SelectedVulnEntry) {
	k := vulnEntryKey(entry)
	if s.LoadedDiffKey == k {
		return
	}
	s.LoadedDiffKey = k

	var leftText, rightText string
	v := entry.Vuln
	if v.MitigateScript != "" || v.RollbackScript != "" {
		leftText = "# === 应急回滚脚本 (Rollback Script, 归档于 /etc/sentinel/remediations/) ===\n" + strings.TrimSpace(v.RollbackScript) + "\n"
		rightText = "# === 现场规避加固脚本 (Mitigation Script, 可直接在此编辑微调) ===\n" + strings.TrimSpace(v.MitigateScript) + "\n"
	} else if v.IsOSPackage {
		leftText = fmt.Sprintf("# 当前状态 (%s)\nPACKAGE=%s\nINSTALLED_VERSION=%s\nSTATUS=VULNERABLE\n",
			entry.Host.Host, v.Package, v.InstalledVersion)
		planCmd := v.RemediationCmd
		if len(entry.Host.OSSecurity.RemediationPlan.Commands) > 0 {
			planCmd = strings.Join(entry.Host.OSSecurity.RemediationPlan.Commands, "\n")
		}
		rightText = fmt.Sprintf("# 定向安全升级计划 (%s)\nPACKAGE=%s\nTARGET_VERSION=%s\n\n#!/bin/sh\n%s\n",
			entry.Host.Host, v.Package, v.FixedVersion, planCmd)
	} else {
		leftText = fmt.Sprintf("# 待研判漏洞 (%s)\n# 主机: %s (%s)\n# 组件: %s %s\n",
			v.EffectiveID(), entry.Host.Host, entry.Host.OSContext.OSPretty, v.Package, v.InstalledVersion)
		rightText = fmt.Sprintf("# 点击上方「AI 研判生成双脚本」按钮，\n# 系统将结合目标机器内核与 Shell 环境生成配对的加固与回滚脚本。\n# 推荐修复版本: %s\n",
			firstNonEmptyStr(v.FixedVersion, "等待官方补丁或生成运行时规避策略"))
	}

	s.DiffState.Old.Reset(leftText)
	s.DiffState.New.Reset(rightText)
}

func firstNonEmptyStr(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

// OpenSSHOnboardingModalAsync opens the SSH import modal and streams verified live servers onto screen in real time!
func (s *AppState) OpenSSHOnboardingModalAsync() {
	s.ShowSSHModal = true
	s.SSHProbing = true
	s.SSHProbeDone = 0
	s.SSHProbeTotal = 0
	s.DiscoveredSSH = nil
	s.SSHFilteredOutCount = 0
	s.SelectedSSH = make(map[string]bool)

	existingSnap := s.Cfg.ConfiguredHosts()
	go func() {
		transport.EnsureStandardUserPATH()
		candidates := config.DiscoverSSHConfigHosts(existingSnap)
		s.uiSync(func() {
			s.SSHProbeTotal = len(candidates)
		})
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()

		_, filtered := config.ProbeValidSSHHostsStream(
			ctx,
			candidates,
			func(found config.DiscoveredSSHHost) {
				s.uiSync(func() {
					s.DiscoveredSSH = append(s.DiscoveredSSH, found)
					if !found.AlreadyAdded {
						s.SelectedSSH[found.Alias] = true
					}
				})
			},
			func(done, total, filt int) {
				s.uiSync(func() {
					s.SSHProbeDone = done
					s.SSHProbeTotal = total
					s.SSHFilteredOutCount = filt
				})
			},
		)
		s.uiSync(func() {
			s.SSHProbing = false
			s.SSHFilteredOutCount = filtered
		})
	}()
}

// StartAuditAsync triggers a non-blocking cluster scan on a background goroutine.
func (s *AppState) StartAuditAsync(applyFixes bool, runAI bool) {
	if s.Scanning {
		return
	}
	s.Scanning = true
	s.ScanStep = 1
	s.ScanTotal = 4
	s.ScanMessage = "正在初始化巡检流水线..."
	if !s.Headless {
		s.refreshTrayAppearance()
	}

	cfgSnap := s.Cfg
	metered := s.MeteredNetwork && cfgSnap.Notifications.RespectHotspot

	go func() {
		var releaseAwake func()
		if !s.Headless {
			releaseAwake = mygo.Power.KeepAwake("Security Sentinel 正在执行安全巡检", false)
		}
		if releaseAwake != nil {
			defer releaseAwake()
		}

		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
		defer cancel()

		rep, err := s.Runner.RunAudit(ctx, pipeline.AuditParams{
			Config:         cfgSnap,
			ApplyOSFixes:   applyFixes,
			EnableAITriage: runAI || cfgSnap.AIRemediation.Enabled,
			AutoExecuteAI:  cfgSnap.AIRemediation.AutoExecute,
			UseAdvCache:    true,
			UseInvCache:    false,
			UseAICache:     true,
			SkipOSV:        metered,
			OnPhase: func(step, total int, msg string) {
				s.uiSync(func() {
					s.ScanStep = step
					s.ScanTotal = total
					s.ScanMessage = msg
				})
			},
		})

		hist := s.Mem.ListHistory()
		cachedAdvs, _ := s.Mem.GetAdvisories(cfgSnap.Advisories.Days, cfgSnap.Advisories.IncludeKernel)
		s.uiSync(func() {
			s.Scanning = false
			if len(cachedAdvs) > 0 {
				s.DailyAdvisories = cachedAdvs
			}
			if err == nil {
				// Reconcile against LIVE s.Cfg so any host removed/added during scan is strictly respected!
				s.Report = reconcileReportWithConfig(rep, s.Cfg)
				_ = notify.SaveReport(s.Report, "")
				s.HistoryItems = hist
				s.LastScanAt = time.Now()
				s.LoadedDiffKey = ""
				s.StatusBanner = fmt.Sprintf("巡检完成 · 集群健康分 %d/100 (耗时 %.1fs)", s.Report.ClusterScore, float64(rep.DurationMS)/1000.0)
			} else {
				s.StatusBanner = "巡检异常: " + err.Error()
			}
		})
	}()
}

// StartDoctorAsync runs full cluster diagnostics in the background.
func (s *AppState) StartDoctorAsync() {
	if s.DoctorRunning {
		return
	}
	s.DoctorRunning = true
	cfgSnap := s.Cfg
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
		defer cancel()
		items := doctor.RunAll(ctx, cfgSnap, s.Mem)
		s.uiSync(func() {
			s.DoctorRunning = false
			s.DoctorItems = items
			s.HostsSubTab = 1
		})
	}()
}

// CheckForUpdatesAsync queries GitHub Releases for a newer prebuilt version.
func (s *AppState) CheckForUpdatesAsync() {
	if s.UpdateChecking || s.UpdateApplying {
		return
	}
	s.UpdateChecking = true
	s.UpdateMessage = "正在从 GitHub Releases 检查最新版本…"
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		cli := updater.NewClient()
		rel, err := cli.CheckLatest(ctx, model.Version)
		s.uiSync(func() {
			s.UpdateChecking = false
			if err != nil {
				s.UpdateMessage = "检查更新提示: " + err.Error()
				return
			}
			s.LatestRelease = &rel
			if rel.HasUpdate {
				s.UpdateMessage = fmt.Sprintf("🎉 发现新版本 %s (当前 v%s)，可一键下载升级！", rel.TagName, model.Version)
			} else {
				s.UpdateMessage = fmt.Sprintf("✅ 当前已是最新版本 (v%s)", model.Version)
			}
		})
	}()
}

// ApplySelfUpgradeAsync downloads & SHA-256 verifies the latest GitHub Actions build and relaunches!
func (s *AppState) ApplySelfUpgradeAsync() {
	if s.UpdateApplying || s.LatestRelease == nil {
		return
	}
	rel := *s.LatestRelease
	s.UpdateApplying = true
	s.UpdateMessage = fmt.Sprintf("正在下载并校验 %s 官方预编译包…", rel.TagName)

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		cli := updater.NewClient()

		// Upgrade local CLI (`~/.local/bin/sectl` + `security-sentinel` symlink)
		cliBin := config.ExpandHome("~/.local/bin/sectl")
		_, _ = cli.UpgradeCLI(ctx, rel, cliBin)

		var appErr error
		if runtime.GOOS == "darwin" {
			_, appErr = cli.UpgradeMacOSApp(ctx, rel, "")
		} else {
			_, appErr = cli.UpgradeCLI(ctx, rel, "")
		}

		s.uiSync(func() {
			s.UpdateApplying = false
			if appErr != nil {
				s.UpdateMessage = "升级未完成: " + appErr.Error()
				return
			}
			s.UpdateMessage = "🎉 升级成功，正在重启进入新版本…"
			if !s.Headless {
				mygo.App.Relaunch()
			}
		})
	}()
}

// ApplyHostOSFixesAsync installs safe OS security updates on a specific host (or all hosts if hostKey == "").
func (s *AppState) ApplyHostOSFixesAsync(hostKey string) {
	if s.FixingHost != "" {
		return
	}
	s.FixingHost = firstNonEmptyStr(hostKey, "all")
	hostsSnap := append([]model.HostAuditResult(nil), s.Report.Hosts...)

	go func() {
		var releaseAwake func()
		if !s.Headless {
			releaseAwake = mygo.Power.KeepAwake("Security Sentinel 正在安装安全补丁", false)
		}
		if releaseAwake != nil {
			defer releaseAwake()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()

		appliedCount := 0
		var lastErr string
		for _, h := range hostsSnap {
			if hostKey != "" && h.Target.EffectiveKey() != hostKey {
				continue
			}
			plan := h.OSSecurity.RemediationPlan
			if len(h.OSSecurity.Updates) == 0 || !plan.SafeToExecute {
				continue
			}
			ok, out := patch.ApplyOSPlan(ctx, h.Target, plan)
			if ok {
				appliedCount++
			} else {
				lastErr = out
			}
		}

		s.uiSync(func() {
			s.FixingHost = ""
			if appliedCount > 0 {
				s.StatusBanner = fmt.Sprintf("成功完成 %d 台主机官方安全补丁热升级，正在复核状态...", appliedCount)
				s.StartAuditAsync(false, false)
			} else if lastErr != "" {
				s.StatusBanner = "安全更新执行失败: " + lastErr
			}
		})
	}()
}

// GenerateAITriageForSelectedAsync invokes AI feasibility & dual-script generation for the selected vulnerability.
func (s *AppState) GenerateAITriageForSelectedAsync(entry SelectedVulnEntry) {
	if s.AIRunning {
		return
	}
	s.AIRunning = true
	aiCfg := s.Cfg.AIRemediation

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		eng := ai.NewEngine(aiCfg, s.Mem)
		inv := model.HostInventory{
			Target:    entry.Host.Target,
			OSContext: entry.Host.OSContext,
		}
		triage := eng.AssessAndMitigate(ctx, entry.Vuln, inv, false)
		s.uiSync(func() {
			s.AIRunning = false
			for hi := range s.Report.Hosts {
				if s.Report.Hosts[hi].Target.EffectiveKey() != entry.Host.Target.EffectiveKey() {
					continue
				}
				for vi := range s.Report.Hosts[hi].Vulnerabilities {
					v := &s.Report.Hosts[hi].Vulnerabilities[vi]
					if v.EffectiveID() == entry.Vuln.EffectiveID() && v.Package == entry.Vuln.Package {
						if triage.Success && triage.HasWorkaround {
							v.MitigateScript = triage.Script
							v.RollbackScript = triage.Rollback
							v.Strategy = triage.Strategy
							v.Reason = "AI 双脚本已就绪，请审阅下方 Diff 后批准执行"
							s.StatusBanner = "AI 已生成加固与回滚脚本: " + triage.Strategy
						} else if triage.Success && !triage.HasWorkaround {
							v.Status = model.StatusAwaitingPatch
							v.Reason = triage.Reason
							s.StatusBanner = "AI 判定无需瞎改配置 (需等上游二进制补丁): " + triage.Reason
						} else {
							s.StatusBanner = "AI 研判提示: " + triage.Error
						}
					}
				}
			}
			s.LoadedDiffKey = ""
		})
	}()
}

// ApproveAndExecuteSelectedMitigation deploys the user-reviewed (and possibly edited!) script from DiffState.New.
func (s *AppState) ApproveAndExecuteSelectedMitigation(entry SelectedVulnEntry) {
	if s.AIRunning {
		return
	}
	editedMitigate := strings.TrimSpace(s.DiffState.New.String())
	rollback := strings.TrimSpace(entry.Vuln.RollbackScript)
	if rollback == "" {
		s.StatusBanner = "缺少配对的应急回滚脚本，拒绝下发执行"
		return
	}
	if ok, msg := ai.VerifyScriptSafety(editedMitigate, entry.Host.OSContext); !ok {
		s.StatusBanner = "静态安全门禁拦截: " + msg
		return
	}

	s.AIRunning = true
	go func() {
		var releaseAwake func()
		if !s.Headless {
			releaseAwake = mygo.Power.KeepAwake("Security Sentinel 正在远程部署加固脚本并探活", false)
		}
		if releaseAwake != nil {
			defer releaseAwake()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		ok, msg, _ := patch.DeployAndExecuteMitigation(
			ctx,
			entry.Host.Target,
			entry.Host.OSContext,
			entry.Vuln.EffectiveID(),
			editedMitigate,
			rollback,
			firstNonEmptyStr(entry.Vuln.Strategy, "人工审阅批准加固"),
			s.Mem,
		)
		hist := s.Mem.ListHistory()
		s.uiSync(func() {
			s.AIRunning = false
			s.HistoryItems = hist
			s.StatusBanner = msg
			if ok {
				s.StartAuditAsync(false, false)
			}
		})
	}()
}

// ExecuteRollbackAsync runs remote rollback script for a RemediationRecord or retirable CVE.
func (s *AppState) ExecuteRollbackAsync(hostKey, cveID string) {
	var target model.HostTarget
	var osCtx model.OSContext
	found := false
	for _, h := range s.Report.Hosts {
		if h.Target.EffectiveKey() == hostKey || h.Host == hostKey {
			target = h.Target
			osCtx = h.OSContext
			found = true
			break
		}
	}
	if !found {
		target = config.NormalizeStringHost(hostKey)
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		ok, msg := patch.RollbackMitigation(ctx, target, osCtx, cveID, s.Mem)
		hist := s.Mem.ListHistory()
		s.uiSync(func() {
			s.HistoryItems = hist
			s.StatusBanner = msg
			if ok {
				s.StartAuditAsync(false, false)
			}
		})
	}()
}

// RefreshHAGatewayAsync queries Clash/Mihomo active proxy and node latencies.
func (s *AppState) RefreshHAGatewayAsync() {
	if !s.Cfg.Gateway.Enabled {
		return
	}
	cfgSnap := s.Cfg
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		defer cancel()
		mgr := ha.NewManager(cfgSnap, nil)
		active, all, err := mgr.GetGatewayActiveNode(ctx)
		delays := make(map[string]int)
		if err == nil {
			for i, n := range all {
				if i >= 8 {
					break
				}
				delays[n] = mgr.TestNodeDelay(ctx, n)
			}
		}
		s.uiSync(func() {
			if err == nil {
				s.GatewayActiveNode = active
				s.GatewayAllNodes = all
				s.GatewayNodeDelays = delays
			} else {
				s.StatusBanner = "查询网关 Clash API 失败: " + err.Error()
			}
		})
	}()
}

// StartRollingRebootAsync runs zero-downtime rolling reboot with Power.KeepAwake protection and live event streaming.
func (s *AppState) StartRollingRebootAsync(nodeIDs []string, forceGateway bool) {
	if s.HARunning {
		return
	}
	s.HARunning = true
	s.HAEvents = nil
	cfgSnap := s.Cfg

	go func() {
		var releaseAwake func()
		if !s.Headless {
			releaseAwake = mygo.Power.KeepAwake("Security Sentinel 正在执行零中断滚动重启与同步", false)
		}
		if releaseAwake != nil {
			defer releaseAwake()
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		mgr := ha.NewManager(cfgSnap, func(ev model.HAProgressEvent) {
			s.uiSync(func() {
				s.HAEvents = append(s.HAEvents, ev)
			})
		})

		targets := nodeIDs
		if len(targets) == 0 && !forceGateway {
			for nid := range cfgSnap.RollingNodesMap() {
				if mgr.CheckRebootRequired(ctx, nid) {
					targets = append(targets, nid)
				}
			}
		}

		err := mgr.ExecuteRollingReboot(ctx, targets, forceGateway)
		s.uiSync(func() {
			s.HARunning = false
			if err != nil {
				s.StatusBanner = "滚动重启异常: " + err.Error()
			} else {
				s.StatusBanner = "零中断滚动重启与网关同步圆满完成！"
				s.RefreshHAGatewayAsync()
			}
		})
	}()
}

// ExportHTMLReport saves and opens a standalone dark-mode HTML report.
func (s *AppState) ExportHTMLReport() string {
	outPath := filepath.Join(config.StateDir(), fmt.Sprintf("sentinel-report-%s.html", time.Now().Format("20060102-150405")))
	if err := report.WriteHTML(s.Report, outPath); err != nil {
		s.StatusBanner = "导出报告失败: " + err.Error()
		return ""
	}
	s.StatusBanner = "已导出战报: " + outPath
	if !s.Headless {
		_ = mygo.Shell.OpenPath(outPath)
	}
	return outPath
}

// SaveSettings persists UI policy & schedule toggles to sentinel.yaml and credentials to OS Keychain.
func (s *AppState) SaveSettings() {
	s.Cfg.Notifications.ScanMode = labelToScanMode(s.ScanModeLabel)
	s.Cfg.Notifications.AutoScanHours = intervalLabelToHours(s.ScanIntervalLabel)
	s.Cfg.Notifications.DailyScanTime = normalizeHHMM(s.DailyScanTimeStr)
	s.DailyScanTimeStr = s.Cfg.Notifications.DailyScanTime
	s.Cfg.Advisories.Days = windowLabelToDays(s.AdvisoryDaysLabel)

	s.Cfg.AutoFix.Enabled = s.AutoFixEnabled
	s.Cfg.AIRemediation.Enabled = s.AIEnabled
	s.Cfg.AIRemediation.AutoExecute = s.AIAutoExec
	s.Cfg.AIRemediation.Provider = s.AIProvider
	if strings.TrimSpace(s.AIModel) != "" {
		s.Cfg.AIRemediation.Model = strings.TrimSpace(s.AIModel)
	}
	s.Cfg.Notifications.Policy = s.NotifyPolicy
	s.Cfg.Notifications.PreferredTerminal = s.PreferredTerminal
	s.Cfg.Notifications.SmartPower = s.SmartPower
	s.Cfg.Notifications.RespectHotspot = s.RespectHotspot

	savedPath, err := config.Save(s.Cfg, s.CfgPath)
	if err == nil {
		s.CfgPath = savedPath
		s.Cfg.SourcePath = savedPath
	}

	saveKey := func(k string, draft *string) {
		if strings.TrimSpace(*draft) != "" {
			_ = secrets.Set(k, strings.TrimSpace(*draft))
			*draft = ""
		}
	}
	saveKey(secrets.KeyTelegramBotToken, &s.TGTokenDraft)
	saveKey(secrets.KeyGitHubToken, &s.GHTokenDraft)
	saveKey(secrets.KeyGeminiAPIKey, &s.GeminiKeyDraft)
	saveKey(secrets.KeyOpenAIAPIKey, &s.OpenAIKeyDraft)
	saveKey(secrets.KeyAnthropicAPIKey, &s.AnthropicKeyDraft)
	saveKey(secrets.KeyClashAPISecret, &s.ClashSecretDraft)

	if !s.Headless {
		_ = mygo.App.SetOpenAtLogin(s.OpenAtLogin)
	}
	_, _, schedSummary := s.NextScheduledScanInfo(time.Now())
	s.StatusBanner = "设置已保存 (" + schedSummary + ")"
}

// NextScheduledScanInfo computes the next scheduled run time, whether a catch-up/scheduled run is due now,
// and a transparent human-readable schedule summary for the Flyout & Settings page.
func (s *AppState) NextScheduledScanInfo(now time.Time) (nextDue time.Time, dueNow bool, summary string) {
	lastStr := "尚未扫描"
	if !s.LastScanAt.IsZero() {
		lastStr = "上次 " + s.LastScanAt.Local().Format("15:04")
	}
	mode := s.Cfg.Notifications.ScanMode
	if mode == "" {
		mode = "interval"
	}

	switch mode {
	case "manual":
		return time.Time{}, false, lastStr + " · 仅手动巡检"

	case "daily":
		hh, mm := parseHHMM(s.Cfg.Notifications.DailyScanTime)
		loc := now.Location()
		todayTarget := time.Date(now.Year(), now.Month(), now.Day(), hh, mm, 0, 0, loc)
		if now.Before(todayTarget) {
			return todayTarget, false, fmt.Sprintf("%s · 下次今日 %02d:%02d", lastStr, hh, mm)
		}
		// Today's target time has passed: check if we already scanned after todayTarget!
		if s.LastScanAt.IsZero() || s.LastScanAt.Before(todayTarget) {
			return todayTarget, true, fmt.Sprintf("%s · 今日 %02d:%02d 待补跑", lastStr, hh, mm)
		}
		tomorrow := todayTarget.Add(24 * time.Hour)
		return tomorrow, false, fmt.Sprintf("%s · 下次明日 %02d:%02d", lastStr, hh, mm)

	default: // "interval"
		hours := s.Cfg.Notifications.AutoScanHours
		if hours <= 0 {
			hours = 12
		}
		dur := time.Duration(hours) * time.Hour
		if s.LastScanAt.IsZero() {
			return now, true, fmt.Sprintf("每 %d 小时自动巡检 · 待首次执行", hours)
		}
		due := s.LastScanAt.Add(dur)
		if !now.Before(due) {
			return due, true, fmt.Sprintf("%s · 已到点准备巡检", lastStr)
		}
		nextFmt := due.Local().Format("15:04")
		if due.Local().Day() != now.Local().Day() {
			nextFmt = "明日 " + nextFmt
		}
		return due, false, fmt.Sprintf("%s · 下次 %s (每%dh)", lastStr, nextFmt, hours)
	}
}

func scanModeToLabel(mode string) string {
	switch mode {
	case "daily":
		return "每日定点巡检"
	case "manual":
		return "仅手动巡检"
	default:
		return "定频间隔巡检"
	}
}

func labelToScanMode(lbl string) string {
	switch lbl {
	case "每日定点巡检":
		return "daily"
	case "仅手动巡检":
		return "manual"
	default:
		return "interval"
	}
}

func hoursToIntervalLabel(h int) string {
	switch h {
	case 4:
		return "每 4 小时"
	case 8:
		return "每 8 小时"
	case 24:
		return "每 24 小时"
	default:
		return "每 12 小时"
	}
}

func intervalLabelToHours(lbl string) int {
	switch lbl {
	case "每 4 小时":
		return 4
	case "每 8 小时":
		return 8
	case "每 24 小时":
		return 24
	default:
		return 12
	}
}

func daysToWindowLabel(d int) string {
	switch d {
	case 1:
		return "近 1 天"
	case 7:
		return "近 7 天"
	case 14:
		return "近 14 天"
	case 30:
		return "近 30 天"
	default:
		return "近 3 天 (推荐)"
	}
}

func windowLabelToDays(lbl string) int {
	switch lbl {
	case "近 1 天":
		return 1
	case "近 7 天":
		return 7
	case "近 14 天":
		return 14
	case "近 30 天":
		return 30
	default:
		return 3
	}
}

func parseHHMM(s string) (int, int) {
	parts := strings.Split(strings.TrimSpace(s), ":")
	if len(parts) == 2 {
		h, err1 := strconv.Atoi(parts[0])
		m, err2 := strconv.Atoi(parts[1])
		if err1 == nil && err2 == nil && h >= 0 && h <= 23 && m >= 0 && m <= 59 {
			return h, m
		}
	}
	return 9, 0
}

func normalizeHHMM(s string) string {
	h, m := parseHHMM(s)
	return fmt.Sprintf("%02d:%02d", h, m)
}
