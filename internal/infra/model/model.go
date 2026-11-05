package model

import "time"

// Version is stamped via -ldflags during release builds.
var Version = "2.7.0"

// Standard 6-state host security statuses (backwards-compatible with v1 labels).
const (
	StatusClean          = "一切安全"
	StatusImmunized      = "已经免疫"
	StatusPendingUpdate  = "待安装更新"
	StatusAwaitingPatch  = "待官方发布补丁"
	StatusManualRequired = "需手动干预"
	StatusVulnerable     = "还未免疫"
)

// Ecosystem identifiers aligned with OSV / GitHub Security Advisories.
const (
	EcoPyPI      = "PyPI"
	EcoNPM       = "npm"
	EcoGo        = "Go"
	EcoCrates    = "crates.io"
	EcoMaven     = "Maven"
	EcoPackagist = "Packagist"
	EcoNuGet     = "NuGet"
	EcoRubyGems  = "RubyGems"
	EcoPub       = "Pub"
	EcoSwift     = "SwiftURL"
	EcoHex       = "Hex"
	EcoActions   = "GitHub Actions"
	EcoLinux     = "Linux"
	EcoHomebrew  = "Homebrew"
	EcoDocker    = "Docker"
	EcoBinary    = "Binary"
)

// HostTarget uniquely identifies a managed host and separates display Name from SSH destination.
type HostTarget struct {
	ID             string            `json:"id" yaml:"id,omitempty"`
	Name           string            `json:"name" yaml:"name"`
	Type           string            `json:"type" yaml:"type"` // "local" or "remote"
	SSHHost        string            `json:"ssh_host,omitempty" yaml:"ssh_host,omitempty"`
	User           string            `json:"user,omitempty" yaml:"user,omitempty"`
	Host           string            `json:"host,omitempty" yaml:"host,omitempty"`
	Port           int               `json:"port,omitempty" yaml:"port,omitempty"`
	IdentityFile   string            `json:"identity_file,omitempty" yaml:"identity_file,omitempty"`
	ProxyJump      string            `json:"proxy_jump,omitempty" yaml:"proxy_jump,omitempty"`
	OSType         string            `json:"os_type,omitempty" yaml:"os_type,omitempty"`
	PackageManager string            `json:"package_manager,omitempty" yaml:"package_manager,omitempty"`
	CustomCommands map[string]string `json:"custom_commands,omitempty" yaml:"custom_commands,omitempty"`
}

func (h HostTarget) IsLocal() bool {
	return h.Type == "local"
}

func (h HostTarget) EffectiveKey() string {
	if h.ID != "" {
		return h.ID
	}
	if h.IsLocal() {
		return "local"
	}
	if h.SSHHost != "" {
		if h.Port > 0 && h.Port != 22 {
			return h.SSHHost + ":" + itoa(h.Port)
		}
		return h.SSHHost
	}
	return h.Name
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// AssetItem represents an installed software component with full namespace and origin context.
type AssetItem struct {
	Ecosystem      string `json:"ecosystem" yaml:"ecosystem"`
	Name           string `json:"name" yaml:"name"`
	SourcePackage  string `json:"source_package,omitempty" yaml:"source_package,omitempty"`
	Version        string `json:"version" yaml:"version"`
	Location       string `json:"location,omitempty" yaml:"location,omitempty"`
	Kind           string `json:"kind,omitempty" yaml:"kind,omitempty"` // os, kernel, venv, lockfile, runtime, binary, container
	ProjectName    string `json:"project_name,omitempty" yaml:"project_name,omitempty"`
	ProjectDir     string `json:"project_dir,omitempty" yaml:"project_dir,omitempty"`
	ManifestKind   string `json:"manifest_kind,omitempty" yaml:"manifest_kind,omitempty"` // uv, poetry, venv, npm, pnpm, yarn, gomod, cargo, composer, bundler
	LastActiveDays int    `json:"last_active_days,omitempty" yaml:"last_active_days,omitempty"`
	ModifiedUnix   int64  `json:"modified_unix,omitempty" yaml:"modified_unix,omitempty"`
	CreatedUnix    int64  `json:"created_unix,omitempty" yaml:"created_unix,omitempty"`
	Archived       bool   `json:"archived,omitempty" yaml:"archived,omitempty"`
}

// OrphanedVenv represents a stale or orphaned central Python virtualenv whose source project was deleted or abandoned.
type OrphanedVenv struct {
	Name               string  `json:"name" yaml:"name"`
	Path               string  `json:"path" yaml:"path"`
	MissingProjectPath string  `json:"missing_project_path,omitempty" yaml:"missing_project_path,omitempty"`
	IdleDays           int     `json:"idle_days" yaml:"idle_days"`
	SizeMB             float64 `json:"size_mb" yaml:"size_mb"`
	Reason             string  `json:"reason" yaml:"reason"`
}

// WorkspacePackageFix aggregates all CVEs for a single dependency inside one project into one actionable upgrade.
type WorkspacePackageFix struct {
	Package          string   `json:"package" yaml:"package"`
	Ecosystem        string   `json:"ecosystem" yaml:"ecosystem"`
	InstalledVersion string   `json:"installed_version" yaml:"installed_version"`
	FixedVersion     string   `json:"fixed_version" yaml:"fixed_version"`
	Severity         string   `json:"severity" yaml:"severity"`
	CVEIDs           []string `json:"cve_ids" yaml:"cve_ids"`
	Summary          string   `json:"summary" yaml:"summary"`
	UpgradeCmd       string   `json:"upgrade_cmd" yaml:"upgrade_cmd"`
}

// WorkspaceProjectAudit groups dependency upgrades by developer project, separated from host runtime security.
type WorkspaceProjectAudit struct {
	ProjectName    string                `json:"project_name" yaml:"project_name"`
	ProjectDir     string                `json:"project_dir" yaml:"project_dir"`
	ManifestKind   string                `json:"manifest_kind" yaml:"manifest_kind"`
	LastActiveDays int                   `json:"last_active_days" yaml:"last_active_days"`
	ModifiedUnix   int64                 `json:"modified_unix,omitempty" yaml:"modified_unix,omitempty"`
	CreatedUnix    int64                 `json:"created_unix,omitempty" yaml:"created_unix,omitempty"`
	Archived       bool                  `json:"archived" yaml:"archived"`
	TotalCVEs      int                   `json:"total_cves" yaml:"total_cves"`
	Packages       []WorkspacePackageFix `json:"packages" yaml:"packages"`
}

// OSContext describes runtime OS capabilities, hardware limits, and privilege posture.
type OSContext struct {
	OSFamily        string  `json:"os_family" yaml:"os_family"`
	DistroID        string  `json:"distro_id" yaml:"distro_id"`
	DistroVersion   string  `json:"distro_version" yaml:"distro_version"`
	DistroCodename  string  `json:"distro_codename,omitempty" yaml:"distro_codename,omitempty"`
	OSPretty        string  `json:"os_pretty" yaml:"os_pretty"`
	Arch            string  `json:"arch" yaml:"arch"`
	KernelRelease   string  `json:"kernel_release" yaml:"kernel_release"`
	Shell           string  `json:"shell" yaml:"shell"`
	InitSystem      string  `json:"init_system" yaml:"init_system"`
	Firewall        string  `json:"firewall" yaml:"firewall"`
	PkgMgr          string  `json:"pkg_mgr" yaml:"pkg_mgr"`
	MemAvailableMB  float64 `json:"mem_available_mb" yaml:"mem_available_mb"`
	MemTotalMB      float64 `json:"mem_total_mb,omitempty" yaml:"mem_total_mb,omitempty"`
	OverlayAvailMB  float64 `json:"overlay_avail_mb" yaml:"overlay_avail_mb"`
	OverlayTotalMB  float64 `json:"overlay_total_mb,omitempty" yaml:"overlay_total_mb,omitempty"`
	IsFlashStorage  bool    `json:"is_flash_storage" yaml:"is_flash_storage"`
	LockdownMode    bool    `json:"lockdown_mode" yaml:"lockdown_mode"`
	LockdownReason       string  `json:"lockdown_reason,omitempty" yaml:"lockdown_reason,omitempty"`
	RebootRequired       bool    `json:"reboot_required" yaml:"reboot_required"`
	OptionalMajorUpgrade string  `json:"optional_major_upgrade,omitempty" yaml:"optional_major_upgrade,omitempty"`
	IsRoot               bool    `json:"is_root" yaml:"is_root"`
	CanSudoNoPass        bool    `json:"can_sudo_nopass" yaml:"can_sudo_nopass"`
}

// OSSecurityUpdate represents an actionable distro/package-manager security patch.
type OSSecurityUpdate struct {
	Package          string   `json:"package" yaml:"package"`
	SourcePackage    string   `json:"source_package" yaml:"source_package"`
	InstalledVersion string   `json:"installed_version" yaml:"installed_version"`
	CandidateVersion string   `json:"candidate_version" yaml:"candidate_version"`
	Repository       string   `json:"repository" yaml:"repository"`
	CVEID            string   `json:"cve_id,omitempty" yaml:"cve_id,omitempty"`
	AllCVEs          []string `json:"all_cves,omitempty" yaml:"all_cves,omitempty"`
	Severity         string   `json:"severity" yaml:"severity"`
	CVSS             float64  `json:"cvss,omitempty" yaml:"cvss,omitempty"`
	Summary          string   `json:"summary" yaml:"summary"`
	RemediationCmd   string   `json:"remediation_cmd,omitempty" yaml:"remediation_cmd,omitempty"`
	ServiceReloadCmd string   `json:"service_reload_cmd,omitempty" yaml:"service_reload_cmd,omitempty"`
	LockdownWarning  string   `json:"lockdown_warning,omitempty" yaml:"lockdown_warning,omitempty"`
	IsKernel         bool     `json:"is_kernel" yaml:"is_kernel"`
}

// RemediationPlan describes a guarded OS-level remediation batch.
type RemediationPlan struct {
	Commands      []string `json:"commands" yaml:"commands"`
	Packages      []string `json:"packages" yaml:"packages"`
	SafeToExecute bool     `json:"safe_to_execute" yaml:"safe_to_execute"`
	NeedsSudo     bool     `json:"needs_sudo,omitempty" yaml:"needs_sudo,omitempty"`
	Warning       string   `json:"warning,omitempty" yaml:"warning,omitempty"`
	Description   string   `json:"description,omitempty" yaml:"description,omitempty"`
}

// OSSecurityReport aggregates OS-level updates and remediation plan for a host.
type OSSecurityReport struct {
	OSContext          OSContext          `json:"os_context" yaml:"os_context"`
	Updates            []OSSecurityUpdate `json:"updates" yaml:"updates"`
	RemediationPlan    RemediationPlan    `json:"remediation_plan" yaml:"remediation_plan"`
	HasVulnerabilities bool               `json:"has_vulnerabilities" yaml:"has_vulnerabilities"`
	Error              string             `json:"error,omitempty" yaml:"error,omitempty"`
}

// EcosystemSummary summarizes 5-layer host, container, toolchain, and workspace assets discovered on a host.
type EcosystemSummary struct {
	HomebrewFormulae int      `json:"homebrew_formulae" yaml:"homebrew_formulae"`
	HomebrewCasks    int      `json:"homebrew_casks" yaml:"homebrew_casks"`
	MacApps          int      `json:"mac_apps" yaml:"mac_apps"`
	DockerContainers int      `json:"docker_containers" yaml:"docker_containers"`
	DockerImages     int      `json:"docker_images" yaml:"docker_images"`
	DockerVersion    string   `json:"docker_version,omitempty" yaml:"docker_version,omitempty"`
	GlobalTools      int      `json:"global_tools" yaml:"global_tools"`
	Toolchains       []string `json:"toolchains,omitempty" yaml:"toolchains,omitempty"`
	PythonVenvs      int      `json:"python_venvs" yaml:"python_venvs"`
	NodeProjects     int      `json:"node_projects" yaml:"node_projects"`
	GoModules        int      `json:"go_modules" yaml:"go_modules"`
	RustCrates       int      `json:"rust_crates" yaml:"rust_crates"`
	JavaJDKs         int      `json:"java_jdks" yaml:"java_jdks"`
	JavaProjects     int      `json:"java_projects" yaml:"java_projects"`
	JavaWrappers     int      `json:"java_wrappers" yaml:"java_wrappers"`
	PHPProjects      int      `json:"php_projects" yaml:"php_projects"`
	RubyProjects     int      `json:"ruby_projects" yaml:"ruby_projects"`
	DotnetProjects   int      `json:"dotnet_projects" yaml:"dotnet_projects"`
	SwiftProjects    int      `json:"swift_projects" yaml:"swift_projects"`
	Kernel           string   `json:"kernel,omitempty" yaml:"kernel,omitempty"`
}

// HostInventory is the complete discovered profile of a single host.
type HostInventory struct {
	Target             HostTarget        `json:"target" yaml:"target"`
	Assets             []AssetItem       `json:"assets" yaml:"assets"`
	Packages           map[string]string `json:"packages" yaml:"packages"`
	OSContext          OSContext         `json:"os_context" yaml:"os_context"`
	OSSecurity         OSSecurityReport  `json:"os_security" yaml:"os_security"`
	AppliedMitigations map[string]string `json:"applied_mitigations,omitempty" yaml:"applied_mitigations,omitempty"`
	EcosystemSummary   EcosystemSummary  `json:"ecosystems_summary" yaml:"ecosystems_summary"`
	OrphanedVenvs      []OrphanedVenv    `json:"orphaned_venvs,omitempty" yaml:"orphaned_venvs,omitempty"`
	DockerContainers   map[string]string `json:"docker_containers,omitempty" yaml:"docker_containers,omitempty"`
	LatencyMS          int64             `json:"latency_ms" yaml:"latency_ms"`
	CollectedAt        time.Time         `json:"collected_at" yaml:"collected_at"`
	Fingerprint        string            `json:"fingerprint,omitempty" yaml:"fingerprint,omitempty"`
	Error              string            `json:"error,omitempty" yaml:"error,omitempty"`
}

// Advisory represents a security advisory from OSV, GitHub GHSA, OS Security Trackers, or Linux Kernel CNA.
type Advisory struct {
	ID              string              `json:"id" yaml:"id"`
	CVEID           string              `json:"cve_id,omitempty" yaml:"cve_id,omitempty"`
	GHSAID          string              `json:"ghsa_id,omitempty" yaml:"ghsa_id,omitempty"`
	Aliases         []string            `json:"aliases,omitempty" yaml:"aliases,omitempty"`
	Category        string              `json:"category,omitempty" yaml:"category,omitempty"` // "language", "os", "kernel"
	Ecosystem       string              `json:"ecosystem" yaml:"ecosystem"`
	Severity        string              `json:"severity" yaml:"severity"`
	CVSS            float64             `json:"cvss,omitempty" yaml:"cvss,omitempty"`
	Summary         string              `json:"summary" yaml:"summary"`
	Details         string              `json:"details,omitempty" yaml:"details,omitempty"`
	Package         string              `json:"package" yaml:"package"`
	VulnerableRange string              `json:"vulnerable_version_range,omitempty" yaml:"vulnerable_version_range,omitempty"`
	FixedIn         []string            `json:"fixed_in,omitempty" yaml:"fixed_in,omitempty"`
	FixedByPkg      map[string][]string `json:"fixed_by_pkg,omitempty" yaml:"fixed_by_pkg,omitempty"`
	IntroducedIn    string              `json:"introduced_in,omitempty" yaml:"introduced_in,omitempty"`
	PublishedAt     string              `json:"published_at,omitempty" yaml:"published_at,omitempty"`
	URL             string              `json:"url,omitempty" yaml:"url,omitempty"`
}

// EffectiveCategory classifies an Advisory into "kernel", "os", or "language".
func (a Advisory) EffectiveCategory() string {
	if a.Category != "" {
		return a.Category
	}
	if a.Ecosystem == EcoLinux || a.Package == "linux" || a.Package == "kernel" {
		return "kernel"
	}
	switch a.Ecosystem {
	case "Debian", "Ubuntu", "RHEL", "Alpine", "Rocky Linux", "AlmaLinux", "macOS", "OpenWrt":
		return "os"
	default:
		return "language"
	}
}

func (a Advisory) DisplayID() string {
	if a.CVEID != "" {
		return a.CVEID
	}
	if a.GHSAID != "" {
		return a.GHSAID
	}
	return a.ID
}

// VulnerabilityMatch represents a confirmed vulnerability or pending security update on a host.
type VulnerabilityMatch struct {
	ID               string   `json:"id" yaml:"id"`
	AdvisoryID       string   `json:"advisory_id,omitempty" yaml:"advisory_id,omitempty"`
	CVEID            string   `json:"cve_id,omitempty" yaml:"cve_id,omitempty"`
	GHSAID           string   `json:"ghsa_id,omitempty" yaml:"ghsa_id,omitempty"`
	CVE              string   `json:"cve" yaml:"cve"`
	Package          string   `json:"package" yaml:"package"`
	SourcePackage    string   `json:"source_package,omitempty" yaml:"source_package,omitempty"`
	Ecosystem        string   `json:"ecosystem,omitempty" yaml:"ecosystem,omitempty"`
	Location         string   `json:"location,omitempty" yaml:"location,omitempty"`
	InstalledVersion string   `json:"installed_version" yaml:"installed_version"`
	FixedVersion     string   `json:"fixed_version,omitempty" yaml:"fixed_version,omitempty"`
	VulnerableRange  string   `json:"vulnerable_range,omitempty" yaml:"vulnerable_range,omitempty"`
	FixedIn          []string `json:"fixed_in,omitempty" yaml:"fixed_in,omitempty"`
	Severity         string   `json:"severity" yaml:"severity"`
	CVSS             float64  `json:"cvss,omitempty" yaml:"cvss,omitempty"`
	Summary          string   `json:"summary" yaml:"summary"`
	URL              string   `json:"url,omitempty" yaml:"url,omitempty"`
	IsOSPackage      bool     `json:"is_os_package,omitempty" yaml:"is_os_package,omitempty"`
	IsKernel         bool     `json:"is_kernel,omitempty" yaml:"is_kernel,omitempty"`
	Mitigated        bool     `json:"mitigated,omitempty" yaml:"mitigated,omitempty"`
	RemediationCmd   string   `json:"remediation_cmd,omitempty" yaml:"remediation_cmd,omitempty"`
	RollbackScript   string   `json:"rollback_script,omitempty" yaml:"rollback_script,omitempty"`
	MitigateScript   string   `json:"mitigate_script,omitempty" yaml:"mitigate_script,omitempty"`
	Strategy         string   `json:"strategy,omitempty" yaml:"strategy,omitempty"`
	LockdownWarning  string   `json:"lockdown_warning,omitempty" yaml:"lockdown_warning,omitempty"`
	Status           string   `json:"status,omitempty" yaml:"status,omitempty"`
	Reason           string   `json:"reason,omitempty" yaml:"reason,omitempty"`
	Action           string   `json:"action,omitempty" yaml:"action,omitempty"`
}

func (v VulnerabilityMatch) EffectiveID() string {
	if v.CVE != "" {
		return v.CVE
	}
	if v.CVEID != "" {
		return v.CVEID
	}
	if v.ID != "" {
		return v.ID
	}
	if v.AdvisoryID != "" {
		return v.AdvisoryID
	}
	return v.Package
}

// HostAuditResult captures the full audit and remediation outcome for one host.
type HostAuditResult struct {
	Target                   HostTarget           `json:"target" yaml:"target"`
	Host                     string               `json:"host" yaml:"host"`
	LegacyName               string               `json:"name,omitempty" yaml:"name,omitempty"`
	Status                   string               `json:"status" yaml:"status"`
	Detail                  string               `json:"detail" yaml:"detail"`
	HealthScore             int                  `json:"health_score" yaml:"health_score"`
	LatencyMS               int64                `json:"latency_ms" yaml:"latency_ms"`
	CVEs                    []string             `json:"cves,omitempty" yaml:"cves,omitempty"`
	Vulnerabilities          []VulnerabilityMatch    `json:"vulnerabilities" yaml:"vulnerabilities"`
	UnmitigatedItems         []VulnerabilityMatch    `json:"unmitigated_items,omitempty" yaml:"unmitigated_items,omitempty"`
	FixedItems               []VulnerabilityMatch    `json:"fixed_items,omitempty" yaml:"fixed_items,omitempty"`
	IgnoredItems             []VulnerabilityMatch    `json:"ignored_items,omitempty" yaml:"ignored_items,omitempty"`
	MitigatedVulnerabilities []VulnerabilityMatch    `json:"mitigated_vulnerabilities,omitempty" yaml:"mitigated_vulnerabilities,omitempty"`
	RetirableMitigations    []string             `json:"retirable_mitigations,omitempty" yaml:"retirable_mitigations,omitempty"`
	PackagesCount           int                  `json:"packages_count" yaml:"packages_count"`
	AssetsCount             int                  `json:"assets_count" yaml:"assets_count"`
	OSContext               OSContext            `json:"os_context" yaml:"os_context"`
	OSSecurity               OSSecurityReport        `json:"os_security" yaml:"os_security"`
	EcosystemSummary         EcosystemSummary        `json:"ecosystems_summary" yaml:"ecosystems_summary"`
	WorkspaceProjects        []WorkspaceProjectAudit `json:"workspace_projects,omitempty" yaml:"workspace_projects,omitempty"`
	OrphanedVenvs            []OrphanedVenv          `json:"orphaned_venvs,omitempty" yaml:"orphaned_venvs,omitempty"`
	Reachable                bool                    `json:"reachable" yaml:"reachable"`
	Error                   string               `json:"error,omitempty" yaml:"error,omitempty"`
}

// AuditReport is the top-level audit result saved to latest_status.json and rendered in GUI/CLI.
type AuditReport struct {
	Timestamp       string            `json:"timestamp" yaml:"timestamp"`
	DurationMS      int64             `json:"duration_ms" yaml:"duration_ms"`
	ClusterScore    int               `json:"cluster_score" yaml:"cluster_score"`
	AdvisoriesCount int               `json:"advisories_count" yaml:"advisories_count"`
	Days            int               `json:"days" yaml:"days"`
	Hosts           []HostAuditResult `json:"hosts" yaml:"hosts"`
}

// AITriageResult holds AI feasibility reasoning and dual remediation/rollback scripts.
type AITriageResult struct {
	Success       bool   `json:"success"`
	Cached        bool   `json:"cached,omitempty"`
	CacheFile     string `json:"cache_file,omitempty"`
	Verdict       string `json:"verdict"` // "mitigable", "awaiting_patch", "failed"
	HasWorkaround bool   `json:"has_workaround"`
	Strategy      string `json:"strategy"`
	Reason        string `json:"reason"`
	Script        string `json:"script"`
	Rollback      string `json:"rollback"`
	Provider      string `json:"provider,omitempty"`
	Model         string `json:"model,omitempty"`
	Error         string `json:"error,omitempty"`
}

// DoctorItem represents a single diagnostic check item in `security-sentinel doctor` and GUI.
type DoctorItem struct {
	Category   string `json:"category"` // "local", "host", "intel", "notify", "ai", "schedule"
	Name       string `json:"name"`
	Status     string `json:"status"` // "ok", "warn", "fail"
	LatencyMS  int64  `json:"latency_ms,omitempty"`
	Summary    string `json:"summary"`
	Suggestion string `json:"suggestion,omitempty"`
}

// HAProgressEvent streams zero-downtime rolling reboot progress to CLI and GUI.
type HAProgressEvent struct {
	Timestamp string `json:"timestamp"`
	NodeID    string `json:"node_id"`
	Phase     string `json:"phase"` // "drain", "reboot", "wait_ssh", "sync", "gateway_reload", "done", "error"
	Level     string `json:"level"` // "INFO", "SUCCESS", "WARN", "ERROR"
	Message   string `json:"message"`
}

// RemediationRecord tracks applied or rolled-back actions in the L4 ledger / Time Machine.
type RemediationRecord struct {
	ID           string `json:"id" yaml:"id"`
	HostKey      string `json:"host_key" yaml:"host_key"`
	HostName     string `json:"host_name" yaml:"host_name"`
	CVEID        string `json:"cve_id" yaml:"cve_id"`
	Package      string `json:"package,omitempty" yaml:"package,omitempty"`
	Kind         string `json:"kind" yaml:"kind"` // "os_patch", "ai_workaround", "rollback", "rolling_reboot"
	Status       string `json:"status" yaml:"status"`
	Strategy     string `json:"strategy,omitempty" yaml:"strategy,omitempty"`
	ScriptPath   string `json:"script_path,omitempty" yaml:"script_path,omitempty"`
	RollbackPath string `json:"rollback_path,omitempty" yaml:"rollback_path,omitempty"`
	CanRollback  bool   `json:"can_rollback" yaml:"can_rollback"`
	FailureCount int    `json:"failure_count" yaml:"failure_count"`
	LockoutUntil int64  `json:"lockout_until" yaml:"lockout_until"`
	UpdatedAt    string `json:"updated_at" yaml:"updated_at"`
	Log          string `json:"log,omitempty" yaml:"log,omitempty"`
}

// IgnoreRule represents a user-defined mute / skip-version / temporary snooze rule on a vulnerability or update.
type IgnoreRule struct {
	Key            string `json:"key" yaml:"key"`
	HostKey        string `json:"host_key" yaml:"host_key"`
	HostName       string `json:"host_name" yaml:"host_name"`
	VulnID         string `json:"vuln_id" yaml:"vuln_id"`
	Package        string `json:"package" yaml:"package"`
	Mode           string `json:"mode" yaml:"mode"` // "skip_version", "snooze", "permanent"
	SkippedVersion string `json:"skipped_version,omitempty" yaml:"skipped_version,omitempty"`
	ExpiresAt      string `json:"expires_at,omitempty" yaml:"expires_at,omitempty"`
	Reason         string `json:"reason,omitempty" yaml:"reason,omitempty"`
	CreatedAt      string `json:"created_at" yaml:"created_at"`
}
