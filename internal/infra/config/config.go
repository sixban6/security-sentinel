package config

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sixban6/security-sentinel/internal/infra/model"
	"gopkg.in/yaml.v3"
)

//go:embed sentinel.example.yaml
var EmbeddedExampleYAML string

type AdvisoriesConfig struct {
	Days          int  `json:"days" yaml:"days"`
	IncludeKernel bool `json:"include_kernel" yaml:"include_kernel"`
	OSVEnabled    bool `json:"osv_enabled" yaml:"osv_enabled"`
}

type GatewayConfig struct {
	Enabled        bool     `json:"enabled" yaml:"enabled"`
	SSHHost        string   `json:"ssh_host" yaml:"ssh_host"`
	ClashAPIURL    string   `json:"clash_api_url" yaml:"clash_api_url"`
	SelectorGroup  string   `json:"selector_group" yaml:"selector_group"`
	ReloadCommands []string `json:"reload_commands" yaml:"reload_commands"`
}

type RollingNodeConfig struct {
	ID          string   `json:"id" yaml:"id"`
	SSHHost     string   `json:"ssh_host" yaml:"ssh_host"`
	Keywords    []string `json:"keywords" yaml:"keywords"`
	Peer        string   `json:"peer" yaml:"peer"`
	SyncCommand string   `json:"sync_command" yaml:"sync_command"`
}

type AIRemediationConfig struct {
	Enabled         bool   `json:"enabled" yaml:"enabled"`
	Provider        string `json:"provider" yaml:"provider"` // auto, gemini, openai, anthropic, agy
	Model           string `json:"model" yaml:"model"`
	BaseURL         string `json:"base_url,omitempty" yaml:"base_url,omitempty"`
	AutoExecute     bool   `json:"auto_execute" yaml:"auto_execute"`
	MaxFixesPerHost int    `json:"max_fixes_per_host,omitempty" yaml:"max_fixes_per_host,omitempty"`
}

type AutoFixConfig struct {
	Enabled bool   `json:"enabled" yaml:"enabled"`
	Mode    string `json:"mode,omitempty" yaml:"mode,omitempty"` // "safe-os", "all", "off"
}

func (a *AutoFixConfig) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		var b bool
		if err := value.Decode(&b); err == nil {
			a.Enabled = b
			if b && a.Mode == "" {
				a.Mode = "safe-os"
			}
			return nil
		}
	}
	type rawAutoFix AutoFixConfig
	var raw rawAutoFix
	raw.Mode = "safe-os"
	if err := value.Decode(&raw); err != nil {
		return err
	}
	*a = AutoFixConfig(raw)
	return nil
}

type NotificationsConfig struct {
	Policy            string `json:"policy" yaml:"policy"` // "always", "on_change", "critical_only"
	Desktop           bool   `json:"desktop" yaml:"desktop"`
	SmartPower        bool   `json:"smart_power" yaml:"smart_power"`
	RespectHotspot    bool   `json:"respect_hotspot" yaml:"respect_hotspot"`
	ScanMode          string `json:"scan_mode,omitempty" yaml:"scan_mode,omitempty"` // "interval" (default), "daily", "manual"
	AutoScanHours     int    `json:"auto_scan_hours" yaml:"auto_scan_hours"`
	DailyScanTime     string `json:"daily_scan_time,omitempty" yaml:"daily_scan_time,omitempty"` // e.g. "09:00"
	PreferredTerminal string `json:"preferred_terminal,omitempty" yaml:"preferred_terminal,omitempty"`
}

// HostEntry supports both shorthand string ("root@1.2.3.4") and rich object syntax in sentinel.yaml.
type HostEntry struct {
	Target model.HostTarget
	RawStr string
}

func (h *HostEntry) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		var s string
		if err := value.Decode(&s); err != nil {
			return err
		}
		h.RawStr = strings.TrimSpace(s)
		h.Target = NormalizeStringHost(h.RawStr)
		return nil
	}
	var raw model.HostTarget
	if err := value.Decode(&raw); err != nil {
		return err
	}
	h.Target = NormalizeStructHost(raw)
	return nil
}

func (h HostEntry) MarshalYAML() (any, error) {
	t := h.Target
	if t.IsLocal() {
		return "local", nil
	}
	if t.Port == 0 && t.IdentityFile == "" && t.OSType == "" && t.PackageManager == "" &&
		len(t.CustomCommands) == 0 && (t.Name == "" || t.Name == t.SSHHost) && t.SSHHost != "" {
		return t.SSHHost, nil
	}
	return t, nil
}

// Config is the root sentinel.yaml configuration structure.
type Config struct {
	Hosts          []HostEntry         `json:"hosts" yaml:"hosts"`
	Advisories     AdvisoriesConfig    `json:"advisories" yaml:"advisories"`
	Gateway        GatewayConfig       `json:"gateway" yaml:"gateway"`
	RollingNodes   []RollingNodeConfig `json:"rolling_nodes" yaml:"rolling_nodes"`
	AIRemediation  AIRemediationConfig `json:"ai_remediation" yaml:"ai_remediation"`
	Workspaces     []string            `json:"workspaces" yaml:"workspaces"`
	WorkspaceRoots []string            `json:"workspace_roots,omitempty" yaml:"workspace_roots,omitempty"`
	AutoFix        AutoFixConfig       `json:"auto_fix" yaml:"auto_fix"`
	Notifications  NotificationsConfig `json:"notifications" yaml:"notifications"`

	SourcePath string `json:"-" yaml:"-"`
}

// DefaultConfig returns safe, zero-surprise defaults (audit is 100% read-only unless auto_fix is enabled).
func DefaultConfig() Config {
	return Config{
		Hosts: []HostEntry{
			{Target: model.HostTarget{ID: "local", Name: "本机研发环境", Type: "local"}},
		},
		Advisories: AdvisoriesConfig{
			Days:          3,
			IncludeKernel: true,
			OSVEnabled:    true,
		},
		Gateway: GatewayConfig{
			Enabled:       false,
			ClashAPIURL:   "http://127.0.0.1:9090",
			SelectorGroup: "Proxy",
		},
		AIRemediation: AIRemediationConfig{
			Enabled:     false,
			Provider:    "gemini",
			Model:       "gemini-2.5-flash",
			AutoExecute: false,
		},
		AutoFix: AutoFixConfig{
			Enabled: false,
			Mode:    "safe-os",
		},
		Notifications: NotificationsConfig{
			Policy:            "always",
			Desktop:           true,
			SmartPower:        true,
			RespectHotspot:    true,
			ScanMode:          "interval",
			AutoScanHours:     12,
			DailyScanTime:     "09:00",
			PreferredTerminal: "auto",
		},
	}
}

// FindConfigFile locates the active sentinel.yaml in priority order.
func FindConfigFile(customPath string) string {
	if customPath != "" {
		exp := ExpandHome(customPath)
		if info, err := os.Stat(exp); err == nil && !info.IsDir() {
			abs, _ := filepath.Abs(exp)
			return abs
		}
	}
	if envCfg := os.Getenv("SENTINEL_CONFIG"); envCfg != "" {
		exp := ExpandHome(envCfg)
		if info, err := os.Stat(exp); err == nil && !info.IsDir() {
			abs, _ := filepath.Abs(exp)
			return abs
		}
	}
	candidates := []string{
		"./sentinel.yaml",
		"./sentinel.yml",
		"./sentinel.json",
		GlobalConfigFile(),
		ExpandHome("~/.gemini/config/sentinel.yaml"),
	}
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(exeDir, "sentinel.yaml"),
			filepath.Join(filepath.Dir(exeDir), "sentinel.yaml"),
		)
	}
	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && !info.IsDir() {
			abs, _ := filepath.Abs(c)
			return abs
		}
	}
	return ""
}

// Load reads sentinel.yaml (or JSON) and merges defaults cleanly.
func Load(customPath string) (Config, error) {
	cfg := DefaultConfig()
	path := FindConfigFile(customPath)
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("read config %s: %w", path, err)
	}
	if err := ParseBytes(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parse config %s: %w", path, err)
	}
	cfg.SourcePath = path
	return cfg, nil
}

// ParseBytes parses YAML or JSON config content into dst.
func ParseBytes(data []byte, dst *Config) error {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil
	}
	if strings.HasPrefix(trimmed, "{") {
		var raw map[string]any
		if err := json.Unmarshal(data, &raw); err == nil {
			yamlBytes, err := yaml.Marshal(raw)
			if err == nil {
				data = yamlBytes
			}
		}
	}
	if err := yaml.Unmarshal(data, dst); err != nil {
		return err
	}
	if dst.Advisories.Days <= 0 {
		dst.Advisories.Days = 3
	}
	if dst.AIRemediation.Provider == "" {
		dst.AIRemediation.Provider = "gemini"
	}
	if dst.AIRemediation.Model == "" {
		dst.AIRemediation.Model = "gemini-2.5-flash"
	}
	if dst.Notifications.Policy == "" {
		dst.Notifications.Policy = "always"
	}
	if dst.Notifications.PreferredTerminal == "" {
		dst.Notifications.PreferredTerminal = "auto"
	}
	if dst.Notifications.ScanMode == "" {
		dst.Notifications.ScanMode = "interval"
	}
	if dst.Notifications.AutoScanHours <= 0 {
		dst.Notifications.AutoScanHours = 12
	}
	if dst.Notifications.DailyScanTime == "" {
		dst.Notifications.DailyScanTime = "09:00"
	}
	if dst.AutoFix.Mode == "" {
		dst.AutoFix.Mode = "safe-os"
	}
	return nil
}

// Save writes Config atomically to targetPath (defaulting to SourcePath or GlobalConfigFile).
func Save(cfg Config, targetPath string) (string, error) {
	dest := targetPath
	if dest == "" {
		dest = cfg.SourcePath
	}
	if dest == "" {
		dest = GlobalConfigFile()
	}
	dest = ExpandHome(dest)
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return "", err
	}
	out, err := yaml.Marshal(cfg)
	if err != nil {
		return "", err
	}
	tmp := fmt.Sprintf("%s.tmp.%d", dest, os.Getpid())
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, dest); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	return dest, nil
}

// NormalizeStringHost converts shorthand like "root@1.2.3.4" or "local" into a HostTarget.
func NormalizeStringHost(s string) model.HostTarget {
	s = strings.TrimSpace(s)
	low := strings.ToLower(s)
	if low == "local" || low == "localhost" || s == "本机" || low == "127.0.0.1" {
		return model.HostTarget{
			ID:   "local",
			Name: "本机研发环境",
			Type: "local",
		}
	}
	t := model.HostTarget{
		Name:    s,
		Type:    "remote",
		SSHHost: s,
	}
	if at := strings.IndexByte(s, '@'); at > 0 {
		t.User = s[:at]
		t.Host = s[at+1:]
	} else {
		t.Host = s
	}
	t.ID = t.EffectiveKey()
	return t
}

// NormalizeStructHost normalizes an object host entry while strictly separating Name from SSHHost.
func NormalizeStructHost(raw model.HostTarget) model.HostTarget {
	lowHost := strings.ToLower(strings.TrimSpace(raw.Host))
	if strings.ToLower(raw.Type) == "local" || lowHost == "local" || lowHost == "localhost" || lowHost == "127.0.0.1" {
		name := strings.TrimSpace(raw.Name)
		if name == "" {
			name = "本机研发环境"
		}
		return model.HostTarget{
			ID:   "local",
			Name: name,
			Type: "local",
		}
	}

	raw.Type = "remote"
	if raw.User == "" {
		raw.User = "root"
	}
	if raw.SSHHost == "" && raw.Host != "" {
		if strings.Contains(raw.Host, "@") {
			raw.SSHHost = raw.Host
		} else {
			raw.SSHHost = raw.User + "@" + raw.Host
		}
	}
	if raw.Host == "" && raw.SSHHost != "" {
		if at := strings.IndexByte(raw.SSHHost, '@'); at > 0 {
			raw.User = raw.SSHHost[:at]
			raw.Host = raw.SSHHost[at+1:]
		} else {
			raw.Host = raw.SSHHost
		}
	}
	if raw.IdentityFile != "" {
		raw.IdentityFile = ExpandHome(raw.IdentityFile)
	}
	if strings.TrimSpace(raw.Name) == "" {
		if raw.SSHHost != "" {
			raw.Name = raw.SSHHost
		} else {
			raw.Name = raw.Host
		}
	}
	if raw.ID == "" {
		raw.ID = raw.EffectiveKey()
	}
	return raw
}

// ConfiguredHosts returns normalized targets with local host always included first unless already present.
func (c Config) ConfiguredHosts() []model.HostTarget {
	var out []model.HostTarget
	hasLocal := false
	seen := make(map[string]bool)

	for _, entry := range c.Hosts {
		t := entry.Target
		if t.IsLocal() {
			hasLocal = true
		}
		key := t.EffectiveKey()
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, t)
	}

	if !hasLocal {
		localTarget := model.HostTarget{
			ID:   "local",
			Name: "本机研发环境",
			Type: "local",
		}
		out = append([]model.HostTarget{localTarget}, out...)
	}
	return out
}

// EffectiveWorkspaces returns expanded, existing workspace roots.
func (c Config) EffectiveWorkspaces() []string {
	var raw []string
	if env := os.Getenv("SENTINEL_WORKSPACE_ROOTS"); env != "" {
		for _, p := range strings.FieldsFunc(env, func(r rune) bool { return r == ':' || r == ';' }) {
			if strings.TrimSpace(p) != "" {
				raw = append(raw, strings.TrimSpace(p))
			}
		}
	}
	raw = append(raw, c.Workspaces...)
	raw = append(raw, c.WorkspaceRoots...)

	// Automatically include standard JetBrains IDE workspace folders (e.g. ~/IdeaProjects for Java Maven/Gradle!)
	// unless isolated unit-test mode is active.
	if os.Getenv("SENTINEL_SKIP_CENTRAL_VENVS") == "" && os.Getenv("SENTINEL_SKIP_IDE_WORKSPACES") == "" {
		raw = append(raw,
			"~/IdeaProjects",
			"~/AndroidStudioProjects",
			"~/PycharmProjects",
			"~/GolandProjects",
			"~/WebstormProjects",
		)
	}

	if len(raw) == 0 {
		defaults := []string{
			"~/Projects",
			"~/workspace",
			"~/Developer",
			"~/Code",
			"~/src",
			"~/repos",
		}
		if cwd, err := os.Getwd(); err == nil {
			defaults = append(defaults, cwd)
		}
		raw = defaults
	}

	seen := make(map[string]bool)
	var valid []string
	for _, p := range raw {
		exp := ExpandHome(p)
		if exp == "" {
			continue
		}
		abs, err := filepath.Abs(exp)
		if err != nil {
			continue
		}
		if realP, err := filepath.EvalSymlinks(abs); err == nil {
			abs = realP
		}
		info, err := os.Stat(abs)
		if err != nil || !info.IsDir() {
			continue
		}
		if !seen[abs] {
			seen[abs] = true
			valid = append(valid, abs)
		}
	}

	// Converge nested subdirectories when parent root is already included.
	var converged []string
	for _, p := range valid {
		nested := false
		for _, other := range valid {
			if p != other && strings.HasPrefix(p, other+string(filepath.Separator)) {
				nested = true
				break
			}
		}
		if !nested {
			converged = append(converged, p)
		}
	}
	return converged
}

// RollingNodesMap returns node_id -> RollingNodeConfig.
func (c Config) RollingNodesMap() map[string]RollingNodeConfig {
	res := make(map[string]RollingNodeConfig, len(c.RollingNodes))
	for _, n := range c.RollingNodes {
		id := strings.TrimSpace(n.ID)
		if id == "" && n.SSHHost != "" {
			parts := strings.Split(n.SSHHost, "@")
			id = parts[len(parts)-1]
		}
		if id != "" {
			n.ID = id
			res[id] = n
		}
	}
	return res
}
