package store

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sixban6/security-sentinel/internal/infra/config"
	"github.com/sixban6/security-sentinel/internal/infra/model"
	"gopkg.in/yaml.v3"
)

const (
	TTLInventoryStatic = 6 * time.Hour
	TTLOSSecurity      = 2 * time.Hour
	TTLAdvisories      = 4 * time.Hour
	TTLOSVDetails      = 24 * time.Hour
	TTLTriageAwaiting  = 7 * 24 * time.Hour
	TTLTriageMitigable = 14 * 24 * time.Hour
	TTLTriageFailed    = 1 * time.Hour
	CircuitLockoutDur  = 24 * time.Hour
	PromptVersionHash  = "v2.0_sentinel_go"
)

var (
	fencedCodeRe   = regexp.MustCompile("(?s)```(?:bash|sh)?\\s*\\n(.*?)\\n```")
	triageReasonRe = regexp.MustCompile(`(?s)### 缺陷机理与研判原因\s*\n+(.*?)(?:\n+###|\z)`)
	unsafeFileRe   = regexp.MustCompile(`[^A-Za-z0-9_.\-]`)
)

type InventoryMeta struct {
	Fingerprint   string `yaml:"fingerprint"`
	PackagesCount int    `yaml:"packages_count"`
	File          string `yaml:"file"`
	UpdatedAt     string `yaml:"updated_at"`
	OSSecAt       string `yaml:"os_sec_at"`
}

type AdvisoryMeta struct {
	Count     int    `yaml:"count"`
	File      string `yaml:"file"`
	FetchedAt string `yaml:"fetched_at"`
	ExpiresAt string `yaml:"expires_at"`
}

type StateFile struct {
	Version           int                                `yaml:"version"`
	CreatedAt         string                             `yaml:"created_at"`
	UpdatedAt         string                             `yaml:"updated_at"`
	Inventories       map[string]InventoryMeta           `yaml:"inventories"`
	Advisories        map[string]AdvisoryMeta            `yaml:"advisories"`
	RemediationLedger map[string]model.RemediationRecord `yaml:"remediation_ledger"`
	History           []model.RemediationRecord          `yaml:"history,omitempty"`
}

type Store struct {
	dir string
	mu  sync.Mutex
}

func New(customDir string) *Store {
	dir := customDir
	if dir == "" {
		dir = config.MemoryDir()
	}
	dir = config.ExpandHome(dir)
	_ = os.MkdirAll(filepath.Join(dir, "inventories"), 0o755)
	_ = os.MkdirAll(filepath.Join(dir, "advisories"), 0o755)
	_ = os.MkdirAll(filepath.Join(dir, "triage"), 0o755)
	return &Store{dir: dir}
}

func (s *Store) Dir() string { return s.dir }

func (s *Store) statePath() string {
	return filepath.Join(s.dir, "state.yaml")
}

func (s *Store) loadStateLocked() StateFile {
	st := StateFile{
		Version:           2,
		CreatedAt:         time.Now().Format(time.RFC3339),
		UpdatedAt:         time.Now().Format(time.RFC3339),
		Inventories:       make(map[string]InventoryMeta),
		Advisories:        make(map[string]AdvisoryMeta),
		RemediationLedger: make(map[string]model.RemediationRecord),
	}
	data, err := os.ReadFile(s.statePath())
	if err != nil {
		return st
	}
	_ = yaml.Unmarshal(data, &st)
	if st.Inventories == nil {
		st.Inventories = make(map[string]InventoryMeta)
	}
	if st.Advisories == nil {
		st.Advisories = make(map[string]AdvisoryMeta)
	}
	if st.RemediationLedger == nil {
		st.RemediationLedger = make(map[string]model.RemediationRecord)
	}
	return st
}

func (s *Store) saveStateLocked(st StateFile) error {
	st.UpdatedAt = time.Now().Format(time.RFC3339)
	return atomicWriteYAML(s.statePath(), st)
}

func atomicWriteYAML(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := yaml.Marshal(v)
	if err != nil {
		return err
	}
	return atomicWriteBytes(path, data)
}

func atomicWriteBytes(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := fmt.Sprintf("%s.tmp.%d.%d", path, os.Getpid(), time.Now().UnixNano())
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func sanitizeFileToken(s string) string {
	return unsafeFileRe.ReplaceAllString(strings.TrimSpace(s), "_")
}

// GetInventory loads cached HostInventory if fingerprint matches AND static TTL (6h) has not expired.
// Also returns osSecFresh indicating whether OS security updates are within their shorter 2h TTL.
func (s *Store) GetInventory(hostKey, currentFingerprint string) (inv *model.HostInventory, hit bool, osSecFresh bool) {
	if currentFingerprint == "" {
		return nil, false, false
	}
	s.mu.Lock()
	st := s.loadStateLocked()
	meta, ok := st.Inventories[hostKey]
	s.mu.Unlock()
	if !ok || meta.Fingerprint != currentFingerprint || meta.File == "" {
		return nil, false, false
	}

	updAt, err := time.Parse(time.RFC3339, meta.UpdatedAt)
	if err != nil || time.Since(updAt) > TTLInventoryStatic {
		return nil, false, false
	}

	fullPath := filepath.Join(s.dir, meta.File)
	data, err := os.ReadFile(fullPath)
	if err != nil {
		return nil, false, false
	}
	var cached model.HostInventory
	if err := yaml.Unmarshal(data, &cached); err != nil {
		return nil, false, false
	}

	secFresh := false
	if osAt, err := time.Parse(time.RFC3339, meta.OSSecAt); err == nil && time.Since(osAt) <= TTLOSSecurity {
		secFresh = true
	}
	return &cached, true, secFresh
}

// SaveInventory persists HostInventory and updates L1 fingerprint metadata.
func (s *Store) SaveInventory(hostKey, fingerprint string, inv model.HostInventory) error {
	relPath := filepath.Join("inventories", sanitizeFileToken(hostKey)+".yaml")
	fullPath := filepath.Join(s.dir, relPath)
	if err := atomicWriteYAML(fullPath, inv); err != nil {
		return err
	}

	nowStr := time.Now().Format(time.RFC3339)
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.loadStateLocked()
	st.Inventories[hostKey] = InventoryMeta{
		Fingerprint:   fingerprint,
		PackagesCount: len(inv.Packages),
		File:          relPath,
		UpdatedAt:     nowStr,
		OSSecAt:       nowStr,
	}
	return s.saveStateLocked(st)
}

// GetAdvisories returns unexpired cached feed advisories (4h TTL).
func (s *Store) GetAdvisories(days int, includeKernel bool) (map[string]model.Advisory, bool) {
	key := fmt.Sprintf("v26_days_%d_kernel_%v", days, includeKernel)
	s.mu.Lock()
	st := s.loadStateLocked()
	meta, ok := st.Advisories[key]
	s.mu.Unlock()
	if !ok || meta.File == "" {
		return nil, false
	}
	expAt, err := time.Parse(time.RFC3339, meta.ExpiresAt)
	if err != nil || time.Now().After(expAt) {
		return nil, false
	}
	data, err := os.ReadFile(filepath.Join(s.dir, meta.File))
	if err != nil {
		return nil, false
	}
	var out map[string]model.Advisory
	if err := yaml.Unmarshal(data, &out); err != nil || len(out) == 0 {
		return nil, false
	}
	return out, true
}

// SaveAdvisories caches feed advisories with TTL.
func (s *Store) SaveAdvisories(advs map[string]model.Advisory, days int, includeKernel bool) error {
	key := fmt.Sprintf("v26_days_%d_kernel_%v", days, includeKernel)
	relPath := filepath.Join("advisories", key+".yaml")
	if err := atomicWriteYAML(filepath.Join(s.dir, relPath), advs); err != nil {
		return err
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.loadStateLocked()
	st.Advisories[key] = AdvisoryMeta{
		Count:     len(advs),
		File:      relPath,
		FetchedAt: now.Format(time.RFC3339),
		ExpiresAt: now.Add(TTLAdvisories).Format(time.RFC3339),
	}
	return s.saveStateLocked(st)
}

// OSVDetailCacheEntry stores enriched OSV vulnerability metadata for 24h.
type OSVDetailCacheEntry struct {
	Advisory  model.Advisory `yaml:"advisory"`
	ExpiresAt string         `yaml:"expires_at"`
}

func (s *Store) LoadOSVDetails() map[string]model.Advisory {
	p := filepath.Join(s.dir, "advisories", "osv_details.yaml")
	data, err := os.ReadFile(p)
	if err != nil {
		return map[string]model.Advisory{}
	}
	var raw map[string]OSVDetailCacheEntry
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return map[string]model.Advisory{}
	}
	now := time.Now()
	out := make(map[string]model.Advisory, len(raw))
	for k, v := range raw {
		if exp, err := time.Parse(time.RFC3339, v.ExpiresAt); err == nil && now.Before(exp) {
			out[k] = v.Advisory
		}
	}
	return out
}

func (s *Store) SaveOSVDetails(items map[string]model.Advisory) {
	if len(items) == 0 {
		return
	}
	p := filepath.Join(s.dir, "advisories", "osv_details.yaml")
	existing := s.LoadOSVDetails()
	for k, v := range items {
		existing[k] = v
	}
	expStr := time.Now().Add(TTLOSVDetails).Format(time.RFC3339)
	wrapped := make(map[string]OSVDetailCacheEntry, len(existing))
	for k, v := range existing {
		wrapped[k] = OSVDetailCacheEntry{Advisory: v, ExpiresAt: expStr}
	}
	_ = atomicWriteYAML(p, wrapped)
}

// L3 AI Triage Markdown Knowledge Base
type triageFrontmatter struct {
	CacheKey         string `yaml:"cache_key"`
	CVEID            string `yaml:"cve_id"`
	Package          string `yaml:"package"`
	InstalledVersion string `yaml:"installed_version"`
	Verdict          string `yaml:"verdict"`
	HasWorkaround    bool   `yaml:"has_workaround"`
	Strategy         string `yaml:"strategy"`
	CreatedAt        string `yaml:"created_at"`
	ExpiresAt        string `yaml:"expires_at"`
	Model            string `yaml:"model"`
	PromptHash       string `yaml:"prompt_template_hash"`
}

func computeTriageKey(vuln model.VulnerabilityMatch, osCtx model.OSContext, modelName string) string {
	envSig := fmt.Sprintf("%s:%s:%s:%s:%s:%s",
		osCtx.OSPretty, osCtx.DistroVersion, osCtx.KernelRelease, osCtx.Arch, osCtx.Shell, osCtx.PkgMgr)
	raw := fmt.Sprintf("%s|%s|%s|%s|%s|%s",
		strings.ToUpper(vuln.EffectiveID()),
		strings.ToLower(vuln.Package),
		vuln.InstalledVersion,
		envSig,
		modelName,
		PromptVersionHash,
	)
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func (s *Store) triageFilePath(cveID, pkg string) string {
	name := fmt.Sprintf("%s_%s.md", sanitizeFileToken(cveID), sanitizeFileToken(pkg))
	return filepath.Join(s.dir, "triage", name)
}

// SaveAITriage writes a human-readable & editable Markdown + YAML Frontmatter triage document.
func (s *Store) SaveAITriage(vuln model.VulnerabilityMatch, osCtx model.OSContext, res model.AITriageResult, modelName string) (string, error) {
	cveID := vuln.EffectiveID()
	pkg := vuln.Package
	if pkg == "" {
		pkg = "system"
	}
	cacheKey := computeTriageKey(vuln, osCtx, modelName)
	now := time.Now()

	verdict := "failed"
	ttl := TTLTriageFailed
	reason := res.Reason
	if res.Success {
		if res.HasWorkaround && strings.TrimSpace(res.Script) != "" {
			verdict = "mitigable"
			ttl = TTLTriageMitigable
		} else {
			verdict = "awaiting_patch"
			ttl = TTLTriageAwaiting
		}
	} else if reason == "" {
		reason = res.Error
	}

	fm := triageFrontmatter{
		CacheKey:         cacheKey,
		CVEID:            cveID,
		Package:          pkg,
		InstalledVersion: vuln.InstalledVersion,
		Verdict:          verdict,
		HasWorkaround:    res.HasWorkaround,
		Strategy:         res.Strategy,
		CreatedAt:        now.Format(time.RFC3339),
		ExpiresAt:        now.Add(ttl).Format(time.RFC3339),
		Model:            modelName,
		PromptHash:       PromptVersionHash,
	}
	fmBytes, err := yaml.Marshal(fm)
	if err != nil {
		return "", err
	}

	var b strings.Builder
	b.WriteString("---\n")
	b.WriteString(strings.TrimSpace(string(fmBytes)))
	b.WriteString("\n---\n\n")
	fmt.Fprintf(&b, "# 漏洞分析与自愈档案: %s (%s)\n\n### 判定结论\n", cveID, pkg)

	switch verdict {
	case "awaiting_patch":
		b.WriteString("⏳ **需等待官方补丁 (无可行的现场配置规避途径)**\n")
	case "mitigable":
		b.WriteString("🛡️ **可现场配置加固 (已有经过静态安全校验的规避与回滚方案)**\n")
	default:
		b.WriteString("⚠️ **研判暂未完成 (AI推理超时或模型异常)**\n")
	}

	if reason == "" {
		reason = "暂无详细机理描述"
	}
	fmt.Fprintf(&b, "\n### 缺陷机理与研判原因\n%s\n", reason)

	if verdict == "mitigable" {
		if res.Strategy != "" {
			fmt.Fprintf(&b, "\n### 规避加固策略\n%s\n", res.Strategy)
		}
		fmt.Fprintf(&b, "\n### 现场规避加固脚本\n```bash\n%s\n```\n", strings.TrimSpace(res.Script))
		rb := strings.TrimSpace(res.Rollback)
		if rb == "" {
			rb = "# 无独立回滚脚本"
		}
		fmt.Fprintf(&b, "\n### 应急回滚脚本\n```bash\n%s\n```\n", rb)
	}

	filePath := s.triageFilePath(cveID, pkg)
	if err := atomicWriteBytes(filePath, []byte(b.String())); err != nil {
		return "", err
	}
	return filePath, nil
}

// GetAITriage loads a matching, unexpired Markdown triage archive (honoring manual edits to script blocks!).
func (s *Store) GetAITriage(vuln model.VulnerabilityMatch, osCtx model.OSContext, modelName string) (*model.AITriageResult, bool) {
	cveID := vuln.EffectiveID()
	pkg := vuln.Package
	if pkg == "" {
		pkg = "system"
	}
	filePath := s.triageFilePath(cveID, pkg)
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, false
	}

	content := string(data)
	if !strings.HasPrefix(content, "---\n") {
		return nil, false
	}
	rest := content[4:]
	endIdx := strings.Index(rest, "\n---\n")
	if endIdx < 0 {
		return nil, false
	}
	fmRaw := rest[:endIdx]
	body := strings.TrimSpace(rest[endIdx+5:])

	var fm triageFrontmatter
	if err := yaml.Unmarshal([]byte(fmRaw), &fm); err != nil {
		return nil, false
	}
	if fm.CacheKey != computeTriageKey(vuln, osCtx, modelName) {
		return nil, false
	}
	if exp, err := time.Parse(time.RFC3339, fm.ExpiresAt); err != nil || time.Now().After(exp) {
		return nil, false
	}

	reason := ""
	if m := triageReasonRe.FindStringSubmatch(body); m != nil {
		reason = strings.TrimSpace(m[1])
	}

	script, rollback := "", ""
	if fm.Verdict == "mitigable" {
		blocks := fencedCodeRe.FindAllStringSubmatch(body, -1)
		if len(blocks) >= 1 {
			script = strings.TrimSpace(blocks[0][1])
		}
		if len(blocks) >= 2 {
			rollback = strings.TrimSpace(blocks[1][1])
		}
	}

	res := &model.AITriageResult{
		Success:       fm.Verdict != "failed",
		Cached:        true,
		CacheFile:     filePath,
		Verdict:       fm.Verdict,
		HasWorkaround: fm.HasWorkaround,
		Strategy:      fm.Strategy,
		Reason:        reason,
		Script:        script,
		Rollback:      rollback,
		Model:         fm.Model,
	}
	if fm.Verdict == "failed" {
		res.Error = reason
	}
	return res, true
}

// CheckCircuitBreaker checks if (hostKey, cveID) is currently locked due to repeated verification/rollback failures.
func (s *Store) CheckCircuitBreaker(hostKey, cveID string) (locked bool, reason string) {
	k := hostKey + ":" + strings.ToUpper(cveID)
	s.mu.Lock()
	st := s.loadStateLocked()
	rec, ok := st.RemediationLedger[k]
	s.mu.Unlock()
	if !ok {
		return false, ""
	}
	nowTS := time.Now().Unix()
	if rec.LockoutUntil > nowTS {
		remMin := (rec.LockoutUntil - nowTS) / 60
		if remMin < 1 {
			remMin = 1
		}
		return true, fmt.Sprintf("此前加固验证失败已触发熔断保护，冷却剩余 %d 分钟", remMin)
	}
	return false, ""
}

// RecordRemediation updates both the L4 circuit-breaker ledger and the Time-Machine history timeline.
func (s *Store) RecordRemediation(rec model.RemediationRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.loadStateLocked()

	now := time.Now()
	rec.UpdatedAt = now.Format("2006-01-02 15:04:05")
	if rec.ID == "" {
		rec.ID = fmt.Sprintf("%d-%s", now.UnixNano(), sanitizeFileToken(rec.CVEID))
	}
	if len(rec.Log) > 400 {
		rec.Log = rec.Log[:400]
	}

	ledgerKey := rec.HostKey + ":" + strings.ToUpper(rec.CVEID)
	prev := st.RemediationLedger[ledgerKey]
	rec.FailureCount = prev.FailureCount
	rec.LockoutUntil = prev.LockoutUntil

	switch rec.Status {
	case "success", "rolled_back_manual":
		rec.FailureCount = 0
		rec.LockoutUntil = 0
	case "transient_error":
		// Do not burn circuit breaker quota on transient SSH hiccups
	case "verification_failed", "reverted":
		rec.FailureCount++
		if rec.FailureCount >= 2 {
			rec.LockoutUntil = now.Add(CircuitLockoutDur).Unix()
			rec.Status = "circuit_breaker_locked"
		}
	}

	st.RemediationLedger[ledgerKey] = rec
	st.History = append([]model.RemediationRecord{rec}, st.History...)
	if len(st.History) > 200 {
		st.History = st.History[:200]
	}
	_ = s.saveStateLocked(st)
}

// ListHistory returns chronological remediation records (newest first) for CLI and GUI Time Machine.
func (s *Store) ListHistory() []model.RemediationRecord {
	s.mu.Lock()
	st := s.loadStateLocked()
	s.mu.Unlock()
	if len(st.History) > 0 {
		out := make([]model.RemediationRecord, len(st.History))
		copy(out, st.History)
		return out
	}
	var out []model.RemediationRecord
	for _, r := range st.RemediationLedger {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].UpdatedAt > out[j].UpdatedAt
	})
	return out
}

// AppliedMitigationsForHost returns CVE -> status for active AI workarounds recorded locally.
func (s *Store) AppliedMitigationsForHost(hostKey string) map[string]string {
	s.mu.Lock()
	st := s.loadStateLocked()
	s.mu.Unlock()
	res := make(map[string]string)
	for _, r := range st.RemediationLedger {
		if r.HostKey == hostKey && r.Kind == "ai_workaround" && r.Status == "success" {
			res[strings.ToUpper(r.CVEID)] = "APPLIED"
		}
	}
	return res
}

type MemorySummary struct {
	MemoryDir           string   `json:"memory_dir"`
	TotalSizeKB         float64  `json:"total_size_kb"`
	FileCount           int      `json:"file_count"`
	InventoriesCount    int      `json:"inventories_count"`
	AdvisoriesCached    bool     `json:"advisories_cached"`
	TriageTotal         int      `json:"triage_total"`
	TriageAwaitingPatch int      `json:"triage_awaiting_patch"`
	TriageMitigable     int      `json:"triage_mitigable"`
	TriageFailed        int      `json:"triage_failed"`
	LedgerEntries       int      `json:"ledger_entries"`
	HistoryEntries      int      `json:"history_entries"`
	LockedEntries       []string `json:"locked_entries"`
}

func (s *Store) Status() MemorySummary {
	s.mu.Lock()
	st := s.loadStateLocked()
	s.mu.Unlock()

	var totalBytes int64
	fileCount := 0
	_ = filepath.Walk(s.dir, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			totalBytes += info.Size()
			fileCount++
		}
		return nil
	})

	triageDir := filepath.Join(s.dir, "triage")
	entries, _ := os.ReadDir(triageDir)
	tTotal, tWait, tMit, tFail := 0, 0, 0, 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
			continue
		}
		tTotal++
		if b, err := os.ReadFile(filepath.Join(triageDir, e.Name())); err == nil {
			head := string(b)
			if len(head) > 600 {
				head = head[:600]
			}
			switch {
			case strings.Contains(head, "verdict: awaiting_patch"):
				tWait++
			case strings.Contains(head, "verdict: mitigable"):
				tMit++
			case strings.Contains(head, "verdict: failed"):
				tFail++
			}
		}
	}

	nowTS := time.Now().Unix()
	var locked []string
	for k, v := range st.RemediationLedger {
		if v.LockoutUntil > nowTS {
			locked = append(locked, k)
		}
	}
	sort.Strings(locked)

	return MemorySummary{
		MemoryDir:           s.dir,
		TotalSizeKB:         float64(totalBytes) / 1024.0,
		FileCount:           fileCount,
		InventoriesCount:    len(st.Inventories),
		AdvisoriesCached:    len(st.Advisories) > 0,
		TriageTotal:         tTotal,
		TriageAwaitingPatch: tWait,
		TriageMitigable:     tMit,
		TriageFailed:        tFail,
		LedgerEntries:       len(st.RemediationLedger),
		HistoryEntries:      len(st.History),
		LockedEntries:       locked,
	}
}

func (s *Store) Clean(target string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.loadStateLocked()
	count := 0

	removeDirFiles := func(sub string) {
		d := filepath.Join(s.dir, sub)
		entries, _ := os.ReadDir(d)
		for _, e := range entries {
			if !e.IsDir() {
				if os.Remove(filepath.Join(d, e.Name())) == nil {
					count++
				}
			}
		}
	}

	switch target {
	case "ai":
		removeDirFiles("triage")
	case "inventory":
		removeDirFiles("inventories")
		st.Inventories = make(map[string]InventoryMeta)
	case "advisories":
		removeDirFiles("advisories")
		st.Advisories = make(map[string]AdvisoryMeta)
	default:
		removeDirFiles("triage")
		removeDirFiles("inventories")
		removeDirFiles("advisories")
		st.Inventories = make(map[string]InventoryMeta)
		st.Advisories = make(map[string]AdvisoryMeta)
		st.RemediationLedger = make(map[string]model.RemediationRecord)
		st.History = nil
	}
	_ = s.saveStateLocked(st)
	return count
}
