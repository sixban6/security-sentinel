package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/sixban6/security-sentinel/internal/infra/config"
	"github.com/sixban6/security-sentinel/internal/infra/store"
	"github.com/sixban6/security-sentinel/internal/infra/model"
	"github.com/sixban6/security-sentinel/internal/infra/secrets"
)

const ScriptDelimiter = "---ROLLBACK_SCRIPT---"

var (
	codeFenceRe  = regexp.MustCompile("(?s)```(?:sh|bash)?\\s*\\n(.*?)\\n```")
	strategyRe   = regexp.MustCompile(`(?i)^#\s*(?:Strategy|REMEDIATION STRATEGY|策略|加固策略)[\s:]+(.+)$`)
	dangerousRe  = regexp.MustCompile(`(?i)(?:\brm\s+-[a-z]*r[a-z]*f\s+/(?:\s|$|\*)|\bmkfs\.|\bdd\s+if=|\bshred\b|:\(\)\s*\{|>\s*/etc/(?:passwd|shadow|sudoers)|curl\s+[^|\n]+\|\s*(?:ba)?sh|wget\s+[^|\n]+\|\s*(?:ba)?sh)`)
	bashismRe    = regexp.MustCompile(`(?m)(?:\[\[|\bdeclare\s+-[aAilrtux]|\bfunction\s+[A-Za-z_]|\bsource\s+)`)
)

type Engine struct {
	Cfg  config.AIRemediationConfig
	Mem  *store.Store
	HTTP *http.Client
}

func NewEngine(cfg config.AIRemediationConfig, mem *store.Store) *Engine {
	return &Engine{
		Cfg:  cfg,
		Mem:  mem,
		HTTP: &http.Client{Timeout: 120 * time.Second},
	}
}

// ResolveProvider selects the best available AI backend ("openai", "anthropic", "gemini", "agy", or "").
func (e *Engine) ResolveProvider() (provider string, detail string) {
	pref := strings.ToLower(strings.TrimSpace(e.Cfg.Provider))
	if pref == "" {
		if strings.TrimSpace(e.Cfg.BaseURL) != "" {
			pref = "openai"
		} else {
			pref = "openai"
		}
	}
	gwDesc := strings.TrimSpace(e.Cfg.BaseURL)
	switch pref {
	case "openai":
		if secrets.GetAIGatewayToken("openai") != "" {
			if gwDesc != "" {
				return "openai", "OpenAI 兼容网关 (" + gwDesc + ")"
			}
			return "openai", "OpenAI Compatible HTTPS API"
		}
		return "", "未配置 AI 网关访问令牌 (Token / API Key)"
	case "anthropic":
		if secrets.GetAIGatewayToken("anthropic") != "" {
			if gwDesc != "" {
				return "anthropic", "Anthropic 兼容网关 (" + gwDesc + ")"
			}
			return "anthropic", "Anthropic Claude HTTPS API"
		}
		return "", "未配置 AI 网关访问令牌 (Token / API Key)"
	case "gemini":
		if secrets.GetAIGatewayToken("gemini") != "" {
			if gwDesc != "" {
				return "gemini", "Gemini 兼容网关 (" + gwDesc + ")"
			}
			return "gemini", "Google Gemini HTTPS API"
		}
		if bin := FindAgyBinary(); bin != "" {
			return "agy", "Google Gemini via local agy (" + bin + ")"
		}
		return "", "未配置 AI 网关访问令牌 (Token / API Key) 或本地 agy"
	case "agy":
		if bin := FindAgyBinary(); bin != "" {
			return "agy", "Local Google agy CLI (" + bin + ")"
		}
		return "", "已指定 provider=agy 但本机未找到 agy 命令"
	default: // "auto"
		if secrets.Get(secrets.KeyAIGatewayToken) != "" || secrets.Get(secrets.KeyOpenAIAPIKey) != "" {
			if gwDesc != "" {
				return "openai", "OpenAI 兼容网关 (" + gwDesc + ")"
			}
			return "openai", "OpenAI Compatible HTTPS API"
		}
		if secrets.Get(secrets.KeyGeminiAPIKey) != "" {
			return "gemini", "Google Gemini HTTPS API"
		}
		if secrets.Get(secrets.KeyAnthropicAPIKey) != "" {
			return "anthropic", "Anthropic Claude HTTPS API"
		}
		if bin := FindAgyBinary(); bin != "" {
			return "agy", "Local Google agy CLI (" + bin + ")"
		}
		return "", "未检测到 AI 网关 Token 或本地 agy 工具"
	}
}

// TestConnectivity sends a minimal ping request to verify BaseURL + Token + Model connectivity and latency.
func (e *Engine) TestConnectivity(ctx context.Context) (latencyMS int64, modelUsed string, err error) {
	provider, reason := e.ResolveProvider()
	if provider == "" {
		return 0, "", fmt.Errorf("%s", reason)
	}
	modelName := strings.TrimSpace(e.Cfg.Model)
	if modelName == "" {
		switch provider {
		case "anthropic":
			modelName = "claude-3-7-sonnet-latest"
		case "gemini", "agy":
			modelName = "gemini-2.5-flash"
		default:
			modelName = "gpt-4o-mini"
		}
	}
	start := time.Now()
	_, err = e.callModel(ctx, provider, modelName, "Reply with the single word OK.")
	latencyMS = time.Since(start).Milliseconds()
	return latencyMS, modelName, err
}

// FindAgyBinary locates Google agy CLI if installed.
func FindAgyBinary() string {
	if p, err := exec.LookPath("agy"); err == nil {
		return p
	}
	for _, cand := range []string{
		"~/.local/bin/agy",
		"~/.gemini/bin/agy",
		"/usr/local/bin/agy",
		"/opt/homebrew/bin/agy",
	} {
		exp := config.ExpandHome(cand)
		if info, err := os.Stat(exp); err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
			return exp
		}
	}
	return ""
}

// AssessAndMitigate evaluates whether a vulnerability has a safe runtime configuration workaround,
// returning paired remediation + rollback scripts (with L3 Markdown cache & static shell safety checks).
func (e *Engine) AssessAndMitigate(ctx context.Context, vuln model.VulnerabilityMatch, inv model.HostInventory, useCache bool) model.AITriageResult {
	modelName := e.Cfg.Model
	if modelName == "" {
		modelName = "gemini-2.5-flash"
	}
	if useCache && e.Mem != nil {
		if cached, ok := e.Mem.GetAITriage(vuln, inv.OSContext, modelName); ok && cached != nil {
			return *cached
		}
	}

	provider, reason := e.ResolveProvider()
	if provider == "" {
		return model.AITriageResult{
			Success: false,
			Verdict: "failed",
			Error:   reason,
		}
	}

	prompt := buildAssessmentPrompt(vuln, inv)
	rawOut, err := e.callModel(ctx, provider, modelName, prompt)
	if err != nil {
		res := model.AITriageResult{
			Success:  false,
			Verdict:  "failed",
			Provider: provider,
			Model:    modelName,
			Error:    err.Error(),
		}
		if useCache && e.Mem != nil {
			_, _ = e.Mem.SaveAITriage(vuln, inv.OSContext, res, modelName)
		}
		return res
	}

	res := parseModelAssessment(rawOut, vuln.EffectiveID(), inv.OSContext)
	res.Provider = provider
	res.Model = modelName

	if useCache && e.Mem != nil {
		if fp, err := e.Mem.SaveAITriage(vuln, inv.OSContext, res, modelName); err == nil {
			res.CacheFile = fp
		}
	}
	return res
}

// DiagnoseAndFix asks the AI model to diagnose a syntax error or post-mitigation network rollback and rewrite both scripts.
func (e *Engine) DiagnoseAndFix(ctx context.Context, vuln model.VulnerabilityMatch, inv model.HostInventory, failedScript, failureLog string) model.AITriageResult {
	provider, reason := e.ResolveProvider()
	if provider == "" {
		return model.AITriageResult{Success: false, Verdict: "failed", Error: reason}
	}
	modelName := e.Cfg.Model
	if modelName == "" {
		modelName = "gemini-2.5-flash"
	}

	prompt := fmt.Sprintf(
		"You are a Principal Linux Systems & Security Engineer.\n\n%s\n\n"+
			"Vulnerability: %s (%s %s)\n"+
			"ALERT: Previous remediation script failed validation or disrupted network connectivity:\n%s\n\n"+
			"Previous Script:\n%s\n\n"+
			"Task:\n"+
			"1. If no safe configuration workaround is actually viable without breaking connectivity, output EXACTLY:\n"+
			"NO_VIABLE_WORKAROUND: <concise technical reason>\n"+
			"2. Otherwise, output ONLY two valid POSIX /bin/sh scripts separated by %q:\n"+
			"Script 1 (Remediation, with # Strategy: <summary> comment) and Script 2 (Idempotent Rollback).\n"+
			"NO markdown prose outside the scripts.",
		FormatHostEnvProfile(inv),
		vuln.EffectiveID(), vuln.Package, vuln.InstalledVersion,
		failureLog,
		failedScript,
		ScriptDelimiter,
	)

	rawOut, err := e.callModel(ctx, provider, modelName, prompt)
	if err != nil {
		return model.AITriageResult{Success: false, Verdict: "failed", Error: err.Error()}
	}
	res := parseModelAssessment(rawOut, vuln.EffectiveID(), inv.OSContext)
	res.Provider = provider
	res.Model = modelName
	return res
}

func FormatHostEnvProfile(inv model.HostInventory) string {
	oc := inv.OSContext
	return fmt.Sprintf(
		"=== TARGET HOST ENVIRONMENT ===\n"+
			"- Host: %s\n"+
			"- OS: %s (Family: %s, Version: %s)\n"+
			"- Architecture: %s\n"+
			"- Kernel: %s\n"+
			"- Shell: %s (CRITICAL: Write strict POSIX /bin/sh; avoid bashisms)\n"+
			"- Init Manager: %s\n"+
			"- Firewall: %s\n"+
			"- Package Manager: %s\n"+
			"===============================",
		inv.Target.Name, oc.OSPretty, oc.OSFamily, oc.DistroVersion,
		oc.Arch, oc.KernelRelease, oc.Shell, oc.InitSystem, oc.Firewall, oc.PkgMgr,
	)
}

func buildAssessmentPrompt(vuln model.VulnerabilityMatch, inv model.HostInventory) string {
	return fmt.Sprintf(
		"You are a Principal Linux Infrastructure & Kernel Security Engineer.\n\n%s\n\n"+
			"Vulnerability To Assess:\n"+
			"- ID: %s (Severity: %s)\n"+
			"- Component: %s (Installed: %s)\n"+
			"- Summary: %s\n\n"+
			"Task:\n"+
			"1. Rigorous Feasibility Gate:\n"+
			"   Determine if a REAL, SAFE runtime configuration workaround exists (e.g. specific sysctl toggle, blacklisting an unused optional module, targeted firewall drop) WITHOUT breaking SSH or active routing.\n"+
			"   - IF NO SAFE WORKAROUND EXISTS (e.g. internal C memory bug in an active core subsystem requiring binary patch):\n"+
			"     Output EXACTLY one line and NOTHING else:\n"+
			"     NO_VIABLE_WORKAROUND: <concise technical reason>\n"+
			"   - IF A GENUINE SAFE WORKAROUND EXISTS:\n"+
			"     Output ONLY two POSIX #!/bin/sh scripts separated by %q:\n"+
			"     Script 1: Idempotent mitigation script (include `# Strategy: <short summary>` in header)\n"+
			"     %s\n"+
			"     Script 2: Exact idempotent rollback script restoring prior state.\n",
		FormatHostEnvProfile(inv),
		vuln.EffectiveID(), vuln.Severity,
		vuln.Package, vuln.InstalledVersion,
		vuln.Summary,
		ScriptDelimiter, ScriptDelimiter,
	)
}

func parseModelAssessment(rawOut, cveID string, osCtx model.OSContext) model.AITriageResult {
	trimmed := strings.TrimSpace(rawOut)
	if idx := strings.Index(trimmed, "NO_VIABLE_WORKAROUND:"); idx >= 0 {
		reason := strings.TrimSpace(trimmed[idx+len("NO_VIABLE_WORKAROUND:"):])
		if nl := strings.IndexByte(reason, '\n'); nl >= 0 {
			reason = strings.TrimSpace(reason[:nl])
		}
		return model.AITriageResult{
			Success:       true,
			Verdict:       "awaiting_patch",
			HasWorkaround: false,
			Reason:        reason,
		}
	}

	mitigate, rollback := ParseDualScripts(trimmed)
	if mitigate == "" {
		return model.AITriageResult{
			Success: false,
			Verdict: "failed",
			Error:   "模型未返回有效的加固脚本或 NO_VIABLE_WORKAROUND 判定",
		}
	}
	if rollback == "" {
		return model.AITriageResult{
			Success: false,
			Verdict: "failed",
			Error:   "安全门禁拦截：模型未同时生成配对的应急回滚脚本，拒绝使用不匹配兜底脚本",
		}
	}

	if ok, errMsg := VerifyScriptSafety(mitigate, osCtx); !ok {
		return model.AITriageResult{
			Success: false,
			Verdict: "failed",
			Script:  mitigate,
			Rollback: rollback,
			Error:   "加固脚本静态安全门禁拦截: " + errMsg,
		}
	}
	if ok, errMsg := VerifyScriptSafety(rollback, osCtx); !ok {
		return model.AITriageResult{
			Success: false,
			Verdict: "failed",
			Script:  mitigate,
			Rollback: rollback,
			Error:   "回滚脚本静态安全门禁拦截: " + errMsg,
		}
	}

	strategy := extractStrategy(mitigate, cveID+" 现场配置规避与持久化加固")
	return model.AITriageResult{
		Success:       true,
		Verdict:       "mitigable",
		HasWorkaround: true,
		Strategy:      strategy,
		Reason:        strategy,
		Script:        mitigate,
		Rollback:      rollback,
	}
}

// ParseDualScripts extracts the paired mitigation and rollback scripts (no fake fallback rollback!).
func ParseDualScripts(raw string) (mitigate, rollback string) {
	if strings.Contains(raw, ScriptDelimiter) {
		parts := strings.SplitN(raw, ScriptDelimiter, 2)
		return extractSingleScript(parts[0]), extractSingleScript(parts[1])
	}
	blocks := codeFenceRe.FindAllStringSubmatch(raw, -1)
	if len(blocks) >= 2 {
		return normalizeShebang(blocks[0][1]), normalizeShebang(blocks[1][1])
	}
	return extractSingleScript(raw), ""
}

func extractSingleScript(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if m := codeFenceRe.FindStringSubmatch(raw); m != nil {
		return normalizeShebang(m[1])
	}
	if idx := strings.Index(raw, "#!/bin/"); idx >= 0 {
		sub := raw[idx:]
		if end := strings.LastIndex(sub, "```"); end > 0 {
			sub = sub[:end]
		}
		return normalizeShebang(sub)
	}
	return ""
}

func normalizeShebang(s string) string {
	s = strings.TrimSpace(s)
	if len(s) < 12 {
		return ""
	}
	if !strings.HasPrefix(s, "#!") {
		s = "#!/bin/sh\n" + s
	}
	return s
}

func extractStrategy(script, fallback string) string {
	for _, line := range strings.Split(script, "\n") {
		line = strings.TrimSpace(line)
		if m := strategyRe.FindStringSubmatch(line); m != nil {
			s := strings.TrimSpace(m[1])
			if len(s) > 4 {
				return s
			}
		}
	}
	return fallback
}

// VerifyScriptSafety enforces:
// 1. Dangerous destructive command denylist (rm -rf /, mkfs, curl|sh, etc.)
// 2. BusyBox ash bashism rejection when target shell is ash/sh
// 3. Local POSIX `sh -n` static syntax validation
func VerifyScriptSafety(script string, osCtx model.OSContext) (bool, string) {
	if strings.TrimSpace(script) == "" {
		return false, "脚本为空"
	}
	if dangerousRe.MatchString(script) {
		return false, "检测到高危破坏性指令或外部管道执行模式"
	}
	isBusyBoxAsh := strings.Contains(strings.ToLower(osCtx.Shell), "busybox") || osCtx.OSFamily == "openwrt" || osCtx.OSFamily == "alpine"
	if isBusyBoxAsh && bashismRe.MatchString(script) {
		return false, "目标主机为 BusyBox ash 环境，检测到不兼容的 Bash 专有语法 ([[ / declare / function)"
	}

	shBin := "/bin/sh"
	if p, err := exec.LookPath("sh"); err == nil {
		shBin = p
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, shBin, "-n")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false, "Shell 静态语法检查未通过 (sh -n): " + strings.TrimSpace(string(out))
	}
	return true, ""
}

func (e *Engine) callModel(ctx context.Context, provider, modelName, prompt string) (string, error) {
	switch provider {
	case "gemini":
		return e.callGeminiREST(ctx, modelName, prompt)
	case "openai":
		return e.callOpenAIREST(ctx, modelName, prompt)
	case "anthropic":
		return e.callAnthropicREST(ctx, modelName, prompt)
	case "agy":
		return e.callAgyCLI(ctx, modelName, prompt)
	default:
		return "", fmt.Errorf("unsupported AI provider: %s", provider)
	}
}

func (e *Engine) callGeminiREST(ctx context.Context, modelName, prompt string) (string, error) {
	apiKey := secrets.GetAIGatewayToken("gemini")
	if apiKey == "" {
		return "", fmt.Errorf("未配置 AI 网关 Token")
	}
	modelName = strings.TrimSpace(modelName)
	if modelName == "" || strings.Contains(modelName, "3.8") {
		modelName = "gemini-2.5-flash"
	}
	baseURL := strings.TrimRight(strings.TrimSpace(e.Cfg.BaseURL), "/")
	if baseURL == "" {
		baseURL = "https://generativelanguage.googleapis.com/v1beta"
	} else if !strings.Contains(baseURL, "/v1") {
		baseURL += "/v1beta"
	}
	u := fmt.Sprintf("%s/models/%s:generateContent?key=%s", baseURL, modelName, apiKey)
	body, _ := json.Marshal(map[string]any{
		"contents": []map[string]any{
			{"parts": []map[string]string{{"text": prompt}}},
		},
		"generationConfig": map[string]any{"temperature": 0.1},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-goog-api-key", apiKey)
	resp, err := e.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	respBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Gemini 网关 HTTP %d: %s", resp.StatusCode, truncateStr(string(respBytes), 120))
	}
	var parsed struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}
	if err := json.Unmarshal(respBytes, &parsed); err != nil || len(parsed.Candidates) == 0 || len(parsed.Candidates[0].Content.Parts) == 0 {
		return "", fmt.Errorf("Gemini 网关返回结果为空")
	}
	return parsed.Candidates[0].Content.Parts[0].Text, nil
}

func resolveOpenAIEndpoint(baseURL string) string {
	b := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if b == "" {
		return "https://api.openai.com/v1/chat/completions"
	}
	if strings.HasSuffix(b, "/chat/completions") {
		return b
	}
	if strings.HasSuffix(b, "/v1") || strings.Contains(b, "/v1/") || strings.HasSuffix(b, "/v4") {
		return b + "/chat/completions"
	}
	return b + "/v1/chat/completions"
}

func (e *Engine) callOpenAIREST(ctx context.Context, modelName, prompt string) (string, error) {
	apiKey := secrets.GetAIGatewayToken("openai")
	if apiKey == "" {
		return "", fmt.Errorf("未配置 AI 网关 Token")
	}
	modelName = strings.TrimSpace(modelName)
	if modelName == "" {
		modelName = "gpt-4o-mini"
	}
	endpoint := resolveOpenAIEndpoint(e.Cfg.BaseURL)
	body, _ := json.Marshal(map[string]any{
		"model":       modelName,
		"temperature": 0.1,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)
	resp, err := e.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	respBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("AI 网关 HTTP %d: %s", resp.StatusCode, truncateStr(string(respBytes), 120))
	}
	var parsed struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(respBytes, &parsed); err != nil || len(parsed.Choices) == 0 {
		return "", fmt.Errorf("AI 网关返回结果为空")
	}
	return parsed.Choices[0].Message.Content, nil
}

func resolveAnthropicEndpoint(baseURL string) string {
	b := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if b == "" {
		return "https://api.anthropic.com/v1/messages"
	}
	if strings.HasSuffix(b, "/messages") {
		return b
	}
	if strings.HasSuffix(b, "/v1") {
		return b + "/messages"
	}
	return b + "/v1/messages"
}

func (e *Engine) callAnthropicREST(ctx context.Context, modelName, prompt string) (string, error) {
	apiKey := secrets.GetAIGatewayToken("anthropic")
	if apiKey == "" {
		return "", fmt.Errorf("未配置 AI 网关 Token")
	}
	modelName = strings.TrimSpace(modelName)
	if modelName == "" {
		modelName = "claude-3-7-sonnet-latest"
	}
	endpoint := resolveAnthropicEndpoint(e.Cfg.BaseURL)
	body, _ := json.Marshal(map[string]any{
		"model":      modelName,
		"max_tokens": 2048,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", apiKey)
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")
	resp, err := e.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	respBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Anthropic 网关 HTTP %d: %s", resp.StatusCode, truncateStr(string(respBytes), 120))
	}
	var parsed struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(respBytes, &parsed); err != nil || len(parsed.Content) == 0 {
		return "", fmt.Errorf("Anthropic 网关返回结果为空")
	}
	return parsed.Content[0].Text, nil
}

func (e *Engine) callAgyCLI(ctx context.Context, modelName, prompt string) (string, error) {
	bin := FindAgyBinary()
	if bin == "" {
		return "", fmt.Errorf("本机未找到 Google agy 命令行工具")
	}
	// Run inside an isolated empty temp working directory WITHOUT --dangerously-skip-permissions!
	tmpDir, err := os.MkdirTemp("", "sentinel-agy-prompt-*")
	if err == nil {
		defer os.RemoveAll(tmpDir)
	}
	runCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	cmd := exec.CommandContext(runCtx, filepath.Clean(bin),
		"-p", prompt,
		"--model", modelName,
		"--disable-slash-commands",
	)
	if tmpDir != "" {
		cmd.Dir = tmpDir
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("agy 调用异常: %v (%s)", err, truncateStr(stderr.String(), 80))
	}
	return stdout.String(), nil
}

func truncateStr(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
