package notify

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/sixban6/security-sentinel/internal/scan/auditor"
	"github.com/sixban6/security-sentinel/internal/infra/config"
	"github.com/sixban6/security-sentinel/internal/infra/model"
	"github.com/sixban6/security-sentinel/internal/infra/secrets"
)

// DesktopNotifyFunc allows MyGo GUI to intercept desktop notifications and attach click-to-open handlers.
type DesktopNotifyFunc func(id, title, subtitle, body string)

var (
	mu                sync.RWMutex
	desktopNotifyHook DesktopNotifyFunc
	httpClient        = &http.Client{Timeout: 10 * time.Second}
)

func RegisterDesktopHook(fn DesktopNotifyFunc) {
	mu.Lock()
	defer mu.Unlock()
	desktopNotifyHook = fn
}

// LoadReport reads an AuditReport from latest_status.json (supporting both v2 object and v1 legacy list).
func LoadReport(statusFile string) (model.AuditReport, error) {
	if statusFile == "" {
		statusFile = config.DefaultStatusFile()
	}
	data, err := os.ReadFile(statusFile)
	if err != nil {
		return model.AuditReport{}, err
	}
	var rep model.AuditReport
	if err := json.Unmarshal(data, &rep); err == nil && (len(rep.Hosts) > 0 || rep.Timestamp != "") {
		normalizeLoadedHosts(rep.Hosts)
		return rep, nil
	}
	var list []model.HostAuditResult
	if err := json.Unmarshal(data, &list); err == nil {
		normalizeLoadedHosts(list)
		return model.AuditReport{Hosts: list}, nil
	}
	return model.AuditReport{}, fmt.Errorf("invalid status file format: %s", statusFile)
}

func normalizeLoadedHosts(hosts []model.HostAuditResult) {
	for i := range hosts {
		h := &hosts[i]
		if h.Host == "" && h.LegacyName != "" {
			h.Host = h.LegacyName
		}
		h.LegacyName = ""
		if h.Host == "" && h.Target.Name != "" {
			h.Host = h.Target.Name
		}
		if h.Target.Type == "" && h.Target.SSHHost == "" && h.Host != "" {
			low := strings.ToLower(h.Host)
			if strings.Contains(h.Host, "本机") || strings.Contains(low, "local") || strings.Contains(low, "macos") {
				h.Target = model.HostTarget{ID: "local", Name: h.Host, Type: "local"}
			} else {
				h.Target = config.NormalizeStringHost(h.Host)
			}
		}
		if h.Host == "" {
			h.Host = h.Target.EffectiveKey()
		}
	}
}

// SaveReport persists AuditReport atomically to statusFile AND mirrors to legacy ~/.gemini path if that directory exists.
func SaveReport(rep model.AuditReport, statusFile string) error {
	if statusFile == "" {
		statusFile = config.PrimaryStatusFile()
	}
	if rep.Timestamp == "" {
		rep.Timestamp = time.Now().Format(time.RFC3339)
	}
	raw, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	if err := writeAtomic(statusFile, raw); err != nil {
		return err
	}
	legacy := config.LegacyStatusFile()
	if legacy != statusFile {
		if info, err := os.Stat(filepath.Dir(legacy)); err == nil && info.IsDir() {
			_ = writeAtomic(legacy, raw)
		}
	}
	return nil
}

func writeAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := fmt.Sprintf("%s.tmp.%d", path, os.Getpid())
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// ShouldNotify implements State-Diff noise reduction ("always", "on_change", "critical_only").
func ShouldNotify(prev *model.AuditReport, curr model.AuditReport, policy string) bool {
	switch strings.ToLower(strings.TrimSpace(policy)) {
	case "critical_only":
		for _, h := range curr.Hosts {
			if h.Status != model.StatusClean {
				return true
			}
		}
		return false
	case "on_change":
		if prev == nil || len(prev.Hosts) != len(curr.Hosts) {
			return true
		}
		prevMap := make(map[string]string, len(prev.Hosts))
		for _, h := range prev.Hosts {
			prevMap[h.Host] = h.Status + "|" + fmt.Sprint(len(h.Vulnerabilities)) + "|" + fmt.Sprint(len(h.FixedItems))
		}
		for _, h := range curr.Hosts {
			sig := h.Status + "|" + fmt.Sprint(len(h.Vulnerabilities)) + "|" + fmt.Sprint(len(h.FixedItems))
			if prevMap[h.Host] != sig {
				return true
			}
		}
		return false
	default: // "always"
		return true
	}
}

// SaveAndNotify persists the AuditReport and dispatches Desktop + Telegram notifications per policy.
func SaveAndNotify(ctx context.Context, rep model.AuditReport, statusFile string, cfg config.NotificationsConfig) (string, error) {
	if statusFile == "" {
		statusFile = config.PrimaryStatusFile()
	}
	var prevPtr *model.AuditReport
	if prev, err := LoadReport(statusFile); err == nil {
		prevPtr = &prev
	}
	if err := SaveReport(rep, statusFile); err != nil {
		return "", err
	}

	plainSummary := strings.Join(FormatStatusLines(rep.Hosts), "\n")
	if !ShouldNotify(prevPtr, rep, cfg.Policy) {
		return plainSummary, nil
	}

	if cfg.Desktop {
		SendDesktopNotification("audit:latest", "Security Sentinel 安全巡检", fmt.Sprintf("集群健康分 %d/100", rep.ClusterScore), plainSummary)
	}
	tgMsg := FormatTelegramHTML(rep, 10)
	_, tgErr := SendTelegram(ctx, tgMsg, "", "")
	return plainSummary, tgErr
}

// SendDesktopNotification uses MyGo's native Notification API in GUI mode,
// or safely falls back to osascript (macOS) / notify-send (Linux) without ever crashing if absent.
func SendDesktopNotification(id, title, subtitle, message string) {
	mu.RLock()
	hook := desktopNotifyHook
	mu.RUnlock()
	if hook != nil {
		hook(id, title, subtitle, message)
		return
	}

	switch runtime.GOOS {
	case "darwin":
		bin, err := exec.LookPath("osascript")
		if err != nil {
			return
		}
		esc := func(s string) string {
			s = strings.ReplaceAll(s, `\`, `\\`)
			s = strings.ReplaceAll(s, `"`, `\"`)
			s = strings.ReplaceAll(s, "\n", `\n`)
			return s
		}
		script := fmt.Sprintf(`display notification "%s" with title "%s" subtitle "%s" sound name "default"`,
			esc(message), esc(title), esc(subtitle))
		_ = exec.Command(bin, "-e", script).Run()
	case "linux":
		if bin, err := exec.LookPath("notify-send"); err == nil {
			_ = exec.Command(bin, title, message).Run()
		}
	}
}

func BadgeForStatus(status string) string {
	switch status {
	case model.StatusClean:
		return "✅ [一切安全]"
	case model.StatusImmunized:
		return "🛡️ [已经免疫]"
	case model.StatusAwaitingPatch, "待官方补丁":
		return "⏳ [待官方补丁]"
	case model.StatusPendingUpdate:
		return "📦 [待安装更新]"
	case model.StatusManualRequired:
		return "⛔ [需手动干预]"
	default:
		return "⚠️ [还未免疫]"
	}
}

func FormatStatusLines(hosts []model.HostAuditResult) []string {
	var lines []string
	for _, h := range hosts {
		name := h.Host
		if name == "" {
			name = h.Target.Name
		}
		badge := BadgeForStatus(h.Status)
		detail := strings.TrimSpace(h.Detail)
		if h.Status == model.StatusImmunized && len(h.CVEs) > 0 {
			hasCVE := false
			for _, c := range h.CVEs {
				if strings.Contains(detail, c) {
					hasCVE = true
					break
				}
			}
			if !hasCVE {
				detail = auditor.FormatRemediationDetail(h.CVEs, detail)
			}
		}
		line := fmt.Sprintf("• %s: %s", name, badge)
		if detail != "" {
			line += " " + detail
		}
		lines = append(lines, line)
	}
	return lines
}

func EscapeHTML(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
	return r.Replace(s)
}

func FormatTelegramHTML(rep model.AuditReport, maxUnmitigatedPerHost int) string {
	if maxUnmitigatedPerHost <= 0 {
		maxUnmitigatedPerHost = 10
	}
	ts := time.Now().Format("2006-01-02 15:04")
	if t, err := time.Parse(time.RFC3339, rep.Timestamp); err == nil {
		ts = t.Local().Format("2006-01-02 15:04")
	}

	var blocks []string
	header := fmt.Sprintf("🛡️ <b>Security-Sentinel v2.0 巡检报告</b>\n⏱️ <b>时间</b>: <code>%s</code> · <b>健康分</b>: <code>%d/100</code>\n", ts, rep.ClusterScore)

	for _, h := range rep.Hosts {
		var lines []string
		badge := strings.ReplaceAll(strings.ReplaceAll(BadgeForStatus(h.Status), "[", "<code>["), "]", "]</code>")
		hostLine := fmt.Sprintf("• <b>%s</b>: %s", EscapeHTML(h.Host), badge)
		lines = append(lines, hostLine)

		fixed := h.FixedItems
		unmit := h.UnmitigatedItems
		if len(unmit) == 0 && len(h.Vulnerabilities) > 0 {
			unmit = h.Vulnerabilities
		}

		switch {
		case len(fixed) > 0 && len(unmit) > 0:
			lines = append(lines, fmt.Sprintf("  ├ <b>✅ 已修复 / 已闭环 (%d 项):</b>", len(fixed)))
			for _, f := range fixed {
				lines = append(lines, "  │  "+formatTelegramBullet(f, true))
			}
			lines = append(lines, fmt.Sprintf("  └ <b>⚠️ 待处置 / 未修复 (%d 项):</b>", len(unmit)))
			for i, u := range unmit {
				if i >= maxUnmitigatedPerHost {
					lines = append(lines, fmt.Sprintf("     • <i>... 另有 %d 项待处置</i>", len(unmit)-maxUnmitigatedPerHost))
					break
				}
				lines = append(lines, "     "+formatTelegramBullet(u, false))
			}
		case len(fixed) > 0:
			lines = append(lines, fmt.Sprintf("  └ <b>✅ 已修复 / 已闭环 (%d 项):</b>", len(fixed)))
			for _, f := range fixed {
				lines = append(lines, "     "+formatTelegramBullet(f, true))
			}
		case len(unmit) > 0:
			lines = append(lines, fmt.Sprintf("  └ <b>⚠️ 待处置 / 未修复 (%d 项):</b>", len(unmit)))
			for i, u := range unmit {
				if i >= maxUnmitigatedPerHost {
					lines = append(lines, fmt.Sprintf("     • <i>... 另有 %d 项待处置</i>", len(unmit)-maxUnmitigatedPerHost))
					break
				}
				lines = append(lines, "     "+formatTelegramBullet(u, false))
			}
		default:
			det := strings.TrimSpace(h.Detail)
			if det == "" {
				det = "所有组件均处于安全版本"
			}
			lines = append(lines, fmt.Sprintf("  └ <i>%s</i>", EscapeHTML(det)))
		}
		blocks = append(blocks, strings.Join(lines, "\n"))
	}

	return header + "\n" + strings.Join(blocks, "\n\n")
}

func formatTelegramBullet(v model.VulnerabilityMatch, isFixed bool) string {
	id := EscapeHTML(v.EffectiveID())
	pkg := EscapeHTML(v.Package)
	inst := EscapeHTML(v.InstalledVersion)
	fixV := EscapeHTML(v.FixedVersion)

	verPart := ""
	switch {
	case inst != "" && fixV != "":
		verPart = fmt.Sprintf("(%s %s ➔ %s)", pkg, inst, fixV)
	case inst != "":
		verPart = fmt.Sprintf("(%s %s)", pkg, inst)
	case pkg != "":
		verPart = fmt.Sprintf("(%s)", pkg)
	}

	extra := ""
	if isFixed {
		if v.Action != "" {
			extra = "· " + EscapeHTML(v.Action)
		} else {
			extra = "· 已闭环加固"
		}
	} else {
		switch {
		case v.Reason != "":
			extra = "· " + EscapeHTML(truncate(v.Reason, 65))
		case v.Summary != "":
			extra = "· " + EscapeHTML(truncate(v.Summary, 60))
		default:
			extra = "· 待处置"
		}
	}
	return strings.TrimSpace(fmt.Sprintf("• <code>%s</code> %s %s", id, verPart, extra))
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

// SplitTelegramMessage safely splits UTF-8 messages under Telegram's 4096-char limit.
func SplitTelegramMessage(msg string, maxBytes int) []string {
	if maxBytes <= 0 {
		maxBytes = 3900
	}
	if len(msg) <= maxBytes {
		return []string{msg}
	}
	var chunks []string
	var cur []string
	curLen := 0
	for _, line := range strings.Split(msg, "\n") {
		l := len(line) + 1
		if curLen+l > maxBytes && len(cur) > 0 {
			chunks = append(chunks, strings.Join(cur, "\n"))
			cur = nil
			curLen = 0
		}
		cur = append(cur, line)
		curLen += l
	}
	if len(cur) > 0 {
		chunks = append(chunks, strings.Join(cur, "\n"))
	}
	return chunks
}

// SendTelegram sends HTML-formatted notification chunks using stored credentials (never auto-binding random strangers!).
// If ctx is nil or already expired (e.g. an upstream scan hit its timeout before producing a partial report),
// SendTelegram allocates an independent 25s delivery timeout so critical alerts are never silently dropped.
func SendTelegram(ctx context.Context, message, overrideToken, overrideChatID string) (bool, error) {
	token := strings.TrimSpace(overrideToken)
	if token == "" {
		token = secrets.Get(secrets.KeyTelegramBotToken)
	}
	chatID := strings.TrimSpace(overrideChatID)
	if chatID == "" {
		chatID = secrets.Get(secrets.KeyTelegramChatID)
	}
	if token == "" || chatID == "" {
		return false, nil
	}

	sendCtx := ctx
	if sendCtx == nil || sendCtx.Err() != nil {
		var cancel context.CancelFunc
		sendCtx, cancel = context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
	}

	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", token)
	for _, chunk := range SplitTelegramMessage(message, 3900) {
		if err := postTelegramChunkWithRetry(sendCtx, apiURL, chatID, chunk, "HTML"); err != nil {
			// Fallback to plain text if HTML tag validation fails
			if err2 := postTelegramChunkWithRetry(sendCtx, apiURL, chatID, chunk, ""); err2 != nil {
				return false, err2
			}
		}
	}
	return true, nil
}

func postTelegramChunkWithRetry(ctx context.Context, apiURL, chatID, text, parseMode string) error {
	err := postTelegramChunk(ctx, apiURL, chatID, text, parseMode)
	if err == nil {
		return nil
	}
	// Do not retry HTTP 400 parse errors on HTML mode (caller falls back to plain text immediately).
	if strings.Contains(err.Error(), "Telegram HTTP 400") {
		return err
	}
	if ctx.Err() != nil {
		return err
	}
	timer := time.NewTimer(1200 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return err
	case <-timer.C:
		return postTelegramChunk(ctx, apiURL, chatID, text, parseMode)
	}
}

func postTelegramChunk(ctx context.Context, apiURL, chatID, text, parseMode string) error {
	payload := map[string]any{
		"chat_id":                  chatID,
		"text":                     text,
		"disable_web_page_preview": true,
	}
	if parseMode != "" {
		payload["parse_mode"] = parseMode
	}
	raw, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Telegram HTTP %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

// GeneratePairCode generates a cryptographic 6-digit one-time pairing code so strangers can never hijack the Bot!
func GeneratePairCode() string {
	n, err := rand.Int(rand.Reader, big.NewInt(900000))
	if err != nil {
		return "849201"
	}
	return fmt.Sprintf("%06d", 100000+n.Int64())
}

// VerifyTelegramPairCode polls getUpdates and binds ONLY the chat that sent the exact 6-digit pairing code!
func VerifyTelegramPairCode(ctx context.Context, botToken, expectedCode string) (chatID string, username string, err error) {
	botToken = strings.TrimSpace(botToken)
	expectedCode = strings.TrimSpace(expectedCode)
	if botToken == "" || expectedCode == "" {
		return "", "", fmt.Errorf("Bot Token 与配对码不能为空")
	}
	u := fmt.Sprintf("https://api.telegram.org/bot%s/getUpdates?limit=30", botToken)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", "", err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var parsed struct {
		OK     bool `json:"ok"`
		Result []struct {
			Message struct {
				Text string `json:"text"`
				Chat struct {
					ID       int64  `json:"id"`
					Username string `json:"username"`
					Title    string `json:"title"`
				} `json:"chat"`
			} `json:"message"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil || !parsed.OK {
		return "", "", fmt.Errorf("查询 Telegram getUpdates 失败")
	}
	for i := len(parsed.Result) - 1; i >= 0; i-- {
		msg := parsed.Result[i].Message
		if strings.TrimSpace(msg.Text) == expectedCode && msg.Chat.ID != 0 {
			cid := fmt.Sprint(msg.Chat.ID)
			who := msg.Chat.Username
			if who == "" {
				who = msg.Chat.Title
			}
			_ = secrets.Set(secrets.KeyTelegramBotToken, botToken)
			_ = secrets.Set(secrets.KeyTelegramChatID, cid)
			return cid, who, nil
		}
	}
	return "", "", fmt.Errorf("尚未收到配对码 %s，请先向您的 Telegram Bot 发送该 6 位数字后再试", expectedCode)
}
