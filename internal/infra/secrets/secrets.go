package secrets

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/sixban6/security-sentinel/internal/infra/config"
)

const ServiceName = "com.sixban6.security-sentinel"

// Standard credential keys.
const (
	KeyTelegramBotToken = "telegram_bot_token"
	KeyTelegramChatID   = "telegram_chat_id"
	KeyGitHubToken      = "github_token"
	KeyAIGatewayToken   = "ai_gateway_token"
	KeyGeminiAPIKey     = "gemini_api_key"
	KeyOpenAIAPIKey     = "openai_api_key"
	KeyAnthropicAPIKey  = "anthropic_api_key"
	KeyClashAPISecret   = "clash_api_secret"
)

var allCredentialKeys = []string{
	KeyTelegramBotToken,
	KeyTelegramChatID,
	KeyGitHubToken,
	KeyAIGatewayToken,
	KeyGeminiAPIKey,
	KeyOpenAIAPIKey,
	KeyAnthropicAPIKey,
	KeyClashAPISecret,
}

var envVarMap = map[string]string{
	KeyTelegramBotToken: "TELEGRAM_BOT_TOKEN",
	KeyTelegramChatID:   "TELEGRAM_CHAT_ID",
	KeyGitHubToken:      "GITHUB_TOKEN",
	KeyAIGatewayToken:   "AI_GATEWAY_TOKEN",
	KeyGeminiAPIKey:     "GEMINI_API_KEY",
	KeyOpenAIAPIKey:     "OPENAI_API_KEY",
	KeyAnthropicAPIKey:  "ANTHROPIC_API_KEY",
	KeyClashAPISecret:   "CLASH_API_SECRET",
}

// NativeBackend allows optional OS keychain hooks when SENTINEL_USE_OS_KEYCHAIN=1 is explicitly set.
type NativeBackend interface {
	Get(key string) (string, error)
	Set(key, value string) error
	Delete(key string) error
}

var (
	mu            sync.RWMutex
	nativeBackend NativeBackend
	memCache      = make(map[string]string)
	migratedVault = make(map[string]bool)
)

// RegisterNativeBackend wires optional OS keychain hooks (only active when SENTINEL_USE_OS_KEYCHAIN=1).
func RegisterNativeBackend(b NativeBackend) {
	mu.Lock()
	defer mu.Unlock()
	nativeBackend = b
	memCache = make(map[string]string)
}

func useOSKeychain() bool {
	return strings.TrimSpace(os.Getenv("SENTINEL_USE_OS_KEYCHAIN")) == "1" &&
		strings.TrimSpace(os.Getenv("SENTINEL_DISABLE_KEYCHAIN")) == ""
}

func cacheSlotKey(key string) string {
	return vaultFilePath() + "|" + os.Getenv("SENTINEL_USE_OS_KEYCHAIN") + "|" + os.Getenv("SENTINEL_DISABLE_KEYCHAIN") + "|" + key
}

func credentialsFilePath() string {
	return filepath.Join(config.ConfigDir(), "credentials.json")
}

// GetAIGatewayToken returns the unified AI Gateway token if configured, falling back to
// provider-specific legacy keys (OPENAI_API_KEY / GEMINI_API_KEY / ANTHROPIC_API_KEY) for backwards compatibility.
func GetAIGatewayToken(provider string) string {
	if tok := Get(KeyAIGatewayToken); tok != "" {
		return tok
	}
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "gemini":
		if tok := Get(KeyGeminiAPIKey); tok != "" {
			return tok
		}
	case "anthropic":
		if tok := Get(KeyAnthropicAPIKey); tok != "" {
			return tok
		}
	case "openai":
		if tok := Get(KeyOpenAIAPIKey); tok != "" {
			return tok
		}
	}
	for _, k := range []string{KeyOpenAIAPIKey, KeyGeminiAPIKey, KeyAnthropicAPIKey} {
		if tok := Get(k); tok != "" {
			return tok
		}
	}
	return ""
}

// Get retrieves a credential with priority:
// 1. Explicit environment variable
// 2. In-memory cache (avoids disk/crypto/subprocess overhead in 60-120fps GUI render loops)
// 3. Hardware-bound AES-256-GCM local encrypted vault (~/.config/sentinel/vault.enc) — zero OS Keychain popups
// 4. Legacy ~/.gemini/config/sentinel_telegram.json read-only fallback & optional `gh auth token`
func Get(key string) string {
	if envName, ok := envVarMap[key]; ok {
		if v := strings.TrimSpace(os.Getenv(envName)); v != "" {
			return v
		}
	}

	slot := cacheSlotKey(key)
	mu.RLock()
	cachedVal, hit := memCache[slot]
	mu.RUnlock()
	if hit {
		return cachedVal
	}

	mu.Lock()
	defer mu.Unlock()
	if memCache == nil {
		memCache = make(map[string]string)
	}
	if cachedVal, hit := memCache[slot]; hit {
		return cachedVal
	}

	val := resolveUncachedLocked(key)
	memCache[slot] = val
	return val
}

func loadOrInitVaultLocked() map[string]string {
	vPath := vaultFilePath()
	id := cachedMachineIDFn()
	vm, err := loadVaultMapWithIdentity(vPath, id)
	if err != nil || vm == nil {
		vm = make(map[string]string)
	}

	if migratedVault[vPath] || vm[vaultMigratedFlagKey] == "1" {
		migratedVault[vPath] = true
		return vm
	}

	// Mark migrated FIRST and persist immediately so legacy Keychain migration never runs twice.
	migratedVault[vPath] = true
	vm[vaultMigratedFlagKey] = "1"
	_ = saveVaultMapWithIdentity(vPath, vm, id)
	dirty := false

	// 1. Migrate legacy plaintext ~/.config/sentinel/credentials.json and shred plaintext file.
	credPath := credentialsFilePath()
	if legacyMap, err := loadFileMap(credPath); err == nil {
		for k, v := range legacyMap {
			if trimmed := strings.TrimSpace(v); trimmed != "" && strings.TrimSpace(vm[k]) == "" {
				vm[k] = trimmed
				dirty = true
			}
		}
		_ = os.Remove(credPath)
	}

	// 2. Import legacy v1 ~/.gemini/config/sentinel_telegram.json into encrypted vault.
	legacyTGPath := config.ExpandHome("~/.gemini/config/sentinel_telegram.json")
	if tgMap, err := loadFileMap(legacyTGPath); err == nil {
		if tok := strings.TrimSpace(tgMap["bot_token"]); tok != "" && strings.TrimSpace(vm[KeyTelegramBotToken]) == "" {
			vm[KeyTelegramBotToken] = tok
			dirty = true
		}
		if cid := strings.TrimSpace(tgMap["chat_id"]); cid != "" && strings.TrimSpace(vm[KeyTelegramChatID]) == "" {
			vm[KeyTelegramChatID] = cid
			dirty = true
		}
	}

	// 3. One-time import & cleanup of legacy macOS Keychain items (metadata-first check, zero popup if absent).
	if runtime.GOOS == "darwin" && os.Getenv("SENTINEL_DISABLE_KEYCHAIN") == "" && !useOSKeychain() {
		for _, k := range allCredentialKeys {
			if !darwinKeychainHasItem(k) {
				continue
			}
			if strings.TrimSpace(vm[k]) == "" {
				var got string
				if nativeBackend != nil {
					if v, err := nativeBackend.Get(k); err == nil {
						got = strings.TrimSpace(v)
					}
				}
				if got == "" {
					got = darwinKeychainGet(k)
				}
				if got != "" {
					vm[k] = got
					dirty = true
					_ = saveVaultMapWithIdentity(vPath, vm, id)
					_ = darwinKeychainDelete(k)
					if nativeBackend != nil {
						_ = nativeBackend.Delete(k)
					}
				}
			} else {
				// Vault already holds this secret; remove stale Keychain item so it never prompts again.
				_ = darwinKeychainDelete(k)
				if nativeBackend != nil {
					_ = nativeBackend.Delete(k)
				}
			}
		}
	}

	if dirty {
		_ = saveVaultMapWithIdentity(vPath, vm, id)
	}
	return vm
}

func resolveUncachedLocked(key string) string {
	if useOSKeychain() {
		if nativeBackend != nil {
			if v, err := nativeBackend.Get(key); err == nil && strings.TrimSpace(v) != "" {
				return strings.TrimSpace(v)
			}
		} else if runtime.GOOS == "darwin" {
			if v := darwinKeychainGet(key); v != "" {
				return v
			}
		}
	}

	vm := loadOrInitVaultLocked()
	if v := strings.TrimSpace(vm[key]); v != "" {
		return v
	}

	// Read-only fallback to legacy ~/.config/sentinel/credentials.json if created externally after migration
	if m, err := loadFileMap(credentialsFilePath()); err == nil {
		if v := strings.TrimSpace(m[key]); v != "" {
			return v
		}
	}

	// Read-only compatibility with v1 ~/.gemini/config/sentinel_telegram.json
	if key == KeyTelegramBotToken || key == KeyTelegramChatID {
		legacyPath := config.ExpandHome("~/.gemini/config/sentinel_telegram.json")
		if m, err := loadFileMap(legacyPath); err == nil {
			if key == KeyTelegramBotToken && strings.TrimSpace(m["bot_token"]) != "" {
				return strings.TrimSpace(m["bot_token"])
			}
			if key == KeyTelegramChatID && strings.TrimSpace(m["chat_id"]) != "" {
				return strings.TrimSpace(m["chat_id"])
			}
		}
	}

	// For GitHub token, optionally query `gh auth token` once if installed
	if key == KeyGitHubToken && os.Getenv("SENTINEL_SKIP_GH_CLI") == "" {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if out, err := exec.CommandContext(ctx, "gh", "auth", "token").Output(); err == nil {
			if tok := strings.TrimSpace(string(out)); tok != "" {
				return tok
			}
		}
	}

	return ""
}

// Set stores a credential securely in the hardware-bound AES-256-GCM encrypted vault (~/.config/sentinel/vault.enc).
func Set(key, value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return Delete(key)
	}

	slot := cacheSlotKey(key)
	mu.Lock()
	defer mu.Unlock()
	if memCache == nil {
		memCache = make(map[string]string)
	}
	memCache[slot] = value

	if useOSKeychain() {
		if nativeBackend != nil {
			if err := nativeBackend.Set(key, value); err == nil {
				_ = deleteFromFileMap(credentialsFilePath(), key)
				return nil
			}
		} else if runtime.GOOS == "darwin" {
			if err := darwinKeychainSet(key, value); err == nil {
				_ = deleteFromFileMap(credentialsFilePath(), key)
				return nil
			}
		}
	}

	vm := loadOrInitVaultLocked()
	vm[vaultMigratedFlagKey] = "1"
	vm[key] = value
	err := saveVaultMapWithIdentity(vaultFilePath(), vm, cachedMachineIDFn())
	_ = deleteFromFileMap(credentialsFilePath(), key)
	if runtime.GOOS == "darwin" && os.Getenv("SENTINEL_DISABLE_KEYCHAIN") == "" && !useOSKeychain() && darwinKeychainHasItem(key) {
		_ = darwinKeychainDelete(key)
	}
	return err
}

// Delete removes a credential from the encrypted vault (and any legacy storage).
func Delete(key string) error {
	slot := cacheSlotKey(key)
	mu.Lock()
	defer mu.Unlock()
	if memCache != nil {
		memCache[slot] = ""
	}

	if useOSKeychain() {
		if nativeBackend != nil {
			_ = nativeBackend.Delete(key)
		} else if runtime.GOOS == "darwin" {
			_ = darwinKeychainDelete(key)
		}
	} else if runtime.GOOS == "darwin" && os.Getenv("SENTINEL_DISABLE_KEYCHAIN") == "" && darwinKeychainHasItem(key) {
		_ = darwinKeychainDelete(key)
	}

	vm := loadOrInitVaultLocked()
	if _, exists := vm[key]; exists {
		delete(vm, key)
		vm[vaultMigratedFlagKey] = "1"
		if err := saveVaultMapWithIdentity(vaultFilePath(), vm, cachedMachineIDFn()); err != nil {
			return err
		}
	}
	return deleteFromFileMap(credentialsFilePath(), key)
}

// Masked returns a safe display mask (e.g. "abcd...wxyz") for UI display.
func Masked(val string) string {
	val = strings.TrimSpace(val)
	if val == "" {
		return "未配置"
	}
	if len(val) <= 8 {
		return "••••••••"
	}
	return val[:4] + "••••" + val[len(val)-4:]
}

// darwinKeychainHasItem checks Keychain item metadata WITHOUT `-w`, which never triggers a password prompt.
func darwinKeychainHasItem(account string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/security", "find-generic-password", "-s", ServiceName, "-a", account)
	return cmd.Run() == nil
}

func darwinKeychainGet(account string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/security", "find-generic-password", "-s", ServiceName, "-a", account, "-w")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func darwinKeychainSet(account, secret string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/security", "add-generic-password", "-U", "-s", ServiceName, "-a", account, "-w", secret)
	return cmd.Run()
}

func darwinKeychainDelete(account string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/security", "delete-generic-password", "-s", ServiceName, "-a", account)
	return cmd.Run()
}

func loadFileMap(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	out := make(map[string]string, len(raw))
	for k, v := range raw {
		switch tv := v.(type) {
		case string:
			out[k] = tv
		}
	}
	return out, nil
}

func deleteFromFileMap(path, key string) error {
	m, err := loadFileMap(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	delete(m, key)
	if len(m) == 0 {
		_ = os.Remove(path)
		return nil
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}
