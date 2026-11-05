package secrets

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/sixban6/security-sentinel/internal/infra/config"
)

const ServiceName = "com.sixban6.security-sentinel"

// Standard credential keys.
const (
	KeyTelegramBotToken = "telegram_bot_token"
	KeyTelegramChatID   = "telegram_chat_id"
	KeyGitHubToken      = "github_token"
	KeyGeminiAPIKey     = "gemini_api_key"
	KeyOpenAIAPIKey     = "openai_api_key"
	KeyAnthropicAPIKey  = "anthropic_api_key"
	KeyClashAPISecret   = "clash_api_secret"
)

var envVarMap = map[string]string{
	KeyTelegramBotToken: "TELEGRAM_BOT_TOKEN",
	KeyTelegramChatID:   "TELEGRAM_CHAT_ID",
	KeyGitHubToken:      "GITHUB_TOKEN",
	KeyGeminiAPIKey:     "GEMINI_API_KEY",
	KeyOpenAIAPIKey:     "OPENAI_API_KEY",
	KeyAnthropicAPIKey:  "ANTHROPIC_API_KEY",
	KeyClashAPISecret:   "CLASH_API_SECRET",
}

// NativeBackend allows GUI (mygo.Secrets) to register native OS keychain hooks.
type NativeBackend interface {
	Get(key string) (string, error)
	Set(key, value string) error
	Delete(key string) error
}

var (
	mu            sync.RWMutex
	nativeBackend NativeBackend
)

// RegisterNativeBackend wires mygo.Secrets when running inside the desktop app.
func RegisterNativeBackend(b NativeBackend) {
	mu.Lock()
	defer mu.Unlock()
	nativeBackend = b
}

func credentialsFilePath() string {
	return filepath.Join(config.ConfigDir(), "credentials.json")
}

// Get retrieves a credential with priority:
// 1. Explicit environment variable
// 2. Registered MyGo OS Keychain backend (or macOS /usr/bin/security Keychain lookup)
// 3. 0600 local credentials.json fallback
// 4. Legacy ~/.gemini/config/sentinel_telegram.json read-only migration fallback
func Get(key string) string {
	if envName, ok := envVarMap[key]; ok {
		if v := strings.TrimSpace(os.Getenv(envName)); v != "" {
			return v
		}
	}

	mu.RLock()
	nb := nativeBackend
	mu.RUnlock()
	if nb != nil {
		if v, err := nb.Get(key); err == nil && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	} else if runtime.GOOS == "darwin" && os.Getenv("SENTINEL_DISABLE_KEYCHAIN") == "" {
		if v := darwinKeychainGet(key); v != "" {
			return v
		}
	}

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

	// For GitHub token, optionally query `gh auth token` if installed
	if key == KeyGitHubToken && os.Getenv("SENTINEL_SKIP_GH_CLI") == "" {
		if out, err := exec.Command("gh", "auth", "token").Output(); err == nil {
			if tok := strings.TrimSpace(string(out)); tok != "" {
				return tok
			}
		}
	}

	return ""
}

// Set stores a credential securely in the OS Keychain (when available) and/or 0600 fallback file.
func Set(key, value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return Delete(key)
	}

	mu.RLock()
	nb := nativeBackend
	mu.RUnlock()
	if nb != nil {
		if err := nb.Set(key, value); err == nil {
			// Also remove any stale plaintext entry in fallback file
			_ = deleteFromFileMap(credentialsFilePath(), key)
			return nil
		}
	} else if runtime.GOOS == "darwin" && os.Getenv("SENTINEL_DISABLE_KEYCHAIN") == "" {
		if err := darwinKeychainSet(key, value); err == nil {
			_ = deleteFromFileMap(credentialsFilePath(), key)
			return nil
		}
	}

	return saveToFileMap(credentialsFilePath(), key, value)
}

// Delete removes a credential from Keychain and local fallback storage.
func Delete(key string) error {
	mu.RLock()
	nb := nativeBackend
	mu.RUnlock()
	if nb != nil {
		_ = nb.Delete(key)
	} else if runtime.GOOS == "darwin" && os.Getenv("SENTINEL_DISABLE_KEYCHAIN") == "" {
		_ = darwinKeychainDelete(key)
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

func darwinKeychainGet(account string) string {
	cmd := exec.Command("/usr/bin/security", "find-generic-password", "-s", ServiceName, "-a", account, "-w")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func darwinKeychainSet(account, secret string) error {
	cmd := exec.Command("/usr/bin/security", "add-generic-password", "-U", "-s", ServiceName, "-a", account, "-w", secret)
	return cmd.Run()
}

func darwinKeychainDelete(account string) error {
	cmd := exec.Command("/usr/bin/security", "delete-generic-password", "-s", ServiceName, "-a", account)
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

func saveToFileMap(path, key, val string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	m, err := loadFileMap(path)
	if err != nil || m == nil {
		m = make(map[string]string)
	}
	m[key] = val
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
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
