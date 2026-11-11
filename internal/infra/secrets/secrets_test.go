package secrets

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEncryptedVaultZeroPlaintextAndPermissions(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("XDG_CONFIG_HOME", tmp)
	t.Setenv("SENTINEL_DISABLE_KEYCHAIN", "1")
	t.Setenv("TELEGRAM_BOT_TOKEN", "")

	secretVal := "123456:ABCDEF-super-secret-token"
	if err := Set(KeyTelegramBotToken, secretVal); err != nil {
		t.Fatalf("Set failed: %v", err)
	}
	got := Get(KeyTelegramBotToken)
	if got != secretVal {
		t.Fatalf("Get = %q, want %q", got, secretVal)
	}

	vaultFile := filepath.Join(tmp, "sentinel", "vault.enc")
	info, err := os.Stat(vaultFile)
	if err != nil {
		t.Fatalf("stat vault.enc: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("expected 0600 permissions, got %o", perm)
	}

	rawBytes, err := os.ReadFile(vaultFile)
	if err != nil {
		t.Fatalf("read vault.enc: %v", err)
	}
	if strings.Contains(string(rawBytes), secretVal) || strings.Contains(string(rawBytes), KeyTelegramBotToken) {
		t.Fatalf("vault.enc leaked plaintext secret or key name on disk: %s", string(rawBytes))
	}

	// Verify hardware/user binding: decrypting with another machine's identity must fail!
	if _, err := loadVaultMapWithIdentity(vaultFile, "stolen-other-mac-uuid|uid=501|goos=darwin"); err == nil {
		t.Fatal("expected AES-GCM authentication failure when decrypting on another machine")
	}

	if err := Delete(KeyTelegramBotToken); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	if after := Get(KeyTelegramBotToken); after != "" {
		t.Fatalf("expected empty after Delete, got %q", after)
	}
}

func TestLegacyPlaintextCredentialsAutoMigrationAndShredding(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("XDG_CONFIG_HOME", tmp)
	t.Setenv("SENTINEL_DISABLE_KEYCHAIN", "1")
	t.Setenv("AI_GATEWAY_TOKEN", "")
	t.Setenv("TELEGRAM_BOT_TOKEN", "")

	// Seed legacy ~/.config/sentinel/credentials.json and ~/.gemini/config/sentinel_telegram.json
	cfgDir := filepath.Join(tmp, "sentinel")
	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	legacyCredFile := filepath.Join(cfgDir, "credentials.json")
	if err := os.WriteFile(legacyCredFile, []byte(`{"ai_gateway_token":"sk-legacy-gw-999"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	geminiDir := filepath.Join(tmp, ".gemini", "config")
	if err := os.MkdirAll(geminiDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(geminiDir, "sentinel_telegram.json"), []byte(`{"bot_token":"tg-legacy-777","chat_id":"888999"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	// Clear in-memory caches for clean migration run
	mu.Lock()
	memCache = make(map[string]string)
	migratedVault = make(map[string]bool)
	mu.Unlock()

	if gotGW := Get(KeyAIGatewayToken); gotGW != "sk-legacy-gw-999" {
		t.Fatalf("expected migrated AI gateway token, got %q", gotGW)
	}
	if gotTG := Get(KeyTelegramBotToken); gotTG != "tg-legacy-777" {
		t.Fatalf("expected migrated Telegram bot token, got %q", gotTG)
	}

	// Plaintext credentials.json must be shredded after migration into vault.enc
	if _, err := os.Stat(legacyCredFile); !os.IsNotExist(err) {
		t.Fatalf("expected legacy plaintext credentials.json to be removed after migration, err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(cfgDir, "vault.enc")); err != nil {
		t.Fatalf("expected encrypted vault.enc to exist after migration: %v", err)
	}
}
