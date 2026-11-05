package secrets

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSecretsFileFallbackAndPermissions(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("XDG_CONFIG_HOME", tmp)
	t.Setenv("SENTINEL_DISABLE_KEYCHAIN", "1")
	t.Setenv("TELEGRAM_BOT_TOKEN", "")

	if err := Set(KeyTelegramBotToken, "123456:ABCDEF-secret-token"); err != nil {
		t.Fatalf("Set failed: %v", err)
	}
	got := Get(KeyTelegramBotToken)
	if got != "123456:ABCDEF-secret-token" {
		t.Fatalf("Get = %q", got)
	}

	credFile := filepath.Join(tmp, "sentinel", "credentials.json")
	info, err := os.Stat(credFile)
	if err != nil {
		t.Fatalf("stat credentials.json: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("expected 0600 permissions, got %o", perm)
	}

	if err := Delete(KeyTelegramBotToken); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	if after := Get(KeyTelegramBotToken); after != "" {
		t.Fatalf("expected empty after Delete, got %q", after)
	}
}
