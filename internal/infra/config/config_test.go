package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseAndNormalizeHosts(t *testing.T) {
	raw := `
hosts:
  - root@1.2.3.4
  - name: "生产 Web 节点"
    user: ubuntu
    host: 5.6.7.8
    port: 2222
auto_fix: true
ai_remediation:
  enabled: true
  model: "gemini-3.8-flash-high"
`
	cfg := DefaultConfig()
	if err := ParseBytes([]byte(raw), &cfg); err != nil {
		t.Fatalf("ParseBytes failed: %v", err)
	}
	if !cfg.AutoFix.Enabled {
		t.Fatal("expected scalar auto_fix: true to set Enabled=true")
	}
	hosts := cfg.ConfiguredHosts()
	if len(hosts) != 3 {
		t.Fatalf("expected local + 2 remote hosts, got %d", len(hosts))
	}
	if !hosts[0].IsLocal() {
		t.Fatal("expected local host first")
	}
	if hosts[2].Name != "生产 Web 节点" || hosts[2].SSHHost != "ubuntu@5.6.7.8" || hosts[2].Port != 2222 {
		t.Fatalf("unexpected custom host normalization: %+v", hosts[2])
	}
}

func TestEmbeddedTemplateMatchesRootExample(t *testing.T) {
	rootBytes, err := os.ReadFile(filepath.Join("..", "..", "..", "sentinel.example.yaml"))
	if err != nil {
		t.Fatalf("read root sentinel.example.yaml: %v", err)
	}
	if string(rootBytes) != EmbeddedExampleYAML {
		t.Fatal("root sentinel.example.yaml and embedded internal/config/sentinel.example.yaml diverged")
	}
}

func TestDiscoverSSHConfigHosts(t *testing.T) {
	dir := t.TempDir()
	sshFile := filepath.Join(dir, "config")
	content := `
Host *
  ServerAliveInterval 30

Host github.com
  HostName github.com
  User git

Host node_alpha
  HostName 203.0.113.10
  User debian
  Port 2222

Host openwrt_gw
  HostName 192.0.2.1
  User root
`
	if err := os.WriteFile(sshFile, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	found := DiscoverSSHConfigFromFile(sshFile, nil)
	if len(found) != 2 {
		t.Fatalf("expected 2 discovered hosts (skipping * and github.com), got %d: %+v", len(found), found)
	}
	if found[0].Alias != "node_alpha" || found[0].Port != 2222 || found[0].User != "debian" {
		t.Fatalf("unexpected first host: %+v", found[0])
	}
}
