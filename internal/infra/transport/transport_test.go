package transport

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/sixban6/security-sentinel/internal/infra/model"
)

func TestBuildSSHArgsSeparatesDisplayNameFromSSHHostAndPort(t *testing.T) {
	target := model.HostTarget{
		Name:         "生产 Web 节点",
		Type:         "remote",
		SSHHost:      "ubuntu@5.6.7.8",
		Port:         2222,
		IdentityFile: "/tmp/id_ed25519",
	}
	args := BuildSSHArgs(target, "uname -a", true)
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "生产 Web 节点") {
		t.Fatalf("SSH args leaked display Name instead of SSHHost: %v", args)
	}
	if !strings.Contains(joined, "-p 2222") || !strings.Contains(joined, "-i /tmp/id_ed25519") || !strings.Contains(joined, "ubuntu@5.6.7.8") {
		t.Fatalf("missing expected flags in SSH args: %v", args)
	}
}

func TestLocalExecutorStdinAndShellQuote(t *testing.T) {
	exec := New(model.HostTarget{ID: "local", Name: "local", Type: "local"})
	quoted := ShellQuote(`hello 'world' $(uname)`)
	res, err := exec.Run(context.Background(), "printf '%s' "+quoted, 5*time.Second)
	if err != nil || res.Code != 0 {
		t.Fatalf("LocalExecutor failed: code=%d err=%v stderr=%s", res.Code, err, res.Stderr)
	}
	if res.Stdout != `hello 'world' $(uname)` {
		t.Fatalf("ShellQuote failed to prevent expansion: got %q", res.Stdout)
	}
}
