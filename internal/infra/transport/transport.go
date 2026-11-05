package transport

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/sixban6/security-sentinel/internal/infra/model"
)

// Result captures execution output, exit code, and wall-clock latency.
type Result struct {
	Code      int
	Stdout    string
	Stderr    string
	LatencyMS int64
}

// Executor abstracts command & script execution across local and SSH targets.
type Executor interface {
	Target() model.HostTarget
	Run(ctx context.Context, cmd string, timeout time.Duration) (Result, error)
	RunStdin(ctx context.Context, cmd string, stdin string, timeout time.Duration) (Result, error)
}

// EnsureStandardUserPATH enriches process PATH with standard Homebrew/user bin directories
// because macOS GUI .app bundles launch with a stripped PATH (/usr/bin:/bin:/usr/sbin:/sbin),
// which would otherwise hide tools like wstunnel, cloudflared, brew, uv, go, and cargo.
func EnsureStandardUserPATH() {
	home, _ := os.UserHomeDir()
	extra := []string{
		"/opt/homebrew/bin",
		"/opt/homebrew/sbin",
		"/usr/local/bin",
		"/usr/local/sbin",
	}
	if home != "" {
		extra = append(extra,
			filepath.Join(home, ".local", "bin"),
			filepath.Join(home, ".cargo", "bin"),
			filepath.Join(home, "go", "bin"),
		)
	}
	cur := os.Getenv("PATH")
	existing := make(map[string]bool)
	var parts []string
	for _, p := range strings.Split(cur, string(os.PathListSeparator)) {
		if p != "" {
			existing[p] = true
			parts = append(parts, p)
		}
	}
	var merged []string
	for _, p := range extra {
		if !existing[p] {
			if info, err := os.Stat(p); err == nil && info.IsDir() {
				existing[p] = true
				merged = append(merged, p)
			}
		}
	}
	merged = append(merged, parts...)
	_ = os.Setenv("PATH", strings.Join(merged, string(os.PathListSeparator)))
}

// New returns the right Executor (LocalExecutor or pooled SSHExecutor) for target.
func New(target model.HostTarget) Executor {
	if target.IsLocal() {
		return &LocalExecutor{target: target}
	}
	return &SSHExecutor{target: target}
}

// LocalExecutor runs commands via /bin/sh locally without shell-interpolation vulnerabilities on arguments.
type LocalExecutor struct {
	target model.HostTarget
}

func (l *LocalExecutor) Target() model.HostTarget { return l.target }

func (l *LocalExecutor) Run(ctx context.Context, cmdStr string, timeout time.Duration) (Result, error) {
	return l.RunStdin(ctx, cmdStr, "", timeout)
}

func (l *LocalExecutor) RunStdin(ctx context.Context, cmdStr string, stdin string, timeout time.Duration) (Result, error) {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	shBin := "/bin/sh"
	if p, err := exec.LookPath("sh"); err == nil {
		shBin = p
	}

	start := time.Now()
	var c *exec.Cmd
	if cmdStr == "" {
		c = exec.CommandContext(runCtx, shBin, "-s")
	} else {
		c = exec.CommandContext(runCtx, shBin, "-c", cmdStr)
	}
	c.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	if stdin != "" {
		c.Stdin = strings.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	c.Stdout = &stdout
	c.Stderr = &stderr

	err := c.Run()
	elapsed := time.Since(start).Milliseconds()
	code := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			code = exitErr.ExitCode()
			err = nil
		} else {
			code = -1
		}
	}
	return Result{
		Code:      code,
		Stdout:    strings.TrimSpace(stdout.String()),
		Stderr:    strings.TrimSpace(stderr.String()),
		LatencyMS: elapsed,
	}, err
}

// SSHExecutor executes remote commands over OpenSSH with private ControlMaster connection multiplexing,
// honoring custom Port, IdentityFile, ProxyJump, and ~/.ssh/config aliases.
type SSHExecutor struct {
	target model.HostTarget
}

func (s *SSHExecutor) Target() model.HostTarget { return s.target }

func controlSocketDir() string {
	// Use /tmp/ss-<uid> instead of os.TempDir() because macOS /var/folders/... paths
	// exceed BSD's 104-byte Unix domain socket sun_path limit when combined with %C + temp suffix.
	dir := fmt.Sprintf("/tmp/ss-%d", os.Getuid())
	if info, err := os.Lstat(dir); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return os.TempDir()
		}
		_ = os.Chmod(dir, 0o700)
		return dir
	}
	_ = os.MkdirAll(dir, 0o700)
	_ = os.Chmod(dir, 0o700)
	return dir
}

// BuildSSHArgs builds injection-safe OpenSSH argv for the configured HostTarget.
func BuildSSHArgs(target model.HostTarget, remoteCmd string, useMultiplex bool) []string {
	args := []string{
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=accept-new",
		"-o", "ConnectTimeout=6",
	}
	if useMultiplex {
		sockPath := filepath.Join(controlSocketDir(), "%C")
		args = append(args,
			"-o", "ControlMaster=auto",
			"-o", "ControlPath="+sockPath,
			"-o", "ControlPersist=60s",
		)
	}
	if target.Port > 0 {
		args = append(args, "-p", strconv.Itoa(target.Port))
	}
	if target.IdentityFile != "" {
		args = append(args, "-i", target.IdentityFile)
	}
	if target.ProxyJump != "" {
		args = append(args, "-J", target.ProxyJump)
	}
	dest := target.SSHHost
	if dest == "" {
		if target.User != "" && target.Host != "" && !strings.Contains(target.Host, "@") {
			dest = target.User + "@" + target.Host
		} else if target.Host != "" {
			dest = target.Host
		} else {
			dest = target.Name
		}
	}
	args = append(args, dest, remoteCmd)
	return args
}

func (s *SSHExecutor) Run(ctx context.Context, remoteCmd string, timeout time.Duration) (Result, error) {
	return s.RunStdin(ctx, remoteCmd, "", timeout)
}

func (s *SSHExecutor) RunStdin(ctx context.Context, remoteCmd string, stdin string, timeout time.Duration) (Result, error) {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if remoteCmd == "" {
		remoteCmd = "sh -s"
	}
	args := BuildSSHArgs(s.target, remoteCmd, true)

	start := time.Now()
	c := exec.CommandContext(runCtx, "ssh", args...)
	if stdin != "" {
		c.Stdin = strings.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	c.Stdout = &stdout
	c.Stderr = &stderr

	err := c.Run()
	elapsed := time.Since(start).Milliseconds()
	code := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			code = exitErr.ExitCode()
			err = nil
		} else {
			code = -1
		}
	}
	return Result{
		Code:      code,
		Stdout:    strings.TrimSpace(stdout.String()),
		Stderr:    strings.TrimSpace(stderr.String()),
		LatencyMS: elapsed,
	}, err
}

// WrapPrivileged prefixes sudo -n when the host user is non-root and passwordless sudo is available.
func WrapPrivileged(cmd string, osCtx model.OSContext) (wrapped string, ok bool) {
	if osCtx.IsRoot {
		return cmd, true
	}
	if osCtx.CanSudoNoPass {
		return "sudo -n sh -c " + ShellQuote(cmd), true
	}
	return cmd, false
}

// ShellQuote safely single-quotes an arbitrary POSIX shell string.
func ShellQuote(s string) string {
	if s == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// ResolveSSHHostPort invokes `ssh -G` safely to inspect effective HostName and Port for TCP readiness polling.
func ResolveSSHHostPort(target model.HostTarget) (host string, port int) {
	host = target.Host
	port = target.Port
	if port <= 0 {
		port = 22
	}
	dest := target.SSHHost
	if dest == "" {
		dest = target.Host
	}
	if dest == "" {
		return host, port
	}
	args := []string{"-G"}
	if target.Port > 0 {
		args = append(args, "-p", strconv.Itoa(target.Port))
	}
	args = append(args, dest)
	out, err := exec.Command("ssh", args...).Output()
	if err != nil {
		if at := strings.IndexByte(dest, '@'); at >= 0 {
			return dest[at+1:], port
		}
		return dest, port
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) >= 2 {
			switch fields[0] {
			case "hostname":
				host = fields[1]
			case "port":
				if p, err := strconv.Atoi(fields[1]); err == nil && p > 0 {
					port = p
				}
			}
		}
	}
	return host, port
}
