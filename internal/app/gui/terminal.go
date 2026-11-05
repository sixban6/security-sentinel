package gui

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/sixban6/security-sentinel/internal/infra/model"
	"github.com/sixban6/security-sentinel/internal/infra/transport"
)

func buildSSHArgv(target model.HostTarget) []string {
	var args []string
	if target.Port > 0 && target.Port != 22 {
		args = append(args, "-p", strconv.Itoa(target.Port))
	}
	if target.IdentityFile != "" {
		args = append(args, "-i", target.IdentityFile)
	}
	if target.ProxyJump != "" {
		args = append(args, "-J", target.ProxyJump)
	}
	dest := strings.TrimSpace(target.SSHHost)
	if dest == "" {
		if target.User != "" && target.Host != "" && !strings.Contains(target.Host, "@") {
			dest = target.User + "@" + target.Host
		} else if target.Host != "" {
			dest = target.Host
		} else {
			dest = target.Name
		}
	}
	if dest != "" {
		args = append(args, dest)
	}
	return args
}

// buildInteractiveSSHWrapper guarantees standard Homebrew/user PATH is injected (so ProxyCommand tools like wstunnel/cloudflared
// always resolve even when GUI apps have a stripped PATH), and pauses on unexpected SSH errors instead of flashing & closing!
func buildInteractiveSSHWrapper(sshArgs []string) (shellBin string, wrapperCmd string) {
	shellBin = os.Getenv("SHELL")
	if shellBin == "" {
		if runtime.GOOS == "darwin" {
			shellBin = "/bin/zsh"
		} else {
			shellBin = "/bin/sh"
		}
	}
	var quoted []string
	for _, a := range sshArgs {
		quoted = append(quoted, transport.ShellQuote(a))
	}
	wrapperCmd = `export PATH="/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:$HOME/.local/bin:$HOME/.cargo/bin:$PATH"; ` +
		`ssh ` + strings.Join(quoted, " ") +
		`; code=$?; if [ "$code" -ne 0 ] && [ "$code" -ne 130 ]; then printf '\n\033[33m[SSH 连接未建立或异常断开 (退出码 %d)，按回车键关闭标签页]\033[0m ' "$code"; read -r _; fi`
	return shellBin, wrapperCmd
}

func findExecutable(candidates ...string) string {
	home, _ := os.UserHomeDir()
	for _, c := range candidates {
		if strings.HasPrefix(c, "~/") && home != "" {
			c = filepath.Join(home, c[2:])
		}
		if filepath.IsAbs(c) {
			if info, err := os.Stat(c); err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
				return c
			}
			continue
		}
		if p, err := exec.LookPath(c); err == nil {
			return p
		}
	}
	return ""
}

func findAppBundle(appName string) string {
	home, _ := os.UserHomeDir()
	for _, p := range []string{
		filepath.Join("/Applications", appName),
		filepath.Join(home, "Applications", appName),
	} {
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			return p
		}
	}
	return ""
}

func isProcessRunning(pattern string) bool {
	return exec.Command("pgrep", "-fi", pattern).Run() == nil
}

func ResolvePreferredTerminal(preferred string) string {
	pref := strings.ToLower(strings.TrimSpace(preferred))
	if pref != "" && pref != "auto" {
		return pref
	}

	if runtime.GOOS == "darwin" {
		runningOrder := []struct {
			id      string
			pattern string
			check   func() bool
		}{
			{"wezterm", "wezterm", func() bool { return weztermBinary() != "" }},
			{"ghostty", "ghostty", func() bool { return ghosttyBinary() != "" }},
			{"iterm2", "iTerm", func() bool { return findAppBundle("iTerm.app") != "" }},
			{"kitty", "kitty", func() bool { return kittyBinary() != "" }},
			{"alacritty", "alacritty", func() bool { return alacrittyBinary() != "" }},
		}
		for _, r := range runningOrder {
			if r.check() && isProcessRunning(r.pattern) {
				return r.id
			}
		}
		for _, r := range runningOrder {
			if r.check() {
				return r.id
			}
		}
		return "terminal"
	}

	for _, id := range []string{"wezterm", "ghostty", "kitty", "alacritty", "x-terminal-emulator", "gnome-terminal", "konsole", "xterm"} {
		if findExecutable(id) != "" {
			return id
		}
	}
	return "xterm"
}

func weztermBinary() string {
	return findExecutable(
		"/Applications/WezTerm.app/Contents/MacOS/wezterm",
		"~/Applications/WezTerm.app/Contents/MacOS/wezterm",
		"/opt/homebrew/bin/wezterm",
		"/usr/local/bin/wezterm",
		"wezterm",
	)
}

func ghosttyBinary() string {
	return findExecutable(
		"/Applications/Ghostty.app/Contents/MacOS/ghostty",
		"~/Applications/Ghostty.app/Contents/MacOS/ghostty",
		"/opt/homebrew/bin/ghostty",
		"/usr/local/bin/ghostty",
		"ghostty",
	)
}

func kittyBinary() string {
	return findExecutable(
		"/Applications/kitty.app/Contents/MacOS/kitty",
		"~/Applications/kitty.app/Contents/MacOS/kitty",
		"/opt/homebrew/bin/kitty",
		"/usr/local/bin/kitty",
		"kitty",
	)
}

func alacrittyBinary() string {
	return findExecutable(
		"/Applications/Alacritty.app/Contents/MacOS/alacritty",
		"~/Applications/Alacritty.app/Contents/MacOS/alacritty",
		"/opt/homebrew/bin/alacritty",
		"/usr/local/bin/alacritty",
		"alacritty",
	)
}

func detectActiveWezTermWindowID(wezBin string) (int, bool) {
	out, err := exec.Command(wezBin, "cli", "list", "--format", "json").Output()
	if err != nil || len(out) == 0 {
		return 0, false
	}
	var panes []struct {
		WindowID  int    `json:"window_id"`
		Workspace string `json:"workspace"`
		IsActive  bool   `json:"is_active"`
	}
	if err := json.Unmarshal(out, &panes); err != nil || len(panes) == 0 {
		return 0, false
	}
	for _, p := range panes {
		if p.IsActive {
			return p.WindowID, true
		}
	}
	return panes[0].WindowID, true
}

// OpenSSHTerminal opens an interactive SSH session inside the user's modern terminal (e.g. WezTerm new focused tab!).
func OpenSSHTerminal(target model.HostTarget, preferred string) (string, error) {
	transport.EnsureStandardUserPATH()
	if target.IsLocal() {
		return "", fmt.Errorf("本机无需打开远程 SSH")
	}
	sshArgs := buildSSHArgv(target)
	if len(sshArgs) == 0 {
		return "", fmt.Errorf("主机 SSH 地址为空")
	}

	homeDir, _ := os.UserHomeDir()
	if homeDir == "" {
		homeDir = "/"
	}
	shellBin, wrapperCmd := buildInteractiveSSHWrapper(sshArgs)
	termID := ResolvePreferredTerminal(preferred)

	switch termID {
	case "wezterm":
		if bin := weztermBinary(); bin != "" {
			spawnArgs := []string{"cli", "spawn", "--cwd", homeDir}
			if wid, ok := detectActiveWezTermWindowID(bin); ok {
				spawnArgs = append(spawnArgs, "--window-id", strconv.Itoa(wid))
			}
			spawnArgs = append(spawnArgs, "--", shellBin, "-lc", wrapperCmd)

			if out, err := exec.Command(bin, spawnArgs...).Output(); err == nil {
				paneID := strings.TrimSpace(string(out))
				if paneID != "" {
					_ = exec.Command(bin, "cli", "activate-pane", "--pane-id", paneID).Run()
				}
			} else {
				startArgs := []string{"start", "--new-tab", "--cwd", homeDir, "--", shellBin, "-lc", wrapperCmd}
				if err2 := exec.Command(bin, startArgs...).Start(); err2 != nil {
					return "", err2
				}
			}
			if runtime.GOOS == "darwin" {
				if app := findAppBundle("WezTerm.app"); app != "" {
					_ = exec.Command("open", "-a", app).Start()
				}
			}
			return "WezTerm", nil
		}

	case "ghostty":
		if runtime.GOOS == "darwin" {
			if app := findAppBundle("Ghostty.app"); app != "" {
				args := []string{"-na", app, "--args", "-e", shellBin, "-lc", wrapperCmd}
				if err := exec.Command("open", args...).Start(); err == nil {
					return "Ghostty", nil
				}
			}
		} else if bin := ghosttyBinary(); bin != "" {
			if err := exec.Command(bin, "-e", shellBin, "-lc", wrapperCmd).Start(); err == nil {
				return "Ghostty", nil
			}
		}

	case "kitty":
		if bin := kittyBinary(); bin != "" {
			if err := exec.Command(bin, shellBin, "-lc", wrapperCmd).Start(); err == nil {
				return "Kitty", nil
			}
		}

	case "alacritty":
		if bin := alacrittyBinary(); bin != "" {
			if err := exec.Command(bin, "-e", shellBin, "-lc", wrapperCmd).Start(); err == nil {
				return "Alacritty", nil
			}
		}

	case "iterm2":
		if runtime.GOOS == "darwin" && findAppBundle("iTerm.app") != "" {
			appleScript := fmt.Sprintf(`tell application "iTerm"
	activate
	if (count of windows) = 0 then
		create window with default profile command %q
	else
		tell current window
			create tab with default profile command %q
		end tell
	end if
end tell`, wrapperCmd, wrapperCmd)
			if err := exec.Command("osascript", "-e", appleScript).Start(); err == nil {
				return "iTerm2", nil
			}
		}
	}

	if runtime.GOOS == "darwin" {
		dest := sshArgs[len(sshArgs)-1]
		sshURL := "ssh://" + dest
		if target.Port > 0 && target.Port != 22 && !strings.Contains(dest, ":") {
			sshURL = fmt.Sprintf("ssh://%s:%d", dest, target.Port)
		}
		if err := exec.Command("open", sshURL).Start(); err == nil {
			return "Terminal", nil
		}
	}

	for _, term := range []string{"x-terminal-emulator", "gnome-terminal", "konsole", "xterm"} {
		if p := findExecutable(term); p != "" {
			if err := exec.Command(p, "-e", shellBin, "-lc", wrapperCmd).Start(); err == nil {
				return term, nil
			}
		}
	}

	return "", fmt.Errorf("未找到可用的终端程序")
}
