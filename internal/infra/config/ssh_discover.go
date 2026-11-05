package config

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sixban6/security-sentinel/internal/infra/model"
)

var nonServerDomains = map[string]bool{
	"github.com":              true,
	"ssh.github.com":          true,
	"gist.github.com":         true,
	"gitlab.com":              true,
	"bitbucket.org":           true,
	"gitee.com":               true,
	"codeup.aliyun.com":       true,
	"e.coding.net":            true,
	"huggingface.co":          true,
	"hf.co":                   true,
	"aur.archlinux.org":       true,
	"vs-ssh.visualstudio.com": true,
	"ssh.dev.azure.com":       true,
	"localhost":               true,
	"127.0.0.1":               true,
	"::1":                     true,
}

// DiscoveredSSHHost represents a concrete host alias found in ~/.ssh/config.
type DiscoveredSSHHost struct {
	Alias        string `json:"alias"`
	HostName     string `json:"host_name"`
	User         string `json:"user"`
	ExplicitUser bool   `json:"explicit_user,omitempty"`
	Port         int    `json:"port"`
	IdentityFile string `json:"identity_file,omitempty"`
	ProxyJump    string `json:"proxy_jump,omitempty"`
	HasProxyCmd  bool   `json:"has_proxy_cmd,omitempty"`
	AlreadyAdded bool   `json:"already_added"`
	Reachable    bool   `json:"reachable"`
	LatencyMS    int64  `json:"latency_ms,omitempty"`
	RemoteOS     string `json:"remote_os,omitempty"`
}

func (d DiscoveredSSHHost) ToHostTarget() model.HostTarget {
	user := d.User
	if user == "" {
		user = "root"
	}
	sshTarget := d.Alias
	if !strings.Contains(sshTarget, "@") {
		sshTarget = user + "@" + d.Alias
	}
	return model.HostTarget{
		ID:      sshTarget,
		Name:    sshTarget,
		Type:    "remote",
		SSHHost: sshTarget,
		User:    user,
		Host:    d.HostName,
		Port:    d.Port,
	}
}

// DiscoverSSHConfigHosts parses ~/.ssh/config, enriches effective OpenSSH parameters via `ssh -G`,
// and deduplicates aliases pointing to the same (HostName, Port).
func DiscoverSSHConfigHosts(existing []model.HostTarget) []DiscoveredSSHHost {
	sshCfgPath := ExpandHome("~/.ssh/config")
	items := DiscoverSSHConfigFromFile(sshCfgPath, existing)
	enrichWithOpenSSHConfig(items, existing)
	return deduplicateByEndpoint(items)
}

func DiscoverSSHConfigFromFile(sshCfgPath string, existing []model.HostTarget) []DiscoveredSSHHost {
	existingKeys := buildExistingHostKeySet(existing)

	visitedFiles := make(map[string]bool)
	var items []DiscoveredSSHHost
	parseSSHConfigFile(sshCfgPath, visitedFiles, &items)

	seenAlias := make(map[string]bool)
	var deduped []DiscoveredSSHHost

	for _, it := range items {
		lowAlias := strings.ToLower(it.Alias)
		lowHost := strings.ToLower(it.HostName)
		if seenAlias[lowAlias] || nonServerDomains[lowAlias] || nonServerDomains[lowHost] {
			continue
		}
		seenAlias[lowAlias] = true
		if isHostAlreadyManaged(it, existingKeys) {
			it.AlreadyAdded = true
		}
		deduped = append(deduped, it)
	}
	return deduplicateByEndpoint(deduped)
}

func buildExistingHostKeySet(existing []model.HostTarget) map[string]bool {
	keys := make(map[string]bool)
	for _, h := range existing {
		if h.SSHHost != "" {
			keys[strings.ToLower(h.SSHHost)] = true
			if at := strings.IndexByte(h.SSHHost, '@'); at >= 0 {
				keys[strings.ToLower(h.SSHHost[at+1:])] = true
			}
		}
		if h.Host != "" {
			keys[strings.ToLower(h.Host)] = true
		}
		if h.Name != "" {
			keys[strings.ToLower(h.Name)] = true
		}
	}
	return keys
}

func isHostAlreadyManaged(it DiscoveredSSHHost, existingKeys map[string]bool) bool {
	if existingKeys[strings.ToLower(it.Alias)] {
		return true
	}
	if it.HostName != "" && existingKeys[strings.ToLower(it.HostName)] {
		return true
	}
	return false
}

// enrichWithOpenSSHConfig invokes `ssh -G <alias>` to obtain OpenSSH's exact merged HostName, Port, and ProxyCommand.
func enrichWithOpenSSHConfig(items []DiscoveredSSHHost, existing []model.HostTarget) {
	if _, err := exec.LookPath("ssh"); err != nil || len(items) == 0 {
		return
	}
	existingKeys := buildExistingHostKeySet(existing)
	var wg sync.WaitGroup
	for i := range items {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			alias := items[idx].Alias
			out, err := exec.Command("ssh", "-G", alias).Output()
			if err != nil {
				return
			}
			for _, line := range strings.Split(string(out), "\n") {
				line = strings.TrimSpace(line)
				sp := strings.IndexByte(line, ' ')
				if sp <= 0 {
					continue
				}
				k, v := line[:sp], strings.TrimSpace(line[sp+1:])
				switch k {
				case "hostname":
					if v != "" {
						items[idx].HostName = v
					}
				case "port":
					if p, err := strconv.Atoi(v); err == nil && p > 0 {
						items[idx].Port = p
					}
				case "proxycommand":
					if v != "" && v != "none" {
						items[idx].HasProxyCmd = true
					}
				}
			}
			if isHostAlreadyManaged(items[idx], existingKeys) {
				items[idx].AlreadyAdded = true
			}
		}(i)
	}
	wg.Wait()
}

func deduplicateByEndpoint(items []DiscoveredSSHHost) []DiscoveredSSHHost {
	seenEndpoint := make(map[string]bool)
	var out []DiscoveredSSHHost
	for _, it := range items {
		lowHost := strings.ToLower(it.HostName)
		if nonServerDomains[lowHost] {
			continue
		}
		port := it.Port
		if port <= 0 {
			port = 22
		}
		u := strings.ToLower(it.User)
		if !it.ExplicitUser {
			u = "auto"
		}
		epKey := fmt.Sprintf("%s@%s:%d", u, lowHost, port)
		if lowHost != "" && seenEndpoint[epKey] {
			continue
		}
		if lowHost != "" {
			seenEndpoint[epKey] = true
		}
		out = append(out, it)
	}
	return out
}

// ProbeValidSSHHosts runs ProbeValidSSHHostsStream and returns the final collected valid list and filtered count.
func ProbeValidSSHHosts(ctx context.Context, candidates []DiscoveredSSHHost) (valid []DiscoveredSSHHost, filteredOut int) {
	return ProbeValidSSHHostsStream(ctx, candidates, nil, nil)
}

// ProbeValidSSHHostsStream concurrently verifies passwordless SSH reachability & POSIX OS support:
// - Enriches PATH so ProxyCommand tools (wstunnel, cloudflared) always work inside macOS .app bundles
// - Allows up to 8.5s per host so cross-Pacific WebSocket/TLS tunnels (4~5s) never get prematurely killed
// - Smartly tries "root@<alias>" first when User was omitted in ~/.ssh/config (preventing local macOS username mismatch!)
// - Streams each verified live server immediately via onFound so fast LAN hosts appear in 150ms!
func ProbeValidSSHHostsStream(
	ctx context.Context,
	candidates []DiscoveredSSHHost,
	onFound func(host DiscoveredSSHHost),
	onProgress func(done int, total int, filtered int),
) (valid []DiscoveredSSHHost, filteredOut int) {
	total := len(candidates)
	if total == 0 {
		return nil, 0
	}

	enrichedEnv := buildEnrichedEnv()
	var (
		mu       sync.Mutex
		wg       sync.WaitGroup
		sem      = make(chan struct{}, 10)
		doneCnt  int32
		filtCnt  int32
		ordered  = make([]*DiscoveredSSHHost, total)
	)

	for idx, cand := range candidates {
		wg.Add(1)
		go func(i int, d DiscoveredSSHHost) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			var usersToTry []string
			if d.ExplicitUser && d.User != "" {
				usersToTry = []string{d.User}
			} else {
				// When User is omitted in ~/.ssh/config, try root first (most VPS/OpenWrt/PVE servers),
				// and only try fallback users if SSH daemon answered with "Permission denied"!
				usersToTry = []string{"root", "", "ubuntu", "debian"}
			}

			matched := false
			for _, u := range usersToTry {
				if ctx.Err() != nil {
					break
				}
				osOut, lat, permDenied, ok := probeSingleSSHUser(ctx, d, u, enrichedEnv)
				if ok {
					if u != "" {
						d.User = u
					} else if d.User == "" {
						d.User = os.Getenv("USER")
					}
					d.Reachable = true
					d.LatencyMS = lat
					d.RemoteOS = osOut
					matched = true
					break
				}
				// If TCP/TLS timed out or connection was refused/reset, the host is offline—do not retry other usernames!
				if !permDenied {
					break
				}
			}

			doneNow := int(atomic.AddInt32(&doneCnt, 1))
			if matched {
				mu.Lock()
				cp := d
				ordered[i] = &cp
				mu.Unlock()
				if onFound != nil {
					onFound(d)
				}
			} else {
				atomic.AddInt32(&filtCnt, 1)
			}
			if onProgress != nil {
				onProgress(doneNow, total, int(atomic.LoadInt32(&filtCnt)))
			}
		}(idx, cand)
	}
	wg.Wait()

	for _, ptr := range ordered {
		if ptr != nil {
			valid = append(valid, *ptr)
		}
	}
	return valid, int(atomic.LoadInt32(&filtCnt))
}

func probeSingleSSHUser(ctx context.Context, d DiscoveredSSHHost, tryUser string, env []string) (remoteOS string, latencyMS int64, permDenied bool, ok bool) {
	pCtx, cancel := context.WithTimeout(ctx, 8500*time.Millisecond)
	defer cancel()

	// Delegate HostName/Port/IdentityFile/ProxyCommand resolution directly to OpenSSH via `d.Alias`!
	args := []string{
		"-T",
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=accept-new",
		"-o", "ConnectTimeout=6",
		"-o", "RemoteCommand=none",
	}
	dest := d.Alias
	if tryUser != "" && !strings.Contains(dest, "@") {
		dest = tryUser + "@" + dest
	}
	args = append(args, dest, "uname -s -r 2>/dev/null")

	start := time.Now()
	cmd := exec.CommandContext(pCtx, "ssh", args...)
	cmd.Env = env
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	lat := time.Since(start).Milliseconds()

	outStr := strings.TrimSpace(stdout.String())
	lowOut := strings.ToLower(outStr)
	isPOSIX := strings.Contains(lowOut, "linux") || strings.Contains(lowOut, "darwin") || strings.Contains(lowOut, "bsd")
	if err == nil && isPOSIX {
		if nl := strings.IndexByte(outStr, '\n'); nl >= 0 {
			outStr = strings.TrimSpace(outStr[:nl])
		}
		return outStr, lat, false, true
	}

	errLow := strings.ToLower(stderr.String())
	if strings.Contains(errLow, "permission denied") {
		return "", lat, true, false
	}
	return "", lat, false, false
}

func buildEnrichedEnv() []string {
	home, _ := os.UserHomeDir()
	extra := []string{"/opt/homebrew/bin", "/opt/homebrew/sbin", "/usr/local/bin", "/usr/local/sbin"}
	if home != "" {
		extra = append(extra, filepath.Join(home, ".local", "bin"), filepath.Join(home, ".cargo", "bin"))
	}
	curPath := os.Getenv("PATH")
	fullPath := strings.Join(extra, string(os.PathListSeparator)) + string(os.PathListSeparator) + curPath
	var env []string
	replaced := false
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "PATH=") {
			env = append(env, "PATH="+fullPath)
			replaced = true
		} else {
			env = append(env, kv)
		}
	}
	if !replaced {
		env = append(env, "PATH="+fullPath)
	}
	return env
}

func parseSSHConfigFile(path string, visited map[string]bool, out *[]DiscoveredSSHHost) {
	abs, err := filepath.Abs(ExpandHome(path))
	if err != nil || visited[abs] {
		return
	}
	visited[abs] = true

	f, err := os.Open(abs)
	if err != nil {
		return
	}
	defer f.Close()

	baseDir := filepath.Dir(abs)
	var currentAliases []string
	var cur DiscoveredSSHHost

	flush := func() {
		for _, alias := range currentAliases {
			if alias == "" || strings.ContainsAny(alias, "*?!") {
				continue
			}
			low := strings.ToLower(alias)
			if nonServerDomains[low] {
				continue
			}
			entry := cur
			entry.Alias = alias
			if entry.HostName == "" {
				entry.HostName = alias
			}
			*out = append(*out, entry)
		}
		currentAliases = nil
		cur = DiscoveredSSHHost{}
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if idx := strings.IndexByte(line, '#'); idx > 0 {
			line = strings.TrimSpace(line[:idx])
		}
		key, val := splitSSHDirective(line)
		switch strings.ToLower(key) {
		case "include":
			flush()
			for _, pat := range strings.Fields(val) {
				fullPat := ExpandHome(pat)
				if !filepath.IsAbs(fullPat) {
					fullPat = filepath.Join(baseDir, fullPat)
				}
				matches, _ := filepath.Glob(fullPat)
				for _, m := range matches {
					parseSSHConfigFile(m, visited, out)
				}
			}
		case "host":
			flush()
			currentAliases = strings.Fields(val)
		case "match":
			flush()
		case "hostname":
			cur.HostName = strings.Trim(val, "\"'")
		case "user":
			u := strings.Trim(val, "\"'")
			if u != "" {
				cur.User = u
				cur.ExplicitUser = true
			}
		case "port":
			if p, err := strconv.Atoi(strings.TrimSpace(val)); err == nil {
				cur.Port = p
			}
		case "identityfile":
			if cur.IdentityFile == "" {
				cur.IdentityFile = ExpandHome(strings.Trim(val, "\"'"))
			}
		case "proxyjump":
			cur.ProxyJump = strings.Trim(val, "\"'")
		case "proxycommand":
			cur.HasProxyCmd = true
		}
	}
	flush()
}

func splitSSHDirective(line string) (string, string) {
	for i := 0; i < len(line); i++ {
		if line[i] == ' ' || line[i] == '\t' || line[i] == '=' {
			k := strings.TrimSpace(line[:i])
			v := strings.TrimLeft(line[i:], " \t=")
			return k, strings.TrimSpace(v)
		}
	}
	return line, ""
}
