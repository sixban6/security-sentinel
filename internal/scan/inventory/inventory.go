package inventory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sixban6/security-sentinel/internal/infra/config"
	"github.com/sixban6/security-sentinel/internal/scan/intel"
	"github.com/sixban6/security-sentinel/internal/scan/inventory/lockfile"
	"github.com/sixban6/security-sentinel/internal/infra/store"
	"github.com/sixban6/security-sentinel/internal/infra/model"
	"github.com/sixban6/security-sentinel/internal/infra/transport"
	"gopkg.in/yaml.v3"
)

var (
	ansiEscapeRe = regexp.MustCompile(`\x1b\[[0-9;]*m`)
	debKernelRe  = regexp.MustCompile(`Debian\s+(\d+\.\d+\.\d+)`)
	linKernelRe  = regexp.MustCompile(`Linux version (\d+\.\d+\.\d+)`)
	semNumRe     = regexp.MustCompile(`(\d+\.\d+(?:\.\d+)?)`)
	apkPkgLineRe = regexp.MustCompile(`^([A-Za-z0-9\-\_\.]+)-(\d+[\.\d\w\-\~]*)$`)
	memKBRe      = regexp.MustCompile(`(\d+)\s+kB`)
)

// Single-roundtrip merged probe bundle for Linux & OpenWrt (replaces 11 serial SSH calls with 1!).
const mergedLinuxProbeScript = `
echo "===SEC:OS_RELEASE==="
cat /etc/os-release /etc/openwrt_release /etc/alpine-release 2>/dev/null || true
echo "===SEC:ENV==="
echo "UNAME:$(uname -s -r -m 2>/dev/null)"
echo "PROC_VER:$(cat /proc/version 2>/dev/null || uname -r 2>/dev/null)"
echo "UID:$(id -u 2>/dev/null)"
if [ "$(id -u 2>/dev/null)" = "0" ]; then echo "SUDO:ROOT"; elif sudo -n true 2>/dev/null; then echo "SUDO:YES"; else echo "SUDO:NO"; fi
echo "SHELL:${SHELL}|$(readlink -f /bin/sh 2>/dev/null || ls -l /bin/sh 2>/dev/null | awk '{print $NF}')|$(command -v bash 2>/dev/null)"
echo "INIT:$(command -v systemctl procd init 2>/dev/null | head -n 1)"
echo "FW:$(command -v nft fw4 iptables ufw 2>/dev/null | tr '\n' ' ')"
echo "PM:$(command -v apk opkg apt-get dpkg-query dnf yum pacman 2>/dev/null | tr '\n' ' ')"
echo "===SEC:HW==="
grep -E 'MemAvailable|MemTotal' /proc/meminfo 2>/dev/null || true
echo "---DF---"
df -m /overlay 2>/dev/null || df -m / 2>/dev/null || true
echo "---MOUNTS---"
grep -E 'squashfs|jffs2|ubifs|overlay' /proc/mounts 2>/dev/null || true
echo "===SEC:REBOOT==="
[ -f /var/run/reboot-required ] && echo "YES" || echo "NO"
echo "===SEC:FP==="
stat -c %Y /var/lib/dpkg/status /lib/apk/db/installed /usr/lib/opkg/status /var/lib/rpm/Packages 2>/dev/null || true
echo "===SEC:PKGS==="
if command -v dpkg-query >/dev/null 2>&1; then
  echo "FMT:DPKG"
  dpkg-query -W -f='${Package}\t${source:Package}\t${Version}\n' 2>/dev/null || true
elif command -v apk >/dev/null 2>&1; then
  echo "FMT:APK"
  apk list -I 2>/dev/null || true
elif command -v opkg >/dev/null 2>&1; then
  echo "FMT:OPKG"
  opkg list-installed 2>/dev/null || true
elif command -v rpm >/dev/null 2>&1; then
  echo "FMT:RPM"
  rpm -qa --qf '%{NAME}\t%{SOURCERPM}\t%{VERSION}-%{RELEASE}\n' 2>/dev/null || true
elif command -v pacman >/dev/null 2>&1; then
  echo "FMT:PACMAN"
  pacman -Q 2>/dev/null || true
fi
echo "===SEC:BINS==="
for b in sing-box caddy nginx docker curl singctl node python3 git mihomo xray; do
  if command -v "$b" >/dev/null 2>&1; then
    v=$("$b" version 2>/dev/null || "$b" --version 2>/dev/null || "$b" -v 2>&1 | head -n 1)
    v=$(printf '%s' "$v" | head -n 1)
    echo "__BIN__:${b}:${v}"
  fi
done
echo "===SEC:DOCKER==="
if command -v docker >/dev/null 2>&1; then
  docker ps --format '{{.Names}}\t{{.Image}}' 2>/dev/null || true
fi
echo "===SEC:MITIGATIONS==="
if [ -d /etc/sentinel/remediations ]; then
  for f in /etc/sentinel/remediations/*.applied; do
    [ -f "$f" ] && echo "__APPLIED__:$(basename "$f" .applied)"
  done
  for f in /etc/sentinel/remediations/*_mitigate.sh; do
    [ -f "$f" ] || continue
    b=$(basename "$f" _mitigate.sh | tr '_' '-')
    if grep -q "APPLIED: $b" /etc/sentinel/remediations/history.log 2>/dev/null; then
      echo "__APPLIED__:$b"
    fi
  done
fi
`

const fastRemoteFingerprintCmd = `stat -c %Y /var/lib/dpkg/status /lib/apk/db/installed /usr/lib/opkg/status /var/lib/rpm/Packages 2>/dev/null; uname -r 2>/dev/null; [ -f /var/run/reboot-required ] && echo R1 || echo R0; ls -1 /etc/sentinel/remediations/*.applied 2>/dev/null || true`

// ProgressFunc receives per-host live collection updates for TTY spinners and MyGo GUI.
type ProgressFunc func(host model.HostTarget, stage string, inv *model.HostInventory)

// CollectOptions configures cluster inventory discovery.
type CollectOptions struct {
	Config      config.Config
	Mem         *store.Store
	Intel       *intel.Client
	UseCache    bool
	OnProgress  ProgressFunc
}

// CollectAll concurrently collects full inventories across all configured hosts (local + remote SSH).
func CollectAll(ctx context.Context, opts CollectOptions) []model.HostInventory {
	targets := opts.Config.ConfiguredHosts()
	workspaces := opts.Config.EffectiveWorkspaces()
	results := make([]model.HostInventory, len(targets))

	var wg sync.WaitGroup
	sem := make(chan struct{}, 6)

	for idx, target := range targets {
		wg.Add(1)
		go func(i int, t model.HostTarget) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				results[i] = model.HostInventory{Target: t, Error: "context canceled"}
				return
			}
			if opts.OnProgress != nil {
				opts.OnProgress(t, "probing", nil)
			}
			inv := CollectSingle(ctx, t, workspaces, opts)
			results[i] = inv
			if opts.OnProgress != nil {
				opts.OnProgress(t, "done", &inv)
			}
		}(idx, target)
	}
	wg.Wait()

	// Persist human-readable discovered_inventory.yaml snapshot
	saveDiscoveredSnapshot(results)
	return results
}

func saveDiscoveredSnapshot(list []model.HostInventory) {
	byName := make(map[string]model.HostInventory, len(list))
	for _, item := range list {
		byName[item.Target.Name] = item
	}
	raw, err := yaml.Marshal(byName)
	if err != nil {
		return
	}
	p := filepath.Join(config.StateDir(), "discovered_inventory.yaml")
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	_ = os.WriteFile(p, raw, 0o600)
}

// LoadDiscoveredInventories loads the full 5-layer discovered asset snapshots from disk for the Asset Explorer.
func LoadDiscoveredInventories() map[string]model.HostInventory {
	p := filepath.Join(config.StateDir(), "discovered_inventory.yaml")
	data, err := os.ReadFile(p)
	if err != nil {
		return nil
	}
	var out map[string]model.HostInventory
	if yaml.Unmarshal(data, &out) != nil {
		return nil
	}
	return out
}

// CollectSingle probes a single local or remote host, honoring split-TTL fingerprint cache.
func CollectSingle(ctx context.Context, target model.HostTarget, workspaces []string, opts CollectOptions) model.HostInventory {
	exec := transport.New(target)
	hostKey := target.EffectiveKey()

	if opts.UseCache && opts.Mem != nil {
		fp, lat := probeQuickFingerprint(ctx, exec, target)
		if fp != "" {
			if cached, hit, osSecFresh := opts.Mem.GetInventory(hostKey, fp); hit && cached != nil {
				cached.Target = target
				if target.IsLocal() {
					cached.LatencyMS = 0
				} else if lat > 0 {
					cached.LatencyMS = lat
				}
				if !osSecFresh {
					srcMap := make(map[string]string)
					for _, a := range cached.Assets {
						if a.Kind == "os" && a.SourcePackage != "" {
							srcMap[strings.ToLower(a.Name)] = a.SourcePackage
						}
					}
					cached.OSSecurity = ScanOSSecurity(ctx, exec, cached.OSContext, srcMap, opts.Intel)
					_ = opts.Mem.SaveInventory(hostKey, fp, *cached)
				}
				return *cached
			}
		}
	}

	var inv model.HostInventory
	if target.IsLocal() && runtime.GOOS == "darwin" {
		inv = collectDarwinLocalInventory(ctx, exec, target, workspaces, opts.Intel)
	} else if target.IsLocal() {
		inv = collectLinuxOrRemoteInventory(ctx, exec, target, workspaces, opts.Intel)
	} else {
		inv = collectLinuxOrRemoteInventory(ctx, exec, target, nil, opts.Intel)
	}

	if inv.Error == "" && opts.UseCache && opts.Mem != nil && inv.Fingerprint != "" {
		_ = opts.Mem.SaveInventory(hostKey, inv.Fingerprint, inv)
	}
	return inv
}

func probeQuickFingerprint(ctx context.Context, exec transport.Executor, target model.HostTarget) (string, int64) {
	if target.IsLocal() && runtime.GOOS == "darwin" {
		res, err := exec.Run(ctx, "sw_vers -productVersion 2>/dev/null; uname -r 2>/dev/null; stat -f %m /Library/Preferences/com.apple.SoftwareUpdate.plist /opt/homebrew/var/homebrew/locks /usr/local/var/homebrew/locks 2>/dev/null || true", 4*time.Second)
		if err != nil || res.Code != 0 {
			return "", 0
		}
		return hashShort(res.Stdout), res.LatencyMS
	}
	res, err := exec.Run(ctx, fastRemoteFingerprintCmd, 6*time.Second)
	if err != nil || res.Code != 0 || res.Stdout == "" {
		return "", 0
	}
	return hashShort(res.Stdout), res.LatencyMS
}

func hashShort(s string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(s)))
	return hex.EncodeToString(sum[:])[:24]
}

func collectDarwinLocalInventory(ctx context.Context, exec transport.Executor, target model.HostTarget, workspaces []string, intelCli *intel.Client) model.HostInventory {
	start := time.Now()
	inv := model.HostInventory{
		Target:             target,
		Packages:           make(map[string]string),
		AppliedMitigations: make(map[string]string),
		DockerContainers:   make(map[string]string),
		CollectedAt:        start,
	}

	// L1: OS & Firmware Metadata (macOS release, kernel, XProtect)
	probeCmd := `
echo "SW_VERS:$(sw_vers -productVersion 2>/dev/null)"
echo "ARCH:$(uname -m 2>/dev/null)"
echo "KRN:$(uname -r 2>/dev/null)"
echo "XPROTECT:$(plutil -extract CFBundleShortVersionString raw -o - /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist 2>/dev/null)"
echo "BREW:$(command -v brew 2>/dev/null)"
`
	res, err := exec.Run(ctx, probeCmd, 8*time.Second)
	if err != nil {
		inv.Error = err.Error()
		return inv
	}

	osVer, arch, krn, xprotectVer, hasBrew := "", runtime.GOARCH, "", "", false
	for _, line := range strings.Split(res.Stdout, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "SW_VERS:"):
			osVer = strings.TrimSpace(strings.TrimPrefix(line, "SW_VERS:"))
		case strings.HasPrefix(line, "ARCH:"):
			if v := strings.TrimSpace(strings.TrimPrefix(line, "ARCH:")); v != "" {
				arch = v
			}
		case strings.HasPrefix(line, "KRN:"):
			krn = strings.TrimSpace(strings.TrimPrefix(line, "KRN:"))
		case strings.HasPrefix(line, "XPROTECT:"):
			xprotectVer = strings.TrimSpace(strings.TrimPrefix(line, "XPROTECT:"))
		case strings.HasPrefix(line, "BREW:"):
			hasBrew = strings.TrimSpace(strings.TrimPrefix(line, "BREW:")) != ""
		}
	}

	pm := "apple-su"
	if hasBrew {
		pm = "brew"
	}
	fwDesc := "pfctl / Application Firewall"
	if xprotectVer != "" {
		fwDesc += " · XProtect " + xprotectVer
		inv.Packages["xprotect"] = xprotectVer
	}
	inv.OSContext = model.OSContext{
		OSFamily:       "darwin",
		DistroID:       "macos",
		DistroVersion:  osVer,
		OSPretty:       strings.TrimSpace("macOS " + osVer),
		Arch:           arch,
		KernelRelease:  krn,
		Shell:          os.Getenv("SHELL"),
		InitSystem:     "launchd",
		Firewall:       fwDesc,
		PkgMgr:         pm,
		MemAvailableMB: 4096,
		OverlayAvailMB: 10240,
		IsRoot:         os.Geteuid() == 0,
	}

	// L2 + L3 + L4 + L5 + OS Security: Run concurrently, with non-blocking TCC guard on workspace directories!
	baseOSCtx := inv.OSContext
	var (
		layerWG   sync.WaitGroup
		wsRes     lockfile.WorkspaceScanResult
		brewInv   model.HostInventory
		dockerInv model.HostInventory
		toolInv   model.HostInventory
		osSecRep  model.OSSecurityReport
		fp        string
	)
	brewInv.Target, brewInv.Packages = target, make(map[string]string)
	dockerInv.Target, dockerInv.Packages = target, make(map[string]string)
	toolInv.Target, toolInv.Packages = target, make(map[string]string)

	layerWG.Add(6)
	go func() {
		defer layerWG.Done()
		wsRes, _ = scanWorkspacesWithTimeout(ctx, workspaces, 15*time.Second)
	}()
	go func() {
		defer layerWG.Done()
		ProbeHomebrewAndAppsLayer(ctx, exec, &brewInv)
	}()
	go func() {
		defer layerWG.Done()
		ProbeContainerLayer(ctx, exec, &dockerInv)
	}()
	go func() {
		defer layerWG.Done()
		ProbeGlobalToolchainsLayer(ctx, exec, &toolInv)
	}()
	go func() {
		defer layerWG.Done()
		osSecRep = ScanOSSecurity(ctx, exec, baseOSCtx, nil, intelCli)
	}()
	go func() {
		defer layerWG.Done()
		fp, _ = probeQuickFingerprint(ctx, exec, target)
	}()
	layerWG.Wait()

	inv.EcosystemSummary = wsRes.Summary
	inv.EcosystemSummary.Kernel = "Darwin " + krn
	inv.OrphanedVenvs = wsRes.OrphanedVenvs

	mergeLayerInventory(&inv, &brewInv)
	mergeLayerInventory(&inv, &dockerInv)
	mergeLayerInventory(&inv, &toolInv)

	inv.Assets = append(inv.Assets, wsRes.Assets...)
	for _, a := range wsRes.Assets {
		low := strings.ToLower(a.Name)
		if _, exists := inv.Packages[low]; !exists {
			inv.Packages[low] = a.Version
		}
	}

	readLocalAppliedMitigations("/etc/sentinel/remediations", inv.AppliedMitigations)

	inv.OSSecurity = osSecRep
	inv.OSContext = inv.OSSecurity.OSContext
	inv.LatencyMS = 0
	inv.ScanDurationMS = time.Since(start).Milliseconds()
	inv.Fingerprint = fp
	return inv
}

// scanWorkspacesWithTimeout protects background scheduled scans from hanging indefinitely if macOS TCC
// prompts for folder permission (e.g. ~/Documents after an ad-hoc binary update while screen is locked).
func scanWorkspacesWithTimeout(ctx context.Context, workspaces []string, timeout time.Duration) (lockfile.WorkspaceScanResult, bool) {
	if len(workspaces) == 0 {
		return lockfile.WorkspaceScanResult{}, true
	}
	ch := make(chan lockfile.WorkspaceScanResult, 1)
	go func() {
		ch <- lockfile.ScanWorkspaces(workspaces)
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case res := <-ch:
		return res, true
	case <-ctx.Done():
		return lockfile.WorkspaceScanResult{}, false
	case <-timer.C:
		return lockfile.WorkspaceScanResult{}, false
	}
}

func mergeLayerInventory(dst *model.HostInventory, src *model.HostInventory) {
	for k, v := range src.Packages {
		dst.Packages[k] = v
	}
	for k, v := range src.DockerContainers {
		dst.DockerContainers[k] = v
	}
	dst.Assets = append(dst.Assets, src.Assets...)
	dst.EcosystemSummary.HomebrewFormulae += src.EcosystemSummary.HomebrewFormulae
	dst.EcosystemSummary.HomebrewCasks += src.EcosystemSummary.HomebrewCasks
	dst.EcosystemSummary.MacApps += src.EcosystemSummary.MacApps
	dst.EcosystemSummary.DockerContainers += src.EcosystemSummary.DockerContainers
	dst.EcosystemSummary.DockerImages += src.EcosystemSummary.DockerImages
	if src.EcosystemSummary.DockerVersion != "" {
		dst.EcosystemSummary.DockerVersion = src.EcosystemSummary.DockerVersion
	}
	dst.EcosystemSummary.GlobalTools += src.EcosystemSummary.GlobalTools
	for _, tc := range src.EcosystemSummary.Toolchains {
		dst.EcosystemSummary.Toolchains = appendUniqueStr(dst.EcosystemSummary.Toolchains, tc)
	}
}

func collectLinuxOrRemoteInventory(ctx context.Context, exec transport.Executor, target model.HostTarget, workspaces []string, intelCli *intel.Client) model.HostInventory {
	start := time.Now()
	inv := model.HostInventory{
		Target:             target,
		Packages:           make(map[string]string),
		AppliedMitigations: make(map[string]string),
		DockerContainers:   make(map[string]string),
		CollectedAt:        start,
	}

	res, err := exec.RunStdin(ctx, "sh -s", mergedLinuxProbeScript, 20*time.Second)
	if target.IsLocal() {
		inv.LatencyMS = 0
	} else {
		inv.LatencyMS = res.LatencyMS
	}
	if err != nil {
		inv.ScanDurationMS = time.Since(start).Milliseconds()
		inv.Error = fmt.Sprintf("SSH 连接或探针超时: %v (%s)", err, res.Stderr)
		return inv
	}
	if res.Code != 0 && res.Stdout == "" {
		inv.ScanDurationMS = time.Since(start).Milliseconds()
		inv.Error = fmt.Sprintf("SSH 认证或连接失败 (code %d): %s", res.Code, res.Stderr)
		return inv
	}

	// Measure pure SSH round-trip latency over the already-open ControlMaster socket
	// instead of conflating network RTT with full remote inventory script duration.
	if !target.IsLocal() {
		if pingRes, pingErr := exec.Run(ctx, ":", 3*time.Second); pingErr == nil && pingRes.Code == 0 && pingRes.LatencyMS > 0 {
			inv.LatencyMS = pingRes.LatencyMS
		}
	}

	srcPkgMap := parseMergedLinuxProbeOutput(res.Stdout, target, &inv)

	// Run any custom_commands specified on target
	for name, cmdStr := range target.CustomCommands {
		if r, err := exec.Run(ctx, cmdStr, 8*time.Second); err == nil && r.Code == 0 && r.Stdout != "" {
			clean := cleanVersionString(r.Stdout)
			inv.Packages[strings.ToLower(name)] = clean
			inv.Assets = append(inv.Assets, model.AssetItem{
				Ecosystem: model.EcoBinary,
				Name:      strings.ToLower(name),
				Version:   clean,
				Location:  "custom",
				Kind:      "binary",
			})
		}
	}

	// If local Linux machine, also scan workspaces!
	if target.IsLocal() && len(workspaces) > 0 {
		wsRes, _ := scanWorkspacesWithTimeout(ctx, workspaces, 15*time.Second)
		wsRes.Summary.DockerContainers = inv.EcosystemSummary.DockerContainers
		wsRes.Summary.Kernel = inv.EcosystemSummary.Kernel
		inv.EcosystemSummary = wsRes.Summary
		inv.OrphanedVenvs = wsRes.OrphanedVenvs
		inv.Assets = append(inv.Assets, wsRes.Assets...)
	}

	// OS security dry-run over already-open SSH ControlMaster socket!
	inv.OSSecurity = ScanOSSecurity(ctx, exec, inv.OSContext, srcPkgMap, intelCli)
	inv.ScanDurationMS = time.Since(start).Milliseconds()
	return inv
}

func parseMergedLinuxProbeOutput(stdout string, target model.HostTarget, inv *model.HostInventory) map[string]string {
	markers := map[string]string{
		"===SEC:OS_RELEASE===":  "os_release",
		"===SEC:ENV===":         "env",
		"===SEC:HW===":          "hw",
		"===SEC:REBOOT===":      "reboot",
		"===SEC:FP===":          "fp",
		"===SEC:PKGS===":        "pkgs",
		"===SEC:BINS===":        "bins",
		"===SEC:DOCKER===":      "docker",
		"===SEC:MITIGATIONS===": "mitigations",
	}
	sec := splitSections(stdout, markers)
	osDict := parseKeyValRelease(sec["os_release"])

	distroID := strings.ToLower(firstNonEmpty(osDict["ID"], osDict["DISTRIB_ID"], target.OSType))
	distroVer := firstNonEmpty(osDict["VERSION_ID"], osDict["DISTRIB_RELEASE"])
	codename := osDict["VERSION_CODENAME"]
	pretty := firstNonEmpty(osDict["PRETTY_NAME"], osDict["DISTRIB_DESCRIPTION"])

	arch := "x86_64"
	procVer := ""
	shellInfo := "/bin/sh"
	initSys := "init"
	fwStack := ""
	pmBins := ""
	isRoot := false
	canSudo := false

	for _, line := range strings.Split(sec["env"], "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "UNAME:"):
			parts := strings.Fields(strings.TrimPrefix(line, "UNAME:"))
			if len(parts) > 0 {
				arch = parts[len(parts)-1]
			}
		case strings.HasPrefix(line, "PROC_VER:"):
			procVer = strings.TrimSpace(strings.TrimPrefix(line, "PROC_VER:"))
		case strings.HasPrefix(line, "SUDO:"):
			v := strings.TrimSpace(strings.TrimPrefix(line, "SUDO:"))
			if v == "ROOT" {
				isRoot = true
				canSudo = true
			} else if v == "YES" {
				canSudo = true
			}
		case strings.HasPrefix(line, "SHELL:"):
			parts := strings.Split(strings.TrimPrefix(line, "SHELL:"), "|")
			curSh, binSh, hasBash := "", "", ""
			if len(parts) > 0 {
				curSh = strings.TrimSpace(parts[0])
			}
			if len(parts) > 1 {
				binSh = strings.TrimSpace(parts[1])
			}
			if len(parts) > 2 {
				hasBash = strings.TrimSpace(parts[2])
			}
			switch {
			case strings.Contains(strings.ToLower(binSh), "busybox"):
				shellInfo = "BusyBox ash (/bin/sh -> busybox, bash unavailable)"
			case hasBash != "":
				shellInfo = fmt.Sprintf("Bash (%s, /bin/sh -> %s)", hasBash, firstNonEmpty(binSh, "sh"))
			default:
				shellInfo = firstNonEmpty(curSh, "/bin/sh")
			}
		case strings.HasPrefix(line, "INIT:"):
			ib := strings.TrimSpace(strings.TrimPrefix(line, "INIT:"))
			switch {
			case strings.Contains(ib, "systemctl"):
				initSys = "systemd (systemctl)"
			case strings.Contains(ib, "procd"):
				initSys = "procd (OpenWrt)"
			case ib != "":
				initSys = ib
			}
		case strings.HasPrefix(line, "FW:"):
			fw := strings.TrimSpace(strings.TrimPrefix(line, "FW:"))
			fw = strings.NewReplacer("/usr/sbin/", "", "/sbin/", "", "/usr/bin/", "").Replace(fw)
			fwStack = strings.TrimSpace(fw)
		case strings.HasPrefix(line, "PM:"):
			pmBins = strings.TrimSpace(strings.TrimPrefix(line, "PM:"))
		}
	}

	osRelLower := strings.ToLower(sec["os_release"])
	osFamily := "linux"
	switch {
	case strings.Contains(distroID, "openwrt") || strings.Contains(osRelLower, "openwrt") || strings.Contains(osRelLower, "immortalwrt"):
		osFamily = "openwrt"
		distroID = "openwrt"
	case strings.Contains(distroID, "ubuntu"):
		osFamily = "ubuntu"
		distroID = "ubuntu"
	case strings.Contains(distroID, "debian"):
		osFamily = "debian"
		distroID = "debian"
	case strings.Contains(distroID, "alpine") || strings.Contains(osRelLower, "alpine"):
		osFamily = "alpine"
		distroID = "alpine"
	case strings.Contains(distroID, "rocky") || strings.Contains(distroID, "almalinux") || strings.Contains(distroID, "rhel") || strings.Contains(distroID, "centos") || strings.Contains(distroID, "fedora"):
		osFamily = "rhel"
	case strings.Contains(distroID, "arch"):
		osFamily = "arch"
		distroID = "arch"
	}

	pkgMgr := strings.ToLower(target.PackageManager)
	if pkgMgr == "" {
		switch {
		case osFamily == "openwrt":
			if strings.Contains(pmBins, "apk") {
				pkgMgr = "apk"
			} else if strings.Contains(pmBins, "opkg") {
				pkgMgr = "opkg"
			} else {
				pkgMgr = "static"
			}
		case osFamily == "debian" || osFamily == "ubuntu":
			pkgMgr = "apt"
		case osFamily == "alpine":
			pkgMgr = "apk"
		case osFamily == "rhel":
			if strings.Contains(pmBins, "dnf") {
				pkgMgr = "dnf"
			} else if strings.Contains(pmBins, "yum") {
				pkgMgr = "yum"
			} else {
				pkgMgr = "rpm"
			}
		case osFamily == "arch":
			pkgMgr = "pacman"
		default:
			pkgMgr = "apt"
		}
	}

	// Hardware limits & OpenWrt flash/memory anti-brick guard
	memAvailMB, memTotalMB := 1024.0, 1024.0
	overlayAvailMB, overlayTotalMB := 1024.0, 1024.0
	isFlash := false
	hwParts := strings.Split(sec["hw"], "---DF---")
	if len(hwParts) > 0 {
		for _, l := range strings.Split(hwParts[0], "\n") {
			if strings.HasPrefix(l, "MemTotal:") {
				if m := memKBRe.FindStringSubmatch(l); m != nil {
					v, _ := strconv.ParseFloat(m[1], 64)
					memTotalMB = v / 1024.0
				}
			} else if strings.HasPrefix(l, "MemAvailable:") {
				if m := memKBRe.FindStringSubmatch(l); m != nil {
					v, _ := strconv.ParseFloat(m[1], 64)
					memAvailMB = v / 1024.0
				}
			}
		}
	}
	if len(hwParts) > 1 {
		dfAndMount := strings.Split(hwParts[1], "---MOUNTS---")
		for _, l := range strings.Split(dfAndMount[0], "\n") {
			f := strings.Fields(l)
			if len(f) >= 4 {
				if tot, err := strconv.ParseFloat(f[1], 64); err == nil {
					if av, err2 := strconv.ParseFloat(f[3], 64); err2 == nil {
						overlayTotalMB = tot
						overlayAvailMB = av
					}
				}
			}
		}
		if len(dfAndMount) > 1 {
			ml := strings.ToLower(dfAndMount[1])
			if strings.Contains(ml, "squashfs") || strings.Contains(ml, "jffs2") || strings.Contains(ml, "ubifs") {
				isFlash = true
			}
		}
	}

	lockdown := false
	lockReason := ""
	if osFamily == "openwrt" {
		if memAvailMB < 32.0 {
			lockdown = true
			lockReason = fmt.Sprintf("可用内存极低 (%.1fMB < 32MB)，防止触发系统 OOM 断网，已锁定在线更新", memAvailMB)
		} else if isFlash && overlayAvailMB < 30.0 {
			lockdown = true
			lockReason = fmt.Sprintf("Flash /overlay 剩余容量不足 (%.1fMB < 30MB)，防写爆变砖已锁定在线更新", overlayAvailMB)
		}
	}

	// Extract running Linux kernel version
	kVer := ""
	if m := debKernelRe.FindStringSubmatch(procVer); m != nil {
		kVer = m[1]
	} else if m := linKernelRe.FindStringSubmatch(procVer); m != nil {
		kVer = m[1]
	} else if fields := strings.Fields(procVer); len(fields) > 0 {
		if m := semNumRe.FindStringSubmatch(fields[0]); m != nil {
			kVer = m[1]
		} else {
			kVer = fields[0]
		}
	}

	rebootReq := strings.Contains(sec["reboot"], "YES")
	if pretty == "" {
		pretty = strings.TrimSpace(strings.ToUpper(distroID[:1]) + distroID[1:] + " " + distroVer)
	}

	inv.OSContext = model.OSContext{
		OSFamily:       osFamily,
		DistroID:       distroID,
		DistroVersion:  distroVer,
		DistroCodename: codename,
		OSPretty:       pretty,
		Arch:           arch,
		KernelRelease:  kVer,
		Shell:          shellInfo,
		InitSystem:     initSys,
		Firewall:       firstNonEmpty(fwStack, "iptables / nftables"),
		PkgMgr:         pkgMgr,
		MemAvailableMB: memAvailMB,
		MemTotalMB:     memTotalMB,
		OverlayAvailMB: overlayAvailMB,
		OverlayTotalMB: overlayTotalMB,
		IsFlashStorage: isFlash,
		LockdownMode:   lockdown,
		LockdownReason: lockReason,
		RebootRequired: rebootReq,
		IsRoot:         isRoot,
		CanSudoNoPass:  canSudo,
	}

	if kVer != "" {
		inv.Packages["linux"] = kVer
		inv.Packages["kernel"] = kVer
		inv.EcosystemSummary.Kernel = "Linux " + kVer
		inv.Assets = append(inv.Assets, model.AssetItem{
			Ecosystem: model.EcoLinux,
			Name:      "linux",
			Version:   kVer,
			Location:  "kernel",
			Kind:      "kernel",
		})
	}

	// Parse system packages
	osvDistroEco := intel.MapOSContextToOSVEcosystem(inv.OSContext)
	srcPkgMap := make(map[string]string)
	pkgLines := strings.Split(strings.TrimSpace(sec["pkgs"]), "\n")
	pkgFmt := ""
	for _, rawLine := range pkgLines {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "FMT:") {
			pkgFmt = strings.TrimPrefix(line, "FMT:")
			continue
		}
		switch pkgFmt {
		case "DPKG":
			parts := strings.Split(line, "\t")
			if len(parts) >= 3 {
				binName := strings.ToLower(strings.TrimSpace(parts[0]))
				srcName := strings.Fields(strings.TrimSpace(parts[1]))
				ver := strings.TrimSpace(parts[2])
				sPkg := binName
				if len(srcName) > 0 && srcName[0] != "" {
					sPkg = strings.ToLower(srcName[0])
				}
				srcPkgMap[binName] = sPkg
				inv.Packages[binName] = ver
				inv.Assets = append(inv.Assets, model.AssetItem{
					Ecosystem:     osvDistroEco,
					Name:          binName,
					SourcePackage: sPkg,
					Version:       ver,
					Location:      "dpkg",
					Kind:          "os",
				})
			}
		case "APK":
			fields := strings.Fields(line)
			if len(fields) > 0 {
				if m := apkPkgLineRe.FindStringSubmatch(fields[0]); m != nil {
					name := strings.ToLower(m[1])
					ver := m[2]
					inv.Packages[name] = ver
					inv.Assets = append(inv.Assets, model.AssetItem{
						Ecosystem:     osvDistroEco,
						Name:          name,
						SourcePackage: name,
						Version:       ver,
						Location:      "apk",
						Kind:          "os",
					})
				}
			}
		case "OPKG":
			parts := strings.Split(line, " - ")
			if len(parts) >= 2 {
				name := strings.ToLower(strings.TrimSpace(parts[0]))
				ver := strings.TrimSpace(parts[1])
				inv.Packages[name] = ver
				inv.Assets = append(inv.Assets, model.AssetItem{
					Ecosystem:     "OpenWrt",
					Name:          name,
					SourcePackage: name,
					Version:       ver,
					Location:      "opkg",
					Kind:          "os",
				})
			}
		case "RPM":
			parts := strings.Split(line, "\t")
			if len(parts) >= 3 {
				name := strings.ToLower(strings.TrimSpace(parts[0]))
				ver := strings.TrimSpace(parts[2])
				inv.Packages[name] = ver
				inv.Assets = append(inv.Assets, model.AssetItem{
					Ecosystem:     osvDistroEco,
					Name:          name,
					SourcePackage: name,
					Version:       ver,
					Location:      "rpm",
					Kind:          "os",
				})
			}
		case "PACMAN":
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				name := strings.ToLower(fields[0])
				ver := fields[1]
				inv.Packages[name] = ver
				inv.Assets = append(inv.Assets, model.AssetItem{
					Ecosystem: "Arch Linux",
					Name:      name,
					Version:   ver,
					Location:  "pacman",
					Kind:      "os",
				})
			}
		}
	}

	// Parse standalone binaries
	for _, rawLine := range strings.Split(sec["bins"], "\n") {
		line := strings.TrimSpace(rawLine)
		if !strings.HasPrefix(line, "__BIN__:") {
			continue
		}
		parts := strings.SplitN(strings.TrimPrefix(line, "__BIN__:"), ":", 2)
		if len(parts) == 2 {
			bName := strings.ToLower(strings.TrimSpace(parts[0]))
			v := cleanVersionString(parts[1])
			if bName != "" && v != "" {
				inv.Packages[bName] = v
				inv.Assets = append(inv.Assets, model.AssetItem{
					Ecosystem: model.EcoBinary,
					Name:      bName,
					Version:   v,
					Location:  "binary",
					Kind:      "binary",
				})
			}
		}
	}

	// Parse Docker containers
	for _, rawLine := range strings.Split(sec["docker"], "\n") {
		parts := strings.Split(strings.TrimSpace(rawLine), "\t")
		if len(parts) == 2 {
			cName := strings.ToLower(strings.TrimSpace(parts[0]))
			cImg := strings.TrimSpace(parts[1])
			if cName != "" && cImg != "" {
				inv.DockerContainers[cName] = cImg
				inv.Packages[cName] = cImg
				inv.Assets = append(inv.Assets, model.AssetItem{
					Ecosystem: model.EcoDocker,
					Name:      cName,
					Version:   cImg,
					Location:  "docker:" + cName,
					Kind:      "container",
				})
			}
		}
	}
	inv.EcosystemSummary.DockerContainers = len(inv.DockerContainers)

	// Parse applied mitigations
	for _, rawLine := range strings.Split(sec["mitigations"], "\n") {
		line := strings.TrimSpace(rawLine)
		if strings.HasPrefix(line, "__APPLIED__:") {
			tok := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(strings.TrimPrefix(line, "__APPLIED__:")), "_", "-"))
			if tok != "" {
				inv.AppliedMitigations[tok] = "APPLIED"
			}
		}
	}

	// Compute deterministic fingerprint matching fastRemoteFingerprintCmd
	fpRaw := strings.TrimSpace(sec["fp"]) + "\n" + kVer + "\n" + sec["reboot"] + "\n" + sec["mitigations"]
	inv.Fingerprint = hashShort(fpRaw)
	return srcPkgMap
}

func readLocalAppliedMitigations(dir string, dst map[string]string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".applied") {
			cve := strings.TrimSuffix(e.Name(), ".applied")
			cve = strings.ToUpper(strings.ReplaceAll(cve, "_", "-"))
			dst[cve] = "APPLIED"
		}
	}
}

func cleanVersionString(raw string) string {
	s := ansiEscapeRe.ReplaceAllString(strings.TrimSpace(raw), "")
	if strings.Contains(s, "SingCtl v") {
		after := strings.Split(s, "SingCtl v")
		fields := strings.Fields(after[len(after)-1])
		if len(fields) > 0 {
			return fields[0]
		}
	}
	if m := semNumRe.FindStringSubmatch(s); m != nil {
		return m[1]
	}
	return s
}

func splitSections(text string, markers map[string]string) map[string]string {
	out := make(map[string]string)
	cur := "head"
	var buf strings.Builder
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if nextKey, isMarker := markers[trimmed]; isMarker {
			out[cur] = strings.TrimSpace(buf.String())
			buf.Reset()
			cur = nextKey
			continue
		}
		buf.WriteString(line)
		buf.WriteByte('\n')
	}
	out[cur] = strings.TrimSpace(buf.String())
	return out
}

func parseKeyValRelease(text string) map[string]string {
	m := make(map[string]string)
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if idx := strings.IndexByte(line, '='); idx > 0 {
			k := strings.TrimSpace(line[:idx])
			v := strings.Trim(strings.TrimSpace(line[idx+1:]), "\"'")
			if _, exists := m[k]; !exists {
				m[k] = v
			}
		}
	}
	return m
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
