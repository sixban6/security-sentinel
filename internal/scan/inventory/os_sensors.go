package inventory

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/sixban6/security-sentinel/internal/scan/intel"
	"github.com/sixban6/security-sentinel/internal/infra/model"
	"github.com/sixban6/security-sentinel/internal/infra/transport"
)

var (
	securityRepoRe = regexp.MustCompile(`(?i)(debian-security|.*-security|security\.debian\.org|security\.ubuntu\.com)`)
	aptInstRe      = regexp.MustCompile(`^Inst\s+(\S+)\s+(?:\[([^\]]+)\]\s+)?\((\S+)\s+([^\s\)]+)(?:\s+\[[^\]]*\])?\)`)
	apkUpgradable  = regexp.MustCompile(`^([A-Za-z0-9_\-]+?)-(\d+[\.\d\w\-\~]*)\s+.*\[upgradable from:\s*([A-Za-z0-9_\-]+?)-(\d+[\.\d\w\-\~]*)\]`)
	dnfPkgSplitRe  = regexp.MustCompile(`^([A-Za-z0-9_\-]+?)(?:-\d+:|-\d+[\.\d])`)
)

var openwrtSecurityWhitelist = map[string]string{
	"dnsmasq":            "/etc/init.d/dnsmasq reload",
	"dnsmasq-full":       "/etc/init.d/dnsmasq reload",
	"dropbear":           "/etc/init.d/dropbear reload",
	"openssl":            "",
	"libopenssl":         "",
	"libopenssl3":        "",
	"mbedtls":            "",
	"libmbedtls":         "",
	"libustream-ssl":     "",
	"libustream-mbedtls": "",
	"libustream-openssl": "",
	"curl":               "",
	"libcurl":            "",
	"uhttpd":             "/etc/init.d/uhttpd reload",
	"nginx":              "/etc/init.d/nginx reload",
	"firewall4":          "/etc/init.d/firewall reload",
	"nftables":           "/etc/init.d/firewall reload",
	"ppp":                "",
	"wireguard-tools":    "",
	"ca-certificates":    "",
	"sing-box":           "/etc/init.d/sing-box reload",
}

// Foundational network, crypto, container, database, and system tools on macOS Homebrew
// (excludes breaking major language compiler upgrades like python@*, node, go unless user runs brew upgrade).
var darwinSafeSecurityWhitelist = map[string]bool{
	"openssl": true, "openssl@3": true, "openssl@1.1": true, "libressl": true,
	"curl": true, "wget": true, "ca-certificates": true, "gnupg": true,
	"openssh": true, "libssh2": true, "nghttp2": true, "git": true, "git-lfs": true,
	"nginx": true, "caddy": true, "haproxy": true, "traefik": true,
	"redis": true, "postgresql": true, "postgresql@16": true, "postgresql@15": true, "mariadb": true, "sqlite": true,
	"ffmpeg": true, "imagemagick": true, "libxml2": true, "xz": true, "zstd": true,
	"jq": true, "vim": true, "neovim": true, "tmux": true,
	"colima": true, "podman": true, "lima": true, "qemu": true,
	"wireguard-tools": true, "dnsmasq": true, "unbound": true, "wstunnel": true, "cloudflared": true,
}

// ScanOSSecurity executes read-only OS update simulation, enriches CVEs via OSV, and builds a safe RemediationPlan.
func ScanOSSecurity(ctx context.Context, exec transport.Executor, osCtx model.OSContext, srcPkgMap map[string]string, intelCli *intel.Client) model.OSSecurityReport {
	report := model.OSSecurityReport{
		OSContext: osCtx,
	}

	var updates []model.OSSecurityUpdate
	switch {
	case osCtx.OSFamily == "openwrt" || osCtx.OSFamily == "alpine":
		updates = checkOpenWrtOrAPKUpdates(ctx, exec, osCtx)
	case osCtx.OSFamily == "debian" || osCtx.OSFamily == "ubuntu" || osCtx.PkgMgr == "apt":
		updates = checkAptSecurityUpdates(ctx, exec, osCtx, srcPkgMap)
	case osCtx.OSFamily == "rhel" || osCtx.PkgMgr == "dnf" || osCtx.PkgMgr == "yum":
		updates = checkDnfSecurityUpdates(ctx, exec, osCtx)
	case osCtx.OSFamily == "darwin":
		updates = checkDarwinSecurityUpdates(ctx, exec, &osCtx)
		report.OSContext = osCtx
	}

	// Enrich CVE IDs and CVSS severity via Google OSV batch API
	eco := intel.MapOSContextToOSVEcosystem(osCtx)
	if len(updates) > 0 && eco != "" && intelCli != nil {
		var queries []intel.OSVQuery
		for _, u := range updates {
			src := u.SourcePackage
			if src == "" {
				src = u.Package
			}
			queries = append(queries, intel.OSVQuery{
				Ecosystem: eco,
				Name:      src,
				Version:   u.InstalledVersion,
			})
		}
		hits := intelCli.QueryOSVAssets(ctx, queries)
		for i := range updates {
			src := updates[i].SourcePackage
			if src == "" {
				src = updates[i].Package
			}
			qk := intel.QueryKey(eco, src, updates[i].InstalledVersion)
			advs := hits[qk]
			if len(advs) == 0 {
				continue
			}
			var allCVEs []string
			seenCVE := make(map[string]bool)
			topSev := updates[i].Severity
			var topCVSS float64
			bestSummary := ""

			for _, adv := range advs {
				id := adv.DisplayID()
				if id != "" && !seenCVE[id] {
					seenCVE[id] = true
					allCVEs = append(allCVEs, id)
				}
				if adv.CVSS > topCVSS {
					topCVSS = adv.CVSS
				}
				if adv.Severity == "CRITICAL" {
					topSev = "CRITICAL"
				}
				if bestSummary == "" && adv.Summary != "" {
					bestSummary = adv.Summary
				}
			}
			if len(allCVEs) > 0 {
				updates[i].CVEID = allCVEs[0]
				updates[i].AllCVEs = allCVEs
			}
			updates[i].Severity = topSev
			updates[i].CVSS = topCVSS
			if bestSummary != "" {
				updates[i].Summary = fmt.Sprintf("%s (修复版本: %s)", bestSummary, updates[i].CandidateVersion)
			}
		}
	}

	report.Updates = updates
	report.HasVulnerabilities = len(updates) > 0
	report.RemediationPlan = buildOSRemediationPlan(updates, osCtx)
	return report
}

func checkAptSecurityUpdates(ctx context.Context, exec transport.Executor, osCtx model.OSContext, srcPkgMap map[string]string) []model.OSSecurityUpdate {
	// Best-effort fast index refresh (3s HTTP timeout, closed fds so mux never blocks)
	syncCmd := "apt-get -o Acquire::http::Timeout=3 -o Acquire::https::Timeout=3 -o Dir::Etc::sourcelist='sources.list' -o Dir::Etc::sourceparts='' update -qq </dev/null >/dev/null 2>&1 || true"
	if privCmd, ok := transport.WrapPrivileged(syncCmd, osCtx); ok {
		_, _ = exec.Run(ctx, privCmd, 5*time.Second)
	}

	simCmd := "apt-get -s dist-upgrade 2>/dev/null || apt-get --just-print upgrade 2>/dev/null"
	res, err := exec.Run(ctx, simCmd, 12*time.Second)
	if err != nil || res.Code != 0 || res.Stdout == "" {
		return nil
	}

	var updates []model.OSSecurityUpdate
	for _, rawLine := range strings.Split(res.Stdout, "\n") {
		line := strings.TrimSpace(rawLine)
		if !strings.HasPrefix(line, "Inst ") {
			continue
		}
		m := aptInstRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		pkgName, instVer, candVer, repoOrigin := m[1], m[2], m[3], m[4]
		if instVer == "" {
			instVer = "unknown"
		}
		if !securityRepoRe.MatchString(repoOrigin) {
			continue
		}
		srcName := srcPkgMap[strings.ToLower(pkgName)]
		if srcName == "" {
			srcName = pkgName
		}
		isKernel := strings.HasPrefix(pkgName, "linux-image-") || strings.HasPrefix(pkgName, "linux-modules-")
		updates = append(updates, model.OSSecurityUpdate{
			Package:          pkgName,
			SourcePackage:    srcName,
			InstalledVersion: instVer,
			CandidateVersion: candVer,
			Repository:       repoOrigin,
			Severity:         "HIGH",
			Summary:          fmt.Sprintf("官方安全更新 (%s): %s -> %s", repoOrigin, instVer, candVer),
			RemediationCmd:   fmt.Sprintf("DEBIAN_FRONTEND=noninteractive apt-get install --no-remove --only-upgrade -y %s", pkgName),
			ServiceReloadCmd: "needrestart -b 2>/dev/null || true",
			IsKernel:         isKernel,
		})
	}
	return updates
}

func checkDnfSecurityUpdates(ctx context.Context, exec transport.Executor, osCtx model.OSContext) []model.OSSecurityUpdate {
	isDnf := osCtx.PkgMgr == "dnf"
	cmd := "yum --security check-update 2>/dev/null || yum updateinfo list sec 2>/dev/null"
	if isDnf {
		cmd = "dnf updateinfo list --security 2>/dev/null"
	}
	res, _ := exec.Run(ctx, cmd, 12*time.Second)
	if res.Code != 0 && res.Code != 100 {
		return nil
	}
	var updates []model.OSSecurityUpdate
	for _, rawLine := range strings.Split(res.Stdout, "\n") {
		parts := strings.Fields(strings.TrimSpace(rawLine))
		if len(parts) < 3 {
			continue
		}
		mid := strings.ToLower(parts[1])
		if !strings.Contains(mid, "sec") && !strings.Contains(mid, "cve") && !strings.Contains(mid, "rhsa") && !strings.Contains(mid, "alsa") && !strings.Contains(mid, "rlsa") {
			continue
		}
		advID := parts[0]
		pkgRaw := parts[len(parts)-1]
		pkgName := pkgRaw
		if m := dnfPkgSplitRe.FindStringSubmatch(pkgRaw); m != nil {
			pkgName = m[1]
		}
		cve := ""
		if strings.HasPrefix(advID, "CVE-") {
			cve = advID
		}
		remCmd := "yum update-minimal --security -y"
		if isDnf {
			remCmd = "dnf upgrade-minimal --security -y"
		}
		updates = append(updates, model.OSSecurityUpdate{
			Package:          pkgName,
			SourcePackage:    pkgName,
			InstalledVersion: "unknown",
			CandidateVersion: pkgRaw,
			Repository:       "updateinfo",
			CVEID:            cve,
			Severity:         "HIGH",
			Summary:          fmt.Sprintf("官方安全公告 (%s): 建议应用最小化安全修补", advID),
			RemediationCmd:   remCmd,
			ServiceReloadCmd: "systemctl daemon-reload",
			IsKernel:         strings.HasPrefix(pkgName, "kernel"),
		})
	}
	return updates
}

func checkOpenWrtOrAPKUpdates(ctx context.Context, exec transport.Executor, osCtx model.OSContext) []model.OSSecurityUpdate {
	var updates []model.OSSecurityUpdate

	if osCtx.PkgMgr == "apk" {
		if osCtx.MemAvailableMB >= 32.0 {
			if priv, ok := transport.WrapPrivileged("apk update 2>/dev/null || true", osCtx); ok {
				_, _ = exec.Run(ctx, priv, 8*time.Second)
			}
		}
		res, err := exec.Run(ctx, "apk list --upgradable 2>/dev/null", 10*time.Second)
		if err != nil || res.Code != 0 {
			return nil
		}
		for _, rawLine := range strings.Split(res.Stdout, "\n") {
			m := apkUpgradable.FindStringSubmatch(strings.TrimSpace(rawLine))
			if m == nil {
				continue
			}
			pkgName := strings.ToLower(m[1])
			candVer := m[2]
			instVer := m[4]
			if strings.HasPrefix(pkgName, "kmod-") {
				continue
			}
			reloadCmd, allowed := openwrtSecurityWhitelist[pkgName]
			if osCtx.OSFamily == "openwrt" && !allowed {
				continue
			}
			remCmd := "apk add --upgrade " + pkgName
			lockWarn := ""
			if osCtx.LockdownMode {
				remCmd = ""
				lockWarn = osCtx.LockdownReason
			}
			updates = append(updates, model.OSSecurityUpdate{
				Package:          pkgName,
				SourcePackage:    pkgName,
				InstalledVersion: instVer,
				CandidateVersion: candVer,
				Repository:       osCtx.OSFamily + "-apk",
				Severity:         "HIGH",
				Summary:          fmt.Sprintf("核心网关/系统安全组件更新: %s (%s -> %s)", pkgName, instVer, candVer),
				RemediationCmd:   remCmd,
				ServiceReloadCmd: reloadCmd,
				LockdownWarning:  lockWarn,
			})
		}
	} else if osCtx.PkgMgr == "opkg" {
		if osCtx.MemAvailableMB >= 32.0 {
			if priv, ok := transport.WrapPrivileged("opkg update 2>/dev/null || true", osCtx); ok {
				_, _ = exec.Run(ctx, priv, 8*time.Second)
			}
		}
		res, err := exec.Run(ctx, "opkg list-upgradable 2>/dev/null", 10*time.Second)
		if err != nil || res.Code != 0 {
			return nil
		}
		for _, rawLine := range strings.Split(res.Stdout, "\n") {
			parts := strings.Split(strings.TrimSpace(rawLine), " - ")
			if len(parts) < 3 {
				continue
			}
			pkgName := strings.ToLower(strings.TrimSpace(parts[0]))
			instVer := strings.TrimSpace(parts[1])
			candVer := strings.TrimSpace(parts[2])
			if strings.HasPrefix(pkgName, "kmod-") {
				continue
			}
			reloadCmd, allowed := openwrtSecurityWhitelist[pkgName]
			if !allowed {
				continue
			}
			remCmd := "opkg upgrade " + pkgName
			lockWarn := ""
			if osCtx.LockdownMode {
				remCmd = ""
				lockWarn = osCtx.LockdownReason
			}
			updates = append(updates, model.OSSecurityUpdate{
				Package:          pkgName,
				SourcePackage:    pkgName,
				InstalledVersion: instVer,
				CandidateVersion: candVer,
				Repository:       "opkg-distfeeds",
				Severity:         "HIGH",
				Summary:          fmt.Sprintf("OpenWrt 核心网关组件更新: %s (%s -> %s)", pkgName, instVer, candVer),
				RemediationCmd:   remCmd,
				ServiceReloadCmd: reloadCmd,
				LockdownWarning:  lockWarn,
			})
		}
	}

	return updates
}

func checkDarwinSecurityUpdates(ctx context.Context, exec transport.Executor, osCtx *model.OSContext) []model.OSSecurityUpdate {
	var updates []model.OSSecurityUpdate

	// 1. Official Apple macOS Software Update / Rapid Security Response / Command Line Tools check:
	// Strictly separate same-branch security patches/RSRs from cross-generational `_major` OS upgrades!
	appleRes, err := exec.Run(ctx, "plutil -extract RecommendedUpdates xml1 -o - /Library/Preferences/com.apple.SoftwareUpdate.plist 2>/dev/null || true", 4*time.Second)
	if err == nil && strings.Contains(appleRes.Stdout, "<dict>") {
		curMajor := leadingMajorInt(osCtx.DistroVersion)
		for _, item := range parseAppleRecommendedUpdatesXML(appleRes.Stdout) {
			dispName := item["Display Name"]
			dispVer := item["Display Version"]
			ident := item["Identifier"]
			isMSU := item["MobileSoftwareUpdate"] == "true"
			if dispName == "" && ident == "" {
				continue
			}
			if dispVer == "" {
				dispVer = dispName
			}

			// Detect cross-generational major OS upgrade (e.g. macOS 15.8.2 -> 27.2 `_major`):
			// Record calmly as informational metadata without raising a false-positive security vulnerability!
			candMajor := leadingMajorInt(dispVer)
			isMajorOSJump := strings.HasSuffix(strings.ToLower(ident), "_major") ||
				(isMSU && curMajor > 0 && candMajor > curMajor)
			if isMajorOSJump {
				osCtx.OptionalMajorUpgrade = firstNonEmptyOSVer(dispName, "macOS "+dispVer)
				continue
			}

			pkgName := "macos-software-update"
			instVer := firstNonEmptyOSVer(osCtx.DistroVersion, "current")
			remCmd := fmt.Sprintf("softwareupdate -i %s", transport.ShellQuote(firstNonEmptyOSVer(item["Product Key"], dispName)))
			summary := fmt.Sprintf("Apple 官方安全与组件补丁: %s (%s)", firstNonEmptyOSVer(dispName, ident), dispVer)
			if isMSU || strings.Contains(strings.ToLower(dispName), "macos") {
				pkgName = "macos-system"
				remCmd = `open "x-apple.systempreferences:com.apple.Software-Update-Settings.extension"`
				summary = fmt.Sprintf("Apple 当前分支安全补丁就绪: %s (当前 %s ➔ %s)", dispName, instVer, dispVer)
			}
			updates = append(updates, model.OSSecurityUpdate{
				Package:          pkgName,
				SourcePackage:    pkgName,
				InstalledVersion: instVer,
				CandidateVersion: dispVer,
				Repository:       "apple-software-update",
				Severity:         "HIGH",
				Summary:          summary,
				RemediationCmd:   remCmd,
				IsKernel:         isMSU,
			})
		}
	}

	// 2. Homebrew foundational security libraries (if Homebrew is installed)
	if osCtx.PkgMgr != "brew" {
		return updates
	}
	res, err := exec.Run(ctx, "brew outdated --json=v2 2>/dev/null", 12*time.Second)
	if err != nil || res.Code != 0 || res.Stdout == "" {
		return updates
	}
	var doc struct {
		Formulae []struct {
			Name              string   `json:"name"`
			InstalledVersions []string `json:"installed_versions"`
			CurrentVersion    string   `json:"current_version"`
		} `json:"formulae"`
	}
	if err := json.Unmarshal([]byte(res.Stdout), &doc); err != nil {
		return updates
	}
	for _, f := range doc.Formulae {
		name := strings.ToLower(strings.TrimSpace(f.Name))
		if !darwinSafeSecurityWhitelist[name] {
			continue
		}
		inst := "unknown"
		if len(f.InstalledVersions) > 0 {
			inst = f.InstalledVersions[0]
		}
		updates = append(updates, model.OSSecurityUpdate{
			Package:          name,
			SourcePackage:    name,
			InstalledVersion: inst,
			CandidateVersion: f.CurrentVersion,
			Repository:       "homebrew-core",
			Severity:         "HIGH",
			Summary:          fmt.Sprintf("macOS Homebrew 安全基础库待更新: %s (%s -> %s)", name, inst, f.CurrentVersion),
			RemediationCmd:   fmt.Sprintf("HOMEBREW_NO_INSTALLED_DEPENDENTS_CHECK=1 brew upgrade %s", name),
		})
	}
	return updates
}

func firstNonEmptyOSVer(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return strings.TrimSpace(a)
	}
	return strings.TrimSpace(b)
}

func leadingMajorInt(ver string) int {
	ver = strings.TrimSpace(ver)
	dot := strings.IndexByte(ver, '.')
	if dot > 0 {
		ver = ver[:dot]
	}
	n := 0
	for i := 0; i < len(ver); i++ {
		if ver[i] < '0' || ver[i] > '9' {
			break
		}
		n = n*10 + int(ver[i]-'0')
	}
	return n
}

var (
	plistDictRe = regexp.MustCompile(`(?s)<dict>(.*?)</dict>`)
	plistKVRe   = regexp.MustCompile(`(?s)<key>([^<]+)</key>\s*(?:<string>([^<]*)</string>|<(true|false)/>|<integer>([^<]*)</integer>)`)
)

func parseAppleRecommendedUpdatesXML(xmlText string) []map[string]string {
	var out []map[string]string
	for _, dm := range plistDictRe.FindAllStringSubmatch(xmlText, -1) {
		m := make(map[string]string)
		for _, kv := range plistKVRe.FindAllStringSubmatch(dm[1], -1) {
			key := strings.TrimSpace(kv[1])
			val := kv[2]
			if kv[3] != "" {
				val = kv[3]
			} else if kv[4] != "" {
				val = kv[4]
			}
			m[key] = strings.TrimSpace(val)
		}
		if len(m) > 0 {
			out = append(out, m)
		}
	}
	return out
}

func buildOSRemediationPlan(updates []model.OSSecurityUpdate, osCtx model.OSContext) model.RemediationPlan {
	if len(updates) == 0 {
		return model.RemediationPlan{SafeToExecute: true}
	}
	var pkgs []string
	for _, u := range updates {
		pkgs = append(pkgs, u.Package)
	}

	if osCtx.LockdownMode {
		return model.RemediationPlan{
			Packages:      pkgs,
			SafeToExecute: false,
			Warning:       osCtx.LockdownReason,
			Description:   "处于硬件防变砖熔断保护！禁止在线升级底层库，建议使用 Attended Sysupgrade 刷入新固件",
		}
	}

	needsSudo := osCtx.OSFamily != "darwin" && !osCtx.IsRoot
	if needsSudo && !osCtx.CanSudoNoPass {
		return model.RemediationPlan{
			Packages:      pkgs,
			SafeToExecute: false,
			NeedsSudo:     true,
			Warning:       "当前 SSH 用户非 root 且未配置免密 sudo (NOPASSWD)，无法无人值守自动安装系统补丁",
			Description:   fmt.Sprintf("请登录主机手动执行升级: %s", strings.Join(pkgs, " ")),
		}
	}

	wrap := func(c string) string {
		w, _ := transport.WrapPrivileged(c, osCtx)
		return w
	}

	switch {
	case osCtx.OSFamily == "darwin":
		var brewPkgs []string
		hasAppleSystemOS := false
		var cliUpdateCmds []string
		for _, u := range updates {
			switch {
			case u.Package == "macos-system":
				hasAppleSystemOS = true
			case u.Repository == "apple-software-update" && u.RemediationCmd != "":
				cliUpdateCmds = append(cliUpdateCmds, u.RemediationCmd)
			case u.Repository == "homebrew-core":
				brewPkgs = append(brewPkgs, u.Package)
			}
		}
		var cmds []string
		if len(brewPkgs) > 0 {
			cmds = append(cmds, fmt.Sprintf("HOMEBREW_NO_INSTALLED_DEPENDENTS_CHECK=1 brew upgrade %s", strings.Join(brewPkgs, " ")))
		}
		cmds = append(cmds, cliUpdateCmds...)

		if hasAppleSystemOS && len(cmds) == 0 {
			// Apple Silicon OS updates require user Touch ID confirmation in System Settings -> Software Update
			return model.RemediationPlan{
				Commands:      []string{`open "x-apple.systempreferences:com.apple.Software-Update-Settings.extension"`},
				Packages:      pkgs,
				SafeToExecute: false,
				Warning:       "Apple macOS 系统固件更新需在「系统设置 ➔ 通用 ➔ 软件更新」中由机主验证重启",
				Description:   "点击「打开 macOS 软件更新」即可直达系统设置页面一键升级",
			}
		}
		return model.RemediationPlan{
			Commands:      cmds,
			Packages:      pkgs,
			SafeToExecute: len(cmds) > 0,
			Description:   fmt.Sprintf("升级 macOS 安全组件 (%s)", strings.Join(pkgs, ", ")),
		}
	case osCtx.OSFamily == "debian" || osCtx.OSFamily == "ubuntu" || osCtx.PkgMgr == "apt":
		raw := fmt.Sprintf("DEBIAN_FRONTEND=noninteractive apt-get install --no-remove --only-upgrade -y %s && (needrestart -b 2>/dev/null || true)", strings.Join(pkgs, " "))
		return model.RemediationPlan{
			Commands:      []string{wrap(raw)},
			Packages:      pkgs,
			SafeToExecute: true,
			NeedsSudo:     needsSudo,
			Description:   fmt.Sprintf("APT 防级联卸载定向安全升级 (%d 个包) + needrestart 热载", len(pkgs)),
		}
	case osCtx.OSFamily == "rhel" || osCtx.PkgMgr == "dnf" || osCtx.PkgMgr == "yum":
		raw := "yum update-minimal --security -y"
		if osCtx.PkgMgr == "dnf" {
			raw = "dnf upgrade-minimal --security -y"
		}
		return model.RemediationPlan{
			Commands:      []string{wrap(raw)},
			Packages:      pkgs,
			SafeToExecute: true,
			NeedsSudo:     needsSudo,
			Description:   "DNF/YUM 最小化安全闭包修补 (upgrade-minimal --security)",
		}
	case osCtx.PkgMgr == "apk":
		var cmds []string
		cmds = append(cmds, wrap("apk add --upgrade "+strings.Join(pkgs, " ")))
		seenReload := make(map[string]bool)
		for _, u := range updates {
			if u.ServiceReloadCmd != "" && !seenReload[u.ServiceReloadCmd] {
				seenReload[u.ServiceReloadCmd] = true
				cmds = append(cmds, wrap(u.ServiceReloadCmd+" 2>/dev/null || true"))
			}
		}
		return model.RemediationPlan{
			Commands:      cmds,
			Packages:      pkgs,
			SafeToExecute: true,
			NeedsSudo:     needsSudo,
			Description:   fmt.Sprintf("APK 定向升级网关核心包 (%s) 并平滑热重载服务", strings.Join(pkgs, ", ")),
		}
	case osCtx.PkgMgr == "opkg":
		var cmds []string
		for _, p := range pkgs {
			cmds = append(cmds, wrap("opkg upgrade "+p))
		}
		seenReload := make(map[string]bool)
		for _, u := range updates {
			if u.ServiceReloadCmd != "" && !seenReload[u.ServiceReloadCmd] {
				seenReload[u.ServiceReloadCmd] = true
				cmds = append(cmds, wrap(u.ServiceReloadCmd+" 2>/dev/null || true"))
			}
		}
		return model.RemediationPlan{
			Commands:      cmds,
			Packages:      pkgs,
			SafeToExecute: true,
			NeedsSudo:     needsSudo,
			Description:   fmt.Sprintf("OPKG 定向升级网关核心包 (%s) 并平滑热重载服务", strings.Join(pkgs, ", ")),
		}
	default:
		return model.RemediationPlan{SafeToExecute: true, Packages: pkgs}
	}
}
