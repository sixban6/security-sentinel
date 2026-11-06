package scheduler

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/sixban6/security-sentinel/internal/infra/config"
)

const (
	LaunchdPlistName = "com.security.sentinel.audit.plist"
	LaunchdLabel     = "com.security.sentinel.audit"
	CronTag          = "# security-sentinel-daily-audit"
)

var (
	hhmmRe        = regexp.MustCompile(`^(\d{1,2}):(\d{1,2})$`)
	hourRe        = regexp.MustCompile(`^(\d{1,2})$`)
	cronCommentRe = regexp.MustCompile(`<!-- Crontab: (.*?) -->`)
)

type InstallOptions struct {
	ScheduleExpr string
	AutoFix      bool
	AutoReboot   bool
	AIHeal       bool
	ConfigPath   string
	Days         int
	ForceCron    bool
}

type ScheduleStatus struct {
	Active        bool   `json:"active"`
	Engine        string `json:"engine"`
	Label         string `json:"label,omitempty"`
	CronExpr      string `json:"cron_expr,omitempty"`
	HumanReadable string `json:"human_readable,omitempty"`
	ConfigFile    string `json:"config_file,omitempty"`
	Command       string `json:"command,omitempty"`
	LogPath       string `json:"log_path,omitempty"`
}

func ParseCronField(val string, minVal, maxVal int) ([]int, error) {
	val = strings.TrimSpace(val)
	if val == "*" {
		return nil, nil
	}
	resSet := make(map[int]bool)
	for _, rawPart := range strings.Split(val, ",") {
		part := strings.TrimSpace(rawPart)
		if part == "" {
			continue
		}
		if strings.Contains(part, "/") {
			sub := strings.Split(part, "/")
			if len(sub) != 2 {
				return nil, fmt.Errorf("无效步长语法: %s", part)
			}
			step, err := strconv.Atoi(sub[1])
			if err != nil || step <= 0 {
				return nil, fmt.Errorf("步长必须大于 0: %s", part)
			}
			start, end := minVal, maxVal
			if sub[0] != "*" {
				if strings.Contains(sub[0], "-") {
					rs := strings.Split(sub[0], "-")
					if len(rs) != 2 {
						return nil, fmt.Errorf("无效区间: %s", part)
					}
					s, err1 := strconv.Atoi(rs[0])
					e, err2 := strconv.Atoi(rs[1])
					if err1 != nil || err2 != nil || s > e {
						return nil, fmt.Errorf("无效区间: %s", part)
					}
					start, end = s, e
				} else {
					s, err := strconv.Atoi(sub[0])
					if err != nil {
						return nil, err
					}
					start = s
				}
			}
			for i := start; i <= end; i += step {
				if i >= minVal && i <= maxVal {
					resSet[i] = true
				}
			}
		} else if strings.Contains(part, "-") {
			rs := strings.Split(part, "-")
			if len(rs) != 2 {
				return nil, fmt.Errorf("无效区间: %s", part)
			}
			s, err1 := strconv.Atoi(rs[0])
			e, err2 := strconv.Atoi(rs[1])
			if err1 != nil || err2 != nil || s > e {
				return nil, fmt.Errorf("无效区间: %s", part)
			}
			for i := s; i <= e; i++ {
				if i >= minVal && i <= maxVal {
					resSet[i] = true
				}
			}
		} else {
			num, err := strconv.Atoi(part)
			if err != nil || num < minVal || num > maxVal {
				return nil, fmt.Errorf("数值超出范围 (%d..%d): %s", minVal, maxVal, part)
			}
			resSet[num] = true
		}
	}
	if len(resSet) == 0 {
		return nil, fmt.Errorf("字段未匹配有效数值: %s", val)
	}
	var out []int
	for k := range resSet {
		out = append(out, k)
	}
	sort.Ints(out)
	return out, nil
}

func NormalizeScheduleExpr(expr string) (string, error) {
	expr = strings.TrimSpace(expr)
	parts := strings.Fields(expr)
	if len(parts) == 5 {
		if _, err := ParseCronField(parts[0], 0, 59); err != nil {
			return "", err
		}
		if _, err := ParseCronField(parts[1], 0, 23); err != nil {
			return "", err
		}
		if _, err := ParseCronField(parts[2], 1, 31); err != nil {
			return "", err
		}
		if _, err := ParseCronField(parts[3], 1, 12); err != nil {
			return "", err
		}
		if _, err := ParseCronField(parts[4], 0, 7); err != nil {
			return "", err
		}
		return strings.Join(parts, " "), nil
	}
	if m := hhmmRe.FindStringSubmatch(expr); m != nil {
		h, _ := strconv.Atoi(m[1])
		min, _ := strconv.Atoi(m[2])
		if h >= 0 && h <= 23 && min >= 0 && min <= 59 {
			return fmt.Sprintf("%d %d * * *", min, h), nil
		}
		return "", fmt.Errorf("时间越界: %s", expr)
	}
	if m := hourRe.FindStringSubmatch(expr); m != nil {
		h, _ := strconv.Atoi(m[1])
		if h >= 0 && h <= 23 {
			return fmt.Sprintf("0 %d * * *", h), nil
		}
	}
	return "", fmt.Errorf("无法识别定时表达式 %q (支持 HH:MM 或 5 段 Crontab)", expr)
}

func HumanReadable(expr string) string {
	norm, err := NormalizeScheduleExpr(expr)
	if err != nil {
		return expr
	}
	p := strings.Fields(norm)
	if strings.HasPrefix(p[0], "*/") && p[1] == "*" && p[2] == "*" && p[3] == "*" && p[4] == "*" {
		return fmt.Sprintf("每 %s 分钟 (%s)", p[0][2:], norm)
	}
	if p[0] == "0" && strings.HasPrefix(p[1], "*/") && p[2] == "*" && p[3] == "*" && p[4] == "*" {
		return fmt.Sprintf("每 %s 小时整点 (%s)", p[1][2:], norm)
	}
	m, errM := strconv.Atoi(p[0])
	h, errH := strconv.Atoi(p[1])
	if errM == nil && errH == nil && p[2] == "*" && p[3] == "*" {
		switch p[4] {
		case "*":
			return fmt.Sprintf("每日 %02d:%02d (%s)", h, m, norm)
		case "1-5":
			return fmt.Sprintf("每周一至周五 %02d:%02d (%s)", h, m, norm)
		case "0,6", "6,0", "6,7":
			return fmt.Sprintf("每周末 %02d:%02d (%s)", h, m, norm)
		}
	}
	return "Crontab: " + norm
}

func CronToLaunchdIntervals(cronExpr string) ([]map[string]int, error) {
	norm, err := NormalizeScheduleExpr(cronExpr)
	if err != nil {
		return nil, err
	}
	p := strings.Fields(norm)
	mins, _ := ParseCronField(p[0], 0, 59)
	hours, _ := ParseCronField(p[1], 0, 23)
	days, _ := ParseCronField(p[2], 1, 31)
	mons, _ := ParseCronField(p[3], 1, 12)
	weeks, _ := ParseCronField(p[4], 0, 7)

	type axis struct {
		key  string
		vals []int
	}
	var axes []axis
	if mins != nil {
		axes = append(axes, axis{"Minute", mins})
	}
	if hours != nil {
		axes = append(axes, axis{"Hour", hours})
	}
	if days != nil {
		axes = append(axes, axis{"Day", days})
	}
	if mons != nil {
		axes = append(axes, axis{"Month", mons})
	}
	if weeks != nil {
		axes = append(axes, axis{"Weekday", weeks})
	}
	if len(axes) == 0 {
		return []map[string]int{{}}, nil
	}

	results := []map[string]int{{}}
	for _, ax := range axes {
		var next []map[string]int
		for _, prev := range results {
			for _, v := range ax.vals {
				cp := make(map[string]int, len(prev)+1)
				for k, pv := range prev {
					cp[k] = pv
				}
				cp[ax.key] = v
				next = append(next, cp)
			}
		}
		results = next
	}
	return results, nil
}

func FindSentinelCLI() string {
	for _, name := range []string{"sectl", "security-sentinel"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	for _, cand := range []string{
		"~/.local/bin/sectl",
		"/usr/local/bin/sectl",
		"~/.local/bin/security-sentinel",
		"/usr/local/bin/security-sentinel",
	} {
		exp := config.ExpandHome(cand)
		if _, err := os.Stat(exp); err == nil {
			return exp
		}
	}
	if exe, err := os.Executable(); err == nil {
		return exe
	}
	return "sectl"
}

func BuildAuditCommand(binPath string, opts InstallOptions) string {
	parts := []string{shellQuoteIfSpaces(binPath), "audit"}
	if opts.AutoFix {
		parts = append(parts, "--fix")
	}
	if opts.AutoReboot {
		parts = append(parts, "--auto-reboot")
	}
	if opts.AIHeal {
		parts = append(parts, "--ai-heal")
	}
	if opts.Days > 0 && opts.Days != 3 {
		parts = append(parts, "--days", strconv.Itoa(opts.Days))
	}
	cfgPath := opts.ConfigPath
	if cfgPath == "" {
		cfgPath = config.FindConfigFile("")
	}
	if cfgPath != "" {
		parts = append(parts, "--config", shellQuoteIfSpaces(cfgPath))
	}
	return strings.Join(parts, " ")
}

func shellQuoteIfSpaces(s string) string {
	if strings.ContainsAny(s, " \t\"'$") {
		return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
	}
	return s
}

func xmlEscape(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

func GenerateLaunchdPlist(cmdStr string, intervals []map[string]int, logDir string, cronComment string) string {
	stdoutLog := xmlEscape(filepath.Join(logDir, "launchd.log"))
	stderrLog := xmlEscape(filepath.Join(logDir, "launchd_err.log"))
	shellLine := xmlEscape(fmt.Sprintf(`[ -f "$HOME/.zshrc" ] && source "$HOME/.zshrc" >/dev/null 2>&1; %s`, cmdStr))

	var ivLines []string
	ivLines = append(ivLines, "    <key>StartCalendarInterval</key>")
	order := []string{"Minute", "Hour", "Day", "Weekday", "Month"}
	if len(intervals) == 1 {
		ivLines = append(ivLines, "    <dict>")
		for _, k := range order {
			if v, ok := intervals[0][k]; ok {
				ivLines = append(ivLines, fmt.Sprintf("        <key>%s</key>\n        <integer>%d</integer>", k, v))
			}
		}
		ivLines = append(ivLines, "    </dict>")
	} else {
		ivLines = append(ivLines, "    <array>")
		for _, d := range intervals {
			ivLines = append(ivLines, "        <dict>")
			for _, k := range order {
				if v, ok := d[k]; ok {
					ivLines = append(ivLines, fmt.Sprintf("            <key>%s</key>\n            <integer>%d</integer>", k, v))
				}
			}
			ivLines = append(ivLines, "        </dict>")
		}
		ivLines = append(ivLines, "    </array>")
	}

	safeComment := strings.ReplaceAll(cronComment, "--", "-")
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>%s</string>
    <!-- Crontab: %s -->
    <key>ProgramArguments</key>
    <array>
        <string>/bin/zsh</string>
        <string>-l</string>
        <string>-c</string>
        <string>%s</string>
    </array>
%s
    <key>StandardOutPath</key>
    <string>%s</string>
    <key>StandardErrorPath</key>
    <string>%s</string>
    <key>RunAtLoad</key>
    <false/>
</dict>
</plist>
`, LaunchdLabel, safeComment, shellLine, strings.Join(ivLines, "\n"), stdoutLog, stderrLog)
}

func launchdPlistPath() string {
	return config.ExpandHome("~/Library/LaunchAgents/" + LaunchdPlistName)
}

func Install(opts InstallOptions) (ScheduleStatus, error) {
	norm, err := NormalizeScheduleExpr(opts.ScheduleExpr)
	if err != nil {
		return ScheduleStatus{}, err
	}
	bin := FindSentinelCLI()
	cmdStr := BuildAuditCommand(bin, opts)
	logDir := config.StateDir()
	_ = os.MkdirAll(logDir, 0o755)

	if runtime.GOOS == "darwin" && !opts.ForceCron {
		intervals, err := CronToLaunchdIntervals(norm)
		if err != nil {
			return ScheduleStatus{}, err
		}
		plistPath := launchdPlistPath()
		_ = os.MkdirAll(filepath.Dir(plistPath), 0o755)
		plistContent := GenerateLaunchdPlist(cmdStr, intervals, logDir, norm)
		if _, err := os.Stat(plistPath); err == nil {
			_ = exec.Command("launchctl", "unload", plistPath).Run()
		}
		if err := os.WriteFile(plistPath, []byte(plistContent), 0o644); err != nil {
			return ScheduleStatus{}, err
		}
		if out, err := exec.Command("launchctl", "load", "-w", plistPath).CombinedOutput(); err != nil {
			return ScheduleStatus{}, fmt.Errorf("launchctl load 失败: %v (%s)", err, strings.TrimSpace(string(out)))
		}
		return ScheduleStatus{
			Active:        true,
			Engine:        "macOS LaunchAgent",
			Label:         LaunchdLabel,
			CronExpr:      norm,
			HumanReadable: HumanReadable(norm),
			ConfigFile:    plistPath,
			Command:       cmdStr,
			LogPath:       filepath.Join(logDir, "launchd.log"),
		}, nil
	}

	// Crontab installation
	curOut, _ := exec.Command("crontab", "-l").Output()
	var lines []string
	for _, l := range strings.Split(string(curOut), "\n") {
		if strings.TrimSpace(l) != "" && !strings.Contains(l, CronTag) {
			lines = append(lines, l)
		}
	}
	logFile := filepath.Join(logDir, "cron.log")
	cronLine := fmt.Sprintf(`%s export PATH="$HOME/.local/bin:/usr/local/bin:$PATH"; %s >> %q 2>&1 %s`, norm, cmdStr, logFile, CronTag)
	lines = append(lines, cronLine)
	writeCmd := exec.Command("crontab", "-")
	writeCmd.Stdin = strings.NewReader(strings.Join(lines, "\n") + "\n")
	if out, err := writeCmd.CombinedOutput(); err != nil {
		return ScheduleStatus{}, fmt.Errorf("crontab 写入失败: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	return ScheduleStatus{
		Active:        true,
		Engine:        "Crontab",
		CronExpr:      norm,
		HumanReadable: HumanReadable(norm),
		Command:       cronLine,
		LogPath:       logFile,
	}, nil
}

func legacyLaunchdPlistPaths() []string {
	paths := []string{launchdPlistPath()}
	if matches, err := filepath.Glob(config.ExpandHome("~/Library/LaunchAgents/*.agy.daily-security-audit.plist")); err == nil {
		paths = append(paths, matches...)
	}
	return paths
}

// RetireLegacyMacOSLaunchd unloads and removes any leftover v1/agy macOS LaunchAgent plists
// so the native Menu Bar App's built-in smart scheduler never collides with a duplicate launchd job.
func RetireLegacyMacOSLaunchd() bool {
	if runtime.GOOS != "darwin" {
		return false
	}
	retired := false
	for _, plistPath := range legacyLaunchdPlistPaths() {
		if _, err := os.Stat(plistPath); err != nil {
			continue
		}
		_ = exec.Command("launchctl", "unload", plistPath).Run()
		_ = os.Remove(plistPath)
		retired = true
	}
	return retired
}

func Uninstall() error {
	if runtime.GOOS == "darwin" {
		for _, plistPath := range legacyLaunchdPlistPaths() {
			if _, err := os.Stat(plistPath); err == nil {
				_ = exec.Command("launchctl", "unload", plistPath).Run()
				_ = os.Remove(plistPath)
			}
		}
	}
	if curOut, err := exec.Command("crontab", "-l").Output(); err == nil {
		var lines []string
		changed := false
		for _, l := range strings.Split(string(curOut), "\n") {
			if strings.Contains(l, CronTag) {
				changed = true
				continue
			}
			if strings.TrimSpace(l) != "" {
				lines = append(lines, l)
			}
		}
		if changed {
			body := ""
			if len(lines) > 0 {
				body = strings.Join(lines, "\n") + "\n"
			}
			writeCmd := exec.Command("crontab", "-")
			writeCmd.Stdin = strings.NewReader(body)
			_ = writeCmd.Run()
		}
	}
	return nil
}

func Status() []ScheduleStatus {
	var out []ScheduleStatus
	if runtime.GOOS == "darwin" {
		plistPath := launchdPlistPath()
		if data, err := os.ReadFile(plistPath); err == nil {
			listOut, _ := exec.Command("launchctl", "list").Output()
			loaded := strings.Contains(string(listOut), LaunchdLabel)
			cronExpr := ""
			if m := cronCommentRe.FindSubmatch(data); m != nil {
				cronExpr = strings.TrimSpace(string(m[1]))
			}
			out = append(out, ScheduleStatus{
				Active:        loaded,
				Engine:        "macOS LaunchAgent",
				Label:         LaunchdLabel,
				CronExpr:      cronExpr,
				HumanReadable: HumanReadable(cronExpr),
				ConfigFile:    plistPath,
			})
		}
	}
	if curOut, err := exec.Command("crontab", "-l").Output(); err == nil {
		for _, l := range strings.Split(string(curOut), "\n") {
			if strings.Contains(l, CronTag) {
				f := strings.Fields(l)
				expr := ""
				if len(f) >= 5 {
					expr = strings.Join(f[:5], " ")
				}
				out = append(out, ScheduleStatus{
					Active:        true,
					Engine:        "Crontab",
					CronExpr:      expr,
					HumanReadable: HumanReadable(expr),
					Command:       l,
				})
			}
		}
	}
	return out
}
