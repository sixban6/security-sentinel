package version

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/sixban6/security-sentinel/internal/infra/model"
)

var (
	clauseRe     = regexp.MustCompile(`^(<=|>=|!=|<>|==|=|<|>)\s*(.+)$`)
	nonDigitPref = regexp.MustCompile(`^[^\d]+`)
	preTokenRe   = regexp.MustCompile(`(?i)^(?:alpha|a|beta|b|pre|preview|rc|c|dev|snapshot)`)
	apkRevRe     = regexp.MustCompile(`-r(\d+)$`)
)

// Compare compares v1 and v2 according to ecosystem conventions.
// Returns -1 if v1 < v2, 0 if v1 == v2, +1 if v1 > v2.
func Compare(ecosystem, v1, v2 string) int {
	eco := strings.ToLower(strings.TrimSpace(ecosystem))
	switch {
	case strings.HasPrefix(eco, "debian") || strings.HasPrefix(eco, "ubuntu") || eco == "dpkg" || eco == "apt":
		return CompareDebian(v1, v2)
	case strings.HasPrefix(eco, "alpine") || eco == "openwrt" || eco == "apk":
		return CompareAPK(v1, v2)
	default:
		return CompareSemVerLike(v1, v2)
	}
}

// CompareOp evaluates v1 <op> v2 for ecosystem.
func CompareOp(ecosystem, v1, op, v2 string) bool {
	cmp := Compare(ecosystem, v1, v2)
	switch strings.TrimSpace(op) {
	case "<":
		return cmp < 0
	case "<=":
		return cmp <= 0
	case ">":
		return cmp > 0
	case ">=":
		return cmp >= 0
	case "=", "==":
		return cmp == 0
	case "!=", "<>":
		return cmp != 0
	default:
		return false
	}
}

// IsVersionVulnerable checks whether installedVersion matches vulnerableRange.
// Supports union expressions separated by "||" and conjunctions separated by ",".
func IsVersionVulnerable(ecosystem, installedVersion, vulnerableRange string) bool {
	installedVersion = strings.TrimSpace(installedVersion)
	vulnerableRange = strings.TrimSpace(vulnerableRange)
	if installedVersion == "" || vulnerableRange == "" {
		return false
	}

	unions := strings.Split(vulnerableRange, "||")
	for _, unionPart := range unions {
		unionPart = strings.TrimSpace(unionPart)
		if unionPart == "" {
			continue
		}
		if matchAndClauses(ecosystem, installedVersion, unionPart) {
			return true
		}
	}
	return false
}

func matchAndClauses(ecosystem, installedVersion, expr string) bool {
	clauses := strings.Split(expr, ",")
	matchedAny := false
	for _, raw := range clauses {
		c := strings.TrimSpace(raw)
		if c == "" {
			continue
		}
		m := clauseRe.FindStringSubmatch(c)
		if m == nil {
			// Handle space-separated constraints like ">=1.0.0 <1.2.0"
			fields := strings.Fields(c)
			if len(fields) >= 2 {
				ok := true
				for _, f := range fields {
					fm := clauseRe.FindStringSubmatch(f)
					if fm == nil {
						ok = false
						break
					}
					if !CompareOp(ecosystem, installedVersion, fm[1], fm[2]) {
						return false
					}
					matchedAny = true
				}
				if ok {
					continue
				}
			}
			return false
		}
		matchedAny = true
		if !CompareOp(ecosystem, installedVersion, m[1], m[2]) {
			return false
		}
	}
	return matchedAny
}

// CompareDebian implements the Debian Policy version comparison algorithm:
// [epoch:]upstream_version[-debian_revision], where '~' sorts before everything including end-of-part.
func CompareDebian(v1, v2 string) int {
	e1, u1, r1 := splitDebianVersion(strings.TrimSpace(v1))
	e2, u2, r2 := splitDebianVersion(strings.TrimSpace(v2))
	if e1 != e2 {
		if e1 < e2 {
			return -1
		}
		return 1
	}
	if c := compareDebianPart(u1, u2); c != 0 {
		return c
	}
	return compareDebianPart(r1, r2)
}

func splitDebianVersion(v string) (epoch int, upstream, revision string) {
	if idx := strings.IndexByte(v, ':'); idx > 0 {
		if e, err := strconv.Atoi(v[:idx]); err == nil {
			epoch = e
			v = v[idx+1:]
		}
	}
	if idx := strings.LastIndexByte(v, '-'); idx >= 0 {
		return epoch, v[:idx], v[idx+1:]
	}
	return epoch, v, "0"
}

func debianCharOrder(b byte) int {
	if b == '~' {
		return -1
	}
	if (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') {
		return int(b)
	}
	return int(b) + 256
}

func isDigit(b byte) bool {
	return b >= '0' && b <= '9'
}

func compareDebianPart(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		// 1. Compare non-digit prefix
		for (i < len(a) && !isDigit(a[i])) || (j < len(b) && !isDigit(b[j])) {
			ac := 0
			if i < len(a) && !isDigit(a[i]) {
				ac = debianCharOrder(a[i])
				i++
			}
			bc := 0
			if j < len(b) && !isDigit(b[j]) {
				bc = debianCharOrder(b[j])
				j++
			}
			if ac != bc {
				if ac < bc {
					return -1
				}
				return 1
			}
		}

		// 2. Compare numeric prefix
		iStart := i
		for i < len(a) && isDigit(a[i]) {
			i++
		}
		jStart := j
		for j < len(b) && isDigit(b[j]) {
			j++
		}
		numA := strings.TrimLeft(a[iStart:i], "0")
		numB := strings.TrimLeft(b[jStart:j], "0")
		if len(numA) != len(numB) {
			if len(numA) < len(numB) {
				return -1
			}
			return 1
		}
		if numA != numB {
			if numA < numB {
				return -1
			}
			return 1
		}
	}
	return 0
}

// CompareAPK compares Alpine / OpenWrt apk versions (e.g. 2.90-r1 < 2.90-r2, 1.0_rc1 < 1.0).
func CompareAPK(v1, v2 string) int {
	base1, rev1 := splitAPKRevision(strings.TrimSpace(v1))
	base2, rev2 := splitAPKRevision(strings.TrimSpace(v2))
	if c := CompareSemVerLike(base1, base2); c != 0 {
		return c
	}
	if rev1 < rev2 {
		return -1
	}
	if rev1 > rev2 {
		return 1
	}
	return 0
}

func splitAPKRevision(v string) (string, int) {
	if m := apkRevRe.FindStringSubmatch(v); m != nil {
		rev, _ := strconv.Atoi(m[1])
		return strings.TrimSuffix(v, m[0]), rev
	}
	return v, 0
}

type parsedSemVer struct {
	nums    []int
	preRank int    // -2 dev, -1 pre-release (alpha/beta/rc), 0 final, +1 post/rev
	preTag  string // raw pre-release/post suffix for lexical+numeric tiebreak
}

// CompareSemVerLike compares SemVer, PEP 440, Go, Cargo, Maven, and generic version strings,
// properly sorting pre-releases BEFORE final releases (e.g. 1.2.0-rc.1 < 1.2.0 < 1.2.0.post1).
func CompareSemVerLike(v1, v2 string) int {
	p1 := parseSemVerLike(v1)
	p2 := parseSemVerLike(v2)

	maxLen := len(p1.nums)
	if len(p2.nums) > maxLen {
		maxLen = len(p2.nums)
	}
	for i := 0; i < maxLen; i++ {
		n1, n2 := 0, 0
		if i < len(p1.nums) {
			n1 = p1.nums[i]
		}
		if i < len(p2.nums) {
			n2 = p2.nums[i]
		}
		if n1 < n2 {
			return -1
		}
		if n1 > n2 {
			return 1
		}
	}

	if p1.preRank != p2.preRank {
		if p1.preRank < p2.preRank {
			return -1
		}
		return 1
	}
	if p1.preTag == p2.preTag {
		return 0
	}
	return comparePreIdentifiers(p1.preTag, p2.preTag)
}

func parseSemVerLike(raw string) parsedSemVer {
	s := strings.TrimSpace(raw)
	if s == "" {
		return parsedSemVer{nums: []int{0}}
	}
	// Strip build metadata (+build...) unless +post
	if plusIdx := strings.IndexByte(s, '+'); plusIdx >= 0 {
		s = s[:plusIdx]
	}
	if strings.HasPrefix(s, "v") || strings.HasPrefix(s, "V") {
		if len(s) > 1 && isDigit(s[1]) {
			s = s[1:]
		}
	}
	s = nonDigitPref.ReplaceAllString(s, "")
	if s == "" {
		return parsedSemVer{nums: []int{0}}
	}

	// Split numeric release core from pre-release / post-release suffix
	var coreParts []int
	var suffix string

	// Locate first pre-release / post separator or attached alpha token (like 1.2.0rc1, 1.2.0-rc.1, 1.2.0_beta2, 1.2.0.post1)
	i := 0
	for i < len(s) {
		j := i
		for j < len(s) && isDigit(s[j]) {
			j++
		}
		if j > i {
			n, _ := strconv.Atoi(s[i:j])
			coreParts = append(coreParts, n)
		}
		if j >= len(s) {
			break
		}
		sep := s[j]
		rest := s[j:]
		if sep == '.' {
			after := s[j+1:]
			if after != "" && !isDigit(after[0]) {
				suffix = after
				break
			}
			i = j + 1
			continue
		}
		if sep == '-' || sep == '_' || sep == '~' {
			after := s[j+1:]
			if sep == '~' {
				suffix = "~" + after
				break
			}
			// Check if "-1" is a post revision vs "-rc.1" pre-release
			if after != "" && isDigit(after[0]) {
				// Pure numeric revision like "1.2.3-1"
				n, nextIdx := readLeadingInt(after)
				coreParts = append(coreParts, n)
				if nextIdx >= len(after) {
					break
				}
				suffix = after[nextIdx:]
				break
			}
			suffix = after
			break
		}
		// Attached alpha suffix like 1.2.0rc1 or 1.0a2
		suffix = rest
		break
	}

	if len(coreParts) == 0 {
		coreParts = []int{0}
	}

	if suffix == "" {
		return parsedSemVer{nums: coreParts, preRank: 0}
	}

	low := strings.ToLower(strings.TrimLeft(suffix, ".-_"))
	if strings.HasPrefix(suffix, "~") || strings.HasPrefix(low, "dev") {
		return parsedSemVer{nums: coreParts, preRank: -2, preTag: strings.TrimPrefix(low, "~")}
	}
	if strings.HasPrefix(low, "post") || strings.HasPrefix(low, "rev") || strings.HasPrefix(low, "pl") || low == "final" || low == "release" {
		if low == "final" || low == "release" {
			return parsedSemVer{nums: coreParts, preRank: 0}
		}
		return parsedSemVer{nums: coreParts, preRank: 1, preTag: low}
	}
	if preTokenRe.MatchString(low) {
		return parsedSemVer{nums: coreParts, preRank: -1, preTag: normalizePreTag(low)}
	}
	// Unknown alpha tag in SemVer pre-release position (e.g. 1.2.0-canary.1) sorts before final release
	return parsedSemVer{nums: coreParts, preRank: -1, preTag: low}
}

func normalizePreTag(s string) string {
	switch {
	case strings.HasPrefix(s, "alpha"):
		return "a." + strings.TrimLeft(s[5:], ".-_")
	case strings.HasPrefix(s, "beta"):
		return "b." + strings.TrimLeft(s[4:], ".-_")
	case strings.HasPrefix(s, "preview"):
		return "c." + strings.TrimLeft(s[7:], ".-_")
	case strings.HasPrefix(s, "pre"):
		return "c." + strings.TrimLeft(s[3:], ".-_")
	case strings.HasPrefix(s, "rc"):
		return "rc." + strings.TrimLeft(s[2:], ".-_")
	case len(s) > 1 && (s[0] == 'a' || s[0] == 'b' || s[0] == 'c') && isDigit(s[1]):
		if s[0] == 'c' {
			return "rc." + s[1:]
		}
		return string(s[0]) + "." + s[1:]
	default:
		return s
	}
}

func readLeadingInt(s string) (int, int) {
	i := 0
	for i < len(s) && isDigit(s[i]) {
		i++
	}
	n, _ := strconv.Atoi(s[:i])
	return n, i
}

func comparePreIdentifiers(a, b string) int {
	pa := splitPreTokens(a)
	pb := splitPreTokens(b)
	maxLen := len(pa)
	if len(pb) > maxLen {
		maxLen = len(pb)
	}
	for i := 0; i < maxLen; i++ {
		if i >= len(pa) {
			return -1
		}
		if i >= len(pb) {
			return 1
		}
		na, errA := strconv.Atoi(pa[i])
		nb, errB := strconv.Atoi(pb[i])
		switch {
		case errA == nil && errB == nil:
			if na != nb {
				if na < nb {
					return -1
				}
				return 1
			}
		case errA == nil && errB != nil:
			return -1
		case errA != nil && errB == nil:
			return 1
		default:
			if pa[i] != pb[i] {
				if pa[i] < pb[i] {
					return -1
				}
				return 1
			}
		}
	}
	return 0
}

func splitPreTokens(s string) []string {
	var out []string
	cur := strings.Builder{}
	lastDigit := false
	for idx := 0; idx < len(s); idx++ {
		ch := s[idx]
		if ch == '.' || ch == '-' || ch == '_' {
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
			continue
		}
		d := isDigit(ch)
		if cur.Len() > 0 && d != lastDigit {
			out = append(out, cur.String())
			cur.Reset()
		}
		cur.WriteByte(ch)
		lastDigit = d
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// ParseKernelTuple extracts numeric tuple (major, minor, patch) for Linux kernel versions.
func ParseKernelTuple(v string) []int {
	p := parseSemVerLike(v)
	return p.nums
}

func compareIntTuples(a, b []int) int {
	m := len(a)
	if len(b) > m {
		m = len(b)
	}
	for i := 0; i < m; i++ {
		va, vb := 0, 0
		if i < len(a) {
			va = a[i]
		}
		if i < len(b) {
			vb = b[i]
		}
		if va < vb {
			return -1
		}
		if va > vb {
			return 1
		}
	}
	return 0
}

// IsKernelVulnerable implements multi-LTS branch matching for Linux kernel advisories
// (e.g. 5.10.x, 5.15.x, 6.1.x, 6.6.x, 6.12.x, mainline) without false positives across older LTS lines.
func IsKernelVulnerable(installedVersion string, adv model.Advisory) bool {
	installedVersion = strings.TrimSpace(installedVersion)
	if installedVersion == "" {
		return false
	}
	inst := ParseKernelTuple(installedVersion)
	if len(inst) == 0 || inst[0] == 0 {
		return false
	}

	if adv.IntroducedIn != "" {
		intro := ParseKernelTuple(adv.IntroducedIn)
		if compareIntTuples(inst, intro) < 0 {
			return false
		}
	}

	if len(adv.FixedIn) == 0 {
		if adv.VulnerableRange != "" {
			return IsVersionVulnerable(model.EcoLinux, installedVersion, adv.VulnerableRange)
		}
		return false
	}

	type branchKey struct{ major, minor int }
	fixesByBranch := make(map[branchKey][]int)
	var highestFixed []int

	for _, f := range adv.FixedIn {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		fp := ParseKernelTuple(f)
		if len(fp) >= 2 {
			bk := branchKey{fp[0], fp[1]}
			if existing, ok := fixesByBranch[bk]; !ok || compareIntTuples(fp, existing) > 0 {
				fixesByBranch[bk] = fp
			}
		}
		if compareIntTuples(fp, highestFixed) > 0 {
			highestFixed = fp
		}
	}

	if len(highestFixed) > 0 && compareIntTuples(inst, highestFixed) >= 0 {
		return false
	}

	instBranch := branchKey{inst[0], 0}
	if len(inst) >= 2 {
		instBranch.minor = inst[1]
	}
	if fixedTuple, ok := fixesByBranch[instBranch]; ok {
		return compareIntTuples(inst, fixedTuple) < 0
	}
	return true
}
