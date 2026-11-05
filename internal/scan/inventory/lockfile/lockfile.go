package lockfile

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/sixban6/security-sentinel/internal/infra/config"
	"github.com/sixban6/security-sentinel/internal/infra/model"
)

const DefaultActiveWindowDays = 90

var (
	distInfoRe    = regexp.MustCompile(`^([A-Za-z0-9_.\-]+)-([0-9][A-Za-z0-9_.\+\-]*)\.dist-info$`)
	goModReqRe    = regexp.MustCompile(`^\s*([A-Za-z0-9_.\-\/]+)\s+v([0-9][^\s\/]*)`)
	cargoPkgName  = regexp.MustCompile(`^\s*name\s*=\s*"([^"]+)"`)
	cargoPkgVer   = regexp.MustCompile(`^\s*version\s*=\s*"([^"]+)"`)
	pnpmPkgHeader = regexp.MustCompile(`^\s{2,4}'?/?(@?[^@'(\s]+)@([0-9][^'(\s:]*)'?:?\s*$`)
	yarnHeaderRe  = regexp.MustCompile(`^"?(@?[^@"\s,]+)@[^":]+"?:$`)
	yarnVerRe     = regexp.MustCompile(`^\s+version\s+"?([^"\s]+)"?`)
	gemSpecRe     = regexp.MustCompile(`^\s{4}([A-Za-z0-9_\-\.]+)\s+\(([0-9][A-Za-z0-9_\-\.]*)\)$`)
	gradleWrapRe  = regexp.MustCompile(`gradle-([0-9][A-Za-z0-9.\-_]*)-`)
	mavenWrapRe   = regexp.MustCompile(`apache-maven-([0-9][A-Za-z0-9.\-_]*)-`)
)

var ignoredDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
	"target":       true,
	"dist":         true,
	"build":        true,
	".next":        true,
	".nuxt":        true,
	".cache":       true,
	"__pycache__":  true,
	".gradle":      true,
	"vendor":       true,
	"archive":      true,
	"archived":     true,
	"deprecated":   true,
	"backup":       true,
	"backups":      true,
	"trash":        true,
	"old":          true,
}

func isBackupOrScrapDir(name string) bool {
	low := strings.ToLower(name)
	if ignoredDirs[low] {
		return true
	}
	for _, suf := range []string{"_bak", "-bak", ".bak", "-broken", "_broken", ".old", "_old", "-old"} {
		if strings.HasSuffix(low, suf) || strings.Contains(low, suf+"-") || strings.Contains(low, suf+"_") {
			return true
		}
	}
	return false
}

// WorkspaceScanResult contains deduplicated project dependency assets, summary counts, and orphaned central venvs.
type WorkspaceScanResult struct {
	Assets        []model.AssetItem
	Summary       model.EcosystemSummary
	OrphanedVenvs []model.OrphanedVenv
}

type projectMeta struct {
	name           string
	dir            string
	manifestKind   string
	lastActiveDays int
	modifiedUnix   int64
	createdUnix    int64
	archived       bool
}

func stampAssets(items []model.AssetItem, meta projectMeta) []model.AssetItem {
	for i := range items {
		items[i].ProjectName = meta.name
		items[i].ProjectDir = meta.dir
		items[i].ManifestKind = meta.manifestKind
		items[i].LastActiveDays = meta.lastActiveDays
		items[i].ModifiedUnix = meta.modifiedUnix
		items[i].CreatedUnix = meta.createdUnix
		items[i].Archived = meta.archived
	}
	return items
}

// ScanSingleProject scans ONLY a single project directory (used after 1-click GUI dependency upgrade for <1s instant refresh).
func ScanSingleProject(projectDir string) []model.AssetItem {
	var res WorkspaceScanResult
	walkWorkspaceRoot(projectDir, 0, 1, make(map[string]bool), make(map[string]bool), make(map[string]bool), &res)
	var filtered []model.AssetItem
	cleanTarget := filepath.Clean(projectDir)
	if rp, err := filepath.EvalSymlinks(cleanTarget); err == nil {
		cleanTarget = rp
	}
	for _, a := range res.Assets {
		if filepath.Clean(a.ProjectDir) == cleanTarget {
			filtered = append(filtered, a)
		}
	}
	return filtered
}

// ScanWorkspaces walks workspace roots (deduplicating lockfile vs .venv, skipping backup dirs, tagging 90-day activity)
// and detects orphaned/zombie central virtualenvs separately.
func ScanWorkspaces(roots []string) WorkspaceScanResult {
	var res WorkspaceScanResult
	seenDirs := make(map[string]bool)
	seenVenvs := make(map[string]bool)
	scannedProjectDirs := make(map[string]bool)

	for _, root := range roots {
		walkWorkspaceRoot(root, 0, 3, seenDirs, seenVenvs, scannedProjectDirs, &res)
	}

	if os.Getenv("SENTINEL_SKIP_CENTRAL_VENVS") == "" {
		scanCentralVirtualenvs(seenVenvs, scannedProjectDirs, &res)
	}

	res.Summary.JavaJDKs = countInstalledJDKs()
	return res
}

// DetectOrphanedVenvs scans standard central virtualenv caches and returns orphaned / long-abandoned environments.
func DetectOrphanedVenvs() []model.OrphanedVenv {
	var res WorkspaceScanResult
	scanCentralVirtualenvs(make(map[string]bool), make(map[string]bool), &res)
	return res.OrphanedVenvs
}

func scanCentralVirtualenvs(seenVenvs, scannedProjectDirs map[string]bool, res *WorkspaceScanResult) {
	centralDirs := []string{
		"~/.local/share/virtualenvs",
		"~/.virtualenvs",
		"~/.cache/pypoetry/virtualenvs",
		"~/Library/Caches/pypoetry/virtualenvs",
	}
	for _, cd := range centralDirs {
		exp := config.ExpandHome(cd)
		entries, err := os.ReadDir(exp)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			vp := filepath.Join(exp, e.Name())
			if realP, err := filepath.EvalSymlinks(vp); err == nil {
				vp = realP
			}
			if seenVenvs[vp] || !isPythonVenv(vp) {
				continue
			}
			seenVenvs[vp] = true

			idleDays := computeDirIdleDays(vp)
			dotProj := filepath.Join(vp, ".project")
			linkedProj := ""
			if b, err := os.ReadFile(dotProj); err == nil {
				linkedProj = strings.TrimSpace(string(b))
			}

			// Case 1: Linked source project directory was deleted -> Orphaned Zombie Venv!
			if linkedProj != "" {
				if info, err := os.Stat(linkedProj); err != nil || !info.IsDir() {
					res.OrphanedVenvs = append(res.OrphanedVenvs, model.OrphanedVenv{
						Name:               e.Name(),
						Path:               vp,
						MissingProjectPath: linkedProj,
						IdleDays:           idleDays,
						SizeMB:             estimateDirSizeMB(vp),
						Reason:             "原项目目录已删除",
					})
					continue
				}
				if rp, err := filepath.EvalSymlinks(linkedProj); err == nil {
					linkedProj = rp
				}
				// Avoid double-counting if project dir was already scanned via uv.lock/poetry.lock/.venv
				if scannedProjectDirs[linkedProj] {
					continue
				}
				idleDays = minInt(idleDays, computeProjectIdleDays(linkedProj))
			}

			// Case 2: Untouched for > 180 days in central cache -> Dormant Zombie Venv!
			if idleDays > 180 {
				res.OrphanedVenvs = append(res.OrphanedVenvs, model.OrphanedVenv{
					Name:     e.Name(),
					Path:     vp,
					IdleDays: idleDays,
					SizeMB:   estimateDirSizeMB(vp),
					Reason:   fmt.Sprintf("闲置 %d 天未活动", idleDays),
				})
				continue
			}

			projName := e.Name()
			projDir := vp
			if linkedProj != "" {
				projName = filepath.Base(linkedProj)
				projDir = linkedProj
			}
			res.Summary.PythonVenvs++
			_, modUnix, crtUnix := computeProjectTimestamps(projDir)
			meta := projectMeta{
				name:           projName,
				dir:            projDir,
				manifestKind:   "venv",
				lastActiveDays: idleDays,
				modifiedUnix:   modUnix,
				createdUnix:    crtUnix,
				archived:       idleDays > DefaultActiveWindowDays,
			}
			res.Assets = append(res.Assets, stampAssets(parsePythonVenv(vp), meta)...)
		}
	}

	sort.Slice(res.OrphanedVenvs, func(i, j int) bool {
		return res.OrphanedVenvs[i].SizeMB > res.OrphanedVenvs[j].SizeMB
	})
}

func walkWorkspaceRoot(dir string, depth, maxDepth int, seenDirs, seenVenvs, scannedProjectDirs map[string]bool, res *WorkspaceScanResult) {
	if depth > maxDepth {
		return
	}
	realDir := dir
	if rp, err := filepath.EvalSymlinks(dir); err == nil {
		realDir = rp
	}
	if seenDirs[realDir] {
		return
	}
	if depth > 0 && isBackupOrScrapDir(filepath.Base(realDir)) {
		return
	}
	seenDirs[realDir] = true

	if isPythonVenv(realDir) {
		if !seenVenvs[realDir] {
			seenVenvs[realDir] = true
			res.Summary.PythonVenvs++
			parent := filepath.Dir(realDir)
			idle, modU, crtU := computeProjectTimestamps(parent)
			meta := projectMeta{
				name:           filepath.Base(parent),
				dir:            parent,
				manifestKind:   "venv",
				lastActiveDays: idle,
				modifiedUnix:   modU,
				createdUnix:    crtU,
				archived:       idle > DefaultActiveWindowDays,
			}
			res.Assets = append(res.Assets, stampAssets(parsePythonVenv(realDir), meta)...)
		}
		return
	}

	entries, err := os.ReadDir(realDir)
	if err != nil {
		return
	}

	fileSet := make(map[string]bool, len(entries))
	dirSet := make(map[string]bool, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			dirSet[e.Name()] = true
		} else {
			fileSet[e.Name()] = true
		}
	}

	projName := filepath.Base(realDir)
	idleDays, modUnix, crtUnix := computeProjectTimestamps(realDir)
	isArchived := idleDays > DefaultActiveWindowDays
	mkMeta := func(kind string) projectMeta {
		return projectMeta{
			name:           projName,
			dir:            realDir,
			manifestKind:   kind,
			lastActiveDays: idleDays,
			modifiedUnix:   modUnix,
			createdUnix:    crtUnix,
			archived:       isArchived,
		}
	}

	// 1. Python lockfiles (uv.lock / poetry.lock) — Single Source of Truth!
	hasPyLock := false
	if fileSet["uv.lock"] {
		hasPyLock = true
		scannedProjectDirs[realDir] = true
		res.Assets = append(res.Assets, stampAssets(parseTOMLPackageBlocks(filepath.Join(realDir, "uv.lock"), model.EcoPyPI), mkMeta("uv"))...)
	} else if fileSet["poetry.lock"] {
		hasPyLock = true
		scannedProjectDirs[realDir] = true
		res.Assets = append(res.Assets, stampAssets(parseTOMLPackageBlocks(filepath.Join(realDir, "poetry.lock"), model.EcoPyPI), mkMeta("poetry"))...)
	}
	if hasPyLock {
		for _, vn := range []string{".venv", "venv"} {
			if dirSet[vn] {
				vp := filepath.Join(realDir, vn)
				if rp, err := filepath.EvalSymlinks(vp); err == nil {
					vp = rp
				}
				if !seenVenvs[vp] && isPythonVenv(vp) {
					seenVenvs[vp] = true
					res.Summary.PythonVenvs++
				}
			}
		}
	}

	// 2. Node.js projects & lockfiles
	if fileSet["package.json"] {
		res.Summary.NodeProjects++
		scannedProjectDirs[realDir] = true
		switch {
		case fileSet["package-lock.json"]:
			res.Assets = append(res.Assets, stampAssets(parsePackageLockJSON(filepath.Join(realDir, "package-lock.json")), mkMeta("npm"))...)
		case fileSet["pnpm-lock.yaml"]:
			res.Assets = append(res.Assets, stampAssets(parsePnpmLock(filepath.Join(realDir, "pnpm-lock.yaml")), mkMeta("pnpm"))...)
		case fileSet["yarn.lock"]:
			res.Assets = append(res.Assets, stampAssets(parseYarnLock(filepath.Join(realDir, "yarn.lock")), mkMeta("yarn"))...)
		}
	}

	// 3. Go go.mod
	if fileSet["go.mod"] {
		res.Summary.GoModules++
		scannedProjectDirs[realDir] = true
		res.Assets = append(res.Assets, stampAssets(parseGoMod(filepath.Join(realDir, "go.mod")), mkMeta("gomod"))...)
	}

	// 4. Rust Cargo.lock
	if fileSet["Cargo.toml"] {
		res.Summary.RustCrates++
		scannedProjectDirs[realDir] = true
		if fileSet["Cargo.lock"] {
			res.Assets = append(res.Assets, stampAssets(parseTOMLPackageBlocks(filepath.Join(realDir, "Cargo.lock"), model.EcoCrates), mkMeta("cargo"))...)
		}
	}

	// 5. PHP composer.lock
	if fileSet["composer.json"] {
		res.Summary.PHPProjects++
		if fileSet["composer.lock"] {
			res.Assets = append(res.Assets, stampAssets(parseComposerLock(filepath.Join(realDir, "composer.lock")), mkMeta("composer"))...)
		}
	}

	// 6. Ruby Gemfile.lock
	if fileSet["Gemfile"] {
		res.Summary.RubyProjects++
		if fileSet["Gemfile.lock"] {
			res.Assets = append(res.Assets, stampAssets(parseGemfileLock(filepath.Join(realDir, "Gemfile.lock")), mkMeta("bundler"))...)
		}
	}

	// 7. Java Maven (pom.xml) & Gradle (build.gradle / build.gradle.kts) + Wrappers
	if fileSet["pom.xml"] {
		res.Summary.JavaProjects++
		scannedProjectDirs[realDir] = true
		mavenAssets, childDirs := parseMavenProject(realDir)
		res.Assets = append(res.Assets, stampAssets(mavenAssets, mkMeta("maven"))...)
		for _, cd := range childDirs {
			if rp, err := filepath.EvalSymlinks(cd); err == nil {
				seenDirs[rp] = true
			} else {
				seenDirs[cd] = true
			}
		}
	} else if fileSet["build.gradle"] || fileSet["build.gradle.kts"] || fileSet["gradle.lockfile"] {
		res.Summary.JavaProjects++
		scannedProjectDirs[realDir] = true
		res.Assets = append(res.Assets, stampAssets(parseGradleProject(realDir), mkMeta("gradle"))...)
	}

	if fileSet["gradlew"] {
		res.Summary.JavaWrappers++
		if v := readWrapperVersion(filepath.Join(realDir, "gradle", "wrapper", "gradle-wrapper.properties"), gradleWrapRe); v != "" {
			res.Assets = append(res.Assets, stampAssets([]model.AssetItem{{
				Ecosystem: model.EcoMaven, Name: "org.gradle:gradle-core", Version: v,
				Location: filepath.Join(realDir, "gradlew"), Kind: "lockfile",
			}}, mkMeta("gradle"))...)
		}
	}
	if fileSet["mvnw"] {
		res.Summary.JavaWrappers++
		if v := readWrapperVersion(filepath.Join(realDir, ".mvn", "wrapper", "maven-wrapper.properties"), mavenWrapRe); v != "" {
			res.Assets = append(res.Assets, stampAssets([]model.AssetItem{{
				Ecosystem: model.EcoMaven, Name: "org.apache.maven:maven-core", Version: v,
				Location: filepath.Join(realDir, "mvnw"), Kind: "lockfile",
			}}, mkMeta("maven"))...)
		}
	}

	// 8. .NET csproj + packages.lock.json
	hasCsproj := false
	for name := range fileSet {
		if strings.HasSuffix(name, ".csproj") {
			hasCsproj = true
			break
		}
	}
	if hasCsproj {
		res.Summary.DotnetProjects++
		if fileSet["packages.lock.json"] {
			res.Assets = append(res.Assets, stampAssets(parseNuGetLock(filepath.Join(realDir, "packages.lock.json")), mkMeta("nuget"))...)
		}
	}

	// 9. Swift Package.swift + Package.resolved
	if fileSet["Package.swift"] {
		res.Summary.SwiftProjects++
		if fileSet["Package.resolved"] {
			res.Assets = append(res.Assets, stampAssets(parseSwiftResolved(filepath.Join(realDir, "Package.resolved")), mkMeta("swift"))...)
		}
	}

	if depth == maxDepth {
		return
	}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if isBackupOrScrapDir(name) {
			continue
		}
		sub := filepath.Join(realDir, name)
		if name == ".venv" || name == "venv" || isPythonVenv(sub) {
			if rp, err := filepath.EvalSymlinks(sub); err == nil {
				sub = rp
			}
			if !seenVenvs[sub] && isPythonVenv(sub) {
				seenVenvs[sub] = true
				scannedProjectDirs[realDir] = true
				res.Summary.PythonVenvs++
				res.Assets = append(res.Assets, stampAssets(parsePythonVenv(sub), mkMeta("venv"))...)
			}
			continue
		}
		if strings.HasPrefix(name, ".") {
			continue
		}
		walkWorkspaceRoot(sub, depth+1, maxDepth, seenDirs, seenVenvs, scannedProjectDirs, res)
	}
}

func computeProjectIdleDays(dir string) int {
	days, _, _ := computeProjectTimestamps(dir)
	return days
}

// computeProjectTimestamps extracts:
// - idleDays since the most recent modification in the project
// - newestModifiedUnix across project manifests/git index
// - earliestCreatedUnix (APFS Birthtime on macOS) of the project root
func computeProjectTimestamps(dir string) (idleDays int, newestModifiedUnix int64, createdUnix int64) {
	if rootInfo, err := os.Stat(dir); err == nil {
		createdUnix = fileCreatedUnix(rootInfo)
		newestModifiedUnix = rootInfo.ModTime().Unix()
	}
	candidates := []string{
		filepath.Join(dir, ".git", "index"),
		filepath.Join(dir, ".git", "HEAD"),
		filepath.Join(dir, "uv.lock"),
		filepath.Join(dir, "poetry.lock"),
		filepath.Join(dir, "pyproject.toml"),
		filepath.Join(dir, "requirements.txt"),
		filepath.Join(dir, "package-lock.json"),
		filepath.Join(dir, "pnpm-lock.yaml"),
		filepath.Join(dir, "package.json"),
		filepath.Join(dir, "go.mod"),
		filepath.Join(dir, "Cargo.lock"),
		filepath.Join(dir, "Cargo.toml"),
		filepath.Join(dir, "pom.xml"),
		filepath.Join(dir, "build.gradle"),
		filepath.Join(dir, "build.gradle.kts"),
	}
	for _, p := range candidates {
		if info, err := os.Stat(p); err == nil {
			if mu := info.ModTime().Unix(); mu > newestModifiedUnix {
				newestModifiedUnix = mu
			}
			if cu := fileCreatedUnix(info); cu > 0 && (createdUnix == 0 || cu < createdUnix) {
				createdUnix = cu
			}
		}
	}
	if newestModifiedUnix <= 0 {
		return 0, 0, createdUnix
	}
	days := int(time.Since(time.Unix(newestModifiedUnix, 0)).Hours() / 24)
	if days < 0 {
		days = 0
	}
	return days, newestModifiedUnix, createdUnix
}

func computeDirIdleDays(dir string) int {
	newest := time.Time{}
	if info, err := os.Stat(dir); err == nil {
		newest = info.ModTime()
	}
	if info, err := os.Stat(filepath.Join(dir, "lib")); err == nil && info.ModTime().After(newest) {
		newest = info.ModTime()
	}
	if newest.IsZero() {
		return 0
	}
	d := int(time.Since(newest).Hours() / 24)
	if d < 0 {
		return 0
	}
	return d
}

func estimateDirSizeMB(dir string) float64 {
	var total int64
	count := 0
	_ = filepath.WalkDir(dir, func(_ string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		count++
		if count > 15000 {
			return filepath.SkipAll
		}
		if !d.IsDir() {
			if info, err := d.Info(); err == nil {
				total += info.Size()
			}
		}
		return nil
	})
	return float64(total) / (1024.0 * 1024.0)
}

// MoveDirectoryToTrash safely moves a directory (such as a local project or orphaned venv) into the OS Trash (never rm -rf!).
func MoveDirectoryToTrash(dirPath string) (string, error) {
	cleanPath := filepath.Clean(dirPath)
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	if cleanPath == "/" || cleanPath == home || len(cleanPath) < len(home)+2 {
		return "", fmt.Errorf("安全护栏拦截：禁止将根目录或用户主目录移入废纸篓 (%s)", cleanPath)
	}
	info, err := os.Stat(cleanPath)
	if err != nil || !info.IsDir() {
		return "", fmt.Errorf("目录不存在: %s", cleanPath)
	}
	trashDir := filepath.Join(home, ".Trash")
	if runtime.GOOS != "darwin" {
		trashDir = filepath.Join(home, ".local", "share", "Trash", "files")
	}
	if err := os.MkdirAll(trashDir, 0o700); err != nil {
		return "", err
	}
	dest := filepath.Join(trashDir, fmt.Sprintf("%s-%d", filepath.Base(cleanPath), time.Now().Unix()))
	if err := os.Rename(cleanPath, dest); err != nil {
		return "", err
	}
	return dest, nil
}

// MoveVenvToTrash safely moves an orphaned Python virtualenv into the user's OS Trash (never rm -rf!).
func MoveVenvToTrash(venvPath string) (string, error) {
	cleanPath := filepath.Clean(venvPath)
	if !isPythonVenv(cleanPath) {
		return "", fmt.Errorf("安全校验拦截：%s 不是有效的 Python 虚拟环境目录", cleanPath)
	}
	return MoveDirectoryToTrash(cleanPath)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func isPythonVenv(dir string) bool {
	if _, err := os.Stat(filepath.Join(dir, "pyvenv.cfg")); err == nil {
		return true
	}
	base := filepath.Base(dir)
	if base == ".venv" || base == "venv" {
		if _, err := os.Stat(filepath.Join(dir, "bin", "python")); err == nil {
			return true
		}
	}
	return false
}

func parsePythonVenv(venvDir string) []model.AssetItem {
	var out []model.AssetItem
	libDir := filepath.Join(venvDir, "lib")
	pyDirs, err := os.ReadDir(libDir)
	if err != nil {
		return out
	}
	seen := make(map[string]bool)
	for _, pd := range pyDirs {
		if !pd.IsDir() {
			continue
		}
		sp := filepath.Join(libDir, pd.Name(), "site-packages")
		items, err := os.ReadDir(sp)
		if err != nil {
			continue
		}
		for _, it := range items {
			m := distInfoRe.FindStringSubmatch(it.Name())
			if m == nil {
				continue
			}
			pkg := strings.ToLower(strings.ReplaceAll(m[1], "_", "-"))
			ver := m[2]
			key := pkg + "@" + ver
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, model.AssetItem{
				Ecosystem: model.EcoPyPI,
				Name:      pkg,
				Version:   ver,
				Location:  venvDir,
				Kind:      "venv",
			})
		}
	}
	return out
}

func parsePackageLockJSON(path string) []model.AssetItem {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var doc struct {
		Packages map[string]struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"packages"`
		Dependencies map[string]struct {
			Version string `json:"version"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil
	}
	seen := make(map[string]bool)
	var out []model.AssetItem
	add := func(name, ver string) {
		name = strings.TrimSpace(name)
		ver = strings.TrimSpace(ver)
		if name == "" || ver == "" {
			return
		}
		k := name + "@" + ver
		if seen[k] {
			return
		}
		seen[k] = true
		out = append(out, model.AssetItem{
			Ecosystem: model.EcoNPM,
			Name:      name,
			Version:   ver,
			Location:  path,
			Kind:      "lockfile",
		})
	}

	if len(doc.Packages) > 0 {
		for pkgPath, meta := range doc.Packages {
			if pkgPath == "" {
				continue
			}
			name := meta.Name
			if name == "" {
				if idx := strings.LastIndex(pkgPath, "node_modules/"); idx >= 0 {
					name = pkgPath[idx+len("node_modules/"):]
				}
			}
			add(name, meta.Version)
		}
	} else {
		for name, meta := range doc.Dependencies {
			add(name, meta.Version)
		}
	}
	return out
}

func parsePnpmLock(path string) []model.AssetItem {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	seen := make(map[string]bool)
	var out []model.AssetItem
	inPackages := false

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "packages:") {
			inPackages = true
			continue
		}
		if inPackages && len(line) > 0 && line[0] != ' ' && line[0] != '\t' {
			inPackages = false
		}
		if !inPackages {
			continue
		}
		if m := pnpmPkgHeader.FindStringSubmatch(line); m != nil {
			name, ver := m[1], m[2]
			k := name + "@" + ver
			if !seen[k] {
				seen[k] = true
				out = append(out, model.AssetItem{
					Ecosystem: model.EcoNPM,
					Name:      name,
					Version:   ver,
					Location:  path,
					Kind:      "lockfile",
				})
			}
		}
	}
	return out
}

func parseYarnLock(path string) []model.AssetItem {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	seen := make(map[string]bool)
	var out []model.AssetItem
	curPkg := ""

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if m := yarnHeaderRe.FindStringSubmatch(strings.TrimSpace(line)); m != nil && !strings.HasPrefix(line, " ") {
			curPkg = m[1]
			continue
		}
		if curPkg != "" {
			if m := yarnVerRe.FindStringSubmatch(line); m != nil {
				ver := m[1]
				k := curPkg + "@" + ver
				if !seen[k] {
					seen[k] = true
					out = append(out, model.AssetItem{
						Ecosystem: model.EcoNPM,
						Name:      curPkg,
						Version:   ver,
						Location:  path,
						Kind:      "lockfile",
					})
				}
				curPkg = ""
			}
		}
	}
	return out
}

func parseGoMod(path string) []model.AssetItem {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	seen := make(map[string]bool)
	var out []model.AssetItem
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "//") || line == "" {
			continue
		}
		if strings.HasPrefix(line, "require ") && !strings.HasSuffix(line, "(") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "require "))
		}
		if m := goModReqRe.FindStringSubmatch(line); m != nil {
			modName := m[1]
			ver := strings.TrimSuffix(m[2], "+incompatible")
			if modName == "go" || modName == "toolchain" || modName == "module" {
				continue
			}
			k := modName + "@" + ver
			if !seen[k] {
				seen[k] = true
				out = append(out, model.AssetItem{
					Ecosystem: model.EcoGo,
					Name:      modName,
					Version:   ver,
					Location:  path,
					Kind:      "lockfile",
				})
			}
		}
	}
	return out
}

func parseTOMLPackageBlocks(path string, eco string) []model.AssetItem {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	seen := make(map[string]bool)
	var out []model.AssetItem
	inPkg := false
	curName, curVer := "", ""

	flush := func() {
		if inPkg && curName != "" && curVer != "" {
			name := curName
			if eco == model.EcoPyPI {
				name = strings.ToLower(strings.ReplaceAll(name, "_", "-"))
			}
			k := name + "@" + curVer
			if !seen[k] {
				seen[k] = true
				out = append(out, model.AssetItem{
					Ecosystem: eco,
					Name:      name,
					Version:   curVer,
					Location:  path,
					Kind:      "lockfile",
				})
			}
		}
		curName, curVer = "", ""
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "[[package]]" {
			flush()
			inPkg = true
			continue
		}
		if strings.HasPrefix(line, "[") {
			flush()
			inPkg = false
			continue
		}
		if !inPkg {
			continue
		}
		if m := cargoPkgName.FindStringSubmatch(line); m != nil && curName == "" {
			curName = m[1]
		} else if m := cargoPkgVer.FindStringSubmatch(line); m != nil && curVer == "" {
			curVer = m[1]
		}
	}
	flush()
	return out
}

func parseComposerLock(path string) []model.AssetItem {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var doc struct {
		Packages []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"packages"`
		PackagesDev []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"packages-dev"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil
	}
	var out []model.AssetItem
	seen := make(map[string]bool)
	for _, list := range [][]struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}{doc.Packages, doc.PackagesDev} {
		for _, p := range list {
			ver := strings.TrimPrefix(p.Version, "v")
			k := p.Name + "@" + ver
			if p.Name != "" && ver != "" && !seen[k] {
				seen[k] = true
				out = append(out, model.AssetItem{
					Ecosystem: model.EcoPackagist,
					Name:      p.Name,
					Version:   ver,
					Location:  path,
					Kind:      "lockfile",
				})
			}
		}
	}
	return out
}

func parseGemfileLock(path string) []model.AssetItem {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	seen := make(map[string]bool)
	var out []model.AssetItem
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if m := gemSpecRe.FindStringSubmatch(scanner.Text()); m != nil {
			k := m[1] + "@" + m[2]
			if !seen[k] {
				seen[k] = true
				out = append(out, model.AssetItem{
					Ecosystem: model.EcoRubyGems,
					Name:      m[1],
					Version:   m[2],
					Location:  path,
					Kind:      "lockfile",
				})
			}
		}
	}
	return out
}

func parseNuGetLock(path string) []model.AssetItem {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var doc struct {
		Dependencies map[string]map[string]struct {
			Resolved string `json:"resolved"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil
	}
	seen := make(map[string]bool)
	var out []model.AssetItem
	for _, tfDeps := range doc.Dependencies {
		for name, info := range tfDeps {
			if name == "" || info.Resolved == "" {
				continue
			}
			k := name + "@" + info.Resolved
			if !seen[k] {
				seen[k] = true
				out = append(out, model.AssetItem{
					Ecosystem: model.EcoNuGet,
					Name:      name,
					Version:   info.Resolved,
					Location:  path,
					Kind:      "lockfile",
				})
			}
		}
	}
	return out
}

func parseSwiftResolved(path string) []model.AssetItem {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var doc struct {
		Pins []struct {
			Identity string `json:"identity"`
			Location string `json:"location"`
			State    struct {
				Version string `json:"version"`
			} `json:"state"`
		} `json:"pins"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil
	}
	var out []model.AssetItem
	for _, pin := range doc.Pins {
		if pin.State.Version != "" && (pin.Location != "" || pin.Identity != "") {
			name := pin.Location
			if name == "" {
				name = pin.Identity
			}
			out = append(out, model.AssetItem{
				Ecosystem: model.EcoSwift,
				Name:      name,
				Version:   pin.State.Version,
				Location:  path,
				Kind:      "lockfile",
			})
		}
	}
	return out
}

func readWrapperVersion(path string, re *regexp.Regexp) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	if m := re.FindSubmatch(data); m != nil {
		return string(m[1])
	}
	return ""
}

func countInstalledJDKs() int {
	patterns := []string{
		"/Library/Java/JavaVirtualMachines/*/Contents/Home",
		"/Library/Java/JavaVirtualMachines/*",
		config.ExpandHome("~/Library/Java/JavaVirtualMachines/*/Contents/Home"),
		config.ExpandHome("~/Library/Java/JavaVirtualMachines/*"),
		config.ExpandHome("~/.sdkman/candidates/java/*"),
		config.ExpandHome("~/.jenv/versions/*"),
		config.ExpandHome("~/.local/share/mise/installs/java/*"),
		"/opt/homebrew/opt/openjdk*",
		"/usr/lib/jvm/java-*",
	}
	seen := make(map[string]bool)
	for _, pat := range patterns {
		matches, _ := filepath.Glob(pat)
		for _, m := range matches {
			if rp, err := filepath.EvalSymlinks(m); err == nil {
				m = rp
			}
			// Normalize .../Contents/Home vs bundle root so the same JDK isn't counted twice
			homeSub := filepath.Join(m, "Contents", "Home")
			if _, err := os.Stat(filepath.Join(homeSub, "bin", "java")); err == nil {
				seen[homeSub] = true
				continue
			}
			if _, err := os.Stat(filepath.Join(m, "bin", "java")); err == nil {
				seen[m] = true
			}
		}
	}
	return len(seen)
}
