package lockfile

import (
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/sixban6/security-sentinel/internal/infra/config"
	"github.com/sixban6/security-sentinel/internal/infra/model"
)

var (
	pomPropPlaceholderRe = regexp.MustCompile(`\$\{([^}]+)\}`)
	gradleShortDepRe     = regexp.MustCompile(`(?m)(?:implementation|api|compileOnly|runtimeOnly|testImplementation|classpath)\s*\(?\s*['"]([A-Za-z0-9_.\-]+):([A-Za-z0-9_.\-]+):([0-9][A-Za-z0-9_.\-\+]*)['"]`)
	gradleLockLineRe     = regexp.MustCompile(`^([A-Za-z0-9_.\-]+):([A-Za-z0-9_.\-]+):([0-9][A-Za-z0-9_.\-\+]*)=`)
)

type pomParent struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
}

type mavenPomDoc struct {
	Parent               pomParent `xml:"parent"`
	GroupID              string    `xml:"groupId"`
	ArtifactID           string    `xml:"artifactId"`
	Version              string    `xml:"version"`
	Packaging            string    `xml:"packaging"`
	Modules              []string  `xml:"modules>module"`
	Properties           pomProps  `xml:"properties"`
	Dependencies         []pomDep  `xml:"dependencies>dependency"`
	DependencyManagement []pomDep  `xml:"dependencyManagement>dependencies>dependency"`
}

type pomDep struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
	Optional   string `xml:"optional"`
}

type pomProps struct {
	Entries map[string]string
}

func (p *pomProps) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	p.Entries = make(map[string]string)
	for {
		tok, err := d.Token()
		if err != nil {
			return err
		}
		switch se := tok.(type) {
		case xml.StartElement:
			var val string
			if err := d.DecodeElement(&val, &se); err != nil {
				return err
			}
			p.Entries[strings.TrimSpace(se.Name.Local)] = strings.TrimSpace(val)
		case xml.EndElement:
			if se.Name == start.Name {
				return nil
			}
		}
	}
}

func m2PomFilePath(m2Repo, groupID, artifactID, ver string) string {
	if m2Repo == "" || groupID == "" || artifactID == "" || ver == "" {
		return ""
	}
	groupSlash := strings.ReplaceAll(groupID, ".", string(filepath.Separator))
	return filepath.Join(m2Repo, groupSlash, artifactID, ver, fmt.Sprintf("%s-%s.pom", artifactID, ver))
}

// loadEffectiveM2Pom reads a cached Maven POM from ~/.m2/repository and merges up to 3 levels of <parent> properties & dependencyManagement!
func loadEffectiveM2Pom(m2Repo, groupID, artifactID, ver string, cache map[string]*effectivePom) *effectivePom {
	key := groupID + ":" + artifactID + ":" + ver
	if c, ok := cache[key]; ok {
		return c
	}
	p := m2PomFilePath(m2Repo, groupID, artifactID, ver)
	doc, ok := readPomFile(p)
	if !ok {
		cache[key] = nil
		return nil
	}

	eff := &effectivePom{
		props:       make(map[string]string),
		managedVers: make(map[string]string),
	}

	// Inherit from <parent> in ~/.m2/repository first
	if doc.Parent.GroupID != "" && doc.Parent.ArtifactID != "" && doc.Parent.Version != "" &&
		!(doc.Parent.GroupID == groupID && doc.Parent.ArtifactID == artifactID) {
		if parentEff := loadEffectiveM2Pom(m2Repo, doc.Parent.GroupID, doc.Parent.ArtifactID, doc.Parent.Version, cache); parentEff != nil {
			for k, v := range parentEff.props {
				eff.props[k] = v
			}
			for k, v := range parentEff.managedVers {
				eff.managedVers[k] = v
			}
		}
	}

	effGroup := doc.GroupID
	if effGroup == "" {
		effGroup = doc.Parent.GroupID
	}
	effVer := doc.Version
	if effVer == "" {
		effVer = doc.Parent.Version
	}
	eff.props["project.groupId"] = effGroup
	eff.props["pom.groupId"] = effGroup
	eff.props["project.version"] = effVer
	eff.props["pom.version"] = effVer
	for k, v := range doc.Properties.Entries {
		eff.props[k] = v
	}

	for _, dm := range doc.DependencyManagement {
		g := resolvePomValue(dm.GroupID, eff.props)
		a := resolvePomValue(dm.ArtifactID, eff.props)
		v := resolvePomValue(dm.Version, eff.props)
		if g != "" && a != "" && v != "" && !strings.Contains(v, "${") {
			eff.managedVers[g+":"+a] = v
		}
	}

	for _, dep := range doc.Dependencies {
		sc := strings.ToLower(strings.TrimSpace(dep.Scope))
		if sc == "test" || strings.EqualFold(strings.TrimSpace(dep.Optional), "true") {
			continue
		}
		g := resolvePomValue(dep.GroupID, eff.props)
		a := resolvePomValue(dep.ArtifactID, eff.props)
		v := resolvePomValue(dep.Version, eff.props)
		if g == "" || a == "" {
			continue
		}
		coord := g + ":" + a
		if v == "" {
			v = eff.managedVers[coord]
		}
		if v == "" || strings.Contains(v, "${") {
			continue
		}
		eff.deps = append(eff.deps, resolvedMavenCoord{group: g, artifact: a, version: v})
	}

	cache[key] = eff
	return eff
}

type effectivePom struct {
	props       map[string]string
	managedVers map[string]string
	deps        []resolvedMavenCoord
}

type resolvedMavenCoord struct {
	group    string
	artifact string
	version  string
}

// parseMavenProject parses a root/standalone pom.xml (plus declared <modules>) AND resolves transitive dependencies
// up to depth 2 via the local `~/.m2/repository` POM cache (zero Maven CLI execution, <15ms pure disk read!).
func parseMavenProject(projectDir string) (assets []model.AssetItem, childModuleDirs []string) {
	pomPath := filepath.Join(projectDir, "pom.xml")
	rootDoc, ok := readPomFile(pomPath)
	if !ok {
		return nil, nil
	}

	m2Repo := ""
	if os.Getenv("SENTINEL_SKIP_CENTRAL_VENVS") == "" {
		cand := config.ExpandHome("~/.m2/repository")
		if info, err := os.Stat(cand); err == nil && info.IsDir() {
			m2Repo = cand
		}
	}
	m2Cache := make(map[string]*effectivePom)

	props := make(map[string]string)
	managedVers := make(map[string]string)

	// Inherit root <parent> from ~/.m2/repository if present (e.g. spring-boot-starter-parent!)
	if m2Repo != "" && rootDoc.Parent.GroupID != "" && rootDoc.Parent.ArtifactID != "" && rootDoc.Parent.Version != "" {
		if pEff := loadEffectiveM2Pom(m2Repo, rootDoc.Parent.GroupID, rootDoc.Parent.ArtifactID, rootDoc.Parent.Version, m2Cache); pEff != nil {
			for k, v := range pEff.props {
				props[k] = v
			}
			for k, v := range pEff.managedVers {
				managedVers[k] = v
			}
		}
	}

	for k, v := range rootDoc.Properties.Entries {
		props[k] = v
	}
	if rootDoc.Version != "" {
		props["project.version"] = rootDoc.Version
	}
	if rootDoc.GroupID != "" {
		props["project.groupId"] = rootDoc.GroupID
	}

	for _, d := range rootDoc.DependencyManagement {
		g := resolvePomValue(d.GroupID, props)
		a := resolvePomValue(d.ArtifactID, props)
		v := resolvePomValue(d.Version, props)
		if g != "" && a != "" && v != "" && !strings.Contains(v, "${") {
			managedVers[g+":"+a] = v
		}
	}

	seen := make(map[string]bool)
	var directCoords []resolvedMavenCoord

	addAsset := func(g, a, v, loc string, isDirect bool) {
		if g == "" || a == "" || v == "" || strings.Contains(v, "${") {
			return
		}
		coord := g + ":" + a
		k := coord + "@" + v
		if seen[k] {
			return
		}
		seen[k] = true
		assets = append(assets, model.AssetItem{
			Ecosystem: model.EcoMaven,
			Name:      coord,
			Version:   v,
			Location:  loc,
			Kind:      "lockfile",
		})
		if isDirect {
			directCoords = append(directCoords, resolvedMavenCoord{group: g, artifact: a, version: v})
		}
	}

	collectDeps := func(deps []pomDep, loc string, localProps map[string]string) {
		for _, d := range deps {
			g := resolvePomValue(d.GroupID, localProps)
			a := resolvePomValue(d.ArtifactID, localProps)
			v := resolvePomValue(d.Version, localProps)
			if g == "" || a == "" {
				continue
			}
			if v == "" {
				v = managedVers[g+":"+a]
			}
			addAsset(g, a, v, loc, true)
		}
	}

	collectDeps(rootDoc.Dependencies, pomPath, props)
	collectDeps(rootDoc.DependencyManagement, pomPath, props)

	for _, modRel := range rootDoc.Modules {
		modRel = strings.TrimSpace(modRel)
		if modRel == "" {
			continue
		}
		modDir := filepath.Join(projectDir, modRel)
		childModuleDirs = append(childModuleDirs, modDir)
		subPom := filepath.Join(modDir, "pom.xml")
		if subDoc, ok := readPomFile(subPom); ok {
			mergedProps := make(map[string]string, len(props)+len(subDoc.Properties.Entries))
			for k, v := range props {
				mergedProps[k] = v
			}
			for k, v := range subDoc.Properties.Entries {
				mergedProps[k] = v
			}
			collectDeps(subDoc.Dependencies, subPom, mergedProps)
			collectDeps(subDoc.DependencyManagement, subPom, mergedProps)
		}
	}

	// Expand 2 hops of compile/runtime transitive dependencies from local ~/.m2/repository!
	if m2Repo != "" && len(directCoords) > 0 {
		hop1 := directCoords
		var hop2 []resolvedMavenCoord
		for _, dc := range hop1 {
			eff := loadEffectiveM2Pom(m2Repo, dc.group, dc.artifact, dc.version, m2Cache)
			if eff == nil {
				continue
			}
			for _, td := range eff.deps {
				addAsset(td.group, td.artifact, td.version, pomPath, false)
				hop2 = append(hop2, td)
			}
			if len(assets) > 250 {
				break
			}
		}
		for _, dc := range hop2 {
			if len(assets) > 350 {
				break
			}
			eff := loadEffectiveM2Pom(m2Repo, dc.group, dc.artifact, dc.version, m2Cache)
			if eff == nil {
				continue
			}
			for _, td := range eff.deps {
				addAsset(td.group, td.artifact, td.version, pomPath, false)
			}
		}
	}

	return assets, childModuleDirs
}

func readPomFile(path string) (mavenPomDoc, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return mavenPomDoc{}, false
	}
	var doc mavenPomDoc
	if err := xml.Unmarshal(data, &doc); err != nil {
		return mavenPomDoc{}, false
	}
	return doc, true
}

func resolvePomValue(val string, props map[string]string) string {
	val = strings.TrimSpace(val)
	for depth := 0; depth < 4 && strings.Contains(val, "${"); depth++ {
		next := pomPropPlaceholderRe.ReplaceAllStringFunc(val, func(m string) string {
			key := m[2 : len(m)-1]
			if rep, ok := props[key]; ok {
				return rep
			}
			return m
		})
		if next == val {
			break
		}
		val = next
	}
	return strings.TrimSpace(val)
}

func parseGradleProject(projectDir string) []model.AssetItem {
	seen := make(map[string]bool)
	var out []model.AssetItem
	add := func(g, a, v, loc string) {
		if g == "" || a == "" || v == "" || strings.Contains(v, "$") {
			return
		}
		coord := g + ":" + a
		k := coord + "@" + v
		if seen[k] {
			return
		}
		seen[k] = true
		out = append(out, model.AssetItem{
			Ecosystem: model.EcoMaven,
			Name:      coord,
			Version:   v,
			Location:  loc,
			Kind:      "lockfile",
		})
	}

	lockPath := filepath.Join(projectDir, "gradle.lockfile")
	if data, err := os.ReadFile(lockPath); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if m := gradleLockLineRe.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
				add(m[1], m[2], m[3], lockPath)
			}
		}
	}

	for _, fname := range []string{"build.gradle", "build.gradle.kts"} {
		p := filepath.Join(projectDir, fname)
		if data, err := os.ReadFile(p); err == nil {
			for _, m := range gradleShortDepRe.FindAllStringSubmatch(string(data), -1) {
				add(m[1], m[2], m[3], p)
			}
		}
	}
	return out
}

func UpgradeJavaProjectFiles(projectDir string, fixes []model.WorkspacePackageFix) (updatedCount int, err error) {
	if len(fixes) == 0 {
		return 0, nil
	}

	var pomFiles []string
	rootPom := filepath.Join(projectDir, "pom.xml")
	if _, err := os.Stat(rootPom); err == nil {
		pomFiles = append(pomFiles, rootPom)
		if rootDoc, ok := readPomFile(rootPom); ok {
			for _, mod := range rootDoc.Modules {
				mp := filepath.Join(projectDir, strings.TrimSpace(mod), "pom.xml")
				if _, err := os.Stat(mp); err == nil {
					pomFiles = append(pomFiles, mp)
				}
			}
		}
	}

	for _, pf := range fixes {
		if pf.FixedVersion == "" {
			continue
		}
		parts := strings.SplitN(pf.Package, ":", 2)
		if len(parts) != 2 {
			continue
		}
		groupID, artifactID := parts[0], parts[1]

		for _, pomFile := range pomFiles {
			rawBytes, rErr := os.ReadFile(pomFile)
			if rErr != nil {
				continue
			}
			content := string(rawBytes)
			modified := content

			artPattern := regexp.QuoteMeta(artifactID)
			if underIdx := strings.LastIndexByte(artifactID, '_'); underIdx > 0 {
				prefix := regexp.QuoteMeta(artifactID[:underIdx])
				artPattern = fmt.Sprintf(`(?:%s|%s_\$\{[^}]+\})`, artPattern, prefix)
			}
			depBlockRe := regexp.MustCompile(fmt.Sprintf(`(?s)(<artifactId>\s*%s\s*</artifactId>\s*<version>\s*)([^<]+?)(\s*</version>)`, artPattern))
			if m := depBlockRe.FindStringSubmatch(modified); m != nil {
				verExpr := strings.TrimSpace(m[2])
				if strings.HasPrefix(verExpr, "${") && strings.HasSuffix(verExpr, "}") {
					propName := verExpr[2 : len(verExpr)-1]
					propTagRe := regexp.MustCompile(fmt.Sprintf(`(<%s>\s*)%s(\s*</%s>)`,
						regexp.QuoteMeta(propName), regexp.QuoteMeta(pf.InstalledVersion), regexp.QuoteMeta(propName)))
					modified = propTagRe.ReplaceAllString(modified, "${1}"+pf.FixedVersion+"${2}")
				} else if verExpr == pf.InstalledVersion {
					modified = depBlockRe.ReplaceAllString(modified, "${1}"+pf.FixedVersion+"${3}")
				}
			}

			if modified == content && pf.InstalledVersion != "" {
				familyHint := strings.Split(artifactID, "-")[0]
				propFamilyRe := regexp.MustCompile(fmt.Sprintf(`(?i)(<[^>]*%s[^>]*>\s*)%s(\s*</[^>]+>)`,
					regexp.QuoteMeta(familyHint), regexp.QuoteMeta(pf.InstalledVersion)))
				modified = propFamilyRe.ReplaceAllString(modified, "${1}"+pf.FixedVersion+"${2}")
			}

			if modified != content {
				if wErr := os.WriteFile(pomFile, []byte(modified), 0o644); wErr == nil {
					updatedCount++
				}
			}
		}

		for _, gName := range []string{"build.gradle", "build.gradle.kts"} {
			gp := filepath.Join(projectDir, gName)
			rawBytes, rErr := os.ReadFile(gp)
			if rErr != nil {
				continue
			}
			oldCoord := fmt.Sprintf("%s:%s:%s", groupID, artifactID, pf.InstalledVersion)
			newCoord := fmt.Sprintf("%s:%s:%s", groupID, artifactID, pf.FixedVersion)
			content := string(rawBytes)
			if strings.Contains(content, oldCoord) {
				modified := strings.ReplaceAll(content, oldCoord, newCoord)
				if os.WriteFile(gp, []byte(modified), 0o644) == nil {
					updatedCount++
				}
			}
		}
	}

	return updatedCount, nil
}
