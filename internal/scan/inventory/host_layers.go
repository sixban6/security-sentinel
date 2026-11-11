package inventory

import (
	"context"
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/sixban6/security-sentinel/internal/infra/config"
	"github.com/sixban6/security-sentinel/internal/infra/model"
	"github.com/sixban6/security-sentinel/internal/infra/transport"
)

var cargoCratesV1Re = regexp.MustCompile(`^"([A-Za-z0-9_\-]+)\s+([0-9][^\s"]*)\s+\(`)

// ProbeHomebrewAndAppsLayer (L2) collects full Homebrew Formulae, Homebrew Casks, and macOS /Applications bundles.
func ProbeHomebrewAndAppsLayer(ctx context.Context, exec transport.Executor, inv *model.HostInventory) {
	probe := `
export HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_INSTALL_CLEANUP=1 HOMEBREW_NO_ENV_HINTS=1
if command -v brew >/dev/null 2>&1; then
  echo "===BREW_VER===:$(brew --version 2>/dev/null | head -n 1)"
  echo "===BREW_FORMULAE==="
  brew list --formula --versions 2>/dev/null || true
  echo "===BREW_CASKS==="
  brew list --cask --versions 2>/dev/null || true
fi
`
	res, err := exec.Run(ctx, probe, 14*time.Second)
	if err == nil && res.Stdout != "" {
		sec := splitSections(res.Stdout, map[string]string{
			"===BREW_FORMULAE===": "formulae",
			"===BREW_CASKS===":    "casks",
		})
		for _, l := range strings.Split(sec["head"], "\n") {
			if strings.HasPrefix(l, "===BREW_VER===:") {
				ver := strings.TrimSpace(strings.TrimPrefix(l, "===BREW_VER===:"))
				if ver != "" {
					inv.EcosystemSummary.Toolchains = appendUniqueStr(inv.EcosystemSummary.Toolchains, ver)
				}
			}
		}

		for _, line := range strings.Split(sec["formulae"], "\n") {
			fields := strings.Fields(strings.TrimSpace(line))
			if len(fields) >= 2 {
				name := strings.ToLower(fields[0])
				ver := fields[len(fields)-1]
				inv.Packages[name] = ver
				inv.EcosystemSummary.HomebrewFormulae++
				inv.Assets = append(inv.Assets, model.AssetItem{
					Ecosystem: model.EcoHomebrew,
					Name:      name,
					Version:   ver,
					Location:  "homebrew-formula",
					Kind:      "os",
				})
			}
		}

		for _, line := range strings.Split(sec["casks"], "\n") {
			fields := strings.Fields(strings.TrimSpace(line))
			if len(fields) >= 2 {
				name := strings.ToLower(fields[0])
				ver := strings.Split(fields[len(fields)-1], ",")[0]
				inv.Packages["cask:"+name] = ver
				inv.EcosystemSummary.HomebrewCasks++
				inv.Assets = append(inv.Assets, model.AssetItem{
					Ecosystem: "Homebrew-Cask",
					Name:      name,
					Version:   ver,
					Location:  "homebrew-cask",
					Kind:      "app",
				})
			}
		}
	}

	// Count installed macOS /Applications bundles on local host
	if inv.Target.IsLocal() {
		entries, err := os.ReadDir("/Applications")
		if err == nil {
			for _, e := range entries {
				if strings.HasSuffix(e.Name(), ".app") {
					inv.EcosystemSummary.MacApps++
				}
			}
		}
	}
}

// ProbeContainerLayer (L3) uniformly collects Docker / OrbStack / Colima / Podman engine version,
// active running containers, and local container images on BOTH macOS and Linux!
func ProbeContainerLayer(ctx context.Context, exec transport.Executor, inv *model.HostInventory) {
	probe := `
RT=""
if command -v docker >/dev/null 2>&1; then RT="docker"; elif command -v podman >/dev/null 2>&1; then RT="podman"; fi
if [ -n "$RT" ]; then
  echo "RT_NAME:$RT"
  echo "RT_VER:$("$RT" version --format '{{.Server.Version}}' 2>/dev/null || "$RT" --version 2>/dev/null | head -n 1)"
  echo "===CONTAINERS==="
  "$RT" ps --format '{{.Names}}\t{{.Image}}' 2>/dev/null || true
  echo "===IMAGES==="
  "$RT" images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | head -n 100 || true
fi
`
	res, err := exec.Run(ctx, probe, 8*time.Second)
	if err != nil || res.Stdout == "" {
		return
	}

	sec := splitSections(res.Stdout, map[string]string{
		"===CONTAINERS===": "containers",
		"===IMAGES===":     "images",
	})

	rtName, rtVer := "docker", ""
	for _, l := range strings.Split(sec["head"], "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "RT_NAME:") {
			rtName = strings.TrimSpace(strings.TrimPrefix(l, "RT_NAME:"))
		} else if strings.HasPrefix(l, "RT_VER:") {
			rtVer = cleanVersionString(strings.TrimPrefix(l, "RT_VER:"))
		}
	}

	if rtVer != "" {
		inv.Packages[rtName] = rtVer
		inv.EcosystemSummary.DockerVersion = rtVer
		inv.EcosystemSummary.Toolchains = appendUniqueStr(inv.EcosystemSummary.Toolchains, strings.Title(rtName)+" "+rtVer)
		inv.Assets = append(inv.Assets, model.AssetItem{
			Ecosystem: model.EcoBinary,
			Name:      rtName,
			Version:   rtVer,
			Location:  "container-engine",
			Kind:      "binary",
		})
	}

	if inv.DockerContainers == nil {
		inv.DockerContainers = make(map[string]string)
	}
	for _, rawLine := range strings.Split(sec["containers"], "\n") {
		parts := strings.Split(strings.TrimSpace(rawLine), "\t")
		if len(parts) == 2 {
			cName := strings.ToLower(strings.TrimSpace(parts[0]))
			cImg := strings.TrimSpace(parts[1])
			if cName != "" && cImg != "" {
				inv.DockerContainers[cName] = cImg
				inv.Packages["container:"+cName] = cImg
				inv.Assets = append(inv.Assets, model.AssetItem{
					Ecosystem: model.EcoDocker,
					Name:      cName,
					Version:   cImg,
					Location:  "docker-container",
					Kind:      "container",
				})
			}
		}
	}
	inv.EcosystemSummary.DockerContainers = len(inv.DockerContainers)

	seenImg := make(map[string]bool)
	for _, rawLine := range strings.Split(sec["images"], "\n") {
		img := strings.TrimSpace(rawLine)
		if img == "" || strings.Contains(img, "<none>") || seenImg[img] {
			continue
		}
		seenImg[img] = true
		inv.EcosystemSummary.DockerImages++
		name, tag := img, "latest"
		if idx := strings.LastIndexByte(img, ':'); idx > 0 {
			name, tag = img[:idx], img[idx+1:]
		}
		inv.Assets = append(inv.Assets, model.AssetItem{
			Ecosystem: model.EcoDocker,
			Name:      name,
			Version:   tag,
			Location:  "docker-image",
			Kind:      "container-image",
		})
	}
}

// ProbeGlobalToolchainsLayer (L4) discovers global CLI packages (`npm -g`, `bun`, `cargo install`, `uv tools`, `pipx`, `pip`)
// and active multi-version managers (`pyenv`, `conda`, `nvm`/`fnm`/`volta`, `rustup`, `sdkman`, `mise`, `asdf`).
func ProbeGlobalToolchainsLayer(ctx context.Context, exec transport.Executor, inv *model.HostInventory) {
	probe := `
echo "===RUNTIMES==="
for b in go node cargo rustc php ruby dotnet swift uv bun deno singctl sing-box; do
  if command -v "$b" >/dev/null 2>&1; then
    v=$("$b" version 2>/dev/null || "$b" --version 2>/dev/null || "$b" -v 2>&1 | head -n 1)
    echo "__RT__:${b}:$(printf '%s' "$v" | head -n 1)"
  fi
done
echo "===PIP_GLOBAL==="
python3 -m pip list --format=json 2>/dev/null || true
echo "===NPM_GLOBAL==="
if command -v npm >/dev/null 2>&1; then
  npm list -g --depth=0 --json 2>/dev/null || true
fi
`
	res, err := exec.Run(ctx, probe, 12*time.Second)
	if err == nil && res.Stdout != "" {
		sec := splitSections(res.Stdout, map[string]string{
			"===RUNTIMES===":   "rt",
			"===PIP_GLOBAL===": "pip",
			"===NPM_GLOBAL===": "npm",
		})

		for _, line := range strings.Split(sec["rt"], "\n") {
			if !strings.HasPrefix(line, "__RT__:") {
				continue
			}
			parts := strings.SplitN(strings.TrimPrefix(line, "__RT__:"), ":", 2)
			if len(parts) == 2 {
				bName := strings.TrimSpace(parts[0])
				rawV := cleanVersionString(parts[1])
				if bName != "" && rawV != "" {
					inv.Packages[bName] = rawV
					inv.EcosystemSummary.GlobalTools++
					inv.Assets = append(inv.Assets, model.AssetItem{
						Ecosystem: model.EcoBinary,
						Name:      bName,
						Version:   rawV,
						Location:  "global-cli",
						Kind:      "binary",
					})
				}
			}
		}

		// Global Python pip
		if pipRaw := strings.TrimSpace(sec["pip"]); strings.HasPrefix(pipRaw, "[") {
			var pipItems []struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			}
			if json.Unmarshal([]byte(pipRaw), &pipItems) == nil {
				for _, it := range pipItems {
					name := strings.ToLower(strings.ReplaceAll(it.Name, "_", "-"))
					if name != "" && it.Version != "" {
						inv.Packages[name] = it.Version
						inv.Assets = append(inv.Assets, model.AssetItem{
							Ecosystem:    model.EcoPyPI,
							Name:         name,
							Version:      it.Version,
							Location:     "global-pip",
							Kind:         "runtime",
							ProjectName:  "全局 Python pip 环境",
							ProjectDir:   "global-pip",
							ManifestKind: "global-pip",
						})
					}
				}
			}
		}

		// Global npm -g
		if npmRaw := strings.TrimSpace(sec["npm"]); strings.HasPrefix(npmRaw, "{") {
			var npmDoc struct {
				Dependencies map[string]struct {
					Version string `json:"version"`
				} `json:"dependencies"`
			}
			if json.Unmarshal([]byte(npmRaw), &npmDoc) == nil {
				for name, info := range npmDoc.Dependencies {
					if name != "" && info.Version != "" {
						inv.EcosystemSummary.GlobalTools++
						inv.Assets = append(inv.Assets, model.AssetItem{
							Ecosystem:    model.EcoNPM,
							Name:         name,
							Version:      info.Version,
							Location:     "global-npm",
							Kind:         "runtime",
							ProjectName:  "全局 npm CLI 工具",
							ProjectDir:   "global-npm",
							ManifestKind: "npm",
						})
					}
				}
			}
		}
	}

	if !inv.Target.IsLocal() {
		return
	}

	// Local zero-subprocess file inspection for Cargo, Bun, UV Tools, and Version Managers!
	// 1. Cargo global crates (~/.cargo/.crates.toml)
	if data, err := os.ReadFile(config.ExpandHome("~/.cargo/.crates.toml")); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if m := cargoCratesV1Re.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
				inv.EcosystemSummary.GlobalTools++
				inv.Assets = append(inv.Assets, model.AssetItem{
					Ecosystem:    model.EcoCrates,
					Name:         m[1],
					Version:      m[2],
					Location:     "global-cargo",
					Kind:         "runtime",
					ProjectName:  "全局 Cargo CLI 工具",
					ProjectDir:   "global-cargo",
					ManifestKind: "cargo",
				})
			}
		}
	}

	// 2. Bun global packages (~/.bun/install/global/package.json)
	if data, err := os.ReadFile(config.ExpandHome("~/.bun/install/global/package.json")); err == nil {
		var bunDoc struct {
			Dependencies map[string]string `json:"dependencies"`
		}
		if json.Unmarshal(data, &bunDoc) == nil {
			for name, ver := range bunDoc.Dependencies {
				cleanV := strings.TrimLeft(ver, "^~>=")
				if name != "" && cleanV != "" {
					inv.EcosystemSummary.GlobalTools++
					inv.Assets = append(inv.Assets, model.AssetItem{
						Ecosystem:    model.EcoNPM,
						Name:         name,
						Version:      cleanV,
						Location:     "global-bun",
						Kind:         "runtime",
						ProjectName:  "全局 Bun CLI 工具",
						ProjectDir:   "global-bun",
						ManifestKind: "npm",
					})
				}
			}
		}
	}

	// 3. Detect installed multi-version toolchain managers on disk
	managers := []struct {
		label string
		dir   string
	}{
		{"uv", "~/.local/share/uv"},
		{"pyenv", "~/.pyenv"},
		{"conda", "~/.conda"},
		{"miniconda", "~/miniconda3"},
		{"rustup", "~/.rustup"},
		{"cargo", "~/.cargo"},
		{"bun", "~/.bun"},
		{"nvm", "~/.nvm"},
		{"fnm", "~/.fnm"},
		{"volta", "~/.volta"},
		{"sdkman", "~/.sdkman"},
		{"mise", "~/.local/share/mise"},
		{"asdf", "~/.asdf"},
		{"rbenv", "~/.rbenv"},
	}
	for _, mgr := range managers {
		if info, err := os.Stat(config.ExpandHome(mgr.dir)); err == nil && info.IsDir() {
			inv.EcosystemSummary.Toolchains = appendUniqueStr(inv.EcosystemSummary.Toolchains, mgr.label)
		}
	}
}

func appendUniqueStr(list []string, val string) []string {
	for _, x := range list {
		if strings.EqualFold(x, val) {
			return list
		}
	}
	return append(list, val)
}
