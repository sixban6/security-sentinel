package config

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrivacyAndNoFakeProductionCVEGuard(t *testing.T) {
	repoRoot := filepath.Join("..", "..", "..")
	forbiddenTokens := []string{
		"sweet" + "cs",
		"six" + "leaves",
		"CVE_ATT" + "_BOT",
		"n41" + "20",
		"vps_" + "rn",
		"vps_" + "sg",
		"vps_" + "gc",
		"sec_" + "san",
		"sec_" + "los",
		"192.168." + "31.",
		"192.168." + "55.",
		"67574" + "3189",
		"90412" + "24907",
	}

	err := filepath.Walk(repoRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(repoRoot, path)
		if info.IsDir() {
			base := info.Name()
			if base == ".git" || base == "build" || base == "bin" || base == "dist" || base == ".mygo" {
				return filepath.SkipDir
			}
			return nil
		}
		// Skip gitignored user local files
		if rel == "sentinel.yaml" || rel == "latest_status.json" || strings.HasSuffix(rel, ".png") {
			return nil
		}

		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		text := string(data)
		for _, tok := range forbiddenTokens {
			if strings.Contains(text, tok) {
				t.Errorf("privacy leak: %s contains forbidden personal identifier %q", rel, tok)
			}
		}
		// Ensure fake test CVE never appears in non-test Go code
		if strings.HasSuffix(rel, ".go") && !strings.HasSuffix(rel, "_test.go") {
			if strings.Contains(text, "CVE-2026-98432") {
				t.Errorf("production code %s must not contain synthetic test fixture CVE-2026-98432", rel)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// Ensure local git repository author identity never leaks forbidden personal handles
	if out, err := exec.Command("git", "-C", repoRoot, "config", "user.name").Output(); err == nil {
		uName := strings.ToLower(strings.TrimSpace(string(out)))
		if strings.Contains(uName, "six"+"leaves") || strings.Contains(uName, "sweet"+"cs") {
			t.Fatalf("privacy leak: git user.name is %q (must use sixban6)", uName)
		}
	}
}
