package lockfile

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sixban6/security-sentinel/internal/infra/model"
)

func TestScanWorkspacesExtractsRealVenvAndLockfilePackagesWithoutDoubleCounting(t *testing.T) {
	t.Setenv("SENTINEL_SKIP_CENTRAL_VENVS", "1")
	root := t.TempDir()

	// 1. Project with BOTH uv.lock AND .venv -> must NOT double-count litellm!
	uvProj := filepath.Join(root, "ai-service")
	venvSP := filepath.Join(uvProj, ".venv", "lib", "python3.12", "site-packages")
	if err := os.MkdirAll(filepath.Join(venvSP, "litellm-1.30.0.dist-info"), 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(uvProj, ".venv", "pyvenv.cfg"), []byte("version = 3.12.2\n"), 0o644)
	_ = os.WriteFile(filepath.Join(uvProj, "uv.lock"), []byte("[[package]]\nname = \"litellm\"\nversion = \"1.30.0\"\n"), 0o644)

	// 2. Backup scrap directory (app_bak) -> must be ignored!
	bakDir := filepath.Join(root, "app_bak")
	_ = os.MkdirAll(bakDir, 0o755)
	_ = os.WriteFile(filepath.Join(bakDir, "package.json"), []byte(`{"name":"old"}`), 0o644)
	_ = os.WriteFile(filepath.Join(bakDir, "package-lock.json"), []byte(`{"lockfileVersion":3,"packages":{"node_modules/axios":{"version":"0.21.1"}}}`), 0o644)

	// 3. Active Node.js, Go, and Rust projects
	webDir := filepath.Join(root, "web-portal")
	_ = os.MkdirAll(webDir, 0o755)
	_ = os.WriteFile(filepath.Join(webDir, "package.json"), []byte(`{"name":"portal"}`), 0o644)
	_ = os.WriteFile(filepath.Join(webDir, "package-lock.json"), []byte(`{
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "portal", "version": "1.0.0"},
    "node_modules/next": {"version": "14.1.0"}
  }
}`), 0o644)

	goDir := filepath.Join(root, "proxy-gw")
	_ = os.MkdirAll(goDir, 0o755)
	_ = os.WriteFile(filepath.Join(goDir, "go.mod"), []byte("module example.com/gw\n\ngo 1.24\n\nrequire (\n\tgolang.org/x/crypto v0.17.0\n)\n"), 0o644)

	rsDir := filepath.Join(root, "crypto-rs")
	_ = os.MkdirAll(rsDir, 0o755)
	_ = os.WriteFile(filepath.Join(rsDir, "Cargo.toml"), []byte("[package]\nname = \"crypto-rs\"\n"), 0o644)
	_ = os.WriteFile(filepath.Join(rsDir, "Cargo.lock"), []byte("[[package]]\nname = \"rustls\"\nversion = \"0.21.5\"\n"), 0o644)

	res := ScanWorkspaces([]string{root})
	if res.Summary.PythonVenvs != 1 || res.Summary.NodeProjects != 1 || res.Summary.GoModules != 1 || res.Summary.RustCrates != 1 {
		t.Fatalf("unexpected workspace summary: %+v", res.Summary)
	}

	litellmCount := 0
	found := make(map[string]string)
	for _, a := range res.Assets {
		if a.Name == "litellm" {
			litellmCount++
		}
		if a.Name == "axios" {
			t.Fatal("expected app_bak backup folder to be skipped!")
		}
		found[a.Ecosystem+":"+a.Name] = a.Version
	}
	if litellmCount != 1 {
		t.Fatalf("expected litellm counted ONCE despite both uv.lock and .venv, got %d", litellmCount)
	}

	checks := map[string]string{
		model.EcoPyPI + ":litellm":           "1.30.0",
		model.EcoNPM + ":next":               "14.1.0",
		model.EcoGo + ":golang.org/x/crypto": "0.17.0",
		model.EcoCrates + ":rustls":          "0.21.5",
	}
	for k, wantVer := range checks {
		if got := found[k]; got != wantVer {
			t.Errorf("asset %s = %q, want %q (all=%v)", k, got, wantVer, found)
		}
	}
}

func TestJavaMavenPropertyInterpolationMultiModuleAndNativeUpgrade(t *testing.T) {
	t.Setenv("SENTINEL_SKIP_CENTRAL_VENVS", "1")
	root := t.TempDir()

	javaProj := filepath.Join(root, "flink-analytics")
	subMod := filepath.Join(javaProj, "stream-job")
	_ = os.MkdirAll(subMod, 0o755)

	_ = os.WriteFile(filepath.Join(javaProj, "pom.xml"), []byte(`<?xml version="1.0" encoding="UTF-8"?>
<project>
  <groupId>com.example</groupId>
  <artifactId>flink-analytics</artifactId>
  <version>1.0</version>
  <modules><module>stream-job</module></modules>
  <properties>
    <log4j.ver>2.13.3</log4j.ver>
    <scala.bin>2.11</scala.bin>
  </properties>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.apache.logging.log4j</groupId>
        <artifactId>log4j-core</artifactId>
        <version>${log4j.ver}</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>`), 0o644)

	_ = os.WriteFile(filepath.Join(subMod, "pom.xml"), []byte(`<?xml version="1.0" encoding="UTF-8"?>
<project>
  <artifactId>stream-job</artifactId>
  <dependencies>
    <dependency>
      <groupId>org.apache.flink</groupId>
      <artifactId>flink-clients_${scala.bin}</artifactId>
      <version>1.12.0</version>
    </dependency>
  </dependencies>
</project>`), 0o644)

	res := ScanWorkspaces([]string{root})
	if res.Summary.JavaProjects != 1 {
		t.Fatalf("expected multi-module Maven project consolidated as 1 JavaProject, got %d", res.Summary.JavaProjects)
	}
	got := make(map[string]string)
	for _, a := range res.Assets {
		got[a.Name] = a.Version
	}
	if got["org.apache.logging.log4j:log4j-core"] != "2.13.3" || got["org.apache.flink:flink-clients_2.11"] != "1.12.0" {
		t.Fatalf("unexpected Maven parsed coordinates: %+v", got)
	}

	// Test native Go pom.xml property & inline version upgrade without mvn CLI!
	updated, err := UpgradeJavaProjectFiles(javaProj, []model.WorkspacePackageFix{
		{Package: "org.apache.logging.log4j:log4j-core", InstalledVersion: "2.13.3", FixedVersion: "2.17.1"},
		{Package: "org.apache.flink:flink-clients_2.11", InstalledVersion: "1.12.0", FixedVersion: "1.18.1"},
	})
	if err != nil || updated < 2 {
		t.Fatalf("UpgradeJavaProjectFiles updated=%d err=%v", updated, err)
	}
	afterAssets := ScanSingleProject(javaProj)
	afterMap := make(map[string]string)
	for _, a := range afterAssets {
		afterMap[a.Name] = a.Version
	}
	if afterMap["org.apache.logging.log4j:log4j-core"] != "2.17.1" || afterMap["org.apache.flink:flink-clients_2.11"] != "1.18.1" {
		t.Fatalf("expected upgraded Maven versions, got %+v", afterMap)
	}
}
