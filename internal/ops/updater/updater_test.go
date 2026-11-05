package updater

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCheckLatestAndAtomicVerifiedUpgrade(t *testing.T) {
	assetName := CLIAssetName(runtime.GOOS, runtime.GOARCH)
	fakeBin := bytes.Repeat([]byte("SENTINEL_V2_BINARY_PAYLOAD_"), 120)
	sum := sha256.Sum256(fakeBin)
	sumHex := hex.EncodeToString(sum[:])

	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/sixban6/security-sentinel/releases/latest":
			_, _ = fmt.Fprintf(w, `{
  "tag_name": "v2.1.0",
  "body": "Faster SSH probes and WezTerm support",
  "assets": [
    {"name": %q, "browser_download_url": "%s/dl/%s"},
    {"name": "checksums.txt", "browser_download_url": "%s/dl/checksums.txt"}
  ]
}`, assetName, srvURL, assetName, srvURL)
		case "/dl/" + assetName:
			_, _ = w.Write(fakeBin)
		case "/dl/checksums.txt":
			_, _ = fmt.Fprintf(w, "%s  %s\n", sumHex, assetName)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	srvURL = srv.URL

	cli := NewClient()
	cli.APIBaseURL = srv.URL

	rel, err := cli.CheckLatest(context.Background(), "2.0.0")
	if err != nil {
		t.Fatalf("CheckLatest failed: %v", err)
	}
	if !rel.HasUpdate || rel.Version != "2.1.0" {
		t.Fatalf("expected HasUpdate=true for 2.0.0 -> 2.1.0, got %+v", rel)
	}

	targetBin := filepath.Join(t.TempDir(), "security-sentinel")
	_ = os.WriteFile(targetBin, []byte("old"), 0o755)

	updatedPath, err := cli.UpgradeCLI(context.Background(), rel, targetBin)
	if err != nil {
		t.Fatalf("UpgradeCLI failed: %v", err)
	}
	gotBytes, err := os.ReadFile(updatedPath)
	if err != nil || !bytes.Equal(gotBytes, fakeBin) {
		t.Fatal("upgraded binary content mismatch")
	}
}
