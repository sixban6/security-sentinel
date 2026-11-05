package intel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sixban6/security-sentinel/internal/infra/store"
	"github.com/sixban6/security-sentinel/internal/infra/model"
)

func TestOSVQueryBatchAndKernelAtomFeed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/querybatch":
			_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"GHSA-xxxx-yyyy-zzzz"}]}]}`))
		case "/v1/vulns/GHSA-xxxx-yyyy-zzzz":
			_, _ = w.Write([]byte(`{
  "id": "GHSA-xxxx-yyyy-zzzz",
  "aliases": ["CVE-2025-99999"],
  "summary": "Remote code execution in litellm proxy",
  "database_specific": {"severity": "CRITICAL"},
  "affected": [{"package":{"ecosystem":"PyPI","name":"litellm"},"ranges":[{"events":[{"fixed":"1.35.0"}]}]}]
}`))
		case "/atom":
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <entry>
    <title>CVE-2025-40001: net: tcp: fix use-after-free in syn_recv</title>
    <link href="https://lore.kernel.org/r/123"/>
    <content>Issue introduced in 5.15 and fixed in 6.1.130 and fixed in 6.6.80</content>
  </entry>
</feed>`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	mem := store.New(t.TempDir())
	cli := NewClient(mem)
	cli.OSVBaseURL = srv.URL
	cli.KernelAtomURL = srv.URL + "/atom"

	hits := cli.QueryOSVAssets(context.Background(), []OSVQuery{
		{Ecosystem: model.EcoPyPI, Name: "litellm", Version: "1.30.0"},
	})
	qk := QueryKey(model.EcoPyPI, "litellm", "1.30.0")
	if len(hits[qk]) != 1 || hits[qk][0].CVEID != "CVE-2025-99999" || hits[qk][0].Severity != "CRITICAL" {
		t.Fatalf("unexpected OSV batch enrichment: %+v", hits)
	}

	kAdvs := cli.FetchKernelAdvisories(context.Background(), 30)
	if len(kAdvs) != 1 || kAdvs["CVE-2025-40001"].Severity != "CRITICAL" {
		t.Fatalf("unexpected kernel atom parse: %+v", kAdvs)
	}
	if _, hasFake := kAdvs["CVE-2026-98432"]; hasFake {
		t.Fatal("production kernel feed must NOT contain hardcoded fake CVE-2026-98432")
	}
}
