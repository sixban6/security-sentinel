package ha

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/sixban6/security-sentinel/internal/infra/config"
)

func TestClashTrafficDrainSwitchesToHealthyPeer(t *testing.T) {
	var switchedTo atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/proxies/DIY-Node":
			_, _ = w.Write([]byte(`{"now":"edge_west_hy2","all":["edge_west_hy2","edge_east_hy2"]}`))
		case r.Method == http.MethodGet && r.URL.Path == "/proxies/edge_east_hy2/delay":
			_, _ = w.Write([]byte(`{"delay":88}`))
		case r.Method == http.MethodPut && r.URL.Path == "/proxies/DIY-Node":
			switchedTo.Store("edge_east_hy2")
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	cfg := config.DefaultConfig()
	cfg.Gateway = config.GatewayConfig{
		Enabled:       true,
		ClashAPIURL:   srv.URL,
		SelectorGroup: "DIY-Node",
	}
	cfg.RollingNodes = []config.RollingNodeConfig{
		{ID: "node_west", SSHHost: "root@node_west", Keywords: []string{"edge_west_hy2"}, Peer: "node_east"},
		{ID: "node_east", SSHHost: "root@node_east", Keywords: []string{"edge_east_hy2"}, Peer: "node_west"},
	}

	mgr := NewManager(cfg, nil)
	if err := mgr.DrainTrafficIfActive(context.Background(), "node_west"); err != nil {
		t.Fatalf("DrainTrafficIfActive failed: %v", err)
	}
	if got, _ := switchedTo.Load().(string); got != "edge_east_hy2" {
		t.Fatalf("expected gateway switch to edge_east_hy2, got %q", got)
	}
}
