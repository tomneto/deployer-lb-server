package lbserver

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// fakeDialer records every dial and answers healthy/unhealthy per address,
// standing in for Config.DialTimeout so no test opens a real socket.
type fakeDialer struct {
	mu        sync.Mutex
	calls     map[string]int
	unhealthy map[string]bool
}

func newFakeDialer() *fakeDialer {
	return &fakeDialer{calls: map[string]int{}, unhealthy: map[string]bool{}}
}

func (f *fakeDialer) dial(_, addr string, _ time.Duration) (net.Conn, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls[addr]++
	if f.unhealthy[addr] {
		return nil, fmt.Errorf("dial tcp %s: connection refused", addr)
	}
	return nil, nil
}

func (f *fakeDialer) callsFor(addr string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[addr]
}

func getStatus(t *testing.T, srv *Server) map[string]any {
	t.Helper()
	mux := http.NewServeMux()
	srv.Routes(mux)
	req := httptest.NewRequest(http.MethodGet, "/v1/status", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 from /v1/status, got %d: %s", rr.Code, rr.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("invalid status json: %v (body=%s)", err, rr.Body.String())
	}
	return out
}

func statusApp(t *testing.T, out map[string]any, ref string) map[string]any {
	t.Helper()
	apps, ok := out["apps"].(map[string]any)
	if !ok {
		t.Fatalf("expected apps object in status, got %v", out["apps"])
	}
	app, ok := apps[ref].(map[string]any)
	if !ok {
		t.Fatalf("expected apps[%q] object, got %v", ref, apps)
	}
	return app
}

// TestStatusEnrichedAfterApply drives the real apply path (FakeRunner) and
// asserts the C6 shape comes back from the conf the apply just wrote.
func TestStatusEnrichedAfterApply(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	now := time.Unix(1_700_000_000, 0)
	srv.cfg.Now = func() time.Time { return now }
	dialer := newFakeDialer()
	srv.cfg.DialTimeout = dialer.dial

	req := signedApplyRequest(t, now, testSecret, testToken, validPayload(7, ""))
	if status, body := doApply(t, srv, req); status != http.StatusOK {
		t.Fatalf("expected apply to succeed, got %d %v", status, body)
	}

	out := getStatus(t, srv)
	app := statusApp(t, out, "app-a")

	if rev := int64(app["applied_revision"].(float64)); rev != 7 {
		t.Fatalf("expected applied_revision 7, got %v", app["applied_revision"])
	}
	domains, _ := app["domains"].([]any)
	if len(domains) != 1 || domains[0] != "app-a.workspacefy.com" {
		t.Fatalf("expected domains [app-a.workspacefy.com], got %v", app["domains"])
	}
	upstreams, _ := app["upstreams"].([]any)
	if len(upstreams) != 1 {
		t.Fatalf("expected 1 upstream, got %v", app["upstreams"])
	}
	up := upstreams[0].(map[string]any)
	if up["host"] != "10.10.0.2" || int(up["port"].(float64)) != 10200 || up["healthy"] != true {
		t.Fatalf("unexpected upstream entry: %v", up)
	}

	// nginx/wg sections must survive the enrichment.
	if _, ok := out["nginx"]; !ok {
		t.Fatal("expected nginx section in status")
	}
	if _, ok := out["wg"]; !ok {
		t.Fatal("expected wg section in status")
	}
}

// TestStatusUnhealthyUpstream flips the fake dialer to refuse and expects
// healthy=false in the same shape.
func TestStatusUnhealthyUpstream(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	now := time.Unix(1_700_000_000, 0)
	srv.cfg.Now = func() time.Time { return now }
	dialer := newFakeDialer()
	dialer.unhealthy["10.10.0.2:10200"] = true
	srv.cfg.DialTimeout = dialer.dial

	req := signedApplyRequest(t, now, testSecret, testToken, validPayload(1, ""))
	if status, _ := doApply(t, srv, req); status != http.StatusOK {
		t.Fatal("apply failed")
	}

	app := statusApp(t, getStatus(t, srv), "app-a")
	up := app["upstreams"].([]any)[0].(map[string]any)
	if up["healthy"] != false {
		t.Fatalf("expected healthy=false for refused upstream, got %v", up)
	}
}

// TestStatusRebuiltFromDiskAfterRestart writes a managed conf fixture
// straight into ConfDir (no apply, empty in-memory state — i.e. the process
// just restarted) and expects /v1/status to report it anyway.
func TestStatusRebuiltFromDiskAfterRestart(t *testing.T) {
	srv, confDir := newTestServer(t, nil)
	dialer := newFakeDialer()
	srv.cfg.DialTimeout = dialer.dial

	fixture := `# managed-by: deployer-lb-server app=app-b revision=42
upstream app_b_pool {
    server 10.0.0.5:9000;
    server 10.0.0.6:9001;
    keepalive 16;
}
server {
    listen 80;
    server_name app-b.example.com www.app-b.example.com;
    location / { proxy_pass http://app_b_pool; }
}
`
	if err := os.WriteFile(filepath.Join(confDir, "app-b.conf"), []byte(fixture), 0o644); err != nil {
		t.Fatal(err)
	}

	app := statusApp(t, getStatus(t, srv), "app-b")
	if rev := int64(app["applied_revision"].(float64)); rev != 42 {
		t.Fatalf("expected applied_revision 42 from the conf header, got %v", app["applied_revision"])
	}
	domains := app["domains"].([]any)
	if len(domains) != 2 || domains[0] != "app-b.example.com" || domains[1] != "www.app-b.example.com" {
		t.Fatalf("unexpected domains: %v", domains)
	}
	upstreams := app["upstreams"].([]any)
	if len(upstreams) != 2 {
		t.Fatalf("expected 2 upstreams, got %v", upstreams)
	}
	first := upstreams[0].(map[string]any)
	if first["host"] != "10.0.0.5" || int(first["port"].(float64)) != 9000 {
		t.Fatalf("unexpected first upstream: %v", first)
	}
}

// TestStatusIgnoresUnmanagedConfs: hand-written confs and the default_server
// catch-all (managed-by header without app=) must never appear as apps.
func TestStatusIgnoresUnmanagedConfs(t *testing.T) {
	srv, confDir := newTestServer(t, nil)
	dialer := newFakeDialer()
	srv.cfg.DialTimeout = dialer.dial

	handWritten := "server {\n    listen 80;\n    server_name legacy.example.com;\n}\n"
	catchAll := "# managed-by: deployer-lb-server (default_server catch-all — D19)\nserver {\n    listen 80 default_server;\n    server_name _;\n    return 444;\n}\n"
	if err := os.WriteFile(filepath.Join(confDir, "legacy.conf"), []byte(handWritten), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(confDir, "00-default.conf"), []byte(catchAll), 0o644); err != nil {
		t.Fatal(err)
	}

	out := getStatus(t, srv)
	apps := out["apps"].(map[string]any)
	if len(apps) != 0 {
		t.Fatalf("expected no apps for unmanaged confs, got %v", apps)
	}
	if dialer.callsFor("legacy.example.com:80") != 0 {
		t.Fatal("expected no health probes for unmanaged confs")
	}
}

// TestStatusHealthProbeCachedForTTL asserts the ~10s memo: repeated GETs
// inside the TTL reuse the probe, and the cache expires with the injected
// clock.
func TestStatusHealthProbeCachedForTTL(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	now := time.Unix(1_700_000_000, 0)
	srv.cfg.Now = func() time.Time { return now }
	dialer := newFakeDialer()
	srv.cfg.DialTimeout = dialer.dial

	req := signedApplyRequest(t, now, testSecret, testToken, validPayload(1, ""))
	if status, _ := doApply(t, srv, req); status != http.StatusOK {
		t.Fatal("apply failed")
	}

	const addr = "10.10.0.2:10200"

	getStatus(t, srv)
	getStatus(t, srv)
	if got := dialer.callsFor(addr); got != 1 {
		t.Fatalf("expected 1 dial while inside the cache TTL, got %d", got)
	}

	// Advance past the TTL (default 10s) — next status must re-probe.
	now = now.Add(11 * time.Second)
	getStatus(t, srv)
	if got := dialer.callsFor(addr); got != 2 {
		t.Fatalf("expected a fresh dial after the TTL expired, got %d", got)
	}

	// A flip in backend health becomes visible after the next expiry.
	dialer.mu.Lock()
	dialer.unhealthy[addr] = true
	dialer.mu.Unlock()
	now = now.Add(11 * time.Second)
	app := statusApp(t, getStatus(t, srv), "app-a")
	up := app["upstreams"].([]any)[0].(map[string]any)
	if up["healthy"] != false {
		t.Fatalf("expected healthy=false after backend went down and cache expired, got %v", up)
	}
}
