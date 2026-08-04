package lbserver

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/tomneto/deployer-lb-server/internal/auth"
	"github.com/tomneto/deployer-lb-server/internal/nginx"
	"github.com/tomneto/deployer-lb-server/internal/render"
)

const testTemplate = `# managed-by: deployer-lb-server app={{.PipelineRef}} revision={{.Revision}}
upstream {{ upstreamName .PipelineRef }} {
{{- range .Upstreams}}
    server {{.IP}}:{{.Port}};
{{- end}}
}
server {
    listen 80;
    server_name {{ join .Domains " " }};
    location / {
        proxy_pass http://{{ upstreamName .PipelineRef }};
    }
}
`

const testToken = "test-token"
const testSecret = "test-secret"

func newTestServer(t *testing.T, runner nginx.Runner) (*Server, string) {
	t.Helper()
	confDir := t.TempDir()
	tmplPath := filepath.Join(t.TempDir(), "nginx-app.conf.tmpl")
	if err := os.WriteFile(tmplPath, []byte(testTemplate), 0o644); err != nil {
		t.Fatal(err)
	}
	if runner == nil {
		runner = nginx.NewFakeRunner()
	}
	srv := New(Config{
		Token:        testToken,
		Secret:       testSecret,
		ConfDir:      confDir,
		TemplatePath: tmplPath,
		Runner:       runner,
		TSWindow:     30 * time.Second,
		NonceTTL:     5 * time.Minute,
	})
	return srv, confDir
}

func validPayload(rev int64, idemKey string) render.Payload {
	if idemKey == "" {
		idemKey = fmt.Sprintf("app-a:run-%d", rev)
	}
	return render.Payload{
		SchemaVersion:  render.SupportedSchemaVersion,
		Revision:       rev,
		IdempotencyKey: idemKey,
		PipelineRef:    "app-a",
		Repo:           "owner/app-a",
		Domains:        []string{"app-a.workspacefy.com"},
		Exposure:       "external",
		Upstreams:      []render.Upstream{{IP: "10.10.0.2", Port: 10200}},
		Timeouts:       render.Timeouts{Read: 120, Send: 120, Connect: 10},
	}
}

// signedApplyRequest builds a POST /v1/apply request signed exactly the way
// the backoffice engine is expected to sign it (§2.3).
func signedApplyRequest(t *testing.T, now time.Time, secret, token string, payload render.Payload) *http.Request {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return signedRequest(t, http.MethodPost, "/v1/apply", now, secret, token, body, fmt.Sprintf("nonce-%d-%s", payload.Revision, payload.IdempotencyKey))
}

func signedRequest(t *testing.T, method, path string, now time.Time, secret, token string, body []byte, nonce string) *http.Request {
	t.Helper()
	ts := fmt.Sprintf("%d", now.Unix())
	sig := computeSig(secret, ts, nonce, body)
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Payload-Ts", ts)
	req.Header.Set("X-Payload-Nonce", nonce)
	req.Header.Set("X-Payload-Sig", sig)
	return req
}

func computeSig(secret, ts, nonce string, body []byte) string {
	return auth.ComputeSignature(secret, ts, nonce, body)
}

func doApply(t *testing.T, srv *Server, req *http.Request) (int, map[string]any) {
	t.Helper()
	rr := httptest.NewRecorder()
	mux := http.NewServeMux()
	srv.Routes(mux)
	mux.ServeHTTP(rr, req)
	var out map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("invalid json response: %v (body=%s)", err, rr.Body.String())
	}
	return rr.Code, out
}

func TestApplySuccessReloadsAndWritesFile(t *testing.T) {
	srv, confDir := newTestServer(t, nil)
	now := time.Unix(1_700_000_000, 0)
	srv.cfg.Now = func() time.Time { return now }

	req := signedApplyRequest(t, now, testSecret, testToken, validPayload(1, ""))
	status, body := doApply(t, srv, req)

	if status != http.StatusOK || body["status"] != "reloaded" {
		t.Fatalf("expected 200 reloaded, got %d %v", status, body)
	}
	if int64(body["applied_revision"].(float64)) != 1 {
		t.Fatalf("expected applied_revision 1, got %v", body["applied_revision"])
	}

	content, err := os.ReadFile(filepath.Join(confDir, "app-a.conf"))
	if err != nil {
		t.Fatalf("expected conf file to be written: %v", err)
	}
	if !bytes.HasPrefix(content, []byte("# managed-by:")) {
		t.Fatalf("expected managed-by header, got: %s", content)
	}
}

func TestApplyInvalidBearerRejected(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	now := time.Unix(1_700_000_000, 0)
	srv.cfg.Now = func() time.Time { return now }

	req := signedApplyRequest(t, now, testSecret, "wrong-token", validPayload(1, ""))
	status, _ := doApply(t, srv, req)
	if status != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", status)
	}
}

func TestApplyInvalidSignatureRejected(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	now := time.Unix(1_700_000_000, 0)
	srv.cfg.Now = func() time.Time { return now }

	p := validPayload(1, "")
	body, _ := json.Marshal(p)
	req := httptest.NewRequest(http.MethodPost, "/v1/apply", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("X-Payload-Ts", fmt.Sprintf("%d", now.Unix()))
	req.Header.Set("X-Payload-Nonce", "nonce-x")
	req.Header.Set("X-Payload-Sig", "sha256=deadbeef")

	status, _ := doApply(t, srv, req)
	if status != http.StatusUnauthorized {
		t.Fatalf("expected 401 for bad signature, got %d", status)
	}
}

func TestApplyNonceReplayRejected(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	now := time.Unix(1_700_000_000, 0)
	srv.cfg.Now = func() time.Time { return now }

	p := validPayload(1, "")
	body, _ := json.Marshal(p)
	req1 := signedRequest(t, http.MethodPost, "/v1/apply", now, testSecret, testToken, body, "fixed-nonce")
	status1, _ := doApply(t, srv, req1)
	if status1 != http.StatusOK {
		t.Fatalf("expected first request to succeed, got %d", status1)
	}

	p2 := validPayload(2, "app-a:run-2")
	body2, _ := json.Marshal(p2)
	req2 := signedRequest(t, http.MethodPost, "/v1/apply", now, testSecret, testToken, body2, "fixed-nonce")
	status2, body2Resp := doApply(t, srv, req2)
	if status2 != http.StatusUnauthorized {
		t.Fatalf("expected replayed nonce to be rejected with 401, got %d %v", status2, body2Resp)
	}
}

func TestApplyTimestampOutsideWindowRejected(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	now := time.Unix(1_700_000_000, 0)
	srv.cfg.Now = func() time.Time { return now }

	old := now.Add(-1 * time.Hour)
	req := signedApplyRequest(t, old, testSecret, testToken, validPayload(1, ""))
	status, _ := doApply(t, srv, req)
	if status != http.StatusUnauthorized {
		t.Fatalf("expected 401 for stale timestamp, got %d", status)
	}
}

func TestApplyStaleRevisionRejected(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	now := time.Unix(1_700_000_000, 0)
	srv.cfg.Now = func() time.Time { return now }

	req1 := signedApplyRequest(t, now, testSecret, testToken, validPayload(5, "app-a:run-5"))
	status1, body1 := doApply(t, srv, req1)
	if status1 != http.StatusOK {
		t.Fatalf("expected first apply to succeed, got %d %v", status1, body1)
	}

	req2 := signedApplyRequest(t, now, testSecret, testToken, validPayload(3, "app-a:run-3"))
	status2, body2 := doApply(t, srv, req2)
	if status2 != http.StatusConflict {
		t.Fatalf("expected 409 for stale revision, got %d %v", status2, body2)
	}
	if int64(body2["applied_revision"].(float64)) != 5 {
		t.Fatalf("expected applied_revision=5 in conflict body, got %v", body2)
	}
}

func TestApplyRepeatedIdempotencyKeyIsNoop(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	now := time.Unix(1_700_000_000, 0)
	srv.cfg.Now = func() time.Time { return now }

	p := validPayload(1, "app-a:run-1")
	req1 := signedApplyRequest(t, now, testSecret, testToken, p)
	status1, _ := doApply(t, srv, req1)
	if status1 != http.StatusOK {
		t.Fatalf("expected first apply to succeed, got %d", status1)
	}

	// Same idempotency key, different (even higher) revision: must still be
	// treated as a replay/no-op, not reprocessed.
	p2 := p
	p2.Revision = 2
	req2 := signedApplyRequest(t, now, testSecret, testToken, p2)
	// Reuse a fresh nonce (nonce replay is a separate protection).
	req2.Header.Set("X-Payload-Nonce", "another-nonce")
	body, _ := json.Marshal(p2)
	req2.Header.Set("X-Payload-Sig", computeSig(testSecret, req2.Header.Get("X-Payload-Ts"), "another-nonce", body))

	status2, body2 := doApply(t, srv, req2)
	if status2 != http.StatusOK || body2["status"] != "noop" {
		t.Fatalf("expected 200 noop for repeated idempotency_key, got %d %v", status2, body2)
	}
}

func TestApplyMalformedPayloadRejectedBeforeDiskWrite(t *testing.T) {
	srv, confDir := newTestServer(t, nil)
	now := time.Unix(1_700_000_000, 0)
	srv.cfg.Now = func() time.Time { return now }

	p := validPayload(1, "")
	p.PipelineRef = "../../etc/passwd" // path traversal attempt
	req := signedApplyRequest(t, now, testSecret, testToken, p)
	status, body := doApply(t, srv, req)
	if status != http.StatusBadRequest || body["status"] != "invalid" {
		t.Fatalf("expected 400 invalid, got %d %v", status, body)
	}

	entries, _ := os.ReadDir(confDir)
	if len(entries) != 0 {
		t.Fatalf("expected no files written for invalid payload, got %v", entries)
	}
}

func TestApplyMalformedJSONRejected(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	now := time.Unix(1_700_000_000, 0)
	srv.cfg.Now = func() time.Time { return now }

	body := []byte(`{not-json`)
	req := signedRequest(t, http.MethodPost, "/v1/apply", now, testSecret, testToken, body, "nonce-bad-json")
	status, respBody := doApply(t, srv, req)
	if status != http.StatusBadRequest || respBody["status"] != "invalid" {
		t.Fatalf("expected 400 invalid for malformed json, got %d %v", status, respBody)
	}
}

func TestApplyBodyTooLargeRejected(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	srv.cfg.MaxBodyBytes = 10 // tiny limit
	now := time.Unix(1_700_000_000, 0)
	srv.cfg.Now = func() time.Time { return now }

	p := validPayload(1, "")
	body, _ := json.Marshal(p)
	if len(body) <= 10 {
		t.Fatal("test payload must exceed the tiny limit")
	}
	req := signedRequest(t, http.MethodPost, "/v1/apply", now, testSecret, testToken, body, "nonce-big")
	status, respBody := doApply(t, srv, req)
	if status != http.StatusBadRequest {
		t.Fatalf("expected 400 for oversized body, got %d %v", status, respBody)
	}
}

func TestApplyNginxTestFailureReturnsInvalidAndLeavesActiveFileUntouched(t *testing.T) {
	fake := nginx.NewFakeRunner()
	fake.TestFunc = func(string) (bool, string, error) {
		return false, "nginx: [emerg] unexpected \"}\"", fmt.Errorf("exit status 1")
	}
	srv, confDir := newTestServer(t, fake)
	now := time.Unix(1_700_000_000, 0)
	srv.cfg.Now = func() time.Time { return now }

	req := signedApplyRequest(t, now, testSecret, testToken, validPayload(1, ""))
	status, body := doApply(t, srv, req)
	if status != http.StatusBadRequest || body["status"] != "invalid" {
		t.Fatalf("expected 400 invalid, got %d %v", status, body)
	}
	if _, err := os.Stat(filepath.Join(confDir, "app-a.conf")); err == nil {
		t.Fatal("expected no file to be promoted when nginx -t fails")
	}
}

func TestApplyOneAppFailingDoesNotBlockAnother(t *testing.T) {
	fake := nginx.NewFakeRunner()
	fake.TestFunc = func(confDir string) (bool, string, error) {
		data, _ := os.ReadFile(filepath.Join(confDir, "broken-app.conf"))
		if bytes.Contains(data, []byte("broken-app")) {
			return false, "broken-app.conf: syntax error", fmt.Errorf("exit status 1")
		}
		return true, "ok", nil
	}
	srv, _ := newTestServer(t, fake)
	now := time.Unix(1_700_000_000, 0)
	srv.cfg.Now = func() time.Time { return now }

	broken := validPayload(1, "broken-app:run-1")
	broken.PipelineRef = "broken-app"
	broken.Repo = "owner/broken-app"
	broken.Domains = []string{"broken-app.workspacefy.com"}
	reqBroken := signedApplyRequest(t, now, testSecret, testToken, broken)
	statusBroken, bodyBroken := doApply(t, srv, reqBroken)
	if statusBroken != http.StatusBadRequest {
		t.Fatalf("expected broken app to be rejected, got %d %v", statusBroken, bodyBroken)
	}

	good := validPayload(1, "app-a:run-1")
	reqGood := signedApplyRequest(t, now, testSecret, testToken, good)
	statusGood, bodyGood := doApply(t, srv, reqGood)
	if statusGood != http.StatusOK || bodyGood["status"] != "reloaded" {
		t.Fatalf("expected unrelated good app to still succeed, got %d %v", statusGood, bodyGood)
	}
}

func TestApplyReloadFailureRevertsFile(t *testing.T) {
	fake := nginx.NewFakeRunner()
	srv, confDir := newTestServer(t, fake)
	now := time.Unix(1_700_000_000, 0)
	srv.cfg.Now = func() time.Time { return now }

	// First apply succeeds and leaves a known-good file behind.
	req1 := signedApplyRequest(t, now, testSecret, testToken, validPayload(1, "app-a:run-1"))
	status1, _ := doApply(t, srv, req1)
	if status1 != http.StatusOK {
		t.Fatalf("expected first apply to succeed, got %d", status1)
	}
	original, err := os.ReadFile(filepath.Join(confDir, "app-a.conf"))
	if err != nil {
		t.Fatal(err)
	}

	// Second apply passes nginx -t but fails to reload.
	fake.ReloadFunc = func() (string, error) { return "reload failed", fmt.Errorf("systemctl error") }
	req2 := signedApplyRequest(t, now, testSecret, testToken, validPayload(2, "app-a:run-2"))
	status2, body2 := doApply(t, srv, req2)
	if status2 != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 on reload failure, got %d %v", status2, body2)
	}

	reverted, err := os.ReadFile(filepath.Join(confDir, "app-a.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, reverted) {
		t.Fatalf("expected file to be reverted to previous version after failed reload")
	}
}

func TestApplyLegacyServerNameCollisionRejected(t *testing.T) {
	fake := nginx.NewFakeRunner()
	fake.DumpFunc = func() (string, error) {
		return `# configuration file /etc/nginx/conf.d/legacy.conf:
server {
    server_name app-a.workspacefy.com;
}
`, nil
	}
	srv, _ := newTestServer(t, fake)
	now := time.Unix(1_700_000_000, 0)
	srv.cfg.Now = func() time.Time { return now }

	req := signedApplyRequest(t, now, testSecret, testToken, validPayload(1, ""))
	status, body := doApply(t, srv, req)
	if status != http.StatusConflict || body["reason"] != "legacy_server_name" {
		t.Fatalf("expected 409 legacy_server_name, got %d %v", status, body)
	}
}

func TestApplyDomainClaimedByAnotherAppRejected(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	now := time.Unix(1_700_000_000, 0)
	srv.cfg.Now = func() time.Time { return now }

	// app-a claims app-a.workspacefy.com first.
	req1 := signedApplyRequest(t, now, testSecret, testToken, validPayload(1, "app-a:run-1"))
	status1, _ := doApply(t, srv, req1)
	if status1 != http.StatusOK {
		t.Fatalf("expected first apply to succeed, got %d", status1)
	}

	// app-b tries to claim the same domain.
	other := validPayload(1, "app-b:run-1")
	other.PipelineRef = "app-b"
	other.Repo = "owner/app-b"
	// same domain as app-a
	req2 := signedApplyRequest(t, now, testSecret, testToken, other)
	status2, body2 := doApply(t, srv, req2)
	if status2 != http.StatusConflict {
		t.Fatalf("expected 409 conflict for domain claimed by another app, got %d %v", status2, body2)
	}
}

func TestApplyConcurrentSameAppCoalescesToHighestRevision(t *testing.T) {
	fake := nginx.NewFakeRunner()
	var testCallCount int
	var muCount sync.Mutex
	fake.TestFunc = func(string) (bool, string, error) {
		muCount.Lock()
		testCallCount++
		muCount.Unlock()
		time.Sleep(10 * time.Millisecond) // widen the coalescing window
		return true, "ok", nil
	}
	srv, _ := newTestServer(t, fake)
	now := time.Unix(1_700_000_000, 0)
	srv.cfg.Now = func() time.Time { return now }

	var wg sync.WaitGroup
	results := make([]int, 5)
	bodies := make([]map[string]any, 5)
	for i := int64(1); i <= 5; i++ {
		wg.Add(1)
		go func(rev int64) {
			defer wg.Done()
			req := signedApplyRequest(t, now, testSecret, testToken, validPayload(rev, fmt.Sprintf("app-a:run-%d", rev)))
			status, body := doApply(t, srv, req)
			results[rev-1] = status
			bodies[rev-1] = body
		}(i)
	}
	wg.Wait()

	for i, status := range results {
		if status != http.StatusOK {
			t.Fatalf("request %d: expected 200, got %d (%v)", i+1, status, bodies[i])
		}
	}

	srv.stateMu.RLock()
	finalRev := srv.appliedRevision["owner/app-a"]
	srv.stateMu.RUnlock()
	if finalRev != 5 {
		t.Fatalf("expected final applied revision to be the highest submitted (5), got %d", finalRev)
	}
}

func TestDeleteRemovesManagedFile(t *testing.T) {
	srv, confDir := newTestServer(t, nil)
	now := time.Unix(1_700_000_000, 0)
	srv.cfg.Now = func() time.Time { return now }

	req := signedApplyRequest(t, now, testSecret, testToken, validPayload(1, ""))
	status, _ := doApply(t, srv, req)
	if status != http.StatusOK {
		t.Fatalf("expected apply to succeed, got %d", status)
	}

	delReq := signedRequest(t, http.MethodDelete, "/v1/app/app-a", now, testSecret, testToken, nil, "nonce-delete")
	rr := httptest.NewRecorder()
	mux := http.NewServeMux()
	srv.Routes(mux)
	mux.ServeHTTP(rr, delReq)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 on delete, got %d: %s", rr.Code, rr.Body.String())
	}
	if _, err := os.Stat(filepath.Join(confDir, "app-a.conf")); !os.IsNotExist(err) {
		t.Fatal("expected app-a.conf to be removed")
	}
}

func TestDeleteRefusesUnmanagedFile(t *testing.T) {
	srv, confDir := newTestServer(t, nil)
	now := time.Unix(1_700_000_000, 0)
	srv.cfg.Now = func() time.Time { return now }

	// Hand-written config without the managed-by header.
	if err := os.WriteFile(filepath.Join(confDir, "app-a.conf"), []byte("server { listen 80; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	delReq := signedRequest(t, http.MethodDelete, "/v1/app/app-a", now, testSecret, testToken, nil, "nonce-delete-2")
	rr := httptest.NewRecorder()
	mux := http.NewServeMux()
	srv.Routes(mux)
	mux.ServeHTTP(rr, delReq)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unmanaged file, got %d: %s", rr.Code, rr.Body.String())
	}
	if _, err := os.Stat(filepath.Join(confDir, "app-a.conf")); err != nil {
		t.Fatal("expected unmanaged file to remain untouched")
	}
}

func TestHealthRequiresNoAuth(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	mux := http.NewServeMux()
	srv.Routes(mux)
	req := httptest.NewRequest(http.MethodGet, "/v1/health", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestStatusRequiresBearerButNotHMAC(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	mux := http.NewServeMux()
	srv.Routes(mux)

	// no auth at all -> 401
	req := httptest.NewRequest(http.MethodGet, "/v1/status", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without bearer, got %d", rr.Code)
	}

	// bearer only, no HMAC headers -> 200
	req2 := httptest.NewRequest(http.MethodGet, "/v1/status", nil)
	req2.Header.Set("Authorization", "Bearer "+testToken)
	rr2 := httptest.NewRecorder()
	mux.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("expected 200 with bearer only (no HMAC required for GET), got %d: %s", rr2.Code, rr2.Body.String())
	}

	var out map[string]any
	if err := json.Unmarshal(rr2.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if _, ok := out["nginx"]; !ok {
		t.Fatal("expected nginx field in status response")
	}
	if _, ok := out["wg"]; !ok {
		t.Fatal("expected wg field (stub) in status response")
	}
}
