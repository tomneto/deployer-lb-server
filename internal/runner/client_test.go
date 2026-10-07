package runner

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/tomneto/deployer-lb-server/internal/hmacauth"
)

func newTestClient(base string) *Client {
	return NewClient(ClientConfig{
		BaseURL:      base,
		Ref:          "mac-builder",
		Secret:       "s3cr3t",
		Wait:         50 * time.Millisecond,
		ClaimMargin:  2 * time.Second,
		ShortTimeout: 2 * time.Second,
		Hostname:     "mac",
		Version:      "test",
		OS:           "darwin",
		Arch:         "amd64",
	})
}

// This is the invariant NewClient exists for. Getting it backwards produces a
// runner that works perfectly on an idle panel and never receives work on a
// busy one, because the only claims that return are the empty ones.
func TestNewClient_ClaimDeadlineExceedsTheLongPollWindow(t *testing.T) {
	c := NewClient(ClientConfig{BaseURL: "https://panel", Wait: 25 * time.Second, ClaimMargin: 20 * time.Second})
	if c.ClaimHTTP.Timeout <= 25*time.Second {
		t.Fatalf("claim timeout %s must exceed the 25s long-poll window", c.ClaimHTTP.Timeout)
	}
	if c.ClaimHTTP.Timeout != 45*time.Second {
		t.Errorf("claim timeout = %s, want wait+margin = 45s", c.ClaimHTTP.Timeout)
	}
	// The short client must stay short: a dead panel must not stall a finished
	// command for the length of a long poll.
	if c.ShortHTTP.Timeout >= c.ClaimHTTP.Timeout {
		t.Errorf("short timeout %s should be well under the claim timeout %s", c.ShortHTTP.Timeout, c.ClaimHTTP.Timeout)
	}
}

// The same three headers the agent sends, over the same signature — this is
// what lets the panel reuse infra_agent.py's verifier unchanged.
func TestClient_SignsLikeTheAgent(t *testing.T) {
	type seen struct {
		path, id, ts, token string
		body                []byte
	}
	got := make(chan seen, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got <- seen{r.URL.Path, r.Header.Get("X-Agent-Id"), r.Header.Get("X-Agent-Ts"), r.Header.Get("X-Agent-Token"), b}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL)
	if _, err := c.Claim(context.Background()); err != nil {
		t.Fatalf("Claim: %v", err)
	}
	s := <-got

	if s.path != "/deploy/runner/claim" {
		t.Errorf("path = %q", s.path)
	}
	if s.id != "mac-builder" {
		t.Errorf("X-Agent-Id = %q, want the target ref", s.id)
	}
	if want := hmacauth.Sign("s3cr3t", s.ts, s.body); s.token != want {
		t.Errorf("X-Agent-Token = %q, want %q (HMAC of ts+body)", s.token, want)
	}
	if n, err := strconv.ParseInt(s.ts, 10, 64); err != nil || time.Since(time.Unix(n, 0)) > time.Minute {
		t.Errorf("X-Agent-Ts = %q, want a current unix timestamp", s.ts)
	}

	var req ClaimRequest
	if err := json.Unmarshal(s.body, &req); err != nil {
		t.Fatalf("claim body: %v", err)
	}
	if req.Ref != "mac-builder" || req.Hostname != "mac" || req.OS != "darwin" {
		t.Errorf("claim body = %+v", req)
	}
	// The server has to be told the window, or it cannot keep its hold inside
	// the client's deadline.
	if req.WaitSeconds <= 0 {
		t.Error("claim body must declare wait_seconds")
	}
}

func TestClient_Claim204MeansIdleNotFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	cmd, err := newTestClient(srv.URL).Claim(context.Background())
	if err != nil {
		t.Fatalf("204 must not be an error, got %v", err)
	}
	if cmd != nil {
		t.Fatalf("204 must yield no command, got %+v", cmd)
	}
}

// A 200 with an empty body is the same thing a 204 is. Treating it as a
// decoding error would turn a harmless server quirk into a backoff storm.
func TestClient_Claim200EmptyBodyIsIdle(t *testing.T) {
	for _, body := range []string{"", "   ", "null"} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, body)
		}))
		cmd, err := newTestClient(srv.URL).Claim(context.Background())
		srv.Close()
		if err != nil || cmd != nil {
			t.Errorf("body %q: got (%v, %v), want idle", body, cmd, err)
		}
	}
}

func TestClient_ClaimDecodesACommand(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"id":"abc","command":"pytest -q","timeout_seconds":900,"mode":"stream"}`)
	}))
	defer srv.Close()

	cmd, err := newTestClient(srv.URL).Claim(context.Background())
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if cmd == nil || cmd.ID != "abc" || cmd.Command != "pytest -q" || !cmd.Streaming() {
		t.Fatalf("decoded = %+v", cmd)
	}
	if cmd.Timeout(0) != 900*time.Second {
		t.Errorf("Timeout = %s", cmd.Timeout(0))
	}
}

// A command with no id cannot be logged against or resulted against, so it is
// rejected at the door rather than executed into a void.
func TestClient_ClaimRejectsACommandWithoutAnID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"command":"rm -rf /"}`)
	}))
	defer srv.Close()

	if cmd, err := newTestClient(srv.URL).Claim(context.Background()); err == nil || cmd != nil {
		t.Fatalf("got (%v, %v), want an error", cmd, err)
	}
}

func TestClient_ClaimErrorsOnBadStatus(t *testing.T) {
	for _, code := range []int{401, 500, 502} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(code)
			_, _ = io.WriteString(w, "nope")
		}))
		_, err := newTestClient(srv.URL).Claim(context.Background())
		srv.Close()
		if err == nil {
			t.Errorf("status %d should be an error", code)
		}
	}
}

// A panel that is simply not there must surface as an error the loop can back
// off on — not as a panic and not as a silent idle.
func TestClient_UnreachablePanelIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close() // nothing listens on that port any more

	if _, err := newTestClient(url).Claim(context.Background()); err == nil {
		t.Fatal("a refused connection must be reported as an error")
	}
}

func TestClient_LogAndResultPaths(t *testing.T) {
	var paths []string
	var bodies [][]byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		paths = append(paths, r.URL.Path)
		bodies = append(bodies, b)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL)
	if err := c.SendLog(context.Background(), LogBatch{CommandID: "id 1", Seq: 3, Lines: []string{"x"}}); err != nil {
		t.Fatalf("SendLog: %v", err)
	}
	if err := c.SendResult(context.Background(), Result{CommandID: "id 1", ExitCode: 2}); err != nil {
		t.Fatalf("SendResult: %v", err)
	}

	// A command id is panel-supplied data in a URL path: it gets escaped.
	if paths[0] != "/deploy/runner/commands/id%201/log" {
		t.Errorf("log path = %q", paths[0])
	}
	if paths[1] != "/deploy/runner/commands/id%201/result" {
		t.Errorf("result path = %q", paths[1])
	}

	var res Result
	if err := json.Unmarshal(bodies[1], &res); err != nil || res.ExitCode != 2 {
		t.Errorf("result body = %s (%v)", bodies[1], err)
	}
}

// A panel mounted under a prefix must keep it: joining must not clobber the
// base path.
func TestClient_URLForPreservesABasePrefix(t *testing.T) {
	c := &Client{BaseURL: "https://vault.local:6069/api"}
	got, err := c.URLFor("/deploy/runner/claim")
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://vault.local:6069/api/deploy/runner/claim" {
		t.Errorf("URLFor = %q", got)
	}

	trailing := &Client{BaseURL: "https://vault.local:6069/"}
	got, _ = trailing.URLFor("deploy/runner/claim")
	if got != "https://vault.local:6069/deploy/runner/claim" {
		t.Errorf("URLFor with a trailing slash = %q", got)
	}
}

func TestClient_URLForRejectsGarbage(t *testing.T) {
	for _, base := range []string{"", "vault.local:6069", "://x"} {
		if _, err := (&Client{BaseURL: base}).URLFor("/x"); err == nil {
			t.Errorf("base %q should not resolve", base)
		}
	}
}

// The long poll must survive the server holding the request: the client's
// deadline is the window plus a margin, so a slow answer still lands.
func TestClient_ClaimSurvivesAHeldRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req ClaimRequest
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &req)
		// Hold for the whole window the runner asked for, then answer.
		time.Sleep(300 * time.Millisecond)
		_, _ = io.WriteString(w, `{"id":"late","command":"true"}`)
	}))
	defer srv.Close()

	c := NewClient(ClientConfig{
		BaseURL: srv.URL, Ref: "r", Secret: "s",
		Wait:        250 * time.Millisecond,
		ClaimMargin: 2 * time.Second,
	})
	cmd, err := c.Claim(context.Background())
	if err != nil {
		t.Fatalf("Claim hung up on a held request: %v", err)
	}
	if cmd == nil || cmd.ID != "late" {
		t.Fatalf("got %+v", cmd)
	}
}
