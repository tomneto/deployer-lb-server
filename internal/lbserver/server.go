// Package lbserver implements the `lb` mode HTTP listener contract from
// pipe-improves.md §2.3/§2.4: POST /v1/apply, DELETE /v1/app/{ref},
// GET /v1/status, GET /v1/health.
package lbserver

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/tomneto/deployer-lb-server/internal/auth"
	"github.com/tomneto/deployer-lb-server/internal/nginx"
	"github.com/tomneto/deployer-lb-server/internal/render"
)

// Config wires the server's dependencies and policy knobs.
type Config struct {
	Token        string        // shared bearer token
	Secret       string        // HMAC shared secret
	ConfDir      string        // e.g. /etc/nginx/conf.d
	TemplatePath string        // e.g. /etc/nginx/lb-templates/nginx-app.conf.tmpl
	MaxBodyBytes int64         // ~64KB per §2.3
	TSWindow     time.Duration // +/-30s per §2.3
	NonceTTL     time.Duration // how long nonces are remembered
	MaxQueueLen  int           // per-app waiter cap before 503
	Runner       nginx.Runner
	Now          func() time.Time // injectable clock; defaults to time.Now
	Logger       *log.Logger      // structured, append-only apply log (§2.3)
}

func (c *Config) setDefaults() {
	if c.MaxBodyBytes <= 0 {
		c.MaxBodyBytes = 64 * 1024
	}
	if c.TSWindow <= 0 {
		c.TSWindow = 30 * time.Second
	}
	if c.NonceTTL <= 0 {
		c.NonceTTL = 5 * time.Minute
	}
	if c.MaxQueueLen <= 0 {
		c.MaxQueueLen = 64
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Logger == nil {
		c.Logger = log.New(os.Stdout, "", log.LstdFlags)
	}
}

// idemRecord remembers that an idempotency key has already been processed,
// so repeats are a cheap 200 {"status":"noop"} (§2.3).
type idemRecord struct{}

// Server holds all mutable state for the listener: applied revisions,
// idempotency keys, and which app currently owns which domain. All
// mutations to this state happen inside the global apply mutex, so
// stateMu only needs to protect concurrent *reads* (e.g. from
// GET /v1/status) racing with the (rare) write path.
type Server struct {
	cfg    Config
	nonces *auth.NonceCache

	// mu is the "mutex global" from §2.3: it serializes the entire
	// validate->render->write->test->mv->reload critical section across
	// every app.
	mu sync.Mutex

	stateMu         sync.RWMutex
	appliedRevision map[string]int64  // repo (pipeline_ref) -> last applied revision
	idempotency     map[string]idemRecord
	domainOwner     map[string]string // domain -> pipeline_ref

	coalMu sync.Mutex
	slots  map[string]*appSlot // pipeline_ref -> in-flight coalescing slot
}

type applyResult struct {
	status int
	body   map[string]any
}

type appSlot struct {
	mu      sync.Mutex
	running bool
	latest  *render.Payload
	waiters []chan applyResult
}

// New builds a Server ready to be wired into an http.ServeMux via Routes().
func New(cfg Config) *Server {
	cfg.setDefaults()
	return &Server{
		cfg:             cfg,
		nonces:          auth.NewNonceCache(cfg.NonceTTL),
		appliedRevision: make(map[string]int64),
		idempotency:     make(map[string]idemRecord),
		domainOwner:     make(map[string]string),
		slots:           make(map[string]*appSlot),
	}
}

// Routes registers the four listener endpoints on mux.
func (s *Server) Routes(mux *http.ServeMux) {
	mux.HandleFunc("/v1/health", s.handleHealth)
	mux.HandleFunc("/v1/status", s.handleStatus)
	mux.HandleFunc("/v1/apply", s.handleApply)
	mux.HandleFunc("/v1/app/", s.handleDeleteApp)
}

func writeJSON(w http.ResponseWriter, status int, body map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// ---- GET /v1/health (no auth) ----

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"status": "invalid"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

// ---- GET /v1/status (bearer required, no HMAC) ----
//
// Decision: the plan states explicitly that GET /v1/status requires the
// same bearer token (it leaks app->revision topology) but that HMAC is not
// required for GETs — only /v1/health skips auth entirely. This matches
// §2.3's auth row verbatim.
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"status": "invalid"})
		return
	}
	if !auth.VerifyBearer(r.Header.Get("Authorization"), s.cfg.Token) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"status": "unauthorized"})
		return
	}

	s.stateMu.RLock()
	apps := make(map[string]any, len(s.appliedRevision))
	for repo, rev := range s.appliedRevision {
		apps[repo] = map[string]any{"applied_revision": rev}
	}
	s.stateMu.RUnlock()

	configOk := true
	if s.cfg.Runner != nil {
		configOk, _, _ = s.cfg.Runner.Test(s.cfg.ConfDir)
	}
	running := true
	if s.cfg.Runner != nil {
		running, _ = s.cfg.Runner.IsActive()
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"apps": apps,
		"nginx": map[string]any{
			"running":   running,
			"config_ok": configOk,
		},
		// wg.peers is only ever populated by the agent/B2 side (real
		// handshake/ping data comes from gopsutil + `wg show`); this shape
		// exists now so the backoffice/central contract doesn't have to
		// change later (§2.3 telemetria).
		"wg": map[string]any{
			"peers": []any{},
		},
	})
}

// ---- POST /v1/apply ----

func (s *Server) handleApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"status": "invalid"})
		return
	}

	// Body size limit MUST be enforced before computing the HMAC (§2.3).
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"status": "invalid",
			"errors": []string{"body too large or unreadable"},
		})
		return
	}

	if !auth.VerifyBearer(r.Header.Get("Authorization"), s.cfg.Token) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"status": "unauthorized"})
		return
	}

	ts := r.Header.Get("X-Payload-Ts")
	nonce := r.Header.Get("X-Payload-Nonce")
	sig := r.Header.Get("X-Payload-Sig")
	now := s.cfg.Now()

	if err := auth.CheckTimestamp(ts, now, s.cfg.TSWindow); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"status": "unauthorized", "error": err.Error()})
		return
	}
	if !auth.VerifySignature(s.cfg.Secret, ts, nonce, body, sig) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"status": "unauthorized"})
		return
	}
	if !s.nonces.CheckAndStore(nonce, now) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"status": "unauthorized", "error": "nonce replay"})
		return
	}

	var p render.Payload
	if err := json.Unmarshal(body, &p); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"status": "invalid",
			"errors": []string{"malformed json: " + err.Error()},
		})
		return
	}

	// Strict validation BEFORE any disk write (§2.3).
	if errs := render.ValidatePayload(&p); len(errs) > 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"status": "invalid", "errors": errs})
		return
	}

	status, respBody := s.submit(p)
	writeJSON(w, status, respBody)
}

// submit routes p through the per-app coalescing slot, then the global
// apply mutex. Concurrent applies for the same pipeline_ref collapse to
// whichever carries the highest revision (§2.3 "coalescing por app").
func (s *Server) submit(p render.Payload) (int, map[string]any) {
	s.coalMu.Lock()
	slot, ok := s.slots[p.PipelineRef]
	if !ok {
		slot = &appSlot{}
		s.slots[p.PipelineRef] = slot
	}
	s.coalMu.Unlock()

	slot.mu.Lock()
	if slot.running {
		if len(slot.waiters) >= s.cfg.MaxQueueLen {
			slot.mu.Unlock()
			return http.StatusServiceUnavailable, map[string]any{
				"status": "unavailable",
				"error":  "apply queue full for this app",
			}
		}
		if slot.latest == nil || p.Revision > slot.latest.Revision {
			pCopy := p
			slot.latest = &pCopy
		}
		ch := make(chan applyResult, 1)
		slot.waiters = append(slot.waiters, ch)
		slot.mu.Unlock()
		res := <-ch
		return res.status, res.body
	}

	slot.running = true
	pCopy := p
	slot.latest = &pCopy
	slot.mu.Unlock()

	for {
		slot.mu.Lock()
		job := slot.latest
		slot.mu.Unlock()

		status, respBody := s.runApplyLocked(*job)

		slot.mu.Lock()
		if slot.latest == job {
			waiters := slot.waiters
			slot.waiters = nil
			slot.running = false
			slot.latest = nil
			slot.mu.Unlock()
			res := applyResult{status, respBody}
			for _, ch := range waiters {
				ch <- res
			}
			return status, respBody
		}
		// A newer job was coalesced in while we were working; loop and
		// process it too, still holding the "leader" role for this app.
		slot.mu.Unlock()
	}
}

// runApplyLocked acquires the global apply mutex and executes the full
// validate->render->stage->test->promote->reload pipeline for a single
// payload. It is the only place that touches disk or calls the nginx
// Runner for writes.
func (s *Server) runApplyLocked(p render.Payload) (int, map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Idempotency: replay of an already-processed key is a no-op success,
	// regardless of what the original outcome was (§2.3).
	s.stateMu.RLock()
	_, seen := s.idempotency[p.IdempotencyKey]
	appliedRev := s.appliedRevision[p.Repo]
	s.stateMu.RUnlock()

	if seen {
		return http.StatusOK, map[string]any{"status": "noop"}
	}

	if p.Revision <= appliedRev {
		return http.StatusConflict, map[string]any{
			"status":           "conflict",
			"applied_revision": appliedRev,
		}
	}

	if status, body, conflict := s.checkDomainCollision(p); conflict {
		return status, body
	}

	rendered, err := render.Render(s.cfg.TemplatePath, p)
	if err != nil {
		return http.StatusBadRequest, map[string]any{
			"status": "invalid",
			"errors": []string{"template render failed: " + err.Error()},
		}
	}

	confFile := p.ConfFileName()
	finalPath := filepath.Join(s.cfg.ConfDir, confFile)

	overlay, err := os.MkdirTemp("", "lb-apply-*")
	if err != nil {
		return http.StatusServiceUnavailable, map[string]any{"status": "unavailable", "error": err.Error()}
	}
	defer os.RemoveAll(overlay)

	if err := nginx.CopyConfTree(s.cfg.ConfDir, overlay, confFile); err != nil {
		return http.StatusServiceUnavailable, map[string]any{"status": "unavailable", "error": err.Error()}
	}
	if err := os.WriteFile(filepath.Join(overlay, confFile), []byte(rendered), 0o644); err != nil {
		return http.StatusServiceUnavailable, map[string]any{"status": "unavailable", "error": err.Error()}
	}

	ok, testOut, _ := s.cfg.Runner.Test(overlay)
	if !ok {
		s.logApply(p, "nginx_test_failed", testOut)
		return http.StatusBadRequest, map[string]any{
			"status": "invalid",
			"errors": splitLines(testOut),
		}
	}

	var backup []byte
	hadBackup := false
	if b, err := os.ReadFile(finalPath); err == nil {
		backup = b
		hadBackup = true
	}

	if err := nginx.WriteAtomic(finalPath, []byte(rendered), 0o644); err != nil {
		return http.StatusServiceUnavailable, map[string]any{"status": "unavailable", "error": err.Error()}
	}

	if reloadOut, err := s.cfg.Runner.Reload(); err != nil {
		// Reload failed: revert the file to its previous version and
		// re-test, per §2.3's rollback rule.
		if hadBackup {
			_ = nginx.WriteAtomic(finalPath, backup, 0o644)
		} else {
			_ = os.Remove(finalPath)
		}
		_, _, _ = s.cfg.Runner.Test(s.cfg.ConfDir)
		s.logApply(p, "reload_failed", reloadOut)
		return http.StatusServiceUnavailable, map[string]any{
			"status": "unavailable",
			"error":  "reload failed, reverted: " + reloadOut,
		}
	}

	s.stateMu.Lock()
	s.appliedRevision[p.Repo] = p.Revision
	s.idempotency[p.IdempotencyKey] = idemRecord{}
	for _, d := range p.Domains {
		s.domainOwner[d] = p.PipelineRef
	}
	s.stateMu.Unlock()

	s.logApply(p, "reloaded", "")
	return http.StatusOK, map[string]any{
		"status":           "reloaded",
		"applied_revision": p.Revision,
	}
}

// checkDomainCollision implements §2.3's "colisão com legado" rule: on the
// first apply of a given domain, scan the live `nginx -T` output for a
// server_name outside our managed files. Domains we already know we own
// (in-memory, from a prior successful apply in this process) skip the scan
// entirely — cheap fast path for the common case (re-applying an existing
// app).
func (s *Server) checkDomainCollision(p render.Payload) (status int, body map[string]any, conflict bool) {
	s.stateMu.RLock()
	unknown := make([]string, 0, len(p.Domains))
	for _, d := range p.Domains {
		owner, known := s.domainOwner[d]
		if known && owner != p.PipelineRef {
			s.stateMu.RUnlock()
			return http.StatusConflict, map[string]any{
				"status": "conflict",
				"reason": "domain_claimed",
			}, true
		}
		if !known {
			unknown = append(unknown, d)
		}
	}
	s.stateMu.RUnlock()

	if len(unknown) == 0 {
		return 0, nil, false
	}

	dump, err := s.cfg.Runner.DumpConfig()
	if err != nil {
		// Fail closed only on the domains we can't verify: if we cannot
		// read the live config, we cannot safely rule out a legacy
		// collision, so refuse rather than risk a duplicate server_name.
		return http.StatusServiceUnavailable, map[string]any{
			"status": "unavailable",
			"error":  "could not verify legacy server_name collisions: " + err.Error(),
		}, true
	}

	for _, d := range unknown {
		owner, found := nginx.FindDomainOwner(dump, d)
		if !found {
			continue
		}
		if !owner.Managed {
			return http.StatusConflict, map[string]any{
				"status": "conflict",
				"reason": "legacy_server_name",
				"domain": d,
			}, true
		}
		if owner.App != p.PipelineRef {
			return http.StatusConflict, map[string]any{
				"status": "conflict",
				"reason": "domain_claimed",
				"domain": d,
			}, true
		}
	}
	return 0, nil, false
}

func (s *Server) logApply(p render.Payload, result, detail string) {
	s.cfg.Logger.Printf(
		"apply pipeline_ref=%s domains=%s revision=%d idempotency_key=%s result=%s detail=%q",
		p.PipelineRef, strings.Join(p.Domains, ","), p.Revision, p.IdempotencyKey, result, detail,
	)
}

func splitLines(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return []string{"nginx -t failed with no output"}
	}
	return strings.Split(s, "\n")
}

// ---- DELETE /v1/app/{pipeline_ref} ----
//
// Decision: the plan's per-endpoint auth row is written once for the whole
// listener and explicitly calls out that only GET /v1/health skips auth and
// that GET /v1/status accepts bearer-only (no HMAC). It does not carve out
// an exception for DELETE. Since DELETE is a mutating, disk-touching
// operation exactly like POST /v1/apply, this implementation requires the
// same bearer + HMAC(timestamp+nonce+body) scheme for it (body is empty for
// DELETE, so the signature covers timestamp+nonce+"").
func (s *Server) handleDeleteApp(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"status": "invalid"})
		return
	}

	ref := strings.TrimPrefix(r.URL.Path, "/v1/app/")
	if !pipelineRefValid(ref) {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"status": "invalid",
			"errors": []string{"invalid pipeline_ref"},
		})
		return
	}

	if !auth.VerifyBearer(r.Header.Get("Authorization"), s.cfg.Token) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"status": "unauthorized"})
		return
	}

	body, _ := io.ReadAll(http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyBytes))
	ts := r.Header.Get("X-Payload-Ts")
	nonce := r.Header.Get("X-Payload-Nonce")
	sig := r.Header.Get("X-Payload-Sig")
	now := s.cfg.Now()

	if err := auth.CheckTimestamp(ts, now, s.cfg.TSWindow); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"status": "unauthorized", "error": err.Error()})
		return
	}
	if !auth.VerifySignature(s.cfg.Secret, ts, nonce, body, sig) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"status": "unauthorized"})
		return
	}
	if !s.nonces.CheckAndStore(nonce, now) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"status": "unauthorized", "error": "nonce replay"})
		return
	}

	status, respBody := s.deleteApp(ref)
	writeJSON(w, status, respBody)
}

func (s *Server) deleteApp(ref string) (int, map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()

	confFile := ref + ".conf"
	finalPath := filepath.Join(s.cfg.ConfDir, confFile)

	content, err := os.ReadFile(finalPath)
	if err != nil {
		return http.StatusNotFound, map[string]any{"status": "invalid", "errors": []string{"app not found"}}
	}
	if !strings.HasPrefix(string(content), "# managed-by:") {
		return http.StatusBadRequest, map[string]any{
			"status": "invalid",
			"errors": []string{"refusing to delete a file without a managed-by header"},
		}
	}

	overlay, err := os.MkdirTemp("", "lb-delete-*")
	if err != nil {
		return http.StatusServiceUnavailable, map[string]any{"status": "unavailable", "error": err.Error()}
	}
	defer os.RemoveAll(overlay)
	if err := nginx.CopyConfTree(s.cfg.ConfDir, overlay, confFile); err != nil {
		return http.StatusServiceUnavailable, map[string]any{"status": "unavailable", "error": err.Error()}
	}

	ok, testOut, _ := s.cfg.Runner.Test(overlay)
	if !ok {
		return http.StatusBadRequest, map[string]any{"status": "invalid", "errors": splitLines(testOut)}
	}

	if err := os.Remove(finalPath); err != nil {
		return http.StatusServiceUnavailable, map[string]any{"status": "unavailable", "error": err.Error()}
	}

	if reloadOut, err := s.cfg.Runner.Reload(); err != nil {
		// restore on failed reload
		_ = nginx.WriteAtomic(finalPath, content, 0o644)
		_, _, _ = s.cfg.Runner.Test(s.cfg.ConfDir)
		return http.StatusServiceUnavailable, map[string]any{
			"status": "unavailable",
			"error":  "reload failed, restored: " + reloadOut,
		}
	}

	s.stateMu.Lock()
	delete(s.appliedRevision, ref)
	for d, owner := range s.domainOwner {
		if owner == ref {
			delete(s.domainOwner, d)
		}
	}
	s.stateMu.Unlock()

	return http.StatusOK, map[string]any{"status": "deleted"}
}

func pipelineRefValid(ref string) bool {
	if ref == "" || len(ref) > 100 {
		return false
	}
	for _, c := range ref {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}
