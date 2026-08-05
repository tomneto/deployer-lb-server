// GET /v1/status enrichment (contract C6): apps/domains/upstreams + health.
//
// The source of truth is the ConfDir itself — every successful apply leaves
// behind `<pipeline_ref>.conf` whose first line is the
// `# managed-by: ... app=<ref> revision=<n>` header and whose upstream/
// server_name blocks name the backends and domains. Parsing those files back
// (internal/nginx.ParseManagedConf) means the status survives process
// restarts with zero extra bookkeeping, and stays consistent with what
// nginx is actually serving.
package lbserver

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/tomneto/deployer-lb-server/internal/nginx"
)

// healthEntry memoizes one TCP probe result for HealthCacheTTL (~10s), so a
// tight status-poll loop doesn't dial every upstream on every GET.
type healthEntry struct {
	healthy   bool
	checkedAt time.Time
}

// upstreamHealthy reports whether host:port accepts a TCP connection,
// answering from the cache when the last probe is fresher than
// HealthCacheTTL. Concurrent misses on the same address may both dial —
// that's an accepted (harmless) race, cheaper than holding the lock across
// a network call.
func (s *Server) upstreamHealthy(host string, port int) bool {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	now := s.cfg.Now()

	s.healthMu.Lock()
	if e, ok := s.healthCache[addr]; ok && now.Sub(e.checkedAt) < s.cfg.HealthCacheTTL {
		s.healthMu.Unlock()
		return e.healthy
	}
	s.healthMu.Unlock()

	conn, err := s.cfg.DialTimeout("tcp", addr, s.cfg.HealthDialTimeout)
	healthy := err == nil
	if conn != nil {
		_ = conn.Close()
	}

	s.healthMu.Lock()
	s.healthCache[addr] = healthEntry{healthy: healthy, checkedAt: now}
	s.healthMu.Unlock()
	return healthy
}

// statusApps builds the C6 `apps` map by scanning ConfDir for managed confs:
//
//	apps[pipeline_ref] = {applied_revision, domains: [...],
//	                      upstreams: [{host, port, healthy}]}
//
// Unmanaged files (hand-written confs, the 00-default catch-all) are
// skipped, mirroring the DELETE handler's managed-by contract. A ConfDir
// read error degrades to an empty map — status must never 500 because a
// directory momentarily can't be listed.
func (s *Server) statusApps() map[string]any {
	apps := make(map[string]any)
	entries, err := os.ReadDir(s.cfg.ConfDir)
	if err != nil {
		return apps
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".conf") || strings.HasPrefix(name, ".") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.cfg.ConfDir, name))
		if err != nil {
			continue
		}
		mc, ok := nginx.ParseManagedConf(string(data))
		if !ok {
			continue
		}
		ref := strings.TrimSuffix(name, ".conf")

		domains := mc.Domains
		if domains == nil {
			domains = []string{}
		}
		upstreams := make([]map[string]any, 0, len(mc.Upstreams))
		for _, u := range mc.Upstreams {
			upstreams = append(upstreams, map[string]any{
				"host":    u.Host,
				"port":    u.Port,
				"healthy": s.upstreamHealthy(u.Host, u.Port),
			})
		}
		apps[ref] = map[string]any{
			"applied_revision": mc.Revision,
			"domains":          domains,
			"upstreams":        upstreams,
		}
	}
	return apps
}
