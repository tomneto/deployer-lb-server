package nginx

import (
	"regexp"
	"strconv"
	"strings"
)

// ManagedUpstream is one backend pool member declared by a managed conf's
// `upstream { server <host>:<port>; }` block.
type ManagedUpstream struct {
	Host string
	Port int
}

// ManagedConf is the parsed view of a single deployer-managed conf.d file —
// the on-disk manifest GET /v1/status is built from (C6). Because every
// apply writes the `# managed-by: ... app=<ref> revision=<n>` header plus
// the upstream/server_name blocks, parsing the file back recovers the full
// app state even after a process restart (the in-memory appliedRevision map
// starts empty on boot).
type ManagedConf struct {
	App       string
	Revision  int64
	Domains   []string
	Upstreams []ManagedUpstream
}

var revisionRe = regexp.MustCompile(`\brevision=(\d+)\b`)

// upstreamServerRe matches only pool member lines (`server <host>:<port>;`)
// — vhost `server {` blocks and directives like `server_name`/`listen`
// never carry a `<host>:<port>;` argument in that shape.
var upstreamServerRe = regexp.MustCompile(`^\s*server\s+([^\s;]+):(\d+)\s*;`)

// ParseManagedConf parses the content of one conf.d file. It returns
// ok=false for anything that is not a fully managed app conf: hand-written
// files, and the `00-default.conf` catch-all (whose managed-by header has
// no `app=` field) — mirroring the strictness of managedByRe used for the
// legacy-collision scan.
func ParseManagedConf(content string) (ManagedConf, bool) {
	lines := strings.Split(content, "\n")
	if len(lines) == 0 {
		return ManagedConf{}, false
	}
	// The managed-by header MUST be the first line (same contract the
	// DELETE handler and the template enforce).
	m := managedByRe.FindStringSubmatch(strings.TrimSpace(lines[0]))
	if m == nil {
		return ManagedConf{}, false
	}
	mc := ManagedConf{App: m[1]}
	if rm := revisionRe.FindStringSubmatch(lines[0]); rm != nil {
		mc.Revision, _ = strconv.ParseInt(rm[1], 10, 64)
	}
	for _, line := range lines[1:] {
		if sm := serverNameRe.FindStringSubmatch(line); sm != nil {
			mc.Domains = append(mc.Domains, strings.Fields(sm[1])...)
			continue
		}
		if um := upstreamServerRe.FindStringSubmatch(line); um != nil {
			port, err := strconv.Atoi(um[2])
			if err != nil || port < 1 || port > 65535 {
				continue
			}
			mc.Upstreams = append(mc.Upstreams, ManagedUpstream{Host: um[1], Port: port})
		}
	}
	return mc, true
}
