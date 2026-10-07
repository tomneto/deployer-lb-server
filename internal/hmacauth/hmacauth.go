// Package hmacauth carries the one signing scheme every binary in this repo
// uses to authenticate itself to the central panel: HMAC-SHA256 of
// `timestamp + body`, keyed by the per-target secret, hex-encoded, shipped in
// the X-Agent-Ts / X-Agent-Token headers alongside X-Agent-Id.
//
// It lives in its own package — free of build tags and of non-stdlib imports —
// because two binaries with disjoint dependency graphs need it: the agent
// (`-tags agent`) and the runner (`-tags runner`). internal/agent.Sign is kept
// as a thin alias so the agent's call sites and tests are untouched.
//
// The receiver side is infra_agent.py's verifier in selfApi (constant-time
// compare, time window, single opaque error).
package hmacauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
	"time"
)

// Sign computes the X-Agent-Token for a request. Pure function — no I/O — so
// it is trivially testable against a known vector.
func Sign(secret, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// Apply stamps the three headers the panel expects onto req, signing body with
// the current wall clock. Keeping the header names in one place is the point:
// a typo in any one of them is a 401 that looks like a bad secret.
func Apply(req *http.Request, agentID, secret string, body []byte, now time.Time) {
	ts := strconv.FormatInt(now.Unix(), 10)
	req.Header.Set("X-Agent-Id", agentID)
	req.Header.Set("X-Agent-Ts", ts)
	req.Header.Set("X-Agent-Token", Sign(secret, ts, body))
}
