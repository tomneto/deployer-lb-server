//go:build agent

package agent

import "github.com/tomneto/deployer-lb-server/internal/hmacauth"

// Sign computes the X-Agent-Token: HMAC-SHA256 of `timestamp + body`, keyed
// by the per-target secret. Mirrors the receiver-side contract in
// pipe-improves.md §2.7.2 (same construction as github_app.py's helper,
// hex-encoded).
//
// The implementation moved to internal/hmacauth when the runner (a second
// binary, with its own build tag and its own dependency graph) needed the very
// same scheme. This stays as the agent's name for it so no call site or test
// here had to change — there is still exactly one implementation.
func Sign(secret, timestamp string, body []byte) string {
	return hmacauth.Sign(secret, timestamp, body)
}
