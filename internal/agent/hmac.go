//go:build agent

package agent

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// Sign computes the X-Agent-Token: HMAC-SHA256 of `timestamp + body`, keyed
// by the per-target secret. Mirrors the receiver-side contract in
// pipe-improves.md §2.7.2 (same construction as github_app.py's helper,
// hex-encoded). Pure function — no I/O — so it's trivially unit-testable
// against a known vector.
func Sign(secret, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}
