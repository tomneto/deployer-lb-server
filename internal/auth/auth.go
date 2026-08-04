// Package auth implements the bearer-token + HMAC-SHA256 authentication
// scheme used by the `lb` mode listener (POST /v1/apply, DELETE
// /v1/app/{ref}, GET /v1/status), per pipe-improves.md §2.3.
//
// Signature covers `timestamp + nonce + body` and is carried in
// `X-Payload-Sig: sha256=<hex>`, with `X-Payload-Ts` / `X-Payload-Nonce`
// as the signed components. Replay protection combines a timestamp window
// check with an in-memory nonce cache.
package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SignaturePrefix is prepended to the hex-encoded HMAC digest.
const SignaturePrefix = "sha256="

// VerifyBearer checks an `Authorization: Bearer <token>` header against the
// expected token using a constant-time comparison.
func VerifyBearer(headerValue, expectedToken string) bool {
	const prefix = "Bearer "
	if !strings.HasPrefix(headerValue, prefix) {
		return false
	}
	got := strings.TrimPrefix(headerValue, prefix)
	if got == "" || expectedToken == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(expectedToken)) == 1
}

// ComputeSignature returns the `sha256=<hex>` signature for
// timestamp+nonce+body signed with secret.
func ComputeSignature(secret, timestamp, nonce string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp))
	mac.Write([]byte(nonce))
	mac.Write(body)
	return SignaturePrefix + hex.EncodeToString(mac.Sum(nil))
}

// VerifySignature reports whether sigHeader matches the expected signature
// for timestamp+nonce+body under secret.
func VerifySignature(secret, timestamp, nonce string, body []byte, sigHeader string) bool {
	if sigHeader == "" || secret == "" {
		return false
	}
	expected := ComputeSignature(secret, timestamp, nonce, body)
	return subtle.ConstantTimeCompare([]byte(expected), []byte(sigHeader)) == 1
}

// CheckTimestamp parses a unix-seconds timestamp string and verifies it
// falls within +/-window of now.
func CheckTimestamp(tsStr string, now time.Time, window time.Duration) error {
	if tsStr == "" {
		return fmt.Errorf("missing timestamp")
	}
	tsInt, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid timestamp: %w", err)
	}
	ts := time.Unix(tsInt, 0)
	diff := now.Sub(ts)
	if diff < 0 {
		diff = -diff
	}
	if diff > window {
		return fmt.Errorf("timestamp outside of allowed window (%s)", window)
	}
	return nil
}

// NonceCache is an in-memory, expiring set used for anti-replay protection.
// Entries expire after ttl; a swept lazily on every access, so no background
// goroutine is required.
type NonceCache struct {
	mu   sync.Mutex
	ttl  time.Duration
	seen map[string]time.Time // nonce -> expiry
}

// NewNonceCache builds a NonceCache whose entries expire after ttl.
func NewNonceCache(ttl time.Duration) *NonceCache {
	return &NonceCache{
		ttl:  ttl,
		seen: make(map[string]time.Time),
	}
}

// CheckAndStore returns true if nonce has not been seen (within ttl) and
// records it; returns false if nonce is a replay.
func (c *NonceCache) CheckAndStore(nonce string, now time.Time) bool {
	if nonce == "" {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sweepLocked(now)
	if exp, ok := c.seen[nonce]; ok && exp.After(now) {
		return false
	}
	c.seen[nonce] = now.Add(c.ttl)
	return true
}

func (c *NonceCache) sweepLocked(now time.Time) {
	for k, exp := range c.seen {
		if !exp.After(now) {
			delete(c.seen, k)
		}
	}
}

// Len reports the number of live (non-expired-at-last-sweep) nonces; useful
// for tests.
func (c *NonceCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.seen)
}
