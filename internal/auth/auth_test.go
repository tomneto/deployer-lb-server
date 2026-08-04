package auth

import (
	"testing"
	"time"
)

func TestVerifyBearer(t *testing.T) {
	if !VerifyBearer("Bearer abc123", "abc123") {
		t.Fatal("expected valid bearer to pass")
	}
	if VerifyBearer("Bearer wrong", "abc123") {
		t.Fatal("expected invalid bearer to fail")
	}
	if VerifyBearer("abc123", "abc123") {
		t.Fatal("expected missing Bearer prefix to fail")
	}
	if VerifyBearer("", "abc123") {
		t.Fatal("expected empty header to fail")
	}
}

func TestVerifySignatureValid(t *testing.T) {
	secret := "s3cr3t"
	ts := "1700000000"
	nonce := "nonce-1"
	body := []byte(`{"hello":"world"}`)
	sig := ComputeSignature(secret, ts, nonce, body)
	if !VerifySignature(secret, ts, nonce, body, sig) {
		t.Fatal("expected matching signature to verify")
	}
}

func TestVerifySignatureInvalid(t *testing.T) {
	secret := "s3cr3t"
	ts := "1700000000"
	nonce := "nonce-1"
	body := []byte(`{"hello":"world"}`)
	sig := ComputeSignature(secret, ts, nonce, body)

	// wrong secret
	if VerifySignature("other-secret", ts, nonce, body, sig) {
		t.Fatal("expected signature with wrong secret to fail")
	}
	// tampered body
	if VerifySignature(secret, ts, nonce, []byte(`{"hello":"mars"}`), sig) {
		t.Fatal("expected signature with tampered body to fail")
	}
	// tampered ts
	if VerifySignature(secret, "1700000001", nonce, body, sig) {
		t.Fatal("expected signature with tampered timestamp to fail")
	}
}

func TestCheckTimestampWithinWindow(t *testing.T) {
	now := time.Unix(1700000000, 0)
	ts := "1700000010" // 10s ahead, within +/-30s
	if err := CheckTimestamp(ts, now, 30*time.Second); err != nil {
		t.Fatalf("expected timestamp within window to pass, got %v", err)
	}
}

func TestCheckTimestampOutsideWindow(t *testing.T) {
	now := time.Unix(1700000000, 0)
	ts := "1699999900" // 100s behind, outside +/-30s
	if err := CheckTimestamp(ts, now, 30*time.Second); err == nil {
		t.Fatal("expected timestamp outside window to fail")
	}
}

func TestCheckTimestampInvalid(t *testing.T) {
	now := time.Unix(1700000000, 0)
	if err := CheckTimestamp("not-a-number", now, 30*time.Second); err == nil {
		t.Fatal("expected non-numeric timestamp to fail")
	}
	if err := CheckTimestamp("", now, 30*time.Second); err == nil {
		t.Fatal("expected empty timestamp to fail")
	}
}

func TestNonceCacheReplay(t *testing.T) {
	c := NewNonceCache(5 * time.Minute)
	now := time.Unix(1700000000, 0)

	if !c.CheckAndStore("n1", now) {
		t.Fatal("expected first use of nonce to succeed")
	}
	if c.CheckAndStore("n1", now.Add(1*time.Second)) {
		t.Fatal("expected replay of nonce to be rejected")
	}
}

func TestNonceCacheExpiry(t *testing.T) {
	c := NewNonceCache(1 * time.Second)
	now := time.Unix(1700000000, 0)

	if !c.CheckAndStore("n1", now) {
		t.Fatal("expected first use of nonce to succeed")
	}
	// After expiry, the same nonce may be reused (window has long since
	// closed for that timestamp anyway, but the cache itself must not leak
	// memory forever).
	later := now.Add(10 * time.Second)
	if !c.CheckAndStore("n1", later) {
		t.Fatal("expected nonce to be evictable after ttl expiry")
	}
}
