//go:build agent

package agent

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestSign_KnownVector(t *testing.T) {
	secret := "super-secret"
	ts := "1700000000"
	body := []byte(`{"hello":"world"}`)

	got := Sign(secret, ts, body)

	// Reference implementation, computed independently to avoid tautology.
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts))
	mac.Write(body)
	want := hex.EncodeToString(mac.Sum(nil))

	if got != want {
		t.Fatalf("Sign() = %q, want %q", got, want)
	}
	if len(got) != 64 {
		t.Fatalf("Sign() length = %d, want 64 (hex-encoded sha256)", len(got))
	}
}

func TestSign_DifferentSecretsDiffer(t *testing.T) {
	ts := "1700000000"
	body := []byte(`{"a":1}`)
	a := Sign("secret-a", ts, body)
	b := Sign("secret-b", ts, body)
	if a == b {
		t.Fatal("Sign() with different secrets produced the same signature")
	}
}

func TestSign_DifferentBodyDiffers(t *testing.T) {
	ts := "1700000000"
	a := Sign("secret", ts, []byte(`{"a":1}`))
	b := Sign("secret", ts, []byte(`{"a":2}`))
	if a == b {
		t.Fatal("Sign() with different bodies produced the same signature")
	}
}

func TestSign_TimestampIsPartOfTheSignedMessage(t *testing.T) {
	body := []byte(`{"a":1}`)
	a := Sign("secret", "1700000000", body)
	b := Sign("secret", "1700000001", body)
	if a == b {
		t.Fatal("Sign() with different timestamps produced the same signature")
	}
}
