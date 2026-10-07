package hmacauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
	"testing"
	"time"
)

func TestSign_KnownVector(t *testing.T) {
	secret, ts := "super-secret", "1700000000"
	body := []byte(`{"hello":"world"}`)

	// Reference computed independently, to avoid a tautological test.
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts))
	mac.Write(body)
	want := hex.EncodeToString(mac.Sum(nil))

	if got := Sign(secret, ts, body); got != want {
		t.Fatalf("Sign() = %q, want %q", got, want)
	}
	if len(Sign(secret, ts, body)) != 64 {
		t.Fatal("Sign() must be hex-encoded sha256 (64 chars)")
	}
}

func TestSign_EveryInputIsPartOfTheMessage(t *testing.T) {
	base := Sign("secret", "1700000000", []byte(`{"a":1}`))
	for name, got := range map[string]string{
		"secret":    Sign("other", "1700000000", []byte(`{"a":1}`)),
		"timestamp": Sign("secret", "1700000001", []byte(`{"a":1}`)),
		"body":      Sign("secret", "1700000000", []byte(`{"a":2}`)),
	} {
		if got == base {
			t.Errorf("changing the %s did not change the signature", name)
		}
	}
}

// The header NAMES are the contract with infra_agent.py. A typo in any one of
// them is a 401 that looks exactly like a bad secret, which is why they live in
// one function with one test.
func TestApply_SetsTheThreeHeaders(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, "https://panel/x", nil)
	now := time.Unix(1700000000, 0)
	body := []byte(`{"a":1}`)

	Apply(req, "target-ref", "secret", body, now)

	if got := req.Header.Get("X-Agent-Id"); got != "target-ref" {
		t.Errorf("X-Agent-Id = %q", got)
	}
	if got := req.Header.Get("X-Agent-Ts"); got != strconv.FormatInt(now.Unix(), 10) {
		t.Errorf("X-Agent-Ts = %q", got)
	}
	if got, want := req.Header.Get("X-Agent-Token"), Sign("secret", "1700000000", body); got != want {
		t.Errorf("X-Agent-Token = %q, want %q", got, want)
	}
}
