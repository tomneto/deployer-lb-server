package runner

import (
	"encoding/json"
	"testing"
	"time"
)

func TestCommand_StreamingFromMode(t *testing.T) {
	cases := map[string]bool{
		"stream":    true,
		"STREAM":    true,
		" live ":    true,
		"streaming": true,
		"buffered":  false,
		"":          false,
		"collect":   false,
	}
	for mode, want := range cases {
		if got := (Command{Mode: mode}).Streaming(); got != want {
			t.Errorf("Streaming() for mode %q = %t, want %t", mode, got, want)
		}
	}
}

// The boolean alias has to WIN over the string: a panel that sends both is
// telling us the same thing twice, and if it ever disagrees the explicit
// boolean is the less ambiguous of the two.
func TestCommand_StreamBooleanOverridesMode(t *testing.T) {
	no := false
	yes := true
	if (Command{Mode: "stream", Stream: &no}).Streaming() {
		t.Error("stream:false should override mode:stream")
	}
	if !(Command{Mode: "buffered", Stream: &yes}).Streaming() {
		t.Error("stream:true should override mode:buffered")
	}
}

func TestCommand_TimeoutNeverZero(t *testing.T) {
	if got := (Command{TimeoutSeconds: 7}).Timeout(time.Minute); got != 7*time.Second {
		t.Errorf("Timeout() = %s, want 7s", got)
	}
	if got := (Command{}).Timeout(time.Minute); got != time.Minute {
		t.Errorf("Timeout() fallback = %s, want 1m", got)
	}
	// Both the command and the runner silent: still a deadline, never "forever".
	if got := (Command{TimeoutSeconds: -1}).Timeout(0); got != DefaultCommandTimeout {
		t.Errorf("Timeout() default = %s, want %s", got, DefaultCommandTimeout)
	}
}

// The Python side is written in parallel, so decoding must survive extra
// fields and must not need the optional ones.
func TestCommand_DecodeIsPermissive(t *testing.T) {
	var c Command
	body := `{"id":"c1","command":"echo hi","timeout_seconds":5,"mode":"stream","unknown_field":{"a":1}}`
	if err := json.Unmarshal([]byte(body), &c); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if c.ID != "c1" || c.Command != "echo hi" || c.TimeoutSeconds != 5 || !c.Streaming() {
		t.Fatalf("decoded badly: %+v", c)
	}

	var min Command
	if err := json.Unmarshal([]byte(`{"id":"c2","command":"true"}`), &min); err != nil {
		t.Fatalf("Unmarshal minimal: %v", err)
	}
	if min.Streaming() {
		t.Error("a command with no mode should not stream")
	}
}
