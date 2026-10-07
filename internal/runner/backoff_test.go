package runner

import (
	"testing"
	"time"
)

func TestBackoff_ClimbsAndCaps(t *testing.T) {
	b := Backoff{Initial: time.Second, Max: 5 * time.Second, Factor: 2}
	want := []time.Duration{1, 2, 4, 5, 5}
	for i, w := range want {
		if got := b.Next(); got != w*time.Second {
			t.Fatalf("Next()[%d] = %s, want %s", i, got, w*time.Second)
		}
	}
	b.Reset()
	if got := b.Next(); got != time.Second {
		t.Errorf("after Reset, Next() = %s, want the initial 1s", got)
	}
}

// A zero-valued Backoff must still back off. The alternative is a runner that
// retries a dead panel as fast as the CPU allows because a field was not set.
func TestBackoff_ZeroValueIsSane(t *testing.T) {
	var b Backoff
	first := b.Next()
	if first <= 0 {
		t.Fatalf("Next() = %s on a zero value", first)
	}
	second := b.Next()
	if second <= first {
		t.Errorf("Next() did not grow: %s then %s", first, second)
	}
	for i := 0; i < 50; i++ {
		b.Next()
	}
	if b.Next() > time.Minute {
		t.Errorf("zero value grew past a sane cap: %s", b.Next())
	}
}
