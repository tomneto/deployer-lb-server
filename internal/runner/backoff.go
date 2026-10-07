package runner

import "time"

// Backoff is a minimal exponential backoff with a cap.
//
// internal/agent has the same shape, but it lives behind the `agent` build tag
// and is entangled with the disk buffer there. Ten lines duplicated beats
// dragging the agent's dependency graph into a binary that reports nothing.
type Backoff struct {
	Initial time.Duration
	Max     time.Duration
	Factor  float64

	cur time.Duration
}

func DefaultBackoff() Backoff {
	return Backoff{Initial: 1 * time.Second, Max: 60 * time.Second, Factor: 2}
}

// Next advances and returns the new wait. Reset puts it back to zero after any
// successful exchange, so one bad minute does not leave the runner sluggish for
// the rest of the day.
func (b *Backoff) Next() time.Duration {
	if b.Factor <= 1 {
		b.Factor = 2
	}
	if b.Initial <= 0 {
		b.Initial = time.Second
	}
	if b.Max <= 0 {
		b.Max = 60 * time.Second
	}
	if b.cur <= 0 {
		b.cur = b.Initial
	} else {
		b.cur = time.Duration(float64(b.cur) * b.Factor)
	}
	if b.cur > b.Max {
		b.cur = b.Max
	}
	return b.cur
}

func (b *Backoff) Reset() { b.cur = 0 }
