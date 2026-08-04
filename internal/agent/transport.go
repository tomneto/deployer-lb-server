//go:build agent

package agent

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"
)

// TransportConfig holds everything Send/Sender need to reach the intake.
type TransportConfig struct {
	IntakeURL string
	AgentID   string
	Secret    string
	Client    *http.Client
}

// Send performs a single POST attempt and returns a non-nil error on any
// failure (network, non-2xx status). It never panics and never touches the
// disk buffer — that's the caller's job (Sender.Run below) so this function
// stays trivially testable with httptest.
func Send(ctx context.Context, cfg TransportConfig, body []byte) error {
	client := cfg.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}

	ts := strconv.FormatInt(time.Now().Unix(), 10)
	sig := Sign(cfg.Secret, ts, body)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.IntakeURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Id", cfg.AgentID)
	req.Header.Set("X-Agent-Ts", ts)
	req.Header.Set("X-Agent-Token", sig)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("post: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("intake returned status %d", resp.StatusCode)
	}
	return nil
}

// Sender drives the periodic report loop: collect -> send -> on failure,
// buffer to disk; on success, also flush any older buffered reports so the
// central catches up once reachable again. It never lets a failure abort the
// process (D5/B2: "nunca deve travar/derrubar o processo").
type Sender struct {
	Cfg     TransportConfig
	Buffer  *DiskBuffer
	Backoff BackoffPolicy
	Logger  *log.Logger

	mu          sync.Mutex
	curBackoff  time.Duration
	nextAttempt time.Time
}

// BackoffPolicy is a minimal exponential backoff with a cap, used both for
// immediate retries of the current report and for draining the disk buffer.
type BackoffPolicy struct {
	Initial time.Duration
	Max     time.Duration
	Factor  float64
}

func DefaultBackoff() BackoffPolicy {
	return BackoffPolicy{Initial: 1 * time.Second, Max: 60 * time.Second, Factor: 2}
}

func (p BackoffPolicy) next(cur time.Duration) time.Duration {
	if cur <= 0 {
		cur = p.Initial
	}
	next := time.Duration(float64(cur) * p.Factor)
	if next > p.Max {
		next = p.Max
	}
	return next
}

// SendOrBuffer tries to POST body once; on failure it buffers to disk instead
// of retrying inline (inline retries would delay the next collection tick —
// retries happen out-of-band via FlushBuffered on the next successful send or
// the background flush loop).
//
// While in a backoff window (set by a previous failure), it skips the
// network attempt entirely and buffers straight away — this is the "retry
// com backoff" from plan B2: a down intake doesn't get hammered every fixed
// collection tick, the effective retry interval grows (capped) until a send
// succeeds again, at which point the backoff resets.
func (s *Sender) SendOrBuffer(ctx context.Context, body []byte) {
	if s.inBackoff() {
		s.logf("intake in backoff window, buffering without attempting send")
		s.bufferOrDrop(body)
		return
	}

	if err := Send(ctx, s.Cfg, body); err != nil {
		s.logf("send failed, buffering: %v", err)
		s.bufferOrDrop(body)
		s.recordFailure()
		return
	}
	s.recordSuccess()
	// Best-effort: drain previously buffered reports now that intake is up.
	s.FlushBuffered(ctx)
}

func (s *Sender) bufferOrDrop(body []byte) {
	if s.Buffer == nil {
		return
	}
	if berr := s.Buffer.Push(body); berr != nil {
		s.logf("buffer write failed (dropping report): %v", berr)
	}
}

func (s *Sender) backoffPolicy() BackoffPolicy {
	if s.Backoff == (BackoffPolicy{}) {
		return DefaultBackoff()
	}
	return s.Backoff
}

func (s *Sender) inBackoff() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return time.Now().Before(s.nextAttempt)
}

func (s *Sender) recordFailure() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.curBackoff = s.backoffPolicy().next(s.curBackoff)
	s.nextAttempt = time.Now().Add(s.curBackoff)
}

func (s *Sender) recordSuccess() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.curBackoff = 0
	s.nextAttempt = time.Time{}
}

// FlushBuffered attempts to resend every buffered report, oldest first,
// stopping at the first failure (preserves order; avoids hammering an
// already-down intake).
func (s *Sender) FlushBuffered(ctx context.Context) {
	if s.Buffer == nil {
		return
	}
	pending, err := s.Buffer.Pending()
	if err != nil {
		s.logf("buffer list failed: %v", err)
		return
	}
	for _, path := range pending {
		data, err := os.ReadFile(path)
		if err != nil {
			s.logf("buffer read failed for %s: %v", path, err)
			continue
		}
		if err := Send(ctx, s.Cfg, data); err != nil {
			s.logf("flush stopped, intake still unreachable: %v", err)
			s.recordFailure()
			return
		}
		if err := s.Buffer.Remove(path); err != nil {
			s.logf("buffer cleanup failed for %s: %v", path, err)
		}
	}
}

func (s *Sender) logf(format string, args ...interface{}) {
	if s.Logger != nil {
		s.Logger.Printf(format, args...)
	}
}
