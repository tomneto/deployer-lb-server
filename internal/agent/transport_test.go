//go:build agent

package agent

import (
	"context"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestSend_SetsExpectedHeadersAndSignature(t *testing.T) {
	var gotAgentID, gotTs, gotToken string
	var gotBody []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAgentID = r.Header.Get("X-Agent-Id")
		gotTs = r.Header.Get("X-Agent-Ts")
		gotToken = r.Header.Get("X-Agent-Token")
		buf := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(buf)
		gotBody = buf
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := TransportConfig{IntakeURL: srv.URL, AgentID: "target-1", Secret: "shh"}
	body := []byte(`{"hello":"world"}`)

	if err := Send(context.Background(), cfg, body); err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	if gotAgentID != "target-1" {
		t.Fatalf("X-Agent-Id = %q, want target-1", gotAgentID)
	}
	if gotTs == "" {
		t.Fatal("X-Agent-Ts was empty")
	}
	wantSig := Sign("shh", gotTs, gotBody)
	if gotToken != wantSig {
		t.Fatalf("X-Agent-Token = %q, want %q (recomputed from observed ts+body)", gotToken, wantSig)
	}
}

func TestSend_NonSuccessStatusIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	cfg := TransportConfig{IntakeURL: srv.URL, AgentID: "t", Secret: "s"}
	if err := Send(context.Background(), cfg, []byte("{}")); err == nil {
		t.Fatal("expected error for 401 response, got nil")
	}
}

func TestSender_SendOrBuffer_BuffersOnFailureThenFlushesOnRecovery(t *testing.T) {
	dir := t.TempDir()
	var up atomic.Bool
	var receivedCount atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !up.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		receivedCount.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sender := &Sender{
		Cfg:    TransportConfig{IntakeURL: srv.URL, AgentID: "t", Secret: "s"},
		Buffer: NewDiskBuffer(dir, 100),
		Logger: log.New(os.Stderr, "test ", 0),
	}

	// Intake is down: two reports should be buffered, never lost.
	sender.SendOrBuffer(context.Background(), []byte(`{"n":1}`))
	sender.SendOrBuffer(context.Background(), []byte(`{"n":2}`))

	pending, err := sender.Buffer.Pending()
	if err != nil {
		t.Fatalf("Pending() error = %v", err)
	}
	if len(pending) != 2 {
		t.Fatalf("expected 2 buffered reports while down, got %d", len(pending))
	}

	// Intake recovers: the next successful send should drain the buffer too.
	up.Store(true)
	// Backoff was armed by the two prior failures; bypass it directly via
	// FlushBuffered to assert the buffer drains once the network is up,
	// without depending on wall-clock backoff timing in this test.
	sender.FlushBuffered(context.Background())

	pending, err = sender.Buffer.Pending()
	if err != nil {
		t.Fatalf("Pending() error = %v", err)
	}
	if len(pending) != 0 {
		t.Fatalf("expected buffer drained after recovery, got %d pending", len(pending))
	}
	if receivedCount.Load() != 2 {
		t.Fatalf("expected intake to receive 2 flushed reports, got %d", receivedCount.Load())
	}
}

func TestSender_InBackoff_SkipsNetworkAttempt(t *testing.T) {
	dir := t.TempDir()
	var attempts atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	sender := &Sender{
		Cfg:     TransportConfig{IntakeURL: srv.URL, AgentID: "t", Secret: "s"},
		Buffer:  NewDiskBuffer(dir, 100),
		Backoff: BackoffPolicy{Initial: time.Hour, Max: time.Hour, Factor: 2},
	}

	sender.SendOrBuffer(context.Background(), []byte(`{"n":1}`))
	if attempts.Load() != 1 {
		t.Fatalf("expected exactly 1 network attempt for the first failure, got %d", attempts.Load())
	}

	// Second call should be within the (1h) backoff window and skip the
	// network entirely, buffering directly.
	sender.SendOrBuffer(context.Background(), []byte(`{"n":2}`))
	if attempts.Load() != 1 {
		t.Fatalf("expected no additional network attempt while backing off, got %d total", attempts.Load())
	}

	pending, err := sender.Buffer.Pending()
	if err != nil {
		t.Fatalf("Pending() error = %v", err)
	}
	if len(pending) != 2 {
		t.Fatalf("expected both reports buffered, got %d", len(pending))
	}
}

func TestDiskBuffer_PushPendingRemove(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "buf")
	b := NewDiskBuffer(dir, 10)

	if err := b.Push([]byte(`{"a":1}`)); err != nil {
		t.Fatalf("Push() error = %v", err)
	}
	if err := b.Push([]byte(`{"a":2}`)); err != nil {
		t.Fatalf("Push() error = %v", err)
	}

	pending, err := b.Pending()
	if err != nil {
		t.Fatalf("Pending() error = %v", err)
	}
	if len(pending) != 2 {
		t.Fatalf("expected 2 pending files, got %d", len(pending))
	}

	if err := b.Remove(pending[0]); err != nil {
		t.Fatalf("Remove() error = %v", err)
	}
	pending, _ = b.Pending()
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending file after removal, got %d", len(pending))
	}
}

func TestDiskBuffer_TrimsOldestBeyondMax(t *testing.T) {
	dir := t.TempDir()
	b := NewDiskBuffer(dir, 2)

	for i := 0; i < 5; i++ {
		if err := b.Push([]byte("x")); err != nil {
			t.Fatalf("Push() error = %v", err)
		}
	}

	pending, err := b.Pending()
	if err != nil {
		t.Fatalf("Pending() error = %v", err)
	}
	if len(pending) != 2 {
		t.Fatalf("expected buffer trimmed to MaxFiles=2, got %d", len(pending))
	}
}

func TestDiskBuffer_PendingOnMissingDirIsEmptyNotError(t *testing.T) {
	b := NewDiskBuffer(filepath.Join(t.TempDir(), "never-created"), 10)
	pending, err := b.Pending()
	if err != nil {
		t.Fatalf("Pending() on missing dir returned error = %v, want nil", err)
	}
	if len(pending) != 0 {
		t.Fatalf("expected empty pending, got %v", pending)
	}
}
