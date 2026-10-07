package runner

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

// fakeClaimer scripts a sequence of claim outcomes and records everything the
// loop sent back. No HTTP, no clock.
type fakeClaimer struct {
	mu sync.Mutex

	// script is consumed one entry per Claim call; the last entry repeats.
	script []claimOutcome
	calls  int

	logs    []LogBatch
	results []Result

	// logErr / resultErr simulate a panel that is up for claims and down for
	// everything else.
	logErr    error
	resultErr error
	// resultFailures makes SendResult fail this many times before succeeding,
	// so the retry ladder can be observed.
	resultFailures int
}

type claimOutcome struct {
	cmd *Command
	err error
}

func (f *fakeClaimer) Claim(ctx context.Context) (*Command, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	i := f.calls
	f.calls++
	if i >= len(f.script) {
		i = len(f.script) - 1
	}
	if i < 0 {
		return nil, nil
	}
	return f.script[i].cmd, f.script[i].err
}

func (f *fakeClaimer) SendLog(ctx context.Context, b LogBatch) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.logs = append(f.logs, b)
	return f.logErr
}

func (f *fakeClaimer) SendResult(ctx context.Context, r Result) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.resultFailures > 0 {
		f.resultFailures--
		return fmt.Errorf("panel restarting")
	}
	f.results = append(f.results, r)
	return f.resultErr
}

func (f *fakeClaimer) snapshot() (int, []LogBatch, []Result) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls, append([]LogBatch(nil), f.logs...), append([]Result(nil), f.results...)
}

// newTestLoop wires a loop whose sleeps are instantaneous and recorded, and
// which stops itself after `cycles` full iterations. Without the stop the loop
// is infinite by design, which is the property under test.
func newTestLoop(t *testing.T, c Claimer, cycles int) (*Loop, context.Context, *[]time.Duration) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	var slept []time.Duration
	n := 0
	l := &Loop{
		Client:         c,
		Exec:           testExecutor(t),
		IdleDelay:      7 * time.Second,
		Backoff:        Backoff{Initial: time.Second, Max: 8 * time.Second, Factor: 2},
		ResultAttempts: 3,
	}
	l.sleep = func(ctx context.Context, d time.Duration) bool {
		slept = append(slept, d)
		return ctx.Err() == nil
	}
	l.onCycle = func(bool, error) {
		n++
		if n >= cycles {
			cancel()
		}
	}
	return l, ctx, &slept
}

func runWithDeadline(t *testing.T, l *Loop, ctx context.Context) {
	t.Helper()
	done := make(chan struct{})
	go func() { l.Run(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Loop.Run did not return after its context was cancelled")
	}
}

// 204 is the normal idle state, not a failure: the loop must keep polling, must
// not execute anything, and must pause by IdleDelay rather than by the error
// backoff.
func TestLoop_EmptyClaimKeepsPollingWithoutExecuting(t *testing.T) {
	f := &fakeClaimer{script: []claimOutcome{{cmd: nil, err: nil}}}
	l, ctx, slept := newTestLoop(t, f, 4)
	runWithDeadline(t, l, ctx)

	calls, logs, results := f.snapshot()
	if calls != 4 {
		t.Errorf("Claim called %d times, want 4", calls)
	}
	if len(logs) != 0 || len(results) != 0 {
		t.Errorf("an empty claim must produce no log and no result, got %d/%d", len(logs), len(results))
	}
	for i, d := range *slept {
		if d != 7*time.Second {
			t.Errorf("sleep[%d] = %s, want the idle delay 7s (an empty poll is not an error)", i, d)
		}
	}
}

// The panel restarts on every backoffice deploy. A refused connection must cost
// a backoff, never the loop.
func TestLoop_NetworkFailureDoesNotBreakTheLoop(t *testing.T) {
	cmd := &Command{ID: "c1", Command: "echo hello", TimeoutSeconds: 5}
	f := &fakeClaimer{script: []claimOutcome{
		{err: fmt.Errorf("dial tcp: connection refused")},
		{err: fmt.Errorf("dial tcp: connection refused")},
		{err: fmt.Errorf("EOF")},
		{cmd: cmd},
		{cmd: nil},
	}}
	l, ctx, slept := newTestLoop(t, f, 5)
	runWithDeadline(t, l, ctx)

	calls, _, results := f.snapshot()
	if calls != 5 {
		t.Fatalf("Claim called %d times, want 5: the loop stopped on a network error", calls)
	}
	if len(results) != 1 || results[0].CommandID != "c1" {
		t.Fatalf("the command claimed after the outage did not run: %+v", results)
	}
	if results[0].ExitCode != 0 {
		t.Errorf("ExitCode = %d, want 0", results[0].ExitCode)
	}

	// Backoff grows while the panel is down, and the pause after the three
	// failures is NOT the idle delay — telling the two apart is the point.
	if len(*slept) < 3 {
		t.Fatalf("expected at least 3 sleeps, got %v", *slept)
	}
	got := (*slept)[:3]
	want := []time.Duration{1 * time.Second, 2 * time.Second, 4 * time.Second}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("backoff sleep[%d] = %s, want %s (got %v)", i, got[i], want[i], got)
		}
	}
}

// After the panel comes back, the next outage must start from the bottom of the
// ladder again — otherwise one bad minute leaves the runner sluggish all day.
func TestLoop_BackoffResetsAfterTheClaimSucceeds(t *testing.T) {
	f := &fakeClaimer{script: []claimOutcome{
		{err: fmt.Errorf("down")},
		{err: fmt.Errorf("down")},
		{cmd: nil}, // panel answers: healthy idle
		{err: fmt.Errorf("down again")},
		{cmd: nil},
	}}
	l, ctx, slept := newTestLoop(t, f, 5)
	runWithDeadline(t, l, ctx)

	if len(*slept) < 4 {
		t.Fatalf("sleeps = %v", *slept)
	}
	s := *slept
	if s[0] != time.Second || s[1] != 2*time.Second {
		t.Errorf("backoff did not climb: %v", s)
	}
	if s[2] != 7*time.Second {
		t.Errorf("sleep after a healthy empty claim = %s, want the idle delay", s[2])
	}
	if s[3] != time.Second {
		t.Errorf("backoff after recovery = %s, want it reset to 1s (got %v)", s[3], s)
	}
}

// Work claimed means work reported — and no pause before asking for the next
// command, because a build run is ~14 round-trips and each pause is dead time.
func TestLoop_ClaimedWorkIsExecutedAndReportedWithoutAPause(t *testing.T) {
	f := &fakeClaimer{script: []claimOutcome{
		{cmd: &Command{ID: "a", Command: "echo one", TimeoutSeconds: 5}},
		{cmd: &Command{ID: "b", Command: "exit 9", TimeoutSeconds: 5}},
		{cmd: nil},
	}}
	l, ctx, slept := newTestLoop(t, f, 2)
	runWithDeadline(t, l, ctx)

	_, _, results := f.snapshot()
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}
	if results[0].ExitCode != 0 || results[1].ExitCode != 9 {
		t.Errorf("exit codes = %d/%d, want 0/9", results[0].ExitCode, results[1].ExitCode)
	}
	if len(*slept) != 0 {
		t.Errorf("the loop paused between commands: %v", *slept)
	}
}

// Stream mode must reach the log endpoint with a monotonic, gapless seq.
func TestLoop_StreamModeFeedsTheLogEndpoint(t *testing.T) {
	f := &fakeClaimer{script: []claimOutcome{
		{cmd: &Command{ID: "s", Command: "echo a; echo b; echo c; echo d", TimeoutSeconds: 5, Mode: "stream"}},
		{cmd: nil},
	}}
	l, ctx, _ := newTestLoop(t, f, 1)
	runWithDeadline(t, l, ctx)

	_, logs, results := f.snapshot()
	if len(logs) == 0 {
		t.Fatal("stream mode produced no log batch")
	}
	for i, b := range logs {
		if b.Seq != i {
			t.Errorf("batch %d has seq %d; a gap makes a hole in the log invisible", i, b.Seq)
		}
		if b.CommandID != "s" {
			t.Errorf("batch %d carries command_id %q", i, b.CommandID)
		}
	}
	if len(results) != 1 {
		t.Fatalf("results = %+v", results)
	}
}

// A log endpoint that is down must not cost the command.
func TestLoop_LogFailureStillProducesAResult(t *testing.T) {
	f := &fakeClaimer{
		script: []claimOutcome{
			{cmd: &Command{ID: "s", Command: "echo a; echo b", TimeoutSeconds: 5, Mode: "stream"}},
			{cmd: nil},
		},
		logErr: fmt.Errorf("panel is down"),
	}
	l, ctx, _ := newTestLoop(t, f, 1)
	runWithDeadline(t, l, ctx)

	_, _, results := f.snapshot()
	if len(results) != 1 || results[0].ExitCode != 0 {
		t.Fatalf("the command should have finished and reported despite the log failing: %+v", results)
	}
}

// The result is the one message worth retrying: losing it means the run hangs
// until the panel's lease expires.
func TestLoop_ResultIsRetried(t *testing.T) {
	f := &fakeClaimer{
		script:         []claimOutcome{{cmd: &Command{ID: "r", Command: "true", TimeoutSeconds: 5}}, {cmd: nil}},
		resultFailures: 2,
	}
	l, ctx, _ := newTestLoop(t, f, 1)
	runWithDeadline(t, l, ctx)

	_, _, results := f.snapshot()
	if len(results) != 1 {
		t.Fatalf("result not delivered after retries: %+v", results)
	}
}

// Giving up on a result is allowed (the lease catches it) — but giving up must
// not take the loop with it.
func TestLoop_GivingUpOnAResultDoesNotBreakTheLoop(t *testing.T) {
	f := &fakeClaimer{
		script:         []claimOutcome{{cmd: &Command{ID: "r", Command: "true", TimeoutSeconds: 5}}, {cmd: nil}},
		resultFailures: 99,
	}
	l, ctx, _ := newTestLoop(t, f, 3)
	runWithDeadline(t, l, ctx)

	calls, _, _ := f.snapshot()
	if calls < 3 {
		t.Errorf("Claim called %d times, want 3: an undeliverable result stopped the loop", calls)
	}
}

// A timed-out command is a normal result on the wire, not an exception: the
// panel has to learn the reason rather than wait out the lease.
func TestLoop_TimeoutIsReportedAsAResult(t *testing.T) {
	f := &fakeClaimer{script: []claimOutcome{
		{cmd: &Command{ID: "slow", Command: "sleep 30", TimeoutSeconds: 1}},
		{cmd: nil},
	}}
	l, ctx, _ := newTestLoop(t, f, 1)
	runWithDeadline(t, l, ctx)

	_, _, results := f.snapshot()
	if len(results) != 1 {
		t.Fatalf("results = %+v", results)
	}
	if !results[0].TimedOut || results[0].ExitCode != ExitTimedOut {
		t.Errorf("result = %+v, want TimedOut with exit %d", results[0], ExitTimedOut)
	}
	if results[0].Error == "" {
		t.Error("a timeout must carry a readable reason; plan §1.3 wants a legible failure, not a hang")
	}
}

// Shutdown is not a panel failure: the last line of a clean stop must not be an
// error, and Run must actually return.
func TestLoop_CancelledContextStopsCleanly(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	f := &fakeClaimer{script: []claimOutcome{{cmd: nil}}}
	l := &Loop{Client: f, Exec: testExecutor(t), IdleDelay: time.Millisecond}
	go func() { l.Run(ctx); close(stopped) }()

	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

// The panel detects a lost log batch by a jump in seq. A keepalive carries no
// output, so burning a number on it would stamp a hole into a log that has
// none — and the panel would report a gap on a perfectly healthy build.
func TestLoop_KeepaliveDoesNotConsumeASequenceNumber(t *testing.T) {
	f := &fakeClaimer{}
	loop := &Loop{
		Client: f,
		Exec: &Executor{
			Workdir:           t.TempDir(),
			DefaultTimeout:    5 * time.Second,
			FlushInterval:     time.Millisecond,
			FlushLines:        1,
			KeepaliveInterval: 20 * time.Millisecond,
		},
	}
	// One batch, a quiet stretch long enough for several keepalives, another
	// batch.
	loop.run(context.Background(), Command{
		ID:      "c",
		Command: "echo one; sleep 0.25; echo two",
		Mode:    "stream", TimeoutSeconds: 5,
	})

	_, logs, _ := f.snapshot()
	keepalives, nextSeq := 0, 0
	for _, b := range logs {
		if len(b.Lines) == 0 {
			keepalives++
			if b.Seq != nextSeq {
				t.Errorf("keepalive carries seq %d, want %d (the number the next real batch will use)", b.Seq, nextSeq)
			}
			continue
		}
		if b.Seq != nextSeq {
			t.Fatalf("batch with output carries seq %d, want %d: a keepalive consumed a number (logs=%v)", b.Seq, nextSeq, logs)
		}
		nextSeq++
	}
	if keepalives == 0 {
		t.Fatalf("no keepalive was sent during the quiet stretch (logs=%v)", logs)
	}
	if nextSeq < 2 {
		t.Fatalf("expected two batches with output, got %d (logs=%v)", nextSeq, logs)
	}
}
