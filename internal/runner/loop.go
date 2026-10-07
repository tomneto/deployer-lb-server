package runner

import (
	"context"
	"log"
	"time"
)

// Claimer is the slice of Client the loop needs. An interface so the loop's
// tests drive it without an HTTP server, and so a future transport (a websocket
// claim, say) drops in without touching the loop.
type Claimer interface {
	Claim(ctx context.Context) (*Command, error)
	SendLog(ctx context.Context, batch LogBatch) error
	SendResult(ctx context.Context, res Result) error
}

// Loop is claim -> execute -> report, forever.
//
// Its single hard rule: no network failure ends it. The panel is the backoffice
// itself, and the backoffice restarts on every one of its own deploys — a
// runner that exits (or even just stops polling) on a refused connection would
// need a human to notice and restart it, every single deploy.
type Loop struct {
	Client Claimer
	Exec   *Executor
	Logger *log.Logger

	// IdleDelay is the pause after an empty claim. Small, because the server
	// long-poll is what actually keeps the runner from spinning; this only
	// covers a server that answers 204 immediately.
	IdleDelay time.Duration

	// Backoff governs the pause after a FAILED claim, which is a different
	// thing from an empty one and must not be confused with it: an empty claim
	// is the healthy idle state, a failed one means the panel is unreachable
	// and hammering it helps nobody.
	Backoff Backoff

	// ResultAttempts is how many times a result is retried before the runner
	// gives up and lets the panel's lease expire. The result is the one message
	// worth retrying: see Client.SendResult.
	ResultAttempts int
	ResultRetryGap time.Duration

	// sleep is injectable so the tests do not spend real seconds backing off.
	sleep func(ctx context.Context, d time.Duration) bool

	// onCycle, when set, is called after each full claim cycle. Tests use it to
	// stop a loop that is otherwise infinite by design.
	onCycle func(claimed bool, err error)
}

func (l *Loop) logf(format string, args ...any) {
	if l.Logger != nil {
		l.Logger.Printf(format, args...)
	}
}

func (l *Loop) idleDelay() time.Duration {
	if l.IdleDelay > 0 {
		return l.IdleDelay
	}
	return 2 * time.Second
}

// doSleep waits d, returning false if the context ended first.
func (l *Loop) doSleep(ctx context.Context, d time.Duration) bool {
	if l.sleep != nil {
		return l.sleep(ctx, d)
	}
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// Run blocks until ctx is cancelled.
func (l *Loop) Run(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}
		claimed, err := l.cycle(ctx)
		if l.onCycle != nil {
			l.onCycle(claimed, err)
		}
		if ctx.Err() != nil {
			return
		}

		switch {
		case err != nil:
			wait := l.Backoff.Next()
			l.logf("claim failed (%v); retrying in %s", err, wait)
			if !l.doSleep(ctx, wait) {
				return
			}
		case !claimed:
			// Empty poll: healthy. Backoff resets because the panel answered.
			l.Backoff.Reset()
			if !l.doSleep(ctx, l.idleDelay()) {
				return
			}
		default:
			// Work was done; go straight back for more, no pause. A build run
			// is ~14 commands and each pause here is dead time on every one.
			l.Backoff.Reset()
		}
	}
}

// cycle performs exactly one claim and, if it got work, runs it. It returns
// whether a command was claimed, and the claim error if any. A failure to
// execute is NOT an error here: it is a Result, and it has already been
// reported by the time this returns.
//
// recover() wraps the execution half for the same reason the agent's tick does:
// one unexpected nil in a command from the panel must not take the runner down.
func (l *Loop) cycle(ctx context.Context) (claimed bool, err error) {
	cmd, err := l.Client.Claim(ctx)
	if err != nil {
		// A cancelled context is a shutdown, not a panel failure; reporting it
		// as one would make the last log line of every clean stop a scary one.
		if ctx.Err() != nil {
			return false, nil
		}
		return false, err
	}
	if cmd == nil {
		return false, nil
	}

	defer func() {
		if r := recover(); r != nil {
			l.logf("recovered from panic while running command %s: %v", cmd.ID, r)
			l.report(ctx, Result{
				CommandID: cmd.ID,
				ExitCode:  ExitSpawnFailed,
				Error:     "runner panicked while executing the command",
			})
			claimed, err = true, nil
		}
	}()

	l.logf("command %s claimed (timeout=%ds stream=%t)", cmd.ID, cmd.TimeoutSeconds, cmd.Streaming())
	res := l.run(ctx, *cmd)
	l.logf("command %s finished: exit=%d timed_out=%t in %dms", cmd.ID, res.ExitCode, res.TimedOut, res.DurationMS)
	l.report(ctx, res)
	return true, nil
}

func (l *Loop) run(ctx context.Context, cmd Command) Result {
	seq := 0
	sink := func(lines []string) error {
		batch := LogBatch{CommandID: cmd.ID, Seq: seq, Lines: lines}
		seq++
		// Deliberately detached from ctx's cancellation for the common case?
		// No: if the runner is shutting down there is no point shipping logs.
		// But a failure here is swallowed by the executor by design.
		if err := l.Client.SendLog(ctx, batch); err != nil {
			l.logf("log batch %d for command %s dropped: %v", batch.Seq, cmd.ID, err)
			return err
		}
		return nil
	}
	return l.Exec.Execute(ctx, cmd, sink)
}

// report delivers the result, retrying a few times. It uses a context detached
// from the loop's own cancellation on purpose: when the runner is asked to stop
// mid-command, the panel still needs to hear how that command ended, or the run
// hangs until the lease expires.
func (l *Loop) report(ctx context.Context, res Result) {
	attempts := l.ResultAttempts
	if attempts <= 0 {
		attempts = 5
	}
	gap := l.ResultRetryGap
	if gap <= 0 {
		gap = 2 * time.Second
	}

	for i := 0; i < attempts; i++ {
		if err := l.Client.SendResult(context.WithoutCancel(ctx), res); err == nil {
			return
		} else {
			l.logf("result for command %s not delivered (attempt %d/%d): %v", res.CommandID, i+1, attempts, err)
		}
		if i == attempts-1 {
			break
		}
		// Sleep against the live ctx: a shutdown should not be held up for the
		// whole retry ladder, only for the attempts themselves.
		if !l.doSleep(ctx, gap) && ctx.Err() != nil {
			// Still make the remaining attempts back-to-back: the result
			// matters more than a prompt exit.
			continue
		}
	}
	l.logf("giving up on the result for command %s; the panel lease will expire it", res.CommandID)
}
