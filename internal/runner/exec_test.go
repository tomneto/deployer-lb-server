package runner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testExecutor(t *testing.T) *Executor {
	t.Helper()
	return &Executor{
		Workdir:        t.TempDir(),
		DefaultTimeout: 10 * time.Second,
		KillGrace:      200 * time.Millisecond,
		FlushInterval:  10 * time.Millisecond,
		FlushLines:     2,
	}
}

func TestExecute_CapturesOutputAndExitCode(t *testing.T) {
	e := testExecutor(t)
	res := e.Execute(context.Background(), Command{
		ID:             "c1",
		Command:        "echo out; echo err 1>&2; exit 3",
		TimeoutSeconds: 10,
	}, nil)

	if res.ExitCode != 3 {
		t.Errorf("ExitCode = %d, want 3", res.ExitCode)
	}
	if res.TimedOut {
		t.Error("TimedOut should be false")
	}
	// stdout and stderr share one channel: a build log that separates them is
	// a build log you cannot read.
	if !strings.Contains(res.Output, "out") || !strings.Contains(res.Output, "err") {
		t.Errorf("Output = %q, want both stdout and stderr", res.Output)
	}
	if res.CommandID != "c1" {
		t.Errorf("CommandID = %q", res.CommandID)
	}
}

func TestExecute_RunsInWorkdir(t *testing.T) {
	e := testExecutor(t)
	res := e.Execute(context.Background(), Command{ID: "c", Command: "pwd", TimeoutSeconds: 10}, nil)
	if res.ExitCode != 0 {
		t.Fatalf("exit=%d output=%q", res.ExitCode, res.Output)
	}
	// macOS hands out /var/folders/... which is a symlink to /private/var/...,
	// so compare the resolved paths rather than the strings.
	got, _ := filepath.EvalSymlinks(strings.TrimSpace(res.Output))
	want, _ := filepath.EvalSymlinks(e.Workdir)
	if got != want {
		t.Errorf("pwd = %q, want %q", got, want)
	}
}

func TestExecute_CommandWorkdirIsRelativeToTheFlag(t *testing.T) {
	e := testExecutor(t)
	sub := filepath.Join(e.Workdir, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	res := e.Execute(context.Background(), Command{ID: "c", Command: "pwd", Workdir: "sub", TimeoutSeconds: 10}, nil)
	got, _ := filepath.EvalSymlinks(strings.TrimSpace(res.Output))
	want, _ := filepath.EvalSymlinks(sub)
	if got != want {
		t.Errorf("pwd = %q, want %q", got, want)
	}
}

func TestExecute_SpawnFailureIsAResultNotAHang(t *testing.T) {
	e := testExecutor(t)
	e.Workdir = filepath.Join(t.TempDir(), "does-not-exist")
	res := e.Execute(context.Background(), Command{ID: "c", Command: "true", TimeoutSeconds: 5}, nil)
	if res.ExitCode != ExitSpawnFailed {
		t.Errorf("ExitCode = %d, want %d", res.ExitCode, ExitSpawnFailed)
	}
	if res.Error == "" {
		t.Error("a spawn failure must carry a readable reason")
	}
}

func TestExecute_EmptyCommand(t *testing.T) {
	e := testExecutor(t)
	res := e.Execute(context.Background(), Command{ID: "c", Command: "   "}, nil)
	if res.ExitCode != ExitSpawnFailed || res.Error == "" {
		t.Errorf("empty command should fail with a reason, got %+v", res)
	}
}

func TestExecute_StreamModeShipsLinesWhileRunning(t *testing.T) {
	e := testExecutor(t)
	var got []string
	done := make(chan struct{})
	res := e.Execute(context.Background(), Command{
		ID:             "c",
		Command:        "for i in 1 2 3 4; do echo line-$i; done",
		TimeoutSeconds: 10,
		Mode:           "stream",
	}, func(lines []string) error {
		got = append(got, lines...)
		return nil
	})
	close(done)

	if res.ExitCode != 0 {
		t.Fatalf("exit=%d output=%q", res.ExitCode, res.Output)
	}
	if len(got) != 4 {
		t.Fatalf("sink received %d lines (%v), want 4", len(got), got)
	}
	if res.Seq == 0 {
		t.Error("Seq should count the batches that went out")
	}
	// The authoritative copy still rides along with the result: a dropped
	// batch must cost liveness, not data.
	if !strings.Contains(res.Output, "line-4") {
		t.Errorf("Output = %q, want the full text even in stream mode", res.Output)
	}
}

func TestExecute_BufferedModeNeverCallsTheSink(t *testing.T) {
	e := testExecutor(t)
	called := 0
	res := e.Execute(context.Background(), Command{
		ID: "c", Command: "echo a; echo b", TimeoutSeconds: 10, Mode: "buffered",
	}, func([]string) error { called++; return nil })

	if called != 0 {
		t.Errorf("sink called %d times in buffered mode, want 0", called)
	}
	if !strings.Contains(res.Output, "a") || !strings.Contains(res.Output, "b") {
		t.Errorf("Output = %q", res.Output)
	}
}

// A sink that fails is a panel that is unreachable. The command must finish
// anyway: the run matters, the live view does not.
func TestExecute_SinkErrorDoesNotAbortTheCommand(t *testing.T) {
	e := testExecutor(t)
	res := e.Execute(context.Background(), Command{
		ID: "c", Command: "echo a; echo b; echo c; exit 0", TimeoutSeconds: 10, Mode: "stream",
	}, func([]string) error { return fmt.Errorf("panel is down") })

	if res.ExitCode != 0 {
		t.Errorf("ExitCode = %d, want 0 despite the sink failing", res.ExitCode)
	}
	if !strings.Contains(res.Output, "c") {
		t.Errorf("Output = %q, want the full output despite the sink failing", res.Output)
	}
}

func TestExecute_TruncatesRunawayOutput(t *testing.T) {
	e := testExecutor(t)
	e.MaxOutputBytes = 200
	res := e.Execute(context.Background(), Command{
		ID: "c", Command: "i=0; while [ $i -lt 200 ]; do echo aaaaaaaaaaaaaaaaaaaa; i=$((i+1)); done",
		TimeoutSeconds: 20,
	}, nil)

	if !res.Truncated {
		t.Error("Truncated should be true")
	}
	if len(res.Output) > 400 {
		t.Errorf("retained %d bytes, cap was 200", len(res.Output))
	}
}

// The one that matters most: a command that blows its deadline is killed, the
// result says so, and NOTHING it spawned survives.
//
// The command backgrounds a writer loop and then sleeps. Killing only the
// direct child (the shell) would leave that writer running with the pipe still
// open — which would ALSO hang Execute forever waiting for EOF. So this test
// catches an orphan twice: once by hanging, once by the file still growing.
func TestExecute_TimeoutKillsTheWholeProcessGroup(t *testing.T) {
	e := testExecutor(t)
	marker := filepath.Join(e.Workdir, "ticks")

	script := fmt.Sprintf(
		`( while true; do echo tick >> %q; sleep 0.1; done ) & echo started; sleep 60`,
		marker,
	)

	type outcome struct {
		res     Result
		elapsed time.Duration
	}
	ch := make(chan outcome, 1)
	go func() {
		start := time.Now()
		r := e.Execute(context.Background(), Command{ID: "slow", Command: script, TimeoutSeconds: 1}, nil)
		ch <- outcome{r, time.Since(start)}
	}()

	var got outcome
	select {
	case got = <-ch:
	case <-time.After(15 * time.Second):
		t.Fatal("Execute never returned: a child outlived the kill and kept the output pipe open")
	}

	if !got.res.TimedOut {
		t.Error("TimedOut should be true")
	}
	if got.res.ExitCode != ExitTimedOut {
		t.Errorf("ExitCode = %d, want %d", got.res.ExitCode, ExitTimedOut)
	}
	if got.res.Error == "" || !strings.Contains(got.res.Error, "timeout") {
		t.Errorf("Error = %q, want a readable timeout reason", got.res.Error)
	}
	if got.elapsed > 10*time.Second {
		t.Errorf("took %s to enforce a 1s timeout", got.elapsed)
	}
	// Output collected before the kill still comes back.
	if !strings.Contains(got.res.Output, "started") {
		t.Errorf("Output = %q, want what the command printed before it was killed", got.res.Output)
	}

	// Now the orphan check proper: the background writer must be dead.
	sizeAt := func() int64 {
		fi, err := os.Stat(marker)
		if err != nil {
			return -1
		}
		return fi.Size()
	}
	first := sizeAt()
	time.Sleep(700 * time.Millisecond)
	if second := sizeAt(); second != first {
		t.Errorf("the backgrounded child survived the timeout: marker grew %d -> %d bytes", first, second)
	}
}

// Shutting the runner down mid-command is not the command's fault: the process
// group still dies (no orphan), but the result must not claim a timeout.
func TestExecute_ContextCancelKillsWithoutClaimingATimeout(t *testing.T) {
	e := testExecutor(t)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(300 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	res := e.Execute(ctx, Command{ID: "c", Command: "sleep 60", TimeoutSeconds: 60}, nil)
	elapsed := time.Since(start)

	if elapsed > 10*time.Second {
		t.Fatalf("cancel did not tear the command down (%s)", elapsed)
	}
	if res.TimedOut {
		t.Error("a shutdown must not be reported as the command timing out")
	}
}
