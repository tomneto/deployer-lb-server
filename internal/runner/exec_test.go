package runner

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

// ───────────────────── keepalive while a command is quiet ─────────────────

// A build is quiet for minutes at a time (a compile, a layer upload), and the
// panel's lease is renewed only by a log call. Without this the runner would be
// given up on exactly during the steps phase 2 exists for.
func TestExecute_QuietCommandKeepsTheLeaseAlive(t *testing.T) {
	e := testExecutor(t)
	e.KeepaliveInterval = 20 * time.Millisecond

	var mu sync.Mutex
	var batches [][]string
	sink := func(lines []string) error {
		mu.Lock()
		defer mu.Unlock()
		batches = append(batches, lines)
		return nil
	}

	res := e.Execute(context.Background(), Command{
		ID: "quiet", Command: "sleep 0.4", Mode: "stream", TimeoutSeconds: 10,
	}, sink)
	if res.ExitCode != 0 {
		t.Fatalf("exit=%d output=%q", res.ExitCode, res.Output)
	}

	mu.Lock()
	defer mu.Unlock()
	empty := 0
	for _, b := range batches {
		if len(b) == 0 {
			empty++
		}
	}
	if empty == 0 {
		t.Fatalf("a command that printed nothing for 400ms sent no keepalive (batches=%v)", batches)
	}
	// It must not count as output, or the result would promise log batches the
	// panel never got lines from.
	if res.Seq != 0 {
		t.Errorf("Seq = %d, want 0: a keepalive is not a batch", res.Seq)
	}
}

// A command that is talking already renews the lease by talking; a keepalive on
// top of that is pure noise on the panel.
func TestExecute_ChattyCommandSendsNoKeepalive(t *testing.T) {
	e := testExecutor(t)
	e.KeepaliveInterval = 30 * time.Millisecond
	e.FlushInterval = time.Millisecond
	e.FlushLines = 1

	var mu sync.Mutex
	empty := 0
	sink := func(lines []string) error {
		mu.Lock()
		defer mu.Unlock()
		if len(lines) == 0 {
			empty++
		}
		return nil
	}

	res := e.Execute(context.Background(), Command{
		ID:      "chatty",
		Command: "for i in 1 2 3 4 5 6 7 8; do echo line$i; sleep 0.02; done",
		Mode:    "stream", TimeoutSeconds: 10,
	}, sink)
	if res.ExitCode != 0 {
		t.Fatalf("exit=%d output=%q", res.ExitCode, res.Output)
	}

	mu.Lock()
	defer mu.Unlock()
	if empty != 0 {
		t.Errorf("sent %d keepalive(s) while the command was printing every 20ms", empty)
	}
}

// `docker login` gets two minutes and the lease is shorter than that: a
// buffered command has to renew its lease too, even though it ships no output
// until the end.
func TestExecute_BufferedCommandAlsoKeepsAlive(t *testing.T) {
	e := testExecutor(t)
	e.KeepaliveInterval = 20 * time.Millisecond

	var mu sync.Mutex
	empty := 0
	sink := func(lines []string) error {
		mu.Lock()
		defer mu.Unlock()
		if len(lines) == 0 {
			empty++
		}
		return nil
	}

	e.Execute(context.Background(), Command{
		ID: "buffered", Command: "sleep 0.3", TimeoutSeconds: 10,
	}, sink)

	mu.Lock()
	defer mu.Unlock()
	if empty == 0 {
		t.Error("a buffered command sent no keepalive: its lease would expire while it was merely slow")
	}
}

// O campo `stdin` existe para que um segredo não precise viajar dentro da
// string do comando. Antes dele o painel embutia um here-document no
// `Command`, e essa string vira o argv de `/bin/sh -c` nesta máquina —
// legível por `ps -ww` para qualquer usuário. `docker login --password-stdin`
// era o caso: a senha ficava fora do argv do docker e caía no do shell.
func TestExecute_StdinIsFedToTheCommand(t *testing.T) {
	e := testExecutor(t)
	res := e.Execute(context.Background(), Command{
		ID:      "c1",
		Command: "cat",
		Stdin:   base64.StdEncoding.EncodeToString([]byte("segredo-por-stdin\n")),
	}, nil)

	if res.ExitCode != 0 {
		t.Fatalf("esperava exit 0, veio %d (%s)", res.ExitCode, res.Error)
	}
	if !strings.Contains(res.Output, "segredo-por-stdin") {
		t.Fatalf("o stdin não chegou ao comando: %q", res.Output)
	}
	// E o segredo NÃO aparece na string do comando — que é o ponto inteiro.
	if strings.Contains("cat", "segredo") {
		t.Fatal("o segredo não pode estar no comando")
	}
}

func TestExecute_NoStdinStillGetsEOF(t *testing.T) {
	// Um comando que lê stdin tem de receber EOF em vez de travar até o
	// timeout — o comportamento de antes, preservado.
	e := testExecutor(t)
	res := e.Execute(context.Background(), Command{
		ID: "c2", Command: "cat", TimeoutSeconds: 5,
	}, nil)
	if res.TimedOut {
		t.Fatal("sem stdin, `cat` deve receber EOF e terminar, não estourar o timeout")
	}
	if res.ExitCode != 0 {
		t.Fatalf("esperava exit 0, veio %d", res.ExitCode)
	}
}

func TestExecute_MalformedStdinFailsLoudly(t *testing.T) {
	// Base64 quebrada não pode virar stdin vazio: `docker login` perguntaria a
	// senha e penduraria até o timeout, o que se lê como "o painel quebrou".
	e := testExecutor(t)
	res := e.Execute(context.Background(), Command{
		ID: "c3", Command: "cat", Stdin: "!!! isto não é base64 !!!",
	}, nil)
	if res.ExitCode != ExitSpawnFailed {
		t.Fatalf("esperava falha de spawn, veio exit %d", res.ExitCode)
	}
	if !strings.Contains(res.Error, "stdin") {
		t.Fatalf("o erro precisa dizer que foi o stdin: %q", res.Error)
	}
}
