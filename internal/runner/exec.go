package runner

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Executor runs one command from the panel in a shell on this machine.
//
// Everything about it is deliberately boring except the teardown: see Execute's
// comment on why the deadline is enforced by this code and not by
// exec.CommandContext.
type Executor struct {
	// Shell and ShellFlag spell out how a command string becomes a process.
	// Defaults: /bin/sh -c.
	Shell     string
	ShellFlag string

	// Workdir is the --workdir flag: the directory every command starts in
	// unless it carries its own.
	Workdir string

	// DefaultTimeout applies to a command that arrives without one.
	DefaultTimeout time.Duration

	// KillGrace is how long a timed-out process group gets between SIGTERM and
	// SIGKILL. A test runner that traps SIGTERM to print its failures deserves
	// the chance; a process that ignores it does not get to stay.
	KillGrace time.Duration

	// FlushInterval and FlushLines decide when a stream-mode batch goes out.
	// Whichever comes first.
	FlushInterval time.Duration
	FlushLines    int

	// MaxOutputBytes caps the retained output. Lines past the cap still flow to
	// the log endpoint in stream mode; it is the in-memory copy that stops
	// growing.
	MaxOutputBytes int

	// BaseEnv is the environment handed to commands. nil means os.Environ().
	BaseEnv []string
}

// LogSink receives a batch of output lines while the command is still running.
// It returns an error the executor deliberately ignores: a log batch that fails
// to reach the panel must never abort the command that produced it. The run
// matters; the live view is a convenience.
type LogSink func(lines []string) error

func (e *Executor) shell() (string, string) {
	sh, flag := e.Shell, e.ShellFlag
	if sh == "" {
		sh = "/bin/sh"
	}
	if flag == "" {
		flag = "-c"
	}
	return sh, flag
}

// resolveWorkdir picks the directory for this command: the command's own when
// absolute, the command's own resolved against --workdir when relative, the
// --workdir otherwise.
func (e *Executor) resolveWorkdir(c Command) string {
	switch {
	case c.Workdir == "":
		return e.Workdir
	case filepath.IsAbs(c.Workdir):
		return c.Workdir
	default:
		return filepath.Join(e.Workdir, c.Workdir)
	}
}

func (e *Executor) env(c Command) []string {
	base := e.BaseEnv
	if base == nil {
		base = os.Environ()
	}
	if len(c.Env) == 0 {
		return base
	}
	out := make([]string, 0, len(base)+len(c.Env))
	out = append(out, base...)
	for k, v := range c.Env {
		out = append(out, k+"="+v)
	}
	return out
}

func (e *Executor) maxOutput() int {
	if e.MaxOutputBytes > 0 {
		return e.MaxOutputBytes
	}
	return DefaultMaxOutputBytes
}

// Execute runs c to completion (or to its deadline) and always returns a
// Result — there is no error return, because every failure mode here is a
// result the panel needs to see rather than an exception the loop should
// handle.
//
// The deadline is NOT exec.CommandContext's: that one kills the direct child
// only, which for `sh -c "..."` is the shell, leaving its children alive with
// the pipe open. Here the child leads its own process group (isolateProcessGroup)
// and the deadline signals the whole group, SIGTERM then SIGKILL after
// KillGrace. That is the difference between "the command was killed" and "the
// command was killed and a `docker build` kept running on the laptop".
func (e *Executor) Execute(ctx context.Context, c Command, sink LogSink) Result {
	started := time.Now()
	res := Result{CommandID: c.ID}

	finish := func() Result {
		res.DurationMS = time.Since(started).Milliseconds()
		return res
	}

	if strings.TrimSpace(c.Command) == "" {
		res.ExitCode = ExitSpawnFailed
		res.Error = "empty command"
		return finish()
	}

	sh, flag := e.shell()
	cmd := exec.Command(sh, flag, c.Command)
	cmd.Dir = e.resolveWorkdir(c)
	cmd.Env = e.env(c)
	// Nothing on this machine's stdin belongs to a command from the panel, and
	// a command that reads stdin must get EOF rather than block forever.
	cmd.Stdin = nil
	isolateProcessGroup(cmd)

	// One pipe for both streams: interleaving is what makes a build log
	// readable, and the panel has a single log channel anyway.
	pipeR, pipeW, err := os.Pipe()
	if err != nil {
		res.ExitCode = ExitSpawnFailed
		res.Error = fmt.Sprintf("pipe: %v", err)
		return finish()
	}
	cmd.Stdout = pipeW
	cmd.Stderr = pipeW

	if err := cmd.Start(); err != nil {
		pipeW.Close()
		pipeR.Close()
		res.ExitCode = ExitSpawnFailed
		res.Error = fmt.Sprintf("start: %v", err)
		return finish()
	}
	// The parent's copy of the write end must go now, or the reader below never
	// sees EOF even after every child has exited.
	pipeW.Close()

	collector := newOutputCollector(e, c, sink)
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		collector.consume(pipeR)
	}()

	timeout := c.Timeout(e.DefaultTimeout)
	timedOut := e.wait(ctx, cmd, timeout)

	// Wait for the reader to drain: once the group is dead the pipe closes and
	// this returns promptly. Doing it before reading res.Output is what makes
	// the output complete rather than racy.
	<-readDone
	pipeR.Close()
	collector.flush()

	res.Output, res.Truncated = collector.text()
	res.Seq = collector.batches

	switch {
	case timedOut:
		res.TimedOut = true
		res.ExitCode = ExitTimedOut
		res.Error = fmt.Sprintf("command exceeded its timeout of %s and was killed", timeout)
	default:
		res.ExitCode = exitCodeOf(cmd)
	}
	return finish()
}

// wait blocks until the command exits, the timeout fires, or ctx is cancelled
// (the runner is shutting down). It returns true when the command had to be
// killed. In every killing path it waits for the process to actually be reaped,
// so Execute never returns while a child is still alive.
func (e *Executor) wait(ctx context.Context, cmd *exec.Cmd, timeout time.Duration) bool {
	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(done)
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case <-done:
		return false
	case <-timer.C:
	case <-ctx.Done():
		// Shutdown: same teardown, but it is not the command's fault, so it is
		// not reported as a timeout.
		e.terminate(cmd, done)
		return false
	}

	e.terminate(cmd, done)
	return true
}

// terminate walks the SIGTERM -> grace -> SIGKILL ladder against the process
// GROUP, then blocks until Wait returns.
func (e *Executor) terminate(cmd *exec.Cmd, done <-chan struct{}) {
	if cmd.Process == nil {
		<-done
		return
	}
	pid := cmd.Process.Pid

	grace := e.KillGrace
	if grace <= 0 {
		grace = 5 * time.Second
	}

	_ = terminateGroup(pid)
	select {
	case <-done:
		return
	case <-time.After(grace):
	}

	_ = killGroup(pid)
	// SIGKILL cannot be caught, so this is bounded; the wait is unconditional
	// on purpose, to guarantee the child is reaped before Execute returns.
	<-done
}

func exitCodeOf(cmd *exec.Cmd) int {
	if cmd.ProcessState == nil {
		return ExitSpawnFailed
	}
	return cmd.ProcessState.ExitCode()
}

// outputCollector turns the merged pipe into (a) batches for the live log and
// (b) the capped full copy that rides in the result.
type outputCollector struct {
	sink       LogSink
	streaming  bool
	flushEvery time.Duration
	flushLines int
	maxBytes   int

	mu        sync.Mutex
	buf       strings.Builder
	truncated bool
	pending   []string
	lastFlush time.Time
	batches   int
}

func newOutputCollector(e *Executor, c Command, sink LogSink) *outputCollector {
	every := e.FlushInterval
	if every <= 0 {
		every = 500 * time.Millisecond
	}
	lines := e.FlushLines
	if lines <= 0 {
		lines = 50
	}
	return &outputCollector{
		sink:       sink,
		streaming:  c.Streaming() && sink != nil,
		flushEvery: every,
		flushLines: lines,
		maxBytes:   e.maxOutput(),
		lastFlush:  time.Now(),
	}
}

// consume reads lines until EOF. bufio.Scanner is given a large buffer because
// a single `docker build` layer line can be long, and a scanner that errors on
// a long line would silently truncate the rest of a build log.
func (o *outputCollector) consume(r io.Reader) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		o.add(sc.Text())
	}
	// A line longer than the scanner's cap, or a read error: recorded in-band
	// so a mangled log is visible rather than silent.
	if err := sc.Err(); err != nil && !errors.Is(err, os.ErrClosed) {
		o.add(fmt.Sprintf("[runner] output read error: %v", err))
	}
}

func (o *outputCollector) add(line string) {
	o.mu.Lock()
	if o.buf.Len()+len(line)+1 <= o.maxBytes {
		o.buf.WriteString(line)
		o.buf.WriteByte('\n')
	} else if !o.truncated {
		o.truncated = true
		o.buf.WriteString("[runner] output truncated: exceeded the retained-output cap\n")
	}
	if o.streaming {
		o.pending = append(o.pending, line)
	}
	due := o.streaming && (len(o.pending) >= o.flushLines || time.Since(o.lastFlush) >= o.flushEvery)
	o.mu.Unlock()

	if due {
		o.flush()
	}
}

// flush ships whatever is pending. A sink error is swallowed by design: see
// LogSink. The batch is NOT retained for retry — the authoritative copy of the
// output goes out with the result, so a dropped batch costs liveness, not data.
func (o *outputCollector) flush() {
	o.mu.Lock()
	if !o.streaming || len(o.pending) == 0 {
		o.mu.Unlock()
		return
	}
	batch := o.pending
	o.pending = nil
	o.lastFlush = time.Now()
	o.batches++
	o.mu.Unlock()

	_ = o.sink(batch)
}

func (o *outputCollector) text() (string, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.buf.String(), o.truncated
}
