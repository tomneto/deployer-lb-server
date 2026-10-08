// Package runner implements the pull-based command runner: a binary that runs
// on a machine OUTSIDE the private network (a development Mac, say), opens no
// port, accepts no inbound connection, and instead ASKS the panel for work
// over HTTPS.
//
// It is the inverse of internal/agent. The agent is reached from the panel;
// the runner reaches the panel. Everything else is shared: the same HMAC
// scheme (internal/hmacauth), the same three headers, the same
// never-die-on-a-network-error posture.
//
// The protocol is three endpoints on the panel:
//
//	POST /deploy/runner/claim                   long-poll: 200 + a command, or 204
//	POST /deploy/runner/commands/{id}/log       incremental output while it runs
//	POST /deploy/runner/commands/{id}/result    exit code + final output
//
// All three authenticated with X-Agent-Id / X-Agent-Ts / X-Agent-Token, exactly
// as the agent's intake POST is.
package runner

import (
	"encoding/base64"
	"strings"
	"time"
)

// Default timings. They are flags on the binary; these are the fallbacks.
const (
	// DefaultCommandTimeout applies when the panel sends a command with no
	// timeout_seconds (or a non-positive one). A command that can run forever
	// is a lease that can never expire — the panel-side lease (plan §1.3) is
	// the real guard, but the runner must not rely on it to stop a process on
	// this machine.
	DefaultCommandTimeout = 30 * time.Minute

	// DefaultMaxOutputBytes caps what one command may accumulate in memory
	// before the tail is dropped. A runaway `yes` must not OOM the laptop.
	DefaultMaxOutputBytes = 8 << 20 // 8 MiB

	// DefaultKeepaliveInterval is how often a quiet command tells the panel it
	// is still running (see Executor.KeepaliveInterval). It has to be a good
	// deal shorter than the panel's lease window so a single dropped batch is
	// not also an expired lease: at 30s against a 90s lease, three in a row
	// have to be lost before a healthy command is given up on.
	DefaultKeepaliveInterval = 30 * time.Second
)

// ExitTimedOut is the exit code reported when the runner killed the process
// because it blew its timeout. 124 is what timeout(1) uses, so it reads
// correctly in a log without any extra explanation; the result also carries
// TimedOut=true, which is what callers should branch on.
const ExitTimedOut = 124

// ExitSpawnFailed is reported when the command never started at all (bad
// workdir, shell missing). Distinct from any code a real process could return.
const ExitSpawnFailed = -1

// ClaimRequest is the body the runner POSTs to /deploy/runner/claim.
//
// It doubles as the heartbeat: plan §1.4 replaces "prove the builder is alive
// with an SSH session" by "the last claim is recent", so the panel's election
// skips a runner whose Mac is closed before it enqueues anything.
type ClaimRequest struct {
	Ref      string `json:"ref"`
	Hostname string `json:"hostname"`
	Version  string `json:"version"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	// WaitSeconds is how long the runner is willing to be held on this
	// request. The server may hold for less; it must not hold for more, or the
	// client-side deadline fires exactly when work was about to arrive.
	WaitSeconds int `json:"wait_seconds"`
}

// Command is what comes back on a 200 from claim.
//
// Decoding is deliberately permissive: the Python side is being written in
// parallel, and a field spelled slightly differently must degrade into a
// default rather than into a runner that refuses every command. Unknown fields
// are ignored by encoding/json already.
type Command struct {
	ID      string `json:"id"`
	Command string `json:"command"`

	// TimeoutSeconds is the hard deadline for this command. Non-positive means
	// "use the runner's default" — never "no deadline".
	TimeoutSeconds int `json:"timeout_seconds"`

	// Mode is "stream" when output must be shipped line by line while the
	// command runs, anything else ("buffered", "", "collect") when the whole
	// output is returned once at the end. Stream is accepted as a boolean
	// alias because that is the other obvious spelling of the same bit.
	Mode   string `json:"mode"`
	Stream *bool  `json:"stream"`

	// Workdir, when set, overrides the runner's --workdir for this command. A
	// relative path is resolved against --workdir.
	Workdir string `json:"workdir"`

	// Env are extra environment variables for this command, on top of the
	// runner's own environment.
	Env map[string]string `json:"env"`

	// Stdin is base64 of the bytes to feed the command's standard input.
	//
	// It exists so a secret never has to ride the command string. Before this
	// field the panel embedded the payload as a here-document inside Command,
	// and that string becomes the argv of `/bin/sh -c` on this machine —
	// readable by `ps -ww` to every user on the box. `docker login
	// --password-stdin` was the case that made it matter: the password stayed
	// out of docker's own argv and landed in the shell's instead.
	//
	// Base64 and not raw bytes because the envelope is JSON, and a credential
	// is not guaranteed to be valid UTF-8.
	Stdin string `json:"stdin"`
}

// StdinBytes decodes Stdin, or returns nil when there is none.
//
// A malformed payload is an error and not an empty stdin: feeding the command
// nothing would make `docker login` prompt and then hang until the timeout,
// which reads like the panel is broken rather than like the envelope was.
func (c Command) StdinBytes() ([]byte, error) {
	if c.Stdin == "" {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(c.Stdin)
}

// Streaming reports whether the output of this command must be shipped
// incrementally through the log endpoint.
func (c Command) Streaming() bool {
	if c.Stream != nil {
		return *c.Stream
	}
	switch strings.ToLower(strings.TrimSpace(c.Mode)) {
	case "stream", "streaming", "live":
		return true
	default:
		return false
	}
}

// Timeout is the effective deadline for this command, never zero.
func (c Command) Timeout(fallback time.Duration) time.Duration {
	if c.TimeoutSeconds > 0 {
		return time.Duration(c.TimeoutSeconds) * time.Second
	}
	if fallback > 0 {
		return fallback
	}
	return DefaultCommandTimeout
}

// LogBatch is the body of POST /deploy/runner/commands/{id}/log.
//
// Seq is monotonic per command and starts at 0, so the panel can detect a gap
// (a batch lost to a 500 the runner gave up retrying) instead of silently
// rendering a log with a hole in it.
type LogBatch struct {
	CommandID string   `json:"command_id"`
	Seq       int      `json:"seq"`
	Lines     []string `json:"lines"`
}

// Result is the body of POST /deploy/runner/commands/{id}/result: the single
// message that closes a command out. Every path through Execute produces one,
// including the timeout and the failed spawn — a command that ends without a
// result is a run that hangs until the panel's lease expires, which is exactly
// what plan §1.3 wants to make rare rather than normal.
type Result struct {
	CommandID string `json:"command_id"`
	ExitCode  int    `json:"exit_code"`
	// Output is the full output in buffered mode. In stream mode it is still
	// sent: the log batches feed the live view, this is the authoritative copy
	// the panel stores, and it is what survives a dropped batch.
	Output string `json:"output"`
	// Truncated says Output hit the cap and lost its tail.
	Truncated bool `json:"truncated"`
	TimedOut  bool `json:"timed_out"`
	// Error is a human-readable reason when the runner itself failed (spawn
	// error, timeout), empty when the command simply exited non-zero.
	Error      string `json:"error,omitempty"`
	DurationMS int64  `json:"duration_ms"`
	// Seq is the number of log batches sent, so the panel can tell a complete
	// stream from a truncated one.
	Seq int `json:"seq"`
}
