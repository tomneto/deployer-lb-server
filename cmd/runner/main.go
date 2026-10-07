// Command deployer-runner is the "runner" mode of deployer-lb-server: it runs
// on a machine that is NOT in the private network — a development Mac — and
// pulls work from the panel over HTTPS.
//
// It is the inverse of cmd/agent in the one way that matters: it never accepts
// an inbound connection. No port is opened, no credential of this machine is
// published, and the panel never needs a route to it. What it needs is the
// panel's URL and the same per-target HMAC secret the agent uses.
//
// Unlike cmd/agent (`-tags agent`) and cmd/apply-server (`-tags lb`), this one
// carries no build tag. Those tags exist to keep two HEAVY dependency graphs
// apart — gopsutil on one side, the nginx renderer on the other. internal/runner
// is stdlib-only, so there is nothing to isolate, and leaving it untagged is
// what makes the repo's default `go build ./...` / `go vet ./cmd/...` actually
// cover this binary instead of silently skipping it.
//
// SECURITY, said out loud: this process executes arbitrary shell commands sent
// by the panel. Trust runs from this machine TO the panel, which is the reverse
// of every other binary here. Plan §"Riscos" accepts that for the build/test
// use case; the two mitigations that live in this file are the mandatory
// working directory and the refusal to run as root without an explicit opt-in.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/tomneto/deployer-lb-server/internal/runner"
	"github.com/tomneto/deployer-lb-server/internal/version"
)

func main() {
	var (
		panelURL   = flag.String("panel-url", envOr("RUNNER_PANEL_URL", ""), "panel base URL, e.g. https://vault.local:6069")
		ref        = flag.String("ref", envOr("RUNNER_REF", ""), "target ref registered in the panel (sent as X-Agent-Id)")
		token      = flag.String("token", envOr("RUNNER_TOKEN", ""), "per-target HMAC secret (signs X-Agent-Token)")
		workdir    = flag.String("workdir", envOr("RUNNER_WORKDIR", ""), "directory commands run in (required; must exist)")
		shell      = flag.String("shell", envOr("RUNNER_SHELL", "/bin/sh"), "shell used to run each command")
		shellFlag  = flag.String("shell-flag", envOr("RUNNER_SHELL_FLAG", "-c"), "flag the shell takes the command string with")
		allowRoot  = flag.Bool("allow-root", envBoolOr("RUNNER_ALLOW_ROOT", false), "permit running as root (refused by default: the panel's commands would run as root too)")
		defTimeout = flag.Duration("default-timeout", envDurationOr("RUNNER_DEFAULT_TIMEOUT", runner.DefaultCommandTimeout), "timeout applied to a command that arrives without one")
		killGrace  = flag.Duration("kill-grace", envDurationOr("RUNNER_KILL_GRACE", 5*time.Second), "grace between SIGTERM and SIGKILL when a command times out")
		maxOutput  = flag.Int("max-output-bytes", envIntOr("RUNNER_MAX_OUTPUT_BYTES", runner.DefaultMaxOutputBytes), "cap on the output retained in memory per command")

		claimWait = flag.Duration("claim-wait", envDurationOr("RUNNER_CLAIM_WAIT", 25*time.Second), "how long the runner asks the panel to hold a claim open (long-poll window)")
		// The margin is the whole reason this is a separate knob: the claim's
		// HTTP deadline is claim-wait + margin. If the client deadline were the
		// shorter of the two, the runner would hang up on exactly the requests
		// that were about to return work.
		claimMargin  = flag.Duration("claim-margin", envDurationOr("RUNNER_CLAIM_MARGIN", 20*time.Second), "slack added on top of --claim-wait for the claim's own HTTP deadline")
		shortTimeout = flag.Duration("request-timeout", envDurationOr("RUNNER_REQUEST_TIMEOUT", 15*time.Second), "HTTP deadline for the log and result calls")
		idleDelay    = flag.Duration("idle-delay", envDurationOr("RUNNER_IDLE_DELAY", 2*time.Second), "pause after an empty claim (a server that long-polls properly makes this nearly moot)")
		backoffMax   = flag.Duration("backoff-max", envDurationOr("RUNNER_BACKOFF_MAX", 60*time.Second), "cap on the retry pause while the panel is unreachable")
		flushEvery   = flag.Duration("log-flush-interval", envDurationOr("RUNNER_LOG_FLUSH_INTERVAL", 500*time.Millisecond), "how often streamed output is shipped")
		flushLines   = flag.Int("log-flush-lines", envIntOr("RUNNER_LOG_FLUSH_LINES", 50), "how many lines force an early flush of streamed output")

		showVerS = flag.Bool("v", false, "print version and exit")
		showVerL = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	// Same ordering as cmd/agent: -v works on a machine with nothing configured.
	if *showVerS || *showVerL {
		fmt.Printf("deployer-runner %s\n", version.Version)
		return
	}

	if *panelURL == "" || *ref == "" || *token == "" {
		log.Fatal("deployer-runner: --panel-url, --ref and --token (or RUNNER_PANEL_URL/RUNNER_REF/RUNNER_TOKEN) are required")
	}
	if !strings.HasPrefix(*panelURL, "https://") && !strings.HasPrefix(*panelURL, "http://") {
		log.Fatalf("deployer-runner: --panel-url must start with https:// (or http:// on a trusted LAN), got %q", *panelURL)
	}

	// Refusing root is not theatre. This process runs whatever the panel sends;
	// as root that is unrestricted control of the machine, and the plan's Phase 1
	// (tests only) is explicitly the phase where the runner can live in a user
	// without Docker. Opting out has to be a typed decision.
	if os.Geteuid() == 0 && !*allowRoot {
		log.Fatal("deployer-runner: refusing to run as root. This process executes commands sent by the panel; run it as an unprivileged user, or pass --allow-root if you have decided otherwise.")
	}

	dir, err := resolveWorkdir(*workdir)
	if err != nil {
		log.Fatalf("deployer-runner: %v", err)
	}

	if *claimMargin <= 0 {
		log.Fatal("deployer-runner: --claim-margin must be positive, or the claim's HTTP deadline races the panel's long-poll window")
	}

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	client := runner.NewClient(runner.ClientConfig{
		BaseURL:      strings.TrimSuffix(*panelURL, "/"),
		Ref:          *ref,
		Secret:       *token,
		Wait:         *claimWait,
		ClaimMargin:  *claimMargin,
		ShortTimeout: *shortTimeout,
		Hostname:     hostname,
		Version:      version.Version,
		OS:           runtime.GOOS,
		Arch:         runtime.GOARCH,
	})

	loop := &runner.Loop{
		Client: client,
		Exec: &runner.Executor{
			Shell:          *shell,
			ShellFlag:      *shellFlag,
			Workdir:        dir,
			DefaultTimeout: *defTimeout,
			KillGrace:      *killGrace,
			FlushInterval:  *flushEvery,
			FlushLines:     *flushLines,
			MaxOutputBytes: *maxOutput,
		},
		Logger:    log.Default(),
		IdleDelay: *idleDelay,
		Backoff:   runner.Backoff{Initial: time.Second, Max: *backoffMax, Factor: 2},
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Printf("deployer-runner %s starting: panel=%s ref=%s workdir=%s uid=%d claim-wait=%s",
		version.Version, *panelURL, *ref, dir, os.Geteuid(), *claimWait)

	loop.Run(ctx)

	log.Println("deployer-runner stopped")
}

// resolveWorkdir makes --workdir mandatory and real. Defaulting it to the
// process's cwd would mean the directory the panel's commands run in depends on
// where someone happened to launch the binary from — which, for a process that
// runs `rm -rf build/`, is not a detail to leave to chance.
func resolveWorkdir(dir string) (string, error) {
	if strings.TrimSpace(dir) == "" {
		return "", fmt.Errorf("--workdir (or RUNNER_WORKDIR) is required: commands must run somewhere chosen on purpose")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("--workdir %q: %w", dir, err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("--workdir %q: %w", abs, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("--workdir %q is not a directory", abs)
	}
	return abs, nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envBoolOr(key string, fallback bool) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}

func envIntOr(key string, fallback int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	n := 0
	for _, r := range v {
		if r < '0' || r > '9' {
			return fallback
		}
		n = n*10 + int(r-'0')
	}
	return n
}

// envDurationOr mirrors cmd/agent's: accepts "30s" and bare seconds alike, and
// falls back rather than failing startup on a typo in an optional knob.
func envDurationOr(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
		if secs, err := time.ParseDuration(v + "s"); err == nil {
			return secs
		}
	}
	return fallback
}
