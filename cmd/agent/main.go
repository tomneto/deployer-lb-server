//go:build agent

// Command deployer-lb-agent is the "agent" mode of deployer-lb-server: it
// runs on backend servers, collects CPU/mem/disk/docker/wireguard telemetry
// and POSTs periodic reports to the central intake. See
// selfApi/pipe-improves.md §2.3, §2.7.2 and plan step B2.
//
// Build tag `agent` keeps this binary's dependency graph separate from the
// `lb` mode (cmd/apply-server): building `deployer-lb-agent` never pulls in
// the nginx-rendering/listener code, and vice versa.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/tomneto/deployer-lb-server/internal/agent"
	"github.com/tomneto/deployer-lb-server/internal/version"
)

func main() {
	var (
		intakeURL   = flag.String("intake-url", envOr("INTAKE_URL", ""), "central intake URL, e.g. https://selfapi.example.com/infra/agent/report")
		agentID     = flag.String("agent-id", envOr("AGENT_ID", ""), "target_id registered in the central (X-Agent-Id)")
		agentToken  = flag.String("agent-token", envOr("AGENT_TOKEN", ""), "per-target HMAC secret (X-Agent-Token)")
		interval    = flag.Duration("interval", envDurationOr("AGENT_INTERVAL", 8*time.Second), "report interval")
		bufferDir   = flag.String("buffer-dir", envOr("AGENT_BUFFER_DIR", "/var/lib/deployer-lb-agent/buffer"), "disk buffer directory for failed reports")
		wgIface     = flag.String("wg-iface", envOr("AGENT_WG_IFACE", "wg0"), "WireGuard interface to inspect")
		mountsCSV   = flag.String("mounts", envOr("AGENT_MOUNTS", "/"), "comma-separated mount points to report disk usage for")
		gitSHA      = flag.String("git-sha", envOr("GIT_SHA", ""), "optional build identifier reported in api.git_sha")
		environment = flag.String("environment", envOr("ENVIRONMENT", "production"), "reported in api.environment")
		// Observability collectors (improves.md C3/WS-4): which systemd units
		// get the detailed `systemctl show` pass in the report.
		managedPrefix = flag.String("managed-prefix", envOr("AGENT_MANAGED_PREFIX", agent.DefaultManagedPrefix), "systemd unit-name prefix considered deployer-managed (detailed reporting)")
		unitsCSV      = flag.String("units", envOr("AGENT_UNITS", ""), "comma-separated extra systemd units to report in detail (\".service\" suffix optional)")
		showVerS      = flag.Bool("v", false, "print version and exit")
		showVerL      = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	// Version check must exit before the required-flags validation so
	// `deployer-lb-agent -v` works on a host with no env configured.
	if *showVerS || *showVerL {
		fmt.Printf("deployer-lb-agent %s\n", version.Version)
		return
	}

	if *intakeURL == "" || *agentID == "" || *agentToken == "" {
		log.Fatal("deployer-lb-agent: --intake-url, --agent-id and --agent-token (or INTAKE_URL/AGENT_ID/AGENT_TOKEN env) are required")
	}

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	sender := &agent.Sender{
		Cfg: agent.TransportConfig{
			IntakeURL: *intakeURL,
			AgentID:   *agentID,
			Secret:    *agentToken,
		},
		Buffer:  agent.NewDiskBuffer(*bufferDir, 500),
		Backoff: agent.DefaultBackoff(),
		Logger:  log.Default(),
	}

	mounts := splitCSV(*mountsCSV)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Printf("deployer-lb-agent %s starting: intake=%s agent_id=%s interval=%s", version.Version, *intakeURL, *agentID, *interval)

	runLoop(ctx, sender, loopConfig{
		hostname:      hostname,
		agentID:       *agentID,
		gitSHA:        *gitSHA,
		environment:   *environment,
		wgIface:       *wgIface,
		mounts:        mounts,
		interval:      *interval,
		managedPrefix: *managedPrefix,
		extraUnits:    splitCSV(*unitsCSV),
		// One process-handle cache for the whole agent lifetime: gopsutil
		// needs two samples on the same handle for a real cpu_percent, so the
		// cache must survive across ticks (improves.md WS-4).
		procCache: agent.NewProcCache(),
	})

	log.Println("deployer-lb-agent stopped")
}

type loopConfig struct {
	hostname      string
	agentID       string
	gitSHA        string
	environment   string
	wgIface       string
	mounts        []string
	interval      time.Duration
	managedPrefix string
	extraUnits    []string
	procCache     *agent.ProcCache
}

// runLoop is the core periodic loop, deliberately free of package-level
// globals so it's the same code path a test could drive with a short
// interval and a cancelable context (not unit-tested here directly since it
// only wires already-tested pieces together and needs wall-clock ticking;
// each collector/transport function it calls has its own focused tests).
func runLoop(ctx context.Context, sender *agent.Sender, cfg loopConfig) {
	ticker := time.NewTicker(cfg.interval)
	defer ticker.Stop()

	// Collect+send once immediately on start, then on every tick.
	tick(ctx, sender, cfg)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			tick(ctx, sender, cfg)
		}
	}
}

// tick recovers from any panic in collection/send so a single bad syscall or
// unexpected nil never brings the whole agent process down (D5/B2:
// "nunca deve travar/derrubar o processo").
func tick(ctx context.Context, sender *agent.Sender, cfg loopConfig) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("deployer-lb-agent: recovered from panic in report tick: %v", r)
		}
	}()

	report := buildReport(cfg)
	body, err := json.Marshal(report)
	if err != nil {
		log.Printf("deployer-lb-agent: marshal report failed: %v", err)
		return
	}

	sendCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	sender.SendOrBuffer(sendCtx, body)
}

func buildReport(cfg loopConfig) agent.Report {
	now := time.Now().UTC()

	// Ports, docker and systemd run first: their PIDs (port owners, container
	// init PIDs, managed-unit MainPIDs) pin entries in the processes
	// cardinality filter (improves.md C3/WS-4).
	ports := agent.CollectPorts()
	docker := agent.CollectContainers(agent.ExecRunner)
	systemd := agent.CollectSystemd(agent.ExecRunner, cfg.managedPrefix, cfg.extraUnits)

	pinned := append(ports.PortPIDs(), systemd.ManagedPIDs()...)
	pinned = append(pinned, docker.ContainerPIDs()...)

	return agent.Report{
		Timestamp:    now.Format(time.RFC3339),
		TargetID:     cfg.agentID,
		Hostname:     cfg.hostname,
		AgentVersion: version.Version,
		API: agent.APIInfo{
			GitSHA:      cfg.gitSHA,
			Environment: cfg.environment,
		},
		Server:    agent.CollectServer(cfg.mounts),
		Docker:    docker,
		WG:        agent.CollectWireGuard(agent.ExecRunner, agent.ExecPing, cfg.wgIface, now),
		Vercel:    agent.ConfigFlag{Configured: false},
		N8N:       agent.ConfigFlag{Configured: false},
		Ports:     ports,
		Processes: cfg.procCache.CollectProcesses(pinned),
		Systemd:   systemd,
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envDurationOr(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
		// Accept bare integer seconds too, matching setup.sh's --interval 8.
		if secs, err := time.ParseDuration(v + "s"); err == nil {
			return secs
		}
	}
	return fallback
}

func splitCSV(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == ',' {
			if cur != "" {
				out = append(out, cur)
				cur = ""
			}
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}
