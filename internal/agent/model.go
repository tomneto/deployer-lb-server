//go:build agent

// Package agent implements the "agent" mode of deployer-lb-server: it collects
// host/container/WireGuard telemetry and POSTs periodic reports to the
// central intake. See selfApi/pipe-improves.md §2.3, §2.7.2 and plan step B2.
package agent

// Report is the JSON payload POSTed to {INTAKE_URL}/infra/agent/report.
//
// Shape reference: pipe-improves.md §2.7.2. `target_id`/`hostname` are added
// by the agent (the central's build_infra() has neither); `vercel`/`n8n` are
// central-only sections and are always reported as {"configured": false} here
// (not to be confused with the local build_infra() fallback semantics, which
// use `configured: true` for its own error fallbacks — that's a different
// code path documented in the plan as a deliberate asymmetry).
type Report struct {
	Timestamp string `json:"timestamp"`
	TargetID  string `json:"target_id"`
	Hostname  string `json:"hostname"`
	// AgentVersion is the binary's own build version (git describe stamp),
	// distinct from api.git_sha which identifies the deployed API build.
	AgentVersion string     `json:"agent_version,omitempty"`
	API          APIInfo    `json:"api"`
	Server       ServerInfo `json:"server"`
	Docker       DockerInfo `json:"docker"`
	WG           WGInfo     `json:"wg"`
	Vercel       ConfigFlag `json:"vercel"`
	N8N          ConfigFlag `json:"n8n"`
	// Ports/Processes/Systemd are the observability sections added by
	// improves.md contract C3. They are additive and optional: intake
	// consumers that predate C3 simply ignore the extra keys — nothing in
	// the pre-existing shape above changes.
	Ports     PortsInfo     `json:"ports"`
	Processes ProcessesInfo `json:"processes"`
	Systemd   SystemdInfo   `json:"systemd"`
}

// APIInfo carries build/environment identification. v1 of the agent has no
// real build pipeline of its own; GitSHA/Environment are best-effort (env
// vars set by setup.sh), never fatal if empty.
type APIInfo struct {
	GitSHA      string `json:"git_sha"`
	Environment string `json:"environment"`
}

// ConfigFlag mirrors sections the central reports but that don't apply to a
// bare backend server (vercel/n8n) — always {"configured": false} here.
type ConfigFlag struct {
	Configured bool `json:"configured"`
}

// ServerInfo is the CPU/mem/disk snapshot collected via gopsutil, extended
// per C3 with loadavg, uptime and per-interface network counters. Network
// counters are CUMULATIVE since boot — the backend derives rates between
// consecutive reports (improves.md C3).
type ServerInfo struct {
	OK            bool        `json:"ok"`
	Error         string      `json:"error,omitempty"`
	CPU           *CPUInfo    `json:"cpu,omitempty"`
	Memory        *MemoryInfo `json:"memory,omitempty"`
	Disks         []DiskInfo  `json:"disks,omitempty"`
	Load          *LoadInfo   `json:"load,omitempty"`
	UptimeSeconds uint64      `json:"uptime_seconds"`
	Network       []NetIOInfo `json:"network,omitempty"`
}

// LoadInfo is the 1/5/15-minute load average (C3 `server.load`).
type LoadInfo struct {
	Load1  float64 `json:"load1"`
	Load5  float64 `json:"load5"`
	Load15 float64 `json:"load15"`
}

// NetIOInfo carries cumulative per-interface counters (C3 `server.network`).
type NetIOInfo struct {
	Iface       string `json:"iface"`
	BytesSent   uint64 `json:"bytes_sent"`
	BytesRecv   uint64 `json:"bytes_recv"`
	PacketsSent uint64 `json:"packets_sent"`
	PacketsRecv uint64 `json:"packets_recv"`
	Errin       uint64 `json:"errin"`
	Errout      uint64 `json:"errout"`
}

type CPUInfo struct {
	PercentTotal float64   `json:"percent_total"`
	PerCPU       []float64 `json:"per_cpu,omitempty"`
	Cores        int       `json:"cores"`
}

type MemoryInfo struct {
	TotalBytes     uint64  `json:"total_bytes"`
	UsedBytes      uint64  `json:"used_bytes"`
	AvailableBytes uint64  `json:"available_bytes"`
	UsedPercent    float64 `json:"used_percent"`
}

type DiskInfo struct {
	MountPoint  string  `json:"mount_point"`
	TotalBytes  uint64  `json:"total_bytes"`
	UsedBytes   uint64  `json:"used_bytes"`
	UsedPercent float64 `json:"used_percent"`
}

// DockerInfo is the container inventory, collected via `docker ps`/`docker
// inspect` (never via the Docker socket/SDK — keeps the agent dependency-free
// besides gopsutil, per D5).
type DockerInfo struct {
	OK         bool        `json:"ok"`
	Error      string      `json:"error,omitempty"`
	Containers []Container `json:"containers"`
}

type Container struct {
	ID     string   `json:"id"`
	Name   string   `json:"name"`
	Image  string   `json:"image"`
	State  string   `json:"state"`
	Health string   `json:"health,omitempty"`
	Ports  []string `json:"ports,omitempty"`
	// Pid/StartedAt (C3): host PID of the container's init process and the
	// RFC3339 start timestamp from `docker inspect` — they let the backend
	// join containers against the ports/processes sections.
	Pid       int32  `json:"pid,omitempty"`
	StartedAt string `json:"started_at,omitempty"`
}

// WGInfo is the WireGuard peer health, per D21: it feeds the "wireguard"
// continuous check on the server side of the connectivity matrix (§2.10).
type WGInfo struct {
	OK    bool     `json:"ok"`
	Error string   `json:"error,omitempty"`
	Peers []WGPeer `json:"peers"`
}

type WGPeer struct {
	PubKey             string  `json:"pubkey"`
	Endpoint           string  `json:"endpoint,omitempty"`
	LatestHandshakeAge int64   `json:"latest_handshake_age"` // seconds; -1 = never
	PingMS             float64 `json:"ping_ms,omitempty"`
	PingOK             bool    `json:"ping_ok"`
}

// PortsInfo is the listening-sockets inventory (C3 `ports`): TCP sockets in
// LISTEN plus bound UDP sockets, each resolved to its owning PID/process/user.
type PortsInfo struct {
	OK        bool       `json:"ok"`
	Error     string     `json:"error,omitempty"`
	Listeners []Listener `json:"listeners"`
}

type Listener struct {
	Proto   string `json:"proto"` // "tcp" | "udp"
	Addr    string `json:"addr"`
	Port    uint32 `json:"port"`
	Pid     int32  `json:"pid"`
	Process string `json:"process,omitempty"`
	UID     int32  `json:"uid"`
	User    string `json:"user,omitempty"`
}

// ProcessesInfo is the filtered process inventory (C3 `processes`). The list
// is cardinality-capped (see CollectProcesses); Truncated flags that the cap
// dropped candidates.
type ProcessesInfo struct {
	OK        bool       `json:"ok"`
	Error     string     `json:"error,omitempty"`
	Truncated bool       `json:"truncated"`
	Procs     []ProcInfo `json:"procs"`
}

type ProcInfo struct {
	Pid        int32   `json:"pid"`
	Ppid       int32   `json:"ppid"`
	Name       string  `json:"name"`
	Cmdline    string  `json:"cmdline"` // truncated to 200 chars
	User       string  `json:"user,omitempty"`
	CPUPercent float64 `json:"cpu_percent"`
	RSSBytes   uint64  `json:"rss_bytes"`
	CreateTime int64   `json:"create_time"` // unix seconds
	Status     string  `json:"status"`      // one-letter ps state (R/S/D/Z/T/I/...)
}

// SystemdInfo is the systemd inventory (C3 `systemd`): a light listing of ALL
// service units plus detailed `systemctl show` fields for managed units only
// (prefix AGENT_MANAGED_PREFIX + explicit AGENT_UNITS list) to keep the
// report size bounded.
type SystemdInfo struct {
	OK      bool          `json:"ok"`
	Error   string        `json:"error,omitempty"`
	Units   []UnitInfo    `json:"units"`
	Managed []ManagedUnit `json:"managed"`
}

type UnitInfo struct {
	Name   string `json:"name"`
	Load   string `json:"load"`
	Active string `json:"active"`
	Sub    string `json:"sub"`
}

type ManagedUnit struct {
	Name          string `json:"name"`
	MainPID       int32  `json:"main_pid"`
	ActiveState   string `json:"active_state"`
	SubState      string `json:"sub_state"`
	UnitFileState string `json:"unit_file_state"`
	NRestarts     int    `json:"n_restarts"`
	ExecMainStart string `json:"exec_main_start"`
}
