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
	Timestamp string     `json:"timestamp"`
	TargetID  string     `json:"target_id"`
	Hostname  string     `json:"hostname"`
	API       APIInfo    `json:"api"`
	Server    ServerInfo `json:"server"`
	Docker    DockerInfo `json:"docker"`
	WG        WGInfo     `json:"wg"`
	Vercel    ConfigFlag `json:"vercel"`
	N8N       ConfigFlag `json:"n8n"`
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

// ServerInfo is the CPU/mem/disk snapshot collected via gopsutil.
type ServerInfo struct {
	OK     bool        `json:"ok"`
	Error  string      `json:"error,omitempty"`
	CPU    *CPUInfo    `json:"cpu,omitempty"`
	Memory *MemoryInfo `json:"memory,omitempty"`
	Disks  []DiskInfo  `json:"disks,omitempty"`
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
