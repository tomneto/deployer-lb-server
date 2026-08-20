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
	// DiskIO/Connections close the parity gap with the central's own local
	// collectors (selfApi infra.host_disk_io / connections_summary), so a
	// remote host renders the same Overview/Rede/Armazenamento cards as the
	// local one. Additive: an intake that predates them ignores the keys, and
	// an OLD agent simply doesn't send them — the backend must treat both
	// sections as optional.
	DiskIO      DiskIOInfo      `json:"disk_io"`
	Connections ConnectionsInfo `json:"connections"`
}

// DiskIOInfo carries per-device block I/O counters. Values are CUMULATIVE
// since boot — the same convention as ServerInfo.Network — and the backend
// derives read/s and write/s between consecutive reports
// (infra_agents.compute_disk_io_rates). Reporting rates here instead would
// mean two different derivations for the same number (WS risk 3).
type DiskIOInfo struct {
	OK      bool         `json:"ok"`
	Error   string       `json:"error,omitempty"`
	Devices []DiskDevice `json:"devices,omitempty"`
}

// DiskDevice is one whole physical disk. Partitions and device-mapper
// pseudo-devices are filtered out (see filterDiskDevices) so the same I/O is
// never counted twice under two names.
type DiskDevice struct {
	Device     string `json:"device"`
	ReadBytes  uint64 `json:"read_bytes"`
	WriteBytes uint64 `json:"write_bytes"`
	ReadCount  uint64 `json:"read_count"`
	WriteCount uint64 `json:"write_count"`
	IoTimeMs   uint64 `json:"io_time_ms"`
}

// ConnectionsInfo is the socket census: AGGREGATE COUNTS ONLY. A busy host has
// tens of thousands of sockets and the full listing would dwarf the rest of
// the report — TopPorts is the bounded drill-down that answers "who is being
// hit" without shipping every tuple.
//
// Inbound/outbound follow the central's own classification
// (infra._classify_connections): an ESTABLISHED socket whose LOCAL port is one
// we also listen on is inbound (someone dialed us); anything else established
// is outbound (we dialed out).
type ConnectionsInfo struct {
	OK          bool        `json:"ok"`
	Error       string      `json:"error,omitempty"`
	Established uint32      `json:"established"`
	Inbound     uint32      `json:"inbound"`
	Outbound    uint32      `json:"outbound"`
	Listening   uint32      `json:"listening"`
	TimeWait    uint32      `json:"time_wait"`
	TopPorts    []PortCount `json:"top_ports,omitempty"`
	// Conns is a bounded (maxConnEntries) sample of established sockets, the
	// per-connection counterpart of the aggregate counts above — the backend
	// forwards it verbatim as `snapshot.connections` for the frontend's
	// "Conexões (entrada/saída)" list.
	Conns []ConnEntry `json:"connections,omitempty"`
}

// ConnEntry is one established socket: which side dialed (Direction, same
// classification as Inbound/Outbound above) and the two endpoints.
type ConnEntry struct {
	Direction string `json:"direction"` // "inbound" | "outbound"
	Remote    string `json:"remote"`
	Local     string `json:"local"`
}

// PortCount is one entry of ConnectionsInfo.TopPorts: a listening local port
// and how many established sockets currently land on it.
type PortCount struct {
	Port        uint32 `json:"port"`
	Connections uint32 `json:"connections"`
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
	TotalBytes      uint64  `json:"total_bytes"`
	UsedBytes       uint64  `json:"used_bytes"`
	AvailableBytes  uint64  `json:"available_bytes"`
	UsedPercent     float64 `json:"used_percent"`
	SwapTotalBytes  uint64  `json:"swap_total_bytes"`
	SwapUsedBytes   uint64  `json:"swap_used_bytes"`
	SwapUsedPercent float64 `json:"swap_used_percent"`
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
	// Images/DiskUsage are the image inventory added by improves.md contract
	// C6, collected by CollectImages and folded in by DockerInfo.WithImages.
	// Both are `omitempty` on purpose: the pre-C6 intake keeps accepting the
	// payload unchanged, and a host whose `docker images`/`docker system df`
	// call failed simply omits the keys instead of sending empty sections.
	Images    []Image    `json:"images,omitempty"`
	DiskUsage *DiskUsage `json:"disk_usage,omitempty"`
}

// Image is one entry of the host's local image cache (C6 `docker.images[]`).
// RepoTags mirrors `docker inspect`'s field of the same name — empty for a
// dangling image. Size is in BYTES, parsed from docker's human-readable column
// ("1.093GB"), matching the *_bytes convention of ServerInfo/DiskInfo. Created
// is docker's CreatedAt string, reported verbatim (it is not RFC3339).
type Image struct {
	ID       string   `json:"id"`
	RepoTags []string `json:"repo_tags"`
	Size     uint64   `json:"size"`
	Created  string   `json:"created"`
	// InUse is computed by the agent by cross-referencing the container
	// inventory (see markImagesInUse); it is what makes a prune decision
	// possible on the backend side.
	InUse bool `json:"in_use"`
}

// DiskUsage is the `docker system df` summary (C6 `docker.disk_usage`). All
// values are BYTES; Reclaimable is the sum of the per-type reclaimable columns
// (docker prints no grand total of its own).
type DiskUsage struct {
	Images      uint64 `json:"images"`
	Containers  uint64 `json:"containers"`
	Volumes     uint64 `json:"volumes"`
	BuildCache  uint64 `json:"build_cache"`
	Reclaimable uint64 `json:"reclaimable"`
}

type Container struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Image string `json:"image"`
	// ImageID is the image's config digest ("sha256:…"), from the top-level
	// `Image` field of `docker inspect`. Distinct from Image above, which is
	// Config.Image — the *tag the container was started with*. C6 joins the
	// image inventory on this field, not on the tag.
	ImageID string   `json:"image_id,omitempty"`
	State   string   `json:"state"`
	Health  string   `json:"health,omitempty"`
	Ports   []string `json:"ports,omitempty"`
	// Pid/StartedAt (C3): host PID of the container's init process and the
	// RFC3339 start timestamp from `docker inspect` — they let the backend
	// join containers against the ports/processes sections.
	Pid       int32  `json:"pid,omitempty"`
	StartedAt string `json:"started_at,omitempty"`
	// Per-container resource usage, matching the field names the central's own
	// local collector already publishes (selfApi infra.py `docker.containers[]`)
	// so the frontend's ContainersSection/ServerHero read one dialect. Filled by
	// DockerInfo.WithStats from `docker stats --no-stream`; all `omitempty`
	// because that call is optional (AGENT_DOCKER_STATS=0) and may time out.
	//
	// CPUPercent/MemPercent/MemUsage/MemLimit are INSTANTANEOUS readings, while
	// Net*/Disk* are CUMULATIVE totals for the container's lifetime — the
	// backend derives per-container rates from consecutive reports
	// (infra_agents.compute_container_io_rates).
	CPUPercent     float64 `json:"cpu_percent,omitempty"`
	MemUsage       uint64  `json:"mem_usage,omitempty"`
	MemLimit       uint64  `json:"mem_limit,omitempty"`
	MemPercent     float64 `json:"mem_percent,omitempty"`
	NetRxBytes     uint64  `json:"net_rx_bytes,omitempty"`
	NetTxBytes     uint64  `json:"net_tx_bytes,omitempty"`
	DiskReadBytes  uint64  `json:"disk_read_bytes,omitempty"`
	DiskWriteBytes uint64  `json:"disk_write_bytes,omitempty"`
	// ExposedPorts are the container-side ports declared by the image
	// (`Config.ExposedPorts`), regardless of whether they were published to the
	// host — Ports above only describes the published bindings.
	ExposedPorts []int `json:"exposed_ports,omitempty"`
	// Where this container sits on the network. Without these three the
	// backend can see a container and still not know whether anything else can
	// reach it: a container on a bridge network and one sharing the host
	// namespace are unreachable from each other by name, and that mismatch is
	// invisible in every other field here.
	//
	// NetworkMode is `HostConfig.NetworkMode` verbatim — "host", "bridge",
	// "default", a network name, or "container:<id>" when it joined another
	// container's namespace. Networks are the keys of
	// `NetworkSettings.Networks`, sorted for a stable report. IPAddress is the
	// address on the first of those networks, and is EMPTY for a host-network
	// container — it has no interface of its own, which is precisely the case
	// the backend has to detect.
	//
	// All three are `omitempty`: an agent older than this field simply omits
	// them, and the intake accepts the payload unchanged.
	NetworkMode string   `json:"network_mode,omitempty"`
	Networks    []string `json:"networks,omitempty"`
	IPAddress   string   `json:"ip_address,omitempty"`
}

// ContainerStats is one `docker stats` row, keyed by container ID in the map
// CollectStats returns. Separate from Container so the stats pass can fail
// wholesale without touching the inventory.
type ContainerStats struct {
	CPUPercent     float64
	MemUsage       uint64
	MemLimit       uint64
	MemPercent     float64
	NetRxBytes     uint64
	NetTxBytes     uint64
	DiskReadBytes  uint64
	DiskWriteBytes uint64
}

// StatsInfo is the result of the whole `docker stats` pass: the per-container
// rows plus one ok/error pair, folded into the report by DockerInfo.WithStats.
type StatsInfo struct {
	OK    bool
	Error string
	Stats map[string]ContainerStats
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
	// MemPercent is RSS as a percentage of host total memory (gopsutil
	// Process.MemoryPercent), the per-process counterpart of ServerInfo's
	// host-wide Memory.UsedPercent.
	MemPercent float64 `json:"mem_percent"`
	// ReadRateBps/WriteRateBps are bytes/sec derived between consecutive
	// report ticks from the process's cumulative IOCounters, the same
	// since-last-report convention CPUPercent already uses.
	ReadRateBps  float64 `json:"read_rate_bps"`
	WriteRateBps float64 `json:"write_rate_bps"`
	// Connections is the count of established sockets owned by this PID
	// (from the same socket scan CollectSockets already does for the
	// `connections`/`ports` sections — no extra syscalls here).
	Connections int    `json:"connections"`
	CreateTime  int64  `json:"create_time"` // unix seconds
	Status      string `json:"status"`      // one-letter ps state (R/S/D/Z/T/I/...)
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
