//go:build agent

package agent

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
)

// dockerStatsRow mirrors the fields of `docker stats --format '{{json .}}'`
// this agent reads. Every value is a HUMAN-FORMATTED STRING ("1.093GiB",
// "12.5MB / 4kB", "0.15%") — docker has no machine-readable stats format on the
// CLI, so parsing the display strings is the only option short of talking to
// the daemon socket (which D5 rules out).
type dockerStatsRow struct {
	ID       string `json:"ID"`
	Name     string `json:"Name"`
	CPUPerc  string `json:"CPUPerc"`
	MemUsage string `json:"MemUsage"` // "1.093GiB / 7.775GiB"
	MemPerc  string `json:"MemPerc"`
	NetIO    string `json:"NetIO"`   // "1.2MB / 800kB"  (rx / tx)
	BlockIO  string `json:"BlockIO"` // "12.5MB / 4kB"   (read / write)
}

// parsePercent reads docker's "0.15%" into 0.15. Unparseable input yields 0
// rather than an error, on the same reasoning as parseHumanSize: a number
// docker formats in a way this agent doesn't know must not void the row.
func parsePercent(s string) float64 {
	s = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(s), "%"))
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || v < 0 {
		return 0
	}
	return v
}

// parsePair splits docker's "A / B" columns (MemUsage, NetIO, BlockIO) into two
// byte counts. A missing or malformed side is 0 — docker prints "--" for a
// container whose cgroup has no limit, and "0B / 0B" for one that never moved a
// byte, and neither is an error.
func parsePair(s string) (uint64, uint64) {
	left, right, found := strings.Cut(s, "/")
	if !found {
		return parseHumanSize(s), 0
	}
	return parseHumanSize(left), parseHumanSize(right)
}

// parseDockerStats decodes the line-delimited JSON of
// `docker stats --no-stream --format '{{json .}}'`. Rows are keyed by the
// container ID docker prints, which is TRUNCATED to 12 chars by default —
// callers join against the full inspect IDs via statsFor, not by direct map
// lookup.
//
// A malformed line is skipped rather than failing the batch: one container
// whose name breaks docker's own JSON escaping must not cost the stats of
// every other container on the host. Exported-adjacent (lowercase but
// unit-tested directly) in the same style as ParseDockerImages.
func parseDockerStats(raw []byte) map[string]ContainerStats {
	out := map[string]ContainerStats{}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	// A container command line can be long; the default 64KiB token limit is
	// generous but a bigger buffer costs nothing and removes the failure mode.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var row dockerStatsRow
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			continue
		}
		if row.ID == "" {
			continue
		}
		memUsage, memLimit := parsePair(row.MemUsage)
		rx, tx := parsePair(row.NetIO)
		read, write := parsePair(row.BlockIO)
		out[row.ID] = ContainerStats{
			CPUPercent:     parsePercent(row.CPUPerc),
			MemUsage:       memUsage,
			MemLimit:       memLimit,
			MemPercent:     parsePercent(row.MemPerc),
			NetRxBytes:     rx,
			NetTxBytes:     tx,
			DiskReadBytes:  read,
			DiskWriteBytes: write,
		}
	}
	return out
}

// CollectStats runs one `docker stats --no-stream` pass over the host.
//
// ⚠ This is the only EXPENSIVE call the agent makes: docker samples every
// container's cgroup twice to compute a CPU percentage, so the call blocks
// ~1s and scales with the container count. On a host with dozens of containers
// it can approach the report interval itself, which is why it is (a) gated by
// AGENT_DOCKER_STATS and (b) run through a Runner that the caller times out —
// degrading to an inventory without stats always beats delaying the report.
func CollectStats(run Runner) StatsInfo {
	if run == nil {
		run = ExecRunner
	}
	out, err := run("docker", "stats", "--no-stream", "--format", "{{json .}}")
	if err != nil {
		return StatsInfo{OK: false, Error: "docker stats: " + err.Error()}
	}
	return StatsInfo{OK: true, Stats: parseDockerStats(out)}
}

// statsFor resolves a container's stats row, tolerating docker's truncated IDs:
// `docker stats` prints 12 chars where `docker inspect` gives the full 64, so a
// direct map lookup misses. Falls back to matching by container name, which is
// what a user-facing `--format` change would leave intact.
func statsFor(stats map[string]ContainerStats, c Container) (ContainerStats, bool) {
	if s, ok := stats[c.ID]; ok {
		return s, true
	}
	for id, s := range stats {
		if id != "" && strings.HasPrefix(c.ID, id) {
			return s, true
		}
	}
	if s, ok := stats[c.Name]; ok {
		return s, true
	}
	return ContainerStats{}, false
}

// WithStats folds a `docker stats` pass into the container inventory, in the
// same shape and for the same reason as WithImages: one `docker` report section
// with one ok/error pair for the whole docker CLI surface.
//
// A failed or skipped stats pass NEVER clears the inventory's OK flag —
// `docker ps`/`docker inspect` succeeded, and every consumer that predates
// these fields reads only the inventory. Containers simply arrive without usage
// numbers and the frontend renders them as unknown ("—"), not as zero.
func (d DockerInfo) WithStats(s StatsInfo) DockerInfo {
	if !s.OK {
		if s.Error != "" {
			d.Error = appendErr(d.Error, s.Error)
		}
		return d
	}
	containers := make([]Container, len(d.Containers))
	copy(containers, d.Containers)
	for i := range containers {
		st, ok := statsFor(s.Stats, containers[i])
		if !ok {
			continue
		}
		containers[i].CPUPercent = st.CPUPercent
		containers[i].MemUsage = st.MemUsage
		containers[i].MemLimit = st.MemLimit
		containers[i].MemPercent = st.MemPercent
		containers[i].NetRxBytes = st.NetRxBytes
		containers[i].NetTxBytes = st.NetTxBytes
		containers[i].DiskReadBytes = st.DiskReadBytes
		containers[i].DiskWriteBytes = st.DiskWriteBytes
	}
	d.Containers = containers
	return d
}
