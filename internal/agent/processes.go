//go:build agent

package agent

import (
	"sort"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v3/process"
)

const (
	// maxCmdlineLen caps the reported cmdline (C3: "cmdline truncado a 200
	// chars") so a single java/node invocation can't bloat the report.
	maxCmdlineLen = 200
	// topNProcs is how many processes are kept per resource dimension
	// (top-N by CPU and top-N by RSS) in the cardinality filter.
	topNProcs = 15
	// maxProcs is the hard cap of the `processes.procs` list.
	maxProcs = 60
)

// ProcCache keeps pid→*process.Process handles alive between report ticks.
// gopsutil's CPUPercent needs two samples on the SAME handle to compute a
// real utilization (the first call on a fresh handle measures since process
// start); reusing handles across ticks turns cpu_percent into "usage since
// the previous report". Handles of dead PIDs are invalidated on every
// collection.
type ProcCache struct {
	handles map[int32]*process.Process
	// ioPrev mirrors handles' reuse-across-ticks discipline for disk I/O:
	// gopsutil's IOCounters returns CUMULATIVE bytes, so a rate needs a prior
	// sample to diff against, the same "since previous report" convention
	// CPUPercent gets for free from gopsutil.
	ioPrev map[int32]procIOSample
}

// procIOSample is the previous tick's cumulative IO counters for one PID,
// timestamped so the rate can be computed regardless of the actual tick
// interval.
type procIOSample struct {
	at    time.Time
	read  uint64
	write uint64
}

func NewProcCache() *ProcCache {
	return &ProcCache{handles: map[int32]*process.Process{}, ioPrev: map[int32]procIOSample{}}
}

// procCandidate is one sampled process, the input of the pure selection
// filter (kept minimal so tests can build fixtures without gopsutil).
type procCandidate struct {
	pid int32
	cpu float64
	rss uint64
}

// CollectProcesses samples all processes and returns the C3 `processes`
// section, filtered for cardinality: the union of pinnedPIDs (port owners ∪
// managed-unit MainPIDs ∪ container PIDs — passed by buildReport) with the
// top-15 by CPU and top-15 by RSS, hard-capped at 60 entries with a
// `truncated` flag. Best-effort like every collector: a listing failure
// yields {OK:false, Error:...}; per-process field failures leave zero values.
func (c *ProcCache) CollectProcesses(pinnedPIDs []int32, pidConns map[int32]int) ProcessesInfo {
	if c == nil {
		// Nil receiver still works (one-shot sampling, cpu_percent will read
		// as since-process-start on the first report) — best-effort over
		// panicking in the report loop.
		c = NewProcCache()
	}
	if c.ioPrev == nil {
		c.ioPrev = map[int32]procIOSample{}
	}
	procs, err := process.Processes()
	if err != nil {
		return ProcessesInfo{OK: false, Error: "list processes: " + err.Error(), Procs: []ProcInfo{}}
	}

	// Refresh the handle cache: reuse live handles (CPU baseline), adopt new
	// ones, drop dead PIDs.
	alive := make(map[int32]*process.Process, len(procs))
	for _, p := range procs {
		if cached, ok := c.handles[p.Pid]; ok {
			alive[p.Pid] = cached
		} else {
			alive[p.Pid] = p
		}
	}
	c.handles = alive

	pinned := make(map[int32]bool, len(pinnedPIDs))
	for _, pid := range pinnedPIDs {
		pinned[pid] = true
	}

	candidates := make([]procCandidate, 0, len(alive))
	for pid, h := range alive {
		cand := procCandidate{pid: pid}
		if cpu, err := h.CPUPercent(); err == nil {
			cand.cpu = cpu
		}
		if mi, err := h.MemoryInfo(); err == nil && mi != nil {
			cand.rss = mi.RSS
		}
		candidates = append(candidates, cand)
	}

	selected, truncated := selectProcs(candidates, pinned, topNProcs, maxProcs)

	byPid := make(map[int32]procCandidate, len(candidates))
	for _, cand := range candidates {
		byPid[cand.pid] = cand
	}

	now := time.Now()
	newIOPrev := make(map[int32]procIOSample, len(selected))

	out := make([]ProcInfo, 0, len(selected))
	for _, pid := range selected {
		h := alive[pid]
		if h == nil {
			continue
		}
		info := ProcInfo{
			Pid:         pid,
			CPUPercent:  byPid[pid].cpu,
			RSSBytes:    byPid[pid].rss,
			Connections: pidConns[pid],
		}
		if mp, err := h.MemoryPercent(); err == nil {
			info.MemPercent = float64(mp)
		}
		if io, err := h.IOCounters(); err == nil && io != nil {
			newIOPrev[pid] = procIOSample{at: now, read: io.ReadBytes, write: io.WriteBytes}
			if prev, ok := c.ioPrev[pid]; ok {
				if elapsed := now.Sub(prev.at).Seconds(); elapsed > 0 {
					info.ReadRateBps = rateOrZero(io.ReadBytes, prev.read, elapsed)
					info.WriteRateBps = rateOrZero(io.WriteBytes, prev.write, elapsed)
				}
			}
		}
		if ppid, err := h.Ppid(); err == nil {
			info.Ppid = ppid
		}
		if name, err := h.Name(); err == nil {
			info.Name = name
		}
		if cmd, err := h.Cmdline(); err == nil {
			info.Cmdline = truncateString(cmd, maxCmdlineLen)
		}
		if usr, err := h.Username(); err == nil {
			info.User = usr
		}
		if ct, err := h.CreateTime(); err == nil {
			info.CreateTime = ct / 1000 // gopsutil returns ms; C3 uses unix seconds
		}
		if st, err := h.Status(); err == nil && len(st) > 0 {
			info.Status = statusLetter(st[0])
		}
		out = append(out, info)
	}
	c.ioPrev = newIOPrev

	return ProcessesInfo{OK: true, Truncated: truncated, Procs: out}
}

// rateOrZero is the IO-counter analogue of a CPU delta: cur/prev are
// cumulative byte counts, elapsed is the seconds between samples. A negative
// delta (pid reuse landing a same-numbered but different process, or a
// counter reset) clamps to 0 rather than reporting a nonsensical negative
// rate.
func rateOrZero(cur, prev uint64, elapsed float64) float64 {
	if cur < prev {
		return 0
	}
	return float64(cur-prev) / elapsed
}

// selectProcs is the pure cardinality filter (C3): union of pinned PIDs,
// top-N by CPU and top-N by RSS, capped at max entries. When the cap drops
// candidates, truncated=true. Pinned PIDs win over top-CPU which wins over
// top-RSS; the returned slice is sorted by PID for a stable report shape.
func selectProcs(cands []procCandidate, pinned map[int32]bool, topN, max int) ([]int32, bool) {
	exists := make(map[int32]bool, len(cands))
	for _, cand := range cands {
		exists[cand.pid] = true
	}

	// Deterministic priority order: pinned (by pid), then top-CPU, then
	// top-RSS.
	var ordered []int32
	inOrder := map[int32]bool{}
	add := func(pid int32) {
		if !inOrder[pid] && exists[pid] {
			inOrder[pid] = true
			ordered = append(ordered, pid)
		}
	}

	pinnedList := make([]int32, 0, len(pinned))
	for pid := range pinned {
		pinnedList = append(pinnedList, pid)
	}
	sort.Slice(pinnedList, func(i, j int) bool { return pinnedList[i] < pinnedList[j] })
	for _, pid := range pinnedList {
		add(pid)
	}

	byCPU := append([]procCandidate(nil), cands...)
	sort.Slice(byCPU, func(i, j int) bool {
		if byCPU[i].cpu != byCPU[j].cpu {
			return byCPU[i].cpu > byCPU[j].cpu
		}
		return byCPU[i].pid < byCPU[j].pid
	})
	for i := 0; i < topN && i < len(byCPU); i++ {
		add(byCPU[i].pid)
	}

	byRSS := append([]procCandidate(nil), cands...)
	sort.Slice(byRSS, func(i, j int) bool {
		if byRSS[i].rss != byRSS[j].rss {
			return byRSS[i].rss > byRSS[j].rss
		}
		return byRSS[i].pid < byRSS[j].pid
	})
	for i := 0; i < topN && i < len(byRSS); i++ {
		add(byRSS[i].pid)
	}

	truncated := false
	if len(ordered) > max {
		ordered = ordered[:max]
		truncated = true
	}

	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	return ordered, truncated
}

// truncateString caps s at max bytes (cmdlines are ASCII-ish; a mid-rune cut
// on a pathological UTF-8 arg is acceptable for a telemetry preview).
func truncateString(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}

// statusLetter maps gopsutil v3 long status names back to the conventional
// one-letter ps codes used by contract C3 ("status": "S").
func statusLetter(s string) string {
	switch strings.ToLower(s) {
	case process.Running:
		return "R"
	case process.Sleep:
		return "S"
	case process.Blocked:
		return "D"
	case process.Idle:
		return "I"
	case process.Lock:
		return "L"
	case process.Stop:
		return "T"
	case process.Wait:
		return "W"
	case process.Zombie:
		return "Z"
	default:
		return s
	}
}
