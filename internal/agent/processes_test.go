//go:build agent

package agent

import (
	"sort"
	"strings"
	"testing"
)

// makeCands builds n candidates with pid i+1, cpu and rss increasing with the
// pid so "top by CPU" and "top by RSS" are the highest pids.
func makeCands(n int) []procCandidate {
	cands := make([]procCandidate, 0, n)
	for i := 1; i <= n; i++ {
		cands = append(cands, procCandidate{
			pid: int32(i),
			cpu: float64(i),
			rss: uint64(i) * 1024,
		})
	}
	return cands
}

func pidSet(pids []int32) map[int32]bool {
	m := map[int32]bool{}
	for _, p := range pids {
		m[p] = true
	}
	return m
}

func TestSelectProcs_UnionOfPinnedAndTops(t *testing.T) {
	cands := makeCands(100)
	// Low pids would never make top-15 CPU/RSS — pinning must keep them.
	pinned := pidSet([]int32{1, 2, 3})

	selected, truncated := selectProcs(cands, pinned, 15, 60)
	if truncated {
		t.Fatal("union of 3 pinned + top-15 (cpu==rss ordering) must not hit the cap")
	}

	sel := pidSet(selected)
	for _, pid := range []int32{1, 2, 3} {
		if !sel[pid] {
			t.Fatalf("pinned pid %d missing from selection %v", pid, selected)
		}
	}
	// Top-15 by CPU and RSS coincide here: pids 86..100.
	for pid := int32(86); pid <= 100; pid++ {
		if !sel[pid] {
			t.Fatalf("top pid %d missing from selection %v", pid, selected)
		}
	}
	if len(selected) != 18 {
		t.Fatalf("expected 3 pinned + 15 top = 18, got %d: %v", len(selected), selected)
	}
	if !sort.SliceIsSorted(selected, func(i, j int) bool { return selected[i] < selected[j] }) {
		t.Fatalf("selection must be sorted by pid: %v", selected)
	}
}

func TestSelectProcs_DisjointTops(t *testing.T) {
	// 40 candidates: pids 1..20 are CPU-heavy with no RSS, 21..40 RSS-heavy
	// with no CPU — top-15 of each dimension are disjoint sets.
	var cands []procCandidate
	for i := 1; i <= 20; i++ {
		cands = append(cands, procCandidate{pid: int32(i), cpu: float64(100 - i)})
	}
	for i := 21; i <= 40; i++ {
		cands = append(cands, procCandidate{pid: int32(i), rss: uint64(1000 - i)})
	}

	selected, truncated := selectProcs(cands, nil, 15, 60)
	if truncated {
		t.Fatal("30 selected < cap 60, must not be truncated")
	}
	if len(selected) != 30 {
		t.Fatalf("expected 15 CPU + 15 RSS = 30, got %d: %v", len(selected), selected)
	}
	sel := pidSet(selected)
	for pid := int32(1); pid <= 15; pid++ {
		if !sel[pid] {
			t.Fatalf("top-CPU pid %d missing", pid)
		}
	}
	for pid := int32(21); pid <= 35; pid++ {
		if !sel[pid] {
			t.Fatalf("top-RSS pid %d missing", pid)
		}
	}
}

func TestSelectProcs_CapAndTruncatedFlag(t *testing.T) {
	cands := makeCands(200)
	// 60 pinned pids + top-15s exceed the cap of 60 → pinned win, truncated set.
	var pinnedList []int32
	for pid := int32(1); pid <= 60; pid++ {
		pinnedList = append(pinnedList, pid)
	}
	pinned := pidSet(pinnedList)

	selected, truncated := selectProcs(cands, pinned, 15, 60)
	if !truncated {
		t.Fatal("expected truncated=true when the cap drops candidates")
	}
	if len(selected) != 60 {
		t.Fatalf("expected exactly cap=60 entries, got %d", len(selected))
	}
	// Pinned have priority over top-CPU/top-RSS when the cap bites.
	sel := pidSet(selected)
	for pid := int32(1); pid <= 60; pid++ {
		if !sel[pid] {
			t.Fatalf("pinned pid %d evicted by cap, selection %v", pid, selected)
		}
	}
}

func TestSelectProcs_DeadPinnedPIDsIgnored(t *testing.T) {
	cands := makeCands(20)
	// 999 is pinned (e.g. a container PID from a stale inspect) but not among
	// the live candidates — it must be skipped, not invented.
	selected, _ := selectProcs(cands, pidSet([]int32{999, 5}), 15, 60)
	sel := pidSet(selected)
	if sel[999] {
		t.Fatal("dead pinned pid 999 must not appear in the selection")
	}
	if !sel[5] {
		t.Fatal("live pinned pid 5 must appear in the selection")
	}
}

func TestSelectProcs_NoDuplicates(t *testing.T) {
	cands := makeCands(30)
	// pid 30 is pinned AND top CPU AND top RSS — must appear once.
	selected, _ := selectProcs(cands, pidSet([]int32{30}), 15, 60)
	count := 0
	for _, pid := range selected {
		if pid == 30 {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("pid 30 appears %d times, want 1", count)
	}
}

func TestTruncateString(t *testing.T) {
	long := strings.Repeat("x", 500)
	if got := truncateString(long, maxCmdlineLen); len(got) != maxCmdlineLen {
		t.Fatalf("truncated len = %d, want %d", len(got), maxCmdlineLen)
	}
	if got := truncateString("short", maxCmdlineLen); got != "short" {
		t.Fatalf("short strings must pass through, got %q", got)
	}
}

func TestStatusLetter(t *testing.T) {
	cases := map[string]string{
		"running": "R",
		"sleep":   "S",
		"blocked": "D",
		"idle":    "I",
		"lock":    "L",
		"stop":    "T",
		"wait":    "W",
		"zombie":  "Z",
		"weird":   "weird", // unknown values pass through untouched
	}
	for in, want := range cases {
		if got := statusLetter(in); got != want {
			t.Fatalf("statusLetter(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCollectProcesses_NilCacheAndSelfPresence(t *testing.T) {
	// Real-collection smoke test: the test process itself must be sampleable
	// and a nil receiver must not panic (best-effort guarantee).
	var cache *ProcCache
	info := cache.CollectProcesses(nil)
	if !info.OK {
		t.Fatalf("expected OK=true, got error %q", info.Error)
	}
	if len(info.Procs) == 0 {
		t.Fatal("expected at least one process in the report")
	}
	for _, p := range info.Procs {
		if len(p.Cmdline) > maxCmdlineLen {
			t.Fatalf("cmdline of pid %d exceeds %d chars", p.Pid, maxCmdlineLen)
		}
	}
	if len(info.Procs) > maxProcs {
		t.Fatalf("procs list exceeds cap: %d > %d", len(info.Procs), maxProcs)
	}
}

func TestProcCache_InvalidatesDeadPIDs(t *testing.T) {
	cache := NewProcCache()
	if info := cache.CollectProcesses(nil); !info.OK {
		t.Fatalf("first collection failed: %q", info.Error)
	}
	// Poison the cache with an impossible PID; the next collection must drop it.
	cache.handles[1<<30] = nil
	if info := cache.CollectProcesses(nil); !info.OK {
		t.Fatalf("second collection failed: %q", info.Error)
	}
	if _, ok := cache.handles[1<<30]; ok {
		t.Fatal("dead pid handle must be invalidated between ticks")
	}
}
