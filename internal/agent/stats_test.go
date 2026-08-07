//go:build agent

package agent

import (
	"errors"
	"reflect"
	"testing"
)

func TestParsePercent(t *testing.T) {
	cases := map[string]float64{
		"0.15%":  0.15,
		"12.50%": 12.5,
		" 3% ":   3,
		"0.00%":  0,
		// Docker prints "--" for a container it could not sample; unparseable
		// input must read as 0, never break the batch.
		"--": 0,
		"":   0,
	}
	for in, want := range cases {
		if got := parsePercent(in); got != want {
			t.Errorf("parsePercent(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestParsePair(t *testing.T) {
	cases := []struct {
		in           string
		wantA, wantB uint64
	}{
		// Binary units (MemUsage) and decimal units (NetIO/BlockIO) — docker
		// mixes both depending on the column and the version.
		{"1.093GiB / 7.775GiB", 1173599814, 8348342682},
		{"12.5MB / 4kB", 12500000, 4000},
		{"0B / 0B", 0, 0},
		// No limit set on the cgroup.
		{"1.5MiB / --", 1572864, 0},
		// Single value, no separator: read as the left side.
		{"800kB", 800000, 0},
		{"", 0, 0},
	}
	for _, c := range cases {
		a, b := parsePair(c.in)
		if a != c.wantA || b != c.wantB {
			t.Errorf("parsePair(%q) = (%d, %d), want (%d, %d)", c.in, a, b, c.wantA, c.wantB)
		}
	}
}

func TestParseDockerStats(t *testing.T) {
	raw := []byte(`{"ID":"abc123def456","Name":"api","CPUPerc":"1.25%","MemUsage":"256MiB / 2GiB","MemPerc":"12.50%","NetIO":"1.2MB / 800kB","BlockIO":"12.5MB / 4kB"}
{"ID":"ffffffffffff","Name":"db","CPUPerc":"0.00%","MemUsage":"1.093GiB / 7.775GiB","MemPerc":"14.06%","NetIO":"0B / 0B","BlockIO":"0B / 0B"}

not json at all
{"Name":"no-id","CPUPerc":"5%"}
`)

	got := parseDockerStats(raw)

	// Malformed lines and rows without an ID are skipped, never fatal: one
	// container with a name that breaks docker's escaping must not cost the rest.
	if len(got) != 2 {
		t.Fatalf("parseDockerStats() returned %d rows, want 2: %+v", len(got), got)
	}
	want := ContainerStats{
		CPUPercent: 1.25, MemUsage: 268435456, MemLimit: 2147483648, MemPercent: 12.5,
		NetRxBytes: 1200000, NetTxBytes: 800000,
		DiskReadBytes: 12500000, DiskWriteBytes: 4000,
	}
	if !reflect.DeepEqual(got["abc123def456"], want) {
		t.Errorf("stats[abc123def456] = %+v, want %+v", got["abc123def456"], want)
	}
}

func TestWithStats_JoinsOnTruncatedID(t *testing.T) {
	// `docker stats` prints 12-char IDs while `docker inspect` gives 64 — a
	// direct map lookup would miss every container.
	inventory := DockerInfo{OK: true, Containers: []Container{
		{ID: "abc123def456789abcdef0123456789abcdef0123456789abcdef0123456789a", Name: "api"},
		{ID: "0000000000000000000000000000000000000000000000000000000000000000", Name: "orphan"},
	}}
	stats := StatsInfo{OK: true, Stats: map[string]ContainerStats{
		"abc123def456": {CPUPercent: 2.5, MemUsage: 1024, MemPercent: 3.5, NetRxBytes: 7, DiskWriteBytes: 9},
	}}

	got := inventory.WithStats(stats)

	if got.Containers[0].CPUPercent != 2.5 || got.Containers[0].MemUsage != 1024 {
		t.Errorf("container[0] = %+v, want stats applied", got.Containers[0])
	}
	// A container with no stats row keeps zeroed fields, which `omitempty` drops
	// from the payload — the frontend renders "—", not a fake zero.
	if got.Containers[1].CPUPercent != 0 || got.Containers[1].MemUsage != 0 {
		t.Errorf("container[1] = %+v, want no stats applied", got.Containers[1])
	}
}

func TestWithStats_FailureKeepsInventoryOK(t *testing.T) {
	// The stats pass and the inventory are independent docker calls: a stats
	// timeout must cost the numbers, never the container list.
	inventory := DockerInfo{OK: true, Containers: []Container{{ID: "abc", Name: "api"}}}

	got := inventory.WithStats(StatsInfo{OK: false, Error: "docker stats: signal: killed"})

	if !got.OK {
		t.Errorf("OK = false, want true (inventory succeeded)")
	}
	if len(got.Containers) != 1 {
		t.Errorf("len(Containers) = %d, want 1", len(got.Containers))
	}
	if got.Error == "" {
		t.Errorf("Error = %q, want the stats failure surfaced", got.Error)
	}
}

func TestCollectStats_RunnerFailureFoldsIntoSection(t *testing.T) {
	got := CollectStats(func(string, ...string) ([]byte, error) {
		return nil, errors.New("signal: killed")
	})
	if got.OK {
		t.Errorf("OK = true, want false")
	}
	if got.Error == "" {
		t.Errorf("Error = %q, want a message", got.Error)
	}
}

func TestCollectStats_PassesNoStreamJSONFormat(t *testing.T) {
	// The `--no-stream` flag is what makes this call terminate at all; the
	// `{{json .}}` format is what parseDockerStats expects.
	var args []string
	CollectStats(func(name string, a ...string) ([]byte, error) {
		args = append([]string{name}, a...)
		return []byte(""), nil
	})
	want := []string{"docker", "stats", "--no-stream", "--format", "{{json .}}"}
	if !reflect.DeepEqual(args, want) {
		t.Errorf("command = %v, want %v", args, want)
	}
}
