//go:build agent

package agent

import (
	"sort"
	"strconv"
	"strings"
)

// DefaultManagedPrefix is the unit-name prefix considered "managed by the
// deployer" when AGENT_MANAGED_PREFIX is not set (improves.md WS-4).
const DefaultManagedPrefix = "deployer-"

// CollectSystemd gathers the C3 `systemd` section in two tiers so the report
// stays small on hosts with hundreds of units:
//
//  1. a light inventory of ALL service units via
//     `systemctl list-units --type=service --all --no-legend --plain --no-pager`
//     → {name, load, active, sub};
//  2. detailed `systemctl show` fields (MainPID, ActiveState, SubState,
//     UnitFileState, NRestarts, ExecMainStartTimestamp) ONLY for managed
//     units: those whose name starts with managedPrefix (env
//     AGENT_MANAGED_PREFIX, default "deployer-") plus the explicit extraUnits
//     list (env AGENT_UNITS, CSV; ".service" suffix optional).
//
// Uses the same injectable Runner seam as docker.go so tests feed canned
// systemctl output. Best-effort: a list-units failure returns {OK:false};
// individual `show` failures degrade OK/Error but keep partial data.
func CollectSystemd(run Runner, managedPrefix string, extraUnits []string) SystemdInfo {
	if run == nil {
		run = ExecRunner
	}
	if managedPrefix == "" {
		managedPrefix = DefaultManagedPrefix
	}

	out, err := run("systemctl", "list-units", "--type=service", "--all", "--no-legend", "--plain", "--no-pager")
	if err != nil {
		return SystemdInfo{OK: false, Error: "systemctl list-units: " + err.Error(), Units: []UnitInfo{}, Managed: []ManagedUnit{}}
	}

	units := parseListUnits(out)
	managedNames := managedUnitNames(units, managedPrefix, extraUnits)

	info := SystemdInfo{OK: true, Units: units, Managed: make([]ManagedUnit, 0, len(managedNames))}
	for _, name := range managedNames {
		showOut, err := run("systemctl", "show", name,
			"-p", "MainPID,ActiveState,SubState,UnitFileState,NRestarts,ExecMainStartTimestamp",
			"--no-pager")
		if err != nil {
			info.OK = false
			info.Error = appendErr(info.Error, "systemctl show "+name+": "+err.Error())
			continue
		}
		info.Managed = append(info.Managed, parseUnitShow(name, showOut))
	}
	return info
}

// parseListUnits parses `systemctl list-units --no-legend --plain` output:
// one unit per line, columns UNIT LOAD ACTIVE SUB DESCRIPTION... (description
// is discarded). Malformed lines are skipped.
func parseListUnits(out []byte) []UnitInfo {
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	units := make([]UnitInfo, 0, len(lines))
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		units = append(units, UnitInfo{
			Name:   fields[0],
			Load:   fields[1],
			Active: fields[2],
			Sub:    fields[3],
		})
	}
	return units
}

// managedUnitNames selects the units that get the detailed `systemctl show`
// pass: inventory units matching the managed prefix, plus the explicit extra
// list (normalized to a ".service" suffix; included even when absent from the
// inventory so a stopped-and-masked managed unit is still reported). The
// result is deduplicated and sorted for a stable report.
func managedUnitNames(units []UnitInfo, managedPrefix string, extraUnits []string) []string {
	seen := map[string]bool{}
	var names []string
	add := func(name string) {
		if name != "" && !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	for _, u := range units {
		if strings.HasPrefix(u.Name, managedPrefix) {
			add(u.Name)
		}
	}
	for _, extra := range extraUnits {
		extra = strings.TrimSpace(extra)
		if extra == "" {
			continue
		}
		if !strings.HasSuffix(extra, ".service") {
			extra += ".service"
		}
		add(extra)
	}
	sort.Strings(names)
	return names
}

// parseUnitShow parses `systemctl show <unit> -p ...` key=value output into a
// ManagedUnit. Unknown keys are ignored; missing keys leave zero values.
func parseUnitShow(name string, out []byte) ManagedUnit {
	mu := ManagedUnit{Name: name}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		key, value, found := strings.Cut(strings.TrimSpace(line), "=")
		if !found {
			continue
		}
		switch key {
		case "MainPID":
			if pid, err := strconv.ParseInt(value, 10, 32); err == nil {
				mu.MainPID = int32(pid)
			}
		case "ActiveState":
			mu.ActiveState = value
		case "SubState":
			mu.SubState = value
		case "UnitFileState":
			mu.UnitFileState = value
		case "NRestarts":
			if n, err := strconv.Atoi(value); err == nil {
				mu.NRestarts = n
			}
		case "ExecMainStartTimestamp":
			mu.ExecMainStart = value
		}
	}
	return mu
}

// ManagedPIDs returns the live MainPIDs of the managed units, used by
// CollectProcesses' cardinality filter (managed units are always kept).
func (s SystemdInfo) ManagedPIDs() []int32 {
	seen := map[int32]bool{}
	out := make([]int32, 0, len(s.Managed))
	for _, m := range s.Managed {
		if m.MainPID > 0 && !seen[m.MainPID] {
			seen[m.MainPID] = true
			out = append(out, m.MainPID)
		}
	}
	return out
}
