//go:build agent

package agent

import (
	"encoding/json"
	"strings"
	"time"
)

// How many CrowdSec decisions ride in the report. Same reasoning as
// maxPeerEntries: a host that pulled a community blocklist can hold tens of
// thousands of decisions, and the panel renders a handful of rows. The
// backoffice's own view of "everything CrowdSec knows" is a separate,
// explicit `cscli decisions list` over SSH — this section is the at-a-glance
// state, not the archive. Truncation is flagged, never silent.
const maxDecisionEntries = 100

// CollectSecurity reports what this host is currently enforcing: the contents
// of the `inet bo_guard` nftables table (via ipctl, so the parsing lives in
// exactly one place — scripts/lib/ip-lib.sh) and CrowdSec's active decisions.
//
// Read-only by construction. The agent has no inbound control channel and
// deliberately gains none here: WRITING a rule stays an SSH-exec of ipctl
// from selfApi. This function only ever answers "what is in place right now",
// which is what makes drift detection possible on the backend side.
//
// Never returns an error — a missing ipctl, a missing cscli or a
// permission-denied all fold into the returned struct, per the D5/B2 rule
// that a collector must never take the process down.
func CollectSecurity(run Runner, now time.Time) SecurityInfo {
	if run == nil {
		run = ExecRunner
	}
	info := SecurityInfo{
		OK:          true,
		CollectedAt: now.UTC().Format(time.RFC3339),
		Guard:       collectGuard(run),
		CrowdSec:    collectCrowdSec(run),
	}
	// OK is about whether this collector ran, not about whether the host is
	// protected. An unprovisioned host with neither tool installed is a
	// perfectly successful collection that happens to report "nothing here".
	return info
}

// ─────────────────────────── nft guard ───────────────────────────

// ipctlList is the JSON shape ip_guard_list_json() prints. Field names are
// the nft set names, which is why they are spelled out rather than derived.
type ipctlList struct {
	TablePresent bool     `json:"table_present"`
	AllowV4      []string `json:"bo_allow_v4"`
	AllowV6      []string `json:"bo_allow_v6"`
	BlockV4      []string `json:"bo_block_v4"`
	BlockV6      []string `json:"bo_block_v6"`
}

func collectGuard(run Runner) GuardInfo {
	// Non-nil empty slices: "no blocks" must marshal as [] and not as null,
	// or the backend's drift diff has to special-case a nil it never asked
	// for.
	g := GuardInfo{
		BlockV4: []string{},
		BlockV6: []string{},
		AllowV4: []string{},
		AllowV6: []string{},
	}

	out, err := run("ipctl", "list")
	if err != nil {
		// ipctl absent (host provisioned by an agent older than this one) or
		// nft absent. Both mean the same thing to the operator — per-IP
		// blocking is not available here — and both are distinguished from a
		// present-but-empty guard by these two flags.
		return g
	}
	g.IpctlPresent = true

	var parsed ipctlList
	if err := json.Unmarshal(out, &parsed); err != nil {
		return g
	}
	g.NftPresent = true
	g.TablePresent = parsed.TablePresent
	if parsed.BlockV4 != nil {
		g.BlockV4 = parsed.BlockV4
	}
	if parsed.BlockV6 != nil {
		g.BlockV6 = parsed.BlockV6
	}
	if parsed.AllowV4 != nil {
		g.AllowV4 = parsed.AllowV4
	}
	if parsed.AllowV6 != nil {
		g.AllowV6 = parsed.AllowV6
	}
	return g
}

// ─────────────────────────── crowdsec ───────────────────────────

// csDecisionJSON is one entry of `cscli decisions list -o json`. CrowdSec
// nests the decision inside an alert envelope, and the fields we want are
// split across both levels: the value/scenario/duration live on the decision,
// but an alert can carry several decisions.
type csDecisionJSON struct {
	ID       int64  `json:"id"`
	Value    string `json:"value"`
	Scope    string `json:"scope"`
	Type     string `json:"type"`
	Scenario string `json:"scenario"`
	Origin   string `json:"origin"`
	Duration string `json:"duration"`
}

type csAlertJSON struct {
	Decisions []csDecisionJSON `json:"decisions"`
	Scenario  string           `json:"scenario"`
}

func collectCrowdSec(run Runner) CrowdSecInfo {
	cs := CrowdSecInfo{}

	verOut, err := run("cscli", "version")
	if err != nil {
		return cs
	}
	cs.Installed = true
	cs.Version = parseCscliVersion(string(verOut))
	cs.Running = unitActive(run, "crowdsec")
	cs.BouncerRunning = unitActive(run, "crowdsec-firewall-bouncer")

	// A stopped LAPI makes this call fail; that is not an error worth
	// surfacing separately, because Running:false already says it.
	out, err := run("cscli", "decisions", "list", "-o", "json")
	if err != nil {
		return cs
	}
	cs.Decisions, cs.Truncated = parseCscliDecisions(out)
	return cs
}

// parseCscliVersion pulls the number out of `cscli version`, whose first line
// is like "version: v1.6.3-rpm-…". Same extraction shape as
// wg_installed_version in setup.sh.
func parseCscliVersion(out string) string {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(strings.ToLower(line), "version:") {
			continue
		}
		v := strings.TrimSpace(line[len("version:"):])
		return strings.TrimPrefix(v, "v")
	}
	return ""
}

// parseCscliDecisions flattens the alert→decisions nesting into a flat list.
//
// `cscli decisions list -o json` prints `null` (not `[]`) when there is
// nothing to report, which json.Unmarshal accepts into a nil slice — so an
// empty result and a parse failure look identical unless the error is checked
// first. Returns whether the list was cut at maxDecisionEntries.
func parseCscliDecisions(out []byte) ([]CSDecision, bool) {
	var alerts []csAlertJSON
	if err := json.Unmarshal(out, &alerts); err != nil {
		return nil, false
	}
	var decisions []CSDecision
	for _, a := range alerts {
		for _, d := range a.Decisions {
			scenario := d.Scenario
			if scenario == "" {
				// The decision inherits the alert's scenario when it has none
				// of its own — which is the common case for `cscli decisions
				// add`, where the alert carries "manual 'ban' from 'user'".
				scenario = a.Scenario
			}
			if len(decisions) >= maxDecisionEntries {
				return decisions, true
			}
			decisions = append(decisions, CSDecision{
				ID:       d.ID,
				Value:    d.Value,
				Scope:    d.Scope,
				Type:     d.Type,
				Scenario: scenario,
				Origin:   d.Origin,
				Duration: d.Duration,
			})
		}
	}
	return decisions, false
}

// unitActive is `systemctl is-active <unit>`, which exits non-zero for every
// non-active state — so the exit code alone cannot distinguish "inactive"
// from "systemctl is missing". The stdout word is what actually answers the
// question, and it is printed in both cases.
func unitActive(run Runner, unit string) bool {
	out, _ := run("systemctl", "is-active", unit)
	return strings.TrimSpace(string(out)) == "active"
}
