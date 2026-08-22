//go:build agent

package agent

import (
	"errors"
	"testing"
	"time"
)

// fakeSecurityRunner dispatches on the first two argv words, which is enough
// to tell `ipctl list` from `cscli version` from `systemctl is-active X`.
// A key with no entry returns an error, which is how "this binary is not
// installed" is simulated.
func fakeSecurityRunner(responses map[string]string) Runner {
	return func(name string, args ...string) ([]byte, error) {
		key := name
		if len(args) > 0 {
			key += " " + args[0]
		}
		if len(args) > 1 && name == "systemctl" {
			key += " " + args[1]
		}
		if out, ok := responses[key]; ok {
			return []byte(out), nil
		}
		return nil, errors.New("command not found: " + key)
	}
}

const ipctlListOut = `{"table_present":true,"bo_allow_v4":["198.51.100.7"],"bo_allow_v6":[],"bo_block_v4":["203.0.113.4","198.51.100.0/24"],"bo_block_v6":["2001:db8::1"]}`

const cscliVersionOut = `version: v1.6.3-rpm-abcdef
Codename: alphaga
BuildDate: 2026-01-01`

const cscliDecisionsOut = `[
  {"scenario":"manual 'ban' from 'ops'","decisions":[
    {"id":12,"value":"192.0.2.44","scope":"Ip","type":"ban","origin":"cscli","duration":"3h59m"}
  ]},
  {"scenario":"crowdsecurity/ssh-bf","decisions":[
    {"id":13,"value":"192.0.2.99","scope":"Ip","type":"ban","scenario":"crowdsecurity/ssh-bf","origin":"crowdsec","duration":"1h"}
  ]}
]`

func TestCollectSecurityFullyProvisioned(t *testing.T) {
	run := fakeSecurityRunner(map[string]string{
		"ipctl list":                   ipctlListOut,
		"cscli version":                cscliVersionOut,
		"cscli decisions":              cscliDecisionsOut,
		"systemctl is-active crowdsec": "active\n",
		"systemctl is-active crowdsec-firewall-bouncer": "active\n",
	})

	got := CollectSecurity(run, time.Unix(1750000000, 0))

	if !got.OK {
		t.Fatalf("OK = false, want true")
	}
	if got.CollectedAt == "" {
		t.Error("CollectedAt is empty — a cached section with no age is unreadable")
	}
	if !got.Guard.IpctlPresent || !got.Guard.NftPresent || !got.Guard.TablePresent {
		t.Errorf("guard presence flags = %+v, want all true", got.Guard)
	}
	if len(got.Guard.BlockV4) != 2 || got.Guard.BlockV4[0] != "203.0.113.4" {
		t.Errorf("BlockV4 = %v", got.Guard.BlockV4)
	}
	if len(got.Guard.BlockV6) != 1 || got.Guard.BlockV6[0] != "2001:db8::1" {
		t.Errorf("BlockV6 = %v", got.Guard.BlockV6)
	}
	if len(got.Guard.AllowV4) != 1 {
		t.Errorf("AllowV4 = %v", got.Guard.AllowV4)
	}
	if !got.CrowdSec.Installed || got.CrowdSec.Version != "1.6.3-rpm-abcdef" {
		t.Errorf("crowdsec = %+v, want installed 1.6.3-rpm-abcdef", got.CrowdSec)
	}
	if !got.CrowdSec.Running || !got.CrowdSec.BouncerRunning {
		t.Errorf("crowdsec running=%v bouncer=%v, want both true",
			got.CrowdSec.Running, got.CrowdSec.BouncerRunning)
	}
	if len(got.CrowdSec.Decisions) != 2 {
		t.Fatalf("decisions = %+v, want 2", got.CrowdSec.Decisions)
	}
	// The manual decision carries no per-decision scenario; it must inherit
	// the alert's, or the panel shows a blank reason for exactly the rows the
	// operator is most likely to want to promote.
	if got.CrowdSec.Decisions[0].Scenario != "manual 'ban' from 'ops'" {
		t.Errorf("decision[0].Scenario = %q, want the alert scenario inherited",
			got.CrowdSec.Decisions[0].Scenario)
	}
	if got.CrowdSec.Decisions[1].Scenario != "crowdsecurity/ssh-bf" {
		t.Errorf("decision[1].Scenario = %q", got.CrowdSec.Decisions[1].Scenario)
	}
}

// The common case on an existing host: nothing installed yet. This must be a
// successful collection reporting absence, not a failure — the backoffice
// renders "provisionar CrowdSec" from exactly this state.
func TestCollectSecurityNothingInstalled(t *testing.T) {
	got := CollectSecurity(fakeSecurityRunner(nil), time.Unix(1750000000, 0))

	if !got.OK {
		t.Error("OK = false; an unprovisioned host is not a collector failure")
	}
	if got.Guard.IpctlPresent || got.Guard.NftPresent || got.Guard.TablePresent {
		t.Errorf("guard = %+v, want all-absent", got.Guard)
	}
	if got.CrowdSec.Installed {
		t.Error("CrowdSec.Installed = true with no cscli")
	}
	// Non-nil empty slices, so the backend's drift diff never has to
	// distinguish nil from empty.
	if got.Guard.BlockV4 == nil || got.Guard.AllowV6 == nil {
		t.Error("guard slices must marshal as [] and not null")
	}
}

// crowdsec deciding while its bouncer is dead: decisions exist and nothing is
// enforced. The single most misleading state the section exists to surface,
// so it gets its own test.
func TestCollectSecurityBouncerDown(t *testing.T) {
	run := fakeSecurityRunner(map[string]string{
		"cscli version":                                 cscliVersionOut,
		"cscli decisions":                               cscliDecisionsOut,
		"systemctl is-active crowdsec":                  "active\n",
		"systemctl is-active crowdsec-firewall-bouncer": "inactive\n",
	})

	got := CollectSecurity(run, time.Unix(1750000000, 0))

	if !got.CrowdSec.Running {
		t.Error("Running = false, want true")
	}
	if got.CrowdSec.BouncerRunning {
		t.Error("BouncerRunning = true, want false")
	}
	if len(got.CrowdSec.Decisions) != 2 {
		t.Errorf("decisions should still be reported when the bouncer is down, got %d",
			len(got.CrowdSec.Decisions))
	}
}

// ipctl installed but nft missing: `ipctl list` fails outright, so the only
// honest report is "guard unavailable".
func TestCollectSecurityGuardUnreadable(t *testing.T) {
	run := fakeSecurityRunner(map[string]string{"cscli version": cscliVersionOut})
	got := CollectSecurity(run, time.Unix(1750000000, 0))
	if got.Guard.IpctlPresent {
		t.Error("IpctlPresent = true after `ipctl list` failed")
	}
	if !got.OK {
		t.Error("a missing guard must not fail the whole section")
	}
}

func TestParseCscliDecisionsEmpty(t *testing.T) {
	// cscli prints `null`, not `[]`, when there is nothing to report.
	got, truncated := parseCscliDecisions([]byte("null"))
	if len(got) != 0 || truncated {
		t.Errorf("got %v truncated=%v, want empty", got, truncated)
	}
	if got, _ := parseCscliDecisions([]byte("not json")); got != nil {
		t.Errorf("garbage input should yield nil, got %v", got)
	}
}

func TestParseCscliDecisionsTruncates(t *testing.T) {
	// One alert holding more decisions than the cap — the community blocklist
	// shape. The cut must be flagged, never silent.
	body := `[{"scenario":"lists","decisions":[`
	for i := 0; i < maxDecisionEntries+20; i++ {
		if i > 0 {
			body += ","
		}
		body += `{"value":"192.0.2.1","scope":"Ip","type":"ban"}`
	}
	body += `]}]`

	got, truncated := parseCscliDecisions([]byte(body))
	if len(got) != maxDecisionEntries {
		t.Errorf("len = %d, want %d", len(got), maxDecisionEntries)
	}
	if !truncated {
		t.Error("truncated = false after cutting the list")
	}
}

func TestParseCscliVersion(t *testing.T) {
	cases := map[string]string{
		cscliVersionOut:     "1.6.3-rpm-abcdef",
		"version: v1.5.0":   "1.5.0",
		"Version: v1.5.0":   "1.5.0",
		"no version at all": "",
		"":                  "",
	}
	for in, want := range cases {
		if got := parseCscliVersion(in); got != want {
			t.Errorf("parseCscliVersion(%q) = %q, want %q", in, got, want)
		}
	}
}
