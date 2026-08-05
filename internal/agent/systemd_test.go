//go:build agent

package agent

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

const fixtureListUnits = `deployer-app1.service       loaded active   running Deployer app1
deployer-app2.service       loaded inactive dead    Deployer app2
nginx.service               loaded active   running A high performance web server
ssh.service                 loaded active   running OpenBSD Secure Shell server
systemd-journald.service    loaded active   running Journal Service
`

const fixtureShowApp1 = `MainPID=3412
ActiveState=active
SubState=running
UnitFileState=enabled
NRestarts=2
ExecMainStartTimestamp=Tue 2026-08-04 11:22:33 UTC
`

const fixtureShowApp2 = `MainPID=0
ActiveState=inactive
SubState=dead
UnitFileState=enabled
NRestarts=0
ExecMainStartTimestamp=
`

func TestParseListUnits(t *testing.T) {
	units := parseListUnits([]byte(fixtureListUnits))
	if len(units) != 5 {
		t.Fatalf("expected 5 units, got %d: %#v", len(units), units)
	}
	want := UnitInfo{Name: "deployer-app1.service", Load: "loaded", Active: "active", Sub: "running"}
	if units[0] != want {
		t.Fatalf("units[0] = %#v, want %#v", units[0], want)
	}
	if units[1].Active != "inactive" || units[1].Sub != "dead" {
		t.Fatalf("units[1] = %#v, want inactive/dead", units[1])
	}
}

func TestParseListUnits_SkipsMalformedLines(t *testing.T) {
	units := parseListUnits([]byte("garbage\n\nnginx.service loaded active running Web\n"))
	if len(units) != 1 || units[0].Name != "nginx.service" {
		t.Fatalf("expected only nginx.service, got %#v", units)
	}
}

func TestParseUnitShow(t *testing.T) {
	mu := parseUnitShow("deployer-app1.service", []byte(fixtureShowApp1))
	want := ManagedUnit{
		Name:          "deployer-app1.service",
		MainPID:       3412,
		ActiveState:   "active",
		SubState:      "running",
		UnitFileState: "enabled",
		NRestarts:     2,
		ExecMainStart: "Tue 2026-08-04 11:22:33 UTC",
	}
	if mu != want {
		t.Fatalf("parseUnitShow() = %#v, want %#v", mu, want)
	}
}

func TestManagedUnitNames(t *testing.T) {
	units := parseListUnits([]byte(fixtureListUnits))
	// Extra unit without .service suffix must be normalized and included even
	// though it's absent from the inventory.
	got := managedUnitNames(units, "deployer-", []string{"backoffice-api", " ", "deployer-app1"})
	want := []string{"backoffice-api.service", "deployer-app1.service", "deployer-app2.service"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("managedUnitNames() = %v, want %v", got, want)
	}
}

func TestCollectSystemd_HappyPath(t *testing.T) {
	var showCalls []string
	run := func(name string, args ...string) ([]byte, error) {
		if name != "systemctl" {
			t.Fatalf("unexpected binary: %s", name)
		}
		switch args[0] {
		case "list-units":
			wantArgs := []string{"list-units", "--type=service", "--all", "--no-legend", "--plain", "--no-pager"}
			if !reflect.DeepEqual(args, wantArgs) {
				t.Fatalf("list-units args = %v, want %v", args, wantArgs)
			}
			return []byte(fixtureListUnits), nil
		case "show":
			unit := args[1]
			showCalls = append(showCalls, unit)
			if args[2] != "-p" || !strings.Contains(args[3], "MainPID") || !strings.Contains(args[3], "NRestarts") {
				t.Fatalf("unexpected show args: %v", args)
			}
			if unit == "deployer-app1.service" {
				return []byte(fixtureShowApp1), nil
			}
			return []byte(fixtureShowApp2), nil
		default:
			t.Fatalf("unexpected systemctl subcommand: %v", args)
			return nil, nil
		}
	}

	info := CollectSystemd(run, "deployer-", nil)
	if !info.OK {
		t.Fatalf("expected OK=true, got error %q", info.Error)
	}
	if len(info.Units) != 5 {
		t.Fatalf("expected 5 inventory units, got %d", len(info.Units))
	}
	// Only the deployer-* units get the detailed show pass — nginx/ssh/journald must not.
	if !reflect.DeepEqual(showCalls, []string{"deployer-app1.service", "deployer-app2.service"}) {
		t.Fatalf("show called for %v, want only managed units", showCalls)
	}
	if len(info.Managed) != 2 {
		t.Fatalf("expected 2 managed units, got %#v", info.Managed)
	}
	if info.Managed[0].MainPID != 3412 || info.Managed[0].NRestarts != 2 {
		t.Fatalf("managed[0] = %#v", info.Managed[0])
	}
	if got := info.ManagedPIDs(); !reflect.DeepEqual(got, []int32{3412}) {
		t.Fatalf("ManagedPIDs() = %v, want [3412] (MainPID=0 excluded)", got)
	}
}

func TestCollectSystemd_ListUnitsFails(t *testing.T) {
	run := func(name string, args ...string) ([]byte, error) {
		return nil, errors.New("systemctl: command not found")
	}
	info := CollectSystemd(run, "deployer-", nil)
	if info.OK {
		t.Fatal("expected OK=false when list-units fails")
	}
	if info.Units == nil || info.Managed == nil {
		t.Fatal("expected non-nil empty slices on failure")
	}
}

func TestCollectSystemd_ShowFailureIsPartial(t *testing.T) {
	run := func(name string, args ...string) ([]byte, error) {
		switch args[0] {
		case "list-units":
			return []byte(fixtureListUnits), nil
		case "show":
			if args[1] == "deployer-app1.service" {
				return nil, errors.New("boom")
			}
			return []byte(fixtureShowApp2), nil
		}
		return nil, nil
	}
	info := CollectSystemd(run, "deployer-", nil)
	if info.OK {
		t.Fatal("expected OK=false when a show call fails")
	}
	if !strings.Contains(info.Error, "deployer-app1.service") {
		t.Fatalf("error should name the failed unit, got %q", info.Error)
	}
	// The other managed unit must still be reported (best-effort partial data).
	if len(info.Managed) != 1 || info.Managed[0].Name != "deployer-app2.service" {
		t.Fatalf("expected partial managed data for app2, got %#v", info.Managed)
	}
	if len(info.Units) != 5 {
		t.Fatalf("inventory must survive a show failure, got %d units", len(info.Units))
	}
}

func TestCollectSystemd_DefaultPrefix(t *testing.T) {
	run := func(name string, args ...string) ([]byte, error) {
		if args[0] == "list-units" {
			return []byte(fixtureListUnits), nil
		}
		return []byte(fixtureShowApp1), nil
	}
	// Empty prefix falls back to DefaultManagedPrefix ("deployer-").
	info := CollectSystemd(run, "", nil)
	if len(info.Managed) != 2 {
		t.Fatalf("expected default prefix to match 2 units, got %#v", info.Managed)
	}
}
