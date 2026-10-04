//go:build agent

package agent

import (
	"errors"
	"testing"
	"time"
)

// Trimmed from a real `smartctl --json=c -x /dev/sdb` on a WD Blue SSD. The
// two values that matter most here are deliberately kept verbatim: attribute
// 194's raw (317827579940) and 230's raw (14491437960494) are vendor-packed
// garbage, and the fixture exists mostly to prove we never read them.
const wdBlueSmartJSON = `{
  "smartctl": {"exit_status": 0},
  "device": {"name": "/dev/sdb", "type": "sat"},
  "model_name": "WDC WDS240G1G0A-00SS50",
  "serial_number": "173964801850",
  "user_capacity": {"blocks": 468860015, "bytes": 240056327680},
  "rotation_rate": 0,
  "smart_support": {"available": true, "enabled": true},
  "smart_status": {"passed": true},
  "temperature": {"current": 36},
  "power_on_time": {"hours": 26171},
  "ata_smart_attributes": {"table": [
    {"id": 5,   "name": "Reallocated_Sector_Ct", "value": 100, "raw": {"value": 0}},
    {"id": 9,   "name": "Power_On_Hours",        "value": 0,   "raw": {"value": 26171}},
    {"id": 194, "name": "Temperature_Celsius",   "value": 64,  "raw": {"value": 317827579940}},
    {"id": 199, "name": "UDMA_CRC_Error_Count",  "value": 100, "raw": {"value": 32}},
    {"id": 230, "name": "Media_Wearout_Indicator","value": 100,"raw": {"value": 14491437960494}}
  ]},
  "ata_smart_self_test_log": {"standard": {"table": [
    {"type": {"string": "Short offline"},
     "status": {"string": "Completed without error", "passed": true},
     "lifetime_hours": 26100}
  ]}}
}`

// The state vault.local was actually in on 2026-10-03: the drive supports
// SMART but it was switched off, so smartctl reports no smart_status at all.
// This is the case that must NOT look like a healthy disk.
const smartDisabledJSON = `{
  "smartctl": {"exit_status": 4},
  "device": {"name": "/dev/sda", "type": "sat"},
  "smart_support": {"available": true, "enabled": false}
}`

func TestParseSmart(t *testing.T) {
	info, err := parseSmart([]byte(wdBlueSmartJSON))
	if err != nil {
		t.Fatalf("parseSmart() error = %v, want nil", err)
	}
	if !info.Available || !info.Enabled {
		t.Errorf("available/enabled = %v/%v, want true/true", info.Available, info.Enabled)
	}
	if info.HealthPassed == nil || !*info.HealthPassed {
		t.Errorf("HealthPassed = %v, want true", info.HealthPassed)
	}
	if info.PowerOnHours == nil || *info.PowerOnHours != 26171 {
		t.Errorf("PowerOnHours = %v, want 26171", info.PowerOnHours)
	}
	// Temperature must come from the top-level `temperature.current` (36), never
	// from attribute 194, whose raw is a packed bitfield worth 317827579940.
	if info.TemperatureC == nil || *info.TemperatureC != 36 {
		t.Errorf("TemperatureC = %v, want 36 (NOT attribute 194's raw)", info.TemperatureC)
	}
	// The 32 CRC errors are the whole reason this feature exists.
	if info.Attributes.CrcErrors == nil || *info.Attributes.CrcErrors != 32 {
		t.Errorf("CrcErrors = %v, want 32", info.Attributes.CrcErrors)
	}
	if info.Attributes.Reallocated == nil || *info.Attributes.Reallocated != 0 {
		t.Errorf("Reallocated = %v, want 0", info.Attributes.Reallocated)
	}
	// This drive exposes no 197, and "absent" must stay absent: a nil here
	// becoming 0 would turn an unknown into a clean bill of health.
	if info.Attributes.Pending != nil {
		t.Errorf("Pending = %v, want nil (drive does not expose attribute 197)", *info.Attributes.Pending)
	}
	// 230's raw is garbage and 177/231 are absent, so wear stays unknown
	// rather than being invented from a vendor bitfield.
	if info.Attributes.WearPercent != nil {
		t.Errorf("WearPercent = %v, want nil (only 230 present, raw unusable)", *info.Attributes.WearPercent)
	}
	if info.LastSelfTest == nil || info.LastSelfTest.Type != "Short offline" {
		t.Fatalf("LastSelfTest = %+v, want the Short offline entry", info.LastSelfTest)
	}
	if info.LastSelfTest.Passed == nil || !*info.LastSelfTest.Passed {
		t.Errorf("LastSelfTest.Passed = %v, want true", info.LastSelfTest.Passed)
	}
}

func TestParseSmartDisabled(t *testing.T) {
	info, err := parseSmart([]byte(smartDisabledJSON))
	if err != nil {
		t.Fatalf("parseSmart() error = %v, want nil", err)
	}
	if !info.Available {
		t.Errorf("Available = false, want true (the drive supports SMART)")
	}
	if info.Enabled {
		t.Errorf("Enabled = true, want false (it was switched off)")
	}
	// No smart_status in the output: unknown health, which must stay nil and
	// never collapse to "passed".
	if info.HealthPassed != nil {
		t.Errorf("HealthPassed = %v, want nil when smart_status is absent", *info.HealthPassed)
	}
}

func TestParseSmartRejectsGarbage(t *testing.T) {
	if _, err := parseSmart([]byte("smartctl: command not found")); err == nil {
		t.Error("parseSmart(non-JSON) = nil error, want a parse error")
	}
}

func TestReadSmartIgnoresExitCode(t *testing.T) {
	// smartctl's exit status is a BITMASK: a drive with any historical
	// self-test error sets a bit while still printing perfectly good JSON.
	// Treating that as failure is how a degrading disk would go unreported.
	run := func(string, ...string) ([]byte, error) {
		return []byte(wdBlueSmartJSON), errors.New("exit status 4")
	}
	info := readSmart(run, "sdb")
	if info == nil {
		t.Fatal("readSmart() = nil despite valid JSON on stdout")
	}
	if info.Attributes.CrcErrors == nil || *info.Attributes.CrcErrors != 32 {
		t.Errorf("CrcErrors = %v, want 32", info.Attributes.CrcErrors)
	}
}

func TestReadSmartWithoutBinary(t *testing.T) {
	run := func(string, ...string) ([]byte, error) { return nil, errors.New("executable file not found") }
	if got := readSmart(run, "sda"); got != nil {
		t.Errorf("readSmart() = %+v, want nil when smartctl is absent", got)
	}
}

// The real /proc/mdstat from vault.local: a raid0 that is perfectly "active"
// and yet one dead disk away from total loss.
const mdstatRaid0 = `Personalities : [linear] [multipath] [raid0] [raid1] [raid6] [raid5] [raid4] [raid10]
md0 : active raid0 sda[0] sdb[1]
      468595712 blocks super 1.2 512k chunks

unused devices: <none>
`

const mdstatDegradedRaid1 = `Personalities : [raid1]
md1 : active raid1 sdc[0] sdd[1](F)
      976630464 blocks super 1.2 [2/1] [U_]

unused devices: <none>
`

func TestParseMdstatRaid0(t *testing.T) {
	arrays := parseMdstat(mdstatRaid0)
	if len(arrays) != 1 {
		t.Fatalf("parseMdstat() returned %d arrays, want 1", len(arrays))
	}
	a := arrays[0]
	if a.Device != "md0" || a.Level != "raid0" || a.State != "active" {
		t.Errorf("got device/level/state = %q/%q/%q, want md0/raid0/active", a.Device, a.Level, a.State)
	}
	// The point of the whole feature: active is not the same as safe.
	if a.HasRedundancy {
		t.Error("HasRedundancy = true for raid0, want false")
	}
	if a.Degraded {
		t.Error("Degraded = true, want false (raid0 prints no health markers)")
	}
	if len(a.Members) != 2 || a.Members[0].Name != "sda" || a.Members[1].Name != "sdb" {
		t.Fatalf("Members = %+v, want sda[0] and sdb[1]", a.Members)
	}
	if a.Members[1].Role != 1 {
		t.Errorf("Members[1].Role = %d, want 1", a.Members[1].Role)
	}
}

func TestParseMdstatDegradedRaid1(t *testing.T) {
	arrays := parseMdstat(mdstatDegradedRaid1)
	if len(arrays) != 1 {
		t.Fatalf("parseMdstat() returned %d arrays, want 1", len(arrays))
	}
	a := arrays[0]
	if !a.HasRedundancy {
		t.Error("HasRedundancy = false for raid1, want true")
	}
	if !a.Degraded {
		t.Error("Degraded = false, want true ([2/1] and [U_] both say so)")
	}
	if a.TotalDevices != 2 || a.ActiveDevices != 1 {
		t.Errorf("active/total = %d/%d, want 1/2", a.ActiveDevices, a.TotalDevices)
	}
	if len(a.Members) != 2 || !a.Members[1].Failed {
		t.Errorf("Members = %+v, want sdd marked failed", a.Members)
	}
}

func TestParseMdstatNoArrays(t *testing.T) {
	// A host with mdadm installed but no arrays. Must be an empty list, not a
	// phantom array parsed out of the Personalities header.
	got := parseMdstat("Personalities : [raid1] \nunused devices: <none>\n")
	if len(got) != 0 {
		t.Errorf("parseMdstat() = %+v, want no arrays", got)
	}
}

func TestParseMdMember(t *testing.T) {
	tests := []struct {
		token      string
		wantName   string
		wantRole   int
		wantFailed bool
		wantSpare  bool
		wantOK     bool
	}{
		{"sda[0]", "sda", 0, false, false, true},
		{"sdd[1](F)", "sdd", 1, true, false, true},
		{"sde[2](S)", "sde", 2, false, true, true},
		{"nvme0n1[3]", "nvme0n1", 3, false, false, true},
		{"garbage", "", 0, false, false, false},
		{"[0]", "", 0, false, false, false},
	}
	for _, tt := range tests {
		m, ok := parseMdMember(tt.token)
		if ok != tt.wantOK {
			t.Errorf("parseMdMember(%q) ok = %v, want %v", tt.token, ok, tt.wantOK)
			continue
		}
		if !ok {
			continue
		}
		if m.Name != tt.wantName || m.Role != tt.wantRole ||
			m.Failed != tt.wantFailed || m.Spare != tt.wantSpare {
			t.Errorf("parseMdMember(%q) = %+v, want %s[%d] failed=%v spare=%v",
				tt.token, m, tt.wantName, tt.wantRole, tt.wantFailed, tt.wantSpare)
		}
	}
}

func TestStorageCacheThrottles(t *testing.T) {
	// The cache IS the throttle that keeps smartctl off the disks every 8s,
	// so "how many times did we shell out" is the actual assertion.
	calls := 0
	run := func(string, ...string) ([]byte, error) {
		calls++
		return []byte(wdBlueSmartJSON), nil
	}
	// Point the sysfs walk at a directory with no block devices so the test
	// never depends on the machine running it.
	oldDir := sysBlockDir
	sysBlockDir = t.TempDir()
	defer func() { sysBlockDir = oldDir }()

	c := NewStorageCache(15 * time.Minute)
	start := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)

	first := c.Collect(run, start)
	if !first.OK {
		t.Fatalf("first Collect() OK = false, error = %q", first.Error)
	}
	if first.CollectedAt == "" {
		t.Error("CollectedAt is empty; a cached section is unreadable without its own timestamp")
	}

	// Within the TTL: same value, no new work.
	again := c.Collect(run, start.Add(8*time.Second))
	if again.CollectedAt != first.CollectedAt {
		t.Errorf("CollectedAt changed inside the TTL: %q then %q", first.CollectedAt, again.CollectedAt)
	}

	// Past the TTL: refreshed.
	later := c.Collect(run, start.Add(16*time.Minute))
	if later.CollectedAt == first.CollectedAt {
		t.Error("CollectedAt did not change after the TTL elapsed")
	}
	if calls != 0 {
		t.Errorf("smartctl ran %d times with no block devices present, want 0", calls)
	}
}
