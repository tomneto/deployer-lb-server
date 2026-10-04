//go:build agent

package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Where the physical-media facts are read from. Package vars rather than
// constants so a test can point them at a fixture tree — the same trick the
// Runner seam plays for external binaries.
var (
	sysBlockDir    = "/sys/block"
	procMdstatPath = "/proc/mdstat"
)

// SMART attribute IDs that carry a meaningful RAW count on every vendor.
// Anything whose raw value is a packed bitfield (194 temperature, 230 wear)
// is deliberately absent — see the SmartAttributes doc comment.
const (
	attrReallocated = 5
	attrPending     = 197
	attrCrcErrors   = 199
	attrWearLevel   = 177
	attrSSDLife     = 231
)

// StorageCache throttles the storage section to its own cadence.
//
// The report ticks every ~8s. Running `smartctl` that often is both pointless
// (power-on hours do not move in 8 seconds) and hostile: on a spun-down HDD
// every invocation can wake the platter, and SAT passthrough on a cheap USB
// bridge is slow. So the section is collected at most once per TTL and the
// last good value is re-sent verbatim in between, carrying its own
// CollectedAt so nobody mistakes it for fresh.
type StorageCache struct {
	ttl  time.Duration
	mu   sync.Mutex
	at   time.Time
	last StorageInfo
}

// NewStorageCache returns a cache that refreshes at most once per ttl. A
// non-positive ttl means "every tick", which is only sane in tests.
func NewStorageCache(ttl time.Duration) *StorageCache {
	return &StorageCache{ttl: ttl}
}

// Collect returns the storage section, refreshing it only when the TTL has
// elapsed. Never returns an error: a failure folds into StorageInfo{OK:false}
// like every other collector.
func (c *StorageCache) Collect(run Runner, now time.Time) StorageInfo {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.at.IsZero() && c.ttl > 0 && now.Sub(c.at) < c.ttl {
		return c.last
	}
	c.last = collectStorage(run, now)
	c.at = now
	return c.last
}

// collectStorage does one full pass: enumerate block devices, ask each one
// for SMART, then read the md arrays.
func collectStorage(run Runner, now time.Time) StorageInfo {
	names, err := listBlockDevices()
	if err != nil {
		return StorageInfo{OK: false, Error: "list block devices: " + err.Error()}
	}
	disks := make([]StorageDisk, 0, len(names))
	for _, name := range names {
		disks = append(disks, readDisk(run, name))
	}
	info := StorageInfo{
		OK:          true,
		CollectedAt: now.UTC().Format(time.RFC3339),
		Disks:       disks,
	}
	if raw, err := os.ReadFile(procMdstatPath); err == nil {
		info.Raid = parseMdstat(string(raw))
	}
	return info
}

// pseudoDiskPrefixes are block devices that exist in /sys/block but are not
// media anyone can ask for health about: squashfs/snap loopbacks, ramdisks,
// optical and floppy nodes, and device-mapper volumes (whose health belongs
// to the physical disk underneath).
var pseudoDiskPrefixes = []string{"loop", "ram", "zram", "sr", "fd", "dm-"}

// isSmartCandidate reports whether a /sys/block entry is a real drive worth
// asking SMART about.
//
// Deliberately NOT isPhysicalDiskKey, even though that function is right next
// door and also answers "is this a whole disk". It serves disk_io, where
// grouping I/O under "loop3" and "md0" is correct, and where its patterns are
// mirrored in selfApi's infra.py on purpose. Reusing it here put eight snap
// loopbacks and an md array into the disk inventory of a real host — nine
// rows that can never have SMART, rendering as nine "no SMART" cards.
//
// md arrays are excluded because they are reported separately under `raid`;
// listing md0 as a disk too would show the same thing twice, once with every
// health field empty.
func isSmartCandidate(name string) bool {
	for _, p := range pseudoDiskPrefixes {
		if strings.HasPrefix(name, p) {
			return false
		}
	}
	if strings.HasPrefix(name, "md") {
		return false
	}
	return isPhysicalDiskKey(name)
}

// listBlockDevices returns the real drives under /sys/block.
func listBlockDevices() ([]string, error) {
	entries, err := os.ReadDir(sysBlockDir)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if isSmartCandidate(e.Name()) {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

// readDisk assembles one disk: sysfs for the facts that are always readable,
// smartctl for the health that needs a privileged ioctl.
func readDisk(run Runner, name string) StorageDisk {
	d := StorageDisk{
		Name:   name,
		Model:  strings.TrimSpace(readSysfs(filepath.Join(sysBlockDir, name, "device", "model"))),
		Serial: strings.TrimSpace(readSysfs(filepath.Join(sysBlockDir, name, "device", "serial"))),
	}
	// /sys/block/<dev>/size is in 512-byte sectors regardless of the device's
	// own logical block size — a kernel ABI, not a property of the disk.
	if v := readSysfs(filepath.Join(sysBlockDir, name, "size")); v != "" {
		if sectors, err := strconv.ParseUint(strings.TrimSpace(v), 10, 64); err == nil {
			d.SizeBytes = sectors * 512
		}
	}
	switch strings.TrimSpace(readSysfs(filepath.Join(sysBlockDir, name, "queue", "rotational"))) {
	case "0":
		f := false
		d.Rotational = &f
	case "1":
		t := true
		d.Rotational = &t
	}
	d.Smart = readSmart(run, name)
	return d
}

// readSmart shells out to smartctl for one device.
//
// smartctl's exit code is a BITMASK, not a success flag: bit 0 means the
// command failed, but bits 2+ are set for things like "a self-test logged an
// error in the past", which still come with perfectly good JSON on stdout. So
// the exit code is ignored entirely and the parse decides — otherwise a disk
// with any historical error would silently report no SMART at all.
func readSmart(run Runner, name string) *SmartInfo {
	if run == nil {
		run = ExecRunner
	}
	out, _ := run("smartctl", "--json=c", "-x", "/dev/"+name)
	if len(out) == 0 {
		return nil
	}
	info, err := parseSmart(out)
	if err != nil {
		return nil
	}
	return info
}

// smartctlOutput mirrors only the fields the report needs. smartctl's schema
// is large, versioned, and mostly vendor trivia.
type smartctlOutput struct {
	SmartSupport *struct {
		Available bool `json:"available"`
		Enabled   bool `json:"enabled"`
	} `json:"smart_support"`
	SmartStatus *struct {
		Passed bool `json:"passed"`
	} `json:"smart_status"`
	Temperature *struct {
		Current int `json:"current"`
	} `json:"temperature"`
	PowerOnTime *struct {
		Hours uint64 `json:"hours"`
	} `json:"power_on_time"`
	AtaSmartAttributes *struct {
		Table []struct {
			ID    int    `json:"id"`
			Name  string `json:"name"`
			Value int    `json:"value"`
			Raw   struct {
				Value uint64 `json:"value"`
			} `json:"raw"`
		} `json:"table"`
	} `json:"ata_smart_attributes"`
	AtaSmartSelfTestLog *struct {
		Standard *struct {
			Table []struct {
				Type struct {
					String string `json:"string"`
				} `json:"type"`
				Status struct {
					String string `json:"string"`
					Passed *bool  `json:"passed"`
				} `json:"status"`
				LifetimeHours *uint64 `json:"lifetime_hours"`
			} `json:"table"`
		} `json:"standard"`
	} `json:"ata_smart_self_test_log"`
}

// parseSmart is the pure core of readSmart: bytes in, SmartInfo out.
func parseSmart(raw []byte) (*SmartInfo, error) {
	var o smartctlOutput
	if err := json.Unmarshal(raw, &o); err != nil {
		return nil, err
	}
	info := &SmartInfo{}
	if o.SmartSupport != nil {
		info.Available = o.SmartSupport.Available
		info.Enabled = o.SmartSupport.Enabled
	}
	// A drive that answers smart_status at all has SMART working, even on the
	// odd firmware that omits the smart_support block.
	if o.SmartStatus != nil {
		passed := o.SmartStatus.Passed
		info.HealthPassed = &passed
		info.Available = true
		info.Enabled = true
	}
	if o.PowerOnTime != nil {
		h := o.PowerOnTime.Hours
		info.PowerOnHours = &h
	}
	if o.Temperature != nil && o.Temperature.Current != 0 {
		t := o.Temperature.Current
		info.TemperatureC = &t
	}
	if o.AtaSmartAttributes != nil {
		for _, a := range o.AtaSmartAttributes.Table {
			raw := a.Raw.Value
			switch a.ID {
			case attrReallocated:
				v := raw
				info.Attributes.Reallocated = &v
			case attrPending:
				v := raw
				info.Attributes.Pending = &v
			case attrCrcErrors:
				v := raw
				info.Attributes.CrcErrors = &v
			case attrWearLevel, attrSSDLife:
				// NORMALIZED value, not raw: these count DOWN from 100 as the
				// NAND wears, and the raw side is vendor-defined. Reported as
				// "percent consumed" so bigger always means worse, matching
				// every other field here.
				if info.Attributes.WearPercent == nil && a.Value > 0 && a.Value <= 100 {
					w := 100 - a.Value
					info.Attributes.WearPercent = &w
				}
			}
		}
	}
	info.LastSelfTest = lastSelfTest(o)
	return info, nil
}

// lastSelfTest pulls the most recent self-test log entry. smartctl lists the
// log newest-first, so entry 0 is the one the UI wants after triggering a run.
func lastSelfTest(o smartctlOutput) *SmartSelfTest {
	if o.AtaSmartSelfTestLog == nil || o.AtaSmartSelfTestLog.Standard == nil {
		return nil
	}
	table := o.AtaSmartSelfTestLog.Standard.Table
	if len(table) == 0 {
		return nil
	}
	e := table[0]
	return &SmartSelfTest{
		Type:         e.Type.String,
		Status:       e.Status.String,
		Passed:       e.Status.Passed,
		PowerOnHours: e.LifetimeHours,
	}
}

// redundantLevels are the md levels where losing one member is survivable.
// Everything else — raid0, linear, and anything unrecognised — is treated as
// no redundancy, which is the safe direction to be wrong in.
var redundantLevels = map[string]bool{
	"raid1": true, "raid4": true, "raid5": true,
	"raid6": true, "raid10": true,
}

// parseMdstat is the pure core of the RAID pass. /proc/mdstat looks like:
//
//	Personalities : [raid0] [raid1]
//	md0 : active raid0 sda[0] sdb[1]
//	      468595712 blocks super 1.2 512k chunks
//	md1 : active raid1 sdc[0] sdd[1](F)
//	      976630464 blocks super 1.2 [2/1] [U_]
//
// The "[n/m]" and "[U_]" markers only appear on redundant levels, which is why
// degraded detection has to tolerate their absence rather than treat a missing
// marker as healthy-by-default.
func parseMdstat(content string) []RaidArray {
	var arrays []RaidArray
	lines := strings.Split(content, "\n")
	for i := 0; i < len(lines); i++ {
		name, rest, ok := strings.Cut(lines[i], " : ")
		name = strings.TrimSpace(name)
		if !ok || !strings.HasPrefix(name, "md") {
			continue
		}
		arr := RaidArray{Device: name}
		for _, f := range strings.Fields(rest) {
			switch {
			case f == "active" || f == "inactive":
				arr.State = f
			case strings.HasPrefix(f, "raid") || f == "linear" || f == "multipath":
				arr.Level = f
			case strings.Contains(f, "["):
				if m, ok := parseMdMember(f); ok {
					arr.Members = append(arr.Members, m)
				}
			}
		}
		arr.HasRedundancy = redundantLevels[arr.Level]
		// The detail line that follows carries the health markers.
		if i+1 < len(lines) {
			arr.ActiveDevices, arr.TotalDevices, arr.Degraded = parseMdHealth(lines[i+1])
		}
		for _, m := range arr.Members {
			if m.Failed {
				arr.Degraded = true
			}
		}
		arrays = append(arrays, arr)
	}
	return arrays
}

// parseMdMember reads one "sda[0]" / "sdd[1](F)" / "sde[2](S)" token.
func parseMdMember(token string) (RaidMember, bool) {
	name, rest, ok := strings.Cut(token, "[")
	if !ok || name == "" {
		return RaidMember{}, false
	}
	roleStr, flags, _ := strings.Cut(rest, "]")
	role, err := strconv.Atoi(roleStr)
	if err != nil {
		return RaidMember{}, false
	}
	return RaidMember{
		Name:   name,
		Role:   role,
		Failed: strings.Contains(flags, "(F)"),
		Spare:  strings.Contains(flags, "(S)"),
	}, true
}

// parseMdHealth reads the "[2/1] [U_]" markers off an array's detail line.
// Returns zeroes and not-degraded when the markers are absent, which is the
// normal case for raid0 and linear.
func parseMdHealth(line string) (active, total int, degraded bool) {
	for _, f := range strings.Fields(line) {
		if !strings.HasPrefix(f, "[") || !strings.HasSuffix(f, "]") {
			continue
		}
		inner := strings.Trim(f, "[]")
		if wanted, have, ok := strings.Cut(inner, "/"); ok {
			t, errT := strconv.Atoi(wanted)
			a, errA := strconv.Atoi(have)
			if errT == nil && errA == nil {
				total, active = t, a
				if a < t {
					degraded = true
				}
			}
			continue
		}
		// The "[UU_]" bitmap: one character per member, "_" meaning down.
		if strings.ContainsAny(inner, "U_") && !strings.ContainsAny(inner, " /") {
			if strings.Contains(inner, "_") {
				degraded = true
			}
		}
	}
	return active, total, degraded
}

// readSysfs returns a sysfs attribute's contents, or "" when it cannot be
// read. Missing attributes are routine: virtualised block devices populate
// almost none of them.
func readSysfs(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}
