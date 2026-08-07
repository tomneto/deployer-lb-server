//go:build agent

package agent

import (
	"regexp"
	"sort"
	"strings"

	"github.com/shirou/gopsutil/v3/disk"
)

// Whole-disk and partition name shapes, mirroring the central's
// _WHOLE_DISK_PATTERNS/_PARTITION_PATTERNS (selfApi infra.py): the two sides
// must agree on what "one disk" is, or the same host would list different
// devices depending on whether it's read locally or through an agent.
var (
	wholeDiskPatterns = []*regexp.Regexp{
		regexp.MustCompile(`^nvme\d+n\d+$`),
		regexp.MustCompile(`^mmcblk\d+$`),
		regexp.MustCompile(`^md\d+$`),
		regexp.MustCompile(`^[a-z]+$`), // sda, vda, xvda, hda, ...
	}
	// Excluded outright: pseudo/virtual devices whose I/O is already counted
	// against the physical disk underneath them (dm-*), and RAM/loop devices
	// that are not storage anyone provisions or monitors.
	ignoredDiskPrefixes = []string{"dm-", "loop", "ram", "zram", "sr", "fd"}
)

// isPhysicalDiskKey reports whether a disk.IOCounters key names a whole
// physical disk, as opposed to one of its partitions ("sda1"), a
// device-mapper/LVM volume ("dm-0") or a non-storage device ("loop3").
//
// Note "loop\d+" IS a whole-disk shape for the central (it groups partitions
// under it) but is dropped here: a squashfs/snap loopback device is pure noise
// in a "which disk is thrashing" dashboard, and the agent has no reason to ship
// dozens of them every 8 seconds.
func isPhysicalDiskKey(name string) bool {
	for _, p := range ignoredDiskPrefixes {
		if strings.HasPrefix(name, p) {
			return false
		}
	}
	for _, re := range wholeDiskPatterns {
		if re.MatchString(name) {
			return true
		}
	}
	return false
}

// filterDiskDevices is the pure core of CollectDiskIO: it keeps only whole
// physical disks and returns them sorted by device name, so consecutive
// reports list the same devices in the same order (the backend keys rates by
// device, but a stable order keeps report diffs readable).
//
// Counters are passed through verbatim — CUMULATIVE since boot. Deriving rates
// here would need state across ticks and would duplicate the derivation the
// backend already does for the local host (WS risk 3).
func filterDiskDevices(counters map[string]disk.IOCountersStat) []DiskDevice {
	out := make([]DiskDevice, 0, len(counters))
	for name, c := range counters {
		if !isPhysicalDiskKey(name) {
			continue
		}
		out = append(out, DiskDevice{
			Device:     name,
			ReadBytes:  c.ReadBytes,
			WriteBytes: c.WriteBytes,
			ReadCount:  c.ReadCount,
			WriteCount: c.WriteCount,
			IoTimeMs:   c.IoTime,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Device < out[j].Device })
	return out
}

// CollectDiskIO reports per-disk block I/O counters (report section
// `disk_io`). Same best-effort discipline as CollectServer: it never returns an
// error — a failed read folds into DiskIOInfo{OK:false, Error:…} so one bad
// syscall never costs the whole report.
//
// An empty device list with OK:true is a legitimate answer (a container-only
// host whose block devices are all device-mapper): the frontend renders an
// EmptyState for it rather than an error.
func CollectDiskIO() DiskIOInfo {
	counters, err := disk.IOCounters()
	if err != nil {
		return DiskIOInfo{OK: false, Error: "disk io counters: " + err.Error()}
	}
	return DiskIOInfo{OK: true, Devices: filterDiskDevices(counters)}
}
