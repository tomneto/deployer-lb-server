//go:build agent

package agent

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/shirou/gopsutil/v3/disk"
)

// filesystemsToReport decides WHICH mounted filesystems land in a report.
//
// Until this existed the agent measured only what AGENT_MOUNTS named, which
// defaults to "/" — and setup.sh never writes AGENT_MOUNTS, so in practice
// every provisioned host reported the root filesystem and nothing else. A
// second disk mounted at /db or /mnt/backup was invisible: not in server.disks
// (never asked for), not in storage.disks (that section is physical media, not
// filesystems), not in disk_io (that one is whole devices). The box had the
// disk, the agent had the data, and no consumer could see it.
//
// So: enumerate. `disk.Partitions(false)` skips pseudo filesystems (proc,
// sysfs, cgroup, overlay) and returns the real ones.
//
// AGENT_MOUNTS is still honoured, with a changed meaning — it no longer LIMITS
// the list, it only guarantees a path is covered. A path that is not itself a
// mount point resolves to the filesystem that actually holds it (longest
// matching mount point), because that is the filesystem whose free space and
// ownership govern writes there. Naming /mnt/backup when the backup disk is
// NOT mounted therefore reports the root filesystem, honestly, instead of
// inventing a mount — which is the same trap `_prepare_data_dir` guards in
// selfApi, where a bare `mkdir -p` on an unmounted path silently fills /.
func filesystemsToReport(explicit []string) []disk.PartitionStat {
	parts, err := disk.Partitions(false)
	if err != nil {
		parts = nil
	}

	byMount := make(map[string]disk.PartitionStat, len(parts)+len(explicit))
	for _, p := range parts {
		// Bind mounts and a few container runtimes surface one filesystem at
		// several paths. Keeping the first is enough: the frontend's DisksGrid
		// already merges partitions that share (total, used, fstype).
		if _, seen := byMount[p.Mountpoint]; !seen {
			byMount[p.Mountpoint] = p
		}
	}

	for _, raw := range explicit {
		mp := strings.TrimSpace(raw)
		if mp == "" {
			continue
		}
		if _, seen := byMount[mp]; seen {
			continue
		}
		if owner, ok := containingPartition(parts, mp); ok {
			if _, seen := byMount[owner.Mountpoint]; !seen {
				byMount[owner.Mountpoint] = owner
			}
			continue
		}
		// Nothing enumerated covers it (Partitions() failed entirely, or the
		// path is on something exotic). Measure it anyway, with no device: an
		// empty DiskDevice reads as "we do not know which disk this is", which
		// is what a same-disk check must see rather than a confident wrong
		// answer.
		byMount[mp] = disk.PartitionStat{Mountpoint: mp}
	}

	if len(byMount) == 0 {
		byMount["/"] = disk.PartitionStat{Mountpoint: "/"}
	}

	out := make([]disk.PartitionStat, 0, len(byMount))
	for _, p := range byMount {
		out = append(out, p)
	}
	// Stable order so two consecutive reports diff cleanly and the UI does not
	// reshuffle rows between ticks.
	sort.Slice(out, func(i, j int) bool { return out[i].Mountpoint < out[j].Mountpoint })
	return out
}

// containingPartition returns the mounted filesystem that actually holds
// `path` — the longest mount point that is a prefix of it.
func containingPartition(parts []disk.PartitionStat, path string) (disk.PartitionStat, bool) {
	best := disk.PartitionStat{}
	found := false
	for _, p := range parts {
		if !underMount(path, p.Mountpoint) {
			continue
		}
		if !found || len(p.Mountpoint) > len(best.Mountpoint) {
			best, found = p, true
		}
	}
	return best, found
}

// underMount reports whether path lives under mount. "/dbx" is NOT under
// "/db": a plain strings.HasPrefix would say it is, and that single character
// would attribute a filesystem's free space to the wrong disk.
func underMount(path, mount string) bool {
	if mount == "/" {
		return strings.HasPrefix(path, "/")
	}
	return path == mount || strings.HasPrefix(path, strings.TrimSuffix(mount, "/")+"/")
}

const sysClassBlockDir = "/sys/class/block"

// physicalDisk maps a partition's device node to the whole disk it lives on:
// "/dev/sda1" -> "sda". That mapping is the entire basis of the "do not put
// the backup on the same disk as the data" rule, which cannot be answered from
// mount points — /db and /backup are routinely two directories on one SSD.
//
// Resolution goes through sysfs rather than by trimming trailing digits:
// "nvme0n1p2" -> "nvme0n1" and "mmcblk0p1" -> "mmcblk0" both break that
// heuristic, and getting it wrong means approving a destination on the very
// disk we were asked to avoid.
//
// Returns the device path unchanged when the parent cannot be determined
// (device mapper, LVM, network mounts). That matches the local psutil
// collector's `block_name or part.device` fallback, and it degrades the right
// way: an LVM volume compares equal only to itself, so a same-disk check stays
// conservative instead of silently passing.
func physicalDisk(device string) string {
	if device == "" {
		return ""
	}
	// /dev/mapper/vg-lv and /dev/disk/by-uuid/... are symlinks to the kernel
	// name (/dev/dm-0, /dev/sda1); sysfs only knows the latter.
	resolved := device
	if r, err := filepath.EvalSymlinks(device); err == nil {
		resolved = r
	}
	base := filepath.Base(resolved)
	if base == "" || base == "." || base == "/" {
		return device
	}

	// A partition carries a "partition" attribute; its parent directory in
	// sysfs IS the whole disk.
	if _, err := os.Stat(filepath.Join(sysClassBlockDir, base, "partition")); err == nil {
		link, err := filepath.EvalSymlinks(filepath.Join(sysClassBlockDir, base))
		if err == nil {
			if parent := filepath.Base(filepath.Dir(link)); parent != "" && parent != "." {
				return parent
			}
		}
	}

	// Not a partition: a whole disk (sda, nvme0n1) or an md array (md0) is
	// already the answer.
	if _, err := os.Stat(filepath.Join(sysBlockDir, base)); err == nil {
		return base
	}
	return device
}
