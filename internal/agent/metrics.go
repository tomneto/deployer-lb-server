//go:build agent

package agent

import (
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"
)

// CollectServer gathers CPU/mem/disk via gopsutil. It never returns an error
// to the caller: any partial failure is folded into ServerInfo{OK:false,
// Error:...} so a single bad syscall never aborts the report loop (agent must
// be best-effort — see pipe-improves.md §2.3 "Resiliência").
func CollectServer(mountPoints []string) ServerInfo {
	info := ServerInfo{OK: true}

	percents, err := cpu.Percent(0, false)
	counts, countErr := cpu.Counts(true)
	if err != nil {
		info.OK = false
		info.Error = appendErr(info.Error, "cpu: "+err.Error())
	} else {
		c := &CPUInfo{Cores: counts}
		if countErr == nil {
			c.Cores = counts
		}
		if len(percents) > 0 {
			c.PercentTotal = percents[0]
		}
		info.CPU = c
	}

	vm, err := mem.VirtualMemory()
	if err != nil {
		info.OK = false
		info.Error = appendErr(info.Error, "mem: "+err.Error())
	} else {
		info.Memory = &MemoryInfo{
			TotalBytes:     vm.Total,
			UsedBytes:      vm.Used,
			AvailableBytes: vm.Available,
			UsedPercent:    vm.UsedPercent,
		}
	}

	if len(mountPoints) == 0 {
		mountPoints = []string{"/"}
	}
	for _, mp := range mountPoints {
		usage, err := disk.Usage(mp)
		if err != nil {
			info.OK = false
			info.Error = appendErr(info.Error, "disk("+mp+"): "+err.Error())
			continue
		}
		info.Disks = append(info.Disks, DiskInfo{
			MountPoint:  mp,
			TotalBytes:  usage.Total,
			UsedBytes:   usage.Used,
			UsedPercent: usage.UsedPercent,
		})
	}

	return info
}

func appendErr(existing, next string) string {
	if existing == "" {
		return next
	}
	return existing + "; " + next
}
