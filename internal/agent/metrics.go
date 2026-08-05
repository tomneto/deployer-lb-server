//go:build agent

package agent

import (
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"
	gonet "github.com/shirou/gopsutil/v3/net"
)

// CollectServer gathers CPU/mem/disk via gopsutil, plus — per improves.md
// contract C3 — loadavg, uptime and per-interface network counters. The
// network counters are CUMULATIVE since boot; the backend derives rates
// between consecutive reports. It never returns an error to the caller: any
// partial failure is folded into ServerInfo{OK:false, Error:...} so a single
// bad syscall never aborts the report loop (agent must be best-effort — see
// pipe-improves.md §2.3 "Resiliência").
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

	avg, err := load.Avg()
	if err != nil {
		info.OK = false
		info.Error = appendErr(info.Error, "load: "+err.Error())
	} else {
		info.Load = &LoadInfo{Load1: avg.Load1, Load5: avg.Load5, Load15: avg.Load15}
	}

	uptime, err := host.Uptime()
	if err != nil {
		info.OK = false
		info.Error = appendErr(info.Error, "uptime: "+err.Error())
	} else {
		info.UptimeSeconds = uptime
	}

	counters, err := gonet.IOCounters(true) // pernic=true: one entry per interface
	if err != nil {
		info.OK = false
		info.Error = appendErr(info.Error, "netio: "+err.Error())
	} else {
		for _, c := range counters {
			if c.Name == "lo" { // loopback is pure noise for rate dashboards
				continue
			}
			info.Network = append(info.Network, NetIOInfo{
				Iface:       c.Name,
				BytesSent:   c.BytesSent,
				BytesRecv:   c.BytesRecv,
				PacketsSent: c.PacketsSent,
				PacketsRecv: c.PacketsRecv,
				Errin:       c.Errin,
				Errout:      c.Errout,
			})
		}
	}

	return info
}

func appendErr(existing, next string) string {
	if existing == "" {
		return next
	}
	return existing + "; " + next
}
