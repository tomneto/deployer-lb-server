//go:build agent

package agent

import (
	"reflect"
	"testing"

	"github.com/shirou/gopsutil/v3/disk"
)

func TestIsPhysicalDiskKey(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		// Whole disks, in the shapes the kernel actually reports.
		{"sda", true},
		{"vda", true},
		{"xvda", true},
		{"nvme0n1", true},
		{"mmcblk0", true},
		{"md0", true},
		// Partitions: their I/O is already counted against the whole disk.
		{"sda1", false},
		{"nvme0n1p2", false},
		{"mmcblk0p1", false},
		{"md0p1", false},
		// Device-mapper / LVM: sits on top of a physical disk, would double-count.
		{"dm-0", false},
		// Not storage anyone provisions — pure noise every 8 seconds.
		{"loop3", false},
		{"ram0", false},
		{"zram0", false},
		{"sr0", false},
		{"", false},
	}
	for _, c := range cases {
		if got := isPhysicalDiskKey(c.name); got != c.want {
			t.Errorf("isPhysicalDiskKey(%q) = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestFilterDiskDevices(t *testing.T) {
	counters := map[string]disk.IOCountersStat{
		"sda":     {ReadBytes: 100, WriteBytes: 200, ReadCount: 10, WriteCount: 20, IoTime: 999},
		"sda1":    {ReadBytes: 50, WriteBytes: 60},
		"dm-0":    {ReadBytes: 7, WriteBytes: 8},
		"loop0":   {ReadBytes: 1, WriteBytes: 2},
		"nvme0n1": {ReadBytes: 300, WriteBytes: 400, ReadCount: 30, WriteCount: 40, IoTime: 111},
	}

	got := filterDiskDevices(counters)

	// Only whole disks survive, sorted by name so consecutive reports agree.
	want := []DiskDevice{
		{Device: "nvme0n1", ReadBytes: 300, WriteBytes: 400, ReadCount: 30, WriteCount: 40, IoTimeMs: 111},
		{Device: "sda", ReadBytes: 100, WriteBytes: 200, ReadCount: 10, WriteCount: 20, IoTimeMs: 999},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("filterDiskDevices() = %+v, want %+v", got, want)
	}
}

func TestFilterDiskDevices_NoPhysicalDisksIsEmptyNotNil(t *testing.T) {
	// A container-only host whose block devices are all device-mapper: an empty
	// list with ok:true is a legitimate answer, not an error.
	got := filterDiskDevices(map[string]disk.IOCountersStat{
		"dm-0": {ReadBytes: 1},
		"dm-1": {ReadBytes: 2},
	})
	if got == nil || len(got) != 0 {
		t.Errorf("filterDiskDevices() = %+v, want empty non-nil slice", got)
	}
}
