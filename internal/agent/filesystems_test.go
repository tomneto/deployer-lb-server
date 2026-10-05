//go:build agent

package agent

import (
	"testing"

	"github.com/shirou/gopsutil/v3/disk"
)

func TestUnderMount(t *testing.T) {
	cases := []struct {
		path, mount string
		want        bool
	}{
		{"/db/bo-db-x", "/db", true},
		{"/db", "/db", true},
		// The whole reason this is not strings.HasPrefix: one character of
		// difference would attribute /dbx's free space to the /db disk.
		{"/dbx", "/db", false},
		{"/dbx/y", "/db", false},
		{"/anything", "/", true},
		{"/db/x", "/db/", true},
		{"/mnt/backup", "/mnt", true},
		{"/mnt", "/mnt/backup", false},
	}
	for _, c := range cases {
		if got := underMount(c.path, c.mount); got != c.want {
			t.Errorf("underMount(%q, %q) = %v, want %v", c.path, c.mount, got, c.want)
		}
	}
}

func TestContainingPartitionPicksLongestMatch(t *testing.T) {
	parts := []disk.PartitionStat{
		{Mountpoint: "/", Device: "/dev/sda1"},
		{Mountpoint: "/db", Device: "/dev/sdb1"},
	}
	got, ok := containingPartition(parts, "/db/bo-db-root")
	if !ok || got.Device != "/dev/sdb1" {
		t.Fatalf("want the /db filesystem, got %+v (ok=%v)", got, ok)
	}

	// A path on no dedicated mount belongs to root — which is exactly the
	// answer that makes an unmounted backup disk visible as "this would land
	// on /" instead of looking like it has its own device.
	got, ok = containingPartition(parts, "/mnt/backup")
	if !ok || got.Mountpoint != "/" {
		t.Fatalf("want root, got %+v (ok=%v)", got, ok)
	}
}

func TestFilesystemsToReportNeverEmpty(t *testing.T) {
	// Whatever the host looks like, a report with no filesystem at all would
	// read as "this machine has no disks" rather than as a failed reading.
	if got := filesystemsToReport(nil); len(got) == 0 {
		t.Fatal("filesystemsToReport returned nothing")
	}
}

func TestFilesystemsToReportCoversExplicitPath(t *testing.T) {
	// AGENT_MOUNTS no longer limits the list, but a path named there must
	// still be covered by something.
	got := filesystemsToReport([]string{"/definitely/not/a/mount/point"})
	if len(got) == 0 {
		t.Fatal("explicit path produced no filesystems")
	}
	covered := false
	for _, p := range got {
		if underMount("/definitely/not/a/mount/point", p.Mountpoint) {
			covered = true
		}
	}
	if !covered {
		t.Error("no reported filesystem contains the explicitly requested path")
	}
}

func TestFilesystemsToReportDeduplicatesAndSorts(t *testing.T) {
	got := filesystemsToReport([]string{"/", "/", "/"})
	seen := map[string]bool{}
	for i, p := range got {
		if seen[p.Mountpoint] {
			t.Errorf("mount point %q reported twice", p.Mountpoint)
		}
		seen[p.Mountpoint] = true
		if i > 0 && got[i-1].Mountpoint > p.Mountpoint {
			t.Errorf("not sorted: %q before %q", got[i-1].Mountpoint, p.Mountpoint)
		}
	}
}

func TestPhysicalDiskFallsBackToTheDevicePath(t *testing.T) {
	// Unknown device: returning the path unchanged keeps a same-disk check
	// conservative (it compares equal only to itself) instead of guessing.
	if got := physicalDisk("/dev/nope-not-real"); got != "/dev/nope-not-real" {
		t.Errorf("got %q, want the input back", got)
	}
	if got := physicalDisk(""); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}
