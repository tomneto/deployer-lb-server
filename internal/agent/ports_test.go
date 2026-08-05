//go:build agent

package agent

import (
	"errors"
	"reflect"
	"syscall"
	"testing"

	gonet "github.com/shirou/gopsutil/v3/net"
)

func fakeConns(conns []gonet.ConnectionStat, err error) func(string) ([]gonet.ConnectionStat, error) {
	return func(kind string) ([]gonet.ConnectionStat, error) {
		if kind != "inet" {
			return nil, errors.New("unexpected kind: " + kind)
		}
		return conns, err
	}
}

func TestCollectPorts_FiltersAndResolves(t *testing.T) {
	conns := []gonet.ConnectionStat{
		// TCP LISTEN → kept.
		{Type: syscall.SOCK_STREAM, Status: "LISTEN", Laddr: gonet.Addr{IP: "0.0.0.0", Port: 8080}, Pid: 3412, Uids: []int32{0}},
		// Established TCP → dropped (not a listener).
		{Type: syscall.SOCK_STREAM, Status: "ESTABLISHED", Laddr: gonet.Addr{IP: "10.0.0.2", Port: 51234}, Raddr: gonet.Addr{IP: "1.2.3.4", Port: 443}, Pid: 3412, Uids: []int32{0}},
		// Bound UDP (no remote peer) → kept.
		{Type: syscall.SOCK_DGRAM, Laddr: gonet.Addr{IP: "0.0.0.0", Port: 53}, Pid: 99, Uids: []int32{101}},
		// Connected UDP → dropped.
		{Type: syscall.SOCK_DGRAM, Laddr: gonet.Addr{IP: "10.0.0.2", Port: 40000}, Raddr: gonet.Addr{IP: "8.8.8.8", Port: 53}, Pid: 99, Uids: []int32{101}},
		// Duplicate of the first listener (second fd, same socket) → deduplicated.
		{Type: syscall.SOCK_STREAM, Status: "LISTEN", Laddr: gonet.Addr{IP: "0.0.0.0", Port: 8080}, Pid: 3412, Uids: []int32{0}},
	}

	nameFor := func(pid int32) string {
		return map[int32]string{3412: "node", 99: "dnsmasq"}[pid]
	}
	userFor := func(uid int32) string {
		return map[int32]string{0: "root", 101: "systemd-resolve"}[uid]
	}

	info := collectPorts(fakeConns(conns, nil), nameFor, userFor)
	if !info.OK {
		t.Fatalf("expected OK=true, got error %q", info.Error)
	}

	want := []Listener{
		{Proto: "udp", Addr: "0.0.0.0", Port: 53, Pid: 99, Process: "dnsmasq", UID: 101, User: "systemd-resolve"},
		{Proto: "tcp", Addr: "0.0.0.0", Port: 8080, Pid: 3412, Process: "node", UID: 0, User: "root"},
	}
	if !reflect.DeepEqual(info.Listeners, want) {
		t.Fatalf("Listeners = %#v, want %#v", info.Listeners, want)
	}
}

func TestCollectPorts_ScanFailure(t *testing.T) {
	info := collectPorts(fakeConns(nil, errors.New("proc unreadable")), nil, nil)
	if info.OK {
		t.Fatal("expected OK=false on scan failure")
	}
	if info.Listeners == nil {
		t.Fatal("expected non-nil empty Listeners on failure")
	}
	if info.Error == "" {
		t.Fatal("expected error message on failure")
	}
}

func TestCollectPorts_UnresolvedPIDAndUID(t *testing.T) {
	conns := []gonet.ConnectionStat{
		// Pid 0 (kernel/unresolvable) and no Uids: optional fields stay empty,
		// UID reports -1 (unknown), and the listener is still present.
		{Type: syscall.SOCK_STREAM, Status: "LISTEN", Laddr: gonet.Addr{IP: "::", Port: 22}},
	}
	nameFor := func(pid int32) string { t.Fatal("must not resolve name for pid<=0"); return "" }
	userFor := func(uid int32) string { t.Fatal("must not resolve user without uids"); return "" }

	info := collectPorts(fakeConns(conns, nil), nameFor, userFor)
	if !info.OK || len(info.Listeners) != 1 {
		t.Fatalf("unexpected result: %#v", info)
	}
	l := info.Listeners[0]
	if l.Process != "" || l.User != "" || l.UID != -1 || l.Pid != 0 {
		t.Fatalf("expected empty optional fields and UID=-1, got %#v", l)
	}
}

func TestPortPIDs_Dedup(t *testing.T) {
	info := PortsInfo{OK: true, Listeners: []Listener{
		{Proto: "tcp", Port: 80, Pid: 10},
		{Proto: "tcp", Port: 443, Pid: 10},
		{Proto: "udp", Port: 53, Pid: 20},
		{Proto: "tcp", Port: 22, Pid: 0}, // unresolved → excluded
	}}
	got := info.PortPIDs()
	if !reflect.DeepEqual(got, []int32{10, 20}) {
		t.Fatalf("PortPIDs() = %v, want [10 20]", got)
	}
}
