//go:build agent

package agent

import (
	"os/user"
	"sort"
	"strconv"
	"syscall"

	gonet "github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
)

// CollectPorts inventories listening sockets per improves.md contract C3
// (`ports` section): TCP sockets in LISTEN state plus bound UDP sockets, via
// gopsutil net.Connections("inet"). Each listener is resolved to its owning
// PID, process name (gopsutil process) and UID/username. Best-effort like the
// other collectors: it never aborts the report loop — a scan failure folds
// into PortsInfo{OK:false, Error:...}; per-listener resolution failures just
// leave the optional fields empty.
func CollectPorts() PortsInfo {
	return collectPorts(gonet.Connections, processName, uidUsername)
}

// collectPorts is the seam-injected core of CollectPorts: connection listing
// and PID/UID resolution are parameters so tests can feed canned
// ConnectionStat slices without real sockets (same pattern as docker.go's
// Runner).
func collectPorts(
	connections func(kind string) ([]gonet.ConnectionStat, error),
	nameFor func(pid int32) string,
	userFor func(uid int32) string,
) PortsInfo {
	conns, err := connections("inet")
	if err != nil {
		return PortsInfo{OK: false, Error: "net connections: " + err.Error(), Listeners: []Listener{}}
	}
	return portsFromConns(conns, nameFor, userFor)
}

// portsFromConns projects an already-fetched socket census onto the `ports`
// section. Split out from collectPorts so CollectSockets can derive both the
// ports and the connections sections from a single scan instead of walking
// every socket twice per tick.
func portsFromConns(
	conns []gonet.ConnectionStat,
	nameFor func(pid int32) string,
	userFor func(uid int32) string,
) PortsInfo {
	type key struct {
		proto string
		addr  string
		port  uint32
		pid   int32
	}
	seen := map[key]bool{}
	nameCache := map[int32]string{}
	userCache := map[int32]string{}

	listeners := make([]Listener, 0, len(conns))
	for _, c := range conns {
		var proto string
		switch {
		case c.Type == syscall.SOCK_STREAM && c.Status == "LISTEN":
			proto = "tcp"
		case c.Type == syscall.SOCK_DGRAM && c.Raddr.Port == 0:
			// A UDP socket with no remote peer is "bound/listening".
			proto = "udp"
		default:
			continue
		}

		k := key{proto: proto, addr: c.Laddr.IP, port: c.Laddr.Port, pid: c.Pid}
		if seen[k] {
			continue
		}
		seen[k] = true

		l := Listener{
			Proto: proto,
			Addr:  c.Laddr.IP,
			Port:  c.Laddr.Port,
			Pid:   c.Pid,
			UID:   -1,
		}
		if c.Pid > 0 {
			if _, ok := nameCache[c.Pid]; !ok {
				nameCache[c.Pid] = nameFor(c.Pid)
			}
			l.Process = nameCache[c.Pid]
		}
		if len(c.Uids) > 0 {
			l.UID = c.Uids[0]
			if _, ok := userCache[l.UID]; !ok {
				userCache[l.UID] = userFor(l.UID)
			}
			l.User = userCache[l.UID]
		}
		listeners = append(listeners, l)
	}

	sort.Slice(listeners, func(i, j int) bool {
		a, b := listeners[i], listeners[j]
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		if a.Proto != b.Proto {
			return a.Proto < b.Proto
		}
		if a.Addr != b.Addr {
			return a.Addr < b.Addr
		}
		return a.Pid < b.Pid
	})

	return PortsInfo{OK: true, Listeners: listeners}
}

// processName resolves a PID to its short process name, "" on any failure
// (process may have exited between the socket scan and the lookup).
func processName(pid int32) string {
	p, err := process.NewProcess(pid)
	if err != nil {
		return ""
	}
	name, err := p.Name()
	if err != nil {
		return ""
	}
	return name
}

// uidUsername resolves a numeric UID to a username, "" when unknown (e.g.
// container UIDs with no passwd entry on the host).
func uidUsername(uid int32) string {
	if uid < 0 {
		return ""
	}
	u, err := user.LookupId(strconv.Itoa(int(uid)))
	if err != nil {
		return ""
	}
	return u.Username
}

// PortPIDs returns the unique owning PIDs of the listeners, used by
// CollectProcesses' cardinality filter (port owners are always kept).
func (p PortsInfo) PortPIDs() []int32 {
	seen := map[int32]bool{}
	out := make([]int32, 0, len(p.Listeners))
	for _, l := range p.Listeners {
		if l.Pid > 0 && !seen[l.Pid] {
			seen[l.Pid] = true
			out = append(out, l.Pid)
		}
	}
	return out
}
