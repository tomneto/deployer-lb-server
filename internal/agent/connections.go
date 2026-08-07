//go:build agent

package agent

import (
	"sort"
	"syscall"

	gonet "github.com/shirou/gopsutil/v3/net"
)

// TCP states gopsutil reports (it stringifies /proc/net/tcp's numeric state
// itself, so the agent never parses the hex codes the central's
// _read_proc_net does).
const (
	tcpListen      = "LISTEN"
	tcpEstablished = "ESTABLISHED"
	tcpTimeWait    = "TIME_WAIT"
)

// How many busiest local ports ride in the report. The point of TopPorts is
// "which service is taking the load", answerable with a handful of rows; the
// full socket list is deliberately never sent (a busy host has tens of
// thousands of sockets and this payload goes out every 8 seconds).
const maxTopPorts = 10

// classifyConnections is the pure core of CollectConnections: it turns a socket
// census into aggregate counts. Kept parameter-free of syscalls so the
// classification — the part with actual semantics — is table-testable.
//
// Direction follows the central's _classify_connections (selfApi infra.py): an
// ESTABLISHED socket whose LOCAL port is also one we LISTEN on is inbound
// (someone dialed us); every other established socket is outbound (we dialed
// out). That's the reading that makes "inbound spiked" mean something.
//
// UDP sockets are counted in Listening only (a bound UDP socket with no peer is
// the closest thing UDP has to listening); they have no established state to
// classify.
func classifyConnections(conns []gonet.ConnectionStat) ConnectionsInfo {
	listeningPorts := map[uint32]bool{}
	for _, c := range conns {
		if c.Status == tcpListen {
			listeningPorts[c.Laddr.Port] = true
		}
	}

	info := ConnectionsInfo{OK: true}
	perPort := map[uint32]uint32{}
	for _, c := range conns {
		switch {
		case c.Status == tcpListen:
			info.Listening++
		case c.Status == tcpTimeWait:
			info.TimeWait++
		case c.Status == tcpEstablished:
			info.Established++
			if listeningPorts[c.Laddr.Port] {
				info.Inbound++
				perPort[c.Laddr.Port]++
			} else {
				info.Outbound++
			}
		case c.Type == syscall.SOCK_DGRAM && c.Raddr.Port == 0:
			info.Listening++
		}
	}

	top := make([]PortCount, 0, len(perPort))
	for port, count := range perPort {
		top = append(top, PortCount{Port: port, Connections: count})
	}
	// Busiest first; port number breaks ties so the report is deterministic
	// (Go's map iteration order is not).
	sort.Slice(top, func(i, j int) bool {
		if top[i].Connections != top[j].Connections {
			return top[i].Connections > top[j].Connections
		}
		return top[i].Port < top[j].Port
	})
	if len(top) > maxTopPorts {
		top = top[:maxTopPorts]
	}
	if len(top) > 0 {
		info.TopPorts = top
	}
	return info
}

// CollectConnections reports the aggregate socket census (report section
// `connections`), the agent-side counterpart of the central's
// infra.connections_summary. Best-effort like every other collector: a failed
// scan folds into ConnectionsInfo{OK:false, Error:…}.
//
// Prefer CollectSockets when the ports section is also wanted — both derive
// from the same scan and there is no reason to walk every socket twice per tick.
func CollectConnections() ConnectionsInfo {
	conns, err := gonet.Connections("inet")
	if err != nil {
		return ConnectionsInfo{OK: false, Error: "net connections: " + err.Error()}
	}
	return classifyConnections(conns)
}

// CollectSockets derives both socket-derived sections from ONE scan of the
// host's inet sockets. The scan is the expensive part (gopsutil walks
// /proc/net/{tcp,tcp6,udp,udp6} and, for ports, the owning PIDs); the two
// projections over it are cheap.
func CollectSockets() (PortsInfo, ConnectionsInfo) {
	conns, err := gonet.Connections("inet")
	if err != nil {
		msg := "net connections: " + err.Error()
		return PortsInfo{OK: false, Error: msg, Listeners: []Listener{}},
			ConnectionsInfo{OK: false, Error: msg}
	}
	return portsFromConns(conns, processName, uidUsername), classifyConnections(conns)
}
