//go:build agent

package agent

import (
	"fmt"
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

// How many established sockets ride in ConnectionsInfo.Conns — same
// reasoning as maxTopPorts: the frontend only ever renders a handful of rows.
const maxConnEntries = 50

// How many remote IPs ride in ConnectionsInfo.Peers. Wider than maxConnEntries
// because this list is the point of the network screen ("quais IPs estão
// conectados") and one row per IP is far cheaper than one row per socket: a
// host being scanned or fronted by a CDN has thousands of sockets across a few
// dozen addresses. Counts are computed over EVERY socket before this cut, so
// the rows that do ship carry true totals.
const maxPeerEntries = 100

// Local ports listed per peer. Enough to tell "this IP is on 443 and 80" from
// "this IP is crawling every port", without turning one row into a port dump.
const maxPeerPorts = 6

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
	perPeer := map[string]*PeerCount{}
	peerPorts := map[string]map[uint32]bool{}
	var entries []ConnEntry
	for _, c := range conns {
		switch {
		case c.Status == tcpListen:
			info.Listening++
		case c.Status == tcpTimeWait:
			info.TimeWait++
		case c.Status == tcpEstablished:
			info.Established++
			direction := "outbound"
			if listeningPorts[c.Laddr.Port] {
				info.Inbound++
				perPort[c.Laddr.Port]++
				direction = "inbound"
			} else {
				info.Outbound++
			}
			entries = append(entries, ConnEntry{
				Direction: direction,
				Remote:    fmt.Sprintf("%s:%d", c.Raddr.IP, c.Raddr.Port),
				Local:     fmt.Sprintf("%s:%d", c.Laddr.IP, c.Laddr.Port),
			})
			// Aggregate by remote IP over every socket, before any cut.
			if ip := c.Raddr.IP; ip != "" {
				peer := perPeer[ip]
				if peer == nil {
					peer = &PeerCount{IP: ip}
					perPeer[ip] = peer
					peerPorts[ip] = map[uint32]bool{}
				}
				peer.Total++
				if direction == "inbound" {
					peer.Inbound++
					peerPorts[ip][c.Laddr.Port] = true
				} else {
					peer.Outbound++
				}
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

	peers := make([]PeerCount, 0, len(perPeer))
	for ip, p := range perPeer {
		ports := make([]uint32, 0, len(peerPorts[ip]))
		for port := range peerPorts[ip] {
			ports = append(ports, port)
		}
		sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
		if len(ports) > maxPeerPorts {
			ports = ports[:maxPeerPorts]
		}
		entry := *p
		if len(ports) > 0 {
			entry.Ports = ports
		}
		peers = append(peers, entry)
	}
	// Busiest peer first; IP breaks ties so the report is deterministic.
	sort.Slice(peers, func(i, j int) bool {
		if peers[i].Total != peers[j].Total {
			return peers[i].Total > peers[j].Total
		}
		return peers[i].IP < peers[j].IP
	})
	if len(peers) > maxPeerEntries {
		peers = peers[:maxPeerEntries]
	}
	if len(peers) > 0 {
		info.Peers = peers
	}

	// Deterministic order (remote endpoint), same reasoning as TopPorts.
	sort.Slice(entries, func(i, j int) bool { return entries[i].Remote < entries[j].Remote })
	if len(entries) > maxConnEntries {
		entries = entries[:maxConnEntries]
	}
	if len(entries) > 0 {
		info.Conns = entries
	}
	return info
}

// connCountsByPid tallies established sockets per owning PID from the same
// socket census classifyConnections uses, so CollectProcesses can fill
// ProcInfo.Connections without a second /proc/net scan.
func connCountsByPid(conns []gonet.ConnectionStat) map[int32]int {
	counts := map[int32]int{}
	for _, c := range conns {
		if c.Status == tcpEstablished && c.Pid > 0 {
			counts[c.Pid]++
		}
	}
	return counts
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

// CollectSockets derives all socket-derived sections from ONE scan of the
// host's inet sockets. The scan is the expensive part (gopsutil walks
// /proc/net/{tcp,tcp6,udp,udp6} and, for ports, the owning PIDs); the
// projections over it are cheap. pidConns is per-PID established-connection
// counts, folded into ProcInfo.Connections by CollectProcesses.
func CollectSockets() (PortsInfo, ConnectionsInfo, map[int32]int) {
	conns, err := gonet.Connections("inet")
	if err != nil {
		msg := "net connections: " + err.Error()
		return PortsInfo{OK: false, Error: msg, Listeners: []Listener{}},
			ConnectionsInfo{OK: false, Error: msg},
			nil
	}
	return portsFromConns(conns, processName, uidUsername), classifyConnections(conns), connCountsByPid(conns)
}
