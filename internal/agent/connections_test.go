//go:build agent

package agent

import (
	"reflect"
	"strconv"
	"syscall"
	"testing"

	gonet "github.com/shirou/gopsutil/v3/net"
)

func TestClassifyConnections_DirectionAndCounts(t *testing.T) {
	conns := []gonet.ConnectionStat{
		// We listen on 8080 and 443.
		{Type: syscall.SOCK_STREAM, Status: "LISTEN", Laddr: gonet.Addr{IP: "0.0.0.0", Port: 8080}},
		{Type: syscall.SOCK_STREAM, Status: "LISTEN", Laddr: gonet.Addr{IP: "0.0.0.0", Port: 443}},
		// Established ON a port we listen on → inbound (someone dialed us).
		{Type: syscall.SOCK_STREAM, Status: "ESTABLISHED", Laddr: gonet.Addr{IP: "10.0.0.2", Port: 8080}, Raddr: gonet.Addr{IP: "1.2.3.4", Port: 51000}},
		{Type: syscall.SOCK_STREAM, Status: "ESTABLISHED", Laddr: gonet.Addr{IP: "10.0.0.2", Port: 8080}, Raddr: gonet.Addr{IP: "1.2.3.5", Port: 51001}},
		{Type: syscall.SOCK_STREAM, Status: "ESTABLISHED", Laddr: gonet.Addr{IP: "10.0.0.2", Port: 443}, Raddr: gonet.Addr{IP: "1.2.3.6", Port: 51002}},
		// Established from an ephemeral local port → outbound (we dialed out).
		{Type: syscall.SOCK_STREAM, Status: "ESTABLISHED", Laddr: gonet.Addr{IP: "10.0.0.2", Port: 51234}, Raddr: gonet.Addr{IP: "8.8.8.8", Port: 443}},
		// TIME_WAIT counted apart: neither inbound nor outbound traffic now.
		{Type: syscall.SOCK_STREAM, Status: "TIME_WAIT", Laddr: gonet.Addr{IP: "10.0.0.2", Port: 8080}, Raddr: gonet.Addr{IP: "1.2.3.9", Port: 51003}},
		// Other TCP states are ignored entirely.
		{Type: syscall.SOCK_STREAM, Status: "SYN_SENT", Laddr: gonet.Addr{IP: "10.0.0.2", Port: 51999}},
		// Bound UDP counts as listening; a connected UDP socket does not.
		{Type: syscall.SOCK_DGRAM, Laddr: gonet.Addr{IP: "0.0.0.0", Port: 53}},
		{Type: syscall.SOCK_DGRAM, Laddr: gonet.Addr{IP: "10.0.0.2", Port: 40000}, Raddr: gonet.Addr{IP: "8.8.8.8", Port: 53}},
	}

	got := classifyConnections(conns)

	if !got.OK {
		t.Fatalf("classifyConnections().OK = false, want true")
	}
	if got.Established != 4 {
		t.Errorf("Established = %d, want 4", got.Established)
	}
	if got.Inbound != 3 {
		t.Errorf("Inbound = %d, want 3", got.Inbound)
	}
	if got.Outbound != 1 {
		t.Errorf("Outbound = %d, want 1", got.Outbound)
	}
	if got.TimeWait != 1 {
		t.Errorf("TimeWait = %d, want 1", got.TimeWait)
	}
	// 2 TCP LISTEN + 1 bound UDP.
	if got.Listening != 3 {
		t.Errorf("Listening = %d, want 3", got.Listening)
	}
	// Busiest listening port first; only inbound sockets contribute.
	want := []PortCount{{Port: 8080, Connections: 2}, {Port: 443, Connections: 1}}
	if !reflect.DeepEqual(got.TopPorts, want) {
		t.Errorf("TopPorts = %+v, want %+v", got.TopPorts, want)
	}
}

func TestClassifyConnections_TopPortsIsCapped(t *testing.T) {
	var conns []gonet.ConnectionStat
	// 20 listening ports, each with a distinct connection count, so the cap has
	// to pick the busiest and drop the rest.
	for i := 0; i < 20; i++ {
		port := uint32(9000 + i)
		conns = append(conns, gonet.ConnectionStat{
			Type: syscall.SOCK_STREAM, Status: "LISTEN", Laddr: gonet.Addr{Port: port},
		})
		for j := 0; j <= i; j++ {
			conns = append(conns, gonet.ConnectionStat{
				Type: syscall.SOCK_STREAM, Status: "ESTABLISHED",
				Laddr: gonet.Addr{Port: port}, Raddr: gonet.Addr{IP: "1.2.3.4", Port: uint32(40000 + j)},
			})
		}
	}

	got := classifyConnections(conns)

	if len(got.TopPorts) != maxTopPorts {
		t.Fatalf("len(TopPorts) = %d, want %d", len(got.TopPorts), maxTopPorts)
	}
	// Port 9019 had 20 connections — the busiest must lead.
	if got.TopPorts[0].Port != 9019 || got.TopPorts[0].Connections != 20 {
		t.Errorf("TopPorts[0] = %+v, want {9019 20}", got.TopPorts[0])
	}
	if got.Listening != 20 {
		t.Errorf("Listening = %d, want 20", got.Listening)
	}
}

func TestClassifyConnections_EmptyHostReportsOKWithoutTopPorts(t *testing.T) {
	// No sockets at all is a valid (if unusual) reading, not a failure: OK stays
	// true and TopPorts is omitted from the payload entirely.
	got := classifyConnections(nil)
	if !got.OK {
		t.Errorf("OK = false, want true")
	}
	if got.TopPorts != nil {
		t.Errorf("TopPorts = %+v, want nil", got.TopPorts)
	}
	if got.Established != 0 || got.Listening != 0 {
		t.Errorf("got %+v, want all-zero counts", got)
	}
}

func TestClassifyConnections_PeersAggregateByRemoteIP(t *testing.T) {
	conns := []gonet.ConnectionStat{
		{Type: syscall.SOCK_STREAM, Status: "LISTEN", Laddr: gonet.Addr{IP: "0.0.0.0", Port: 443}},
		{Type: syscall.SOCK_STREAM, Status: "LISTEN", Laddr: gonet.Addr{IP: "0.0.0.0", Port: 80}},
		// One busy client across both listening ports…
		{Type: syscall.SOCK_STREAM, Status: "ESTABLISHED", Laddr: gonet.Addr{Port: 443}, Raddr: gonet.Addr{IP: "1.2.3.4", Port: 51000}},
		{Type: syscall.SOCK_STREAM, Status: "ESTABLISHED", Laddr: gonet.Addr{Port: 443}, Raddr: gonet.Addr{IP: "1.2.3.4", Port: 51001}},
		{Type: syscall.SOCK_STREAM, Status: "ESTABLISHED", Laddr: gonet.Addr{Port: 80}, Raddr: gonet.Addr{IP: "1.2.3.4", Port: 51002}},
		// …a quieter one…
		{Type: syscall.SOCK_STREAM, Status: "ESTABLISHED", Laddr: gonet.Addr{Port: 443}, Raddr: gonet.Addr{IP: "5.6.7.8", Port: 40000}},
		// …and an outbound peer, which carries no local ports.
		{Type: syscall.SOCK_STREAM, Status: "ESTABLISHED", Laddr: gonet.Addr{Port: 51234}, Raddr: gonet.Addr{IP: "8.8.8.8", Port: 443}},
		// Non-established states never reach the peer list.
		{Type: syscall.SOCK_STREAM, Status: "TIME_WAIT", Laddr: gonet.Addr{Port: 443}, Raddr: gonet.Addr{IP: "9.9.9.9", Port: 41000}},
	}

	got := classifyConnections(conns).Peers

	want := []PeerCount{
		{IP: "1.2.3.4", Inbound: 3, Total: 3, Ports: []uint32{80, 443}},
		{IP: "5.6.7.8", Inbound: 1, Total: 1, Ports: []uint32{443}},
		{IP: "8.8.8.8", Outbound: 1, Total: 1},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Peers = %+v, want %+v", got, want)
	}
}

func TestClassifyConnections_PeersCappedButCountedInFull(t *testing.T) {
	conns := []gonet.ConnectionStat{
		{Type: syscall.SOCK_STREAM, Status: "LISTEN", Laddr: gonet.Addr{Port: 443}},
	}
	// More distinct peers than the cap, the busiest one last so ordering (not
	// insertion) is what decides who survives the cut.
	for i := 0; i < maxPeerEntries+30; i++ {
		count := 1
		if i == maxPeerEntries+29 {
			count = 500 // the peer hammering us
		}
		for j := 0; j < count; j++ {
			conns = append(conns, gonet.ConnectionStat{
				Type: syscall.SOCK_STREAM, Status: "ESTABLISHED",
				Laddr: gonet.Addr{Port: 443},
				Raddr: gonet.Addr{IP: "10.9." + itoa(i/256) + "." + itoa(i%256), Port: uint32(40000 + j)},
			})
		}
	}

	got := classifyConnections(conns)

	if len(got.Peers) != maxPeerEntries {
		t.Fatalf("len(Peers) = %d, want %d", len(got.Peers), maxPeerEntries)
	}
	// The count is taken before the cut: truncating first would have shown 50.
	if got.Peers[0].Total != 500 {
		t.Errorf("Peers[0] = %+v, want Total 500", got.Peers[0])
	}
}

func TestClassifyConnections_PeerPortsAreCapped(t *testing.T) {
	var conns []gonet.ConnectionStat
	// One IP landing on more listening ports than a row is allowed to show.
	for i := 0; i < maxPeerPorts+5; i++ {
		port := uint32(8000 + i)
		conns = append(conns,
			gonet.ConnectionStat{Type: syscall.SOCK_STREAM, Status: "LISTEN", Laddr: gonet.Addr{Port: port}},
			gonet.ConnectionStat{
				Type: syscall.SOCK_STREAM, Status: "ESTABLISHED",
				Laddr: gonet.Addr{Port: port}, Raddr: gonet.Addr{IP: "1.2.3.4", Port: 50000 + port},
			})
	}

	got := classifyConnections(conns).Peers

	if len(got) != 1 {
		t.Fatalf("len(Peers) = %d, want 1", len(got))
	}
	if len(got[0].Ports) != maxPeerPorts {
		t.Errorf("len(Ports) = %d, want %d", len(got[0].Ports), maxPeerPorts)
	}
	// Every socket still counts, even the ones whose port didn't make the list.
	if got[0].Total != uint32(maxPeerPorts+5) {
		t.Errorf("Total = %d, want %d", got[0].Total, maxPeerPorts+5)
	}
}

func itoa(v int) string { return strconv.Itoa(v) }
