//go:build agent

package agent

import (
	"errors"
	"testing"
	"time"
)

// Fixture matches `wg show wg0 dump` real-world format: first line is
// interface-only, subsequent lines are tab-separated peer records.
const fixtureWGDump = "priv==\tpub==\t51820\toff\n" +
	"peerA==\t(none)\t10.20.30.1:51820\t10.10.0.2/32\t1700000000\t100\t200\toff\n" +
	"peerB==\t(none)\t(none)\t10.10.0.3/32\t0\t0\t0\toff\n"

func TestParseWGDump(t *testing.T) {
	peers := ParseWGDump([]byte(fixtureWGDump))
	if len(peers) != 2 {
		t.Fatalf("expected 2 peers, got %d: %#v", len(peers), peers)
	}
	if peers[0].PubKey != "peerA==" || peers[0].AllowedIPs != "10.10.0.2/32" || peers[0].LatestHandshake != 1700000000 {
		t.Fatalf("unexpected peer[0]: %#v", peers[0])
	}
	if peers[1].PubKey != "peerB==" || peers[1].LatestHandshake != 0 {
		t.Fatalf("unexpected peer[1]: %#v", peers[1])
	}
}

func TestParseWGDump_EmptyOrHeaderOnly(t *testing.T) {
	if peers := ParseWGDump([]byte("priv==\tpub==\t51820\toff\n")); len(peers) != 0 {
		t.Fatalf("expected no peers for header-only dump, got %v", peers)
	}
	if peers := ParseWGDump([]byte("")); len(peers) != 0 {
		t.Fatalf("expected no peers for empty dump, got %v", peers)
	}
}

func TestCollectWireGuard_HandshakeAgeAndPing(t *testing.T) {
	now := time.Unix(1700000100, 0).UTC() // 100s after peerA's handshake

	run := func(name string, args ...string) ([]byte, error) {
		if name != "wg" {
			t.Fatalf("unexpected binary: %s", name)
		}
		return []byte(fixtureWGDump), nil
	}
	ping := func(host string) (float64, bool) {
		if host == "10.10.0.2" {
			return 3.5, true
		}
		return 0, false
	}

	info := CollectWireGuard(run, ping, "wg0", now)
	if !info.OK {
		t.Fatalf("expected OK=true, got error %q", info.Error)
	}
	if len(info.Peers) != 2 {
		t.Fatalf("expected 2 peers, got %d", len(info.Peers))
	}

	peerA := info.Peers[0]
	if peerA.LatestHandshakeAge != 100 {
		t.Fatalf("peerA handshake age = %d, want 100", peerA.LatestHandshakeAge)
	}
	if !peerA.PingOK || peerA.PingMS != 3.5 {
		t.Fatalf("peerA ping = %v/%v, want ok=true ms=3.5", peerA.PingOK, peerA.PingMS)
	}

	peerB := info.Peers[1]
	if peerB.LatestHandshakeAge != -1 {
		t.Fatalf("peerB (never handshaked) age = %d, want -1", peerB.LatestHandshakeAge)
	}
	if peerB.PingOK {
		t.Fatal("peerB has no allowed-ips/endpoint, expected no ping attempt to succeed")
	}
}

func TestCollectWireGuard_CommandFails(t *testing.T) {
	run := func(name string, args ...string) ([]byte, error) {
		return nil, errors.New("wg: command not found")
	}
	info := CollectWireGuard(run, nil, "wg0", time.Now())
	if info.OK {
		t.Fatal("expected OK=false when wg show fails")
	}
}

func TestParsePingRTT(t *testing.T) {
	cases := map[string]struct {
		wantMS float64
		wantOK bool
	}{
		"64 bytes from 10.10.0.2: icmp_seq=1 ttl=64 time=3.45 ms\n": {3.45, true},
		"64 bytes from 10.10.0.2: icmp_seq=1 ttl=64 time<1 ms\n":    {1, true},
		"Request timeout for icmp_seq 0\n":                          {0, false},
		"":                                                          {0, false},
	}
	for out, want := range cases {
		ms, ok := parsePingRTT(out)
		if ok != want.wantOK {
			t.Fatalf("parsePingRTT(%q) ok = %v, want %v", out, ok, want.wantOK)
		}
		if ok && ms != want.wantMS {
			t.Fatalf("parsePingRTT(%q) ms = %v, want %v", out, ms, want.wantMS)
		}
	}
}

func TestPeerPingTarget(t *testing.T) {
	cases := []struct {
		peer wgDumpPeer
		want string
	}{
		{wgDumpPeer{AllowedIPs: "10.10.0.2/32"}, "10.10.0.2"},
		{wgDumpPeer{AllowedIPs: "10.10.0.2/32,10.10.0.3/32"}, "10.10.0.2"},
		{wgDumpPeer{AllowedIPs: "(none)", Endpoint: "203.0.113.5:51820"}, "203.0.113.5"},
		{wgDumpPeer{AllowedIPs: "(none)", Endpoint: "(none)"}, ""},
	}
	for _, c := range cases {
		if got := peerPingTarget(c.peer); got != c.want {
			t.Fatalf("peerPingTarget(%#v) = %q, want %q", c.peer, got, c.want)
		}
	}
}
