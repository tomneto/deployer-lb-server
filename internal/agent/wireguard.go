//go:build agent

package agent

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// PingFunc probes a host and reports round-trip time. It is the seam that
// lets tests avoid real ICMP traffic.
type PingFunc func(host string) (ms float64, ok bool)

// ExecPing shells out to the system `ping` (one packet, 1s timeout) — no
// special privileges/libs required, matching the "stdlib + gopsutil only"
// dependency budget (D5).
func ExecPing(host string) (float64, bool) {
	out, err := ExecRunner("ping", "-c", "1", "-W", "1", host)
	if err != nil {
		return 0, false
	}
	return parsePingRTT(string(out))
}

var pingRTTRe = regexp.MustCompile(`time[=<]([0-9.]+)\s*ms`)

func parsePingRTT(out string) (float64, bool) {
	m := pingRTTRe.FindStringSubmatch(out)
	if m == nil {
		return 0, false
	}
	v, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// wgDumpPeer is one parsed line of `wg show <iface> dump` (peer lines only —
// the first line of the dump is interface-only and is skipped).
type wgDumpPeer struct {
	PubKey          string
	Endpoint        string
	AllowedIPs      string
	LatestHandshake int64
}

// ParseWGDump parses the tab-separated output of `wg show <iface> dump`.
// Format per peer line: pubkey, preshared-key, endpoint, allowed-ips,
// latest-handshake, transfer-rx, transfer-tx, persistent-keepalive. The
// interface-only first line (private-key, public-key, listen-port, fwmark)
// is skipped.
func ParseWGDump(out []byte) []wgDumpPeer {
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) <= 1 {
		return nil
	}
	peers := make([]wgDumpPeer, 0, len(lines)-1)
	for _, line := range lines[1:] {
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 5 {
			continue
		}
		hs, _ := strconv.ParseInt(f[4], 10, 64)
		peers = append(peers, wgDumpPeer{
			PubKey:          f[0],
			Endpoint:        f[2],
			AllowedIPs:      f[3],
			LatestHandshake: hs,
		})
	}
	return peers
}

// peerPingTarget resolves the address to ping for a peer: prefer the first
// allowed-ip (strip the /mask), fall back to the endpoint host.
func peerPingTarget(p wgDumpPeer) string {
	if p.AllowedIPs != "" && p.AllowedIPs != "(none)" {
		first := strings.Split(p.AllowedIPs, ",")[0]
		return strings.Split(strings.TrimSpace(first), "/")[0]
	}
	if p.Endpoint != "" && p.Endpoint != "(none)" {
		if idx := strings.LastIndex(p.Endpoint, ":"); idx > 0 {
			return p.Endpoint[:idx]
		}
		return p.Endpoint
	}
	return ""
}

// CollectWireGuard runs `wg show <iface> dump`, computes handshake age for
// each peer and pings it (D21: feeds the "wireguard" continuous check).
// Never returns an error to the caller — a missing wg-tools install or a
// down interface folds into WGInfo{OK:false}, it never aborts the report.
func CollectWireGuard(run Runner, ping PingFunc, iface string, now time.Time) WGInfo {
	if run == nil {
		run = ExecRunner
	}
	if ping == nil {
		ping = ExecPing
	}
	if iface == "" {
		iface = "wg0"
	}

	out, err := run("wg", "show", iface, "dump")
	if err != nil {
		return WGInfo{OK: false, Error: fmt.Sprintf("wg show %s dump: %v", iface, err), Peers: []WGPeer{}}
	}

	dumped := ParseWGDump(out)
	peers := make([]WGPeer, 0, len(dumped))
	for _, d := range dumped {
		age := int64(-1)
		if d.LatestHandshake > 0 {
			age = now.Unix() - d.LatestHandshake
			if age < 0 {
				age = 0
			}
		}
		peer := WGPeer{
			PubKey:             d.PubKey,
			Endpoint:           d.Endpoint,
			LatestHandshakeAge: age,
		}
		if target := peerPingTarget(d); target != "" {
			if ms, ok := ping(target); ok {
				peer.PingMS = ms
				peer.PingOK = true
			}
		}
		peers = append(peers, peer)
	}

	return WGInfo{OK: true, Peers: peers}
}
