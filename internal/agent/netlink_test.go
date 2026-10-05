//go:build agent

package agent

import (
	"errors"
	"reflect"
	"testing"
)

// Verbatim `ethtool enp3s0` from vault.local, the host whose link sat at
// 100 Mb/s from boot without a single alarm. Kept whole because the shape is
// the point: the three link-mode blocks are multi-line continuations with no
// colon, so a per-line parser silently reads only their first row and decides
// a gigabit card tops out at 10 Mb/s.
const vaultEthtoolBase = `Settings for enp3s0:
	Supported ports: [ TP	 MII ]
	Supported link modes:   10baseT/Half 10baseT/Full
	                        100baseT/Half 100baseT/Full
	                        1000baseT/Half 1000baseT/Full
	Supported pause frame use: Symmetric Receive-only
	Supports auto-negotiation: Yes
	Supported FEC modes: Not reported
	Advertised link modes:  10baseT/Half 10baseT/Full
	                        100baseT/Half 100baseT/Full
	                        1000baseT/Half 1000baseT/Full
	Advertised pause frame use: Symmetric Receive-only
	Advertised auto-negotiation: Yes
	Advertised FEC modes: Not reported
	Link partner advertised link modes:  10baseT/Half 10baseT/Full
	                                     100baseT/Half 100baseT/Full
	                                     1000baseT/Full
	Link partner advertised pause frame use: No
	Link partner advertised auto-negotiation: Yes
	Link partner advertised FEC modes: Not reported
	Speed: 1000Mb/s
	Duplex: Full
	Auto-negotiation: on
	master-slave cfg: preferred slave
	master-slave status: slave
	Port: Twisted Pair
	PHYAD: 0
	Transceiver: external
	MDI-X: Unknown
	Supports Wake-on: pumbg
	Wake-on: d
	Link detected: yes
`

const vaultEthtoolDriver = `driver: r8169
version: 6.1.0-35-amd64
firmware-version: 
expansion-rom-version: 
bus-info: 0000:02:00.0
supports-statistics: yes
`

// Both halves say RX: 256 — the ring is already at its hardware maximum, so
// "raise the ring" is not an available answer on this card. Telling the two
// sections apart is the only way to know that.
const vaultEthtoolRing = `Ring parameters for enp3s0:
Pre-set maximums:
RX:		256
RX Mini:	n/a
RX Jumbo:	n/a
TX:		256
Current hardware settings:
RX:		256
RX Mini:	n/a
RX Jumbo:	n/a
TX:		256
TX Push:	off
`

// rx-frames: 1 with rx-usecs: 0 is one interrupt per frame. On this host that
// measured 54k interrupts per second, all on one core.
const vaultEthtoolCoalesce = `Coalesce parameters for enp3s0:
Adaptive RX: n/a  TX: n/a
stats-block-usecs: n/a

rx-usecs: 0
rx-frames: 1
rx-usecs-irq: n/a

tx-usecs: 0
tx-frames: 1
`

func TestParseEthtoolBaseReadsEveryLinkModeRow(t *testing.T) {
	var f netFacts
	parseEthtoolBase(vaultEthtoolBase, &f)

	want := []int{10, 100, 1000}
	if !reflect.DeepEqual(f.supported, want) {
		t.Fatalf("supported = %v, want %v", f.supported, want)
	}
	if !reflect.DeepEqual(f.advertised, want) {
		t.Fatalf("advertised = %v, want %v", f.advertised, want)
	}
	if !reflect.DeepEqual(f.partner, want) {
		t.Fatalf("partner = %v, want %v", f.partner, want)
	}
	if f.autoneg == nil || !*f.autoneg {
		t.Fatalf("autoneg = %v, want on", f.autoneg)
	}
}

// The incident this whole section exists for: the card advertises gigabit and
// the link came up at 100 Mb/s. Nothing is broken, no counter moves, and every
// byte-rate dashboard looks fine — only supported-vs-negotiated exposes it.
func TestMaxSpeedExposesALinkBelowTheCardsCapability(t *testing.T) {
	var f netFacts
	parseEthtoolBase(vaultEthtoolBase, &f)

	iface := NetInterface{Iface: "enp3s0", SpeedMbps: 100, Carrier: true}
	applyFacts(&iface, f)

	if iface.MaxSpeedMbps != 1000 {
		t.Fatalf("MaxSpeedMbps = %d, want 1000", iface.MaxSpeedMbps)
	}
	if iface.SpeedMbps >= iface.MaxSpeedMbps {
		t.Fatalf("fixture no longer reproduces the fault: %d >= %d",
			iface.SpeedMbps, iface.MaxSpeedMbps)
	}
}

func TestParseEthtoolRingSeparatesMaximumsFromCurrent(t *testing.T) {
	var f netFacts
	parseEthtoolRing(vaultEthtoolRing, &f)

	if f.rxRingMax != 256 || f.rxRing != 256 {
		t.Fatalf("rx ring = %d/%d, want 256/256", f.rxRing, f.rxRingMax)
	}
	if f.txRingMax != 256 || f.txRing != 256 {
		t.Fatalf("tx ring = %d/%d, want 256/256", f.txRing, f.txRingMax)
	}
}

func TestParseEthtoolCoalesceReadsOneInterruptPerFrame(t *testing.T) {
	var f netFacts
	parseEthtoolCoalesce(vaultEthtoolCoalesce, &f)

	if f.coalesce == nil {
		t.Fatal("coalesce not parsed")
	}
	if f.coalesce.RxUsecs != 0 || f.coalesce.RxFrames != 1 {
		t.Fatalf("coalesce = %+v, want rx-usecs 0 / rx-frames 1", *f.coalesce)
	}
	if f.coalesce.AdaptiveRx {
		t.Fatal("AdaptiveRx true, but the card reports n/a")
	}
}

func TestParseEthtoolDriver(t *testing.T) {
	var f netFacts
	parseEthtoolDriver(vaultEthtoolDriver, &f)

	if f.driver != "r8169" || f.busInfo != "0000:02:00.0" {
		t.Fatalf("driver = %q bus = %q", f.driver, f.busInfo)
	}
	// firmware-version is present but empty on this card: an empty value is
	// not a key/value pair, so it must stay empty rather than absorb the next
	// line's value.
	if f.firmware != "" {
		t.Fatalf("firmware = %q, want empty", f.firmware)
	}
}

func TestHexLEToIPDecodesProcNetRoute(t *testing.T) {
	// 0164A8C0 is 192.168.100.1 stored little-endian.
	if got := hexLEToIP("0164A8C0"); got != "192.168.100.1" {
		t.Fatalf("hexLEToIP = %q, want 192.168.100.1", got)
	}
	if got := hexLEToIP("nonsense"); got != "" {
		t.Fatalf("hexLEToIP(bad) = %q, want empty", got)
	}
}

func TestMatchesIfaceAcceptsMultiQueueNames(t *testing.T) {
	want := map[string]bool{"enp3s0": true}

	for _, name := range []string{"enp3s0", "enp3s0-TxRx-0", "enp3s0-rx-1"} {
		if !matchesIface(name, want) {
			t.Fatalf("%q should match", name)
		}
	}
	for _, name := range []string{"eth0", "nvme0q1", ""} {
		if matchesIface(name, want) {
			t.Fatalf("%q should not match", name)
		}
	}
}

func TestParseLinkModesIgnoresNonModeLines(t *testing.T) {
	if got := parseLinkModes("	Speed: 1000Mb/s"); len(got) != 0 {
		t.Fatalf("Speed line parsed as link modes: %v", got)
	}
	if got := parseLinkModes("	Supported ports: [ TP	 MII ]"); len(got) != 0 {
		t.Fatalf("ports line parsed as link modes: %v", got)
	}
}

func TestEthtoolAvailableFoldsAMissingBinary(t *testing.T) {
	missing := func(name string, args ...string) ([]byte, error) {
		return nil, errors.New("exec: ethtool: not found")
	}
	if ethtoolAvailable(missing) {
		t.Fatal("reported ethtool present when the binary is missing")
	}
}

// A host without ethtool still has to answer the question that matters. The
// facts degrade, the negotiated speed does not — it comes from sysfs.
func TestFactsAreOptionalForTheSpeedSignal(t *testing.T) {
	iface := NetInterface{Iface: "enp3s0", SpeedMbps: 100, Carrier: true}
	applyFacts(&iface, netFacts{})

	if iface.SpeedMbps != 100 {
		t.Fatalf("SpeedMbps = %d, want 100", iface.SpeedMbps)
	}
	if iface.MaxSpeedMbps != 0 {
		t.Fatalf("MaxSpeedMbps = %d, want 0 (unknown without ethtool)",
			iface.MaxSpeedMbps)
	}
}

func TestGroupSubnetsFindsTwoNicsOnOnePrefix(t *testing.T) {
	// vault.local exactly: the cable and the Wi-Fi card both hold an address
	// in 192.168.100.0/24, which is what lets inbound traffic migrate to
	// Wi-Fi while the return path stays on the cable.
	ifaces := []NetInterface{
		{Iface: "enp3s0", Addresses: []NetAddress{
			{CIDR: "192.168.100.100/24", Family: "inet"}}},
		{Iface: "wlan0", Addresses: []NetAddress{
			{CIDR: "192.168.100.17/24", Family: "inet"}}},
		{Iface: "wg0", Addresses: []NetAddress{
			{CIDR: "10.10.0.2/24", Family: "inet"}}},
	}

	subnets := groupSubnets(ifaces)

	var shared *NetSubnet
	for i := range subnets {
		if subnets[i].CIDR == "192.168.100.0/24" {
			shared = &subnets[i]
		}
	}
	if shared == nil {
		t.Fatalf("192.168.100.0/24 not grouped: %+v", subnets)
	}
	if !reflect.DeepEqual(shared.Ifaces, []string{"enp3s0", "wlan0"}) {
		t.Fatalf("ifaces = %v, want [enp3s0 wlan0]", shared.Ifaces)
	}
}

func TestGroupSubnetsIgnoresIPv6(t *testing.T) {
	// ARP is IPv4-only; NDP does not share the permissive default that makes
	// a shared prefix dangerous, so an IPv6 address must not raise the shape.
	ifaces := []NetInterface{
		{Iface: "enp3s0", Addresses: []NetAddress{
			{CIDR: "fe80::1/64", Family: "inet6"}}},
		{Iface: "wlan0", Addresses: []NetAddress{
			{CIDR: "fe80::2/64", Family: "inet6"}}},
	}

	if got := groupSubnets(ifaces); len(got) != 0 {
		t.Fatalf("IPv6 addresses grouped into subnets: %+v", got)
	}
}
