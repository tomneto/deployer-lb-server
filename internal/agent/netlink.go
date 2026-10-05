//go:build agent

package agent

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Where the link facts are read from. Package vars rather than constants so a
// test can point them at a fixture tree — the same trick storage.go plays.
var (
	sysClassNet     = "/sys/class/net"
	procNetRoute    = "/proc/net/route"
	procNetArp      = "/proc/net/arp"
	procNetSnmp     = "/proc/net/snmp"
	procNetNetstat  = "/proc/net/netstat"
	procSoftnetStat = "/proc/net/softnet_stat"
	procInterrupts  = "/proc/interrupts"
	procSysNet      = "/proc/sys/net"
	procBootID      = "/proc/sys/kernel/random/boot_id"
)

// Counters every mainline driver exports through sysfs. Read from
// /sys/class/net/<if>/statistics, which is universal — unlike `ethtool -S`,
// whose key names are per-driver and whose absence must therefore read as
// unknown rather than as zero errors.
var sysfsStatNames = []string{
	"rx_errors", "rx_dropped", "rx_crc_errors", "rx_fifo_errors",
	"rx_missed_errors", "rx_length_errors", "rx_over_errors",
	"tx_errors", "tx_dropped", "tx_carrier_errors", "tx_fifo_errors",
	"collisions",
}

// Virtual interface prefixes that get the cheap treatment. A host running
// forty containers has forty veths; asking ethtool about each one would double
// the report and bury the two interfaces anyone cares about.
var virtualIfacePrefixes = []string{"veth", "br-", "docker", "virbr", "tap", "tun", "lo"}

// The only ethtool invocations this agent makes. Every one of them reads;
// none of them writes. -s/-G/-C/-L are absent on purpose and must stay absent:
// the agent is a sensor, and a sensor that can retune a link is a control
// plane with no authorization story. Changing a NIC goes through SSH, where
// there is an operator, an audit row and a revert.
var ethtoolReadFlags = map[string]bool{
	"":   true,
	"-i": true,
	"-k": true,
	"-l": true,
	"-g": true,
	"-c": true,
	"-S": true,
}

// NetLinkCache throttles the expensive half of the section.
//
// Counters are re-read every tick; facts (ethtool) only once per TTL, and the
// last good facts are carried forward verbatim with their own FactsAt so
// nobody mistakes a five-minute-old driver string for a fresh one.
type NetLinkCache struct {
	ttl   time.Duration
	mu    sync.Mutex
	at    time.Time
	facts map[string]netFacts
	ethOK bool
}

type netFacts struct {
	driver     string
	driverVer  string
	firmware   string
	busInfo    string
	supported  []int
	advertised []int
	partner    []int
	autoneg    *bool
	queues     int
	rxRing     int
	rxRingMax  int
	txRing     int
	txRingMax  int
	coalesce   *NetCoalesce
}

func NewNetLinkCache(ttl time.Duration) *NetLinkCache {
	return &NetLinkCache{ttl: ttl, facts: map[string]netFacts{}}
}

// Collect returns the link section. Never returns an error: a failure folds
// into NetLinkInfo{OK:false} like every other collector, because one unreadable
// file must not cost the whole report.
func (c *NetLinkCache) Collect(run Runner, now time.Time) NetLinkInfo {
	c.mu.Lock()
	defer c.mu.Unlock()

	names, err := listNetInterfaces()
	if err != nil {
		return NetLinkInfo{OK: false, Error: "list interfaces: " + err.Error()}
	}

	refreshFacts := c.at.IsZero() || c.ttl <= 0 || now.Sub(c.at) >= c.ttl
	if refreshFacts {
		c.ethOK = ethtoolAvailable(run)
		fresh := map[string]netFacts{}
		for _, name := range names {
			if c.ethOK && !isVirtualIface(name) {
				fresh[name] = readEthtoolFacts(run, name)
			}
		}
		c.facts = fresh
		c.at = now
	}

	info := NetLinkInfo{
		OK:             true,
		CountersAt:     now.UTC().Format(time.RFC3339),
		FactsAt:        c.at.UTC().Format(time.RFC3339),
		EthtoolPresent: c.ethOK,
		BootID:         strings.TrimSpace(readSysfs(procBootID)),
	}

	addrsByIface := interfaceAddresses()
	for _, name := range names {
		iface := readInterface(name, addrsByIface[name], isVirtualIface(name))
		if f, ok := c.facts[name]; ok {
			applyFacts(&iface, f)
		}
		info.Interfaces = append(info.Interfaces, iface)
	}

	info.Subnets = groupSubnets(info.Interfaces)
	info.DefaultRoutes = readDefaultRoutes()
	info.Neighbors = readNeighbors(info.DefaultRoutes)
	info.Nstat = readNstat()
	info.Softnet = readSoftnet()
	info.IRQs = readNetIRQs(names)
	info.IRQBalance = readIRQBalance(run)
	return info
}

func listNetInterfaces() ([]string, error) {
	entries, err := os.ReadDir(sysClassNet)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.Name() != "lo" {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

func isVirtualIface(name string) bool {
	for _, p := range virtualIfacePrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// classifyIface names the interface kind from what sysfs exposes, not from the
// name: `wireless/` only exists on a Wi-Fi device and `tun_flags` only on a
// tun/tap, which beats guessing from a prefix that a distro may rename.
func classifyIface(name string) string {
	base := filepath.Join(sysClassNet, name)
	if _, err := os.Stat(filepath.Join(base, "wireless")); err == nil {
		return "wifi"
	}
	if _, err := os.Stat(filepath.Join(base, "bridge")); err == nil {
		return "bridge"
	}
	if _, err := os.Stat(filepath.Join(base, "tun_flags")); err == nil {
		return "tun"
	}
	if strings.HasPrefix(name, "veth") {
		return "veth"
	}
	if strings.HasPrefix(name, "wg") {
		return "wireguard"
	}
	if _, err := os.Stat(filepath.Join(base, "device")); err == nil {
		return "ethernet"
	}
	return "virtual"
}

// readInterface reads one NIC. A virtual device (veth, bridge, docker) gets
// only the cheap half: a host running forty containers has forty veths whose
// error counters nobody will ever look at, and shipping all of them buries the
// two interfaces that carry real traffic. Its addresses are still collected —
// subnet grouping needs them.
func readInterface(name string, addrs []NetAddress, virtual bool) NetInterface {
	base := filepath.Join(sysClassNet, name)
	iface := NetInterface{
		Iface:     name,
		Kind:      classifyIface(name),
		OperSt:    strings.TrimSpace(readSysfs(filepath.Join(base, "operstate"))),
		MAC:       strings.TrimSpace(readSysfs(filepath.Join(base, "address"))),
		SpeedMbps: -1,
		Addresses: addrs,
	}
	iface.Carrier = strings.TrimSpace(readSysfs(filepath.Join(base, "carrier"))) == "1"
	if mtu, err := strconv.Atoi(strings.TrimSpace(readSysfs(filepath.Join(base, "mtu")))); err == nil {
		iface.MTU = mtu
	}
	// Only a carrying interface has a negotiated speed. Reading it while down
	// yields EINVAL or -1; either way it is unknown, and unknown is not zero.
	if iface.Carrier {
		if v, err := strconv.Atoi(strings.TrimSpace(readSysfs(filepath.Join(base, "speed")))); err == nil {
			iface.SpeedMbps = v
		}
		if d := strings.TrimSpace(readSysfs(filepath.Join(base, "duplex"))); d != "" && d != "unknown" {
			iface.Duplex = d
		}
	}
	if link, err := os.Readlink(filepath.Join(base, "device", "driver")); err == nil {
		iface.Driver = filepath.Base(link)
	}
	if !virtual {
		iface.Stats = readIfaceStats(base)
	}
	return iface
}

func readIfaceStats(base string) map[string]uint64 {
	stats := map[string]uint64{}
	for _, key := range sysfsStatNames {
		raw := strings.TrimSpace(readSysfs(filepath.Join(base, "statistics", key)))
		if raw == "" {
			continue
		}
		// Zeros are shipped deliberately. These counters are only readable as
		// a delta against the previous report, so dropping a zero would strip
		// the baseline that the first error has to be measured from: a counter
		// going 0 -> 5 would arrive with no "before", the tick would be
		// skipped, and a fault that does not repeat would never be seen at
		// all. Size is paid back by skipping virtual interfaces instead.
		if v, err := strconv.ParseUint(raw, 10, 64); err == nil {
			stats[key] = v
		}
	}
	if len(stats) == 0 {
		return nil
	}
	return stats
}

// interfaceAddresses uses the stdlib rather than shelling out to `ip`: the
// addresses are the one fact here that needs no external binary, and a host
// without iproute2 still has to report which NICs share a subnet.
func interfaceAddresses() map[string][]NetAddress {
	out := map[string][]NetAddress{}
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			family := "inet6"
			if ipnet.IP.To4() != nil {
				family = "inet"
			}
			out[i.Name] = append(out[i.Name], NetAddress{
				CIDR: ipnet.String(), Family: family,
			})
		}
	}
	return out
}

// groupSubnets buckets IPv4 interfaces by the prefix they sit on and attaches
// the three sysctls that decide whether sharing a prefix is harmless or is the
// silent-failover trap. Only IPv4: ARP is an IPv4 protocol, and the IPv6
// equivalent (NDP) does not have the same default-permissive behaviour.
func groupSubnets(ifaces []NetInterface) []NetSubnet {
	byPrefix := map[string][]string{}
	for _, i := range ifaces {
		for _, a := range i.Addresses {
			if a.Family != "inet" {
				continue
			}
			_, ipnet, err := net.ParseCIDR(a.CIDR)
			if err != nil {
				continue
			}
			p := ipnet.String()
			byPrefix[p] = append(byPrefix[p], i.Iface)
		}
	}
	prefixes := make([]string, 0, len(byPrefix))
	for p := range byPrefix {
		prefixes = append(prefixes, p)
	}
	sort.Strings(prefixes)

	out := make([]NetSubnet, 0, len(prefixes))
	for _, p := range prefixes {
		members := dedupeSorted(byPrefix[p])
		sub := NetSubnet{CIDR: p, Ifaces: members}
		// Only worth the sysctl reads when more than one NIC shares the
		// prefix: with a single member there is no flux to describe.
		if len(members) > 1 {
			sub.ArpIgnore = readConfSysctls("arp_ignore", members)
			sub.ArpAnnounce = readConfSysctls("arp_announce", members)
			sub.RpFilter = readConfSysctls("rp_filter", members)
		}
		out = append(out, sub)
	}
	return out
}

func dedupeSorted(in []string) []string {
	sort.Strings(in)
	out := in[:0:0]
	for i, v := range in {
		if i == 0 || v != in[i-1] {
			out = append(out, v)
		}
	}
	return out
}

// readConfSysctls reads net.ipv4.conf.<scope>.<key> for "all" plus each
// interface. "all" matters as much as the per-interface value because the
// kernel takes the max of the two for arp_ignore.
func readConfSysctls(key string, ifaces []string) map[string]int {
	out := map[string]int{}
	scopes := append([]string{"all"}, ifaces...)
	for _, scope := range scopes {
		raw := strings.TrimSpace(readSysfs(filepath.Join(procSysNet, "ipv4", "conf", scope, key)))
		if raw == "" {
			continue
		}
		if v, err := strconv.Atoi(raw); err == nil {
			out[scope] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// readDefaultRoutes parses /proc/net/route for IPv4 default routes. More than
// one, on different interfaces, is how traffic ends up leaving by a path
// nobody chose.
func readDefaultRoutes() []NetRoute {
	f, err := os.Open(procNetRoute)
	if err != nil {
		return nil
	}
	defer f.Close()

	var out []NetRoute
	sc := bufio.NewScanner(f)
	for first := true; sc.Scan(); first = false {
		if first {
			continue // header
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 7 || fields[1] != "00000000" {
			continue
		}
		metric, _ := strconv.Atoi(fields[6])
		out = append(out, NetRoute{
			Iface:   fields[0],
			Gateway: hexLEToIP(fields[2]),
			Metric:  metric,
		})
	}
	return out
}

// hexLEToIP decodes the little-endian hex IPv4 that /proc/net/route uses.
func hexLEToIP(h string) string {
	v, err := strconv.ParseUint(h, 16, 32)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d", v&0xff, (v>>8)&0xff, (v>>16)&0xff, (v>>24)&0xff)
}

func readNeighbors(routes []NetRoute) []NetNeighbor {
	gateways := map[string]bool{}
	for _, r := range routes {
		if r.Gateway != "" {
			gateways[r.Gateway] = true
		}
	}
	f, err := os.Open(procNetArp)
	if err != nil {
		return nil
	}
	defer f.Close()

	var out []NetNeighbor
	sc := bufio.NewScanner(f)
	for first := true; sc.Scan(); first = false {
		if first {
			continue
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 6 {
			continue
		}
		out = append(out, NetNeighbor{
			IP:        fields[0],
			MAC:       fields[3],
			Iface:     fields[5],
			IsGateway: gateways[fields[0]],
		})
	}
	return out
}

// Counters lifted from /proc/net/snmp and /proc/net/netstat. The key names
// match what `nstat` prints so an operator recognises them, but nstat itself
// is never invoked: without -az it rewrites its own history file and zeroes
// the counters for every other consumer on the machine.
var nstatWanted = map[string]bool{
	"Udp.RcvbufErrors": true, "Udp.SndbufErrors": true, "Udp.InErrors": true,
	"Udp.NoPorts": true, "Udp.InDatagrams": true,
	"Tcp.RetransSegs": true, "Tcp.OutSegs": true, "Tcp.InSegs": true,
	"Ip.InDiscards": true, "Ip.InReceives": true,
	"TcpExt.TCPBacklogDrop": true, "TcpExt.ListenDrops": true,
	"TcpExt.TCPRcvQDrop": true, "TcpExt.RcvPruned": true,
}

func readNstat() map[string]uint64 {
	out := map[string]uint64{}
	for _, path := range []string{procNetSnmp, procNetNetstat} {
		mergeNstatFile(path, out)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// mergeNstatFile reads the paired-line format both files use: a header line of
// names prefixed by the protocol, then a value line with the same prefix.
func mergeNstatFile(path string, out map[string]uint64) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var header []string
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			header = nil
			continue
		}
		if header == nil || fields[0] != header[0] {
			header = fields
			continue
		}
		proto := strings.TrimSuffix(fields[0], ":")
		for i := 1; i < len(fields) && i < len(header); i++ {
			key := proto + "." + header[i]
			if !nstatWanted[key] {
				continue
			}
			if v, err := strconv.ParseUint(fields[i], 10, 64); err == nil {
				out[strings.ReplaceAll(key, ".", "")] = v
			}
		}
		header = nil
	}
}

func readSoftnet() []NetSoftnetCPU {
	f, err := os.Open(procSoftnetStat)
	if err != nil {
		return nil
	}
	defer f.Close()

	var out []NetSoftnetCPU
	sc := bufio.NewScanner(f)
	for cpu := 0; sc.Scan(); cpu++ {
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 {
			continue
		}
		row := NetSoftnetCPU{CPU: cpu}
		row.Processed, _ = strconv.ParseUint(fields[0], 16, 64)
		row.Dropped, _ = strconv.ParseUint(fields[1], 16, 64)
		row.TimeSqueeze, _ = strconv.ParseUint(fields[2], 16, 64)
		out = append(out, row)
	}
	return out
}

// readNetIRQs keeps only the lines whose trailing name matches one of this
// host's interfaces. The rest of /proc/interrupts is noise for this section,
// and shipping all of it would dwarf everything else in the report.
func readNetIRQs(ifaces []string) []NetIRQ {
	f, err := os.Open(procInterrupts)
	if err != nil {
		return nil
	}
	defer f.Close()

	want := map[string]bool{}
	for _, n := range ifaces {
		want[n] = true
	}

	var out []NetIRQ
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for first := true; sc.Scan(); first = false {
		if first {
			continue // CPU header
		}
		line := sc.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.HasSuffix(fields[0], ":") {
			continue
		}
		name := strings.TrimSpace(fields[len(fields)-1])
		if !matchesIface(name, want) {
			continue
		}
		row := NetIRQ{IRQ: strings.TrimSuffix(fields[0], ":"), Name: name}
		for _, f := range fields[1:] {
			v, err := strconv.ParseUint(f, 10, 64)
			if err != nil {
				break // first non-numeric column ends the per-CPU counts
			}
			row.CountsPerCPU = append(row.CountsPerCPU, v)
			row.Total += v
		}
		out = append(out, row)
	}
	return out
}

// matchesIface accepts both the bare interface name and the multi-queue forms
// drivers use (`eth0-TxRx-0`, `enp3s0-rx-1`).
func matchesIface(name string, want map[string]bool) bool {
	if want[name] {
		return true
	}
	if i := strings.IndexByte(name, '-'); i > 0 {
		return want[name[:i]]
	}
	return false
}

func readIRQBalance(run Runner) *NetIRQBalance {
	out, err := run("systemctl", "is-active", "irqbalance")
	if err != nil && len(out) == 0 {
		return nil
	}
	state := strings.TrimSpace(string(out))
	if state == "" || state == "unknown" {
		return &NetIRQBalance{Present: false}
	}
	return &NetIRQBalance{Present: true, Active: state == "active"}
}

func ethtoolAvailable(run Runner) bool {
	_, err := run("ethtool", "--version")
	return err == nil
}

func readEthtoolFacts(run Runner, iface string) netFacts {
	var f netFacts
	if out, err := run("ethtool", iface); err == nil {
		parseEthtoolBase(string(out), &f)
	}
	if out, err := run("ethtool", "-i", iface); err == nil {
		parseEthtoolDriver(string(out), &f)
	}
	if out, err := run("ethtool", "-g", iface); err == nil {
		parseEthtoolRing(string(out), &f)
	}
	if out, err := run("ethtool", "-l", iface); err == nil {
		parseEthtoolChannels(string(out), &f)
	}
	if out, err := run("ethtool", "-c", iface); err == nil {
		parseEthtoolCoalesce(string(out), &f)
	}
	return f
}

func applyFacts(iface *NetInterface, f netFacts) {
	iface.Driver = firstNonEmpty(f.driver, iface.Driver)
	iface.DriverVer = f.driverVer
	iface.Firmware = f.firmware
	iface.BusInfo = f.busInfo
	iface.SupportedSpeedsMbps = f.supported
	iface.AdvertisedSpeedsMbps = f.advertised
	iface.PartnerSpeedsMbps = f.partner
	iface.AutoNeg = f.autoneg
	iface.CombinedQueues = f.queues
	iface.RxRing, iface.RxRingMax = f.rxRing, f.rxRingMax
	iface.TxRing, iface.TxRingMax = f.txRing, f.txRingMax
	iface.Coalesce = f.coalesce
	for _, s := range f.supported {
		if s > iface.MaxSpeedMbps {
			iface.MaxSpeedMbps = s
		}
	}
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// parseEthtoolBase pulls the link-mode blocks out of plain `ethtool <if>`.
// The three blocks are multi-line and continue until the next "Key:" line,
// which is why this tracks the current block rather than matching per line.
func parseEthtoolBase(out string, f *netFacts) {
	block := ""
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "Supported link modes:"):
			block = "supported"
		case strings.HasPrefix(trimmed, "Advertised link modes:"):
			block = "advertised"
		case strings.HasPrefix(trimmed, "Link partner advertised link modes:"):
			block = "partner"
		case strings.HasPrefix(trimmed, "Auto-negotiation:"):
			on := strings.Contains(trimmed, "on")
			f.autoneg = &on
			block = ""
		case strings.Contains(trimmed, ":"):
			block = ""
		}
		speeds := parseLinkModes(trimmed)
		if len(speeds) == 0 {
			continue
		}
		switch block {
		case "supported":
			f.supported = mergeSpeeds(f.supported, speeds)
		case "advertised":
			f.advertised = mergeSpeeds(f.advertised, speeds)
		case "partner":
			f.partner = mergeSpeeds(f.partner, speeds)
		}
	}
}

// parseLinkModes turns "1000baseT/Full 100baseT/Half" into [1000, 100].
func parseLinkModes(line string) []int {
	if i := strings.Index(line, ":"); i >= 0 {
		line = line[i+1:]
	}
	var out []int
	for _, token := range strings.Fields(line) {
		i := strings.Index(token, "base")
		if i <= 0 {
			continue
		}
		if v, err := strconv.Atoi(token[:i]); err == nil {
			out = append(out, v)
		}
	}
	return out
}

func mergeSpeeds(existing, extra []int) []int {
	seen := map[int]bool{}
	for _, v := range existing {
		seen[v] = true
	}
	for _, v := range extra {
		if !seen[v] {
			existing = append(existing, v)
			seen[v] = true
		}
	}
	sort.Ints(existing)
	return existing
}

func parseEthtoolDriver(out string, f *netFacts) {
	for _, line := range strings.Split(out, "\n") {
		key, value, ok := splitEthtoolKV(line)
		if !ok {
			continue
		}
		switch key {
		case "driver":
			f.driver = value
		case "version":
			f.driverVer = value
		case "firmware-version":
			f.firmware = value
		case "bus-info":
			f.busInfo = value
		}
	}
}

// parseEthtoolRing reads the two sections `ethtool -g` prints: the hardware
// maximums first, then the current settings. A ring sitting far below its own
// maximum is a tuning fact; a ring already at the maximum means the knob is
// spent and the answer lies elsewhere.
func parseEthtoolRing(out string, f *netFacts) {
	current := false
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "Current hardware settings") {
			current = true
			continue
		}
		key, value, ok := splitEthtoolKV(line)
		if !ok {
			continue
		}
		v, err := strconv.Atoi(value)
		if err != nil {
			continue
		}
		switch {
		case key == "RX" && current:
			f.rxRing = v
		case key == "RX":
			f.rxRingMax = v
		case key == "TX" && current:
			f.txRing = v
		case key == "TX":
			f.txRingMax = v
		}
	}
}

func parseEthtoolChannels(out string, f *netFacts) {
	current := false
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "Current hardware settings") {
			current = true
			continue
		}
		key, value, ok := splitEthtoolKV(line)
		if !ok || !current {
			continue
		}
		if key == "Combined" {
			if v, err := strconv.Atoi(value); err == nil {
				f.queues = v
			}
		}
	}
}

func parseEthtoolCoalesce(out string, f *netFacts) {
	c := NetCoalesce{}
	found := false
	for _, line := range strings.Split(out, "\n") {
		key, value, ok := splitEthtoolKV(line)
		if !ok {
			continue
		}
		switch key {
		case "rx-usecs":
			if v, err := strconv.Atoi(value); err == nil {
				c.RxUsecs, found = v, true
			}
		case "rx-frames":
			if v, err := strconv.Atoi(value); err == nil {
				c.RxFrames, found = v, true
			}
		case "Adaptive RX":
			c.AdaptiveRx = strings.HasPrefix(value, "on")
			found = true
		}
	}
	if found {
		f.coalesce = &c
	}
}

func splitEthtoolKV(line string) (string, string, bool) {
	i := strings.Index(line, ":")
	if i < 0 {
		return "", "", false
	}
	key := strings.TrimSpace(line[:i])
	value := strings.TrimSpace(line[i+1:])
	if key == "" || value == "" {
		return "", "", false
	}
	return key, value, true
}
