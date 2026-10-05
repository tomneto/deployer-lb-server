//go:build agent

package agent

// NetLinkInfo is the link-health section: everything needed to answer "is this
// NIC performing the way the hardware allows, and is the traffic even taking
// the interface we think it is".
//
// It exists because the most expensive network fault is also the most silent:
// a gigabit NIC that negotiated 100 Mb/s at boot looks perfectly healthy from
// every byte-rate dashboard — the host simply never moves more than 11 MB/s
// and nothing says why. The one fact that exposes it (negotiated speed vs what
// the card supports) is not in any counter; it has to be read on purpose.
//
// Two clocks, because the two halves cost differently. Facts (driver, ring,
// coalesce, supported modes) shell out to ethtool and change only when someone
// changes them. Counters are /proc and sysfs reads, cheap enough for every
// tick, and they are the half that has to be sampled often to be worth
// anything at all — a cumulative error count is unreadable, only its delta
// between two samples means something.
type NetLinkInfo struct {
	OK             bool              `json:"ok"`
	Error          string            `json:"error,omitempty"`
	FactsAt        string            `json:"facts_at,omitempty"`
	CountersAt     string            `json:"counters_at,omitempty"`
	EthtoolPresent bool              `json:"ethtool_present"`
	BootID         string            `json:"boot_id,omitempty"`
	Interfaces     []NetInterface    `json:"interfaces,omitempty"`
	Subnets        []NetSubnet       `json:"subnets,omitempty"`
	DefaultRoutes  []NetRoute        `json:"default_routes,omitempty"`
	Neighbors      []NetNeighbor     `json:"neighbors,omitempty"`
	Nstat          map[string]uint64 `json:"nstat,omitempty"`
	Softnet        []NetSoftnetCPU   `json:"softnet,omitempty"`
	IRQs           []NetIRQ          `json:"irqs,omitempty"`
	IRQBalance     *NetIRQBalance    `json:"irqbalance,omitempty"`
}

// NetInterface is one NIC as the kernel and the driver describe it.
//
// SpeedMbps is -1 when unknown (no carrier, or a virtual device that has no
// notion of line rate) and is deliberately NOT coerced to 0: zero reads as "a
// link doing nothing", unknown reads as "do not score this". The same applies
// to every counter below — a driver that does not export a statistic leaves it
// absent, and absent must never be scored as healthy.
type NetInterface struct {
	Iface   string `json:"iface"`
	Kind    string `json:"kind"`
	OperSt  string `json:"oper_state"`
	Carrier bool   `json:"carrier"`
	MTU     int    `json:"mtu,omitempty"`
	MAC     string `json:"mac,omitempty"`

	Driver    string `json:"driver,omitempty"`
	DriverVer string `json:"driver_version,omitempty"`
	Firmware  string `json:"firmware,omitempty"`
	BusInfo   string `json:"bus_info,omitempty"`

	SpeedMbps int    `json:"speed_mbps"`
	Duplex    string `json:"duplex,omitempty"`
	AutoNeg   *bool  `json:"autoneg,omitempty"`

	// SupportedSpeedsMbps comes from ethtool and is the yardstick the whole
	// section exists for: without it "100 Mb/s" is just a number, with it the
	// same number is a fault. MaxSpeedMbps is its max, carried separately so a
	// consumer never has to re-derive it and risk disagreeing with us.
	SupportedSpeedsMbps  []int `json:"supported_speeds_mbps,omitempty"`
	AdvertisedSpeedsMbps []int `json:"advertised_speeds_mbps,omitempty"`
	PartnerSpeedsMbps    []int `json:"link_partner_speeds_mbps,omitempty"`
	MaxSpeedMbps         int   `json:"max_speed_mbps,omitempty"`

	CombinedQueues int `json:"combined_queues,omitempty"`
	RxRing         int `json:"rx_ring,omitempty"`
	RxRingMax      int `json:"rx_ring_max,omitempty"`
	TxRing         int `json:"tx_ring,omitempty"`
	TxRingMax      int `json:"tx_ring_max,omitempty"`

	Coalesce  *NetCoalesce      `json:"coalesce,omitempty"`
	Stats     map[string]uint64 `json:"stats,omitempty"`
	Addresses []NetAddress      `json:"addresses,omitempty"`
}

// NetCoalesce is interrupt moderation. RxFrames of 1 with RxUsecs of 0 means
// one interrupt per frame, which on a single-queue NIC pins an entire core at
// line rate — visible nowhere else.
type NetCoalesce struct {
	RxUsecs    int  `json:"rx_usecs"`
	RxFrames   int  `json:"rx_frames"`
	AdaptiveRx bool `json:"adaptive_rx"`
}

type NetAddress struct {
	CIDR   string `json:"cidr"`
	Family string `json:"family"`
}

// NetSubnet groups the interfaces that carry an address inside the same
// prefix. More than one entry in Ifaces is the ARP-flux shape: with
// arp_ignore at 0 the host answers an ARP for the cabled IP out of the
// wireless NIC, and inbound traffic silently migrates to Wi-Fi while the
// return path stays on the cable. Nothing in any throughput graph explains it.
type NetSubnet struct {
	CIDR        string         `json:"cidr"`
	Ifaces      []string       `json:"ifaces"`
	ArpIgnore   map[string]int `json:"arp_ignore,omitempty"`
	ArpAnnounce map[string]int `json:"arp_announce,omitempty"`
	RpFilter    map[string]int `json:"rp_filter,omitempty"`
}

type NetRoute struct {
	Iface   string `json:"iface"`
	Gateway string `json:"gateway,omitempty"`
	Metric  int    `json:"metric"`
}

type NetNeighbor struct {
	IP        string `json:"ip"`
	MAC       string `json:"mac,omitempty"`
	Iface     string `json:"iface"`
	IsGateway bool   `json:"is_gateway,omitempty"`
}

// NetSoftnetCPU is one line of /proc/net/softnet_stat. Dropped counts packets
// the kernel discarded because the per-CPU backlog was full — a receiver
// problem that looks exactly like packet loss on the wire to anything
// measuring end to end, which is precisely the confusion this section is here
// to settle.
type NetSoftnetCPU struct {
	CPU         int    `json:"cpu"`
	Processed   uint64 `json:"processed"`
	Dropped     uint64 `json:"dropped"`
	TimeSqueeze uint64 `json:"time_squeeze"`
}

// NetIRQ is one interrupt line and how it spread across CPUs. A single-queue
// NIC has exactly one, and CountsPerCPU shows the whole receive path landing
// on one core.
type NetIRQ struct {
	IRQ          string   `json:"irq"`
	Name         string   `json:"name"`
	CountsPerCPU []uint64 `json:"counts_per_cpu"`
	Total        uint64   `json:"total"`
}

type NetIRQBalance struct {
	Present bool `json:"present"`
	Active  bool `json:"active"`
}
