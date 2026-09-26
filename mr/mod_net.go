package main

// net module: LAN / extra networks (+ tagged VLANs) / WAN (PPPoE, DHCP, static, optional VLAN) /
// multi-WAN failover + per-connection balancing / policy routes / static routes / multicast / port status.
// Owns: router.yaml lan, networks, wan, multiwan, policy_routes, static_routes, multicast; hooks.go.
//
// Files: mod_net.go (types, registration, validation), mod_net_render.go (generated files, network.sh,
// nftables), mod_net_status.go (status + web UI API), hooks.go (runtime: pppd / udhcpc / dhcpcd /
// health-check hooks that install routes). Docs: docs/modules/net.md.

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type LAN struct {
	Bridge string   `yaml:"bridge"`
	Ports  []string `yaml:"ports"`
	IPv4   string   `yaml:"ipv4"` // CIDR, e.g. 192.168.1.6/24
	IPv6RA bool     `yaml:"ipv6_ra"`
	// Gateway: the main router, in mode bypass / ap (mode.go)
	Gateway string `yaml:"gateway,omitempty"`
}

type WAN struct {
	Name     string   `yaml:"name"`           // logical name, e.g. wan / wan2
	Device   string   `yaml:"device"`         // underlying netdev, e.g. wan
	VLAN     int      `yaml:"vlan,omitempty"` // 802.1Q id on Device (0 = untagged), e.g. ISPs that tag PPPoE
	MAC      string   `yaml:"mac"`
	Proto    string   `yaml:"proto"` // pppoe | dhcp | static
	Username string   `yaml:"username"`
	Password string   `yaml:"password_secret"`   // key in secrets.yaml
	IPv4     string   `yaml:"ipv4,omitempty"`    // static: address/prefix, e.g. 203.0.113.10/24
	Gateway  string   `yaml:"gateway,omitempty"` // static: IPv4 gateway inside IPv4's subnet
	DNS      []string `yaml:"dns,omitempty"`     // static: upstream DNS servers
	MTU      int      `yaml:"mtu"`
	Metric   int      `yaml:"metric"` // default-route metric: lower = preferred (failover order)
	PeerDNS  bool     `yaml:"peerdns"`
	IPv6     bool     `yaml:"ipv6"`
	IPv6PD   bool     `yaml:"ipv6_pd"`       // request a delegated prefix and put it on the LAN
	SrcRoute bool     `yaml:"ipv6_srcroute"` // IPv6 traffic sourced from this WAN's prefix leaves via this WAN
}

// LinkDev is the ethernet-level netdev of the WAN: Device, or its 802.1Q subinterface.
func (w WAN) LinkDev() string {
	if w.VLAN > 0 {
		return fmt.Sprintf("%s.%d", w.Device, w.VLAN)
	}
	return w.Device
}

// Ifname is the L3 interface pppd / udhcpc / the static address ends up on.
func (w WAN) Ifname() string {
	if w.Proto == "pppoe" {
		return "pppoe-" + w.Name
	}
	return w.LinkDev()
}

// Route is a static route. Via (gateway) or Dev (interface) or both; Table 0 = main.
type Route struct {
	Name   string `yaml:"name" json:"name"`
	Target string `yaml:"target" json:"target"` // CIDR, v4 or v6
	Via    string `yaml:"via,omitempty" json:"via,omitempty"`
	Dev    string `yaml:"dev,omitempty" json:"dev,omitempty"`
	Metric int    `yaml:"metric,omitempty" json:"metric,omitempty"`
	Table  int    `yaml:"table,omitempty" json:"table,omitempty"`
}

// Mcast: LAN multicast behaviour. Snooping off = flood (most compatible: mDNS/SSDP/AirPlay).
// IGMPProxy relays multicast (e.g. IPTV) from one WAN into the LAN.
type Mcast struct {
	Snooping  bool   `yaml:"igmp_snooping" json:"igmp_snooping"`
	IGMPProxy bool   `yaml:"igmp_proxy" json:"igmp_proxy"`
	Upstream  string `yaml:"upstream,omitempty" json:"upstream,omitempty"` // WAN name
}

// Policy steers NEW outbound connections from LAN-side networks to one WAN. Selectors are ANDed;
// at least one of MAC / Src / Dst / Domains is required. Src/Dst decide the family (IPv4 or IPv6);
// a rule without them covers both. Domains: dnsmasq puts the addresses its upstream answers for
// these names (and their subdomains) into nft sets, the rule matches the destination against them
// (mod_net_domains.go). Table/Mark are optional: the first policy via a WAN may pin that WAN's
// routing table and fwmark (the home config keeps table 102 / 0x102 for wan2); otherwise 200+i / 0x200+i.
type Policy struct {
	Name        string   `yaml:"name"`
	MAC         string   `yaml:"mac,omitempty"`
	Src         string   `yaml:"src,omitempty"`          // source IP or CIDR (LAN side)
	Dst         string   `yaml:"dst,omitempty"`          // destination IP or CIDR
	Domains     []string `yaml:"domains,omitempty"`      // destination by DNS name: example.com = it and every subdomain
	DomainsFile string   `yaml:"domains_file,omitempty"` // more domains, one per line (# comments)
	Via         string   `yaml:"via"`                    // WAN name
	Table       int      `yaml:"table,omitempty"`
	Mark        string   `yaml:"mark,omitempty"` // e.g. 0x102
}

// byDomain reports whether the policy selects destinations by DNS name.
func (p Policy) byDomain() bool { return len(p.Domains) > 0 || p.DomainsFile != "" }

// MultiWAN: health-checked failover and optional per-connection load balancing.
//
// failover: a busybox sh loop (mr-wanmon) pings Targets through every WAN; a WAN that fails Fall
// rounds in a row is "down": its default route metric is raised by downMetric (the next WAN by
// metric takes over) and its per-WAN table loses the default route (policy routes fall back to
// the best healthy WAN). After Rise good rounds it is restored.
// balance: additionally, NEW IPv4 connections from LAN-side networks are spread over the healthy
// WANs with Weight > 0 (nft numgen → per-WAN fwmark, kept per connection by connmark).
type MultiWAN struct {
	Mode     string         `yaml:"mode,omitempty"`     // "" (off) | failover | balance
	Targets  []string       `yaml:"targets,omitempty"`  // IPv4 addresses pinged through each WAN
	Interval int            `yaml:"interval,omitempty"` // seconds between check rounds (default 5)
	Timeout  int            `yaml:"timeout,omitempty"`  // seconds to wait for a reply (default 2)
	Fall     int            `yaml:"fall,omitempty"`     // failed rounds before a WAN is down (default 3)
	Rise     int            `yaml:"rise,omitempty"`     // good rounds before it is up again (default 2)
	Weights  map[string]int `yaml:"weights,omitempty"`  // balance: WAN name -> share of new connections (default 1 each)
}

// Enabled reports whether the health checker runs.
func (m MultiWAN) Enabled() bool { return m.Mode == "failover" || m.Mode == "balance" }

// Weight of a WAN in balance mode (0 = never chosen by the balancer, only by failover).
func (m MultiWAN) Weight(name string) int {
	if len(m.Weights) == 0 {
		return 1
	}
	return m.Weights[name]
}

// Network is an extra LAN-side network (guest, IoT, a VLAN). The main LAN stays in `lan`.
type Network struct {
	Name   string   `yaml:"name"`            // [a-z][a-z0-9_-]{0,9}; its bridge is br-<name>
	IPv4   string   `yaml:"ipv4"`            // router address + prefix, e.g. 192.168.10.1/24
	Ports  []string `yaml:"ports,omitempty"` // untagged member ports (must not also be in lan.ports)
	VLAN   int      `yaml:"vlan,omitempty"`  // 802.1Q id carried tagged on Trunk ports (0 = none)
	Trunk  []string `yaml:"trunk,omitempty"` // ports that carry this network tagged (<port>.<vlan> joins br-<name>)
	Zone   string   `yaml:"zone,omitempty"`  // firewall zone: guest (default: internet only) | lan (trusted)
	IPv6RA bool     `yaml:"ipv6_ra,omitempty"`
	DHCP   Pool     `yaml:"dhcp,omitempty"` // address pool, rendered by the dns module
}

func (n Network) BridgeName() string { return "br-" + n.Name }

// WANTable returns the routing table and fwmark for a WAN. The first policy route that targets the
// WAN with an explicit table+mark lends them; otherwise 200+index / 0x200+index.
func (c *Config) WANTable(name string) (int, string) {
	for _, p := range c.Policy {
		if p.Via == name && p.Table != 0 && p.Mark != "" {
			return p.Table, p.Mark
		}
	}
	for i, w := range c.WAN {
		if w.Name == name {
			return 200 + i, fmt.Sprintf("0x%x", 0x200+i)
		}
	}
	return 0, ""
}

func (c *Config) WANByName(n string) *WAN {
	for i := range c.WAN {
		if c.WAN[i].Name == n {
			return &c.WAN[i]
		}
	}
	return nil
}

// wanByIfname finds the WAN whose L3 interface is ifname.
func (c *Config) wanByIfname(ifname string) *WAN {
	for i := range c.WAN {
		if c.WAN[i].Ifname() == ifname {
			return &c.WAN[i]
		}
	}
	return nil
}

// netService is the OpenRC service that brings a WAN up ("" for static WANs).
func netService(w WAN) string {
	switch w.Proto {
	case "pppoe":
		return "mr-pppoe." + w.Name
	case "dhcp":
		return "mr-udhcpc." + w.Name
	}
	return ""
}

func init() {
	register(&Module{
		Name:     "net",
		Prio:     10,
		Defaults: netDefaults,
		Validate: netValidate,
		Render:   netRender,
		NetSh:    netSh,
		Nft:      netNft,
		// policy_routes domains: dnsmasq fills the nft sets the policy rules match (mod_net_domains.go)
		Dnsmasq: policyDnsmasq,
		FlowDevs: func(c *Config) []string {
			devs := append([]string{}, c.LAN.Ports...)
			for _, n := range c.Networks {
				devs = append(devs, n.Ports...)
				devs = append(devs, n.Trunk...)
			}
			for _, w := range c.WAN {
				devs = append(devs, w.Device, w.Ifname())
			}
			return devs
		},
		Services: func(c *Config) []string {
			var s []string
			for _, w := range c.WAN {
				if svc := netService(w); svc != "" {
					s = append(s, svc)
				}
			}
			s = append(s, "mr-dhcpcd")
			if c.Mcast.IGMPProxy {
				s = append(s, "igmpproxy")
			}
			if c.MultiWAN.Enabled() {
				s = append(s, "mr-wanmon")
			}
			return s
		},
		// mr-pppoe.* instances are found by the core; mr-udhcpc.* instances are listed here so a
		// WAN that is removed or switched away from DHCP gets its client stopped and disabled.
		Managed: append([]string{"igmpproxy", "mr-wanmon", "dhcpcd"}, initInstances("mr-udhcpc.")...), // dhcpcd: Alpine's service, replaced by mr-dhcpcd
		Restart: func(path string) string {
			switch {
			case strings.HasPrefix(path, "/etc/ppp/peers/"):
				return "mr-pppoe." + filepath.Base(path)
			case strings.HasPrefix(path, "/etc/init.d/mr-pppoe."):
				return "-" // wrapper only depends on the name; the peers file carries the settings
			case strings.HasPrefix(path, "/etc/init.d/mr-udhcpc."):
				return filepath.Base(path) // carries the interface
			case path == GenDir+"/wanmon.conf":
				return "mr-wanmon"
			case path == "/etc/dhcpcd.conf":
				return "mr-dhcpcd"
			case path == "/etc/igmpproxy.conf":
				return "igmpproxy"
			}
			return ""
		},
		RestartOrder: []string{"mr-pppoe.", "mr-udhcpc.", "mr-dhcpcd", "igmpproxy", "mr-wanmon"},
		Verify:       netVerify,
		Status:       netStatus,
		API: map[string]func(r apiReq) apiResp{
			"net":        func(apiReq) apiResp { return apiNet() },
			"net.ports":  func(apiReq) apiResp { return apiNetPorts() },
			"net.routes": func(apiReq) apiResp { return apiNetRoutes() },
			"net.wan":    func(apiReq) apiResp { return apiNetWAN() },
			"net.redial": apiNetRedial,
		},
		Commands: map[string]func(c *Config, args []string) error{
			"wan": wanCommand,
		},
	})
}

// initInstances lists /etc/init.d entries with the given prefix (multi-instance services).
func initInstances(prefix string) []string {
	var out []string
	ents, _ := os.ReadDir("/etc/init.d")
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), prefix) {
			out = append(out, e.Name())
		}
	}
	return out
}

func netDefaults(c *Config) {
	if c.LAN.Bridge == "" {
		c.LAN.Bridge = "br-lan"
	}
	for i := range c.WAN {
		w := &c.WAN[i]
		if w.MTU == 0 && w.Proto == "pppoe" {
			w.MTU = 1492
		}
	}
	for i := range c.Networks {
		if c.Networks[i].Zone == "" {
			c.Networks[i].Zone = "guest"
		}
	}
	if m := &c.MultiWAN; m.Enabled() {
		if len(m.Targets) == 0 {
			m.Targets = []string{"1.1.1.1", "8.8.8.8"}
		}
		if m.Interval == 0 {
			m.Interval = 5
		}
		if m.Timeout == 0 {
			m.Timeout = 2
		}
		if m.Fall == 0 {
			m.Fall = 3
		}
		if m.Rise == 0 {
			m.Rise = 2
		}
	}
}

var reNetName = lazyRegexp(`^[a-z][a-z0-9_-]{0,9}$`)

// validDev: a netdev name that is safe as a shell word / command argument.
func validDev(s string) bool { return reDev.MatchString(s) && !strings.HasPrefix(s, "-") }

// parseIPOrCIDR accepts "1.2.3.4", "1.2.3.0/24", "2001:db8::1", "2001:db8::/32".
func parseIPOrCIDR(s string) (*net.IPNet, bool) {
	if strings.Contains(s, "/") {
		_, n, err := net.ParseCIDR(s)
		return n, err == nil
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return nil, false
	}
	bits := 128
	if ip.To4() != nil {
		ip, bits = ip.To4(), 32
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}, true
}

func isV4(n *net.IPNet) bool { return n.IP.To4() != nil }

// isIPv4Literal: dotted IPv4 (optionally /prefix), not an IPv4-mapped IPv6 form.
func isIPv4Literal(s string) bool {
	a := strings.SplitN(s, "/", 2)[0]
	ip := net.ParseIP(a)
	return ip != nil && ip.To4() != nil && !strings.Contains(a, ":")
}

// markValue parses "0x102" (0 when invalid).
func markValue(s string) uint64 {
	v, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(s), "0x"), 16, 32)
	if err != nil {
		return 0
	}
	return v
}

func netValidate(c *Config, v *Validator) {
	ip, lanNet, err := net.ParseCIDR(c.LAN.IPv4)
	if err != nil || ip.To4() == nil {
		v.Add("lan.ipv4: need IPv4 CIDR, got %q", c.LAN.IPv4)
	}
	if len(c.LAN.Ports) == 0 {
		v.Add("lan.ports: empty")
	}
	for _, p := range c.LAN.Ports {
		if !validDev(p) {
			v.Add("lan.ports: invalid %q", p)
		}
	}
	if !validDev(c.LAN.Bridge) {
		v.Add("lan.bridge: invalid %q", c.LAN.Bridge)
	}
	used := map[string]string{}
	for _, p := range c.LAN.Ports {
		used[p] = "lan"
	}
	vlans := map[string]string{} // "<port>.<vid>" -> owner
	nets := []*net.IPNet{lanNet}
	names := map[string]bool{}
	for i, n := range c.Networks {
		p := fmt.Sprintf("networks[%d]", i)
		if !reNetName.MatchString(n.Name) || n.Name == "lan" {
			v.Add("%s.name: [a-z][a-z0-9_-]{0,9}, not \"lan\", got %q", p, n.Name)
		}
		if names[n.Name] {
			v.Add("%s.name: duplicate %q", p, n.Name)
		}
		names[n.Name] = true
		ip, nn, err := net.ParseCIDR(n.IPv4)
		if err != nil || ip.To4() == nil {
			v.Add("%s.ipv4: need IPv4 CIDR, got %q", p, n.IPv4)
		} else {
			for _, o := range nets {
				if o != nil && (o.Contains(nn.IP) || nn.Contains(o.IP)) {
					v.Add("%s.ipv4: %s overlaps another network", p, n.IPv4)
				}
			}
			nets = append(nets, nn)
		}
		for _, port := range n.Ports {
			if !validDev(port) {
				v.Add("%s.ports: invalid %q", p, port)
			}
			if o, ok := used[port]; ok {
				v.Add("%s.ports: %s already used by %s", p, port, o)
			}
			used[port] = n.Name
		}
		if n.VLAN < 0 || n.VLAN > 4094 {
			v.Add("%s.vlan: 0-4094", p)
		}
		if len(n.Trunk) > 0 && n.VLAN < 1 {
			v.Add("%s.vlan: trunk ports need a VLAN id 1-4094", p)
		}
		if n.VLAN > 0 && len(n.Trunk) == 0 {
			v.Add("%s.trunk: vlan %d needs at least one trunk port", p, n.VLAN)
		}
		for _, port := range n.Trunk {
			sub := fmt.Sprintf("%s.%d", port, n.VLAN)
			if !validDev(port) || len(sub) > 15 {
				v.Add("%s.trunk: invalid port %q", p, port)
			}
			if o, ok := vlans[sub]; ok {
				v.Add("%s.trunk: %s already used by %s", p, sub, o)
			}
			vlans[sub] = n.Name
		}
		if n.Zone != "guest" && n.Zone != "lan" {
			v.Add("%s.zone: guest|lan, got %q", p, n.Zone)
		}
	}
	netValidateWAN(c, v, used, vlans)
	netValidatePolicy(c, v)
	for i, r := range c.Routes {
		p := fmt.Sprintf("static_routes[%d]", i)
		if r.Name != "" && !reLabel.MatchString(r.Name) {
			v.Add("%s.name: invalid %q", p, r.Name)
		}
		_, tn, err := net.ParseCIDR(r.Target)
		if err != nil {
			v.Add("%s.target: CIDR required, got %q", p, r.Target)
		}
		if r.Via == "" && r.Dev == "" {
			v.Add("%s: via or dev required", p)
		}
		if r.Via != "" {
			g := net.ParseIP(r.Via)
			if g == nil || (tn != nil && (g.To4() == nil) != (tn.IP.To4() == nil)) {
				v.Add("%s.via: gateway IP of the same family as target, got %q", p, r.Via)
			}
		}
		if r.Dev != "" && !validDev(r.Dev) {
			v.Add("%s.dev: invalid %q", p, r.Dev)
		}
		if r.Metric < 0 {
			v.Add("%s.metric: >= 0", p)
		}
		if r.Table < 0 || r.Table > 252 {
			v.Add("%s.table: 0-252", p)
		}
	}
	if c.Mcast.IGMPProxy && c.WANByName(c.Mcast.Upstream) == nil {
		v.Add("multicast.upstream: unknown wan %q", c.Mcast.Upstream)
	}
	netValidateMultiWAN(c, v)
}

func netValidateWAN(c *Config, v *Validator, ports, vlans map[string]string) {
	if len(c.WAN) == 0 && c.routerMode() {
		v.Add("wan: at least one WAN required (or mode bypass / ap)")
	}
	seen := map[string]bool{}
	ifnames := map[string]string{}
	metrics := map[int]string{}
	macs := map[string][2]string{} // device -> {mac, wan}
	for i, w := range c.WAN {
		p := fmt.Sprintf("wan[%d]", i)
		if !reName.MatchString(w.Name) {
			v.Add("%s.name: invalid %q", p, w.Name)
		}
		if seen[w.Name] {
			v.Add("%s.name: duplicate %q", p, w.Name)
		}
		seen[w.Name] = true
		if !validDev(w.Device) {
			v.Add("%s.device: invalid %q", p, w.Device)
		}
		// LinkDev: the untagged port itself, or e.g. "wan.20" when that was also listed as a network port
		if o, ok := ports[w.LinkDev()]; ok {
			v.Add("%s.device: %s is an untagged port of %s (use another port, or a vlan)", p, w.LinkDev(), o)
		}
		if w.VLAN == 0 { // the untagged WAN wire is the ISP side: no LAN-side network may be bridged onto it
			for _, n := range c.Networks {
				for _, t := range n.Trunk {
					if t == w.Device {
						v.Add("%s.device: %s carries VLAN %d of network %s (use another port, or a vlan)", p, w.Device, n.VLAN, n.Name)
					}
				}
			}
		}
		for _, br := range c.LANBridges() {
			if w.Device == br {
				v.Add("%s.device: %s is a LAN-side bridge", p, w.Device)
			}
		}
		if w.VLAN < 0 || w.VLAN > 4094 {
			v.Add("%s.vlan: 0-4094", p)
		}
		if len(w.LinkDev()) > 15 {
			v.Add("%s: interface name %s longer than 15 characters", p, w.LinkDev())
		}
		// several PPPoE sessions may share one VLAN; a network trunk may not (also when the device is
		// written as the subinterface, e.g. device: lan4.10)
		if o, ok := vlans[w.LinkDev()]; ok && !strings.HasPrefix(o, "wan ") {
			v.Add("%s.vlan: %s already used by network %s", p, w.LinkDev(), o)
		} else if !ok && w.VLAN > 0 {
			vlans[w.LinkDev()] = "wan " + w.Name
		}
		if o, ok := ifnames[w.Ifname()]; ok {
			v.Add("%s: interface %s already used by wan %s (one DHCP/static WAN per device or VLAN)", p, w.Ifname(), o)
		}
		ifnames[w.Ifname()] = w.Name
		if w.MAC != "" && !reMAC.MatchString(w.MAC) {
			v.Add("%s.mac: invalid %q", p, w.MAC)
		}
		// the MAC is set on the device: two different ones would make network.sh flip it (and drop
		// every session on that port) on each run
		if w.MAC != "" {
			if o, ok := macs[w.Device]; ok && !strings.EqualFold(o[0], w.MAC) {
				v.Add("%s.mac: %s already gets MAC %s from wan %s (the MAC belongs to the device)", p, w.Device, o[0], o[1])
			} else if !ok {
				macs[w.Device] = [2]string{w.MAC, w.Name}
			}
		}
		if !safeText(w.Username) {
			v.Add("%s.username: control characters not allowed", p)
		}
		if w.MTU != 0 && (w.MTU < 576 || w.MTU > 9000) {
			v.Add("%s.mtu: 576-9000 (0 = default), got %d", p, w.MTU)
		}
		if w.Metric < 0 || w.Metric >= downMetric {
			v.Add("%s.metric: 0-%d, got %d", p, downMetric-1, w.Metric)
		}
		// `ip route replace default ... metric M` replaces any default route with that metric, so two
		// WANs with one metric would silently drop each other's route (and break failover)
		if o, ok := metrics[w.Metric]; ok {
			v.Add("%s.metric: %d already used by wan %s (every WAN needs its own metric)", p, w.Metric, o)
		} else {
			metrics[w.Metric] = w.Name
		}
		switch w.Proto {
		case "pppoe":
			if w.Username == "" {
				v.Add("%s.username: required for pppoe", p)
			}
			if _, err := c.Secret(w.Password); err != nil || w.Password == "" {
				v.Add("%s.password_secret: %v", p, orMissing(err))
			}
			if len(w.Ifname()) > 15 {
				v.Add("%s.name: at most 9 characters for pppoe (interface pppoe-<name>)", p)
			}
			if w.MTU > 1500 {
				v.Add("%s.mtu: at most 1500 for pppoe", p)
			}
		case "dhcp":
		case "static":
			ip, sn, err := net.ParseCIDR(w.IPv4)
			if err != nil || !isIPv4Literal(w.IPv4) {
				v.Add("%s.ipv4: static needs address/prefix, got %q", p, w.IPv4)
			}
			g := net.ParseIP(w.Gateway)
			if !isIPv4Literal(w.Gateway) || (sn != nil && !sn.Contains(g)) || g.Equal(ip) {
				v.Add("%s.gateway: IPv4 inside %s, got %q", p, w.IPv4, w.Gateway)
			}
		default:
			v.Add("%s.proto: pppoe|dhcp|static, got %q", p, w.Proto)
		}
		if w.Proto != "static" && (w.IPv4 != "" || w.Gateway != "" || len(w.DNS) > 0) {
			v.Add("%s: ipv4/gateway/dns are only for proto static", p)
		}
		if len(w.DNS) > 3 {
			v.Add("%s.dns: at most 3 servers", p)
		}
		for _, d := range w.DNS {
			if net.ParseIP(d) == nil {
				v.Add("%s.dns: invalid address %q", p, d)
			}
		}
	}
	// a DHCP / static WAN has the device's MTU as its IP MTU: it must not be raised for a PPPoE
	// session's baby jumbo frames (RFC 4638, wanLinkMTUs) on the same device
	need := wanLinkMTUs(c)
	for i, w := range c.WAN {
		want := w.MTU
		if want == 0 {
			want = 1500
		}
		if w.Proto != "pppoe" && need[w.LinkDev()] > want {
			v.Add("wan[%d].mtu: %s also carries PPPoE with mtu above 1492, which needs link MTU %d — this WAN would get it too (put one of them on a VLAN, or give the PPPoE mtu 1492)",
				i, w.LinkDev(), need[w.LinkDev()])
		}
	}
	// every WAN needs its own table and mark
	tables, marks := map[int]string{}, map[uint64]string{}
	for _, w := range c.WAN {
		t, m := c.WANTable(w.Name)
		if o, ok := tables[t]; ok {
			v.Add("wan %s: routing table %d already used by wan %s (policy_routes table)", w.Name, t, o)
		}
		if o, ok := marks[markValue(m)]; ok {
			v.Add("wan %s: fwmark %s already used by wan %s (policy_routes mark)", w.Name, m, o)
		}
		tables[t], marks[markValue(m)] = w.Name, w.Name
	}
}

func netValidatePolicy(c *Config, v *Validator) {
	for i, pr := range c.Policy {
		p := fmt.Sprintf("policy_routes[%d]", i)
		if !reLabel.MatchString(pr.Name) {
			v.Add("%s.name: invalid %q", p, pr.Name)
		}
		if pr.MAC == "" && pr.Src == "" && pr.Dst == "" && !pr.byDomain() {
			v.Add("%s: need at least one of mac, src, dst, domains", p)
		}
		for _, d := range pr.Domains {
			if _, ok := proxyNormDomain(d); !ok {
				v.Add("%s.domains: invalid domain %q", p, d)
			}
		}
		if pr.DomainsFile != "" && !rePath.MatchString(pr.DomainsFile) {
			v.Add("%s.domains_file: absolute path required, got %q", p, pr.DomainsFile)
		}
		if pr.MAC != "" && !reMAC.MatchString(pr.MAC) {
			v.Add("%s.mac: invalid %q", p, pr.MAC)
		}
		var src, dst *net.IPNet
		ok := true
		if pr.Src != "" {
			if src, ok = parseIPOrCIDR(pr.Src); !ok {
				v.Add("%s.src: IP or CIDR, got %q", p, pr.Src)
			}
		}
		if pr.Dst != "" {
			if dst, ok = parseIPOrCIDR(pr.Dst); !ok {
				v.Add("%s.dst: IP or CIDR, got %q", p, pr.Dst)
			}
		}
		if src != nil && dst != nil && isV4(src) != isV4(dst) {
			v.Add("%s: src and dst must be the same family", p)
		}
		if c.WANByName(pr.Via) == nil {
			v.Add("%s.via: unknown wan %q", p, pr.Via)
		}
		if (pr.Table == 0) != (pr.Mark == "") {
			v.Add("%s: table and mark go together (or leave both empty)", p)
		}
		if pr.Mark != "" && (!reMark.MatchString(pr.Mark) || markValue(pr.Mark) == 0) {
			v.Add("%s.mark: invalid %q", p, pr.Mark)
		}
		if pr.Table != 0 && (pr.Table < 1 || pr.Table > 250) {
			v.Add("%s.table: 1-250, got %d", p, pr.Table)
		}
		// table/mark belong to the WAN: a second policy via the same WAN cannot pick different ones
		if t, m := c.WANTable(pr.Via); pr.Table != 0 && m != "" && (pr.Table != t || markValue(pr.Mark) != markValue(m)) {
			v.Add("%s: wan %s already uses table %d / mark %s (leave table and mark empty)", p, pr.Via, t, m)
		}
	}
	n := 0
	for _, pr := range c.Policy {
		if pr.byDomain() {
			n++
		}
	}
	if n > policyDomainMax {
		v.Add("policy_routes: at most %d routes with domains (put more domains into one route), got %d", policyDomainMax, n)
	}
}

func netValidateMultiWAN(c *Config, v *Validator) {
	m := c.MultiWAN
	switch m.Mode {
	case "":
		return
	case "failover", "balance":
	default:
		v.Add("multiwan.mode: failover|balance (or empty = off), got %q", m.Mode)
		return
	}
	if len(c.WAN) < 2 {
		v.Add("multiwan: needs at least two WANs")
	}
	if len(m.Targets) == 0 || len(m.Targets) > 4 {
		v.Add("multiwan.targets: 1-4 IPv4 addresses")
	}
	for _, t := range m.Targets {
		ip := net.ParseIP(t)
		if !isIPv4Literal(t) || ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() {
			v.Add("multiwan.targets: IPv4 address, got %q", t)
		}
	}
	if m.Interval < 1 || m.Interval > 300 {
		v.Add("multiwan.interval: 1-300 seconds")
	}
	if m.Timeout < 1 || m.Timeout > 10 {
		v.Add("multiwan.timeout: 1-10 seconds")
	}
	if m.Fall < 1 || m.Fall > 20 || m.Rise < 1 || m.Rise > 20 {
		v.Add("multiwan.fall/rise: 1-20 rounds")
	}
	members := 0
	for name, wt := range m.Weights {
		if c.WANByName(name) == nil {
			v.Add("multiwan.weights: unknown wan %q", name)
		}
		if wt < 0 || wt > 100 {
			v.Add("multiwan.weights.%s: 0-100", name)
		}
	}
	for _, w := range c.WAN {
		if m.Weight(w.Name) > 0 {
			members++
		}
	}
	if m.Mode == "balance" && members < 2 {
		v.Add("multiwan.weights: balance needs at least two WANs with weight > 0")
	}
}
