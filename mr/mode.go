package main

// mode: what this box is on the network (Cd1s/mini-router#24, #26). Core, like the guard: every
// module looks at it, Config.Validate checks it after the modules.
//
//	router (default, "")  the main router: WANs, NAT, DHCP / RA, firewall zones
//	bypass                旁路由: one LAN (a single port is fine) behind the main router at lan.gateway, no
//	                      WAN. It serves DNS and the proxy for the network; bypass.clients picks the topology:
//	  route-only (default)  the main router stays everyone's gateway and DHCP server; it hands out this box as
//	                      DNS and routes the proxied ranges (fake-ip + rule CIDRs, `mr proxy routes`) here.
//	                      Only proxied connections pass this box, and their replies go back through the main
//	                      router (connmark + a routing rule), so its connection tracking sees both
//	                      directions — a main router that drops invalid packets (OpenWrt does) keeps them.
//	  all                 this box is the DHCP server (the main router's is off) and every client's gateway +
//	                      DNS; forwarded traffic is masqueraded towards the main router (bypass.nat)
//	  selected            the same, but only bypass.macs get this box as gateway + DNS; everyone else gets
//	                      the main router's
//	ap                    pure AP / switch: every port and the SSIDs in one bridge with a management address;
//	                      no routing (forwarding off), no NAT, DHCP, RA, proxy or flow offload
//
// Neither bypass nor ap has WANs, extra networks, port forwards, open WAN ports, multi-WAN or policy
// routes. The box's own DNS goes to lan.gateway unless dns.upstream says otherwise.

import (
	"fmt"
	"net"
	"strings"
)

type Bypass struct {
	Clients string   `yaml:"clients,omitempty"` // route-only (default) | all | selected
	MACs    []string `yaml:"macs,omitempty"`    // selected: the devices that use this box as gateway + DNS
	NAT     *bool    `yaml:"nat,omitempty"`     // all / selected: masquerade forwarded traffic (default true)
}

const (
	bypassReplyMark = "0x2000000" // fwmark: replies of proxied connections, routed back via lan.gateway
	bypassTable     = 301         // routing table: default via lan.gateway
	bypassRulePref  = proxyRulePref + 1
)

func (c *Config) routerMode() bool { return c.Mode == "" || c.Mode == "router" }
func (c *Config) bypassMode() bool { return c.Mode == "bypass" }
func (c *Config) apMode() bool     { return c.Mode == "ap" }

// bypassClients: the effective topology in mode bypass.
func (c *Config) bypassClients() string {
	if c.Bypass.Clients == "" {
		return "route-only"
	}
	return c.Bypass.Clients
}

// bypassServesDHCP: this box hands out addresses (bypass all / selected).
func (c *Config) bypassServesDHCP() bool { return c.bypassMode() && c.bypassClients() != "route-only" }

// bypassNAT: forwarded traffic is masqueraded towards the main router.
func (c *Config) bypassNAT() bool { return c.bypassServesDHCP() && on(c.Bypass.NAT) }

// bypassReplyRoute: proxied connections' replies go back through the main router (route-only).
func (c *Config) bypassReplyRoute() bool {
	return c.bypassMode() && c.bypassClients() == "route-only" && c.Proxy.Enabled
}

func modeValidate(c *Config, v *Validator) {
	switch c.Mode {
	case "", "router":
		if c.LAN.Gateway != "" {
			v.Add("lan.gateway: only in mode bypass or ap (a router's gateway is its WAN)")
		}
		if c.Bypass.Clients != "" || len(c.Bypass.MACs) > 0 || c.Bypass.NAT != nil {
			v.Add("bypass: only in mode bypass")
		}
		return
	case "bypass", "ap":
	default:
		v.Add("mode: router, bypass or ap, got %q", c.Mode)
		return
	}
	m := c.Mode
	ip, lanNet, err := net.ParseCIDR(c.LAN.IPv4)
	gw := net.ParseIP(c.LAN.Gateway)
	switch {
	case c.LAN.Gateway == "":
		v.Add("lan.gateway: the main router's address is required in mode %s", m)
	case gw == nil || gw.To4() == nil:
		v.Add("lan.gateway: an IPv4 address, got %q", c.LAN.Gateway)
	case err == nil && !lanNet.Contains(gw):
		v.Add("lan.gateway: %s is not inside lan.ipv4 %s", c.LAN.Gateway, c.LAN.IPv4)
	case err == nil && ip.Equal(gw):
		v.Add("lan.gateway: %s is this box's own address", c.LAN.Gateway)
	}
	not := func(cond bool, what string) {
		if cond {
			v.Add("%s: not in mode %s (the main router has it)", what, m)
		}
	}
	not(len(c.WAN) > 0, "wan")
	not(len(c.Networks) > 0, "networks")
	not(c.MultiWAN.Enabled(), "multiwan")
	not(len(c.Policy) > 0, "policy_routes")
	not(len(c.Firewall.Forwards) > 0, "firewall.forwards")
	not(len(c.Firewall.Open) > 0, "firewall.open")
	not(len(c.Firewall.IPv6Allow) > 0, "firewall.ipv6_allow")
	not(c.Mcast.IGMPProxy, "multicast.igmpproxy")
	not(c.LAN.IPv6RA, "lan.ipv6_ra")
	not(c.Services.Edge.Open, "services.edge.open")
	not(len(c.Firewall.Access) > 0, "firewall.access")
	for i, r := range c.Firewall.Rules {
		not(r.Src == "wan" || r.Dest == "wan", fmt.Sprintf("firewall.rules[%d] with src / dest wan", i))
	}
	not(c.DNS.Upstream == "isp", "dns.upstream isp")
	if c.apMode() {
		not(c.Proxy.Enabled, "proxy")
		not(c.DNS.Redirect, "dns.redirect")
		if c.Bypass.Clients != "" || len(c.Bypass.MACs) > 0 || c.Bypass.NAT != nil {
			v.Add("bypass: only in mode bypass")
		}
		return
	}
	switch c.Bypass.Clients {
	case "", "route-only", "all", "selected":
	default:
		v.Add("bypass.clients: route-only, all or selected, got %q", c.Bypass.Clients)
	}
	if c.bypassClients() == "selected" && len(c.Bypass.MACs) == 0 {
		v.Add("bypass.macs: clients selected needs at least one MAC")
	}
	if c.bypassClients() != "selected" && len(c.Bypass.MACs) > 0 {
		v.Add("bypass.macs: only with clients selected")
	}
	if c.bypassClients() == "route-only" && c.Bypass.NAT != nil {
		v.Add("bypass.nat: only with clients all or selected (route-only forwards nothing)")
	}
	seen := map[string]bool{}
	for i, mac := range c.Bypass.MACs {
		if !reMAC.MatchString(mac) {
			v.Add("bypass.macs[%d]: invalid %q", i, mac)
		} else if seen[strings.ToLower(mac)] {
			v.Add("bypass.macs[%d]: duplicate %s", i, mac)
		}
		seen[strings.ToLower(mac)] = true
	}
	if c.Proxy.Enabled && !c.Proxy.IPv4Only {
		v.Add("proxy.ipv4_only: must be true in mode bypass (the main router's IPv6 routes and DNS stay its own)")
	}
	if len(c.Bypass.MACs) > 64 {
		v.Add("bypass.macs: at most 64")
	}
}

// modeNetSh: the default route (bypass, ap) and the reply route of proxied connections (bypass route-only).
func modeNetSh(c *Config, phase string, b *strings.Builder) {
	if c.routerMode() || phase != "routes" {
		return
	}
	br := c.LAN.Bridge
	fmt.Fprintf(b, "# mode %s: the main router at %s is the way out; IPv6 from its router advertisements\n", c.Mode, c.LAN.Gateway)
	fmt.Fprintf(b, "ip -4 route replace default via %s dev %s\n", c.LAN.Gateway, br)
	fmt.Fprintf(b, "echo 2 > /proc/sys/net/ipv6/conf/%s/accept_ra\n", br)
	fmt.Fprintf(b, "while ip -4 rule del pref %d 2>/dev/null; do :; done\n", bypassRulePref)
	if c.bypassReplyRoute() {
		b.WriteString("# replies of proxied connections go back through the main router (it saw the request)\n")
		fmt.Fprintf(b, "ip -4 rule add fwmark %s/%s lookup %d pref %d\n", bypassReplyMark, bypassReplyMark, bypassTable, bypassRulePref)
		fmt.Fprintf(b, "ip -4 route replace default via %s dev %s table %d\n", c.LAN.Gateway, br, bypassTable)
	}
}
