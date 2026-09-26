package main

// guard: the owner's baselines as machine checks (Cd1s/mini-router#38), checked by Config.Validate after
// every module (core, not a module). `mr validate` refuses any
// config that breaks them, whichever way it arrives — web UI, CLI, restore, an API token or an AI
// agent. Changing the guard section itself is a high-risk change (risk.go).
//
//	guard:
//	  never_expose: [ssh, panel, dns]   # never reachable from the WAN (firewall.open, forwards to the router, services.edge routes)
//	  always_bypass: [desktop]          # these devices (devices / dhcp.hosts / proxy.bypass names) never go through the proxy
//	  offload: hardware                 # flow offload may not drop below this (hardware > software > off)
//	  ssh_lan_only: true                # SSH, when on, listens on the LAN-zone addresses only

import (
	"net"
	"strconv"
	"strings"
)

type Guard struct {
	NeverExpose  []string `yaml:"never_expose,omitempty"`
	AlwaysBypass []string `yaml:"always_bypass,omitempty"`
	Offload      string   `yaml:"offload,omitempty"`
	SSHLANOnly   bool     `yaml:"ssh_lan_only,omitempty"`
}

// guardPorts: the router's own services a guard can name, and their TCP/UDP ports.
func guardPorts(c *Config, svc string) []int {
	switch svc {
	case "ssh":
		if p := c.Services.SSH.Port; p > 0 {
			return []int{p}
		}
		return []int{22}
	case "panel":
		return []int{80} // busybox httpd
	case "dns":
		return []int{53}
	}
	return nil
}

var offloadRank = map[string]int{"off": 0, "software": 1, "hardware": 2}

func guardValidate(c *Config, v *Validator) {
	g := c.Guard
	for _, s := range g.NeverExpose {
		ports := guardPorts(c, s)
		if ports == nil {
			v.Add("guard.never_expose: ssh, panel or dns, got %q", s)
			continue
		}
		for _, o := range c.Firewall.Open {
			if o.Enabled != nil && !*o.Enabled {
				continue
			}
			for _, p := range ports {
				if portIn(o.Port, p) {
					v.Add("guard.never_expose: firewall.open[%s] opens port %d (%s) to the WAN", o.Name, p, s)
				}
			}
		}
		for _, f := range c.Firewall.Forwards {
			if f.Enabled != nil && !*f.Enabled || !c.isRouterAddr(devHostIP(c, f.To)) {
				continue
			}
			to := f.ToPort
			if to == "" {
				to = f.Port
			}
			for _, p := range ports {
				if portIn(to, p) {
					v.Add("guard.never_expose: firewall.forwards[%s] forwards to the router's port %d (%s)", f.Name, p, s)
				}
			}
		}
		// the HTTPS reverse proxy: a WAN-reachable route to one of these ports on the router itself
		edgeGuard(c, v, s, ports)
	}
	if len(g.AlwaysBypass) > 0 && c.Proxy.Enabled {
		bypass := map[string]bool{} // entry names and every bypassed MAC
		for _, d := range c.Proxy.Bypass {
			bypass[strings.ToLower(d.Name)] = true
			for _, m := range proxyBypassMACs(c, d) {
				bypass[m] = true
			}
		}
		hosts := map[string][]string{} // a name → its MACs (a device may have several: all must be bypassed)
		for _, h := range c.knownHosts() {
			n := strings.ToLower(h.Name)
			hosts[n] = append(hosts[n], strings.ToLower(h.MAC))
		}
		for _, name := range g.AlwaysBypass {
			n := strings.ToLower(name)
			all := len(hosts[n]) > 0
			for _, m := range hosts[n] {
				all = all && bypass[m]
			}
			if !bypass[n] && !all {
				v.Add("guard.always_bypass: device %q is not in proxy.bypass", name)
			}
		}
	}
	if g.Offload != "" {
		want, ok := offloadRank[g.Offload]
		if !ok {
			v.Add("guard.offload: hardware, software or off, got %q", g.Offload)
		} else if got := offloadRank[c.Firewall.Offload]; got < want {
			v.Add("guard.offload: firewall.offload may not be below %s, got %q", g.Offload, c.Firewall.Offload)
		}
	}
	if g.SSHLANOnly && c.Services.SSH.Enabled && !c.Services.SSH.LANOnly {
		v.Add("guard.ssh_lan_only: services.ssh.lan_only must stay true")
	}
}

// portIn: whether port p is in a port spec ("443", "8000-8100", "80,443", "").
func portIn(spec string, p int) bool {
	for _, part := range strings.Split(spec, ",") {
		lo, hi, ok := strings.Cut(strings.TrimSpace(part), "-")
		if !ok {
			hi = lo
		}
		a, e1 := strconv.Atoi(lo)
		b, e2 := strconv.Atoi(hi)
		if e1 == nil && e2 == nil && a <= p && p <= b {
			return true
		}
	}
	return false
}

// isRouterAddr: whether ip is one of the router's LAN-side addresses.
func (c *Config) isRouterAddr(ip string) bool {
	a := net.ParseIP(ip)
	if a == nil {
		return false
	}
	for _, cidr := range append([]string{c.LAN.IPv4}, networkAddrs(c)...) {
		if r, _, err := net.ParseCIDR(cidr); err == nil && r.Equal(a) {
			return true
		}
	}
	return false
}

func networkAddrs(c *Config) []string {
	var out []string
	for _, n := range c.Networks {
		out = append(out, n.IPv4)
	}
	return out
}
