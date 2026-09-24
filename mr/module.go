package main

// Feature modules. Every feature area (net, wifi, dns, fw, mon, proxy, sys) lives in its own
// mod_<name>*.go files and registers one Module in init(). The core (config loading, apply,
// snapshots, API auth, status) calls into the registered modules at fixed extension points, so
// feature areas never have to edit each other's files. Contract: docs/MODULES.md.

import (
	"fmt"
	"sort"
	"strings"
)

// Module is one feature area. Every field is optional.
type Module struct {
	Name string
	// Prio orders modules wherever order matters (network.sh fragments, nft hook emission,
	// render output): lower runs first. net=10 wifi=20 dns=30 fw=40 mon=50 proxy=55 sys=70.
	Prio int

	// Defaults fills in zero values after loading (runs before Validate).
	Defaults func(c *Config)
	// Validate reports problems through v.Add; it must not touch the system.
	Validate func(c *Config, v *Validator)
	// Render adds generated files; it must not touch the system.
	Render func(c *Config, out *Out) error
	// NetSh appends shell to network.sh (run at boot by mr-network and in place by apply) for the
	// given phase: "links" (netdevs, bridges, VLANs, addresses), "wifi" (AP netdevs),
	// "routes" (ip rules/routes), "tail" (tuning). Output must be idempotent POSIX sh.
	NetSh func(c *Config, phase string, b *strings.Builder)
	// Nft emits nftables lines for a hook point inside `table inet mr` (see nftHooks).
	Nft func(c *Config, hook string, n *Nft)
	// FlowDevs lists netdevs this module wants in the offload flowtable (only existing ones are used).
	FlowDevs func(c *Config) []string
	// Dnsmasq appends lines to /etc/dnsmasq.conf (e.g. nftset=, extra dhcp-range=).
	Dnsmasq func(c *Config) []string
	// Services lists OpenRC services this module wants enabled for c.
	Services func(c *Config) []string
	// Managed lists every service this module may enable/disable (mr never touches others).
	Managed []string
	// Restart maps a generated path to the service to restart when it changes. Return "" if
	// the path is not this module's. Special services: "mr-network" re-runs network.sh in place,
	// "sysctl" reloads sysctl, "-" means no restart needed.
	Restart func(path string) string
	// RestartOrder: services this module owns, in the order they should restart relative to the
	// core order (lower layers first). Entries ending in "." match prefixes (mr-pppoe.).
	RestartOrder []string
	// Verify runs after an apply restarted services; return problems (rolls back the apply).
	Verify func(c *Config, restarted []string) []string
	// Status adds keys to the status JSON (panel, web UI overview, agent).
	Status func(c *Config, st map[string]any)
	// API adds web UI actions: /cgi-bin/api?a=<name>. Handlers run only for logged-in sessions.
	// Name them "<module>.<verb>" (e.g. "wifi.scan"). Side effects need r.method == "POST".
	API map[string]func(r apiReq) apiResp
	// Commands adds `mr <name> ...` subcommands (e.g. hooks called by daemons).
	Commands map[string]func(c *Config, args []string) error
	// Secrets lists the secret NAMES this module's config references (the web UI shows which are
	// set; values are never returned).
	Secrets func(c *Config) []string
}

var modules []*Module

func register(m *Module) {
	modules = append(modules, m)
	sort.SliceStable(modules, func(i, j int) bool { return modules[i].Prio < modules[j].Prio })
}

// Validator collects every problem so one run shows all mistakes.
type Validator struct{ errs []string }

func (v *Validator) Add(f string, a ...any) { v.errs = append(v.errs, fmt.Sprintf(f, a...)) }

// Out collects generated files.
type Out struct{ files []File }

func (o *Out) Add(path string, mode uint32, data string) {
	o.files = append(o.files, File{path, mode, data})
}

// Nft is the writer handed to Module.Nft; W appends one line (a tab is added for rule hooks).
type Nft struct {
	b      *strings.Builder
	indent string
	// Exists reports whether a netdev exists right now (always true when rendering for review/tests).
	Exists func(string) bool
}

func (n *Nft) W(f string, a ...any) { fmt.Fprintf(n.b, n.indent+f+"\n", a...) }

// nftHooks are the extension points inside `table inet mr`, in ruleset order:
//
//	defs          table level: sets, maps, counters, extra chains (with or without hooks)
//	input         filter/input after established/related/lo/LAN accepts; accept or drop WAN-side traffic
//	forward_early filter/forward before the LAN accept (blocks: traffic rules, guest isolation);
//	              fw's device access control sits at the very top of forward, before `flow add`
//	forward       filter/forward after the LAN accept (extra accepts, e.g. igmpproxy)
//	mark          prerouting mangle (policy routing marks, connmark); runs before routing
//	dstnat        nat prerouting (port forwards, DNS redirect)
//	srcnat        nat postrouting (masquerade, SNAT)
//	output        filter/output (policy accept)
var nftHooks = []string{"defs", "input", "forward_early", "forward", "mark", "dstnat", "srcnat", "output"}

func emitNft(c *Config, hook string, b *strings.Builder, exists func(string) bool) {
	indent := "\t\t"
	if hook == "defs" {
		indent = "\t"
	}
	n := &Nft{b: b, indent: indent, Exists: exists}
	for _, m := range modules {
		if m.Nft != nil {
			m.Nft(c, hook, n)
		}
	}
}

// ---- cross-module helpers ----

// LANNet is one LAN-side L3 network: the main LAN ("lan") or an entry of `networks`.
type LANNet struct {
	Name   string // "lan" or Network.Name
	Bridge string
	IPv4   string // CIDR (router address)
	Zone   string // firewall zone: "lan" (trusted) or "guest" (internet only)
	IPv6RA bool
}

// LANNets returns the main LAN first, then every extra network.
func (c *Config) LANNets() []LANNet {
	out := []LANNet{{Name: "lan", Bridge: c.LAN.Bridge, IPv4: c.LAN.IPv4, Zone: "lan", IPv6RA: c.LAN.IPv6RA}}
	for _, n := range c.Networks {
		out = append(out, LANNet{Name: n.Name, Bridge: n.BridgeName(), IPv4: n.IPv4, Zone: n.Zone, IPv6RA: n.IPv6RA})
	}
	return out
}

// BridgeFor returns the bridge of a LAN-side network by name ("" or "lan" = main LAN).
func (c *Config) BridgeFor(network string) string {
	if network == "" || network == "lan" {
		return c.LAN.Bridge
	}
	for _, n := range c.Networks {
		if n.Name == network {
			return n.BridgeName()
		}
	}
	return ""
}

// LANBridges returns every LAN-side bridge (main LAN first).
func (c *Config) LANBridges() []string {
	var out []string
	for _, n := range c.LANNets() {
		out = append(out, n.Bridge)
	}
	return out
}

// WANIfnames returns the L3 interface of every WAN.
func (c *Config) WANIfnames() []string {
	var out []string
	for _, w := range c.WAN {
		out = append(out, w.Ifname())
	}
	return out
}
