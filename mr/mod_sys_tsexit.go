package main

// sys module: a tailscale exit node for LAN devices (services.tailscale.exit_node, Cd1s/mini-router#29).
//
// tailscaled gets the exit node (`tailscale set --exit-node`, from /etc/conf.d/tailscale at start) and puts
// its default route into table 52, which tailscale's rule 5270 would use for everything, the router
// included. mr keeps that to the chosen devices:
//
//	5201  fwmark M/M lookup main suppress_prefixlength 0   the device's LAN / static routes stay direct
//	5202  fwmark M/M lookup 52                              the device → exit node (while one is set)
//	5203  fwmark M/M unreachable                            kill_switch: no fallback to the WAN
//	5208  lookup 52 suppress_prefixlength 0                 everyone else: tailnet routes, not its default
//	5209  goto 5280 / 5280 lookup main suppress_prefixlength 0   skip tailscale's 5210-5270
//
// M = tsExitMark, set by chain ts_exit (prerouting mangle+2, after net's mark_pre) by source MAC and kept
// in the connmark, so replies from tailscale0 pass strict rp_filter; srcnat masquerades them on tailscale0.
// Without a kill switch a device falls back to the normal WAN while the exit node is unset / offline.

import (
	"fmt"
	"strings"
)

// TSExit is services.tailscale.exit_node.
type TSExit struct {
	Node       string   `yaml:"node,omitempty"`        // exit node: tailnet IP or MagicDNS name
	Devices    []string `yaml:"devices,omitempty"`     // devices / group:NAME; empty = the whole LAN zone
	KillSwitch bool     `yaml:"kill_switch,omitempty"` // no fallback to the WAN
}

const tsExitMark = "0x4000000"

var reTSNode = lazyRegexp(`^[A-Za-z0-9][A-Za-z0-9.:-]{0,99}$`)

func tsExitOn(c *Config) bool {
	return c.Services.Tailscale.Enabled && c.Services.Tailscale.ExitNode.Node != ""
}

func tsExitValidate(c *Config, v *Validator) {
	x := c.Services.Tailscale.ExitNode
	const p = "services.tailscale.exit_node"
	if x.Node == "" {
		if len(x.Devices) > 0 || x.KillSwitch {
			v.Add("%s.node: required", p)
		}
		return
	}
	if !reTSNode.MatchString(x.Node) {
		v.Add("%s.node: a tailnet IP or MagicDNS name, got %q", p, x.Node)
	}
	if !c.Services.Tailscale.Enabled || !c.routerMode() {
		v.Add("%s: needs services.tailscale.enabled and mode router", p)
	}
	devCheckRefs(c, v, p+".devices", x.Devices)
}

// tsExitConf: the line for /etc/conf.d/tailscale (none while unset).
func tsExitConf(c *Config) string {
	if !tsExitOn(c) {
		return ""
	}
	return fmt.Sprintf("TS_EXIT_NODE='%s'\n", c.Services.Tailscale.ExitNode.Node)
}

func tsExitNetSh(c *Config, phase string, b *strings.Builder) {
	if phase != "routes" || !tsExitOn(c) {
		return
	}
	m := tsExitMark + "/" + tsExitMark
	b.WriteString("# tailscale exit node for chosen LAN devices (services.tailscale.exit_node)\n")
	for _, f := range []string{"-4", "-6"} {
		for _, pref := range []int{5201, 5202, 5203, 5208, 5209, 5280} {
			fmt.Fprintf(b, "while ip %s rule del pref %d 2>/dev/null; do :; done\n", f, pref)
		}
		fmt.Fprintf(b, "ip %s rule add fwmark %s lookup main suppress_prefixlength 0 pref 5201\n", f, m)
		fmt.Fprintf(b, "ip %s rule add fwmark %s lookup 52 pref 5202\n", f, m)
		if c.Services.Tailscale.ExitNode.KillSwitch {
			fmt.Fprintf(b, "ip %s rule add fwmark %s unreachable pref 5203\n", f, m)
		}
		fmt.Fprintf(b, "ip %s rule add lookup 52 suppress_prefixlength 0 pref 5208\n", f)
		fmt.Fprintf(b, "ip %s rule add lookup main suppress_prefixlength 0 pref 5280\n", f)
		fmt.Fprintf(b, "ip %s rule add goto 5280 pref 5209\n", f)
	}
}

func tsExitNft(c *Config, hook string, n *Nft) {
	if !tsExitOn(c) {
		return
	}
	switch hook {
	case "defs":
		src := ""
		if d := c.Services.Tailscale.ExitNode.Devices; len(d) > 0 {
			macs := devMACs(c, d)
			if len(macs) == 0 {
				return
			}
			src = " ether saddr { " + strings.Join(macs, ", ") + " }"
		}
		n.W("chain ts_exit {\n\t\ttype filter hook prerouting priority mangle + 2; policy accept;")
		n.W("\tiifname { %s }%s ct mark set ct mark | %s", quoteList(proxyBridges(c)), src, tsExitMark)
		n.W("\tct mark & %s == %s meta mark set meta mark | %s", tsExitMark, tsExitMark, tsExitMark)
		n.W("}")
	case "srcnat":
		n.W("oifname \"tailscale0\" meta mark & %s == %s masquerade comment \"ts-exit\"", tsExitMark, tsExitMark)
	}
}
