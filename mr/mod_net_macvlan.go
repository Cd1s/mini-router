package main

// net module: several PPPoE sessions on one port, each with its own MAC (Cd1s/mini-router#114).
// BRAS key sessions by MAC: a second session on the port's MAC may be ended when the other one starts or
// ends. A PPPoE WAN whose link device (device[.vlan]) an earlier WAN already uses and whose mac differs
// from that WAN's dials on a macvlan mv-<name> (mode private, IPv6 off, no addresses) with that MAC.
// Without a mac it shares the port's MAC as before (`mr doctor` warns). Flows over the macvlan are
// offloaded to the PPE by the kernel patch build/m3/patches/992-net-macvlan-add-ndo_fill_forward_path.

import (
	"crypto/sha256"
	"fmt"
	"net"
	"strings"
)

// wanPrimary: the first WAN on w's link device (w itself when it is the first).
func wanPrimary(c *Config, w WAN) WAN {
	for _, o := range c.WAN {
		if o.LinkDev() == w.LinkDev() {
			return o
		}
	}
	return w
}

// wanMacvlan: the macvlan a PPPoE WAN dials on ("" = the link device itself).
func wanMacvlan(c *Config, w WAN) string {
	p := wanPrimary(c, w)
	if w.Proto != "pppoe" || w.MAC == "" || p.Name == w.Name || strings.EqualFold(w.MAC, p.MAC) {
		return ""
	}
	return "mv-" + w.Name
}

// wanNic: the ethernet device pppd runs PPPoE discovery on.
func wanNic(c *Config, w WAN) string {
	if mv := wanMacvlan(c, w); mv != "" {
		return mv
	}
	return w.LinkDev()
}

// wanSharesMAC: a PPPoE WAN that shares its port's MAC with an earlier PPPoE WAN on the same link device.
func wanSharesMAC(c *Config, w WAN) bool {
	p := wanPrimary(c, w)
	return w.Proto == "pppoe" && p.Proto == "pppoe" && p.Name != w.Name && wanMacvlan(c, w) == ""
}

// wanPortMAC: the MAC of w's port: the first WAN's mac on the link device, else the device's own.
func wanPortMAC(c *Config, w WAN, read func(string) string) string {
	if p := wanPrimary(c, w); p.MAC != "" {
		return strings.ToLower(p.MAC)
	}
	return strings.ToLower(strings.TrimSpace(read("/sys/class/net/" + w.Device + "/address")))
}

// wanMACSuggest: a stable locally administered unicast MAC for WAN name on a port whose MAC is portMAC
// (02 + bytes 1..5 of sha256("<portMAC> <name>")).
func wanMACSuggest(portMAC, name string) string {
	h := sha256.Sum256([]byte(portMAC + " " + name))
	h[0] = 0x02
	return net.HardwareAddr(h[:6]).String()
}

// unicastMAC: a parseable, non-zero, non-multicast MAC.
func unicastMAC(s string) bool {
	hw, err := net.ParseMAC(s)
	return err == nil && len(hw) == 6 && hw[0]&1 == 0 && hw.String() != "00:00:00:00:00:00"
}

// macvlanSh (network.sh, links phase, after the WAN link devices): removes macvlans the config no longer
// wants, then creates each wanted one, or recreates it when its lower device, MAC or mode differ (the
// peers file names the MAC, so its pppd is restarted by the same apply).
func macvlanSh(c *Config, b *strings.Builder, need map[string]int) {
	var keep []string
	for _, w := range c.WAN {
		if mv := wanMacvlan(c, w); mv != "" {
			keep = append(keep, mv)
		}
	}
	fmt.Fprintf(b, "for d in /sys/class/net/mv-*; do n=${d##*/}; case \" %s \" in *\" $n \"*) continue;; esac; case \"$(ip -d -o link show \"$n\" 2>/dev/null)\" in *\" macvlan mode \"*) ip link del \"$n\";; esac; done\n",
		strings.Join(keep, " "))
	if len(keep) == 0 {
		return
	}
	b.WriteString("modprobe -q macvlan 2>/dev/null\n")
	for _, w := range c.WAN {
		mv := wanMacvlan(c, w)
		if mv == "" {
			continue
		}
		mac, low := strings.ToLower(w.MAC), w.LinkDev()
		fmt.Fprintf(b, "case \"$(ip -d -o link show %s 2>/dev/null)\" in *\"%s@%s:\"*\"link/ether %s \"*\" macvlan mode private \"*) ;; *) ip link del %s 2>/dev/null; ip link add link %s name %s address %s type macvlan mode private;; esac\n",
			mv, mv, low, mac, mv, low, mv, mac)
		fmt.Fprintf(b, "echo 1 2>/dev/null > /proc/sys/net/ipv6/conf/%s/disable_ipv6\n", mv)
		if m := need[low]; m > 0 { // RFC 4638: the same link MTU as the lower device
			fmt.Fprintf(b, "ip link set dev %s mtu %d\n", mv, m)
		}
		fmt.Fprintf(b, "ip link set %s up\n", mv)
	}
}

// docWANMACs (mr doctor, wan): PPPoE sessions that share a MAC — on one port (no own mac), or on
// different ports of one account (DSA ports inherit the conduit's MAC).
func docWANMACs(c *Config, e *docEnv) []docFinding {
	var out []docFinding
	byAcct := map[string]string{} // username + effective MAC -> WAN
	for i, w := range c.WAN {
		if w.Proto != "pppoe" {
			continue
		}
		if wanSharesMAC(c, w) {
			p := wanPrimary(c, w)
			out = append(out, docFinding{ID: "wan.mac." + w.Name, Sev: "warn", Title: "WAN " + w.Name, NoEvent: true,
				Detail: fmt.Sprintf("shares %s's MAC on device %s: ISPs often end one session when the other starts or ends", p.Name, w.LinkDev()),
				Fix:    fmt.Sprintf("set wan[%d].mac, e.g. %s (mr wan mac %s): it dials on its own macvlan", i, wanMACSuggest(wanPortMAC(c, w, e.read), w.Name), w.Name)})
			continue
		}
		mac := strings.ToLower(w.MAC)
		if wanMacvlan(c, w) == "" {
			mac = wanPortMAC(c, w, e.read)
		}
		k := w.Username + " " + mac
		if o, ok := byAcct[k]; ok && mac != "" && w.LinkDev() != c.WANByName(o).LinkDev() {
			out = append(out, docFinding{ID: "wan.mac." + w.Name, Sev: "warn", Title: "WAN " + w.Name, NoEvent: true,
				Detail: fmt.Sprintf("dials the same account as %s with the same MAC %s on another port", o, mac),
				Fix:    fmt.Sprintf("give one of them its own wan[].mac, e.g. %s", wanMACSuggest(mac, w.Name))})
		}
		byAcct[k] = w.Name
	}
	return out
}
