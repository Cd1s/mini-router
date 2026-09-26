package main

// dev module: per-device rate limits (devices[].limit, #33) — nftables policers in forward_first.
//
// Upload: packets from the device's MACs towards a WAN over the rate are dropped. Download: the device's
// addresses are learned from its own packets into @limN_4 / @limN_6 (like firewall.access) and packets
// from a WAN to them over the rate are dropped. The learned addresses also go into fw's @ac_4 / @ac_6,
// so the device's connections never enter the offload flowtable (a policer only sees CPU-path packets):
// a limited device loses hardware offload. One token bucket per device and direction (all its MACs and
// addresses share it); burst = 1/8 s of the rate. It is a policer, not a shaper: TCP settles a little
// below the limit, and traffic between LAN devices is not limited.

import "fmt"

// DevLimit: Mbit/s, 0 = no limit.
type DevLimit struct {
	Down int `yaml:"down,omitempty"`
	Up   int `yaml:"up,omitempty"`
}

const devLimitMax = 10000

// devLimited: indices of devices with a limit (none without a WAN: bypass / ap modes route nothing).
func devLimited(c *Config) []int {
	var out []int
	if len(c.WAN) == 0 {
		return nil
	}
	for i, d := range c.Devices {
		if d.Limit != nil && (d.Limit.Down > 0 || d.Limit.Up > 0) {
			out = append(out, i)
		}
	}
	return out
}

func devLimitValidate(v *Validator, p string, l *DevLimit) {
	if l == nil {
		return
	}
	if l.Down < 0 || l.Down > devLimitMax || l.Up < 0 || l.Up > devLimitMax {
		v.Add("%s.limit: down / up in Mbit/s, 0-%d", p, devLimitMax)
	}
}

// devLimitRate: an nft limit for mbit Mbit/s (kbytes/second, burst 1/8 s).
func devLimitRate(mbit int) string {
	kb := mbit * 125
	return fmt.Sprintf("limit rate over %d kbytes/second burst %d kbytes", kb, max(kb/8, 16))
}

func devNft(c *Config, hook string, n *Nft) {
	ls := devLimited(c)
	if len(ls) == 0 {
		return
	}
	switch hook {
	case "defs":
		for _, i := range ls {
			n.W("set lim%d_4 { type ipv4_addr; size 256; flags dynamic,timeout; timeout 6h; }", i)
			n.W("set lim%d_6 { type ipv6_addr; size 256; flags dynamic,timeout; timeout 6h; }", i)
		}
	case "forward_first":
		lans := "{ " + quoteList(c.LANBridges()) + " }"
		wans := "{ " + quoteList(c.WANIfnames()) + " }"
		for _, i := range ls {
			d := c.Devices[i]
			macs := nftSet(lowerAll(d.MACs))
			cm := fmt.Sprintf("%q", "limit:"+d.Name)
			n.W("iifname %s ether saddr %s update @ac_4 { ip saddr } update @lim%d_4 { ip saddr }", lans, macs, i)
			n.W("iifname %s ether saddr %s update @ac_6 { ip6 saddr } update @lim%d_6 { ip6 saddr }", lans, macs, i)
			if d.Limit.Up > 0 {
				n.W("iifname %s ether saddr %s oifname %s %s drop comment %s", lans, macs, wans, devLimitRate(d.Limit.Up), cm)
			}
			if d.Limit.Down > 0 {
				n.W("iifname %s ip daddr @lim%d_4 %s drop comment %s", wans, i, devLimitRate(d.Limit.Down), cm)
				n.W("iifname %s ip6 daddr @lim%d_6 %s drop comment %s", wans, i, devLimitRate(d.Limit.Down), cm)
			}
		}
	}
}
