package main

// DNS sovereignty (Cd1s/mini-router#45): keep LAN devices on the router's DNS, which local names,
// the DNS split, policy routes by domain and the proxy's fake-ip split all depend on.
//
//	firefox_canary      use-application-dns.net answers NXDOMAIN: Firefox does not switch DoH on by
//	                    itself (default on; a user who turns DoH on explicitly keeps it)
//	private_relay       block: mask.icloud.com / mask-h2.icloud.com answer NXDOMAIN, so iCloud Private
//	                    Relay stays off on this network and the device says so (default allow)
//	block_dot           LAN → port 853 (DNS over TLS / QUIC) refused: apps and devices that try DoT fall
//	                    back to the router's DNS
//	doh_blocklist_file  one IP or CIDR per line (# comments): LAN → port 443 of these public DoH
//	                    resolvers refused (TCP and HTTP/3)
//
// The refusals are a chain of their own at prerouting priority mangle - 1: before the policy marks
// (mangle + 1) and the proxy's tproxy (mangle + 5), so a resolver inside a proxied range is refused
// too instead of being tunnelled. Both dnsmasq instances (main, proxy) answer the NXDOMAIN names.

import (
	"fmt"
	"net/netip"
)

type DNSSovereignty struct {
	FirefoxCanary *bool  `yaml:"firefox_canary"` // default on
	PrivateRelay  string `yaml:"private_relay"`  // allow (default) | block
	BlockDoT      bool   `yaml:"block_dot"`
	DoHBlocklist  string `yaml:"doh_blocklist_file"`
}

const dohBlocklistMax = 65536

// dnsLocalOnly: names dnsmasq answers NXDOMAIN itself (never forwarded), for both instances.
func dnsLocalOnly(c *Config) []string {
	s := &c.DNS.Sovereignty
	var out []string
	if on(s.FirefoxCanary) {
		out = append(out, "local=/use-application-dns.net/")
	}
	if s.PrivateRelay == "block" {
		out = append(out, "local=/mask.icloud.com/", "local=/mask-h2.icloud.com/")
	}
	return out
}

// dohBlocklist reads doh_blocklist_file. strict (render): an unreadable file, a bad line or too many
// entries is an error naming the file and line, never its content. Otherwise (nftables hook, which
// cannot fail) whatever cannot be used is skipped.
func dohBlocklist(c *Config, strict bool) (v4, v6 []netip.Prefix, err error) {
	path := c.DNS.Sovereignty.DoHBlocklist
	if path == "" {
		return nil, nil, nil
	}
	lines, nums, err := proxyReadList(path)
	if err != nil {
		if strict {
			return nil, nil, fmt.Errorf("dns.sovereignty.doh_blocklist_file: %w", err)
		}
		return nil, nil, nil
	}
	for i, l := range lines {
		p, err := netip.ParsePrefix(l)
		if err != nil {
			a, aerr := netip.ParseAddr(l)
			if aerr != nil || a.Zone() != "" {
				if strict {
					return nil, nil, fmt.Errorf("dns.sovereignty.doh_blocklist_file: %s line %d: not an IP address or CIDR", path, nums[i])
				}
				continue
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		if p.Addr().Is4In6() && p.Bits() >= 96 { // ::ffff:192.0.2.1 is 192.0.2.1
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		if p = p.Masked(); p.Addr().Is4() {
			v4 = append(v4, p)
		} else {
			v6 = append(v6, p)
		}
	}
	if len(v4)+len(v6) > dohBlocklistMax {
		if strict {
			return nil, nil, fmt.Errorf("dns.sovereignty.doh_blocklist_file: %s has %d entries, at most %d", path, len(v4)+len(v6), dohBlocklistMax)
		}
		return nil, nil, nil
	}
	return v4, v6, nil
}

func sovereigntyValidate(c *Config, v *Validator) {
	s := &c.DNS.Sovereignty
	switch s.PrivateRelay {
	case "", "allow", "block":
	default:
		v.Add("dns.sovereignty.private_relay: allow|block, got %q", s.PrivateRelay)
	}
	if s.DoHBlocklist != "" && !rePath.MatchString(s.DoHBlocklist) {
		v.Add("dns.sovereignty.doh_blocklist_file: absolute path required, got %q", s.DoHBlocklist)
	}
}

// sovereigntyNft: the refusals (see the top of this file), declared at the "defs" hook.
func sovereigntyNft(c *Config, n *Nft) {
	s := &c.DNS.Sovereignty
	v4, v6, _ := dohBlocklist(c, false)
	if !s.BlockDoT && len(v4)+len(v6) == 0 {
		return
	}
	if len(v4) > 0 {
		n.W("set doh4 {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t\tauto-merge\n\t\telements = { %s }\n\t}", nftElems(v4))
	}
	if len(v6) > 0 {
		n.W("set doh6 {\n\t\ttype ipv6_addr\n\t\tflags interval\n\t\tauto-merge\n\t\telements = { %s }\n\t}", nftElems(v6))
	}
	n.W("chain dns_guard {\n\t\ttype filter hook prerouting priority mangle - 1; policy accept;")
	n.W("\tiifname != { %s } return", quoteList(c.LANBridges()))
	n.W("\tfib daddr type local return")
	if s.BlockDoT {
		n.W("\ttcp dport 853 counter reject with tcp reset comment \"dns: DoT refused\"")
		n.W("\tudp dport 853 counter reject comment \"dns: DoQ refused\"")
	}
	for _, x := range []struct {
		set, match string
		n          int
	}{{"doh4", "ip daddr", len(v4)}, {"doh6", "ip6 daddr", len(v6)}} {
		if x.n > 0 {
			n.W("\t%s @%s tcp dport 443 counter reject with tcp reset comment \"dns: DoH refused\"", x.match, x.set)
			n.W("\t%s @%s udp dport 443 counter reject comment \"dns: DoH3 refused\"", x.match, x.set)
		}
	}
	n.W("}")
}
