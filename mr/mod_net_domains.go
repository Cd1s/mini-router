package main

// net module: policy routes by domain (policy_routes[].domains / domains_file). Docs: docs/modules/net.md.
//
// Nothing new runs: dnsmasq (the main one and the proxy module's second instance) puts every address
// its upstream answers for a listed name (or a subdomain) into the policy's nft sets @pr_<i>_4 /
// @pr_<i>_6 (nftset=); the policy rule in mark_pre marks NEW connections to those addresses with the
// WAN's fwmark, like every other policy route. The connection then keeps its WAN through the ct mark
// and goes into the flowtable (PPE / WED) like any other: only its first packet is looked up.
//
//   - dnsmasq adds addresses only from upstream replies (not from its cache) and never removes them;
//     the sets time them out (policyDomainTTL) and a new connection to a learned address restarts its
//     timer (`update` in the rule), so addresses in use never drop out while cached answers still point
//     at them.
//   - Every firewall reload (apply, PPPoE up/down, health changes) replaces the table and with it the
//     sets; fwLoad refills them in the same transaction with what they held (policyDomainCarry), unless
//     the policy's domain list changed (the set comment carries a hash of it): addresses of a removed
//     domain must not stay on the WAN just because they keep being used.
//   - The dnsmasq build must have nftset support (Alpine: dnsmasq-dnssec-nftset); without it dnsmasq
//     refuses the config and the apply rolls back.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
)

const (
	policyDomainTTL  = "1d"  // a learned address leaves the set after a day without new connections
	policyDomainSize = 16384 // per set and family (bounds kernel memory: ~100 bytes per address)
	policyDomainMax  = 16    // policies with domains (keeps every nftset= line below dnsmasq's 1024 bytes)
)

// policyDomainSet is one policy's expanded domain list.
type policyDomainSet struct {
	idx     int      // index in policy_routes (names the sets)
	domains []string // normalized, deduplicated, sorted
	fams    []int    // address families the policy's rule covers
	gen     string   // hash of domains: a changed list gets fresh sets
}

// policySet names the nft set of policy i for one address family.
func policySet(i, fam int) string { return fmt.Sprintf("pr_%d_%d", i, fam) }

func (pd policyDomainSet) comment() string { return "domains " + pd.gen }

// policyFams: the address families a policy's rule covers (src / dst decide; otherwise both).
func policyFams(p Policy) []int {
	for _, s := range []string{p.Src, p.Dst} {
		if n, ok := parseIPOrCIDR(s); s != "" && ok {
			return []int{family(n)}
		}
	}
	return []int{4, 6}
}

// policyDomains expands the domain lists of every policy that has one. strict (render): an unreadable
// file, a bad line or an empty list is an error. Non-strict (nftables / dnsmasq renderers, which cannot
// fail): what cannot be used is skipped, but the policy keeps its (possibly empty) sets, so its rule
// never turns into one that matches every destination.
func policyDomains(c *Config, strict bool) ([]policyDomainSet, error) {
	var out []policyDomainSet
	for i, p := range c.Policy {
		if !p.byDomain() {
			continue
		}
		where := fmt.Sprintf("policy_routes[%d] (%s)", i, p.Name)
		seen := map[string]bool{}
		var ds []string
		add := func(s string) bool {
			d, ok := proxyNormDomain(s)
			if ok && !seen[d] {
				seen[d] = true
				ds = append(ds, d)
			}
			return ok
		}
		for _, d := range p.Domains {
			if !add(d) && strict {
				return nil, fmt.Errorf("%s: invalid domain %q", where, d)
			}
		}
		if p.DomainsFile != "" {
			lines, nums, err := proxyReadList(p.DomainsFile)
			if err != nil && strict {
				return nil, fmt.Errorf("%s: domains_file: %v", where, err)
			}
			for k, l := range lines {
				// error messages name the line, never echo file content
				if !add(l) && strict {
					return nil, fmt.Errorf("%s: %s line %d: not a domain", where, p.DomainsFile, nums[k])
				}
			}
		}
		if len(ds) == 0 && strict {
			return nil, fmt.Errorf("%s: no domains (domains / domains_file)", where)
		}
		sort.Strings(ds)
		h := sha256.Sum256([]byte(strings.Join(ds, "\n")))
		out = append(out, policyDomainSet{idx: i, domains: ds, fams: policyFams(p), gen: hex.EncodeToString(h[:6])})
	}
	return out, nil
}

// policyDomainDefs: the nft sets (defs hook). dynamic: the rule's `update` restarts an address's timer
// (with the set's timeout, also for an address carried over with less time left).
func policyDomainDefs(c *Config, n *Nft) {
	pds, _ := policyDomains(c, false)
	for _, pd := range pds {
		for _, fam := range pd.fams {
			typ := "ipv4_addr"
			if fam == 6 {
				typ = "ipv6_addr"
			}
			n.W("set %s { type %s; size %d; flags dynamic,timeout; timeout %s; comment %q; }",
				policySet(pd.idx, fam), typ, policyDomainSize, policyDomainTTL, pd.comment())
		}
	}
}

// policyNftsetLines: dnsmasq nftset= lines for every policy with domains ("inet mr" sets; "4#" / "6#"
// keeps each family out of the other's set). skip leaves domains out (the proxy module's dnsmasq: names
// it sends to sing-box get fake-ip answers, which are no destination to route).
//
// dnsmasq uses only the most specific nftset= line that matches a query, so a domain's line also names
// the sets of every policy that lists one of its parent domains: each set holds the addresses of its
// domains and all their subdomains, whichever policy lists the subdomain too. Domains with the same
// sets share lines (less dnsmasq memory), each line below dnsmasq's 1024-byte line limit.
func policyNftsetLines(c *Config, skip func(string) bool) []string {
	pds, _ := policyDomains(c, false)
	own := map[string][]int{} // domain -> positions in pds
	for k, pd := range pds {
		for _, d := range pd.domains {
			own[d] = append(own[d], k)
		}
	}
	groups := map[string][]string{} // set list -> domains
	for d := range own {
		if skip != nil && skip(d) {
			continue
		}
		var ks []int
		for p := d; ; {
			ks = append(ks, own[p]...)
			i := strings.IndexByte(p, '.')
			if i < 0 {
				break
			}
			p = p[i+1:]
		}
		sort.Ints(ks)
		var refs []string
		for j, k := range ks {
			if j > 0 && ks[j-1] == k {
				continue
			}
			for _, fam := range pds[k].fams {
				refs = append(refs, fmt.Sprintf("%d#inet#mr#%s", fam, policySet(pds[k].idx, fam)))
			}
		}
		key := strings.Join(refs, ",")
		groups[key] = append(groups[key], d)
	}
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []string
	for _, key := range keys {
		ds := groups[key]
		sort.Strings(ds)
		line := ""
		for _, d := range ds {
			if line != "" && len(line)+len(d)+len(key)+2 > 1000 {
				out = append(out, line+"/"+key)
				line = ""
			}
			if line == "" {
				line = "nftset=/" + d
			} else {
				line += "/" + d
			}
		}
		out = append(out, line+"/"+key)
	}
	return out
}

// policyDnsmasq: the main dnsmasq's lines (Module.Dnsmasq).
func policyDnsmasq(c *Config) []string {
	lines := policyNftsetLines(c, nil)
	if len(lines) == 0 {
		return nil
	}
	return append([]string{"# policy_routes domains -> nft sets (route by domain)"}, lines...)
}

// policyDomainCarry: `add element` commands that put the addresses the loaded domain sets hold back
// into the new ruleset's sets (fwLoad runs them in the same transaction as the ruleset).
func policyDomainCarry(c *Config) string {
	pds, _ := policyDomains(c, false)
	var b strings.Builder
	for _, pd := range pds {
		for _, fam := range pd.fams {
			set := policySet(pd.idx, fam)
			if out, err := run("nft", "-j", "list", "set", "inet", "mr", set); err == nil {
				b.WriteString(policyCarryScript(set, fam, pd.comment(), []byte(out)))
			}
		}
	}
	return b.String()
}

// policyCarryScript: the addresses of a loaded set (`nft -j list set` output) with their remaining
// lifetime, as one `add element` command — only if the loaded set was made for the same domain list
// (same comment); "" otherwise. Addresses are re-parsed before they reach the script.
func policyCarryScript(set string, fam int, comment string, js []byte) string {
	var doc struct {
		Nftables []struct {
			Set *struct {
				Comment string `json:"comment"`
			} `json:"set"`
		} `json:"nftables"`
	}
	if json.Unmarshal(js, &doc) != nil {
		return ""
	}
	same := false
	for _, it := range doc.Nftables {
		if it.Set != nil {
			same = it.Set.Comment == comment
		}
	}
	if !same {
		return ""
	}
	var xs []string
	for _, e := range fwSetElems(js) {
		ip := net.ParseIP(e.Val)
		if ip == nil || (ip.To4() != nil) != (fam == 4) {
			continue
		}
		xs = append(xs, fmt.Sprintf("%s timeout %ds", ip, e.Expires))
	}
	if len(xs) == 0 {
		return ""
	}
	return fmt.Sprintf("add element inet mr %s { %s }\n", set, strings.Join(xs, ", "))
}
