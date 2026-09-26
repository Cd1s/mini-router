package main

// Local DNS records (dns.records): names for home servers answered by dnsmasq itself.
//
//	A / AAAA  name  -> host-record= (also answers the matching PTR); a name without a dot also gets
//	                   <name>.<dhcp.domain>; "*.example.com" -> address=/example.com/ip (the domain and
//	                   every subdomain)
//	CNAME     alias -> cname= (the target must be a name dnsmasq knows locally: a record, a DHCP host
//	                   or an addn-hosts entry — dnsmasq never chases a CNAME upstream)
//	PTR       ip or *.in-addr.arpa / *.ip6.arpa name -> ptr-record=
//	SRV       _service._proto.domain, value "target:port[:priority[:weight]]" -> srv-host=
//	TXT       name, value up to 255 characters -> txt-record= (quoted)

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"unicode/utf8"
)

type Record struct {
	Name  string `yaml:"name"`
	Type  string `yaml:"type"` // A | AAAA | CNAME | PTR | SRV | TXT
	Value string `yaml:"value"`
}

// recordNames: the owner names a record is published under (short names also get the local domain).
func recordNames(c *Config, name string) []string {
	if !strings.Contains(name, ".") && c.DHCP.Domain != "" {
		return []string{name, name + "." + c.DHCP.Domain}
	}
	return []string{name}
}

// localAnswerNames: full names the main dnsmasq answers itself — dns.records and the reverse proxy's hosts.
// The proxy's dnsmasq (which answers the LAN while the proxy is on) sends them there instead of upstream,
// and lets the private answers through its rebind protection.
func localAnswerNames(c *Config) []string {
	seen := map[string]bool{}
	var out []string
	add := func(n string) {
		n = strings.TrimPrefix(n, "*.")
		if strings.Contains(n, ".") && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	for _, r := range c.DNS.Records {
		if r.Type != "PTR" {
			add(r.Name)
		}
	}
	for _, h := range edgeLANHosts(c) {
		add(h)
	}
	return out
}

// reverseName converts an IP address to its in-addr.arpa / ip6.arpa name.
func reverseName(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", v4[3], v4[2], v4[1], v4[0])
	}
	const hexd = "0123456789abcdef"
	var b strings.Builder
	for i := len(ip) - 1; i >= 0; i-- {
		b.WriteByte(hexd[ip[i]&0xf])
		b.WriteByte('.')
		b.WriteByte(hexd[ip[i]>>4])
		b.WriteByte('.')
	}
	b.WriteString("ip6.arpa")
	return b.String()
}

// parseSRV splits "target:port[:priority[:weight]]".
func parseSRV(v string) (target string, port, prio, weight int, ok bool) {
	f := strings.Split(v, ":")
	if len(f) < 2 || len(f) > 4 || !validDNSName(f[0]) {
		return "", 0, 0, 0, false
	}
	nums := []int{0, 0, 0}
	for i, s := range f[1:] {
		n, err := strconv.Atoi(s)
		if err != nil || n < 0 || n > 65535 || strconv.Itoa(n) != s {
			return "", 0, 0, 0, false
		}
		nums[i] = n
	}
	if nums[0] == 0 {
		return "", 0, 0, 0, false
	}
	return f[0], nums[0], nums[1], nums[2], true
}

func validTXT(s string) bool {
	return s != "" && len(s) <= 255 && utf8.ValidString(s) && safeText(s) && !strings.ContainsAny(s, "\"\\")
}

func validRecords(c *Config, v *Validator) {
	if len(c.DNS.Records) > 2000 {
		v.Add("dns.records: at most 2000")
	}
	cnames := map[string]bool{}
	others := map[string]bool{}
	for i, r := range c.DNS.Records {
		p := fmt.Sprintf("dns.records[%d] (%s %s)", i, r.Type, r.Name)
		name := strings.ToLower(strings.TrimSuffix(r.Name, "."))
		switch r.Type {
		case "A", "AAAA":
			n := strings.TrimPrefix(name, "*.")
			if !validDNSName(n) {
				v.Add("%s: invalid name (letters, digits, '-', '_', dots; \"*.\" prefix for a wildcard)", p)
			} else if n == name && (strings.Trim(n, "0123456789") == "" || net.ParseIP(n) != nil) {
				// host-record= reads an all-digit field as a TTL and an address-shaped one as an address
				v.Add("%s: a name cannot be all digits or look like an IP address", p)
			}
			if r.Type == "A" && !isIPv4(r.Value) {
				v.Add("%s: value must be an IPv4 address, got %q", p, r.Value)
			}
			if r.Type == "AAAA" && !isIPv6(r.Value) {
				v.Add("%s: value must be an IPv6 address, got %q", p, r.Value)
			}
		case "CNAME":
			if !validDNSName(name) || strings.HasPrefix(name, "*") {
				v.Add("%s: invalid name", p)
			}
			if !validDNSName(r.Value) {
				v.Add("%s: target must be a host name, got %q", p, r.Value)
			} else if strings.EqualFold(strings.TrimSuffix(r.Value, "."), name) {
				v.Add("%s: points to itself", p)
			}
			if cnames[name] {
				v.Add("%s: duplicate CNAME", p)
			}
			cnames[name] = true
		case "PTR":
			ip := net.ParseIP(r.Name)
			if ip == nil && (!validDNSName(name) || !(strings.HasSuffix(name, ".in-addr.arpa") || strings.HasSuffix(name, ".ip6.arpa"))) {
				v.Add("%s: name must be an IP address or an in-addr.arpa / ip6.arpa name", p)
			}
			if !validDNSName(r.Value) {
				v.Add("%s: value must be a host name, got %q", p, r.Value)
			}
		case "SRV":
			if !validDNSName(name) || !strings.HasPrefix(name, "_") || !strings.Contains(name, "._") {
				v.Add("%s: name must look like _service._tcp.domain", p)
			}
			if _, _, _, _, ok := parseSRV(r.Value); !ok {
				v.Add("%s: value must be target:port[:priority[:weight]] (e.g. nas.lan:445), got %q", p, r.Value)
			}
		case "TXT":
			if !validDNSName(name) {
				v.Add("%s: invalid name", p)
			}
			if !validTXT(r.Value) {
				v.Add("%s: value must be 1-255 printable characters without \" or \\", p)
			}
		default:
			v.Add("dns.records[%d].type: A|AAAA|CNAME|PTR|SRV|TXT, got %q", i, r.Type)
			continue
		}
		if r.Type != "CNAME" && r.Type != "PTR" {
			for _, n := range recordNames(c, name) {
				others[n] = true
			}
		}
	}
	for n := range cnames {
		for _, x := range recordNames(c, n) {
			if others[x] {
				v.Add("dns.records: %s has a CNAME and other records (not allowed in DNS)", x)
			}
		}
	}
}

// recordLines renders dns.records into dnsmasq.conf lines (input already validated).
func recordLines(c *Config) []string {
	var out []string
	for _, r := range c.DNS.Records {
		name := strings.TrimSuffix(r.Name, ".")
		switch r.Type {
		case "A", "AAAA":
			if strings.HasPrefix(name, "*.") {
				out = append(out, fmt.Sprintf("address=/%s/%s", name[2:], r.Value))
			} else {
				out = append(out, fmt.Sprintf("host-record=%s,%s", strings.Join(recordNames(c, name), ","), r.Value))
			}
		case "CNAME":
			out = append(out, fmt.Sprintf("cname=%s,%s", strings.Join(recordNames(c, name), ","), strings.TrimSuffix(r.Value, ".")))
		case "PTR":
			if ip := net.ParseIP(name); ip != nil {
				name = reverseName(ip)
			}
			out = append(out, fmt.Sprintf("ptr-record=%s,%s", name, strings.TrimSuffix(r.Value, ".")))
		case "SRV":
			t, port, prio, weight, ok := parseSRV(r.Value)
			if ok {
				out = append(out, fmt.Sprintf("srv-host=%s,%s,%d,%d,%d", name, t, port, prio, weight))
			}
		case "TXT":
			out = append(out, fmt.Sprintf("txt-record=%s,\"%s\"", name, r.Value))
		}
	}
	return out
}
