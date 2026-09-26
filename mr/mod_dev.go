package main

// dev module: the device inventory (router.yaml devices, groups) and runtime pauses (mod_dev_pause.go).
//
// A device is a name for one or more MACs (a laptop's cable + WiFi, a phone's per-network private
// address), optionally with a fixed IPv4. Other sections refer to it by name instead of repeating
// MACs / addresses. Names are resolved when the config is validated and rendered; router.yaml is
// never rewritten, and the older keys (dhcp.hosts, macs, mac, IPv4 targets) keep working as before:
//
//	firewall.forwards[].to      a device with ip:          → its address
//	firewall.access[].devices   devices and group:NAME     → their MACs (next to macs:)
//	policy_routes[].device      a device or group:NAME     → ether saddr { its MACs } (instead of mac:)
//	proxy.bypass[].device       a device or group:NAME     → its MACs in @proxy_bypass (instead of mac:)
//	guard.always_bypass, sys.wol / mr wol, mr pause        device names
//
// An unknown name is a validation error at the place that uses it, so deleting a device that is
// still referenced lists every reference. dnsmasq: every device is one dhcp-host line
// (dhcp-host=MAC[,MAC…][,IP],NAME[,lease]) rendered by the dns module: the inventory name is the
// device's DHCP / DNS name, ip: makes it a static lease (like dhcp.hosts). A MAC, name or address
// may be in devices or in dhcp.hosts, not in both, so there is one source of truth per device.
// Owns: router.yaml devices, groups. Docs: docs/modules/dev.md.

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

// Device is one entry of the device inventory.
type Device struct {
	Name  string   `yaml:"name"`
	MACs  []string `yaml:"macs"`
	IP    string   `yaml:"ip,omitempty"`    // fixed IPv4: a static DHCP lease; forwards may use the name
	Type  string   `yaml:"type,omitempty"`  // free label: pc, phone, tablet, tv, console, iot, server, …
	Owner string   `yaml:"owner,omitempty"` // free label (the person)
	Desc  string   `yaml:"desc,omitempty"`
}

const (
	devMax      = 256 // devices (and members of one group)
	devMaxMACs  = 8
	devGroupMax = 32
)

var (
	// a DNS label that cannot be read as an IPv4 address, a MAC or a dnsmasq lease time
	reDevName  = lazyRegexp(`^[a-z]([a-z0-9-]{0,30}[a-z0-9])?$`)
	reDevLabel = lazyRegexp(`^[a-z0-9][a-z0-9_-]{0,15}$`)
)

func init() {
	register(&Module{
		Name:       "dev",
		Prio:       35,
		Validate:   devValidate,
		Status:     pauseStatus,
		TokenScope: map[string]string{"dev.paused": "read", "dev.pause": "operate", "dev.unpause": "operate"},
		API: map[string]func(r apiReq) apiResp{
			"dev.paused":  apiDevPaused,
			"dev.pause":   apiDevPause,
			"dev.unpause": apiDevUnpause,
		},
		Commands: map[string]func(c *Config, args []string) error{
			"pause":   pauseCommand,
			"unpause": unpauseCommand,
		},
	})
}

func devValidate(c *Config, v *Validator) {
	if len(c.Devices) > devMax {
		v.Add("devices: at most %d", devMax)
	}
	hostName, hostMAC, hostIP := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, h := range c.DHCP.Hosts {
		hostName[strings.ToLower(h.Name)] = h.Name != ""
		hostMAC[strings.ToLower(h.MAC)] = true
		hostIP[h.IP] = true
	}
	names, macs, ips := map[string]bool{}, map[string]string{}, map[string]string{}
	for i, d := range c.Devices {
		p := fmt.Sprintf("devices[%d]", i)
		switch {
		case !reDevName.MatchString(d.Name):
			v.Add("%s.name: lowercase letters, digits and - (1-32, starting with a letter), got %q", p, d.Name)
		case names[d.Name]:
			v.Add("%s.name: duplicate %q", p, d.Name)
		case hostName[d.Name]:
			v.Add("%s.name: %q is also a dhcp.hosts name", p, d.Name)
		}
		names[d.Name] = true
		if len(d.MACs) == 0 || len(d.MACs) > devMaxMACs {
			v.Add("%s.macs: 1-%d MACs", p, devMaxMACs)
		}
		for _, m := range d.MACs {
			l := strings.ToLower(m)
			switch hw, err := net.ParseMAC(m); {
			case !reMAC.MatchString(m) || err != nil:
				v.Add("%s.macs: invalid %q", p, m)
				continue
			case hw[0]&1 != 0:
				v.Add("%s.macs: %s is not a unicast MAC", p, m)
			case macs[l] != "":
				v.Add("%s.macs: %s is also in device %s", p, m, macs[l])
			case hostMAC[l]:
				v.Add("%s.macs: %s is also in dhcp.hosts (keep each device in one place)", p, m)
			}
			macs[l] = d.Name
		}
		if d.IP != "" {
			if e := fwCheckTarget(c, d.IP); e != "" {
				v.Add("%s.ip: an IPv4 inside a LAN-side network, got %q: %s", p, d.IP, e)
			} else if ips[d.IP] != "" {
				v.Add("%s.ip: %s is also the address of device %s", p, d.IP, ips[d.IP])
			} else if hostIP[d.IP] {
				v.Add("%s.ip: %s is also in dhcp.hosts", p, d.IP)
			}
			ips[d.IP] = d.Name
		}
		if d.Type != "" && !reDevLabel.MatchString(d.Type) {
			v.Add("%s.type: a short label (lowercase letters, digits, _ -; max 16), got %q", p, d.Type)
		}
		if !safeText(d.Owner) || len(d.Owner) > 40 {
			v.Add("%s.owner: max 40 characters, no control characters", p)
		}
		fwCheckDesc(v, p, d.Desc)
	}
	if len(c.Groups) > devGroupMax {
		v.Add("groups: at most %d", devGroupMax)
	}
	for _, g := range devGroupNames(c) {
		if !reName.MatchString(g) {
			v.Add("groups: name %q: lowercase letters, digits, _ - (1-15, starting with a letter)", g)
			continue
		}
		members := c.Groups[g]
		if len(members) == 0 || len(members) > devMax {
			v.Add("groups.%s: 1-%d devices", g, devMax)
		}
		seen := map[string]bool{}
		for _, m := range members {
			if c.device(m) == nil {
				v.Add("groups.%s: unknown device %q (devices:)", g, m)
			} else if seen[m] {
				v.Add("groups.%s: duplicate %q", g, m)
			}
			seen[m] = true
		}
	}
}

func devGroupNames(c *Config) []string {
	out := make([]string, 0, len(c.Groups))
	for g := range c.Groups {
		out = append(out, g)
	}
	sort.Strings(out)
	return out
}

// device returns the inventory entry named name (nil if there is none).
func (c *Config) device(name string) *Device {
	for i := range c.Devices {
		if c.Devices[i].Name == name {
			return &c.Devices[i]
		}
	}
	return nil
}

// devRefMACs resolves one reference — a device name or group:NAME — to lowercase MACs; ok is false
// when it names nothing.
func devRefMACs(c *Config, ref string) ([]string, bool) {
	if g, isGroup := strings.CutPrefix(ref, "group:"); isGroup {
		members, ok := c.Groups[g]
		if !ok {
			return nil, false
		}
		var out []string
		for _, m := range members {
			if d := c.device(m); d != nil {
				out = append(out, lowerAll(d.MACs)...)
			}
		}
		return dedup(out), true
	}
	if d := c.device(ref); d != nil {
		return lowerAll(d.MACs), true
	}
	return nil, false
}

// devMACs: the MACs of every reference (unknown ones contribute nothing; validation reports them).
func devMACs(c *Config, refs []string) []string {
	var out []string
	for _, r := range refs {
		m, _ := devRefMACs(c, r)
		out = append(out, m...)
	}
	return dedup(out)
}

// devCheckRefs reports every reference in refs that names no device / group, at path p.
func devCheckRefs(c *Config, v *Validator, p string, refs []string) {
	for _, r := range refs {
		if _, ok := devRefMACs(c, r); ok {
			continue
		}
		if strings.HasPrefix(r, "group:") {
			v.Add("%s: unknown group %q (groups:)", p, r)
		} else {
			v.Add("%s: unknown device %q (devices:)", p, r)
		}
	}
}

// devHostIP: the address a target names — a device's ip, anything else as it is.
func devHostIP(c *Config, s string) string {
	if d := c.device(s); d != nil {
		return d.IP
	}
	return s
}

// knownHosts: dhcp.hosts plus one entry per MAC of every device (IP empty when it has none) — the
// names and fixed addresses the router knows, for neighbour hints, names in lists and events.
func (c *Config) knownHosts() []Host {
	out := append([]Host{}, c.DHCP.Hosts...)
	for _, d := range c.Devices {
		for _, m := range d.MACs {
			out = append(out, Host{Name: d.Name, MAC: m, IP: d.IP})
		}
	}
	return out
}

// devDHCPHosts: one dnsmasq dhcp-host line per device — its MACs, the fixed address if any, the name
// and the per-host lease time from dhcp.host_leases (the first of its MACs that has one).
func devDHCPHosts(c *Config) []string {
	var out []string
	for _, d := range c.Devices {
		parts := lowerAll(d.MACs)
		if d.IP != "" {
			parts = append(parts, d.IP)
		}
		parts = append(parts, d.Name)
		for _, m := range d.MACs {
			if l := hostLease(c, m); l != "" {
				parts = append(parts, l)
				break
			}
		}
		out = append(out, "dhcp-host="+strings.Join(parts, ","))
	}
	return out
}
