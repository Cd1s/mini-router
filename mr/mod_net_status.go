package main

// net module: status JSON, post-apply verification and web UI API. Everything is computed on
// demand from /sys, iproute2 JSON and the small state files the hooks write — no daemon.

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// sysNet is /sys/class/net (a variable so tests can point it at a fake tree).
var sysNet = "/sys/class/net"

func sysRead(dev, attr string) string {
	return strings.TrimSpace(readFile(filepath.Join(sysNet, dev, attr)))
}

func carrier(dev string) bool { return sysRead(dev, "carrier") == "1" }

type wanStatus struct {
	Name   string   `json:"name"`
	Proto  string   `json:"proto"`
	Up     bool     `json:"up"`
	IP     string   `json:"ip"`
	Dev    string   `json:"dev"`
	RX     uint64   `json:"rx"`
	TX     uint64   `json:"tx"`
	Uptime int64    `json:"uptime"`
	Health string   `json:"health,omitempty"` // up | down (multiwan health checker)
	RTT    *float64 `json:"rtt_ms,omitempty"`
}

func netStatus(c *Config, st map[string]any) {
	health := map[string]wanHealth{}
	if c.MultiWAN.Enabled() {
		if f, ok := readWanHealth(); ok {
			for _, h := range f.WANs {
				health[h.Name] = h
			}
		}
	}
	var wans []wanStatus
	for _, w := range c.WAN {
		dev := w.Ifname()
		ws := wanStatus{Name: w.Name, Proto: w.Proto, Dev: dev}
		if a := ipv4Addrs(dev); len(a) > 0 {
			ws.Up = true
			ws.IP = strings.SplitN(a[0], "/", 2)[0]
		}
		ws.RX = uint64(atoi(sysRead(dev, "statistics/rx_bytes")))
		ws.TX = uint64(atoi(sysRead(dev, "statistics/tx_bytes")))
		if ws.Up {
			if l, ok := readLease(w.Name); ok && l.Since > 0 {
				ws.Uptime = time.Now().Unix() - l.Since
			} else if fi, err := os.Stat(filepath.Join(sysNet, dev)); err == nil {
				ws.Uptime = int64(time.Since(fi.ModTime()).Seconds())
			}
		}
		if h, ok := health[w.Name]; ok {
			ws.Health, ws.RTT = h.State, h.RTT
		}
		wans = append(wans, ws)
	}
	st["wan"] = wans
	if c.MultiWAN.Enabled() {
		st["multiwan"] = c.MultiWAN.Mode
	}
}

func netVerify(c *Config, restarted []string) []string {
	var errs []string
	deadline := verifyDeadline()
	for _, s := range restarted {
		if s == "mr-network" { // network.sh ran again: did every link take its MTU?
			errs = append(errs, linkMTUErrors(c)...)
		}
		var w *WAN
		what := ""
		switch {
		case strings.HasPrefix(s, "mr-pppoe."):
			w, what = c.WANByName(strings.TrimPrefix(s, "mr-pppoe.")), "PPPoE did not come up"
		case strings.HasPrefix(s, "mr-udhcpc."):
			w, what = c.WANByName(strings.TrimPrefix(s, "mr-udhcpc.")), "no DHCP lease"
			// Only roll back when this leaves the router without internet: no cable means nothing to wait
			// for, and a backup DHCP WAN (e.g. next to PPPoE on the same port for travelling) may have no
			// server while another WAN is up. The client keeps trying in the background either way.
			if w != nil && (!carrier(w.LinkDev()) || otherWANUp(c, w.Name)) {
				continue
			}
		}
		if w != nil && !waitFor(deadline, func() bool { return hasIPv4(w.Ifname()) }) {
			errs = append(errs, w.Name+": "+what+" within 90s")
		}
	}
	return errs
}

// linkMTUErrors: WAN devices that network.sh had to raise above 1500 (e.g. 1508 for a PPPoE mtu of
// 1500, RFC 4638) but that are below that now: the network card or its driver refused it, and pppd
// would quietly stay at 1492. The apply is rolled back instead of keeping a setting this hardware
// cannot do.
func linkMTUErrors(c *Config) []string {
	need := wanLinkMTUs(c)
	var devs []string
	for d := range need {
		devs = append(devs, d)
	}
	sort.Strings(devs)
	var errs []string
	for _, d := range devs {
		if got := atoi(sysRead(d, "mtu")); need[d] > 1500 && got > 0 && got < need[d] {
			errs = append(errs, fmt.Sprintf("%s: MTU %d, router.yaml needs %d there and the device refused it (PPPoE: use mtu 1492)", d, got, need[d]))
		}
	}
	return errs
}

// otherWANUp reports whether a WAN other than name has an IPv4 address right now.
func otherWANUp(c *Config, name string) bool {
	for _, w := range c.WAN {
		if w.Name != name && len(ipv4Addrs(w.Ifname())) > 0 {
			return true
		}
	}
	return false
}

// ---- web UI API ----

// ipJSON runs `ip -j ...` and returns the decoded result (nil on error).
func ipJSON(args ...string) any {
	out, err := exec.Command("ip", append([]string{"-j"}, args...)...).Output()
	if err != nil {
		return nil
	}
	var v any
	if json.Unmarshal(out, &v) != nil {
		return nil
	}
	return v
}

// apiNet: raw iproute2 view (links with counters, addresses, routes, rules, neighbours).
func apiNet() apiResp {
	return apiResp{body: map[string]any{
		"links":  ipJSON("-s", "link", "show"),
		"addrs":  ipJSON("addr", "show"),
		"route4": ipJSON("-4", "route", "show", "table", "all"),
		"route6": ipJSON("-6", "route", "show", "table", "all"),
		"rules4": ipJSON("-4", "rule", "show"),
		"rules6": ipJSON("-6", "rule", "show"),
		"neigh":  ipJSON("neigh", "show"),
	}}
}

// apiNetRoutes: just the routing state (routes of every table + rules), for the routing pages.
func apiNetRoutes() apiResp {
	body := map[string]any{
		"route4": ipJSON("-4", "route", "show", "table", "all"),
		"route6": ipJSON("-6", "route", "show", "table", "all"),
		"rules4": ipJSON("-4", "rule", "show"),
		"rules6": ipJSON("-6", "rule", "show"),
	}
	if c, err := loadConfig(ConfigPath, SecretsPath); err == nil {
		body["learned"] = policyLearned(c)
	}
	return apiResp{body: body}
}

// policyLearned: how many destination addresses each domain policy has learned so far, per family
// (the sets dnsmasq fills; Cd1s/mini-router#64). A set that cannot be read counts as absent.
func policyLearned(c *Config) map[string]map[string]int {
	out := map[string]map[string]int{}
	for i, p := range c.Policy {
		if !p.byDomain() {
			continue
		}
		m := map[string]int{}
		for _, fam := range policyFams(p) {
			if b, err := run("nft", "-j", "list", "set", "inet", "mr", policySet(i, fam)); err == nil {
				m[fmt.Sprintf("v%d", fam)] = len(fwSetElems([]byte(b)))
			}
		}
		out[p.Name] = m
	}
	return out
}

// portInfo is one netdev as the port panel / interface table shows it.
type portInfo struct {
	Name      string `json:"name"`
	Kind      string `json:"kind"` // port | cpu | bridge | vlan | ppp | wifi | tunnel | other
	Role      string `json:"role,omitempty"`
	AdminUp   bool   `json:"admin_up"`
	Carrier   bool   `json:"carrier"`
	Oper      string `json:"oper"`
	OperRaw   string `json:"oper_raw,omitempty"` // the kernel's operstate when Oper was derived from the flags (ppp, tun)
	Speed     int    `json:"speed,omitempty"`    // Mbit/s
	Duplex    string `json:"duplex,omitempty"`
	MTU       int    `json:"mtu"`
	MAC       string `json:"mac,omitempty"`
	Master    string `json:"master,omitempty"`
	RxBytes   uint64 `json:"rx_bytes"`
	TxBytes   uint64 `json:"tx_bytes"`
	RxPackets uint64 `json:"rx_packets"`
	TxPackets uint64 `json:"tx_packets"`
	RxErrors  uint64 `json:"rx_errors"`
	TxErrors  uint64 `json:"tx_errors"`
	RxDropped uint64 `json:"rx_dropped"`
	TxDropped uint64 `json:"tx_dropped"`
}

var kindOrder = map[string]int{"port": 0, "cpu": 1, "bridge": 2, "vlan": 3, "ppp": 4, "wifi": 5, "tunnel": 6, "other": 7}

func sysExists(dev, attr string) bool {
	_, err := os.Stat(filepath.Join(sysNet, dev, attr))
	return err == nil
}

// netRoles maps netdev names to what the config uses them for ("WAN wan, WAN wan2", "LAN", "guest").
func netRoles(c *Config) map[string]string {
	var order []string
	roles := map[string][]string{}
	add := func(dev, role string) {
		for _, r := range roles[dev] {
			if r == role {
				return
			}
		}
		if len(roles[dev]) == 0 {
			order = append(order, dev)
		}
		roles[dev] = append(roles[dev], role)
	}
	for _, w := range c.WAN {
		add(w.Device, "WAN "+w.Name)
		add(w.LinkDev(), "WAN "+w.Name)
		add(w.Ifname(), "WAN "+w.Name)
	}
	add(c.LAN.Bridge, "LAN")
	for _, p := range c.LAN.Ports {
		add(p, "LAN")
	}
	for _, n := range c.Networks {
		add(n.BridgeName(), n.Name)
		for _, p := range n.Ports {
			add(p, n.Name)
		}
		for _, p := range n.Trunk {
			add(p+"."+strconv.Itoa(n.VLAN), n.Name)
			add(p, n.Name+" (VLAN "+strconv.Itoa(n.VLAN)+")")
		}
	}
	add("tailscale0", "tailscale")
	out := map[string]string{}
	for _, d := range order {
		out[d] = strings.Join(roles[d], ", ")
	}
	return out
}

// readPorts reads every netdev from /sys (link, speed, duplex, counters). Cheap: a few small files per device.
func readPorts(c *Config) []portInfo {
	ents, _ := os.ReadDir(sysNet)
	roles := netRoles(c)
	var out []portInfo
	for _, e := range ents {
		d := e.Name()
		if d == "lo" {
			continue
		}
		p := portInfo{Name: d, Role: roles[d], Oper: effOper(sysRead(d, "operstate"), sysRead(d, "flags"), sysRead(d, "carrier")), MTU: atoi(sysRead(d, "mtu")), MAC: sysRead(d, "address")}
		if raw := sysRead(d, "operstate"); raw != p.Oper {
			p.OperRaw = raw
		}
		flags, _ := strconv.ParseUint(strings.TrimPrefix(sysRead(d, "flags"), "0x"), 16, 32)
		p.AdminUp = flags&1 == 1
		p.Carrier = sysRead(d, "carrier") == "1"
		if s := atoi(sysRead(d, "speed")); s > 0 && p.Carrier {
			p.Speed = s
			if dx := sysRead(d, "duplex"); dx == "full" || dx == "half" {
				p.Duplex = dx
			}
		}
		if l, err := os.Readlink(filepath.Join(sysNet, d, "master")); err == nil {
			p.Master = filepath.Base(l)
		}
		devtype := ""
		for _, l := range strings.Split(readFile(filepath.Join(sysNet, d, "uevent")), "\n") {
			if strings.HasPrefix(l, "DEVTYPE=") {
				devtype = strings.TrimPrefix(l, "DEVTYPE=")
			}
		}
		switch {
		case sysExists(d, "bridge"):
			p.Kind = "bridge"
		case sysExists(d, "phy80211"):
			p.Kind = "wifi"
		case sysExists(d, "dsa"):
			p.Kind = "cpu" // DSA conduit (eth0): carries every switch port
		case devtype == "vlan":
			p.Kind = "vlan"
		case sysRead(d, "type") == "512":
			p.Kind = "ppp"
		case sysRead(d, "phys_port_name") != "" || sysRead(d, "phys_switch_id") != "":
			p.Kind = "port"
		case sysRead(d, "type") == "65534" || devtype == "wireguard":
			p.Kind = "tunnel"
		case sysExists(d, "device"):
			p.Kind = "port"
		default:
			p.Kind = "other"
		}
		st := func(n string) uint64 { v, _ := strconv.ParseUint(sysRead(d, "statistics/"+n), 10, 64); return v }
		p.RxBytes, p.TxBytes = st("rx_bytes"), st("tx_bytes")
		p.RxPackets, p.TxPackets = st("rx_packets"), st("tx_packets")
		p.RxErrors, p.TxErrors = st("rx_errors"), st("tx_errors")
		p.RxDropped, p.TxDropped = st("rx_dropped"), st("tx_dropped")
		out = append(out, p)
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if kindOrder[a.Kind] != kindOrder[b.Kind] {
			return kindOrder[a.Kind] < kindOrder[b.Kind]
		}
		if a.Kind == "port" && (a.Name == "wan") != (b.Name == "wan") {
			return a.Name == "wan" // front-panel order: WAN, then LAN ports
		}
		return natLess(a.Name, b.Name)
	})
	return out
}

// natLess orders lan2 < lan10.
func natLess(a, b string) bool {
	ta, tb := strings.TrimRight(a, "0123456789"), strings.TrimRight(b, "0123456789")
	if ta == tb {
		return atoi(a[len(ta):]) < atoi(b[len(tb):])
	}
	return a < b
}

func apiNetPorts() apiResp {
	c, err := loadConfig(ConfigPath, SecretsPath)
	if err != nil {
		return errResp(500, "%v", err)
	}
	return apiResp{body: map[string]any{"time": time.Now().UnixMilli(), "ports": readPorts(c)}}
}

// wanRT is the runtime view of one WAN (WAN page, 多线路 page, `mr wan status`).
type wanRT struct {
	Name        string   `json:"name"`
	Proto       string   `json:"proto"`
	Dev         string   `json:"dev"`
	Service     string   `json:"service,omitempty"`
	Up          bool     `json:"up"` // has an IPv4 address
	IP          string   `json:"ip,omitempty"`
	MTU         int      `json:"mtu,omitempty"` // of the L3 interface while up: PPPoE 1500 = RFC 4638 granted
	Gateway     string   `json:"gateway,omitempty"`
	DNS         []string `json:"dns,omitempty"`
	Since       int64    `json:"since,omitempty"`
	Table       int      `json:"table"`
	Mark        string   `json:"mark"`
	Metric      int      `json:"metric"`                 // configured
	RouteMetric *int     `json:"route_metric,omitempty"` // main-table default route right now (metric+10000 = down)
	Weight      int      `json:"weight,omitempty"`
	Health      string   `json:"health,omitempty"`
	RTT         *float64 `json:"rtt_ms,omitempty"`
	Fails       int      `json:"fails,omitempty"`
	HealthSince int64    `json:"health_since,omitempty"`
}

type wanRuntimeView struct {
	Mode     string   `json:"mode"`
	Checked  int64    `json:"checked,omitempty"` // last health round (unix)
	Interval int      `json:"interval,omitempty"`
	Targets  []string `json:"targets,omitempty"`
	WANs     []wanRT  `json:"wans"`
}

func wanRuntime(c *Config) wanRuntimeView {
	v := wanRuntimeView{Mode: c.MultiWAN.Mode, Targets: c.MultiWAN.Targets}
	health := map[string]wanHealth{}
	if c.MultiWAN.Enabled() {
		if f, ok := readWanHealth(); ok {
			v.Checked, v.Interval = f.Time, f.Interval
			for _, h := range f.WANs {
				health[h.Name] = h
			}
		}
	}
	for _, w := range c.WAN {
		t, m := c.WANTable(w.Name)
		r := wanRT{Name: w.Name, Proto: w.Proto, Dev: w.Ifname(), Service: netService(w), Table: t, Mark: m, Metric: w.Metric}
		if a := ipv4Addrs(r.Dev); len(a) > 0 {
			r.Up, r.IP, r.MTU = true, strings.SplitN(a[0], "/", 2)[0], atoi(sysRead(r.Dev, "mtu"))
			if l, ok := readLease(w.Name); ok {
				r.Gateway, r.DNS, r.Since = l.Gateway, l.DNS, l.Since
			}
			if ms := mainDefaultMetrics(r.Dev); len(ms) > 0 {
				r.RouteMetric = &ms[0]
			}
		}
		if c.MultiWAN.Mode == "balance" {
			r.Weight = c.MultiWAN.Weight(w.Name)
		}
		if h, ok := health[w.Name]; ok {
			r.Health, r.RTT, r.Fails, r.HealthSince = h.State, h.RTT, h.Fails, h.Since
		}
		v.WANs = append(v.WANs, r)
	}
	return v
}

func apiNetWAN() apiResp {
	c, err := loadConfig(ConfigPath, SecretsPath)
	if err != nil {
		return errResp(500, "%v", err)
	}
	return apiResp{body: wanRuntime(c)}
}

// apiNetRedial restarts the service of one WAN (PPPoE redial / DHCP renew from scratch).
func apiNetRedial(r apiReq) apiResp {
	if r.method != "POST" {
		return errResp(405, "POST required")
	}
	var in struct {
		WAN string `json:"wan"`
	}
	json.Unmarshal(r.body, &in)
	if !reName.MatchString(in.WAN) {
		return errResp(400, "bad wan name")
	}
	c, err := loadConfig(ConfigPath, SecretsPath)
	if err != nil {
		return errResp(500, "%v", err)
	}
	w := c.WANByName(in.WAN)
	if w == nil {
		return errResp(404, "no wan %q", in.WAN)
	}
	svc := netService(*w)
	if svc == "" {
		return errResp(400, "static WAN: nothing to redial")
	}
	if _, err := os.Stat("/etc/init.d/" + svc); err != nil {
		return errResp(404, "service %s not installed (apply first)", svc)
	}
	appendChangeLog("webui: redial wan " + w.Name)
	startDetached("rc-service", svc, "restart")
	return apiResp{body: map[string]any{"ok": true, "service": svc}}
}
