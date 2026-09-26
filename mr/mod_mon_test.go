package main

import (
	"encoding/binary"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// monFake points the mon module at a fake /proc, /sys, /run tree and fake network lookups.
func monFake(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	oldRoot, oldLink, oldLocal, oldNeigh, oldKlog := monRoot, monLink, monLocalAddrs, monNeighbours, monKlog
	t.Cleanup(func() {
		monRoot, monLink, monLocalAddrs, monNeighbours, monKlog = oldRoot, oldLink, oldLocal, oldNeigh, oldKlog
	})
	monRoot = root
	monWrite(t, root, files)
	pfx := func(s ...string) []netip.Prefix {
		var out []netip.Prefix
		for _, x := range s {
			out = append(out, netip.MustParsePrefix(x))
		}
		return out
	}
	monLink = func(name string) (int, []netip.Prefix) {
		if name == "br-lan" {
			return 5, pfx("192.168.1.6/24", "2001:db8:b910:1::1/64", "fe80::1/64")
		}
		return 0, nil
	}
	monLocalAddrs = func() []netip.Prefix {
		return pfx("127.0.0.1/8", "192.168.1.6/24", "203.0.113.9/32", "2001:db8:b910:1::1/64")
	}
	monNeighbours = func() ([]monNeigh, error) {
		return []monNeigh{
			{netip.MustParseAddr("192.168.1.233"), "02:e3:50:10:6a:63", 5, 2},
			{netip.MustParseAddr("2001:db8:b910:1::abcd"), "02:e3:50:10:6a:63", 5, 2},
			{netip.MustParseAddr("10.0.0.1"), "00:11:22:33:44:55", 7, 2}, // WAN side: not a LAN device
		}, nil
	}
	return root
}

func monWrite(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for p, data := range files {
		full := filepath.Join(root, p)
		if strings.HasSuffix(p, "/") {
			os.MkdirAll(full, 0755)
			continue
		}
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(data), 0644); err != nil {
			t.Fatal(err)
		}
	}
}

const monCTFixture = `ipv4     2 tcp      6 7440 ESTABLISHED src=192.168.1.233 dst=142.250.1.1 sport=51000 dport=443 packets=10 bytes=1000 src=142.250.1.1 dst=203.0.113.9 sport=443 dport=51000 packets=20 bytes=50000 [ASSURED] mark=0 zone=0 use=2
ipv4     2 udp      17 25 src=192.168.1.170 dst=8.8.8.8 sport=5353 dport=53 packets=1 bytes=60 [UNREPLIED] src=8.8.8.8 dst=203.0.113.9 sport=53 dport=5353 packets=0 bytes=0 mark=0 zone=0 use=2
ipv4     2 tcp      6 ESTABLISHED src=192.168.1.233 dst=1.1.1.1 sport=52000 dport=443 packets=100 bytes=10000 src=1.1.1.1 dst=203.0.113.9 sport=443 dport=52000 packets=900 bytes=1200000 [HW_OFFLOAD] mark=258 zone=0 use=3
ipv6     10 tcp      6 7430 ESTABLISHED src=2001:db8:b910:0001:0000:0000:0000:abcd dst=2606:4700:0000:0000:0000:0000:0000:1111 sport=40000 dport=443 packets=5 bytes=500 src=2606:4700:0000:0000:0000:0000:0000:1111 dst=2001:db8:b910:0001:0000:0000:0000:abcd sport=443 dport=40000 packets=6 bytes=6000 [OFFLOAD] mark=0 zone=0 use=2
ipv4     2 tcp      6 100 ESTABLISHED src=198.51.100.7 dst=203.0.113.9 sport=33333 dport=12000 packets=3 bytes=300 src=192.168.1.241 dst=198.51.100.7 sport=12000 dport=33333 packets=4 bytes=4000 [ASSURED] mark=0 zone=0 use=2
ipv4     2 udp      17 20 src=203.0.113.9 dst=17.253.1.1 sport=123 dport=123 packets=1 bytes=76 src=17.253.1.1 dst=203.0.113.9 sport=123 dport=123 packets=1 bytes=76 mark=0 zone=0 use=2
ipv4     2 icmp     1 29 src=192.168.1.170 dst=1.1.1.1 type=8 code=0 id=4321 packets=1 bytes=84 src=1.1.1.1 dst=203.0.113.9 type=0 code=0 id=4321 packets=1 bytes=84 mark=0 zone=0 use=2
ipv4     2 udp      17 10 src=192.168.1.233 dst=192.168.1.6 sport=40001 dport=53 packets=1 bytes=70 src=192.168.1.6 dst=192.168.1.233 sport=53 dport=40001 packets=1 bytes=200 mark=0 zone=0 use=2
garbage line
ipv4 2 tcp 6 10 ESTABLISHED src=1.2.3.4
`

func monCTFiles(ct, uptime string) map[string]string {
	return map[string]string{
		"/proc/net/nf_conntrack":                    ct,
		"/proc/uptime":                              uptime,
		"/proc/sys/net/netfilter/nf_conntrack_acct": "1\n",
		"/tmp/dhcp.leases": "1790291888 02:e3:50:10:6a:63 192.168.1.233 laptop 01:02:e3:50:10:6a:63\n" +
			"1790290795 02:c8:61:52:f4:45 192.168.1.170 TrebleDroid *\n" +
			"1790289177 02:13:2c:f7:cb:f2 192.168.1.167 * *\n",
		GenDir + "/nftables.nft": "table inet mr {\n\tflowtable ft {\n\t\thook ingress priority filter\n\t\tdevices = { \"lan2\", \"wan\" }\n\t\tflags offload\n\t}\n}\n",
	}
}

func TestMonRender(t *testing.T) {
	c := testConfig(t)
	files, err := Render(c)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, f := range files {
		got[f.Path] = f.Data
	}
	if !strings.Contains(got[monSysctl], "\nnet.netfilter.nf_conntrack_acct=1\n") {
		t.Errorf("91-mon.conf: %q", got[monSysctl])
	}
	if !strings.Contains(got[monConfD], "\nMON_WAN=\"wan\"\n") { // wan + wan2 share the device
		t.Errorf("conf.d/mr-mon: %q", got[monConfD])
	}
	if !strings.Contains(got[GenDir+"/services"], "mr-mon\n") {
		t.Error("mr-mon not enabled")
	}
	if serviceFor(monSysctl) != "sysctl" || serviceFor(monConfD) != "mr-mon" {
		t.Error("restart mapping")
	}
	c.WAN = append(c.WAN, WAN{Name: "x", Device: "$(reboot)"}, WAN{Name: "y", Device: ".."}, WAN{Name: "z", Device: "eth1"})
	if d := strings.Join(monWANDevs(c), " "); d != "wan eth1" {
		t.Errorf("unsafe WAN devices must be dropped, got %q", d)
	}
}

func TestMonParseCT(t *testing.T) {
	var e monCT
	lines := strings.Split(monCTFixture, "\n")
	if !monParseCT(lines[0], &e) {
		t.Fatal("tcp line rejected")
	}
	if e.Fam != 4 || e.Proto != "tcp" || e.TTL != 7440 || e.State != "ESTABLISHED" || e.O.Src.String() != "192.168.1.233" ||
		e.O.Dport != 443 || e.R.Dst.String() != "203.0.113.9" || e.OB != 1000 || e.RB != 50000 || e.OP != 10 || e.RP != 20 || e.Flags != monCTAssured {
		t.Errorf("tcp: %+v", e)
	}
	if !monParseCT(lines[1], &e) || e.State != "" || e.TTL != 25 || e.Flags != monCTUnreplied || e.R.Sport != 53 {
		t.Errorf("udp unreplied: %+v", e)
	}
	if !monParseCT(lines[2], &e) || e.TTL != -1 || e.State != "ESTABLISHED" || e.Flags != monCTHWOffload || e.Mark != 258 || e.RB != 1200000 {
		t.Errorf("hw offload (no timeout printed): %+v", e)
	}
	if !monParseCT(lines[3], &e) || e.Fam != 6 || e.O.Src.String() != "2001:db8:b910:1::abcd" || e.Flags != monCTOffload {
		t.Errorf("ipv6: %+v", e)
	}
	if !monParseCT(lines[6], &e) || !e.icmp() || e.O.Sport != 4321 || e.O.Dport != 8<<8 {
		t.Errorf("icmp: %+v", e)
	}
	if o := monConnJSON(&e); o.ICMP != "8/0" || o.NatSrc != "203.0.113.9" || o.Sport != 0 {
		t.Errorf("icmp json: %+v", o)
	}
	for _, l := range lines[8:] {
		if monParseCT(l, &e) {
			t.Errorf("accepted %q", l)
		}
	}
}

func TestMonNftFlowCounter(t *testing.T) {
	c := testConfig(t)
	nft := renderNft(c, func(string) bool { return true })
	if ft, _ := monNftFlowCounter(nft); !ft {
		t.Error("flowtable not found in the rendered ruleset")
	}
	withCounter := strings.Replace(nft, "\t\tflags offload\n", "\t\tflags offload\n\t\tcounter\n", 1)
	if ft, cnt := monNftFlowCounter(withCounter); !ft || !cnt {
		t.Error("counter not detected")
	}
	if ft, cnt := monNftFlowCounter("table inet mr {\n\tflowtable ft { hook ingress priority filter; devices = { \"wan\" }; counter; }\n\tchain x {\n\t}\n}\n"); !ft || !cnt {
		t.Error("one-line flowtable block")
	}
	if ft, cnt := monNftFlowCounter("table inet mr {\n\tflowtable ft { devices = { \"wan\" }; }\n\tchain forward {\n\t\tcounter\n\t}\n}\n"); !ft || cnt {
		t.Error("counter outside the flowtable counted")
	}
	if ft, cnt := monNftFlowCounter("table inet mr {\n\tchain forward {\n\t\tmeta l4proto { tcp, udp } flow add @ft\n\t\tcounter\n\t}\n}\n"); ft || cnt {
		t.Error("no flowtable")
	}
}

func TestMonDevices(t *testing.T) {
	c := testConfig(t)
	root := monFake(t, monCTFiles(monCTFixture, "1000.00 3000.00\n"))
	r, err := monDevices(c)
	if err != nil {
		t.Fatal(err)
	}
	if r["dt"].(float64) != 0 || r["acct"] != true || r["flowtable"] != true || r["flow_counter"] != false || r["entries"] != 8 {
		t.Fatalf("first poll: %v", r)
	}
	devs := map[string]*monDevice{}
	for _, d := range r["devices"].([]*monDevice) {
		devs[d.ID] = d
	}
	a := devs["02:e3:50:10:6a:63"]
	if a == nil || a.Name != "laptop" || a.Conns != 4 || a.Up != 11570 || a.Down != 1256200 ||
		strings.Join(a.IPs, ",") != "192.168.1.233,2001:db8:b910:1::abcd" {
		t.Fatalf("device A: %+v", a)
	}
	if b := devs["02:c8:61:52:f4:45"]; b == nil || b.Name != "TrebleDroid" || b.Conns != 2 || b.Up != 144 || b.Down != 84 {
		t.Errorf("device B: %+v", b)
	}
	// port forward: the LAN side of an inbound (DNAT) connection; named from router.yaml dhcp.hosts
	if v := devs["02:bb:dd:96:49:e2"]; v == nil || v.Name != "server" || v.Up != 4000 || v.Down != 300 {
		t.Errorf("port-forward target: %+v", v)
	}
	if o := r["other"].(*monDevice); o.Conns != 1 || o.Up != 76 {
		t.Errorf("router's own traffic: %+v", o)
	}
	if len(devs) != 3 {
		t.Errorf("devices: %v", devs)
	}

	// second poll 2 s later: two flows grew, the IPv6 flow closed, a new flow appeared
	ct := strings.Replace(monCTFixture, "packets=10 bytes=1000 src=142.250.1.1 dst=203.0.113.9 sport=443 dport=51000 packets=20 bytes=50000",
		"packets=30 bytes=3000 src=142.250.1.1 dst=203.0.113.9 sport=443 dport=51000 packets=120 bytes=150000", 1)
	ct = strings.Replace(ct, "bytes=10000 src=1.1.1.1 dst=203.0.113.9 sport=443 dport=52000 packets=900 bytes=1200000",
		"bytes=20000 src=1.1.1.1 dst=203.0.113.9 sport=443 dport=52000 packets=1800 bytes=2400000", 1)
	lines := strings.Split(ct, "\n")
	lines = append(append(lines[:3:3], lines[4:]...), // the IPv6 flow is gone
		"ipv4     2 tcp      6 7440 ESTABLISHED src=192.168.1.233 dst=9.9.9.9 sport=53000 dport=443 packets=5 bytes=500 src=9.9.9.9 dst=203.0.113.9 sport=443 dport=53000 packets=5 bytes=1000 [ASSURED] mark=0 zone=0 use=2")
	monWrite(t, root, map[string]string{"/proc/net/nf_conntrack": strings.Join(lines, "\n") + "\n", "/proc/uptime": "1002.00 3000.00\n"})
	r, err = monDevices(c)
	if err != nil {
		t.Fatal(err)
	}
	if r["dt"].(float64) != 2 {
		t.Fatalf("dt = %v", r["dt"])
	}
	list := r["devices"].([]*monDevice)
	if list[0].ID != "02:e3:50:10:6a:63" || list[0].UpRate != (2000+10000+500)/2 || list[0].DownRate != (100000+1200000+1000)/2 {
		t.Errorf("rates: %+v", list[0])
	}
	for _, d := range list {
		if d.ID == "02:c8:61:52:f4:45" && (d.UpRate != 0 || d.DownRate != 0) {
			t.Errorf("idle device has a rate: %+v", d)
		}
	}
}

func TestMonDevicesWithoutConntrack(t *testing.T) {
	monFake(t, map[string]string{"/proc/uptime": "5.00 5.00\n"})
	r, err := monDevices(nil)
	if err != nil || r["available"] != false {
		t.Fatalf("%v %v", r, err)
	}
}

// fe80::/64 is on every link: the ISP's DHCPv6 reply (accepted on the WAN, so it is in conntrack)
// must not turn into a LAN device; a LAN device's link-local address is known from the neighbour table.
func TestMonDevicesLinkLocal(t *testing.T) {
	c := testConfig(t)
	ct := "ipv6     10 udp      17 25 src=fe80:0000:0000:0000:0000:0000:0000:00b1 dst=fe80:0000:0000:0000:0000:0000:0000:0009 sport=547 dport=546 packets=1 bytes=120 [UNREPLIED] src=fe80:0000:0000:0000:0000:0000:0000:0009 dst=fe80:0000:0000:0000:0000:0000:0000:00b1 sport=546 dport=547 packets=0 bytes=0 mark=0 zone=0 use=2\n" +
		"ipv6     10 udp      17 25 src=fe80:0000:0000:0000:0000:0000:0000:0007 dst=fe80:0000:0000:0000:0000:0000:0000:0001 sport=5353 dport=53 packets=1 bytes=90 src=fe80:0000:0000:0000:0000:0000:0000:0001 dst=fe80:0000:0000:0000:0000:0000:0000:0007 sport=53 dport=5353 packets=1 bytes=150 mark=0 zone=0 use=2\n"
	monFake(t, monCTFiles(ct, "1000.00 3000.00\n"))
	monNeighbours = func() ([]monNeigh, error) {
		return []monNeigh{{netip.MustParseAddr("fe80::7"), "02:e3:50:10:6a:63", 5, 2}}, nil
	}
	r, err := monDevices(c)
	if err != nil {
		t.Fatal(err)
	}
	devs := r["devices"].([]*monDevice)
	if len(devs) != 1 || devs[0].ID != "02:e3:50:10:6a:63" || devs[0].Up != 90 || devs[0].Down != 150 {
		t.Errorf("devices: %+v", devs)
	}
	if o := r["other"].(*monDevice); o.Conns != 1 || o.Up != 120 {
		t.Errorf("ISP link-local must be the router's own traffic: %+v", o)
	}
}

// More than monCTMax connections: only the first monCTMax are read, and which ones those are shifts
// between polls. A flow that slides into the window must not add its lifetime bytes to the rate.
func TestMonDevicesTruncated(t *testing.T) {
	c := testConfig(t)
	flow := func(i int, bytes uint64) string {
		return "ipv4     2 udp      17 25 src=192.168.1.233 dst=10." + strconv.Itoa(i>>16) + "." + strconv.Itoa(i>>8&255) + "." + strconv.Itoa(i&255) +
			" sport=5000 dport=53 packets=1 bytes=" + strconv.FormatUint(bytes, 10) + " src=10." + strconv.Itoa(i>>16) + "." + strconv.Itoa(i>>8&255) + "." + strconv.Itoa(i&255) +
			" dst=203.0.113.9 sport=53 dport=5000 packets=1 bytes=0 mark=0 zone=0 use=2\n"
	}
	table := func(from, to int) string {
		var b strings.Builder
		for i := from; i <= to; i++ {
			bytes := uint64(100)
			if i == monCTMax {
				bytes = 1 << 40 // a long-lived big download that sits beyond the parsed window
			}
			b.WriteString(flow(i, bytes))
		}
		return b.String()
	}
	root := monFake(t, monCTFiles(table(0, monCTMax), "1000.00 3000.00\n"))
	if r, _ := monDevices(c); r["truncated"] != true {
		t.Fatalf("first poll not truncated: %v", r["entries"])
	}
	// 2 s later flow 0 closed, so the big flow is inside the window now; nothing transferred anything
	monWrite(t, root, map[string]string{"/proc/net/nf_conntrack": table(1, monCTMax), "/proc/uptime": "1002.00 3000.00\n"})
	r, _ := monDevices(c)
	if d := r["devices"].([]*monDevice); len(d) != 1 || d[0].UpRate != 0 || r["dt"].(float64) != 2 {
		t.Errorf("rate spike from a flow entering the parsed window: %+v dt=%v", d, r["dt"])
	}
}

func TestMonConnFilterValidation(t *testing.T) {
	for _, body := range []string{`{"proto":"tcp;rm"}`, `{"ip":"1.2.3.4; reboot"}`, `{"ip":"fe80::1%br-lan"}`, `{"port":70000}`, `{"port":-1}`,
		`{"state":"established"}`, `{"offload":"x"}`, `{"family":5}`, `{"sort":"name"}`, `{"bogus":1}`, `{"limit":"a"}`, `not json`} {
		if _, err := monParseConnFilter([]byte(body)); err == nil {
			t.Errorf("accepted %s", body)
		}
	}
	f, err := monParseConnFilter(nil)
	if err != nil || f.Limit != 200 {
		t.Fatal(f, err)
	}
	if f, _ := monParseConnFilter([]byte(`{"limit":99999}`)); f.Limit != monConnsLimit {
		t.Error("limit not clamped")
	}
	// the API rejects bad input with 400 (read-only handler, no session needed at this level)
	for _, m := range modules {
		if m.Name == "mon" {
			if r := m.API["mon.conns"](apiReq{method: "POST", body: []byte(`{"proto":"x"}`)}); r.status != 400 {
				t.Errorf("status %d", r.status)
			}
		}
	}
}

func TestMonConns(t *testing.T) {
	c := testConfig(t)
	monFake(t, monCTFiles(monCTFixture, "1000.00 3000.00\n"))
	get := func(body string) map[string]any {
		t.Helper()
		v, err := monConns(c, []byte(body))
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(v)
		var m map[string]any
		json.Unmarshal(b, &m)
		return m
	}
	all := get(`{}`)
	if all["total"].(float64) != 8 || all["matched"].(float64) != 8 {
		t.Fatalf("totals: %v", all)
	}
	js, _ := json.Marshal([]any{all["by_proto"], all["by_offload"], all["by_family"], all["by_state"]})
	if string(js) != `[{"icmp":1,"tcp":4,"udp":3},{"hw":1,"none":6,"sw":1},{"4":7,"6":1},{"ESTABLISHED":4}]` {
		t.Errorf("aggregates: %s", js)
	}
	conns := all["conns"].([]any)
	if first := conns[0].(map[string]any); first["off"] != "hw" || first["rb"].(float64) != 1200000 {
		t.Errorf("not sorted by bytes: %v", first)
	}
	if all["names"].(map[string]any)["192.168.1.233"] != "laptop" {
		t.Errorf("names: %v", all["names"])
	}
	if top := all["top_src"].([]any)[0].(map[string]any); top["ip"] != "192.168.1.233" || top["conns"].(float64) != 3 || top["name"] != "laptop" {
		t.Errorf("top_src: %v", top)
	}
	for body, want := range map[string]float64{
		`{"proto":"tcp","offload":"hw"}`:           1,
		`{"ip":"192.168.1.0/24","port":53}`:        2,
		`{"family":6}`:                             1,
		`{"proto":"icmp","port":8}`:                0,
		`{"offload":"none","state":"ESTABLISHED"}`: 2,
		`{"proto":"other"}`:                        0,
	} {
		if got := get(body)["matched"].(float64); got != want {
			t.Errorf("%s: matched %v, want %v", body, got, want)
		}
	}
	fwd := get(`{"ip":"192.168.1.241"}`)["conns"].([]any)[0].(map[string]any)
	if fwd["nat_dst"] != "192.168.1.241" || fwd["nat_dport"].(float64) != 12000 || fwd["dst"] != "203.0.113.9" {
		t.Errorf("DNAT: %v", fwd)
	}
	if n := len(get(`{"limit":2}`)["conns"].([]any)); n != 2 {
		t.Errorf("limit: %d", n)
	}
}

func TestMonHistory(t *testing.T) {
	data := "100 1000 2000 50 100 400000 10 50000\n" +
		"160 61000 122000 110 700 390000 12 51000\n" +
		"220 50 100 170 1300 380000 13 0\n" + // counter reset (device re-created), no temperature sensor
		"1000 60050 120100 230 1900 370000 14 52000 61400 80\n" + // 13 min gap: sampler was stopped; WiFi throttled
		"1060 12\n" // partial line being written
	ss := parseMonHistory(data)
	if len(ss) != 4 {
		t.Fatalf("samples: %d", len(ss))
	}
	h := monHistory(ss, 1_700_000_000, 1100, 500000)
	js, _ := json.Marshal([]any{h["t"], h["rx"], h["tx"], h["cpu"], h["mem"], h["ct"], h["temp"]})
	want := `[[1699999000,1699999060,1699999120,1699999900],[null,1000,null,null],[null,2000,null,null],[null,10,10,null],[100000,110000,120000,130000],[10,12,13,14],[50,51,null,52]]`
	if string(js) != want {
		t.Errorf("history columns:\n got %s\nwant %s", js, want)
	}
	if js, _ := json.Marshal([]any{h["wtemp"], h["wduty"]}); string(js) != `[[null,null,null,61.4],[null,null,null,80]]` {
		t.Errorf("wifi columns: %s", js)
	}
	if col := h["collector"].(map[string]any); col["ok"] != true || col["age"] != 100 {
		t.Errorf("collector: %v", col)
	}
	// samples older than 24 h are dropped; a stale file means the sampler is not running
	h = monHistory(ss, 1_700_000_000, 100000, 500000)
	if len(h["t"].([]int64)) != 0 || h["collector"].(map[string]any)["ok"] != false {
		t.Errorf("stale: %v", h)
	}
	if h := monHistory(nil, 1, 1, 1); h["collector"].(map[string]any)["ok"] != false {
		t.Error("empty")
	}
}

func TestMonNow(t *testing.T) {
	c := testConfig(t)
	monFake(t, map[string]string{
		"/proc/stat":    "cpu  100 0 50 800 10 5 20 0 0 0\ncpu0 25 0 12 200 3 1 5 0 0 0\ncpu1 25 0 13 200 2 1 5 0 0 0\nintr 1 2 3\nctxt 99\n",
		"/proc/meminfo": "MemTotal:         494324 kB\nMemFree:           50000 kB\nMemAvailable:     153588 kB\nBuffers: 1000 kB\nCached: 90000 kB\nSwapTotal: 123580 kB\nSwapFree: 123000 kB\n",
		"/proc/loadavg": "0.32 0.70 0.54 2/123 4567\n",
		"/proc/uptime":  "12345.67 40000.00\n",
		"/proc/net/dev": "Inter-|   Receive                                                |  Transmit\n" +
			" face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n" +
			"    lo: 100 1 0 0 0 0 0 0 100 1 0 0 0 0 0 0\n" +
			"   wan:123456789012 1000 1 2 0 0 0 0 98765 900 3 4 0 0 0 0\n" +
			"pppoe-wan: 5000 50 0 0 0 0 0 0 6000 60 0 0 0 0 0 0\n" +
			"br-lan: 7000 70 0 0 0 0 0 0 8000 80 0 0 0 0 0 0\n" +
			"phy1-ap0: 1 1 0 0 0 0 0 0 1 1 0 0 0 0 0 0\n" +
			"  lan2: 1 1 0 0 0 0 0 0 1 1 0 0 0 0 0 0\n" +
			"tailscale0: 1 1 0 0 0 0 0 0 1 1 0 0 0 0 0 0\n",
		"/sys/class/net/wan/operstate":               "up\n",
		"/sys/class/net/pppoe-wan/operstate":         "unknown\n",
		"/sys/class/net/phy1-ap0/phy80211/":          "",
		"/sys/class/net/lan2/brport/":                "",
		"/sys/class/thermal/thermal_zone0/temp":      "52300\n",
		"/sys/class/thermal/thermal_zone0/type":      "cpu-thermal\n",
		"/proc/sys/net/netfilter/nf_conntrack_count": "757\n",
		"/proc/sys/net/netfilter/nf_conntrack_max":   "100000\n",
	})
	st := monNow(c)
	b, _ := json.Marshal(st)
	var m map[string]any
	json.Unmarshal(b, &m)
	if m["up"].(float64) != 12345.67 || m["ct"].(float64) != 757 || m["ct_max"].(float64) != 100000 || m["procs"].(float64) != 123 {
		t.Errorf("now: %s", b)
	}
	if cpus := m["cpus"].([]any); len(cpus) != 2 || cpus[1].([]any)[2].(float64) != 13 {
		t.Errorf("cpus: %v", m["cpus"])
	}
	if mem := m["mem"].(map[string]any); mem["avail"].(float64) != 153588 || mem["swap_total"].(float64) != 123580 {
		t.Errorf("mem: %v", mem)
	}
	if tp := m["temps"].([]any)[0].(map[string]any); tp["mc"].(float64) != 52300 || tp["type"] != "cpu-thermal" {
		t.Errorf("temps: %v", m["temps"])
	}
	roles := map[string]string{}
	for _, x := range m["ifaces"].([]any) {
		it := x.(map[string]any)
		roles[it["name"].(string)], _ = it["role"].(string)
		if it["name"] == "wan" && (it["rx"].(float64) != 123456789012 || it["tx"].(float64) != 98765 || it["err"].(float64) != 4 || it["drop"].(float64) != 6 || it["state"] != "up") {
			t.Errorf("wan counters: %v", it)
		}
	}
	want := map[string]string{"wan": "wan-dev", "pppoe-wan": "wan", "br-lan": "lan", "phy1-ap0": "wifi", "lan2": "port", "tailscale0": "vpn"}
	for k, v := range want {
		if roles[k] != v {
			t.Errorf("role %s = %q, want %q", k, roles[k], v)
		}
	}
	if _, ok := roles["lo"]; ok || len(roles) != len(want) {
		t.Errorf("ifaces: %v", roles)
	}
}

func TestMonProcs(t *testing.T) {
	monFake(t, map[string]string{
		"/proc/1/stat":     "1 (init) S 0 1 1 0 -1 4194560 100 0 0 0 5 10 0 0 20 0 1 0 2 1654784 200 18446744073709551615 1 1 0 0 0\n",
		"/proc/1/cmdline":  "/sbin/init\x00",
		"/proc/2/stat":     "2 (kthreadd) S 0 0 0 0 -1 2129984 0 0 0 0 0 0 0 0 20 0 1 0 2 0 0 18446744073709551615 0 0 0 0 0\n",
		"/proc/42/stat":    "42 (my (proc) x) R 1 42 42 0 -1 4194560 0 0 0 0 300 200 0 0 20 0 3 0 500 10485760 1024 18446744073709551615 1 1\n",
		"/proc/42/cmdline": "tailscaled\x00--authkey\x00tskey-abc\x00--state=/var/lib/x\x00password=hunter2\x00-p\x0022\x00",
		"/proc/self/stat":  "garbage",
		"/proc/stat":       "cpu  1 1 1 1 1 1 1 1\ncpu0 1 1 1 1 1 1 1 1\n",
		"/proc/uptime":     "10.00 5.00\n",
		"/etc/passwd":      "root:x:0:0:root:/root:/bin/sh\n",
	})
	r := monProcs()
	ps := r["procs"].([]monProc)
	if len(ps) != 3 || r["ncpu"] != 1 {
		t.Fatalf("procs: %+v", r)
	}
	page := uint64(os.Getpagesize()) / 1024
	if p := ps[0]; p.Name != "init" || p.CPU != 15 || p.RSS != 200*page || p.VSZ != 1616 || p.Kernel || p.Cmd != "/sbin/init" || p.Threads != 1 {
		t.Errorf("init: %+v", p)
	}
	if p := ps[1]; !p.Kernel || p.Cmd != "" || p.PPID != 0 {
		t.Errorf("kthreadd: %+v", p)
	}
	if p := ps[2]; p.Name != "my (proc) x" || p.State != "R" || p.Threads != 3 || p.CPU != 500 ||
		p.Cmd != "tailscaled --authkey *** --state=/var/lib/x password=*** -p 22" {
		t.Errorf("proc 42: %+v", p)
	}
	if u := ps[0].User; u == "" {
		t.Error("user empty")
	}
}

func TestMonDmesg(t *testing.T) {
	monFake(t, map[string]string{"/proc/uptime": "10.00 5.00\n"})
	monKlog = func() (string, error) {
		return "<6>[    0.000000] Booting Linux\n<3>[    1.000000] mt7915e: error \x1b[31m\n\n<12>[    2.000000] user msg\nno prefix\n", nil
	}
	r, err := monDmesg()
	if err != nil {
		t.Fatal(err)
	}
	js, _ := json.Marshal(r["lines"])
	want := `[[6,"[    0.000000] Booting Linux"],[3,"[    1.000000] mt7915e: error  [31m"],[4,"[    2.000000] user msg"],[6,"no prefix"]]`
	if string(js) != want {
		t.Errorf("got %s", js)
	}
	if got := monParseKlog(strings.Repeat("<6>x\n", 10), 3); len(got) != 3 {
		t.Error("max")
	}
}

func TestMonParseNeigh(t *testing.T) {
	msg := func(state uint16, ifindex int32, dst, mac []byte) []byte {
		b := make([]byte, 12)
		binary.NativeEndian.PutUint32(b[4:], uint32(ifindex))
		binary.NativeEndian.PutUint16(b[8:], state)
		attr := func(typ uint16, v []byte) {
			a := make([]byte, 4, 4+len(v)+3)
			binary.NativeEndian.PutUint16(a[0:], uint16(4+len(v)))
			binary.NativeEndian.PutUint16(a[2:], typ)
			a = append(a, v...)
			for len(a)%4 != 0 {
				a = append(a, 0)
			}
			b = append(b, a...)
		}
		attr(1, dst)
		if mac != nil {
			attr(2, mac)
		}
		return b
	}
	mac := []byte{0x02, 0xe3, 0x50, 0x10, 0x6a, 0x63}
	n, ok := monParseNeigh(msg(0x04, 5, []byte{192, 168, 1, 233}, mac))
	if !ok || n.Addr.String() != "192.168.1.233" || n.MAC != "02:e3:50:10:6a:63" || n.Ifindex != 5 {
		t.Errorf("v4 stale: %+v %v", n, ok)
	}
	v6 := netip.MustParseAddr("2001:db8:b910:1::abcd").As16()
	if n, ok := monParseNeigh(msg(0x02, 5, v6[:], mac)); !ok || n.Addr.String() != "2001:db8:b910:1::abcd" {
		t.Errorf("v6 reachable: %+v", n)
	}
	if _, ok := monParseNeigh(msg(0x20, 5, []byte{192, 168, 1, 9}, nil)); ok {
		t.Error("failed entry accepted")
	}
	if _, ok := monParseNeigh([]byte{1, 2, 3}); ok {
		t.Error("short message accepted")
	}
}

func TestMonFlowSnapshot(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x", "flows")
	m := map[uint64][2]uint64{1: {2, 3}, 0xffffffffffffffff: {4, 5}}
	if err := monSaveFlows(p, 123.45, m); err != nil {
		t.Fatal(err)
	}
	got, up, ok := monLoadFlows(p)
	if !ok || up != 123.45 || len(got) != 2 || got[0xffffffffffffffff] != [2]uint64{4, 5} {
		t.Errorf("%v %v %v", got, up, ok)
	}
	os.WriteFile(p, []byte("MRF1garbage"), 0600)
	if _, _, ok := monLoadFlows(p); ok {
		t.Error("corrupt snapshot accepted")
	}
}
