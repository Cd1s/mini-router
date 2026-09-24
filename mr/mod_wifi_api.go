package main

// wifi module: web UI / CLI data computed on demand from iw (no resident process).
//   wifi.status    live state per SSID (hostapd STATUS: radio state, channel, clients)
//   wifi.stations  associated clients per SSID (iw station dump)
//   wifi.kick      disconnect a client (hostapd control socket, mod_wifi_ctrl.go)
//   wifi.survey    per-channel noise / busy time (iw survey dump) + live radio state (hostapd STATUS)
//   wifi.scan      neighbour networks (iw scan ap-force: the radio leaves its channel for a few seconds)

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

// runTimeout runs a command (argv only, never a shell) and kills it after d.
func runTimeout(d time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if ctx.Err() != nil {
		return string(out), fmt.Errorf("%s: timed out after %s", name, d)
	}
	return string(out), err
}

// ---- stations ----

type station struct {
	Ifname    string  `json:"ifname"`
	SSID      string  `json:"ssid"`
	Band      string  `json:"band"`
	Network   string  `json:"network"`
	MAC       string  `json:"mac"`
	Signal    string  `json:"signal"`     // as iw prints it, incl. per-chain values
	SignalDBm int     `json:"signal_dbm"` // 0 = unknown
	TxRate    string  `json:"tx_rate"`    // router -> client
	RxRate    string  `json:"rx_rate"`    // client -> router
	TxMbps    float64 `json:"tx_mbps"`
	RxMbps    float64 `json:"rx_mbps"`
	TxBytes   uint64  `json:"tx_bytes"`
	RxBytes   uint64  `json:"rx_bytes"`
	TxRetries uint64  `json:"tx_retries"`
	TxFailed  uint64  `json:"tx_failed"`
	Connected int     `json:"connected"` // seconds
	Inactive  int     `json:"inactive_ms"`
	MFP       bool    `json:"mfp"`
}

func parseStations(out, ifname string) []station {
	var st []station
	var cur *station
	for _, l := range strings.Split(out, "\n") {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "Station ") {
			f := strings.Fields(t)
			if len(f) < 2 || !reMAC.MatchString(f[1]) {
				cur = nil
				continue
			}
			st = append(st, station{Ifname: ifname, MAC: strings.ToLower(f[1])})
			cur = &st[len(st)-1]
			continue
		}
		if cur == nil {
			continue
		}
		k, v, ok := strings.Cut(t, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch k {
		case "signal":
			cur.Signal = v
			cur.SignalDBm = atoi(firstField(v))
		case "tx bitrate":
			cur.TxRate = v
			cur.TxMbps = atof(firstField(v))
		case "rx bitrate":
			cur.RxRate = v
			cur.RxMbps = atof(firstField(v))
		case "tx bytes":
			cur.TxBytes = atou(firstField(v))
		case "rx bytes":
			cur.RxBytes = atou(firstField(v))
		case "tx retries":
			cur.TxRetries = atou(firstField(v))
		case "tx failed":
			cur.TxFailed = atou(firstField(v))
		case "connected time":
			cur.Connected = atoi(firstField(v))
		case "inactive time":
			cur.Inactive = atoi(firstField(v))
		case "MFP":
			cur.MFP = v == "yes"
		}
	}
	return st
}

func atou(s string) uint64 { n, _ := strconv.ParseUint(s, 10, 64); return n }

func stationsFor(c *Config) []station {
	st := []station{}
	for _, r := range c.WiFi.Radios {
		for i, ifn := range apIfnames(r) {
			if !netdevExists(ifn) {
				continue
			}
			out, err := runTimeout(5*time.Second, "iw", "dev", ifn, "station", "dump")
			if err != nil {
				continue
			}
			for _, s := range parseStations(out, ifn) {
				s.SSID, s.Band, s.Network = r.SSIDs[i].SSID, r.Band, networkName(r.SSIDs[i].Network)
				st = append(st, s)
			}
		}
	}
	return st
}

func apiStations() apiResp {
	c, err := loadConfig(ConfigPath, SecretsPath)
	if err != nil {
		return errResp(500, "%v", err)
	}
	return apiResp{body: map[string]any{"stations": stationsFor(c)}}
}

// apiWifiStatus: live state of every SSID (one hostapd STATUS per radio, no exec) — cheaper than the
// full status JSON for pages that only need the WiFi part.
func apiWifiStatus() apiResp {
	c, err := loadConfig(ConfigPath, SecretsPath)
	if err != nil {
		return errResp(500, "%v", err)
	}
	st := wifiStatusAll(c)
	if st == nil {
		st = []wifiStatus{}
	}
	return apiResp{body: st}
}

// ---- survey ----

type surveyChan struct {
	Freq     int  `json:"freq"`
	Channel  int  `json:"channel"`
	InUse    bool `json:"in_use"`
	Noise    int  `json:"noise"` // dBm, 0 = not reported
	ActiveMs int  `json:"active_ms"`
	BusyMs   int  `json:"busy_ms"`
	RxMs     int  `json:"rx_ms"`
	TxMs     int  `json:"tx_ms"`
}

// freqChan converts a centre frequency (MHz) to its channel number (2.4 / 5 / 6 GHz).
func freqChan(f int) int {
	switch {
	case f == 2484:
		return 14
	case f >= 2412 && f < 2484:
		return (f - 2407) / 5
	case f >= 5955 && f <= 7115:
		return (f - 5950) / 5
	case f >= 5000 && f < 5950:
		return (f - 5000) / 5
	}
	return 0
}

func parseSurvey(out string) []surveyChan {
	var res []surveyChan
	var cur *surveyChan
	for _, l := range strings.Split(out, "\n") {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "Survey data from ") {
			res = append(res, surveyChan{})
			cur = &res[len(res)-1]
			continue
		}
		k, v, ok := strings.Cut(t, ":")
		if cur == nil || !ok {
			continue
		}
		v = strings.TrimSpace(v)
		n := atoi(firstField(v))
		switch k {
		case "frequency":
			cur.Freq = int(atof(firstField(v)))
			cur.Channel = freqChan(cur.Freq)
			cur.InUse = strings.Contains(v, "[in use]")
		case "noise":
			cur.Noise = n
		case "channel active time":
			cur.ActiveMs = n
		case "channel busy time":
			cur.BusyMs = n
		case "channel receive time":
			cur.RxMs = n
		case "channel transmit time":
			cur.TxMs = n
		}
	}
	// channels the radio never visited report nothing useful
	out2 := res[:0]
	for _, s := range res {
		if s.Freq > 0 && (s.ActiveMs > 0 || s.Noise != 0 || s.InUse) {
			out2 = append(out2, s)
		}
	}
	return out2
}

type radioSurvey struct {
	Phy      string       `json:"phy"`
	Band     string       `json:"band"`
	Ifname   string       `json:"ifname"`
	State    string       `json:"state"`
	Channel  int          `json:"channel"`
	Width    int          `json:"width"`
	CACLeft  int          `json:"cac_left"`
	Config   string       `json:"config"` // channel / width as set in router.yaml
	Channels []surveyChan `json:"channels"`
	Error    string       `json:"error,omitempty"`
}

func surveyFor(c *Config) []radioSurvey {
	var res []radioSurvey
	for _, r := range c.WiFi.Radios {
		ifn := r.Phy + "-ap0"
		rs := radioSurvey{Phy: r.Phy, Band: r.Band, Ifname: ifn, Config: r.Channel + " · " + r.HTMode, Channels: []surveyChan{}}
		if op, err := radioStatus(r, time.Second); err == nil {
			rs.State, rs.Channel, rs.Width, rs.CACLeft = op.State, op.Channel, op.Width, op.CACLeft
		}
		if out, err := runTimeout(5*time.Second, "iw", "dev", ifn, "survey", "dump"); err != nil {
			rs.Error = strings.TrimSpace(firstLine(out + " " + err.Error()))
		} else {
			rs.Channels = parseSurvey(out)
		}
		res = append(res, rs)
	}
	return res
}

func apiSurvey() apiResp {
	c, err := loadConfig(ConfigPath, SecretsPath)
	if err != nil {
		return errResp(500, "%v", err)
	}
	return apiResp{body: map[string]any{"radios": surveyFor(c), "time": time.Now().Unix()}}
}

// ---- neighbour scan ----

type neighbour struct {
	BSSID    string  `json:"bssid"`
	SSID     string  `json:"ssid"` // "" = hidden
	Freq     int     `json:"freq"`
	Channel  int     `json:"channel"`
	Width    int     `json:"width"` // MHz (20 when the AP announces nothing wider)
	Signal   float64 `json:"signal"`
	Security string  `json:"security"`       // open | WEP | WPA | WPA2 | WPA2/WPA3 | WPA3 | 802.1X | OWE
	Stations int     `json:"stations"`       // from the BSS Load element, -1 = not announced
	Util     int     `json:"util"`           // channel utilisation 0-100 % (BSS Load), -1 = not announced
	Seen     int     `json:"seen_ms"`        // ms since last seen
	Standard string  `json:"standard"`       // n / ac / ax
	Own      bool    `json:"own,omitempty"`  // one of this router's BSSes
	Band     string  `json:"band,omitempty"` // 2g | 5g | 6g
}

// unescapeSSID undoes iw's print_ssid_escaped (\xNN for everything but printable ASCII).
func unescapeSSID(s string) string {
	var b []byte
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) && s[i+1] == 'x' {
			if n, err := strconv.ParseUint(s[i+2:i+4], 16, 8); err == nil {
				b = append(b, byte(n))
				i += 3
				continue
			}
		}
		b = append(b, s[i])
	}
	return strings.ToValidUTF8(string(b), "�")
}

func parseScan(out string) []neighbour {
	var res []neighbour
	var cur *neighbour
	var sect, auth string
	var rsn, wpa, privacy bool
	var ht40, vhtW int
	var seg1, seg2 int
	finish := func() {
		if cur == nil {
			return
		}
		switch {
		case rsn && strings.Contains(auth, "802.1X"):
			cur.Security = "802.1X"
		case rsn && strings.Contains(auth, "SAE") && strings.Contains(auth, "PSK"):
			cur.Security = "WPA2/WPA3"
		case rsn && strings.Contains(auth, "SAE"):
			cur.Security = "WPA3"
		case rsn && strings.Contains(auth, "OWE"):
			cur.Security = "OWE"
		case rsn:
			cur.Security = "WPA2"
		case wpa:
			cur.Security = "WPA"
		case privacy:
			cur.Security = "WEP"
		default:
			cur.Security = "open"
		}
		cur.Width = 20
		if ht40 > 0 {
			cur.Width = 40
		}
		switch vhtW {
		case 1:
			cur.Width = 80
			if seg2 != 0 && (seg2-seg1 == 8 || seg1-seg2 == 8) { // 160 MHz signalled the VHT way
				cur.Width = 160
			}
		case 2, 3:
			cur.Width = 160
		}
		cur.Channel = freqChan(cur.Freq)
		switch {
		case cur.Freq >= 5955:
			cur.Band = "6g"
		case cur.Freq >= 5000:
			cur.Band = "5g"
		default:
			cur.Band = "2g"
		}
	}
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "BSS ") {
			finish()
			m := strings.TrimPrefix(l, "BSS ")
			if i := strings.IndexAny(m, "( "); i > 0 {
				m = m[:i]
			}
			res = append(res, neighbour{BSSID: strings.ToLower(m), Stations: -1, Util: -1, Standard: "legacy"})
			cur = &res[len(res)-1]
			sect, auth, rsn, wpa, privacy, ht40, vhtW, seg1, seg2 = "", "", false, false, false, 0, 0, 0, 0
			continue
		}
		if cur == nil {
			continue
		}
		t := strings.TrimSpace(l)
		sub := strings.HasPrefix(t, "* ")
		if sub {
			t = strings.TrimPrefix(t, "* ")
		} else if strings.HasPrefix(l, "\t") && !strings.HasPrefix(l, "\t\t") {
			// top-level field or element header ("RSN:\t * Version: 1" carries its first item inline)
			k, v, _ := strings.Cut(t, ":")
			sect = k
			v = strings.TrimSpace(v)
			switch k {
			case "freq":
				if cur.Freq == 0 {
					cur.Freq = int(atof(v))
				}
			case "signal":
				if cur.Signal == 0 {
					cur.Signal = atof(firstField(v))
				}
			case "last seen":
				if strings.HasSuffix(v, "ms ago") {
					cur.Seen = atoi(firstField(v))
				}
			case "capability":
				privacy = strings.Contains(v, "Privacy")
			case "SSID":
				if cur.SSID == "" {
					cur.SSID = unescapeSSID(strings.TrimPrefix(l[strings.Index(l, ":")+1:], " "))
				}
			case "RSN":
				rsn = true
			case "WPA":
				wpa = true
			case "HT operation", "HT capabilities":
				if cur.Standard == "legacy" {
					cur.Standard = "n"
				}
			case "VHT operation", "VHT capabilities":
				if cur.Standard != "ax" {
					cur.Standard = "ac"
				}
			case "HE capabilities", "HE Operation", "HE operation":
				cur.Standard = "ax"
			}
			if !strings.HasPrefix(v, "* ") {
				continue
			}
			t = strings.TrimPrefix(v, "* ")
			sub = true
		}
		if !sub {
			continue
		}
		k, v, ok := strings.Cut(t, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch {
		case sect == "RSN" && k == "Authentication suites":
			auth = v
		case sect == "HT operation" && k == "secondary channel offset":
			if v == "above" || v == "below" {
				ht40 = 1
			}
		case sect == "VHT operation" && k == "channel width":
			vhtW = atoi(firstField(v))
		case sect == "VHT operation" && k == "center freq segment 1":
			seg1 = atoi(v)
		case sect == "VHT operation" && k == "center freq segment 2":
			seg2 = atoi(v)
		case sect == "BSS Load" && k == "station count":
			cur.Stations = atoi(v)
		case sect == "BSS Load" && k == "channel utilisation":
			if n, _, ok := strings.Cut(v, "/"); ok {
				cur.Util = atoi(n) * 100 / 255
			}
		}
	}
	finish()
	sort.SliceStable(res, func(i, j int) bool { return res[i].Signal > res[j].Signal })
	return res
}

// scanRadio runs an active scan from the AP netdev of one radio. ap-force lets the AP leave its
// channel briefly (clients see a short stall); flush drops stale cached results first.
func scanRadio(c *Config, phy string) (map[string]any, error) {
	var r *Radio
	for i := range c.WiFi.Radios {
		if c.WiFi.Radios[i].Phy == phy {
			r = &c.WiFi.Radios[i]
		}
	}
	if r == nil {
		return nil, fmt.Errorf("bad radio %q", phy)
	}
	ifn := r.Phy + "-ap0"
	out, err := runTimeout(30*time.Second, "iw", "dev", ifn, "scan", "flush", "ap-force")
	if err != nil {
		return nil, fmt.Errorf("scan on %s failed: %s", ifn, strings.TrimSpace(firstLine(out+" "+err.Error())))
	}
	res := parseScan(out)
	own := map[string]bool{}
	if op, err := radioStatus(*r, time.Second); err == nil {
		for _, b := range op.BSS {
			own[strings.ToLower(b.BSSID)] = true
		}
	}
	for i := range res {
		res[i].Own = own[res[i].BSSID]
	}
	return map[string]any{"phy": r.Phy, "band": r.Band, "ifname": ifn, "time": time.Now().Unix(), "bss": res}, nil
}

// apiScan: POST {"phy": "phy1"}. POST because it disturbs the radio for a few seconds.
func apiScan(r apiReq) apiResp {
	if r.method != "POST" {
		return errResp(405, "POST required")
	}
	var in struct {
		Phy string `json:"phy"`
	}
	if err := json.Unmarshal(r.body, &in); err != nil || !rePhy.MatchString(in.Phy) {
		return errResp(400, "bad request: need {\"phy\": \"phyN\"}")
	}
	c, err := loadConfig(ConfigPath, SecretsPath)
	if err != nil {
		return errResp(500, "%v", err)
	}
	res, err := scanRadio(c, in.Phy)
	if err != nil {
		if strings.HasPrefix(err.Error(), "bad ") {
			return errResp(400, "%v", err)
		}
		return errResp(502, "%v", err)
	}
	logf("webui: wifi scan on %s", in.Phy)
	return apiResp{body: res}
}

// ---- CLI: mr wifi stations|survey|scan PHY|kick MAC [IFNAME] (JSON on stdout, for agents) ----

func wifiCommand(c *Config, args []string) error {
	var v any
	switch {
	case len(args) == 1 && args[0] == "stations":
		v = map[string]any{"stations": stationsFor(c)}
	case len(args) == 1 && args[0] == "status":
		v = wifiStatusAll(c)
	case len(args) == 1 && args[0] == "survey":
		v = map[string]any{"radios": surveyFor(c)}
	case len(args) == 2 && args[0] == "scan":
		res, err := scanRadio(c, args[1])
		if err != nil {
			return err
		}
		v = res
	case (len(args) == 2 || len(args) == 3) && args[0] == "kick":
		ifn := ""
		if len(args) == 3 {
			ifn = args[2]
		}
		got, err := kick(c, args[1], ifn)
		if err != nil {
			return err
		}
		logf("mr wifi: kick %s from %s", strings.ToLower(args[1]), got)
		v = map[string]any{"ok": true, "ifname": got}
	default:
		return fmt.Errorf("usage: mr wifi status | stations | survey | scan PHY | kick MAC [IFNAME]")
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", " ")
	return enc.Encode(v)
}
