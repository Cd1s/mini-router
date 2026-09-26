package main

// wifi module: talking to hostapd over its control socket (/var/run/hostapd/<ifname>, unix datagram)
// directly — no hostapd_cli. Used for radio/BSS status, post-apply verification and kicking stations.

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// hostapdCtrlPath is the ctrl_interface directory written into hostapd configs; hostapdCtrlDir is where
// the client looks (tests point it at a temporary directory).
const hostapdCtrlPath = "/var/run/hostapd"

var hostapdCtrlDir = hostapdCtrlPath

// hostapdCmd sends one control command to the hostapd BSS ifname and returns the reply.
// The client socket is autobound in the abstract namespace (bind with an empty name), so nothing is
// left behind on disk; hostapd replies to whatever address the request came from.
func hostapdCmd(ifname, cmd string, timeout time.Duration) (string, error) {
	if !reDev.MatchString(ifname) || strings.Contains(ifname, "..") {
		return "", fmt.Errorf("bad interface %q", ifname)
	}
	c, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: "", Net: "unixgram"})
	if err != nil {
		return "", err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(timeout))
	dst := &net.UnixAddr{Name: filepath.Join(hostapdCtrlDir, ifname), Net: "unixgram"}
	if _, err := c.WriteToUnix([]byte(cmd), dst); err != nil {
		return "", fmt.Errorf("hostapd %s: %w", ifname, err)
	}
	buf := make([]byte, 16384)
	for {
		n, _, err := c.ReadFromUnix(buf)
		if err != nil {
			return "", fmt.Errorf("hostapd %s: %w", ifname, err)
		}
		// unsolicited event messages ("<3>AP-STA-CONNECTED ...") only go to attached monitors, but be safe
		if n > 0 && buf[0] == '<' {
			continue
		}
		return string(buf[:n]), nil
	}
}

// parseKV parses hostapd's "key=value" reply lines.
func parseKV(s string) map[string]string {
	m := map[string]string{}
	for _, l := range strings.Split(s, "\n") {
		if k, v, ok := strings.Cut(l, "="); ok {
			m[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return m
}

// radioOp is the live operating state of one radio, from hostapd's STATUS.
type radioOp struct {
	State   string  // ENABLED, DFS (radar check running), ACS, HT_SCAN, COUNTRY_UPDATE, DISABLED, ...
	Channel int     // primary channel, 0 while ACS runs
	Freq    int     // MHz
	Width   int     // MHz
	CACLeft int     // seconds of DFS channel availability check left
	BSS     []opBSS // in config order
}

type opBSS struct {
	Ifname  string
	BSSID   string
	Clients int
}

func parseHostapdStatus(s string) radioOp {
	kv := parseKV(s)
	op := radioOp{State: kv["state"], Channel: atoi(kv["channel"]), Freq: atoi(kv["freq"]), CACLeft: atoi(kv["cac_time_left_seconds"])}
	op.Width = 20
	if kv["secondary_channel"] != "" && kv["secondary_channel"] != "0" {
		op.Width = 40
	}
	cw := kv["he_oper_chwidth"]
	if cw == "" {
		cw = kv["vht_oper_chwidth"]
	}
	if kv["ieee80211ac"] == "1" || kv["hw_mode"] == "a" {
		switch cw {
		case "1":
			op.Width = 80
		case "2", "3":
			op.Width = 160
		}
	}
	for i := 0; ; i++ {
		ifn, ok := kv[fmt.Sprintf("bss[%d]", i)]
		if !ok {
			break
		}
		op.BSS = append(op.BSS, opBSS{Ifname: ifn, BSSID: kv[fmt.Sprintf("bssid[%d]", i)], Clients: atoi(kv[fmt.Sprintf("num_sta[%d]", i)])})
	}
	return op
}

func radioStatus(r Radio, timeout time.Duration) (radioOp, error) {
	out, err := hostapdCmd(r.Phy+"-ap0", "STATUS", timeout)
	if err != nil {
		return radioOp{}, err
	}
	if !strings.Contains(out, "state=") {
		return radioOp{}, fmt.Errorf("hostapd %s-ap0: unexpected STATUS reply", r.Phy)
	}
	return parseHostapdStatus(out), nil
}

type wifiStatus struct {
	Ifname  string `json:"ifname"`
	Up      bool   `json:"up"`
	SSID    string `json:"ssid"`
	Channel string `json:"channel"`
	HTMode  string `json:"htmode"`
	Clients int    `json:"clients"`
	Phy     string `json:"phy"`
	Band    string `json:"band"`
	Network string `json:"network"`
	State   string `json:"state,omitempty"`    // hostapd radio state
	CACLeft int    `json:"cac_left,omitempty"` // seconds of radar check left (state DFS)
	BSSID   string `json:"bssid,omitempty"`
}

// wifiStatusAll: one entry per configured SSID (BSS), from one STATUS request per radio.
func wifiStatusAll(c *Config) []wifiStatus {
	var out []wifiStatus
	for _, r := range c.WiFi.Radios {
		op, err := radioStatus(r, time.Second)
		byIf := map[string]opBSS{}
		for _, b := range op.BSS {
			byIf[b.Ifname] = b
		}
		for i, ifn := range apIfnames(r) {
			s := r.SSIDs[i]
			ws := wifiStatus{Ifname: ifn, SSID: s.SSID, Phy: r.Phy, Band: r.Band, Network: networkName(s.Network)}
			if err == nil {
				b, ok := byIf[ifn]
				ws.State = op.State
				ws.Up = ok && op.State == "ENABLED"
				ws.Clients = b.Clients
				ws.BSSID = b.BSSID
				ws.CACLeft = op.CACLeft
				if op.Channel > 0 {
					ws.Channel = strconv.Itoa(op.Channel)
					ws.HTMode = fmt.Sprintf("%dMHz", op.Width)
				}
			}
			out = append(out, ws)
		}
	}
	return out
}

func networkName(n string) string {
	if n == "" {
		return "lan"
	}
	return n
}

// wifiNotReady lists what is not (yet) up: every radio must be ENABLED, or DFS (radar check before
// transmitting; up to 10 minutes on weather-radar channels, so it counts as configured), with every BSS.
func wifiNotReady(c *Config) []string {
	var bad []string
	for _, r := range c.WiFi.Radios {
		op, err := radioStatus(r, 2*time.Second)
		if err != nil {
			bad = append(bad, fmt.Sprintf("%s: hostapd not answering (%v)", r.Phy, err))
			continue
		}
		if op.State == "DISABLED" && schedOff(c, "wifi-off", "wifi-on", r.Phy) {
			continue // switched off by a schedule (wifiWindow)
		}
		if op.State != "ENABLED" && op.State != "DFS" {
			bad = append(bad, fmt.Sprintf("%s: state %s", r.Phy, op.State))
			continue
		}
		have := map[string]bool{}
		for _, b := range op.BSS {
			have[b.Ifname] = true
		}
		for _, ifn := range apIfnames(r) {
			if !have[ifn] {
				bad = append(bad, ifn+": BSS missing")
			}
		}
	}
	return bad
}

func wifiVerify(c *Config, restarted []string) []string {
	for _, s := range restarted {
		if s != "mr-hostapd" {
			continue
		}
		var bad []string
		if !waitFor(verifyDeadline(), func() bool { bad = wifiNotReady(c); return len(bad) == 0 }) {
			return []string{"wifi: " + strings.Join(bad, "; ")}
		}
	}
	return nil
}

// ---- kick ----

// kickStation deauthenticates mac from whichever of the candidate BSSes it is associated with.
func kickStation(candidates []string, mac string) (string, error) {
	var lastErr error
	for _, ifn := range candidates {
		out, err := hostapdCmd(ifn, "STA "+mac, 2*time.Second)
		if err != nil {
			lastErr = err
			continue
		}
		if !strings.HasPrefix(strings.ToLower(out), mac) {
			continue // "FAIL": not on this BSS
		}
		out, err = hostapdCmd(ifn, "DEAUTHENTICATE "+mac, 2*time.Second)
		if err != nil {
			return "", err
		}
		if strings.TrimSpace(out) != "OK" {
			return "", fmt.Errorf("hostapd %s: %s", ifn, strings.TrimSpace(out))
		}
		return ifn, nil
	}
	if lastErr != nil {
		return "", lastErr
	}
	return "", errNotConnected
}

var errNotConnected = fmt.Errorf("station not connected")

// apiKick: POST {"mac": "aa:bb:..", "ifname": "phy1-ap0"(optional)} — disconnect one station now.
// It may reconnect right away; to keep it out, add it to the SSID's deny list (macfilter).
func apiKick(r apiReq) apiResp {
	if r.method != "POST" {
		return errResp(405, "POST required")
	}
	var in struct {
		MAC    string `json:"mac"`
		Ifname string `json:"ifname"`
	}
	if err := json.Unmarshal(r.body, &in); err != nil {
		return errResp(400, "bad request")
	}
	c, err := loadConfig(ConfigPath, SecretsPath)
	if err != nil {
		return errResp(500, "%v", err)
	}
	ifn, err := kick(c, in.MAC, in.Ifname)
	switch {
	case err == errNotConnected:
		return errResp(404, "%v", err)
	case err != nil && strings.HasPrefix(err.Error(), "bad "):
		return errResp(400, "%v", err)
	case err != nil:
		return errResp(502, "%v", err)
	}
	logf("webui: wifi kick %s from %s", strings.ToLower(in.MAC), ifn)
	return apiResp{body: map[string]any{"ok": true, "ifname": ifn}}
}

// kick validates the request against the config (only our own BSSes) and kicks.
func kick(c *Config, mac, ifname string) (string, error) {
	if !reMAC.MatchString(mac) {
		return "", fmt.Errorf("bad mac %q", mac)
	}
	var all []string
	for _, r := range c.WiFi.Radios {
		all = append(all, apIfnames(r)...)
	}
	cands := all
	if ifname != "" {
		cands = nil
		for _, x := range all {
			if x == ifname {
				cands = []string{x}
			}
		}
		if cands == nil {
			return "", fmt.Errorf("bad ifname %q", ifname)
		}
	}
	return kickStation(cands, strings.ToLower(mac))
}

// wifiWindowDir holds a marker per radio that wifiWindow switched off (a variable for tests).
var wifiWindowDir = RunDir

// wifiWindow applies the wifi-off / wifi-on schedules (mod_sys_cron.go) to every radio: hostapd DISABLE
// while its newest firing is an off one, ENABLE again afterwards (only radios it disabled itself). A
// radio whose hostapd does not answer is skipped: the hostapd start (wifi-hostapd) runs this again.
func wifiWindow(c *Config) error {
	var errs []string
	for _, r := range c.WiFi.Radios {
		op, err := radioStatus(r, 2*time.Second)
		if err != nil {
			continue
		}
		mark := filepath.Join(wifiWindowDir, "wifi-off."+r.Phy)
		off, cmd := schedOff(c, "wifi-off", "wifi-on", r.Phy), ""
		switch {
		case off && op.State != "DISABLED":
			cmd = "DISABLE"
			os.WriteFile(mark, nil, 0644)
		case !off && op.State == "DISABLED" && fileExists(mark):
			cmd = "ENABLE"
		}
		if !off {
			os.Remove(mark)
		}
		if cmd == "" {
			continue
		}
		out, err := hostapdCmd(r.Phy+"-ap0", cmd, 5*time.Second)
		if err == nil && strings.TrimSpace(out) != "OK" {
			err = fmt.Errorf("%s", firstLine(strings.TrimSpace(out)))
		}
		logf("wifi: %s %s (schedules): %v", r.Phy, cmd, err)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s %s: %v", r.Phy, cmd, err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}
