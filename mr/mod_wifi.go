package main

// wifi module: radios, SSIDs (up to 4 per radio), hostapd, AP netdevs, stations, channel analysis.
// Owns: router.yaml wifi. Files: mod_wifi.go (config, validation, rendering, registration),
// mod_wifi_ctrl.go (hostapd control socket: status, kick), mod_wifi_api.go (stations, survey, scan),
// mod_wifi_steer.go (802.11v band steering), mod_wifi_health.go (radio health, self-heal, `mr wifi tick`).
// Channel, width, tx power and country are only ever what the user set: nothing here adjusts them.

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

type WiFi struct {
	Country string `yaml:"country"`
	// Steering: 802.11v band steering, 2.4 -> 5 GHz within one SSID (mod_wifi_steer.go). Off by default.
	Steering Steering `yaml:"steering,omitempty"`
	// SelfHeal: a radio whose TX stops with stations associated gets the driver's firmware recovery,
	// then a hostapd restart (mod_wifi_health.go). Off by default.
	SelfHeal bool    `yaml:"self_heal,omitempty"`
	Radios   []Radio `yaml:"radios"`
}

// Steering is wifi.steering: stations on 2.4 GHz with a good signal that support BSS Transition
// Management are asked (never forced) to move to the 5 GHz BSS of the same SSID.
type Steering struct {
	Enabled     bool     `yaml:"enabled"`
	MinSignal2G int      `yaml:"min_signal_2g,omitempty"` // dBm; default -60 (set while enabled)
	Exclude     []string `yaml:"exclude,omitempty"`       // MACs never steered
}

type Radio struct {
	Phy      string `yaml:"phy"`     // phy0 / phy1 (our name; the kernel phy is found by band)
	Band     string `yaml:"band"`    // 2g | 5g
	Channel  string `yaml:"channel"` // number or auto
	Channels string `yaml:"channels"`
	HTMode   string `yaml:"htmode"` // HE20..HE160 (802.11ax); generic profile also HT20/HT40, VHT20..VHT160
	// Profile: "" / mt7986 = capabilities tuned for MT7986 + mt76 and hostapd with OpenWrt's noscan
	// patch (Redmi AX6000 image); generic = only what every nl80211 driver + stock hostapd accepts.
	Profile     string `yaml:"profile,omitempty"`
	TxPower     int    `yaml:"txpower"`                // dBm, 0 = driver default
	BeaconInt   int    `yaml:"beacon_int,omitempty"`   // TU (1.024 ms), default 100
	DTIM        int    `yaml:"dtim_period,omitempty"`  // beacons per DTIM, default 2
	LegacyRates bool   `yaml:"legacy_rates,omitempty"` // 2g: keep 802.11b rates (1-11 Mbps); default off
	SSIDs       []SSID `yaml:"ssids"`
}

type SSID struct {
	SSID       string   `yaml:"ssid"`
	Key        string   `yaml:"key_secret"`
	Encryption string   `yaml:"encryption"`            // sae-mixed | sae | psk2 | none
	PMF        string   `yaml:"pmf,omitempty"`         // 802.11w: "" (by encryption) | disabled | optional | required
	Hidden     bool     `yaml:"hidden"`                // do not broadcast the SSID
	Isolate    bool     `yaml:"isolate,omitempty"`     // clients cannot reach each other (or other isolated SSIDs)
	MaxClients int      `yaml:"max_clients,omitempty"` // 0 = no limit
	MACFilter  string   `yaml:"macfilter,omitempty"`   // "" | allow (only maclist) | deny (all but maclist)
	MACList    []string `yaml:"maclist,omitempty"`
	Network    string   `yaml:"network,omitempty"` // LAN-side network this SSID bridges into ("" = lan)
	// MulticastToUnicast: mac80211 sends ARP / IPv4 / IPv6 multicast to each station as unicast
	// (hostapd multicast_to_unicast): mDNS, AirPlay, IPTV at the station's rate, acknowledged
	MulticastToUnicast bool `yaml:"multicast_to_unicast,omitempty"`
}

const maxSSIDs = 4 // per radio: the BSSID block of a radio is 4 addresses (see mr_apmac)

// pmfLevel maps SSID.PMF to hostapd's ieee80211w.
var pmfLevel = map[string]int{"disabled": 0, "optional": 1, "required": 2}

const heCommon = `he_spr_sr_control=3
ieee80211ax=1
he_su_beamformer=1
he_su_beamformee=1
he_mu_beamformer=1
he_twt_required=0
he_twt_responder=1
he_default_pe_duration=4
he_rts_threshold=1023
he_mu_edca_qos_info_param_count=0
he_mu_edca_qos_info_q_ack=0
he_mu_edca_qos_info_queue_request=0
he_mu_edca_qos_info_txop_request=0
he_mu_edca_ac_be_aifsn=8
he_mu_edca_ac_be_aci=0
he_mu_edca_ac_be_ecwmin=9
he_mu_edca_ac_be_ecwmax=10
he_mu_edca_ac_be_timer=255
he_mu_edca_ac_bk_aifsn=15
he_mu_edca_ac_bk_aci=1
he_mu_edca_ac_bk_ecwmin=9
he_mu_edca_ac_bk_ecwmax=10
he_mu_edca_ac_bk_timer=255
he_mu_edca_ac_vi_ecwmin=5
he_mu_edca_ac_vi_ecwmax=7
he_mu_edca_ac_vi_aifsn=5
he_mu_edca_ac_vi_aci=2
he_mu_edca_ac_vi_timer=255
he_mu_edca_ac_vo_aifsn=5
he_mu_edca_ac_vo_aci=3
he_mu_edca_ac_vo_ecwmin=5
he_mu_edca_ac_vo_ecwmax=7
he_mu_edca_ac_vo_timer=255
`

// Capabilities copied from the working OpenWrt-generated config on this board (mt7986 + mt76).
const htCapab = "[LDPC][SHORT-GI-20][SHORT-GI-40][TX-STBC][MAX-AMSDU-7935][RX-STBC1]"

const vhtCapabBase = "[RXLDPC][SHORT-GI-80][SHORT-GI-160][TX-STBC-2BY1][SU-BEAMFORMER][SU-BEAMFORMEE][MU-BEAMFORMER][MU-BEAMFORMEE][RX-ANTENNA-PATTERN][TX-ANTENNA-PATTERN][RX-STBC-1][SOUNDING-DIMENSION-4][BF-ANTENNA-4][MAX-MPDU-11454][MAX-A-MPDU-LEN-EXP7]"

// hostapdConfPath is where the config of one radio lives (0600: it holds the passphrases).
func hostapdConfPath(r Radio) string { return fmt.Sprintf("/etc/hostapd/hostapd-%s.conf", r.Phy) }

// macListPath is the accept/deny MAC file of one BSS.
func macListPath(ifname string) string { return "/etc/hostapd/" + ifname + ".maclist" }

func renderHostapd(c *Config, r Radio) (string, error) {
	var b strings.Builder
	b.WriteString("# generated by mr — edit router.yaml instead\ndriver=nl80211\n")
	b.WriteString("logger_syslog=127\nlogger_syslog_level=2\nlogger_stdout=127\nlogger_stdout_level=2\n")
	if c.WiFi.Country != "" {
		fmt.Fprintf(&b, "country_code=%s\nieee80211d=1\n", c.WiFi.Country)
	}
	fmt.Fprintf(&b, "beacon_int=%d\nstationary_ap=1\n", r.BeaconInt)
	width := htWidth(r.HTMode)
	generic := r.Profile == "generic"
	he := strings.HasPrefix(r.HTMode, "HE")
	vht := he || strings.HasPrefix(r.HTMode, "VHT")
	ch := 0
	if r.Channel != "auto" {
		ch, _ = strconv.Atoi(r.Channel)
	}
	if r.Band == "2g" {
		b.WriteString("hw_mode=g\n")
	} else {
		b.WriteString("hw_mode=a\n")
		if c.WiFi.Country != "" { // hostapd refuses 802.11h without 802.11d, which needs a country
			b.WriteString("ieee80211h=1\n")
		}
		b.WriteString("acs_exclude_dfs=0\n")
	}
	fmt.Fprintf(&b, "channel=%d\n", ch)
	if r.Channels != "" && ch == 0 {
		fmt.Fprintf(&b, "chanlist=%s\n", r.Channels)
	}
	ht := htCapab
	if generic {
		ht = ""
	}
	if width >= 40 {
		dir := "[HT40+]"
		if r.Band == "5g" && ch != 0 && (ch/4)%2 == 0 { // 40, 48, 56, 64, ... are the upper 20 MHz of a 40 MHz pair
			dir = "[HT40-]"
		}
		if r.Band == "2g" && ch > 7 {
			dir = "[HT40-]"
		}
		ht = dir + ht
		if r.Band == "2g" && !generic {
			// keep HT40 on 2.4 GHz even with neighbours around (hostapd built with OpenWrt's noscan patch)
			b.WriteString("noscan=1\n")
		}
	}
	fmt.Fprintf(&b, "ieee80211n=1\nht_capab=%s\n", ht)
	if r.Band == "5g" && vht {
		oper := map[int]int{20: 0, 40: 0, 80: 1, 160: 2}[width]
		caps := vhtCapabBase
		if generic {
			caps = ""
		}
		if width == 160 {
			if generic {
				caps = "[VHT160]"
			} else {
				caps = strings.Replace(caps, "[MAX-MPDU-11454]", "[VHT160][MAX-MPDU-11454]", 1)
			}
		}
		fmt.Fprintf(&b, "ieee80211ac=1\nvht_oper_chwidth=%d\nvht_capab=%s\n", oper, caps)
		if he {
			fmt.Fprintf(&b, "he_oper_chwidth=%d\n", oper)
		}
		if ch != 0 && width >= 80 {
			seg := centerChan(ch, "HE"+strconv.Itoa(width))
			fmt.Fprintf(&b, "vht_oper_centr_freq_seg0_idx=%d\n", seg)
			if he {
				fmt.Fprintf(&b, "he_oper_centr_freq_seg0_idx=%d\n", seg)
			}
		}
	}
	if he {
		fmt.Fprintf(&b, "he_bss_color=%d\n", bssColor(r.Phy))
		if generic {
			b.WriteString("ieee80211ax=1\n")
		} else {
			b.WriteString(heCommon)
		}
	}

	ifs := apIfnames(r)
	steer := steerIfnames(c)
	for i, s := range r.SSIDs {
		if i == 0 {
			fmt.Fprintf(&b, "\ninterface=%s\n", ifs[i])
		} else {
			fmt.Fprintf(&b, "\nbss=%s\n", ifs[i])
		}
		fmt.Fprintf(&b, "ctrl_interface=%s\nbridge=%s\nssid2=%s\nutf8_ssid=1\n", hostapdCtrlPath, c.BridgeFor(s.Network), hex.EncodeToString([]byte(s.SSID)))
		if s.Hidden {
			b.WriteString("ignore_broadcast_ssid=1\n")
		}
		isolate := 0
		if s.Isolate {
			isolate = 1
		}
		fmt.Fprintf(&b, "wmm_enabled=1\nuapsd_advertisement_enabled=1\ndtim_period=%d\ndisassoc_low_ack=1\nap_isolate=%d\n", r.DTIM, isolate)
		if s.MulticastToUnicast {
			b.WriteString("multicast_to_unicast=1\n")
		}
		if steer[ifs[i]] {
			// BSS Transition Management advertised (clients honour requests from APs that announce it) and
			// our own neighbor report, which `mr wifi tick` reads (SHOW_NEIGHBOR) as the steering target
			b.WriteString("bss_transition=1\nrrm_neighbor_report=1\n")
		}
		if s.MaxClients > 0 {
			fmt.Fprintf(&b, "max_num_sta=%d\n", s.MaxClients)
		}
		switch s.MACFilter {
		case "allow":
			fmt.Fprintf(&b, "macaddr_acl=1\naccept_mac_file=%s\n", macListPath(ifs[i]))
		case "deny":
			fmt.Fprintf(&b, "macaddr_acl=0\ndeny_mac_file=%s\n", macListPath(ifs[i]))
		}
		if r.Band == "2g" && !r.LegacyRates {
			b.WriteString("supported_rates=60 90 120 180 240 360 480 540\nbasic_rates=60 120 240\n")
		}
		if s.Encryption == "none" {
			continue
		}
		key, err := c.Secret(s.Key)
		if err != nil {
			return "", err
		}
		b.WriteString("wpa=2\nwpa_pairwise=CCMP\nokc=1\n")
		w := ssidPMF(s)
		switch s.Encryption {
		case "psk2":
			akm := "WPA-PSK WPA-PSK-SHA256"
			if w == 0 { // the SHA256 AKM needs management frame protection
				akm = "WPA-PSK"
			}
			fmt.Fprintf(&b, "wpa_key_mgmt=%s\nieee80211w=%d\nwpa_passphrase=%s\n", akm, w, key)
		case "sae":
			fmt.Fprintf(&b, "wpa_key_mgmt=SAE\nieee80211w=2\nsae_require_mfp=1\nsae_pwe=2\nsae_groups=19 20 21\nsae_password=%s\nbeacon_prot=1\ngroup_mgmt_cipher=AES-128-CMAC\n", key)
		case "sae-mixed":
			fmt.Fprintf(&b, "wpa_key_mgmt=SAE WPA-PSK WPA-PSK-SHA256\nieee80211w=%d\nsae_require_mfp=1\nsae_pwe=2\nsae_groups=19 20 21\nsae_password=%s\nwpa_passphrase=%s\nbeacon_prot=1\ngroup_mgmt_cipher=AES-128-CMAC\n", w, key, key)
		}
	}
	return b.String(), nil
}

// ssidPMF is the ieee80211w level of an SSID: the explicit pmf setting, else the encryption's default
// (WPA3-only requires it, the WPA2 modes offer it).
func ssidPMF(s SSID) int {
	if s.Encryption == "sae" {
		return 2
	}
	if l, ok := pmfLevel[s.PMF]; ok {
		return l
	}
	return 1
}

// renderMACList is an accept/deny file for hostapd: one address per line.
func renderMACList(s SSID) string {
	var b strings.Builder
	b.WriteString("# generated by mr — edit router.yaml instead\n")
	for _, m := range s.MACList {
		b.WriteString(strings.ToLower(m) + "\n")
	}
	return b.String()
}

// renderWifiPost runs in the background after hostapd started (mr-hostapd start_post runs `mr fw` right
// after it): tx power where the user fixed it, and bridge port isolation for isolated SSIDs (so their
// clients can't talk across radios either; ap_isolate only covers one BSS).
// hostapd creates the extra BSS netdevs (<phy>-ap0-<i>) only once the radio is up: after ACS and, on radar
// (DFS) channels, after the channel availability check (60 s; 10 min on weather-radar channels). So the
// script waits for every one of them (bridge port present = set up), both to isolate it and so that the
// `mr fw` that follows puts it into the offload flowtable (which only takes netdevs that exist). One
// shared deadline bounds the whole wait.
func renderWifiPost(c *Config) string {
	var b strings.Builder
	b.WriteString("#!/bin/sh\n# generated by mr — edit router.yaml instead\n")
	for _, r := range c.WiFi.Radios {
		if r.TxPower > 0 {
			fmt.Fprintf(&b, "iw dev %s-ap0 set txpower fixed %d\n", r.Phy, r.TxPower*100)
		} else {
			fmt.Fprintf(&b, "iw dev %s-ap0 set txpower auto\n", r.Phy)
		}
	}
	// isolated BSSes first (so a BSS that never comes up delays no isolation), 2.4 GHz before 5 GHz, then
	// the other extra BSSes (only needed for the flowtable, i.e. by the time the script ends)
	var wait []string // extra BSSes, plus isolated primaries (their bridge port exists from the start)
	iso := map[string]bool{}
	for _, pass := range []struct{ isolated, twoG bool }{{true, true}, {true, false}, {false, true}, {false, false}} {
		for _, r := range c.WiFi.Radios {
			if (r.Band == "2g") != pass.twoG {
				continue
			}
			ifs := apIfnames(r)
			for i, s := range r.SSIDs {
				if s.Isolate == pass.isolated && (i > 0 || s.Isolate) {
					wait = append(wait, ifs[i])
					iso[ifs[i]] = s.Isolate
				}
			}
		}
	}
	if len(wait) > 0 {
		b.WriteString("mr_t=0\nmr_wait() { while [ ! -e \"/sys/class/net/$1/brport\" ]; do [ $mr_t -ge 660 ] && return 1; sleep 1; mr_t=$((mr_t+1)); done; }\n")
		for _, d := range wait {
			if iso[d] {
				fmt.Fprintf(&b, "mr_wait %s && echo 1 > /sys/class/net/%s/brport/isolated\n", d, d)
			} else {
				fmt.Fprintf(&b, "mr_wait %s\n", d)
			}
		}
	}
	return b.String()
}

// bssColor gives each radio a stable HE BSS color in 1..63 (upstream hostapd rejects OpenWrt's "128 = random").
func bssColor(phy string) int {
	h := 0
	for _, ch := range phy {
		h = h*31 + int(ch)
	}
	return h%63 + 1
}

// centerChan returns the VHT/HE segment-0 center channel index for a 5 GHz primary channel, 0 if impossible.
// htWidth: channel width in MHz of an htmode (HT40, VHT80, HE160, ...), 0 if unknown.
func htWidth(m string) int {
	for _, p := range []string{"VHT", "HE", "HT"} {
		if strings.HasPrefix(m, p) {
			if n, err := strconv.Atoi(m[len(p):]); err == nil {
				return n
			}
		}
	}
	return 0
}

func centerChan(ch int, htmode string) int {
	width := htWidth(htmode)
	if width == 20 {
		width = 0
	}
	if width == 0 {
		return ch
	}
	blocks := map[int][]int{
		40:  {38, 46, 54, 62, 102, 110, 118, 126, 134, 142, 151, 159, 167, 175},
		80:  {42, 58, 106, 122, 138, 155, 171},
		160: {50, 114, 163},
	}
	span := width / 5 / 2 // channels from center to edge (in 5 MHz units: 40->4, 80->8, 160->16)
	for _, c := range blocks[width] {
		if ch >= c-span+2 && ch <= c+span-2 {
			return c
		}
	}
	return 0
}

// apIfnames returns every AP netdev of a radio: phyN-ap0 for the first SSID, phyN-ap0-<i> for the rest.
func apIfnames(r Radio) []string {
	ap := r.Phy + "-ap0"
	out := []string{ap}
	for i := 1; i < len(r.SSIDs); i++ {
		out = append(out, fmt.Sprintf("%s-%d", ap, i))
	}
	return out
}

// wifiNetSh: AP netdevs; hostapd adds them to their bridge itself. The kernel phy is found by band, not by
// name: phyN numbers change when mt76 is reloaded (e.g. to toggle WED) and phyN names can't be reclaimed.
func wifiNetSh(c *Config, phase string, b *strings.Builder) {
	if phase != "wifi" || len(c.WiFi.Radios) == 0 {
		return
	}
	var aps []string
	multi := false
	for _, r := range c.WiFi.Radios {
		aps = append(aps, r.Phy+"-ap0")
		multi = multi || len(r.SSIDs) > 1
	}
	b.WriteString("mr_phy() { for p in /sys/class/ieee80211/*; do p=${p##*/}; iw phy \"$p\" info | grep -q \"Band $1:\" && { echo \"$p\"; return; }; done; }\n")
	if multi {
		// hostapd numbers extra BSSes up from the first one's address and insists that address starts an
		// aligned block (addr & mask == addr). The factory MAC may not, so radios with several SSIDs get a
		// locally administered base address (low 2 bits clear = room for 4 BSSes), unique per band (+4 / +8
		// on the first byte). Adding (not XOR) keeps it above the factory address (unless the first byte
		// wraps past 0xff): a bridge without a fixed MAC takes its lowest port's, so an AP address below the
		// wired ports' (same OUI) would become the LAN MAC and flip every time hostapd leaves and rejoins it.
		b.WriteString("mr_apmac() { f=/sys/class/ieee80211/$1/macaddress; d=$2; x=$3; [ -r \"$f\" ] || return 0; " +
			"set -- $(tr ':' ' ' < \"$f\"); m=$(printf '%02x:%s:%s:%s:%s:%02x' $(( ((0x$1 | 2) + x) & 0xff )) \"$2\" \"$3\" \"$4\" \"$5\" $(( 0x$6 & 0xfc ))); " +
			"[ \"$(cat \"/sys/class/net/$d/address\" 2>/dev/null)\" = \"$m\" ] || { ip link set \"$d\" down; ip link set \"$d\" address \"$m\"; }; }\n")
	}
	// drop driver defaults like wlan0 and anything that isn't one of our primary APs
	// (extra BSSes phyN-ap0-<i> are created and removed by hostapd itself)
	fmt.Fprintf(b, "for d in /sys/class/net/*/phy80211; do d=${d%%%%/phy80211}; d=${d##*/}; case \" %s \" in *\" $d \"*) ;; *-ap0-[0-9]*) ;; *) iw dev \"$d\" del;; esac; done\n", strings.Join(aps, " "))
	for _, r := range c.WiFi.Radios {
		ap := r.Phy + "-ap0"
		band := map[string]int{"2g": 1, "5g": 2}[r.Band]
		fmt.Fprintf(b, "p=$(mr_phy %d); if [ -n \"$p\" ] && [ \"$(cat /sys/class/net/%s/phy80211/name 2>/dev/null)\" != \"$p\" ]; then iw dev %s del 2>/dev/null; iw phy \"$p\" interface add %s type __ap; fi\n", band, ap, ap, ap)
		if len(r.SSIDs) > 1 {
			fmt.Fprintf(b, "[ -n \"$p\" ] && mr_apmac \"$p\" %s %d\n", ap, 4*band)
		}
	}
}

func wifiDefaults(c *Config) {
	st := &c.WiFi.Steering
	if st.Enabled && st.MinSignal2G == 0 { // only while on: an absent section stays absent
		st.MinSignal2G = steerMinSignal
	}
	for i := range st.Exclude {
		st.Exclude[i] = strings.ToLower(st.Exclude[i])
	}
	for i := range c.WiFi.Radios {
		r := &c.WiFi.Radios[i]
		if r.BeaconInt == 0 {
			r.BeaconInt = 100
		}
		if r.DTIM == 0 {
			r.DTIM = 2
		}
		for j := range r.SSIDs {
			s := &r.SSIDs[j]
			for k := range s.MACList {
				s.MACList[k] = strings.ToLower(s.MACList[k])
			}
		}
	}
}

func init() {
	register(&Module{
		Name:     "wifi",
		Prio:     20,
		Defaults: wifiDefaults,
		Validate: wifiValidate,
		Render: func(c *Config, out *Out) error {
			for _, r := range c.WiFi.Radios {
				s, err := renderHostapd(c, r)
				if err != nil {
					return err
				}
				out.Add(hostapdConfPath(r), 0600, s)
				ifs := apIfnames(r)
				for i, ss := range r.SSIDs {
					if ss.MACFilter != "" {
						out.Add(macListPath(ifs[i]), 0600, renderMACList(ss))
					}
				}
			}
			out.Add(GenDir+"/wifi-post.sh", 0755, renderWifiPost(c))
			// WED: mt76 hands WiFi<->ethernet flows to the PPE too (takes effect when mt7915e loads)
			wed := 0
			if c.Firewall.Offload == "hardware" {
				wed = 1
			}
			out.Add("/etc/modprobe.d/mt7915e.conf", 0644, fmt.Sprintf("options mt7915e wed_enable=%d\n", wed))
			return nil
		},
		NetSh: wifiNetSh,
		FlowDevs: func(c *Config) []string {
			var d []string
			for _, r := range c.WiFi.Radios {
				d = append(d, apIfnames(r)...)
			}
			return d
		},
		Services: func(c *Config) []string {
			if len(c.WiFi.Radios) > 0 {
				return []string{"mr-hostapd"}
			}
			return nil
		},
		Managed: []string{"mr-hostapd"},
		Restart: func(path string) string {
			if strings.HasPrefix(path, "/etc/hostapd/") || path == GenDir+"/wifi-post.sh" {
				return "mr-hostapd"
			}
			if path == "/etc/modprobe.d/mt7915e.conf" {
				return "-" // driver option: applies on next module load / reboot
			}
			return ""
		},
		RestartOrder: []string{"mr-hostapd"},
		Verify:       wifiVerify,
		Status: func(c *Config, st map[string]any) {
			st["wifi"] = wifiStatusAll(c)
		},
		API: map[string]func(r apiReq) apiResp{
			"clients":       func(apiReq) apiResp { return apiStations() }, // kept for older pages
			"wifi.stations": func(apiReq) apiResp { return apiStations() },
			"wifi.status":   func(apiReq) apiResp { return apiWifiStatus() },
			"wifi.kick":     apiKick,
			"wifi.survey":   func(apiReq) apiResp { return apiSurvey() },
			"wifi.scan":     apiScan,
			"wifi.health":   func(apiReq) apiResp { return apiWifiHealth() },
		},
		Commands: map[string]func(c *Config, args []string) error{"wifi": wifiCommand},
	})
}

var (
	reHTM = lazyRegexp(`^HE(20|40|80|160)$`)
	// generic profile: 802.11n / ac / ax
	reHTMGeneric = lazyRegexp(`^(HT(20|40)|VHT(20|40|80|160)|HE(20|40|80|160))$`)
	reChans      = lazyRegexp(`^[0-9]+(-[0-9]+)?( [0-9]+(-[0-9]+)?)*$`)
	reCC         = lazyRegexp(`^[A-Z]{2}$`)
	rePhy        = lazyRegexp(`^phy[0-9]$`)
)

// saeSuffixes are the parts hostapd's sae_password parser splits off; a passphrase containing one
// would silently become a different password.
var saeSuffixes = []string{"|mac=", "|vlanid=", "|pk=", "|id="}

func wifiValidate(c *Config, v *Validator) {
	if c.WiFi.Country != "" && !reCC.MatchString(c.WiFi.Country) {
		v.Add("wifi.country: two upper-case letters, got %q", c.WiFi.Country)
	}
	validateSteering(c, v)
	phys := map[string]bool{}
	bands := map[string]bool{}
	for i, r := range c.WiFi.Radios {
		p := fmt.Sprintf("wifi.radios[%d]", i)
		if !rePhy.MatchString(r.Phy) || phys[r.Phy] {
			v.Add("%s.phy: phy0..phy9, unique, got %q", p, r.Phy)
		}
		phys[r.Phy] = true
		if r.Band != "2g" && r.Band != "5g" {
			v.Add("%s.band: 2g|5g, got %q", p, r.Band)
		} else if bands[r.Band] {
			v.Add("%s.band: only one radio per band (%s)", p, r.Band)
		}
		bands[r.Band] = true
		switch r.Profile {
		case "", "mt7986", "generic":
		default:
			v.Add("%s.profile: mt7986|generic, got %q", p, r.Profile)
		}
		if r.Profile == "generic" {
			if !reHTMGeneric.MatchString(r.HTMode) {
				v.Add("%s.htmode: HT20|HT40|VHT20|VHT40|VHT80|VHT160|HE20|HE40|HE80|HE160, got %q", p, r.HTMode)
			}
		} else if !reHTM.MatchString(r.HTMode) {
			v.Add("%s.htmode: HE20|HE40|HE80|HE160, got %q", p, r.HTMode)
		}
		if r.Band == "2g" && (htWidth(r.HTMode) > 40 || strings.HasPrefix(r.HTMode, "VHT")) {
			v.Add("%s.htmode: 2.4 GHz supports HT20|HT40|HE20|HE40, got %q", p, r.HTMode)
		}
		if r.Channel != "auto" {
			if n, err := strconv.Atoi(r.Channel); err != nil || n < 1 || n > 196 {
				v.Add("%s.channel: auto or number, got %q", p, r.Channel)
			} else if r.Band == "5g" && htWidth(r.HTMode) > 20 && centerChan(n, r.HTMode) == 0 {
				v.Add("%s: channel %d cannot carry %s", p, n, r.HTMode)
			}
		}
		if r.Channels != "" && !reChans.MatchString(r.Channels) {
			v.Add("%s.channels: e.g. \"1-11\", got %q", p, r.Channels)
		}
		if r.TxPower < 0 || r.TxPower > 40 {
			v.Add("%s.txpower: 0-40 dBm", p)
		}
		if r.BeaconInt < 10 || r.BeaconInt > 10000 {
			v.Add("%s.beacon_int: 10-10000 TU, got %d", p, r.BeaconInt)
		}
		if r.DTIM < 1 || r.DTIM > 255 {
			v.Add("%s.dtim_period: 1-255, got %d", p, r.DTIM)
		}
		if len(r.SSIDs) == 0 || len(r.SSIDs) > maxSSIDs {
			v.Add("%s.ssids: 1-%d SSIDs per radio", p, maxSSIDs)
		}
		names := map[string]bool{}
		for j, s := range r.SSIDs {
			q := fmt.Sprintf("%s.ssids[%d]", p, j)
			if s.SSID == "" || len(s.SSID) > 32 {
				v.Add("%s.ssid: 1-32 bytes", q)
			} else if !safeText(s.SSID) {
				v.Add("%s.ssid: control characters", q)
			} else if names[s.SSID] {
				v.Add("%s.ssid: %q twice on this radio", q, s.SSID)
			}
			names[s.SSID] = true
			if c.BridgeFor(s.Network) == "" {
				v.Add("%s.network: unknown network %q", q, s.Network)
			}
			validateSSIDSecurity(c, s, q, v)
			if s.MaxClients < 0 || s.MaxClients > 2007 {
				v.Add("%s.max_clients: 0 (no limit) - 2007, got %d", q, s.MaxClients)
			}
			seen := map[string]bool{}
			for _, m := range s.MACList {
				if !reMAC.MatchString(m) {
					v.Add("%s.maclist: invalid MAC %q", q, m)
				} else if seen[strings.ToLower(m)] {
					v.Add("%s.maclist: %s listed twice", q, m)
				}
				seen[strings.ToLower(m)] = true
			}
			switch s.MACFilter {
			case "", "deny":
			case "allow":
				if len(s.MACList) == 0 {
					v.Add("%s.maclist: macfilter allow with an empty list would lock every device out", q)
				}
			default:
				v.Add("%s.macfilter: allow|deny or empty, got %q", q, s.MACFilter)
			}
		}
	}
}

// validateSteering: wifi.steering. While on, some SSID must exist on both bands with the same
// encryption, password and network (a client only moves within one network), and no same-named pair
// may differ in those (a client asked to move could not join).
func validateSteering(c *Config, v *Validator) {
	st := c.WiFi.Steering
	if st.MinSignal2G != 0 && (st.MinSignal2G < -90 || st.MinSignal2G > -30) {
		v.Add("wifi.steering.min_signal_2g: -90 to -30 dBm, got %d", st.MinSignal2G)
	}
	if len(st.Exclude) > 64 {
		v.Add("wifi.steering.exclude: at most 64 devices")
	}
	seen := map[string]bool{}
	for _, m := range st.Exclude {
		if !reMAC.MatchString(m) {
			v.Add("wifi.steering.exclude: invalid MAC %q", m)
		} else if seen[strings.ToLower(m)] {
			v.Add("wifi.steering.exclude: %s listed twice", m)
		}
		seen[strings.ToLower(m)] = true
	}
	if !st.Enabled {
		return
	}
	two, five := bandRadio(c, "2g"), bandRadio(c, "5g")
	if two == nil || five == nil {
		v.Add("wifi.steering: needs a 2.4 GHz and a 5 GHz radio")
		return
	}
	for _, a := range two.SSIDs {
		for _, b := range five.SSIDs {
			if a.SSID == b.SSID && !steerCompatible(a, b) {
				v.Add("wifi.steering: SSID %q differs between 2.4 and 5 GHz (encryption, key_secret or network): a client asked to move could not join", a.SSID)
			}
		}
	}
	if len(steerPairs(c)) == 0 {
		v.Add("wifi.steering: no SSID is on both 2.4 and 5 GHz with the same encryption, key_secret and network (steering moves clients within one SSID)")
	}
}

// validateSSIDSecurity: encryption, passphrase and 802.11w (PMF) sanity for one SSID.
func validateSSIDSecurity(c *Config, s SSID, q string, v *Validator) {
	switch s.Encryption {
	case "none":
		if s.PMF != "" {
			v.Add("%s.pmf: management frame protection needs encryption (encryption is none)", q)
		}
		return
	case "sae-mixed", "sae", "psk2":
	default:
		v.Add("%s.encryption: sae-mixed|sae|psk2|none, got %q", q, s.Encryption)
		return
	}
	if !regexpSecretKey(s.Key) || s.Key == pwSecretKey {
		v.Add("%s.key_secret: secret name [a-z0-9_-]{1,40}, got %q", q, s.Key)
		return
	}
	k, err := c.Secret(s.Key)
	if err != nil || len(k) < 8 || len(k) > 63 {
		v.Add("%s.key_secret: 8-63 char passphrase required (%v)", q, orMissing(err))
	}
	for _, ch := range k {
		if ch < 0x20 || ch > 0x7e {
			v.Add("%s.key_secret: passphrase must be printable ASCII", q)
			break
		}
	}
	if s.Encryption != "psk2" {
		for _, x := range saeSuffixes {
			if strings.Contains(k, x) {
				v.Add("%s.key_secret: a WPA3 passphrase must not contain %q", q, x)
			}
		}
	}
	switch s.PMF {
	case "":
	case "disabled", "optional", "required":
		if s.Encryption == "sae" && s.PMF != "required" {
			v.Add("%s.pmf: WPA3-SAE always requires management frame protection, got %q", q, s.PMF)
		}
		if s.Encryption == "sae-mixed" && s.PMF == "disabled" {
			v.Add("%s.pmf: WPA3 clients need management frame protection; use optional or required", q)
		}
	default:
		v.Add("%s.pmf: disabled|optional|required or empty, got %q", q, s.PMF)
	}
}
