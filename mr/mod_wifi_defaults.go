package main

// The factory image deliberately has no radios.  This read-only suggestion is
// used by the first-run wizard (and by the WiFi page's enable action) to turn
// detected hardware into validated router.yaml values without guessing a
// secret.  It never changes the running configuration or starts hostapd.

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
)

type wifiRadioSuggestion struct {
	Phy     string               `json:"phy"`
	Band    string               `json:"band"`
	Channel string               `json:"channel"`
	HTMode  string               `json:"htmode"`
	Profile string               `json:"profile,omitempty"`
	TxPower int                  `json:"txpower"`
	SSIDs   []wifiSSIDSuggestion `json:"ssids"`
}

type wifiSSIDSuggestion struct {
	SSID       string `json:"ssid"`
	KeySecret  string `json:"key_secret"`
	Encryption string `json:"encryption"`
}

func suggestedRadio(band string, logical int) wifiRadioSuggestion {
	mode, name := "HE80", "MiniRouter-5G"
	if band == "2g" {
		mode, name = "HE40", "MiniRouter-2.4G"
	}
	return wifiRadioSuggestion{
		Phy: "phy" + strconv.Itoa(logical), Band: band, Channel: "auto", HTMode: mode,
		Profile: "generic", SSIDs: []wifiSSIDSuggestion{{SSID: name, KeySecret: "wifi_key", Encryption: "psk2"}},
	}
}

// wifiHardwareBands returns one logical radio per supported band.  The
// logical names are stable (phy0/phy1); renderNetwork resolves them to the
// kernel phy by band, so a driver may enumerate hardware in another order.
func wifiHardwareBands() (twoG, fiveG bool) {
	ents, err := os.ReadDir("/sys/class/ieee80211")
	if err != nil {
		return false, false
	}
	for _, ent := range ents {
		// /sys/class/ieee80211/phyN is a symlink on Alpine; IsDir reports
		// false for it even though the target is the hardware directory.
		if !strings.HasPrefix(ent.Name(), "phy") {
			continue
		}
		b, err := exec.Command("iw", "phy", ent.Name(), "info").Output()
		if err != nil {
			continue
		}
		twoG = twoG || strings.Contains(string(b), "Band 1:")
		fiveG = fiveG || strings.Contains(string(b), "Band 2:")
	}
	return twoG, fiveG
}

func suggestedWiFiRadios() []wifiRadioSuggestion {
	twoG, fiveG := wifiHardwareBands()
	var out []wifiRadioSuggestion
	if twoG {
		out = append(out, suggestedRadio("2g", 0))
	}
	if fiveG {
		out = append(out, suggestedRadio("5g", 1))
	}
	return out
}

func apiWifiDefaults() apiResp {
	return apiResp{body: map[string]any{"radios": suggestedWiFiRadios()}}
}
