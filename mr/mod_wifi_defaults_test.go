package main

import "testing"

func TestSuggestedRadioDefaults(t *testing.T) {
	two := suggestedRadio("2g", 0)
	if two.Phy != "phy0" || two.Band != "2g" || two.HTMode != "HE40" || two.SSIDs[0].KeySecret != "wifi_key" {
		t.Fatalf("2g suggestion=%+v", two)
	}
	five := suggestedRadio("5g", 1)
	if five.Phy != "phy1" || five.Band != "5g" || five.HTMode != "HE80" || five.SSIDs[0].SSID != "MiniRouter-5G" {
		t.Fatalf("5g suggestion=%+v", five)
	}
}
