package main

// Front-panel LEDs: status = green once the router is up; network = blue while at least one WAN has
// an IPv4 address, red when none does. U-Boot leaves the status LED red, and nothing else touches it.
// LEDs are found by name (*:status, *:network or *:wan); RGB (multicolor) LEDs get a colour, single
// colour LEDs are switched on/off. system.leds: false turns them all off.

import (
	"os"
	"path/filepath"
	"strings"
)

const ledDir = "/sys/class/leds"

// setLED sets one LED: rgb = "R G B" for multicolor LEDs, on = brightness for plain ones.
func setLED(name, rgb string, on bool) {
	d := filepath.Join(ledDir, name)
	os.WriteFile(filepath.Join(d, "trigger"), []byte("none"), 0644)
	if _, err := os.Stat(filepath.Join(d, "multi_intensity")); err == nil && on {
		os.WriteFile(filepath.Join(d, "multi_intensity"), []byte(rgb), 0644)
	}
	b := "0"
	if on {
		b = strings.TrimSpace(readFile(filepath.Join(d, "max_brightness")))
		if b == "" {
			b = "1"
		}
	}
	os.WriteFile(filepath.Join(d, "brightness"), []byte(b), 0644)
}

func ledsByRole() (status, network []string) {
	ents, _ := os.ReadDir(ledDir)
	for _, e := range ents {
		n := e.Name()
		switch {
		case strings.HasSuffix(n, ":status"):
			status = append(status, n)
		case strings.HasSuffix(n, ":network"), strings.HasSuffix(n, ":wan"):
			network = append(network, n)
		}
	}
	return
}

// updateLEDs sets every LED from the current state. Cheap: called from the WAN hooks and `mr led`.
func updateLEDs(c *Config) {
	status, network := ledsByRole()
	on := c.System.LEDs == nil || *c.System.LEDs
	for _, l := range status {
		setLED(l, "0 255 0", on)
	}
	up := false
	for _, w := range c.WAN {
		up = up || hasIPv4(w.Ifname())
	}
	rgb := "255 0 0"
	if up {
		rgb = "0 0 255"
	}
	for _, l := range network {
		setLED(l, rgb, on)
	}
}
