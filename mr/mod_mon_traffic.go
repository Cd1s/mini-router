package main

// mon module: monthly traffic per device and per physical WAN device (system.traffic_stats, #33).
//
// While it is on, mon-collect runs `mr mon account` every minute. Devices: the byte deltas of the
// connections in conntrack since the previous run (the per-flow diff of mon.devices, with its own
// snapshot), by MAC (or address). A connection that opens and leaves the table between two runs is
// missed, and so are the last seconds of one that ends, so the numbers are a lower bound (offloaded
// flows count only while the flowtable has `counter`). WAN: the byte counters of the physical WAN
// devices (every WAN on a device together; they also see offloaded packets). Kept in RAM
// (/run/mr-mon/traffic.json) and copied to flash (/etc/mini-router/state/traffic.json) at most once an
// hour and at the month change, so a reboot loses at most an hour. Current and previous month
// (router time).

import (
	"encoding/json"
	"strings"
	"time"
)

const monTrafficMax = 256 // devices per month; later ones are not counted

var (
	monTrafficRun   = monDir + "/traffic.json"
	monTrafficFlows = monDir + "/traffic.flows"
	monTrafficFlash = "/etc/mini-router/state/traffic.json"
	monTrafficNow   = time.Now
)

type monBytes struct {
	Up   uint64 `json:"up"` // WAN: sent (tx)
	Down uint64 `json:"down"`
	Name string `json:"name,omitempty"`
}

type monMonth struct {
	Month string               `json:"month"`
	Dev   map[string]*monBytes `json:"dev"` // MAC (or address) → bytes
	WAN   map[string]*monBytes `json:"wan"` // physical WAN device → bytes
}

type monTrafficState struct {
	Cur   monMonth             `json:"cur"`
	Prev  *monMonth            `json:"prev,omitempty"`
	Last  map[string][2]uint64 `json:"last,omitempty"` // WAN device → rx, tx at the previous run
	Saved int64                `json:"saved"`          // last flash copy (unix)
}

func monTrafficLoad() monTrafficState {
	var st monTrafficState
	if readJSONFile(monTrafficRun, &st); st.Cur.Month == "" {
		readJSONFile(monTrafficFlash, &st) // after a reboot
		st.Last = nil
	}
	return st
}

// monAccount: `mr mon account` (the sampler, every minute).
func monAccount(c *Config) error {
	if c == nil || !c.System.TrafficStats {
		return nil
	}
	lk := flock(monTrafficRun+".lock", false)
	if lk == nil {
		return nil // the previous run is still going
	}
	defer lk.Close()
	now := monTrafficNow()
	if now.Year() < 2025 {
		return nil // clock not set yet (no RTC)
	}
	month := now.UTC().Add(time.Duration(tzOffset(sysTZ(c), now)) * time.Second).Format("2006-01")
	st := monTrafficLoad()
	if st.Cur.Month != month {
		if st.Cur.Month != "" {
			p := st.Cur
			st.Prev = &p
		}
		st.Cur, st.Saved = monMonth{Month: month}, 0
	}
	if st.Cur.Dev == nil {
		st.Cur.Dev = map[string]*monBytes{}
	}
	if st.Cur.WAN == nil {
		st.Cur.WAN = map[string]*monBytes{}
	}
	if res, err := monDevicesAt(c, monTrafficFlows); err == nil {
		list, _ := res["devices"].([]*monDevice)
		for _, d := range list {
			b := st.Cur.Dev[d.ID]
			if b == nil {
				if len(st.Cur.Dev) >= monTrafficMax || d.dUp+d.dDown == 0 {
					continue
				}
				b = &monBytes{}
				st.Cur.Dev[d.ID] = b
			}
			b.Up, b.Down = b.Up+d.dUp, b.Down+d.dDown
			if d.Name != "" {
				b.Name = d.Name
			}
		}
	}
	delta := func(cur, prev uint64) uint64 {
		if cur >= prev {
			return cur - prev
		}
		return cur // counter reset (device re-created)
	}
	last := map[string][2]uint64{}
	for _, dev := range monWANDevs(c) {
		s := monPath("/sys/class/net/" + dev + "/statistics/")
		rx, tx := strings.TrimSpace(readFile(s+"rx_bytes")), strings.TrimSpace(readFile(s+"tx_bytes"))
		if rx == "" || tx == "" {
			continue
		}
		cur := [2]uint64{atou(rx), atou(tx)}
		last[dev] = cur
		if p, ok := st.Last[dev]; ok {
			b := st.Cur.WAN[dev]
			if b == nil {
				b = &monBytes{}
				st.Cur.WAN[dev] = b
			}
			b.Down, b.Up = b.Down+delta(cur[0], p[0]), b.Up+delta(cur[1], p[1])
		}
	}
	st.Last = last
	flash := now.Unix()-st.Saved >= 3600 || now.Unix() < st.Saved
	if flash {
		st.Saved = now.Unix()
	}
	b, _ := json.Marshal(st)
	if err := writeAtomic(monTrafficRun, b, 0600); err != nil {
		return err
	}
	if flash {
		return writeAtomic(monTrafficFlash, b, 0600)
	}
	return nil
}

// monTraffic: API mon.traffic / `mr mon traffic`.
func monTraffic(c *Config) map[string]any {
	st := monTrafficLoad()
	return map[string]any{"enabled": c != nil && c.System.TrafficStats, "cur": st.Cur, "prev": st.Prev, "saved": st.Saved}
}
