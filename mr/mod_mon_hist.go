package main

// mon.history: 24 h at 1-minute resolution, sampled by rootfs/usr/libexec/mr/mon-collect (busybox sh,
// service mr-mon) into a RAM ring buffer. The sampler stores raw cumulative counters with the
// uptime as timestamp; rates and wall-clock times are computed here on demand, so a clock step
// (NTP sync after boot: the router has no RTC) or a sampler restart never corrupts the history.

import (
	"math"
	"os"
	"strconv"
	"strings"
	"time"
)

// monSample is one line of the history file:
//
//	uptime_s wan_rx_bytes wan_tx_bytes cpu_busy cpu_total mem_avail_kb conntrack temp_mc
type monSample struct{ Up, RX, TX, Busy, Total, Avail, CT, Temp int64 }

const (
	monHistSpan   = 86400 // seconds kept / served
	monHistMaxGap = 600   // no rate across a gap longer than this (sampler was stopped)
)

func parseMonHistory(data string) []monSample {
	var out []monSample
	for _, l := range strings.Split(data, "\n") {
		f := strings.Fields(l)
		if len(f) != 8 {
			continue // partial line (read during an append) or garbage
		}
		var s monSample
		ok := true
		for i, p := range []*int64{&s.Up, &s.RX, &s.TX, &s.Busy, &s.Total, &s.Avail, &s.CT, &s.Temp} {
			v, err := strconv.ParseInt(f[i], 10, 64)
			if err != nil {
				ok = false
				break
			}
			*p = v
		}
		if ok {
			out = append(out, s)
		}
	}
	return out
}

// monHistoryFor adds the WAN devices the sampler sums (for the chart label).
func monHistoryFor(c *Config, path string) (map[string]any, error) {
	h, err := monHistoryFile(path)
	if err == nil {
		h["wan"] = monNonNil(monWANDevs(c))
	}
	return h, err
}

func monHistoryFile(path string) (map[string]any, error) {
	b, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	mem := monParseMeminfo(readFile(monPath("/proc/meminfo")))
	return monHistory(parseMonHistory(string(b)), time.Now().Unix(), monUptime(), mem["MemTotal"]), nil
}

// monHistory turns samples into columns: t (unix s), rx/tx (bytes/s), cpu (%), mem (used KiB),
// ct (entries), temp (°C). Rates are null where no valid previous sample exists (first sample,
// sampler gap, counter reset such as a WAN device re-created).
func monHistory(ss []monSample, nowUnix int64, nowUp float64, memTotal int64) map[string]any {
	var t []int64
	var rx, tx, cpu, mem, ct, temp []any
	var last int64 = -1
	for i, s := range ss {
		if float64(s.Up) < nowUp-monHistSpan || float64(s.Up) > nowUp+120 {
			continue
		}
		var r, x, u any
		if i > 0 {
			p := ss[i-1]
			if dt := s.Up - p.Up; dt > 0 && dt <= monHistMaxGap {
				if s.RX >= p.RX && s.TX >= p.TX {
					r, x = (s.RX-p.RX)/dt, (s.TX-p.TX)/dt
				}
				if dT := s.Total - p.Total; dT > 0 && s.Busy >= p.Busy {
					u = math.Round(float64(s.Busy-p.Busy)*1000/float64(dT)) / 10
				}
			}
		}
		t = append(t, nowUnix-int64(math.Round(nowUp-float64(s.Up))))
		rx, tx, cpu = append(rx, r), append(tx, x), append(cpu, u)
		var used any
		if memTotal > 0 && s.Avail > 0 {
			used = memTotal - s.Avail
		}
		mem = append(mem, used)
		ct = append(ct, s.CT)
		var tc any
		if s.Temp != 0 {
			tc = math.Round(float64(s.Temp)/100) / 10
		}
		temp = append(temp, tc)
		last = s.Up
	}
	age := -1
	if last >= 0 {
		age = int(nowUp) - int(last)
	}
	return map[string]any{
		"now": nowUnix, "step": 60, "span": monHistSpan, "mem_total": memTotal,
		// the sampler writes once a minute; older than 3 minutes means mr-mon is not running
		"collector": map[string]any{"ok": age >= 0 && age < 180, "age": age, "samples": len(t)},
		"t":         monNonNil(t), "rx": monNonNil(rx), "tx": monNonNil(tx), "cpu": monNonNil(cpu),
		"mem": monNonNil(mem), "ct": monNonNil(ct), "temp": monNonNil(temp),
	}
}

// monNonNil keeps empty columns as [] (not null) in JSON.
func monNonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
