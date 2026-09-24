package main

// fw module: weekly time windows (traffic rules, access control) → nftables `meta day` / `meta hour`.
//
// The kernel evaluates `meta hour` in UTC and `meta day` in the kernel timezone (sys_tz, normally
// UTC), while nft converts "HH:MM" strings with the timezone of whatever process runs nft. To be
// independent of all of that, windows are converted here from system.timezone to UTC and emitted
// as raw seconds (`meta hour 54000-86399`, nft takes numbers verbatim), split at UTC midnight and
// at kernel-day boundaries. The UTC offset is taken at render time, so a DST change takes effect
// at the next firewall reload (boot, PPPoE reconnect, apply, `mr fw`).

import (
	"fmt"
	"sort"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

type fwClock struct {
	LocalOff int // local time offset east of UTC, seconds
	KernelMW int // kernel sys_tz.tz_minuteswest (what `meta day` uses)
}

// overridable in tests
var (
	fwNow      = time.Now
	fwKernelMW = kernelMinutesWest
)

func fwClockFor(c *Config) fwClock {
	return fwClock{LocalOff: tzOffset(c.System.Timezone, fwNow()), KernelMW: fwKernelMW()}
}

// kernelMinutesWest reads the kernel timezone (gettimeofday(NULL, &tz)).
func kernelMinutesWest() int {
	var tz [2]int32
	if _, _, e := syscall.RawSyscall(syscall.SYS_GETTIMEOFDAY, 0, uintptr(unsafe.Pointer(&tz[0])), 0); e != 0 {
		return 0
	}
	return int(tz[0])
}

const fwWeek = 7 * 86400

var fwDayNames = []string{"Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"}

// fwTimeMatches converts weekly windows into nft match expressions: the rule must be emitted once
// per returned expression. An empty schedule (or one covering the whole week) returns [""].
func fwTimeMatches(sch []FwTime, clk fwClock) []string {
	if len(sch) == 0 {
		return []string{""}
	}
	type iv struct{ a, b int }
	var ivs []iv
	for _, t := range sch {
		var days []int
		for _, d := range t.Days {
			if n, ok := fwDayNum[d]; ok {
				days = append(days, n)
			}
		}
		if len(days) == 0 {
			days = []int{0, 1, 2, 3, 4, 5, 6}
		}
		s, e := 0, 86400
		if t.Time != "" {
			var ok bool
			if s, e, ok = fwParseWindow(t.Time); !ok {
				continue
			}
			if e <= s {
				e += 86400 // crosses midnight: ends on the next day
			}
		}
		for _, d := range days {
			a := ((d*86400+s-clk.LocalOff)%fwWeek + fwWeek) % fwWeek
			b := a + e - s
			if b > fwWeek {
				ivs = append(ivs, iv{a, fwWeek}, iv{0, b - fwWeek})
			} else {
				ivs = append(ivs, iv{a, b})
			}
		}
	}
	// union of all windows (UTC seconds since Sunday 00:00)
	sort.Slice(ivs, func(i, j int) bool { return ivs[i].a < ivs[j].a })
	var merged []iv
	for _, x := range ivs {
		if n := len(merged); n > 0 && x.a <= merged[n-1].b {
			merged[n-1].b = max(merged[n-1].b, x.b)
		} else {
			merged = append(merged, x)
		}
	}
	if len(merged) == 1 && merged[0].a == 0 && merged[0].b == fwWeek {
		return []string{""}
	}
	kOff := ((clk.KernelMW*60)%86400 + 86400) % 86400
	groups := map[[2]int]map[int]bool{} // UTC hour range → kernel weekdays
	for _, x := range merged {
		for p := x.a; p < x.b; {
			q := (p/86400 + 1) * 86400                                  // next UTC midnight
			if kb := p - ((p-kOff)%86400+86400)%86400 + 86400; kb < q { // next kernel-day boundary
				q = kb
			}
			if x.b < q {
				q = x.b
			}
			kday := (((p-clk.KernelMW*60)%fwWeek + fwWeek) % fwWeek) / 86400
			k := [2]int{p % 86400, (q - 1) % 86400}
			if groups[k] == nil {
				groups[k] = map[int]bool{}
			}
			groups[k][kday] = true
			p = q
		}
	}
	keys := make([][2]int, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i][0] != keys[j][0] {
			return keys[i][0] < keys[j][0]
		}
		return keys[i][1] < keys[j][1]
	})
	var out []string
	for _, k := range keys {
		var parts []string
		if days := groups[k]; len(days) < 7 {
			var names []string
			for d := 0; d < 7; d++ {
				if days[d] {
					names = append(names, fwDayNames[d])
				}
			}
			parts = append(parts, "meta day { "+strings.Join(names, ", ")+" }")
		}
		switch {
		case k[0] == 0 && k[1] == 86399:
		case k[0] == k[1]:
			parts = append(parts, fmt.Sprintf("meta hour %d", k[0]))
		default:
			parts = append(parts, fmt.Sprintf("meta hour %d-%d", k[0], k[1]))
		}
		if len(parts) == 0 {
			return []string{""} // the windows cover the whole week
		}
		out = append(out, strings.Join(parts, " "))
	}
	if len(out) == 0 {
		return nil // nothing valid: never matches (validation rejects this anyway)
	}
	return out
}

// ---- POSIX TZ ("<+07>-7", "ICT-7", "UTC0", "CET-1CEST,M3.5.0,M10.5.0/3") ----

// tzOffset returns the UTC offset (seconds east) of a TZ value at time t. Olson names work only if
// zoneinfo is installed; anything unparsable counts as UTC (the string itself is validated by sys).
func tzOffset(tz string, t time.Time) int {
	if tz == "" {
		return 0
	}
	p := &tzParser{s: tz}
	ok := p.name()
	std := 0
	if ok {
		std, ok = p.offset()
	}
	if !ok { // not POSIX: maybe an Olson name ("Asia/Bangkok", ":Europe/Berlin")
		if loc, err := time.LoadLocation(strings.TrimPrefix(tz, ":")); err == nil {
			_, off := t.In(loc).Zone()
			return off
		}
		return 0
	}
	stdEast := -std
	if p.s == "" || !p.name() {
		return stdEast
	}
	dstEast := stdEast + 3600
	if p.s != "" && p.s[0] != ',' {
		d, ok := p.offset()
		if !ok {
			return stdEast
		}
		dstEast = -d
	}
	rules := strings.Split(strings.TrimPrefix(p.s, ","), ",")
	if !strings.HasPrefix(p.s, ",") || len(rules) != 2 {
		return stdEast // DST without explicit rules: implementation-defined, ignore
	}
	year := time.Unix(t.Unix()+int64(stdEast), 0).UTC().Year()
	start, ok1 := tzRule(rules[0], year, stdEast)
	end, ok2 := tzRule(rules[1], year, dstEast)
	if !ok1 || !ok2 {
		return stdEast
	}
	u := t.Unix()
	if (start < end && u >= start && u < end) || (start > end && (u >= start || u < end)) {
		return dstEast
	}
	return stdEast
}

type tzParser struct{ s string }

func (p *tzParser) name() bool {
	if strings.HasPrefix(p.s, "<") {
		i := strings.IndexByte(p.s, '>')
		if i < 2 {
			return false
		}
		p.s = p.s[i+1:]
		return true
	}
	i := 0
	for i < len(p.s) && (p.s[i] >= 'A' && p.s[i] <= 'Z' || p.s[i] >= 'a' && p.s[i] <= 'z') {
		i++
	}
	if i < 3 {
		return false
	}
	p.s = p.s[i:]
	return true
}

// offset parses [+-]hh[:mm[:ss]] into seconds.
func (p *tzParser) offset() (int, bool) {
	sign := 1
	if strings.HasPrefix(p.s, "+") {
		p.s = p.s[1:]
	} else if strings.HasPrefix(p.s, "-") {
		sign, p.s = -1, p.s[1:]
	}
	secs := 0
	for k, mul := range []int{3600, 60, 1} {
		if k > 0 {
			if !strings.HasPrefix(p.s, ":") {
				break
			}
			p.s = p.s[1:]
		}
		i := 0
		for i < len(p.s) && i < 3 && p.s[i] >= '0' && p.s[i] <= '9' {
			i++
		}
		if i == 0 {
			return 0, false
		}
		secs += atoi(p.s[:i]) * mul
		p.s = p.s[i:]
	}
	return sign * secs, secs <= 25*3600
}

// tzRule returns when a "Mm.w.d[/time]" transition happens in year, the wall clock running at
// offset east (seconds).
func tzRule(r string, year, east int) (int64, bool) {
	secs := 7200
	if i := strings.IndexByte(r, '/'); i >= 0 {
		p := &tzParser{s: r[i+1:]}
		v, ok := p.offset()
		if !ok || p.s != "" {
			return 0, false
		}
		secs, r = v, r[:i]
	}
	f := strings.Split(strings.TrimPrefix(r, "M"), ".")
	if !strings.HasPrefix(r, "M") || len(f) != 3 {
		return 0, false
	}
	for _, x := range f {
		if x == "" || len(x) > 2 || strings.Trim(x, "0123456789") != "" {
			return 0, false
		}
	}
	m, w, d := atoi(f[0]), atoi(f[1]), atoi(f[2])
	if m < 1 || m > 12 || w < 1 || w > 5 || d < 0 || d > 6 {
		return 0, false
	}
	first := time.Date(year, time.Month(m), 1, 0, 0, 0, 0, time.UTC)
	day := 1 + (d-int(first.Weekday())+7)%7 + (w-1)*7
	for day > time.Date(year, time.Month(m)+1, 0, 0, 0, 0, 0, time.UTC).Day() {
		day -= 7
	}
	wall := time.Date(year, time.Month(m), day, 0, 0, 0, 0, time.UTC).Unix() + int64(secs)
	return wall - int64(east), true
}
