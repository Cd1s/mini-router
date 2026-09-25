package main

// sys module: time. system.timezone is a POSIX TZ string (Alpine ships no zoneinfo), validated
// strictly here. It is rendered three ways:
//
//	/etc/localtime       a TZif file carrying the POSIX string, so every musl / Go program (syslogd
//	                     timestamps, crond, lucky, mr itself) uses local time without a TZ variable
//	/etc/conf.d/crond    export TZ=... (crond gets the zone even if /etc/localtime were unreadable)
//	/etc/profile.d/tz.sh export TZ=... for login shells
//
// NTP: busybox ntpd syncs from system.ntp; with system.ntp_server it also answers on udp/123.
// ntpd listens on every address, but the firewall input chain only accepts the LAN zone
// (LAN-zone bridges + tailscale0); guest networks and WANs are dropped (fw module).
//
// Coarse time over HTTP: the board has no RTC, and hotels often block udp/123 while VMess /
// Shadowsocks 2022 need the clock within a minute or so. The WAN connectivity check hands over the
// Date header of an online (204) answer; while NTP has not synced and the clock is more than 60 s off
// it is stepped to that Date once (clockFromHTTP). ntpd stays in charge as soon as it gets through.

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// posixTZ is a parsed POSIX TZ string ("std offset [dst [offset],start[/time],end[/time]]").
type posixTZ struct {
	Std, DST       string
	StdOff, DSTOff int // seconds EAST of UTC (POSIX offsets count west, so the sign is flipped)
	HasDST         bool
}

// parseTZ accepts only well-formed POSIX TZ strings: names of 3-16 letters (or <...> with letters,
// digits, + and -), offsets up to 24:59:59, and when a DST name is given, explicit transition rules
// (Jn, n or Mm.w.d, optional /time up to 24:59:59). Everything else is rejected.
func parseTZ(s string) (*posixTZ, error) {
	if s == "" || len(s) > 64 {
		return nil, fmt.Errorf("1-64 characters")
	}
	p := &tzScan{s: s}
	z := &posixTZ{}
	var ok bool
	if z.Std, ok = p.name(); !ok {
		return nil, fmt.Errorf("standard time name: 3-16 letters or <...>, e.g. CET or <+07>")
	}
	off, ok := p.offset(true)
	if !ok {
		return nil, fmt.Errorf("offset after %q: [+-]hh[:mm[:ss]] (hours 0-24, west of UTC is positive)", z.Std)
	}
	z.StdOff = -off
	if p.done() {
		return z, nil
	}
	if z.DST, ok = p.name(); !ok {
		return nil, fmt.Errorf("unexpected %q", p.s)
	}
	z.HasDST = true
	z.DSTOff = z.StdOff + 3600
	if !p.done() && p.s[0] != ',' {
		if off, ok = p.offset(true); !ok {
			return nil, fmt.Errorf("DST offset after %q", z.DST)
		}
		z.DSTOff = -off
	}
	if p.done() {
		return nil, fmt.Errorf("DST %q needs explicit rules: ,start[/time],end[/time] (e.g. ,M3.5.0,M10.5.0/3)", z.DST)
	}
	for i := 0; i < 2; i++ {
		if !p.eat(',') || !p.rule() {
			return nil, fmt.Errorf("DST rule %d: Jn, n or Mm.w.d with optional /hh[:mm[:ss]]", i+1)
		}
	}
	if !p.done() {
		return nil, fmt.Errorf("trailing %q", p.s)
	}
	return z, nil
}

type tzScan struct{ s string }

func (p *tzScan) done() bool { return p.s == "" }

func (p *tzScan) eat(ch byte) bool {
	if p.s != "" && p.s[0] == ch {
		p.s = p.s[1:]
		return true
	}
	return false
}

func (p *tzScan) name() (string, bool) {
	if p.eat('<') {
		i := strings.IndexByte(p.s, '>')
		if i < 3 || i > 16 {
			return "", false
		}
		n := p.s[:i]
		for j := 0; j < len(n); j++ {
			ch := n[j]
			if !(ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '+' || ch == '-') {
				return "", false
			}
		}
		p.s = p.s[i+1:]
		return n, true
	}
	i := 0
	for i < len(p.s) && (p.s[i] >= 'A' && p.s[i] <= 'Z' || p.s[i] >= 'a' && p.s[i] <= 'z') {
		i++
	}
	if i < 3 || i > 16 {
		return "", false
	}
	n := p.s[:i]
	p.s = p.s[i:]
	return n, true
}

// num reads 1..max digits and returns the value.
func (p *tzScan) num(maxDigits int) (int, bool) {
	i := 0
	for i < len(p.s) && i < maxDigits && p.s[i] >= '0' && p.s[i] <= '9' {
		i++
	}
	if i == 0 {
		return 0, false
	}
	n, _ := strconv.Atoi(p.s[:i])
	p.s = p.s[i:]
	return n, true
}

// offset reads [+-]hh[:mm[:ss]] (hours 0-24) and returns seconds; signed=false forbids the sign.
func (p *tzScan) offset(signed bool) (int, bool) {
	sign := 1
	if signed {
		if p.eat('-') {
			sign = -1
		} else {
			p.eat('+')
		}
	}
	h, ok := p.num(2)
	if !ok || h > 24 {
		return 0, false
	}
	secs := h * 3600
	for _, mul := range []int{60, 1} {
		if !p.eat(':') {
			break
		}
		n, ok := p.num(2)
		if !ok || n > 59 {
			return 0, false
		}
		secs += n * mul
	}
	return sign * secs, true
}

func (p *tzScan) rule() bool {
	switch {
	case p.eat('J'):
		if n, ok := p.num(3); !ok || n < 1 || n > 365 {
			return false
		}
	case p.eat('M'):
		m, ok1 := p.num(2)
		if !ok1 || m < 1 || m > 12 || !p.eat('.') {
			return false
		}
		w, ok2 := p.num(1)
		if !ok2 || w < 1 || w > 5 || !p.eat('.') {
			return false
		}
		if d, ok := p.num(1); !ok || d > 6 {
			return false
		}
	default:
		if n, ok := p.num(3); !ok || n > 365 {
			return false
		}
	}
	if p.eat('/') {
		if _, ok := p.offset(false); !ok {
			return false
		}
	}
	return true
}

// sysTZ is the configured zone, UTC when unset.
func sysTZ(c *Config) string {
	if c.System.Timezone == "" {
		return "UTC0"
	}
	return c.System.Timezone
}

// tzifFromPOSIX builds a TZif (RFC 8536, version 2) file for a POSIX TZ string: one local time type
// (standard time), a single transition at the "big bang" (-2^59) and the POSIX string as footer.
// Readers (musl, glibc, Go) apply the footer rule to every time after the last transition, i.e.
// always, so DST zones work without a transition table.
func tzifFromPOSIX(tz string) ([]byte, error) {
	z, err := parseTZ(tz)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	chars := z.Std + "\x00"
	header := func(timecnt int) {
		b.WriteString("TZif2")
		b.Write(make([]byte, 15))
		// isutcnt, isstdcnt, leapcnt, timecnt, typecnt, charcnt
		binary.Write(&b, binary.BigEndian, [6]uint32{0, 0, 0, uint32(timecnt), 1, uint32(len(chars))})
	}
	ttinfo := func() {
		binary.Write(&b, binary.BigEndian, int32(z.StdOff))
		b.WriteByte(0) // isdst
		b.WriteByte(0) // designation index
		b.WriteString(chars)
	}
	header(0) // v1 block (32-bit): no transitions, just the standard-time type
	ttinfo()
	header(1) // v2 block (64-bit)
	binary.Write(&b, binary.BigEndian, int64(-1)<<59)
	b.WriteByte(0) // transition -> type 0
	ttinfo()
	b.WriteString("\n" + tz + "\n")
	return b.Bytes(), nil
}

// sysLocation is time.Location for the configured zone (UTC if it cannot be built).
func sysLocation(c *Config) *time.Location {
	tz := sysTZ(c)
	if data, err := tzifFromPOSIX(tz); err == nil {
		if loc, err := time.LoadLocationFromTZData(tz, data); err == nil {
			return loc
		}
	}
	return time.UTC
}

var reNTPHost = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,62})(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}))*\.?$`)

// validNTPServer: an IP address or a host name (busybox ntpd -p argument; no "keyno:" prefixes).
func validNTPServer(s string) bool {
	if net.ParseIP(s) != nil {
		return true
	}
	return len(s) <= 253 && reNTPHost.MatchString(s)
}

func renderNtpd(c *Config) string {
	args := []string{"-S /usr/libexec/mr/clock-save"} // saves the synced time for the next boot (no RTC)
	for _, s := range c.System.NTP {
		args = append(args, "-p "+s)
	}
	if c.System.NTPServer {
		args = append(args, "-l") // answer NTP requests; the firewall only lets the LAN zone in
	}
	return fmt.Sprintf("# generated by mr\nNTPD_OPTS=\"-N %s\"\n", strings.Join(args, " "))
}

// httpClockMaxSkew: a clock that NTP has not synced is stepped to an HTTP Date beyond this.
const httpClockMaxSkew = 60 * time.Second

var (
	clockFloorFile = "/etc/mini-router-release"     // image build time: the clock never goes before it (as mr-clock)
	clockRefFile   = "/etc/mini-router/state/clock" // mr-clock starts from its mtime after a reboot
)

// httpClockStep reports whether a clock reading now should be stepped to date (an HTTP Date): only
// while NTP has not synced, only for a skew above httpClockMaxSkew, never to before floor (the image
// build) or into the next century.
func httpClockStep(synced bool, now, date, floor time.Time) bool {
	if synced || date.IsZero() || date.Before(floor) || date.Year() >= 2100 {
		return false
	}
	d := date.Sub(now)
	return d > httpClockMaxSkew || d < -httpClockMaxSkew
}

// clockFromHTTP: the skew (seconds) between an HTTP Date and the clock at the moment the server sent
// it, and whether the clock was stepped to it (see httpClockStep). src names the URL for the log.
func clockFromHTTP(date, sent time.Time, src string) (int64, bool) {
	skew := int64(date.Sub(sent).Round(time.Second) / time.Second)
	synced, known := clockSynced()
	if !known {
		return skew, false
	}
	var floor time.Time
	if fi, err := os.Stat(clockFloorFile); err == nil {
		floor = fi.ModTime()
	}
	if !httpClockStep(synced, sent, date, floor) {
		return skew, false
	}
	t := date.Add(time.Since(sent)) // the time that has passed since the answer
	if err := setClock(t); err != nil {
		logf("clock: cannot set from the HTTP Date of %s: %v", src, err)
		return skew, false
	}
	logf("clock: stepped %+ds to %s from the HTTP Date of %s (NTP not synced yet; ntpd takes over when it can)",
		skew, t.UTC().Format(time.RFC3339), src)
	if _, err := os.Stat(clockRefFile); err == nil {
		os.Chtimes(clockRefFile, t, t)
	}
	return skew, true
}

// apiSysTime: the router's clock as the configured zone sees it, plus NTP sync state.
func apiSysTime(r apiReq) apiResp {
	c, err := loadConfig(ConfigPath, SecretsPath)
	if err != nil {
		return errResp(500, "%v", err)
	}
	now := time.Now()
	loc := sysLocation(c)
	lt := now.In(loc)
	_, off := lt.Zone()
	body := map[string]any{
		"now": now.Unix(), "tz": sysTZ(c), "offset": off,
		"local":      lt.Format("2006-01-02 15:04:05 MST"),
		"ntp":        c.System.NTP,
		"ntp_server": c.System.NTPServer,
		"synced":     nil,
	}
	if s, ok := clockSynced(); ok {
		body["synced"] = s
	}
	return apiResp{body: body}
}
