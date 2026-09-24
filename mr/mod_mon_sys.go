package main

// mon.procs (process list from /proc) and mon.dmesg (kernel ring buffer via syslog(2)).

import (
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf8"
)

type monProc struct {
	PID     int    `json:"pid"`
	PPID    int    `json:"ppid"`
	Name    string `json:"name"`
	State   string `json:"state"` // R running, S sleeping, D disk wait, Z zombie, I idle (kernel)
	User    string `json:"user"`
	RSS     uint64 `json:"rss"` // KiB resident
	VSZ     uint64 `json:"vsz"` // KiB virtual
	Threads int    `json:"threads"`
	CPU     uint64 `json:"cpu"`   // utime + stime in clock ticks (USER_HZ = 100); the UI diffs between polls
	Start   uint64 `json:"start"` // clock ticks after boot
	Kernel  bool   `json:"kernel,omitempty"`
	Cmd     string `json:"cmd,omitempty"` // argv, secrets-looking values replaced by ***
}

// monParsePidStat parses /proc/<pid>/stat; the command name may contain spaces and parentheses.
func monParsePidStat(s string, pageKB uint64) (monProc, bool) {
	i, j := strings.IndexByte(s, '('), strings.LastIndexByte(s, ')')
	if i < 0 || j < i {
		return monProc{}, false
	}
	f := strings.Fields(s[j+1:])
	if len(f) < 22 {
		return monProc{}, false
	}
	u := func(k int) uint64 { v, _ := strconv.ParseUint(f[k], 10, 64); return v }
	p := monProc{
		PID: atoi(strings.TrimSpace(s[:i])), Name: monClean(s[i+1 : j]), State: f[0], PPID: atoi(f[1]),
		CPU: u(11) + u(12), Threads: int(u(17)), Start: u(19), VSZ: u(20) / 1024, RSS: u(21) * pageKB,
		Kernel: u(6)&0x00200000 != 0, // PF_KTHREAD
	}
	return p, true
}

var (
	// key=value / key:value arguments whose key looks secret, and flags whose next argument is one
	monSecretKV   = regexp.MustCompile(`(?i)^(-{0,2}[a-z0-9_.-]*(?:pass|secret|token|auth-?key|psk|api-?key|private-?key)[a-z0-9_.-]*[=:])(.+)$`)
	monSecretFlag = regexp.MustCompile(`(?i)^-{1,2}[a-z0-9_.-]*(?:pass|secret|token|auth-?key|psk|api-?key|private-?key)[a-z0-9_.-]*$`)
)

// monCmdline turns /proc/<pid>/cmdline into one display line with secret-looking values masked.
func monCmdline(raw string) string {
	args := strings.Split(strings.TrimRight(raw, "\x00"), "\x00")
	for i := 0; i < len(args); i++ {
		if m := monSecretKV.FindStringSubmatch(args[i]); m != nil {
			args[i] = m[1] + "***"
		} else if monSecretFlag.MatchString(args[i]) && i+1 < len(args) {
			args[i+1] = "***"
			i++
		}
	}
	s := monClean(strings.Join(args, " "))
	if len(s) > 300 {
		s = s[:300]
		for !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
		s += "…"
	}
	return s
}

// monClean replaces control characters and invalid UTF-8 (process names and kernel messages are
// arbitrary bytes) so the JSON stays printable.
func monClean(s string) string {
	s = strings.ToValidUTF8(s, "?")
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}

// monUsers maps uid → name from /etc/passwd.
func monUsers() map[uint32]string {
	m := map[uint32]string{}
	for _, l := range strings.Split(readFile(monPath("/etc/passwd")), "\n") {
		f := strings.Split(l, ":")
		if len(f) >= 3 {
			if id, err := strconv.ParseUint(f[2], 10, 32); err == nil {
				m[uint32(id)] = f[0]
			}
		}
	}
	return m
}

func monProcs() map[string]any {
	users := monUsers()
	pageKB := uint64(os.Getpagesize()) / 1024
	procs := []monProc{}
	ents, _ := os.ReadDir(monPath("/proc"))
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		dir := monPath("/proc/" + e.Name())
		p, ok := monParsePidStat(readFile(dir+"/stat"), pageKB)
		if !ok {
			continue // exited meanwhile
		}
		p.PID = pid
		if fi, err := os.Stat(dir); err == nil {
			if st, ok := fi.Sys().(*syscall.Stat_t); ok {
				uid := uint32(st.Uid)
				if p.User = users[uid]; p.User == "" {
					p.User = strconv.FormatUint(uint64(uid), 10)
				}
			}
		}
		if !p.Kernel {
			p.Cmd = monCmdline(readFile(dir + "/cmdline"))
		}
		procs = append(procs, p)
	}
	sort.Slice(procs, func(i, j int) bool { return procs[i].PID < procs[j].PID })
	_, cores := monParseStat(readFile(monPath("/proc/stat")))
	mem := monParseMeminfo(readFile(monPath("/proc/meminfo")))
	return map[string]any{"up": monUptime(), "hz": 100, "ncpu": len(cores), "mem_total": mem["MemTotal"], "procs": procs}
}

// ---- mon.dmesg ----

// monKlog reads the kernel ring buffer (injected for tests; see mod_mon_linux.go).
var monKlog = monReadKlog

const monDmesgMax = 2000

func monDmesg() (map[string]any, error) {
	s, err := monKlog()
	if err != nil {
		return nil, err
	}
	return map[string]any{"up": monUptime(), "lines": monParseKlog(s, monDmesgMax)}, nil
}

// monParseKlog splits "<6>[   12.345678] text" records into [level, "[   12.345678] text"],
// keeping the newest max lines. Level: 0 emerg … 3 err, 4 warning, 5 notice, 6 info, 7 debug.
func monParseKlog(s string, max int) [][2]any {
	out := [][2]any{}
	for _, l := range strings.Split(s, "\n") {
		lvl := 6
		if strings.HasPrefix(l, "<") {
			if j := strings.IndexByte(l, '>'); j > 1 && j < 6 {
				if v, err := strconv.Atoi(l[1:j]); err == nil {
					lvl, l = v&7, l[j+1:]
				}
			}
		}
		if strings.TrimSpace(l) == "" {
			continue
		}
		out = append(out, [2]any{lvl, monClean(l)})
	}
	if len(out) > max {
		out = out[len(out)-max:]
	}
	return out
}
