package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type svcStatus struct {
	Name    string `json:"name"`
	Running bool   `json:"running"`
}

// printStatus emits the JSON the panel, the web UI overview and the agent consume.
func printStatus(c *Config) error {
	st, err := collectStatus(c)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(st)
}

// collectStatus: core system facts, then every module's Status keys (wan, wifi, leases, tailscale, ...).
func collectStatus(c *Config) (map[string]any, error) {
	st := map[string]any{}
	host, _ := os.Hostname()
	st["host"] = host
	st["version"] = "mini-router " + version + " (Alpine " + strings.TrimSpace(readFile("/etc/alpine-release")) + ")"
	st["kernel"] = strings.TrimSpace(firstField(readFile("/proc/sys/kernel/osrelease")))
	st["time"] = time.Now().Unix()
	st["uptime"] = int64(atof(firstField(readFile("/proc/uptime"))))
	if f := strings.Fields(readFile("/proc/loadavg")); len(f) >= 3 {
		st["load"] = strings.Join(f[:3], " ")
	}
	mem := meminfo()
	st["mem_total_kb"], st["mem_avail_kb"] = mem["MemTotal"], mem["MemAvailable"]
	st["temp_mc"] = atoi(strings.TrimSpace(readFile("/sys/class/thermal/thermal_zone0/temp")))
	st["conntrack"] = atoi(strings.TrimSpace(readFile("/proc/sys/net/netfilter/nf_conntrack_count")))
	st["conntrack_max"] = atoi(strings.TrimSpace(readFile("/proc/sys/net/netfilter/nf_conntrack_max")))
	total, free := dfKB("/etc/mini-router")
	st["overlay_total_kb"], st["overlay_free_kb"] = total, free
	st["hnat_bind"] = strings.Count(readFile("/proc/net/nf_conntrack"), "[HW_OFFLOAD]")

	for _, m := range modules {
		if m.Status != nil {
			m.Status(c, st)
		}
	}

	var svcs []svcStatus
	for _, s := range enabledServices(c) {
		err := exec.Command("rc-service", s, "status").Run()
		svcs = append(svcs, svcStatus{s, err == nil})
	}
	st["services"] = svcs

	var changes []string
	lines := strings.Split(strings.TrimSpace(readFile(ChangeLog)), "\n")
	if len(lines) > 15 {
		lines = lines[len(lines)-15:]
	}
	for _, l := range lines {
		if l != "" {
			changes = append(changes, l)
		}
	}
	st["changes"] = changes
	return st, nil
}

func readFile(p string) string { b, _ := os.ReadFile(p); return string(b) }

func firstField(s string) string {
	if f := strings.Fields(s); len(f) > 0 {
		return f[0]
	}
	return ""
}

func atoi(s string) int     { n, _ := strconv.Atoi(s); return n }
func atof(s string) float64 { f, _ := strconv.ParseFloat(s, 64); return f }

func meminfo() map[string]int {
	m := map[string]int{}
	for _, l := range strings.Split(readFile("/proc/meminfo"), "\n") {
		f := strings.Fields(l)
		if len(f) >= 2 {
			m[strings.TrimSuffix(f[0], ":")] = atoi(f[1])
		}
	}
	return m
}
