package main

// fw module web UI backend: read-only rule counters and the rate-limited drop log.
// Computed on demand inside the CGI (no daemon); fixed argv, no user input.

import (
	"encoding/json"
	"strings"
)

type fwCounter struct {
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

// fwAPIStats (GET fw.stats): counters of the fw-owned rules, keyed by rule comment
// ("rule:<name>", "access:<name>", "v6in:<name>", "wan-in-drop"), and the last kernel log lines
// written by `log_drops` / rules with `log: true`.
func fwAPIStats(r apiReq) apiResp {
	resp := map[string]any{"counters": map[string]fwCounter{}, "log": []string{}}
	if out, err := run("nft", "-j", "list", "table", "inet", "mr"); err == nil {
		resp["counters"] = fwParseCounters([]byte(out))
	} else {
		resp["error"] = "firewall table not loaded"
	}
	if out, err := run("dmesg"); err == nil {
		resp["log"] = fwLogLines(out, 100)
	}
	return apiResp{body: resp}
}

// fwParseCounters sums the counters of every commented rule in `nft -j list table` output.
func fwParseCounters(b []byte) map[string]fwCounter {
	var doc struct {
		Nftables []struct {
			Rule *struct {
				Comment string                       `json:"comment"`
				Expr    []map[string]json.RawMessage `json:"expr"`
			} `json:"rule"`
		} `json:"nftables"`
	}
	out := map[string]fwCounter{}
	if json.Unmarshal(b, &doc) != nil {
		return out
	}
	for _, it := range doc.Nftables {
		if it.Rule == nil || it.Rule.Comment == "" {
			continue
		}
		for _, e := range it.Rule.Expr {
			raw, ok := e["counter"]
			if !ok {
				continue
			}
			var ctr fwCounter
			if json.Unmarshal(raw, &ctr) == nil {
				sum := out[it.Rule.Comment]
				sum.Packets += ctr.Packets
				sum.Bytes += ctr.Bytes
				out[it.Rule.Comment] = sum
			}
		}
	}
	return out
}

// fwLogLines keeps the last max kernel log lines written by fw log rules.
func fwLogLines(dmesg string, max int) []string {
	lines := []string{}
	for _, l := range strings.Split(dmesg, "\n") {
		if strings.Contains(l, "mr-drop ") || strings.Contains(l, "mr-rule ") {
			lines = append(lines, strings.TrimSpace(l))
		}
	}
	if len(lines) > max {
		lines = lines[len(lines)-max:]
	}
	return lines
}
