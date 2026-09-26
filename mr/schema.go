package main

// JSON Schema of router.yaml (Cd1s/mini-router#17; MCP input schemas, Cd1s/mini-router#37/#38; editor
// completion): generated from the Go types by reflection, so it cannot drift from what the config
// decoder accepts. Types, nesting and unknown keys (additionalProperties: false) come from the
// types; value sets (enum) from schemaEnums, which a test checks against validation. `required`
// lists the keys that are always present in the effective config (GET config, `mr export`); a
// router.yaml may leave them out — the defaults fill them in. `mr schema [PATH]`, `GET schema`.

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
)

// schemaEnums: the value sets of string fields (and of the items of string lists), by Go
// <type>.<field>. "" = empty is valid (a default applies).
func schemaEnums() map[string][]string {
	e := func(v ...string) []string { return v }
	opt := func(v []string) []string { return append([]string{""}, v...) }
	var ssMethods []string
	for m := range proxySSMethods {
		ssMethods = append(ssMethods, m)
	}
	sort.Strings(ssMethods)
	return map[string][]string{
		"WAN.Proto":           e("pppoe", "dhcp", "static"),
		"Network.Zone":        e("", "guest", "lan"),
		"MultiWAN.Mode":       e("", "failover", "balance"),
		"Radio.Band":          e("2g", "5g"),
		"Radio.Profile":       e("", "mt7986", "generic"),
		"Radio.HTMode":        e("HT20", "HT40", "VHT20", "VHT40", "VHT80", "VHT160", "HE20", "HE40", "HE80", "HE160"),
		"SSID.Encryption":     e("sae-mixed", "sae", "psk2", "none"),
		"SSID.PMF":            e("", "disabled", "optional", "required"),
		"SSID.MACFilter":      e("", "allow", "deny"),
		"RA.Mode":             e("", "slaac", "stateless", "stateful"),
		"RA.Priority":         e("", "high", "low"),
		"DNS.Upstream":        e("", "isp", "manual", "dot"),
		"Record.Type":         e("A", "AAAA", "CNAME", "PTR", "SRV", "TXT"),
		"Firewall.Offload":    e("", "hardware", "software", "off"),
		"Forward.Proto":       e("tcp", "udp"),
		"Open.Proto":          e("tcp", "udp"),
		"FwV6Allow.Proto":     e("tcp", "udp"),
		"FwRule.Action":       e("accept", "drop", "reject"),
		"FwRule.Src":          e("", "any", "lan", "guest", "wan"),
		"FwRule.Dest":         e("", "any", "lan", "guest", "wan", "router"),
		"FwRule.Proto":        e("tcp", "udp", "icmp"),
		"FwTime.Days":         e("mon", "tue", "wed", "thu", "fri", "sat", "sun"),
		"Proxy.LogLevel":      e("", "error", "warn", "info", "debug"),
		"ProxyNode.Type":      opt(proxyTypeNames),
		"ProxyNode.Method":    opt(ssMethods),
		"ProxyNode.Flow":      opt(proxyFlows),
		"ProxyNode.Security":  opt(proxyVMessSec),
		"ProxyNode.Transport": opt(proxyTransports),
		"ProxyNode.Obfs":      e("", "salamander"),
		// sing-box option sets
		"ProxyNode.PacketEncoding":    opt(proxyPacketEnc),
		"ProxyNode.CongestionControl": opt(proxyCongestion),
		"ProxyNode.UDPRelayMode":      opt(proxyUDPRelay),
		"ProxyNode.Fingerprint":       opt(proxyFingerprints),
		"ProxyGroup.Type":             e("urltest", "selector"),
		"Schedule.Action":             e("reboot", "restart", "reconnect", "wol"),
		"DDNSRecord.Provider":         e("", "cloudflare"),
		"APIToken.Scope":              e("read", "operate", "apply"),
		"SSHAgent.Scope":              e("read", "operate", "apply"),
		"Guard.MaxRiskWithoutTouch":   e("", "low", "medium"),

		"DNSSovereignty.PrivateRelay": e("", "allow", "block"),
	}
}

func configSchema() map[string]any {
	s := typeSchema(reflect.TypeOf(Config{}), "", schemaEnums())
	s["$schema"] = "https://json-schema.org/draft/2020-12/schema"
	s["title"] = "mini-router router.yaml"
	s["description"] = "The whole router (/etc/mini-router/router.yaml). Secrets are never in it: *_secret keys name " +
		"entries of secrets.yaml. required = always present in the effective config; a file may leave them out (defaults). " +
		"Paths for mr get/set and API patches: a.b[name].c (list items by name, or phy / ssid / mac; [key=value]; [N])."
	return s
}

func typeSchema(t reflect.Type, key string, enums map[string][]string) map[string]any {
	switch t.Kind() {
	case reflect.Pointer:
		return typeSchema(t.Elem(), key, enums)
	case reflect.Bool:
		return map[string]any{"type": "boolean"}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return map[string]any{"type": "integer"}
	case reflect.Float32, reflect.Float64:
		return map[string]any{"type": "number"}
	case reflect.String:
		s := map[string]any{"type": "string"}
		if v, ok := enums[key]; ok {
			s["enum"] = v
		}
		return s
	case reflect.Slice:
		return map[string]any{"type": "array", "items": typeSchema(t.Elem(), key, enums)}
	case reflect.Map:
		return map[string]any{"type": "object", "additionalProperties": typeSchema(t.Elem(), "", enums)}
	case reflect.Struct:
		props := map[string]any{}
		req := []string{}
		structFields(t, props, &req, enums)
		s := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
		if len(req) > 0 {
			s["required"] = req
		}
		return s
	}
	return map[string]any{}
}

func structFields(t reflect.Type, props map[string]any, req *[]string, enums map[string][]string) {
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := f.Tag.Get("yaml")
		if !f.IsExported() || tag == "-" {
			continue
		}
		name, opts, _ := strings.Cut(tag, ",")
		if strings.Contains(opts, "inline") {
			structFields(f.Type, props, req, enums)
			continue
		}
		if name == "" {
			name = strings.ToLower(f.Name)
		}
		p := typeSchema(f.Type, t.Name()+"."+f.Name, enums)
		if strings.HasSuffix(name, "_secret") {
			p["description"] = "name of a secret in secrets.yaml (router.yaml never holds the value)"
		}
		props[name] = p
		if !strings.Contains(opts, "omitempty") {
			*req = append(*req, name)
		}
	}
}

// schemaAt: the part of schema s that describes the values at path.
func schemaAt(s map[string]any, path string) (map[string]any, error) {
	steps, err := parsePath(path)
	if err != nil {
		return nil, err
	}
	for i, st := range steps {
		var next any
		if st.sel {
			next = s["items"]
		} else if props, ok := s["properties"].(map[string]any); ok {
			next = props[st.key]
		} else {
			next = s["additionalProperties"]
		}
		n, ok := next.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s: no such key in router.yaml", fmtPath(steps[:i+1]))
		}
		s = n
	}
	return s, nil
}

// schemaCommand is `mr schema [PATH]`.
func schemaCommand(args []string) error {
	s := configSchema()
	if len(args) > 0 {
		var err error
		if s, err = schemaAt(s, args[0]); err != nil {
			return err
		}
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(s)
}
