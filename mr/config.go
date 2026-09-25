package main

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the single source of truth for the router (/etc/mini-router/router.yaml).
// Each section's type lives in the module that owns it (mod_*.go); see docs/MODULES.md.
type Config struct {
	System    System     `yaml:"system"`              // sys
	LAN       LAN        `yaml:"lan"`                 // net
	Networks  []Network  `yaml:"networks,omitempty"`  // net: extra LAN-side networks (guest, IoT, VLANs)
	WAN       []WAN      `yaml:"wan"`                 // net
	MultiWAN  MultiWAN   `yaml:"multiwan,omitempty"`  // net: failover / load balancing
	Policy    []Policy   `yaml:"policy_routes"`       // net
	Routes    []Route    `yaml:"static_routes"`       // net
	Mcast     Mcast      `yaml:"multicast"`           // net
	Firewall  Firewall   `yaml:"firewall"`            // fw
	DHCP      DHCP       `yaml:"dhcp"`                // dns
	DNS       DNS        `yaml:"dns"`                 // dns
	WiFi      WiFi       `yaml:"wifi"`                // wifi
	Proxy     Proxy      `yaml:"proxy,omitempty"`     // proxy: selective transparent proxy
	Services  Services   `yaml:"services"`            // sys
	Schedules []Schedule `yaml:"schedules,omitempty"` // sys
	Guard     Guard      `yaml:"guard,omitempty"`     // baselines every config must keep (guard.go)

	secrets map[string]string
}

func loadConfig(path, secretsPath string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := &Config{}
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	c.secrets = map[string]string{}
	if sb, err := os.ReadFile(secretsPath); err == nil {
		if err := yaml.Unmarshal(sb, &c.secrets); err != nil {
			return nil, fmt.Errorf("%s: %w", secretsPath, err)
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	c.defaults()
	return c, nil
}

func (c *Config) defaults() {
	for _, m := range modules {
		if m.Defaults != nil {
			m.Defaults(c)
		}
	}
}

func (c *Config) Secret(key string) (string, error) {
	if key == "" {
		return "", nil
	}
	v, ok := c.secrets[key]
	if !ok {
		return "", fmt.Errorf("secret %q missing from secrets.yaml", key)
	}
	return v, nil
}

// RulePref is where mr's ip rules sit: after tailscale's (5210-5270) so tailnet routes win, before main (32766).
const RulePref = 5300

// shared validation helpers
var (
	reName  = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,14}$`)
	reLabel = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,40}$`) // free-form rule names
	reMAC   = regexp.MustCompile(`^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$`)
	rePort  = regexp.MustCompile(`^[0-9]{1,5}(-[0-9]{1,5})?$`)
	reMark  = regexp.MustCompile(`^0x[0-9a-fA-F]{1,8}$`)
	reDev   = regexp.MustCompile(`^[A-Za-z0-9_.@-]{1,15}$`)
	rePath  = regexp.MustCompile(`^/[A-Za-z0-9_./-]{1,200}$`)
)

// Validate returns every problem found, so one run shows all mistakes.
func (c *Config) Validate() []string {
	v := &Validator{}
	for _, m := range modules {
		if m.Validate != nil {
			m.Validate(c, v)
		}
	}
	guardValidate(c, v)
	return v.errs
}

func orMissing(err error) any {
	if err == nil {
		return "missing"
	}
	return err
}

func validPorts(s string) bool {
	if !rePort.MatchString(s) {
		return false
	}
	parts := strings.SplitN(s, "-", 2)
	lo, _ := strconv.Atoi(parts[0])
	hi := lo
	if len(parts) == 2 {
		hi, _ = strconv.Atoi(parts[1])
	}
	return lo >= 1 && hi <= 65535 && lo <= hi
}

func validProtos(p []string) bool {
	if len(p) == 0 {
		return false
	}
	for _, x := range p {
		if x != "tcp" && x != "udp" {
			return false
		}
	}
	return true
}

// safeText reports whether s can be embedded in a generated config line (no newlines,
// NULs or other control characters). Every free-form string must pass this.
func safeText(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}
