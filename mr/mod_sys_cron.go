package main

// sys module: scheduled tasks (router.yaml schedules) run by busybox crond.
//
// Only a fixed set of actions exists, and the crontab only ever contains fixed text built from
// validated tokens:
//
//	reboot             /usr/sbin/mr sys run reboot
//	restart <service>  /usr/sbin/mr sys run restart <service>   (a service the config enables)
//	reconnect <wan>    /usr/sbin/mr sys run reconnect <wan>     (restarts mr-pppoe.<wan> / mr-udhcpc.<wan>)
//	wol <host>         /usr/sbin/mr sys run wol <host>          (Wake-on-LAN: a dhcp.hosts name or a MAC)
//
// plus, while services.ddns is on with an interval, the DDNS safety check (mod_sys_ddns.go), and while
// services.edge is on, the daily certificate check (mod_sys_edge_acme.go; minute and hour fixed per router):
//
//	*/<interval> * * * * /usr/sbin/mr ddns sync --cron
//	M H * * * /usr/sbin/mr edge renew --cron
//
// and while dns.adblock is on, the hourly list check (mod_dns_adblock.go; downloads once a day):
//
//	M * * * * /usr/sbin/mr dns adblock update --cron
//
// `mr sys run` checks the action against the live config again, logs it (syslog + change log) and
// runs it. The time spec is a strict 5-field cron expression (numbers, *, a-b, /step, lists; no
// names, no @reboot) with safety limits: every task runs at most once per hour (fixed minute), a
// reboot at most once per day (fixed minute and hour). crond gets the zone via /etc/conf.d/crond.
// The crontab is a marked block in /etc/crontabs/root; Alpine's periodic lines and anything else
// outside the block are kept.

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Schedule is one scheduled task.
type Schedule struct {
	Name    string `yaml:"name"`
	Enabled *bool  `yaml:"enabled,omitempty"` // default true
	Cron    string `yaml:"cron"`              // "minute hour day month weekday", e.g. "30 4 * * 1"
	Action  string `yaml:"action"`            // reboot | restart | reconnect | wol
	Target  string `yaml:"target,omitempty"`  // restart: service name; reconnect: WAN name; wol: dhcp.hosts name or MAC
}

// cronFile is root's crontab (a variable so tests can point it elsewhere).
var cronFile = "/etc/crontabs/root"

const (
	cronBegin = "# --- begin mini-router schedules (router.yaml schedules) ---"
	cronEnd   = "# --- end mini-router schedules ---"
	mrBin     = "/usr/sbin/mr"
)

// cron field bounds as busybox crond parses them
var cronFields = []struct {
	name     string
	min, max int
}{{"minute", 0, 59}, {"hour", 0, 23}, {"day", 1, 31}, {"month", 1, 12}, {"weekday", 0, 6}}

// parseCronField checks one field ("*", "*/n", "a", "a-b", "a-b/n", comma lists of those) and
// reports whether it is a single fixed number.
func parseCronField(s string, lo, hi int) (single bool, err error) {
	items := strings.Split(s, ",")
	if len(items) > 16 {
		return false, fmt.Errorf("at most 16 list items")
	}
	num := func(x string) (int, error) {
		if x == "" || len(x) > 2 {
			return 0, fmt.Errorf("bad number %q", x)
		}
		for _, ch := range x {
			if ch < '0' || ch > '9' {
				return 0, fmt.Errorf("bad number %q", x)
			}
		}
		n, _ := strconv.Atoi(x)
		if n < lo || n > hi {
			return 0, fmt.Errorf("%d out of range %d-%d", n, lo, hi)
		}
		return n, nil
	}
	for _, it := range items {
		rng, step, hasStep := strings.Cut(it, "/")
		if hasStep {
			n, err := strconv.Atoi(step)
			if err != nil || n < 1 || n > hi-lo+1 || len(step) > 2 {
				return false, fmt.Errorf("bad step %q", step)
			}
		}
		switch {
		case rng == "*":
		case strings.Contains(rng, "-"):
			a, b, _ := strings.Cut(rng, "-")
			x, err := num(a)
			if err != nil {
				return false, err
			}
			y, err := num(b)
			if err != nil {
				return false, err
			}
			if x > y {
				return false, fmt.Errorf("range %q runs backwards", rng)
			}
		default:
			if _, err := num(rng); err != nil {
				return false, err
			}
			if hasStep {
				return false, fmt.Errorf("a step needs * or a range")
			}
		}
	}
	single = len(items) == 1 && !strings.ContainsAny(s, "*-/")
	return single, nil
}

// checkCron validates a 5-field spec for an action; returns the normalized spec.
func checkCron(spec, action string) (string, error) {
	f := strings.Fields(spec)
	if len(f) != 5 {
		return "", fmt.Errorf("want 5 fields (minute hour day month weekday), got %d", len(f))
	}
	var single [5]bool
	for i, x := range f {
		s, err := parseCronField(x, cronFields[i].min, cronFields[i].max)
		if err != nil {
			return "", fmt.Errorf("%s: %v", cronFields[i].name, err)
		}
		single[i] = s
	}
	if !single[0] {
		return "", fmt.Errorf("minute must be one number (a task runs at most once per hour)")
	}
	if action == "reboot" && !single[1] {
		return "", fmt.Errorf("hour must be one number for reboot (at most once per day)")
	}
	return strings.Join(f, " "), nil
}

// scheduleService resolves an action/target against c: the OpenRC service it restarts ("" for reboot).
func scheduleService(c *Config, action, target string) (string, error) {
	switch action {
	case "reboot":
		if target != "" {
			return "", fmt.Errorf("reboot takes no target")
		}
		return "", nil
	case "restart":
		if target == "mr-network" {
			return "", fmt.Errorf("mr-network cannot be restarted (it is re-run by apply)")
		}
		for _, s := range enabledServices(c) {
			if s == target {
				return s, nil
			}
		}
		return "", fmt.Errorf("restart: %q is not a service this config enables", target)
	case "reconnect":
		w := c.WANByName(target)
		if w == nil {
			return "", fmt.Errorf("reconnect: no wan %q", target)
		}
		svc := netService(*w)
		if svc == "" {
			return "", fmt.Errorf("reconnect: wan %q is static (nothing to reconnect)", target)
		}
		return svc, nil
	case "wol":
		// target ends up in the crontab line: a MAC or an existing dhcp.hosts name (reHostname) only
		if _, _, _, err := wolTarget(c, target, ""); err != nil {
			return "", fmt.Errorf("wol: %v", err)
		}
		return "", nil
	}
	return "", fmt.Errorf("action: reboot | restart | reconnect | wol, got %q", action)
}

func validateSchedules(c *Config, v *Validator) {
	if len(c.Schedules) > 32 {
		v.Add("schedules: at most 32")
	}
	names := map[string]bool{}
	for i, s := range c.Schedules {
		p := fmt.Sprintf("schedules[%d]", i)
		if !reLabel.MatchString(s.Name) {
			v.Add("%s.name: letters, digits, _ . - (1-40), got %q", p, s.Name)
		} else if names[s.Name] {
			v.Add("%s.name: duplicate %q", p, s.Name)
		}
		names[s.Name] = true
		if _, err := checkCron(s.Cron, s.Action); err != nil {
			v.Add("%s.cron: %v", p, err)
		}
		if _, err := scheduleService(c, s.Action, s.Target); err != nil {
			v.Add("%s: %v", p, err)
		}
	}
}

func cronWanted(c *Config) bool {
	if ddnsInterval(c) > 0 || edgeOn(c) || c.DNS.Adblock.Enabled {
		return true
	}
	for _, s := range c.Schedules {
		if on(s.Enabled) {
			return true
		}
	}
	return false
}

// renderCronLines: the managed crontab lines (only valid, enabled schedules).
func renderCronLines(c *Config) []string {
	var lines []string
	for _, s := range c.Schedules {
		if !on(s.Enabled) {
			continue
		}
		spec, err := checkCron(s.Cron, s.Action)
		if err != nil {
			continue
		}
		if _, err := scheduleService(c, s.Action, s.Target); err != nil {
			continue
		}
		cmd := mrBin + " sys run " + s.Action
		if s.Target != "" {
			cmd += " " + s.Target
		}
		lines = append(lines, "# "+s.Name, spec+" "+cmd)
	}
	if n := ddnsInterval(c); n > 0 {
		lines = append(lines, "# ddns (services.ddns)", fmt.Sprintf("*/%d * * * * %s ddns sync --cron", n, mrBin))
	}
	return append(append(lines, edgeCronLine(c)...), adblockCronLine(c)...)
}

// renderCrontab: /etc/crontabs/root with the managed block (ok=false: leave the file alone).
func renderCrontab(c *Config) (string, bool) {
	cur, _ := os.ReadFile(cronFile)
	return mergeManaged(string(cur), cronBegin, cronEnd, renderCronLines(c))
}

func renderCrondConf(c *Config) string {
	return fmt.Sprintf("# generated by mr\nCRON_OPTS=\"-c /etc/crontabs\"\n# schedules run in the router's zone (system.timezone)\nexport TZ='%s'\n", sysTZ(c))
}

// sysRunTask is `mr sys run ACTION [TARGET]` (called by crond).
func sysRunTask(c *Config, args []string) error {
	if len(args) < 1 || len(args) > 2 {
		return fmt.Errorf("usage: mr sys run reboot | restart SERVICE | reconnect WAN | wol HOST|MAC")
	}
	action, target := args[0], ""
	if len(args) == 2 {
		target = args[1]
	}
	svc, err := scheduleService(c, action, target)
	if err != nil {
		return err
	}
	what := strings.TrimSpace(action + " " + target)
	logf("schedule: %s", what)
	appendChangeLog("schedule: " + what)
	if action == "wol" {
		_, err := wolWake(c, target, "")
		return err
	}
	if action == "reboot" {
		run("sync")
		_, err := run("reboot")
		return err
	}
	if _, err := os.Stat("/etc/init.d/" + svc); err != nil {
		return fmt.Errorf("service %s is not installed", svc)
	}
	if out, err := run("rc-service", svc, "restart"); err != nil {
		logf("schedule: %s failed: %v %s", what, err, strings.TrimSpace(out))
		return err
	}
	return nil
}
