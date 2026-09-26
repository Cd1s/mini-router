// mr — mini-router control tool. router.yaml is the single source of truth.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log/syslog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

var version = "dev"

const usage = `mr — mini-router control

  mr validate                 check router.yaml + secrets.yaml
  mr plan [-v|--explain]      what apply would change: config changes, files, services, risk
                              (-v: what each action does, file diffs with secrets masked)
  mr apply [--confirm SECS [--wait]] [-m COMMENT] [-v]
                              apply router.yaml (auto-rollback on failure;
                              with --confirm, also roll back unless 'mr confirm' runs in time;
                              --wait: ask here, Ctrl-C / a dropped session rolls back at once)
  mr confirm                  keep the last --confirm apply
  mr rollback [SNAPSHOT]      undo the change waiting for confirmation, else restore the latest
                              (or given) snapshot at once
  mr rollback N [--confirm S] the config from before change #N, applied as a new change
  mr rollback --boot          at boot (mr-preinit): roll back a change that was never confirmed
  mr history [--json]         the changes: who, when, comment, result, what changed
  mr get [PATH] [--json|--flat]  a value of the effective config (router.yaml + defaults)
  mr set [-n] PATH=VALUE ...  edit router.yaml (validated; comments and layout kept), e.g.
                              mr set 'firewall.forwards[nas].enabled=false'; then mr plan / apply
  mr add [-n] PATH VALUE      append a list item: mr add dhcp.hosts '{name: tv, mac: "…", ip: 192.168.1.30}'
  mr del [-n] PATH ...        remove a key (back to its default) or a list item
  mr export [--json|--flat]   the effective config (--flat: PATH=VALUE lines, as mr set takes them)
  mr schema [PATH]            JSON Schema of router.yaml, from the Go types
  mr token list | create NAME [-scope read|operate|apply] [-from CIDR,..] [-expires DATE] [-allow A,..] | revoke NAME
                              API tokens (Authorization: Bearer) for scripts and agents
  mr mcp [--scope=read|operate|apply] [--agent=NAME]
                              MCP server for AI agents on stdin / stdout (one SSH session;
                              services.ssh.agents keys run it); mr mcp plans | show ID
  mr render DIR               write all generated files under DIR (for review/tests)
  mr fw                       (re)load the firewall for the current set of netdevs
  mr routes                   re-install per-WAN routes/rules for WANs that are up, then reload the firewall
  mr status                   JSON status for the panel / agent
  mr api                      web UI backend (CGI, run by busybox httpd)
  mr passwd < PASSWORD        set the web UI admin password
  mr hook ppp-up|ppp-down ... called by pppd
  mr hook dhcpcd              called by dhcpcd
  mr version

module commands (JSON output unless noted):
  mr wan status | health      WAN state; multi-WAN health
  mr wifi status | stations | survey | scan PHY | kick MAC [IFNAME]
  mr dns stats | leases | query NAME [TYPE] [SERVER] | release IP [MAC] | querylog on [MIN]|off|show
                              | adblock status | update   ad blocking lists (dns.adblock)
  mr proxy status | check | delay [NODE|GROUP] | select GROUP NODE | parse [--secrets] [FILE] | fetch [--secrets] URL|SUB
  mr mon now | history | devices | conns [JSON] | procs | dmesg
  mr sys run ACTION [TARGET] | backup [-secrets] FILE|- | restore [-confirm SECS] FILE | keys
  mr ddns status | update [--force] [NAME...]   DDNS records; update now (sync --hook|--cron: WAN hooks / crond)
  mr wol MAC|HOST [NETWORK]   Wake-on-LAN magic packet (HOST: a dhcp.hosts name) to the LAN's broadcast
  mr doctor [--json]          health and security checks: every finding ok / warn / risk / skip with its fix
  mr event list [--json] [N]  the event log: WAN down / up, failover, changes, login locks, new devices, boots
                              (tick: mr-mon's sampler; boot | shutdown: mr-bootlog)
  mr notify status | test [NAME]   notification channels: what waits, last error; send a test message now
  mr edge status | renew [--force] [CERT...]   HTTPS reverse proxy: routes, certificates; renew now
  mr edge serve [-c FILE]     the proxy itself (service mr-edge; reads only gen/edge.json + certificates)
  mr led                      set the status LEDs from the WAN state
`

func main() {
	// hooks run from pppd (empty environment), dhcpcd and busybox httpd: never depend on the caller's PATH
	os.Setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
	cfgPath := flag.String("c", ConfigPath, "router.yaml")
	secPath := flag.String("s", SecretsPath, "secrets.yaml")
	flag.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	flag.Parse()
	args := flag.Args()
	if len(args) == 0 {
		flag.Usage()
		os.Exit(2)
	}
	if err := dispatch(args, *cfgPath, *secPath); err != nil {
		fmt.Fprintln(os.Stderr, "mr:", err)
		os.Exit(1)
	}
}

func dispatch(args []string, cfgPath, secPath string) error {
	cmd := args[0]
	switch cmd {
	case "version":
		fmt.Println(version)
		return nil
	case "confirm":
		ok, err := confirm()
		if err == nil {
			fmt.Println(map[bool]string{true: "confirmed", false: "nothing pending"}[ok])
		}
		return err
	case "history":
		return historyCommand(args[1:])
	case "rollback":
		return rollbackCommand(args[1:], cfgPath, secPath)
	case "rollback-if-unconfirmed":
		secs, _ := strconv.Atoi(args[2])
		return rollbackIfUnconfirmed(args[1], secs)
	case "api":
		return runAPI()
	case "passwd":
		// mr passwd < password: set the web UI admin password (install.sh, console recovery)
		b, err := io.ReadAll(io.LimitReader(os.Stdin, 1024))
		if err != nil {
			return err
		}
		pw := strings.TrimRight(string(b), "\r\n")
		if len(pw) < 8 {
			return fmt.Errorf("password must be at least 8 characters")
		}
		sec, err := readSecretsFrom(secPath)
		if err != nil {
			return err
		}
		sec[pwSecretKey] = hashPassword(pw)
		if err := writeSecrets(secPath, sec); err != nil {
			return err
		}
		appendChangeLog("mr passwd: web UI admin password set")
		fmt.Println("web UI password set")
		return nil
	case "apply-job":
		secs, _ := strconv.Atoi(args[1])
		return runApplyJob(secs)
	case "get", "set", "add", "del", "export":
		return cfgCommand(cmd, args[1:], cfgPath, secPath)
	case "schema":
		return schemaCommand(args[1:])
	case "token":
		return tokenCommand(args[1:], cfgPath, secPath)
	case "mcp":
		return mcpCommand(args[1:], cfgPath, secPath)
	case "edge":
		// the proxy process runs unprivileged: it must not need router.yaml / secrets.yaml
		if len(args) > 1 && args[1] == "serve" {
			return edgeServe(args[2:])
		}
	}

	c, err := loadConfig(cfgPath, secPath)
	if err != nil {
		return err
	}
	switch cmd {
	case "validate":
		if errs := c.Validate(); len(errs) > 0 {
			return fmt.Errorf("invalid:\n  %s", strings.Join(errs, "\n  "))
		}
		fmt.Println("ok")
	case "plan":
		fs := flag.NewFlagSet("plan", flag.ExitOnError)
		verbose := fs.Bool("v", false, "also show what each action does and each generated file's diff (secrets masked)")
		explain := fs.Bool("explain", false, "same as -v")
		fs.Parse(args[1:])
		*verbose = *verbose || *explain
		if errs := c.Validate(); len(errs) > 0 {
			return fmt.Errorf("invalid:\n  %s", strings.Join(errs, "\n  "))
		}
		p, err := plan(c)
		if err != nil {
			return err
		}
		if p.Empty() {
			fmt.Println("nothing to do")
		} else {
			printPlan(c, p, *verbose)
		}
	case "apply":
		fs := flag.NewFlagSet("apply", flag.ExitOnError)
		secs := fs.Int("confirm", 0, "seconds to wait for `mr confirm`")
		dry := fs.Bool("dry-run", false, "only show the plan")
		comment := fs.String("m", "", "a comment for the history")
		verbose := fs.Bool("v", false, "also show what each action does and each generated file's diff (secrets masked)")
		wait := fs.Bool("wait", false, "with --confirm: ask here; Ctrl-C or a dropped session rolls back at once")
		fs.Parse(args[1:])
		if len(*comment) > 200 || strings.ContainsAny(*comment, "\n\r") {
			return fmt.Errorf("-m: one line, at most 200 characters")
		}
		if err := Apply(c, *dry, *secs, *comment, *verbose); err != nil || !*wait || *secs <= 0 || *dry {
			return err
		}
		return waitConfirm(*secs)
	case "render":
		if len(args) < 2 {
			return fmt.Errorf("render DIR")
		}
		if errs := c.Validate(); len(errs) > 0 {
			return fmt.Errorf("invalid:\n  %s", strings.Join(errs, "\n  "))
		}
		files, err := Render(c)
		if err != nil {
			return err
		}
		files = append(files, File{GenDir + "/nftables.nft", 0644, renderNft(c, func(string) bool { return true })})
		for _, f := range files {
			if err := writeAtomic(filepath.Join(args[1], f.Path), []byte(f.Data), os.FileMode(f.Mode)); err != nil {
				return err
			}
		}
		fmt.Printf("rendered %d files under %s\n", len(files), args[1])
	case "fw":
		return fwLoad(c)
	case "routes":
		refreshRoutes(c)
		updateLEDs(c)
		return fwLoad(c)
	case "led":
		updateLEDs(c)
	case "status":
		return printStatus(c)
	case "hook":
		if len(args) < 2 {
			return fmt.Errorf("hook what?")
		}
		switch args[1] {
		case "ppp-up":
			return hookPPP(c, true, args[2:])
		case "ppp-down":
			return hookPPP(c, false, args[2:])
		case "dhcpcd":
			return hookDhcpcd(c)
		}
		return fmt.Errorf("unknown hook %q", args[1])
	default:
		for _, m := range modules {
			if f, ok := m.Commands[cmd]; ok {
				return f(c, args[1:])
			}
		}
		flag.Usage()
		return fmt.Errorf("unknown command %q", cmd)
	}
	return nil
}

// ---- helpers ----

func run(name string, args ...string) (string, error) {
	var out bytes.Buffer
	cmd := exec.Command(name, args...)
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.String(), err
}

func runStdin(stdin, name string, args ...string) (string, error) {
	var out bytes.Buffer
	cmd := exec.Command(name, args...)
	cmd.Stdin = strings.NewReader(stdin)
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.String(), err
}

func must(name string, args ...string) {
	if out, err := run(name, args...); err != nil {
		logf("%s %s: %v %s", name, strings.Join(args, " "), err, strings.TrimSpace(out))
	}
}

var slog *syslog.Writer

func logf(f string, a ...any) {
	msg := fmt.Sprintf(f, a...)
	if slog == nil {
		slog, _ = syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, "mr")
	}
	if slog != nil {
		slog.Info(msg)
	}
	fmt.Fprintln(os.Stderr, msg)
}

// selfCmd is this mr binary with the same -c / -s files, to run a subcommand in the background.
func selfCmd(args ...string) (string, []string) {
	self, err := os.Executable()
	if err != nil {
		self = "/usr/sbin/mr"
	}
	var pre []string
	for _, f := range []string{"c", "s"} {
		if fl := flag.Lookup(f); fl != nil && fl.Value.String() != fl.DefValue {
			pre = append(pre, "-"+f, fl.Value.String())
		}
	}
	return self, append(pre, args...)
}

func startDetached(name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	devnull, _ := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = devnull, devnull, devnull
	cmd.Start()
}
