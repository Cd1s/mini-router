package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	ConfigPath  = "/etc/mini-router/router.yaml"
	SecretsPath = "/etc/mini-router/secrets.yaml"
	GenDir      = "/etc/mini-router/gen"
	HistoryDir  = "/etc/mini-router/history"
	ConfirmFile = "/run/mini-router/confirm-pending"
	ChangeLog   = "/etc/router-changes.log"
	keepHistory = 20
)

// serviceFor maps a generated path to the OpenRC service that must be restarted when it changes.
func serviceFor(path string) string {
	switch {
	case path == GenDir+"/network.sh":
		return "mr-network"
	}
	for _, m := range modules {
		if m.Restart != nil {
			if s := m.Restart(path); s != "" {
				if s == "-" {
					return ""
				}
				return s
			}
		}
	}
	return ""
}

// restartOrder: lower layers first. Core services, then each module's RestartOrder by module Prio.
func restartOrder() []string {
	o := []string{"hostname", "sysctl", "mr-network"}
	for _, m := range modules {
		o = append(o, m.RestartOrder...)
	}
	return o
}

func rank(s string) int {
	order := restartOrder()
	for i, p := range order {
		if s == p || (strings.HasSuffix(p, ".") && strings.HasPrefix(s, p)) {
			return i
		}
	}
	return len(order)
}

type Plan struct {
	Changed  []File
	Services []string
	Firewall bool
	Enable   []string
	Disable  []string
}

func plan(c *Config) (*Plan, error) {
	files, err := Render(c)
	if err != nil {
		return nil, err
	}
	p := &Plan{}
	svc := map[string]bool{}
	for _, f := range files {
		cur, err := os.ReadFile(f.Path)
		if err == nil && bytes.Equal(cur, []byte(f.Data)) {
			continue
		}
		p.Changed = append(p.Changed, f)
		if s := serviceFor(f.Path); s != "" {
			svc[s] = true
		}
	}
	for s := range svc {
		p.Services = append(p.Services, s)
	}
	sort.Slice(p.Services, func(i, j int) bool { return rank(p.Services[i]) < rank(p.Services[j]) })

	cur, _ := os.ReadFile(GenDir + "/nftables.nft")
	p.Firewall = string(cur) != renderNft(c, netdevExists)

	want := map[string]bool{}
	for _, s := range enabledServices(c) {
		want[s] = true
	}
	have := map[string]bool{}
	if ents, err := os.ReadDir("/etc/runlevels/default"); err == nil {
		for _, e := range ents {
			have[e.Name()] = true
		}
	}
	for s := range want {
		if !have[s] {
			p.Enable = append(p.Enable, s)
		}
	}
	for _, s := range managedServices(c) {
		if have[s] && !want[s] {
			p.Disable = append(p.Disable, s)
		}
	}
	sort.Strings(p.Enable)
	sort.Strings(p.Disable)
	return p, nil
}

// managedServices: everything mr may switch on/off (never touches services it does not own).
func managedServices(c *Config) []string {
	var s []string
	prefixes := []string{"mr-pppoe."}
	for _, m := range modules {
		s = append(s, m.Managed...)
		for _, o := range m.RestartOrder {
			if strings.HasSuffix(o, ".") {
				prefixes = append(prefixes, o)
			}
		}
	}
	// per-instance services (mr-pppoe.<wan>, mr-udhcpc.<wan>, ...) exist only as init.d entries
	if ents, err := os.ReadDir("/etc/init.d"); err == nil {
		for _, e := range ents {
			for _, p := range prefixes {
				if strings.HasPrefix(e.Name(), p) {
					s = append(s, e.Name())
					break
				}
			}
		}
	}
	return dedup(s)
}

func (p *Plan) Empty() bool {
	return len(p.Changed) == 0 && !p.Firewall && len(p.Enable) == 0 && len(p.Disable) == 0
}

func (p *Plan) String() string {
	var b strings.Builder
	for _, f := range p.Changed {
		fmt.Fprintf(&b, "  write   %s\n", f.Path)
	}
	if p.Firewall {
		b.WriteString("  reload  firewall\n")
	}
	for _, s := range p.Services {
		fmt.Fprintf(&b, "  restart %s\n", s)
	}
	for _, s := range p.Enable {
		fmt.Fprintf(&b, "  enable  %s\n", s)
	}
	for _, s := range p.Disable {
		fmt.Fprintf(&b, "  disable %s\n", s)
	}
	return b.String()
}

// snapshot saves every file the plan will touch (plus router.yaml) so a failed apply can be undone.
func snapshot(paths []string) (string, error) {
	os.MkdirAll(HistoryDir, 0700)
	name := filepath.Join(HistoryDir, time.Now().Format("20060102-150405")+".tar.gz")
	f, err := os.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return "", err
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for _, p := range paths {
		st, err := os.Stat(p)
		if err != nil {
			continue // file did not exist before; restore will remove it
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return "", err
		}
		tw.WriteHeader(&tar.Header{Name: strings.TrimPrefix(p, "/"), Mode: int64(st.Mode().Perm()), Size: int64(len(data)), ModTime: st.ModTime()})
		tw.Write(data)
	}
	// list of paths covered, so restore knows which ones to delete
	list := []byte(strings.Join(paths, "\n") + "\n")
	tw.WriteHeader(&tar.Header{Name: ".mr-paths", Mode: 0600, Size: int64(len(list))})
	tw.Write(list)
	tw.Close()
	gz.Close()
	pruneHistory()
	return name, nil
}

func pruneHistory() {
	ents, _ := os.ReadDir(HistoryDir)
	var names []string
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".tar.gz") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for len(names) > keepHistory {
		os.Remove(filepath.Join(HistoryDir, names[0]))
		names = names[1:]
	}
}

// restore puts a snapshot back and returns the services that need restarting.
func restore(snap string) ([]string, error) {
	f, err := os.Open(snap)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(gz)
	present := map[string]bool{}
	var covered []string
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		data, _ := io.ReadAll(tr)
		if h.Name == ".mr-paths" {
			covered = strings.Fields(string(data))
			continue
		}
		p := "/" + h.Name
		present[p] = true
		if err := writeAtomic(p, data, os.FileMode(h.Mode)); err != nil {
			return nil, err
		}
	}
	svc := map[string]bool{}
	for _, p := range covered {
		if !present[p] {
			os.Remove(p)
		}
		if s := serviceFor(p); s != "" {
			svc[s] = true
		}
	}
	var out []string
	for s := range svc {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return rank(out[i]) < rank(out[j]) })
	return out, nil
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	tmp := path + ".mr-tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	os.Chmod(tmp, mode)
	return os.Rename(tmp, path)
}

func restartAll(svcs []string) []string {
	var failed []string
	for _, s := range svcs {
		if s == "mr-network" {
			// re-run in place: restarting the service would restart everything that needs net (PPPoE redial)
			if out, err := run("sh", GenDir+"/network.sh"); err != nil {
				failed = append(failed, fmt.Sprintf("network.sh: %v %s", err, strings.TrimSpace(out)))
			}
			if c, err := loadConfig(ConfigPath, SecretsPath); err == nil {
				refreshRoutes(c)
			}
			continue
		}
		if s == "sysctl" {
			// every module may render its own /etc/sysctl.d/9x-*.conf; reload all of them
			files, _ := filepath.Glob("/etc/sysctl.d/*.conf")
			sort.Strings(files)
			for _, f := range files {
				run("sysctl", "-q", "-p", f)
			}
			continue
		}
		if _, err := os.Stat("/etc/init.d/" + s); err != nil {
			continue
		}
		if out, err := run("rc-service", s, "restart"); err != nil {
			failed = append(failed, fmt.Sprintf("%s: %v %s", s, err, strings.TrimSpace(out)))
		}
	}
	return failed
}

// Apply: validate → plan → snapshot → write → enable/disable → restart → firewall → verify; undo on failure.
func Apply(c *Config, dryRun bool, confirmSecs int) error {
	return applyWith(c, dryRun, confirmSecs, nil)
}

// ApplyCandidate applies a config written by the web UI. The live router.yaml/secrets.yaml are
// snapshotted first and replaced only after the snapshot exists, so a failed or unconfirmed apply
// restores the previous config files too.
func ApplyCandidate(candYAML, candSecrets string, confirmSecs int) error {
	c, err := loadConfig(candYAML, candSecrets)
	if err != nil {
		return err
	}
	install := func() error {
		y, err := os.ReadFile(candYAML)
		if err != nil {
			return err
		}
		s, err := os.ReadFile(candSecrets)
		if err != nil {
			return err
		}
		if err := writeAtomic(ConfigPath, y, 0644); err != nil {
			return err
		}
		return writeAtomic(SecretsPath, s, 0600)
	}
	return applyWith(c, false, confirmSecs, install)
}

func applyWith(c *Config, dryRun bool, confirmSecs int, install func() error) error {
	if errs := c.Validate(); len(errs) > 0 {
		return fmt.Errorf("router.yaml invalid:\n  %s", strings.Join(errs, "\n  "))
	}
	p, err := plan(c)
	if err != nil {
		return err
	}
	if p.Empty() && install == nil {
		fmt.Println("nothing to do")
		return nil
	}
	fmt.Print("plan:\n" + p.String())
	if dryRun {
		return nil
	}
	var paths []string
	for _, f := range p.Changed {
		paths = append(paths, f.Path)
	}
	paths = append(paths, ConfigPath, SecretsPath, GenDir+"/nftables.nft")
	snap, err := snapshot(paths)
	if err != nil {
		return fmt.Errorf("snapshot: %w", err)
	}
	if install != nil {
		if err := install(); err != nil {
			return rollback(snap, fmt.Errorf("install candidate: %w", err))
		}
	}
	for _, f := range p.Changed {
		if err := writeAtomic(f.Path, []byte(f.Data), os.FileMode(f.Mode)); err != nil {
			return rollback(snap, fmt.Errorf("write %s: %w", f.Path, err))
		}
	}
	for _, s := range p.Enable {
		run("rc-update", "add", s, "default")
	}
	for _, s := range p.Disable {
		run("rc-service", s, "stop")
		run("rc-update", "del", s, "default")
	}
	restart := dedup(append(append([]string{}, p.Services...), p.Enable...))
	if failed := restartAll(restart); len(failed) > 0 {
		return rollback(snap, fmt.Errorf("service restart failed:\n  %s", strings.Join(failed, "\n  ")))
	}
	// stopping or restarting a service stops everything that depends on it (e.g. whatever provides
	// "net"); bring every service the config wants back up before checking
	ensureStarted(c)
	refreshRoutes(c)
	if err := fwLoad(c); err != nil {
		return rollback(snap, err)
	}
	if errs := verify(c, restart); len(errs) > 0 {
		return rollback(snap, fmt.Errorf("verification failed:\n  %s", strings.Join(errs, "\n  ")))
	}
	appendChangeLog(fmt.Sprintf("mr apply: %s", summary(p)))
	fmt.Printf("applied (snapshot %s)\n", filepath.Base(snap))
	if confirmSecs > 0 {
		armConfirm(snap, confirmSecs)
		fmt.Printf("run `mr confirm` within %ds or this change is rolled back\n", confirmSecs)
	}
	return nil
}

func rollback(snap string, cause error) error {
	logf("apply failed, rolling back to %s: %v", filepath.Base(snap), cause)
	svcs, err := restore(snap)
	if err != nil {
		return fmt.Errorf("%v\nROLLBACK FAILED: %v", cause, err)
	}
	restartAll(svcs)
	if c, err := loadConfig(ConfigPath, SecretsPath); err == nil {
		reconcileRunlevel(c)
		refreshRoutes(c)
		fwLoad(c)
	}
	appendChangeLog("mr apply: failed and rolled back — " + firstLine(cause.Error()))
	return fmt.Errorf("%v\nrolled back to %s", cause, filepath.Base(snap))
}

// reconcileRunlevel makes the default runlevel match c after a rollback: services the restored
// config wants are enabled and started, managed services it no longer wants are stopped and removed.
func reconcileRunlevel(c *Config) {
	want := map[string]bool{}
	for _, s := range enabledServices(c) {
		want[s] = true
	}
	have := map[string]bool{}
	if ents, err := os.ReadDir("/etc/runlevels/default"); err == nil {
		for _, e := range ents {
			have[e.Name()] = true
		}
	}
	for _, s := range managedServices(c) {
		if have[s] && !want[s] {
			run("rc-service", s, "stop")
			run("rc-update", "del", s, "default")
		}
	}
	for _, s := range enabledServices(c) {
		if _, err := os.Stat("/etc/init.d/" + s); err != nil {
			continue
		}
		if !have[s] {
			run("rc-update", "add", s, "default")
		}
		if _, err := run("rc-service", s, "status"); err != nil {
			run("rc-service", s, "start")
		}
	}
}

func summary(p *Plan) string {
	var parts []string
	for _, f := range p.Changed {
		parts = append(parts, filepath.Base(f.Path))
	}
	if p.Firewall {
		parts = append(parts, "firewall")
	}
	for _, s := range p.Enable {
		parts = append(parts, "+"+s)
	}
	for _, s := range p.Disable {
		parts = append(parts, "-"+s)
	}
	if len(parts) == 0 {
		return "router.yaml (no generated file changed)"
	}
	return strings.Join(parts, ", ")
}

func firstLine(s string) string { return strings.SplitN(s, "\n", 2)[0] }

func appendChangeLog(line string) {
	f, err := os.OpenFile(ChangeLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s %s\n", time.Now().Format("2006-01-02 15:04:05"), line)
}

// ---- confirm / auto-rollback ----

func armConfirm(snap string, secs int) {
	os.MkdirAll(filepath.Dir(ConfirmFile), 0755)
	os.WriteFile(ConfirmFile, []byte(snap), 0600)
	self, _ := os.Executable()
	startDetached(self, "rollback-if-unconfirmed", snap, fmt.Sprint(secs))
}

func rollbackIfUnconfirmed(snap string, secs int) error {
	time.Sleep(time.Duration(secs) * time.Second)
	cur, err := os.ReadFile(ConfirmFile)
	if err != nil || string(cur) != snap {
		return nil // confirmed, or superseded by a newer apply
	}
	os.Remove(ConfirmFile)
	return rollback(snap, fmt.Errorf("not confirmed within %ds", secs))
}

func confirm() error {
	if _, err := os.Stat(ConfirmFile); err != nil {
		fmt.Println("nothing pending")
		return nil
	}
	os.Remove(ConfirmFile)
	fmt.Println("confirmed")
	return nil
}

// ---- verification ----

// ensureStarted starts every service the config wants that is not running (OpenRC stops the
// dependents of a service it stops, and does not bring them back).
func ensureStarted(c *Config) {
	for _, s := range enabledServices(c) {
		if _, err := os.Stat("/etc/init.d/" + s); err != nil {
			continue
		}
		if _, err := run("rc-service", s, "status"); err != nil {
			run("rc-service", s, "start")
		}
	}
}

func verify(c *Config, restarted []string) []string {
	var errs []string
	// every wanted service, not only the restarted ones: a restart can take dependents down with it
	for _, s := range dedup(append(append([]string{}, restarted...), enabledServices(c)...)) {
		if s == "mr-network" || s == "sysctl" {
			continue
		}
		if _, err := os.Stat("/etc/init.d/" + s); err != nil {
			continue
		}
		if _, err := run("rc-service", s, "status"); err != nil {
			errs = append(errs, s+" not running")
		}
	}
	if !netdevExists(c.LAN.Bridge) {
		errs = append(errs, c.LAN.Bridge+" missing")
	}
	if _, err := run("nft", "list", "table", "inet", "mr"); err != nil {
		errs = append(errs, "firewall table missing")
	}
	for _, m := range modules {
		if m.Verify != nil {
			errs = append(errs, m.Verify(c, restarted)...)
		}
	}
	return errs
}

// verifyDeadline is shared by module Verify funcs that wait for something to come up.
func verifyDeadline() time.Time { return time.Now().Add(90 * time.Second) }

func waitFor(deadline time.Time, ok func() bool) bool {
	for {
		if ok() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(2 * time.Second)
	}
}

func hasIPv4(ifname string) bool {
	out, err := run("ip", "-4", "-o", "addr", "show", "dev", ifname)
	return err == nil && strings.Contains(out, "inet ")
}
