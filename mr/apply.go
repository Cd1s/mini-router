package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	ConfigPath  = "/etc/mini-router/router.yaml"
	SecretsPath = "/etc/mini-router/secrets.yaml"
	GenDir      = "/etc/mini-router/gen"
)

// variables so tests can point them elsewhere
var (
	HistoryDir = "/etc/mini-router/history"
	// ConfirmFile marks a change that is not accepted yet: an apply in progress or waiting for `mr confirm`.
	// It is on persistent storage, so a power cut, watchdog reset or crash cannot turn the change into the
	// accepted config: the next boot restores the snapshot it names before any service starts.
	ConfirmFile = "/etc/mini-router/confirm-pending"
	ChangeLog   = "/etc/router-changes.log"
	clockRef    = "/etc/mini-router/state/clock" // mr-clock / clock-save: mtime = last known time
	initDir     = "/etc/init.d"
	runlevelDir = "/etc/runlevels/default"
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
	files = append(files, appliedFiles(c)...)
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
	if ents, err := os.ReadDir(runlevelDir); err == nil {
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
	if ents, err := os.ReadDir(initDir); err == nil {
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
	record := false
	for _, f := range p.Changed {
		if bookkeeping(f.Path) {
			record = true
			continue
		}
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
	if b.Len() == 0 && record {
		b.WriteString("  (no generated file changes: only the record of the applied config)\n")
	}
	return b.String()
}

// printPlan shows what c changes in config terms (since the last apply), the plan's actions and its
// risk; verbose adds what each action does and each generated file's diff (secret values masked).
func printPlan(c *Config, p *Plan, verbose bool) {
	if changes, ok := changesSinceApplied(c); !ok {
		fmt.Print("changes: (no record of the applied config yet — this apply writes it)\n")
	} else if len(changes) > 0 {
		fmt.Print("changes:\n  " + strings.Join(changes, "\n  ") + "\n")
	}
	fmt.Print("plan:\n" + p.String())
	printRisk(planRisk(c, p, sshClientAddr()), verbose)
	if verbose {
		for _, f := range p.Changed {
			if bookkeeping(f.Path) {
				continue
			}
			cur, _ := os.ReadFile(f.Path)
			fmt.Print(fileDiff(f.Path, string(cur), f.Data, c.secrets))
		}
		if p.Firewall {
			cur, _ := os.ReadFile(GenDir + "/nftables.nft")
			fmt.Print(fileDiff(GenDir+"/nftables.nft", string(cur), renderNft(c, netdevExists), c.secrets))
		}
	}
}

// snapshot saves every file the plan will touch (plus router.yaml) so a failed apply can be undone.
// It is on disk (fsync) before the pending marker: a power cut after the marker must find it whole.
func snapshot(paths []string, keep int) (string, error) {
	// a second snapshot in the same second gets a letter (sorting after the first), never its name
	base := filepath.Join(HistoryDir, time.Now().Format("20060102-150405"))
	name := base + ".tar.gz"
	for c := 'b'; ; c++ {
		if _, err := os.Stat(name); err != nil || c > 'z' {
			break
		}
		name = base + string(c) + ".tar.gz"
	}
	if err := writeSnapshot(name, paths); err != nil {
		return "", err
	}
	pruneHistory(keep, filepath.Base(name))
	return name, nil
}

// pruneHistory keeps the newest keep snapshots (and their revision records), always counting and
// keeping the one just written (keepName): after the clock went back it sorts first.
func pruneHistory(keep int, keepName string) {
	ents, _ := os.ReadDir(HistoryDir)
	var names []string
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".tar.gz") && e.Name() != keepName {
			names = append(names, e.Name())
		}
	}
	if keepName != "" {
		keep--
	}
	sort.Strings(names)
	for len(names) > keep && len(names) > 0 {
		os.Remove(filepath.Join(HistoryDir, names[0]))
		os.Remove(filepath.Join(HistoryDir, revFile(names[0])))
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
		if p == sysSecretsPath {
			data = keepPassword(data)
		}
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

// keepPassword: secrets.yaml data with the web UI password as it is now. A password set while a change
// was pending (web UI, `mr passwd` on the console) must survive that change's rollback.
func keepPassword(data []byte) []byte {
	cur, ok := readSecretsFile(sysSecretsPath)[pwSecretKey]
	old := map[string]string{}
	if !ok || yaml.Unmarshal(data, &old) != nil || old[pwSecretKey] == cur {
		return data
	}
	old[pwSecretKey] = cur
	b, err := yaml.Marshal(old)
	if err != nil {
		return data
	}
	return b
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	// a temp file of its own (two writers of one path must not share one) whose data is on flash
	// before the rename (UBIFS: a rename can reach the disk before unsynced data — an empty file)
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.mr-tmp")
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Chmod(mode)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(f.Name(), path)
	}
	if err != nil {
		os.Remove(f.Name())
	}
	return err
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
		if _, err := os.Stat(filepath.Join(initDir, s)); err != nil {
			continue
		}
		if out, err := run("rc-service", s, "restart"); err != nil {
			failed = append(failed, fmt.Sprintf("%s: %v %s", s, err, strings.TrimSpace(out)))
		}
	}
	return failed
}

// Apply: validate → plan → snapshot → write → enable/disable → restart → firewall → verify; undo on failure.
func Apply(c *Config, dryRun bool, confirmSecs int, comment string, verbose bool) error {
	return applyWith(c, dryRun, confirmSecs, nil, applyOpts{Via: "mr apply", Comment: comment}, verbose)
}

// ApplyCandidate applies a config written by the web UI. The live router.yaml/secrets.yaml are
// snapshotted first and replaced only after the snapshot exists, so a failed or unconfirmed apply
// restores the previous config files too. o records the origin (pending marker, revision).
func ApplyCandidate(candYAML, candSecrets string, confirmSecs int, o applyOpts) error {
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
	return applyWith(c, false, confirmSecs, install, o, false)
}

func applyWith(c *Config, dryRun bool, confirmSecs int, install func() error, o applyOpts, verbose bool) error {
	if !dryRun {
		if err := pendingBlocks(); err != nil {
			return err
		}
	}
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
	changes, _ := changesSinceApplied(c)
	printPlan(c, p, verbose)
	if dryRun {
		return nil
	}
	var paths []string
	for _, f := range p.Changed {
		paths = append(paths, f.Path)
	}
	paths = append(paths, ConfigPath, SecretsPath, GenDir+"/nftables.nft")
	defer shieldSignals()()
	snap, err := snapshot(paths, historyKeep(c))
	if err != nil {
		return fmt.Errorf("snapshot: %w", err)
	}
	// on disk before the first new file: if the router goes down from here until the change is
	// accepted, the next boot rolls it back. Claimed atomically: of two applies started at once, one
	// is refused here.
	if err := claimPending(pendingApply{Snapshot: snap, State: stateApplying, Via: o.Via, Pid: os.Getpid()}); err != nil {
		os.Remove(snap)
		return err
	}
	if o.BaseRev != "" && configRev() != o.BaseRev {
		// router.yaml changed between the request and now (mr set, an editor, another client):
		// installing the candidate would silently undo that change. Nothing is written yet.
		clearPending(snap)
		os.Remove(snap)
		return errStaleCandidate
	}
	newRevision(snap, o, changes)
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
		armConfirm(snap, confirmSecs, o.Via)
		setResult(snap, "pending")
		fmt.Printf("run `mr confirm` within %ds or this change is rolled back\n", confirmSecs)
	} else {
		clearPending(snap)
		setResult(snap, "applied")
	}
	return nil
}

// rollback restores snap after a failed or unconfirmed apply. The pending marker goes only when the
// old files are back, so a crash in the middle of it rolls back again at boot.
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
	clearPending(snap)
	setResult(snap, "rolled back: "+firstLine(cause.Error()))
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
	if ents, err := os.ReadDir(runlevelDir); err == nil {
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
		if _, err := os.Stat(filepath.Join(initDir, s)); err != nil {
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

func appendChangeLog(line string) { appendChangeLogAt(time.Now(), line) }

func appendChangeLogAt(t time.Time, line string) {
	f, err := os.OpenFile(ChangeLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s %s\n", t.Format("2006-01-02 15:04:05"), line)
}

// ---- confirm / auto-rollback ----

// pendingApply is the content of ConfirmFile.
type pendingApply struct {
	Snapshot string `json:"snapshot"`           // history snapshot taken before the change
	State    string `json:"state"`              // stateApplying | statePending | stateReverting
	Deadline int64  `json:"deadline,omitempty"` // unix time the confirm timer rolls back at (statePending)
	Via      string `json:"via"`                // origin: mr apply | web UI | restore
	Pid      int    `json:"pid,omitempty"`      // the applying process (stateApplying)
}

// interrupted: an apply whose process is gone (killed, out of memory). Nothing finishes or undoes it
// but `mr rollback` (or a reboot).
func (p *pendingApply) interrupted() bool {
	return p.State == stateApplying && p.Pid > 0 && syscall.Kill(p.Pid, 0) == syscall.ESRCH
}

// shieldSignals keeps a dropped SSH session (SIGHUP, SIGPIPE on the next write to it) or Ctrl-C from
// killing an apply halfway — before its confirm timer runs, with the marker stuck at "applying".
// The returned func restores the defaults.
func shieldSignals() func() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGPIPE)
	return func() { signal.Stop(ch) }
}

const (
	stateApplying  = "applying"  // the apply is still running
	statePending   = "pending"   // applied, waiting for `mr confirm`
	stateReverting = "reverting" // being rolled back
)

func readPending() (*pendingApply, error) {
	b, err := os.ReadFile(ConfirmFile)
	if err != nil {
		return nil, err
	}
	var p pendingApply
	if err := json.Unmarshal(b, &p); err != nil || p.Snapshot == "" {
		return nil, fmt.Errorf("%s: unreadable marker", ConfirmFile)
	}
	return &p, nil
}

// pendingBlocks refuses a new change while another one is not accepted yet: applied on top, a later
// rollback of the second would silently keep the first.
func pendingBlocks() error {
	p, err := readPending()
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%v: `mr confirm` clears it", err)
	}
	switch p.State {
	case stateApplying:
		if p.interrupted() {
			return fmt.Errorf("an apply (%s) was interrupted: `mr rollback` puts the config from before it back", p.Via)
		}
		return fmt.Errorf("another apply (%s) is running", p.Via)
	case stateReverting:
		return fmt.Errorf("a change (%s) is being rolled back", p.Via)
	}
	return fmt.Errorf("a change (%s) is waiting for confirmation (rolled back in %ds): keep it (`mr confirm`) or roll it back (`mr rollback`) first",
		p.Via, p.left())
}

// left: seconds until the confirm timer rolls the change back.
func (p *pendingApply) left() int64 {
	if l := p.Deadline - time.Now().Unix(); l > 0 {
		return l
	}
	return 0
}

// claimPending creates the marker only if there is none: checking and claiming are one step.
var errStaleCandidate = errors.New("router.yaml changed since this change was built from it: read the config again and redo the change")

func claimPending(p pendingApply) error {
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(ConfirmFile), 0755); err != nil {
		return err
	}
	f, err := os.OpenFile(ConfirmFile, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if errors.Is(err, fs.ErrExist) {
		if err := pendingBlocks(); err != nil {
			return err
		}
		return errors.New("another change is pending")
	}
	if err != nil {
		return fmt.Errorf("pending marker: %w", err)
	}
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(ConfirmFile)
		return fmt.Errorf("pending marker: %w", err)
	}
	syncDir(filepath.Dir(ConfirmFile))
	return nil
}

func setPending(p pendingApply) error {
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return writeDurable(ConfirmFile, b, 0600)
}

// clearPending removes the marker when it names snap ("" = any). Everything written before is synced
// first: the marker must never reach the disk as gone while the change's files are still in flight.
func clearPending(snap string) {
	if snap != "" {
		if p, err := readPending(); err != nil || p.Snapshot != snap {
			return
		}
	}
	syscall.Sync()
	if os.Remove(ConfirmFile) == nil {
		syncDir(filepath.Dir(ConfirmFile))
	}
}

// writeDurable is writeAtomic that returns only when the data and the rename are on disk.
func writeDurable(path string, data []byte, mode os.FileMode) error {
	if err := writeAtomic(path, data, mode); err != nil {
		return err
	}
	syncDir(filepath.Dir(path))
	return nil
}

func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
}

// lockPending serializes the processes that settle a pending change (confirm, the timer, a revert,
// mr rollback): of a confirm and a rollback racing at the deadline exactly one wins.
func lockPending() func() {
	f, err := os.OpenFile(ConfirmFile+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return func() {}
	}
	syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
	return func() { f.Close() }
}

// startRevert marks the pending change of snapshot snap ("" = whichever) as being rolled back, if it
// is still waiting for confirmation; false: confirmed, being reverted, or another change.
func startRevert(snap string) (*pendingApply, bool) {
	defer lockPending()()
	p, err := readPending()
	if err != nil || snap != "" && p.Snapshot != snap || p.State != statePending {
		return nil, false
	}
	p.State = stateReverting // the timer and `mr confirm` leave it alone now
	if setPending(*p) != nil {
		return nil, false
	}
	return p, true
}

func armConfirm(snap string, secs int, via string) {
	setPending(pendingApply{Snapshot: snap, State: statePending, Deadline: time.Now().Unix() + int64(secs), Via: via})
	self, _ := os.Executable()
	startDetached(self, "rollback-if-unconfirmed", snap, fmt.Sprint(secs))
}

func rollbackIfUnconfirmed(snap string, secs int) error {
	time.Sleep(time.Duration(secs) * time.Second)
	if _, ok := startRevert(snap); !ok {
		return nil // confirmed, being reverted, or superseded by a newer apply
	}
	return rollback(snap, fmt.Errorf("not confirmed within %ds", secs))
}

// confirm keeps the pending change; false: there was none.
func confirm() (bool, error) {
	unlock := lockPending()
	defer unlock()
	p, err := readPending()
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err == nil && p.State == stateApplying {
		return false, errors.New("the apply is still running: confirm it when it has finished")
	}
	if err == nil && p.State == stateReverting {
		return false, errors.New("the change is being rolled back")
	}
	clearPending("") // an unreadable marker too: `mr confirm` is the way out
	unlock()
	if err == nil {
		setResult(p.Snapshot, "confirmed")
	}
	return true, nil
}

// rollbackCommand is `mr rollback [--boot] [SNAPSHOT]`.
func rollbackCommand(args []string, cfgPath, secPath string) error {
	fl := flag.NewFlagSet("rollback", flag.ContinueOnError)
	boot := fl.Bool("boot", false, "at boot, before any service starts: roll back a change that was never accepted")
	secs := fl.Int("confirm", 120, "rollback N: seconds to wait for `mr confirm` (0: keep at once)")
	if err := fl.Parse(args); err != nil {
		return err
	}
	if *boot {
		return rollbackAtBoot(cfgPath, secPath)
	}
	if fl.NArg() > 0 {
		if n, err := strconv.Atoi(strings.TrimPrefix(fl.Arg(0), "#")); err == nil {
			return rollbackToRev(n, *secs) // the config from before change N, as a new change
		}
	}
	unlock := lockPending()
	defer unlock()
	p, err := readPending()
	if err == nil && p.State == stateApplying && !p.interrupted() {
		return fmt.Errorf("an apply (%s) is running: roll back when it has finished", p.Via)
	}
	var snap string
	switch {
	case fl.NArg() > 0:
		snap = filepath.Join(HistoryDir, filepath.Base(fl.Arg(0)))
	case err == nil:
		snap = filepath.Join(HistoryDir, filepath.Base(p.Snapshot)) // undo the pending change
	default:
		ents, _ := os.ReadDir(HistoryDir)
		if len(ents) == 0 {
			return fmt.Errorf("no snapshots")
		}
		snap = filepath.Join(HistoryDir, ents[len(ents)-1].Name())
	}
	// pending, an interrupted apply, or marked reverting by the web UI's revert that started this rollback
	reverting := err == nil
	orig := statePending
	if reverting && p.State == stateApplying {
		orig = stateApplying
	}
	if reverting && p.State != stateReverting {
		p.State = stateReverting // the confirm timer leaves it alone now
		setPending(*p)
	}
	unlock()
	svcs, err := restore(snap)
	if err != nil {
		if reverting { // still pending: the timer, `mr confirm` or another rollback decide
			p.State = orig
			setPending(*p)
		}
		return err
	}
	restartAll(svcs)
	if c, err := loadConfig(cfgPath, secPath); err == nil {
		reconcileRunlevel(c)
		refreshRoutes(c)
		fwLoad(c)
	}
	clearPending("") // an explicit rollback settles a pending change
	if reverting {
		setResult(p.Snapshot, "rolled back: reverted")
	}
	appendChangeLog("mr rollback: " + filepath.Base(snap))
	fmt.Println("restored", filepath.Base(snap))
	return nil
}

// rollbackAtBoot runs before OpenRC (mr-preinit on the image, the mr-unconfirmed boot service
// elsewhere). A marker left over means the router went down in the middle of an apply or inside its
// confirm window: the snapshot's files and the default runlevel's links go back, and the services
// start from them. Nothing is restarted — nothing runs yet.
func rollbackAtBoot(cfgPath, secPath string) error {
	p, err := readPending()
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	at := bootClock()
	if err != nil {
		os.Rename(ConfirmFile, ConfirmFile+".bad")
		appendChangeLogAt(at, "boot: unreadable pending marker set aside ("+filepath.Base(ConfirmFile)+".bad), config kept")
		return err
	}
	snap := filepath.Join(HistoryDir, filepath.Base(p.Snapshot))
	what := "unconfirmed change"
	if p.State == stateApplying {
		what = "interrupted apply"
	}
	if _, err := restore(snap); err != nil {
		os.Rename(ConfirmFile, ConfirmFile+".failed") // do not retry at every boot
		appendChangeLogAt(at, fmt.Sprintf("boot: rolling back the %s (%s) to %s FAILED: %v", what, p.Via, filepath.Base(snap), err))
		return fmt.Errorf("rolling back the %s to %s: %w", what, filepath.Base(snap), err)
	}
	if c, err := loadConfig(cfgPath, secPath); err == nil {
		linkRunlevel(c)
	}
	clearPending("")
	setResult(snap, "rolled back at boot: the router restarted before it was confirmed")
	appendChangeLogAt(at, fmt.Sprintf("boot: %s (%s) rolled back to %s — the router restarted before it was confirmed", what, p.Via, filepath.Base(snap)))
	fmt.Printf("%s (%s) rolled back to %s\n", what, p.Via, filepath.Base(snap))
	return nil
}

// bootClock: the board has no RTC and mr-clock has not run yet — the latest of the clock, the marker
// (written by the apply) and mr-clock's reference file is the best guess for the change log.
func bootClock() time.Time {
	t := time.Now()
	for _, f := range []string{ConfirmFile, clockRef} {
		if st, err := os.Stat(f); err == nil && st.ModTime().After(t) {
			t = st.ModTime()
		}
	}
	return t
}

// linkRunlevel is reconcileRunlevel before OpenRC runs: only the default runlevel's links change.
func linkRunlevel(c *Config) {
	want := map[string]bool{}
	for _, s := range enabledServices(c) {
		want[s] = true
	}
	for _, s := range managedServices(c) {
		if !want[s] {
			os.Remove(filepath.Join(runlevelDir, s))
		}
	}
	// links to init scripts the restore removed (per-WAN instances)
	ents, _ := os.ReadDir(runlevelDir)
	for _, e := range ents {
		l := filepath.Join(runlevelDir, e.Name())
		if e.Type()&fs.ModeSymlink != 0 {
			if _, err := os.Stat(l); errors.Is(err, fs.ErrNotExist) {
				os.Remove(l)
			}
		}
	}
	for s := range want {
		if _, err := os.Stat(filepath.Join(initDir, s)); err == nil {
			os.Symlink(filepath.Join(initDir, s), filepath.Join(runlevelDir, s)) // already there: EEXIST
		}
	}
}

// ---- verification ----

// ensureStarted starts every service the config wants that is not running (OpenRC stops the
// dependents of a service it stops, and does not bring them back).
func ensureStarted(c *Config) {
	for _, s := range enabledServices(c) {
		if _, err := os.Stat(filepath.Join(initDir, s)); err != nil {
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
		if _, err := os.Stat(filepath.Join(initDir, s)); err != nil {
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
