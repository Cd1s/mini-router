package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// confirmEnv points the history, the pending marker, the change log and OpenRC's directories into a
// temp dir, and writes the home config there as the live router.yaml.
func confirmEnv(t *testing.T) (d, cfg, sec string) {
	t.Helper()
	d = t.TempDir()
	oldH, oldC, oldL, oldK, oldI, oldR := HistoryDir, ConfirmFile, ChangeLog, clockRef, initDir, runlevelDir
	t.Cleanup(func() {
		HistoryDir, ConfirmFile, ChangeLog, clockRef, initDir, runlevelDir = oldH, oldC, oldL, oldK, oldI, oldR
	})
	HistoryDir, ConfirmFile, ChangeLog = filepath.Join(d, "history"), filepath.Join(d, "etc", "confirm-pending"), filepath.Join(d, "changes.log")
	clockRef, initDir, runlevelDir = filepath.Join(d, "clock"), filepath.Join(d, "init.d"), filepath.Join(d, "runlevels", "default")
	os.MkdirAll(initDir, 0755)
	os.MkdirAll(runlevelDir, 0755)
	cfg, sec = filepath.Join(d, "router.yaml"), filepath.Join(d, "secrets.yaml")
	for src, dst := range map[string]string{"../examples/router.yaml": cfg, "testdata/secrets.yaml": sec} {
		b, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		os.WriteFile(dst, b, 0600)
	}
	return d, cfg, sec
}

func mustRead(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The router went down inside the confirm window: the next boot puts the snapshot's files back
// (removing the ones the change created), makes the default runlevel match the restored config and
// drops the marker — an unconfirmed change never survives a reboot (Cd1s/mini-router#9).
func TestBootRollsBackUnconfirmedChange(t *testing.T) {
	d, cfg, sec := confirmEnv(t)
	c, err := loadConfig(cfg, sec)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{}
	for _, s := range enabledServices(c) {
		want[s] = true
		os.WriteFile(filepath.Join(initDir, s), []byte("#!/sbin/openrc-run\n"), 0755)
		os.Symlink(filepath.Join(initDir, s), filepath.Join(runlevelDir, s))
	}
	var extra string // a managed service the home config does not run
	for _, s := range []string{"mr-hostapd", "mr-proxy", "igmpproxy", "mr-wanmon", "mr-mon", "mr-zram", "crond"} {
		if !want[s] {
			extra = s
			break
		}
	}
	if extra == "" {
		t.Fatal("no managed service outside the home config")
	}
	gen, created := filepath.Join(d, "gen", "x.conf"), filepath.Join(d, "gen", "new.conf")
	os.MkdirAll(filepath.Dir(gen), 0755)
	os.WriteFile(gen, []byte("old\n"), 0644)
	oldCfg := mustRead(t, cfg)
	snap, err := snapshot([]string{gen, created, cfg}, 20)
	if err != nil {
		t.Fatal(err)
	}
	if err := setPending(pendingApply{Snapshot: snap, State: statePending, Deadline: 1, Via: "web UI"}); err != nil {
		t.Fatal(err)
	}
	// the unconfirmed change: new file contents, a new file, a service switched on, one switched off,
	// a per-WAN instance whose init script only the change had
	os.WriteFile(gen, []byte("new\n"), 0644)
	os.WriteFile(created, []byte("new\n"), 0644)
	os.WriteFile(cfg, []byte(strings.Replace(oldCfg, "192.168.1.6/24", "192.168.77.1/24", 1)), 0644)
	os.WriteFile(filepath.Join(initDir, extra), []byte("#!/sbin/openrc-run\n"), 0755)
	os.Symlink(filepath.Join(initDir, extra), filepath.Join(runlevelDir, extra))
	os.Remove(filepath.Join(runlevelDir, "mr-network"))
	os.Symlink(filepath.Join(initDir, "mr-pppoe.wan9"), filepath.Join(runlevelDir, "mr-pppoe.wan9"))

	if err := rollbackAtBoot(cfg, sec); err != nil {
		t.Fatal(err)
	}
	if mustRead(t, gen) != "old\n" || mustRead(t, cfg) != oldCfg {
		t.Error("files not restored")
	}
	if _, err := os.Stat(created); !errors.Is(err, fs.ErrNotExist) {
		t.Error("file created by the change survived")
	}
	if _, err := os.Stat(ConfirmFile); !errors.Is(err, fs.ErrNotExist) {
		t.Error("marker left behind")
	}
	for s := range want {
		if _, err := os.Lstat(filepath.Join(runlevelDir, s)); err != nil {
			t.Errorf("wanted service %s not in the runlevel", s)
		}
	}
	for _, s := range []string{extra, "mr-pppoe.wan9"} {
		if _, err := os.Lstat(filepath.Join(runlevelDir, s)); err == nil {
			t.Errorf("%s still in the runlevel", s)
		}
	}
	log := mustRead(t, ChangeLog)
	if !strings.Contains(log, "boot: unconfirmed change (web UI) rolled back to "+filepath.Base(snap)) {
		t.Errorf("change log: %q", log)
	}
	// nothing pending: the next boot changes nothing
	os.WriteFile(gen, []byte("kept\n"), 0644)
	if err := rollbackAtBoot(cfg, sec); err != nil || mustRead(t, gen) != "kept\n" {
		t.Errorf("boot without a marker changed something: %v", err)
	}
}

// Power lost in the middle of an apply (the marker is written before the first new file): rolled
// back at boot as well.
func TestBootRollsBackInterruptedApply(t *testing.T) {
	d, cfg, sec := confirmEnv(t)
	f := filepath.Join(d, "gen.conf")
	os.WriteFile(f, []byte("old\n"), 0644)
	snap, _ := snapshot([]string{f}, 20)
	setPending(pendingApply{Snapshot: snap, State: stateApplying, Via: "mr apply"})
	os.WriteFile(f, []byte("half\n"), 0644)
	if err := rollbackAtBoot(cfg, sec); err != nil {
		t.Fatal(err)
	}
	if mustRead(t, f) != "old\n" || !strings.Contains(mustRead(t, ChangeLog), "interrupted apply (mr apply) rolled back") {
		t.Error("interrupted apply not rolled back")
	}
}

func TestBootRollbackBadMarker(t *testing.T) {
	d, cfg, sec := confirmEnv(t)
	f := filepath.Join(d, "gen.conf")
	os.WriteFile(f, []byte("new\n"), 0644)
	os.MkdirAll(filepath.Dir(ConfirmFile), 0755)
	os.WriteFile(ConfirmFile, []byte("{garbage"), 0600)
	if err := rollbackAtBoot(cfg, sec); err == nil {
		t.Error("unreadable marker accepted")
	}
	if _, err := os.Stat(ConfirmFile + ".bad"); err != nil || mustRead(t, f) != "new\n" {
		t.Error("unreadable marker: want it set aside and the files left alone")
	}
	// a snapshot that is gone: reported once, not retried at every boot
	setPending(pendingApply{Snapshot: filepath.Join(HistoryDir, "missing.tar.gz"), State: statePending})
	if err := rollbackAtBoot(cfg, sec); err == nil {
		t.Error("missing snapshot accepted")
	}
	if _, err := os.Stat(ConfirmFile); err == nil {
		t.Error("failed rollback leaves the marker for the next boot")
	}
	if !strings.Contains(mustRead(t, ChangeLog), "FAILED") {
		t.Error("failed rollback not in the change log")
	}
}

func TestConfirmStates(t *testing.T) {
	confirmEnv(t)
	if ok, err := confirm(); ok || err != nil {
		t.Fatalf("nothing pending: %v %v", ok, err)
	}
	for _, st := range []string{stateApplying, stateReverting} {
		setPending(pendingApply{Snapshot: "/x.tar.gz", State: st})
		if _, err := confirm(); err == nil {
			t.Errorf("confirm accepted while %s", st)
		}
		if _, err := os.Stat(ConfirmFile); err != nil {
			t.Errorf("marker removed while %s", st)
		}
	}
	setPending(pendingApply{Snapshot: "/x.tar.gz", State: statePending, Deadline: 1})
	if ok, err := confirm(); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if _, err := os.Stat(ConfirmFile); !errors.Is(err, fs.ErrNotExist) {
		t.Error("confirm kept the marker")
	}
}

// The confirm timer only acts on the change it was started for, and only while it is pending.
func TestTimerLeavesOtherChangesAlone(t *testing.T) {
	confirmEnv(t)
	for _, p := range []pendingApply{
		{Snapshot: "/h/newer.tar.gz", State: statePending},
		{Snapshot: "/h/mine.tar.gz", State: stateReverting},
		{Snapshot: "/h/mine.tar.gz", State: stateApplying},
	} {
		setPending(p)
		if err := rollbackIfUnconfirmed("/h/mine.tar.gz", 0); err != nil {
			t.Fatal(err)
		}
		if got, err := readPending(); err != nil || *got != p {
			t.Errorf("marker changed: %+v -> %+v (%v)", p, got, err)
		}
	}
	clearPending("/h/other.tar.gz")
	if _, err := readPending(); err != nil {
		t.Error("clearPending removed another change's marker")
	}
	clearPending("/h/mine.tar.gz")
	if _, err := readPending(); !errors.Is(err, fs.ErrNotExist) {
		t.Error("clearPending kept the marker")
	}
}

// While a change waits for confirmation (or is still applying / being rolled back), every other way
// to change the config is refused — applied on top, the first change would be kept by a rollback of
// the second without anyone confirming it (Cd1s/mini-router#10). Keeping or rolling it back lifts it.
func TestApplyRefusedWhilePending(t *testing.T) {
	confirmEnv(t)
	c := testConfig(t)
	if err := pendingBlocks(); err != nil {
		t.Fatalf("nothing pending: %v", err)
	}
	for _, p := range []pendingApply{
		{Snapshot: "/h/a.tar.gz", State: statePending, Deadline: time.Now().Unix() + 90, Via: "web UI"},
		{Snapshot: "/h/a.tar.gz", State: stateApplying, Via: "mr apply"},
		{Snapshot: "/h/a.tar.gz", State: stateReverting, Via: "restore"},
	} {
		setPending(p)
		err := applyWith(c, false, 120, nil, applyOpts{Via: "mr apply"}, false)
		if err == nil || !strings.Contains(err.Error(), p.Via) {
			t.Errorf("%s: second apply not refused: %v", p.State, err)
		}
		if p.State == statePending && !strings.Contains(err.Error(), "waiting for confirmation (rolled back in 9") {
			t.Errorf("message: %v", err)
		}
		r := apiApply(apiReq{method: "POST", body: []byte(`{"config":{}}`)})
		if r.status != 409 || r.body.(map[string]any)["pending"].(map[string]any)["state"] != p.State {
			t.Errorf("%s: web UI apply: %d %v", p.State, r.status, r.body)
		}
		if _, _, err := startRestore(&restoreSet{}, 120); err == nil {
			t.Errorf("%s: restore not refused", p.State)
		}
		if got, _ := readPending(); got == nil || *got != p {
			t.Errorf("%s: the refused apply touched the marker: %+v", p.State, got)
		}
		if ents, _ := os.ReadDir(HistoryDir); len(ents) != 0 {
			t.Errorf("%s: the refused apply took a snapshot", p.State)
		}
	}
	// a dry run (mr apply --dry-run) still shows the plan
	if err := applyWith(c, true, 0, nil, applyOpts{Via: "mr apply"}, false); err != nil {
		t.Errorf("dry run refused: %v", err)
	}
	setPending(pendingApply{Snapshot: "/h/a.tar.gz", State: statePending, Deadline: 1})
	if _, err := confirm(); err != nil || pendingBlocks() != nil {
		t.Errorf("confirmed, still blocked: %v %v", err, pendingBlocks())
	}
	os.WriteFile(ConfirmFile, []byte("{garbage"), 0600)
	if err := pendingBlocks(); err == nil || !strings.Contains(err.Error(), "mr confirm") {
		t.Errorf("unreadable marker: %v", err)
	}
	if v := pendingView(); v["state"] != "unknown" {
		t.Errorf("view of an unreadable marker: %v", v)
	}
}

// Two applies started at the same moment: exactly one claims the marker.
func TestClaimPendingIsExclusive(t *testing.T) {
	confirmEnv(t)
	var wg sync.WaitGroup
	var mu sync.Mutex
	won := 0
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if claimPending(pendingApply{Snapshot: "/h/a.tar.gz", State: stateApplying, Via: "mr apply"}) == nil {
				mu.Lock()
				won++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if won != 1 {
		t.Fatalf("%d applies claimed the marker", won)
	}
	if v := pendingView(); v["state"] != stateApplying || v["via"] != "mr apply" {
		t.Errorf("view: %v", v)
	}
	clearPending("")
	if pendingView() != nil || claimPending(pendingApply{Snapshot: "/h/b.tar.gz", State: stateApplying}) != nil {
		t.Error("marker not free after the change was settled")
	}
}

// A rollback of the pending change that cannot restore leaves it pending (not stuck in reverting,
// which would refuse every later apply and `mr confirm`).
func TestFailedRollbackKeepsChangePending(t *testing.T) {
	_, cfg, sec := confirmEnv(t)
	for _, st := range []string{statePending, stateReverting} {
		setPending(pendingApply{Snapshot: filepath.Join(HistoryDir, "gone.tar.gz"), State: st, Deadline: 1, Via: "web UI"})
		if err := rollbackCommand(nil, cfg, sec); err == nil {
			t.Fatalf("%s: rollback of a missing snapshot succeeded", st)
		}
		if p, err := readPending(); err != nil || p.State != statePending {
			t.Errorf("%s: after the failed rollback: %+v %v", st, p, err)
		}
	}
	setPending(pendingApply{Snapshot: "/h/a.tar.gz", State: stateApplying})
	if err := rollbackCommand(nil, cfg, sec); err == nil || !strings.Contains(err.Error(), "is running") {
		t.Errorf("rollback during an apply: %v", err)
	}
}

// base_rev is checked again when the apply job installs (Cd1s/mini-router#68): a router.yaml changed
// between the request and the install refuses the apply, leaves no marker and no snapshot, and writes
// nothing.
func TestApplyStaleCandidate(t *testing.T) {
	_, cfg, _ := confirmEnv(t)
	old := liveConfig
	liveConfig = cfg
	t.Cleanup(func() { liveConfig = old })
	c := testConfig(t)
	rev := configRev()
	os.WriteFile(cfg, append([]byte("# edited meanwhile\n"), mustRead(t, cfg)...), 0600)
	err := applyWith(c, false, 120, func() error { t.Error("installed a stale candidate"); return nil },
		applyOpts{Via: "web UI", BaseRev: rev}, false)
	if !errors.Is(err, errStaleCandidate) {
		t.Fatalf("stale candidate: %v", err)
	}
	if _, err := readPending(); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("marker left behind: %v", err)
	}
	if ents, _ := os.ReadDir(HistoryDir); len(ents) != 0 {
		t.Errorf("snapshot left behind: %d files", len(ents))
	}
}

// Writers of one path at the same time (hooks, the web UI, cron) must not share a temp file: with a
// fixed name one rename took the other's half-written file away and the other failed.
func TestWriteAtomicConcurrent(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.json")
	var wg sync.WaitGroup
	errs := make(chan error, 400)
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				if err := writeAtomic(p, []byte(strings.Repeat(string(rune('a'+g)), 4096)), 0600); err != nil {
					errs <- err
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	if len(b) != 4096 || strings.Trim(string(b), string(b[:1])) != "" {
		t.Errorf("mixed content (%d bytes)", len(b))
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0600 {
		t.Errorf("mode %v", fi.Mode())
	}
	if m, _ := filepath.Glob(p + ".*"); len(m) != 0 {
		t.Errorf("temp files left: %v", m)
	}
}
