package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	snap, err := snapshot([]string{gen, created, cfg})
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
	snap, _ := snapshot([]string{f})
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
	if err := confirm(); err != nil {
		t.Fatalf("nothing pending: %v", err)
	}
	for _, st := range []string{stateApplying, stateReverting} {
		setPending(pendingApply{Snapshot: "/x.tar.gz", State: st})
		if err := confirm(); err == nil {
			t.Errorf("confirm accepted while %s", st)
		}
		if _, err := os.Stat(ConfirmFile); err != nil {
			t.Errorf("marker removed while %s", st)
		}
	}
	setPending(pendingApply{Snapshot: "/x.tar.gz", State: statePending, Deadline: 1})
	if err := confirm(); err != nil {
		t.Fatal(err)
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
