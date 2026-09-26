package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// A dropped SSH session (SIGHUP) or Ctrl-C during an apply must not kill it halfway: the marker would
// stay "applying", no confirm timer would run. Without the shield this test binary dies.
func TestApplyShieldsSignals(t *testing.T) {
	stop := shieldSignals()
	for _, s := range []syscall.Signal{syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGPIPE} {
		syscall.Kill(os.Getpid(), s)
	}
	time.Sleep(100 * time.Millisecond)
	stop()
}

// An apply whose process died (killed, OOM) left the marker at "applying": every apply, confirm and
// rollback was refused until a reboot. `mr rollback` now undoes it; a live apply is still left alone.
func TestRollbackInterruptedApply(t *testing.T) {
	d, _, _ := confirmEnv(t)
	f := filepath.Join(d, "gen.conf")
	os.WriteFile(f, []byte("old\n"), 0644)
	snap, err := snapshot([]string{f}, 20)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(f, []byte("half-applied\n"), 0644)
	dead := exec.Command("true")
	dead.Run()
	setPending(pendingApply{Snapshot: snap, State: stateApplying, Via: "mr apply", Pid: os.Getpid()})
	if err := rollbackCommand(nil, "/nonexistent", "/nonexistent"); err == nil || !strings.Contains(err.Error(), "is running") {
		t.Fatalf("rollback of a running apply: %v", err)
	}
	setPending(pendingApply{Snapshot: snap, State: stateApplying, Via: "mr apply", Pid: dead.Process.Pid})
	if err := pendingBlocks(); err == nil || !strings.Contains(err.Error(), "interrupted") {
		t.Errorf("blocks: %v", err)
	}
	if err := rollbackCommand(nil, "/nonexistent", "/nonexistent"); err != nil {
		t.Fatal(err)
	}
	if mustRead(t, f) != "old\n" {
		t.Error("the interrupted apply's files were not put back")
	}
	if _, err := readPending(); err == nil {
		t.Error("marker left behind")
	}
}

// A confirm and a rollback (timer, revert) racing at the deadline: exactly one of them wins — never
// "confirmed" reported while the change is rolled back.
func TestConfirmRevertRace(t *testing.T) {
	confirmEnv(t)
	for i := 0; i < 30; i++ {
		setPending(pendingApply{Snapshot: "/h/a.tar.gz", State: statePending, Deadline: 1})
		var wg sync.WaitGroup
		var confirmed, reverted bool
		wg.Add(2)
		go func() { defer wg.Done(); confirmed, _ = confirm() }()
		go func() { defer wg.Done(); _, reverted = startRevert("/h/a.tar.gz") }()
		wg.Wait()
		if confirmed == reverted {
			t.Fatalf("round %d: confirmed %v, reverted %v", i, confirmed, reverted)
		}
		clearPending("")
	}
}

// A rollback puts the old secrets back but keeps the web UI password as it is now (changed in the
// web UI or with `mr passwd` while the change was pending).
func TestRestoreKeepsPassword(t *testing.T) {
	d, _, _ := confirmEnv(t)
	old := sysSecretsPath
	t.Cleanup(func() { sysSecretsPath = old })
	sysSecretsPath = filepath.Join(d, "secrets.yaml")
	os.WriteFile(sysSecretsPath, []byte(pwSecretKey+": OLD\nwifi_key: old-key\n"), 0600)
	snap, err := snapshot([]string{sysSecretsPath}, 20)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(sysSecretsPath, []byte(pwSecretKey+": NEW\nwifi_key: new-key\n"), 0600)
	if _, err := restore(snap); err != nil {
		t.Fatal(err)
	}
	if s := readSecretsFile(sysSecretsPath); s[pwSecretKey] != "NEW" || s["wifi_key"] != "old-key" {
		t.Errorf("after restore: %v", s)
	}
}

// Two apply requests at once: the second waits for the first to start its job and is then refused
// (before, both started a job and the second's candidate replaced the first's).
func TestApplyJobStartSerialized(t *testing.T) {
	d, _, _ := confirmEnv(t)
	oldJ, oldS := JobFile, startDetached
	t.Cleanup(func() { JobFile, startDetached = oldJ, oldS })
	JobFile = filepath.Join(d, "job.json")
	startDetached = func(string, ...string) {}
	unlock := lockJob()
	done := make(chan apiResp)
	go func() { done <- apiApply(apiReq{method: "POST", body: []byte(`{}`)}) }()
	time.Sleep(100 * time.Millisecond)
	writeJob(jobState{State: "running", Started: time.Now().Unix()})
	unlock()
	if r := <-done; r.status != 409 {
		t.Errorf("second apply: %d %v", r.status, r.body)
	}
}

// An apply job whose process died (or never started) no longer blocks the web UI until a reboot.
func TestDeadApplyJobIsFailed(t *testing.T) {
	d, _, _ := confirmEnv(t)
	old := JobFile
	t.Cleanup(func() { JobFile = old })
	JobFile = filepath.Join(d, "job.json")
	dead := exec.Command("true")
	dead.Run()
	now := time.Now().Unix()
	for _, tc := range []struct {
		j    jobState
		want string
	}{
		{jobState{State: "running", Started: now, Pid: os.Getpid()}, "running"},
		{jobState{State: "running", Started: now}, "running"}, // starting
		{jobState{State: "running", Started: now, Pid: dead.Process.Pid}, "failed"},
		{jobState{State: "running", Started: now - 120}, "failed"}, // never started
	} {
		writeJob(tc.j)
		if got := readJob().State; got != tc.want {
			t.Errorf("%+v: %s", tc.j, got)
		}
	}
	if r := apiApply(apiReq{method: "POST", body: []byte(`{}`)}); r.status == 409 {
		t.Errorf("a dead job still blocks: %v", r.body)
	}
}

// Two snapshots in the same second get two files; the one just written survives pruning even when
// the clock went back (it sorts before the older ones).
func TestSnapshotNames(t *testing.T) {
	d, _, _ := confirmEnv(t)
	f := filepath.Join(d, "x")
	os.WriteFile(f, []byte("1"), 0644)
	a, err1 := snapshot([]string{f}, 20)
	b, err2 := snapshot([]string{f}, 20)
	if err1 != nil || err2 != nil || a == b {
		t.Fatalf("%s %s %v %v", a, b, err1, err2)
	}
	if strings.TrimSuffix(filepath.Base(a), ".tar.gz")[:15] == strings.TrimSuffix(filepath.Base(b), ".tar.gz")[:15] && !(a < b) {
		t.Errorf("same-second order: %s %s", a, b)
	}
	for _, n := range []string{"29990101-000000", "29990101-000001", "29990101-000002"} {
		os.WriteFile(filepath.Join(HistoryDir, n+".tar.gz"), nil, 0600)
	}
	c, err := snapshot([]string{f}, 2)
	if err != nil {
		t.Fatal(err)
	}
	ents, _ := os.ReadDir(HistoryDir)
	var left []string
	for _, e := range ents {
		left = append(left, e.Name())
	}
	if _, err := os.Stat(c); err != nil || len(left) != 2 || left[1] != "29990101-000002.tar.gz" {
		t.Errorf("after pruning: %v (new %s)", left, filepath.Base(c))
	}
}

// Without a record of the applied config the change's reach is unknown: never low (auto-kept).
func TestRiskUnknownChangesIsHigh(t *testing.T) {
	d := t.TempDir()
	oy, os_ := appliedYAML, appliedSecrets
	t.Cleanup(func() { appliedYAML, appliedSecrets = oy, os_ })
	appliedYAML, appliedSecrets = filepath.Join(d, "applied.yaml"), filepath.Join(d, "applied-secrets")
	c := testConfig(t)
	if r := planRisk(c, &Plan{}, ""); r.Level != "high" {
		t.Errorf("unknown changes: %+v", r)
	}
	for _, f := range appliedFiles(c) {
		os.WriteFile(f.Path, []byte(f.Data), 0600)
	}
	if r := planRisk(c, &Plan{}, ""); r.Level != "low" {
		t.Errorf("no changes: %+v", r)
	}
}
