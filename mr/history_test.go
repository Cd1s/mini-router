package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func canon(t *testing.T, c *Config) *yaml.Node {
	t.Helper()
	n, err := canonNode(c)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// The semantic diff names what changed in config terms: list items by name (radios by phy), inline
// lists as a whole, a value switched back to its default, reordering (Cd1s/mini-router#12).
func TestConfigChanges(t *testing.T) {
	a := testConfig(t)
	b := testConfig(t)
	b.System.Hostname = "office"
	b.WiFi.Radios[1].HTMode = "HE80"
	b.LAN.Ports = b.LAN.Ports[:len(b.LAN.Ports)-1]
	b.Firewall.Forwards = append(b.Firewall.Forwards, Forward{Name: "web", Proto: []string{"tcp"}, Port: "8080", To: "192.168.1.50"})
	gone := b.DHCP.Hosts[0].Name
	b.DHCP.Hosts = b.DHCP.Hosts[1:]
	b.WAN[1].SrcRoute = !a.WAN[1].SrcRoute
	f := b.Firewall.Forwards
	f[0], f[1] = f[1], f[0]
	got := strings.Join(configChanges(canon(t, a), canon(t, b)), "\n")
	for _, want := range []string{
		"~ system.hostname: " + a.System.Hostname + " → office",
		"~ wifi.radios[" + a.WiFi.Radios[1].Phy + "].htmode: " + a.WiFi.Radios[1].HTMode + " → HE80",
		"~ lan.ports: ",
		"+ firewall.forwards[web]",
		"- dhcp.hosts[" + gone + "]",
		"~ wan[" + a.WAN[1].Name + "].ipv6_srcroute: ",
		"~ firewall.forwards: order " + a.Firewall.Forwards[0].Name + ", " + a.Firewall.Forwards[1].Name,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if n := len(configChanges(canon(t, a), canon(t, testConfig(t)))); n != 0 {
		t.Errorf("identical configs: %d changes", n)
	}
}

func TestSecretChanges(t *testing.T) {
	old := map[string]string{"a": secretHash("1"), "b": secretHash("2"), "gone": secretHash("x")}
	got := strings.Join(secretChanges(old, map[string]string{"a": "1", "b": "22", "new": "n", pwSecretKey: "h"}), "|")
	if got != "~ secrets.b: (changed)|+ secrets.new|- secrets.gone" {
		t.Errorf("got %q", got)
	}
	if strings.Contains(got, "22") {
		t.Error("secret value in the diff")
	}
}

// The record of the applied config: plans do not list it; the next plan's diff is against it.
func TestChangesSinceApplied(t *testing.T) {
	d := t.TempDir()
	oldY, oldS := appliedYAML, appliedSecrets
	t.Cleanup(func() { appliedYAML, appliedSecrets = oldY, oldS })
	appliedYAML, appliedSecrets = filepath.Join(d, "applied.yaml"), filepath.Join(d, "applied-secrets")
	c := testConfig(t)
	if _, ok := changesSinceApplied(c); ok {
		t.Fatal("no record yet, but a diff")
	}
	for _, f := range appliedFiles(c) {
		os.WriteFile(f.Path, []byte(f.Data), os.FileMode(f.Mode))
		if strings.Contains(f.Data, c.secrets["pppoe_password"]) {
			t.Errorf("%s holds a secret value", f.Path)
		}
	}
	if ch, ok := changesSinceApplied(c); !ok || len(ch) != 0 {
		t.Fatalf("unchanged: %v %v", ok, ch)
	}
	c.System.Hostname = "office"
	c.secrets["pppoe_password"] = "new"
	ch, _ := changesSinceApplied(c)
	if strings.Join(ch, "|") != "~ system.hostname: "+testConfig(t).System.Hostname+" → office|~ secrets.pppoe_password: (changed)" {
		t.Errorf("got %q", ch)
	}
	p := &Plan{Changed: []File{{Path: appliedYAML}}}
	if s := p.String(); strings.Contains(s, "applied.yaml") || !strings.Contains(s, "only the record") {
		t.Errorf("plan shows the bookkeeping file: %q", s)
	}
}

// Revisions: numbered, results recorded, pruned together with their snapshots.
func TestRevisions(t *testing.T) {
	confirmEnv(t)
	os.MkdirAll(HistoryDir, 0700)
	var snaps []string
	for i := 0; i < 4; i++ {
		s := filepath.Join(HistoryDir, "2026092"+string(rune('1'+i))+"-120000.tar.gz")
		os.WriteFile(s, []byte("x"), 0600)
		newRevision(s, applyOpts{Via: "web UI", From: "192.0.2.5", Comment: "c"}, []string{"~ a: 1 → 2"})
		snaps = append(snaps, s)
	}
	setResult(snaps[3], "pending")
	setResult(snaps[3], "confirmed")
	rs := readRevisions()
	if len(rs) != 4 || rs[3].Rev != 4 || rs[3].Result != "confirmed" || rs[0].Result != "applying" || rs[3].From != "192.0.2.5" {
		t.Fatalf("revisions: %+v", rs)
	}
	pruneHistory(2)
	rs = readRevisions()
	if len(rs) != 2 || rs[0].Rev != 3 {
		t.Errorf("after prune: %+v", rs)
	}
	if _, err := os.Stat(revFile(snaps[0])); err == nil {
		t.Error("sidecar of a pruned snapshot kept")
	}
	if p, err := revSnapshot(4); err != nil || p != snaps[3] {
		t.Errorf("revSnapshot: %q %v", p, err)
	}
	if _, err := revSnapshot(1); err == nil {
		t.Error("pruned revision found")
	}
}

func writeTarGz(t *testing.T, path string, files map[string]string) {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for n, d := range files {
		tw.WriteHeader(&tar.Header{Name: strings.TrimPrefix(n, "/"), Mode: 0600, Size: int64(len(d))})
		tw.Write([]byte(d))
	}
	tw.Close()
	gz.Close()
	os.WriteFile(path, buf.Bytes(), 0600)
}

// Rolling back to before a change stages that snapshot's router.yaml and secrets as the candidate —
// with the web UI password of today, not the one saved back then.
func TestStageRollbackKeepsPassword(t *testing.T) {
	d, _, _ := confirmEnv(t)
	oldY, oldS, oldL := CandidateYAML, CandidateSec, sysSecretsPath
	t.Cleanup(func() { CandidateYAML, CandidateSec, sysSecretsPath = oldY, oldS, oldL })
	CandidateYAML, CandidateSec, sysSecretsPath = filepath.Join(d, "cand.yaml"), filepath.Join(d, "cand-sec.yaml"), filepath.Join(d, "live-secrets.yaml")
	os.WriteFile(sysSecretsPath, []byte(pwSecretKey+": NOW\nwifi_key: now-key\n"), 0600)
	os.MkdirAll(HistoryDir, 0700)
	snap := filepath.Join(HistoryDir, "20260920-120000.tar.gz")
	writeTarGz(t, snap, map[string]string{ConfigPath: "system: {hostname: before}\n", SecretsPath: pwSecretKey + ": THEN\nwifi_key: then-key\n"})
	newRevision(snap, applyOpts{Via: "mr apply"}, nil)
	if err := stageRollback(1); err != nil {
		t.Fatal(err)
	}
	if y, _ := os.ReadFile(CandidateYAML); string(y) != "system: {hostname: before}\n" {
		t.Errorf("candidate router.yaml: %q", y)
	}
	sec := readSecretsFile(CandidateSec)
	if sec[pwSecretKey] != "NOW" || sec["wifi_key"] != "then-key" {
		t.Errorf("candidate secrets: %v", sec)
	}
	if err := stageRollback(7); err == nil {
		t.Error("unknown revision staged")
	}
}

func TestFileDiffMasksSecrets(t *testing.T) {
	old := "a\nb\npassword secret-one\nc\nd\n"
	new := "a\nb\npassword secret-two\nc\nd\ne\n"
	d := fileDiff("/etc/x.conf", old, new, map[string]string{"k1": "secret-one", "k2": "secret-two"})
	if strings.Contains(d, "secret-") {
		t.Errorf("secret in diff:\n%s", d)
	}
	// masked, the password line is the same on both sides; only the new line shows
	for _, want := range []string{"--- /etc/x.conf", "+e\n", " d\n"} {
		if !strings.Contains(d, want) {
			t.Errorf("missing %q:\n%s", want, d)
		}
	}
	if fileDiff("/x", "same\n", "same\n", nil) != "" {
		t.Error("diff of equal files")
	}
}
