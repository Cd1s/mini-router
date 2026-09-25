package main

import (
	"os"
	"strings"
	"testing"
)

// Agent keys land in the managed block of authorized_keys with a forced `mr mcp` and every
// forwarding / pty option off; mr reads the lines back; lines it did not render are not agent lines.
func TestAgentKeysRender(t *testing.T) {
	sysTemp(t)
	login, ak1, ak2 := fakeKey("ssh-ed25519", 1, "laptop"), fakeKey("ssh-ed25519", 2, "agent laptop"), fakeKey("sk-ssh-ed25519@openssh.com", 3, "")
	c := testConfig(t)
	c.Services.SSH.Keys = []string{login}
	c.Services.SSH.Agents = []SSHAgent{{Name: "claude", Key: ak1, Scope: "operate"}, {Name: "ci-bot", Key: ak2, Scope: "read"}}
	if errs := c.Validate(); len(errs) > 0 {
		t.Fatal(errs)
	}
	f := strings.Fields(ak1)
	want1 := `command="/usr/sbin/mr mcp --scope=operate --agent=claude",no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty ` + f[0] + " " + f[1] + " mr-agent:claude"
	os.WriteFile(authKeysFile, []byte("# image keys\n"), 0600)
	got := renderMap(t, c)[authKeysFile]
	f2 := strings.Fields(ak2)
	want := "# image keys\n" + akBegin + "\n" + login + "\n" + want1 + "\n" +
		`command="/usr/sbin/mr mcp --scope=read --agent=ci-bot",no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty ` + f2[0] + " " + f2[1] + " mr-agent:ci-bot\n" + akEnd + "\n"
	if got != want {
		t.Fatalf("authorized_keys:\n%s\nwant:\n%s", got, want)
	}
	k, err := parseKeyLine(want1)
	if err != nil || k.Comment != "agent claude (mr mcp, scope operate)" || k.Type != "ssh-ed25519" {
		t.Errorf("agent line read back: %+v %v", k, err)
	}
	for _, bad := range []string{
		strings.Replace(want1, "mr-agent:claude", "mr-agent:other", 1), // names disagree
		strings.Replace(want1, ",no-pty", "", 1),                       // an option missing
		strings.Replace(want1, "/usr/sbin/mr mcp", "/bin/sh -c mr mcp", 1),
	} {
		if _, err := parseKeyLine(bad); err == nil {
			t.Errorf("not rendered by mr, read as a key: %s", bad)
		}
	}
	os.WriteFile(authKeysFile, []byte(got), 0600)
	r := apiSysSSHKeys(apiReq{})
	body := r.body.(map[string]any)
	if m := body["managed"].([]authKey); len(m) != 3 || m[1].Comment != "agent claude (mr mcp, scope operate)" || body["other_unparsed"] != 0 {
		t.Errorf("sys.sshkeys: %+v", body)
	}
}

func TestAgentKeysValidate(t *testing.T) {
	login := fakeKey("ssh-ed25519", 1, "laptop")
	for name, c := range map[string]struct {
		agents []SSHAgent
		want   string
	}{
		"bad name":          {[]SSHAgent{{Name: "Claude Code", Key: fakeKey("ssh-ed25519", 2, ""), Scope: "read"}}, "agents[0].name"},
		"bad scope":         {[]SSHAgent{{Name: "a", Key: fakeKey("ssh-ed25519", 2, ""), Scope: "root"}}, "agents[a].scope"},
		"options in key":    {[]SSHAgent{{Name: "a", Key: `command="/bin/sh" ` + fakeKey("ssh-ed25519", 2, ""), Scope: "read"}}, "agents[a].key: unsupported key type"},
		"control character": {[]SSHAgent{{Name: "a", Key: fakeKey("ssh-ed25519", 2, "x\ny"), Scope: "read"}}, "agents[a].key: control characters"},
		"a login key":       {[]SSHAgent{{Name: "a", Key: login, Scope: "read"}}, "also a login key"},
		"two agents, one key": {[]SSHAgent{{Name: "a", Key: fakeKey("ssh-ed25519", 2, ""), Scope: "read"},
			{Name: "b", Key: fakeKey("ssh-ed25519", 2, "same"), Scope: "apply"}}, "another agent's key"},
		"duplicate name": {[]SSHAgent{{Name: "a", Key: fakeKey("ssh-ed25519", 2, ""), Scope: "read"},
			{Name: "a", Key: fakeKey("ssh-ed25519", 3, ""), Scope: "read"}}, "agents[a]: duplicate name"},
	} {
		cfg := testConfig(t)
		cfg.Services.SSH.Keys = []string{login}
		cfg.Services.SSH.Agents = c.agents
		if errs := strings.Join(cfg.Validate(), "\n"); !strings.Contains(errs, c.want) {
			t.Errorf("%s: want %q in:\n%s", name, c.want, errs)
		}
	}
	for name, c := range map[string]struct {
		g    Guard
		want string
	}{
		"ordinary key as approver": {Guard{Approvers: []string{fakeKey("ssh-ed25519", 4, "")}}, "not a FIDO security key"},
		"high needs no touch":      {Guard{MaxRiskWithoutTouch: "high"}, "guard.max_risk_without_touch: low or medium"},
		"duplicate approver": {Guard{Approvers: []string{fakeKey("sk-ssh-ed25519@openssh.com", 5, "a"),
			fakeKey("sk-ssh-ed25519@openssh.com", 5, "b")}}, "duplicate key"},
	} {
		cfg := testConfig(t)
		cfg.Guard = c.g
		if errs := strings.Join(cfg.Validate(), "\n"); !strings.Contains(errs, c.want) {
			t.Errorf("%s: want %q in:\n%s", name, c.want, errs)
		}
	}
	cfg := testConfig(t)
	cfg.Guard = Guard{Approvers: []string{fakeKey("sk-ssh-ed25519@openssh.com", 5, "owner"), fakeKey("sk-ecdsa-sha2-nistp256@openssh.com", 6, "")}, MaxRiskWithoutTouch: "low"}
	if errs := cfg.Validate(); len(errs) > 0 {
		t.Errorf("FIDO approvers refused: %v", errs)
	}
}
