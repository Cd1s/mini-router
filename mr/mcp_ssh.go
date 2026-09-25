package main

// AI agents over SSH (Cd1s/mini-router#37). services.ssh.agents gives an agent an SSH key that can
// do nothing but run `mr mcp` with a fixed scope; it is rendered into the managed block of root's
// authorized_keys as
//
//	command="/usr/sbin/mr mcp --scope=operate --agent=claude",no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty ssh-ed25519 AAAA… mr-agent:claude
//
// dropbear runs the forced command whatever the client asks for (the client's command only reaches
// SSH_ORIGINAL_COMMAND, which mr ignores); the four no-* options exist in every dropbear version
// (`restrict` only in newer ones) and leave no tunnel, agent, X11 or terminal. The key's own comment
// is not kept: the line ends in mr-agent:<name>.
//
// guard.approvers are the owner's FIDO security keys: a plan above guard.max_risk_without_touch
// (default medium: high-risk changes) is applied only with a signature one of them made for that plan
// (sshsig.go, mcp_plan.go). Both are in guard, which agents and API tokens can never change.

import (
	"fmt"
	"strings"
)

type SSHAgent struct {
	Name  string `yaml:"name"`
	Key   string `yaml:"key"`   // public key: type base64 [comment]
	Scope string `yaml:"scope"` // read | operate | apply (each includes the ones before)
}

const (
	agentOpts  = "no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty"
	maxAgents  = 8
	maxSignKey = 8
)

var reAgentLine = lazyRegexp(`^command="/usr/sbin/mr mcp --scope=(read|operate|apply) --agent=([a-z][a-z0-9_-]{0,14})",no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty (\S+ \S+) mr-agent:([a-z][a-z0-9_-]{0,14})$`)

// agentKeyLine: the authorized_keys line of agent a.
func agentKeyLine(a SSHAgent) (string, error) {
	k, err := parseAuthKey(a.Key)
	if err != nil {
		return "", err
	}
	f := strings.Fields(k.line)
	return fmt.Sprintf(`command="%s mcp --scope=%s --agent=%s",%s %s %s mr-agent:%s`, mrBin, a.Scope, a.Name, agentOpts, f[0], f[1], a.Name), nil
}

// agentKeyLines: every valid agent's line, for the managed block (renderAuthKeys).
func agentKeyLines(c *Config) []string {
	var out []string
	for _, a := range c.Services.SSH.Agents {
		if scopeLevel[a.Scope] == 0 || !reName.MatchString(a.Name) {
			continue
		}
		if l, err := agentKeyLine(a); err == nil {
			out = append(out, l)
		}
	}
	return out
}

// parseKeyLine reads one authorized_keys line: a plain key, or an agent's line as rendered here.
func parseKeyLine(l string) (*authKey, error) {
	if m := reAgentLine.FindStringSubmatch(l); m != nil && m[2] == m[4] {
		k, err := parseAuthKey(m[3])
		if err != nil {
			return nil, err
		}
		k.Comment = "agent " + m[2] + " (mr mcp, scope " + m[1] + ")"
		return k, nil
	}
	return parseAuthKey(l)
}

func validateAgents(c *Config, v *Validator) {
	s := c.Services.SSH
	if len(s.Agents) > maxAgents {
		v.Add("services.ssh.agents: at most %d", maxAgents)
	}
	logins := map[string]bool{}
	for _, l := range s.Keys {
		if k, err := parseAuthKey(l); err == nil {
			logins[k.FP] = true
		}
	}
	names, fps := map[string]bool{}, map[string]bool{}
	for i, a := range s.Agents {
		p := fmt.Sprintf("services.ssh.agents[%d]", i)
		if !reName.MatchString(a.Name) {
			v.Add("%s.name: [a-z][a-z0-9_-]{0,14}, got %q", p, clip(a.Name, 40))
		} else {
			p = "services.ssh.agents[" + a.Name + "]"
		}
		if names[a.Name] {
			v.Add("%s: duplicate name", p)
		}
		names[a.Name] = true
		if scopeLevel[a.Scope] == 0 {
			v.Add("%s.scope: read|operate|apply, got %q", p, clip(a.Scope, 20))
		}
		k, err := parseAuthKey(a.Key)
		if err != nil {
			v.Add("%s.key: %v", p, err)
			continue
		}
		if logins[k.FP] {
			v.Add("%s.key: %s is also a login key in services.ssh.authorized_keys (that line would open a shell): give the agent a key of its own", p, k.FP)
		}
		if fps[k.FP] {
			v.Add("%s.key: %s is another agent's key", p, k.FP)
		}
		fps[k.FP] = true
	}
}

// validateApproval: guard.approvers (FIDO keys only) and guard.max_risk_without_touch.
func validateApproval(c *Config, v *Validator) {
	g := c.Guard
	switch g.MaxRiskWithoutTouch {
	case "", "low", "medium":
	default:
		v.Add("guard.max_risk_without_touch: low or medium, got %q (high-risk changes by agents always need a touch)", clip(g.MaxRiskWithoutTouch, 20))
	}
	if len(g.Approvers) > maxSignKey {
		v.Add("guard.approvers: at most %d keys", maxSignKey)
	}
	seen := map[string]bool{}
	for i, l := range g.Approvers {
		k, err := parseAuthKey(l)
		if err != nil {
			v.Add("guard.approvers[%d]: %v", i, err)
			continue
		}
		if k.Type != skEd25519 && k.Type != skECDSA {
			v.Add("guard.approvers[%d]: %s is not a FIDO security key: want %s or %s (ssh-keygen -t ed25519-sk)", i, k.Type, skEd25519, skECDSA)
		}
		if seen[k.FP] {
			v.Add("guard.approvers[%d]: duplicate key %s", i, k.FP)
		}
		seen[k.FP] = true
	}
}
