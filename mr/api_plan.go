package main

// plan / patch / base_rev (Cd1s/mini-router#17). The web UI and API clients change the config by
// sending all of it (`config`) or a patch (`patch`: [{op: set|add|del, path, value}], paths as in
// cfgpath.go) — applied to router.yaml as written, so the file keeps its comments and layout.
// `GET config` answers the live router.yaml's `rev` (a content hash); `plan` and `apply` with
// `base_rev` fail with 409 when router.yaml changed since (another browser, an agent, `mr set`),
// so clients never overwrite each other's changes unseen. `POST plan` is a dry run: errors,
// config-level changes, files, services — nothing is changed.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
)

// liveConfig: the router.yaml that rev and patches refer to (a variable so tests can point it elsewhere).
var liveConfig = ConfigPath

// configRev: the live router.yaml's revision for optimistic concurrency ("" when there is none).
func configRev() string {
	b, err := os.ReadFile(liveConfig)
	if err != nil {
		return ""
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:8])
}

// staleBase: the 409 answer when base (a rev the client read) is no longer the live one.
func staleBase(base string) *apiResp {
	if base == "" {
		return nil
	}
	if now := configRev(); base != now {
		e := apiResp{status: 409, body: map[string]any{
			"error": "router.yaml changed since base_rev: read the config again (GET config) and redo the change",
			"rev":   now}}
		return &e
	}
	return nil
}

// patchedConfig: the live router.yaml with ops applied (layout kept) and the config it holds (no
// defaults, no secrets yet).
func patchedConfig(ops []patchOp) ([]byte, *Config, error) {
	cur, err := os.ReadFile(liveConfig)
	if err != nil {
		return nil, nil, err
	}
	y, c, kept, err := editYAML(cur, ops)
	if err == nil && !kept {
		logf("api patch: router.yaml rewritten in canonical form (comments not kept)")
	}
	return y, c, err
}

// apiPlan: what a config or patch would change — nothing is written.
func apiPlan(r apiReq) apiResp {
	in, err := parseSubmit(r.body)
	if err != nil {
		return errResp(400, "%v", err)
	}
	if e := staleBase(in.BaseRev); e != nil {
		return *e
	}
	rev := configRev()
	c, _, _, _, err := candidate(r)
	if err != nil {
		return apiResp{body: map[string]any{"errors": []string{err.Error()}, "rev": rev}}
	}
	if errs := c.Validate(); len(errs) > 0 {
		return apiResp{body: map[string]any{"errors": errs, "rev": rev}}
	}
	p, err := plan(c)
	if err != nil {
		return apiResp{body: map[string]any{"errors": []string{err.Error()}, "rev": rev}}
	}
	changes, known := changesSinceApplied(c)
	files := []string{}
	for _, f := range p.Changed {
		if !bookkeeping(f.Path) {
			files = append(files, f.Path)
		}
	}
	return apiResp{body: map[string]any{"errors": []string{}, "rev": rev,
		"changes": orEmpty(changes), "changes_known": known,
		"plan": p.String(), "empty": p.Empty(), "files": files, "firewall": p.Firewall,
		"restart": orEmpty(p.Services), "enable": orEmpty(p.Enable), "disable": orEmpty(p.Disable)}}
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// parseSubmit reads a plan / validate / apply body.
func parseSubmit(b []byte) (configSubmit, error) {
	var in configSubmit
	err := json.Unmarshal(b, &in)
	return in, err
}
