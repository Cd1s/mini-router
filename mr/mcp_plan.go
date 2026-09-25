package main

// `mr mcp` changes (Cd1s/mini-router#37): plan_change, apply_plan, confirm, rollback.
//
// plan_change edits the live router.yaml's text with the patch (layout kept, like the API's patches),
// refuses what agents may never change (lockedChanges: api, services.ssh, system.sysctl, guard, new
// *_file references, items that reference a secret — the API tokens' rule) before anything else
// looks at the candidate, validates it (the guard included), plans it and rates its risk. The plan
// is stored in /run/mini-router/mcp/<id>.{json,yaml} (RAM, root only, 1 hour, at most 16) with the
// sha256 of the exact candidate, the live router.yaml's rev and a hash of the live secrets.
//
// apply_plan re-checks all of it: the candidate's sha256, the live files unchanged since the plan (else
// "stale"), validation, the locked parts, a risk not higher than planned. A risk above
// guard.max_risk_without_touch (default medium) needs an SSH signature over the plan's approval text
// — plan id, sha256, base rev, risk, the changes — by one of guard.approvers (FIDO keys), touched
// (sshsig.go). The owner can read that text from the router itself (`mr mcp show ID`) instead of
// trusting the agent's copy: it is exactly what the signature covers. Then the plan is used up and
// the standard apply job runs it (snapshot, verify, automatic rollback, confirm window), recorded as
// via=mcp:<agent>. confirm and rollback settle only the agent's own pending change.

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const sigNamespace = "mr-plan"

// variables so tests can replace them
var (
	mcpPlanDir  = RunDir + "/mcp"
	mcpPlanTTL  = time.Hour
	mcpMaxPlans = 16
	// mcpPlanFn plans a candidate (tests: plan() compares with the files of the host it runs on)
	mcpPlanFn = plan
	// mcpStartJob starts the apply job (`mr apply-job`) for CandidateYAML / CandidateSec
	mcpStartJob = func(secs int) {
		self, _ := os.Executable()
		startDetached(self, "apply-job", strconv.Itoa(secs))
	}
	// mcpRevert rolls the pending change back in the background (`mr rollback SNAPSHOT`)
	mcpRevert = func(snap string) {
		self, _ := os.Executable()
		startDetached(self, "rollback", snap)
	}
	mcpJobWait = 50 * time.Second // apply_plan waits this long for the job (MCP clients time out at ~60 s)
	mcpJobPoll = time.Second
)

var rePlanID = lazyRegexp(`^[0-9a-f]{16}$`)

func riskRank(level string) int {
	switch level {
	case "low":
		return 1
	case "medium":
		return 2
	case "high":
		return 3
	}
	return 0
}

// touchThreshold: the highest risk an agent's plan may have without an approver's signature.
func touchThreshold(c *Config) string {
	if t := c.Guard.MaxRiskWithoutTouch; t != "" {
		return t
	}
	return "medium"
}

func approvalNeeded(level string, c *Config) bool {
	return riskRank(level) > riskRank(touchThreshold(c))
}

func revOf(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:8]) }

func sha256hex(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// mcpPlan is a stored plan (<id>.json; the candidate is <id>.yaml).
type mcpPlan struct {
	ID          string   `json:"id"`
	Kind        string   `json:"kind"` // change | rollback
	Agent       string   `json:"agent"`
	Host        string   `json:"host"`
	Created     int64    `json:"created"`
	Expires     int64    `json:"expires"`
	BaseRev     string   `json:"base_rev"`     // the live router.yaml it was made from
	SecretsHash string   `json:"secrets_hash"` // sha256 of the live secrets.yaml (never shown)
	SHA256      string   `json:"sha256"`       // of the candidate router.yaml
	Risk        riskInfo `json:"risk"`
	Changes     []string `json:"changes"`
	Actions     []string `json:"actions"`
	Comment     string   `json:"comment"`
	Approval    string   `json:"approval"` // the text an approver signs
}

type mcpPatchOp struct {
	Op    string `json:"op" yaml:"op"`
	Path  string `json:"path" yaml:"path"`
	Value any    `json:"value,omitempty" yaml:"value,omitempty"`
}

type mcpPlanIn struct {
	Patch   []mcpPatchOp `json:"patch" yaml:"patch"`
	Comment string       `json:"comment,omitempty" yaml:"comment,omitempty"`
	BaseRev string       `json:"base_rev,omitempty" yaml:"base_rev,omitempty"`
}

type mcpApprovalHow struct {
	Why     string `json:"why" yaml:"why"`
	File    string `json:"file" yaml:"file"`
	Text    string `json:"text" yaml:"text"`
	Command string `json:"command" yaml:"command"`
}

type mcpPlanOut struct {
	PlanID        string          `json:"plan_id" yaml:"plan_id"`
	SHA256        string          `json:"sha256" yaml:"sha256"`
	BaseRev       string          `json:"base_rev" yaml:"base_rev"`
	Expires       string          `json:"expires" yaml:"expires"`
	Changes       []string        `json:"changes" yaml:"changes"`
	Actions       []string        `json:"actions" yaml:"actions"`
	Risk          riskInfo        `json:"risk" yaml:"risk"`
	NeedsApproval bool            `json:"needs_approval" yaml:"needs_approval"`
	Approval      *mcpApprovalHow `json:"approval,omitempty" yaml:"approval,omitempty"`
	Next          string          `json:"next" yaml:"next"`
}

type mcpApplyIn struct {
	PlanID      string `json:"plan_id" yaml:"plan_id"`
	ConfirmSecs int    `json:"confirm_secs,omitempty" yaml:"confirm_secs,omitempty"`
	Signature   string `json:"signature,omitempty" yaml:"signature,omitempty"`
}

type mcpApplyOut struct {
	State       string   `json:"state" yaml:"state"`
	Output      []string `json:"output" yaml:"output"`
	ConfirmSecs int      `json:"confirm_secs" yaml:"confirm_secs"`
	Pending     bool     `json:"pending" yaml:"pending"`
	Left        int64    `json:"left" yaml:"left"`
	ApprovedBy  string   `json:"approved_by,omitempty" yaml:"approved_by,omitempty"`
	Next        string   `json:"next" yaml:"next"`
}

type mcpConfirmOut struct {
	Confirmed bool   `json:"confirmed" yaml:"confirmed"`
	Message   string `json:"message" yaml:"message"`
}

type mcpRollbackIn struct {
	Rev int `json:"rev,omitempty" yaml:"rev,omitempty"`
}

// ---- plan_change ----

func mcpPlanChange(s *mcpSession, raw json.RawMessage) (any, error) {
	var in mcpPlanIn
	if err := decodeArgs(raw, &in); err != nil {
		return nil, err
	}
	if len(in.Patch) == 0 || len(in.Patch) > 100 {
		return nil, refuse(nil, "patch: 1 to 100 edits")
	}
	if len(in.Comment) > 200 || !safeText(in.Comment) {
		return nil, refuse(nil, "comment: one line, at most 200 characters")
	}
	live, err := os.ReadFile(s.cfgPath)
	if err != nil {
		return nil, err
	}
	if in.BaseRev != "" && in.BaseRev != revOf(live) {
		return nil, refuse(map[string]string{"rev": revOf(live)}, "router.yaml changed since base_rev: read it again (config_get) and redo the change")
	}
	var ops []patchOp
	for _, o := range in.Patch {
		op := patchOp{Op: o.Op, Path: o.Path}
		if o.Value != nil {
			op.Value, _ = json.Marshal(o.Value)
		}
		ops = append(ops, op)
	}
	cand, _, _, err := editYAML(live, ops)
	if err != nil {
		return nil, refuse(nil, "%v", err)
	}
	return s.makePlan(live, cand, in.Comment, "change")
}

// makePlan checks, plans and stores candidate cand (a whole router.yaml) against the live one.
func (s *mcpSession) makePlan(live, cand []byte, comment, kind string) (any, error) {
	lc, k, err := s.load()
	if err != nil {
		return nil, err
	}
	sec, _ := os.ReadFile(s.secPath)
	cc, err := s.candidate(lc, cand)
	if err != nil {
		return nil, err
	}
	p, err := mcpPlanFn(cc)
	if err != nil {
		return nil, refuse(nil, "plan: %s", k.text(err.Error()))
	}
	changes := s.changes(lc, cc)
	if len(changes) == 0 && p.Empty() && bytes.Equal(live, cand) {
		return nil, refuse(nil, "nothing would change")
	}
	risk := classifyRisk(p, changes, findAdminPath(s.remote))
	risk.Reasons, risk.Effects = orEmpty(risk.Reasons), orEmpty(risk.Effects)
	now := time.Now()
	pl := &mcpPlan{ID: newPlanID(), Kind: kind, Agent: s.agent, Host: lc.System.Hostname, Created: now.Unix(),
		Expires: now.Add(mcpPlanTTL).Unix(), BaseRev: revOf(live), SecretsHash: sha256hex(sec), SHA256: sha256hex(cand),
		Risk: risk, Comment: comment}
	for _, l := range changes {
		pl.Changes = append(pl.Changes, k.text(l))
	}
	for _, l := range strings.Split(strings.TrimRight(p.String(), "\n"), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			pl.Actions = append(pl.Actions, k.text(l))
		}
	}
	pl.Approval = approvalText(pl)
	if err := storePlan(pl, cand); err != nil {
		return nil, err
	}
	logf("mcp %s: plan %s (%s, risk %s): %d changes", s.agent, pl.ID, kind, risk.Level, len(changes))
	return s.planOut(pl, lc), nil
}

// candidate: cand decoded with the live secrets and defaults; refused when it touches what agents may
// never change (checked first: validation must not look at a new *_file) or does not validate.
func (s *mcpSession) candidate(lc *Config, cand []byte) (*Config, error) {
	cc, err := decodeConfig(cand)
	if err != nil {
		return nil, refuse(nil, "the result does not fit router.yaml: %v", err)
	}
	cc.secrets = lc.secrets
	cc.defaults()
	if bad := lockedChanges(lc, cc); len(bad) > 0 {
		return nil, refuse(map[string][]string{"locked": bad}, "agents cannot change %s: only the owner can (web UI or SSH)", strings.Join(bad, ", "))
	}
	if errs := cc.Validate(); len(errs) > 0 {
		return nil, refuse(map[string][]string{"errors": errs}, "the change is invalid (nothing was planned)")
	}
	return cc, nil
}

// changes: the config-level diff an apply of cc makes (since the last apply; live → cc without a record).
func (s *mcpSession) changes(lc, cc *Config) []string {
	if ch, known := changesSinceApplied(cc); known {
		return ch
	}
	a, err1 := canonNode(lc)
	b, err2 := canonNode(cc)
	if err1 != nil || err2 != nil {
		return nil
	}
	return configChanges(a, b)
}

func (s *mcpSession) planOut(pl *mcpPlan, lc *Config) mcpPlanOut {
	o := mcpPlanOut{PlanID: pl.ID, SHA256: pl.SHA256, BaseRev: pl.BaseRev, Changes: orEmpty(pl.Changes),
		Actions: orEmpty(pl.Actions), Risk: pl.Risk, Expires: time.Unix(pl.Expires, 0).UTC().Format(time.RFC3339)}
	o.NeedsApproval = approvalNeeded(pl.Risk.Level, lc)
	switch {
	case scopeLevel[s.scope] < scopeLevel["apply"]:
		o.Next = "this agent's scope is " + s.scope + ": show the plan to the owner; applying it needs scope apply"
	case o.NeedsApproval && len(lc.Guard.Approvers) == 0:
		o.Next = "risk " + pl.Risk.Level + " needs the owner's FIDO approval, but guard.approvers is empty: only the owner can make this change (web UI or SSH)"
	case o.NeedsApproval:
		o.Next = "write approval.text to approval.file exactly (or the owner runs `mr mcp show " + pl.ID + "` on the router), " +
			"ask the owner to run approval.command and touch the key, then apply_plan with plan_id and signature = the .sig file's content"
	default:
		o.Next = "tell the user the changes and the risk, then apply_plan with this plan_id (valid until " + o.Expires + ")"
	}
	if o.NeedsApproval {
		file := "mr-plan-" + pl.ID + ".txt"
		o.Approval = &mcpApprovalHow{
			Why:     fmt.Sprintf("risk %s is above guard.max_risk_without_touch (%s)", pl.Risk.Level, touchThreshold(lc)),
			File:    file,
			Text:    pl.Approval,
			Command: "ssh-keygen -Y sign -n " + sigNamespace + " -f ~/.ssh/id_ed25519_sk " + file,
		}
	}
	return o
}

// approvalText: what an approver signs — everything that identifies the change, in plain lines. Every
// value is cleaned (no invisible or bidi characters that could make it read differently).
func approvalText(pl *mcpPlan) string {
	var b strings.Builder
	v := func(s string) string { return cleanText(s, 400) }
	fmt.Fprintf(&b, "mini-router change approval (ssh-keygen -Y sign -n %s)\n", sigNamespace)
	fmt.Fprintf(&b, "router:  %s\nplan:    %s\nagent:   %s\nkind:    %s\nsha256:  %s\nbase:    %s\n", v(pl.Host), pl.ID, v(pl.Agent), pl.Kind, pl.SHA256, pl.BaseRev)
	fmt.Fprintf(&b, "risk:    %s", pl.Risk.Level)
	if len(pl.Risk.Reasons) > 0 {
		fmt.Fprintf(&b, " — %s", v(strings.Join(pl.Risk.Reasons, "; ")))
	}
	fmt.Fprintf(&b, "\ncomment: %s\nexpires: %s\nchanges:\n", v(pl.Comment), time.Unix(pl.Expires, 0).UTC().Format(time.RFC3339))
	for i, l := range pl.Changes {
		if i == 100 {
			fmt.Fprintf(&b, "  … and %d more (the sha256 covers all of them)\n", len(pl.Changes)-i)
			break
		}
		fmt.Fprintf(&b, "  %s\n", v(l))
	}
	return b.String()
}

// ---- the plan store ----

func newPlanID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func planFiles(id string) (string, string) {
	return filepath.Join(mcpPlanDir, id+".json"), filepath.Join(mcpPlanDir, id+".yaml")
}

func storePlan(pl *mcpPlan, cand []byte) error {
	if err := os.MkdirAll(mcpPlanDir, 0700); err != nil {
		return err
	}
	prunePlans(mcpMaxPlans - 1)
	meta, y := planFiles(pl.ID)
	b, err := json.Marshal(pl)
	if err != nil {
		return err
	}
	if err := writeAtomic(y, cand, 0600); err != nil {
		return err
	}
	return writeAtomic(meta, b, 0600)
}

// loadPlan: a stored plan and its candidate (expired plans are removed).
func loadPlan(id string) (*mcpPlan, []byte, error) {
	if !rePlanID.MatchString(id) {
		return nil, nil, errors.New("plan_id: 16 hex digits from plan_change")
	}
	meta, y := planFiles(id)
	var pl mcpPlan
	b, err := os.ReadFile(meta)
	if err == nil {
		err = json.Unmarshal(b, &pl)
	}
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil, fmt.Errorf("no plan %s: it expired, was applied already, or the router restarted (plan again)", id)
	}
	if err != nil {
		return nil, nil, err
	}
	if time.Now().Unix() > pl.Expires {
		dropPlan(id)
		return nil, nil, fmt.Errorf("plan %s expired at %s: plan again", id, time.Unix(pl.Expires, 0).UTC().Format(time.RFC3339))
	}
	cand, err := os.ReadFile(y)
	return &pl, cand, err
}

func dropPlan(id string) {
	meta, y := planFiles(id)
	os.Remove(meta)
	os.Remove(y)
}

// prunePlans removes expired plans and keeps at most keep of the others (the newest).
func prunePlans(keep int) {
	ents, _ := os.ReadDir(mcpPlanDir)
	type pe struct {
		id      string
		created int64
	}
	var live []pe
	for _, e := range ents {
		id, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok || !rePlanID.MatchString(id) {
			continue
		}
		var pl mcpPlan
		b, err := os.ReadFile(filepath.Join(mcpPlanDir, e.Name()))
		if err != nil || json.Unmarshal(b, &pl) != nil || time.Now().Unix() > pl.Expires {
			dropPlan(id)
			continue
		}
		live = append(live, pe{id, pl.Created})
	}
	sort.Slice(live, func(i, j int) bool { return live[i].created > live[j].created })
	for i := keep; i < len(live); i++ {
		dropPlan(live[i].id)
	}
}

// ---- apply_plan ----

func mcpApplyPlan(s *mcpSession, raw json.RawMessage) (any, error) {
	var in mcpApplyIn
	if err := decodeArgs(raw, &in); err != nil {
		return nil, err
	}
	if in.ConfirmSecs == 0 {
		in.ConfirmSecs = 120
	}
	if in.ConfirmSecs < 30 || in.ConfirmSecs > 600 {
		return nil, refuse(nil, "confirm_secs: 30 to 600")
	}
	if s.cfgPath != liveConfig {
		return nil, refuse(nil, "apply_plan changes the live router only (mr mcp without -c)")
	}
	pl, cand, err := loadPlan(in.PlanID)
	if err != nil {
		return nil, refuse(nil, "%v", err)
	}
	if pl.Agent != s.agent {
		return nil, refuse(nil, "plan %s belongs to agent %s", pl.ID, pl.Agent)
	}
	if sha256hex(cand) != pl.SHA256 {
		dropPlan(pl.ID)
		return nil, refuse(nil, "plan %s: the stored candidate does not match its sha256 (changed on the router): plan again", pl.ID)
	}
	live, err := os.ReadFile(s.cfgPath)
	if err != nil {
		return nil, err
	}
	sec, _ := os.ReadFile(s.secPath)
	if revOf(live) != pl.BaseRev || sha256hex(sec) != pl.SecretsHash {
		dropPlan(pl.ID)
		return nil, refuse(nil, "router.yaml or secrets.yaml changed since plan %s was made: plan again", pl.ID)
	}
	lc, k, err := s.load()
	if err != nil {
		return nil, err
	}
	cc, err := s.candidate(lc, cand)
	if err != nil {
		return nil, err
	}
	p, err := mcpPlanFn(cc)
	if err != nil {
		return nil, refuse(nil, "plan: %s", k.text(err.Error()))
	}
	if now := classifyRisk(p, s.changes(lc, cc), findAdminPath(s.remote)); riskRank(now.Level) > riskRank(pl.Risk.Level) {
		dropPlan(pl.ID)
		return nil, refuse(now, "the risk rose from %s to %s since the plan was made: plan again", pl.Risk.Level, now.Level)
	}
	var who *approval
	need := approvalNeeded(pl.Risk.Level, lc)
	switch {
	case need && len(lc.Guard.Approvers) == 0:
		return nil, refuse(nil, "risk %s needs the owner's FIDO approval and guard.approvers is empty: only the owner can make this change (web UI or SSH)", pl.Risk.Level)
	case need && strings.TrimSpace(in.Signature) == "":
		return nil, refuse(s.planOut(pl, lc).Approval, "risk %s: this plan needs the owner's approval with a FIDO key (signature)", pl.Risk.Level)
	}
	if strings.TrimSpace(in.Signature) != "" { // given: it must be good, needed or not
		msg := []byte(pl.Approval)
		who, err = verifyApproval(in.Signature, msg, sigNamespace, lc.Guard.Approvers)
		if err != nil && strings.HasSuffix(pl.Approval, "\n") { // an editor dropped the final newline
			if w, err2 := verifyApproval(in.Signature, msg[:len(msg)-1], sigNamespace, lc.Guard.Approvers); err2 == nil {
				who, err = w, nil
			}
		}
		if err != nil {
			logf("mcp %s: apply_plan %s refused: approval: %v", s.agent, pl.ID, err)
			return nil, refuse(nil, "approval refused: %s", k.text(err.Error()))
		}
	}
	if j := readJob(); j.State == "running" {
		return nil, refuse(nil, "another apply (%s) is running", j.Via)
	}
	if err := pendingBlocks(); err != nil {
		return nil, refuse(pendingView(), "%v", err)
	}
	comment := pl.Comment
	if pl.Kind == "rollback" && comment == "" {
		comment = "rollback"
	}
	comment = strings.TrimSpace(comment + " (plan " + pl.ID + ")")
	if who != nil {
		comment += " approved with " + who.FP
	}
	if err := os.MkdirAll(filepath.Dir(CandidateYAML), 0700); err != nil {
		return nil, err
	}
	if err := writeAtomic(CandidateYAML, cand, 0600); err != nil {
		return nil, err
	}
	if err := writeAtomic(CandidateSec, sec, 0600); err != nil {
		return nil, err
	}
	dropPlan(pl.ID) // used once
	writeJob(jobState{State: "running", Started: time.Now().Unix(), Confirm: in.ConfirmSecs, Via: s.via(), From: s.remote, Comment: comment})
	logf("mcp %s: apply_plan %s (risk %s%s)", s.agent, pl.ID, pl.Risk.Level, map[bool]string{true: ", approved", false: ""}[who != nil])
	mcpStartJob(in.ConfirmSecs)
	deadline := time.Now().Add(mcpJobWait)
	j := readJob()
	for j.State == "running" && time.Now().Before(deadline) {
		time.Sleep(mcpJobPoll)
		j = readJob()
	}
	if j.State == "running" {
		if b, err := os.ReadFile(JobLog); err == nil {
			j.Output = string(b)
		}
	}
	o := mcpApplyOut{State: j.State, Output: k.lines(j.Output, 40, false), ConfirmSecs: in.ConfirmSecs}
	if who != nil {
		o.ApprovedBy = who.FP + " " + k.text(who.Comment)
	}
	if pv, err := readPending(); err == nil && pv.State == statePending && pv.Via == s.via() {
		o.Pending, o.Left = true, pv.left()
	}
	switch o.State {
	case "ok":
		o.Next = fmt.Sprintf("check the router (status, diagnose), then confirm within %d s — or rollback now if something is wrong", o.Left)
	case "running":
		o.Next = "still applying: call status until job.state is ok or failed, then check and confirm"
	default:
		o.Next = "the apply failed and was rolled back: the output says why"
		return nil, refuse(o, "apply failed and rolled back")
	}
	return o, nil
}

// ---- confirm / rollback ----

func mcpConfirm(s *mcpSession, raw json.RawMessage) (any, error) {
	if err := decodeArgs(raw, &mcpNoArgs{}); err != nil {
		return nil, err
	}
	p, err := readPending()
	if errors.Is(err, fs.ErrNotExist) {
		return mcpConfirmOut{Message: "nothing waits for confirmation"}, nil
	}
	if err != nil {
		return nil, refuse(nil, "%v", err)
	}
	if p.Via != s.via() {
		return nil, refuse(nil, "the change waiting for confirmation was made by %s: only it, or the owner (web UI / SSH), can keep it", p.Via)
	}
	ok, err := confirm()
	if err != nil {
		return nil, refuse(nil, "%v", err)
	}
	logf("mcp %s: confirmed", s.agent)
	return mcpConfirmOut{Confirmed: ok, Message: "kept"}, nil
}

func mcpRollback(s *mcpSession, raw json.RawMessage) (any, error) {
	var in mcpRollbackIn
	if err := decodeArgs(raw, &in); err != nil {
		return nil, err
	}
	if in.Rev > 0 {
		snap, err := revSnapshot(in.Rev)
		if err != nil {
			return nil, refuse(nil, "%v", err)
		}
		y, ok, err := snapshotFile(snap, ConfigPath)
		if err != nil || !ok {
			return nil, refuse(nil, "change #%d: no router.yaml in its snapshot", in.Rev)
		}
		live, err := os.ReadFile(s.cfgPath)
		if err != nil {
			return nil, err
		}
		return s.makePlan(live, y, fmt.Sprintf("back to before #%d", in.Rev), "rollback")
	}
	p, err := readPending()
	if errors.Is(err, fs.ErrNotExist) {
		return nil, refuse(nil, "nothing waits for confirmation; to go back to before an earlier change, give rev (history)")
	}
	if err != nil {
		return nil, refuse(nil, "%v", err)
	}
	if p.Via != s.via() {
		return nil, refuse(nil, "the pending change was made by %s: only it, or the owner (web UI / SSH), can roll it back", p.Via)
	}
	if p.State != statePending {
		return nil, refuse(nil, "the change is %s: wait for it", p.State)
	}
	p.State = stateReverting // the confirm timer leaves it alone; the rollback removes the marker
	if err := setPending(*p); err != nil {
		return nil, err
	}
	mcpRevert(filepath.Base(p.Snapshot))
	logf("mcp %s: rolled back its pending change", s.agent)
	return map[string]any{"reverting": true, "message": "rolling back now (about as long as the apply took); status shows when it is done"}, nil
}

// ---- mr mcp plans | show ID (the owner, in a shell) ----

func mcpPlansCommand(args []string) error {
	if args[0] == "show" {
		if len(args) != 2 {
			return errors.New("mr mcp show PLAN_ID")
		}
		pl, _, err := loadPlan(args[1])
		if err != nil {
			return err
		}
		fmt.Print(pl.Approval)
		return nil
	}
	prunePlans(mcpMaxPlans)
	ents, _ := os.ReadDir(mcpPlanDir)
	n := 0
	for _, e := range ents {
		id, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok {
			continue
		}
		pl, _, err := loadPlan(id)
		if err != nil {
			continue
		}
		n++
		fmt.Printf("%s  %-15s %-8s %-6s expires %s  %d changes  %s\n", pl.ID, pl.Agent, pl.Kind, pl.Risk.Level,
			time.Unix(pl.Expires, 0).Format("15:04"), len(pl.Changes), cleanText(pl.Comment, 80))
	}
	if n == 0 {
		fmt.Println("no plans")
	}
	return nil
}
