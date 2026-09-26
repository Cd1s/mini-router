package main

// sys module (Cd1s/mini-router#20, #82): what a new firmware or release means for this router, a copy
// of the config off the router, and `mr doctor --heal`.
//
//   - upgrade plan check: the first boot of a new MR_VERSION (eventBoot) starts `mr plan -v` in the
//     background into /run/mini-router/upgrade-plan.txt; when the new renderers would change generated
//     files, `mr doctor` says so (check "upgrade") until the next apply. Never applied automatically.
//   - update check (notify.update_check): crond runs `mr notify update-check` once a day; it asks GitHub
//     for the latest release of Cd1s/mini-router (verified TLS, no proxy, answer capped) and a newer one
//     becomes an `update` event, once per release. Never downloads or installs anything.
//   - archive (notify.archive): after a change is accepted (applied without --confirm, or confirmed), a
//     detached `mr notify archive` sends router.yaml — never secrets.yaml — off the router
//     (mod_sys_archive.go: https, WebDAV, S3, GitHub); a failure is an `archive` event.
//   - heal: `mr doctor --heal` restarts wanted services that are installed but not running (a crash loop
//     that hit respawn_max), each at most once per 10 minutes; logged and recorded as doctor events.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const healEvery = 600 // s between two restarts of one service by --heal

var (
	upgradePlanFile = RunDir + "/upgrade-plan.txt"
	healFile        = RunDir + "/heal.json"
	updateStateFile = "/etc/mini-router/state/update.json"
	updateURL       = "https://api.github.com/repos/Cd1s/mini-router/releases/latest"
	reReleaseTag    = lazyRegexp(`^v([0-9]{1,4})\.([0-9]{1,4})\.([0-9]{1,4})$`)
	reImageVersion  = lazyRegexp(`^[a-z0-9]+-(20[0-9]{6})-[0-9a-f]{4,40}$`) // m3-20260925-92b2ecc
	// upgradePlanKick: `mr plan -v` in the background, its output in upgradePlanFile.
	upgradePlanKick = func() {
		f, err := os.OpenFile(upgradePlanFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
		if err != nil {
			return
		}
		defer f.Close()
		self, args := selfCmd("plan", "-v")
		cmd := exec.Command(self, args...)
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		cmd.Stdout, cmd.Stderr = f, f
		cmd.Start()
	}
	archiveKick = func() {
		self, args := selfCmd("notify", "archive")
		startDetached(self, args...)
	}
)

// ---- upgrade plan check ----

// docUpgrade: what the plan saved at the first boot of a new firmware says.
func docUpgrade(c *Config, e *docEnv) []docFinding {
	s := e.read(upgradePlanFile)
	if s == "" {
		return []docFinding{{Sev: "skip", Title: "New firmware", Detail: "no plan check since the last firmware change or apply"}}
	}
	n, fw := 0, false
	for _, l := range strings.Split(s, "\n") {
		if strings.HasPrefix(l, "  write   ") {
			n++
		}
		fw = fw || l == "  reload  firewall"
	}
	fix := "cat " + upgradePlanFile + "; mr plan -v; mr apply --confirm 120 when the changes look right"
	switch {
	case strings.HasPrefix(s, "mr:"):
		return []docFinding{{Sev: "warn", Title: "New firmware", Detail: "mr plan failed: " + eventClean(firstLine(s), 160), Fix: fix}}
	case n == 0 && !fw:
		return []docFinding{docOK("New firmware", "renders the same files as before")}
	}
	d := fmt.Sprintf("the new version would change %d generated file(s)", n)
	if fw {
		d += " and the firewall"
	}
	return []docFinding{{Sev: "warn", Title: "New firmware", Detail: d + " (nothing is applied by itself)", Fix: fix}}
}

// ---- update check ----

type updateState struct {
	Tag     string `json:"tag,omitempty"` // the newest release reported
	Checked int64  `json:"checked,omitempty"`
}

// releaseNewer: release tag (published at pub, RFC 3339) is newer than the running version cur —
// a vX.Y.Z install compares versions, a firmware image build (name-YYYYMMDD-sha) the dates.
func releaseNewer(cur, tag, pub string) bool {
	b := reReleaseTag.FindStringSubmatch(tag)
	if b == nil {
		return false
	}
	if a := reReleaseTag.FindStringSubmatch(cur); a != nil {
		for i := 1; i <= 3; i++ {
			x, _ := strconv.Atoi(a[i])
			y, _ := strconv.Atoi(b[i])
			if x != y {
				return y > x
			}
		}
		return false
	}
	if m := reImageVersion.FindStringSubmatch(cur); m != nil && len(pub) >= 10 {
		return strings.ReplaceAll(pub[:10], "-", "") > m[1]
	}
	return false
}

// updateCheck asks GitHub for the latest release; a newer one is an update event (once per tag).
func updateCheck(c *Config, hc *http.Client) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", updateURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "mini-router/"+version)
	resp, err := hc.Do(req)
	if err != nil {
		return notifyErr(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("GitHub: HTTP %d", resp.StatusCode)
	}
	var r struct {
		Tag       string `json:"tag_name"`
		Published string `json:"published_at"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 512<<10)).Decode(&r); err != nil || !reReleaseTag.MatchString(r.Tag) {
		return errors.New("GitHub: not a release answer")
	}
	var st updateState
	readJSONFile(updateStateFile, &st)
	st.Checked = eventNow().Unix()
	if releaseNewer(version, r.Tag, r.Published) && st.Tag != r.Tag {
		st.Tag = r.Tag
		eventAdd(c, "update", "info", r.Tag, fmt.Sprintf("mini-router %s is available (running %s): https://github.com/Cd1s/mini-router/releases/tag/%s",
			r.Tag, eventClean(version, 40), r.Tag), true)
	}
	b, _ := json.Marshal(st)
	return writeAtomic(updateStateFile, b, 0600)
}

// updateCronLine: the daily release check, at a minute and hour (10:00-17:59) fixed per router.
func updateCronLine(c *Config) []string {
	if !c.Notify.UpdateCheck {
		return nil
	}
	h := fnv.New32a()
	h.Write([]byte(c.System.Hostname + "|update"))
	n := h.Sum32()
	return []string{"# release check (notify.update_check)", fmt.Sprintf("%d %d * * * %s notify update-check", n%60, 10+(n/60)%8, mrBin)}
}

// ---- archive ----

// archiveAfterChange: a change was accepted — send router.yaml in the background when an archive is set.
func archiveAfterChange() {
	if c, err := loadConfig(sysConfigPath, sysSecretsPath); err == nil && c.Notify.Archive != nil {
		archiveKick()
	}
}

// ---- heal ----

// apiSysHeal: POST → `mr doctor --heal`'s step now; returns what it did.
func apiSysHeal(r apiReq) apiResp {
	if r.method != "POST" {
		return errResp(405, "POST required")
	}
	c, err := loadConfig(sysConfigPath, sysSecretsPath)
	if err != nil {
		return errResp(500, "%v", err)
	}
	return apiResp{body: map[string]any{"actions": doctorHeal(c, newDocEnv())}}
}

// doctorHeal restarts the wanted, installed services that do not run (not mr-network / mr-firewall:
// a restart of those is an outage; mr routes / mr fw repair them). Each at most once per healEvery.
func doctorHeal(c *Config, e *docEnv) []string {
	if lk := flock(healFile+".lock", true); lk != nil { // the web UI's 修复 and the background run at once
		defer lk.Close()
	}
	want := enabledServices(c)
	st := e.running(want)
	last := map[string]int64{}
	readJSONFile(healFile, &last)
	now := e.now.Unix()
	var done []string
	for _, s := range want {
		if r, inst := st[s]; !inst || r || s == "mr-network" || s == "mr-firewall" {
			continue
		}
		if now-last[s] < healEvery {
			done = append(done, s+": not running, left alone (restarted "+fmtSecs(now-last[s])+" ago)")
			continue
		}
		last[s] = now
		res, sev := "restarted", "info"
		if err := e.restart(s); err != nil {
			res, sev = "restart failed", "warn"
		}
		logf("doctor --heal: %s %s", s, res)
		appendChangeLog("doctor --heal: restart " + s)
		eventAdd(c, "doctor", sev, "heal."+s, "heal: "+s+" was not running, "+res, false)
		done = append(done, s+": "+res)
	}
	b, _ := json.Marshal(last)
	writeAtomic(healFile, b, 0600)
	if len(done) > 0 {
		eventKick(c, "doctor")
	}
	return done
}
