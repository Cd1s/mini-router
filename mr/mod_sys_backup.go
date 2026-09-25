package main

// sys module: configuration backup and restore.
//
// A backup is a tar.gz of
//
//	etc/mini-router/router.yaml
//	etc/mini-router/secrets.yaml      only when asked for; the web UI password hash is never included
//	etc/mini-router/dns/<file>        list files (split DNS domains)
//	etc/mini-router/proxy/<file>      list files (proxy domains / CIDRs)
//	mr-backup.json                    manifest (informational)
//
// Restore never writes router.yaml / secrets.yaml itself: the archive is checked strictly (only the
// names above, regular files, size limits), the candidate config is validated and rendered, and then
// the standard web UI apply job installs it (ApplyCandidate: snapshot, apply, verify, confirm
// countdown, automatic rollback). List files are data outside that snapshot, so restore saves the
// current ones as a snapshot of their own (<time>-restore-lists.tar.gz in the history, same format)
// before replacing them, and puts them back when validation fails, the apply fails, or the apply is
// rolled back (not confirmed / reverted). Secrets from a backup are merged over the current ones;
// the web UI password always stays the current one.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

const (
	backupMaxUpload  = 2_900_000 // decoded archive size the API accepts (base64 in JSON stays under the 4 MiB body limit)
	backupMaxFile    = 16 << 20
	backupMaxTotal   = 48 << 20
	backupMaxEntries = 256
	backupManifest   = "mr-backup.json"
)

// Paths used by backup/restore (variables so tests can use a temp dir).
var (
	sysConfigPath  = ConfigPath
	sysSecretsPath = SecretsPath
	sysHistoryDir  = HistoryDir
	restoreDir     = RunDir + "/restore"
	// archive directory name → live directory of list files
	backupListDirs = map[string]string{"dns": "/etc/mini-router/dns", "proxy": "/etc/mini-router/proxy"}
)

var reBackupFile = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

func validListName(n string) bool { return reBackupFile.MatchString(n) && !strings.Contains(n, "..") }

type backupFile struct {
	name string
	mode int64
	data []byte
}

func readSecretsFrom(p string) (map[string]string, error) {
	m := map[string]string{}
	b, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return m, nil
		}
		return nil, err
	}
	if err := yaml.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// makeBackup builds the archive; returns it and the archive names it contains.
func makeBackup(withSecrets bool) ([]byte, []string, error) {
	var files []backupFile
	y, err := os.ReadFile(sysConfigPath)
	if err != nil {
		return nil, nil, err
	}
	files = append(files, backupFile{"etc/mini-router/router.yaml", 0644, y})
	if withSecrets {
		sec, err := readSecretsFrom(sysSecretsPath)
		if err != nil {
			return nil, nil, err
		}
		delete(sec, pwSecretKey)
		b, err := yaml.Marshal(sec)
		if err != nil {
			return nil, nil, err
		}
		files = append(files, backupFile{"etc/mini-router/secrets.yaml", 0600, b})
	}
	dirs := make([]string, 0, len(backupListDirs))
	for d := range backupListDirs {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)
	for _, d := range dirs {
		ents, _ := os.ReadDir(backupListDirs[d])
		for _, e := range ents {
			if !e.Type().IsRegular() || !validListName(e.Name()) {
				continue
			}
			b, err := os.ReadFile(filepath.Join(backupListDirs[d], e.Name()))
			if err != nil || len(b) > backupMaxFile {
				continue
			}
			files = append(files, backupFile{"etc/mini-router/" + d + "/" + e.Name(), 0644, b})
		}
	}
	host, _ := os.Hostname()
	var names []string
	for _, f := range files {
		names = append(names, f.name)
	}
	man, _ := json.MarshalIndent(map[string]any{"format": 1, "host": host, "version": version,
		"created": time.Now().UTC().Format(time.RFC3339), "secrets": withSecrets, "files": names}, "", " ")
	files = append(files, backupFile{backupManifest, 0644, append(man, '\n')})

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	now := time.Now()
	for _, f := range files {
		if err := tw.WriteHeader(&tar.Header{Name: f.name, Mode: f.mode, Size: int64(len(f.data)), ModTime: now, Typeflag: tar.TypeReg}); err != nil {
			return nil, nil, err
		}
		if _, err := tw.Write(f.data); err != nil {
			return nil, nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, nil, err
	}
	return buf.Bytes(), names, nil
}

// restoreSet is a checked backup archive.
type restoreSet struct {
	yaml    []byte
	secrets map[string]string // nil: the archive has no secrets.yaml
	lists   map[string][]byte // live absolute path → content
	names   []string          // archive names, for messages
}

// textOK: list files must be UTF-8 text without NULs / control characters (tabs and CR allowed).
func textOK(b []byte) bool {
	if !utf8.Valid(b) {
		return false
	}
	for _, ch := range b {
		if ch < 0x20 && ch != '\n' && ch != '\r' && ch != '\t' || ch == 0x7f {
			return false
		}
	}
	return true
}

// parseBackup checks an archive strictly: known names only, regular files, size limits.
func parseBackup(data []byte) (*restoreSet, error) {
	if len(data) > backupMaxUpload {
		return nil, fmt.Errorf("backup larger than %d bytes", backupMaxUpload)
	}
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("not a .tar.gz file: %v", err)
	}
	tr := tar.NewReader(io.LimitReader(gz, backupMaxTotal+(1<<20)))
	rs := &restoreSet{lists: map[string][]byte{}}
	seen := map[string]bool{}
	total := 0
	for n := 0; ; n++ {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("corrupt archive: %v", err)
		}
		if n >= backupMaxEntries {
			return nil, fmt.Errorf("more than %d entries", backupMaxEntries)
		}
		name := strings.TrimPrefix(h.Name, "./")
		if h.Typeflag == tar.TypeDir {
			switch strings.TrimSuffix(name, "/") {
			case "", ".", "etc", "etc/mini-router", "etc/mini-router/dns", "etc/mini-router/proxy":
				continue
			}
			return nil, fmt.Errorf("unexpected directory %q", clip(name, 80))
		}
		if name == "" || strings.HasPrefix(name, "/") || strings.Contains(name, "\\") || path.Clean(name) != name {
			return nil, fmt.Errorf("unsafe name %q", clip(h.Name, 80))
		}
		if h.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("%q is not a regular file", clip(name, 80))
		}
		if h.Size < 0 || h.Size > backupMaxFile {
			return nil, fmt.Errorf("%q too large", clip(name, 80))
		}
		if total += int(h.Size); total > backupMaxTotal {
			return nil, fmt.Errorf("archive content larger than %d bytes", backupMaxTotal)
		}
		if seen[name] {
			return nil, fmt.Errorf("duplicate entry %q", clip(name, 80))
		}
		seen[name] = true
		body, err := io.ReadAll(io.LimitReader(tr, h.Size+1))
		if err != nil || int64(len(body)) != h.Size {
			return nil, fmt.Errorf("%q: truncated", clip(name, 80))
		}
		dir, file := path.Split(name)
		switch {
		case name == "etc/mini-router/router.yaml":
			rs.yaml = body
		case name == "etc/mini-router/secrets.yaml":
			m := map[string]string{}
			if err := yaml.Unmarshal(body, &m); err != nil {
				return nil, fmt.Errorf("secrets.yaml: %v", err)
			}
			for k := range m {
				if k != pwSecretKey && !regexpSecretKey(k) {
					return nil, fmt.Errorf("secrets.yaml: invalid key %q", clip(k, 40))
				}
			}
			rs.secrets = m
		case name == backupManifest:
		case (dir == "etc/mini-router/dns/" || dir == "etc/mini-router/proxy/") && validListName(file):
			live := backupListDirs[strings.TrimSuffix(strings.TrimPrefix(dir, "etc/mini-router/"), "/")]
			if !textOK(body) {
				return nil, fmt.Errorf("%q is not a text file", name)
			}
			rs.lists[filepath.Join(live, file)] = body
		default:
			return nil, fmt.Errorf("unexpected file %q (a backup holds router.yaml, secrets.yaml and dns/proxy list files)", clip(name, 80))
		}
		rs.names = append(rs.names, name)
	}
	if rs.yaml == nil {
		return nil, errors.New("no etc/mini-router/router.yaml in the archive")
	}
	return rs, nil
}

// writeSnapshot saves paths in the core snapshot format (restore() and `mr rollback` read it).
func writeSnapshot(name string, paths []string) error {
	if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
		return err
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, p := range paths {
		st, err := os.Stat(p)
		if err != nil {
			continue // did not exist: restore removes it
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		tw.WriteHeader(&tar.Header{Name: strings.TrimPrefix(p, "/"), Mode: int64(st.Mode().Perm()), Size: int64(len(data)), ModTime: st.ModTime()})
		tw.Write(data)
	}
	list := []byte(strings.Join(paths, "\n") + "\n")
	tw.WriteHeader(&tar.Header{Name: ".mr-paths", Mode: 0600, Size: int64(len(list))})
	tw.Write(list)
	tw.Close()
	gz.Close()
	return writeAtomic(name, buf.Bytes(), 0600)
}

// undoLists puts the list files of a restore back from their snapshot.
func undoLists(snap string) {
	if snap == "" {
		return
	}
	if _, err := restore(filepath.Join(sysHistoryDir, filepath.Base(snap))); err != nil {
		logf("restore: putting the list files back from %s failed: %v", snap, err)
		return
	}
	logf("restore: list files put back from %s", snap)
}

// restoreStage installs the list files of rs (after snapshotting the current ones) and validates +
// renders the candidate config. On success it returns the candidate router.yaml, the merged secrets
// and the list snapshot name ("" if no list file changed). On failure the list files are back as
// they were and errs/err say why.
func restoreStage(rs *restoreSet) (y []byte, sec map[string]string, snap string, errs []string, err error) {
	sec, err = readSecretsFrom(sysSecretsPath)
	if err != nil {
		return nil, nil, "", nil, err
	}
	for k, v := range rs.secrets {
		if k != pwSecretKey {
			sec[k] = v
		}
	}
	var changed []string
	for p, data := range rs.lists {
		if cur, err := os.ReadFile(p); err == nil && bytes.Equal(cur, data) {
			continue
		}
		if fi, err := os.Lstat(filepath.Dir(p)); err == nil && !fi.IsDir() {
			return nil, nil, "", nil, fmt.Errorf("%s is not a directory", filepath.Dir(p))
		}
		if fi, err := os.Lstat(p); err == nil && !fi.Mode().IsRegular() {
			return nil, nil, "", nil, fmt.Errorf("%s exists and is not a regular file", p)
		}
		changed = append(changed, p)
	}
	sort.Strings(changed)
	if len(changed) > 0 {
		snap = time.Now().Format("20060102-150405") + "-restore-lists.tar.gz"
		if err := writeSnapshot(filepath.Join(sysHistoryDir, snap), changed); err != nil {
			return nil, nil, "", nil, fmt.Errorf("snapshot of the list files: %w", err)
		}
		if sysHistoryDir == HistoryDir {
			pruneHistory()
		}
		for _, p := range changed {
			if err := writeAtomic(p, rs.lists[p], 0644); err != nil {
				undoLists(snap)
				return nil, nil, "", nil, err
			}
		}
	}
	fail := func(e error, es []string) ([]byte, map[string]string, string, []string, error) {
		undoLists(snap)
		return nil, nil, "", es, e
	}
	if err := os.MkdirAll(restoreDir, 0700); err != nil {
		return fail(err, nil)
	}
	cy, cs := filepath.Join(restoreDir, "router.yaml"), filepath.Join(restoreDir, "secrets.yaml")
	defer os.Remove(cy)
	defer os.Remove(cs)
	if err := writeAtomic(cy, rs.yaml, 0600); err != nil {
		return fail(err, nil)
	}
	if err := writeSecrets(cs, sec); err != nil {
		return fail(err, nil)
	}
	c, err := loadConfig(cy, cs)
	if err != nil {
		return fail(nil, []string{err.Error()})
	}
	if es := c.Validate(); len(es) > 0 {
		return fail(nil, es)
	}
	if _, err := Render(c); err != nil {
		return fail(nil, []string{err.Error()})
	}
	return rs.yaml, sec, snap, nil, nil
}

// startRestore stages rs and starts the standard apply job for it (like the web UI's apply).
func startRestore(rs *restoreSet, confirmSecs int) (map[string]any, []string, error) {
	if j := readJob(); j.State == "running" {
		return nil, nil, errors.New("another apply is running")
	}
	if err := pendingBlocks(); err != nil { // before the list files are touched
		return nil, nil, err
	}
	y, sec, snap, errs, err := restoreStage(rs)
	if err != nil || len(errs) > 0 {
		return nil, errs, err
	}
	if err := os.MkdirAll(RunDir, 0700); err != nil {
		undoLists(snap)
		return nil, nil, err
	}
	if err := writeAtomic(CandidateYAML, y, 0600); err != nil {
		undoLists(snap)
		return nil, nil, err
	}
	if err := writeSecrets(CandidateSec, sec); err != nil {
		undoLists(snap)
		return nil, nil, err
	}
	writeJob(jobState{State: "running", Started: time.Now().Unix(), Confirm: confirmSecs, Via: "restore"})
	lists := 0
	if snap != "" {
		lists = len(rs.lists)
	}
	appendChangeLog(fmt.Sprintf("restore from backup: router.yaml, secrets: %v, %d list files changed", rs.secrets != nil, lists))
	var logStart int64
	if fi, err := os.Stat(ChangeLog); err == nil {
		logStart = fi.Size()
	}
	self, _ := os.Executable()
	// the core apply job (needs no loadable live config), plus a watcher that puts the list files
	// back if that apply fails or is rolled back later
	startDetached(self, "apply-job", strconv.Itoa(confirmSecs))
	if snap != "" {
		startDetached(self, "sys", "restore-watch", strconv.Itoa(confirmSecs), snap, strconv.FormatInt(logStart, 10))
	}
	return map[string]any{"ok": true, "confirm": confirmSecs, "files": rs.names, "list_snapshot": snap}, nil, nil
}

// sysRestoreWatch is `mr sys restore-watch SECS SNAP LOGOFFSET`: waits for the restore's apply job
// and its confirm window; if the change log (from LOGOFFSET on) shows the apply failed or was
// rolled back (not confirmed in time, or reverted), the list files go back to SNAP.
func sysRestoreWatch(secs int, snap string, logStart int64) error {
	deadline := time.Now().Add(15 * time.Minute)
	for readJob().State == "running" && time.Now().Before(deadline) {
		time.Sleep(time.Second)
	}
	switch readJob().State {
	case "failed":
		undoLists(snap)
		appendChangeLog("restore failed: list files put back from " + snap)
		return nil
	case "ok":
		deadline = time.Now().Add(time.Duration(secs+120) * time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(ConfirmFile); err != nil {
				break
			}
			time.Sleep(2 * time.Second)
		}
	}
	time.Sleep(5 * time.Second) // a rollback writes its change log line when it is done
	f, err := os.Open(ChangeLog)
	if err != nil {
		return nil
	}
	defer f.Close()
	f.Seek(logStart, io.SeekStart)
	tail, _ := io.ReadAll(io.LimitReader(f, 1<<20))
	for _, l := range strings.Split(string(tail), "\n") {
		if strings.Contains(l, "failed and rolled back") || strings.Contains(l, "mr rollback: ") {
			undoLists(snap)
			appendChangeLog("restore rolled back: list files put back from " + snap)
			break
		}
	}
	return nil
}

func apiSysBackup(r apiReq) apiResp {
	if r.method != "POST" {
		return errResp(405, "POST required")
	}
	var in struct {
		Secrets bool `json:"secrets"`
	}
	json.Unmarshal(r.body, &in)
	data, names, err := makeBackup(in.Secrets)
	if err != nil {
		return errResp(500, "%v", err)
	}
	host, _ := os.Hostname()
	if !reHostnameSys.MatchString(host) {
		host = "mini-router"
	}
	if in.Secrets {
		appendChangeLog("webui: backup downloaded (with secrets)")
	}
	return apiResp{body: map[string]any{
		"name": fmt.Sprintf("%s-backup-%s.tar.gz", host, time.Now().Format("20060102-1504")),
		"data": base64.StdEncoding.EncodeToString(data), "size": len(data), "files": names,
		"secrets": in.Secrets, "restorable": len(data) <= backupMaxUpload, "max_upload": backupMaxUpload,
	}}
}

func apiSysRestore(r apiReq) apiResp {
	if r.method != "POST" {
		return errResp(405, "POST required")
	}
	var in struct {
		Data    string `json:"data"`
		Confirm int    `json:"confirm"`
	}
	if err := json.Unmarshal(r.body, &in); err != nil {
		return errResp(400, "bad request")
	}
	if len(in.Data) > backupMaxUpload*4/3+8 {
		return errResp(413, "backup larger than %d bytes", backupMaxUpload)
	}
	raw, err := base64.StdEncoding.DecodeString(in.Data)
	if err != nil {
		return errResp(400, "data: not base64")
	}
	rs, err := parseBackup(raw)
	if err != nil {
		return errResp(400, "%v", err)
	}
	secs := in.Confirm
	if secs <= 0 {
		secs = 120
	}
	if secs < 60 || secs > 600 {
		return errResp(400, "confirm: 60-600 seconds")
	}
	out, errs, err := startRestore(rs, secs)
	if len(errs) > 0 {
		return apiResp{status: 400, body: map[string]any{"error": "restored config is invalid", "errors": errs}}
	}
	if err != nil {
		return errResp(409, "%v", err)
	}
	return apiResp{body: out}
}

// sysBackupCommand: mr sys backup [-secrets] FILE|-  and  mr sys restore [-confirm SECS] FILE
func sysBackupCommand(args []string) error {
	fs := flag.NewFlagSet("backup", flag.ContinueOnError)
	withSec := fs.Bool("secrets", false, "include secrets.yaml (without the web UI password)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: mr sys backup [-secrets] FILE|-")
	}
	data, names, err := makeBackup(*withSec)
	if err != nil {
		return err
	}
	if fs.Arg(0) == "-" {
		_, err = os.Stdout.Write(data)
		return err
	}
	if err := os.WriteFile(fs.Arg(0), data, 0600); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote %s (%d bytes): %s\n", fs.Arg(0), len(data), strings.Join(names, " "))
	return nil
}

func sysRestoreCommand(args []string) error {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	secs := fs.Int("confirm", 120, "seconds to wait for `mr confirm` before rolling back (60-600)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 || *secs < 60 || *secs > 600 {
		return errors.New("usage: mr sys restore [-confirm 60-600] FILE")
	}
	data, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	rs, err := parseBackup(data)
	if err != nil {
		return err
	}
	_, errs, err := startRestore(rs, *secs)
	if len(errs) > 0 {
		return fmt.Errorf("restored config is invalid:\n  %s", strings.Join(errs, "\n  "))
	}
	if err != nil {
		return err
	}
	fmt.Println("restoring: the apply job runs in the background (log: " + JobLog + ")")
	for i := 0; i < 600; i++ {
		time.Sleep(time.Second)
		if j := readJob(); j.State != "running" {
			fmt.Print(j.Output)
			if j.State == "failed" {
				return errors.New("restore failed and was rolled back")
			}
			fmt.Printf("\nrun `mr confirm` within %ds or the restore is rolled back\n", *secs)
			return nil
		}
	}
	return errors.New("apply job still running; see " + JobLog)
}
