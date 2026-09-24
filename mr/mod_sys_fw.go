package main

// sys module: firmware upgrade and factory reset (web UI). The platform ships the scripts that do
// the real work:
//
//	/usr/libexec/mr/sysupgrade IMAGE   checks and flashes IMAGE (a file in /tmp) and reboots;
//	                                   exit code != 0 = refused, reason on stderr
//	/usr/libexec/mr/factory-reset      wipes the configuration and reboots
//
// When a script is missing the web UI shows "当前构建不支持". The image is uploaded in chunks
// (the API body limit is 4 MiB): each POST carries {offset, total, data (base64)} and must continue
// exactly where the file ends, so a lost response can be resumed; the final call carries the
// SHA-256 the browser computed and the flash starts only if it matches the file in /tmp.
// Scripts run detached; their output and exit code land in /run/mini-router for the UI to poll.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Paths (variables so tests can use a temp dir).
var (
	fwSysupgrade   = "/usr/libexec/mr/sysupgrade"
	fwFactoryReset = "/usr/libexec/mr/factory-reset"
	fwDir          = "/tmp/mr-upgrade" // root-only (0700): /tmp is world-writable, no symlink games in here
	fwRunDir       = RunDir
)

func fwImage() string       { return fwDir + "/firmware.img" }
func fwUploadState() string { return fwDir + "/upload.json" }

// fwPrepareDir makes sure fwDir is a directory only root can write: anything else at that path
// (a file, a symlink, a directory someone else created) is removed first.
func fwPrepareDir() error {
	if fi, err := os.Lstat(fwDir); err == nil {
		st, ok := fi.Sys().(*syscall.Stat_t)
		if fi.IsDir() && fi.Mode().Perm() == 0700 && ok && int(st.Uid) == os.Getuid() {
			return nil
		}
		if err := os.RemoveAll(fwDir); err != nil {
			return err
		}
	}
	return os.Mkdir(fwDir, 0700)
}

const (
	fwMaxImage = 128 << 20
	fwMaxChunk = 2 << 20
)

type fwUpload struct {
	Total int64 `json:"total"`
}

func fwUploadInfo() (fwUpload, int64, bool) {
	var u fwUpload
	b, err := os.ReadFile(fwUploadState())
	if err != nil || json.Unmarshal(b, &u) != nil || u.Total <= 0 {
		return u, 0, false
	}
	fi, err := os.Stat(fwImage())
	if err != nil {
		return u, 0, true
	}
	return u, fi.Size(), true
}

func fileExists(p string) bool { fi, err := os.Stat(p); return err == nil && !fi.IsDir() }

func tmpFree() int64 {
	var s syscall.Statfs_t
	if syscall.Statfs("/tmp", &s) != nil {
		return 0
	}
	return int64(s.Bavail) * int64(s.Bsize)
}

// fwRunStatus: state of the last detached script run: "" (none), running, failed, done.
func fwRunStatus() map[string]any {
	b, err := os.ReadFile(fwRunDir + "/fw-run.json")
	if err != nil {
		return map[string]any{"state": ""}
	}
	st := map[string]any{}
	json.Unmarshal(b, &st)
	st["state"] = "running"
	if started, _ := st["started"].(float64); time.Since(time.Unix(int64(started), 0)) > time.Hour {
		st["state"] = "stale" // killed without a result (a reboot clears /run anyway)
	}
	if rc, err := os.ReadFile(fwRunDir + "/fw-run.rc"); err == nil {
		n, _ := strconv.Atoi(strings.TrimSpace(string(rc)))
		st["rc"] = n
		st["state"] = "failed"
		if n == 0 {
			st["state"] = "done"
		}
	}
	if out, err := os.ReadFile(fwRunDir + "/fw-run.log"); err == nil {
		if len(out) > 4096 {
			out = out[len(out)-4096:]
		}
		st["message"] = string(out)
	}
	return st
}

func apiSysFw(r apiReq) apiResp {
	body := map[string]any{
		"sysupgrade": fileExists(fwSysupgrade), "factory_reset": fileExists(fwFactoryReset),
		"tmp_free": tmpFree(), "max_image": fwMaxImage, "max_chunk": fwMaxChunk, "run": fwRunStatus(),
	}
	if u, got, ok := fwUploadInfo(); ok {
		body["upload"] = map[string]any{"total": u.Total, "received": got}
	}
	return apiResp{body: body}
}

func fwRunning() bool { return fwRunStatus()["state"] == "running" }

// apiSysFwUpload: POST {offset, total, data} appends one chunk; POST {cancel: true} drops the upload.
func apiSysFwUpload(r apiReq) apiResp {
	if r.method != "POST" {
		return errResp(405, "POST required")
	}
	var in struct {
		Offset int64  `json:"offset"`
		Total  int64  `json:"total"`
		Data   string `json:"data"`
		Cancel bool   `json:"cancel"`
	}
	if err := json.Unmarshal(r.body, &in); err != nil {
		return errResp(400, "bad request")
	}
	if fwRunning() {
		return errResp(409, "an upgrade / reset is running")
	}
	if in.Cancel {
		os.RemoveAll(fwDir)
		return apiResp{body: map[string]any{"ok": true}}
	}
	if !fileExists(fwSysupgrade) {
		return errResp(501, "firmware upgrade is not supported by this build")
	}
	if in.Total <= 0 || in.Total > fwMaxImage {
		return errResp(400, "total: 1-%d bytes", fwMaxImage)
	}
	data, err := base64.StdEncoding.DecodeString(in.Data)
	if err != nil || len(data) == 0 || len(data) > fwMaxChunk {
		return errResp(400, "data: base64, 1-%d bytes per chunk", fwMaxChunk)
	}
	if in.Offset < 0 || in.Offset+int64(len(data)) > in.Total {
		return errResp(400, "chunk outside the image")
	}
	if in.Offset == 0 {
		os.RemoveAll(fwDir)
		if err := fwPrepareDir(); err != nil {
			return errResp(500, "%v", err)
		}
		if free := tmpFree(); free < in.Total+(8<<20) {
			return errResp(507, "not enough space in /tmp: %d MiB free, %d MiB needed", free>>20, (in.Total+(8<<20))>>20)
		}
		b, _ := json.Marshal(fwUpload{Total: in.Total})
		if err := writeAtomic(fwUploadState(), b, 0600); err != nil {
			return errResp(500, "%v", err)
		}
	}
	if err := fwPrepareDir(); err != nil {
		return errResp(500, "%v", err)
	}
	u, got, ok := fwUploadInfo()
	if !ok || u.Total != in.Total {
		return errResp(409, "no upload in progress for this image; start again at offset 0")
	}
	if got != in.Offset {
		return apiResp{status: 409, body: map[string]any{"error": "offset does not continue the upload", "received": got}}
	}
	f, err := os.OpenFile(fwImage(), os.O_WRONLY|os.O_CREATE|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return errResp(500, "%v", err)
	}
	_, err = f.WriteAt(data, in.Offset)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return errResp(500, "write: %v", err)
	}
	return apiResp{body: map[string]any{"received": in.Offset + int64(len(data)), "total": in.Total}}
}

func fileSHA256(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// fwStart runs a platform script detached. The shell text is constant (no request data in it):
// the scripts must also run when router.yaml does not load, so `mr` is not in this path.
func fwStart(what, script string, args ...string) error {
	os.MkdirAll(fwRunDir, 0700)
	for _, f := range []string{"fw-run.rc", "fw-run.log"} {
		os.Remove(fwRunDir + "/" + f)
	}
	b, _ := json.Marshal(map[string]any{"what": what, "started": time.Now().Unix()})
	if err := writeAtomic(fwRunDir+"/fw-run.json", b, 0600); err != nil {
		return err
	}
	// "$0" "$@" are the script and its arguments (argv, never parsed as shell text)
	cmd := `"$0" "$@" >` + fwRunDir + `/fw-run.log 2>&1; echo $? >` + fwRunDir + `/fw-run.rc`
	startDetached("/bin/sh", append([]string{"-c", cmd, script}, args...)...)
	return nil
}

// apiSysFwUpgrade: POST {sha256}: verify the uploaded image and hand it to the platform script.
func apiSysFwUpgrade(r apiReq) apiResp {
	if r.method != "POST" {
		return errResp(405, "POST required")
	}
	var in struct {
		SHA256 string `json:"sha256"`
	}
	json.Unmarshal(r.body, &in)
	if !fileExists(fwSysupgrade) {
		return errResp(501, "firmware upgrade is not supported by this build")
	}
	if fwRunning() {
		return errResp(409, "an upgrade / reset is running")
	}
	u, got, ok := fwUploadInfo()
	if !ok || got != u.Total {
		return errResp(409, "upload incomplete (%d of %d bytes)", got, u.Total)
	}
	sum, err := fileSHA256(fwImage())
	if err != nil {
		return errResp(500, "%v", err)
	}
	if want := strings.ToLower(strings.TrimSpace(in.SHA256)); len(want) != 64 || want != sum {
		return apiResp{status: 400, body: map[string]any{"error": "SHA-256 mismatch: the uploaded image is not the file you selected", "sha256": sum}}
	}
	appendChangeLog("webui: firmware upgrade started (sha256 " + sum[:16] + "…)")
	logf("webui: firmware upgrade, image sha256 %s", sum)
	if err := fwStart("sysupgrade", fwSysupgrade, fwImage()); err != nil {
		return errResp(500, "%v", err)
	}
	return apiResp{body: map[string]any{"ok": true, "sha256": sum}}
}

// apiSysFactoryReset: POST {confirm: "RESET"}.
func apiSysFactoryReset(r apiReq) apiResp {
	if r.method != "POST" {
		return errResp(405, "POST required")
	}
	var in struct {
		Confirm string `json:"confirm"`
	}
	json.Unmarshal(r.body, &in)
	if in.Confirm != "RESET" {
		return errResp(400, `confirm must be "RESET"`)
	}
	if !fileExists(fwFactoryReset) {
		return errResp(501, "factory reset is not supported by this build")
	}
	if fwRunning() {
		return errResp(409, "an upgrade / reset is running")
	}
	appendChangeLog("webui: factory reset")
	logf("webui: factory reset")
	if err := fwStart("factory-reset", fwFactoryReset); err != nil {
		return errResp(500, "%v", err)
	}
	return apiResp{body: map[string]any{"ok": true}}
}
