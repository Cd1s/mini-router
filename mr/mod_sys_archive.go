package main

// sys module: off-site copies of router.yaml (notify.archive, Cd1s/mini-router#20). After a change is
// accepted a detached `mr notify archive` sends router.yaml (never secrets.yaml) to one target:
//
//	https  (default) POST / PUT to a URL from secrets.yaml, optional bearer token
//	webdav PUT with Basic auth into a folder (坚果云, Nextcloud, a NAS)
//	s3     PUT object signed with AWS Signature V4 (R2, OSS, MinIO, B2, AWS)
//	github contents API PUT (current sha first, base64 content)
//
// Every credential is a *_secret name. Verified TLS, no redirects (ddnsHTTP), answers capped, errors
// without URLs or secrets. The last result is kept in archiveStateFile (web UI: 备份与升级 › 异地备份).

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

// NotifyArchive is router.yaml notify.archive.
type NotifyArchive struct {
	Type     string `yaml:"type,omitempty"`            // https (default) | webdav | s3 | github
	URL      string `yaml:"url_secret,omitempty"`      // https: secrets.yaml key of the https:// URL
	Token    string `yaml:"token_secret,omitempty"`    // https: bearer token (optional); github: the token
	Method   string `yaml:"method,omitempty"`          // https: post (default) | put
	Endpoint string `yaml:"url,omitempty"`             // webdav: folder URL; s3: endpoint (https://)
	User     string `yaml:"user,omitempty"`            // webdav
	Password string `yaml:"password_secret,omitempty"` // webdav
	Name     string `yaml:"name,omitempty"`            // webdav, s3: fixed file name ("" = router-YYYYMMDD-HHMMSS.yaml)
	Region   string `yaml:"region,omitempty"`          // s3 (R2: auto)
	Bucket   string `yaml:"bucket,omitempty"`          // s3: path style; "" = the endpoint is the bucket's host
	Prefix   string `yaml:"prefix,omitempty"`          // s3: key prefix (backups/)
	KeyID    string `yaml:"access_key_id,omitempty"`   // s3
	Secret   string `yaml:"secret_key_secret,omitempty"`
	Repo     string `yaml:"repo,omitempty"`   // github: owner/name
	Branch   string `yaml:"branch,omitempty"` // github: "" = the default branch
	Path     string `yaml:"path,omitempty"`   // github: file in the repo (default router.yaml)
}

var (
	archiveStateFile = "/etc/mini-router/state/archive.json"
	archiveGitHubAPI = "https://api.github.com"
	reArchName       = lazyRegexp(`^[A-Za-z0-9_-][A-Za-z0-9._-]{0,99}$`)
	reArchPath       = lazyRegexp(`^[A-Za-z0-9_-][A-Za-z0-9._-]{0,99}(/[A-Za-z0-9_-][A-Za-z0-9._-]{0,99}){0,9}$`)
	reArchRepo       = lazyRegexp(`^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$`)
	reArchBucket     = lazyRegexp(`^[a-z0-9][a-z0-9.-]{1,62}$`)
	reArchRegion     = lazyRegexp(`^[a-z0-9-]{1,40}$`)
	reArchKeyID      = lazyRegexp(`^[A-Za-z0-9]{8,128}$`)
	reArchUser       = lazyRegexp(`^[^:\s"'\\]{1,128}$`)
)

// archiveEndpointOK: an https:// URL without credentials, query or fragment.
func archiveEndpointOK(s string) bool {
	u, err := url.Parse(s)
	return err == nil && notifyURLProblem(s) == "" && u.Scheme == "https" && u.User == nil && u.RawQuery == "" && u.Fragment == "" && !strings.Contains(s, "..")
}

func validateArchive(c *Config, v *Validator) {
	a := c.Notify.Archive
	if a == nil {
		return
	}
	bad := func(key, want string, x string) { v.Add("notify.archive.%s: %s, got %q", key, want, x) }
	secret := func(key, name string, ok func(string) bool, what string) {
		if !reDDNSSecret.MatchString(name) {
			bad(key, "secret name [a-z0-9_-]{1,40} required", name)
		} else if val, err := c.Secret(name); err != nil {
			v.Add("notify.archive.%s: %v", key, err)
		} else if !ok(val) {
			v.Add("notify.archive.%s: the secret is not %s", key, what)
		}
	}
	token := func(s string) bool { return s != "" && len(s) <= 4096 && safeText(s) && !strings.ContainsAny(s, " \t") }
	if a.Name != "" && !reArchName.MatchString(a.Name) {
		bad("name", "a file name [A-Za-z0-9._-]", a.Name)
	}
	switch a.Type {
	case "", "https":
		secret("url_secret", a.URL, func(s string) bool { return notifyURLProblem(s) == "" && strings.HasPrefix(s, "https://") }, "an https:// URL")
		if a.Token != "" {
			secret("token_secret", a.Token, token, "a single-line token")
		}
		if a.Method != "" && a.Method != "post" && a.Method != "put" {
			bad("method", "post | put", a.Method)
		}
	case "webdav":
		if !archiveEndpointOK(a.Endpoint) {
			bad("url", "https:// folder URL (no credentials, no query)", a.Endpoint)
		}
		if !reArchUser.MatchString(a.User) {
			bad("user", "the account name (no ':' or spaces)", a.User)
		}
		secret("password_secret", a.Password, token, "a single-line password")
	case "s3":
		if u, err := url.Parse(a.Endpoint); !archiveEndpointOK(a.Endpoint) || err != nil || strings.Trim(u.Path, "/") != "" {
			bad("url", "https:// endpoint without a path", a.Endpoint)
		}
		if !reArchRegion.MatchString(a.Region) {
			bad("region", "[a-z0-9-] (R2: auto)", a.Region)
		}
		if a.Bucket != "" && !reArchBucket.MatchString(a.Bucket) {
			bad("bucket", "a bucket name [a-z0-9.-]", a.Bucket)
		}
		if a.Prefix != "" && (!reArchPath.MatchString(strings.TrimSuffix(a.Prefix, "/")) || strings.Contains(a.Prefix, "..")) {
			bad("prefix", "a key prefix like backups/", a.Prefix)
		}
		if !reArchKeyID.MatchString(a.KeyID) {
			bad("access_key_id", "8-128 letters / digits", a.KeyID)
		}
		secret("secret_key_secret", a.Secret, token, "a single-line key")
	case "github":
		if !reArchRepo.MatchString(a.Repo) {
			bad("repo", "owner/name", a.Repo)
		}
		if a.Branch != "" && (!reArchPath.MatchString(a.Branch) || strings.Contains(a.Branch, "..")) {
			bad("branch", "a branch name", a.Branch)
		}
		if a.Path != "" && (!reArchPath.MatchString(a.Path) || strings.Contains(a.Path, "..")) {
			bad("path", "a file path in the repo", a.Path)
		}
		secret("token_secret", a.Token, token, "a single-line token")
	default:
		bad("type", "https | webdav | s3 | github", a.Type)
	}
}

// archiveFile: the file name webdav / s3 write.
func archiveFile(a *NotifyArchive, t time.Time) string {
	if a.Name != "" {
		return a.Name
	}
	return "router-" + t.Format("20060102-150405") + ".yaml"
}

// archiveDo sends one request; the answer (capped) and the status come back.
func archiveDo(ctx context.Context, hc *http.Client, method, u string, hdr map[string]string, body []byte) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(body))
	if err != nil {
		return 0, nil, errors.New("bad request")
	}
	req.Header.Set("User-Agent", "mini-router/"+version)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, notifyMaxBody))
	return resp.StatusCode, raw, nil
}

// sigV4 returns the Authorization header of an AWS Signature V4 request. hdr: the signed headers,
// lower-case names (host, x-amz-date, x-amz-content-sha256, …); path unescaped, query canonical.
func sigV4(method, path, query string, hdr map[string]string, payload, region, service, keyID, secret string, t time.Time) string {
	names := make([]string, 0, len(hdr))
	for k := range hdr {
		names = append(names, k)
	}
	sort.Strings(names)
	var ch strings.Builder
	for _, n := range names {
		ch.WriteString(n + ":" + strings.TrimSpace(hdr[n]) + "\n")
	}
	seg := strings.Split(path, "/")
	for i := range seg {
		seg[i] = rfc3986(seg[i])
	}
	signed := strings.Join(names, ";")
	canon := method + "\n" + strings.Join(seg, "/") + "\n" + query + "\n" + ch.String() + "\n" + signed + "\n" + payload
	day := t.UTC().Format("20060102")
	scope := day + "/" + region + "/" + service + "/aws4_request"
	sts := "AWS4-HMAC-SHA256\n" + t.UTC().Format("20060102T150405Z") + "\n" + scope + "\n" + hexSHA256([]byte(canon))
	k := []byte("AWS4" + secret)
	for _, x := range []string{day, region, service, "aws4_request"} {
		k = hmacSHA256(k, x)
	}
	return "AWS4-HMAC-SHA256 Credential=" + keyID + "/" + scope + ",SignedHeaders=" + signed + ",Signature=" + hex.EncodeToString(hmacSHA256(k, sts))
}

// archiveSend sends router.yaml (as it is on flash) to the archive target.
func archiveSend(c *Config, hc *http.Client) error {
	a := c.Notify.Archive
	if a == nil {
		return nil
	}
	sec := func(key, name string) (string, error) {
		s, err := c.Secret(name)
		if err != nil || s == "" {
			return "", errors.New(key + ": not set")
		}
		return s, nil
	}
	data, err := os.ReadFile(sysConfigPath)
	if err != nil {
		return errors.New("cannot read router.yaml")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	now := time.Now()
	hdr := map[string]string{"Content-Type": "application/yaml"}
	var code int
	switch a.Type {
	case "webdav":
		pw, err := sec("password_secret", a.Password)
		if err != nil {
			return err
		}
		hdr["Authorization"] = "Basic " + base64.StdEncoding.EncodeToString([]byte(a.User+":"+pw))
		code, _, err = archiveDo(ctx, hc, "PUT", strings.TrimRight(a.Endpoint, "/")+"/"+archiveFile(a, now), hdr, data)
		if err != nil {
			return notifyErr(err, pw, a.Endpoint)
		}
	case "s3":
		key, err := sec("secret_key_secret", a.Secret)
		if err != nil {
			return err
		}
		u, _ := url.Parse(a.Endpoint)
		path := "/" + a.Prefix + archiveFile(a, now)
		if a.Bucket != "" {
			path = "/" + a.Bucket + path
		}
		sum := hexSHA256(data)
		sig := map[string]string{"host": u.Host, "x-amz-content-sha256": sum, "x-amz-date": now.UTC().Format("20060102T150405Z")}
		auth := sigV4("PUT", path, "", sig, sum, a.Region, "s3", a.KeyID, key, now)
		h := map[string]string{"Content-Type": "application/yaml", "Authorization": auth, "x-amz-content-sha256": sum, "x-amz-date": sig["x-amz-date"]}
		code, _, err = archiveDo(ctx, hc, "PUT", "https://"+u.Host+path, h, data)
		if err != nil {
			return notifyErr(err, key)
		}
	case "github":
		tok, err := sec("token_secret", a.Token)
		if err != nil {
			return err
		}
		p := a.Path
		if p == "" {
			p = "router.yaml"
		}
		u := archiveGitHubAPI + "/repos/" + a.Repo + "/contents/" + p
		h := map[string]string{"Authorization": "Bearer " + tok, "Accept": "application/vnd.github+json"}
		q := ""
		if a.Branch != "" {
			q = "?ref=" + url.QueryEscape(a.Branch)
		}
		code, raw, err := archiveDo(ctx, hc, "GET", u+q, h, nil)
		if err != nil {
			return notifyErr(err, tok)
		}
		var cur struct {
			SHA string `json:"sha"`
		}
		if code == 200 {
			json.Unmarshal(raw, &cur)
		} else if code != 404 {
			return fmt.Errorf("GitHub: HTTP %d", code)
		}
		put := map[string]string{"message": "router.yaml from " + c.System.Hostname, "content": base64.StdEncoding.EncodeToString(data)}
		if cur.SHA != "" {
			put["sha"] = cur.SHA
		}
		if a.Branch != "" {
			put["branch"] = a.Branch
		}
		body, _ := json.Marshal(put)
		h["Content-Type"] = "application/json"
		if code, _, err = archiveDo(ctx, hc, "PUT", u, h, body); err != nil {
			return notifyErr(err, tok)
		}
		if code/100 != 2 {
			return fmt.Errorf("GitHub: HTTP %d", code)
		}
		return nil
	default:
		u, err := c.Secret(a.URL)
		if err != nil || notifyURLProblem(u) != "" || !strings.HasPrefix(u, "https://") {
			return errors.New("url_secret: not an https:// URL")
		}
		tok := ""
		if a.Token != "" {
			if tok, err = sec("token_secret", a.Token); err != nil {
				return err
			}
			hdr["Authorization"] = "Bearer " + tok
		}
		method := "POST"
		if a.Method == "put" {
			method = "PUT"
		}
		if code, _, err = archiveDo(ctx, hc, method, u, hdr, data); err != nil {
			return notifyErr(err, u, tok)
		}
	}
	if code/100 != 2 {
		return fmt.Errorf("HTTP %d", code)
	}
	return nil
}

type archiveState struct {
	Time  int64  `json:"time"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

func archiveRun(c *Config, hc *http.Client) error {
	if c.Notify.Archive == nil {
		return nil
	}
	err := archiveSend(c, hc)
	st := archiveState{Time: time.Now().Unix(), OK: err == nil}
	if err != nil {
		st.Error = err.Error()
		eventAdd(c, "archive", "warn", "", "router.yaml was not archived: "+st.Error, true)
	} else {
		logf("archive: router.yaml sent")
	}
	b, _ := json.Marshal(st)
	writeAtomic(archiveStateFile, b, 0600)
	return err
}

// apiSysArchiveTest: GET → the last result; POST → send router.yaml now (the applied config) and
// return the result. Session only (no TokenScope).
func apiSysArchiveTest(r apiReq) apiResp {
	var st archiveState
	if r.method != "POST" {
		readJSONFile(archiveStateFile, &st)
		return apiResp{body: st}
	}
	c, err := loadConfig(sysConfigPath, sysSecretsPath)
	if err != nil {
		return errResp(500, "%v", err)
	}
	if c.Notify.Archive == nil {
		return errResp(409, "no notify.archive (save and apply the settings first)")
	}
	archiveRun(c, ddnsHTTP())
	readJSONFile(archiveStateFile, &st)
	return apiResp{body: st}
}
