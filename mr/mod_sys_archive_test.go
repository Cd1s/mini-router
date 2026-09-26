package main

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The two S3 examples of the AWS Signature V4 documentation (GET object, PUT object).
func TestSigV4Vector(t *testing.T) {
	tm := time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC)
	key, id := "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "AKIAIOSFODNN7EXAMPLE"
	e := hexSHA256(nil)
	got := sigV4("GET", "/test.txt", "", map[string]string{"host": "examplebucket.s3.amazonaws.com", "range": "bytes=0-9",
		"x-amz-content-sha256": e, "x-amz-date": "20130524T000000Z"}, e, "us-east-1", "s3", id, key, tm)
	want := "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
	if got != want {
		t.Errorf("GET:\n%s\n%s", got, want)
	}
	b := hexSHA256([]byte("Welcome to Amazon S3."))
	got = sigV4("PUT", "/test$file.text", "", map[string]string{"date": "Fri, 24 May 2013 00:00:00 GMT", "host": "examplebucket.s3.amazonaws.com",
		"x-amz-content-sha256": b, "x-amz-date": "20130524T000000Z", "x-amz-storage-class": "REDUCED_REDUNDANCY"}, b, "us-east-1", "s3", id, key, tm)
	if !strings.HasSuffix(got, "Signature=98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd") {
		t.Errorf("PUT: %s", got)
	}
}

func TestArchiveTargets(t *testing.T) {
	eventEnv(t)
	type hit struct{ method, path, auth, body string }
	var hits []hit
	code := 201
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		hits = append(hits, hit{r.Method, r.URL.RequestURI(), r.Header.Get("Authorization"), string(b)})
		if r.Method == "GET" {
			w.Write([]byte(`{"sha":"abc123"}`))
			return
		}
		w.WriteHeader(code)
	}))
	defer srv.Close()
	d := t.TempDir()
	oc, og, os_ := sysConfigPath, archiveGitHubAPI, archiveStateFile
	t.Cleanup(func() { sysConfigPath, archiveGitHubAPI, archiveStateFile = oc, og, os_ })
	sysConfigPath, archiveGitHubAPI, archiveStateFile = filepath.Join(d, "router.yaml"), srv.URL, filepath.Join(d, "archive.json")
	os.WriteFile(sysConfigPath, []byte("system:\n  hostname: r1\n"), 0600)
	c := testConfig(t)
	c.secrets["dav_pw"], c.secrets["s3_key"], c.secrets["gh_tok"] = "pw-s3cr3t", "key-s3cr3t", "ghp_s3cr3t"
	for _, x := range []struct {
		a    NotifyArchive
		want []string // method path, per request
	}{
		{NotifyArchive{Type: "webdav", Endpoint: srv.URL + "/dav/mr/", User: "me@example.com", Password: "dav_pw", Name: "router.yaml"}, []string{"PUT /dav/mr/router.yaml"}},
		{NotifyArchive{Type: "s3", Endpoint: srv.URL, Region: "auto", Bucket: "bk", Prefix: "backups/", KeyID: "AKIDEXAMPLE1", Secret: "s3_key", Name: "r.yaml"}, []string{"PUT /bk/backups/r.yaml"}},
		{NotifyArchive{Type: "github", Repo: "me/cfg", Branch: "main", Path: "home/router.yaml", Token: "gh_tok"}, []string{"GET /repos/me/cfg/contents/home/router.yaml?ref=main", "PUT /repos/me/cfg/contents/home/router.yaml"}},
	} {
		hits, code = nil, 201
		a := x.a
		c.Notify.Archive = &a
		mustValid(t, c)
		if err := archiveSend(c, srv.Client()); err != nil || len(hits) != len(x.want) {
			t.Fatalf("%s: %v %+v", a.Type, err, hits)
		}
		for i, w := range x.want {
			if hits[i].method+" "+hits[i].path != w {
				t.Errorf("%s: request %d %s %s, want %s", a.Type, i, hits[i].method, hits[i].path, w)
			}
		}
		last := hits[len(hits)-1]
		switch a.Type {
		case "webdav":
			if last.auth != "Basic "+base64.StdEncoding.EncodeToString([]byte("me@example.com:pw-s3cr3t")) || last.body != "system:\n  hostname: r1\n" {
				t.Errorf("webdav: %+v", last)
			}
		case "s3":
			if !strings.HasPrefix(last.auth, "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE1/") || !strings.Contains(last.auth, "/auto/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,") {
				t.Errorf("s3: %s", last.auth)
			}
		case "github":
			var p map[string]string
			json.Unmarshal([]byte(last.body), &p)
			if last.auth != "Bearer ghp_s3cr3t" || p["sha"] != "abc123" || p["branch"] != "main" || p["content"] != base64.StdEncoding.EncodeToString([]byte("system:\n  hostname: r1\n")) {
				t.Errorf("github: %+v", last)
			}
		}
		code = 401
		if err := archiveRun(c, srv.Client()); err == nil || strings.Contains(err.Error(), "s3cr3t") || strings.Contains(err.Error(), "127.0.0.1") {
			t.Errorf("%s failure: %v", a.Type, err)
		}
	}
	var st archiveState
	if readJSONFile(archiveStateFile, &st); st.OK || st.Error == "" {
		t.Errorf("state: %+v", st)
	}
	// dated names, strict validation
	if n := archiveFile(&NotifyArchive{}, time.Date(2026, 9, 26, 8, 5, 3, 0, time.UTC)); n != "router-20260926-080503.yaml" {
		t.Errorf("name %s", n)
	}
	c.Notify.Archive = &NotifyArchive{Type: "webdav", Endpoint: "http://192.0.2.1/dav", User: "a:b", Password: "nope", Name: "../x"}
	errs := strings.Join(c.Validate(), "\n")
	c.Notify.Archive = &NotifyArchive{Type: "s3", Endpoint: "https://198.51.100.1/path?x=1", Region: "US", Prefix: "../", KeyID: "k", Secret: "s3_key"}
	errs += strings.Join(c.Validate(), "\n")
	c.Notify.Archive = &NotifyArchive{Type: "github", Repo: "x", Path: "a/../b", Token: "gh_tok"}
	errs += strings.Join(c.Validate(), "\n")
	for _, s := range []string{"archive.url", "archive.user", "archive.password_secret", "archive.name", "archive.region", "archive.prefix", "archive.access_key_id", "archive.repo", "archive.path"} {
		if !strings.Contains(errs, s+":") {
			t.Errorf("missing %s in\n%s", s, errs)
		}
	}
}
