package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSpeedtest(t *testing.T) {
	var got int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/__down":
			buf := make([]byte, 64<<10)
			for i := 0; i < 1000; i++ {
				if _, err := w.Write(buf); err != nil {
					return
				}
			}
		case r.Method == "POST" && r.URL.Path == "/__up":
			got, _ = io.Copy(io.Discard, r.Body)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	oURL, oTime, oLock := speedURL, speedTime, speedLock
	t.Cleanup(func() { speedURL, speedTime, speedLock = oURL, oTime, oLock })
	speedURL, speedTime, speedLock = srv.URL, 300*time.Millisecond, filepath.Join(t.TempDir(), "lock")
	res, err := speedTest()
	if err != nil || res.Down <= 0 || res.Up <= 0 || got == 0 {
		t.Fatalf("%+v %v (server got %d bytes)", res, err, got)
	}
	if r := apiSysSpeedtest(apiReq{method: "GET"}); r.status != 405 {
		t.Errorf("GET: %d", r.status)
	}
	speedURL = srv.URL + "/nope"
	if _, err := speedTest(); err == nil || !strings.Contains(err.Error(), "HTTP 404") {
		t.Errorf("404: %v", err)
	}
}
