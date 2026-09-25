package main

// Web UI login throttling (Cd1s/mini-router#22). Every API request is its own CGI process, so the
// state is a file under /run shared by all of them and changed under flock. Each attempt is counted
// before the password is checked — parallel requests cannot slip through while earlier ones are
// still hashing. The 5th consecutive failure locks the source for 30 s, doubling with every further
// lock up to an hour; a locked source gets 429 at once, without a password check (no PBKDF2 work).
// A correct password clears the source; other sources are not affected. IPv6 sources count per /64
// (a host can use any address of its prefix).

import (
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"time"
)

var (
	loginFile  = RunDir + "/login.json"
	loginClock = time.Now
)

const (
	loginMax     = 5                // consecutive failures before a lock
	loginBase    = 30 * time.Second // first lock; doubled for each lock in a row
	loginMaxLock = time.Hour
	loginForget  = 15 * time.Minute // failures further apart than this start a new count
	loginSources = 1024             // records kept (oldest dropped)
)

type loginRec struct {
	Fails int   `json:"fails"` // attempts since the last success or lock (counted before the check)
	Until int64 `json:"until"` // locked until (unix time)
	Locks int   `json:"locks"` // locks in a row: the next lasts loginBase << locks
	Seen  int64 `json:"seen"`  // last attempt
}

// loginKey: the source an attempt counts against.
func loginKey(remote string) string {
	ip := net.ParseIP(remote)
	switch {
	case ip == nil:
		return "unknown"
	case ip.To4() != nil:
		return ip.To4().String()
	}
	m := net.CIDRMask(64, 128)
	return (&net.IPNet{IP: ip.Mask(m), Mask: m}).String()
}

// loginUpdate changes key's record under an exclusive lock of the shared file.
func loginUpdate(key string, f func(r *loginRec, now int64)) error {
	if err := os.MkdirAll(filepath.Dir(loginFile), 0700); err != nil {
		return err
	}
	fd, err := os.OpenFile(loginFile, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer fd.Close()
	if err := syscall.Flock(int(fd.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	b, _ := io.ReadAll(fd)
	m := map[string]*loginRec{}
	json.Unmarshal(b, &m)
	now := loginClock().Unix()
	r := m[key]
	if r == nil {
		r = &loginRec{}
		m[key] = r
	}
	f(r, now)
	if *r == (loginRec{}) {
		delete(m, key)
	}
	for k, x := range m { // forget sources idle for a day
		if now-x.Seen > 86400 && x.Until < now {
			delete(m, k)
		}
	}
	if len(m) > loginSources {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return m[keys[i]].Seen < m[keys[j]].Seen })
		for _, k := range keys[:len(m)-loginSources] {
			delete(m, k)
		}
	}
	out, _ := json.Marshal(m)
	if err := fd.Truncate(0); err != nil {
		return err
	}
	_, err = fd.WriteAt(out, 0)
	return err
}

// loginBegin counts an attempt from remote. ok: go on and check the password; else the source is
// locked for wait more seconds. fails: attempts in the current series; locked: the lock this attempt
// starts if it fails (for the log).
func loginBegin(remote string) (ok bool, wait int64, fails int, locked time.Duration) {
	err := loginUpdate(loginKey(remote), func(r *loginRec, now int64) {
		if now < r.Until {
			wait = r.Until - now
			return
		}
		if now-r.Seen > int64(loginForget/time.Second) {
			r.Fails = 0
		}
		if r.Until != 0 && now-r.Until > int64(loginMaxLock/time.Second) {
			r.Locks = 0 // quiet for longer than the longest lock: start over
		}
		ok = true
		r.Seen = now
		r.Fails++
		fails = r.Fails
		if r.Fails >= loginMax {
			d := loginBase << r.Locks
			if d > loginMaxLock || d <= 0 {
				d = loginMaxLock
			}
			r.Until, r.Fails = now+int64(d/time.Second), 0
			r.Locks++
			locked = d
		}
	})
	if err != nil { // /run unusable: no shared state, fall back to slowing this request down
		logf("webui: login throttle: %v", err)
		time.Sleep(1500 * time.Millisecond)
		return true, 0, 1, 0
	}
	return ok, wait, fails, locked
}

// loginSucceeded clears remote's record.
func loginSucceeded(remote string) {
	loginUpdate(loginKey(remote), func(r *loginRec, now int64) { *r = loginRec{} })
}

// checkPasswordFrom checks pw for a request from remote under the throttle: nil when it matches,
// else 429 while the source is locked (no password check) or 401 with msg. Logged once per series
// and when a lock starts.
func checkPasswordFrom(remote, stored, pw, msg string) *apiResp {
	ok, wait, fails, locked := loginBegin(remote)
	if !ok {
		r := errResp(429, "too many failed attempts from this address: try again in %d s", wait)
		return &r
	}
	if checkPassword(stored, pw) {
		loginSucceeded(remote)
		return nil
	}
	switch {
	case locked > 0:
		logf("webui: %d failed logins from %s: locked for %s", loginMax, remote, locked)
		eventLoginLock(remote, "web UI logins", locked)
	case fails == 1:
		logf("webui: failed login from %s", remote)
	}
	r := errResp(401, "%s", msg)
	return &r
}
