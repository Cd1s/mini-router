package main

import (
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"
)

// loginEnv: throttle state in a temp dir, a clock the test moves, and a stored password.
func loginEnv(t *testing.T) (secrets map[string]string, advance func(time.Duration)) {
	t.Helper()
	oldF, oldC := loginFile, loginClock
	t.Cleanup(func() { loginFile, loginClock = oldF, oldC })
	loginFile = filepath.Join(t.TempDir(), "login.json")
	now := time.Unix(1790000000, 0)
	var mu sync.Mutex
	loginClock = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	advance = func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
	return map[string]string{pwSecretKey: hashPassword("correct horse")}, advance
}

func login(sec map[string]string, remote, pw string) int {
	r := apiLogin(apiReq{method: "POST", remote: remote, body: []byte(`{"password":` + strconv.Quote(pw) + `}`)}, sec)
	if r.status == 0 {
		return 200
	}
	return r.status
}

// 20 wrong passwords at once from one address: 5 are checked, the rest refused without a check and
// the address is locked; another address is not affected; the lock expires; locks double
// (Cd1s/mini-router#22).
func TestLoginThrottleConcurrent(t *testing.T) {
	sec, advance := loginEnv(t)
	var wg sync.WaitGroup
	var mu sync.Mutex
	got := map[int]int{}
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := login(sec, "192.0.2.10", "guess")
			mu.Lock()
			got[s]++
			mu.Unlock()
		}()
	}
	wg.Wait()
	if got[401] != loginMax || got[429] != 20-loginMax {
		t.Fatalf("20 parallel wrong logins: %v, want %d x 401 and the rest 429", got, loginMax)
	}
	if s := login(sec, "192.0.2.10", "correct horse"); s != 429 {
		t.Errorf("locked address: the right password must not even be checked, got %d", s)
	}
	if s := login(sec, "192.0.2.11", "correct horse"); s != 200 {
		t.Errorf("another address: %d", s)
	}
	advance(loginBase + time.Second)
	if s := login(sec, "192.0.2.10", "correct horse"); s != 200 {
		t.Errorf("after the lock: %d", s)
	}
	// success cleared the record: the next lock is the first one again; a second lock in a row doubles
	for i := 0; i < loginMax; i++ {
		login(sec, "192.0.2.10", "guess")
	}
	advance(loginBase + time.Second)
	for i := 0; i < loginMax; i++ {
		if s := login(sec, "192.0.2.10", "guess"); s != 401 {
			t.Fatalf("attempt %d after the first lock: %d", i, s)
		}
	}
	advance(loginBase + time.Second)
	if s := login(sec, "192.0.2.10", "guess"); s != 429 {
		t.Errorf("second lock should last %s: %d", 2*loginBase, s)
	}
	advance(loginBase)
	if s := login(sec, "192.0.2.10", "correct horse"); s != 200 {
		t.Errorf("after the doubled lock: %d", s)
	}
}

func TestLoginThrottleKeys(t *testing.T) {
	sec, advance := loginEnv(t)
	for i := 0; i < loginMax; i++ {
		login(sec, "2001:db8:1:2::10", "guess")
	}
	if s := login(sec, "2001:db8:1:2:aaaa::99", "correct horse"); s != 429 {
		t.Errorf("same /64: %d", s)
	}
	if s := login(sec, "2001:db8:1:3::10", "correct horse"); s != 200 {
		t.Errorf("other /64: %d", s)
	}
	// failures spread out over more than loginForget do not add up
	for i := 0; i < 2*loginMax; i++ {
		if s := login(sec, "192.0.2.20", "guess"); s != 401 {
			t.Fatalf("slow guess %d: %d", i, s)
		}
		advance(loginForget + time.Second)
		if i%(loginMax-1) == loginMax-2 {
			advance(loginMaxLock)
		}
	}
	for k, want := range map[string]string{"192.0.2.1": "192.0.2.1", "::ffff:192.0.2.1": "192.0.2.1",
		"2001:db8::1": "2001:db8::/64", "bogus": "unknown"} {
		if got := loginKey(k); got != want {
			t.Errorf("loginKey(%q) = %q, want %q", k, got, want)
		}
	}
}

func TestPasswordChangeThrottled(t *testing.T) {
	sec, _ := loginEnv(t)
	if r := apiPassword(apiReq{method: "GET"}, sec); r.status != 405 {
		t.Errorf("GET: %d", r.status)
	}
	for i := 0; i < loginMax; i++ {
		if r := apiPassword(apiReq{method: "POST", remote: "192.0.2.30", body: []byte(`{"old":"x","new":"yyyyyyyy"}`)}, sec); r.status != 401 {
			t.Fatalf("attempt %d: %d", i, r.status)
		}
	}
	if r := apiPassword(apiReq{method: "POST", remote: "192.0.2.30", body: []byte(`{"old":"correct horse","new":"yyyyyyyy"}`)}, sec); r.status != 429 {
		t.Errorf("password change from a locked address: %d", r.status)
	}
}
