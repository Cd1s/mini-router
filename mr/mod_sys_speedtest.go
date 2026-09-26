package main

// sys module: `mr speedtest` and API sys.speedtest (#33) — the router's own download and upload through
// its default route, against Cloudflare's speed test endpoints (speed.cloudflare.com/__down, /__up).
// One TCP connection each way for about 8 s, so the result is a lower bound: a single stream, TLS on
// the router's CPU (LAN clients behind hardware offload can get more), and traffic of other devices
// shares the line meanwhile. One test at a time.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

var (
	speedURL  = "https://speed.cloudflare.com"
	speedTime = 8 * time.Second
	speedLock = RunDir + "/speedtest.lock"
)

type speedResult struct {
	Down float64 `json:"down_mbps"`
	Up   float64 `json:"up_mbps"`
	Time int64   `json:"time"`
}

// speedBody: zeros for speedTime after the first read, counted.
type speedBody struct {
	start, last time.Time
	n           int64
}

var speedZeros = make([]byte, 32<<10)

func (b *speedBody) Read(p []byte) (int, error) {
	now := time.Now()
	if b.start.IsZero() {
		b.start = now
	}
	if now.Sub(b.start) >= speedTime {
		return 0, io.EOF
	}
	n := copy(p, speedZeros)
	b.n, b.last = b.n+int64(n), now
	return n, nil
}

func mbps(n int64, d time.Duration) float64 {
	if d <= 0 {
		return 0
	}
	return float64(int64(float64(n)*8/d.Seconds()/1e4)) / 100
}

func speedTest() (speedResult, error) {
	res := speedResult{Time: time.Now().Unix()}
	lk := flock(speedLock, false)
	if lk == nil {
		return res, fmt.Errorf("a speed test is already running")
	}
	defer lk.Close()
	hc := &http.Client{}
	ctx, cancel := context.WithTimeout(context.Background(), speedTime+15*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", speedURL+"/__down?bytes=1000000000", nil)
	resp, err := hc.Do(req)
	if err != nil {
		return res, fmt.Errorf("download: %v", err)
	}
	buf := make([]byte, 64<<10)
	var n int64
	start := time.Now()
	for time.Since(start) < speedTime {
		k, err := resp.Body.Read(buf)
		n += int64(k)
		if err != nil {
			break
		}
	}
	res.Down = mbps(n, time.Since(start))
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return res, fmt.Errorf("download: HTTP %d", resp.StatusCode)
	}
	body := &speedBody{}
	req, _ = http.NewRequestWithContext(ctx, "POST", speedURL+"/__up", body)
	if resp, err = hc.Do(req); err != nil {
		return res, fmt.Errorf("upload: %v", err)
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	res.Up = mbps(body.n, body.last.Sub(body.start))
	if resp.StatusCode != 200 {
		return res, fmt.Errorf("upload: HTTP %d", resp.StatusCode)
	}
	logf("speedtest: down %.1f Mbit/s, up %.1f Mbit/s", res.Down, res.Up)
	return res, nil
}

func speedCommand(_ *Config, _ []string) error {
	res, err := speedTest()
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(res)
}

// apiSysSpeedtest: POST → {down_mbps, up_mbps, time}; about 20 s.
func apiSysSpeedtest(r apiReq) apiResp {
	if r.method != "POST" {
		return errResp(405, "POST required")
	}
	res, err := speedTest()
	if err != nil {
		return errResp(502, "%v", err)
	}
	return apiResp{body: res}
}
