package main

import (
	"os"
	"regexp"
	"strconv"
	"testing"
)

// A stopped PPPoE service must have time to send the PADT (a reboot, `rc-service restart`, a guard redial):
// pppd sends LCP Terminate-Request and waits lcp-restart (3 s, pppd's default) for the Terminate-Ack, up to
// lcp-max-terminate times. supervise-daemon declares the service stopped after `retry` seconds (default 5);
// OpenRC then goes on while pppd is still counting, and a reboot kills the PADT. Lab: scenario 15.
func TestPPPoEStopLeavesTimeForPADT(t *testing.T) {
	read := func(p string) string {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	const lcpRestart = 3 // seconds, pppd's default
	retry := regexp.MustCompile(`(?m)^retry="SIGTERM/(\d+)"$`).FindStringSubmatch(read("../rootfs/etc/init.d/mr-pppoe"))
	if retry == nil {
		t.Fatal(`mr-pppoe: no retry="SIGTERM/N": supervise-daemon would stop waiting for pppd after 5 s`)
	}
	term := regexp.MustCompile(`(?m)^exec /usr/sbin/pppd call "\$1" lcp-max-terminate (\d+)$`).FindStringSubmatch(read("../rootfs/usr/libexec/mr/pppoe-dial"))
	if term == nil {
		t.Fatal("pppoe-dial: pppd is not started with lcp-max-terminate N (the default of 2 needs 6 s before the PADT)")
	}
	wait, _ := strconv.Atoi(retry[1])
	n, _ := strconv.Atoi(term[1])
	if n < 1 {
		t.Fatalf("lcp-max-terminate %d: pppd would not send an LCP Terminate-Request", n)
	}
	if need := n*lcpRestart + 2; wait < need {
		t.Fatalf("supervise-daemon waits %d s for pppd, which needs %d x %d s for LCP terminate plus the PADT (%d s)", wait, n, lcpRestart, need)
	}
}
