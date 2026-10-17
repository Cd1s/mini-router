package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFirstRunMarkerKinds(t *testing.T) {
	d := t.TempDir()
	old := firstRunMarker
	firstRunMarker = filepath.Join(d, "first-run")
	t.Cleanup(func() { firstRunMarker = old })
	if err := os.WriteFile(firstRunMarker, []byte("factory\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if !firstRunPending() || !firstRunPasswordPending() || !firstRunFactory() {
		t.Fatal("factory marker was not recognized")
	}
	if err := markFirstRunPasswordDone(); err != nil {
		t.Fatal(err)
	}
	if firstRunPasswordPending() || !firstRunFactory() {
		t.Fatal("factory marker did not transition after setup")
	}
}

func TestSuppressFirstRunForAcceptedExistingRouter(t *testing.T) {
	if !suppressFirstRun("install\n", "webui_password: pbkdf2-sha256$1$abc\n", true) {
		t.Fatal("accepted router with password was not suppressed")
	}
	if suppressFirstRun("install\n", "webui_password: pbkdf2-sha256$1$abc\n", false) {
		t.Fatal("unapplied config was suppressed")
	}
	if !suppressFirstRun("factory\n", "webui_password: pbkdf2-sha256$1$abc\n", true) {
		t.Fatal("stale factory marker did not suppress an accepted router")
	}
	if suppressFirstRun("install\n", "wifi_key: only\n", true) {
		t.Fatal("router without admin password was suppressed")
	}
}
