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
	d := t.TempDir()
	oldMarker, oldSecrets, oldGen := firstRunMarker, firstRunSecretsPath, firstRunGenDir
	firstRunMarker = filepath.Join(d, "state", "first-run")
	firstRunSecretsPath = filepath.Join(d, "secrets.yaml")
	firstRunGenDir = filepath.Join(d, "gen")
	t.Cleanup(func() { firstRunMarker, firstRunSecretsPath, firstRunGenDir = oldMarker, oldSecrets, oldGen })
	if err := os.MkdirAll(firstRunGenDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(firstRunMarker), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(firstRunMarker, []byte("factory\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(firstRunSecretsPath, []byte("webui_password: pbkdf2-sha256$1$abc\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(firstRunGenDir, "applied.yaml"), []byte("lan:\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if firstRunPending() {
		t.Fatal("accepted router with stale factory marker entered first run")
	}

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
