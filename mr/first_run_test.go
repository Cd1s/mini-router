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

func TestFactoryPasswordSetupKeepsWizardPending(t *testing.T) {
	d := t.TempDir()
	oldMarker := firstRunMarker
	firstRunMarker = filepath.Join(d, "state", "first-run")
	t.Cleanup(func() { firstRunMarker = oldMarker })
	if err := os.MkdirAll(filepath.Dir(firstRunMarker), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(firstRunMarker, []byte("factory-done\n"), 0600); err != nil {
		t.Fatal(err)
	}
	// render can create applied.yaml in the read-only factory layer and setup
	// writes the password before the wizard continues; the marker is decisive.
	if !firstRunPending() {
		t.Fatal("factory password setup incorrectly hid the wizard")
	}
}
