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
