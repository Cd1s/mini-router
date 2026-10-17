package main

import (
	"os"
	"strings"
)

// firstRunMarker is created by install.sh or preinit when rootfs_data is new
// or factory-reset. It is intentionally outside router.yaml so importing an
// old configuration never triggers the wizard for an existing owner.
var firstRunMarker = "/etc/mini-router/state/first-run"

func firstRunPending() bool {
	_, err := os.Stat(firstRunMarker)
	return err == nil
}

// Factory images use a marker value until apiSetup has safely established the
// first password.  Installer-created markers contain "install" and skip that
// extra password step in the wizard.
func firstRunPasswordPending() bool {
	b, err := os.ReadFile(firstRunMarker)
	return err == nil && strings.TrimSpace(string(b)) == "factory"
}

func firstRunFactory() bool {
	b, err := os.ReadFile(firstRunMarker)
	if err != nil {
		return false
	}
	v := strings.TrimSpace(string(b))
	return v == "factory" || v == "factory-done"
}

func markFirstRunPasswordDone() error {
	b, err := os.ReadFile(firstRunMarker)
	if err != nil || strings.TrimSpace(string(b)) != "factory" {
		return err
	}
	return os.WriteFile(firstRunMarker, []byte("factory-done\n"), 0600)
}

func apiSetupComplete(r apiReq) apiResp {
	if r.method != "POST" {
		return errResp(405, "POST required")
	}
	if err := os.Remove(firstRunMarker); err != nil && !os.IsNotExist(err) {
		return errResp(500, "%v", err)
	}
	return apiResp{body: map[string]any{"ok": true}}
}
