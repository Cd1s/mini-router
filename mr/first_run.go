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
	b, err := os.ReadFile(firstRunMarker)
	if err != nil {
		return false
	}
	if _, pwErr := os.Stat(SecretsPath); pwErr == nil {
		if _, appliedErr := os.Stat(GenDir + "/applied.yaml"); appliedErr == nil {
			secrets, _ := os.ReadFile(SecretsPath)
			if suppressFirstRun(string(b), string(secrets), true) {
				return false
			}
		}
	}
	return true
}

func suppressFirstRun(marker, secrets string, applied bool) bool {
	// A marker can survive an image upgrade in the writable overlay.  Once an
	// accepted generation and administrator password exist, it is an existing
	// router regardless of whether the stale marker says install or factory.
	return applied && strings.TrimSpace(marker) != "" && strings.Contains(secrets, pwSecretKey+":")
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
