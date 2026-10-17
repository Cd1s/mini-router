package main

import "os"

// firstRunMarker is created by install.sh for a newly flashed image.  It is
// intentionally outside router.yaml so importing an old configuration never
// triggers the wizard for an existing owner.
var firstRunMarker = "/etc/mini-router/state/first-run"

func firstRunPending() bool {
	_, err := os.Stat(firstRunMarker)
	return err == nil
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
