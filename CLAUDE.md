# CLAUDE.md — Mini-Router

Alpine-based router OS: `router.yaml` + the static Go tool `mr` + a web UI. Read `docs/MODULES.md` before
changing anything; per-module docs are in `docs/modules/`.

## Commands

```sh
sudo ./tools/ci.sh                        # everything: gofmt, vet, tests, cross-builds, shellcheck, nft/dnsmasq/hostapd/sing-box e2e
cd mr && go test ./...                    # unit tests only
python3 tools/mock/mockapi.py 8088        # web UI against fixtures: http://127.0.0.1:8088/
./tools/release.sh vX.Y.Z out/release     # mr for 7 architectures + rootfs tarball + install.sh
```
AX6000 firmware: `build/m3/` (`kernel.sh` → `build.sh`, `selftest.sh` runs sysupgrade / preinit on nandsim; root + docker).

## Layout

- `mr/` — `main.go` (CLI), `config.go`, `module.go` (hook registry), `render.go`, `apply.go` (snapshot, verify,
  rollback), `api.go` (web UI CGI, auth), `mod_<net|wifi|dns|fw|mon|proxy|sys>*.go`.
- `rootfs/` — files installed on the router: OpenRC services `etc/init.d/mr-*`, `usr/libexec/mr/*`, `sbin/mr-preinit`
  (image only), `www/` (`index.html` + `ui/core.js` + one `ui/<module>.js` per module).
- `tools/ci.sh` + `tools/ci.d/<module>.sh`, `tools/mock/`, `examples/router.yaml` + `examples/lab.d/` (all features).
- `skills/mini-router/SKILL.md` — how an AI agent should operate a live router.

## Rules

- Validation is the security boundary: every string that reaches a generated file goes through the validators in
  `config.go` (`safeText`, `reName`, …). Mutating API actions require POST and never return secrets.
- A module only touches its own files (see the table in `docs/MODULES.md`); core changes go through the hooks.
- Generated files are never edited by hand; `mr apply` must stay idempotent and roll back on any failed check.
- New config keys: validation + render + docs (`docs/modules/<module>.md`) + a lab fragment + a test.
- Web UI: plain JS, no build step, no external assets; works on phones (≥ 360 px) and in both themes.
