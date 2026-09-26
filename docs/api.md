# API — tokens, plan / patch, config paths, schema

The web UI's backend is also the API for scripts, Home Assistant and AI agents: `mr api`, a CGI run by
busybox httpd on the main LAN address (port 80) for each request — no resident process, nothing
listening that was not there before. The same config paths drive `mr get / set / add / del / export`
over SSH, and `mr schema` describes router.yaml as JSON Schema (Cd1s/mini-router#17).

| | |
|---|---|
| Go | `mr/api_token.go` (the `api` module: tokens, scopes, guard, last use, `mr token`), `mr/api_plan.go` (`plan`, patches, `rev` / `base_rev`), `mr/cfgpath.go` (paths, edits in the text of router.yaml, `mr get/set/add/del/export`), `mr/schema.go` (`mr schema`, `GET schema`); hooks in `api.go` (Authorization header, `apiAction`, `candidate`, `base_rev`, `via`) |
| UI | 系统 → 管理与 SSH → “API 令牌” (`rootfs/www/ui/sys.js`); `core.js` sends `base_rev` with every save |
| Checks | `mr/api_token_test.go`, `mr/cfgpath_test.go`, `mr/schema_test.go`; `tools/ci.sh` step 5 (real `mr api` CGI runs); lab fragment `examples/lab.d/80-api.yaml` |
| Cost | no process, no port; `mr` grows by the code above; per token request one flock'ed write to `/run` (last use), to flash at most once an hour per token |

## Tokens

```yaml
api:
  tokens:
    - {name: homeassistant, scope: read, allow: [status, mon.*, wifi.stations], from: [192.168.1.0/24], expires: "2027-01-01"}
    - {name: agent, scope: apply}
```

| Key | |
|---|---|
| `name` | `[a-z][a-z0-9_-]{0,14}`, unique; recorded as `via: api:<name>` in the history |
| `scope` | `read` \| `operate` \| `apply` — each includes the ones before |
| `allow` | optional: only these actions (`mon.*` = every `mon.` action); must match actions of the scope |
| `from` | optional: source addresses / CIDRs (IPv4-mapped IPv6 sources match IPv4 networks) |
| `expires` | optional: `YYYY-MM-DD` — the token stops working when that day begins (router time) |

The token is `mrt_` + 32 random bytes (base64url). router.yaml names it; `secrets.yaml` holds only
`api_token_<name>: sha256:<hex>`. It is shown once: by `mr token create`, or by the web UI, which
generates it in the browser and sends only the hash (the page's normal 保存并应用 installs it).
Creating or revoking a token is a config change like any other: previewed, applied, in the history,
undone by a rollback. Revoking also drops the hash, so a name used again never brings an old token back.

| Scope | Actions |
|---|---|
| `read` | `status`, `config`, `schema`, `history`, `history.diff`, `job`, `net`, `net.ports`, `net.routes`, `net.wan`, `wifi.status`, `wifi.stations`, `wifi.survey`, `wifi.health`, `dns.stats`, `dns.leases`, `fw.stats`, `proxy.status`, `mon.now`, `mon.history`, `mon.devices`, `mon.conns`, `mon.procs`, `mon.dmesg`, `sys.services`, `sys.time`, `sys.doctor` (runs the health checks), `sys.events` (the event log), `sys.edge` |
| `operate` | + `net.redial`, `wifi.kick`, `wifi.scan`, `dns.release`, `proxy.delay`, `proxy.select`, `service` (start / stop / restart), `diag` |
| `apply` | + `plan`, `validate`, `apply`, `confirm`, `revert`, `rollback` |

Never, whatever the scope: login / sessions, the web UI password, logs (`logs`, `sys.logs`: they can
hold URLs with access tokens), `dns.querylog`, backup / restore, firmware, factory reset, reboot, SSH
keys, subscription fetches and share-link parsing (`proxy.fetch`, `proxy.parse`), list files
(`proxy.lists`), token management, test notifications (`sys.notifytest`). A new module action is refused until it is listed in
`tokenActions` (`api_token.go`).

Within `apply`, a token's change is refused (403) when it touches the token list (`api`), SSH
(`services.ssh`: keys and password logins are a root shell), `system.sysctl` (`kernel.core_pattern`
runs programs as root), the `guard` (the owner's baselines), `notify` (a token must not silence or
redirect the owner's alerts), points a `*_file` key at a file the config
did not reference yet (its content could come back in an error), or **adds or changes any item that
references a secret** (a proxy node, a PPPoE WAN, an SSID, a DDNS record — pointed at a host of its own,
the router would send the secret there; removing such an item is allowed). A token cannot set token
hashes, can confirm or revert only a pending change it made itself, and needs `base_rev` to send a whole
config. **An `apply` token still controls the network** — routing, port forwards, which proxy node
traffic uses: give it only to agents you trust, with `from` and `expires`, and keep the `guard` on.
The owner's own AI agents use root SSH and `mr` directly (`mr plan`, `mr apply --confirm`, `mr get/set`, JSON output).

Authentication: only `Authorization: Bearer mrt_…` (no cookie, so no CSRF; no `X-MR` header needed).
A bad token counts against its source address in the login throttle (5 failures → 30 s lock, doubling);
a locked source gets 429 without a check, valid token or not, and a valid token never clears the count.
An expired token gets 401, a source outside `from` or an action outside the scope 403. Every answer to a
token carries `X-MR-Pending` like the web UI's.

```sh
mr token create homeassistant -scope read -allow status,mon.* -from 192.168.1.0/24 -expires 2027-01-01
mr token list        # scope, sources, expiry, last use (time and address) — never the token
mr token revoke homeassistant
```

## Requests

```sh
R=http://192.168.1.1/cgi-bin/api; H="Authorization: Bearer $MR_TOKEN"
curl -sH "$H" "$R?a=status"
curl -sH "$H" "$R?a=mon.devices"
curl -sH "$H" -d '{"mac":"aa:bb:cc:dd:ee:ff"}' "$R?a=wifi.kick"          # operate
```

POST bodies are JSON. Errors: `{"error": "..."}` with the HTTP status (400 bad input, 401 no / bad /
expired token, 403 not allowed, 404 unknown, 405 POST required, 409 conflict, 429 locked source).

### Changing the config (apply scope)

| Action | Body → answer |
|---|---|
| `GET config` | → `{config, secrets_set, rev}` — the effective config (defaults filled in), which secrets exist (names only), `rev` = a content hash of router.yaml |
| `GET config.raw` | `{yaml, rev}`: router.yaml as it is on flash (comments and layout; secret names only) |
| `POST plan` | `{patch \| yaml \| config, base_rev?, secrets?}` → `{errors, rev, changes, changes_known, plan, files, restart, enable, disable, firewall, empty}` — nothing is changed |
| `POST apply` | `{patch \| yaml \| config, base_rev, confirm (s, default 120), comment, secrets?}` (`yaml`: the whole router.yaml text, written as typed — the web UI's 系统 → router.yaml 原文) → `{ok, confirm}`: the apply job starts; 409 when `base_rev` is stale or another change waits for confirmation |
| `GET job` | → `{job: {state: running \| ok \| failed, output}, confirm_pending, pending}` |
| `POST confirm` / `POST revert` | keep / undo the pending change (a token: only its own) |
| `GET history`, `POST history.diff {rev}`, `POST rollback {rev}` | revisions; the config from before #rev applied as a new change |

`secrets` sets secret values by name (`{"proxy_jp2": "…"}`; empty = keep) — for new credentials; values
never come back. `changes` is the config-level diff against the last applied config (`~ path: old → new`,
`+ path`, `- path`; secrets only as `(changed)`).

```sh
rev=$(curl -sH "$H" "$R?a=config" | jq -r .rev)
patch='[{"op":"set","path":"firewall.forwards[nas].enabled","value":false},
        {"op":"add","path":"dhcp.hosts","value":{"name":"tv","mac":"aa:bb:cc:dd:ee:01","ip":"192.168.1.30"}}]'
curl -sH "$H" -d "{\"base_rev\":\"$rev\",\"patch\":$patch}" "$R?a=plan" | jq '.errors, .changes, .plan'
curl -sH "$H" -d "{\"base_rev\":\"$rev\",\"patch\":$patch,\"comment\":\"TV lease, nas off\"}" "$R?a=apply"
curl -sH "$H" "$R?a=job" | jq .job.state             # until ok, then check the network
curl -sH "$H" -d '{}' "$R?a=confirm"                   # within 120 s, else it rolls back by itself
```

`base_rev` keeps clients from overwriting each other: the web UI sends the `rev` it loaded with every
save too, so an agent's change and a browser's never silently undo each other (409: read again, redo).

## Config paths

| Path | Selects |
|---|---|
| `firewall.offload` | a key |
| `firewall.forwards[nas]` | a list item by name — `phy` (radios), `ssid` (SSIDs) or `mac` in lists without names |
| `dhcp.hosts[mac=aa:bb:cc:dd:ee:ff].ip` | a list item by any key |
| `system.ntp[pool.ntp.org]`, `system.ntp[0]` | lists of values: by value, else by position (also lists whose names repeat) |
| `system.sysctl."net.core.rmem_max"`, `wifi.radios[phy1].ssids["My Wifi"]` | keys and names with dots, spaces or brackets in double quotes |

Patch operations (`op`): `set` (a value, a new key, a whole list item; missing parent mappings are
created), `add` (append to a list; a named item's name must be new, a value must not be there yet),
`del` (a key — back to its default — or a list item). Values are JSON in the API and YAML on the
command line; they are converted to the field's type (`"8443"` for a port string) and the result must
decode (unknown keys, wrong types are errors) and validate before anything is written.

Edits apply to router.yaml **as written** (without defaults, so values derived from others follow them)
and are made in its text like the web UI's saves: comments, order, quoting and layout stay, only the
edited values change. If an edit cannot be made in place, the canonical form is written (logged).

## CLI (SSH)

```sh
mr get firewall.forwards[nas]            # a value of the effective config (YAML; --json)
mr get wifi --flat                       # PATH=VALUE lines
mr set 'firewall.forwards[nas].enabled=false' 'lan.ipv6_ra=true'   # validated, then written; -n: only show
mr add dhcp.hosts '{name: tv, mac: "aa:bb:cc:dd:ee:01", ip: 192.168.1.30}'
mr del 'firewall.forwards[old]' system.history
mr export --flat > before.txt            # the whole effective config (--json, or YAML)
mr schema wan                            # the JSON Schema of a part (all of it without PATH)
```

`mr set / add / del` print the config-level changes and edit `router.yaml` only — apply as usual with
`mr plan`, `mr apply --confirm 120`, `mr confirm`. They refuse an invalid result and, on the live file,
any edit while a change waits for confirmation (its rollback would silently undo the edit). Nothing here
prints secret values: router.yaml only names them.

## Schema

`mr schema` / `GET schema` return JSON Schema (2020-12) generated from the Go types, so it cannot
drift from the decoder: types, nesting, `additionalProperties: false` (unknown keys are errors), `enum`
for value sets (`schemaEnums` in `schema.go`, checked by a test: every configured value is listed and
a value outside the set fails validation), `*_secret` fields described as secret names. `required`
lists the keys always present in the effective config (`GET config`, `mr export`); a router.yaml may
leave them out — the defaults fill them in. For scripts, agents (`mr schema PATH`) and editor completion
(`# yaml-language-server: $schema=…` with the output saved as a file).

## 怎么用

- **给 Home Assistant 只读令牌**：网页 系统 → 管理与 SSH → API 令牌，名称 `homeassistant`、权限“只读”、
  来源填 HA 的地址，点“生成令牌”，复制弹出的令牌（只显示一次），再点页面下方“保存并应用”并“保留”。
  HA 的 RESTful 传感器用 `http://<路由器>/cgi-bin/api?a=status`，请求头 `Authorization: Bearer <令牌>`。
  或者 SSH：`mr token create homeassistant -scope read -from 192.168.1.20`。
- **给 AI agent 修改权限**：`mr token create agent -scope apply -expires 2026-12-31`。agent 的流程：
  `GET config` 拿 `rev` → `POST plan`（patch + base_rev）看 changes / plan → `POST apply` → 轮询 `job` →
  检查网络 → `POST confirm`。改令牌、SSH、sysctl 它做不到，只能人在网页或 SSH 上改。
- **吊销**：网页里点“吊销”再保存，或 `mr token revoke agent`；哈希一起删除。“最后使用”列显示时间和来源地址。
- **SSH 上改配置**：优先 `mr set` / `mr add` / `mr del`（自动校验，保留注释），再 `mr plan`、
  `mr apply --confirm 120`、`mr confirm`；`mr export --flat` 可以把全部配置变成一行一个的路径。
