---
name: mini-router
description: Operate a router running mini-router (Alpine Linux + the `mr` tool + /etc/mini-router/router.yaml) over SSH — status, health checks (`mr doctor`), the event log and phone notifications, WAN / PPPoE, LAN and DHCP static leases, DNS, WiFi, firewall port forwards and open ports, the selective proxy (sing-box nodes, share links, subscriptions, rules, bypass devices), services, backups, rollback and firmware upgrades. Use when the user asks to check or change their mini-router, mentions router.yaml, `mr apply`, or the Mini-Router web UI.
---

# Operating a mini-router

mini-router is declarative: **`/etc/mini-router/router.yaml` is the whole router**. `mr` validates it, renders
every config file (nftables, dnsmasq, hostapd, pppd, sing-box, sysctl, OpenRC runlevel), applies with a snapshot,
checks every service and rolls back by itself when something fails. Never edit generated files
(`/etc/mini-router/gen/*`, `/etc/dnsmasq.conf`, `/etc/hostapd/*`, `/etc/ppp/peers/*`, nft rules): the next apply
overwrites them. Passwords and keys live in `/etc/mini-router/secrets.yaml` (0600) and are referenced from
router.yaml by `*_secret` keys — never print them, never put them in router.yaml, logs or chat.

Access: `ssh root@<router-ip>` (LAN only; the web UI at `http://<router-ip>/` uses the same backend).
Tools on the router: busybox (sh, sed, awk, grep, wget), `mr`, `nft`, `ip`, `iw`, `rc-service`, `rc-status`.
No python/jq there: edit YAML with care, or edit a copy on your side and send it back.

## The safe change workflow (every change)

1. **Read first**: `mr status` and the part you will touch: `mr get firewall.forwards` (effective values, defaults
   filled in; `--json`), `mr export --flat | grep …` (one `PATH=VALUE` per line), `mr schema firewall.forwards` (keys,
   types, allowed values).
2. **Edit with `mr set` / `mr add` / `mr del`** — prefer them to editing the file by hand: they validate the result
   before writing (an invalid edit changes nothing), keep router.yaml's comments and layout, print the config-level
   changes, and never touch secrets. Paths address list items by name (`[key=value]` for other keys, quotes for dots):
   ```sh
   mr set 'firewall.forwards[nas].enabled=false' 'lan.ipv6_ra=true'   # -n: only show the changes
   mr add dhcp.hosts '{name: tv, mac: "aa:bb:cc:dd:ee:01", ip: 192.168.1.30}'
   mr del 'firewall.forwards[old-game]'                               # a key: back to its default
   mr plan                                                            # changes + files + services
   ```
   For a large rework, edit a copy instead: `cp /etc/mini-router/router.yaml /tmp/new.yaml`, edit,
   `mr -c /tmp/new.yaml validate && mr -c /tmp/new.yaml plan`, then copy it back.
3. **Apply with a safety net**: `mr apply --confirm 120`. It prints the plan, applies, verifies services; failures
   roll back at once. Then verify (step 4) and run **`mr confirm` within 120 s** — without it the change is rolled
   back automatically (that is the net when you cut your own connection; never forget it when all is fine).
   A reboot or power cut before `mr confirm` rolls the change back at boot as well. While a change waits for
   confirmation (yours, the web UI's or another agent's) every new apply is refused: `mr confirm` or `mr rollback` first.
   The plan ends with `risk: low | medium | high — reasons` (high: your own connection's path, LAN addresses, WANs,
   the router's inbound rules / SSH / web UI / tailscale, the guard); `mr plan --explain` says what each action does.
   Interactive sessions: `mr apply --confirm 120 --wait` asks on the terminal; Ctrl-C or a dropped SSH connection rolls
   back at once. `guard:` in router.yaml holds the owner's baselines; `mr validate` refuses configs that break them —
   never weaken the guard to get a change through; ask the owner.
4. **Verify by reading back**: the live state, not the exit code (`mr status`, `nft list ruleset | grep …`,
   `mr wifi status`, a real connection test).
5. History: `mr plan` starts with the config-level diff (`~ path: old → new`, `+`/`- list[name]`; `-v` adds the
   generated files' diffs, secrets masked); `mr apply -m "why"` records a comment. `mr history` lists every change
   (#N, time, origin, comment, result, what changed); `mr rollback N` applies the config from before change #N as a new
   change (with `--confirm`, default 120 s). Every apply is also logged in `/etc/router-changes.log`
   — append a line for manual actions: `echo "$(date '+%F %T') <what>" >> /etc/router-changes.log`.

Warn the user before anything that can cut connectivity (LAN address, WAN, WiFi they are on, reboot, upgrade),
and do one change at a time.

## router.yaml cheat sheet

```yaml
guard: {never_expose: [ssh, panel, dns], always_bypass: [desktop], offload: hardware, ssh_lan_only: true}
lan: {bridge: br-lan, ports: [lan1, lan2], ipv4: 192.168.1.1/24, ipv6_ra: true}
# side router / AP (no wan, no ipv6_ra): mode: bypass | ap, lan.gateway: <main router>,
#   bypass: {clients: route-only | all | selected, macs: [...]}; route-only: `mr proxy routes` = the main router's static routes
wan:
  - {name: wan, device: wan, proto: pppoe, username: "…", password_secret: pppoe_password, ipv6: true, ipv6_pd: true}  # mtu: 1500 = RFC 4638 (falls back to 1492)
  - {name: wan2, device: eth2, proto: dhcp}           # proto: pppoe | dhcp | static (ipv4:, gateway:, dns:)
policy_routes:                                        # pick the WAN for NEW connections (selectors are ANDed)
  - {name: nas, mac: "aa:bb:cc:dd:ee:02", via: wan2}  # mac / src / dst / domains
  - {name: video, domains: [video.example], via: wan2}  # + subdomains; dnsmasq fills nft set pr_<index>_4/_6
dhcp:
  start: 100
  end: 249
  hosts:                                              # static leases (IP outside start..end)
    - {name: nas, mac: "aa:bb:cc:dd:ee:ff", ip: 192.168.1.20}
firewall:
  offload: hardware                                   # hardware | software | off
  forwards:                                           # WAN → LAN port forwards
    - {name: web, proto: [tcp], port: "8443", to: 192.168.1.20, to_port: "443"}
    - {name: game, proto: [tcp, udp], port: 27000-27010, to: 192.168.1.30}
  open:                                               # ports on the router itself, from WAN
    - {name: https, proto: [tcp], port: "443"}
wifi:
  country: US
  radios:
    - phy: phy1
      band: 5g
      channel: "36"
      htmode: HE160
      ssids: [{ssid: Home-5G, key_secret: wifi_key, encryption: sae-mixed}]
proxy:                                                # selective transparent proxy (sing-box, fake-ip)
  enabled: true
  nodes: [{name: jp1, server: 203.0.113.7, port: 8388, method: aes-128-gcm, password_secret: proxy_jp1}]
  groups: [{name: auto, type: urltest, nodes: [jp1]}]
  rules: [{name: ai, outbound: auto, domains: [openai.com, claude.ai]}]   # only matches go through the proxy
  bypass: [{name: tv, mac: "aa:bb:cc:dd:ee:01"}]      # devices that never use the proxy
  subscriptions: [{name: airport, url_secret: proxy_sub_airport}]
```
Full reference per module: `docs/modules/<net|wifi|dns|fw|proxy|sys|mon>.md` in the repository, and the examples in
`examples/`. Unknown keys are rejected by `mr validate`, which names the line.

Secrets: add `name: value` to `/etc/mini-router/secrets.yaml` without echoing the value into the terminal output
(`printf '%s: %s\n' proxy_jp1 "$VALUE" >> …`, value supplied by the user), then reference it with `*_secret: name`.

## Recipes

- **Static lease / port forward / open port**: edit `dhcp.hosts`, `firewall.forwards`, `firewall.open` as above.
  Check: `nft list ruleset | grep -A2 <port>`; test from outside the LAN. Never forward SSH (22) or the web UI to WAN.
- **Proxy nodes from share links / subscription**: `mr proxy parse links.txt` (ss://, vless://, vmess://, trojan://,
  hysteria2://, tuic://, anytls://, base64 lists) prints node lines for router.yaml and the secret *names*; add
  `--secrets` only when writing them straight into secrets.yaml. `mr proxy fetch <subscription-name|URL>` downloads
  and parses a subscription. After apply: `mr proxy status`, `mr proxy delay`, `mr proxy select GROUP NODE`.
- **WiFi**: change country / channel / width / power only when the user asks for exact values. Check with
  `mr wifi status` (`iw dev` shows channel, width, txpower); clients: `mr wifi stations`; kick: `mr wifi kick MAC`.
- **WiFi tuning** (all off by default; no daemon — crond runs `mr wifi tick` each minute while steering or self-heal is on;
  none of it touches country / channel / width / power): per SSID `multicast_to_unicast: true` (AirPlay / mDNS / IPTV as
  unicast per client); `wifi.steering: {enabled: true, min_signal_2g: -60, exclude: [MAC…]}` asks 802.11v clients on 2.4 GHz
  with a good signal to move to 5 GHz — never forced; needs an SSID with the **same name, encryption, key_secret and network
  on both bands** (validation says so otherwise; renaming SSIDs is the owner's call); `wifi.self_heal: true`: a radio whose
  acknowledged TX stops for 10 min with clients on gets mt76's firmware recovery (SER, both bands, seconds), then a
  mr-hostapd restart, then only a `wifi` event — never a reboot. Check: `mr wifi steer --dry-run` (who would be asked and
  why not), `mr wifi health` (temperature, throttling, airtime fairness `vow_atf`, firmware restarts, stall / heal stage,
  steering counts), `grep 'wifi steer\|wifi self-heal' /var/log/messages`, `mr event list`.
- **WAN**: `mr wan status`; redial one line at a time: `rc-service mr-pppoe.<name> restart`.
- **A website via another WAN**: `policy_routes: [{name: …, domains: [site.example], via: wan2}]` (or `domains_file:`).
  Connections stay hardware-offloaded. Check: `mr dns query site.example`, then `nft list set inet mr pr_<index>_4`
  lists the learned addresses. Devices using DoH / their own DNS are not covered (`dns.redirect` catches plain DNS).
- **Services** (`services:` in router.yaml, e.g. `ssh`, `tailscale`, `stubby`): enabling adds them to the runlevel on apply.
- **DDNS** (Cloudflare; no daemon: WAN hooks + crond): token (Zone › DNS › Edit on that zone) into secrets.yaml as
  e.g. `cf_ddns_token`, then `services: {ddns: {enabled: true, records: [{name: home.example.com, zone: example.com,
  token_secret: cf_ddns_token, ipv4: active, ipv6: router}]}}` (`ipv4`: active | WAN name | "off"; `ipv6`: "off" |
  router | "::10" for a LAN device; `interval`: minutes, default 10). Check: `mr ddns status` (`local` vs `published`,
  `note` explains a missing address, e.g. CGNAT); force a re-check: `mr ddns update --force`. Only changes record content
  (proxied stays); never deletes records.
- **Notifications to the phone** (Telegram bot or a webhook: ntfy, Bark, Gotify, Home Assistant; no daemon): the bot
  token / webhook URL into secrets.yaml (e.g. `notify_tg_token`), then `notify: {channels: [{name: phone, type: telegram,
  token_secret: notify_tg_token, chat_id: "123456789"}], quiet_hours: "23:00-07:00"}` (webhook: `{name: ntfy, type:
  webhook, url_secret: notify_ntfy_url, format: text}`; `format: json` for the others). Default events: WAN down / up,
  failover, rollback, login locks, new devices, boots (and why), firmware changes, new `mr doctor` findings (background run
  every `doctor_interval` minutes, default 30). After apply: `mr notify test`, `mr notify status` (pending, last error,
  retry). API tokens and agents cannot change `notify` — ask the owner.
- **HTTPS reverse proxy with certificates** (`services.edge`; replaces lucky's 443 proxy; `mr edge serve` runs as
  service `mr-edge` only while on): same Cloudflare token kind as DDNS (reuse `cf_ddns_token`), then
  `services: {edge: {enabled: true, open: true, acme: {token_secret: cf_ddns_token, wildcard: [example.com]},
  routes: [{name: nas, host: nas.example.com, to: "http://192.168.1.10:5000"}, {name: ha, host: ha.example.com,
  to: "http://192.168.1.20:8123", allow: [lan]}]}}` (`to`: http(s)://LAN-IP:port only; `allow`: `lan` and / or CIDRs,
  empty = everyone; `open`: reachable from the WANs; try `acme.staging: true` first). A `firewall.open` of the same tcp
  port is refused while it is on (remove lucky's `lucky-https`, disable lucky in the same apply). Plan risk is high.
  Check: `mr edge status` (`serving`, certificates `state` / `error`, requests per route); issue now: `mr edge renew`
  (certificates come from Let's Encrypt via DNS-01 in 1–2 minutes; renewed daily when a third of the lifetime is left).
- **Wake a device (WOL)**: `mr wol <dhcp.hosts name>` or `mr wol aa:bb:cc:dd:ee:ff [network]` — magic packet to that
  LAN network's broadcast through its bridge (never a WAN). Scheduled: `schedules: [{name: wake-nas, cron: "0 7 * * 1-5",
  action: wol, target: nas}]`. The device needs WOL enabled in its BIOS / NIC and usually a cable.

## Status and diagnostics (read-only)

```sh
mr doctor                      # health and security checks, problems first, each with its fix (--json)
mr event list                  # what happened: WAN down / up, failover, changes, rollbacks, login locks, new devices, boots and why
mr status                      # JSON: WANs, WiFi, services, memory, offload, versions, last doctor problems, newest events
mr wan status | mr wan health
mr wifi status | mr wifi stations | mr wifi survey
mr wifi health                 # per radio: temperature, TX duty (throttling), ATF, firmware restarts, self-heal; steering stats
mr dns leases | mr dns stats | mr dns query example.com AAAA
mr mon now | mr mon devices | mr mon conns '{"limit":20}'
mr proxy status | mr proxy check
mr ddns status                 # DDNS records: local / published address, last error
mr notify status               # notification channels: pending, last error, retry
mr edge status                 # reverse proxy: serving, routes (requests), certificates (expiry, last error)
rc-status -c                   # crashed services (should be empty)
tail -n 100 /var/log/messages  # system log (logread is not used)
dmesg | tail -n 50
```

## Without SSH: the HTTP API with a token

Scripts, Home Assistant or an agent without root access use the web UI's API with a scoped token
(`docs/api.md` in the repository): the user creates it (web UI 系统 → 管理与 SSH → API 令牌, or
`mr token create NAME -scope read|operate|apply [-from CIDR] [-expires DATE]`), it is shown once and only its
hash is stored. Requests: `curl -H "Authorization: Bearer $MR_TOKEN" http://<router-ip>/cgi-bin/api?a=status`.
Changing the config (scope `apply`): `GET config` (note `rev`) → `POST plan {"base_rev": REV, "patch": [{"op":
"set", "path": "firewall.forwards[nas].enabled", "value": false}]}` → read `errors` / `changes` / `plan` →
`POST apply` (same body, plus `"comment"`) → poll `GET job` until `ok` → verify → `POST confirm` within 120 s.
409 = someone else changed router.yaml (read again) or a change waits for confirmation. Tokens can never
change the token list, SSH, sysctl, read logs or secrets, back up / restore, upgrade, reset or reboot — ask
the user to do those. Never print or store a token in files, logs or chat.

## Firmware upgrade (AX6000 image; installs from the running system)

```sh
/usr/libexec/mr/sysupgrade -T --sha256 <SHA> /tmp/<image>-sysupgrade.tar      # verify only
setsid /usr/libexec/mr/sysupgrade -y --sha256 <SHA> /tmp/<image> > /tmp/su.log 2>&1 &
```
The router kexecs an installer, writes flash and reboots (≈2 min offline); settings are kept. A failure before the
write reboots the old system. Afterwards: `cat /etc/mini-router-release`, `rc-status -c`, `mr plan` (a new version
may render files differently) and `mr apply --confirm 120` + `mr confirm` if it shows changes.
On plain Alpine installs, update with `install.sh` from the latest release instead.

## Never

- expose SSH or the web UI to WAN; print or commit secrets;
- edit generated files, or leave an `apply --confirm` unconfirmed when the result is good;
- reboot, upgrade or restart the WAN/WiFi without telling the user;
- auto-accept a changed SSH host key — report it and let the user verify.
