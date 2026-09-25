---
name: mini-router
description: Operate a router running mini-router (Alpine Linux + the `mr` tool + /etc/mini-router/router.yaml) over SSH — status and diagnostics, WAN / PPPoE, LAN and DHCP static leases, DNS, WiFi, firewall port forwards and open ports, the selective proxy (sing-box nodes, share links, subscriptions, rules, bypass devices), services, backups, rollback and firmware upgrades. Use when the user asks to check or change their mini-router, mentions router.yaml, `mr apply`, or the Mini-Router web UI.
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

1. **Read first**: `mr status` and the section you will touch (`sed -n '/^firewall:/,/^[a-z]/p' /etc/mini-router/router.yaml`).
2. **Edit a copy**, validate and preview it, then install it:
   ```sh
   cp /etc/mini-router/router.yaml /tmp/new.yaml        # edit /tmp/new.yaml (or copy it out, edit, copy back)
   mr -c /tmp/new.yaml validate && mr -c /tmp/new.yaml plan
   cp /tmp/new.yaml /etc/mini-router/router.yaml
   ```
3. **Apply with a safety net**: `mr apply --confirm 120`. It prints the plan, applies, verifies services; failures
   roll back at once. Then verify (step 4) and run **`mr confirm` within 120 s** — without it the change is rolled
   back automatically (that is the net when you cut your own connection; never forget it when all is fine).
   A reboot or power cut before `mr confirm` rolls the change back at boot as well. While a change waits for
   confirmation (yours, the web UI's or another agent's) every new apply is refused: `mr confirm` or `mr rollback` first.
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
lan: {bridge: br-lan, ports: [lan1, lan2], ipv4: 192.168.1.1/24, ipv6_ra: true}
wan:
  - {name: wan, device: wan, proto: pppoe, username: "…", password_secret: pppoe_password, ipv6: true, ipv6_pd: true}
  - {name: wan2, device: eth2, proto: dhcp}           # proto: pppoe | dhcp | static (ipv4:, gateway:, dns:)
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
- **WAN**: `mr wan status`; redial one line at a time: `rc-service mr-pppoe.<name> restart`.
- **Services** (`services:` in router.yaml, e.g. `ssh`, `tailscale`, `stubby`): enabling adds them to the runlevel on apply.

## Status and diagnostics (read-only)

```sh
mr status                      # JSON: WANs, WiFi, services, memory, offload, versions
mr wan status | mr wan health
mr wifi status | mr wifi stations | mr wifi survey
mr dns leases | mr dns stats | mr dns query example.com AAAA
mr mon now | mr mon devices | mr mon conns '{"limit":20}'
mr proxy status | mr proxy check
rc-status -c                   # crashed services (should be empty)
tail -n 100 /var/log/messages  # system log (logread is not used)
dmesg | tail -n 50
```

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
