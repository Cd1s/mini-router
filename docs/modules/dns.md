# dns module — dnsmasq (DNS, DHCP, RA / DHCPv6) + stubby (DoT)

Files: `mr/mod_dns.go` (types, validation, dnsmasq/stubby rendering), `mr/mod_dns_records.go` (local
records), `mr/mod_dns_query.go` (tiny DNS client, statistics, post-apply read-back),
`mr/mod_dns_leases.go` (leases, DHCPRELEASE, query log, web UI actions, `mr dns`),
`mr/mod_dns_release_*.go`, `rootfs/etc/conf.d/dnsmasq`, `rootfs/www/ui/dns.js`,
`examples/lab.d/30-dns.yaml`, `tools/ci.d/dns.sh`. router.yaml keys: `dhcp`, `dns`, `networks[].dhcp`.

## What it does

- **One resident process: dnsmasq** — DNS cache/forwarder for every LAN-side network, DHCPv4 pools,
  router advertisements and optional DHCPv6. stubby runs only when `services.stubby.enabled`.
  Statistics, lease release and query logging are computed on demand by the non-resident `mr`
  (CGI / CLI); nothing else stays in memory.
- **Local DNS records for home servers** (`dns.records`): A/AAAA, wildcard domains, CNAME, PTR, SRV, TXT.
  After every apply that restarts dnsmasq, `mr` queries 127.0.0.1 for each A/AAAA record (up to 20)
  and rolls the apply back if one is not served.
- **Upstream control** (`dns.upstream`): the ISP's DNS from PPPoE (default), a manual list, or
  everything over DNS-over-TLS through stubby. `dns.split` sends listed domains to another upstream.
- **stubby config** (`dns.dot`): `/etc/stubby/stubby.yml` is rendered whenever stubby is enabled;
  it listens on `127.0.0.1@<port>` only (Alpine's default file listens on 127.0.0.1:53 — dnsmasq's
  port — and uses getdnsapi.net, so this file is required for the existing split to work).
- **DHCP**: per-network pools, static leases (`dhcp.hosts`) with optional per-host lease time
  (`dhcp.host_leases`), per-network DNS / NTP / search domains / raw options, lease list,
  "set static", and **release** (the router sends the DHCPRELEASE the client would send, exactly like
  dnsmasq's `dhcp_release`; the lease file is never edited while dnsmasq owns it).
- **IPv6 LAN**: per network SLAAC (`ra-only`, default), SLAAC + stateless DHCPv6 (`ra-stateless`) or
  stateful DHCPv6 + SLAAC, RDNSS, RA interval / router lifetime / priority / MTU.
- **Cache statistics** from dnsmasq's CHAOS `*.bind` TXT records (cache size, insertions, evictions,
  answered locally, forwarded, per-upstream queries / failures).
- **Temporary query logging**: off by default; switching it on restarts dnsmasq with `--log-queries`
  for 1–60 minutes. The flag is `/run/mini-router/dns-querylog` (tmpfs: gone after a reboot) and a
  detached `mr dns querylog-expire` switches it off at the deadline. `conf.d/dnsmasq` also ignores
  an expired flag, so no later restart re-enables logging even if that switch-off never ran (it
  needs router.yaml to load, like every `mr` module command). The view hides `mr`'s own statistics
  probes (`*.bind` CHAOS queries from 127.0.0.1).
- DNS redirect (`dns.redirect`, nft DNAT of LAN port 53 to the router) — unchanged.
- **DNS sovereignty** (`dns.sovereignty`, Cd1s/mini-router#45): keeps devices on the router's DNS, which
  local names, the split, policy routes by domain and the proxy's fake-ip all rely on (see below).
- **nftset lines from the net module** (`policy_routes[].domains`, `Module.Dnsmasq`): dnsmasq writes the addresses
  its upstream answers for those names into nft sets that pick the WAN (docs/modules/net.md, "按域名"). This needs
  a dnsmasq built with nftset: the image ships Alpine's `dnsmasq-dnssec-nftset` (DNSSEC is compiled in but off);
  plain `dnsmasq` refuses such a config (`dnsmasq --test` in the init script), so the apply rolls back.

- **Ad blocking** (`dns.adblock`, Cd1s/mini-router#30, off by default): blocklists as dnsmasq `local=` lines, no new
  process (see below).

Not included on purpose: AdGuard Home (≈34 MiB, killed by the OOM killer with big lists), DHCPv6-only (no SLAAC) mode (Android cannot use it),
DHCPv6 lease release, MX records.

Cost: no new daemon. Flash: a few KB of Go code in `mr`. RAM: none at rest; stubby (~2 MB RSS) only
when enabled — it already was at home.

## Config reference

### `dhcp` (main LAN) and `networks[].dhcp` (extra networks, type `Pool`)

```yaml
dhcp:
  start: 100              # pool = host numbers inside lan.ipv4
  end: 249
  lease: 12h              # 30m, 12h, 1d, infinite (bare seconds also accepted)
  domain: lan             # local domain: DHCP names answer as <name>.lan
  dns: []                 # option 6; empty = the router's address on that network
  ntp: []                 # option 42; IPv4 addresses only
  search: [lan]           # option 119
  options:                # any other option by number
    - {code: 26, value: "1492"}                                        # interface MTU
    - {code: 121, value: "0.0.0.0/0,192.168.1.6,10.8.0.0/24,192.168.1.10"}  # classless routes
    - {code: 66, value: nas.lan}                                       # PXE / TFTP server
  ipv6:                   # used when lan.ipv6_ra is true (see below)
    mode: slaac
  hosts:                  # static leases
    - {name: nas, mac: "aa:bb:cc:dd:ee:01", ip: 192.168.1.10}
  host_leases:            # optional per-host lease time, keyed by the host's MAC
    "aa:bb:cc:dd:ee:01": infinite

networks:                 # owned by the net module; only `dhcp` belongs to this module
  - name: guest
    ipv4: 192.168.20.1/24
    ipv6_ra: true
    dhcp: {enabled: true, start: 100, end: 199, lease: 2h, dns: [], ntp: [], search: [], options: [], ipv6: {mode: slaac}}
```

Option rules (validation is the security boundary): numbers 1–254; 1, 3, 6, 12, 15, 42, 50–61 and
119 are refused (the router sets them or they belong to the protocol — use `dns` / `ntp` /
`search`); values are comma-separated tokens of `A-Z a-z 0-9 . _ : / @ + = -` only (no spaces,
quotes, `#`, control characters). Options 121 / 249 must start with `0.0.0.0/0,<router>`: a client
that receives classless routes ignores option 3, so a route list without the default route would cut
it off the internet.

`hosts[].name` may not be something dnsmasq reads as a lease time or keyword in `dhcp-host=`
(`12345`, `5m`, `2w`, `infinite`, `ignore` — the last one would stop DHCP for that device);
"设为静态" in the UI turns such a DHCP-supplied name into `host-<n>`.
Devices of the inventory (`devices:`, dev module, [dev.md](dev.md)) are rendered here too, after the
`dhcp.hosts` lines: one `dhcp-host=MAC[,MAC…][,IP],NAME[,lease]` per device (the name becomes its DHCP / DNS
name; `ip:` makes it a static lease). A MAC, name or address may be in `dhcp.hosts` or in `devices`, not in
both. `host_leases` keys must be MACs of `dhcp.hosts` entries or devices (a device takes the lease time of its
first MAC that has one). (It is a separate map because the core test
`render_test.go` builds `Host` with a positional literal; moving it to `hosts[].lease` needs that one
line changed — see the integration notes.)

### IPv6 RA / DHCPv6 (`dhcp.ipv6`, `networks[].dhcp.ipv6`)

On/off stays `lan.ipv6_ra` / `networks[].ipv6_ra` (net module). The prefix is whatever global address
the bridge has (`constructor:`), i.e. the prefix dhcpcd delegated.

| key | default | meaning |
|---|---|---|
| `mode` | `slaac` | `slaac` → `ra-only`; `stateless` → `ra-stateless` (SLAAC + DNS via DHCPv6); `stateful` → DHCPv6 addresses from `start`–`end` **plus** SLAAC (`slaac` keyword, so Android still gets an address) |
| `start`, `end` | `::1000`, `::ffff` | stateful only: interface ids (upper 64 bits must be zero) |
| `lease` | `45m` | prefix / DHCPv6 lifetime, at most 45m: dnsmasq advertises it as both preferred and valid lifetime, RFC 9096 wants preferred ≤ 2700 s, valid ≤ 5400 s; unit required (`3600` alone would read as a prefix length) |
| `dns` | router | RDNSS + DHCPv6 DNS servers, IPv6 only; `"::"` = the router's global address |
| `ra_interval` | 60 | seconds, 4–900 (dnsmasq keeps lifetimes ≥ 3 × the interval; the RFC 9096 cap is 2700 s) |
| `ra_lifetime` | 1800 | router lifetime, 60–9000, ≥ interval |
| `ra_priority` | medium | `high` / `low` |
| `ra_mtu` | 0 | advertised MTU, 0 = not advertised (1280–9000) |

The home config (`ipv6_ra: true`, no `ipv6` block) renders
`dhcp-range=::,constructor:br-lan,ra-only,45m` + `ra-param=br-lan,60,1800`.
An extra network with `ipv6_ra: true` now gets RA even when its DHCPv4 pool is off (before, RA was
only emitted together with a pool).

### `dns`

```yaml
dns:
  cache_size: 8000
  min_cache_ttl: 3600         # dnsmasq caps this at 3600
  use_stale_cache: 3600
  no_negcache: true
  edns_packet_max: 1232
  upstream: isp               # isp | manual | dot
  servers: []                 # manual: ["1.1.1.1", "9.9.9.9#9953", "2606:4700:4700::1111"]
  dot:                        # stubby; rendered when services.stubby.enabled
    port: 5453                # stubby listens on 127.0.0.1:<port> only (not 53)
    servers:                  # default: Cloudflare 1.1.1.1 + 1.0.0.1, TLS name cloudflare-dns.com
      - {address: 1.1.1.1, name: cloudflare-dns.com}
      - {address: 9.9.9.9, name: dns.quad9.net, port: 853}
    bootstrap: []             # upstream=dot: plain DNS for NTP names (default: the DoT servers' IPs, port 53)
  rebind_protection: true
  local_service: true
  redirect: true
  addn_hosts: [/etc/lucky/dnsmasq.hosts]
  servers_file: ""
  records:
    - {name: nas, type: A, value: 192.168.1.10}                  # nas and nas.lan (+ PTR)
    - {name: nas.lan, type: AAAA, value: "fd00::10"}
    - {name: "*.home.example.com", type: A, value: 192.168.1.6}  # the domain and every subdomain
    - {name: photos.lan, type: CNAME, value: nas.lan}
    - {name: 192.168.1.11, type: PTR, value: printer.lan}        # IP or *.in-addr.arpa / *.ip6.arpa
    - {name: _smb._tcp.lan, type: SRV, value: "nas.lan:445"}     # target:port[:priority[:weight]]
    - {name: nas.lan, type: TXT, value: "home server; v=1"}      # 1-255 chars, no " or \
  split:
    - {name: cloudflare-dot, domains_file: /etc/mini-router/dns/cloudflare-dot.domains, server: "127.0.0.1#5453"}
  sovereignty:
    firefox_canary: true      # default: use-application-dns.net → NXDOMAIN
    private_relay: allow      # allow (default) | block: mask.icloud.com / mask-h2.icloud.com → NXDOMAIN
    block_dot: false          # true: LAN → port 853 (DoT / DoQ) refused
    doh_blocklist_file: ""    # /etc/mini-router/dns/doh.ips: LAN → port 443 of these IPs / CIDRs refused
  adblock:
    enabled: false
    lists:                    # https only; plain domains, hosts, adblock (||name^) or dnsmasq (local=/name/) lines
      - https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/multi-onlydomains.txt   # ~165k
      # - https://anti-ad.net/domains.txt                                                         # ~110k, Chinese sites
    allow: [example.com]      # never blocked, with everything under it
    max_domains: 300000       # default; an update above it keeps the previous lists
```

DNS sovereignty (`dns.sovereignty`). Encrypted DNS that bypasses the router doesn't break anything by
itself, but the device then misses local names, the DNS split, policy routes by domain and the proxy's
fake-ip split (ECH does not matter here: the split works on the DNS name, not on TLS SNI).

- `firefox_canary` (default on): Firefox checks `use-application-dns.net` before it turns DoH on by
  itself; NXDOMAIN keeps it on the router's DNS. A user who turns DoH on explicitly keeps it.
- `private_relay: block`: iCloud Private Relay checks `mask.icloud.com` / `mask-h2.icloud.com`; NXDOMAIN
  turns it off on this network and the device shows a notice. Off by default: it is the user's choice.
- `block_dot`: LAN → any port 853, TCP (DoT) and UDP (DoQ), is refused at once (TCP reset / ICMP port
  unreachable), so apps and devices that try DoT fall back to plain DNS. A device with a *strict*
  private DNS host name (Android "Private DNS provider hostname") does not fall back: it loses DNS until
  that setting is changed, which is how you find it. Android's automatic mode asks the network's own DNS
  server (the router) on 853 and falls back as before.
- `doh_blocklist_file`: one IP address or CIDR per line (`#` comments), both families, at most 65536
  entries (e.g. dibdot or HaGeZi's DoH IP list, ~3k entries). LAN → port 443 of them (TCP and HTTP/3)
  is refused. A bad line stops `mr apply` (the error names the line, never its content); edit the file,
  then `mr apply` (or `mr fw`) loads it. Keep it under `/etc/mini-router/dns/` so backups include it.
  Agents and API tokens cannot set it (a `*_file` key).

**Ad blocking** (`dns.adblock`). `mr dns adblock update` downloads the lists (https only, the router's own
connection: not through the proxy), keeps valid names (at least two labels, no IPs; element-hiding rules, exceptions
and `server=/name/#` lines are not names), drops duplicates and names under another listed name, removes the allowed
ones, and writes `/etc/mini-router/state/adblock.conf`: one `local=/name/` per domain, plus `server=/name/#` for an
allowed name under a blocked one (forwarded as usual). Both dnsmasq instances load it (`conf-file=`): a blocked name
and everything under it answer NXDOMAIN. The lists' own hosts, the NTP servers and the local domain are never blocked.

- An update never makes things worse: a list that fails to download, is larger than 64 MiB or does not look like a
  domain list (under half of its lines usable, e.g. an HTML error page) keeps the previous file; so does a result
  above `max_domains`. A new file restarts dnsmasq (and the proxy's dnsmasq): DNS pauses 1–2 s; if dnsmasq does not
  answer again within 30 s the previous file is put back.
- Schedule: crond runs `mr dns adblock update --cron` hourly at a minute fixed per router; it downloads only when the
  file is 20 h old or was built from other settings, so switching it on, or a failed update, is (re)tried within the
  hour. Never while a change waits for confirmation. `mr dns adblock update` / 立即更新 runs it now.
- `mr apply` renders an empty file when there is none (dnsmasq refuses a missing `conf-file`); an existing list is
  never part of a plan or a snapshot.
- Cost: no process. RAM: dnsmasq ≥ 2.86 keeps large `local=` sets compactly (CI prints dnsmasq's RSS with 150k names;
  the proxy's instance holds a second copy). Flash: ~25 bytes a name before UBIFS compression, rewritten once a day.

Both dnsmasq instances (the main one and the proxy's) answer the NXDOMAIN names. The refusals are a
chain of their own (`dns_guard`, prerouting priority mangle − 1) in front of the policy marks and the
proxy's tproxy: a resolver inside a proxied range is refused too, not tunnelled. Only LAN-side bridges
are matched, and the router's own addresses are left alone. Cost: three dnsmasq lines, a few nft rules,
the set (tens of KB for a DoH list).

Upstream modes:

- `isp` (default): `resolv-file=/run/ppp/resolv.conf`, i.e. the DNS servers PPPoE hands out
  (`wan[].peerdns`). Follows the router when it travels.
- `manual`: `no-resolv` + one `server=` per entry (`ip` or `ip#port`, v4 or v6). Port 53 on
  loopback or on the router's own LAN-side addresses (dnsmasq itself — a forwarding loop) is refused,
  here and in `dns.split` / `dns.dot.bootstrap`.
- `dot`: `no-resolv` + `server=127.0.0.1#<dot.port>`; requires `services.stubby.enabled`. NTP host
  names from `system.ntp` get `server=/<name>/<bootstrap>` lines: TLS certificate checks need a correct
  clock, the AX6000 has no RTC, and the clock comes from NTP — without this, DNS and NTP would wait
  for each other forever after a cold boot. stubby retries a failed upstream after 60 s (getdns
  default: 1 h) so DoT recovers right after NTP sets the clock.

Record rules: names are letters, digits, `-`, `_` and dots (≤ 253 chars); an A/AAAA name may not be
all digits or look like an IP address (`host-record=` would read it as a TTL / address); a name
without a dot also gets `.<dhcp.domain>`; a CNAME name may have no other records, CNAME targets must be names dnsmasq
knows locally (records, DHCP hosts, addn-hosts — dnsmasq never resolves a CNAME target upstream).

### Parental control (`dns.parental`, #33)

```yaml
dns:
  parental:
    devices: ["group:kids"]      # device names / group:NAME (dev module)
    safe_search: true            # Google, YouTube (strict), Bing (strict), DuckDuckGo (safe)
    block: [example-games.com]   # NXDOMAIN, subdomains included (at most 512)
```

A third dnsmasq, `mr-parental-dns` (port 5356, no DHCP, `gen/parental-dns.conf`), runs while `devices` resolve to
MACs and `safe_search` or `block` is set. nft chain `parental_dns` (nat prerouting, `dstnat - 10`: ahead of the proxy's
and `dns.redirect`) redirects every udp/tcp 53 packet of those MACs, to any server, to it. It forwards to the main
dnsmasq (to `mr-proxy-dns` while the proxy is on; a device may then not also be in `proxy.bypass`) and adds
`address=/<search host>/<safe-search address>` for www.google.com, the YouTube hosts, www.bing.com and duckduckgo.com
(the providers' published safe-search hosts: 216.239.38.120, 204.79.197.220, 20.43.161.151, fixed in
`mr/mod_dns_parental.go`; with `address=` AAAA gets no answer, so IPv6 cannot bypass it) and `local=/<domain>/` per
blocked domain. Limits: only DNS the router sees — DoH in browsers / apps, DoT, a VPN, a device with a new private MAC,
Google's country domains (google.co.xx) are not covered; `dns.sovereignty` blocks the known DoH / DoT endpoints.

### Precedence (what answers a query)

1. Local data: `dns.records`, DHCP host names, `addn-hosts`, `/etc/hosts`.
2. `server=/domain/` and `address=/domain/` lines — **the longest (most specific) matching domain
   wins, regardless of line order**. A wildcard record (`address=/domain/<ip>`) answers only the
   address family it has: `*.home.example.com A` answers A queries, while AAAA (and TXT, MX, …) for
   those names still go to the matching `server=` line or the default upstream — add an AAAA wildcard
   too if IPv6 clients must not get the public address (verified against dnsmasq 2.91). Plain
   records (`host-record`) and everything under `dhcp.domain` never go upstream (the other types
   answer NODATA). Several `server=/same.domain/` lines are one group (dnsmasq picks among them), not
   "last wins".
3. The default upstream (`dns.upstream`).

Sources of `server=/domain/` lines: `dns.split` (`gen/dns-split.servers`), `dns.servers_file`, the
dot bootstrap lines, and **the proxy module, which appends `server=/domain/127.0.0.1#<port>` (fake-ip
DNS) through the `Dnsmasq` hook at the end of dnsmasq.conf**. Consequences for proxy lists:

- A domain in a proxy list and a *more specific* domain in a split list (or a record): the more
  specific one wins for its subtree.
- The same domain in both a proxy list and a split list makes two upstreams one group — don't;
  keep each domain in one list.
- `stop-dns-rebind` drops upstream answers in private ranges (10/8, 172.16/12, 192.168/16,
  169.254/16, fd00::/8, fe80::/10, …). sing-box's default fake-ip ranges pass (checked against dnsmasq
  2.91: 198.18.0.5 and fc00::5 are answered, 192.168.9.9 is dropped; 100.64/10 also passes); a fake-ip
  range inside the private ranges would need `rebind-domain-ok=` lines from the proxy module.
- `min_cache_ttl: 3600` also applies to fake-ip answers; that is fine while the proxy keeps its
  fake-ip mapping across restarts (sing-box `store_fakeip`).

### Runtime files

| file | owner | restart on change |
|---|---|---|
| `/etc/dnsmasq.conf` | rendered | dnsmasq |
| `/etc/mini-router/gen/dns-split.servers` | rendered | dnsmasq |
| `/etc/stubby/stubby.yml` | rendered when stubby is enabled | stubby (restarted before dnsmasq) |
| `/etc/resolv.conf` | rendered (`nameserver 127.0.0.1`) | — |
| `/tmp/dhcp.leases` | dnsmasq | read only by `mr` |
| `/run/mini-router/dns-querylog` | `mr dns querylog` | read by `rootfs/etc/conf.d/dnsmasq` |

## CLI and API

```
mr dns stats                          dnsmasq cache / upstream statistics (JSON)
mr dns query NAME [TYPE] [SERVER]     ask dnsmasq (or SERVER ip[#port]); TYPE A AAAA CNAME PTR SRV TXT
mr dns leases                         DHCP leases (JSON)
mr dns release IP [MAC]               make dnsmasq drop a DHCPv4 lease
mr dns querylog on [MINUTES]|off|show temporary query logging (default 10 min, max 60)
mr dns adblock status                 ad blocking: domains, last update, per-list results (JSON)
mr dns adblock update [--cron]        download the lists now (--cron: only when due; --no-reload: no restart)
```

Web UI actions (logged-in sessions only): `dns.stats` (GET), `dns.leases` (GET), `dns.release`
(POST `{ip, mac}` — the pair must exist in the lease file and the IP must be inside a LAN network),
`dns.querylog` (GET = state + last 300 lines; POST `{on, minutes}`), `dnslist` (split list editor), `dns.adblock`
(GET = status; POST `{update: true}` starts an update in the background; API tokens: scope operate).
No handler builds a shell command; `rc-service dnsmasq restart` is the only exec, with fixed argv.

## Checks

- Go tests (`mr/mod_dns_test.go`): the home dnsmasq.conf is byte-identical to the previous output;
  records / options / RA / upstream rendering; validation rejects injection (newlines, quotes, commas,
  `#`, spaces, reserved options); stubby.yml parses as YAML; lease parsing; DHCPRELEASE packet bytes;
  DNS message parser against truncation/corruption; statistics against a fake CHAOS server;
  `dnsmasq --test` on a config using every feature in all three upstream modes.
- `tools/ci.d/dns.sh`: stubby listens on loopback only; the rendered **lab** dnsmasq.conf runs for
  real in a throwaway net+mount namespace, every record type is queried through `mr dns query`,
  `mr dns stats` answers, `mr dns release` makes dnsmasq drop a lease, and the canary / Private Relay
  names answer NXDOMAIN (the namespace has no upstream, so only dnsmasq's own answer can say that).
- `tools/ci.d/fw.sh` (lab: `block_dot`, a DoH list with the test "internet" host): LAN and guest → 853
  and → 443 of a listed resolver are refused (IPv4 and IPv6), DoT to a proxied range is refused before
  the proxy socket could take it, the router's own 853 and the resolver's other ports still work.
- `mr/mod_dns_sovereignty_test.go`: defaults, validation, blocklist parsing (bad lines named, not echoed).
- `mr/mod_dns_adblock_test.go`: every list format, subdomain folding and allow, validation, render (empty file only
  when missing), cron line; updates against a TLS test server: unchanged lists do not restart dnsmasq, `--cron`
  skips a fresh file and rebuilds after a settings change, failed / HTML / oversized lists keep the file, a dnsmasq
  that does not come back gets the previous file. `tools/ci.d/dns.sh` runs the real update against a local HTTPS
  server (150k names) and the real dnsmasq answers them.
- stubby 0.4.3 (Alpine 3.24) accepts the rendered stubby.yml (`stubby -C … -i`, checked once in an
  arm64 Alpine container; not part of CI because it needs network access).

## 怎么用

### 网页（网络 › DHCP / IPv6 RA、网络 › DNS、状态 › 终端设备）

- **给家里服务器起名字**：网络 › DNS › 本地记录 → “+ 添加”，名称填 `nas`，类型 A，值 `192.168.1.10`，
  底部“保存并应用”。之后局域网里 `nas` 和 `nas.lan` 都解析到它；应用后路由器会自己查询一遍，
  查不到就自动回滚。想让 `*.home.example.com` 在家里直接走内网（Lucky 反代），名称填
  `*.home.example.com`、值填路由器地址即可。
- **固定 IP**：状态 › 终端设备，在设备那一行点“设为静态”，再“保存并应用”；或在 网络 › DHCP / IPv6 RA ›
  静态分配 手动添加。服务器可以在“租期”列填 `infinite`。
- **释放租约**：状态 › 终端设备 → “释放”。路由器替设备发送 DHCPRELEASE，地址立即回到地址池（设备
  下次续约会重新申请）。
- **网络唤醒**：状态 › 终端设备 和 DHCP / IPv6 RA › 静态分配 每行有“唤醒”，发送 Wake-on-LAN 魔术包
  （sys 模块的 `sys.wol`，见 sys.md）。
- **上游 DNS**：网络 › DNS › 上游与缓存。默认用运营商 DNS（出国换网络自动跟随）；也可以手动指定，
  或全部走 DoT（需同时开启 stubby；NTP 域名会用“引导 DNS”明文解析，保证开机对时）。
- **DHCP 选项**：网络 › DHCP / IPv6 RA › DHCP 选项，按网络设置下发的 DNS、NTP、搜索域和其他编号选项。
- **IPv6**：同页 › IPv6 通告 (RA)。一般保持 SLAAC；需要固定段地址时选“有状态 DHCPv6 + SLAAC”。
- **去广告**：网络 › DNS › 去广告 → 点“+ HaGeZi Multi NORMAL”（或填别的列表地址），打开“启用”，“保存并应用”，
  再点“立即更新”。约半分钟后状态显示拦截的域名数。某个网站被误拦：把它的域名加进“白名单”再保存。
- **防止设备绕过路由器的 DNS**：网络 › DNS › 上游与缓存 › 防绕过。Firefox 金丝雀默认开；需要时打开“拦截 DoT /
  DoQ”，或填一个 DoH 服务器 IP 列表文件。
- **看缓存命中率 / 排查解析**：网络 › DNS › 统计 / 查询日志。查询日志默认关闭，开启会重启 dnsmasq
  （约 1 秒），到时自动关闭，重启路由器也不会保留。

### router.yaml / agent

改 `/etc/mini-router/router.yaml` 里的 `dhcp` / `dns` 段，然后：

```sh
mr validate && mr plan          # 先看会改哪些文件、重启哪些服务
mr apply --confirm 120          # 应用；确认网络正常后再执行 mr confirm
mr confirm
mr dns query nas.lan A          # 写后回读
mr dns stats                    # 命中率、上游查询/失败数
mr dns leases                   # 当前租约
mr dns release 192.168.1.123 aa:bb:cc:dd:ee:ff
mr dns querylog on 10; mr dns querylog show; mr dns querylog off
```

agent 改配置时遵守通用纪律：先读当前值、改完 `mr apply --confirm`、用 `mr dns query` 回读验证、
在变更记录里写清楚。
