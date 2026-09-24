#!/bin/sh
# proxy module checks. Run by tools/ci.sh (OUT, ROOT set; inside its private mount namespace, after
# the home and lab configs were rendered to $OUT/home and $OUT/lab).
#   1. home config: no proxy artefacts at all (the proxy is not configured there)
#   2. lab config: proxy-dns.conf passes `dnsmasq --test`, sing-box.json has a node of every type and
#      passes `sing-box check`
#   3. lab config end to end in network namespaces (needs the official sing-box build of the version
#      the router ships at /opt/sing-box/<version>/sing-box):
#        client ─┐                ┌─ wan: proxy servers of every node type (sing-box, generated from the
#        desktop ─┴─ br-lan  rtr ─┘       rendered outbounds; TLS with a test CA, REALITY with a test key),
#                                         web + UDP echo + subscription on 198.51.100.10
#      rtr runs the real lab nftables ruleset, the proxy lines of network.sh, strict rp_filter with
#      src_valid_mark, the rendered sing-box.json and proxy-dns.conf, and a stand-in main dnsmasq.
#      Checks: fake-ip A/AAAA for proxied domains, TCP over IPv4 and IPv6 fake IPs, CIDR rule over
#      TCP and UDP through Shadowsocks; TCP and UDP through every other node (selector switched per
#      node); the bypass device (desktop MAC) gets real DNS and goes direct; `mr proxy fetch` of the
#      saved subscription with busybox wget.
set -eu
SB_VERSION=1.14.1
# SING_BOX=/path/to/sing-box tools/ci.sh runs the checks with another build (e.g. the router's minimal tags)
SB=${SING_BOX:-/opt/sing-box/$SB_VERSION/sing-box}
H=$OUT/home/etc/mini-router/gen
L=$OUT/lab/etc/mini-router/gen
fail() { echo "FAIL: $*"; exit 1; }

echo "home: no proxy artefacts"
if [ -e "$H/sing-box.json" ] || [ -e "$H/proxy-dns.conf" ]; then fail "home config rendered proxy files"; fi
if grep -q proxy "$OUT/home-nft.nft" "$H/network.sh" "$H/services"; then fail "home config has proxy rules"; fi

echo "lab: proxy-dns.conf"
dnsmasq --test --conf-file="$L/proxy-dns.conf"
grep -qx 'server=/e2e.test/127.0.0.1#1053' "$L/proxy-dns.conf" || fail "proxied domain not forwarded to sing-box"
if grep -qx 'server=/example-b.net/127.0.0.1#5453' "$L/proxy-dns.conf"; then fail "proxied domain kept its dns.split upstream"; fi
[ "$(stat -c %a "$L/sing-box.json")" = 600 ] || fail "sing-box.json (passwords) must be 0600"

if [ ! -x "$SB" ]; then
	echo "sing-box $SB_VERSION not installed at $SB: skipping sing-box check and the end-to-end test"
	exit 0
fi
echo "lab: every node type rendered"
python3 - "$L/sing-box.json" <<'EOF' || fail "lab sing-box.json lacks a node type"
import json, sys
c = json.load(open(sys.argv[1]))
types = {o["type"] for o in c["outbounds"]} | {e["type"] for e in c.get("endpoints", [])}
want = {"shadowsocks", "vless", "vmess", "trojan", "hysteria2", "tuic", "anytls", "socks", "http", "wireguard", "selector", "urltest"}
assert want <= types, sorted(want - types)
assert all(e["type"] == "wireguard" for e in c.get("endpoints", [])), c["endpoints"]
print("ok:", len(c["outbounds"]), "outbounds,", len(c.get("endpoints", [])), "endpoint(s)")
EOF
echo "lab: sing-box check"
"$SB" check -c "$L/sing-box.json"

echo "lab: end to end (network namespaces)"
T=$OUT/proxy-e2e
rm -rf "$T" && mkdir -p "$T"
P=mrpx$$
R=${P}r C=${P}c M=${P}m S=${P}s
cleanup() {
	for n in $R $C $M $S; do
		for pid in $(ip netns pids "$n" 2>/dev/null); do kill "$pid" 2>/dev/null || true; done
		ip netns del "$n" 2>/dev/null || true
	done
}
trap cleanup EXIT
for n in $R $C $M $S; do
	ip netns add "$n"
	ip -n "$n" link set lo up
done
# veth NETNS1 NAME1 NETNS2 NAME2
veth() {
	ip link add "${P}x" type veth peer name "${P}y"
	ip link set "${P}x" netns "$1"
	ip link set "${P}y" netns "$3"
	ip -n "$1" link set "${P}x" name "$2"
	ip -n "$3" link set "${P}y" name "$4"
}

# router
ip -n "$R" link add br-lan type bridge
ip -n "$R" link add br-iot type bridge
veth "$C" eth0 "$R" lanc
veth "$M" eth0 "$R" lanm
veth "$R" w0 "$S" eth0
for d in lanc lanm; do ip -n "$R" link set "$d" master br-lan up; done
ip -n "$R" addr add 192.168.1.6/24 dev br-lan
ip -n "$R" addr add 2001:db8:1::6/64 dev br-lan nodad
ip -n "$R" addr add 192.168.30.1/24 dev br-iot
ip -n "$R" link set br-lan up
ip -n "$R" link set br-iot up
ip -n "$R" addr add 10.0.0.1/24 dev w0
ip -n "$R" link set w0 up
ip -n "$R" route add default via 10.0.0.2
for s in net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1 net.ipv4.conf.all.rp_filter=1 net.ipv4.conf.all.src_valid_mark=1; do
	ip netns exec "$R" sysctl -qw "$s"
done
# flowtable devices must exist; hardware offload flag cannot work on dummies
devs=$(sed -n 's/^[[:space:]]*devices = { \(.*\) }/\1/p' "$L/nftables.nft" | tr -d '",')
for d in $devs; do
	ip -n "$R" link show "$d" >/dev/null 2>&1 || ip -n "$R" link add "$d" type dummy
	ip -n "$R" link set "$d" up
done
sed '/flags offload/d' "$L/nftables.nft" > "$T/nftables.nft"
# variant: without dns.redirect only DNS addressed to the router is taken (fib daddr type local)
sed 's/^  redirect: true/  redirect: false/' "$OUT/lab.yaml" > "$T/lab-noredirect.yaml"
"$OUT/mr-host" -c "$T/lab-noredirect.yaml" -s "$OUT/lab-secrets.yaml" render "$T/noredirect" > /dev/null
grep -q 'th dport 53 fib daddr type local redirect to :1054' "$T/noredirect/etc/mini-router/gen/nftables.nft" || fail "dns.redirect=false variant not rendered"
sed '/flags offload/d' "$T/noredirect/etc/mini-router/gen/nftables.nft" > "$T/nft-noredirect.nft"
ip netns exec "$R" nft -c -f "$T/nft-noredirect.nft"
ip netns exec "$R" nft -f "$T/nftables.nft"
grep -E 'lookup 300|table 300|pref 5200' "$L/network.sh" > "$T/routes.sh"
ip netns exec "$R" sh -e "$T/routes.sh"

# clients: "client" (proxied) and the desktop (bypass by MAC)
ip -n "$C" addr add 192.168.1.100/24 dev eth0
ip -n "$C" addr add 2001:db8:1::100/64 dev eth0 nodad
ip -n "$M" link set eth0 address 02:c3:06:d6:7f:8a
ip -n "$M" addr add 192.168.1.66/24 dev eth0
for n in $C $M; do
	ip -n "$n" link set eth0 up
	ip -n "$n" route add default via 192.168.1.6
done
ip -n "$C" -6 route add default via 2001:db8:1::6

# "internet": Shadowsocks servers + web server + UDP echo, all answering with the peer address
ip -n "$S" addr add 10.0.0.2/24 dev eth0
ip -n "$S" link set eth0 up
ip -n "$S" addr add 198.51.100.10/32 dev lo
ip -n "$S" route add 192.168.1.0/24 via 10.0.0.1

cat > "$T/peer.py" <<'EOF'
# tiny web server + UDP echo that answer with the client address; /sub serves the subscription;
# a TLS 1.3 server on 127.0.0.1:9443 is the site the REALITY server borrows its handshake from
import http.server, socket, socketserver, ssl, sys, threading
T = sys.argv[1]
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        hdr = {}
        if self.path == "/sub?token=lab-not-real":
            b = open(T + "/sub.txt", "rb").read()
            hdr["Subscription-Userinfo"] = "upload=1024; download=2048; total=10737418240; expire=4102444800"
        else:
            b = self.client_address[0].encode()
        self.send_response(200)
        for k, v in hdr.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def log_message(self, *a): pass
class S(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
def udp():
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.bind(("0.0.0.0", 9999))
    while True:
        d, a = u.recvfrom(2048); u.sendto(a[0].encode(), a)
def tls_site():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(T + "/cert.pem", T + "/key.pem")
    ls = socket.socket(); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); ls.bind(("127.0.0.1", 9443)); ls.listen(64)
    def serve(c):
        try:
            with ctx.wrap_socket(c, server_side=True) as t:
                t.settimeout(10); t.recv(1)
        except Exception:
            pass
    while True:
        c, _ = ls.accept()
        threading.Thread(target=serve, args=(c,), daemon=True).start()
threading.Thread(target=udp, daemon=True).start()
threading.Thread(target=tls_site, daemon=True).start()
S(("0.0.0.0", 8080), H).serve_forever()
EOF
cat > "$T/q.py" <<'EOF'
# q.py dns SERVER NAME A|AAAA  -> first address;  q.py udp HOST PORT -> reply
import random, socket, struct, sys
if sys.argv[1] == "udp":
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(4)
    s.sendto(b"ping", (sys.argv[2], int(sys.argv[3]))); print(s.recv(100).decode()); sys.exit(0)
srv, name, qt = sys.argv[2], sys.argv[3], sys.argv[4]
t = 1 if qt == "A" else 28
qid = random.randint(0, 65535)
q = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\0" + struct.pack(">HH", t, 1)
s = socket.socket(socket.AF_INET6 if ":" in srv else socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(4)
s.sendto(q, (srv, 53)); m = s.recv(4096)
an, off = struct.unpack(">H", m[6:8])[0], 12
def skip(o):
    while True:
        l = m[o]
        if l == 0: return o + 1
        if l & 0xC0 == 0xC0: return o + 2
        o += 1 + l
off = skip(off) + 4
for _ in range(an):
    off = skip(off); typ, _, _, rdl = struct.unpack(">HHIH", m[off:off + 10]); off += 10
    if typ == t:
        print(socket.inet_ntop(socket.AF_INET if t == 1 else socket.AF_INET6, m[off:off + rdl])); sys.exit(0)
    off += rdl
print("none")
EOF

# test CA for the TLS servers (the router's outbounds trust it through tls.certificate_path)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -subj /CN=mr-proxy-e2e \
	-addext "subjectAltName=DNS:*.example.net,DNS:example.net,DNS:www.example.com,IP:10.0.0.2" \
	-keyout "$T/key.pem" -out "$T/cert.pem" 2>/dev/null
# private half of the lab-only REALITY key pair (public key in examples/lab.d/55-proxy.yaml)
REALITY_PRIVATE=uHOx455rjfRRwJX1OA00D9jBtxRlltzdiOe1IuIgaEM

# configs derived from the rendered lab files: every node's server moves to the wan namespace, where
# one sing-box inbound per node is generated from the node's own outbound (same credentials, TLS,
# transport); cache in $T. e2e-nodes lists the nodes to send traffic through ("tag tcp|udp").
python3 - "$L/sing-box.json" "$T" "$REALITY_PRIVATE" <<'EOF'
import base64, json, sys
cfg, t, reality_key = json.load(open(sys.argv[1])), sys.argv[2], sys.argv[3]
srv = {"log": {"level": "warn"}, "dns": {"servers": [{"type": "hosts", "tag": "h", "path": [t + "/empty-hosts"], "predefined": {"www.e2e.test": "198.51.100.10"}}]},
       "inbounds": [], "outbounds": [{"type": "direct", "tag": "direct"}], "route": {"final": "direct", "default_domain_resolver": "h"}}
nodes = []
for o in cfg["outbounds"]:
    typ = o["type"]
    if typ not in ("shadowsocks", "vless", "vmess", "trojan", "hysteria2", "tuic", "anytls", "socks", "http"):
        continue
    host = o["server"]
    o["server"] = "10.0.0.2"
    o.pop("server_ports", None)  # port hopping: the test server listens on server_port only
    ib = {"type": typ, "tag": "in-" + o["tag"], "listen": "10.0.0.2", "listen_port": o["server_port"]}
    if typ == "shadowsocks":
        ib.update(method=o["method"], password=o["password"])
    elif typ == "vless":
        ib["users"] = [{"uuid": o["uuid"], "flow": o.get("flow", "")}]
    elif typ == "vmess":
        ib["users"] = [{"uuid": o["uuid"], "alterId": o.get("alter_id", 0)}]
    elif typ in ("trojan", "anytls"):
        ib["users"] = [{"password": o["password"]}]
    elif typ == "hysteria2":
        ib["users"] = [{"password": o["password"]}]
        if "obfs" in o:
            ib["obfs"] = o["obfs"]
    elif typ == "tuic":
        ib["users"] = [{"uuid": o["uuid"], "password": o["password"]}]
        if "congestion_control" in o:
            ib["congestion_control"] = o["congestion_control"]
    elif "username" in o:  # socks, http
        ib["users"] = [{"username": o["username"], "password": o.get("password", "")}]
    if "transport" in o:
        ib["transport"] = o["transport"]
    tls = o.get("tls")
    if tls:
        tls.setdefault("server_name", host)  # what the client sends before the server address moved
        stls = {"enabled": True, "server_name": tls["server_name"]}
        if "reality" in tls:
            stls["reality"] = {"enabled": True, "handshake": {"server": "127.0.0.1", "server_port": 9443},
                               "private_key": reality_key, "short_id": [tls["reality"].get("short_id", "")]}
        else:
            stls.update(certificate_path=t + "/cert.pem", key_path=t + "/key.pem")
            if "alpn" in tls:
                stls["alpn"] = tls["alpn"]
            if not tls.get("insecure"):
                tls["certificate_path"] = t + "/cert.pem"
        ib["tls"] = stls
    srv["inbounds"].append(ib)
    nodes.append("%s %s" % (o["tag"], "tcp" if o.get("network") == "tcp" or typ == "http" else "udp"))
cfg["experimental"]["cache_file"]["path"] = t + "/cache.db"
json.dump(cfg, open(t + "/router.json", "w"), indent=1)
json.dump(srv, open(t + "/server.json", "w"), indent=1)
open(t + "/e2e-nodes", "w").write("\n".join(nodes) + "\n")
open(t + "/empty-hosts", "w").close()
# the saved lab subscription (proxy_sub_airport): base64 share links, as subscription services send them
b64 = lambda s: base64.urlsafe_b64encode(s.encode()).decode().rstrip("=")
links = ["ss://" + b64("aes-128-gcm:sub-pass-1") + "@203.0.113.50:8388#%F0%9F%87%AD%F0%9F%87%B0%20%E9%A6%99%E6%B8%AF%2001",
         "vless://1b4a9b3c-6f0e-4d3a-9d2b-3c5e7f901a09@203.0.113.51:443?encryption=none&flow=xtls-rprx-vision&security=reality"
         "&sni=www.example.com&fp=chrome&pbk=LHrjuwEq6GjVwsi-cALKBZ7shC7yUshr_0MQBbg5qQA&sid=ab12&type=tcp#sub-reality",
         "hysteria2://sub-pass-2@203.0.113.52:443,20000-21000/?sni=hy.example.net&obfs=salamander&obfs-password=sub-obfs#sub-hy2",
         "tuic://1b4a9b3c-6f0e-4d3a-9d2b-3c5e7f901a0a:sub-pass-3@203.0.113.53:443?alpn=h3&congestion_control=bbr#sub-tuic",
         "ssr://bm90IHN1cHBvcnRlZA"]
open(t + "/sub.txt", "w").write(base64.b64encode("\r\n".join(links).encode()).decode())
EOF
"$SB" check -c "$T/router.json"
"$SB" check -c "$T/server.json"

ip netns exec "$S" python3 "$T/peer.py" "$T" > "$T/peer.log" 2>&1 &
ip netns exec "$S" "$SB" run -c "$T/server.json" > "$T/server.log" 2>&1 &
ip netns exec "$R" "$SB" run --disable-color -c "$T/router.json" -D "$T" > "$T/router.log" 2>&1 &
# stand-in for the main dnsmasq (real answers for bypass devices; local names for mr-proxy-dns)
ip netns exec "$R" dnsmasq --keep-in-foreground --pid-file= --user=root --conf-file=/dev/null --no-resolv --no-hosts \
	--interface=br-lan --listen-address=127.0.0.1 --bind-dynamic --address=/e2e.test/198.51.100.10 > "$T/main-dns.log" 2>&1 &
# (dnsmasq refuses to start when the resolv-file directory is missing; pppd's is not here)
: > "$T/resolv.conf"
sed "s#^resolv-file=.*#resolv-file=$T/resolv.conf#" "$L/proxy-dns.conf" > "$T/proxy-dns.conf"
ip netns exec "$R" dnsmasq --keep-in-foreground --pid-file= --user=root --conf-file="$T/proxy-dns.conf" > "$T/proxy-dns.log" 2>&1 &

q() { ns=$1; shift; ip netns exec "$ns" python3 "$T/q.py" "$@" 2>/dev/null || echo error; }
logs() {
	for f in "$T"/*.log; do
		echo "--- $f"
		tail -20 "$f"
	done
	echo "--- rtr sockets / rules / counters"
	ip netns exec "$R" ss -lntup || true
	ip netns exec "$R" ip rule || true
	ip netns exec "$R" nft list chain inet mr proxy_dns || true
	ip netns exec "$R" nft list chain inet mr proxy_tp4 || true
	ip netns exec "$C" python3 "$T/q.py" dns 192.168.1.6 www.e2e.test A || true
}
i=0
until [ "$(q "$C" dns 192.168.1.6 www.e2e.test A)" != error ]; do
	i=$((i + 1))
	[ $i -lt 30 ] || { logs; fail "proxy DNS never answered"; }
	sleep 0.5
done

a4=$(q "$C" dns 192.168.1.6 www.e2e.test A)
a6=$(q "$C" dns 2001:db8:1::6 www.e2e.test AAAA)
am=$(q "$M" dns 192.168.1.6 www.e2e.test A)
echo "client A=$a4 AAAA=$a6, desktop A=$am"
case $a4 in 198.18.* | 198.19.*) ;; *) logs; fail "client did not get a fake IPv4 ($a4)" ;; esac
case $a6 in fc00:*) ;; *) logs; fail "client did not get a fake IPv6 ($a6)" ;; esac
[ "$am" = 198.51.100.10 ] || { logs; fail "bypass device did not get the real answer ($am)"; }
# dns.redirect (lab): DNS sent to some server inside a proxied range is hijacked as well, not tunnelled
ah=$(q "$C" dns 198.51.100.10 www.e2e.test A)
[ "$ah" = "$a4" ] || { logs; fail "DNS to a proxied range was not hijacked ($ah)"; }

get() { ip netns exec "$1" curl -s --max-time 8 -H 'Host: www.e2e.test' "$2" || echo error; }
v4=$(get "$C" "http://$a4:8080/")
v6=$(get "$C" "http://[$a6]:8080/")
cidr=$(get "$C" http://198.51.100.10:8080/)
udp=$(q "$C" udp 198.51.100.10 9999)
mac=$(get "$M" http://198.51.100.10:8080/)
echo "web server saw: fake4=$v4 fake6=$v6 cidr=$cidr udp=$udp desktop=$mac"
# through the proxy the server sees the Shadowsocks server's own address, directly it sees the client
[ "$v4" = 198.51.100.10 ] || { logs; fail "TCP to the fake IPv4 did not go through the proxy"; }
[ "$v6" = 198.51.100.10 ] || { logs; fail "TCP to the fake IPv6 did not go through the proxy"; }
[ "$cidr" = 198.51.100.10 ] || { logs; fail "TCP to a proxied CIDR did not go through the proxy"; }
[ "$udp" = 198.51.100.10 ] || { logs; fail "UDP to a proxied CIDR did not go through the proxy"; }
[ "$mac" = 192.168.1.66 ] || { logs; fail "bypass device was proxied or blocked"; }

# a client behind a LAN-side router (lab static route 10.9.0.0/16 via 192.168.1.50): strict rp_filter
# must not drop its proxied packets (the reverse-path check must not see table 300)
grep -E '^ip -4 route replace 10\.9\.' "$L/network.sh" | ip netns exec "$R" sh -e
ip -n "$C" addr add 192.168.1.50/24 dev eth0
ip -n "$C" addr add 10.9.1.2/32 dev lo
behind=$(ip netns exec "$C" curl -s --max-time 8 --interface 10.9.1.2 http://198.51.100.10:8080/ || echo error)
echo "client behind a LAN router: web server saw $behind"
[ "$behind" = 198.51.100.10 ] || { logs; fail "client behind a LAN static route not proxied ($behind)"; }

# a port forward whose remote peer is inside a proxied CIDR: the LAN host's replies belong to an inbound
# connection and must be forwarded, not taken by tproxy (only the original direction is proxied)
ip netns exec "$R" nft add rule inet mr dstnat iifname w0 tcp dport 12000 dnat ip to 192.168.1.100:12000
ip netns exec "$C" python3 -m http.server 12000 --bind 192.168.1.100 --directory "$T" > "$T/fwd.log" 2>&1 &
i=0
until ip netns exec "$C" ss -ltn | grep -q ':12000 '; do
	i=$((i + 1))
	[ $i -lt 20 ] || fail "port-forward test server did not start"
	sleep 0.25
done
fwd=$(ip netns exec "$S" curl -s -o /dev/null -w '%{http_code}' --max-time 5 --interface 198.51.100.10 http://10.0.0.1:12000/ || true)
echo "port forward from a proxied CIDR: HTTP $fwd"
[ "$fwd" = 200 ] || { logs; fail "port forward from a proxied CIDR: the LAN host's replies were taken by the proxy (HTTP $fwd)"; }

# mr's own view: DNS probes (post-apply Verify uses the same code) and the clash API client
MR="$OUT/mr-host -c $OUT/lab.yaml -s $OUT/lab-secrets.yaml"
# shellcheck disable=SC2086
ip netns exec "$R" $MR proxy check || { logs; fail "mr proxy check"; }
# shellcheck disable=SC2086
ip netns exec "$R" $MR proxy status > "$T/status.json"
python3 - "$T/status.json" "$ROOT/mr/testdata/secrets.d/proxy.yaml" <<'EOF' || fail "mr proxy status: unexpected content"
import json, re, sys
s = json.load(open(sys.argv[1]))
assert s["running"] and s["version"], s
assert s["proxies"]["pick"]["now"] == "jp1" and s["proxies"]["auto"]["type"] == "URLTest", s["proxies"]
# every lab proxy secret (node credentials, custom JSON, the subscription URL) is referenced and reported set
want = {m.group(1): True for m in re.finditer(r"^(proxy_[^:\s]+):", open(sys.argv[2]).read(), re.M)}
assert s["secrets_set"] == want, (s["secrets_set"], want)
assert s["download_total"] > 0 and s["upload_total"] > 0, s
print("mr proxy status: running", s["version"], "- traffic", s["upload_total"], "/", s["download_total"])
EOF
# manual group switch and latency test through the same loopback API client
# shellcheck disable=SC2086
ip netns exec "$R" $MR proxy select pick sg1 > /dev/null || fail "mr proxy select"
# shellcheck disable=SC2086
ip netns exec "$R" $MR proxy status > "$T/status2.json"
python3 -c 'import json,sys; assert json.load(open(sys.argv[1]))["proxies"]["pick"]["now"] == "sg1"' "$T/status2.json" || fail "selector switch not effective"
# shellcheck disable=SC2086
ip netns exec "$R" $MR proxy delay > "$T/delay.json" || fail "mr proxy delay"
python3 - "$T/delay.json" "$T/e2e-nodes" <<'EOF' || fail "mr proxy delay output"
import json, sys
d = json.load(open(sys.argv[1]))
want = {l.split()[0] for l in open(sys.argv[2]) if l.strip()} | {"wg"}
assert set(d["results"]) == want, (sorted(d["results"]), sorted(want))
print("mr proxy delay:", d["results"])
EOF

# every node type end to end: switch the selector to the node, then TCP (and UDP where the node
# relays it) to the proxied CIDR must arrive from the proxy server's side, not from the client
while read -r tag net; do
	# shellcheck disable=SC2086
	ip netns exec "$R" $MR proxy select pick "$tag" > /dev/null || { logs; fail "mr proxy select pick $tag"; }
	tcp=$(get "$C" http://198.51.100.10:8080/)
	udp=-
	[ "$net" = tcp ] || udp=$(q "$C" udp 198.51.100.10 9999)
	echo "node $tag: tcp=$tcp udp=$udp"
	[ "$tcp" = 198.51.100.10 ] || { logs; fail "TCP through node $tag did not work ($tcp)"; }
	[ "$net" = tcp ] || [ "$udp" = 198.51.100.10 ] || { logs; fail "UDP through node $tag did not work ($udp)"; }
done < "$T/e2e-nodes"

# subscription import with busybox wget (the router's downloader): the saved lab subscription points
# at the web server above; `mr proxy fetch` must list the usable nodes, report the bad link, show the
# traffic header and keep credentials hidden unless asked
if command -v busybox > /dev/null && busybox --list | grep -qx wget; then
	mkdir -p "$T/bin"
	ln -sf "$(command -v busybox)" "$T/bin/wget"
	# shellcheck disable=SC2086
	ip netns exec "$R" env PATH="$T/bin:$PATH" $MR proxy fetch airport > "$T/fetch.out" 2> "$T/fetch.err" || { cat "$T/fetch.err"; fail "mr proxy fetch airport"; }
	cat "$T/fetch.out" "$T/fetch.err"
	[ "$(grep -c '^    - {name: ' "$T/fetch.out")" = 4 ] || fail "subscription: want 4 nodes"
	grep -q '^    - {name: HK-01, server: 203.0.113.50, port: 8388, method: aes-128-gcm, password_secret: proxy_hk-01_password}$' "$T/fetch.out" || fail "subscription: ss node"
	grep -q 'reality_public_key: LHrjuwEq6GjVwsi-cALKBZ7shC7yUshr_0MQBbg5qQA' "$T/fetch.out" || fail "subscription: reality node"
	grep -q "hop_ports: '443,20000-21000'" "$T/fetch.out" || fail "subscription: hysteria2 port hopping"
	grep -q '^# subscription: upload 1024, download 2048, total 10737418240 bytes, expires 2100-01-01$' "$T/fetch.out" || fail "subscription: traffic header (wget -S)"
	grep -q '^line 5: ShadowsocksR is not supported' "$T/fetch.err" || fail "subscription: bad link not reported"
	if grep -q 'sub-pass' "$T/fetch.out" "$T/fetch.err"; then fail "subscription credentials printed without --secrets"; fi
	# shellcheck disable=SC2086
	ip netns exec "$R" env PATH="$T/bin:$PATH" $MR proxy fetch --secrets http://198.51.100.10:8080/sub?token=lab-not-real 2> /dev/null | grep -q '^proxy_hk-01_password: sub-pass-1$' || fail "subscription: --secrets"
	# shellcheck disable=SC2086
	if ip netns exec "$R" env PATH="$T/bin:$PATH" $MR proxy fetch http://198.51.100.10:8080/nothing-here?token=x > /dev/null 2> "$T/fetch.err"; then fail "a page without share links was accepted"; fi
	echo "subscription fetch (busybox wget): ok"
else
	echo "busybox wget not installed: skipping the subscription fetch test"
fi

# sing-box down: proxied destinations are dropped (fail closed), never sent direct
for pid in $(ip netns pids "$R"); do
	case $(cat "/proc/$pid/comm" 2>/dev/null) in
	sing-box | dnsmasq) echo "rtr $(cat "/proc/$pid/comm") $(grep VmRSS "/proc/$pid/status")" ;;
	esac
	case $(cat "/proc/$pid/comm" 2>/dev/null) in sing-box) kill "$pid" ;; esac
done
sleep 1
down=$(ip netns exec "$C" curl -s --max-time 3 http://198.51.100.10:8080/ || echo blocked)
[ "$down" = blocked ] || fail "with sing-box down a proxied CIDR went out directly ($down)"
[ "$(get "$M" http://198.51.100.10:8080/)" = 192.168.1.66 ] || fail "bypass device affected by sing-box being down"
echo "proxy end to end: ok"
