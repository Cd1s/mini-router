#!/bin/sh
# sys module: the HTTPS reverse proxy (services.edge, `mr edge serve`). Run by tools/ci.sh inside its
# private mount namespace (tmpfs on /etc/mini-router), with OUT and ROOT set and the home / lab configs
# rendered to $OUT/home, $OUT/lab. Never contacts Let's Encrypt or Cloudflare: the certificate is a
# test CA's, placed where `mr edge renew` would write it.
#  1. rendering: home has no trace of it; lab: edge.json (no secrets), mr-edge enabled, the host-records
#     in dnsmasq.conf, the firewall lines, `mr edge status` offline (certificates missing, no token)
#  2. the real process in a network namespace, the rendered lab edge.json, a backend on a LAN address:
#     HTTP/1.1 and HTTP/2 through it, headers to the upstream, unknown SNI refused, Host ≠ SNI → 421,
#     a WebSocket-style upgrade, SIGHUP picks up a new certificate
#  3. the WAN side through the rendered nftables lines (a second namespace as the internet, IPv4 and
#     IPv6): the port is redirected to the WAN listener, where lan-only routes fail the handshake and the
#     internal port itself is not reachable; the same route works from the LAN
#  4. memory: RSS idle and after 200 concurrent TLS clients × 20 requests (GOMEMLIMIT as in the init script)
set -eu
: "${OUT:?}" "${ROOT:?}"
MR=$OUT/mr-host
H=$OUT/home L=$OUT/lab
fail() { echo "FAIL: $*"; exit 1; }
ok() { echo "ok: $*"; }

# 1. rendering
# home: the reverse proxy on 443, open, the route hosts answered on the LAN (A + AAAA)
[ -e "$H/etc/mini-router/gen/edge.json" ] || fail "home: no edge.json"
grep -qx 'mr-edge' "$H/etc/mini-router/gen/services" || fail "home: mr-edge not enabled"
grep -q 'dport 443 redirect to :44300 comment "edge"' "$OUT/home-nft.nft" || fail "home: no edge redirect in the firewall"
grep -q '^interface-name=.*,br-lan$' "$H/etc/dnsmasq.conf" || fail "home: no interface-name in dnsmasq.conf"
E=$L/etc/mini-router/gen/edge.json
grep -qx 'mr-edge' "$L/etc/mini-router/gen/services" || fail "lab: mr-edge not enabled"
python3 - "$E" <<'EOF' || fail "lab edge.json"
import json, sys
c = json.load(open(sys.argv[1]))
assert c["port"] == 8443 and c["wan_port"] == 44300 and c["certs"] == "/etc/mini-router/state/edge", c
got = [(r["name"], r["host"], r["cert"], r.get("allow", [])) for r in c["routes"]]
assert got == [("nas", "nas.example.com", "_.example.com", []), ("ha", "ha.example.com", "_.example.com", ["lan", "198.51.100.0/24"]),
               ("cam", "cam.lab.example.org", "cam.lab.example.org", ["lan"]), ("tailnet-app", "app.example.com", "_.example.com", []),
               ("admin-ui", "admin.example.com", "_.example.com", ["lan"])], got
EOF
if grep -q 'lab-token\|cf_ddns_token' "$E"; then fail "edge.json names the token"; fi
[ "$(stat -c %a "$E")" = 644 ] || fail "edge.json mode"
for h in nas.example.com ha.example.com cam.lab.example.org app.example.com admin.example.com; do
	grep -qx "interface-name=$h,br-lan" "$L/etc/dnsmasq.conf" || fail "lab dnsmasq: no interface-name for $h"
done
if grep -q 'old.example.com' "$L/etc/dnsmasq.conf"; then fail "lab dnsmasq: a disabled route resolves"; fi
grep -q 'fib daddr type local tcp dport { 8443, 10443 } redirect to :44300 comment "edge"' "$OUT/lab-nft.nft" || fail "lab nft: no redirect"
grep -q 'tcp dport 44300 ct status dnat accept comment "edge"' "$OUT/lab-nft.nft" || fail "lab nft: no WAN accept"
CFG="-c $OUT/lab.yaml -s $OUT/lab-secrets.yaml"
# shellcheck disable=SC2086
"$MR" $CFG edge status > "$OUT/edge-status.json"
python3 - "$OUT/edge-status.json" <<'EOF' || fail "lab edge status (offline)"
import json, sys
s = json.load(open(sys.argv[1]))
assert s["enabled"] and s["port"] == 8443 and s["open"] and not s["serving"], s
assert [(c["name"], c["state"]) for c in s["certs"]] == [("_.example.com", "missing"), ("cam.lab.example.org", "missing")], s["certs"]
assert [r["wan"] for r in s["routes"]] == [True, True, False, True, False], s["routes"]
EOF
if grep -q 'lab-token' "$OUT/edge-status.json"; then fail "edge status shows the token"; fi
ok "edge rendering: home untouched; lab edge.json, dnsmasq host-records, firewall, offline status"

# 2. the process. Certificates of a test CA whose name marks it as a staging CA (the lab uses staging).
T=$OUT/edge
rm -rf "$T" && mkdir -p "$T" /etc/mini-router/state/edge /run/mr-edge
mount -t tmpfs tmpfs /run/mr-edge # private mount namespace: the status file stays in this run
cert() { # cert NAME SANs: a leaf of the test CA + its key, as `mr edge renew` writes <NAME>.pem
	openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj "/CN=$1" -keyout "$T/$1.key" -out "$T/$1.csr" 2>/dev/null
	# the extensions a strict verifier (Python 3.13: VERIFY_X509_STRICT) wants, like a real CA's leaf
	printf 'subjectAltName=%s\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n' "$2" > "$T/$1.ext"
	openssl x509 -req -in "$T/$1.csr" -CA "$T/ca.pem" -CAkey "$T/ca.key" -CAcreateserial -days 2 -extfile "$T/$1.ext" -out "$T/$1.crt" 2>/dev/null
	cat "$T/$1.crt" "$T/ca.pem" "$T/$1.key" > "/etc/mini-router/state/edge/$1.pem"
	chmod 600 "/etc/mini-router/state/edge/$1.pem"
}
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -subj "/CN=(STAGING) mr ci CA" \
	-addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
	-keyout "$T/ca.key" -out "$T/ca.pem" 2>/dev/null
cert _.example.com "DNS:example.com,DNS:*.example.com"
# shellcheck disable=SC2086
"$MR" $CFG edge status | python3 -c 'import json,sys; s=json.load(sys.stdin); assert [c["state"] for c in s["certs"]] == ["ok", "missing"], s["certs"]' ||
	fail "edge status with a certificate"

NS=mrciedge$$ NW=mrciedgew$$
ip netns add "$NS"
ip netns add "$NW"
EDGE='' BACK=''
cleanup() {
	# shellcheck disable=SC2086
	kill $EDGE $BACK 2>/dev/null || :
	ip netns del "$NS" 2>/dev/null || :
	ip netns del "$NW" 2>/dev/null || :
}
trap cleanup EXIT
ip -n "$NS" link set lo up
ip -n "$NS" link add lan0 type dummy
ip -n "$NS" addr add 192.168.1.6/24 dev lan0
ip -n "$NS" addr add 192.168.1.10/24 dev lan0
ip -n "$NS" addr add 192.168.1.20/24 dev lan0 # ha's host, nothing listening: refused at once (502)
ip -n "$NS" link set lan0 up
# the WAN: pppoe-wan (a name the rendered rules match) towards a second namespace
ip -n "$NS" link add pppoe-wan type veth peer name wan0 netns "$NW"
ip -n "$NS" addr add 203.0.113.1/24 dev pppoe-wan
ip -n "$NS" -6 addr add 2001:db8:e::1/64 dev pppoe-wan nodad
ip -n "$NS" link set pppoe-wan up
ip -n "$NW" link set lo up
ip -n "$NW" addr add 203.0.113.2/24 dev wan0
ip -n "$NW" -6 addr add 2001:db8:e::2/64 dev wan0 nodad
ip -n "$NW" link set wan0 up

# the backend (nas: 192.168.1.10:5000): echoes the request line and the forwarded headers as JSON;
# an Upgrade: websocket request gets 101 and then every chunk back with "echo:" in front
ip netns exec "$NS" python3 - <<'EOF' > "$T/backend.log" 2>&1 &
import json, socketserver
class H(socketserver.StreamRequestHandler):
    def handle(self):
        while True:
            line = self.rfile.readline()
            if not line:
                return
            hdrs = {}
            while True:
                l = self.rfile.readline().decode()
                if l in ("\r\n", "\n", ""):
                    break
                k, _, v = l.partition(":")
                hdrs[k.strip().lower()] = v.strip()
            if hdrs.get("upgrade") == "websocket":
                self.wfile.write(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
                self.wfile.flush()
                while True:
                    d = self.request.recv(4096)
                    if not d:
                        return
                    self.request.sendall(b"echo:" + d)
            n = int(hdrs.get("content-length") or 0)
            if n:
                self.rfile.read(n)
            body = json.dumps({"req": line.decode().strip(), "host": hdrs.get("host"), "xff": hdrs.get("x-forwarded-for"),
                               "proto": hdrs.get("x-forwarded-proto")}).encode()
            self.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n" % len(body) + body)
            self.wfile.flush()
class S(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 512
S(("192.168.1.10", 5000), H).serve_forever()
EOF
BACK=$!
ip netns exec "$NS" env GOGC=50 GOMEMLIMIT=24MiB "$MR" edge serve -c "$E" > "$T/edge.log" 2>&1 &
EDGE=$!
i=0
while [ ! -s /run/mr-edge/status.json ] && [ $i -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
[ -s /run/mr-edge/status.json ] || { cat "$T/edge.log"; fail "mr edge serve did not start"; }
python3 - "$E" "$EDGE" <<'EOF' || fail "status.json"
import hashlib, json, sys
st = json.load(open("/run/mr-edge/status.json"))
assert st["pid"] == int(sys.argv[2]) and st["port"] == 8443 and st["wan_port"] == 44300, st
assert st["conf"] == hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest()[:16], st
EOF
edge_rss() { awk '/^VmRSS/ { r = $2 } /^VmHWM/ { h = $2 } /^RssAnon/ { a = $2 } END { print r, h, a }' "/proc/$EDGE/status"; } # "RSS peak anonymous" in kB
i=0
until ip netns exec "$NS" python3 -c 'import socket; socket.create_connection(("192.168.1.10", 5000), 1)' 2>/dev/null; do
	i=$((i + 1))
	[ $i -lt 50 ] || fail "backend did not start: $(cat "$T/backend.log")"
	sleep 0.1
done
sleep 1
idle=$(edge_rss)

# curl through the proxy: NS = the LAN side (the main listener), NW = the internet
c() { # c NS HOST ADDR PORT [curl args]: prints "<http code> <http version> <body>" or "error <curl exit>"
	ns=$1 host=$2 addr=$3 port=$4
	shift 4
	out=$(ip netns exec "$ns" curl -sS --max-time 5 --cacert "$T/ca.pem" --resolve "$host:$port:$addr" \
		-w '\n%{http_code} %{http_version}' "$@" "https://$host:$port/p?q=1" 2>/dev/null) || { echo "error $?"; return 0; }
	printf '%s %s\n' "$(echo "$out" | tail -n 1)" "$(echo "$out" | head -n 1)"
}
r=$(c "$NS" nas.example.com 192.168.1.6 8443 --http2 -H 'X-Forwarded-For: 192.0.2.66')
case $r in '200 2 {"req": "GET /p?q=1 HTTP/1.1", "host": "nas.example.com:8443", "xff": "192.168.1.6", "proto": "https"}') ;; *) fail "LAN, HTTP/2: $r" ;; esac
# basic auth (the lab's tailnet-app route): no credentials → 401; the right ones get past it (to a 502: no upstream here)
r=$(c "$NS" app.example.com 192.168.1.6 8443)
case $r in "401 "*) ;; *) fail "basic auth: no credentials must be 401: $r" ;; esac
r=$(c "$NS" app.example.com 192.168.1.6 8443 -u alice:wrong)
case $r in "401 "*) ;; *) fail "basic auth: a wrong password must be 401: $r" ;; esac
r=$(c "$NS" app.example.com 192.168.1.6 8443 -u alice:lab-basic-auth-pw)
case $r in "502 "*) ;; *) fail "basic auth: the right password must reach the upstream (502 here): $r" ;; esac
r=$(c "$NS" nas.example.com 192.168.1.6 8443 --http1.1)
case $r in "200 1.1 "*) ;; *) fail "LAN, HTTP/1.1: $r" ;; esac
r=$(c "$NS" ha.example.com 192.168.1.6 8443)
case $r in "502 "*) ;; *) fail "ha (nothing listens on 192.168.1.20:8123) should be 502: $r" ;; esac
r=$(c "$NS" other.example.com 192.168.1.6 8443)
case $r in "error "*) ;; *) fail "unknown SNI answered: $r" ;; esac
r=$(c "$NS" cam.lab.example.org 192.168.1.6 8443)
case $r in "error "*) ;; *) fail "a route without its certificate answered: $r" ;; esac
r=$(ip netns exec "$NS" curl -sS --max-time 5 --cacert "$T/ca.pem" --resolve nas.example.com:8443:192.168.1.6 \
	-H 'Host: admin.example.com' -o /dev/null -w '%{http_code}' https://nas.example.com:8443/ 2>/dev/null || echo error)
[ "$r" = 421 ] || fail "Host ≠ SNI: $r"
ip netns exec "$NS" python3 - "$T/ca.pem" <<'EOF' || fail "WebSocket upgrade through the proxy"
import socket, ssl, sys
ctx = ssl.create_default_context(cafile=sys.argv[1])
ctx.set_alpn_protocols(["http/1.1"])
s = ctx.wrap_socket(socket.create_connection(("192.168.1.6", 8443), timeout=5), server_hostname="nas.example.com")
s.sendall(b"GET /ws HTTP/1.1\r\nHost: nas.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
          b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
head = b""
while b"\r\n\r\n" not in head:
    head += s.recv(1)
assert head.startswith(b"HTTP/1.1 101"), head
for msg in (b"hello", b"second"):
    s.sendall(msg)
    got = s.recv(64)
    assert got == b"echo:" + msg, got
EOF
# SIGHUP: a new certificate (another serial) is served without a restart
serial() { echo | ip netns exec "$NS" openssl s_client -connect 192.168.1.6:8443 -servername nas.example.com 2>/dev/null | openssl x509 -noout -serial; }
s1=$(serial)
cert _.example.com "DNS:example.com,DNS:*.example.com"
kill -HUP "$EDGE"
sleep 0.3
s2=$(serial)
[ -n "$s1" ] && [ "$s1" != "$s2" ] && kill -0 "$EDGE" || fail "SIGHUP reload: $s1 → $s2"
ok "mr edge serve: HTTP/2 + HTTP/1.1, X-Forwarded-*, 502, unknown SNI / no certificate refused, 421, WebSocket, SIGHUP reload"

# 3. the WAN side through the rendered firewall lines (a minimal table: the edge's dstnat + input lines,
#    then what the real input chain does with the rest of the WAN: drop)
{
	echo 'table inet edgeci {'
	echo '	chain dstnat { type nat hook prerouting priority dstnat; policy accept;'
	grep 'redirect to :44300 comment "edge"' "$OUT/lab-nft.nft"
	echo '	}'
	echo '	chain input { type filter hook input priority filter; policy accept;'
	echo '		ct state established,related accept'
	echo '		meta l4proto ipv6-icmp accept' # neighbour discovery (the real chain accepts the ND types)
	grep 'tcp dport 44300 ct status dnat accept comment "edge"' "$OUT/lab-nft.nft"
	echo '		iifname "pppoe-wan" drop'
	echo '	}'
	echo '}'
} > "$T/edge.nft"
ip netns exec "$NS" nft -f "$T/edge.nft"
for a in 203.0.113.1 "[2001:db8:e::1]"; do
	r=$(c "$NW" nas.example.com "$a" 8443)
	case $r in '200 2 {"req": "GET /p?q=1 HTTP/1.1", "host": "nas.example.com:8443", "xff": "'*) ;; *) fail "WAN $a: nas: $r" ;; esac
	r=$(c "$NW" ha.example.com "$a" 8443)
	case $r in "error "*) ;; *) fail "WAN $a: the lan-only route ha answered: $r" ;; esac
	r=$(c "$NW" admin.example.com "$a" 8443)
	case $r in "error "*) ;; *) fail "WAN $a: the lan-only route admin-ui answered: $r" ;; esac
	r=$(c "$NW" nas.example.com "$a" 44300 --connect-timeout 2)
	case $r in "error "*) ;; *) fail "WAN $a: the internal WAN port is reachable directly: $r" ;; esac
done
r=$(c "$NW" nas.example.com 203.0.113.1 8443)
case $r in *'"xff": "203.0.113.2"'*) ;; *) fail "WAN client address not forwarded: $r" ;; esac
r=$(c "$NS" ha.example.com 203.0.113.1 8443)
case $r in "502 "*) ;; *) fail "LAN client to the WAN address (hairpin) is not LAN: $r" ;; esac
ok "WAN side: port redirected to the WAN listener (IPv4 + IPv6), lan-only routes refused there, internal port closed; hairpin from the LAN is LAN"

# 4. memory
ip netns exec "$NS" python3 - "$T/ca.pem" <<'EOF' || fail "load test"
import http.client, socket, ssl, sys, threading
ctx = ssl.create_default_context(cafile=sys.argv[1])
ctx.set_alpn_protocols(["http/1.1"])
errs, lock = [], threading.Lock()
def worker():
    try:
        s = ctx.wrap_socket(socket.create_connection(("192.168.1.6", 8443), timeout=20), server_hostname="nas.example.com")
        for _ in range(20):
            s.sendall(b"GET /load HTTP/1.1\r\nHost: nas.example.com\r\n\r\n")
            r = http.client.HTTPResponse(s)
            r.begin()
            r.read()
            if r.status != 200:
                raise Exception("status %d" % r.status)
        s.close()
    except Exception as e:
        with lock:
            errs.append(str(e))
ts = [threading.Thread(target=worker) for _ in range(200)]
for t in ts:
    t.start()
for t in ts:
    t.join()
assert not errs, errs[:5]
EOF
loaded=$(edge_rss)
echo "mr edge serve memory (kB, x86_64, 'RSS peak anonymous'): idle $idle; after 200 concurrent TLS clients x 20 requests: $loaded"
peak=$(echo "$loaded" | awk '{print $2}')
[ "${peak:-99999}" -lt 65536 ] || fail "mr edge serve peak RSS ${peak} kB (budget 64 MiB)"
kill -TERM "$EDGE"
wait "$EDGE" || fail "mr edge serve did not exit cleanly on SIGTERM"
EDGE=''
if grep -q 'PRIVATE\|lab-token' "$T/edge.log"; then fail "the proxy's log has key material or the token"; fi
cleanup
trap - EXIT
ok "4000 requests from 200 concurrent clients, no errors; clean exit on SIGTERM"
