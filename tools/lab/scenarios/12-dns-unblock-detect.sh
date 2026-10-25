#!/bin/sh
# Read-only dns.unblock detection (mr dns unblock detect) against the ISP simulator:
#   block page shared by two domains, private sinkhole, NXDOMAIN block, regional-CDN names that must NOT
#   be flagged, UDP/53 interception (also with protocol: udp configured), and a trusted resolver that is
#   closed / stalls (nothing may be recommended). The trusted resolver is a DoT stand-in
#   (tools/lab/dot-standin.py) whose certificate mr verifies through SSL_CERT_FILE; plain 1.1.1.1 is
#   a stand-in inside the ISP namespace (--plain-cf), so the scenario never touches the internet.
NAME=12-dns-unblock-detect
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

REPO=$(CDPATH='' cd -- "$SELF_DIR/../../.." && pwd)
TRUSTED="10.$ID.1.2"
WORK=/tmp/mrlab$ID-detect
rm -rf "$WORK"
mkdir -p "$WORK"

# the built-in probe names come from the source, so the scenario follows the list
BUILTIN=$(sed -n '/^var dnsUnblockDetectDomains/,/^}/p' "$REPO/mr/mod_dns_unblock_detect.go" | grep -o '"[a-z0-9.-]*"' | tr -d '"')
i=0
ISP_NAMES=""
for d in $BUILTIN; do
	i=$((i + 1))
	ISP_NAMES="$ISP_NAMES --address $d=198.51.100.$i --trusted $d=198.51.100.$i --plain-cf $d=198.51.100.$i"
done
[ "$i" -ge 25 ] || { printf 'Bail out! built-in probe list not found in the source\n'; exit 1; }

isp() { # isp [--hijack53]
	# shellcheck disable=SC2086
	lab isp "$ID" 1 dhcp $ISP_NAMES \
		--address blocked-a.test=125.26.170.3 --trusted blocked-a.test=1.1.1.53 --plain-cf blocked-a.test=1.1.1.53 \
		--address blocked-b.test=125.26.170.3 --trusted blocked-b.test=1.1.1.54 --plain-cf blocked-b.test=1.1.1.54 \
		--address fake.test=10.10.10.10 --trusted fake.test=1.1.1.56 --plain-cf fake.test=1.1.1.56 \
		--nxdomain empty.test --trusted empty.test=1.1.1.57 --plain-cf empty.test=1.1.1.57 \
		--address cdn-a.test=1.1.1.88 --trusted cdn-a.test=1.1.1.89 --plain-cf cdn-a.test=1.1.1.89 \
		--address cdn-b.test=1.1.1.88 --trusted cdn-b.test=1.1.1.90 --plain-cf cdn-b.test=1.1.1.90 \
		"$@"
}

# DoT stand-in in the ISP namespace; a new `lab isp` kills it (it stops every process of the namespace)
DOT_PID=""
stop_dot() { [ -n "$DOT_PID" ] && kill "$DOT_PID" 2>/dev/null; DOT_PID=""; return 0; }
start_dot() { # start_dot [--silent|--stall]
	stop_dot
	ip netns exec "mrlab${ID}-isp1" python3 "$SELF_DIR/../dot-standin.py" "$TRUSTED" 853 "$TRUSTED" "$WORK/cert.pem" "$WORK/key.pem" "$@" > "$WORK/dot.log" 2>&1 &
	DOT_PID=$!
	sleep 1
	kill -0 "$DOT_PID" 2>/dev/null
}
trap 'stop_dot; cleanup' EXIT

# detect <outfile> [domains]: the report as JSON on the host, from the router's own mr
detect() {
	out=$1
	shift
	lab console "$ID" "SSL_CERT_FILE=/tmp/lab-dot-ca.pem mr dns unblock detect --json $*" > "$out" 2>> "$LOG"
}
# q <file> <python expression over d (the report) and R (rows by domain)>
q() {
	f=$1
	shift
	python3 -I -c 'import json,sys
d = json.load(open(sys.argv[1]))
R = {r["domain"]: r for r in d["results"]}
sys.exit(0 if eval(sys.argv[2]) else 1)' "$f" "$*"
}
# patch <protocol>: dns.upstream isp, unblock configured but OFF, trusted = the stand-in
patch() {
	lab change "$ID" "[{\"op\":\"set\",\"path\":\"dns.upstream\",\"value\":\"isp\"},{\"op\":\"set\",\"path\":\"dns.unblock\",\"value\":{\"enabled\":false,\"block_ips\":[],\"retry_private\":true,\"retry_empty\":true,\"fallback\":\"custom\",\"protocol\":\"$1\",\"server\":\"$TRUSTED\"}}]"
}
md5() { lab console "$ID" 'md5sum /etc/mini-router/router.yaml' 2>> "$LOG" | awk '/router.yaml/ {print $1}'; }
same() { [ -n "$1" ] && [ "$1" = "$2" ]; }
CUSTOM="blocked-a.test blocked-b.test fake.test empty.test cdn-a.test cdn-b.test"

step lab reset "$ID"
step isp --hijack53
check "install.sh completes on the DHCP WAN" lab install "$ID" --wan-proto dhcp
step lab lan "$ID" dhcp

step openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$WORK/key.pem" -out "$WORK/cert.pem" -days 2 -subj "/CN=mrlab-dot" -addext "subjectAltName=IP:$TRUSTED"
step lab console "$ID" "echo $(base64 -w0 "$WORK/cert.pem") | base64 -d > /tmp/lab-dot-ca.pem && wc -c /tmp/lab-dot-ca.pem"
retry 30 patch tls
MD5_0=$(md5)

# ---- A: the ISP hijacks port 53, protocol: tls configured, DoT stand-in works -----------------------
step start_dot
step detect "$WORK/a.json" $CUSTOM
check "A: the report is conclusive and complete" q "$WORK/a.json" "d['status']=='ok' and d['conclusive'] is True and d['probed']==d['total']==$((i + 6))"
check "A: the repeated ISP block-page address is found" q "$WORK/a.json" "d['block_ips']==['125.26.170.3'] and R['blocked-a.test']['kind']=='block_page' and R['blocked-b.test']['kind']=='block_page'"
check "A: private sinkhole and NXDOMAIN block are told apart" q "$WORK/a.json" "R['fake.test']['kind']=='fake_address' and R['empty.test']['kind']=='empty'"
check "A: regional CDN names (different edge of one network) are not blocked" q "$WORK/a.json" "R['cdn-a.test']['kind']=='ok' and R['cdn-b.test']['kind']=='ok'"
check "A: every built-in name is normal" q "$WORK/a.json" "all(r['kind']=='ok' for r in d['results'] if not r.get('custom'))"
check "A: port-53 interception is detected and tls recommended" q "$WORK/a.json" "d['interception']=='yes' and d['intercepted'] is True and d['recommend']=={'enable':True,'block_ips':['125.26.170.3'],'protocol':'tls'}"
check "A: the trusted answers came through DoT (latency measured, no errors)" q "$WORK/a.json" "d['trusted'].startswith('tls://') and d['latency']['trusted_ms']>=0 and d['errors']==[]"
check "A: detection is read-only: router.yaml is unchanged" same "$MD5_0" "$(md5)"

# ---- B: the same with protocol: udp configured (a hijacked plaintext answer must not hide it) ------
retry 30 patch udp
MD5_1=$(md5)
step detect "$WORK/b.json" $CUSTOM
check "B: protocol: udp configured, interception is still detected" q "$WORK/b.json" "d['interception']=='yes' and d['recommend']['protocol']=='tls' and R['blocked-a.test']['kind']=='block_page'"

# ---- C: no interception: plain 1.1.1.1 answers like the trusted resolver, udp may be recommended ---
step isp
step start_dot
step detect "$WORK/c.json" $CUSTOM
check "C: no interception, plain 1.1.1.1 works: udp recommended" q "$WORK/c.json" "d['interception']=='no' and d['intercepted'] is False and d['recommend']['protocol']=='udp' and d['recommend']['enable'] is True"

# ---- D: the trusted resolver stalls / is closed: nothing is judged, nothing recommended, no hang ----
step start_dot --stall
t0=$(date +%s)
step detect "$WORK/d.json" $CUSTOM
t1=$(date +%s)
check "D: a stalled DoT server cannot hang the detection (done in <= 16 s)" test $((t1 - t0)) -le 16
check "D: stalled trusted resolver: cannot tell, no recommendation, no block_ips" q "$WORK/d.json" "d['status']=='inconclusive' and d['conclusive'] is False and d['recommend']['enable'] is False and d['recommend']['block_ips']==[] and d['block_ips']==[] and d['blocked']==[]"
check "D: the failure is reported" q "$WORK/d.json" "len(d['errors'])>0 and d['trusted_ok']==0"
stop_dot
step detect "$WORK/e.json" $CUSTOM
check "D: closed DoT port: cannot tell, no recommendation" q "$WORK/e.json" "d['status']=='inconclusive' and d['recommend']['enable'] is False and d['block_ips']==[]"

# ---- the detection changed nothing ---------------------------------------------------------------
check "B-E: detection is read-only: router.yaml is unchanged" same "$MD5_1" "$(md5)"
finish
