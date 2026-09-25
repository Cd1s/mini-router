#!/bin/sh
# mr mcp checks (mr/mcp*.go, mr/sshsig.go, docs/mcp.md): real `mr mcp` sessions — JSON-RPC lines on
# stdin, answers on stdout — against the lab config installed as the live router.yaml (the CI tmpfs
# over /etc/mini-router; /run/mini-router gets its own tmpfs here). Run by tools/ci.sh inside its
# private mount namespace, with OUT and ROOT set.
#  1. protocol: initialize (2025-06-18), tools by scope, ping, notifications, errors
#  2. read tools: config_get without secret values, explain, mon_query
#  3. plan_change: the guard and the locked parts refuse; a good patch gives plan_id + the sha256 of
#     the stored candidate; `mr mcp show ID` prints exactly the approval text plan_change returned
#  4. approval: the lab needs a FIDO touch above low risk — apply_plan is refused without a signature
#     and with a real `ssh-keygen -Y sign` made with an ordinary (not FIDO) key
# Nothing is ever applied: every apply_plan here is refused before the apply job would start.
set -eu
: "${OUT:?}" "${ROOT:?}"
MR=$OUT/mr-host
M=$OUT/mcp
fail() { echo "FAIL: $*"; exit 1; }
ok() { echo "ok: $*"; }
command -v jq >/dev/null || apt-get install -y -qq jq >/dev/null
rm -rf "$M" && mkdir -p "$M"

E=/etc/mini-router
for f in router.yaml secrets.yaml; do [ ! -e "$E/$f" ] || mv "$E/$f" "$M/saved-$f"; done
mkdir -p /run/mini-router && mount -t tmpfs tmpfs /run/mini-router
cleanup() {
	umount /run/mini-router 2>/dev/null || true
	rm -f "$E/router.yaml" "$E/secrets.yaml"
	for f in router.yaml secrets.yaml; do [ ! -e "$M/saved-$f" ] || mv "$M/saved-$f" "$E/$f"; done
}
trap cleanup EXIT
cp "$OUT/lab.yaml" "$E/router.yaml"
cp "$OUT/lab-secrets.yaml" "$E/secrets.yaml"

# session SCOPE NAME: run the JSON-RPC lines on stdin through `mr mcp`; answers in $M/NAME.out
session() {
	"$MR" mcp --scope="$1" --agent=ci > "$M/$2.out" 2> "$M/$2.err" || fail "$2: mr mcp exited: $(cat "$M/$2.err")"
}
call() { jq -cn --argjson id "$1" --arg name "$2" --argjson args "$3" '{jsonrpc: "2.0", id: $id, method: "tools/call", params: {name: $name, arguments: $args}}'; }
ans() { jq -c "select(.id == $2)" "$M/$1.out"; }        # the answer to request id N
text() { jq -r "select(.id == $2) | .result.content[0].text" "$M/$1.out"; }
iserr() { [ "$(jq -r "select(.id == $2) | .result.isError // false" "$M/$1.out")" = true ]; }

# 1 + 2 + 3: a read-scoped agent
{
	echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"ci","version":"0"}}}'
	echo '{"jsonrpc":"2.0","method":"notifications/initialized"}'
	echo '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
	echo '{"jsonrpc":"2.0","id":3,"method":"ping"}'
	echo '{"jsonrpc":"2.0","id":4,"method":"resources/list"}'
	call 5 config_get '{}'
	call 6 config_get '{"path":"services.ssh.agents[claude].scope"}'
	call 7 explain '{"path":"guard.approvers"}'
	call 8 mon_query '{"view":"procs"}'
	call 9 plan_change '{"patch":[{"op":"set","path":"firewall.offload","value":"software"}]}'
	call 10 plan_change '{"patch":[{"op":"set","path":"services.ssh.port","value":2222}]}'
	call 11 plan_change '{"patch":[{"op":"set","path":"dhcp.lease","value":"6h"}],"comment":"ci"}'
	call 12 apply_plan '{"plan_id":"0000000000000000"}'
	echo 'this is not JSON'
} | session read read
[ "$(wc -l < "$M/read.out")" = 13 ] || fail "read session: want 13 answers, got $(wc -l < "$M/read.out")"
[ "$(ans read 1 | jq -r .result.protocolVersion)" = 2025-06-18 ] || fail "initialize: $(ans read 1)"
tools=$(ans read 2 | jq -r '[.result.tools[].name] | join(",")')
[ "$tools" = status,explain,mon_query,diagnose,config_get,history,plan_change ] || fail "read tools: $tools"
[ "$(ans read 3 | jq -c .result)" = '{}' ] || fail "ping"
[ "$(ans read 4 | jq -r .error.code)" = -32601 ] || fail "resources/list: $(ans read 4)"
[ "$(jq -r 'select(.id == null) | .error.code' "$M/read.out")" = -32700 ] || fail "parse error"
sed -n 's/^[a-z0-9_-]*: *"\{0,1\}\([^"]*\)"\{0,1\}$/\1/p' "$E/secrets.yaml" | while read -r v; do
	[ ${#v} -lt 6 ] || ! grep -qF -- "$v" "$M/read.out" || fail "a secret value is in an answer"
done
[ "$(text read 5 | jq -r .secrets_set.pppoe_password)" = true ] || fail "config_get secrets_set: $(text read 5 | head -c 300)"
[ "$(text read 6 | jq -r .value)" = apply ] || fail "config_get path: $(text read 6)"
[ "$(text read 7 | jq -r .agents_may_change)" = false ] || fail "explain guard.approvers: $(text read 7)"
iserr read 8 && fail "mon_query procs: $(text read 8)"
iserr read 9 && text read 9 | grep -q 'guard.offload' || fail "guard not enforced: $(text read 9)"
iserr read 10 && text read 10 | grep -q 'agents cannot change services.ssh' || fail "locked path: $(text read 10)"
iserr read 11 && fail "plan_change: $(text read 11)"
ans read 11 | jq -e '.result.structuredContent.next | test("scope is read")' > /dev/null || fail "read scope plan: $(ans read 11)"
iserr read 12 && text read 12 | grep -q 'needs scope apply' || fail "apply_plan with scope read: $(text read 12)"
ok "protocol, tools by scope, no secrets, guard + locked paths refused"

# 3 + 4: an apply-scoped agent plans; the owner's view of the plan; approvals
call 1 plan_change '{"patch":[{"op":"set","path":"dhcp.lease","value":"6h"}],"comment":"ci"}' | session apply plan
P=$(ans plan 1 | jq -r .result.structuredContent.plan_id)
echo "$P" | grep -Eqx '[0-9a-f]{16}' || fail "no plan id: $(ans plan 1)"
[ "$(sha256sum < "/run/mini-router/mcp/$P.yaml" | cut -d' ' -f1)" = "$(ans plan 1 | jq -r .result.structuredContent.sha256)" ] || fail "sha256 of the stored candidate"
grep -q 'lease: 6h' "/run/mini-router/mcp/$P.yaml" || fail "candidate without the change"
[ "$(ans plan 1 | jq -r .result.structuredContent.needs_approval)" = true ] || fail "lab (max_risk_without_touch: low): no approval needed: $(ans plan 1)"
ans plan 1 | jq -j .result.structuredContent.approval.text > "$M/agent-copy.txt"
"$MR" mcp show "$P" > "$M/plan.txt"
cmp -s "$M/plan.txt" "$M/agent-copy.txt" || fail "mr mcp show differs from the approval text plan_change returned"
"$MR" mcp plans | grep -q "^$P " || fail "mr mcp plans"
ssh-keygen -q -t ed25519 -N '' -C ci -f "$M/key"
ssh-keygen -q -Y sign -n mr-plan -f "$M/key" "$M/plan.txt" 2> /dev/null
{
	call 1 apply_plan "{\"plan_id\":\"$P\"}"
	jq -cn --arg id "$P" --rawfile sig "$M/plan.txt.sig" '{jsonrpc: "2.0", id: 2, method: "tools/call", params: {name: "apply_plan", arguments: {plan_id: $id, signature: $sig}}}'
	call 3 confirm '{}'
	call 4 rollback '{}'
} | session apply apply
iserr apply 1 && text apply 1 | grep -q "needs the owner's approval" || fail "apply without a signature: $(text apply 1)"
iserr apply 2 && text apply 2 | grep -q 'approval refused: signed with a ssh-ed25519 key' || fail "ordinary-key signature: $(text apply 2)"
[ "$(ans apply 3 | jq -r .result.structuredContent.confirmed)" = false ] || fail "confirm: $(ans apply 3)"
iserr apply 4 || fail "rollback with nothing pending: $(text apply 4)"
[ ! -e /run/mini-router/job.json ] && [ ! -e "$E/confirm-pending" ] || fail "an apply job was started"
ok "plan $P: sha256 of the candidate, mr mcp show = the agent's copy, refused without a FIDO approval"
