#!/bin/sh
# platform CI checks (run by tools/ci.sh with OUT and ROOT set; no image build needed):
#  1. the factory router.yaml (build/m3/router.yaml) validates with an empty secrets.yaml, renders, and
#     the real nft / dnsmasq accept the result; its documented defaults hold
#  2. build/m3/fit-offsets.py finds the kernel and DTB of a synthetic FIT
#  3. sysupgrade -T accepts a well-formed image and refuses every tampered variant (board, CONTROL,
#     members, sizes, checksums, magics, FIT offsets, meta injection, --sha256, unsafe --data tarballs)
#  4. tools/provision.sh: root ownership, normalised modes, .firstboot marker; refuses symlinks, odd
#     names, paths outside etc/ root/ var/lib/ usr/local/, and files that must come from the image
set -eu
: "${OUT:?}" "${ROOT:?}"
MR=$OUT/mr-host
P=$OUT/platform
SU=$ROOT/rootfs/usr/libexec/mr/sysupgrade
BOARD=xiaomi,redmi-router-ax6000-hanwckf
PREFIX=sysupgrade-xiaomi_redmi-router-ax6000-hanwckf
rm -rf "$P" && mkdir -p "$P"
fail() {
	echo "FAIL: $*"
	exit 1
}

# ---- 1. factory configuration
: > "$P/no-secrets.yaml"
F=$P/factory
"$MR" -c "$ROOT/build/m3/router.yaml" -s "$P/no-secrets.yaml" validate
"$MR" -c "$ROOT/build/m3/router.yaml" -s "$P/no-secrets.yaml" render "$F" > /dev/null
grep -q '192\.168\.31\.1/24' "$F/etc/mini-router/gen/network.sh" || fail "factory LAN address"
for s in mr-network mr-firewall dnsmasq dropbear mr-panel mr-udhcpc.wan; do
	grep -qx "$s" "$F/etc/mini-router/gen/services" || fail "factory service $s missing"
done
if grep -qx 'mr-hostapd\|tailscale\|dstatus-agent\|mr-proxy' "$F/etc/mini-router/gen/services"; then
	fail "factory config enables an optional service"
fi
if ls "$F"/etc/hostapd/hostapd-phy*.conf > /dev/null 2>&1; then fail "factory config has WiFi"; fi
grep -q -- '-s -g' "$F/etc/conf.d/dropbear" || fail "factory SSH allows passwords"
shellcheck -s sh -S error "$F"/etc/mini-router/gen/*.sh
NS=mrciplat$$
ip netns add "$NS"
# shellcheck disable=SC2064
trap "ip netns del $NS 2>/dev/null" EXIT
devs=$(sed -n 's/^[[:space:]]*devices = { \(.*\) }/\1/p' "$F/etc/mini-router/gen/nftables.nft" | tr -d '",')
for d in $devs br-lan; do
	ip -n "$NS" link add "$d" type dummy 2> /dev/null || true
	ip -n "$NS" link set "$d" up
done
sed '/flags offload/d' "$F/etc/mini-router/gen/nftables.nft" > "$P/factory.nft"
ip netns exec "$NS" nft -c -f "$P/factory.nft"
ip netns exec "$NS" nft -f "$P/factory.nft"
ip netns del "$NS"
trap - EXIT
rm -rf "$P/gen.saved" && mkdir -p /etc/mini-router/gen && cp -a /etc/mini-router/gen "$P/gen.saved"
cp -r "$F/etc/mini-router/gen/." /etc/mini-router/gen/
for f in $(sed -n 's/^\(addn-hosts\|servers-file\|conf-file\)=//p' "$F/etc/dnsmasq.conf"); do
	[ -e "$f" ] || { mkdir -p "$(dirname "$f")"; : > "$f"; }
done
dnsmasq --test --conf-file="$F/etc/dnsmasq.conf"
rm -rf /etc/mini-router/gen && cp -a "$P/gen.saved" /etc/mini-router/gen
echo "factory config ok"

# ---- 2 + 3. synthetic FIT and sysupgrade images
python3 - "$P" "$ROOT/build/m3/fit-offsets.py" << 'EOF'
import hashlib, io, lzma, os, struct, subprocess, sys, tarfile
P, FITOFF = sys.argv[1], sys.argv[2]
BOARD = "xiaomi,redmi-router-ax6000-hanwckf"
PREFIX = "sysupgrade-xiaomi_redmi-router-ax6000-hanwckf"

def fdt(tree):
    """minimal FDT writer: tree = {name: bytes | str | dict}"""
    struct_b, strings = bytearray(), bytearray()
    def s_off(n):
        i = strings.find(n.encode() + b"\0")
        if i < 0 or (i > 0 and strings[i - 1] != 0):
            i = len(strings); strings.extend(n.encode() + b"\0")
        return i
    def node(name, d):
        struct_b.extend(struct.pack(">I", 1)); nb = name.encode() + b"\0"
        struct_b.extend(nb + b"\0" * (-len(nb) % 4))
        for k, v in d.items():
            if isinstance(v, dict): continue
            v = v.encode() + b"\0" if isinstance(v, str) else v
            struct_b.extend(struct.pack(">III", 3, len(v), s_off(k))); struct_b.extend(v + b"\0" * (-len(v) % 4))
        for k, v in d.items():
            if isinstance(v, dict): node(k, v)
        struct_b.extend(struct.pack(">I", 2))
    node("", tree); struct_b.extend(struct.pack(">I", 9))
    off_rsv = 40; off_struct = off_rsv + 16; off_strings = off_struct + len(struct_b)
    total = off_strings + len(strings)
    hdr = struct.pack(">10I", 0xD00DFEED, total, off_struct, off_strings, off_rsv, 17, 16, 0, len(strings), len(struct_b))
    return hdr + b"\0" * 16 + bytes(struct_b) + bytes(strings)

image = b"ARM64 Image " + os.urandom(3000)
klzma = lzma.compress(image, format=lzma.FORMAT_ALONE)
def mkfit(compat):
    dtb = fdt({"compatible": compat.encode() + b"\0mediatek,mt7986a\0", "model": "test"})
    fit = fdt({"description": "test FIT", "images": {
        "kernel-1": {"data": klzma, "type": "kernel", "compression": "lzma"},
        "fdt-1": {"data": dtb, "type": "flat_dt", "compression": "none"}},
        "configurations": {"default": "config-1", "config-1": {"kernel": "kernel-1", "fdt": "fdt-1"}}})
    return fit, dtb

fit, dtb = mkfit(BOARD)
open(P + "/test.itb", "wb").write(fit)
out = subprocess.run([sys.executable, FITOFF, P + "/test.itb"], capture_output=True, text=True, check=True).stdout
m = dict(l.split("=", 1) for l in out.split())
cut = lambda k, blob=fit: blob[int(m[k + "_OFFSET"]):int(m[k + "_OFFSET"]) + int(m[k + "_SIZE"])]
assert cut("FIT_KERNEL") == klzma and cut("FIT_FDT") == dtb and m["FIT_KERNEL_COMP"] == "lzma", out
assert m["FIT_KERNEL_SHA256"] == hashlib.sha256(klzma).hexdigest()
print("fit-offsets ok")

root = b"hsqs" + os.urandom(5000)
sha = lambda b: hashlib.sha256(b).hexdigest()
def meta(kernel, root, fitmeta, **over):
    d = {"MR_FORMAT": "1", "MR_BOARD": BOARD, "MR_VERSION": "m3-test", "MR_KERNEL": "6.18.52",
         "KERNEL_SIZE": str(len(kernel)), "KERNEL_SHA256": sha(kernel),
         "ROOT_SIZE": str(len(root)), "ROOT_SHA256": sha(root)}
    d.update(fitmeta); d.update(over)
    return "".join("%s=%s\n" % kv for kv in d.items() if kv[1] is not None).encode()

def image_tar(name, members):
    with tarfile.open(P + "/" + name, "w", format=tarfile.GNU_FORMAT) as t:
        for n, data in members:
            ti = tarfile.TarInfo(n)
            if data is None:
                ti.type = tarfile.DIRTYPE; ti.mode = 0o755; t.addfile(ti)
            else:
                ti.size = len(data); ti.mode = 0o644; t.addfile(ti, io.BytesIO(data))

def std(kernel=fit, root=root, control=b"BOARD=" + PREFIX[11:].encode() + b"\n", prefix=PREFIX, extra=(), fitmeta=m, **over):
    ms = [(prefix + "/", None), (prefix + "/CONTROL", control), (prefix + "/kernel", kernel), (prefix + "/root", root)]
    mm = meta(kernel, root, fitmeta, **over)
    return ms + [(prefix + "/mr-meta", mm)] + list(extra)

image_tar("ok.tar", std())
image_tar("board-meta.tar", std(MR_BOARD="xiaomi,mi-router-ax3000t"))
image_tar("control.tar", std(control=b"BOARD=other\n"))
image_tar("prefix.tar", std(prefix="sysupgrade-xiaomi_mi-router-ax3000t"))
image_tar("extra.tar", std(extra=[("evil", b"x")]))
image_tar("dotdot.tar", std(extra=[(PREFIX + "/../../etc/passwd", b"x")]))
bad_root = bytearray(root); bad_root[100] ^= 1
ms = std(); ms[3] = (ms[3][0], bytes(bad_root)); image_tar("rootsha.tar", ms)
image_tar("rootsize.tar", std(ROOT_SIZE=str(len(root) + 1)))
notsq = b"sqsh" + root[4:]
image_tar("magic.tar", std(root=notsq))
image_tar("fitoff.tar", std(FIT_FDT_OFFSET=str(len(fit) - 10)))
image_tar("fitsha.tar", std(FIT_KERNEL_SHA256="0" * 64))
fit2, dtb2 = mkfit("xiaomi,mi-router-ax3000t")
out2 = subprocess.run([sys.executable, FITOFF], input=None, capture_output=True, text=True, args=None) if False else None
open(P + "/test2.itb", "wb").write(fit2)
m2 = dict(l.split("=", 1) for l in subprocess.run([sys.executable, FITOFF, P + "/test2.itb"], capture_output=True, text=True, check=True).stdout.split())
image_tar("fdtboard.tar", std(kernel=fit2, fitmeta=m2))
image_tar("inject.tar", std(MR_VERSION="$(reboot)"))
ms = std(); image_tar("nometa.tar", ms[:4])
image_tar("comp.tar", std(FIT_KERNEL_COMP="gzip"))
open(P + "/notatar.tar", "wb").write(os.urandom(4096))
open(P + "/ok.sha256", "w").write(sha(open(P + "/ok.tar", "rb").read()))

def tgz(name, entries):
    with tarfile.open(P + "/" + name, "w:gz", format=tarfile.GNU_FORMAT) as t:
        for n, kind in entries:
            ti = tarfile.TarInfo(n); ti.uid = ti.gid = 0
            if kind == "d": ti.type = tarfile.DIRTYPE; ti.mode = 0o755; t.addfile(ti)
            elif kind == "l": ti.type = tarfile.SYMTYPE; ti.linkname = "/etc/passwd"; t.addfile(ti)
            else: ti.size = 1; ti.mode = 0o644; t.addfile(ti, io.BytesIO(b"x"))
tgz("data-ok.tgz", [("./", "d"), ("./etc/", "d"), ("./etc/mini-router/", "d"), ("./etc/mini-router/router.yaml", "f")])
tgz("data-link.tgz", [("./", "d"), ("./etc/", "d"), ("./etc/x", "l")])
tgz("data-dotdot.tgz", [("./", "d"), ("./etc/../../x", "f")])
tgz("data-abs.tgz", [("/etc/x", "f")])
print("test images written")
EOF

su_t() { # su_t EXPECT(ok|message) ARGS...: run sysupgrade -T and check the outcome
	want=$1
	shift
	rc=0
	out=$(MR_SYSUPGRADE_WORK="$P/su-work" MR_SYSUPGRADE_TEST_COMPAT="${COMPAT:-$BOARD mediatek,mt7986a}" \
		sh "$SU" -T "$@" 2>&1) || rc=$?
	if [ "$want" = ok ]; then
		[ "$rc" = 0 ] || fail "sysupgrade -T $*: expected success, got: $out"
	else
		[ "$rc" != 0 ] || fail "sysupgrade -T $*: expected refusal ($want), got success"
		case $out in *"$want"*) ;; *) fail "sysupgrade -T $*: expected '$want', got: $out" ;; esac
	fi
	[ ! -e "$P/su-work" ] || [ "$rc" != 0 ] || fail "sysupgrade -T left its work directory"
}
su_t ok "$P/ok.tar"
su_t ok --sha256 "$(cat "$P/ok.sha256")" "$P/ok.tar"
su_t "does not match --sha256" --sha256 "$(printf '%064d' 0)" "$P/ok.tar"
su_t "expected 64 hex digits" --sha256 1234 "$P/ok.tar"
su_t "is for board" "$P/board-meta.tar"
su_t "CONTROL: wrong BOARD" "$P/control.tar"
su_t "another board" "$P/prefix.tar"
su_t "unexpected member" "$P/extra.tar"
su_t "another board" "$P/dotdot.tar"
su_t "root: sha256 mismatch" "$P/rootsha.tar"
su_t "root: size differs" "$P/rootsize.tar"
su_t "root: bad magic" "$P/magic.tar"
su_t "FIT offset out of range" "$P/fitoff.tar"
su_t "FIT: kernel.lzma does not match" "$P/fitsha.tar"
su_t "device tree is not for" "$P/fdtboard.tar"
su_t "mr-meta: malformed" "$P/inject.tar"
su_t "image has no mr-meta" "$P/nometa.tar"
su_t "unsupported kernel compression" "$P/comp.tar"
su_t "not a sysupgrade tar" "$P/notatar.tar"
su_t "no such file" "$P/missing.tar"
COMPAT="xiaomi,mi-router-ax3000t mediatek,mt7981" su_t "is not $BOARD" "$P/ok.tar"
su_t ok --data "$P/data-ok.tgz" "$P/ok.tar"
su_t "unsafe member" --data "$P/data-link.tgz" "$P/ok.tar"
su_t "unsafe member" --data "$P/data-dotdot.tgz" "$P/ok.tar"
su_t "unsafe member" --data "$P/data-abs.tgz" "$P/ok.tar"
echo "sysupgrade -T ok (1 image accepted, 21 refused)"

# ---- 4. provision.sh
command -v cpio > /dev/null || apt-get install -y -qq cpio > /dev/null
S=$P/prov
mkdir -p "$S/etc/mini-router/dns" "$S/root/.ssh" "$S/etc/dropbear" "$S/etc/app" "$S/var/lib/misc" "$P/prov-out"
echo 'system: {}' > "$S/etc/mini-router/router.yaml"
echo 'k: v' > "$S/etc/mini-router/secrets.yaml" && chmod 0666 "$S/etc/mini-router/secrets.yaml"
echo example.com > "$S/etc/mini-router/dns/a.domains" && chmod 0600 "$S/etc/mini-router/dns/a.domains"
echo 'ssh-ed25519 AAAA test' > "$S/root/.ssh/authorized_keys" && chmod 0644 "$S/root/.ssh/authorized_keys"
echo key > "$S/etc/dropbear/dropbear_ed25519_host_key"
echo '192.168.1.6 a.example' > "$S/etc/app/dnsmasq.hosts" && chmod 0600 "$S/etc/app/dnsmasq.hosts"
printf '#!/bin/sh\n' > "$S/etc/app/hook" && chmod 0700 "$S/etc/app/hook"
echo x > "$S/var/lib/misc/state" && chmod 4755 "$S/var/lib/misc/state"
chown -R 1234:1234 "$S"
sh "$ROOT/tools/provision.sh" -o "$P/prov-out" "$S" > /dev/null
python3 - "$P/prov-out" << 'EOF'
import stat, sys, tarfile
d = sys.argv[1]
want = {".": 0o40755, "etc": 0o40755, "etc/mini-router": 0o40755, "etc/mini-router/dns": 0o40755,
        "etc/mini-router/router.yaml": 0o100644, "etc/mini-router/secrets.yaml": 0o100600,
        "etc/mini-router/dns/a.domains": 0o100644, "etc/mini-router/.firstboot": 0o100644,
        "root": 0o40700, "root/.ssh": 0o40700, "root/.ssh/authorized_keys": 0o100600,
        "etc/dropbear": 0o40700, "etc/dropbear/dropbear_ed25519_host_key": 0o100600,
        "etc/app": 0o40755, "etc/app/dnsmasq.hosts": 0o100644, "etc/app/hook": 0o100755,
        "var": 0o40755, "var/lib": 0o40755, "var/lib/misc": 0o40755, "var/lib/misc/state": 0o100755}
def check(got, what):
    if got != want:
        for k in sorted(set(got) | set(want)):
            if got.get(k) != want.get(k):
                print(what, k, oct(got.get(k, 0)), "want", oct(want.get(k, 0)))
        sys.exit(1)
b = open(d + "/provision.cpio", "rb").read()
got, pos = {}, 0
while True:
    h = b[pos:pos + 110]; assert h[:6] == b"070701", "not newc"
    f = [int(h[6 + 8 * i:14 + 8 * i], 16) for i in range(13)]
    mode, uid, gid, fsize, nsize = f[1], f[2], f[3], f[6], f[11]
    name = b[pos + 110:pos + 110 + nsize - 1].decode()
    pos = (pos + 110 + nsize + 3) & ~3
    pos = (pos + fsize + 3) & ~3
    if name == "TRAILER!!!": break
    assert uid == 0 and gid == 0, (name, uid, gid)
    got[name[2:] if name.startswith("./") else name] = mode
check(got, "cpio")
got = {}
with tarfile.open(d + "/overlay.tar.gz") as t:
    for m in t.getmembers():
        assert m.uid == 0 and m.gid == 0, (m.name, m.uid, m.gid)
        n = m.name[2:] if m.name.startswith("./") else m.name
        got[n.rstrip("/") or "."] = m.mode | (stat.S_IFDIR if m.isdir() else stat.S_IFREG)
check(got, "tar")
print("provision.sh output ok (owner root, modes, .firstboot)")
EOF
[ "$(stat -c %a "$P/prov-out/provision.cpio")" = 600 ] || fail "provision.cpio is not 0600"
prov_refuses() { # prov_refuses MESSAGE SETUP-COMMAND...
	msg=$1
	shift
	rm -rf "$P/prov-bad" && cp -a "$S" "$P/prov-bad"
	(cd "$P/prov-bad" && "$@")
	if out=$(sh "$ROOT/tools/provision.sh" -o "$P/prov-out" "$P/prov-bad" 2>&1); then fail "provision.sh accepted: $*"; fi
	case $out in *"$msg"*) ;; *) fail "provision.sh $*: expected '$msg', got: $out" ;; esac
}
prov_refuses "only plain files" ln -s /etc/shadow etc/x
prov_refuses "unsupported character" touch "etc/a b"
prov_refuses "only etc/, root/" mkdir -p usr/bin
prov_refuses "must come from the image" touch etc/shadow
prov_refuses "must come from the image" mkdir -p etc/config
prov_refuses "router.yaml missing" rm etc/mini-router/router.yaml
echo "provision.sh refusals ok"
echo "platform checks passed"
