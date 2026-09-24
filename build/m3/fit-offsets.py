#!/usr/bin/env python3
"""fit-offsets.py FIT — mr-meta lines for the kernel and DTB of the FIT's default configuration.

The router's sysupgrade extracts the kernel and DTB for kexec with tail/head at these offsets
(busybox has no FDT parser), and checks each piece against its sha256 before using it.
Embedded-data FITs only (what OpenWrt's mkits.sh + mkimage produce for this board).
"""
import hashlib
import struct
import sys

FDT_BEGIN_NODE, FDT_END_NODE, FDT_PROP, FDT_NOP, FDT_END = 1, 2, 3, 4, 9


def parse(blob):
    magic, total, off_struct, off_strings = struct.unpack(">IIII", blob[:16])
    if magic != 0xD00DFEED:
        sys.exit("not an FDT/FIT")
    if total > len(blob):
        sys.exit("truncated FIT")

    def string(off):
        end = blob.index(b"\0", off)
        return blob[off:end].decode()

    props = {}  # "/path/prop" -> (file offset, length)
    path = []
    pos = off_struct
    while True:
        (tok,) = struct.unpack(">I", blob[pos:pos + 4])
        pos += 4
        if tok == FDT_BEGIN_NODE:
            end = blob.index(b"\0", pos)
            path.append(blob[pos:end].decode())
            pos = (end + 1 + 3) & ~3
        elif tok == FDT_END_NODE:
            path.pop()
        elif tok == FDT_PROP:
            length, nameoff = struct.unpack(">II", blob[pos:pos + 8])
            pos += 8
            name = string(off_strings + nameoff)
            props["/".join(path) + "/" + name] = (pos, length)
            pos = (pos + length + 3) & ~3
        elif tok == FDT_NOP:
            pass
        elif tok == FDT_END:
            return props
        else:
            sys.exit("bad FDT token %d" % tok)


def main():
    blob = open(sys.argv[1], "rb").read()
    props = parse(blob)

    def val(key):
        if key not in props:
            sys.exit("FIT has no " + key)
        off, n = props[key]
        return blob[off:off + n]

    def cstr(key):
        return val(key).rstrip(b"\0").decode()

    conf = cstr("/configurations/default")
    out = []
    for kind, meta in (("kernel", "FIT_KERNEL"), ("fdt", "FIT_FDT")):
        img = cstr("/configurations/%s/%s" % (conf, kind))
        base = "/images/" + img
        if base + "/data" not in props:
            sys.exit(img + ": external data is not supported")
        off, n = props[base + "/data"]
        out.append("%s_OFFSET=%d" % (meta, off))
        out.append("%s_SIZE=%d" % (meta, n))
        out.append("%s_SHA256=%s" % (meta, hashlib.sha256(blob[off:off + n]).hexdigest()))
        if kind == "kernel":
            out.append("FIT_KERNEL_COMP=" + cstr(base + "/compression"))
    print("\n".join(out))


if __name__ == "__main__":
    main()
