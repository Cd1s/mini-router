#!/usr/bin/env python3
"""DNS-over-TLS stand-in for the lab (python3, stdlib only).

    dot-standin.py LISTEN_IP PORT UPSTREAM_IP CERT KEY [--silent | --stall]

Terminates TLS on LISTEN_IP:PORT and relays every query over UDP/53 to UPSTREAM_IP (the lab's
"trusted resolver" dnsmasq). --silent: finish the handshake, then never answer. --stall: accept the TCP
connection and say nothing at all (what a filtering middlebox does). mr verifies the certificate, so the
scenario hands mr its CA through SSL_CERT_FILE.
"""
import socket
import ssl
import struct
import sys
import threading
import time

listen, port, upstream, cert, key = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5]
mode = sys.argv[6] if len(sys.argv) > 6 else ""


def read_n(c, n):
    buf = b""
    while len(buf) < n:
        chunk = c.recv(n - len(buf))
        if not chunk:
            raise EOFError
        buf += chunk
    return buf


def relay(q):
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.settimeout(2)
    try:
        u.sendto(q, (upstream, 53))
        return u.recvfrom(4096)[0]
    finally:
        u.close()


def serve(raw, ctx):
    try:
        if mode == "--stall":
            time.sleep(60)
            return
        c = ctx.wrap_socket(raw, server_side=True)
        while True:
            n = struct.unpack("!H", read_n(c, 2))[0]
            q = read_n(c, n)
            if mode == "--silent":
                time.sleep(60)
                return
            a = relay(q)
            c.sendall(struct.pack("!H", len(a)) + a)
    except Exception:
        pass
    finally:
        raw.close()


ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(cert, key)
ls = socket.socket()
ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ls.bind((listen, port))
ls.listen(64)
while True:
    conn, _ = ls.accept()
    threading.Thread(target=serve, args=(conn, ctx), daemon=True).start()
