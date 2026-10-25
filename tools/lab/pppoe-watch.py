#!/usr/bin/env python3
"""Lab ISP: log the PPPoE frames that cross DEV, one line each, to LOGFILE.

    ip netns exec <isp> python3 -I pppoe-watch.py DEV LOGFILE

Discovery: PADI PADO PADR PADS PADT. Session stage: LCP Terminate-Request / Terminate-Ack (what pppd
sends when it is stopped). Line: "<unix time> <KIND> from=<mac> to=<mac> sess=<id>"; `from` is the
router's session MAC for frames the router sent. Used by the lab scenarios to prove that a restart
or a reboot ended the sessions at the ISP (PADT) and which lines a redial touched.
"""
import socket
import struct
import sys
import time

ETH_P_ALL = 3
DISCOVERY, SESSION = 0x8863, 0x8864
CODES = {0x09: "PADI", 0x07: "PADO", 0x19: "PADR", 0x65: "PADS", 0xA7: "PADT"}
LCP = 0xC021
LCP_CODES = {5: "LCP-TERM-REQ", 6: "LCP-TERM-ACK"}


def mac(b):
    return ":".join("%02x" % x for x in b)


def main():
    dev, out = sys.argv[1], sys.argv[2]
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    s.bind((dev, 0))
    with open(out, "a", buffering=1) as log:
        log.write("%.3f WATCH-START dev=%s\n" % (time.time(), dev))
        while True:
            frame, _ = s.recvfrom(2048)
            if len(frame) < 20:
                continue
            dst, src, eth = frame[0:6], frame[6:12], struct.unpack("!H", frame[12:14])[0]
            if eth not in (DISCOVERY, SESSION):
                continue
            ver_type, code, sess, _length = struct.unpack("!BBHH", frame[14:20])
            if ver_type != 0x11:
                continue
            kind = None
            if eth == DISCOVERY:
                kind = CODES.get(code)
            elif len(frame) >= 26 and struct.unpack("!H", frame[20:22])[0] == LCP:
                kind = LCP_CODES.get(frame[22])
            if kind:
                log.write("%.3f %s from=%s to=%s sess=0x%04x\n" % (time.time(), kind, mac(src), mac(dst), sess))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
