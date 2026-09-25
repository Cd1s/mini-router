#!/usr/bin/env python3
"""cdpshot.py URL OUT.png WIDTH HEIGHT light|dark WAIT_SECONDS — screenshot after a real-time wait.

Starts headless Chrome with the DevTools protocol, loads URL at WIDTH x HEIGHT (device scale 2) with the given
prefers-color-scheme, waits WAIT_SECONDS of wall-clock time (pages that poll an API need it), captures a PNG.
Standard library only (a minimal WebSocket client)."""
import base64, json, os, socket, struct, subprocess, sys, tempfile, time, urllib.request

CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"


def recv_exact(s, n):
    b = b""
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c:
            raise EOFError
        b += c
    return b


class WS:
    def __init__(self, url):
        hostport, path = url[len("ws://"):].split("/", 1)
        host, port = hostport.split(":")
        self.s = socket.create_connection((host, int(port)))
        key = base64.b64encode(os.urandom(16)).decode()
        self.s.sendall((f"GET /{path} HTTP/1.1\r\nHost: {hostport}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                        f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
        r = b""
        while b"\r\n\r\n" not in r:
            r += self.s.recv(1)
        self.id = 0

    def send(self, obj):
        data = json.dumps(obj).encode()
        hdr, n, mask = bytearray([0x81]), len(data), os.urandom(4)
        if n < 126:
            hdr.append(0x80 | n)
        elif n < 65536:
            hdr += bytes([0x80 | 126]) + struct.pack(">H", n)
        else:
            hdr += bytes([0x80 | 127]) + struct.pack(">Q", n)
        self.s.sendall(bytes(hdr) + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(data)))

    def recv(self):
        msg = b""
        while True:
            b1, b2 = recv_exact(self.s, 2)
            n = b2 & 0x7F
            if n == 126:
                n = struct.unpack(">H", recv_exact(self.s, 2))[0]
            elif n == 127:
                n = struct.unpack(">Q", recv_exact(self.s, 8))[0]
            msg += recv_exact(self.s, n)
            if b1 & 0x80:
                return json.loads(msg)

    def call(self, method, **params):
        self.id += 1
        self.send({"id": self.id, "method": method, "params": params})
        while True:
            m = self.recv()
            if m.get("id") == self.id:
                if "error" in m:
                    raise RuntimeError(m["error"])
                return m.get("result", {})


def main():
    url, out, w, h, scheme, wait = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), sys.argv[5], float(sys.argv[6])
    port = 9333
    prof = tempfile.mkdtemp(prefix="cdpshot-")
    p = subprocess.Popen([CHROME, "--headless=new", "--disable-gpu", "--hide-scrollbars", f"--remote-debugging-port={port}",
                          f"--user-data-dir={prof}", f"--window-size={w},{h}", "about:blank"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            try:
                pages = json.load(urllib.request.urlopen(f"http://127.0.0.1:{port}/json"))
                page = next(x for x in pages if x.get("type") == "page")
                break
            except Exception:
                time.sleep(0.1)
        ws = WS(page["webSocketDebuggerUrl"])
        ws.call("Emulation.setDeviceMetricsOverride", width=w, height=h, deviceScaleFactor=2, mobile=False)
        ws.call("Emulation.setEmulatedMedia", features=[{"name": "prefers-color-scheme", "value": scheme}])
        ws.call("Page.enable")
        ws.call("Page.navigate", url=url)
        time.sleep(wait)
        shot = ws.call("Page.captureScreenshot", format="png")
        open(out, "wb").write(base64.b64decode(shot["data"]))
        print(out, os.path.getsize(out))
    finally:
        p.terminate()
        p.wait()
        subprocess.run(["rm", "-rf", prof])


if __name__ == "__main__":
    main()
