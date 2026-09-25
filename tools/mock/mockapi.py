#!/usr/bin/env python3
"""Mock mini-router backend for developing / testing the web UI without a router.

    python3 tools/mock/mockapi.py [port]        # default 8088, then open http://127.0.0.1:8088/

Serves rootfs/www statically and answers /cgi-bin/api?a=<action> like `mr api` does:
  * GET-style actions return tools/mock/fixtures/<action>.json (sanitized captures from a real router).
  * POST actions return tools/mock/fixtures/<action>.post.json if present, else {"ok": true}.
  * config / validate / apply / job / confirm / revert keep an in-memory config so the whole
    save flow (validate -> plan -> apply -> confirm) can be exercised.
  * Extra config sections for new modules: tools/mock/fixtures/config.d/<module>.json is merged
    into the base config (top-level keys), so each module ships its own sample data.
Always logged in (the real login is tested against the router). No dependencies beyond python3.
"""
import copy
import math
import http.server
import json
import os
import sys
import time
import urllib.parse

ROOT = os.path.dirname(os.path.abspath(__file__))
WWW = os.path.normpath(os.path.join(ROOT, "..", "..", "rootfs", "www"))
FIX = os.path.join(ROOT, "fixtures")


def load(name, default=None):
    p = os.path.join(FIX, name)
    if os.path.exists(p):
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    return default


T0 = time.time()


def live_mon_now():
    """mon.now whose counters advance like a busy router (the fixture alone is one frozen sample: no rates)."""
    j = copy.deepcopy(load("mon.now.json"))
    dt = time.time() - T0

    def integ(period, lo, hi):  # integral over [0, dt] of lo + (hi-lo)*(0.5+0.5*sin(2*pi*t/period))
        w = 2 * math.pi / period
        return lo * dt + (hi - lo) * (0.5 * dt + 0.5 * (1 - math.cos(w * dt)) / w)

    j["t"] = int(time.time() * 1000)
    j["up"] = j["up"] + dt
    rates = {"wan-dev": (4e6, 70e6, 3e5, 6e6), "wan": (1e5, 2e6, 5e4, 8e5), "lan": (3e5, 6e6, 4e6, 65e6),
             "port": (2e5, 3e6, 2e6, 30e6), "wifi": (1e5, 2e6, 1e6, 25e6)}
    for i, x in enumerate(j.get("ifaces", [])):
        r = rates.get(x.get("role"))
        if r:
            x["rx"] += int(integ(41 + 7 * i, r[0], r[1]))
            x["tx"] += int(integ(53 + 5 * i, r[2], r[3]))
    tot = [0] * 8
    for i, c in enumerate(j.get("cpus", [])):
        busy = integ(23 + 9 * i, 5, 55 + 10 * i)  # jiffies (USER_HZ 100 per core per second)
        c[0] += int(busy * 0.55); c[2] += int(busy * 0.2); c[6] += int(busy * 0.2); c[4] += int(busy * 0.05)
        c[3] += int(100 * dt - busy)
        tot = [a + b for a, b in zip(tot, c)]
    if j.get("cpus"):
        j["cpu"] = tot
    return j


def base_config():
    cfg = load("config.json")
    d = os.path.join(FIX, "config.d")
    if os.path.isdir(d):
        for n in sorted(os.listdir(d)):
            if n.endswith(".json"):
                with open(os.path.join(d, n), encoding="utf-8") as f:
                    extra = json.load(f)
                cfg["config"].update(extra.get("config", extra))
                cfg.setdefault("secrets_set", {}).update(extra.get("secrets_set", {}))
    return cfg


STATE = {"cfg": base_config(), "job": None, "pending": False, "deadline": 0}


def pending_view():
    return {"state": "pending", "via": "web UI", "left": max(0, STATE["deadline"] - int(time.time()))}


def plan_for(new):
    old = STATE["cfg"]["config"]
    changed = [k for k in sorted(set(old) | set(new)) if old.get(k) != new.get(k)]
    if not changed:
        return "", True
    return "".join("  write   (section %s)\n" % k for k in changed) + "  reload  firewall\n", False


class H(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=WWW, **kw)

    def log_message(self, fmt, *args):
        sys.stderr.write("mock: " + fmt % args + "\n")

    def send_json(self, obj, status=200):
        b = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        if STATE["pending"]:  # like `mr api`: every answer carries the change waiting for confirmation
            self.send_header("X-MR-Pending", json.dumps(pending_view()))
        self.end_headers()
        self.wfile.write(b)

    def api(self, method):
        if self.headers.get("X-MR") != "1":
            return self.send_json({"error": "missing X-MR header"}, 403)
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        a = q.get("a", [""])[0]
        body = {}
        n = int(self.headers.get("Content-Length") or 0)
        if n:
            try:
                body = json.loads(self.rfile.read(n) or b"{}")
            except ValueError:
                return self.send_json({"error": "bad json"}, 400)
        if a == "session":
            return self.send_json({"authenticated": True, "password_set": True})
        if a == "config":
            return self.send_json(STATE["cfg"])
        if a == "mon.now":
            return self.send_json(live_mon_now())
        if a == "validate":
            p, empty = plan_for(body.get("config", {}))
            changes = ["~ %s: (changed)" % k for k in sorted(set(STATE["cfg"]["config"]) | set(body.get("config", {})))
                       if STATE["cfg"]["config"].get(k) != body.get("config", {}).get(k)]
            return self.send_json({"errors": [], "plan": p, "empty": empty, "changes": changes, "changes_known": True})
        if a in ("apply", "rollback"):
            if STATE["pending"]:
                return self.send_json({"error": "a change (web UI) is waiting for confirmation", "pending": pending_view()}, 409)
            if a == "apply":
                STATE["cfg"]["config"] = body.get("config", {})
            now = int(time.time())
            STATE["job"] = {"state": "ok", "started": now, "ended": now, "output": "plan:\n  (mock)\napplied (snapshot mock.tar.gz)\n", "confirm": body.get("confirm", 120)}
            STATE["pending"] = True
            STATE["deadline"] = now + body.get("confirm", 120)
            return self.send_json({"ok": True, "confirm": body.get("confirm", 120)})
        if a == "job":
            return self.send_json({"job": STATE["job"] or {}, "confirm_pending": STATE["pending"],
                                   "pending": pending_view() if STATE["pending"] else None})
        if a in ("confirm", "revert"):
            STATE["pending"] = False
            return self.send_json({"ok": True})
        fx = load(a + ".post.json") if method == "POST" else None
        if fx is None:
            fx = load(a + ".json")
        if fx is None:
            if method == "POST":
                return self.send_json({"ok": True})
            return self.send_json({"error": "mock: no fixture for %r (add tools/mock/fixtures/%s.json)" % (a, a)}, 404)
        return self.send_json(fx)

    def do_GET(self):
        if self.path.startswith("/cgi-bin/api"):
            return self.api("GET")
        return super().do_GET()

    def do_POST(self):
        if self.path.startswith("/cgi-bin/api"):
            return self.api("POST")
        self.send_error(405)

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        super().end_headers()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8088
    print("mock mini-router UI on http://127.0.0.1:%d/  (www=%s)" % (port, WWW))
    http.server.ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
