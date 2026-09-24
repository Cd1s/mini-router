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


STATE = {"cfg": base_config(), "job": None, "pending": False}


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
        if a == "validate":
            p, empty = plan_for(body.get("config", {}))
            return self.send_json({"errors": [], "plan": p, "empty": empty})
        if a == "apply":
            STATE["cfg"]["config"] = body.get("config", {})
            now = int(time.time())
            STATE["job"] = {"state": "ok", "started": now, "ended": now, "output": "plan:\n  (mock)\napplied (snapshot mock.tar.gz)\n", "confirm": body.get("confirm", 120)}
            STATE["pending"] = True
            return self.send_json({"ok": True, "confirm": body.get("confirm", 120)})
        if a == "job":
            return self.send_json({"job": STATE["job"] or {}, "confirm_pending": STATE["pending"]})
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
