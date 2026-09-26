#!/usr/bin/env python3
"""English UI dictionary (rootfs/www/ui/lang/en.json) for the web UI (#31). python3, stdlib only.

    python3 tools/i18n.py check      # CI: fail on UI strings missing from en.json (unused keys: warning)
    python3 tools/i18n.py missing    # the missing ones as a JSON skeleton {"中文": ""} to translate
    python3 tools/i18n.py fmt        # rewrite en.json in source order, one entry per line, unused keys dropped

Chinese is the UI's source language. The keys are every string literal containing CJK characters in
rootfs/www/ui/*.js (template literal parts too; concatenations are translated at runtime by replacing
these fragments), the visible text of rootfs/www/index.html and the few backend strings the UI shows
(string literals in mr/*.go, e.g. the risk explanations of the apply dialog). A line containing
`i18n-ignore` is skipped (e.g. the language switch's own "中文"). core.js translates text given to h(),
toast(), modal(), confirm() and a few attributes; `el.textContent = "中文…"` must go through tr().
"""
import glob
import json
import os
import re
import sys
from html.parser import HTMLParser

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
EN = os.path.join(ROOT, "rootfs", "www", "ui", "lang", "en.json")
# keep in sync with CJK in rootfs/www/ui/core.js
CJK = re.compile(r"[\u3000-\u303f\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff\uff00-\uffef]")
# the keys alone (the Chinese originals, 3 bytes a character) are about half of it; fetched only in English
BUDGET = 128 * 1024

ESC = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "v": "\v", "0": "\0"}


def unescape(s):
    """The runtime value of a JS / Go string literal body (quotes removed)."""
    out, i = [], 0
    while i < len(s):
        c = s[i]
        if c != "\\" or i + 1 >= len(s):
            out.append(c)
            i += 1
            continue
        n = s[i + 1]
        if n == "u" and s[i + 2:i + 3] == "{":
            j = s.index("}", i)
            out.append(chr(int(s[i + 3:j], 16)))
            i = j + 1
        elif n == "u":
            out.append(chr(int(s[i + 2:i + 6], 16)))
            i += 6
        elif n == "x":
            out.append(chr(int(s[i + 2:i + 4], 16)))
            i += 4
        elif n == "\n":  # line continuation
            i += 2
        else:
            out.append(ESC.get(n, n))
            i += 2
    return "".join(out)


# tokens after which "/" starts a regular expression, not a division
REGEX_AFTER = set("(,=:[!&|?{};+-*%<>~^") | {"", "return", "typeof", "case", "do", "else", "in", "of", "new", "delete", "void", "throw", "=>"}


def js_strings(src):
    """Yield (line, value) for every string literal and template literal part in JS source."""
    i, n, line, prev = 0, len(src), 1, ""
    stack = []  # brace depth per open template ${ … }

    def template(i, line):
        # at the character after ` (or after the } closing a ${…}); returns (i, line, closed)
        buf, start = [], line
        while i < n:
            c = src[i]
            if c == "\\":
                buf.append(src[i:i + 2])
                line += src[i:i + 2].count("\n")
                i += 2
            elif c == "`":
                parts.append((start, unescape("".join(buf))))
                return i + 1, line, True
            elif c == "$" and src[i + 1:i + 2] == "{":
                parts.append((start, unescape("".join(buf))))
                return i + 2, line, False
            else:
                if c == "\n":
                    line += 1
                buf.append(c)
                i += 1
        raise SyntaxError("unterminated template literal at line %d" % start)

    parts = []
    while i < n:
        c = src[i]
        if c == "\n":
            line += 1
            i += 1
        elif c in " \t\r":
            i += 1
        elif src.startswith("//", i):
            j = src.find("\n", i)
            i = n if j < 0 else j
        elif src.startswith("/*", i):
            j = src.index("*/", i + 2)
            line += src.count("\n", i, j)
            i = j + 2
        elif c in "\"'":
            j = i + 1
            while src[j] != c:
                if src[j] == "\n":
                    raise SyntaxError("newline in string at line %d" % line)
                j += 2 if src[j] == "\\" else 1
            parts.append((line, unescape(src[i + 1:j])))
            i, prev = j + 1, "str"
        elif c == "`":
            i, line, closed = template(i + 1, line)
            if not closed:
                stack.append(0)
            prev = "str"
        elif c == "{":
            if stack:
                stack[-1] += 1
            i, prev = i + 1, "{"
        elif c == "}":
            if stack and stack[-1] == 0:
                stack.pop()
                i, line, closed = template(i + 1, line)
                if not closed:
                    stack.append(0)
                prev = "str"
            else:
                if stack:
                    stack[-1] -= 1
                i, prev = i + 1, "}"
        elif c == "/" and prev in REGEX_AFTER:
            j, cls = i + 1, False
            while True:
                d = src[j]
                if d == "\\":
                    j += 2
                    continue
                if d == "\n":
                    raise SyntaxError("newline in regex at line %d" % line)
                if d == "[":
                    cls = True
                elif d == "]":
                    cls = False
                elif d == "/" and not cls:
                    break
                j += 1
            i = j + 1
            while i < n and (src[i].isalnum()):
                i += 1
            prev = "re"
        elif c.isalnum() or c in "_$" or ord(c) > 127:
            j = i
            while j < n and (src[j].isalnum() or src[j] in "_$" or (ord(src[j]) > 127 and not src[j].isspace())):
                j += 1
            prev, i = src[i:j], j
        elif src.startswith("=>", i):
            i, prev = i + 2, "=>"
        else:
            i, prev = i + 1, (c if c not in ")]" else "x")
    return parts


def go_strings(src):
    """Yield (line, value) for Go string literals (comments and runes skipped)."""
    out = []
    for m in re.finditer(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\\n])*"|`[^`]*`|\'(?:\\.|[^\'\\\n])+\'', src, re.S):
        t = m.group(0)
        if t[0] == '"':
            out.append((src.count("\n", 0, m.start()) + 1, unescape(t[1:-1])))
        elif t[0] == "`":
            out.append((src.count("\n", 0, m.start()) + 1, t[1:-1]))
    return out


class HTMLText(HTMLParser):
    ATTRS = {"title", "placeholder", "aria-label", "alt", "content"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.skip, self.out = 0, []

    def handle_starttag(self, tag, attrs):
        if tag in ("style", "script"):
            self.skip += 1
        for k, v in attrs:
            if k in self.ATTRS and v:
                self.out.append((self.getpos()[0], v))

    def handle_endtag(self, tag):
        if tag in ("style", "script"):
            self.skip -= 1

    def handle_data(self, data):
        if not self.skip and data.strip():
            self.out.append((self.getpos()[0], data.strip()))


def sources():
    ui = sorted(glob.glob(os.path.join(ROOT, "rootfs", "www", "ui", "*.js")))
    core = [f for f in ui if f.endswith("core.js")]
    yield from ((f, "js") for f in core + [f for f in ui if f not in core])
    yield os.path.join(ROOT, "rootfs", "www", "index.html"), "html"
    for f in sorted(glob.glob(os.path.join(ROOT, "mr", "*.go"))):
        if not f.endswith("_test.go"):
            yield f, "go"


def extract():
    """{key: [file:line, ...]} in source order."""
    keys = {}
    for path, kind in sources():
        with open(path, encoding="utf-8") as f:
            src = f.read()
        lines = src.split("\n")
        if kind == "js":
            found = js_strings(src)
        elif kind == "go":
            found = go_strings(src)
        else:
            p = HTMLText()
            p.feed(src)
            found = p.out
        rel = os.path.relpath(path, ROOT)
        for line, s in found:
            if CJK.search(s) and "i18n-ignore" not in lines[line - 1]:
                keys.setdefault(s, []).append("%s:%d" % (rel, line))
    return keys


def args(s):
    """The argument list at the start of s (up to the unmatched ")"), strings skipped over."""
    depth, q, i = 0, None, 0
    while i < len(s):
        c = s[i]
        if q:
            if c == "\\":
                i += 1
            elif c == q:
                q = None
        elif c in "\"'`":
            q = c
        elif c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0:
                return s[:i]
            depth -= 1
        i += 1
    return s


def lint():
    """Text that bypasses h() needs tr(): `el.textContent = "中文…"` (also title / placeholder) and a CJK
    string handed straight to append / prepend / replaceChildren (before any call such as h(…))."""
    errs = []
    assign = re.compile(r"\.(textContent|title|placeholder|innerText)\s*=(?!=)([^;]*)")
    insert = re.compile(r"\.(append|prepend|replaceChildren)\(")
    call = re.compile(r"[\w$]\(")
    for path in sorted(glob.glob(os.path.join(ROOT, "rootfs", "www", "ui", "*.js"))):
        with open(path, encoding="utf-8") as f:
            for no, l in enumerate(f, 1):
                if "i18n-ignore" in l:
                    continue
                where = "%s:%d" % (os.path.relpath(path, ROOT), no)
                for m in assign.finditer(l):
                    rhs = m.group(2)
                    if CJK.search(rhs) and "tr(" not in rhs:
                        errs.append("%s: .%s = … needs tr(…)" % (where, m.group(1)))
                for m in insert.finditer(l):
                    rest = args(l[m.end():])
                    c = call.search(rest)
                    if CJK.search(rest[:c.start() if c else len(rest)]):
                        errs.append("%s: a string given to .%s() needs tr(…)" % (where, m.group(1)))
    return errs


def load_en():
    if not os.path.exists(EN):
        return {}
    with open(EN, encoding="utf-8") as f:
        return json.load(f)


def edge(s):
    return re.match(r"\s*", s).group(0) != "", re.search(r"\s*$", s).group(0) != ""


def check():
    keys, en = extract(), load_en()
    bad = []
    missing = [k for k in keys if k not in en]
    for k in missing:
        bad.append("missing: %s  (%s)" % (json.dumps(k, ensure_ascii=False), keys[k][0]))
    for k, v in en.items():
        if not isinstance(v, str) or not v.strip():
            bad.append("empty translation: %s" % json.dumps(k, ensure_ascii=False))
        elif CJK.search(v):
            bad.append("CJK in translation: %s" % json.dumps(k, ensure_ascii=False))
        else:
            kl, kt = edge(k)
            vl, vt = edge(v)
            if (kl and not vl) or (kt and not vt):
                bad.append("leading/trailing space lost: %s → %s" % (json.dumps(k, ensure_ascii=False), json.dumps(v)))
    bad += lint()
    unused = [k for k in en if k not in keys]
    for k in unused:
        print("warning: unused key %s" % json.dumps(k, ensure_ascii=False))
    size = os.path.getsize(EN) if os.path.exists(EN) else 0
    print("i18n: %d UI strings, %d translated, en.json %d bytes (budget %d)" % (len(keys), len(keys) - len(missing), size, BUDGET))
    if size > BUDGET:
        print("warning: en.json is over the size budget")
    for b in bad:
        print(b)
    if bad:
        print("FAIL: %d problem(s); `python3 tools/i18n.py missing` prints a skeleton to translate" % len(bad))
        return 1
    return 0


def dump(d):
    return "{\n" + ",\n".join("%s: %s" % (json.dumps(k, ensure_ascii=False), json.dumps(v, ensure_ascii=False)) for k, v in d.items()) + "\n}\n"


def main(argv):
    cmd = argv[1] if len(argv) > 1 else "check"
    if cmd == "check":
        return check()
    if cmd == "missing":
        en = load_en()
        sys.stdout.write(dump({k: "" for k in extract() if k not in en}))
        return 0
    if cmd == "fmt":
        en = load_en()
        out = {k: en[k] for k in extract() if k in en}
        os.makedirs(os.path.dirname(EN), exist_ok=True)
        with open(EN, "w", encoding="utf-8") as f:
            f.write(dump(out))
        print("en.json: %d entries (%d unused dropped)" % (len(out), len(en) - len(out)))
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
