#!/usr/bin/env python3
"""Compare the GHAV noninterference runs of smoke (oauth.json) and storybook (coverage/)."""
import difflib
import hashlib
import os
import re
import sys

RUNS = sys.argv[1]
ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
NOISE = [
    (re.compile(r"\d{4}-\d\d-\d\dT[\d:.]+Z?"), "<ts>"),
    (re.compile(r"\b\d+(\.\d+)?\s?(ms|s|m)\b"), "<dur>"),
    (re.compile(r"(localhost|127\.0\.0\.1|\[::1\]):\d+"), r"\1:<port>"),
    (re.compile(r"/tmp/[\w.\-/]+"), "/tmp/<tmp>"),
    (re.compile(r"\b0x[0-9a-fA-F]+\b"), "<hex>"),
    (re.compile(r"\b[0-9a-f]{12,}\b"), "<id>"),
    (re.compile(r"\bpid[ =:]\d+", re.I), "pid <n>"),
    (re.compile(r"(Start at|Duration)\s+.*"), r"\1 <t>"),
]


def read(name):
    p = os.path.join(RUNS, name)
    return open(p, errors="replace").read() if os.path.exists(p) else None


def norm(text):
    out = []
    for line in (text or "").splitlines():
        line = ANSI.sub("", line).rstrip()
        for rx, rep in NOISE:
            line = rx.sub(rep, line)
        if line.strip():
            out.append(line)
    return out


def digest(lines):
    return hashlib.sha256("\n".join(lines).encode()).hexdigest()[:12]


def summary_lines(lines):
    keys = ("Test Files", "Tests ", "passed", "failed", "FAIL", "✓", "✗", "smoke", "OK", "ok")
    return [l for l in lines if any(k in l for k in ("Test Files", "Tests "))] or \
           [l for l in lines if any(k in l for k in keys)][-6:]


def report(kind, labels, pairs):
    print(f"\n===== {kind}")
    data = {}
    for lab in labels:
        ex = (read(f"{kind}-{lab}.exit") or "?").strip()
        lines = norm(read(f"{kind}-{lab}.log"))
        extra = ""
        if kind == "smoke":
            extra = f" oauth={(read(f'smoke-{lab}.oauth') or '?').split()[0][:12]}"
            st = read(f"smoke-{lab}.state")
            extra += f" state={hashlib.sha256((st or '').encode()).hexdigest()[:12]}"
        data[lab] = lines
        print(f"{lab}: exit={ex} log={digest(lines)} lines={len(lines)}{extra}")
        for l in summary_lines(lines):
            print("     ", l[:150])
    for a, b, meaning in pairs:
        if a in data and b in data:
            same = data[a] == data[b]
            print(f"\n{a} vs {b} ({meaning}): normalized logs {'IDENTICAL' if same else 'DIFFER'}")
            if not same:
                for d in list(difflib.unified_diff(data[a], data[b], a, b, n=0, lineterm=""))[:30]:
                    print("   ", d[:160])


report("smoke", ["A1", "B1", "C1", "B2", "A2"],
       [("A1", "A2", "noise, same input"), ("B1", "B2", "noise, same input"),
        ("A1", "B1", "obligation: coverage vs validate oauth.json"),
        ("A1", "C1", "any dependence on oauth.json")])
report("storybook", ["P1", "Q1", "Q2", "P2"],
       [("P1", "P2", "noise, same input"), ("Q1", "Q2", "noise, same input"),
        ("P1", "Q1", "obligation: coverage/ present vs absent")])
