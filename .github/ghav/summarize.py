#!/usr/bin/env python3
"""Summarize per-step `strace -ff` traces into per-process file footprints.

Input:  $GHAV_TRACE_DIR/<step>/{cwd,start,t.<tid>}
Output: gzip JSON {step: {cwd, start, root, procs: {tgid: record}}}
A record has parent, argv, exe, cwd0, t0, t1 and the sorted path sets
read / write / probe / list / exec.
"""
import gzip
import json
import os
import re
import sys
from collections import deque

ROOT = os.environ.get("GHAV_TRACE_DIR", os.path.expanduser("~/ghav-trace"))
OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.expanduser("~/ghav-trace-summary.json.gz")

LINE = re.compile(r"^(\d+\.\d+)\s+(.*)$")
CALL = re.compile(r"^([a-z0-9_]+)\((.*)\)\s+=\s+(.*)$")
UNFINISHED = re.compile(r"^([a-z0-9_]+)\((.*)<unfinished \.\.\.>$")
RESUMED = re.compile(r"^<\.\.\. ([a-z0-9_]+) resumed>(.*)\)\s+=\s+(.*)$")
FD = re.compile(r"^(?:AT_FDCWD|-?\d+)(?:<(.*)>)?$")
RET_PATH = re.compile(r"^-?\d+<(.*)>")
STRING = re.compile(r'^"((?:[^"\\]|\\.)*)"(?:\.\.\.)?$')

WRITE_FLAGS = ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND")
PROBE_CALLS = {"stat", "lstat", "newfstatat", "fstatat64", "statx", "access",
               "faccessat", "faccessat2", "readlink", "readlinkat", "statfs"}
OPEN_CALLS = {"open", "openat", "openat2", "creat"}
DIRFD_FIRST = {"openat", "openat2", "newfstatat", "fstatat64", "statx", "faccessat",
               "faccessat2", "readlinkat", "mkdirat", "unlinkat", "fchmodat",
               "fchownat", "utimensat", "mknodat", "execveat", "renameat", "renameat2",
               "linkat"}
WRITE_ONE = {"mkdir", "rmdir", "unlink", "chmod", "chown", "lchown", "truncate",
             "mknod", "utime", "utimes"}


def split_args(s):
    """Split a strace argument list at top-level commas."""
    out, depth, cur, i, inq = [], 0, [], 0, False
    while i < len(s):
        c = s[i]
        if inq:
            cur.append(c)
            if c == "\\" and i + 1 < len(s):
                cur.append(s[i + 1])
                i += 1
            elif c == '"':
                inq = False
        elif c == '"':
            inq = True
            cur.append(c)
        elif c in "([{":
            depth += 1
            cur.append(c)
        elif c in ")]}":
            depth -= 1
            cur.append(c)
        elif c == "," and depth == 0:
            out.append("".join(cur).strip())
            cur = []
        else:
            cur.append(c)
        i += 1
    if cur:
        out.append("".join(cur).strip())
    return out


def unq(tok):
    m = STRING.match(tok or "")
    if not m:
        return None
    return bytes(m.group(1), "utf-8").decode("unicode_escape").encode("latin-1", "replace").decode("utf-8", "replace")


def fdpath(tok):
    m = FD.match(tok or "")
    return m.group(1) if m and m.group(1) else None


def join(base, p):
    if p is None:
        return None
    if not p.startswith("/"):
        if not base:
            return None
        p = os.path.join(base, p)
    return os.path.normpath(p)


def new_rec(parent, cwd0):
    return {"parent": parent, "argv": None, "exe": None, "cwd0": cwd0, "t0": None, "t1": None,
            "read": set(), "write": set(), "probe": set(), "list": set(), "exec": set()}


def summarize_step(sdir):
    files = {}
    for name in os.listdir(sdir):
        if name.startswith("t.") and name[2:].isdigit():
            files[int(name[2:])] = os.path.join(sdir, name)
    with open(os.path.join(sdir, "cwd")) as f:
        root_cwd = f.read().strip()
    start = open(os.path.join(sdir, "start")).read().strip() if os.path.exists(os.path.join(sdir, "start")) else None

    children = {}  # child tid -> (parent tid, is_thread)
    first_pass = {}
    for tid, path in files.items():
        with open(path, errors="replace") as f:
            for raw in f:
                m = LINE.match(raw.rstrip("\n"))
                if not m:
                    continue
                body = m.group(2)
                c = CALL.match(body) or RESUMED.match(body)
                if not c:
                    continue
                name, ret = c.group(1), c.group(3)
                if name in ("clone", "clone3", "fork", "vfork"):
                    r = ret.split()[0]
                    if r.isdigit():
                        children[int(r)] = (tid, "CLONE_THREAD" in body)
    roots = [t for t in files if t not in children]
    root = min(roots) if roots else min(files)

    tgid_of = {root: root}
    procs = {root: new_rec(None, root_cwd)}
    cwd = {root: root_cwd}
    order = deque([root])
    seen = set()
    while order:
        tid = order.popleft()
        if tid in seen or tid not in files:
            continue
        seen.add(tid)
        tg = tgid_of[tid]
        rec = procs[tg]
        pending = {}
        with open(files[tid], errors="replace") as f:
            for raw in f:
                m = LINE.match(raw.rstrip("\n"))
                if not m:
                    continue
                ts, body = float(m.group(1)), m.group(2)
                u = UNFINISHED.match(body)
                if u:
                    pending[u.group(1)] = u.group(2)
                    continue
                r = RESUMED.match(body)
                if r:
                    name = r.group(1)
                    args = pending.pop(name, "") + r.group(2)
                    ret = r.group(3)
                else:
                    c = CALL.match(body)
                    if not c:
                        continue
                    name, args, ret = c.group(1), c.group(2), c.group(3)
                rec["t0"] = ts if rec["t0"] is None else min(rec["t0"], ts)
                rec["t1"] = ts if rec["t1"] is None else max(rec["t1"], ts)
                a = split_args(args)
                ok = not ret.startswith("-1")
                here = cwd.get(tg)
                if name in ("clone", "clone3", "fork", "vfork"):
                    rv = ret.split()[0]
                    if rv.isdigit():
                        child = int(rv)
                        if "CLONE_THREAD" in args or (child in children and children[child][1]):
                            tgid_of[child] = tg
                        else:
                            tgid_of[child] = child
                            procs[child] = new_rec(tg, here)
                            cwd[child] = here
                        order.append(child)
                    continue
                if name in ("chdir",):
                    if ok:
                        cwd[tg] = join(here, unq(a[0]))
                    continue
                if name == "fchdir":
                    p = fdpath(a[0]) if a else None
                    if ok and p:
                        cwd[tg] = p
                    continue
                if name in ("getdents64", "getdents"):
                    p = fdpath(a[0]) if a else None
                    if p and ok:
                        rec["list"].add(p)
                    continue
                base = here
                pi = 0
                if name in DIRFD_FIRST and a:
                    base = fdpath(a[0]) or here
                    pi = 1
                path = join(base, unq(a[pi])) if len(a) > pi else None
                if name in ("utimensat",) and path is None and a:
                    path = fdpath(a[0])
                if name in ("execve", "execveat"):
                    if path:
                        rec["exec"].add(path)
                    if ok and ret.strip().startswith("0"):
                        rec["exe"] = path
                        argv_tok = a[pi + 1] if len(a) > pi + 1 else ""
                        rec["argv"] = [unq(x.strip()) for x in split_args(argv_tok.strip()[1:-1])] if argv_tok.startswith("[") else None
                    continue
                if path is None:
                    continue
                if name in OPEN_CALLS:
                    flags = a[pi + 1] if len(a) > pi + 1 else ""
                    if name == "creat":
                        flags = "O_CREAT"
                    if not ok:
                        rec["probe"].add(path)
                    elif any(fl in flags for fl in WRITE_FLAGS):
                        rec["write"].add(path)
                    elif "O_DIRECTORY" in flags:
                        rec["probe"].add(path)
                    else:
                        rec["read"].add(path)
                elif name in PROBE_CALLS:
                    rec["probe"].add(path)
                elif name in WRITE_ONE or name in ("mkdirat", "unlinkat", "fchmodat", "fchownat", "utimensat", "mknodat"):
                    if ok:
                        rec["write"].add(path)
                elif name in ("rename", "renameat", "renameat2", "link", "linkat"):
                    if name == "rename" or name == "link":
                        src, dst = path, join(here, unq(a[1])) if len(a) > 1 else None
                    else:
                        src = path
                        dbase = (fdpath(a[2]) or here) if len(a) > 2 else here
                        dst = join(dbase, unq(a[3])) if len(a) > 3 else None
                    if ok:
                        (rec["write"] if name.startswith("rename") else rec["read"]).add(src)
                        if dst:
                            rec["write"].add(dst)
                elif name in ("symlink", "symlinkat"):
                    if name == "symlink":
                        dst = join(here, unq(a[1])) if len(a) > 1 else None
                    else:
                        dst = join(fdpath(a[1]) or here, unq(a[2])) if len(a) > 2 else None
                    if ok and dst:
                        rec["write"].add(dst)
    out = {}
    for tg, rec in procs.items():
        out[str(tg)] = {k: (sorted(v) if isinstance(v, set) else v) for k, v in rec.items()}
    return {"cwd": root_cwd, "start": start, "root": root, "files": len(files), "procs": out}


def main():
    summary = {}
    for step in sorted(os.listdir(ROOT)):
        sdir = os.path.join(ROOT, step)
        if not os.path.isdir(sdir):
            continue
        try:
            summary[step] = summarize_step(sdir)
            s = summary[step]
            print(f"{step}: {s['files']} thread files, {len(s['procs'])} processes")
        except Exception as e:  # keep going; the raw traces are uploaded too
            summary[step] = {"error": repr(e)}
            print(f"{step}: ERROR {e!r}")
    with gzip.open(OUT, "wt") as f:
        json.dump(summary, f)
    print("wrote", OUT, os.path.getsize(OUT), "bytes")


if __name__ == "__main__":
    main()
