#!/usr/bin/env python3
"""
test_render_mermaid_flags.py — render_mermaid.py must only pass flags the INSTALLED mmdc accepts.

Run:  python3 tests/test_render_mermaid_flags.py   (stdlib only; a stub mmdc, no Chrome)

The regression: mermaid-cli 12 removed `-w/--width` (and `-f/--pdfFit`) and exits with
"error: unknown option '-w'". render_mermaid appended `-w <n>` unconditionally, so every harness
render failed. A stub mmdc that advertises the v12 option set and rejects the removed flags must
render the whole triple (+ PDF); a stub advertising the legacy set must still receive `-w`.
"""
import os
import stat
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "IntelGraph", "scripts"))

import render_mermaid as rm                                                    # noqa: E402

_STUB = r'''#!{py}
import sys
V12 = {v12}
args = sys.argv[1:]
if "--help" in args:
    print("Usage: mmdc [options]\n\nOptions:")
    print("  -t, --theme <theme>  Theme")
    if V12:
        print("  --size <size>  Size of the diagram.")
    else:
        print("  -w, --width <width>  Width of the page")
        print("  -f, --pdfFit  Scale PDF to fit chart")
    for line in ("  -i, --input <input>  Input", "  -o, --output <output>  Output",
                 "  -b, --backgroundColor <c>  bg", "  -C, --cssFile <f>  css",
                 "  -s, --scale <scale>  scale", "  -p --puppeteerConfigFile <f>  pptr",
                 "  -h, --help  display help for command"):
        print(line)
    sys.exit(0)
with open({log!r}, "a", encoding="utf-8") as fh:
    fh.write(" ".join(args) + "\n")
if V12:
    for bad in ("-w", "--width", "-f", "--pdfFit"):
        if bad in args:
            sys.stderr.write("error: unknown option '%s'\n" % bad)
            sys.exit(1)
open(args[args.index("-o") + 1], "w").write("stub")
'''


def _stub(bindir, log, v12):
    path = os.path.join(bindir, "mmdc")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(_STUB.format(py=sys.executable, v12=v12, log=log))
    os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _render(v12, tmp):
    bindir = os.path.join(tmp, "v12" if v12 else "legacy")
    os.makedirs(bindir)
    log = os.path.join(bindir, "calls.log")
    _stub(bindir, log, v12)
    mmd = os.path.join(tmp, "g.mmd")
    with open(mmd, "w", encoding="utf-8") as fh:
        fh.write("graph LR\n  a --> b\n")
    old = os.environ.get("PATH", "")
    os.environ["PATH"] = bindir + os.pathsep + old
    try:
        outs = rm.render(mmd, os.path.join(bindir, "fig"), 2200, "neutral", "white",
                         scale=2, pdf=True)
        err = ""
    except SystemExit as exc:
        outs, err = [], str(exc)
    finally:
        os.environ["PATH"] = old
    calls = open(log, encoding="utf-8").read().splitlines() if os.path.isfile(log) else []
    return outs, err, calls


def check():
    out, passed, failed = [], 0, 0

    def ok(cond, label):
        nonlocal passed, failed
        passed += bool(cond)
        failed += not cond
        out.append(("ok" if cond else "FAIL", label))

    with tempfile.TemporaryDirectory() as tmp:
        outs, err, calls = _render(True, tmp)
        ok(len(outs) == 4 and not err, f"mmdc 12 (rejects -w/-f): svg+hires+thumb+pdf rendered "
                                       f"({len(outs)} outputs{', ' + err if err else ''})")
        ok(calls and not any(" -w " in f" {c} " or " -f " in f" {c} " for c in calls),
           "mmdc 12: no removed flag passed")
        ok(any("_thumb.png" in c and "--size 900" in c for c in calls),
           "mmdc 12: the thumb is capped with --size instead")
        outs, err, calls = _render(False, tmp)
        ok(len(outs) == 4 and any("_hires.png" in c and "-w 2200" in c for c in calls),
           "legacy mmdc (advertises -w): -w still passed")
    return passed, failed, out


if __name__ == "__main__":
    p, f, lines = check()
    for status, label in lines:
        print(f"{'  ok  ' if status == 'ok' else '  FAIL'} {label}")
    if f:
        print(f"FAIL — {f} mmdc flag check(s) failed")
        sys.exit(1)
    print(f"PASS — render_mermaid passes only flags the installed mmdc accepts ({p} checks)")
