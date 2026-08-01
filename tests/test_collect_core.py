#!/usr/bin/env python3
"""collect_core regression tests — the single-sourced host-collection routine BOTH the MCP harness
(harness/tools.py) and the deterministic pipeline (tools/intel.py) delegate to.

Covers the behaviours most expensive to silently regress:
  - egress policy: never fetch hostile infra directly (must demand passive/proxy first)
  - cache-reuse across cases: don't re-spend on an already-investigated host, and copy it in
  - force: bypass the cache and re-collect
  - collect_many: parallel fan-out with the on_result callback and miss-retry
  - the loop seam: collect -> ingest -> correlate, two peers cluster on a shared indicator

Run:  python3 tests/test_collect_core.py                    (zero deps, no pytest needed)
      .venv/bin/pytest tests/test_collect_core.py -q        (also works)

No case data here — only placeholders (example.com / site-a.example / CASE-000x), which CLAUDE.md
explicitly permits in tracked files. Fully hermetic: a stub collector stands in for pivot_extract,
so nothing touches the network or the real knowledge/ + cases/ stores.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ENGINE = os.path.join(HERE, "..", "intel_engine")
sys.path.insert(0, os.path.join(ENGINE, "tools"))

import collect_core as C  # noqa: E402

FAILURES = []


def check(label, got, want=True):
    if got != want:
        FAILURES.append(f"{label}: got {got!r}, want {want!r}")


# A hermetic stub collector: honours pivot_extract's `-o <path>` contract, writes a minimal
# evidence envelope, and reaches nothing. Its --help lists the flags so none get filtered.
_STUB = r'''
import sys, json
a = sys.argv[1:]
if "--help" in a:
    print("usage: stub [--pretty] [-o O] [--save-dom D] [--timeout T] [--render]"
          " [--whois-reverse] [--no-enrich] [--no-whois] [--fofa-full]")
    sys.exit(0)
out = a[a.index("-o") + 1] if "-o" in a else None
host = a[0].split("://", 1)[-1].split("/", 1)[0]
if out:
    json.dump({"meta": {"host": host}, "artifacts": {}, "pivots": [{"kind": "x", "value": "1"}]},
              open(out, "w"))
'''


def _write_stub(dirpath):
    p = os.path.join(dirpath, "stub_collector.py")
    with open(p, "w") as fh:
        fh.write(_STUB)
    return p


def _run_checks():
    root = tempfile.mkdtemp(prefix="cc-test-")
    try:
        stub = _write_stub(root)
        NX = "/nonexistent-collector.py"   # if this is ever executed, the run fails loudly

        # 1) EGRESS GATE — hostile + no passive/proxy is refused before the collector runs
        r = C.collect_host("https://evil.example", "CASE-0001", root=root, py=sys.executable,
                           collector=NX, hostile=True)
        check("egress gate blocks hostile", (not r["ok"]) and "BLOCKED" in (r["error"] or ""))
        r = C.collect_host("https://evil.example", "CASE-0001", root=root, py=sys.executable,
                           collector=stub, hostile=True, passive=True, no_archive=True)
        check("egress gate: passive bypass reaches collector", r["ok"])

        # 2) HAPPY PATH — stub run yields data + host, raw lands in the case
        r = C.collect_host("https://example.com", "CASE-0001", root=root, py=sys.executable,
                           collector=stub, no_archive=True)
        check("happy path ok", r["ok"] and not r["reused"])
        check("raw written into case", os.path.exists(
            os.path.join(root, "cases", "CASE-0001", "raw", "example.com.json")))

        # 3) CACHE-REUSE across cases — a host from CASE-0001 is reused for CASE-0002, no re-run
        r = C.collect_host("https://example.com", "CASE-0002", root=root, py=sys.executable,
                           collector=NX)   # would fail if it actually ran
        check("cache-reuse across cases", r["ok"] and r["reused"])
        check("cache-reuse copies into requested case", os.path.exists(
            os.path.join(root, "cases", "CASE-0002", "raw", "example.com.json")))

        # 4) FORCE bypasses the cache (re-runs the stub)
        r = C.collect_host("https://example.com", "CASE-0002", root=root, py=sys.executable,
                           collector=stub, no_archive=True, force=True)
        check("force re-collects (not reused)", not r["reused"])

        # 5) collect_many — fan-out + on_result + mixed cache/egress. Fresh hostile names (never
        # collected above) so they exercise the egress gate, not the cache.
        seen = []
        res = C.collect_many(
            ["https://example.com", "https://attacker.example", "https://ghost.example"],
            "CASE-0003",
            max_workers=3, on_result=lambda x: seen.append(x["host"]), retry_misses=1,
            root=root, py=sys.executable, collector=NX, hostile=True)
        byhost = {x["host"]: x for x in res}
        check("collect_many fans all seeds", len(res) == 3)
        check("collect_many on_result fired per host",
              sorted(seen) == ["attacker.example", "example.com", "ghost.example"])
        check("collect_many cache hit (example.com)", byhost["example.com"]["reused"] is True)
        check("collect_many egress-blocks hostile",
              "BLOCKED" in (byhost["attacker.example"]["error"] or ""))

        # 6) LOOP SEAM — collect -> ingest -> correlate: two peers cluster on a shared favicon
        kb = os.path.join(root, "kb")
        for h in ("site-a.example", "site-b.example"):
            json.dump({"meta": {"host": h},
                       "artifacts": {"favicon": {"shodan_mmh3": 987654321, "md5": "deadbeef"}}},
                      open(os.path.join(root, h + ".json"), "w"))
        kbtools = os.path.join(ENGINE, "tools", "kb")
        subprocess.run([sys.executable, os.path.join(kbtools, "ingest_webpivot.py"), "--kb", kb,
                        os.path.join(root, "site-a.example.json"),
                        os.path.join(root, "site-b.example.json")],
                       capture_output=True, text=True)
        q = subprocess.run([sys.executable, os.path.join(kbtools, "query.py"),
                            "--kb", kb, "--shared", "--min", "2"], capture_output=True, text=True)
        check("loop: peers cluster on shared favicon",
              "favicon:987654321" in q.stdout
              and "site-a.example" in q.stdout and "site-b.example" in q.stdout)
    finally:
        shutil.rmtree(root, ignore_errors=True)


_run_checks()


if __name__ == "__main__":
    if FAILURES:
        print("FAIL — collect_core regressions:")
        for f in FAILURES:
            print("  -", f)
        sys.exit(1)
    print("PASS — collect_core: egress gate, cache-reuse, force, collect_many fan-out, "
          "and the collect->ingest->correlate loop all green")


def test_collect_core():
    """pytest entry point — the module body does the work at import time."""
    assert not FAILURES, FAILURES
