#!/usr/bin/env python3
"""Regression gate for the 5 HIGH correctness bugs found in the 2026-07-31 audit.

Each assertion pins a specific fixed defect so it can't silently regress:
  H1 noise_filters.is_managed_dns   — label-boundary match (no `dan.com`⊂`jordan.com` false hit)
  H2 knowledge_base.KB._load_edges  — one torn JSONL line no longer crashes KB construction
  H3 wp_ippivot._dig                — strips dig's surrounding quotes so SPF/DMARC parse
  H4 wp_extract.extract_trackers    — clarity_ms only emits a real tag id, never `clarity("set"`
  H5 wayback_ga.sample_evenly       — no ZeroDivisionError at --max 1
Pure stdlib, deterministic. Run standalone or via run_eval.py.
"""
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "tools", "kb"))
sys.path.insert(0, os.path.join(ROOT, "WebPivot", "tools"))
import noise_filters as nf        # noqa: E402
import knowledge_base as kb       # noqa: E402
import wp_ippivot as ip           # noqa: E402
import wp_extract as ex           # noqa: E402
import wayback_ga as wg           # noqa: E402


def check():
    """Return (passed, failed, [outcome lines])."""
    out, passed, failed = [], 0, 0

    def ok(cond, label):
        nonlocal passed, failed
        passed, failed = (passed + 1, failed) if cond else (passed, failed + 1)
        out.append(("ok" if cond else "FAIL", label))

    # --- H1: managed-DNS label-boundary match ---
    ok(nf.is_managed_dns("ns1.jordan.com") is False, "H1 jordan.com NOT managed (⊄ dan.com)")
    ok(nf.is_managed_dns("ns1.casedo.com") is False, "H1 casedo.com NOT managed (⊄ sedo.com)")
    ok(nf.is_managed_dns("ns1.cloudflare.com") is True, "H1 real cloudflare.com still managed")
    ok(nf.is_managed_dns("carol.ns.cloudflare.com") is True, "H1 *.ns.cloudflare.com still managed")
    ok(nf.is_managed_dns("ns1.sedo.com") is True, "H1 real sedo.com still managed")
    ok(nf.is_managed_dns("ns-2048.awsdns-64.co.uk") is True, "H1 bare-label awsdns preserved")
    ok(nf.is_managed_dns("ns1.notawsdnsy.com") is False, "H1 awsdns substring not over-matched")

    # --- H2: a torn append line must NOT crash KB edge loading ---
    fd, tmp = tempfile.mkstemp(suffix=".jsonl")
    os.write(fd, b'{"src":"a","rel":"uses","dst":"b"}\n{"src":"c","rel":"broken"')  # 2nd line torn
    os.close(fd)
    inst = kb.KB.__new__(kb.KB)          # bypass __init__; _load_edges only needs .rel_path
    inst.rel_path = tmp
    try:
        edges = inst._load_edges()
        ok(len(edges) == 1 and edges[0]["rel"] == "uses", "H2 good edge kept, torn line skipped")
    except Exception as e:               # noqa: BLE001
        ok(False, f"H2 _load_edges raised: {e!r}")
    finally:
        os.unlink(tmp)

    # --- H3: _dig strips dig's double-quotes so SPF/DMARC prefixes match ---
    _which, _run = ip.shutil.which, ip.subprocess.run

    class _CP:
        def __init__(self, stdout):
            self.stdout = stdout
    try:
        ip.shutil.which = lambda _x: "/usr/bin/dig"
        ip.subprocess.run = lambda *a, **k: _CP('"v=spf1 include:_spf.example ~all"\n')
        got = ip._dig("op.example", "TXT")
        ok(got == ["v=spf1 include:_spf.example ~all"], "H3 _dig strips TXT quotes")
    finally:
        ip.shutil.which, ip.subprocess.run = _which, _run

    # --- H4: clarity_ms emits a real tag id, never the group-less `clarity("set"` garbage ---
    t_set = ex.extract_trackers('<script>clarity("set","k","v")</script>')
    ok("clarity_ms" not in t_set, "H4 bare clarity('set') → no garbage pivot")
    t_url = ex.extract_trackers('<img src="https://c.clarity.ms/tag/abcd1234ef">')
    ok(t_url.get("clarity_ms") == ["abcd1234ef"], "H4 clarity.ms/tag/<id> captured")
    t_ld = ex.extract_trackers('})(window,document,"clarity","script","abcd1234ef");')
    ok(t_ld.get("clarity_ms") == ["abcd1234ef"], "H4 clarity loader tag-id captured")

    # --- H5: no ZeroDivisionError at n==1 ---
    try:
        ok(wg.sample_evenly([10, 20, 30, 40], 1) == [10], "H5 sample_evenly(--max 1) → 1, no crash")
    except ZeroDivisionError:
        ok(False, "H5 sample_evenly still divides by zero at n==1")
    ok(wg.sample_evenly([1, 2, 3], 5) == [1, 2, 3], "H5 n>=len returns all")
    ok(len(wg.sample_evenly(list(range(10)), 3)) == 3, "H5 evenly samples n")

    return passed, failed, out


if __name__ == "__main__":
    p, f, lines = check()
    for status, label in lines:
        print(f"  [{status:4s}] {label}")
    print(f"\n{p} passed, {f} failed")
    sys.exit(1 if f else 0)
