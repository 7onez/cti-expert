#!/usr/bin/env python3
"""Gate for the WHOIS current+history parallelization in whois_summary (speed).

Proves the two WhoisXML calls run CONCURRENTLY (not sequentially) with a 2-party threading.Barrier:
both calls must reach it for it to clear, so if whois_summary ran them one-after-another the barrier
would time out and the test would fail. Also asserts the merged result is unchanged. Deterministic,
no network. Run standalone or via run_eval.py.
"""
import os
import sys
import threading

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "WebPivot", "tools"))
import whois_enrich as we  # noqa: E402


def check():
    out, passed, failed = [], 0, 0

    def ok(cond, label):
        nonlocal passed, failed
        passed, failed = (passed + 1, failed) if cond else (passed, failed + 1)
        out.append(("ok" if cond else "FAIL", label))

    barrier = threading.Barrier(2, timeout=5)   # clears ONLY if both calls run concurrently
    _key0, _cur0, _hist0 = we._key, we.whois_current, we.whois_history
    try:
        we._key = lambda: "FAKEKEY"

        def fake_cur(domain, timeout=40, keep_raw=True):
            barrier.wait()                       # blocks unless whois_history is also running now
            return {"registrant_name": "Owner A", "registrant_phone": "+15551234567"}

        def fake_hist(domain, mode="purchase", timeout=40, keep_raw=True):
            barrier.wait()
            return {"count": 3, "registrant_phones": ["+15551234567"], "registrant_names": ["Owner A"]}

        we.whois_current, we.whois_history = fake_cur, fake_hist
        try:
            res = we.whois_summary("op.example")
            concurrent = True
        except threading.BrokenBarrierError:
            res, concurrent = None, False           # barrier timed out ⇒ calls ran sequentially

        ok(concurrent, "current+history run CONCURRENTLY (barrier cleared)")
        ok(res is not None and res.get("registrant_name") == "Owner A", "current fields merged")
        ok(res is not None and (res.get("history") or {}).get("count") == 3, "history block merged")
    finally:
        we._key, we.whois_current, we.whois_history = _key0, _cur0, _hist0

    return passed, failed, out


if __name__ == "__main__":
    p, f, lines = check()
    for status, label in lines:
        print(f"  [{status:4s}] {label}")
    print(f"\n{p} passed, {f} failed")
    sys.exit(1 if f else 0)
