#!/usr/bin/env python3
"""Offline unit gate for the licensed-API usage ledger (api_usage.record/summary)."""
import os
import sys
import json
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))), "WebPivot", "tools"))
import api_usage as A  # noqa: E402


def check():
    out, passed, failed = [], 0, 0

    def ok(cond, label):
        nonlocal passed, failed
        if cond:
            passed += 1
            out.append(("ok", label))
        else:
            failed += 1
            out.append(("FAIL", label))

    tf = tempfile.mktemp(suffix=".jsonl")
    A._session.clear()
    A.set_context(case="CASE-X", skill="WebPivot")
    A.record("fofa", "search", credits=1, query='ip="1.2.3.4"', results=8, path=tf)
    A.record("urlscan", "search", credits=2, query="domain:x", remaining=990, limit=1000, path=tf)
    A.record("fofa", "search", credits=0, ok=False, path=tf)   # error → 0 credits

    rows = [json.loads(l) for l in open(tf) if l.strip()]
    ok(len(rows) == 3, "3 records written to ledger")
    ok(rows[0]["case"] == "CASE-X" and rows[0]["skill"] == "WebPivot", "context tagged onto record")
    ok(rows[2]["credits"] == 0 and rows[2]["ok"] is False, "failed call → 0 credits")
    ok(all(r["ts"].endswith("Z") for r in rows), "UTC timestamps")

    summ = A.session_summary()
    ok(summ["fofa"]["calls"] == 2 and summ["fofa"]["credits"] == 1, "fofa: 2 calls, 1 credit")
    ok(summ["urlscan"]["calls"] == 1 and summ["urlscan"]["credits"] == 2, "urlscan: 1 call, 2 credits")

    # rate-limit header parsing
    class _H:
        def __init__(self, d): self._d = d
        def get(self, k, default=None): return self._d.get(k, default)

    class _R:
        headers = _H({"X-Rate-Limit-Remaining": "42", "X-Rate-Limit-Limit": "100"})
    ok(A.rl_headers(_R()) == (42, 100), "rate-limit headers parsed")
    ok(A.rl_headers(object()) == (None, None), "missing headers safe")

    os.unlink(tf)
    A._session.clear()
    return passed, failed, out


if __name__ == "__main__":
    p, f, lines = check()
    for s, l in lines:
        print(f"  {'ok ' if s == 'ok' else '✗  '} {l}")
    sys.exit(1 if f else 0)
