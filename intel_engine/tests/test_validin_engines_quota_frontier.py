#!/usr/bin/env python3
"""
test_validin_engines_quota_frontier.py — companion to test_validin_engines.py (same offline
premium-engine regression gate, split to keep each module close to the ~200-line modularisation
guideline). Reuses that file's `patched()` harness and the `wp_validin` module handle.

WHAT THIS FILE PROTECTS
------------------------
  3. wp_validin's quota gate — a low cached remaining-quota short-circuits domain_lookup() to
     {"skipped": "quota"} BEFORE any HTTP call; the per-domain cap
     (VALIDIN_MAX_CALLS_PER_DOMAIN, default 2) allows exactly 2 calls to the same bucket and
     short-circuits the 3rd.
  4. wp_validin.cert_hosts uses the SHA1 hash/pivots reverse path (CERT_FINGERPRINT category),
     never bleeding into favicon_hosts' FAVICON_HASH category.
  5. case_state._free_candidates_from_raw actually MINES the validin/validin_subs/hunterhow/
     censys_cert/securitytrails/dnslytics pivots into frontier candidates — the
     "wired-but-not-consumed" regression this whole suite exists to catch — and correctly
     dedupes a subdomain-of-seed to the seed apex (NOT a new candidate).

OFFLINE, DETERMINISTIC, ZERO NETWORK — see test_validin_engines.py's module docstring.

Run:  python3 tests/test_validin_engines_quota_frontier.py
      pytest -q tests/test_validin_engines_quota_frontier.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_validin_engines import V, patched  # noqa: E402 — shared harness + the Validin module

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS = os.path.join(ROOT, "tools")
if TOOLS not in sys.path:
    sys.path.insert(0, TOOLS)
import case_state as CS  # noqa: E402


def _counting_get(sink):
    """A _get stand-in that records every path it was asked for and answers with an empty,
    well-formed payload — proves exactly how many HTTP calls a gated call path fires."""
    def _get(path, **kw):
        sink.append(path)
        return {"dns": []}, None
    return _get


def _mine(obj, seeds=("seed.example",)):
    """Run the frontier miner over one synthetic raw pivot JSON -> (cands, deferred)."""
    cands, deferred = {}, CS._new_deferred()
    CS._free_candidates_from_raw(obj, cands, {CS._registrable(s) for s in seeds}, deferred)
    return cands, deferred


def _domain_pivot(**live):
    return {"meta": {"host": "seed.example"},
            "pivots": [{"kind": "domain", "value": "seed.example", "live_results": live}]}


def check():
    passed = failed = 0
    out = []

    def ok(cond, label):
        nonlocal passed, failed
        if cond:
            passed += 1
            out.append(("ok", label))
        else:
            failed += 1
            out.append(("FAIL", label))

    # --- 3a. low remaining quota short-circuits BEFORE any HTTP call -----------------------
    calls = []
    with patched(V, validin_key=(lambda: "FAKEKEY"),
                 _USAGE={"daily_remaining": 0, "monthly_remaining": 0},
                 _RUN_CALLS=0, _DOMAIN_CALLS={}):
        with patched(V, _get=_counting_get(calls)):
            r = V.domain_lookup("quota.example")
    ok(r == {"skipped": "quota"},
       f"validin: low remaining quota -> {{'skipped':'quota'}} (got {r!r})")
    ok(not calls, "validin: quota-gated domain_lookup fires ZERO HTTP calls")

    # --- 3b. per-domain cap (VALIDIN_MAX_CALLS_PER_DOMAIN=2) short-circuits the 3rd call ----
    calls = []
    with patched(V, validin_key=(lambda: "FAKEKEY"),
                 _USAGE={"daily_remaining": 100, "monthly_remaining": 100},
                 _RUN_CALLS=0, _DOMAIN_CALLS={}, _MAX_PER_DOMAIN=2):
        with patched(V, _get=_counting_get(calls)):
            r1 = V.domain_lookup("cap.example")
            r2 = V.domain_lookup("cap.example")
            r3 = V.domain_lookup("cap.example")
    ok(len(calls) == 2,
       f"validin: per-domain cap allows exactly 2 calls to the same bucket (got {len(calls)})")
    ok(r1 != {"skipped": "quota"} and r2 != {"skipped": "quota"},
       "validin: the first 2 calls to the bucket are NOT quota-skipped")
    ok(r3 == {"skipped": "quota"}, f"validin: the 3rd call to the SAME bucket short-circuits (got {r3!r})")

    # --- 4. cert_hosts: SHA1 hash/pivots path, CERT_FINGERPRINT category only --------------
    captured = {}

    def _fake_get(path, **kw):
        captured["path"] = path
        return {"records": {
            "CERT_FINGERPRINT": [{"value": "203.0.113.20"}, {"value": "203.0.113.21"}],
            "FAVICON_HASH": [{"value": "203.0.113.99"}],
        }}, None

    sha1 = "a1" * 20  # 40 hex chars — SHA1 length, distinct from SHA256's 64
    with patched(V, validin_key=(lambda: "FAKEKEY"), _allow=(lambda bucket: True), _get=_fake_get):
        r = V.cert_hosts(sha1)
    ok(sha1 in captured.get("path", ""),
       f"validin: cert_hosts sends the raw SHA1 value into the hash/pivots path "
       f"(got {captured.get('path')!r})")
    ok("hash/pivots" in captured.get("path", ""),
       "validin: cert_hosts hits the hash_pivots endpoint template")
    ok(r == {"total": 2, "hosts": ["203.0.113.20", "203.0.113.21"]},
       f"validin: cert_hosts filters strictly to CERT_FINGERPRINT, never FAVICON_HASH (got {r!r})")

    # --- 5. frontier consumption: every premium engine's pivots actually get mined ---------
    live = {
        "validin": {"hosts": ["validin-sib.example", "sub.seed.example"]},
        "validin_subs": {"hosts": ["validin-sub-sib.example"]},
        "hunterhow": {"hosts": [{"domain": "hunterhow-sib.example"}, "hunterhow-plain.example"]},
        "censys_cert": {"names": ["censys-sib.example"]},
        "securitytrails": {"hosts": ["securitytrails-sib.example"]},
        "dnslytics": {"domains": ["dnslytics-sib.example"]},
    }
    cands, _deferred = _mine(_domain_pivot(**live))
    expected = {
        "validin-sib.example": {"validin"},
        "validin-sub-sib.example": {"validin_subdomain"},
        "hunterhow-sib.example": {"hunterhow"},
        "hunterhow-plain.example": {"hunterhow"},
        "censys-sib.example": {"censys_cert"},
        "securitytrails-sib.example": {"securitytrails"},
        "dnslytics-sib.example": {"dnslytics"},
    }
    for apex, sources in expected.items():
        ok(apex in cands,
           f"frontier: {apex} mined as a frontier candidate (wired-but-not-consumed guard)")
        ok(cands.get(apex, {}).get("sources") == sources,
           f"frontier: {apex} tagged source={sources} (got {cands.get(apex, {}).get('sources')})")
    ok(len(cands) == len(expected),
       f"frontier: subdomain-of-seed dedupes to the seed apex, no phantom candidate "
       f"(got {len(cands)} candidates: {sorted(cands)})")

    return passed, failed, out


def main():
    passed, failed, lines = check()
    for status, label in lines:
        print(f"  {'ok ' if status == 'ok' else '✗  '} {label}")
    print(f"\n{passed} passed, {failed} failed")
    return 1 if failed else 0


def test_validin_quota_cert_and_frontier():
    """pytest entry point."""
    passed, failed, lines = check()
    assert not failed, [l for s, l in lines if s != "ok"]


if __name__ == "__main__":
    sys.exit(main())
