#!/usr/bin/env python3
"""
test_validin_engines.py — offline regression gate for the premium-engine WebPivot clients
(wp_validin, wp_securitytrails, wp_dnslytics) added in
plans/260827-1901-validin-api-integration/ and wired into enrich_live + frontier
(tools/case_state.py) + report (evidence_report).

All three mirror the wp_hunterhow/wp_censys tri-state contract:
  * keyless-safe   -> every typed lookup returns None, nothing errors, nothing egresses.
  * tri-state      -> a normalised dict on success, {"skipped": reason} for auth/quota/tier
                       conditions the caller degrades around, {"error": reason} for transport
                       faults. Never raises.
  * quota-governed -> a per-run cap + a remaining-quota gate short-circuit BEFORE any HTTP call.

WHAT THIS FILE PROTECTS
------------------------
  1. Keyless safety for all 3 clients — no key -> *_configured() False, every typed lookup
     returns None, and ZERO network (urlopen patched to raise; any call fails the check loudly).
  2. Tri-state propagation for all 3 clients — a stubbed {"error":...}/{"skipped":...} from the
     low-level HTTP call comes back UNCHANGED; a stubbed normal payload normalises to the
     documented {"total", "hosts"/"domains"} shape; nothing raises.

See test_validin_engines_quota_frontier.py (same directory) for the Validin quota gate, the
cert_hosts fingerprint_sha1 path, and the case_state frontier-consumption regression — split out
to keep each module close to the ~200-line modularisation guideline.

OFFLINE, DETERMINISTIC, ZERO NETWORK. Every client function's HTTP-touching internals (`_get` /
`_get_raw`) is monkeypatched before any call, and `urllib.request.urlopen` itself is patched to
raise for the keyless paths — nothing here reads a real API key or egresses.

Run:  python3 tests/test_validin_engines.py
      pytest -q tests/test_validin_engines.py tests/test_validin_engines_quota_frontier.py
"""
import os
import sys
import urllib.request
from contextlib import contextmanager

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WP = os.path.join(ROOT, "WebPivot", "tools")
for _p in (WP,):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import wp_validin as V          # noqa: E402
import wp_securitytrails as S   # noqa: E402
import wp_dnslytics as D        # noqa: E402

_MISSING = object()


@contextmanager
def patched(mod, **attrs):
    """Save/restore module attributes. These clients cache key/quota state ON THE MODULE (one
    process = one case), so every check must leave it exactly as it found it for the next one."""
    saved = {k: getattr(mod, k, _MISSING) for k in attrs}
    for k, v in attrs.items():
        setattr(mod, k, v)
    try:
        yield
    finally:
        for k, v in saved.items():
            if v is _MISSING:
                delattr(mod, k)
            else:
                setattr(mod, k, v)


@contextmanager
def no_network():
    """Fail loudly instead of silently permitting a real HTTP call through any client."""
    def _blow_up(*_a, **_kw):
        raise AssertionError("urlopen called — a keyless/gated code path leaked to the network")
    with patched(urllib.request, urlopen=_blow_up):
        yield


def _check_keyless(mod, key_attr, configured_fn, lookups, ok):
    """Contract item 1: no key -> *_configured() False, every lookup -> None, zero network."""
    with patched(mod, **{key_attr: (lambda: None)}):
        try:
            with no_network():
                cfg = getattr(mod, configured_fn)()
                ok(cfg is False, f"{mod.__name__}.{configured_fn}() is False when keyless")
                for name, args in lookups:
                    r = getattr(mod, name)(*args)
                    ok(r is None, f"{mod.__name__}.{name}{args} -> None when keyless (got {r!r})")
        except AssertionError as e:
            ok(False, f"{mod.__name__}: keyless path touched the network — {e}")


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

    # --- 1. keyless safety, all 3 clients ---------------------------------------------------
    _check_keyless(V, "validin_key", "validin_configured",
                   [("domain_lookup", ("keyless.example",)), ("subdomains", ("keyless.example",)),
                    ("certificates", ("keyless.example",)), ("cert_hosts", ("aa" * 20,))], ok)
    _check_keyless(S, "securitytrails_key", "securitytrails_configured",
                   [("subdomains", ("keyless.example",)), ("dns_history", ("keyless.example",))],
                   ok)
    _check_keyless(D, "dnslytics_key", "dnslytics_configured",
                   [("reverse_ip", ("203.0.113.5",)),
                    ("ga_adsense_siblings", ("pub-1234567890",))], ok)

    # --- 2. tri-state propagation, all 3 clients --------------------------------------------
    with patched(V, validin_key=(lambda: "FAKEKEY"), _allow=(lambda bucket: True)):
        with patched(V, _get=(lambda path, **kw: (None, {"error": "boom"}))):
            r = V.subdomains("tri.example")
            ok(r == {"error": "boom"},
               f"validin: _get {{'error':...}} propagates unmodified (got {r!r})")
        with patched(V, _get=(lambda path, **kw: (None, {"skipped": "no key"}))):
            r = V.subdomains("tri.example")
            ok(r == {"skipped": "no key"},
               f"validin: _get {{'skipped':...}} propagates unmodified (got {r!r})")
        data = {"records": {"subdomains": [{"value": "a.tri.example"}, {"value": "b.tri.example"}]}}
        with patched(V, _get=(lambda path, **kw: (data, None))):
            r = V.subdomains("tri.example")
            ok(r == {"total": 2, "hosts": ["a.tri.example", "b.tri.example"]},
               f"validin: a normal dict normalises to total/hosts, nothing raises (got {r!r})")

    with patched(S, securitytrails_key=(lambda: "FAKEKEY"), _allow=(lambda: True)):
        with patched(S, _get_raw=(lambda path, **kw: (None, {"error": "boom"}))):
            r = S.subdomains("tri.example")
            ok(r == {"error": "boom"},
               f"securitytrails: {{'error':...}} propagates unmodified (got {r!r})")
        with patched(S, _get_raw=(lambda path, **kw: (None, {"skipped": "no key"}))):
            r = S.subdomains("tri.example")
            ok(r == {"skipped": "no key"},
               f"securitytrails: {{'skipped':...}} propagates unmodified (got {r!r})")
        data = {"subdomains": ["www", "gist"]}
        with patched(S, _get_raw=(lambda path, **kw: (data, None))):
            r = S.subdomains("tri.example")
            ok(r == {"total": 2, "hosts": ["www.tri.example", "gist.tri.example"]},
               f"securitytrails: bare labels join to the queried apex (got {r!r})")

    with patched(D, dnslytics_key=(lambda: "FAKEKEY"), _allow=(lambda cost: True)):
        with patched(D, _get=(lambda path, params, timeout=25: (None, {"error": "boom"}))):
            r = D.reverse_ip("203.0.113.9")
            ok(r == {"error": "boom"},
               f"dnslytics: {{'error':...}} propagates unmodified (got {r!r})")
        with patched(D, _get=(lambda path, params, timeout=25: (None, {"skipped": "no key"}))):
            r = D.reverse_ip("203.0.113.9")
            ok(r == {"skipped": "no key"},
               f"dnslytics: {{'skipped':...}} propagates unmodified (got {r!r})")
        body = {"status": "succeed", "data": {"ndomains": 2, "domains": ["a.example", "b.example"]}}
        with patched(D, _get=(lambda path, params, timeout=25: (body, None))):
            r = D.reverse_ip("203.0.113.9")
            ok(r == {"total": 2, "domains": ["a.example", "b.example"]},
               f"dnslytics: normal succeed-body normalises to total/domains (got {r!r})")

    return passed, failed, out


def main():
    passed, failed, lines = check()
    for status, label in lines:
        print(f"  {'ok ' if status == 'ok' else '✗  '} {label}")
    print(f"\n{passed} passed, {failed} failed")
    return 1 if failed else 0


def test_validin_premium_engines():
    """pytest entry point — keyless safety + tri-state propagation (this module's half)."""
    passed, failed, lines = check()
    assert not failed, [l for s, l in lines if s != "ok"]


if __name__ == "__main__":
    sys.exit(main())
