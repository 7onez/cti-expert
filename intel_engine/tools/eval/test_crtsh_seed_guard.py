#!/usr/bin/env python3
"""Offline unit gate for the A3 crt.sh co-tenancy guard (case_state._crtsh_candidates).

A live run seeded two foreign apexes from a re-registered domain's crt.sh listing: wp_recon.py
keeps only the newest 40 certs (`certs[:40]`) but builds the flat `subdomains` list from ALL certs
plus other CT peers, so a foreign apex could ride in on a cert never examined by the per-cert
MAX_CERT_APEXES guard at all — and even ON an examined narrow cert, that cert could predate the
CURRENT owner's registration (crt.sh logs certs forever; the host was a 2025 re-registration of a
name with prior owners). This defends both gaps, through `_free_candidates_from_raw` — the same
public frontier-mining entry point `test_frontier_guards.py` exercises — never the private helper
directly:
  (a) a foreign apex named ONLY in the flat listing (no examined cert carries it) never seeds,
      and is recorded as an `unexamined` cert_overlap lead; an own-apex name in the same list
      still seeds normally.
  (b) a foreign co-SAN on a kept NARROW cert seeds when that cert's `not_before` is on/after the
      host's current WHOIS registration date.
  (c) the same shape, but the cert predates the registration -> held back as a `previous_owner`
      lead, never seeded.
  (d) the host's current registration date is unknown -> held back as an `unregistered` lead,
      never seeded (guessing is worse than asking).
  (e) a wide (> MAX_CERT_APEXES) cert is still rejected outright, unaffected by any of the above.
Synthetic data only (*.example names, made-up dates).
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))), "tools"))
import case_state as CS  # noqa: E402

SEED = "seed.example"


def _raw(crt, registered_on=None):
    obj = {"meta": {"host": SEED},
           "pivots": [{"kind": "domain", "value": SEED, "live_results": {"crtsh": crt}}]}
    if registered_on:
        obj["artifacts"] = {"whois": {"created": registered_on}}
    return obj


def _mine(obj):
    """Run the public frontier-mining entry point over one synthetic raw pivot JSON."""
    cands, deferred = {}, CS._new_deferred()
    CS._SUBS.clear()
    CS._free_candidates_from_raw(obj, cands, {CS._registrable(SEED)}, deferred)
    leads = [v for slot in deferred.values() for v in slot.values()]
    return set(cands), leads


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

    # --- (a) flat-list bypass: an own subdomain and a foreign apex both appear ONLY in the flat
    # `subdomains` list; the foreign one's certificate was never among the ones examined above.
    crt_a = {"certs": [{"id": 1, "names": [SEED]}],
             "subdomains": ["sub.seed.example", "foreign-flat.example"]}
    apex, leads = _mine(_raw(crt_a))
    ok("foreign-flat.example" not in apex,
       "(a) flat-list foreign apex with no examined cert does NOT seed")
    ok("sub.seed.example" in CS._SUBS.get(SEED, {}),
       "(a) flat-list OWN subdomain still seeds")
    unexamined = [l for l in leads if l.get("check") == "cert_overlap"
                  and "flat CT subdomain listing" in l.get("why", "")]
    ok(bool(unexamined) and unexamined[0].get("sample_apexes") == ["foreign-flat.example"],
       "(a) held back as an `unexamined` cert_overlap lead naming the foreign apex")

    # --- (b) foreign co-SAN on a kept narrow cert, issued AFTER the current registration.
    crt_b = {"certs": [{"id": 2, "names": [SEED, "co-fresh.example"],
                        "not_before": "2024-06-01T00:00:00"}],
             "subdomains": ["co-fresh.example"]}
    apex, leads = _mine(_raw(crt_b, registered_on="2024-01-01"))
    ok("co-fresh.example" in apex, "(b) cert issued AFTER registration: foreign co-SAN seeds")
    ok(not leads, "(b) cert issued after registration: no co-tenancy lead")

    # --- (c) same shape, cert issued BEFORE the current registration (previous owner's era).
    crt_c = {"certs": [{"id": 3, "names": [SEED, "co-stale.example"],
                        "not_before": "2023-01-01T00:00:00"}],
             "subdomains": ["co-stale.example"]}
    apex, leads = _mine(_raw(crt_c, registered_on="2024-01-01"))
    ok("co-stale.example" not in apex,
       "(c) cert issued BEFORE registration: foreign co-SAN does NOT seed")
    stale = [l for l in leads if l.get("check") == "cert_overlap"
             and "previous-owner-era cert" in l.get("why", "")]
    ok(bool(stale) and stale[0].get("sample_apexes") == ["co-stale.example"],
       "(c) held back as a `previous_owner` lead")

    # --- (d) current registration date unknown -> cannot confirm the cert postdates this owner.
    crt_d = {"certs": [{"id": 4, "names": [SEED, "co-unknown.example"],
                        "not_before": "2024-06-01T00:00:00"}],
             "subdomains": ["co-unknown.example"]}
    apex, leads = _mine(_raw(crt_d, registered_on=None))
    ok("co-unknown.example" not in apex,
       "(d) registration date unknown: foreign co-SAN does NOT seed")
    unknown = [l for l in leads if l.get("check") == "cert_overlap"
               and "registration date is unknown" in l.get("why", "")]
    ok(bool(unknown) and unknown[0].get("sample_apexes") == ["co-unknown.example"],
       "(d) held back as an `unregistered` lead")

    # --- (e) wide-cert rejection is unaffected by the date gate.
    wide_names = [SEED] + [f"tenant{i}.example" for i in range(CS.MAX_CERT_APEXES + 2)]
    crt_e = {"certs": [{"id": 5, "names": wide_names, "not_before": "2024-06-01T00:00:00"}],
             "subdomains": [n for n in wide_names if n != SEED]}
    apex, leads = _mine(_raw(crt_e, registered_on="2024-01-01"))
    ok(not any(a.startswith("tenant") for a in apex),
       "(e) wide cert: co-names do NOT seed (unchanged)")
    ok(any(l.get("check") == "cert_overlap" and l.get("apex_count", 0) > CS.MAX_CERT_APEXES
           for l in leads),
       "(e) wide cert: still raised as a multi-tenant cert_overlap lead (unchanged)")

    return passed, failed, out


if __name__ == "__main__":
    p, f, lines = check()
    for s, l in lines:
        print(f"  {'ok ' if s == 'ok' else '✗  '} {l}")
    print(f"\n{p} passed, {f} failed")
    sys.exit(1 if f else 0)
