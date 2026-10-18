#!/usr/bin/env python3
"""
test_mail_signals.py — regression test for mail infrastructure as a same-operator signal.

wp_recon.detect_mail_provider already writes `artifacts.mail` (M365 tenant, custom MX hosts, SPF);
rank_relations scores it as ONE `mail` family at weight 3 and convergence counts it as growth. The
rail this defends: mail infra corroborates but NEVER links two hosts on its own — not even when an
M365 tenant and its own MX host both match (one fact, one family) — and shared-platform MX hosts
and SPF netblocks never become a signal at all (managed-provider vs self-hosted, CLAUDE.md RULE 5).

Every value is synthetic (`*.example`, RFC 5737 IPs). No network.

Run:  python3 tests/test_mail_signals.py
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts", "webpivot"))
sys.path.insert(0, os.path.join(ROOT, "intel_engine", "tools", "kb"))

import rank_relations as rr                                                    # noqa: E402
import convergence as cv                                                       # noqa: E402

SHARED_MX = "mx.dynadot.com"          # a hosted-platform apex in noise_filters.shared_infra_apexes


def _page(host, mail=None, favicon=None):
    art = {}
    if mail is not None:
        art["mail"] = mail
    if favicon is not None:
        art["favicon"] = {"shodan_mmh3": favicon}
    return {"meta": {"host": host}, "artifacts": art}


def _mail(tenant=None, mx=(), ip4=()):
    return {"m365_tenant": tenant, "custom_mx_hosts": list(mx),
            "spf": {"ip4": list(ip4), "ip6": []}}


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

    deny = frozenset()

    # 1. extraction: tenant + self-hosted MX + single-host SPF kept; netblock and shared MX dropped
    sig, _ = rr.extract_signals(_page("a.example", _mail(
        "op-example", mx=["mail.op.example", SHARED_MX],
        ip4=["192.0.2.10", "198.51.100.0/24", "203.0.113.5/32"])), deny)
    got = sig.get("mail", set())
    ok({"m365:op-example", "mx:mail.op.example", "spf_ip:192.0.2.10", "spf_ip:203.0.113.5"} <= got,
       "mail signal carries the M365 tenant, the custom MX and single-host SPF IPs")
    ok(f"mx:{SHARED_MX}" not in got, "an MX on a shared-infra apex never becomes a mail signal")
    ok(not any(v.startswith("spf_ip:198.51.100.") for v in got),
       "an SPF netblock (an ESP range) never becomes a mail signal")

    # 2. mail alone — even tenant AND its MX host both shared — is one family: no link, no cluster
    m = _mail("op-example", mx=["mail.op.example"])
    res = rr.rank([_page("a.example", m), _page("b.example", m)], deny, include_weak=True)
    rel = res["relations"][0] if res["relations"] else {}
    ok(rel.get("signals") == ["mail"] and rel.get("relation_strength") == 3,
       "a shared tenant + MX host scores ONE mail signal (strength 3), not two")
    ok(rel.get("assessment") == "weak_lead" and res["clusters"] == [],
       "mail infrastructure alone never links two hosts into a cluster")
    ok(rr.rank([_page("a.example", m), _page("b.example", m)], deny)["relations"] == [],
       "mail-only relation stays hidden as a weak lead by default")

    # 3. mail corroborating an independent signal does link
    res2 = rr.rank([_page("a.example", m, favicon=111222333),
                    _page("b.example", m, favicon=111222333)], deny)
    ok(res2["relations"] and res2["relations"][0]["assessment"] == "same_operator_likely"
       and res2["clusters"] == [["a.example", "b.example"]],
       "mail + an independent shared favicon clusters the pair")

    # 4. two hosts sharing only a shared-platform MX: no relation at all
    sh = _mail(mx=[SHARED_MX])
    ok(rr.rank([_page("a.example", sh), _page("b.example", sh)], deny, include_weak=True)
       ["relations"] == [],
       "two tenants of a shared-platform MX score no relation (co-tenancy, not ownership)")

    # 5. convergence counts the same mail facts as growth, with the same noise rules
    inds = cv._indicators_from_raw(_page("a.example", _mail(
        "Op-Example", mx=["mail.op.example", SHARED_MX], ip4=["192.0.2.10", "198.51.100.0/24"])))
    ok({"mail:m365:op-example", "mail:mx:mail.op.example", "mail:spf_ip:192.0.2.10"} <= inds,
       "convergence counts M365 tenant, custom MX and single-host SPF IPs as indicators")
    ok(f"mail:mx:{SHARED_MX}" not in inds and not any(i.startswith("mail:spf_ip:198.51.100.")
                                                      for i in inds),
       "convergence drops the shared-platform MX and the SPF netblock")

    return passed, failed, out


_PASSED, _FAILED, _LINES = check()


def test_mail_signals():
    """pytest entry point — the module body does the work at import time."""
    assert not _FAILED, [l for s, l in _LINES if s != "ok"]


if __name__ == "__main__":
    for status, label in _LINES:
        print(f"{'  ok  ' if status == 'ok' else '  FAIL'} {label}")
    print()
    if _FAILED:
        print(f"FAIL — {_FAILED} mail-signal check(s) failed")
    else:
        print(f"PASS — mail infrastructure corroborates but never links alone ({_PASSED} checks)")
    raise SystemExit(bool(_FAILED))
