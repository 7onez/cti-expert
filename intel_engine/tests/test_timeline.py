#!/usr/bin/env python3
"""
test_timeline.py — the gate on the TEMPORAL layer (IntelAnalysis §1.5 + case_timeline.py).

Run:  python3 tests/test_timeline.py         (zero deps — the figure needs matplotlib, the
                                              extraction/correlation logic under test does not)
      python3 tools/eval/run_eval.py          (runs as part of the regression gate)

WHAT THIS PROTECTS
------------------
The doctrine this tool encodes is that a shared indicator only links two hosts if BOTH carried it
at the same time. Each check below guards a way that claim can silently become wrong:

  1. Timestamp parsing. Five collectors emit five formats (crt.sh ISO, getpeercert 'Jun  1 …',
     Wayback 14-digit, epoch seconds, plain dates). A format we silently fail to parse doesn't
     raise — the fact just vanishes from the timeline, and an absent interval reads as "no
     overlap to check" rather than as missing data.
  2. Host normalisation. `lstrip("www.")` strips CHARACTERS, so it renames 'world.example' to
     'orld.example' and splits one host's timeline into two lanes that can never overlap.
  3. Co-tenancy. Overlapping and non-overlapping tenancy of the same IP must be reported as
     DIFFERENT verdicts — collapsing them is exactly the false cluster this layer exists to stop.
  4. The expiry discriminator. Same expiry from different creation dates is a second, independent
     signal (one payer aligned the renewals); same expiry from a shared creation date + term is
     the registration cohort restated. Counting the second as independent double-counts one fact.
  5. Citations. Every emitted event must carry an ONLINE link or none at all — never a local
     case-store path, which is unverifiable for a reader and is the rule §7 exists to enforce.
"""
import os
import sys
from datetime import datetime, timedelta, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "IntelGraph", "scripts"))

import case_timeline as ct                                                     # noqa: E402


def _analysis(host, created, expires, ip, ip_first, ip_last, cert_nb, cert_id, updated="2025-02-01"):
    """A minimal pivot_extract-shaped result — synthetic placeholders only (RULE 1)."""
    return {
        "meta": {"source": f"https://{host}", "final_url": f"https://{host}/", "host": host},
        "artifacts": {"whois": {"domain": host, "registrar": "Example Registrar",
                                "created": created, "expires": expires, "updated": updated}},
        "pivots": [{"kind": "domain", "value": host, "live_results": {
            "crtsh": {"certs": [{"id": cert_id, "issuer": "C=US, O=Example CA", "names": [host],
                                 "not_before": cert_nb, "not_after": "2026-12-31T00:00:00"}]},
            "pdns": {"records": [{"rrname": host, "rrtype": "A", "rdata": ip,
                                  "time_first": ip_first, "time_last": ip_last, "count": 5}]}}}],
    }


def _events(analyses):
    out = []
    for a in analyses:
        host = ct._host_of(a)
        ct.whois_events(host, (a["artifacts"]).get("whois"), out)
        ct.cert_events(host, a, out)
        ct.hosting_events(host, a, out)
    return [e for e in out if e]


def check():
    """Return (passed, failed, [(status, label)]) — the tools/eval unit-module contract."""
    out, passed, failed = [], 0, 0

    def ok(cond, label):
        nonlocal passed, failed
        if cond:
            passed += 1
            out.append(("ok", label))
        else:
            failed += 1
            out.append(("FAIL", label))

    # --- 1. every collector's timestamp format parses to the same instant --------------------
    expect = datetime(2026, 6, 1, tzinfo=timezone.utc)
    for label, value in [("crt.sh ISO", "2026-06-01T00:00:00"),
                         ("ISO with Z", "2026-06-01T00:00:00Z"),
                         ("space-separated", "2026-06-01 00:00:00"),
                         ("plain date", "2026-06-01"),
                         ("Wayback 14-digit", "20260601000000"),
                         ("Wayback 8-digit", "20260601"),
                         ("getpeercert", "Jun  1 00:00:00 2026 GMT")]:
        got = ct.parse_dt(value)
        ok(got is not None and got.date() == expect.date(), f"parse_dt reads {label}: {value!r}")
    ok(ct.parse_dt(1780272000) == datetime(2026, 6, 1, tzinfo=timezone.utc),
       "parse_dt reads passive-DNS epoch seconds")
    ok(ct.parse_dt(None) is None and ct.parse_dt("") is None and ct.parse_dt("n/a") is None,
       "parse_dt returns None (not a wrong date) on empty/garbage")

    # --- 2. host normalisation must not eat leading characters -------------------------------
    ok(ct.strip_www("www.site-a.example") == "site-a.example", "strip_www removes a www. prefix")
    ok(ct.strip_www("world.example") == "world.example",
       "strip_www leaves 'world.example' intact (lstrip('www.') would give 'orld.example')")
    ok(ct.strip_www("WWW.Site-A.Example.") == "site-a.example",
       "strip_www normalises case + trailing dot")

    # --- 3. co-tenancy is an OVERLAP claim, not a shared-value claim --------------------------
    day = 86400
    base = 1700000000
    overlapping = [_analysis("site-a.example", "2023-01-10", "2026-01-10", "198.51.100.10",
                             base, base + 400 * day, "2025-11-02T10:00:00", 1),
                   _analysis("site-b.example", "2024-05-02", "2026-01-10", "198.51.100.10",
                             base + 100 * day, base + 400 * day, "2025-11-02T10:20:00", 2)]
    corr = ct.correlate(_events(overlapping))
    ten = corr["ip_tenancy"]
    ok(len(ten) == 1 and ten[0]["ip"] == "198.51.100.10", "shared IP surfaces as one tenancy row")
    ok(ten[0]["pairs"] and ten[0]["pairs"][0]["verdict"] == "co-tenant",
       "overlapping hosting windows -> co-tenant")
    ok(ten[0]["pairs"][0]["overlap_days"] > 0 and ten[0]["pairs"][0]["overlap"],
       "co-tenancy states the overlap interval and its length")

    sequential = [_analysis("site-a.example", "2023-01-10", "2026-01-10", "198.51.100.10",
                            base, base + 90 * day, "2025-11-02T10:00:00", 1),
                  _analysis("site-b.example", "2024-05-02", "2026-01-10", "198.51.100.10",
                            base + 200 * day, base + 300 * day, "2025-11-02T10:20:00", 2)]
    seq = ct.correlate(_events(sequential))["ip_tenancy"]
    ok(seq and "NOT co-tenancy" in seq[0]["pairs"][0]["verdict"],
       "NON-overlapping windows on one IP -> sequential tenancy, NOT co-tenancy")
    ok(seq[0]["pairs"][0]["overlap_days"] == 0, "sequential tenancy reports zero overlap")

    # --- 4. the expiry discriminator (one payer vs one fact restated) -------------------------
    exp = corr["expiry_cohorts"]
    ok(len(exp) == 1 and exp[0]["expires"] == "2026-01-10", "shared expiry date forms a cohort")
    ok(exp[0]["independent_signal"] is True,
       "same expiry from DIFFERENT creation days = an independent signal (one payer)")
    same_created = [_analysis("site-a.example", "2024-05-02", "2025-05-02", "203.0.113.1",
                              base, base + day, "2025-11-02T10:00:00", 3),
                    _analysis("site-b.example", "2024-05-02", "2025-05-02", "203.0.113.2",
                              base, base + day, "2025-11-02T10:00:00", 4)]
    c2 = ct.correlate(_events(same_created))
    ok(c2["expiry_cohorts"] and c2["expiry_cohorts"][0]["independent_signal"] is False,
       "same expiry from the SAME creation day is the registration cohort restated, not a 2nd signal")
    ok(c2["registration_cohorts"] and len(c2["registration_cohorts"][0]["hosts"]) == 2,
       "same-day creation surfaces as a registration cohort")
    ok(c2["lapse_cohorts"] and len(c2["lapse_cohorts"][0]["hosts"]) == 2,
       "expiry already passed with no renewal -> abandonment cohort (dates the campaign's end)")

    # --- 5. certificate issuance batches group inside the cohort window ----------------------
    ok(corr["cert_batches"] and len(corr["cert_batches"][0]["hosts"]) == 2,
       "certs issued 20 minutes apart across two hosts = one provisioning run")
    wide = [_analysis("site-a.example", "2023-01-10", "2026-01-10", "198.51.100.10",
                      base, base + day, "2024-01-02T10:00:00", 5),
            _analysis("site-b.example", "2024-05-02", "2026-01-10", "198.51.100.11",
                      base, base + day, "2025-07-09T10:00:00", 6)]
    ok(not ct.correlate(_events(wide))["cert_batches"],
       "certs issued 18 months apart are NOT reported as one batch")

    # --- 6. shared artifacts: contemporaneous or not -----------------------------------------
    def _hist(host, first, last):
        return {"domain": host, "snapshots_total": 9, "span": [first, last],
                "pivots": [{"kind": "tracker:ga4", "value": "G-XXXXXXXXXX",
                            "first_seen": first, "last_seen": last, "hits": 4}]}

    ev = []
    ct.history_events(_hist("site-a.example", "20230115000000", "20260101000000"), ev)
    ct.history_events(_hist("site-b.example", "20240601000000", "20260101000000"), ev)
    shared = ct.correlate([e for e in ev if e])["shared_artifact_windows"]
    ok(shared and shared[0]["contemporaneous"] is True and shared[0]["overlap_days"] > 0,
       "one artifact on two hosts with overlapping windows -> contemporaneous link")

    ev = []
    ct.history_events(_hist("site-a.example", "20200101000000", "20201231000000"), ev)
    ct.history_events(_hist("site-b.example", "20240601000000", "20260101000000"), ev)
    apart = ct.correlate([e for e in ev if e])["shared_artifact_windows"]
    ok(apart and apart[0]["contemporaneous"] is False and apart[0]["overlap_days"] == 0,
       "same artifact in windows years apart -> NOT contemporaneous (resold kit reading)")

    # --- 7. citations are online, or absent — never a local case-store path -------------------
    every = _events(overlapping)
    ct.observation_events("site-a.example", overlapping[0], every,
                          datetime.now(timezone.utc) - timedelta(days=1), {"site-a.example"})
    bad = [e for e in every if e.get("url") and not str(e["url"]).startswith(("http://", "https://"))]
    ok(not bad, f"every event link is an http(s) URL, never a file path ({len(bad)} bad)")
    ok(all(e.get("source") and e.get("grading") for e in every),
       "every event carries a source and an Admiralty grade")
    ok(any("rdap.org" in (e.get("url") or "") for e in every)
       and any("crt.sh" in (e.get("url") or "") for e in every)
       and any("bgp.he.net" in (e.get("url") or "") for e in every),
       "registration / certificate / hosting rows each cite their public register")

    # --- 8. permalink minting degrades safely -------------------------------------------------
    ok(ct.permalink("rdap_domain", host="site-a.example") == "https://rdap.org/domain/site-a.example",
       "permalink mints a known template")
    ok(ct.permalink("no_such_service", host="x") is None,
       "unknown template -> None, never an invented URL shape")
    ok(ct.permalink("wayback_snapshot", timestamp="20240101000000") is None,
       "missing placeholder -> None, never a half-formatted link")
    ok(ct.link_name("https://urlscan.io/result/abc/") == "urlscan"
       and ct.link_name("https://web.archive.org/web/1/x") == "Wayback",
       "link_name labels a citation by the service it points at")

    return passed, failed, out


_PASSED, _FAILED, _LINES = check()


def test_timeline():
    """pytest entry point — the module body does the work at import time."""
    assert not _FAILED, [l for s, l in _LINES if s != "ok"]


if __name__ == "__main__":
    for status, label in _LINES:
        print(f"{'  ok  ' if status == 'ok' else '  FAIL'} {label}")
    print()
    if _FAILED:
        print(f"FAIL — {_FAILED} temporal check(s) failed")
        sys.exit(1)
    print(f"PASS — temporal layer green ({_PASSED} checks: formats parse, overlap ≠ shared value, "
          f"expiry discriminator holds, citations online)")
