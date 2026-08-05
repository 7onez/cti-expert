#!/usr/bin/env python3
"""Offline unit gate for the two SELECTOR/OBSERVATION layers — IntelX (wp_intelx) and ANY.RUN
(bp_anyrun).

Neither layer's live calls are exercised here: both need a key and both spend a metered allowance.
What IS gated is everything that decides whether their output is usable or actively misleading, and
each of these has a silent failure mode:

  1. **Keyless must still produce the query.** Both layers exist to be half-useful with no key: the
     selector/query is composed offline and the analyst runs it in the web UI. If the builder ever
     starts requiring a key, a keyless run degrades from "here is the query" to nothing, silently.
  2. **The ~50% capability statement must be present and loud.** A missing key is not an error, but
     an absent IntelX/ANY.RUN section that is not labelled reads as "the operator is in no leak" /
     "this sample is unknown" — a fact about the credentials misread as a fact about the target.
  3. **Soft selectors never reach IntelX.** IntelX refuses a brand or person name with an HTTP 400
     that still counts against the allowance. Classification happens locally, before the call.
  4. **ANY.RUN gets an observation field, not a string match.** `app:c2_endpoint` is `ip:port`; sent
     literally it matches nothing forever. It has to split into destinationIP + destinationPort.
  5. **Kinds neither service indexes emit NOTHING.** A favicon hash on IntelX or a signing cert on
     ANY.RUN is not a query that returns zero — it is a query that should never have been built.
  6. **The clustering policy fails CLOSED.** Breach co-membership (IntelX) and a shared malware
     family (ANY.RUN) are the textbook false clusters for these two corpora. If the policy data is
     unreadable, `clusterable()` / `grade_field()` must deny, not allow.
  7. **The spend guard actually blocks.** Both allowances are small and both fail silently when
     exhausted, so an over-budget call must come back as a `skipped` reason carrying the balance.

Run standalone (`python3 tools/eval/test_intelx_anyrun.py`) or via run_eval.py.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "WebPivot", "tools"))
sys.path.insert(0, os.path.join(ROOT, "BinaryPivot", "tools"))
import wp_intelx as ix     # noqa: E402
import bp_anyrun as ar     # noqa: E402

FAKE_EMAIL = "registrant@example.com"
FAKE_DOMAIN = "site-a.example"
FAKE_SHA256 = "a" * 64


def check():
    """Return (passed, failed, [outcome lines])."""
    out, passed, failed = [], 0, 0

    def ok(cond, label):
        nonlocal passed, failed
        if cond:
            passed += 1
            out.append(("ok", label))
        else:
            failed += 1
            out.append(("FAIL", label))

    # --- 1. reference DATA actually loaded (not the embedded fallback) -----------------------
    ok(len(ix.SELECTOR_TYPES) > 5,
       f"intelx.json selector_types loaded ({len(ix.SELECTOR_TYPES)} classes)")
    ok(len(ix.BUCKETS) >= 5, f"intelx.json bucket catalogue loaded ({len(ix.BUCKETS)} buckets)")
    ok(len(ar.QUERY_FIELDS) > 10,
       f"anyrun.json query_fields loaded ({len(ar.QUERY_FIELDS)} fields)")

    # --- 2. IntelX classifies STRONG selectors locally, and refuses soft ones -----------------
    ok(ix.classify_selector(FAKE_EMAIL)[0] == "email", "an email classifies as the email selector")
    ok(ix.classify_selector(FAKE_DOMAIN)[0] == "domain", "a domain classifies as the domain selector")
    ok(ix.classify_selector("198.51.100.7")[0] == "ipv4", "an IPv4 classifies as the ipv4 selector")
    ok(ix.classify_selector("+84 90 000 0000")[0] == "phone", "a phone number classifies as phone")
    ok(ix.classify_selector("https://site-a.example/login")[0] == "url", "a URL classifies as url")
    ok(ix.classify_selector("Some Brand Name")[0] is None,
       "a SOFT term (brand/person name) is refused locally — never sent, never charged")
    ok(ix.classify_selector("")[0] is None, "an empty term is refused")
    # A wildcard apex is the phonebook's whole point and must not be rejected by the pattern.
    ok(ix.classify_selector("*.site-a.example")[0] == "domain", "a wildcard apex still classifies")

    # --- 3. the KEYLESS query builder produces a runnable URL with no key ---------------------
    was_key = os.environ.pop("INTELX_KEY", None)
    try:
        ok(not ix.intelx_configured(), "no INTELX_KEY -> the layer reports itself unconfigured")
        qs = ix.intelx_queries("email", FAKE_EMAIL)
        ok(bool(qs), "keyless: an email pivot still gets IntelX entries")
        ok(any(q["query"].startswith("https://intelx.io/") for q in qs),
           "keyless: a ready-to-run intelx.io UI URL is emitted")
        dqs = ix.intelx_queries("domain", FAKE_DOMAIN)
        ok(any("phonebook" in (q.get("service") or "").lower() for q in dqs),
           "a domain pivot names the PHONEBOOK inventory explicitly (the layer's best move)")
        cap = ix.capability()
        ok(cap["power_pct"] == 50 and cap["mode"] == "keyless",
           "keyless IntelX reports ~50% capability")
        ok("not queried" in cap["statement"] or "never EXECUTED" in cap["statement"],
           "the IntelX statement says the indexes were NOT queried (an empty result is not a finding)")
        ok(bool(ix.banner_lines()), "keyless IntelX prints a banner")
        ok(not ix.banner_lines(free_only=False) == [], "banner is non-empty in keyless mode")
    finally:
        if was_key is not None:
            os.environ["INTELX_KEY"] = was_key
    # Fully keyed, the banner must be SILENT — a caveat on every run trains people to skip it.
    os.environ["INTELX_KEY"] = "test-key-not-a-real-credential"
    try:
        ok(ix.capability()["power_pct"] == 100, "with a key, IntelX reports full capability")
        ok(ix.banner_lines() == [], "with a key, IntelX prints NO banner")
        ok(ix.capability(free_only=True)["power_pct"] == 50,
           "--free-only reports ~50% even when the key exists (it is suppressed, not absent)")
    finally:
        os.environ.pop("INTELX_KEY", None)
        if was_key is not None:
            os.environ["INTELX_KEY"] = was_key

    # --- 4. kinds IntelX cannot search emit NOTHING -------------------------------------------
    ok(ix.intelx_queries("favicon_hash", "123456789") == [],
       "a favicon hash emits no IntelX query (IntelX does not index it)")
    ok(ix.intelx_queries("tracker:ga4", "G-XXXXXXXXXX") == [],
       "a GA4 tracker emits no IntelX query")
    ok(ix.selector_for_kind("jarm:hash") is None, "JARM is not an IntelX selector")

    # --- 5. IntelX bucket grading + FALSE-CLUSTER control -------------------------------------
    ok(not ix.clusterable("leaks.public.general"),
       "a public breach corpus is NOT clusterable — shared victims, not a shared operator")
    ok(not ix.clusterable("leaks.logs"),
       "a stealer log is NOT clusterable — it is victim/exposure evidence")
    ok(ix.clusterable("whois"), "a historical WHOIS snapshot IS clusterable")
    ok(ix.clusterable("pastes"), "a paste IS clusterable (often the operator's own text)")
    ok(not ix.clusterable("some.bucket.we.have.never.seen"),
       "an UNKNOWN bucket is not clusterable — the policy fails closed")
    ok(ix.bucket_grade("web.public.com")["grade"] != "ungraded",
       "a per-TLD web.public.<tld> bucket inherits the web.public grade")
    ok(ix.bucket_grade("leaks.logs")["grade"] == "strong", "stealer logs are graded strong")
    # LOGS BEAT DUMPS. A breach dump is one site's user table (an address and a year, recycled
    # through dozens of combolists); a stealer log is one machine at one moment, and may be the
    # OPERATOR's machine holding the campaign's panel credentials. If the ranking ever inverts, a
    # long-exposed address buries its one useful hit under a hundred stale combolist rows.
    ok(ix.bucket_rank("leaks.logs") < ix.bucket_rank("leaks.public.general"),
       "an infostealer log outranks a public breach dump")
    ok(ix.bucket_rank("leaks.logs") < ix.bucket_rank("leaks.private.general"),
       "an infostealer log outranks a private breach dump too")
    ok(ix.bucket_rank("leaks.logs") == min(ix.bucket_rank(b) for b in ix.BUCKETS),
       "the stealer-log bucket is ranked FIRST of all buckets")
    ok(ix.bucket_rank("some.bucket.we.have.never.seen") >= 99, "an unknown bucket ranks last")
    # "not an automatic edge" and "not worth reading" are DIFFERENT claims — collapsing them
    # throws away the best material IntelX has.
    ok(ix.item_evidence("leaks.logs") and not ix.clusterable("leaks.logs"),
       "a stealer log is per-ITEM evidence to open by hand, yet still never an automatic edge")
    ok(not ix.item_evidence("leaks.public.general"),
       "a breach dump is NOT flagged for item-by-item reading (skim it for the date)")
    ok(ix.summarise_record({"bucket": "leaks.logs", "name": "x"}).get("read_item") is True,
       "a stealer-log record is flagged read_item in the case file")
    # Ordering is what the analyst actually sees; assert it on the summarised records directly.
    mixed = [ix.summarise_record({"bucket": b, "name": b})
             for b in ("leaks.public.general", "dumpster", "leaks.logs", "pastes")]
    mixed.sort(key=lambda r: r.get("rank", 99))
    ok(mixed[0]["bucket"] == "leaks.logs" and mixed[-1]["bucket"] == "dumpster",
       "sorting summarised records by rank puts logs first and the unsorted dumpster last")
    rec = ix.summarise_record({"bucket": "leaks.public.general", "name": "x", "media": 24,
                               "systemid": "id", "date": "2026-01-01"})
    ok(rec.get("clusterable") is False and rec.get("grade") == "context",
       "every summarised record carries its grade + clusterable flag into the case file")

    # --- 6. ANY.RUN builds an OBSERVATION query, not a string match ---------------------------
    ok(ar.build_query("file:sha256", FAKE_SHA256) == f'sha256:"{FAKE_SHA256}"',
       "a file hash maps to the sha256 field")
    c2 = ar.build_query("app:c2_endpoint", "203.0.113.10:8443")
    ok("destinationIP:" in c2 and 'destinationPort:"8443"' in c2,
       "an ip:port C2 endpoint SPLITS into destinationIP + destinationPort")
    ok(ar.build_query("app:c2_endpoint", "203.0.113.10") == 'destinationIP:"203.0.113.10"',
       "a bare IP endpoint still builds a destinationIP query")
    ok(ar.build_query("app:backend_host", "api.site-a.example") ==
       'domainName:"api.site-a.example"', "a backend host maps to domainName")
    ok(ar.build_query("apk:signing_cert_sha256", "abc") == "",
       "a signing certificate emits NO ANY.RUN query (not an observation field)")
    ok(ar.build_query("apk:package", "com.example.app") == "",
       "an APK package name emits NO ANY.RUN query")
    ok(ar.build_query("cloud:firebase_project", "proj") == "",
       "a firebase project id emits NO ANY.RUN query")
    ok(ar.build_query("file:sha256", "") == "", "an empty value never builds a query")

    # --- 7. ANY.RUN keyless capability + query attachment --------------------------------------
    was_ar = os.environ.pop("ANYRUN_API_KEY", None)
    try:
        cap = ar.capability()
        ok(cap["power_pct"] == 50 and cap["mode"] == "keyless",
           "keyless ANY.RUN reports ~50% capability")
        ok("PACKED" in cap["statement"],
           "the ANY.RUN statement names the PACKED-sample case, where the loss actually bites")
        ok(bool(ar.banner_lines()), "keyless ANY.RUN prints a banner")
        pivots = [{"kind": "file:sha256", "value": FAKE_SHA256, "queries": []},
                  {"kind": "apk:package", "value": "com.example.app", "queries": []}]
        ar.attach_anyrun_queries(pivots)
        ok(any("ANY.RUN" in (q["service"] or "") for q in pivots[0]["queries"]),
           "keyless: the hash pivot gains a TI Lookup query")
        ok(pivots[1]["queries"] == [],
           "keyless: the package pivot gains nothing (correctly — not indexed)")
        ar.attach_anyrun_queries(pivots)
        ok(len([q for q in pivots[0]["queries"] if "ANY.RUN" in q["service"]]) == 2,
           "attach is idempotent — a second pass does not duplicate the entries")
    finally:
        if was_ar is not None:
            os.environ["ANYRUN_API_KEY"] = was_ar

    # --- 8. ANY.RUN clustering policy fails closed ---------------------------------------------
    ok(ar.grade_field("domainName") == "cluster", "a contacted domain may support an operator edge")
    ok(ar.grade_field("threatName") == "context",
       "a malware FAMILY is context only — same kit, not same operator")
    ok(ar.grade_field("suricataID") == "context", "a Suricata signature id is context only")
    ok(ar.grade_field("madeUpField") == "ungraded",
       "an unknown field is ungraded (never silently clusterable)")

    # --- 9. the spend guards actually block ----------------------------------------------------
    saved = (ix._RUN_SPENT, ar._RUN_SPENT)
    try:
        ix._RUN_SPENT = ix.budget_status()["max_searches_per_run"]
        blocked = ix._budget_block(1, "test search")
        ok(isinstance(blocked, str) and "per-run" in blocked,
           "IntelX: over the per-run cap returns a skip REASON, not a silent call")
        ar._RUN_SPENT = ar.budget_status()["max_requests_per_run"]
        blocked = ar._budget_block(1, "test lookup")
        ok(isinstance(blocked, str) and "per-run" in blocked,
           "ANY.RUN: over the per-run cap returns a skip REASON, not a silent call")
    finally:
        ix._RUN_SPENT, ar._RUN_SPENT = saved

    # --- 10. the two layers never crash a keyless run -----------------------------------------
    was_ix, was_ar = os.environ.pop("INTELX_KEY", None), os.environ.pop("ANYRUN_API_KEY", None)
    try:
        ok(ix.search(FAKE_EMAIL) is None, "keyless IntelX search returns None, never raises")
        ok(ix.phonebook(FAKE_DOMAIN) is None, "keyless IntelX phonebook returns None, never raises")
        ok(ar.ti_lookup('sha256:"x"') is None, "keyless ANY.RUN lookup returns None, never raises")
        res = {"meta": {"host": FAKE_DOMAIN}, "pivots": []}
        ix.enrich_result(res)
        ok(res["intelx"]["capability"]["power_pct"] == 50,
           "keyless enrich_result records the capability instead of an empty result set")
        bres = {"pivots": [{"kind": "file:sha256", "value": FAKE_SHA256}]}
        ar.enrich_result(bres)
        ok(bres["anyrun"]["capability"]["power_pct"] == 50,
           "keyless ANY.RUN enrich_result records the capability instead of an empty result set")
    finally:
        if was_ix is not None:
            os.environ["INTELX_KEY"] = was_ix
        if was_ar is not None:
            os.environ["ANYRUN_API_KEY"] = was_ar

    return passed, failed, out


if __name__ == "__main__":
    p, f, lines = check()
    for status, label in lines:
        print(f"  {'ok ' if status == 'ok' else 'FAIL'}  {label}")
    print(f"\n{p} passed, {f} failed")
    sys.exit(1 if f else 0)
