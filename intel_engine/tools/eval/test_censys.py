#!/usr/bin/env python3
"""Offline unit gate for WebPivot's Censys Platform layer (wp_censys).

The lookups and searches need a Personal Access Token and spend Censys CREDITS, so they are not
exercised here. What IS gated is everything that decides whether a Censys pivot is usable at all,
and every one of these has a silent failure mode:

  1. **CenQL, not Legacy Search.** Censys retired the old query language. A template that still
     emits `services.tls.certificates.leaf_data.fingerprint_sha256:` does not error — it returns
     zero hits, which reads to an analyst as "no related infrastructure". So we assert every
     emitted query is namespaced under host./web./cert.
  2. **The right operator per artifact.** `=` is exact; `:` is tokenised. A bare subdomain LABEL
     matched with `=` against a full hostname field finds nothing, forever.
  3. **The favicon hash is MD5.** Censys is the one engine in the matrix that does not use mmh3.
     Passing the Shodan mmh3 to a Censys favicon query is a query that cannot ever match.
  4. **Free-plan degradation is a skip, not an error.** A Free account gets 403 on the search API;
     that must surface as `skipped` with the UI URL, so the analyst still has a runnable query.
  5. **No key = no crash.** WebPivot's contract is that everything works keyless, with the metered
     extras simply absent.
  6. **The credit guard actually blocks.** A free account gets 100 credits a MONTH, no rollover,
     shared across every case. A guard that computes a budget but still lets the call through is
     worse than none: it reports a balance nobody can trust. So we assert an over-budget spend
     comes back as a `skipped` reason carrying the balance, and that the UI link — which costs the
     same 5 credits as an API search — says its price rather than reading as a free escape hatch.

Run standalone (`python3 tools/eval/test_censys.py`) or via run_eval.py.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))), "WebPivot", "tools"))
import wp_censys as cen  # noqa: E402

FAKE_MD5 = "0123456789abcdef0123456789abcdef"
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

    # --- 1. every emitted query is CenQL, never Legacy Search syntax -------------------------
    legacy_markers = ("services.http.response.", "services.tls.certificates.",
                      "services.jarm.fingerprint", "dns.names:", "autonomous_system.asn:")
    all_tpls = [t for forms in cen.CENQL_TEMPLATES.values() for t in forms]
    ok(bool(all_tpls), "cenql_templates loaded from references/censys_queries.json")
    ok(all(t.startswith(("host.", "web.", "cert.")) for t in all_tpls),
       "every template is namespaced host./web./cert. (CenQL, not Legacy Search)")
    ok(not any(t.startswith(m) for t in all_tpls for m in legacy_markers),
       "no template uses a retired Legacy Search field path")
    ok(not any("=~" in t for t in all_tpls),
       "no template uses regex (=~) — that is Starter+ only and would 403 on a free plan")

    # --- 2. operator choice: exact for hashes, tokenised for labels/keywords -----------------
    fp_q = cen.cenql_for("tls_cert:fingerprint_sha256", FAKE_SHA256)
    ok(fp_q and all("=" in q and ":" not in q.split("=")[0] for q in fp_q),
       "cert fingerprint uses the EXACT (=) operator")
    label_q = cen.cenql_for("subdomain", "svc-a")
    ok(label_q and all(":" in q for q in label_q),
       "a bare subdomain LABEL uses the tokenised (:) operator, not exact =")
    body_q = cen.cenql_for("tracker:ga4", "G-XXXXXXXXXX")
    ok(body_q and all(q.startswith(("web.endpoints.http.body:", "host.services.endpoints.http.body:"))
                      for q in body_q),
       "a tracker ID reverses through the HTTP body index, tokenised")

    # --- 3. favicon is MD5 on Censys --------------------------------------------------------
    fav = cen.cenql_for("favicon_hash", FAKE_MD5)
    ok(fav and all("favicons.hash_md5" in q for q in fav),
       "favicon_hash maps to the MD5 favicon field (Censys does not use mmh3)")

    # --- kind coverage: prefix entries must resolve for unseen subtypes ----------------------
    ok(cen.template_for("tracker:some_new_vendor") == "body_keyword",
       "an unseen tracker: subtype still resolves via the prefix entry")
    ok(cen.template_for("wallet:btc") is None,
       "an artifact Censys does not index yields NO query (better than a query that can't match)")
    ok(cen.censys_queries("wallet:btc", "1abc") == [],
       "…and censys_queries returns [] for it rather than a broken entry")

    # --- the UI URL is the free-plan escape hatch -------------------------------------------
    qs = cen.censys_queries("favicon_hash", FAKE_MD5)
    ok(any(q["query"].startswith("https://platform.censys.io/search?q=") for q in qs),
       "every pivot carries a platform.censys.io UI URL (search API is Starter+, UI is not)")
    ok(cen.censys_ui_url('web.hostname="a b"').count(" ") == 0,
       "the UI URL is percent-encoded (a raw space would break the link)")

    # --- forms cap keeps a big result from tripling in size ----------------------------------
    ok(len([q for q in cen.censys_queries("tls_cert:fingerprint_sha256", FAKE_SHA256, forms=1)
            if not q["query"].startswith("http")]) == 1,
       "forms=1 emits exactly one CenQL variant")

    # --- 4/5. keyless + attach pass ----------------------------------------------------------
    saved_token = os.environ.pop("CENSYS_PAT", None)
    saved_enabled = cen.ENABLED
    try:
        cen.ENABLED = False                      # simulate --no-censys / no key
        ok(cen.censys_configured() is False, "censys_configured() False with Censys switched off")
        ok(cen.censys_host("1.2.3.4") is None, "host lookup returns None (no key) instead of raising")
        ok(cen.censys_certificate(FAKE_SHA256) is None, "cert lookup returns None instead of raising")
        ok(cen.censys_search('web.hostname="x"') is None, "search returns None instead of raising")
        # the BUILDER must keep working with no key — that is the whole keyless contract
        ok(bool(cen.cenql_for("favicon_hash", FAKE_MD5)),
           "the CenQL builder still works with no key (offline, costs nothing)")
    finally:
        cen.ENABLED = saved_enabled
        if saved_token is not None:
            os.environ["CENSYS_PAT"] = saved_token

    pivots = [{"kind": "domain", "value": "site-a.example", "queries": [{"service": "crt.sh", "query": "x"}]},
              {"kind": "favicon_hash", "value": "123456789",
               "queries": [{"service": "Censys", "query": "web.endpoints.http.favicons.hash_md5=" + FAKE_MD5}]},
              {"kind": "email", "value": "operator@example.com", "queries": []}]
    cen.attach_censys_queries(pivots)
    ok(any("Censys" in q["service"] for q in pivots[0]["queries"]),
       "attach pass adds a Censys query to a domain pivot")
    fav_cen = [q for q in pivots[1]["queries"] if "Censys" in q["service"]]
    ok(len(fav_cen) == 1 and FAKE_MD5 in fav_cen[0]["query"],
       "attach pass leaves the hand-written favicon MD5 query alone (no mmh3 overwrite)")
    ok(not any("Censys" in q["service"] for q in pivots[2]["queries"]),
       "attach pass adds nothing for an artifact Censys does not index (email)")

    # --- credits/entitlements are DATA the degradation messages depend on --------------------
    ok(cen.CREDIT_COSTS.get("entity_lookup", 0) >= 1 and cen.CREDIT_COSTS.get("standard_query", 0) > 1,
       "credit_costs loaded: a lookup is cheaper than a search (why --free-only skips Censys)")
    ok(cen.PLAN_CAPABILITIES.get("free", {}).get("api_search") is False,
       "plan_capabilities records that the FREE plan has NO search API")
    ok(cen.PLAN_CAPABILITIES.get("free", {}).get("api_lookup") is True,
       "…but DOES have the lookup endpoints — the free-plan path WebPivot actually uses")
    ok("403" in str(cen._STATUS_REASON.get(403)) or "plan" in str(cen._STATUS_REASON.get(403)),
       "a 403 degrades to an analyst-readable plan message, not an opaque error")

    # --- 6. the credit budget guard ----------------------------------------------------------
    # Censys is the tightest quota in the toolkit and the quota is per ACCOUNT, so an overspend in
    # one case silently disarms Censys in every later one. These assert the guard is real.
    b = cen.budget_status()
    ok(b["monthly_credits"] >= 1 and b["remaining_this_month"] <= b["monthly_credits"],
       "budget_status reports a coherent monthly balance")
    ok(b["max_credits_per_run"] < b["monthly_credits"],
       "the per-run cap is smaller than the month — one run cannot spend the whole quota")
    # These two assert the guard's SHAPE, so they must not depend on how much of the real month's
    # quota happens to be spent — otherwise the gate turns red for every contributor once the
    # account's 100 credits run out, which says nothing about the code. Pin the ledger the same
    # way the exhausted-month case below does.
    _saved_run, _saved_month = cen._RUN_SPENT, cen._MONTH_SPENT
    try:
        cen._RUN_SPENT = cen._MONTH_SPENT = 0
        ok(cen._budget_block(1, "cert lookup") is None,
           "a 1-credit lookup inside budget is allowed")
        ok(isinstance(cen._budget_block(b["max_credits_per_run"] + 1, "huge bulk lookup"), str),
           "a spend over the per-run cap is BLOCKED with an analyst-readable reason")
    finally:
        cen._RUN_SPENT, cen._MONTH_SPENT = _saved_run, _saved_month

    saved_run = cen._RUN_SPENT
    saved_month = cen._MONTH_SPENT
    try:
        cen._MONTH_SPENT = cen.CREDIT_BUDGET.get("monthly_credits", 100)   # month exhausted
        reason = cen._budget_block(1, "cert lookup")
        ok(isinstance(reason, str) and "roll over" in reason,
           "an exhausted month blocks even a 1-credit lookup, and says credits do not roll over")
        # …and the block must surface as a `skipped` result carrying the balance, never an
        # exception and never a silent None that reads as "Censys had nothing".
        os.environ["CENSYS_PAT"] = "test-token-not-used"                  # no call is made
        cen.ENABLED = True
        cen._MEMO.clear()
        res = cen.censys_search('web.hostname="site-a.example"')
        ok(isinstance(res, dict) and res.get("skipped") and res.get("ui_url"),
           "an unaffordable search degrades to skipped + the UI link (same shape as a plan 403)")
        ok(isinstance(res.get("budget"), dict),
           "…and carries the balance, so the reason is auditable in the case file")
        # The reserve keeps the cheap, highest-value lookups affordable when a search would not be.
        cen._MONTH_SPENT = cen.CREDIT_BUDGET.get("monthly_credits", 100) - 12
        cen._RUN_SPENT = 0
        ok(cen._budget_block(1, "cert lookup") is None,
           "with 12 credits left a 1-credit cert lookup still runs")
        ok(isinstance(cen._budget_block(5, "search", is_search=True), str),
           "…but a 5-credit search is refused, reserving the balance for lookups")
    finally:
        cen._RUN_SPENT, cen._MONTH_SPENT = saved_run, saved_month
        cen.ENABLED = saved_enabled
        os.environ.pop("CENSYS_PAT", None)
        if saved_token is not None:
            os.environ["CENSYS_PAT"] = saved_token
        cen._MEMO.clear()

    ui = [q for q in cen.censys_queries("favicon_hash", FAKE_MD5)
          if q["query"].startswith("https://platform.censys.io")]
    ok(ui and "credit" in ui[0]["service"].lower(),
       "the UI link states its price — running that CenQL in the console costs credits too")

    # --- web-property identifier normalisation ----------------------------------------------
    ok(cen.webproperty_id("example.com") == "example.com:443", "bare host -> host:443")
    ok(cen.webproperty_id("www.example.com") == "example.com:443", "www stripped")
    ok(cen.webproperty_id("http://example.com") == "example.com:80", "http URL -> :80")
    ok(cen.webproperty_id("example.com:8443") == "example.com:8443", "explicit port kept")

    # --- summarisers must not explode on a partial/empty record ------------------------------
    ok(cen.summarise_host({}) == {} and cen.summarise_webproperty({}) == {}
       and cen.summarise_certificate({}) == {}, "summarisers return {} on an empty record")
    ok(cen.summarise_certificate({"fingerprint_sha256": FAKE_SHA256,
                                  "names": ["a.example", "b.example", "a.example"]})["names"]
       == ["a.example", "b.example"], "certificate names deduped (the cross-brand apex list)")

    return passed, failed, out


if __name__ == "__main__":
    p, f, lines = check()
    for status, label in lines:
        print(("  ok  " if status == "ok" else "  FAIL") + " " + label)
    print(f"\n{p} passed, {f} failed")
    sys.exit(1 if f else 0)
