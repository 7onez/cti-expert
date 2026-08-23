#!/usr/bin/env python3
"""
test_serp.py — the gate on the ADVERTISING layer (wp_serp): ad parameters, the Ads Transparency
advertiser, and the click-keyed cloaking probe.

Run:  python3 tests/test_serp.py
      python3 tools/eval/run_eval.py          (runs as part of the regression gate)

WHAT THIS PROTECTS
------------------
Three failure modes, all silent in production.

1. THE CLOAKING VERDICT MUST BE FALSIFIABLE. The probe's whole value is telling an analyst that the
   page they collected is a decoy. The matching risk is the opposite error: any live page differs a
   little between two fetches (session ids, tokens, rotating banners), and a probe that called that
   "cloaking" would manufacture a fraud indicator — an accusation of deliberate evasion — out of an
   ordinary CMS. So these tests pin all five verdicts, and in particular assert that a page which
   ALSO differs between two identical plain requests comes back `inconclusive_unstable` and never
   `divergent`. That control fetch is the difference between an observation and a guess.

2. THE BASE-RATE CONTROL ON AD PARAMETERS. `utm_campaign=google` is on millions of unrelated URLs
   and a per-click `gclid` is unique by construction. Either one treated as a fingerprint fuses
   unrelated cases or clusters a case with itself. A click id must never be pivotable, a generic
   value must never emit a pivot, and only the Google Ads ACCOUNT OBJECT ids may.

3. THE OWNER BOUNDARY. `utm_*` and affiliate codes are already emitted as `affiliate:*` pivots by
   wp_pivots (contributor RULE 3: one group, one owner). If this layer starts emitting them too,
   every advertising URL produces duplicate pivots that inflate every downstream count.

Plus the keyless contract: with no SERPAPI_KEY nothing may be reported as a negative finding.
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "WebPivot", "tools"))

import wp_serp as S      # noqa: E402


# --------------------------------------------------------------------------- fake target
def _page(title, body, n=1):
    return (f"<html><head><title>{title}</title></head><body>{body * n}</body></html>").encode()


def _fetcher(script):
    """A fake fetch that answers each labelled view from `script` — {label: (status, url, bytes)}.

    The probe fetches plain, then click, then plain again as a control; the fake keys off the
    Referer header, which is exactly what a real cloaker keys off."""
    def fetch(url, timeout=20, ua=None, proxy=None, headers_extra=None):
        is_click = bool((headers_extra or {}).get("Referer"))
        seq = script["click"] if is_click else script["plain"]
        if isinstance(seq, list):
            item = seq.pop(0) if len(seq) > 1 else seq[0]
        else:
            item = seq
        if isinstance(item, Exception):
            raise item
        status, final_url, body = item
        return final_url or url, status, {"content-type": "text/html"}, body
    return fetch


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

    # --- 1. parameter classification -------------------------------------------------------
    p = S.ad_params("https://x.example/?gclid=EAIabc&utm_source=google&utm_campaign=vn_q3"
                    "&campaignid=22114455&device=m&sessionid=zzz")
    ok(p["gclid"]["class"] == "click_id" and p["gclid"]["pivotable"] is False,
       "a click id is classified click_id and is NEVER pivotable (its value is unique per click)")
    ok(p["campaignid"]["class"] == "valuetrack" and p["campaignid"]["pivotable"] is True,
       "a ValueTrack account-object id is pivotable — it identifies one Google Ads account")
    ok("sessionid" not in p, "a non-advertising query parameter is not advertising evidence")
    ok(p["utm_campaign"]["generic"] is False and
       S.ad_params("https://x.example/?utm_campaign=google")["utm_campaign"]["generic"] is True,
       "the generic-value denylist separates an operator campaign name from a platform name")
    ok(S.is_generic_value("cpc") and S.is_generic_value("") and not S.is_generic_value("vn_wallet_q3"),
       "is_generic_value fails CLOSED on empty/short values (no pivot) and passes a real label")

    arr = S.paid_arrival("https://x.example/?gclid=EAIabc&utm_medium=cpc")
    ok(arr["is_paid_click"] and arr["platforms"] == ["google"],
       "a gclid proves a PAID arrival and names the platform")
    ok(S.paid_arrival("https://x.example/?utm_source=google")["is_paid_click"] is False,
       "utm tagging alone is NOT proof of a paid click — only a platform-minted click id is")

    # --- 2. base rate + the owner boundary --------------------------------------------------
    piv = S.ad_param_pivots("https://x.example/?gclid=EAIabc&utm_campaign=vn_q3&campaignid=22114455")
    kinds = [v["kind"] for v in piv]
    ok("ads:campaignid" in kinds, "the account-object id becomes a pivot")
    ok(not any(k.startswith("ads:utm") for k in kinds),
       "utm_* values are NOT re-emitted here — wp_pivots owns them (RULE 3: one group, one owner)")
    ok(not any(k.startswith("affiliate:") for k in kinds),
       "this layer never emits affiliate:* pivots")
    ok(not any(v["value"] == "EAIabc" for v in piv),
       "the click id VALUE is never emitted as a pivot value")
    ok("ads:paid_arrival" in kinds and
       next(v for v in piv if v["kind"] == "ads:paid_arrival")["confidence"] == "informational",
       "the paid-arrival observation is recorded as informational, not as a link")
    ok(not S.ad_param_pivots("https://x.example/?campaignid=22114455&utm_campaign=google")
        or all(v["kind"] != "ads:utm_campaign"
               for v in S.ad_param_pivots("https://x.example/?utm_campaign=google")),
       "a generic campaign value produces no pivot from this layer")

    # --- 3. URL surgery ---------------------------------------------------------------------
    u = "https://x.example/promo?ref=abc&gclid=E1&utm_source=google"
    ok(S.strip_ad_params(u) == "https://x.example/promo?ref=abc",
       "strip_ad_params removes the ad set and KEEPS the site's own parameters")
    unlocked = S.unlock_url(u)
    ok("ref=abc" in unlocked and "gclid=E1" in unlocked and "utm_medium=cpc" in unlocked,
       "unlock_url keeps the operator's own parameters, keeps the site's, and fills the gaps")
    ok(S.unlock_params(u, {"utm_campaign": "x"})["gclid"] == "E1",
       "the URL's REAL click id wins over the synthetic probe default")

    # --- 4. the cloaking probe, all five verdicts -------------------------------------------
    same = (200, None, _page("Shop", "<p>hello</p>"))
    probe = S.cloak_probe("https://c.example/", fetch_fn=_fetcher({"plain": same, "click": same}))
    ok(probe["verdict"] == "identical", "identical bytes -> `identical`, not cloaking")

    # A page that differs only by a token: an ordinary live page, NOT an accusation.
    big = "<p>the same long marketing copy repeated for length</p>" * 60
    probe = S.cloak_probe("https://c.example/", fetch_fn=_fetcher({
        "plain": (200, None, _page("Shop", big + "<input name=csrf value=aaaaaaaa>")),
        "click": (200, None, _page("Shop", big + "<input name=csrf value=bbbbbbbb>"))}))
    ok(probe["verdict"] == "dynamic",
       "a token-sized difference is `dynamic` — an ordinary live page, never a cloaking claim")

    # The real thing: the click view is a different page.
    probe = S.cloak_probe("https://c.example/", fetch_fn=_fetcher({
        "plain": (200, None, _page("Coming soon", "<p>this site is under construction</p>")),
        "click": (200, None, _page("Verify your wallet",
                                   "<h1>connect wallet</h1>" + "<p>seed phrase</p>" * 40))}))
    ok(probe["verdict"] == "divergent", "a different page for paid clicks -> `divergent`")
    ok(any("title" in s for s in probe["signals"]), "the divergence signals name the evidence")
    ok("unlock_url" in probe and "gclid=" in probe["unlock_url"],
       "a divergent verdict hands back the URL the case must actually be collected from")
    ok(S.cloaking_pivots(probe, host="c.example")[0]["kind"] == "ads:cloaking",
       "a divergent verdict becomes a finding pivot")
    ok(S.cloaking_pivots({"verdict": "dynamic"}, host="c.example") == [],
       "a non-divergent verdict produces NO finding")

    # The falsification control: the page is simply unstable, so nothing may be attributed to the
    # click. This is the test that stops the probe manufacturing evasion findings.
    probe = S.cloak_probe("https://c.example/", fetch_fn=_fetcher({
        "plain": [(200, None, _page("A", "<p>first render</p>" * 30)),
                  (200, None, _page("C", "<p>third totally different render</p>" * 30))],
        "click": (200, None, _page("B", "<p>second other render</p>" * 30))}))
    ok(probe["verdict"] == "inconclusive_unstable",
       "a page that differs between two IDENTICAL plain fetches is `inconclusive_unstable`, "
       "never `divergent`")

    probe = S.cloak_probe("https://c.example/", fetch_fn=_fetcher({
        "plain": RuntimeError("connection reset"), "click": same}))
    ok(probe["verdict"] == "inconclusive" and "NOT evidence" in probe["note"],
       "an unreachable view is `inconclusive` and says so — silence is not exoneration")

    # A redirect away on the click is divergence even when both bodies are small.
    probe = S.cloak_probe("https://c.example/", fetch_fn=_fetcher({
        "plain": (200, "https://c.example/", _page("Shop", "<p>x</p>")),
        "click": (200, "https://evil.example/kit/", _page("Shop", "<p>x</p>"))}))
    ok(probe["verdict"] == "divergent" and any("host" in s for s in probe["signals"]),
       "a paid click that lands on a DIFFERENT host is divergence")

    # --- 4b. the two false-positive classes found in live testing ---------------------------
    # (a) LENGTH ALONE IS NOT DIVERGENCE. A live run against a major booking site produced two views
    # with identical visible text (similarity 1.0) and a 0.56 length ratio — padding and per-request
    # nonces. The length rule alone called that cloaking, i.e. accused a legitimate site of
    # deliberate evasion. Length may now only corroborate a difference something else already found.
    pad = "<p>identical visible copy for both views</p>" * 40
    probe = S.cloak_probe("https://c.example/", fetch_fn=_fetcher({
        "plain": (200, None, _page("Shop", pad)),
        "click": (200, None, _page("Shop", pad + "<script>var n='" + "x" * 4000 + "'</script>"))}))
    ok(probe["verdict"] != "divergent" and probe.get("supporting_only"),
       "a big LENGTH difference with unchanged visible text is NOT cloaking — length only "
       "corroborates, it can never carry a verdict alone")

    # (b) AN ANTI-BOT WALL IS NOT A PAGE. Two challenge interstitials differ from each other by
    # construction, and this fires on exactly the hostile infrastructure where a cloaking finding
    # would be believed hardest.
    chal_a = _page("", "<div>Just a moment...</div><script src='/__challenge/a.js'></script>")
    chal_b = _page("", "<div>Just a moment...</div><script src='/__challenge/b.js'></script>"
                       + "<!--" + "p" * 3000 + "-->")
    probe = S.cloak_probe("https://c.example/", fetch_fn=_fetcher({
        "plain": (202, None, chal_a), "click": (202, None, chal_b)}))
    ok(probe["verdict"] == "inconclusive" and probe.get("challenge_detected"),
       "an anti-bot interstitial makes the probe `inconclusive` — the bot wall is never reported "
       "as the operator's evasion")
    ok("NOT evidence that the page is clean" in probe["note"],
       "…and it is not read as exoneration either")
    ok(S.is_challenge({"body": "<html><body>hCaptcha required</body></html>", "status": 200}),
       "a marker anywhere in the body identifies a challenge, whatever the status")
    ok(not S.is_challenge({"body": "<html>" + "real page content " * 500 + "</html>",
                           "status": 403, "bytes": 9000, "title": "Blocked in your region"}),
       "a real page returned with a 403 is NOT a challenge — some sites answer a region that way")

    # --- 5. advertiser grouping + the agency base-rate control -------------------------------
    creatives = [{"advertiser_id": "AR100", "advertiser": "Acme Ltd", "ad_creative_id": "CR1",
                  "format": "text", "target_domain": "a.example", "first_shown": 1700000000,
                  "last_shown": 1800000000},
                 {"advertiser_id": "AR100", "advertiser": "Acme Ltd", "ad_creative_id": "CR2",
                  "format": "image", "target_domain": "b.example", "first_shown": 1600000000,
                  "last_shown": 1700000000}]
    grouped = S._group_creatives(creatives, "anywhere")
    ok(len(grouped) == 1 and grouped[0]["creative_count"] == 2,
       "creatives are grouped by ADVERTISER — the account is the unit of analysis")
    ok(grouped[0]["target_domains"] == ["a.example", "b.example"],
       "the advertiser's distinct target domains are the reverse pivot")
    ok(grouped[0]["first_shown"] == "2020-09-13" and grouped[0]["last_shown"] == "2027-01-15",
       "first/last shown become ISO dates spanning ALL creatives (the campaign window)")
    ok(grouped[0]["agency_shaped"] is False, "two domains is not agency-shaped")
    ok(grouped[0]["advertiser"] == "Acme Ltd" and
       "adstransparency.google.com" in (grouped[0]["ui_url"] or ""),
       "the funded-by NAME and the transparency URL live in separate keys "
       "(the name is a pivot; a link must never shadow it)")

    threshold = int(S.CLUSTERING_POLICY.get("agency_domain_threshold", 12))
    wide = [{"advertiser_id": "AR200", "advertiser": "Media Buyer Inc", "ad_creative_id": f"CR{i}",
             "target_domain": f"d{i}.example"} for i in range(threshold + 3)]
    gw = S._group_creatives(wide, "anywhere")[0]
    ok(gw["agency_shaped"] is True and "agency_note" in gw,
       f"an advertiser pointing at {threshold}+ domains is flagged agency-shaped")
    pv = S.advertiser_pivots([gw], seed_host="d0.example")
    ok(all(v["confidence"] == "low" for v in pv if v["kind"] == "ads:co_advertised_domain"),
       "an agency-shaped advertiser's co-advertised domains drop to LEADS, not operator links")
    ok(next(v for v in pv if v["kind"] == "ads:advertiser_id")["confidence"] == "medium",
       "and the advertiser id itself is downgraded with them")
    ok(not any(v["value"] == "d0.example" for v in pv),
       "the seed domain is not emitted as a pivot to itself")

    pv2 = S.advertiser_pivots(grouped, seed_host="a.example")
    ok(next(v for v in pv2 if v["kind"] == "ads:advertiser_id")["confidence"] == "high",
       "a normal advertiser id is HIGH — a verified, paying identity")
    ok(any(v["kind"] == "ads:advertiser" and v["value"] == "Acme Ltd" for v in pv2),
       "the verified 'funded by' legal name is its own pivot (corporate registry / reverse-WHOIS)")

    # --- 5b. the ad-details response shape, as the API ACTUALLY returns it -------------------
    # Pinned against a live response, not against SerpApi's published schema — the two disagree.
    # The docs put `link` / `headline` / `ad_funded_by` at the top level; the live API nests the
    # metadata under `search_information` and the creative content under `ad_creatives[]`, and for
    # text ads it commonly returns a rendered IMAGE with no destination URL at all. A parser
    # written to the docs silently extracts nothing and the layer looks broken.
    live_shape = {
        "search_information": {
            "format": "text", "last_shown": 1786102026, "region_name": "anywhere",
            "ad_funded_by": "Example Holdings B.V.",
            "regions": [{"region": 2124, "region_name": "Canada", "last_shown": 20260807},
                        {"region": 2704, "region_name": "Vietnam", "last_shown": 20260801}]},
        "ad_creatives": [{"image": "https://tpc.googlesyndication.com/archive/simgad/1"}]}
    _real_call = S._call
    try:
        S._call = lambda *a, **k: (live_shape, None)
        det = S.creative_details("AR100", "CR1")
    finally:
        S._call = _real_call
    ok(det.get("ad_funded_by") == "Example Holdings B.V.",
       "ad_funded_by is read from search_information — the VERIFIED legal entity, the field that "
       "goes into a corporate registry")
    ok(det.get("markets") == ["Canada", "Vietnam"],
       "the per-region breakdown is kept: which markets the operator PAID to reach, each dated")
    ok("no_link_note" in det and "NORMAL" in det["no_link_note"],
       "a creative with no destination URL says so explicitly — it is the common case, not an error")
    ok(det.get("ui_advertiser", "").startswith("https://adstransparency.google.com/advertiser/")
       and "ad_funded_by" in det,
       "the transparency links are ui_-prefixed so they cannot shadow the funded-by name")

    with_link = {"search_information": {"ad_funded_by": "Example Holdings B.V."},
                 "ad_creatives": [{"link": "https://land.example/promo?utm_campaign=vn_q3&gclid=E1",
                                   "headline": "Claim your bonus"}]}
    try:
        S._call = lambda *a, **k: (with_link, None)
        det2 = S.creative_details("AR100", "CR2")
    finally:
        S._call = _real_call
    ok(det2.get("landing_host") == "land.example"
       and "utm_campaign" in (det2.get("landing_params") or {}),
       "when a destination URL IS returned, its campaign parameters are parsed out as the "
       "operator's own cloaking key")
    ok("no_link_note" not in det2, "…and the no-link caveat is then absent")

    # --- 6. regions: the API and the UI use different codes ----------------------------------
    ok(S.region_codes("VN")["api"] == "2704" and S.region_codes("VN")["ui"] == "VN",
       "a region resolves to BOTH codes — mixing them silently returns nothing")
    ok(S.region_codes("anywhere")["api"] is None,
       "'anywhere' has no API code, so the API call omits region")
    ok(S.region_codes("2372")["api"] == "2372",
       "an unlisted numeric geotarget passes through (Google has ~200; the file lists 25)")

    # --- 7. the keyless contract -------------------------------------------------------------
    key_present = bool(S.serpapi_key())
    cap = S.capability(free_only=True)
    ok(cap["power_pct"] == 55 and cap["mode"] == "free-only",
       "the layer states its own degraded capability rather than looking fully powered")
    ok("cloaking probe" in " ".join(cap["available"]).lower(),
       "the keyless statement keeps the cloaking probe — it needs no key and still runs")
    ok("never asked" in cap["statement"] or "NOT queried" in cap["statement"],
       "the keyless statement forbids reading an unqueried archive as a negative finding")
    ok(len(S.banner_lines(free_only=True)) >= 4 and S.banner_lines(free_only=False) != []
       or key_present,
       "a keyless/free-only run prints the capability banner")

    if not key_present:
        res = S.advertiser_search("example.com", region="VN")
        ok("skipped" in res and res["advertisers"] == [],
           "with no key the archive lookup is SKIPPED, not silently empty")
        ok("adstransparency.google.com" in (res.get("ui_url") or ""),
           "and it still hands back the free Ads Transparency Center address for the domain")
        ok("not a finding" in (res.get("note") or "").lower(),
           "and says in words that absence here is absence of a query")
    else:
        out.append(("ok", "SERPAPI_KEY present — keyless-path assertions skipped"))
        passed += 1

    # --- 8. the spend guard ------------------------------------------------------------------
    b = S.budget_status()
    ok(b["max_searches_per_run"] > 0 and b["monthly_searches"] > 0,
       "the budget guard has a per-run cap and a monthly ceiling")
    saved = S._RUN_SPENT
    try:
        S._RUN_SPENT = b["max_searches_per_run"]
        blocked = S._budget_block(1, "advertiser lookup")
        ok(isinstance(blocked, str) and "per-run" in blocked,
           "spending past the per-run cap is REFUSED before the call, with a readable reason")
        ok("Ads Transparency" in blocked or "SERPAPI_MAX_SEARCHES_PER_RUN" in blocked,
           "and the refusal names the free alternative / the override")
    finally:
        S._RUN_SPENT = saved

    # --- 9. reference DATA is loaded, not the fallback ---------------------------------------
    ok(len(S.AD_PARAMETERS) > len(S._SERP_FALLBACK["ad_parameters"]),
       "the parameter table came from references/serpapi.json, not the embedded fallback")
    ok(S.CLUSTERING_POLICY.get("agency_domain_threshold") is not None,
       "the agency threshold survived loading (it sits outside an `entries` wrapper on purpose)")
    ok(S.PROBE_HEADERS.get("Referer", "").startswith("https://www.google."),
       "the probe's click headers loaded (a referrer-only cloaker is defeated by these alone)")

    # --- 10. the base-rate control reaches the KNOWLEDGE BASE --------------------------------
    # The guards above are worthless if the ingest path re-introduces what they filtered, so this
    # asserts the boundary where it actually matters: an edge is what makes two domains cluster.
    sys.path.insert(0, os.path.join(ROOT, "tools", "kb"))
    import ingest_webpivot as IW      # noqa: E402

    class _KB:
        def __init__(self):
            self.facts, self.edges = [], []

        def touch(self, *a, **k):
            pass

        def add_fact(self, et, e, k, v, *a, **kw):
            self.facts.append((e, k, v))

        def add_edge(self, et, e, rel, it, ind, *a, **kw):
            self.edges.append((e, rel, ind))

    doc = {"advertising": {"advertisers": [
        {"advertiser_id": "AR100", "advertiser": "Acme Ltd", "creative_count": 2,
         "target_domains": ["peer.example"], "agency_shaped": False},
        {"advertiser_id": "AR200", "advertiser": "Media Buyer", "creative_count": 30,
         "target_domains": [f"d{i}.example" for i in range(14)], "agency_shaped": True,
         "agency_note": "many unrelated domains"}]},
        "pivots": [{"kind": "ads:campaignid", "value": "22114455"},
                   {"kind": "ads:paid_arrival", "value": "google"}]}
    kb = _KB()
    IW._ingest_ads(kb, doc, {"cloaking": {"verdict": "divergent",
                                          "unlock_url": "https://a.example/?gclid=x"}},
                   "a.example", "T", "ev")
    ok(("peer.example", "advertised_by", "ads_advertiser:AR100") in kb.edges,
       "a co-advertised domain gets an edge to the advertiser indicator — that is the cluster")
    ok(not any(e[0].startswith("d") and e[2] == "ads_advertiser:AR200" for e in kb.edges),
       "an AGENCY-shaped advertiser's clients get NO edge — a media buyer is not one operator")
    ok(any(f[1] == "co_advertised" for f in kb.facts),
       "…they are kept as facts instead, so the leads are not lost, only un-clustered")
    ok(any(f[1] == "funded_by" and f[2] == "Acme Ltd" for f in kb.facts),
       "the verified legal name is carried on the indicator, so the whole cluster inherits it")
    ok(not any(e[2].startswith("ads_") and "paid_arrival" in e[2] for e in kb.edges),
       "the paid-arrival observation never becomes a clustering indicator")
    ok(any(f[1] == "cloaking" for f in kb.facts)
       and not any("cloak" in e[2] for e in kb.edges),
       "cloaking lands as a FACT on the domain, never an indicator (it is intent, not identity)")

    return passed, failed, out


def main():
    passed, failed, lines = check()
    for status, label in lines:
        print(f"  {'ok  ' if status == 'ok' else 'FAIL'} {label}")
    print(f"\n{'PASS' if not failed else 'FAIL'} — {passed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
