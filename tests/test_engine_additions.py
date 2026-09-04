#!/usr/bin/env python3
"""test_engine_additions.py — gate on the Validin-plan engine additions (Phases 5/8/10).

Run:  python3 tests/test_engine_additions.py     (zero deps)
      pytest tests/test_engine_additions.py -q     (also works)

WHAT THIS PROTECTS
------------------
  1. QUAKE / ZOOMEYE CLIENTS (Phase 8). Configured-gate is False without a key; no network at
     import; proxy-safe (no custom urllib opener); the favicon reverse normalises a captured
     response to {"total","hosts":[...]} and turns an API-level error code into a tri-state note.
  2. REPUTATION FOLD (Phase 5). risk_signals.score_domain treats Validin reputation as
     CORROBORATION ONLY — a risky reputation never escalates on its own, but sharpens an existing
     escalation.
  3. CROSS-ENGINE MERGE (Phase 10). The frontier merges one apex found by N engines into a single
     candidate whose `sources` set has length N; the evidence report lists a discovered host's
     engines instead of collapsing them.
"""
import os
import sys
import tempfile

# Vendor clients ledger every (mocked) call via api_usage; a test must never write phantom credits
# into the real MEMORY/api_usage.jsonl (the monthly budgets are derived from it).
os.environ.setdefault("API_USAGE_LOG", os.path.join(tempfile.gettempdir(), "cti-tests-api_usage.jsonl"))

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..", "intel_engine")
for _p in ("WebPivot/tools", "tools", "tools/kb"):
    sys.path.insert(0, os.path.join(ROOT, _p))

FAILURES = []


def check(label, cond, detail=""):
    if cond:
        print("  ok   {}".format(label))
    else:
        print("  FAIL {} {}".format(label, detail))
        FAILURES.append(label)


# --- 1. Quake / ZoomEye clients ------------------------------------------------------------
import wp_quake      # noqa: E402
import wp_zoomeye    # noqa: E402


def test_quake_zoomeye_gate_and_proxy_safe():
    # No key in the test env -> configured() False, favicon_reverse() None (no network attempted).
    for name in ("QUAKE_API_KEY", "QUAKE_API_KEY_FALLBACK", "QUAKE_TOKEN",
                 "ZOOMEYE_API_KEY", "ZOOMEYE_API_KEY_FALLBACK", "ZOOMEYE_KEY"):
        os.environ.pop(name, None)
    check("quake unconfigured without a key", wp_quake.quake_configured() is False)
    check("zoomeye unconfigured without a key", wp_zoomeye.zoomeye_configured() is False)
    check("quake favicon_reverse returns None unconfigured", wp_quake.favicon_reverse("1") is None)
    check("zoomeye favicon_reverse returns None unconfigured", wp_zoomeye.favicon_reverse("1") is None)
    for mod in (wp_quake, wp_zoomeye):
        src = open(mod.__file__, encoding="utf-8").read()
        check("%s builds no custom urllib opener (proxy-safe)" % mod.__name__.split(".")[-1],
              "build_opener(" not in src and "install_opener(" not in src)


def test_quake_normalises_and_tri_states():
    os.environ["QUAKE_API_KEY"] = "dummy-not-a-real-key"
    wp_quake._RUN_CALLS = 0
    wp_quake._post = lambda path, body, timeout=25: (
        {"code": 0, "data": [{"domain": "a.example"},
                             {"service": {"http": {"host": "b.example"}}},
                             {"ip": "1.2.3.4"}]}, None)   # ip-only row (no name) is dropped
    r = wp_quake.favicon_reverse("325177753")
    check("quake normalises to total/hosts", r.get("total") == 2 and set(r.get("hosts") or []) ==
          {"a.example", "b.example"}, detail=str(r))
    wp_quake._RUN_CALLS = 0
    wp_quake._post = lambda *a, **k: ({"code": "q3005", "message": "invalid token"}, None)
    r2 = wp_quake.favicon_reverse("325177753")
    check("quake non-zero code -> skipped tri-state", "skipped" in (r2 or {}), detail=str(r2))
    os.environ.pop("QUAKE_API_KEY", None)


def test_zoomeye_normalises_and_tri_states():
    os.environ["ZOOMEYE_API_KEY"] = "dummy-not-a-real-key"
    wp_zoomeye._RUN_CALLS = 0
    wp_zoomeye._post = lambda path, body, timeout=25: (
        {"code": 60000, "data": [{"domain": "z.example"},
                                 {"url": "http://u.example/path"}]}, None)
    r = wp_zoomeye.favicon_reverse("325177753")
    check("zoomeye normalises to total/hosts (url host extracted)",
          r.get("total") == 2 and set(r.get("hosts") or []) == {"z.example", "u.example"}, detail=str(r))
    wp_zoomeye._RUN_CALLS = 0
    wp_zoomeye._post = lambda *a, **k: ({"code": 40000, "message": "unauthorized"}, None)
    r2 = wp_zoomeye.favicon_reverse("325177753")
    check("zoomeye non-success code -> skipped tri-state", "skipped" in (r2 or {}), detail=str(r2))
    os.environ.pop("ZOOMEYE_API_KEY", None)


# --- 2. Reputation fold (corroboration only) -----------------------------------------------
import risk_signals as rs   # noqa: E402


def test_reputation_is_corroboration_only():
    rep_only = {"meta": {"host": "x.example"}, "artifacts": {"whois": {}}, "pivots": [
        {"kind": "domain", "live_results": {"validin_reputation": {"annotations": ["MALICIOUS phishing"]}}}]}
    s = rs.score_domain(rep_only)
    check("reputation risky is detected", s["reputation"]["risky"] is True)
    check("risky reputation ALONE never escalates", "validin-reputation" not in s["escalate"],
          detail=str(s["escalate"]))
    both = {"meta": {"host": "y.example"}, "artifacts": {"whois": {}},
            "related_urlscan": {"verdict": {"malicious": True, "score": 80, "brands": ["PayPal"]}},
            "pivots": [{"kind": "domain", "live_results": {
                "validin_ip_reputation": {"1.2.3.4": {"annotations": [{"cat": "scam"}]}}}}]}
    s2 = rs.score_domain(both)
    check("risky reputation corroborates when another signal fired",
          "validin-reputation" in s2["escalate"], detail=str(s2["escalate"]))


# --- 3. Cross-engine merge (Phase 10) ------------------------------------------------------
import case_state as cs        # noqa: E402
import evidence_report as er   # noqa: E402

MULTI = {"meta": {"host": "seed.example"}, "pivots": [
    {"kind": "domain", "value": "seed.example", "live_results": {
        "validin": {"total": 1, "hosts": ["sibling.example"]},
        "fofa_ip_reverse": {"total": 1, "results": [{"domain": "sibling.example", "ip": "9.9.9.9"}]}}},
    {"kind": "favicon_hash", "value": "123", "live_results": {
        "hunterhow": {"total": 1, "hosts": [{"domain": "sibling.example"}]},
        "quake": {"total": 1, "hosts": ["quakeonly.example"]}}}]}


def test_frontier_merges_sources():
    cands, seeds = {}, {cs._frontier_apex("seed.example")}
    cs._free_candidates_from_raw(MULTI, cands, seeds)
    sib = cands.get(cs._frontier_apex("sibling.example"), {})
    check("sibling apex merges validin+hunterhow into one candidate",
          {"validin", "hunterhow"}.issubset(set(sib.get("sources") or [])), detail=str(sib))
    check("corroboration score = |sources| >= 2", len(sib.get("sources") or []) >= 2)
    qk = cands.get(cs._frontier_apex("quakeonly.example"), {})
    check("quake feeds the frontier (registry-driven)", "quake" in (qk.get("sources") or []))


def test_report_lists_engines():
    rep = er.render_cluster_report([MULTI], case="T")
    line = [l for l in rep.splitlines() if "sibling.example" in l and "seen by" in l]
    check("report shows a discovered host's engine list", bool(line), detail="no 'seen by' line")
    if line:
        check("report lists >=2 engines for the corroborated host",
              "Validin" in line[0] and "Hunter.how" in line[0] and "corroborated" in line[0],
              detail=line[0])


# --- 4. Vendor-wiring residue (Phase 5 of the premium-key plan) -------------------------------------
import json as _json          # noqa: E402
import tempfile as _tempfile  # noqa: E402
import wp_securitytrails as st  # noqa: E402
st._record = lambda *a, **k: None          # mocked calls must not ledger
for _m in (wp_quake, wp_zoomeye):
    if hasattr(_m, "_record"):
        _m._record = lambda *a, **k: None


def test_dnslytics_reverseip_is_cohost_routed_never_yielding():
    """The landmine: `dnslytics` (GA/AdSense siblings) is a host-yielding source with no co-tenancy
    filter; reverse-IP rows MUST live under the distinct `dnslytics_reverseip` key and go through
    _cohost_candidates — bulk hosting -> deferred lead, never a seed."""
    check("_HOST_YIELDING_SOURCES never reads dnslytics_reverseip",
          all(k != "dnslytics_reverseip" for k, _f, _l in cs._HOST_YIELDING_SOURCES))
    check("…but still reads the artifact-reverse `dnslytics` key",
          any(k == "dnslytics" for k, _f, _l in cs._HOST_YIELDING_SOURCES))
    bulk = {"ip": "203.0.113.9", "total": 500,
            "domains": [f"tenant{i}.example" for i in range(cs.MAX_IP_COHOSTS + 5)]}
    raw = {"meta": {"host": "seed.example"}, "pivots": [{"kind": "domain", "value": "seed.example",
           "live_results": {"dnslytics_reverseip": bulk}}]}
    cands, deferred = {}, cs._new_deferred()
    cs._free_candidates_from_raw(raw, cands, {"seed.example"}, deferred)
    check("bulk-hosting reverse-IP seeds NOTHING", not any(a.startswith("tenant") for a in cands), detail=str(sorted(cands)[:3]))
    lead = deferred["cohost"].get("203.0.113.9")
    check("…and lands in deferred['cohost'] keyed by the origin IP", bool(lead) and lead["source"] == "dnslytics_reverseip", detail=str(lead)[:120])
    small = {"ip": "198.51.100.7", "total": 2, "domains": ["sib1.example", "sib2.example"]}
    raw["pivots"][0]["live_results"]["dnslytics_reverseip"] = small
    cands = {}
    cs._free_candidates_from_raw(raw, cands, {"seed.example"}, cs._new_deferred())
    check("a dedicated box (2 tenants) DOES seed via the co-host route",
          {"sib1.example", "sib2.example"} <= set(cands) and all("ip_cohost" in c["sources"] for c in cands.values()))  # fixed co-host label
    # a raw file carrying rows under the OLD key shape would still be a landmine — the wiring never does that
    src = open(os.path.join(ROOT, "WebPivot", "tools", "wp_analyze.py"), encoding="utf-8").read()
    check("wp_analyze writes reverse-IP under lr['dnslytics_reverseip'] only",
          'lr["dnslytics_reverseip"]' in src and 'lr["dnslytics"] = dict(_rv' not in src)
    check("report maps dnslytics_reverseip as an IP reverse, not an artifact reverse",
          "dnslytics_reverseip" in er._IP_REVERSE_DISCOVERY and "dnslytics_reverseip" not in er._ARTIFACT_DISCOVERY)
    check("…and as an INFORMATIONAL source (a 500-tenant origin never saturates the domain pivot)",
          "dnslytics_reverseip" in er._INFO_SOURCES)


def test_securitytrails_history_and_reverse_whois():
    """dns_history a/aaaa -> {total, ips, eras[]}; _post builds no custom opener; reverse_whois_email
    degrades keyless; the diff has three honest buckets; the frontier seeds it via _whois_candidates."""
    saved = (st._get, st.securitytrails_configured)
    try:
        st.securitytrails_configured = lambda: True
        st._get = lambda path, **k: ({"records": [
            {"values": [{"ip": "198.51.100.7"}], "first_seen": "2025-01-02", "last_seen": "2025-03-01", "organizations": ["ExampleHost"]},
            {"values": [{"ip": "198.51.100.9"}], "first_seen": "2025-03-02", "last_seen": "2025-06-01"}]}, None)
        h = st.dns_history("seed.example", "a")
        check("dns_history normalises a-records to ips + dated eras",
              h["total"] == 2 and h["ips"] == ["198.51.100.7", "198.51.100.9"] and h["eras"][0]["first_seen"] == "2025-01-02"
              and h["eras"][0]["org"] == "ExampleHost", detail=str(h)[:160])
        st._get = lambda path, **k: ({"records": [{"values": [{"host": "mail.example"}]}]}, None)
        check("mx history stays raw records", st.dns_history("seed.example", "mx")["total"] == 1)
        check("unsupported record type -> error dict, no raise", "error" in st.dns_history("seed.example", "cname"))
    finally:
        st._get, st.securitytrails_configured = saved
    src = open(os.path.join(ROOT, "WebPivot", "tools", "wp_securitytrails.py"), encoding="utf-8").read()
    check("_post builds no custom opener (proxy-safe)", "build_opener(" not in src and "install_opener(" not in src)
    saved_cfg = st.securitytrails_configured
    try:
        st.securitytrails_configured = lambda: False
        check("reverse_whois_email keyless -> None (no network)", st.reverse_whois_email("owner@example.com") is None)
        st.securitytrails_configured = lambda: True
        saved_post = st._post
        st._post = lambda path, body, **k: ({"records": [{"hostname": "A.example"}, {"hostname": "b.example"}], "record_count": 2}, None)
        r = st.reverse_whois_email("Owner@Example.com")
        check("reverse_whois_email -> {term,count,domains} lowercased (same shape as WhoisXML)",
              r["term"] == "owner@example.com" and r["count"] == 2 and r["domains"] == ["a.example", "b.example"], detail=str(r))
        check("…and carries `total` too, so the report's hit readers render it", r["total"] == 2)
        check("an e-mail with a quote is refused before any call", "error" in st.reverse_whois_email("x'y@example.com"))
        st._post = lambda path, body, **k: (None, {"skipped": "HTTP 403 — plan"})
        check("a 403 degrades to a skipped dict carrying the term", st.reverse_whois_email("o@example.com").get("skipped"))
        st._post = saved_post
    finally:
        st.securitytrails_configured = saved_cfg
    d = st.reverse_whois_diff({"domains": ["a.example", "b.example"]},
                              [{"domains": ["b.example", "c.example"]}, {"skipped": "x"}])
    check("diff -> both / securitytrails_only / whoisxml_only",
          d["both"] == ["b.example"] and d["securitytrails_only"] == ["a.example"] and d["whoisxml_only"] == ["c.example"] and not d["note"])
    d2 = st.reverse_whois_diff({"skipped": "quota"}, [{"domains": ["c.example"]}])
    check("a skipped side is noted, never read as disagreement", "SecurityTrails side unavailable" in d2["note"] and d2["whoisxml_only"] == ["c.example"])
    raw = {"meta": {"host": "seed.example"}, "pivots": [{"kind": "whois:registrant_email", "value": "owner@example.com",
           "live_results": {"securitytrails_reverse_whois": {"term": "owner@example.com", "count": 2, "domains": ["sib1.example", "sib2.example"]}}}]}
    cands = {}
    cs._free_candidates_from_raw(raw, cands, {"seed.example"}, cs._new_deferred())
    check("securitytrails_reverse_whois seeds the frontier through _whois_candidates",
          {"sib1.example", "sib2.example"} <= set(cands) and all("reverse_whois" in c["sources"] for c in cands.values()))  # fixed reverse-WHOIS label
    raw["pivots"][0]["live_results"]["securitytrails_reverse_whois"] = {
        "term": "privacy@example-proxy.net", "count": 900, "domains": [f"x{i}.example" for i in range(30)]}
    cands, deferred = {}, cs._new_deferred()
    cs._free_candidates_from_raw(raw, cands, {"seed.example"}, deferred)
    check("…with the same privacy / MAX_WHOIS_SIBLINGS guard (held back as a lead)", not cands and deferred["whois"])
    # timeline reader
    sys.path.insert(0, os.path.join(ROOT, "IntelGraph", "scripts"))
    import case_timeline as ct  # noqa: E402
    out = []
    ct.hosting_events("seed.example", {"pivots": [{"kind": "domain", "value": "seed.example", "live_results": {
        "securitytrails_dns_history": {"total": 1, "ips": ["198.51.100.7"],
                                       "eras": [{"ip": "198.51.100.7", "first_seen": "2025-01-02", "last_seen": "2025-03-01"}]}}}]}, out)
    ev = [e for e in out if e]
    check("dns_history eras land on the `hosting` track with source securitytrails",
          len(ev) == 1 and ev[0]["kind"] == "hosting" and ev[0]["source"] == "securitytrails" and ev[0]["value"]["ip"] == "198.51.100.7", detail=str(ev)[:160])


def test_grayhatwarfare_is_exposure_never_seed():
    leads = {}
    cs._enrichment_leads_from_raw({"meta": {"host": "seed-brand.example"}, "artifacts": {}, "pivots": []}, leads)
    ghw = leads.get(("grayhatwarfare", "seed-brand.example"))
    check("GrayHatWarfare exposure lead is emitted per apex", bool(ghw) and ghw["key"] == "grayhatwarfare:seed-brand.example", detail=str(ghw)[:120])
    check("…keyed so enrichment-done can close it", ghw and ghw["key"].startswith("grayhatwarfare:"))
    check("GrayHatWarfare is in NO frontier registry",
          all("grayhat" not in k for k, _f, _l in cs._HOST_YIELDING_SOURCES))
    check("…and in NO report discovery map / hit source",
          all("grayhat" not in k for k in list(er._IP_REVERSE_DISCOVERY) + list(er._ARTIFACT_DISCOVERY) + [k for k, _ in er._HIT_SOURCES]))
    rep = er.render_cluster_report([{"meta": {"host": "seed-brand.example"}, "artifacts": {
        "buckets": {"buckets": [{"bucket": "seed-brand-assets", "fileCount": 3}]}}, "pivots": []}], case="T")
    check("report renders an Exposure section (not attribution) with the bucket",
          "## Exposure (leak surface — not attribution)" in rep and "seed-brand-assets" in rep)
    check("…and never lists the bucket as discovered infrastructure", "seed-brand-assets" not in rep.split("## Exposure")[0])


def test_censys_search_file_seeds_on_exact_cert_only():
    with _tempfile.TemporaryDirectory() as tmp:
        cdir = os.path.join(tmp, "CASE-0001")
        os.makedirs(os.path.join(cdir, "raw"))
        _json.dump({"meta": {"host": "seed.example"}, "pivots": []}, open(os.path.join(cdir, "raw", "seed.example.json"), "w"))
        _json.dump({"fingerprints": ["a" * 64], "hostnames": ["twin.example", "www.twin.example"], "ips": [], "hits": 2, "queries": []},
                   open(os.path.join(cdir, "censys_search.json"), "w"))
        fr = cs.frontier(cdir)
        check("censys_search.json hostnames seed the frontier (exact-cert = owner link)",
              "twin.example" in fr["pending"] and fr["candidates"]["twin.example"]["sources"] == ["censys_search"], detail=str(fr["pending"]))
        _json.dump({"fingerprints": ["a" * 64], "hostnames": ["twin.example"], "skipped": "recorded free", "queries": []},
                   open(os.path.join(cdir, "censys_search.json"), "w"))
        check("a skipped search seeds nothing", "twin.example" not in cs.frontier(cdir)["pending"])
        # a SHARED certificate (CDN / hoster bundle) returns many tenants: NEVER seeds, becomes a cert lead
        many = [f"tenant{i}.example" for i in range(cs.MAX_CERT_APEXES + 3)]
        _json.dump({"fingerprints": ["a" * 64, "b" * 64], "hits": 40,
                    "queries": [{"fingerprints": ["a" * 64], "hostnames": ["twin.example"], "total": 1},
                                {"fingerprints": ["b" * 64], "hostnames": many, "total": 900}],
                    "hostnames": ["twin.example"] + many, "ips": []},
                   open(os.path.join(cdir, "censys_search.json"), "w"))
        fr = cs.frontier(cdir)
        check("per-query guard: the genuine cert still seeds", "twin.example" in fr["pending"])
        check("…while the shared cert's tenants seed NOTHING", not any(a.startswith("tenant") for a in fr["pending"]), detail=str(fr["pending"])[:120])
        check("…and surface as a cert_overlap lead with the fingerprint",
              any(l.get("check") == "cert_overlap" and l.get("fingerprints") == ["b" * 64] for l in fr["co_tenancy_leads"]))
        _json.dump({"fingerprints": ["c" * 64], "hits": 3, "queries": [], "hostnames": ["x1.example", "x2.example", "x3.example"], "error": "timeout"},
                   open(os.path.join(cdir, "censys_search.json"), "w"))
        check("an errored search seeds nothing either", not {"x1.example", "x2.example", "x3.example"} & set(cs.frontier(cdir)["pending"]))
    # ST per-case cap + reverse-WHOIS case memo (wp_casememo under $WP_CASE_DIR)
    import wp_casememo
    with _tempfile.TemporaryDirectory() as tmp:
        saved_env = {k: os.environ.get(k) for k in (wp_casememo.CASE_DIR_ENV, wp_casememo.RUN_ID_ENV)}
        os.environ[wp_casememo.CASE_DIR_ENV] = tmp
        os.environ[wp_casememo.RUN_ID_ENV] = "run-1"
        saved = (st._post_raw, st.securitytrails_configured, st._RUN_CALLS, st._MAX_PER_CASE, st._USAGE)
        calls = []
        try:
            st.securitytrails_configured = lambda: True
            st._USAGE = {"used": 0, "allowed": 50}
            st._post_raw = lambda path, body, **k: (calls.append(body) or ({"records": [{"hostname": "sib.example"}], "record_count": 1}, None))
            r1 = st.reverse_whois_email("owner@example.com")
            st._RUN_CALLS = 0                       # a "new subprocess"
            r2 = st.reverse_whois_email("owner@example.com")
            check("ST reverse-WHOIS term is bought ONCE per case (disk memo survives a new process)",
                  len(calls) == 1 and r2.get("memo") == "case cache" and r2["domains"] == r1["domains"])
            st._MAX_PER_CASE = 2
            for i in range(5):
                st._RUN_CALLS = 0
                st.reverse_whois_email(f"o{i}@example.com")
            check("per-CASE cap holds across 'subprocesses' (process counter reset each time): cap 2 = r1 + one more",
                  len(calls) == 2, detail=f"calls={len(calls)}")
            check("…the ledger counts this run's charges", wp_casememo.spent("securitytrails") == 2)
        finally:
            st._post_raw, st.securitytrails_configured, st._RUN_CALLS, st._MAX_PER_CASE, st._USAGE = saved
            for k, v in saved_env.items():
                os.environ.pop(k, None)
                if v is not None:
                    os.environ[k] = v
    # what may be frozen for the case: entitlement skips yes; cap/budget/quota skips and errors never
    m = wp_casememo.memoisable
    check("casememo: results and entitlement skips are memoisable",
          m({"total": 1}) and m({"skipped": "HTTP 402 — phonebook is PAID-only"}) and m({"skipped": "your plan does not allow this"})
          and m({"skipped": "x", "skipped_kind": "entitlement"}))
    check("casememo: cap/budget/quota/rate-limit skips and errors are NOT memoisable",
          not m({"skipped": "per-run search cap reached"}) and not m({"skipped": "monthly budget exhausted"})
          and not m({"skipped": "quota"}) and not m({"skipped": "HTTP 429 rate limit"})
          and not m({"error": "timeout"}) and not m({"skipped": "x", "skipped_kind": "budget"}))
    check("casememo.put refuses a budget skip on disk", wp_casememo.put("t", "k", {"skipped": "per-run cap"}) is False
          and wp_casememo.get("t", "k") is None)
    src = open(os.path.join(ROOT, "tools", "intel.py"), encoding="utf-8").read()
    check("cmd_open never runs the Censys search under --no-collect (documented zero-egress) or no_spend",
          'if not getattr(a, "no_collect", False) and not _case_no_spend(case_dir):\n        _censys_certs_once(case_dir, raw_files)' in src)
    check("a skipped prior censys_search.json is retried, not frozen",
          'and not prev.get("skipped")' in src)


def test_live_run_followups_ranking_memo_mask_roles():
    """Findings from the Phase-6 live run, pinned: (1) impersonation-only lookalikes rank BELOW owner-link
    candidates in the frontier; (2) WhoisXML reverse-WHOIS is bought once per case; (3) registrar role
    mailboxes stay in clear deliberately; (4) IntelX never spends a unit on spam-reports@/abuse@."""
    # (1) ranking
    with _tempfile.TemporaryDirectory() as tmp:
        cdir = os.path.join(tmp, "CASE-0001"); os.makedirs(os.path.join(cdir, "raw"))
        raw = {"meta": {"host": "seed.example"}, "pivots": [
            {"kind": "impersonation:candidate", "value": "aaa-lookalike.example"},
            {"kind": "impersonation:candidate", "value": "aab-lookalike.example"},
            {"kind": "whois:registrant_email", "value": "owner@example.com",
             "live_results": {"reverse_whois_current": {"term": "owner@example.com", "count": 1, "domains": ["zzz-sibling.example"]}}}]}
        _json.dump(raw, open(os.path.join(cdir, "raw", "seed.example.json"), "w"))
        fr = cs.frontier(cdir, max_new=1)
        check("an owner-link candidate outranks alphabetically-earlier lookalike-only candidates",
              fr["pending"] == ["zzz-sibling.example"], detail=str(fr["pending"]))
        check("…lookalikes are still candidates (not dropped)", "aaa-lookalike.example" in fr["candidates"])
    # (2) WhoisXML reverse memo
    import whois_enrich as we, wp_casememo
    with _tempfile.TemporaryDirectory() as tmp:
        saved_env = {k: os.environ.get(k) for k in (wp_casememo.CASE_DIR_ENV,)}
        os.environ[wp_casememo.CASE_DIR_ENV] = tmp
        saved = (we._key, we._post_json)
        calls = []
        try:
            we._key = lambda: "test-key-not-real"
            we._post_json = lambda url, payload, timeout=40: (calls.append(payload) or {"domainsCount": 1, "domainsList": ["sib.example"]})
            r1 = we.reverse_whois("owner@example.com", "email", search_type="current")
            r2 = we.reverse_whois("owner@example.com", "email", search_type="current")
            check("WhoisXML reverse-WHOIS bought once per case (memo hit on the second call)",
                  len(calls) == 1 and r2.get("memo") == "case cache" and r2["domains"] == r1["domains"])
            check("…a different search_type is a different purchase", we.reverse_whois("owner@example.com", "email", search_type="historic") and len(calls) == 2)
        finally:
            we._key, we._post_json = saved
            for k, v in saved_env.items():
                os.environ.pop(k, None)
                if v is not None: os.environ[k] = v
    # (3) role mailboxes in clear, deliberately
    sys.path.insert(0, os.path.join(ROOT, "..", "scripts"))
    import cti_third_party_mask as m
    out = m.mask_third_parties("refer to abuse@registrar.example and owner@third.example", keep=(), hosts=())
    check("registrar abuse@ role mailbox stays in clear; a third-party person is masked",
          "abuse@registrar.example" in out and "owner@third.example" not in out and "o***@third.example" in out, detail=out)
    # (4) IntelX role filter
    import wp_intelx as ix
    rows = ix._enrich_targets({"meta": {"host": "seed.example"}, "pivots": [
        {"kind": "email", "value": "spam-reports@seed.example"}, {"kind": "email", "value": "abuse@seed.example"},
        {"kind": "whois:registrant_email", "value": "owner7781@example.org"}]})
    vals = [v for _c, v, _p in rows]
    check("IntelX skips spam-reports@/abuse@ role mailboxes and keeps the real selector",
          "owner7781@example.org" in vals and not any(v.startswith(("spam-reports@", "abuse@")) for v in vals), detail=str(vals))


for _t in (test_quake_zoomeye_gate_and_proxy_safe, test_quake_normalises_and_tri_states,
           test_zoomeye_normalises_and_tri_states, test_reputation_is_corroboration_only,
           test_frontier_merges_sources, test_report_lists_engines,
           test_dnslytics_reverseip_is_cohost_routed_never_yielding, test_securitytrails_history_and_reverse_whois,
           test_grayhatwarfare_is_exposure_never_seed, test_censys_search_file_seeds_on_exact_cert_only,
           test_live_run_followups_ranking_memo_mask_roles):
    _t()

if FAILURES:
    print(f"\nFAIL — {len(FAILURES)} check(s) failed:")
    for f in FAILURES:
        print("  -", f)
    sys.exit(1)
print("\nPASS — all engine-addition checks green")


def test_engine_additions():
    """pytest entry point — module body runs the checks at import time."""
    assert not FAILURES, FAILURES
