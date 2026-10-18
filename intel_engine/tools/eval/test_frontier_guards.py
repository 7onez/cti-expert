#!/usr/bin/env python3
"""Offline unit gate for the frontier CO-TENANCY guards (case_state).

A frontier seed is not just a fetch — it is collected AND ingested, so a co-tenant that slips
through becomes a fake "shared indicator" in every later case. These are the three counting rules
that keep that from happening (multi-tenant cert / shared-hosting IP / bulk registrant term), plus
the proof that a NARROW cert, a small IP, and a small registrant term still seed normally — the
guards must not cost us real leads.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))), "tools"))
import case_state as CS  # noqa: E402


def _mine(obj, seeds=("seed.example",)):
    """Run the frontier miner over one synthetic raw pivot JSON. Returns (apexes, leads)."""
    cands, deferred = {}, CS._new_deferred()
    CS._free_candidates_from_raw(obj, cands, {CS._registrable(s) for s in seeds}, deferred)
    leads = [v for slot in deferred.values() for v in slot.values()]
    return set(cands), leads


def _domain_pivot(registered_on=None, **live):
    obj = {"meta": {"host": "seed.example"},
           "pivots": [{"kind": "domain", "value": "seed.example", "live_results": live}]}
    if registered_on:
        obj["artifacts"] = {"whois": {"created": registered_on}}
    return obj


def _reverse_pivot(kind, term, **live):
    """A raw file whose reverse-WHOIS block rides on the registrant pivot that produced it — the
    shape wp_analyze.whois_enrich_result emits (the block is on the email/name pivot, not `domain`)."""
    return {"meta": {"host": "seed.example"},
            "pivots": [{"kind": "domain", "value": "seed.example"},
                       {"kind": kind, "value": term, "live_results": live}]}


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

    # --- 1. TLS certs -------------------------------------------------------------------------
    # A2/A3 crt.sh guard: a foreign co-SAN on a narrow cert only seeds when that cert's not_before
    # is on/after the host's current WHOIS registration (see test_crtsh_seed_guard.py for the full
    # date-gate + flat-list-truncation matrix) — registered_on/not_before are set here so this
    # section still isolates the CERT-WIDTH guard, not the date guard.
    narrow = {"certs": [{"id": 1, "issuer": "CA", "names": ["seed.example", "sibling.example"],
                         "not_before": "2024-06-01T00:00:00"}],
              "subdomains": ["sibling.example"]}
    apex, leads = _mine(_domain_pivot(crtsh=narrow, registered_on="2024-01-01"))
    ok("sibling.example" in apex, "narrow cert: a real SAN sibling still seeds")
    ok(not leads, "narrow cert: no co-tenancy lead raised")

    wide_names = ["seed.example"] + [f"tenant{i}.example" for i in range(CS.MAX_CERT_APEXES + 2)]
    wide = {"certs": [{"id": 2, "issuer": "CA", "names": wide_names}],
            "subdomains": [n for n in wide_names if n != "seed.example"]}
    apex, leads = _mine(_domain_pivot(crtsh=wide))
    ok(not any(a.startswith("tenant") for a in apex), "multi-tenant cert: co-names do NOT seed")
    ok(any(l["check"] == "cert_overlap" for l in leads), "multi-tenant cert: raised as cert lead")

    # a host whose CT listing carries a wide cert sits on a multi-tenant cert PLATFORM: its narrow
    # 2-name pairings are load-balancer co-tenants (Google-managed / CDN certs pair random customers),
    # so even a name on a narrow cert is held back as a cert_overlap lead — never seeded blind.
    both = {"certs": [{"id": 3, "names": wide_names},
                      {"id": 4, "names": ["seed.example", "tenant0.example"]}],
            "subdomains": ["tenant0.example", "tenant1.example", "panel.seed.example"]}
    CS._SUBS.clear()
    apex, leads = _mine(_domain_pivot(crtsh=both))
    ok("tenant0.example" not in apex, "narrow pairing on a multi-tenant-platform host does NOT seed")
    ok("tenant1.example" not in apex, "name only on the wide cert stays suppressed")
    ok(any(l.get("seen_on") == "seed.example" and "multi-tenant cert platform" in l["why"] for l in leads),
       "…surfaced as a cert_overlap lead naming the platform pairing")
    ok("panel.seed.example" in CS._SUBS.get("seed.example", {}), "the seed's OWN subdomain is still noted")
    CS._SUBS.clear()
    # dedicated issuance (no wide cert anywhere in the listing): a narrow co-SAN is a real sibling
    # once its cert postdates the current registration (see test_crtsh_seed_guard.py for the
    # stale/unknown-date branches this guard also holds back).
    dedicated = {"certs": [{"id": 5, "names": ["seed.example", "sibling.example"],
                            "not_before": "2024-06-01T00:00:00"},
                           {"id": 6, "names": ["www.seed.example", "seed.example"],
                            "not_before": "2024-06-02T00:00:00"}],
                 "subdomains": ["sibling.example"]}
    apex, leads = _mine(_domain_pivot(crtsh=dedicated, registered_on="2024-01-01"))
    ok("sibling.example" in apex and not leads, "dedicated certs only: the narrow co-SAN seeds")

    # --- 2. IP co-hosts -----------------------------------------------------------------------
    small = {"query": 'ip="203.0.113.7"', "total": 2,
             "results": [{"host": "a.example", "ip": "203.0.113.7", "domain": "a.example"},
                         {"host": "b.example:443", "ip": "203.0.113.7", "domain": ""}]}
    apex, leads = _mine(_domain_pivot(fofa_ip_reverse=small))
    ok({"a.example", "b.example"} <= apex, "small IP: co-hosts seed (port stripped from host)")
    ok(not leads, "small IP: no co-tenancy lead")

    many = {"query": 'ip="203.0.113.8"', "total": CS.MAX_IP_COHOSTS + 5,
            "results": [{"host": f"t{i}.example", "ip": "203.0.113.8", "domain": f"t{i}.example"}
                        for i in range(CS.MAX_IP_COHOSTS + 5)]}
    apex, leads = _mine(_domain_pivot(fofa_ip_reverse=many))
    ok(not apex, "shared-hosting IP: co-tenants do NOT seed")
    ok(any(l["check"] == "shared-hosting co-tenancy" for l in leads), "shared IP: raised as lead")
    ok(any(l.get("cohost_count", 0) > CS.MAX_IP_COHOSTS for l in leads),
       "shared IP lead carries the true co-host count")

    # an ORIGIN IP with many open services is one row per host:port — that must NOT read as tenancy
    ports = {"query": 'ip="203.0.113.9"', "total": 40,
             "results": ([{"host": f"203.0.113.9:{p}", "ip": "203.0.113.9", "domain": ""}
                          for p in range(8000, 8038)]
                         + [{"host": "origin.example", "ip": "203.0.113.9", "domain": "origin.example"}])}
    apex, leads = _mine(_domain_pivot(fofa_ip_reverse=ports))
    ok(apex == {"origin.example"}, "origin IP with many PORTS still seeds its one real co-host")
    ok(not leads, "many services on one IP is not co-tenancy")

    # TRUNCATED page off a bulk IP: few apexes visible, but thousands of rows behind it → suppress
    bulkip = {"query": 'ip="203.0.113.10"', "total": CS.BULK_IP_RESULTS + 1,
              "results": [{"host": "x.example", "ip": "203.0.113.10", "domain": "x.example"}]}
    apex, leads = _mine(_domain_pivot(fofa_ip_reverse=bulkip))
    ok(not apex, "truncated bulk IP: narrow page still suppressed via the total backstop")

    # COMPLETE result set of the same size: we measured every row, so the apex count is exact and
    # the backstop must NOT fire — otherwise a well-populated single-operator host is lost.
    n = CS.BULK_IP_RESULTS + 1
    complete = {"query": 'ip="203.0.113.11"', "total": n,
                "results": ([{"host": f"svc{i}.own.example:{8000 + i}", "ip": "203.0.113.11",
                              "domain": "own.example"} for i in range(n)])}
    apex, leads = _mine(_domain_pivot(fofa_ip_reverse=complete))
    ok(apex == {"own.example"}, "untruncated big result set: exact apex count wins, still seeds")
    ok(not leads, "untruncated big result set: no false co-tenancy lead")

    # --- 3. Reverse-WHOIS ---------------------------------------------------------------------
    few = {"term": "operator@example.com", "count": 3,
           "domains": ["one.example", "two.example", "three.example"]}
    apex, leads = _mine(_reverse_pivot("whois:registrant_email", few["term"], reverse_whois_current=few))
    ok({"one.example", "two.example", "three.example"} <= apex,
       "small registrant term: siblings seed")
    ok(not leads, "small registrant term: no lead")

    bulk = {"term": "reseller@example.com", "count": CS.MAX_WHOIS_SIBLINGS + 100,
            "domains": [f"b{i}.example" for i in range(10)]}   # count > returned page
    apex, leads = _mine(_reverse_pivot("whois:registrant_email", bulk["term"], reverse_whois_historic=bulk))
    ok(not apex, "bulk registrant term: siblings do NOT seed (count, not page size, decides)")
    ok(any(l["check"] == "bulk registrant term" for l in leads), "bulk term: raised as lead")

    privacy = {"term": "registry-abuse@cloudflare.com", "count": 2,
               "domains": ["p1.example", "p2.example"]}
    apex, leads = _mine(_reverse_pivot("whois:registrant_email", privacy["term"], reverse_whois_current=privacy))
    ok(not apex, "privacy/registrar-abuse term: never seeds even when the count is small")
    ok(any(l["check"] == "bulk registrant term" for l in leads), "privacy term: raised as lead")

    # RULE 5: only registrant e-mail/phone are decisive join keys. A NAME reverse answers every
    # namesake — live run: a common registrant name returned 28 current / 153 historic unrelated
    # domains, all under MAX_WHOIS_SIBLINGS, and every one was seeded and collected.
    namesakes = {"term": "Nguyen Van Example", "count": 12,
                 "domains": ["n1.example", "n2.example", "n3.example"]}
    for kind in ("whois:registrant_name", "whois:registrant_org"):
        apex, leads = _mine(_reverse_pivot(kind, namesakes["term"], reverse_whois_current=namesakes,
                                           reverse_whois_historic=namesakes))
        ok(not apex, f"{kind} reverse: a small namesake set still NEVER seeds")
        ok(len(leads) == 1 and "collision" in leads[0]["check"] and leads[0]["sibling_count"] == 12,
           f"{kind} reverse: held as ONE collision lead carrying its count (current+historic merged)")
    phone = {"term": "15550000000", "count": 2, "domains": ["ph1.example", "ph2.example"]}
    apex, _leads = _mine(_reverse_pivot("whois:registrant_phone", phone["term"], reverse_whois_current=phone))
    ok({"ph1.example", "ph2.example"} <= apex, "registrant PHONE reverse is decisive and still seeds")

    # --- 3b. METERED leads never ask for spend that is wasted or already made ---------------------
    def _metered(obj):
        leads = {}
        CS._metered_leads_from_raw(obj, leads)
        return {v["query"] for v in leads.values()}
    owner = "owner@example.com"
    def _email_raw(**live):
        return {"meta": {"host": "seed.example"}, "artifacts": {"whois": {"registrant_email": owner}},
                "pivots": [{"kind": "whois:registrant_email", "value": owner, "live_results": live}]}
    rw_q = f'reverse-whois email="{owner}"'
    ok(rw_q in _metered(_email_raw()), "an owner email never reversed is offered as a metered lead")
    ok(rw_q not in _metered(_email_raw(reverse_whois_current={"term": owner, "count": 0, "domains": []})),
       "an owner email whose reverse-WHOIS already ran (even with 0 hits) is NOT offered again — "
       "that would ask the analyst to approve spend that already happened")
    ok(rw_q in _metered(_email_raw(reverse_whois_current={"error": "HTTP 503"})),
       "a reverse-WHOIS that ERRORED stays offered (nothing was learned)")
    dns_obj = {"meta": {"host": "seed.example"}, "pivots": [{"kind": "domain", "value": "seed.example",
               "live_results": {"dns": {"ip_classification": [
                   {"ip": "127.0.0.1", "cdn": False, "kind": "bogon"},
                   {"ip": "198.51.100.7", "cdn": False, "kind": "origin_candidate"}]}}}]}
    q = _metered(dns_obj)
    ok('ip="127.0.0.1"' not in q, "a bogon (loopback/private) origin is never offered as a FOFA ip reverse")
    ok('ip="198.51.100.7"' in q, "a real origin candidate is still offered")
    fav_obj = {"meta": {"host": "seed.example"}, "pivots": [{"kind": "favicon_hash", "value": 12345}]}
    ok('icon_hash="12345"' in _metered(fav_obj), "a favicon hash never reversed is offered as a FOFA lead")
    fav_paid = {"meta": {"host": "seed.example"}, "pivots": [{"kind": "favicon_hash", "value": 12345,
                "live_results": {"fofa": {"results": [], "total": 0}}}]}
    ok('icon_hash="12345"' not in _metered(fav_paid),
       "a favicon hash whose FOFA reverse already ran is NOT offered again")

    # --- 4. ONE noise policy: the frontier gate delegates to noise_filters -----------------------
    infra = {"query": 'ip="203.0.113.12"', "total": 3,
             "results": [{"host": h, "ip": "203.0.113.12", "domain": h}
                         for h in ("sedo.com", "godaddy.com", "cdn.jsdelivr.net")]}
    apex, _ = _mine(_domain_pivot(fofa_ip_reverse=infra))
    ok(not apex, "registrar / parking / CDN apexes never seed (noise_filters)")

    # a SaaS tenant is a real target even though the platform apex is infrastructure
    tenant = {"query": 'ip="203.0.113.13"', "total": 3,
              "results": [{"host": h, "ip": "203.0.113.13", "domain": h}
                          for h in ("pages.dev", "kit.pages.dev", "shop.myshopify.com")]}
    apex, _ = _mine(_domain_pivot(fofa_ip_reverse=tenant))
    ok("kit.pages.dev" in apex and "shop.myshopify.com" in apex,
       "SaaS TENANTS still seed (platform apex is noise, tenant is a target)")
    ok("pages.dev" not in apex, "the bare SaaS platform apex does not seed")

    # analyst-marked benign in reference.jsonl suppresses an apex everywhere, not just once
    CS._BENIGN.clear()
    CS._BENIGN.append({"known-benign.example"})
    try:
        ref = {"query": 'ip="203.0.113.14"', "total": 2,
               "results": [{"host": h, "ip": "203.0.113.14", "domain": h}
                           for h in ("known-benign.example", "real-lead.example")]}
        apex, _ = _mine(_domain_pivot(fofa_ip_reverse=ref))
        ok(apex == {"real-lead.example"}, "reference-benign apex suppressed; the real lead survives")
    finally:
        CS._BENIGN.clear()

    # --- 5. helpers ---------------------------------------------------------------------------
    ok(CS._clean_name("*.Wild.Example.") == "wild.example", "wildcard/case/dot normalised")
    ok(CS._clean_name("https://h.example/path?q=1") == "h.example", "scheme+path stripped")
    ok(CS._clean_name("10.0.0.1:8080") == "", "bare IP is not a domain candidate")
    ok(CS._cohost_name({"host": "1.2.3.4:80", "domain": "real.example"}) == "real.example",
       "co-host row prefers the clean domain field")

    # --- 6. NON-OWNER sources never seed (the urlscan related-scan drift) ----------------------
    # urlscan `domain:<host>` returns every page that merely LOADED a resource from the host: the
    # vendor's customers, not its registrations. A candidate whose only sources are that class is a
    # `related_lead`, never `pending`; one owner-link source (a cert co-SAN) still seeds.
    rel_only = {"related": {"sources": {"urlscan_related", "urlscan_related_domain"}, "examples": {"related.example"}},
                "owner": {"sources": {"crtsh_san"}, "examples": {"owner.example"}},
                "both": {"sources": {"urlscan_related", "validin"}, "examples": {"both.example"}},
                "look": {"sources": {"impersonation"}, "examples": {"look.example"}}}
    ok(not CS._owner_linked(rel_only["related"]["sources"]), "urlscan_related-only candidate is NOT owner-linked")
    ok(not CS._owner_linked(rel_only["look"]["sources"]), "impersonation-only candidate is NOT owner-linked")
    ok(CS._owner_linked(rel_only["owner"]["sources"]), "a cert co-SAN candidate IS owner-linked")
    ok(CS._owner_linked(rel_only["both"]["sources"]), "urlscan_related + one engine reverse IS owner-linked")
    ok(not CS._owner_linked(set()), "no sources → not owner-linked")
    # end-to-end through the miner: a page-related domain from the urlscan block is a candidate…
    apex, _ = _mine(_domain_pivot(urlscan={"domains": ["customer-shop.example"]}))
    ok("customer-shop.example" in apex, "urlscan related domain is recorded as a candidate")
    # …but with ONLY that source it cannot be seeded (frontier() drops it into related_leads)
    cands, deferred = {}, CS._new_deferred()
    CS._free_candidates_from_raw(_domain_pivot(urlscan={"domains": ["customer-shop.example"]}), cands,
                                 {"seed.example"}, deferred)
    ok(cands["customer-shop.example"]["sources"] <= CS._NON_OWNER_SOURCES,
       "that candidate carries only non-owner sources → frontier() will not put it in pending")

    # --- 7. never_seed: the analyst-directed route rejects vendors / shared infra ---------------
    ok(CS.never_seed("hunter.how") and CS.never_seed("fofa.info") and CS.never_seed("urlscan.io"),
       "the engine's own data vendors are never leads (api_keys.json signup hosts)")
    ok(CS.never_seed("cloudflaressl.com"), "a shared-cert CDN apex is never a lead")
    ok(not CS.never_seed("real-lead.example"), "an ordinary apex is not rejected")
    # A domain-SHAPED token is not a hostname when its last label is not a TLD. The loop once read
    # "see clusters.json" and "indicator:ns:a.<registrar-dns>" out of its own assessment and paid
    # WHOIS for both; the TLD gate closes the first class on every route, the managed-DNS denylist
    # the second.
    ok(CS.never_seed("clusters.json") and CS.never_seed("state.txt") and CS.never_seed("index.html"),
       "a filename-shaped token is never a lead (no PSL TLD)")
    ok(CS._clean_name("clusters.json") == "" and CS._clean_name("lead.example") == "lead.example",
       "_clean_name drops a non-TLD token but keeps a reserved .example fixture host")
    ok(not CS.never_seed("shop.onion"), ".onion is a real pivot target, not a filename")
    ok(CS._is_noise_apex("share-dns.com", set()) or CS.never_seed("a.share-dns.com"),
       "a registrar's default nameserver apex is never a lead")
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    import intel as IP  # noqa: E402
    own = {"_generator": IP._LOOP_GENERATOR,
           "next_pivots": ["judge cluster c1 (3 domains: x.example) — bound by indicator:ns:a.self-fed.example"],
           "gaps": ["6 components (see clusters.json)"]}
    ok(IP._analyst_leads(own) == set(), "the loop never reads its OWN assessment.json back as leads")
    theirs = dict(own, _generator="analyst")
    ok(IP._analyst_leads(theirs) == {"x.example", "a.self-fed.example"},
       "an analyst-authored assessment still yields its domain leads, minus filename tokens")

    # --- 8. PSL-aware apex keying (second-level registries / free-subdomain platforms) -----------
    ok(CS._frontier_apex("horizon.io.vn") == "horizon.io.vn", "io.vn is a VNNIC public suffix: tenant is the apex")
    ok(CS._frontier_apex("zc2.sa.com") == "zc2.sa.com", "sa.com (CentralNic) is a public suffix: tenant is the apex")
    ok(CS._frontier_apex("huystore.work.gd") == "huystore.work.gd", "work.gd free-subdomain platform: tenant is the apex")
    ok(CS._is_noise_apex("work.gd", set()) and CS._is_noise_apex("cloudflaressl.com", set()),
       "bare work.gd / cloudflaressl.com apexes are noise, never seeds")
    ok(CS._frontier_apex("api.cmsnt.example") == "cmsnt.example", "an ordinary host still reduces to its apex")
    # Shared-infra merge (RULE 5): a page that loads mobile-attribution / session-replay / chat-widget
    # vendors reports their hosts as "related"; those apexes must not seed, while an operator's own
    # apex in the same block still does. A per-customer helpdesk (`<company>.zendesk.com`) is a
    # TENANT — the bare platform apex is noise, the tenant is the registrable unit and stays a lead.
    rel = ["sdk.appsflyer.com", "static.hotjar.io", "client.crisp.chat", "t.me", "zendesk.com",
           "acme-help.zendesk.com", "cdn.operator-a.example"]
    apex, _ = _mine(_domain_pivot(urlscan={"domains": rel}))
    ok(not apex & {"appsflyer.com", "hotjar.io", "crisp.chat", "t.me", "zendesk.com"},
       f"newly listed shared-infra apexes never become frontier candidates ({sorted(apex)})")
    ok({"operator-a.example", "acme-help.zendesk.com"} <= apex,
       "the operator's own apex and a helpdesk TENANT still become candidates")
    ok(CS._frontier_apex("acme-help.zendesk.com") == "acme-help.zendesk.com",
       "a zendesk tenant is keyed on its tenant label, not collapsed into zendesk.com")

    # --- 9. ENGINE artifact reverses carry the same prevalence guard as certs/IPs/registrants -----
    # DNSLytics answered 2,500 domains for the template placeholder `G-XXXXXXXXXX`; Hunter.how / Validin
    # / Censys rows have the same shape. Small = owner link, seeds; large = platform artifact, lead.
    def _tracker_pivot(engine, field, rows, total=None):
        blk = {field: rows}
        if total is not None:
            blk["total"] = total
        return {"meta": {"host": "seed.example"},
                "pivots": [{"kind": "tracker:google_analytics_ga4", "value": "G-REAL12345",
                            "live_results": {engine: blk}}]}
    small = [f"sib{i}.example" for i in range(5)]
    apex, leads = _mine(_tracker_pivot("dnslytics", "domains", small))
    ok(set(small) <= apex and not leads, "5-domain tracker reverse: siblings seed, no lead")
    big = [f"stranger{i}.example" for i in range(CS.MAX_ARTIFACT_SIBLINGS + 3)]
    apex, leads = _mine(_tracker_pivot("dnslytics", "domains", big))
    ok(not any(a.startswith("stranger") for a in apex), "shared tracker (> MAX_ARTIFACT_SIBLINGS): NOTHING seeds")
    ok(any(l["check"] == "reference_check" and l["source"] == "dnslytics" and l["sibling_count"] == len(big)
           for l in leads), "…held back as an `artifact` lead carrying the true count and a reference_check hint")
    # a truncated page: few rows returned but `total` says thousands → still a platform artifact
    apex, leads = _mine(_tracker_pivot("hunterhow", "hosts", [{"host": "h1.example"}, {"host": "h2.example"}], total=4000))
    ok("h1.example" not in apex and any(l["sibling_count"] == 4000 for l in leads),
       "engine `total` beyond the page still trips the guard (Hunter.how dict rows)")
    # bare IP rows are not domain candidates
    apex, leads = _mine(_tracker_pivot("validin", "hosts", ["203.0.113.5", "real.example"]))
    ok(apex == {"real.example"} and not leads, "an IP row in an engine block is skipped, the host seeds")
    # an engine SUBDOMAIN listing of the seed apex (Validin/SecurityTrails) is the same registration:
    # 60 own hosts are noted as subdomains, never counted as foreign siblings, no lead raised
    CS._SUBS.clear()
    subs = [f"sub{i}.seed.example" for i in range(CS.MAX_ARTIFACT_SIBLINGS * 2 + 10)]
    apex, leads = _mine(_tracker_pivot("validin_subs", "hosts", subs))
    ok(not leads and not apex and len(CS._SUBS.get("seed.example", {})) == len(subs),
       "a 60-host listing of the seed's OWN subdomains is not a prevalence hit (noted as subdomains)")
    CS._SUBS.clear()

    # --- 10. template PLACEHOLDER tracker ids never become tracker pivots ------------------------
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__)))), "WebPivot", "tools"))
    import wp_pivots as WP  # noqa: E402
    for v in ("G-XXXXXXXXXX", "GTM-XXXXXXX", "UA-XXXXXXXX-X", "UA-00000-0", "AW-123456789", "G-XXXX1234"):
        ok(WP._is_placeholder_tracker(v), f"{v} is a template placeholder, not an owner id")
    for v in ("G-ABCDEFGH1", "UA-42424-7", "GTM-ABCDEF", "ca-pub-4242424242424242"):
        ok(not WP._is_placeholder_tracker(v), f"{v} is a real-looking id and is kept")

    # --- 11. EXPANSION ANCHOR: hops from the seeds; a host at the depth is a leaf -----------------
    # seed (hop 0) → its registrant's sibling (hop 1) → the sibling's registrant's other site (hop 2)
    # → THAT site's registrant's sites (hop 3 = strangers). With depth 2: hop 1 mined, hop 2 collected
    # as a leaf, hop 3 never enters the frontier; the MO/estate identity is taken from hops < 2 only.
    import json as _json
    import tempfile as _tf

    def _raw(host, rw_domains, rw_term):
        return {"meta": {"host": host}, "pivots": [
            {"kind": "domain", "value": host},
            {"kind": "whois:registrant_email", "value": rw_term,
             "live_results": {"reverse_whois_current": {"term": rw_term, "count": len(rw_domains),
                                                        "domains": rw_domains}}}]}
    with _tf.TemporaryDirectory() as tmp:
        cdir = os.path.join(tmp, "CASE-0001")
        os.makedirs(os.path.join(cdir, "raw"))
        for host, doms, term in (("seed.example", ["sib.example"], "owner@example.com"),
                                 ("sib.example", ["client.example"], "owner@example.com"),
                                 ("client.example", ["stranger.example"], "client@example.com")):
            _json.dump(_raw(host, doms, term), open(os.path.join(cdir, "raw", host + ".json"), "w"))
        st = CS.load_state(cdir)
        st["hops"] = {"seed.example": 0, "sib.example": 1, "client.example": 2}
        st["expansion_depth"] = 2
        CS.save_state(cdir, st)
        fr = CS.frontier(cdir, max_new=0)
        ok(fr["leaves"] == ["client.example"], "the hop-2 host is a LEAF (collected, not mined)")
        ok("stranger.example" not in fr["pending"] and "stranger.example" not in fr["candidates"],
           "a leaf's registrant siblings never enter the frontier (no hop 3)")
        ok(fr["expansion_depth"] == 2, "frontier reports the anchor depth")
        # raise the depth: the leaf is mined and the stranger appears at hop 3 with its origin recorded
        st["expansion_depth"] = 3
        CS.save_state(cdir, st)
        fr3 = CS.frontier(cdir, max_new=0)
        c = fr3["candidates"].get("stranger.example") or {}
        ok(c.get("hop") == 3 and c.get("origins") == ["client.example"],
           "with depth 3 the stranger is a hop-3 candidate whose origin is the hop-2 host")
        ok(CS._expanding_hosts(cdir) == {"seed.example", "sib.example", "client.example"},
           "expanding set follows the depth (all three at depth 3)")
        st["expansion_depth"] = 1
        CS.save_state(cdir, st)
        ok(CS._expanding_hosts(cdir) == {"seed.example"}, "…and only the seed at depth 1")
        fr1 = CS.frontier(cdir, max_new=0)
        ok(fr1["pending"] == [] and set(fr1["leaves"]) == {"sib.example", "client.example"},
           "at depth 1 nothing beyond the seed's own siblings is pending; hop-1/2 hosts are leaves")
        # UNKNOWN PROVENANCE in an anchored case: a collected host with no recorded hop (a subdomain
        # collected under a leaf, an interrupted round) is a LEAF, and a candidate whose only origin
        # is such a host is never pending — an unknown must not become a seed by omission.
        st["expansion_depth"] = 2
        st["hops"] = {"seed.example": 0, "sib.example": 1}          # client.example: no hop recorded
        CS.save_state(cdir, st)
        fru = CS.frontier(cdir, max_new=0)
        ok("client.example" in fru["leaves"], "a collected host with no recorded hop is a leaf in an anchored case")
        ok("stranger.example" not in fru["pending"] and "stranger.example" not in fru["candidates"],
           "…so a candidate whose sole origin is that host is NOT pending")
        ok(CS._expanding_hosts(cdir) == {"seed.example", "sib.example"},
           "…and it contributes no identity to the MO/estate anchor")
    # an older state.json without hops treats every collected host as a seed (no behaviour change)
    hops, depth = CS._hops_and_depth({"collected": ["x.example"]})
    ok(hops == {} and depth == CS.DEFAULT_EXPANSION_DEPTH and not CS.is_leaf("x.example", hops, depth),
       "legacy state without hops: nothing is a leaf, default depth applies")

    return passed, failed, out


if __name__ == "__main__":
    p, f, lines = check()
    for s, l in lines:
        print(f"  {'ok ' if s == 'ok' else '✗  '} {l}")
    sys.exit(1 if f else 0)
