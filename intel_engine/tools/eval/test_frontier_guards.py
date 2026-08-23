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


def _domain_pivot(**live):
    return {"meta": {"host": "seed.example"},
            "pivots": [{"kind": "domain", "value": "seed.example", "live_results": live}]}


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
    narrow = {"certs": [{"id": 1, "issuer": "CA", "names": ["seed.example", "sibling.example"]}],
              "subdomains": ["sibling.example"]}
    apex, leads = _mine(_domain_pivot(crtsh=narrow))
    ok("sibling.example" in apex, "narrow cert: a real SAN sibling still seeds")
    ok(not leads, "narrow cert: no co-tenancy lead raised")

    wide_names = ["seed.example"] + [f"tenant{i}.example" for i in range(CS.MAX_CERT_APEXES + 2)]
    wide = {"certs": [{"id": 2, "issuer": "CA", "names": wide_names}],
            "subdomains": [n for n in wide_names if n != "seed.example"]}
    apex, leads = _mine(_domain_pivot(crtsh=wide))
    ok(not any(a.startswith("tenant") for a in apex), "multi-tenant cert: co-names do NOT seed")
    ok(any(l["check"] == "cert_overlap" for l in leads), "multi-tenant cert: raised as cert lead")

    # a name on BOTH a wide and a narrow cert is a genuine co-SAN — the guard must not eat it
    both = {"certs": [{"id": 3, "names": wide_names},
                      {"id": 4, "names": ["seed.example", "tenant0.example"]}],
            "subdomains": ["tenant0.example", "tenant1.example"]}
    apex, _ = _mine(_domain_pivot(crtsh=both))
    ok("tenant0.example" in apex, "name on a narrow cert too is kept (not tainted)")
    ok("tenant1.example" not in apex, "name only on the wide cert stays suppressed")

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
    apex, leads = _mine(_domain_pivot(reverse_whois_current=few))
    ok({"one.example", "two.example", "three.example"} <= apex,
       "small registrant term: siblings seed")
    ok(not leads, "small registrant term: no lead")

    bulk = {"term": "reseller@example.com", "count": CS.MAX_WHOIS_SIBLINGS + 100,
            "domains": [f"b{i}.example" for i in range(10)]}   # count > returned page
    apex, leads = _mine(_domain_pivot(reverse_whois_historic=bulk))
    ok(not apex, "bulk registrant term: siblings do NOT seed (count, not page size, decides)")
    ok(any(l["check"] == "bulk registrant term" for l in leads), "bulk term: raised as lead")

    privacy = {"term": "registry-abuse@cloudflare.com", "count": 2,
               "domains": ["p1.example", "p2.example"]}
    apex, leads = _mine(_domain_pivot(reverse_whois_current=privacy))
    ok(not apex, "privacy/registrar-abuse term: never seeds even when the count is small")
    ok(any(l["check"] == "bulk registrant term" for l in leads), "privacy term: raised as lead")

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

    return passed, failed, out


if __name__ == "__main__":
    p, f, lines = check()
    for s, l in lines:
        print(f"  {'ok ' if s == 'ok' else '✗  '} {l}")
    sys.exit(1 if f else 0)
