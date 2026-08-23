#!/usr/bin/env python3
"""
test_pssl.py — the gate on the PASSIVE SSL layer (WebPivot/tools/wp_pssl.py).

Run:  python3 tests/test_pssl.py
      python3 tools/eval/run_eval.py     (runs as part of the regression gate)

WHAT THIS PROTECTS
------------------
Passive SSL answers cert -> IP, which is how an origin is recovered from behind a CDN. It is also
the single most dangerous clustering source in the toolkit, because the same question asked about
a SHARED certificate returns a CDN's entire customer list:

  * A CDN CERTIFICATE BECOMING AN "ESTATE". A Cloudflare/DigiCert edge certificate is served by
    hundreds or thousands of unrelated addresses (915 in live measurement). If `clusterable` ever
    returns true for one of those, the layer manufactures an operator estate out of a CDN's
    tenant list — the most convincing false positive this repo could produce. The threshold and
    the subject markers are DATA, and both must be enforced.
  * AN EMPTY ANSWER READ AS A NEGATIVE FINDING. CIRCL's coverage is Europe-weighted; an empty
    result for a Vietnamese or small-ISP address is routine and means the corpus never saw it.
    "Asked and found nothing" and "never asked" must stay distinguishable in the output.
  * A SILENT DEPENDENCE ON A LIVE HANDSHAKE. The layer is sha1-keyed while the rest of the
    toolkit is sha256-keyed; the sha1 must come from the DER bytes the TLS probe already read,
    not from an extra connection to hostile infrastructure.
  * AN UNREGISTERED CAPABILITY. Contributor RULE 2: a new capability must be reachable through
    the one typed surface (harness/tools.py), not only as a raw python3 line.

Everything here is OFFLINE — the HTTP layer is monkeypatched. No network, no credentials, no case
data (contributor RULE 1).
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "WebPivot", "tools"))

import wp_pssl as P  # noqa: E402


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

    # --- 1. the reference data is real, documented, and actually loaded --------------------
    ref = os.path.join(ROOT, "WebPivot", "references", "pssl.json")
    ok(os.path.exists(ref), "references/pssl.json ships with the layer")
    raw = json.load(open(ref, encoding="utf-8"))
    ok(raw.get("_comment"), "the reference file documents itself at the top")
    ok(all(g.get("_comment") for k, g in raw.items()
           if isinstance(g, dict) and not k.startswith("_")),
       "every group in the reference file carries its own _comment")
    ok(P.POLICY.get("max_ips_per_cert") == raw["clustering_policy"]["max_ips_per_cert"],
       "the loaded policy is the JSON's, not the embedded fallback")

    # --- 2. THE SAFETY RAIL: a shared/CDN certificate can never become an operator edge -----
    saved = P._get
    try:
        # a) over-prevalent certificate — a CDN edge cert on 900 addresses
        P._get = lambda path, action, query: ({"seen": [f"10.0.{i // 256}.{i % 256}"
                                                        for i in range(900)]}, None)
        r = P.cert_ips("a" * 40)
        ok(r["count"] == 900, "every observed address is returned (nothing silently dropped)")
        ok(r["clusterable"] is False,
           "a certificate on 900 addresses is NOT clusterable (CDN customer list, not an estate)")
        ok("max_ips_per_cert" in r["why"], "the refusal names the threshold that fired")

        # b) a SMALL address set whose subject is a CDN wildcard — rejected on the subject alone
        P._get = lambda path, action, query: ({"seen": ["203.0.113.7", "203.0.113.8"]}, None)
        r = P.cert_ips("b" * 40, subject="CN=sni.cloudflaressl.com, O=Cloudflare, Inc.")
        ok(r["clusterable"] is False,
           "a CDN subject is rejected however few addresses carry it")
        ok("cloudflaressl.com" in r["why"], "the refusal names the marker that matched")

        # c) the legitimate case — a distinct leaf on a small, non-CDN address set
        r = P.cert_ips("c" * 40, subject="CN=example.com")
        ok(r["clusterable"] is True,
           "a distinct certificate on a small non-CDN address set IS clusterable")

        # d) a single address links nothing to anything, but is still reported
        P._get = lambda path, action, query: ({"seen": ["203.0.113.9"]}, None)
        r = P.cert_ips("d" * 40, subject="CN=example.com")
        ok(r["clusterable"] is False and r["count"] == 1,
           "a cert on ONE address is reported but is not an edge (min_ips_for_edge)")

        # --- 3. an empty answer is ABSENCE OF RECORD, never a negative finding -------------
        P._get = lambda path, action, query: ({}, None)
        r = P.cert_ips("e" * 40)
        ok(r["count"] == 0 and r["clusterable"] is False, "an empty corpus answer yields no edge")
        ok("ABSENCE OF RECORD" in r["why"].upper() or "not evidence" in r["why"].lower(),
           "an empty result states that it is absence of RECORD, not absence of certificates")
        ip = P.ip_certificates("203.0.113.10")
        ok(ip["count"] == 0 and "not evidence" in (ip["note"] or "").lower(),
           "an empty IP answer carries the same disclaimer")

        # --- 4. origin recovery: the host's own CDN addresses are excluded -----------------
        P._get = lambda path, action, query: (
            {"seen": ["104.21.19.225", "172.67.190.109", "45.61.2.7"]}, None)
        o = P.origin_candidates("site-a.example", sha1="f" * 40,
                                known_ips=["104.21.19.225", "172.67.190.109"])
        ok(o["origin_candidates"] == ["45.61.2.7"],
           "an address serving the cert but absent from live DNS is the ORIGIN CANDIDATE")
        ok("verify" in (o["note"] or "").lower(),
           "the result says the candidate must be verified before it is called the origin")
        o2 = P.origin_candidates("site-a.example", sha1="f" * 40,
                                 known_ips=["104.21.19.225", "172.67.190.109", "45.61.2.7"])
        ok(o2["origin_candidates"] == [] and "no origin recovered" in (o2["note"] or "").lower(),
           "when every address is already the front, it says so rather than inventing a candidate")

        # --- 5. pivots: policy decided once, and honoured by the emitter -------------------
        piv = P.pssl_pivots("site-a.example", o)
        kinds = {p["kind"] for p in piv}
        ok("pssl:origin_candidate" in kinds, "an origin candidate becomes its own pivot")
        cand = [p for p in piv if p["kind"] == "pssl:origin_candidate"][0]
        ok(any(q["service"] == "Shodan" for q in cand["queries"]),
           "the origin candidate ships ready-to-run reverse queries")
        shared = dict(o)
        shared["clusterable"] = False
        kinds2 = {p["kind"] for p in P.pssl_pivots("site-a.example", shared)}
        ok("pssl:cert_ip" not in kinds2 and "pssl:information" in kinds2,
           "a non-clusterable certificate is emitted as INFORMATION, never as a cert_ip edge")
    finally:
        P._get = saved

    # --- 6. budget guard and the never-block degradations ---------------------------------
    b = P.budget_status()
    ok(b["max_requests_per_run"] >= 1 and "remaining_this_run" in b,
       "the request budget is reportable offline")
    saved_enabled = P.ENABLED
    try:
        P.ENABLED = False
        r = P.cert_ips("a" * 40)
        ok(r.get("skipped") and "ui_url" in r,
           "a disabled layer returns a skipped payload with the UI address, never an exception")
    finally:
        P.ENABLED = saved_enabled

    # --- 7. sha1, not sha256 — and it comes from bytes the TLS probe already read ----------
    recon = open(os.path.join(ROOT, "WebPivot", "tools", "wp_recon.py"), encoding="utf-8").read()
    ok("fingerprint_sha1" in recon,
       "the TLS probe records a sha1 fingerprint (CIRCL passive SSL is sha1-keyed)")
    ok(recon.count("hashlib.sha1(der)") >= 2,
       "the sha1 is derived from the DER bytes already in hand, in both handshake paths — "
       "no extra connection to the target just to re-derive a hash")
    analyze = open(os.path.join(ROOT, "WebPivot", "tools", "wp_analyze.py"), encoding="utf-8").read()
    ok('_leaf.get("fingerprint_sha1")' in analyze,
       "the enrichment path feeds that stored sha1 into passive SSL")
    ok("wp_pssl.pssl_configured()" in analyze and "free_only" in analyze,
       "passive SSL is gated by credentials and skipped under --free-only")

    # --- 8. RULE 2: the capability is registered on the typed surface ----------------------
    reg = open(os.path.join(ROOT, "harness", "tools.py"), encoding="utf-8").read()
    ok('"passive_ssl"' in reg, "passive_ssl is registered as an @tool in harness/tools.py")
    ok("mcp__collect__passive_ssl" in reg, "it is exposed on the collect MCP surface")
    ok("passive_ssl," in reg, "it is included in the SDK server's tool list")
    pe = open(os.path.join(ROOT, "WebPivot", "tools", "pivot_extract.py"), encoding="utf-8").read()
    ok("--no-pssl" in pe, "pivot_extract exposes the opt-out flag")
    intel = open(os.path.join(ROOT, "tools", "intel.py"), encoding="utf-8").read()
    ok("--serp" in intel and "serp_region" in intel,
       "the case pipeline can reach the advertising layer (it previously could not)")
    ok("--no-pssl" in intel, "the case pipeline exposes the passive-SSL opt-out")

    return passed, failed, out


def main():
    passed, failed, lines = check()
    for status, label in lines:
        print(f"  {'ok  ' if status == 'ok' else 'FAIL'} {label}")
    print(f"\n{'PASS' if not failed else 'FAIL'} — {passed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
