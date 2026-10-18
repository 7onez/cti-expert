#!/usr/bin/env python3
"""A Quarry import covers the queries it actually returned, and only those.

Collection must not spend the same vendor account on an equivalent query, and must still
spend on a query Quarry did not run. The proof is a counting urlopen stub: a covered call
never opens a connection; a different query on the same vendor does.
"""
import json
import os
import sys
import tempfile
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENGINE = os.path.join(ROOT, "intel_engine")
sys.path.insert(0, os.path.join(ENGINE, "tools"))
sys.path.insert(0, os.path.join(ENGINE, "WebPivot", "tools"))

import wp_quarry_reuse as qr                    # noqa: E402
import wp_recon                                 # noqa: E402
import wp_censys                                # noqa: E402
import whois_enrich                             # noqa: E402
import wp_securitytrails                        # noqa: E402
import wp_ippivot                               # noqa: E402
import wp_hunterhow                             # noqa: E402
import wp_analyze as WA                         # noqa: E402

_passed = _failed = 0
_lines = []
HOST = "reuse.example"
IP = "93.184.216.34"
FP = "ab" * 32
ICON = "-1256781000"


def ok(cond, label):
    global _passed, _failed
    if cond:
        _passed += 1
        _lines.append(("PASS", label))
    else:
        _failed += 1
        _lines.append(("FAIL", label))


class _Resp:
    def __init__(self, url):
        self.url = url
        self.headers = {}

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self, n=-1):
        return b'{"results":[],"matches":[],"total":0,"records":[]}'

    def geturl(self):
        return self.url


def _host(url):
    raw = getattr(url, "full_url", None) or str(url)
    return raw.split("/")[2] if "://" in raw else raw


def _bundle():
    return {"export": {"content": {
        "fofa": {
            "queries": [f'ip="{IP}"', f'domain="{HOST}"'],
            "hosts": [{"ip": IP, "host": "cohost.example", "title": "panel",
                       "port": 443, "protocol": "https"}],
        },
        "censys": {"certs": [{"fingerprint_sha256": FP,
                              "sans": [HOST, "sibling.example"]}],
                   "hosts": [{"ip": IP}]},
        "whois": {
            "whois_history": [{
                "created_date": "2024-01-15",
                "registrar": "Example Registrar",
                "registrant": {"email": "owner@example.com", "name": "Owner A",
                               "phone": "+15550100001"},
            }],
            "ns_history": [{"value": "ns1.example", "first_seen": "2024-01-15",
                            "last_seen": "2024-06-01"}],
            "mx_history": [{"value": "mx.example"}],
        },
        "ip_whois": {"results": [{"ip": IP, "provider": "ipinfo", "asn": "AS64500",
                                  "org": "Example Hosting", "country": "US"}]},
    }}}


def test_ledger_is_query_exact(case):
    path = qr.write_coverage(case, _bundle(), HOST)
    doc = json.load(open(path))
    keys = set(doc["queries"])
    ok(qr.fofa_key(f'ip="{IP}"') in keys, "covered FOFA IP query is recorded")
    ok(qr.censys_cert_key(FP) in keys, "covered Censys certificate is recorded")
    ok(qr.whois_history_key(HOST) in keys, "covered WhoisXML history is recorded")
    ok(qr.securitytrails_key(HOST, "ns") in keys, "covered NS history is recorded")
    ok(qr.ipinfo_key(IP) in keys, "covered IPinfo address is recorded")
    ok(not any(k.startswith("censys:webproperty:") for k in keys),
       "Censys hosts do not cover a web-property lookup")
    ok(qr.securitytrails_key(HOST, "a") not in keys, "NS history does not cover A history")
    ok(qr.fofa_key(f'icon_hash="{ICON}"') not in keys, "an icon_hash query is not covered")
    ok(not any(k.startswith("urlscan:") or k.startswith("shodan:") for k in keys),
       "urlscan and Shodan stay uncovered when the export has neither")


def test_calls(case):
    os.environ["WP_CASE_DIR"] = case
    calls = []
    real = urllib.request.urlopen

    def fake(url, *a, **k):
        calls.append(_host(url))
        return _Resp(url)

    urllib.request.urlopen = fake
    saved = {n: os.environ.get(n) for n in (
        "FOFA_KEY", "CENSYS_PAT", "WHOISXML_API_KEY", "SECURITYTRAILS_API_KEY",
        "SHODAN_API_KEY", "HUNTERHOW_API_KEY", "URLSCAN_API_KEY", "IPINFO_TOKEN")}
    os.environ.update({
        "FOFA_KEY": "test-key", "CENSYS_PAT": "test-key", "WHOISXML_API_KEY": "test-key",
        "SECURITYTRAILS_API_KEY": "test-key", "SHODAN_API_KEY": "test-key",
        "HUNTERHOW_API_KEY": "test-key", "URLSCAN_API_KEY": "test-key",
        "IPINFO_TOKEN": "test-key"})
    try:
        covered = wp_recon.fofa_search(f'domain="{HOST}"')
        ok(any((r.get("domain") or r.get("host")) == "cohost.example"
               for r in covered.get("results") or []),
           "reused FOFA result still lists the co-host")
        ok(covered.get("reused") == "quarry" and "fofa.info" not in calls,
           "equivalent FOFA query returns the stored result and does not call FOFA")
        before = list(calls)
        fresh = wp_recon.fofa_search(f'icon_hash="{ICON}"')
        ok(fresh.get("reused") != "quarry" and calls.count("fofa.info") == before.count("fofa.info") + 1,
           "a different FOFA query still calls FOFA")

        cert = wp_censys.censys_certificate(FP)
        ok(cert.get("reused") == "quarry" and "api.platform.censys.io" not in calls,
           "equivalent Censys certificate lookup does not call Censys")
        ok("sibling.example" in (cert.get("names") or []),
           "reused Censys certificate still lists its names")
        before = calls.count("api.platform.censys.io")
        prop = wp_censys.censys_webproperty(HOST)
        ok(prop.get("reused") != "quarry"
           and calls.count("api.platform.censys.io") == before + 1,
           "Censys web-property is not covered by a certificate result and still calls")

        hist = whois_enrich.whois_history(HOST)
        ok(hist.get("reused") == "quarry"
           and not any("whoisxml" in h for h in calls),
           "WhoisXML history already held by Quarry is not purchased again")
        ok(any(r.get("email") == "owner@example.com" for r in hist.get("records") or []),
           "reused WHOIS history still has the registrant record")
        ok(any("owner@example.com" in (e.get("emails") or []) for e in hist.get("eras") or []),
           "reused WHOIS history still splits into eras")

        ns = wp_securitytrails.dns_history(HOST, "ns")
        ok(ns.get("reused") == "quarry" and "api.securitytrails.com" not in calls,
           "covered NS history does not call SecurityTrails")
        ok(any(r.get("value") == "ns1.example" for r in ns.get("records") or []),
           "reused NS history still has the nameserver record")
        before = calls.count("api.securitytrails.com")
        a = wp_securitytrails.dns_history(HOST, "a")
        ok(a.get("reused") != "quarry" and calls.count("api.securitytrails.com") > before,
           "A history Quarry did not return still calls SecurityTrails")

        info = wp_ippivot.ipinfo_lookup(IP)
        ok(info.get("reused") == "quarry" and "ipinfo.io" not in calls,
           "covered IPinfo address does not call IPinfo")
        before = calls.count("ipinfo.io")
        other = wp_ippivot.ipinfo_lookup("198.51.100.9")
        ok(other.get("reused") != "quarry" and calls.count("ipinfo.io") == before + 1,
           "a different address still calls IPinfo")

        before = calls.count("urlscan.io")
        us = wp_recon.urlscan_search(f"domain:{HOST}")
        ok(us.get("reused") != "quarry" and calls.count("urlscan.io") == before + 1,
           "urlscan is not in the Quarry export, so the domain search still runs")
        before = calls.count("api.shodan.io")
        sh = wp_ippivot.shodan_search(f"ssl.cert.fingerprint:{FP[:40]}")
        ok(sh.get("reused") != "quarry" and calls.count("api.shodan.io") == before + 1,
           "Shodan is not in the Quarry export, so the search still runs")
        before = calls.count("api.hunter.how")
        hh = wp_hunterhow.search(f'domain="{HOST}"')
        ok(hh.get("reused") != "quarry" and calls.count("api.hunter.how") == before + 1,
           "Hunterhow is not in the Quarry export, so the search still runs")
    finally:
        urllib.request.urlopen = real
        for n, v in saved.items():
            if v is None:
                os.environ.pop(n, None)
            else:
                os.environ[n] = v


def test_enrich_live_skips_only_the_covered_query(case):
    os.environ["WP_CASE_DIR"] = case
    os.environ["FOFA_KEY"] = "test-key"
    os.environ["CENSYS_PAT"] = "test-key"
    calls = []
    real_open = urllib.request.urlopen
    saved_fns = {
        "resolve_live_dns": WA.resolve_live_dns,
        "ct_search": WA.ct_search,
        "passivedns_search": WA.passivedns_search,
        "classify_ip": WA.classify_ip,
        "_mo_neighbours": WA._mo_neighbours,
    }

    def fake(url, *a, **k):
        calls.append(_host(url))
        return _Resp(url)

    urllib.request.urlopen = fake
    WA.resolve_live_dns = lambda h, **k: {"ips": [IP], "ns": []}
    WA.ct_search = lambda h, **k: {}
    WA.passivedns_search = lambda h, **k: {}
    WA.classify_ip = lambda ip: {"ip": ip, "cdn": False, "kind": "origin_candidate", "provider": ""}
    WA._mo_neighbours = lambda *a, **k: {}
    try:
        result = WA.enrich_live({
            "meta": {"host": HOST},
            "artifacts": {"tls_cert": {"fingerprint_sha256": FP}},
            "pivots": [
                {"kind": "domain", "value": HOST},
                {"kind": "favicon_hash", "value": ICON},
                {"kind": "tls_cert:fingerprint_sha256", "value": FP},
            ],
        })
        domain = result["pivots"][0]["live_results"]
        cert = result["pivots"][2]["live_results"]
        ok((domain.get("fofa_ip_reverse") or {}).get("reused") == "quarry",
           "enrich_live reuses the Quarry FOFA IP reverse")
        ok(any((r.get("domain") or r.get("host")) == "cohost.example"
               for r in (domain.get("fofa_ip_reverse") or {}).get("results") or []),
           "enrich_live's reused FOFA reverse still lists the co-host")
        ok("sibling.example" in ((cert.get("censys_cert") or {}).get("names") or []),
           "enrich_live's reused certificate still lists its names")
        ok(calls.count("fofa.info") == 1,
           "enrich_live still calls FOFA once, for the uncovered icon_hash")
        ok((cert.get("censys_cert") or {}).get("reused") == "quarry",
           "enrich_live reuses the Quarry certificate lookup")
        censys = (result["pivots"][0].get("live_results") or {}).get("censys") or {}
        ok(censys.get("reused") != "quarry",
           "enrich_live does not treat a Censys web property as covered by a certificate")
    finally:
        urllib.request.urlopen = real_open
        for name, fn in saved_fns.items():
            setattr(WA, name, fn)


def check():
    with tempfile.TemporaryDirectory() as tmp:
        case = os.path.join(tmp, "CASE-0001")
        os.makedirs(case)
        prev = os.environ.get("WP_CASE_DIR")
        os.environ["API_USAGE_LOG"] = os.path.join(tmp, "api_usage.jsonl")
        try:
            test_ledger_is_query_exact(case)
            test_calls(case)
            test_enrich_live_skips_only_the_covered_query(case)
        finally:
            if prev is None:
                os.environ.pop("WP_CASE_DIR", None)
            else:
                os.environ["WP_CASE_DIR"] = prev
    return _passed, _failed, _lines


if __name__ == "__main__":
    passed, failed, lines = check()
    for status, label in lines:
        print(f"{status:>4}  {label}")
    print(f"\n{passed} passed, {failed} failed")
    raise SystemExit(bool(failed))
