#!/usr/bin/env python3
"""wp_ippivot.shodan_search — the cert-SHA1 / JARM reverse (premium-key plan, Phase 5 item 7C).

Contract: None without a key (no network); a Membership/credit refusal (401/402/403 or a body naming
membership/upgrade/credits) is a NAMED skip, never a failure; `{matches:[…]}` normalises to
{total, hosts[{ip,port,hostnames,org,asn,domains}], domains[]}; the client never raises; proxy-safe
(no custom opener); wp_analyze wires it at the cert-SHA1 and JARM pivots behind `have_shodan`
(`and not free_only`). Everything here is offline — urlopen is stubbed, every key popped."""
import io
import json
import os
import sys
import tempfile
import urllib.error
import urllib.request

os.environ.setdefault("API_USAGE_LOG", os.path.join(tempfile.gettempdir(), "cti-tests-api_usage.jsonl"))
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "intel_engine", "WebPivot", "tools"))

import wp_ippivot as ip  # noqa: E402

FAILURES = []


def check(label, cond, detail=""):
    if cond:
        print("  ok   " + label)
    else:
        print("  FAIL " + label + (" " + str(detail) if detail else ""))
        FAILURES.append(label)


_saved_env = {k: os.environ.pop(k, None) for k in ("SHODAN_KEY", "SHODAN_API_KEY")}
_saved_urlopen = urllib.request.urlopen
_saved_usage = ip.api_usage
ip.api_usage = None                                   # mocked calls never ledger
try:
    urllib.request.urlopen = lambda *a, **k: (_ for _ in ()).throw(AssertionError("network reached keyless"))
    check("keyless -> None, no network", ip.shodan_search("ssl.jarm:abc") is None)
    check("shodan_configured() False keyless", ip.shodan_configured() is False)
    os.environ["SHODAN_KEY"] = "test-key-not-real"
    check("shodan_configured() True with a key", ip.shodan_configured() is True)
    check("empty query -> error dict, no call", "error" in ip.shodan_search(""))

    body = {"total": 3, "matches": [
        {"ip_str": "198.51.100.7", "port": 443, "hostnames": ["Kit.Example", "www.kit.example"], "org": "ExampleHost", "asn": "AS64496", "domains": ["kit.example"]},
        {"ip_str": "198.51.100.9", "port": 8443, "hostnames": [], "org": None, "asn": None, "domains": ["twin.example"]},
        "garbage-row"]}
    seen = {}
    urllib.request.urlopen = lambda req, timeout=25: (seen.setdefault("url", req.full_url), io.BytesIO(json.dumps(body).encode()))[1]
    r = ip.shodan_search("ssl.cert.fingerprint:" + "a" * 40)
    check("normalises matches -> total + hosts + deduped domains",
          r["total"] == 3 and len(r["hosts"]) == 2 and r["domains"] == ["kit.example", "www.kit.example", "twin.example"], detail=str(r)[:200])
    check("hostnames lowercased; port/org/asn carried", r["hosts"][0]["hostnames"] == ["kit.example", "www.kit.example"] and r["hosts"][0]["port"] == 443 and r["hosts"][0]["asn"] == "AS64496")
    check("hits /shodan/host/search with minify", "/shodan/host/search?" in seen["url"] and "minify=true" in seen["url"])
    check("key never appears in the result", "test-key-not-real" not in json.dumps(r))

    def _http(code, text):
        def _f(req, timeout=25):
            raise urllib.error.HTTPError(req.full_url, code, "x", {}, io.BytesIO(text.encode()))
        return _f
    urllib.request.urlopen = _http(402, '{"error": "Requires membership or higher to access"}')
    r = ip.shodan_search("ssl.jarm:abc")
    check("402 membership -> named skip, not error", r.get("skipped") and "Membership" in r["skipped"] and r["http"] == 402, detail=str(r))
    urllib.request.urlopen = _http(401, '{"error": "Invalid API key"}')
    check("401 -> skip (entitlement/auth class)", "skipped" in ip.shodan_search("ssl.jarm:abc"))
    urllib.request.urlopen = _http(500, "boom")
    check("500 -> error dict, no raise", "error" in ip.shodan_search("ssl.jarm:abc"))
    urllib.request.urlopen = lambda *a, **k: (_ for _ in ()).throw(TimeoutError("slow"))
    check("transport exception -> error dict, no raise", "error" in ip.shodan_search("ssl.jarm:abc"))
    src = open(ip.__file__, encoding="utf-8").read()
    check("proxy-safe: no custom opener in wp_ippivot", "build_opener(" not in src and "install_opener(" not in src)
    an = open(os.path.join(ROOT, "intel_engine", "WebPivot", "tools", "wp_analyze.py"), encoding="utf-8").read()
    check("wp_analyze gates Shodan search `and not free_only`", "have_shodan = _shodan_configured() and not free_only" in an)
    check("…wired at the cert SHA1 pivot and the JARM pivot",
          'have_shodan and kind == "tls_cert:fingerprint_sha256"' in an and 'have_shodan and kind == "jarm:hash"' in an)
    check("…through a never-raise wrapper", "def _shodan_search(query: str):" in an)
finally:
    urllib.request.urlopen = _saved_urlopen
    ip.api_usage = _saved_usage
    for k, v in _saved_env.items():
        os.environ.pop(k, None)
        if v is not None:
            os.environ[k] = v

if FAILURES:
    print(f"\nFAIL — {len(FAILURES)} check(s) failed:")
    for f in FAILURES:
        print("  -", f)
    raise SystemExit(1)
print("\nPASS — Shodan search checks green")


def test_shodan_search():
    assert not FAILURES, FAILURES
