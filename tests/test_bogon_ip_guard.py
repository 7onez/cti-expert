#!/usr/bin/env python3
"""Regression: a bogon live IP (loopback/private/link-local/reserved/multicast/unspecified —
e.g. a registrar-parking A record of 127.0.0.1) must classify as 'bogon' — even when the
CDN-range cache (scripts/webpivot/cdn_ranges.json) has never been fetched — and enrich_live must
never spend a reverse-IP call resolving one: not DNSLytics reverse-IP, not FOFA ip=, not
Validin IP reputation, not IPinfo, not the MO-neighbours fan-out (Netlas rides inside the
MO-neighbours call and is covered transitively).

Run:  python3 tests/test_bogon_ip_guard.py
Fully offline: every vendor call is stubbed; no network, no metered calls.
Synthetic data only: site-a.example, RFC 1918/3927/1112 bogon addresses, and the well-known
public constant 8.8.8.8 (Google DNS) as the one genuinely non-bogon control value.
"""
import os
import sys
import tempfile

os.environ.setdefault("API_USAGE_LOG", os.path.join(tempfile.gettempdir(), "cti-tests-api_usage.jsonl"))

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
WP = os.path.join(ROOT, "intel_engine", "WebPivot", "tools")
if WP not in sys.path:
    sys.path.insert(0, WP)


def test_classify_ip_flags_every_bogon_class():
    import wp_analyze as WA
    for ip in ("127.0.0.1", "10.1.2.3", "192.168.1.1", "169.254.1.1", "0.0.0.0", "224.0.0.1"):
        c = WA.classify_ip(ip)
        assert c.get("kind") == "bogon" and c.get("cdn") is False, (ip, c)
    # 8.8.8.8 (Google public DNS) — a generic, globally-routable public constant, not case
    # data — must never be flagged bogon: it is real, reachable internet infrastructure.
    real = WA.classify_ip("8.8.8.8")
    assert real.get("kind") != "bogon", real


def test_enrich_live_never_reverses_a_bogon_origin():
    import wp_analyze as WA
    import wp_ippivot
    import wp_capabilities

    calls = {"validin_ip": 0, "dnslytics": 0, "fofa": 0, "ipinfo": 0, "mo": 0}

    saved_fns = {"resolve_live_dns": WA.resolve_live_dns, "ct_search": WA.ct_search,
                 "passivedns_search": WA.passivedns_search, "urlscan_search": WA.urlscan_search,
                 "fofa_search": WA.fofa_search, "_mo_neighbours": WA._mo_neighbours}
    gates = [(WA, "censys_configured"), (WA, "hunterhow_configured"),
             (WA.wp_quake, "quake_configured"), (WA.wp_zoomeye, "zoomeye_configured"),
             (WA.wp_pssl, "pssl_configured"), (WA.wp_cld, "cld_configured"),
             (WA.wp_webamon, "webamon_configured"), (WA.wp_securitytrails, "securitytrails_configured")]
    saved_gates = [(m, n, getattr(m, n)) for m, n in gates]
    for m, n in gates:
        setattr(m, n, lambda: False)

    saved_validin = {n: getattr(WA.wp_validin, n) for n in
                     ("validin_configured", "domain_lookup", "subdomains", "reputation", "ip_reputation")}
    saved_dnslytics = {n: getattr(WA.wp_dnslytics, n) for n in ("dnslytics_configured", "reverse_ip")}
    saved_whois_configured = WA.whois_enrich.whois_configured

    env_keys = {"FOFA_KEY", "FOFA_API_KEY", "PDNS_USERNAME", "PDNS_PASSWORD",
                "WHOISXML_API_KEY", "WHOISXMLAPI_KEY", "WHOIS_API_KEY", "CENSYS_PAT", "CENSYS_API_KEY"}
    for row in wp_capabilities.key_status():
        env_keys.add(row["env"])
        env_keys.update(row.get("aliases") or [])
        env_keys.update(row.get("companion") or [])
        env_keys.update(row.get("requires") or [])
    saved_env = {k: os.environ.pop(k, None) for k in sorted(env_keys)}

    saved_ipinfo_lookup = wp_ippivot.ipinfo_lookup
    try:
        # keyless base jobs — never touch the network
        WA.resolve_live_dns = lambda h, **k: {"ips": ["127.0.0.1"], "ns": []}
        WA.ct_search = lambda h, **k: {}
        WA.passivedns_search = lambda h, **k: {}
        WA.urlscan_search = lambda q, **k: {"domains": []}
        # FOFA / Validin / DNSLytics / MO-neighbours / IPinfo: CONFIGURED (so the bogon guard,
        # not a missing key, is what stops them), every actual network call stubbed + counted.
        os.environ["FOFA_KEY"] = "test-key"
        WA.fofa_search = lambda *a, **k: calls.__setitem__("fofa", calls["fofa"] + 1) or {}
        WA.wp_validin.validin_configured = lambda: True
        WA.wp_validin.domain_lookup = lambda h: {}
        WA.wp_validin.subdomains = lambda h: {}
        WA.wp_validin.reputation = lambda h: {}
        WA.wp_validin.ip_reputation = lambda ip: calls.__setitem__(
            "validin_ip", calls["validin_ip"] + 1) or {}
        WA.wp_dnslytics.dnslytics_configured = lambda: True
        WA.wp_dnslytics.reverse_ip = lambda ip: calls.__setitem__(
            "dnslytics", calls["dnslytics"] + 1) or {}
        WA.whois_enrich.whois_configured = lambda: True
        WA._mo_neighbours = lambda *a, **k: calls.__setitem__("mo", calls["mo"] + 1) or {}
        wp_ippivot.ipinfo_lookup = lambda ip: calls.__setitem__("ipinfo", calls["ipinfo"] + 1) or {}

        res = {"meta": {"host": "site-a.example"}, "artifacts": {},
               "pivots": [{"kind": "domain", "value": "site-a.example"}]}
        WA.enrich_live(res, free_only=False)
        lr = res["pivots"][0]["live_results"]
        assert lr["dns"]["ip_classification"][0]["kind"] == "bogon", lr.get("dns")
        assert calls["dnslytics"] == 0, calls
        assert calls["fofa"] == 0, calls
        assert calls["validin_ip"] == 0, calls
        assert calls["ipinfo"] == 0, calls
        assert calls["mo"] == 0, calls
        assert "dnslytics_reverseip" not in lr and "mo_neighbours" not in lr \
            and "fofa_ip_reverse" not in lr, lr
    finally:
        for k, v in saved_fns.items():
            setattr(WA, k, v)
        for m, n, v in saved_gates:
            setattr(m, n, v)
        for n, v in saved_validin.items():
            setattr(WA.wp_validin, n, v)
        for n, v in saved_dnslytics.items():
            setattr(WA.wp_dnslytics, n, v)
        WA.whois_enrich.whois_configured = saved_whois_configured
        wp_ippivot.ipinfo_lookup = saved_ipinfo_lookup
        for k, v in saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


_TESTS = [test_classify_ip_flags_every_bogon_class, test_enrich_live_never_reverses_a_bogon_origin]


def check():
    passed = failed = 0
    lines = []
    for test in _TESTS:
        label = test.__name__.removeprefix("test_").replace("_", " ")
        try:
            test()
        except Exception as exc:  # noqa: BLE001
            failed += 1
            lines.append(("FAIL", f"{label}: {exc}"))
        else:
            passed += 1
            lines.append(("ok", label))
    return passed, failed, lines


if __name__ == "__main__":
    _passed, _failed, _lines = check()
    for _status, _label in _lines:
        print(("ok" if _status == "ok" else "FAIL") + "  " + _label)
    raise SystemExit(bool(_failed))
