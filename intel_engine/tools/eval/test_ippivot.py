#!/usr/bin/env python3
"""Offline unit gate for WebPivot's IPPivot (wp_ippivot).

The live lookups (IPinfo / FOFA / Shodan / dig) need network and are asserted in a smoke test;
the PURE decision logic gated here is what keeps IP recon honest: bare-IP detection, ASN parsing,
noise classification (CDN edge / hosting / registry flag → INFORMATION, origin candidate → pivot),
generic-only ASN-registry writes (opsec), and MX/mail parsing. Run standalone or via run_eval.py.
"""
import os
import sys
import json
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))), "WebPivot", "tools"))
import wp_ippivot as ip  # noqa: E402
import wp_recon as rec  # noqa: E402


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

    # --- bare-IP detection ---
    ok(ip.ip_mode_target("1.2.3.4") == "1.2.3.4", "IPv4 detected")
    ok(ip.ip_mode_target("[2001:db8::1]") == "2001:db8::1", "bracketed IPv6 detected")
    ok(ip.ip_mode_target("ip://8.8.8.8") == "8.8.8.8", "scheme stripped")
    ok(ip.ip_mode_target("example.com") is None, "hostname → not IP mode")
    ok(ip.ip_mode_target("https://example.com/x") is None, "URL → not IP mode")

    # --- ASN parse ---
    ok(ip._asn_from_org("AS13335 Cloudflare, Inc.") == ("AS13335", "Cloudflare, Inc."), "ASN parsed")
    ok(ip._asn_from_org("") == (None, None), "empty org safe")

    # --- noise classification ---
    reg = {"asns": {"AS99999": {"noise": True, "name": "NoiseHost"}}}
    ok(ip.is_noise_provider({"cdn": True, "provider": "CF"}, {}, reg)[0] is True, "CDN edge = noise")
    ok(ip.is_noise_provider({"cdn": False}, {"asn": "AS99999"}, reg)[0] is True, "registry ASN = noise")
    ok(ip.is_noise_provider({"cdn": False}, {"asn": "AS1", "is_hosting": True}, reg)[0] is True,
       "IPinfo hosting flag = noise")
    ok(ip.is_noise_provider({"cdn": False}, {"asn": "AS1"}, reg)[0] is False, "origin candidate")
    ok(ip.is_noise_provider({"cdn": False}, {"asn": "AS1"}, reg, tenant_total=5000)[0] is True,
       "shared host / LB (high tenant count) = noise")
    ok(ip.is_noise_provider({"cdn": False}, {"asn": "AS1"}, reg, tenant_total=8)[0] is False,
       "dedicated origin (few tenants) stays origin")

    # --- ASN registry upsert writes generic facts only, never target/case ---
    tf = tempfile.mktemp(suffix=".json")
    with open(tf, "w") as f:
        f.write('{"asns":{}}')
    ip.asn_registry_upsert("AS4242", name="TestHost", abuse=["abuse@test.example"],
                           noise=True, kind="hosting", path=tf)
    blob = open(tf).read()
    e = json.loads(blob)["asns"]["AS4242"]
    ok(e.get("noise") is True and e.get("name") == "TestHost"
       and e.get("abuse_contacts") == ["abuse@test.example"], "registry stores provider facts")
    ok("1.2.3.4" not in blob and "CASE" not in blob and "case" not in blob,
       "registry never leaks target/case")
    os.unlink(tf)

    # --- mail parsing (monkeypatch dns_records) ---
    _orig = ip.dns_records
    try:
        ip.dns_records = lambda name, types=(): (
            {"MX": ["10 mail.operator.example", "20 mail2.operator.example"]} if types == ("MX",)
            else {"TXT": ["v=spf1 ~all"]} if (types == ("TXT",) and not name.startswith("_dmarc"))
            else {"TXT": ["v=DMARC1; p=reject"]} if name.startswith("_dmarc") else {})
        m = ip.mail_intel("operator.example")
        ok(m["mx"] == ["mail.operator.example", "mail2.operator.example"], "MX priority stripped")
        ok(m["mail_domains"] == ["operator.example"], "mail domain extracted")
        ok(m["managed"] is False, "self-hosted MX not managed")
        ok(bool(m["spf"]) and bool(m["dmarc"]), "SPF + DMARC extracted")
        ip.dns_records = lambda name, types=(): ({"MX": ["1 aspmx.l.google.com"]}
                                                 if types == ("MX",) else {})
        ok(ip.mail_intel("victim.example")["managed"] is True, "managed provider MX flagged")
    finally:
        ip.dns_records = _orig

    # --- SPF / DMARC parsers (wp_recon, pure — no network) ---
    spf = rec.parse_spf(["v=spf1 include:_spf.google.com include:mail.op.example "
                         "ip4:203.0.113.5 ip4:198.51.100.0/24 -all"])
    ok(bool(spf) and "mail.op.example" in spf["includes"] and "203.0.113.5" in spf["ip4"]
       and spf["all"] == "-all", "SPF include/ip4/all parsed")
    ok(rec._classify_spf_include("_spf.google.com") == "ESP"
       and rec._classify_spf_include("mail.op.example") is None, "SPF ESP vs custom include")
    dm = rec.parse_dmarc(["v=DMARC1; p=reject; "
                          "rua=mailto:dmarc@op.example,mailto:x@dmarc.postmarkapp.com"])
    ok(bool(dm) and dm["p"] == "reject" and "dmarc@op.example" in dm["rua"],
       "DMARC policy + rua parsed")
    ok(rec.parse_spf(["not spf here"]) is None and rec.parse_dmarc([]) is None,
       "no SPF/DMARC record → None")

    # --- build_ip_result end-to-end (network fully mocked): origin vs noise ---
    saved = {n: getattr(ip, n) for n in ("ipinfo_lookup", "classify_ip", "asn_registry_load",
             "asn_registry_upsert", "fofa_ip", "shodan_host", "reverse_dns", "mail_intel")}
    try:
        ip.ipinfo_lookup = lambda x, **k: {"ip": x, "asn": "AS4242", "org_name": "AcmeHost",
            "hostname": "mail.op.example", "abuse": {"email": "abuse@acme.example"}, "is_hosting": False}
        ip.asn_registry_load = lambda p=None: {"asns": {}}
        ip.fofa_ip = lambda x, full=False: {"ports": ["80", "443"], "services": ["http/nginx"],
                                            "co_domains": ["site-a.example"]}
        ip.shodan_host = lambda x: None
        ip.reverse_dns = lambda x, **k: "mail.op.example"
        ip.mail_intel = lambda d: {"mx": ["mail.op.example"], "mail_domains": ["op.example"],
                                   "managed": False, "spf": None, "dmarc": None}
        _up = []
        ip.asn_registry_upsert = lambda *a, **k: _up.append((a, k)) or {}

        ip.classify_ip = lambda x: {"ip": x, "cdn": False, "provider": None, "kind": "origin_candidate"}
        r = ip.build_ip_result("203.0.113.7")
        ko = {p["kind"] for p in r["pivots"]}
        ok(r["meta"]["kind"] == "ip" and r["meta"]["host"] == "203.0.113.7", "IP result meta")
        ok("ip" in ko and "ip:information" not in ko, "origin → ip pivot, no information")
        ok(any(p["kind"] == "ip" and p.get("live_results", {}).get("co_hosted_domains")
               for p in r["pivots"]), "origin ip pivot carries co-hosted domains")
        ok({"ip:ports", "ip:asn", "ip:ptr", "ip:mx"} <= ko, "ports/asn/ptr/mx surfaced")

        ip.classify_ip = lambda x: {"ip": x, "cdn": True, "provider": "CF", "kind": "cdn"}
        r2 = ip.build_ip_result("198.51.100.9")
        k2 = {p["kind"] for p in r2["pivots"]}
        ok("ip:information" in k2 and "ip" not in k2, "noise → information, no ip pivot")
        ok(_up and _up[-1][1].get("noise") is True and _up[-1][1].get("reg") is not None,
           "noise banks ASN with reused registry")
    finally:
        for n, fn in saved.items():
            setattr(ip, n, fn)

    return passed, failed, out


if __name__ == "__main__":
    p, f, lines = check()
    for status, label in lines:
        print(f"  {'ok ' if status == 'ok' else '✗  '} {label}")
    print(f"\n{p}/{p + f} passed" + ("" if not f else f", {f} FAILED"))
    sys.exit(1 if f else 0)
