#!/usr/bin/env python3
"""
test_misconfig.py — the gate on the MISCONFIG TRIAGE layer (wp_recon.scan_misconfig, surfaced in
IPPivot as the `ip:misconfig` pivot).

Run:  python3 tests/test_misconfig.py
      python3 tools/eval/run_eval.py     (runs as part of the regression gate)

WHAT THIS PROTECTS
------------------
A FOFA/Shodan/Censys result sometimes carries the tell that a box is a MISCONFIGURED, operator-run
machine rather than hardened or CDN infrastructure. Two signals, both read PASSIVELY from an index
that already holds the banner — no packet is ever sent:

  * INTERNAL-IP LEAK. An RFC1918 / loopback / link-local address surfacing in a public result's
    ip / host / banner means the box is dual-homed and exposing its internal topology (a redirect
    Location, a self-signed cert SAN, a config echo). The scan must catch it WHEREVER it appears —
    including inside a free-text banner — and must NOT fire on the ordinary public address the row
    is actually about.
  * ANONYMOUS FTP. An FTP banner granting anonymous login is a high-value triage lead. The scan
    must recognise the service (protocol / port 21 / a 220 greeting) AND an anon-login success
    banner, and must NOT flag an FTP box that refused anonymous access.

Two failure modes this gate exists to prevent:
  * A FALSE LEAK — flagging the row's own public IP, or a public address, as "internal" — which
    would send an analyst chasing a leak that isn't there.
  * A SILENT DROP — the tunable markers/classes coming from the embedded fallback instead of the
    JSON, which narrows what is recognised without saying so (contributor RULE 3). And the whole
    capability must be reachable through the typed surface, not only a raw python3 line (RULE 2).

Everything here is OFFLINE — scan_misconfig is a pure function over result rows. No network, no
credentials, no case data (contributor RULE 1).
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "WebPivot", "tools"))

import wp_recon as R  # noqa: E402


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

    def kinds(findings):
        return {f["type"] for f in findings}

    # --- 1. reference data is real, documented, and actually loaded (RULE 3) ------------------
    ref = os.path.join(ROOT, "WebPivot", "references", "misconfig_signals.json")
    ok(os.path.exists(ref), "references/misconfig_signals.json ships with the layer")
    raw = json.load(open(ref, encoding="utf-8"))
    ok(raw.get("_comment"), "the reference file documents itself at the top")
    ok(all(g.get("_comment") for k, g in raw.items()
           if isinstance(g, dict) and not k.startswith("_")),
       "every group in the reference file carries its own _comment")
    ok(len(R.ANON_FTP_MARKERS) > len(R._MISCONFIG_FALLBACK["anon_ftp_markers"]),
       "the loaded anon-FTP markers are the JSON's, not the embedded fallback")

    # --- 2. INTERNAL-IP LEAK in an explicit host field ---------------------------------------
    f = R.scan_misconfig([{"ip": "203.0.113.9", "port": "8080", "host": "192.168.1.10"}],
                         self_ip="203.0.113.9")
    leak = [x for x in f if x["type"] == "internal_ip_leak"]
    ok(len(leak) == 1 and leak[0]["address"] == "192.168.1.10",
       "an RFC1918 address in the host field is flagged as an internal leak")
    ok(leak and leak[0]["leak_class"] == "private", "the leak is classed 'private'")

    # --- 3. INTERNAL-IP LEAK hidden inside a free-text banner (a redirect Location) -----------
    f = R.scan_misconfig([{"ip": "203.0.113.9", "port": "80",
                           "banner": "HTTP/1.1 302 Found\r\nLocation: http://10.8.0.5/panel\r\n"}],
                         self_ip="203.0.113.9")
    leak = [x for x in f if x["type"] == "internal_ip_leak"]
    ok(len(leak) == 1 and leak[0]["address"] == "10.8.0.5",
       "an RFC1918 literal inside a banner (redirect Location) is caught")
    ok(leak and leak[0]["field"] == "banner" and "10.8.0.5" in leak[0].get("excerpt", ""),
       "a banner-sourced leak carries the excerpt so the analyst sees the context")

    # --- 4. loopback + link-local are leaks; a public address never is ------------------------
    ok(R.scan_misconfig([{"ip": "203.0.113.9", "host": "127.0.0.1"}], self_ip="203.0.113.9"),
       "127.0.0.1 (loopback) is a leak")
    ok(R.scan_misconfig([{"ip": "203.0.113.9", "host": "169.254.10.10"}], self_ip="203.0.113.9"),
       "169.254.x (link-local) is a leak")
    ok(not R.scan_misconfig([{"ip": "8.8.8.8", "port": "443", "host": "dns.google"}]),
       "a purely public row yields NOTHING (no false leak)")
    ok(not R.scan_misconfig([{"ip": "192.168.1.10", "port": "80"}], self_ip="192.168.1.10"),
       "the row's OWN address (self_ip) is never reported as a leak against itself")

    # --- 5. CGNAT is OFF by default (100.64/10 is often legitimately public) ------------------
    ok(not R.scan_misconfig([{"ip": "203.0.113.9", "host": "100.64.0.5"}], self_ip="203.0.113.9"),
       "100.64/10 (CGNAT) is NOT flagged while leak_classes.cgnat is false")

    # --- 6. ANONYMOUS FTP — recognise the service AND the anon-login success banner -----------
    f = R.scan_misconfig([{"ip": "203.0.113.9", "port": "21", "protocol": "ftp",
                           "banner": "220 FTP ready\r\n230 Anonymous access granted."}])
    anon = [x for x in f if x["type"] == "anon_ftp"]
    ok(len(anon) == 1 and anon[0]["port"] == "21", "an anon-login FTP banner is flagged")
    ok(anon and "230 anonymous" in anon[0].get("excerpt", "").lower(),
       "the anon-FTP finding carries the banner excerpt")
    # an FTP box that refused anonymous login is NOT flagged
    ok("anon_ftp" not in kinds(R.scan_misconfig(
        [{"ip": "203.0.113.9", "port": "21", "protocol": "ftp",
          "banner": "220 FTP ready\r\n530 Login incorrect."}])),
       "an FTP box that REFUSED anonymous access is not flagged")
    # a non-FTP 230 in some other protocol's banner must not be mistaken for anon FTP
    ok("anon_ftp" not in kinds(R.scan_misconfig(
        [{"ip": "203.0.113.9", "port": "443", "protocol": "https",
          "banner": "HTTP/1.1 230 whatever"}])),
       "a 230 in a non-FTP service is not mistaken for anonymous FTP")

    # --- 7. dedupe — the same leak across many rows collapses to one finding ------------------
    rows = [{"ip": "203.0.113.9", "port": "80", "host": "10.0.0.1"} for _ in range(5)]
    ok(len(R.scan_misconfig(rows, self_ip="203.0.113.9")) == 1,
       "the same (address, port) leak seen on five rows is one finding, not five")

    # --- 8. robustness — junk rows never raise ------------------------------------------------
    try:
        R.scan_misconfig([None, {}, {"ip": "not-an-ip"}, {"banner": None}, "garbage"])
        ok(True, "malformed rows are skipped without raising")
    except Exception as e:
        ok(False, f"malformed rows raised: {e}")

    # --- 9. IPPivot surfaces it as the ip:misconfig pivot (integration, no network) -----------
    import wp_ippivot as IP  # noqa: E402
    # build_ip_result is network-heavy; assert the wiring exists instead of running it.
    src = open(os.path.join(ROOT, "WebPivot", "tools", "wp_ippivot.py"), encoding="utf-8").read()
    ok("scan_misconfig" in src and 'fields="ip,port,protocol,host,domain,title,server,banner"' in src,
       "fofa_ip requests the banner field and runs scan_misconfig on the rows")
    ok('add("ip:misconfig"' in src and "never auto-connects" in src,
       "build_ip_result emits an ip:misconfig pivot carrying the DON'T-auto-connect rule")
    ok("scan_misconfig" in IP.__dict__ or hasattr(IP, "scan_misconfig"),
       "scan_misconfig is importable into the IPPivot module")

    # --- 10. RULE 2: the capability is reachable on the typed surface -------------------------
    reg = open(os.path.join(ROOT, "harness", "tools.py"), encoding="utf-8").read()
    ok("ip:misconfig" in reg and "ANONYMOUS-FTP" in reg,
       "the pivot_extract (IPPivot) tool description documents the misconfig/anon-FTP signal")

    return passed, failed, out


def main():
    passed, failed, lines = check()
    for status, label in lines:
        print(f"  {'ok  ' if status == 'ok' else 'FAIL'} {label}")
    print(f"\n{'PASS' if not failed else 'FAIL'} — {passed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
