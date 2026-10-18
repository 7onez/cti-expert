#!/usr/bin/env python3
"""Regression gate for the cert-pivot QUERY FORMS each engine actually answers.

What it defends (Quarry live checks, 2026-10):
  * FOFA `cert="<sha256>"` matches nothing, so cert_pivot emits `cert.sn="<decimal serial>"` —
    and only for a REAL x509 serial (the served leaf's DER, or a CT record backed by crt.sh /
    CertKit / Netlas). A record backed only by a surrogate-serial source (CertSpotter issuance id,
    CertIndex, Shodan CTL, Censys) yields NO FOFA query and no FOFA deep link, never a dead one.
  * a serial carrying a quote / backslash / control char is never embedded: the target controls
    its certificate fields, so `x" || ip="…` would otherwise rewrite the analyst's query.
  * hunter.how: `cert.subject="<domain>"` is the working cert form; a fingerprint or serial has no
    hunter.how field and yields None. The API window never starts more than 365 days back, and a
    "cannot exceed one year" refusal is retried once with the start a day later.
  * the impersonation FOFA keyword hunt asks `cert.subject="<label>"`, never the bare `cert=`.

Run:  python3 tests/test_cert_queries.py
Fully offline. Synthetic data only: *.example hosts, RFC 5737 addresses.
"""
import base64
import datetime
import io
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for p in (os.path.join(ROOT, "intel_engine", "WebPivot", "tools"), os.path.join(ROOT, "intel_engine", "tools"),
          os.path.join(ROOT, "scripts"), os.path.join(ROOT, "scripts", "webpivot")):
    if p not in sys.path:
        sys.path.insert(0, p)

import cert_pivot as CP  # noqa: E402
import wp_hunterhow as HH  # noqa: E402

SEED = "seed-brand.example.com"
LEAF = "ab" * 32
OTHER = "cd" * 32


def _tlv(tag, body):
    n = len(body)
    if n < 128:
        ln = bytes([n])
    else:
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        ln = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + ln + body


def _der(serial_bytes, v3=True, pad=0):
    """A synthetic certificate skeleton: only the fields before the serial are realistic."""
    tbs = (_tlv(0xA0, _tlv(0x02, b"\x02")) if v3 else b"") + _tlv(0x02, serial_bytes)
    tbs += _tlv(0x04, b"\x00" * pad)                    # stands in for the rest of the TBS
    return _tlv(0x30, _tlv(0x30, tbs) + _tlv(0x30, b"") + _tlv(0x03, b"\x00"))


# ------------------------------------------------------------------ FOFA serial conversion
def test_hex_serial_becomes_the_decimal_fofa_expects():
    assert CP.fofa_serial("0a:1b:2c") == str(0x0A1B2C)
    assert CP.fofa_serial("0A1B2C") == str(0x0A1B2C)
    # crt.sh may prefix a 20-byte serial with a 00 sign byte (42 hex chars) — still a real serial.
    assert CP.fofa_serial("00" + "f" * 40) == str(int("f" * 40, 16))
    assert CP.fofa_serial("1" + "0" * 40) == "", "a 21-byte serial is not an x509 serial"


def test_attacker_controlled_serial_never_reaches_the_query():
    for bad in ('1a" || ip="192.0.2.1', "1a\\", "1a\n", "1a\x00", "1a\x7f", "0x1a", "xyz", "", None, "00"):
        assert CP.fofa_serial(bad) == "", repr(bad)
    assert CP.fofa_cert_query('1" || ip="192.0.2.1') is None
    assert CP.fofa_cert_query("") is None


def test_leaf_serial_is_read_from_the_der():
    assert CP._der_serial(_der(b"\x0a\x1b\x2c")) == "0a1b2c"
    assert CP._der_serial(_der(b"\x00\xff\x01", v3=False)) == "00ff01", "v1 cert has no [0] version"
    assert CP._der_serial(_der(b"\x12\x34", pad=300)) == "1234", "long-form lengths decode"
    assert CP._der_serial(b"\x30\x03\x02\x01") == "" and CP._der_serial(b"") == ""


# ------------------------------------------------------------------ cert_pivot.run wiring
def _run(certs, **kw):
    saved = (CP.crtsh_history, CP.shodan_pivot, CP.censys_pivot)
    CP.crtsh_history = lambda d, cap=40: {"certs": certs, "san_siblings": [], "completeness": "full"}
    CP.shodan_pivot = lambda *a, **k: ([], None)
    CP.censys_pivot = lambda *a, **k: ([], None)
    try:
        return CP.run(domain=SEED, sha256=LEAF, passive=True, **kw)
    finally:
        CP.crtsh_history, CP.shodan_pivot, CP.censys_pivot = saved


def _fofa_links(r):
    return [base64.b64decode(l["url"].split("qbase64=")[1].split("&")[0]).decode()
            for l in r["passive_links"] if l["engine"] == "fofa_web"]


def _no_dead_cert_query(r):
    blob = json.dumps(r["queries"]) + json.dumps(_fofa_links(r))
    assert 'cert=\\"' not in blob, f"dead FOFA cert= query emitted: {blob}"


def test_surrogate_serial_certs_produce_no_fofa_query():
    certs = [{"sha256": LEAF, "serial_number": "77", "sources": ["certspotter"]},
             {"sha256": OTHER, "serial_number": "0a1b", "sources": ["certindex", "shodan-ctl", "censys"]}]
    r = _run(certs)
    assert "fofa" not in r["queries"] and not _fofa_links(r), r["queries"]
    assert any("FOFA cert pivot not emitted" in n for n in r["notes"]), r["notes"]
    assert r["queries"]["shodan"].endswith(LEAF), "fingerprint engines are unaffected"
    _no_dead_cert_query(r)


def test_real_serial_drives_fofa_cert_sn_and_the_deep_link():
    certs = [{"sha256": OTHER, "serial_number": "ff", "sources": ["crt.sh"]},
             {"sha256": LEAF, "serial_number": "0a:1b", "sources": ["certspotter", "crt.sh"]}]
    r = _run(certs)
    want = f'cert.sn="{0x0A1B}"'
    assert r["queries"]["fofa"] == want, "the pivoted fingerprint's own CT record wins"
    assert _fofa_links(r) == [want]
    assert r["fingerprints"]["serial_decimal"] == str(0x0A1B)
    _no_dead_cert_query(r)


def test_explicit_serial_rejects_injection_and_falls_back_to_ct():
    r = _run([{"sha256": LEAF, "serial_number": "1f", "sources": ["certkit"]}],
             x509_serial='1a" || ip="192.0.2.1')
    assert r["queries"]["fofa"] == 'cert.sn="31"', r["queries"]
    assert any("--serial rejected" in n for n in r["notes"])


# ------------------------------------------------------------------ hunter.how
def test_hunterhow_cert_kind_uses_cert_subject_and_skips_hashes():
    assert HH.query_for("cert", "shop.example.com") == 'cert.subject="shop.example.com"'
    assert HH.query_for("cert_subject", "Example Org") == 'cert.subject="Example Org"'
    for kind, val in (("cert", LEAF), ("cert", "0a:1b:2c:3d:4e:5f:60:71"), ("cert_sha256", LEAF),
                      ("cert_serial", "0a1b"), ("cert_sha1", "ab" * 20)):
        assert HH.query_for(kind, val) is None, (kind, val)
    piv = [{"kind": "cert_sha256", "value": LEAF, "queries": []}]
    assert HH.attach_hunterhow_queries(piv)[0]["queries"] == []


def test_hunterhow_window_never_exceeds_365_days():
    today = datetime.date.today()
    floor = (today - datetime.timedelta(days=365)).isoformat()
    assert HH._window(9999)[0] == floor
    assert HH._window(30, start="2000-01-01")[0] == floor, "an explicit old start is clamped"
    assert HH._window(30, start="not-a-date")[0] == (today - datetime.timedelta(days=30)).isoformat()


def test_hunterhow_retries_once_when_the_api_calls_the_start_too_old():
    import wp_quarry_reuse as QR
    calls = []

    def fake_urlopen(req, timeout=None):
        calls.append(req.full_url)
        body = ({"code": 400, "message": "The interval between the start time and end time cannot "
                                         "exceed one year"} if len(calls) == 1 else
                {"code": 200, "data": {"total": 1, "list": [{"domain": "a.example", "ip": "192.0.2.5",
                                                               "port": 443}]}})
        return io.BytesIO(json.dumps(body).encode())

    saved = (HH.urllib.request.urlopen, HH.hunterhow_key, HH.api_usage, QR.get)
    HH.urllib.request.urlopen, HH.hunterhow_key, HH.api_usage = fake_urlopen, (lambda: "k"), None
    QR.get = lambda *a, **k: None
    try:
        out = HH.search('cert.subject="a.example"', days=365)
    finally:
        HH.urllib.request.urlopen, HH.hunterhow_key, HH.api_usage, QR.get = saved
    shifted = (datetime.date.today() - datetime.timedelta(days=364)).isoformat()
    assert len(calls) == 2 and out["code"] == 200 and out["hosts"][0]["ip"] == "192.0.2.5", out
    assert out["window"][0] == shifted and f"start_time={shifted}" in calls[1]


# ------------------------------------------------------------------ impersonation hunt
def test_impersonation_fofa_hunt_asks_cert_subject():
    import wp_impersonate as IMP
    import wp_recon
    asked = []

    def fake_fofa(q, size=100, timeout=30):
        asked.append(q)
        return {"results": [{"domain": "examplebrand-login.example"}], "total": 1}

    saved = wp_recon.fofa_search
    wp_recon.fofa_search = fake_fofa
    try:
        res = IMP.fofa_keyword_hunt("examplebrand")
        unsafe = IMP.fofa_keyword_hunt('examplebrand" || ip="192.0.2.1')
    finally:
        wp_recon.fofa_search = saved
    assert asked == ['cert.subject="examplebrand"'], asked
    assert res["domains"] == ["examplebrand-login.example"]
    assert "skipped" in unsafe


_TESTS = [
    test_hex_serial_becomes_the_decimal_fofa_expects,
    test_attacker_controlled_serial_never_reaches_the_query,
    test_leaf_serial_is_read_from_the_der,
    test_surrogate_serial_certs_produce_no_fofa_query,
    test_real_serial_drives_fofa_cert_sn_and_the_deep_link,
    test_explicit_serial_rejects_injection_and_falls_back_to_ct,
    test_hunterhow_cert_kind_uses_cert_subject_and_skips_hashes,
    test_hunterhow_window_never_exceeds_365_days,
    test_hunterhow_retries_once_when_the_api_calls_the_start_too_old,
    test_impersonation_fofa_hunt_asks_cert_subject,
]


def check():
    passed = failed = 0
    lines = []
    for test in _TESTS:
        label = test.__name__.removeprefix("test_").replace("_", " ")
        try:
            test()
        except Exception as exc:  # noqa: BLE001
            failed += 1
            lines.append(("FAIL", f"{label}: {type(exc).__name__}: {exc}"))
        else:
            passed += 1
            lines.append(("ok", label))
    return passed, failed, lines


if __name__ == "__main__":
    _passed, _failed, _lines = check()
    for _status, _label in _lines:
        print(("ok" if _status == "ok" else "FAIL") + "  " + _label)
    print(f"{_passed} passed, {_failed} failed")
    raise SystemExit(bool(_failed))
