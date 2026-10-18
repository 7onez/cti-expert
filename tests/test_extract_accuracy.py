#!/usr/bin/env python3
"""Regression: wp_extract free-text contact/wallet/social extraction accuracy.

Each case pairs an input the extractor used to get WRONG with one it must keep getting right:
  phones   — CVE ids, build timestamps, ISBNs and year-prefixed order numbers were emitted as phone
             pivots; dotted national numbers (0912.345.678) were missed; `+84 (0) 912…` kept the
             domestic trunk 0. Dotted amounts / IPv4 must stay out; tel:, JSON-LD and +E.164 stay in.
  emails   — retina/package asset names (hero@2x.jpeg, jquery@3.6.0.min.js) were emitted as
             mailboxes; a percent-encoded mailto: yielded `6F%70%73@…`. All-digit mail domains
             (163.com) and platform system mailboxes keep their current treatment.
  wallets  — a BTC P2SH '3…' address was also reported as LTC; real LTC 'L'/'M' must stay LTC.
  socials  — facebook.com/profile.php?id=… was dropped as a static asset; t.me/s/<chan> (the
             channel web preview) was dropped as boilerplate.

Run:  python3 tests/test_extract_accuracy.py
Fully offline: pure parsing functions, no network. Synthetic data only (example.org, fake numbers).
"""
import hashlib
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
WP = os.path.join(ROOT, "intel_engine", "WebPivot", "tools")
if WP not in sys.path:
    sys.path.insert(0, WP)

import wp_extract as E  # noqa: E402

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58check(version: int, body: bytes) -> str:
    """Encode a synthetic base58check address (valid checksum, made-up hash160)."""
    payload = bytes([version]) + body
    raw = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    num = int.from_bytes(raw, "big")
    out = ""
    while num:
        num, r = divmod(num, 58)
        out = _B58[r] + out
    return "1" * (len(raw) - len(raw.lstrip(b"\x00"))) + out


def _phones(text):
    return E.extract_phones(f"<html><body><p>{text}</p></body></html>")


def test_identifier_shapes_are_not_phones():
    for text in ("Patched CVE-2024-12345 today", "Build 2026-10-11 12:34:56",
                 "ISBN 978-3-16-148410-0", "Order 2024-000123-45"):
        got = _phones(text)
        assert got == [], (text, got)


def test_real_phones_still_extracted():
    assert _phones("Call +1 202-555-0143") == ["+12025550143"], _phones("Call +1 202-555-0143")
    assert _phones("Hotline 0912 345 678") == ["0912345678"], _phones("Hotline 0912 345 678")
    html = ('<a href="tel:+84912345678">call</a><script type="application/ld+json">'
            '{"telephone": "+44 20 7946 0000"}</script>')
    got = E.extract_phones(html)
    assert got == ["+84912345678", "+442079460000"], got


def test_dotted_national_numbers_extracted():
    assert _phones("Zalo: 0912.345.678") == ["0912345678"], _phones("Zalo: 0912.345.678")
    assert _phones("Tel 06.12.34.56.78") == ["0612345678"], _phones("Tel 06.12.34.56.78")


def test_dotted_ipv4_and_amounts_are_not_phones():
    for text in ("Origin 10.20.30.40 behind CDN", "Price 12.500.000 VND", "Fee 125.000.000"):
        got = _phones(text)
        assert got == [], (text, got)


def test_trunk_zero_after_country_code_dropped():
    assert _phones("Phone +84 (0) 912 345 678") == ["+84912345678"], _phones("Phone +84 (0) 912 345 678")
    assert E.extract_phones('<a href="tel:+44(0)2079460000">x</a>') == ["+442079460000"]


def test_asset_names_are_not_emails():
    html = ('<script src="/vendor/jquery@3.6.0.min.js"></script><img src="/img/hero@2x.jpeg">'
            '<img src="/img/icon@3x.avif"><a href="mailto:ops@example.org">mail</a>')
    got = E.extract_emails(html)
    assert got == ["ops@example.org"], got


def test_numeric_mail_domain_and_platform_mailbox_kept_as_before():
    got = E.extract_emails("contact: registrant@163.com, relay@users.wixpress.com")
    assert got == ["registrant@163.com"], got


def test_percent_encoded_mailto_decoded():
    got = E.extract_emails('<a href="mailto:%6F%70%73@example.org?subject=Hi%20there">mail</a>')
    assert got == ["ops@example.org"], got


def test_btc_p2sh_is_not_ltc():
    got = E.extract_crypto("Send to 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy")
    assert got == {"btc": ["3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"]}, got


def test_real_ltc_and_btc_legacy_classified_once():
    body = bytes(range(1, 21))
    ltc_l, ltc_m, btc_1 = _b58check(0x30, body), _b58check(0x32, body), _b58check(0x00, body)
    assert ltc_l.startswith("L") and ltc_m.startswith("M") and btc_1.startswith("1")
    got = E.extract_crypto(f"a {ltc_l} b {ltc_m} c {btc_1}")
    assert got == {"ltc": [ltc_l, ltc_m], "btc": [btc_1]}, got


def test_facebook_numeric_profile_kept_static_assets_dropped():
    hrefs = ["https://www.facebook.com/profile.php?id=100012345",
             "https://facebook.com/sharer/share.php",
             "https://github.com/images/octocat.png"]
    got = E.extract_socials(hrefs)
    assert got == {"facebook": ["https://www.facebook.com/profile.php?id=100012345"]}, got


def test_telegram_web_preview_takes_channel():
    got = E.extract_telegram(["https://t.me/s/OtherChan", "https://t.me/s", "https://t.me/share/url?u=x"])
    assert got == [{"url": "https://t.me/s/OtherChan", "kind": "channel", "handle": "otherchan"}], got


_TESTS = [test_identifier_shapes_are_not_phones, test_real_phones_still_extracted,
          test_dotted_national_numbers_extracted, test_dotted_ipv4_and_amounts_are_not_phones,
          test_trunk_zero_after_country_code_dropped, test_asset_names_are_not_emails,
          test_numeric_mail_domain_and_platform_mailbox_kept_as_before,
          test_percent_encoded_mailto_decoded, test_btc_p2sh_is_not_ltc,
          test_real_ltc_and_btc_legacy_classified_once,
          test_facebook_numeric_profile_kept_static_assets_dropped,
          test_telegram_web_preview_takes_channel]


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
