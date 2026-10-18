#!/usr/bin/env python3
"""Regression: punycode (IDN) hosts are hostnames, and a typed Telegram selector keys the KB on the
same ACCOUNT the page ingest does.

WHAT THIS PROTECTS
------------------
1. The PSL reference stores IDN rules in Unicode (`рф`, `公司.cn`), but DNS, crt.sh and urlscan hand
   back the ASCII (punycode) form. Without the punycode rule labels, `shop.xn--e1afmkfd.xn--p1ai` was
   "not a known TLD": case_state dropped it from the frontier (`_clean_name` -> '', `never_seed` ->
   True), selector_types classified it as a free-text string, and email_hygiene silently skipped an
   address on it. A fully-qualified `example.com.` was likewise a string. Unicode input, ordinary
   ccTLD second levels (co.uk / com.vn), PRIVATE platforms (github.io) and wildcard/exception rules
   (*.kawasaki.jp / !city.kawasaki.jp) must reduce exactly as before.
2. `kb_key('telegram', …)` took the LAST path segment: a post URL keyed on the post id, a `?start=`
   deep link kept the query, an invite hash was lowercased (invite hashes are case-sensitive). It now
   goes through noise_filters.social_handle, the function the page ingest keys socials with.
Offline — no network, no case/KB writes.
"""
import importlib.util
import os
import pathlib
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.join(ROOT, "intel_engine", "WebPivot", "tools"),
           os.path.join(ROOT, "intel_engine", "tools"),
           os.path.join(ROOT, "intel_engine", "tools", "kb")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import wp_common as W  # noqa: E402
import case_state as CS  # noqa: E402
import selector_types as ST  # noqa: E402
import noise_filters as NF  # noqa: E402

_eh_path = pathlib.Path(ROOT) / "scripts" / "webpivot" / "email_hygiene.py"
_spec = importlib.util.spec_from_file_location("email_hygiene_idn_test", _eh_path)
EH = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(EH)

IDN_APEX = "xn--e1afmkfd.xn--p1ai"          # пример.рф
IDN_HOST = "shop." + IDN_APEX


def _graded(emails):
    """grade_emails with the MX lookup stubbed (all domains deliverable) — offline."""
    orig = EH._mx_lookup_many
    EH._mx_lookup_many = lambda domains, timeout=8: {d: True for d in domains}
    try:
        out = EH.grade_emails(emails)
    finally:
        EH._mx_lookup_many = orig
    rows = out.get("results", out) if isinstance(out, dict) else out
    return [r["domain"] for r in rows]


def check():
    passed = failed = 0
    lines = []

    def ok(cond, label):
        nonlocal passed, failed
        if cond:
            passed += 1
            lines.append(("ok", label))
        else:
            failed += 1
            lines.append(("FAIL", label))

    # ---- 1. PSL: punycode rule labels sit beside the Unicode ones -----------------------------
    ok(W.has_known_tld("sub.xn--p1ai") and W.has_known_tld(IDN_HOST),
       "has_known_tld: a punycode IDN ccTLD (xn--p1ai) is a known TLD")
    ok(W.has_known_tld("sub.рф"), "has_known_tld: the Unicode form still works")
    ok(not W.has_known_tld("clusters.json") and not W.has_known_tld("xn--p1ai.xn--zzzz"),
       "has_known_tld: a file extension / unknown punycode label is still not a TLD")
    ok(W.public_suffix("shop.xn--55qx5d.cn") == "xn--55qx5d.cn"
       and W._registrable("a.shop.xn--55qx5d.cn") == "shop.xn--55qx5d.cn",
       "multi-label IDN rule (公司.cn) matches in punycode: shop.xn--55qx5d.cn is registrable")
    ok(W.public_suffix("shop.公司.cn") == "公司.cn" and W._registrable("a.shop.公司.cn") == "shop.公司.cn",
       "multi-label IDN rule still matches in Unicode")
    ok(W._registrable("a." + IDN_HOST) == IDN_APEX, "punycode host reduces to its punycode apex")
    unchanged = [("news.bbc.co.uk", "bbc.co.uk"), ("a.shop.com.vn", "shop.com.vn"),
                 ("x.shop.github.io", "shop.github.io"), ("a.b.kawasaki.jp", "a.b.kawasaki.jp"),
                 ("x.city.kawasaki.jp", "city.kawasaki.jp"), ("a.b.example.com", "example.com")]
    ok(all(W._registrable(h) == want for h, want in unchanged),
       "registrable domain unchanged for co.uk / com.vn / github.io (private) / *.kawasaki.jp "
       "wildcard / !city.kawasaki.jp exception / ordinary .com")
    ok(W.is_private_suffix("github.io") and not W.is_private_suffix("xn--p1ai"),
       "PRIVATE-section membership unchanged (github.io private, an IDN ccTLD is not)")

    # ---- case_state: IDN hosts stay in the frontier ------------------------------------------
    ok(CS._clean_name(IDN_HOST) == IDN_HOST and CS._clean_name("*." + IDN_HOST + ".") == IDN_HOST,
       "case_state._clean_name keeps a punycode IDN-ccTLD host (and strips wildcard/trailing dot)")
    ok(CS._clean_name("report.json") == "", "case_state._clean_name still drops a filename-shaped token")
    ok(CS.never_seed(IDN_APEX) is False, "case_state.never_seed: a punycode IDN apex is seedable")
    ok(CS.never_seed("report.json") is True, "case_state.never_seed: a filename-shaped token is not")

    # ---- selector_types.classify ---------------------------------------------------------------
    ok(ST.classify(IDN_APEX) == "domain" and ST.classify(IDN_HOST) == "domain",
       "classify: a punycode IDN-ccTLD domain is a domain")
    ok(ST.classify("example.com.") == "domain", "classify: a fully-qualified name (trailing dot) is a domain")
    ok(ST.classify("a@" + IDN_APEX) == "email", "classify: an address on a punycode domain is an email")
    ok(ST.classify("example.com..") == "string" and ST.classify("xn--.") == "string",
       "classify: only ONE trailing dot is stripped; junk stays a string")
    ok(ST.classify("example.com") == "domain" and ST.classify("not a domain") == "string",
       "classify: ordinary domain / free text unchanged")

    # ---- email_hygiene -------------------------------------------------------------------------
    ok(_graded(["a@" + IDN_APEX]) == [IDN_APEX],
       "email_hygiene grades an address on a punycode IDN domain (no silent skip)")
    ok(_graded(["ceo@example.com", "bad@nodot"]) == ["example.com"],
       "email_hygiene: ordinary address graded, malformed one still skipped")

    # ---- 2. telegram kb_key == the page-ingest account key -------------------------------------
    def ingest_key(url):
        return ("indicator", f"social:telegram:{NF.social_handle('telegram', url)}")

    post = "https://t.me/op_channel/123"
    ok(ST.kb_key("telegram", post) == ingest_key(post) == ("indicator", "social:telegram:op_channel"),
       "kb_key: a post URL keys on the channel, not the post id (== social_handle key)")
    inv = "https://t.me/+AbCdEfGh"
    ok(ST.kb_key("telegram", inv) == ingest_key(inv) == ("indicator", "social:telegram:+AbCdEfGh"),
       "kb_key: an invite hash keeps its case (== social_handle key)")
    jc = "https://t.me/joinchat/AbCdEfGh"
    ok(ST.kb_key("telegram", jc) == ingest_key(jc) == ("indicator", "social:telegram:AbCdEfGh"),
       "kb_key: a legacy joinchat invite hash keeps its case (== social_handle key)")
    start = "t.me/channel?start=x"
    ok(ST.kb_key("telegram", start) == ingest_key(start) == ("indicator", "social:telegram:channel"),
       "kb_key: a ?start= deep link keys on the channel (== social_handle key)")
    s_link = "https://t.me/s/chan_name/55"
    ok(ST.kb_key("telegram", s_link) == ingest_key(s_link) == ("indicator", "social:telegram:chan_name"),
       "kb_key: a t.me/s/<chan> preview link keys on the channel (== social_handle key)")
    ok(ST.kb_key("telegram", "@Op_Channel") == ("indicator", "social:telegram:op_channel")
       and ST.kb_key("telegram", "https://t.me/Op_Channel") == ("indicator", "social:telegram:op_channel"),
       "kb_key: a bare @handle and a mixed-case username both key on the lowercased username")
    return passed, failed, lines


if __name__ == "__main__":
    _passed, _failed, _lines = check()
    for _status, _label in _lines:
        print(f"[{_status}] {_label}")
    print(f"\n{_passed} passed, {_failed} failed")
    raise SystemExit(bool(_failed))
