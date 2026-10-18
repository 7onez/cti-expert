#!/usr/bin/env python3
"""Regression: wp_vncorp — the keyless Vietnamese business-registry lookup (#16).

Pure-parsing coverage only (no network): the MST (tax-code) validator, the table/`<dt><dd>`
structured extractor, the colon-pair text fallback, the `<script>`/`<style>` exclusion guard, and
`lookup()`'s fan-out across every configured mirror with `_fetch` stubbed. Synthetic company data
only (CLAUDE.md): a fabricated name, address and 10-digit tax code, never a real filing."""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "WebPivot", "tools"))

import wp_vncorp as vn  # noqa: E402

_SYNTH_TABLE_HTML = """<html><body>
<table class="table-simple">
<tr><td>M\u00e3 s\u1ed1 thu\u1ebf</td><td>0101234567</td></tr>
<tr><td>T\u00ean ch\u00ednh th\u1ee9c</td><td>CONG TY TNHH VI DU MINH HOA</td></tr>
<tr><td>T\u00ean qu\u1ed1c t\u1ebf</td><td>EXAMPLE DEMO COMPANY LIMITED</td></tr>
<tr><td>Ng\u01b0\u1eddi \u0111\u1ea1i di\u1ec7n</td><td>Nguyen Van Vi Du</td></tr>
<tr><td>\u0110\u1ecba ch\u1ec9</td><td>123 Duong Vi Du, Phuong Demo, Quan Test, TP. Vi Du</td></tr>
<tr><td>\u0110i\u1ec7n tho\u1ea1i</td><td>0123456789</td></tr>
<tr><td>T\u00ecnh tr\u1ea1ng</td><td>Dang hoat dong</td></tr>
<tr><td>Ng\u00e0y c\u1ea5p</td><td>2020-01-15</td></tr>
</table>
</body></html>"""


def test_is_mst_accepts_10_and_13_digit_forms():
    assert vn.is_mst("0101234567")
    assert vn.is_mst("0101234567-001")
    assert vn.is_mst("0101234567001")
    assert not vn.is_mst("Cong ty TNHH Vi Du")
    assert not vn.is_mst("12345")


def test_table_fixture_parses_all_fields_with_source_tagging():
    fields = vn.parse_company_html(_SYNTH_TABLE_HTML, "masothue.com", "https://masothue.com/x")
    for k in ("tax_code", "company_name_vn", "company_name_intl", "legal_representative",
              "address", "phone", "status", "registration_date"):
        assert fields[k] is not None, f"missing field {k}"
        assert fields[k]["source"] == "masothue.com"
        assert fields[k]["source_url"] == "https://masothue.com/x"
    assert fields["tax_code"]["value"] == "0101234567"
    assert fields["company_name_vn"]["value"].startswith("CONG TY")


def test_dt_dd_fixture_parses_via_definition_list_path():
    html = ("<html><body><dl>"
            "<dt>MST</dt><dd>0101234567</dd>"
            "<dt>Ten cong ty</dt><dd>CONG TY TNHH VI DU MINH HOA</dd>"
            "<dt>Dia chi</dt><dd>123 Duong Vi Du</dd>"
            "</dl></body></html>")
    f = vn.parse_company_html(html, "hsctvn.com", "https://hsctvn.com/x")
    assert f["tax_code"]["value"] == "0101234567"
    assert f["company_name_vn"]["value"].startswith("CONG TY")
    assert f["address"]["value"] == "123 Duong Vi Du"
    assert f["phone"] is None


def test_colon_pair_text_fallback_parses_unstructured_markup():
    html = ("<html><body><div>"
            "Ma so thue: 0101234567<br>"
            "Dia chi: 123 Duong Vi Du"
            "</div></body></html>")
    f = vn.parse_company_html(html, "doanhnghiep.biz", "https://doanhnghiep.biz/x")
    assert f["tax_code"]["value"] == "0101234567"
    assert f["address"]["value"] == "123 Duong Vi Du"


def test_no_signal_page_returns_all_none_never_guesses():
    f = vn.parse_company_html("<html><body>not found</body></html>", "x", "https://x")
    assert all(v is None for v in f.values())


def test_script_and_style_content_never_leaks_into_fields():
    """A `<style>`/`<script>` block can contain colon-separated CSS/JS text (`border: 1px solid`,
    a JS string literal) that must never be read as a business-registry label:value pair."""
    html = ("<html><head><style>.badge { border: 1px solid #e5e7eb; color: red; }</style></head>"
            "<body><script>var mst = \"0000000000\"; "
            "console.log(\"ma so thue: 9999999999\");</script>"
            "<dl><dt>Ma so thue</dt><dd>0101234567</dd></dl></body></html>")
    f = vn.parse_company_html(html, "x", "https://x")
    assert f["tax_code"]["value"] == "0101234567", f["tax_code"]


def test_lookup_fans_out_across_every_configured_mirror():
    calls = []

    def fake_fetch(url, timeout=None):
        calls.append(url)
        return _SYNTH_TABLE_HTML, None

    saved = vn._fetch
    vn._fetch = fake_fetch
    try:
        out = vn.lookup("0101234567")
    finally:
        vn._fetch = saved
    assert out["kind"] == "mst"
    assert out["fields"]["tax_code"]["value"] == "0101234567"
    assert len(calls) == len(vn.SOURCES) > 0
    assert set(out["sources"]) == set(vn.SOURCES)


def test_lookup_never_raises_on_a_fetch_error():
    def fake_fetch_error(url, timeout=None):
        return None, "ConnectionError: refused"

    saved = vn._fetch
    vn._fetch = fake_fetch_error
    try:
        out = vn.lookup("Cong ty TNHH Vi Du")
    finally:
        vn._fetch = saved
    assert out["kind"] == "name"
    assert out["fields"] == {}
    assert all(s.get("status") == "error" for s in out["sources"].values())


def test_name_lookup_rejects_a_results_page_about_another_company():
    """Live bug: two different company names both 'matched' one unrelated branch, because a name
    search returns a listing page and its first record was parsed as the answer."""
    saved = vn._fetch
    vn._fetch = lambda url, timeout=None: (_SYNTH_TABLE_HTML, None)
    try:
        other = vn.lookup("CONG TY TNHH KHONG LIEN QUAN")
        same = vn.lookup("Công ty TNHH Ví Dụ Minh Họa")
    finally:
        vn._fetch = saved
    assert other["fields"] == {}, other["fields"]
    assert all(s["status"] == "unmatched" for s in other["sources"].values())
    assert same["fields"]["tax_code"]["value"] == "0101234567"   # diacritics fold, still matches



_TESTS = [
    test_is_mst_accepts_10_and_13_digit_forms,
    test_table_fixture_parses_all_fields_with_source_tagging,
    test_dt_dd_fixture_parses_via_definition_list_path,
    test_colon_pair_text_fallback_parses_unstructured_markup,
    test_no_signal_page_returns_all_none_never_guesses,
    test_script_and_style_content_never_leaks_into_fields,
    test_lookup_fans_out_across_every_configured_mirror,
    test_lookup_never_raises_on_a_fetch_error,
    test_name_lookup_rejects_a_results_page_about_another_company,
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
