"""Regression for data-driven WHOIS placeholder-country reconciliation.

All contacts are synthetic. The module proves the helper is not shaped around one country or case,
that the country field cannot corroborate itself, and that current/history address construction does
not re-inject an overridden placeholder value.
"""
import importlib.util
import json
import os

_CANON = os.path.join(os.path.dirname(__file__), "..", "intel_engine",
                      "WebPivot", "tools", "whois_enrich.py")


def _load():
    spec = importlib.util.spec_from_file_location("whois_enrich_canon", os.path.abspath(_CANON))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


we = _load()


def test_placeholder_with_non_namibian_calling_code_is_corrected():
    contact = {"country": "NAMIBIA", "telephone": "+49 30 000000"}
    assert we._reconcile_country(contact) == "DE"


def test_placeholder_with_country_name_in_address_fields_is_corrected():
    contact = {"country": "NA", "street1": "1 Example Road", "state": "France"}
    assert we._reconcile_country(contact) == "FR"


def test_genuine_namibian_calling_code_keeps_namibia_without_note():
    contact = {"country": "NAMIBIA", "telephone": "+264 61 000000"}
    assert we._reconcile_country(contact) is None


def test_shared_calling_zone_does_not_guess_one_country():
    contact = {"country": "NAMIBIA", "telephone": "+1 202 000000"}
    assert we._country_from_phone(contact["telephone"]) is None
    assert we._reconcile_country(contact) is None


def test_no_contradicting_signal_keeps_namibia_without_note():
    contact = {"country": "NAMIBIA", "street1": "1 Example Road", "city": "Example City"}
    assert we._reconcile_country(contact) is None


def test_country_field_never_corroborates_itself():
    contact = {"country": "NAMIBIA"}
    assert we._country_from_address_fields(contact) is None
    assert we._reconcile_country(contact) is None


def test_non_placeholder_country_is_never_rewritten():
    contact = {"country": "GERMANY", "telephone": "+33 1 000000"}
    assert we._reconcile_country(contact) is None


def test_corrected_address_does_not_reinject_placeholder_country():
    contact = {"country": "NAMIBIA", "telephone": "+49 30 000000",
               "street1": "1 Example Road", "city": "Example City"}
    override = we._reconcile_country(contact)
    address = we._address(contact, country_override=override)
    assert address.endswith("DE")
    assert "NAMIBIA" not in address


def test_whois_current_rebuilds_address_from_corrected_country():
    sample = {"WhoisRecord": {"registrantContact": {
        "country": "NAMIBIA", "telephone": "+49 30 000000",
        "street1": "1 Example Road", "city": "Example City",
    }}}
    old_key, old_get = we._key, we._get_json
    try:
        we._key = lambda: "synthetic-test-key"
        we._get_json = lambda *args, **kwargs: sample
        result = we.whois_current("synthetic.invalid", keep_raw=False)
    finally:
        we._key, we._get_json = old_key, old_get

    assert result["registrant_country"] == "DE"
    assert result["registrant_country_raw"] == "NAMIBIA"
    assert result["registrant_address"].endswith("DE")
    assert "NAMIBIA" not in result["registrant_address"]
    assert "registrant_country_note" not in result


def test_whois_history_reconciles_each_record_and_preserves_raw_for_audit():
    sample = {
        "recordsCount": 2,
        "records": [
            {"registrantContact": {"country": "NAMIBIA", "telephone": "+49 30 000000",
                                    "street1": "1 Example Road", "city": "Example City"}},
            {"registrantContact": {"country": "NAMIBIA", "telephone": "+264 61 000000",
                                    "street1": "2 Example Road", "city": "Example City"}},
        ],
    }
    old_key, old_get = we._key, we._get_json
    try:
        we._key = lambda: "synthetic-test-key"
        we._get_json = lambda *args, **kwargs: sample
        result = we.whois_history("synthetic.invalid", keep_raw=False)
    finally:
        we._key, we._get_json = old_key, old_get

    corrected, genuine = result["records"]
    assert corrected["country"] == "DE" and corrected["country_raw"] == "NAMIBIA"
    assert corrected["address"].endswith("DE") and "NAMIBIA" not in corrected["address"]
    assert genuine["country"] == "NAMIBIA" and "country_raw" not in genuine
    assert "country_note" not in corrected and "country_note" not in genuine



def test_rdap_cc_is_authoritative_over_a_namibian_phone():
    # RDAP adr.cc is the registry's own structured country; it must win even over a +264 number.
    contact = {"country": "NAMIBIA", "telephone": "+264 61 000000"}
    assert we._reconcile_country(contact, rdap_cc="VN") == "VN"


def test_whois_current_recovers_country_from_embedded_rdap_cc():
    # WhoisXML normalized country="NAMIBIA" but the raw RDAP jCard adr keeps cc=VN (the true value).
    rawtext = json.dumps({"entities": [{"roles": ["registrant"], "vcardArray": ["vcard", [
        ["version", {}, "text", "4.0"],
        ["adr", {"cc": "VN"}, "text", ["", "NA", "example ward", "NA", "example city", "NA", ""]],
        ["tel", {}, "uri", "tel:+84.900000000"]]]}]})
    sample = {"WhoisRecord": {
        "registrantContact": {"country": "NAMIBIA", "countryCode": "NA",
                              "street1": "NA", "city": "example city", "state": "NA"},
        "rawText": rawtext}}
    old_key, old_get = we._key, we._get_json
    try:
        we._key = lambda: "synthetic-test-key"
        we._get_json = lambda *a, **k: sample
        result = we.whois_current("synthetic.invalid", keep_raw=False)
    finally:
        we._key, we._get_json = old_key, old_get
    assert result["registrant_country"] == "VN"
    assert result["registrant_country_raw"] == "NAMIBIA"
    assert "NAMIBIA" not in (result["registrant_address"] or "")

_TESTS = [
    test_placeholder_with_non_namibian_calling_code_is_corrected,
    test_placeholder_with_country_name_in_address_fields_is_corrected,
    test_genuine_namibian_calling_code_keeps_namibia_without_note,
    test_shared_calling_zone_does_not_guess_one_country,
    test_no_contradicting_signal_keeps_namibia_without_note,
    test_country_field_never_corroborates_itself,
    test_non_placeholder_country_is_never_rewritten,
    test_corrected_address_does_not_reinject_placeholder_country,
    test_whois_current_rebuilds_address_from_corrected_country,
    test_whois_history_reconciles_each_record_and_preserves_raw_for_audit,
    test_rdap_cc_is_authoritative_over_a_namibian_phone,
    test_whois_current_recovers_country_from_embedded_rdap_cc,
]


def check():
    passed = failed = 0
    lines = []
    for test in _TESTS:
        label = test.__name__.removeprefix("test_").replace("_", " ")
        try:
            test()
        except Exception as exc:  # noqa: BLE001 — unit harness reports every independent case
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
