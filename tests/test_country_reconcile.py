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

# --- whois_summary shape: the sidecar / timeline contract -----------------------------------------

def _fake_history(records):
    """A whois_history()-shaped return: the era list plus the summary counts."""
    return {"count": len(records), "records": records,
            "registrant_emails": sorted({r.get("email") for r in records if r.get("email")}),
            "registrant_names": [], "registrant_phones": [], "registrant_addresses": [],
            "registrars": sorted({r.get("registrar") for r in records if r.get("registrar")}),
            "_raw": {"records": "raw-history"}}


def _with_fakes(records, keep_raw=True, history_mode="purchase"):
    old = (we._key, we.whois_current, we.whois_history)
    try:
        we._key = lambda: "synthetic-test-key"
        we.whois_current = lambda d, timeout=40, keep_raw=True: {
            "registrar": "Example Registrar", "created": "2026-05-21", "expires": "2027-05-21",
            "name_servers": ["ns1.example.net"], "registrant_email": "b@synthetic.invalid",
            **({"_raw": {"WhoisRecord": {"registrantContact": {"country": "VN"}}}} if keep_raw else {})}
        we.whois_history = lambda d, mode="purchase", timeout=40, keep_raw=True: _fake_history(
            records if mode == "purchase" else [])
        return we.whois_summary("synthetic.invalid", history_mode=history_mode, keep_raw=keep_raw)
    finally:
        we._key, we.whois_current, we.whois_history = old


_ERAS = [
    {"email": "a@synthetic.invalid", "registrar": "Old Registrar", "updated": "2021-11-02"},
    {"email": "b@synthetic.invalid", "registrar": "Example Registrar", "updated": "2026-05-21"},
]


def test_whois_summary_carries_the_per_era_records_through():
    # The bug the audit missed: history.records was dropped, so case_timeline never saw an era.
    out = _with_fakes(_ERAS)
    assert out["history"]["records"] == _ERAS
    assert out["history"]["count"] == 2
    assert out["history"]["mode"] == "purchase"


def test_whois_summary_preview_mode_has_no_records_and_says_so():
    out = _with_fakes(_ERAS, history_mode="preview")
    assert out["history"]["records"] == []
    assert out["history"]["mode"] == "preview"


def test_dossier_country_reconcile_reads_both_raw_shapes():
    # whois_current() → top-level `_raw`; whois_summary() → nested raw.current. The dossier's
    # placeholder-country fallback must fire on a sidecar written in EITHER shape.
    dt_dir = os.path.join(os.path.dirname(__file__), "..", "intel_engine", "tools")
    spec = importlib.util.spec_from_file_location("house_report_dossier_canon",
                                                  os.path.abspath(os.path.join(dt_dir, "house_report_dossier.py")))
    hrd = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(hrd)
    rec = {"WhoisRecord": {"registrant": {"country": "NAMIBIA", "telephone": "+49 30 000000"}}}
    assert hrd.registrant_country({"registrant_country": "NAMIBIA", "_raw": rec}) == "DE"
    assert hrd.registrant_country({"registrant_country": "NAMIBIA", "raw": {"current": rec}}) == "DE"
    # WhoisXML's PRIMARY contact key is `registrantContact` (legacy `registrant`); `registryData` is
    # the fallback record — the reconcile must fire on the keys the collector itself parses.
    contact = {"country": "NAMIBIA", "telephone": "+49 30 000000"}
    rec2 = {"WhoisRecord": {"registrantContact": contact}}
    rec3 = {"WhoisRecord": {"registryData": {"registrantContact": contact}}}
    assert hrd.registrant_country({"registrant_country": "NA", "_raw": rec2}) == "DE"
    assert hrd.registrant_country({"registrant_country": "NA", "raw": {"current": rec3}}) == "DE"
    out = _with_fakes(_ERAS, keep_raw=True)
    assert "_raw" not in out                                   # no duplicated payload in artifacts.whois
    assert out["raw"]["current"]["WhoisRecord"]["registrantContact"]["country"] == "VN"


def test_whois_summary_without_keep_raw_has_no_raw_and_still_carries_records():
    out = _with_fakes(_ERAS, keep_raw=False)
    assert "raw" not in out and "_raw" not in out
    assert out["history"]["records"] == _ERAS


# --- domain_table sidecar: history spend is opt-in and cache-hits need PURCHASED records -----------

def _load_domain_table():
    path = os.path.join(os.path.dirname(__file__), "..", "intel_engine", "tools", "domain_table.py")
    spec = importlib.util.spec_from_file_location("domain_table_canon", os.path.abspath(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_sidecar_default_is_current_whois_only_and_never_purchases_history():
    import tempfile
    dt = _load_domain_table()
    calls = []
    dt.whois_current = lambda d: (calls.append(("current", d)), {"registrar": "R", "created": "2026-01-01"})[1]
    dt.whois_summary = lambda d, history_mode="purchase": (calls.append(("summary", history_mode)), {})[1]
    with tempfile.TemporaryDirectory() as tmp:
        w = dt._whois_cached("synthetic.invalid", tmp)                 # default history_mode="off"
        assert w["registrar"] == "R"
        assert calls == [("current", "synthetic.invalid")]              # no history call at all
        calls.clear()
        assert dt._whois_cached("synthetic.invalid", tmp)["registrar"] == "R"
        assert calls == []                                              # cached, zero spend


def test_sidecar_preview_or_historyless_cache_is_not_a_purchased_cache_hit():
    import tempfile
    dt = _load_domain_table()
    calls = []
    dt.whois_current = lambda d: {"registrar": "R"}
    dt.whois_summary = lambda d, history_mode="purchase": (calls.append(history_mode), {
        "registrar": "R", "history": {"count": 2, "mode": history_mode,
                                       "records": _ERAS if history_mode == "purchase" else []}})[1]
    with tempfile.TemporaryDirectory() as tmp:
        dt._whois_cached("synthetic.invalid", tmp, history_mode="preview")   # cached: history key, no records
        assert calls == ["preview"]
        w = dt._whois_cached("synthetic.invalid", tmp, history_mode="purchase")
        assert calls == ["preview", "purchase"]                             # stale for purchase → refetched
        assert w["history"]["records"] == _ERAS
        dt._whois_cached("synthetic.invalid", tmp, history_mode="purchase")
        assert calls == ["preview", "purchase"]                             # purchased cache reused
        # an explicit "off" read reuses whatever is cached, never spends
        assert dt._whois_cached("synthetic.invalid", tmp)["history"]["records"] == _ERAS
        assert calls == ["preview", "purchase"]
        # a completed purchase with ZERO era records (a young domain) is still a purchase — never re-bought
        dt.whois_summary = lambda d, history_mode="purchase": (calls.append(("young", history_mode)), {
            "registrar": "R", "history": {"count": 0, "mode": history_mode, "records": []}})[1]
        dt._whois_cached("young.invalid", tmp, history_mode="purchase")
        dt._whois_cached("young.invalid", tmp, history_mode="purchase")
        assert calls.count(("young", "purchase")) == 1
        # an ERRORED purchase is not a purchase — refetched once on the next purchase request
        state = {"n": 0}
        def _flaky(d, history_mode="purchase"):
            state["n"] += 1
            h = {"mode": history_mode, "records": []}
            if state["n"] == 1:
                h["error"] = "HTTP 503"
            else:
                h["records"] = _ERAS
            return {"registrar": "R", "history": h}
        dt.whois_summary = _flaky
        assert dt._whois_cached("flaky.invalid", tmp, history_mode="purchase")["history"].get("error")
        assert dt._whois_cached("flaky.invalid", tmp, history_mode="purchase")["history"]["records"] == _ERAS
        dt._whois_cached("flaky.invalid", tmp, history_mode="purchase")
        assert state["n"] == 2
        # a legacy sidecar written before the mode stamp reads as unpurchased → refetched once
        json.dump({"registrar": "R", "history": {"count": 3, "records": _ERAS}},
                  open(os.path.join(tmp, "whois", "legacy.invalid.json"), "w"))
        state["n"] = 5
        assert dt._whois_cached("legacy.invalid", tmp, history_mode="purchase")["history"]["mode"] == "purchase"
        assert state["n"] == 6


def test_sidecar_free_only_takes_the_keyless_path_and_scoping_limits_history():
    import tempfile
    dt = _load_domain_table()
    calls = []
    dt.whois_current = lambda d: (calls.append(("current", d)), {"registrar": "R"})[1]
    dt.whois_summary = lambda d, history_mode="purchase": (calls.append(("summary", d)), {"registrar": "R", "history": {"records": _ERAS}})[1]
    dt.whois_summary_keyless = lambda d: (calls.append(("keyless", d)), {"registrar": "RDAP", "history": {}})[1]
    dt._status_from_live = lambda d: ("unknown", "")
    dt._asn_for_ip = lambda ip, cache, timeout=8: ""
    with tempfile.TemporaryDirectory() as tmp:
        assert dt._whois_cached("free.invalid", tmp, history_mode="purchase", free_only=True)["registrar"] == "RDAP"
        assert calls == [("keyless", "free.invalid")]
        calls.clear()
        rows = dt.gather_rows([("seed.invalid", None), ("other.invalid", None)], tmp, os.path.join(tmp, "kb"), {},
                              history_mode="purchase", history_for={"seed.invalid"})
        assert len(rows) == 2
        assert ("summary", "seed.invalid") in calls and ("current", "other.invalid") in calls
        assert ("summary", "other.invalid") not in calls


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
    test_whois_summary_carries_the_per_era_records_through,
    test_whois_summary_preview_mode_has_no_records_and_says_so,
    test_dossier_country_reconcile_reads_both_raw_shapes,
    test_whois_summary_without_keep_raw_has_no_raw_and_still_carries_records,
    test_sidecar_default_is_current_whois_only_and_never_purchases_history,
    test_sidecar_preview_or_historyless_cache_is_not_a_purchased_cache_hit,
    test_sidecar_free_only_takes_the_keyless_path_and_scoping_limits_history,
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
