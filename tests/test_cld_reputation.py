"""Regression: the ChongLuaDao reputation layer (wp_cld) and its KB ingest.

  1. cld_domain returns checkurl + ioc_url, adds a whois leg ONLY for .vn, and returns None under
     free_only / no key (metered gate).
  2. verdict_of reads the verdict AND folds a checkurl denylist listing into has_evidence — a label
     on empty evidence stays has_evidence=False (never adopted as a finding), a denylist hit flips it.
  3. ingest records the verdict as FACTS on the domain (cld_verdict / cld_denylisted /
     cld_reputation_score) — never a same-operator edge; an empty-evidence label carries a note.
Network fully stubbed via a fake cld_api; synthetic hosts only (example.com / .vn)."""
import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "intel_engine", "WebPivot", "tools"))
sys.path.insert(0, os.path.join(ROOT, "intel_engine", "tools", "kb"))

import wp_cld  # noqa: E402
wp_cld.api_usage = None   # stubbed HTTP makes no real metered call — never touch the credit ledger (offline gate)
import ingest_webpivot as iw  # noqa: E402
import knowledge_base as kbm  # noqa: E402


class _FakeCldApi:
    """Stands in for scripts/cld/cld_api.py: routes (method, base, path) to canned responses."""
    FEEDS = "https://feeds.example"
    TI = "https://ti.example"

    def __init__(self, routes, key="k"):
        self.routes, self._key = routes, key
        self.calls = []

    def _api_key(self):
        return self._key

    def _request(self, method, base, path, key, params=None, body=None, timeout=30):
        self.calls.append((method, path))
        return self.routes.get(path, (200, {}, None))


_MALICIOUS = {
    "/external/checkurl": (200, {"result": "malicious", "details": "URL in denylist"}, None),
    "/api/v1/ioc/external/url": (200, {"verdict": "malicious", "data": {
        "domain_reputation": {"reputation_score": -0.3, "has_abuse_listing": False},
        "threat_matches": [], "threat_reports": {"count": 0}}}, None),
    "/external/checkwhois": (200, {"registrar": "iNET", "owner": "Test Co",
                                   "registration_date": "27-04-2022"}, None),
}
_EMPTY_LABEL = {
    "/external/checkurl": (200, {"result": "clean", "details": "URL not in denylist"}, None),
    "/api/v1/ioc/external/url": (200, {"verdict": "suspicious", "data": {
        "domain_reputation": {"reputation_score": -0.1, "has_abuse_listing": False},
        "threat_matches": [], "threat_reports": {"count": 0}}}, None),
}


def _install(routes, key="k"):
    orig = wp_cld._api
    fake = _FakeCldApi(routes, key)
    wp_cld._api = lambda: fake
    # cld_configured() is env-first — set/clear the process key to match `key`
    if key:
        os.environ["CHONGLUADAO_API_KEY"] = key
    else:
        for n in wp_cld._KEY_NAMES:
            os.environ.pop(n, None)
    return orig, fake


def test_cld_domain_shape_and_vn_whois_and_gate():
    orig, fake = _install(_MALICIOUS)
    try:
        b = wp_cld.cld_domain("example.vn", timeout=5)
        assert set(b) == {"checkurl", "ioc_url", "whois"}, b   # .vn adds the whois leg
        assert wp_cld.cld_domain("example.com", timeout=5).keys() == {"checkurl", "ioc_url"}  # no whois off-.vn
        assert wp_cld.cld_domain("example.com", free_only=True) is None    # metered gate
    finally:
        wp_cld._api = orig
    # no key configured → not configured, cld_domain None
    orig2, _ = _install(_MALICIOUS, key=None)
    try:
        assert not wp_cld.cld_configured()
        assert wp_cld.cld_domain("example.com") is None
    finally:
        wp_cld._api = orig2


def test_verdict_folds_denylist_into_evidence():
    orig, _ = _install(_MALICIOUS)
    try:
        v = wp_cld.verdict_of(wp_cld.cld_domain("example.com", timeout=5))
    finally:
        wp_cld._api = orig
    assert v["verdict"] == "malicious" and v["denylisted"] is True and v["has_evidence"] is True, v

    orig, _ = _install(_EMPTY_LABEL)
    try:
        v = wp_cld.verdict_of(wp_cld.cld_domain("example.com", timeout=5))
    finally:
        wp_cld._api = orig
    assert v["verdict"] == "suspicious" and v["denylisted"] is False and v["has_evidence"] is False, v
    # "URL not in denylist" must NOT read as denylisted (verdict keys on checkurl `result`, not a substring)


def _ingest(cld_block):
    with tempfile.TemporaryDirectory() as tmp:
        kb = kbm.KB(os.path.join(tmp, "knowledge"))
        raw = {"meta": {"host": "example.com"}, "artifacts": {"title": "x"},
               "pivots": [{"kind": "domain", "value": "example.com", "live_results": {"cld": cld_block}}]}
        p = os.path.join(tmp, "example.com.json")
        json.dump(raw, open(p, "w"))
        iw.ingest_file(kb, p)
        facts = {f["attribute"]: f["value"] for e in kb.all_entities() for f in e.get("facts", [])
                 if f["attribute"].startswith("cld_")}
        edges = [e["rel"] for e in kb.edges()]
        return facts, edges


def test_ingest_records_facts_not_edges():
    facts, edges = _ingest({"checkurl": {"result": "malicious", "details": "URL in denylist"},
                            "ioc_url": {"verdict": "malicious",
                                        "data": {"domain_reputation": {"reputation_score": -0.3,
                                                                       "has_abuse_listing": False},
                                                 "threat_matches": [], "threat_reports": {"count": 0}}}})
    assert facts.get("cld_verdict") == "malicious"
    assert facts.get("cld_denylisted") == "URL in denylist"
    assert facts.get("cld_reputation_score") == "-0.3"
    assert "cld_verdict_note" not in facts                    # denylist = real evidence, no note
    assert not any("cld" in r for r in edges), "a CLD verdict must never be an edge"


def test_ingest_flags_empty_evidence_label():
    facts, _ = _ingest({"checkurl": {"result": "clean", "details": "not listed"},
                        "ioc_url": {"verdict": "malicious",
                                    "data": {"domain_reputation": {"reputation_score": -0.3,
                                                                   "has_abuse_listing": False},
                                             "threat_matches": [], "threat_reports": {"count": 0}}}})
    assert facts.get("cld_verdict") == "malicious"
    assert "cld_verdict_note" in facts, "an empty-evidence label must be flagged, not adopted silently"



def test_vn_whois_is_cld_primary_with_fallback():
    import whois_enrich as we
    routes = dict(_MALICIOUS)  # includes /external/checkwhois → registrar/owner/dates
    orig, fake = _install(routes)
    try:
        r = we._cld_vn_whois("example.vn", timeout=5)
    finally:
        wp_cld._api = orig
    assert r and r["registrar"] == "iNET" and r["registrant_name"] == "Test Co", r
    assert r["created"] == "2022-04-27 00:00:00 UTC" and r["source"] == "chongluadao", r   # DD-MM-YYYY → datetime
    assert fake.calls == [("GET", "/external/checkwhois")], fake.calls   # 1 call, not the 3 cld_domain fires
    # a non-.vn host is never routed to CLD whois (returns None → caller uses RDAP/WhoisXML)
    assert we._cld_vn_whois("example.com") is None


def test_keyed_whois_summary_vn_merge():
    """The keyed path (WhoisXML key present) backfills a .vn NO_DATA record from CLD: source must be
    a clean 'chongluadao' (not doubled) and the stale error must be cleared so the row renders."""
    import whois_enrich as we
    saved = {n: getattr(we, n) for n in ("_key", "whois_current", "whois_history", "rdap_lookup")}
    orig, _ = _install(dict(_MALICIOUS))
    try:
        we._key = lambda: "wx"
        we.whois_current = lambda d, timeout=40, keep_raw=True: {"error": "no WhoisRecord", "source": "whoisxml"}
        we.whois_history = lambda d, mode="purchase", timeout=40, keep_raw=True: {}
        we.rdap_lookup = lambda d, timeout=30, keep_raw=False: {"error": "no rdap"}
        out = we.whois_summary("example.vn", timeout=10)
    finally:
        for n, v in saved.items():
            setattr(we, n, v)
        wp_cld._api = orig
    assert out["source"] == "chongluadao", out          # not "chongluadao+chongluadao"
    assert "error" not in out, out                        # stale NO_DATA error cleared
    assert out["registrar"] == "iNET" and out["created"] == "2022-04-27 00:00:00 UTC", out


def test_cld_email_ioc():
    routes = dict(_MALICIOUS)
    # real CLD ioc/email shape: data.breaches / data.pastes / totals — no verdict field
    routes["/api/v1/ioc/external/email"] = (200, {"data": {
        "breaches": [{"name": "GameSalad", "domain": "gamesalad.com",
                      "breach_date": "2019-02-24", "is_verified": True}],
        "pastes": [], "total_breaches": 1, "total_pastes": 0}}, None)
    orig, fake = _install(routes)
    try:
        e = wp_cld.cld_email("owner@example.com", timeout=5)
        assert e and e.get("data", {}).get("breaches"), e
        assert fake.calls == [("POST", "/api/v1/ioc/external/email")], fake.calls
        assert wp_cld.cld_email("owner@example.com", free_only=True) is None   # metered gate
        assert wp_cld.cld_email("notanemail") is None
    finally:
        wp_cld._api = orig


def test_ingest_records_cld_email_fact():
    with tempfile.TemporaryDirectory() as tmp:
        kb = kbm.KB(os.path.join(tmp, "knowledge"))
        raw = {"meta": {"host": "example.com"}, "artifacts": {"title": "x"},
               "pivots": [
                   {"kind": "domain", "value": "example.com", "live_results": {}},
                   {"kind": "whois:registrant_email", "value": "owner@example.com",
                    "live_results": {"cld_email": {"data": {
                        "breaches": [{"name": "GameSalad", "is_verified": True}],
                        "pastes": [], "total_breaches": 1, "total_pastes": 0}}}},
               ]}
        p = os.path.join(tmp, "example.com.json")
        json.dump(raw, open(p, "w"))
        iw.ingest_file(kb, p)
        ent = next((e for e in kb.all_entities()
                    if e.get("type") == "email" and e.get("value") == "owner@example.com"), None)
        facts = {f["attribute"]: f["value"] for f in (ent or {}).get("facts", [])}
        conf = {f["attribute"]: f["confidence"] for f in (ent or {}).get("facts", [])}
        # exposure recorded as a FACT (never an edge); a verified breach is high confidence
        assert "GameSalad" in (facts.get("cld_email_exposure") or ""), (ent, facts)
        assert (conf.get("cld_email_exposure") or 0) >= 0.8, conf   # verified breach → high confidence
        assert not any("cld_email" in (e.get("rel") or "") for e in kb.edges()), "exposure must be a fact, not an edge"


def test_ingest_records_clean_email_exposure():
    """CLD asked and found no exposure → a low-confidence 'none' fact, so 'asked, clean' is not
    indistinguishable from 'never asked'."""
    with tempfile.TemporaryDirectory() as tmp:
        kb = kbm.KB(os.path.join(tmp, "knowledge"))
        raw = {"meta": {"host": "example.com"}, "artifacts": {"title": "x"},
               "pivots": [{"kind": "whois:registrant_email", "value": "clean@example.com",
                           "live_results": {"cld_email": {"data": {
                               "breaches": [], "pastes": [], "total_breaches": 0, "total_pastes": 0}}}}]}
        p = os.path.join(tmp, "example.com.json")
        json.dump(raw, open(p, "w"))
        iw.ingest_file(kb, p)
        ent = next((e for e in kb.all_entities()
                    if e.get("type") == "email" and e.get("value") == "clean@example.com"), None)
        facts = {f["attribute"]: f["value"] for f in (ent or {}).get("facts", [])}
        conf = {f["attribute"]: f["confidence"] for f in (ent or {}).get("facts", [])}
        assert facts.get("cld_email_exposure", "").startswith("none"), (ent, facts)
        assert (conf.get("cld_email_exposure") or 1) <= 0.5, conf   # clean result is low confidence


def test_vn_sidecar_self_heals():
    """An all-null `.vn` sidecar (written before CLD was the .vn-primary WHOIS source) self-heals on
    the next render: registrar/dates fill from CLD, and the purchased `history` block survives."""
    sys.path.insert(0, os.path.join(ROOT, "intel_engine", "tools"))
    import domain_table as dt
    with tempfile.TemporaryDirectory() as tmp:
        case = os.path.join(tmp, "case")
        os.makedirs(os.path.join(case, "whois"))
        sidecar = os.path.join(case, "whois", "example.vn.json")
        json.dump({"domain": "example.vn", "registrar": None, "created": None, "expires": None,
                   "name_servers": [], "source": "whoisxml",
                   "history": {"mode": "purchase", "count": 21, "records": []}}, open(sidecar, "w"))
        saved = dt.whois_summary
        dt.whois_summary = lambda d, history_mode="off": {
            "domain": d, "registrar": "iNET", "registrant_name": "X",
            "created": "2022-04-27 00:00:00 UTC", "expires": "2027-04-27 00:00:00 UTC",
            "name_servers": ["a.ns"], "source": "chongluadao", "history": {"records": []}}
        try:
            w = dt._whois_cached("example.vn", case, history_mode="off")
        finally:
            dt.whois_summary = saved
        assert w.get("registrar") == "iNET" and w.get("source") == "chongluadao", w
        assert (w.get("history") or {}).get("count") == 21, w          # purchased history preserved
        on_disk = json.load(open(sidecar))
        assert on_disk.get("registrar") == "iNET" and on_disk["history"]["count"] == 21, on_disk


def test_vn_sidecar_transient_failure_retries():
    """A transient failure — an exception OR an error response — must NOT stamp the sidecar: it stays
    byte-identical and retryable so the next render heals it, rather than freezing on a one-off 5xx."""
    sys.path.insert(0, os.path.join(ROOT, "intel_engine", "tools"))
    import domain_table as dt

    def _raise(d, history_mode="off"):
        raise RuntimeError("proxy tunnel failed")

    for stub in (_raise, lambda d, history_mode="off": {"domain": d, "error": "no WhoisRecord"}):
        with tempfile.TemporaryDirectory() as tmp:
            case = os.path.join(tmp, "case")
            os.makedirs(os.path.join(case, "whois"))
            sidecar = os.path.join(case, "whois", "example.vn.json")
            json.dump({"domain": "example.vn", "registrar": None, "created": None, "expires": None,
                       "name_servers": [], "source": "whoisxml",
                       "history": {"mode": "purchase", "count": 3, "records": []}}, open(sidecar, "w"))
            before = open(sidecar, "rb").read()
            saved = dt.whois_summary
            dt.whois_summary = stub
            try:
                w = dt._whois_cached("example.vn", case, history_mode="off")
            finally:
                dt.whois_summary = saved
            assert w.get("registrar") is None and "refetch_attempted" not in w, w   # not stamped → retryable
            assert open(sidecar, "rb").read() == before, "sidecar must be byte-identical on a transient failure"


_TESTS = [
    test_cld_domain_shape_and_vn_whois_and_gate,
    test_verdict_folds_denylist_into_evidence,
    test_ingest_records_facts_not_edges,
    test_ingest_flags_empty_evidence_label,
    test_vn_whois_is_cld_primary_with_fallback,
    test_keyed_whois_summary_vn_merge,
    test_cld_email_ioc,
    test_ingest_records_clean_email_exposure,
    test_ingest_records_cld_email_fact,
    test_vn_sidecar_self_heals,
    test_vn_sidecar_transient_failure_retries,
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
