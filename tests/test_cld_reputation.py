"""Regression: the ChongLuaDao reputation layer (wp_cld) and its KB ingest.

  1. cld_domain returns checkurl + ioc_url + Shield ransomware/clickfix, adds a whois leg ONLY
     for .vn, and returns None under free_only / no key (metered gate).
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
        assert set(b) == {"checkurl", "ioc_url", "ransomware", "clickfix", "phaas",
                          "internal_leaks", "denylist", "whois"}, b
        assert set(wp_cld.cld_domain("example.com", timeout=5)) == {
            "checkurl", "ioc_url", "ransomware", "clickfix", "phaas", "internal_leaks", "denylist"}
        # CLD is unlimited — no free-only spend gate (cld_domain has no free_only param anymore).
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
        assert ("POST", "/api/v1/ioc/external/email") in fake.calls
        assert ("GET", "/external/checkburneremail") in fake.calls
        # CLD is unlimited — cld_email runs regardless of spend posture (no free_only param).
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


def _load_cld():
    """A fresh cld_api module (its own ledger state), deterministic classifier."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "cld_api_under_test", os.path.join(ROOT, "scripts", "cld", "cld_api.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod._classify = None
    mod.POLL_INTERVAL = 0
    return mod


class _CliEnv:
    """Process env for one synthetic CLI run: key present/absent, ledger in a temp file, no .env."""
    _NAMES = ("CHONGLUADAO_API_KEY", "CLD_API_KEY", "CHONGLUADAO_KEY", "BURNER_API_KEY",
              "API_USAGE_LOG", "CTI_API_KEYS_ENV", "WP_CASE_DIR")

    def __init__(self, tmp, key="k"):
        self.log = os.path.join(tmp, "api_usage.jsonl")
        self.key, self.tmp = key, tmp

    def __enter__(self):
        self.saved = {n: os.environ.get(n) for n in self._NAMES}
        for n in self._NAMES:
            os.environ.pop(n, None)
        os.environ["API_USAGE_LOG"] = self.log
        os.environ["CTI_API_KEYS_ENV"] = os.path.join(self.tmp, "absent.env")
        os.environ["WP_CASE_DIR"] = os.path.join(self.tmp, "CASE-LEDGER")
        if self.key:
            os.environ["CHONGLUADAO_API_KEY"] = self.key
        return self

    def __exit__(self, *exc):
        for n, v in self.saved.items():
            if v is None:
                os.environ.pop(n, None)
            else:
                os.environ[n] = v

    def rows(self):
        if not os.path.isfile(self.log):
            return []
        with open(self.log, encoding="utf-8") as fh:
            return [json.loads(line) for line in fh if line.strip()]


def _run_cli(mod, argv, responder):
    """Run cld_api.main(argv) with the wire stubbed BELOW the ledger → (exit, envelope, wire calls)."""
    import contextlib
    import io
    wire = []

    def http(method, base, path, key, params, body, timeout):
        wire.append((base, path))
        return responder(base, path, body)

    mod._http = http
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = mod.main(argv)
    text = out.getvalue().strip()
    return code, (json.loads(text) if text else None), wire


def test_cli_route_ledgers_every_leg_once():
    """`route` (the MCP default) ledgers each HTTP leg it sends — not one row per route — and a
    rejected leg is ledgered with ok=false / 0 credits while the envelope keeps its partial."""
    mod = _load_cld()

    def responder(base, path, body):
        if base == mod.FEEDS:
            return 500, None, "HTTP 500"
        return 200, {"items": []}, None

    with tempfile.TemporaryDirectory() as tmp, _CliEnv(tmp) as env:
        code, envelope, wire = _run_cli(mod, ["route", "https://example.com"], responder)
        rows = env.rows()
    assert code == 0 and envelope["ok"] is True, envelope
    assert envelope["result"]["sides"]["feeds_checkurl"]["ok"] is False, envelope
    actions = [r["action"] for r in rows]
    assert sorted(actions) == sorted([
        "feeds:checkurl", "ti:ransomware", "ti:clickfix", "ti:phaas", "ti:internal-leaks",
        "ti:ioc/url"]), actions
    assert len(rows) == len(wire), (rows, wire)          # one ledger row per wire call, no more
    by = {r["action"]: r for r in rows}
    assert by["feeds:checkurl"]["ok"] is False and by["feeds:checkurl"]["credits"] == 0, by
    assert all(r["credits"] == 0 and r["ok"] for a, r in by.items() if a.startswith("ti:")), by
    assert {r["provider"] for r in rows} == {"chongluadao"}
    assert {r["case"] for r in rows} == {"CASE-LEDGER"}, rows
    usage = envelope["usage"]
    assert usage["calls"] == 6 and usage["billable_units"] == 0 and usage["basis"] == "unlimited", usage
    assert usage["by_tier"]["feeds"] == {"calls": 1, "billable_units": 0}, usage


def test_cli_direct_and_async_ledger_per_request():
    """A direct op ledgers once; an async job ledgers its start and every status poll. CLD is
    unlimited so every unit is 0 (still one ledger row per call). With the reference missing, the
    conservative fallback prices every call at 1 (never silently free)."""
    polls = {"n": 0}

    def responder(base, path, body):
        if path.endswith("/start"):
            return 200, {"job_id": "job-1"}, None
        if path.endswith("/poll"):
            polls["n"] += 1
            return 200, {"status": "done" if polls["n"] >= 2 else "running"}, None
        return 200, {"verdict": "clean"}, None

    mod = _load_cld()
    with tempfile.TemporaryDirectory() as tmp, _CliEnv(tmp) as env:
        code, envelope, wire = _run_cli(mod, ["ioc", "url", "https://example.com"], responder)
        assert code == 0 and len(wire) == 1, (code, wire)
        code, envelope, wire = _run_cli(mod, ["leaked-accounts", "user@example.com"], responder)
        rows = env.rows()
    assert code == 0 and envelope["ok"] is True, envelope
    assert [(r["action"], r["credits"]) for r in rows] == [
        ("ti:ioc/url", 0), ("ti:leaked-accounts/start", 0),
        ("ti:leaked-accounts/poll", 0), ("ti:leaked-accounts/poll", 0)], rows
    assert envelope["usage"]["calls"] == 3 and envelope["usage"]["polls"] == 2, envelope["usage"]

    polls["n"] = 0
    mod = _load_cld()
    mod._USAGE_REF = os.path.join(ROOT, "scripts", "cld", "absent-usage.json")
    with tempfile.TemporaryDirectory() as tmp, _CliEnv(tmp) as env:
        _run_cli(mod, ["leaked-accounts", "user@example.com"], responder)
        rows = env.rows()
    assert [r["credits"] for r in rows] == [1, 1, 1], rows      # conservative fallback


def test_no_key_preflight_and_library_calls_ledger_nothing():
    """No key (exit 3), a failed pre-flight, and a route skip send nothing and ledger nothing; an
    importer calling `_request` directly (wp_cld keeps its own accounting) is never double-ledgered."""
    mod = _load_cld()
    with tempfile.TemporaryDirectory() as tmp, _CliEnv(tmp, key=None) as env:
        code, envelope, wire = _run_cli(mod, ["route", "https://example.com"], lambda *a: (200, {}, None))
        assert code == 3 and wire == [] and env.rows() == [], (code, wire)
    mod = _load_cld()
    with tempfile.TemporaryDirectory() as tmp, _CliEnv(tmp) as env:
        code, _, wire = _run_cli(mod, ["clickfix"], lambda *a: (200, {}, None))
        assert code == 2 and wire == [] and env.rows() == [], (code, wire)
        code, envelope, wire = _run_cli(mod, ["route", "John Smith"], lambda *a: (200, {}, None))
        assert code == 0 and envelope["skipped"] is True and wire == [], envelope
        assert envelope["usage"]["calls"] == 0 and env.rows() == [], envelope
    lib = _load_cld()
    lib._http = lambda *a: (200, {"ok": True}, None)
    with tempfile.TemporaryDirectory() as tmp, _CliEnv(tmp) as env:
        assert lib._request("POST", lib.FEEDS, "/external/checkurl", "k")[0] == 200
        assert env.rows() == [] and lib.usage_summary() is None


def test_route_queries_both_apis_and_keeps_a_partial():
    import argparse
    mod = _load_cld()
    calls = []

    def ok(method, base, path, key, params=None, body=None, timeout=30):
        calls.append((base, path))
        if path.endswith("/victims"):
            return 200, {"items": [{"website": "other.example"}, {"website": "https://example.com"}]}, None
        return 200, {"ok": True}, None

    mod._request = ok
    a = argparse.Namespace(target="https://example.com", ai=False, timeout=5)
    _name, tup = mod.op_route("k", a)
    bases = {c[0] for c in calls}
    paths = [c[1] for c in calls]
    assert mod.FEEDS in bases and mod.TI in bases, calls
    assert "/external/checkurl" in paths, paths
    assert "/api/v1/ioc/external/url" in paths, paths
    assert "/api/v1/ransomware/external/victims" in paths, paths
    assert tup[1]["sides"]["shield_ransomware"]["matched"] == 1
    assert tup[1]["sides"]["shield_ransomware"]["hit"] is True

    def feeds_down(method, base, path, key, params=None, body=None, timeout=30):
        if base == mod.FEEDS:
            return 500, None, "HTTP 500"
        return 200, {"verdict": "clean"}, None

    mod._request = feeds_down
    _name, tup = mod.op_route("k", a)
    assert tup[0] == 200 and tup[1]["sides"]["shield_ioc"]["ok"], tup
    assert tup[1]["sides"]["feeds_checkurl"]["ok"] is False


def test_denylist_label_boundary_estate_vs_lead():
    """(#14) A brand-label denylist row is matched on a DNS-label boundary, never a raw substring:
    an IPFS-gateway host with the label embedded inside an opaque CID subdomain must never match
    (even though a naive substring check WOULD); the case's own apex is estate evidence, a
    different apex sharing the same wordmark is a name-similar LEAD, never a cluster member."""
    cid_host = "bafyzntbrandxuhm123456789abc.ipfs.dweb.link"
    assert "brandx" in cid_host, "sanity: the CID host DOES contain the label as a raw substring"
    routes = dict(_MALICIOUS)
    routes["/external/denylists/search"] = (200, {"items": [
        {"domain": "brandx.example", "status": "scam"},          # estate (case apex)
        {"domain": "shop.brandx.test", "status": "scam"},        # name-similar lead (diff apex)
        {"domain": cid_host},                                    # must NOT match — no label boundary
    ]}, None)
    orig, _ = _install(routes)
    try:
        out = wp_cld.cld_domain("brandx.example", timeout=5, page_title="BrandX - Home")
    finally:
        wp_cld._api = orig
    dl = out["denylist"]
    assert "brandx" in dl["labels_searched"], dl["labels_searched"]
    estate_hosts = {r["_matched_host"] for r in dl["estate"]}
    lead_hosts = {r["_matched_host"] for r in dl["leads"]}
    assert estate_hosts == {"brandx.example"}, dl
    assert lead_hosts == {"shop.brandx.test"}, dl
    assert cid_host not in (estate_hosts | lead_hosts), dl
    # a raw substring check WOULD have matched the CID row — proving the boundary rule is load-bearing
    assert not wp_cld._label_boundary_match("brandx", cid_host)


def test_cld_whois_all_null_is_miss():
    """(#15) An all-null CLD checkwhois body (no registrar, dates, owner, or NS) is a MISS, not an
    answer — cld_whois must say so instead of handing back a confirmed empty-registrant WHOIS, so
    the caller (whois_enrich) falls back to RDAP/port-43 instead of trusting a null CLD record."""
    sys.path.insert(0, os.path.join(ROOT, "scripts", "cld"))
    import cld_api as real_api
    orig_api, orig_request = wp_cld._api, real_api._request
    os.environ["CHONGLUADAO_API_KEY"] = "k"
    wp_cld._api = lambda: real_api
    try:
        real_api._request = lambda method, base, path, key, params=None, body=None, timeout=30: (
            200, {"registrar": None, "owner": None, "registration_date": None, "name_servers": []}, None)
        r = wp_cld.cld_whois("example.vn", timeout=5)
        assert r.get("miss") is True, r
        assert "RDAP" in r.get("reason", ""), r

        real_api._request = lambda method, base, path, key, params=None, body=None, timeout=30: (
            200, {"registrar": "iNET", "owner": "Test Co", "registration_date": "27-04-2022"}, None)
        r2 = wp_cld.cld_whois("example.vn", timeout=5)
        assert "miss" not in r2, r2
        assert r2.get("registrar") == "iNET", r2
    finally:
        wp_cld._api = orig_api
        real_api._request = orig_request


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
    test_route_queries_both_apis_and_keeps_a_partial,
    test_denylist_label_boundary_estate_vs_lead,
    test_cld_whois_all_null_is_miss,
    test_cli_route_ledgers_every_leg_once,
    test_cli_direct_and_async_ledger_per_request,
    test_no_key_preflight_and_library_calls_ledger_nothing,
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
