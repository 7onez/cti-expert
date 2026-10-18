#!/usr/bin/env python3
"""Regression gate for the ONE certificate-transparency client (WebPivot/tools/wp_ct.py) and the
callers that judge on it (cert_overlap, fallback_probe, ct_monitor).

What it defends:
  * crt.sh's three outcomes are never conflated — `empty` (HTTP 200 `[]`) is authoritative and
    not retried away; `degraded` (web + PostgreSQL failed) is incomplete history, never "no
    certificates"; a merge where one sub-query failed is never `ok`.
  * strict fallback: backups run only when crt.sh is degraded or empty.
  * the completeness line: "Full CT history" only when crt.sh answered.
  * dedup: precert + final count once (serial for crt.sh, the twin key for sha256-only sources);
    day-only same-day twins never merge; short serials need the issuer.
  * truncation is recorded, never silent.
  * a degraded crt.sh turns cert_overlap / fallback_probe negatives into INCONCLUSIVE, and keeps
    ct_monitor from baselining on a partial listing.

Run:  python3 tests/test_ct_client.py
Fully offline: wp_ct._http, wp_ct._crtsh_pg and the clock are replaced. Synthetic data only.
"""
import contextlib
import json
import os
import sys
import tempfile
import urllib.error
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
ENGINE = os.path.join(HERE, "..", "intel_engine")
sys.path.insert(0, os.path.join(ENGINE, "WebPivot", "tools"))
sys.path.insert(0, os.path.join(ENGINE, "tools"))

import wp_ct  # noqa: E402

SEED = "site-a.example"
ISSUER = "C=US, O=Example Trust, CN=Example Issuing CA 1"


def _bad_gateway(url="https://crt.sh/"):
    return urllib.error.HTTPError(url, 502, "Bad Gateway", {}, None)


def crt_row(cid, serial, nb, na, names, issuer=ISSUER):
    return {"id": cid, "serial_number": serial, "not_before": nb, "not_after": na,
            "common_name": names[0], "name_value": "\n".join(names), "issuer_name": issuer}


def shodan_row(sha, nb_epoch, na_epoch, names, issuer_cn="Example Issuing CA 1"):
    return {"hash": sha, "subject_cn": names[0], "issuer_cn": issuer_cn,
            "not_before": nb_epoch, "not_after": na_epoch, "san_dns_names": names}


class Clock:
    def __init__(self):
        self.t = 1000.0

    def now(self):
        return self.t

    def sleep(self, s):
        self.t += s


class Net:
    """URL router standing in for wp_ct._http. `crtsh` maps a crt.sh search value to a body (str),
    an Exception, or a callable(attempt) returning either. Other hosts route by substring."""

    def __init__(self, crtsh=None, routes=None):
        self.crtsh = crtsh or {}
        self.routes = routes or {}
        self.calls = []
        self.attempts = {}

    def __call__(self, url, timeout, headers=None):
        self.calls.append(url)
        if url.startswith("https://crt.sh/"):
            q = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(url).query))
            value = q.get("q") or q.get("identity")
            n = self.attempts[value] = self.attempts.get(value, 0) + 1
            resp = self.crtsh.get(value, _bad_gateway())
            resp = resp(n) if callable(resp) else resp
        else:
            hits = [p for p in self.routes if p in url]
            resp = (self.routes[max(hits, key=len)] if hits    # most specific route wins
                    else urllib.error.URLError("no route"))
        if isinstance(resp, Exception):
            raise resp
        return resp if isinstance(resp, str) else json.dumps(resp)

    def hit(self, needle):
        return [u for u in self.calls if needle in u]


KEYED = ("certkit", "certindex", "netlas", "censys")


@contextlib.contextmanager
def fake(net, pg=(None, "PostgreSQL fallback skipped: psycopg not installed"), keyed=None):
    """Offline wp_ct: `net` answers HTTP, `pg` the PostgreSQL step, `keyed` maps a keyed source to
    a result dict (default: skipped-no-key). Yields (clock, calls) — calls lists keyed sources asked."""
    clock, calls = Clock(), []
    names = ["_http", "_crtsh_pg", "_sleep", "_now"] + [f"_{k}" for k in KEYED]
    saved = {n: getattr(wp_ct, n) for n in names}
    saved_breaker, saved_final = dict(wp_ct._BREAKER), dict(wp_ct._FINAL)
    wp_ct._http = net
    wp_ct._crtsh_pg = (pg if callable(pg) else (lambda d: pg))
    wp_ct._sleep, wp_ct._now = clock.sleep, clock.now
    wp_ct._BREAKER["web_down_until"] = 0.0
    wp_ct._FINAL.clear()
    for k in KEYED:
        res = (keyed or {}).get(k) or wp_ct._skip(k, "skipped-no-key")
        setattr(wp_ct, f"_{k}", (lambda r, k: lambda d: calls.append(k) or
                                 (r(d) if callable(r) else r))(res, k))
    try:
        yield clock, calls
    finally:
        for n, v in saved.items():
            setattr(wp_ct, n, v)
        wp_ct._BREAKER.clear()
        wp_ct._BREAKER.update(saved_breaker)
        wp_ct._FINAL.clear()
        wp_ct._FINAL.update(saved_final)


NO_BACKUPS = {"ctl.shodan.io": [], "api.certspotter.com": [], "crt.name": urllib.error.URLError("x"),
              "agniops": urllib.error.URLError("x")}
ROW_A = crt_row(101, "0a1b2c3d4e5f60718293a4b5c6d7e8f9", "2026-01-10T08:00:00", "2026-04-10T08:00:00",
                [SEED, "www." + SEED])


# ------------------------------------------------------------------ crt.sh outcomes
def test_crtsh_ok_never_asks_the_backups():
    net = Net({f"%.{SEED}": [ROW_A], SEED: []}, NO_BACKUPS)
    with fake(net):
        r = wp_ct.ct_search(SEED)
    assert r["ct_status"]["crt.sh"]["status"] == "ok", r["ct_status"]
    assert r["completeness"] == "full" and r["completeness_line"] == "Full CT history (crt.sh)"
    assert not net.hit("ctl.shodan.io") and not net.hit("certspotter"), net.calls


APEX_ONLY = crt_row(102, "0b1c2d3e4f5061728394a5b6c7d8e9f0", "2026-02-10T08:00:00",
                    "2026-05-10T08:00:00", [SEED])
AGG = {"crt.name": f"api.{SEED}\n", "agniops": f"mail.{SEED}\n"}


def test_apex_only_certificates_never_reach_the_aggregated_indexes():
    # crt.sh ok with apex-only certs: a CT answer, so the apex must not be disclosed to crt.name/agniops
    net = Net({f"%.{SEED}": [], SEED: [APEX_ONLY]}, dict(NO_BACKUPS, **AGG))
    with fake(net):
        r = wp_ct.ct_search(SEED)
    assert r["cert_total"] == 1 and r["subdomain_total"] == 0, r
    assert not net.hit("crt.name") and not net.hit("agniops"), net.calls
    assert "aggregated_subdomains" not in r
    # crt.sh degraded, a backup holds an apex-only cert: same rule
    routes = dict(NO_BACKUPS, **AGG, **{"ctl.shodan.io": [shodan_row("ab" * 32, 1790000000,
                                                                      1797776000, [SEED])]})
    net = Net({}, routes)
    with fake(net):
        r = wp_ct.ct_search(SEED)
    assert r["cert_total"] == 1 and not net.hit("crt.name") and not net.hit("agniops"), net.calls


def test_aggregated_indexes_run_only_after_the_whole_chain_found_nothing():
    net = Net({f"%.{SEED}": "[]", SEED: "[]"}, dict(NO_BACKUPS, **AGG))
    with fake(net) as (_, calls):
        r = wp_ct.ct_search(SEED)
    assert "censys" in calls, "aggregated indexes were asked before the Censys last resort"
    assert net.hit("crt.name") and net.hit("agniops"), net.calls
    assert r["aggregated_subdomains"] == [f"api.{SEED}", f"mail.{SEED}"]
    assert r["subdomains"] == [] and r["completeness"] == "full", r


def test_crtsh_empty_is_authoritative_and_not_retried():
    net = Net({f"%.{SEED}": "[]", SEED: "[]"}, NO_BACKUPS)
    with fake(net):
        r = wp_ct.ct_search(SEED)
    st = r["ct_status"]["crt.sh"]
    assert st["status"] == "empty" and st["attempts"] == 2, st
    assert r["completeness"] == "full" and "no certificates on record" in r["completeness_line"]
    assert "error" not in r


def test_crtsh_empty_with_backup_rows_reads_as_ingestion_lag():
    net = Net({f"%.{SEED}": "[]", SEED: "[]"},
              dict(NO_BACKUPS, **{"ctl.shodan.io/api/v1/domain/site-a.example/hostnames": [SEED],
                                  "ctl.shodan.io": [shodan_row("aa" * 32, 1790000000, 1797776000,
                                                               [SEED])]}))
    with fake(net):
        r = wp_ct.ct_search(SEED)
    assert r["completeness"] == "lag", r["completeness_line"]
    assert "ingestion lag" in r["completeness_line"]


def test_crtsh_degraded_with_backups_is_incomplete_not_none():
    routes = dict(NO_BACKUPS, **{
        "ctl.shodan.io/api/v1/domain/site-a.example/hostnames": ["api." + SEED],
        "ctl.shodan.io": [shodan_row("bb" * 32, 1790000000, 1797776000, [SEED])],
        "api.certspotter.com": [{"id": "77", "cert_sha256": "cc" * 32, "dns_names": [SEED],
                                 "issuer": {"name": ISSUER},
                                 "not_before": "2026-02-01T00:00:00Z",
                                 "not_after": "2026-05-02T00:00:00Z"}]})
    net = Net({}, routes)
    with fake(net):
        r = wp_ct.ct_search(SEED)
    assert r["ct_status"]["crt.sh"]["status"] == "degraded"
    assert r["completeness_line"] == "Incomplete: crt.sh unreachable; backups cover ~1 year"
    assert "error" not in r and r["cert_total"] == 2
    assert r["ct_status"]["shodan-ctl"]["window"] == "~1 year"
    assert {c["confidence"] for c in r["certs"]} == {"MEDIUM"}, r["certs"]


def test_degraded_without_any_backup_is_an_error_not_no_certificates():
    net = Net({}, {})
    with fake(net):
        r = wp_ct.ct_search(SEED)
    assert r.get("error") and "not 'no certificates'" in r["completeness_line"], r
    assert r["ct_status"]["shodan-ctl"]["status"] == "failed"
    assert r["ct_status"]["certspotter"]["status"] == "failed"


def test_partial_crtsh_merge_is_never_ok():
    net = Net({SEED: [ROW_A]}, NO_BACKUPS)          # %.d fails every attempt, apex answers
    with fake(net):
        r = wp_ct.crtsh_fetch(SEED)
    assert r["status"] == "degraded" and r["n"] == 1, r
    assert "partial" in r.get("note", "")


def test_postgres_fills_a_failed_web_subquery():
    pg_row = crt_row(202, "1f2e3d4c5b6a79881726354453627180", "2025-06-01 00:00:00",
                     "2025-08-30 00:00:00", ["mail." + SEED])
    net = Net({SEED: [ROW_A]}, NO_BACKUPS)
    with fake(net, pg=(lambda d: ([pg_row], None))):
        r = wp_ct.crtsh_fetch(SEED)
    assert r["status"] == "ok" and r["via"] == "web+pg" and r["n"] == 2, r


def test_backoff_walk_stays_inside_the_wall_clock_budget():
    budget = wp_ct.CRTSH["web_budget_seconds"]
    with fake(Net({})) as (clock, _):
        rows, err, attempts = wp_ct._crtsh_web("%." + SEED)
    assert rows is None and err == "HTTP 502" and attempts > 2
    assert clock.t - 1000.0 <= budget, clock.t
    net = Net({"%." + SEED: lambda n: [ROW_A] if n >= 3 else _bad_gateway()})
    with fake(net):
        rows, err, attempts = wp_ct._crtsh_web("%." + SEED)
    assert rows == [ROW_A] and err is None and attempts == 3


# ------------------------------------------------------------------ fallback chain (keyed)
def _keyed_row(source, sha, names=(SEED,)):
    """One distinct certificate per source: its own issuance second, so the precert/final twin key
    (issuer, validity, SANs) does not — correctly — fold them together."""
    sec = int(sha[:2], 16) % 60
    return {"source": source, "status": "complete", "window": wp_ct.WINDOWS.get(source),
            "rows": [_c(source, sha256=sha, issuer="Example Issuing CA 1", names=list(names),
                        not_before=f"2026-02-01T00:00:{sec:02d}Z",
                        not_after=f"2026-05-01T00:00:{sec:02d}Z")],
            "n": 1, "errors": []}


def test_keyed_sources_only_join_when_crtsh_has_nothing():
    keyed = {k: _keyed_row(k, f"{i:02x}" * 32) for i, k in enumerate(KEYED, 1)}
    with fake(Net({f"%.{SEED}": [ROW_A], SEED: []}, NO_BACKUPS), keyed=keyed) as (_, calls):
        wp_ct.ct_search(SEED)
    assert calls == [], calls


def test_netlas_only_on_crtsh_failure_never_on_authoritative_empty():
    keyed = {k: _keyed_row(k, f"{i:02x}" * 32) for i, k in enumerate(KEYED, 1)}
    with fake(Net({f"%.{SEED}": "[]", SEED: "[]"}, NO_BACKUPS), keyed=keyed) as (_, calls):
        r = wp_ct.ct_search(SEED)
    assert sorted(calls) == ["certindex", "certkit"], calls
    assert "netlas" not in r["ct_status"] and "censys" not in r["ct_status"]
    with fake(Net({}, NO_BACKUPS), keyed=keyed) as (_, calls):
        r = wp_ct.ct_search(SEED)
    assert sorted(calls) == ["certindex", "certkit", "netlas"], calls
    assert r["cert_total"] == 3 and r["completeness"] == "incomplete"


def test_free_only_skips_netlas_and_censys_but_not_certkit_certindex():
    keyed = {"certkit": _skip_row("certkit"), "certindex": _skip_row("certindex")}
    with fake(Net({}, NO_BACKUPS), keyed=keyed) as (_, calls):
        r = wp_ct.ct_search(SEED, free_only=True)
    assert sorted(calls) == ["certindex", "certkit"], calls
    assert r["ct_status"]["netlas"]["status"] == "skipped-free-only"
    assert r["ct_status"]["censys"]["status"] == "skipped-free-only"


def _skip_row(source):
    return {"source": source, "status": "complete", "window": None, "rows": [], "n": 0, "errors": []}


def test_censys_is_the_last_resort_only():
    keyed = {"censys": _keyed_row("censys", "ab" * 32)}
    with fake(Net({}, NO_BACKUPS), keyed=dict(keyed, certkit=_keyed_row("certkit", "cd" * 32))) as (_, calls):
        wp_ct.ct_search(SEED)
    assert "censys" not in calls, "Censys spent credits although CertKit had rows"
    with fake(Net({}, NO_BACKUPS), keyed=keyed) as (_, calls):
        r = wp_ct.ct_search(SEED)
    assert "censys" in calls and r["cert_total"] == 1
    assert "Incomplete" in r["completeness_line"]


def test_censys_page_walk_status_and_partial_is_asked_again():
    import wp_censys
    hit = {"kind": "certificate", "fingerprint_sha256": "ef" * 32, "names": [SEED, "lookalike-" + SEED],
           "issuer_cn": "Example Issuing CA 1", "not_before": "2026-01-01T00:00:00Z",
           "not_after": "2026-04-01T00:00:00Z", "serial_number_hex": "ab" * 10}
    cases = [({"hits": [hit], "total": 1, "more_pages": False}, "complete"),
             ({"hits": [hit], "total": 900, "more_pages": True}, "capped"),
             ({"hits": [hit], "total": 900, "more_pages": True, "page_error": {"error": "HTTP 500"}}, "partial"),
             ({"hits": [], "total": 0, "more_pages": False}, "complete"),
             ({"error": "HTTP 500", "http": 500}, "failed"),
             ({"skipped": "monthly budget spent"}, "skipped-quota")]
    saved = (wp_censys.censys_configured, wp_censys.censys_search)
    try:
        wp_censys.censys_configured = lambda: True
        for resp, want in cases:
            wp_censys.censys_search = lambda q, **k: resp
            r = wp_ct.censys_fetch(SEED)
            assert r["status"] == want, (resp, r["status"])
            if r["rows"]:
                assert r["rows"][0]["names"] == [SEED], "look-alike name survived the filter"
        n = []
        wp_censys.censys_search = lambda q, **k: n.append(1) or cases[2][0]
        wp_ct._FINAL.clear()
        wp_ct._memo(wp_ct.censys_fetch, "censys", SEED)
        wp_ct._memo(wp_ct.censys_fetch, "censys", SEED)
        assert len(n) == 2, "a partial Censys walk was memoised instead of asked again"
        wp_censys.censys_search = lambda q, **k: n.append(1) or cases[0][0]
        wp_ct._memo(wp_ct.censys_fetch, "censys", SEED)
        wp_ct._memo(wp_ct.censys_fetch, "censys", SEED)
        assert len(n) == 3, "a complete Censys walk was paid for twice in one run"
    finally:
        wp_censys.censys_configured, wp_censys.censys_search = saved
        wp_ct._FINAL.clear()


def test_netlas_name_filter_and_short_download():
    import wp_netlas
    doc = (lambda names, serial: {"data": {"certificate": {
        "names": names, "serial_number": serial, "fingerprint_sha256": None,
        "validity": {"start": "2014-03-01T00:00:00Z", "end": "2015-03-01T00:00:00Z"},
        "issuer": {"common_name": ["Example Issuing CA 1"]}, "subject": {"common_name": [names[0]]}}}})
    docs = [doc([SEED, "www." + SEED], "26263731215954453627226573386786054392"),
            doc(["one-" + SEED], "382098820814132449575243331397721652958180"),
            doc(["*." + SEED], "330025241826334010965943673745784206729409")]
    saved = (wp_netlas.netlas_configured, wp_netlas.count, wp_netlas._record, wp_ct._urlopen,
             wp_netlas.netlas_key)

    class _Resp:
        def __init__(self, body):
            self.body = body

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return self.body
    try:
        wp_netlas.netlas_configured = lambda: True
        wp_netlas._record = lambda *a, **k: None
        wp_ct._urlopen = lambda: (lambda req, timeout: _Resp(json.dumps(docs).encode()))
        wp_netlas.netlas_key = lambda: "synthetic-test-key"
        wp_netlas.count = lambda c, q, **k: {"count": 3}
        r = wp_ct.netlas_fetch(SEED)
        assert r["status"] == "complete" and r["n"] == 2, r
        assert "1 of 3 documents were look-alike" in r["note"]
        assert r["rows"][0]["serial"] == format(26263731215954453627226573386786054392, "x")
        wp_netlas.count = lambda c, q, **k: {"count": 6}
        r = wp_ct.netlas_fetch(SEED)
        assert r["status"] == "partial" and "short download: 3 of 6" in r["note"], r
    finally:
        (wp_netlas.netlas_configured, wp_netlas.count, wp_netlas._record, wp_ct._urlopen,
         wp_netlas.netlas_key) = saved


def test_certindex_spent_quota_is_skipped_not_waited_on():
    import wp_certindex
    saved = (wp_certindex.certindex_configured, wp_certindex.usage, wp_certindex._get)
    asked = []
    try:
        wp_certindex.certindex_configured = lambda: True
        wp_certindex._get = lambda p, params=None: asked.append(p) or (500, "unexpected")
        wp_certindex.usage = lambda: {"full_domain_left": 0, "monthly_left": 9000}
        r = wp_certindex.certindex_fetch(SEED)
        assert r["status"] == "skipped-quota" and not asked, (r, asked)
        wp_certindex.usage = lambda: {"full_domain_left": 2, "monthly_left": 9000}
        page = {"results": [{"sha256": "aa" * 32, "sans": [SEED], "issuer_cn": "Example Issuing CA 1",
                             "not_before": "2026-01-01T00:00:00Z", "not_after": "2026-04-01T00:00:00Z"}],
                "has_more": True, "coverage": {"basis": "domain_backfill_completed_v2"},
                "total_is_lower_bound": False}
        wp_certindex._get = lambda p, params=None: asked.append(p) or (200, page)
        r = wp_certindex.certindex_fetch(SEED)
        assert r["status"] == "capped" and len(asked) == 2, (r["status"], asked)
        page = dict(page, has_more=False, coverage={"basis": "domain_backfill_failed"},
                    total_is_lower_bound=True)
        r = wp_certindex.certindex_fetch(SEED)
        assert r["status"] == "partial" and "domain_backfill_failed" in r["note"], r
    finally:
        wp_certindex.certindex_configured, wp_certindex.usage, wp_certindex._get = saved


def test_certkit_csv_rows_keep_day_only_twins_and_drop_lookalikes():
    import wp_certkit
    csv_body = ("Not Before,Not After,Days Remaining,Common Name,SANs,Issuer Organization,"
                "Issuer Common Name,Serial Number,Wildcard\n"
                f"2026-09-26,2026-12-25,72,{SEED},*.{SEED}; {SEED},Example Trust,Example Issuing CA 3,"
                "1eee6aabb521d5e14fc315fd9985690,true\n"
                f"2026-09-26,2026-12-25,72,{SEED},*.{SEED}; {SEED},Example Trust,Example Issuing CA 3,"
                "62036c9f540965765e0ecc173cd1509c,true\n"
                f"2026-08-01,2026-10-30,15,shop-{SEED},shop-{SEED},Example Trust,Example Issuing CA 3,"
                "0abc,false\n")
    saved = (wp_certkit.certkit_configured, wp_certkit._load_session, wp_certkit._export)
    try:
        wp_certkit.certkit_configured = lambda: True
        wp_certkit._load_session = lambda: (object(), "coll-1")
        wp_certkit._export = lambda jar, coll, d: csv_body
        r = wp_certkit.certkit_fetch(SEED)
        assert r["status"] == "complete" and r["n"] == 2, r
        assert {c["date_precision"] for c in r["rows"]} == {"day"}
    finally:
        wp_certkit.certkit_configured, wp_certkit._load_session, wp_certkit._export = saved


def test_breaker_sends_later_seeds_straight_to_postgres():
    net = Net({}, NO_BACKUPS)
    pg_calls = []
    with fake(net, pg=(lambda d: pg_calls.append(d) or (None, "down"))):
        wp_ct.crtsh_fetch(SEED)
        before = len(net.hit("crt.sh"))
        r = wp_ct.crtsh_fetch("site-b.example")
    assert len(net.hit("crt.sh")) == before, "web retried while the breaker was open"
    assert pg_calls == [SEED, "site-b.example"] and r["status"] == "degraded"


# ------------------------------------------------------------------ dedup
def _c(source, **kw):
    return wp_ct._cert(source, **kw)


def test_precert_and_final_count_once_per_source():
    pre = crt_row(1, "00ab" + "cd" * 8, "2026-03-01T10:00:00", "2026-05-30T10:00:00", [SEED])
    fin = dict(pre, id=2)
    assert len(wp_ct.dedup_certs(wp_ct._crtsh_rows_to_certs([pre, fin]))) == 1
    sh = [_c("shodan-ctl", sha256=h, issuer="Example Issuing CA 1", names=[SEED],
             not_before=1790000000, not_after=1797776000) for h in ("dd" * 32, "ee" * 32)]
    assert len(wp_ct.dedup_certs(sh)) == 1, "Shodan precert/final twins were counted twice"


def test_same_certificate_across_sources_merges_and_grades_high():
    crt = wp_ct._crtsh_rows_to_certs([crt_row(5, "ab" * 9, "2026-03-01T10:00:00",
                                              "2026-05-30T10:00:00", [SEED])])[0]
    sh = _c("shodan-ctl", sha256="ff" * 32, issuer="Example Issuing CA 1", names=[SEED],
            not_before="2026-03-01T10:00:00Z", not_after="2026-05-30T10:00:00Z")
    out = wp_ct.dedup_certs([crt, sh])
    assert len(out) == 1 and set(out[0]["sources"]) == {"crt.sh", "shodan-ctl"}
    assert out[0]["sha256"] == "ff" * 32 and out[0]["crtsh_id"] == "5"
    assert out[0]["confidence"] == "HIGH"


def test_day_only_same_day_twins_never_merge():
    ecc = _c("certkit", serial="1eee6aabb521d5e14fc315fd9985690", issuer="Example Issuing CA 3",
             names=[SEED, "*." + SEED], not_before="2026-09-26", not_after="2026-12-25")
    rsa = _c("certkit", serial="62036c9f540965765e0ecc173cd1509c", issuer="Example Issuing CA 3",
             names=[SEED, "*." + SEED], not_before="2026-09-26", not_after="2026-12-25")
    assert len(wp_ct.dedup_certs([ecc, rsa])) == 2


def test_day_only_row_merges_into_the_richer_row_by_serial():
    day = _c("certkit", serial="0062036c9f540965765e0ecc173cd1509c", issuer="Example Issuing CA 3",
             names=[SEED], not_before="2026-09-26", not_after="2026-12-25")
    full = _c("netlas", serial="62036C9F540965765E0ECC173CD1509C", sha256="12" * 32,
              issuer="Example Issuing CA 3", names=[SEED],
              not_before="2026-09-26T22:09:26", not_after="2026-12-25T22:09:25")
    out = wp_ct.dedup_certs([day, full])
    assert len(out) == 1 and out[0]["date_precision"] == "second" and out[0]["sha256"]


def test_day_only_row_attaches_to_a_unique_sha256_only_twin():
    ecc_full = _c("shodan-ctl", sha256="a1" * 32, issuer="Example Issuing ECC CA 3", names=[SEED],
                  not_before="2026-09-26T22:49:11Z", not_after="2026-12-25T22:56:35Z")
    rsa_full = _c("shodan-ctl", sha256="b2" * 32, issuer="Example Issuing RSA CA 3", names=[SEED],
                  not_before="2026-09-26T22:09:26Z", not_after="2026-12-25T22:09:25Z")
    ecc_day = _c("certkit", serial="1eee6aabb521d5e14fc315fd9985690", issuer="Example Issuing ECC CA 3",
                 names=[SEED], not_before="2026-09-26", not_after="2026-12-25")
    rsa_day = _c("certkit", serial="62036c9f540965765e0ecc173cd1509c", issuer="Example Issuing RSA CA 3",
                 names=[SEED], not_before="2026-09-26", not_after="2026-12-25")
    out = wp_ct.dedup_certs([ecc_full, rsa_full, ecc_day, rsa_day])
    assert len(out) == 2 and all(len(c["sources"]) == 2 for c in out), out
    assert {c["serial"] for c in out} == {ecc_day["serial"], rsa_day["serial"]}
    # two same-day certs from ONE issuer: the day-only row cannot tell which it is → stays apart
    second = dict(ecc_full, sha256="c3" * 32, not_before="2026-09-26T10:00:00",
                  not_after="2026-12-25T10:00:00")
    assert len(wp_ct.dedup_certs([ecc_full, second, ecc_day])) == 3
    # two day-only rows with one candidate: neither attaches, so they never merge via the target
    twin_day = dict(ecc_day, serial="7f" * 16)
    assert len(wp_ct.dedup_certs([ecc_full, ecc_day, twin_day])) == 3


def test_short_serials_need_the_issuer_to_match():
    a = _c("netlas", serial="01", issuer="CN=Private CA A", names=["x." + SEED],
           not_before="2012-01-01", not_after="2013-01-01")
    b = _c("netlas", serial="01", issuer="CN=Private CA B", names=["y." + SEED],
           not_before="2012-01-01", not_after="2013-01-01")
    assert len(wp_ct.dedup_certs([a, b])) == 2
    assert len(wp_ct.dedup_certs([a, dict(a, sources=["censys"])])) == 1


# ------------------------------------------------------------------ truncation
def test_capped_listing_records_the_true_total():
    rows = [crt_row(1000 + i, f"{i + 1:032x}", f"2025-{1 + i % 12:02d}-{1 + i % 28:02d}T00:00:{i % 60:02d}",
                    "2026-12-31T00:00:00", [f"h{i}.{SEED}"]) for i in range(45)]
    net = Net({f"%.{SEED}": rows, SEED: []}, NO_BACKUPS)
    with fake(net):
        r = wp_ct.ct_search(SEED)
        full = wp_ct.ct_search(SEED, max_certs=None)
    cap = wp_ct.LISTING["max_certs"]
    assert r["truncated"] and r["cert_total"] == 45 and len(r["certs"]) == cap
    assert not full["truncated"] and len(full["certs"]) == 45
    assert r["subdomain_total"] == 45


# ------------------------------------------------------------------ judges on top
def test_cert_overlap_negative_needs_crtsh():
    import cert_overlap as CO
    saved = CO.wp_ct.ct_search
    try:
        for crt, verdict in (("degraded", "INCONCLUSIVE-CT-DEGRADED"), ("ok", "NO-CT-OVERLAP")):
            CO.wp_ct.ct_search = lambda d, **k: {
                "certs": [], "ct_status": {"crt.sh": {"status": crt}},
                "completeness_line": "synthetic"}
            r = CO.analyze([SEED, "site-b.example"])
            assert r["verdict"] == verdict, (crt, r["verdict"])
    finally:
        CO.wp_ct.ct_search = saved


def test_fallback_probe_cold_seed_on_degraded_crtsh_is_inconclusive():
    import fallback_probe as FP
    saved = (FP.crtsh, FP.wayback, FP.archive_is, FP.kb_lookup)
    try:
        FP.wayback = lambda d: {"ok": True, "captures": 0}
        FP.archive_is = lambda d: {"ok": True, "mementos": 0}
        FP.kb_lookup = lambda d, k: {"known": False, "attributed": False}
        for crt, verdict in (("degraded", "INCONCLUSIVE-CT-DEGRADED"), ("empty", "NO-PIVOT-YET")):
            FP.crtsh = lambda d: {"ok": True, "crtsh_status": crt, "completeness_line": "synthetic",
                                  "subdomains": [], "san_siblings": []}
            assert FP.probe(SEED, "knowledge")["verdict"] == verdict, crt
    finally:
        FP.crtsh, FP.wayback, FP.archive_is, FP.kb_lookup = saved


def test_ct_monitor_never_baselines_on_degraded_crtsh_and_keeps_legacy_state():
    import ct_monitor as CM
    cert = wp_ct.dedup_certs(wp_ct._crtsh_rows_to_certs([ROW_A]))[0]
    saved = CM.wp_ct.ct_search
    with tempfile.TemporaryDirectory() as tmp:
        state = os.path.join(tmp, "ct_state.json")
        try:
            CM.wp_ct.ct_search = lambda d, **k: {"certs": [], "completeness_line": "synthetic",
                                                  "ct_status": {"crt.sh": {"status": "degraded"}}}
            with contextlib.redirect_stderr(open(os.devnull, "w")):
                new, base = CM.watch([SEED], state)
            assert not new and not base and SEED not in CM.load_state(state)
            CM.save_state(state, {SEED: ["101"]})          # a pre-wp_ct state: bare crt.sh ids
            CM.wp_ct.ct_search = lambda d, **k: {"certs": [cert], "completeness_line": "synthetic",
                                                  "sources": ["crt.sh"],
                                                  "ct_status": {"crt.sh": {"status": "ok"}}}
            new, base = CM.watch([SEED], state)
            assert not new, "a cert already in a legacy state file alerted as new"
        finally:
            CM.wp_ct.ct_search = saved


_TESTS = [
    test_crtsh_ok_never_asks_the_backups,
    test_apex_only_certificates_never_reach_the_aggregated_indexes,
    test_aggregated_indexes_run_only_after_the_whole_chain_found_nothing,
    test_crtsh_empty_is_authoritative_and_not_retried,
    test_crtsh_empty_with_backup_rows_reads_as_ingestion_lag,
    test_crtsh_degraded_with_backups_is_incomplete_not_none,
    test_degraded_without_any_backup_is_an_error_not_no_certificates,
    test_partial_crtsh_merge_is_never_ok,
    test_postgres_fills_a_failed_web_subquery,
    test_backoff_walk_stays_inside_the_wall_clock_budget,
    test_breaker_sends_later_seeds_straight_to_postgres,
    test_precert_and_final_count_once_per_source,
    test_same_certificate_across_sources_merges_and_grades_high,
    test_day_only_same_day_twins_never_merge,
    test_day_only_row_merges_into_the_richer_row_by_serial,
    test_short_serials_need_the_issuer_to_match,
    test_capped_listing_records_the_true_total,
    test_cert_overlap_negative_needs_crtsh,
    test_fallback_probe_cold_seed_on_degraded_crtsh_is_inconclusive,
    test_ct_monitor_never_baselines_on_degraded_crtsh_and_keeps_legacy_state,
    test_keyed_sources_only_join_when_crtsh_has_nothing,
    test_netlas_only_on_crtsh_failure_never_on_authoritative_empty,
    test_free_only_skips_netlas_and_censys_but_not_certkit_certindex,
    test_censys_is_the_last_resort_only,
    test_censys_page_walk_status_and_partial_is_asked_again,
    test_netlas_name_filter_and_short_download,
    test_certindex_spent_quota_is_skipped_not_waited_on,
    test_certkit_csv_rows_keep_day_only_twins_and_drop_lookalikes,
    test_day_only_row_attaches_to_a_unique_sha256_only_twin,
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
    raise SystemExit(bool(_failed))
