#!/usr/bin/env python3
"""Regression gate for the CT + pivot-hit REPORTING contract (WebPivot/tools/wp_related.py), as
printed by every renderer: assessment.md (evidence_report), the house report, REPORT.json
(build_report_data) and /cert-pivot's graded hits.

What it defends:
  * a degraded CT lookup reads "Incomplete" with each source's status and window — never "Full CT
    history", never a bare zero; a collection made before per-source status reads "not recorded".
  * a pivot hit (host sharing a cert / favicon / tracking ID) is a RELATED host graded by agreeing
    origin checks: 1 = LOW, 2 = MEDIUM probable origin, 3+ = HIGH; an edge address is never an
    origin however many checks agree; an unreachable probe is `not run`, never a `fail`.
  * a pivot-hit IP never reaches hosting / abuse output, even when its IP raw (with an abuse
    contact) sits in the case.
  * IP co-hosting reverses and JARM hits are not pivot hits.

Run:  python3 tests/test_ct_reporting.py
Fully offline. Synthetic data only: *.example hosts, RFC 5737 addresses, CASE-0001.
"""
import contextlib
import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for p in (os.path.join(ROOT, "intel_engine", "WebPivot", "tools"), os.path.join(ROOT, "intel_engine", "tools"),
          os.path.join(ROOT, "scripts"), os.path.join(ROOT, "scripts", "webpivot"), os.path.join(ROOT, "tests")):
    if p not in sys.path:
        sys.path.insert(0, p)

import wp_related as WR  # noqa: E402
import wp_origin_history as OH  # noqa: E402
import evidence_report as ER  # noqa: E402

SEED = "seed-brand.example.com"
LEAF = "ab" * 32
DEGRADED = {"ct_status": {"crt.sh": {"status": "degraded", "window": "full CT history", "n": 0,
                                     "errors": ["web: HTTP 502"]},
                          "shodan-ctl": {"status": "failed", "window": "~1 year", "n": 0},
                          "certspotter": {"status": "failed", "window": "~1 year", "n": 0},
                          "certindex": {"status": "skipped-quota", "window": "~1 year", "n": 0}},
            "completeness": "incomplete",
            "completeness_line": ("Incomplete: crt.sh unreachable and no backup answered — CT history "
                                  "was not collected (this is not 'no certificates')"),
            "cert_total": 0, "cert_count": 0, "certs": [], "subdomains": [], "total": 0,
            "error": "crt.sh unreachable"}
# address → wp_origin_history.classify status (RFC 5737 space is really bogon; the stub stands in
# for routable origins and a CDN edge)
CLASS = {"192.0.2.10": "origin", "192.0.2.20": "origin", "192.0.2.30": "origin", "203.0.113.5": "cdn",
         "192.0.2.99": "origin"}


@contextlib.contextmanager
def classified():
    saved = OH.classify
    OH.classify = lambda ip, asn=None, org=None: {"status": CLASS.get(ip, "bogon"), "provider": None,
                                                  "why": "test stub"}
    try:
        yield
    finally:
        OH.classify = saved


def _raw(host=SEED, ct=None, dns_ips=(), extra=(), leaf=True):
    lr = {"dns": {"ips": list(dns_ips)}}
    if ct is not None:
        lr["crtsh"] = ct
    art = {"tls_cert": {"fingerprint_sha256": LEAF, "issuer": "C=US, O=Example Trust, CN=Example CA 1",
                        "sans": [host, "*." + host]}} if leaf else {}
    return {"meta": {"host": host}, "artifacts": art,
            "pivots": [{"kind": "domain", "value": host, "live_results": lr}] + list(extra)}


def _hits():
    return [
        {"kind": "tls_cert:fingerprint_sha256", "value": LEAF, "live_results": {
            "shodan_search": {"total": 1, "matches": [{"ip_str": "192.0.2.10", "hostnames": ["box.other.example"],
                                                       "timestamp": "2026-09-30T10:00:00"}]}}},
        {"kind": "favicon_hash", "value": "123456789", "live_results": {
            "zoomeye": {"total": 3, "hosts": [{"host": "kit.example", "ip": "192.0.2.20", "timestamp": "2026-09-28"},
                                              {"host": "edge.example", "ip": "203.0.113.5"}]},
            "hunterhow": {"total": 1, "hosts": [{"domain": "probe.example", "ip": "192.0.2.30"}]},
            "origin_probe": {"192.0.2.30": {"ran": True, "match": True, "status": 200}}}},
        {"kind": "tls_jarm", "value": "2ad2ad0002ad2ad", "live_results": {
            "shodan_search": {"total": 1, "matches": [{"ip_str": "192.0.2.40"}]}}},
    ]


# ------------------------------------------------------------------ CT completeness
def test_degraded_ct_reads_incomplete_with_per_source_status():
    md = ER.render_cluster_report([_raw(ct=DEGRADED)], case="CASE-0001")
    sec = md.split("## Certificate Transparency — completeness")[1].split("\n## ")[0]
    assert "Incomplete: crt.sh unreachable" in sec and "Full CT history" not in sec, sec
    assert "| crt.sh | degraded | 0 | full CT history |" in sec, sec
    assert "| certindex | skipped-quota | 0 | ~1 year |" in sec, sec
    gaps = md.split("## Intelligence Gaps")[1]
    assert "Certificate history for seed-brand.example.com: Incomplete" in gaps
    assert "crt.sh" in gaps.split("unqueried / failed:")[1], "degraded crt.sh missing from the gap"


def test_pre_contract_collection_reads_not_recorded_never_zero():
    old = {"query": "%." + SEED, "total": 2, "subdomains": ["a." + SEED], "cert_count": 5, "certs": []}
    s = WR.ct_summary(WR.ct_of(_raw(ct=old)))
    assert s["completeness"] == "unknown" and "not recorded" in s["completeness_line"], s
    assert "not 'no certificates'" in s["completeness_line"]


def test_full_crtsh_answer_needs_no_source_table():
    full = dict(DEGRADED, ct_status={"crt.sh": {"status": "ok", "window": "full CT history", "n": 7}},
                completeness="full", completeness_line="Full CT history (crt.sh)", cert_total=7)
    lines = WR.ct_md({SEED: WR.ct_summary(full)})
    assert any("Full CT history (crt.sh)" in l for l in lines)
    assert not any(l.startswith("Per-source status") for l in lines)
    assert WR.ct_gap_lines({SEED: WR.ct_summary(full)}) == []


# ------------------------------------------------------------------ related hosts
def test_pivot_hits_are_graded_by_agreeing_origin_checks():
    with classified():
        rows = {r["ip"]: r for r in WR.related_hosts(_raw(dns_ips=["192.0.2.10"], extra=_hits()))}
    # cert hit on the target's own non-CDN leaf, in its DNS history, outside CDN ranges → 3 checks
    assert rows["192.0.2.10"]["passed"] == ["cert_san", "history", "non_cdn"], rows["192.0.2.10"]
    assert rows["192.0.2.10"]["rung"] == "origin (HIGH)" and rows["192.0.2.10"]["scan_date"] == "2026-09-30"
    # Host-header probe matched + outside CDN ranges → 2 checks
    assert rows["192.0.2.30"]["rung"] == "probable origin (MEDIUM)", rows["192.0.2.30"]
    # favicon hit, only outside CDN ranges → 1 check
    assert rows["192.0.2.20"]["rung"] == "lead (LOW)" and rows["192.0.2.20"]["checks"]["host_header"] == "not run"
    # a CDN edge is never an origin
    assert rows["203.0.113.5"]["rung"].startswith("edge"), rows["203.0.113.5"]
    assert "192.0.2.40" not in rows, "a JARM hit was reported as a shared-value related host"


def test_ip_cohosting_reverse_is_not_a_pivot_hit():
    raw = _raw()
    raw["pivots"][0]["live_results"]["fofa_ip_reverse"] = {"total": 1, "results": [["co.example", "192.0.2.10"]]}
    assert WR.related_hosts(raw) == []


def test_an_edge_never_promotes_even_when_every_other_check_agrees():
    passed, rung = WR.grade({"host_header": "pass", "cert_san": "pass", "history": "pass", "non_cdn": "fail"})
    assert len(passed) == 3 and rung.startswith("edge"), rung


def test_cert_pivot_unreachable_probe_is_not_run_and_hits_are_graded():
    import cert_pivot as CP
    hits = [{"engine": "shodan", "matched_ip": "192.0.2.20", "matched_host": "", "scan_date": "2026-10-01"},
            {"engine": "censys", "matched_ip": "203.0.113.5", "matched_host": "edge.example"}]
    leaf = {"fingerprint_sha256": LEAF, "issuer": "CN=Example CA 1", "sans": [SEED]}
    probe = {"192.0.2.20": {"ran": False, "match": False, "error": "OSError: refused"},
             "203.0.113.5": {"ran": True, "match": True, "status": 200}}
    with classified():
        rows = {r["ip"]: r for r in CP.grade_hits(SEED, LEAF, hits, leaf, probe)}
    assert rows["192.0.2.20"]["checks"]["host_header"] == "not run", rows["192.0.2.20"]
    assert rows["192.0.2.20"]["rung"] == "probable origin (MEDIUM)"      # cert_san + non_cdn
    assert rows["203.0.113.5"]["rung"].startswith("edge")


# ------------------------------------------------------------------ /cert-pivot egress rails
@contextlib.contextmanager
def _no_dial():
    """Any socket the probe/leaf path opens is a test failure — the leak this guards against."""
    import cert_pivot as CP
    import socket as _socket
    dialed = []
    saved = (_socket.create_connection, CP.socket.create_connection)

    def _boom(addr, *a, **k):
        dialed.append(addr)
        raise AssertionError(f"dialed {addr}")
    _socket.create_connection = CP.socket.create_connection = _boom
    try:
        yield dialed
    finally:
        _socket.create_connection, CP.socket.create_connection = saved


@contextlib.contextmanager
def _audit(hostile):
    import cert_pivot as CP
    audit = CP._harness_module("audit")
    saved = (audit.record, audit._ENV_HOSTILE)
    audit.record = lambda *a, **k: None                  # hermetic: no ledger writes
    audit._ENV_HOSTILE = hostile
    env = {k: os.environ.pop(k) for k in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy",
                                          "ALL_PROXY", "all_proxy", "WP_CASE_DIR", "INTEL_CASE")
           if k in os.environ}
    try:
        yield audit
    finally:
        audit.record, audit._ENV_HOSTILE = saved
        os.environ.pop("HTTPS_PROXY", None)
        os.environ.update(env)


def _run_with_hits(**kw):
    import cert_pivot as CP
    saved = (CP.shodan_pivot, CP.censys_pivot)
    CP.shodan_pivot = lambda *a, **k: ([{"engine": "shodan", "matched_ip": "192.0.2.20",
                                          "matched_host": "", "scan_date": "2026-10-01"}], None)
    CP.censys_pivot = lambda *a, **k: ([], None)
    try:
        return CP.run(domain=SEED, sha256=LEAF, use_crtsh=False, **kw)
    finally:
        CP.shodan_pivot, CP.censys_pivot = saved


def test_passive_cert_pivot_never_dials_and_reads_not_run():
    with _audit(hostile=False), _no_dial() as dialed, classified():
        r = _run_with_hits(passive=True)
    assert not dialed and r["egress"]["allowed"] is False and r["origin_probe"] == {}
    row = r["related_hosts"][0]
    assert row["checks"]["host_header"] == "not run" and row["checks"]["cert_san"] == "not run", row


def test_missing_proxy_layer_refuses_live_contact_never_direct():
    import cert_pivot as CP
    saved = CP._proxy_layer
    CP._proxy_layer = lambda: None
    try:
        with _audit(hostile=False), _no_dial() as dialed, classified():
            r = _run_with_hits()
            try:
                CP._egress_socket("192.0.2.20", 443, 5)
                raised = False
            except OSError:
                raised = True
    finally:
        CP._proxy_layer = saved
    assert raised and not dialed, "no proxy layer must refuse, not dial direct"
    assert r["egress"]["allowed"] is False and "proxy layer" in r["egress"]["reason"]
    assert r["related_hosts"][0]["checks"]["host_header"] == "not run"


def test_hostile_posture_denies_live_contact_unless_a_proxy_routes_it():
    import cert_pivot as CP
    with _audit(hostile=True) as audit, _no_dial() as dialed, classified():
        r = _run_with_hits()
        assert not dialed and r["egress"]["allowed"] is False, r["egress"]
        assert "HOSTILE" in r["egress"]["reason"]
        # MCP-level gate: the tool itself is outbound — denied bare, allowed passive or proxied
        assert audit.decide("cert_pivot", {"domain": SEED}, hostile=True)[0] is False
        assert audit.decide("cert_pivot", {"domain": SEED, "passive": True}, hostile=True)[0] is True
        os.environ["HTTPS_PROXY"] = "http://192.0.2.1:3128"
        ok, _why = CP.egress_gate(SEED)
    assert ok, "a configured proxy must satisfy the hostile egress rule"


def test_bare_ip_rows_are_ips_and_the_targets_own_names_are_not_related():
    raw = _raw(extra=[{"kind": "tls_cert:fingerprint_sha256", "value": LEAF, "live_results": {
        "validin_cert": {"total": 3, "hosts": ["192.0.2.20", "www." + SEED, "other.example"]}}}])
    with classified():
        rows = WR.related_hosts(raw)
    assert {(r["host"], r["ip"]) for r in rows} == {(None, "192.0.2.20"), ("other.example", None)}, rows
    ip_row = next(r for r in rows if r["ip"])
    assert ip_row["checks"]["non_cdn"] == "pass", "an IP-only row was never graded"


# ------------------------------------------------------------------ renderers
def _house_case(tmp, dns_ips):
    import test_house_report_compose as T
    case = T._synthetic_case(tmp)
    raw = _raw(dns_ips=dns_ips, extra=[{"kind": "favicon_hash", "value": "123456789", "live_results": {
        "zoomeye": {"total": 1, "hosts": [{"host": "kit.example", "ip": "192.0.2.99", "timestamp": "2026-09-28"}]}}}],
        ct=DEGRADED)
    json.dump(raw, open(os.path.join(case, "raw", SEED + ".json"), "w"))
    json.dump({"meta": {"host": "192.0.2.99", "kind": "ip"}, "pivots": [], "artifacts": {"ip_intel": {
        "ipinfo": {"asn": "AS64500", "org_name": "Example Hoster", "abuse": {"email": "abuse@hoster.example"}}}}},
        open(os.path.join(case, "raw", "192.0.2.99.json"), "w"))
    return T._compose(case)[1]


def test_pivot_hit_ip_never_reaches_the_house_report_hosting_or_abuse():
    with tempfile.TemporaryDirectory() as tmp, classified():
        md = _house_case(tmp, dns_ips=[])
    assert "abuse@hoster.example" not in md, "a pivot-hit IP's abuse contact reached the report"
    hosting = md.split("## Historical origin hosting")[1].split("\n## ")[0] if "## Historical origin hosting" in md else ""
    assert "192.0.2.99" not in hosting, "a pivot-hit IP was listed as hosting"
    rel = md.split("## Related hosts (unverified)")[1].split("\n#")[0]
    assert "192.0.2.99" in rel and "lead (LOW)" in rel, rel
    assert "ZoomEye" not in rel and "web-scan index" in rel, "Rule 12: vendor name in the deliverable"
    ct = md.split("## Certificate transparency — completeness")[1].split("\n## ")[0]
    assert "crt.sh" not in ct, "Rule 12: CT vendor name in the deliverable"
    assert "Incomplete: certificate transparency unreachable" in ct and "CT log search (full history)" in ct, ct
    # positive control: the SAME address in the target's own resolution IS hosting, with its abuse
    # contact — so the absence above is the pivot-hit rule, not a renderer that prints nothing
    with tempfile.TemporaryDirectory() as tmp, classified():
        md = _house_case(tmp, dns_ips=["192.0.2.99"])
    hosting = md.split("## Historical origin hosting")[1].split("\n## ")[0]
    assert "192.0.2.99" in hosting and "abuse@hoster.example" in hosting, hosting


def test_report_json_carries_ct_history_and_related_hosts_as_gaps_not_hosting():
    import build_report_data as brd
    import test_build_report_data_privacy as P
    with tempfile.TemporaryDirectory() as tmp, classified():
        case, kb = P._case(tmp, P._REAL_WHOIS)
        raw = _raw("seed.example.com", ct=DEGRADED, extra=_hits())
        json.dump(raw, open(os.path.join(case, "raw", "seed.example.com.json"), "w"))
        r = brd.build(case, kb)
    assert r["ct_history"]["seed.example.com"]["completeness"] == "incomplete", r["ct_history"]
    assert any(g.startswith("Certificate history for seed.example.com: Incomplete") for g in r["intelligence_gaps"])
    ips = {h["ip"] for h in r["related_hosts"]}
    assert {"192.0.2.10", "192.0.2.20", "192.0.2.30", "203.0.113.5"} <= ips, ips
    assert any("None is the estate's hosting" in g for g in r["intelligence_gaps"])
    iocs = {i["value"] for i in r["indicators"]}
    assert not ({"192.0.2.20", "203.0.113.5", "kit.example"} & iocs), "a pivot hit became an IOC"


_TESTS = [
    test_degraded_ct_reads_incomplete_with_per_source_status,
    test_pre_contract_collection_reads_not_recorded_never_zero,
    test_full_crtsh_answer_needs_no_source_table,
    test_pivot_hits_are_graded_by_agreeing_origin_checks,
    test_ip_cohosting_reverse_is_not_a_pivot_hit,
    test_bare_ip_rows_are_ips_and_the_targets_own_names_are_not_related,
    test_an_edge_never_promotes_even_when_every_other_check_agrees,
    test_cert_pivot_unreachable_probe_is_not_run_and_hits_are_graded,
    test_passive_cert_pivot_never_dials_and_reads_not_run,
    test_missing_proxy_layer_refuses_live_contact_never_direct,
    test_hostile_posture_denies_live_contact_unless_a_proxy_routes_it,
    test_pivot_hit_ip_never_reaches_the_house_report_hosting_or_abuse,
    test_report_json_carries_ct_history_and_related_hosts_as_gaps_not_hosting,
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
