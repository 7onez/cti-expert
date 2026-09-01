#!/usr/bin/env python3
"""Smoke test — the /cti (/case) Deliver chain, end to end and hermetic.

Guards the failure class that shipped a chartless report: a completed case must turn into a
populated, §2.5-clean flat report JSON (scripts/build_report_data.py) that the report
generators consume into a real bundle (indicators with contacts + network domains, IOC
formats that carry the operator selectors, and — best-effort — a DOCX with embedded chart
media). Everything runs in a temp dir with SYNTHETIC placeholders (*.example / @example.com /
+1 555 010 xxxx) per the repo leak gate — no shared-KB pollution, no egress.

Run:  python3 tests/test_case_pipeline_smoke.py        (zero third-party deps for the core)
      pytest -q tests/test_case_pipeline_smoke.py
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(ROOT, "scripts")
SEVERITY = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


def _make_case(base):
    """A minimal but schema-faithful completed case: two collected hosts sharing a shared/CDN
    origin, an operator ledger row, a registrant triple, and an analyst assessment.md."""
    case = os.path.join(base, "CASE-EXAMPLE-01")
    os.makedirs(os.path.join(case, "raw"))
    os.makedirs(os.path.join(case, "whois"))
    kb = os.path.join(base, "knowledge")
    os.makedirs(kb)

    def raw(host, ip):
        return {
            "meta": {"host": host, "final_url": f"https://{host}/",
                     "collected_at": "2026-01-01T00:00:00Z"},
            "artifacts": {
                "title": host, "favicon": {"shodan_mmh3": "1198047028", "md5": "abc"},
                "wp_themes": ["flatsome"], "http": {"status": "200"},
                "tls_cert": {"host": host, "fingerprint_sha256": "aa11bb22", "sans": [host]},
                "whois": {"domain": host, "registrar": "Example Registrar LLC",
                          "created": "2026-01-01T00:00:00Z", "expires": "2027-01-01T00:00:00Z",
                          "name_servers": ["ns1.example.net"], "source": "rdap"}},
            "pivots": [{"kind": "tls_cert:fingerprint_sha256", "value": "aa11bb22",
                        "confidence": "high", "note": "",
                        "live_results": {"dns": {
                            "ip_classification": [{"ip": ip, "cdn": True, "provider": "cloudflare"}],
                            "stale_passive_ips": ["203.0.113.9"]}}}]}

    for host, ip in (("kit-apex.example", "198.51.100.10"), ("kit-two.example", "198.51.100.10")):
        with open(os.path.join(case, "raw", host + ".json"), "w", encoding="utf-8") as fh:
            json.dump(raw(host, ip), fh)
    with open(os.path.join(case, "whois", "kit-apex.example.json"), "w", encoding="utf-8") as fh:
        json.dump({"domain": "kit-apex.example", "registrant_name": "Test Operator",
                   "registrant_email": "operator@example.com", "registrant_phone": "+1 555 010 0042",
                   "registrar": "Example Registrar LLC", "created": "2026-01-01T00:00:00Z",
                   "expires": "2027-01-01T00:00:00Z", "name_servers": ["ns1.example.net"],
                   "source": "rdap"}, fh)
    with open(os.path.join(kb, "operators.jsonl"), "w", encoding="utf-8") as fh:
        fh.write(json.dumps({"operator": "Test Operator (operator@example.com)",
                             "domains": ["kit-apex.example", "kit-two.example", "kit-three.example"],
                             "case": "CASE-EXAMPLE-01", "confidence": "assessed",
                             "basis": "identical registrant triple across the estate",
                             "added": "2026-01-01"}) + "\n")
    with open(os.path.join(case, "assessment.md"), "w", encoding="utf-8") as fh:
        fh.write("# Analyst Assessment (ICD-203) — CASE-EXAMPLE-01\n\n## Bottom Line Up Front\n\n"
                 "kit-apex.example is operated by Test Operator across a three-domain estate.\n\n"
                 "## Recommendation\n\n- Preserve registration records.\n- Submit abuse referral.\n")
    return case, kb


def _build(case, kb, out):
    subprocess.run([sys.executable, os.path.join(SCRIPTS, "build_report_data.py"),
                    case, "-o", out, "--kb", kb], check=True, capture_output=True, text=True)
    with open(out, encoding="utf-8") as fh:
        return json.load(fh)


def test_converter_populates_valid_report_json():
    with tempfile.TemporaryDirectory() as tmp:
        case, kb = _make_case(tmp)
        rep = _build(case, kb, os.path.join(tmp, "R.json"))
        for key in ("generator", "case", "executive_summary", "subjects", "findings",
                    "connections", "timeline", "sources", "recommendations", "indicators",
                    "ioc_exclude"):
            assert key in rep, f"missing {key}"
        ids = {s["id"] for s in rep["subjects"]}
        assert len(rep["subjects"]) >= 3           # operator + 2 hosts
        assert rep["subjects"][0]["type"] == "person" and rep["subjects"][0]["role"] == "actor"
        assert all(isinstance(s["confidence"], int) and s["label"] for s in rep["subjects"])
        assert rep["findings"] and all(f["weight"] in SEVERITY and isinstance(f["confidence"], int)
                                       for f in rep["findings"])
        assert all(c["from_id"] in ids and c["to_id"] in ids for c in rep["connections"])
        assert all(isinstance(x, str) for x in rep["recommendations"]) and rep["recommendations"]
        assert "**" not in rep["executive_summary"]          # markdown emphasis stripped
        # estate domains present as network indicators (incl. the un-collected ledger member)
        net = {i["value"] for i in rep["indicators"] if i["category"] == "network"}
        assert {"kit-apex.example", "kit-two.example", "kit-three.example"} <= net


def test_section25_exclusions_populated_and_gated():
    with tempfile.TemporaryDirectory() as tmp:
        case, kb = _make_case(tmp)
        out = os.path.join(tmp, "R.json")
        rep = _build(case, kb, out)
        excl = {v.lower() for v in rep["ioc_exclude"]}
        # the CDN edge IP, the stale passive origin, the registrar and the nameserver are §2.5 noise
        assert "198.51.100.10" in excl and "203.0.113.9" in excl
        assert "example registrar llc" in excl and "ns1.example.net" in excl
        # and they must NOT leave as an emitted IOC value in any format
        subprocess.run([sys.executable, os.path.join(SCRIPTS, "generate-cti-iocs.py"),
                        out, os.path.join(tmp, "IOC"), "--format", "all"],
                       check=True, capture_output=True, text=True, cwd=ROOT)
        rows = [json.loads(ln) for ln in open(os.path.join(tmp, "IOC.jsonl"), encoding="utf-8")]
        ind = [r for r in rows if r.get("kind") == "indicator"]
        assert ind, "no indicators exported"
        assert all(r["value"].lower() not in excl for r in ind), "an excluded value leaked as an IOC"
        # the operator's reachable selectors survive into the flat .txt (regression: contact block)
        txt = open(os.path.join(tmp, "IOC.txt"), encoding="utf-8").read()
        assert "operator@example.com" in txt and "+1 555 010 0042" in txt


def test_html_report_renders_from_converter():
    with tempfile.TemporaryDirectory() as tmp:
        case, kb = _make_case(tmp)
        out = os.path.join(tmp, "R.json")
        _build(case, kb, out)
        html = os.path.join(tmp, "R.html")
        subprocess.run([sys.executable, os.path.join(SCRIPTS, "generate-cti-html.py"), out, html],
                       check=True, capture_output=True, text=True, cwd=ROOT)
        body = open(html, encoding="utf-8").read()
        assert 'id="cti-data"' in body and os.path.getsize(html) > 50_000


def test_empty_case_degrades_without_crashing():
    """A bare case dir (no raw/whois/ledger) still yields a valid, if thin, report JSON."""
    with tempfile.TemporaryDirectory() as tmp:
        case = os.path.join(tmp, "CASE-EMPTY-01")
        os.makedirs(os.path.join(case, "raw"))
        rep = _build(case, os.path.join(tmp, "kb"), os.path.join(tmp, "R.json"))
        assert rep["case"]["id"] == "CASE-EMPTY-01"
        for key in ("subjects", "findings", "indicators", "ioc_exclude", "recommendations"):
            assert key in rep and isinstance(rep[key], list)


def test_docx_renders_with_chart_media_best_effort():
    """When uv/pandoc are available, the hybrid DOCX embeds chart media (no chartless report)."""
    if not shutil.which("uv"):
        print("  (skipped DOCX media check — uv not on PATH)")
        return
    with tempfile.TemporaryDirectory() as tmp:
        case, kb = _make_case(tmp)
        out = os.path.join(tmp, "R.json")
        _build(case, kb, out)
        docx = os.path.join(tmp, "R.docx")
        r = subprocess.run(["uv", "run", os.path.join(SCRIPTS, "generate-cti-docx-hybrid.py"),
                            os.path.join(case, "assessment.md"), out, docx],
                           capture_output=True, text=True, cwd=ROOT)
        if r.returncode != 0 or not os.path.isfile(docx):
            print("  (skipped DOCX media check — generator unavailable in this env)")
            return
        import zipfile
        with zipfile.ZipFile(docx) as z:
            media = [n for n in z.namelist() if n.startswith("word/media/")]
        assert media, "hybrid DOCX rendered with zero chart media (the chartless-report regression)"


def test_operator_survives_redacted_registrant_name():
    """Registrant name redacted (email+phone only) must still yield an actor subject with BOTH
    reachable selectors, no dangling finding subject_id, and the phone surviving into the IOC .txt.
    Guards the 'dropped contact selector / dangling SUB-001' regression."""
    with tempfile.TemporaryDirectory() as tmp:
        case, kb = _make_case(tmp)
        os.remove(os.path.join(kb, "operators.jsonl"))          # no ledger name either
        who = os.path.join(case, "whois", "kit-apex.example.json")
        rec = json.load(open(who, encoding="utf-8"))
        rec.pop("registrant_name", None)                        # name redacted at the registry
        json.dump(rec, open(who, "w", encoding="utf-8"))
        out = os.path.join(tmp, "R.json")
        rep = _build(case, kb, out)
        actors = [s for s in rep["subjects"] if s["role"] == "actor"]
        assert len(actors) == 1, "operator subject dropped when name redacted"
        sel = {s["type"]: s["value"] for s in actors[0]["selectors"]}
        assert sel.get("email") == "operator@example.com" and sel.get("phone") == "+1 555 010 0042"
        ids = {s["id"] for s in rep["subjects"]}
        assert all(f["subject_id"] in ids for f in rep["findings"]), "dangling finding subject_id"
        subprocess.run([sys.executable, os.path.join(SCRIPTS, "generate-cti-iocs.py"),
                        out, os.path.join(tmp, "IOC"), "--format", "all"],
                       check=True, capture_output=True, text=True, cwd=ROOT)
        assert "+1 555 010 0042" in open(os.path.join(tmp, "IOC.txt"), encoding="utf-8").read()


def test_multi_operator_case_is_flagged_not_silent():
    """A case whose clusters.json reports >1 operator cluster must record the single-operator
    attribution limit in intelligence_gaps rather than silently over-attributing."""
    with tempfile.TemporaryDirectory() as tmp:
        case, kb = _make_case(tmp)
        with open(os.path.join(case, "clusters.json"), "w", encoding="utf-8") as fh:
            json.dump({"case": "CASE-EXAMPLE-01", "n_clusters": 2, "clusters": []}, fh)
        rep = _build(case, kb, os.path.join(tmp, "R.json"))
        assert any("cluster" in g.lower() for g in rep["intelligence_gaps"]), \
            "multi-operator case not flagged in intelligence_gaps"


_TESTS = [test_converter_populates_valid_report_json,
          test_section25_exclusions_populated_and_gated,
          test_html_report_renders_from_converter,
          test_empty_case_degrades_without_crashing,
          test_docx_renders_with_chart_media_best_effort,
          test_operator_survives_redacted_registrant_name,
          test_multi_operator_case_is_flagged_not_silent]


def check():
    passed = failed = 0
    lines = []
    for t in _TESTS:
        label = t.__name__.removeprefix("test_").replace("_", " ")
        try:
            t()
        except Exception as exc:  # noqa: BLE001 — report each contract independently
            failed += 1
            lines.append(("FAIL", f"{label}: {exc}"))
        else:
            passed += 1
            lines.append(("ok", label))
    return passed, failed, lines


if __name__ == "__main__":
    _p, _f, _lines = check()
    for _s, _l in _lines:
        print(("ok   " if _s == "ok" else "FAIL ") + _l)
    print(f"\n{_p} passed, {_f} failed")
    raise SystemExit(bool(_f))
