"""Regression: build_report_data.py must never promote a registrar privacy/role address to the
operator identity. A seed whose current WHOIS shows `abuse@<registrar>` (GoDaddy's privacy
placeholder) or `REDACTED FOR PRIVACY` produces NO actor e-mail IOC, NO 'registrant-triple'
finding and no 'verified' operator subject; a real registrant e-mail still does. Synthetic data
only: example.com hosts, CASE-0001, a temp knowledge dir."""
import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import build_report_data as brd  # noqa: E402


def _case(tmp, whois, ledger=None, scope=None):
    engine = os.path.join(tmp, "engine")
    case = os.path.join(engine, "cases", "CASE-0001")
    for d in ("raw", "whois"):
        os.makedirs(os.path.join(case, d))
    kb = os.path.join(engine, "knowledge")
    os.makedirs(kb)
    hosts = ["seed.example.com", "sibling.example.com", "zz-candidate.example.com"]
    for h in hosts:
        json.dump({"meta": {"host": h, "fetched_with": "urllib", "collected_at": "2026-01-01T00:00:00Z"},
                   "artifacts": {"title": h, "http": {"status": 200}}, "pivots": []},
                  open(os.path.join(case, "raw", h + ".json"), "w"))
        json.dump(dict(whois, domain=h), open(os.path.join(case, "whois", h + ".json"), "w"))
    open(os.path.join(case, "assessment.md"), "w", encoding="utf-8").write(
        "# Analyst Assessment (ICD-203) — synthetic\n\n## Bottom Line Up Front\n\ntext\n")
    if ledger:
        with open(os.path.join(kb, "operators.jsonl"), "w", encoding="utf-8") as fh:
            fh.write(json.dumps(ledger, ensure_ascii=False) + "\n")
    if scope:
        json.dump(scope, open(os.path.join(case, "scope.json"), "w"))
    return case, kb


_PRIVACY_WHOIS = {"registrant_name": "REDACTED FOR PRIVACY", "registrant_email": "abuse@godaddy.com",
                  "registrant_phone": None, "registrar": "GoDaddy.com, LLC",
                  "created": "2020-07-15 00:00:00 UTC", "name_servers": ["ns1.example.net"]}
_REAL_WHOIS = dict(_PRIVACY_WHOIS, registrant_name="Test Persona",
                   registrant_email="persona@example.com", registrant_phone="+1.2025550100")


def _build(whois):
    with tempfile.TemporaryDirectory() as tmp:
        case, kb = _case(tmp, whois)
        return brd.build(case, kb)


def test_privacy_placeholder_is_not_an_operator_identity():
    r = _build(_PRIVACY_WHOIS)
    actor_emails = [i["value"] for i in r["indicators"] if i["type"] == "email" and i.get("role") == "actor"]
    assert actor_emails == [], f"privacy address leaked as actor IOC: {actor_emails}"
    assert not any("registrant-triple" in f.get("tags", []) for f in r["findings"]), \
        "FND-001 registrant-triple finding minted from a privacy placeholder"
    actors = [s for s in r["subjects"] if s.get("role") == "actor"]
    assert not any(s.get("verified") for s in actors), "operator marked verified on a privacy address"
    assert not any("abuse@godaddy.com" in json.dumps(s, ensure_ascii=False) for s in actors)
    assert not any("REDACTED" in json.dumps(s, ensure_ascii=False) for s in actors)
    assert any("registrant triple" in g.lower() for g in r["intelligence_gaps"]), \
        "missing-registrant gap not stated"


def test_real_registrant_still_drives_the_operator_subject():
    r = _build(_REAL_WHOIS)
    actor_emails = [i["value"] for i in r["indicators"] if i["type"] == "email" and i.get("role") == "actor"]
    assert actor_emails == ["persona@example.com"], actor_emails
    assert any("registrant-triple" in f.get("tags", []) for f in r["findings"])
    sub = next(s for s in r["subjects"] if s["id"] == "SUB-001")
    assert sub["label"] == "Test Persona" and sub["verified"] is True


def test_fallback_detector_matches_registrar_roles_when_engine_absent():
    with tempfile.TemporaryDirectory() as tmp:
        chk = brd._privacy_checker(os.path.join(tmp, "not-an-engine", "cases", "CASE-0001"))
        assert chk("abuse@example-registrar.com") and chk("REDACTED FOR PRIVACY") and chk("")
        assert chk("Registration Private") and chk("proxy@withheldforprivacy.com")
        assert not chk("persona@example.com") and not chk("Test Persona")


def test_engine_predicate_is_the_one_used_in_production():
    """The synthetic engine has no WebPivot/tools, so the cases above run on the fallback; this one
    swaps in the real whois_enrich.is_privacy so a change to it is caught here too."""
    sys.path.insert(0, os.path.join(ROOT, "intel_engine", "WebPivot", "tools"))
    from whois_enrich import is_privacy  # noqa: E402
    orig = brd._privacy_checker
    brd._privacy_checker = lambda _case_dir: is_privacy
    try:
        r = _build(_PRIVACY_WHOIS)
        assert not [i for i in r["indicators"] if i["type"] == "email" and i.get("role") == "actor"]
        r = _build(_REAL_WHOIS)
        assert [i["value"] for i in r["indicators"] if i["type"] == "email" and i.get("role") == "actor"] \
            == ["persona@example.com"]
    finally:
        brd._privacy_checker = orig


_LEDGER = {"operator": "Example Co (owner@example.com)", "domains": ["seed.example.com", "sibling.example.com"],
           "case": "CASE-0001", "confidence": "assessed", "basis": "synthetic", "added": "2026-01-01"}


def test_ledger_identity_is_not_written_as_a_registrant_triple():
    with tempfile.TemporaryDirectory() as tmp:
        case, kb = _case(tmp, _PRIVACY_WHOIS, ledger=_LEDGER)
        r = brd.build(case, kb)
    sub = next(s for s in r["subjects"] if s["id"] == "SUB-001")
    assert sub["label"] == "Example Co", sub["label"]
    f1 = next(f for f in r["findings"] if f["id"] == "FND-001")
    assert "registrant-triple" not in f1["tags"] and "ledger" in f1["tags"], f1
    assert "recurs across" not in f1["description"], f1["description"]
    # a collected host the ledger does not list is a candidate edge, not a confirmed one
    strength = {c["to_id"]: c["strength"] for c in r["connections"] if c["from_id"] == "SUB-001"}
    by_label = {s["id"]: s["label"] for s in r["subjects"]}
    strengths = {by_label[k]: v for k, v in strength.items()}
    assert strengths["sibling.example.com"] == "confirmed" and strengths["zz-candidate.example.com"] == "probable", strengths
    # not a benign_check case: the operator selector stays an actor IOC
    assert "owner@example.com" not in r["ioc_exclude"]


def test_benign_check_keeps_identity_selectors_out_of_the_ioc_feed():
    with tempfile.TemporaryDirectory() as tmp:
        case, kb = _case(tmp, _PRIVACY_WHOIS, ledger=_LEDGER, scope={"target_class": "benign_check"})
        r = brd.build(case, kb)
    assert {"owner@example.com", "owner", "Example Co"} <= set(r["ioc_exclude"]), r["ioc_exclude"]
    sub = next(s for s in r["subjects"] if s["id"] == "SUB-001")
    assert {"type": "email", "value": "owner@example.com"} in sub["selectors"], "identity must stay in the narrative"
    fp = next(f for f in r["findings"] if "false-positive-control" in f["tags"])
    assert "owner@example.com" not in fp["description"], "an e-mail is not a shared/CDN origin"


_TESTS = [
    test_privacy_placeholder_is_not_an_operator_identity,
    test_real_registrant_still_drives_the_operator_subject,
    test_fallback_detector_matches_registrar_roles_when_engine_absent,
    test_engine_predicate_is_the_one_used_in_production,
    test_ledger_identity_is_not_written_as_a_registrant_triple,
    test_benign_check_keeps_identity_selectors_out_of_the_ioc_feed,
]


def check():
    passed = failed = 0
    lines = []
    for test in _TESTS:
        label = test.__name__.removeprefix("test_").replace("_", " ")
        try:
            test()
        except Exception as exc:  # noqa: BLE001 — report every independent contract
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
