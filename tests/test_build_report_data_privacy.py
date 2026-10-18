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
    assert {"owner@example.com", "owner"} <= set(r["ioc_exclude"]), r["ioc_exclude"]
    assert "Example Co" not in r["ioc_exclude"], "the operator's name is not infrastructure noise"
    sub = next(s for s in r["subjects"] if s["id"] == "SUB-001")
    assert {"type": "email", "value": "owner@example.com"} in sub["selectors"], "identity must stay in the narrative"
    fp = next(f for f in r["findings"] if "false-positive-control" in f["tags"])
    assert "owner@example.com" not in fp["description"], "an e-mail is not a shared/CDN origin"



_ORG_WHOIS = {"registrant_name": "Nguyen Van A", "registrant_org": "Legit Trading Co Ltd",
              "registrant_email": "ops@legittrading.example", "registrant_phone": "+84.987654321",
              "registrar": "Example Registrar LLC", "created": "2025-09-09 00:00:00 UTC",
              "name_servers": ["ns1.example.net"]}


def test_organization_subject_registered_relationship_and_selector_indicators():
    """Org registrant -> organization subject + legal_representative attribute (not a relationship);
    a nominee/front alternative marked CANNOT RULE OUT keeps every connection `registered`, never
    `operates`; assessment-asserted selectors and a CLD denylist URL become indicators, but a
    report_exclude.json value never does, however it was named."""
    with tempfile.TemporaryDirectory() as tmp:
        case, kb = _case(tmp, _ORG_WHOIS)
        json.dump({
            "attribution_level": "same-operator estate (rung 1)",
            "alternatives": ["Nominee registrant — CANNOT RULE OUT: no KYC corroboration"],
            "evidence": ["E1 [A1] Registrant e-mail ops@legittrading.example recurs — WhoisXML lookup",
                         "E2 [B2] Off-store app host app-store-mirror.example serves the same kit"],
            "cluster": [{"domain": "seed.example.com",
                         "shared_artifacts": ["domain:excluded-partner.example"]}],
        }, open(os.path.join(case, "assessment.json"), "w"))
        json.dump(["excluded-partner.example"], open(os.path.join(case, "report_exclude.json"), "w"))
        seed_raw = os.path.join(case, "raw", "seed.example.com.json")
        raw = json.load(open(seed_raw))
        raw["meta"]["final_url"] = "https://seed.example.com/scam"
        raw["pivots"] = [{"kind": "domain", "value": "seed.example.com",
                          "live_results": {"cld": {"checkurl": {"result": "malicious"}}}}]
        json.dump(raw, open(seed_raw, "w"))
        r = brd.build(case, kb)
    sub = next(s for s in r["subjects"] if s["id"] == "SUB-001")
    assert sub["type"] == "organization" and sub["label"] == "Legit Trading Co Ltd", sub
    assert sub.get("attributes", {}).get("legal_representative") == "Nguyen Van A", sub
    assert not any(c["relationship"] == "operates" for c in r["connections"]), r["connections"]
    assert all(c["relationship"] == "registered" for c in r["connections"]
              if c["from_id"] == "SUB-001" and c["strength"] != "possible"), r["connections"]
    ind_values = {i["value"] for i in r["indicators"]}
    assert "https://seed.example.com/scam" in ind_values, ind_values      # CLD denylist row
    assert "app-store-mirror.example" in ind_values, ind_values           # evidence-line selector
    assert "excluded-partner.example" not in ind_values, ind_values       # report_exclude wins


def test_no_operator_default_summary_never_claims_attribution():
    """With no analyst BLUF and no operator identity (privacy-masked WHOIS, no ledger), the default
    summary must not say the seed "is attributed to a single operator" — it used to, even for an
    all-failed collection or an empty case."""
    with tempfile.TemporaryDirectory() as tmp:
        case, kb = _case(tmp, _PRIVACY_WHOIS)
        os.remove(os.path.join(case, "assessment.md"))           # no analyst BLUF → default text
        for h in ("seed.example.com", "sibling.example.com"):
            p = os.path.join(case, "raw", h + ".json")
            raw = json.load(open(p))
            raw["meta"]["live_error"] = "timeout"
            json.dump(raw, open(p, "w"))
        r = brd.build(case, kb)
    s = r["executive_summary"]
    assert "attributed to" not in s, s
    assert "No operator identity was recovered" in s and "2 unreachable" in s, s


def test_operator_default_summary_still_attributes():
    with tempfile.TemporaryDirectory() as tmp:
        case, kb = _case(tmp, _REAL_WHOIS)
        os.remove(os.path.join(case, "assessment.md"))
        r = brd.build(case, kb)
    s = r["executive_summary"]
    assert "is attributed to Test Persona" in s, s


def _links(r):
    label = {s["id"]: s["label"] for s in r["subjects"]}
    return {label[c["to_id"]]: (c["relationship"], c["strength"])
            for c in r["connections"] if c["from_id"] == "SUB-001"}


def test_only_hosts_sharing_the_registrant_are_confirmed():
    """A collected host whose OWN record names a different real registrant is related_to/possible,
    a privacy-masked one stays probable, and FND-001 counts only hosts that carry the identity —
    it used to wire every collected host operates/confirmed and count the whole estate."""
    with tempfile.TemporaryDirectory() as tmp:
        case, kb = _case(tmp, _REAL_WHOIS)
        other = dict(_REAL_WHOIS, domain="sibling.example.com", registrant_name="Other Person",
                     registrant_email="someone.else@example.net", registrant_phone="+1.2025550199")
        json.dump(other, open(os.path.join(case, "whois", "sibling.example.com.json"), "w"))
        json.dump(dict(_PRIVACY_WHOIS, domain="zz-candidate.example.com"),
                  open(os.path.join(case, "whois", "zz-candidate.example.com.json"), "w"))
        r = brd.build(case, kb)
    links = _links(r)
    assert links["seed.example.com"][1] == "confirmed", links
    assert links["sibling.example.com"] == ("related_to", "possible"), links
    assert links["zz-candidate.example.com"][1] == "probable", links
    f1 = next(f for f in r["findings"] if f["id"] == "FND-001")
    assert "recurs across 1 current domain(s)" in f1["description"], f1["description"]


def test_hosts_carrying_the_registrant_phone_are_confirmed():
    with tempfile.TemporaryDirectory() as tmp:
        case, kb = _case(tmp, _REAL_WHOIS)
        phone_only = dict(_REAL_WHOIS, domain="sibling.example.com", registrant_email=None,
                          registrant_phone="+1 202-555-0100")          # same number, other format
        json.dump(phone_only, open(os.path.join(case, "whois", "sibling.example.com.json"), "w"))
        r = brd.build(case, kb)
    links = _links(r)
    assert all(v[1] == "confirmed" for v in links.values()), links
    f1 = next(f for f in r["findings"] if f["id"] == "FND-001")
    assert "recurs across 3 current domain(s)" in f1["description"], f1["description"]


def _hop_case(tmp, state=None):
    """kit-apex (hop 0) + kit-two (hop 1) recorded in state.json; `absent.example` was collected but
    is in no hop — the probe case where the two report generators disagreed."""
    engine = os.path.join(tmp, "engine")
    case = os.path.join(engine, "cases", "CASE-0001")
    for d in ("raw", "whois"):
        os.makedirs(os.path.join(case, d))
    kb = os.path.join(engine, "knowledge")
    os.makedirs(kb)
    for h in ("kit-apex.example", "kit-two.example", "absent.example"):
        json.dump({"meta": {"host": h, "fetched_with": "urllib", "collected_at": "2026-01-01T00:00:00Z"},
                   "artifacts": {"title": h, "http": {"status": 200}}, "pivots": []},
                  open(os.path.join(case, "raw", h + ".json"), "w"))
        json.dump(dict(_REAL_WHOIS, domain=h), open(os.path.join(case, "whois", h + ".json"), "w"))
    json.dump({"seed": "kit-apex.example"}, open(os.path.join(case, "scope.json"), "w"))
    open(os.path.join(case, "assessment.md"), "w", encoding="utf-8").write(
        "# Analyst Assessment (ICD-203) — synthetic\n\n## Bottom Line Up Front\n\ntext\n")
    if state is not None:
        json.dump(state, open(os.path.join(case, "state.json"), "w"))
    return case, kb


_HOP_STATE = {"hops": {"kit-apex.example": 0, "kit-two.example": 1}, "expansion_depth": 2}


def test_host_absent_from_hops_is_a_leaf_not_infrastructure():
    with tempfile.TemporaryDirectory() as tmp:
        case, kb = _hop_case(tmp, _HOP_STATE)
        r = brd.build(case, kb)
    sub = {s["label"]: s for s in r["subjects"] if s.get("type") == "domain"}
    absent = sub["absent.example"]
    assert absent["role"] == "related" and absent.get("ioc_exclude") is True, absent
    assert absent.get("hop") == 2, absent
    ioc_domains = {i["value"] for i in r["indicators"] if i["type"] == "domain"}
    assert "absent.example" not in ioc_domains, ioc_domains
    assert {"kit-apex.example", "kit-two.example"} <= ioc_domains, ioc_domains
    assert sub["kit-two.example"]["role"] == "infrastructure"
    edge = [c for c in r["connections"] if c["to_id"] == absent["id"]]
    assert edge and all(c["relationship"] == "related_to" and c["strength"] == "possible" for c in edge), edge


def test_case_without_hops_keeps_every_collected_host_in_the_estate():
    with tempfile.TemporaryDirectory() as tmp:
        case, kb = _hop_case(tmp, None)
        r = brd.build(case, kb)
    roles = {s["label"]: s["role"] for s in r["subjects"] if s.get("type") == "domain"}
    assert set(roles.values()) == {"infrastructure"}, roles


def test_both_report_generators_agree_on_leaf_hosts():
    sys.path.insert(0, os.path.join(ROOT, "intel_engine", "tools"))
    import house_report as hr  # noqa: E402
    with tempfile.TemporaryDirectory() as tmp:
        case, kb = _hop_case(tmp, _HOP_STATE)
        r = brd.build(case, kb)
        hr.KB = kb                                   # hermetic: never read the live ledgers
        c = hr.load_case(case)
    brd_leaves = {s["label"] for s in r["subjects"] if s.get("type") == "domain" and s["role"] == "related"}
    assert brd_leaves == set(c["related_hosts"]) == {"absent.example"}, (brd_leaves, c["related_hosts"])
    assert set(c["hosts"]) == {"kit-apex.example", "kit-two.example"}, c["hosts"]


_TESTS = [
    test_privacy_placeholder_is_not_an_operator_identity,
    test_real_registrant_still_drives_the_operator_subject,
    test_fallback_detector_matches_registrar_roles_when_engine_absent,
    test_engine_predicate_is_the_one_used_in_production,
    test_ledger_identity_is_not_written_as_a_registrant_triple,
    test_benign_check_keeps_identity_selectors_out_of_the_ioc_feed,
    test_organization_subject_registered_relationship_and_selector_indicators,
    test_no_operator_default_summary_never_claims_attribution,
    test_operator_default_summary_still_attributes,
    test_only_hosts_sharing_the_registrant_are_confirmed,
    test_hosts_carrying_the_registrant_phone_are_confirmed,
    test_host_absent_from_hops_is_a_leaf_not_infrastructure,
    test_case_without_hops_keeps_every_collected_host_in_the_estate,
    test_both_report_generators_agree_on_leaf_hosts,
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
