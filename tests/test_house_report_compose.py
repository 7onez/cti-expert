"""Regression: the deterministic house-report composer (intel_engine/tools/house_report.py) must
produce the IntelReport structure from a synthetic case dir — decision statement first, Methodology
with both confidence scales, Roman-level sections in order, a raw \\appendix marker followed by the
four evidence appendices — while scrubbing internal tool / vendor / path names (Rule 12), keeping
indicator values (Rule 12a), and never listing the impersonated brand's genuine domain as an
artifact. Synthetic data only: example.com / .invalid domains, CASE-0001, RFC 5737 addresses."""
import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "intel_engine", "tools"))

import house_report as hr

_WHOIS = {"registrant_name": "Test Persona", "registrant_email": "persona@example.com",
          "registrant_phone": "+1.2025550100", "registrar": "Example Registrar LLC",
          "created": "2025-01-05 00:00:00 UTC", "expires": "2026-01-05 00:00:00 UTC",
          "name_servers": ["ns1.example.net", "ns2.example.net"]}


def _synthetic_case(tmp):
    case = os.path.join(tmp, "CASE-0001")
    for d in ("raw", "whois"):
        os.makedirs(os.path.join(case, d))
    hosts = ["seed-brand.example.com", "sibling-a.example.com", "sibling-b.example.com"]
    for h in hosts:
        json.dump({"meta": {"host": h, "fetched_with": "urllib"}, "artifacts": {}, "pivots": []},
                  open(os.path.join(case, "raw", h + ".json"), "w"))
        json.dump(_WHOIS, open(os.path.join(case, "whois", h + ".json"), "w"))
    json.dump({"claim": "seed-brand.example.com impersonates Example Brand", "brand": "Example Brand",
               "target_class": "suspected_scam", "purpose": "attribution"},
              open(os.path.join(case, "scope.json"), "w"))
    json.dump({"bluf": "seed-brand.example.com is one of 3 domains under one registrant record.",
               "decision_supported": "Supports an abuse referral.",
               "attribution_level": "same-operator estate (rung 1)", "confidence": "high",
               "premise": "impersonation", "premise_verdict": "supported",
               "evidence": ["E1 [A1, rung 1] Registrant e-mail persona@example.com on 3/3 domains — WhoisXML lookup",
                            "E2 [B2] Page is a link farm — see evidence/cld-analyze.json [cld]"],
               "alternatives": ["Genuine brand property — REJECTED: registered via personal mailbox",
                                "Nominee registrant — CANNOT RULE OUT: no KYC corroboration"],
               "gaps": ["No residential vantage"], "next_pivots": ["Watch renewals"]},
              open(os.path.join(case, "assessment.json"), "w"))
    open(os.path.join(case, "assessment.md"), "w", encoding="utf-8").write(
        "# Analyst Assessment (ICD-203) — synthetic\n\n## BLUF\n\ntext\n\n## Key judgments\n\n"
        "1. **Impersonation of Example Brand — assessed / high.** Body text `[search]` (A2)\n\n"
        "2. **One operator across 3 domains — assessed / high.** Reverse-WHOIS via WhoisXML = 3; IntelX empty; "
        "urlscan saw the link farm. `[whois-api][intelx]` (A1)\n\n"
        "## Excluded\n\n- scraped contacts thirdparty@example.org, phone 0987654321, persona of CASE-0002 — not operator.\n\n"
        "## Recommendation\n\n1. Refer for takedown.\n\n## Collection gaps\n\n- ran `/intelx --phonebook` (3 × 5 units) — see evidence/x.json\n")
    json.dump({"n_clusters": 2, "clusters": [
        {"id": 1, "size": 3, "domains": hosts, "singleton": False, "binding_indicators": [], "binding_total": 1},
        {"id": 2, "size": 1, "domains": ["harvest.indicators"], "singleton": True}]},
        open(os.path.join(case, "clusters.json"), "w"))
    open(os.path.join(case, "shared.txt"), "w", encoding="utf-8").write(
        "# Shared indicators\n\n[3] email:persona@example.com  (registered_by)  [KB-wide: 3 domains]\n"
        "     " + ", ".join(hosts) + "\n"
        "[2] indicator:ip:192.0.2.10  (hosted_on)  [KB-wide: 900 domains]\n     " + ", ".join(hosts[:2]) + "\n")
    return case


def _compose(case):
    hr.KB = os.path.join(os.path.dirname(case), "kb-empty")   # hermetic: never read the live ledgers
    os.makedirs(hr.KB, exist_ok=True)
    c = hr.load_case(case)
    return c, hr.compose(c, {}, "TLP:AMBER", "2026-01-01")


def test_structure_is_the_house_order_with_appendix_marker():
    with tempfile.TemporaryDirectory() as tmp:
        _, md = _compose(_synthetic_case(tmp))
    heads = [l[2:] for l in md.splitlines() if l.startswith("# ")]
    assert heads[:4] == ["Executive Summary — Key Judgments", "Methodology", "Scope and the seed", "Findings"]
    assert "\\appendix" in md
    tail = heads[heads.index("Artifact register"):]
    assert tail == ["Artifact register", "Evidence ledger", "Domain and infrastructure profiles", "Cluster enumeration"]
    assert md.index("Supports an abuse referral.") < md.index("**BLUF.**")  # decision statement first
    assert "| A | Completely reliable |" in md and "almost certain" in md  # both scales present


def test_seed_comes_from_scope_claim_not_alphabetical_order():
    with tempfile.TemporaryDirectory() as tmp:
        c, md = _compose(_synthetic_case(tmp))
    assert c["seed"] == "seed-brand.example.com"
    assert "| Seed | `seed-brand.example.com` |" in md


def test_rule12_scrubs_internal_working_but_keeps_evidence_values():
    with tempfile.TemporaryDirectory() as tmp:
        _, md = _compose(_synthetic_case(tmp))
    body = md.split("\\appendix")[0]
    for leak in ("WhoisXML", "IntelX", "urlscan", "[cld]", "[whois-api]", "evidence/x.json", "/intelx", "5 units"):
        assert leak not in body, f"internal working leaked: {leak}"
    for keep in ("persona@example.com", "seed-brand.example.com", "192.0.2.10", "Example Registrar LLC"):
        assert keep in md, f"evidence value lost: {keep}"


def test_prevalent_indicator_is_marked_excluded_and_sidecar_not_enumerated():
    with tempfile.TemporaryDirectory() as tmp:
        _, md = _compose(_synthetic_case(tmp))
    reg = md.split("# Artifact register")[1].split("# Evidence ledger")[0]
    assert "`192.0.2.10`" in reg and "excluded" in [l for l in reg.splitlines() if "192.0.2.10" in l][0]
    assert "join key" in [l for l in reg.splitlines() if "persona@example.com" in l][0]
    assert "harvest.indicators" not in md.split("# Cluster enumeration")[1]


def test_third_parties_are_masked_but_operator_join_key_is_kept():
    with tempfile.TemporaryDirectory() as tmp:
        case = _synthetic_case(tmp)
        json.dump(["Some Third Party"], open(os.path.join(case, "report_mask.json"), "w"))
        _, md = _compose(case)
    assert "thirdparty@example.org" not in md and "t***@example.org" in md
    assert "0987654321" not in md and "09********" in md
    assert "CASE-0002" not in md and "a related case" in md
    assert "persona@example.com" in md          # operator join key stays in clear
    assert "CASE-0001" in md                     # this case's own id is not masked


def test_composer_degrades_without_assessment_json():
    with tempfile.TemporaryDirectory() as tmp:
        case = _synthetic_case(tmp)
        os.remove(os.path.join(case, "assessment.json"))
        c, md = _compose(case)
        rep = os.path.join(case, "report"); os.makedirs(rep)
        assert hr.fig_attribution_chain(c, rep) is None   # no evidence -> no chain figure, no crash
    assert "# Executive Summary — Key Judgments" in md and "\\appendix" in md
    assert "Impersonation of Example Brand" in md          # judgments still come from assessment.md


def test_sector_typology_from_domain_tokens():
    assert hr._sector("benhvienbachmai.example.com") == "Medical"
    assert hr._sector("tuyendungaeon-vn.example.com").startswith("Recruitment")
    assert hr._sector("hrvincom.example.com").startswith("Recruitment")
    assert hr._sector("pnjvn.example.com").startswith("Corporate")


def test_alternatives_table_parses_status_with_digits_and_words():
    with tempfile.TemporaryDirectory() as tmp:
        _, md = _compose(_synthetic_case(tmp))
    alt = md.split("# Alternative analysis")[1].split("# Gaps")[0]
    assert "| **rejected** |" in alt and "| **cannot rule out** |" in alt


_TESTS = [
    test_structure_is_the_house_order_with_appendix_marker,
    test_seed_comes_from_scope_claim_not_alphabetical_order,
    test_rule12_scrubs_internal_working_but_keeps_evidence_values,
    test_prevalent_indicator_is_marked_excluded_and_sidecar_not_enumerated,
    test_alternatives_table_parses_status_with_digits_and_words,
    test_sector_typology_from_domain_tokens,
    test_third_parties_are_masked_but_operator_join_key_is_kept,
    test_composer_degrades_without_assessment_json,
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
