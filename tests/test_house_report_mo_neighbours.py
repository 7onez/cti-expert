"""Regression: the house report's 'Related personas on the same infrastructure' table (MO-neighbour
pivot, rung 10) under *Alternative analysis*.

Contract: a verified same-MO persona renders IN CLEAR by default (analyst decision, Validation
Session 1) together with the rung-10 caveat — which proves load_case() folds exactly those identities
into _KEEP; an UNRELATED third-party e-mail elsewhere in the case stays masked (the fold-in is scoped,
never blanket); `--mask-personas` renders the aggregated form; a case without the file renders no
table; a bulk-skipped origin is stated, not classified. Synthetic data only (CASE-0001, *.example,
example.com, RFC 5737 addresses)."""
import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "intel_engine", "tools"))

import house_report as hr  # noqa: E402
from test_house_report_compose import _synthetic_case  # noqa: E402  same fixture builder, one convention

PERSONA = "khoan5521@example.org"
STRANGER = "thirdparty@example.org"           # already in the fixture's Excluded section — must stay masked

_MO = {"case": "CASE-0001", "generated": "2026-01-01T00:00:00+00:00", "window_days": 90,
       "estate": {"hosts": 3, "registrant_terms": 2, "registrars": ["example registrar llc"],
                  "tokens": ["seed", "brand", "sibling"], "created_window": ["2024-10-07", "2025-04-05"],
                  "context_source": "whois sidecar", "reseller_estate": False},
       "origins": [{"origin_ip": "198.51.100.7", "seen_on": ["seed-brand.example.com"], "fan_out": 87, "sources": {"netlas": 87}}],
       "bulk_origins": [{"origin_ip": "203.0.113.9", "fan_out": 1018, "sample_apexes": ["t1.example"],
                         "seen_on": "sibling-a.example.com", "why": "bulk hosting"}],
       "same_registrant": [],
       "related_personas": [{"persona": PERSONA, "name": "Person", "domains": ["brand-mo.example", "brand-mo2.example"],
                             "registrar": "example registrar llc", "created_span": ["2025-01-20", "2025-02-11"],
                             "origin_ips": ["198.51.100.7"], "signals": ["same registrar", "created in estate window",
                                                                         "naming token(s) brand", "throwaway-handle mailbox"],
                             "rung": 10, "caveat": "candidate, single-indicator (rung 10): shared provider + same MO; not estate membership"}],
       "unrelated_count": 4, "unrelated_sample": ["shoes.example"], "unverifiable_count": 1, "unverifiable": ["broken.example"],
       "verified": []}


def _compose(case, mask_personas=False):
    hr.KB = os.path.join(os.path.dirname(case), "kb-empty")
    os.makedirs(hr.KB, exist_ok=True)
    c = hr.load_case(case, mask_personas=mask_personas)
    return c, hr.compose(c, {}, "TLP:AMBER", "2026-01-01")


def _section(md, title):
    lines = md.splitlines()
    start = next(i for i, l in enumerate(lines) if l.strip() == f"# {title}")
    end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("# ")), len(lines))
    return "\n".join(lines[start:end])


def test_persona_renders_in_clear_by_default_with_rung10_caveat():
    with tempfile.TemporaryDirectory() as tmp:
        case = _synthetic_case(tmp)
        json.dump(_MO, open(os.path.join(case, "mo_neighbours.json"), "w"))
        c, md = _compose(case)
    alt = _section(md, "Alternative analysis")
    assert "## Related personas on the same infrastructure" in alt
    assert PERSONA in alt, "verified persona must render in clear by default (scoped _KEEP fold-in)"
    assert "rung 10" in alt and "NOT members of the estate" in alt
    assert "brand-mo.example, brand-mo2.example" in alt and "2025-01-20 → 2025-02-11" in alt
    assert "198.51.100.7" in alt and "throwaway-handle mailbox" in alt
    assert PERSONA in hr._KEEP


def test_fold_in_is_scoped_unrelated_third_party_stays_masked():
    with tempfile.TemporaryDirectory() as tmp:
        case = _synthetic_case(tmp)
        json.dump(_MO, open(os.path.join(case, "mo_neighbours.json"), "w"))
        _, md = _compose(case)
    assert PERSONA in md
    assert STRANGER not in md, "an unrelated third-party e-mail elsewhere in the case must stay masked"
    assert STRANGER not in hr._KEEP


def test_mask_personas_renders_aggregated_form():
    with tempfile.TemporaryDirectory() as tmp:
        case = _synthetic_case(tmp)
        json.dump(_MO, open(os.path.join(case, "mo_neighbours.json"), "w"))
        c, md = _compose(case, mask_personas=True)
    alt = _section(md, "Alternative analysis")
    assert "## Related personas on the same infrastructure" in alt
    assert PERSONA not in md, "--mask-personas: the identity must not appear anywhere"
    assert "| 1 | persona 1 |" in alt and "brand-mo.example" in alt, "aggregated row keeps domains/dates, drops identity"
    assert PERSONA not in hr._KEEP


def test_bulk_origin_is_stated_not_classified_and_counts_are_present():
    with tempfile.TemporaryDirectory() as tmp:
        case = _synthetic_case(tmp)
        json.dump(_MO, open(os.path.join(case, "mo_neighbours.json"), "w"))
        _, md = _compose(case)
    alt = _section(md, "Alternative analysis")
    assert "203.0.113.9 answers with ~1018 apexes" in alt and "bulk hosting" in alt
    assert "t1.example" not in alt, "bulk co-tenants are never listed"
    assert "4 co-tenant(s) with an unrelated registration profile (not enumerated)" in alt
    assert "shoes.example" not in alt, "unrelated co-tenants are counted, never enumerated in the report"
    assert "1 whose registration could not be read" in alt


def test_no_file_no_table():
    with tempfile.TemporaryDirectory() as tmp:
        _, md = _compose(_synthetic_case(tmp))
    assert "Related personas on the same infrastructure" not in md
    assert PERSONA not in hr._KEEP


_TESTS = [
    test_persona_renders_in_clear_by_default_with_rung10_caveat,
    test_fold_in_is_scoped_unrelated_third_party_stays_masked,
    test_mask_personas_renders_aggregated_form,
    test_bulk_origin_is_stated_not_classified_and_counts_are_present,
    test_no_file_no_table,
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
