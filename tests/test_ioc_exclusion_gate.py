"""§2.5 IOC exclusion gate — generate-cti-iocs.py.

Rejected/masked subjects and false-positive findings must never be harvested as
IOCs, and a report-level `ioc_exclude` list must drop a value even when it is
embedded inside an otherwise-legitimate subject's `notes`. All fixtures use
synthetic placeholders (*.example / @example.com) per the repo leak gate.
"""
import importlib.util
import pathlib

_SPEC = importlib.util.spec_from_file_location(
    "gen_iocs",
    pathlib.Path(__file__).resolve().parents[1] / "scripts" / "generate-cti-iocs.py",
)
gen = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(gen)


def _domains(records):
    return {r["value"] for r in records if r["category"] == "network" and r["type"] == "domain"}


def _emails(records):
    return {r["value"] for r in records if r["category"] == "contact" and r["type"] == "email"}


def test_default_behavior_unchanged_when_no_markers():
    """No exclusion markers → legitimate subjects/notes still harvested."""
    data = {
        "subjects": [
            {"id": "s1", "label": "operator-estate.example", "type": "domain",
             "role": "infrastructure", "confidence": 90,
             "notes": "Sibling operator-two.example on same box."},
        ],
    }
    doms = _domains(gen.extract(data))
    assert "operator-estate.example" in doms
    assert "operator-two.example" in doms  # scanned out of notes, as before


def test_rejected_subject_not_harvested():
    """A subject flagged rejected contributes no label and no notes IOCs."""
    data = {
        "subjects": [
            {"id": "keep", "label": "operator-estate.example", "type": "domain",
             "role": "infrastructure", "confidence": 90},
            {"id": "fp", "label": "innocent-collision.example", "type": "domain",
             "role": "rejected", "confidence": 90,
             "notes": "Different real individual; also innocent-two.example."},
        ],
    }
    doms = _domains(gen.extract(data))
    assert "operator-estate.example" in doms
    assert "innocent-collision.example" not in doms
    assert "innocent-two.example" not in doms


def test_false_positive_finding_prose_not_harvested():
    """A finding whose type/tags mark it a rejected FP is not text-scanned."""
    data = {
        "subjects": [
            {"id": "opA", "label": "operator-estate.example", "type": "domain",
             "role": "infrastructure", "confidence": 90},
        ],
        "findings": [
            {"id": "F1", "subject_id": "opA", "type": "false-positive",
             "tags": ["§2.5", "name-collision"], "confidence": 90,
             "description": "Rejected: innocent-collision.example belongs to a "
                            "different person (someone@example.com)."},
        ],
    }
    recs = gen.extract(data)
    assert "operator-estate.example" in _domains(recs)
    assert "innocent-collision.example" not in _domains(recs)
    assert "someone@example.com" not in _emails(recs)


def test_report_level_exclude_drops_value_embedded_in_legit_notes():
    """ioc_exclude drops a value even when mentioned in a real subject's notes
    (the registrar-privacy / masked-value failure mode)."""
    data = {
        "ioc_exclude": ["privacy-proxy@example.com", "registrar-mask.example"],
        "subjects": [
            {"id": "cand", "label": "candidate-domain.example", "type": "domain",
             "role": "unknown", "confidence": 45,
             "notes": "Registrant privacy privacy-proxy@example.com via "
                      "registrar-mask.example."},
        ],
    }
    recs = gen.extract(data)
    assert "candidate-domain.example" in _domains(recs)          # the real IOC stays
    assert "privacy-proxy@example.com" not in _emails(recs)      # masked value dropped
    assert "registrar-mask.example" not in _domains(recs)        # masked value dropped
