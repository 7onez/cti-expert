"""Regression: metadata-only CTI reports must not grow an empty Visual Analytics page."""
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

from docx import Document
import cti_docx_postprocess as post


def test_empty_report_data_adds_no_visual_appendix():
    doc = Document()
    with tempfile.TemporaryDirectory() as case_dir:
        post._append_remaining_charts(doc, {"case": {}}, set(), {}, case_dir)
    text = "\n".join(p.text for p in doc.paragraphs)
    assert "Visual Analytics" not in text
    assert "Campaign Heatmaps" not in text


def test_registration_data_makes_heatmap_appendix_eligible():
    data = {"subjects": [{
        "id": "domain-1", "type": "domain", "label": "synthetic.invalid",
        "created": "2025-01-01",
    }]}
    with tempfile.TemporaryDirectory() as case_dir:
        assert post._has_heatmap_data(data, case_dir)


_TESTS = [
    test_empty_report_data_adds_no_visual_appendix,
    test_registration_data_makes_heatmap_appendix_eligible,
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
