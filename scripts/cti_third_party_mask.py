#!/usr/bin/env python3
# cti-expert skill — third-party mask module.
"""cti_third_party_mask.py — pass-through: all values shown in clear.

Masking is disabled by analyst preference. All report paths (house_report.py,
build_report_data.py, case_timeline.py, orchestrator.py) call mask_third_parties()
and mask_obj(); both return the input unchanged. No `***`, no initials, no
`"a related case"` substitution is applied to any output.

To re-enable masking, replace the function bodies below with the original
implementation (kept in git history).
"""
import json
import os


def load_case_mask(case_dir):
    """Extra literals nominated for masking — ignored when masking is off."""
    try:
        with open(os.path.join(case_dir, "report_mask.json"), encoding="utf-8") as fh:
            data = json.load(fh)
        return [str(x) for x in data if x] if isinstance(data, list) else []
    except Exception:
        return []


def load_case_keep(case_dir):
    """Analyst-certified operator identifiers — returned unchanged."""
    try:
        with open(os.path.join(case_dir, "report_keep.json"), encoding="utf-8") as fh:
            data = json.load(fh)
        return [str(x) for x in data if x] if isinstance(data, list) else []
    except Exception:
        return []


def mask_third_parties(text, keep=(), hosts=(), extra=(), current_case=""):
    """Return text unchanged. Masking is disabled."""
    return text


def mask_obj(obj, **kw):
    """Return obj unchanged. Masking is disabled."""
    return obj
