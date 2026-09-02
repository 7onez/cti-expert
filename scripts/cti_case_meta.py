#!/usr/bin/env python3
# cti-expert skill — shared case metadata resolution for the report builders.
"""cti_case_meta.py — one answer to "what is the seed?" and "what is the handling caveat?".

Both report paths (`scripts/build_report_data.py` for the dashboard bundle and
`intel_engine/tools/house_report.py` for the editorial PDF/DOCX) must agree on the seed named on
the cover / IOC headers and on the TLP marking in the header — so they resolve both HERE.

Seed resolution order (never "alphabetically first host"):
  1. scope.json `seed`
  2. the first collected host named in scope.json `claim` / `basis`
  3. the first line of the case's seeds file (<engine>/<CASE>-seeds.txt or <case>/*seeds*.txt)
  4. the host whose raw pivot has the EARLIEST `meta.collected_at`
  5. the alphabetically-first host (last resort)

Classification: `**Classification:** TLP:X` in assessment.md, else `classification`/`tlp` in
assessment.json or scope.json, else None (callers pick their own fallback).

Author: Hieu Ngo - chongluadao.vn
"""
import glob
import json
import os
import re

_DOMAIN_RE = re.compile(r"\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b", re.I)
_TLP_RE = re.compile(r"\bTLP:(RED|AMBER\+STRICT|AMBER|GREEN|CLEAR|WHITE)\b")


def _load_json(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


def resolve_seed(case_dir, hosts, raw_paths=()):
    """The seed the case was opened on. `hosts`: collected host names (lower-case).
    `raw_paths`: the raw pivot JSON paths, used for the collected_at fallback."""
    hosts = [h.lower() for h in hosts or []]
    hostset = set(hosts)
    case_id = os.path.basename(os.path.normpath(case_dir))
    sc = _load_json(os.path.join(case_dir, "scope.json")) or {}
    if isinstance(sc, dict):
        if sc.get("seed"):
            return str(sc["seed"]).lower()
        for field in ("claim", "basis"):
            for d in _DOMAIN_RE.findall(str(sc.get(field) or "")):
                if d.lower() in hostset:
                    return d.lower()
    engine_root = os.path.dirname(os.path.dirname(os.path.normpath(case_dir)))
    for sf in glob.glob(os.path.join(engine_root, f"{case_id}-seeds.txt")) + glob.glob(os.path.join(case_dir, "*seeds*.txt")):
        try:
            first = open(sf, encoding="utf-8").readline().strip().lower()
        except OSError:
            continue
        if first in hostset:
            return first
    earliest = None
    for rp in raw_paths or []:
        d = _load_json(rp)
        if not isinstance(d, dict):
            continue
        host = os.path.basename(rp)[:-5].lower()
        when = ((d.get("meta") or {}).get("collected_at") or "")
        if host in hostset and when and (earliest is None or when < earliest[0]):
            earliest = (when, host)
    if earliest:
        return earliest[1]
    return hosts[0] if hosts else case_id


def case_classification(case_dir):
    """TLP marking recorded on the case, or None."""
    try:
        head = open(os.path.join(case_dir, "assessment.md"), encoding="utf-8").read(4000)
        m = _TLP_RE.search(head)
        if m:
            return "TLP:" + m.group(1)
    except OSError:
        pass
    for name in ("assessment.json", "scope.json"):
        d = _load_json(os.path.join(case_dir, name))
        if isinstance(d, dict):
            v = d.get("classification") or d.get("tlp")
            if v:
                return str(v)
    return None
