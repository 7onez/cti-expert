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

Expansion anchor (`expansion_anchor` / `raw_host_names`): which collected hosts are LEAVES — owner-
linked to a previous hop, collected to bound the estate, never operator infrastructure. One rule for
both builders: a host named in clusters.json `related_hosts` is a leaf; in a hop-tracked case
(state.json `hops` non-empty) a host is a leaf unless one of its names (raw file stem, `meta.host`)
sits at a hop below `expansion_depth` — a collected host ABSENT from `hops` was not a seed, so it is a
leaf. A case with no `hops` has no hop-based leaves.

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


class ExpansionAnchor:
    """state.json hops / expansion_depth + clusters.json related_hosts for one case."""

    def __init__(self, hops=None, depth=2, related=()):
        self.hops = dict(hops or {})
        self.depth = depth
        self.related = set(related or ())

    def _names(self, names):
        return {str(n).lower() for n in names if n}

    def is_leaf(self, *names):
        """`names`: every identity of ONE collected host (raw file stem, meta.host)."""
        ns = self._names(names)
        if ns & self.related:
            return True
        if not self.hops:
            return False
        known = [self.hops[n] for n in ns if n in self.hops]
        return not known or min(known) >= self.depth

    def hop(self, *names):
        """Recorded hop of the host; an unrecorded leaf sits at the expansion boundary (depth)."""
        known = [self.hops[n] for n in self._names(names) if n in self.hops]
        if known:
            return min(known)
        return self.depth if self.is_leaf(*names) else 0


def expansion_anchor(case_dir):
    st = _load_json(os.path.join(case_dir, "state.json"))
    st = st if isinstance(st, dict) else {}
    raw_hops = st.get("hops") if isinstance(st.get("hops"), dict) else {}
    hops = {str(k).lower(): int(v) for k, v in raw_hops.items() if isinstance(v, int)}
    depth = st.get("expansion_depth")
    depth = depth if isinstance(depth, int) and depth >= 0 else 2
    cl = _load_json(os.path.join(case_dir, "clusters.json"))
    related = (cl.get("related_hosts") if isinstance(cl, dict) else None) or []
    return ExpansionAnchor(hops, depth, {str(h).lower() for h in related if h})


def raw_host_names(raw_path, data=None):
    """Every identity of one raw pivot: its file stem and its `meta.host` (lower-case)."""
    stem = os.path.basename(raw_path)[:-5].lower()
    if data is None:
        data = _load_json(raw_path)
    meta = (data or {}).get("meta") if isinstance(data, dict) else None
    host = str((meta or {}).get("host") or "").lower() if isinstance(meta, dict) else ""
    return {stem, host} - {""}


def raw_name_index(case_dir):
    """{identity: names} over <case>/raw/*.json, identity = `meta.host` or the file stem (the key
    build_report_data uses), names = every identity of that raw (see raw_host_names)."""
    out = {}
    for p in sorted(glob.glob(os.path.join(case_dir, "raw", "*.json"))):
        data = _load_json(p)
        names = raw_host_names(p, data)
        meta = data.get("meta") if isinstance(data, dict) else None
        ident = (str(meta.get("host") or "") if isinstance(meta, dict) else "") or os.path.basename(p)[:-5]
        out.setdefault(ident.lower(), set()).update(names)
    return out
