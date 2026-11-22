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

Classification (`case_classification`): every TLP marking the case records — TLP tokens in the head
of assessment.md, and `classification` / `tlp` in assessment.json and scope.json — read with
`tlp_parse` (bare `red`, `TLP:RED`, `TLP: amber + strict`; WHITE is read as its TLP 2.0 successor
CLEAR) and the MOST RESTRICTIVE readable level wins, returned as `TLP:<LEVEL>`. Unreadable markings
are shown alongside that level, never replacing it. `case_markings` preserves each readable source
and unreadable raw value separately for REPORT.json and the fail-closed STIX gates. No marking at
all → None (callers pick their own fallback).

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
# TLP 2.0 levels, least to most restrictive.
TLP_ORDER = ("clear", "green", "amber", "amber+strict", "red")
# A whole field holding one marking, with or without the `TLP:` prefix: `red`, `TLP:RED`, `TLP: Amber + Strict`.
_TLP_FULL_RE = re.compile(r"^(?:TLP:?\s*)?(clear|white|green|amber\s*\+\s*strict|amber|red)$", re.I)
# Assessment headers may be markdown-decorated; consume the entire value, not a valid prefix
# of an invalid marking such as TLP:AMBER+UNKNOWN.
_TLP_LINE_RE = re.compile(r"^\s*(?:\*\*)?Classification(?:\*\*)?\s*:\s*(?:\*\*)?\s*(.*?)\s*$", re.I)
_TLP_WORD_RE = re.compile(r"\bTLP\b", re.I)
# build_report_data's cover caveat when the case records no marking: it states absence, not a level.
NO_MARKING = frozenset({"UNCLASSIFIED//FOR OFFICIAL USE ONLY"})


def _tlp_norm(token):
    lvl = re.sub(r"\s+", "", token.lower())
    return "clear" if lvl == "white" else lvl


def tlp_most_restrictive(levels):
    """The most restrictive of TLP 2.0 `levels`, or None when there are none."""
    levels = [lv for lv in levels if lv in TLP_ORDER]
    return max(levels, key=TLP_ORDER.index) if levels else None


def tlp_parse(value):
    """A whole-field TLP 2.0 marking, lower-case (WHITE read as CLEAR), or None if unreadable."""
    s = str(value if value is not None else "").strip()
    m = _TLP_FULL_RE.fullmatch(s)
    return _tlp_norm(m.group(1)) if m else None


def tlp_collect(fields):
    """Sort `fields`, a list of (label, value, is_tlp_field), into (readable, bad, other), never
    raises: readable = [(label, level)] for every value that parses; bad = [(label, raw)] for a `tlp`
    field or TLP-mentioning value that does not parse; other = [(label, raw)] for classification text
    with no TLP word. Empty values and NO_MARKING placeholders are skipped."""
    readable, bad, other = [], [], []
    for label, value, is_tlp in fields:
        s = str(value if value is not None else "").strip()
        if not s or s.upper() in NO_MARKING:
            continue
        lvl = tlp_parse(s)
        if lvl:
            readable.append((label, lvl))
        elif is_tlp or _TLP_WORD_RE.search(s):
            bad.append((label, s))
        else:
            other.append((label, s))
    return readable, bad, other


def tlp_resolve(fields):
    """Resolve one TLP level from `fields`, a list of (label, value, is_tlp_field).

    Returns (level, problem), never raises:
      (level, None)  the most restrictive marking found;
      (None, None)   no marking recorded at all (empty values, NO_MARKING placeholders);
      (None, text)   a marking is present but unreadable: a `tlp` field or a TLP-mentioning value
                     that does not parse, or only non-TLP classification text — fail closed."""
    readable, bad, other = tlp_collect(fields)
    if bad:
        return None, "unreadable TLP marking: " + ", ".join("%s=%r" % kv for kv in bad)
    if readable:
        return tlp_most_restrictive([lv for _, lv in readable]), None
    if other:
        return None, "classification carries no TLP level: " + ", ".join("%s=%r" % kv for kv in other)
    return None, None


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


def case_markings(case_dir):
    """Every TLP marking the case records, never raises:
      tlp             `TLP:<LEVEL>`, the most restrictive READABLE marking, or None;
      tlp_sources     [{"source", "tlp"}] for each readable marking;
      tlp_unreadable  [{"source", "value"}] for each present but unreadable marking (verbatim) —
                      non-TLP classification text counts only when nothing readable sits beside it.
    An unreadable value never displaces a readable one: both are kept, separately."""
    fields = []
    try:
        with open(os.path.join(case_dir, "assessment.md"), encoding="utf-8") as fh:
            head = fh.read(4000)
        for line in head.splitlines():
            m = _TLP_LINE_RE.match(line)
            if m:
                fields.append(("assessment.md", m.group(1).strip("* ").strip(), True))
            elif re.match(r"^\s*(?:\*\*)?TLP\s*:?", line, re.I):
                fields.append(("assessment.md", line.strip("* ").strip(), True))
    except (OSError, ValueError):
        pass
    for name in ("assessment.json", "scope.json"):
        d = _load_json(os.path.join(case_dir, name))
        if isinstance(d, dict):
            fields += [(name + ":" + k, d.get(k), k == "tlp") for k in ("classification", "tlp")]
    readable, bad, other = tlp_collect(fields)
    level = tlp_most_restrictive([lv for _, lv in readable])
    unreadable = bad + ([] if readable else other)
    return {"tlp": "TLP:" + level.upper() if level else None,
            "tlp_sources": [{"source": s, "tlp": "TLP:" + lv.upper()} for s, lv in readable],
            "tlp_unreadable": [{"source": s, "value": v} for s, v in unreadable]}


def case_classification(case_dir):
    """TLP marking recorded on the case, as `TLP:<LEVEL>` (the most restrictive readable one), or
    None when the case records none. Bare levels and `TLP: X` spellings are normalised; the TLP 1.0
    label WHITE is returned as its TLP 2.0 successor TLP:CLEAR. A present but unreadable marking is
    returned verbatim when nothing readable exists, and appended (`TLP:RED; unreadable: purple`)
    when something readable does — it never hides the readable level (see case_markings)."""
    m = case_markings(case_dir)
    raw = [u["value"] for u in m["tlp_unreadable"]]
    if m["tlp"]:
        return m["tlp"] + ("; unreadable: " + ", ".join(raw) if raw else "")
    return raw[0] if raw else None


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
