#!/usr/bin/env python3
"""
kb_reconcile.py — the deterministic decision when a new value enters a SINGLE-VALUED slot.

A single-valued attribute (a domain's registrar, its ASN, a reputation verdict …) has one current
value at a time. Two sources can disagree about it, and the newer claim is NOT automatically the
truer one: a page extractor scraping a stale footer must never overwrite what the registry says,
and an analyst's graded finding outranks every machine source. So a new value is judged against
the slot's ACTIVE values by AUTHORITY and EFFECTIVE DATE, with the same answer for the same inputs:

  skip       — no value, no source/collector, or no date at all: never stored
  create     — the slot holds no other active value (same value from another source = corroboration)
  supersede  — the new value outranks EVERY competing value: authority tier ≥ theirs AND effective
               date ≥ theirs (exact tie on both → higher confidence, else dispute). The losers are
               kept as history: status=superseded, superseded_by=<id>, valid_until closed.
  dispute    — anything else: the new value is stored status=disputed, disputes=[<ids>], and the
               standing value is untouched. Disputes surface in the assessment, never silently.

Same writer: a value from the SAME source AND collector, reported at the same or a later
OBSERVATION day, is that writer updating its own claim (a re-collection, a parser fix) — the old
value is superseded whatever its effective date, and only OTHER writers' values are weighed above.

Authority tiers (references/kb_memory.json): analyst > registry > vendor > extractor > derived.
A record's tier comes from its `source` when that is listed (chongluadao, webamon, analyst_import …),
else from its `collector` (glob patterns), else the default — the extractor tier, so an unknown
writer can never override registry or analyst data. Effective date = valid_from, else the first
observation. Multi-valued attributes are never reconciled: they keep plain create/extend.

The analyst tier is reserved: tools/evidence_import.py writes `analyst_finding` facts and owner
edges, never a value into a single-valued attribute, so no analyst value reaches this module today.
Letting an analyst set one (e.g. a corrected registrar) needs an attribute/value field on imported
findings first.

Pure functions only (no I/O beyond loading the reference file); knowledge_base.KB applies them.
"""
import fnmatch
import hashlib
import json
import os
import sys

try:
    from kb_refs import load_ref, ref_path  # noqa: E402 — the shared RULE 3 loader (same dir)
except Exception:  # noqa: BLE001 — degrade loudly, never block
    def ref_path(module_file, name):
        return os.path.join(os.path.dirname(os.path.abspath(module_file)), "references", name)

    def load_ref(path, fallback):
        sys.stderr.write("[kb] WARNING: kb_refs unavailable; kb_memory.json not read — running "
                         "on the minimal embedded fallback.\n")
        return dict(fallback)

# DATA: references/kb_memory.json. The fallback reconciles NOTHING (no single-valued attributes) —
# the pre-reconcile behaviour, where every disagreement is simply kept side by side.
_FALLBACK = {
    "single_valued": [],
    "authority_order": ["derived", "extractor", "vendor", "registry", "analyst"],
    "authority_sources": {},
    "authority_collectors": {},
    "authority_default": {"tier": "extractor"},
}
_REF = load_ref(ref_path(__file__, "kb_memory.json"), _FALLBACK)
SINGLE_VALUED = frozenset(_REF.get("single_valued") or [])
AUTHORITY_ORDER = list(_REF.get("authority_order") or _FALLBACK["authority_order"])
_RANK = {name: i for i, name in enumerate(AUTHORITY_ORDER)}
_BY_SOURCE = dict(_REF.get("authority_sources") or {})
_BY_COLLECTOR = dict(_REF.get("authority_collectors") or {})
_DEFAULT_TIER = str((_REF.get("authority_default") or {}).get("tier") or "extractor")

ACTIVE = (None, "active")


def fact_key(f):
    """A fact's identity: (attribute, value, source, collector) — value JSON-normalised."""
    return (f["attribute"], json.dumps(f["value"], sort_keys=True, ensure_ascii=False),
            f["source"], f["collector"])


def fact_id(f):
    """Stable 12-hex id of a fact (its identity key) — what superseded_by / disputes point at."""
    return hashlib.sha1(json.dumps(fact_key(f), ensure_ascii=False).encode("utf-8")).hexdigest()[:12]


def is_active(f):
    """The slot's current claim: not superseded, disputed or retracted."""
    return f.get("status") in ACTIVE


def tier_of(source, collector):
    """(rank, name) of a writer's authority: its source when listed, else its collector pattern,
    else the default (extractor)."""
    name = _BY_SOURCE.get(str(source or ""))
    if name is None:
        col = str(collector or "")
        name = _BY_COLLECTOR.get(col)
        if name is None:
            name = next((t for pat, t in _BY_COLLECTOR.items()
                         if any(c in pat for c in "*?[") and fnmatch.fnmatchcase(col, pat)), None)
    name = name if name in _RANK else _DEFAULT_TIER
    return _RANK.get(name, _RANK.get("extractor", 1)), name


def effective_day(f):
    """When the value took effect: its source-stated valid_from, else its first observation."""
    return str(f.get("valid_from") or f.get("first_observed") or f.get("observed_at") or "")[:10]


def _empty(v):
    return v is None or (isinstance(v, (str, list, dict)) and not v)


def _beats(cand, group):
    ct, ce, cc = cand
    gt, ge, gc = group
    if ct < gt or ce < ge:
        return False
    if ct == gt and ce == ge:
        return cc > gc
    return True


def _same_writer_update(cand, f):
    """`f` is the candidate's own writer's earlier claim: same source AND collector, and the
    candidate was observed on the same day or later."""
    if (f["source"], f["collector"]) != (cand["source"], cand["collector"]):
        return False
    seen = str(cand.get("observed_at") or cand.get("first_observed") or "")[:10]
    return bool(seen) and seen >= str(f.get("observed_at") or f.get("first_observed") or "")[:10]


def reconcile(slot, cand):
    """Decide what a candidate fact does to its single-valued slot.

    `slot` — every stored fact of the entity with the candidate's attribute (any status);
    `cand` — the candidate record (attribute, value, source, collector, observed_at / valid_from,
    confidence). Returns (action, superseded, disputed): action in skip | create | supersede |
    dispute; `superseded` the active facts the candidate replaces (its own writer's earlier claims
    even when it disputes another writer); `disputed` the standing facts it conflicts with.
    Pure: mutates nothing."""
    if _empty(cand.get("value")) or not cand.get("source") or not cand.get("collector") \
            or not effective_day(cand):
        return "skip", [], []
    norm = json.dumps(cand["value"], sort_keys=True, ensure_ascii=False)
    conflicts = [f for f in slot if is_active(f) and f is not cand
                 and json.dumps(f["value"], sort_keys=True, ensure_ascii=False) != norm]
    if not conflicts:
        return "create", [], []
    own = [f for f in conflicts if _same_writer_update(cand, f)]
    rivals = [f for f in conflicts if not _same_writer_update(cand, f)]
    groups = {}
    for f in rivals:
        k = json.dumps(f["value"], sort_keys=True, ensure_ascii=False)
        t, e, c = groups.get(k, (-1, "", -1.0))
        groups[k] = (max(t, tier_of(f["source"], f["collector"])[0]), max(e, effective_day(f)),
                     max(c, float(f.get("confidence") or 0)))
    me = (tier_of(cand["source"], cand["collector"])[0], effective_day(cand),
          float(cand.get("confidence") or 0))
    if all(_beats(me, g) for g in groups.values()):
        return "supersede", conflicts, []
    return "dispute", own, rivals
