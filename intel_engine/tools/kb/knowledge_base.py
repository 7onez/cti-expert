#!/usr/bin/env python3
"""
knowledge_base.py — normalized, append-only, attributed OSINT knowledge store.

Implements the entity / relationship / evidence model from the architecture doc §5-6:
  * every atomic fact carries provenance (source, collector, observed_at, confidence,
    evidence_ref) — nothing is stored without saying who said it, using what, when.
  * idempotent: re-ingesting a target UPDATES facts/edges instead of duplicating them.
  * conflicts are kept, not overwritten — two sources disagreeing both stay, attributed.
  * sighting history: a re-observed fact/edge keeps its first and last observation, a count of
    distinct sightings (a new UTC day or a new evidence_ref; a same-day re-ingest of the same
    evidence is not one) and its newest evidence_refs (cap: references/kb_memory.json).
      fact:  first_observed … observed_at (last), observations, evidence_refs
      edge:  observed_at (first) … last_observed, observations, evidence_refs
  * case provenance: every fact/edge lists the `cases` whose collections recorded it (UNATTRIBUTED
    for a sighting with no known case, and for everything written before provenance existed).
    `forget_case` removes one case's contribution: a record ONLY that case recorded is retracted
    (status=retracted, kept for audit, invisible to every reader) or purged; a record other cases
    also recorded keeps living with the case removed. A retracted record re-observed is live again.
  * validity: valid_from / valid_until (YYYY-MM-DD) say when the SOURCE asserts a fact/edge held —
    a WHOIS era, a passive-DNS or advertising window, an archive capture — kept apart from when it
    was observed. `KB(root, as_of=day)` makes every reader show the KB as it held that day
    (holds_at): the validity window when known, else whether it had been observed by then.
  * reconcile: a new, different value in a SINGLE-VALUED slot (registrar, ASN, verdict …) is
    judged deterministically by kb_reconcile.py — authority tier (analyst > registry > vendor >
    extractor) AND effective date — and either supersedes the standing value (kept as history,
    status=superseded: a CHANGE closes its window and it stays visible to an as_of view inside it;
    a CORRECTION — never held per the new source — is flagged `corrected` and never shown) or is
    stored DISPUTED beside it (always visible; `disputes` / disputes_markdown surface it).

Storage (files now; drop into SQLite/graph DB later with no schema change):
  knowledge/
    entities/<type>/<value>.json     one record per entity, facts merged across sources
    relationships/edges.jsonl        one attributed edge per line, plus append-only fold lines
                                     {"_op": "seen", <edge key>, observed_at, evidence_ref, case}
                                     and {"_op": "forget", <edge key>, case, at} that _load_edges
                                     folds into their edge (clean_kb --apply compacts them)
    evidence/<source>/<target>/<day>.json   raw cached payloads (attribution backing)

This is a LIBRARY (collectors call it) + a tiny CLI for stats. It does no I/O to the web.
"""
import contextlib
import os
import re
import sys
import json
import tempfile
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kb_reconcile import (SINGLE_VALUED, effective_day, fact_key as _fact_key,  # noqa: E402
                          fact_id, is_active, reconcile, tier_of)


try:
    from kb_refs import load_ref, ref_path  # noqa: E402 — the shared RULE 3 loader (same dir)
except Exception:  # noqa: BLE001 — degrade loudly, never block
    def ref_path(module_file, name):
        return os.path.join(os.path.dirname(os.path.abspath(module_file)), "references", name)

    def load_ref(path, fallback):
        sys.stderr.write("[kb] WARNING: kb_refs unavailable; kb_memory.json not read — running "
                         "on the minimal embedded fallback.\n")
        return dict(fallback)

# DATA: references/kb_memory.json. The fallback is the pre-history behaviour: keep only the newest
# evidence_ref.
_MEMORY_FALLBACK = {"observations": {"evidence_refs_cap": 1}}
_MEMORY = load_ref(ref_path(__file__, "kb_memory.json"), _MEMORY_FALLBACK)
EVIDENCE_REFS_CAP = max(1, int((_MEMORY.get("observations") or {}).get("evidence_refs_cap") or 1))

EDGE_KEY_FIELDS = ("src_type", "src", "rel", "dst_type", "dst", "source", "collector")

# Provenance tag for a sighting whose case is unknown: a case-less write, or any record written
# before case provenance existed. forget_case never removes it, so such support always survives.
UNATTRIBUTED = "(pre-provenance)"

CONF_WORDS = {"high": 0.9, "medium": 0.6, "low": 0.35, "inferred": 0.4, "confirmed": 0.9}

# canonical entity types (extensible)
ENTITY_TYPES = {"domain", "ip", "cidr", "asn", "tls_cert", "url", "email", "org",
                "person", "file_hash", "malware", "cve", "indicator"}


def _slug(s):
    return re.sub(r"[^a-zA-Z0-9._@-]", "_", str(s)).strip("_")[:200] or "_"


def _entity_path(root, etype, value):
    return os.path.join(root, "entities", _slug(etype), _slug(value) + ".json")


def _conf(c):
    if isinstance(c, (int, float)):
        return float(c)
    return CONF_WORDS.get(str(c).lower(), 0.5)


def _day(ts):
    return str(ts or "")[:10]


def is_live(rec):
    """False for a fact/edge retracted by `forget_case` — kept for audit, hidden from readers."""
    return rec.get("status") != "retracted"


def case_id(case):
    """Normalise a case reference — an id, or a cases/<id> directory path — to its id."""
    s = str(case or "").strip()
    return (os.path.basename(os.path.normpath(s)) or None) if s else None


def case_of_path(path):
    """The case id a collection file belongs to (…/cases/<id>/…/<file>), else None."""
    parts = os.path.abspath(str(path)).split(os.sep)
    for i in range(len(parts) - 3, -1, -1):
        if parts[i] == "cases":
            return parts[i + 1]
    return None


_DATE_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})")


def valid_day(v):
    """A validity bound as 'YYYY-MM-DD' — from an ISO date/datetime, a compact Wayback timestamp
    (YYYYMMDD[hhmm[ss]]) or a unix epoch (s or ms). None when absent or unparseable: an unreadable
    bound is never stored as a guess."""
    if v is None or v == "" or isinstance(v, bool):
        return None
    s = str(v).strip()
    if s.isdigit() and len(s) in (8, 12, 14) and s[:2] in ("19", "20"):
        return f"{s[:4]}-{s[4:6]}-{s[6:8]}"
    if isinstance(v, (int, float)) or (s.isdigit() and len(s) >= 9):
        n = float(v)
        if n < 1e8:                         # not an epoch (a bare year, a count)
            return None
        if n > 1e11:                        # milliseconds
            n /= 1000.0
        try:
            return datetime.fromtimestamp(n, timezone.utc).strftime("%Y-%m-%d")
        except (OverflowError, OSError, ValueError):
            return None
    m = _DATE_RE.match(s)
    return m.group(1) if m else None


def _merge_validity(rec, valid_from, valid_until):
    """Widen a record's validity window — when the source says the fact/edge held — to cover a new
    sighting's bounds (earliest valid_from, latest valid_until). True when it changed."""
    changed = False
    vf, vu = valid_day(valid_from), valid_day(valid_until)
    if vf and (not rec.get("valid_from") or vf < rec["valid_from"]):
        rec["valid_from"], changed = vf, True
    if vu and (not rec.get("valid_until") or vu > rec["valid_until"]):
        rec["valid_until"], changed = vu, True
    return changed


def holds_at(rec, as_of):
    """Did this fact/edge hold on `as_of` (a day)? Its validity window when the source gave one
    (valid_from ≤ day ≤ valid_until; a missing valid_from falls back to the first observation);
    otherwise whether the KB had observed it by that day (first observation ≤ day) — what was
    known then. No date at all: False."""
    t = valid_day(as_of)
    vf, vu = rec.get("valid_from"), rec.get("valid_until")
    first = _day(rec.get("first_observed") or rec.get("observed_at"))
    lower = vf or first
    if vf or vu:
        return bool(lower) and lower <= t and (not vu or t <= vu)
    return bool(first) and first <= t


def _apply_sighting(rec, first_key, last_key, observed_at, evidence_ref, case=None, force=None):
    """Fold one observation into a fact/edge record in place. Returns (changed, sighting).

    `sighting` — a NEW sighting: a new evidence_ref, or a UTC day later than the last observation
    (a same-day re-ingest of the same evidence is not one). `changed` — the record must be
    persisted: a new sighting, a case not yet in its provenance, or the revival of a retracted
    record. `force` (replaying a fold line) replaces the sighting test with the line's own flag.
    Records written before sighting history read as one observation spanning
    observed_at..observed_at; records written before case provenance read as UNATTRIBUTED."""
    first = rec.get(first_key) or rec.get(last_key)
    last = rec.get(last_key) or rec.get(first_key)
    refs = list(rec.get("evidence_refs") or ([rec["evidence_ref"]] if rec.get("evidence_ref") else []))
    if force is not None:
        sighting = bool(force)
    else:
        sighting = bool(evidence_ref and evidence_ref not in refs) \
            or bool(observed_at and _day(observed_at) > _day(last))
    changed = sighting
    if not is_live(rec):                    # re-observed after forget_case: live again, and its
        for k in ("status", "retracted_at", "retracted_case"):   # provenance restarts here
            rec.pop(k, None)
        rec["cases"] = []
        changed = True
    cases = list(rec["cases"]) if rec.get("cases") is not None else [UNATTRIBUTED]
    tag = case or UNATTRIBUTED
    if tag not in cases:
        cases.append(tag)
        changed = True
    rec["cases"] = cases
    if observed_at:
        if not first or str(observed_at) < str(first):
            first = observed_at
        if not last or str(observed_at) >= str(last):
            last = observed_at
            if evidence_ref:
                rec["evidence_ref"] = evidence_ref
    if evidence_ref and evidence_ref not in refs:
        refs.insert(0, evidence_ref)
    rec[first_key], rec[last_key] = first, last
    rec["observations"] = int(rec.get("observations") or 1) + (1 if sighting else 0)
    if refs:
        rec["evidence_refs"] = refs[:EVIDENCE_REFS_CAP]
    return changed, sighting


def _forget(rec, cid, at, purge=False):
    """Apply forget_case(cid) to one fact/edge record in place. Returns the action: None (cid is
    not in its provenance — includes every UNATTRIBUTED-only record), 'shared' (other cases also
    recorded it: only cid is removed), 'retracted', 'already' (retracted earlier), or 'purge'
    (the caller deletes it)."""
    cs = rec.get("cases")
    if not cs or cid not in cs:
        return None
    others = [c for c in cs if c != cid]
    if others:
        rec["cases"] = others
        return "shared"
    if purge:
        return "purge"
    if not is_live(rec):
        return "already"
    rec.update(status="retracted", retracted_at=at, retracted_case=cid)
    return "retracted"


def _unattributed(rec):
    return set(rec.get("cases") or [UNATTRIBUTED]) == {UNATTRIBUTED}


def _norm_value(v):
    return json.dumps(v, sort_keys=True, ensure_ascii=False)


def _slot(ent, attribute):
    return [f for f in ent.get("facts") or [] if f.get("attribute") == attribute]


def _supersede(facts, losers, winner, clear=True):
    """Mark `losers` superseded by `winner`, history kept: superseded_by, and superseded_at — when
    the KB replaced it (transaction time, never a source date). The source-validity window is
    closed at the winner's effective day only for a CHANGE (that day falls after the loser's own
    start). A CORRECTION — the winner takes effect on or before the loser's start, i.e. its source
    says the loser never held — is flagged `corrected` and its validity is left untouched: closing
    it would end the window before it begins. With `clear`, a fact DISPUTING with the winner's
    value is corroboration now and loses its dispute."""
    wid, eff, wv = fact_id(winner), effective_day(winner), _norm_value(winner["value"])
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    for f in losers:
        f["status"], f["superseded_by"], f["superseded_at"] = "superseded", wid, now
        start = effective_day(f)
        if eff and start and eff <= start:
            f["corrected"] = True
        elif eff and not f.get("valid_until"):
            f["valid_until"], f["closed_by_supersede"] = eff, True
    if clear:
        for f in facts:
            if f.get("status") == "disputed" and _norm_value(f["value"]) == wv:
                f.pop("status", None)
                f.pop("disputes", None)


def _revive(f):
    """Undo _supersede on one fact (its writer re-asserted it and it wins again)."""
    for k in ("status", "superseded_by", "superseded_at", "corrected"):
        f.pop(k, None)
    if f.pop("closed_by_supersede", False):
        f.pop("valid_until", None)


def _disputes_of(ent):
    facts = [f for f in ent.get("facts") or [] if is_live(f)]
    by_id = {fact_id(f): f for f in facts}
    return [{"fact": f, "vs": [by_id[i] for i in f.get("disputes") or [] if i in by_id]}
            for f in facts if f.get("status") == "disputed"]


def disputes_markdown(kb_root, domains):
    """The assessment's `Conflicting Evidence` section for these domains — markdown lines, or []
    when no domain carries a disputed fact. Reads entity files only (no edge load), and never
    raises: a missing KB or unreadable entity simply contributes nothing."""
    def cell(f):
        v = f["value"] if isinstance(f["value"], str) else _norm_value(f["value"])
        since = effective_day(f) or "?"
        return (f"`{str(v)[:80]}` — {f['source']}/{f['collector']} · "
                f"{tier_of(f['source'], f['collector'])[1]} · since {since}").replace("|", "\\|")
    rows = []
    for d in sorted({str(x).strip().lower() for x in domains or () if x}):
        try:
            with open(_entity_path(os.path.abspath(kb_root), "domain", d), encoding="utf-8") as fh:
                ent = json.load(fh)
        except (OSError, ValueError):
            continue
        for x in _disputes_of(ent):
            for s in x["vs"] or [None]:
                rows.append(f"| `{d}` | {x['fact']['attribute']} | {cell(s) if s else '—'} | "
                            f"{cell(x['fact'])} |")
    if not rows:
        return []
    return ["## Conflicting Evidence (disputed facts)", "",
            "Sources disagree on a single-valued attribute and the newer claim did not outrank "
            "the standing one on authority (analyst > registry > vendor > extractor) and "
            "effective date. Both are kept — neither was silently overwritten. Resolve before "
            "relying on either value.", "",
            "| Domain | Attribute | Standing value | Disputing value |", "|---|---|---|---|",
            *rows, ""]


class KB:
    def __init__(self, root, case=None, as_of=None):
        self.root = os.path.abspath(root)
        self.ent_dir = os.path.join(self.root, "entities")
        self.rel_path = os.path.join(self.root, "relationships", "edges.jsonl")
        self.evidence_dir = os.path.join(self.root, "evidence")
        os.makedirs(self.ent_dir, exist_ok=True)
        os.makedirs(os.path.dirname(self.rel_path), exist_ok=True)
        os.makedirs(self.evidence_dir, exist_ok=True)
        self._edges = []
        self._edge_index = {}           # edge key -> its (folded) record in self._edges
        self._load_edges()
        self._display_index = None      # org key -> registrar spelling (built lazily)
        self.case = case_id(case)       # default case provenance for writes (see for_case)
        # Read-side view: every reader shows the KB as it held on this day (see holds_at).
        self.as_of = valid_day(as_of) if as_of else None
        if as_of and not self.as_of:
            raise ValueError(f"as_of must be YYYY-MM-DD (or an ISO datetime): {as_of!r}")

    def _visible(self, rec):
        """What readers see: live records holding at `as_of` (when set). A SUPERSEDED fact is
        history — shown only in an as_of view whose day falls inside its validity window; a
        CORRECTED one never held (its replacement's source says so) and is never shown."""
        if not is_live(rec):
            return False
        if rec.get("status") == "superseded":
            return (self.as_of is not None and not rec.get("corrected")
                    and holds_at(rec, self.as_of))
        return self.as_of is None or holds_at(rec, self.as_of)

    @contextlib.contextmanager
    def for_case(self, case):
        """Default case provenance for every write inside the block — an ingester working through
        one case's collection files. A None case keeps the current default."""
        prev = self.case
        self.case = case_id(case) or prev
        try:
            yield self
        finally:
            self.case = prev

    # ---------------------------------------------------------------- entities
    def _ent_file(self, etype, value):
        p = _entity_path(self.root, etype, value)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        return p

    def _read_entity(self, etype, value):
        f = self._ent_file(etype, value)
        if os.path.exists(f):
            return json.load(open(f, encoding="utf-8"))
        return {"type": etype, "value": value, "first_seen": None,
                "last_seen": None, "facts": []}

    def entity(self, etype, value, include_retracted=False):
        """One entity record — the facts visible to readers (live, and holding at `as_of` when the
        KB has one). include_retracted returns every stored fact."""
        ent = self._read_entity(etype, value)
        if not include_retracted:
            ent["facts"] = [f for f in ent.get("facts") or [] if self._visible(f)]
        return ent

    def _save_entity(self, ent):
        """Write an entity file atomically: a uniquely named temp file in the same directory, then
        os.replace. An interrupted write (killed process, full disk) leaves the previous file intact
        instead of a truncated one, and concurrent writers never share a temp name. No fsync: this
        guards against process death, not power loss."""
        path = self._ent_file(ent["type"], ent["value"])
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".ent-", suffix=".tmp")
        try:
            try:                        # mkstemp is 0600; keep the file's mode (new files 0644)
                os.chmod(tmp, os.stat(path).st_mode & 0o777)
            except OSError:
                os.chmod(tmp, 0o644)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(ent, fh, indent=2, ensure_ascii=False)
            os.replace(tmp, path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.remove(tmp)
            raise

    def _bump_seen(self, ent, observed_at):
        seen = [x for x in (ent.get("first_seen"), observed_at) if x]
        ent["first_seen"] = min(seen) if seen else observed_at
        seen = [x for x in (ent.get("last_seen"), observed_at) if x]
        ent["last_seen"] = max(seen) if seen else observed_at

    def touch(self, etype, value, observed_at=None):
        """Ensure an entity file exists (no facts). Used for edge endpoints."""
        f = self._ent_file(etype, value)
        if not os.path.exists(f):
            ent = {"type": etype, "value": value, "first_seen": observed_at,
                   "last_seen": observed_at, "facts": []}
            self._save_entity(ent)

    def add_fact(self, etype, value, attribute, fvalue, source, collector,
                 observed_at, confidence, evidence_ref=None, case=None,
                 valid_from=None, valid_until=None):
        """Attributed atomic fact. Idempotent on (attribute,value,source,collector); a repeat
        folds into the existing fact's sighting history (first_observed / observed_at /
        observations / evidence_refs) instead of duplicating it.

        Conflicts (same attribute, DIFFERENT value, different source) are kept as
        separate facts — the store never silently overwrites a disagreement. In a SINGLE-VALUED
        slot (kb_memory.json) a new value is reconciled (kb_reconcile.py): it supersedes the
        standing value only if it outranks it on authority AND effective date, else it is stored
        disputed; an empty/undated candidate is skipped.

        `case` (else the KB's default, see for_case) is recorded in the fact's `cases`.
        `valid_from` / `valid_until` — when the SOURCE says the fact held (a WHOIS era, a passive-DNS
        window, an archive capture) — are kept apart from when it was observed, widened across
        sightings, and drive as_of reads.

        Returns what happened: "extend" (already recorded — a sighting), "create", "supersede"
        (replaced the standing value), "dispute" (stored disputed) or "skip" (not stored).
        """
        c = case_id(case) or self.case
        ent = self._read_entity(etype, value)
        idx = {_fact_key(f): f for f in ent["facts"]}
        key = _fact_key({"attribute": attribute, "value": fvalue, "source": source,
                         "collector": collector})
        single = attribute in SINGLE_VALUED
        outcome = "create"
        if key in idx:
            rec = idx[key]
            outcome = "extend"
            was = rec.get("status")
            _apply_sighting(rec, "first_observed", "observed_at", observed_at, evidence_ref, case=c)
            _merge_validity(rec, valid_from, valid_until)
            if single and was in (None, "active", "superseded"):
                # Re-judge on re-observation. An ACTIVE value only ever wins here (settling a legacy
                # multi-value slot, or its writer's older claims) — it never demotes itself. A
                # SUPERSEDED value its writer re-asserts is judged like a new entry: it returns if it
                # wins, or as disputed when it displaces its writer's own newer claim but not a rival.
                judged = {k: v for k, v in rec.items() if k != "status"}
                action, sup, rivals = reconcile(_slot(ent, attribute), judged)
                if was != "superseded":
                    if sup:
                        _supersede(ent["facts"], sup, rec, clear=action == "supersede")
                elif action == "supersede" or sup:
                    _revive(rec)
                    _supersede(ent["facts"], sup, rec, clear=action == "supersede")
                    if action == "dispute":
                        rec["status"] = "disputed"
                        rec["disputes"] = sorted({fact_id(o) for o in rivals})
        else:
            fact = {"attribute": attribute, "value": fvalue, "source": source,
                    "collector": collector, "observed_at": observed_at,
                    "first_observed": observed_at, "observations": 1,
                    "confidence": _conf(confidence), "evidence_ref": evidence_ref,
                    "cases": [c or UNATTRIBUTED]}
            if evidence_ref:
                fact["evidence_refs"] = [evidence_ref]
            _merge_validity(fact, valid_from, valid_until)
            if single:
                action, sup, rivals = reconcile(_slot(ent, attribute), fact)
                if action == "skip":
                    return "skip"
                if sup:
                    _supersede(ent["facts"], sup, fact, clear=action == "supersede")
                if action == "dispute":
                    fact["status"] = "disputed"
                    fact["disputes"] = sorted({fact_id(o) for o in rivals})
                outcome = action
            ent["facts"].append(fact)
        self._bump_seen(ent, observed_at)
        self._save_entity(ent)
        return outcome

    def disputes(self, etype, value):
        """The entity's DISPUTED facts, each as {"fact", "vs": [standing facts it conflicts with]}."""
        return _disputes_of(self._read_entity(etype, value))

    def merge_fact(self, etype, value, fact):
        """Fold a complete fact record — sighting history and case provenance included — into
        (etype, value). Used when an entity is re-keyed (clean_kb org spellings), so the move keeps
        first_observed, observations, evidence_refs and cases instead of collapsing them."""
        ent = self._read_entity(etype, value)
        f = dict(fact)
        f.setdefault("first_observed", f.get("observed_at"))
        cur = next((x for x in ent["facts"] if _fact_key(x) == _fact_key(f)), None)
        if cur is None:
            ent["facts"].append(f)
        else:
            if is_live(f) and not is_live(cur):
                for k in ("status", "retracted_at", "retracted_case"):
                    cur.pop(k, None)
            cur["cases"] = list(dict.fromkeys(list(cur.get("cases") or [UNATTRIBUTED])
                                              + list(f.get("cases") or [UNATTRIBUTED])))
            firsts = [t for t in (cur.get("first_observed") or cur.get("observed_at"),
                                  f["first_observed"]) if t]
            later = f if str(f.get("observed_at") or "") > str(cur.get("observed_at") or "") else cur
            refs = []
            for r in ([later.get("evidence_ref")] + list(cur.get("evidence_refs") or [])
                      + list(f.get("evidence_refs") or [])):
                if r and r not in refs:
                    refs.append(r)
            cur["first_observed"] = min(firsts) if firsts else None
            cur["observed_at"] = later.get("observed_at")
            cur["evidence_ref"] = later.get("evidence_ref")
            cur["observations"] = int(cur.get("observations") or 1) + int(f.get("observations") or 1)
            if refs:
                cur["evidence_refs"] = refs[:EVIDENCE_REFS_CAP]
            _merge_validity(cur, f.get("valid_from"), f.get("valid_until"))
        self._bump_seen(ent, f.get("first_observed"))
        self._bump_seen(ent, f.get("observed_at"))
        self._save_entity(ent)

    # ---------------------------------------------------------------- edges
    @staticmethod
    def _edge_key(e):
        return tuple(e[k] for k in EDGE_KEY_FIELDS)

    def add_edge(self, src_type, src, rel, dst_type, dst, source, collector,
                 observed_at, confidence, evidence_ref=None, attrs=None, case=None,
                 valid_from=None, valid_until=None):
        """Attributed, deduped relationship. Ensures both endpoints exist as entities.

        `attrs` (optional) merges extra data-level fields onto the edge — e.g. a `hosted_on`
        edge's `first_seen`/`last_seen` hosting window from passive DNS. It does not affect the
        dedup key, so the first ingest's window is preserved on re-ingest.

        `case` (else the KB's default, see for_case) is recorded in the edge's `cases`;
        `valid_from` / `valid_until` as in add_fact (widened across sightings, unlike attrs).

        A repeat of an existing edge that changes it (see _apply_sighting, or a wider validity
        window) appends one `{"_op": "seen"}` fold line; a same-day re-ingest of the same evidence
        writes nothing."""
        c = case_id(case) or self.case
        e = {"src_type": src_type, "src": src, "rel": rel, "dst_type": dst_type,
             "dst": dst, "source": source, "collector": collector,
             "observed_at": observed_at, "confidence": _conf(confidence),
             "evidence_ref": evidence_ref, "cases": [c or UNATTRIBUTED]}
        if attrs:
            e.update(attrs)
        k = self._edge_key(e)
        cur = self._edge_index.get(k)
        if cur is None:
            _merge_validity(e, valid_from, valid_until)
            self._edge_index[k] = e
            self._edges.append(e)
            self._display_index = None
            self._append_edge_line(e)
        else:
            was_live = is_live(cur)
            changed, sighting = _apply_sighting(cur, "observed_at", "last_observed", observed_at,
                                                evidence_ref, case=c)
            widened = _merge_validity(cur, valid_from, valid_until)
            if changed or widened:
                fold = {"_op": "seen", **{f: e[f] for f in EDGE_KEY_FIELDS},
                        "observed_at": observed_at, "evidence_ref": evidence_ref, "case": c}
                if not sighting:
                    fold["sighting"] = False
                for b, v in (("valid_from", valid_from), ("valid_until", valid_until)):
                    if valid_day(v):
                        fold[b] = valid_day(v)
                self._append_edge_line(fold)
            if not was_live:
                self._display_index = None
        self.touch(src_type, src, observed_at)
        self.touch(dst_type, dst, observed_at)

    def _append_edge_line(self, rec):
        with open(self.rel_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")

    def _fold_edge(self, rec):
        """Load one edges.jsonl line: a base edge (a duplicate base line from a concurrent writer
        folds as a sighting), a `seen` fold line, or a `forget` fold line onto its base edge."""
        op = rec.pop("_op", None)
        try:
            k = self._edge_key(rec)
        except KeyError:
            sys.stderr.write(f"[kb] skipped edge line without a full key in {self.rel_path}\n")
            return
        cur = self._edge_index.get(k)
        if cur is None:
            if op:
                sys.stderr.write(f"[kb] skipped orphan '{op}' line in {self.rel_path}\n")
                return
            self._edge_index[k] = rec
            self._edges.append(rec)
            return
        if op is None:
            cs = rec.get("cases") or [None]
            _apply_sighting(cur, "observed_at", "last_observed", rec.get("observed_at"),
                            rec.get("evidence_ref"), case=cs[0], force=True)
            cur["cases"] = list(dict.fromkeys(cur["cases"] + [c for c in cs[1:] if c]))
            _merge_validity(cur, rec.get("valid_from"), rec.get("valid_until"))
        elif op == "seen":
            _apply_sighting(cur, "observed_at", "last_observed", rec.get("observed_at"),
                            rec.get("evidence_ref"), case=rec.get("case"),
                            force=rec.get("sighting", True))
            _merge_validity(cur, rec.get("valid_from"), rec.get("valid_until"))
        elif op == "forget":
            _forget(cur, rec.get("case"), rec.get("at"))
        else:
            sys.stderr.write(f"[kb] skipped unknown edge op '{op}' in {self.rel_path}\n")

    def _load_edges(self):
        if not os.path.exists(self.rel_path):
            return
        with open(self.rel_path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    # edges.jsonl is append-only; an interrupted append leaves a partial final
                    # line. Skip it (and warn) instead of crashing every KB tool at construction.
                    sys.stderr.write(f"[kb] skipped malformed edge line in {self.rel_path}\n")
                    continue
                if isinstance(rec, dict):
                    self._fold_edge(rec)

    # ---------------------------------------------------------------- evidence
    def save_evidence(self, source, target, raw_obj, day):
        d = os.path.join(self.evidence_dir, _slug(source), _slug(target))
        os.makedirs(d, exist_ok=True)
        p = os.path.join(d, f"{day}.json")
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(raw_obj, fh, indent=2, ensure_ascii=False)
        return os.path.relpath(p, self.root)

    # ---------------------------------------------------------------- queries
    def all_entities(self, include_retracted=False):
        """Every entity record with the facts visible to readers (live, holding at `as_of` when the
        KB has one); include_retracted returns every stored fact."""
        for root, _, files in os.walk(self.ent_dir):
            for fn in files:
                if not fn.endswith(".json"):
                    continue
                p = os.path.join(root, fn)
                try:
                    with open(p, encoding="utf-8") as fh:
                        ent = json.load(fh)
                except (json.JSONDecodeError, OSError):
                    sys.stderr.write(f"[kb] skipped unreadable entity file {p}\n")
                    continue
                if not include_retracted:
                    ent["facts"] = [f for f in ent.get("facts") or [] if self._visible(f)]
                yield ent

    def edges(self, include_retracted=False):
        """Every edge (folded) visible to readers — live, and holding at `as_of` when the KB has
        one. include_retracted returns every stored edge (the raw view clean_kb rewrites)."""
        return [e for e in self._edges if include_retracted or self._visible(e)]

    def neighbors(self, etype, value):
        """Entities one edge away from (etype,value), with the connecting rel."""
        out = []
        for e in self.edges():
            if e["src_type"] == etype and e["src"] == value:
                out.append((e["dst_type"], e["dst"], e["rel"], e["confidence"]))
            elif e["dst_type"] == etype and e["dst"] == value:
                out.append((e["src_type"], e["src"], e["rel"], e["confidence"]))
        return out

    def display_value(self, etype, value):
        """The human-readable form of an entity value. `org` nodes are keyed on
        noise_filters.canonical_org_key ('company a ltd'); this returns the registrar's own spelling
        instead — the one carried by the most `registered_by` edges (`display` attr), ties to the
        earliest-seen, else the first-seen `display_name` fact, else the key. Other types: unchanged."""
        if etype != "org":
            return value
        if self._display_index is None:
            votes: dict = {}
            for e in self.edges():
                if e.get("dst_type") == "org" and e.get("display"):
                    n, first = votes.setdefault(e["dst"], {}).get(e["display"], (0, None))
                    obs = str(e.get("observed_at") or "")
                    votes[e["dst"]][e["display"]] = (n + 1, obs if first is None else min(first, obs))
            self._display_index = {k: min(v.items(), key=lambda kv: (-kv[1][0], kv[1][1], kv[0]))[0]
                                   for k, v in votes.items()}
        if value in self._display_index:
            return self._display_index[value]
        facts = [f for f in self.entity("org", value).get("facts") or []
                 if f.get("attribute") == "display_name" and f.get("value")]
        best = (min(facts, key=lambda f: (str(f.get("observed_at") or ""), str(f["value"])))["value"]
                if facts else value)
        self._display_index[value] = best
        return best

    def shared_indicators(self, min_domains=2, drop_noise=True):
        """Indicators (favicon/tracker/token/registrant/…) linked to >= N domains.
        These are the same-operator cluster seeds — the auto-correlation payoff.

        `drop_noise` (default on) filters out shared-INFRASTRUCTURE indicators — a
        managed-DNS nameserver, a parking favicon — that link unrelated domains without
        implying common ownership (see noise_filters.py). This cleans historical KBs too,
        not just fresh ingests.
        """
        try:
            from noise_filters import is_noise_indicator, is_noise_email
        except Exception:
            def is_noise_indicator(_):  # graceful degrade if module missing
                return False
            def is_noise_email(_):
                return False
        by_ind = {}
        for e in self.edges():
            # domain --rel--> indicator/email/person
            if e["src_type"] == "domain" and e["dst_type"] in ("indicator", "email", "person", "org"):
                if drop_noise and e["dst_type"] == "indicator" and is_noise_indicator(e["dst"]):
                    continue
                if drop_noise and e["dst_type"] == "email" and is_noise_email(e["dst"]):
                    continue
                by_ind.setdefault((e["dst_type"], e["dst"]), {}).setdefault(e["rel"], set()).add(e["src"])
        out = []
        for (dtype, dval), rels in by_ind.items():
            doms = set().union(*rels.values())
            if len(doms) >= min_domains:
                out.append({"indicator_type": dtype, "indicator": dval,
                            "display": self.display_value(dtype, dval),
                            "rels": sorted(rels), "domains": sorted(doms),
                            "domain_count": len(doms)})
        return sorted(out, key=lambda x: -x["domain_count"])

    # ---------------------------------------------------------------- forget
    def forget_case(self, case, purge=False, apply=False, hosts=None):
        """Remove one case's contribution from the KB — provenance-aware, dry-run unless `apply`.

        A fact/edge ONLY this case recorded is retracted (status=retracted: kept for audit, hidden
        from every reader; an edge via a `forget` fold line) or, with `purge`, deleted (edges.jsonl
        rewritten compacted). A record other cases also recorded keeps living with this case
        removed from its `cases`. Records with no case provenance (UNATTRIBUTED only — everything
        written before provenance existed) are never touched, only counted; `hosts` (the case's
        collected hosts) counts how many of those touch the case. Returns a report dict."""
        cid = case_id(case)
        if not cid:
            raise ValueError("forget_case needs a case id")
        at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        hosts = {str(h).strip().lower() for h in hosts or ()}
        acts = ("retracted", "shared", "already", "purge")
        rep = {"case": cid, "mode": "purge" if purge else "retract", "applied": bool(apply),
               "facts": dict.fromkeys(acts, 0), "edges": dict.fromkeys(acts, 0),
               "unattributed_facts": 0, "unattributed_edges": 0,
               "unattributed_touching_case_hosts": 0, "samples": []}

        def _note(kind, act, label):
            rep[kind][act] += 1
            if act in ("retracted", "purge") and len(rep["samples"]) < 10:
                rep["samples"].append(f"{kind[:-1]} {label}")

        for root, _, files in os.walk(self.ent_dir):
            for fn in sorted(files):
                if not fn.endswith(".json"):
                    continue
                p = os.path.join(root, fn)
                try:
                    with open(p, encoding="utf-8") as fh:
                        ent = json.load(fh)
                except (json.JSONDecodeError, OSError):
                    continue
                keep, changed = [], False
                for f in ent.get("facts") or []:
                    if _unattributed(f):
                        rep["unattributed_facts"] += 1
                        if str(ent.get("value", "")).lower() in hosts:
                            rep["unattributed_touching_case_hosts"] += 1
                    rec = f if apply else dict(f)
                    act = _forget(rec, cid, at, purge)
                    if act:
                        _note("facts", act, f"{ent['type']}:{ent['value']} "
                                            f"{f['attribute']}={json.dumps(f['value'], ensure_ascii=False)[:80]}")
                        changed = changed or act != "already"
                    if act != "purge":
                        keep.append(rec)
                if apply and changed:
                    ent["facts"] = keep
                    self._save_entity(ent)

        purged = set()
        for e in self._edges:
            if _unattributed(e):
                rep["unattributed_edges"] += 1
                if str(e["src"]).lower() in hosts or str(e["dst"]).lower() in hosts:
                    rep["unattributed_touching_case_hosts"] += 1
            rec = e if apply else dict(e)
            act = _forget(rec, cid, at, purge)
            if not act:
                continue
            _note("edges", act, f"{e['src']} -{e['rel']}-> {e['dst_type']}:{e['dst']}")
            if not apply:
                continue
            if act == "purge":
                purged.add(self._edge_key(e))
            elif act in ("shared", "retracted") and not purge:
                self._append_edge_line({"_op": "forget", **{k: e[k] for k in EDGE_KEY_FIELDS},
                                        "case": cid, "at": at})
        if apply and purge:
            self._edges = [e for e in self._edges if self._edge_key(e) not in purged]
            self._edge_index = {self._edge_key(e): e for e in self._edges}
            tmp = self.rel_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                for e in self._edges:
                    fh.write(json.dumps(e, ensure_ascii=False) + "\n")
            os.replace(tmp, self.rel_path)
        if apply:
            self._display_index = None
        return rep


# ------------------------------------------------------------------ tiny CLI
def _main():
    import argparse
    from collections import Counter
    ap = argparse.ArgumentParser(description="Knowledge-base stats.")
    ap.add_argument("root", help="knowledge/ directory")
    args = ap.parse_args()
    kb = KB(args.root)
    ents = list(kb.all_entities())
    types = Counter(e["type"] for e in ents)
    facts = sum(len(e["facts"]) for e in ents)
    print(f"entities: {len(ents)}  facts: {facts}  edges: {len(kb.edges())}")
    print("by type:", dict(types))


if __name__ == "__main__":
    _main()
