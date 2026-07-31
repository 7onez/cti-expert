#!/usr/bin/env python3
"""
knowledge_base.py — normalized, append-only, attributed OSINT knowledge store.

Implements the entity / relationship / evidence model from the architecture doc §5-6:
  * every atomic fact carries provenance (source, collector, observed_at, confidence,
    evidence_ref) — nothing is stored without saying who said it, using what, when.
  * idempotent: re-ingesting a target UPDATES facts/edges instead of duplicating them.
  * conflicts are kept, not overwritten — two sources disagreeing both stay, attributed.

Storage (files now; drop into SQLite/graph DB later with no schema change):
  knowledge/
    entities/<type>/<value>.json     one record per entity, facts merged across sources
    relationships/edges.jsonl        one attributed edge per line
    evidence/<source>/<target>/<day>.json   raw cached payloads (attribution backing)

This is a LIBRARY (collectors call it) + a tiny CLI for stats. It does no I/O to the web.
"""
import os
import re
import sys
import json

CONF_WORDS = {"high": 0.9, "medium": 0.6, "low": 0.35, "inferred": 0.4, "confirmed": 0.9}

# canonical entity types (extensible)
ENTITY_TYPES = {"domain", "ip", "cidr", "asn", "tls_cert", "url", "email", "org",
                "person", "file_hash", "malware", "cve", "indicator"}


def _slug(s):
    return re.sub(r"[^a-zA-Z0-9._@-]", "_", str(s)).strip("_")[:200] or "_"


def _conf(c):
    if isinstance(c, (int, float)):
        return float(c)
    return CONF_WORDS.get(str(c).lower(), 0.5)


class KB:
    def __init__(self, root):
        self.root = os.path.abspath(root)
        self.ent_dir = os.path.join(self.root, "entities")
        self.rel_path = os.path.join(self.root, "relationships", "edges.jsonl")
        self.evidence_dir = os.path.join(self.root, "evidence")
        os.makedirs(self.ent_dir, exist_ok=True)
        os.makedirs(os.path.dirname(self.rel_path), exist_ok=True)
        os.makedirs(self.evidence_dir, exist_ok=True)
        self._edges = self._load_edges()
        self._edge_keys = {self._edge_key(e) for e in self._edges}

    # ---------------------------------------------------------------- entities
    def _ent_file(self, etype, value):
        d = os.path.join(self.ent_dir, _slug(etype))
        os.makedirs(d, exist_ok=True)
        return os.path.join(d, _slug(value) + ".json")

    def entity(self, etype, value):
        f = self._ent_file(etype, value)
        if os.path.exists(f):
            return json.load(open(f, encoding="utf-8"))
        return {"type": etype, "value": value, "first_seen": None,
                "last_seen": None, "facts": []}

    def _save_entity(self, ent):
        with open(self._ent_file(ent["type"], ent["value"]), "w", encoding="utf-8") as fh:
            json.dump(ent, fh, indent=2, ensure_ascii=False)

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
                 observed_at, confidence, evidence_ref=None):
        """Attributed atomic fact. Idempotent on (attribute,value,source,collector).

        Conflicts (same attribute, DIFFERENT value, different source) are kept as
        separate facts — the store never silently overwrites a disagreement.
        """
        ent = self.entity(etype, value)
        norm = json.dumps(fvalue, sort_keys=True, ensure_ascii=False)
        idx = {(f["attribute"], json.dumps(f["value"], sort_keys=True, ensure_ascii=False),
                f["source"], f["collector"]): f for f in ent["facts"]}
        key = (attribute, norm, source, collector)
        if key in idx:
            idx[key]["observed_at"] = observed_at
            if evidence_ref:
                idx[key]["evidence_ref"] = evidence_ref
        else:
            ent["facts"].append({
                "attribute": attribute, "value": fvalue, "source": source,
                "collector": collector, "observed_at": observed_at,
                "confidence": _conf(confidence), "evidence_ref": evidence_ref})
        self._bump_seen(ent, observed_at)
        self._save_entity(ent)

    # ---------------------------------------------------------------- edges
    def _edge_key(self, e):
        return (e["src_type"], e["src"], e["rel"], e["dst_type"], e["dst"],
                e["source"], e["collector"])

    def add_edge(self, src_type, src, rel, dst_type, dst, source, collector,
                 observed_at, confidence, evidence_ref=None, attrs=None):
        """Attributed, deduped relationship. Ensures both endpoints exist as entities.

        `attrs` (optional) merges extra data-level fields onto the edge — e.g. a `hosted_on`
        edge's `first_seen`/`last_seen` hosting window from passive DNS. It does not affect the
        dedup key, so the first ingest's window is preserved on re-ingest."""
        e = {"src_type": src_type, "src": src, "rel": rel, "dst_type": dst_type,
             "dst": dst, "source": source, "collector": collector,
             "observed_at": observed_at, "confidence": _conf(confidence),
             "evidence_ref": evidence_ref}
        if attrs:
            e.update(attrs)
        k = self._edge_key(e)
        if k not in self._edge_keys:
            self._edge_keys.add(k)
            self._edges.append(e)
            with open(self.rel_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(e, ensure_ascii=False) + "\n")
        self.touch(src_type, src, observed_at)
        self.touch(dst_type, dst, observed_at)

    def _load_edges(self):
        if not os.path.exists(self.rel_path):
            return []
        out = []
        with open(self.rel_path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    # edges.jsonl is append-only; an interrupted append leaves a partial final
                    # line. Skip it (and warn) instead of crashing every KB tool at construction.
                    sys.stderr.write(f"[kb] skipped malformed edge line in {self.rel_path}\n")
        return out

    # ---------------------------------------------------------------- evidence
    def save_evidence(self, source, target, raw_obj, day):
        d = os.path.join(self.evidence_dir, _slug(source), _slug(target))
        os.makedirs(d, exist_ok=True)
        p = os.path.join(d, f"{day}.json")
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(raw_obj, fh, indent=2, ensure_ascii=False)
        return os.path.relpath(p, self.root)

    # ---------------------------------------------------------------- queries
    def all_entities(self):
        for root, _, files in os.walk(self.ent_dir):
            for fn in files:
                if not fn.endswith(".json"):
                    continue
                p = os.path.join(root, fn)
                try:
                    with open(p, encoding="utf-8") as fh:
                        yield json.load(fh)
                except (json.JSONDecodeError, OSError):
                    sys.stderr.write(f"[kb] skipped unreadable entity file {p}\n")

    def edges(self):
        return list(self._edges)

    def neighbors(self, etype, value):
        """Entities one edge away from (etype,value), with the connecting rel."""
        out = []
        for e in self._edges:
            if e["src_type"] == etype and e["src"] == value:
                out.append((e["dst_type"], e["dst"], e["rel"], e["confidence"]))
            elif e["dst_type"] == etype and e["dst"] == value:
                out.append((e["src_type"], e["src"], e["rel"], e["confidence"]))
        return out

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
        for e in self._edges:
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
                            "rels": sorted(rels), "domains": sorted(doms),
                            "domain_count": len(doms)})
        return sorted(out, key=lambda x: -x["domain_count"])


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
