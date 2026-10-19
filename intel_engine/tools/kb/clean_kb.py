#!/usr/bin/env python3
"""
clean_kb.py — one-time hygiene sweep over an existing KB. Dry-run by default.

The collectors/ingester now reject bad data at the door, but edges ingested BEFORE those guards
persist (add_edge only adds). This removes the known garbage classes so correlation and the
money trail stop resting on noise:

  * invalid crypto wallets  — regex false-positives (md5/asset hashes) that fail checksum validation
  * IP-literal "domains"     — 0.0.0.0, 45.223.137.200:12169 ingested as domain entities
  * WHOIS-label "persons"    — "Registrant State/Province: Rome", "REACTIVATION PERIOD", etc.
  * org-as-person            — "Ultima Markets Pty Ltd" reclassified from person -> org (kept, retyped)
  * org spelling splits      — a `registered_by -> org` edge still keyed on a registrar's verbatim
    spelling ('Company A Co., Ltd') is re-keyed to noise_filters.canonical_org_key, so the comma /
    no-comma / legal-form / diacritic variants of one company collapse onto ONE org node (the old
    spelling is kept as a `display_name` fact); a privacy/redaction org edge is dropped.
  * era-forbidden registrants — a `registered_by` edge whose target is a PREVIOUS owner's WHOIS
    value (drop-catch/resale) rather than the current owner's (whois_eras.py owner_values(); the
    ingester's flat `history.registrant_*` read predates that guard). Checked against the WHOIS the
    ingester archived for that edge (its `evidence_ref`), never re-fetched. `--case` scopes this
    (and `--value`) to one case's domains; the four classes above stay KB-wide always.
  * `--value <selector>` — targeted purge of every edge touching one exact selector, regardless
    of classification (e.g. a specific registrar-abuse mailbox that slipped through).

Usage:
  python3 tools/kb/clean_kb.py --kb knowledge                        # dry-run: report only
  python3 tools/kb/clean_kb.py --kb knowledge --apply                 # rewrite edges + entity files
  python3 tools/kb/clean_kb.py --kb knowledge --case CASE-0001         # scope era/--value to a case
  python3 tools/kb/clean_kb.py --kb knowledge --value abuse@x.example --apply
"""
import argparse
import glob
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(HERE)), "WebPivot", "tools"))
# One source of truth with the ingester — including its registrant-noise lists, which it loads
# from references/registrant_noise.json. Re-pasting them here is what let them drift before.
from ingest_webpivot import (_is_role_placeholder, _ORG_SUFFIX,  # noqa: E402
                             _NAME_JUNK)
# The single ownership-era authority (WebPivot/tools/whois_eras.py) — a `registered_by` edge may
# only carry a CURRENT-era value; anything else is a previous owner and belongs in a fact, not here.
from whois_eras import owner_values  # noqa: E402
from noise_filters import canonical_org_key, is_noise_org  # noqa: E402
try:
    from wp_extract import valid_crypto_address as _valid_wallet
except Exception:
    def _valid_wallet(label, value):
        return True

_IP = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}(?:[:_]\d+)?$")


def _wallet_parts(dst):                 # "wallet:btc:<addr>" -> ("btc","<addr>")
    p = dst.split(":", 2)
    return (p[1], p[2]) if len(p) == 3 else (None, None)


def _name_kind(nm):
    s = (nm or "").strip().lower()
    if not s or any(j in s for j in _NAME_JUNK):
        return None
    if any(suf in " " + s for suf in _ORG_SUFFIX):
        return "org"
    return "person"


def classify_edge(e):
    """Return ('drop', reason) | ('retype', 'org') | ('keep', None)."""
    for role in ("src", "dst"):
        if e[f"{role}_type"] == "domain" and _IP.match(e[role]):
            return ("drop", "ip-literal domain")
    if e["rel"] == "uses_wallet" and e["dst_type"] == "indicator" and e["dst"].startswith("wallet:"):
        kind, addr = _wallet_parts(e["dst"])
        if addr and not _valid_wallet(kind, addr):
            return ("drop", "invalid wallet (checksum / reference vector / token contract)")
    if e["rel"] == "registered_by" and e["dst_type"] in ("person", "org"):
        # Generic registrant ROLE boilerplate ("Domain Admin", "Hostmaster", …). The ingester now
        # rejects these at the door, but edges created BEFORE that guard persist — and one such
        # edge silently merges every domain whose registrar emitted the same placeholder.
        if _is_role_placeholder(e["dst"]):
            return ("drop", "generic registrant role placeholder")
    if e["rel"] == "registered_by" and e["dst_type"] == "org" and is_noise_org(e["dst"]):
        return ("drop", "privacy/redaction registrant org")
    if e["rel"] == "registered_by" and e["dst_type"] == "person":
        k = _name_kind(e["dst"])
        if k is None:
            return ("drop", "whois-label person")
        if k == "org":
            return ("retype", "org")
    return ("keep", None)


def _era_whois(evidence_ref, kb_root):
    """Load the ingester's archived pivot_extract JSON for a `registered_by` edge and return its
    WHOIS block — the SAME record whois_eras.split_eras would have seen at ingest time. Never
    re-fetched: a classification and the evidence it is judged against must agree."""
    if not evidence_ref:
        return None
    path = evidence_ref if os.path.isabs(evidence_ref) else os.path.join(kb_root, evidence_ref)
    try:
        raw = json.load(open(path, encoding="utf-8"))
    except Exception:
        return None
    return (raw.get("artifacts") or {}).get("whois")


def era_forbidden(e, kb_root):
    """True if a `registered_by` edge's target is NOT an owner_values() hit for the domain's
    archived WHOIS — i.e. it is a previous owner's era value (drop-catch, resale) or an undated
    one, which whois_eras.py's contract says may only ever be recorded as a FACT, never this edge.
    Missing evidence never counts as forbidden — an edge is purged on positive proof it predates
    the current owner, not on absent data."""
    if e.get("rel") != "registered_by" or e.get("dst_type") not in ("email", "person", "org", "phone"):
        return False
    wh = _era_whois(e.get("evidence_ref"), kb_root)
    if not wh:
        return False
    dst = str(e.get("dst") or "")
    if e["dst_type"] == "phone":
        target = re.sub(r"\D", "", dst)
        pool = {re.sub(r"\D", "", str(v)) for v in owner_values(wh, "phone")}
    elif e["dst_type"] == "email":
        target = dst.strip().lower()
        pool = {str(v).strip().lower() for v in owner_values(wh, "email")}
    elif e["dst_type"] == "org":   # org edges carry canonical_org_key — compare keys, not spellings
        target = canonical_org_key(dst)
        pool = {canonical_org_key(v) for v in owner_values(wh, "name") + owner_values(wh, "org")}
    else:  # person — the ingester draws it from the same registrant name/org pool
        target = re.sub(r"\s+", " ", dst.strip().lower())
        pool = {re.sub(r"\s+", " ", str(v).strip().lower())
                for v in owner_values(wh, "name") + owner_values(wh, "org")}
    return bool(pool) and target not in pool


def _case_hosts(case_id, kb_root):
    """Domains collected into `case_id` — cases/<id>/raw/*.json sits alongside the KB under the
    same $INTEL_HOME, so this needs no new configuration. Empty on a missing/unreadable case dir:
    a scope that matches nothing, never one that silently widens to the whole KB."""
    raw_dir = os.path.join(os.path.dirname(kb_root), "cases", case_id, "raw")
    hosts = set()
    for fn in glob.glob(os.path.join(raw_dir, "*.json")):
        try:
            d = json.load(open(fn, encoding="utf-8"))
        except Exception:
            continue
        h = (d.get("meta") or {}).get("host")
        if h:
            hosts.add(str(h).strip().lower())
    return hosts


def main():
    ap = argparse.ArgumentParser(description="KB hygiene sweep (dry-run by default).")
    ap.add_argument("--kb", required=True)
    ap.add_argument("--apply", action="store_true", help="actually rewrite (default: report only)")
    ap.add_argument("--case", help="scope the era-purge/--value checks to one case's domains "
                                   "(cases/<id>/raw/*.json hosts); the original four garbage "
                                   "classes stay KB-wide regardless")
    ap.add_argument("--value", help="targeted purge: drop every edge touching this exact selector "
                                    "(email/name/phone/domain), regardless of classification — "
                                    "scoped by --case if both are given")
    a = ap.parse_args()
    kb_root = os.path.abspath(a.kb)
    edges_path = os.path.join(kb_root, "relationships", "edges.jsonl")
    ent_dir = os.path.join(kb_root, "entities")
    edges = [json.loads(l) for l in open(edges_path, encoding="utf-8") if l.strip()]
    case_hosts = _case_hosts(a.case, kb_root) if a.case else None
    value_l = a.value.strip().lower() if a.value else None

    kept, drop_reasons, retyped = [], {}, 0
    rekeyed, org_seen = {}, set()     # canonical org key -> {old spellings}; dedupe merged edges
    drop_domains, drop_persons, drop_wallets = set(), set(), set()
    era_dropped, value_dropped = [], []
    for e in edges:
        action, info = classify_edge(e)
        if action == "keep":
            in_scope = (case_hosts is None or str(e["src"]).strip().lower() in case_hosts
                       or str(e["dst"]).strip().lower() in case_hosts)
            if in_scope and value_l and (str(e["dst"]).strip().lower() == value_l
                                        or str(e["src"]).strip().lower() == value_l):
                action, info = "drop", "manual selector purge"
                value_dropped.append(e)
            elif in_scope and era_forbidden(e, kb_root):
                action, info = "drop", "prior-era/non-owner registered_by value"
                era_dropped.append(e)
        if action == "drop":
            drop_reasons[info] = drop_reasons.get(info, 0) + 1
            if info == "ip-literal domain":
                for role in ("src", "dst"):
                    if e[f"{role}_type"] == "domain" and _IP.match(e[role]):
                        drop_domains.add(e[role])
            elif info == "whois-label person":
                drop_persons.add(e["dst"])
            elif info.startswith("invalid wallet"):
                drop_wallets.add(e["dst"])
            continue
        if action == "retype":
            e = dict(e, dst_type="org")
            retyped += 1
        if e["rel"] == "registered_by" and e["dst_type"] == "org":
            if is_noise_org(e["dst"]):        # a retyped person that is a privacy/redaction org
                drop_reasons["privacy/redaction registrant org"] = \
                    drop_reasons.get("privacy/redaction registrant org", 0) + 1
                continue
            key = canonical_org_key(e["dst"])
            if key and key != e["dst"]:
                rekeyed.setdefault(key, set()).add(e["dst"])
                e = dict(e, dst=key, display=e.get("display") or e["dst"])
            ek = (e["src_type"], e["src"], e["rel"], e["dst_type"], e["dst"], e["source"],
                  e["collector"])
            if ek in org_seen:                # two spellings of one org on one domain → one edge
                continue
            org_seen.add(ek)
        kept.append(e)

    scope_note = "".join([f"  [case={a.case}]" if a.case else "",
                         f"  [value={a.value}]" if a.value else ""])
    print(f"# KB hygiene sweep on {a.kb}  ({'APPLY' if a.apply else 'dry-run'}){scope_note}")
    print(f"  edges: {len(edges)} -> {len(kept)}  (dropped {len(edges) - len(kept)}, retyped person→org {retyped}, "
          f"re-keyed org spellings {sum(len(v) for v in rekeyed.values())} → {len(rekeyed)} org node(s))")
    for r, c in sorted(drop_reasons.items(), key=lambda x: -x[1]):
        print(f"    - {c:4} {r}")
    print(f"  entity files to remove: {len(drop_domains)} ip-domain, {len(drop_persons)} label-person, "
          f"{len(drop_wallets)} invalid-wallet indicator")
    if era_dropped:
        print(f"  era-forbidden registered_by edges ({len(era_dropped)}):")
        for e in era_dropped:
            print(f"      {e['src']} --registered_by--> {e['dst_type']}:{e['dst']}")
    if value_dropped:
        print(f"  --value {a.value!r} selector purge ({len(value_dropped)}):")
        for e in value_dropped:
            print(f"      {e['src']} --{e['rel']}--> {e['dst_type']}:{e['dst']}")
    for key, olds in sorted(rekeyed.items())[:10]:
        print(f"      org {sorted(olds)} → {key!r}")
    if not a.apply:
        for label, s in (("ip-domain", drop_domains), ("label-person", drop_persons),
                         ("invalid-wallet", drop_wallets)):
            for v in list(s)[:5]:
                print(f"      {label}: {v}")
        print("\n  dry-run — nothing written. Re-run with --apply to execute.")
        return

    # rewrite edges — atomically, so an interrupted clean can't truncate the core edge store
    tmp = edges_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        for e in kept:
            fh.write(json.dumps(e, ensure_ascii=False) + "\n")
    os.replace(tmp, edges_path)

    def _rm(etype, value):
        f = os.path.join(ent_dir, etype, re.sub(r"[^a-zA-Z0-9._@-]", "_", str(value))[:200] + ".json")
        if os.path.isfile(f):
            os.remove(f)
            return 1
        return 0

    removed = 0
    for v in drop_domains:
        removed += _rm("domain", v)
    for v in drop_persons:
        removed += _rm("person", v)
    for v in drop_wallets:
        removed += _rm("indicator", v)
    # re-keyed orgs: move each old spelling's facts onto the canonical node and keep the spelling
    # itself as a display_name fact, then drop the orphaned per-spelling entity file.
    if rekeyed:
        from knowledge_base import KB  # noqa: E402
        kb = KB(kb_root)
        for key, olds in rekeyed.items():
            for old in sorted(olds):
                ent = kb.entity("org", old)
                for f in ent.get("facts") or []:
                    kb.add_fact("org", key, f["attribute"], f["value"], f["source"], f["collector"],
                                f.get("observed_at"), f.get("confidence", 0.5), f.get("evidence_ref"))
                kb.add_fact("org", key, "display_name", old, "clean_kb", "kb/clean_kb",
                            ent.get("last_seen"), "high")
                old_f = kb._ent_file("org", old)
                if old_f != kb._ent_file("org", key) and os.path.isfile(old_f):
                    os.remove(old_f)
                    removed += 1
    print(f"  applied: rewrote edges.jsonl, removed {removed} entity file(s).")
    print("  (retyped person→org entities will be recreated as type 'org' on next ingest.)")


if __name__ == "__main__":
    main()
