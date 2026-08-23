#!/usr/bin/env python3
"""
clean_kb.py — one-time hygiene sweep over an existing KB. Dry-run by default.

The collectors/ingester now reject bad data at the door, but edges ingested BEFORE those guards
persist (add_edge only adds). This removes the four known garbage classes so correlation and the
money trail stop resting on noise:

  * invalid crypto wallets  — regex false-positives (md5/asset hashes) that fail checksum validation
  * IP-literal "domains"     — 0.0.0.0, 45.223.137.200:12169 ingested as domain entities
  * WHOIS-label "persons"    — "Registrant State/Province: Rome", "REACTIVATION PERIOD", etc.
  * org-as-person            — "Ultima Markets Pty Ltd" reclassified from person -> org (kept, retyped)

Usage:
  python3 tools/kb/clean_kb.py --kb knowledge                 # dry-run: report only
  python3 tools/kb/clean_kb.py --kb knowledge --apply         # rewrite edges + entity files
"""
import argparse
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
try:
    from pivot_extract import valid_crypto_address as _valid_wallet
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
            return ("drop", "invalid wallet (checksum)")
    if e["rel"] == "registered_by" and e["dst_type"] in ("person", "org"):
        # Generic registrant ROLE boilerplate ("Domain Admin", "Hostmaster", …). The ingester now
        # rejects these at the door, but edges created BEFORE that guard persist — and one such
        # edge silently merges every domain whose registrar emitted the same placeholder.
        if _is_role_placeholder(e["dst"]):
            return ("drop", "generic registrant role placeholder")
    if e["rel"] == "registered_by" and e["dst_type"] == "person":
        k = _name_kind(e["dst"])
        if k is None:
            return ("drop", "whois-label person")
        if k == "org":
            return ("retype", "org")
    return ("keep", None)


def main():
    ap = argparse.ArgumentParser(description="KB hygiene sweep (dry-run by default).")
    ap.add_argument("--kb", required=True)
    ap.add_argument("--apply", action="store_true", help="actually rewrite (default: report only)")
    a = ap.parse_args()
    edges_path = os.path.join(a.kb, "relationships", "edges.jsonl")
    ent_dir = os.path.join(a.kb, "entities")
    edges = [json.loads(l) for l in open(edges_path, encoding="utf-8") if l.strip()]

    kept, drop_reasons, retyped = [], {}, 0
    drop_domains, drop_persons, drop_wallets = set(), set(), set()
    for e in edges:
        action, info = classify_edge(e)
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
        kept.append(e)

    print(f"# KB hygiene sweep on {a.kb}  ({'APPLY' if a.apply else 'dry-run'})")
    print(f"  edges: {len(edges)} -> {len(kept)}  (dropped {len(edges) - len(kept)}, retyped person→org {retyped})")
    for r, c in sorted(drop_reasons.items(), key=lambda x: -x[1]):
        print(f"    - {c:4} {r}")
    print(f"  entity files to remove: {len(drop_domains)} ip-domain, {len(drop_persons)} label-person, "
          f"{len(drop_wallets)} invalid-wallet indicator")
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
    print(f"  applied: rewrote edges.jsonl, removed {removed} entity file(s).")
    print("  (retyped person→org entities will be recreated as type 'org' on next ingest.)")


if __name__ == "__main__":
    main()
