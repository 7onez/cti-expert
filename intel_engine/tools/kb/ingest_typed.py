#!/usr/bin/env python3
"""ingest_typed — rung-aware KB writes for cross-type auto-pivot corpus rows.

Contract (phase 3):
  ingest_rows(kb, case, origin_type, origin_value, rows, *, route) -> int

Rung semantics (collecting ≠ attributing):
  * owner  → kb.add_edge(origin → row)
  * kit    → kb.add_fact(attribute="kit_sibling")   NEVER add_edge
  * neighbour → kb.add_fact(attribute="neighbour")  NEVER add_edge
  * mention   → kb.add_fact(attribute="mention")    NEVER add_edge

Rows are dicts: {type, value, rung_class, source, evidence?, coin?}.
type "mention" is always a fact (never an edge endpoint seed).
"""
from __future__ import annotations

import datetime
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_TOOLS = os.path.dirname(_HERE)
if _TOOLS not in sys.path:
    sys.path.insert(0, _TOOLS)
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

try:
    from selector_types import kb_key, rung_for  # noqa: E402
except Exception:  # noqa: BLE001 — degrade: everything is kit, no edges
    def kb_key(type_, value, *, coin=""):
        t = (type_ or "").strip().lower()
        v = str(value or "").strip()
        if t == "domain":
            return "domain", v.lower()
        if t == "email":
            return "email", v.lower()
        return "indicator", f"{t}:{v}"

    def rung_for(_rc):
        return "kit"


def _utcnow():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _rel_for(rung_class: str, route: str) -> str:
    """Edge relationship label for an owner-link row."""
    rc = (rung_class or "").strip().lower()
    if rc.startswith("analytics."):
        return "shares_tracker"
    if rc.startswith("whois."):
        return "registrant_of" if "email" in rc or "phone" in rc else "whois_link"
    if rc.startswith("wallet."):
        return "controls_wallet"
    if rc.startswith("token."):
        return "shares_token"
    if rc.startswith("cert."):
        return "shares_cert"
    return f"pivot:{(route or 'corpus').replace('.', '_')}"


def ingest_rows(kb, case, origin_type, origin_value, rows, *, route) -> int:
    """Write typed corpus rows into `kb`. Returns the number of rows accepted.

    Owner rows become edges from the origin selector; kit/neighbour/mention become
    facts on the ORIGIN entity (and the row entity is touched so it exists). Never
    calls add_edge for kit, neighbour or mention rows.
    """
    if kb is None:
        return 0
    origin_t = (origin_type or "string").strip().lower()
    origin_v = str(origin_value or "").strip()
    if not origin_v:
        return 0
    src_etype, src_val = kb_key(origin_t, origin_v)
    when = _utcnow()
    collector = f"pivot_routes/{route}" if route else "pivot_routes"
    accepted = 0
    for raw in rows or []:
        if not isinstance(raw, dict):
            continue
        rtype = (raw.get("type") or "").strip().lower()
        rval = str(raw.get("value") or "").strip()
        if not rtype or not rval:
            continue
        rc = str(raw.get("rung_class") or "").strip()
        source = str(raw.get("source") or route or "corpus")
        evidence = raw.get("evidence") if isinstance(raw.get("evidence"), dict) else {}
        coin = str(raw.get("coin") or "")
        # mention is always a fact type
        if rtype == "mention":
            rung = "mention"
        else:
            rung = rung_for(rc) if rc else "kit"
        dst_etype, dst_val = kb_key(rtype if rtype != "mention" else "string", rval, coin=coin)
        conf = "medium"
        ev_ref = None
        try:
            if evidence:
                day = when[:10]
                ev_ref = kb.save_evidence(source, dst_val, {
                    "route": route, "origin": {"type": origin_t, "value": origin_v},
                    "row": {"type": rtype, "value": rval, "rung_class": rc},
                    "evidence": evidence, "case": case,
                }, day)
        except Exception:  # noqa: BLE001
            ev_ref = None

        if rung == "owner" and rtype != "mention":
            # Clustering (KB.shared_indicators / query._components) reads domain→indicator edges,
            # so a host found through an owner selector is written FROM the host TO the selector —
            # the same direction ingest_webpivot uses for a tracker or wallet on the page.
            a_t, a_v, b_t, b_v = ((dst_etype, dst_val, src_etype, src_val)
                                  if dst_etype == "domain" and src_etype != "domain"
                                  else (src_etype, src_val, dst_etype, dst_val))
            try:
                kb.add_edge(a_t, a_v, _rel_for(rc, route or ""), b_t, b_v,
                            source=source, collector=collector,
                            observed_at=when, confidence=conf, evidence_ref=ev_ref,
                            attrs={"rung_class": rc, "route": route, "case": case} if case else {
                                "rung_class": rc, "route": route})
                accepted += 1
            except Exception:  # noqa: BLE001
                continue
            continue

        # kit / neighbour / mention → facts ONLY (never add_edge)
        if rung == "neighbour":
            attr = "neighbour"
        elif rtype == "mention" or rung == "mention":
            attr = "mention"
        else:
            attr = "kit_sibling"
        fvalue = {
            "type": rtype,
            "value": rval,
            "rung_class": rc or ("string" if rtype == "mention" else ""),
            "route": route,
            "dst_entity": [dst_etype, dst_val],
        }
        if coin:
            fvalue["coin"] = coin
        if evidence:
            fvalue["evidence"] = {k: evidence[k] for k in list(evidence)[:8]}
        try:
            kb.add_fact(src_etype, src_val, attr, fvalue,
                        source=source, collector=collector,
                        observed_at=when, confidence=conf, evidence_ref=ev_ref)
            # Ensure the destination entity file exists so later proposers can see it.
            try:
                kb.touch(dst_etype, dst_val, when)
            except Exception:  # noqa: BLE001
                pass
            accepted += 1
        except Exception:  # noqa: BLE001
            continue
    return accepted


__all__ = ["ingest_rows"]
