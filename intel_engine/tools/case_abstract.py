#!/usr/bin/env python3
"""case_abstract.py — the short summary of a case that recall shows before any detail.

Recall answers "have I seen this before?" with the case ids an artifact appears in; the analyst then
had to open each case to learn what it concluded. An abstract is that conclusion in ~50 tokens —
BLUF excerpt, attribution level, confidence, premise verdict, the cluster's domains and the
recorded operator — so a prior case can be judged relevant or not before its detail is expanded.

  cases/<id>/abstract.json
    {"case", "generated", "bluf", "attribution_level", "confidence", "premise_verdict",
     "n_domains", "domains", "operator", "source": {"path": "assessment.json", "sha256"}}

It summarises the case HEAD (`assessment.json`, whoever wrote it — loop, harness or analyst) and
never modifies it. `source.sha256` binds the abstract to the head it was built from: `load` rebuilds
a stale or missing one, so a reader never shows a summary of an assessment that has since changed.
A case with no assessment.json has no abstract (None). Tunables: tools/kb/references/kb_memory.json
`abstract`.

Usage:
  python3 tools/case_abstract.py CASE-0001            # print (rebuilding when stale)
  python3 tools/case_abstract.py CASE-0001 --json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
KB_TOOLS = os.path.join(HERE, "kb")
if KB_TOOLS not in sys.path:
    sys.path.insert(0, KB_TOOLS)

try:
    from kb_refs import load_ref, ref_path  # noqa: E402 — the shared RULE 3 loader
except Exception:  # noqa: BLE001 — degrade loudly, never block
    def ref_path(module_file, name):
        return os.path.join(os.path.dirname(os.path.abspath(module_file)), "kb", "references", name)

    def load_ref(path, fallback):
        print("[case_abstract] WARNING: kb_refs unavailable; kb_memory.json not read — running on "
              "the minimal embedded fallback.", file=sys.stderr)
        return dict(fallback)

_FALLBACK = {"abstract": {"bluf_chars": 200, "max_domains": 3}}
_REF = load_ref(os.path.join(KB_TOOLS, "references", "kb_memory.json"), _FALLBACK)
_CFG = _REF.get("abstract") or _FALLBACK["abstract"]
BLUF_CHARS = int(_CFG.get("bluf_chars") or _FALLBACK["abstract"]["bluf_chars"])
MAX_DOMAINS = int(_CFG.get("max_domains") or _FALLBACK["abstract"]["max_domains"])

HEAD, ABSTRACT = "assessment.json", "abstract.json"
_SENTENCE_END = re.compile(r"(?<=[.!?])\s+(?=[A-Z0-9\"'(\[])")


def case_dir(case: str) -> str:
    """A case id → cases/<id> under the engine root; a path is used as given."""
    return case if os.sep in case or os.path.isdir(case) else os.path.join(ROOT, "cases", case)


def _excerpt(bluf: str) -> str:
    s = " ".join(str(bluf or "").split())
    first = _SENTENCE_END.split(s, 1)[0]
    if len(first) > BLUF_CHARS:
        first = first[:BLUF_CHARS - 1].rsplit(" ", 1)[0] + "…"
    return first


def _domains(head: dict) -> list:
    seen = []
    for m in head.get("cluster") or []:
        d = (m.get("domain") if isinstance(m, dict) else str(m)) or ""
        d = d.strip().lower()
        if d and d not in seen:
            seen.append(d)
    return seen


def _operators(case_id: str) -> list:
    try:
        import operator_registry  # noqa: E402 — knowledge/operators.jsonl (the LEARN ledger)
        return sorted({r.get("operator") for r in operator_registry._load()
                       if r.get("case") == case_id and r.get("operator")})
    except Exception:  # noqa: BLE001 — a missing ledger is no recorded operator, never an error
        return []


def build(cdir: str) -> dict | None:
    """The abstract of the case at `cdir`, from its current head; None without a readable head."""
    hp = os.path.join(cdir, HEAD)
    try:
        with open(hp, "rb") as fh:
            raw = fh.read()
        head = json.loads(raw.decode("utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(head, dict):
        return None
    cid = os.path.basename(os.path.normpath(cdir))
    doms = _domains(head)
    ops = _operators(cid)
    return {"case": cid,
            "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "bluf": _excerpt(head.get("bluf")),
            "attribution_level": head.get("attribution_level") or "",
            "confidence": head.get("confidence") or "",
            "premise_verdict": head.get("premise_verdict") or "",
            "n_domains": len(doms), "domains": doms[:MAX_DOMAINS],
            "operator": ", ".join(ops),
            "source": {"path": HEAD, "sha256": hashlib.sha256(raw).hexdigest()}}


def refresh(cdir: str) -> dict | None:
    """(Re)write cdir/abstract.json from the current head. Call after any head write. Returns the
    abstract, or None (and removes a leftover abstract.json) when the case has no readable head."""
    a = build(cdir)
    ap = os.path.join(cdir, ABSTRACT)
    if a is None:
        if os.path.isfile(ap):
            os.remove(ap)
        return None
    tmp = ap + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(a, fh, indent=2, ensure_ascii=False)
    os.replace(tmp, ap)
    return a


def try_refresh(cdir: str) -> None:
    """refresh() for a head writer: an abstract is derived data and must never fail the write."""
    try:
        refresh(cdir)
    except Exception as exc:  # noqa: BLE001
        print(f"   abstract.json not refreshed ({type(exc).__name__}: {exc})", file=sys.stderr)


def load(cdir: str) -> dict | None:
    """The case abstract, rebuilt when missing or bound to a different head than the current one."""
    try:
        with open(os.path.join(cdir, ABSTRACT), encoding="utf-8") as fh:
            a = json.load(fh)
        with open(os.path.join(cdir, HEAD), "rb") as fh:
            current = hashlib.sha256(fh.read()).hexdigest()
        if (a.get("source") or {}).get("sha256") == current:
            return a
    except (OSError, ValueError, AttributeError):
        pass
    try:
        return refresh(cdir)
    except OSError:                     # read-only case dir: still answer, just don't persist
        return build(cdir)


def line(a: dict | None, case_id: str = "") -> str:
    """One recall line for a case — `CASE  [level · confidence · premise]  BLUF  (n domains: …)`."""
    if not a:
        return f"{case_id}  [no assessment yet]"
    tags = " · ".join(x for x in (a.get("attribution_level"), a.get("confidence"),
                                  a.get("premise_verdict") and f"premise {a['premise_verdict']}") if x)
    doms = a.get("domains") or []
    more = a.get("n_domains", len(doms)) - len(doms)
    dom_s = (f"  ({a.get('n_domains', len(doms))} domain(s): {', '.join(doms)}"
             + (f" +{more}" if more > 0 else "") + ")") if doms else ""
    op = f"  operator: {a['operator']}" if a.get("operator") else ""
    return f"{a.get('case') or case_id}  [{tags or 'unassessed'}]  {a.get('bluf') or ''}{dom_s}{op}"


def _main() -> None:
    ap = argparse.ArgumentParser(description="a case's short recall summary (abstract.json)")
    ap.add_argument("case", help="case id or cases/<id> path")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    a = load(case_dir(args.case))
    print(json.dumps(a, ensure_ascii=False, indent=2) if args.json
          else line(a, os.path.basename(os.path.normpath(args.case))))


if __name__ == "__main__":
    _main()
