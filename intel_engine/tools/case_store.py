#!/usr/bin/env python3
"""case_store.py — plain-Python case store: assessment VERSIONING + evidence MANIFEST, no SDK.

The harness has two front-ends over the same tools/KB:
  - harness/orchestrator.py  — Agent-SDK driver (pay-per-token, headless, schema-forced)
  - the IntelHarness skill    — Claude Code drives the same pipeline (subscription, agent-in-loop)

This module is the shared, SDK-free persistence both use, so a case worked either way gets the
SAME append-only assessment history and the SAME evidence index. Depends only on the stdlib.

  # after writing an assessment JSON (schema: bluf, cluster[{domain,shared_artifacts[]}],
  # attribution_level, confidence, evidence[], gaps[], next_pivots[]):
  python3 tools/case_store.py snapshot CASE-0001 --assessment /tmp/assessment.json --table table.md

  # (re)build the evidence manifest from everything collected into the case:
  python3 tools/case_store.py manifest CASE-0001
"""
from __future__ import annotations

import argparse
import datetime
import glob
import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _stamp() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _case_dir(case: str) -> str:
    return case if os.path.isabs(case) else os.path.join(ROOT, "cases", case)


def _render_md(a: dict, table_md: str = "") -> str:
    """Render an assessment dict to the same shape as the SDK harness's markdown."""
    out = [f"# Assessment", ""]
    if table_md:
        out += [table_md, ""]
    out += [f"**BLUF.** {a.get('bluf', '').strip()}", "",
            f"**Attribution:** `{a.get('attribution_level', '?')}`  ·  "
            f"**Confidence:** `{a.get('confidence', '?')}`", ""]
    cluster = a.get("cluster") or []
    if cluster:
        out.append("## Cluster")
        for m in cluster:
            arts = m.get("shared_artifacts") or []
            out.append(f"- **{m.get('domain', '?')}**" + (f" — {'; '.join(arts)}" if arts else ""))
        out.append("")
    for title, key in (("Evidence", "evidence"), ("Gaps / competing explanation", "gaps"),
                       ("Next pivots", "next_pivots")):
        items = a.get(key) or []
        if items:
            out.append(f"## {title}")
            out += [f"- {x}" for x in items]
            out.append("")
    return "\n".join(out)


def snapshot(case: str, assessment_path: str, table_md: str = "") -> dict:
    """Write an immutable, timestamped assessment snapshot (append-only history), refresh SUMMARY.md
    (living head) + assessment.json (back-compat head), and append one CHANGELOG.md line."""
    a = json.load(open(assessment_path, encoding="utf-8"))
    case_dir = _case_dir(case)
    snap_dir = os.path.join(case_dir, "assessments")
    os.makedirs(snap_dir, exist_ok=True)
    stamp = _stamp()
    rnd = len([f for f in os.listdir(snap_dir) if f.endswith(".json")]) + 1
    base = f"{stamp}_r{rnd}"
    md_body = _render_md(a, table_md)
    js = json.dumps(a, ensure_ascii=False, indent=2)

    with open(os.path.join(snap_dir, base + ".md"), "w", encoding="utf-8") as f:
        f.write(md_body)
    with open(os.path.join(snap_dir, base + ".json"), "w", encoding="utf-8") as f:
        f.write(js)
    with open(os.path.join(case_dir, "SUMMARY.md"), "w", encoding="utf-8") as f:
        f.write(f"<!-- round {rnd} · {stamp} · {a.get('attribution_level','?')}/"
                f"{a.get('confidence','?')} · snapshot assessments/{base}.md -->\n\n" + md_body)
    with open(os.path.join(case_dir, "assessment.json"), "w", encoding="utf-8") as f:
        f.write(js)
    bluf = (a.get("bluf") or "").replace("\n", " ")[:140]
    with open(os.path.join(case_dir, "CHANGELOG.md"), "a", encoding="utf-8") as f:
        f.write(f"- {stamp} · r{rnd} · {a.get('attribution_level','?')}/{a.get('confidence','?')} · "
                f"{len(a.get('cluster') or [])} in cluster · {bluf}\n")
    return {"round": rnd, "snapshot": os.path.join(snap_dir, base + ".md")}


def manifest(case: str) -> int:
    """(Re)build cases/<case>/evidence/manifest.jsonl from every raw pivot JSON in the case — the
    provenance index: WHERE (source + enrichment services), WHEN (collected_at), WHAT WAS ARCHIVED
    (saved DOM / screenshot / Wayback flag). Idempotent: rewrites the file from current state."""
    case_dir = _case_dir(case)
    raw_dir = os.path.join(case_dir, "raw")
    ev_dir = os.path.join(case_dir, "evidence")
    os.makedirs(ev_dir, exist_ok=True)
    rows = []
    for path in sorted(glob.glob(os.path.join(raw_dir, "*.json"))):
        try:
            data = json.load(open(path, encoding="utf-8"))
        except Exception:  # noqa: BLE001
            continue
        meta = data.get("meta") or {}
        host = meta.get("host") or os.path.basename(path)[:-5]
        dom = os.path.join(case_dir, "dom", host + ".html")
        shot = os.path.join(case_dir, "screenshots", host + ".png")
        rows.append({
            "case": os.path.basename(case_dir.rstrip("/")), "host": host,
            "collected_at": meta.get("collected_at"), "logged_at": _now(),
            "source_url": meta.get("source"), "final_url": meta.get("final_url"),
            "fetched_with": meta.get("fetched_with"), "enriched_with": meta.get("enriched_with"),
            "archived_via_wayback": meta.get("archived_via_wayback"),
            "n_pivots": len(data.get("pivots", [])),
            "dom_path": os.path.relpath(dom, ROOT) if os.path.exists(dom) else None,
            "screenshot_path": os.path.relpath(shot, ROOT) if os.path.exists(shot) else None,
            "ledger": os.path.join("cases", os.path.basename(case_dir.rstrip("/")),
                                   "evidence", "master_pivots.csv"),
        })
    with open(os.path.join(ev_dir, "manifest.jsonl"), "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    return len(rows)


def _main() -> None:
    ap = argparse.ArgumentParser(description="plain-Python case store (versioning + manifest)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("snapshot", help="write a versioned assessment snapshot + SUMMARY + CHANGELOG")
    s.add_argument("case")
    s.add_argument("--assessment", required=True, help="path to the assessment JSON")
    s.add_argument("--table", default="", help="path to a Domain Summary markdown table (optional)")
    m = sub.add_parser("manifest", help="(re)build the evidence manifest from the case's raw JSON")
    m.add_argument("case")
    a = ap.parse_args()
    if a.cmd == "snapshot":
        table_md = open(a.table, encoding="utf-8").read() if a.table and os.path.exists(a.table) else ""
        r = snapshot(a.case, a.assessment, table_md)
        print(f"snapshot round {r['round']} → {os.path.relpath(r['snapshot'], ROOT)}")
    elif a.cmd == "manifest":
        n = manifest(a.case)
        print(f"evidence manifest: {n} row(s) → cases/{a.case}/evidence/manifest.jsonl")


if __name__ == "__main__":
    _main()
