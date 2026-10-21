#!/usr/bin/env python3
"""ghw_exposure — GrayHatWarfare results persisted into a case and ingested as KB FACTS.

The client is WebPivot/tools/wp_buckets.py (buckets + shortener corpus + git corpus). This module
owns the case side, shared by the pipeline auto-fire (intel.py open / loop --full), the dispatcher
op and the `grayhatwarfare` MCP tool:

  cases/<case>/grayhatwarfare/exposure.json   {case, updated, tier, apexes:{apex: wp_buckets.exposure()},
                                               lookups:{"<mode>|<selector>": result}}
  cases/<case>/grayhatwarfare/short_urls.json [{url, host, short, discovered}] — every historical long URL
                                               the case's lookups returned; url_paths(mode='patterns') input
  cases/<case>/grayhatwarfare/<sha>.json      wp_casememo: one API call per selector per case

KB writes go through ingest_typed.ingest_rows with wp_buckets.rows_for(): exposure / shortener hits
are `mention` facts, committers (git.committer_email) and verified code reuse (git.code) are kit
facts — none of them can become an edge, a cluster member or an operator lead.

CLI:
  ghw_exposure.py exposure <CASE> <apex> [<apex> …] [--kb DIR]
  ghw_exposure.py lookup <mode> <selector> [--case CASE] [--kb DIR] [--limit N] [--ext pdf,xlsx]
  ghw_exposure.py show <CASE>
Stdlib-only. Never raises out of run_apexes()/lookup().
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ENGINE = os.path.dirname(_HERE)
for _p in (_HERE, os.path.join(_HERE, "kb"), os.path.join(_ENGINE, "WebPivot", "tools")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import wp_buckets as GHW  # noqa: E402

DIRNAME = "grayhatwarfare"


def case_dir_for(case: str) -> str:
    return os.path.join(_ENGINE, "cases", str(case))


def _kb_root(kb_root=None) -> str:
    return kb_root or os.path.join(_ENGINE, os.environ.get("HARNESS_KB", "knowledge"))


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load(case_dir: str) -> dict:
    """The case's exposure document, or {} when GrayHatWarfare never ran for it."""
    try:
        with open(os.path.join(case_dir, DIRNAME, "exposure.json"), encoding="utf-8") as fh:
            doc = json.load(fh)
        return doc if isinstance(doc, dict) else {}
    except (OSError, ValueError):
        return {}


def _short_url_rows(doc: dict) -> list:
    seen, out = set(), []
    blocks = [(a or {}).get("short_urls") for a in (doc.get("apexes") or {}).values()]
    blocks += [r for r in (doc.get("lookups") or {}).values()
               if isinstance(r, dict) and r.get("mode") in ("short_urls", "short_handle")]
    for blk in blocks:
        for u in (blk or {}).get("urls") or []:
            if u.get("url") and u["url"] not in seen:
                seen.add(u["url"])
                out.append({"url": u["url"], "host": u.get("host"), "short": u.get("short"),
                             "discovered": u.get("discovered")})
    return out


def _save(case_dir: str, doc: dict) -> str:
    d = os.path.join(case_dir, DIRNAME)
    os.makedirs(d, exist_ok=True)
    doc["updated"] = _now()
    for name, body in (("exposure.json", doc), ("short_urls.json", _short_url_rows(doc))):
        p = os.path.join(d, name)
        with open(p + ".tmp", "w", encoding="utf-8") as fh:
            json.dump(body, fh, indent=2, ensure_ascii=False)
        os.replace(p + ".tmp", p)
    return os.path.join(d, "exposure.json")


def _origin(mode: str, selector: str, res: dict):
    """(origin_type, origin_value) the facts hang off — the selector the analyst asked about."""
    if mode in ("short_subdomains", "exposure"):
        return "domain", res.get("apex") or selector
    if mode == "short_urls":
        return "domain", (res.get("hosts") or [selector])[0]
    if mode == "short_handle":
        return ("phone" if res.get("kind") == "whatsapp" else "telegram"), selector
    if mode == "git_committers":
        return ("email" if res.get("by") == "email" else "domain"), res.get("selector") or selector
    if mode == "git_code":
        try:
            from selector_types import classify
            return classify(selector), selector
        except Exception:  # noqa: BLE001
            return "string", selector
    return "string", selector


def _ingest(case: str, mode: str, selector: str, res: dict, kb_root=None) -> int:
    rows = GHW.rows_for(res)
    if not rows:
        return 0
    try:
        import ingest_typed
        from knowledge_base import KB
        ot, ov = _origin(mode, selector, res)
        return ingest_typed.ingest_rows(KB(_kb_root(kb_root)), case, ot, ov, rows,
                                        route=f"grayhatwarfare.{mode}")
    except Exception as e:  # noqa: BLE001 — bookkeeping must never sink a collection
        print(f"   note: grayhatwarfare KB ingest failed ({type(e).__name__}: {e})", file=sys.stderr)
        return 0


def _count(blk, key):
    if not isinstance(blk, dict):
        return "—"
    if blk.get("error"):
        return "error"
    if blk.get("skipped"):
        return "skipped"
    return len(blk.get(key) or [])


def apex_summary(apex: str, blk: dict) -> dict:
    return {"apex": apex, "buckets": _count(blk.get("buckets"), "buckets"),
            "short_hosts": _count(blk.get("short_subdomains"), "subdomains"),
            "short_urls": _count(blk.get("short_urls"), "urls"),
            "committers": _count(blk.get("git_committers"), "committers")}


def run_apexes(case: str, apexes, *, case_dir=None, kb_root=None) -> dict:
    """Auto-fire: wp_buckets.exposure() once per apex per CASE (an apex already in exposure.json
    without an error is not re-queried), persisted and ingested. Returns {apex: summary}."""
    case_dir = case_dir or case_dir_for(case)
    out = {}
    if not GHW.ghw_configured():
        return out
    doc = load(case_dir)
    doc["case"] = case
    doc.setdefault("apexes", {})
    doc.setdefault("lookups", {})
    if not doc.get("tier"):
        acct = GHW.account() or {}
        doc["tier"], doc["expires"] = acct.get("tier") or "unknown", acct.get("expires")
    for apex in apexes:
        prev = doc["apexes"].get(apex)
        if isinstance(prev, dict) and not any(
                isinstance(prev.get(k), dict) and prev[k].get("error")
                for k in ("buckets", "short_subdomains", "short_urls", "git_committers")):
            continue
        try:
            with GHW.case_scope(case_dir):          # memo under THIS case, whatever WP_CASE_DIR says
                blk = GHW.exposure(apex)
        except Exception as e:  # noqa: BLE001
            print(f"   note: grayhatwarfare exposure failed for {apex} ({e}); skipped.", file=sys.stderr)
            continue
        doc["apexes"][apex] = blk
        for part in ("buckets", "short_subdomains", "short_urls", "git_committers"):
            res = blk.get(part)
            if isinstance(res, dict):
                _ingest(case, res.get("mode") or part, blk.get("apex") or apex, res, kb_root)
        out[apex] = apex_summary(apex, blk)
    if out:
        _save(case_dir, doc)
        # the per-apex `grayhatwarfare:<apex>` enrichment lead (case_state) is now accounted for
        try:
            import case_state
            for apex, s in out.items():
                found = any(isinstance(s.get(k), int) and s[k] for k in ("buckets", "short_hosts", "short_urls", "committers"))
                case_state.mark_enrichment_done(case, [f"grayhatwarfare:{apex}"], "ran" if found else "empty")
        except Exception as e:  # noqa: BLE001
            print(f"   note: could not close grayhatwarfare leads ({e})", file=sys.stderr)
    return out


def lookup(mode: str, selector: str, *, case: str = "", case_dir=None, kb_root=None,
           limit=None, ext=None, ingest: bool = True) -> dict:
    """One on-demand lookup. With `case` the result is persisted under lookups and (unless
    ingest=False — the corpus-route path, whose execute() ingests) ingested as KB facts."""
    mode = str(mode or "").replace("-", "_")
    if mode == "account":
        return GHW.account() or {"skipped": "no GRAYHATWARFARE_API_KEY configured"}
    if case:
        case_dir = case_dir or case_dir_for(case)
    with GHW.case_scope(case_dir if case else None):   # explicit per call; restored on exit
        res = GHW.lookup(mode, selector, limit=limit, ext=ext)
    if case and isinstance(res, dict) and not res.get("error") and not (
            res.get("skipped") and res.get("dork")):
        doc = load(case_dir)
        doc["case"] = case
        doc.setdefault("apexes", {})
        doc.setdefault("lookups", {})[f"{mode}|{selector}"] = res
        res["persisted"] = _save(case_dir, doc)
        if ingest:
            res["ingested"] = _ingest(case, mode, selector, res, kb_root)
    return res


def _main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="GrayHatWarfare results -> case files + KB facts")
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("exposure", help="per-apex auto-fire for a case")
    e.add_argument("case")
    e.add_argument("apexes", nargs="+")
    e.add_argument("--kb", default=None)
    lk = sub.add_parser("lookup", help="one on-demand lookup (persisted when --case is given)")
    lk.add_argument("mode", choices=["account", *[m.replace("_", "-") for m in GHW.LOOKUPS], *GHW.LOOKUPS])
    lk.add_argument("selector", nargs="?", default="")
    lk.add_argument("--case", default="")
    lk.add_argument("--kb", default=None)
    lk.add_argument("--limit", type=int, default=None)
    lk.add_argument("--ext", default=None)
    s = sub.add_parser("show", help="print a case's exposure document")
    s.add_argument("case")
    a = ap.parse_args(argv)
    if a.cmd == "exposure":
        if not GHW.ghw_configured():
            print(json.dumps({"skipped": "no GRAYHATWARFARE_API_KEY configured",
                              "dorks": [GHW.dork(x, "buckets") for x in a.apexes]}, indent=2))
            return 0
        res = run_apexes(a.case, [GHW._registrable(GHW._host(x)) or GHW._host(x) for x in a.apexes],
                         kb_root=a.kb)
        doc = load(case_dir_for(a.case))
        print(json.dumps({"tier": doc.get("tier"), "ran": res,
                          "cached": sorted(set((doc.get("apexes") or {})) - set(res)),
                          "file": os.path.join(case_dir_for(a.case), DIRNAME, "exposure.json")},
                         indent=2, ensure_ascii=False))
        return 0
    if a.cmd == "show":
        print(json.dumps(load(case_dir_for(a.case)), indent=2, ensure_ascii=False))
        return 0
    res = lookup(a.mode, a.selector, case=a.case, kb_root=a.kb, limit=a.limit, ext=a.ext)
    print(json.dumps(res, indent=2, ensure_ascii=False))
    return 1 if isinstance(res, dict) and res.get("error") else 0


__all__ = ["load", "run_apexes", "lookup", "apex_summary", "case_dir_for", "DIRNAME"]


if __name__ == "__main__":
    sys.exit(_main())
