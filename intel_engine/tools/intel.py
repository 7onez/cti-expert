#!/usr/bin/env python3
"""
intel.py — one deterministic command that turns a domain list into a persisted case.

Orchestrates the existing tools (it reimplements nothing) so a case is produced the SAME
way every time and always lands on disk:

    python3 tools/intel.py open <case> domains.txt

    cases/<case>/raw/<host>.json     one pivot_extract JSON per host (overwrites on re-run)
    knowledge/                        ingested (idempotent) so IntelAnalysis can reason
    cases/<case>/shared.txt           the --shared cluster seeds, saved not just printed
    cases/<case>/case_graph.json      + network.html   (unless --no-graph)

Runs from anywhere: all tool paths are resolved from this file's location, not the CWD.
Zero third-party dependencies — stdlib + the repo's own tools.

Subcommands:
    open <case> <domains-file>   full pipeline (extract -> ingest -> shared [-> graph])
    status <case>                audit an existing case: which hosts have raw JSON / are in KB

Common flags for `open`:
    --jobs N            parallel extractions (default 4; archive.org rate-limits above ~4)
    --whois-reverse     run reverse-WHOIS live during extraction (costs WhoisXML credits)
    --render            also build + render the interactive network graph
    --no-graph          skip the graph build entirely (default: build case_graph.json)
    --operator NAME     operator persona node for the graph
    --operator-links a.com,b.com   domains tied to that operator
    --min N             --shared threshold (default 2)
    --timeout S         per-fetch timeout (default 20)
"""
import argparse
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)                              # for the sibling collect_core module
import collect_core                                   # noqa: E402  shared host-collection routine
ROOT = os.path.dirname(HERE)                          # intel_engine project root
WP = os.path.join(ROOT, "WebPivot", "tools")
KB_TOOLS = os.path.join(ROOT, "tools", "kb")
KB = os.path.join(ROOT, "knowledge")

# Primary collector: cti-expert's monolithic scripts/webpivot/pivot_extract.py (richer — Wayback-
# raw recovery, shared-host classification, WHOIS-reverse-by-default + registrant-phone, deeper
# enrichment) when present; else the vendored WebPivot copy. Override with $PIVOT_EXTRACT.
# scripts/webpivot lives at the cti-expert repo root (one level ABOVE this vendored engine subtree)
_CTI_PIVOT = os.path.join(os.path.dirname(ROOT), "scripts", "webpivot", "pivot_extract.py")
_ENGINE_PIVOT = os.path.join(WP, "pivot_extract.py")
PIVOT_EXTRACT = (os.environ.get("PIVOT_EXTRACT")
                 or (_CTI_PIVOT if os.path.isfile(_CTI_PIVOT) else _ENGINE_PIVOT))
PIVOT_IS_CTI = os.path.realpath(PIVOT_EXTRACT) == os.path.realpath(_CTI_PIVOT)
# confirmed-operator registry (git-ignored, lives under knowledge/). The LEARN step of an
# investigation appends to it; `open` reads it so a new case inherits prior attributions.
OPERATORS = os.path.join(KB, "operators.jsonl")

# IntelGraph scripts: repo copy first, then the installed skill symlink
_GRAPH_CANDIDATES = [
    os.path.join(ROOT, "IntelGraph", "scripts"),
    os.path.expanduser("~/.claude/skills/IntelGraph/scripts"),
]
GRAPH = next((p for p in _GRAPH_CANDIDATES if os.path.isdir(p)), _GRAPH_CANDIDATES[0])


def _host(raw):
    """Bare hostname for a domain/URL line: no scheme, no path, no trailing dot."""
    s = raw.strip()
    s = re.sub(r"^\w+://", "", s)
    s = s.split("/", 1)[0].split("?", 1)[0].strip().rstrip(".")
    return s.lower()


def _load_env():
    """Load .env into os.environ so child tools see the API keys (a real exported env var wins).
    ONE key store for the unified skill: the cti-expert skill-root .env (managed by /apikeys) is
    read FIRST, then `intel_engine`'s own intel_engine/.env if present. So keys set via
    `/apikeys set <svc> <KEY>` reach the engine pipeline too."""
    for p in (os.path.join(os.path.dirname(ROOT), ".env"),  # cti-expert/.env — /apikeys store
              os.path.join(ROOT, ".env")):                   # intel_engine/.env — optional engine-local
        if not os.path.isfile(p):
            continue
        for line in open(p, encoding="utf-8"):
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k, v = k.strip(), v.strip().strip('"').strip("'")
            os.environ.setdefault(k, v)   # first file / real exported key wins


def _read_domains(path):
    if not os.path.isfile(path):
        sys.exit(f"domains file not found: {path}")
    seen, out = set(), []
    for line in open(path, encoding="utf-8"):
        h = _host(line.replace("\r", ""))
        if h and not h.startswith("#") and h not in seen:
            seen.add(h)
            out.append(h)
    return out


def _run(cmd, **kw):
    return subprocess.run(cmd, **kw)


def _load_operators():
    """Read the confirmed-operator registry (git-ignored). Returns domain -> [operator,…]."""
    import json
    dom2op = {}
    if not os.path.isfile(OPERATORS):
        return dom2op
    for line in open(OPERATORS, encoding="utf-8"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            rec = json.loads(line)
        except Exception:
            continue
        op = rec.get("operator") or rec.get("name")
        for d in rec.get("domains", []):
            if op:
                dom2op.setdefault(_host(d), []).append(op)
    return dom2op


def _prior_overlap(hosts, min_shared=1):
    """LEARN-FROM-THE-PAST: after ingest, surface which of this case's seeds already
    connect — through a shared indicator in the KB — to domains from PRIOR work, and to
    any confirmed operator in the registry. This is the auto-correlation payoff made visible
    (it was previously latent in shared.txt). Zero web I/O — pure KB read.
    """
    sys.path.insert(0, KB_TOOLS)
    try:
        from knowledge_base import KB as _KB  # noqa: E402
    except Exception as e:
        print(f"   note: prior-overlap check skipped ({e})")
        return
    kb = _KB(KB)
    seeds = {h.lower() for h in hosts}
    edges = kb.edges()
    # indicator (type,value) -> set(domains that use it)
    ind_domains = {}
    for e in edges:
        if e["src_type"] == "domain" and e["dst_type"] in ("indicator", "email", "person", "org"):
            ind_domains.setdefault((e["dst_type"], e["dst"]), set()).add(e["src"].lower())
    # for each seed, the prior (non-seed) domains it shares an indicator with, and via what
    prior_peers = {}     # peer_domain -> set("kind:value")
    for (dt, dv), doms in ind_domains.items():
        if not (seeds & doms):
            continue
        for peer in doms - seeds:
            prior_peers.setdefault(peer, set()).add(dv if ":" in str(dv) else f"{dt}:{dv}")

    dom2op = _load_operators()
    hit_ops = {}
    for peer in prior_peers:
        for op in dom2op.get(peer, []):
            hit_ops.setdefault(op, set()).add(peer)

    print("\n== prior-knowledge overlap (does this case connect to what we already know?) ==")
    if not prior_peers:
        print("   none — these seeds share no KB indicator with any previously-seen domain (new cluster).")
        return
    if hit_ops:
        print("   ⚠ CONFIRMED-OPERATOR MATCH:")
        for op, doms in sorted(hit_ops.items(), key=lambda x: -len(x[1])):
            print(f"      • {op}  (via {len(doms)} known domain(s): {', '.join(sorted(doms)[:5])}"
                  + (" …" if len(doms) > 5 else "") + ")")
    strong = [(p, v) for p, v in prior_peers.items() if len(v) >= min_shared]
    print(f"   {len(strong)} prior domain(s) share an indicator with this case's seeds:")
    for peer, via in sorted(strong, key=lambda x: -len(x[1]))[:15]:
        tag = f"  [{', '.join(dom2op[peer])}]" if peer in dom2op else ""
        print(f"      {peer}{tag}  via {len(via)}: {', '.join(sorted(via)[:4])}"
              + (" …" if len(via) > 4 else ""))
    if len(strong) > 15:
        print(f"      … and {len(strong) - 15} more (see shared.txt for the full cluster).")


def _extract_ok(res):
    """A collection result counts as a hit only if the collector produced a file AND extraction
    yielded a host (no file / no host = rate-limit or dead site)."""
    return bool(res.get("ok") and ((res.get("data") or {}).get("meta") or {}).get("host"))


def _risk_signals(raw_files):
    """Score each freshly-collected host for NRD / BPH / money-trail. Pure local read."""
    sys.path.insert(0, KB_TOOLS)
    try:
        import json as _json
        import risk_signals as _rs  # noqa: E402
    except Exception as e:
        print(f"   note: risk-signals check skipped ({e})")
        return
    print("\n== scam red-flags (newly-registered / bulletproof-hosting / money-trail) ==")
    esc = []
    for rf in sorted(raw_files):
        try:
            s = _rs.score_domain(_json.load(open(rf, encoding="utf-8")))
        except Exception:
            continue
        print(_rs._fmt(s))
        if s.get("escalate"):
            esc.append(s)
    if esc:
        print("   ⚠ escalate: " +
              "; ".join(f"{s['host']}[{','.join(s['escalate'])}]" for s in esc[:10]))


def cmd_open(a):
    _load_env()
    case_dir = os.path.join(ROOT, "cases", a.case)
    os.makedirs(os.path.join(case_dir, "raw"), exist_ok=True)
    hosts = _read_domains(a.domains)
    if not hosts:
        sys.exit("no domains to process")

    print(f"== intel: case '{a.case}' — {len(hosts)} host(s), jobs={a.jobs} ==")
    print(f"   collector: {'cti-expert' if PIVOT_IS_CTI else 'vendored WebPivot'} "
          f"({os.path.relpath(PIVOT_EXTRACT, ROOT)})")
    if not os.environ.get("WHOISXML_API_KEY"):
        print("   note: WHOISXML_API_KEY not set — WHOIS registrant spine will be empty.")

    # 1) extract (parallel, via the shared collector core) -------------------
    ok, failed = [], []
    extra = []
    if a.whois_reverse:
        extra.append("--whois-reverse")
    if a.fofa_full and not PIVOT_IS_CTI:
        extra.append("--fofa-full")   # engine-only flag; cti-expert's collector doesn't take it
    if a.render_extract:
        extra.append("--render")      # post-JS DOM — unlocks SaaS/analytics tokens

    def _status(res):
        good = _extract_ok(res)
        note = (res.get("note") or "").strip() or ("ok" if good else res.get("error") or "miss")
        print(f"   [{'ok ' if good else 'MISS'}] {res['host']}  {note}")
        (ok if good else failed).append(res["host"])

    collect_core.collect_many(
        [f"https://{h}" for h in hosts], a.case,
        max_workers=max(1, a.jobs), on_result=_status, retry_misses=1,
        root=ROOT, py=sys.executable, collector=PIVOT_EXTRACT,
        timeout=a.timeout, force=a.force, no_archive=(not a.archive), extra_flags=extra)

    raw_glob = os.path.join(case_dir, "raw")
    raw_files = [os.path.join(raw_glob, f) for f in os.listdir(raw_glob) if f.endswith(".json")]
    if not raw_files:
        sys.exit("no raw JSON produced — nothing to ingest.")

    # 2) ingest into the KB (idempotent) ------------------------------------
    print(f"== ingesting {len(raw_files)} raw file(s) into {os.path.relpath(KB, ROOT)} ==")
    _run([sys.executable, os.path.join(KB_TOOLS, "ingest_webpivot.py"),
          "--kb", KB, *raw_files])

    # 2.5) prior-knowledge overlap — surface cross-case learning, not just latent in shared.txt
    _prior_overlap(hosts)

    # 2.6) scam red-flag signals — NRD / bulletproof-hosting / money-trail per seed
    _risk_signals(raw_files)

    # 3) shared cluster seeds — saved to the case, not just printed ----------
    shared_path = os.path.join(case_dir, "shared.txt")
    print(f"== cluster seeds (--shared --min {a.min}) -> {os.path.relpath(shared_path, ROOT)} ==")
    r = _run([sys.executable, os.path.join(KB_TOOLS, "query.py"),
              "--kb", KB, "--shared", "--min", str(a.min)],
             capture_output=True, text=True)
    sys.stdout.write(r.stdout)
    with open(shared_path, "w", encoding="utf-8") as fh:
        fh.write(r.stdout)

    # 4) graph (default on; --no-graph to skip) -----------------------------
    graph_json = os.path.join(case_dir, "case_graph.json")
    if not a.no_graph:
        print(f"== building case graph -> {os.path.relpath(graph_json, ROOT)} ==")
        gcmd = [sys.executable, os.path.join(WP, "graph_build.py"), *raw_files, "-o", graph_json]
        if a.operator:
            gcmd += ["--operator", a.operator]
        if a.operator_links:
            gcmd += ["--operator-links", a.operator_links]
        _run(gcmd)
        if a.render:
            net_html = os.path.join(case_dir, "network.html")
            rn = os.path.join(GRAPH, "render_network.py")
            if os.path.isfile(rn):
                print(f"== rendering -> {os.path.relpath(net_html, ROOT)} ==")
                _run([sys.executable, rn, graph_json, net_html,
                      "--title", f"Case: {a.case}"])
            else:
                print(f"   note: render_network.py not found at {rn}; skipped --render.")

    # 5) cluster intelligence assessment (ICD-203) -> cases/<case>/assessment.md
    if not a.no_report:
        assess_path = os.path.join(case_dir, "assessment.md")
        print(f"== rendering ICD-203 cluster assessment -> {os.path.relpath(assess_path, ROOT)} ==")
        try:
            sys.path.insert(0, WP)
            import evidence_report
            import json as _json
            results = []
            for rf in raw_files:
                try:
                    results.append(_json.load(open(rf, encoding="utf-8")))
                except Exception:
                    pass
            md = evidence_report.render_cluster_report(
                results, case=a.case, analyst=a.analyst,
                classification=a.classification)
            with open(assess_path, "w", encoding="utf-8") as fh:
                fh.write(md)
        except Exception as e:
            print(f"   note: assessment render failed ({e}); skipped.")

    # 6) completeness summary (stable output is auditable) ------------------
    print("\n== summary ==")
    print(f"   extracted: {len(ok)}/{len(hosts)}   raw files: {len(raw_files)}")
    if failed:
        print(f"   MISSES ({len(failed)}) — re-run these: {', '.join(failed)}")
    print(f"   case dir : {os.path.relpath(case_dir, ROOT)}/  (raw/, shared.txt"
          + ("" if a.no_graph else ", case_graph.json")
          + (", network.html" if a.render and not a.no_graph else "") + ")")
    print(f"   next     : IntelAnalysis over knowledge/ -> knowledge/reports/{a.case}/assessment.md")


def cmd_status(a):
    case_dir = os.path.join(ROOT, "cases", a.case)
    raw_dir = os.path.join(case_dir, "raw")
    if not os.path.isdir(raw_dir):
        sys.exit(f"no such case: {os.path.relpath(case_dir, ROOT)}")
    raw = sorted(f[:-5] for f in os.listdir(raw_dir) if f.endswith(".json"))
    print(f"case '{a.case}': {len(raw)} raw host file(s)")
    for h in raw:
        print(f"   raw  {h}")
    for extra in ("shared.txt", "case_graph.json", "network.html"):
        mark = "yes" if os.path.isfile(os.path.join(case_dir, extra)) else "MISSING"
        print(f"   {extra:16} {mark}")


def main():
    ap = argparse.ArgumentParser(description="Deterministic OSINT case pipeline over the repo tools.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    o = sub.add_parser("open", help="run the full extract->ingest->shared[->graph] pipeline")
    o.add_argument("case")
    o.add_argument("domains", help="file with one domain/URL per line")
    o.add_argument("--jobs", type=int, default=4)
    o.add_argument("--whois-reverse", action="store_true")
    o.add_argument("--fofa-full", action="store_true",
                   help="FOFA reverses over ALL historical data (full=true), not just ~1yr")
    o.add_argument("--render-extract", action="store_true",
                   help="render post-JS DOM per page (unlocks SaaS/analytics tokens; needs playwright)")
    o.add_argument("--render", action="store_true")
    o.add_argument("--no-graph", action="store_true")
    o.add_argument("--operator", default=None)
    o.add_argument("--operator-links", default=None)
    o.add_argument("--min", type=int, default=2)
    o.add_argument("--timeout", type=int, default=20)
    o.add_argument("--force", action="store_true",
                   help="re-collect even if this host was already investigated in another case "
                        "(default: reuse the cached pivot — inherited from the shared collector core)")
    o.add_argument("--archive", action="store_true",
                   help="capture evidence while collecting (Wayback SPN snapshot + master ledger + "
                        "manifest). Off by default to keep the pipeline's cost profile; the MCP "
                        "harness archives by default")
    o.add_argument("--no-report", action="store_true",
                   help="skip the ICD-203 cluster assessment (default: write assessment.md)")
    o.add_argument("--analyst", default=None, help="analyst handle stamped on the assessment")
    o.add_argument("--classification", default="UNCLASSIFIED//FOR OFFICIAL USE ONLY",
                   help="classification banner for the assessment")
    o.set_defaults(func=cmd_open)

    s = sub.add_parser("status", help="audit an existing case's persisted outputs")
    s.add_argument("case")
    s.set_defaults(func=cmd_status)

    a = ap.parse_args()
    a.func(a)


if __name__ == "__main__":
    main()
