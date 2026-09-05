#!/usr/bin/env python3
"""
intel.py — one deterministic command that turns a domain list into a persisted case.

Orchestrates the existing tools (it reimplements nothing) so a case is produced the SAME
way every time and always lands on disk:

    python3 tools/intel.py open <case> domains.txt

    cases/<case>/raw/<host>.json     one pivot_extract JSON per host (overwrites on re-run)
    knowledge/                        ingested (idempotent) so IntelAnalysis can reason
    cases/<case>/shared.txt           the --shared cluster seeds, SCOPED to this case's hosts
    cases/<case>/clusters.json        same-operator components + the indicators binding each —
                                      judgment runs per CLUSTER, not per case
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
import glob
import json
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


# No pipeline sub-step may hang the whole run: each is bounded, and a timeout degrades to a logged
# rc-124 skip. The DEFAULT bound is the shared per-call ceiling (collect_core.CALL_TIMEOUT = 1800s /
# 30 min, env CTI_CALL_TIMEOUT) instead of the old 600, so a step that makes no explicit request gets
# the ceiling. INTEL_STEP_TIMEOUT overrides the default to ANY value, and a caller may still pass an
# explicit per-step timeout (e.g. a fast bound in a test) — both are honoured.
_STEP_TIMEOUT = int(os.environ.get("INTEL_STEP_TIMEOUT") or collect_core.CALL_TIMEOUT)


def _run(cmd, **kw):
    """Run a pipeline sub-step, bounded so no single step can hang or crash the whole run. A
    timeout or a failure to start degrades to a logged non-zero result (rc 124) instead of
    stalling/aborting: callers that read .returncode skip the step, .stdout callers get ''; the
    pipeline continues to the next step with whatever completed."""
    kw.setdefault("timeout", _STEP_TIMEOUT)
    try:
        return subprocess.run(cmd, **kw)
    except subprocess.TimeoutExpired:
        label = os.path.basename(cmd[1] if cmd[:1] == [sys.executable] and len(cmd) > 1 else cmd[0])
        print(f"   note: step '{label}' exceeded {kw['timeout']}s — skipped; pipeline continues.",
              file=sys.stderr)
    except (FileNotFoundError, OSError) as e:
        print(f"   note: step could not start ({e}) — skipped; pipeline continues.", file=sys.stderr)
    return subprocess.CompletedProcess(cmd, 124, stdout="", stderr="")


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
    # The curated reference's BENIGN verdicts (platform defaults, mass-market themes, archive
    # artifacts) are the same denylist clustering honours — an overlap that rests only on them
    # is a base-rate coincidence, and printing it as a CONFIRMED-OPERATOR MATCH names an innocent.
    try:
        from reference import benign_values as _benign_values  # noqa: E402
        benign = _benign_values(KB)
    except Exception:
        benign = set()
    seeds = {h.lower() for h in hosts}
    edges = kb.edges()
    # indicator (type,value) -> set(domains that use it)
    ind_domains = {}
    for e in edges:
        if e["src_type"] == "domain" and e["dst_type"] in ("indicator", "email", "person", "org"):
            if str(e["dst"]) in benign:
                continue
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
    _export_run_env(case_dir)
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
    # The ADVERTISING layer is opt-in per RUN, not per host, because it is the one layer here that
    # spends a SerpApi search on every host it touches: on by default it would quietly multiply a
    # batch's cost by the host count. Without it the pipeline could never reach the Ads Transparency
    # archive at all. The cloaking probe inside wp_serp stays free and automatic.
    if getattr(a, "serp", False):
        extra.append("--serp")
        if getattr(a, "serp_region", None):
            extra += ["--serp-region", str(a.serp_region)]
    # Passive SSL is FREE (same CIRCL account as passive DNS) and therefore ON by default — only an
    # explicit opt-out is passed through.
    if getattr(a, "no_pssl", False):
        extra.append("--no-pssl")
    # --free-only (explicit, or a no_spend scope): forward to the collector so its metered layers
    # gate off — subenum reads it via cmd_open too.
    if getattr(a, "free_only", False) or _case_no_spend(case_dir):
        extra.append("--free-only")
    # IntelX auto-fire (SKILL.md declares it required; the pipeline never appended the flag). METERED,
    # so it fires only when a key is present AND the case is not a no-spend / free-only posture. The
    # loop is free-only by default and appends it only under --full (see cmd_loop).
    if not getattr(a, "free_only", False):
        extra += _intelx_flag(case_dir, loop=False)
    # collect_core.filter_args probes the collector's --help and drops whatever it does not accept,
    # surfacing every dropped flag (RULE 4) — so a flag the cti-expert collector lacks degrades
    # loudly instead of aborting the batch.

    def _status(res):
        good = _extract_ok(res)
        note = (res.get("note") or "").strip() or ("ok" if good else res.get("error") or "miss")
        print(f"   [{'ok ' if good else 'MISS'}] {res['host']}  {note}")
        (ok if good else failed).append(res["host"])

    if getattr(a, "no_collect", False):
        # Handoff mode: a collector (e.g. cti-expert's /case) has already fetched every host and
        # written cases/<case>/raw/<host>.json. Everything below operates purely on those raw files,
        # so we skip the live fetch entirely — a COMPLETE persisted case with ZERO extra egress.
        print("   --no-collect: reusing pivot JSONs already in "
              f"{os.path.relpath(os.path.join(case_dir, 'raw'), ROOT)}/ (zero egress)")
        ok = [h for h in hosts if os.path.isfile(os.path.join(case_dir, "raw", h + ".json"))]
    else:
        collect_core.collect_many(
            [f"https://{h}" for h in hosts], a.case,
            max_workers=max(1, a.jobs), on_result=_status, retry_misses=1,
            root=ROOT, py=sys.executable, collector=PIVOT_EXTRACT,
            timeout=a.timeout, force=a.force, no_archive=(not a.archive),
            want_shot=getattr(a, "screenshots", False), extra_flags=extra)

    raw_glob = os.path.join(case_dir, "raw")
    raw_files = [os.path.join(raw_glob, f) for f in os.listdir(raw_glob) if f.endswith(".json")]
    if not raw_files:
        sys.exit("no raw JSON produced — nothing to ingest.")

    # 1b) Censys cert search — ONCE per case over the estate's leaf-cert SHA-256s (bounded budget).
    #     Run-unless-`free` (the search is the probe). NEVER under --no-collect (documented zero-egress:
    #     the /case hand-off and case-restore flows rely on it) and never on a no-spend posture.
    if not getattr(a, "no_collect", False) and not _case_no_spend(case_dir) and not getattr(a, "free_only", False):
        _censys_certs_once(case_dir, raw_files)

    # 1c) subdomain enumeration — ONCE per apex per case via the installed passive tools
    #     (subfinder / amass / assetfinder / findomain, subfinder keyed from the skill-owned config).
    #     never under --no-collect; keyless-only under a no-spend scope or --free-only.
    if not getattr(a, "no_collect", False):
        _subenum_once(case_dir, hosts, free_only=getattr(a, "free_only", False), jobs=max(1, a.jobs))

    # 1d) EXPANSION ANCHOR: the analyst's seeds are hop 0 in state.json, so a later `loop` knows which
    #     hosts are the operator's own registrations and which were reached over owner-link hops.
    try:
        sys.path.insert(0, HERE)
        import case_state as _cs
        _st = _cs.load_state(a.case)
        for h in hosts:
            _st.setdefault("hops", {}).setdefault(_host(h).lower(), 0)
        _cs.save_state(a.case, _st)
    except Exception as e:  # noqa: BLE001 — bookkeeping must never fail the pipeline
        print(f"   note: could not record seed hops in state.json ({e})")

    # 2) ingest into the KB (idempotent) ------------------------------------
    print(f"== ingesting {len(raw_files)} raw file(s) into {os.path.relpath(KB, ROOT)} ==")
    _run([sys.executable, os.path.join(KB_TOOLS, "ingest_webpivot.py"),
          "--kb", KB, *raw_files])

    # 2.5) prior-knowledge overlap — surface cross-case learning, not just latent in shared.txt
    _prior_overlap(hosts)

    # 2.6) scam red-flag signals — NRD / bulletproof-hosting / money-trail per seed
    _risk_signals(raw_files)

    # 3) shared cluster seeds — saved to the case, not just printed ----------
    #    SCOPED to this case's hosts (--domains): unscoped, this reported every past case's
    #    indicators too, which is noise once the KB holds more than one investigation.
    shared_path = os.path.join(case_dir, "shared.txt")
    case_hosts = _case_hosts(case_dir)
    print(f"== cluster seeds (--shared --min {a.min}, scoped to {len(case_hosts)} case host(s)) "
          f"-> {os.path.relpath(shared_path, ROOT)} ==")
    _write_shared(case_dir, a.min, case_hosts)
    sys.stdout.write(open(shared_path, encoding="utf-8").read())

    # 3b) same-operator partition -> clusters.json (judge per cluster, not per case)
    _write_clusters(case_dir, a.case, case_hosts, min_shared=a.min)

    # 4) graph (default on; --no-graph to skip) -----------------------------
    graph_json = os.path.join(case_dir, "case_graph.json")
    graph_ok = False
    if not a.no_graph:
        print(f"== building case graph -> {os.path.relpath(graph_json, ROOT)} ==")
        gcmd = [sys.executable, os.path.join(WP, "graph_build.py"), *raw_files, "-o", graph_json]
        if a.operator:
            gcmd += ["--operator", a.operator]
        if a.operator_links:
            gcmd += ["--operator-links", a.operator_links]
        rc = _run(gcmd).returncode
        graph_ok = rc == 0 and os.path.isfile(graph_json)
        if not graph_ok:
            print(f"   WARNING: case graph build FAILED (rc={rc}); case_graph.json not written. "
                  "Downstream render/report figures will be missing until this is re-run.")
        elif a.render:
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
            whois_mode, whois_for = _whois_history_policy(a, case_dir, hosts)
            if whois_mode != "off":
                print(f"   whois-history: {whois_mode} for {len(whois_for)} seed/cluster host(s) "
                      f"(explicit opt-in; every other host stays current-WHOIS-only)")
            md = evidence_report.render_cluster_report(
                results, case=a.case, analyst=a.analyst,
                classification=a.classification, kb_dir=KB,
                whois_history=whois_mode, whois_history_for=whois_for)
            if _is_loop_authored_md(assess_path):
                with open(assess_path, "w", encoding="utf-8") as fh:
                    fh.write(md)
            else:
                with open(os.path.join(case_dir, "loop_assessment.md"), "w", encoding="utf-8") as fh:
                    fh.write(md)
                print("   analyst assessment.md present — not overwritten; "
                      "loop view -> loop_assessment.md")
        except Exception as e:
            print(f"   note: assessment render failed ({e}); skipped.")

    # 5b) MO-neighbour classification (Phase B) — AFTER step 5 so the whois sidecar exists and the
    #     estate registrant set is real (fresh case: falls back to raw artifacts.whois).
    _write_mo_neighbours(case_dir, a.case)

    # 6) completeness summary (stable output is auditable) ------------------
    print("\n== summary ==")
    print(f"   extracted: {len(ok)}/{len(hosts)}   raw files: {len(raw_files)}")
    if failed:
        print(f"   MISSES ({len(failed)}) — re-run these: {', '.join(failed)}")
    print(f"   case dir : {os.path.relpath(case_dir, ROOT)}/  (raw/, shared.txt, clusters.json"
          + (", case_graph.json" if graph_ok else "")
          + (", network.html" if a.render and graph_ok else "") + ")")
    print(f"   next     : IntelAnalysis over knowledge/ -> cases/{a.case}/assessment.md "
          f"(hand-written; this loop's render stays in loop_assessment.md)")


def _all_raw(case_dir):
    d = os.path.join(case_dir, "raw")
    return [os.path.join(d, f) for f in os.listdir(d) if f.endswith(".json")] if os.path.isdir(d) else []


def _ingest_case(raw_files):
    if not raw_files:
        return
    _run([sys.executable, os.path.join(KB_TOOLS, "ingest_webpivot.py"), "--kb", KB, *raw_files])


def _subenum_once(case_dir, hosts, timeout=None, free_only=False, jobs=4):
    """Subdomain enumeration per registrable apex of the case's hosts (wp_subenum: every installed
    passive tool, unioned, DNS-verified) → cases/<case>/subenum/<apex>.json, which the frontier reads
    to queue the apex's live subdomains for the next round. Idempotent per apex (an existing file is
    reused); no tool installed → one note, no failure. `free_only` (no-spend scope OR --free-only)
    restricts subfinder to keyless sources. Apexes run in a small thread pool (mechanical, no LLM):
    every enumerator is floored to the per-call ceiling, so serial apexes would sum to N × 30 min —
    the pool bounds the stage by one apex, not the sum."""
    try:
        sys.path.insert(0, WP)
        sys.path.insert(0, HERE)
        import wp_subenum
        import case_state as _cs
        import concurrent.futures as _cf
        tools = wp_subenum.which_tools()
        if not tools:
            print("   subdomain enumeration: no enumerator installed (subfinder/amass/assetfinder/findomain) — skipped")
            return
        apexes = sorted({_cs._frontier_apex(h) for h in hosts if h and "." in h})
        todo = [a for a in apexes if a and not re.fullmatch(r"[\d.]+", a)
                and not os.path.isfile(os.path.join(case_dir, "subenum", a + ".json"))]
        if not todo:
            return
        no_spend = free_only or _case_no_spend(case_dir)
        sync = wp_subenum.sync_providers(free_only=no_spend)   # ONCE: threads must not rewrite the config

        def _one(apex):
            return apex, wp_subenum.run(apex, case_dir=case_dir, timeout=timeout, free_only=no_spend, sync=sync)
        with _cf.ThreadPoolExecutor(max_workers=max(1, min(jobs, 4, len(todo)))) as ex:   # ≤4: each apex spawns 4 tools + a resolve pool
            for fu in _cf.as_completed([ex.submit(_one, a) for a in todo]):
                try:
                    apex, res = fu.result()
                except Exception as e:  # noqa: BLE001 — one apex failing must not sink the stage
                    print(f"   note: subdomain enumeration failed for one apex ({e}); skipped.")
                    continue
                p = os.path.join(case_dir, "subenum", apex + ".json")
                filled = (res.get("provider_sync") or {}).get("filled") or []
                print(f"   subdomains {apex}: {len(res.get('subdomains') or [])} name(s) via "
                      f"{', '.join(tools)} — {len(res.get('live') or [])} resolving"
                      + (f" (subfinder keyed from .env: {', '.join(filled)})" if filled else "")
                      + f" -> {os.path.relpath(p, ROOT)}")
    except Exception as e:  # noqa: BLE001
        print(f"   note: subdomain enumeration failed ({e}); skipped.")


def _censys_certs_once(case_dir, raw_files, budget=1):
    """Case-level Censys cert search (wp_censys.certs_search_once) over every leaf-cert SHA-256 the
    collection recorded; persists cases/<case>/censys_search.json, which the frontier merges on
    exact-cert match. Idempotent per case: an existing file with the same fingerprint set is reused
    (no second spend). Never raises."""
    try:
        import json as _json
        sys.path.insert(0, WP)
        import wp_censys
        fps = set()
        for rf in raw_files:
            try:
                obj = _json.load(open(rf, encoding="utf-8"))
            except Exception:
                continue
            if not isinstance(obj, dict):
                continue
            fp = ((obj.get("artifacts") or {}).get("tls_cert") or {}).get("fingerprint_sha256")
            if fp:
                fps.add(str(fp).lower())
        path = os.path.join(case_dir, "censys_search.json")
        if os.path.isfile(path):
            try:
                prev = _json.load(open(path, encoding="utf-8"))
                # reuse only a COMPLETED search over a superset of these certs. A skipped result (no
                # PAT then, monthly budget exhausted) must be retried; a plan-`free` skip is already
                # zero-cost through wp_plans, so nothing is bought by freezing it here.
                if (set(prev.get("fingerprints") or []) >= fps and not prev.get("error")
                        and not prev.get("skipped")):
                    return prev                          # already searched this cert set: no re-spend
            except Exception:
                pass
        if not fps:
            return None
        os.environ.setdefault("WP_CASE_DIR", case_dir)
        res = wp_censys.certs_search_once(sorted(fps), case_budget=budget, case_dir=case_dir)
        with open(path, "w", encoding="utf-8") as fh:
            _json.dump(res, fh, indent=2, ensure_ascii=False)
        if res.get("skipped"):
            print(f"   censys cert search: skipped — {res['skipped']}")
        else:
            print(f"   censys cert search: {len(res['queries'])} query, {res['hits']} hit(s), "
                  f"{len(res['hostnames'])} hostname(s) -> {os.path.relpath(path, ROOT)}")
        return res
    except Exception as e:  # noqa: BLE001
        print(f"   note: censys cert search failed ({e}); skipped.")
        return None


def _write_mo_neighbours(case_dir, case):
    """Classify the collectors' UNCLASSIFIED mo_neighbours blocks case-wide (case_state Phase B),
    persist cases/<case>/mo_neighbours.json and ingest it as KB FACTS (never edges). Returns the block
    or None when the case carries no discovery block at all. Never raises."""
    try:
        sys.path.insert(0, os.path.join(ROOT, "tools"))
        import case_state as cs
        import json as _json
        if not cs._mo_blocks(case_dir):
            return None
        blk = cs.mo_neighbour_classification(case_dir)      # a dir path: never re-resolved under ROOT/cases
        blk["case"] = case
        path = os.path.join(case_dir, "mo_neighbours.json")
        with open(path, "w", encoding="utf-8") as fh:
            _json.dump(blk, fh, indent=2, ensure_ascii=False)
        _run([sys.executable, os.path.join(KB_TOOLS, "ingest_mo_neighbours.py"), "--kb", KB, path])
        print(f"   mo-neighbours: {len(blk['same_registrant'])} same-registrant, "
              f"{len(blk['related_personas'])} related persona(s) [rung 10], "
              f"{blk['unrelated_count']} unrelated, {blk['unverifiable_count']} unverifiable, "
              f"{len(blk['bulk_origins'])} bulk origin(s) skipped -> {os.path.relpath(path, ROOT)}")
        return blk
    except Exception as e:  # noqa: BLE001
        print(f"   note: mo-neighbour classification failed ({e}); skipped.")
        return None


# raw/ files that are evidence bundles keyed like a host but are NOT hosts (same set as
# scripts/build_report_data.py _NON_HOST_STEMS) — counting them as hosts inflates clusters.json,
# shared.txt scope and the convergence snapshot ("+1 host: harvest.indicators").
_NON_HOST_STEMS = {"leak-sweep", "estate-seo-sweep", "shared-infra-note", "harvest.indicators"}


def _case_hosts(case_dir):
    """The hosts THIS case has collected (from raw/*.json) — the scope for shared/components."""
    return sorted({os.path.basename(p)[:-5].lower()
                   for p in _all_raw(case_dir)
                   if not p.endswith(".impersonation.json")
                   and os.path.basename(p)[:-5] not in _NON_HOST_STEMS})


def _write_shared(case_dir, min_shared, hosts=None):
    """(re)compute the --shared cluster seeds into shared.txt (persisted, not just printed).

    SCOPED to this case's hosts: without --domains the query reports indicators shared across the
    WHOLE KB, so a case's shared.txt filled up with unrelated past cases. The KB-wide count is
    still printed per indicator, which is the prevalence signal an analyst wants anyway."""
    cmd = [sys.executable, os.path.join(KB_TOOLS, "query.py"),
           "--kb", KB, "--shared", "--min", str(min_shared)]
    hosts = hosts if hosts is not None else _case_hosts(case_dir)
    # EXPANSION ANCHOR: shared indicators are cluster SEEDS for attribution, so they are computed over
    # the estate (hop < depth). A leaf's registrant would otherwise surface as a "join key" row.
    try:
        sys.path.insert(0, HERE)
        import case_state as _cs
        expanding = {h.lower() for h in _cs._expanding_hosts(case_dir)}
        if expanding:
            hosts = [h for h in hosts if h.lower() in expanding]
    except Exception:  # noqa: BLE001
        pass
    if hosts:
        cmd += ["--domains", ",".join(hosts)]
    r = _run(cmd, capture_output=True, text=True)
    shared = os.path.join(case_dir, "shared.txt")
    if r.returncode == 0:
        with open(shared, "w", encoding="utf-8") as fh:
            fh.write(r.stdout or "")
    elif not os.path.exists(shared):
        open(shared, "w", encoding="utf-8").close()   # ensure it exists for the downstream read
        print("   note: cluster-seed query did not complete — shared.txt left empty this run.",
              file=sys.stderr)
    else:
        print("   note: cluster-seed query did not complete — kept the existing shared.txt.",
              file=sys.stderr)


def _intelx_keyed():
    """True when an IntelX key is present under any registered alias (wp_intelx is the authority)."""
    try:
        if WP not in sys.path:
            sys.path.insert(0, WP)
        import wp_intelx
        return bool(wp_intelx.intelx_configured())
    except Exception:  # noqa: BLE001
        return False


def _intelx_flag(case_dir, loop=False, full=False):
    """['--intelx'] when the collector should auto-fire IntelX, else []. cmd_open: key present and
    the case is not a no-spend posture. cmd_loop: additionally ONLY under --full — the default loop
    is free-only and must never spend an IntelX search on its own."""
    if loop and not full:
        return []
    if not _intelx_keyed() or _case_no_spend(case_dir):
        return []
    return ["--intelx"]


def _case_no_spend(case_dir):
    """True when the persisted intake (cases/<case>/scope.json) carries constraints.no_spend."""
    p = os.path.join(case_dir, "scope.json")
    if not os.path.isfile(p):
        return False
    try:
        import json as _json
        sc = _json.load(open(p, encoding="utf-8"))
        return bool((sc.get("constraints") or {}).get("no_spend"))
    except Exception:
        return False


def _whois_history_policy(a, case_dir, seeds):
    """(history_mode, domains) for the WHOIS sidecar on the report step.

    Default "off": a routine assessment render never purchases WHOIS history (~50 DRS/domain).
    `--whois-history preview|purchase` is the explicit opt-in and is SCOPED to the seeds plus the
    members of every multi-domain same-operator cluster in clusters.json — never the whole estate.
    A `no_spend` intake forces "off" regardless of the flag (posture wins over the CLI)."""
    mode = getattr(a, "whois_history", "off") or "off"
    if mode == "off":
        return "off", set()
    if _case_no_spend(case_dir):
        print("   whois-history: scope.json constraints.no_spend → forced off (no history spend)")
        return "off", set()
    scoped = {_host(h).lower() for h in (seeds or []) if h}
    cpath = os.path.join(case_dir, "clusters.json")
    if os.path.isfile(cpath):
        try:
            import json as _json
            for c in (_json.load(open(cpath, encoding="utf-8")).get("clusters") or []):
                if not c.get("singleton"):
                    scoped.update(d.lower() for d in (c.get("domains") or []))
        except Exception:
            pass
    return mode, scoped



def _corroboration(case_dir, clusters, min_independent=2):
    """Annotate each cluster with HOW MANY INDEPENDENT ARTIFACTS actually corroborate it.

    The rule this repo states everywhere — one shared artifact is a LEAD, two independent ones are
    a CLUSTER — was enforced only by an analyst remembering it. `_write_clusters`' `min_shared`
    is a different test (one indicator binding >=2 domains), so a component resting on a single
    artifact was reported identically to one resting on five.

    This ANNOTATES; it never re-partitions. Changing which components form could split a real
    estate or merge an innocent party, and that is a rearchitecture rather than a fix. The verdict
    rides alongside so IntelAnalysis and the analyst can see which clusters are actually load-
    bearing.

    Prefers `rank_relations` over the case's raw pivot JSON (it applies the noise denylist and
    scores pairwise strength); falls back to counting distinct KB binding indicators when no raw
    JSON is present. `source` always records which was used.
    """
    rel_by_pair, source = {}, "kb_binding"
    raw = sorted(glob.glob(os.path.join(case_dir, "raw", "*.json")))
    if len(raw) >= 2:
        rr = os.path.join(os.path.dirname(ROOT), "scripts", "webpivot", "rank_relations.py")
        if os.path.isfile(rr):
            try:
                # include-weak so a 1-signal pair is still RETURNED and can be labelled a lead —
                # filtering it out here would hide exactly the case this function exists to name.
                res = subprocess.run([sys.executable, rr, *raw, "--include-weak"],
                                     capture_output=True, text=True, timeout=120)
                if res.returncode == 0 and res.stdout.strip():
                    for r in (json.loads(res.stdout).get("relations") or []):
                        key = tuple(sorted((str(r.get("a", "")).lower(),
                                            str(r.get("b", "")).lower())))
                        prev = rel_by_pair.get(key)
                        if prev is None or len(r.get("signals") or []) > len(prev.get("signals") or []):
                            rel_by_pair[key] = r
                    source = "rank_relations"
            except Exception as e:  # noqa: BLE001
                # Clustering must survive a broken corroborator. A pipeline that dies because an
                # annotation failed is worse than one that reports the annotation as unavailable.
                print(f"   note: rank_relations unavailable ({type(e).__name__}); "
                      f"falling back to KB binding counts")

    for c in clusters:
        if c.get("singleton"):
            c["corroboration"] = {"independent_artifacts": 0, "source": source,
                                  "assessment": "singleton",
                                  "verdict": "no relation to corroborate"}
            continue
        arts, best = set(), None
        if source == "rank_relations":
            doms = [d.lower() for d in c["domains"]]
            for i in range(len(doms)):
                for j in range(i + 1, len(doms)):
                    r = rel_by_pair.get(tuple(sorted((doms[i], doms[j]))))
                    if not r:
                        continue
                    sig = set(r.get("signals") or [])
                    if len(sig) > len(arts):
                        arts, best = sig, r
        if not arts:
            # KB fallback: distinct indicator TYPES binding this component. Types, not values —
            # three GA IDs from one operator are one artifact class, not three corroborations.
            arts = {b["indicator"].split(":", 1)[0] for b in c.get("binding_indicators", [])}
            source_used = "kb_binding"
        else:
            source_used = "rank_relations"
        n = len(arts)
        c["corroboration"] = {
            "independent_artifacts": n,
            "artifacts": sorted(arts)[:8],
            "source": source_used,
            "assessment": (best or {}).get("assessment"),
            "verdict": ("CORROBORATED — >=%d independent artifacts" % min_independent) if n >= min_independent
                       else ("LEAD ONLY — a single shared artifact. One artifact is a lead, not "
                             "proof: trackers get copied and favicons are reused by templates. "
                             "Find a second independent artifact before asserting same operator.")
                       if n == 1 else
                       "UNCORROBORATED — no strong shared artifact survived noise filtering",
        }
    return clusters


def _write_clusters(case_dir, case, hosts=None, min_shared=2, max_prevalence=8):
    """Partition THIS case's collected hosts into same-operator components (strong edges only) and
    persist them with the indicators binding each -> cases/<case>/clusters.json.

    WHY: judgment does not scale per-CASE, it scales per-CLUSTER. A 200-domain case is not one
    attribution question, it is N of them, and handing IntelAnalysis the undifferentiated case (plus
    a KB-wide shared.txt) is what made large cases unfocused. This is the same partition the SDK
    harness runs before judging (`orchestrator._compute_components` / `--parallel`), so both
    front-ends judge the same units. Returns the cluster list (empty if the KB can't be read)."""
    sys.path.insert(0, KB_TOOLS)
    try:
        from knowledge_base import KB as _KB  # noqa: E402
        from query import (_components, REGISTRANT_RELS, is_registrant_noise)  # noqa: E402
        from noise_filters import is_bulk_registrant, BOILERPLATE_RELS  # noqa: E402
    except Exception as e:
        print(f"   note: cluster partition skipped ({e})")
        return []
    hosts = hosts if hosts is not None else _case_hosts(case_dir)
    if not hosts:
        return []
    kb = _KB(KB)
    restrict = {h.lower() for h in hosts}
    # EXPANSION ANCHOR + landlord IPs, both from case_state: the partition is the unit of ATTRIBUTION,
    # so it runs over the hosts within the expansion depth only. A LEAF (hop >= depth) is owner-linked
    # to a previous-hop host, not to the operator — it is listed as `related_hosts`, never a member.
    # `hosted_on` to a landlord IP (an IP the case's own reverses showed answering > the shared-hosting
    # bound, or a CDN edge) is co-tenancy, not a binder.
    related_hosts = []
    try:
        sys.path.insert(0, HERE)
        import case_state as _cs
        noise_ips = _cs.shared_hosting_ips(case_dir)
        expanding = {h.lower() for h in _cs._expanding_hosts(case_dir)}
        if expanding:
            related_hosts = sorted(restrict - expanding)
            restrict = restrict & expanding
    except Exception:  # noqa: BLE001
        noise_ips = set()
    comps = _components(kb, KB, max_prevalence, restrict, noise_ips=noise_ips)
    noise_ip_inds = {f"ip:{ip}" for ip in noise_ips}
    shared = kb.shared_indicators(1)          # count in-cluster below; keep KB-wide as prevalence
    # The reported binding must be the edges that ACTUALLY formed the component, so it is filtered
    # by the same strong-edge rules _components uses — boilerplate rels (shared cache-plugin CSS /
    # HTML comment / DOM skeleton), reference-benign values, and over-prevalent indicators. Without
    # this the brief cites a template hash as the reason two domains are one operator.
    NOISE_RELS = BOILERPLATE_RELS
    try:
        from reference import benign_values  # noqa: E402
        benign = benign_values(KB)
    except Exception:
        benign = set()
    clusters = []
    for i, members in enumerate(comps, 1):
        mset = {m.lower() for m in members}
        binding = []
        for s in shared:
            strong_rels = [r for r in s["rels"] if r not in NOISE_RELS]
            if not strong_rels or s["indicator"] in benign:
                continue
            if s["indicator"] in noise_ip_inds and strong_rels == ["hosted_on"]:
                continue                          # landlord IP — the same exclusion _components applied
            # Registrant edges get the operator-grade carve-out (same as query._components): exempt
            # from the generic prevalence cap up to the bulk-registrant bound, and placeholder/
            # privacy values dropped — so a 31-domain estate binds instead of shattering, and the
            # "Registry Registrant ID: Not Available From Registry" mis-parse never binds anything.
            is_reg = any(r in REGISTRANT_RELS for r in strong_rels)
            if is_reg:
                if is_registrant_noise(s["indicator_type"], s["indicator"]) \
                        or is_bulk_registrant(s["domain_count"]):
                    continue
            elif s["domain_count"] > max_prevalence:
                continue
            inside = sorted(d for d in s["domains"] if d.lower() in mset)
            if len(inside) < min_shared:
                continue
            binding.append({"indicator": f"{s['indicator_type']}:{s['indicator']}",
                            "rels": strong_rels, "domains_in_cluster": inside,
                            "kb_wide_domains": s["domain_count"]})
        # most distinctive first: rare KB-wide, but binding many of this cluster's domains
        binding.sort(key=lambda b: (b["kb_wide_domains"], -len(b["domains_in_cluster"])))
        clusters.append({"id": i, "size": len(mset), "domains": sorted(mset),
                         "singleton": len(mset) == 1, "binding_indicators": binding[:15],
                         "binding_total": len(binding)})
    _corroboration(case_dir, clusters)
    doc = {"case": case, "generated": _iso_now(), "scope_hosts": len(restrict),
           "n_clusters": len(clusters), "max_prevalence": max_prevalence,
           "note": ("Same-operator components over STRONG shared indicators (boilerplate / "
                    "reference-benign / over-prevalent edges excluded). Judge each cluster "
                    "separately with IntelAnalysis — a cluster, not the case, is one attribution "
                    "question. kb_wide_domains >> domains_in_cluster means the indicator is "
                    "prevalent noise, not an owner link. Each cluster carries `corroboration`: "
                    "ONE shared artifact is a LEAD, TWO independent ones make a cluster — a "
                    "cluster marked LEAD ONLY must not be reported as an attributed estate. "
                    "`related_hosts` sit at the expansion depth (owner-linked to a previous hop, "
                    "not to the operator): collected for context, never cluster members."),
           "related_hosts": related_hosts,
           "clusters": clusters}
    import json as _json
    with open(os.path.join(case_dir, "clusters.json"), "w", encoding="utf-8") as fh:
        _json.dump(doc, fh, indent=2, ensure_ascii=False)
    multi = [c for c in clusters if not c["singleton"]]
    print(f"   clusters: {len(clusters)} component(s) over {len(restrict)} host(s) — "
          f"{len(multi)} multi-domain, {len(clusters) - len(multi)} singleton"
          + (f"; {len(related_hosts)} related host(s) at the expansion depth kept out" if related_hosts else "")
          + f" -> {os.path.relpath(os.path.join(case_dir, 'clusters.json'), ROOT)}")
    for c in multi[:8]:
        top = c["binding_indicators"][0]["indicator"] if c["binding_indicators"] else "—"
        cor = c.get("corroboration") or {}
        flag = "" if cor.get("independent_artifacts", 0) >= 2 else "  ⚠ LEAD ONLY"
        print(f"      c{c['id']} ({c['size']}): {', '.join(c['domains'][:5])}"
              f"{' …' if c['size'] > 5 else ''}   via {top}"
              f"  [{cor.get('independent_artifacts', 0)} artifact(s)]{flag}")
    return clusters


_DOMAIN_RE = re.compile(r'\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,})\b', re.I)


def _domains_in_text(s):
    """Domain-like tokens in a free-text string (for reading an analyst's next_pivots / gaps)."""
    return {m.group(1).lower().rstrip(".") for m in _DOMAIN_RE.finditer(s or "")}


def _is_loop_authored_md(path):
    """True when `path` is absent or holds THIS loop's own render — i.e. safe to overwrite.

    The loop re-renders assessment.md every round, so an analyst's hand-written markdown parked
    at that path would be destroyed silently on the next run. `assessment.json` has had this
    guard since it was written; the markdown did not, which is the gap this closes.

    The ownership rule and the conservative failure mode live in case_state — this loop renders
    through evidence_report, so it claims only evidence_report's output."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import case_state as cs
    return cs.may_overwrite_assessment(path, cs.EVIDENCE_REPORT_MD)


def _scope_premise(case):
    """The claim this case was opened on, from the harness intake record — '' when none was set.

    Read-only and best-effort on purpose: the loop must run identically on a machine where the
    harness is absent, so a missing module or an unscoped case costs the line, not the round."""
    try:
        sys.path.insert(0, os.path.join(ROOT, "harness"))
        import case_scope
        s = case_scope.resolve(case, persist=False)
        if case_scope.said(s, "claim") and s.get("claim"):
            return f"{s['claim']} (stated; basis: {s.get('basis') or 'unstated'})"
        return f"assumed target_class `{s.get('target_class')}` — no claim was stated"
    except Exception:  # noqa: BLE001
        return ""


def _structural_labels():
    """urlscan result labels that describe structure/hosting class, not a finding — reference DATA
    in WebPivot/references/urlscan_endpoints.json (wp_net.URLSCAN_STRUCTURAL_LABELS)."""
    try:
        if WP not in sys.path:
            sys.path.insert(0, WP)
        import wp_net  # noqa: E402
        return set(wp_net.URLSCAN_STRUCTURAL_LABELS)
    except Exception:  # noqa: BLE001 — conservative minimum, same as wp_net's fallback
        return {"domain.apexdomain", "content.rootdir", "hosting.cdn"}


def _urlscan_verdict_evidence(results, cap=12, start=4):
    """Appendix-B rows for urlscan's third-party verdict on each host's latest scan — a LEAD from an
    external scanner (Admiralty B2: usually reliable source, probably true), never our own verdict.
    Reads `live_results.urlscan_verdict` on the domain pivot (Pro: engine score + labels) and the
    fallback `related_urlscan.verdict`.

    A row is emitted ONLY on SIGNAL: flagged malicious (overall or engines), an overall/engine score
    above zero, a brand match, or a label outside the structural set. A benign scan (score 0, only
    domain.*/content.rootdir/hosting.* labels) contributes nothing — otherwise every estate host
    would fill Appendix B with non-evidence. Absence is never a row."""
    structural = _structural_labels()
    rows = []
    for r in results or []:
        host = (r.get("meta") or {}).get("host")
        if not host:
            continue
        v = None
        for piv in r.get("pivots") or []:
            if piv.get("kind") == "domain" and isinstance(piv.get("live_results"), dict):
                v = piv["live_results"].get("urlscan_verdict")
                if v:
                    break
        v = v or (r.get("related_urlscan") or {}).get("verdict")
        if not isinstance(v, dict):
            continue
        eng = v.get("engines") if isinstance(v.get("engines"), dict) else {}
        eng_score = eng.get("score") if isinstance(eng.get("score"), (int, float)) and eng.get("score", -1) >= 0 else None
        ov_score = v.get("score") if isinstance(v.get("score"), (int, float)) and v.get("score", -1) >= 0 else None
        malicious = bool(v.get("malicious") or eng.get("malicious"))
        brands = [b for b in (v.get("brands") or []) if b]
        signal_labels = [l for l in (v.get("labels") or []) if l and l not in structural]
        if not (malicious or (eng_score or 0) > 0 or (ov_score or 0) > 0 or brands or signal_labels):
            continue                                   # benign scan: no row
        parts = []
        if eng_score is not None:
            parts.append(f"engine score {eng_score}/100"
                         + (f" ({eng.get('malicious_total')}/{eng.get('total')} engines malicious)"
                            if eng.get("total") else ""))
        elif ov_score is not None:
            parts.append(f"overall score {ov_score}/100")
        if malicious:
            parts.append("flagged malicious")
        if signal_labels:
            parts.append("labels " + ", ".join(signal_labels[:4]))
        if brands:
            parts.append("brand " + ", ".join(brands[:3]))
        # 'E<n> [B2] <claim> — <source>' is the shape house_report.evidence_ledger parses (grade from
        # the bracket, source after the em dash); `start` follows the loop's three fixed rows. No URL
        # here: the Rule-12 vendor scrub would mangle it; the frozen result link lives in the captures ledger.
        rows.append(f"E{start + len(rows)} [B2] urlscan verdict for {host}: {'; '.join(parts)} — public web-scan "
                    f"verdict on the host's latest scan; a lead, not proof")
        if len(rows) >= cap:
            break
    return rows


def _render_assessment(case_dir, case, raw_files, fr, verdict, a, clusters=None):
    """Write the human ICD-203 assessment.md, and a machine-readable assessment.json that conforms to
    the SAME schema the SDK/IntelAnalysis path uses (bluf, cluster, attribution_level, confidence,
    evidence, gaps, next_pivots[str]) — loop-specific detail lives under an additive `loop` key.

    CONSISTENCY: if assessment.json was written by the ANALYST / SDK (not this loop), we do NOT
    overwrite it — we READ its next_pivots + gaps for domain leads and fold them into the frontier
    (the "read assessment.json, fill the gaps" chain). Returns that set of analyst-named leads."""
    import json as _json
    results = []
    for rf in raw_files:
        try:
            results.append(_json.load(open(rf, encoding="utf-8")))
        except Exception:
            pass
    try:
        sys.path.insert(0, WP)
        import evidence_report
        md = evidence_report.render_cluster_report(
            results, case=case, analyst=a.analyst, classification=a.classification, kb_dir=KB)
        # Never clobber a hand-written assessment — the SAME rule assessment.json follows below.
        mdpath = os.path.join(case_dir, "assessment.md")
        if _is_loop_authored_md(mdpath):
            with open(mdpath, "w", encoding="utf-8") as fh:
                fh.write(md)
        else:
            with open(os.path.join(case_dir, "loop_assessment.md"), "w", encoding="utf-8") as fh:
                fh.write(md)
            print("   analyst assessment.md present — not overwritten; "
                  "loop view -> loop_assessment.md")
    except Exception as e:
        print(f"   note: assessment.md render failed ({e}); skipped.")

    apath = os.path.join(case_dir, "assessment.json")
    existing = None
    if os.path.isfile(apath):
        try:
            existing = _json.load(open(apath, encoding="utf-8"))
        except Exception:
            existing = None
    # read analyst-authored leads (any assessment.json — canonical strings) for the chain. Free text
    # names the engine's own vendors ("reverses ran only on Hunter.how") and shared infra; a
    # domain-shaped token is a lead only when case_state.never_seed() does not reject it.
    import case_state as cs
    analyst_leads = set()
    if existing:
        for s in list(existing.get("next_pivots") or []) + list(existing.get("gaps") or []):
            analyst_leads |= {d for d in _domains_in_text(str(s)) if not cs.never_seed(d)}

    cluster = []
    sp = os.path.join(case_dir, "shared.txt")
    if os.path.isfile(sp):
        cluster = [l.strip() for l in open(sp, encoding="utf-8") if l.strip() and not l.startswith("#")][:100]
    clusters = clusters or []
    multi = [c for c in clusters if not c.get("singleton")]
    # domain -> the indicators binding it inside its own cluster (schema's shared_artifacts)
    by_domain = {}
    for c in clusters:
        for b in c.get("binding_indicators", []):
            for d in b.get("domains_in_cluster", []):
                by_domain.setdefault(d.lower(), []).append(b["indicator"])

    gaps = []
    if fr["candidate_total"]:
        gaps.append(f"{fr['candidate_total']} discovered apex(es) not yet collected "
                    f"(next {len(fr['pending'])} queued): {', '.join(fr['pending'][:10])}")
    if fr["metered_leads"]:
        gaps.append(f"{len(fr['metered_leads'])} metered pivot(s) deferred for analyst approval "
                    f"(FOFA/WhoisXML) — would spend credits.")
    if fr.get("co_tenancy_leads"):
        gaps.append(f"{len(fr['co_tenancy_leads'])} co-tenancy lead(s) held back from seeding "
                    f"(multi-tenant cert / shared or CDN hosting) — their co-names are other "
                    f"customers; check a specific pair with cert_overlap if you suspect otherwise.")
    if len(clusters) > 1:
        gaps.append(f"Case splits into {len(clusters)} same-operator component(s) "
                    f"({len(multi)} multi-domain) — this is {len(clusters)} attribution questions, "
                    f"not one. Judge each cluster separately (see clusters.json).")
    if verdict["verdict"] == "CONVERGED":
        gaps.append("Free frontier exhausted / no new growth — cluster looks converged.")
    collected = sorted({(r.get("meta") or {}).get("host") for r in results if (r.get("meta") or {}).get("host")})
    # canonical next_pivots as STRINGS (schema parity); structured detail kept under loop.frontier
    next_pivots = [f"judge cluster c{c['id']} with IntelAnalysis ({c['size']} domains: "
                   f"{', '.join(c['domains'][:5])}{' …' if c['size'] > 5 else ''}) — bound by "
                   f"{c['binding_indicators'][0]['indicator'] if c['binding_indicators'] else 'no strong indicator'}"
                   for c in multi]
    next_pivots += [f"collect {ap} (via {', '.join(fr['candidates'].get(ap, {}).get('sources', []))}) — free"
                    for ap in fr["pending"]]
    next_pivots += [f"collect subdomain {sub} of {apex} (via {', '.join(fr['subdomains'].get(sub, {}).get('sources', []))}) — free, same registration"
                    for apex, subs in (fr.get("subdomains_pending") or {}).items() for sub in subs]
    next_pivots += [f"[metered — approve first] {ml['service']} {ml['query']} — {ml['why']}"
                    for ml in fr["metered_leads"]]
    doc = {
        "bluf": (f"Deterministic convergence loop, round {fr['round']}: {len(collected)} host(s) "
                 f"collected across {len(clusters) or 1} same-operator component(s), "
                 f"{verdict['verdict'].lower()}; {len(fr['pending'])} free lead(s) pending, "
                 f"{len(fr['metered_leads'])} metered deferred. Attribution pending IntelAnalysis judgment."),
        "cluster": [{"domain": h, "shared_artifacts": sorted(set(by_domain.get(h.lower(), [])))[:8]}
                    for h in collected],
        "attribution_level": "inconclusive",   # the mechanical loop never attributes — IntelAnalysis does
        "confidence": "low",
        # Same reason, for the intake premise: this loop collects and converges, it does not weigh
        # a claim. It records WHAT was asserted so the analyst sees it, and leaves the verdict at
        # `inconclusive` — the honest value for "not tested here". Anything else would let a
        # mechanical round appear to have confirmed the requester's belief.
        "premise": _scope_premise(case),
        "premise_verdict": "inconclusive",
        "evidence": [f"convergence: {verdict['verdict']} ({verdict.get('rounds', 0)} round(s))",
                     f"{len(cluster)} shared cluster seed(s) recorded in shared.txt "
                     f"(scoped to this case's hosts)",
                     f"{len(clusters)} same-operator component(s) in clusters.json "
                     f"({len(multi)} multi-domain)"] + _urlscan_verdict_evidence(results),
        "gaps": gaps,
        "next_pivots": next_pivots,
        "_generator": "intel-loop",
        "loop": {
            "round": fr["round"], "generated": _iso_now(), "convergence": verdict,
            "collected": collected, "cluster_shared": cluster,
            # the partition judgment should run over — one cluster is one attribution question
            "clusters": [{"id": c["id"], "size": c["size"], "domains": c["domains"],
                          "binding_indicators": [b["indicator"] for b in c["binding_indicators"][:5]]}
                         for c in clusters],
            "frontier": [{"seed": ap, "why": fr["candidates"].get(ap, {}).get("sources", []),
                          "cost": "free"} for ap in fr["pending"]],
            "metered_leads": fr["metered_leads"],
            "co_tenancy_leads": fr.get("co_tenancy_leads", []),
            "assessment_md": os.path.relpath(os.path.join(case_dir, "assessment.md"), ROOT),
        },
    }
    # only (over)write assessment.json when it is absent or loop-authored — never clobber the analyst's
    if not existing or existing.get("_generator") == "intel-loop":
        with open(apath, "w", encoding="utf-8") as fh:
            _json.dump(doc, fh, indent=2, ensure_ascii=False)
    else:
        # analyst assessment present — keep it; drop the loop view in a sidecar so nothing is lost
        with open(os.path.join(case_dir, "loop_assessment.json"), "w", encoding="utf-8") as fh:
            _json.dump(doc, fh, indent=2, ensure_ascii=False)
        print("   analyst assessment.json present — not overwritten; loop view -> loop_assessment.json")
    return analyst_leads


def _iso_now():
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def _export_run_env(case_dir):
    """Tell every collector subprocess which case it serves and which RUN it belongs to (inherited
    env). wp_mo_neighbours keys its on-disk per-origin memo on the case dir and its per-run WhoisXML
    cap on the run token — without these, eight concurrent pivot_extract processes would each
    re-verify a shared origin and the cap would be a case-lifetime ceiling."""
    import uuid
    os.environ["WP_CASE_DIR"] = case_dir
    os.environ["WP_RUN_ID"] = f"{_iso_now()}-{uuid.uuid4().hex[:8]}"


def _promote(fr, hops, depth):
    """Frontier → next-round batch, with HOP bookkeeping (the expansion anchor). A new apex's hop is
    1 + the smallest hop among the collected hosts whose raw yielded it; a collected apex's own
    subdomain inherits the apex's hop (same registration). A candidate that would land beyond
    `depth` is not collected at all — it could only ever be a leaf's leaf. New apexes first, then
    the collected apexes' own live subdomains."""
    batch = []
    for apex in fr["pending"]:
        hop = int((fr["candidates"].get(apex) or {}).get("hop", 1))
        if hop > depth:
            continue
        hops[apex.lower()] = min(hop, hops.get(apex.lower(), hop))
        batch.append(apex)
    for apex, subs in (fr.get("subdomains_pending") or {}).items():
        for s in subs:
            if s not in batch:
                hops[s.lower()] = hops.get(apex.lower(), 0)
                batch.append(s)
    return batch


def cmd_loop(a):
    """Resumable convergence feedback loop: collect (free-only WebPivot) -> ingest -> snapshot ->
    assess (md+json) -> chase the discovered free frontier -> repeat until CONVERGED, cold (no free
    frontier left), or the round cap (awaiting-analyst). Checkpoints cases/<case>/state.json every
    round, so an interrupt resumes and a cold case re-mines against the current KB on re-run."""
    _load_env()
    import case_state as cs
    case = a.case
    case_dir = os.path.join(ROOT, "cases", case)
    os.makedirs(os.path.join(case_dir, "raw"), exist_ok=True)
    _export_run_env(case_dir)

    st = cs.load_state(case)
    st["depth_limit"] = a.max_rounds
    if getattr(a, "depth", None) is not None:
        st["expansion_depth"] = int(a.depth)
    hops = st.setdefault("hops", {})
    # seed the pending queue: a domains file or a comma list, merged (first run or added evidence)
    if a.seeds:
        if os.path.isfile(a.seeds):
            new = _read_domains(a.seeds)
        else:
            new = [_host(x) for x in a.seeds.split(",") if _host(x)]
        have = {h.lower() for h in st.get("pending", [])} | {h.lower() for h in st.get("consumed", [])}
        for h in new:
            if h not in have:
                st.setdefault("pending", []).append(h)
            hops.setdefault(h.lower(), 0)               # analyst seeds are hop 0
        if st.get("status") in ("converged", "cold"):
            st["status"] = "expanding"          # new evidence reopens a finished case
    # reconcile against ground truth on disk (robust to a mid-round interrupt)
    collected = cs.collected_hosts(case_dir)
    st["collected"] = sorted(collected)
    st["pending"] = [h for h in st.get("pending", []) if h.lower() not in collected]
    # EXPANSION ANCHOR reconcile: in an anchored case every collected host needs a hop. A subdomain
    # inherits its apex's hop; anything else of unknown provenance is a LEAF (depth), never a seed —
    # only analyst seeds (`open` / `loop <seeds>`) are hop 0. A legacy case with no hops at all keeps
    # its old behaviour (every host a seed) until the analyst seeds it.
    if hops:
        for h in sorted(collected):
            if h.lower() not in hops:
                hops[h.lower()] = hops.get(cs._frontier_apex(h), st["expansion_depth"])
    if not st["pending"] and not collected:
        sys.exit("no seeds — first run needs a domains file or comma list: "
                 "intel.py loop <case> seeds.txt")
    cs.save_state(case, st)

    print(f"== intel loop: case '{case}' — status={st['status']}, "
          f"{len(collected)} collected, {len(st['pending'])} pending, max {a.max_rounds} round(s) ==")

    for _ in range(a.max_rounds):
        # replenish the queue from the discovered free frontier when empty
        if not st["pending"]:
            fr = cs.frontier(case, max_new=a.max_new)
            # new apexes first, then the collected apexes' own live subdomains (same registration)
            st["pending"] = _promote(fr, hops, st["expansion_depth"])
            st["metered_leads"] = fr["metered_leads"]
            if not st["pending"]:
                st["status"] = "cold"
                cs.save_state(case, st)
                print("   frontier empty — no free leads left. status=cold.")
                break
        batch = st["pending"]
        st["pending"] = []
        st["round"] += 1
        # checkpoint NOW: frontier() re-reads state.json, so the batch's hops must be on disk before
        # this round's end-of-round frontier decides which of these hosts are leaves
        cs.save_state(case, st)
        print(f"\n-- round {st['round']}: collecting {len(batch)} host(s) (free-only): "
              f"{', '.join(batch[:8])}{' …' if len(batch) > 8 else ''}")

        # 1) collect (parallel, FREE-ONLY — no metered credits) ---------------
        # Same single-sourced collector as `open` above (collect_core), not a second fan-out: the
        # autonomous loop must spend no credits, so --free-only rides as an extra flag and
        # filter_args drops it (loudly) if this checkout's collector does not take it.
        ok, failed = [], []
        # DEFAULT: --free-only guards the autonomous loop (no credit spend). `--full` opts metered
        # engines in; free Validin + keyless sources run either way.
        loop_extra = [] if getattr(a, "full", False) else ["--free-only"]
        if a.render_extract:
            loop_extra.append("--render")
        # DEEP ARCHIVE (passive, keyless — safe under the free-only guard). Default: only the
        # primary seeds (round 1) get the exhaustive Wayback+urlscan+CommonCrawl+archive.today
        # pass; --deep-archive extends it to every frontier seed; --no-deep-primary turns it off.
        deep_this_round = getattr(a, "deep_archive", False) or (
            st["round"] == 1 and not getattr(a, "no_deep_primary", False))
        if deep_this_round:
            loop_extra.append("--deep-archive")
        # IntelX is the loop's METERED identity tier: only under --full (never in the default free-only
        # loop), only with a key, never on a no-spend posture — and ONLY on hosts that may still expand
        # the estate. A LEAF (hop == depth) is collected to bound the estate; buying leak/phonebook
        # units on a hosting vendor's customers is how one drift run exhausted a month's allowance.
        metered_extra = _intelx_flag(case_dir, loop=True, full=getattr(a, "full", False))
        depth = st["expansion_depth"]
        expanding_batch = [h for h in batch if not cs.is_leaf(h, hops, depth)]   # unknown hop = leaf in an anchored case
        leaf_batch = [h for h in batch if h not in expanding_batch]

        def _loop_status(res):
            good = _extract_ok(res)
            note = (res.get("note") or "").strip() or ("ok" if good else res.get("error") or "miss")
            print(f"   [{'ok ' if good else 'MISS'}] {res['host']}  {note}")
            (ok if good else failed).append(res["host"])

        for hosts_part, extra in ((expanding_batch, loop_extra + metered_extra), (leaf_batch, loop_extra)):
            if not hosts_part:
                continue
            collect_core.collect_many(
                [f"https://{h}" for h in hosts_part], case,
                max_workers=max(1, a.jobs), on_result=_loop_status, retry_misses=1,
                root=ROOT, py=sys.executable, collector=PIVOT_EXTRACT,
                # no_archive=True keeps the ported behaviour EXACTLY: the routine this replaced never
                # passed --archive-missing/--master. Archiving asks a third-party archive to fetch the
                # target, which is outbound and attributable — an autonomous loop must not start doing
                # that as a side effect of a refactor. `open` still archives; that run is analyst-driven.
                timeout=a.timeout, no_archive=True, extra_flags=extra)
        for h in batch:                              # consumed even on miss (don't re-queue a dead host)
            if h.lower() not in {c.lower() for c in st["consumed"]}:
                st["consumed"].append(h.lower())

        raw_files = _all_raw(case_dir)
        # 2) ingest whole case (idempotent), 3) refresh shared cluster seeds --
        _ingest_case(raw_files)
        case_hosts = _case_hosts(case_dir)
        _write_shared(case_dir, a.min, case_hosts)
        # 3b) partition into same-operator components — judgment scales per CLUSTER, not per case
        clusters = _write_clusters(case_dir, case, case_hosts, min_shared=a.min)
        # 4) convergence snapshot (convergence.py owns rounds.jsonl) ----------
        _run([sys.executable, os.path.join(KB_TOOLS, "convergence.py"), "snapshot", case])
        verdict = cs.convergence_verdict(case, stale=a.stale)
        # 5) compute the next free frontier + assess (md + json) -------------
        fr = cs.frontier(case, max_new=a.max_new)
        st["collected"] = sorted(cs.collected_hosts(case_dir))
        st["metered_leads"] = fr["metered_leads"]
        analyst_leads = _render_assessment(case_dir, case, raw_files, fr, verdict, a, clusters)
        # 5b) MO-neighbour Phase B after the sidecar exists; a fresh join-key-verified
        #     same_registrant enters THIS round's frontier (pure re-read of raw/ + the new file).
        mo = _write_mo_neighbours(case_dir, case)
        if mo and mo.get("same_registrant"):
            fr = cs.frontier(case, max_new=a.max_new)
        st["history"].append({"round": st["round"], "collected": len(st["collected"]),
                              "new_hosts": verdict.get("new_hosts_recent"),
                              "verdict": verdict["verdict"], "ts": _iso_now()})
        # CHAIN: fold any domains the analyst named in assessment.json (next_pivots/gaps) into the
        # frontier — an analyst-directed lead outranks the mechanically-discovered ones.
        done = {c.lower() for c in st["consumed"]} | {h.lower() for h in st["collected"]}
        analyst_new = sorted(d for d in (analyst_leads or set()) if d.lower() not in done)
        if analyst_new:
            print(f"   + {len(analyst_new)} analyst-directed lead(s) from assessment.json: "
                  f"{', '.join(analyst_new[:6])}")
        print(f"   collected={len(st['collected'])}  convergence={verdict['verdict']}  "
              f"fresh-frontier={fr['candidate_total']}  metered-leads={len(fr['metered_leads'])}")

        # 6) stop conditions -------------------------------------------------
        #    analyst-directed leads keep the case alive even if the mechanical frontier converged.
        if verdict["verdict"] == "CONVERGED" and not analyst_new:
            st["status"] = "converged"
            cs.save_state(case, st)
            print(f"   CONVERGED after round {st['round']}. Stop; write the final assessment.")
            break
        for h in analyst_new:
            hops.setdefault(h.lower(), 1)              # analyst-directed: linked to the case, hop 1
        st["pending"] = analyst_new + [h for h in _promote(fr, hops, st["expansion_depth"])
                                       if h.lower() not in done and h not in analyst_new]
        if not st["pending"]:
            st["status"] = "cold"
            cs.save_state(case, st)
            print("   no free frontier left. status=cold.")
            break
        cs.save_state(case, st)                       # checkpoint every round (resumable)
    else:
        # hit the round cap with free work still queued → paused for the analyst to resume/approve
        st["status"] = "awaiting-analyst" if st["pending"] else st["status"]
        cs.save_state(case, st)
        print(f"\n   reached max {a.max_rounds} round(s); status={st['status']} "
              f"(resume: intel.py loop {case} --max-rounds N).")

    print(f"\n== loop done: status={st['status']}, {len(st['collected'])} host(s), "
          f"{st['round']} round(s) ==")
    print(f"   assessment: cases/{case}/assessment.md  (+ assessment.json: gaps, next_pivots)")
    if st.get("metered_leads"):
        print(f"   ⚠ {len(st['metered_leads'])} metered lead(s) await approval — see "
              f"assessment.json → loop.metered_leads (would spend FOFA/WhoisXML credits).")
    print(f"   state: cases/{case}/state.json  (resume/reopen: intel.py loop {case}  |  "
          f"case_state.py reopen {case})")


def cmd_clusters(a):
    """Partition a case into same-operator components WITHOUT collecting anything — pure KB read.

    This is the unit of judgment: run it before correlating a big case so each cluster is judged on
    its own evidence instead of one unfocused pass over every domain."""
    case_dir = os.path.join(ROOT, "cases", a.case)
    if not os.path.isdir(os.path.join(case_dir, "raw")):
        sys.exit(f"no such case: {os.path.relpath(case_dir, ROOT)}")
    hosts = _case_hosts(case_dir)
    clusters = _write_clusters(case_dir, a.case, hosts, min_shared=a.min,
                               max_prevalence=a.max_prevalence)
    if a.json:
        import json as _json
        print(_json.dumps(clusters, indent=2, ensure_ascii=False))
        return
    for c in clusters:
        if c["singleton"] and not a.all:
            continue
        print(f"\nCLUSTER {c['id']}  ({c['size']} domain(s))")
        print(f"  domains: {', '.join(c['domains'])}")
        if not c["binding_indicators"]:
            print("  bound by: (no strong shared indicator — singleton / weak component)")
        for b in c["binding_indicators"][:6]:
            print(f"  bound by: {b['indicator']}  [{len(b['domains_in_cluster'])} in cluster, "
                  f"{b['kb_wide_domains']} KB-wide]")


def cmd_status(a):
    case_dir = os.path.join(ROOT, "cases", a.case)
    raw_dir = os.path.join(case_dir, "raw")
    if not os.path.isdir(raw_dir):
        sys.exit(f"no such case: {os.path.relpath(case_dir, ROOT)}")
    raw = sorted(f[:-5] for f in os.listdir(raw_dir) if f.endswith(".json"))
    print(f"case '{a.case}': {len(raw)} raw host file(s)")
    for h in raw:
        print(f"   raw  {h}")
    for extra in ("shared.txt", "clusters.json", "case_graph.json", "network.html"):
        mark = "yes" if os.path.isfile(os.path.join(case_dir, extra)) else "MISSING"
        print(f"   {extra:16} {mark}")


def main():
    ap = argparse.ArgumentParser(description="Deterministic OSINT case pipeline over the repo tools.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    o = sub.add_parser("open", help="run the full extract->ingest->shared[->graph] pipeline")
    o.add_argument("case")
    o.add_argument("domains", help="file with one domain/URL per line")
    o.add_argument("--no-collect", action="store_true",
                   help="skip the live fetch and reuse pivot JSONs already in cases/<case>/raw/ "
                        "(zero egress — for a handoff from a collector that already fetched, e.g. /case)")
    o.add_argument("--jobs", type=int, default=4)
    o.add_argument("--whois-reverse", action="store_true")
    o.add_argument("--whois-history", choices=("off", "preview", "purchase"), default="off",
                   help="WHOIS-history for the Domain Summary sidecar, SCOPED to seeds + multi-domain "
                        "cluster members: off (default — a rebuild spends no history credits), "
                        "preview (era count, 1 DRS), purchase (per-era records for the registrant-era "
                        "timeline, ~50 DRS/domain). A no_spend intake forces off.")
    o.add_argument("--fofa-full", action="store_true",
                   help="FOFA reverses over ALL historical data (full=true), not just ~1yr")
    o.add_argument("--render-extract", action="store_true",
                   help="render post-JS DOM per page (unlocks SaaS/analytics tokens; needs playwright)")
    o.add_argument("--render", action="store_true")
    o.add_argument("--screenshots", action="store_true",
                   help="capture a full-page PNG of each host (evidence backup for findings; "
                        "implies per-host --render, needs playwright; auto-skipped on hostile "
                        "targets without a proxy). PNGs land in cases/<case>/screenshots/ and are "
                        "embedded into reports via scripts/evidence-images.py")
    o.add_argument("--serp", action="store_true",
                   help="run the ADVERTISING layer on every host: Google Ads Transparency — the "
                        "VERIFIED paying advertiser account and the legal name its ads are funded "
                        "by, which survives WHOIS privacy and domain rotation. METERED (one "
                        "SerpApi search per host), which is why it is opt-in per run rather than "
                        "on by default. The free cloaking probe runs regardless.")
    o.add_argument("--serp-region", default=None, metavar="CODE",
                   help="market to query the Ads Transparency archive for (e.g. VN, US); "
                        "default is anywhere.")
    o.add_argument("--no-pssl", action="store_true",
                   help="skip CIRCL passive SSL (historical certificate->IP, i.e. origin recovery "
                        "from behind a CDN). It is free and on by default — this is for a minimal "
                        "footprint or a rate-limit.")
    o.add_argument("--no-graph", action="store_true")
    o.add_argument("--operator", default=None)
    o.add_argument("--operator-links", default=None)
    o.add_argument("--min", type=int, default=2)
    o.add_argument("--timeout", type=int, default=20)
    o.add_argument("--free-only", action="store_true", dest="free_only",
                   help="spend no metered credits: the collector's metered layers are gated off and "
                        "subdomain enumeration uses keyless sources only. Also inferred from a "
                        "no_spend scope.json.")
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

    lp = sub.add_parser("loop", help="resumable convergence feedback loop (collect→assess→chase gaps)")
    lp.add_argument("case")
    lp.add_argument("seeds", nargs="?", default=None,
                    help="first run / added evidence: a domains file OR a comma list (omit to resume)")
    lp.add_argument("--max-rounds", type=int, default=6, help="round cap before pausing (default 6)")
    lp.add_argument("--max-new", type=int, default=8, help="new frontier seeds collected per round")
    lp.add_argument("--depth", type=int, default=None,
                    help="expansion anchor: owner-link HOPS from the seeds a host may be at and still "
                         "be mined for new apexes (default 2 — seeds=0, their siblings=1, a sibling's "
                         "siblings=2 are collected as LEAVES and never expanded further)")
    lp.add_argument("--stale", type=int, default=2,
                    help="consecutive zero-growth rounds that mean CONVERGED (default 2)")
    lp.add_argument("--jobs", type=int, default=4)
    lp.add_argument("--timeout", type=int, default=20)
    lp.add_argument("--render-extract", action="store_true",
                    help="render post-JS DOM per page (needs playwright)")
    lp.add_argument("--deep-archive", action="store_true",
                    help="EXHAUSTIVE archival collection on EVERY seed each round: full Wayback "
                         "history (whole domain), every urlscan cached DOM, CommonCrawl + "
                         "archive.today. Passive & keyless (safe for the free-only loop). Default: "
                         "the primary (round-1) seeds are deep-archived; frontier seeds are not.")
    lp.add_argument("--no-deep-primary", action="store_true",
                    help="do NOT deep-archive the primary seeds either (fastest; archive only on "
                         "explicit --deep-archive)")
    lp.add_argument("--full", action="store_true",
                    help="run METERED engines (FOFA/Censys/SecurityTrails/DNSLytics/HunterHow/…) in "
                         "the autonomous loop too — drops the default --free-only credit guard. Free "
                         "Validin + keyless sources run either way. Opt-in; spends credits per round.")
    lp.add_argument("--min", type=int, default=2, help="--shared cluster threshold")
    lp.add_argument("--analyst", default=None)
    lp.add_argument("--classification", default="UNCLASSIFIED//FOR OFFICIAL USE ONLY")
    lp.set_defaults(func=cmd_loop)

    c = sub.add_parser("clusters", help="partition a case into same-operator components (no collection)")
    c.add_argument("case")
    c.add_argument("--min", type=int, default=2, help="domains an indicator must bind to be listed")
    c.add_argument("--max-prevalence", type=int, default=8,
                   help="an indicator on more than this many KB domains is generic noise")
    c.add_argument("--all", action="store_true", help="also list singleton clusters")
    c.add_argument("--json", action="store_true")
    c.set_defaults(func=cmd_clusters)

    s = sub.add_parser("status", help="audit an existing case's persisted outputs")
    s.add_argument("case")
    s.set_defaults(func=cmd_status)

    a = ap.parse_args()
    a.func(a)


if __name__ == "__main__":
    main()
