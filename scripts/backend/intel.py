#!/usr/bin/env python3
"""
intel.py — cti-expert → intel_engine Tier-2 dispatcher.

One uniform entry point for every engine tool cti-expert shells to when the
optional `intel_engine` backend is present (Tier 2 CLI). It resolves
`$INTEL_HOME` via `backend.py`, runs the right engine script **from the engine
root** (so the engine's own relative paths — `knowledge/`, `WebPivot/tools/…` —
resolve), injects `--kb knowledge` where the tool needs it, and forwards every
remaining argument verbatim. When the backend is absent it prints one clear
note and exits 3 — callers never hand-build `python3 $INTEL_HOME/…` paths.

This is the CLI half of the backend. At Tier 1 the same operations are the typed
MCP tools (`mcp__analyze__*`); prefer those when the `intel` server is connected.
See connectors/intel-backend.md §4–§5.

Recommended runner: `uv run intel.py <op> [args…]`  (stdlib-only; python3 works too)

Examples:
    uv run intel.py kb --stats                       # KB overview
    uv run intel.py kb --entity example.com          # one entity's facts + edges
    uv run intel.py kb --cluster example.com         # domains sharing an indicator
    uv run intel.py kb --shared --min 2              # whole-KB shared indicators
    uv run intel.py recall scam-site.top             # "seen before?" (query.py --entity)
    uv run intel.py risk --case CASE-0001            # NRD / BPH / money-trail scoring
    uv run intel.py reverse-whois --reverse-email owner@x.com --search-type historic --json
    uv run intel.py cert-overlap a.example b.example # TLS/SAN same-operator verdict
    uv run intel.py reference check favicon:123       # BENIGN / SIGNAL / UNKNOWN
    uv run intel.py operators list -v                # confirmed-operator ledger
    uv run intel.py harness status CASE-0001         # whole-case state (IntelHarness)
    uv run intel.py graph case_graph.json out --legend   # IntelGraph diagram
    uv run intel.py report assessment.md out --pdf --docx # IntelReport PDF/DOCX
    uv run intel.py binary ./trader.apk --leads      # BinaryPivot IOC extraction
    uv run intel.py list                             # show the op → script map
    uv run intel.py --dry-run kb --stats            # print the command, don't run it
"""
# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
import sys
import os
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
import backend  # noqa: E402  (sibling resolver: resolve()/status())

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

# --- egress proxy / rotation: export HTTP(S)_PROXY so every subprocess tool
# this dispatcher spawns (env=dict(os.environ,...)) inherits the same egress ---
def _install_cti_proxy():
    import os as _o, sys as _s
    _b = _o.path.dirname(_o.path.abspath(__file__))
    for _ in range(6):
        _c = _o.path.join(_b, "proxy", "cti_proxy.py")
        if _o.path.isfile(_c):
            _s.path.insert(0, _o.path.dirname(_c))
            try:
                import cti_proxy
                cti_proxy.install()
            except Exception:
                pass
            return
        _p = _o.path.dirname(_b)
        if _p == _b:
            return
        _b = _p
_install_cti_proxy()

# Engine interpreter: $INTEL_PY → the skill's own .venv (harness SDK/MCP + IntelGraph deps
# live there, installed via `uv pip install -r requirements.txt`) → whatever runs this file.
# The stdlib layers (collectors, KB, deterministic pipeline) work under any of these; only the
# LLM orchestrator / MCP server / chart renderers need the .venv.
_VENV_PY = os.path.join(backend.SKILL_DIR, ".venv", "bin", "python")
PY = (os.environ.get("INTEL_PY")
      or (_VENV_PY if os.path.isfile(_VENV_PY) else None)
      or sys.executable or "python3")

# op → (script relative to $INTEL_HOME, prefix args injected before the caller's).
# The caller's remaining argv is appended verbatim, so new flags need no change here.
# Goal: 100% parity — EVERY standalone engine CLI is reachable. Internal library
# modules (wp_*, noise_filters, schemas, agents, orchestrator, render.py) are imported
# by these tools and are deliberately NOT exposed as ops.
DISPATCH = {
    # ── whole-case pipelines (IntelHarness) ─────────────────────────────
    "pipeline":      ("tools/intel.py",               []),   # deterministic open/status
    "harness":       ("harness/cli.py",               []),   # LLM Collect→Correlate→Assess
    "clusters":      ("tools/intel.py",               ["clusters"]),  # partition a case first —
                                                                      # the unit of judgment is the
                                                                      # CLUSTER, not the case
    "loop":          ("tools/intel.py",               ["loop"]),      # collect→assess to convergence
    "frontier":      ("tools/case_state.py",          ["frontier"]),  # unresolved free/metered gaps
    "reopen":        ("tools/case_state.py",          ["reopen"]),    # re-open on new seeds
    "enrichment-done": ("tools/case_state.py",         ["enrichment-done"]),  # close leak/breach/dork leads
    "scope":         ("harness/case_scope.py",        []),   # intake: no-touch class, victim owner
    # ── acquire / collect (WebPivot engine collectors) ──────────────────
    "pivot-extract": ("WebPivot/tools/pivot_extract.py", []),
    "fallback":      ("tools/fallback_probe.py",      ["--kb", "knowledge"]),
    "whois":         ("WebPivot/tools/whois_enrich.py", []),   # forward WHOIS enrich
    "reverse-whois": ("WebPivot/tools/whois_enrich.py", []),   # --reverse-email/-name …
    "cdn-ranges":    ("WebPivot/tools/cdn_ranges.py",  []),    # CDN/ASN range classify (--update)
    "ct-monitor":    ("WebPivot/tools/ct_monitor.py",  []),    # CT-log watch
    "wayback-ga":    ("WebPivot/tools/wayback_ga.py",  []),    # historic GA/GTM harvest
    "impersonate":   ("WebPivot/tools/wp_impersonate.py", []), # typosquat/TLD-sweep/CT lookalikes
    "search-pivot":  ("tools/search_pivot.py",        []),     # multi-engine dork queries
    "censys":        ("WebPivot/tools/wp_censys.py",  []),     # CenQL build + free-plan lookups
    "capabilities":  ("WebPivot/tools/wp_capabilities.py", []),# which keys exist, what's unqueried
    "jarm":          ("WebPivot/tools/jarm.py",       []),     # JARM TLS-stack fingerprint
    "email-permute": ("WebPivot/tools/email_permute.py", []),  # name/handle -> email CANDIDATES
    "intelx":        ("WebPivot/tools/wp_intelx.py",  []),     # leak/paste/darknet selector search
    "anyrun":        ("BinaryPivot/tools/bp_anyrun.py", []),   # TI Lookup — READ-ONLY by default;
                                                               # --submit needs analyst confirmation
    "docmeta":       ("WebPivot/tools/wp_docmeta.py", []),     # PDF/EXIF/PNG author+GPS metadata
    "paths":         ("WebPivot/tools/wp_paths.py",   []),     # URL-path kit extraction (path_kit:)
    "capture":       ("WebPivot/tools/wp_capture.py", []),     # raw-evidence capture + manifest hash
    "screenshot":    ("WebPivot/tools/wp_screenshot.py", []),  # rendered full-page PNG as
                                                               # timestamped, hashed evidence
    "serp":          ("WebPivot/tools/wp_serp.py",    []),     # Ads Transparency + cloaking probe
    "pssl":          ("WebPivot/tools/wp_pssl.py",    []),     # passive SSL: historic cert -> IP
    "liveness":      ("WebPivot/tools/wp_liveness.py", []),    # parked/soft-404 vs genuinely dead
    "exhaust":       ("WebPivot/tools/wp_exhaust.py", []),     # which collection layers actually
                                                               # RAN vs silently never fired
    "netlas":        ("WebPivot/tools/wp_netlas.py", []),    # Netlas DNS/scan/WHOIS/cert index —
                                                             # ip|ns|spf|domain|san|title|plan|raw
    "buckets":       ("WebPivot/tools/wp_buckets.py", []),   # GrayHatWarfare open-bucket /
                                                             # exposed-file search (/secrets, /docleak)

    # ── repo-root collectors (scripts/webpivot/ — one level ABOVE $INTEL_HOME). These
    # existed and worked but were reachable only as raw `python3 …` lines documented in
    # techniques/web-pivot.md, i.e. invisible to both front-ends (CLAUDE.md RULE 3).
    "cert-pivot":    ("../scripts/webpivot/cert_pivot.py",      []),  # leaf-cert fingerprint -> other
                                                               # hosts serving it; SANs = siblings
    "rank-relations":("../scripts/webpivot/rank_relations.py",  []),  # score same-operator links across
                                                               # a case's raw/*.json, noise-filtered
    "pivot-suggest": ("../scripts/webpivot/pivot_suggest.py",   []),  # rank "what to pivot on next"
    "crypto-balance":("../scripts/webpivot/crypto_balance.py",  []),  # wallet balance / lifetime flow
    "email-hygiene": ("../scripts/webpivot/email_hygiene.py",   []),  # 0-100 + A-F email-domain grade
    "sensitive-paths":("../scripts/webpivot/sensitive_paths.py",[]),  # classify URLs against sensitive
                                                               # -path patterns (pure, no network)
    "wayback-fetch": ("../scripts/webpivot/wayback_fetch.py",   []),  # nearest snapshot + RAW content
    "wayback-harvest":("../scripts/webpivot/wayback_harvest.py",[]),  # full-IOC sweep of a domain's
                                                               # whole Wayback history

    # ── scripts/osint/ — Phase 2 builds. Commands SKILL.md documented for months with no
    # implementation behind them; each is keyless-first and discloses what it could NOT check.
    "hash-id":       ("../scripts/osint/hash_id.py",         []),  # MD5-vs-NTLM before you submit
    "threat-check":  ("../scripts/osint/reputation_check.py", []), # any indicator -> reputation
    "scam-check":    ("../scripts/osint/reputation_check.py", ["--mode", "scam"]),
    "vuln-check":    ("../scripts/osint/vuln_check.py",      []),  # CVE via CIRCL + NVD (keyless)
    "msftrecon":     ("../scripts/osint/msft_recon.py",      []),  # M365 tenant id / federation
    "username":      ("../scripts/osint/username_enum.py",   []),  # handle presence (HYPOTHESES)
    "phone":         ("../scripts/osint/phone_osint.py",     []),  # E.164 decomposition + pivots
    "exposure":      ("../scripts/osint/exposure_score.py",  []),  # weight-engine composite 0-100
    # ── Phase 3: the commands SKILL.md marked [unimplemented] ───────────────────────
    "subdomain":     ("../scripts/osint/subdomain_enum.py",  []),  # multi-source, keyless CT+PDNS
    "github-osint":  ("../scripts/osint/github_osint.py",    []),  # accounts, repos, commit emails
    "secrets":       ("../scripts/osint/github_osint.py",    ["--secrets"]),
    "traffic":       ("../scripts/osint/traffic_rank.py",    []),  # Tranco rank (absence matters)
    "sharelink":     ("../scripts/osint/sharelink_resolve.py", []),# expand + sharer identity
    "docleak":       ("../scripts/osint/dork_builder.py",    []),  # emits queries, never scrapes
    "icp":           ("../scripts/osint/cn_recon.py",        []),  # ICP filing + serial pivot
    "cn-corp":       ("../scripts/osint/cn_recon.py",        []),  # PRC registry chain (gated)
    "crossref":      ("../scripts/osint/kb_crossref.py",     []),  # identifiers across CASES
    "drift":         ("../scripts/osint/case_drift.py",      []),  # what changed between runs
    "signatures":    ("../scripts/osint/signature_scan.py",  []),  # behavioural signature catalog
    "email-deep":    ("../scripts/osint/deep_profile.py",    []),  # composition, not a collector
    "breach-deep":   ("../scripts/osint/deep_profile.py",    ["--mode", "breach"]),
    "wifi":          ("../scripts/osint/wifi_ssid.py",       []),  # WiGLE (keyed; discloses gap)
    "gdoc":          ("WebPivot/tools/wp_docmeta.py",        []),  # /gdoc == doc_metadata
    # Aliases surfaced by a recount: these commands only ever appear WITH arguments in
    # SKILL.md, so the old bare-backtick regex never saw them and they were never triaged.
    "archive-harvest":("../scripts/webpivot/wayback_harvest.py", []),  # = wayback-harvest
    "ransomware-check":("../scripts/osint/reputation_check.py", ["--mode", "scam"]),
    "techstack":     ("WebPivot/tools/pivot_extract.py",     []),  # tech_fingerprint layer
    "visitors":      ("WebPivot/tools/pivot_extract.py",     []),  # tracker / visitor-intel layer
    "saas-map":      ("WebPivot/tools/pivot_extract.py",     []),  # saas_ids.* layer
    "cert-history":  ("WebPivot/tools/wp_pssl.py",           []),  # historic cert -> IP
    "dns-history":   ("../scripts/webpivot/wayback_ga.py",   []),  # historic records
    # ── aliases: the code already existed, only the documented NAME never resolved ──────
    "webpivot":      ("WebPivot/tools/pivot_extract.py",     []),  # /webpivot, the flagship verb
    "iban":          ("../scripts/iban_analyze.py",          []),  # /iban -> the existing script
    "redact":        ("../scripts/redact.py",                []),  # /redact -> the existing script
    "stealer-log":   ("../scripts/stealer_log_parse.py",     []),  # /stealer-log
    "snapshots":     ("../scripts/webpivot/wayback_fetch.py", []), # /snapshots
    "query":         ("tools/search_pivot.py",               []),  # /query and /dork-sweep are
    "dork-sweep":    ("tools/search_pivot.py",               []),  # the same multi-engine builder
    "stats":         ("tools/kb/query.py",       ["--kb", "knowledge", "--stats"]),
    "case":          ("tools/intel.py",                      []),  # /case and /sweep both mean
    "sweep":         ("tools/intel.py",                      []),  # "run the pipeline"
    # ── enrich / correlate (KB + cert) ──────────────────────────────────
    "kb":            ("tools/kb/query.py",            ["--kb", "knowledge"]),
    "recall":        ("tools/kb/query.py",            ["--kb", "knowledge", "--entity"]),
    "kb-stats":      ("tools/kb/knowledge_base.py",   ["knowledge"]),
    "risk":          ("tools/kb/risk_signals.py",     []),
    "reference":     ("tools/kb/reference.py",        ["--kb", "knowledge"]),
    "cert-overlap":  ("tools/cert_overlap.py",        []),
    "hypothesize":   ("tools/kb/hypothesize.py",      ["--kb", "knowledge"]),
    "noise":         ("tools/kb/noise_filters.py",    []),   # is this indicator shared-infra noise?
    "operators":     ("tools/kb/operator_registry.py", []),
    "calibration":   ("tools/kb/calibration.py",      ["--kb", "knowledge"]),
    "convergence":   ("tools/kb/convergence.py",      []),
    "domains":       ("tools/domain_table.py",        ["--kb", "knowledge"]),
    "victims":       ("tools/kb/victim_profile.py",   []),   # access vector from the victim set
    "mirrors":       ("tools/kb/sync_mirrors.py",     []),   # keep duplicated denylists in step
    # ── ingest (feed the KB) ────────────────────────────────────────────
    "ingest":        ("tools/kb/ingest_webpivot.py",  ["--kb", "knowledge"]),
    "ingest-report": ("tools/kb/ingest_report.py",    []),
    "ingest-rwhois": ("tools/kb/ingest_reverse_whois.py", ["--kb", "knowledge"]),
    # ── KB hygiene / export / sync ──────────────────────────────────────
    "clean":         ("tools/kb/clean_kb.py",         ["--kb", "knowledge"]),
    "export-graph":  ("tools/kb/export_graph.py",     ["--kb", "knowledge"]),
    # ── case store / index / cost ───────────────────────────────────────
    "case-store":    ("tools/case_store.py",          []),   # snapshot/manifest
    "case-index":    ("tools/case_index.py",          []),   # which case is an artifact in?
    "cost":          ("tools/cost_report.py",         []),
    "api-usage":     ("WebPivot/tools/api_usage.py",  []),
    "tool-calls":    ("harness/audit.py",             []),   # what the model actually called
    "dashboard":     ("harness/dashboard/serve.py",   []),   # loopback-only run inspector
    # ── deliver / render (IntelGraph / IntelReport + evidence) ──────────
    "graph-build":   ("WebPivot/tools/graph_build.py", []),  # → case_graph.json (render input)
    "graph":         ("IntelGraph/scripts/graph_to_diagram.py", []),
    "network":       ("IntelGraph/scripts/render_network.py",   []),
    "gantt":         ("IntelGraph/scripts/gantt.py",           []),
    "graphviz":      ("IntelGraph/scripts/render_graphviz.py", []),
    "mermaid":       ("IntelGraph/scripts/render_mermaid.py",  []),
    "report":        ("IntelReport/scripts/render_report.py",  []),
    "house-report":  ("tools/house_report.py",         []),   # case dir → editorial PDF+DOCX, deterministic
    "evidence-report": ("WebPivot/tools/evidence_report.py",   []),
    "timeline":      ("IntelGraph/scripts/case_timeline.py",   []),  # infrastructure lifecycle
    # ── disseminate (IntelShare) ─────────────────────────────────────────
    # sh_export builds the event locally and touches nothing. sh_misp `push` STAGES it on
    # your own instance (organisation-only, unpublished); `publish` syncs it to the
    # community and CANNOT be recalled — a shared indicator becomes somebody else's
    # blocking rule. Two separate ops because they are two separate decisions.
    "misp-export":   ("IntelShare/tools/sh_export.py",  []),   # build the event from the case
    "misp":          ("IntelShare/tools/sh_misp.py",    []),   # keycheck/budget/search/push/publish
    # ── file half of the funnel (BinaryPivot) ───────────────────────────
    "binary":        ("BinaryPivot/tools/analyze_artifact.py",  []),
    # ── authentication surface (Engage) ─────────────────────────────────
    # Detection is passive and free. en_engage/en_harvest create and drive a SYNTHETIC-persona
    # account: that is OUTBOUND, attributable and irreversible, and gated in the tool itself.
    "github":        ("WebPivot/tools/wp_github.py",  []),   # committer identities: user/org/repo/commit
    "subenum":       ("WebPivot/tools/wp_subenum.py", []),   # subdomains via subfinder/amass/assetfinder/findomain
    "login-detect":  ("Engage/tools/en_forms.py",     []),   # find the login/registration form
    "persona":       ("Engage/tools/en_persona.py",   []),   # mint a synthetic research persona
    "engage":        ("Engage/tools/en_engage.py",    []),   # GATED — register / log in
    "engage-harvest": ("Engage/tools/en_harvest.py",  []),   # read the members area
    "engage-report": ("Engage/tools/en_report.py",    []),   # shareable engagement write-up
    # ── eval / self-test ────────────────────────────────────────────────
    "eval":          ("tools/eval/run_eval.py",       []),
}

# One-line help shown by `intel.py list`.
BLURB = {
    "pipeline": "deterministic case pipeline: open <case> domains.txt | status",
    "harness": "LLM whole-case orchestration: open/continue/status",
    "clusters": "partition a case into same-operator clusters BEFORE judging",
    "loop": "collect → assess repeatedly until the case converges",
    "frontier": "unresolved gaps: free next seeds + deferred metered leads",
    "reopen": "re-open a converged case on newly discovered seeds",
    "enrichment-done": "close leak/breach/OSINT/dork leads (suppress from frontier once run)",
    "scope": "case intake: no-touch class, victim ownership, egress gate",
    "pivot-extract": "engine WebPivot collector → pivot JSON (--render/--leads)",
    "fallback": "fallback probe when a page won't render",
    "whois": "forward WHOIS enrich for a domain",
    "reverse-whois": "reverse-WHOIS a registrant email/name (noise-filtered)",
    "cdn-ranges": "CDN/ASN range table — classify an IP, --update the cache",
    "ct-monitor": "certificate-transparency log watch",
    "wayback-ga": "historic GA/GTM tracker harvest from Wayback",
    "impersonate": "hunt typosquat/lookalike domains (crt.sh + DNS, free)",
    "search-pivot": "multi-engine dork queries for any indicator (no scraping)",
    "censys": "Censys: cert/host/webproperty lookup, CenQL build, budget",
    "capabilities": "which API keys exist and what each absence costs",
    "jarm": "JARM TLS-stack fingerprint of a host",
    "email-permute": "name/username -> ranked email CANDIDATES (hypotheses, never findings)",
    "intelx": "IntelX: search a strong selector in leaks/pastes/darknet",
    "anyrun": "ANY.RUN TI Lookup (read-only; --submit needs confirmation)",
    "docmeta": "document/image metadata: PDF /Info + XMP, EXIF incl. GPS",
    "paths": "URL-path kit extraction — path_kit: when hosts rotate",
    "capture": "raw-evidence capture + tamper-evident manifest hashing",
    "screenshot": "rendered full-page PNG as timestamped, hashed evidence",
    "serp": "Ads Transparency (who PAID) + the cloaking probe",
    "pssl": "passive SSL: historic cert → IP, recovers an origin behind CDN",
    "liveness": "parked / soft-404 / bot-walled vs genuinely dead",
    "exhaust": "which collection layers RAN vs silently never fired",
    "netlas": "Netlas index: reverse a NON-CDN origin IP / NS / SPF include to apexes (ip|ns|spf|domain|san|title|plan|raw; --count)",
    "buckets": "GrayHatWarfare open-bucket / exposed-file search (/secrets, /docleak)",
    "cert-pivot": "leaf-cert fingerprint → other hosts serving it; SANs = siblings",
    "rank-relations": "score same-operator links across a case's raw/*.json (noise-filtered)",
    "pivot-suggest": "rank what to pivot on next from case findings",
    "crypto-balance": "on-chain balance / lifetime-flow enrichment for wallets",
    "email-hygiene": "deterministic 0-100 + A-F email-domain hygiene grade",
    "sensitive-paths": "classify URLs against sensitive-path patterns (pure, no network)",
    "wayback-fetch": "nearest Wayback snapshot + RAW content (robots.txt-proof)",
    "wayback-harvest": "full-IOC harvest across a domain's whole Wayback history",
    "hash-id": "identify a hash's algorithm BEFORE lookup (MD5 vs NTLM = submit vs never)",
    "threat-check": "reputation for ip/domain/url/hash across keyless feeds (OTX, urlscan)",
    "scam-check": "the fraud reading of the same feeds, plus ransomware victim records",
    "vuln-check": "CVE lookup via CIRCL + NVD, both keyless; flags scorer disagreement",
    "msftrecon": "M365/Entra tenant id, federation and namespace — keyless and passive",
    "username": "handle presence across curated platforms (HYPOTHESES, never findings)",
    "phone": "E.164 decomposition, territory, messaging links, source-search queries",
    "exposure": "composite 0-100 subject exposure score (analysis/weight-engine)",
    "subdomain": "passive subdomain enum (certspotter+hackertarget+crt.sh); flags admin hosts",
    "github-osint": "GitHub account/org/repo recon; commit-author emails",
    "secrets": "leaked-secret hunt queries for a target (code search needs auth — emits)",
    "traffic": "Tranco popularity rank; an UNRANKED 'established' site contradicts itself",
    "sharelink": "expand a share/short link and read the sharer-identity parameters",
    "docleak": "build document/leak-hunt queries across 18 hosts (emitted, never run)",
    "icp": "ICP filing via keyless mirrors + licence-serial sibling pivot",
    "cn-corp": "PRC corporate registry chain; names every CAPTCHA/geo gate it did not pass",
    "crossref": "identifiers appearing across MORE THAN ONE case (strongest operator signal)",
    "drift": "what changed in a case between two collections",
    "signatures": "evaluate observations against analysis/signature-catalog.md",
    "email-deep": "compose the email profile from existing tools; plans the metered steps",
    "breach-deep": "same chain, breach-weighted; states what went unqueried for want of a key",
    "wifi": "WiGLE SSID geolocation (needs a WiGLE account; discloses the gap without one)",
    "gdoc": "document/image metadata for a Google Doc/Sheet/Drive URL (= docmeta)",
    "archive-harvest": "full-IOC harvest across a domain's Wayback history (= wayback-harvest)",
    "ransomware-check": "reputation check incl. ransomware victim records (= scam-check)",
    "techstack": "CMS/framework/version fingerprint (pivot_extract's tech layer)",
    "visitors": "analytics/tracker IDs — the visitor-intelligence layer of pivot_extract",
    "saas-map": "SaaS/no-code operator tokens (pivot_extract's saas_ids layer)",
    "cert-history": "historic certificate -> IP (passive SSL)",
    "dns-history": "historic DNS/analytics records from the archive",
    "webpivot": "the flagship verb — collect pivot artifacts from one page (= pivot-extract)",
    "iban": "validate + decompose a bank account as a selector (mod-97)",
    "redact": "strip PII from a document before sharing",
    "stealer-log": "triage a folder of infostealer logs; operator-vs-victim verdict",
    "snapshots": "list/fetch archived Wayback snapshots (= wayback-fetch)",
    "query": "build advanced search-operator queries for an indicator",
    "dork-sweep": "zero-auth dork sweep (same builder as /query)",
    "stats": "KB counts and coverage statistics",
    "case": "run the full pipeline on a seed (= pipeline)",
    "sweep": "multi-vector recon on any target type (= pipeline)",
    "kb": "query the KB (--stats/--entity/--cluster/--shared)",
    "recall": "\"seen this seed before?\" — query.py --entity fallback",
    "kb-stats": "KB stats (positional root)",
    "risk": "score a case for NRD / bulletproof-hosting / money-trail",
    "reference": "curated FP-control ledger (add/check/search/list)",
    "cert-overlap": "TLS/SAN same-operator verdict across 2+ domains",
    "hypothesize": "generate same-operator hypotheses from the KB",
    "noise": "classify an indicator as shared-infra noise vs signal",
    "operators": "confirmed-operator ledger (add/list/find)",
    "calibration": "confidence-calibration ledger (record/resolve/score/list)",
    "convergence": "case stop-condition (snapshot/status)",
    "domains": "per-domain attribution table for a case",
    "victims": "infer the ACCESS VECTOR from the victim set (+demography)",
    "mirrors": "keep the duplicated denylists in step (--write/--union)",
    "ingest": "ingest a pivot_extract JSON into the shared KB",
    "ingest-report": "harvest IOCs from a finished report into a case",
    "ingest-rwhois": "ingest reverse-WHOIS results into the KB",
    "clean": "KB hygiene sweep (dry-run; --apply to write)",
    "export-graph": "export the KB as a graph (JSON)",
    "case-store": "versioned case store (snapshot/manifest)",
    "case-index": "which case(s) is an artifact recorded in?",
    "cost": "API/LLM cost report (--all/--session/--file)",
    "api-usage": "API credit/budget usage report",
    "tool-calls": "audit what the model actually called (+ denied calls)",
    "dashboard": "loopback-only run inspector (cost, trace, tool pairing)",
    "graph-build": "build case_graph.json (input to graph/network render)",
    "graph": "IntelGraph: case graph JSON → Mermaid → PNG/SVG",
    "network": "IntelGraph: interactive network diagram render",
    "gantt": "IntelGraph: Gantt/timeline chart",
    "graphviz": "IntelGraph: render a .dot → PNG/SVG",
    "mermaid": "IntelGraph: render Mermaid → PNG/SVG",
    "report": "IntelReport: assessment .md → PDF/DOCX (house style)",
    "house-report": "case dir → IntelReport editorial PDF+DOCX (I–XI + Appendices, figures) — no LLM",
    "evidence-report": "build an evidence report / MISP export for a case",
    "timeline": "infrastructure lifecycle timeline + dated evidence ledger",
    "misp-export": "build a MISP event from the case (local only, no network)",
    "misp": "MISP: keycheck/budget/search/push (stage) /publish (IRREVERSIBLE)",
    "binary": "BinaryPivot: static IOC extraction from APK/exe/zip",
    "subenum":      "subdomain enumeration for an apex via installed subfinder/amass/assetfinder/findomain (subfinder auto-keyed from .env; --sync-only to just sync keys) → cases/<id>/subenum/<apex>.json; the frontier collects the live ones next round",
    "github":       "GitHub committer-identity harvest — user/org/repo/commit URL → .patch From: e-mails, profile + top-contributor selectors (free; GITHUB_TOKEN raises the rate limit)",
    "login-detect": "find the login / registration form (passive, free)",
    "persona": "mint a SYNTHETIC research persona (never a real identity)",
    "engage": "GATED: register / log in on a synthetic persona (outbound)",
    "engage-harvest": "read the members area behind the login",
    "engage-report": "shareable engagement write-up (no case store in it)",
    "eval": "run the engine's self-test / eval suite",
}


def _print_list():
    st = backend.status()
    print(st["line"])
    print("\nops (uv run intel.py <op> [args…]):")
    width = max(len(k) for k in DISPATCH)
    for op in DISPATCH:
        print(f"  {op:<{width}}  {BLURB.get(op, '')}")
    print(f"\n  {'cases':<{width}}  list/locate cases in the engine store ($INTEL_HOME/cases)")
    print(f"  {'mcp':<{width}}  print/--write the .mcp.json that enables Tier 1 (the server)")
    print(f"  {'list':<{width}}  this map")
    print("\nUnknown flags pass straight through to the engine script.")
    return 0


def _cmd_mcp(rest):
    """Enable Tier 1 — print (or --write) the `.mcp.json` that registers the engine's
    `intel` MCP server ("the server"), using the resolved absolute command path."""
    import json
    root, method, _ = backend.resolve()
    if not root:
        print("intel.py mcp: backend not found — cannot locate the MCP server.\n"
              "  set INTEL_HOME or see connectors/intel-backend.md.", file=sys.stderr)
        return 3
    server = os.path.join(root, "harness", "mcp-server")
    if not os.path.isfile(server):
        print(f"intel.py mcp: MCP server missing at {server}", file=sys.stderr)
        return 4
    block = {"mcpServers": {"intel": {"command": server, "args": []}}}
    payload = json.dumps(block, indent=2)
    if "--write" in rest:
        dest = os.path.join(os.getcwd(), ".mcp.json")
        if os.path.exists(dest) and "--force" not in rest:
            print(f"intel.py mcp: {dest} exists — pass --force to overwrite.", file=sys.stderr)
            return 5
        with open(dest, "w", encoding="utf-8") as f:
            f.write(payload + "\n")
        print(f"wrote {dest}\n  → restart the client so it picks up the `intel` server (Tier 1).\n"
              "  NOTE: .mcp.json holds an absolute path — keep it gitignored (local-only).")
        return 0
    exe = "✓ executable" if os.access(server, os.X_OK) else "⚠ not executable (chmod +x it)"
    print(f"MCP server: {server}  [{exe}]  (resolved via {method})")
    print("\nAdd this to the project's .mcp.json to enable Tier 1 (or run `intel.py mcp --write`):\n")
    print(payload)
    return 0


def _cmd_cases(rest):
    """List / locate cases in the engine's case store ($INTEL_HOME/cases)."""
    root, _, _ = backend.resolve()
    if not root:
        print("intel.py cases: backend not found (Tier 3).", file=sys.stderr)
        return 3
    cases_dir = os.path.join(root, "cases")
    if not os.path.isdir(cases_dir):
        print(f"no case store yet at {cases_dir}")
        return 0
    names = sorted(d for d in os.listdir(cases_dir)
                   if os.path.isdir(os.path.join(cases_dir, d)))
    # `cases --path [name]` → just print the path (for scripting)
    if rest and rest[0] == "--path":
        target = os.path.join(cases_dir, rest[1]) if len(rest) > 1 else cases_dir
        print(target)
        return 0
    # `cases <name>` → show one case's file tree
    if rest and rest[0] in names:
        base = os.path.join(cases_dir, rest[0])
        print(f"case: {rest[0]}  ({base})")
        for dp, _dn, fns in os.walk(base):
            rel = os.path.relpath(dp, base)
            for fn in sorted(fns):
                if fn == ".DS_Store":
                    continue
                p = os.path.join(rel, fn) if rel != "." else fn
                print(f"  {p}")
        return 0
    # default: list all cases with a one-line status
    print(f"cases in {cases_dir}:  ({len(names)})")
    for n in names:
        b = os.path.join(cases_dir, n)
        raw = os.path.join(b, "raw")
        nraw = len([f for f in os.listdir(raw) if f.endswith(".json")]) if os.path.isdir(raw) else 0
        marks = []
        if nraw:
            marks.append(f"{nraw} raw")
        if os.path.isfile(os.path.join(b, "shared.txt")):
            marks.append("shared")
        if any(os.path.isfile(os.path.join(b, a)) for a in ("ASSESSMENT.md", "assessment.json")):
            marks.append("assessed")
        if os.path.isdir(os.path.join(b, "report")):
            marks.append("report")
        print(f"  {n:<32} {', '.join(marks) or '(empty)'}")
    print("\n  intel.py cases <name>   file tree   ·   intel.py cases --path [name]")
    return 0


def _normalize_report_md(rest):
    """For the pandoc `report` op, hand the engine a dash-normalized copy of the
    assessment `.md` so the rendered PDF/DOCX carries plain hyphens (em/en dashes read as
    LLM-authored). The copy is written beside the original — keeping relative image paths
    valid — and the analyst's source file is never mutated. Returns (rest, temp_path|None)."""
    scripts_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if scripts_dir not in sys.path:
        sys.path.insert(0, scripts_dir)
    try:
        from cti_text_normalize import normalize_dashes
    except Exception:
        return rest, None
    for i, arg in enumerate(rest):
        if not (isinstance(arg, str) and arg.lower().endswith(".md") and os.path.isfile(arg)):
            continue
        try:
            with open(arg, "r", encoding="utf-8") as f:
                original = f.read()
        except OSError:
            return rest, None
        normalized = normalize_dashes(original)
        if normalized == original:
            return rest, None
        d = os.path.dirname(os.path.abspath(arg))
        stem = os.path.splitext(os.path.basename(arg))[0]
        tmp = os.path.join(d, f".{stem}.dashnorm.{os.getpid()}.md")
        with open(tmp, "w", encoding="utf-8", newline="\n") as f:
            f.write(normalized)
        new_rest = list(rest)
        new_rest[i] = tmp
        return new_rest, tmp
    return rest, None


def main(argv):
    dry = False
    if argv and argv[0] in ("--dry-run", "-n"):
        dry = True
        argv = argv[1:]

    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__.strip())
        return 0
    if argv[0] == "list":
        return _print_list()
    if argv[0] == "mcp":
        return _cmd_mcp(argv[1:])
    if argv[0] == "cases":
        return _cmd_cases(argv[1:])

    op, rest = argv[0], argv[1:]
    if op not in DISPATCH:
        print(f"intel.py: unknown op '{op}'. Run `intel.py list` for the map.",
              file=sys.stderr)
        return 2

    root, method, _ = backend.resolve()
    if not root:
        print("intel.py: intelligence backend not found (Tier 3 / stateless).\n"
              "  set INTEL_HOME or see connectors/intel-backend.md.\n"
              f"  '{op}' needs the engine — run it where intel_engine lives.",
              file=sys.stderr)
        return 3

    script, prefix = DISPATCH[op]
    script_abs = os.path.join(root, script)
    if not os.path.isfile(script_abs):
        print(f"intel.py: engine script missing for '{op}': {script_abs}\n"
              "  the backend resolved but this component isn't installed.",
              file=sys.stderr)
        return 4

    md_cleanup = None
    if op == "report" and not dry:
        rest, md_cleanup = _normalize_report_md(rest)

    cmd = [PY, script_abs, *prefix, *rest]
    if dry:
        # Show it exactly as it would run (cwd matters for the engine's relative paths).
        print(f"cd {root} && {' '.join(cmd)}")
        return 0
    try:
        # Run FROM the engine root so knowledge/, WebPivot/tools/… resolve.
        return subprocess.run(cmd, cwd=root).returncode
    except FileNotFoundError:
        print(f"intel.py: cannot exec {PY} — set INTEL_PY to a working interpreter.",
              file=sys.stderr)
        return 5
    except KeyboardInterrupt:
        return 130
    finally:
        if md_cleanup:
            try:
                os.unlink(md_cleanup)
            except OSError:
                pass


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
