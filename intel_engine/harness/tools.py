"""Your existing Python CLI tools, wrapped as in-process Agent-SDK tools.

Each wrapper shells out to the real script (the tools stay the source of truth)
and returns the result as a TEXT content block. NOTE: the Python `@tool` decorator
forwards only `content` and `is_error` — it does NOT forward `structuredContent`
(that needs a standalone MCP server). So the model reads the JSON as text here;
machine-validated structure is enforced separately at the final assessment via
ClaudeAgentOptions.output_format (see orchestrator.py).

ADJUST: the exact CLI flags below are the integration seam — tweak them to match
your scripts (e.g. pivot_extract's --crawl / --rotate-ua, risk_signals' options).
"""
from __future__ import annotations

import concurrent.futures
import contextvars
import datetime
import glob          # case_timeline expands a glob pattern when `inputs` arrives as one string
import json
import os
import subprocess
import sys
import threading
from typing import Any

from claude_agent_sdk import ToolAnnotations, create_sdk_mcp_server, tool

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # repo root (harness/..)
PY = sys.executable
READONLY = ToolAnnotations(readOnlyHint=True)  # lets the model batch these in parallel

# The host-collection routine + its flag/cache helpers are single-sourced in the stdlib-only
# tools/collect_core.py so the deterministic pipeline (tools/intel.py) shares the SAME collector
# invocation path without importing this SDK module. This module keeps its own thin helper names
# (below) as delegates so the rest of the file is untouched.
sys.path.insert(0, os.path.join(ROOT, "tools"))
import collect_core  # noqa: E402

# knobs (env) — cheap/isolated smoke runs without touching the real KB:
KB_DIR = os.environ.get("HARNESS_KB", "knowledge")        # e.g. HARNESS_KB=knowledge_scratch
SMOKE = bool(os.environ.get("HARNESS_NO_ENRICH"))         # skip FOFA/urlscan/WHOIS (fast, no credits)
FORCE = bool(os.environ.get("HARNESS_FORCE"))             # re-collect even if already investigated
SHOT = bool(os.environ.get("HARNESS_SCREENSHOT"))         # capture a page screenshot as visual evidence (needs browser)
NO_ARCHIVE = bool(os.environ.get("HARNESS_NO_ARCHIVE"))   # disable Wayback SPN + master ledger (evidence capture is ON by default)


_MANIFEST_LOCK = threading.Lock()   # collect_many appends the manifest from worker threads


def _utcnow() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _append_manifest(case: str, host: str, data: dict, *, reused: bool,
                     dom_path: str = "", shot_path: str = "") -> None:
    """Append one provenance row per collection to cases/<case>/evidence/manifest.jsonl — the
    evidence index answering WHERE (source URL + which enrichment services), WHEN (collected_at),
    and WHAT WAS ARCHIVED (saved DOM, screenshot, Wayback flag) for every host we touched. The
    per-pivot detail (kind/value/query) lives alongside it in master_pivots.csv (--master)."""
    meta = data.get("meta") or {}
    ev_dir = os.path.join(ROOT, "cases", case, "evidence")
    os.makedirs(ev_dir, exist_ok=True)
    row = {
        "case": case, "host": host,
        "collected_at": meta.get("collected_at"),          # when the evidence was actually gathered (UTC)
        "logged_at": _utcnow(),                            # when this manifest row was written
        "reused_cache": reused,                            # true = served from a prior run, not re-fetched
        "source_url": meta.get("source"), "final_url": meta.get("final_url"),
        "fetched_with": meta.get("fetched_with"), "recovered_via": meta.get("recovered_via"),
        "enriched_with": meta.get("enriched_with"),        # which services corroborated (crtsh/fofa/urlscan/…)
        "archived_via_wayback": meta.get("archived_via_wayback"),
        "n_pivots": len(data.get("pivots", [])),
        "dom_path": os.path.relpath(dom_path, ROOT) if dom_path and os.path.exists(dom_path) else None,
        "screenshot_path": os.path.relpath(shot_path, ROOT) if shot_path and os.path.exists(shot_path) else None,
        "ledger": os.path.join("cases", case, "evidence", "master_pivots.csv"),
    }
    with _MANIFEST_LOCK:
        with open(os.path.join(ev_dir, "manifest.jsonl"), "a", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

# CF-bypass: --render needs a playwright-capable python (the WebPivot venv); FlareSolverr needs a URL.
RENDER_PY = os.environ.get("HARNESS_RENDER_PY") or (
    _wp if os.path.exists(_wp := os.path.join(ROOT, "WebPivot", ".venv", "bin", "python3")) else PY)
FLARESOLVERR = os.environ.get("HARNESS_FLARESOLVERR")     # e.g. http://localhost:8191/v1

# reuse the KB's registrant/privacy noise filter for reverse-WHOIS triage
sys.path.insert(0, os.path.join(ROOT, "tools", "kb"))
try:
    from noise_filters import is_noise_email as _is_noise_email  # noqa: E402
except Exception:  # noqa: BLE001
    def _is_noise_email(_e: str) -> bool:
        return False

# --- egress-policy guardrail (the tradecraft-as-code seam) -------------------
# When hostile, a direct live fetch of the target is refused (pivot_extract forces
# passive= or proxy=) so the analyst's own IP never touches attacker infra.
# Two front-ends must agree on this:
#   - the SDK orchestrator flips it per-phase (orchestrator._phase: T.POLICY["hostile"] = hostile);
#   - the stdio MCP server (mcp_server.py) has no phase loop, so it inherits the default below.
# The default reads HARNESS_HOSTILE from the env at import so the MCP / Claude-Code path can
# enforce the SAME gate (export HARNESS_HOSTILE=1 for a hostile-infra session) instead of always
# defaulting to permissive — this closes the front-end drift. For a hard, un-bypassable guarantee
# still layer a PreToolUse hook / can_use_tool callback on top; this global is the shared floor.
POLICY: dict[str, bool] = {"hostile": os.environ.get("HARNESS_HOSTILE", "").strip().lower()
                           in ("1", "true", "yes", "on")}


# Thin delegates to the single-sourced helpers in collect_core (bodies live there now; these keep
# the local names so the ~40 call sites across this module are untouched).
def _host(url: str) -> str:
    return collect_core.host_of(url)


def _run(cmd: list[str], timeout: int = 180) -> subprocess.CompletedProcess:
    return collect_core.run(cmd, ROOT, timeout)


def _filter_args(script: str, args: list[str]) -> tuple[list[str], list[str]]:
    return collect_core.filter_args(PY, script, ROOT, args)


def _load_json(path: str):
    return collect_core.load_json(path)


def _load_json_str(s: str):
    try:
        return json.loads(s)
    except Exception:  # noqa: BLE001
        return None


def _find_cached_raw(host: str, exclude: str = "") -> str:
    return collect_core.find_cached_raw(ROOT, host, exclude)


# --- context governor -------------------------------------------------------
# One place that bounds how much of a tool result enters the model's context, replacing the
# four hand-placed slices that used to be the whole story (every other tool returned its full
# payload, so one pivot_extract over a large cluster could crowd the phase's own instructions
# out of the window). Budgets are DATA — references/context_budget.json (RULE 3).
#
# TRUNCATION IS NEVER SILENT. A quietly shortened result is indistinguishable from a tool that
# found less, and "found less" is how a false negative enters a case — the same reason a
# keyless run has to announce what it could not query. Every cut carries the original size,
# what was dropped, and where to read the full copy.
try:
    from wp_refs import load_ref as _load_ref, ref_path as _ref_path   # the shared RULE 3 loader
except Exception:  # noqa: BLE001 — degrade, never block a run
    def _ref_path(module_file: str, name: str) -> str:
        return os.path.join(os.path.dirname(os.path.abspath(module_file)), "references", name)

    def _load_ref(path: str, fallback: dict) -> dict:
        print(f"[tools] WARNING: wp_refs unavailable; {os.path.basename(path)} not read — "
              f"running on the minimal embedded context budget.", file=sys.stderr)
        return dict(fallback)


_CTX_FALLBACK = {
    "result_budget": {"default_chars": 12000, "large_chars": 40000, "head_fraction": 0.7,
                      "min_tail_chars": 800, "error_chars": 4000},
    "large_result_tools": ["pivot_extract", "impersonation_hunt", "fallback_probe",
                           "reverse_whois", "intelx_search", "censys"],
    "transcript_budget": {"max_total_chars": 360000, "max_tool_result_chars": 24000,
                          "keep_recent_rounds": 6},
}
_CTX = _load_ref(_ref_path(__file__, "context_budget.json"), _CTX_FALLBACK)

# The OPTIONAL parameters each handler reads via args.get(). They are not in the `@tool` schema
# (which lists only the required ones), so before this they existed nowhere the model could see —
# only inside the description prose. Strong models infer them; mid-size open-weight models mostly
# do not, and the miss is expensive rather than loud: no `passive=true` on a hostile run means the
# gate denies the call and the run burns turns. Attached to the tool objects below and read by
# BOTH schema builders (mcp_server._input_schema, openai_backend._params_schema).
_PARAMS_FALLBACK = {"optional_params": {}}
OPTIONAL_PARAMS = _load_ref(_ref_path(__file__, "tool_params.json"),
                            _PARAMS_FALLBACK)["optional_params"]

RESULT_BUDGET = dict(_CTX["result_budget"])
LARGE_RESULT_TOOLS = set(_CTX["large_result_tools"])
TRANSCRIPT_BUDGET = dict(_CTX["transcript_budget"])
# Per-run override without a code edit or a data edit (e.g. a cheap smoke run on a small model).
_BUDGET_ENV = os.environ.get("HARNESS_RESULT_CHARS")


# Which @tool is executing right now. A ContextVar (not a global) because collect_fanout runs
# several collector agents concurrently in ONE process — a plain global would let one agent's
# tool name decide another agent's budget. Set by _governed() below, read by _budget_for(), so
# every tool is governed by NAME without editing ~60 _ok() call sites.
_CURRENT_TOOL: contextvars.ContextVar = contextvars.ContextVar("harness_current_tool",
                                                               default=None)


def _budget_for(tool: str | None) -> int:
    if _BUDGET_ENV:
        try:
            return max(500, int(_BUDGET_ENV))
        except ValueError:
            pass
    name = tool or _CURRENT_TOOL.get()
    key = "large_chars" if name in LARGE_RESULT_TOOLS else "default_chars"
    return int(RESULT_BUDGET.get(key, 12000))


def _governed(t):
    """Bind a tool's NAME around its handler so _ok()/_err() inside it pick the right budget.

    Wrapping here rather than at each return keeps the governor in one place and makes it
    impossible for a NEW tool to escape it by forgetting to pass `tool=` — the failure mode
    that left this gap open before, where only four of the tools capped themselves."""
    h = getattr(t, "handler", None)
    name = getattr(t, "name", None)
    if h is None or name is None or getattr(t, "_governed", False):
        return t

    async def _wrapped(args, _h=h, _n=name):
        token = _CURRENT_TOOL.set(_n)
        try:
            return await _h(args)
        finally:
            _CURRENT_TOOL.reset(token)

    try:
        t.handler = _wrapped
        t._governed = True
    except Exception:  # noqa: BLE001 — an immutable tool object still works, just at the default budget
        pass
    return t


def _bounded(text: str, *, tool: str | None = None, budget: int | None = None,
             where: str = "") -> str:
    """Cap one tool result at its budget, keeping the HEAD and the TAIL and saying so.

    The head is kept because our JSON leads with `meta` — host, http status, capability,
    collection time — which the model needs to reason about the payload at all. The tail is
    kept because list-shaped output carries its summary/last rows at the end. What disappears
    is the middle, and the marker names its exact size so the model can ask for it narrowly
    instead of assuming the tool came back empty."""
    text = text if isinstance(text, str) else str(text)
    limit = budget or _budget_for(tool)
    if len(text) <= limit:
        return text
    head_n = max(1, int(limit * float(RESULT_BUDGET.get("head_fraction", 0.7))))
    tail_n = max(int(RESULT_BUDGET.get("min_tail_chars", 800)), limit - head_n)
    head_n = max(1, limit - tail_n)
    dropped = len(text) - head_n - tail_n
    marker = (
        f"\n\n… ⚠️ RESULT TRUNCATED TO FIT THE CONTEXT BUDGET — "
        f"{len(text):,} chars → {head_n + tail_n:,} (head {head_n:,} + tail {tail_n:,}); "
        f"{dropped:,} chars omitted from the MIDDLE.\n"
        f"This is a context cut, NOT the tool's full output and NOT evidence of absence — "
        f"do not report the omitted portion as 'nothing found'.\n"
        + (f"Full result on disk: {where}\n" if where else "")
        + f"To see the omitted part, re-run narrowed (one host / one kind / a smaller limit) "
          f"or raise HARNESS_RESULT_CHARS.\n… \n\n"
    )
    return text[:head_n] + marker + text[-tail_n:]


def _err(text: str, *, tool: str | None = None) -> dict[str, Any]:
    return {"content": [{"type": "text",
                         "text": _bounded(text, tool=tool,
                                          budget=int(RESULT_BUDGET.get("error_chars", 4000)))}],
            "is_error": True}


def _ok(text: str, *, tool: str | None = None, where: str = "") -> dict[str, Any]:
    return {"content": [{"type": "text", "text": _bounded(text, tool=tool, where=where)}]}


# ---------------------------------------------------------------- COLLECT tools
@tool(
    "pivot_extract",
    "Extract pivot artifacts and write the JSON into the case. `url` may also be a local path to a "
    "victim's saved email (`.eml`): it is parsed to the HTML body so every HTML-side extractor runs "
    "over what the funnel actually SENT, plus header/CDN-derived selectors (sender domains, the "
    "sending platform) that emit pivots like any other artifact — the first hop of the funnel, "
    "which no live fetch of the landing page can recover. `url` may be a URL/host "
    "(domainPivot: favicon hash, tracking/analytics IDs, wallets, emails, third-party infra, plus "
    "the full HTTP request/response headers and an active CORS probe — a foreign-Origin GET+preflight "
    "that reads Access-Control-Allow-Origin: any LITERAL origin the server trusts becomes a "
    "cors_allowed_origin pivot exposing backend/API/sibling hosts absent from the HTML, and a "
    "reflect-any + Allow-Credentials misconfig is flagged; plus a `dig MX` mail-provider check — "
    "classifies Google Workspace / Microsoft 365 / Zoho / custom self-hosted MX, turns a custom MX "
    "host into a mail_server pivot and an M365 routing host into an m365_tenant pivot, and flags a "
    "no-MX domain as a throwaway/parked tell; and reads SPF + DMARC (apex/_dmarc TXT) — custom SPF "
    "includes and ip4/ip6 senders become spf_include/mail_sender_ip pivots, and DMARC rua/ruf "
    "addresses not at a monitoring vendor become dmarc_contact attribution pivots; plus the ASSET "
    "layer, which is what makes an SPA/white-label kit readable — it fetches the page's OWN JS "
    "bundles (config/env-named files and hashed build artifacts first, known libraries skipped) and "
    "re-runs every extractor over the bundle source, because on a modern kit the shell HTML is empty "
    "and the operator's config lives only there: an off-apex api_endpoint / websocket_endpoint (the "
    "backend the front end was compiled against — the strongest same-operator link in a white-label "
    "kit, since every front rotates but the backend does not), build_env:<KEY> tokens inlined by the "
    "bundler (a VUE_APP_BRAND/REACT_APP_TENANT value is the platform naming its own customer — same "
    "value = same tenant, same KEY with a different value = same PLATFORM not same operator), and a "
    "js_bundle_sha256 kit fingerprint that survives a favicon/DOM re-skin; from those same "
    "already-fetched bundles it also recovers the SPA ROUTE TABLE (Vue/React/Angular route "
    "literals, Next.js sortedPages/__NEXT_DATA__) at ZERO extra requests and with no path "
    "brute-forcing — a spa_route_signature (sha256 over the sorted route set: an identical route "
    "inventory elsewhere = the same compiled app, same-KIT not same-operator), plus spa_route:admin "
    "leads (the operator panel the public funnel never links to) and spa_route:funnel leads "
    "(deposit/withdraw/KYC/referral — the scam's mechanics, read without walking the funnel); "
    "discovered routes are NEVER fetched, they are leads for the analyst to judge; it then follows "
    "sourceMappingURL to the .js.map for dev_username / dev_project / dev_path — the operator's own "
    "build machine and internal project name, which survive every re-brand; and it reads the fixed "
    "list of published policy files (robots.txt, sitemap.xml, ads.txt, app-ads.txt, security.txt, "
    "humans.txt, apple-app-site-association) yielding adstxt_publisher (an owner-registered AdSense "
    "pub- account, Tier-A like a GSC/GA4 token), apple_team_id + ios_bundle_id, security_contact and "
    "robots_disallow leads. All of it is free/keyless and on by default; disable with "
    "no_assets=true / no_well_known=true, or cap the bundle count with assets_max=<N>); plus the "
    "DOCUMENT/IMAGE METADATA layer, which reads the files the site HOSTS rather than the page — "
    "it downloads the linked PDFs (the 'licence', 'certificate', 'prospectus') and the site's own "
    "images and parses /Info + XMP + EXIF out of them. A page is re-skinned in minutes, but nobody "
    "re-exports the PDF when the brand changes, so these outlive every cosmetic rotation: "
    "doc_author (a real name or OS account from /Author, EXIF Artist or XPAuthor — not copyable "
    "by a stranger), doc_xmp_docid (an XMP DocumentID is minted per SOURCE document, so the same "
    "id on two domains is literally the same file — near-decisive same-operator), doc_copyright, "
    "doc_gps (coordinates from an unstripped photo), doc_camera, doc_producer/doc_software (the "
    "SHOP that made the file — same-KIT until corroborated), and media_sha256. Values naming a "
    "common TOOL or a DEFAULT account (Microsoft Word, Photoshop, Canva, 'Windows User') are "
    "recorded as context but NEVER clustered on — base-rate rule, tunable in "
    "references/docmeta.json. Note that an EMPTY result is the normal case (most CMS/CDN "
    "pipelines strip EXIF automatically) and is NOT evidence of deliberate sanitising. Free and "
    "keyless but it costs extra requests TO THE TARGET, so disable with no_docmeta=true or cap it "
    "with docmeta_max=<N>) OR a "
    "bare IP (IPPivot: passive IP recon — IPinfo ASN/abuse, FOFA ip= ports/services/co-hosted "
    "domains, Shodan host, dig MX/NS/TXT/PTR; a shared CDN/hosting IP is marked information not a "
    "same-operator pivot, and its ASN is banked to references/asn_registry.json. It also flags "
    "MISCONFIG TRIAGE leads read passively from the FOFA banner — an internal/RFC1918/loopback "
    "address leaking into the public result (a dual-homed operator box exposing its internal "
    "topology) or an ANONYMOUS-FTP service — as an ip:misconfig pivot; these are FLAGS only, the "
    "tool never auto-connects). If ALREADY "
    "investigated (a pivot JSON exists in any case), it returns the cached data instead of "
    "re-collecting — pass force=true to refresh. `url` may also be a LOCAL PATH: a saved HTML file, "
    "or a victim's saved .eml — the email is parsed to its HTML body (so every extractor runs over "
    "what the funnel actually sent) plus header selectors: the Return-Path/From/DKIM sender domain "
    "(the operator's own sending infra in a low-effort scam → email:sender_domain, or email:sending_infra "
    "when it is a public ESP), and embedded image URLs (a logo on a multi-tenant CDN under a per-brand "
    "path is a fleet selector → email:image_url). For HOSTILE targets a direct live fetch is "
    "refused — pass proxy='<cidr>' to rotate egress, or passive=true with url set to an "
    "already-saved/archived HTML file (captured out-of-band via Wayback/urlscan).",
    {"url": str, "case": str},  # force/passive:bool, proxy:str are optional -> read via args.get()
)
async def pivot_extract(args: dict[str, Any]) -> dict[str, Any]:
    res = collect_one(args["url"], args["case"], hostile=POLICY["hostile"],
                      passive=args.get("passive", False), proxy=args.get("proxy"),
                      force=bool(args.get("force")),
                      no_assets=bool(args.get("no_assets")),
                      no_well_known=bool(args.get("no_well_known")),
                      assets_max=args.get("assets_max"),
                      no_docmeta=bool(args.get("no_docmeta")),
                      docmeta_max=args.get("docmeta_max"))
    if res.get("error"):
        return _err(res["error"])
    blob = json.dumps(res.get("data") or {}, ensure_ascii=False)
    # No hand-placed slice here any more: the governor applies pivot_extract's LARGE budget and,
    # if it has to cut, says so and names the raw JSON — a silent `blob[:6000]` looked identical
    # to a host that simply had fewer pivots.
    raw_path = os.path.join("cases", args.get("case", ""), "raw", res["host"] + ".json")
    if res["reused"]:
        return _ok(f"ALREADY INVESTIGATED — reused cached pivot for {res['host']} "
                   f"({res['n_pivots']} pivots); NOT re-collected. force=true to refresh.\n{blob}",
                   where=raw_path)
    return _ok(f"Extracted {res['n_pivots']} pivots from {res['host']}{res['note']}\n"
               f"DOM saved for manual review: {res['dom']}\n{blob}", where=raw_path)


def collect_one(url: str, case: str, *, hostile: bool = False, passive: bool = False,
                proxy: str | None = None, force: bool = False, no_assets: bool = False,
                no_well_known: bool = False, assets_max: int | None = None,
                no_docmeta: bool = False, docmeta_max: int | None = None) -> dict[str, Any]:
    """Collect ONE host end-to-end (cache-reuse → live fetch + enrichment → evidence capture →
    manifest) via the shared, single-sourced collect_core.collect_host — the SAME routine the
    deterministic pipeline (tools/intel.py) delegates to. This wrapper only supplies the harness's
    config (env knobs + the WebPivot-shim collector + the evidence-manifest callback). Sync + safe
    to fan out across threads via collect_many. Returns a summary dict, never raises."""
    # The asset (JS bundles / source maps / well-known) and document-metadata layers are ON by
    # default in pivot_extract; these knobs only ever turn them DOWN, so a caller can shrink the
    # target footprint. They ride as extra_flags because collect_core.filter_args probes the
    # collector's --help and drops whatever it does not accept — surfacing every dropped flag
    # (RULE 4) rather than aborting the collection.
    extra: list[str] = []
    if no_assets:
        extra.append("--no-assets")
    if no_well_known:
        extra.append("--no-well-known")
    if assets_max is not None:
        extra += ["--assets-max", str(int(assets_max))]
    if no_docmeta:
        extra.append("--no-docmeta")
    if docmeta_max is not None:
        extra += ["--docmeta-max", str(int(docmeta_max))]
    return collect_core.collect_host(
        url, case,
        root=ROOT, py=PY, render_py=RENDER_PY,
        collector=os.path.join(ROOT, "WebPivot", "tools", "pivot_extract.py"),
        hostile=hostile, passive=passive, proxy=proxy,
        force=(FORCE or force), smoke=SMOKE, no_archive=NO_ARCHIVE, want_shot=SHOT,
        flaresolverr=FLARESOLVERR, manifest_cb=_append_manifest, extra_flags=extra)


def collect_many(seeds: list[str], case: str, *, hostile: bool = False,
                 max_workers: int = 8) -> list[dict[str, Any]]:
    """Fan collect_one across `seeds` concurrently (mechanical, no LLM) — the Phase-3 collector
    that scales to a big seed set without blowing one model session's context/turn budget. Same
    single-sourced fan-out (collect_core.collect_many) the deterministic pipeline uses; this
    wrapper only supplies the harness's config + evidence-manifest callback."""
    return collect_core.collect_many(
        seeds, case, max_workers=max_workers,
        root=ROOT, py=PY, render_py=RENDER_PY,
        collector=os.path.join(ROOT, "WebPivot", "tools", "pivot_extract.py"),
        hostile=hostile, force=FORCE, smoke=SMOKE, no_archive=NO_ARCHIVE,
        want_shot=SHOT, flaresolverr=FLARESOLVERR, manifest_cb=_append_manifest)


def ingest(case: str) -> tuple[bool, str]:
    """Ingest a case's raw pivot JSON into the KB (sync). Run once after collect_many."""
    raw = os.path.join(ROOT, "cases", case, "raw")
    files = ([os.path.join(raw, f) for f in os.listdir(raw) if f.endswith(".json")]
             if os.path.isdir(raw) else [])   # skip .DS_Store and other non-pivot files
    if not files:
        return False, f"no raw pivot JSON in {raw}"
    r = _run([PY, os.path.join("tools", "kb", "ingest_webpivot.py"), "--kb", KB_DIR, *files])
    return r.returncode == 0, (r.stdout + r.stderr) or "ingested"


@tool(
    "fallback_probe",
    "LAST-RESORT probe — call this when pivot_extract returns ZERO/near-zero pivots or an "
    "empty-favicon/parked/NXDOMAIN page, i.e. WHOIS+FOFA+urlscan all came back empty. Never end "
    "a seed on a silent 'nothing found'. Keyless sweep of the corners that survive a dead front "
    "page: crt.sh certs (SAN-sibling domains = strongest same-owner link), the full Wayback "
    "capture TIMELINE (parked-today was often a live scam last year), archive.today mementos, "
    "ready-to-run search dorks, and the local KB (already known/attributed?). Returns a VERDICT: "
    "PIVOTABLE (a lead survived) or NO-PIVOT-YET (genuinely cold + explicit next steps).",
    {"domain": str},
    annotations=READONLY,
)
async def fallback_probe(args: dict[str, Any]) -> dict[str, Any]:
    r = _run([PY, os.path.join("tools", "fallback_probe.py"), _host(args["domain"]),
              "--kb", KB_DIR], timeout=120)
    return {"content": [{"type": "text", "text": r.stdout or r.stderr or "probe produced no output"}],
            "is_error": r.returncode != 0}


@tool(
    "impersonation_hunt",
    "Hunt IMPERSONATION / typosquat / lookalike domains of a seed — not the one page, but the "
    "domains an operator would register to mimic it. Three moves: (1) TYPOSQUAT permutations of "
    "the brand label (omission/insertion/adjacent-key/transposition/homoglyph/hyphenation/"
    "combosquat), (2) a TLD SWEEP of the exact label across a curated scam-heavy TLD list, (3) a "
    "KEYWORD HUNT for every domain whose NAME contains the label via certificate transparency "
    "(crt.sh identity LIKE). Candidates are then existence-checked with live DNS, so the output "
    "SEPARATES confirmed/registered lookalikes (with DNS/CT evidence — each an "
    "impersonation:candidate pivot: run pivot_extract on it and compare) from an unregistered "
    "monitoring watchlist. FREE by default (crt.sh + DNS, zero credits); pass fofa=true / "
    "urlscan=true for the metered cert=/page.domain keyword sweeps. Does NOT live-fetch the "
    "lookalike infra (opsec). Writes the result into the case's raw/ so kb_ingest clusters "
    "lookalikes with the rest of the case's web infrastructure.",
    {"domain": str, "case": str},  # fofa/urlscan:bool, max:int optional -> args.get()
)
async def impersonation_hunt(args: dict[str, Any]) -> dict[str, Any]:
    host = _host(args["domain"])
    case = args["case"]
    raw_dir = os.path.join(ROOT, "cases", case, "raw")
    os.makedirs(raw_dir, exist_ok=True)
    out = os.path.join(raw_dir, host + ".impersonation.json")
    cmd = [PY, os.path.join("WebPivot", "tools", "pivot_extract.py"), host,
           "--hunt-impersonation", "--pretty", "-o", out, "--case", case]
    if args.get("fofa"):
        cmd += ["--hunt-fofa"]
    if args.get("urlscan"):
        cmd += ["--hunt-urlscan"]
    if args.get("max"):
        cmd += ["--hunt-max", str(int(args["max"]))]
    r = _run(cmd, timeout=240)
    data = _load_json(out)
    if data is None:
        return _err(f"impersonation_hunt failed for {host}: {(r.stderr or '')[-500:]}")
    art = (data.get("artifacts") or {}).get("impersonation") or {}
    blob = json.dumps(data, ensure_ascii=False)
    return _ok(f"ImpersonationHunt on {host}: generated {art.get('generated', 0)} candidates → "
               f"{art.get('existing_count', 0)} confirmed lookalikes (DNS/CT), "
               f"{art.get('candidate_count', 0)} on the monitoring watchlist. "
               f"Written to {os.path.relpath(out, ROOT)} for kb_ingest.\n{blob}",
               where=os.path.relpath(out, ROOT))


@tool(
    "domain_liveness",
    "Is this host actually SERVING the operator's content? Decides by READING THE PAGE plus DNS, "
    "never by the HTTP status code alone — the guardrail in front of every 'is it still up' "
    "claim. Two errors it exists to stop, both of which corrupt a case silently. (1) 200 IS NOT "
    "ALIVE: a registrar parking page, a fresh 'Welcome to nginx' default page, a host's 'Account "
    "Suspended' notice and a soft-404 all return HTTP 200 with a full HTML document, and "
    "collecting pivots off one of those harvests a template shared by millions of unrelated "
    "domains — which is how a parking favicon becomes a fifty-domain 'operator cluster' that "
    "isn't one. (2) 404/403 IS NOT DEAD: the server ANSWERED, so the name is registered, "
    "resolving and pointed at infrastructure someone controls — only that path is gone, or we "
    "specifically are being refused (allowlist / geo-fence / cloaking). A Cloudflare interstitial "
    "returns state='blocked' with live=null: the page was never seen, which is absence of RECORD, "
    "not evidence about the target. States: live · parked · default_page · suspended · soft_404 · "
    "not_found · forbidden · blocked · empty · redirected_offsite · server_error · no_http · "
    "unresolved. EVERY state except live and unresolved sets reuse_watch=true, meaning the name "
    "is STILL CONTROLLED and can be flipped to live content later (operators park names between "
    "campaigns, and rebuild after a takedown while keeping the domain) — put those on the "
    "re-check list, do not discard them. Only NXDOMAIN evidences a dead name. Pass "
    "domain=<host|url>; case=<ID> to classify from the ALREADY-COLLECTED pivot JSON offline "
    "(no new request to the target — use this on hostile infra).",
    {"domain": str},   # case:str, offline:bool, timeout:int optional -> args.get()
    annotations=READONLY,
)
async def domain_liveness(args: dict[str, Any]) -> dict[str, Any]:
    target = str(args["domain"])
    host = _host(target)
    script = os.path.join("WebPivot", "tools", "wp_liveness.py")

    # Offline path: classify from the pivot JSON we already hold — no packet to the target.
    raw = ""
    if args.get("case"):
        cand = os.path.join(ROOT, "cases", str(args["case"]), "raw", host + ".json")
        raw = cand if os.path.exists(cand) else ""
    if not raw and args.get("offline"):
        raw = _find_cached_raw(host)
    if raw:
        code = ("import json,sys;sys.path.insert(0,'WebPivot/tools');import wp_liveness;"
                "print(json.dumps(wp_liveness.from_pivot_result("
                "json.load(open(sys.argv[1],encoding='utf-8'))),ensure_ascii=False))")
        r = _run([PY, "-c", code, raw], timeout=60)
        v = _load_json_str(r.stdout or "")
        if v is None:
            return _err(f"domain_liveness (offline) failed for {host}: {(r.stderr or '')[-400:]}")
        return _ok(f"LIVENESS {host} (offline, from the stored capture — no request sent)\n"
                   f"{json.dumps(v, ensure_ascii=False, indent=2)}")

    if POLICY.get("hostile"):
        return _err(f"domain_liveness refused: this run is HOSTILE and a live probe would touch "
                    f"attacker infrastructure from the analyst's own IP. Collect first "
                    f"(pivot_extract with passive/proxy), then re-run with case=<ID> to classify "
                    f"the stored capture offline.")
    cmd = [PY, script, target, "--json"]
    if args.get("timeout"):
        cmd += ["--timeout", str(int(args["timeout"]))]
    r = _run(cmd, timeout=120)
    v = _load_json_str(r.stdout or "")
    if not v:
        return _err(f"domain_liveness failed for {host}: {(r.stderr or '')[-400:]}")
    return _ok(f"LIVENESS {host}\n{json.dumps(v, ensure_ascii=False, indent=2)}")


@tool(
    "search_pivot",
    "Multi-engine SEARCH-ENGINE pivot for an indicator — the general-web complement to FOFA/"
    "PublicWWW (which only see served HTML). Takes ANY indicator and auto-detects one of four "
    "KINDS: 'domain' (footprint + off-site mentions + related: sites), 'handle' (a username/alias "
    "— e.g. a Telegram/Discord/forum handle: emits dox-index, market/staff and cross-platform "
    "dork context PLUS direct t.me/telegram.im profile and telemetr.io/tgstat ANALYTICS-MIRROR "
    "URLs that expose a channel's bio, admin list and first-seen date the app hides), 'discord_id' "
    "(a numeric snowflake — decodes the account-creation date LOCALLY and emits the discord user-"
    "lookup mirrors), and 'keyword' (a slogan/tracking-ID/wallet — exact string + bilingual scam/"
    "fraud context + paste/code leaks). It emits ready-to-open, URL-encoded result URLs + the raw "
    "dork queries across a switchable engine set (Google / Yandex / DuckDuckGo / Bing / Brave). It "
    "does NOT scrape (SERPs are bot-walled) — FIRE the queries with Claude Code's WebSearch "
    "(single-engine but free) and/or WebFetch the duckduckgo html URL (the one a plain fetch can "
    "read; Google/Yandex bot-wall WebFetch), open the `directories` URLs directly, extract "
    "candidate hosts/handles from the results, and feed the NEW ones back into pivot_extract to "
    "close the keyword→search→infrastructure loop. Pass engines='google,yandex,duckduckgo' to pick "
    "engines; kind='domain'|'keyword'|'handle'|'discord_id' to override auto-detection.",
    {"indicator": str},  # engines:str (comma list), kind:str optional -> args.get()
    annotations=READONLY,
)
async def search_pivot(args: dict[str, Any]) -> dict[str, Any]:
    cmd = [PY, os.path.join("tools", "search_pivot.py"), args["indicator"]]
    if args.get("engines"):
        cmd += ["--engines", str(args["engines"])]
    if args.get("kind"):
        cmd += ["--kind", str(args["kind"])]
    r = _run(cmd, timeout=30)
    if r.returncode != 0:
        return _err(r.stderr or "search_pivot failed")
    return _ok(r.stdout or "search_pivot produced no output")


@tool(
    "kb_ingest",
    "Ingest a case's raw pivot JSON into the knowledge base so it becomes correlatable. "
    "Run this after pivot_extract; a run that isn't ingested is invisible to correlation.",
    {"case": str},
)
async def kb_ingest(args: dict[str, Any]) -> dict[str, Any]:
    ok, msg = ingest(args["case"])
    if not ok and msg.startswith("no raw"):
        return _err(msg)
    return {"content": [{"type": "text", "text": msg or "ingested"}], "is_error": not ok}


def collect_binary(target: str, case: str | None = None, keep: str | None = None,
                   timeout: int = 240) -> dict[str, Any]:
    """Static IOC + packer/protector extraction from a scam-funnel binary (APK/exe/installer/zip)
    via BinaryPivot/analyze_artifact.py — the file-half sibling of collect_one. When `case` is set,
    the WebPivot-shaped JSON is written to cases/<case>/raw/<host>.json so kb_ingest folds the app's
    signing cert / backend host / firebase tenant / named protector into the SAME cluster as the web
    infra. Returns a summary dict, never raises."""
    import re
    import tempfile
    if POLICY["hostile"] and re.match(r"^https?://", target, re.I):
        return {"ok": False, "leads": "", "saved": None, "host": None,
                "error": (f"BLOCKED by egress policy: refusing a direct download of {target} on "
                          "hostile infra (it would touch attacker infra from your IP). Pull it from "
                          "non-attributable egress (research VPS/VPN) and re-call with the LOCAL path.")}
    script = os.path.join("BinaryPivot", "tools", "analyze_artifact.py")
    raw_dir = os.path.join(ROOT, "cases", case, "raw") if case else None
    if raw_dir:
        os.makedirs(raw_dir, exist_ok=True)

    def _unlink(p):
        try:
            os.unlink(p)
        except OSError:
            pass

    # Put the temp JSON on the SAME filesystem as its final home (the case raw dir) so the rename
    # is atomic and never cross-device; with no case it's a throwaway we delete after reading.
    fd, tmp_out = tempfile.mkstemp(suffix=".json", prefix="binpivot_", dir=raw_dir)
    os.close(fd)
    cmd = [PY, script, target, "--leads", "-o", tmp_out]
    if case:
        cmd += ["--case", case]
    keep_dir = keep or (os.path.join(ROOT, "cases", case, "bin") if case else None)
    if keep_dir:
        cmd += ["--keep", keep_dir]
    r = _run(cmd, timeout=timeout)
    data = _load_json(tmp_out)
    if data is None:
        _unlink(tmp_out)
        return {"ok": False, "leads": "", "saved": None, "host": None,
                "error": f"analyze_artifact failed for {target}: {(r.stderr or '')[-500:]}"}
    host = (data.get("meta") or {}).get("host") or "artifact"
    saved = None
    if case:
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", host)[:120] or "artifact"
        saved = os.path.join(raw_dir, safe + ".json")
        try:
            os.replace(tmp_out, saved)
        except OSError:
            saved = tmp_out          # same-fs replace should not fail; keep the temp copy if it does
    else:
        _unlink(tmp_out)             # no case → ephemeral; the leads text is the deliverable
    prot = ((data.get("artifacts") or {}).get("binary") or {}).get("protection") or {}
    return {"ok": not data.get("error"), "error": data.get("error"), "leads": r.stdout or "",
            "saved": saved, "host": host, "n_pivots": len(data.get("pivots", [])),
            "packed": bool(prot.get("packed") or prot.get("obfuscated"))}


@tool(
    "analyze_artifact",
    "Static IOC + PACKER/obfuscation extraction from the FILE half of a scam funnel — a sideloaded "
    "APK/AAB, a desktop 'trading terminal' .exe/.msi/.dmg, or a bundled .jar/.zip (BinaryPivot). "
    "`target` is a LOCAL path or an http(s) URL. Hashes it, then pulls the operator-clustering "
    "identifiers that survive re-skinning: APK signing-cert SHA-256 (strongest same-developer link), "
    "package name + sensitive permissions, embedded backend/C2 hosts + IP:port, Firebase/appspot "
    "tenant, S3 buckets, crypto wallets, Telegram/WhatsApp handles — PLUS a packer/protector triage "
    "(entropy + section/member signatures: UPX, VMProtect, Themida, NSIS/Inno self-extractors, and "
    "the Android app-protectors Qihoo Jiagu / Tencent Legu / Bangcle / Ijiami…) that EXPLAINS a thin "
    "string sweep and routes a protected sample to a dynamic sandbox. When case=<ID> is given the "
    "WebPivot-shaped JSON is written to cases/<ID>/raw/<host>.json so kb_ingest folds the app's "
    "cert/backend/firebase/protector into the SAME cluster as the web infra. For HOSTILE targets a "
    "direct URL download is refused — pull it from non-attributable egress and pass the local path.",
    {"target": str},   # case:str, keep:str optional via args.get()
)
async def analyze_artifact(args: dict[str, Any]) -> dict[str, Any]:
    res = collect_binary(str(args["target"]), case=args.get("case"), keep=args.get("keep"))
    if res.get("error") and not res.get("leads"):
        return _err(res["error"])
    head = f"Analyzed {res['host']} — {res.get('n_pivots', 0)} pivots" \
           + (" · ⚠ PACKED/PROTECTED (thin static IOCs are expected — consider a sandbox)"
              if res.get("packed") else "")
    if res.get("saved"):
        head += f"\nJSON saved: {res['saved']}  → run kb_ingest(case={args['case']}) to correlate."
    else:
        head += "\n(JSON not persisted — pass case=<ID> to save it into the case for kb_ingest.)"
    return _ok(head + "\n\n" + (res.get("leads") or ""))


# ---------------------------------------------------------------- ANALYZE tools
@tool(
    "kb_cluster",
    "Peers of ONE domain — the domains sharing an indicator with it (its cluster neighborhood). "
    "PREFER this over kb_query_shared: it returns only the seed's subgraph, not the whole KB, so "
    "it is far cheaper.",
    {"domain": str},
    annotations=READONLY,
)
async def kb_cluster(args: dict[str, Any]) -> dict[str, Any]:
    r = _run([PY, os.path.join("tools", "kb", "query.py"),
              "--kb", KB_DIR, "--cluster", _host(args["domain"])])
    return {"content": [{"type": "text", "text": r.stdout or r.stderr or "no peers"}],
            "is_error": r.returncode != 0}


@tool(
    "kb_entity",
    "One entity's facts + edges + provenance (a domain, email, indicator, or operator). "
    "A focused lookup — cheaper than dumping the whole KB.",
    {"value": str},
    annotations=READONLY,
)
async def kb_entity(args: dict[str, Any]) -> dict[str, Any]:
    r = _run([PY, os.path.join("tools", "kb", "query.py"),
              "--kb", KB_DIR, "--entity", args["value"]])
    return {"content": [{"type": "text", "text": r.stdout or r.stderr or "no record"}],
            "is_error": r.returncode != 0}


@tool(
    "kb_query_shared",
    "The WHOLE-KB view: every indicator shared by >= min domains. LARGE/expensive — use only when "
    "you need the global picture; prefer kb_cluster/kb_entity for a specific seed. Read-only.",
    {"min": int},
    annotations=READONLY,
)
async def kb_query_shared(args: dict[str, Any]) -> dict[str, Any]:
    r = _run([PY, os.path.join("tools", "kb", "query.py"),
              "--kb", KB_DIR, "--shared", "--min", str(args.get("min", 2))])
    return {"content": [{"type": "text", "text": r.stdout or r.stderr}], "is_error": r.returncode != 0}


@tool(
    "risk_signals",
    "Score a case's hosts for NRD / bulletproof-hosting / money-trail risk. Read-only.",
    {"case": str},
    annotations=READONLY,
)
async def risk_signals(args: dict[str, Any]) -> dict[str, Any]:
    r = _run([PY, os.path.join("tools", "kb", "risk_signals.py"), "--case", args["case"]])
    return {"content": [{"type": "text", "text": r.stdout or r.stderr}], "is_error": r.returncode != 0}


_REVERSE_FLAG = {"email": "--reverse-email", "name": "--reverse-name", "phone": "--reverse-phone"}


def _reverse_gate(kind: str, count: int, cap: int, confirm: bool) -> tuple[str, str]:
    """Decide what to do after a reverse-WHOIS PREVIEW (cheap count, no credits). Pure — no I/O —
    so the 'preview first, ask if it's a lot' logic is unit-tested. Returns (action, reason) with
    action ∈ {'empty','confirm','purchase'}."""
    if count <= 0:
        return "empty", "0 domains — no reverse-WHOIS pivot here"
    if count > cap and not confirm:
        noise = {"phone": "a shared registrar/reseller phone stamped on many unrelated domains",
                 "email": "a shared reseller/agency mailbox",
                 "name": "a shared registration service"}.get(kind, "a shared service")
        return "confirm", (f"{count} domains (> {cap}) — likely {noise} = NOISE, not one operator, "
                           "and pulling them all spends credits. NOT purchased. If you're sure, "
                           "re-call with confirm=true (optionally raise max_domains) to purchase.")
    return "purchase", f"{count} domains"


@tool(
    "reverse_whois",
    "Reverse-WHOIS a registrant email, name, or PHONE for HIGH-VALUE pivots. PREVIEWS FIRST (cheap "
    "count, no credits spent); if the term matches MORE than max_domains (default 150) — a shared "
    "reseller/agency/registrar term = NOISE — it STOPS and asks you to confirm rather than spending "
    "credits to pull them, so re-call with confirm=true (and optionally a higher max_domains) to "
    "purchase anyway. Refuses a privacy/registrar email outright. kind = 'email' | 'name' | 'phone'.",
    {"term": str, "kind": str},  # max_domains:int (default 150), confirm:bool — both optional
    annotations=READONLY,
)
async def reverse_whois(args: dict[str, Any]) -> dict[str, Any]:
    term = str(args["term"]).strip()
    kind = args.get("kind", "email")
    cap = int(args.get("max_domains", 150))
    confirm = bool(args.get("confirm"))
    if kind == "email" and _is_noise_email(term):
        return _err(f"'{term}' is a privacy/registrar address (shared by every domain there) — "
                    "NOT a registrant pivot. Do not reverse it.")
    flag = _REVERSE_FLAG.get(kind)
    if not flag:
        return _err(f"kind must be 'email', 'name', or 'phone' (got '{kind}').")

    def _call(mode: str):
        r = _run([PY, os.path.join("WebPivot", "tools", "whois_enrich.py"), flag, term,
                  "--search-type", "historic", "--reverse-mode", mode, "--json"], timeout=150)
        data = _load_json_str(r.stdout) or {}
        rec = (data.get("reverse_email") or data.get("reverse_name")
               or data.get("reverse_phone") or {})
        return rec, r

    # 1) PREVIEW — count only, spends no purchase credits
    rec, r = _call("preview")
    if not rec or rec.get("error"):
        return _err(f"reverse-WHOIS preview failed for '{term}': "
                    f"{rec.get('error') or (r.stderr or '')[-300:]}")
    count = rec.get("count", 0)
    action, reason = _reverse_gate(kind, count, cap, confirm)
    if action == "empty":
        return _ok(f"'{term}' ({kind}) → {reason}.")
    if action == "confirm":
        return _ok(f"⚠ '{term}' ({kind}): {reason}")
    # 2) PURCHASE — small enough, or explicitly confirmed
    rec, r = _call("purchase")
    if not rec or rec.get("error"):
        return _err(f"reverse-WHOIS purchase failed for '{term}': "
                    f"{rec.get('error') or (r.stderr or '')[-300:]}")
    domains = rec.get("domains") or []
    override = "  (confirmed override of the >cap gate — verify it isn't shared/bulk)" if count > cap else ""
    return _ok(f"'{term}' ({kind}) → {rec.get('count', count)} domains{override}:\n"
               + ("\n".join(domains) if domains else "(none returned)"))


@tool(
    "cert_overlap",
    "TLS certificate / SAN-overlap check across 2+ domains (comma-separated in `domains`) — a "
    "CORRELATION signal. Two domains sharing a TLS cert is near-decisive same-operator proof: SAN "
    "names are chosen by whoever controls the cert. Keyless dual-source CT (Shodan CTL + crt.sh). "
    "Returns a VERDICT: SHARED-CERT / SAN cross-cover (decisive), SIBLING-OVERLAP (certs share a "
    "third registrable domain = strong), or NO-CT-OVERLAP. Run this on candidate same-operator "
    "seeds before asserting a cluster — it either corroborates or refutes at the TLS layer.",
    {"domains": str},
    annotations=READONLY,
)
async def cert_overlap(args: dict[str, Any]) -> dict[str, Any]:
    doms = [d.strip() for d in str(args["domains"]).replace(",", " ").split() if d.strip()]
    if len({_host(d) for d in doms}) < 2:
        return _err("cert_overlap needs at least two distinct domains (comma-separated).")
    r = _run([PY, os.path.join("tools", "cert_overlap.py"), *doms], timeout=120)
    return {"content": [{"type": "text", "text": r.stdout or r.stderr or "no output"}],
            "is_error": r.returncode != 0}


@tool(
    "censys",
    "Censys Platform — the SERVER-side view of a target, complementing FOFA/urlscan (which index "
    "what the page looks like). Six modes via `mode`:\n"
    "  mode='cert' + value=<leaf SHA-256> — THE high-value one, and it works on a FREE Censys "
    "plan: returns the certificate's own `names` list, i.e. EVERY hostname on that exact "
    "certificate. crt.sh gives fuzzy name overlap; this is the cert stating its own coverage, so a "
    "multi-apex name list is near-decisive same-operator evidence across brands.\n"
    "  mode='host' + value=<IP> — ASN/WHOIS org, forward+reverse DNS names, open ports, per-service "
    "banners and cert fingerprints. Free plan OK.\n"
    "  mode='webproperty' + value=<hostname[:port]> (default :443) — the cert, favicon hashes, body "
    "hash, software stack and threat labels Censys recorded for that hostname. Free plan OK.\n"
    "  mode='search' + value=<CenQL query> — reverse ANY indexed artifact (favicon MD5, body "
    "keyword, cert fingerprint). NEEDS a Censys Starter plan or above; on a FREE plan Censys 403s "
    "and this returns `skipped` together with a platform.censys.io UI link that runs the identical "
    "query by hand — use that link, do not report it as a failure.\n"
    "  mode='query' + value=<pivot value> + kind=<WebPivot pivot kind> — OFFLINE: build the CenQL "
    "for an artifact without a key and without spending anything.\n"
    "  mode='budget' (no value needed) — OFFLINE: how many of this month's Censys credits are left. "
    "Check it before a batch.\n"
    "COST — READ THIS BEFORE CALLING: Censys bills CREDITS, a FREE account gets only 100 per MONTH, "
    "they do NOT roll over, and the quota is per ACCOUNT, so overspending here removes Censys from "
    "every later case too. A lookup is 1 credit, a search 5 (and running the emitted CenQL in the "
    "web UI costs the same 5 — the UI link is not free). Use it deliberately, on the artifact that "
    "decides the question, not as a default enrichment on every host: prefer 'cert'/'host'/"
    "'webproperty' lookups over 'search', and prefer handing the analyst the 'query' CenQL over "
    "spending a search yourself. The tool refuses to exceed the monthly/per-run budget and returns "
    "`skipped` with the balance instead. Needs CENSYS_PAT; without it every mode except 'query' and "
    "'budget' returns nothing — which is a missing CREDENTIAL, never evidence about the target. "
    "Read-only.",
    {"mode": str, "value": str},  # kind:str (mode='query'), port:int (mode='webproperty') optional
    annotations=READONLY,
)
async def censys(args: dict[str, Any]) -> dict[str, Any]:
    mode, value = str(args.get("mode", "")).strip().lower(), str(args.get("value", "")).strip()
    if not value and mode != "budget":       # budget is a balance check — it has no target
        return _err("censys needs a `value` (an IP, hostname, cert SHA-256, or CenQL query).")
    script = os.path.join("WebPivot", "tools", "wp_censys.py")
    if mode == "cert":
        cmd = [PY, script, "cert", value]
    elif mode == "host":
        cmd = [PY, script, "host", value]
    elif mode == "webproperty":
        cmd = [PY, script, "webproperty", value, "--port", str(args.get("port", 443))]
    elif mode == "search":
        cmd = [PY, script, "search", value]
    elif mode == "query":
        cmd = [PY, script, "query", str(args.get("kind", "")), value]
    elif mode == "budget":
        cmd = [PY, script, "budget"]
    else:
        return _err("censys `mode` must be one of: "
                    "cert | host | webproperty | search | query | budget.")
    r = _run(cmd, timeout=120)
    return {"content": [{"type": "text", "text": r.stdout or r.stderr or "no output"}],
            "is_error": r.returncode != 0}


@tool(
    "capability_check",
    "What can this machine actually collect? Reports which optional API keys are configured and — "
    "for each one that is NOT — the exact evidence class that is unavailable and the free path that "
    "substitutes. Call it at the START of a case, and whenever a collection comes back thin. "
    "WebPivot always runs keyless, so a missing key is never an error, but it changes what a NULL "
    "result means: with no FOFA/urlscan credential the favicon and tracker reverse-lookups never "
    "ran, so 'no sibling domains' is a fact about the credentials, not about the operator. TELL THE "
    "USER when the mode is keyless/partial and say which indexes went unqueried before presenting "
    "any 'nothing found' conclusion. Optional `free_only=true` reports it as the convergence loop "
    "sees it (keys present but forbidden to spend). Offline, free, read-only.",
    {},  # free_only:bool optional
    annotations=READONLY,
)
async def capability_check(args: dict[str, Any]) -> dict[str, Any]:
    cmd = [PY, os.path.join("WebPivot", "tools", "wp_capabilities.py")]
    if args.get("free_only"):
        cmd.append("--free-only")
    r = _run(cmd, timeout=30)
    return {"content": [{"type": "text", "text": r.stdout or r.stderr or "no output"}],
            "is_error": r.returncode != 0}


@tool(
    "reference_check",
    "Check a hash/keyword against the curated fingerprint reference BEFORE trusting it as a "
    "same-operator link. Returns BENIGN (a globally common logo/CDN/CSS-framework artifact — a "
    "FALSE POSITIVE, do NOT cluster on it), SIGNAL (a distinctive fingerprint from a prior case — "
    "pivot on it, and see which case), or UNKNOWN. Pass the indicator string (e.g. favicon:123, "
    "css_hash:ab12, urlscan_resource:<h>) or a keyword. Read-only.",
    {"value": str},
    annotations=READONLY,
)
async def reference_check(args: dict[str, Any]) -> dict[str, Any]:
    val = str(args["value"])
    chk = _run([PY, os.path.join("tools", "kb", "reference.py"), "--kb", KB_DIR, "check", val])
    srch = _run([PY, os.path.join("tools", "kb", "reference.py"), "--kb", KB_DIR, "search", val])
    return _ok((chk.stdout or chk.stderr or "").rstrip() + "\n--- related reference entries ---\n"
               + (srch.stdout or "").rstrip())


@tool(
    "reference_mirrors",
    "Check (or repair) the reference DENYLISTS that are duplicated across skills. Each skill is "
    "imported standalone and cannot read another's references/, so a denylist both the collector "
    "and the ingest need is physically copied — and when the copies drift the failure is SILENT: "
    "one side filters a platform's default favicon, the other does not, and a thousand-edge false "
    "cluster reaches the knowledge base with nothing logged. Returns which mirrored groups are "
    "identical and which have drifted, with the differing values. mode='check' (default) is "
    "read-only; mode='repair' merges every copy (union — the safe direction, since a value was "
    "put there by an analyst who had a reason) and writes it back to all sides. The mirror list "
    "is declared in tests/reference_mirrors.json.",
    {},   # optional: mode ('check' | 'repair')
    annotations=READONLY,
)
async def reference_mirrors(args: dict[str, Any]) -> dict[str, Any]:
    mode = str(args.get("mode", "check")).lower()
    if mode not in ("check", "repair"):
        return _err("mode must be 'check' or 'repair'.")
    cmd = [PY, os.path.join("tools", "kb", "sync_mirrors.py")]
    if mode == "repair":
        cmd += ["--union", "--write"]
    r = _run(cmd)
    return {"content": [{"type": "text", "text": (r.stdout or r.stderr or "").rstrip()}],
            "is_error": False}


@tool(
    "reference_add",
    "Remember a fingerprint in the reference so it improves every future case. Use verdict="
    "'benign' when a hash/keyword turned out to be a common logo / CDN / CSS-framework / template "
    "default (it will be SUPPRESSED from clustering everywhere), or verdict='signal' for a "
    "distinctive hash/keyword worth watching for (a watchlist tied to this case). Give a short "
    "label; pass the case so signal provenance is kept.",
    {"value": str, "verdict": str, "label": str},  # optional: case, note, type via args.get
)
async def reference_add(args: dict[str, Any]) -> dict[str, Any]:
    verdict = str(args.get("verdict", "")).lower()
    if verdict not in ("benign", "signal"):
        return _err("verdict must be 'benign' or 'signal'.")
    cmd = [PY, os.path.join("tools", "kb", "reference.py"), "--kb", KB_DIR, "add",
           "--value", str(args["value"]), "--verdict", verdict,
           "--label", str(args.get("label", ""))]
    if args.get("case"):
        cmd += ["--case", str(args["case"])]
    if args.get("note"):
        cmd += ["--note", str(args["note"])]
    r = _run(cmd)
    return {"content": [{"type": "text", "text": r.stdout or r.stderr or "added"}],
            "is_error": r.returncode != 0}


@tool(
    "which_cases",
    "Cross-case provenance: given a domain OR an indicator string (favicon:<h>, ga:<id>, "
    "wallet:<coin>:<addr>, email:<addr>, social:<net>:<handle>), report which CASE(S) it already "
    "appears in across the cases/ store. Call this before pivoting on a known artifact — a hit "
    "means it carries prior case context (don't treat it as new); an indicator seen across "
    "MULTIPLE cases is a cross-case link worth surfacing. Read-only.",
    {"artifact": str},
    annotations=READONLY,
)
async def which_cases(args: dict[str, Any]) -> dict[str, Any]:
    r = _run([PY, os.path.join("tools", "case_index.py"), str(args["artifact"])])
    return {"content": [{"type": "text", "text": r.stdout or r.stderr or "no output"}],
            "is_error": r.returncode != 0}


@tool(
    "domain_verdict",
    "The PRIOR verdict for a domain already in the store: which CASE(S) it appears in, who it's "
    "attributed to (operator registry) + its known KB facts/edges. Call this before treating a "
    "seed as new — if it's already resolved or belongs to a known case, show that instead of "
    "re-investigating.",
    {"domain": str},
    annotations=READONLY,
)
async def domain_verdict(args: dict[str, Any]) -> dict[str, Any]:
    d = _host(args["domain"])
    op = _run([PY, os.path.join("tools", "kb", "operator_registry.py"), "find", d])
    kb = _run([PY, os.path.join("tools", "kb", "query.py"), "--kb", KB_DIR, "--entity", d])
    ci = _run([PY, os.path.join("tools", "case_index.py"), d])
    verdict = (op.stdout or "").strip() or "not attributed to any known operator"
    facts = (kb.stdout or "").strip() or "no KB record for this domain"
    cases = (ci.stdout or "").strip() or f"{d} (domain): NOT seen in any existing case."
    collected = bool(_find_cached_raw(d))
    return _ok(f"VERDICT for {d}  (pivot data on file: {'yes' if collected else 'no'})\n"
               f"[cases] {cases}\n[operator] {verdict}\n[KB] {facts}")


@tool(
    "api_usage",
    "Report LICENSED/metered API credit usage (FOFA, urlscan, WhoisXML, IPinfo, Shodan) from the "
    "ledger every collection writes. Pass case=<ID> to scope to one case, since=YYYY-MM-DD to bound "
    "by date, last=<N> to also list the most recent calls. Shows credits per provider / day / case. "
    "Read-only — use it to answer 'how many credits did this case/run cost'.",
    {},   # all optional: case, since (str), last (int) via args.get()
    annotations=READONLY,
)
async def api_usage(args: dict[str, Any]) -> dict[str, Any]:
    cmd = [PY, os.path.join("WebPivot", "tools", "api_usage.py"), "report"]
    if args.get("case"):
        cmd += ["--case", str(args["case"])]
    if args.get("since"):
        cmd += ["--since", str(args["since"])]
    if args.get("last"):
        cmd += ["--last", str(int(args["last"]))]
    r = _run(cmd)
    return {"content": [{"type": "text", "text": r.stdout or r.stderr or "no output"}],
            "is_error": r.returncode != 0}


@tool(
    "doc_metadata",
    "Download a hosted DOCUMENT or IMAGE and read the identifiers embedded inside it — the "
    "standalone form of pivot_extract's document/image layer, for a file or URL you already have "
    "(a PDF an analyst was sent, an image pulled from a Telegram channel, a file already on disk). "
    "Give it `targets` as a comma-separated list of URLs and/or local paths. Parses PDF /Info and "
    "the XMP packet, JPEG/TIFF EXIF (including GPS), and PNG tEXt/zTXt/iTXt chunks, dispatching on "
    "MAGIC BYTES not the file extension (a .jpg URL serving an error page is common). Returns "
    "every field found, plus a `pivotable` subset with the generic values removed: an Author of "
    "'Windows User' or a Producer of 'Microsoft Word' names a default or a tool, not an operator, "
    "and clustering on those fuses unrelated cases. The high-value fields are author/artist "
    "(a real name, uncopyable by a stranger), xmp_document_id (minted per SOURCE document — the "
    "same id elsewhere is literally the same file), copyright, and gps. IMPORTANT: an empty result "
    "is the NORMAL case — most CMS and CDN pipelines strip EXIF automatically — so never report "
    "absent metadata as evidence of deliberate sanitising. Read-only apart from the fetch; a URL "
    "target is an OUTBOUND request to whoever hosts it.",
    {"targets": str},
    annotations=READONLY,
)
async def doc_metadata(args: dict[str, Any]) -> dict[str, Any]:
    targets = [t.strip() for t in str(args.get("targets", "")).split(",") if t.strip()]
    if not targets:
        return _err("doc_metadata needs `targets`: a comma-separated list of URLs or file paths.")
    r = _run([PY, os.path.join("WebPivot", "tools", "wp_docmeta.py"), *targets[:12]])
    return {"content": [{"type": "text", "text": r.stdout or r.stderr or "no output"}],
            "is_error": r.returncode != 0}


@tool(
    "case_scope",
    "The case INTAKE record — what this target IS, and what claim the run is testing. READ it "
    "before collecting and WRITE it as soon as the analyst tells you any of it; every harness "
    "phase renders it into its prompt, so this is how context reaches the automated path that "
    "otherwise has nobody to ask. Call with only `case` to READ (also prints the questions to "
    "ask when nothing is set yet); pass any of target_class / purpose / claim / basis / brand / "
    "how / window / falsifier to SET it (persisted to cases/<case>/scope.json, so later rounds, "
    "a --continue resume and the other front-end inherit it). `target_class` is one of "
    "confirmed_scam · suspected_scam · threat_actor_infra · victim_host · benign_check · unknown "
    "and it decides three things: the FETCH POSTURE (threat_actor_infra means the tool gate "
    "DENIES outbound collection from this address — passive sources only), the OWNERSHIP rule "
    "(on victim_host the page's WHOIS/favicon/cert/analytics are the VICTIM's and clustering on "
    "them fuses unrelated victims into a fake operator estate), and the DISCONFIRMING checks the "
    "run must report on. `claim` is recorded as an ASSERTION WITH A SOURCE, never as a collected "
    "fact — the assessment answers it with a premise_verdict. Setting nothing is allowed: an "
    "unscoped case resolves to `unknown` under the conservative posture and the deliverable must "
    "say so. Use `no_direct_contact=true` when the analyst forbids touching the target at all, "
    "`no_spend=true` when metered credits are not authorised.",
    {"case": str},   # optional: target_class, purpose, claim, basis, brand, how, window,
                     # falsifier, no_direct_contact (bool), no_spend (bool)
    annotations=ToolAnnotations(readOnlyHint=False),   # writes cases/<case>/scope.json
)
async def case_scope(args: dict[str, Any]) -> dict[str, Any]:
    case = str(args.get("case") or "").strip()
    if not case:
        return _err("case_scope needs `case`: the case id whose scope you want to read or set.")
    setters = {"target_class": "--target-class", "purpose": "--purpose", "claim": "--claim",
               "basis": "--basis", "brand": "--brand", "how": "--how",
               "window": "--window", "falsifier": "--falsifier"}
    cmd = [PY, os.path.join("harness", "case_scope.py"),
           "set" if any(args.get(k) for k in setters) or args.get("no_direct_contact")
           or args.get("no_spend") else "show", case]
    for key, flag in setters.items():
        if args.get(key):
            cmd += [flag, str(args[key])]
    for key, flag in (("no_direct_contact", "--no-direct-contact"), ("no_spend", "--no-spend")):
        if args.get(key):
            cmd.append(flag)
    r = _run(cmd)
    return {"content": [{"type": "text", "text": r.stdout or r.stderr or "no output"}],
            "is_error": r.returncode != 0}


@tool(
    "tool_calls",
    "Read back the TOOL-CALL LEDGER — what a run actually DID, the action counterpart to "
    "api_usage (which reports what it SPENT). Every tool call on every front-end is written to "
    "cases/<case>/tool_calls.jsonl by the gate, allowed or denied, with its risk classes "
    "(outbound = touched the target from your IP, metered = spent third-party credits, mutating = "
    "wrote to the shared KB). Pass case=<ID> to scope to one case (omit for the interactive "
    "MEMORY ledger, all=true for every case), denied=true to see only what the gate BLOCKED and "
    "why, tool=<name> to follow one tool, since=YYYY-MM-DD to bound by date, last=<N> to list the "
    "most recent calls. Use it to answer 'did this run touch the target directly', 'what got "
    "blocked', 'which round introduced that KB entry'. Read-only. NOTE a missing ledger is "
    "ABSENCE OF RECORD (the case predates the gate, or nothing has run) — never report it as "
    "'the run did nothing'.",
    {},   # all optional: case, all (bool), denied (bool), tool (str), since (str), last (int)
    annotations=READONLY,
)
async def tool_calls(args: dict[str, Any]) -> dict[str, Any]:
    cmd = [PY, os.path.join("harness", "audit.py"), "report"]
    if args.get("case"):
        cmd.append(str(args["case"]))
    for flag in ("all", "denied"):
        if args.get(flag):
            cmd.append("--" + flag)
    for opt in ("tool", "since"):
        if args.get(opt):
            cmd += ["--" + opt, str(args[opt])]
    if args.get("last"):
        cmd += ["--last", str(int(args["last"]))]
    r = _run(cmd)
    return {"content": [{"type": "text", "text": r.stdout or r.stderr or "no output"}],
            "is_error": r.returncode != 0}


# ---------------------------------------------------------------- RENDER tools
@tool(
    "render_diagram",
    "RENDERING ONLY — the `IntelGraph` skill owns figure DESIGN (engine choice, encoding, when to "
    "split one hairball into several focused figures); load it if the figure needs judgement. Note "
    "this builds the graph from COLLECTED hosts only, so a case whose finding spans domains you never "
    "collected will render a misleading partial picture — check the node count against the claim, and "
    "hand-edit the emitted .mmd (then render with IntelGraph's render_mermaid.py, and pass "
    "no_figures=true to render_report so it is not overwritten) when it does not match. "
    "Turn a graph_build.py case_graph.json into an EDITABLE Mermaid diagram source (.mmd) and "
    "render it to PNG + SVG (+ thumb) via IntelGraph. Use this when you want the relationship web "
    "as a static, hand-editable figure to drop into a report — unlike render_network.py's opaque "
    "interactive HTML, the .mmd is plain text you can tweak (rename a cluster, prune a node) and "
    "re-render. Faithful encoding: node shape = entity type, node fill = Louvain cluster, operator "
    "= red anchor, edge color = evidence class (operator/kit/infra/link), dashed = inferred. "
    "Required: graph_json (path), stem (output path, no extension). Optional: title, direction "
    "(LR|TB|RL|BT), legend=true (append an edge-color legend), no_render=true (emit only the .mmd).",
    {"graph_json": str, "stem": str},
)
async def render_diagram(args: dict[str, Any]) -> dict[str, Any]:
    cmd = [PY, os.path.join("IntelGraph", "scripts", "graph_to_diagram.py"),
           str(args["graph_json"]), str(args["stem"])]
    if args.get("title"):
        cmd += ["--title", str(args["title"])]
    if args.get("direction"):
        cmd += ["--direction", str(args["direction"])]
    if args.get("legend"):
        cmd += ["--legend"]
    if args.get("no_render"):
        cmd += ["--no-render"]
    r = _run(cmd, timeout=180)
    return {"content": [{"type": "text", "text": r.stdout or r.stderr or "no output"}],
            "is_error": r.returncode != 0}


@tool(
    "case_timeline",
    "THE TEMPORAL VIEW of a case — run this before asserting any same-operator link, because a "
    "shared artifact only links two hosts if BOTH carried it at the same time. Reads the case's "
    "pivot_extract JSON (out/*.json) and extracts every dated fact: registration span "
    "(created→expires), registrant eras from WHOIS history, hosting windows from passive DNS "
    "(which IP served the name, between which dates), certificate validity windows from CT, "
    "Wayback archive spans + per-artifact presence windows, and point observations (WHOIS "
    "updates, urlscan scans, recovered snapshots). Then derives the correlations: registration "
    "cohorts, EXPIRY/renewal cohorts (aligned expiry from DIFFERENT creation dates = one payer, "
    "the billing-account tell), same-day WHOIS updates, certificate issuance batches, IP-tenancy "
    "OVERLAP (co-tenancy vs sequential tenancy of a recycled address), shared-artifact window "
    "overlap, and abandonment cohorts. Emits a swimlane figure (PNG+SVG+thumb), a "
    "<stem>_events.json evidence ledger and, with markdown=true, a paste-ready evidence table "
    "where every row carries when (UTC) + source + Admiralty grade + an ONLINE permalink "
    "(Wayback / urlscan / crt.sh / RDAP / BGP) — never a local case-store path. Required: inputs "
    "(list of JSON paths or a glob), stem (output path, no extension). Optional: title, subtitle, "
    "history (wayback_ga.py JSON paths), markdown=true, lang (en|vi), source, grading, "
    "max_certs (default 12), max_lanes (default 24), no_figure=true.",
    {"inputs": list, "stem": str},
)
async def case_timeline(args: dict[str, Any]) -> dict[str, Any]:
    inputs = args["inputs"]
    if isinstance(inputs, str):
        inputs = sorted(glob.glob(inputs)) or [inputs]
    cmd = [PY, os.path.join("IntelGraph", "scripts", "case_timeline.py"),
           *[str(i) for i in inputs], "--stem", str(args["stem"])]
    for key, flag in (("title", "--title"), ("subtitle", "--subtitle"), ("lang", "--lang"),
                      ("source", "--source"), ("grading", "--grading"),
                      ("max_certs", "--max-certs"), ("max_lanes", "--max-lanes")):
        if args.get(key):
            cmd += [flag, str(args[key])]
    hist = args.get("history")
    if hist:
        cmd += ["--history", *[str(h) for h in (hist if isinstance(hist, list) else [hist])]]
    if args.get("markdown"):
        cmd += ["--markdown"]
    if args.get("no_figure"):
        cmd += ["--no-figure"]
    r = _run(cmd, timeout=300)
    return {"content": [{"type": "text", "text": (r.stdout or "") + (r.stderr or "") or "no output"}],
            "is_error": r.returncode != 0}


@tool(
    "render_report",
    "TYPOGRAPHY ONLY — this renders a markdown file you have ALREADY written to the house structure; "
    "it does NOT make a report conformant. LOAD THE `IntelReport` SKILL FIRST and author the markdown "
    "to its contract, then call this. The skill owns the structure and the OPSEC rules; this tool only "
    "applies the LaTeX template (cover, TOC, running header/footer, figure styling, Vietnamese-safe "
    "fonts) via pandoc and emits PDF + DOCX. What the skill requires and this tool cannot supply: "
    "Executive-Summary-first Key Judgments, an early Methodology with the NATO Admiralty + ICD-203 "
    "tables, the artifact register and per-domain-profile appendices, and — critically — naming every "
    "indicator (seed domain, IPs, hashes, impersonated brands) in the BODY while keeping internal "
    "tool/vendor/case-store names out of it. Required: markdown (path), stem (output path, no "
    "extension). Optional: lang ('en'|'vi') — localises the GENERATED furniture only (cover labels, "
    "TOC title, 'Phụ lục', figure/table captions) and picks a Vietnamese-capable font; it does NOT "
    "translate the body, so write the assessment in the target language from the start and take the "
    "estimative wording verbatim from `render_report.py --glossary` (the ICD-203 scale is calibrated "
    "— a paraphrase changes what the report claims). report_ref (EXTERNAL reference shown on the "
    "cover — use this, NOT case_id, "
    "or the internal case-store id leaks onto every page), audience (technical|executive|le), title, "
    "subtitle, case_id (internal fallback only), classification (e.g. TLP:AMBER), date (YYYY-MM-DD), "
    "no_figures=true (skip figures.json regeneration — set this when the .mmd was hand-edited, else "
    "the hand-edited figure is overwritten), pdf=true / docx=true (default: both). Embed figures with "
    "a markdown image path resolvable from the markdown file's directory.",
    {"markdown": str, "stem": str},
)
async def render_report(args: dict[str, Any]) -> dict[str, Any]:
    cmd = [PY, os.path.join("IntelReport", "scripts", "render_report.py"),
           str(args["markdown"]), str(args["stem"])]
    for k, flag in (("title", "--title"), ("subtitle", "--subtitle"),
                    ("report_ref", "--report-ref"), ("audience", "--audience"),
                    ("case_id", "--case-id"), ("classification", "--classification"),
                    ("date", "--date"), ("lang", "--lang")):
        if args.get(k):
            cmd += [flag, str(args[k])]
    if args.get("no_figures"):
        cmd += ["--no-figures"]
    if args.get("pdf"):
        cmd += ["--pdf"]
    if args.get("docx"):
        cmd += ["--docx"]
    r = _run(cmd, timeout=300)
    return {"content": [{"type": "text", "text": r.stdout or r.stderr or "no output"}],
            "is_error": r.returncode != 0}


@tool(
    "email_permute",
    "Generate email CANDIDATES from a person name or a username. Call this when a case yields a "
    "real name or a handle AND you already hold a domain that matters to the case — an operator's "
    "mailbox is rarely published but is usually derivable from the local-part conventions mail "
    "hosts actually use. Pass subject (the name, e.g. 'Nguyen Van Hieu', or the handle) plus "
    "domains (comma-separated). Set username=true if the subject is a handle rather than a name. "
    "Handles family-name-first VN/CN/KR names and folds Latin letters Unicode does not decompose "
    "(Vietnamese d-stroke, Polish l-stroke, o-slash, sharp-s, dotless-i) — a generic permutator "
    "inverts first.last on a Vietnamese name and mangles the diacritics, producing addresses that "
    "look right and do not exist. CRITICAL — the output is HYPOTHESES, not findings: every row "
    "returns status='candidate' with confidence 0. Do NOT ingest them into the KB, cite them in a "
    "report, feed them to the spider-map as seeds, or contact them. Only addresses in the "
    "'promote' list have been corroborated by independent evidence and may be treated as a real "
    "email seed. verify=true adds keyless corroboration: an MX gate that drops whole domains that "
    "cannot receive mail (RFC 7505 null MX included) plus a Gravatar registration check. It NEVER "
    "probes the target's mail server over SMTP — that touches hostile infrastructure and a "
    "catch-all domain answers 250 for everything. Default domain set is what you pass; free=true "
    "adds free-mail providers and is high-noise. Read-only, no API key, no credits.",
    {"subject": str, "domains": str},  # username/verify/free:bool, max:int optional -> args.get()
    annotations=READONLY,
)
async def email_permute(args: dict[str, Any]) -> dict[str, Any]:
    cmd = [PY, os.path.join("WebPivot", "tools", "email_permute.py"), str(args["subject"])]
    for d in str(args.get("domains") or "").split(","):
        if d.strip():
            cmd += ["--domain", d.strip()]
    if args.get("username"):
        cmd += ["--username"]
    if args.get("verify"):
        cmd += ["--verify"]
    if args.get("free"):
        cmd += ["--free"]
    if args.get("order"):
        cmd += ["--order", str(args["order"])]
    if args.get("max"):
        cmd += ["--max", str(args["max"])]
    r = _run(cmd)
    return _ok(r.stdout or r.stderr or "no output")
# ---------------------------------------------------------------- convergence loop
@tool(
    "case_clusters",
    "PARTITION a case into same-operator clusters BEFORE judging it — the unit of judgment is the "
    "CLUSTER, not the case. Returns each connected component over STRONG shared indicators "
    "(boilerplate / reference-benign / over-prevalent edges excluded), the indicators binding it, "
    "and each indicator's KB-WIDE prevalence — so an indicator binding 3 domains here but sitting "
    "on 400 domains KB-wide is visibly noise, not an owner link. Judge each cluster on its own "
    "evidence: correlating 100 domains in one pass is unfocused and blows context, and it is N "
    "attribution questions, not one. Pure KB read — collects nothing, spends no credits. Writes "
    "cases/<case>/clusters.json. Optional: min (domains an indicator must bind, default 2), "
    "max_prevalence (KB-wide count above which an indicator is generic noise, default 8).",
    {"case": str},
    annotations=READONLY,
)
async def case_clusters(args: dict[str, Any]) -> dict[str, Any]:
    cmd = [PY, os.path.join("tools", "intel.py"), "clusters", str(args["case"]),
           "--min", str(int(args.get("min", 2))),
           "--max-prevalence", str(int(args.get("max_prevalence", 8)))]
    if args.get("all"):
        cmd.append("--all")
    if args.get("json"):
        cmd.append("--json")
    r = _run(cmd, timeout=300)
    return {"content": [{"type": "text", "text": r.stdout or r.stderr or "no output"}],
            "is_error": r.returncode != 0}


@tool(
    "case_frontier",
    "Read the case's UNRESOLVED GAPS without collecting anything: the next FREE frontier (new "
    "registrable apexes already discovered — via crt.sh SAN, passive-DNS co-host, urlscan-related, "
    "TLS co-SAN, CORS, impersonation, reverse-WHOIS — that are not yet collected), plus the "
    "convergence verdict and the DEFERRED metered leads (FOFA/WhoisXML pivots that would spend "
    "credits, held for your approval). Call this after an assessment to decide what to chase next. "
    "Read-only; spends no credits.",
    {"case": str},
    annotations=READONLY,
)
async def case_frontier(args: dict[str, Any]) -> dict[str, Any]:
    r = _run([PY, os.path.join("tools", "case_state.py"), "frontier", str(args["case"]),
              "--max-new", str(int(args.get("max_new", 8)))])
    return {"content": [{"type": "text", "text": r.stdout or r.stderr or "no output"}],
            "is_error": r.returncode != 0}


@tool(
    "case_loop",
    "Run the RESUMABLE convergence feedback loop on a case: collect (free-only WebPivot) -> ingest "
    "-> convergence snapshot -> assess (assessment.md + machine-readable assessment.json) -> chase "
    "the discovered FREE frontier back into WebPivot -> repeat until CONVERGED, cold (no free leads "
    "left), or the round cap (awaiting-analyst). Never spends FOFA/urlscan-Pro/WhoisXML credits — "
    "those pivots are deferred to assessment.json.metered_leads. Checkpoints cases/<case>/state.json "
    "every round, so an interrupt RESUMES and a cold case re-mines against the current KB on re-run. "
    "First run / added evidence: pass seeds (a domains-file path or a comma list). Resume: omit seeds.",
    {"case": str},
    annotations=ToolAnnotations(readOnlyHint=False),
)
async def case_loop(args: dict[str, Any]) -> dict[str, Any]:
    cmd = [PY, os.path.join("tools", "intel.py"), "loop", str(args["case"])]
    if args.get("seeds"):
        cmd.append(str(args["seeds"]))
    cmd += ["--max-rounds", str(int(args.get("max_rounds", 6))),
            "--max-new", str(int(args.get("max_new", 8)))]
    r = _run(cmd, timeout=1800)   # a multi-round loop of live free collection can take a while
    return {"content": [{"type": "text", "text": r.stdout or r.stderr or "no output"}],
            "is_error": r.returncode != 0}


@tool(
    "case_reopen",
    "Cold-case reopen: flip a finished (converged/cold) case back to 'expanding' and optionally "
    "merge NEW seeds, so the next case_loop re-mines its frontier against the CURRENT knowledge base "
    "— an old case benefits from breakthroughs made in other cases since it closed. Pass seeds as a "
    "space/comma list of new domains, or omit to just reopen for re-mining.",
    {"case": str},
    annotations=ToolAnnotations(readOnlyHint=False),
)
async def case_reopen(args: dict[str, Any]) -> dict[str, Any]:
    seeds = str(args.get("seeds", "")).replace(",", " ").split()
    r = _run([PY, os.path.join("tools", "case_state.py"), "reopen", str(args["case"]), *seeds])
    return {"content": [{"type": "text", "text": r.stdout or r.stderr or "no output"}],
            "is_error": r.returncode != 0}


@tool(
    "victim_profile",
    "VICTIM-SIDE analysis — run this when the operator serves from hostnames they DO NOT OWN "
    "(a phishing label on a legitimate business's subdomain, a compromised CMS, a dangling "
    "record). It does not attribute; it infers the operator's ACCESS VECTOR, because the victim "
    "set is a sample of their capability: victims all at one provider = that provider is "
    "breached; one control panel across many providers = a panel exploit; one CMS = a plugin "
    "vulnerability; a small shared DNS operator + one country/sector = a compromised web agency; "
    "and NOTHING technical in common = STOLEN OR PURCHASED CREDENTIALS (dispersion is a positive "
    "finding, not a dead end — a credential list has no common platform by construction). Fully "
    "PASSIVE: public DNS only, the victims are never scanned; the control panel is read from the "
    "subdomains a panel creates in its own customer's zone. Flags base-rate confounds (cPanel/"
    "WordPress dominate any victim set) instead of counting them. Pass case=<case> to derive the "
    "victim set from collected hosts, and exclude='a.com,b.com' for any apex the OPERATOR "
    "registered themselves — those have no victim and would corrupt every concentration. "
    "Thresholds are tunable in tools/kb/references/victim_profile.json. Read-only.",
    {"case": str},  # victims:str (comma list), exclude:str optional -> args.get()
    annotations=READONLY,
)
async def victim_profile(args: dict[str, Any]) -> dict[str, Any]:
    cmd = [PY, os.path.join("tools", "kb", "victim_profile.py")]
    if args.get("case"):
        case = args["case"]
        cmd += ["--case", case,
                "-o", os.path.join(ROOT, "cases", case, "victim_profile.json")]
    for v in (args.get("victims") or "").replace(",", " ").split():
        cmd.append(v)
    if args.get("exclude"):
        cmd += ["--exclude", str(args["exclude"])]
    r = _run(cmd, timeout=300)
    return {"content": [{"type": "text",
                         "text": r.stdout or r.stderr or "victim_profile produced no output"}],
            "is_error": r.returncode != 0}


@tool(
    "intelx_search",
    "Intelligence X — search ONE STRONG SELECTOR across a corpus nothing else here indexes: breach "
    "dumps, infostealer logs, pastes, darknet mirrors, historical WHOIS and IntelX's own web crawl. "
    "`selector` must be an email, domain (a `*.apex` wildcard is allowed), URL, IP/CIDR, phone "
    "number, wallet, MAC/UUID/IBAN — never a brand or person name (a soft term is refused and still "
    "costs a unit). SEARCH THE CASE DOMAIN FIRST, then the operator's email: a stealer-log record is "
    "indexed by the URL the malware captured, so the domain returns the MACHINES that held "
    "credentials for it — the campaign's victims, the admin/panel URLs the public site never links, "
    "and sometimes the operator's own infected box (direct attribution). Then the contact artifacts "
    "(support phone, payout wallet), which carry the operator's own advertising copy in pastes. "
    "The STEALER LOGS ARE QUERIED IN THEIR OWN PASS BEFORE the general one, because IntelX returns a "
    "bounded page and recycled public-breach rows would otherwise fill it and truncate the one log "
    "record away: a default search is 2 units (logs pass + general pass), buckets='leaks.logs' is "
    "the 1-unit logs-only question. Check `logs_pass` in the output — only with it true is an empty "
    "`read_these` a real negative. mode='phonebook' instead turns ONE domain into an inventory of "
    "every email address, subdomain and URL IntelX has seen under it — the highest-value call for "
    "web casework, and PAID-only. Every record comes back graded: a hit in a breach corpus or a "
    "stealer log is EXPOSURE evidence and is flagged NOT clusterable (two addresses in one combolist "
    "share victims, not an operator); only whois/pastes/darknet hits may support a same-operator "
    "edge — but a stealer-log ITEM comes back in `read_these` to open one by one and ask whose "
    "machine it is (victim = credentials FOR the front-end; operator = the back office, i.e. the "
    "registrar/hosting/CMS/exchange logins behind it). Judgement lives in IntelAnalysis SKILL.md "
    "§1.7 + Workflows/StealerLog.md. Never quote a password/cookie/token — metadata only. "
    "METERED and capped per run. With no INTELX_KEY the layer still runs at ~50%: it classifies the "
    "selector and returns the intelx.io / phonebook.cz URL to run by hand — say so rather than "
    "reporting an empty result as 'not in any leak'.",
    {"selector": str},  # mode:'search'|'phonebook', buckets:str, max:int optional -> args.get()
    annotations=READONLY,
)
async def intelx_search(args: dict[str, Any]) -> dict[str, Any]:
    script = os.path.join("WebPivot", "tools", "wp_intelx.py")
    mode = str(args.get("mode") or "search").lower()
    sel = str(args["selector"])
    if mode == "phonebook":
        cmd = [PY, script, "phonebook", sel]
        if args.get("target"):
            cmd += ["--target", str(args["target"])]
    else:
        cmd = [PY, script, "search", sel]
        if args.get("buckets"):
            cmd += ["--buckets", str(args["buckets"])]
    if args.get("max"):
        cmd += ["--max", str(int(args["max"]))]
    r = _run(cmd, timeout=180)
    if r.returncode != 0 and not r.stdout:
        # rc=2 is the documented KEYLESS path: the stderr block explains what was not queried and
        # gives the UI URL. That is information, not a failure — surfacing it as an error would
        # teach the model to stop asking.
        return _ok((r.stderr or "intelx produced no output") +
                   "\n\n(Keyless/limited IntelX: nothing was queried. Do NOT report this as "
                   "'the selector appears in no leak' — run the URL above by hand.)")
    return _ok((r.stdout or "") + ("\n" + r.stderr if r.stderr else ""))


@tool(
    "url_paths",
    "THE URL PATH AS A CAMPAIGN IDENTIFIER — use this whenever the hosts in a case look disposable "
    "(numeric/random labels, cheap TLDs, a fresh certificate each, nothing shared at host level) but "
    "the pages are branded. That is a deliberate technique: the operator keeps one directory per "
    "branded template on a shared back end and selects which victim sees which brand by the URL "
    "PATH, so `host-a/<kit>/`, `host-b/<kit>/` and `host-c/<kit>/` are ONE operator running one kit "
    "on three throwaway hosts. Every other pivot here (favicon, TLS, registrant, JARM, nameserver) "
    "hangs off the hostname and therefore sees three unrelated sites; the kit directory is the one "
    "string that survives the rotation, because it is the operator's own routing. "
    "mode='analyze' (default) takes ONE url and returns the normalised path, the path TEMPLATE "
    "(session ids / build hashes / dates / locales replaced by placeholders, so per-victim URLs "
    "collapse to one template), the kit directory, the locale, and ready-to-run reverse queries "
    "(urlscan page.url, an inurl: dork, FOFA, PublicWWW, a Wayback CDX sweep) that find the NEXT "
    "host serving the same kit before it is reported anywhere. mode='patterns' takes `paths` (globs "
    "of collected WebPivot result JSON, e.g. 'cases/<case>/raw/*.json') and reports which kits recur "
    "and on how many DISTINCT hosts, plus multi_kit_hosts (one back end serving several brands — the "
    "other half of the same technique). Offline, free, zero API credits. Base-rate controlled: "
    "`/login`, `/assets`, `/api/v1`, `/wp-admin` and friends are denylisted in "
    "WebPivot/references/url_paths.json and NEVER become a kit, so a path with nothing distinctive "
    "returns no pivot — that is the correct result for an ordinary site, not a failure. A shared kit "
    "directory is SAME-KIT evidence and a strong collection lead; it becomes a same-OPERATOR claim "
    "only when an independent artifact class agrees (two resellers of one kit share these strings).",
    {"url": str},  # mode:'analyze'|'patterns', paths:str (space-separated globs), min_hosts:int
    annotations=READONLY,
)
async def url_paths(args: dict[str, Any]) -> dict[str, Any]:
    script = os.path.join("WebPivot", "tools", "wp_paths.py")
    mode = str(args.get("mode") or "analyze").lower()
    # `url` is the one required field, so mode='patterns' accepts its globs in EITHER `paths` or
    # `url` — a caller that has only the required field must still be able to run the mode.
    if mode == "patterns":
        globs = str(args.get("paths") or args.get("url") or "").split()
        if not globs:
            return _ok("url_paths(mode='patterns') needs result-JSON globs in `paths` (or `url`), "
                       "e.g. 'cases/<case>/raw/*.json'.")
        cmd = [PY, script, "patterns", *globs]
        if args.get("min_hosts"):
            cmd += ["--min-hosts", str(int(args["min_hosts"]))]
    else:
        cmd = [PY, script, "analyze", str(args["url"])]
    r = _run(cmd, timeout=120)
    return _ok((r.stdout or "") + ("\n" + r.stderr if r.stderr else ""))


@tool(
    "ip_info",
    "WHERE IS THIS ADDRESS AND WHOSE IS IT — country, city, ASN + org, reverse hostname, the "
    "network's ABUSE CONTACT, and IPinfo's privacy flags (hosting / proxy / vpn / tor / relay) for "
    "one IP. Use it on any address a case surfaces: the host's live A record, an origin candidate "
    "recovered from passive DNS or passive SSL, a mail sender from SPF, a stealer-log victim "
    "address. Three things it decides that nothing else here does cleanly. (1) WHETHER THE ADDRESS "
    "IS A PIVOT AT ALL — a shared CDN/cloud edge is other people's tenants, so reversing it "
    "returns noise, while a small hosting ASN is a real co-tenancy lead. (2) JURISDICTION — the "
    "country and the abuse contact are who a takedown or an LEA referral actually goes to, and "
    "they are properties of the ADDRESS, never of the domain's WHOIS (which on a privacy-masked "
    "registration says nothing). (3) WHAT KIND of address it is: `hosting` on a scam site's server "
    "is ordinary and means nothing, but `vpn`/`proxy`/`tor` on an address an operator connected "
    "FROM is a different statement entirely — the flags are returned individually, not collapsed "
    "into one boolean, so that distinction survives. Runs KEYLESS (rate-limited, still gives "
    "country + org); IPINFO_TOKEN adds the structured ASN block, the abuse contact and the privacy "
    "flags. Memoised per process, so re-asking about the same address inside one case is free. "
    "For the full passive recon of an address (FOFA/Shodan co-tenancy, PTR, MX) pass the bare IP "
    "to pivot_extract instead — that runs IPPivot, of which this is the identity half.",
    {"ip": str},
    annotations=READONLY,
)
async def ip_info(args: dict[str, Any]) -> dict[str, Any]:
    ip = str(args.get("ip") or "").strip()
    code = (
        "import json,sys;sys.path.insert(0,'WebPivot/tools');"
        "from wp_ippivot import ipinfo_lookup, ip_summary;"
        f"d=ipinfo_lookup({ip!r});d.pop('raw',None);"
        f"d['summary']=ip_summary({ip!r});print(json.dumps(d,indent=2,ensure_ascii=False))"
    )
    r = _run([PY, "-c", code], timeout=60)
    return _ok((r.stdout or "") + ("\n" + r.stderr if r.stderr else ""))


@tool(
    "passive_ssl",
    "PASSIVE SSL (CIRCL) — the HISTORICAL certificate view, and the only pivot here that runs "
    "cert -> IP. Every other TLS source reads the certificate a host presents NOW (the live "
    "handshake) or the names a CA logged at issuance (crt.sh, Censys); this one answers which IP "
    "ADDRESSES have actually been observed serving a given leaf certificate, over time. That is "
    "how you RECOVER AN ORIGIN FROM BEHIND A CDN: an operator who later fronted a host with "
    "Cloudflare usually served the same certificate on their own box first, and a passive sensor "
    "recorded it there. It is the partner of passive DNS — pDNS gives historical name->IP, pSSL "
    "gives historical cert->IP, and an address returned by BOTH is the strongest origin lead the "
    "pair produces. Modes: **origin** (default, `target`=a hostname) — take the host's leaf "
    "certificate and return every address that served it, with the host's current (CDN) addresses "
    "removed, so what is left are ORIGIN CANDIDATES to verify directly with the Host header. "
    "**cert** (`target`=a certificate SHA-1 — this API is sha1-keyed, unlike Censys which is "
    "sha256) — every IP observed serving that leaf. **ip** (`target`=an address) — every "
    "certificate seen on it. THE BASE RATE IS THE WHOLE DIFFICULTY: a shared CDN or default-"
    "hosting certificate is served by THOUSANDS of unrelated addresses (a Cloudflare edge cert "
    "measured in testing came back on 915), so clustering on one would fabricate an estate out of "
    "a CDN's customer list. The result therefore carries `clusterable`, already decided against "
    "references/pssl.json — trust it, and never build a same-operator edge on a cert marked "
    "false. COVERAGE IS EUROPE-WEIGHTED AND PARTIAL: an empty answer for a Vietnamese, Chinese or "
    "small-ISP address is routine and means the corpus never saw it — report it as ABSENCE OF "
    "RECORD, never as 'this address served no certificate'. Uses the same free CIRCL account as "
    "passive DNS (PDNS_USERNAME/PDNS_PASSWORD); rate-limited rather than credit-metered.",
    {"target": str},  # mode:'origin'|'cert'|'ip'|'budget', sha1:str, known_ips:str -> args.get()
    annotations=READONLY,
)
async def passive_ssl(args: dict[str, Any]) -> dict[str, Any]:
    script = os.path.join("WebPivot", "tools", "wp_pssl.py")
    mode = str(args.get("mode") or "origin").lower()
    target = str(args.get("target") or "").strip()
    if mode == "budget":
        cmd = [PY, script, "budget"]
    elif mode == "cert":
        cmd = [PY, script, "cert", target]
        if args.get("subject"):
            cmd += ["--subject", str(args["subject"])]
    elif mode == "ip":
        cmd = [PY, script, "ip", target]
    else:
        cmd = [PY, script, "origin", target]
        if args.get("sha1"):
            cmd += ["--sha1", str(args["sha1"])]
        for ip in str(args.get("known_ips") or "").split(","):
            if ip.strip():
                cmd += ["--known-ip", ip.strip()]
    r = _run(cmd, timeout=180)
    return _ok((r.stdout or "") + ("\n" + r.stderr if r.stderr else ""))


@tool(
    "serp_ads",
    "THE ADVERTISING LAYER — who PAID to send traffic to this domain, and whether the page shows "
    "those visitors something different from what it shows you. Use it whenever a target buys "
    "traffic: an `AW-` conversion id in the page, an ads.txt, a URL carrying a gclid/utm set, a "
    "victim who says they clicked an ad, or a brand you suspect is being impersonated in search "
    "results. Modes: "
    "**advertiser** (default, needs `target`=domain) — the Google Ads Transparency Center, which "
    "publishes a VERIFIED, paying advertiser account for the domain plus the legal name its ads are "
    "'funded by'. That identity survives WHOIS privacy and domain rotation, because nobody "
    "re-verifies a fresh ad account for each throwaway host. "
    "**creatives** (`target`=an AR… advertiser id) — the reverse, and the reason to be here: every "
    "OTHER domain that account advertised. Same-PAYER evidence, stronger than a shared template — "
    "unless the advertiser is agency-shaped (many unrelated domains), which the result flags, and "
    "then the co-advertised domains are leads, not operator links. "
    "**serp** (`target`=a keyword) — who is buying that keyword right now, in market `gl`. "
    "BEST-EFFORT: Google serves the sponsored block inconsistently to automated clients, so an empty "
    "result means the response carried no ads block, NEVER 'nobody advertises this keyword'. Two "
    "domains bidding on one keyword are competitors, NEVER an operator link. "
    "**cloak** (`target`=a URL) — FREE, no API credit: fetch the page as a plain visitor, as a paid "
    "ad click, and once more as a control, then compare. Many fraud landing pages serve the real "
    "scam ONLY to traffic carrying the right utm/gclid and show everyone else a decoy, so a "
    "collection of the bare domain describes the decoy and its 'nothing found' is worthless. A "
    "`divergent` verdict returns the `unlock_url` — re-run pivot_extract on THAT. Pass the ad's own "
    "parameters in `ad_params` (a landing URL or 'k=v&k=v') when you have them; the advertiser mode "
    "sometimes recovers them from a creative, but the archive often stores a text ad as an image "
    "with no URL — that is normal. Verdicts `dynamic` / `inconclusive_unstable` are NOT "
    "cloaking — do not report them as evasion. "
    "**params** (`target`=a URL) — offline classification of the advertising parameters. "
    "METERED except cloak/params (1 SerpApi search per call, capped per run). Keyless it still runs "
    "at ~55%: the cloaking probe in full plus the free adstransparency.google.com address — say so "
    "rather than reporting an unqueried archive as 'the domain does not advertise'.",
    {"target": str},  # mode:'advertiser'|'creatives'|'serp'|'cloak'|'params', region:str,
                      # ad_params:str, gl:str, hl:str, details:int -> args.get()
    annotations=READONLY,
)
async def serp_ads(args: dict[str, Any]) -> dict[str, Any]:
    script = os.path.join("WebPivot", "tools", "wp_serp.py")
    mode = str(args.get("mode") or "advertiser").lower()
    target = str(args["target"]).strip()
    if mode in ("cloak", "cloaking"):
        cmd = [PY, script, "cloak", target]
        if args.get("ad_params"):
            cmd += ["--ad-params", str(args["ad_params"])]
    elif mode == "params":
        cmd = [PY, script, "params", target]
    elif mode == "serp":
        cmd = [PY, script, "serp", target]
        for flag in ("gl", "hl"):
            if args.get(flag):
                cmd += [f"--{flag}", str(args[flag])]
    else:
        cmd = [PY, script, "creatives" if target.upper().startswith("AR") else "advertiser", target]
        if args.get("region"):
            cmd += ["--region", str(args["region"])]
        if args.get("details"):
            cmd += ["--details", str(int(args["details"]))]
    r = _run(cmd, timeout=240)
    body = (r.stdout or "") + ("\n" + r.stderr if r.stderr else "")
    if r.returncode != 0 and not r.stdout:
        # Keyless is a documented path, not a failure: returning it as an error teaches the model to
        # stop asking, and the free UI address in the stderr block is the actual deliverable.
        return _ok(body + "\n\n(Keyless/limited SerpApi: the Ads Transparency archive was NOT "
                          "queried. Do NOT report this as 'the domain does not advertise' — open "
                          "the adstransparency.google.com URL above by hand.)")
    return _ok(body)


@tool(
    "capture_evidence",
    "STORE THE RAW BYTES the host served — the DOM plus every JavaScript and stylesheet the page "
    "loaded, each with its own sha256, under cases/<case>/evidence/captures/<host>/<kit>/<UTC>/ with "
    "a manifest and a bundle-level `capture_sha256`. Everything else this toolkit produces is "
    "DERIVED: a favicon hash, a DOM fingerprint, an extracted wallet — assertions about a page that "
    "will not exist next month. Once the host is gone nobody can re-check them, including us. "
    "pivot_extract already captures automatically whenever --case is set, so call this tool for a "
    "page you did NOT collect through the pipeline, for a re-capture (captures are timestamped and "
    "never overwritten — the diff between two captures is how you date a re-skin), or with "
    "verify=true to re-hash a stored capture and confirm it still matches its manifest before citing "
    "it. Required: url (or dir with verify=true). Optional: case, outdir, third_party=false (record "
    "third-party URLs in the manifest but do not download them). BUDGETED: same-site assets get the "
    "generous allowance because they are the operator's own code, third-party CDN libraries a small "
    "one — anything dropped is listed in `skipped_for_budget`, so read that before treating a bundle "
    "as the whole page. Cite the capture_sha256, not the directory path.",
    {"url": str},  # case:str, outdir:str, verify:bool, dir:str, third_party:bool
)
async def capture_evidence(args: dict[str, Any]) -> dict[str, Any]:
    script = os.path.join("WebPivot", "tools", "wp_capture.py")
    # verify=true takes a capture DIRECTORY; accept it in either `dir` or the required `url`, so a
    # caller passing only the required field can still verify.
    target = str(args.get("dir") or args.get("url") or "")
    if not target:
        return _ok("capture_evidence needs a `url` to capture, or a capture directory in `url`/"
                   "`dir` with verify=true.")
    cmd = [PY, script, target]
    if args.get("verify") or args.get("dir"):
        cmd += ["--verify"]
    else:
        if args.get("case"):
            cmd += ["--case", str(args["case"])]
        if args.get("outdir"):
            cmd += ["--outdir", str(args["outdir"])]
        if args.get("third_party") is False:
            cmd += ["--no-third-party"]
    r = _run(cmd, timeout=300)
    return {"content": [{"type": "text", "text": (r.stdout or "") + (r.stderr or "") or "no output"}],
            "is_error": r.returncode != 0}


@tool(
    "capture_screenshot",
    "Capture a rendered full-page PNG of a live page as TIMESTAMPED, HASHED visual evidence — the "
    "page as a human sees it (a Telegram channel bio naming admins, a crew card, a members-area "
    "panel, a deposit page), which is real contemporaneous evidence the DOM/artifact layers do not "
    "preserve. Renders post-JS via a real browser, so it captures what the page actually DISPLAYS, "
    "not the empty SPA shell. Writes to cases/<case>/evidence/screenshots/<host>/<UTC>.png with a "
    "sha256, pixel dimensions and page title recorded in a per-case manifest, so the image is citable "
    "in a report's evidence ledger and embeddable as a figure (cite the sha256, not the path). "
    "Captures are timestamped and never overwritten — re-capturing a page dates any change. Many "
    "evidence pages sit behind ONE interaction (a splash/'ENTER' gate, a cookie wall, a lazy card "
    "grid): pass click='ENTER NETWORK' to click the first element with that text and re-wait before "
    "the shot, wait_selector=<css> to wait for an element, or wait_after=<sec> to settle — every "
    "action taken is recorded in the manifest so a capture that clicked through a gate says so. "
    "OUTBOUND and ATTRIBUTABLE like any live fetch: on hostile infrastructure pass proxy=<egress> so "
    "the request does not carry the analyst's own IP. verify=true re-hashes a stored PNG or a case "
    "manifest to confirm nothing was altered before you cite it. Required: url (or a png/manifest "
    "path with verify=true). Optional: case, outdir, proxy, label, click, wait_selector, wait_after.",
    {"url": str},  # case,outdir,proxy,label,click,wait_selector:str; wait_after:num; verify:bool -> args.get()
)
async def capture_screenshot(args: dict[str, Any]) -> dict[str, Any]:
    script = os.path.join("WebPivot", "tools", "wp_screenshot.py")
    target = str(args.get("url") or "")
    if not target:
        return _err("capture_screenshot needs a `url` to capture (or a png/manifest path with verify=true).")
    if args.get("verify"):
        r = _run([RENDER_PY, script, "--verify", target], timeout=120)
        return _ok(r.stdout or r.stderr or "no output")
    cmd = [RENDER_PY, script, target, "--json"]
    for flag in ("case", "outdir", "proxy", "label", "click", "wait_after"):
        if args.get(flag) is not None:
            cmd += [f"--{flag.replace('_', '-')}", str(args[flag])]
    if args.get("wait_selector"):
        cmd += ["--wait-selector", str(args["wait_selector"])]
    if args.get("full_page") is False:
        cmd += ["--no-full-page"]
    r = _run(cmd, timeout=300)      # a real browser render is slow; matches the screenshot timeout
    if r.returncode != 0:
        return _err(f"capture_screenshot failed for {target}: {(r.stderr or '')[-500:]}")
    return _ok(r.stdout or "capture_screenshot produced no output")


@tool(
    "anyrun_lookup",
    "ANY.RUN READ-ONLY side — nothing is ever submitted by this tool (that is `anyrun_submit`). "
    "Threat Intelligence Lookup: what samples carrying this indicator DID when detonated — the "
    "domains, IPs, URLs and ports contacted, the family label, Suricata context, public task links. "
    "Run it after analyze_artifact on the sample's sha256, its backend host or its C2 `ip:port`; it "
    "is the cheapest way to recover a PACKED sample's real endpoints, which exist only at runtime, "
    "so a thin static sweep plus a `binary:protection` finding is the cue to call it. NOTE TI Lookup "
    "is a SEPARATE and limited licence — a plain sandbox key answers 403 here, so a failure usually "
    "means 'not entitled', not 'nothing known'; mode='history' lists YOUR OWN past tasks and "
    "mode='report' with indicator=<task-uuid> fetches one, both of which need only the sandbox key. "
    "`indicator` is auto-typed (sha256/md5/domain/ip[:port]/url); query='field:\"value\"' for a raw "
    "query. Contacted hosts may support an operator edge once corroborated; a shared threat FAMILY "
    "is same-KIT only, never attribution alone. METERED and capped per run. With no ANYRUN_API_KEY "
    "the layer still runs at ~50%: it composes the correct query and returns the UI address — say "
    "so rather than reporting silence as 'unknown sample'.",
    {"indicator": str},  # mode:'lookup'|'history'|'report', query:str, days:int -> args.get()
    annotations=READONLY,
)
async def anyrun_lookup(args: dict[str, Any]) -> dict[str, Any]:
    import re
    script = os.path.join("BinaryPivot", "tools", "bp_anyrun.py")
    mode = str(args.get("mode") or "lookup").lower()
    if mode == "history":
        r = _run([PY, script, "history", "--limit", str(int(args.get("limit", 25)))], timeout=120)
        return _ok((r.stdout or "") + ("\n" + r.stderr if r.stderr else ""))
    if mode == "report":
        cmd = [PY, script, "report", str(args["indicator"])]
        if args.get("iocs"):
            cmd.append("--iocs")
        r = _run(cmd, timeout=180)
        return _ok((r.stdout or "") + ("\n" + r.stderr if r.stderr else ""))
    cmd = [PY, script, "lookup"]
    if args.get("query"):
        cmd += ["--query", str(args["query"])]
    else:
        ind = str(args["indicator"]).strip()
        host = ind.split(":")[0]
        if re.fullmatch(r"[0-9a-fA-F]{64}", ind):
            flag = "--sha256"
        elif re.fullmatch(r"[0-9a-fA-F]{32}", ind):
            flag = "--md5"
        elif ind.startswith(("http://", "https://")):
            flag = "--url"
        elif re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host):
            flag = "--ip"
        else:
            flag = "--domain"
        cmd += [flag, ind]
    if args.get("days"):
        cmd += ["--days", str(int(args["days"]))]
    r = _run(cmd, timeout=180)
    if r.returncode != 0 and not r.stdout:
        return _ok((r.stderr or "anyrun produced no output") +
                   "\n\n(Keyless/limited ANY.RUN: nothing was queried. Do NOT report this as "
                   "'the sample is unknown to the sandbox world' — paste the query into the UI.)")
    return _ok((r.stdout or "") + ("\n" + r.stderr if r.stderr else ""))


@tool(
    "anyrun_submit",
    "DETONATE a file or URL in the ANY.RUN sandbox. **YOU MUST ASK THE USER FIRST, EVERY TIME.** "
    "Call it with confirm=false (or omitted) to get the RISK BRIEFING, show that briefing to the "
    "analyst, and only call again with confirm=true after they explicitly say yes to THIS "
    "submission. Consent to 'analyze this sample' is NOT consent to detonate it. Why it is gated: a "
    "submission is outbound, attributable and irreversible — it hands case material to a third "
    "party, and a URL detonation FETCHES the live target from published ANY.RUN egress, so the "
    "operator learns they are being sandboxed and rotates or starts serving a decoy (which also "
    "poisons the verdict: 'info' from a datacenter IP is not exoneration). On a free plan the task "
    "is PUBLIC and searchable, and operators watch that feed. Deleting the task afterwards un-sends "
    "nothing. TRY FIRST and say what you tried: static analyze_artifact, then an EXISTING detonation "
    "of the hash (anyrun_lookup / VirusTotal / MalwareBazaar / Triage / Koodous). Prefer submitting "
    "the downloaded FILE over the live URL. Privacy defaults to owner (only you); public is refused "
    "unless the analyst separately authorizes it. NEVER put a case ID or an analyst/client name in "
    "`tags` or the filename. kind='file' (a local path) or 'url'.",
    {"target": str},  # kind:'file'|'url', confirm:bool, privacy:str, allow_public:bool, tags:str
    annotations=ToolAnnotations(readOnlyHint=False),
)
async def anyrun_submit(args: dict[str, Any]) -> dict[str, Any]:
    script = os.path.join("BinaryPivot", "tools", "bp_anyrun.py")
    kind = str(args.get("kind") or ("url" if str(args["target"]).startswith(("http://", "https://"))
                                    else "file")).lower()
    cmd = [PY, script, "submit", str(args["target"])]
    if kind == "url":
        cmd.append("--url")
    confirmed = bool(args.get("confirm"))
    if confirmed:
        cmd.append("--confirm-submission")
    if args.get("privacy"):
        cmd += ["--privacy", str(args["privacy"])]
    if args.get("allow_public"):
        cmd.append("--allow-public")
    if args.get("tags"):
        cmd += ["--tags", str(args["tags"])]
    r = _run(cmd, timeout=300)
    body = (r.stdout or "") + ("\n" + r.stderr if r.stderr else "")
    if not confirmed:
        # rc=3 is the gate firing, which is the DESIGNED outcome, not a failure. Returning it as an
        # error would push the model to retry with confirm=true on its own — the exact thing this
        # gate exists to prevent.
        return _ok("NOTHING WAS SUBMITTED — confirmation required.\n"
                   "Show the briefing below to the analyst, ask them explicitly whether to "
                   "detonate, and only then call anyrun_submit again with confirm=true.\n\n" + body)
    return _ok(body)


# ---------------------------------------------------------------- Engage (auth surface + gated engagement)
_ENGAGE = os.path.join("Engage", "tools")


@tool(
    "detect_login",
    "DETECT a site's authentication surface — the login form, the password field and the "
    "registration page — passively, needing no account. Reads the page and classifies every "
    "<form> by the FIELDS it carries, not by a word in the URL: LOGIN (an identifier + a "
    "password, no confirm-password), REGISTER (adds a confirm-password / invite code / terms / "
    "extra identity fields), PASSWORD-RESET (an identifier, no password, under 'forgot/recover'). "
    "Follows ONE hop to the linked register/login page so the signup form is found even when the "
    "entry page shows only a login box, confirmed by that page's fields. Surfaces what engagement "
    "would need before anyone touches the box: the form POST `action` (an auth_endpoint pivot, "
    "often the backend/API the HTML never otherwise names), a CAPTCHA or OTP/verification step "
    "that BLOCKS an automated signup, and a required invite/referral code (a closed-funnel tell "
    "AND a clustering pivot). If the form is JS-rendered and absent from static HTML it says so "
    "and points at a rendered fetch — 'no form in static HTML' is never reported as 'no login'. "
    "GET-only; free/keyless. Pass url=<URL|host>; proxy=<research egress> optional.",
    {"url": str},   # proxy:str, no_crawl:bool, case:str optional -> args.get()
    annotations=READONLY,
)
async def detect_login(args: dict[str, Any]) -> dict[str, Any]:
    target = str(args["url"])
    cmd = [PY, os.path.join(_ENGAGE, "en_forms.py"), target]
    if args.get("proxy"):
        cmd += ["--proxy", str(args["proxy"])]
    if args.get("no_crawl"):
        cmd += ["--no-crawl"]
    if args.get("case"):
        out = os.path.join(ROOT, "cases", str(args["case"]), "engage", "forms.json")
        os.makedirs(os.path.dirname(out), exist_ok=True)
        cmd += ["-o", out, "--pretty"]
    r = _run(cmd, timeout=120)
    v = _load_json_str(r.stdout or "")
    if v is None:
        return _err(f"detect_login failed for {_host(target)}: {(r.stderr or '')[-400:]}")
    return _ok(json.dumps(v, ensure_ascii=False, indent=2))


@tool(
    "make_persona",
    "Mint a SYNTHETIC research persona for an authorized engagement — the identity a signup form "
    "asks for, generated fresh and obviously non-real, never a real person's details. Email is a "
    "non-deliverable .invalid placeholder unless email_domain names a disposable inbox YOU "
    "control (so an email-verifying signup forces a conscious choice, not an invented live "
    "address); phone is omitted unless with_phone, then a reserved non-routable number. Nothing "
    "is registered or sent — this only produces the data. Persist under cases/<case>/engage/ with "
    "case=<ID>. One persona per case; never reuse across cases (a reused research identity links "
    "your own operations for the adversary).",
    {},   # case:str, email_domain:str, with_phone:bool, seed:str, country:str optional -> args.get()
    annotations=READONLY,
)
async def make_persona(args: dict[str, Any]) -> dict[str, Any]:
    cmd = [PY, os.path.join(_ENGAGE, "en_persona.py"), "--pretty"]
    for flag, key in (("--email-domain", "email_domain"), ("--country", "country"),
                      ("--seed", "seed"), ("--case", "case")):
        if args.get(key):
            cmd += [flag, str(args[key])]
    if args.get("with_phone"):
        cmd += ["--with-phone"]
    r = _run(cmd, timeout=60)
    v = _load_json_str(r.stdout or "")
    if v is None:
        return _err(f"make_persona failed: {(r.stderr or '')[-300:]}")
    return _ok(json.dumps(v, ensure_ascii=False, indent=2))


@tool(
    "engage_account",
    "GATED — create an account on the target and log in to gather intel from the members area "
    "(panel, deposit/withdraw flow, referral tree, support handles) the public page hides. This "
    "is OUTBOUND, ATTRIBUTABLE and IRREVERSIBLE — a POST to the operator's own backend that tells "
    "them a new member appeared, from your egress, with a fingerprint — so it is gated exactly "
    "like a sandbox submission. WITHOUT confirm=true it returns only the preflight BRIEFING and "
    "does nothing; the harness ALSO requires env INTEL_ENGAGE_CONFIRM=1 (approval_required), which "
    "an agent loop cannot set for itself. It refuses a non-synthetic persona (use make_persona), "
    "refuses direct egress unless allow_direct_egress=true, STOPS at any CAPTCHA/OTP blocker "
    "(never solves or evades one), and drives a real browser via Playwright if present else "
    "returns a fill-by-hand runbook. Most fraud funnels do NOT verify identity — a made-up "
    "username+password registers and logs straight in; when a funnel gates on email confirmation, "
    "mint the persona --from-pool (a real puppet inbox) and pass await_confirm=true so en_inbox "
    "fetches the confirm link and the browser clicks it before login (hard KYC — government ID / "
    "selfie — is a STOP the tool never fabricates). Once logged in it runs the MISSION harvest over "
    "the members area: the operator's crypto WALLET and BANK/payee details, the SERVICE FLOW, and "
    "the credential-harvester UPLOAD PATH. Persona, screenshots, authenticated DOM, harvest and one "
    "audit line per engagement are written under cases/<case>/engage/. Try the no-account routes "
    "first (detect_login; leaked panel credentials in the leak corpus; an archived authenticated "
    "view) — a fresh signup is the most attributable option, not the first. Pass url; persona=<path "
    "to a make_persona JSON>; detection=<path to a detect_login JSON, the fill plan>; case; "
    "proxy=<research egress>; await_confirm for email-gated signups; confirm=true only after a "
    "human said yes to THIS engagement.",
    {"url": str},   # persona:str, detection:str, case:str, proxy:str, allow_direct_egress:bool, confirm:bool, no_login:bool
    annotations=ToolAnnotations(readOnlyHint=False),
)
async def engage_account(args: dict[str, Any]) -> dict[str, Any]:
    target = str(args["url"])
    cmd = [PY, os.path.join(_ENGAGE, "en_engage.py"), target]
    for flag, key in (("--persona", "persona"), ("--detection", "detection"),
                      ("--case", "case"), ("--proxy", "proxy"), ("--target-domain", "target_domain")):
        if args.get(key):
            cmd += [flag, str(args[key])]
    if args.get("allow_direct_egress"):
        cmd += ["--allow-direct-egress"]
    if args.get("await_confirm"):
        cmd += ["--await-confirm"]
    if args.get("no_login"):
        cmd += ["--no-login"]
    # confirm is honoured ONLY if the analyst also set the env second-lock; en_engage re-checks it.
    if args.get("confirm") and os.environ.get("INTEL_ENGAGE_CONFIRM") == "1":
        cmd += ["--confirm-engagement"]
    r = _run(cmd, timeout=240)
    v = _load_json_str(r.stdout or "")
    if v is None:
        return _err(f"engage_account failed for {_host(target)}: {(r.stderr or '')[-400:]}")
    if isinstance(v, dict) and str(v.get("action", "")).startswith("CONFIRMATION REQUIRED"):
        return _ok("NOTHING WAS SENT — no account created; confirmation required.\n"
                   "Show the briefing below to the analyst, ask explicitly whether to create an "
                   "account on the operator's box, and only then call engage_account with "
                   "confirm=true (the run must also have INTEL_ENGAGE_CONFIRM=1).\n\n"
                   + json.dumps(v, ensure_ascii=False, indent=2))
    return _ok(json.dumps(v, ensure_ascii=False, indent=2))


@tool(
    "harvest_authenticated",
    "The post-login MISSION extractor — read an AUTHENTICATED members-area page (the DOM "
    "engage_account captured, or any saved authenticated HTML) for the operator's money and "
    "mechanics that the public page hid: crypto WALLET addresses deposits go to (BTC / ETH-ERC20-"
    "BEP20 / TRON-TRC20), BANK / payee details (IBAN, SWIFT/BIC, account numbers taken ONLY in "
    "bank context), the SERVICE FLOW present (deposit → task/trade → withdraw-block → top-up; VIP "
    "levels; referral tree), and the CREDENTIAL-HARVESTER UPLOAD PATH (a form whose action is a "
    "collector, a file-upload endpoint, or a page collecting third-party card/CVV/seed-phrase/bank "
    "logins — the operator's own routing, which clusters the kit). Extracts only; every wallet/"
    "account is a lead fed back into WebPivot + IntelAnalysis and base-rate checked there — a "
    "shared processor wallet is infrastructure, not the operator's. Pass html_path=<file>; "
    "base_url optional; case to append to the evidence ledger.",
    {"html_path": str},   # base_url:str, case:str optional -> args.get()
    annotations=READONLY,
)
async def harvest_authenticated(args: dict[str, Any]) -> dict[str, Any]:
    cmd = [PY, os.path.join(_ENGAGE, "en_harvest.py"), str(args["html_path"]), "--pretty"]
    if args.get("base_url"):
        cmd += ["--base-url", str(args["base_url"])]
    if args.get("case"):
        cmd += ["--case", str(args["case"])]
    r = _run(cmd, timeout=90)
    v = _load_json_str(r.stdout or "")
    if v is None:
        return _err(f"harvest_authenticated failed: {(r.stderr or '')[-300:]}")
    return _ok(json.dumps(v, ensure_ascii=False, indent=2))


@tool(
    "engage_report",
    "Render a case's ENGAGEMENT artifacts (under cases/<case>/engage/ — payment_methods, "
    "cluster_expansion, detect_* and the interaction ledger) into a citable 'Panel Engagement — "
    "Evidence' markdown section: the method/authorization note, the auth surface, the payment "
    "methods (bank + crypto, with base-rate exclusions kept visible), the cluster expansion, and "
    "an evidence table citing each fact to the API endpoint or capture it came from. Fold it into "
    "the case assessment (append_to=<path>) and re-render with render_report. Reads only the "
    "case folder — holds no case data itself. Pass case=<ID>; append_to optional.",
    {"case": str},   # append_to:str optional -> args.get()
    annotations=READONLY,
)
async def engage_report(args: dict[str, Any]) -> dict[str, Any]:
    cmd = [PY, os.path.join(_ENGAGE, "en_report.py"), str(args["case"])]
    if args.get("append_to"):
        cmd += ["--append-to", str(args["append_to"])]
    r = _run(cmd, timeout=60)
    out = (r.stdout or "") + (("\n" + r.stderr) if args.get("append_to") else "")
    if r.returncode != 0 and not out.strip():
        return _err(f"engage_report failed: {(r.stderr or '')[-300:]}")
    return _ok(out or "(engagement section written)")


# ---------------------------------------------------------------- servers + names
# Every @tool MUST appear in exactly one server below AND in that server's *_TOOLS allowlist.
# The stdio front-end (mcp_server.py) auto-discovers @tools, so a tool missing here is visible in
# Claude Code and INVISIBLE to the SDK — the two front-ends silently diverge and a phase prompt
# that references the tool just fails. The reverse is worse: an allowlist entry with no served
# tool tells the model it may call something that does not exist. `tests/test_tool_registry.py`
# asserts the three lists agree, so this can only drift again on purpose.
# Bind every @tool's NAME around its handler, so the context governor knows which budget to
# apply to that tool's output (see _bounded / _budget_for). Done by sweeping the module rather
# than by listing tools, so a tool added later CANNOT escape the governor by being forgotten —
# which is exactly how the old per-call slices ended up covering only four of them.
for _t in list(globals().values()):
    if hasattr(_t, "handler") and hasattr(_t, "name") and hasattr(_t, "input_schema"):
        _governed(_t)
        # Same sweep, same reason: attach the declared optional params so every front-end's
        # schema builder can show them. A tool with none simply gets {}.
        try:
            _t.optional_schema = dict(OPTIONAL_PARAMS.get(_t.name) or {})
        except Exception:  # noqa: BLE001 — an immutable tool object still works, just without them
            pass

COLLECT_SERVER = create_sdk_mcp_server(
    "collect", tools=[pivot_extract, doc_metadata, analyze_artifact, fallback_probe,
                      impersonation_hunt, search_pivot, censys, intelx_search,
                      anyrun_lookup, anyrun_submit, capability_check,
                      url_paths, capture_evidence, capture_screenshot, serp_ads, passive_ssl, ip_info,
                      domain_liveness,
                      detect_login, make_persona, engage_account, harvest_authenticated,
                      engage_report,
                      kb_ingest])
ANALYZE_SERVER = create_sdk_mcp_server(
    "analyze", tools=[kb_cluster, kb_entity, kb_query_shared, risk_signals,
                      reverse_whois, cert_overlap, reference_check, reference_add, reference_mirrors,
                      which_cases, domain_verdict, api_usage, tool_calls, case_scope,
                      case_clusters, case_frontier, case_loop, case_reopen,
                      email_permute,
                      render_diagram, case_timeline, render_report, victim_profile])

COLLECT_TOOLS = ["mcp__collect__pivot_extract", "mcp__collect__doc_metadata",
                 "mcp__collect__analyze_artifact",
                 "mcp__collect__fallback_probe", "mcp__collect__impersonation_hunt",
                 "mcp__collect__search_pivot", "mcp__collect__censys",
                 "mcp__collect__intelx_search",
                 "mcp__collect__anyrun_lookup", "mcp__collect__anyrun_submit",
                 "mcp__collect__capability_check",
                 "mcp__collect__url_paths", "mcp__collect__capture_evidence",
                 "mcp__collect__capture_screenshot",
                 "mcp__collect__serp_ads", "mcp__collect__passive_ssl",
                 "mcp__collect__ip_info",
                 "mcp__collect__domain_liveness",
                 "mcp__collect__detect_login", "mcp__collect__make_persona",
                 "mcp__collect__engage_account", "mcp__collect__harvest_authenticated",
                 "mcp__collect__engage_report",
                 "mcp__collect__kb_ingest"]
ANALYZE_TOOLS = ["mcp__analyze__kb_cluster", "mcp__analyze__kb_entity",
                 "mcp__analyze__kb_query_shared", "mcp__analyze__risk_signals",
                 "mcp__analyze__reverse_whois", "mcp__analyze__cert_overlap",
                 "mcp__analyze__reference_check", "mcp__analyze__reference_add",
                 "mcp__analyze__reference_mirrors",
                 "mcp__analyze__which_cases", "mcp__analyze__domain_verdict",
                 "mcp__analyze__api_usage", "mcp__analyze__tool_calls",
                 "mcp__analyze__case_scope",
                 "mcp__analyze__case_clusters", "mcp__analyze__case_frontier",
                 "mcp__analyze__case_loop",
                 "mcp__analyze__case_reopen",
                 "mcp__analyze__email_permute",
                 "mcp__analyze__render_diagram", "mcp__analyze__case_timeline",
                 "mcp__analyze__render_report", "mcp__analyze__victim_profile"]
