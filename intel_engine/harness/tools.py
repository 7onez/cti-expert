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

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # harness/ on path for sdk_compat
from sdk_compat import ToolAnnotations, create_sdk_mcp_server, tool  # noqa: E402 — backend-neutral

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # repo root (harness/..)
PY = sys.executable
READONLY = ToolAnnotations(readOnlyHint=True)  # lets the model batch these in parallel

# The host-collection routine + its flag/cache helpers are single-sourced in the stdlib-only
# tools/collect_core.py so the deterministic pipeline (tools/intel.py) shares the SAME collector
# invocation path without importing this SDK module. This module keeps its own thin helper names
# (below) as delegates so the rest of the file is untouched.
sys.path.insert(0, os.path.join(ROOT, "tools"))
import collect_core  # noqa: E402
import binary_auto  # noqa: E402

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
            refused = _free_only_refusal(_n, args)
            if refused:
                return _err(refused)
            return await _h(args)
        finally:
            _CURRENT_TOOL.reset(token)

    try:
        t.handler = _wrapped
        t._governed = True
    except Exception:  # noqa: BLE001 — an immutable tool object still works, just at the default budget
        pass
    return t


def _free_only_refusal(name: str, args) -> str:
    """The gate treats free_only=true as 'not metered' and lets the call through, so a metered
    tool that has NO keyless mode must refuse it rather than spend anyway. Data:
    tool_policy.json metered_tools − free_only_capable_tools."""
    try:
        import audit as _a  # harness/audit.py — the policy data owner
        if (name in _a.METERED_TOOLS and name not in _a.FREE_ONLY_CAPABLE
                and _a._truthy(args or {}, _a.FREE_ONLY_ARGS)):
            return (f"{name} has no keyless mode — with free_only=true it does not run (that would "
                    f"spend metered credits). Use a keyless source, or propose it for the analyst's "
                    f"approval on a case that allows spending.")
    except Exception:  # noqa: BLE001 — policy unreadable: FAIL CLOSED when free_only was asked
        return (f"{name}: spend policy unreadable — refusing free_only=true rather than risk a "
                f"metered call." if (args or {}).get("free_only") else "")
    return ""


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


def _flag(args: dict[str, Any], name: str) -> bool:
    """Read a boolean tool argument with the GATE's own rule (audit._truthy): "false", "no", "0",
    "off", "none", "null", "" and None are NO. `bool("false")` is True, so a handler testing raw
    truthiness would run the action (a sandbox detonation, a paid search) the gate had just
    classified as a harmless briefing. Every flag a handler acts on is read through here."""
    import audit as _a  # harness/audit.py — the policy data owner
    return _a._truthy(args or {}, {name})


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
    "domains, Shodan host, Censys host, Validin + keyless HackerTarget reverse-IP, CIRCL passive DNS "
    "and the passive-SSL certificates seen ON the box, dig MX/NS/TXT/PTR; under free_only IPinfo "
    "runs keyless and FOFA/Shodan/Censys/CIRCL are skipped. In a case it stamps meta.origin_context "
    "— which case hosts resolved here, when, and whether that tenancy is stale or the network is a "
    "DDoS-proxy-or-host (`ambiguous`): then the co-hosted domains are LEADS, never siblings. A "
    "shared CDN/hosting IP is marked information not a "
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
                      passive=_flag(args, "passive"), proxy=args.get("proxy"),
                      force=_flag(args, "force"),
                      no_assets=_flag(args, "no_assets"),
                      no_well_known=_flag(args, "no_well_known"),
                      assets_max=args.get("assets_max"),
                      no_docmeta=_flag(args, "no_docmeta"),
                      docmeta_max=args.get("docmeta_max"),
                      free_only=_flag(args, "free_only"))
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
                no_docmeta: bool = False, docmeta_max: int | None = None,
                free_only: bool = False, allow_spend: bool = False) -> dict[str, Any]:
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
    # free_only → the collector's own --free-only: every metered enrichment engine (and the
    # default reverse-WHOIS purchase) is held. ONE rule (proposal.collect_free_only): free-only on
    # a no_spend case and, while the cross-type loop is active, for every host EXCEPT the analyst's
    # own typed seeds and an approved `enrich.host` (allow_spend). Consent is per HOST, never per
    # round — an agent reaching other hosts in the seed round collects them free-only.
    import proposal as _P  # harness/proposal.py
    if _P.collect_free_only(ROOT, case, url, free_only=free_only, allow_spend=allow_spend):
        extra.append("--free-only")
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
    import proposal as _P
    keyed = [s for s in seeds if not _P.collect_free_only(ROOT, case, s)]
    free = [s for s in seeds if s not in keyed]
    out: list[dict[str, Any]] = []
    for group, flags in ((keyed, ()), (free, ["--free-only"])):
        if group:
            out += collect_core.collect_many(
                group, case, max_workers=max_workers,
                root=ROOT, py=PY, render_py=RENDER_PY,
                collector=os.path.join(ROOT, "WebPivot", "tools", "pivot_extract.py"),
                hostile=hostile, force=FORCE, smoke=SMOKE, no_archive=NO_ARCHIVE,
                want_shot=SHOT, flaresolverr=FLARESOLVERR, manifest_cb=_append_manifest,
                extra_flags=flags)
    return out


def ingest(case: str) -> tuple[bool, str]:
    """Ingest web hosts and binary files into the same case KB."""
    case_dir = os.path.join(ROOT, "cases", case)
    raw = os.path.join(case_dir, "raw")
    files = ([os.path.join(raw, f) for f in os.listdir(raw)
              if f.endswith(".json") and not f.startswith("bin_")]
             if os.path.isdir(raw) else [])
    r = (_run([PY, os.path.join("tools", "kb", "ingest_webpivot.py"),
               "--kb", KB_DIR, *files]) if files else None)
    binary_ok, binary_note = binary_auto.ingest(case_dir, os.path.join(ROOT, KB_DIR))
    web_note = (r.stdout + r.stderr) if r else ""
    ok = (bool(files or binary_note) and (r is None or
          (r.returncode == 0 and "[skip]" not in r.stderr)) and binary_ok)
    return ok, (web_note + binary_note) or f"no raw or binary JSON in {case_dir}"


@tool(
    "fallback_probe",
    "LAST-RESORT probe — call this when pivot_extract returns ZERO/near-zero pivots or an "
    "empty-favicon/parked/NXDOMAIN page, i.e. WHOIS+FOFA+urlscan all came back empty. Never end "
    "a seed on a silent 'nothing found'. Keyless sweep of the corners that survive a dead front "
    "page: CT certs via the shared wp_ct client (SAN-sibling domains = strongest same-owner link), the full Wayback "
    "capture TIMELINE (parked-today was often a live scam last year), archive.today mementos, "
    "ready-to-run search dorks, and the local KB (already known/attributed?). Returns a VERDICT: "
    "PIVOTABLE (a lead survived), NO-PIVOT-YET (genuinely cold + explicit next steps), or "
    "INCONCLUSIVE-CT-DEGRADED (cold, but crt.sh was unreachable — CT not really swept; re-run).",
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
    "github_harvest",
    "Harvest COMMITTER IDENTITIES from GitHub for a user, organisation, repository or single commit "
    "URL — the one identity surface GitHub never redacts. For each repository it reads the commit "
    "history and fetches `<commit>.patch`, whose `From:` line is git's own record of the author's "
    "configured name and e-mail (a personal mailbox, a company address, or the "
    "`<id>+<login>@users.noreply.github.com` form that binds a numeric user id to a login — and "
    "reveals a FORMER login when the account was renamed). Sampling: a repository with more than "
    "10 commits contributes its FIRST 2 and LAST 2 (founder and current maintainer); shorter "
    "histories contribute every commit. For an organisation it also reads the about-profile "
    "(public e-mail, website, socials, location), the public member list and the top "
    "contributors' profile selectors, then walks every repository. Rails: identities seen only "
    "in FORKED repositories are upstream authors and never become pivots; bots are dropped; a "
    "commit e-mail identifies the COMMITTER, not necessarily the repository owner. Writes the "
    "harvest into cases/<case>/raw/github.com_<owner>.json (kb_ingest joins its e-mails on the "
    "same `email` node as WHOIS registrants and on-page contacts). FREE: 60 API calls/hour "
    "keyless, 5000 with GITHUB_TOKEN; GitHub is a vendor endpoint, never the hostile target.",
    {"target": str, "case": str},  # max_repos:int, max_contributors:int, patches:bool optional
)
async def github_harvest(args: dict[str, Any]) -> dict[str, Any]:
    target = str(args["target"]).strip()
    case = args["case"]
    raw_dir = os.path.join(ROOT, "cases", case, "raw")
    os.makedirs(raw_dir, exist_ok=True)
    owner = [x for x in target.replace("https://", "").replace("http://", "").replace("github.com/", "").split("/") if x]
    stem = "github.com_" + (owner[0] if owner else "target")
    out = os.path.join(raw_dir, stem + ".json")
    cmd = [PY, os.path.join("WebPivot", "tools", "wp_github.py"), target, "-o", out,
           "--max-repos", str(int(args.get("max_repos") or 30)),
           "--max-contributors", str(int(args.get("max_contributors") or 10))]
    if args.get("patches") is False:
        cmd.append("--no-patches")
    r = _run(cmd, timeout=900)
    data = _load_json(out)
    if data is None:
        return _err(f"github_harvest failed for {target}: {(r.stderr or '')[-500:]}")
    ids = [i for i in data.get("identities") or [] if i.get("kind") != "bot" and i.get("own_repo")]
    summary = (r.stderr or "").strip().split("\n")
    summary = "\n".join(ln for ln in summary if not ln.startswith("wrote "))[-6000:]
    return _ok(f"GitHub harvest on {target}: {len(data.get('repos') or [])} repo(s), "
               f"{len(ids)} committer identity(ies) from the target's own repositories, "
               f"{len(data.get('pivots') or [])} pivot(s). Written to {os.path.relpath(out, ROOT)} "
               f"for kb_ingest.\n{summary}", where=os.path.relpath(out, ROOT))


@tool(
    "subdomain_enum",
    "Enumerate a seed apex's SUBDOMAINS with the installed passive tools — subfinder (auto-keyed from "
    "the skill's .env: Shodan, SecurityTrails, WhoisXML, CertSpotter, FOFA, IntelX, GitHub, Netlas, "
    "and any other provider whose key is set), amass -passive, assetfinder, findomain — unions the "
    "names, DNS-verifies them and writes cases/<case>/subenum/<apex>.json. The frontier then queues "
    "the LIVE subdomains for next-round collection exactly like the apex (client., api., panel., "
    "shop.… are the same registration, so kb_ingest joins them to the apex on `apex:<registrable>`, "
    "rung 1); dead CT/archive names are recorded, not collected; hoster plumbing (cpanel, webmail, "
    "autodiscover…) is a fact, not a seed. `pipeline open` runs this once per apex automatically; "
    "call it directly to enumerate a new apex or re-run after adding provider keys. Egress goes to "
    "the enumeration providers only — the target is never touched here.",
    {"apex": str, "case": str},  # timeout:int optional
)
async def subdomain_enum(args: dict[str, Any]) -> dict[str, Any]:
    apex = _host(args["apex"])
    case = args["case"]
    case_dir = os.path.join(ROOT, "cases", case)
    os.makedirs(case_dir, exist_ok=True)
    cmd = [PY, os.path.join("WebPivot", "tools", "wp_subenum.py"), apex, "--case-dir", case_dir,
           "--timeout", str(int(args.get("timeout") or 240))]
    # keyless-only when asked, or when the case scope forbids spending metered credits
    # (case_scope.resolve stores the flag under `constraints`, never at the top level)
    scope = _load_json(os.path.join(case_dir, "scope.json")) or {}
    if _flag(args, "free_only") or (scope.get("constraints") or {}).get("no_spend"):
        cmd.append("--free-only")
    r = _run(cmd, timeout=900)
    out = os.path.join(case_dir, "subenum", apex + ".json")
    data = _load_json(out)
    if data is None:
        return _err(f"subdomain_enum failed for {apex}: {(r.stderr or '')[-500:]}")
    live = data.get("live") or []
    return _ok(f"subdomain enumeration on {apex}: {len(data.get('subdomains') or [])} name(s) via "
               f"{', '.join(data.get('tools') or []) or 'no tool installed'}; {len(live)} resolving → "
               f"queued for the next round by `case_frontier` (subdomains_pending). "
               f"{('subfinder keyed from .env: ' + ', '.join(data['provider_sync']['filled'])) if (data.get('provider_sync') or {}).get('filled') else ''}\n"
               f"live: {', '.join(live[:40])}{' …' if len(live) > 40 else ''}\n"
               f"{(r.stderr or '')[-2500:]}", where=os.path.relpath(out, ROOT))

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
    "dork queries across a switchable engine set (Google / Yandex / DuckDuckGo / Bing / Brave). By "
    "default it does NOT fetch — FIRE the queries with Claude Code's WebSearch (single-engine but "
    "free) and/or WebFetch the duckduckgo html URL (Google/Yandex bot-wall WebFetch). Pass run=true "
    "to EXECUTE them here instead: DuckDuckGo HTML first (free), per query; only a query the free "
    "path could not answer (bot challenge, HTTP error, unparseable page, or 0 hits on an operator "
    "DDG ignores: intext:/after:/before:) is re-run via SerpApi Google — 1 METERED search per such "
    "query, ledgered. `related:` is never bought (Google retired it) and is reported NOT ANSWERED. "
    "free_only=true (or no SERPAPI_KEY) never spends and "
    "marks those queries NOT ANSWERED. max_queries caps execution. Open the `directories` URLs "
    "directly, extract candidate hosts/handles from the results (`found_hosts` when run=true), and "
    "feed the NEW ones back into pivot_extract to close the keyword→search→infrastructure loop. Pass "
    "engines='google,yandex,duckduckgo' to pick engines; kind='domain'|'keyword'|'handle'|"
    "'discord_id' to override auto-detection.",
    {"indicator": str},  # engines:str, kind:str, run:bool, free_only:bool, max_queries:int optional
    annotations=READONLY,
)
async def search_pivot(args: dict[str, Any]) -> dict[str, Any]:
    cmd = [PY, os.path.join("tools", "search_pivot.py"), args["indicator"]]
    if args.get("engines"):
        cmd += ["--engines", str(args["engines"])]
    if args.get("kind"):
        cmd += ["--kind", str(args["kind"])]
    if _flag(args, "run"):
        cmd.append("--run")
        if _flag(args, "free_only"):
            cmd.append("--free-only")
        if args.get("max_queries"):
            cmd += ["--max-queries", str(int(args["max_queries"]))]
    r = _run(cmd, timeout=300 if _flag(args, "run") else 30)
    if r.returncode != 0:
        return _err(r.stderr or "search_pivot failed")
    return _ok(r.stdout or "search_pivot produced no output")


@tool(
    "corpus_search",
    "Run ONE cross-type corpus pivot route and ingest the typed rows into the case KB "
    "(owner edges; kit/neighbour/mention facts only — collecting is not attributing). "
    "`route` is a pivot_map key (urlscan.title, urlscan.identifier, wayback.telegram, "
    "wayback.pdf, wayback.news, fofa.body, publicwww.source, webamon.corpus, email.deep, "
    "phone.osint, rwhois.purchase, crypto.counterparties, anyrun.lookup, binary.analyze, "
    "ghw.git_code, ghw.git_committers, ghw.short_handle, …). "
    "`query` is the corpus query string (from pivot_routes.query_for or a hand-built Lucene/"
    "collection query). `case` scopes the ingest provenance. Owner-rung hits become KB edges; "
    "kit/neighbour/mention hits are stored as facts only (collecting ≠ attributing). Tri-state: "
    "rows+total, skipped (no key / free_only on metered), or error. free_only holds metered "
    "routes and forces urlscan onto the keyless path.",
    {"route": str, "query": str, "case": str},  # free_only:bool, origin_type:str, origin_value:str optional
    annotations=READONLY,
)
async def corpus_search(args: dict[str, Any]) -> dict[str, Any]:
    route = str(args.get("route") or "").strip()
    query = str(args.get("query") or "").strip()
    case = str(args.get("case") or "").strip()
    if not route or not query:
        return _err("corpus_search needs route= and query=")
    if not case:
        return _err("corpus_search needs case=<ID> so ingest provenance is scoped")
    free_only = _flag(args, "free_only") or SMOKE        # execute() also folds in no_spend
    hostile = bool(POLICY.get("hostile"))
    try:
        import pivot_routes as PR  # noqa: E402 — lazy: a missing module never blocks the surface
    except Exception as e:  # noqa: BLE001
        return _err(f"corpus_search imports failed: {e}")
    res = PR.execute(route, query, case=case,
                     origin_type=str(args.get("origin_type") or "string").strip() or "string",
                     origin_value=str(args.get("origin_value") or query).strip() or query,
                     free_only=free_only, hostile=hostile,
                     kb_root=KB_DIR if os.path.isabs(KB_DIR) else os.path.join(ROOT, KB_DIR))
    if not isinstance(res, dict) or not res:
        return _err("corpus_search: empty result")
    if res.get("error"):
        return _err(str(res["error"]))
    if res.get("ingest_error") or res.get("nodes_error"):
        # Hits came back but were not recorded — reporting success would hide lost evidence.
        return _err(f"corpus_search: {res.get('rows', 0)} row(s) found but NOT recorded — "
                    f"ingest: {res.get('ingest_error') or 'ok'}; nodes: {res.get('nodes_error') or 'ok'}")
    if res.get("skipped"):
        return _ok(json.dumps({"skipped": res["skipped"], "route": route, "query": query},
                              ensure_ascii=False))
    return _ok(json.dumps(res, ensure_ascii=False))


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
    """Statically analyze a binary. Case JSON lives in bin/analysis/<sha256>.json and is
    ingested separately from raw web-host evidence. Returns a summary dict, never raises."""
    import re
    import tempfile
    if POLICY["hostile"] and re.match(r"^https?://", target, re.I):
        return {"ok": False, "leads": "", "saved": None, "host": None,
                "error": (f"BLOCKED by egress policy: refusing a direct download of {target} on "
                          "hostile infra (it would touch attacker infra from your IP). Pull it from "
                          "non-attributable egress (research VPS/VPN) and re-call with the LOCAL path.")}
    script = os.path.join("BinaryPivot", "tools", "analyze_artifact.py")
    case_dir = os.path.join(ROOT, "cases", case) if case else None
    analysis_dir = os.path.join(case_dir, "bin", "analysis") if case_dir else None
    if analysis_dir:
        os.makedirs(analysis_dir, exist_ok=True)

    def _unlink(p):
        try:
            os.unlink(p)
        except OSError:
            pass

    # The case's temporary output is outside raw/ from the start.
    fd, tmp_out = tempfile.mkstemp(suffix=".json", prefix="binpivot_", dir=analysis_dir)
    os.close(fd)
    cmd = [PY, script, target, "--leads", "-o", tmp_out]
    if case:
        cmd += ["--case", case]
    # When a case is set, its bin/ is the canonical store the completeness gate and the sandbox
    # uploader both key off (save_analysis requires saved_to to live under <case>/bin). A custom
    # keep dir alongside a case would land the file where those checks can't find it, so the case
    # store wins; keep only applies to a case-less manual analysis.
    keep_dir = (os.path.join(ROOT, "cases", case, "bin") if case else keep)
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
    error = data.get("error")
    if case and not error:
        try:
            saved = binary_auto.save_analysis(case_dir, data)
            if saved is None:
                error = ("not a complete binary: truncated, non-2xx, non-binary, or the saved "
                         "file does not match its hash — nothing was stored or ingested")
            else:
                ingested, note = binary_auto.ingest(case_dir, os.path.join(ROOT, KB_DIR))
                if not ingested:
                    error = f"binary KB ingest failed: {note[-500:]}"
        except (OSError, ValueError) as exc:
            error = f"binary case save failed: {exc}"
    _unlink(tmp_out)
    prot = ((data.get("artifacts") or {}).get("binary") or {}).get("protection") or {}
    return {"ok": not error, "error": error, "leads": r.stdout or "",
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
    "JSON is saved under cases/<ID>/bin/analysis/<sha256>.json and explicitly ingested into the KB, "
    "without creating a web host row. For HOSTILE targets a direct URL download is refused — "
    "pull it from non-attributable egress and pass the local path.",
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

# The reverse-WHOIS AUTO-BUY cap: a preview count above it is treated as a bulk registrant and
# is not purchased without confirm=true. DATA, not code (RULE 3) — references/reverse_whois.json
# → rwhois_auto_cap. Read per call so an analyst's edit applies to the next gate decision.
_RWHOIS_FALLBACK = {"rwhois_auto_cap": {"value": 150}}
_RWHOIS_REF = _ref_path(__file__, "reverse_whois.json")


def _rwhois_auto_cap() -> int:
    """rwhois_auto_cap from references/reverse_whois.json (embedded fallback 150)."""
    node = _load_ref(_RWHOIS_REF, _RWHOIS_FALLBACK).get("rwhois_auto_cap")
    try:
        return int(node["value"] if isinstance(node, dict) else node)
    except (TypeError, ValueError, KeyError):
        return int(_RWHOIS_FALLBACK["rwhois_auto_cap"]["value"])


def _reverse_gate(kind: str, count: int, cap: int | None, confirm: bool) -> tuple[str, str]:
    """Decide what to do after a reverse-WHOIS PREVIEW (cheap count, no credits). Pure apart from
    reading the cap — `cap=None` means the reference rwhois_auto_cap — so the 'preview first, ask
    if it's a lot' logic is unit-tested. Returns (action, reason) with
    action ∈ {'empty','confirm','purchase'}."""
    if cap is None:
        cap = _rwhois_auto_cap()
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
    "count, no credits spent); if the term matches MORE than max_domains (default: the "
    "rwhois_auto_cap reference, references/reverse_whois.json) — a shared "
    "reseller/agency/registrar term = NOISE — it STOPS and asks you to confirm rather than spending "
    "credits to pull them, so re-call with confirm=true (and optionally a higher max_domains) to "
    "purchase anyway. Refuses a privacy/registrar email outright. kind = 'email' | 'name' | 'phone'.",
    {"term": str, "kind": str},  # max_domains:int (default rwhois_auto_cap), confirm:bool — optional
    annotations=READONLY,
)
async def reverse_whois(args: dict[str, Any]) -> dict[str, Any]:
    term = str(args["term"]).strip()
    kind = args.get("kind", "email")
    cap = int(args["max_domains"]) if args.get("max_domains") is not None else _rwhois_auto_cap()
    confirm = _flag(args, "confirm")
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
    if _flag(args, "free_only"):
        # free_only (a no_spend posture, or the gate's "re-call with free_only=true"): the free
        # count is the whole answer — the purchase is never made.
        return _ok(f"'{term}' ({kind}) → {count} domain(s) (preview count only — free_only: NOT "
                   f"purchased; propose the purchase for analyst approval if it is worth it).")
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
    "names are chosen by whoever controls the cert. Keyless CT via wp_ct (crt.sh, then Shodan CTL "
    "+ CertSpotter when crt.sh is down). Returns a VERDICT: SHARED-CERT / SAN cross-cover "
    "(decisive), SIBLING-OVERLAP (certs share a third registrable domain = strong), NO-CT-OVERLAP "
    "(clean negative: crt.sh answered for every input), or INCONCLUSIVE-CT-DEGRADED (crt.sh was "
    "unreachable — NOT a negative). Run this on candidate same-operator seeds before asserting a "
    "cluster — it either corroborates or refutes at the TLS layer.",
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
    if _flag(args, "free_only"):
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
    "by date, last=<N> to also list the most recent calls. Shows estimated units per cost class "
    "(free / quota / metered — WebPivot/references/api_cost_classes.json) and per provider / day / case. "
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
    if _flag(args, "all"):
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
    "case_enrich",
    "Run all machine-executable, target-matched identity/exposure leads already discovered in "
    "a case: registrant email profile, phone OSINT, keyed ChongLuaDao phone/Telegram/actor/org, "
    "IntelX phonebook and linked GitHub account — plus the MANDATORY LEAK FAN-OUT: every CONFIRMED "
    "selector (analyst seed, owner-rung node, first-round WHOIS registrant email/phone, owned seed "
    "domain, social-intake account username; never a kit/neighbour/co-tenant one) is checked "
    "against ChongLuaDao, IntelX, Hudson Rock (email → login/emails, domain → search-by-domain, "
    "username → login/usernames) and, for emails, the deep_profile breach chain. Writes cases/"
    "<case>/enrichment/leak_coverage.json: one row per selector × vendor, state hit | clean | "
    "not_consulted with the reason (missing key, free_only/no_spend hold, n/a for the type, "
    "retryable error). Consulted results are KB exposure facts (leak_exposure), never attribution "
    "edges. Results are checkpointed in cases/<case>/"
    "enrichment/; a finished lead closes as ran or empty, while missing-key, held, transient-error "
    "and query-only dork/secret leads stay OPEN for a later keyed run or analyst review; a rerun "
    "never re-buys a closed leg. This does "
    "not fetch the target or re-collect hosts. It SPENDS credits on metered legs unless free_only "
    "or the case's scope is no_spend (then only keyless CLD runs and metered vendors read "
    "not_consulted); passive is an egress posture and does NOT hold spend. leak_only=true runs "
    "just the leak fan-out (the harness runs it after round-1 collection, before frontier pivots).",
    {"case": str},  # free_only, passive, reopen_legacy, leak_only: bool optional (tool_params.json)
    annotations=ToolAnnotations(readOnlyHint=False),
)
async def case_enrich(args: dict[str, Any]) -> dict[str, Any]:
    cmd = [PY, os.path.join("tools", "intel.py"), "enrich", str(args["case"])]
    if _flag(args, "free_only"):
        cmd.append("--free-only")
    if _flag(args, "passive"):
        cmd.append("--passive")
    if _flag(args, "reopen_legacy"):
        cmd.append("--reopen-legacy")
    if _flag(args, "leak_only"):
        cmd.append("--leak-only")
    r = _run(cmd, timeout=1800)
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
    "case_approve",
    "Approve or reject the cross-type loop's PENDING pivot proposal for a case (cases/<case>/proposal.json) "
    "— the per-round consent step before any metered or oversized "
    "pivot runs. Two-step and ANALYST-ONLY: call with confirm omitted/false to get the BRIEFING "
    "(the proposal table: id, type, route, metered, estimated hits, rung, who proposed it and "
    "why), show it to the analyst, and only after they name what to approve re-call with "
    "confirm=true plus `only` (comma-separated ids) or all=true, and optionally `reject`. A "
    "harness phase can never approve its own pivots (the gate denies this tool outside "
    "interactive use). Approval is bound to the case state the proposal was made against: if the "
    "case moved on, it is refused as stale and the loop re-proposes. Resume with `harness continue`.",
    {"case": str},  # confirm:bool, only:str, all:bool, reject:str optional — tool_params.json
    annotations=ToolAnnotations(readOnlyHint=False),
)
async def case_approve(args: dict[str, Any]) -> dict[str, Any]:
    import proposal as _P  # harness/proposal.py — stdlib only
    case = str(args["case"]).strip()
    data = _P.load(ROOT, case)
    if not data or not data.get("items"):
        return _err(f"no proposal for {case} — nothing is awaiting approval")
    if not _flag(args, "confirm"):
        return _ok("BRIEFING — show this to the analyst; approve only what they name:\n"
                   + _P.render(data)
                   + "\n\nRe-call with confirm=true and only=<ids> (or all=true), optional reject=<ids>. "
                     "Unlisted items are DEFERRED (proposed again later); only reject=<ids> drops one for good.")
    split = lambda v: [x.strip() for x in str(v or "").replace(" ", ",").split(",") if x.strip()]  # noqa: E731
    res = _P.approve(ROOT, case, only=split(args.get("only")), reject=split(args.get("reject")),
                     approve_all=_flag(args, "all"))
    if res.get("error"):
        return _err(f"case_approve: {res['error']}")
    return _ok(f"approved {len(res.get('approved') or [])} · rejected {len(res.get('rejected') or [])} · "
               f"deferred {len(res.get('deferred') or [])} item(s) for {case} (only rejected ids are "
               f"dropped for good; deferred ones are proposed again). Resume with: harness continue {case}")


@tool(
    "cti",
    "Run the `cti` driver end-to-end on ONE target (domain, URL, email, phone, IP, hash or wallet). "
    "DEFAULT ENGINE = the cross-type harness loop: recall, then typed pivots on any seed type, a "
    "read-only Plan phase and per-round analyst approval of every metered pivot. A harness run "
    "takes tens of minutes, so this tool STARTS it in the background and returns at once with the "
    "case id, a log path and the status command — check `case_frontier`/`harness status`, and the "
    "analyst approves pending pivots with `case_approve`. When Quarry is on for the case (quarry=true, "
    "QUARRY_ENABLED=on, or a recorded yes) the driver first waits for the Quarry scan with no time "
    "limit (hours or days on a large estate — the wait survives network faults and resumes if "
    "interrupted) before any pivot spends the same vendor accounts, and the run is backgrounded on "
    "EVERY path, pipeline included, so the wait is not cut by the tool timeout. Ask the user before "
    "passing quarry=true when QUARRY_ENABLED=ask. pipeline=true (or quick=true) runs the "
    "deterministic pipeline instead (recall -> collect -> enrich -> frontier -> "
    "loop) and returns its machine-readable summary (case, status, converged, open_leads, next) "
    "as the LAST line. Called from inside a harness phase it always uses the pipeline (no "
    "recursion).",
    {"target": str},  # case, quick, deep, passive, free_only, extend optional — tool_params.json
    annotations=ToolAnnotations(readOnlyHint=False),
)
async def cti(args: dict[str, Any]) -> dict[str, Any]:
    target = str(args["target"])
    # Inside ANY harness run (SDK in-process tools have no HARNESS_PHASE; the orchestrator exports
    # INTEL_IN_HARNESS for every backend) the driver must never start a nested harness.
    in_harness = bool(os.environ.get("INTEL_IN_HARNESS") or os.environ.get("HARNESS_PHASE"))
    harness_path = not (_flag(args, "pipeline") or _flag(args, "quick") or _flag(args, "passive")
                        or in_harness)
    # A Quarry wait has no time limit — never inside the tool-call timeout, and never nested.
    case = str(args.get("case") or "") or ("" if in_harness else _cti_default_case(target))
    quarry_waits = not in_harness and _cti_waits_on_quarry(
        case, quarry=_flag(args, "quarry"), no_quarry=bool(args.get("no_quarry")))
    background = (harness_path or quarry_waits) and not in_harness
    cmd = [PY, os.path.join("tools", "intel.py"), "cti", target]
    if case:
        cmd += ["--case", case]
    if _flag(args, "quick"):
        cmd.append("--quick")
    if _flag(args, "deep"):
        cmd.append("--deep")
    if _flag(args, "passive"):
        cmd.append("--passive")
    if _flag(args, "free_only"):
        cmd.append("--free-only")
    if _flag(args, "extend"):
        cmd.append("--extend")
    if _flag(args, "quarry"):
        cmd.append("--quarry")
    if args.get("no_quarry"):
        cmd.append("--no-quarry")
    if args.get("pipeline") or (in_harness and not harness_path):
        cmd.append("--pipeline")
    if args.get("depth"):
        cmd += ["--depth", str(int(args["depth"]))]
    if background:
        # Background: the harness loop outlives the host's tool-call timeout. The driver itself
        # falls back to the pipeline if no backend answers. The case id is fixed HERE so the
        # analyst gets it now, not only when the run ends.
        log_dir = os.path.join(ROOT, "cases", case)
        os.makedirs(log_dir, exist_ok=True)
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        log_path = os.path.join(log_dir, f"cti_harness_{stamp}.log")
        with open(log_path, "w", encoding="utf-8") as log:
            subprocess.Popen(cmd, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT,
                             stdin=subprocess.DEVNULL, start_new_session=True)
        return _ok(f"cti started on {target} — case {case} — in the background"
                   + (" (waiting for Quarry first)" if quarry_waits else "")
                   + f". Log: {log_path}. Its last line is the JSON summary when it "
                   f"finishes; the case stops at `awaiting-approval` when paid pivots need the "
                   f"analyst — show the proposal (case_approve case={case}, no confirm) and approve "
                   f"only what they name. Status: `harness status {case}`.")
    r = _run(cmd, timeout=1800)   # pipeline: the driver may run a full collect+loop pass
    return {"content": [{"type": "text", "text": r.stdout or r.stderr or "no output"}],
            "is_error": r.returncode != 0}


def _cti_waits_on_quarry(case: str, *, quarry: bool, no_quarry: bool) -> bool:
    """True when the driver will block on a Quarry scan for this call: the same precedence as
    quarry_bridge.resolve_decision (flag -> recorded answer -> QUARRY_ENABLED) and the driver's
    skip when Quarry is unconfigured or switched off — read only, nothing is recorded. An
    undecided `ask` holds at once (`awaiting-quarry`), so it does not wait. The two flags are
    passed explicitly so the handler's args reads stay statically resolvable."""
    if no_quarry:
        return False
    if quarry:
        return True
    try:
        import quarry_bridge as qb
        mode = qb.q.quarry_mode()
        if mode == "off":
            return False
        recorded = qb.recorded_decision(case)
        return recorded if recorded is not None else mode == "on"
    except Exception:  # noqa: BLE001 — the driver's own Quarry import would fail too: no wait
        return False


def _cti_default_case(target: str) -> str:
    """The case id the `cti` driver derives for a target (tools/intel.py _default_case_for), so
    the background reply can name it. Loaded from the driver itself — one rule, not a copy."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "cti_driver_case_rule",    # code location, not the (overridable) data ROOT
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools", "intel.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod._default_case_for(target)

@tool(
    "quarry",
    "Quarry scan platform — a separate scanner that already holds, or will run, the vendor sweeps "
    "this skill would otherwise pay for again (same accounts). Call with only case+target to READ "
    "what Quarry already has and import it (free, no scan). start=true STARTS a scan when none "
    "exists: it crawls the target from Quarry's own egress and spends the shared vendor accounts, "
    "so ask the user first — and it is refused on a no-spend or no-contact case. A scan takes "
    "minutes to days; this call waits at most wait_minutes (default 20) and persists the job, so "
    "call again to resume the same wait rather than scanning twice. The long wait belongs to the "
    "`cti` driver (quarry=true), which blocks on Quarry before any pivot. Non-domain selectors are "
    "looked up in Quarry's corpus, never scanned. Imported rows go through the rung table: owner "
    "links become edges, co-tenancy and kit matches become facts only.",
    {"case": str, "target": str},   # start, wait_minutes, free_only — tool_params.json
    annotations=ToolAnnotations(readOnlyHint=False),
)
async def quarry(args: dict[str, Any]) -> dict[str, Any]:
    case = str(args.get("case") or "").strip()
    target = str(args.get("target") or "").strip()
    if not case or not target:
        return _err("quarry needs `case` and `target`.")
    if os.environ.get("INTEL_IN_HARNESS") or os.environ.get("HARNESS_PHASE"):
        if _flag(args, "start"):
            return _err("quarry start=true is refused inside a harness phase — the `cti` driver "
                        "owns the Quarry wait, and a phase must not start a second scan.")
    cmd = [PY, os.path.join("tools", "quarry_bridge.py"), "sync",
           "--case", case, "--target", target]
    if _flag(args, "start"):
        cmd.append("--quarry-scan")
    if _flag(args, "free_only"):
        cmd.append("--free-only")
    wait = args.get("wait_minutes")
    cmd += ["--wait-minutes", str(int(wait) if wait else 20)]
    r = _run(cmd, timeout=max(300, (int(wait) if wait else 20) * 60 + 180))
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
    "mode='item' OPENS one record: `selector` = the record's `storageid`, plus `bucket` (and "
    "optionally `media` = its `media_id`, `ctype` = its `type`, `lines`, `systemid`) — returns a "
    "bounded, REDACTED text preview (/file/preview; metered, usually paid-only). A search hit COUNT "
    "only says the selector appears in the leak corpus; an infection/compromise claim MUST cite an "
    "opened item. Every search returns `status`: 'clean' = IntelX finished every pass; "
    "'partial (deadline)' / 'partial (poll limit)' / 'partial (budget)' = only what arrived before "
    "the stop — missing records are NOT negatives. The whole search runs under one deadline "
    "proportional to the buckets searched (override with `deadline` seconds). "
    "METERED and capped per run. With no INTELX_KEY the layer still runs at ~50%: it classifies the "
    "selector and returns the intelx.io / phonebook.cz URL to run by hand — say so rather than "
    "reporting an empty result as 'not in any leak'.",
    {"selector": str},  # mode:'search'|'phonebook'|'item'|'budget', buckets, logs_only, max,
                        # deadline, target; item: bucket, media, ctype, lines, systemid -> args.get()
    annotations=READONLY,
)
async def intelx_search(args: dict[str, Any]) -> dict[str, Any]:
    script = os.path.join("WebPivot", "tools", "wp_intelx.py")
    mode = str(args.get("mode") or "search").lower()
    sel = str(args["selector"])
    # The collector enforces its OWN deadline and returns a partial result when it expires; the
    # wrapper must outlive that (cap + grace), never kill it first and lose the partial page.
    limits = _load_ref(os.path.join(ROOT, "WebPivot", "references", "intelx.json"),
                       {"result_limits": {"deadline_max_seconds": 900}})["result_limits"]
    deadline = int(args.get("deadline") or limits.get("deadline_max_seconds", 900))
    if mode == "budget":
        cmd = [PY, script, "budget"]
    elif mode == "phonebook":
        cmd = [PY, script, "phonebook", sel]
        if args.get("target"):
            cmd += ["--target", str(args["target"])]
    elif mode == "item":
        if not args.get("bucket"):
            return _err("intelx_search mode='item' needs `bucket` (and `selector` = the record's "
                        "storageid) — both are on every search records/read_these row.")
        cmd = [PY, script, "item", sel, "--bucket", str(args["bucket"])]
        for flag, key in (("--media", "media"), ("--type", "ctype"), ("--lines", "lines")):
            if args.get(key) not in (None, ""):
                cmd += [flag, str(int(args[key]))]
        if args.get("systemid"):
            cmd += ["--systemid", str(args["systemid"])]
    else:
        cmd = [PY, script, "search", sel]
        if args.get("buckets"):
            cmd += ["--buckets", str(args["buckets"])]
        elif _flag(args, "logs_only"):
            cmd += ["--logs-only"]
        if args.get("deadline"):
            cmd += ["--deadline", str(deadline)]
    if args.get("max") and mode in ("search", "phonebook"):
        cmd += ["--max", str(int(args["max"]))]
    r = _run(cmd, timeout=deadline + 120)
    if r.returncode != 0 and not r.stdout:
        # rc=2 is the documented KEYLESS path: the stderr block explains what was not queried and
        # gives the UI URL. That is information, not a failure — surfacing it as an error would
        # teach the model to stop asking.
        return _ok((r.stderr or "intelx produced no output") +
                   "\n\n(Keyless/limited IntelX: nothing was queried. Do NOT report this as "
                   "'the selector appears in no leak' — run the URL above by hand.)")
    return _ok((r.stdout or "") + ("\n" + r.stderr if r.stderr else ""))


@tool(
    "grayhatwarfare",
    "GrayHatWarfare — three corpora behind one key, every hit EXPOSURE or a LEAD, never a same-operator "
    "edge. mode='exposure' (default; `selector` = case domain(s), needs `case`) runs the per-apex sweep "
    "the pipeline auto-fires: open S3/Azure/GCS/Spaces buckets for the brand label, every host the "
    "SHORTENER corpus saw under the apex, the historical long URLs those short links expanded to "
    "(hidden paths, documents, invite/ref params — run url_paths mode='patterns' over "
    "cases/<case>/grayhatwarfare/short_urls.json), and git committers whose author e-mail is on the "
    "apex. Single lookups: 'buckets'/'files' (keyword); 'short_subdomains' (apex); 'short_urls' "
    "(comma list of EXACT hosts, optional `ext`); 'short_handle' (t.me/<h>, @h, wa.me/<n>, +<n> — the "
    "short links an operator spread for that handle); 'git_committers' (an e-mail, or a SELF-HOSTED "
    "mail domain — managed mail like gmail.com is refused); 'git_code' (a distinctive token: tracker "
    "id, wallet, API host — only rows with verified=true, raw file fetched and token present, are "
    "code reuse = same KIT; the index tokenises, the rest are mentions); 'git_secrets' (owner/repo or "
    "repo URL — files TruffleHog flagged, tags and commits only, never the secret); 'account' (plan "
    "tier, free). The shortener corpus is historical (discovered 2017–2025): a hit proves a URL existed "
    "and was shared, never that it is live. Git author e-mails are self-asserted: confirm a committer "
    "with github_harvest before naming anyone. With `case` results persist under "
    "cases/<case>/grayhatwarfare/ and land in the KB as facts only. Keyless it returns the site: dork "
    "to run by hand — never report that as 'no exposure'.",
    {"selector": str},  # mode, case, limit, ext -> args.get()
    annotations=READONLY,
)
async def grayhatwarfare(args: dict[str, Any]) -> dict[str, Any]:
    script = os.path.join("tools", "ghw_exposure.py")
    mode = str(args.get("mode") or "exposure").lower().replace("-", "_")
    sel = str(args.get("selector") or "")
    case = str(args.get("case") or "")
    if mode == "exposure":
        if not case:
            return _err("grayhatwarfare mode='exposure' needs `case` — it persists into "
                        "cases/<case>/grayhatwarfare/; use a single-lookup mode without one.")
        cmd = [PY, script, "exposure", case, *sel.replace(",", " ").split()]
    else:
        cmd = [PY, script, "lookup", mode, sel]
        if case:
            cmd += ["--case", case]
        if args.get("limit"):
            cmd += ["--limit", str(int(args["limit"]))]
        if args.get("ext"):
            cmd += ["--ext", str(args["ext"])]
    r = _run(cmd, timeout=900)
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
    "unless the analyst separately authorizes it. PLAN GATE: the engine reads the key's own account "
    "record (/user private quota, else a prior private task in history) and FAILS CLOSED without "
    "proof (`refused` + `plan_evidence`); a ZERO private quota is denied outright. Only if the "
    "analyst explicitly attests to a paid plan pass allow_unverified_plan=true — never set it on "
    "your own. READ-BACK: after the POST the engine waits (bounded) for the task to finish and reads "
    "the privacy ANY.RUN applied; a forbidden mode is withdrawn and flagged `exposed`. If the result "
    "says privacy_verified=null with a `verify_command`, the task was still running — call again "
    "with verify_task=true and target=<task uuid> to finish the check (nothing is submitted). NEVER "
    "put a case ID or an analyst/client name in `tags` or the filename. kind='file' (a local path) "
    "or 'url'.",
    {"target": str},  # kind, confirm, privacy, allow_public, allow_unverified_plan, tags, verify_task:bool, wait:int
    annotations=ToolAnnotations(readOnlyHint=False),
)
async def anyrun_submit(args: dict[str, Any]) -> dict[str, Any]:
    script = os.path.join("BinaryPivot", "tools", "bp_anyrun.py")
    if _flag(args, "verify_task"):
        # Follow-up read-back for a task that was still running at submit time: `target` is the
        # task uuid. Nothing is submitted; a task that landed in a forbidden mode is withdrawn.
        wait = max(0, min(int(args.get("wait", 0) or 0), 240))   # 240 + one 30 s poll < the 290 s _run budget
        cmd = [PY, script, "verify-privacy", str(args["target"]), "--wait", str(wait)]
        if args.get("privacy"):
            cmd += ["--requested", str(args["privacy"])]
        r = _run(cmd, timeout=290)
        return _ok((r.stdout or "") + ("\n" + r.stderr if r.stderr else ""))
    kind = str(args.get("kind") or ("url" if str(args["target"]).startswith(("http://", "https://"))
                                    else "file")).lower()
    cmd = [PY, script, "submit", str(args["target"])]
    if kind == "url":
        cmd.append("--url")
    confirmed = _flag(args, "confirm")
    if confirmed:
        cmd.append("--confirm-submission")
    if args.get("privacy"):
        cmd += ["--privacy", str(args["privacy"])]
    if args.get("allow_public"):
        cmd.append("--allow-public")
    if args.get("allow_unverified_plan"):
        cmd.append("--i-have-a-paid-plan")
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


@tool(
    "webamon_scan",
    "Submit a URL to the Webamon sandbox and follow it to a report + same-kit siblings. **YOU MUST "
    "ASK THE USER FIRST, EVERY TIME.** Call with confirm=false (or omitted) to get the RISK BRIEFING "
    "(nothing is sent), show it, and only call again with confirm=true after an explicit yes to THIS "
    "submission. How it differs from anyrun_submit: the fetch comes from Webamon's OWN egress, so "
    "your IP never touches the target (posture-safe on hostile infrastructure) — but every scan is "
    "indexed into the PUBLIC searchable Webamon corpus with no private mode and no delete, and the "
    "operator sees a datacenter visit. The corpus is world-readable, so what is disclosed is the URL "
    "ITSELF: the query string/fragment (where a phishing link carries the victim id or one-time "
    "token) is STRIPPED by default and the briefing shows the exact `will_submit` — pass "
    "keep_query=true only when the analyst explicitly decides the full URL may be public. TRY "
    "FIRST: pivot_extract already reads the corpus (`webamon` block) — a host scanned recently needs "
    "no submission. Never submit a URL whose path carries a victim token or a case ID. Indexing "
    "takes ~1-5 min: the tool polls by report_id (wait, default 240 s) and a still-pending result "
    "returns the report_id for a later wp_webamon.py report <id> — nothing is re-submitted. "
    "Free-keyed; the vendor's 429 is the limit.",
    {"target": str},  # confirm:bool, wait:int, keep_query:bool optional
    annotations=ToolAnnotations(readOnlyHint=False),
)
async def webamon_scan(args: dict[str, Any]) -> dict[str, Any]:
    script = os.path.join("WebPivot", "tools", "wp_webamon.py")
    confirmed = _flag(args, "confirm")
    wait = max(0, min(int(args.get("wait", 240) or 0), 240))   # + one poll < the 290 s _run budget
    cmd = [PY, script, "scan", str(args["target"]), "--wait", str(wait)]
    if confirmed:
        cmd.append("--confirm-submission")
    if args.get("keep_query"):
        cmd.append("--keep-query")
    r = _run(cmd, timeout=290)
    body = (r.stdout or "") + ("\n" + r.stderr if r.stderr else "")
    if not confirmed:
        # rc=3 is the gate firing — the DESIGNED outcome. Returned as ok so the model is never
        # nudged to retry with confirm=true on its own.
        return _ok("NOTHING WAS SUBMITTED — confirmation required.\n"
                   "Show the briefing below to the analyst, ask explicitly whether to submit this URL "
                   "to the PUBLIC Webamon corpus, and only then call webamon_scan again with "
                   "confirm=true.\n\n" + body)
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
    if _flag(args, "confirm") and os.environ.get("INTEL_ENGAGE_CONFIRM") == "1":
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


@tool(
    "collection_gaps",
    "HAS THIS SEED BEEN WORKED, OR ONLY TRIAGED? Reads the case's STORED collections — no "
    "network, no credits, no key — and reports which evidence layers have actually run against "
    "each host and which never did, what each absence removes from the case, and the exact "
    "command that closes it (cheapest first). Call it after the first collection on a seed and "
    "again before writing the assessment. Why it matters: the deep layers are opt-in flags, so a "
    "run reliably gets the fetch, WHOIS, CT, archive and the reverse indexes, and reliably skips "
    "the leak/stealer-log corpus (IntelX), the advertising + cloaking probe, the lookalike hunt "
    "and document metadata — measured across this repo's stored collections, IntelX had run on "
    "exactly one. A correlation pass over a triage-depth collection is then scrupulous about "
    "every artifact it has and silent about the search space it never entered, so 'no further "
    "links found' reads as a finding when it is a statement about which flags were passed. "
    "Verdict is `exhausted`, `triage`, `failed` (the collector crashed/timed out — RE-RUN it, "
    "never report the host as collected-empty) or `skipped` (withheld by policy: onion/hostile). "
    "Each gap carries its execution status — error/timed_out (FAILED, re-runnable, listed under "
    "RE-RUNNABLE with failed enrichment leads), skipped_policy (free-only/no_spend/hostile/onion) "
    "or skipped_no_key (set the named key). A `triage` verdict must be STATED in the assessment, "
    "and a layer that did not run is absence of COLLECTION, never absence of evidence. Pass "
    "case; optional host to check one, json for the raw structure.",
    {"case": str},   # host:str, json:bool optional -> args.get()
    annotations=READONLY,
)
async def collection_gaps(args: dict[str, Any]) -> dict[str, Any]:
    cmd = [PY, os.path.join("WebPivot", "tools", "wp_exhaust.py"), str(args["case"])]
    if args.get("host"):
        cmd.append(str(args["host"]))
    if args.get("json"):
        cmd.append("--json")
    r = _run(cmd, timeout=90)
    out = (r.stdout or "") + (("\n" + r.stderr) if r.stderr else "")
    if r.returncode != 0 and not (r.stdout or "").strip():
        return _err(f"collection_gaps failed for {args['case']}: {(r.stderr or '')[-300:]}")
    return _ok(out or "collection_gaps produced no output")


@tool(
    "origin_history",
    "THE HOSTING HISTORY of a case's collected hosts — every address each domain/subdomain has EVER "
    "resolved to, merged from live DNS, passive DNS (CIRCL, HackerTarget), SecurityTrails history, "
    "Validin, urlscan's hostname index and scans, Webamon and passive SSL, dated (first/last seen) "
    "and classified: `origin` (a box the operator rented), `ambiguous` (a network that sells DDoS "
    "proxying AND servers — DDoS-Guard, StackPath), or suppressed as a CDN/WAF edge, parking farm or "
    "bogon (counts only). Each origin carries its era — current / recent / historical / undated / "
    "previous_owner (last seen before the current registration: someone else's box) — and whether "
    "it was already collected as an IP seed. Use it to find the real server behind a CDN-fronted "
    "host and to date a shared-IP claim before making it. Offline: reads the stored collections, no "
    "network, no credits. Pass case; optional host.",
    {"case": str},   # host:str optional -> args.get()
    annotations=READONLY,
)
async def origin_history(args: dict[str, Any]) -> dict[str, Any]:
    cmd = [PY, os.path.join("WebPivot", "tools", "wp_origin_history.py"), str(args["case"])]
    if args.get("host"):
        cmd += ["--host", str(args["host"])]
    r = _run(cmd, timeout=90)
    if r.returncode != 0:
        return _err(f"origin_history failed for {args['case']}: {(r.stderr or r.stdout or '')[-300:]}")
    return _ok(r.stdout or "[]")


# ---------------------------------------------------------------- IntelShare (MISP dissemination)
_SHARE = os.path.join("IntelShare", "tools")


@tool(
    "misp_export",
    "BUILD the MISP event for a case — offline, sends nothing, and is the step that decides what "
    "may be shared at all. Reads the case's collected pivots and its intake scope, maps each "
    "artifact through IntelShare/references/misp.json and splits everything three ways: `auto` "
    "(infrastructure the operator provisioned — domains, kit routes, file hashes, favicon/JARM/"
    "cert fingerprints, owner-provisioned tracker ids), `review` (PERSONAL DATA — registrant name/"
    "email/phone, page emails, identity handles — plus values derived from a third party rather "
    "than observed by us; these are approved VALUE BY VALUE via review_value, never in bulk), and "
    "`never` (page context, generated lookalike candidates, shared platform noise). Base rates are "
    "a sharing control here: a parking favicon, a registrar contact, a platform tracker id and "
    "every third_party_host are refused, because published with to_ids they become other people's "
    "wrong blocking rules. OWNERSHIP first — a `victim_host` or `benign_check` case is REFUSED "
    "outright (a compromised site's WHOIS/favicon/cert belong to the victim). Show the analyst "
    "the summary, especially the review list and the to_ids count, before proposing any push. "
    "Pass case; optional host (space/comma-separated), info (the event headline — never a case "
    "id), label, tlp, confidence (the ICD-203 term), distribution (the level to REQUEST — the "
    "push still stages at 0), include_review, review_value (one approved value; repeatable as a "
    "space-separated list), threat_level, analysis.",
    {"case": str},
    annotations=READONLY,
)
async def misp_export(args: dict[str, Any]) -> dict[str, Any]:
    cmd = [PY, os.path.join(_SHARE, "sh_export.py"), str(args["case"]), "--leads"]
    for flag, key in (("--info", "info"), ("--label", "label"), ("--tlp", "tlp"),
                      ("--confidence", "confidence")):
        if args.get(key):
            cmd += [flag, str(args[key])]
    for flag, key in (("--threat-level", "threat_level"), ("--analysis", "analysis"),
                      ("--distribution", "distribution")):
        if args.get(key) is not None and str(args.get(key)) != "":
            cmd += [flag, str(int(args[key]))]
    for host in str(args.get("host") or "").replace(",", " ").split():
        cmd += ["--host", host]
    for val in str(args.get("review_value") or "").replace(",", " ").split():
        cmd += ["--review-value", val]
    if args.get("include_review"):
        cmd += ["--include-review"]
    r = _run(cmd, timeout=120)
    out = (r.stdout or "") + (("\n" + r.stderr) if r.stderr else "")
    if r.returncode != 0 and not (r.stdout or "").strip():
        return _err(f"misp_export failed for {args['case']}: {(r.stderr or '')[-400:]}")
    return _ok(out + "\n\nNOTHING HAS BEEN SENT. Sharing is a separate, confirmed step "
                     "(misp_push stages; misp_publish shares).")


@tool(
    "misp_search",
    "Ask the MISP instance whether an indicator is ALREADY KNOWN there — read-only, sends nothing "
    "of the case, safe to call unattended, and the cheapest useful question before proposing to "
    "publish anything: a value the community already holds does not need re-sharing, and a value "
    "nobody has is the one worth the trouble. Returns the matching attributes with their event "
    "ids, types and to_ids flags. A failure is a CHANNEL failure — absence of an answer, never "
    "evidence the value is unknown — and with no MISP_URL/MISP_KEY it says the channel is absent "
    "rather than reporting silence as 'not seen before'. Pass value; optional type (a MISP "
    "attribute type such as domain/sha256/ip-dst) and limit.",
    {"value": str},
    annotations=READONLY,
)
async def misp_search(args: dict[str, Any]) -> dict[str, Any]:
    cmd = [PY, os.path.join(_SHARE, "sh_misp.py"), "search", str(args["value"])]
    if args.get("type"):
        cmd += ["--type", str(args["type"])]
    if args.get("limit"):
        cmd += ["--limit", str(int(args["limit"]))]
    r = _run(cmd, timeout=90)
    if r.returncode != 0 and not (r.stdout or "").strip():
        return _err(f"misp_search failed: {(r.stderr or '')[-300:]}")
    return _ok((r.stdout or "") + (("\n" + r.stderr) if r.stderr else ""))


@tool(
    "misp_push",
    "STAGE an exported event on the MISP instance. **YOU MUST ASK THE ANALYST FIRST, EVERY TIME.** "
    "Call it with confirm=false (or omitted) to get the BRIEFING — instance, event headline, tags, "
    "attribute counts by type, how many carry to_ids (i.e. how many become somebody's blocking "
    "rule), what is held back, and the case's intake caveat — then show that briefing to the "
    "analyst and only call again with confirm=true after they say yes to THIS event. Working a "
    "case is not consent to share it. What this does and does not do: it CREATES (or updates) the "
    "event at distribution 0 — your organisation only — and published=false, and that clamp is "
    "enforced in code, so asking for a wider distribution here still stages. Nobody outside your "
    "organisation sees it, no sync happens, and the event can be deleted; SHARING is the separate "
    "misp_publish step. Values classed `review` are not included unless the export already "
    "approved them by value. Pass case (uses the case's newest export) or event_file=<path>; "
    "optional event_id to update an existing event, confirm, dry_run (prints the exact request "
    "and sends nothing), and publish=true + distribution=<level> to run the sharing step in the "
    "same call — that still needs INTEL_MISP_PUBLISH=1, and without the lock the event simply "
    "stays staged and says so. The event is built to the MISP standard: OBJECTS where several "
    "values describe one thing (a `whois` record, a `domain-ip` resolution), dated attributes, "
    "and an EVENT REPORT stating what was collected, what was withheld and why, and whether the "
    "collection was exhaustive or only a triage.",
    {},   # case, event_file, event_id, confirm, dry_run, publish, distribution -> args.get()
    annotations=ToolAnnotations(readOnlyHint=False),
)
async def misp_push(args: dict[str, Any]) -> dict[str, Any]:
    path = str(args.get("event_file") or "")
    case = str(args.get("case") or "")
    if not path:
        if not case:
            return _err("misp_push needs case=<ID> or event_file=<path>.")
        found = sorted(glob.glob(os.path.join(ROOT, "cases", case, "misp", "event-*.json")))
        if not found:
            return _err(f"no exported event for case {case} — run misp_export first (it is "
                        f"offline and sends nothing).")
        path = found[-1]
    cmd = [PY, os.path.join(_SHARE, "sh_misp.py"), "push", path]
    if case:
        cmd += ["--case", case]
    if args.get("event_id"):
        cmd += ["--event-id", str(args["event_id"])]
    if args.get("dry_run"):
        cmd += ["--dry-run"]
    if _flag(args, "publish"):
        cmd += ["--publish", "--distribution", str(int(args.get("distribution") or 1))]
    confirmed = _flag(args, "confirm")
    if confirmed:
        cmd += ["--confirm-push"]
    r = _run(cmd, timeout=180)
    body = (r.stdout or "") + (("\n" + r.stderr) if r.stderr else "")
    if not confirmed:
        return _ok("NOTHING WAS SENT — confirmation required.\nShow the briefing below to the "
                   "analyst, ask explicitly whether to stage these indicators on MISP, and only "
                   "then call misp_push again with confirm=true.\n\n" + body)
    return _ok(body)


@tool(
    "misp_publish",
    "SHARE a staged MISP event — raise its distribution and publish it. **IRREVERSIBLE, and you "
    "MUST ASK THE ANALYST FIRST, EVERY TIME**, including which audience they mean. Publishing "
    "pushes the event to every server the instance synchronises with and notifies subscribers; "
    "deleting your copy afterwards deletes nothing of theirs, and the to_ids attributes become "
    "other people's blocking rules. Without confirm=true it returns only the BRIEFING (audience "
    "for the requested level, attribute counts, which values are personal data, what cannot be "
    "undone) and does nothing. The harness ALSO requires env INTEL_MISP_PUBLISH=1, which an agent "
    "loop cannot set for itself: with confirm but no lock it says so and still sends nothing — "
    "ask the analyst, then the run must be re-launched with the lock. Distribution: 1 this "
    "community, 2 connected communities, 3 all communities (treat as public), 4 a named sharing "
    "group (needs sharing_group_id). Before proposing this, misp_search the strong indicators — "
    "re-sharing what the community already holds adds noise — and on threat-actor infrastructure "
    "coordinate first, because publishing can collide with somebody else's live operation. Pass "
    "event_id; distribution; optional sharing_group_id, case (for the local share ledger), "
    "confirm, dry_run.",
    {"event_id": str},   # distribution:int, sharing_group_id:str, case:str, confirm:bool, dry_run:bool
    annotations=ToolAnnotations(readOnlyHint=False),
)
async def misp_publish(args: dict[str, Any]) -> dict[str, Any]:
    cmd = [PY, os.path.join(_SHARE, "sh_misp.py"), "publish", str(args["event_id"]),
           "--distribution", str(int(args.get("distribution") or 1))]
    if args.get("sharing_group_id"):
        cmd += ["--sharing-group-id", str(args["sharing_group_id"])]
    if args.get("case"):
        cmd += ["--case", str(args["case"])]
    if args.get("dry_run"):
        cmd += ["--dry-run"]
    confirmed = _flag(args, "confirm")
    # confirm is honoured only alongside the env second-lock; sh_misp re-checks it and returns the
    # briefing with `blocked_by` when the lock is absent, so the model is told WHY rather than
    # silently retrying.
    if confirmed:
        cmd += ["--confirm-publish"]
    r = _run(cmd, timeout=180)
    body = (r.stdout or "") + (("\n" + r.stderr) if r.stderr else "")
    if not confirmed:
        return _ok("NOTHING WAS PUBLISHED — confirmation required.\nShow the briefing below to "
                   "the analyst, ask explicitly whether these indicators should be shared and "
                   "with WHICH audience, and only then call misp_publish with confirm=true (the "
                   "run must also have INTEL_MISP_PUBLISH=1).\n\n" + body)
    return _ok(body)


# ── repo-root collectors (scripts/webpivot/, one level above this engine) ─────────────
# These worked but were reachable only as raw `python3 …` lines in techniques/web-pivot.md,
# so neither front-end could call them (CLAUDE.md RULE 3). Registered 2026-08-27.
def _rr(name: str) -> str:
    """Path to a repo-root scripts/webpivot collector, relative to ROOT (= intel_engine/)."""
    return os.path.join("..", "scripts", "webpivot", name)


@tool(
    "cert_pivot",
    "Pivot on a TLS LEAF-CERTIFICATE FINGERPRINT to find the other hosts serving the SAME cert — "
    "the opposite direction from CT enumeration, which only lists one domain's own certs. Give it "
    "`domain` to fetch the live cert and pivot, or an explicit `sha1`/`sha256` you already hold "
    "(`serial` = hex x509 serial for the FOFA cert.sn query; FOFA cannot search fingerprints). "
    "Also mines the cert's SAN list, which is often where sibling domains are named outright. The "
    "fingerprint is computed KEYLESS from a stdlib TLS handshake, and the CT history (crtsh block: "
    "ct_status + completeness_line) needs no key either; Shodan/Censys keys only widen the search. "
    "Every hit is in `related_hosts`, graded by agreeing origin checks (Host-header probe, cert, "
    "history, non-CDN) — a related host, never the target's hosting or abuse contact. Shared hosting "
    "and CDN certs are served by thousands of unrelated hosts — treat a match on a wildcard or CDN "
    "cert as noise, not as a same-operator link.",
    {"domain": str},  # sha1, sha256, serial, no_live, passive, proxy, no_crtsh, cap
    annotations=READONLY,
)
async def cert_pivot(args: dict[str, Any]) -> dict[str, Any]:
    cmd = [PY, _rr("cert_pivot.py")]
    if args.get("domain"):
        cmd.append(str(args["domain"]))
    for k in ("sha1", "sha256", "serial"):
        if args.get(k):
            cmd += [f"--{k}", str(args[k])]
    if args.get("no_live") or args.get("passive"):
        cmd.append("--passive")
    if args.get("proxy") and not args.get("passive"):
        cmd += ["--proxy", str(args["proxy"])]
    if args.get("no_crtsh"):
        cmd.append("--no-crtsh")
    if args.get("cap"):
        cmd += ["--cap", str(args["cap"])]
    r = _run(cmd)
    return {"content": [{"type": "text", "text": r.stdout or r.stderr}], "is_error": r.returncode != 0}


@tool(
    "rank_relations",
    "Score and rank SAME-OPERATOR relations between the pages already collected into a case. Feed "
    "it `inputs` — the pivot_extract JSON a case has written (typically `cases/<CASE>/raw/*.json`, "
    "space-separated or a glob). For every pair of hosts it sums the weighted strength of the "
    "artifacts they share (tracker ID, favicon hash, wallet, registrant email, origin IP, cert, DOM "
    "template …) after dropping ubiquitous CDN/analytics/font infrastructure via the noise denylist. "
    "This MECHANIZES the rule that one shared artifact is a lead and two independent ones are a "
    "cluster — run it before asserting any cluster by eye. Pure post-processing, no network.",
    {"inputs": str},  # min_strength:int, include_weak:bool, md:bool
    annotations=READONLY,
)
async def rank_relations(args: dict[str, Any]) -> dict[str, Any]:
    cmd = [PY, _rr("rank_relations.py"), *str(args.get("inputs") or "").split()]
    if args.get("min_strength"):
        cmd += ["--min-strength", str(args["min_strength"])]
    if args.get("include_weak"):
        cmd.append("--include-weak")
    if args.get("md"):
        cmd.append("--md")
    r = _run(cmd)
    return {"content": [{"type": "text", "text": r.stdout or r.stderr}], "is_error": r.returncode != 0}


@tool(
    "pivot_suggest",
    "Rank WHAT TO PIVOT ON NEXT from a case's findings — the triage step between a collection round "
    "and the next one, so the expensive query goes to the highest-yield selector instead of the "
    "first one you noticed. Takes a `findings` JSON path, or ad-hoc comma-separated `usernames` / "
    "`emails` / `names` / `domains` / `cjk` when you have not written findings yet. Returns the "
    "selectors ordered by expected yield with the reason each was ranked where it was. Pure "
    "reasoning over what you already hold — no network, no credits.",
    {},  # findings:str, usernames:str, emails:str, names:str, domains:str, cjk:str
    annotations=READONLY,
)
async def pivot_suggest(args: dict[str, Any]) -> dict[str, Any]:
    cmd = [PY, _rr("pivot_suggest.py")]
    if args.get("findings"):
        cmd.append(str(args["findings"]))
    for k in ("usernames", "emails", "names", "domains", "cjk"):
        if args.get(k):
            cmd += [f"--{k}", str(args[k])]
    r = _run(cmd)
    return {"content": [{"type": "text", "text": r.stdout or r.stderr}], "is_error": r.returncode != 0}


@tool(
    "crypto_balance",
    "On-chain BALANCE and lifetime-flow enrichment for wallet `addresses` (comma- or space-"
    "separated). Auto-detects the chain per address, or force it with `coin` "
    "(btc/eth/ltc/trx/ada/dot/bch/doge/dash/zec/xmr). Turns a wallet string scraped off a scam page "
    "into evidence of SCALE — total received, transaction count, first/last activity — which is what "
    "separates a live cash-out address from a decorative one copied off another kit. Read-only "
    "public block-explorer queries; it never broadcasts anything.",
    {"addresses": str},  # coin:str
    annotations=READONLY,
)
async def crypto_balance(args: dict[str, Any]) -> dict[str, Any]:
    addrs = str(args.get("addresses") or "").replace(",", " ").split()
    cmd = [PY, _rr("crypto_balance.py"), *addrs]
    if args.get("coin"):
        cmd += ["--coin", str(args["coin"])]
    r = _run(cmd)
    return {"content": [{"type": "text", "text": r.stdout or r.stderr}], "is_error": r.returncode != 0}


@tool(
    "email_hygiene",
    "Grade the DOMAIN behind one or more `emails` 0-100 and A-F, deterministically — same input "
    "always yields the same grade. Penalises disposable/burner providers, an absent or RFC 7505 "
    "null MX (a domain publishing `0 .` accepts no mail and is scored as undeliverable, not as "
    "valid), free webmail, and role mailboxes. Use it to decide how much weight a registrant or "
    "contact address deserves BEFORE pivoting on it: a burner scores low and a corporate domain "
    "scores high, and that ordering is the whole point. MX is checked keyless over DNS-over-HTTPS; "
    "disposable detection works fully offline.",
    {"emails": str},
    annotations=READONLY,
)
async def email_hygiene(args: dict[str, Any]) -> dict[str, Any]:
    emails = str(args.get("emails") or "").replace(",", " ").split()
    r = _run([PY, _rr("email_hygiene.py"), *emails])
    return {"content": [{"type": "text", "text": r.stdout or r.stderr}], "is_error": r.returncode != 0}


@tool(
    "sensitive_paths",
    "Classify `urls` against sensitive-path patterns and return only what is worth a look — admin "
    "panels, backups, config and env files, dumps, installers, credential stores — each with a "
    "severity (CRITICAL/HIGH/MEDIUM/LOW). Built to be pointed at a Wayback/CDX listing, so accepts "
    "bare URLs, `timestamp url` rows, and raw CDX lines. Filter with `severity`. PURE pattern "
    "matching with NO network: it tells you which archived paths existed and are worth fetching — "
    "it never requests them, so nothing here touches the target.",
    {"urls": str},  # severity:str, file:str
    annotations=READONLY,
)
async def sensitive_paths(args: dict[str, Any]) -> dict[str, Any]:
    cmd = [PY, _rr("sensitive_paths.py")]
    if args.get("file"):
        cmd += ["--file", str(args["file"])]
    else:
        cmd += str(args.get("urls") or "").split()
    if args.get("severity"):
        cmd += ["--severity", str(args["severity"]).upper()]
    r = _run(cmd)
    return {"content": [{"type": "text", "text": r.stdout or r.stderr}], "is_error": r.returncode != 0}


@tool(
    "wayback_fetch",
    "Resolve the nearest Wayback snapshot of `url` and return its RAW archived content. This is the "
    "way to read a page that is dead, cloaked, or robots.txt-blocked to a normal fetch, and it is "
    "PASSIVE — the request goes to archive.org, never to the target, so it leaves no trace in the "
    "operator's logs. `near` takes 'latest' (default), 'earliest', or a YYYY / YYYYMMDD to pin an "
    "era; `yfrom`/`yto` bound the range; `list` enumerates the available snapshots instead of "
    "fetching one. Prefer this over a live fetch for any adversarial infrastructure.",
    {"url": str},  # near:str, yfrom:str, yto:str, status:str, mime:str, list:bool, text:bool
    annotations=READONLY,
)
async def wayback_fetch(args: dict[str, Any]) -> dict[str, Any]:
    cmd = [PY, _rr("wayback_fetch.py"), str(args.get("url") or "")]
    for k, flag in (("near", "--near"), ("yfrom", "--from"), ("yto", "--to"),
                    ("status", "--status"), ("mime", "--mime")):
        if args.get(k):
            cmd += [flag, str(args[k])]
    if args.get("list"):
        cmd.append("--list")
    if args.get("text"):
        cmd.append("--text")
    r = _run(cmd)
    return {"content": [{"type": "text", "text": r.stdout or r.stderr}], "is_error": r.returncode != 0}


@tool(
    "wayback_harvest",
    "Sweep a `domain`'s ENTIRE Wayback history and harvest every indicator the archive still holds — "
    "trackers, wallets, emails, phones, Telegram handles, third-party hosts — across snapshots, not "
    "just the page as it stands today. This is how you recover the artifacts an operator has since "
    "SCRUBBED: the GA ID that clustered the estate is frequently only in a 2023 capture. Set `max` "
    "to bound how many snapshots are sampled, `yfrom`/`yto` to target a registrant era, `timeline` "
    "for chronological output, `indicators` for the IOC roll-up. Passive — archive.org only.",
    {"domain": str},  # max:int, yfrom:str, yto:str, urlscan:bool, timeline:bool, indicators:bool
    annotations=READONLY,
)
async def wayback_harvest(args: dict[str, Any]) -> dict[str, Any]:
    cmd = [PY, _rr("wayback_harvest.py"), str(args.get("domain") or "")]
    if args.get("max"):
        cmd += ["--max", str(args["max"])]
    for k, flag in (("yfrom", "--from"), ("yto", "--to")):
        if args.get(k):
            cmd += [flag, str(args[k])]
    for k in ("urlscan", "timeline", "indicators"):
        if args.get(k):
            cmd.append(f"--{k}")
    r = _run(cmd)
    return {"content": [{"type": "text", "text": r.stdout or r.stderr}], "is_error": r.returncode != 0}


@tool(
    "wayback_exhaust",
    "EXHAUSTIVELY download a `domain`'s WHOLE Wayback history — every distinct capture (deduped by "
    "content hash across all subdomains and paths, HTML + JS/JSON), not the ~15-snapshot sample "
    "`wayback_harvest` takes — plus every urlscan scan + cached DOM, and harvest every selector. "
    "Runs as a DETACHED background job (default budget 7 h; `max_hours` overrides, 0 = unbounded) "
    "across parallel egress exits, and returns at once with the job's state/log path; call again "
    "with `status: true` to read progress, and re-call without it to resume a finished or cut job "
    "(state is saved per capture). Selectors are split at the domain's current WHOIS registration "
    "date: `prior_era` ones (seen only before it) are an EARLIER owner's — historical facts, never "
    "indicators or pivots. `case` stores state under the case; `yfrom`/`yto` bound an era; "
    "`created` overrides the registration date; `html_only` skips JS/JSON; `exits` overrides "
    "routes. Passive (archive.org / urlscan only, never the target).",
    {"domain": str},  # case, yfrom, yto, created, exits, state:str; max_hours:float; html_only, status:bool
    annotations=READONLY,
)
async def wayback_exhaust(args: dict[str, Any]) -> dict[str, Any]:
    cmd = [PY, os.path.join("WebPivot", "tools", "wp_wayback_exhaust.py"),
           str(args.get("domain") or "")]
    for k, flag in (("case", "--case"), ("yfrom", "--from"), ("yto", "--to"),
                    ("exits", "--exits"), ("state", "--state"), ("created", "--created")):
        if args.get(k):
            cmd += [flag, str(args[k])]
    if args.get("max_hours") is not None:
        cmd += ["--max-hours", str(args["max_hours"])]
    if args.get("html_only"):
        cmd.append("--html-only")
    # never run the sweep inside the call: the host kills a call at ~30 min. --detach starts it in
    # its own session and returns at once; --status only reads the state file.
    cmd.append("--status" if args.get("status") else "--detach")
    r = _run(cmd, timeout=60)
    return {"content": [{"type": "text", "text": r.stdout or r.stderr}], "is_error": r.returncode != 0}


def _os_(name: str) -> str:
    """Path to a scripts/osint tool, relative to ROOT (= intel_engine/)."""
    return os.path.join("..", "scripts", "osint", name)


@tool(
    "hash_id",
    "Identify what a hash IS before looking it up — and refuse to guess when it matters. A 32-hex "
    "string is MD5 *or* NTLM: the first is a file hash you may freely submit to a public corpus, "
    "the second is CREDENTIAL material whose submission irreversibly discloses someone's password "
    "hash to a third party. Length cannot separate them, so an unqualified 32-hex returns "
    "AMBIGUOUS with safe_to_submit=false; pass `context` as 'file' or 'credential' once you know "
    "the provenance and it resolves. Also covers bcrypt/argon2/scrypt/shadow formats, ssdeep and "
    "TLSH. Pure, offline, no keys. Run this BEFORE any sandbox or corpus submission.",
    {"hashes": str},  # context:'file'|'credential'
    annotations=READONLY,
)
async def hash_id(args: dict[str, Any]) -> dict[str, Any]:
    cmd = [PY, _os_("hash_id.py"), *str(args.get("hashes") or "").replace(",", " ").split()]
    if args.get("context"):
        cmd += ["--context", str(args["context"])]
    r = _run(cmd)
    return {"content": [{"type": "text", "text": r.stdout or r.stderr}], "is_error": r.returncode != 0}


@tool(
    "threat_check",
    "Reputation for any `indicator` — ip, domain, url or file hash — across feeds that are still "
    "genuinely keyless (AlienVault OTX, urlscan.io), plus VirusTotal/AbuseIPDB/abuse.ch/ChongLuaDao "
    "only when their key is set. Spamhaus Intelligence API is the FALLBACK: queried only when those "
    "feeds did not already corroborate MALICIOUS — an IP's active XBL/CSS/BCL listing or a domain's "
    "DBL listing / abuse tag counts as a signal; expired IP history and a compromised-legitimate "
    "domain are notes. Set `mode` to 'scam' to add ransomware victim records for the fraud reading. Two "
    "behaviours matter: a feed with no key is reported as NOT CONSULTED rather than silently "
    "counted as clean, and OTX's own whitelist is respected so popular infrastructure is not "
    "flagged for merely appearing in pulses. 'NO ADVERSE RECORD' is never a clean bill — fresh "
    "scam infrastructure is absent from every reputation feed for weeks, so judge new domains on "
    "their own artifacts instead.",
    {"indicator": str},  # mode:'threat'|'scam'
    annotations=READONLY,
)
async def threat_check(args: dict[str, Any]) -> dict[str, Any]:
    cmd = [PY, _os_("reputation_check.py"), str(args.get("indicator") or "")]
    if str(args.get("mode") or "") == "scam":
        cmd += ["--mode", "scam"]
    r = _run(cmd)
    return {"content": [{"type": "text", "text": r.stdout or r.stderr}], "is_error": r.returncode != 0}


@tool(
    "vuln_check",
    "Resolve a `cve` id (or search `product`) against CIRCL cve-search and NVD API v2 — both "
    "keyless. Returns CVSS score, severity, vector, description and references. Queries BOTH "
    "corpora on purpose: CIRCL lags on very fresh CVEs, NVD lags on enrichment, and a "
    "single-source severity is a number you cannot defend; when the two disagree the result "
    "carries `severity_disagreement` rather than silently picking one. Reconnaissance only — this "
    "maps a product/version to PUBLIC advisories and never probes a host.",
    {},  # cve:str, product:str, limit:int
    annotations=READONLY,
)
async def vuln_check(args: dict[str, Any]) -> dict[str, Any]:
    cmd = [PY, _os_("vuln_check.py")]
    if args.get("product"):
        cmd += ["--product", str(args["product"])]
        if args.get("limit"):
            cmd += ["--limit", str(args["limit"])]
    else:
        cmd += str(args.get("cve") or "").replace(",", " ").split()
    r = _run(cmd)
    return {"content": [{"type": "text", "text": r.stdout or r.stderr}], "is_error": r.returncode != 0}


@tool(
    "msft_recon",
    "M365 / Entra ID tenant recon for a `domain` — tenant id, namespace (Managed vs Federated), "
    "federation brand and cloud instance. Entirely KEYLESS and passive: every request goes to "
    "login.microsoftonline.com, never to the target, so the operator sees nothing. Useful because "
    "a real trading company usually has a tenant and a two-week-old shell usually does not, and "
    "because a Federated namespace exposes the identity provider host as its own pivot. Note that "
    "Microsoft has RESTRICTED tenant-domain enumeration — the result says so explicitly rather "
    "than implying a tenant owns a single domain.",
    {"domain": str},
    annotations=READONLY,
)
async def msft_recon(args: dict[str, Any]) -> dict[str, Any]:
    r = _run([PY, _os_("msft_recon.py"), str(args.get("domain") or "")])
    return {"content": [{"type": "text", "text": r.stdout or r.stderr}], "is_error": r.returncode != 0}


@tool(
    "username_enum",
    "Check whether a `username` exists on a curated set of platforms whose present/absent "
    "detection has been VERIFIED (github, gitlab, keybase, npm, hackernews, telegram, dev.to). "
    "Deliberately small: platforms that soft-404 were removed because a detector that always "
    "answers 'present' manufactures links that do not exist. The output is explicitly HYPOTHESES, "
    "never findings — a handle existing in two places does not make it one person, since handles "
    "are squatted, recycled and coincidental. Corroborate with profile content or a shared "
    "artifact before linking identities, and never write a hypothesis into a case as fact.",
    {"username": str},  # platforms:str
    annotations=READONLY,
)
async def username_enum(args: dict[str, Any]) -> dict[str, Any]:
    cmd = [PY, _os_("username_enum.py"), str(args.get("username") or "")]
    if args.get("platforms"):
        cmd += ["--platforms", str(args["platforms"])]
    r = _run(cmd)
    return {"content": [{"type": "text", "text": r.stdout or r.stderr}], "is_error": r.returncode != 0}


@tool(
    "phone_osint",
    "Decompose one or more phone `numbers` into what is deterministically knowable: E.164 "
    "validation, territory from the calling code, national-number split with a length check, "
    "messaging deep links, and the source-search queries that actually cluster infrastructure — "
    "an operator reuses one contact number across a whole estate, so finding it quoted in page "
    "source links the sites. It does NOT report carrier or line type: those need a metered "
    "HLR/portability lookup and a prefix guess is unreliable because numbers are ported. The "
    "result names those as not_determined instead of inventing them. Offline and deterministic.",
    {"numbers": str},
    annotations=READONLY,
)
async def phone_osint(args: dict[str, Any]) -> dict[str, Any]:
    # One number per argv item: split only on list separators — never on the spaces inside
    # `+1 202 555 0100`, which would turn one number into four fragments.
    nums = [n.strip() for n in str(args.get("numbers") or "").replace(";", ",")
            .replace("\n", ",").split(",") if n.strip()]
    r = _run([PY, _os_("phone_osint.py"), "--", *nums])
    return {"content": [{"type": "text", "text": r.stdout or r.stderr}], "is_error": r.returncode != 0}


@tool(
    "exposure_score",
    "Composite 0-100 SUBJECT exposure score from analysis/weight-engine.md — security, privacy, "
    "reputation, legal, infrastructure and surface, weighted. This is the person/organisation "
    "counterpart to `risk_signals`, which scores INFRASTRUCTURE; do not conflate the two in a "
    "report. Pure: it consumes indicator values you have already collected (pass `indicators` as "
    "'key=value,key=value' or a JSON file path) and looks nothing up. Indicators you omit are "
    "listed as missing and excluded from the denominator, and the result states the coverage — a "
    "subject scored on 3 of 11 indicators is not comparable to one scored on 11.",
    {},  # indicators:str, infile:str
    annotations=READONLY,
)
async def exposure_score(args: dict[str, Any]) -> dict[str, Any]:
    cmd = [PY, _os_("exposure_score.py")]
    if args.get("infile"):
        cmd.append(str(args["infile"]))
    for kv in str(args.get("indicators") or "").split(","):
        if kv.strip():
            cmd += ["--set", kv.strip()]
    r = _run(cmd)
    return {"content": [{"type": "text", "text": r.stdout or r.stderr}], "is_error": r.returncode != 0}


@tool(
    "github_osint",
    "GitHub reconnaissance for a `target` (user, org, owner/repo, or a github.com URL) — profile, "
    "repos, and the COMMIT-AUTHOR EMAILS, which are usually the strongest pivot because a public "
    "commit exposes an address that reverse-pivots to other accounts and leak corpora. Set "
    "`secrets` to also emit leaked-credential hunt queries. Keyless at 60 requests/hour; the "
    "rate-limit state is ALWAYS reported, because a 403 returning nothing looks exactly like an "
    "account that does not exist. Code search requires authentication, so /secrets emits the "
    "queries rather than pretending to have run them.",
    {"target": str},  # secrets:bool, repo:bool
    annotations=READONLY,
)
async def github_osint(args: dict[str, Any]) -> dict[str, Any]:
    cmd = [PY, _os_("github_osint.py"), str(args.get("target") or "")]
    if args.get("secrets"):
        cmd.append("--secrets")
    if args.get("repo"):
        cmd.append("--repo")
    r = _run(cmd)
    return {"content": [{"type": "text", "text": r.stdout or r.stderr}], "is_error": r.returncode != 0}


@tool(
    "traffic_rank",
    "Tranco popularity rank for one or more `domains`, keyless. The ANALYTIC POINT IS USUALLY THE "
    "ABSENCE: a funnel claiming years of operation that is unranked in a 1M-entry list is "
    "contradicting its own copy. Deliberately does NOT report traffic estimates or audience "
    "demographics — those come only from paid panels whose low-traffic figures are modelled "
    "guesses, and reporting a model as a measurement about a scam site would be inventing "
    "evidence. Passive; Tranco is queried, never the target.",
    {"domains": str},
    annotations=READONLY,
)
async def traffic_rank(args: dict[str, Any]) -> dict[str, Any]:
    r = _run([PY, _os_("traffic_rank.py"),
              *str(args.get("domains") or "").replace(",", " ").split()])
    return {"content": [{"type": "text", "text": r.stdout or r.stderr}], "is_error": r.returncode != 0}


@tool(
    "sharelink_resolve",
    "Expand a share/short `url` (vm.tiktok.com, t.co, bit.ly, facebook.com/share/r/… …) and read "
    "the SHARER-IDENTITY parameters platforms embed in it — u_code, sec_user_id, igshid, mibextid, "
    "invite and affiliate codes. Recursively unwraps redirect-carrier params (next/u/url/"
    "redirect_uri/continue/target, bounded depth) so a chain ending on a LOGIN WALL still yields "
    "the content URL, and returns `platform_ids`: Facebook page/profile/owner id, story_fbid, "
    "fbid, reel/video id, share token; Instagram shortcode, username, igshid; TikTok video id, "
    "@user, sec_user_id. Headers only, never renders. NOT PASSIVE: the final host is contacted — "
    "use a research egress, or `no_follow=true` to parse a URL you already hold offline. A sharer "
    "parameter or platform id names an ACCOUNT, not the person who sent the link.",
    {"url": str},  # max_hops:int, no_follow:bool
    annotations=READONLY,
)
async def sharelink_resolve(args: dict[str, Any]) -> dict[str, Any]:
    cmd = [PY, _os_("sharelink_resolve.py"), str(args.get("url") or "")]
    if args.get("max_hops"):
        cmd += ["--max-hops", str(args["max_hops"])]
    if args.get("no_follow"):
        cmd.append("--no-follow")
    r = _run(cmd)
    return {"content": [{"type": "text", "text": r.stdout or r.stderr}], "is_error": r.returncode != 0}

@tool(
    "meta_transparency",
    "Keyless Meta ACCOUNT transparency for a Facebook Page (vanity / numeric id / URL) or an "
    "Instagram account (@handle / URL, platform='instagram'): Page id + name via the Page plugin; "
    "the Ad Library About tab — creation date, name-change/merge dates, admin countries, confirmed "
    "owning organisation, linked Instagram, category, likes, active/total ads, shared-disclaimer "
    "and related Pages, and the page_name each ad ran under; Instagram public profile (name, bio, "
    "links, category, business email/phone if public, linked fbid). Name/username/bio/location "
    "HISTORY rebuilt from Wayback captures. Per-field tri-state (found / not_exposed / "
    "login_required / blocked / rate_limited), 429s backed off with Retry-After. Login-only panels "
    "come back as a `capture_checklist` of screenshots to take — NEVER ask for cookies or session "
    "tokens. Account-level facts, never person attribution. `search` = Ad Library page-name "
    "search; `case` writes cases/<case>/enrichment/meta_transparency/.",
    {"target": str},  # platform:str, search:str, case:str, no_wayback:bool, no_linked:bool
    annotations=READONLY,
)
async def meta_transparency(args: dict[str, Any]) -> dict[str, Any]:
    cmd = [PY, os.path.join("WebPivot", "tools", "wp_meta.py"), "--json"]
    if args.get("search"):
        cmd += ["--search", str(args["search"])]
    elif args.get("target"):
        cmd.append(str(args["target"]))
    if args.get("platform"):
        cmd += ["--platform", str(args["platform"])]
    if args.get("case"):
        cmd += ["--case", str(args["case"])]
    if args.get("no_wayback"):
        cmd.append("--no-wayback")
    if args.get("no_linked"):
        cmd.append("--no-linked")
    r = _run(cmd, timeout=1800)
    return {"content": [{"type": "text", "text": r.stdout or r.stderr}], "is_error": r.returncode != 0}



@tool(
    "dork_builder",
    "Build document- and leak-hunt search queries for a `target` across 18 document hosts, paste "
    "sites and object stores, plus filetype families, each graded by how damaging a hit WOULD be. "
    "EMITS, NEVER RUNS: automated querying of these engines gets the egress blocked within a few "
    "requests, breaks on every layout change, and on several hosts breaches the terms the analyst "
    "is bound by — so running one is a human decision made in a browser they control. The "
    "severity grades the QUERY, not a result: nothing here is evidence until a human opens it. "
    "Filter with `severity`. Pure and offline.",
    {"target": str},  # severity:str
    annotations=READONLY,
)
async def dork_builder(args: dict[str, Any]) -> dict[str, Any]:
    cmd = [PY, _os_("dork_builder.py"), str(args.get("target") or "")]
    if args.get("severity"):
        cmd += ["--severity", str(args["severity"]).lower()]
    r = _run(cmd)
    return {"content": [{"type": "text", "text": r.stdout or r.stderr}], "is_error": r.returncode != 0}


@tool(
    "cn_recon",
    "PRC filing and corporate-registry recon for a `domain` (or a `serial` / `company` you already "
    "hold): pulls the keyless ICP mirrors, parses the licence, and reverses the LICENCE SERIAL "
    "into sibling-domain queries — cluster on the serial, never the province prefix, since 苏 "
    "covers a whole province while -3 is one site within one filing. Names every gate it did not "
    "pass rather than working around it: beian.miit.gov.cn and GSXT are CAPTCHA-walled, and "
    "TianYanCha/QCC/Aiqicha are IP-blocked outside mainland China. An empty result is therefore an "
    "absence of collection, never evidence that no filing or company exists.",
    {},  # domain:str, serial:str, company:str
    annotations=READONLY,
)
async def cn_recon(args: dict[str, Any]) -> dict[str, Any]:
    cmd = [PY, _os_("cn_recon.py")]
    if args.get("domain"):
        cmd.append(str(args["domain"]))
    for k in ("serial", "company"):
        if args.get(k):
            cmd += [f"--{k}", str(args[k])]
    r = _run(cmd)
    return {"content": [{"type": "text", "text": r.stdout or r.stderr}], "is_error": r.returncode != 0}


@tool(
    "vn_corp",
    "Keyless Vietnamese business-registry lookup: a 10/13-digit MST tax code or a company name "
    "against public mirrors (masothue.com, hsctvn.com, doanhnghiep.biz) → company name (VN + "
    "international), tax code, legal representative, address, phone, status, registration date — "
    "each field tri-state with its own source URL. No key, no account. Use it to CORROBORATE a "
    "WHOIS registrant org/phone (a matching director phone is rung-1 corroboration of who "
    "REGISTERED, not who runs the scheme — a registered LLC can be a nominee front), or to "
    "resolve an MST printed on a page. Run it before naming any Vietnamese company.",
    {"query": str},  # timeout:int
    annotations=READONLY,
)
async def vn_corp(args: dict[str, Any]) -> dict[str, Any]:
    cmd = [PY, os.path.join("WebPivot", "tools", "wp_vncorp.py"), str(args["query"]), "--json"]
    if args.get("timeout"):
        cmd += ["--timeout", str(int(args["timeout"]))]
    r = _run(cmd)
    return {"content": [{"type": "text", "text": r.stdout or r.stderr}], "is_error": r.returncode != 0}


@tool(
    "sellers_lookup",
    "AdSense publisher id (ca-pub-… / pub-… / digits) → the LEGAL PAYEE name, domain and seller "
    "type Google's public sellers.json lists for it. Keyless and free; the ~110 MB file is "
    "downloaded once into a gitignored cache and reused for its TTL. A NAMED payee is an "
    "owner-rung signal (rungs.json ads.payee) — the pub id alone is kit, the entity Google pays "
    "for it is who monetises the site; a confidential row has no name and stays kit. Several ids "
    "may be space/comma separated.",
    {"pub_id": str},  # refresh:bool optional — tool_params.json
    annotations=READONLY,
)
async def sellers_lookup(args: dict[str, Any]) -> dict[str, Any]:
    ids = str(args["pub_id"]).replace(",", " ").split()
    cmd = [PY, os.path.join("WebPivot", "tools", "wp_sellers.py"), *ids, "--json"]
    if args.get("refresh"):
        cmd.append("--refresh")
    r = _run(cmd)
    return {"content": [{"type": "text", "text": r.stdout or r.stderr}], "is_error": r.returncode != 0}


@tool(
    "app_developer",
    "Keyless app-store DEVELOPER lookup: a Google Play package (or play.google.com URL) → the "
    "listing's developer name, 'About the developer' LEGAL name, contact email (plus a distinct "
    "developer email), postal address, phone, website and the "
    "account's other apps; an App Store id / apps.apple.com URL (or bundle id with "
    "store='appstore') → iTunes artistName, artistId, sellerName, sellerUrl and other apps, plus "
    "the EU-storefront product page's DSA TRADER block (declared → Apple-displayed address, phone, "
    "email; not_declared; geo_redirected when the egress is served another storefront — then "
    "absence is not evidence) and its support/privacy links. A "
    "developer website whose registrable domain equals a case domain is an OWNER link (rung "
    "app.developer_url); the email and any other website are seed CANDIDATES only, never "
    "auto-seeded — a listing is self-declared. Pass `case` to scope the owner check; the "
    "resolved record is then saved to cases/<case>/appdev/ so build_report_data carries the "
    "developer (legal name, emails, address, phone, website, other apps) into the report subjects "
    "and findings; emails and phone are seed candidates, never auto-seeded.",
    {"query": str},  # store:'auto'|'play'|'appstore', case:str, case_domains:str, timeout:int
    annotations=READONLY,
)
async def app_developer(args: dict[str, Any]) -> dict[str, Any]:
    cmd = [PY, os.path.join("WebPivot", "tools", "wp_appdev.py"), str(args["query"]), "--json"]
    if args.get("store"):
        cmd += ["--store", str(args["store"])]
    if args.get("case"):
        cmd += ["--case", str(args["case"])]
    if args.get("case_domains"):
        cmd += ["--case-domains", str(args["case_domains"])]
    if args.get("timeout"):
        cmd += ["--timeout", str(int(args["timeout"]))]
    r = _run(cmd)
    return {"content": [{"type": "text", "text": r.stdout or r.stderr}], "is_error": r.returncode != 0}


@tool(
    "kb_crossref",
    "Which identifiers appear across MORE THAN ONE case. `kb_query_shared` answers which "
    "indicators bind domains; this answers the question that matters once you have a backlog — "
    "does something in today's case also appear in one you closed months ago? A repeat across "
    "INDEPENDENTLY collected cases is the strongest same-operator signal available. Scope with "
    "`case`, raise the bar with `min_cases`. Noise control is inherited, not reinvented: "
    "indicator-level from noise_filters.py, relation-level using the same boilerplate set the "
    "cluster writer excludes, plus the /reference benign ledger. Pure — local KB only.",
    {},  # case:str, min_cases:int
    annotations=READONLY,
)
async def kb_crossref(args: dict[str, Any]) -> dict[str, Any]:
    cmd = [PY, _os_("kb_crossref.py")]
    if args.get("case"):
        cmd += ["--case", str(args["case"])]
    if args.get("min_cases"):
        cmd += ["--min-cases", str(args["min_cases"])]
    r = _run(cmd)
    return {"content": [{"type": "text", "text": r.stdout or r.stderr}], "is_error": r.returncode != 0}


@tool(
    "case_drift",
    "What CHANGED in a `case` between two collections. Re-running collection on a live estate "
    "produces new facts; the useful question is what MOVED — a changed origin IP, a gained "
    "nameserver, a dropped tracker, a host gone dark — because the date of that movement is often "
    "the most reportable thing in the case. Pass `snapshot` to store the current state, then diff "
    "against it after the next collection. Only a narrow set of fields is diffed, on purpose: a "
    "diff reporting every byte of a re-scrape buries the three facts that matter. A field going "
    "missing can mean the operator removed it OR that the collector failed — check before calling "
    "it an operator action. Pure and local.",
    {"case": str},  # snapshot:bool, against:str
    annotations=READONLY,
)
async def case_drift(args: dict[str, Any]) -> dict[str, Any]:
    cmd = [PY, _os_("case_drift.py"), str(args.get("case") or "")]
    if args.get("snapshot"):
        cmd.append("--snapshot")
    if args.get("against"):
        cmd += ["--against", str(args["against"])]
    r = _run(cmd)
    return {"content": [{"type": "text", "text": r.stdout or r.stderr}], "is_error": r.returncode != 0}


@tool(
    "evidence_import",
    "Import an analyst's GRADED findings into a case: `findings` is a path to a JSON list of "
    "{claim, source_url, rung, rung_class, admiralty, indicators:[{type,value}], "
    "selector_links:[{from,to,rel}]}. Stored under cases/<case>/evidence/imported/; an OWNER "
    "finding (owner rung AND a rung_class rungs.json grades owner) writes its selector_links as KB "
    "edges, everything else — indicators, kit/neighbour links, demoted owner claims — is facts only "
    "(collecting ≠ attributing). Every row carries source `analyst_import` so the assessment can "
    "cite it. Entries missing a claim or a valid admiralty grade (A-F + 1-6, e.g. B2) are rejected "
    "with a message. Never writes assessment.md/.json.",
    {"case": str, "findings": str},
    annotations=ToolAnnotations(readOnlyHint=False),   # writes evidence/imported/ + the KB
)
async def evidence_import(args: dict[str, Any]) -> dict[str, Any]:
    case = str(args.get("case") or "").strip()
    findings = str(args.get("findings") or "").strip()
    if not case or not findings:
        return _err("evidence_import needs case=<ID> and findings=<path to findings JSON>")
    kb = KB_DIR if os.path.isabs(KB_DIR) else os.path.join(ROOT, KB_DIR)
    r = _run([PY, os.path.join("tools", "evidence_import.py"), "--kb", kb, "import", case,
              os.path.abspath(findings)])
    if r.returncode != 0:
        return _err(r.stdout or r.stderr or "evidence_import failed")
    return _ok(r.stdout or "evidence_import produced no output")


@tool(
    "signature_scan",
    "Evaluate behavioural observations against analysis/signature-catalog.md — the TEMPORAL / "
    "BEHAVIORAL / NETWORK / LINGUISTIC families and their thresholds (posting-interval variance "
    "under 3 minutes reads as automation, a follower ratio under 0.1 as an inorganic graph, and "
    "so on). Pass `observations` as 'key=value,key=value'; `list` shows the catalogue and the "
    "keys it accepts. IT DOES NOT COLLECT: it cannot observe posting cadence or a follower graph, "
    "and inventing one would be worse than useless — supply what you measured. A fired signature "
    "is a hypothesis about behaviour, not an identification: automation and a bought follower "
    "graph are equally consistent with ordinary marketing.",
    {},  # observations:str, list:bool
    annotations=READONLY,
)
async def signature_scan(args: dict[str, Any]) -> dict[str, Any]:
    cmd = [PY, _os_("signature_scan.py")]
    if args.get("list"):
        cmd.append("--list")
    for kv in str(args.get("observations") or "").split(","):
        if kv.strip():
            cmd += ["--set", kv.strip()]
    r = _run(cmd)
    return {"content": [{"type": "text", "text": r.stdout or r.stderr}], "is_error": r.returncode != 0}


@tool(
    "deep_profile",
    "Run the email-deep / breach-deep chain over a `selector`. When the key is set and "
    "`free_only` is not set, this SENDS Hudson Rock, ZoneCruncher, one IntelX stealer-log "
    "search, OSINT Industries account existence, and a WhoisXML reverse-WHOIS (preview, then "
    "purchase only if the count is not "
    "bulk). Pass `case` so the case memo dedups a second call. HIBP stays a collection gap "
    "unless HIBP_API_KEY is set. Set `mode` to 'breach' for the breach-weighted variant. "
    "Do not ingest reverse-WHOIS domains from this result as operator edges. Absence of a "
    "breach record means 'not queried', never 'not breached'.",
    {"selector": str},  # mode, case, free_only are optional — tool_params.json
    annotations=READONLY,
)
async def deep_profile(args: dict[str, Any]) -> dict[str, Any]:
    cmd = [PY, _os_("deep_profile.py"), str(args.get("selector") or "")]
    if str(args.get("mode") or "") == "breach":
        cmd += ["--mode", "breach"]
    if args.get("case"):
        # deep_profile.py takes a case DIRECTORY (it exports WP_CASE_DIR); a bare case ID would
        # create a stray <cwd>/<id>/ memo dir outside cases/.
        c = str(args["case"])
        cdir = c if (os.path.isabs(c) or os.sep in c) else os.path.join(ROOT, "cases", c)
        cmd += ["--case", cdir]
    if _flag(args, "free_only"):
        cmd.append("--free-only")
    r = _run(cmd, timeout=240)
    return {"content": [{"type": "text", "text": r.stdout or r.stderr}], "is_error": r.returncode != 0}


@tool(
    "osint_industries",
    "OSINT Industries account-existence lookup for ONE strong selector (`type` email | phone "
    "E.164 | username | name | wallet; default guesses email/phone/username). Returns the "
    "platforms with an account registered to it TODAY, self-declared display names/handles, "
    "profile URLs, masked email/phone hints, HIBP breach rows and, for an email, WHOIS rows. "
    "1 credit per lookup (+3 with premium); `type='credits'` reads the balance free. Pass `case` "
    "to save the raw response and reuse it instead of buying the same lookup again. LEADS ONLY: "
    "a hit is not attribution, never links two domains, never names an operator; masked hints "
    "are not identity evidence either way, and the current holders of a phone are never pivoted "
    "to. A name search returns namesakes — join on a case selector before using any row. For a "
    "registrant email prefer deep_profile, which already sends this.",
    {"query": str},  # type, premium, exact_match, case, refresh, timeout — tool_params.json
    annotations=READONLY,
)
async def osint_industries(args: dict[str, Any]) -> dict[str, Any]:
    typ = str(args.get("type") or "auto")
    cmd = [PY, _os_("osint_industries.py"), typ]
    if typ != "credits":
        cmd.append(str(args.get("query") or ""))
    if _flag(args, "premium"):
        cmd.append("--premium")
    if "exact_match" in (args or {}) and not _flag(args, "exact_match"):
        cmd.append("--no-exact-match")
    if args.get("case"):
        cmd += ["--case", str(args["case"])]
    if _flag(args, "refresh"):
        cmd.append("--refresh")
    if args.get("timeout"):
        cmd += ["--timeout", str(int(args["timeout"]))]
    r = _run(cmd, timeout=180)
    return {"content": [{"type": "text", "text": r.stdout or r.stderr}], "is_error": r.returncode != 0}


@tool(
    "cld",
    "ChongLuaDao Feeds + Shield for one selector, using the same key as the collector. "
    "`route` (the default) fires only the endpoints that match: a domain gets checkurl, "
    "IoC, and host-matched ransomware/ClickFix/Phaas; a t.me handle gets Telegram posts, "
    "not a domain lookup; an email gets burner + IoC; a phone gets checkphone + IoC; "
    "`bank:<digits>` gets the VN bank-account IoC (reported holder name + bank). "
    "Do not re-run it for a host the pipeline already collected. Internal-leak urls are "
    "the paste the document was found on, not the target host.",
    {"target": str},
    annotations=READONLY,
)
async def cld(args: dict[str, Any]) -> dict[str, Any]:
    if _flag(args, "free_only"):
        return {"content": [{"type": "text", "text": "{\"status\": \"HELD — free_only\"}"}],
                "is_error": False}
    cmd = [PY, os.path.join("..", "scripts", "cld", "cld_api.py"),
           str(args.get("op") or "route"), str(args.get("target") or "")]
    r = _run(cmd, timeout=90)
    return {"content": [{"type": "text", "text": r.stdout or r.stderr}], "is_error": r.returncode != 0}


@tool(
    "wifi_ssid",
    "Geolocate a WiFi `ssid` through WiGLE's wardriving corpus. There is NO keyless path: without "
    "WIGLE_API_NAME / WIGLE_API_TOKEN this returns the query to run rather than an empty result "
    "that would read as 'no such network'. Handle hits carefully — an SSID observation is a HOME "
    "OR WORKPLACE location for whoever runs that access point, and a distinctive SSID usually "
    "resolves to a private residence, so use it for infrastructure attribution rather than to "
    "locate a person. A common or default SSID matches many unrelated networks and narrows "
    "nothing.",
    {"ssid": str},
    annotations=READONLY,
)
async def wifi_ssid(args: dict[str, Any]) -> dict[str, Any]:
    r = _run([PY, _os_("wifi_ssid.py"), str(args.get("ssid") or "")])
    return {"content": [{"type": "text", "text": r.stdout or r.stderr}], "is_error": r.returncode != 0}


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

# ---------------------------------------------------------------- servers + names
# Every @tool MUST appear in exactly one server below AND in that server's *_TOOLS allowlist.
# The stdio front-end (mcp_server.py) auto-discovers @tools, so a tool missing here is visible in
# Claude Code and INVISIBLE to the SDK — the two front-ends silently diverge and a phase prompt
# that references the tool just fails. The reverse is worse: an allowlist entry with no served
# tool tells the model it may call something that does not exist. `tests/test_tool_registry.py`
# asserts the three lists agree, so this can only drift again on purpose.
# NOTE: `subdomain_enum` is the case-persisting wp_subenum tool defined above (subfinder/amass/
# assetfinder/findomain → cases/<id>/subenum/<apex>.json, queued by the frontier). The keyless
# certspotter+hackertarget+crt.sh enumerator stays a T2 CLI (`intel.py subdomain`), not a second
# @tool under the same name.

COLLECT_SERVER = create_sdk_mcp_server(
    "collect", tools=[pivot_extract, doc_metadata, analyze_artifact, fallback_probe,
                      impersonation_hunt, search_pivot, censys, intelx_search, grayhatwarfare,
                      anyrun_lookup, anyrun_submit, webamon_scan, capability_check,
                      url_paths, capture_evidence, capture_screenshot, serp_ads, passive_ssl, ip_info,
                      domain_liveness,
                      detect_login, make_persona, engage_account, harvest_authenticated,
                      engage_report,
                      cert_pivot, crypto_balance, wayback_fetch, wayback_harvest, wayback_exhaust,
                      threat_check, msft_recon, username_enum,
                      subdomain_enum, github_harvest, github_osint, traffic_rank, sharelink_resolve,
                      meta_transparency,
                      cn_recon, vn_corp, sellers_lookup, cti, quarry, deep_profile, wifi_ssid, cld,
                      kb_ingest, corpus_search, app_developer, osint_industries])
ANALYZE_SERVER = create_sdk_mcp_server(
    "analyze", tools=[kb_cluster, kb_entity, kb_query_shared, risk_signals,
                      reverse_whois, cert_overlap, reference_check, reference_add, reference_mirrors,
                      which_cases, domain_verdict, api_usage, tool_calls, case_scope,
                      case_clusters, case_frontier, case_loop, case_enrich, case_reopen, case_approve,
                      email_permute,
                      render_diagram, case_timeline, render_report, victim_profile,
                      collection_gaps, origin_history,
                      rank_relations, pivot_suggest, sensitive_paths, email_hygiene,
                      hash_id, vuln_check, phone_osint, exposure_score,
                      dork_builder, kb_crossref, case_drift, signature_scan,
                      misp_export, misp_search, misp_push, misp_publish,
                      evidence_import])

COLLECT_TOOLS = ["mcp__collect__pivot_extract", "mcp__collect__doc_metadata",
                 "mcp__collect__analyze_artifact",
                 "mcp__collect__fallback_probe", "mcp__collect__impersonation_hunt",
                 "mcp__collect__search_pivot", "mcp__collect__censys",
                 "mcp__collect__intelx_search", "mcp__collect__grayhatwarfare",
                 "mcp__collect__anyrun_lookup", "mcp__collect__anyrun_submit",
                 "mcp__collect__webamon_scan",
                 "mcp__collect__capability_check",
                 "mcp__collect__url_paths", "mcp__collect__capture_evidence",
                 "mcp__collect__capture_screenshot",
                 "mcp__collect__serp_ads", "mcp__collect__passive_ssl",
                 "mcp__collect__ip_info",
                 "mcp__collect__domain_liveness",
                 "mcp__collect__detect_login", "mcp__collect__make_persona",
                 "mcp__collect__engage_account", "mcp__collect__harvest_authenticated",
                 "mcp__collect__engage_report",
                 "mcp__collect__cert_pivot", "mcp__collect__crypto_balance",
                 "mcp__collect__threat_check", "mcp__collect__msft_recon",
                 "mcp__collect__username_enum", "mcp__collect__subdomain_enum",
                 "mcp__collect__github_harvest",
                 "mcp__collect__github_osint", "mcp__collect__traffic_rank",
                 "mcp__collect__sharelink_resolve", "mcp__collect__meta_transparency",
                 "mcp__collect__cn_recon", "mcp__collect__vn_corp", "mcp__collect__cti", "mcp__collect__quarry",
                 "mcp__collect__deep_profile", "mcp__collect__wifi_ssid", "mcp__collect__cld",
                 "mcp__collect__wayback_fetch", "mcp__collect__wayback_harvest",
                 "mcp__collect__wayback_exhaust",
                 "mcp__collect__kb_ingest", "mcp__collect__corpus_search",
                 "mcp__collect__app_developer", "mcp__collect__sellers_lookup",
                 "mcp__collect__osint_industries"]
ANALYZE_TOOLS = ["mcp__analyze__kb_cluster", "mcp__analyze__kb_entity",
                 "mcp__analyze__kb_query_shared", "mcp__analyze__risk_signals",
                 "mcp__analyze__reverse_whois", "mcp__analyze__cert_overlap",
                 "mcp__analyze__reference_check", "mcp__analyze__reference_add",
                 "mcp__analyze__reference_mirrors",
                 "mcp__analyze__which_cases", "mcp__analyze__domain_verdict",
                 "mcp__analyze__api_usage", "mcp__analyze__tool_calls",
                 "mcp__analyze__case_scope",
                 "mcp__analyze__case_clusters", "mcp__analyze__case_frontier",
                 "mcp__analyze__case_loop", "mcp__analyze__case_enrich",
                 "mcp__analyze__case_reopen", "mcp__analyze__case_approve",
                 "mcp__analyze__email_permute",
                 "mcp__analyze__render_diagram", "mcp__analyze__case_timeline",
                 "mcp__analyze__render_report", "mcp__analyze__victim_profile",
                 "mcp__analyze__collection_gaps", "mcp__analyze__origin_history",
                 "mcp__analyze__misp_export", "mcp__analyze__misp_search",
                 "mcp__analyze__rank_relations", "mcp__analyze__pivot_suggest",
                 "mcp__analyze__hash_id", "mcp__analyze__vuln_check",
                 "mcp__analyze__phone_osint", "mcp__analyze__exposure_score",
                 "mcp__analyze__dork_builder", "mcp__analyze__kb_crossref",
                 "mcp__analyze__case_drift", "mcp__analyze__signature_scan",
                 "mcp__analyze__sensitive_paths", "mcp__analyze__email_hygiene",
                 "mcp__analyze__misp_push", "mcp__analyze__misp_publish",
                 "mcp__analyze__evidence_import"]
# The cross-type loop's Plan phase: READ-ONLY. ANALYZE_TOOLS also carries tools that spend
# (reverse_whois, case_enrich), expand (case_loop, case_reopen), write shared state
# (reference_add, misp_push/publish) or approve (case_approve) — a planner holding any of them
# could act without the per-round approval it exists to feed. tests/test_tool_registry.py asserts
# this list stays a subset of ANALYZE_TOOLS with no metered, outbound, mutating or approval tool.
PLAN_TOOLS = ["mcp__analyze__kb_cluster", "mcp__analyze__kb_entity",
              "mcp__analyze__kb_query_shared", "mcp__analyze__kb_crossref",
              "mcp__analyze__case_frontier", "mcp__analyze__case_clusters",
              "mcp__analyze__pivot_suggest", "mcp__analyze__rank_relations",
              "mcp__analyze__which_cases", "mcp__analyze__domain_verdict",
              "mcp__analyze__api_usage", "mcp__analyze__collection_gaps",
              "mcp__analyze__case_drift", "mcp__analyze__case_timeline",
              "mcp__analyze__reference_check", "mcp__analyze__origin_history"]
