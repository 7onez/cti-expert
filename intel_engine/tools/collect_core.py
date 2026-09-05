"""collect_core — the ONE host-collection routine both front-ends delegate to.

Before this module the collection logic existed twice and had drifted apart:

    harness/tools.py : collect_one()   (SDK/MCP path)  — cache-reuse, egress policy,
                                                          Cloudflare retry, evidence manifest
    tools/intel.py   : _extract_one()  (deterministic pipeline) — a thinner re-implementation
                                                          with none of the above

`harness/tools.py` imports `claude_agent_sdk`, so the stdlib-only pipeline can NOT import
`collect_one` to share it — pulling the SDK into the zero-dep pipeline would break it. Hence
the shared core lives here, in a **stdlib-only** module both layers import. `collect_host()`
below is the single source of truth for "collect one host end-to-end"; each caller passes its
own paths/knobs (and, optionally, an evidence-manifest callback) and gets a uniform result dict.

Keeping this dependency-free is load-bearing (see SKILL.md §12 "self-contained & self-resolving"
— the collector + KB + deterministic pipeline are stdlib and need no venv). Do not import the
SDK, requests, or anything outside the standard library here.
"""
from __future__ import annotations

import concurrent.futures
import glob
import os
import shutil
import subprocess
import threading
from typing import Any, Callable, Optional, Sequence
from urllib.parse import urlparse

# --- small stdlib helpers (single home; harness/tools.py delegates to these) -------------
_FLAGS_CACHE: dict[str, frozenset[str]] = {}
_FLAGS_LOCK = threading.Lock()

# Per-call ceiling for subprocess "task calls". Mirrors wp_common.CALL_TIMEOUT; the env var
# CTI_CALL_TIMEOUT is the single runtime source of truth (default 1800s / 30 min). Flooring here
# means every harness _run(...) call and every collector subprocess this module launches runs up to
# the ceiling, then times out and the run moves on — without editing each of the ~40 call sites.
try:
    CALL_TIMEOUT = int(os.environ.get("CTI_CALL_TIMEOUT", "") or 1800)
    if CALL_TIMEOUT <= 0:
        CALL_TIMEOUT = 1800
except (TypeError, ValueError):
    CALL_TIMEOUT = 1800


def host_of(url: str) -> str:
    """Bare hostname for a URL/host string (no scheme/path)."""
    return urlparse(url if "://" in url else "http://" + url).hostname or url


def run(cmd: Sequence[str], cwd: str, timeout: int = None) -> subprocess.CompletedProcess:
    # Floor to CALL_TIMEOUT: a caller's shorter per-call timeout is raised to the ceiling.
    eff = CALL_TIMEOUT if not isinstance(timeout, (int, float)) else max(int(timeout), CALL_TIMEOUT)
    return subprocess.run(list(cmd), cwd=cwd, capture_output=True, text=True, timeout=eff)


def load_json(path: str):
    try:
        import json
        return json.load(open(path, encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return None


def find_cached_raw(root: str, host: str, exclude: str = "") -> str:
    """Newest existing pivot JSON for this host across ALL cases (already investigated?)."""
    hits = [p for p in glob.glob(os.path.join(root, "cases", "*", "raw", host + ".json"))
            if p != exclude]
    hits.sort(key=os.path.getmtime, reverse=True)
    return hits[0] if hits else ""


def supported_flags(py: str, script: str, cwd: str) -> frozenset[str]:
    """The option strings a collector script actually accepts, read from its own --help.

    The engine and cti-expert each ship a pivot_extract; the canonical one resolved via the
    WebPivot shim does NOT accept every flag the engine's richer collector once did. Passing an
    unknown flag makes argparse exit 2 and the whole collection fails. Probing --help once per
    script keeps the wrapper working across either layer instead of hard-coding one vocabulary."""
    with _FLAGS_LOCK:
        hit = _FLAGS_CACHE.get(script)
    if hit is not None:
        return hit
    flags: set[str] = set()
    try:
        r = run([py, script, "--help"], cwd=cwd, timeout=30)
        for tok in (r.stdout or "").replace(",", " ").split():
            if tok.startswith("-") and len(tok) > 1:
                flags.add(tok.split("=", 1)[0].rstrip("[]"))
    except Exception:  # noqa: BLE001
        flags = set()   # probe failed → treat every flag as supported, same as the old behaviour
    out = frozenset(flags)
    with _FLAGS_LOCK:
        _FLAGS_CACHE[script] = out
    return out


def filter_args(py: str, script: str, cwd: str, args: list[str]) -> tuple[list[str], list[str]]:
    """Drop (flag, value) pairs the collector does not support. Returns (kept, dropped_flags)."""
    supported = supported_flags(py, script, cwd)
    if not supported:
        return args, []
    kept: list[str] = []
    dropped: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a.startswith("-") and a not in supported:
            dropped.append(a)
            i += 1
            while i < len(args) and not args[i].startswith("-"):
                i += 1
            continue
        kept.append(a)
        i += 1
    return kept, dropped


# --- the shared collection routine -------------------------------------------------------
def collect_host(
    url: str,
    case: str,
    *,
    root: str,
    py: str,
    collector: str,
    render_py: Optional[str] = None,
    hostile: bool = False,
    passive: bool = False,
    proxy: Optional[str] = None,
    force: bool = False,
    smoke: bool = False,
    no_archive: bool = False,
    want_shot: bool = False,
    flaresolverr: Optional[str] = None,
    timeout: Optional[int] = None,
    extra_flags: Sequence[str] = (),
    manifest_cb: Optional[Callable[..., None]] = None,
) -> dict[str, Any]:
    """Collect ONE host end-to-end and return a summary dict; never raises.

    Pipeline: cache-reuse (already investigated in ANY case?) → egress policy (refuse a direct
    live fetch of a hostile target) → collector run with unsupported-flag filtering → Cloudflare
    retry (flaresolverr/browser) → optional evidence manifest. Self-contained + stdlib, so it is
    safe to fan out across threads.

    `collector` is the pivot_extract.py path (absolute, or relative to `root`). `render_py` is the
    interpreter used for browser render/screenshot (defaults to `py`). `manifest_cb(case, host,
    data, reused=..., dom_path=..., shot_path=...)` records evidence provenance when provided (the
    harness passes its `_append_manifest`; the deterministic pipeline passes None). `extra_flags`
    are appended verbatim before filtering (e.g. `--whois-reverse` / `--fofa-full` / `--render`).

    Result dict keys: host, ok, reused, error, dom, n_pivots, note, data.
    """
    render_py = render_py or py
    collpath = collector if os.path.isabs(collector) else os.path.join(root, collector)
    raw_dir = os.path.join(root, "cases", case, "raw")
    dom_dir = os.path.join(root, "cases", case, "dom")
    shot_dir = os.path.join(root, "cases", case, "screenshots")
    os.makedirs(raw_dir, exist_ok=True)
    os.makedirs(dom_dir, exist_ok=True)
    host = host_of(url)
    out = os.path.join(raw_dir, host + ".json")
    dom = os.path.join(dom_dir, host + ".html")
    shot = os.path.join(shot_dir, host + ".png")

    # ALREADY INVESTIGATED? reuse the cached pivot rather than (expensively) re-collecting.
    if not force:
        prior = out if os.path.exists(out) else find_cached_raw(root, host, exclude=out)
        data = load_json(prior) if prior else None
        if data is not None:
            if prior != out:
                shutil.copyfile(prior, out)  # bring it into this case so kb_ingest still sees it
            if manifest_cb:
                manifest_cb(case, host, data, reused=True,
                            dom_path=dom if os.path.exists(dom) else "")
            return {"host": host, "ok": True, "reused": True, "error": None, "dom": dom,
                    "n_pivots": len(data.get("pivots", [])), "note": " (cached)", "data": data}

    # EGRESS POLICY — never let the analyst's own IP touch hostile infra without passive/proxy.
    if hostile and not passive and not proxy:
        return {"host": host, "ok": False, "reused": False, "n_pivots": 0, "data": None, "dom": dom,
                "note": "", "error": (f"BLOCKED by egress policy: {host} is hostile. Re-call with "
                                      "passive=true or proxy='<cidr>'.")}

    args = [url, "--pretty", "-o", out, "--save-dom", dom]
    if timeout is not None:
        args += ["--timeout", str(timeout)]
    if proxy:
        args += ["--proxy-range", proxy]
    args += list(extra_flags)
    if smoke:
        args += ["--no-enrich", "--no-whois"]                # cheap smoke only
    elif not no_archive:
        # EVIDENCE CAPTURE: Wayback SPN snapshot + master evidence ledger, case-tagged.
        args += ["--submit", "--archive-missing", "--master", "--case", case]
    screenshot_py = py
    if want_shot and not smoke and not (hostile and not proxy):   # screenshot needs a browser
        os.makedirs(shot_dir, exist_ok=True)                     # pivot_extract writes the PNG here
        args += ["--render", "--screenshot", shot]
        screenshot_py = render_py
    args, dropped = filter_args(py, collpath, root, args)
    base = [collpath, *args]
    # A --deep-archive collection exhausts Wayback history + every urlscan DOM + CommonCrawl +
    # archive.today on top of normal enrichment, so it needs far more than the 240s calibrated for
    # a single-capture collection (deep_archive self-budgets at ~150s; give the whole run headroom).
    _deep = "--deep-archive" in args
    _sub_timeout = 600 if _deep else (300 if want_shot else 240)
    r = run([screenshot_py, *base], cwd=root, timeout=_sub_timeout)
    data = load_json(out)
    if data is None:
        return {"host": host, "ok": False, "reused": False, "n_pivots": 0, "data": None, "dom": dom,
                "note": "", "error": f"pivot_extract failed for {host}: {(r.stderr or '')[-500:]}"}

    cf = (data.get("meta") or {}).get("cloudflare")             # Cloudflare interstitial? retry
    used = "direct"
    if cf and not smoke:
        retry, cf_dropped = filter_args(
            py, collpath, root,
            ["--solve-cf", "--flaresolverr", flaresolverr] if flaresolverr else ["--render"])
        if flaresolverr and not cf_dropped:
            run([py, *base, *retry], cwd=root, timeout=300)
            used = "flaresolverr"
        elif retry:
            run([render_py, *base, *retry], cwd=root, timeout=300)
            used = "render(browser)"
        else:
            used = "no CF bypass available (collector lacks --solve-cf/--render)"
        data = load_json(out) or data
    if manifest_cb:
        manifest_cb(case, host, data, reused=False, dom_path=dom, shot_path=shot)
    walled = (data.get("meta") or {}).get("cloudflare")
    cfnote = f"  · CF {cf} → {used} ({'STILL WALLED' if walled else 'bypassed'})" if cf else ""
    archnote = "" if (smoke or no_archive) else "  · archived + logged"
    # Never silently drop a requested capability — an unsupported flag means the collector in use
    # cannot do that step, and the analyst has to know the evidence was not captured.
    dropnote = f"  · unsupported by collector, skipped: {' '.join(dropped)}" if dropped else ""
    return {"host": host, "ok": True, "reused": False, "error": None, "dom": dom,
            "n_pivots": len(data.get("pivots", [])), "note": cfnote + archnote + dropnote,
            "data": data}


def collect_many(
    seeds: Sequence[str],
    case: str,
    *,
    max_workers: int = 8,
    on_result: Optional[Callable[[dict], None]] = None,
    retry_misses: int = 0,
    **collect_kwargs: Any,
) -> list[dict[str, Any]]:
    """Fan collect_host across `seeds` concurrently (threads, mechanical — NO LLM). Both front-ends
    delegate here so the parallel-collection wrapper is single-sourced too. `collect_kwargs` are
    forwarded to collect_host per seed (root/py/collector/knobs). `on_result(res)` fires as each
    host finalizes — use it for live per-host status. `retry_misses` re-collects a host whose
    result is not ok, up to N extra times, forcing past any partial cache (transient rate-limits /
    archive.org). Returns the list of collect_host result dicts (order = completion order)."""
    results: list[dict[str, Any]] = []

    def _one(seed: str) -> dict[str, Any]:
        res = collect_host(seed, case, **collect_kwargs)
        tries = 0
        while (not res.get("ok")) and tries < retry_misses:
            res = collect_host(seed, case, **{**collect_kwargs, "force": True})
            tries += 1
        return res

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, max_workers)) as ex:
        futs = {ex.submit(_one, s): s for s in seeds}
        for fu in concurrent.futures.as_completed(futs):
            try:
                res = fu.result()
            except Exception as e:  # noqa: BLE001
                res = {"host": host_of(futs[fu]), "ok": False, "reused": False, "n_pivots": 0,
                       "error": str(e), "data": None, "note": "", "dom": ""}
            if on_result:
                on_result(res)
            results.append(res)
    return results
