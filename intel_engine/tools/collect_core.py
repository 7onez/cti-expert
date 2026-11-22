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
import json
import os
import shutil
import subprocess
import threading
import time
from typing import Any, Callable, Optional, Sequence
from urllib.parse import urlparse

# --- small stdlib helpers (single home; harness/tools.py delegates to these) -------------
_FLAGS_CACHE: dict[str, frozenset[str]] = {}
_FLAGS_LOCK = threading.Lock()

# Per-call ceiling for subprocess "task calls" — ONE resolver (WebPivot/tools/wp_timeouts: env
# CTI_CALL_TIMEOUT → skill-root/engine .env → references/timeouts.json → 18000s / 5 h). Flooring
# in run() means every harness _run(...) call and every collector subprocess this module launches
# runs up to the ceiling — never past the active phase deadline (wp_timeouts clamps) — then times
# out and the run moves on, without editing each call site.
# wp_timeouts is stdlib, so importing it keeps this module dependency-free.
import signal
import sys
_WP_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "WebPivot", "tools")
sys.path.insert(0, _WP_DIR)
import wp_timeouts  # noqa: E402
from wp_timeouts import CALL_TIMEOUT, floor as _floor  # noqa: E402
import wp_exhaust  # noqa: E402 — execution-outcome vocabulary + collection_outcomes.json writer
from wp_refs import load_ref  # noqa: E402 — stdlib reference loader (RULE 3)

# AUTOMATIC per-host screenshot (WebPivot/references/screenshot.json -> collection). The env
# HARNESS_SCREENSHOT (0/1) wins over `enabled`; the per-host bound is still clamped to the phase
# deadline by run(). The shot itself runs in tools/collect_screenshot.py under the render
# interpreter, so no browser/Playwright code enters this stdlib module.
_SHOT_FALLBACK = {"collection": {"enabled": True, "per_host_timeout_seconds": 60}}
_SHOT_REF = load_ref(os.path.join(_WP_DIR, os.pardir, "references", "screenshot.json"),
                     _SHOT_FALLBACK)["collection"]
SHOT_DEFAULT = bool(_SHOT_REF.get("enabled", True))
SHOT_TIMEOUT = int(_SHOT_REF.get("per_host_timeout_seconds") or 60)
SHOT_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "collect_screenshot.py")


def screenshots_enabled(env: Optional[dict] = None) -> bool:
    """HARNESS_SCREENSHOT=0/1 (also false/true, no/yes, off/on), else the references default."""
    v = str((os.environ if env is None else env).get("HARNESS_SCREENSHOT", "")).strip().lower()
    if v in ("0", "false", "no", "off"):
        return False
    if v in ("1", "true", "yes", "on"):
        return True
    return SHOT_DEFAULT


def host_of(url: str) -> str:
    """Bare hostname for a URL/host string (no scheme/path)."""
    return urlparse(url if "://" in url else "http://" + url).hostname or url


class RunResult(subprocess.CompletedProcess):
    """A CompletedProcess with a tri-state `status`: "ok" (exit 0), "error" (non-zero exit or
    could not start) or "timed_out" (killed at its bound; returncode 124, partial output kept)."""

    def __init__(self, args, returncode, stdout="", stderr="", *, timed_out=False):
        super().__init__(args, returncode, stdout, stderr)
        self.timed_out = timed_out

    @property
    def status(self) -> str:
        return "timed_out" if self.timed_out else ("ok" if self.returncode == 0 else "error")


def _kill_group(p: subprocess.Popen) -> None:
    """SIGKILL the child's whole process group (it leads its own session), so a grandchild that
    inherited the stdout/stderr pipes cannot keep communicate() blocked after the child dies."""
    try:
        os.killpg(p.pid, signal.SIGKILL)
    except OSError:
        pass
    try:
        p.kill()
    except OSError:
        pass


def run(cmd: Sequence[str], cwd: str, timeout: int = None,
        env: Optional[dict] = None, *, exact: bool = False) -> RunResult:
    """Run one task-call subprocess; never raises. The bound is floored to CALL_TIMEOUT (or, with
    exact=True, kept as given — for a caller with its own budget) and clamped to the time left in
    the active harness phase. On timeout the whole process group is killed and a
    RunResult(status="timed_out", returncode=124) carries whatever output arrived."""
    eff = wp_timeouts.clamp(timeout) if exact and isinstance(timeout, (int, float)) else _floor(timeout)
    deadline = wp_timeouts.phase_deadline()
    child_env = {**os.environ, **(env or {})}
    if deadline is not None:   # children clamp their own calls (urlopen floor) to the same deadline
        child_env[wp_timeouts.DEADLINE_ENV] = repr(deadline)
    cmd = list(cmd)
    try:
        p = subprocess.Popen(cmd, cwd=cwd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True, env=child_env,
                             start_new_session=True)
    except (OSError, ValueError) as e:
        return RunResult(cmd, 127, "", f"could not start {cmd[:1]}: {e}")
    try:
        out, err = p.communicate(timeout=eff)
        return RunResult(cmd, p.returncode, out or "", err or "")
    except subprocess.TimeoutExpired:
        _kill_group(p)
        try:
            out, err = p.communicate(timeout=5)
        except subprocess.TimeoutExpired:    # a descendant left the group and still holds a pipe
            for f in (p.stdout, p.stderr):
                try:
                    f.close()
                except OSError:
                    pass
            out, err = "", ""
        num = isinstance(timeout, (int, float))
        asked = timeout if exact and num else max(int(timeout) if num else 0, CALL_TIMEOUT)
        why = ("phase budget" if deadline is not None and eff < asked
               else ("call bound" if exact else "call ceiling"))
        note = f"timed out after {eff}s ({why})"
        return RunResult(cmd, 124, out or "", ((err or "") + "\n" + note).strip(), timed_out=True)


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


def _shot_plan(url: str, data: dict, status: str) -> tuple[Optional[str], dict, str]:
    """(target URL or None, extra manifest fields, skip reason) for one collected host.

    Collected live → the host itself. Recovered from a Wayback capture → the toolbar-free
    `if_` view of THAT capture, filed under the host with source=wayback (the house report then
    dates it by the archive, as it does its own archive renders). Any other recovery (a urlscan
    DOM) or an unreachable host → no shot, with the reason."""
    meta = data.get("meta") or {}
    rv = str(meta.get("recovered_via") or "")
    if status.startswith("unreachable"):
        return None, {}, "host unreachable; no live page and no archive copy"
    if status.startswith(("recovered", "archive-only")) and rv.startswith("wayback:"):
        ts = rv.split(":", 1)[1]
        src = meta.get("source") or url
        archived_at = (f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}T{ts[8:10]}:{ts[10:12]}:{ts[12:14]}Z"
                       if len(ts) >= 14 and ts[:14].isdigit() else None)
        return (f"https://web.archive.org/web/{ts}if_/{src}",
                {"source": "wayback", "source_url": f"https://web.archive.org/web/{ts}/{src}",
                 "archived_at": archived_at}, "")
    if status.startswith("archive-only") or (status.startswith("recovered") and rv != "flaresolverr"):
        return None, {}, f"recovered from {rv or 'an archive'}; no Wayback capture to render"
    return url, {}, ""


def _fetch_exit(data: dict) -> Optional[str]:
    """The masked pool exit a hostile fetch used: the exit that answered, else the last one tried."""
    att = [a for a in (((data.get("meta") or {}).get("hostile_fetch") or {}).get("attempts") or [])
           if isinstance(a, dict) and a.get("exit")]
    ok = [a for a in att if a.get("result") == "ok"]
    return (ok or att or [{}])[-1].get("exit")


def take_screenshot(url: str, case: str, host: str, data: dict, status: str, *, root: str,
                    render_py: str, hostile: bool = False, proxy: Optional[str] = None,
                    egress_env: Optional[dict] = None,
                    timeout: Optional[int] = None) -> tuple[str, dict]:
    """One custody-tracked full-page screenshot of a collected host → (summary, detail); never
    raises. `summary` is what the per-host line and the result dict carry: 'ok (<path>, sha256
    <…>, seal <status>)' | 'failed (<reason>)' | 'unavailable (no browser)' | 'skipped (<why>)'.

    The child (tools/collect_screenshot.py → wp_screenshot) writes evidence/screenshots/<host>/
    <UTC>.png with sha256, a custody line, a seal and seal_status — the one screenshot store. A
    hostile host is shot only through the pool exit its fetch used (`--exit`), pinned no-direct;
    the bound is `timeout` (screenshot.json per_host_timeout_seconds), clamped to the phase
    deadline."""
    target, extra, why = _shot_plan(url, data, status)
    if not target:
        return f"skipped ({why})", {"status": "skipped", "reason": why}
    bound = int(timeout or SHOT_TIMEOUT)
    cmd = [render_py, SHOT_SCRIPT, target, "--case", case, "--root", root, "--host", host,
           "--timeout", str(max(1, bound * 3 // 4)),
           "--label", "landing page (web-archive snapshot)" if extra else "landing page (collection)"]
    if extra:
        cmd += ["--extra", json.dumps(extra)]
    if proxy:
        cmd += ["--proxy-range", proxy]
    if hostile:
        cmd.append("--hostile")
        ex = _fetch_exit(data)
        if ex:
            cmd += ["--exit", ex]
    try:
        r = run(cmd, cwd=root, timeout=bound, env=egress_env, exact=True)
    except Exception as e:  # noqa: BLE001 — never fatal to collection
        return f"failed ({type(e).__name__}: {e})", {"status": "failed", "reason": str(e)}
    if getattr(r, "timed_out", False):
        why = (r.stderr or "").strip().splitlines()[-1:] or [f"timed out after {bound}s"]
        return f"failed ({why[0]})", {"status": "failed", "reason": why[0]}
    detail = None
    for ln in reversed((r.stdout or "").strip().splitlines()):
        try:
            detail = json.loads(ln)
        except ValueError:
            continue
        if isinstance(detail, dict):
            break
    if not isinstance(detail, dict) or not detail.get("status"):
        tail = ((r.stderr or "").strip().splitlines() or [f"exit {r.returncode}, no result"])[-1][:200]
        return f"failed ({tail})", {"status": "failed", "reason": tail}
    st, reason = detail["status"], detail.get("reason")
    if st == "ok":
        rel = os.path.relpath(detail["path"], root) if detail.get("path") else "?"
        return (f"ok ({rel}, sha256 {detail.get('sha256')}, seal {detail.get('seal_status')})",
                detail)
    return f"{st} ({reason})", detail


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
    shot_timeout: Optional[int] = None,
    flaresolverr: Optional[str] = None,
    timeout: Optional[int] = None,
    extra_flags: Sequence[str] = (),
    manifest_cb: Optional[Callable[..., None]] = None,
) -> dict[str, Any]:
    """Collect ONE host end-to-end and return a summary dict; never raises.

    Pipeline: cache-reuse (already investigated in ANY case?) → onion isolation (a .onion never
    reaches the clearnet collector) → egress policy (refuse a direct live fetch of a hostile
    target) → collector run with unsupported-flag filtering → Cloudflare retry
    (flaresolverr/browser) → screenshot (want_shot) → optional evidence manifest → execution
    outcomes recorded in cases/<case>/collection_outcomes.json (wp_exhaust vocabulary).
    Self-contained + stdlib, so it is safe to fan out across threads.

    `collector` is the pivot_extract.py path (absolute, or relative to `root`). `render_py` is the
    interpreter used for the browser render/screenshot (defaults to `py`). `want_shot` takes one
    custody-tracked full-page screenshot of a host collected live or recovered from a Wayback
    capture (take_screenshot; `shot_timeout` overrides screenshot.json per_host_timeout_seconds);
    its outcome is the result's `screenshot` summary and never fails the collection.
    `manifest_cb(case, host, data, reused=..., dom_path=..., shot_path=...)` records evidence
    provenance when provided (the harness passes its `_append_manifest`; the deterministic
    pipeline passes None). `extra_flags` are appended verbatim before filtering (e.g.
    `--whois-reverse` / `--fofa-full` / `--render`).

    Result dict keys: host, ok, reused, error, dom, n_pivots, note, status, collect_failed, data,
    outcome (and `skipped` for a policy skip — onion / hostile — which collect_many never retries).
    `status` is one of 'ok' (the live fetch itself succeeded), 'recovered (<source>)' (content came
    from an archive/urlscan capture instead), 'archive-only (<source>; live failed (…))' (a
    hostile host whose live fetch failed on every exit tried), 'unreachable (<reason>)' (neither),
    'error (…)' / 'timed_out (…)' (the collector crashed or produced no fresh file), or
    'skipped (onion)' —
    `note` starts with it on a collected host, so the printed per-host line never reports 'ok'
    for a dead live target. `collect_failed` is True for 'unreachable' and for a crashed/timed-out
    collector — use it, not `ok`, to tell a real collection failure from a cached/host-derived hit.
    """
    render_py = render_py or py
    collpath = collector if os.path.isabs(collector) else os.path.join(root, collector)
    raw_dir = os.path.join(root, "cases", case, "raw")
    dom_dir = os.path.join(root, "cases", case, "dom")
    os.makedirs(raw_dir, exist_ok=True)
    os.makedirs(dom_dir, exist_ok=True)
    # A bare hostname ("pa.tatao.net", what the harness's frontier discovery hands back) is not a
    # source pivot_extract accepts — it refused every one in <1 s ("source must be a URL"), so a
    # whole round read as "collected 0/N". The pipeline already prefixes https://; do it once here
    # so every caller is covered. A local file (a saved .eml / .html) stays a path.
    if "://" not in url and not os.path.exists(url):
        url = "https://" + url
    host = host_of(url)
    out = os.path.join(raw_dir, host + ".json")
    dom = os.path.join(dom_dir, host + ".html")

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

    case_dir = os.path.join(root, "cases", case)

    # ONION ISOLATION — a .onion is never handed to the collector. pivot_extract's live fetch,
    # TLS/JARM/MX probes, live-DNS anchor, WHOIS/RDAP and CT all resolve or query the name over
    # the clearnet (system resolver / rdap.org / crt.sh), so even a Tor-proxied fetch would leak
    # it through the MX `dig` and the DNS anchor. Recorded as a policy skip, not a failure: the
    # clearnet-only layers become not-applicable; the rest stay open for an onion-safe route
    # (corpus/search pivots of the string still run through the harness and enrichment).
    if wp_exhaust.is_onion_host(host):
        skip = wp_exhaust.outcome("skipped_policy", "onion")
        wp_exhaust.record_outcomes(
            case_dir, host, collect=skip,
            layers=wp_exhaust.layer_outcomes(
                {"meta": {"host": host}, "pivots": []},
                failure=wp_exhaust.outcome("skipped_policy", "onion_collector")))
        return {"host": host, "ok": False, "reused": False, "n_pivots": 0, "data": None,
                "dom": dom, "note": "", "skipped": True, "collect_failed": False,
                "status": "skipped (onion)", "outcome": skip,
                "error": ("skipped by policy: .onion — the clearnet collector would resolve it via "
                          "the system DNS; corpus/search pivots of the string still apply")}

    # EGRESS POLICY — never let the analyst's own IP touch hostile infra without passive/proxy.
    if hostile and not passive and not proxy:
        skip = wp_exhaust.outcome("skipped_policy", "hostile")
        wp_exhaust.record_outcomes(case_dir, host, collect=skip)
        return {"host": host, "ok": False, "reused": False, "n_pivots": 0, "data": None, "dom": dom,
                "note": "", "skipped": True, "outcome": skip,
                "error": (f"BLOCKED by egress policy: {host} is hostile. Re-call with "
                          "passive=true or proxy='<cidr>'.")}

    args = [url, "--pretty", "-o", out, "--save-dom", dom]
    if timeout is not None:
        args += ["--timeout", str(timeout)]
    if proxy:
        args += ["--proxy-range", proxy]
    args += list(extra_flags)
    # HOSTILE (passive pool or explicit proxy): the collector names its exit, rotates once to a
    # different exit on a proxy-side failure, then reads the archives only (pivot_extract
    # --hostile). The child's egress layer is pinned to no-direct as well, whatever proxies.json
    # says, so no urllib call in that process can fail over to the analyst's own IP.
    egress_env = None
    if hostile:
        args.append("--hostile")
        egress_env = {"CTI_PROXY_ALLOW_DIRECT": "0"}
    if smoke:
        args += ["--no-enrich", "--no-whois"]                # cheap smoke only
    elif not no_archive:
        # EVIDENCE CAPTURE: Wayback SPN snapshot + master evidence ledger, case-tagged.
        args += ["--submit", "--archive-missing", "--master", "--case", case]
    args, dropped = filter_args(py, collpath, root, args)
    base = [collpath, *args]
    # A --deep-archive collection SAMPLES the archive layers (≤25 Wayback snapshots, ≤25 urlscan
    # DOMs from ≤5×100 scans, CommonCrawl + archive.today) within a ~150s self-budget, on top of
    # normal enrichment — heavier than the 240s calibrated for a single-capture collection, but NOT
    # exhaustive (that is the separate resumable `wayback-exhaust` job). Give the run headroom.
    _deep = "--deep-archive" in args
    _sub_timeout = 600 if _deep else 240
    # EXECUTION OUTCOME — a collector that crashes, times out or exits without writing a FRESH
    # file is FAILED (re-runnable), never "collected, found nothing". The mtime check matters on
    # a forced re-collect: the previous run's file is still on disk and would otherwise be read
    # back as this run's result.
    before = os.path.getmtime(out) if os.path.exists(out) else None
    t0 = time.monotonic()
    r, run_err = None, None
    try:
        r = run([py, *base], cwd=root, timeout=_sub_timeout, env=egress_env)
    except subprocess.TimeoutExpired as e:
        run_err = ("timed_out", f"collector timed out after {e.timeout}s")
    except Exception as e:  # noqa: BLE001 — collect_host never raises
        run_err = ("error", f"{type(e).__name__}: {e}")
    elapsed = time.monotonic() - t0
    fresh = os.path.exists(out) and os.path.getmtime(out) != before
    data = load_json(out) if (run_err is None and fresh) else None
    if data is None:
        if run_err is None:
            rc = getattr(r, "returncode", None)
            run_err = ("timed_out" if rc == 124 else "error",
                       f"exit {rc}: {((getattr(r, 'stderr', '') or '')[-300:]).strip() or 'no output file'}")
        fail = wp_exhaust.outcome(run_err[0], run_err[1], elapsed)
        wp_exhaust.record_outcomes(
            case_dir, host, collect=fail,
            layers=wp_exhaust.layer_outcomes({"meta": {"host": host}, "pivots": []}, failure=fail))
        return {"host": host, "ok": False, "reused": False, "n_pivots": 0, "data": None, "dom": dom,
                "note": "", "collect_failed": True, "status": f"{run_err[0]} ({run_err[1][:120]})",
                "outcome": fail,
                "error": f"pivot_extract {run_err[0]} for {host}: {run_err[1]}"}

    cf = (data.get("meta") or {}).get("cloudflare")             # Cloudflare interstitial? retry
    used = "direct"
    if cf and not smoke:
        retry, cf_dropped = filter_args(
            py, collpath, root,
            ["--solve-cf", "--flaresolverr", flaresolverr] if flaresolverr else ["--render"])
        if flaresolverr and not cf_dropped:
            run([py, *base, *retry], cwd=root, timeout=300, env=egress_env)
            used = "flaresolverr"
        elif retry:
            # The browser retry exists to clear a Cloudflare challenge: only Chromium can, so the
            # render engine is pinned here — under CTI_BROWSER=auto a plain --render would pick Moli.
            run([render_py, *base, *retry], cwd=root, timeout=300,
                env={**(egress_env or {}), "CTI_BROWSER": "chromium"})
            used = "render(browser)"
        else:
            used = "no CF bypass available (collector lacks --solve-cf/--render)"
        data = load_json(out) or data
    meta = data.get("meta") or {}
    walled = meta.get("cloudflare")
    # STATUS REFLECTS REALITY: 'ok' only when the live fetch itself succeeded (no live_error);
    # 'recovered (<source>)' when content came from an archive/urlscan capture instead;
    # 'unreachable (<reason>)' when neither — never the bare 'ok' fallback a blank note used to
    # produce even when the live fetch failed and nothing recovered it. A hostile host carries the
    # collector's own verdict (meta.content_source / live_fetch): 'archive-only (<source>; live
    # failed (…))' or 'unreachable (live failed (…); archive: …)', so the frontier and the
    # assessment read "archive-only, live failed", never "collected live".
    live_error = meta.get("live_error")
    recovered_via = meta.get("recovered_via")
    content_source = meta.get("content_source") if hostile else None
    if content_source == "archive":
        status = f"archive-only ({recovered_via}; live {meta.get('live_fetch')})"
    elif content_source == "none":
        status = (f"unreachable (live {meta.get('live_fetch')}; archive: "
                  f"{(meta.get('hostile_fetch') or {}).get('archive') or 'none'})")
    elif not live_error:
        status = "ok"
    elif recovered_via:
        status = f"recovered ({recovered_via})"
    else:
        status = f"unreachable ({live_error})"
    # SCREENSHOT — one custody-tracked PNG per host collected live or recovered from a Wayback
    # capture, in the same store as capture_screenshot (evidence/screenshots/<host>/<UTC>.png).
    # A separate browser pass AFTER the fetch, so the collected DOM path is unchanged; a hostile
    # host goes only through the exit its fetch used. Never fatal: failure is just recorded.
    shot_note, shot_detail = "", None
    if want_shot and not smoke:
        shot_note, shot_detail = take_screenshot(
            url, case, host, data, status, root=root, render_py=render_py, hostile=hostile,
            proxy=proxy, egress_env=egress_env, timeout=shot_timeout)
    if manifest_cb:
        manifest_cb(case, host, data, reused=False, dom_path=dom,
                    shot_path=(shot_detail or {}).get("path") or "")
    cfnote = f"  · CF {cf} → {used} ({'STILL WALLED' if walled else 'bypassed'})" if cf else ""
    archnote = "" if (smoke or no_archive) else "  · archived + logged"
    # Never silently drop a requested capability — an unsupported flag means the collector in use
    # cannot do that step, and the analyst has to know the evidence was not captured.
    dropnote = f"  · unsupported by collector, skipped: {' '.join(dropped)}" if dropped else ""
    # Per-layer outcomes for this run: evidence → ran; a flag this run passed (after the --help
    # filter) → skipped_policy; meta.capability → skipped_no_key / free-only. `--no-archive` is a
    # policy pseudo-flag: capture is off because pivot_extract ran without --case.
    n_piv = len(data.get("pivots", []))
    done = wp_exhaust.outcome("ran" if n_piv else "empty", status, elapsed)
    try:
        wp_exhaust.record_outcomes(
            case_dir, host, collect=done,
            layers=wp_exhaust.layer_outcomes(
                data, flags=list(args) + (["--no-archive"] if (smoke or no_archive) else [])))
    except OSError as e:  # the outcome file is bookkeeping — never fail a good collection on it
        dropnote += f"  · outcome record not written ({e})"
    return {"host": host, "ok": True, "reused": False, "error": None, "dom": dom,
            "n_pivots": n_piv, "outcome": done,
            "note": status + cfnote + archnote + (f"  · screenshot: {shot_note}" if shot_note else "")
            + dropnote,
            "screenshot": shot_note or None, "screenshot_detail": shot_detail,
            # `ok` above means only "pivot_extract produced a parseable file" — it stays True even
            # for the 'unreachable' branch (WHOIS/DNS-derived pivots can still land with zero live
            # content), so it is the WRONG signal for "did we actually collect this host". Callers
            # that print a per-host line or feed convergence.py's `snapshot --failed` must key off
            # `collect_failed` instead, or a blocked/dead target reads as a successful collection.
            "collect_failed": status.startswith("unreachable"),
            "status": status, "data": data}


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
        while (not res.get("ok")) and not res.get("skipped") and tries < retry_misses:
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
