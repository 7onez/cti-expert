"""wp_wayback_guard — run-scoped circuit breaker + machine-wide pacer + per-exit cooldown on every
Wayback Machine / archive.org call (the pacer/cooldown section is at the end of this file; the
client every call site uses is wp_wayback).

WHY THIS EXISTS
---------------
A hostile or offline archive.org (a network blip, a proxy CONNECT failure, a sustained run of
429/5xx) used to mean every Wayback-backed collector kept retrying it host after host, burning the
whole collection window on a service that was never going to answer. This module counts
CONSECUTIVE Wayback FAILURES for one RUN; once they cross the threshold, every further Wayback
call site in the SAME run returns its normal tri-state skip WITHOUT making a request. The next run
(a fresh $INTEL_RUN_ID) starts with a clean counter. This is a run-scoped breaker, never a usage
cap: unlimited successful calls never trip it — only an unbroken run of failures does (project
rule: no CTI-wide local usage caps).

WHAT COUNTS AS A FAILURE
-------------------------
The archive did not ANSWER: a network error, a timeout, connection refused/reset, a proxy CONNECT
failure, HTTP 429, or HTTP 5xx. It is NOT a failure when the archive gives a valid answer that
there is simply nothing there — an empty CDX result, the availability API reporting no snapshot, a
404 for a snapshot that legitimately does not exist. `is_failure()` is the one classifier every
call site shares, so this distinction never drifts between collectors.

STATE
-----
Keyed on `$INTEL_RUN_ID` — set once by the entry points (`tools/intel.py open/loop/enrich/cti`,
`tools/house_report.py`, `harness/orchestrator.py`, `scripts/backend/intel.py`) via
`os.environ.setdefault`, so every child process this run spawns shares the same id. No run id at
all (a script invoked by hand) falls back to a coarse TIME WINDOW (`adhoc_window_seconds`, default
1800s) so an ad-hoc session still recovers on its own. The counter lives in a small JSON file:
under the case dir when `$WP_CASE_DIR`/`$INTEL_CASE` identify one
(`cases/<case>/wayback_breaker.json`), else `intel_engine/MEMORY/wayback_breaker.json`. Parallel
collector subprocesses share the run id and the file; read-modify-write goes through an `fcntl`
advisory lock on a sidecar `.lock` file (mirrors `wp_plans.py`) — degrades to best-effort on
platforms without `fcntl`, never raises.

USAGE
-----
    import wp_wayback_guard as wg

    reason = wg.blocked()
    if reason:
        return {"skipped": reason, "skipped_kind": "breaker"}
    try:
        ...make the one Wayback request...
    except Exception as exc:
        wg.record(not wg.is_failure(exc), kind="cdx")
        ...handle...
    else:
        wg.record(True, kind="cdx")

`guarded()` wraps a zero/kw-arg client that already returns the tri-state dict convention: if the
breaker is tripped, the wrapped client is never called and its skip dict comes back instead.

A tripped skip is never a definitive "not archived": callers must not memoise it — `wp_casememo`
already refuses any `skipped_kind` outside {"entitlement", "plan"}, so `skipped_kind="breaker"` is
non-memoisable there without further change — and must not let it read as an empty/negative
collection result. It is a GAP (not queried), which is exactly how `wp_exhaust` / `collection_gaps`
already report it: their "archive" layer detects a positive `archived_via_wayback` /
`recovered_via` field, and a skip sets neither, so it reads as "never ran", not "ran, found
nothing".
"""
from __future__ import annotations

import json
import os
import re
import sys
import threading
import time

try:
    import fcntl
except Exception:  # noqa: BLE001 — Windows / restricted sandboxes: degrade to best-effort
    fcntl = None

try:
    from wp_refs import ref_path, load_ref
except Exception:  # noqa: BLE001 — never let a missing sibling module break the breaker
    ref_path = load_ref = None

__all__ = ["blocked", "record", "is_failure", "guarded", "fail_limit", "adhoc_window_seconds",
           "admit", "observe", "cooling", "min_interval", "cooldown_seconds",
           "archive_user_agent", "ua_for", "scope_ua",
           "RUN_ID_ENV", "CASE_DIR_ENV", "CASE_ID_ENV", "STATE_FILE", "GUARD_FALLBACK",
           "PACE_STATE_ENV", "MIN_INTERVAL_ENV"]

RUN_ID_ENV = "INTEL_RUN_ID"
CASE_DIR_ENV = "WP_CASE_DIR"
CASE_ID_ENV = "INTEL_CASE"
STATE_FILE = "wayback_breaker.json"

# RULE 3 — tunables live in references/wayback_guard.json; this is the conservative embedded
# minimum load_ref() falls back to when the file is missing or malformed.
GUARD_FALLBACK = {
    "fail_limit": {"value": 20},
    "adhoc_window_seconds": {"value": 1800},
    "pace": {"index": 1.5, "playback": 4.0},
    "cooldown": {"throttled": 60, "refused": 300, "max": 3600},
    "archive_user_agent": {"value": "cti-expert/1.0 (OSINT archive client; python-urllib)"},
}


def _load_refs() -> dict:
    if load_ref is None or ref_path is None:
        import copy
        return copy.deepcopy(GUARD_FALLBACK)
    return load_ref(ref_path(__file__, "wayback_guard.json"), GUARD_FALLBACK)


_REFS = _load_refs()
_LOCK = threading.Lock()
_LOGGED = False   # per-process: the stderr trip notice fires once, however many callers ask


def _reference_fail_limit() -> int:
    try:
        return int(_REFS["fail_limit"]["value"])
    except Exception:  # noqa: BLE001
        return 20


def _reference_adhoc_window() -> int:
    try:
        return max(1, int(_REFS["adhoc_window_seconds"]["value"]))
    except Exception:  # noqa: BLE001
        return 1800


def fail_limit() -> int:
    """Consecutive-failure threshold — reference default, overridable with $WAYBACK_FAIL_LIMIT."""
    env = os.environ.get("WAYBACK_FAIL_LIMIT")
    if env:
        try:
            n = int(env)
            if n > 0:
                return n
        except ValueError:
            pass
    return _reference_fail_limit()


def adhoc_window_seconds() -> int:
    """Fallback bucket width (seconds) when no $INTEL_RUN_ID is set at all."""
    return _reference_adhoc_window()


def archive_user_agent() -> str:
    """The honest client UA archive.org hosts get (wayback_guard.json → archive_user_agent)."""
    for src in (_REFS, GUARD_FALLBACK):
        try:
            v = str(src["archive_user_agent"]["value"]).strip()
            if v:
                return v
        except Exception:  # noqa: BLE001
            continue
    return GUARD_FALLBACK["archive_user_agent"]["value"]


def ua_for(host_or_url: str, ua: str) -> str:
    """`ua` unless the request goes to archive.org (or a subdomain), which gets
    archive_user_agent() instead — archive.org 429s a browser UA from a script client. Every
    other host, target or third party, keeps the caller's UA (the Android-UA project rule)."""
    s = (host_or_url or "").strip().lower()
    if "://" in s:
        import urllib.parse
        s = urllib.parse.urlsplit(s).hostname or ""
    s = s.split("/")[0].split(":")[0].rstrip(".")
    return archive_user_agent() if (s == "archive.org" or s.endswith(".archive.org")) else ua


_BASE_UA_ATTR = "_cti_base_ua"


def scope_ua(req, base_ua: str):
    """Give urllib Request `req` the UA for ITS host (ua_for) and remember the caller's `base_ua`,
    so every redirect hop is re-scoped too: urllib copies a request's headers onto each hop, which
    would otherwise carry the archive.org UA to whatever host the archive redirects to."""
    setattr(req, _BASE_UA_ATTR, base_ua)
    req.add_header("User-Agent", ua_for(req.full_url, base_ua))
    return req


def _install_redirect_scope() -> None:
    """Re-scope the UA on every redirect hop of a scope_ua() request, whatever opener sends it
    (direct, cti_proxy's installed opener, a wp_exits.Exit). Patches urllib's base
    HTTPRedirectHandler once; a request without the scope_ua() marker is returned untouched, so no
    other caller's behaviour changes. Idempotent across imports."""
    import urllib.request
    cls = urllib.request.HTTPRedirectHandler
    if getattr(cls.redirect_request, "_cti_ua_scoped", False):
        return
    orig = cls.redirect_request

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = orig(self, req, fp, code, msg, headers, newurl)
        base = getattr(req, _BASE_UA_ATTR, None)
        if new is not None and base is not None:
            scope_ua(new, base)
        return new

    redirect_request._cti_ua_scoped = True
    cls.redirect_request = redirect_request


_install_redirect_scope()


def _engine_root() -> str:
    # this file: intel_engine/WebPivot/tools/wp_wayback_guard.py -> intel_engine/
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _state_path() -> str:
    # Explicit override first — tests and the audit gate point it at a temp file so a stubbed
    # failure can never trip the user's real breaker.
    if os.environ.get("WAYBACK_GUARD_STATE"):
        return os.environ["WAYBACK_GUARD_STATE"]
    case_dir = os.environ.get(CASE_DIR_ENV) or ""
    if not case_dir:
        case_id = os.environ.get(CASE_ID_ENV) or ""
        if case_id and os.sep not in case_id and case_id not in (".", ".."):
            case_dir = os.path.join(_engine_root(), "cases", case_id)
    if case_dir:
        return os.path.join(case_dir, STATE_FILE)
    return os.path.join(_engine_root(), "MEMORY", STATE_FILE)


def _run_key() -> str:
    rid = os.environ.get(RUN_ID_ENV)
    if rid:
        return f"run:{rid}"
    window = adhoc_window_seconds()
    return f"adhoc:{int(time.time() // window)}"


def _read_doc() -> dict:
    path = _state_path()
    try:
        if not os.path.isfile(path):
            return {}
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
        return doc if isinstance(doc, dict) else {}
    except Exception:  # noqa: BLE001
        return {}


def _prune(doc: dict, keep_key: str) -> dict:
    """Keep the current run/window plus anything touched in the last day, so a long-lived case
    dir's breaker file never grows across every run it has ever seen."""
    cutoff = time.time() - 86400
    out = {}
    for k, v in doc.items():
        if k == keep_key or (isinstance(v, dict) and v.get("updated", 0) >= cutoff):
            out[k] = v
    return out


def _transact(fn, path: str | None = None):
    """Lock the state file's sidecar `.lock`, hand `fn(doc)` the parsed document, atomically
    persist whatever it returns as the new document, and give back fn's second return value. Never
    raises: any failure to make/read/lock/write the file degrades to `None`, i.e. 'not blocked' —
    a broken breaker must never brick collection. `path` defaults to the run breaker's state file;
    the egress pacer passes its own."""
    path = path or _state_path()
    try:
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)
        with _LOCK, open(path + ".lock", "a", encoding="utf-8") as lk:
            if fcntl is not None:
                try:
                    fcntl.flock(lk.fileno(), fcntl.LOCK_EX)
                except Exception:  # noqa: BLE001
                    pass
            try:
                doc = {}
                if os.path.isfile(path):
                    try:
                        with open(path, encoding="utf-8") as fh:
                            doc = json.load(fh)
                    except Exception:  # noqa: BLE001
                        doc = {}
                if not isinstance(doc, dict):
                    doc = {}
                doc, result = fn(doc)
                tmp = path + ".tmp"
                with open(tmp, "w", encoding="utf-8") as fh:
                    json.dump(doc, fh)
                    fh.flush()
                    try:
                        os.fsync(fh.fileno())
                    except Exception:  # noqa: BLE001
                        pass
                os.replace(tmp, path)
                return result
            finally:
                if fcntl is not None:
                    try:
                        fcntl.flock(lk.fileno(), fcntl.LOCK_UN)
                    except Exception:  # noqa: BLE001
                        pass
    except Exception:  # noqa: BLE001
        return None


def _log_trip() -> None:
    global _LOGGED
    if _LOGGED:
        return
    _LOGGED = True
    print(f"[wayback-guard] {fail_limit()} consecutive Wayback failures this run — skipping "
          f"Wayback for the rest of it (retried on the next run)", file=sys.stderr)


def blocked() -> str | None:
    """None when Wayback calls are allowed right now; a human-readable reason when the breaker is
    tripped for the current run/window. A plain read — never makes a network call, never blocks
    on the lock other writers hold."""
    limit = fail_limit()
    e = _read_doc().get(_run_key()) or {}
    streak = int(e.get("streak", 0) or 0)
    if not (bool(e.get("tripped")) or streak >= limit):
        return None
    _log_trip()
    return (f"Wayback skipped for the rest of this run after {limit} consecutive failures — "
            f"retried on the next run")


def record(ok: bool, kind: str = "") -> None:
    """Record one Wayback attempt's outcome. A success resets the streak to 0; a failure
    increments it and trips the breaker once `fail_limit()` consecutive failures land. Never a
    usage cap on success — only failures ever move the counter toward tripping."""
    limit = fail_limit()
    key = _run_key()

    def _update(doc):
        e = dict(doc.get(key) or {})
        if ok:
            e["streak"] = 0
            e["tripped"] = False
        else:
            e["streak"] = int(e.get("streak", 0) or 0) + 1
            if kind:
                e["last_kind"] = kind
            if e["streak"] >= limit:
                e["tripped"] = True
        e["updated"] = time.time()
        doc[key] = e
        doc = _prune(doc, key)
        newly_tripped = (not ok) and e.get("tripped") and e["streak"] == limit
        return doc, newly_tripped

    newly_tripped = _transact(_update)
    if newly_tripped:
        _log_trip()


_STATUS_FAIL_RE = re.compile(r"\b(429|5\d\d)\b")
_TRANSPORT_HINTS = ("timed out", "timeout", "connection refused", "connection reset",
                    "connect timeout", "proxy", "temporary failure in name resolution",
                    "network is unreachable", "econnreset", "econnrefused",
                    "handshake", "reset by peer", "broken pipe")


def is_failure(exc_or_status) -> bool:
    """True when the archive did not ANSWER — network error, timeout, connection refused/reset, a
    proxy CONNECT failure, HTTP 429, HTTP 5xx. False for a valid answer, including a valid 'no
    capture' answer (empty CDX, availability API with no snapshot, a genuine 404) — that is an
    answer, not a failure, and must never count against the streak. Accepts an int status code, an
    exception (urllib/requests/generic), or a plain error-message string."""
    if exc_or_status is None or isinstance(exc_or_status, bool):
        return False
    if isinstance(exc_or_status, int):
        return exc_or_status == 429 or exc_or_status >= 500
    if isinstance(exc_or_status, BaseException):
        import socket
        import urllib.error
        if isinstance(exc_or_status, urllib.error.HTTPError):
            return is_failure(exc_or_status.code)
        try:
            import requests.exceptions as _rqexc
        except Exception:  # noqa: BLE001
            _rqexc = None
        if _rqexc is not None and isinstance(exc_or_status, _rqexc.RequestException):
            resp = getattr(exc_or_status, "response", None)
            status = getattr(resp, "status_code", None) if resp is not None else None
            if status is not None:
                return is_failure(status)
            return True   # requests ConnectionError/Timeout/ProxyError with no response at all
        if isinstance(exc_or_status, (TimeoutError, socket.timeout, ConnectionError,
                                       urllib.error.URLError, OSError)):
            return True
        text = str(exc_or_status).lower()
        return bool(_STATUS_FAIL_RE.search(text)) or any(h in text for h in _TRANSPORT_HINTS)
    text = str(exc_or_status).lower()
    if _STATUS_FAIL_RE.search(text):
        return True
    return any(h in text for h in _TRANSPORT_HINTS)


def guarded(fn):
    """Decorate a Wayback client that already returns the tri-state dict convention: if the
    breaker is tripped, `fn` is never called and its skip dict comes back instead."""
    import functools

    @functools.wraps(fn)
    def _wrapped(*args, **kwargs):
        reason = blocked()
        if reason:
            return {"skipped": reason, "skipped_kind": "breaker"}
        return fn(*args, **kwargs)
    return _wrapped


# ─────────────────────────────────────────────────────────── egress pacing + cooldown
# The breaker above is RUN-scoped and only counts failures. The archive's own limits are
# per-IP: web.archive.org answers a burst from one IP with HTTP 429 and then refuses TCP
# connections from it outright (measured 2026-09-28 on the direct IP: ~17 playback fetches in ~40s
# → every connection to 207.241.237.3:443 refused for ~8 minutes; the archive doubles the block on
# each repeat). Hammering a refusing archive is what extends the block, so the pacer (a) spaces
# requests per host+lane across every process on this machine and (b) arms a cooldown on a 429 or
# an archive-side refusal, keyed per host AND per exit (direct, or the proxy set this process
# uses — a block earned on one IP never stalls another), during which every call site on that exit
# skips without touching the network. Pacing is spacing, never a usage cap.

PACE_STATE_ENV = "WAYBACK_PACE_STATE"
PACE_FILE = "wayback_pace.json"
MIN_INTERVAL_ENV = "WAYBACK_MIN_INTERVAL"
_COOLDOWN_NOTED: set = set()


def _pace_path() -> str:
    # Machine-wide, not case/run-scoped: the archive limits the egress IP, whichever case asks.
    return os.environ.get(PACE_STATE_ENV) or os.path.join(_engine_root(), "MEMORY", PACE_FILE)


def _pace_doc() -> dict:
    try:
        with open(_pace_path(), encoding="utf-8") as fh:
            doc = json.load(fh)
        return doc if isinstance(doc, dict) else {}
    except Exception:  # noqa: BLE001
        return {}


def _ref_number(section: str, key: str) -> float:
    for src in (_REFS, GUARD_FALLBACK):
        try:
            return max(0.0, float(src[section][key]))
        except Exception:  # noqa: BLE001
            continue
    return 0.0


def min_interval(lane: str) -> float:
    """Seconds between two requests on one host+lane — $WAYBACK_MIN_INTERVAL (all lanes) first,
    then wayback_guard.json → pace.<lane>. An unknown lane takes the strictest (playback) spacing."""
    env = os.environ.get(MIN_INTERVAL_ENV)
    if env not in (None, ""):
        try:
            return max(0.0, float(env))
        except ValueError:
            pass
    ref_lanes = _REFS.get("pace") if isinstance(_REFS.get("pace"), dict) else {}
    known = set(GUARD_FALLBACK["pace"]) | {k for k in ref_lanes if not k.startswith("_")}
    return _ref_number("pace", lane if lane in known else "playback")


def cooldown_seconds(kind: str) -> float:
    """Base cooldown for `throttled` (HTTP 429) / `refused` (TCP refused), and the `max` cap."""
    return _ref_number("cooldown", kind)


def cooling(host: str, exit_id: str | None = None) -> str | None:
    """A human-readable reason while `host` is cooling down on THIS process's exit (direct, or the
    proxy set) after a 429/refusal, else None. A plain read — never a network call."""
    c = (_pace_doc().get("cooldown") or {}).get(_cooldown_key(host, exit_id)) or {}
    try:
        left = float(c.get("until") or 0) - time.time()
    except (TypeError, ValueError):
        return None
    if left <= 0:
        return None
    return (f"{host} is cooling down after {c.get('reason') or 'a refusal'} on exit "
            f"{exit_id or _egress_id()} — no request for {int(left) + 1}s (resumes on its own)")


def admit(host: str, lane: str, max_wait: float | None = None,
          exit_id: str | None = None) -> str | None:
    """Gate ONE request to `host`: None = send it now (after sleeping for this process's paced
    slot); a reason string = skip it without a request (breaker tripped, host cooling down, or the
    next slot is further away than `max_wait` seconds). The slot is reserved under the pace file's
    lock, so parallel collectors queue instead of bursting. A broken pace file never blocks."""
    reason = blocked() or cooling(host, exit_id)
    if reason:
        return reason
    interval = min_interval(lane)
    if interval <= 0:
        return None
    key = f"{host}:{lane}@{exit_id or _egress_id()}"   # the archive limits per IP: per-exit slots
    now = time.time()

    def _reserve(doc):
        lanes = doc.get("lanes") if isinstance(doc.get("lanes"), dict) else {}
        try:
            nxt = float(lanes.get(key) or 0)
        except (TypeError, ValueError):
            nxt = 0.0
        if nxt > now + 3600:          # a clock jump / corrupt value must not stall the machine
            nxt = now
        slot = max(now, nxt)
        wait = slot - now
        if max_wait is not None and wait > max_wait:
            return doc, ("skip", wait)
        lanes[key] = slot + interval
        doc["lanes"] = lanes
        return doc, ("go", wait)

    res = _transact(_reserve, path=_pace_path())
    if not res:
        return None
    verdict, wait = res
    if verdict == "skip":
        return f"{host} pacing: the next {lane} slot is {wait:.0f}s away, past this call's budget"
    if wait > 0:
        time.sleep(wait)
    return cooling(host, exit_id)     # another process may have hit a refusal while we waited


def _egress_id() -> str:
    """The exit of a process-level request (no explicit exit): 'direct', or the proxy host:port
    set (userinfo stripped — never persist a credential). APPROXIMATE: cti_proxy exports only the
    process's START exit, and its FailoverOpener may move to another pool entry on failure. Calls
    that pick their route explicitly (wp_exits.Exit) pass exit_id and are exact."""
    raw = ""
    for v in ("ALL_PROXY", "all_proxy", "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"):
        if os.environ.get(v):
            raw = os.environ[v]
            break
    if not raw:
        return "direct"
    return ",".join(re.sub(r"^[a-z0-9+.-]+://(?:[^@/]*@)?", "", p.strip()).rstrip("/")
                    for p in raw.split(",") if p.strip()) or "proxy"


def _cooldown_key(host: str, exit_id: str | None = None) -> str:
    return f"{host}@{exit_id or _egress_id()}"


def _cooldown_kind(outcome, exit_id: str | None = None) -> str | None:
    import urllib.error
    if isinstance(outcome, bool) or outcome is None:
        return None
    if isinstance(outcome, int):
        return "throttled" if outcome == 429 else None
    if isinstance(outcome, urllib.error.HTTPError):
        return "throttled" if outcome.code == 429 else None
    text = str(outcome).lower()
    if ("error connecting to" in text and ("proxy" in text or "socks" in text)) \
            or re.search(r"tunnel connection failed: 40[37]\b", text) or "proxy authentication" in text:
        return None      # the PROXY is down, rejects our credentials (407) or forbids the destination
                         # by its own policy (403) — the archive never saw us
    if "tunnel connection failed" in text or "connect refused" in text or \
            ("socks" in text and "refused" in text):
        return "refused"  # the exit reached out and the destination refused it: that exit is blocked
    refused = (isinstance(outcome, ConnectionRefusedError)
               or isinstance(getattr(outcome, "reason", None), ConnectionRefusedError)
               or "connection refused" in text or "errno 111" in text or "econnrefused" in text)
    if refused:
        # a bare TCP refusal is the archive only on a DIRECT connection; through a proxy exit it
        # is the proxy's own port refusing (dead exit) — the breaker's business, not a cooldown
        return "refused" if (exit_id or _egress_id()) == "direct" else None
    if re.search(r"\b429\b", text):
        return "throttled"
    return None


def observe(host: str, outcome, headers=None, exit_id: str | None = None) -> str | None:
    """Feed one answer from `host` to the cooldown: `True` = a request got through (clears the
    repeat-offence count); an HTTP 429 or a refusal by the archive arms a cooldown for this exit —
    Retry-After when the archive sends one, else the reference base — doubled for each repeat
    offence within 15 minutes (the archive doubles its own block the same way), capped at `max`.
    Anything else (5xx, timeout) is the breaker's business, not the cooldown's. Returns the
    cooldown kind it armed ("throttled" / "refused"), else None."""
    key = _cooldown_key(host, exit_id)
    if outcome is True:
        c = (_pace_doc().get("cooldown") or {}).get(key) or {}
        if c.get("strikes"):
            def _clear(doc):
                cds = doc.get("cooldown") if isinstance(doc.get("cooldown"), dict) else {}
                cds.pop(key, None)
                doc["cooldown"] = cds
                return doc, None
            _transact(_clear, path=_pace_path())
        return None
    kind = _cooldown_kind(outcome, exit_id)
    if not kind:
        return None
    retry_after = 0.0
    try:
        retry_after = float((headers or {}).get("Retry-After") or 0)
    except (TypeError, ValueError, AttributeError):
        retry_after = 0.0
    now = time.time()

    def _arm(doc):
        cds = doc.get("cooldown") if isinstance(doc.get("cooldown"), dict) else {}
        c = dict(cds.get(key) or {})
        try:
            recent = now - float(c.get("until") or 0) < 900
        except (TypeError, ValueError):
            recent = False
        strikes = int(c.get("strikes") or 0) + 1 if recent else 1
        base = retry_after or cooldown_seconds(kind)
        secs = min(cooldown_seconds("max") or base, base * (2 ** (strikes - 1)))
        cds[key] = {"until": now + secs, "strikes": strikes, "kind": kind,
                     "reason": "HTTP 429 (throttled)" if kind == "throttled"
                               else "refused connections (IP firewalled)"}
        doc["cooldown"] = cds
        return doc, secs

    secs = _transact(_arm, path=_pace_path())
    if secs and (host, kind) not in _COOLDOWN_NOTED:
        _COOLDOWN_NOTED.add((host, kind))
        print(f"[wayback-guard] {host} {'throttled (429)' if kind == 'throttled' else 'refused the connection'}"
              f" via {exit_id or _egress_id()} — every Wayback call on this exit skips it for {int(secs)}s",
              file=sys.stderr)
    return kind
