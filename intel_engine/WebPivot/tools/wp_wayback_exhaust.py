#!/usr/bin/env python3
"""wp_wayback_exhaust — download EVERY distinct archived capture of a domain (not a time sample),
across several egress exits in parallel, resumably.

WHY
---
`wayback_harvest`/`wayback_ga` sample ~12-25 snapshots spread over time — fast, but they miss a
selector that appears in only one un-sampled capture. This module instead:

  1. Enumerates the domain's WHOLE index (wp_wayback.index_pages, resumeKey paging), so nothing is
     lost to the 2000-row cap. matchType=domain (every subdomain + path), HTML and JS/JSON,
     collapse=digest so identical content is one row.
  2. De-duplicates by content digest GLOBALLY across the whole estate (the same shared asset under
     100 URLs is fetched once).
  3. Downloads every remaining capture's original bytes (id_), spread across all working exits
     (direct / proxy pool / WARP / Tor) — the archive limits per IP, so N exits ≈ N× throughput,
     each on its own paced slot and cooldown (wp_wayback_guard, keyed per exit).
  4. Extracts selectors from each body (wayback_harvest.harvest_html) and rolls them up.

RESUMABLE: progress is a JSON state file (default cases/<case>/deep-archive/<host>.exhaust.json, or
--state). Re-running skips already-fetched digests and resumes the fetch queue, so a multi-hour run
survives interruption. A tripped run breaker or an all-exits-cooling stop is a PAUSE, not a
failure — re-run to continue.

Passive & keyless (Wayback only; urlscan is a separate module). Stdlib only.
FOR AUTHORIZED INVESTIGATIONS ONLY.
"""
from __future__ import annotations

import json
import os
import queue
import re
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wp_wayback as W  # noqa: E402
import wp_wayback_guard as wg  # noqa: E402
import wp_exits  # noqa: E402

try:
    from wp_refs import ref_path, load_ref  # noqa: E402
except Exception:  # noqa: BLE001
    ref_path = load_ref = None

# scripts/webpivot is where the canonical harvest extractors live
_SCRIPTS_WP = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..", "..",
                                            "scripts", "webpivot"))
if _SCRIPTS_WP not in sys.path:
    sys.path.insert(0, _SCRIPTS_WP)

_HTML_MIME = "(text/html|application/xhtml.*)"
_ASSET_MIME = "(text/javascript|application/javascript|application/x-javascript|application/json)"

_EXHAUST_FALLBACK = {
    "index_page_rows": {"value": 5000}, "fetch_attempts": {"value": 3},
    "exit_fail_limit": {"value": 8}, "fetch_timeout": {"value": 60},
}


def _cfg(key: str, default):
    if load_ref and ref_path:
        try:
            d = load_ref(ref_path(__file__, "wayback_endpoints.json"), {})
            return d.get("exhaust", {}).get(key, default)
        except Exception:  # noqa: BLE001
            pass
    return default


# default run budget (hours) — the analyst's setting (wayback_endpoints.json → exhaust.
# default_max_hours); the run then stops cleanly with state saved and resumes on the next call.
DEFAULT_MAX_HOURS = float(_cfg("default_max_hours", 7))


def _harvest_html(html: str) -> dict:
    from wayback_harvest import harvest_html
    return harvest_html(html)


def _norm_host(domain: str) -> str:
    d = (domain or "").strip()
    if "://" in d:
        d = d.split("://", 1)[1]
    d = d.split("/", 1)[0].split("?", 1)[0].strip().lower()
    return d[4:] if d.startswith("www.") else d


# ------------------------------------------------------------------ state
def _load_state(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as fh:
            d = json.load(fh)
        return d if isinstance(d, dict) else {}
    except Exception:  # noqa: BLE001
        return {}


def _save_state(path: str, state: dict) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(state, fh)
    os.replace(tmp, path)


def _default_state_path(host: str, case: str | None, out: str | None) -> str:
    if case:   # the single case store: $INTEL_HOME/cases/<id>/ wherever the caller's cwd is
        home = os.environ.get("INTEL_HOME") or _engine_root()
        return os.path.join(home, "cases", case, "deep-archive", host + ".exhaust.json")
    if out:
        base = out[:-5] if out.endswith(".json") else out
        return base + ".exhaust.json"
    # no case: a fixed engine-owned location, so a later `--status` call finds the same job
    base = os.environ.get("WP_CASE_DIR") or os.path.join(
        os.environ.get("INTEL_HOME") or _engine_root(), "MEMORY", "exhaust")
    return os.path.join(base, host + ".exhaust.json")


# ------------------------------------------------------------------ registration eras
# An exhaustive sweep reads EVERY capture a domain ever had — including the years before its
# current registration, when a previous owner (a dropped-then-recaught domain, a parked reseller
# page) served their own contacts and trackers. Attributing those to today's operator is exactly
# the "never name an innocent party" failure (SKILL.md RULE 5), so each selector is placed in an
# era against the current registration's `created` date:
#   current  — first seen on/after registration: the current operator's
#   spans    — seen before AND after: carried across the registration (reuse, or a same-owner
#              re-register); kept with the current era but flagged
#   prior    — last seen before registration: an EARLIER owner's — facts only, never an indicator,
#              pivot or frontier seed
#   undated  — no registration date available: the split could not be made (say so)
ERA_CAVEAT = ("Seen only in archive captures made BEFORE the current registration (created {created}). "
              "These most likely belong to an EARLIER owner of the domain: record as historical "
              "facts only — never an indicator, pivot, frontier seed, or evidence of who runs it today.")


def _ymd(v) -> str:
    d = re.sub(r"\D", "", str(v or ""))
    return d[:8] if len(d) >= 8 else ""


def _engine_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def registration_date(host: str, case: str | None = None, explicit: str | None = None,
                      lookup: bool = True):
    """(YYYYMMDD, source) of the current registration, or ("", reason). Explicit value first, then
    the case's WHOIS sidecar, then a keyless WHOIS lookup (registries only — the target is never
    contacted; .vn goes through the ChongLuaDao endpoint first). Never raises."""
    if _ymd(explicit):
        return _ymd(explicit), "explicit --created"
    if case:
        home = os.environ.get("INTEL_HOME") or _engine_root()
        for h in (host, "www." + host):
            p = os.path.join(home, "cases", case, "whois", h + ".json")
            try:
                with open(p, encoding="utf-8") as fh:
                    d = json.load(fh)
                c = _ymd(d.get("created") or (d.get("current") or {}).get("created"))
                if c:
                    return c, f"case WHOIS sidecar ({os.path.basename(p)})"
            except (OSError, ValueError, AttributeError):
                continue
    if lookup:
        try:
            import whois_enrich
            w = whois_enrich.whois_summary_keyless(host, keep_raw=False) or {}
            if _ymd(w.get("created")):
                return _ymd(w["created"]), "keyless WHOIS/RDAP lookup"
        except Exception as e:  # noqa: BLE001
            return "", f"WHOIS lookup failed ({e})"
    return "", "no registration date found"


def split_eras(records: dict, created: str) -> dict:
    """records ("kind\\tvalue" → {first,last,…}) → {"current","spans","prior","undated"} lists."""
    out = {"current": [], "spans": [], "prior": [], "undated": []}
    for r in records.values():
        first, last = _ymd(r.get("first")), _ymd(r.get("last")) or _ymd(r.get("first"))
        if not created or not first:
            out["undated"].append(r)
        elif last and last < created:
            out["prior"].append(r)
        elif first < created:
            out["spans"].append(r)
        else:
            out["current"].append(r)
    return out


def write_eras(state_path: str, state: dict) -> dict:
    """Persist the era split beside the state file; returns the counts for the summary."""
    created = state.get("registration_created") or ""
    eras = split_eras(state.get("records") or {}, created)
    doc = {"host": state.get("host"), "registration_created": created,
           "registration_source": state.get("registration_source"),
           "current": eras["current"], "spans_registration": eras["spans"],
           "prior_era": {"caveat": ERA_CAVEAT.format(created=created or "?"), "records": eras["prior"]},
           "undated": eras["undated"]}
    p = (state_path[:-5] if state_path.endswith(".json") else state_path) + ".eras.json"
    try:
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, ensure_ascii=False, indent=1)
    except OSError:
        p = None
    return {"current": len(eras["current"]), "spans_registration": len(eras["spans"]),
            "prior_era": len(eras["prior"]), "undated": len(eras["undated"]), "file": p}


# ------------------------------------------------------------------ enumerate
def enumerate_captures(host: str, *, include_assets=True, year_from=None, year_to=None,
                       page_rows=5000, ua=None, exit=None, progress=None):
    """Every distinct capture of the whole domain, deduped by digest across HTML then assets →
    {digest: {"timestamp","original","digest","first","last","n"}} plus an `err` if enumeration did
    not finish. Digest dedup is global: the same asset under many URLs is one entry, fetched once.

    `first`/`last`/`n` are the digest's WHOLE capture range — every URL and every run of it — so a
    page unchanged from 2019 to 2024 dates its selectors 2019→2024, not 2019→2019. collapse=digest
    folds each consecutive run into one row carrying `endtimestamp` + `groupcount` (verified live
    2026-09-28 against the uncollapsed rows), and the same digest recurring later or under another
    URL is merged here."""
    groups = [_HTML_MIME] + ([_ASSET_MIME] if include_assets else [])
    caps: dict[str, dict] = {}
    err = None
    for mime in groups:
        params = [("url", host), ("matchType", "domain"),
                  ("fl", "timestamp,original,digest,endtimestamp,groupcount"),
                  ("filter", "statuscode:200"),
                  ("filter", f"mimetype:{mime}"), ("collapse", "digest")]
        if year_from:
            params.append(("from", str(year_from)))
        if year_to:
            params.append(("to", str(year_to)))
        for rows, perr in W.index_pages(params, ua=ua, page_rows=page_rows, exit=exit):
            if perr:
                err = perr
                break
            for r in rows:
                if len(r) < 3 or not r[2]:
                    continue
                ts, end = r[0], (r[3] if len(r) > 3 and r[3] else r[0])
                try:
                    n = int(r[4]) if len(r) > 4 and r[4] else 1
                except ValueError:
                    n = 1
                c = caps.get(r[2])
                if c is None:
                    caps[r[2]] = {"timestamp": ts, "original": r[1], "digest": r[2],
                                  "first": ts, "last": max(ts, end), "n": n}
                else:
                    c["first"] = min(c.get("first") or ts, ts)
                    c["last"] = max(c.get("last") or end, end, ts)
                    c["n"] = int(c.get("n") or 1) + n
            if progress:
                progress(len(caps))
        if err:
            break
    return caps, err


# ------------------------------------------------------------------ parallel fetch
class _Worker(threading.Thread):
    def __init__(self, exit, q, results, lock, ua, attempts, timeout, fail_limit, stop, deadline=None,
                 undecodable=None):
        super().__init__(daemon=True)
        self.exit, self.q, self.results, self.lock = exit, q, results, lock
        self.ua, self.attempts, self.timeout = ua, attempts, timeout
        self.fail_limit, self.stop, self.deadline = fail_limit, stop, deadline
        self.undecodable = undecodable if undecodable is not None else {}
        self.fetched = self.failed = 0
        self.stopped_reason = None

    def run(self):
        import time as _t
        streak = 0
        while not self.stop.is_set():
            if self.deadline is not None and _t.monotonic() > self.deadline:
                self.stopped_reason = f"{self.exit.id}: time budget reached"
                return
            try:
                digest, cap = self.q.get_nowait()
            except queue.Empty:
                return
            try:
                resp, err = W.fetch(cap["timestamp"], cap["original"], ua=self.ua,
                                    timeout=self.timeout, exit=self.exit, attempts=self.attempts)
                if resp is not None and resp.status == 200 and W.undecodable(resp):
                    # answered, but the body could not be decompressed (e.g. `br` without the
                    # brotli library): NOT read — kept out of `done` so a later run retries it
                    with self.lock:
                        self.undecodable[digest] = W.undecodable(resp)
                    streak = 0
                elif resp is not None and resp.status == 200:
                    with self.lock:
                        self.results[digest] = (cap, resp.body)
                    self.fetched += 1
                    streak = 0
                else:
                    # 404/403 for THIS capture is a real dead capture, not an exit problem —
                    # record it done (empty) so a resume never re-queues it; a transport err
                    # (err set) is re-queued to another exit.
                    if resp is not None:
                        with self.lock:
                            self.results[digest] = (cap, None)
                    else:
                        self.q.put((digest, cap))
                        streak += 1
            except Exception:  # noqa: BLE001
                self.q.put((digest, cap))
                streak += 1
            finally:
                self.q.task_done()
            if streak >= self.fail_limit:
                self.stopped_reason = f"{self.exit.id}: {streak} consecutive failures — exit dropped"
                return


def fetch_all(captures: dict, exits: list, *, ua=None, attempts=3, timeout=60, fail_limit=8,
              done_digests=None, on_body=None, state_flush=None, deadline=None):
    """Fetch every capture in `captures` (digest→cap) across `exits` in parallel. `on_body(digest,
    cap, body)` is called for each fetched body (body may be None for a dead 404/403 capture) —
    the caller extracts + persists and returns quickly. Returns a summary dict."""
    done = set(done_digests or ())
    q: queue.Queue = queue.Queue()
    for digest, cap in captures.items():
        if digest not in done:
            q.put((digest, cap))
    total_queued = q.qsize()
    results: dict = {}
    lock = threading.Lock()
    stop = threading.Event()
    undecodable: dict = {}

    workers = [_Worker(ex, q, results, lock, ua, attempts, timeout, fail_limit, stop, deadline,
                       undecodable) for ex in exits]
    for w in workers:
        w.start()

    # drain results as they arrive, so a long run persists incrementally and stays bounded in memory
    processed = 0
    flush_every = 25
    while any(w.is_alive() for w in workers) or results:
        drained = []
        with lock:
            if results:
                drained = list(results.items())
                results.clear()
        for digest, (cap, body) in drained:
            if on_body:
                on_body(digest, cap, body)
            processed += 1
            if state_flush and processed % flush_every == 0:
                state_flush()
        if not drained:
            if wg.blocked():
                stop.set()
                break
            time.sleep(0.3)
    for w in workers:
        w.join(timeout=1)
    if state_flush:
        state_flush()
    return {
        "queued": total_queued, "fetched": sum(w.fetched for w in workers),
        "processed": processed,
        "exits": {w.exit.id: {"fetched": w.fetched, "stopped": w.stopped_reason} for w in workers},
        "paused": bool(wg.blocked()) or any(w.stopped_reason for w in workers),
        # answered but not decompressible (e.g. `br` without brotli): NOT read, retried next run
        "undecodable": dict(undecodable),
    }




def _dom_ledger_path(state_path):
    return (state_path[:-5] if state_path.endswith(".json") else state_path) + ".urlscan_done.jsonl"


def _load_dom_ledger(state_path):
    """The crash-safe set of urlscan uuids already fetched+billed (append-only sidecar, merged on
    load). Survives a hard kill that never reached a state flush, so a re-run never re-pays."""
    done = set()
    try:
        with open(_dom_ledger_path(state_path), encoding="utf-8") as fh:
            for line in fh:
                u = line.strip()
                if u:
                    done.add(u)
    except OSError:
        pass
    return done


def _append_dom_ledger(state_path, uuid):
    try:
        with open(_dom_ledger_path(state_path), "a", encoding="utf-8") as fh:
            fh.write(uuid + "\n")
            fh.flush()
            os.fsync(fh.fileno())
    except OSError:
        pass


def _urlscan_search_pages(host, key, ua, per_timeout, cursor, deadline, api_usage, on_page,
                          max_pages=None, listed=0):
    """Page /api/v1/search/ ourselves (unfloored urlopen, per-request timeout, deadline between
    pages) so the listing is bounded and RESUMABLE from `cursor` (search_after). on_page(scans,
    domains, next_cursor, total) runs after EVERY page, so the caller persists the cursor per page
    and a kill mid-listing resumes from the last page, not the first.

    `key` falsy → an ANONYMOUS search: no API-Key header at all (never `API-Key: None`), not ledgered
    as a credit (anonymous search is not metered), and — like urlscan_intel(free_only=True) — capped
    by the caller to one page. A keyed page is ledgered (success and failure). Returns
    (next_cursor, complete, stop_reason, total)."""
    import urllib.error
    import urllib.request
    _urlopen = getattr(urllib.request.urlopen, "_cti_orig", urllib.request.urlopen)
    size = int(_cfg("urlscan_page_size", 100))
    hdr = {"User-Agent": ua}
    if key:
        hdr["API-Key"] = key
    page = 0
    total = None
    while True:
        if max_pages is not None and page >= max_pages:
            return cursor, False, f"anonymous search: {max_pages} page(s) only (no key spent)", total
        if deadline is not None and time.monotonic() > deadline:
            return cursor, False, "time budget reached (search)", total
        api = f"https://urlscan.io/api/v1/search/?q=domain:{host}&size={size}"
        if cursor:
            api += f"&search_after={urllib.parse.quote(cursor, safe='')}"
        try:
            req = urllib.request.Request(api, headers=hdr)
            with _urlopen(req, timeout=per_timeout) as r:
                data = json.loads(r.read().decode("utf-8", "ignore"))
            if api_usage and key:
                api_usage.record("urlscan", "search", credits=1, query=f"domain:{host}",
                                 results=data.get("total"))
        except urllib.error.HTTPError as e:
            if api_usage and key:
                api_usage.record("urlscan", "search", credits=1, query=f"domain:{host}", ok=False)
            return cursor, False, f"HTTP {e.code} (search)", total
        except Exception as e:  # noqa: BLE001
            return cursor, False, f"search error: {e}", total
        results = data.get("results") or []
        total = data.get("total", total)
        page += 1
        sys.stderr.write(f"[exhaust] urlscan search page {page} (+{len(results)} scans, "
                         f"vendor total {total})\n")
        scans = [{"uuid": res.get("_id"), "url": (res.get("page") or {}).get("url"),
                  "time": (res.get("task") or {}).get("time")} for res in results if res.get("_id")]
        sortv = results[-1].get("sort") if results else None
        nxt = (",".join(str(x) for x in sortv) if isinstance(sortv, list) else str(sortv)) if sortv else None
        listed += len(scans)
        # urlscan's `has_more` is NOT trustworthy (measured 2026-09-28: has_more=false on a page of
        # 100 while `total` was 248 and page 2 held 100 fresh scans). Follow the cursor until an
        # empty or short page, or until we have listed `total`.
        done = (not results or not nxt
                or (listed >= total if isinstance(total, int) else len(results) < size))
        on_page(scans, [(res.get("page") or {}).get("domain") for res in results],
                None if done else nxt, total)
        if done:
            return None, True, None, total
        cursor = nxt


def _urlscan_exhaust(host, state, ua, spend_key, flush=None, deadline=None, state_path=None):
    """Every urlscan scan of the host + every distinct cached DOM, selectors folded into the same
    records. `spend_key` spends the urlscan credential even on a free-only run (the exhaustive job's
    explicit posture — the default loop's no-spend rule is untouched). Keyless → /dom/ is 403, so
    only the scan LISTING runs.

    RESUMABLE + BOUNDED-PER-REQUEST, both phases:
      * SEARCH — paged here (not via urlscan_intel), unfloored urlopen + per-request timeout, the
        `search_after` cursor saved to state after each page, so a re-run continues the listing
        instead of re-reading the first pages. Every page ledgered.
      * DOM — each /dom/ uuid fetched with the unfloored urlopen + per-request timeout; the uuid is
        appended to a crash-safe sidecar ledger the instant it is billed, so a hard kill (the MCP
        ~30-min limit, Ctrl-C, `timeout`) never causes a re-pay. Every keyed request ledgered to
        api_usage, including a 403/404 (still a metered call).
    Either phase stops on a 429/402 vendor limit or the run's time budget, recording the gap for the
    next run — vendor limits and the budget decide the stop, never a local usage cap."""
    import hashlib
    import urllib.error
    import urllib.request
    import wp_net
    from wp_common import _decode_body
    recs = state["records"]
    api_usage = getattr(wp_net, "api_usage", None)
    key = wp_net._secret("URLSCAN_API_KEY")
    keyed = spend_key and bool(key)
    per_timeout = int(_cfg("urlscan_dom_timeout", 20))

    # --- search phase (resumable cursor) ---
    if not isinstance(state.get("urlscan_scans"), list):   # pre-rewrite state stored an int count
        state["urlscan_scans"] = []
        state.pop("urlscan_search_complete", None)
    state.setdefault("urlscan_related", [])
    seen_uids = {s["uuid"] for s in state["urlscan_scans"] if isinstance(s, dict) and s.get("uuid")}

    def _on_page(scans, domains, next_cursor, total):
        for s in scans:
            if s["uuid"] not in seen_uids:
                seen_uids.add(s["uuid"])
                state["urlscan_scans"].append(s)
        for d in domains:
            if d and d not in state["urlscan_related"]:
                state["urlscan_related"].append(d)
        state["urlscan_search_cursor"] = next_cursor       # per page: a kill resumes from here
        if next_cursor:
            state["urlscan_last_cursor"] = next_cursor
        state["urlscan_vendor_total"] = total
        if flush:
            flush()

    if keyed and "urlscan_plan_window" not in state:
        # entitlement probe — free, not counted against quota: the plan's search-result window
        q = wp_net.urlscan_quotas(ua=ua) or {}
        state["urlscan_plan_window"] = q.get("max_search_results")

    tot = state.get("urlscan_vendor_total")
    if (state.get("urlscan_search_complete") and isinstance(tot, int)
            and len(state["urlscan_scans"]) < tot and state.get("urlscan_last_cursor")):
        # an older run trusted urlscan's has_more and stopped short — resume from its last cursor
        state["urlscan_search_complete"] = False
        state["urlscan_search_cursor"] = state["urlscan_last_cursor"]
    if not state.get("urlscan_search_complete"):
        # the key is sent ONLY when this run may spend it; a free-only / keyless run searches
        # anonymously (no header, no credit) and — like urlscan_intel(free_only=True) — one page
        cursor, complete, stop, _total = _urlscan_search_pages(
            host, key if keyed else None, ua, per_timeout, state.get("urlscan_search_cursor"),
            deadline, api_usage, _on_page, max_pages=None if keyed else 1,
            listed=len(state["urlscan_scans"]))
        state["urlscan_search_cursor"] = cursor
        state["urlscan_search_complete"] = complete
        state["urlscan_search_gap"] = None if complete else stop
        if flush:
            flush()
    state["urlscan_scan_count"] = len(state["urlscan_scans"])

    if not keyed:
        state["urlscan_dom_capability"] = ("keyless / free-only — anonymous scan listing only; "
                                           "/dom/ needs the key")
        return

    # --- dom phase (crash-safe per-uuid ledger) ---
    hdr = {"User-Agent": ua, "API-Key": key}
    _urlopen = getattr(urllib.request.urlopen, "_cti_orig", urllib.request.urlopen)
    done = _load_dom_ledger(state_path) if state_path else set(state.get("urlscan_done", []))
    seen_hashes = set(state.setdefault("urlscan_hashes", []))
    state.setdefault("urlscan_doms", 0)
    dom_gap = None
    for scan in state["urlscan_scans"]:
        uid = scan.get("uuid")
        if not uid or uid in done:
            continue
        if deadline is not None and time.monotonic() > deadline:
            dom_gap = f"time budget reached ({len(done)} DOM(s) done) — re-run to continue"
            break
        raw = enc = None
        billed = False
        try:
            req = urllib.request.Request(f"https://urlscan.io/dom/{uid}/", headers=hdr)
            with _urlopen(req, timeout=per_timeout) as r:
                raw = r.read()
                enc = r.headers.get("Content-Encoding") if hasattr(r, "headers") else None
            billed = True
        except urllib.error.HTTPError as e:
            billed = True                       # a keyed request is metered even on 403/404
            if e.code in (429, 402):
                dom_gap = f"HTTP {e.code} ({len(done)} DOM(s) done) — re-run to continue"
                break                            # `finally` still ledgers this billed request
        except Exception:  # noqa: BLE001 — transport: skip this DOM, do not mark done (retry next run)
            continue
        finally:
            if billed and api_usage:
                api_usage.record("urlscan", "dom", credits=1, query=uid,
                                 results=1 if raw else 0)
        done.add(uid)
        if state_path:
            _append_dom_ledger(state_path, uid)     # crash-safe: billed ⇒ recorded now
        if raw is None:
            continue
        html = _decode_body(raw, enc).decode("utf-8", "ignore")
        if not html or len(html) < 200:
            continue
        h = hashlib.sha256(html.encode("utf-8", "ignore")).hexdigest()
        if h in seen_hashes:
            continue
        seen_hashes.add(h)
        state["urlscan_doms"] += 1
        ts = (scan.get("time") or "")[:10].replace("-", "")
        url = scan.get("url") or f"https://urlscan.io/result/{uid}/"
        for kind, values in _harvest_html(html).items():
            for v in values:
                k = f"{kind}\t{v}"
                r = recs.get(k)
                if r is None:
                    recs[k] = {"kind": kind, "value": v, "first": ts, "last": ts, "hits": 1,
                               "first_url": url}
                else:
                    r["hits"] += 1
                    if ts and (not r["first"] or ts < r["first"]):
                        r["first"], r["first_url"] = ts, url
                    if ts and ts > (r["last"] or ""):
                        r["last"] = ts
        if len(done) % 25 == 0 and flush:
            state["urlscan_done"] = sorted(done)
            state["urlscan_hashes"] = sorted(seen_hashes)
            flush()
    state["urlscan_done"] = sorted(done)
    state["urlscan_hashes"] = sorted(seen_hashes)
    state["urlscan_dom_gap"] = dom_gap
    complete = state.get("urlscan_search_complete") and not dom_gap and not state.get("urlscan_search_gap")
    state["urlscan_dom_capability"] = ("keyed — every DOM fetched (credit spent)" if complete
                                       else "keyed — DOM pass INCOMPLETE (gap recorded; re-run to continue)")


# ------------------------------------------------------------------ driver
def exhaust(domain, *, case=None, out=None, state_path=None, include_assets=True,
            year_from=None, year_to=None, exits_spec=None, ua=None, resume=True,
            urlscan=True, urlscan_spend=True, max_seconds=None, created=None):
    host = _norm_host(domain)
    ua = ua or W.DEFAULT_UA
    deadline = (time.monotonic() + max_seconds) if max_seconds else None
    state_path = state_path or _default_state_path(host, case, out)
    state = _load_state(state_path) if resume else {}
    state.setdefault("host", host)
    state.setdefault("captures", {})       # digest -> cap (the enumerated plan)
    state.setdefault("done", [])           # digests fetched (or dead) — never re-queued
    state.setdefault("records", {})        # "kind\\tvalue" -> {first,last,hits,first_url}
    done = set(state["done"])
    if created or not state.get("registration_created"):
        c, src = registration_date(host, case, created)
        state["registration_created"], state["registration_source"] = c, src
        sys.stderr.write(f"[exhaust] current registration: {c or 'UNKNOWN'} ({src}) — "
                         f"{'selectors split into current / prior-owner eras' if c else 'era split NOT possible'}\n")

    exits = wp_exits.configured_exits(exits_spec, default=_cfg_exits())
    probed = _probe_exits(exits, ua)
    state["exits_used"] = [e.id for e in probed]
    if not probed:
        return {**_summary(state), "error": "no working exit (every route failed its probe)"}

    page_rows = int(_cfg("index_page_rows", 5000))
    # (re)enumerate only when the plan is not already complete — the plan is the expensive-to-lose
    # part, and an interrupted enumeration must not read as "no captures" on resume
    if not state.get("enum_complete"):
        caps, enum_err = enumerate_captures(
            host, include_assets=include_assets, year_from=year_from, year_to=year_to,
            page_rows=page_rows, ua=ua, exit=probed[0],
            progress=lambda n: sys.stderr.write(f"\r[exhaust] enumerating… {n} distinct captures\n") or None)
        # merge (a resumed partial plan keeps what it had)
        state["captures"].update(caps)
        state["enum_error"] = enum_err
        state["enum_complete"] = enum_err is None
        _save_state(state_path, state)
        if enum_err and not state["captures"]:
            return {**_summary(state), "error": f"enumeration did not answer: {enum_err}"}

    captures = state["captures"]
    records = state["records"]
    rec_lock = threading.Lock()

    def _note(kind, value, first, last, url, n=1):
        """Fold one selector sighting spanning [first, last] (n captures) into the record."""
        k = f"{kind}\t{value}"
        with rec_lock:
            r = records.get(k)
            if r is None:
                records[k] = {"kind": kind, "value": value, "first": first, "last": last,
                              "hits": n, "first_url": url}
            else:
                r["hits"] += n
                if first and (not r["first"] or first < r["first"]):
                    r["first"], r["first_url"] = first, url
                if last and last > (r["last"] or ""):
                    r["last"] = last

    def _on_body(digest, cap, body):
        done.add(digest)
        if body:
            try:
                html = body.decode("utf-8", "ignore")
            except Exception:  # noqa: BLE001
                html = ""
            if html:
                snap = W.raw_url(cap["timestamp"], cap["original"])
                # one fetch of this content version dates its selectors over the version's WHOLE
                # capture range (every URL, every run) — not just the capture we downloaded
                first = cap.get("first") or cap["timestamp"]
                last = cap.get("last") or cap["timestamp"]
                n = int(cap.get("n") or 1)
                for kind, values in _harvest_html(html).items():
                    for v in values:
                        _note(kind, v, first, last, snap, n)

    def _flush():
        state["done"] = sorted(done)
        state["records"] = records
        _save_state(state_path, state)

    summary = fetch_all(
        captures, probed, ua=ua, attempts=int(_cfg("fetch_attempts", 3)),
        timeout=int(_cfg("fetch_timeout", 60)), fail_limit=int(_cfg("exit_fail_limit", 8)),
        done_digests=done, on_body=_on_body, state_flush=_flush, deadline=deadline)
    if urlscan:
        _urlscan_exhaust(host, state, ua, urlscan_spend, flush=_flush, deadline=deadline,
                         state_path=state_path)
    undec = {k: v for k, v in (state.get("undecodable") or {}).items() if k not in done}
    undec.update(summary.get("undecodable") or {})
    state["undecodable"] = undec                 # not read yet — retried by the next run
    _flush()
    return {**_summary(state), "eras": write_eras(state_path, state), "run": summary}


def _cfg_exits():
    if load_ref and ref_path:
        try:
            d = load_ref(ref_path(__file__, "wayback_endpoints.json"), {})
            v = d.get("exits", {}).get("value")
            if v:
                return v
        except Exception:  # noqa: BLE001
            pass
    return ["direct", "pool", "socks5h://127.0.0.1:40000", "socks5h://127.0.0.1:9050"]


def _probe_exits(exits, ua):
    """Keep every exit that ANSWERS a cheap archive request, and also keep one that is merely
    THROTTLED (429 / cooldown) — its per-exit cooldown holds its worker back until it clears, so a
    transient throttle never permanently drops a route. Only a HARD-broken exit (dead port, 407
    credential rejection, SOCKS reply 1/2/4, connection refused) is dropped, and reported."""
    good = []
    for ex in exits:
        try:
            rows, err = W.index([("url", "example.com"), ("fl", "timestamp"), ("limit", "1")],
                                ua=ua, exit=ex, attempts=1, timeout=25)
            if err is None:
                good.append(ex)
                continue
            low = err.lower()
            throttled = "429" in low or "throttled" in low or "cooling" in low or "budget" in low
            if throttled:
                good.append(ex)                 # keep it; the per-exit cooldown paces its worker
                sys.stderr.write(f"[exhaust] exit {ex.id} kept (throttled: {err})\n")
            else:
                sys.stderr.write(f"[exhaust] exit {ex.id} DROPPED (broken: {err})\n")
        except Exception as e:  # noqa: BLE001
            sys.stderr.write(f"[exhaust] exit {ex.id} DROPPED (broken: {e})\n")
    return good


def _summary(state):
    caps = state.get("captures", {})
    done = set(state.get("done", []))
    recs = state.get("records", {})
    return {
        "host": state.get("host"), "state_captures": len(caps), "fetched_or_dead": len(done),
        "remaining": max(0, len(caps) - len(done)), "distinct_selectors": len(recs),
        "exits_used": state.get("exits_used", []), "enum_error": state.get("enum_error"),
        "enum_complete": state.get("enum_complete"),
        "registration_created": state.get("registration_created"),
        "registration_source": state.get("registration_source"),
        "undecodable": len(state.get("undecodable") or {}),   # answered, not decompressible: NOT read
        "urlscan_scans": state.get("urlscan_scan_count"), "urlscan_doms": state.get("urlscan_doms"),
        "urlscan_search_complete": state.get("urlscan_search_complete"),
        "urlscan_search_gap": state.get("urlscan_search_gap"),
        # "listed N of vendor total T (plan window W)": when N == W < T, urlscan holds more scans
        # than this key may page — a VENDOR limit, not ours
        "urlscan_vendor_total": state.get("urlscan_vendor_total"),
        "urlscan_plan_window": state.get("urlscan_plan_window"),
        "urlscan_dom_gap": state.get("urlscan_dom_gap"),
        "urlscan_dom_capability": state.get("urlscan_dom_capability"),
    }


def indicators(state_path):
    """Roll the state's CURRENT-era records (plus those spanning the registration) into the
    wayback_harvest indicator schema. PRIOR-era records — seen only before the current registration,
    most likely an earlier owner's — never become indicators (SKILL.md RULE 5); they stay in the
    `.eras.json` prior_era block as historical facts. With no registration date the split cannot be
    made and every record is returned UNDATED — the caller must treat them with that caveat."""
    from wayback_harvest import build_indicators
    state = _load_state(state_path)
    eras = split_eras(state.get("records") or {}, state.get("registration_created") or "")
    keep = eras["current"] + eras["spans"] + eras["undated"]
    recs = [{"kind": r["kind"], "value": r["value"], "first": r.get("first"),
             "last": r.get("last"), "hits": r.get("hits", 1), "first_url": r.get("first_url")}
            for r in keep]
    return build_indicators({"domain": state.get("host"), "records": recs})


# ------------------------------------------------------------------ detached job control
# A 7-hour sweep cannot run inside a tool call (the host kills a call at ~30 min, and a killed
# synchronous child is left running unobserved). So the MCP tool starts the job DETACHED — its own
# session and log, the state file as the progress channel — returns at once, and a later
# `status` call reads progress. One job per state file: an O_EXCL lock holds the child's pid.

def _lock_path(state_path):
    return (state_path[:-5] if state_path.endswith(".json") else state_path) + ".lock"


def _log_path(state_path):
    return (state_path[:-5] if state_path.endswith(".json") else state_path) + ".log"


def _pid_alive(pid) -> bool:
    try:
        pid = int(pid)
        if pid == os.getpid():
            return True
        os.kill(pid, 0)
    except (OSError, ValueError, TypeError):
        return False
    stat = f"/proc/{pid}/stat"
    if os.path.exists(stat):            # a zombie still answers kill(0); a reused pid runs something else
        try:
            if open(stat).read().split(")")[-1].split()[0] == "Z":
                return False
            # the job runs as wp_wayback_exhaust.py or via wayback_harvest.py --all
            return "wayback" in open(f"/proc/{pid}/cmdline").read()
        except OSError:
            return False
    return True


def _lock_holder(state_path):
    try:
        d = json.load(open(_lock_path(state_path), encoding="utf-8"))
        return d if _pid_alive(d.get("pid")) else None
    except (OSError, ValueError):
        return None


def _acquire_lock(state_path) -> bool:
    """Atomically take the job lock for this state file; a stale lock (dead pid) is reclaimed."""
    os.makedirs(os.path.dirname(state_path) or ".", exist_ok=True)
    lp = _lock_path(state_path)
    for _ in range(2):
        try:
            fd = os.open(lp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
            with os.fdopen(fd, "w") as fh:
                json.dump({"pid": os.getpid(), "started": time.time()}, fh)
            return True
        except FileExistsError:
            if _lock_holder(state_path):
                return False
            try:
                os.remove(lp)           # stale: its holder is gone
            except OSError:
                return False
    return False


def _release_lock(state_path):
    try:
        d = json.load(open(_lock_path(state_path), encoding="utf-8"))
        if int(d.get("pid") or 0) == os.getpid():
            os.remove(_lock_path(state_path))
    except (OSError, ValueError):
        pass


def job_status(state_path) -> dict:
    """Progress of the job owning `state_path` — read from its state file, never a network call."""
    holder = _lock_holder(state_path)
    state = _load_state(state_path)
    tail = []
    try:
        with open(_log_path(state_path), encoding="utf-8", errors="ignore") as fh:
            tail = [ln.rstrip() for ln in fh.readlines()[-6:]]
    except OSError:
        pass
    return {"running": bool(holder), "pid": (holder or {}).get("pid"),
            "started": (holder or {}).get("started"), "state": state_path,
            "log": _log_path(state_path), **(_summary(state) if state else {"state_captures": 0}),
            "log_tail": tail}


def start_detached(argv, state_path) -> dict:
    """Start this module as a detached background job on `state_path` (same args, minus --detach)
    and return at once. If a job already owns the state file, return its status instead."""
    import subprocess
    if _lock_holder(state_path):
        return {"status": "already running", **job_status(state_path)}
    os.makedirs(os.path.dirname(state_path) or ".", exist_ok=True)
    args = [a for a in argv if a != "--detach"]
    if "--state" not in args:
        args += ["--state", state_path]
    log = open(_log_path(state_path), "a", encoding="utf-8")
    p = subprocess.Popen([sys.executable, os.path.abspath(__file__), *args],
                         stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                         start_new_session=True, cwd=os.environ.get("INTEL_HOME") or _engine_root())
    # reap the child when it exits, so a long-lived parent (the MCP server) never holds a zombie
    # that would read as "still running"
    threading.Thread(target=p.wait, daemon=True).start()
    return {"status": "started", "pid": p.pid, "state": state_path, "log": _log_path(state_path),
            "max_hours": _argv_value(args, "--max-hours") or DEFAULT_MAX_HOURS,
            "next": "call again with status=true (or --status) to read progress"}


def _argv_value(argv, flag):
    return argv[argv.index(flag) + 1] if flag in argv and argv.index(flag) + 1 < len(argv) else None


def _main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description="Exhaustively download a domain's whole Wayback history "
                                             "across parallel exits (resumable).")
    ap.add_argument("domain")
    ap.add_argument("--case", help="case id (state under cases/<case>/deep-archive/)")
    ap.add_argument("-o", "--out", help="write the roll-up JSON here")
    ap.add_argument("--state", help="explicit resumable state-file path")
    ap.add_argument("--exits", help="comma list: direct,pool,socks5h://host:port (default: reference)")
    ap.add_argument("--from", dest="yfrom", help="earliest year/date")
    ap.add_argument("--to", dest="yto", help="latest year/date")
    ap.add_argument("--html-only", action="store_true", help="skip archived JS/JSON")
    ap.add_argument("--no-resume", action="store_true", help="ignore any prior state and start over")
    ap.add_argument("--created", help="current registration date (YYYY-MM-DD) for the prior-owner "
                                      "split; default: case WHOIS sidecar, else a keyless WHOIS lookup")
    ap.add_argument("--max-hours", type=float, default=DEFAULT_MAX_HOURS,
                    help=f"stop after N hours, saving state (resume with a re-run). Default "
                         f"{DEFAULT_MAX_HOURS:g}; 0 = unbounded.")
    ap.add_argument("--no-urlscan", action="store_true", help="skip the urlscan scan/DOM pass")
    ap.add_argument("--urlscan-no-spend", action="store_true",
                    help="do not spend the urlscan credential (keyless /dom/ is 403 → scan list only)")
    ap.add_argument("--pretty", action="store_true")
    ap.add_argument("--detach", action="store_true",
                    help="start the job in the background (own session + log) and return at once")
    ap.add_argument("--status", action="store_true",
                    help="report the progress of the job owning this state file (no network)")
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    a = ap.parse_args(raw_argv)
    state_path = os.path.abspath(a.state or _default_state_path(_norm_host(a.domain), a.case, a.out))
    raw_argv = [x for x in raw_argv]
    if "--state" in raw_argv:          # the detached child runs from the engine root: pin the path
        raw_argv[raw_argv.index("--state") + 1] = state_path
    ind = 2 if a.pretty else None
    if a.status:
        print(json.dumps(job_status(state_path), ensure_ascii=False, indent=ind))
        return 0
    if a.detach:
        print(json.dumps(start_detached(raw_argv, state_path), ensure_ascii=False, indent=ind))
        return 0
    if not _acquire_lock(state_path):
        print(json.dumps({"error": "another job owns this state file", **job_status(state_path)},
                         ensure_ascii=False, indent=ind))
        return 3
    try:
        res = exhaust(a.domain, case=a.case, out=a.out, state_path=state_path,
                      include_assets=not a.html_only, year_from=a.yfrom, year_to=a.yto,
                      exits_spec=a.exits, resume=not a.no_resume,
                      urlscan=not a.no_urlscan, urlscan_spend=not a.urlscan_no_spend,
                      max_seconds=(a.max_hours * 3600) if a.max_hours else None,
                      created=a.created)
    finally:
        _release_lock(state_path)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as fh:
            json.dump(res, fh, ensure_ascii=False, indent=ind)
    print(json.dumps(res, ensure_ascii=False, indent=ind))
    return 0 if not res.get("error") else 2


if __name__ == "__main__":
    raise SystemExit(_main())
