#!/usr/bin/env python3
"""wp_wayback — the ONE Wayback Machine client every archive call site goes through.

WHY
---
Each collector used to hand-roll its own urllib call against ONE endpoint, most with a single
attempt, so one transient answer read as "never archived". Measured 2026-09-28 (see
references/wayback_endpoints.json for the numbers):

  * /cdx/search/cdx intermittently answers 503 "Temporarily Offline" (or hangs) — while
    /web/timemap/json serves the same index, same query grammar, identical rows, reliably.
  * archive.org/wayback/available answered 429 on every paced request from every exit — unused.
  * id_ playback replays the capture's ORIGINAL Content-Encoding (often gzip); urllib does not
    decompress, so every body is decoded here.
  * /web/<ts>id_/<url> redirects to the nearest capture in <1s; 404 means no capture.
  * a burst of playback fetches gets the egress IP firewalled for minutes.
  * a browser UA from a script client draws 429 "suspected abusive bot traffic" (archive.org bot
    filter, Sept 2026) — every archive.org request here sends wp_wayback_guard's honest client UA
    instead of the caller's (Android) UA, re-scoped on every redirect hop (wg.scope_ua) so a hop
    off archive.org goes back to the caller's UA.

So this module: tries every index endpoint per round with backoff (index), resolves the nearest
capture through the id_ redirect with an index fallback (closest), fetches raw snapshot bytes
with retry and decompression (fetch), can pin any request to an explicit wp_exits.Exit, and sends
EVERY request through wp_wayback_guard — the run breaker, the per-exit pacer and the per-exit
429/refusal cooldown.

CONTRACT
--------
Never raises. Every public call returns its data plus an `err` string: err=None with an empty
result is a VALID "nothing archived" answer; err set means the archive did not answer (or was
skipped by the guard) and the negative is NOT definitive — callers report it as a gap.
Stdlib only.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import NamedTuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wp_wayback_guard as wg  # noqa: E402

try:
    from wp_refs import ref_path, load_ref  # noqa: E402
except Exception:  # noqa: BLE001
    ref_path = load_ref = None

try:
    from wp_common import DEFAULT_UA, _decode_body  # noqa: E402  (Android UA; gzip/deflate decoder)
except Exception:  # noqa: BLE001
    import gzip as _gzip
    DEFAULT_UA = ("Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/140.0.0.0 Mobile Safari/537.36")

    def _decode_body(raw, content_encoding):
        try:
            if "gzip" in (content_encoding or "").lower() or raw[:2] == b"\x1f\x8b":
                return _gzip.decompress(raw)
        except Exception:  # noqa: BLE001
            pass
        return raw

__all__ = ["Response", "index", "index_pages", "closest", "fetch", "fetch_capture", "fetch_url", "raw_url",
           "undecodable", "UNDECODABLE",
           "snapshot_url", "parse_snapshot", "ENDPOINTS_FALLBACK"]

# RULE 3 — the conservative embedded minimum when references/wayback_endpoints.json is missing.
ENDPOINTS_FALLBACK = {
    "index": {"value": ["https://web.archive.org/web/timemap/json",
                        "https://web.archive.org/cdx/search/cdx"]},
    "playback": {"value": "https://web.archive.org/web/"},
    "latest_timestamp": {"value": "99991231235959"},
    "attempts": {"value": 3},
    "backoff_seconds": {"value": 3},
    "truncation_topup_rows": {"value": 200},
}


def _load_refs() -> dict:
    if load_ref is None or ref_path is None:
        import copy
        return copy.deepcopy(ENDPOINTS_FALLBACK)
    return load_ref(ref_path(__file__, "wayback_endpoints.json"), ENDPOINTS_FALLBACK)


_REFS = _load_refs()


def _ref(key):
    try:
        return _REFS[key]["value"]
    except Exception:  # noqa: BLE001
        return ENDPOINTS_FALLBACK[key]["value"]


INDEX_ENDPOINTS = list(_ref("index"))
PLAYBACK = str(_ref("playback"))
LATEST_TS = str(_ref("latest_timestamp"))
ATTEMPTS = max(1, int(_ref("attempts")))
BACKOFF = max(0.0, float(_ref("backoff_seconds")))
TOPUP_ROWS = max(1, int(_ref("truncation_topup_rows")))

# /web/<ts><modifier>/<original>
_SNAP_RE = re.compile(r"^https?://web\.archive\.org/web/(\d{4,14})([a-z]{2}_)?/(.+)$", re.I)


class Response(NamedTuple):
    status: int
    url: str          # final URL after redirects
    headers: dict
    body: bytes       # DECOMPRESSED (gzip/deflate per Content-Encoding, gzip magic sniffed)


class _Stop(Exception):
    """The guard or the archive said stop: no further attempt this call."""


class _BadQuery(Exception):
    """HTTP 400 from the index: the query itself is wrong — retrying another endpoint won't help."""


def _host_of(url: str) -> str:
    return (urllib.parse.urlsplit(url).hostname or "").lower()


def _lane(url: str) -> str:
    if "/cdx/search" in url or "/web/timemap" in url:
        return "index"
    return "playback"


def _headers_of(obj) -> dict:
    h = getattr(obj, "headers", None)
    try:
        return {k: v for k, v in h.items()} if h is not None else {}
    except Exception:  # noqa: BLE001
        return {}


def _urlopen_for(bounded: bool):
    """The urlopen to use for one attempt. wp_common floors every urlopen timeout to
    CTI_CALL_TIMEOUT (project rule: a call runs up to the ceiling, then the run moves on). For an
    attempt that still has an EQUIVALENT endpoint or round after it, that floor would turn a
    hanging /cdx/search (measured: 40s+ hangs on direct, WARP and Tor) into an 83-minute stall
    before the failover this client exists for — so those attempts deliberately use the unfloored
    urlopen (`_cti_orig`, still the process's installed proxy opener) with the caller's bound. The
    FINAL attempt always takes the floored urlopen: the last try still runs to the full ceiling.
    An explicit wp_exits.Exit uses its own opener with the caller's bound: the exhaustive job
    re-queues a failed capture onto another exit, which is its failover."""
    uo = urllib.request.urlopen
    return getattr(uo, "_cti_orig", uo) if bounded else uo


UNDECODABLE = "X-WP-Undecodable"   # set on a Response whose body could not be decompressed


def _brotli_decompress(raw: bytes):
    """brotli / brotlicffi if either imports (optional — WebPivot/requirements.txt), else None."""
    for mod in ("brotli", "brotlicffi"):
        try:
            return __import__(mod).decompress(raw)
        except ImportError:
            continue
    return None


class _Undecodable(Exception):
    pass


def _decoded(raw: bytes, headers: dict) -> bytes:
    """The archive replays a capture's ORIGINAL Content-Encoding even to a client that never asked
    for compression (measured: chongluadao.vn 20210401031237id_ is 9817 B of gzip, 36741 B of
    HTML) and urllib never decompresses — so decode here, once, for every caller. gzip/deflate via
    wp_common; `br` via the optional brotli library. A body that cannot be decoded raises
    _Undecodable — it must never reach the extractors as binary junk read as 'no selectors'."""
    if not raw:
        return raw
    enc = next((v for k, v in (headers or {}).items() if k.lower() == "content-encoding"), "")
    if "br" in [e.strip() for e in (enc or "").lower().split(",")]:
        try:
            out = _brotli_decompress(raw)
        except Exception as e:  # noqa: BLE001 — corrupt stream
            raise _Undecodable(f"br ({e})")
        if out is None:
            raise _Undecodable("br (install the optional `brotli` package)")
        return out
    return _decode_body(raw, enc)


def undecodable(resp) -> str | None:
    """Why `resp`'s body could not be decompressed, or None. The body is then b"" — a caller must
    count the capture as NOT READ (retry later), never as read-and-empty."""
    return ((resp.headers or {}).get(UNDECODABLE) if resp is not None else None)


def _once(url: str, ua: str, timeout: float, method: str, max_wait: float | None,
          bounded: bool = False, exit=None) -> Response:
    """One guarded, paced request. Returns a Response for ANY answer the archive gave (including
    404/403), body decompressed; raises _Stop when the guard skips or the archive throttles or
    refuses this exit, and re-raises a transport/5xx failure for the retry loop. `bounded` = a
    failover attempt remains after this one (see _urlopen_for); `exit` = an explicit
    wp_exits.Exit (its own opener, pacing slot and cooldown)."""
    host = _host_of(url)
    xid = getattr(exit, "id", None)
    reason = wg.admit(host, _lane(url), max_wait=max_wait, exit_id=xid)
    if reason:
        raise _Stop(reason)
    req = wg.scope_ua(urllib.request.Request(url, method=method), ua)  # re-scoped per redirect hop
    opener = exit.open if exit is not None else _urlopen_for(bounded)
    try:
        with opener(req, timeout=timeout) as r:
            hdrs = _headers_of(r)
            raw = r.read() if method != "HEAD" else b""
            geturl = getattr(r, "geturl", None)
            status = int(getattr(r, "status", None) or getattr(r, "code", None) or 200)
            final = geturl() if callable(geturl) else url
        try:
            body = _decoded(raw, hdrs)
        except _Undecodable as ue:
            hdrs, body = {**hdrs, UNDECODABLE: str(ue)}, b""
        resp = Response(status, final, hdrs, body)
    except urllib.error.HTTPError as e:
        if wg.observe(host, e, _headers_of(e), exit_id=xid):
            wg.record(False, kind=_lane(url))
            raise _Stop(f"{host} HTTP 429 (throttled) via {xid or wg._egress_id()}")
        final = e.geturl() or url
        # a HEAD whose redirect landed on a failing hop: the archive DID answer the resolver (the
        # 302 named the capture); only that capture's playback failed — hand the URL back
        answered = not wg.is_failure(e) or (method == "HEAD" and final != url)
        wg.record(answered, kind=_lane(url))
        if not answered:
            raise
        try:
            body = _decoded(e.read() or b"", _headers_of(e))
        except Exception:  # noqa: BLE001
            body = b""
        wg.observe(host, True, exit_id=xid)
        return Response(e.code, final, _headers_of(e), body)
    except Exception as e:  # noqa: BLE001 — transport: timeout, reset, refused, proxy
        wg.record(not wg.is_failure(e), kind=_lane(url))
        if wg.observe(host, e, exit_id=xid):
            raise _Stop(f"{host} refused the connection via {xid or wg._egress_id()} ({e})")
        raise
    wg.record(True, kind=_lane(url))
    wg.observe(host, True, exit_id=xid)
    return resp


def _request(urls, *, ua=None, timeout=60, method="GET", valid=None, max_wait=None,
             exit=None, attempts=None):
    """Try `urls` in order each round, `attempts` (default ATTEMPTS) rounds with linear backoff.
    `valid(resp)` returns the parsed value for an acceptable answer or raises ValueError for an
    unusable body (moves on to the next endpoint). Returns (value, err)."""
    ua = ua or DEFAULT_UA
    urls = [urls] if isinstance(urls, str) else list(urls)
    rounds = max(1, int(attempts or ATTEMPTS))
    last = "no attempt made"
    for rnd in range(rounds):
        for i, url in enumerate(urls):
            final_attempt = rnd == rounds - 1 and i == len(urls) - 1
            try:
                resp = _once(url, ua, timeout, method, max_wait, bounded=not final_attempt,
                             exit=exit)
            except _Stop as s:
                return None, str(s)
            except Exception as e:  # noqa: BLE001
                last = f"{_host_of(url)}: {e}"
                continue
            try:
                return (valid(resp) if valid else resp), None
            except ValueError as e:
                last = f"{_host_of(url)}: {e}"
                continue
        if rnd < rounds - 1 and BACKOFF:
            time.sleep(BACKOFF * (rnd + 1))
    return None, f"Wayback did not answer after {rounds} round(s) ({last})"


def _query(params) -> str:
    # CDX regex filters (mimetype:(text/html|…)) are accepted verbatim, so keep their punctuation;
    # but `+` MUST be percent-encoded — the archive reads a raw `+` in a query value as a space,
    # which corrupts a base64 resumeKey (paging then repeats or skips). `+` is not needed literally
    # by any CDX param, so encoding it is always safe.
    return "&".join(f"{k}={urllib.parse.quote(str(v), safe=':/()|.*!,[]^$-_~')}"
                    for k, v in params)


def index(params, *, ua=None, timeout=120, max_wait=None, exit=None, attempts=None):
    """A CDX-grammar index query → (rows, err). `params` is a list of (key, value) pairs in order
    (repeat a key for several filters); `output=json` is added when absent. `rows` excludes the
    header row; [] with err=None is a valid 'no captures'; None with err = the archive did not
    answer (a gap, not a negative)."""
    params = list(params)
    if not any(k == "output" for k, _ in params):
        params.append(("output", "json"))
    qs = _query(params)

    def _valid(resp):
        if resp.status != 200:
            if resp.status == 400:
                raise _BadQuery(resp.body[:200].decode("utf-8", "ignore"))
            raise ValueError(f"HTTP {resp.status}")
        text = resp.body.decode("utf-8", "ignore").strip()
        if not text:
            return []
        try:
            rows = json.loads(text)
        except ValueError:
            raise ValueError(f"non-JSON index body ({text[:60]!r})")
        if not isinstance(rows, list):
            raise ValueError("index body is not a list")
        return [r for r in rows[1:] if isinstance(r, list)] if rows else []

    try:
        return _request([f"{ep}?{qs}" for ep in INDEX_ENDPOINTS], ua=ua, timeout=timeout,
                        valid=_valid, max_wait=max_wait, exit=exit, attempts=attempts)
    except _BadQuery as e:
        return None, f"Wayback rejected the query: {e}"


def raw_url(timestamp: str, original: str, mode: str = "id_") -> str:
    return f"{PLAYBACK}{timestamp}{mode}/{original}"


def snapshot_url(timestamp: str, original: str) -> str:
    return f"{PLAYBACK}{timestamp}/{original}"


def parse_snapshot(url: str):
    """(timestamp, modifier, original) of a /web/ snapshot URL, else None."""
    m = _SNAP_RE.match(url or "")
    return (m.group(1), m.group(2) or "", m.group(3)) if m else None


def _norm_ts(ts) -> str:
    digits = re.sub(r"\D", "", str(ts or ""))
    return digits[:14]


def _index_key(url: str) -> str:
    """The index's exact-match key for a URL: scheme dropped (the archive canonicalises http/https
    and www), path + query kept — so a deep URL never silently resolves to its host root."""
    rest = url.split("://", 1)[1] if "://" in url else url
    host, _, path = rest.partition("/")
    return host if path in ("", "/") else f"{host}/{path}"


def closest(url: str, timestamp=None, *, ua=None, timeout=60):
    """Nearest capture of `url` to `timestamp` (default: the newest) → (snapshot_url, ts, err).

    1. the id_ redirect resolver — HEAD {playback}<ts>id_/<url>; the archive 302s to its nearest
       capture, 404 = no capture (definitive);
    2. the index (closest+sort=closest, or the newest 200 row via fastLatest), full path kept.
    (The availability API is not used: it answered 429 on 27/27 paced requests from three
    unrelated IPs on 2026-09-28, and once returned {} for an archived URL.)
    snapshot_url is the plain /web/<ts>/<original> form (pass it through raw_url/parse_snapshot for
    the id_ bytes). (None, None, None) = a valid 'not archived'; err set = not definitive."""
    if not url:
        return None, None, None
    target = url if "://" in url else "http://" + url
    want = _norm_ts(timestamp)
    probe_ts = (want + "0" * 14)[:14] if want else LATEST_TS
    errs = []

    resp, err = _request(raw_url(probe_ts, target), ua=ua, timeout=timeout, method="HEAD")
    if resp is not None:
        if resp.status in (404, 410):
            return None, None, None
        snap = parse_snapshot(resp.url)
        # redirected → the archive named its nearest capture (even when that capture's own playback
        # then failed: a 5xx on the hop still names the timestamp). No redirect → the archive served
        # the probe URL itself: a capture only for an exact 14-digit timestamp (the placeholder is
        # never a real capture).
        if snap and (snap[0] != probe_ts or (resp.status == 200 and len(want) == 14)):
            return snapshot_url(snap[0], snap[2]), snap[0], None
        errs.append(f"resolver: HTTP {resp.status} without a capture redirect")
    elif err:
        errs.append(f"resolver: {err}")
        if wg.blocked() or wg.cooling(_host_of(PLAYBACK)):
            return None, None, err

    q = [("url", _index_key(target)), ("fl", "timestamp,original"), ("filter", "statuscode:200")]
    q += ([("closest", probe_ts), ("sort", "closest"), ("limit", "1")] if want
          else [("fastLatest", "true"), ("limit", "-1")])
    rows, err = index(q, ua=ua, timeout=timeout)
    rows = [r for r in (rows or []) if len(r) >= 2]
    if rows:
        row = rows[0] if want else rows[-1]
        ts, orig = row[0], row[1]
        return snapshot_url(ts, orig), ts, None
    if err:
        errs.append(f"index: {err}")
        return None, None, "; ".join(errs)
    return None, None, None


def index_pages(params, *, ua=None, timeout=120, page_rows=5000, exit=None, max_pages=100000):
    """Yield the WHOLE index for `params`, page by page, via resumeKey paging — the way to read a
    domain's complete capture list without the row cap that silently drops recent years from a
    single query. Each yield is (rows, err): rows is that page's list (header + resumeKey row
    stripped), err is set only when a page did not answer (the caller decides whether the partial
    result is usable). `params` must NOT set limit/showResumeKey/resumeKey — this owns paging."""
    base = [(k, v) for k, v in params if k not in ("limit", "showResumeKey", "resumeKey")]
    base += [("limit", int(page_rows)), ("showResumeKey", "true")]
    resume = None
    seen_keys = set()
    for _ in range(max_pages):
        page = base + ([("resumeKey", resume)] if resume else [])
        rows, err = index(page, ua=ua, timeout=timeout, exit=exit)
        if err:
            yield [], err
            return
        rows = rows or []
        # the resumeKey is the last non-empty single-field row, preceded by a blank separator row
        resume = None
        if rows and len(rows[-1]) == 1 and rows[-1][0]:
            resume = rows[-1][0]
            rows = rows[:-1]
            while rows and not rows[-1]:      # drop the blank separator row(s)
                rows = rows[:-1]
        data = [r for r in rows if len(r) >= 2]
        yield data, None
        if not resume:
            return
        if resume in seen_keys:              # a server that never advances the key: stop, don't spin
            yield [], f"resumeKey did not advance ({resume[:12]}…) — stopping paging"
            return
        seen_keys.add(resume)


def fetch_url(url: str, *, ua=None, timeout=60, max_wait=None, exit=None, attempts=None):
    """GET one snapshot URL with retry → (Response, err), body decompressed. A 404/403 comes back
    as a Response with that status (the archive answered); err set = it did not."""
    return _request(url, ua=ua, timeout=timeout, max_wait=max_wait, exit=exit, attempts=attempts)


def fetch(timestamp: str, original: str, mode: str = "id_", *, ua=None, timeout=60, max_wait=None,
          exit=None, attempts=None):
    """The archived bytes of one capture (`id_` = original bytes) → (Response, err)."""
    return fetch_url(raw_url(timestamp, original, mode), ua=ua, timeout=timeout, max_wait=max_wait,
                     exit=exit, attempts=attempts)


def fetch_capture(timestamp: str, original: str, mode: str = "id_", *, ua=None, timeout=60,
                  neighbours: int = 3):
    """fetch() one capture, and when ITS playback fails — some indexed captures are unplayable
    (measured: a capture the resolver names answers 503 every time) — try up to `neighbours` of
    the nearest other 200 captures of the same URL. The first capture gets ONE attempt (an
    unplayable capture fails the same way on every retry; its neighbours are the better bet), the
    neighbours the normal retries. → (Response, timestamp_used, err); Response is None only when
    no candidate could be fetched. Cite timestamp_used — it is the capture the bytes came from."""
    resp, err = fetch(timestamp, original, mode, ua=ua, timeout=timeout,
                      attempts=1 if neighbours > 0 else None)
    if resp is not None and resp.status == 200 and not undecodable(resp):
        return resp, timestamp, None
    first = err or (f"undecodable body: {undecodable(resp)}" if undecodable(resp)
                    else f"HTTP {resp.status}")
    if wg.blocked() or wg.cooling(_host_of(PLAYBACK)) or neighbours <= 0:
        return None, timestamp, first
    ts14 = (_norm_ts(timestamp) + "0" * 14)[:14]
    rows, ierr = index([("url", _index_key(original)), ("fl", "timestamp,original"),
                        ("filter", "statuscode:200"), ("closest", ts14), ("sort", "closest"),
                        ("limit", neighbours + 1)], ua=ua, timeout=timeout)
    for row in [r for r in (rows or []) if len(r) >= 2 and r[0] != timestamp][:neighbours]:
        resp, err = fetch(row[0], row[1], mode, ua=ua, timeout=timeout)
        if resp is not None and resp.status == 200 and not undecodable(resp):
            print(f"[wayback] capture {timestamp} unplayable ({first}) — used neighbour {row[0]}",
                  file=sys.stderr)
            return resp, row[0], None
    # an unplayable capture is the ARCHIVE answering badly, not a transport gap — but it is still
    # not "no content": callers treat Response=None as not-fetched and say why
    return None, timestamp, first + (f"; neighbours: {ierr}" if ierr else "; no playable neighbour")


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Wayback client probe: nearest capture + index count.")
    ap.add_argument("url")
    ap.add_argument("--at", help="timestamp (YYYY[MMDD…]); default newest")
    a = ap.parse_args()
    print(json.dumps(dict(zip(("snapshot", "timestamp", "err"), closest(a.url, a.at))), indent=2))
