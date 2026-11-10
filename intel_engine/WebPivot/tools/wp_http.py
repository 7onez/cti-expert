#!/usr/bin/env python3
"""
wp_http.py — the ONE transport for vendor / index API calls.

WHY THIS EXISTS
---------------
Every client used to carry its own `Request` + `urlopen` + `try/except` + (sometimes) a 429 loop.
Thirty copies meant thirty slightly different answers to the same four questions: which
User-Agent, what happens on an HTTP error, what happens when the network drops, and whether a
rate-limit is retried. This module answers them once. A client keeps its own function name,
signature and return contract and maps a `Response` onto it.

THE CONTRACT
------------
`request()` NEVER RAISES. It returns a `Response`:

    status    int, or None when no HTTP response was received
    headers   dict with lower-cased keys ({} when status is None)
    body      bytes, gzip/deflate-decoded unless decode=False (b"" when status is None)
    url       the final URL after redirects (the requested URL when status is None)
    error     None, or "<ExceptionType>: <message>" when status is None
    attempts  how many requests were sent

An HTTP error status is an ANSWER, not an exception: 402 / 429 / 404 come back as `status` with
the service's body, for the client to classify. `error` is set only when there was no answer at
all, and never contains the request headers or the URL, so a key cannot leak through it.

WHAT IT OWNS
------------
  * User-Agent    the Android default from wp_ua unless the caller passes ua= or its own header
                  (the documented exceptions: fetch_profile.json -> ua_exceptions).
  * Decoding      Content-Encoding gzip/deflate, via wp_common._decode_body.
  * Retry         OPT-IN: a call is sent once unless the client passes retries=N. Existing clients
                  fail fast on purpose (a quota 429 is latched, a per-run counter is kept), and a
                  silent default retry would turn one refused lookup into minutes of sleeping. With
                  retries=N the shared policy applies (http_client.json): a status in
                  retry_statuses, or a connection that was reset / refused / closed by the peer;
                  Retry-After is honoured up to a cap. A TIMEOUT IS NEVER RETRIED: the per-call
                  ceiling (CTI_CALL_TIMEOUT) would multiply into hours. A request that is not
                  GET / HEAD is retried ONLY on 429 or a refused connection — the two cases where
                  the service provably did not act — so a metered POST is never charged twice.

WHAT IT DOES NOT OWN
--------------------
Key handling, per-vendor status classification, per-run caps and the credit ledger
(api_usage.record) stay in the client. There is no local usage cap here (project rule).

`urllib.request.urlopen` is looked up at call time, never bound at import, so wp_common's timeout
floor, the cti_proxy failover opener and a test's stub all apply. A client with its own wall-clock
budget (crt.sh, a fail-fast probe) passes bounded=True to have its timeout honoured exactly: that
uses the unfloored urlopen — still the installed proxy opener — and a test stub as-is.
`wp_net.fetch` remains the TARGET-PAGE fetcher (browser header profile, redirect chain, per-call
proxy); use it for a page a victim would load, and this for an API.

Stdlib only.
"""
from __future__ import annotations

import collections
import email.utils
import http.client
import io
import json
import os
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
import wp_common  # noqa: E402,F401 — installs the egress proxy + the urlopen timeout floor
from wp_common import CALL_TIMEOUT, _decode_body  # noqa: E402
from wp_refs import load_ref, ref_path  # noqa: E402
from wp_ua import DEFAULT_UA  # noqa: E402

__all__ = ["Response", "request", "get_json"]

# RULE 3 — the conservative minimum when references/http_client.json is missing: only a 429 is
# worth repeating, with no wait of our own and a short Retry-After cap.
_HTTP_FALLBACK = {"backoff_seconds": [], "retry_statuses": [429],
                  "retry_after_cap_seconds": {"value": 30}}
_HTTP_REF = load_ref(ref_path(__file__, "http_client.json"), _HTTP_FALLBACK)


def _scalar(group, default):
    try:
        return int((_HTTP_REF.get(group) or {}).get("value"))
    except (TypeError, ValueError, AttributeError):
        return default


BACKOFF_SECONDS = [float(s) for s in (_HTTP_REF.get("backoff_seconds") or [])]
RETRY_STATUSES = frozenset(int(s) for s in (_HTTP_REF.get("retry_statuses") or [429]))
RETRY_AFTER_CAP = max(0, _scalar("retry_after_cap_seconds", 30))

# A connection the peer dropped before answering. Retried; a timeout is not (see module docstring).
_DROPPED = (ConnectionResetError, ConnectionRefusedError, ConnectionAbortedError,
            http.client.RemoteDisconnected)
_TIMEOUTS = (TimeoutError, socket.timeout)
_SAFE_METHODS = frozenset(("GET", "HEAD", "OPTIONS"))


class Response(collections.namedtuple("Response", "status headers body url error attempts")):
    """One call's outcome. See THE CONTRACT in the module docstring."""
    __slots__ = ()

    @property
    def ok(self) -> bool:
        return self.status is not None and 200 <= self.status < 300

    @property
    def text(self) -> str:
        return (self.body or b"").decode("utf-8", "replace")

    @property
    def reason(self) -> str:
        """The standard reason phrase for the status ('Not Found'); '' when there is none."""
        return http.client.responses.get(self.status, "") if self.status is not None else ""

    @property
    def http_error(self) -> str:
        """What str() of urllib's HTTPError read for this status: 'HTTP Error 404: Not Found'."""
        return "HTTP Error %d: %s" % (self.status, self.reason)

    @property
    def failure(self):
        """None on a 2xx; otherwise the one-line reason a client reports: the transport error
        when no answer came back, else `http_error`."""
        if self.status is None:
            return self.error
        return None if self.ok else self.http_error

    def json(self):
        """The body parsed as JSON at ANY status (services put error detail in a JSON body), or
        None when there is no body or it is not JSON."""
        try:
            return json.loads(self.text) if self.body else None
        except ValueError:
            return None

    def raise_for_status(self):
        """For a helper whose own CONTRACT is to raise: raise what urllib raised before —
        URLError when there was no answer; for a non-2xx status an HTTPError with the same
        `.code` and `.headers`, a readable body (`e.read()`, `json.load(e)`) and
        'HTTP Error 404: Not Found' as its text. Returns self on 2xx."""
        if self.status is None:
            raise urllib.error.URLError(self.error or "no response")
        if not self.ok:
            raise urllib.error.HTTPError(self.url, self.status, self.reason, self.headers,
                                         io.BytesIO(self.body or b""))
        return self


def _retry_after(headers: dict):
    """Seconds asked for by a Retry-After header (delta-seconds or HTTP-date), or None."""
    raw = (headers or {}).get("retry-after")
    if not raw:
        return None
    raw = str(raw).strip()
    try:
        return max(0.0, float(raw))
    except ValueError:
        pass
    try:
        when = email.utils.parsedate_to_datetime(raw)
        return max(0.0, when.timestamp() - time.time())
    except (TypeError, ValueError, OverflowError):
        return None


def _wait(attempt: int, headers: dict) -> float:
    """How long to sleep before retry number `attempt` (1-based)."""
    asked = _retry_after(headers)
    if asked is not None:
        return min(asked, float(RETRY_AFTER_CAP))
    if not BACKOFF_SECONDS:
        return 0.0
    return BACKOFF_SECONDS[min(attempt, len(BACKOFF_SECONDS)) - 1]


def _is_dropped(exc, safe: bool) -> bool:
    """True when the connection failed in a way worth retrying. For a request that is not safe to
    repeat, only a REFUSED connection counts: nothing reached the service."""
    reason = getattr(exc, "reason", None)
    if isinstance(exc, _TIMEOUTS) or isinstance(reason, _TIMEOUTS):
        return False
    kinds = _DROPPED if safe else (ConnectionRefusedError,)
    return isinstance(exc, kinds) or isinstance(reason, kinds)


def _describe(exc, url: str) -> str:
    """'<Type>: <message>' with the URL (and so any key in its query string) removed."""
    msg = str(getattr(exc, "reason", None) or exc)
    for secret in (url, url.split("?", 1)[-1] if "?" in url else ""):
        if secret:
            msg = msg.replace(secret, "<url>")
    return f"{type(exc).__name__}: {msg}"[:300]


def _lower(headers) -> dict:
    try:
        return {str(k).lower(): v for k, v in headers.items()}
    except Exception:  # noqa: BLE001 — a stubbed response without a header mapping
        return {}


def request(url: str, *, method: str = None, headers: dict = None, params=None, json_body=None,
            data=None, timeout=None, ua: str = None, retries: int = 0, max_body: int = None,
            decode: bool = True, bounded: bool = False) -> Response:
    """Send one HTTP request and return a `Response`. Never raises.

    params     appended to the URL as a query string (dict or sequence of pairs; doseq)
    json_body  serialised as the request body, Content-Type: application/json
    data       raw request body (bytes or str); mutually exclusive with json_body
    method     defaults to POST when there is a body, else GET
    timeout    seconds; None = the per-call ceiling. wp_common floors anything shorter …
    bounded    … unless bounded=True, which honours `timeout` exactly (the unfloored urlopen)
    ua         User-Agent for a documented exception; a caller header named User-Agent also wins
    retries    how many times to retry after the first attempt (default 0 = send once)
    max_body   read at most this many bytes of the response body
    decode     False returns the body exactly as sent (a .gz file, a WARC range)
    """
    try:
        if params:
            url += ("&" if "?" in url else "?") + urllib.parse.urlencode(params, doseq=True)
        hdrs = {"User-Agent": ua or DEFAULT_UA}
        body = None
        if json_body is not None:
            body = json.dumps(json_body).encode("utf-8")
            hdrs["Content-Type"] = "application/json"
        elif data is not None:
            body = data.encode("utf-8") if isinstance(data, str) else data
        for name, value in (headers or {}).items():
            for default in [k for k in hdrs if k.lower() == str(name).lower()]:
                del hdrs[default]
            hdrs[name] = value
        verb = (method or ("POST" if body is not None else "GET")).upper()
        budget = max(0, int(retries or 0))
    except Exception as e:  # noqa: BLE001 — an unserialisable body or parameter: nothing was sent
        return Response(None, {}, b"", url, _describe(e, url), 0)
    wait_s = timeout if isinstance(timeout, (int, float)) and timeout > 0 else CALL_TIMEOUT

    attempt = 0
    while True:
        attempt += 1
        resp_headers: dict = {}
        try:
            req = urllib.request.Request(url, data=body, headers=hdrs, method=verb)
            opener = urllib.request.urlopen                         # looked up at call time
            if bounded:
                opener = getattr(opener, "_cti_orig", opener)
            with opener(req, timeout=wait_s) as r:
                resp_headers = _lower(getattr(r, "headers", None) or {})
                raw = r.read(max_body) if max_body else r.read()
                status = getattr(r, "status", None) or (r.getcode() if hasattr(r, "getcode") else 200)
                final = r.geturl() if hasattr(r, "geturl") else url
        except urllib.error.HTTPError as e:
            resp_headers = _lower(e.headers or {})
            try:
                raw = e.read(max_body) if max_body else e.read()
            except Exception:  # noqa: BLE001 — an error response whose body cannot be read
                raw = b""
            status, final = e.code, url
        except Exception as e:  # noqa: BLE001 — no HTTP answer: network, TLS, timeout, bad URL
            if attempt <= budget and _is_dropped(e, verb in _SAFE_METHODS):
                time.sleep(_wait(attempt, {}))
                continue
            return Response(None, {}, b"", url, _describe(e, url), attempt)
        if attempt <= budget and status in RETRY_STATUSES and (verb in _SAFE_METHODS or status == 429):
            time.sleep(_wait(attempt, resp_headers))
            continue
        raw = raw or b""
        if decode:
            raw = _decode_body(raw, resp_headers.get("content-encoding"))
        return Response(int(status), resp_headers, raw, final, None, attempt)


def get_json(url: str, **kw):
    """`request()` for the common case: -> (parsed JSON or None, Response). The first element is
    None on a non-2xx status or a body that is not JSON; read `Response.json()` for an error body."""
    r = request(url, **kw)
    return (r.json() if r.ok else None), r
