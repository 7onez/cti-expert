#!/usr/bin/env python3
"""
wp_liveness.py — is this host actually SERVING the operator's content? Decided by reading
the page, not by trusting the HTTP status code.

WHY THIS EXISTS
---------------
"Is the domain live" was answered in three different places in this repo by three different
one-liners, and every one of them was a status-code check with a small hardcoded list of
parking strings bolted on. That is wrong in both directions, and both directions corrupt a
case silently:

  * **200 is not alive.** A registrar parking page, a freshly-provisioned `Welcome to nginx`
    default page, a host's "Account Suspended" notice and a soft-404 all return HTTP 200 with
    a complete HTML document. A status check calls all four LIVE, and the collector then
    harvests favicon hashes, analytics IDs and DOM fingerprints off a template shared by
    millions of unrelated domains — which is exactly how a parking favicon becomes a
    fifty-domain "operator cluster" that isn't one.
  * **404/403 is not dead.** The server ANSWERED. The name is registered, resolving, and
    pointed at infrastructure someone controls; only that path is gone (or we specifically
    are being refused). Marking it dead deletes a live lead from the case, and worse, it
    stops the re-check that would have caught the kit coming back at the same URL.

  * **A bot wall is not a verdict at all.** A Cloudflare interstitial means the page was never
    seen. That is absence of RECORD, not evidence of absence — the same discipline the
    capability layer applies to a missing API key. It classifies as `blocked`, live=None.

THE REUSE POINT
---------------
A domain that is parked, suspended, serving a server default page or answering 404 is still
UNDER SOMEONE'S CONTROL. Fraud operators park names between campaigns, rebuild on a new
provider after a takedown while keeping the domain, and stage infrastructure days before the
kit is uploaded. So every one of those states sets **`reuse_watch: True`** — meaning "this
name can be flipped to live content later; keep it on the re-check list". The only state that
evidences a name is genuinely gone is `unresolved` (NXDOMAIN), and even that is dormancy
rather than death while the registration is unexpired.

THE GUARDRAIL
-------------
`references/liveness.json` → `policy` holds four rules the classifier enforces on itself, so a
verdict cannot be produced from thin evidence:

    require_content_for_live   a `live` verdict REQUIRES that a body was actually read and
                               passed the marker + thin-content tests. A 200 with no body
                               read can never be reported as live — it degrades to `unknown`.
    never_dead_from_status     no HTTP status code, alone, may produce dead=True. Only DNS
                               non-resolution does.
    never_dead_when_blocked    a bot-wall hit forces live=None.
    min_signals                a verdict resting on fewer than N independent signals
                               (status / content / visible-text volume / DNS / nameservers)
                               comes back `confident: False`, so the report hedges.

All the matching values — parking markers, parking nameservers, soft-404 strings, suspension
notices, server-default pages, bot walls, thresholds and the state vocabulary itself — are
DATA in `WebPivot/references/liveness.json` (contributor RULE 3), so an analyst extends them
without touching this file.

CLI:
    python3 WebPivot/tools/wp_liveness.py <host-or-url> [more ...] [--json] [--timeout N]
"""
from __future__ import annotations

import json
import os
import re
import socket
import sys
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from wp_refs import load_ref, ref_path  # noqa: E402

try:                                                # optional: shared fetch honours --proxy
    from wp_net import fetch as _wp_fetch           # noqa: E402
except Exception:                                   # noqa: BLE001
    _wp_fetch = None
try:
    from wp_common import _registrable              # noqa: E402
except Exception:                                   # noqa: BLE001
    def _registrable(host: str) -> str:             # crude eTLD+1, good enough for a redirect test
        parts = (host or "").strip(".").split(".")
        return ".".join(parts[-2:]) if len(parts) > 2 else (host or "")

# Minimal embedded fallback — see wp_refs.py's FAILURE MODE. On the fallback this module still
# refuses to call a 404 dead and still refuses to call a bot wall a verdict (those rules are
# CODE, not data); it just recognises far fewer templates, so more pages land in `live` than
# should. That is the loud-and-lossy direction, and the loader warns on stderr when it happens.
_LIVE_FALLBACK = {
    "parking_markers": ["parked domain name", "buy this domain", "this domain is for sale",
                        "coming soon", "under construction"],
    "parking_nameservers": ["sedoparking.com", "parkingcrew.net", "bodis.com", "dan.com"],
    "soft_404_markers": ["404 not found", "page not found", "page does not exist"],
    "suspended_markers": ["account suspended", "domain has expired",
                          "bandwidth limit exceeded"],
    "default_page_markers": ["welcome to nginx", "apache2 ubuntu default page", "it works!</h1>"],
    "blocked_markers": ["just a moment...", "attention required! | cloudflare",
                        "checking your browser before accessing", "verify you are human"],
    "thresholds": {"body_read_bytes": 200000, "marker_scan_chars": 60000,
                   "thin_body_chars": 512, "min_text_chars": 64, "http_timeout": 15,
                   "widget_page_text_chars": 1500},
    "states": {
        "live": {"live": True, "reuse_watch": False, "dead": False, "note": "Serves real content."},
        "unknown": {"live": None, "reuse_watch": True, "dead": False,
                    "note": "Could not reach a conclusion; never round this to dead."},
    },
    "policy": {"require_content_for_live": True, "never_dead_from_status": True,
               "never_dead_when_blocked": True, "min_signals": 2},
}

_L = load_ref(ref_path(__file__, "liveness.json"), _LIVE_FALLBACK)

PARKING_MARKERS = tuple(m.lower() for m in _L["parking_markers"])
PARKING_NS = tuple(n.lower().strip(".") for n in _L["parking_nameservers"])
SOFT_404_MARKERS = tuple(m.lower() for m in _L["soft_404_markers"])
SUSPENDED_MARKERS = tuple(m.lower() for m in _L["suspended_markers"])
DEFAULT_PAGE_MARKERS = tuple(m.lower() for m in _L["default_page_markers"])
BLOCKED_MARKERS = tuple(m.lower() for m in _L["blocked_markers"])
THRESHOLDS = dict(_L["thresholds"])
STATES = dict(_L["states"])
POLICY = dict(_L["policy"])

BODY_READ_BYTES = int(THRESHOLDS.get("body_read_bytes", 200000))
MARKER_SCAN = int(THRESHOLDS.get("marker_scan_chars", 60000))
THIN_BODY = int(THRESHOLDS.get("thin_body_chars", 512))
MIN_TEXT = int(THRESHOLDS.get("min_text_chars", 64))
HTTP_TIMEOUT = int(THRESHOLDS.get("http_timeout", 15))
MIN_SIGNALS = int(POLICY.get("min_signals", 2))

# States that must never be reachable from an HTTP status code alone. Enforced in _finalize().
_DNS_ONLY_DEAD = {"unresolved"}

_TAG_RE = re.compile(r"<[^>]+>")
_DROP_RE = re.compile(r"(?is)<(script|style|noscript|template)\b.*?</\1>")
_WS_RE = re.compile(r"\s+")


# ------------------------------------------------------------------ helpers
def visible_text(html: str) -> str:
    """Roughly what a human would SEE: script/style/markup removed, whitespace collapsed.

    The point is volume, not fidelity. A JS-only stub or a meta-refresh redirector has plenty
    of HTML and almost no text; treating it as `live` invites the collector to fingerprint a
    framework instead of a site."""
    if not html:
        return ""
    return _WS_RE.sub(" ", _TAG_RE.sub(" ", _DROP_RE.sub(" ", html))).strip()


def _hits(haystack: str, needles) -> list[str]:
    return [n for n in needles if n in haystack]


def _state(name: str) -> dict:
    """The state record from the data file, with a safe shape if the file omits it."""
    rec = STATES.get(name) or {}
    return {"live": rec.get("live"), "reuse_watch": bool(rec.get("reuse_watch", True)),
            "dead": bool(rec.get("dead", False)), "note": rec.get("note", "")}


def _decode(body) -> str:
    if body is None:
        return ""
    if isinstance(body, bytes):
        return body[:BODY_READ_BYTES].decode("utf-8", "ignore")
    return str(body)[:BODY_READ_BYTES]


def _finalize(state: str, reason: str, evidence: list, signals: list, **extra) -> dict:
    """Apply the self-imposed policy, then emit the verdict.

    This is where the guardrail actually bites: a `live` claim with no body read is downgraded,
    a status-derived dead claim is refused, and a verdict on thin evidence is marked
    unconfident rather than silently asserted."""
    rec = _state(state)
    live, dead = rec["live"], rec["dead"]
    body_read = "content" in signals

    if state == "live" and POLICY.get("require_content_for_live", True) and not body_read:
        state, rec = "unknown", _state("unknown")
        live, dead = rec["live"], rec["dead"]
        reason = ("no response body was read, so 'live' cannot be asserted — "
                  "require_content_for_live") + f" (was: {reason})"
    if POLICY.get("never_dead_from_status", True) and dead and state not in _DNS_ONLY_DEAD:
        dead = False
        reason += " [dead suppressed: never_dead_from_status — only DNS non-resolution evidences a dead name]"
    if POLICY.get("never_dead_when_blocked", True) and state == "blocked":
        live, dead = None, False

    out = {
        "state": state,
        "live": live,                       # tri-state: True / False / None(=unknown)
        "dead": dead,
        "reuse_watch": rec["reuse_watch"],  # still controlled → keep re-checking this name
        "confident": len(signals) >= MIN_SIGNALS,
        "reason": reason,
        "evidence": evidence,
        "note": rec["note"],
        "signals": signals,
        "checked": "+".join(signals) or "nothing",
    }
    out.update(extra)
    return out


# ------------------------------------------------------------------ the classifier
def classify(*, url: str = "", final_url: str = "", status=None, headers: dict = None,
             body=None, ips=None, nameservers=None, error: str = "") -> dict:
    """Classify one host's liveness from whatever evidence the caller has.

    Every argument is optional — the classifier reports what it can support and marks the
    verdict unconfident rather than inventing the rest. `body` may be bytes or str and SHOULD
    be passed even for a 4xx/5xx response: the body of a 404 is what distinguishes "this path
    is gone" from "this whole host is a parking page that answers 404 for everything"."""
    headers = {k.lower(): v for k, v in (headers or {}).items()}
    ips = list(ips or [])
    nameservers = [str(n).lower().strip(".") for n in (nameservers or [])]
    html = _decode(body)
    scan = html[:MARKER_SCAN].lower()
    text = visible_text(html)

    signals = []
    if status is not None:
        signals.append("status")
    if html:
        signals.append("content")
    if ips:
        signals.append("dns")
    if nameservers:
        signals.append("ns")

    common = {"http_status": status, "final_url": final_url or url, "ips": ips,
              "body_chars": len(html), "text_chars": len(text),
              "server": headers.get("server", "")}

    # -- 0. transport-level outcomes: DNS is the ONLY evidence of a dead name -------------
    if status is None:
        err = (error or "").lower()
        dns_dead = any(s in err for s in ("nodename nor servname", "name or service not known",
                                          "nxdomain", "not known", "no address associated",
                                          "temporary failure in name resolution",
                                          "getaddrinfo failed"))
        if dns_dead or (not ips and "dns" in (error or "").lower()):
            return _finalize("unresolved", f"DNS does not resolve ({error or 'NXDOMAIN'})",
                             [error] if error else [], signals or ["dns"], **common)
        if ips:
            return _finalize("no_http", f"DNS resolves to {', '.join(ips[:3])} but no HTTP "
                                        f"response ({error or 'no response'}) — the name is "
                                        f"registered and pointed somewhere, so this is NOT dead",
                             [error] if error else [], signals, **common)
        return _finalize("unknown", f"no HTTP response and no DNS evidence ({error or 'unknown'})",
                         [error] if error else [], signals, **common)

    code = int(status)

    # -- 1. bot wall FIRST: it invalidates every content test below ------------------------
    # …unless the "wall" sits on a SERVED page (2xx/3xx) with thousands of characters of real
    # copy: then the marker is a widget (reCAPTCHA badge on a login form, a Ray-ID in a footer)
    # and the page WAS seen. The exemption never applies to a 4xx: a verbose block page
    # (Cloudflare 1020 with its "Why have I been blocked?" copy) can exceed the threshold, and a
    # refused request with a wall marker is a wall regardless of how much it says.
    hits = _hits(scan, BLOCKED_MARKERS)
    if hits and (code >= 400 or len(text) <= int(THRESHOLDS.get("widget_page_text_chars", 1500))):
        return _finalize("blocked", f"HTTP {code} carrying a bot-wall/WAF interstitial — the "
                                    f"real page was never seen; this is absence of record, "
                                    f"not evidence about the target", hits, signals, **common)

    # -- 2. status classes that answer WITHOUT settling liveness ---------------------------
    if code >= 500:
        return _finalize("server_error", f"HTTP {code} — the host answered, the application is "
                                         f"broken; transient, re-check before recording anything",
                         [], signals, **common)
    if code in (401, 403):
        return _finalize("forbidden", f"HTTP {code} — the server is up and refusing US. Content "
                                      f"unknown: this is commonly an allowlist, a geo-fence or a "
                                      f"cloaking rule, NOT a dead domain", [], signals, **common)
    if code in (404, 410):
        # The body still matters: a parking platform answers 404 for unknown paths too.
        for name, markers, why in (
            ("parked", PARKING_MARKERS, "parking/for-sale template"),
            ("suspended", SUSPENDED_MARKERS, "provider suspension/expiry notice"),
        ):
            h = _hits(scan, markers)
            if h:
                return _finalize(name, f"HTTP {code} serving a {why} — the name is still "
                                       f"controlled", h, signals, **common)
        return _finalize("not_found", f"HTTP {code} for this path — the server ANSWERED, so the "
                                      f"host is reachable; only this path is gone",
                         [], signals, **common)

    # -- 3. HTTP 2xx/3xx: now the CONTENT decides, in most-specific-first order -------------
    for name, markers, why in (
        ("suspended", SUSPENDED_MARKERS, "a provider suspension / domain-expiry notice"),
        ("parked", PARKING_MARKERS, "a domain-parking / for-sale template"),
        ("default_page", DEFAULT_PAGE_MARKERS, "a web-server default page (no content deployed)"),
        ("soft_404", SOFT_404_MARKERS, "a not-found page returned with a success status (soft 404)"),
    ):
        h = _hits(scan, markers)
        if h:
            return _finalize(name, f"HTTP {code} but the body is {why}", h, signals, **common)

    # Parking corroborated by delegation, even when the page itself gave nothing away.
    ns_hits = [n for n in nameservers if any(n.endswith(p) for p in PARKING_NS)]
    if ns_hits:
        return _finalize("parked", f"HTTP {code}, and the domain is delegated to parking "
                                   f"nameservers ({', '.join(ns_hits[:2])})", ns_hits,
                         signals, **common)

    if len(html) <= THIN_BODY or len(text) <= MIN_TEXT:
        return _finalize("empty", f"HTTP {code} but effectively no content "
                                  f"({len(html)} bytes of HTML, {len(text)} chars of visible "
                                  f"text) — may be a client-side-rendered kit; re-collect with "
                                  f"--render before judging", [], signals, **common)

    src_host = urlparse(url if "://" in (url or "") else "http://" + (url or "")).hostname or ""
    dst_host = urlparse(final_url or url or "").hostname or ""
    if src_host and dst_host and _registrable(src_host) != _registrable(dst_host):
        return _finalize("redirected_offsite", f"HTTP {code} after redirecting to a different "
                                               f"registrable domain ({dst_host}) — the "
                                               f"destination is the lead", [dst_host],
                         signals, **common)

    return _finalize("live", f"HTTP {code} with {len(text)} chars of visible text and no "
                             f"parking / default-page / soft-404 / suspension marker",
                     [], signals, **common)


# ------------------------------------------------------------------ live probe
def resolve(host: str):
    try:
        _, _, ips = socket.gethostbyname_ex(host)
        return ips, ""
    except Exception as exc:                                    # noqa: BLE001
        return [], f"{type(exc).__name__}: {exc}"


def nameservers_for(host: str) -> list[str]:
    """Best-effort NS lookup via `dig`; an empty list simply drops the `ns` signal."""
    try:
        import subprocess
        r = subprocess.run(["dig", "+short", "NS", host], capture_output=True, text=True,
                           timeout=10)
        return [l.strip().rstrip(".").lower() for l in (r.stdout or "").splitlines() if l.strip()]
    except Exception:                                           # noqa: BLE001
        return []


def probe(target: str, *, timeout: int = None, proxy: str = None,
          with_ns: bool = True) -> dict:
    """DNS + one bounded HTTP read + classify(). The body is read for EVERY status code."""
    timeout = timeout or HTTP_TIMEOUT
    url = target if "://" in target else "https://" + target
    host = urlparse(url).hostname or target
    ips, dns_err = resolve(host)
    ns = nameservers_for(host) if (with_ns and ips) else []

    if not ips:
        return dict(classify(url=url, ips=[], nameservers=ns, error=dns_err or "NXDOMAIN"),
                    host=host)

    final_url, status, headers, body, err = url, None, {}, b"", ""
    for candidate in (url, "http://" + host + "/" if url.startswith("https://") else None):
        if not candidate:
            continue
        try:
            if _wp_fetch is not None:
                final_url, status, headers, body = _wp_fetch(candidate, timeout=timeout,
                                                             proxy=proxy)
            else:                                   # standalone: stdlib, still reads 4xx bodies
                import urllib.error
                import urllib.request
                req = urllib.request.Request(candidate,
                                             headers={"User-Agent": "Mozilla/5.0 (compatible)"})
                try:
                    with urllib.request.urlopen(req, timeout=timeout) as resp:
                        final_url, status = resp.geturl(), resp.status
                        headers = {k.lower(): v for k, v in resp.headers.items()}
                        body = resp.read(BODY_READ_BYTES)
                except urllib.error.HTTPError as e:      # a 404 body is EVIDENCE, not an error
                    final_url, status = candidate, e.code
                    headers = {k.lower(): v for k, v in (e.headers or {}).items()}
                    body = e.read(BODY_READ_BYTES)
            err = ""
            break
        except Exception as exc:                        # noqa: BLE001
            err = f"{type(exc).__name__}: {exc}"

    return dict(classify(url=url, final_url=final_url, status=status, headers=headers,
                         body=body, ips=ips, nameservers=ns, error=err), host=host)


# ------------------------------------------------------------------ pivot-JSON adapter
def from_pivot_result(result: dict) -> dict:
    """Classify from an ALREADY-COLLECTED pivot_extract JSON — no new request to the target.

    Prefers the captured DOM/body over the title, because the title of a parking page is often
    just the bare domain. Falls back to whatever the capture recorded."""
    meta = (result or {}).get("meta", {}) or {}
    arts = (result or {}).get("artifacts", {}) or {}
    ips, ns = [], []
    for p in (result or {}).get("pivots", []) or []:
        if p.get("kind") == "domain":
            live = (p.get("live_results", {}) or {})
            ips = ((live.get("dns", {}) or {}).get("ips") or [])
            ns = [str(x).lower().rstrip(".") for x in ((live.get("dns", {}) or {}).get("ns") or [])]
            break
    if not ns:
        ns = [str(x).lower().rstrip(".") for x in (((result or {}).get("whois") or {}).get("nameServers") or [])]

    body = arts.get("body") or arts.get("html") or ""
    document_read = bool(body)                 # True only when the page itself was read
    if not body:
        # the collector writes the captured DOM path as meta.raw_dom_file (older captures: dom/dom_path)
        dom = meta.get("raw_dom_file") or meta.get("dom") or meta.get("dom_path") or ""
        if dom and os.path.exists(dom):
            try:
                with open(dom, "rb") as fh:
                    body = fh.read(BODY_READ_BYTES)
                document_read = bool(body)
            except Exception:                                   # noqa: BLE001
                body = ""
    if not body:
        # Last resort: the title alone. Recorded as a WEAK signal — one signal, so the verdict
        # comes back confident=False rather than pretending the page was read.
        body = f"<title>{arts.get('title', '')}</title>{arts.get('description', '')}"
        if not (arts.get("title") or arts.get("description")):
            body = ""

    # Status: the collector's own record first (artifacts.http.status; meta.http_status is the
    # legacy field). A LIVE capture whose document was actually read but whose status code was
    # lost is a served page, not "no HTTP response" — infer 200. Never for an archive/urlscan
    # recovery (recovered_via set) and never from the title-only fallback.
    status = (((arts.get("http") or {}).get("status"))
              or meta.get("http_status") or meta.get("status"))
    live_error = meta.get("live_error") or ""
    if (status is None and document_read and len(body) >= 200 and not live_error
            and not meta.get("recovered_via")):
        status = 200
    headers = meta.get("headers") or arts.get("server_headers") or {}
    return classify(url=meta.get("source") or "", final_url=meta.get("final_url") or "",
                    status=status, headers=headers, body=body, ips=ips, nameservers=ns,
                    error=live_error)


# ------------------------------------------------------------------ CLI
def _main() -> None:
    import argparse
    ap = argparse.ArgumentParser(
        description="Classify host liveness by READING THE PAGE, not by the status code. "
                    "Distinguishes live / parked / default_page / suspended / soft_404 / "
                    "not_found / forbidden / blocked / empty / redirected_offsite / "
                    "server_error / no_http / unresolved, and flags every state whose name is "
                    "still controlled (reuse_watch) for re-checking.")
    ap.add_argument("targets", nargs="+", help="host or URL")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    ap.add_argument("--timeout", type=int, default=HTTP_TIMEOUT)
    ap.add_argument("--proxy", default=None)
    ap.add_argument("--no-ns", action="store_true", help="skip the NS lookup (one fewer signal)")
    a = ap.parse_args()

    out = [probe(t, timeout=a.timeout, proxy=a.proxy, with_ns=not a.no_ns) for t in a.targets]
    if a.json:
        print(json.dumps(out, indent=2, ensure_ascii=False))
        return
    for r in out:
        live = {True: "LIVE", False: "not live", None: "UNKNOWN"}[r["live"]]
        flags = " ".join(x for x in (
            "⟲reuse-watch" if r["reuse_watch"] else "",
            "" if r["confident"] else "⚠low-confidence",
            "☠dead" if r["dead"] else "") if x)
        print(f"\n{r.get('host', '?')}  →  {r['state'].upper()}  ({live}) {flags}")
        print(f"  why      : {r['reason']}")
        if r["evidence"]:
            print(f"  matched  : {', '.join(str(e) for e in r['evidence'][:5])}")
        print(f"  signals  : {r['checked']}  ·  HTTP {r['http_status']}  ·  "
              f"{r['body_chars']}B html / {r['text_chars']} chars text")
        if r["note"]:
            print(f"  analyst  : {r['note']}")


if __name__ == "__main__":
    _main()
