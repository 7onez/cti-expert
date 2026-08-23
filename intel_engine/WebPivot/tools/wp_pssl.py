#!/usr/bin/env python3
"""wp_pssl — CIRCL **Passive SSL**: the historical certificate view, and the cert -> IP direction.

WHAT THIS ADDS THAT THE OTHER TLS SOURCES DON'T
------------------------------------------------
Everything else in WebPivot reads a certificate in the *present* or at *issuance*:

  live 443 handshake  what this host presents RIGHT NOW
  crt.sh / CT logs    what a CA logged WHEN IT WAS ISSUED (name overlap)
  Censys `cert`       the names on that leaf, as Censys last saw it

Passive SSL answers the retrospective question none of those can: **which IP addresses have
actually been observed serving this exact leaf certificate, over time.** That is the direction
that recovers an ORIGIN from behind a CDN — an operator who fronted a host with Cloudflare
usually served the same certificate on the origin first, and a passive sensor recorded it there.

It is the natural partner of passive DNS, which this repo already had:

    pDNS   historical  name -> IP
    pSSL   historical  cert -> IP        <- this module
    both agreeing on an address = a strong origin candidate

THE BASE RATE IS THE ENTIRE DIFFICULTY
---------------------------------------
A shared CDN or default-hosting certificate is served by *thousands* of unrelated addresses. A
single Cloudflare/DigiCert edge certificate measured while writing this came back on several
hundred IPs across a dozen countries and as many operators. Clustering on one of those would
manufacture an "estate" out of a CDN's customer list — the most convincing false positive this
toolkit is capable of producing. So the policy in `references/pssl.json` is a safety rail, not a
preference: past `max_ips_per_cert` a certificate is INFRASTRUCTURE and can never become a
same-operator edge, and a subject matching `shared_subject_markers` is rejected however few
addresses carry it. `clusterable` is computed here, once, and the ingest path trusts it.

COVERAGE IS PARTIAL — AN EMPTY ANSWER IS NOT A NEGATIVE FINDING
----------------------------------------------------------------
CIRCL's sensors are Europe-weighted. An empty answer for a Vietnamese, Chinese or small-ISP
address is routine and means *the corpus never saw it*. Every empty result therefore carries
`reporting.empty_note` and is reported as ABSENCE OF RECORD, never as "this address served no
certificate". With no credentials the layer does not run at all, which is a different statement
again (`no_creds_note`) — "never asked" and "asked, nothing there" must not collapse into one
line in an assessment.

Auth is the SAME CIRCL account as passive DNS (`PDNS_USERNAME` / `PDNS_PASSWORD`) — if pDNS works,
this works. Free with an account but rate-limited rather than credit-metered, so `request_budget`
bounds politeness and blast radius rather than money; every call is still logged through
`api_usage.record` (credits=0) so a run's third-party activity stays fully auditable.

CLI:
  python3 wp_pssl.py ip 1.2.3.4              # certificates seen on that address
  python3 wp_pssl.py cert <sha1>             # every IP observed serving that leaf
  python3 wp_pssl.py origin example.com      # cert-of-record -> IPs -> origin candidates
  python3 wp_pssl.py budget                  # offline: requests used this run
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import socket
import ssl
import sys
import urllib.error
import urllib.request

from wp_common import *  # noqa — DEFAULT_UA, _secret, uniq
from wp_refs import ref_path, load_ref  # noqa — reference DATA lives in references/*.json

try:
    import api_usage                      # licensed-API call ledger
except Exception:                         # noqa: BLE001
    api_usage = None

#: Minimal embedded default. load_ref falls back to this and WARNS if the JSON is missing or
#: malformed — a filter silently running on a stub is how a CDN certificate becomes a "cluster".
#: Deliberately a MINIMAL subset of the JSON, not a copy of it: everything omitted here is read
#: through `.get()` with a safe default, and `tests/test_references.py` asserts the loaded groups
#: are strictly richer than this stub — which is how a silent fall back to the stub is detected.
#: The one thing the stub must never do is get PERMISSIVE: its thresholds are the JSON's or
#: tighter, so a degraded run refuses more certificates, never fewer.
_PSSL_FALLBACK = {
    "endpoints": {"base_url": "https://www.circl.lu/v2pssl", "ip_query": "/query/{ip}",
                  "cert_query": "/cquery/{sha1}",
                  "ui_url": "https://www.circl.lu/services/passive-ssl/"},
    "clustering_policy": {"max_ips_per_cert": 12, "max_certs_per_ip": 60,
                          "shared_subject_markers": ["cloudflaressl.com", "cloudflare", "akamai",
                                                     "fastly", "cloudfront.net"]},
    "request_budget": {"max_requests_per_run": 40, "max_cert_lookups_per_ip": 6,
                       "max_ips_per_host": 8},
    "reporting": {
        "empty_note": "CIRCL passive SSL holds NO RECORD for this value — absence of record, "
                      "not evidence that the address served no certificate.",
        "no_creds_note": "Passive SSL did NOT run (no PDNS_USERNAME/PDNS_PASSWORD).",
        "shared_cert_note": "Recorded as INFRASTRUCTURE, not as an operator link.",
    },
}

_REFS = load_ref(ref_path(__file__, "pssl.json"), _PSSL_FALLBACK)

ENDPOINTS = _REFS["endpoints"]
POLICY = _REFS["clustering_policy"]
BUDGET = _REFS["request_budget"]
REPORTING = _REFS["reporting"]

#: Flipped off by `pivot_extract --no-pssl` / `--free-only`. The offline helpers stay usable.
ENABLED = True

_REQUESTS_THIS_RUN = 0


# --------------------------------------------------------------------------- config / budget
def pssl_configured() -> bool:
    """Same CIRCL credential pair as passive DNS — one account covers both services."""
    return bool(_secret("PDNS_USERNAME") and _secret("PDNS_PASSWORD"))


def _max_requests() -> int:
    env = os.environ.get("PSSL_MAX_REQUESTS_PER_RUN")
    if env and env.isdigit():
        return max(1, int(env))
    return int(BUDGET.get("max_requests_per_run", 40))


def budget_status() -> dict:
    """Requests issued this process vs the per-run cap. Offline and free."""
    cap = _max_requests()
    return {"requests_this_run": _REQUESTS_THIS_RUN, "max_requests_per_run": cap,
            "remaining_this_run": max(0, cap - _REQUESTS_THIS_RUN),
            "note": "CIRCL passive SSL is free with an account but RATE-LIMITED; this cap bounds "
                    "politeness and blast radius, not spend. Override with "
                    "PSSL_MAX_REQUESTS_PER_RUN."}


def _budget_block() -> str:
    if not ENABLED:
        return "passive SSL disabled for this run (--no-pssl / --free-only)"
    if not pssl_configured():
        return REPORTING.get("no_creds_note", "no CIRCL credentials")
    if _REQUESTS_THIS_RUN >= _max_requests():
        return (f"per-run passive-SSL request cap reached "
                f"({_REQUESTS_THIS_RUN}/{_max_requests()}) — raise PSSL_MAX_REQUESTS_PER_RUN")
    return ""


def _skipped(reason: str, **extra) -> dict:
    out = {"skipped": reason, "ui_url": ENDPOINTS.get("ui_url"), "source": "circl_pssl"}
    out.update(extra)
    return out


# --------------------------------------------------------------------------- HTTP
def _get(path: str, action: str, query: str):
    """One authenticated GET against the CIRCL API. Returns (payload|None, error|None)."""
    global _REQUESTS_THIS_RUN
    url = ENDPOINTS.get("base_url", "").rstrip("/") + path
    user, pwd = _secret("PDNS_USERNAME"), _secret("PDNS_PASSWORD")
    req = urllib.request.Request(url)
    req.add_header("Authorization",
                   "Basic " + base64.b64encode(f"{user}:{pwd}".encode()).decode())
    req.add_header("User-Agent", DEFAULT_UA)
    req.add_header("Accept", "application/json")
    _REQUESTS_THIS_RUN += 1
    try:
        with urllib.request.urlopen(req, timeout=int(ENDPOINTS.get("timeout_s", 25))) as r:
            payload = json.loads(r.read().decode("utf-8", "replace") or "{}")
        if api_usage:
            api_usage.record("circl_pssl", action, credits=0, query=query, ok=True)
        return payload, None
    except urllib.error.HTTPError as e:
        # 404 is CIRCL's "nothing on file", which is a RESULT, not a failure.
        err = f"HTTP {e.code}"
        if api_usage:
            api_usage.record("circl_pssl", action, credits=0, query=query,
                             ok=(e.code == 404))
        return ({} if e.code == 404 else None), err
    except Exception as e:  # noqa: BLE001
        if api_usage:
            api_usage.record("circl_pssl", action, credits=0, query=query, ok=False)
        return None, str(e)[:200]


# --------------------------------------------------------------------------- readers
def ip_certificates(ip: str) -> dict:
    """Every certificate CIRCL has observed on `ip`, with its subject.

    An address presenting more than `max_certs_per_ip` distinct certificates is shared hosting or
    a CDN edge: its certificates belong to its tenants and not to each other, so the result is
    marked `shared_host` and nothing on it may be clustered."""
    blocked = _budget_block()
    if blocked:
        return _skipped(blocked, ip=ip)
    payload, err = _get(ENDPOINTS["ip_query"].format(ip=ip), "ip_query", ip)
    if payload is None:
        return _skipped(f"passive-SSL query failed: {err}", ip=ip)

    entry = payload.get(ip) or {}
    certs = list(entry.get("certificates") or [])
    subjects = {k: (v or {}).get("values") or [] for k, v in (entry.get("subjects") or {}).items()}
    shared = len(certs) > int(POLICY.get("max_certs_per_ip", 60))
    return {
        "ip": ip, "source": "circl_pssl", "certificates": certs, "subjects": subjects,
        "count": len(certs),
        "shared_host": shared,
        "note": (REPORTING.get("empty_note") if not certs else
                 (REPORTING.get("shared_cert_note") if shared else "")),
    }


def _subject_is_shared(subject: str) -> str:
    s = (subject or "").lower()
    for marker in (POLICY.get("shared_subject_markers") or []):
        if str(marker).lower() in s:
            return str(marker)
    return ""


def cert_ips(sha1: str, subject: str = "") -> dict:
    """Every IP observed serving leaf certificate `sha1` — the origin-recovery direction.

    `clusterable` is decided HERE so no caller has to re-derive it: a certificate on more
    addresses than `max_ips_per_cert`, or whose subject names a CDN, is infrastructure."""
    blocked = _budget_block()
    if blocked:
        return _skipped(blocked, sha1=sha1)
    payload, err = _get(ENDPOINTS["cert_query"].format(sha1=sha1), "cert_query", sha1)
    if payload is None:
        return _skipped(f"passive-SSL cert query failed: {err}", sha1=sha1)

    ips = uniq([str(x) for x in (payload.get("seen") or [])])
    marker = _subject_is_shared(subject)
    over = len(ips) > int(POLICY.get("max_ips_per_cert", 12))
    clusterable = bool(ips) and not over and not marker \
        and len(ips) >= int(POLICY.get("min_ips_for_edge", 2))
    if marker:
        why = (f"subject names a shared CDN/provider ({marker}) — infrastructure, "
               f"never an operator link")
    elif over:
        why = (f"served by {len(ips)} addresses (> max_ips_per_cert "
               f"{POLICY.get('max_ips_per_cert')}) — {REPORTING.get('shared_cert_note','')}")
    elif not ips:
        why = REPORTING.get("empty_note", "")
    elif len(ips) < int(POLICY.get("min_ips_for_edge", 2)):
        why = ("seen on a single address — reported as an origin candidate, but one endpoint "
               "joins nothing to anything")
    else:
        why = "distinct leaf certificate on a small, non-CDN address set"
    return {"sha1": sha1, "subject": subject, "source": "circl_pssl", "ips": ips,
            "count": len(ips), "clusterable": clusterable, "why": why}


def live_cert_sha1(host: str, port: int = 443, timeout: int = 10) -> str:
    """SHA-1 of the leaf certificate `host` presents right now.

    CIRCL's passive-SSL index is sha1-keyed (Censys is sha256-keyed), so this is the bridge from
    a live handshake into the historical corpus. Free, and one connection to the target — under a
    passive-first posture, pass a sha1 you already hold instead of calling this."""
    import hashlib
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
        return hashlib.sha1(der).hexdigest() if der else ""
    except Exception:  # noqa: BLE001
        return ""


def origin_candidates(host: str, sha1: str = "", known_ips=None) -> dict:
    """The layer's headline question: which addresses have served this host's certificate?

    Any address returned that is NOT one of the host's current (CDN) addresses is an
    origin candidate — the operator's own server, seen before or alongside the front."""
    sha1 = sha1 or live_cert_sha1(host)
    if not sha1:
        return _skipped("could not obtain a leaf certificate sha1 for this host", host=host)
    res = cert_ips(sha1)
    if res.get("skipped"):
        return res
    known = {str(x) for x in (known_ips or [])}
    behind = [ip for ip in res["ips"] if ip not in known]
    return {"host": host, "sha1": sha1, "source": "circl_pssl",
            "all_ips": res["ips"], "origin_candidates": behind,
            "clusterable": res["clusterable"], "why": res["why"],
            "note": (REPORTING.get("empty_note") if not res["ips"] else
                     ("Addresses not in the host's current DNS answer are ORIGIN CANDIDATES — "
                      "verify each by fetching it directly with the Host header before treating "
                      "it as the operator's server." if behind else
                      "Every observed address is already the host's current front; no origin "
                      "recovered."))}


# --------------------------------------------------------------------------- pivots
def pssl_pivots(host: str, result: dict) -> list:
    """Turn a passive-SSL result into WebPivot pivot dicts.

    A cert the policy marked non-clusterable still produces a pivot — as `information`, so it is
    visible in the case without ever becoming a same-operator edge."""
    out = []
    if not result or result.get("skipped"):
        return out
    sha1 = result.get("sha1")
    ips = result.get("all_ips") or result.get("ips") or []
    if not sha1 or not ips:
        return out
    clusterable = bool(result.get("clusterable"))
    out.append({
        "kind": "pssl:cert_ip" if clusterable else "pssl:information",
        "value": sha1,
        "confidence": "medium" if clusterable else "information",
        "note": ("Historical certificate->IP mapping from CIRCL passive SSL. "
                 + str(result.get("why") or "")),
        "live_results": {"circl_pssl": {"ips": ips, "count": len(ips),
                                        "clusterable": clusterable}},
        "queries": [{"service": "CIRCL Passive SSL",
                     "query": ENDPOINTS.get("base_url", "") +
                              ENDPOINTS.get("cert_query", "").format(sha1=sha1)}],
    })
    for ip in (result.get("origin_candidates") or [])[:int(BUDGET.get("max_ips_per_host", 8))]:
        out.append({
            "kind": "pssl:origin_candidate", "value": ip, "confidence": "medium",
            "note": ("Served this host's leaf certificate but is not in its current DNS answer — "
                     "a candidate ORIGIN behind the front. Verify by requesting it directly with "
                     "the Host header set before treating it as the operator's server."),
            "queries": [{"service": "Shodan", "query": f"ip:{ip}"},
                        {"service": "FOFA", "query": f'ip="{ip}"'}],
        })
    return out


def banner_lines(free_only: bool = False) -> list:
    """One-line capability disclosure for the run banner."""
    if free_only:
        return ["  passive SSL   skipped (--free-only) — historical cert->IP never queried"]
    if not pssl_configured():
        return ["  passive SSL   NOT CONFIGURED — " + REPORTING.get("no_creds_note", "")]
    b = budget_status()
    return [f"  passive SSL   CIRCL, ready ({b['remaining_this_run']} requests left this run)"]


__all__ = ["pssl_configured", "ip_certificates", "cert_ips", "live_cert_sha1",
           "origin_candidates", "pssl_pivots", "budget_status", "banner_lines", "ENABLED"]


# --------------------------------------------------------------------------- CLI
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    sub = ap.add_subparsers(dest="mode", required=True)
    p_ip = sub.add_parser("ip", help="certificates observed on an IP")
    p_ip.add_argument("ip")
    p_c = sub.add_parser("cert", help="every IP observed serving a leaf cert (sha1)")
    p_c.add_argument("sha1")
    p_c.add_argument("--subject", default="", help="cert subject, for the CDN base-rate check")
    p_o = sub.add_parser("origin", help="host -> its cert -> the addresses that served it")
    p_o.add_argument("host")
    p_o.add_argument("--sha1", default="", help="use this leaf sha1 instead of a live handshake")
    p_o.add_argument("--known-ip", action="append", default=[],
                     help="current/front IP to exclude from origin candidates (repeatable)")
    sub.add_parser("budget", help="requests used this run (offline)")
    args = ap.parse_args()

    if args.mode == "ip":
        out = ip_certificates(args.ip)
    elif args.mode == "cert":
        out = cert_ips(args.sha1, subject=args.subject)
    elif args.mode == "origin":
        out = origin_candidates(args.host, sha1=args.sha1, known_ips=args.known_ip)
    else:
        out = budget_status()
    print(json.dumps(out, indent=2, ensure_ascii=False))
    if api_usage and args.mode != "budget":
        api_usage.print_session_summary()
    return 0


if __name__ == "__main__":
    sys.exit(main())
