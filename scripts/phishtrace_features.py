#!/usr/bin/env python3
# cti-expert skill — PhishTrace dynamic-feature characterization from a runtime trace.
"""phishtrace_features.py — characterize a phishing site from DYNAMIC (runtime) features:
the requests it made, the redirect chain, the form POST targets, cloaking behavior, and the
exfil endpoints observed while the page ran.

Grounded in: Ridwan Arefin Islam (McGill), Mohammad Mannan (Concordia) — *"PhishTrace:
Characterizing Phishing Websites from Dynamic Features"*, APWG eCrime 2026. Static HTML misses
pages that look inert or cloaked until they run; the runtime trace is the discriminator.

The feature extraction + verdict are a PURE, deterministic function over a trace dict — offline,
CI-testable with a synthetic/recorded trace. Capturing the trace live is the renderer's job
(`render_confirm.py` / the renderer path); this module consumes what the renderer produced.

Trace schema (all keys optional; feed what the renderer captured):
  {
    "landing_url": "https://host/…", "final_url": "https://host2/…",
    "requests":  [{"url":…, "method":"GET|POST", "status":200, "type":"xhr|script|document|…"}],
    "redirects": [{"from":…, "to":…, "status":302}],
    "form_posts":[{"action":"https://exfil/…", "fields":["username","password",…]}],
    "timing_ms": 1234, "bot_wall": false, "cloak": false, "dom_text_len": 4200
  }

ATTRIBUTION SAFETY: exfil endpoints are OFF-ORIGIN POST targets only — a page posting its own
credentials to its own origin is the normal case and is never emitted as an IOC. Off-origin
hosts are pivot leads, NOT same-operator attribution, and well-known platform/CDN hosts are
split out as base-rate noise. An empty/thin trace on a statically-suspicious page is a CLOAKING
signal, never a "benign" verdict.

Usage:
  cat trace.json | uv run phishtrace_features.py - --origin site.com
  uv run phishtrace_features.py trace.json --json -o features.json
  uv run phishtrace_features.py trace.json --static-suspicious   # caller flagged static risk

Exit codes: 0 = ran, 4 = bad input.
"""
# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
import re
import sys
import json
import argparse

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

# Credential field names matched as WHOLE tokens (not substrings) — "shipping" must not match
# "pin", "discard" must not match "card", "accountant" must not match "account".
_CRED_TOKENS = {
    "password", "passwd", "pass", "passcode", "otp", "mfa", "2fa", "cvv", "cvc",
    "ssn", "pin", "seed", "mnemonic", "secret", "iban", "routing", "card",
    "cardnumber", "ccnumber", "account", "accountno", "accountnumber",
}
# Multi-label public suffixes so eTLD+1 grouping doesn't collapse evil.co.uk == hsbc.co.uk.
_MULTI_SUFFIX = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "co.jp", "or.jp", "ne.jp", "com.br",
    "com.au", "net.au", "org.au", "co.za", "com.cn", "com.hk", "com.tw", "com.sg",
    "com.mx", "com.tr", "co.kr", "co.nz", "co.in", "com.ar", "com.pl", "com.vn", "com.ph",
}
# Well-known platform / CDN / analytics hosts — off-origin but base-rate noise, not IOCs.
_PLATFORM_HOSTS = (
    "google.com", "googleapis.com", "gstatic.com", "google-analytics.com", "googletagmanager.com",
    "doubleclick.net", "gomodules", "cloudflare.com", "cloudflareinsights.com", "jsdelivr.net",
    "cdnjs.cloudflare.com", "unpkg.com", "fontawesome.com", "bootstrapcdn.com", "jquery.com",
    "facebook.net", "fbcdn.net", "cdn.shopify.com", "wp.com", "gravatar.com", "recaptcha.net",
    "cloudfront.net", "akamaihd.net", "fastly.net", "azureedge.net",
)


def _dicts(v):
    """Return only the dict items of a value that should be a list (hostile/malformed-safe)."""
    return [x for x in v if isinstance(x, dict)] if isinstance(v, list) else []


def _fields(f):
    raw = f.get("fields")
    if isinstance(raw, (list, tuple)):
        return [str(x) for x in raw]
    if isinstance(raw, str):
        return [raw]
    return []


def _is_cred_field(name):
    toks = set(re.split(r"[^a-z0-9]+", str(name).lower()))
    return bool(_CRED_TOKENS & toks)


def _host(url):
    m = re.match(r"[a-z]+://([^/:]+)", (url or "").strip(), re.I)
    return m.group(1).lower() if m else ""


def _reg_domain(host):
    """eTLD+1 (static public-suffix-aware). Fails toward treating hosts as DIFFERENT sites when
    the two-label reduction lands on a known multi-label public suffix."""
    parts = [p for p in (host or "").split(".") if p]
    if len(parts) >= 3 and ".".join(parts[-2:]) in _MULTI_SUFFIX:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else (parts[0] if parts else "")


def _is_platform(host):
    return any(host == p or host.endswith("." + p) for p in _PLATFORM_HOSTS)


def analyze_trace(trace, origin=None, static_suspicious=False):
    """Pure, deterministic characterization of a runtime trace."""
    trace = trace if isinstance(trace, dict) else {}
    landing = trace.get("landing_url") or ""
    final = trace.get("final_url") or landing
    # normalize origin: accept a bare host OR a URL (a URL is the obvious mistake).
    origin_host = (_host(origin) or (origin or "").strip().strip("/").lower()
                   or _host(landing) or _host(final))
    origin_reg = _reg_domain(origin_host)

    requests = _dicts(trace.get("requests"))
    redirects = _dicts(trace.get("redirects"))
    form_posts = _dicts(trace.get("form_posts"))

    # third-party hosts (different registrable domain than the page), split by base-rate.
    third_party, platform_hosts = [], []
    for r in requests:
        h = _host(r.get("url"))
        if not h or _reg_domain(h) == origin_reg:
            continue
        if _is_platform(h):
            if h not in platform_hosts:
                platform_hosts.append(h)
        elif h not in third_party:
            third_party.append(h)

    # exfil endpoints: OFF-ORIGIN POST targets only (a same-origin credential form is normal).
    exfil = []
    cred_form_offorigin = False
    cred_form_onorigin = False
    for f in form_posts:
        act = f.get("action") or ""
        has_cred = any(_is_cred_field(x) for x in _fields(f))
        h = _host(act)
        off = bool(h) and _reg_domain(h) != origin_reg
        if act and off:
            exfil.append(act)
        if has_cred:
            if off:
                cred_form_offorigin = True
            else:
                cred_form_onorigin = True
    for r in requests:
        if (r.get("method") or "").upper() == "POST":
            h = _host(r.get("url"))
            if h and _reg_domain(h) != origin_reg and not _is_platform(h) and r.get("url") not in exfil:
                exfil.append(r.get("url"))

    redirect_len = len(redirects)
    cross_origin_redirect = bool(landing and final and _reg_domain(_host(landing)) != _reg_domain(_host(final)))
    bot_wall = bool(trace.get("bot_wall"))
    cloak_flag = bool(trace.get("cloak"))
    dom_len = trace.get("dom_text_len")
    empty_dom = isinstance(dom_len, (int, float)) and not isinstance(dom_len, bool) and dom_len < 40

    features = {
        "redirect_chain_len": redirect_len,
        "cross_origin_redirect": cross_origin_redirect,
        "third_party_host_count": len(third_party),
        "platform_host_count": len(platform_hosts),
        "credential_form_offorigin": cred_form_offorigin,
        "credential_form_onorigin": cred_form_onorigin,
        "exfil_endpoint_count": len(exfil),
        "bot_wall": bot_wall,
        "cloak_flag": cloak_flag,
        "empty_dom": empty_dom,
        "timing_ms": trace.get("timing_ms"),
    }

    # ---- verdict -----------------------------------------------------------
    trace_is_thin = (not requests and not form_posts) or empty_dom or bot_wall or cloak_flag
    reasons = []
    if cred_form_offorigin:
        reasons.append("credential form posts off-origin")
    if exfil:
        reasons.append(f"{len(exfil)} off-origin exfil endpoint(s)")
    if cross_origin_redirect:
        reasons.append("cross-origin redirect chain")

    if cred_form_offorigin or (exfil and cross_origin_redirect):
        verdict = "phishing_likely"
    elif trace_is_thin and (static_suspicious or cloak_flag or bot_wall):
        verdict = "cloaked"
        reasons.append("thin/cloaked runtime trace on a flagged page — not benign")
    elif exfil or cross_origin_redirect:
        verdict = "suspicious"
    elif trace_is_thin:
        verdict = "inconclusive"
        reasons.append("thin trace with no static-risk flag — collect a fuller render")
    elif static_suspicious:
        # a rich but innocuous trace does NOT clear a static finding (decoy-page scenario)
        verdict = "inconclusive"
        reasons.append("no dynamic signals, but static risk was flagged — dynamic silence "
                       "does not clear a static finding")
    else:
        verdict = "benign"

    rationale = ("; ".join(reasons) + ".") if reasons else "No dynamic phishing signals in the trace."

    return {
        "verdict": verdict,
        "features": features,
        "iocs": {"exfil_endpoints": exfil, "third_party_hosts": third_party,
                 "platform_hosts_excluded": platform_hosts},
        "rationale": rationale,
        "note": "Exfil endpoints are OFF-ORIGIN POST targets (pivot-lead IOCs, not same-operator "
                "attribution); a same-origin credential form is the normal case and is not an IOC. "
                "Well-known platform/CDN hosts are excluded as base-rate noise. A thin/empty trace "
                "on a suspicious page is a cloaking signal, never 'benign'.",
    }


def _fmt_text(r):
    f = r["features"]
    out = [f"Verdict : {r['verdict'].upper()}", "", r["rationale"], "",
           "Features:",
           f"  redirects={f['redirect_chain_len']}  cross_origin_redirect={f['cross_origin_redirect']}",
           f"  third_party_hosts={f['third_party_host_count']}  platform_hosts={f['platform_host_count']}"
           f"  exfil_endpoints={f['exfil_endpoint_count']}",
           f"  credential_form_offorigin={f['credential_form_offorigin']}  "
           f"credential_form_onorigin={f['credential_form_onorigin']}",
           f"  bot_wall={f['bot_wall']}  cloak={f['cloak_flag']}  empty_dom={f['empty_dom']}"]
    if r["iocs"]["exfil_endpoints"]:
        out += ["", "Exfil endpoints (off-origin IOC):"] + [f"  {u}" for u in r["iocs"]["exfil_endpoints"]]
    if r["iocs"]["third_party_hosts"]:
        out += ["", "Third-party hosts: " + ", ".join(r["iocs"]["third_party_hosts"])]
    if r["iocs"]["platform_hosts_excluded"]:
        out += ["Platform hosts (excluded as noise): " + ", ".join(r["iocs"]["platform_hosts_excluded"])]
    out += ["", "NOTE: " + r["note"]]
    return "\n".join(out)


def _cli(argv):
    ap = argparse.ArgumentParser(
        description="Characterize a phishing site from a runtime trace (dynamic features, offline).")
    ap.add_argument("input", nargs="?", default="-", help="trace JSON file, or '-' for stdin")
    ap.add_argument("--origin", help="page origin host or URL (else inferred from landing/final)")
    ap.add_argument("--static-suspicious", action="store_true", dest="static_suspicious",
                    help="caller's static analysis already flagged this page (affects cloaked verdict)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("-o", "--out")
    args = ap.parse_args(argv)

    try:
        raw = sys.stdin.read() if args.input == "-" else open(args.input, encoding="utf-8").read()
        trace = json.loads(raw)
        if not isinstance(trace, dict):
            raise ValueError("trace must be a JSON object")
    except (OSError, ValueError, json.JSONDecodeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 4

    r = analyze_trace(trace, origin=args.origin, static_suspicious=args.static_suspicious)
    body = json.dumps(r, indent=2, ensure_ascii=False) if args.json else _fmt_text(r)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(body + "\n")
        print(f"wrote {args.out}", file=sys.stderr)
    else:
        print(body)
    return 0


if __name__ == "__main__":
    sys.exit(_cli(sys.argv[1:]))
