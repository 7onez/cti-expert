#!/usr/bin/env python3
# cti-expert skill — Lunar Domain Exposure enrichment (canonical fetch).
# Wraps the free, keyless Lunar Domain Exposure API into a single poll-aware call so
# the endpoint string lives in exactly one place (no per-file curl drift).
"""lunar_domain_exposure.py — org-level infostealer + data-breach exposure for a domain.

Source: https://api.lunarcyber.com/domain-exposure?domain=<domain>  (free, no API token).

Why a script and not a bare curl: the API is ASYNCHRONOUS. A cold/unseen domain returns
HTTP 200 with {"status":"GENERATING_REPORT","report":null}; the report only populates on a
later request. This tool polls status until REPORT_READY (bounded) and then normalizes the
payload, so the async contract is handled once and correctly.

GRADING (carry into the case): a Lunar hit is EXPOSURE evidence, NOT a same-operator /
clusterable signal. Two domains in one combolist share victims, not an operator — identical
to the IntelX grading rule. Findings feed exposure/trend, never attribution edges.

What it returns (verbatim report keys): summary, exposure_subject_breakdown, monthly_timeline,
event_family_breakdown, infostealer_summary, malware_family_breakdown, os_breakdown,
antivirus_breakdown, data_breach_summary, data_breach_source_type_breakdown,
service_classification_breakdown, top_login_urls, country_breakdown.

Usage:
  uv run lunar_domain_exposure.py stryker.com                 # normalized analyst summary
  uv run lunar_domain_exposure.py stryker.com --json          # full report JSON
  uv run lunar_domain_exposure.py stryker.com --raw           # full API envelope (with status)
  uv run lunar_domain_exposure.py stryker.com -o out.json --json
  uv run lunar_domain_exposure.py stryker.com --max-wait 120 --interval 8

Exit codes: 0 = REPORT_READY (data or empty), 2 = still GENERATING_REPORT after --max-wait,
3 = transport/HTTP/JSON error, 4 = bad input.
"""
# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
import sys
import re
import json
import time
import argparse
import urllib.parse
import urllib.request
import urllib.error

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

# --- egress proxy / rotation: route outbound HTTP through the /proxy pool ----
def _install_cti_proxy():
    import os as _o, sys as _s
    _b = _o.path.dirname(_o.path.abspath(__file__))
    for _ in range(6):
        _c = _o.path.join(_b, "proxy", "cti_proxy.py")
        if _o.path.isfile(_c):
            _s.path.insert(0, _o.path.dirname(_c))
            try:
                import cti_proxy
                cti_proxy.install()
            except Exception:
                pass
            return
        _p = _o.path.dirname(_b)
        if _p == _b:
            return
        _b = _p
_install_cti_proxy()

API_BASE = "https://api.lunarcyber.com/domain-exposure"  # canonical — the ONLY place this lives
USER_AGENT = "cti-expert/lunar-domain-exposure (+https://github.com/7onez/cti-expert)"

# Login-URL service classes that are attack-surface leads, not just exposure counts.
ATTACK_SURFACE_HINTS = (
    "vpn", "citrix", "anyconnect", "pulse", "fortinet", "globalprotect",
    "okta", "entra", "adfs", "sso", "rdweb", "owa", "vmware", "sonicwall",
)


def _norm_domain(raw: str) -> str:
    d = (raw or "").strip().lower()
    d = re.sub(r"^[a-z]+://", "", d)          # strip scheme
    d = d.split("/")[0].split("?")[0]          # strip path/query
    d = d.split("@")[-1]                        # strip user@ if an email slipped in
    d = d.rstrip(".")
    return d


def _is_domain(d: str) -> bool:
    return bool(re.fullmatch(r"(?=.{1,253}$)([a-z0-9](-?[a-z0-9])*\.)+[a-z]{2,}", d))


def fetch(domain: str, req_timeout: int) -> dict:
    url = API_BASE + "?" + urllib.parse.urlencode({"domain": domain})
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=req_timeout) as resp:
        body = resp.read().decode("utf-8", "replace")
    return json.loads(body)


RETRYABLE_HTTP = {429, 500, 502, 503, 504}
TRANSIENT_ERRORS = (urllib.error.URLError, TimeoutError, ConnectionError, json.JSONDecodeError)


def _reason(err) -> str:
    return str(getattr(err, "reason", None) or err.__class__.__name__)


def _retry_after(err, default: int) -> int:
    """Honor an integer Retry-After header (429/503); else fall back to default."""
    try:
        ra = err.headers.get("Retry-After")
        if ra and ra.strip().isdigit():
            return max(1, int(ra.strip()))
    except Exception:
        pass
    return default


def _backoff(domain: str, attempt: int, deadline: float, want: float, reason: str) -> bool:
    """Sleep before a retry, never past the deadline. False => no time left, give up."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return False
    sleep = min(max(1.0, want), remaining)
    print(
        f"[lunar] {domain}: transient error ({reason}) on attempt {attempt}; "
        f"retry in {sleep:.0f}s (\u2264{remaining:.0f}s left)",
        file=sys.stderr,
    )
    time.sleep(sleep)
    return True


def poll(domain: str, max_wait: int, interval: int, req_timeout: int) -> dict:
    deadline = time.monotonic() + max_wait
    attempt = 0
    while True:
        attempt += 1
        try:
            env = fetch(domain, req_timeout)
        except urllib.error.HTTPError as e:
            # 4xx (except 429) is a hard error — surface it. 429/5xx are transient.
            if e.code not in RETRYABLE_HTTP:
                raise
            if not _backoff(domain, attempt, deadline, _retry_after(e, interval), f"HTTP {e.code}"):
                raise
            continue
        except TRANSIENT_ERRORS as e:  # URLError covers HTTPError, so this is 2nd
            if not _backoff(domain, attempt, deadline, interval, _reason(e)):
                raise
            continue
        status = str(env.get("status", "")).upper()
        if status == "REPORT_READY":
            return env
        if status != "GENERATING_REPORT":
            # Unknown terminal status — surface it, do not loop forever.
            return env
        if time.monotonic() >= deadline:
            return env  # caller detects still-generating and exits 2
        remaining = deadline - time.monotonic()
        sleep = min(interval, max(1.0, remaining))
        print(
            f"[lunar] {domain}: GENERATING_REPORT (attempt {attempt}); "
            f"retry in {sleep:.0f}s (\u2264{remaining:.0f}s left)",
            file=sys.stderr,
        )
        time.sleep(sleep)


def _mean(vals):
    nums = [v for v in vals if isinstance(v, (int, float))]
    return sum(nums) / len(nums) if nums else 0.0


def _monthly_trend(timeline):
    # Half-window means, not endpoints: the series is spiky, so first-vs-last month
    # inverts the verdict on noisy data. Compare mean(earliest half) vs mean(latest half).
    if not timeline or len(timeline) < 2:
        return "insufficient-data"
    events = [m.get("total_events", 0) for m in timeline]
    half = len(events) // 2
    first = _mean(events[:half])
    last = _mean(events[-half:])
    if first == 0:
        return "rising" if last > 0 else "flat"  # emergence: newly appearing in exposure data
    if last > first * 1.15:
        return "rising"
    if last < first * 0.85:
        return "declining"
    return "flat"


def summarize(report: dict) -> dict:
    s = report.get("summary", {}) or {}
    infostealer = report.get("infostealer_summary", {}) or {}
    fams = report.get("malware_family_breakdown", []) or []
    services = report.get("service_classification_breakdown", []) or []
    login_urls = report.get("top_login_urls", []) or []

    attack_surface = [
        svc for svc in services
        if any(h in str(svc.get("service", "")).lower() for h in ATTACK_SURFACE_HINTS)
    ]
    sso_login_urls = [
        u for u in login_urls
        if any(h in str(u.get("url", "")).lower() for h in ("adfs", "sts.", "sso", "login", "signin", "okta"))
    ]

    return {
        "domain": report.get("domain"),
        "period": report.get("period"),
        "generated_at": report.get("generated_at"),
        "grading": "EXPOSURE — not clusterable / not same-operator (victims, not operator)",
        "summary": {
            "total_events": s.get("total_events"),
            "infostealer_events": s.get("infostealer_events"),
            "data_breach_events": s.get("data_breach_events"),
            "employee_events": s.get("employee_events"),
            "client_events": s.get("client_events"),
            "first_seen": s.get("first_seen"),
            "last_seen": s.get("last_seen"),
        },
        "infostealer": {
            "total_events": infostealer.get("total_events"),
            "malware_families_observed": infostealer.get("malware_families_observed"),
        },
        "top_malware_families": [
            {
                "family": f.get("family"),
                "events": f.get("events"),
                "share_pct": f.get("share_of_infostealer_events_percent"),
                "first_seen": f.get("first_seen"),
                "last_seen": f.get("last_seen"),
            }
            for f in fams[:5]
        ],
        "monthly_trend": _monthly_trend(report.get("monthly_timeline")),
        "attack_surface_leads": [
            {"service": svc.get("service"), "events": svc.get("events")} for svc in attack_surface
        ],
        "sso_login_urls": [
            {"url": u.get("url"), "events": u.get("events")} for u in sso_login_urls[:10]
        ],
        "next_pivots": _pivots(attack_surface, sso_login_urls),
    }


def _pivots(attack_surface, sso_login_urls):
    tips = []
    if attack_surface:
        tips.append("Exposed VPN/SSO service classes present \u2192 feed to /msftrecon + edge-appliance recon.")
    if sso_login_urls:
        tips.append("SSO/ADFS login URLs surfaced \u2192 register as attack_surface leads (auth endpoints).")
    tips.append("Corroborate malware families/OS against /stealer-log and HudsonRock domain results.")
    tips.append("Feed monthly_timeline into risk-trend-tracker / exposure-model.")
    return tips


def main() -> int:
    ap = argparse.ArgumentParser(description="Lunar Domain Exposure enrichment (free, keyless, poll-aware).")
    ap.add_argument("domain", help="apex domain, e.g. example.com")
    ap.add_argument("--json", action="store_true", help="print full report JSON (report block only)")
    ap.add_argument("--raw", action="store_true", help="print full API envelope incl. status")
    ap.add_argument("-o", "--out", help="write output to file instead of stdout")
    ap.add_argument("--max-wait", type=int, default=90, help="max seconds to poll GENERATING_REPORT (default 90)")
    ap.add_argument("--interval", type=int, default=6, help="seconds between polls (default 6)")
    ap.add_argument("--timeout", type=int, default=1800, help="per-request timeout seconds (default 1800 = 30-min ceiling)")
    args = ap.parse_args()

    domain = _norm_domain(args.domain)
    if not _is_domain(domain):
        print(f"error: not a valid domain: {args.domain!r}", file=sys.stderr)
        return 4

    try:
        env = poll(domain, args.max_wait, args.interval, args.timeout)
    except urllib.error.HTTPError as e:
        print(f"error: HTTP {e.code} from Lunar API for {domain}", file=sys.stderr)
        return 3
    except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
        print(f"error: transport failure persisted past --max-wait for {domain}: {_reason(e)}", file=sys.stderr)
        return 3
    except json.JSONDecodeError:
        print(f"error: non-JSON response from Lunar API for {domain}", file=sys.stderr)
        return 3

    status = str(env.get("status", "")).upper()
    report = env.get("report")

    if status == "GENERATING_REPORT" or report is None:
        print(
            f"[lunar] {domain}: report still GENERATING after {args.max_wait}s "
            f"(status={status or 'unknown'}). Re-run later or raise --max-wait. "
            f"Note: unseen/clean domains can stay in this state \u2014 absence \u2260 clean.",
            file=sys.stderr,
        )
        if status != "GENERATING_REPORT":
            print(f"[lunar] terminal status was {status!r}", file=sys.stderr)
        return 2

    if args.raw:
        payload = env
    elif args.json:
        payload = report
    else:
        payload = summarize(report)

    text = json.dumps(payload, indent=2, ensure_ascii=False)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        print(f"[lunar] wrote {args.out}", file=sys.stderr)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
