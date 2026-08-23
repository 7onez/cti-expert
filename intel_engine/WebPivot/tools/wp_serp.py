#!/usr/bin/env python3
"""wp_serp — the ADVERTISING layer: who PAID to send traffic here, and what the page shows them.

WHY THIS LAYER EXISTS
---------------------
Every other pivot in WebPivot reads something the operator PROVISIONED — a host, a certificate, a
registrant record, a favicon. This one reads something they BOUGHT, and that turns out to be a
different and better class of evidence, for two reasons.

**1. A Google advertiser is a verified, paying identity.** Google will not take an operator's money
without identity verification, and it publishes the outcome in the Ads Transparency Center: a stable
`advertiser_id`, the legal name the ads are "funded by", and every creative that account ran with the
domain each one pointed at. So a domain that advertises carries an artifact WHOIS privacy cannot
hide and a re-skin cannot change — nobody re-verifies a fresh ad account for each throwaway host,
because verification is slow and the money is already in the old one. Reverse the advertiser_id and
you get the operator's other landing domains, including the ones not yet reported anywhere.

**2. A page that buys traffic often only shows its real self to that traffic.** This is the half the
rest of the toolkit is blind to. A kit that pays for clicks gates on the arrival: present a `gclid`
and the campaign's `utm` set and you get the scam; arrive without them — direct, from a crawler,
from Google's own reviewer on an unexpected referrer — and you get a decoy. A blank page. A
"coming soon". A redirect to the real brand. Collect the bare domain and every artifact in the
result is the DECOY's: the favicon, the DOM fingerprint, the wallets that are not there. The run
does not fail, which is the danger — it succeeds, quietly, on the wrong page, and "no scam content
found" gets written down as a finding.

So this layer does three things, and the third is free:

  - **finds the advertiser** for a domain (SerpApi -> Ads Transparency Center), and reverses an
    advertiser_id back to every domain that account advertised;
  - **names the payer precisely**: opening a creative returns `ad_funded_by`, the LEGAL ENTITY
    Google verified ("<Brand> B.V." rather than "<Brand>"), plus the per-region breakdown of which
    markets the ad ran in and when each last ran — dated target-selection evidence. When the
    creative also carries its destination link, that link's `utm`/`gclid` set is the operator's own
    cloaking key; the archive often stores a text ad as a rendered image with no URL, so treat
    getting it as a bonus rather than the plan;
  - **probes for click-keyed cloaking**: fetch the page as a plain visitor, fetch it again as a paid
    click, and compare. That costs no API credit at all and works with no key.

BASE RATES, OR THIS LAYER MANUFACTURES CLUSTERS
-----------------------------------------------
`utm_source=google` is on a hundred million URLs. A `gclid` proves a click was paid for; it says
nothing about WHO, and its value is unique per click, so clustering on one would join a case to
itself and nothing else. Advertiser identity is strong but not automatic either: a media buyer or
affiliate network advertises for many unrelated clients from ONE account, so past
`clustering_policy.agency_domain_threshold` distinct target domains an advertiser is treated as a
traffic broker and its co-advertised domains drop to leads. All of that is DATA
(`references/serpapi.json`) — when an advertising artifact joins two unrelated cases, extend the
JSON, not this file.

The cloaking verdict has its own discipline. Ordinary pages differ between any two fetches (session
ids, CSRF tokens, rotating banners), and calling that "cloaking" would put a fabricated fraud
indicator into an assessment. So a difference is only attributed to the CLICK when a control fetch
of the plain view, taken AFTER the click view, still matches the first plain view — otherwise the
page is simply unstable and the probe says `inconclusive_unstable` instead of guessing.

WHAT IS OWNED ELSEWHERE
-----------------------
`utm_*` and affiliate/referral codes already become `affiliate:<param>` pivots in
`wp_pivots.build_affiliate_pivots` (data: `pivot_tables.json:affiliate_params`). This module does
NOT re-emit those. It owns the advertising-specific names that live nowhere else — the click ids,
and the Google ValueTrack macros (`campaignid`, `adgroupid`, `creative`) whose values are object ids
*inside one Google Ads account* and therefore identify the account itself.

KEYLESS ≈ 55%
-------------
With no `SERPAPI_KEY` the whole cloaking probe still runs (it is just HTTP to the target), every
parameter is still classified, and the Ads Transparency Center *web* address for the domain and for
any advertiser id is still composed — free to open, same data. What is lost is execution: the
advertiser is never resolved automatically, the reverse advertiser_id -> other domains never runs,
and the creative's destination link — the operator's real campaign tagging, the best possible
unlock key — is never read. Say so; do not report an unqueried archive as "does not advertise".

CLI:
  python3 wp_serp.py advertiser example.com [--region VN]     # who advertises this domain
  python3 wp_serp.py creatives AR1234567890 [--details 3]     # reverse: that account's other domains
  python3 wp_serp.py serp "brand keyword" [--gl vn]           # who is BUYING this keyword right now
  python3 wp_serp.py params 'https://host.example/?gclid=..&utm_campaign=x'   # offline classify
  python3 wp_serp.py cloak https://host.example/ [--ad-params '...']          # free cloaking probe
  python3 wp_serp.py budget                                   # offline ledger + live quota
  python3 wp_serp.py keycheck
"""
import argparse
import datetime
import difflib
import hashlib
import json
import os
import re
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request

from wp_common import _secret, DEFAULT_UA, uniq, strip_www  # noqa
from wp_refs import ref_path, load_ref  # noqa — reference DATA lives in references/*.json

try:
    import api_usage                      # licensed-API credit ledger
except Exception:                         # pragma: no cover - optional
    api_usage = None

try:
    from wp_net import fetch as _wp_fetch  # the shared browser-profile fetcher
except Exception:                          # pragma: no cover - standalone import
    _wp_fetch = None


# --- reference DATA (RULE 3). The fallback is the minimum that keeps this layer HONEST if the JSON
#     goes missing: without the generic-value list a utm_campaign of "google" would become an
#     operator fingerprint, and without the probe thresholds every dynamic page would read as
#     cloaking. So the fallback carries the base-rate controls, not just the plumbing. load_ref
#     warns loudly when it fires.
_SERP_FALLBACK = {
    # Deliberately the three that keep the layer USABLE if the JSON goes missing: the API address,
    # and the two free web addresses a keyless run hands the analyst instead. The rest degrade to a
    # missing link, not to a broken layer.
    "endpoints": {
        "search": "https://serpapi.com/search",
        "ui_transparency_domain": "https://adstransparency.google.com/?region={region}&domain={domain}",
        "ui_transparency_advertiser": "https://adstransparency.google.com/advertiser/{advertiser_id}?region={region}",
    },
    "engines": {"ads_transparency": "google_ads_transparency_center",
                "ad_details": "google_ads_transparency_center_ad_details",
                "google": "google"},
    "ad_parameters": {
        "gclid": {"class": "click_id", "pivotable": False, "cloak_key": True},
        "gbraid": {"class": "click_id", "pivotable": False, "cloak_key": True},
        "wbraid": {"class": "click_id", "pivotable": False, "cloak_key": True},
        "msclkid": {"class": "click_id", "pivotable": False, "cloak_key": True},
        "fbclid": {"class": "click_id", "pivotable": False, "cloak_key": True},
        "gad_source": {"class": "valuetrack", "pivotable": False, "cloak_key": True},
        "utm_source": {"class": "campaign", "pivotable": False, "cloak_key": True},
        "utm_medium": {"class": "campaign", "pivotable": False, "cloak_key": True},
        "utm_campaign": {"class": "campaign", "pivotable": True, "cloak_key": True},
        "utm_content": {"class": "campaign", "pivotable": True, "cloak_key": False},
        "utm_term": {"class": "campaign", "pivotable": True, "cloak_key": False},
        "campaignid": {"class": "valuetrack", "pivotable": True, "cloak_key": False},
        "adgroupid": {"class": "valuetrack", "pivotable": True, "cloak_key": False},
        "creative": {"class": "valuetrack", "pivotable": True, "cloak_key": False},
    },
    "generic_values": ["google", "facebook", "cpc", "ppc", "paid", "organic", "search", "display",
                       "social", "email", "direct", "none", "(not set)", "banner", "brand"],
    "probe_params": {"gclid": "EAIaIQobChMIsynthetic0probe0value", "gad_source": "1",
                     "utm_source": "google", "utm_medium": "cpc"},
    "probe_headers": {"Referer": "https://www.google.com/", "Sec-Fetch-Site": "cross-site",
                      "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"},
    "challenge_markers": ["__challenge", "challenge-platform", "cf-browser-verification",
                          "just a moment", "checking your browser", "datadome", "hcaptcha",
                          "g-recaptcha", "_incapsula_resource", "perimeterx"],
    "cloaking_probe": {"timeout_seconds": 20, "max_body_bytes": 3000000, "min_similarity": 0.9,
                       "length_ratio_band": 0.75, "control_refetch": True,
                       "title_change_is_divergence": True, "host_change_is_divergence": True,
                       "min_body_bytes_for_verdict": 200},
    "clustering_policy": {
        "advertiser_id": {"relation": "same_payer", "confidence": "high"},
        "ad_funded_by": {"relation": "same_payer", "confidence": "high"},
        "campaign_object_id": {"relation": "same_payer", "confidence": "medium"},
        "utm_campaign": {"relation": "same_campaign", "confidence": "medium"},
        "serp_ad_coappearance": {"relation": "none", "confidence": "informational"},
        "cloaking_observed": {"relation": "none", "confidence": "high"},
        "agency_domain_threshold": 12,
    },
    "regions": {"anywhere": {"api": None, "ui": "anywhere"}, "US": {"api": "2840", "ui": "US"},
                "VN": {"api": "2704", "ui": "VN"}, "default": "anywhere"},
    "credit_costs": {"search": 1, "ad_details": 1, "account": 0, "free_monthly_searches": 100},
    # Conservative on purpose: a missing data file must not silently unlock a bigger spend.
    "search_budget": {"monthly_searches": 100, "max_searches_per_run": 8,
                      "max_creative_details_per_run": 3, "block_when_exhausted": True,
                      "warn_at_remaining": 25},
    "result_limits": {"max_creatives": 40, "max_creative_ids_kept": 5,
                      "max_target_domains": 25, "max_serp_ads": 12},
}
# load_ref already unwraps a group's `values` / `entries`, so every constant below is the flat
# Python value — a group must therefore never carry scalars ALONGSIDE an `entries` block, or the
# loader drops them. `clustering_policy` and `regions` are written without the wrapper for exactly
# that reason (their threshold / default would otherwise vanish silently).
_REFS = load_ref(ref_path(__file__, "serpapi.json"), _SERP_FALLBACK)
ENDPOINTS = _REFS["endpoints"]
ENGINES = _REFS["engines"]
AD_PARAMETERS = _REFS["ad_parameters"]
GENERIC_VALUES = frozenset(str(v).strip().lower() for v in _REFS["generic_values"])
PROBE_PARAMS = _REFS["probe_params"]
PROBE_HEADERS = _REFS["probe_headers"]
CHALLENGE_MARKERS = tuple(str(v).lower() for v in _REFS["challenge_markers"])
CLOAKING_PROBE = _REFS["cloaking_probe"]
CLUSTERING_POLICY = _REFS["clustering_policy"]
REGIONS = _REFS["regions"]
CREDIT_COSTS = _REFS["credit_costs"]
SEARCH_BUDGET = _REFS["search_budget"]
RESULT_LIMITS = _REFS["result_limits"]

# Derived sets — computed from the ONE parameter table so a name can never be classified two ways.
CLICK_ID_PARAMS = frozenset(k.lower() for k, v in AD_PARAMETERS.items()
                            if (v or {}).get("class") == "click_id")
CLOAK_KEY_PARAMS = frozenset(k.lower() for k, v in AD_PARAMETERS.items() if (v or {}).get("cloak_key"))
PIVOTABLE_PARAMS = frozenset(k.lower() for k, v in AD_PARAMETERS.items() if (v or {}).get("pivotable"))
# The account-object ids: pivotable AND a Google Ads macro, i.e. the ones that identify the ADVERTISER
# rather than the campaign copy. These are the only value pivots this module emits — the utm_* values
# belong to wp_pivots.build_affiliate_pivots and are not re-emitted here.
ACCOUNT_OBJECT_PARAMS = frozenset(k.lower() for k, v in AD_PARAMETERS.items()
                                  if (v or {}).get("pivotable") and (v or {}).get("class") == "valuetrack")
ALL_AD_PARAMS = frozenset(k.lower() for k in AD_PARAMETERS)

_ADVERTISER_ID_RE = re.compile(r"^AR\d{6,32}$", re.I)
_CREATIVE_ID_RE = re.compile(r"^CR\d{6,32}$", re.I)

# Master off switch, flipped by `pivot_extract --no-serp`. Only the METERED SerpApi calls honour it —
# the parameter classifier, the UI-address builder and the cloaking probe are free and keep working.
ENABLED = True


# --------------------------------------------------------------------------- auth / config
def serpapi_key():
    """The SerpApi private key, or None. `SERPAPI_KEY` is the documented name; the aliases are what
    the serpapi client libraries and older write-ups export."""
    return _secret("SERPAPI_KEY", "SERPAPI_API_KEY", "SERP_API_KEY")


def serpapi_configured() -> bool:
    """True when a key is available and the layer is not switched off — the gate every metered
    caller checks before spending a search."""
    return ENABLED and bool(serpapi_key())


def region_codes(region: str = None) -> dict:
    """One region token -> {api, ui, name}. Unknown tokens are passed through rather than rejected:
    Google has ~200 geotargets and this file lists 25, so an analyst who looked up `2372` must be
    able to use it. A bare 4-5 digit number is taken as an API code, an ISO-2 pair as a UI code."""
    key = (region or REGIONS.get("default") or "anywhere").strip()
    for k, v in REGIONS.items():
        if k.lower() == key.lower() and isinstance(v, dict):
            return {"api": v.get("api"), "ui": v.get("ui") or k, "name": v.get("name") or k}
    if re.fullmatch(r"\d{4,6}", key):
        return {"api": key, "ui": key, "name": f"geotarget {key}"}
    return {"api": None, "ui": key, "name": key}


def transparency_urls(domain: str = None, advertiser_id: str = None, creative_id: str = None,
                      region: str = None) -> dict:
    """The Ads Transparency Center WEB addresses for a domain / advertiser / creative.

    Built offline and free, and this is deliberate: the transparency archive is a public web
    product, so a keyless run must still hand the analyst a working address instead of an apology.
    Everything the API would have returned is visible at these URLs by hand."""
    r = region_codes(region)["ui"]
    out = {}
    if domain:
        out["domain"] = ENDPOINTS["ui_transparency_domain"].format(
            region=r, domain=urllib.parse.quote(strip_www(domain)))
    if advertiser_id:
        out["advertiser"] = ENDPOINTS["ui_transparency_advertiser"].format(
            region=r, advertiser_id=advertiser_id)
        if creative_id and ENDPOINTS.get("ui_transparency_creative"):
            out["creative"] = ENDPOINTS["ui_transparency_creative"].format(
                region=r, advertiser_id=advertiser_id, creative_id=creative_id)
    return out


# --------------------------------------------------------------------------- search BUDGET guard
# Same shape and same reasoning as the Censys guard: the quota is monthly, per ACCOUNT and shared by
# every case, so it is checked against the ledger BEFORE the call rather than discovered as an HTTP
# 429 in the middle of a batch. Thresholds are DATA (references/serpapi.json -> search_budget), with
# env overrides for the analyst who topped up today and does not want to edit a tracked file.
_RUN_SPENT = 0
_RUN_DETAILS = 0
_MONTH_SPENT = None
_WARNED = set()
_BUDGET_LOCK = threading.Lock()


def _budget(key: str, env: str = None, default=0):
    if env:
        raw = _secret(env)
        if raw:
            try:
                return int(float(raw))
            except ValueError:
                print(f"[serp] WARNING: {env}={raw!r} is not a number; using the reference value.",
                      file=sys.stderr)
    return SEARCH_BUDGET.get(key, default)


def _ledger_path():
    if api_usage:
        return api_usage._log_path()
    return _secret("API_USAGE_LOG") or os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "MEMORY", "api_usage.jsonl")


def month_spent(refresh: bool = False) -> int:
    """SerpApi searches already spent this UTC month, read from the api_usage ledger.

    Counts every SerpApi call made by ANY tool or case this month, which is the number that matters
    because the quota is per account. An unreadable ledger yields 0 — never block work because a log
    is missing, and say so on stderr when it happens."""
    global _MONTH_SPENT
    with _BUDGET_LOCK:
        if _MONTH_SPENT is not None and not refresh:
            return _MONTH_SPENT
    month = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m")
    total = 0
    try:
        with open(_ledger_path(), encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or '"serpapi"' not in line:
                    continue
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                if rec.get("provider") == "serpapi" and (rec.get("ts") or "").startswith(month):
                    total += rec.get("credits") or 0
    except FileNotFoundError:
        total = 0
    except Exception as exc:
        print(f"[serp] WARNING: could not read the credit ledger ({exc}); the monthly budget guard "
              f"is running on this process's spend only.", file=sys.stderr)
        total = 0
    with _BUDGET_LOCK:
        _MONTH_SPENT = total
    return total


def _spend(credits: int, is_detail: bool = False) -> None:
    global _RUN_SPENT, _RUN_DETAILS, _MONTH_SPENT
    with _BUDGET_LOCK:
        _RUN_SPENT += credits
        if is_detail:
            _RUN_DETAILS += 1
        if _MONTH_SPENT is not None:
            _MONTH_SPENT += credits


def budget_status() -> dict:
    """Where the month's SerpApi searches stand — the number to quote when reporting cost."""
    limit = _budget("monthly_searches", "SERPAPI_MONTHLY_SEARCHES", 100)
    run_cap = _budget("max_searches_per_run", "SERPAPI_MAX_SEARCHES_PER_RUN", 8)
    spent = month_spent()
    return {"monthly_searches": limit, "spent_this_month": spent,
            "remaining_this_month": max(0, limit - spent),
            "spent_this_run": _RUN_SPENT, "max_searches_per_run": run_cap,
            "creative_details_this_run": _RUN_DETAILS,
            "max_creative_details_per_run": _budget("max_creative_details_per_run", default=3),
            "ledger": _ledger_path(),
            "month": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m")}


def _budget_block(cost: int, action: str, is_detail: bool = False):
    """None when `cost` searches may be spent, else the analyst-readable reason not to.

    Returned as a `skipped` reason, never an exception: an unaffordable SerpApi call is the same
    class of outcome as a missing key — the transparency UI address is still the deliverable, and it
    costs nothing to open."""
    b = budget_status()
    if not SEARCH_BUDGET.get("block_when_exhausted", True):
        return None
    if is_detail and b["creative_details_this_run"] + 1 > b["max_creative_details_per_run"]:
        return (f"per-run creative-detail cap reached ({b['creative_details_this_run']}/"
                f"{b['max_creative_details_per_run']}). Each detail call opens ONE creative; a wide "
                f"advertiser would otherwise spend a month's quota on one domain. Open the rest in "
                f"the Ads Transparency Center UI.")
    if b["spent_this_run"] + cost > b["max_searches_per_run"]:
        return (f"per-run SerpApi cap reached ({b['spent_this_run']}/{b['max_searches_per_run']} "
                f"searches spent this run; {action} needs {cost}). Raise "
                f"SERPAPI_MAX_SEARCHES_PER_RUN for a run that genuinely needs it, or use the "
                f"emitted Ads Transparency Center URL by hand.")
    remaining = b["remaining_this_month"]
    if cost > remaining:
        return (f"monthly SerpApi search budget exhausted ({b['spent_this_month']}/"
                f"{b['monthly_searches']} spent in {b['month']}; {action} needs {cost}). Raise "
                f"SERPAPI_MONTHLY_SEARCHES if you are on a larger plan.")
    if remaining <= _budget("warn_at_remaining", default=25) and action not in _WARNED:
        _WARNED.add(action)
        print(f"[serp] ⚠ {remaining} of {b['monthly_searches']} monthly SerpApi searches left "
              f"({b['spent_this_month']} spent in {b['month']}). Spending {cost} on {action}.",
              file=sys.stderr)
    return None


def _record(action: str, credits: int, query: str, results=None, ok: bool = True,
            is_detail: bool = False):
    if credits:
        _spend(credits, is_detail=is_detail)
    if api_usage:
        api_usage.record("serpapi", action, credits=credits, query=query, results=results, ok=ok)


# --------------------------------------------------------------------------- transport
_STATUS_REASON = {
    401: "SerpApi rejected the key (SERPAPI_KEY missing, wrong, or revoked)",
    403: "your SerpApi plan does not allow this engine",
    429: "SerpApi quota or rate limit reached — the monthly searches are used up, or too many "
         "requests this hour",
}


def _call(engine_key: str, params: dict, action: str, cost: int = None, timeout: int = 30,
          is_detail: bool = False):
    """One SerpApi call -> (data, error_dict). Never raises.

    `error_dict` is `{"skipped": reason}` for the key/quota/budget conditions the caller is expected
    to survive with its UI fallback, and `{"error": ...}` for anything genuinely unexpected. Note
    SerpApi answers 200 with an `error` string when a query simply has no results — that is a real
    NEGATIVE about the archive, not a failure, and it is returned as `{"empty": reason}` so a caller
    can tell "the archive has nothing" apart from "we never asked"."""
    if not serpapi_configured():
        return None, {"skipped": "no SERPAPI_KEY configured — the Ads Transparency Center archive "
                                 "was never queried; this establishes nothing about whether the "
                                 "domain advertises"}
    engine = ENGINES.get(engine_key, engine_key)
    cost = CREDIT_COSTS.get("search", 1) if cost is None else cost
    blocked = _budget_block(cost, action, is_detail=is_detail)
    if blocked:
        return None, {"skipped": blocked}
    q = {k: v for k, v in (params or {}).items() if v not in (None, "")}
    q["engine"] = engine
    q["api_key"] = serpapi_key()
    url = ENDPOINTS["search"] + "?" + urllib.parse.urlencode(q)
    shown = urllib.parse.urlencode({k: v for k, v in q.items() if k != "api_key"})
    try:
        req = urllib.request.Request(url, headers={"User-Agent": DEFAULT_UA,
                                                   "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.load(r)
    except urllib.error.HTTPError as e:
        reason = _STATUS_REASON.get(e.code)
        detail = ""
        try:
            detail = (json.loads(e.read().decode()) or {}).get("error") or ""
        except Exception:
            pass
        msg = f"HTTP {e.code}" + (f" — {reason}" if reason else "") + (f" ({detail})" if detail else "")
        # SerpApi does not bill a failed search, so nothing is recorded as spent.
        _record(action, 0, shown, ok=False)
        return None, ({"skipped": msg} if e.code in _STATUS_REASON else {"error": msg})
    except Exception as e:
        _record(action, 0, shown, ok=False)
        return None, {"error": str(e)}
    if isinstance(data, dict) and data.get("error"):
        # A no-results answer — and SerpApi DOES bill it. This was previously recorded at zero on
        # the assumption that an empty result is free; measured against the live account endpoint
        # it is not: one such query moved this_month_usage 11 -> 12 and plan_searches_left
        # 239 -> 238. Recording it at zero made the ledger under-report, which matters because
        # month_spent() sums exactly this field to enforce the monthly cap — so the guard believed
        # it had headroom the account did not have. A search that reached the API and came back 200
        # is a spent search whatever the payload says. Compare `ledger_spent_this_month` with
        # `account_spent_this_month` in `wp_serp.py budget` to confirm the two agree.
        # (An HTTP error above is different and stays at zero: SerpApi does not bill those.)
        # ok=True is deliberate and is what makes the cost stick: api_usage.record() zeroes the
        # credits of any call flagged ok=False, and `ok` means "the CALL succeeded", not "results
        # were found". This one returned HTTP 200 and was billed; `results=0` is what records that
        # the archive held nothing, and the caller still gets {"empty": ...} to tell a real negative
        # apart from a query that never ran.
        _record(action, cost, shown, results=0, ok=True, is_detail=is_detail)
        return None, {"empty": str(data["error"])}
    _record(action, cost, shown, results=_count_results(data), is_detail=is_detail)
    return data, None


def _count_results(data) -> int:
    if not isinstance(data, dict):
        return 0
    for key in ("ad_creatives", "ads", "organic_results"):
        v = data.get(key)
        if isinstance(v, list):
            return len(v)
    return 1


def account_status(timeout: int = 20):
    """The live quota straight from SerpApi. FREE — the account endpoint does not count against the
    monthly searches, which is why the budget command may call it. Returns (data, error)."""
    key = serpapi_key()
    if not key:
        return None, {"skipped": "no SERPAPI_KEY configured"}
    base = ENDPOINTS.get("account") or "https://serpapi.com/account.json"
    url = base + "?" + urllib.parse.urlencode({"api_key": key})
    try:
        req = urllib.request.Request(url, headers={"User-Agent": DEFAULT_UA,
                                                   "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.load(r)
    except Exception as e:
        return None, {"error": str(e)}
    return {k: data.get(k) for k in ("plan_name", "searches_per_month", "plan_searches_left",
                                     "extra_credits", "total_searches_left", "this_month_usage",
                                     "account_rate_limit_per_hour") if k in data}, None


# --------------------------------------------------------------------------- offline: ad parameters
def _query_pairs(url_or_query: str):
    """(key, value) pairs from a URL's query string, a bare query string, or a `k=v&k=v` fragment."""
    raw = (url_or_query or "").strip()
    if not raw:
        return []
    if "://" in raw or raw.startswith("//"):
        raw = urllib.parse.urlparse(raw).query
    elif raw.startswith("?"):
        raw = raw[1:]
    return urllib.parse.parse_qsl(raw, keep_blank_values=False)


def is_generic_value(value: str) -> bool:
    """True when a parameter's value names a platform or channel rather than an operator.

    The base-rate control for this layer. `utm_campaign=google` and `utm_content=banner` appear on
    unrelated sites by the million; treating one as a fingerprint would fuse every advertiser on the
    internet into a single cluster."""
    v = (value or "").strip().lower()
    if not v or len(v) < 3:
        return True
    return v in GENERIC_VALUES


def ad_params(url_or_query: str) -> dict:
    """The advertising parameters present in a URL -> {param: {value, class, pivotable, generic}}.

    Offline, free, and the entry point for everything else here: what is present decides whether the
    page was reached by PAID traffic, which parameters can be reversed, and what the cloaking probe
    must replay to look like a real click. Parameter names not in the table are ignored — a page's
    ordinary query string is not advertising evidence."""
    out = {}
    for k, v in _query_pairs(url_or_query):
        kl = k.strip().lower()
        spec = AD_PARAMETERS.get(kl)
        if not spec or not v:
            continue
        rec = {"value": v, "class": spec.get("class") or "campaign",
               "pivotable": bool(spec.get("pivotable")), "cloak_key": bool(spec.get("cloak_key"))}
        if rec["pivotable"]:
            rec["generic"] = is_generic_value(v)
        if spec.get("note"):
            rec["note"] = spec["note"]
        out[kl] = rec
    return out


def parse_ad_params(spec: str) -> dict:
    """--ad-params accepts either a full ad URL or a bare `k=v&k=v` fragment. Analysts paste
    whichever they have in front of them, and rejecting one of the two forms for tidiness would just
    lose the parameters."""
    if not spec:
        return {}
    return {k.strip().lower(): v for k, v in _query_pairs(spec) if v}


def paid_arrival(url_or_query: str) -> dict:
    """Was this URL reached by a PAID click, and from which platform?

    The click ids are the evidence: they are minted by the ad platform at click time, so their
    presence in a URL an analyst was handed (a report, a victim's browser history, a stealer log)
    proves the victim arrived through an advertisement rather than a search result — which is a
    finding in itself, and the cue to run the transparency lookup and the cloaking probe."""
    found = ad_params(url_or_query)
    clicks = {k: v["value"] for k, v in found.items() if k in CLICK_ID_PARAMS}
    platforms = []
    for k in clicks:
        if k in ("gclid", "gbraid", "wbraid", "dclid"):
            platforms.append("google")
        elif k == "msclkid":
            platforms.append("microsoft")
        elif k == "fbclid" or k == "igshid":
            platforms.append("meta")
        elif k == "ttclid":
            platforms.append("tiktok")
        elif k == "yclid":
            platforms.append("yandex")
        else:
            platforms.append(k)
    return {"is_paid_click": bool(clicks), "click_ids": clicks, "platforms": uniq(platforms),
            "campaign_params": {k: v["value"] for k, v in found.items()
                                if v["class"] in ("campaign", "valuetrack")},
            "params": found}


def strip_ad_params(url: str) -> str:
    """The same URL as an ordinary visitor would reach it — every known advertising parameter
    removed. This is the PLAIN view of the cloaking probe, and it is also the URL that should be
    used as a case identifier: a per-click gclid would make every observation of one page unique."""
    p = urllib.parse.urlsplit(url)
    keep = [(k, v) for k, v in urllib.parse.parse_qsl(p.query, keep_blank_values=True)
            if k.strip().lower() not in ALL_AD_PARAMS]
    return urllib.parse.urlunsplit((p.scheme, p.netloc, p.path,
                                    urllib.parse.urlencode(keep), p.fragment))


def unlock_params(url: str = "", extra: dict = None) -> dict:
    """The parameter set to send as the "paid click" view.

    Priority is the point: the operator's OWN tagging beats anything we invent. Whatever the URL
    already carries is kept, `extra` (from --ad-params, or from the ad creative's destination link
    that SerpApi returned) is layered on top, and the synthetic `probe_profile` fills only the gaps.
    A cloaker that validates its gclid server-side will not be unlocked by the synthetic set — and
    the probe will then correctly report no divergence rather than a false negative dressed as a
    fact."""
    merged = {str(k).lower(): str(v) for k, v in PROBE_PARAMS.items()}
    for k, v in ad_params(url).items():
        merged[k] = v["value"]
    for k, v in (extra or {}).items():
        kl = str(k).strip().lower()
        if v not in (None, ""):
            merged[kl] = str(v)
    return merged


def unlock_url(url: str, extra: dict = None) -> str:
    """The URL that arrives as a paid click — the address to collect if the page cloaks.

    Non-advertising query parameters on the original are preserved; only the ad set is (re)written,
    so a kit that needs both its own routing parameter and the click id still resolves."""
    p = urllib.parse.urlsplit(url)
    base = [(k, v) for k, v in urllib.parse.parse_qsl(p.query, keep_blank_values=True)
            if k.strip().lower() not in ALL_AD_PARAMS]
    base += sorted(unlock_params(url, extra).items())
    return urllib.parse.urlunsplit((p.scheme, p.netloc, p.path or "/",
                                    urllib.parse.urlencode(base), p.fragment))


# --------------------------------------------------------------------------- the CLOAKING probe
def _norm_text(html: str, cap: int = None) -> str:
    """A page's visible text, normalised for comparison: scripts, styles, comments and tags removed,
    whitespace collapsed, lowercased.

    Comparing raw HTML would score two views as different because of a rotating nonce in a script
    tag; comparing visible text asks the question that matters — is the victim being shown the same
    page."""
    cap = cap or int(CLOAKING_PROBE.get("max_body_bytes", 3000000))
    s = (html or "")[:cap]
    s = re.sub(r"(?is)<(script|style|noscript)\b.*?</\1>", " ", s)
    s = re.sub(r"(?s)<!--.*?-->", " ", s)
    s = re.sub(r"(?s)<[^>]+>", " ", s)
    return re.sub(r"\s+", " ", s).strip().lower()


def _title(html: str) -> str:
    m = re.search(r"(?is)<title[^>]*>(.*?)</title>", html or "")
    return re.sub(r"\s+", " ", m.group(1)).strip()[:200] if m else ""


def _similarity(a: str, b: str) -> float:
    """Cheap similarity of two normalised page texts, 0..1.

    `quick_ratio` compares character multisets rather than doing the quadratic diff, which is the
    only affordable choice on multi-megabyte pages and is more than sharp enough for the question
    being asked: a decoy and a scam page do not share a character distribution."""
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return round(difflib.SequenceMatcher(None, a, b).quick_ratio(), 4)


def _view(label: str, url: str, fetch_fn, ua: str, proxy: str, timeout: int,
          headers_extra: dict = None) -> dict:
    """One fetch, reduced to the fields the comparison needs (plus the body, for the caller)."""
    rec = {"label": label, "url": url}
    try:
        final_url, status, headers, body = fetch_fn(url, timeout=timeout, ua=ua, proxy=proxy,
                                                    headers_extra=headers_extra)
        html = body.decode("utf-8", "ignore") if isinstance(body, (bytes, bytearray)) else str(body)
        rec.update({
            "status": status, "final_url": final_url,
            "final_host": strip_www(urllib.parse.urlparse(final_url or url).netloc),
            "bytes": len(html), "sha256": hashlib.sha256(html.encode("utf-8", "ignore")).hexdigest(),
            "title": _title(html), "content_type": (headers or {}).get("content-type", ""),
            "body": html,
        })
    except Exception as exc:
        rec["error"] = str(exc)
    return rec


def _default_fetch(url, timeout=20, ua=DEFAULT_UA, proxy=None, headers_extra=None):
    """The probe's fetcher. Uses WebPivot's shared browser-profile `fetch` when importable (so the
    request looks like every other request this toolkit makes) and falls back to stdlib urllib when
    wp_serp is run standalone. `headers_extra` is what makes the click view a click view — the
    Google referrer and the cross-site fetch metadata."""
    if _wp_fetch is not None and not headers_extra:
        return _wp_fetch(url, timeout=timeout, ua=ua, proxy=proxy)
    headers = {"User-Agent": ua or DEFAULT_UA,
               "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               "Accept-Language": "en-US,en;q=0.9", "Accept-Encoding": "identity",
               "Upgrade-Insecure-Requests": "1"}
    headers.update(headers_extra or {})
    handlers = [urllib.request.ProxyHandler({"http": proxy, "https": proxy})] if proxy else []
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(url, headers=headers)
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.geturl(), r.status, {k.lower(): v for k, v in r.headers.items()}, r.read()
    except urllib.error.HTTPError as e:
        return url, e.code, {k.lower(): v for k, v in (e.headers or {}).items()}, e.read()


def is_challenge(view: dict) -> bool:
    """True when a fetched view is an ANTI-BOT INTERSTITIAL rather than the site's own page.

    This matters more than it looks. Two challenge pages differ from each other by construction —
    per-request nonces, padded bodies — so a probe that scored them would report the BOT WALL as
    operator evasion, on exactly the hostile infrastructure where a cloaking finding would be taken
    most seriously. Neither view is what a victim sees, so the honest answer is that the probe could
    not observe the page at all."""
    body = (view.get("body") or "").lower()
    if not body:
        return False
    if any(m in body for m in CHALLENGE_MARKERS):
        return True
    # A challenge status WITH a body too small to be a real page. The status alone is not enough:
    # 403 is also how plenty of sites answer an unwelcome region, and that IS a page.
    statuses = CLOAKING_PROBE.get("challenge_statuses") or []
    return (view.get("status") in statuses
            and view.get("bytes", 0) < 8192 and not (view.get("title") or "").strip())


def _click_headers() -> dict:
    """The headers a real ad click carries. A cloaker that only checks the referrer — and many do,
    because it is one line of PHP — is unlocked by this alone, with no parameters at all."""
    return {str(k): str(v) for k, v in PROBE_HEADERS.items()}


def cloak_probe(url: str, extra_params: dict = None, ua: str = DEFAULT_UA, proxy: str = None,
                timeout: int = None, fetch_fn=None, keep_bodies: bool = False) -> dict:
    """Does this page show paid-click visitors something different from everyone else?

    Three fetches, in this order, and the order is the whole design:

      1. **plain**   — the URL with every ad parameter stripped and no referrer: what we, a crawler,
                       or a Google reviewer arriving out of band would see.
      2. **click**   — the same URL carrying the operator's own campaign tagging (or the synthetic
                       profile) plus a Google referrer and cross-site fetch metadata: what the
                       victim who clicked the ad sees.
      3. **control** — plain again, AFTER the click view. This is the falsification step. Without it
                       a page that simply differs between any two fetches — session ids, rotating
                       creatives, load-balanced backends, a first-visit-only interstitial — reads as
                       cloaking, and a fabricated evasion finding is worse than no finding. If plain
                       and control disagree, the verdict is `inconclusive_unstable` and nothing is
                       attributed to the click.

    Verdicts: `identical` (same bytes), `dynamic` (differs within the thresholds — an ordinary live
    page), `divergent` (**click-keyed cloaking observed**), `inconclusive_unstable`, `inconclusive`
    (a view could not be fetched). Costs no API credit; it is three requests to the target.

    A `divergent` verdict means the artifacts collected from the plain view describe the DECOY. The
    returned `unlock_url` is the address the case should actually be collected from."""
    timeout = int(timeout or CLOAKING_PROBE.get("timeout_seconds", 20))
    fetch_fn = fetch_fn or _default_fetch
    plain_url = strip_ad_params(url)
    click_url = unlock_url(url, extra_params)
    params_used = unlock_params(url, extra_params)

    views = {"plain": _view("plain", plain_url, fetch_fn, ua, proxy, timeout),
             "click": _view("click", click_url, fetch_fn, ua, proxy, timeout,
                            headers_extra=_click_headers())}
    if CLOAKING_PROBE.get("control_refetch", True):
        views["control"] = _view("control", plain_url, fetch_fn, ua, proxy, timeout)

    report = {
        "probe": "click_keyed_cloaking", "url": url, "plain_url": plain_url,
        "unlock_url": click_url, "params_sent": params_used,
        "params_source": ("operator" if ad_params(url) or extra_params else "synthetic"),
        "referer_sent": _click_headers().get("Referer"),
        "views": {k: {kk: vv for kk, vv in v.items() if kk != "body"} for k, v in views.items()},
    }
    plain, click = views["plain"], views["click"]
    if plain.get("error") or click.get("error"):
        report.update({"verdict": "inconclusive", "signals": [],
                       "note": ("a view could not be fetched, so nothing can be concluded about "
                                "cloaking — this is NOT evidence that the page is clean.")})
        return _attach_bodies(report, views, keep_bodies)

    if is_challenge(plain) or is_challenge(click):
        report.update({
            "verdict": "inconclusive", "signals": [], "challenge_detected": True,
            "note": ("an ANTI-BOT INTERSTITIAL was served instead of the page (challenge / CAPTCHA "
                     "wall), so neither view is the content a victim sees and the two cannot be "
                     "compared — two challenge pages differ from each other by design. This is NOT "
                     "evidence that the page is clean, and it is NOT evasion by the operator. "
                     "Re-probe through a residential --proxy, or collect with --solve-cf and pass "
                     "the resulting URL to `wp_serp.py cloak`."),
        })
        return _attach_bodies(report, views, keep_bodies)

    min_bytes = int(CLOAKING_PROBE.get("min_body_bytes_for_verdict", 200))
    signals, thin = [], (plain["bytes"] < min_bytes or click["bytes"] < min_bytes)
    p_text, c_text = _norm_text(plain["body"]), _norm_text(click["body"])
    sim = _similarity(p_text, c_text)
    ratio = round(min(plain["bytes"], click["bytes"]) / max(1, max(plain["bytes"], click["bytes"])), 4)
    report["similarity"] = sim
    report["length_ratio"] = ratio

    # The TRANSPORT signals are checked before the body comparison, not after: a paid click that is
    # redirected to a different host is divergence even when the two pages happen to render the same
    # bytes — the victim is being sent somewhere the plain visitor is not.
    if CLOAKING_PROBE.get("host_change_is_divergence", True) and \
            plain.get("final_host") != click.get("final_host"):
        signals.append(f"final host differs: plain -> {plain.get('final_host')}, "
                       f"click -> {click.get('final_host')}")
    if plain.get("status") != click.get("status"):
        signals.append(f"HTTP status differs: plain {plain.get('status')}, click {click.get('status')}")
    if plain["sha256"] == click["sha256"] and not signals:
        report.update({"verdict": "identical", "signals": [],
                       "note": ("byte-identical to a paid-click arrival — no click-keyed cloaking on "
                                "this URL. A cloaker that validates its click id server-side, or "
                                "one keyed on geography/ASN rather than the click, would also look "
                                "like this.")})
        return _attach_bodies(report, views, keep_bodies)
    if CLOAKING_PROBE.get("title_change_is_divergence", True) and \
            (plain.get("title") or "") != (click.get("title") or ""):
        signals.append(f"<title> differs: plain {plain.get('title')!r}, click {click.get('title')!r}")
    if sim < float(CLOAKING_PROBE.get("min_similarity", 0.9)):
        signals.append(f"visible-text similarity {sim} below {CLOAKING_PROBE.get('min_similarity')}")
    # LENGTH IS A SUPPORTING SIGNAL, NEVER A SOLE ONE. Bytes differ for a dozen benign reasons — a
    # per-request nonce, an inlined token, a padded anti-bot interstitial — and live testing found a
    # major booking site whose two views had IDENTICAL visible text (similarity 1.0) and a 0.56
    # length ratio, which the length rule alone called cloaking. It is the text a victim reads that
    # decides whether they are being shown a different page, so the length only corroborates a
    # difference something else already found.
    if ratio < float(CLOAKING_PROBE.get("length_ratio_band", 0.75)):
        note = f"body length ratio {ratio} below {CLOAKING_PROBE.get('length_ratio_band')}"
        if signals:
            signals.append(note)
        else:
            report["supporting_only"] = (
                note + " — but the visible text is unchanged, so this is padding/nonce variation, "
                       "not a different page. Not counted as divergence.")

    control = views.get("control")
    if signals and control and not control.get("error"):
        ctl_sim = _similarity(p_text, _norm_text(control["body"]))
        report["control_similarity"] = ctl_sim
        if control["sha256"] != plain["sha256"] and \
                ctl_sim < float(CLOAKING_PROBE.get("min_similarity", 0.9)):
            report.update({
                "verdict": "inconclusive_unstable", "signals": signals,
                "note": ("the page also differs between two IDENTICAL plain requests "
                         f"(control similarity {ctl_sim}), so the difference cannot be attributed "
                         "to the ad click. Rotating content, per-session rendering or a "
                         "load-balanced backend all look like this. Re-probe with a stable network "
                         "path, or compare captured evidence bundles instead."),
            })
            return _attach_bodies(report, views, keep_bodies)

    if signals:
        report.update({
            "verdict": "divergent", "signals": signals, "thin_response": thin,
            "note": ("CLICK-KEYED CLOAKING OBSERVED — this host serves different content to a "
                     "visitor arriving from a paid ad than to everyone else, and the plain view is "
                     "the decoy. Collect the case from `unlock_url`: any artifact taken from the "
                     "plain view (favicon, DOM fingerprint, wallets, contacts) describes the decoy "
                     "and must not be clustered. Serving one page to reviewers and another to "
                     "victims is deliberate evasion and belongs in the assessment on its own."),
        })
    else:
        report.update({
            "verdict": "dynamic", "signals": [],
            "note": ("the two views differ, but within the thresholds for an ordinary live page "
                     "(session ids, tokens, timestamps, rotating creatives). Not cloaking."),
        })
    return _attach_bodies(report, views, keep_bodies)


def _attach_bodies(report: dict, views: dict, keep: bool) -> dict:
    """Hand back the fetched bodies only when the caller asked for them.

    pivot_extract wants the click view's HTML — on a `divergent` verdict that is the page the whole
    collection should run against. Everything else wants a JSON-serialisable report, and a
    multi-megabyte DOM inside a result file is not that."""
    if keep:
        report["_bodies"] = {k: v.get("body", "") for k, v in views.items()}
    return report


# --------------------------------------------------------------------------- metered: the archive
def _ts(value):
    """A SerpApi unix timestamp -> an ISO date. Dates are what the temporal layer joins on, and an
    ad's first/last-shown window is a hosting window by another name: it dates the campaign
    independently of registration or certificate records."""
    try:
        n = int(value)
    except (TypeError, ValueError):
        return None
    if n > 10_000_000_000:              # milliseconds
        n //= 1000
    try:
        return datetime.datetime.fromtimestamp(n, datetime.timezone.utc).strftime("%Y-%m-%d")
    except Exception:
        return None


def _group_creatives(creatives: list, region: str) -> list:
    """ad_creatives[] -> one record per ADVERTISER, which is the unit of analysis.

    The API returns creatives; the question is always about the account behind them. Grouping here
    also produces the two fields the rest of the layer runs on: the distinct target domains (the
    reverse pivot) and the first/last shown window (the campaign's dates)."""
    by_adv = {}
    cap = int(RESULT_LIMITS.get("max_target_domains", 25))
    for c in creatives or []:
        if not isinstance(c, dict):
            continue
        aid = (c.get("advertiser_id") or "").strip()
        if not aid:
            continue
        rec = by_adv.setdefault(aid, {
            "advertiser_id": aid, "advertiser": (c.get("advertiser") or "").strip(),
            "creative_count": 0, "formats": [], "target_domains": [], "creative_ids": [],
            "first_shown": None, "last_shown": None,
        })
        rec["creative_count"] += 1
        if c.get("format") and c["format"] not in rec["formats"]:
            rec["formats"].append(c["format"])
        td = strip_www((c.get("target_domain") or "").strip().lower())
        if td and td not in rec["target_domains"] and len(rec["target_domains"]) < cap:
            rec["target_domains"].append(td)
        cid = (c.get("ad_creative_id") or c.get("creative_id") or "").strip()
        # A capped SAMPLE, not an inventory: these ids exist so a follow-up call can open one, and
        # `creative_count` already carries how many the account ran.
        if cid and cid not in rec["creative_ids"] and \
                len(rec["creative_ids"]) < int(RESULT_LIMITS.get("max_creative_ids_kept", 5)):
            rec["creative_ids"].append(cid)
        first, last = _ts(c.get("first_shown")), _ts(c.get("last_shown"))
        if first and (not rec["first_shown"] or first < rec["first_shown"]):
            rec["first_shown"] = first
        if last and (not rec["last_shown"] or last > rec["last_shown"]):
            rec["last_shown"] = last
    out = []
    threshold = int(CLUSTERING_POLICY.get("agency_domain_threshold", 12))
    for rec in by_adv.values():
        rec["target_domains"].sort()
        rec["agency_shaped"] = len(rec["target_domains"]) >= threshold
        if rec["agency_shaped"]:
            rec["agency_note"] = (
                f"this advertiser points at {len(rec['target_domains'])}+ distinct domains "
                f"(threshold {threshold}) — that is the shape of a media buyer, affiliate network "
                f"or agency BUYING TRAFFIC FOR OTHERS, not of one operator's estate. Its "
                f"co-advertised domains are leads, not same-operator evidence.")
        # Under `ui_url`, NOT `advertiser` — that key holds the funded-by NAME, which is a pivot in
        # its own right (the string to run through a corporate registry) and must not be shadowed
        # by a link.
        rec["ui_url"] = transparency_urls(advertiser_id=rec["advertiser_id"],
                                          region=region).get("advertiser")
        out.append(rec)
    return sorted(out, key=lambda r: (-r["creative_count"], r["advertiser_id"]))


def advertiser_search(domain: str, region: str = None, timeout: int = 30) -> dict:
    """WHO ADVERTISES THIS DOMAIN — the Ads Transparency Center, searched by domain.

    The headline call. A hit returns a Google-verified advertiser identity for a domain whose WHOIS
    is behind privacy and whose host is a week old. A miss is a real negative ONLY when the archive
    was actually queried — with no key this returns the UI address and says so, and reporting that
    as "the domain does not advertise" is the exact error this layer's disclosure exists to
    prevent."""
    dom = strip_www((domain or "").strip().lower())
    r = region_codes(region)
    out = {"query_domain": dom, "region": r["name"],
           "ui_url": transparency_urls(domain=dom, region=region).get("domain"),
           "advertisers": []}
    data, err = _call("ads_transparency",
                      {"text": dom, "region": r["api"],
                       "num": int(RESULT_LIMITS.get("max_creatives", 40))},
                      action="ads_transparency_domain", timeout=timeout)
    if err:
        out.update(err)
        if "skipped" in err:
            out["note"] = ("the Ads Transparency Center was NOT queried — open ui_url by hand. "
                           "Absence of advertisers here is absence of a query, not a finding.")
        elif "empty" in err:
            out["note"] = ("the archive returned no creatives for this domain in this region. Try "
                           "region=anywhere and the operator's target market before concluding the "
                           "domain never advertised — the archive is queried PER REGION.")
        return out
    out["advertisers"] = _group_creatives(data.get("ad_creatives"), region)
    out["total_results"] = (data.get("search_information") or {}).get("total_results")
    return out


def advertiser_creatives(advertiser_id: str, region: str = None, timeout: int = 30) -> dict:
    """THE REVERSE — one advertiser_id -> every domain that account advertised.

    This is the pivot the layer is built for. One verified, billed Google Ads account paid to send
    traffic to all of these, which is a same-PAYER link and a materially stronger one than a shared
    template: money is harder to share than code. Read `agency_shaped` before treating the list as
    one operator's estate — a traffic broker's account looks exactly like this and is not one."""
    aid = (advertiser_id or "").strip()
    r = region_codes(region)
    out = {"advertiser_id": aid, "region": r["name"],
           "ui_url": transparency_urls(advertiser_id=aid, region=region).get("advertiser"),
           "advertisers": []}
    if not _ADVERTISER_ID_RE.match(aid):
        out["error"] = (f"{aid!r} is not an Ads Transparency advertiser id (they look like "
                        f"AR followed by digits)")
        return out
    data, err = _call("ads_transparency",
                      {"advertiser_id": aid, "region": r["api"],
                       "num": int(RESULT_LIMITS.get("max_creatives", 40))},
                      action="ads_transparency_advertiser", timeout=timeout)
    if err:
        out.update(err)
        if "skipped" in err:
            out["note"] = ("not queried — open ui_url by hand; the advertiser's full creative list "
                           "and every domain it points at are public there.")
        return out
    out["advertisers"] = _group_creatives(data.get("ad_creatives"), region)
    out["target_domains"] = uniq([d for a in out["advertisers"] for d in a["target_domains"]])
    return out


def creative_details(advertiser_id: str, creative_id: str, region: str = None,
                     timeout: int = 30) -> dict:
    """One creative, opened. What this reliably buys, and what it does not.

    RELIABLY: **`ad_funded_by`** — the LEGAL ENTITY name Google verified against documents before
    the account was allowed to spend, which is usually more precise than the display name on the
    search result ("<Brand> B.V." rather than "<Brand>"). That string is the one that goes into a
    corporate registry. Also the creative's format, when it was last shown, and — the underrated
    field — the **per-region breakdown**: which markets the ad actually ran in, each with its own
    last-shown date. Which countries an operator paid to reach is target-selection evidence, and it
    is dated.

    NOT RELIABLY: the destination link. SerpApi documents `link` / `visible_link` / `headline` on the
    creative, but Google's archive frequently returns a text ad only as a RENDERED IMAGE with no
    URL attached, and then there is nothing to parse. So this is read opportunistically: when a link
    comes back its campaign parameters become the cloaking key, and when it does not, that is the
    normal case and not an error. Do not plan a case around getting it — the reliable sources for an
    operator's real ad parameters are a URL the analyst already holds (a report, a victim's browser
    history, a stealer log) passed via `--ad-params`, or the synthetic probe profile.

    The API nests the metadata under `search_information` and the creative content under
    `ad_creatives[]`; both are read, because the published schema and the live response disagree and
    the live one wins."""
    out = {"advertiser_id": advertiser_id, "creative_id": creative_id}
    # `ui_` prefixed — `advertiser` is the funded-by NAME below, and a link must never shadow it.
    _urls = transparency_urls(advertiser_id=advertiser_id, creative_id=creative_id, region=region)
    out["ui_advertiser"] = _urls.get("advertiser")
    out["ui_creative"] = _urls.get("creative")
    data, err = _call("ad_details", {"advertiser_id": advertiser_id, "creative_id": creative_id},
                      action="ads_transparency_creative", cost=CREDIT_COSTS.get("ad_details", 1),
                      timeout=timeout, is_detail=True)
    if err:
        out.update(err)
        return out
    info = data.get("search_information") or {}
    creatives = [c for c in (data.get("ad_creatives") or []) if isinstance(c, dict)]
    first = creatives[0] if creatives else {}
    # Read each field from whichever level actually carries it. Merging rather than choosing keeps
    # this working if SerpApi moves a field back to where its documentation says it lives.
    for k in ("link", "visible_link", "headline", "snippet", "title", "call_to_action",
              "ad_funded_by", "is_verified", "format", "first_shown", "last_shown", "image"):
        v = first.get(k, info.get(k, data.get(k)))
        if v not in (None, ""):
            out[k] = v
    for k in ("first_shown", "last_shown"):
        if out.get(k):
            out[k] = _ts(out[k]) or out[k]
    regions = info.get("regions") if isinstance(info.get("regions"), list) else data.get("regions")
    if isinstance(regions, list) and regions:
        # Which markets, and when each last ran — targeting evidence, and dated.
        out["regions"] = [{"region_name": r.get("region_name"), "region": r.get("region"),
                           "last_shown": r.get("last_shown")}
                          for r in regions[:20] if isinstance(r, dict)]
        out["markets"] = uniq([r.get("region_name") for r in out["regions"] if r.get("region_name")])
    if out.get("link"):
        out["landing_params"] = ad_params(out["link"])
        out["landing_host"] = strip_www(urllib.parse.urlparse(out["link"]).netloc)
        if out["landing_params"]:
            out["unlock_note"] = ("these are the operator's OWN campaign parameters. Pass them to "
                                  "the cloaking probe (--ad-params) and collect the landing page "
                                  "as the ad's audience sees it.")
    else:
        out["no_link_note"] = ("the archive returned this creative without a destination URL (it is "
                               "commonly stored as a rendered image). NORMAL, not an error — the "
                               "advertiser identity below still stands. For the real ad parameters "
                               "use a URL you already hold (report / victim / stealer log) with "
                               "--ad-params, or let the probe use its synthetic profile.")
    return out


def serp_ads(query: str, gl: str = None, hl: str = None, location: str = None,
             timeout: int = 30) -> dict:
    """WHO IS BUYING THIS KEYWORD RIGHT NOW — the sponsored block of a live Google SERP.

    The complement to the archive: the transparency centre tells you who advertised, this tells you
    who is advertising, in a specific market, at this moment. It is how brand-impersonation
    malvertising is caught while the campaign is live — search the victim brand and read which
    domains are paying to sit above it.

    ⚠️ BEST-EFFORT. Google does not reliably serve the sponsored block to automated clients: live
    testing got no `ads` key at all for high-commercial-intent queries, with and without a US
    location and a desktop device. So an empty result sets `ads_block_present: False` and carries a
    note — it is a fact about the RESPONSE, never the finding "nobody advertises against this
    brand". Treat `advertiser_search` as the reliable path and this as a bonus when it fires.

    Note also what a hit is NOT: two domains bidding on one keyword are competitors, so
    co-appearance here is never an operator link (`clustering_policy`)."""
    out = {"query": query, "gl": gl, "hl": hl, "ads": []}
    data, err = _call("google", {"q": query, "gl": gl, "hl": hl, "location": location},
                      action="serp_ads", timeout=timeout)
    if err:
        out.update(err)
        if "skipped" in err:
            out["ui_url"] = "https://www.google.com/search?" + urllib.parse.urlencode(
                {"q": query, "gl": gl or "", "hl": hl or ""})
            out["note"] = ("not queried — run the search yourself in the target market. A SERP from "
                           "your own location shows YOUR market's advertisers, not the victims'.")
        return out
    cap = int(RESULT_LIMITS.get("max_serp_ads", 12))
    # BEST-EFFORT, and it must say so. Google serves the sponsored block inconsistently to scrapers:
    # live testing returned NO `ads` key at all for high-commercial-intent queries, with and without
    # a US location and desktop device. An empty list here therefore means "this response carried no
    # ads block", which is NOT the same claim as "nobody is buying this keyword" — and treating the
    # two as equal is exactly the absence-of-evidence error this toolkit exists to prevent. The Ads
    # Transparency archive is the reliable path; this mode is a live snapshot when it works.
    out["ads_block_present"] = isinstance(data.get("ads"), list) and bool(data.get("ads"))
    for ad in (data.get("ads") or [])[:cap]:
        if not isinstance(ad, dict):
            continue
        link = ad.get("link") or ""
        rec = {k: ad.get(k) for k in ("position", "block_position", "title", "displayed_link",
                                      "description", "source") if ad.get(k) not in (None, "")}
        rec["link"] = link
        rec["host"] = strip_www(urllib.parse.urlparse(link).netloc)
        if ad.get("tracking_link"):
            rec["tracking_link"] = ad["tracking_link"]
        p = ad_params(link)
        if p:
            rec["landing_params"] = p
        out["ads"].append(rec)
    out["advertising_hosts"] = uniq([a["host"] for a in out["ads"] if a.get("host")])
    if not out["ads_block_present"]:
        out["ui_url"] = "https://www.google.com/search?" + urllib.parse.urlencode(
            {"q": query, "gl": gl or "", "hl": hl or ""})
        out["note"] = ("the response carried NO sponsored block. That is a fact about this "
                       "response, not about the keyword — Google serves ads inconsistently to "
                       "automated clients, and live testing saw the block absent even for "
                       "high-commercial-intent queries. Do NOT report this as 'nobody is "
                       "advertising against this brand'. Run the search yourself in the target "
                       "market (ui_url), and use the Ads Transparency archive "
                       "(`wp_serp.py advertiser <domain>`) for the reliable answer.")
    return out


# --------------------------------------------------------------------------- pivots
def _policy(kind: str, field: str, default):
    node = CLUSTERING_POLICY.get(kind) or {}
    return node.get(field, default)


def advertiser_pivots(advertisers: list, seed_host: str = "", region: str = None) -> list:
    """Ready-to-run pivots for a resolved advertiser: the account id, the funded-by legal name, and
    every other domain that account advertised.

    The funded-by name is worth as much as the id and is easy to under-use: it is a name Google
    VERIFIED against documents, so it is the string to run through a corporate registry and through
    reverse-WHOIS — the one place an operator's real-world identity and their infrastructure can be
    made to meet."""
    out = []
    for adv in advertisers or []:
        aid = adv.get("advertiser_id")
        if not aid:
            continue
        agency = adv.get("agency_shaped")
        urls = transparency_urls(advertiser_id=aid, region=region)
        out.append({
            "kind": "ads:advertiser_id", "value": aid,
            "confidence": "medium" if agency else _policy("advertiser_id", "confidence", "high"),
            "note": ("Google Ads Transparency advertiser account — a VERIFIED, paying identity that "
                     "survives domain rotation, because an operator does not re-verify a new ad "
                     "account for each throwaway host. Reverse it for every other domain this "
                     "account advertised: same-PAYER evidence."
                     + (" " + adv["agency_note"] if agency and adv.get("agency_note") else "")),
            "queries": [
                {"service": "Ads Transparency Center (UI, free)", "query": urls.get("advertiser", "")},
                {"service": "SerpApi", "query": f"engine=google_ads_transparency_center&advertiser_id={aid}"},
                {"service": "wp_serp", "query": f"python3 wp_serp.py creatives {aid}"},
            ],
        })
        name = (adv.get("advertiser") or "").strip()
        if name:
            out.append({
                "kind": "ads:advertiser", "value": name,
                "confidence": _policy("ad_funded_by", "confidence", "high"),
                "note": ("The legal name the ads are funded by — verified by Google against "
                         "identity documents before the account could spend. Run it through the "
                         "corporate registry of the stated country and through reverse-WHOIS: this "
                         "is where a real-world identity and the infrastructure meet."),
                "queries": [
                    {"service": "reverse-WHOIS (name)", "query": name},
                    {"service": "Google", "query": f'"{name}"'},
                    {"service": "OpenCorporates", "query": f"https://opencorporates.com/companies?q="
                                                           f"{urllib.parse.quote(name)}"},
                ],
            })
        for dom in adv.get("target_domains") or []:
            if not dom or dom == strip_www(seed_host or ""):
                continue
            out.append({
                "kind": "ads:co_advertised_domain", "value": dom,
                "confidence": "low" if agency else "medium",
                "note": (f"Advertised by the same account ({aid}) as the seed. "
                         + ("That account is agency-shaped, so treat this as a lead to collect, "
                            "not as an operator link." if agency else
                            "One verified billing identity paid to drive traffic to both — a "
                            "same-payer link. Collect it and corroborate with a second artifact "
                            "class before calling it one operator.")),
                "queries": [{"service": "WebPivot", "query": f"pivot_extract https://{dom}/"}],
            })
    return out


def ad_param_pivots(url: str, host: str = "") -> list:
    """Pivots from the advertising parameters on a URL.

    Deliberately narrow. `utm_*` values are already emitted as `affiliate:<param>` pivots by
    wp_pivots (one owner per artifact class), and a click id is unique per click and pivots to
    nothing. What is left, and what nothing else in the toolkit reads, are the Google ValueTrack
    ACCOUNT OBJECT ids: `campaignid`, `adgroupid`, `creative` are integers allocated inside ONE ad
    account, so the same value on two unrelated-looking domains means one account paid for both.
    They are also short numbers, hence the requirement that the parameter NAME match too and the
    medium ceiling."""
    out, found = [], ad_params(url)
    for name, rec in found.items():
        if name not in ACCOUNT_OBJECT_PARAMS or rec.get("generic"):
            continue
        out.append({
            "kind": f"ads:{name}", "value": rec["value"],
            "confidence": _policy("campaign_object_id", "confidence", "medium"),
            "note": ("Google Ads ValueTrack object id — allocated inside ONE advertiser account, so "
                     "the same value under the same parameter name on another domain means the "
                     "same ad account paid for both. Short numeric value: require the parameter "
                     "name to match, and treat a lone hit as a lead."),
            "queries": [
                {"service": "urlscan.io", "query": f'page.url:"{name}={rec["value"]}"'},
                {"service": "Google/Bing dork", "query": f'inurl:"{name}={rec["value"]}"'},
                {"service": "PublicWWW", "query": f'"{name}={rec["value"]}"'},
            ],
        })
    arrival = paid_arrival(url)
    if arrival["is_paid_click"]:
        out.append({
            "kind": "ads:paid_arrival", "value": ",".join(arrival["platforms"]) or "paid",
            "confidence": "informational",
            "note": ("This URL carries an ad-platform click id, so the visit it describes was PAID "
                     "traffic, not a search result — the operator is buying victims. Two "
                     "consequences: the advertiser is resolvable in the Ads Transparency Center, "
                     "and the page may serve its real content only to arrivals like this one (run "
                     "the cloaking probe). The click id VALUE is unique per click and is never a "
                     "pivot."),
            "queries": [{"service": "wp_serp", "query": f"python3 wp_serp.py advertiser "
                                                        f"{strip_www(host) or '<domain>'}"}],
        })
    return out


def cloaking_pivots(report: dict, host: str = "") -> list:
    """The cloaking verdict as a finding. Not a link between domains — a property of this page, and
    one that belongs in an assessment on its own: serving reviewers a decoy and victims a scam is
    deliberate evasion, and it is evidence of intent rather than of identity."""
    if not report or report.get("verdict") != "divergent":
        return []
    return [{
        "kind": "ads:cloaking", "value": f"click-keyed cloaking on {strip_www(host) or report.get('url')}",
        "confidence": _policy("cloaking_observed", "confidence", "high"),
        "note": (report.get("note", "") + " Signals: " + "; ".join(report.get("signals") or [])),
        "queries": [{"service": "WebPivot (collect the REAL page)",
                     "query": f"pivot_extract '{report.get('unlock_url')}'"},
                    {"service": "urlscan.io", "query": f'page.domain:"{strip_www(host)}"'}],
    }]


# --------------------------------------------------------------------------- pivot_extract entry
def has_ad_evidence(result: dict) -> dict:
    """Is there any reason to believe this target buys ads? Returns {found: bool, reasons: [...]}.

    Used to decide whether the metered lookup and the extra probe requests are proportionate. Four
    independent tells: a Google Ads conversion id (`AW-`) in the page, an AdSense publisher id or an
    ads.txt (this site MONETISES ads, which is adjacent and usually worth the look), advertising
    parameters on the URL we were given, and a redirect chain that passed through an ad click
    tracker."""
    reasons = []
    art = (result or {}).get("artifacts") or {}
    meta = (result or {}).get("meta") or {}
    trackers = art.get("trackers") or {}
    if trackers.get("google_ads"):
        reasons.append(f"Google Ads conversion id in the page ({trackers['google_ads'][0]})")
    if trackers.get("google_adsense"):
        reasons.append("AdSense publisher id in the page")
    if (art.get("well_known") or {}).get("ads_txt") or art.get("ads_txt"):
        reasons.append("ads.txt is published")
    urls = [meta.get("source_url"), meta.get("final_url")]
    urls += [h.get("to") for h in (meta.get("redirect_chain") or []) if isinstance(h, dict)]
    for u in urls:
        if u and ad_params(u):
            reasons.append(f"advertising parameters on the URL ({', '.join(sorted(ad_params(u)))})")
            break
    return {"found": bool(reasons), "reasons": reasons}


def enrich_result(result: dict, region: str = None, details: int = 1, free_only: bool = False,
                  timeout: int = 30) -> dict:
    """Run the METERED advertising layer over a collected result and fold it in.

    Adds `result["advertising"]` (the advertiser records, their co-advertised domains, and any
    creative destination link that was opened) and appends the pivots. Returns the advertising block
    so a caller can decide what to do next — in particular, a `landing_params` here is the operator's
    real cloaking key and is what the probe should be re-run with."""
    if free_only or not serpapi_configured():
        return {}
    host = strip_www((result.get("meta") or {}).get("host") or "")
    if not host:
        return {}
    block = advertiser_search(host, region=region, timeout=timeout)
    advs = block.get("advertisers") or []
    # Open one creative per advertiser, cheapest first: the destination link is the only thing here
    # that changes what we COLLECT rather than what we know, so it earns the extra search.
    opened = []
    for adv in advs[:max(0, int(details))]:
        cid = (adv.get("creative_ids") or [None])[0]
        if not cid:
            continue
        det = creative_details(adv["advertiser_id"], cid, region=region, timeout=timeout)
        # Keep it for ANY of the three things a detail call actually buys, not just the link. Gating
        # on `link` threw away the reliable half — the verified legal entity and the dated market
        # list — every time the archive stored the ad as a rendered image, which is most of the time.
        if det.get("ad_funded_by") or det.get("markets") or det.get("link"):
            opened.append(det)
    if opened:
        block["creatives_opened"] = opened
        # The markets the account actually bought traffic in — target-selection evidence, and the
        # answer to "which region should the next archive query use".
        block["markets"] = uniq([m for det in opened for m in (det.get("markets") or [])])
    result["advertising"] = block
    pivots = advertiser_pivots(advs, seed_host=host, region=region)
    for det in opened:
        pivots += ad_param_pivots(det.get("link") or "", host=host)
        # The LEGAL ENTITY name from the creative is often more precise than the display name on the
        # search result ("<Brand> B.V." vs "<Brand>"), and precision is the whole point when the
        # next step is a corporate registry — so it is emitted separately rather than deduped away.
        funded = (det.get("ad_funded_by") or "").strip()
        if funded and funded not in {(a.get("advertiser") or "").strip() for a in advs}:
            pivots.append({
                "kind": "ads:advertiser", "value": funded,
                "confidence": _policy("ad_funded_by", "confidence", "high"),
                "note": ("The legal entity Google verified before this account could spend — taken "
                         "from the creative itself, and usually more precise than the advertiser's "
                         "display name. This is the string to run through the corporate registry of "
                         "the stated country and through reverse-WHOIS."),
                "queries": [{"service": "reverse-WHOIS (name)", "query": funded},
                            {"service": "Google", "query": f'"{funded}"'},
                            {"service": "OpenCorporates",
                             "query": "https://opencorporates.com/companies?q="
                                      + urllib.parse.quote(funded)}],
            })
    if pivots:
        result.setdefault("pivots", []).extend(pivots)
    return block


# --------------------------------------------------------------------------- capability disclosure
def capability(free_only: bool = False) -> dict:
    """What THIS run's advertising layer can do — same contract as wp_capabilities / wp_intelx, so
    the statement can be pasted into an assessment's collection-limitations note verbatim.

    Keyless is genuinely more than half here, and the split is unusual: the CLOAKING PROBE — the
    part that changes which page gets collected — needs no key at all, while the archive lookup that
    names the advertiser needs one. So a keyless run can still catch the evasion and still fail to
    name the payer."""
    keyed = bool(serpapi_key()) and not free_only
    if keyed:
        return {"layer": "serpapi", "mode": "keyed", "power_pct": 100,
                "available": ["Ads Transparency Center lookup by domain (who advertises it)",
                              "reverse advertiser_id -> every domain that account advertised",
                              "creative destination links — the operator's own campaign tagging",
                              "live SERP ads block (who is buying a brand keyword right now)",
                              "the free click-keyed cloaking probe"],
                "unavailable": [],
                "statement": "Ads Transparency Center queried live — advertiser identity, "
                             "co-advertised domains and campaign tagging are covered."}
    why = ("--free-only suppressed the metered SerpApi calls" if free_only
           else "no SERPAPI_KEY is configured")
    return {
        "layer": "serpapi", "mode": "free-only" if free_only else "keyless", "power_pct": 55,
        "available": ["the CLICK-KEYED CLOAKING PROBE in full — it is plain HTTP to the target and "
                      "costs nothing",
                      "classification of every advertising parameter (click id / campaign / "
                      "ValueTrack account object id) and its base rate",
                      "the Ads Transparency Center web address for the domain and for any "
                      "advertiser id, which shows the same data by hand and free"],
        "unavailable": ["the advertiser identity itself — advertiser_id and the verified "
                        "'ad funded by' legal name",
                        "the reverse: every OTHER domain that ad account advertised",
                        "the ad creative's destination link, i.e. the operator's real campaign "
                        "tagging (the best possible cloaking key)",
                        "the live SERP ads block for a brand keyword"],
        "statement": (f"COLLECTION LIMITATION — the advertising layer ran at roughly 55%: {why}, so "
                      f"the Ads Transparency Center archive was NOT queried. This run establishes "
                      f"nothing about whether the domain advertises, who paid for it, or what else "
                      f"that account advertised; 'no advertiser found' here means 'never asked'. "
                      f"The cloaking probe is unaffected and its verdict stands. Open the emitted "
                      f"adstransparency.google.com URL by hand, or set SERPAPI_KEY."),
    }


def banner_lines(free_only: bool = False) -> list:
    """The stderr block for a keyless/free-only advertising layer. Empty when keyed."""
    cap = capability(free_only=free_only)
    if cap["power_pct"] >= 100:
        return []
    return [f"[!] ADS/SERP: {cap['mode'].upper()} — ~{cap['power_pct']}% capability.",
            f"    lost:    {cap['unavailable'][0]}; {cap['unavailable'][1]}",
            f"    kept:    {cap['available'][0]}",
            f"    instead: {cap['available'][2]}",
            "    get a key: https://serpapi.com/ (free tier: 100 searches/month)"]


__all__ = ["serpapi_key", "serpapi_configured", "region_codes", "transparency_urls",
           "ad_params", "paid_arrival", "is_generic_value", "strip_ad_params", "unlock_params",
           "unlock_url", "cloak_probe", "advertiser_search", "advertiser_creatives",
           "creative_details", "serp_ads", "advertiser_pivots", "ad_param_pivots",
           "cloaking_pivots", "has_ad_evidence", "enrich_result", "capability", "banner_lines",
           "parse_ad_params",
           "budget_status", "month_spent", "account_status",
           "ENDPOINTS", "ENGINES", "AD_PARAMETERS", "GENERIC_VALUES", "PROBE_PARAMS",
           "PROBE_HEADERS",
           "CLOAKING_PROBE", "CLUSTERING_POLICY", "REGIONS", "CREDIT_COSTS", "SEARCH_BUDGET",
           "RESULT_LIMITS", "CLICK_ID_PARAMS", "CLOAK_KEY_PARAMS", "PIVOTABLE_PARAMS",
           "ACCOUNT_OBJECT_PARAMS", "ALL_AD_PARAMS"]


# --------------------------------------------------------------------------- CLI
def main():
    ap = argparse.ArgumentParser(
        description="Advertising layer: Google Ads Transparency (SerpApi) + click-keyed cloaking probe")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("advertiser", help="who advertises this DOMAIN (Ads Transparency Center)")
    p.add_argument("domain")
    p.add_argument("--region", default=None, help="ISO-2 (VN, US) or a numeric geotarget; default anywhere")
    p.add_argument("--details", type=int, default=0,
                   help="also open N creatives per advertiser for their destination link (extra searches)")

    p = sub.add_parser("creatives", help="reverse an ADVERTISER ID to every domain it advertised")
    p.add_argument("advertiser_id")
    p.add_argument("--region", default=None)
    p.add_argument("--details", type=int, default=0)

    p = sub.add_parser("serp", help="who is BUYING this keyword right now (live SERP ads block)")
    p.add_argument("query")
    p.add_argument("--gl", default=None, help="country of the search, e.g. vn")
    p.add_argument("--hl", default=None, help="interface language, e.g. vi")
    p.add_argument("--location", default=None)

    p = sub.add_parser("params", help="offline: classify the advertising parameters on a URL")
    p.add_argument("url")

    p = sub.add_parser("cloak", help="free: does this page cloak on the ad click?")
    p.add_argument("url")
    p.add_argument("--ad-params", default=None, metavar="SPEC",
                   help="the ad's own parameters — a full landing URL or 'k=v&k=v'")
    p.add_argument("--proxy", default=None)
    p.add_argument("--ua", default=DEFAULT_UA)
    p.add_argument("--timeout", type=int, default=None)

    sub.add_parser("budget", help="this month's SerpApi search budget (ledger + live quota)")
    sub.add_parser("keycheck", help="is a SERPAPI_KEY configured, and what does its absence cost?")

    args = ap.parse_args()

    if args.cmd == "advertiser":
        out = advertiser_search(args.domain, region=args.region)
        if args.details:
            out["creatives_opened"] = [
                creative_details(a["advertiser_id"], cid, region=args.region)
                for a in out.get("advertisers", [])
                for cid in (a.get("creative_ids") or [])[:args.details]]
        out["pivots"] = advertiser_pivots(out.get("advertisers"), seed_host=args.domain,
                                          region=args.region)
    elif args.cmd == "creatives":
        out = advertiser_creatives(args.advertiser_id, region=args.region)
        if args.details:
            out["creatives_opened"] = [
                creative_details(a["advertiser_id"], cid, region=args.region)
                for a in out.get("advertisers", [])
                for cid in (a.get("creative_ids") or [])[:args.details]]
        out["pivots"] = advertiser_pivots(out.get("advertisers"), region=args.region)
    elif args.cmd == "serp":
        out = serp_ads(args.query, gl=args.gl, hl=args.hl, location=args.location)
    elif args.cmd == "params":
        out = paid_arrival(args.url)
        out["stripped_url"] = strip_ad_params(args.url)
        out["unlock_url"] = unlock_url(args.url)
        out["pivots"] = ad_param_pivots(args.url)
    elif args.cmd == "cloak":
        out = cloak_probe(args.url, extra_params=parse_ad_params(args.ad_params),
                          ua=args.ua, proxy=args.proxy, timeout=args.timeout)
        out["pivots"] = cloaking_pivots(out, host=urllib.parse.urlparse(args.url).netloc)
    elif args.cmd == "budget":
        out = budget_status()
        live, err = account_status()
        out["live_account"] = live or err
        # Reconcile the two numbers, because they measure different things and only one is
        # authoritative. The ledger counts what THIS toolkit spent; the account counts everything —
        # a search run in the SerpApi playground, another script, a second machine. When they
        # disagree the guard is working off an under-count, and the analyst should be told which
        # number to believe rather than discovering the gap as an HTTP 429 mid-case.
        if live and live.get("this_month_usage") is not None:
            drift = int(live["this_month_usage"]) - int(out["spent_this_month"])
            out["reconciliation"] = {
                "ledger_spent_this_month": out["spent_this_month"],
                "account_spent_this_month": live["this_month_usage"],
                "unledgered": drift,
                "authoritative_remaining": live.get("total_searches_left"),
                "note": ("the ACCOUNT figure is authoritative — the ledger only sees calls made "
                         "through this toolkit. " +
                         (f"{drift} search(es) this month were spent elsewhere; the local guard is "
                          f"running on an under-count, so set SERPAPI_MONTHLY_SEARCHES (or edit "
                          f"references/serpapi.json -> search_budget.monthly_searches) if the "
                          f"account's grant differs from {out['monthly_searches']}."
                          if drift > 0 else "ledger and account agree.")),
            }
            grant = live.get("searches_per_month")
            if grant and int(grant) != int(out["monthly_searches"]):
                out["reconciliation"]["grant_mismatch"] = (
                    f"the account's plan grants {grant} searches/month but the guard is enforcing "
                    f"{out['monthly_searches']} — update search_budget.monthly_searches, or the "
                    f"guard will refuse calls you have already paid for.")
    else:
        out = capability()

    for line in banner_lines():
        print(line, file=sys.stderr)
    print(json.dumps(out, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
