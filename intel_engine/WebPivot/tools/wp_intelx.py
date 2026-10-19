#!/usr/bin/env python3
"""wp_intelx — Intelligence X (intelx.io) SELECTOR search + keyless query builder for WebPivot.

WHAT INTELX ADDS THAT THE OTHER ENGINES DON'T
---------------------------------------------
FOFA/Censys/urlscan answer "who else is running this infrastructure". IntelX answers a different
question — "where else has this SELECTOR been seen" — over a corpus none of the others index:
breach dumps, infostealer logs, pastes, darknet mirrors, historical WHOIS snapshots and its own web
crawl. Three of its moves have no substitute in the rest of the toolkit:

  - **phonebook(domain)** -> every email address, subdomain and URL IntelX has ever seen under an
    apex. Point it at a case domain and it hands back the exact artifact classes the rest of
    WebPivot pivots on. This is the layer's highest-value call — and it is PAID-only.
  - **search(email | phone)** -> the operator's own contact selector in pastes, forum posts and
    darknet listings, frequently alongside their advertising copy. A support phone or a registrant
    address that turns up in a market listing is attribution the DNS/TLS layer cannot reach.
  - **the `whois` bucket** -> historical registrant snapshots from an index that is not WhoisXML,
    i.e. a genuinely independent second source for a registrant selector.

IntelX takes STRONG SELECTORS ONLY — an email, a domain (wildcards allowed), a URL, an IP/CIDR, a
phone number, a wallet, a MAC/UUID/IBAN/credit-card. A brand name or a person's name is a *soft*
selector: the API refuses it, and the attempt still spends a search. `classify_selector()` enforces
that locally so a refused query is never even sent.

WHAT A HIT DOES AND DOES NOT PROVE — READ BEFORE CLUSTERING
-----------------------------------------------------------
IntelX answers a question about EXPOSURE, not about ownership. Two addresses in the same combolist
share a victim population, not an operator, and clustering on breach co-membership manufactures
exactly the kind of false edge the KB's noise filters exist to kill. The buckets that carry an
ownership signal (`whois`, `pastes`, the darknet mirrors) are listed in
`references/intelx.json -> clustering_policy.cluster_on`; everything else is context, a date anchor,
or a lead for the victim layer. `summarise_record()` stamps every record with that judgement so the
distinction survives into the case file.

BUT THE BUCKETS ARE NOT INTERCHANGEABLE — LOGS BEAT DUMPS
----------------------------------------------------------
"Not an automatic operator edge" and "not worth reading" are different claims, and collapsing them
throws away the best material IntelX has. A **breach dump** is one site's user table: an address
and a year, recycled through dozens of combolists, usually stale before it is public — skim it for
the DATE and move on. An **infostealer log** is one machine at one moment: the URL/user/password
triple with its session context, cookies and autofill. That is a different class of fact —

  - it dates the compromise to a specific host rather than to a corpus;
  - it exposes ADMIN/PANEL URLs the public site never links, which is direct input to the
    victim/access-vector layer;
  - and operators get infected too. A log whose machine holds the campaign's own panel URL and
    credentials is attribution, not exposure.

So the logs are QUERIED FIRST, not merely sorted first. IntelX returns a bounded page, and on a
long-exposed selector the recycled combolist rows fill it — the one infostealer record is truncated
away before any sort can reach it. `search()` therefore runs a bucket-scoped pass over
`leaks.logs` and only then the general pass (`search_plan` in the reference file; one unit each,
and when the budget allows only one, the logs pass is the one that runs). `logs_pass` records
whether that happened, which is what makes an empty `read_these` a real negative. Hits come back
separately as `read_these` / `stealer_log_items` — items to OPEN one by one and ask *whose machine
is this*, even though the corpus itself can never carry an automatic edge. Handle them as real
victim credentials: cite metadata, never paste secrets into a case file.

AND SEARCH THE DOMAIN, NOT JUST THE CONTACTS
---------------------------------------------
A stealer-log record is indexed by the URL the malware captured, so the CASE DOMAIN is a first-class
IntelX selector, not an afterthought: searching it returns the machines that held credentials FOR
that domain — the campaign's victims, the admin/panel URLs the public site never links, and, when
the operator logged into their own panel from an infected box, the operator's own machine. So
`search_plan.selector_priority` spends the allowance on the DOMAIN and the EMAIL first (the seed
host ahead of any discovered sibling), and the contact artifacts after them.

KEYLESS IS A SUPPORTED MODE — AND IT IS ABOUT HALF THE LAYER
-------------------------------------------------------------
With no `INTELX_KEY` this module still classifies the selector and emits the ready-to-run
intelx.io / phonebook.cz URL for every artifact WebPivot extracted, so an analyst with a free web
account can run the identical selector by hand. What is lost is everything automatic: the records
themselves, the phonebook inventory, item content, and the ability to fold newly-discovered emails/
subdomains back into the case. `capability()` reports that as **~50% of full capability**, and the
banner says it out loud — because an IntelX section that is absent must never read as "the operator
appears in no leak, paste or darknet listing".

CREDITS
-------
Searches are metered (a free key gets a small allowance; a paid key spends credits) and running out
is SILENT from the analyst's side — the search just returns nothing. So spend is counted from
`MEMORY/api_usage.jsonl` per run and per month. The shipped policy warns at/over those thresholds
but does not block; the vendor's 402/429 is the real limit. Set `block_when_exhausted: true` in
`references/intelx.json -> search_budget` for strict refusal. Thresholds are DATA and remain
overridable with `INTELX_MAX_SEARCHES_PER_RUN` / `INTELX_MONTHLY_SEARCHES`.

Auth: `INTELX_KEY` (Account -> Developer tab), sent as the `x-key` header. `INTELX_BASE_URL`
overrides the API root when your account is issued against a different instance.

CLI:
  python3 wp_intelx.py search registrant@example.com          # logs pass + general pass (2 units)
  python3 wp_intelx.py search example.com --logs-only         # 1 unit: whose machine held creds?
  python3 wp_intelx.py search example.com --deadline 300      # override the bucket-proportional deadline
  python3 wp_intelx.py item <storageid> --bucket leaks.logs   # OPEN one record: bounded, redacted preview
  python3 wp_intelx.py search example.com --no-logs-first     # 1 unit, general only (noisier)
  python3 wp_intelx.py phonebook example.com [--target emails]   # PAID endpoint
  python3 wp_intelx.py query example.com          # OFFLINE — selector class + UI URLs, no key
  python3 wp_intelx.py caps                       # what this key is entitled to
  python3 wp_intelx.py budget                     # OFFLINE — this month's search spend
"""
import argparse
import copy
import concurrent.futures
import datetime
import json
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from wp_common import *  # noqa — DEFAULT_UA, _secret, uniq, strip_www
from wp_refs import ref_path, load_ref  # noqa — reference DATA lives in references/*.json

try:
    import api_usage                      # licensed-API credit ledger
except Exception:
    api_usage = None

DEFAULT_API_ROOT = "https://2.intelx.io"

# --- reference DATA (RULE 3): endpoints, selector patterns, bucket grading and the spend guard are
#     IntelX product facts that change without our code changing. The fallback below is the minimum
#     that keeps the KEYLESS builder honest if the JSON goes missing — load_ref warns loudly.
_INTELX_FALLBACK = {
    "endpoints": {"search_start": "/intelligent/search", "search_result": "/intelligent/search/result",
                  "search_terminate": "/intelligent/search/terminate",
                  "phonebook_start": "/phonebook/search", "phonebook_result": "/phonebook/search/result",
                  "capabilities": "/authenticate/info", "item_selectors": "/item/selector/list/human",
                  "file_preview": "/file/preview"},
    "search_status": {"0": "results", "1": "complete", "2": "unknown id", "3": "still aggregating"},
    "selector_types": {
        "email": {"regex": r"^[^@\s]+@[a-z0-9.-]+\.[a-z]{2,}$", "strong": True},
        "url": {"regex": r"^https?://\S+$", "strong": True},
        "ipv4": {"regex": r"^(?:\d{1,3}\.){3}\d{1,3}$", "strong": True},
        "phone": {"regex": r"^\+?[0-9][0-9 ().-]{6,20}$", "strong": True},
        "domain": {"regex": r"^(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$", "strong": True},
    },
    "pivot_kind_map": {"email": "email", "phone": "phone", "domain": "domain", "ip": "ipv4"},
    # Conservative but NOT neutral: even on a broken data file the logs pass still runs first and
    # the domain/email selectors are still spent first, because the failure this ordering prevents
    # (combolist rows truncating the one stealer-log record out of the page) is silent.
    "search_plan": {"logs_first": True, "first_pass_buckets": ["leaks.logs"],
                    "selector_priority": ["domain", "email", "url", "phone", "ipv4"]},
    "buckets": {},
    "media_types": {},
    "phonebook_targets": {"all": 0, "domains": 1, "emails": 2, "urls": 3},
    "selector_result_types": {"1": "email", "2": "domain", "3": "url", "23": "url query"},
    "plan_capabilities": {"none": {"search": False, "phonebook": False, "file_read": False}},
    # Deliberately the CONSERVATIVE minimum: a broken data file must not silently unlock a bigger
    # spend than the analyst signed up for.
    "search_budget": {"daily_searches": 500, "monthly_searches": 500, "max_searches_per_run": 25,
                      "warn_at_remaining": 50, "phonebook_costs": 5, "search_costs": 1,
                      "preview_costs": 1, "block_when_exhausted": True},
    # The deadline knobs are conservative in the OTHER direction: a missing data file must never
    # cut a slow-but-live search short, so the fallback is generous and the cap is high.
    "result_limits": {"max_records": 200, "max_selectors": 500, "poll_attempts": 8,
                      "poll_sleep_seconds": 1, "search_timeout_seconds": 5, "preview_lines": 8,
                      "preview_max_chars": 2000,
                      "max_concurrent_searches": 4, "http_timeout_seconds": 30,
                      "deadline_base_seconds": 180, "deadline_per_bucket_seconds": 120,
                      "deadline_all_buckets_weight": 3, "deadline_max_seconds": 900},
    "ui_templates": {"search": "https://intelx.io/?s={term}", "phonebook": "https://phonebook.cz/?q={term}",
                     "item": "https://intelx.io/?did={term}", "signup": "https://intelx.io/signup"},
    # Fails CLOSED: with no readable policy the module clusters on nothing, which costs leads but
    # never manufactures an operator link out of a shared breach corpus.
    "clustering_policy": {"cluster_on": [], "never_cluster_on": []},
}
_REFS = load_ref(ref_path(__file__, "intelx.json"), _INTELX_FALLBACK)
ENDPOINTS = _REFS["endpoints"]
SEARCH_STATUS = _REFS["search_status"]
SELECTOR_TYPES = _REFS["selector_types"]
PIVOT_KIND_MAP = _REFS["pivot_kind_map"]
SEARCH_PLAN = _REFS["search_plan"]
BUCKETS = _REFS["buckets"]
MEDIA_TYPES = _REFS["media_types"]
PHONEBOOK_TARGETS = _REFS["phonebook_targets"]
SELECTOR_RESULT_TYPES = _REFS["selector_result_types"]
PLAN_CAPABILITIES = _REFS["plan_capabilities"]
SEARCH_BUDGET = _REFS["search_budget"]
RESULT_LIMITS = _REFS["result_limits"]
UI_TEMPLATES = _REFS["ui_templates"]
CLUSTERING_POLICY = _REFS["clustering_policy"]

# One process = one case: paying twice for the same selector inside a run is real spend.
_MEMO = {}
_MEMO_LOCK = threading.Lock()

# Master off switch, flipped by `pivot_extract --no-intelx`. Only the NETWORK calls honour it — the
# selector classifier and the UI-link builder are offline and free, so they keep working either way.
ENABLED = True


# --------------------------------------------------------------------------- auth / transport
def intelx_key():
    """The IntelX API key, or None. `INTELX_KEY` is the name Setup.md documents; the aliases are
    what analysts who came from other wrappers tend to export."""
    return _secret("INTELX_KEY", "INTELX_API_KEY", "INTELLIGENCEX_KEY")


def api_root() -> str:
    """The account's API instance. A normal API key answers on 2.intelx.io; free/public keys are
    issued against a different host, which the Developer tab shows — hence the override."""
    return (_secret("INTELX_BASE_URL", "INTELX_API_ROOT") or DEFAULT_API_ROOT).rstrip("/")


def intelx_configured() -> bool:
    """True when a key is available and IntelX isn't switched off — the gate every network call
    checks before spending a search."""
    return ENABLED and bool(intelx_key())


def _headers():
    h = {"User-Agent": DEFAULT_UA, "Accept": "application/json"}
    key = intelx_key()
    if key:
        h["x-key"] = key
    return h


# HTTP status -> the analyst-readable reason. The point is that a free-key 402 on /phonebook reads
# as "your entitlement does not include this call, here is the UI link" and NOT as a bare error.
_STATUS_REASON = {
    400: "IntelX rejected the request — usually a SOFT selector (a brand or person name); IntelX "
         "searches strong selectors only (email/domain/URL/IP/phone/wallet/MAC/UUID/IBAN)",
    401: "IntelX rejected the key (INTELX_KEY missing, expired, or issued for a different API root "
         "— check the Developer tab and set INTELX_BASE_URL if your instance differs)",
    402: "IntelX: insufficient credits / entitlement — the phonebook endpoint and item content are "
         "PAID-only; a free key gets metadata search and the web UI",
    403: "IntelX: your account is not entitled to this endpoint",
    404: "not in the IntelX dataset",
    429: "IntelX rate limit — the client already paces itself at 1 request/second",
}


def _call(path: str, *, method: str = "GET", params: dict = None, body: dict = None,
          timeout: int = 30, raw: bool = False):
    """One IntelX API call -> (data, error_dict). Never raises.

    `error_dict` is `{"skipped": reason}` for the entitlement/credit/auth conditions the caller is
    expected to survive, and `{"error": ...}` for anything genuinely unexpected. `raw=True` returns
    the body as text (the file endpoints answer with content, not JSON)."""
    if not intelx_configured():
        return None, {"skipped": "no INTELX_KEY configured"}
    url = api_root() + path
    if params:
        url += "?" + urllib.parse.urlencode({k: v for k, v in params.items() if v not in (None, "")})
    data = json.dumps(body).encode() if body is not None else None
    headers = _headers()
    if data:
        headers["Content-Type"] = "application/json"
    try:
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw_body = r.read().decode("utf-8", "replace")
            if raw:
                return raw_body, None
            try:
                return json.loads(raw_body), None
            except ValueError:
                return {"raw": raw_body}, None
    except urllib.error.HTTPError as e:
        reason = _STATUS_REASON.get(e.code)
        msg = f"HTTP {e.code}" + (f" — {reason}" if reason else "")
        if e.code in _STATUS_REASON:
            return None, {"skipped": msg}
        return None, {"error": msg}
    except Exception as e:                              # network/timeout
        return None, {"error": str(e)}


def _record(action: str, credits: int, query: str, results=None, ok: bool = True):
    if credits:
        _spend(credits)
    if api_usage:
        api_usage.record("intelx", action, credits=credits, query=query, results=results, ok=ok)


# --------------------------------------------------------------------------- search BUDGET ledger
# Running out of IntelX searches is silent from the analyst's side: the call returns nothing, and an
# empty result reads as "this selector appears in no leak". Spend is therefore tracked against the
# shared ledger and threshold breaches are reported before the call. Shipped policy is advisory;
# `block_when_exhausted: true` makes the same thresholds strict.
_RUN_SPENT = 0
_MONTH_SPENT = None          # summed from the ledger once per process
_DAY_SPENT = None            # summed from the ledger once per process (this UTC day)
_WARNED = set()
_BUDGET_LOCK = threading.Lock()


def _budget(key: str, env: str = None, default=0):
    if env:
        raw = _secret(env)
        if raw:
            try:
                return int(float(raw))
            except ValueError:
                print(f"[intelx] WARNING: {env}={raw!r} is not a number; using the reference value.",
                      file=sys.stderr)
    return SEARCH_BUDGET.get(key, default)


def _ledger_path():
    if api_usage:
        return api_usage._log_path()
    return _secret("API_USAGE_LOG") or os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "MEMORY", "api_usage.jsonl")


def month_spent(refresh: bool = False) -> int:
    """IntelX search units already spent this UTC month, read from the api_usage ledger — every
    tool and every case, since the allowance is per ACCOUNT. Unreadable ledger -> 0 (never block
    work because a log is missing)."""
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
                if not line or '"intelx"' not in line:
                    continue
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                if rec.get("provider") == "intelx" and (rec.get("ts") or "").startswith(month):
                    total += rec.get("credits") or 0
    except FileNotFoundError:
        total = 0
    except Exception as exc:
        print(f"[intelx] WARNING: could not read the usage ledger ({exc}); the monthly guard is "
              f"running on this process's spend only.", file=sys.stderr)
        total = 0
    with _BUDGET_LOCK:
        _MONTH_SPENT = total
    return total


def day_spent(refresh: bool = False) -> int:
    """IntelX search units spent so far this UTC DAY, read from the shared api_usage ledger — every
    tool and case, since the allowance is per ACCOUNT. Unreadable ledger -> 0 (never block work
    because a log is missing)."""
    global _DAY_SPENT
    with _BUDGET_LOCK:
        if _DAY_SPENT is not None and not refresh:
            return _DAY_SPENT
    day = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
    total = 0
    try:
        with open(_ledger_path(), encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or '"intelx"' not in line:
                    continue
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                if rec.get("provider") == "intelx" and (rec.get("ts") or "").startswith(day):
                    total += rec.get("credits") or 0
    except FileNotFoundError:
        total = 0
    except Exception as exc:
        print(f"[intelx] WARNING: could not read the usage ledger ({exc}); the daily guard is "
              f"running on this process's spend only.", file=sys.stderr)
        total = 0
    with _BUDGET_LOCK:
        _DAY_SPENT = total
    return total


def _spend(units: int) -> None:
    global _RUN_SPENT, _MONTH_SPENT, _DAY_SPENT
    with _BUDGET_LOCK:
        _RUN_SPENT += units
        if _MONTH_SPENT is not None:
            _MONTH_SPENT += units
        if _DAY_SPENT is not None:
            _DAY_SPENT += units


def budget_status() -> dict:
    """Where the IntelX search allowance stands — the numbers to quote when reporting cost."""
    limit = _budget("monthly_searches", "INTELX_MONTHLY_SEARCHES", 15500)
    day_limit = _budget("daily_searches", "INTELX_DAILY_SEARCHES", 500)
    run_cap = _budget("max_searches_per_run", "INTELX_MAX_SEARCHES_PER_RUN", 50)
    spent = month_spent()
    d_spent = day_spent()
    now = datetime.datetime.now(datetime.timezone.utc)
    return {"monthly_searches": limit, "spent_this_month": spent,
            "remaining_this_month": max(0, limit - spent),
            "daily_searches": day_limit, "spent_today": d_spent,
            "remaining_today": max(0, day_limit - d_spent),
            "spent_this_run": _RUN_SPENT, "max_searches_per_run": run_cap,
            "ledger": _ledger_path(),
            "day": now.strftime("%Y-%m-%d"),
            "month": now.strftime("%Y-%m")}


def _budget_block(cost: int, action: str):
    """None when `cost` units may be spent, else the analyst-readable reason not to. Returned as a
    `skipped` reason, never an exception — the UI link is still the deliverable.

    With `block_when_exhausted: false` the ledger still counts and the balance banner still prints,
    but a cap that would have refused the call is printed once as an advisory and the call proceeds:
    the vendor's own 402/429 (already tri-state) becomes the real limit."""
    b = budget_status()
    if (b["remaining_today"] <= _budget("warn_at_remaining", default=50)
            or b["remaining_this_month"] <= _budget("warn_at_remaining", default=50)) and action not in _WARNED:
        _WARNED.add(action)
        print(f"[intelx] ⚠ {b['remaining_today']} of {b['daily_searches']} daily "
              f"(+{b['remaining_this_month']} of {b['monthly_searches']} monthly) search units left "
              f"({b['spent_today']} spent {b['day']}). Spending {cost} on {action}.", file=sys.stderr)
    reason = None
    if b["spent_this_run"] + cost > b["max_searches_per_run"]:
        reason = (f"per-run IntelX cap reached ({b['spent_this_run']}/{b['max_searches_per_run']} "
                  f"units spent this run; {action} needs {cost}). Raise INTELX_MAX_SEARCHES_PER_RUN "
                  f"for a run that genuinely needs it, or run the emitted selector in the web UI.")
    elif cost > b["remaining_today"]:
        reason = (f"daily IntelX allowance exhausted ({b['spent_today']}/"
                  f"{b['daily_searches']} units on {b['day']}; {action} needs {cost}). Raise "
                  f"INTELX_DAILY_SEARCHES if your plan is larger.")
    elif cost > b["remaining_this_month"]:
        reason = (f"monthly IntelX allowance exhausted ({b['spent_this_month']}/"
                  f"{b['monthly_searches']} units in {b['month']}; {action} needs {cost}). Raise "
                  f"INTELX_MONTHLY_SEARCHES if your plan is larger.")
    if reason is None:
        return None
    if SEARCH_BUDGET.get("block_when_exhausted", True):
        return reason
    key = ("advisory", action)
    if key not in _WARNED:
        _WARNED.add(key)
        print(f"[intelx] ⚠ {reason} (block_when_exhausted is off — proceeding; the vendor quota "
              f"is the limit.)", file=sys.stderr)
    return None


def _store_memo(kind: str, ident: str, val) -> None:
    """Write `val` into both the process cache and the on-disk per-CASE memo (wp_casememo)."""
    with _MEMO_LOCK:
        _MEMO[(kind, ident)] = val
    try:
        import wp_casememo
        wp_casememo.put("intelx", f"{kind}|{ident}", val)      # errors are never memoised (put refuses)
    except Exception:  # noqa: BLE001
        pass


def _cache_get(kind: str, ident: str):
    """The cached value for (kind, ident) — process cache first, then the on-disk per-CASE memo.
    None when neither has it yet."""
    with _MEMO_LOCK:
        if (kind, ident) in _MEMO:
            return copy.deepcopy(_MEMO[(kind, ident)])
    try:
        import wp_casememo
        return wp_casememo.get("intelx", f"{kind}|{ident}")
    except Exception:  # noqa: BLE001
        return None


def _covers(cached, want_passes) -> bool:
    """True when an already-cached SEARCH result already ran every pass THIS call needs — so a
    narrower earlier ask (e.g. email-deep's `--logs-only`) never hides the general pass from a
    later, broader one, and a broader earlier ask (the collector's default logs+general) always
    satisfies a later narrower one."""
    if not isinstance(cached, dict):
        return False
    if cached.get("skipped"):
        return True    # authoritative: no key / soft selector / budget exhausted — asking again
                        # hits the exact same wall, so the skip IS the cached answer
    # A pass cut short by the deadline/poll limit is NOT coverage: reusing it would freeze a
    # partial page into the case memo as if IntelX had finished. Legacy entries lack `complete`.
    ran = {p.get("pass") for p in (cached.get("passes") or [])
           if p.get("ran") and p.get("complete", True)}
    return set(want_passes) <= ran


def _memoised(kind: str, ident: str, fn):
    """Run `fn()` once per (kind, ident) per process — AND once per CASE across the per-host collector
    subprocesses (wp_casememo under $WP_CASE_DIR): the estate's 25 hosts share one registrant e-mail,
    so without the on-disk half every host would buy the same search (and 5-credit phonebook) again.
    Hands back a private copy."""
    cached = _cache_get(kind, ident)
    if cached is not None:
        _store_memo(kind, ident, cached)     # promote a disk hit into the process cache too
        return copy.deepcopy(cached)
    val = fn()
    _store_memo(kind, ident, val)
    return copy.deepcopy(val)


# --------------------------------------------------------------------------- selector handling
def classify_selector(value: str):
    """(selector_class, normalised_value) for a term IntelX can search, else (None, normalised).

    Done LOCALLY and before any call, because IntelX refuses soft selectors with an HTTP 400 that
    still counts against the allowance. Patterns are DATA (references/intelx.json ->
    selector_types) and are tried in file order, so the specific classes match before the loose
    ones."""
    v = (value or "").strip()
    if not v:
        return None, v
    probe = v if "://" in v else v.lower()
    for name, spec in SELECTOR_TYPES.items():
        if not isinstance(spec, dict) or not spec.get("regex"):
            continue
        try:
            if re.match(spec["regex"], probe, re.I):
                return name, (v if name == "url" else probe)
        except re.error as exc:
            print(f"[intelx] WARNING: selector pattern {name!r} is not a valid regex ({exc}); "
                  f"skipping it.", file=sys.stderr)
    return None, probe


def is_searchable(value: str) -> bool:
    """True when IntelX will accept this term as a strong selector."""
    kind, _ = classify_selector(value)
    return bool(kind and (SELECTOR_TYPES.get(kind) or {}).get("strong", True))


def selector_for_kind(kind: str):
    """WebPivot pivot `kind` -> the IntelX selector class, honouring the `prefix:` entries in
    pivot_kind_map. None when IntelX does not index the artifact."""
    if not kind:
        return None
    if kind in PIVOT_KIND_MAP:
        return PIVOT_KIND_MAP[kind]
    for pref, sel in PIVOT_KIND_MAP.items():
        if pref.endswith(":") and kind.startswith(pref):
            return sel
    return None


# --------------------------------------------------------------------------- query BUILDER (keyless)
def intelx_url(term: str, template: str = "search") -> str:
    """The web-UI URL for a selector — what a keyless (or free-plan) analyst clicks."""
    tpl = UI_TEMPLATES.get(template) or "https://intelx.io/?s={term}"
    return tpl.replace("{term}", urllib.parse.quote(str(term or ""), safe=""))


def intelx_queries(kind: str, value, ui: bool = True) -> list:
    """Ready-to-run IntelX entries for a pivot's `queries` list. [] when IntelX cannot search the
    artifact — which is the correct outcome for favicon hashes, tracker IDs and JARM, none of which
    IntelX indexes.

    Keyless-safe: this is pure string building, costs nothing, and is what makes a no-key run still
    worth reading."""
    sel = selector_for_kind(kind)
    if not sel:
        return []
    cls, norm = classify_selector(str(value))
    if not cls:                      # the map said this kind is searchable but the VALUE isn't
        return []
    out = [{"service": f"IntelX ({cls} selector)", "query": norm}]
    if ui:
        out.append({"service": "IntelX UI (free web account — no API key needed)",
                    "query": intelx_url(norm)})
    if cls == "domain":
        # The phonebook inventory is the reason to care about IntelX on a web case, so name it
        # explicitly on every domain rather than leaving the analyst to know the endpoint exists.
        out.append({"service": "IntelX phonebook (domain -> emails/subdomains/URLs; PAID API, or "
                               "run it in the UI)", "query": intelx_url(norm, "phonebook")})
    return out


def attach_intelx_queries(pivots: list) -> list:
    """Append the IntelX selector query (+ UI URLs) to every pivot whose kind IntelX can search.

    One pass over the finished pivot list rather than at each `add(...)` call site, so
    `references/intelx.json -> pivot_kind_map` is the single place an analyst edits to teach
    WebPivot a new IntelX selector. Mutates and returns `pivots`."""
    for piv in pivots or []:
        if any("IntelX" in (q.get("service") or "") for q in (piv.get("queries") or [])):
            continue
        qs = intelx_queries(piv.get("kind"), piv.get("value"))
        if qs:
            piv.setdefault("queries", []).extend(qs)
    return pivots


# --------------------------------------------------------------------------- record grading
def bucket_grade(bucket: str) -> dict:
    """What a hit in this bucket is worth. Unknown buckets are reported ungraded rather than
    dropped — IntelX adds buckets, and a silently discarded record is worse than an unlabelled
    one. `web.public.<tld>` collapses onto the `web.public` entry."""
    b = (bucket or "").strip().lower()
    spec = BUCKETS.get(b)
    if not spec:
        for known in BUCKETS:
            if b.startswith(known + "."):
                spec = BUCKETS[known]
                break
    if not isinstance(spec, dict):
        return {"grade": "ungraded", "kind": "unknown", "rank": 99,
                "note": "bucket not in references/intelx.json — grade it there once you know what "
                        "it contains"}
    return {"grade": spec.get("grade") or "ungraded", "kind": spec.get("kind") or "unknown",
            "rank": int(spec.get("rank") or 99), "note": spec.get("note") or ""}


def bucket_rank(bucket: str) -> int:
    """Investigative-value order for a bucket (1 = read first); unknown ranks last.

    The buckets are NOT interchangeable, and the widest gap is between a stealer log and a breach
    dump. A breach dump is one site's user table — an address and a year, recycled through dozens
    of combolists. A stealer log is one machine at one moment, with the URL/user/password triple
    and its session context, and it may be the OPERATOR'S OWN machine holding the campaign's panel
    credentials. Sorting on this is what stops a hundred stale combolist rows from burying the one
    log entry that makes the case."""
    return bucket_grade(bucket).get("rank", 99)


def item_evidence(bucket: str) -> bool:
    """True when items in this bucket are worth OPENING one by one even though corpus
    co-membership proves nothing (`clustering_policy.item_evidence` — stealer logs).

    This is the distinction `clusterable()` cannot express: 'not an automatic edge' and 'not worth
    reading' are different claims, and collapsing them throws away the best material IntelX has."""
    b = (bucket or "").strip().lower()
    marked = [str(x).lower() for x in (CLUSTERING_POLICY.get("item_evidence") or [])]
    return any(b == m or b.startswith(m + ".") for m in marked)


def clusterable(bucket: str) -> bool:
    """True when a hit in this bucket may support a same-operator edge.

    Everything else — every breach corpus and every stealer log — is EXPOSURE evidence: two
    selectors in one dump share a victim population, not an owner. Fails closed."""
    b = (bucket or "").strip().lower()
    never = [str(x).lower() for x in (CLUSTERING_POLICY.get("never_cluster_on") or [])]
    ok = [str(x).lower() for x in (CLUSTERING_POLICY.get("cluster_on") or [])]
    if any(b == n or b.startswith(n + ".") for n in never):
        return False
    return any(b == c or b.startswith(c + ".") for c in ok)


def summarise_record(rec: dict) -> dict:
    """One IntelX search record -> the fields an analyst actually reads, plus our own grading.

    A raw record carries a dozen internal ids; the case file keeps the ones that let you re-open
    the item (systemid/storageid/bucket) and the ones that carry meaning (date, media, bucket)."""
    if not isinstance(rec, dict):
        return {}
    bucket = rec.get("bucket") or rec.get("bucketh") or ""
    g = bucket_grade(bucket)
    out = {
        "name": rec.get("name"),
        "date": rec.get("date") or rec.get("added"),
        "bucket": bucket,
        "grade": g["grade"],
        "bucket_kind": g["kind"],
        "rank": g["rank"],
        "clusterable": clusterable(bucket),
        # Not the same claim as `clusterable`: a stealer-log item is worth opening by hand even
        # though the corpus it lives in can never carry an automatic operator edge.
        "read_item": item_evidence(bucket),
        "media": MEDIA_TYPES.get(str(rec.get("media")), rec.get("media")),
        # The raw ids the item-read (`/file/preview`) needs: `m` = media, `c` = content type.
        "media_id": rec.get("media"),
        "size": rec.get("size"),
        "systemid": rec.get("systemid"),
        "storageid": rec.get("storageid"),
        "xscore": rec.get("xscore"),
        "type": rec.get("type"),
    }
    return {k: v for k, v in out.items() if v not in (None, "", [])}


# --------------------------------------------------------------------------- search (2-step)
# How each poll ending is reported. Only "complete" lets an empty page stand as a negative.
POLL_STATE_LABEL = {"complete": "clean", "deadline": "partial (deadline)",
                    "poll_limit": "partial (poll limit)", "expired": "partial (search id expired)",
                    "error": "partial (error)"}


def _remaining(deadline):
    """Seconds left before `deadline` (a time.monotonic() stamp); None when unbounded."""
    return None if deadline is None else deadline - time.monotonic()


def _http_timeout(deadline, cap) -> int:
    """Per-request timeout: the usual cap, shortened so one slow request cannot overrun the
    search's own deadline."""
    rem = _remaining(deadline)
    return int(cap) if rem is None else max(1, min(int(cap), int(rem) + 1))


def search_deadline(passes) -> int:
    """Overall wall-clock budget (seconds) for a search, proportional to the buckets it covers.

    An unscoped (all-bucket) pass weighs `deadline_all_buckets_weight` buckets. Tunables live in
    `references/intelx.json -> result_limits`; the cap bounds the whole search, every pass."""
    base = float(RESULT_LIMITS.get("deadline_base_seconds", 180))
    per = float(RESULT_LIMITS.get("deadline_per_bucket_seconds", 120))
    allw = float(RESULT_LIMITS.get("deadline_all_buckets_weight", 3))
    cap = float(RESULT_LIMITS.get("deadline_max_seconds", 900))
    n = sum((len(p.get("buckets") or []) or allw) for p in (passes or []))
    return int(min(cap, base + per * max(1, n)))


def deadline_for(buckets=None, logs_first=None, general_pass=None) -> int:
    """`search_deadline` for the plan a `search(...)` call with these arguments would run — what a
    subprocess wrapper must exceed (plus a small grace) so it never kills the collector before the
    collector's own deadline returns its partial result."""
    return search_deadline(_plan_passes(buckets, logs_first, general_pass))


def _poll(path: str, ident: str, key: str, limit: int, deadline=None):
    """Drive IntelX's two-step result fetch: GET until `status` says stop -> (rows, err, state).

    status 3 means "still aggregating" — returning on the first empty page would turn a slow
    backend into a false negative, which is the whole failure mode this layer must not have. With
    a `deadline` the loop polls until IntelX reports completion or time runs out (state
    'deadline', rows so far kept); without one it stops after `poll_attempts` ('poll_limit').
    status 1 ends the loop at once — a finished-empty search returns on its first page."""
    rows, attempts = [], int(RESULT_LIMITS.get("poll_attempts", 8))
    sleep = float(RESULT_LIMITS.get("poll_sleep_seconds", 1))
    cap = int(RESULT_LIMITS.get("http_timeout_seconds", 30))
    n = 0
    while True:
        rem = _remaining(deadline)
        if rem is not None and rem <= 0:
            return rows, None, "deadline"
        if deadline is None and n >= max(1, attempts):
            return rows, None, "poll_limit"
        n += 1
        data, err = _call(path, params={"id": ident, "limit": limit},
                          timeout=_http_timeout(deadline, cap))
        if err:
            rem = _remaining(deadline)
            return (rows, None, "deadline") if rem is not None and rem <= 0 else (rows, err, "error")
        page = (data.get(key) or []) if isinstance(data, dict) else []
        rows += [r for r in page if isinstance(r, dict)]
        status = data.get("status") if isinstance(data, dict) else None
        if status == 1 or len(rows) >= limit:
            return rows, None, "complete"
        if status == 2:
            return rows, None, "expired"
        rem = _remaining(deadline)
        time.sleep(sleep if rem is None else max(0.0, min(sleep, rem)))


STEALER_LOG_NOTE = (
    "Stealer-log items matched. A hit COUNT says only that the selector appears in the leak "
    "corpus — it is not evidence that any machine or person was infected. Open the items ONE BY "
    "ONE (mode 'item': `wp_intelx.py item <storageid> --bucket <bucket>`) and cite the opened "
    "record — a log is one machine at one moment, so the question is WHOSE machine: a victim of "
    "this campaign (holds credentials FOR the scam's front-end → victim/access-vector layer) or "
    "the OPERATOR's own box (holds the admin panel, and the registrar / CMS / hosting / exchange "
    "logins behind it → direct attribution). Corpus co-membership is still not an operator link. "
    "Handle as real victim credentials: cite the item's metadata, never paste secrets into the "
    "case file.")


def _plan_passes(buckets, logs_first=None, general_pass=None):
    """The bucket-scoped passes to run for one selector, in order.

    An explicit `buckets` from the analyst is honoured verbatim — one pass, exactly what was asked
    for, and (by design) kept OUT of the shared per-selector cache `search()` uses for the named
    plan, since a one-off custom corpus must never downgrade a broader cached result. Otherwise the
    plan from `references/intelx.json -> search_plan` applies: the stealer logs are queried in
    their OWN pass before the general one. `logs_first`/`general_pass` override the plan's own
    flags per call (this is how `--logs-only`/`--no-logs-first` reach it) while staying part of the
    NAMED (shareable) plan — unlike an explicit `buckets` override.

    This is not cosmetic ordering. IntelX returns a bounded page, so on a long-exposed selector the
    recycled combolist rows fill it and the single infostealer-log record is truncated away before
    any sort can reach it. Scoping the first pass to `leaks.logs` is what guarantees the logs are
    actually retrieved; sorting only decides what an analyst reads first among records that came
    back. Costs one unit per pass — that is the price of the guarantee."""
    if buckets:
        return [{"pass": "explicit", "buckets": list(buckets)}]
    first = [str(b) for b in (SEARCH_PLAN.get("first_pass_buckets") or []) if b]
    want_logs = SEARCH_PLAN.get("logs_first", True) if logs_first is None else bool(logs_first)
    want_general = SEARCH_PLAN.get("general_pass", True) if general_pass is None else bool(general_pass)
    passes = []
    if want_logs and first:
        passes.append({"pass": "logs", "buckets": first})
    if not passes or want_general:
        passes.append({"pass": "general", "buckets": []})
    return passes


def _search_once(norm, buckets, limit, media, datefrom, dateto, timeout, deadline=None):
    """One IntelX search -> (summarised_records, error_dict_or_None, state).

    state 'failed' = the search never started (auth / soft selector / entitlement / network) and
    `err` says why; otherwise a POLL_STATE_LABEL key. `[]` with state 'complete' is a REAL
    negative: the search ran to completion and IntelX has nothing in these buckets."""
    body = {"term": norm, "buckets": list(buckets or []), "lookuplevel": 0,
            "maxresults": limit, "media": media, "sort": 4, "terminate": [],
            "datefrom": datefrom, "dateto": dateto,
            "timeout": int(RESULT_LIMITS.get("search_timeout_seconds", 5))}
    data, err = _call(ENDPOINTS.get("search_start", "/intelligent/search"),
                      method="POST", body=body, timeout=_http_timeout(deadline, timeout))
    if err:
        rem = _remaining(deadline)
        if rem is not None and rem <= 0 and "error" in err:
            return [], None, "deadline"      # cut by our own deadline, not refused by IntelX
        return [], err, "failed"
    ident = (data or {}).get("id") if isinstance(data, dict) else None
    if not ident:
        # status 1 with no id = IntelX accepted the selector and has nothing. That IS a real
        # negative — but only because the search ran, which is exactly the distinction the
        # keyless mode cannot make.
        return [], None, "complete"
    rows, perr, state = _poll(ENDPOINTS.get("search_result", "/intelligent/search/result"),
                              ident, "records", limit, deadline=deadline)
    _call(ENDPOINTS.get("search_terminate", "/intelligent/search/terminate"),
          params={"id": ident}, timeout=5)   # free the backend slot; costs nothing
    recs = [r for r in (summarise_record(r) for r in rows) if r]
    return recs[:limit], ({"partial": perr} if perr else None), state


PARTIAL_NOTE = (
    "IntelX did NOT report this search as finished — the records below are only what arrived "
    "before the stop named in `status`. An absent record is NOT a negative; re-run the selector "
    "(optionally `--deadline <seconds>`, or `--logs-only` to narrow the buckets).")


def search(term: str, maxresults: int = None, buckets: list = None, media: int = 0,
           datefrom: str = "", dateto: str = "", timeout: int = None, logs_first: bool = None,
           general_pass: bool = None, deadline_seconds: int = None):
    """Search IntelX for one strong selector -> {'term','selector','status','records':[…],…}.

    Runs the STEALER LOGS in their own pass first (see `_plan_passes`), then the general pass, and
    merges — so a hundred recycled combolist rows can never crowd the one infostealer record out of
    a bounded page. `logs_pass` records whether that pass actually ran TO COMPLETION, which is
    what makes an empty `read_these` a real negative rather than a budget/deadline artefact. Pass
    `buckets` to override the plan, or `logs_first=False` for a single general pass.

    The whole search runs under ONE wall-clock deadline proportional to the buckets searched
    (`search_deadline`, override with `deadline_seconds`). `status` is 'clean' when every pass
    finished, else 'partial (deadline)' / 'partial (poll limit)' / 'partial (budget)' / … with the
    records that did arrive — never a bare timeout.

    Memoised ONCE PER SELECTOR PER CASE regardless of which pass-plan the caller wants (shared
    between the collector's own enrich_result call and a later enrich/email-deep ask) — see
    `_covers`; a partial pass never counts as coverage. An explicit `buckets` override is cached
    under its own key.

    Returns None with no key. `{"skipped": …}` when the selector is soft, the budget is spent, or
    the account is not entitled — in every one of those cases the emitted UI URL is still the
    deliverable, and the caller MUST NOT read the absence of records as an absence of hits."""
    if not intelx_configured():
        return None
    timeout = int(timeout) if timeout is not None else int(RESULT_LIMITS.get("http_timeout_seconds", 30))
    cls, norm = classify_selector(term)
    ui = intelx_url(norm)
    if not cls:
        return {"skipped": "not a strong selector — IntelX searches email/domain/URL/IP/CIDR/phone/"
                           "wallet/MAC/UUID/IBAN only, never a brand or person name",
                "status": "skipped", "term": term, "ui_url": ui}
    limit = int(maxresults or RESULT_LIMITS.get("max_records", 200))
    cost = int(SEARCH_BUDGET.get("search_costs", 1))
    plan = _plan_passes(buckets, logs_first, general_pass)
    budget_s = int(deadline_seconds) if deadline_seconds else search_deadline(plan)

    def run():
        started = time.monotonic()
        deadline = started + budget_s
        out = {"term": norm, "selector": cls, "ui_url": ui, "passes": [],
               "logs_pass": False, "deadline_seconds": budget_s}
        recs, seen, hard_err = [], set(), None
        for p in plan:
            if _remaining(deadline) <= 0:
                # Out of time before this pass started: nothing spent, and said so.
                out["passes"].append(dict(p, ran=False, complete=False,
                                          status=POLL_STATE_LABEL["deadline"],
                                          skipped="deadline reached before this pass started"))
                continue
            blocked = _budget_block(cost, f"{cls} {p['pass']} search")
            if blocked:
                # A pass NOT run is recorded as such. The logs pass is first precisely so that a
                # tight allowance buys log coverage and drops the combolists, never the reverse.
                out["passes"].append(dict(p, ran=False, complete=False,
                                          status="partial (budget)", skipped=blocked))
                continue
            got, err, state = _search_once(norm, p["buckets"], limit, media, datefrom, dateto,
                                           timeout, deadline=deadline)
            if state == "failed":
                _record("search", 0, norm, ok=False)
                out["passes"].append(dict(p, ran=False, complete=False, **err))
                hard_err = hard_err or err
                break                    # auth / soft selector / entitlement — later passes fail too
            _record("search", cost, norm, results=len(got))
            fresh = 0
            for r in got:      # the general pass re-returns what the logs pass already found
                ident = r.get("systemid") or (r.get("name"), r.get("date"), r.get("bucket"))
                if ident in seen:
                    continue
                seen.add(ident)
                recs.append(r)
                fresh += 1
            complete = state == "complete"
            entry = dict(p, ran=True, complete=complete, status=POLL_STATE_LABEL.get(state, state),
                         records=len(got), new=fresh)
            if err:
                entry.update(err)
            out["passes"].append(entry)
            if p["pass"] in ("logs", "explicit") and complete:
                out["logs_pass"] = out["logs_pass"] or any(item_evidence(b) for b in p["buckets"])
        out["elapsed_seconds"] = round(time.monotonic() - started, 1)
        ran = [p for p in out["passes"] if p.get("ran")]
        if not ran:
            # Nothing was queried at all — keep the legacy `skipped` shape so callers that test
            # `hits.get("skipped")` still see this as "not searched", never as "no hits".
            reason = hard_err or {}
            return {"skipped": reason.get("skipped") or reason.get("error")
                    or (out["passes"][0].get("skipped") if out["passes"] else "no pass ran"),
                    "status": "skipped",
                    "term": norm, "selector": cls, "ui_url": ui, "passes": out["passes"],
                    "budget": budget_status()}
        # First non-clean pass names the overall status; 'clean' only when every pass finished.
        out["status"] = next((p.get("status") for p in out["passes"]
                              if p.get("status") and p.get("status") != "clean"),
                             "clean" if all(p.get("complete") for p in out["passes"])
                             else "partial (error)")
        if out["status"] != "clean":
            out["partial_note"] = PARTIAL_NOTE
        recs = recs[:limit]
        # Rank order, newest first within a rank. IntelX returns whatever matched, and on a
        # long-exposed address that is overwhelmingly recycled combolist rows — sorting by bucket
        # value is what keeps the one stealer-log entry from being buried under a hundred of them.
        # Two stable passes: newest first, then bucket rank on top of it — so within the logs the
        # freshest infection leads, and the logs as a whole lead the combolists.
        recs.sort(key=lambda r: str(r.get("date") or ""), reverse=True)
        recs.sort(key=lambda r: r.get("rank", 99))
        by_bucket = {}
        for r in recs:
            by_bucket[r.get("bucket") or "(none)"] = by_bucket.get(r.get("bucket") or "(none)", 0) + 1
        by_bucket = dict(sorted(by_bucket.items(), key=lambda kv: bucket_rank(kv[0])))
        out.update({"records": recs, "by_bucket": by_bucket,
                    "clusterable_hits": [r for r in recs if r.get("clusterable")],
                    # The items to actually open — stealer-log entries, where a single record can
                    # name the operator's own machine. Surfaced separately so a thin
                    # `clusterable_hits` list never reads as "nothing here worth reading".
                    "read_these": [r for r in recs if r.get("read_item")]})
        if out["read_these"]:
            out["stealer_log_note"] = STEALER_LOG_NOTE
        elif out["logs_pass"]:
            out["logs_note"] = ("The stealer-log buckets were queried in their own pass and "
                                "returned nothing for this selector — a real negative, not a "
                                "truncated page.")
        if not recs:
            out["note"] = ("IntelX ran the search and returned no records for this selector."
                           if out["status"] == "clean" else
                           "No records arrived before the search stopped — NOT a negative.")
        return out
    # One search per SELECTOR per case — shared between the collector's own default (logs+general)
    # pass and enrich/email-deep's later ask (often `--logs-only`), regardless of which bucket/pass
    # plan each caller wants: keyed by the selector ALONE (not buckets/limit/passes), so a narrower
    # later ask reuses the earlier broader result instead of re-buying it. A cached entry that ran
    # FEWER (complete) passes than THIS call needs is not reused as-is — it is recomputed and the
    # cache is upgraded, so the ordering can never go the other way and hide the general pass from
    # a later, broader caller, and a deadline-cut pass is retried rather than frozen.
    # An explicit analyst `--buckets` override is a one-off query with its own key: it must not
    # downgrade a broader collector/enrich result already cached for this selector.
    key = norm if not buckets else f"{norm}|explicit|{','.join(buckets)}|{limit}"
    want = {p["pass"] for p in plan}
    cached = _cache_get("search", key)
    if _covers(cached, want):
        _store_memo("search", key, cached)
        return copy.deepcopy(cached)
    val = run()
    _store_memo("search", key, val)
    return copy.deepcopy(val)


def phonebook(domain: str, target: str = "all", maxresults: int = None, timeout: int = 30):
    """The domain -> selector inventory: every email, subdomain and URL IntelX has seen under an
    apex. **PAID endpoint** — a free key gets HTTP 402 and this returns `{"skipped": …}` with the
    phonebook.cz UI link.

    This is the layer's highest-value call for web casework: the emails it returns are registrant/
    operator leads the DNS and TLS layers never see, and the subdomains feed straight back into
    the collector."""
    if not intelx_configured():
        return None
    cls, norm = classify_selector(domain)
    ui = intelx_url(norm, "phonebook")
    if cls != "domain":
        return {"skipped": "phonebook takes a domain (a `*.example.com` wildcard is allowed)",
                "term": domain, "ui_url": ui}
    tgt = PHONEBOOK_TARGETS.get(str(target).lower(), 0)
    limit = int(maxresults or RESULT_LIMITS.get("max_selectors", 500))
    cost = int(SEARCH_BUDGET.get("phonebook_costs", 5))

    def run():
        blocked = _budget_block(cost, "phonebook search")
        if blocked:
            return {"skipped": blocked, "term": norm, "ui_url": ui, "budget": budget_status()}
        body = {"term": norm, "buckets": [], "lookuplevel": 0, "maxresults": limit,
                "media": 0, "sort": 4, "terminate": [], "target": tgt, "datefrom": "", "dateto": "",
                "timeout": int(RESULT_LIMITS.get("search_timeout_seconds", 5))}
        data, err = _call(ENDPOINTS.get("phonebook_start", "/phonebook/search"),
                          method="POST", body=body, timeout=timeout)
        if err:
            _record("phonebook", 0, norm, ok=False)
            return dict(err, term=norm, ui_url=ui,
                        hint="the phonebook endpoint is PAID-only; run it in the web UI on a free "
                             "account")
        ident = (data or {}).get("id")
        if not ident:
            _record("phonebook", cost, norm, results=0)
            return {"term": norm, "ui_url": ui, "emails": [], "domains": [], "urls": []}
        rows, perr, pstate = _poll(ENDPOINTS.get("phonebook_result", "/phonebook/search/result"),
                                   ident, "selectors", limit)
        groups = {"email": [], "domain": [], "url": [], "url query": [], "other": []}
        for r in rows:
            val = r.get("selectorvalue") or r.get("selectorvaluehash") or ""
            label = SELECTOR_RESULT_TYPES.get(str(r.get("selectortype")), "other")
            groups.setdefault(label, []).append(val)
        _record("phonebook", cost, norm, results=len(rows))
        out = {"term": norm, "ui_url": ui,
               "emails": uniq([v for v in groups.get("email", []) if v])[:limit],
               "domains": uniq([v for v in groups.get("domain", []) if v])[:limit],
               "urls": uniq([v for v in groups.get("url", []) if v])[:limit],
               "total": len(rows), "status": POLL_STATE_LABEL.get(pstate, pstate)}
        if perr:
            out["partial"] = perr
        if pstate != "complete":
            out["partial_note"] = PARTIAL_NOTE
        return out
    return _memoised("phonebook", f"{norm}|{tgt}|{limit}", run)


def item_selectors(systemid: str, timeout: int = 30):
    """The selectors IntelX extracted from ONE item (emails, phones, wallets it found inside a
    leak document) — how you turn a single hit into new pivot values without downloading the item.
    Needs an entitlement that allows item access."""
    if not intelx_configured():
        return None

    def run():
        data, err = _call(ENDPOINTS.get("item_selectors", "/item/selector/list/human"),
                          params={"id": systemid, "k": intelx_key()}, timeout=timeout)
        if err:
            _record("item_selectors", 0, systemid, ok=False)
            return dict(err, systemid=systemid)
        vals = data.get("selectors") if isinstance(data, dict) else data
        _record("item_selectors", 0, systemid, results=len(vals or []))
        return {"systemid": systemid, "selectors": vals}
    return _memoised("item_selectors", systemid, run)


# --------------------------------------------------------------------------- item READ (preview)
# Opening the record is what turns "this selector appears in a stealer-log corpus" into a citable
# statement about ONE machine. The preview is bounded (`result_limits.preview_lines` /
# `preview_max_chars`) and REDACTED before it leaves this module: identifiers that answer "whose
# machine" (URLs, logins, hostnames, dates) stay; secrets (passwords, cookies, tokens) never do.
_SECRET_LABEL_RE = re.compile(
    r"^(\s*(?:pass(?:word)?|pwd|passwd|pin|otp|token|access[_ -]?token|refresh[_ -]?token|"
    r"cookies?|secret|api[_ -]?key|auth(?:orization)?|session(?:[_ -]?id)?|seed|mnemonic|"
    r"private[_ -]?key)\s*[:=]\s*)(\S.*)$", re.I)
_CRED_PAIR_RE = re.compile(r"^(\s*[^\s:;|@]+@[^\s:;|@]+\.[A-Za-z]{2,}\s*[:;|]\s*)(\S.*)$")
_LONG_TOKEN_RE = re.compile(r"[A-Za-z0-9_\-+=%]{32,}")


def _mask(secret: str) -> str:
    return f"[REDACTED:{len(secret)} chars]"


def redact_line(line: str):
    """(redacted_line, n_redactions) — masks credential VALUES, keeps the identifiers around them:
    `label: value` secrets, `email:password` combolist rows, `url:login:password` stealer rows,
    Netscape cookie-file values, and any long opaque token (session ids, JWT parts, hashes)."""
    n = 0
    m = _SECRET_LABEL_RE.match(line)
    if m:
        return m.group(1) + _mask(m.group(2)), 1
    m = _CRED_PAIR_RE.match(line)
    if m:
        return m.group(1) + _mask(m.group(2)), 1
    if "://" in line and line.count(":") >= 3:
        head, user, pw = line.rsplit(":", 2)
        if "/" not in user and "/" in head and pw.strip():
            line, n = f"{head}:{user}:{_mask(pw)}", n + 1
    cols = line.split("\t")
    if len(cols) >= 7 and cols[1].upper() in ("TRUE", "FALSE"):      # Netscape cookie file row
        cols[6] = _mask(cols[6])
        line, n = "\t".join(cols), n + 1
    line, k = _LONG_TOKEN_RE.subn(lambda mm: _mask(mm.group(0)), line)
    return line, n + k


ITEM_READ_NOTE = (
    "Opened record (bounded, redacted preview). THIS is what an infection/compromise statement may "
    "cite — the storageid/bucket below plus what the lines show (whose machine, which logins). A "
    "search hit count alone only says the selector appears in the leak corpus. Secrets are masked "
    "by design; never re-fetch them into the case file.")


def read_item(storageid: str, bucket: str, media=None, ctype=None, lines: int = None,
              systemid: str = "", timeout: int = None):
    """Open ONE search record via IntelX `/file/preview` (`c`=content type, `m`=media, `f`=0 text,
    `sid`=storageid, `b`=bucket, `l`=lines — the official SDK's FILE_PREVIEW) and return a bounded,
    redacted text preview. `storageid`, `bucket`, `media_id` and `type` are all on every search
    `records` / `read_these` row. Metered: recorded in api_usage as `file_preview`; a free key
    usually gets HTTP 402/403 here and this returns `{"skipped": …}` with the UI link."""
    if not intelx_configured():
        return None
    sid, bkt = str(storageid or "").strip(), str(bucket or "").strip()
    ui = intelx_url(systemid, "item") if systemid else intelx_url(sid)
    if not sid or not bkt:
        return {"skipped": "item read needs the record's storageid AND bucket (both are on every "
                           "search `records` / `read_these` row)", "status": "skipped"}
    n = max(1, int(lines or RESULT_LIMITS.get("preview_lines", 8)))
    max_chars = int(RESULT_LIMITS.get("preview_max_chars", 2000))
    cost = int(SEARCH_BUDGET.get("preview_costs", 1))
    http_t = int(timeout or RESULT_LIMITS.get("http_timeout_seconds", 30))

    def run():
        blocked = _budget_block(cost, "item preview")
        if blocked:
            return {"skipped": blocked, "status": "skipped", "storageid": sid, "bucket": bkt,
                    "ui_url": ui, "budget": budget_status()}
        params = {"c": int(ctype) if ctype not in (None, "") else 1,
                  "m": int(media) if media not in (None, "") else 0,
                  "f": 0, "sid": sid, "b": bkt, "e": 0, "l": n, "k": intelx_key()}
        text, err = _call(ENDPOINTS.get("file_preview", "/file/preview"), params=params,
                          timeout=http_t, raw=True)
        if err:
            _record("file_preview", 0, sid, ok=False)
            return dict(err, status="skipped" if "skipped" in err else "failed",
                        storageid=sid, bucket=bkt, ui_url=ui)
        raw_lines = str(text or "").splitlines()
        shown, redactions, used, cut = [], 0, 0, len(raw_lines) > n
        for ln in raw_lines[:n]:
            red, k = redact_line(ln)
            redactions += k
            if used + len(red) > max_chars:
                shown.append(red[:max(0, max_chars - used)])
                cut = True
                break
            shown.append(red)
            used += len(red) + 1
        _record("file_preview", cost, sid, results=len(shown))
        out = {"status": "read", "storageid": sid, "bucket": bkt, "ui_url": ui,
               "lines": shown, "line_count": len(shown), "truncated": cut,
               "redactions": redactions, "note": ITEM_READ_NOTE}
        if systemid:
            out["systemid"] = systemid
        if not shown:
            out["note"] = ("IntelX returned no text preview for this item (binary, picture or "
                           "empty) — open it in the web UI; nothing here supports a claim yet.")
        return out
    return _memoised("item_read", f"{sid}|{bkt}|{n}", run)


def capabilities(timeout: int = 20):
    """`/authenticate/info` — what this key is actually entitled to and how much of it is left.
    Costs nothing; run it before a batch rather than discovering an entitlement mid-case."""
    if not intelx_configured():
        return None

    def run():
        data, err = _call(ENDPOINTS.get("capabilities", "/authenticate/info"), timeout=timeout)
        return dict(err) if err else data
    return _memoised("capabilities", "self", run)


# --------------------------------------------------------------------------- run enrichment
# Priority order for spending a bounded allowance across a result's artifacts — DATA
# (`references/intelx.json -> search_plan.selector_priority`), because which artifact deserves the
# next unit is exactly the kind of judgement an analyst should be able to retune per case.
#
# THE DOMAIN AND THE EMAIL LEAD, and the domain leads them. A stealer-log record is indexed by the
# URL the malware captured, so searching the CASE DOMAIN returns the machines that held credentials
# FOR it: the campaign's victims, the admin/panel URLs the public site never links, and — when the
# operator logged into their own panel from an infected box — the operator's own machine. Nothing
# else in this toolkit reaches that. The email is next: it is the selector that carries identity
# across corpora. Contact artifacts (phone, wallet) follow, since they carry the operator's own
# advertising copy in pastes and market listings.
_ENRICH_PRIORITY = [str(s) for s in (SEARCH_PLAN.get("selector_priority") or []) if s] or \
                   ["domain", "email", "url", "phone", "bitcoin", "iban", "ipv4"]


_ROLE_LOCALS = frozenset({"abuse", "spam-reports", "spam", "postmaster", "hostmaster", "noc", "webmaster",
                          "noreply", "no-reply", "dmarc", "dmarc-reports", "security", "privacy", "support",
                          "info", "admin", "contact", "sales", "help", "billing", "legal", "compliance"})


def _is_role_or_noise_email(addr: str) -> bool:
    """A role/abuse mailbox or a registrar / privacy-proxy relay is NOT a person selector — IntelX
    would spend a unit and return the whole internet's spam reports. Uses the KB noise filters when
    importable (registrar domains, privacy tokens) plus a local role list."""
    a = str(addr or "").lower().strip()
    if "@" not in a:
        return False
    local, _, dom = a.partition("@")
    if local in _ROLE_LOCALS or local.startswith(("abuse", "spam-report", "dmarc")):
        return True
    try:
        import os as _os, sys as _sys
        _kb = _os.path.join(_os.path.dirname(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))), "tools", "kb")
        if _kb not in _sys.path:
            _sys.path.insert(0, _kb)
        from noise_filters import is_noise_email  # noqa: WPS433
        return bool(is_noise_email(a))
    except Exception:  # noqa: BLE001
        return False


def _enrich_targets(result: dict) -> list:
    """[(selector_class, value, pivot)] for every artifact in a result IntelX can search, ordered
    by `_ENRICH_PRIORITY` and de-duplicated on the normalised value."""
    seen, rows = set(), []
    # The SEED HOST goes in first, so that among the domains it is the one the allowance is spent
    # on before any discovered sibling: it is the hostname a stealer log would have captured a
    # credential for, i.e. the one most likely to name an infected machine that matters.
    host = (result.get("meta") or {}).get("host")
    if host:
        cls, norm = classify_selector(str(host))
        if cls == "domain":
            seen.add(norm)
            rows.append((cls, norm, None))
    for piv in result.get("pivots") or []:
        sel = selector_for_kind(piv.get("kind"))
        if not sel:
            continue
        cls, norm = classify_selector(str(piv.get("value") or ""))
        if not cls or norm in seen:
            continue
        if cls == "email" and _is_role_or_noise_email(norm):
            continue          # spam-reports@ / abuse@ / privacy relays: a search unit spent on nobody
        seen.add(norm)
        rows.append((cls, norm, piv))
    # Stable — so within a selector class the seed host keeps its head start.
    rows.sort(key=lambda r: _ENRICH_PRIORITY.index(r[0]) if r[0] in _ENRICH_PRIORITY else 99)
    return rows


def enrich_result(result: dict, do_phonebook: bool = True, free_only: bool = False,
                  max_selectors: int = None) -> dict:
    """Run IntelX over a finished WebPivot result and fold what comes back into it.

    Each searched artifact gets its hits on `pivot['live_results']['intelx']` (the same shape FOFA
    and Censys use), and the run-level summary lands on `result['intelx']`. The seed domain also
    gets a phonebook inventory when the entitlement allows, because the emails and subdomains it
    returns are new collection targets, not just evidence.

    Spending is bounded twice: by the module's own run cap and by `max_selectors`, and the targets
    are ordered by `search_plan.selector_priority` — the SEED DOMAIN and the operator's EMAIL
    first, because a stealer-log record is indexed by the URL it captured, so those two are the
    selectors that can name an infected machine (a victim's, or the operator's own).

    Each selector normally costs TWO units, not one: the stealer logs are queried in their own pass
    ahead of the general one so the public breach corpora cannot fill the page first. `max_selectors`
    counts UNITS, so a cap of 10 buys 5 fully-searched selectors — or 10 log-only ones with
    `search_plan.general_pass` set false.

    Every target is searched CONCURRENTLY (bounded by `result_limits.max_concurrent_searches`) —
    one selector's poll loop no longer blocks every other selector in this same result behind it.

    Keyless / --free-only: nothing is queried and `result['intelx']` carries the capability
    statement instead, so the case file records that these indexes were NOT consulted."""
    cap = capability(free_only=free_only)
    if not intelx_configured() or free_only:
        result["intelx"] = {"capability": cap, "searched": []}
        return result["intelx"]

    budget = budget_status()
    room = max(0, budget["max_searches_per_run"] - budget["spent_this_run"])
    limit = min(int(max_selectors or room), room)
    targets = _enrich_targets(result)
    out = {"capability": cap, "searched": [], "skipped_for_budget": [], "discovered": {}}

    if do_phonebook:
        host = (result.get("meta") or {}).get("host")
        cls, norm = classify_selector(str(host or ""))
        if cls == "domain":
            before = budget_status()["spent_this_run"]
            pb = phonebook(norm) or {}
            out["phonebook"] = pb
            limit -= max(0, budget_status()["spent_this_run"] - before)
            if pb.get("emails") or pb.get("domains"):
                # These are COLLECTION TARGETS, not conclusions: an address IntelX saw under the
                # apex still has to be corroborated before it attributes anything.
                out["discovered"] = {"emails": pb.get("emails", [])[:50],
                                     "subdomains": pb.get("domains", [])[:50],
                                     "urls": pb.get("urls", [])[:50]}
            limit = max(0, limit)

    # Every distinct selector in this result is searched CONCURRENTLY, bounded by
    # `result_limits.max_concurrent_searches` (reference DATA, never a spend cap) — one selector's
    # 1-2 pass poll loop no longer blocks every OTHER selector in the same result behind it, which
    # is what turned a handful of selectors into serial waits tens of seconds apart on a real run.
    # `limit` still bounds how many of the (already priority-ordered) targets are dispatched at
    # all — as a target COUNT now, not the old adaptive per-unit one, because concurrent dispatch
    # cannot observe one target's actual spend before deciding the next; the per-run/day/month unit
    # ledger is still enforced inside `search()` itself, thread-safely, at the point of spend.
    to_run = targets if limit >= len(targets) else targets[:max(0, limit)]
    out["skipped_for_budget"].extend(value for _cls, value, _piv in targets[len(to_run):])
    workers = max(1, int(RESULT_LIMITS.get("max_concurrent_searches", 4)))
    hits_by_value = {}
    if to_run:
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(workers, len(to_run))) as ex:
            futures = {ex.submit(search, value): value for _cls, value, _piv in to_run}
            for fut in concurrent.futures.as_completed(futures):
                value = futures[fut]
                try:
                    hits_by_value[value] = fut.result()
                except Exception as e:  # noqa: BLE001 — a search thread must never take the run down
                    hits_by_value[value] = {"error": str(e)[:200]}

    for cls, value, piv in to_run:
        hits = hits_by_value.get(value)
        if not isinstance(hits, dict):
            continue
        if piv is not None:
            piv.setdefault("live_results", {})["intelx"] = hits
        out["searched"].append({"selector": cls, "value": value,
                                "records": len(hits.get("records") or []),
                                "by_bucket": hits.get("by_bucket") or {},
                                "clusterable": len(hits.get("clusterable_hits") or []),
                                # Stealer-log items to open by hand. Counted separately from
                                # `clusterable` because it is the opposite trade-off: no automatic
                                # edge, but the highest chance of naming a machine that matters.
                                "read_these": len(hits.get("read_these") or []),
                                # Did the logs-scoped pass actually run for this selector? Without
                                # it, zero `read_these` says nothing — with it, it is a negative.
                                "logs_pass": bool(hits.get("logs_pass")),
                                # 'clean' only when IntelX finished every pass; anything else is
                                # a partial page whose missing records are NOT negatives.
                                "status": hits.get("status"),
                                "skipped": hits.get("skipped")})
        if hits.get("read_these"):
            out.setdefault("stealer_log_items", []).extend(hits["read_these"][:10])
    searched = out["searched"]
    out["logs_coverage"] = {
        "selectors_with_logs_pass": [s["value"] for s in searched if s.get("logs_pass")],
        "selectors_without_logs_pass": [s["value"] for s in searched if not s.get("logs_pass")]}
    if out.get("stealer_log_items"):
        out["stealer_log_note"] = STEALER_LOG_NOTE
    elif out["logs_coverage"]["selectors_with_logs_pass"]:
        out["stealer_log_note"] = (
            "The stealer-log buckets were queried FIRST for "
            f"{len(out['logs_coverage']['selectors_with_logs_pass'])} selector(s) and returned "
            "nothing. That is a real negative for those selectors — not a page filled by breach "
            "dumps before the logs were reached.")
    if out["skipped_for_budget"]:
        out["note"] = (f"{len(out['skipped_for_budget'])} selector(s) were NOT searched — the "
                       f"per-run IntelX cap was reached. Their absence from this file is a budget "
                       f"fact, not a finding.")
    result["intelx"] = out
    srcs = result.setdefault("meta", {}).setdefault("enriched_with", [])
    if isinstance(srcs, list) and "intelx" not in srcs:
        srcs.append("intelx")
    return out


# --------------------------------------------------------------------------- capability statement
def capability(free_only: bool = False) -> dict:
    """What THIS run's IntelX layer can do — mirrors wp_capabilities' contract so the statement can
    be pasted into an assessment's collection-limitations note verbatim.

    The percentage is deliberately blunt. Keyless, the layer still classifies every selector and
    hands the analyst a working UI link for it — genuinely half the job, because the query design
    is most of the tradecraft. What it cannot do is RUN any of them, so nothing comes back to fold
    into the case automatically, and no negative is ever established."""
    keyed = bool(intelx_key()) and not free_only
    if keyed:
        return {"layer": "intelx", "mode": "keyed", "power_pct": 100,
                "available": ["selector search over leaks / stealer logs / pastes / darknet / "
                              "historical WHOIS", "phonebook domain inventory (paid entitlement)",
                              "per-item selector extraction", "graded, clusterable-flagged records"],
                "unavailable": [],
                "statement": "IntelX queried live — leak/paste/darknet/WHOIS-snapshot coverage for "
                             "every strong selector in this run."}
    why = ("--free-only suppressed the metered IntelX calls" if free_only
           else "no INTELX_KEY is configured")
    return {
        "layer": "intelx", "mode": "free-only" if free_only else "keyless", "power_pct": 50,
        "available": ["strong-selector classification of every extracted artifact",
                      "ready-to-run intelx.io and phonebook.cz URLs for each one (free web account)",
                      "the bucket-grading and clustering policy that says what a hit would prove"],
        "unavailable": ["the records themselves — leak, stealer-log, paste, darknet and historical-"
                        "WHOIS sightings", "the phonebook domain->emails/subdomains/URLs inventory",
                        "per-item selector extraction", "any automatic feedback of discovered "
                        "emails/subdomains into the case"],
        "statement": (f"COLLECTION LIMITATION — IntelX ran at roughly HALF capability: {why}, so "
                      f"the selector queries were BUILT but never EXECUTED. This run establishes "
                      f"nothing about whether the operator's emails, phones, wallets or domains "
                      f"appear in leaks, stealer logs, pastes or darknet listings — those indexes "
                      f"were not queried. Run the emitted URLs by hand, or set INTELX_KEY."),
    }


def banner_lines(free_only: bool = False) -> list:
    """The stderr block for a keyless/free-only IntelX layer. Empty when keyed — a run at full
    capability needs no caveat."""
    cap = capability(free_only=free_only)
    if cap["power_pct"] >= 100:
        return []
    lines = [f"[!] INTELX: {cap['mode'].upper()} — ~{cap['power_pct']}% capability."]
    lines.append(f"    lost:    {cap['unavailable'][0]}; {cap['unavailable'][1]}")
    lines.append(f"    instead: {cap['available'][1]}")
    lines.append(f"    get a key: {UI_TEMPLATES.get('developer_tab') or UI_TEMPLATES.get('signup')}")
    return lines


__all__ = ["intelx_key", "intelx_configured", "api_root", "classify_selector", "is_searchable",
           "selector_for_kind", "intelx_url", "intelx_queries", "attach_intelx_queries",
           "search", "search_deadline", "deadline_for", "phonebook", "item_selectors",
           "read_item", "redact_line", "capabilities", "enrich_result",
           "capability", "banner_lines",
           "bucket_grade", "bucket_rank", "item_evidence", "clusterable", "summarise_record",
           "budget_status", "month_spent", "STEALER_LOG_NOTE", "ITEM_READ_NOTE", "SEARCH_PLAN",
           "ENDPOINTS", "SELECTOR_TYPES", "PIVOT_KIND_MAP", "BUCKETS", "PHONEBOOK_TARGETS",
           "PLAN_CAPABILITIES", "SEARCH_BUDGET", "RESULT_LIMITS", "UI_TEMPLATES",
           "CLUSTERING_POLICY"]


def main():
    ap = argparse.ArgumentParser(description="Intelligence X selector search + keyless query builder")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("search", help="search one strong selector (logs pass + general pass, "
                                      "1 unit each)")
    p.add_argument("term")
    p.add_argument("--buckets", default="", help="comma list, e.g. leaks.logs,pastes — overrides "
                                                 "the two-pass plan and searches exactly these")
    p.add_argument("--no-logs-first", dest="logs_first", action="store_false", default=None,
                   help="skip the stealer-log pass and run ONE general search (halves the cost, "
                        "and lets recycled breach rows fill the page before the logs are reached)")
    p.add_argument("--logs-only", action="store_true",
                   help="run ONLY the stealer-log pass (1 unit) — the cheap high-yield question: "
                        "is there an infected machine holding credentials for this selector?")
    p.add_argument("--max", type=int, default=None)
    p.add_argument("--datefrom", default="")
    p.add_argument("--dateto", default="")
    p.add_argument("--deadline", type=int, default=None,
                   help="overall wall-clock seconds for the whole search (default: proportional "
                        "to buckets searched, references/intelx.json result_limits.deadline_*); "
                        "on expiry the records so far return with status 'partial (deadline)'")
    p = sub.add_parser("phonebook", help="domain -> emails/subdomains/URLs (PAID endpoint)")
    p.add_argument("domain")
    p.add_argument("--target", default="all", choices=sorted(PHONEBOOK_TARGETS.keys()))
    p.add_argument("--max", type=int, default=None)
    p = sub.add_parser("selectors", help="selectors extracted from one item, by systemid")
    p.add_argument("systemid")
    p = sub.add_parser("item", help="OPEN one search record (/file/preview): bounded, redacted "
                                    "text preview — what an infection claim must cite")
    p.add_argument("storageid", help="the record's `storageid` (on every records/read_these row)")
    p.add_argument("--bucket", required=True, help="the record's `bucket`, e.g. leaks.logs")
    p.add_argument("--media", type=int, default=None, help="the record's `media_id` (default 0)")
    p.add_argument("--type", dest="ctype", type=int, default=None,
                   help="the record's content `type` (default 1 = text)")
    p.add_argument("--lines", type=int, default=None,
                   help="preview lines (default result_limits.preview_lines)")
    p.add_argument("--systemid", default="", help="optional: the record's systemid, for the UI link")
    p = sub.add_parser("query", help="OFFLINE: classify a selector + build its UI URLs (no key)")
    p.add_argument("term")
    sub.add_parser("caps", help="what this key is entitled to (/authenticate/info)")
    sub.add_parser("budget", help="OFFLINE: this month's IntelX search spend (no key, no spend)")
    args = ap.parse_args()

    if args.cmd == "query":
        cls, norm = classify_selector(args.term)
        out = {"term": norm, "selector": cls,
               "searchable": bool(cls),
               "queries": [{"service": "IntelX UI", "query": intelx_url(norm)}]}
        if cls == "domain":
            out["queries"].append({"service": "IntelX phonebook UI",
                                   "query": intelx_url(norm, "phonebook")})
        if not cls:
            out["note"] = ("IntelX searches STRONG selectors only — a brand or person name is a "
                           "soft term and is refused. Use FOFA body= / PublicWWW / a search engine "
                           "for keyword work.")
        out["capability"] = capability()
    elif args.cmd == "budget":
        out = budget_status()
        out["note"] = (f"A search costs {SEARCH_BUDGET.get('search_costs', 1)} unit, a phonebook "
                       f"search {SEARCH_BUDGET.get('phonebook_costs', 5)}. Counted from the shared "
                       f"ledger across every case.")
    elif not intelx_configured():
        # Keyless is a supported mode, not an error — say exactly what is and is not available so
        # nobody reads an absent IntelX section as "the operator appears in no leak".
        cap = capability()
        print(
            "INTELX: KEYLESS — no INTELX_KEY configured. Capability ~50%.\n"
            "  UNAVAILABLE (needs a key): " + "; ".join(cap["unavailable"]) + ".\n"
            "    Nothing was queried, so nothing being reported is NOT a finding about the target.\n"
            "  STILL AVAILABLE, keyless and free: " + "; ".join(cap["available"]) + ".\n"
            "    Every pivot_extract run already carries those URLs; run them in the web UI.\n"
            f"  Get a key: {UI_TEMPLATES.get('developer_tab')} (Account -> Developer tab), then\n"
            "    `printf 'INTELX_KEY=…\\n' >> .env && chmod 600 .env`.\n"
            "  Detail: WebPivot/references/Setup.md",
            file=sys.stderr)
        return 2
    elif args.cmd == "search":
        bk = [b.strip() for b in args.buckets.split(",") if b.strip()]
        logs_only = bool(args.logs_only and not bk)
        out = search(args.term, maxresults=args.max, buckets=bk,
                     logs_first=(True if logs_only else args.logs_first),
                     general_pass=(False if logs_only else None),
                     datefrom=args.datefrom, dateto=args.dateto, deadline_seconds=args.deadline)
    elif args.cmd == "phonebook":
        out = phonebook(args.domain, target=args.target, maxresults=args.max)
    elif args.cmd == "selectors":
        out = item_selectors(args.systemid)
    elif args.cmd == "item":
        out = read_item(args.storageid, args.bucket, media=args.media, ctype=args.ctype,
                        lines=args.lines, systemid=args.systemid)
    else:
        out = capabilities()
    print(json.dumps(out, indent=2, ensure_ascii=False))
    if args.cmd not in ("query", "budget"):
        b = budget_status()
        print(f"[intelx] spent {b['spent_this_run']} unit(s) this run · "
              f"{b['remaining_today']}/{b['daily_searches']} left today · "
              f"{b['remaining_this_month']}/{b['monthly_searches']} left for {b['month']}",
              file=sys.stderr)
    if api_usage:
        api_usage.print_session_summary()
    return 0


if __name__ == "__main__":
    sys.exit(main())
