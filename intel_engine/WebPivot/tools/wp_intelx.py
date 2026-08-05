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

So results are ordered by `bucket_rank()` (logs first, public combolists near the bottom), and
stealer-log hits come back separately as `read_these` / `stealer_log_items` — items to OPEN one by
one and ask *whose machine is this*, even though the corpus itself can never carry an automatic
edge. Handle them as real victim credentials: cite metadata, never paste secrets into a case file.

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
`MEMORY/api_usage.jsonl` and capped before the call, per run and per month, exactly like the Censys
guard. Thresholds are DATA (`references/intelx.json -> search_budget`), overridable with
`INTELX_MAX_SEARCHES_PER_RUN` / `INTELX_MONTHLY_SEARCHES`.

Auth: `INTELX_KEY` (Account -> Developer tab), sent as the `x-key` header. `INTELX_BASE_URL`
overrides the API root when your account is issued against a different instance.

CLI:
  python3 wp_intelx.py search registrant@example.com [--buckets leaks.logs,pastes] [--max 50]
  python3 wp_intelx.py phonebook example.com [--target emails]   # PAID endpoint
  python3 wp_intelx.py query example.com          # OFFLINE — selector class + UI URLs, no key
  python3 wp_intelx.py caps                       # what this key is entitled to
  python3 wp_intelx.py budget                     # OFFLINE — this month's search spend
"""
import argparse
import copy
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
                  "capabilities": "/authenticate/info", "item_selectors": "/item/selector/list/human"},
    "search_status": {"0": "results", "1": "complete", "2": "unknown id", "3": "still aggregating"},
    "selector_types": {
        "email": {"regex": r"^[^@\s]+@[a-z0-9.-]+\.[a-z]{2,}$", "strong": True},
        "url": {"regex": r"^https?://\S+$", "strong": True},
        "ipv4": {"regex": r"^(?:\d{1,3}\.){3}\d{1,3}$", "strong": True},
        "phone": {"regex": r"^\+?[0-9][0-9 ().-]{6,20}$", "strong": True},
        "domain": {"regex": r"^(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$", "strong": True},
    },
    "pivot_kind_map": {"email": "email", "phone": "phone", "domain": "domain", "ip": "ipv4"},
    "buckets": {},
    "media_types": {},
    "phonebook_targets": {"all": 0, "domains": 1, "emails": 2, "urls": 3},
    "selector_result_types": {"1": "email", "2": "domain", "3": "url", "23": "url query"},
    "plan_capabilities": {"none": {"search": False, "phonebook": False, "file_read": False}},
    # Deliberately the CONSERVATIVE minimum: a broken data file must not silently unlock a bigger
    # spend than the analyst signed up for.
    "search_budget": {"monthly_searches": 500, "max_searches_per_run": 25, "warn_at_remaining": 50,
                      "phonebook_costs": 5, "search_costs": 1, "block_when_exhausted": True},
    "result_limits": {"max_records": 200, "max_selectors": 500, "poll_attempts": 8,
                      "poll_sleep_seconds": 1, "search_timeout_seconds": 5, "preview_lines": 8},
    "ui_templates": {"search": "https://intelx.io/?s={term}", "phonebook": "https://phonebook.cz/?q={term}",
                     "signup": "https://intelx.io/signup"},
    # Fails CLOSED: with no readable policy the module clusters on nothing, which costs leads but
    # never manufactures an operator link out of a shared breach corpus.
    "clustering_policy": {"cluster_on": [], "never_cluster_on": []},
}
_REFS = load_ref(ref_path(__file__, "intelx.json"), _INTELX_FALLBACK)
ENDPOINTS = _REFS["endpoints"]
SEARCH_STATUS = _REFS["search_status"]
SELECTOR_TYPES = _REFS["selector_types"]
PIVOT_KIND_MAP = _REFS["pivot_kind_map"]
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
          timeout: int = 30):
    """One IntelX API call -> (data, error_dict). Never raises.

    `error_dict` is `{"skipped": reason}` for the entitlement/credit/auth conditions the caller is
    expected to survive, and `{"error": ...}` for anything genuinely unexpected."""
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
            raw = r.read().decode("utf-8", "replace")
            try:
                return json.loads(raw), None
            except ValueError:
                return {"raw": raw}, None
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


# --------------------------------------------------------------------------- search BUDGET guard
# Running out of IntelX searches is silent from the analyst's side: the call returns nothing, and an
# empty result reads as "this selector appears in no leak". So the spend is tracked against the
# shared ledger and capped BEFORE the call, never discovered as an empty page mid-batch.
_RUN_SPENT = 0
_MONTH_SPENT = None          # summed from the ledger once per process
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


def _spend(units: int) -> None:
    global _RUN_SPENT, _MONTH_SPENT
    with _BUDGET_LOCK:
        _RUN_SPENT += units
        if _MONTH_SPENT is not None:
            _MONTH_SPENT += units


def budget_status() -> dict:
    """Where the month's IntelX search allowance stands — the number to quote when reporting cost."""
    limit = _budget("monthly_searches", "INTELX_MONTHLY_SEARCHES", 500)
    run_cap = _budget("max_searches_per_run", "INTELX_MAX_SEARCHES_PER_RUN", 25)
    spent = month_spent()
    return {"monthly_searches": limit, "spent_this_month": spent,
            "remaining_this_month": max(0, limit - spent),
            "spent_this_run": _RUN_SPENT, "max_searches_per_run": run_cap,
            "ledger": _ledger_path(),
            "month": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m")}


def _budget_block(cost: int, action: str):
    """None when `cost` units may be spent, else the analyst-readable reason not to. Returned as a
    `skipped` reason, never an exception — the UI link is still the deliverable."""
    if not SEARCH_BUDGET.get("block_when_exhausted", True):
        return None
    b = budget_status()
    if b["spent_this_run"] + cost > b["max_searches_per_run"]:
        return (f"per-run IntelX cap reached ({b['spent_this_run']}/{b['max_searches_per_run']} "
                f"units spent this run; {action} needs {cost}). Raise INTELX_MAX_SEARCHES_PER_RUN "
                f"for a run that genuinely needs it, or run the emitted selector in the web UI.")
    if cost > b["remaining_this_month"]:
        return (f"monthly IntelX allowance exhausted ({b['spent_this_month']}/"
                f"{b['monthly_searches']} units in {b['month']}; {action} needs {cost}). Raise "
                f"INTELX_MONTHLY_SEARCHES if your plan is larger.")
    if b["remaining_this_month"] <= _budget("warn_at_remaining", default=50) and action not in _WARNED:
        _WARNED.add(action)
        print(f"[intelx] ⚠ {b['remaining_this_month']} of {b['monthly_searches']} monthly search "
              f"units left ({b['spent_this_month']} spent in {b['month']}). Spending {cost} on "
              f"{action}.", file=sys.stderr)
    return None


def _memoised(kind: str, ident: str, fn):
    """Run `fn()` once per (kind, ident) per process and hand back a private copy."""
    key = (kind, ident)
    with _MEMO_LOCK:
        if key in _MEMO:
            return copy.deepcopy(_MEMO[key])
    val = fn()
    with _MEMO_LOCK:
        _MEMO[key] = val
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
        "size": rec.get("size"),
        "systemid": rec.get("systemid"),
        "storageid": rec.get("storageid"),
        "xscore": rec.get("xscore"),
        "type": rec.get("type"),
    }
    return {k: v for k, v in out.items() if v not in (None, "", [])}


# --------------------------------------------------------------------------- search (2-step)
def _poll(path: str, ident: str, key: str, limit: int):
    """Drive IntelX's two-step result fetch: GET until `status` says stop.

    status 3 means "still aggregating" — returning on the first empty page would turn a slow
    backend into a false negative, which is the whole failure mode this layer must not have."""
    rows, attempts = [], int(RESULT_LIMITS.get("poll_attempts", 8))
    sleep = float(RESULT_LIMITS.get("poll_sleep_seconds", 1))
    for _ in range(max(1, attempts)):
        data, err = _call(path, params={"id": ident, "limit": limit})
        if err:
            return rows, err
        page = (data or {}).get(key) or []
        rows += [r for r in page if isinstance(r, dict)]
        status = (data or {}).get("status")
        if status in (1, 2) or len(rows) >= limit:
            break
        time.sleep(sleep)
    return rows, None


def search(term: str, maxresults: int = None, buckets: list = None, media: int = 0,
           datefrom: str = "", dateto: str = "", timeout: int = 30):
    """Search IntelX for one strong selector -> {'term','selector','records':[…],'by_bucket':{…}}.

    Returns None with no key. `{"skipped": …}` when the selector is soft, the budget is spent, or
    the account is not entitled — in every one of those cases the emitted UI URL is still the
    deliverable, and the caller MUST NOT read the absence of records as an absence of hits."""
    if not intelx_configured():
        return None
    cls, norm = classify_selector(term)
    ui = intelx_url(norm)
    if not cls:
        return {"skipped": "not a strong selector — IntelX searches email/domain/URL/IP/CIDR/phone/"
                           "wallet/MAC/UUID/IBAN only, never a brand or person name",
                "term": term, "ui_url": ui}
    limit = int(maxresults or RESULT_LIMITS.get("max_records", 200))
    cost = int(SEARCH_BUDGET.get("search_costs", 1))

    def run():
        blocked = _budget_block(cost, f"{cls} search")
        if blocked:
            return {"skipped": blocked, "term": norm, "selector": cls, "ui_url": ui,
                    "budget": budget_status()}
        body = {"term": norm, "buckets": list(buckets or []), "lookuplevel": 0,
                "maxresults": limit, "media": media, "sort": 4, "terminate": [],
                "datefrom": datefrom, "dateto": dateto,
                "timeout": int(RESULT_LIMITS.get("search_timeout_seconds", 5))}
        data, err = _call(ENDPOINTS.get("search_start", "/intelligent/search"),
                          method="POST", body=body, timeout=timeout)
        if err:
            _record("search", 0, norm, ok=False)
            return dict(err, term=norm, selector=cls, ui_url=ui)
        ident = (data or {}).get("id")
        if not ident:
            # status 1 with no id = IntelX accepted the selector and has nothing. That IS a real
            # negative — but only because the search ran, which is exactly the distinction the
            # keyless mode cannot make.
            _record("search", cost, norm, results=0)
            return {"term": norm, "selector": cls, "ui_url": ui, "records": [], "by_bucket": {},
                    "note": "IntelX ran the search and returned no records for this selector."}
        rows, perr = _poll(ENDPOINTS.get("search_result", "/intelligent/search/result"),
                           ident, "records", limit)
        _call(ENDPOINTS.get("search_terminate", "/intelligent/search/terminate"),
              params={"id": ident})          # free the backend slot; costs nothing
        recs = [summarise_record(r) for r in rows]
        recs = [r for r in recs if r][:limit]
        # Rank order, newest first within a rank. IntelX returns whatever matched, and on a
        # long-exposed address that is overwhelmingly recycled combolist rows — sorting by bucket
        # value is what keeps the one stealer-log entry from being buried under a hundred of them.
        # Two stable passes: newest first, then bucket rank on top of it — so within the logs the
        # freshest infection leads, and the logs as a whole lead the combolists.
        recs.sort(key=lambda r: str(r.get("date") or ""), reverse=True)
        recs.sort(key=lambda r: r.get("rank", 99))
        _record("search", cost, norm, results=len(recs))
        by_bucket = {}
        for r in recs:
            by_bucket[r.get("bucket") or "(none)"] = by_bucket.get(r.get("bucket") or "(none)", 0) + 1
        by_bucket = dict(sorted(by_bucket.items(), key=lambda kv: bucket_rank(kv[0])))
        out = {"term": norm, "selector": cls, "ui_url": ui, "records": recs,
               "by_bucket": by_bucket,
               "clusterable_hits": [r for r in recs if r.get("clusterable")],
               # The items to actually open — stealer-log entries, where a single record can name
               # the operator's own machine. Surfaced separately so a thin `clusterable_hits` list
               # never reads as "nothing here worth reading".
               "read_these": [r for r in recs if r.get("read_item")]}
        if perr:
            out["partial"] = perr
        return out
    return _memoised("search", f"{norm}|{','.join(buckets or [])}|{limit}", run)


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
        rows, perr = _poll(ENDPOINTS.get("phonebook_result", "/phonebook/search/result"),
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
               "total": len(rows)}
        if perr:
            out["partial"] = perr
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
# Priority order for spending a bounded allowance across a result's artifacts. Contact selectors
# come first because they are the ones that carry ATTRIBUTION — a registrant email or a support
# phone in a paste or a market listing is the operator's own text. The host itself is last: it is
# the selector the analyst can most easily run by hand in the UI.
_ENRICH_PRIORITY = ["email", "phone", "bitcoin", "iban", "url", "ipv4", "domain"]


def _enrich_targets(result: dict) -> list:
    """[(selector_class, value, pivot)] for every artifact in a result IntelX can search, ordered
    by `_ENRICH_PRIORITY` and de-duplicated on the normalised value."""
    seen, rows = set(), []
    for piv in result.get("pivots") or []:
        sel = selector_for_kind(piv.get("kind"))
        if not sel:
            continue
        cls, norm = classify_selector(str(piv.get("value") or ""))
        if not cls or norm in seen:
            continue
        seen.add(norm)
        rows.append((cls, norm, piv))
    host = (result.get("meta") or {}).get("host")
    if host:
        cls, norm = classify_selector(str(host))
        if cls == "domain" and norm not in seen:
            seen.add(norm)
            rows.append((cls, norm, None))
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
    are ordered so a small allowance is spent on the contact selectors that carry attribution
    rather than on whatever happened to sort first.

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
            pb = phonebook(norm) or {}
            out["phonebook"] = pb
            if pb.get("emails") or pb.get("domains"):
                # These are COLLECTION TARGETS, not conclusions: an address IntelX saw under the
                # apex still has to be corroborated before it attributes anything.
                out["discovered"] = {"emails": pb.get("emails", [])[:50],
                                     "subdomains": pb.get("domains", [])[:50],
                                     "urls": pb.get("urls", [])[:50]}
            limit = max(0, limit - 1)

    for cls, value, piv in targets:
        if limit <= 0:
            out["skipped_for_budget"].append(value)
            continue
        hits = search(value)
        if not isinstance(hits, dict):
            continue
        limit -= 1
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
                                "skipped": hits.get("skipped")})
        if hits.get("read_these"):
            out.setdefault("stealer_log_items", []).extend(hits["read_these"][:10])
    if out.get("stealer_log_items"):
        out["stealer_log_note"] = (
            "Stealer-log items matched. Open them individually — a log is one machine at one "
            "moment, so the question is WHOSE machine: a victim of this campaign (holds "
            "credentials for the scam's front-end → victim/access-vector layer) or the OPERATOR's "
            "own box (holds the admin panel, registrar, CMS or exchange logins behind it → direct "
            "attribution). Corpus co-membership is still not an operator link. Handle as real "
            "victim credentials: cite the item's metadata, never paste secrets into the case file.")
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
           "search", "phonebook", "item_selectors", "capabilities", "enrich_result",
           "capability", "banner_lines",
           "bucket_grade", "bucket_rank", "item_evidence", "clusterable", "summarise_record",
           "budget_status", "month_spent",
           "ENDPOINTS", "SELECTOR_TYPES", "PIVOT_KIND_MAP", "BUCKETS", "PHONEBOOK_TARGETS",
           "PLAN_CAPABILITIES", "SEARCH_BUDGET", "RESULT_LIMITS", "UI_TEMPLATES",
           "CLUSTERING_POLICY"]


def main():
    ap = argparse.ArgumentParser(description="Intelligence X selector search + keyless query builder")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("search", help="search one strong selector (1 unit)")
    p.add_argument("term")
    p.add_argument("--buckets", default="", help="comma list, e.g. leaks.logs,pastes")
    p.add_argument("--max", type=int, default=None)
    p.add_argument("--datefrom", default="")
    p.add_argument("--dateto", default="")
    p = sub.add_parser("phonebook", help="domain -> emails/subdomains/URLs (PAID endpoint)")
    p.add_argument("domain")
    p.add_argument("--target", default="all", choices=sorted(PHONEBOOK_TARGETS.keys()))
    p.add_argument("--max", type=int, default=None)
    p = sub.add_parser("selectors", help="selectors extracted from one item, by systemid")
    p.add_argument("systemid")
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
        out = search(args.term, maxresults=args.max,
                     buckets=[b.strip() for b in args.buckets.split(",") if b.strip()],
                     datefrom=args.datefrom, dateto=args.dateto)
    elif args.cmd == "phonebook":
        out = phonebook(args.domain, target=args.target, maxresults=args.max)
    elif args.cmd == "selectors":
        out = item_selectors(args.systemid)
    else:
        out = capabilities()
    print(json.dumps(out, indent=2, ensure_ascii=False))
    if args.cmd not in ("query", "budget"):
        b = budget_status()
        print(f"[intelx] spent {b['spent_this_run']} unit(s) this run · "
              f"{b['remaining_this_month']}/{b['monthly_searches']} left for {b['month']}",
              file=sys.stderr)
    if api_usage:
        api_usage.print_session_summary()
    return 0


if __name__ == "__main__":
    sys.exit(main())
