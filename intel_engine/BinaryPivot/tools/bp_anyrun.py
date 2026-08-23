#!/usr/bin/env python3
"""bp_anyrun — ANY.RUN sandbox client for BinaryPivot: gated submission, task reads, TI Lookup.

WHAT THIS API ACTUALLY IS
-------------------------
The ANY.RUN API is a SANDBOX-SUBMISSION API. Its centre of gravity is `POST /v1/analysis`: hand it
a file or a URL, it detonates it in an interactive VM and returns a task with the network log,
dropped files and a verdict. **Threat Intelligence Lookup — searching other people's detonations
without running your own — is a separate and comparatively limited product**: its own licence, a
small request allowance, and absent entirely from a plain sandbox subscription. So TI Lookup is
treated here as a bonus for when the licence exists (`keycheck` says whether it does), and the
sandbox is the layer's real surface.

SUBMISSION IS AN OPSEC DECISION, AND IT IS ALWAYS THE ANALYST'S
----------------------------------------------------------------
A lookup asks a question. A submission takes the analyst's case material, hands it to a third
party, and then reaches out and TOUCHES the target from a fingerprintable sandbox. Both halves can
burn an investigation and neither is reversible — deleting the task afterwards does not un-send the
sample and does not un-notify the operator. Concretely:

  - **public exposure** — on a free plan every submission is world-readable and searchable: sample,
    URL, screenshots, network log. Operators monitor that feed for their own domains and hashes.
  - **tipping the operator** — a URL detonation FETCHES the live target from published ANY.RUN
    egress ranges. The operator sees a known sandbox hit their funnel, and rotates or cloaks.
  - **a poisoned verdict** — the same filtering means a clean result may just be the decoy these
    funnels serve to datacenter IPs. `info` is not exoneration.
  - **third-party data handling** — the sample may carry victim PII or client data.

So this module **never submits without explicit, per-submission confirmation**. `submit()` refuses
unless `confirm=True` is passed and returns `submit_preflight()` — the risk briefing plus the
cheaper alternatives — instead. Nothing in the collector path can reach it: `analyze_artifact` does
static extraction and lookups only. Privacy defaults to `owner`, `public` is refused outright, and
a free-plan submission is refused rather than silently downgraded to a public one. The policy is
DATA (`references/anyrun.json -> submission_policy`), so an analyst can tighten it without touching
code — but `require_explicit_confirmation` is enforced in the function signature, not read from the
file, because a config edit must not be able to turn the gate off.

WHAT THE LOOKUP SIDE ADDS THAT STATIC ANALYSIS CANNOT
------------------------------------------------------
`analyze_artifact.py` reads what a sample IS. ANY.RUN reports what samples like it DID when they
were detonated: the domains and IPs actually contacted, the family label, the Suricata alerts, and
the public sandbox sessions an analyst can open and watch. Three consequences for casework:

  - **it recovers infrastructure static extraction never sees.** A backend host assembled at
    runtime, or decrypted out of a packed payload, is absent from the strings sweep by
    construction — but it is right there in the network log of any detonation. This is the direct
    answer to a `binary:protection` finding: when the string sweep is thin BECAUSE the sample is
    protected, the sandbox record is where the operator's real endpoints live.
  - **it is an observation, not a reputation score.** `domainName` / `destinationIP` hits mean a
    sample *contacted* that host. That is a far stronger statement than "this string appears in
    the file", and it joins straight onto the web case: those hosts go back into WebPivot.
  - **it dates the behaviour.** Task timestamps give the campaign's active window from a corpus
    that is independent of WHOIS, CT and the archive.

WHAT IT DOES NOT PROVE — READ BEFORE CLUSTERING
-----------------------------------------------
A shared **threat family** is a same-KIT signal, exactly like a shared packer or a shared
white-label CDN: two unrelated crews running the same commodity stealer are not one crew. And half
of what any detonation contacts is shared internet furniture. `references/anyrun.json ->
clustering_policy` fixes which fields may carry an operator edge (`domainName`, `destinationIP`,
`url`, `jarm`) and which are context only; `grade_field()` stamps that judgement onto every result
so the distinction survives into the case file.

KEYLESS IS A SUPPORTED MODE — AND IT IS ABOUT HALF THE LAYER
-------------------------------------------------------------
With no `ANYRUN_API_KEY` this module still writes the correct TI Lookup query for every artifact
the analysis produced (choosing the right observation field, splitting an `ip:port` into
destinationIP + destinationPort, bounding the time window) and hands over the UI address to paste
it into, plus the public-task links. Composing the query is most of the tradecraft, and it costs
nothing. What is lost is running it: the related domains/IPs/URLs, the family label, the task list,
and any automatic feedback of discovered infrastructure into the case. `capability()` reports that
as **~50% of full capability** and the banner says it out loud — because an absent ANY.RUN section
must never read as "this sample is unknown to the sandbox world".

REQUESTS ARE METERED
--------------------
A TI Lookup trial is tens of requests, not thousands. Spend is counted from the shared
`MEMORY/api_usage.jsonl` ledger and capped before the call, per run and per month; thresholds are
DATA (`references/anyrun.json -> request_budget`), overridable with `ANYRUN_MAX_REQUESTS_PER_RUN` /
`ANYRUN_MONTHLY_REQUESTS`.

Auth: `ANYRUN_API_KEY`, sent as `Authorization: API-KEY <key>` (a bare key is fine — the prefix is
added). TI Lookup is a SEPARATE licence from the sandbox: a sandbox-only key answers 401/403 on
`/intelligence/*`, which this module reports as an entitlement fact, not as an error.

CLI:
  python3 bp_anyrun.py query file:sha256 <hash>     # OFFLINE — builds the query + UI link, no key
  python3 bp_anyrun.py lookup --sha256 <hash>       # TI Lookup (needs the separate licence)
  python3 bp_anyrun.py lookup --domain backend.example.com [--days 90]
  python3 bp_anyrun.py history [--limit 20]         # YOUR OWN past tasks
  python3 bp_anyrun.py report <task-uuid> [--iocs]  # one task's report / IOC set
  python3 bp_anyrun.py submit ./sample.bin          # prints the RISK BRIEFING and refuses
  python3 bp_anyrun.py submit ./sample.bin --confirm-submission   # actually detonates
  python3 bp_anyrun.py keycheck                     # is this key entitled to TI Lookup?
  python3 bp_anyrun.py budget                       # OFFLINE — this month's request spend
"""
import argparse
import copy
import datetime
import json
import os
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request

import bp_refs  # noqa: E402 — reference DATA lives in references/*.json (RULE 3)

# The licensed-API ledger lives with WebPivot (one ledger for every metered call in the toolkit —
# CLAUDE.md § Cost visibility). BinaryPivot is imported standalone on other machines, so the import
# is best-effort: inside the repo we reuse api_usage.record; outside it we append the SAME JSONL
# schema ourselves rather than silently losing the spend record.
try:
    import api_usage
except Exception:
    api_usage = None
    _sib = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                         os.pardir, os.pardir, "WebPivot", "tools"))
    if os.path.isdir(_sib):
        sys.path.append(_sib)
        try:
            import api_usage  # noqa: F811
        except Exception:
            api_usage = None

DEFAULT_UA = "Mozilla/5.0 (compatible; BinaryPivot/1.0)"

# --- reference DATA (RULE 3). The fallback is the minimum that keeps the KEYLESS query builder
#     correct if the JSON goes missing — load_ref warns loudly when it does.
_ANYRUN_FALLBACK = {
    "endpoints": {"api_base": "https://api.any.run/v1", "report_base": "https://api.any.run/report",
                  "submit_analysis": "/analysis",
                  "ti_search": "/intelligence/api/search", "ti_keycheck": "/intelligence/keycheck",
                  "analysis_history": "/analysis", "analysis_report": "/analysis/{id}",
                  "report_ioc": "/{id}/ioc/json", "user_limits": "/user"},
    "privacy_types": {"owner": "only you"},
    # The fallback is the STRICT end of the policy on purpose: if the data file is unreadable the
    # gate must still hold. `require_explicit_confirmation` is enforced in code regardless.
    "submission_policy": {"require_explicit_confirmation": True, "default_privacy": "owner",
                          "forbidden_privacy": ["public"], "refuse_on_free_plan": True,
                          "default_auto_delete_after": "week",
                          "risks": ["a submission is outbound, attributable and irreversible — it "
                                    "may expose the sample publicly and tells the target it is "
                                    "being sandboxed"],
                          "preflight_checks": ["run the static analysis first",
                                               "look for an EXISTING detonation of this hash"],
                          "never_send": ["case IDs", "analyst or client names"]},
    "query_fields": {"sha256": "file hash", "domainName": "a domain contacted during detonation",
                     "destinationIP": "an IP contacted during detonation",
                     "destinationPort": "the port of that connection", "url": "a full URL requested"},
    "pivot_field_map": {"file:sha256": "sha256", "app:backend_host": "domainName",
                        "app:c2_endpoint": "destinationIP", "domain": "domainName",
                        "ip": "destinationIP", "url": "url"},
    "verdict_levels": {},
    "plan_capabilities": {"none": {"ti_lookup": False, "sandbox_api": False}},
    # Deliberately the CONSERVATIVE minimum: a broken data file must never unlock a bigger spend.
    "request_budget": {"monthly_requests": 50, "max_requests_per_run": 10, "warn_at_remaining": 10,
                       "lookup_costs": 1, "block_when_exhausted": True},
    "result_limits": {"max_tasks": 25, "max_related_indicators": 100, "lookup_days": 180},
    "ui_templates": {"lookup_ui": "https://intelligence.any.run/analysis/lookup",
                     "public_task": "https://app.any.run/tasks/{id}",
                     "submissions": "https://app.any.run/submissions"},
    # Fails CLOSED: with no readable policy nothing is clusterable, which costs leads but never
    # manufactures an operator link out of a shared malware family.
    "clustering_policy": {"cluster_on": [], "context_only": []},
}
_REFS = bp_refs.load_ref(bp_refs.ref_path(__file__, "anyrun.json"), _ANYRUN_FALLBACK)
ENDPOINTS = _REFS["endpoints"]
PRIVACY_TYPES = _REFS["privacy_types"]
SUBMISSION_POLICY = _REFS["submission_policy"]
QUERY_FIELDS = _REFS["query_fields"]
PIVOT_FIELD_MAP = _REFS["pivot_field_map"]
VERDICT_LEVELS = _REFS["verdict_levels"]
PLAN_CAPABILITIES = _REFS["plan_capabilities"]
REQUEST_BUDGET = _REFS["request_budget"]
RESULT_LIMITS = _REFS["result_limits"]
UI_TEMPLATES = _REFS["ui_templates"]
CLUSTERING_POLICY = _REFS["clustering_policy"]

_MEMO = {}
_MEMO_LOCK = threading.Lock()

# Master off switch, flipped by `analyze_artifact --no-anyrun`. Only the NETWORK calls honour it —
# the query builder is offline and free, so it keeps emitting queries either way.
ENABLED = True


def _secret(*names):
    """First non-empty environment variable among `names`, else None (same contract as WebPivot's
    `wp_common._secret`, re-implemented locally because BinaryPivot ships standalone)."""
    for n in names:
        v = os.environ.get(n)
        if v and v.strip():
            return v.strip()
    return None


def uniq(seq):
    seen, out = set(), []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


# --------------------------------------------------------------------------- auth / transport
def anyrun_key():
    """The ANY.RUN API key, or None."""
    return _secret("ANYRUN_API_KEY", "ANY_RUN_API_KEY", "ANYRUN_KEY")


def anyrun_configured() -> bool:
    return ENABLED and bool(anyrun_key())


def _headers():
    h = {"User-Agent": DEFAULT_UA, "Accept": "application/json"}
    key = anyrun_key()
    if key:
        # ANY.RUN expects `API-KEY <key>`; analysts paste the bare key as often as the prefixed
        # form, and sending the bare one is an opaque 401 rather than a useful error.
        h["Authorization"] = key if key.lower().startswith(("api-key ", "basic ")) else f"API-KEY {key}"
    return h


_STATUS_REASON = {
    400: "ANY.RUN rejected the query — check the field name against references/anyrun.json -> "
         "query_fields (TI Lookup is field:\"value\", not free text)",
    401: "ANY.RUN rejected the key (ANYRUN_API_KEY missing or expired)",
    403: "your ANY.RUN plan does not include this endpoint — TI Lookup is a SEPARATE licence from "
         "the sandbox, so a sandbox key cannot query /intelligence/*",
    404: "not in the ANY.RUN dataset",
    429: "ANY.RUN rate limit",
}


def _call(url: str, *, method: str = "GET", body: dict = None, timeout: int = 30):
    """One ANY.RUN API call -> (data, error_dict). Never raises.

    `error_dict` is `{"skipped": reason}` for the entitlement/auth/quota conditions the caller is
    expected to survive, `{"error": ...}` for anything genuinely unexpected."""
    if not anyrun_configured():
        return None, {"skipped": "no ANYRUN_API_KEY configured"}
    data = json.dumps(body).encode() if body is not None else None
    headers = _headers()
    if data:
        headers["Content-Type"] = "application/json"
    try:
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.load(r), None
    except urllib.error.HTTPError as e:
        reason = _STATUS_REASON.get(e.code)
        msg = f"HTTP {e.code}" + (f" — {reason}" if reason else "")
        if e.code in _STATUS_REASON:
            return None, {"skipped": msg}
        return None, {"error": msg}
    except Exception as e:
        return None, {"error": str(e)}


def _log_path():
    if api_usage:
        return api_usage._log_path()
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    return _secret("API_USAGE_LOG") or os.path.join(root, "MEMORY", "api_usage.jsonl")


def _record(action: str, credits: int, query: str, results=None, ok: bool = True):
    """Log one metered ANY.RUN call (CLAUDE.md: every licensed API call is recorded)."""
    if credits:
        _spend(credits)
    if api_usage:
        api_usage.record("anyrun", action, credits=credits, query=query, results=results, ok=ok)
        return
    rec = {"ts": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
           "provider": "anyrun", "action": action, "credits": (credits if ok else 0),
           "query": (str(query)[:200] if query else None), "results": results, "ok": ok,
           "case": None, "skill": "binarypivot"}
    try:
        p = _log_path()
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception:
        pass


# --------------------------------------------------------------------------- request BUDGET guard
_RUN_SPENT = 0
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
                print(f"[anyrun] WARNING: {env}={raw!r} is not a number; using the reference value.",
                      file=sys.stderr)
    return REQUEST_BUDGET.get(key, default)


def month_spent(refresh: bool = False) -> int:
    """ANY.RUN requests already spent this UTC month, from the shared ledger — every tool and every
    case, since the allowance is per account. Unreadable ledger -> 0."""
    global _MONTH_SPENT
    with _BUDGET_LOCK:
        if _MONTH_SPENT is not None and not refresh:
            return _MONTH_SPENT
    month = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m")
    total = 0
    try:
        with open(_log_path(), encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or '"anyrun"' not in line:
                    continue
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                if rec.get("provider") == "anyrun" and (rec.get("ts") or "").startswith(month):
                    total += rec.get("credits") or 0
    except FileNotFoundError:
        total = 0
    except Exception as exc:
        print(f"[anyrun] WARNING: could not read the usage ledger ({exc}); the monthly guard is "
              f"running on this process's spend only.", file=sys.stderr)
        total = 0
    with _BUDGET_LOCK:
        _MONTH_SPENT = total
    return total


def _spend(n: int) -> None:
    global _RUN_SPENT, _MONTH_SPENT
    with _BUDGET_LOCK:
        _RUN_SPENT += n
        if _MONTH_SPENT is not None:
            _MONTH_SPENT += n


def budget_status() -> dict:
    limit = _budget("monthly_requests", "ANYRUN_MONTHLY_REQUESTS", 50)
    run_cap = _budget("max_requests_per_run", "ANYRUN_MAX_REQUESTS_PER_RUN", 10)
    spent = month_spent()
    return {"monthly_requests": limit, "spent_this_month": spent,
            "remaining_this_month": max(0, limit - spent),
            "spent_this_run": _RUN_SPENT, "max_requests_per_run": run_cap,
            "ledger": _log_path(),
            "month": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m")}


def _budget_block(cost: int, action: str):
    """None when `cost` requests may be spent, else the analyst-readable reason not to. Returned as
    a `skipped` reason — the built query and its UI link remain the deliverable."""
    if not REQUEST_BUDGET.get("block_when_exhausted", True):
        return None
    b = budget_status()
    if b["spent_this_run"] + cost > b["max_requests_per_run"]:
        return (f"per-run ANY.RUN cap reached ({b['spent_this_run']}/{b['max_requests_per_run']} "
                f"requests this run; {action} needs {cost}). Raise ANYRUN_MAX_REQUESTS_PER_RUN, or "
                f"paste the emitted query into the TI Lookup UI.")
    if cost > b["remaining_this_month"]:
        return (f"monthly ANY.RUN allowance exhausted ({b['spent_this_month']}/"
                f"{b['monthly_requests']} in {b['month']}; {action} needs {cost}). Raise "
                f"ANYRUN_MONTHLY_REQUESTS if your licence is larger.")
    if b["remaining_this_month"] <= _budget("warn_at_remaining", default=10) and action not in _WARNED:
        _WARNED.add(action)
        print(f"[anyrun] ⚠ {b['remaining_this_month']} of {b['monthly_requests']} monthly TI Lookup "
              f"requests left. Spending {cost} on {action}.", file=sys.stderr)
    return None


def _memoised(kind: str, ident: str, fn):
    key = (kind, ident)
    with _MEMO_LOCK:
        if key in _MEMO:
            return copy.deepcopy(_MEMO[key])
    val = fn()
    with _MEMO_LOCK:
        _MEMO[key] = val
    return copy.deepcopy(val)


# --------------------------------------------------------------------------- query BUILDER (keyless)
def field_for_kind(kind: str):
    """BinaryPivot pivot `kind` -> the TI Lookup field that reverses it, honouring `prefix:`
    entries. None when the sandbox does not index the artifact — which is the right answer for a
    signing certificate, an APK package name or a firebase project id."""
    if not kind:
        return None
    if kind in PIVOT_FIELD_MAP:
        return PIVOT_FIELD_MAP[kind]
    for pref, field in PIVOT_FIELD_MAP.items():
        if pref.endswith(":") and kind.startswith(pref):
            return field
    return None


def build_query(kind: str, value) -> str:
    """The TI Lookup query string for one artifact, or "" when ANY.RUN cannot reverse it.

    `app:c2_endpoint` is the one special case: an `ip:port` value is split into
    destinationIP + destinationPort so the query matches the CONNECTION rather than a literal
    string that would never appear in the index."""
    field = field_for_kind(kind)
    if not field:
        return ""
    val = str(value or "").strip()
    if not val:
        return ""
    if field == "destinationIP" and ":" in val and val.count(":") == 1:
        ip, _, port = val.partition(":")
        if port.isdigit():
            return f'destinationIP:"{ip}" AND destinationPort:"{port}"'
        val = ip
    return f'{field}:"{val}"'


def anyrun_queries(kind: str, value, ui: bool = True) -> list:
    """Ready-to-run ANY.RUN entries for a pivot's `queries` list. [] when the sandbox does not
    index the artifact. Pure string building — keyless-safe and free."""
    q = build_query(kind, value)
    if not q:
        return []
    out = [{"service": "ANY.RUN TI Lookup", "query": q}]
    if ui:
        # TI Lookup has no shareable query URL, so the honest keyless deliverable is the UI address
        # plus the exact query text to paste into it.
        out.append({"service": "ANY.RUN TI Lookup UI (paste the query above)",
                    "query": UI_TEMPLATES.get("lookup_ui", "https://intelligence.any.run/analysis/lookup")})
    return out


def attach_anyrun_queries(pivots: list) -> list:
    """Append the TI Lookup query (+ the UI link) to every pivot whose kind ANY.RUN can reverse.

    One pass over the finished pivot list, so `references/anyrun.json -> pivot_field_map` is the
    single place an analyst edits to teach BinaryPivot a new lookup field. Mutates and returns
    `pivots`."""
    for piv in pivots or []:
        if any("ANY.RUN" in (q.get("service") or "") for q in (piv.get("queries") or [])):
            continue
        qs = anyrun_queries(piv.get("kind"), piv.get("value"))
        if qs:
            piv.setdefault("queries", []).extend(qs)
    return pivots


def task_url(task_id: str) -> str:
    """The public sandbox session for a task uuid — the link a report cites so a reader can watch
    the detonation instead of taking our word for it."""
    tpl = UI_TEMPLATES.get("public_task", "https://app.any.run/tasks/{id}")
    return tpl.replace("{id}", urllib.parse.quote(str(task_id or ""), safe=""))


# --------------------------------------------------------------------------- result grading
def grade_field(field: str) -> str:
    """`cluster` | `context` | `ungraded` — whether a hit on this TI Lookup field may support a
    same-operator edge. Fails closed: an unknown field is never clusterable."""
    f = (field or "").strip()
    if f in (CLUSTERING_POLICY.get("cluster_on") or []):
        return "cluster"
    if f in (CLUSTERING_POLICY.get("context_only") or []):
        return "context"
    return "ungraded"


def _rows(node, *keys):
    """Pull a list out of whichever container ANY.RUN wrapped it in. The lookup response has been
    reshaped by ANY.RUN more than once, so every extraction here is defensive: a field we cannot
    find is reported empty, never as an exception in the middle of a case."""
    if not isinstance(node, dict):
        return []
    for k in keys:
        v = node.get(k)
        if isinstance(v, list):
            return v
    return []


def summarise_lookup(data: dict) -> dict:
    """A TI Lookup response -> the operator-relevant subset, each indicator carrying its grade.

    Keeps the network observations (domains, IPs, URLs) because those are the ones that go back
    into WebPivot, plus the summary verdict and the task links that let a reader verify."""
    if not isinstance(data, dict):
        return {}
    body = data.get("data") if isinstance(data.get("data"), dict) else data
    cap = int(RESULT_LIMITS.get("max_related_indicators", 100))
    summary = body.get("summary") if isinstance(body.get("summary"), dict) else {}

    def _vals(rows, key):
        return uniq([r.get(key) for r in rows if isinstance(r, dict) and r.get(key)])[:cap]

    dns_rows = _rows(body, "relatedDNS", "domainName")
    ip_rows = _rows(body, "destinationIP", "relatedIP")
    url_rows = _rows(body, "relatedURLs", "url")
    threats = uniq([t for r in (dns_rows + ip_rows + url_rows) if isinstance(r, dict)
                    for t in (r.get("threatName") or [])])
    tasks = _rows(body, "relatedTasks", "sourceTasks", "tasks")
    task_ids = uniq([t.get("uuid") or t.get("related") or t.get("taskId")
                     for t in tasks if isinstance(t, dict)])[:int(RESULT_LIMITS.get("max_tasks", 25))]
    out = {
        "threat_level": summary.get("threatLevel"),
        "last_seen": summary.get("lastSeen"),
        "tags": summary.get("tags") or [],
        "domains": _vals(dns_rows, "domainName"),
        "ips": _vals(ip_rows, "destinationIP"),
        "urls": _vals(url_rows, "url"),
        "ports": uniq(body.get("destinationPort") or [])[:cap],
        "countries": uniq(body.get("destinationIPgeo") or [])[:cap],
        "asns": uniq([a.get("asn") for a in _rows(body, "destinationIpAsn") if isinstance(a, dict)])[:cap],
        "related_files": [f.get("hashes", {}).get("sha256") for f in _rows(body, "relatedFiles")
                          if isinstance(f, dict) and f.get("hashes")][:cap],
        "threat_names": threats[:cap],
        "task_urls": [task_url(t) for t in task_ids if t],
    }
    out = {k: v for k, v in out.items() if v not in (None, [], "")}
    if out.get("domains") or out.get("ips") or out.get("urls"):
        out["clusterable"] = ("domains / ips / urls are OBSERVED CONTACTS and may support an "
                              "operator edge once corroborated")
    if out.get("threat_names"):
        out["kit_level_only"] = ("threat_names group by malware FAMILY, not by operator — a shared "
                                 "family is a same-KIT signal, never attribution on its own")
    return out


# --------------------------------------------------------------------------- TI Lookup
def _window(days: int = None):
    d = int(days or RESULT_LIMITS.get("lookup_days", 180))
    today = datetime.datetime.now(datetime.timezone.utc).date()
    return (today - datetime.timedelta(days=d)).isoformat(), today.isoformat()


def ti_lookup(query: str, days: int = None, timeout: int = 45):
    """Run a raw TI Lookup query -> the summarised observation set.

    Returns None with no key. `{"skipped": …}` when the licence or the budget says no — in which
    case the query string itself is still the deliverable and its absence of results says NOTHING
    about the sample."""
    if not anyrun_configured():
        return None
    q = (query or "").strip()
    if not q:
        return {"error": "empty query"}
    cost = int(REQUEST_BUDGET.get("lookup_costs", 1))
    start, end = _window(days)

    def run():
        blocked = _budget_block(cost, "TI Lookup")
        if blocked:
            return {"skipped": blocked, "query": q, "ui_url": UI_TEMPLATES.get("lookup_ui"),
                    "budget": budget_status()}
        url = ENDPOINTS.get("api_base", "https://api.any.run/v1") + \
            ENDPOINTS.get("ti_search", "/intelligence/api/search")
        data, err = _call(url, method="POST",
                          body={"query": q, "startDate": start, "endDate": end}, timeout=timeout)
        if err:
            _record("ti_lookup", 0, q, ok=False)
            return dict(err, query=q, ui_url=UI_TEMPLATES.get("lookup_ui"))
        res = summarise_lookup(data)
        _record("ti_lookup", cost, q,
                results=len(res.get("domains", [])) + len(res.get("ips", [])))
        return dict(res, query=q, window={"from": start, "to": end},
                    ui_url=UI_TEMPLATES.get("lookup_ui"))
    return _memoised("ti_lookup", f"{q}|{start}", run)


def lookup_artifact(kind: str, value, days: int = None):
    """TI Lookup for one BinaryPivot artifact, by pivot kind. `{"skipped": …}` when ANY.RUN does
    not index that kind — a fact about the sandbox, not about the sample."""
    q = build_query(kind, value)
    if not q:
        return {"skipped": f"ANY.RUN does not index {kind} — no observation field maps to it",
                "kind": kind, "value": value}
    return ti_lookup(q, days=days)


def keycheck(timeout: int = 20):
    """Is this key entitled to TI Lookup? Costs nothing, and answers the question that otherwise
    surfaces as a confusing 403 halfway through a batch."""
    if not anyrun_configured():
        return None

    def run():
        url = ENDPOINTS.get("api_base", "https://api.any.run/v1") + \
            ENDPOINTS.get("ti_keycheck", "/intelligence/keycheck")
        data, err = _call(url, timeout=timeout)
        if err:
            return dict(err, entitled=False,
                        note="TI Lookup is a separate licence from the sandbox")
        return {"entitled": True, "response": data}
    return _memoised("keycheck", "self", run)


# --------------------------------------------------------------------------- sandbox READS
def analysis_history(limit: int = 25, skip: int = 0, timeout: int = 30):
    """YOUR OWN past tasks. Read-only and free of the submission gate — and the first thing to
    check before detonating anything, because the answer is often already in your history."""
    if not anyrun_configured():
        return None
    url = (ENDPOINTS.get("api_base", "https://api.any.run/v1")
           + ENDPOINTS.get("analysis_history", "/analysis")
           + f"?limit={max(1, min(100, int(limit)))}&skip={max(0, int(skip))}")

    def run():
        data, err = _call(url, timeout=timeout)
        if err:
            return dict(err)
        rows = ((data or {}).get("data") or {}).get("tasks") or []
        out = []
        for t in rows if isinstance(rows, list) else []:
            if not isinstance(t, dict):
                continue
            out.append({k: v for k, v in {
                "uuid": t.get("uuid"), "verdict": t.get("verdict"),
                "name": (t.get("related") or t.get("name")), "date": t.get("date"),
                "task_url": task_url(t.get("uuid") or ""),
            }.items() if v})
        return {"tasks": out, "count": len(out)}
    return _memoised("history", f"{limit}|{skip}", run)


def analysis_report(task_uuid: str, iocs: bool = False, timeout: int = 45):
    """One task's report, or its IOC set with `iocs=True`. Read-only."""
    if not anyrun_configured():
        return None
    base = ENDPOINTS.get("api_base", "https://api.any.run/v1")
    if iocs:
        url = (ENDPOINTS.get("report_base", "https://api.any.run/report")
               + ENDPOINTS.get("report_ioc", "/{id}/ioc/json").replace("{id}", str(task_uuid)))
    else:
        url = base + ENDPOINTS.get("analysis_report", "/analysis/{id}").replace("{id}", str(task_uuid))

    def run():
        data, err = _call(url, timeout=timeout)
        if err:
            return dict(err, task_uuid=task_uuid)
        return {"task_uuid": task_uuid, "task_url": task_url(task_uuid),
                "report": (data or {}).get("data") or data}
    return _memoised("report", f"{task_uuid}|{iocs}", run)


# --------------------------------------------------------------------------- submission (GATED)
def submit_preflight(target: str, kind: str = "file") -> dict:
    """The briefing an analyst must see BEFORE a submission — never a step that can be skipped.

    Returned by `submit()` whenever confirmation is absent, and meant to be shown verbatim: the
    irreversible consequences, the cheaper things to try first, and the settings this submission
    would actually use. The caller's job is to put this in front of the human and ask; consent to
    'analyze this sample' is NOT consent to detonate it on someone else's infrastructure."""
    policy = SUBMISSION_POLICY
    privacy = policy.get("default_privacy", "owner")
    return {
        "action": "CONFIRMATION REQUIRED — nothing has been submitted",
        "target": target,
        "kind": kind,
        "irreversible": True,
        "why_it_is_gated": (
            "A submission hands your case material to a third party AND touches the target from a "
            "published sandbox egress range. Deleting the task afterwards un-sends nothing and "
            "un-notifies nobody."),
        "risks": list(policy.get("risks") or []),
        "try_first": list(policy.get("preflight_checks") or []),
        "would_use": {
            "privacy": privacy,
            "privacy_means": (PRIVACY_TYPES or {}).get(privacy, "unknown"),
            "auto_delete_after": policy.get("default_auto_delete_after") or "(account default)",
            "network": "enabled — a URL submission WILL fetch the live target",
        },
        "never_send": list(policy.get("never_send") or []),
        "to_proceed": ("ask the analyst explicitly, then call submit(..., confirm=True) — or "
                       "`bp_anyrun.py submit <target> --confirm-submission` on the CLI"),
    }


def submit(target: str, kind: str = "file", *, confirm: bool = False, privacy: str = None,
           timeout_s: int = None, auto_delete: str = None, allow_public: bool = False,
           tags: str = None, timeout: int = 120):
    """Detonate a file or URL in the ANY.RUN sandbox. **Refuses unless `confirm=True`.**

    `confirm` is a function parameter rather than a config value on purpose: `submission_policy` in
    the reference file can make the gate STRICTER, but nothing an analyst edits — or a stale copy
    of the JSON — can turn it off. Without it you get `submit_preflight()` back and nothing is
    sent.

    Two more refusals that are not overridable by accident:
      - `privacy='public'` (and anything in `forbidden_privacy`) needs `allow_public=True` on top
        of `confirm`, because a public task is the failure mode that actually burns cases;
      - a plan with no private-submission entitlement is refused rather than silently downgraded —
        'it worked' must never mean 'it went to the public feed instead'.

    REQUIRES_ANALYST_CONFIRMATION — this marker is the token cti-expert's OPSEC gate
    (tests/test_no_sample_submission.py) looks for. It is placed here, on the one function that can
    reach the network with a sample, so the gate cannot be satisfied by a string sitting somewhere
    harmless. The line below it is the enforcement the marker claims.
    """
    policy = SUBMISSION_POLICY
    if not confirm:
        return submit_preflight(target, kind)
    if not anyrun_configured():
        return {"skipped": "no ANYRUN_API_KEY configured — nothing submitted",
                "capability": capability()}
    privacy = (privacy or policy.get("default_privacy") or "owner").lower()
    forbidden = [str(p).lower() for p in (policy.get("forbidden_privacy") or ["public"])]
    if privacy in forbidden and not allow_public:
        return {"refused": (f"privacy='{privacy}' is forbidden by submission_policy — that task "
                            f"would be world-readable and searchable, and operators watch the "
                            f"public feed. Pass allow_public=True ONLY if the analyst has said so "
                            f"knowing that."),
                "target": target, "preflight": submit_preflight(target, kind)}

    body = {"obj_type": "url" if kind == "url" else "file",
            "opt_privacy_type": privacy,
            "opt_timeout": int(timeout_s or 120),
            "opt_auto_delete_after": auto_delete or policy.get("default_auto_delete_after") or ""}
    if tags:
        # RULE 1 crossing an API boundary: a case identifier must not travel to a third party.
        body["user_tags"] = tags
    url = ENDPOINTS.get("api_base", "https://api.any.run/v1") + \
        ENDPOINTS.get("submit_analysis", "/analysis")

    if kind == "url":
        body["obj_url"] = target
        data, err = _call(url, method="POST", body=body, timeout=timeout)
    else:
        if not os.path.isfile(target):
            return {"error": f"no such file: {target}"}
        data, err = _post_multipart(url, body, target, timeout=timeout)
    if err:
        _record("submit", 0, f"{kind}:{target}", ok=False)
        return dict(err, target=target, kind=kind)
    uuid = ((data or {}).get("data") or {}).get("taskid") or (data or {}).get("taskid")
    _record("submit", int(REQUEST_BUDGET.get("submit_costs", 1)), f"{kind}:{target}", results=1)
    return {"submitted": True, "task_uuid": uuid, "task_url": task_url(uuid or ""),
            "privacy": privacy,
            "note": ("Submitted. The target now knows it was fetched by a sandbox if this was a "
                     "URL; treat any 'clean' verdict as possibly a decoy served to a datacenter IP."),
            "raw": data if not uuid else None}


def _post_multipart(url: str, fields: dict, filepath: str, timeout: int = 120):
    """Minimal multipart/form-data POST (stdlib only — BinaryPivot ships with no dependencies).

    The filename sent is the basename as-is; strip case identifiers from it BEFORE calling, per
    `submission_policy.never_send` — this function does not rename files behind the analyst's back,
    because silently altering what was submitted is its own kind of surprise."""
    import mimetypes
    import uuid as _uuid
    boundary = "----BinaryPivot" + _uuid.uuid4().hex
    name = os.path.basename(filepath)
    ctype = mimetypes.guess_type(name)[0] or "application/octet-stream"
    parts = []
    for k, v in (fields or {}).items():
        if v in (None, ""):
            continue
        parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n"
                     .encode())
    try:
        with open(filepath, "rb") as fh:
            blob = fh.read()
    except OSError as exc:
        return None, {"error": f"cannot read {filepath}: {exc}"}
    parts.append((f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; "
                  f"filename=\"{name}\"\r\nContent-Type: {ctype}\r\n\r\n").encode())
    parts.append(blob)
    parts.append(f"\r\n--{boundary}--\r\n".encode())
    payload = b"".join(parts)
    headers = _headers()
    headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
    try:
        req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.load(r), None
    except urllib.error.HTTPError as e:
        reason = _STATUS_REASON.get(e.code)
        msg = f"HTTP {e.code}" + (f" — {reason}" if reason else "")
        return None, ({"skipped": msg} if e.code in _STATUS_REASON else {"error": msg})
    except Exception as e:
        return None, {"error": str(e)}


def user_limits(timeout: int = 20):
    """The sandbox account's own limits — what is left of the plan."""
    if not anyrun_configured():
        return None

    def run():
        url = ENDPOINTS.get("api_base", "https://api.any.run/v1") + \
            ENDPOINTS.get("user_limits", "/user")
        data, err = _call(url, timeout=timeout)
        return dict(err) if err else ((data or {}).get("data") or data)
    return _memoised("user_limits", "self", run)


# --------------------------------------------------------------------------- run enrichment
# Priority for spending a bounded allowance across one artifact's pivots. The file hash first — it
# is the question "has anyone already detonated THIS sample", and one answer to it can replace the
# whole rest of the lookup. Then the endpoints the sample talks to, which is where new
# infrastructure comes from.
_ENRICH_PRIORITY = ["file:sha256", "app:c2_endpoint", "app:backend_host", "url"]


def _priority(kind: str) -> int:
    for i, k in enumerate(_ENRICH_PRIORITY):
        if kind == k:
            return i
    return len(_ENRICH_PRIORITY)


def enrich_result(result: dict, max_lookups: int = None, days: int = None) -> dict:
    """Run ANY.RUN TI Lookup over a finished BinaryPivot result and fold what comes back into it.

    Each looked-up pivot gets its observations on `pivot['live_results']['anyrun']`; the run summary
    lands on `result['anyrun']`, including the hosts the sandbox saw contacted that this static
    analysis did not find — the point of the layer on a packed sample.

    Keyless: nothing is queried and `result['anyrun']` carries the capability statement instead, so
    the case file records that the observation index was NOT consulted."""
    cap = capability()
    if not anyrun_configured():
        result["anyrun"] = {"capability": cap, "looked_up": []}
        return result["anyrun"]

    b = budget_status()
    room = max(0, b["max_requests_per_run"] - b["spent_this_run"])
    limit = min(int(max_lookups or room), room)
    out = {"capability": cap, "looked_up": [], "skipped_for_budget": [], "new_infrastructure": []}
    static_hosts = set()
    for piv in result.get("pivots") or []:
        if piv.get("kind") in ("app:backend_host", "app:c2_endpoint"):
            static_hosts.add(str(piv.get("value") or "").split(":")[0].lower())

    for piv in sorted(result.get("pivots") or [], key=lambda p: _priority(p.get("kind", ""))):
        if not build_query(piv.get("kind"), piv.get("value")):
            continue
        if limit <= 0:
            out["skipped_for_budget"].append(f"{piv.get('kind')}={piv.get('value')}")
            continue
        hits = lookup_artifact(piv.get("kind"), piv.get("value"), days=days)
        if not isinstance(hits, dict):
            continue
        limit -= 1
        piv.setdefault("live_results", {})["anyrun"] = hits
        out["looked_up"].append({"kind": piv.get("kind"), "value": piv.get("value"),
                                 "domains": len(hits.get("domains") or []),
                                 "ips": len(hits.get("ips") or []),
                                 "threat_names": hits.get("threat_names") or [],
                                 "skipped": hits.get("skipped")})
        # Anything the sandbox saw contacted that the strings sweep did NOT find is the layer
        # earning its keep — on a packed sample that is where the operator's real endpoints are.
        for host in (hits.get("domains") or []):
            h = str(host).lower()
            if h and h not in static_hosts:
                out["new_infrastructure"].append(h)
    out["new_infrastructure"] = uniq(out["new_infrastructure"])[
        :int(RESULT_LIMITS.get("max_related_indicators", 100))]
    if out["new_infrastructure"]:
        out["note"] = ("Hosts observed in detonations that are NOT in this file's static strings. "
                       "They are collection targets for WebPivot — corroborate before treating any "
                       "of them as the operator's own.")
    if out["skipped_for_budget"]:
        out["budget_note"] = (f"{len(out['skipped_for_budget'])} artifact(s) were NOT looked up — "
                              f"the per-run cap was reached. That absence is a budget fact, not a "
                              f"finding.")
    result["anyrun"] = out
    return out


# --------------------------------------------------------------------------- capability statement
def capability() -> dict:
    """What THIS run's ANY.RUN layer can do — same contract as WebPivot's `wp_capabilities`, so the
    statement drops straight into an assessment's collection-limitations note.

    The percentage is blunt on purpose. Keyless, the layer still writes the correct query for every
    artifact and points at the UI that runs it — genuinely half the job, since choosing the right
    observation field is the tradecraft. What it cannot do is EXECUTE any of them, so no sandbox
    observation ever reaches the case file automatically and no negative is ever established."""
    if anyrun_key() and ENABLED:
        return {"layer": "anyrun", "mode": "keyed", "power_pct": 100,
                "available": ["TI Lookup over detonation observations (contacted domains/IPs/URLs)",
                              "family + Suricata context and the public task links",
                              "runtime infrastructure a packed sample never reveals statically"],
                "unavailable": [],
                "statement": "ANY.RUN TI Lookup queried live — sandbox-observed infrastructure for "
                             "every artifact the sandbox indexes."}
    return {
        "layer": "anyrun", "mode": "keyless", "power_pct": 50,
        "available": ["the correct TI Lookup query for every indexable artifact (right observation "
                      "field, ip:port split, bounded time window)",
                      "the TI Lookup UI address to paste it into, plus public-task links",
                      "the clustering policy that says what a hit would and would not prove"],
        "unavailable": ["the observations themselves — contacted domains, IPs, URLs and ports",
                        "the threat/family label and Suricata context",
                        "the runtime backend hosts a PACKED sample hides from static extraction",
                        "any automatic feedback of discovered infrastructure into the case"],
        "statement": ("COLLECTION LIMITATION — ANY.RUN ran at roughly HALF capability: no "
                      "ANYRUN_API_KEY is configured, so the TI Lookup queries were BUILT but never "
                      "EXECUTED. This run establishes nothing about what this sample or its "
                      "infrastructure did when detonated — that index was not queried. This "
                      "matters most on a PACKED sample, whose real endpoints only exist at "
                      "runtime. Run the emitted queries in the TI Lookup UI, or set "
                      "ANYRUN_API_KEY."),
    }


def banner_lines() -> list:
    """The stderr block for a keyless ANY.RUN layer. Empty when keyed."""
    cap = capability()
    if cap["power_pct"] >= 100:
        return []
    return [
        f"[!] ANY.RUN: KEYLESS — ~{cap['power_pct']}% capability.",
        f"    lost:    {cap['unavailable'][0]}; {cap['unavailable'][2]}",
        f"    instead: {cap['available'][0]}",
        f"    get a key: {UI_TEMPLATES.get('api_key_tab') or UI_TEMPLATES.get('signup')}",
    ]


__all__ = ["anyrun_key", "anyrun_configured", "field_for_kind", "build_query", "anyrun_queries",
           "attach_anyrun_queries", "task_url", "grade_field", "summarise_lookup", "ti_lookup",
           "lookup_artifact", "enrich_result", "keycheck", "user_limits", "capability",
           "banner_lines", "analysis_history", "analysis_report", "submit", "submit_preflight",
           "budget_status", "month_spent", "ENDPOINTS", "QUERY_FIELDS", "PIVOT_FIELD_MAP",
           "PLAN_CAPABILITIES", "REQUEST_BUDGET", "RESULT_LIMITS", "UI_TEMPLATES",
           "CLUSTERING_POLICY", "SUBMISSION_POLICY", "PRIVACY_TYPES"]


def main():
    ap = argparse.ArgumentParser(description="ANY.RUN TI Lookup + keyless query builder")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("lookup", help="run a TI Lookup (1 request)")
    p.add_argument("--sha256")
    p.add_argument("--md5")
    p.add_argument("--domain")
    p.add_argument("--ip", help="IP or IP:port")
    p.add_argument("--url")
    p.add_argument("--query", help="raw TI Lookup query, e.g. 'domainName:\"example.com\"'")
    p.add_argument("--days", type=int, default=None)
    p = sub.add_parser("query", help="OFFLINE: build the TI Lookup query for a pivot kind (no key)")
    p.add_argument("kind", help="BinaryPivot pivot kind, e.g. file:sha256, app:backend_host")
    p.add_argument("value")
    p = sub.add_parser("history", help="YOUR OWN past sandbox tasks (read-only)")
    p.add_argument("--limit", type=int, default=25)
    p = sub.add_parser("report", help="one task's report (read-only)")
    p.add_argument("task_uuid")
    p.add_argument("--iocs", action="store_true", help="the task's IOC set instead of the report")
    p = sub.add_parser("submit", help="DETONATE a file/URL — prints the risk briefing and REFUSES "
                                      "unless --confirm-submission is given")
    p.add_argument("target", help="local file path, or a URL with --url")
    p.add_argument("--url", action="store_true", help="submit TARGET as a URL to browse, not a file")
    p.add_argument("--confirm-submission", action="store_true",
                   help="I have asked the analyst and they authorized THIS submission. Without it "
                        "nothing is sent — you get the briefing instead.")
    p.add_argument("--privacy", default=None,
                   choices=sorted(PRIVACY_TYPES.keys()) or None,
                   help="who can see the task (default: owner — only you)")
    p.add_argument("--allow-public", action="store_true",
                   help="permit a PUBLIC task. Operators watch the public feed; this is the option "
                        "that burns cases, so it is separate from --confirm-submission")
    p.add_argument("--sandbox-timeout", type=int, default=None, metavar="SECONDS")
    p.add_argument("--tags", default=None,
                   help="ANY.RUN user tags — NEVER put a case ID or an analyst/client name here")
    sub.add_parser("keycheck", help="is this key entitled to TI Lookup?")
    sub.add_parser("limits", help="the sandbox account's remaining plan limits")
    sub.add_parser("budget", help="OFFLINE: this month's ANY.RUN request spend (no key, no spend)")
    args = ap.parse_args()

    if args.cmd == "query":
        q = build_query(args.kind, args.value)
        out = {"kind": args.kind, "field": field_for_kind(args.kind), "query": q,
               "queries": anyrun_queries(args.kind, args.value), "capability": capability()}
        if not q:
            out["note"] = ("ANY.RUN indexes DETONATION OBSERVATIONS — hashes, contacted domains/"
                           "IPs/URLs, JARM. A signing certificate, an APK package name or a "
                           "firebase project id is not an observation field; reverse those on "
                           "VirusTotal / Koodous / Triage instead.")
    elif args.cmd == "budget":
        out = budget_status()
        out["note"] = (f"A TI Lookup costs {REQUEST_BUDGET.get('lookup_costs', 1)} request. "
                       f"Counted from the shared ledger across every case.")
    elif args.cmd == "submit" and not args.confirm_submission:
        # The briefing path is OFFLINE and works with no key: an analyst must be able to read what
        # a submission would cost them before deciding, and before wiring up a credential.
        pf = submit_preflight(args.target, "url" if args.url else "file")
        print(json.dumps(pf, indent=2, ensure_ascii=False))
        print("\n[anyrun] NOTHING WAS SUBMITTED. Show the risks above to the analyst and get an "
              "explicit yes, then re-run with --confirm-submission.", file=sys.stderr)
        return 3
    elif not anyrun_configured():
        cap = capability()
        print(
            "ANY.RUN: KEYLESS — no ANYRUN_API_KEY configured. Capability ~50%.\n"
            "  UNAVAILABLE (needs a key): " + "; ".join(cap["unavailable"]) + ".\n"
            "    Nothing was queried, so nothing being reported is NOT a finding about the sample.\n"
            "  STILL AVAILABLE, keyless and free: " + "; ".join(cap["available"]) + ".\n"
            f"  Get a key: {UI_TEMPLATES.get('api_key_tab')}, then\n"
            "    `printf 'ANYRUN_API_KEY=…\\n' >> .env && chmod 600 .env`.\n"
            "  NOTE: TI Lookup is a separate licence from the sandbox — check with `keycheck`.\n"
            "  Detail: BinaryPivot/SKILL.md § ANY.RUN",
            file=sys.stderr)
        return 2
    elif args.cmd == "keycheck":
        out = keycheck()
    elif args.cmd == "limits":
        out = user_limits()
    elif args.cmd == "history":
        out = analysis_history(limit=args.limit)
    elif args.cmd == "report":
        out = analysis_report(args.task_uuid, iocs=args.iocs)
    elif args.cmd == "submit":
        out = submit(args.target, "url" if args.url else "file", confirm=True,
                     privacy=args.privacy, timeout_s=args.sandbox_timeout,
                     allow_public=args.allow_public, tags=args.tags)
    else:
        if args.query:
            out = ti_lookup(args.query, days=args.days)
        else:
            pairs = [("file:sha256", args.sha256), ("file:md5", args.md5),
                     ("domain", args.domain), ("ip", args.ip), ("url", args.url)]
            terms = [build_query(k, v) for k, v in pairs if v]
            terms = [t for t in terms if t]
            if not terms:
                print("lookup needs at least one of --sha256/--md5/--domain/--ip/--url/--query",
                      file=sys.stderr)
                return 2
            out = ti_lookup(" AND ".join(terms), days=args.days)
    print(json.dumps(out, indent=2, ensure_ascii=False))
    if args.cmd not in ("query", "budget"):
        b = budget_status()
        print(f"[anyrun] spent {b['spent_this_run']} request(s) this run · "
              f"{b['remaining_this_month']}/{b['monthly_requests']} left for {b['month']}",
              file=sys.stderr)
    if api_usage:
        api_usage.print_session_summary()
    return 0


if __name__ == "__main__":
    sys.exit(main())
