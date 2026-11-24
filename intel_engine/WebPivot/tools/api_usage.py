#!/usr/bin/env python3
"""api_usage.py — ledger of LICENSED / paid-API calls (FOFA, urlscan, WhoisXML, IPinfo, Shodan).

Every time a tool hits a metered API it calls `record(...)`, which:
  - appends one line to a git-ignored JSONL ledger (default MEMORY/api_usage.jsonl, or $API_USAGE_LOG),
  - keeps an in-process tally so a run can print "API usage this run".

Credits: most providers do NOT return a per-call billed cost, so `credits` is a best-effort unit
count per billable action (1 = one query/request; urlscan_search records 1 per page fetched). Where
the provider DOES expose quota (urlscan's `X-Rate-Limit-Remaining` header), we capture `remaining`
so you see the authoritative balance. This is a usage LOG, not an invoice — treat credits as units.

Cost classes: every row is classed free | quota | metered from WebPivot/references/
api_cost_classes.json (RULE 3 — data, not code) and `report` prints one subtotal per class, so a
free reverse-WHOIS preview or a keyless lookup is never read as a purchase. The overall total is
labelled "estimated units" for the same reason.

CLI:
  python3 api_usage.py report [--log PATH] [--case ID] [--since YYYY-MM-DD] [--last N]
  python3 api_usage.py report --yield [--since YYYY-MM-DD] [--case ID] [--json]
      what each provider endpoint RETURNED: failure, zero-result and repeat rates. Unscoped by
      case it also rewrites route_yield.json beside the ledger (read by case_state.propose);
      --no-save prints without writing it.
"""
import argparse
import collections
import datetime
import json
import os
import sys
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))          # repo root (WebPivot/tools -> ../..)

_ctx = {"case": None, "skill": None}
_session = []
_lock = threading.Lock()

if HERE not in sys.path:
    sys.path.insert(0, HERE)
try:
    from wp_refs import load_ref as _load_ref, ref_path as _ref_path   # the shared RULE 3 loader
except Exception:  # noqa: BLE001 — degrade, never block a report
    _load_ref, _ref_path = None, None

COST_CLASSES = ("free", "quota", "metered")
# Conservative embedded fallback: everything unclassified is `metered` (over-states, never hides).
_COST_FALLBACK = {
    "rules": {"default_class": "metered", "zero_credit_is_free": True},
    "action_classes": {"whoisxml:reverse-whois-preview": "free"},
    "provider_classes": {},
}


def load_cost_classes(path=None):
    """The cost-class reference (api_cost_classes.json), or the embedded fallback with a warning."""
    if _load_ref is None:
        print("[api_usage] WARNING: wp_refs unavailable; api_cost_classes.json not read — every "
              "unlisted provider is classed metered.", file=sys.stderr)
        return dict(_COST_FALLBACK)
    return _load_ref(path or _ref_path(__file__, "api_cost_classes.json"), _COST_FALLBACK)


def cost_class(rec, ref=None):
    """Class one ledger row as 'free' | 'quota' | 'metered'. Order: provider:action override,
    then the provider's class, then rules.default_class; a 0-credit row is free when
    rules.zero_credit_is_free is set (keyless call or rejected request — nothing billed)."""
    ref = ref if ref is not None else load_cost_classes()
    rules = ref.get("rules") or {}
    default = rules.get("default_class") if rules.get("default_class") in COST_CLASSES else "metered"
    prov, act = rec.get("provider"), rec.get("action")
    cls = (ref.get("action_classes") or {}).get(f"{prov}:{act}")
    if cls not in COST_CLASSES:
        cls = (ref.get("provider_classes") or {}).get(prov)
    if cls not in COST_CLASSES:
        cls = default
    if cls != "free" and rules.get("zero_credit_is_free", True) and not (rec.get("credits") or 0):
        cls = "free"
    return cls


def _log_path():
    return os.environ.get("API_USAGE_LOG") or os.path.join(ROOT, "MEMORY", "api_usage.jsonl")


def set_context(case=None, skill=None):
    """Tag every subsequent record in this process with the case / skill that triggered it."""
    if case is not None:
        _ctx["case"] = case
    if skill is not None:
        _ctx["skill"] = skill


def _now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def record(provider, action, credits=1, query=None, results=None,
           remaining=None, limit=None, ok=True, path=None, cached=False):
    """Log one licensed-API call. Returns the record dict; never raises (best-effort append).

    `ok` means THE CALL SUCCEEDED — not that it returned results. Credits are zeroed when ok is
    False because providers do not bill a rejected request (401/403/429/5xx). Do NOT pass ok=False
    merely because a search came back empty: a 200 that found nothing is still a billed call, and
    flagging it as failed silently under-reports the month. Record emptiness with `results=0`
    instead. This exact confusion made the SerpApi ledger read 8 spent against an account that had
    really spent 12, and the monthly guard enforces its cap from this field.

    `cached=True` marks an answer served from the cross-case cache (wp_respcache): no request was
    made, so pass credits=0. The row exists so the saving is visible; the yield report counts it
    apart from the vendor's calls.
    """
    rec = {"ts": _now(), "provider": provider, "action": action,
           "credits": (credits if ok else 0),
           "query": (str(query)[:200] if query else None), "results": results,
           "remaining": remaining, "limit": limit, "ok": ok,
           # In-process set_context() wins; otherwise fall back to the env vars the parent pipeline
           # (tools/intel.py) exports before spawning this as a SEPARATE process (#23) — without
           # this, every subprocess vendor client logged case=null and `api-usage --case X` found
           # nothing for anything that wasn't the top-level collector itself.
           "case": _ctx.get("case") or os.environ.get("INTEL_CASE"),
           "skill": _ctx.get("skill") or os.environ.get("INTEL_SKILL")}
    if cached:
        rec["cached"] = True
    with _lock:
        _session.append(rec)
        try:
            p = path or _log_path()
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        except Exception:
            pass
    return rec


def rl_headers(resp):
    """Pull urlscan-style rate-limit headers from a urllib/requests response → (remaining, limit)."""
    try:
        h = getattr(resp, "headers", None)
        if h is None:
            return (None, None)
        g = h.get
        rem = g("X-Rate-Limit-Remaining") or g("x-rate-limit-remaining")
        lim = g("X-Rate-Limit-Limit") or g("x-rate-limit-limit")
        return (int(rem) if rem not in (None, "") else None,
                int(lim) if lim not in (None, "") else None)
    except Exception:
        return (None, None)


def session_summary():
    """Per provider: vendor calls and credits this run. An answer served from the cross-case
    cache is not a call; it is counted under `cached`."""
    agg = collections.OrderedDict()
    for r in _session:
        a = agg.setdefault(r["provider"], {"calls": 0, "credits": 0, "cached": 0})
        if r.get("cached"):
            a["cached"] += 1
            continue
        a["calls"] += 1
        a["credits"] += (r.get("credits") or 0)
    return agg


def print_session_summary(file=sys.stderr):
    agg = session_summary()
    if not agg:
        return
    print("\n--- API usage this run (licensed/metered) ---", file=file)
    total = 0
    for prov, a in agg.items():
        total += a["credits"]
        rem = next((r["remaining"] for r in reversed(_session)
                    if r["provider"] == prov and r.get("remaining") is not None), None)
        remtxt = f" · quota remaining≈{rem}" if rem is not None else ""
        remtxt += f" · {a['cached']} answer(s) from the cross-case cache" if a.get("cached") else ""
        print(f"  {prov:<10} {a['calls']:>3} call(s) · ~{a['credits']} credit(s){remtxt}", file=file)
    print(f"  {'TOTAL':<10} ~{total} estimated units   (ledger: {_log_path()})", file=file)


# ---------------------------------------------------------------------------- yield
YIELD_FILE = "route_yield.json"


def yield_path(log=None):
    """The measured yield table lives beside the ledger it was computed from (MEMORY/ by default),
    so a redirected $API_USAGE_LOG never overwrites the real measurement."""
    return os.path.join(os.path.dirname(log or _log_path()), YIELD_FILE)


def _rate(n, d):
    return round(n / d, 4) if d else None


def yield_table(rows):
    """Per `provider:action`: calls, credits, failed calls, and two rates with their own
    denominators — `zero_rate` over the answered rows that recorded a result count (`counted`),
    `dup_rate` over the answered rows that recorded a query (`with_query`), a duplicate being an
    (action, query) pair already answered earlier in `rows`. A rate is None when nothing was
    recorded to compute it from: an endpoint that never logs `results` has no yield figure.
    A row served from the cross-case cache is no vendor call: it is counted in `cached` only."""
    table = collections.OrderedDict()
    seen = set()
    for r in rows:
        key = f"{r.get('provider')}:{r.get('action')}"
        t = table.setdefault(key, {"calls": 0, "credits": 0, "failed": 0, "counted": 0, "zero": 0,
                                   "with_query": 0, "duplicates": 0, "cached": 0})
        if r.get("cached"):
            t["cached"] += 1
            continue
        t["calls"] += 1
        c = r.get("credits")
        t["credits"] += c if isinstance(c, (int, float)) and not isinstance(c, bool) else 0
        if r.get("ok") is False:
            t["failed"] += 1
            continue
        res = r.get("results")
        if isinstance(res, (int, float)) and not isinstance(res, bool):
            t["counted"] += 1
            t["zero"] += 1 if res == 0 else 0
        q = r.get("query")
        if q:
            t["with_query"] += 1
            if (key, q) in seen:
                t["duplicates"] += 1
            seen.add((key, q))
    for t in table.values():
        t["fail_rate"] = _rate(t["failed"], t["calls"])
        t["zero_rate"] = _rate(t["zero"], t["counted"])
        t["dup_rate"] = _rate(t["duplicates"], t["with_query"])
    return table


def write_yield(table, rows, path, since=None):
    """Persist the table with the ledger span it covers. Atomic; returns the path or None."""
    tmp = f"{path}.{os.getpid()}.tmp"
    try:
        stamps = sorted(s for s in (r.get("ts") for r in rows) if isinstance(s, str) and s)
        doc = {"generated": _now(),
               "ledger": {"rows": len(rows), "first": stamps[0] if stamps else None,
                          "last": stamps[-1] if stamps else None, "since": since},
               "routes": table}
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=1, ensure_ascii=False)
        os.replace(tmp, path)
        return path
    except Exception:  # noqa: BLE001 — a report must never fail on its own side file
        try:
            os.unlink(tmp)
        except OSError:
            pass
        return None


def _pct(v):
    return "    -" if v is None else f"{100 * v:4.0f}%"


def _yield_report(rows, a):
    table = yield_table(rows)
    keep = not a.case and not a.no_save
    saved = write_yield(table, rows, yield_path(a.log), since=a.since) if keep else None
    if a.json:
        print(json.dumps({"rows": len(rows), "saved": saved, "routes": table}, ensure_ascii=False))
        return 0
    scope = f" (case={a.case})" if a.case else ""
    scope += f" (since {a.since})" if a.since else ""
    print(f"# Vendor yield{scope} — {len(rows)} ledger rows\n")
    print(f"{'provider:action':<38} {'calls':>6} {'credits':>8} {'fail':>5} "
          f"{'zero':>5} {'(n)':>6} {'repeat':>6} {'(n)':>6} {'cached':>6}")
    for key, t in sorted(table.items(), key=lambda kv: -kv[1]["calls"]):
        print(f"{key:<38} {t['calls']:>6} {t['credits']:>8.0f} {_pct(t['fail_rate'])} "
              f"{_pct(t['zero_rate'])} {t['counted']:>6} {_pct(t['dup_rate']):>6} {t['with_query']:>6} "
              f"{t['cached']:>6}")
    print("\nzero = answered calls that returned nothing, over the calls that recorded a result "
          "count (n).\nrepeat = an (action, query) already answered earlier in this window (the pages "
          "of one paginated search count as repeats), over the "
          "calls that recorded a query (n).\ncached = answers served from the cross-case cache: no "
          "request, no credit, not in any other column.\nA dash means the endpoint records no such field.")
    if saved:
        print(f"\nsaved {saved}")
    elif a.case:
        print("\n(case-scoped: route_yield.json not rewritten)")
    elif a.no_save:
        print("\n(--no-save: route_yield.json not rewritten)")
    return 0


# ---------------------------------------------------------------------------- CLI report
def _report(argv):
    ref = load_cost_classes()
    ap = argparse.ArgumentParser(description="Report licensed-API credit usage from the ledger.")
    ap.add_argument("cmd", nargs="?", default="report", choices=["report"])
    ap.add_argument("--log", default=_log_path())
    ap.add_argument("--case", default=None)
    ap.add_argument("--since", default=None, help="YYYY-MM-DD (inclusive)")
    ap.add_argument("--last", type=int, default=0, help="also print the last N individual calls")
    ap.add_argument("--yield", dest="yield_", action="store_true",
                    help="per-endpoint failure / zero-result / repeat rates instead of the cost report")
    ap.add_argument("--json", action="store_true", help="with --yield: machine-readable output")
    ap.add_argument("--no-save", action="store_true",
                    help="with --yield: do not rewrite route_yield.json")
    a = ap.parse_args(argv)

    def _nothing(msg):       # --yield --json stays machine-readable when there is nothing to report
        print(json.dumps({"rows": 0, "saved": None, "routes": {}}) if a.yield_ and a.json else msg)
        return 0
    if not os.path.exists(a.log):
        return _nothing(f"no ledger at {a.log} — no licensed-API calls recorded yet.")
    rows = []
    for line in open(a.log, encoding="utf-8"):
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except Exception:
            continue
        if a.case and r.get("case") != a.case:
            continue
        if a.since and (r.get("ts") or "")[:10] < a.since:
            continue
        rows.append(r)
    if not rows:
        return _nothing("no matching records.")
    if a.yield_:
        return _yield_report(rows, a)
    # an answer served from the cross-case cache is not a vendor call: counted apart, below
    n_cached = sum(1 for r in rows if r.get("cached"))
    rows = [r for r in rows if not r.get("cached")]
    by_prov = collections.OrderedDict()
    by_day = collections.defaultdict(int)
    by_case = collections.defaultdict(int)
    by_class = collections.OrderedDict((k, {"calls": 0, "credits": 0}) for k in COST_CLASSES)
    total = 0
    for r in rows:
        c = r.get("credits") or 0
        total += c
        k = by_class[cost_class(r, ref)]
        k["calls"] += 1
        k["credits"] += c
        p = by_prov.setdefault(r["provider"], {"calls": 0, "credits": 0, "actions": collections.Counter()})
        p["calls"] += 1
        p["credits"] += c
        p["actions"][r.get("action")] += 1
        by_day[(r.get("ts") or "")[:10]] += c
        by_case[r.get("case") or "(none)"] += c
    scope = f" (case={a.case})" if a.case else ""
    scope += f" (since {a.since})" if a.since else ""
    print(f"# Licensed-API usage{scope} — {len(rows)} calls, ~{total} estimated units "
          "(not a bill — see the cost classes below)"
          + (f"\n# plus {n_cached} answer(s) served from the cross-case cache: no request, no units"
             if n_cached else "") + "\n")
    print("By cost class:")
    for cls, k in by_class.items():
        print(f"  {cls:<10} {k['calls']:>4} calls · ~{k['credits']:>4} units")
    print("\nBy provider:")
    for prov, p in sorted(by_prov.items(), key=lambda kv: -kv[1]["credits"]):
        acts = ", ".join(f"{k}×{v}" for k, v in p["actions"].most_common())
        print(f"  {prov:<10} {p['calls']:>4} calls · ~{p['credits']:>4} credits   [{acts}]")
    print("\nBy day:")
    for d in sorted(by_day):
        print(f"  {d}  ~{by_day[d]} credits")
    if not a.case and len(by_case) > 1:
        print("\nBy case:")
        for c in sorted(by_case, key=lambda k: -by_case[k]):
            print(f"  {c:<24} ~{by_case[c]} credits")
    if a.last:
        print(f"\nLast {a.last} calls:")
        for r in rows[-a.last:]:
            rem = f" rem={r['remaining']}" if r.get("remaining") is not None else ""
            print(f"  {r['ts']}  {r['provider']}/{r.get('action')}  ~{r.get('credits')}cr"
                  f" [{cost_class(r, ref)}]  {r.get('query') or ''}{rem}  [{r.get('case') or '-'}]")
    return 0


if __name__ == "__main__":
    sys.exit(_report(sys.argv[1:]))
