#!/usr/bin/env python3
"""watchlist.py — re-check brands, domains and cases when they are DUE, with the monitors the
engine already has.

    intel.py watch add brand example-brand                 # new certificates naming the brand
    intel.py watch add domain example.com --interval 12    # lookalikes, new certs, takedown status
    intel.py watch add case CASE-0001                      # takedown status + drift of a case
    intel.py watch list
    intel.py watch run                                     # every DUE entry, once, then exit
    intel.py watch rm <id>

WHAT A RUN DOES
    For each due entry it runs that entry's sources — the existing tools, as they are:
      ct             WebPivot/tools/ct_monitor.py watch   (keyless; its own state file per entry)
      impersonation  WebPivot/tools/wp_impersonate.py     (keyless; --allow-metered adds the FOFA /
                                                           urlscan sweeps)
      takedown       WebPivot/tools/wp_takedown.py        (keyless; --fetch lets it read co-tenant
                                                           pages, off by default)
      drift          scripts/osint/case_drift.py          (offline; reads the stored case)
    and prints what is NEW since the entry's previous run. The full answers are kept under
    MEMORY/watch/<id>/<utc>.json.

WHAT A RUN NEVER DOES
    It never opens a case, never collects a host and never writes to the knowledge base. Every
    hit is a LEAD for the analyst, printed with the command that would investigate it. A closed
    case is skipped unless its disposition is `monitoring`.

SCHEDULING
    There is no daemon. Call `intel.py watch run` from your own cron or systemd timer, for example
        17 * * * *  cd <repo> && python3 scripts/backend/intel.py watch run >> ~/cti-watch.log 2>&1
    An entry that is not due costs nothing, so an hourly call is fine.

WHEN A SOURCE DOES NOT REALLY LOOK
    A source that fails, or answers DEGRADED (crt.sh down: only the backup CT sources were
    checked), is reported as such — never as "nothing new" — gets no clean stamp, and is retried on
    the very next run while the entry's other sources wait out their interval. `watch run` exits
    3 when any source failed or was degraded, so a cron wrapper can tell an incomplete run apart.

Stdlib only. Policy (default interval, timeout, sources per kind) is reference data:
tools/kb/references/watchlist.json.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
REPO = os.path.dirname(ROOT)
sys.path.insert(0, os.path.join(HERE, "kb"))
import kb_refs  # noqa: E402

KINDS = ("brand", "domain", "case")
# Conservative minimum: one keyless or offline source per kind.
_FALLBACK = {"defaults": {"interval_hours": 24, "timeout_seconds": 300, "max_entries": 20},
             "sources_by_kind": {"brand": ["ct"], "domain": ["ct"], "case": ["drift"]}}
_REF = kb_refs.load_ref(kb_refs.ref_path(kb_refs.__file__, "watchlist.json"), _FALLBACK)
DEFAULTS = _REF.get("defaults") or _FALLBACK["defaults"]
SOURCES_BY_KIND = _REF.get("sources_by_kind") or _FALLBACK["sources_by_kind"]
_VALUE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,251}")


def home():
    """MEMORY/ (git-ignored runtime data). $WATCHLIST_HOME redirects it — tests use this."""
    return os.environ.get("WATCHLIST_HOME") or os.path.join(ROOT, "MEMORY")


def _list_path():
    return os.path.join(home(), "watchlist.json")


def _entry_dir(eid):
    return os.path.join(home(), "watch", eid)


def _now():
    return _dt.datetime.now(_dt.timezone.utc)


def _iso(t):
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def _read(path, default):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return default


def _write(path, doc):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = f"{path}.{os.getpid()}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=1, ensure_ascii=False)
    os.replace(tmp, path)


def load():
    doc = _read(_list_path(), [])
    return [e for e in doc if isinstance(e, dict) and e.get("id")] if isinstance(doc, list) else []


# --------------------------------------------------------------------------- list edits
def add(kind, value, sources=None, interval_hours=None):
    """(entry, error). Refuses an unknown kind, a value that is not a plain token, a source the
    kind does not allow, a duplicate and a full list."""
    kind, value = str(kind or "").strip().lower(), str(value or "").strip()
    if kind not in KINDS:
        return None, f"kind must be one of {', '.join(KINDS)}"
    if not _VALUE_RE.fullmatch(value):
        return None, "value must be a plain keyword, domain or case id (letters, digits, . _ -)"
    allowed = list(SOURCES_BY_KIND.get(kind) or [])
    want = [s.strip().lower() for s in (sources or allowed) if str(s).strip()]
    bad = [s for s in want if s not in allowed]
    if bad or not want:
        return None, (f"source(s) {', '.join(bad) or '(none)'} not available for a {kind} entry; "
                      f"allowed: {', '.join(allowed) or 'none'}")
    entries = load()
    eid = f"{kind}-" + re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    if any(e["id"] == eid for e in entries):
        return None, f"{eid} is already on the watch-list"
    if len(entries) >= int(DEFAULTS.get("max_entries", 20)):
        return None, f"the watch-list is full ({len(entries)} entries); remove one first"
    try:
        interval = float(interval_hours) if interval_hours not in (None, "") else float(
            DEFAULTS.get("interval_hours", 24))
    except (TypeError, ValueError):
        return None, "interval must be a number of hours"
    if interval <= 0:
        return None, "interval must be a positive number of hours"
    entry = {"id": eid, "kind": kind, "value": value.lower() if kind != "case" else value,
             "sources": want, "interval_hours": interval, "added": _iso(_now()), "last_run": None}
    _write(_list_path(), entries + [entry])
    return entry, ""


def remove(eid):
    entries = load()
    kept = [e for e in entries if e["id"] != eid]
    if len(kept) == len(entries):
        return False
    _write(_list_path(), kept)
    return True


def _older_than_interval(stamp, entry, now):
    if not stamp:
        return True
    try:
        then = _dt.datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=_dt.timezone.utc)
    except ValueError:
        return True
    return now - then >= _dt.timedelta(hours=float(entry.get("interval_hours") or 24))


def due_sources(entry, now=None):
    """The entry's sources whose last CLEAN run is older than the interval. A source that failed,
    or answered degraded, never got a clean stamp — so it is due again on the very next run
    instead of waiting out the interval behind a result that was not a real look."""
    now = now or _now()
    clean = entry.get("source_last_run") or {}
    return [s for s in entry.get("sources") or []
            if _older_than_interval(clean.get(s), entry, now)]


def is_due(entry, now=None):
    return bool(due_sources(entry, now))


# --------------------------------------------------------------------------- sources
def _command(source, entry, edir, allow_metered=False, fetch=False):
    """argv for one source of one entry. Paths are absolute: the dispatcher changes directory."""
    v, wp = entry["value"], os.path.join(ROOT, "WebPivot", "tools")
    if source == "ct":
        # --status-json, not --json: the plain list is empty both when nothing is new AND when
        # crt.sh did not answer; only the per-pattern status tells them apart.
        return [sys.executable, os.path.join(wp, "ct_monitor.py"), "watch", v,
                "--state", os.path.join(edir, "ct_state.json"), "--status-json"]
    if source == "impersonation":
        return [sys.executable, os.path.join(wp, "wp_impersonate.py"), v,
                *(["--fofa", "--urlscan"] if allow_metered else [])]
    if source == "takedown":
        target = ["--case", v] if entry["kind"] == "case" else [v]
        return [sys.executable, os.path.join(wp, "wp_takedown.py"), *target, "--json",
                *([] if fetch else ["--no-fetch"])]
    if source == "drift":
        return [sys.executable, os.path.join(REPO, "scripts", "osint", "case_drift.py"), v]
    return None


def _exec(cmd, timeout):
    """(parsed JSON | None, error, warnings). The one seam a test replaces; never raises.
    `warnings` are the child's own `[!]` lines from stderr — the engine's convention for "I
    answered, but not completely" — kept even when stdout parsed, because a clean-looking answer
    with a degraded-source warning beside it is not a clean answer."""
    try:
        r = subprocess.run(cmd, cwd=ROOT, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                           timeout=timeout)
    except subprocess.TimeoutExpired:
        return None, f"timed out after {timeout}s", []
    except OSError as e:
        return None, f"could not start: {e}", []
    warns = [ln.strip()[:240] for ln in (r.stderr or "").splitlines() if ln.strip().startswith("[!]")][:8]
    out = (r.stdout or "").strip()
    if not out:
        return None, (r.stderr or f"no output (exit {r.returncode})").strip()[-300:], warns
    try:
        return json.loads(out), "", warns
    except ValueError:
        return None, f"unreadable output (exit {r.returncode}): {(r.stderr or out)[-300:]}", warns


def health(source, data):
    """("ok" | "degraded" | "failed", note) for one source's parsed answer — whether it was a real
    look, read from the status the monitor itself reports.
      ct             failed    crt.sh did not answer on a pattern's FIRST run: the baseline was
                               postponed and nothing was recorded, so there is no answer at all.
                     degraded  crt.sh did not answer on a later run: what the backup sources saw was
                               checked and recorded; a certificate only crt.sh holds would be missed.
      impersonation  degraded  its CT keyword hunt came back degraded or errored: the permutations
                               were still resolved, but a lookalike only CT would show is missed.
      takedown       degraded  a domain's status is `unknown`: RDAP / DNS did not answer for it.
      drift          always ok once it parses (it reads stored files)."""
    if source == "impersonation":
        hunt = ((((data or {}).get("artifacts") or {}).get("impersonation") or {})
                .get("keyword_hunt") or {}) if isinstance(data, dict) else {}
        crt = hunt.get("crt.sh") or hunt.get("crtsh") or {}
        if isinstance(crt, dict) and (crt.get("ct_status") == "degraded" or crt.get("error")):
            return "degraded", ("the CT keyword hunt did not answer; only DNS-resolving "
                                "permutations were checked")
        return "ok", ""
    if source == "takedown":
        unknown = sorted(str((r or {}).get("domain")) for r in ((data or {}).get("domains") or [])
                         if (r or {}).get("status") == "unknown") if isinstance(data, dict) else []
        if unknown:
            return "degraded", f"status unknown (RDAP / DNS did not answer) for {', '.join(unknown[:5])}"
        return "ok", ""
    if source != "ct":
        return "ok", ""
    pats = (data or {}).get("patterns") if isinstance(data, dict) else None
    if not isinstance(pats, dict) or not pats:
        return "failed", "the CT monitor returned no per-pattern status"
    postponed = sorted(p for p, s in pats.items() if (s or {}).get("postponed"))
    if postponed:
        return "failed", f"crt.sh did not answer; baseline postponed for {', '.join(postponed)}"
    degraded = sorted(p for p, s in pats.items() if (s or {}).get("ct_status") == "degraded")
    if degraded:
        return "degraded", (f"crt.sh did not answer for {', '.join(degraded)}; only the backup "
                            f"sources were checked — a quiet result is not an all-clear")
    return "ok", ""


def signals(source, data):
    """The comparable facts in one source's answer, as sorted strings. `new` is the difference
    from the previous run, so a string must be stable while the fact it states is unchanged."""
    out = set()
    if source == "ct":                       # the monitor lists only certificates NEW to its state
        for c in (data or {}).get("new") or [] if isinstance(data, dict) else []:
            for n in (c or {}).get("names") or []:
                out.add(f"new certificate name: {str(n).lower()}")
    elif source == "impersonation":
        for p in (data or {}).get("pivots") or [] if isinstance(data, dict) else []:
            if (p or {}).get("kind") == "impersonation:candidate" and p.get("value"):
                live = "resolves" if (p.get("live") or {}).get("resolves") else "seen, not resolving"
                out.add(f"lookalike {live}: {str(p['value']).lower()}")
    elif source == "takedown":
        for row in (data or {}).get("domains") or [] if isinstance(data, dict) else []:
            d = str((row or {}).get("domain") or "").lower()
            if not d:
                continue
            out.add(f"{d} status: {row.get('status')}")
            for s in row.get("successors") or []:
                if (s or {}).get("domain"):
                    out.add(f"{d} successor lead ({s.get('rung') or 'lead'}): {str(s['domain']).lower()}")
    elif source == "drift":
        for c in (data or {}).get("changes") or [] if isinstance(data, dict) else []:
            what = c.get("field") or "host"
            out.add(f"{str(c.get('host') or '').lower()} {what}: {c.get('change')}")
    return sorted(out)


def _closed_and_not_monitored(entry):
    """A closed case is watched only when its disposition says to keep monitoring it."""
    if entry["kind"] != "case":
        return ""
    st = _read(os.path.join(ROOT, "cases", entry["value"], "state.json"), {}) or {}
    outcome = ((st.get("disposition") or {}).get("outcome") or "")
    if st.get("status") == "closed" and outcome != "monitoring":
        return f"case is closed (outcome {outcome or 'unset'}) — not watched"
    return ""


def run_entry(entry, sources=None, allow_metered=False, fetch=False, now=None):
    """Run `sources` of one entry (default: all of them) once. Returns the result document and
    writes it beside the entry's state. `clean` lists the sources that really looked: a source
    that failed or answered degraded is not in it, keeps its previous baseline where it has none
    of its own, and is reported. Nothing here opens a case, collects a host or touches the KB."""
    now = now or _now()
    edir = _entry_dir(entry["id"])
    os.makedirs(edir, exist_ok=True)
    res = {"id": entry["id"], "kind": entry["kind"], "value": entry["value"], "ran_at": _iso(now),
           "sources": {}, "new": {}, "errors": {}, "degraded": {}, "warnings": {}, "clean": [],
           "skipped": ""}
    skip = _closed_and_not_monitored(entry)
    if skip:
        res["skipped"] = skip
        return res
    state = _read(os.path.join(edir, "state.json"), {}) or {}
    timeout = int(DEFAULTS.get("timeout_seconds", 300))
    raw = {}
    for source in (sources if sources is not None else entry.get("sources") or []):
        cmd = _command(source, entry, edir, allow_metered=allow_metered, fetch=fetch)
        if cmd is None:
            res["errors"][source] = "unknown source"
            continue
        data, err, warns = _exec(cmd, timeout)
        if warns:
            res["warnings"][source] = warns
        if data is None:
            res["errors"][source] = err or "no answer"      # the previous state is kept untouched
            continue
        if isinstance(data, dict) and data.get("error"):
            res["errors"][source] = str(data["error"])[:300]
            continue
        verdict, note = health(source, data)
        if verdict == "failed":
            res["errors"][source] = note
            continue
        now_sig = signals(source, data)
        seen = set(state.get(source) or [])
        first = source not in state
        # ct_monitor keeps its own baseline and only ever reports new certificates; every other
        # source is baselined on its first run here, so a new entry does not flood the analyst.
        fresh = now_sig if source == "ct" else ([] if first else [s for s in now_sig if s not in seen])
        res["sources"][source] = {"signals": len(now_sig), "baseline_run": first and source != "ct"}
        if fresh:
            res["new"][source] = fresh
        state[source] = sorted(seen | set(now_sig)) if source == "ct" else now_sig
        raw[source] = data
        if verdict == "degraded":
            res["degraded"][source] = note            # recorded, but due again on the next run
        else:
            res["clean"].append(source)
    _write(os.path.join(edir, "state.json"), state)
    _write(os.path.join(edir, _iso(now).replace(":", "") + ".json"), dict(res, answers=raw))
    return res


def run(only=None, every=False, allow_metered=False, fetch=False, now=None):
    """Run each entry's DUE sources (every source of `only`, or of all entries with `every`).
    Only a source that answered cleanly gets its stamp moved; a failed or degraded one stays due
    and is retried on the next run."""
    now = now or _now()
    entries, results = load(), []
    for e in entries:
        if only and e["id"] != only:
            continue
        todo = list(e.get("sources") or []) if (every or only) else due_sources(e, now)
        if not todo:
            continue
        r = run_entry(e, sources=todo, allow_metered=allow_metered, fetch=fetch, now=now)
        stamps = dict(e.get("source_last_run") or {})
        for s in (todo if r["skipped"] else r["clean"]):
            stamps[s] = _iso(now)
        e["source_last_run"] = stamps
        if r["clean"] or r["skipped"]:
            e["last_run"] = _iso(now)
        results.append(r)
        # saved per entry: a run killed part-way (the tool's time limit) keeps the stamps of the
        # entries it finished instead of repeating their sweeps - metered ones included
        _write(_list_path(), entries)
    return results


# --------------------------------------------------------------------------- CLI
_DOMAIN_IN = re.compile(r"(?<![\w.-])((?:[a-z0-9-]+\.)+[a-z]{2,})(?![\w.-])")


def _print_results(results):
    if not results:
        print("nothing due.")
        return
    for r in results:
        head = f"{r['id']} ({r['kind']} {r['value']})"
        if r["skipped"]:
            print(f"- {head}: {r['skipped']}")
            continue
        ran = ", ".join(f"{s}{' [baseline]' if m['baseline_run'] else ''}" for s, m in r["sources"].items())
        print(f"- {head}: ran {ran or 'nothing'}")
        for s, why in r["errors"].items():
            print(f"    ! {s} FAILED — not a result, retried on the next run: {why}")
        for s, why in (r.get("degraded") or {}).items():
            print(f"    ~ {s} DEGRADED — retried on the next run: {why}")
        for s, lines in (r.get("warnings") or {}).items():
            for ln in lines:
                print(f"    ~ {s}: {ln}")
        leads = set()
        for s, items in r["new"].items():
            for it in items:
                print(f"    NEW [{s}] {it}")
                leads.update(m for m in _DOMAIN_IN.findall(it.split(": ", 1)[-1]) if m != r["value"])
        for d in sorted(leads):
            print(f"    lead — not collected, no case opened. To investigate: /cti {d}")
        if not r["new"] and not r["errors"] and not r.get("degraded"):
            print("    nothing new")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Watch-list over the existing CT / lookalike / "
                                             "takedown / drift monitors. Leads only.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("add", help="add a brand keyword, a domain or a case")
    a.add_argument("kind", choices=KINDS)
    a.add_argument("value")
    a.add_argument("--sources", default="", help="comma-separated; default: every source the kind allows")
    a.add_argument("--interval", default=None, help="hours between runs")
    ls = sub.add_parser("list", help="show the watch-list")
    ls.add_argument("--json", action="store_true")
    rm = sub.add_parser("rm", help="remove an entry by id")
    rm.add_argument("id")
    r = sub.add_parser("run", help="run every DUE entry once, then exit")
    r.add_argument("--due", action="store_true", help="the default; accepted for readability")
    r.add_argument("--all", action="store_true", help="run every entry, due or not")
    r.add_argument("--id", default=None, help="run this entry now")
    r.add_argument("--allow-metered", action="store_true",
                   help="let the lookalike source run its FOFA / urlscan sweeps")
    r.add_argument("--fetch", action="store_true",
                   help="let the takedown source read co-tenant pages (off: status and leads only)")
    r.add_argument("--json", action="store_true")
    args = ap.parse_args(sys.argv[1:] if argv is None else argv)

    if args.cmd == "add":
        entry, err = add(args.kind, args.value, [s for s in args.sources.split(",") if s.strip()] or None,
                         args.interval)
        if err:
            print(f"watch add: {err}", file=sys.stderr)
            return 2
        print(f"added {entry['id']}: {', '.join(entry['sources'])} every {entry['interval_hours']:g}h")
        return 0
    if args.cmd == "list":
        entries = load()
        if args.json:
            print(json.dumps(entries, ensure_ascii=False))
        elif not entries:
            print("the watch-list is empty — `intel.py watch add brand|domain|case <value>`")
        else:
            now = _now()
            for e in entries:
                print(f"{e['id']:<34} {', '.join(e['sources']):<30} every {e['interval_hours']:g}h  "
                      f"last {e.get('last_run') or 'never'}  {'DUE' if is_due(e, now) else ''}")
        return 0
    if args.cmd == "rm":
        if not remove(args.id):
            print(f"watch rm: no entry {args.id}", file=sys.stderr)
            return 2
        print(f"removed {args.id} (its history under MEMORY/watch/{args.id}/ is kept)")
        return 0
    results = run(only=args.id, every=args.all, allow_metered=args.allow_metered, fetch=args.fetch)
    if args.json:
        print(json.dumps(results, ensure_ascii=False))
    else:
        _print_results(results)
    incomplete = any(r["errors"] or r.get("degraded") for r in results)
    return 3 if incomplete else 0


if __name__ == "__main__":
    sys.exit(main())
