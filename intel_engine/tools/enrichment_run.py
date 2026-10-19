#!/usr/bin/env python3
"""Execute machine-runnable case enrichment leads; keep analyst-only leads open.

Each lead has a structured run spec from case_state.frontier(). A successful step is
checkpointed before the next one, so a partial multi-call lead resumes without buying
its successful calls again. The caller supplies spend posture; no producer display text
is ever interpreted as a command.
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import case_state  # noqa: E402
if os.path.join(ROOT, "WebPivot", "tools") not in sys.path:
    sys.path.insert(0, os.path.join(ROOT, "WebPivot", "tools"))
import wp_exhaust  # noqa: E402 — the shared execution-outcome vocabulary (ran|empty|error|…)

SCRIPTS = {
    "email-deep": os.path.join(ROOT, "..", "scripts", "osint", "deep_profile.py"),
    "phone": os.path.join(ROOT, "..", "scripts", "osint", "phone_osint.py"),
    "cld": os.path.join(ROOT, "..", "scripts", "cld", "cld_api.py"),
    "intelx": os.path.join(ROOT, "WebPivot", "tools", "wp_intelx.py"),
    "github": os.path.join(ROOT, "WebPivot", "tools", "wp_github.py"),
    "hudsonrock": os.path.join(ROOT, "..", "scripts", "osint", "keyed_feeds.py"),
}
METERED = {"email-deep", "intelx", "hudsonrock"}   # spend-gated legs held under free-only/no_spend/defer.
# ChongLuaDao is NOT here: its usage is unlimited (no per-call credit / quota), so CLD legs run
# under free-only and no_spend like a free source. The api_usage ledger still LOGS every CLD
# request — a usage log never caps — but it is not a spend gate.
_KEY_REGISTRY = os.path.join(ROOT, "WebPivot", "references", "api_keys.json")


def _registry_aliases():
    """canonical env name -> (canonical, *aliases) from the key registry (reference data, RULE 3).
    A missing/broken file degrades to identity so a name still matches itself."""
    try:
        with open(_KEY_REGISTRY, encoding="utf-8") as fh:
            entries = json.load(fh)["api_keys"]["entries"]
    except (OSError, ValueError, KeyError, TypeError):
        return {}
    out = {}
    for canon, meta in entries.items():
        names = [canon] + [a for a in (meta.get("aliases") or []) if isinstance(a, str)]
        out[canon] = tuple(dict.fromkeys(names))
    return out


_ALIASES = _registry_aliases()


def _with_aliases(names):
    """Expand canonical env names to include every registered alias, order-preserving. Blanking a
    key must blank ITS ALIASES too, or deep_profile's .env reload resurrects a memoized metered
    step through the alias and buys it a second time."""
    seen = []
    for n in names:
        for x in _ALIASES.get(n, (n,)):
            if x not in seen:
                seen.append(x)
    return tuple(seen)


KEY_ENVS = {op: _with_aliases(names) for op, names in {
    "cld": ("CHONGLUADAO_API_KEY", "CLD_API_KEY", "CHONGLUADAO_KEY", "BURNER_API_KEY"),
    "intelx": ("INTELX_KEY", "INTELX_API_KEY"),
    "hudsonrock": ("HUDSONROCK_API_KEY",),
    "email-deep": ("HUDSONROCK_API_KEY", "ZONECRUNCHER_API_KEY", "INTELX_KEY",
                   "INTELX_API_KEY", "WHOISXML_API_KEY"),
}.items()}
EMAIL_METERED = {step: _with_aliases(names) for step, names in {
    "hudsonrock": ("HUDSONROCK_API_KEY",),
    "zonecruncher": ("ZONECRUNCHER_API_KEY",),
    "intelx_search": ("INTELX_KEY", "INTELX_API_KEY"),
    "reverse_whois": ("WHOISXML_API_KEY",),
}.items()}
FINAL_OUTCOMES = ("ran", "empty")


def _has_any(names):
    return any(os.environ.get(k) for k in names)


def _keys(op):
    return True if op not in KEY_ENVS else _has_any(KEY_ENVS[op])


def _scope(case_dir):
    try:
        with open(os.path.join(case_dir, "scope.json"), encoding="utf-8") as fh:
            return json.load(fh).get("constraints") or {}
    except (OSError, ValueError, AttributeError):
        return {}


def _artifact(case_dir, key):
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:20]
    return os.path.join(case_dir, "enrichment", digest + ".json")


def _save(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", suffix=".json", dir=os.path.dirname(path))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _load(path, key):
    try:
        with open(path, encoding="utf-8") as fh:
            row = json.load(fh)
        if row.get("key") == key:
            return row
    except (OSError, ValueError, AttributeError):
        pass
    return {"key": key, "steps": {}}


def _ledger_delta(ledger, before):
    """Metered rows the child appended to the shared api_usage ledger since `before` bytes. Read on
    EVERY return path: a child killed at the timeout may already have spent credits, and dropping
    them silently under-reports the run's spend."""
    rows = []
    if not os.path.isfile(ledger):
        return rows
    try:
        with open(ledger, encoding="utf-8") as fh:
            fh.seek(before)
            for line in fh:
                try:
                    row = json.loads(line)
                except ValueError:
                    continue
                if row.get("credits"):
                    rows.append({"provider": row.get("provider"), "action": row.get("action"),
                                 "credits": row["credits"]})
    except OSError:
        pass
    return rows


def _call(op, argv, case_dir, hide_env=None):
    cmd = [sys.executable, SCRIPTS[op], *argv]
    if op == "email-deep":
        cmd += ["--case", case_dir]
    env = os.environ.copy()
    for name in hide_env or ():
        env[name] = ""
    env["WP_CASE_DIR"] = case_dir
    wp = os.path.join(ROOT, "WebPivot", "tools")
    if wp not in sys.path:
        sys.path.insert(0, wp)
    import api_usage
    ledger = api_usage._log_path()
    before = os.path.getsize(ledger) if os.path.isfile(ledger) else 0
    timeout = int(env.get("CTI_CALL_TIMEOUT") or 5000)
    try:
        r = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True, timeout=timeout)
        result = {"returncode": r.returncode, "stdout": r.stdout, "stderr": r.stderr[-1000:]}
    except subprocess.TimeoutExpired:
        result = {"returncode": 124,
                  "error": f"{op} {' '.join(argv)} timed out after {timeout}s — killed, not silently retried"}
    except OSError as exc:
        result = {"returncode": 127, "error": str(exc)}
    result["credits"] = _ledger_delta(ledger, before)
    return result


def _index_path(case_dir):
    return os.path.join(case_dir, "enrichment", "index.json")


def _load_index(case_dir):
    try:
        with open(_index_path(case_dir), encoding="utf-8") as fh:
            data = json.load(fh)
        leads = data.get("leads") or {}
        return {"leads": leads if isinstance(leads, dict) else {}}
    except (OSError, ValueError, AttributeError):
        return {"leads": {}}


def _write_index(case_dir, data):
    leads = data.get("leads") or {}
    data["leads"] = leads if isinstance(leads, dict) else {}
    _save(_index_path(case_dir), data)


def _short(text, limit=260):
    s = " ".join(str(text or "").split())
    return s if len(s) <= limit else s[:limit - 1].rstrip() + "…"


def _result_json(result):
    if result.get("returncode") != 0:
        detail = result.get("error") or result.get("stderr") or result.get("stdout")
        return None, f"exit {result.get('returncode')}: {_short(detail, 180)}"
    # exit 0 with NOTHING on stdout (or a bare `{}`) is a step that broke quietly — FAILED and
    # retried, never "asked and found nothing", which would close the lead for good.
    if not (result.get("stdout") or "").strip():
        return None, "exit 0 with empty stdout — the step produced nothing (failed, not empty)"
    try:
        data = json.loads(result.get("stdout") or "")
    except (TypeError, ValueError):
        return None, "exit 0 but stdout was not JSON"
    result["data"] = data
    result.pop("stdout", None)
    if not isinstance(data, dict):
        return None, "JSON output was not an object"
    if not data:
        return None, "exit 0 with an empty JSON object — the step produced nothing (failed, not empty)"
    return data, None


def _row_count(data, names):
    for name in names:
        rows = data.get(name)
        if isinstance(rows, list):
            return len(rows)
    return 0


def _cld_summary(data):
    result = data.get("result") or {}
    usage = data.get("usage") or {}
    parts = []
    sides = result.get("sides") if isinstance(result, dict) else None
    if isinstance(sides, dict) and sides:
        for name, side in sorted(sides.items()):
            if not isinstance(side, dict):
                continue
            if side.get("ok"):
                matched = side.get("matched")
                if matched is None:
                    matched = _row_count(side.get("result") or {}, ("items", "data", "results", "victims"))
                verdict = (side.get("result") or {}).get("verdict")
                suffix = f", verdict={verdict}" if verdict else ""
                parts.append(f"{name}: ok matched={matched}{suffix}")
            else:
                status = side.get("status") if side.get("status") is not None else "n/a"
                parts.append(f"{name}: unavailable status={status}")
    else:
        rows = result if isinstance(result, dict) else {}
        count = _row_count(rows, ("items", "data", "results", "victims"))
        if "matched" in rows:
            count = rows.get("matched") or count
        parts.append(f"{data.get('op') or 'cld'}: matched={count}")
    if usage:
        calls = usage.get("calls")
        units = usage.get("billable_units")
        if calls is not None or units is not None:
            parts.append(f"usage calls={calls or 0} units={units or 0}")
    return _short("; ".join(parts) or "CLD completed")


def _email_hits(name, row):
    if not isinstance(row, dict):
        return 0
    if name in ("hudsonrock", "zonecruncher"):
        return int(row.get("hits") or 0)
    if name == "intelx_search":
        return int(row.get("records") or 0)
    if name == "reverse_whois":
        if isinstance(row.get("count"), int):
            return row["count"]
        domains = row.get("domains")
        return len(domains) if isinstance(domains, list) else 0
    return 0


def _email_state_from_run(name, row):
    status = str((row or {}).get("status") or "")
    if status == "ok" or (name == "reverse_whois" and status == "skipped"):
        return {"state": "done", "status": status, "hits": _email_hits(name, row)}
    if status == "skipped":
        return {"state": "unavailable", "status": status, "hits": _email_hits(name, row)}
    if status == "unavailable":
        return {"state": "retry", "status": status, "hits": _email_hits(name, row)}
    return {"state": "retry", "status": status or "failed", "hits": _email_hits(name, row)}


def _email_state_from_plan(plan):
    status = str((plan or {}).get("status") or "")
    if status.startswith("BLOCKED"):
        return {"state": "unavailable", "status": "missing key", "hits": 0}
    if status.startswith("HELD") or status.startswith("READY"):
        return {"state": "held", "status": status.split("—", 1)[0].strip().lower(), "hits": 0}
    if status.startswith("n/a"):
        return {"state": "done", "status": "n/a", "hits": 0}
    return {"state": "unavailable", "status": status or "not run", "hits": 0}


def _email_completed(memo):
    return {name for name, row in (memo or {}).items()
            if isinstance(row, dict) and row.get("state") == "done"}


def _email_hide_env(memo):
    hide = set()
    for name in _email_completed(memo):
        hide.update(EMAIL_METERED.get(name, ()))
    return sorted(hide)


def _email_pending_have_key(memo):
    done = _email_completed(memo)
    for name, keys in EMAIL_METERED.items():
        if name not in done and _has_any(keys):
            return True
    return False


def _email_summary(memo, data=None):
    pieces = []
    for name in EMAIL_METERED:
        row = (memo or {}).get(name) or {}
        state = row.get("state") or "pending"
        hits = row.get("hits", 0)
        pieces.append(f"{name}={state}:{hits}")
    if data:
        free = [k for k, v in (data.get("ran") or {}).items()
                if k not in EMAIL_METERED and isinstance(v, dict)]
        if free:
            failures = [k for k in free if str((data.get("ran") or {}).get(k, {}).get("status")) != "ok"]
            pieces.append(f"free={len(free)} ran/{len(failures)} failed")
    return _short("; ".join(pieces))


def _email_outcome(memo):
    states = {((memo or {}).get(name) or {}).get("state") for name in EMAIL_METERED}
    if "retry" in states:
        return "retry"
    if "unavailable" in states:
        return "unavailable"
    if "held" in states:
        return "held"
    if all(((memo or {}).get(name) or {}).get("state") == "done" for name in EMAIL_METERED):
        return "ran"
    return "unavailable"


def _judge_email(result, memo):
    data, err = _result_json(result)
    if err:
        return "retry", err, dict(memo or {})
    merged = dict(memo or {})
    ran = data.get("ran") or {}
    planned = {p.get("step"): p for p in (data.get("planned") or []) if isinstance(p, dict)}
    for name in EMAIL_METERED:
        current = merged.get(name) if isinstance(merged.get(name), dict) else None
        if current and current.get("state") == "done":
            continue
        if isinstance(ran.get(name), dict):
            merged[name] = _email_state_from_run(name, ran[name])
        else:
            merged[name] = _email_state_from_plan(planned.get(name))
    return _email_outcome(merged), _email_summary(merged, data), merged


_LEAK_COUNT_KEYS = frozenset({"count", "total", "total_count", "matched", "hits", "found",
                              "exposed", "exposure_count", "records", "breaches", "leaks"})
_LEAK_LIST_KEYS = frozenset({"items", "data", "results", "records", "accounts", "breaches",
                             "sources", "leaks", "victims"})
_LEAK_FLAG_KEYS = frozenset({"exposed", "found", "is_exposed", "leaked", "compromised"})


def _leak_hits(obj, depth=0):
    """Largest positive exposure signal anywhere in a leak-check response: a count, a non-empty
    row list, or a true exposed/found flag. 0 means the vendor answered and found nothing."""
    if depth > 4:
        return 0
    if isinstance(obj, list):
        return len(obj)
    if not isinstance(obj, dict):
        return 0
    best = 0
    for k, v in obj.items():
        kl = str(k).lower()
        if isinstance(v, bool):
            best = max(best, 1 if (v and kl in _LEAK_FLAG_KEYS) else 0)
        elif isinstance(v, (int, float)) and kl in _LEAK_COUNT_KEYS:
            best = max(best, int(v))
        elif isinstance(v, list) and kl in _LEAK_LIST_KEYS:
            best = max(best, len(v))
        elif isinstance(v, dict):
            best = max(best, _leak_hits(v, depth + 1))
    return best


def _judge(op, result, memo=None, argv=None):
    if op == "email-deep":
        return _judge_email(result, memo or {})
    data, err = _result_json(result)
    if err:
        return "retry", err, memo
    if op == "hudsonrock":
        status = str(data.get("status") or "")
        if status == "ok":
            hits = int(data.get("hits") or 0)
            return ("ran" if hits else "empty"), f"hudsonrock {data.get('endpoint')}: hits={hits}", memo
        if status.startswith("NOT CONSULTED") or status == "skipped":
            return "unavailable", _short(data.get("skipped") or status), memo
        return "retry", _short(f"hudsonrock {status or 'failed'}: {data.get('error') or ''}"), memo
    if op == "cld" and argv and argv[0] == "exposure":
        if not data.get("ok") or data.get("skipped"):
            return "retry", _short(data.get("error") or "CLD exposure was skipped"), memo
        hits = _leak_hits(data.get("result"))
        return ("ran" if hits else "empty"), f"cld exposure ({argv[-1]}): hits={hits}", memo
    if op == "cld":
        if not data.get("ok") or data.get("skipped"):
            reason = data.get("error") or "CLD lookup was skipped"
            return "retry", _short(reason), memo
        sides = (data.get("result") or {}).get("sides") or {}
        if any(isinstance(row, dict) and not row.get("ok") for row in sides.values()):
            return "retry", _cld_summary(data), memo
        if sides:
            positive = any(isinstance(row, dict) and (
                row.get("hit") or row.get("matched") or (row.get("result") or {}).get("verdict"))
                for row in sides.values())
            return ("ran" if positive else "empty"), _cld_summary(data), memo
        rows = data.get("result") or {}
        count = _row_count(rows, ("items", "data", "results", "victims"))
        return ("ran" if count else "empty"), _cld_summary(data), memo
    if data.get("error") or data.get("skipped"):
        reason = data.get("error") or data.get("skipped")
        return "retry", _short(reason), memo
    if op == "phone":
        summary = data.get("summary") or {}
        valid = summary.get("valid") or 0
        return ("ran" if valid else "empty"), f"phone valid={valid}", memo
    if op == "github":
        api = data.get("api") or {}
        counts = {k: len(data.get(k) or []) for k in ("repos", "identities")}
        has_profile = bool(data.get("profile"))
        summary = (f"github profile={'yes' if has_profile else 'no'} repos={counts['repos']} "
                   f"identities={counts['identities']}")
        if api.get("errors"):
            return "retry", _short(summary + f"; api errors={api.get('errors')}"), memo
        return ("ran" if has_profile or any(counts.values()) else "empty"), summary, memo
    if op == "intelx":
        counts = {k: len(data.get(k) or []) for k in ("emails", "domains", "urls", "records")}
        summary = "intelx " + " ".join(f"{k}={v}" for k, v in counts.items())
        return ("ran" if any(counts.values()) else "empty"), summary, memo
    return "ran", f"{op} completed", memo


#: lead outcome -> execution-outcome status (wp_exhaust vocabulary). `retry` is a FAILED step —
#: error, or timed_out when the child was killed at the ceiling — never collected-empty.
_STATUS_OF = {"ran": "ran", "empty": "empty", "retry": "error",
              "unavailable": "skipped_no_key", "held": "skipped_policy"}


def _execution_outcome(outcome, summary, policy="", returncode=None, elapsed=None):
    status = _STATUS_OF.get(outcome, "error")
    if status == "error" and returncode == 124:
        status = "timed_out"
    reason = policy if status == "skipped_policy" else ("" if status in ("ran", "empty") else summary)
    return wp_exhaust.outcome(status, reason, elapsed)


def _index_row(case_dir, key, outcome, summary, execution=None):
    path = _artifact(case_dir, key)
    row = {"outcome": outcome, "summary": _short(summary)}
    if os.path.isfile(path):
        row["file"] = os.path.basename(path)
    if execution:                       # additive: status / reason / elapsed_s (+ at)
        row.update({k: execution[k] for k in ("status", "reason", "elapsed_s", "at")})
    return row


def _update_index(case_dir, key, outcome, summary, execution=None):
    index = _load_index(case_dir)
    index["leads"][key] = _index_row(case_dir, key, outcome, summary, execution)
    _write_index(case_dir, index)


def _lead_ops(lead):
    return [step.get("op") for step in (lead.get("run") or [])]


def _all_runnable_leads(case_dir):
    leads = {}
    raw = os.path.join(case_dir, "raw")
    for name in sorted(os.listdir(raw)) if os.path.isdir(raw) else ():
        if not name.endswith(".json"):
            continue
        try:
            with open(os.path.join(raw, name), encoding="utf-8") as fh:
                obj = json.load(fh)
            case_state._enrichment_leads_from_raw(obj, leads)
        except Exception:
            continue
    return {v["key"]: v for v in leads.values() if v.get("run")}


def _legacy_can_reopen(lead, free_only, constraints, defer_metered):
    ops = _lead_ops(lead)
    if defer_metered and any(op in METERED for op in ops):
        return False
    if (free_only or constraints.get("no_spend")) and any(op in METERED for op in ops):
        return False
    return all(_keys(op) for op in ops)


def _reopen_legacy(case, case_dir, free_only, constraints, defer_metered, reopen_legacy=False):
    st = case_state.load_state(case)
    done = case_state._done_map(st)
    if not done:
        return [], []
    index = _load_index(case_dir)["leads"]
    leads = _all_runnable_leads(case_dir)
    reopened, ambiguous = [], []
    for key, reason in list(done.items()):
        if reason not in ("skipped", "unavailable"):
            continue
        if key in index or key not in leads:
            continue
        if not _legacy_can_reopen(leads[key], free_only, constraints, defer_metered):
            continue
        if os.path.isfile(_artifact(case_dir, key)) or reopen_legacy:
            done.pop(key, None)
            reopened.append(key)
        else:
            ambiguous.append(key)
    if reopened:
        st["enrichment_done"] = done
        case_state.save_state(case, st)
    return reopened, ambiguous


def _missing_key_summary(ops):
    missing = []
    for op in ops:
        if op in KEY_ENVS and not _keys(op):
            missing.append(f"{op}: set one of {', '.join(KEY_ENVS[op])}")
    return "; ".join(missing) or "required key unavailable"


def _invoke(invoke, op, argv, case_dir, hide_env=None):
    """A runner that RAISES is a failed step (retry, status error) — not a crash of the whole
    case, and never a silent empty."""
    try:
        return invoke(op, argv, case_dir, hide_env=hide_env)
    except Exception as exc:  # noqa: BLE001
        return {"returncode": 1, "error": f"{op} raised {type(exc).__name__}: {exc}", "credits": []}


def _run_step(invoke, case_dir, record, step):
    op, argv = step.get("op"), step.get("argv")
    if op not in SCRIPTS or not isinstance(argv, list):
        return "retry", "invalid runner step", False
    step_key = json.dumps([op, argv], ensure_ascii=False)
    previous = record["steps"].get(step_key) or {}
    if previous.get("outcome") in FINAL_OUTCOMES:
        return previous["outcome"], previous.get("summary") or f"{op} memoized", False
    memo = previous.get("memo") or {}
    if op == "email-deep":
        if all(name in _email_completed(memo) for name in EMAIL_METERED):
            outcome = _email_outcome(memo)
            summary = _email_summary(memo)
            record["steps"][step_key] = {"outcome": outcome, "summary": summary, "memo": memo}
            return outcome, summary, True
        if memo and not _email_pending_have_key(memo):
            summary = _email_summary(memo) + "; pending keyed steps unavailable"
            record["steps"][step_key] = {"outcome": "unavailable", "summary": _short(summary),
                                         "memo": memo}
            return "unavailable", _short(summary), True
        response = _invoke(invoke, op, argv, case_dir, hide_env=_email_hide_env(memo))
        outcome, summary, memo = _judge(op, response, memo)
        record["steps"][step_key] = {"outcome": outcome, "summary": summary, "memo": memo, **response}
    else:
        response = _invoke(invoke, op, argv, case_dir)
        outcome, summary, _ = _judge(op, response, argv=argv)
        record["steps"][step_key] = {"outcome": outcome, "summary": summary, **response}
    _save(_artifact(case_dir, record["key"]), record)
    credits = (record["steps"].get(step_key) or {}).get("credits") or []
    if credits:
        print(f"   credits {record['key']}: " + ", ".join(
            f"{r['provider']}/{r['action']} ~{r['credits']}" for r in credits))
    return outcome, summary, True


_VIA_STEP = {"hudsonrock": "hudsonrock", "intelx": "intelx_search"}   # vendor -> email-deep memo step
LEAK_COLLECTOR = "enrichment_run/leak_fanout"


def _leak_cell(row, done_reason, key):
    """(state, reason) for one runnable vendor leg from its index row: hit | clean | not_consulted."""
    if not row:
        if done_reason in FINAL_OUTCOMES:
            return ("hit" if done_reason == "ran" else "clean"), f"closed as {done_reason} ({key})"
        if done_reason:
            return "not_consulted", f"closed as {done_reason} by analyst/legacy state ({key})"
        return "not_consulted", "not run yet — lead open"
    outcome, summary = row.get("outcome"), row.get("summary") or ""
    if outcome == "ran":
        return "hit", summary
    if outcome == "empty":
        return "clean", summary
    if outcome == "held":
        return "not_consulted", f"[{row.get('reason') or 'spend posture'}] {summary}"
    if outcome == "unavailable":
        return "not_consulted", f"missing key / unsupported: {summary}"
    return "not_consulted", f"error, retryable: {summary}"


def _email_memo(case_dir, key, email):
    rec = _load(_artifact(case_dir, key), key)
    step = rec["steps"].get(json.dumps(["email-deep", [email]], ensure_ascii=False)) or {}
    return step.get("memo") or {}


def _email_deep_cell(row, done_reason, key, memo):
    """deep_profile's own cell: a finished chain is a hit when ANY metered step found rows."""
    state, reason = _leak_cell(row, done_reason, key)
    if state == "hit":           # email-deep `ran` = every keyed step done, not "found something"
        hits = sum(int((memo.get(n) or {}).get("hits") or 0) for n in EMAIL_METERED)
        state = "hit" if hits else "clean"
    return state, reason


def _via_cell(row, done_reason, key, memo, vendor):
    """A vendor deep_profile sends for an email (never bought twice): read from its memo."""
    sub = memo.get(_VIA_STEP.get(vendor, vendor)) or {}
    st = sub.get("state")
    if st == "done":
        hits = int(sub.get("hits") or 0)
        return ("hit" if hits else "clean"), f"via deep_profile: {vendor} hits={hits}"
    if st:
        return "not_consulted", f"via deep_profile: {vendor} {st} ({sub.get('status') or '?'})"
    state, reason = _leak_cell(row, done_reason, key)
    if state in ("hit", "clean"):
        return "not_consulted", f"via deep_profile: no {vendor} step recorded"
    return "not_consulted", f"via deep_profile — {reason}"


def leak_coverage(case, case_dir=None, kb_root=None):
    """Per-selector × per-vendor leak coverage for every CONFIRMED selector (case_state.
    leak_selectors). Writes enrichment/leak_coverage.json and records consulted results (hit /
    clean) as KB EXPOSURE FACTS (attribute leak_exposure) — never edges, never attribution."""
    case_dir = case_dir or case_state._case_dir(case)
    index = _load_index(case_dir)["leads"]
    done = case_state._done_map(case_state.load_state(case))
    rows = []
    for sel in case_state.leak_selectors(case):
        plan = case_state.leak_vendor_plan(sel["type"], sel["value"])
        for vendor in case_state.LEAK_VENDORS:
            step = plan.get(vendor) or {"na": "not planned"}
            if step.get("na"):
                state, reason, key = "not_consulted", f"n/a: {step['na']}", ""
            elif step.get("via"):
                via = plan.get(step["via"]) or {}
                key = via.get("key", "")
                memo = _email_memo(case_dir, key, sel["value"]) if key else {}
                state, reason = _via_cell(index.get(key), done.get(key), key, memo, vendor)
            else:
                key = step["key"]
                if step["op"] == "email-deep":
                    state, reason = _email_deep_cell(index.get(key), done.get(key), key,
                                                     _email_memo(case_dir, key, sel["value"]))
                else:
                    state, reason = _leak_cell(index.get(key), done.get(key), key)
            rows.append({"type": sel["type"], "selector": sel["value"], "origin": sel["origin"],
                         "vendor": vendor, "state": state, "reason": _short(reason, 200),
                         "lead": key})
    doc = {"case": str(case), "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "vendors": list(case_state.LEAK_VENDORS), "rows": rows}
    _save(os.path.join(case_dir, "enrichment", "leak_coverage.json"), doc)
    _leak_facts(case, case_dir, rows, kb_root)
    return doc


def _leak_facts(case, case_dir, rows, kb_root=None):
    consulted = [r for r in rows if r["state"] in ("hit", "clean")]
    if not consulted:
        return 0
    kb_dir = os.path.join(HERE, "kb")
    if kb_dir not in sys.path:
        sys.path.insert(0, kb_dir)
    try:
        from knowledge_base import KB
        from selector_types import kb_key
        kb = KB(kb_root or os.path.join(ROOT, os.environ.get("HARNESS_KB", "knowledge")))
    except Exception as exc:  # noqa: BLE001 — coverage JSON is the record; the KB is best-effort
        print(f"   leak coverage: KB facts not written ({type(exc).__name__}: {exc})")
        return 0
    when = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    ref = "/".join(("cases", os.path.basename(os.path.normpath(case_dir)), "enrichment",
                    "leak_coverage.json"))
    for r in consulted:
        et, ev = kb_key(r["type"], r["selector"])
        kb.add_fact(et, ev, "leak_exposure",
                    {"vendor": r["vendor"], "state": r["state"], "detail": r["reason"],
                     "case": str(case)},
                    r["vendor"], LEAK_COLLECTOR, when, "medium", ref)
    return len(consulted)


def _print_coverage(doc):
    rows = doc.get("rows") or []
    if not rows:
        print("   leak coverage: no confirmed selector in this case yet")
        return
    print(f"   leak coverage ({len({(r['type'], r['selector']) for r in rows})} confirmed "
          "selector(s); hit | clean | not_consulted — exposure, not attribution):")
    for r in rows:
        print(f"     {r['type']:8} {r['selector'][:48]:48} {r['vendor']:12} {r['state']:13} {r['reason']}")


def run_case(case, free_only=False, passive=False, call=None, defer_metered=False, reopen_legacy=False,
             leak_only=False):
    """Run eligible leads once; checkpoint results and close only accounted-for legs.

    `passive` is an egress posture flag and does not block third-party enrichment. Non-executable
    dork/secret query leads remain open for the slash-command agent to execute and review.
    `leak_only` runs just the leak fan-out leads (the harness's round-1 step). Every run ends by
    writing the per-selector leak coverage table (enrichment/leak_coverage.json).
    """
    case_dir = case_state._case_dir(case)
    constraints = _scope(case_dir)
    hold = free_only or constraints.get("no_spend")
    reopened, ambiguous = _reopen_legacy(
        case, case_dir, free_only, constraints, defer_metered, reopen_legacy=reopen_legacy)
    for key in reopened:
        print(f"   enrichment {key}: reopened legacy held/unavailable state")
    if ambiguous:
        print(f"   enrichment: {len(ambiguous)} legacy held/unavailable lead(s) are runnable now but "
              "cannot be distinguished from manual analyst closure; pass --reopen-legacy to reopen")
    invoke = call or _call
    results = []
    for lead in case_state.frontier(case).get("enrichment_leads", []):
        if leak_only and not lead.get("leak"):
            continue
        run = lead.get("run") or []
        if not run:
            continue
        key = lead["key"]
        ops = _lead_ops(lead)
        policy, rc, t0 = "", None, time.monotonic()
        if defer_metered and any(op in METERED for op in ops):
            reason, policy = "held", "defer_metered"
            summary = "held: default loop defers metered enrichment; rerun full/keyed collection"
        elif hold and any(op in METERED for op in ops):
            reason, policy = "held", ("free_only" if free_only else "no_spend")
            why = "free-only posture" if free_only else "case no_spend constraint"
            summary = f"held: {why} blocks metered enrichment; lead remains open"
        elif any(not _keys(op) for op in ops):
            reason = "unavailable"
            summary = _missing_key_summary(ops)
        else:
            path = _artifact(case_dir, key)
            record = _load(path, key)
            reason = "empty"
            summaries = []
            for step in run:
                outcome, summary, _changed = _run_step(invoke, case_dir, record, step)
                summaries.append(summary)
                if outcome in ("retry", "unavailable", "held"):
                    reason = outcome
                    rc = (record["steps"].get(json.dumps([step.get("op"), step.get("argv")],
                                                          ensure_ascii=False)) or {}).get("returncode")
                    policy = "memoized step held" if outcome == "held" else ""
                    break
                if outcome == "ran":
                    reason = "ran"
            summary = "; ".join(s for s in summaries if s) or f"{key} completed"
        execution = _execution_outcome(reason, summary, policy, rc, time.monotonic() - t0)
        _update_index(case_dir, key, reason, summary, execution)
        if reason in FINAL_OUTCOMES:
            case_state.mark_enrichment_done(case, [key], reason)
        results.append({"key": key, "reason": reason, "status": execution["status"],
                        "summary": _short(summary)})
        print(f"   enrichment {key}: {reason} [{execution['status']}]"
              + (" (open for later run)" if reason not in FINAL_OUTCOMES else ""))
    remaining = len(case_state.frontier(case).get("enrichment_leads", []))
    print(f"   enrichment: {len(results)} handled; {remaining} lead(s) still open "
          "(query-only, held, unavailable, and retryable leads require later review/run)")
    try:
        _print_coverage(leak_coverage(case, case_dir))
    except Exception as exc:  # noqa: BLE001 — the table is a report; a failure never fails the run
        print(f"   leak coverage: not computed ({type(exc).__name__}: {exc})")
    return results


def main():
    ap = argparse.ArgumentParser(description="Run structured case enrichment leads.")
    ap.add_argument("case")
    ap.add_argument("--free-only", action="store_true", help="hold metered leads")
    ap.add_argument("--passive", action="store_true",
                    help="third-party passive enrichment stays allowed; reserved for hostile egress")
    ap.add_argument("--reopen-legacy", action="store_true",
                    help="reopen old skipped/unavailable state rows that lack runner index evidence")
    ap.add_argument("--leak-only", action="store_true",
                    help="run only the leak/stealer fan-out leads on confirmed selectors")
    a = ap.parse_args()
    import intel  # noqa: E402 — the pipeline's env resolver is the one key store
    intel._load_env()
    run_case(a.case, free_only=a.free_only, passive=a.passive,
             reopen_legacy=a.reopen_legacy, leak_only=a.leak_only)

if __name__ == "__main__":
    main()
