"""wp_plans — the on-disk, per-case ENTITLEMENT store: cases/<id>/capability_plans.json.

Entitlement is DISCOVERED, not assumed. Every keyed vendor answers a cheap (free) probe, and one
vendor — Censys — cannot be probed at all except by the productive call itself (its search IS the
probe: a Free plan answers 403). Two facts make a per-process memo useless for this:

  * `cmd_open` and every loop round are separate processes, and the collector runs one
    pivot_extract subprocess per host — so "we already learned this key is Free" must live on disk
    under the case, read at process start and written on the first 403/200;
  * the store must never gate a call that only that call can decide (red-team H0): a reader asks
    "is Censys already recorded as free?" and runs the search otherwise. The first attempt is the
    probe; the 403 records `free`; every later process skips.

Shape: {"generated": iso, "plans": {vendor: tier-string | {…}}, "history": [{vendor, plan, at, why}]}.
Case dir comes from the argument or $WP_CASE_DIR (exported by intel.py cmd_open/loop). Without a
case dir the store is a no-op and readers see {} — never an error. Never stores a key value.
"""
import datetime
import json
import os
import threading

FILE = "capability_plans.json"
CASE_DIR_ENV = "WP_CASE_DIR"
_LOCK = threading.Lock()

try:
    import fcntl
except Exception:  # noqa: BLE001
    fcntl = None


def _now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def path_for(case_dir=None):
    case_dir = case_dir or os.environ.get(CASE_DIR_ENV) or ""
    return os.path.join(case_dir, FILE) if case_dir else ""


def load(case_dir=None) -> dict:
    """The stored plans dict ({} when no case dir / no file / unreadable)."""
    p = path_for(case_dir)
    if not p or not os.path.isfile(p):
        return {}
    try:
        doc = json.load(open(p, encoding="utf-8"))
        return dict(doc.get("plans") or {}) if isinstance(doc, dict) else {}
    except Exception:  # noqa: BLE001
        return {}


def get(vendor: str, case_dir=None, default=None):
    return load(case_dir).get(vendor, default)


def record(vendor: str, plan, why: str = "", case_dir=None) -> bool:
    """Persist one vendor's measured plan. Read-modify-write under an exclusive lock on a SIDECAR
    lock file, then an atomic `os.replace` of the data file — so eight collector subprocesses cannot
    clobber each other AND an unlocked `load()` can never observe a truncated/partial document (a
    crash mid-write leaves the previous complete file, never an empty one). Returns True when written."""
    p = path_for(case_dir)
    if not p:
        return False
    try:
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with _LOCK, open(p + ".lock", "a", encoding="utf-8") as lk:
            if fcntl is not None:
                fcntl.flock(lk.fileno(), fcntl.LOCK_EX)
            try:
                doc = {}
                if os.path.isfile(p):
                    try:
                        with open(p, encoding="utf-8") as fh:
                            doc = json.load(fh)
                    except Exception:  # noqa: BLE001
                        doc = {}
                if not isinstance(doc, dict):
                    doc = {}
                plans = doc.setdefault("plans", {})
                if plans.get(vendor) == plan:
                    return True                          # already recorded: idempotent, no history noise
                plans[vendor] = plan
                doc["generated"] = _now()
                doc.setdefault("history", []).append({"vendor": vendor, "plan": plan, "at": _now(), "why": why[:200]})
                tmp = p + ".tmp"
                with open(tmp, "w", encoding="utf-8") as fh:
                    json.dump(doc, fh, indent=2, ensure_ascii=False)
                    fh.flush()
                    os.fsync(fh.fileno())
                os.replace(tmp, p)
            finally:
                if fcntl is not None:
                    fcntl.flock(lk.fileno(), fcntl.LOCK_UN)
        return True
    except Exception:  # noqa: BLE001
        return False


def record_many(plans: dict, why: str = "", case_dir=None) -> int:
    n = 0
    for v, plan in (plans or {}).items():
        if record(v, plan, why=why, case_dir=case_dir):
            n += 1
    return n


__all__ = ["FILE", "CASE_DIR_ENV", "path_for", "load", "get", "record", "record_many"]
