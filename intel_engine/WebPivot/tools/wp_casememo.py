"""wp_casememo — per-CASE on-disk memo + capped ledger for metered vendor calls.

collect_core runs one pivot_extract subprocess per host, eight at a time, so any "once per run"
memo or "N calls per run" cap that lives in process memory is really "once per HOST" — the estate's
25 hosts share the same registrant e-mail, the same origin IP, the same cert, and each subprocess
would buy the same answer again. This module gives every metered client the same two primitives,
keyed on the case dir the pipeline exports as $WP_CASE_DIR (intel.py cmd_open/loop; pivot_extract
derives it from `-o cases/<id>/raw/<host>.json`):

  get(ns, key) / put(ns, key, value)   cases/<id>/<ns>/<sha1(key)>.json — atomic write, never raises
  charge(ns, cap, note)                 cases/<id>/<ns>/ledger.jsonl — flock'd read-then-append; False
                                        when `cap` calls were already charged THIS RUN ($WP_RUN_ID)
  spent(ns)                             this run's charged calls

No case dir -> get() is None, put() is a no-op, charge() always allows (process-local caps still
apply in the caller). Values are JSON; a value carrying an `error` key is never memoised (transient
failures must be retried), a `skipped` one is (a plan/quota verdict is a fact for the run).
"""
import hashlib
import json
import os
import re
import threading

try:
    import fcntl
except Exception:  # noqa: BLE001
    fcntl = None

CASE_DIR_ENV = "WP_CASE_DIR"
RUN_ID_ENV = "WP_RUN_ID"
_LOCK = threading.Lock()


def case_dir():
    return os.environ.get(CASE_DIR_ENV) or ""


def _dir(ns):
    cd = case_dir()
    if not cd:
        return None
    d = os.path.join(cd, ns)
    try:
        os.makedirs(d, exist_ok=True)
    except Exception:  # noqa: BLE001
        return None
    return d


def _path(ns, key):
    d = _dir(ns)
    if not d:
        return None
    return os.path.join(d, hashlib.sha1(str(key).encode("utf-8")).hexdigest()[:24] + ".json")


def get(ns, key):
    p = _path(ns, key)
    if not p or not os.path.isfile(p):
        return None
    try:
        doc = json.load(open(p, encoding="utf-8"))
        return doc.get("value") if isinstance(doc, dict) and "value" in doc else None
    except Exception:  # noqa: BLE001
        return None


_ENTITLEMENT_RE = re.compile(r"HTTP 40[123]\b|\bplan\b|entitl|membership|\bpaid\b|\bpro key\b|starter|professional",
                             re.I)
_TRANSIENT_RE = re.compile(r"\bcap\b|budget|quota|exhaust|rate.?limit|\b429\b|\b5\d\d\b|timeout|per-run|per-case", re.I)


def memoisable(value) -> bool:
    """What may be frozen for the case. A transport `error` never (retry). A `skipped` only when it is an
    ENTITLEMENT fact (402/403, plan, membership — true for every later process too); a cap / budget /
    quota / rate-limit skip is a fact about THIS process' counters and must not stop the next one.
    Clients may say so explicitly with `skipped_kind`: 'entitlement' | 'budget'."""
    if not isinstance(value, dict):
        return value is not None
    if value.get("error"):
        return False
    sk = value.get("skipped")
    if not sk:
        return True
    kind = str(value.get("skipped_kind") or "").lower()
    if kind:
        return kind in ("entitlement", "plan")
    txt = str(sk)
    if _TRANSIENT_RE.search(txt) and not _ENTITLEMENT_RE.search(txt):
        return False
    return bool(_ENTITLEMENT_RE.search(txt))


def put(ns, key, value):
    """Memoise `value` unless it is a transport error or a transient (cap/budget/quota) skip. Returns
    True when written."""
    if not memoisable(value):
        return False
    p = _path(ns, key)
    if not p:
        return False
    try:
        with open(p + ".tmp", "w", encoding="utf-8") as fh:
            json.dump({"key": str(key), "value": value}, fh, ensure_ascii=False)
        os.replace(p + ".tmp", p)
        return True
    except Exception:  # noqa: BLE001
        return False


def _ledger(ns):
    d = _dir(ns)
    return os.path.join(d, "ledger.jsonl") if d else None


def _count(fh, rid):
    n = 0
    fh.seek(0)
    for line in fh:
        try:
            if not rid or json.loads(line).get("run") == rid:
                n += 1
        except Exception:  # noqa: BLE001
            continue
    return n


def spent(ns):
    p = _ledger(ns)
    if not p or not os.path.isfile(p):
        return 0
    try:
        with open(p, "r", encoding="utf-8") as fh:
            return _count(fh, os.environ.get(RUN_ID_ENV) or "")
    except Exception:  # noqa: BLE001
        return 0


def charge(ns, cap, note=""):
    """Reserve one call under a per-RUN, per-CASE cap. True = go ahead (and the call is now counted);
    False = cap reached. Atomic across subprocesses (exclusive flock around read+append); without a
    case dir it always allows — the caller's process-local cap still applies."""
    p = _ledger(ns)
    if not p:
        return True
    rid = os.environ.get(RUN_ID_ENV) or ""
    try:
        with _LOCK, open(p, "a+", encoding="utf-8") as fh:
            if fcntl is not None:
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            try:
                if _count(fh, rid) >= int(cap):
                    return False
                fh.seek(0, os.SEEK_END)
                fh.write(json.dumps({"run": rid, "note": str(note)[:120], "pid": os.getpid()}) + "\n")
                fh.flush()
            finally:
                if fcntl is not None:
                    fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        return True
    except Exception:  # noqa: BLE001
        return True


__all__ = ["case_dir", "get", "put", "charge", "spent", "CASE_DIR_ENV", "RUN_ID_ENV"]
