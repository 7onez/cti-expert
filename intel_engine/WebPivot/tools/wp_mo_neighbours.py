"""wp_mo_neighbours — Phase A of the MO-neighbour pivot: reverse a NON-CDN origin IP (a mail
server, a shared host) and WHOIS-verify each co-tenant's OWN registrant. UNCLASSIFIED output.

The question this answers is the cartel question — "who else runs the same play from the same
box?" — and by construction it is a SHARED-PROVIDER pivot (rung 10: a provider-customer
enumerator). That shapes the rails baked in here:

  * BULK GUARD FIRST. Distinct apexes above `bulk_results` (case_state.BULK_IP_RESULTS, 120) —
    backstopped by a source's total ONLY when that source truncated — is bulk hosting / parking:
    count + a top-N sample, a cohost lead, NO WHOIS spend. The band 12 < fan-out <= 120 (the audit's
    87-apex mail server) is exactly the band we want to classify, so the hosting/ASN rejections of
    `wp_ippivot.is_noise_provider` are deliberately NOT inherited — only its CDN-edge refusal is
    (via the caller's classify_ip) and the count guard.
  * NO CLASSIFICATION HERE. Each candidate row carries its own CURRENT WHOIS (whois_current, 1 DRS —
    never whois_summary's history purchase) and nothing else; `case_state.mo_neighbour_classification`
    decides same_registrant / same_mo / unrelated / unverifiable against the ESTATE context it alone
    has. `case_state._free_candidates_from_raw` never reads this block. Candidate rows live in their
    own block, never in cases/<id>/whois/ — a co-tenant must not masquerade as an estate sidecar.
  * SPEND BOUNDED ACROSS PROCESSES. collect_core runs one pivot_extract subprocess per host, eight at
    a time, so process-local state is not a memo. Under cases/<id>/mo_neighbours/: `<ip>.json` is the
    per-origin block cache read BEFORE any vendor call (bulk-skipped results included); `<ip>.lock`
    (O_CREAT|O_EXCL) makes ONE subprocess do the work while siblings wait, bounded, for the cache;
    `whois_ledger.jsonl` is read-then-appended under an exclusive flock and each line carries the run
    token (WP_RUN_ID, exported by intel.py), so `whois_run_cap` is a per-RUN cap, not a case-lifetime
    one. `verified[]` rows from earlier rounds (mo_neighbours.json) are reused unless they errored.

Never raises: every vendor call is tri-state and the block is always a dict a reader can consume.
"""
import concurrent.futures
import json
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wp_common import _registrable, _secret  # noqa: E402
import whois_enrich  # noqa: E402
import wp_netlas  # noqa: E402
import wp_validin  # noqa: E402
from wp_recon import urlscan_search  # noqa: E402

try:
    import fcntl  # POSIX advisory locks for the ledger; Windows degrades to process-local counting
except Exception:  # noqa: BLE001
    fcntl = None

# Thresholds and policy are OWNED by case_state (frontier guards + tools/kb/references/mo_neighbours.json);
# read them from there so discover() and the classifier can never disagree. The literals below are
# only the standalone fallback and a test asserts they match.
_TOOLS = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "tools")


def _policy():
    try:
        if _TOOLS not in sys.path:
            sys.path.insert(0, _TOOLS)
        import case_state  # noqa: E402
        return (int(case_state.MAX_IP_COHOSTS), int(case_state.BULK_IP_RESULTS), int(case_state.MO_MAX_CANDIDATES),
                int(case_state.MO_WHOIS_RUN_CAP), int(case_state.MO_WHOIS_WORKERS), int(case_state.MO_SIBLING_WAIT_S))
    except Exception:  # noqa: BLE001 — standalone WebPivot use
        return 12, 120, 40, 160, 4, 90


MAX_IP_COHOSTS, BULK_IP_RESULTS, MAX_CANDIDATES, WHOIS_RUN_CAP, WHOIS_WORKERS, SIBLING_WAIT_S = _policy()
CACHE_SUBDIR = "mo_neighbours"   # cases/<id>/mo_neighbours/{<ip>.json, <ip>.lock, whois_ledger.jsonl}
RUN_ID_ENV = "WP_RUN_ID"
CASE_DIR_ENV = "WP_CASE_DIR"

_MEMO: dict = {}             # origin_ip -> block (in-process half of the memo)
_LOCK = threading.Lock()
_WHOIS_SPENT = [0]           # process-local count (the fallback when no case dir / no flock)


def reset_process_state():
    """Test hook: forget the in-process memo and counter."""
    with _LOCK:
        _MEMO.clear()
        _WHOIS_SPENT[0] = 0


def whois_calls_made():
    return _WHOIS_SPENT[0]


def run_id():
    return os.environ.get(RUN_ID_ENV) or ""


# ------------------------------------------------------------------ on-disk memo / lock / ledger
def _cache_dir(case_dir):
    if not case_dir:
        return None
    d = os.path.join(case_dir, CACHE_SUBDIR)
    try:
        os.makedirs(d, exist_ok=True)
    except Exception:  # noqa: BLE001
        return None
    return d


def _block_path(case_dir, ip):
    d = _cache_dir(case_dir)
    return os.path.join(d, ip + ".json") if d else None


def _cached_block(case_dir, ip):
    p = _block_path(case_dir, ip)
    if p and os.path.isfile(p):
        try:
            return json.load(open(p, encoding="utf-8"))
        except Exception:  # noqa: BLE001
            return None
    return None


def _store_block(case_dir, ip, blk):
    p = _block_path(case_dir, ip)
    if not p:
        return
    try:
        with open(p + ".tmp", "w", encoding="utf-8") as fh:
            json.dump(blk, fh, ensure_ascii=False)
        os.replace(p + ".tmp", p)
    except Exception:  # noqa: BLE001
        pass


STALE_LOCK_S = 600           # > collect_core's longest per-host subprocess timeout (600s deep-archive)


def _pid_alive(pid):
    try:
        os.kill(int(pid), 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True                                   # exists, owned by someone else
    except Exception:  # noqa: BLE001
        return True                                   # unparseable/odd: be conservative, treat as live


def _lock_is_stale(path):
    """A lock whose writer is dead, or older than any collector subprocess can live. collect_core
    SIGKILLs a pivot_extract on timeout — no `finally` runs — so without this an origin would stay
    'in progress' for the rest of the case and never be verified again."""
    try:
        pid = open(path, encoding="utf-8").read().strip()
        age = time.time() - os.path.getmtime(path)
    except Exception:  # noqa: BLE001
        return False
    if pid.isdigit() and not _pid_alive(pid):
        return True
    return age > STALE_LOCK_S


def _acquire_origin_lock(case_dir, ip):
    """True = this process owns the origin; False = a live sibling is already verifying it."""
    d = _cache_dir(case_dir)
    if not d:
        return True
    path = os.path.join(d, ip + ".lock")
    for _attempt in (0, 1):
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.write(fd, str(os.getpid()).encode())
            os.close(fd)
            return True
        except FileExistsError:
            if _attempt == 0 and _lock_is_stale(path):
                try:
                    os.remove(path)                   # break it once, then retry the exclusive create
                except Exception:  # noqa: BLE001
                    return False
                continue
            return False
        except Exception:  # noqa: BLE001
            return True
    return False


def _release_origin_lock(case_dir, ip):
    d = _cache_dir(case_dir)
    if d:
        try:
            os.remove(os.path.join(d, ip + ".lock"))
        except Exception:  # noqa: BLE001
            pass


def _wait_for_sibling(case_dir, ip, wait_s):
    deadline = time.time() + max(0, wait_s)
    while time.time() < deadline:
        blk = _cached_block(case_dir, ip)
        if blk is not None:
            return blk
        time.sleep(0.5)
    return None


def _ledger_path(case_dir):
    d = _cache_dir(case_dir)
    return os.path.join(d, "whois_ledger.jsonl") if d else None


def _ledger_count(fh, rid):
    """Lines belonging to this run (all lines when no run token is set)."""
    n = 0
    fh.seek(0)
    for line in fh:
        if not rid:
            n += 1
            continue
        try:
            if json.loads(line).get("run") == rid:
                n += 1
        except Exception:  # noqa: BLE001
            continue
    return n


def _try_charge(case_dir, apex):
    """Reserve one WhoisXML call under the run cap. Atomic across processes when a case dir and
    flock are available (read count + append under one exclusive lock); process-local otherwise."""
    p = _ledger_path(case_dir)
    rid = run_id()
    if p and fcntl is not None:
        try:
            with open(p, "a+", encoding="utf-8") as fh:
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
                try:
                    if _ledger_count(fh, rid) >= WHOIS_RUN_CAP:
                        return False
                    fh.seek(0, os.SEEK_END)
                    fh.write(json.dumps({"run": rid, "apex": apex, "pid": os.getpid()}) + "\n")
                    fh.flush()
                finally:
                    fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
            with _LOCK:
                _WHOIS_SPENT[0] += 1
            return True
        except Exception:  # noqa: BLE001
            pass
    with _LOCK:
        if _WHOIS_SPENT[0] >= WHOIS_RUN_CAP:
            return False
        _WHOIS_SPENT[0] += 1
    return True


def spent(case_dir=None):
    """WhoisXML calls this RUN has made through this pivot (disk when available, else process)."""
    p = _ledger_path(case_dir)
    if p and os.path.isfile(p):
        try:
            with open(p, "r", encoding="utf-8") as fh:
                return _ledger_count(fh, run_id())
        except Exception:  # noqa: BLE001
            pass
    return _WHOIS_SPENT[0]


# ------------------------------------------------------------------ reverse sources (tri-state)
# Each returns (total | None | "error…", hosts[], truncated). `truncated` is judged by the source
# against the ROWS it returned (netlas documents, urlscan pages), never against a deduped host list.
def _netlas(ip):
    if not wp_netlas.netlas_configured():
        return None, [], False
    try:
        r = wp_netlas.reverse_ip(ip, max_results=400)
    except Exception as e:  # noqa: BLE001
        return f"error: {e}", [], False
    if not isinstance(r, dict) or "hosts" not in r:
        return (r or {}).get("error") or (r or {}).get("skipped") or "error", [], False
    return r.get("total"), list(r.get("hosts") or []), bool(r.get("truncated"))


def _validin(ip):
    if not wp_validin.validin_configured():
        return None, [], False
    try:
        r = wp_validin.ip_lookup(ip)
    except Exception as e:  # noqa: BLE001
        return f"error: {e}", [], False
    if not isinstance(r, dict):
        return None, [], False
    if r.get("error"):
        return f"error: {r['error']}", [], False
    return r.get("total"), list(r.get("domains") or []), False      # total == len(domains): complete


def _urlscan(ip):
    if not _secret("URLSCAN_API_KEY"):
        return None, [], False
    try:
        r = urlscan_search(f"page.ip:{ip}", limit=100, max_results=400)
    except Exception as e:  # noqa: BLE001
        return f"error: {e}", [], False
    if not isinstance(r, dict):
        return None, [], False
    if r.get("error"):
        return f"error: {r['error']}", [], False
    return r.get("total"), list(r.get("domains") or []), bool(r.get("truncated"))


_SOURCES = (("netlas", _netlas), ("validin", _validin), ("urlscan", _urlscan))


# ------------------------------------------------------------------ verified-row reuse
def _prior_verified(case_dir):
    """apex -> whois row already verified in an earlier round of this case (mo_neighbours.json).
    Errored rows are NOT reused — a transient WHOIS failure must be retried, not frozen."""
    if not case_dir:
        return {}
    p = os.path.join(case_dir, "mo_neighbours.json")
    if not os.path.isfile(p):
        return {}
    try:
        blk = json.load(open(p, encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return {}
    return {str(v.get("apex")).lower(): v.get("whois") for v in (blk.get("verified") or [])
            if isinstance(v, dict) and v.get("apex") and isinstance(v.get("whois"), dict)
            and not v["whois"].get("error")}


_WHOIS_FIELDS = ("registrant_email", "registrant_name", "registrant_org", "registrant_phone",
                 "registrant_country", "registrar", "created", "expires", "name_servers")


def _slim(w):
    """The classification-relevant fields of a whois_current() row — no raw payload."""
    if not isinstance(w, dict):
        return {"error": "no record"}
    if w.get("error"):
        return {"error": str(w["error"])}
    return {k: w.get(k) for k in _WHOIS_FIELDS if w.get(k) is not None}


def _whois_one(apex, case_dir=None):
    if not _try_charge(case_dir, apex):
        return None
    try:
        return _slim(whois_enrich.whois_current(apex, keep_raw=False))
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)}


def _empty(ip, seed, note):
    return {"origin_ip": ip, "seed_apex": seed, "bulk_skipped": False, "fan_out": 0, "sources": {},
            "candidate_total": 0, "sample_apexes": [], "candidates": [], "unverified": [],
            "whois_calls": 0, "whois_cap_hit": False, "note": note}


# ------------------------------------------------------------------ the pivot
def discover(origin_ip, seed_apex, case_dir=None, max_candidates=None, bulk_results=None,
             classified=None, sources=_SOURCES, sibling_wait_s=None):
    """Reverse `origin_ip` across the configured indexes and WHOIS-verify the co-tenant apexes.

    Returns the UNCLASSIFIED block
      {origin_ip, seed_apex, bulk_skipped, fan_out, sources:{name: total|note}, candidate_total,
       sample_apexes[], candidates:[{apex, sources[], whois{}}], unverified[], whois_calls,
       whois_cap_hit, note, memo?}
    memoised per origin in process AND, when `case_dir` (or $WP_CASE_DIR) is known, on disk, with an
    exclusive per-origin lock so eight concurrent collector subprocesses verify an origin ONCE.
    `classified` is the caller's classify_ip() dict for the origin; a CDN/cloud edge is refused."""
    ip = str(origin_ip or "").strip()
    seed = _registrable(str(seed_apex or "").lower()) or str(seed_apex or "").lower()
    case_dir = case_dir or os.environ.get(CASE_DIR_ENV) or None
    max_candidates = MAX_CANDIDATES if max_candidates is None else max_candidates
    bulk_results = BULK_IP_RESULTS if bulk_results is None else bulk_results
    sibling_wait_s = SIBLING_WAIT_S if sibling_wait_s is None else sibling_wait_s
    if not ip:
        return _empty(ip, seed, "no origin IP")
    with _LOCK:
        if ip in _MEMO:
            return json.loads(json.dumps(_MEMO[ip]))
    blk = _cached_block(case_dir, ip)
    if blk is not None:
        blk["memo"] = "case cache"
    elif not _acquire_origin_lock(case_dir, ip):
        blk = _wait_for_sibling(case_dir, ip, sibling_wait_s)
        if blk is not None:
            blk["memo"] = "verified by a sibling host in this run"
        else:
            blk = _empty(ip, seed, "a sibling host in this run is still verifying this origin — "
                                   "classification merges by origin, nothing lost")
            blk["memo"] = "sibling in progress"
            return blk                                   # do not memoise a placeholder
    else:
        try:
            blk = _discover(ip, seed, case_dir, max_candidates, bulk_results, classified or {}, sources)
            _store_block(case_dir, ip, blk)
        finally:
            _release_origin_lock(case_dir, ip)
    with _LOCK:
        _MEMO[ip] = blk
    return json.loads(json.dumps(blk))


def _discover(ip, seed, case_dir, max_candidates, bulk_results, classified, sources):
    out = _empty(ip, seed, "")
    if classified.get("cdn") is True:
        out["note"] = ("%s is a CDN/cloud edge (%s) — its co-tenants are unrelated sites; not reversed"
                       % (ip, classified.get("provider") or "shared edge"))
        return out
    # 1) reverse across every configured index; keep which index saw which apex
    by_apex: dict = {}
    truncated_totals = []
    for name, fn in sources:
        total, hosts, truncated = fn(ip)
        out["sources"][name] = total if total is not None else ("not configured" if not hosts else "ok")
        if truncated and isinstance(total, int):
            truncated_totals.append(total)
        for h in hosts:
            h = str(h or "").strip().lower().rstrip(".")
            if not h or "." not in h:
                continue
            apex = _registrable(h) or h
            by_apex.setdefault(apex, set()).add(name)
    if not by_apex:
        out["note"] = "no reverse-IP source configured or none returned hosts"
        return out
    by_apex.pop(seed, None)                                   # the estate's own apex is not a neighbour
    apexes = sorted(by_apex)
    # 2) BULK GUARD — distinct apexes, backstopped by a TRUNCATED source's total
    fan_out = max([len(apexes)] + truncated_totals)
    out["fan_out"] = fan_out
    out["candidate_total"] = len(apexes)
    out["sample_apexes"] = apexes[:8]
    if fan_out > bulk_results:
        out["bulk_skipped"] = True
        out["note"] = (f"{ip} answers with ~{fan_out} apexes (> {bulk_results}) — bulk hosting / "
                       "parking, not a same-play neighbourhood; sample kept as a cohost lead, no WHOIS spent")
        return out
    if not apexes:
        out["note"] = "only the seed's own apex resolves here"
        return out
    # 3) WHOIS-verify each candidate's OWN registrant (bounded; reuse rows verified in earlier rounds)
    prior = _prior_verified(case_dir)
    todo = apexes[:max_candidates]
    out["unverified"] = apexes[max_candidates:]
    rows, fetch = {}, []
    for a in todo:
        if a in prior:
            rows[a] = prior[a]
        else:
            fetch.append(a)
    if fetch and whois_enrich.whois_configured():
        with concurrent.futures.ThreadPoolExecutor(max_workers=WHOIS_WORKERS) as ex:
            futs = {a: ex.submit(_whois_one, a, case_dir) for a in fetch}
            for a, fu in futs.items():
                try:
                    rows[a] = fu.result()
                except Exception as e:  # noqa: BLE001
                    rows[a] = {"error": str(e)}
    for a in todo:
        w = rows.get(a)
        if w is None:                                         # run cap hit or no key: verify later
            out["whois_cap_hit"] = out["whois_cap_hit"] or whois_enrich.whois_configured()
            out["unverified"].append(a)
            continue
        out["candidates"].append({"apex": a, "sources": sorted(by_apex[a]), "whois": w})
    out["whois_calls"] = sum(1 for a in fetch if rows.get(a) is not None)
    if out["whois_cap_hit"]:
        out["note"] = (f"WhoisXML run cap ({WHOIS_RUN_CAP} per run) reached — {len(out['unverified'])} "
                       "candidate(s) left unverified this run")
    elif not whois_enrich.whois_configured():
        out["note"] = "no WhoisXML key — candidates listed, none verified"
    return out


__all__ = ["discover", "reset_process_state", "whois_calls_made", "spent", "run_id", "MAX_CANDIDATES",
           "WHOIS_RUN_CAP", "MAX_IP_COHOSTS", "BULK_IP_RESULTS", "CACHE_SUBDIR", "RUN_ID_ENV", "CASE_DIR_ENV"]
