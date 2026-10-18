#!/usr/bin/env python3
"""quarry_bridge — hand a case's seed to a Quarry scan platform and wait for the result.

Quarry holds vendor answers this skill would otherwise pay for a second time. This bridge:

  1. decides whether Quarry runs for the case (QUARRY_ENABLED=on|off|ask, overridable per run
     with --quarry / --no-quarry, and remembered per case so a resumed run does not re-ask),
  2. reuses a scan Quarry already finished, or starts one and WAITS for it. A large estate takes
     hours or days; the wait is the point. Transient faults (network, 429, 5xx, a session the
     server forgot after a restart) back off and retry — they never end the wait. Only an auth
     failure or a terminal job status does,
  3. imports the result through the SAME rung-aware path corpus pivots use (kb/ingest_typed.py +
     case_state.add_nodes). Owner rows become edges; everything provider-level is a fact.
     Page-scraped contacts (page.email / page.phone) are facts on the page only — add_nodes keeps
     them out of the node registry propose() pivots on. Collecting is not attributing.

The raw export is kept under cases/<case>/quarry/ (git-ignored with the rest of the case store).
Stdlib only, plus the engine modules it orchestrates. sync() never raises.
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
WP = os.path.join(ROOT, "WebPivot", "tools")
KB_TOOLS = os.path.join(HERE, "kb")
for _p in (HERE, WP, KB_TOOLS):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import case_state as cs                      # noqa: E402 — case dir + co-tenancy caps
import wp_quarry as q                        # noqa: E402 — the MCP client

try:                                         # registrable-apex reducer, shared with the collectors
    from wp_common import _registrable       # noqa: E402
except Exception:                            # noqa: BLE001
    def _registrable(host):
        parts = (host or "").strip(".").lower().split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else (host or "")

try:
    from noise_filters import (              # noqa: E402 — the shared denylist
        is_noise_email, is_noise_phone, is_noise_tracker, is_shared_infra_apex, is_parking_host)
except Exception:                            # noqa: BLE001 — degrade: drop nothing, import still caps
    def is_noise_email(_e):
        return False

    def is_noise_phone(_p, registrant_email=None, registrant_org=None):
        return False

    def is_noise_tracker(_t):
        return False

    def is_shared_infra_apex(_a):
        return False

    def is_parking_host(_h):
        return False

try:
    from selector_types import classify, rung_for  # noqa: E402
except Exception:                            # noqa: BLE001
    def classify(raw, hint=None):
        return "domain" if "." in str(raw) else "string"

    def rung_for(_rc):
        return "kit"

# Quarry wallet subtypes → the coin label kb_key expects. Data, but short and stable.
_COIN = {
    "bitcoin_p2pkh": "btc", "bitcoin_p2sh": "btc", "bitcoin_bech32": "btc",
    "ethereum": "eth", "litecoin_bech32": "ltc", "monero": "xmr", "dogecoin": "doge",
    "bitcoin_cash": "bch", "dash": "dash", "zcash_t": "zec", "zcash_z": "zec",
    "tron": "trx", "cardano": "ada", "polkadot": "dot",
}

_TERMINAL = {"completed", "failed", "cancelled"}
_RESTART_MARK = "dashboard restarted"      # quarry remote-mcp-guide: a restart kills running scans
_ROUTE_PAGE = "quarry.page"
_ROUTE_CONN = "quarry.connected"

_RANK = {"owner": 0, "kit": 1, "neighbour": 2}


def _now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _say(log, msg):
    (log or (lambda *_a, **_k: None))(f"   quarry: {msg}")


# ---------------------------------------------------------------- decision

def _decision_path(case):
    return os.path.join(cs._case_dir(case), "quarry", "decision.json")


def recorded_decision(case):
    """True/False when this case already answered, else None. Never raises."""
    try:
        with open(_decision_path(case), encoding="utf-8") as fh:
            d = json.load(fh)
        return bool(d["enabled"]) if isinstance(d, dict) and "enabled" in d else None
    except (OSError, ValueError):
        return None


def record_decision(case, enabled, how):
    p = _decision_path(case)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump({"enabled": bool(enabled), "decided_by": how, "decided_at": _now()}, fh, indent=2)
    os.replace(tmp, p)


def resolve_decision(case, *, explicit=None, no_quarry=False, tty=None):
    """'on' | 'off' | 'undecided'.

    Precedence: --no-quarry, then --quarry, then the decision already recorded for the case,
    then QUARRY_ENABLED. 'ask' prompts once on a terminal and records the answer; with nobody
    to ask it returns 'undecided' and the driver holds collection until the analyst answers."""
    if no_quarry:
        record_decision(case, False, "flag")
        return "off"
    if explicit:
        record_decision(case, True, "flag")
        return "on"
    recorded = recorded_decision(case)
    if recorded is not None:
        return "on" if recorded else "off"
    mode = q.quarry_mode()
    if mode == "off":
        return "off"
    if mode == "on":
        record_decision(case, True, "env")
        return "on"
    interactive = sys.stdin.isatty() and sys.stdout.isatty() if tty is None else tty
    if interactive and not os.environ.get("INTEL_NO_PROMPT"):
        try:
            ans = input("   quarry: use Quarry for this case? It scans the seed on shared vendor "
                        "accounts and the wait can run for hours or days. [y/N] ")
        except (EOFError, OSError):
            ans = ""
        enabled = ans.strip().lower() in ("y", "yes")
        record_decision(case, enabled, "prompt")
        return "on" if enabled else "off"
    return "undecided"


# ---------------------------------------------------------------- scope posture

def _scope(case):
    """{target_class, no_direct_contact, no_spend} from cases/<case>/scope.json. Missing = empty."""
    try:
        with open(os.path.join(cs._case_dir(case), "scope.json"), encoding="utf-8") as fh:
            d = json.load(fh) or {}
    except (OSError, ValueError):
        d = {}
    c = d.get("constraints") or {}
    return {
        "target_class": str(d.get("target_class") or ""),
        "no_direct_contact": bool(c.get("no_direct_contact")),
        "no_spend": bool(c.get("no_spend")),
    }


def _rung_cap(scope):
    """victim_host: the page's WHOIS/cert/analytics/wallets belong to the VICTIM, so nothing
    Quarry found on the page may come back as an owner link."""
    return "kit" if scope.get("target_class") == "victim_host" else ""


def _quarry_class(scope):
    mapping = q.TARGET_CLASS_MAP or {}
    return mapping.get(scope.get("target_class") or "", "unknown")


# ---------------------------------------------------------------- row building (pure — no network, no KB)

def _apex(host):
    return _registrable((host or "").strip().lower().rstrip("."))


def _skip_host(host, target_apex):
    a = _apex(host)
    if not a or a == target_apex:
        return True
    return is_shared_infra_apex(a) or is_parking_host(a)


def _tracker_rung(value):
    v = str(value or "").strip()
    if not v or is_noise_tracker(v):
        return ""
    up = v.upper()
    if up.startswith("GTM-"):
        return "analytics.gtm"
    if up.startswith("UA-"):
        return "analytics.ga"
    if up.startswith("G-") and len(up) > 4:
        return "analytics.gtag"
    low = v.lower()
    if low.startswith("ca-pub-") or low.startswith("pub-"):
        return "ads.adsense"
    if up.startswith(("AW-", "DC-", "GT-")):
        return "ads.other"
    return "token.other"


def _cap_for(kind):
    if kind in ("cert_sha256", "cert_sha1", "cert_san"):
        return cs.MAX_CERT_APEXES
    if kind == "ip":
        return cs.MAX_IP_COHOSTS
    if kind == "registrant_email":
        return cs.MAX_WHOIS_SIBLINGS
    if kind == "tracking_id":
        return cs.MAX_ARTIFACT_SIBLINGS
    return None


def _downgrade(rung_class, cap):
    """A victim-owned page cannot produce an owner link. cap is 'kit' or ''."""
    if cap != "kit" or not rung_class:
        return rung_class
    return "kit_link" if _RANK.get(rung_for(rung_class), 1) < _RANK["kit"] else rung_class


def _row(type_, value, rung_class, source, evidence=None, coin=""):
    r = {"type": type_, "value": value, "rung_class": rung_class, "source": source}
    if evidence:
        r["evidence"] = evidence
    if coin:
        r["coin"] = coin
    return r


def _exchange_wallet(addr):
    try:
        import pivot_routes
        return bool(pivot_routes._is_exchange_addr(addr))
    except Exception:                        # noqa: BLE001 — unknown beats a wrong owner link
        return False


def build_row_groups(bundle, *, target, rung_cap=""):
    """Quarry's export + connections → typed row groups for ingest_typed.

    Returns (groups, notes). A group is {origin_type, origin_value, route, rows, seed}.
    `seed` marks groups whose domain rows may enter the case's node registry (owner-linked
    peers the loop should chase). Kit/neighbour domain peers are facts only — they stay out of
    the frontier, matching the co-tenancy rails. notes carries what was dropped and why, so a
    shorter import never reads as 'nothing found'."""
    notes = {"dropped_noise": 0, "co_tenancy": [], "leak_records": 0, "secret_findings": 0}
    groups = []
    export = (bundle or {}).get("export") or {}
    content = export.get("content") if isinstance(export.get("content"), dict) else export
    target_apex = _apex(target)

    page_rows = _page_rows(content, notes, rung_cap)
    if page_rows:
        groups.append({"origin_type": "domain", "origin_value": target_apex, "route": _ROUTE_PAGE,
                       "rows": page_rows, "seed": True})

    for g in _connection_groups(bundle.get("connected") or {}, target_apex, notes, rung_cap):
        groups.append(g)
    return groups, notes


def _page_rows(content, notes, rung_cap):
    rows = []
    findings = content.get("findings") or {}
    if not isinstance(findings, dict):
        return rows
    rung_of = q.FINDING_RUNGS or {}

    def add(type_, value, rung_class, evidence=None, coin=""):
        rc = _downgrade(rung_class, rung_cap)
        if rc:
            rows.append(_row(type_, value, rc, "quarry", evidence, coin))

    for f in findings.get("emails") or []:
        v = str((f or {}).get("value") or "").strip().lower()
        if not v or is_noise_email(v):
            notes["dropped_noise"] += 1
            continue
        add("email", v, rung_of.get("emails", "page.email"),
            {"subtype": (f or {}).get("subtype") or ""})
    for f in findings.get("phones") or []:
        v = str((f or {}).get("value") or "").strip()
        if not v or is_noise_phone(v):
            notes["dropped_noise"] += 1
            continue
        add("phone", v, rung_of.get("phones", "page.phone"))
    for f in findings.get("crypto") or []:
        v = str((f or {}).get("value") or "").strip()
        if not v:
            continue
        coin = _COIN.get(str((f or {}).get("subtype") or "").lower(), "")
        rc = "wallet.exchange" if _exchange_wallet(v) else rung_of.get("crypto", "wallet.operator")
        add("wallet", v, rc, coin=coin)
    for f in findings.get("tracking_ids") or []:
        v = str((f or {}).get("value") or "").strip()
        rc = _tracker_rung(v)
        if not rc:
            notes["dropped_noise"] += 1
            continue
        add("string", v, rc)
    for f in findings.get("social") or []:
        sub = str((f or {}).get("subtype") or "").lower()
        v = str((f or {}).get("value") or "").strip().lstrip("@")
        if sub == "telegram" and v:
            add("telegram", v, "telegram.username")
    for f in findings.get("ip_address") or findings.get("ips") or []:
        v = str((f or {}).get("value") or "").strip()
        if v and not cs._is_cdn_ip(v) and not cs._is_social_ip(v):
            add("ip", v, "ip.cotenant")

    whois = content.get("whois") or {}
    seen = set()
    for era in whois.get("whois_history") or []:
        reg = (era or {}).get("registrant") or {}
        email = str(reg.get("email") or "").strip().lower()
        if email and email not in seen and not is_noise_email(email):
            seen.add(email)
            add("email", email, "whois.registrant_email", {"era": (era or {}).get("timestamp") or ""})
        elif email:
            notes["dropped_noise"] += 1
        phone = str(reg.get("phone") or "").strip()
        if phone and phone not in seen and not is_noise_phone(phone, email, reg.get("organization")):
            seen.add(phone)
            add("phone", phone, "whois.registrant_phone", {"era": (era or {}).get("timestamp") or ""})

    notes["secret_findings"] = sum(len(findings.get(k) or []) for k in
                                   ("secrets", "hardcoded_secrets", "git_secrets"))
    leaks = content.get("leaks") or {}
    notes["leak_records"] = _count_leaf_records(leaks)
    return rows


def _count_leaf_records(node):
    """How many leak records Quarry holds — counts only, the values stay in the saved export."""
    if isinstance(node, list):
        return len(node) + sum(_count_leaf_records(x) for x in node if isinstance(x, (dict, list)))
    if isinstance(node, dict):
        return sum(_count_leaf_records(v) for v in node.values())
    return 0


def _connection_groups(connected, target_apex, notes, rung_cap):
    """One group per shared fingerprint, classed by its kind and capped like the frontier guards."""
    peers_of = {}
    for conn in connected.get("connections") or []:
        peer = _apex((conn or {}).get("domain") or "")
        if not peer or _skip_host(peer, target_apex):
            if peer and peer != target_apex:
                notes["dropped_noise"] += 1
            continue
        for shared in (conn or {}).get("shared") or []:
            kind = str((shared or {}).get("kind") or "")
            value = str((shared or {}).get("value") or "").strip()
            if not kind or not value:
                continue
            peers_of.setdefault((kind, value), set()).add(peer)

    groups = []
    rung_of = q.KIND_RUNGS or {}
    for (kind, value), peers in sorted(peers_of.items()):
        if kind == "tracking_id":
            rc = _tracker_rung(value) or "token.other"
        else:
            rc = rung_of.get(kind, "kit_link")
        cap = _cap_for(kind)
        if cap is not None and len(peers) + 1 > cap:
            notes["co_tenancy"].append({"kind": kind, "value": value, "apexes": len(peers) + 1})
            rc = "neighbour_link" if kind == "ip" else "kit_link"
        rc = _downgrade(rc, rung_cap)
        owner = rung_for(rc) == "owner"
        rows = [_row("domain", p, rc, "quarry", {"shared_kind": kind, "shared_value": value})
                for p in sorted(peers)]
        if owner:                        # the target must edge to the same indicator to cluster
            rows.append(_row("domain", target_apex, rc, "quarry",
                             {"shared_kind": kind, "shared_value": value}))
        groups.append({"origin_type": "string", "origin_value": f"{kind}:{value}",
                       "route": _ROUTE_CONN, "rows": rows, "seed": owner})
    return groups


# ---------------------------------------------------------------- import

def _kb():
    sys.path.insert(0, KB_TOOLS)
    import ingest_typed
    from knowledge_base import KB
    root = os.path.join(ROOT, os.environ.get("HARNESS_KB", "knowledge"))
    return ingest_typed, KB(root)


def import_groups(case, groups, *, target=""):
    """Write groups into the KB and register owner-linked domain peers as nodes. Idempotent."""
    out = {"ingested": 0, "nodes_added": 0, "owner_domains": []}
    try:
        ingest_typed, kb = _kb()
    except Exception as e:                   # noqa: BLE001
        out["error"] = f"{type(e).__name__}: {e}"
        return out
    try:
        import api_usage
        api_usage.set_context(case=case, skill="cti-expert")
    except Exception:                        # noqa: BLE001
        pass
    target_apex = _apex(target)
    for g in groups:
        try:
            out["ingested"] += ingest_typed.ingest_rows(
                kb, case, g["origin_type"], g["origin_value"], g["rows"], route=g["route"])
        except Exception:                    # noqa: BLE001 — one bad group must not drop the rest
            continue
        seed_rows = [r for r in g["rows"] if r["type"] != "domain" or g.get("seed")]
        # the target itself is a seed already; re-adding it as a hop-1 node would mis-tier it
        seed_rows = [r for r in seed_rows if not (r["type"] == "domain" and r["value"] == target_apex)]
        try:
            out["nodes_added"] += cs.add_nodes(
                case, seed_rows, origin_type=g["origin_type"], origin_value=g["origin_value"],
                route=g["route"])
        except Exception:                    # noqa: BLE001
            pass
        if g.get("seed"):
            out["owner_domains"] += [r["value"] for r in g["rows"]
                                     if r["type"] == "domain" and r["value"] != target_apex]
    out["owner_domains"] = sorted(set(out["owner_domains"]))
    return out


def seed_frontier(case, domains):
    """Queue owner-linked domains Quarry found so the deterministic loop collects them.

    Appends to the pending queue only — it never sets hop 0, so they stay discoveries rather
    than analyst seeds, and it never creates the hops map on a case that has none (that would
    anchor a previously unanchored case)."""
    doms = [str(d).strip().lower() for d in domains or [] if str(d).strip()]
    doms = [d for d in doms if not cs.never_seed(cs._frontier_apex(d))]
    if not doms:
        return 0
    st = cs.load_state(case)
    have = ({h.lower() for h in st.get("pending", [])}
            | {h.lower() for h in st.get("consumed", [])}
            | {h.lower() for h in st.get("collected", [])})
    added = 0
    for d in doms:
        if d in have:
            continue
        st.setdefault("pending", []).append(d)
        have.add(d)
        added += 1
    if added:
        cs.save_state(case, st)
    return added



# ---------------------------------------------------------------- the wait

def _job_path(case):
    return os.path.join(cs._case_dir(case), "quarry", "job.json")


def _load_job(case):
    try:
        with open(_job_path(case), encoding="utf-8") as fh:
            d = json.load(fh)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_job(case, job):
    p = _job_path(case)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(job, fh, indent=2, ensure_ascii=False)
    os.replace(tmp, p)


def _host_of(target):
    t = target.strip()
    if "://" in t:
        t = urllib.parse.urlsplit(t).hostname or t
    return t.split("/")[0].split(":")[0].strip().lower().rstrip(".")


def _call(session, name, arguments, log):
    """One tool call. Returns (result, err). Prints nothing — the caller decides."""
    result, err = session.call(name, arguments)
    return result, err


def _existing_scan(session, domain, log):
    """The domain's stored overview, or None when Quarry has never scanned it."""
    result, err = _call(session, "quarry_get_domain", {"domain": domain}, log)
    if err:
        return None
    if isinstance(result, dict) and result.get("kind") == "tool":
        return None
    return result if isinstance(result, dict) and result.get("domain") else None


def _submit(session, domain, scope, log):
    """Start a scan. Returns (job_id, status_dict). An already-running scan is joined, not
    duplicated — its job id comes back in the 409 body."""
    args = {"domain": domain, "target_class": _quarry_class(scope)}
    result, err = _call(session, "quarry_scan", args, log)
    if err:
        return None, err
    if not isinstance(result, dict):
        return None, {"error": "empty scan response", "kind": "protocol"}
    code = result.get("error")
    if code in ("ACTIVE_SCAN_IN_PROGRESS", "JOINED_ACTIVE_SCAN"):
        active = result.get("active") or {}
        _say(log, f"scan already running for {domain} — joining job {active.get('job_id')}")
        return active.get("job_id"), None
    if code in ("SELF_DUPLICATE_SCAN", "DUPLICATE_SCAN_EXISTS"):
        return None, {"error": code, "kind": "duplicate", "detail": result.get("existing")}
    if code or result.get("kind") == "tool":
        return None, result if result.get("kind") else {"error": code, "kind": "tool"}
    job = result.get("job") or {}
    q._record("scan", 1, ok=bool(job.get("id")))
    return job.get("id"), None


def _backoff(attempt):
    base = int(q.POLLING.get("backoff_initial_s", 30))
    cap = int(q.POLLING.get("backoff_max_s", 600))
    return min(cap, base * 2 ** min(attempt, 6))


def _wait(session, case, job, *, deadline, log):
    """Block until the job reaches a terminal status. Returns the last status dict or an error.
    Transient faults retry until `deadline` (None = no limit)."""
    poll = int(q.POLLING.get("poll_seconds", 60))
    heartbeat = int(q.POLLING.get("heartbeat_minutes", 15)) * 60
    last_line, last_print, faults = "", 0.0, 0
    while True:
        if deadline is not None and time.monotonic() >= deadline:
            return {"status": "running", "timed_out": True}
        result, err = _call(session, "quarry_scan_status",
                            {"job_id": job["job_id"],
                             "wait_until_complete": bool(q.CONNECTION.get("status_wait", True))},
                            log)
        if err:
            if err.get("kind") == "auth":
                return err
            faults += 1
            delay = _backoff(faults)
            _say(log, f"status check failed ({err.get('error')}) — retrying in {delay}s")
            time.sleep(delay)
            continue
        faults = 0
        status = str((result or {}).get("status") or "")
        lines = (result or {}).get("recent_log_lines") or []
        tail = str(lines[-1]).strip() if lines else ""
        now = time.monotonic()
        if tail != last_line or now - last_print >= heartbeat:
            _say(log, f"job {job['job_id']} {status or 'unknown'}"
                      + (f" — {tail[:160]}" if tail else ""))
            last_line, last_print = tail, now
        job["status"] = status
        job["checked_at"] = _now()
        _save_job(case, job)
        if status in _TERMINAL:
            return result or {"status": status}
        time.sleep(poll)


def _restartable(status):
    text = str((status or {}).get("error") or "").lower()
    return _RESTART_MARK in text


def fetch_results(session, case, domain, log):
    """Pull the finished scan into cases/<case>/quarry/. Export is required; the rest degrade."""
    d = os.path.join(cs._case_dir(case), "quarry")
    os.makedirs(d, exist_ok=True)
    bundle = {}
    export, err = _call(session, "quarry_export",
                        {"domain": domain, "format": "json", "mask_third_party": False}, log)
    if err or not isinstance(export, dict) or "content" not in export:
        return None, err or {"error": "export returned no content", "kind": "tool"}
    _write(os.path.join(d, "export.json"), export)
    bundle["export"] = export
    for name, args, fname in (
        ("quarry_get_domain", {"domain": domain}, "overview.json"),
        ("quarry_js_findings", {"domain": domain}, "js.json"),
    ):
        got, gerr = _call(session, name, args, log)
        if gerr:
            _say(log, f"{name} unavailable ({gerr.get('error')}) — continuing")
            continue
        _write(os.path.join(d, fname), got)
        bundle[fname.split(".")[0]] = got
    bundle["connected"] = _fetch_connections(session, domain, d, log)
    return bundle, None


def _fetch_connections(session, domain, d, log):
    page = max(1, min(200, int(q.FETCH.get("connected_page", 200))))
    cap = int(q.FETCH.get("connected_max", 2000))
    out = {"connections": [], "total": 0}
    offset = 0
    while offset < cap:
        got, err = _call(session, "quarry_connected_scans",
                         {"domain": domain, "limit": page, "offset": offset}, log)
        if err or not isinstance(got, dict):
            _say(log, f"connected scans unavailable ({(err or {}).get('error')}) — continuing")
            break
        out["total"] = got.get("total") or 0
        out["connections"].extend(got.get("connections") or [])
        offset += page
        if offset >= (got.get("total") or 0):
            break
    _write(os.path.join(d, "connected.json"), out)
    return out


def _write(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, ensure_ascii=False, default=str)
    os.replace(tmp, path)


def _import(case, bundle, domain, scope, log):
    groups, notes = build_row_groups(bundle, target=domain, rung_cap=_rung_cap(scope))
    imported = import_groups(case, groups, target=domain)
    imported["notes"] = notes
    _write(os.path.join(cs._case_dir(case), "quarry", "import.json"),
           {"imported_at": _now(), **imported})
    try:
        import wp_quarry_reuse as _qr
        _qr.write_coverage(cs._case_dir(case), bundle, domain)
        os.environ["WP_CASE_DIR"] = cs._case_dir(case)
    except Exception as e:  # noqa: BLE001 — import stands; a missing ledger just means no reuse
        _say(log, f"quarry coverage ledger not written: {e}")
    _say(log, f"imported {imported.get('ingested', 0)} rows, "
              f"{imported.get('nodes_added', 0)} new nodes, "
              f"{len(imported.get('owner_domains') or [])} owner-linked domains")
    if notes["co_tenancy"]:
        _say(log, f"{len(notes['co_tenancy'])} shared fingerprints over the co-tenancy cap — "
                  "kept as leads, not links")
    return imported


def _deadline(wait_minutes):
    """Only an explicit per-call slice (the standalone `quarry` tool / `sync --wait-minutes`) ends a
    wait early; the job stays persisted and the next call resumes it. The `cti` driver passes none,
    so it waits for the scan's terminal status with no time limit."""
    return time.monotonic() + wait_minutes * 60 if wait_minutes else None


def sync(case, target, *, start=False, wait=True, free_only=False, passive=False,
         wait_minutes=None, log=print):
    """Reuse, join or start a Quarry scan for `target` and import the result.

    `start` allows a NEW scan. Without it, only a scan Quarry already has is used. A no-spend
    or no-contact posture also refuses a new scan. `wait_minutes` caps this call; the job
    state is persisted, so the next call resumes the same wait instead of submitting again."""
    if not q.quarry_configured():
        return {"status": "skipped", "reason": "not configured"}
    kind = classify(target)
    if kind != "domain":
        return _lookup(case, target, log)
    domain = _host_of(target)
    scope = _scope(case)
    session = q.Session()

    job = _load_job(case)
    # A failed or cancelled job is the checkpoint. Submitting again spends the shared accounts
    # the hold told the analyst not to spend. Delete cases/<case>/quarry/job.json to scan again.
    if job.get("job_id") and job.get("status") in ("failed", "cancelled"):
        _say(log, f"job {job['job_id']} already {job['status']} — not submitting again")
        return {"status": job["status"], "reason": job.get("error") or job["status"],
                "domain": job.get("domain") or domain, "job_id": job["job_id"]}
    if job.get("job_id") and job.get("status") not in _TERMINAL | {"imported"}:
        _say(log, f"resuming job {job['job_id']} for {job.get('domain') or domain}")
        return _finish(session, case, job, scope, wait, wait_minutes, log)

    existing = _existing_scan(session, domain, log)
    if existing:
        _say(log, f"{domain} already scanned {existing.get('scan_date') or 'earlier'} — reusing")
        bundle, err = fetch_results(session, case, domain, log)
        if err:
            return {"status": "error", "reason": err.get("error"), "domain": domain}
        imported = _import(case, bundle, domain, scope, log)
        return {"status": "reused", "domain": domain,
                "scan_date": existing.get("scan_date"), "imported": imported}

    blocked = _start_blocked(scope, start, free_only, passive)
    if blocked:
        _say(log, blocked)
        return {"status": "skipped", "reason": blocked, "domain": domain}

    _say(log, f"starting a scan of {domain} (posture {_quarry_class(scope)})")
    job_id, err = _submit(session, domain, scope, log)
    if err and err.get("kind") == "duplicate":
        # Quarry holds the scan but this key cannot read it. skipped would let collection
        # spend the same vendors; error holds the run until the scan is readable.
        _say(log, f"Quarry already holds {domain} but this key cannot read it ({err.get('error')})")
        return {"status": "error", "reason": err.get("error"), "domain": domain}
    if err or not job_id:
        return {"status": "error", "reason": (err or {}).get("error") or "no job id",
                "domain": domain}
    job = {"domain": domain, "job_id": job_id, "status": "queued", "submitted_at": _now(),
           "resubmits": 0}
    _save_job(case, job)
    if not wait:
        return {"status": "running", "domain": domain, "job_id": job_id}
    return _finish(session, case, job, scope, True, wait_minutes, log)


def _start_blocked(scope, start, free_only, passive):
    if not start:
        return "no existing scan, and this run is not allowed to start one"
    if passive or scope.get("no_direct_contact"):
        return "no-contact posture — Quarry would crawl the target, so no scan was started"
    if free_only or scope.get("no_spend"):
        return "no-spend posture — a Quarry scan spends the shared vendor accounts, so none was started"
    return ""


def _finish(session, case, job, scope, wait, wait_minutes, log):
    if not wait:
        return {"status": job.get("status") or "running", "domain": job.get("domain"),
                "job_id": job.get("job_id")}
    status = _wait(session, case, job, deadline=_deadline(wait_minutes), log=log)
    if status.get("timed_out"):
        _say(log, f"still {status.get('status')} at the wait cap — rerun resumes job {job['job_id']}")
        return {"status": "running", "domain": job.get("domain"), "job_id": job["job_id"],
                "resumable": True}
    if status.get("kind"):
        return {"status": "error", "reason": status.get("error"), "domain": job.get("domain"),
                "job_id": job.get("job_id")}
    state = str(status.get("status") or "")
    if state == "completed":
        bundle, err = fetch_results(session, case, job["domain"], log)
        if err:
            return {"status": "error", "reason": err.get("error"), "domain": job["domain"],
                    "job_id": job["job_id"]}
        imported = _import(case, bundle, job["domain"], scope, log)
        job["status"] = "imported"
        _save_job(case, job)
        return {"status": "completed", "domain": job["domain"], "job_id": job["job_id"],
                "imported": imported}
    if state == "failed" and _restartable(status) and job.get("resubmits", 0) < int(
            q.POLLING.get("max_resubmits", 1)):
        _say(log, "the server restarted mid-scan — resubmitting once")
        job["resubmits"] = job.get("resubmits", 0) + 1
        new_id, err = _submit(session, job["domain"], scope, log)
        if new_id:
            job.update(job_id=new_id, status="queued")
            _save_job(case, job)
            return _finish(session, case, job, scope, True, wait_minutes, log)
    _say(log, f"scan {state}: {status.get('error') or 'no detail'}")
    job["status"] = state or "failed"
    _save_job(case, job)
    return {"status": state or "failed", "reason": status.get("error"),
            "domain": job.get("domain"), "job_id": job.get("job_id")}


def _lookup(case, target, log):
    """A non-domain selector cannot be scanned. Report which Quarry scans already contain it."""
    session = q.Session()
    result, err = _call(session, "quarry_search_ioc", {"query": target}, log)
    if err:
        return {"status": "error", "reason": err.get("error")}
    d = os.path.join(cs._case_dir(case), "quarry")
    os.makedirs(d, exist_ok=True)
    _write(os.path.join(d, "lookup.json"), result)
    _say(log, f"{target} is not a domain — searched Quarry's corpus, no scan started")
    return {"status": "lookup", "target": target, "saved": "quarry/lookup.json"}


def stage(case, target, *, explicit=False, no_quarry=False, free_only=False, passive=False,
          log=print):
    """The driver's entry: resolve the decision, then sync() if Quarry is on for this case.
    No wait limit: it returns only on a terminal job status, an auth failure or a refusal."""
    decision = resolve_decision(case, explicit=explicit, no_quarry=no_quarry)
    if decision == "undecided":
        _say(log, "QUARRY_ENABLED=ask and nobody answered — skipping "
                  "(pass --quarry or --no-quarry)")
        return {"status": "undecided"}
    if decision == "off":
        return {"status": "off"}
    _say(log, "enabled for this case — waiting for Quarry before collection continues")
    return sync(case, target, start=True, wait=True, free_only=free_only, passive=passive,
                wait_minutes=None, log=log)


# ---------------------------------------------------------------- CLI

def _main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description="Quarry scan bridge: reuse or run a scan, wait, import")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("sync", "status", "lookup"):
        p = sub.add_parser(name)
        p.add_argument("--case", required=True)
        p.add_argument("--target", required=True)
    sub.choices["sync"].add_argument("--quarry-scan", action="store_true",
                                     help="allow a new scan (spends shared vendor accounts)")
    sub.choices["sync"].add_argument("--no-wait", action="store_true")
    sub.choices["sync"].add_argument("--free-only", action="store_true")
    sub.choices["sync"].add_argument("--passive", action="store_true")
    sub.choices["sync"].add_argument("--wait-minutes", type=int, default=None)
    a = ap.parse_args(argv)
    if a.cmd == "sync":
        out = sync(a.case, a.target, start=a.quarry_scan, wait=not a.no_wait, free_only=a.free_only,
                   passive=a.passive, wait_minutes=a.wait_minutes)
    elif a.cmd == "lookup":
        out = _lookup(a.case, a.target, print)
    else:
        out = _load_job(a.case) or {"status": "none"}
    print(json.dumps(out, ensure_ascii=False, default=str))
    return 0 if out.get("status") not in ("error", "failed") else 1


if __name__ == "__main__":
    sys.exit(_main())
