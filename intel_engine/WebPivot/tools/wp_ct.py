#!/usr/bin/env python3
"""wp_ct — the ONE certificate-transparency client.

Every CT lookup in the skill goes through here (enrich_live's `ct_search`, cert_pivot,
subdomain_enum, ct_monitor, cert_overlap, fallback_probe, the impersonation keyword hunt), so a
crt.sh outage is handled — and REPORTED — the same way everywhere.

STATUS CONTRACT (never conflated)
---------------------------------
crt.sh:   ok        rows came back (web or PostgreSQL)
          empty     HTTP 200 with `[]` / zero PostgreSQL rows — authoritative "none on record";
                    never retried away
          degraded  web retries AND the PostgreSQL fallback failed (or a sub-query failed and
                    nothing filled it) — the history is INCOMPLETE, not "no certificates"
others:   complete | capped | partial | failed | skipped-quota | skipped-no-key | skipped-free-only

A merge where one sub-query failed is never `ok`. Every source's status, observation window and
row count is returned under `ct_status`, with one `completeness_line` for the whole lookup.

FALLBACK CHAIN (strict: backups run only when crt.sh is degraded or empty; keyless first)
----------------------------------------------------------------------------------------
crt.sh web (q= → identity=, retry + backoff inside a wall-clock budget, per-process breaker)
  → crt.sh PostgreSQL (optional psycopg)            [crt.sh still one source]
  → Shodan CTL + CertSpotter, merged                 [keyless, ~1 year]
  + CertKit, CertIndex when their keys are set      [~1 year; CertIndex skipped, never waited on,
                                                     when its hourly quota is spent]
  + Netlas, ONLY when crt.sh failed (not empty)     [metered, multi-year sparse; name-filtered]
  → Censys certificate search, ONLY when every source above left no certificate [metered, sample]
  → crt.name + agniops                               [AGGREGATED names only, last, never complete]
Metered sources (Netlas, Censys) answer `skipped-free-only` under --free-only; a missing key is
`skipped-no-key` — both visible in `ct_status`, so the unqueried evidence class is named. A final
answer (complete/capped) from a keyed source is memoised per process; `partial` is asked again.

DEDUP
-----
Same certificate when any identity key matches: crt.sh id; sha256; x509 serial (hex, lowercased,
leading zeros stripped — alone only when >= 16 hex chars, otherwise together with the issuer CN);
or the precert/final TWIN key (issuer CN, not_before and not_after to the second, sorted-SAN hash)
— only for rows with full timestamps, never for day-only dates (same-day ECC + RSA twins for one
SAN set would merge). On a collision the richer row wins (full timestamps + sha256 beat day-only
serial) and the others only fill its gaps. A day-only row (CertKit) that shares no key with a
sha256-only row is attached to it only when the (issuer CN, validity day, SAN set) match is unique
both ways; two day-only rows never merge.

Stdlib-only at module level; psycopg is imported lazily and its absence is a status note.
"""
import concurrent.futures
import datetime
import hashlib
import json
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wp_common import DEFAULT_UA, _secret  # noqa: E402 — loads the skill .env, installs cti-proxy
from wp_refs import ref_path, load_ref  # noqa: E402

__all__ = ["ct_search", "crtsh_fetch", "crtsh_keyword", "shodan_ctl_fetch", "certspotter_fetch",
           "aggregated_fetch", "dedup_certs", "completeness", "capability_entry", "normalize_serial",
           "WINDOWS"]


def capability_entry(ct):
    """A ct_search result → the `meta.capability.ct` block: completeness, each source's status and
    window, and which CT sources went UNQUERIED (skipped) or FAILED — so /capabilities and the
    report can name the missing evidence class instead of implying 'no certificates'."""
    st = (ct or {}).get("ct_status") or {}
    if not st:
        return None
    return {"completeness": ct.get("completeness"), "completeness_line": ct.get("completeness_line"),
            "sources": {s: {"status": v.get("status"), "window": v.get("window"), "n": v.get("n", 0)}
                        for s, v in st.items()},
            "unqueried": sorted(s for s, v in st.items() if str(v.get("status")).startswith("skipped")),
            "failed": sorted(s for s, v in st.items() if v.get("status") in ("failed", "degraded"))}


# RULE 3 — conservative minimum fallback; the real values live in references/ct_sources.json.
_CT_FALLBACK = {
    "windows": {"crt.sh": "full CT history"},
    "crtsh": {"web_budget_seconds": 60, "attempt_timeout_seconds": 30, "backoff_step_seconds": 3,
              "backoff_cap_seconds": 30, "breaker_cooldown_seconds": 300, "pg_host": "crt.sh",
              "pg_port": 5432, "pg_database": "certwatch", "pg_user": "guest",
              "pg_connect_timeout_seconds": 20, "pg_budget_seconds": 120, "pg_row_limit": 10000},
    "backups": {"request_timeout_seconds": 30, "certspotter_max_pages": 1},
    "aggregated": {"timeout_seconds": 25, "max_names": 200},
    "netlas": {"download_size": 10000, "hard_limit_seconds": 600},
    "censys": {"max_pages": 1, "page_size": 100},
    "listing": {"max_certs": 40, "max_subdomains": 80},
}
_CT_REF = load_ref(ref_path(__file__, "ct_sources.json"), _CT_FALLBACK)
WINDOWS = _CT_REF["windows"]
CRTSH = _CT_REF["crtsh"]
BACKUPS = _CT_REF["backups"]
AGGREGATED = _CT_REF["aggregated"]
NETLAS = _CT_REF["netlas"]
CENSYS = _CT_REF["censys"]
LISTING = _CT_REF["listing"]

CRTSH_STATUSES = ("ok", "empty", "degraded")
SOURCE_STATUSES = ("complete", "capped", "partial", "failed", "skipped-quota", "skipped-no-key",
                   "skipped-free-only")
_ANSWERED = ("complete", "capped", "partial")

_sleep = time.sleep          # module seams: tests swap both for a fake clock, so a backoff walk
_now = time.monotonic       # is deterministic and costs no wall time
_BREAKER = {"web_down_until": 0.0}
_BREAKER_LOCK = threading.Lock()


# ------------------------------------------------------------------ transport
def _urlopen():
    """urlopen WITHOUT the process-wide CALL_TIMEOUT floor wp_common installs: CT budgets are
    explicit wall-clock limits from ct_sources.json, and a floored per-attempt timeout would let
    one hung crt.sh request eat the whole run. A test stub (no `_cti_orig`) is used as-is."""
    fn = urllib.request.urlopen
    return getattr(fn, "_cti_orig", fn)


def _http(url, timeout, headers=None):
    """GET → decoded body. Raises on any transport/HTTP error (callers classify it)."""
    req = urllib.request.Request(url, headers={"User-Agent": DEFAULT_UA,
                                               "Accept": "application/json", **(headers or {})})
    with _urlopen()(req, timeout=max(1.0, float(timeout))) as r:
        return r.read().decode("utf-8", "replace")


def _with_deadline(fn, seconds):
    """Run fn() under a HARD wall-clock limit enforced around the whole call (not per socket
    read). Returns (result, None) or (None, error). The worker is a daemon thread: on timeout it
    is abandoned, never joined, so the caller moves on at the deadline."""
    box = {}

    def _run():
        try:
            box["v"] = fn()
        except Exception as e:  # noqa: BLE001
            box["e"] = f"{type(e).__name__}: {e}"

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    t.join(max(0.0, float(seconds)))
    if t.is_alive():
        return None, f"timed out after {int(seconds)}s"
    if "e" in box:
        return None, box["e"]
    return box.get("v"), None


def _err(e):
    if isinstance(e, urllib.error.HTTPError):
        return f"HTTP {e.code}"
    return f"{type(e).__name__}: {e}"[:200]


# ------------------------------------------------------------------ normalisation
_DN_CN = re.compile(r"(?:^|[,/]\s*)CN\s*=\s*([^,/]+)", re.I)


def _issuer_cn(issuer):
    """Issuer CN from a DN ('C=US, O=X, CN=R11') or a bare CN — the cross-source issuer key."""
    s = str(issuer or "").strip()
    if not s:
        return ""
    m = _DN_CN.search(s)
    return (m.group(1) if m else s).strip().lower()


def normalize_serial(serial):
    """x509 serial → lowercase hex, separators and leading zeros stripped ('' when absent)."""
    digits = re.sub(r"[^0-9a-fA-F]", "", str(serial or "")).lower()
    return digits.lstrip("0") or ("0" if digits else "")


def _norm_time(v):
    """Epoch / ISO / 'YYYY-MM-DD HH:MM:SS' / day-only → (iso, precision) or (None, None)."""
    if v is None or v == "":
        return None, None
    if isinstance(v, datetime.datetime):
        return v.replace(tzinfo=None).strftime("%Y-%m-%dT%H:%M:%S"), "second"
    if isinstance(v, (int, float)) or (isinstance(v, str) and v.strip().isdigit()):
        try:
            return (datetime.datetime.fromtimestamp(int(v), datetime.timezone.utc)
                    .strftime("%Y-%m-%dT%H:%M:%S")), "second"
        except (OverflowError, OSError, ValueError):
            return None, None
    s = str(v).strip().replace(" ", "T").rstrip("Z")
    s = re.sub(r"[+-]\d\d:?\d\d$", "", s) if "T" in s else s
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", s):
        return s, "day"
    m = re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", s)
    if m:
        return m.group(1), "second"
    return None, None


def _clean_names(names):
    out = []
    for n in names or []:
        for part in re.split(r"[\n;,]", str(n)):
            p = part.strip().lower().rstrip(".")
            if p and "@" not in p and " " not in p and p not in out:
                out.append(p)
    return out


def _cert(source, *, cid=None, serial=None, sha256=None, issuer=None, common_name=None,
          names=(), not_before=None, not_after=None, crtsh_id=None):
    """One certificate row in the shared shape every source is normalised to."""
    nb, p1 = _norm_time(not_before)
    na, p2 = _norm_time(not_after)
    precision = "day" if "day" in (p1, p2) else ("second" if nb else None)
    nm = _clean_names(list(names) + ([common_name] if common_name else []))
    sha = re.sub(r"[^0-9a-f]", "", str(sha256 or "").lower()) or None
    ser = normalize_serial(serial) or None
    return {
        "id": str(cid) if cid not in (None, "") else (sha or ser),
        "sources": [source],
        "crtsh_id": str(crtsh_id) if crtsh_id not in (None, "") else None,
        "serial": ser,
        "sha256": sha,
        "issuer": issuer or None,
        "issuer_cn": _issuer_cn(issuer) or None,
        "common_name": (str(common_name).strip().lower() or None) if common_name else None,
        "names": nm,
        "not_before": nb,
        "not_after": na,
        "date_precision": precision,
    }


# ------------------------------------------------------------------ dedup
def _keys(c):
    keys = []
    if c.get("crtsh_id"):
        keys.append(("crtsh", c["crtsh_id"]))
    if c.get("sha256"):
        keys.append(("sha256", c["sha256"]))
    ser = c.get("serial")
    if ser:
        if len(ser) >= 16:
            keys.append(("serial", ser))
        elif c.get("issuer_cn"):
            keys.append(("serial", c["issuer_cn"], ser))
    if (c.get("date_precision") == "second" and c.get("not_before") and c.get("not_after")
            and c.get("names")):
        san = hashlib.sha1("\n".join(sorted(set(c["names"]))).encode()).hexdigest()
        keys.append(("twin", c.get("issuer_cn") or "", c["not_before"], c["not_after"], san))
    return keys


def _richness(c):
    return (c.get("date_precision") == "second", bool(c.get("sha256")), bool(c.get("serial")),
            bool(c.get("not_after")), bool(c.get("issuer")), len(c.get("names") or []))


def _confidence(c):
    """§6: HIGH for crt.sh rows and identity matches across 2+ sources; MEDIUM a single backup."""
    if "crt.sh" in c["sources"] or len(c["sources"]) >= 2:
        return "HIGH"
    return "MEDIUM"


def _day_key(c):
    if not (c.get("not_before") and c.get("not_after") and c.get("names") and c.get("issuer_cn")):
        return None
    return (c["issuer_cn"], c["not_before"][:10], c["not_after"][:10],
            frozenset(n.lower() for n in c["names"]))


def _attach_day_only(rows, find, parent):
    """A day-only row (CertKit: serial, no sha256) shares no identity key with a sha256-only row
    (Shodan CTL / CertSpotter / CertIndex), so the same certificate would count twice. Attach a
    day-only GROUP to a full-timestamp group only when the match is unique both ways on (issuer CN,
    validity day, SAN set): exactly one full-timestamp group and exactly one day-only group carry the
    key. Same-day ECC + RSA twins differ in issuer CN; any remaining ambiguity leaves the rows apart,
    and two day-only rows never merge (not even through a shared target)."""
    timed = {find(i) for i, c in enumerate(rows) if c.get("date_precision") == "second"}
    full, day = {}, {}
    for i, c in enumerate(rows):
        k = _day_key(c)
        if k is not None:
            r = find(i)
            (full if r in timed else day).setdefault(k, set()).add(r)
    for k, roots in day.items():
        cands = full.get(k, set())
        if len(roots) == 1 and len(cands) == 1:
            parent[next(iter(roots))] = next(iter(cands))


def dedup_certs(rows):
    """Union rows that are the same certificate (see module docstring) → merged list, newest
    first. Each merged row lists every source that saw it and carries a confidence grade."""
    parent = list(range(len(rows)))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    owner = {}
    for i, c in enumerate(rows):
        for k in _keys(c):
            if k in owner:
                a, b = find(i), find(owner[k])
                if a != b:
                    parent[a] = b
            else:
                owner[k] = i
    _attach_day_only(rows, find, parent)
    groups = {}
    for i in range(len(rows)):
        groups.setdefault(find(i), []).append(rows[i])
    out = []
    for members in groups.values():
        members = sorted(members, key=_richness, reverse=True)
        base = dict(members[0])
        base["sources"] = []
        names = list(base.get("names") or [])
        for m in members:
            for s in m["sources"]:
                if s not in base["sources"]:
                    base["sources"].append(s)
            for f in ("crtsh_id", "serial", "sha256", "issuer", "issuer_cn", "common_name",
                      "not_before", "not_after"):
                if not base.get(f) and m.get(f):
                    base[f] = m[f]
            names += [n for n in m.get("names") or [] if n not in names]
        base["names"] = names
        if base.get("crtsh_id"):
            base["id"] = base["crtsh_id"]
        base["confidence"] = _confidence(base)
        out.append(base)
    out.sort(key=lambda c: c.get("not_before") or "", reverse=True)
    return out


# ------------------------------------------------------------------ crt.sh
def _parse_crtsh_body(body):
    body = (body or "").strip()
    if not body:
        raise ValueError("empty body")
    try:
        data = json.loads(body)
    except ValueError:
        if body.startswith("{"):   # crt.sh occasionally concatenates objects
            data = json.loads("[" + body.replace("}\n{", "},{").replace("}{", "},{") + "]")
        else:
            raise ValueError("non-JSON body (front end error page)")
    if not isinstance(data, list):
        raise ValueError("unexpected JSON shape")
    return data


def _breaker_open():
    with _BREAKER_LOCK:
        return _now() < _BREAKER["web_down_until"]


def _trip_breaker():
    with _BREAKER_LOCK:
        _BREAKER["web_down_until"] = _now() + float(CRTSH["breaker_cooldown_seconds"])


def _crtsh_web(value, budget=None):
    """One crt.sh value over the web front end: q= then identity= each round, backoff between
    rounds, all inside `budget` wall-clock seconds. → (rows|None, error, attempts)."""
    deadline = _now() + float(budget if budget is not None else CRTSH["web_budget_seconds"])
    step, cap = float(CRTSH["backoff_step_seconds"]), float(CRTSH["backoff_cap_seconds"])
    attempts, last, rnd = 0, None, 0
    while _now() < deadline:
        rnd += 1
        for param in ("q", "identity"):
            remaining = deadline - _now()
            if remaining <= 0:
                break
            attempts += 1
            url = "https://crt.sh/?" + urllib.parse.urlencode({param: value, "output": "json"})
            try:
                return _parse_crtsh_body(_http(url, min(float(CRTSH["attempt_timeout_seconds"]),
                                                        remaining))), None, attempts
            except Exception as e:  # noqa: BLE001 — every crt.sh failure is transient here
                last = _err(e)
        nap = min(step * rnd, cap, deadline - _now())
        if nap <= 0:
            break
        _sleep(nap)
    return None, last or "web budget exhausted", attempts


_PG_SQL = """
WITH ci AS (
  SELECT min(sub.certificate_id) AS id, min(sub.issuer_ca_id) AS issuer_ca_id,
         array_agg(DISTINCT sub.name_value) AS name_values,
         x509_commonName(sub.certificate) AS common_name,
         x509_notBefore(sub.certificate) AS not_before,
         x509_notAfter(sub.certificate) AS not_after,
         encode(x509_serialNumber(sub.certificate), 'hex') AS serial_number
  FROM (SELECT * FROM certificate_and_identities cai
        WHERE plainto_tsquery('certwatch', %(d)s) @@ identities(cai.certificate)
          AND (cai.name_value ILIKE ('%%.' || %(d)s) OR lower(cai.name_value) = lower(%(d)s))
        LIMIT 10000) sub
  GROUP BY sub.certificate)
SELECT ci.id, ci.common_name, array_to_string(ci.name_values, chr(10)) AS name_value,
       ci.not_before, ci.not_after, ci.serial_number, ca.name AS issuer_name
FROM ci LEFT JOIN ca ON ca.id = ci.issuer_ca_id
ORDER BY ci.not_before DESC LIMIT %(lim)s
"""


def _crtsh_pg(domain):
    """crt.sh's public PostgreSQL (guest, no password) — same data when the web front end is
    down. → (rows|None, error). Skips with a note when psycopg is not installed."""
    try:
        import psycopg  # noqa: PLC0415 — optional dependency
    except ImportError:
        return None, "PostgreSQL fallback skipped: psycopg not installed (uv pip install 'psycopg[binary]')"
    limit = int(CRTSH["pg_row_limit"])

    def run():
        with psycopg.connect(host=CRTSH["pg_host"], port=int(CRTSH["pg_port"]),
                             dbname=CRTSH["pg_database"], user=CRTSH["pg_user"],
                             connect_timeout=int(CRTSH["pg_connect_timeout_seconds"]),
                             autocommit=True) as conn:
            cur = conn.execute(_PG_SQL, {"d": domain, "lim": limit})
            cols = [d.name for d in cur.description]
            return [dict(zip(cols, r)) for r in cur.fetchall()]

    return _with_deadline(run, CRTSH["pg_budget_seconds"])


def _crtsh_rows_to_certs(rows):
    return [_cert("crt.sh", cid=r.get("id"), crtsh_id=r.get("id"), serial=r.get("serial_number"),
                  issuer=r.get("issuer_name"), common_name=r.get("common_name"),
                  names=str(r.get("name_value") or "").splitlines(),
                  not_before=r.get("not_before"), not_after=r.get("not_after"))
            for r in rows or [] if isinstance(r, dict)]


def crtsh_fetch(domain):
    """crt.sh for `domain` and its subdomains: the `%.d` and apex values over the web (concurrent),
    then — if either failed — one PostgreSQL query that covers both. Never raises.

    → {'source':'crt.sh','status':ok|empty|degraded,'via','rows','n','capped','attempts','errors','note'}"""
    t0 = time.monotonic()
    values = [f"%.{domain}", domain]
    web, errors, attempts = {}, [], 0
    web_tried = not _breaker_open()
    if not web_tried:
        errors.append("web skipped: crt.sh breaker open (failed earlier this run)")
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
            futs = {v: ex.submit(_crtsh_web, v) for v in values}
            for v, f in futs.items():
                rows, err, n = f.result()
                attempts += n
                web[v] = rows
                if err:
                    errors.append(f"web {v}: {err}")
    failed = [v for v in values if web.get(v) is None]
    raw = [r for v in values for r in (web.get(v) or [])]
    res = {"source": "crt.sh", "window": WINDOWS.get("crt.sh"), "attempts": attempts,
           "errors": errors, "capped": False}
    if not failed:
        certs = dedup_certs(_crtsh_rows_to_certs(raw))
        res.update(status="ok" if certs else "empty", via="web", rows=certs, n=len(certs))
        res["elapsed_s"] = round(time.monotonic() - t0, 1)
        return res
    if web_tried:
        _trip_breaker()
    pg_rows, pg_err = _crtsh_pg(domain)
    if pg_rows is not None:
        certs = dedup_certs(_crtsh_rows_to_certs(raw + pg_rows))
        res.update(status="ok" if certs else "empty", via="pg" if not raw else "web+pg",
                   rows=certs, n=len(certs), capped=len(pg_rows) >= int(CRTSH["pg_row_limit"]))
    else:
        errors.append(pg_err)
        certs = dedup_certs(_crtsh_rows_to_certs(raw))
        res.update(status="degraded", via="web" if raw else None, rows=certs, n=len(certs))
        if raw:
            res["note"] = (f"partial: {', '.join(failed)} failed — {len(certs)} certificate(s) from "
                           "the sub-query that answered")
    res["elapsed_s"] = round(time.monotonic() - t0, 1)
    return res


def crtsh_keyword(pattern):
    """crt.sh LIKE search for a brand keyword ('%label%') — web only: the PostgreSQL query and
    every backup are domain-scoped. → same shape as crtsh_fetch (status ok|empty|degraded)."""
    t0 = time.monotonic()
    if _breaker_open():
        return {"source": "crt.sh", "status": "degraded", "rows": [], "raw_rows": [], "n": 0,
                "window": WINDOWS.get("crt.sh"), "attempts": 0,
                "errors": ["web skipped: crt.sh breaker open (failed earlier this run)"]}
    rows, err, attempts = _crtsh_web(pattern)
    res = {"source": "crt.sh", "window": WINDOWS.get("crt.sh"), "attempts": attempts,
           "errors": [err] if err else [], "via": "web"}
    if rows is None:
        _trip_breaker()
        res.update(status="degraded", rows=[], raw_rows=[], n=0)
    else:
        certs = dedup_certs(_crtsh_rows_to_certs(rows))
        res.update(status="ok" if certs else "empty", rows=certs, raw_rows=rows, n=len(certs))
    res["elapsed_s"] = round(time.monotonic() - t0, 1)
    return res


# ------------------------------------------------------------------ keyless backups
def shodan_ctl_fetch(domain):
    """Shodan's keyless CTL mirror: /hostnames (flat names) + the cert objects (sha256 `hash`,
    epoch validity, san_dns_names). Precert and final are both listed — the twin key merges them.
    → {'source':'shodan-ctl','status':complete|partial|failed,'rows','hostnames','n'}"""
    base = f"https://ctl.shodan.io/api/v1/domain/{urllib.parse.quote(domain)}"
    to = float(BACKUPS["request_timeout_seconds"])
    out = {"source": "shodan-ctl", "window": WINDOWS.get("shodan-ctl"), "rows": [],
           "hostnames": [], "errors": []}
    ok = 0
    try:
        data = json.loads(_http(base + "/hostnames", to))
        out["hostnames"] = _clean_names(data if isinstance(data, list) else [])
        ok += 1
    except Exception as e:  # noqa: BLE001
        out["errors"].append(f"hostnames: {_err(e)}")
    try:
        data = json.loads(_http(base, to))
        out["rows"] = [_cert("shodan-ctl", sha256=r.get("hash"), issuer=r.get("issuer_cn"),
                             common_name=r.get("subject_cn"), names=r.get("san_dns_names") or [],
                             not_before=r.get("not_before"), not_after=r.get("not_after"))
                       for r in (data if isinstance(data, list) else []) if isinstance(r, dict)]
        ok += 1
    except Exception as e:  # noqa: BLE001
        out["errors"].append(f"certificates: {_err(e)}")
    out["status"] = {2: "complete", 1: "partial", 0: "failed"}[ok]
    out["n"] = len(dedup_certs(out["rows"]))
    return out


def certspotter_fetch(domain):
    """CertSpotter /v1/issuances with include_subdomains, walked with after=<id>. Optional
    CERTSPOTTER_API_KEY (Bearer) raises the rate limit; keyless works. `id` is CertSpotter's own
    issuance id, NOT an x509 serial — identity is cert_sha256.
    → {'source':'certspotter','status':complete|capped|partial|failed|skipped-quota,'rows','n'}"""
    key = _secret("CERTSPOTTER_API_KEY")
    hdr = {"Authorization": f"Bearer {key}"} if key else None
    base = ("https://api.certspotter.com/v1/issuances?"
            + urllib.parse.urlencode([("domain", domain), ("include_subdomains", "true"),
                                      ("expand", "dns_names"), ("expand", "issuer")]))
    to = float(BACKUPS["request_timeout_seconds"])
    out = {"source": "certspotter", "window": WINDOWS.get("certspotter"), "rows": [], "errors": []}
    after, pages, status = None, 0, None
    while pages < int(BACKUPS["certspotter_max_pages"]):
        url = base + (f"&after={urllib.parse.quote(str(after))}" if after else "")
        try:
            data = json.loads(_http(url, to, headers=hdr))
        except Exception as e:  # noqa: BLE001
            out["errors"].append(f"page {pages + 1}: {_err(e)}")
            quota = isinstance(e, urllib.error.HTTPError) and e.code == 429
            status = ("skipped-quota" if quota else "failed") if pages == 0 else "partial"
            break
        pages += 1
        if not isinstance(data, list) or not data:
            status = "complete"
            break
        for r in data:
            if isinstance(r, dict):
                out["rows"].append(_cert(
                    "certspotter", sha256=r.get("cert_sha256"),
                    issuer=(r.get("issuer") or {}).get("name"), names=r.get("dns_names") or [],
                    not_before=r.get("not_before"), not_after=r.get("not_after")))
        after = data[-1].get("id") if isinstance(data[-1], dict) else None
        if not after:
            status = "complete"
            break
    out["status"] = status or "capped"
    out["pages"] = pages
    out["n"] = len(dedup_certs(out["rows"]))
    return out


# ------------------------------------------------------------------ aggregated (names only)
def _hostlist(domain, source, url):
    try:
        body = _http(url, float(AGGREGATED["timeout_seconds"])).strip()
    except Exception as e:  # noqa: BLE001
        return {"source": source, "status": "failed", "names": [], "errors": [_err(e)]}
    if not body or body[0] == "<":            # empty or an HTML error page, not a host list
        return {"source": source, "status": "failed", "names": [],
                "errors": [body[:120] or "empty response"]}
    dom, names = domain.lower(), []
    for line in body.splitlines():
        n = line.strip().lower().lstrip(".")
        bare = n.lstrip("*.")
        if not n or " " in n or "@" in n or (bare != dom and not bare.endswith("." + dom)):
            continue
        if n not in names:
            names.append(n)
    return {"source": source, "status": "complete", "names": names, "errors": []}


def aggregated_fetch(domain):
    """crt.name + agniops — keyless AGGREGATED indexes (CT unioned with crawl/zone/feeds). A hit is
    NOT CT-log evidence and the query discloses the apex to a third party, so ct_search asks them
    last and keeps their names apart. → [source result, source result]"""
    q = urllib.parse.urlencode
    jobs = (("crt.name(aggregated)", "https://crt.name/v1/search?" + q({"apex": domain})),
            ("agniops(aggregated)", "https://app.agniops.in/v1/search?" + q({"domain": domain})))
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
        res = [f.result() for f in [ex.submit(_hostlist, domain, s, u) for s, u in jobs]]
    for r in res:
        r["window"] = WINDOWS.get(r["source"])
        r["n"] = len(r["names"])
    return res


# ------------------------------------------------------------------ keyed / metered backups
def _in_scope(names, domain):
    """Only `domain` and its subdomains: the keyed indexes token-match, so look-alikes ride in."""
    return [n for n in names if n.lstrip("*.") == domain or n.lstrip("*.").endswith("." + domain)]


def _skip(source, status, note=None):
    r = {"source": source, "status": status, "window": WINDOWS.get(source), "rows": [], "n": 0,
         "errors": []}
    if note:
        r["note"] = note
    return r


def _hex_serial(dec):
    """Netlas reports the x509 serial in DECIMAL → hex for the shared serial key."""
    try:
        return format(int(str(dec)), "x")
    except (TypeError, ValueError):
        return None


_NETLAS_FIELDS = ["certificate.names", "certificate.serial_number", "certificate.fingerprint_sha256",
                  "certificate.validity", "certificate.issuer.common_name",
                  "certificate.subject.common_name"]


def netlas_fetch(domain):
    """Netlas certificates index (multi-year, sparse). count + one download under a HARD wall-clock
    limit around both. A download shorter than the count is `partial`; one that hits download_size
    is `capped`. Look-alike documents (token matching) are dropped by the name filter."""
    import wp_netlas  # noqa: PLC0415
    if not wp_netlas.netlas_configured():
        return _skip("netlas", "skipped-no-key")
    q = f"certificate.names:{domain}"
    size = int(NETLAS["download_size"])

    def run():
        cnt = wp_netlas.count("certs", q)
        req = urllib.request.Request(
            wp_netlas.BASE + "/api/certs/download/", method="POST",
            data=json.dumps({"q": q, "fields": _NETLAS_FIELDS, "source_type": "include",
                             "size": size}).encode(),
            headers={"Authorization": "Bearer " + wp_netlas.netlas_key(), "User-Agent": DEFAULT_UA,
                     "Content-Type": "application/json", "Accept": "application/json"})
        with _urlopen()(req, timeout=float(NETLAS["hard_limit_seconds"])) as r:
            docs = json.loads(r.read().decode("utf-8", "replace") or "[]")
        return cnt, docs if isinstance(docs, list) else []

    res, err = _with_deadline(run, NETLAS["hard_limit_seconds"])
    if err:
        wp_netlas._record("certs_download", q, 0, ok=False)
        r = _skip("netlas", "failed")
        r["errors"].append(err)
        return r
    cnt, docs = res
    wp_netlas._record("certs_download", q, len(docs))
    rows, lookalikes = [], 0
    for d in docs:
        c = ((d or {}).get("data") or d or {}).get("certificate") or {}
        names = _in_scope(_clean_names(c.get("names") or []), domain)
        if not names:
            lookalikes += 1
            continue
        val, iss, subj = c.get("validity") or {}, c.get("issuer") or {}, c.get("subject") or {}
        first = (lambda v: v[0] if isinstance(v, list) and v else v)
        rows.append(_cert("netlas", sha256=c.get("fingerprint_sha256"),
                          serial=_hex_serial(c.get("serial_number")),
                          issuer=first(iss.get("common_name")),
                          common_name=first(subj.get("common_name")), names=names,
                          not_before=val.get("start"), not_after=val.get("end")))
    total = cnt.get("count") if isinstance(cnt, dict) else None
    if len(docs) >= size:
        status = "capped"
    elif isinstance(total, int) and len(docs) < total:
        status = "partial"
    else:
        status = "complete"
    out = {"source": "netlas", "status": status, "window": WINDOWS.get("netlas"), "rows": rows,
           "n": len(dedup_certs(rows)), "errors": []}
    notes = []
    if lookalikes:
        notes.append(f"{lookalikes} of {len(docs)} documents were look-alike names, dropped")
    if status == "partial":
        notes.append(f"short download: {len(docs)} of {total} documents (cold index) — ask again")
    if notes:
        out["note"] = "; ".join(notes)
    return out


def censys_fetch(domain):
    """Censys certificate search — last resort, a capped sample of a global index. Spends credits
    through wp_censys's budget. complete / capped are final even when empty; a later page failing
    is `partial`; a first-page failure is `failed` (a Free plan's 403 says so in the note)."""
    import wp_censys  # noqa: PLC0415
    if not wp_censys.censys_configured():
        return _skip("censys", "skipped-no-key")
    q = f'cert.names="{domain}" or cert.names="*.{domain}" or cert.names="www.{domain}"'
    r = wp_censys.censys_search(q, page_size=int(CENSYS["page_size"]), pages=int(CENSYS["max_pages"]))
    if not isinstance(r, dict):
        return _skip("censys", "skipped-no-key")
    if r.get("skipped"):
        if r.get("plan") == "free":
            out = _skip("censys", "failed", "Free plan: certificate search needs Starter+")
        else:
            out = _skip("censys", "skipped-quota", str(r["skipped"])[:200])
        return out
    if r.get("error") or "hits" not in r:
        out = _skip("censys", "failed",
                    "Free plan: certificate search needs Starter+" if r.get("plan") == "free" else None)
        out["errors"].append(str(r.get("error") or "no hits field"))
        return out
    rows = []
    for h in r["hits"]:
        if h.get("kind") != "certificate":
            continue
        names = _in_scope(_clean_names(h.get("names") or []), domain)
        if names:
            rows.append(_cert("censys", sha256=h.get("fingerprint_sha256"),
                              serial=h.get("serial_number_hex"), issuer=h.get("issuer_cn"),
                              common_name=h.get("subject_cn"), names=names,
                              not_before=h.get("not_before"), not_after=h.get("not_after")))
    status = "partial" if r.get("page_error") else ("capped" if r.get("more_pages") else "complete")
    out = {"source": "censys", "status": status, "window": WINDOWS.get("censys"), "rows": rows,
           "n": len(dedup_certs(rows)), "errors": []}
    if status == "capped":
        out["note"] = f"sample: {len(r['hits'])} of {r.get('total')} hits read"
    return out


_FINAL = {}
_FINAL_LOCK = threading.Lock()


def _memo(fetch, source, domain):
    """Run a keyed source once per (source, domain) per process when its answer is final
    (complete / capped); a partial / failed / skipped answer is asked again next time."""
    with _FINAL_LOCK:
        hit = _FINAL.get((source, domain))
    if hit is not None:
        return hit
    r = fetch(domain)
    if r.get("status") in ("complete", "capped"):
        with _FINAL_LOCK:
            _FINAL[(source, domain)] = r
    return r


def _certkit(domain):
    import wp_certkit  # noqa: PLC0415
    return _memo(wp_certkit.certkit_fetch, "certkit", domain)


def _certindex(domain):
    import wp_certindex  # noqa: PLC0415
    return _memo(wp_certindex.certindex_fetch, "certindex", domain)


def _netlas(domain):
    return _memo(netlas_fetch, "netlas", domain)


def _censys(domain):
    return _memo(censys_fetch, "censys", domain)


# ------------------------------------------------------------------ completeness
def _backup_sources(status):
    return {k: v for k, v in status.items()
            if k != "crt.sh" and not k.endswith("(aggregated)")}


def completeness(status):
    """→ (key, line). `full` only when crt.sh answered (ok, or empty with nothing elsewhere)."""
    crt = status.get("crt.sh") or {}
    st = crt.get("status")
    backups = _backup_sources(status)
    backup_rows = sum(int(v.get("n") or 0) for v in backups.values())
    answered = any(v.get("status") in _ANSWERED for v in backups.values())
    if st == "ok":
        if crt.get("capped"):
            return ("incomplete", f"Incomplete: crt.sh returned its row cap ({crt.get('n')}); "
                                  "older certificates are not listed")
        return "full", "Full CT history (crt.sh)"
    if st == "empty":
        if backup_rows:
            return "lag", ("crt.sh has no record yet (possible ingestion lag); "
                           "backups cover ~1 year")
        return "full", "Full CT history: no certificates on record (crt.sh)"
    lead = ("Incomplete: crt.sh partly unreachable" if crt.get("n")
            else "Incomplete: crt.sh unreachable")
    if answered:
        return "incomplete", f"{lead}; backups cover ~1 year"
    return "incomplete", (f"{lead} and no backup answered — CT history was not collected "
                          "(this is not 'no certificates')")


def _status_entry(r):
    e = {"status": r["status"], "window": r.get("window"), "n": int(r.get("n") or 0)}
    for k in ("via", "attempts", "elapsed_s", "capped", "note", "pages"):
        if r.get(k) not in (None, False, ""):
            e[k] = r[k]
    errs = [x for x in r.get("errors") or [] if x]
    if errs:
        e["errors"] = errs[:4]
    return e


# ------------------------------------------------------------------ the merged lookup
_DEFAULT = object()


def ct_search(domain, *, free_only=False, max_certs=_DEFAULT, max_subdomains=_DEFAULT):
    """Certificate-transparency history of `domain` and its subdomains, through the fallback
    chain in the module docstring. Never raises.

    Returns the long-standing CT shape — subdomains / wildcards / certs / cert_count — plus
    `ct_status` (per-source status, window, row count), `completeness` + `completeness_line`,
    `cert_total` / `truncated` and `subdomain_total` / `subdomains_truncated`. `subdomains` is
    every name on any certificate (foreign co-SANs included) other than the apex; listings are
    capped by references/ct_sources.json `listing` (pass None for no cap). `error` is set only
    when no CT history at all was collected. `free_only` gates metered sources (none of the
    keyless chain is metered)."""
    domain = str(domain or "").strip().lower().rstrip(".")
    if domain.startswith("*."):
        domain = domain[2:]
    cap_c = LISTING["max_certs"] if max_certs is _DEFAULT else max_certs
    cap_s = LISTING["max_subdomains"] if max_subdomains is _DEFAULT else max_subdomains
    status, rows, hostnames = {}, [], []

    crt = crtsh_fetch(domain)
    status["crt.sh"] = _status_entry(crt)
    rows += crt["rows"]
    if crt["status"] in ("degraded", "empty"):
        jobs = [shodan_ctl_fetch, certspotter_fetch, _certkit, _certindex]
        skipped = []
        if crt["status"] == "degraded":          # Netlas never overrides an authoritative empty
            if free_only:
                skipped.append(_skip("netlas", "skipped-free-only"))
            else:
                jobs.append(_netlas)
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(jobs)) as ex:
            backups = [f.result() for f in [ex.submit(fn, domain) for fn in jobs]] + skipped
        for b in backups:
            status[b["source"]] = _status_entry(b)
            rows += b["rows"]
            hostnames += b.get("hostnames") or []
        if not rows:                                # last resort: nothing anywhere so far
            cen = _skip("censys", "skipped-free-only") if free_only else _censys(domain)
            status["censys"] = _status_entry(cen)
            rows += cen["rows"]

    certs = dedup_certs(rows)
    subs, wildcards = set(), set()
    for name in [n for c in certs for n in c["names"]] + hostnames:
        if name.startswith("*."):
            wildcards.add(name)
        bare = name.lstrip("*.")
        if bare and bare != domain:
            subs.add(bare)

    agg_names, agg_sources = [], []
    # Aggregated indexes are the LAST resort: only when the whole chain above (crt.sh, the backups,
    # Censys) produced no certificate and no hostname at all. An apex-only certificate is a CT
    # answer — asking crt.name/agniops then would disclose the apex to them for nothing.
    if not certs and not hostnames:
        for a in aggregated_fetch(domain):
            status[a["source"]] = _status_entry(a)
            if a["names"]:
                agg_sources.append(a["source"])
                agg_names += [n for n in a["names"] if n not in agg_names]

    key, line = completeness(status)
    ordered = sorted(subs)
    out = {
        "query": f"%.{domain}", "domain": domain,
        "sources": [s for s, v in status.items()
                    if v["status"] in ("ok", "empty") + _ANSWERED and not s.endswith("(aggregated)")],
        "ct_status": status, "completeness": key, "completeness_line": line,
        "total": len(ordered), "subdomain_total": len(ordered),
        "subdomains": ordered if cap_s is None else ordered[:cap_s],
        "subdomains_truncated": cap_s is not None and len(ordered) > cap_s,
        "wildcards": sorted(wildcards),
        "cert_count": len(certs), "cert_total": len(certs),
        "certs": certs if cap_c is None else certs[:cap_c],
        "truncated": cap_c is not None and len(certs) > cap_c,
    }
    if agg_sources:
        agg_names = [n.lstrip("*.") for n in agg_names]
        out["aggregated_sources"] = agg_sources
        out["aggregated_subdomains"] = sorted(set(n for n in agg_names if n != domain))[
            :int(AGGREGATED["max_names"])]
    if not certs and not subs and crt["status"] == "degraded":
        out["error"] = line
    return out


def _main():
    import argparse
    ap = argparse.ArgumentParser(description="Certificate-transparency history with per-source status")
    ap.add_argument("domain")
    ap.add_argument("--free-only", action="store_true", help="skip metered CT sources")
    ap.add_argument("--all", action="store_true", help="list every certificate and subdomain (no cap)")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    kw = {"max_certs": None, "max_subdomains": None} if a.all else {}
    r = ct_search(a.domain, free_only=a.free_only, **kw)
    if a.json:
        print(json.dumps(r, ensure_ascii=False, indent=2))
        return
    print(f"CT (certificate transparency) — {r['domain']}")
    print(f"  Completeness: {r['completeness_line']}")
    for src, st in r["ct_status"].items():
        extra = ", ".join(f"{k}={v}" for k, v in st.items() if k in ("via", "attempts", "pages"))
        err = f"  [{'; '.join(st['errors'])}]" if st.get("errors") else ""
        print(f"  {src:22} {st['status']:17} {st['n']:>4} certs  window: {st.get('window')}"
              + (f"  ({extra})" if extra else "") + err)
    print(f"  Merged: {r['cert_total']} certificate(s), {r['subdomain_total']} name(s)"
          + ("  [listing truncated]" if r["truncated"] or r["subdomains_truncated"] else ""))
    for c in r["certs"]:
        print(f"    {c.get('not_before') or '?':19}  {c.get('confidence'):6} "
              f"{'+'.join(c['sources']):24} {(c.get('issuer_cn') or '')[:34]:34} "
              f"{', '.join(c['names'][:3])}")


if __name__ == "__main__":
    _main()
