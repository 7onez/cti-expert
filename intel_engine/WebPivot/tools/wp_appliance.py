#!/usr/bin/env python3
"""wp_appliance — PASSIVE edge/VPN appliance scan: fingerprint -> CISA KEV -> patch-lag inference.

Implements `/appliance-scan` (techniques/fx-edge-appliance-recon.md). Input: a domain or an IP.
A domain is resolved to its A records through the shared recursive-resolver helper
(wp_ippivot.dns_records — a resolver query, never a connection to the host). Then, per IP:

  (a) COLLECT what scan databases ALREADY stored. Shodan InternetDB (keyless: ports, CPEs, tags,
      index CVEs) runs for every IP first. Shodan host and Censys host only when a key is
      configured AND spending is allowed: `--free-only` or the case scope's
      `constraints.no_spend` skips both with the reason, the way wp_analyze.enrich_live gates
      its metered engines. Even then they are bought only for an IP whose InternetDB record shows
      a catalogue CPE, a metered_gate_ports port or a metered_gate_tags tag, capped at
      settings.max_metered_ips; the planned credit count is computed before any spend and
      reported (`metered_plan`, plus a stderr line). Metered calls are
      ledgered through api_usage.record (Censys through wp_censys, which also applies its credit
      budget). THE TARGET IS NEVER CONTACTED: no page fetch, no banner grab, no port probe.
  (b) FINGERPRINT product + version from CPEs, the index's structured product/version fields and
      stored banner text, against the product catalogue in references/appliance.json.
  (c) MAP each product to the CISA KEV catalogue (fetched through wp_http, cached with a TTL; the
      reason is reported when it is unavailable). KEV matches the product FAMILY; a version
      compared with the advisory table decides pre-fix / fixed / branch_only / unknown.
      branch_only = the version names the fix's branch but is less specific than the fixed
      release (a branch-level CPE `13.1` vs `13.1-49.15`); it is never pre-fix, never a lag,
      never CRITICAL — only versions at least as specific as the fix are compared.
  (d) PATCH-LAG inference, two signals reported separately:
        uptime  -> "No reboot since about <boot> (per <index> record of <scan date>)", with the
                   497.1-day SNMP wrap (and TCP-timestamp) caveats and the wrapped readings;
        version -> lag in days between the advisory and the latest record still announcing a
                   pre-fix version. The words that claim exploitability are never written.
  (e) OUTPUT per-host rows: product, version (+ basis), evidence, KEV matches, patch-lag rows,
      uptime rows, port-risk rows and caveats, plus an escalation flag:
        CRITICAL  a KEV CVE whose advisory row shows the version is pre-fix, on a version the
                  ANALYST confirmed (--version-confirmed; basis in
                  settings.confirmed_version_bases, shipped as ["analyst"] only);
        TENTATIVE a KEV family match without that — including a pre-fix version read only from
                  a CPE or the index's version field;
        NONE      no KEV family match.
      Each product carries `version_confirmed_by` (the confirming basis, or null) so a report
      can say who confirmed the version.
      With --case the result is written to cases/<id>/appliances.json; with --kb the findings
      are recorded as KB FACTS only (appliance_product; kev_exposure ONLY for a pre-fix KEV CVE)
      — never an edge, never an operator (attribution rail: a product on a host says nothing
      about who runs it).

CLI:
  python3 wp_appliance.py vpn.example.com --json
  python3 wp_appliance.py 203.0.113.10 --free-only --case CASE-0001 --kb ../knowledge
  python3 wp_appliance.py 203.0.113.10 --advisory EXAMPLE-SA-2026-001:2026-06-10:9.4.2
"""
from __future__ import annotations

import argparse
import datetime
import ipaddress
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
from wp_refs import ref_path, load_ref  # noqa: E402 — reference DATA lives in references/*.json
import wp_http  # noqa: E402 — the one API transport (Android UA)
from wp_common import _secret  # noqa: E402

try:
    import api_usage  # noqa: E402 — licensed-API credit ledger
except Exception:  # noqa: BLE001
    api_usage = None

ENGINE = os.path.dirname(os.path.dirname(HERE))
COLLECTOR = "wp_appliance"

# RULE 3 — the conservative minimum when references/appliance.json is missing: one product, no
# advisory rows, every version TENTATIVE (no confirmed bases), the snmp wrap constant.
_FALLBACK = {
    "settings": {"internetdb_url": "https://internetdb.shodan.io/{ip}",
                 "shodan_host_url": "https://api.shodan.io/shodan/host/{ip}",
                 "censys_host_path": "/v3/global/asset/host/{id}",
                 "kev_url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                 "kev_cache_path": "cache/kev.json", "kev_ttl_hours": 24, "timeout_seconds": 20,
                 "kev_timeout_seconds": 60, "max_ips": 4, "max_metered_ips": 2,
                 "metered_gate_ports": [443], "metered_gate_tags": ["vpn"],
                 "max_kev_per_product": 40,
                 "snmp_wrap_days": 497.1, "tcp_ts_wrap_days": 49.7, "wrap_alternatives": 2,
                 "boot_window_days": 1, "confirmed_version_bases": ["analyst"]},
    "products": {"citrix_netscaler": {
        "name": "Citrix NetScaler ADC / Gateway", "vendor": "Citrix",
        "cpe": [{"vendor": "^citrix$", "product": "netscaler|gateway"}],
        "banner": ["(?i)netscaler"], "version_regex": [], "build_map": {},
        "kev": {"vendor": "(?i)^citrix$", "product": "(?i)netscaler|gateway"}}},
    "build_regex": [],
    "advisories": {},
    "port_risk": {},
    "uptime_fields": [{"path": "uptime", "unit": "minutes", "clock": "unknown"}],
    "caveats": {"general": "Passive scan-database evidence only; the version-to-CVE mapping stays "
                           "TENTATIVE until the version is verified."},
}
REF = load_ref(ref_path(__file__, "appliance.json"), _FALLBACK)
SETTINGS = REF["settings"]
PRODUCTS = REF["products"]


def verified_advisories(rows: dict) -> tuple:
    """-> (kept, ignored_ids). An advisory row drives CRITICAL and lag wording, so a row nobody
    checked against the vendor must not reach a report: a row without both `verified` and
    `source_url` is ignored and listed. An analyst's --advisory never passes through here."""
    kept = {c: a for c, a in (rows or {}).items()
            if isinstance(a, dict) and a.get("verified") and a.get("source_url")}
    return kept, sorted(set(rows or {}) - set(kept))


ADVISORIES, ADVISORIES_IGNORED = verified_advisories(REF["advisories"])
PORT_RISK = REF["port_risk"]
UPTIME_FIELDS = REF["uptime_fields"]
BUILD_RES = [re.compile(p) for p in REF["build_regex"]]
CAVEATS = REF["caveats"]


def _s(key):
    v = SETTINGS.get(key)
    return _FALLBACK["settings"][key] if v is None else v


TIMEOUT = int(_s("timeout_seconds"))
CONFIRMED_BASES = set(_s("confirmed_version_bases") or [])
_kcp = str(_s("kev_cache_path"))
KEV_CACHE = _kcp if os.path.isabs(_kcp) else os.path.join(ENGINE, _kcp)
_UNIT_DAYS = {"minutes": 1 / 1440.0, "seconds": 1 / 86400.0, "timeticks": 1 / 8640000.0}
_CASE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,80}$")


def _cav(key):
    return CAVEATS.get(key) or ""


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ") if dt else None


def _parse_dt(s):
    """Index timestamps ('2026-07-28T09:12:00.123456', '...Z', '2026-07-28') -> aware UTC."""
    if not s:
        return None
    t = str(s).strip().replace("Z", "+00:00")
    for cand in (t, t[:26], t[:19], t[:10]):
        try:
            dt = datetime.datetime.fromisoformat(cand)
        except ValueError:
            continue
        return dt if dt.tzinfo else dt.replace(tzinfo=datetime.timezone.utc)
    return None


# ================================================================ resolution (resolver only)
def is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def resolve_ips(host: str) -> list:
    """A records through the shared resolver helper (dig/nslookup against the recursive
    resolver). Never a connection to the host itself."""
    import wp_ippivot  # lazy: heavy import, only needed for a domain target
    return list((wp_ippivot.dns_records(host, types=("A",)) or {}).get("A") or [])


# ================================================================ spend gate
def case_dir(case: str) -> str:
    return os.path.join(os.environ.get("INTEL_HOME") or ENGINE, "cases", case)


def scope_no_spend(case) -> bool:
    if not case:
        return False
    try:
        with open(os.path.join(case_dir(case), "scope.json"), encoding="utf-8") as fh:
            return bool(((json.load(fh) or {}).get("constraints") or {}).get("no_spend"))
    except (OSError, ValueError):
        return False


def shodan_configured() -> bool:
    return bool(_secret("SHODAN_KEY", "SHODAN_API_KEY"))


def censys_configured() -> bool:
    try:
        import wp_censys
        return wp_censys.censys_configured()
    except Exception:  # noqa: BLE001
        return False


# ================================================================ collectors (passive indexes)
def internetdb(ip: str) -> dict:
    """Keyless Shodan InternetDB record -> {status, ports, cpes, tags, vulns, hostnames}."""
    r = wp_http.request(str(_s("internetdb_url")).replace("{ip}", ip), timeout=TIMEOUT)
    if r.status == 404:
        return {"status": "not_found", "reason": "InternetDB holds no record for this IP"}
    if r.failure:
        return {"status": "error", "reason": r.failure}
    d = r.json()
    if not isinstance(d, dict):
        return {"status": "error", "reason": "InternetDB answer is not a JSON object"}
    return {"status": "ok", "ports": sorted(int(p) for p in d.get("ports") or [] if str(p).isdigit()),
            "cpes": list(d.get("cpes") or []), "tags": list(d.get("tags") or []),
            "vulns": sorted(d.get("vulns") or []), "hostnames": list(d.get("hostnames") or [])}


def shodan_host_raw(ip: str) -> dict:
    """Shodan host record (keyed, 1 query credit) -> {status, services:[...], vulns, last_update}.
    The key travels in the query string only; wp_http never echoes the URL in an error."""
    key = _secret("SHODAN_KEY", "SHODAN_API_KEY")
    r = wp_http.request(str(_s("shodan_host_url")).replace("{ip}", ip), params={"key": key},
                        timeout=TIMEOUT)
    if r.status == 404:
        if api_usage:
            api_usage.record("shodan", "host", credits=0, query=ip, ok=False)
        return {"status": "not_found", "reason": "Shodan holds no host record for this IP"}
    if r.failure:
        if api_usage:
            api_usage.record("shodan", "host", credits=0, query=ip, ok=False)
        return {"status": "error", "reason": r.failure}
    d = r.json()
    if not isinstance(d, dict):
        if api_usage:
            api_usage.record("shodan", "host", credits=0, query=ip, ok=False)
        return {"status": "error", "reason": "Shodan answer is not a JSON object"}
    if api_usage:
        api_usage.record("shodan", "host", credits=1, query=ip, results=len(d.get("data") or []))
    svcs = []
    for rec in d.get("data") or []:
        if not isinstance(rec, dict):
            continue
        http = rec.get("http") if isinstance(rec.get("http"), dict) else {}
        svcs.append({"port": rec.get("port"), "timestamp": rec.get("timestamp"),
                     "product": rec.get("product"), "version": rec.get("version"),
                     "cpe": list(rec.get("cpe23") or []) + list(rec.get("cpe") or []),
                     "title": http.get("title"), "html": (http.get("html") or "")[:200000],
                     "banner": (rec.get("data") or "")[:20000], "raw": rec})
    return {"status": "ok", "services": svcs, "vulns": sorted((d.get("vulns") or [])),
            "last_update": d.get("last_update")}


def _censys_summary(res: dict) -> dict:
    svcs = []
    for s in (res or {}).get("services") or []:
        if not isinstance(s, dict):
            continue
        for sw in s.get("software") or [{}]:
            sw = sw if isinstance(sw, dict) else {}
            svcs.append({"port": s.get("port"), "timestamp": s.get("scan_time"),
                         "product": sw.get("product"), "vendor": sw.get("vendor"),
                         "version": sw.get("version"),
                         "cpe": [sw["cpe"]] if sw.get("cpe") else [],
                         "banner": str(s.get("banner") or "")[:20000]})
    return {"status": "ok", "services": svcs}


def censys_host_raw(ip: str) -> dict:
    """Censys host lookup through wp_censys (its credit budget + ledger) with a version-keeping
    summary. 1 credit."""
    import wp_censys
    out = wp_censys._lookup("appliance_host", ip, str(_s("censys_host_path")), _censys_summary,
                            timeout=TIMEOUT)
    if isinstance(out, dict) and ("skipped" in out or "error" in out):
        return {"status": "skipped" if "skipped" in out else "error",
                "reason": out.get("skipped") or out.get("error")}
    return out if isinstance(out, dict) else {"status": "error", "reason": "no Censys answer"}


# ================================================================ KEV catalogue
def _valid_kev(doc) -> bool:
    return isinstance(doc, dict) and isinstance(doc.get("vulnerabilities"), list)


def load_kev(kev_file=None, refresh=False) -> tuple:
    """-> (entries, meta). meta.status: file | cache | fetched | stale_cache | unavailable, with
    `reason` whenever the fresh catalogue could not be had."""
    if kev_file:
        try:
            with open(kev_file, encoding="utf-8") as fh:
                doc = json.load(fh)
            if _valid_kev(doc):
                return doc["vulnerabilities"], {"status": "file", "path": kev_file,
                                                "catalog_version": doc.get("catalogVersion")}
            return [], {"status": "unavailable", "reason": f"{kev_file} is not a KEV catalogue"}
        except (OSError, ValueError) as exc:
            return [], {"status": "unavailable", "reason": f"cannot read {kev_file}: {exc}"}
    cached, age_h = None, None
    try:
        age_h = (_now().timestamp() - os.path.getmtime(KEV_CACHE)) / 3600.0
        with open(KEV_CACHE, encoding="utf-8") as fh:
            cached = json.load(fh)
        if not _valid_kev(cached):
            cached = None
    except (OSError, ValueError):
        cached = None
    if cached and not refresh and age_h is not None and age_h <= float(_s("kev_ttl_hours")):
        return cached["vulnerabilities"], {"status": "cache", "age_hours": round(age_h, 1),
                                           "catalog_version": cached.get("catalogVersion")}
    r = wp_http.request(str(_s("kev_url")), timeout=int(_s("kev_timeout_seconds")))
    doc = r.json() if not r.failure else None
    if _valid_kev(doc):
        try:
            os.makedirs(os.path.dirname(KEV_CACHE), exist_ok=True)
            tmp = KEV_CACHE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(doc, fh)
            os.replace(tmp, KEV_CACHE)
        except OSError as exc:
            print(f"[appliance] KEV cache not written ({exc})", file=sys.stderr)
        return doc["vulnerabilities"], {"status": "fetched",
                                        "catalog_version": doc.get("catalogVersion")}
    why = r.failure or "the KEV feed answer is not a KEV catalogue"
    if cached:
        return cached["vulnerabilities"], {
            "status": "stale_cache", "age_hours": round(age_h or 0, 1),
            "catalog_version": cached.get("catalogVersion"),
            "reason": f"KEV refresh failed ({why}); using the cached copy"}
    return [], {"status": "unavailable",
                "reason": f"KEV catalogue unavailable ({why}) and no cached copy at {KEV_CACHE}; "
                          f"KEV mapping was not done"}


def kev_family(pid: str, kev: list) -> list:
    spec = (PRODUCTS.get(pid) or {}).get("kev") or {}
    try:
        vre, pre = re.compile(spec.get("vendor") or "$^"), re.compile(spec.get("product") or "$^")
    except re.error:
        return []
    rows = [e for e in kev if isinstance(e, dict) and vre.search(str(e.get("vendorProject") or ""))
            and pre.search(str(e.get("product") or ""))]
    rows.sort(key=lambda e: str(e.get("cveID")))
    return rows[: int(_s("max_kev_per_product"))]


# ================================================================ fingerprint
def parse_cpe(cpe: str):
    """CPE 2.2 `cpe:/a:v:p:ver` or 2.3 `cpe:2.3:a:v:p:ver:...` -> (vendor, product, version)."""
    c = str(cpe or "").strip()
    if c.startswith("cpe:2.3:"):
        parts = c.split(":")[3:]
    elif c.startswith("cpe:/"):
        parts = c[5:].split(":")[1:]
    else:
        return None
    vendor = parts[0] if parts else ""
    product = parts[1] if len(parts) > 1 else ""
    version = parts[2] if len(parts) > 2 and parts[2] not in ("", "*", "-") else None
    return vendor.lower(), product.lower(), version


def _cpe_product(vendor: str, product: str):
    for pid, spec in PRODUCTS.items():
        for pat in spec.get("cpe") or []:
            try:
                if re.search(pat.get("vendor") or "$^", vendor, re.I) and \
                        re.search(pat.get("product") or "$^", product, re.I):
                    return pid
            except re.error:
                continue
    return None


def _banner_products(text: str) -> list:
    out = []
    for pid, spec in PRODUCTS.items():
        for pat in spec.get("banner") or []:
            try:
                m = re.search(pat, text)
            except re.error:
                continue
            if m:
                out.append((pid, m.group(0)))
                break
    return out


def _vt(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", str(v or "")))


def version_status(version: str, fixed_in, depth: int) -> str:
    """pre-fix | fixed | branch_only | branch_unlisted | unknown — on the advisory's per-branch
    fixed list. branch_only = the version names the fixed release's branch but fewer components
    than that release (a branch-level CPE `13.1` vs the fix `13.1-49.15`): it cannot be ordered
    against the fix, so it is never pre-fix — only versions at least as specific as the fix
    are compared."""
    if not version or not fixed_in:
        return "unknown"
    v = _vt(version)
    if len(v) < depth:
        return "unknown"
    for f in fixed_in:
        fv = _vt(f)
        if fv[:depth] == v[:depth]:
            if len(v) < len(fv):
                return "branch_only"
            return "pre-fix" if v < fv else "fixed"
    return "branch_unlisted"


# Edition-aware comparison (Citrix standard / FIPS / NDcPP trains share version numbers). Only
# vendor-documented signals decide the edition — see products.<pid>.editions in appliance.json.
_EDITION_FIELD = {"standard": "fixed_in", "fips": "fixed_fips", "ndcpp": "fixed_ndcpp"}


def edition_markers(pid: str, text) -> set:
    """Editions whose documented marker appears in one piece of version-bearing evidence."""
    marks = (((PRODUCTS.get(pid) or {}).get("editions") or {}).get("markers") or {})
    out = set()
    for ed, pats in marks.items():
        for pat in pats or []:
            try:
                if re.search(pat, str(text or "")):
                    out.add(ed)
                    break
            except re.error:
                continue
    return out


def resolve_edition(pid: str, ver: str, slot: dict) -> tuple:
    """(edition, basis) — standard | fips | ndcpp from a documented signal (an analyst --edition,
    a marker in version-bearing evidence, an exact match in the vendor's standard build list),
    else ('unknown', None). Never inferred from a build range."""
    eds = slot.get("editions") or {}
    if len(eds) == 1:
        return next(iter(eds.items()))
    if len(eds) > 1:
        return "unknown", "conflicting markers: " + ", ".join(sorted(eds))
    std = (((PRODUCTS.get(pid) or {}).get("editions") or {}).get("standard_builds") or {})
    v = _vt(ver)
    if std and len(v) >= 4 and f"{v[2]}.{v[3]}" in (std.get(f"{v[0]}.{v[1]}") or []):
        return "standard", "vendor_build_list"
    return "unknown", None


def _edition_verdict(version: str, a: dict, ed: str, depth: int) -> str:
    """pre-fix | fixed | unknown | unlisted (branch not in this edition's list) | nolist."""
    v = _vt(version)
    if len(v) < depth:
        return "unknown"
    if ed == "standard" and ".".join(map(str, v[:depth])) in [str(b) for b in a.get("affected_no_fix") or []]:
        return "pre-fix"
    fixed = a.get(_EDITION_FIELD[ed])
    if fixed is None:
        return "nolist"
    if not fixed:
        return "unknown"            # an edition list left empty = not confirmed from the vendor
    st = version_status(version, fixed, depth)
    return "unlisted" if st == "branch_unlisted" else st


def advisory_status(version: str, a: dict, edition: str) -> tuple:
    """-> (status, per-edition verdicts or None). A row without fixed_fips / fixed_ndcpp keeps
    the plain fixed_in comparison. With edition lists: a known edition uses its own list; an
    unknown edition gets one status only when every edition that covers the branch agrees,
    otherwise `ambiguous_edition`."""
    depth = int(a.get("branch_depth") or 2)
    if not any(k in a for k in ("fixed_fips", "fixed_ndcpp")):
        return version_status(version, a.get("fixed_in"), depth), None
    if edition in _EDITION_FIELD:
        v = _edition_verdict(version, a, edition, depth)
        return {"unlisted": "branch_unlisted", "nolist": "unknown"}.get(v, v), None
    verdicts = {ed: _edition_verdict(version, a, ed, depth) for ed in _EDITION_FIELD}
    definite = {ed: v for ed, v in verdicts.items() if v not in ("unlisted", "nolist")}
    if not definite:
        return "branch_unlisted", verdicts
    if len(set(definite.values())) == 1:
        return next(iter(definite.values())), verdicts
    return "ambiguous_edition", definite


class _Product:
    def __init__(self, pid):
        self.pid = pid
        self.evidence = []
        self.versions = {}      # version -> {"bases": [...], "dates": [...], "editions": {ed: basis}}

    def add(self, source, field, value, port=None, record_date=None):
        ev = {"source": source, "field": field, "value": str(value)[:300]}
        if port is not None:
            ev["port"] = port
        if record_date:
            ev["record_date"] = record_date
        if ev not in self.evidence:
            self.evidence.append(ev)

    def version(self, ver, basis, record_date=None, text=None):
        """Record one version sighting. `text` = the version-bearing evidence it came from (a
        CPE string, the index's product/version field, a version_regex hit) — the only place an
        edition marker is read."""
        if not ver:
            return
        slot = self.versions.setdefault(str(ver), {"bases": [], "dates": [], "editions": {}})
        if basis not in slot["bases"]:
            slot["bases"].append(basis)
        if record_date and record_date not in slot["dates"]:
            slot["dates"].append(record_date)
        for ed in edition_markers(self.pid, text if text is not None else ver):
            slot["editions"].setdefault(ed, f"marker in {basis}")


def fingerprint(idb: dict, shodan: dict, censys: dict, analyst_confirmed=False,
                analyst_edition=None) -> dict:
    prods = {}

    def get(pid):
        return prods.setdefault(pid, _Product(pid))

    for cpe in (idb or {}).get("cpes") or []:
        p = parse_cpe(cpe)
        pid = p and _cpe_product(p[0], p[1])
        if pid:
            get(pid).add("internetdb", "cpe", cpe)
            get(pid).version(p[2], "cpe_version", text=cpe)
    for src, rec in (("shodan", shodan), ("censys", censys)):
        for s in (rec or {}).get("services") or []:
            date = (_parse_dt(s.get("timestamp")) or None)
            dstr = date.strftime("%Y-%m-%d") if date else None
            hit, field_hit = set(), set()
            for cpe in s.get("cpe") or []:
                p = parse_cpe(cpe)
                pid = p and _cpe_product(p[0], p[1])
                if pid:
                    hit.add(pid)
                    field_hit.add(pid)
                    get(pid).add(src, "cpe", cpe, s.get("port"), dstr)
                    get(pid).version(p[2], "cpe_version", dstr, text=cpe)
            prod_field = " ".join(x for x in (s.get("vendor"), s.get("product")) if x)
            if prod_field:
                field_hit |= {pid for pid, _m in _banner_products(prod_field)}
            text = "\n".join(str(x) for x in (prod_field, s.get("title"), s.get("banner"),
                                                s.get("html")) if x)
            for pid, match in _banner_products(text):
                hit.add(pid)
                get(pid).add(src, "banner", match, s.get("port"), dstr)
            for pid in hit:
                spec = PRODUCTS.get(pid) or {}
                # The index's structured version belongs to the product its own product field /
                # CPE names — not to every product whose marker appears somewhere in the body.
                if s.get("version") and prod_field and pid in field_hit:
                    get(pid).add(src, "product/version field", f"{prod_field} {s['version']}",
                                 s.get("port"), dstr)
                    get(pid).version(s["version"], "index_version_field", dstr,
                                     text=f"{prod_field} {s['version']}")
                for vre in spec.get("version_regex") or []:
                    try:
                        m = re.search(vre, text)
                    except re.error:
                        continue
                    if m:
                        get(pid).add(src, "version banner", m.group(0), s.get("port"), dstr)
                        get(pid).version(m.group(1), "banner_regex", dstr, text=m.group(0))
                for bre in BUILD_RES:
                    m = bre.search(str(s.get("html") or ""))
                    if m:
                        build = m.group(1)
                        get(pid).add(src, "static-asset build string", m.group(0), s.get("port"),
                                     dstr)
                        mapped = (spec.get("build_map") or {}).get(build)
                        get(pid).version(mapped or f"build {build} (UNMAPPED)",
                                         "build_string", dstr, text="")
    if analyst_confirmed:
        for p in prods.values():
            for slot in p.versions.values():
                slot["bases"].append("analyst")
    if analyst_edition:
        for p in prods.values():
            for slot in p.versions.values():
                slot["editions"] = {analyst_edition: "analyst"}
    return prods


# ================================================================ patch lag
def _uptime_value(rec: dict, path: str):
    node = rec
    for part in path.split("."):
        if not isinstance(node, dict):
            return None
        node = node.get(part)
    try:
        return float(node)
    except (TypeError, ValueError):
        return None


def uptime_rows(shodan: dict, advisory_dates: list) -> tuple:
    """Shodan service records carrying an uptime -> ("no reboot since" rows, ha_conflict)."""
    rows = []
    wrap = float(_s("snmp_wrap_days"))
    tcp_wrap = float(_s("tcp_ts_wrap_days"))
    win = float(_s("boot_window_days"))
    for s in (shodan or {}).get("services") or []:
        scan = _parse_dt(s.get("timestamp"))
        raw = s.get("raw") or {}
        for f in UPTIME_FIELDS:
            val = _uptime_value(raw, f.get("path") or "")
            if val is None or not scan:
                continue
            days = val * _UNIT_DAYS.get(f.get("unit"), 1 / 1440.0)
            boot = scan - datetime.timedelta(days=days)
            clock = f.get("clock") or "unknown"
            cav = [_cav("snmp_wrap")]
            if clock in ("tcp_timestamp", "unknown"):
                cav.append(_cav("tcp_wrap"))
            cav += [_cav("ha_pair"), _cav("hot_patch"), _cav("clock_offset")]
            alts = []
            for k in range(1, int(_s("wrap_alternatives")) + 1):
                d2 = days + k * wrap
                alts.append({"wraps": k, "clock": "snmp_sysuptime", "uptime_days": round(d2, 1),
                             "boot_estimate": (scan - datetime.timedelta(days=d2)).strftime("%Y-%m-%d")})
            bstr, sstr = boot.strftime("%Y-%m-%d"), scan.strftime("%Y-%m-%d")
            row = {"source": "shodan", "port": s.get("port"), "field": f.get("path"),
                   "clock": clock, "record_date": sstr, "uptime_days": round(days, 1),
                   "boot_estimate": bstr,
                   "boot_window": [(boot - datetime.timedelta(days=win)).strftime("%Y-%m-%d"),
                                   (boot + datetime.timedelta(days=win)).strftime("%Y-%m-%d")],
                   "text": (f"No reboot since about {bstr} (per Shodan record of {sstr}); firmware "
                            f"updates that need a reboot cannot have been applied since then."),
                   "wrap_alternatives": alts,
                   "wrap_note": (f"A {round(days, 1)}-day reading may be {round(days + wrap, 1)} "
                                 f"days or more (one {wrap}-day SNMP wrap per step)"
                                 + (f"; a TCP-timestamp clock wraps every {tcp_wrap} days"
                                    if clock in ("tcp_timestamp", "unknown") else "") + "."),
                   "caveats": [c for c in cav if c]}
            vs = []
            for a in advisory_dates:
                adv = _parse_dt(a.get("published"))
                if adv and boot < adv:
                    vs.append({"cve": a.get("cve"), "advisory_id": a.get("advisory_id"),
                               "published": a.get("published"),
                               "upgrade_reboots": a.get("upgrade_reboots"),
                               "text": (f"Boot (about {bstr}) predates {a.get('advisory_id')} "
                                        f"({a.get('published')})"
                                        + ("; the fixed firmware upgrade reboots the device, so it "
                                           f"was not installed as of {sstr}."
                                           if a.get("upgrade_reboots") else
                                           "; check whether the fix needs a reboot before "
                                           "drawing a conclusion."))})
            if vs:
                row["vs_advisories"] = vs
            rows.append(row)
    boots = {r["boot_estimate"] for r in rows}
    spread = 0
    if len(boots) > 1:
        ds = sorted(_parse_dt(b) for b in boots)
        spread = (ds[-1] - ds[0]).days
    return rows, spread > 2 * win


def _advisories_for(pid: str, kev_rows: list, extra: list) -> list:
    kev_ids = {e.get("cveID") for e in kev_rows}
    out = []
    for cve, a in ADVISORIES.items():
        if isinstance(a, dict) and a.get("product") == pid and (cve in kev_ids or not kev_rows):
            out.append(dict(a, cve=cve))
    out += [dict(a) for a in extra]
    return out


def lag_rows(prod: _Product, advisories: list, kev_by_cve: dict) -> list:
    rows = []
    for ver, slot in sorted(prod.versions.items()):
        dates = sorted(slot["dates"])
        edition, ed_basis = resolve_edition(prod.pid, ver, slot)
        for a in advisories:
            adv = _parse_dt(a.get("published"))
            st, verdicts = advisory_status(ver, a, edition)
            kev = kev_by_cve.get(a.get("cve")) or {}
            row = {"cve": a.get("cve"), "advisory_id": a.get("advisory_id"),
                   "advisory_date": a.get("published"), "fixed_in": a.get("fixed_in"),
                   "kev_date_added": kev.get("dateAdded"), "kev_due_date": kev.get("dueDate"),
                   "announced_version": ver, "version_basis": slot["bases"],
                   "version_status": st, "first_seen": dates[0] if dates else None,
                   "last_seen": dates[-1] if dates else None, "lag_days": None,
                   "past_kev_due": None, "advisory_source": a.get("source_url"),
                   "advisory_verified": a.get("verified"), "advisory_source_kind":
                   a.get("source") or "reference_table"}
            if a.get("notes"):
                row["advisory_notes"] = a["notes"]
            if any(k in a for k in ("fixed_fips", "fixed_ndcpp")):
                row.update({"edition": edition, "edition_basis": ed_basis,
                            "fixed_fips": a.get("fixed_fips"), "fixed_ndcpp": a.get("fixed_ndcpp")})
            if st == "ambiguous_edition":
                row["edition_verdicts"] = verdicts
                row["edition_note"] = (
                    f"Edition unknown for {ver}: against {a.get('advisory_id')} it reads "
                    + ", ".join(f"{v} as {ed}" for ed, v in sorted(verdicts.items()))
                    + ". The vendor documents no build range that separates its standard, FIPS "
                      "and NDcPP trains; confirm the edition and re-run with --edition.")
            last = _parse_dt(row["last_seen"])
            if st == "ambiguous_edition":
                row["text"] = row["edition_note"]
            elif st == "fixed":
                row["text"] = (f"Announced {ver} is at or after the fixed release for "
                               f"{a.get('cve')}; no lag.")
            elif st == "branch_only":
                row["text"] = (f"Announced {ver} names only the branch of the fixed release for "
                               f"{a.get('cve')} (less specific than the fix) — it cannot be ordered "
                               f"against the fix, so no pre-fix status and no lag; read the full "
                               f"build from the vendor or an authorised check.")
            elif not adv:
                row["text"] = "No advisory date — lag cannot be computed."
            elif not last:
                row["text"] = ("No index record date carries this version (InternetDB stores "
                               "none) — lag cannot be computed.")
            else:
                lag = (last - adv).days
                row["lag_days"] = lag
                due = _parse_dt(kev.get("dueDate"))
                row["past_kev_due"] = bool(due and last > due) if st == "pre-fix" else None
                if lag < 0:
                    row["text"] = (f"Version {ver} was last seen {row['last_seen']}, before the "
                                   f"advisory ({a.get('published')}): no lag can be shown.")
                elif st == "pre-fix":
                    row["text"] = (f"{lag} days after {a.get('advisory_id')} ({a.get('published')}) "
                                   f"the index still recorded pre-fix {ver} (last seen "
                                   f"{row['last_seen']})"
                                   + ("; past the KEV due date." if row["past_kev_due"] else "."))
                else:
                    row["text"] = (f"Last record announcing {ver} is {lag} days after "
                                   f"{a.get('advisory_id')} ({a.get('published')}); pre-fix status "
                                   f"is {st.replace('_', ' ')} — compare with the vendor's fixed "
                                   f"releases.")
            rows.append(row)
    return rows


# ================================================================ assemble
def _best_version(prod: _Product):
    """(version, bases, confirmed) — prefer a confirmed basis, then the most-recent record."""
    best = None
    for ver, slot in prod.versions.items():
        conf = bool(CONFIRMED_BASES & set(slot["bases"]))
        key = (conf, max(slot["dates"] or [""]), "UNMAPPED" not in ver)
        if best is None or key > best[0]:
            best = (key, ver, slot["bases"], conf)
    return (best[1], best[2], best[3]) if best else (None, [], False)


def metered_gate(idb: dict) -> tuple:
    """(eligible, why) — a metered lookup (Shodan host, Censys host) is bought for an IP only when
    its keyless InternetDB record already shows a catalogue CPE, a settings.metered_gate_ports
    port or a settings.metered_gate_tags tag. Never raises."""
    idb = idb or {}
    if idb.get("status") != "ok":
        return False, (f"InternetDB {idb.get('status') or 'no answer'}: no index record to justify "
                       f"a metered lookup")
    for cpe in idb.get("cpes") or []:
        p = parse_cpe(cpe)
        if p and _cpe_product(p[0], p[1]):
            return True, f"catalogue CPE {cpe}"
    gate_ports = {int(p) for p in _s("metered_gate_ports") or [] if str(p).isdigit()}
    hit = sorted(gate_ports & {int(p) for p in idb.get("ports") or [] if str(p).isdigit()})
    if hit:
        return True, f"appliance port {hit[0]}"
    tags = sorted(set(_s("metered_gate_tags") or []) & set(idb.get("tags") or []))
    if tags:
        return True, f"tag {tags[0]}"
    return False, "InternetDB shows no catalogue CPE, appliance port or tag — metered lookup not bought"


def metered_plan(ips: list, idbs: dict, spend_reason: str) -> dict:
    """Decide BEFORE any spend which IPs get the metered legs and what that costs: gated by
    metered_gate, capped at settings.max_metered_ips, 1 credit per leg per IP."""
    cap = int(_s("max_metered_ips"))
    legs = {"shodan": shodan_configured(), "censys": censys_configured()}
    metered, skipped, why = [], {}, {}
    for ip in ips:
        if spend_reason:
            skipped[ip] = spend_reason
            continue
        eligible, reason = metered_gate(idbs.get(ip))
        if not eligible:
            skipped[ip] = reason
        elif not any(legs.values()):
            continue                    # no key: each source reports its own "not configured"
        elif len(metered) >= cap:
            skipped[ip] = f"metered cap of {cap} IP(s) reached (settings.max_metered_ips)"
        else:
            metered.append(ip)
            why[ip] = reason
    credits = {leg: (len(metered) if on else 0) for leg, on in legs.items()}
    credits["total"] = credits["shodan"] + credits["censys"]
    return {"cap": cap, "metered_ips": metered, "gate": why, "skipped": skipped,
            "planned_credits": credits,
            "credit_unit": "1 Shodan query credit + 1 Censys credit per metered IP, per configured key"}


def scan_ip(ip: str, kev: list, *, free_only: bool, spend_reason: str, extra_adv: list,
            analyst_confirmed: bool, analyst_edition=None, idb=None) -> dict:
    """spend_reason = why the metered legs are skipped for THIS IP ('' = buy them when keyed)."""
    sources = {}
    idb = idb if idb is not None else internetdb(ip)
    if free_only:
        spend_reason = "free_only: metered Shodan host / Censys skipped"
    elif not spend_reason:
        eligible, reason = metered_gate(idb)
        if not eligible:
            spend_reason = reason
    sources["internetdb"] = {k: v for k, v in idb.items() if k in ("status", "reason")}
    shodan = censys = None
    if spend_reason:
        sources["shodan"] = {"status": "skipped", "reason": spend_reason}
        sources["censys"] = {"status": "skipped", "reason": spend_reason}
    else:
        if shodan_configured():
            shodan = shodan_host_raw(ip)
            sources["shodan"] = {k: v for k, v in shodan.items() if k in ("status", "reason")}
        else:
            sources["shodan"] = {"status": "skipped", "reason": "no SHODAN_KEY configured"}
        if censys_configured():
            censys = censys_host_raw(ip)
            sources["censys"] = {k: v for k, v in censys.items() if k in ("status", "reason")}
        else:
            sources["censys"] = {"status": "skipped", "reason": "no CENSYS_PAT configured"}

    prods = fingerprint(idb, shodan if (shodan or {}).get("status") == "ok" else None,
                        censys if (censys or {}).get("status") == "ok" else None,
                        analyst_confirmed, analyst_edition)
    kev_by_cve = {e.get("cveID"): e for e in kev if isinstance(e, dict)}
    index_vulns = sorted(set((idb or {}).get("vulns") or []) | set((shodan or {}).get("vulns") or []))
    products, all_adv = [], []
    for pid in sorted(prods):
        p = prods[pid]
        spec = PRODUCTS.get(pid) or {}
        fam = kev_family(pid, kev)
        advs = _advisories_for(pid, fam, extra_adv)
        all_adv += advs
        lags = lag_rows(p, advs, kev_by_cve)
        ver, bases, confirmed = _best_version(p)
        read_from = "/".join(b for b in bases if b not in CONFIRMED_BASES) or "analyst input"
        confirmed_by = sorted(CONFIRMED_BASES & set(bases)) if confirmed else []
        prefix_kev = sorted({r["cve"] for r in lags if r["version_status"] == "pre-fix"
                             and r["announced_version"] == ver and r["cve"] in kev_by_cve})
        ambiguous_kev = sorted({r["cve"] for r in lags if r["version_status"] == "ambiguous_edition"
                                and r["announced_version"] == ver and r["cve"] in kev_by_cve})
        branch_kev = sorted({r["cve"] for r in lags if r["version_status"] == "branch_only"
                             and r["announced_version"] == ver and r["cve"] in kev_by_cve})
        edition, ed_basis = resolve_edition(pid, ver, p.versions[ver]) if ver else ("unknown", None)
        if prefix_kev and confirmed:
            esc, why = "CRITICAL", (f"version {ver} (read from {read_from}; confirmed by "
                                    f"{'/'.join(confirmed_by)}) is pre-fix for KEV "
                                    f"{', '.join(prefix_kev)}")
        elif fam:
            esc = "TENTATIVE"
            if prefix_kev:
                detail = (f"version {ver} (read from {read_from}) is pre-fix for KEV "
                          f"{', '.join(prefix_kev)} but not analyst-confirmed — verify it "
                          f"(/vuln-check, vendor advisory, authorised check) and re-run with "
                          f"--version-confirmed")
            elif ambiguous_kev:
                detail = (f"the edition of {ver} (standard vs FIPS/NDcPP) is unknown and the "
                          f"vendor's fixed releases for KEV {', '.join(ambiguous_kev)} differ by "
                          f"edition; no documented build range separates the trains — confirm the "
                          f"edition and re-run with --edition")
            elif branch_kev:
                detail = (f"version {ver} names only the branch, less specific than the fixed "
                          f"release for KEV {', '.join(branch_kev)} — it cannot be ordered against "
                          f"the fix; read the full build (vendor, authorised check) and re-run")
            else:
                detail = (f"version {ver or 'not announced'} not shown pre-fix for a KEV CVE in "
                          f"the advisory table — verify with /vuln-check")
            why = "KEV family match; " + detail
        else:
            esc, why = "NONE", ("no KEV entry for this product family" if kev else
                                "KEV catalogue unavailable — KEV mapping not assessed")
        km = [{"cve": e.get("cveID"), "vendor_project": e.get("vendorProject"),
               "product": e.get("product"), "name": e.get("vulnerabilityName"),
               "date_added": e.get("dateAdded"), "due_date": e.get("dueDate"),
               "ransomware_use": e.get("knownRansomwareCampaignUse"),
               "version_status": next((r["version_status"] for r in lags
                                       if r["cve"] == e.get("cveID") and r["announced_version"] == ver),
                                      "unknown"),
               "index_lists_cve": e.get("cveID") in index_vulns} for e in fam]
        products.append({
            "product_id": pid, "product": spec.get("name"), "vendor": spec.get("vendor"),
            "version": ver, "version_basis": bases, "version_confirmed": confirmed,
            "version_confirmed_by": "/".join(confirmed_by) or None,
            "edition": edition if PRODUCTS.get(pid, {}).get("editions") else None,
            "edition_basis": ed_basis if PRODUCTS.get(pid, {}).get("editions") else None,
            "versions_seen": {v: s for v, s in sorted(p.versions.items())},
            "evidence": p.evidence, "kev_matches": km, "patch_lag": lags,
            "escalation": esc, "escalation_reason": why,
            "caveats": [c for c in (_cav("general"), _cav("kev_family") if fam else "",
                                    _cav("lag_wording") if lags else "",
                                    _cav("kev_due") if any(r.get("past_kev_due") for r in lags) else "")
                        if c] + sorted({f"{r['advisory_id']}: {r['advisory_notes']}" for r in lags
                                        if r.get("advisory_notes") and r["version_status"] == "pre-fix"})})
    up, conflict = uptime_rows(shodan if (shodan or {}).get("status") == "ok" else None, all_adv)
    ports = sorted(set((idb or {}).get("ports") or [])
                   | {int(s["port"]) for r in (shodan, censys) for s in (r or {}).get("services") or []
                      if str(s.get("port") or "").isdigit()})
    risk = [dict(PORT_RISK[str(p)], port=p) for p in ports if str(p) in PORT_RISK]
    cav = [_cav("index_vulns")] if index_vulns else []
    if conflict:
        cav.append(_cav("ha_conflict"))
    order = {"CRITICAL": 2, "TENTATIVE": 1, "NONE": 0}
    if any(r.get("critical") for r in risk):
        cav.append("A container/cluster control-plane port is internet-facing in the index "
                   "record — hand off to techniques/cloud-audit.md.")
    return {"ip": ip, "hostnames": (idb or {}).get("hostnames") or [], "ports": ports,
            "tags": (idb or {}).get("tags") or [], "index_vulns": index_vulns,
            "sources": sources, "products": products, "uptime": up, "port_risk": risk,
            "escalation": max((p["escalation"] for p in products), key=order.get, default="NONE"),
            "caveats": [c for c in cav if c]}


def parse_advisory(spec: str) -> dict:
    """--advisory ID:YYYY-MM-DD[:fixed1,fixed2[:CVE]] -> an advisory row for every product."""
    parts = spec.split(":")
    if len(parts) < 2 or not _parse_dt(parts[1]):
        raise ValueError(f"--advisory needs ID:YYYY-MM-DD[:fixed,…[:CVE]], got {spec!r}")
    fixed = [f for f in (parts[2].split(",") if len(parts) > 2 else []) if f] or None
    return {"advisory_id": parts[0], "published": parts[1][:10], "fixed_in": fixed,
            "cve": parts[3] if len(parts) > 3 and parts[3] else None, "branch_depth": 2,
            "upgrade_reboots": None, "source": "analyst"}


def run(target: str, *, case=None, free_only=False, kev_file=None, refresh_kev=False,
        advisories=(), analyst_confirmed=False, analyst_edition=None) -> dict:
    target = (target or "").strip().lower().rstrip(".")
    if "://" in target:
        target = target.split("://", 1)[1]
    target = target.split("/", 1)[0]
    if not is_ip(target):
        target = target.split(":", 1)[0]
    spend_reason = ""
    if free_only:
        spend_reason = "free_only: metered Shodan host / Censys skipped"
    elif scope_no_spend(case):
        spend_reason = f"case {case} scope is no_spend: metered Shodan host / Censys skipped"
    meta = {"target": target, "generated_utc": _iso(_now()), "collector": COLLECTOR,
            "contacted_target": False, "free_only": bool(free_only), "case": case}
    if is_ip(target):
        ips, res = [target], {"method": "literal"}
    else:
        try:
            ips = [i for i in resolve_ips(target) if is_ip(i)]
            res = {"method": "resolver", "ips": ips}
        except Exception as exc:  # noqa: BLE001
            ips, res = [], {"method": "resolver", "error": f"{type(exc).__name__}: {exc}"}
    max_ips = int(_s("max_ips"))
    if len(ips) > max_ips:
        res["truncated_from"] = len(ips)
        ips = ips[:max_ips]
    kev, kev_meta = load_kev(kev_file, refresh_kev)
    kev_meta["count"] = len(kev)
    idbs = {ip: internetdb(ip) for ip in ips}          # keyless leg first: it gates the spend
    plan = metered_plan(ips, idbs, spend_reason)
    c = plan["planned_credits"]
    print(f"[appliance] planned metered credits: {c['total']} (shodan {c['shodan']}, censys "
          f"{c['censys']}) on {len(plan['metered_ips'])} of {len(ips)} IP(s), cap {plan['cap']}",
          file=sys.stderr)
    hosts = [dict(scan_ip(ip, kev, free_only=free_only,
                          spend_reason=plan["skipped"].get(ip, ""),
                          extra_adv=list(advisories), analyst_confirmed=analyst_confirmed,
                          analyst_edition=analyst_edition, idb=idbs[ip]),
                  host=target) for ip in ips]
    order = {"CRITICAL": 2, "TENTATIVE": 1, "NONE": 0}
    return {"meta": meta, "resolution": res, "kev": kev_meta, "metered_plan": plan,
            "advisory_table": {"verified_rows": len(ADVISORIES),
                               "ignored_unverified": ADVISORIES_IGNORED},
            "hosts": hosts,
            "escalation": max((h["escalation"] for h in hosts), key=order.get, default="NONE"),
            "caveats": [_cav("general")]}


def write_case(doc: dict, case: str) -> str:
    out = os.path.join(case_dir(case), "appliances.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    tmp = out + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    os.replace(tmp, out)
    return out


def write_kb_facts(doc: dict, kb_root: str, case=None, evidence_ref=None) -> int:
    """`appliance_product` + `kev_exposure` FACTS on the host entity — never an edge.
    `kev_exposure` is written ONLY for a KEV CVE whose version status is pre-fix; a family match
    on a fixed / branch_only / unknown / unlisted version records no exposure fact."""
    kb_dir = os.path.join(ENGINE, "tools", "kb")
    if kb_dir not in sys.path:
        sys.path.insert(0, kb_dir)
    from knowledge_base import KB  # noqa: E402
    kb = KB(kb_root, case=case)
    observed = doc["meta"]["generated_utc"]
    n = 0
    for h in doc["hosts"]:
        etype, value = ("ip", h["ip"]) if is_ip(h["host"]) else ("domain", h["host"])
        for p in h["products"]:
            conf = "medium" if p["version_confirmed"] else "low"
            label = f"{p['product']} {p['version'] or '(version not announced)'} [{h['ip']}]"
            kb.add_fact(etype, value, "appliance_product", label, "appliance_scan", COLLECTOR,
                        observed, conf, evidence_ref, case=case)
            n += 1
            for k in p["kev_matches"]:
                if k.get("version_status") != "pre-fix":
                    continue
                kb.add_fact(etype, value, "kev_exposure",
                            f"{k['cve']} ({p['escalation']}; version {k['version_status']}) [{h['ip']}]",
                            "appliance_scan", COLLECTOR, observed, conf, evidence_ref, case=case)
                n += 1
    return n


def _text(doc: dict) -> str:
    lines = [f"APPLIANCE SCAN {doc['meta']['target']} — escalation {doc['escalation']} "
             f"(passive; target not contacted) · KEV {doc['kev'].get('status')}"
             + (f": {doc['kev']['reason']}" if doc["kev"].get("reason") else "")]
    plan = doc.get("metered_plan") or {}
    if plan:
        c = plan.get("planned_credits") or {}
        lines.append(f"Metered plan: {c.get('total', 0)} credit(s) (shodan {c.get('shodan', 0)}, "
                     f"censys {c.get('censys', 0)}) on {len(plan.get('metered_ips') or [])} IP(s), "
                     f"cap {plan.get('cap')}")
    for h in doc["hosts"]:
        lines.append(f"Host: {h['host']} ({h['ip']})  ports {h['ports']}")
        for k, v in h["sources"].items():
            lines.append(f"  source {k}: {v.get('status')}" + (f" — {v['reason']}" if v.get("reason") else ""))
        for p in h["products"]:
            lines.append(f"  Product:   {p['product']}  version {p['version'] or '?'} "
                         f"({'/'.join(p['version_basis']) or 'none'})")
            for k in p["kev_matches"][:10]:
                lines.append(f"  KEV match: {k['cve']} ({k['version_status']})")
            lines.append(f"  Escalation: {p['escalation']} — {p['escalation_reason']}")
            for r in p["patch_lag"]:
                lines.append(f"  Lag:       {r['text']}")
        for u in h["uptime"]:
            lines.append(f"  Uptime:    {u['text']} {u['wrap_note']}")
            for v in u.get("vs_advisories") or []:
                lines.append(f"             {v['text']}")
        for r in h["port_risk"]:
            lines.append(f"  Port risk: {r['port']} {r['service']} — {r['why']}")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Passive edge-appliance fingerprint -> KEV -> patch lag.")
    ap.add_argument("target", help="domain, hostname or IP")
    ap.add_argument("--json", action="store_true", help="print the JSON result")
    ap.add_argument("--case", help="write cases/<id>/appliances.json; reads its scope no_spend")
    ap.add_argument("--kb", help="record appliance_product / kev_exposure FACTS in this KB dir")
    ap.add_argument("--free-only", action="store_true", help="skip metered Shodan host / Censys")
    ap.add_argument("--kev-file", help="use this KEV catalogue JSON (offline)")
    ap.add_argument("--refresh-kev", action="store_true", help="re-download KEV within its TTL")
    ap.add_argument("--advisory", action="append", default=[],
                    help="ID:YYYY-MM-DD[:fixed1,fixed2[:CVE]] — extra advisory for the lag rows")
    ap.add_argument("--version-confirmed", action="store_true",
                    help="the analyst verified the announced version(s) (basis analyst)")
    ap.add_argument("--edition", choices=sorted(_EDITION_FIELD),
                    help="the analyst verified the firmware edition (Citrix standard / fips / ndcpp)")
    a = ap.parse_args(argv)
    if a.case and not _CASE_RE.match(a.case):
        print(f"[appliance] invalid case id {a.case!r}", file=sys.stderr)
        return 2
    try:
        extra = [parse_advisory(s) for s in a.advisory]
    except ValueError as exc:
        print(f"[appliance] {exc}", file=sys.stderr)
        return 2
    if api_usage and a.case:
        api_usage.set_context(case=a.case, skill="WebPivot")
    doc = run(a.target, case=a.case, free_only=a.free_only, kev_file=a.kev_file,
              refresh_kev=a.refresh_kev, advisories=extra, analyst_confirmed=a.version_confirmed,
              analyst_edition=a.edition)
    if a.case:
        out = write_case(doc, a.case)
        print(f"[appliance] -> {out}", file=sys.stderr)
    if a.kb:
        ref = f"cases/{a.case}/appliances.json" if a.case else None
        n = write_kb_facts(doc, a.kb, a.case, ref)
        print(f"[appliance] {n} KB fact(s) recorded (facts only, no edges)", file=sys.stderr)
    print(json.dumps(doc, indent=2, ensure_ascii=False) if a.json else _text(doc))
    return 0


if __name__ == "__main__":
    sys.exit(main())
