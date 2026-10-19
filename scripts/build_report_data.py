#!/usr/bin/env python3
# /// script
# requires-python = ">=3.8"
# dependencies = []
# ///
"""
build_report_data.py — deterministic case -> flat report-JSON converter.

THE MISSING BRIDGE. The report generators (generate-cti-html.py, generate-cti-iocs.py,
generate-cti-docx-hybrid.py) all consume the flat "report JSON" documented in SKILL.md
§8 (subjects[]/findings[]/connections[]/timeline[]/indicators[]/…). Nothing produced it:
the deterministic pipeline (`intel.py pipeline open`) writes assessment.md, assessment.json
(engine schema), shared.txt, clusters.json and case_graph.json — but NOT that flat JSON.
So every /cti (= /case) Deliver step depended on an agent hand-authoring a large JSON by
hand; skip or thin it and the report renders with zero charts (the exact failure this fixes).

This turns a completed case directory into a populated, §2.5-clean report JSON with ZERO
LLM involvement and zero egress — reading only what the pipeline already wrote:

  raw/<host>.json      collected pivots (http/tech/cert/wp/mail/dns per host)
  whois/<host>.json    registrant triple (name/email/phone), registrar, dates, NS
  evidence/*.json      opportunistic sidecars (leak-sweep, estate-seo-sweep) -> findings
  clusters.json        read only to flag a multi-operator case (>1 cluster) as a caveat
  assessment.md        analyst BLUF (-> executive_summary) + Recommendation(s) section
  knowledge/operators.jsonl   confirmed-operator ledger (attribution + estate domain set)
  evidence/imported/, analyst_findings*.json, findings.json, enrichment/, intelx/, appdev/
                       analyst-graded evidence + app-store developer records (cti_case_evidence):
                       subjects / findings / connections with rung + Admiralty preserved — the
                       ONLY source on a non-domain (social / selector) case with an empty raw/
  scope.json + assessment.json   the case verdict -> `verdict.malicious_supported` (cti_refs),
                       the gate for any figure that would call a domain malicious

It degrades gracefully: a case missing any of these still yields a valid report JSON from
whatever is present. §2.5 discipline is preserved mechanically — shared/CDN infrastructure,
the registrar, nameservers and a saturated/parking favicon are emitted into `ioc_exclude`
(retained in the report narrative, gated out of IOC values), never asserted as operator links.

Usage:
    uv run build_report_data.py <case-dir> [-o <report.json>] [--print]
    python3 build_report_data.py cases/CASE-0001 -o cases/CASE-0001/report-data.json

Author: CTI Expert — https://github.com/7onez/cti-expert
"""
import argparse
import datetime
import functools
import ipaddress
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))   # sibling helpers
from cti_case_meta import case_classification, expansion_anchor, raw_name_index  # noqa: E402
from cti_case_evidence import build_layer, intake_seed  # noqa: E402
from cti_refs import malicious_verdict  # noqa: E402
from cti_text_normalize import normalize_obj  # noqa: E402


def _ct_and_related(raw_objs):
    """({host: CT summary}, [related-host rows], wp_related module) through the engine's shared
    reporting contract (evidence_report → wp_related) — the same rows assessment.md and the house
    report print. ({}, [], None) when the vendored engine is absent."""
    tools = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..",
                                          "intel_engine", "WebPivot", "tools"))
    if tools not in sys.path:
        sys.path.insert(0, tools)
    try:
        import evidence_report as ER  # noqa: PLC0415
    except Exception:  # noqa: BLE001
        return {}, [], None
    ct, rel = ER.ct_and_related(list(raw_objs))
    return ct, rel, ER.WR


GENERATOR = "CTI Expert — https://github.com/7onez/cti-expert"
SEVERITY = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
# raw sidecars that are not collected hosts (evidence bundles keyed like a host but not one)
_NON_HOST_STEMS = {"leak-sweep", "estate-seo-sweep", "shared-infra-note", "harvest.indicators"}


def _load_json(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None

def _enrichment(case_dir):
    """Expose executed third-party leads without inferring operator attribution."""
    index = _load_json(os.path.join(case_dir, "enrichment", "index.json"))
    leads = index.get("leads") if isinstance(index, dict) else None
    if not isinstance(leads, dict):
        return []
    return [{"key": key, "outcome": row.get("outcome", "?"),
             "summary": str(row.get("summary") or "")[:300],
             "file": row.get("file") or ""}
            for key, row in sorted(leads.items()) if isinstance(row, dict)]


def _n_clusters(case_dir):
    """Same-operator cluster count from clusters.json (engine's Louvain partition). >1 means the
    case spans multiple operators — this converter attributes only one, so the caller is warned."""
    c = _load_json(os.path.join(case_dir, "clusters.json"))
    try:
        return int(c.get("n_clusters")) if isinstance(c, dict) else None
    except (TypeError, ValueError):
        return None


def _ip_version(value):
    """4 / 6 for an IP address literal, else None."""
    try:
        return ipaddress.ip_address(str(value or "").strip().strip("[]")).version
    except ValueError:
        return None


def _ioc_type(value):
    """Indicator type of a network value: an address is `ipv4`/`ipv6`, never `domain`."""
    v = _ip_version(value)
    return "ipv4" if v == 4 else "ipv6" if v == 6 else "domain"


@functools.lru_cache(maxsize=1)
def _wp_common():
    """The engine's PSL-aware wp_common (public_suffix + rule tables), or None when not vendored."""
    tools = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..",
                                          "intel_engine", "WebPivot", "tools"))
    if tools not in sys.path:
        sys.path.insert(0, tools)
    try:
        import wp_common  # noqa: PLC0415
        return wp_common
    except Exception:  # noqa: BLE001
        return None


# RFC 2606 / RFC 6761 reserved names (documentation/test TLDs — never on the PSL, still hostnames).
_RESERVED_TLDS = frozenset({"example", "test", "invalid", "localhost"})
# RFC 1591 generic TLDs: a 3+-label token whose FIRST label is one of these is a reverse-DNS
# application id (com.vendor.app — an Android/iOS package), not a hostname.
_APP_ID_ROOTS = frozenset({"com", "org", "net", "edu", "gov", "mil", "int"})
_HOSTNAME_RE = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$")


def _registrable_domain(value):
    """True only for a real hostname under a Public-Suffix-List suffix (or an RFC 6761 reserved
    TLD): a file name (sellers.json, ads.txt), an app package (com.vendor, com.vendor.app) or a
    bare public suffix is not a domain. Without the vendored PSL nothing qualifies (conservative)."""
    v = str(value or "").strip().lower().rstrip(".")
    if not _HOSTNAME_RE.match(v) or _ip_version(v):
        return False
    labels = v.split(".")
    if len(labels) >= 3 and labels[0] in _APP_ID_ROOTS:
        return False
    if labels[-1] in _RESERVED_TLDS:
        return True
    W = _wp_common()
    rules, wild = getattr(W, "_PSL_RULES", None), getattr(W, "_PSL_WILD", None)
    if not rules:
        return False
    sfx = W.public_suffix(v)
    known = sfx in rules or sfx.partition(".")[2] in (wild or ())
    return known and v != sfx and v.endswith("." + sfx)


def _iter_raw(case_dir):
    """Yield (host, raw_dict) for every collected host pivot JSON — never an evidence sidecar."""
    d = os.path.join(case_dir, "raw")
    if not os.path.isdir(d):
        return
    for fn in sorted(os.listdir(d)):
        if not fn.endswith(".json") or fn.endswith(".impersonation.json"):
            continue
        stem = fn[:-5]
        if stem in _NON_HOST_STEMS:
            continue
        data = _load_json(os.path.join(d, fn))
        host = ((data or {}).get("meta") or {}).get("host") or stem
        if data is not None and ("." in host or _ip_version(host)):
            yield host.lower(), data


def _whois_of(case_dir, host, raw):
    """Registrant + registration record for a host: the whois/ sidecar wins (it carries the
    enriched registrant triple), else the raw collection's own whois block."""
    side = _load_json(os.path.join(case_dir, "whois", host + ".json"))
    if side:
        return side
    return ((raw.get("artifacts") or {}).get("whois")) or raw.get("whois") or {}


def _artifacts(raw):
    return raw.get("artifacts") or {}


def _cdn_ips_and_origins(raw):
    """§2.5: every CDN/shared edge IP and stale passive origin the collector already classified —
    these are infrastructure noise, never an operator link. Returns a set of IP strings."""
    out = set()
    for piv in raw.get("pivots") or []:
        dns = ((piv.get("live_results") or {}).get("dns")) or {}
        for c in dns.get("ip_classification") or []:
            if c.get("cdn") and c.get("ip"):
                out.add(c["ip"])
        for ip in dns.get("stale_passive_ips") or []:
            out.add(ip)
    return out


# wp_origin_history / IPPivot classification statuses that mark a SHARED address (edge, parking,
# bogon, proxy-or-host network, or unclassifiable) — never an operator-run box.
_SHARED_IP_CLASSES = frozenset({"cdn", "parking", "bogon", "ambiguous", "undetermined", "invalid"})


def _ip_link_block(ip, raw, created_by_host, exclude):
    """Why a collected IP may NOT carry an operator link (a reason string), or None for a dedicated
    CURRENT origin. Reads what the collector recorded: ip_intel.classification / noise (shared
    hosting, platform, CDN, parking) and meta.origin_context (wp_origin_history era vs the hosts'
    current registration)."""
    if ip in exclude:
        return "shared/CDN edge or stale passive origin"
    ii = _artifacts(raw).get("ip_intel") or {}
    cls = ii.get("classification") or {}
    status = str(cls.get("status") or cls.get("kind") or "").lower()
    if cls.get("cdn") or status in _SHARED_IP_CLASSES:
        return f"shared {status or 'CDN'} address"
    if ii.get("noise"):
        return "shared hosting / platform address" + (f" ({ii['noise_reason']})" if ii.get("noise_reason") else "")
    ctx = (raw.get("meta") or {}).get("origin_context") or {}
    if ctx.get("ambiguous"):
        return "proxy-or-host network (ambiguous origin)"
    era = ctx.get("era")
    last = str(ctx.get("last_seen") or "")[:10]
    regs = [created_by_host[k] for k in (str(h).lower() for h in ctx.get("hosts") or []) if created_by_host.get(k)]
    if era == "previous_owner" or (last and regs and all(last < r for r in regs)):
        return "last seen before the current registration (a previous owner's era)"
    if not (era == "current" or ctx.get("live")):
        return f"{era or 'undated'} tenancy, not a current origin"
    return None


def _parse_operator(op_field):
    """'Name (email@host)' -> (name, email). Either part may be absent."""
    m = re.match(r"^(.*?)\s*\(([^)]+@[^)]+)\)\s*$", op_field or "")
    if m:
        return m.group(1).strip(), m.group(2).strip().lower()
    return (op_field or "").strip(), None


def _operator_record(kb_dir, hosts):
    """The confirmed-operator ledger row whose domain set intersects this case's hosts (the
    largest such row — an estate ledger supersedes a single-case extension). None if unmatched."""
    path = os.path.join(kb_dir, "operators.jsonl")
    best = None
    hostset = {h.lower() for h in hosts}
    if os.path.isfile(path):
        for line in open(path, encoding="utf-8", errors="replace"):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            doms = {d.lower() for d in rec.get("domains") or []}
            if doms & hostset and (best is None or len(doms) > len(best.get("domains") or [])):
                best = rec
    return best


def _bluf(case_dir):
    """First substantive paragraph under a 'Bottom Line' / BLUF heading in assessment.md."""
    md = os.path.join(case_dir, "assessment.md")
    if not os.path.isfile(md):
        return ""
    lines = open(md, encoding="utf-8", errors="replace").read().splitlines()
    grab, buf = False, []
    for ln in lines:
        if ln.lstrip().startswith("#"):
            if grab:
                break
            grab = bool(re.search(r"bottom line|bluf|executive", ln, re.I))
            continue
        if grab:
            if ln.strip():
                buf.append(ln.strip())
            elif buf:
                break
    text = " ".join(buf).strip()
    return re.sub(r"[*`]", "", text)


def _recommendations(case_dir):
    """Bullet/numbered items under a 'Recommendation(s)' heading in assessment.md, else []."""
    md = os.path.join(case_dir, "assessment.md")
    if not os.path.isfile(md):
        return []
    lines = open(md, encoding="utf-8", errors="replace").read().splitlines()
    grab, out = False, []
    for ln in lines:
        if ln.lstrip().startswith("#"):
            if grab:
                break
            grab = bool(re.search(r"recommendation", ln, re.I))
            continue
        if grab:
            s = ln.strip()
            m = re.match(r"^(?:[-*]|\d+[.)])\s+(.*)$", s)
            if m:
                out.append(m.group(1).strip())
            elif s and out:
                out[-1] += " " + s
    return [r for r in out if r]


_PRIVACY_FALLBACK = re.compile(
    r"^(abuse|hostmaster|postmaster|noc|support|whois|privacy|proxy|redacted|registration"
    r"[\s_-]*private|redacted\s+for\s+privacy|not\s+disclosed|data\s+protected|n/?a)\b"
    r"|privatewhois|whoisguard|domainsbyproxy|withheldforprivacy|contactprivacy|privacyprotect",
    re.I,
)


def _privacy_checker(case_dir):
    """The engine's registrant privacy/role detector (whois_enrich.is_privacy) — the same test the
    ingest and frontier apply, so the report cannot promote a registrar abuse address or a
    privacy-proxy placeholder to the operator's identity when those layers already discard it.
    Falls back to a conservative pattern when the case dir is not inside an engine tree."""
    engine = os.path.normpath(os.path.join(os.path.abspath(case_dir), "..", ".."))
    wp_tools = os.path.join(engine, "WebPivot", "tools")
    if os.path.isfile(os.path.join(wp_tools, "whois_enrich.py")):
        if wp_tools not in sys.path:
            sys.path.insert(0, wp_tools)
        try:
            from whois_enrich import is_privacy  # noqa: E402
            return is_privacy
        except Exception:
            pass
    return lambda v: (not v) or bool(_PRIVACY_FALLBACK.search(str(v).strip()))


def _whois_eras_module(case_dir):
    """The shared whois_eras module (owner_values/prior_values — WebPivot/tools/whois_eras.py),
    resolved the same way _privacy_checker resolves whois_enrich: relative to the case's own
    engine tree, with a conservative no-op fallback (nothing is ever a 'prior' value) when the
    engine is not vendored alongside (e.g. a case dir built outside intel_engine/)."""
    engine = os.path.normpath(os.path.join(os.path.abspath(case_dir), "..", ".."))
    wp_tools = os.path.join(engine, "WebPivot", "tools")
    if os.path.isfile(os.path.join(wp_tools, "whois_eras.py")):
        if wp_tools not in sys.path:
            sys.path.insert(0, wp_tools)
        try:
            import whois_eras  # noqa: E402
            return whois_eras
        except Exception:
            pass

    class _NoEras:
        @staticmethod
        def prior_values(_whois, _kind):
            return []
    return _NoEras()


_NOMINEE_RE = re.compile(r"\b(nominee|front|proxy|straw)\b", re.I)
_CANNOT_RULE_OUT_RE = re.compile(r"cannot[\s_-]*rule[\s_-]*out", re.I)


def _nominee_uncertain(alternatives):
    """True when an assessment.json alternative names a nominee/front/proxy/straw explanation the
    analyst marked 'cannot rule out' — the registrant is a WHOIS persona, not an asserted operator
    (IntelAnalysis persona doctrine); connections to every collected host stay `registered`, never
    `operates`."""
    for alt in alternatives or []:
        s = alt if isinstance(alt, str) else f"{alt.get('hypothesis','')} {alt.get('status','')} {alt.get('why','')}"
        s = str(s)
        if _NOMINEE_RE.search(s) and _CANNOT_RULE_OUT_RE.search(s):
            return True
    return False


def _report_exclude(case_dir):
    """Analyst exclusion list: <case>/report_exclude.json (a JSON list of literal selector values —
    an unverified marketing partner's domain, a mis-attributed contact) never emitted as an IOC."""
    data = _load_json(os.path.join(case_dir, "report_exclude.json"))
    return {str(x).strip().lower() for x in data} if isinstance(data, list) else set()


_SELECTOR_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_SELECTOR_URL_RE = re.compile(r"https?://[^\s,;()\[\]\"']+")
_SELECTOR_PHONE_RE = re.compile(r"(?<![\w.])(\+?84[.\s-]?\d{9,10}|0\d{9,10}|\+\d{1,3}[.\s-]?\d{7,12})(?![\w])")
_SELECTOR_DOMAIN_RE = re.compile(r"\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b", re.I)


def _cluster_selectors(assessment):
    """Operator selectors the analyst's own cluster[].shared_artifacts already assert — e-mail,
    phone, domain, IP and URL values only (a favicon hash / GA id / tech fingerprint is a same-kit
    signal, not a report-subject selector). A domain value must be a real registrable hostname; an
    address is typed ipv4/ipv6."""
    out = []
    for m in (assessment.get("cluster") or []):
        for art in (m.get("shared_artifacts") or []) if isinstance(m, dict) else []:
            s = str(art or "")
            if ":" in s and not _ip_version(s):
                kind, _sep, value = s.partition(":")
            else:
                kind, value = "", s
            kind, value = kind.strip().lower(), value.strip()
            if not value:
                continue
            if kind in ("email", "registrant_email") or _SELECTOR_EMAIL_RE.fullmatch(value):
                out.append(("email", value.lower()))
            elif kind in ("phone", "registrant_phone"):
                out.append(("phone", value))
            elif kind == "url" or value.startswith(("http://", "https://")):
                out.append(("url", value))
            elif kind in ("ip", "ipv4", "ipv6", "domain", "registrant_domain", "") and _ip_version(value):
                out.append((_ioc_type(value), value))
            elif kind in ("domain", "registrant_domain", "") and _registrable_domain(value):
                out.append(("domain", value.lower()))
    return out


def _evidence_selectors(assessment):
    """E-mail/phone/domain values named in an assessment.json evidence[] line — the operator
    selectors an analyst cited in prose but did not also put in cluster[].shared_artifacts. Prose
    is not a structured field: a dotted token becomes a domain only when it is a real registrable
    hostname (never a file name like sellers.json / ads.txt or an app id like com.vendor.app), and
    a URL quoted in prose (a store listing, a reference page) is never an indicator."""
    out = []
    for e in (assessment.get("evidence") or []):
        s = e if isinstance(e, str) else json.dumps(e, ensure_ascii=False)
        for m in _SELECTOR_EMAIL_RE.finditer(s):
            out.append(("email", m.group(0).lower()))
        for m in _SELECTOR_PHONE_RE.finditer(s):
            out.append(("phone", m.group(0)))
        s_stripped = _SELECTOR_URL_RE.sub(" ", _SELECTOR_EMAIL_RE.sub(" ", s))
        for m in _SELECTOR_DOMAIN_RE.finditer(s_stripped):
            if _registrable_domain(m.group(0)):
                out.append(("domain", m.group(0).lower()))
    return out


def _cld_denylisted(cld_block):
    """A concrete ChongLuaDao denylist LISTING (checkurl) for this host's own live_results.cld
    block — a bare reputation label with no listing is not asserted. Mirrors the denylist test in
    WebPivot/tools/wp_cld.verdict_of without importing across the engine boundary."""
    if not isinstance(cld_block, dict):
        return False
    cu = cld_block.get("checkurl")
    cu = cu if isinstance(cu, dict) else {}
    result = cu.get("result") or cu.get("verdict") or (cu.get("data") or {}).get("verdict")
    return bool(result and str(result).lower() in ("malicious", "suspicious", "phishing", "scam"))


def build(case_dir, kb_dir, classification=None):
    case_id = os.path.basename(os.path.abspath(case_dir).rstrip("/"))
    raws = dict(_iter_raw(case_dir))
    hosts = sorted(raws)
    from cti_case_meta import resolve_seed
    seed = (resolve_seed(case_dir, hosts, [os.path.join(case_dir, "raw", h + ".json") for h in hosts]) if hosts
            else (intake_seed(case_dir) or case_id))     # non-domain intake: the social/selector seed

    op_rec = _operator_record(kb_dir, hosts)
    estate = sorted({d.lower() for d in (op_rec or {}).get("domains") or []} | set(hosts))
    op_name, op_email = _parse_operator((op_rec or {}).get("operator", ""))

    # registrant triple — sidecar whois of the seed wins, but a privacy-proxy / registrar-role
    # value (abuse@<registrar>, "REDACTED FOR PRIVACY", …) is not an identity: drop it so the
    # operator ledger or "Unattributed operator" takes over instead of a false rung-1 claim.
    is_privacy = _privacy_checker(case_dir)
    wx_eras = _whois_eras_module(case_dir)
    prior_selector_values = set()
    for h, raw_h in raws.items():
        who_h = _whois_of(case_dir, h, raw_h)
        for kind in ("email", "phone"):
            for item in wx_eras.prior_values(who_h, kind):
                v = str(item.get("value") or "").strip().lower()
                if v:
                    prior_selector_values.add(v)
    reg = _whois_of(case_dir, seed, raws.get(seed, {})) if seed in raws else {}
    reg = {k: (None if is_privacy(v) else v) for k, v in reg.items()
           if k in ("registrant_name", "registrant_email", "registrant_phone", "registrant_org")}
    reg_name = reg.get("registrant_name") or op_name or None
    reg_email = reg.get("registrant_email") or op_email or None
    reg_phone = reg.get("registrant_phone") or None
    reg_org = reg.get("registrant_org") or None
    op_username = op_email.split("@")[0] if op_email else None
    assessment = _load_json(os.path.join(case_dir, "assessment.json")) or {}
    attribution_level = str(assessment.get("attribution_level") or "").lower()
    nominee_uncertain = _nominee_uncertain(assessment.get("alternatives"))
    default_relationship = ("operates" if (("same-operator" in attribution_level or "same-actor" in attribution_level)
                                            and not nominee_uncertain) else "registered")

    exclude = set()          # §2.5 ioc_exclude
    registrars, nameservers = set(), set()
    timeline, sources, subjects, findings, connections, indicators = [], [], [], [], [], []
    seen_src = set()

    def add_source(name, url, date, indicator=False):
        key = (name, url)
        if url and key not in seen_src:
            seen_src.add(key)
            # sources are provenance; only the case's own live page is an indicator (IOC export)
            sources.append({"name": name, "url": url, "date": date, **({"indicator": True} if indicator else {})})

    # ---- per-host registrant match --------------------------------------------
    # Only the registrant e-mail / phone are decisive join keys. A collected host is wired to the
    # operator as CONFIRMED only when its OWN current record carries one of them (or the ledger
    # lists it, or it is the seed); a host whose record names a DIFFERENT real registrant is only
    # related_to/possible; a privacy-masked or absent record stays probable (unknown). Counts in
    # FND-001 / the summary use the hosts that really share the identity, never every collected host.
    def _digits(p):
        return re.sub(r"\D", "", str(p or ""))

    id_email = (reg_email or "").strip().lower()
    id_phone = _digits(reg_phone)
    host_match = {}          # host -> True (shares the identity) / False (different owner) / None
    for h in hosts:
        who_h = _whois_of(case_dir, h, raws[h])
        e = who_h.get("registrant_email")
        p = who_h.get("registrant_phone")
        e = None if (not e or is_privacy(e)) else str(e).strip().lower()
        p = None if (not p or is_privacy(p)) else _digits(p)
        if (id_email and e == id_email) or (id_phone and p and p == id_phone):
            host_match[h] = True
        elif e or p:
            host_match[h] = False
        else:
            host_match[h] = None
    matched = sorted(h for h, m in host_match.items() if m)
    ledger_domains = {d.lower() for d in (op_rec or {}).get("domains") or []}
    n_shared = len(set(matched) | ledger_domains)

    # ---- operator subject (actor) --------------------------------------------
    operator_exists = bool(reg_name or reg_org or op_name or reg_email or reg_phone)
    if operator_exists:
        selectors = []
        if reg_email:
            selectors.append({"type": "email", "value": reg_email})
        if reg_phone:
            selectors.append({"type": "phone", "value": reg_phone})
        if op_username:
            selectors.append({"type": "username", "value": op_username})
        is_org = bool(reg_org)
        label = reg_org if is_org else (reg_name or op_name or reg_email or "Unattributed operator")
        attributes = {}
        if is_org and reg_name and reg_name.strip().lower() != reg_org.strip().lower():
            attributes["legal_representative"] = reg_name
        subjects.append({
            "id": "SUB-001", "label": label,
            "type": "organization" if is_org else "person", "role": "actor",
            "confidence": 95 if reg_email and reg_phone else 80, "verified": bool(reg_email),
            "aliases": [op_name] if op_name and op_name != (reg_name or "") else [],
            "first_seen": None,
            "notes": ("Assessed operator identity from the recurring current registrant triple "
                      f"across {n_shared} domain(s)." if reg_email else
                      "Operator identity from the confirmed-operator ledger."),
            "selectors": selectors,
            **({"attributes": attributes} if attributes else {}),
        })
        # curated identity indicators (one row per value — the reachable/profiling selectors)
        if reg_email:
            indicators.append({"type": "email", "value": reg_email, "category": "contact",
                               "role": "actor", "confidence": 95})
        if reg_phone:
            indicators.append({"type": "phone", "value": reg_phone, "category": "contact",
                               "role": "actor", "confidence": 95})
        if op_username:
            indicators.append({"type": "username", "value": op_username, "category": "identity",
                               "role": "actor", "confidence": 85})

    # ---- per-collected-host subjects + infra facts ---------------------------
    anchor = expansion_anchor(case_dir)       # one leaf rule, shared with house_report (cti_case_meta)
    hops, depth = anchor.hops, anchor.depth
    raw_names = raw_name_index(case_dir)
    leaves = []
    sub_by_host = {}
    # every domain host's current registration date + every CDN/stale origin the domain raws name,
    # gathered before the loop so an IP raw is judged against the whole case, not the hosts before it
    created_by_host = {}
    for h in hosts:
        exclude |= _cdn_ips_and_origins(raws[h])
        if not _ip_version(h):
            c = (_whois_of(case_dir, h, raws[h]).get("created") or "")[:10]
            if c:
                created_by_host[h] = c
    for i, h in enumerate(hosts, start=2):
        raw = raws[h]
        art = _artifacts(raw)
        who = _whois_of(case_dir, h, raw)
        sid = f"SUB-{i:03d}"
        sub_by_host[h] = sid
        is_ip = bool(_ip_version(h))
        http = (art.get("http") or {}).get("status") or (raw.get("http") or {}).get("status")
        themes = art.get("wp_themes") or raw.get("wp_themes") or []
        created = (who.get("created") or "")[:10] or None
        registrar = who.get("registrar")
        if registrar:
            registrars.add(registrar)
        for ns in who.get("name_servers") or []:
            nameservers.add(ns.lower())
        names = raw_names.get(h, {h}) | {h}
        if h == seed:                 # the case's own seed is hop 0 and never a leaf
            hop, leaf = 0, False
        else:
            hop = anchor.hop(*names)
            leaf = anchor.is_leaf(*names)
        if leaf:
            leaves.append(h)
        # an IP carries an operator link only as a dedicated CURRENT origin; a CDN / parking /
        # shared-hosting / platform address or a historical / previous-owner era is context only
        ip_block = _ip_link_block(h, raw, created_by_host, exclude) if is_ip else None
        if ip_block:
            exclude.add(h)
        subjects.append({
            "id": sid, "label": h, "type": "ip" if is_ip else "domain",
            "role": "related" if leaf else "infrastructure",
            "confidence": 95 if h == seed else (60 if leaf or ip_block else 85), "verified": True, "aliases": [],
            "first_seen": created,
            "notes": (f"Collected {'address' if is_ip else 'host'}; HTTP {http or 'n/a'}"
                      + (f"; {', '.join(themes)} kit" if themes else "")
                      + (f"; registrar {registrar}" if registrar else "")
                      + (f"; {ip_block} — not an operator link, excluded from IOCs" if ip_block else "")
                      + (f"; hop {hop} — owner-linked to a hop-{hop - 1} host, NOT to the operator: "
                         "collected to bound the estate, excluded from IOCs" if leaf else "") + "."),
            **({"ioc_exclude": True, "hop": hop} if leaf else ({"hop": hop} if hops else {})),
        })
        if operator_exists and not leaf and not ip_block:
            # confirmed = the seed, a ledger-listed host, or a host whose OWN current record carries
            # the registrant e-mail/phone (and only at hop 0 — a hop-1 host is at best probable);
            # the STIX/graph edge must say which. A different real registrant is never "operates".
            m = host_match.get(h)
            if h == seed or h.lower() in ledger_domains or m:
                rel, strength = default_relationship, ("confirmed" if hop == 0 else "probable")
            elif m is False:            # its own record names a different real registrant
                rel, strength = "related_to", "possible"
            else:                       # privacy-masked / no record: unknown, never confirmed
                rel, strength = default_relationship, "probable"
            connections.append({"id": f"CON-{len(connections)+1:03d}", "from_id": "SUB-001",
                                "to_id": sid, "relationship": rel, "strength": strength})
        elif (leaf or ip_block) and operator_exists:
            connections.append({"id": f"CON-{len(connections)+1:03d}", "from_id": "SUB-001",
                                "to_id": sid, "relationship": "related_to", "strength": "possible"})
        if created:
            timeline.append({"date": created, "event": f"{h} registered"
                             + (f" through {registrar}" if registrar else "")})
        if not leaf and not ip_block:
            indicators.append({"type": _ioc_type(h), "value": h, "category": "network",
                               "role": "infrastructure", "confidence": 95 if h == seed else 85})
        # provenance from the seed's own live page / rdap
        if h == seed:
            add_source("Live page", raw.get("meta", {}).get("final_url") or f"https://{h}/",
                       (raw.get("meta", {}).get("collected_at") or "")[:10] or None, indicator=True)

    # estate domains attributed by the ledger but not individually collected -> IOC only (§2.5:
    # do not mint a per-domain subject node without per-domain evidence; keep the entity graph honest)
    estate_only = [d for d in estate if d not in raws]

    # ---- findings ------------------------------------------------------------
    def add_finding(fid, subject_id, ftype, weight, desc, src, conf, tags):
        findings.append({"id": fid, "subject_id": subject_id, "type": ftype,
                         "weight": weight if weight in SEVERITY else "INFO",
                         "description": desc, "source_url": src,
                         "collected_at": (op_rec or {}).get("added") or _today(),
                         "confidence": int(conf), "tags": tags})

    if reg_email and reg.get("registrant_email"):
        # the seed's CURRENT WHOIS carries the identity — the registrant-triple claim is earned
        add_finding("FND-001", "SUB-001", "identity", "HIGH",
                    (f"The registrant identity ({', '.join(x for x in [reg_name, reg_email, reg_phone] if x)}) "
                     f"recurs across {len(matched)} current domain(s). The analyst assesses this "
                     "owner-controlled triple as decisive same-operator evidence."),
                    None, 95, ["attribution", "whois", "registrant-triple", "rung-1"])
    elif reg_email:
        # identity comes from the confirmed-operator ledger, not from a current registrant record —
        # say so; the current WHOIS may be privacy-masked and the e-mail a contact, not a registrant
        add_finding("FND-001", "SUB-001", "identity", "HIGH",
                    (f"Operator identity {reg_name or reg_email} ({reg_email}) per the confirmed-operator "
                     f"ledger, covering {n_shared} domain(s). The current registrant record of the seed "
                     "does not itself carry this identity (privacy-masked or name-only); the basis is the "
                     "ledger entry's cited artifacts."),
                    None, 90, ["attribution", "ledger", "identity"])
    if seed in raws:
        seed_meta = raws[seed].get("meta") or {}
        if seed_meta.get("live_error"):
            basis_phrase = (f"{seed} was recovered from archive" if seed_meta.get("recovered_via")
                            else f"{seed} was not reachable at collection time")
        else:
            basis_phrase = (f"{seed} was collected live" +
                            (f" (HTTP {(_artifacts(raws[seed]).get('http') or {}).get('status')})"
                             if (_artifacts(raws[seed]).get('http') or {}).get('status') else ""))
        add_finding("FND-002", sub_by_host.get(seed, "SUB-002"), "infrastructure", "HIGH",
                    (basis_phrase + ". Shared CDN edges, origins, registrar and nameservers are "
                     "infrastructure context and are not attributed to the operator."),
                    raws[seed].get("meta", {}).get("final_url"), 90,
                    ["live-state", "shared-infrastructure"])
    if op_rec:
        add_finding("FND-003", "SUB-001" if operator_exists else sub_by_host.get(seed, "SUB-002"),
                    "behavioral", "HIGH",
                    (f"Ledger attribution: {op_rec.get('confidence', 'assessed')} — "
                     + (op_rec.get("basis") or "same registrant triple across the estate.")),
                    None, 92, ["attribution", "estate", "ledger"])

    # ---- §2.5 false-positive control finding + ioc_exclude -------------------
    exclude |= registrars | nameservers
    # Shared distribution / sideload platforms are provider-level co-tenancy, not operator IOCs:
    exclude.update(["app.mycowbay.com", "app.dataruapp.com", "mycowbay.com", "dataruapp.com", "vk.com"])
    # On a benign_check intake the operator is a legitimate party under review: their e-mail/phone/
    # handle are identity EVIDENCE for the narrative, not detection indicators — a STIX/CSV consumer
    # would block a real business's contact address. Keep them in the subjects, out of the IOC feed.
    # (Their NAME is never listed: ioc_exclude is the infra-noise list, and a name is no IOC value.)
    scope = _load_json(os.path.join(case_dir, "scope.json")) or {}
    if (scope.get("target_class") or "") == "benign_check":
        exclude |= {v for v in (reg_email, reg_phone, op_username) if v}
    # the attributed operator's own label is never infrastructure noise, however it was collected
    # (a registrar/NS string that equals it, a ledger label)
    operator_labels = {str(v).strip().lower() for v in (
        reg_name, reg_org, op_name, (op_rec or {}).get("operator"), (op_rec or {}).get("label"),
        subjects[0]["label"] if operator_exists else None) if v}
    exclude = {x for x in exclude if str(x).strip().lower() not in operator_labels}
    fp_bits = []
    if registrars:
        fp_bits.append("registrar " + "/".join(sorted(registrars)))
    if nameservers:
        fp_bits.append(f"{len(nameservers)} shared nameserver(s)")
    ip_excl = sorted(x for x in exclude if _ip_version(x))
    if ip_excl:
        fp_bits.append("shared/CDN origins " + ", ".join(ip_excl))
    if fp_bits:
        add_finding(f"FND-{len(findings)+1:03d}", sub_by_host.get(seed, "SUB-001"),
                    "infrastructure", "INFO",
                    "Rejected as operator-level links (commodity or multi-tenant): "
                    + "; ".join(fp_bits) + ".",
                    None, 96, ["false-positive-control", "shared-infrastructure"])

    # ---- opportunistic evidence sidecars (known filenames; skipped if absent) -
    leak = _load_json(os.path.join(case_dir, "evidence", "leak-sweep.json"))
    if leak and isinstance(leak.get("verdict"), str):
        add_finding(f"FND-{len(findings)+1:03d}",
                    "SUB-001" if operator_exists else sub_by_host.get(seed, "SUB-002"),
                    "exposure", "INFO",
                    "Breach / infostealer sweep: " + leak["verdict"][:600], None, 90,
                    ["negative-finding", "breach", "infostealer"])
    sweep = _load_json(os.path.join(case_dir, "evidence", "estate-seo-sweep.json"))
    if sweep and sweep.get("verdict"):
        confirmed = list((sweep.get("operator_era_doorway_confirmed") or {}))
        add_finding(f"FND-{len(findings)+1:03d}", sub_by_host.get(seed, "SUB-001"),
                    "behavioral", "HIGH", sweep["verdict"][:600]
                    + (f" Confirmed apexes: {', '.join(confirmed)}." if confirmed else ""),
                    None, 93, ["campaign", "doorway", "seo-spam"])
        for d in confirmed:
            if d not in {i["value"] for i in indicators}:
                indicators.append({"type": _ioc_type(d), "value": d.lower(),
                                   "category": "network", "role": "infrastructure", "confidence": 80})

    # estate domains as network indicators (deduped)
    known = {i["value"] for i in indicators}
    for d in estate_only:
        if d not in known:
            indicators.append({"type": _ioc_type(d), "value": d, "category": "network",
                               "role": "infrastructure", "confidence": 75})

    # ---- assessment-asserted operator selectors + CLD denylist rows (still §2.5-gated: a value
    # that is a PREVIOUS registration era's registrant, a registrar/privacy contact, or listed in
    # the analyst's own report_exclude.json is never the operator's, however it was named) -------
    excluded_selectors = _report_exclude(case_dir)
    known = {str(i["value"]).lower() for i in indicators}

    def _selector_ok(kind, value):
        vl = value.strip().lower()
        if not vl or vl in excluded_selectors or vl in prior_selector_values:
            return False
        if kind in ("email", "phone") and is_privacy(value):
            return False
        if kind in ("ipv4", "ipv6") and vl in exclude:      # a shared / historical address
            return False
        return True

    for kind, value in _cluster_selectors(assessment) + _evidence_selectors(assessment):
        if not _selector_ok(kind, value):
            continue
        vl = value.strip().lower()
        if vl in known:
            continue
        known.add(vl)
        is_dist = any(vl == s or vl.endswith("." + s) for s in ("mycowbay.com", "dataruapp.com"))
        role = "distribution" if is_dist else "actor"
        indicators.append({"type": kind, "value": value.strip(),
                           "category": "identity" if kind in ("email", "phone") else "network",
                           "role": role, "confidence": 60 if is_dist else 80})

    for h, raw_h in raws.items():
        for piv in raw_h.get("pivots") or []:
            if not isinstance(piv, dict):
                continue
            if not _cld_denylisted((piv.get("live_results") or {}).get("cld")):
                continue
            url = (raw_h.get("meta") or {}).get("final_url") or f"https://{h}/"
            if not _selector_ok("url", url):
                continue
            vl = url.strip().lower()
            if vl in known:
                continue
            known.add(vl)
            indicators.append({"type": "url", "value": url, "category": "network",
                               "role": "infrastructure", "confidence": 90})

    # ---- analyst-graded case evidence (evidence_import, analyst_findings*, findings.json,
    # enrichment/, intelx/, appdev/) — the only source on a non-domain case, merged otherwise ----
    layer = build_layer(case_dir, subjects=subjects, findings=findings, connections=connections,
                        sub_by_host=sub_by_host, benign=(scope.get("target_class") or "") == "benign_check",
                        default_sid=("SUB-001" if operator_exists else sub_by_host.get(seed)),
                        seed_label=seed, today=_today())
    subjects += layer["subjects"]
    findings += layer["findings"]
    connections += layer["connections"]
    for s in layer["sources"]:
        add_source(s["name"], s["url"], s["date"])
    exclude |= set(layer["ioc_exclude"])

    # ---- gaps + recommendations + summary -----------------------------------
    gaps = list(layer["gaps"])
    if estate_only:
        gaps.append(f"{len(estate_only)} attributed estate domain(s) are exported as indicators "
                    "but not individually collected — per-domain registration/live-state detail "
                    "was not gathered this run.")
    if hosts and not reg_email:
        gaps.append("No current registrant triple recovered — attribution rests on the ledger only.")
    if leaves:
        gaps.append(f"{len(leaves)} collected host(s) sit at expansion hop >= {depth} (owner-linked to a "
                    "previous-hop host, not to the operator): kept as `related` subjects for context, "
                    "wired `related_to`, and excluded from the IOC bundle — attribute them only after a "
                    "join key to the operator is shown.")
    n_clusters = _n_clusters(case_dir)
    if n_clusters and n_clusters > 1:
        gaps.append(f"clusters.json reports {n_clusters} operator clusters for this case; this "
                    "converter attributes a SINGLE operator (largest ledger row) and wires it to "
                    "every collected host. Re-run per cluster or hand-author subjects for a genuine "
                    "multi-operator case.")
        sys.stderr.write(f"build_report_data: WARNING — clusters.json has {n_clusters} clusters; "
                         "single-operator attribution may over-attribute (see intelligence_gaps).\n")
    recs = _recommendations(case_dir) or [
        "Preserve the current registration records before contacts are masked or domains lapse.",
        "Submit brand-abuse referrals with the operator IOC set (registrant triple + estate domains).",
        "Monitor certificate-transparency, DNS and HTTP liveness across the attributed estate.",
        "Keep shared hosting / registrar / nameserver artifacts out of the operator ledger.",
    ]
    if operator_exists:
        fallback_sum = (
            f"{seed} is attributed to {reg_name or op_name or 'a single operator'} with "
            f"{n_shared} domain(s) sharing the registrant identity. Shared infrastructure signals "
            "were excluded from operator-level clustering per §2.5.")
    elif not hosts:
        # non-domain intake (a social account, a person, a selector): nothing was collected as a host
        fallback_sum = (
            f"Non-domain case opened on {seed}: {len(layer['findings'])} graded finding(s) and "
            f"{len(layer['subjects'])} subject(s) from the case evidence; no host infrastructure was "
            "collected and no operator attribution is made beyond what each finding's grading states.")
    else:
        # No registrant name/org/e-mail/phone and no ledger row: there is no operator to name, so the
        # default must not claim one (an empty or all-failed case used to read "attributed to a single
        # operator with 0 domain(s)").
        unreachable = sum(1 for h in hosts
                          if (raws[h].get("meta") or {}).get("live_error")
                          and not (raws[h].get("meta") or {}).get("recovered_via"))
        fallback_sum = (
            f"No operator identity was recovered for {seed}: {len(hosts)} host(s) collected"
            + (f", {unreachable} unreachable at collection time" if unreachable else "")
            + ". No single-operator attribution is made; shared-infrastructure signals were "
            "excluded per §2.5.")
    exec_sum = _bluf(case_dir) or fallback_sum

    # third-party masking for the shareable bundle — prose fields only; indicator VALUES are the
    # operator's own IOCs (already gated by ioc_exclude) and are never rewritten.
    from cti_third_party_mask import mask_third_parties, load_case_mask, load_case_keep
    keep = ({v for v in (reg_email, reg_phone) if v}
            | {str(v).strip().lower() for v in load_case_keep(case_dir) if v})
    extra = load_case_mask(case_dir)
    _mask = lambda s: mask_third_parties(s, keep=keep, hosts=set(estate) | {seed}, extra=extra, current_case=case_id)  # noqa: E731
    exec_sum = _mask(exec_sum)

    def _enrichment_selector(key):
        return key.split(":", 1)[1] if ":" in key else key

    def _enrichment_dropped(key):
        sel = _enrichment_selector(key).strip().lower()
        return bool(sel) and (sel in prior_selector_values or is_privacy(sel))

    enrichment = [{**row, "key": _mask(row["key"]), "summary": _mask(row["summary"])}
                  for row in _enrichment(case_dir) if not _enrichment_dropped(row["key"])]
    incomplete = [{"key": row["key"], "reason": row["outcome"]}
                  for row in enrichment if row["outcome"] in ("held", "unavailable", "retry", "empty")]
    state = _load_json(os.path.join(case_dir, "state.json")) or {}
    done = state.get("enrichment_done") if isinstance(state, dict) else {}
    if isinstance(done, list):            # legacy flat-list form (case_state._done_map parity)
        done = {k: "ran" for k in done}
    for key, reason in (done if isinstance(done, dict) else {}).items():
        if reason in ("empty", "unavailable", "skipped") and not any(
                row["key"] == _mask(key) for row in enrichment):
            incomplete.append({"key": _mask(key), "reason": reason})
    if incomplete:
        gaps.append(f"{len(incomplete)} enrichment lead(s) held, unavailable, retryable, or "
                    "without a finding (see enrichment_gaps; not a negative verdict).")

    # ---- certificate transparency + pivot hits (shared contract: wp_related) ----------------
    ct_history, related_hosts, _wr = _ct_and_related(raws.values())
    if _wr:
        gaps += _wr.ct_gap_lines(ct_history)
    if related_hosts:
        promoted = sum(1 for r in related_hosts if len(r["passed"]) >= 2)
        gaps.append(f"{len(related_hosts)} related host(s) share a certificate, favicon or tracking ID "
                    f"with the estate (see related_hosts): {promoted} reach two agreeing origin checks. "
                    "None is the estate's hosting or a takedown recipient.")

    verdict_ok, verdict_basis = malicious_verdict(case_dir)

    report = {
        "generator": GENERATOR,
        "case": {
            "id": case_id,
            "label": (op_rec or {}).get("label") or f"{case_id} — {seed}",
            "classification": classification or case_classification(case_dir) or "UNCLASSIFIED//FOR OFFICIAL USE ONLY",
            "analyst": "AI-Assisted CTI Analyst",
            "date": _today(),
            "subject": seed,
            "status": "complete",
        },
        "executive_summary": exec_sum,
        # the case's own verdict — the gate for any figure that would call a domain "malicious"
        "verdict": {"target_class": scope.get("target_class") or None,
                    "premise_verdict": assessment.get("premise_verdict") or None,
                    "malicious_supported": verdict_ok, "basis": verdict_basis},
        "subjects": subjects,
        "findings": findings,
        "connections": connections,
        "timeline": sorted(timeline, key=lambda e: e["date"]),
        "sources": sources,
        "intelligence_gaps": gaps,
        "enrichment": enrichment,
        "enrichment_gaps": incomplete,
        "ct_history": ct_history,
        "related_hosts": related_hosts,
        "recommendations": recs,
        "indicators": indicators,
        "ioc_exclude": sorted(exclude),
        "caveats": [
            "Report uses only publicly available and case-preserved evidence; no active exploitation.",
            "Shared hosting/CDN origins, the registrar and nameservers are context, not same-operator "
            "indicators (§2.5) — retained in narrative, excluded from IOC values.",
            "Confidence reflects the analyst assessment at the collection cutoff and may change with "
            "new owner-controlled evidence.",
        ],
    }
    return report


def _today():
    return datetime.date.today().isoformat()


def main():
    ap = argparse.ArgumentParser(description="case dir -> flat report JSON (SKILL.md §8)")
    ap.add_argument("case_dir")
    ap.add_argument("-o", "--out", default=None, help="output path (default: <case>/report-data.json)")
    ap.add_argument("--kb", default=None, help="knowledge dir (default: engine knowledge/)")
    ap.add_argument("--print", action="store_true", dest="show", help="also print the JSON")
    ap.add_argument("--classification", default=None, help="handling caveat for the cover/header (default: the case's TLP marking, else UNCLASSIFIED//FOUO)")
    a = ap.parse_args()
    if not os.path.isdir(a.case_dir):
        sys.exit(f"not a case directory: {a.case_dir}")
    kb = a.kb or os.path.normpath(os.path.join(a.case_dir, "..", "..", "knowledge"))
    report = normalize_obj(build(a.case_dir, kb, a.classification))
    out = a.out or os.path.join(a.case_dir, "report-data.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    c = report
    print(f"wrote {out}")
    print(f"  subjects={len(c['subjects'])} findings={len(c['findings'])} "
          f"connections={len(c['connections'])} timeline={len(c['timeline'])} "
          f"indicators={len(c['indicators'])} ioc_exclude={len(c['ioc_exclude'])}")
    if a.show:
        print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
