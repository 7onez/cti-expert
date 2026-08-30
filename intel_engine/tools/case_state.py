#!/usr/bin/env python3
"""
case_state.py — resumable stage machine + gap/frontier extractor for the convergence loop.

WHY THIS EXISTS
---------------
A case is worked as a feedback loop: collect (WebPivot) -> assess (IntelAnalysis) -> read the
assessment -> chase the unresolved gaps back into WebPivot -> repeat until nothing new can be
collected for free or the analyst says stop. Two things were missing to run that loop safely and
resumably, and this module supplies exactly those two:

  1. A single per-case STATE file (`cases/<case>/state.json`) — the loop's stage/cursor: status
     (expanding / converged / cold / awaiting-analyst), round number, the pending/collected/consumed
     seed queues, deferred metered leads, and a compact history. An interrupt leaves this on disk, so
     the next run RESUMES instead of restarting; a cold/old case re-opened after new evidence lands
     re-mines its frontier against the CURRENT knowledge base and picks up cross-case breakthroughs.

  2. A FRONTIER extractor — the bridge nothing had before. It mines each collected `raw/*.json` for
     concrete NEW candidate domains already discovered *for free* during the round (crt.sh SAN
     siblings, passive-DNS co-hosted hosts, urlscan related domains, TLS co-SAN cross-apex, CORS
     trusted origins, impersonation lookalikes, and any reverse-WHOIS siblings a prior keyed run
     left behind), reduces them to new registrable apexes, drops shared-infra/noise, and dedupes
     against everything already collected/queued. CO-TENANCY is rejected before it can seed: a
     multi-tenant TLS cert (> MAX_CERT_APEXES apexes), a shared/bulk-hosting or CDN IP
     (> MAX_IP_COHOSTS apexes), and a bulk/privacy registrant term (> MAX_WHOIS_SIBLINGS domains)
     all name other CUSTOMERS, not the operator's siblings — they are held back as
     `co_tenancy_leads` for a deliberate check instead of auto-collected, because a bad seed is not
     just a wasted fetch: it is ingested, and becomes a fake shared indicator in every later case.
     Pivots that would need a METERED call to expand
     (FOFA ip=/icon_hash=, WhoisXML reverse) are NOT auto-run — they are recorded as `metered_leads`
     for analyst approval, honoring "auto-chase on free sources only; pause before spending credits."

This module is deterministic and side-effect-free except for reading/writing state.json; the round
loop that calls it lives in `tools/intel.py loop`. Convergence itself is delegated to the existing
`tools/kb/convergence.py` (single authority: it owns rounds.jsonl); here we only READ its verdict.

CLI:
  python3 tools/case_state.py status   <case>
  python3 tools/case_state.py frontier <case> [--max-new N] [--json]
  python3 tools/case_state.py reopen   <case> [seed ...]   # cold-case reopen (+ optional new seeds)
"""
import argparse
import glob
import json
import os
import re
import sys
from datetime import datetime, timezone

_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
WP = os.path.join(ROOT, "WebPivot", "tools")
KB_TOOLS = os.path.join(ROOT, "tools", "kb")
for _p in (WP, KB_TOOLS):
    if _p not in sys.path:
        sys.path.insert(0, _p)

# registrable-domain reducer — reuse WebPivot's so apex logic matches the collectors exactly.
try:
    from wp_common import _registrable  # noqa: E402
except Exception:
    def _registrable(host):
        parts = (host or "").strip(".").lower().split(".")
        # crude fallback (no PSL): keep last 2 labels, or 3 for common multi-part TLDs
        if len(parts) >= 3 and parts[-2] in ("com", "co", "org", "net", "gov", "edu"):
            return ".".join(parts[-3:])
        return ".".join(parts[-2:]) if len(parts) >= 2 else host

# noise / convergence helpers from the KB toolkit (best-effort — degrade gracefully)
try:
    import convergence as _conv  # tools/kb/convergence.py
except Exception:
    _conv = None
try:
    from whois_enrich import is_privacy as _is_privacy  # registrar/privacy-proxy filter
except Exception:
    def _is_privacy(_):
        return False
try:
    import cdn_ranges as _cdn        # CDN/cloud edge ranges — a shared edge IP is never an owner link
except Exception:
    _cdn = None
try:
    from noise_filters import is_noise_email as _is_noise_email   # registrar/privacy denylist
except Exception:
    def _is_noise_email(_):
        return False

STATE_VERSION = 1

# --- frontier blast-radius guards -------------------------------------------------------------
# A frontier seed is collected AND ingested, so a bad one doesn't just waste a fetch — it becomes a
# "shared indicator" that pollutes every later case. THREE co-tenancy sources look like owner links
# but are not, and all three are cheap to detect by counting:
#   * a TLS cert naming many registrable apexes is a MULTI-TENANT cert (cPanel AutoSSL, Let's
#     Encrypt multi-domain, a hoster's bundle) — the co-names are other customers;
#   * an IP answering with many apexes is SHARED/bulk hosting (or a CDN edge) — likewise;
#   * a registrant term answering with many domains is a RESELLER / PRIVACY-PROXY term (and a
#     privacy or registrar-abuse address is one by definition) — likewise.
# None of them is discarded: each is recorded in `co_tenancy_leads` so the analyst can test a
# specific pair deliberately (only a SAN cross-cover survives cert_overlap) — they just never seed.
MAX_CERT_APEXES = 4      # distinct registrable apexes on one cert before it reads as multi-tenant
MAX_IP_COHOSTS = 12      # distinct registrable apexes on one IP before it reads as shared hosting
BULK_IP_RESULTS = 120    # truncation backstop: total hits on one IP that mean bulk hosting/parking
# Reverse-WHOIS: harness/tools.py gates an INTERACTIVE reverse at 150 and asks the analyst. Auto-
# seeding has no analyst in the loop, so the bar is much lower — a real operator portfolio is small.
MAX_WHOIS_SIBLINGS = 25  # domains on one registrant term before it reads as a bulk/reseller term


def _new_deferred():
    """Empty co-tenancy lead accumulator — one slot per rejection class, keyed so leads dedupe
    across the many raw files that saw the same cert / IP / registrant term."""
    return {"cert": {}, "cohost": {}, "whois": {}}

# ONE noise policy. The shared-infrastructure denylist lives in tools/kb/noise_filters.py — the
# module whose whole job is "shared INFRASTRUCTURE, not a shared OPERATOR" and which the ingester
# and the KB queries already read. Keeping a second private copy here meant the loop's frontier
# gate and the correlation gate could disagree about the same domain; now they cannot.
try:
    from noise_filters import SAAS_TENANT_SUFFIXES as _SAAS
    from noise_filters import is_shared_infra_apex as _is_shared_infra
except Exception:
    _SAAS = frozenset()

    def _is_shared_infra(apex):          # degrade to "block nothing" rather than block wrongly
        return False


def _frontier_apex(host):
    """The registrable unit a frontier seed should be keyed on.

    `wp_common._registrable` has no PSL *private* section, so it reduces `kit.pages.dev` to
    `pages.dev` — collapsing every tenant of a SaaS platform into one entry and throwing away the
    actual target. Scam operators host on those platforms constantly, so for a SAAS_TENANT_SUFFIXES
    domain the TENANT label is the registrable unit; everything else defers to the collectors'
    reducer unchanged, so apex logic still matches the KB."""
    h = (host or "").strip().lower().rstrip(".")
    for s in _SAAS:
        if h == s:
            return s
        if h.endswith("." + s):
            label = h[:-(len(s) + 1)].rsplit(".", 1)[-1]
            return f"{label}.{s}" if label else s
    return _registrable(h)

# The analyst's learned denylist: anything marked benign in <kb>/reference.jsonl. Marking a domain
# benign once must stop it re-entering the frontier in every later round and case — the same
# reference the Correlate phase checks before trusting a shared artifact.
KB_DIR = os.environ.get("HARNESS_KB", "knowledge")


_BENIGN = []          # lazy one-shot cache: [] = not loaded, [set] = loaded


def _benign_set():
    """Values marked benign in the reference (loaded once per process; empty if unavailable)."""
    if not _BENIGN:
        try:
            from reference import benign_values
            kb = KB_DIR if os.path.isabs(KB_DIR) else os.path.join(ROOT, KB_DIR)
            _BENIGN.append(benign_values(kb))
        except Exception:
            _BENIGN.append(set())
    return _BENIGN[0]


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _case_dir(case):
    return case if os.path.isdir(case) else os.path.join(ROOT, "cases", case)


def state_path(cdir):
    return os.path.join(cdir, "state.json")


def _fresh_state(case):
    return {
        "version": STATE_VERSION, "case": case, "created": _now(), "updated": _now(),
        "status": "expanding",          # expanding | converged | cold | awaiting-analyst | error
        "round": 0, "depth_limit": None,
        "collected": [], "pending": [], "consumed": [],
        "metered_leads": [], "history": [], "reopen_count": 0, "note": None,
        "enrichment_done": {},   # {lead_key: reason} — dict, NOT in the list-coercion guard below
    }


def load_state(case):
    """Load state.json, BACKFILLED against the current schema.

    The round loop mutates keys in place (`st["consumed"].append`, `st["round"] += 1`), so a state
    file written by an older build — or truncated by a kill between rounds — used to blow up the
    loop with a KeyError mid-case. Every key in `_fresh_state` is defaulted here instead, so an old
    or partial file resumes rather than crashing; `version` records what it was written by."""
    cdir = _case_dir(case)
    p = state_path(cdir)
    if os.path.isfile(p):
        try:
            with open(p, encoding="utf-8") as fh:
                st = json.load(fh)
            if isinstance(st, dict):
                for k, v in _fresh_state(case).items():
                    st.setdefault(k, v)
                st["case"] = st.get("case") or case
                # a list-typed key that was persisted as null/scalar would fail the same way
                for k in ("collected", "pending", "consumed", "metered_leads", "history"):
                    if not isinstance(st.get(k), list):
                        st[k] = []
                if not isinstance(st.get("round"), int):
                    st["round"] = 0
                return st
        except Exception:
            pass
    return _fresh_state(case)


def save_state(case, st):
    cdir = _case_dir(case)
    os.makedirs(cdir, exist_ok=True)
    st["updated"] = _now()
    p = state_path(cdir)
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(st, fh, indent=2, ensure_ascii=False)
    os.replace(tmp, p)          # atomic — an interrupt never leaves a half-written state.json
    return p


def collected_hosts(cdir):
    """Ground truth of what has actually been collected = the hosts on disk in raw/*.json.
    Used to reconcile state after a mid-round interrupt (raw/ is the real checkpoint)."""
    hosts = set()
    for path in glob.glob(os.path.join(cdir, "raw", "*.json")):
        try:
            with open(path, encoding="utf-8") as fh:
                obj = json.load(fh)
            h = (obj.get("meta") or {}).get("host") or os.path.basename(path)[:-5]
            if h:
                hosts.add(h.lower())
        except Exception:
            hosts.add(os.path.basename(path)[:-5].lower())
    return hosts


def _is_noise_apex(apex, seed_apexes, benign=None):
    """Reject an apex as a frontier seed. Three checks, all delegated so the loop can never
    disagree with the rest of the system: it's the seed itself, it's shared infrastructure
    (noise_filters), or the analyst already marked it benign (reference.jsonl)."""
    if not apex or "." not in apex:
        return True
    if apex in seed_apexes:            # the seed itself / its own subdomains — not a NEW lead
        return True
    benign = _benign_set() if benign is None else benign
    if apex in benign:                 # learned once, suppressed everywhere after
        return True
    return _is_shared_infra(apex)


def _add_cand(cands, host, source, seed_apexes):
    """Reduce a discovered host to its registrable apex and record it as a free frontier candidate."""
    apex = _frontier_apex(host)
    if _is_noise_apex(apex, seed_apexes):
        return
    slot = cands.setdefault(apex, {"sources": set(), "examples": set()})
    slot["sources"].add(source)
    if host and host.lower() != apex:
        slot["examples"].add(host.lower())


# Phase 10 — UNIVERSAL frontier consumption. Every engine that attaches a host/domain-yielding
# live_results block is ONE entry here: (live_results key, list field, source label). A row is a
# bare host string or an engine dict carrying domain/host/name. Adding an engine is a one-line
# addition, never a new branch. The same apex found by N engines merges into ONE candidate whose
# `sources` set has length N (see _add_cand) → corroboration score = |sources|.
_HOST_YIELDING_SOURCES = (
    ("validin",        "hosts",   "validin"),
    ("validin_subs",   "hosts",   "validin_subdomain"),
    ("hunterhow",      "hosts",   "hunterhow"),
    ("censys_cert",    "names",   "censys_cert"),
    ("securitytrails", "hosts",   "securitytrails"),
    ("dnslytics",      "domains", "dnslytics"),
    ("quake",          "hosts",   "quake"),
    ("zoomeye",        "hosts",   "zoomeye"),
)


def _row_host(row):
    """A host/domain string from a frontier row that may be a bare string or an engine dict."""
    if isinstance(row, dict):
        return row.get("domain") or row.get("host") or row.get("name") or ""
    return row


_CDN_IDX = []          # lazy one-shot cache: [] = not loaded, [None] = unavailable, [idx] = loaded


def _cdn_index():
    """Load the CDN/cloud range index once per process (best-effort — None if unavailable)."""
    if not _CDN_IDX:
        try:
            _CDN_IDX.append(_cdn.load_ranges())
        except Exception:
            _CDN_IDX.append(None)
    return _CDN_IDX[0]


def _is_cdn_ip(ip):
    """True only when the IP is a KNOWN CDN/cloud edge. Unknown/unloadable → False (don't over-block)."""
    idx = _cdn_index()
    if not idx or not ip:
        return False
    try:
        return bool(_cdn.classify(str(ip).strip(), idx).get("cdn"))
    except Exception:
        return False


def _clean_name(name):
    """A bare hostname from a cert SAN / co-host row: no wildcard, scheme, port, or path."""
    s = str(name or "").strip().lower().rstrip(".")
    if not s:
        return ""
    s = re.sub(r"^\w+://", "", s).split("/", 1)[0].split("?", 1)[0]
    s = s.split(":", 1)[0]                      # strip :port (FOFA hosts are often host:port)
    if s.startswith("*."):
        s = s[2:]
    return s if "." in s and not _IP_RE.match(s) else ""


def _cohost_name(row):
    """The domain-ish name in an IP-reverse row. FOFA rows carry a clean `domain` plus a `host`
    that may be `ip:port` or a URL; prefer the former, fall back to a parseable host."""
    if not isinstance(row, dict):
        return _clean_name(row)
    return _clean_name(row.get("domain") or "") or _clean_name(row.get("host") or "")


def _free_candidates_from_raw(obj, cands, seed_apexes, deferred=None):
    """Mine one raw pivot_extract JSON for NEW registrable apexes discovered FOR FREE this round.

    Co-tenancy is filtered here, not later: a multi-tenant TLS cert or a shared-hosting IP names
    other CUSTOMERS, and seeding from those would both waste the round and poison the KB with
    fake shared indicators. Those are routed into `deferred` as analyst leads instead (see
    MAX_CERT_APEXES / MAX_IP_COHOSTS)."""
    deferred = _new_deferred() if deferred is None else deferred
    host = (obj.get("meta") or {}).get("host") or "?"
    for piv in obj.get("pivots", []) or []:
        kind, val = piv.get("kind", ""), piv.get("value")
        # pivots whose VALUE is itself a co-domain / lookalike / trusted-origin host
        if kind in ("tls_cert:co_san", "cors_allowed_origin", "impersonation:candidate",
                    "urlscan_related_domain", "archive_related_domain"):
            _add_cand(cands, str(val), kind.split(":")[0], seed_apexes)
        lr = piv.get("live_results") or {}
        if kind == "domain":
            _crtsh_candidates(lr.get("crtsh") or {}, cands, seed_apexes, deferred, host)
            for h in (lr.get("passivedns") or {}).get("hosts") or []:
                _add_cand(cands, h.get("host") if isinstance(h, dict) else h, "passive_dns", seed_apexes)
            for d in (lr.get("urlscan") or {}).get("domains") or []:
                _add_cand(cands, d, "urlscan_related", seed_apexes)
            # co-hosted domains from a PRIOR keyed run (already paid for — reusing is free)
            for key in ("fofa_ip_reverse", "pdns_ip_reverse"):
                _cohost_candidates(lr.get(key) or {}, cands, seed_apexes, deferred, host, key)
        # reverse-WHOIS siblings left behind by a prior --whois-reverse run
        for st in ("reverse_whois_current", "reverse_whois_historic"):
            _whois_candidates(lr.get(st) or {}, cands, seed_apexes, deferred, host, st)
        # ARTIFACT-REVERSE hosts -> frontier seeds, REGISTRY-DRIVEN (Phase 10 universal
        # consumption). Every host/domain-yielding engine is one _HOST_YIELDING_SOURCES entry
        # (Validin co-hosted+subdomains, Hunter.how, Censys cert names, SecurityTrails, DNSLytics,
        # Quake, ZoomEye), so a new engine is a one-line addition — not a new branch here. Attached
        # to domain AND per-artifact pivots, so mined across every pivot. Same apex from N engines
        # merges into ONE candidate with |sources| == N (corroboration score).
        for lr_key, field, label in _HOST_YIELDING_SOURCES:
            for row in (lr.get(lr_key) or {}).get(field) or []:
                _add_cand(cands, _row_host(row), label, seed_apexes)
    # top-level urlscan-related infra attached when the page itself was gone
    for d in ((obj.get("related_urlscan") or {}).get("domains") or []):
        _add_cand(cands, d, "urlscan_related", seed_apexes)


def _crtsh_candidates(crt, cands, seed_apexes, deferred, host):
    """CT names → frontier seeds, EXCEPT names that only ever appear on a multi-tenant cert.

    crt.sh returns whole certificates; a cert covering more than MAX_CERT_APEXES registrable
    apexes is a hoster's shared bundle (cPanel AutoSSL / LE multi-domain), so its co-names are
    other customers, not the operator's siblings. Those certs are recorded as `cert_overlap`
    leads — the analyst can still test a specific pair, where only a SAN cross-cover survives.
    A name that ALSO appears on a narrow cert with the seed is kept: that one is a real co-SAN."""
    clean, dirty = set(), set()
    for cert in crt.get("certs") or []:
        names = {n for n in (_clean_name(x) for x in (cert.get("names") or [])) if n}
        if not names:
            continue
        apexes = {_frontier_apex(n) for n in names}
        if len(apexes) > MAX_CERT_APEXES:
            dirty |= names
            key = cert.get("id") or cert.get("serial") or ",".join(sorted(apexes)[:3])
            deferred["cert"][key] = {
                "check": "cert_overlap", "cost": "free", "seen_on": host,
                "cert_id": cert.get("id"), "issuer": cert.get("issuer"),
                "apex_count": len(apexes), "sample_apexes": sorted(apexes)[:6],
                "why": (f"cert names {len(apexes)} registrable apexes (> {MAX_CERT_APEXES}) — reads "
                        "as a multi-tenant/hoster bundle, so its co-names were NOT seeded. Run "
                        "cert_overlap on a specific pair if you suspect a real SAN cross-cover."),
            }
            continue
        clean |= names
    tainted = dirty - clean          # a name on a narrow cert too is legitimate — keep it
    for nm in clean:
        _add_cand(cands, nm, "crtsh_san", seed_apexes)
    for sd in crt.get("subdomains") or []:
        name = _clean_name(sd)
        if name and name not in tainted:
            _add_cand(cands, name, "crtsh_san", seed_apexes)


def _whois_candidates(blk, cands, seed_apexes, deferred, host, source):
    """Reverse-WHOIS siblings → frontier seeds, unless the registrant term is shared.

    A privacy proxy or registrar-abuse address (`registry-abuse@…`, `domainabuse@…`) is a shared
    term by definition, and any term answering with more than MAX_WHOIS_SIBLINGS domains is a
    reseller/agency mailbox — in both cases the "siblings" are other customers. This is the same
    call `harness/tools.py:_reverse_gate` makes interactively; auto-seeding needs it more, not less,
    because nobody is asked. Rejected terms become leads carrying their true count."""
    domains = blk.get("domains") or []
    if not domains:
        return
    term = str(blk.get("term") or "").strip()
    count = blk.get("count")
    n = int(count) if isinstance(count, int) else len(domains)
    reason = ""
    if term and (_is_privacy(term) or _is_noise_email(term)):
        reason = (f"registrant term '{term}' is a privacy-proxy / registrar-abuse address — it is "
                  "stamped on every domain at that provider, so its siblings are unrelated")
    elif n > MAX_WHOIS_SIBLINGS:
        reason = (f"registrant term '{term or '?'}' answers with {n} domains (> "
                  f"{MAX_WHOIS_SIBLINGS}) — reads as a bulk reseller/agency term, not one operator")
    if reason:
        deferred["whois"][term or f"{source}:{host}"] = {
            "check": "bulk registrant term", "cost": "free", "seen_on": host, "source": source,
            "term": term, "sibling_count": n,
            "sample_domains": sorted(str(d).lower() for d in domains)[:6], "why": reason,
        }
        return
    for d in domains:
        _add_cand(cands, d, "reverse_whois", seed_apexes)


def _cohost_candidates(blk, cands, seed_apexes, deferred, host, source):
    """IP-reverse rows → frontier seeds, unless the IP is shared infrastructure.

    Two rejections, both cheap: a KNOWN CDN/cloud edge IP (cdn_ranges) is never an owner link, and
    an IP answering with more than MAX_IP_COHOSTS registrable apexes is shared/bulk hosting whose
    co-tenants are unrelated. Rejected IPs become `cohost` leads carrying the count, so the analyst
    sees the co-tenancy rather than silently losing it."""
    rows = blk.get("results") or blk.get("hosts") or []
    if not rows:
        return
    ip = ""
    for row in rows:
        if isinstance(row, dict) and row.get("ip"):
            ip = str(row["ip"]).strip()
            break
    if not ip:
        m = re.search(r'ip="?([0-9a-fA-F:.]+)"?', str(blk.get("query") or ""))
        ip = m.group(1) if m else ""
    names = {n for n in (_cohost_name(r) for r in rows) if n}
    apexes = {_frontier_apex(n) for n in names}
    apexes = {a for a in apexes if not _is_noise_apex(a, seed_apexes)}
    # DISTINCT APEXES is the decision variable, not the row count: the reverse returns one row per
    # host:port, so an origin IP with many open services would otherwise look like many tenants.
    # `total` is only consulted when the result set was TRUNCATED — if we saw every row, the apex
    # count is an exact measurement and needs no backstop; if we saw a page out of thousands, the
    # IP is bulk hosting whatever that page happened to contain.
    total = blk.get("total") if isinstance(blk.get("total"), int) else 0
    truncated = total > len(rows)
    reason = ""
    if ip and _is_cdn_ip(ip):
        reason = f"{ip} is a known CDN/cloud edge range — shared by unrelated sites, never an owner link"
    elif len(apexes) > MAX_IP_COHOSTS:
        reason = (f"{ip or 'the IP'} answers with {len(apexes)} distinct apexes (> "
                  f"{MAX_IP_COHOSTS}) — reads as shared/bulk hosting, so its co-tenants were NOT seeded")
    elif truncated and total > BULK_IP_RESULTS:
        reason = (f"{ip or 'the IP'} returned {len(rows)} of {total} rows (> {BULK_IP_RESULTS}) — the "
                  f"page shows only {len(apexes)} apex(es) but the IP is bulk hosting; not seeded")
    n_cohosts = max(len(apexes), total)
    if reason:
        deferred["cohost"][ip or f"{source}:{host}"] = {
            "check": "shared-hosting co-tenancy", "cost": "free", "seen_on": host, "source": source,
            "ip": ip, "cohost_count": n_cohosts, "sample_apexes": sorted(apexes)[:6], "why": reason,
        }
        return
    for n in names:
        _add_cand(cands, n, "ip_cohost", seed_apexes)


def _metered_leads_from_raw(obj, leads):
    """Pivots that would need a METERED call to expand — deferred for analyst approval, never
    auto-run by the free loop. Keyed by (service,value) so they dedupe across hosts."""
    host = (obj.get("meta") or {}).get("host") or "?"
    for piv in obj.get("pivots", []) or []:
        kind, val = piv.get("kind", ""), piv.get("value")
        if kind == "favicon_hash" and val is not None:
            leads[("FOFA", f"icon_hash={val}")] = {
                "service": "FOFA", "query": f'icon_hash="{val}"', "cost": "metered",
                "why": f"reverse favicon hash to find co-branded siblings (seen on {host})"}
        # A privacy proxy, a registrar-abuse mailbox, or a WHOIS-redacted string is shared by every
        # domain at that provider — reversing it is a guaranteed-noise result that COSTS CREDITS, so
        # it must never even be offered as a lead (same rule the frontier applies to free seeding).
        elif (kind == "whois:registrant_email" and val and not _is_privacy(val)
                and not _is_noise_email(str(val)) and "*" not in str(val)):
            leads[("WhoisXML", f"reverse_email={val}")] = {
                "service": "WhoisXML", "query": f'reverse-whois email="{val}"', "cost": "metered",
                "why": f"reverse-WHOIS the registrant email for the owner's other domains ({host})"}
    # origin-candidate IPs -> FOFA ip= reverse (find more co-hosted domains)
    for piv in obj.get("pivots", []) or []:
        if piv.get("kind") != "domain":
            continue
        dns = (piv.get("live_results") or {}).get("dns") or {}
        for c in dns.get("ip_classification") or []:
            if c.get("cdn") is False and c.get("ip"):
                leads[("FOFA", f"ip={c['ip']}")] = {
                    "service": "FOFA", "query": f'ip="{c["ip"]}"', "cost": "metered",
                    "why": f"reverse the origin IP {c['ip']} for co-hosted domains (from {host})"}


def _enrichment_leads_from_raw(obj, leads):
    """Leak/breach/OSINT/dork legs that the infra pipeline never runs — emitted as OPEN leads per
    discovered registrant email and per case apex so a run can't quietly report 'done' while
    `/intelx`, `/breach-deep`, `/dork-sweep` and `/github-osint` were never fired (the exact gap that
    let a case look converged on infra alone). Keyed so they dedupe across hosts; each carries a
    stable `key` that `enrichment_done` suppresses once the leg has run."""
    art = obj.get("artifacts") or {}
    host = (obj.get("meta") or {}).get("host") or "?"
    apex = _frontier_apex(host)
    benign = _benign_set()
    # registrant emails (current + history) — the high-signal identities; skip privacy/registrar noise
    emails = set()
    who = art.get("whois") or {}
    if who.get("registrant_email"):
        emails.add(str(who["registrant_email"]).lower())
    for e in (who.get("history") or {}).get("registrant_emails", []) or []:
        emails.add(str(e).lower())
    for piv in obj.get("pivots", []) or []:
        if piv.get("kind") == "whois:registrant_email" and piv.get("value"):
            emails.add(str(piv["value"]).lower())
    for em in emails:
        if (not em or "*" in em or em in benign
                or _is_privacy(em) or _is_noise_email(em)):
            continue
        leads[("breach", em)] = {
            "tool": "/breach-deep", "value": em, "key": f"breach:{em}", "cost": "metered",
            "why": f"breach/exposure lookup for registrant email {em} ({host})"}
        leads[("intelx", em)] = {
            "tool": "/intelx", "value": em, "key": f"intelx:{em}", "cost": "metered (logs-first ~50% keyless)",
            "why": f"breach dumps / infostealer logs / pastes / darknet for {em} — machine-tie is direct attribution"}
    # per-apex OSINT/dork legs (deduped by apex) — skip benign/victim/shared-infra apexes so the
    # legit impersonation target (e.g. the real hospital) never gets metered breach/leak leads (§2.5)
    if apex and apex != "?" and apex not in benign and not _is_shared_infra(apex):
        leads[("intelx-phonebook", apex)] = {
            "tool": "/intelx --phonebook", "value": apex, "key": f"intelx-phonebook:{apex}", "cost": "metered",
            "why": f"inventory every email/subdomain/URL IntelX has seen under {apex}"}
        leads[("dork", apex)] = {
            "tool": "/dork-sweep --filetype --docs", "value": apex, "key": f"dork:{apex}", "cost": "free",
            "why": f"Google/Bing dork sweep + doc-leak hunt on {apex}"}
        leads[("github", apex)] = {
            "tool": "/github-osint + /secrets", "value": apex, "key": f"github:{apex}", "cost": "free",
            "why": f"GitHub org/repo/code + exposed-secret recon for {apex}"}


def frontier(case, max_new=8):
    """Compute the next FREE frontier + deferred metered leads for a case, from its raw/*.json.

    Returns dict: pending (new apexes to collect next, capped), candidates (apex->why),
    metered_leads (analyst-approval pivots), and co_tenancy_leads (multi-tenant certs /
    shared-hosting IPs held back from seeding). Pure read — does not touch state.json."""
    cdir = _case_dir(case)
    st = load_state(case)
    collected = collected_hosts(cdir)
    consumed = {h.lower() for h in st.get("consumed", [])}
    seed_apexes = {_frontier_apex(h) for h in collected} | {_frontier_apex(h) for h in consumed}
    cands, leads, enr = {}, {}, {}
    deferred = _new_deferred()
    for path in sorted(glob.glob(os.path.join(cdir, "raw", "*.json"))):
        try:
            with open(path, encoding="utf-8") as fh:
                obj = json.load(fh)
        except Exception:
            continue
        _free_candidates_from_raw(obj, cands, seed_apexes, deferred)
        _metered_leads_from_raw(obj, leads)
        _enrichment_leads_from_raw(obj, enr)
    # drop apexes already collected or already queued/consumed; rank by # of corroborating sources
    already = {_frontier_apex(h) for h in collected} | {_frontier_apex(h) for h in consumed}
    fresh = {a: v for a, v in cands.items() if a not in already}
    ranked = sorted(fresh.items(), key=lambda kv: (-len(kv[1]["sources"]), kv[0]))
    pending = [a for a, _ in ranked][:max_new] if max_new else [a for a, _ in ranked]
    return {
        "case": st["case"], "round": st.get("round", 0),
        "pending": pending,
        "candidates": {a: {"sources": sorted(v["sources"]),
                           "examples": sorted(v["examples"])[:4]} for a, v in ranked},
        "candidate_total": len(fresh),
        "metered_leads": list(leads.values()),
        # co-tenancy held back from seeding (multi-tenant certs / shared-hosting IPs) — free to
        # check by hand, never auto-chased, and surfaced so the suppression is visible not silent.
        "co_tenancy_leads": [v for slot in deferred.values() for v in slot.values()],
        # leak/breach/OSINT/dork legs the infra pipeline never runs. OPEN = not yet closed;
        # closed-with-a-reason (empty/unavailable/skipped) move to gaps so a keyless/passive/empty
        # run can't stay permanently non-converged. NOTE: the engine loop converges on
        # hosts/indicators (convergence.py), NOT on these — this is a /cti completeness checklist.
        "enrichment_leads": [v for k, v in enr.items() if v["key"] not in _done_map(st)],
        "enrichment_gaps": [{"key": k, "reason": r} for k, r in _done_map(st).items()
                            if r in ("empty", "unavailable", "skipped")],
    }


def convergence_verdict(case, stale=2):
    """Read the convergence verdict from rounds.jsonl (convergence.py owns writing it)."""
    cdir = _case_dir(case)
    if _conv is None:
        return {"verdict": "UNKNOWN", "rounds": 0, "reason": "convergence module unavailable"}
    rounds = _conv._load_rounds(cdir)
    if not rounds:
        return {"verdict": "EXPANDING", "rounds": 0, "reason": "no snapshots yet"}
    recent = rounds[-stale:]
    converged = (len(rounds) >= stale and
                 all(r["new_hosts"] == 0 and r["new_indicators"] == 0 for r in recent))
    last = rounds[-1]
    return {"verdict": "CONVERGED" if converged else "EXPANDING", "rounds": len(rounds),
            "hosts": last.get("hosts"), "indicators": last.get("indicators"),
            "new_hosts_recent": sum(r["new_hosts"] for r in recent),
            "new_indicators_recent": sum(r["new_indicators"] for r in recent)}


def reopen(case, new_seeds=None):
    """Cold-case reopen: flip status back to expanding, merge any new seeds into pending, and let
    the next loop re-mine the frontier against the CURRENT KB (cross-case breakthroughs included)."""
    st = load_state(case)
    st["status"] = "expanding"
    st["reopen_count"] = st.get("reopen_count", 0) + 1
    st["note"] = f"reopened {_now()}"
    if new_seeds:
        have = {h.lower() for h in st.get("pending", [])} | {h.lower() for h in st.get("consumed", [])}
        for s in new_seeds:
            h = s.strip().lower()
            if h and h not in have:
                st.setdefault("pending", []).append(h)
    save_state(case, st)
    return st


def _done_map(st):
    """Normalise enrichment_done to {key: reason} (tolerates the legacy flat-list form)."""
    d = st.get("enrichment_done", {})
    if isinstance(d, list):
        return {k: "ran" for k in d}
    return dict(d) if isinstance(d, dict) else {}


def mark_enrichment_done(case, keys, reason="ran"):
    """Close leak/breach/OSINT/dork legs by key, so the frontier stops listing them as open.

    `reason` records WHY the leg is closed and is distinct from never-ran, so a case can't be
    trapped permanently non-converged when a leg legitimately can't produce more:
      ran         — executed, results folded in
      empty       — executed, found nothing (a collection gap, not a failure)
      unavailable — could not run (missing API key / capability)
      skipped     — deliberately not run (e.g. --passive posture, out-of-scope)
    Idempotent; keys are the `key` field from frontier's enrichment_leads."""
    reason = (reason or "ran").strip().lower()
    if reason not in ("ran", "empty", "unavailable", "skipped"):
        reason = "ran"
    st = load_state(case)
    done = _done_map(st)
    for k in (keys or []):
        if k and k.strip():
            done[k.strip()] = reason
    st["enrichment_done"] = done
    save_state(case, st)
    return st


# ------------------------------------------------------------------------- CLI
def _print_status(case):
    st = load_state(case)
    cdir = _case_dir(case)
    if not os.path.isdir(cdir):
        print(f"no such case: {case}", file=sys.stderr)
        return 2
    v = convergence_verdict(case)
    print(f"# Case state — {case}")
    print(f"  status   : {st.get('status')}   (round {st.get('round')}, reopened×{st.get('reopen_count', 0)})")
    print(f"  collected: {len(collected_hosts(cdir))} host(s) on disk")
    print(f"  pending  : {len(st.get('pending', []))}  consumed: {len(st.get('consumed', []))}")
    print(f"  converge : {v['verdict']}  ({v.get('rounds', 0)} round(s); "
          f"recent +{v.get('new_hosts_recent', 0)} hosts / +{v.get('new_indicators_recent', 0)} indicators)")
    if st.get("metered_leads"):
        print(f"  metered leads awaiting approval: {len(st['metered_leads'])}")
    try:
        _open_enr = len(frontier(case).get("enrichment_leads", []))
    except Exception:
        _open_enr = 0
    if _open_enr:
        print(f"  enrichment : {_open_enr} OPEN leak/breach/OSINT/dork lead(s) — case NOT done on infra alone")
    for h in st.get("history", [])[-6:]:
        print(f"    r{h.get('round')}: +{h.get('new_hosts', 0)} hosts  {h.get('verdict', '')}  {h.get('ts', '')}")
    return 0


def main():
    ap = argparse.ArgumentParser(description="Resumable case stage machine + gap/frontier extractor.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("status", help="show the case's stage, queues, and convergence verdict")
    s.add_argument("case")
    f = sub.add_parser("frontier", help="compute the next FREE frontier + deferred metered leads")
    f.add_argument("case")
    f.add_argument("--max-new", type=int, default=8)
    f.add_argument("--json", action="store_true")
    r = sub.add_parser("reopen", help="cold-case reopen (+ optional new seeds), re-mine next run")
    r.add_argument("case")
    r.add_argument("seeds", nargs="*", help="optional new seed domains to merge into pending")
    e = sub.add_parser("enrichment-done", help="mark leak/breach/OSINT/dork leads addressed (suppresses them)")
    e.add_argument("case")
    e.add_argument("--key", action="append", help="lead key to close, e.g. intelx:u@d.com (repeatable)")
    e.add_argument("--reason", default="ran", choices=["ran", "empty", "unavailable", "skipped"],
                   help="why the leg is closed: ran|empty|unavailable|skipped (default ran)")
    a = ap.parse_args()

    if a.cmd == "status":
        return _print_status(a.case)
    if a.cmd == "frontier":
        fr = frontier(a.case, max_new=a.max_new)
        if a.json:
            print(json.dumps(fr, indent=2, ensure_ascii=False))
            return 0
        print(f"# Frontier — {a.case}  (round {fr['round']})")
        print(f"  {fr['candidate_total']} fresh apex candidate(s); next {len(fr['pending'])} to collect:")
        for apex in fr["pending"]:
            why = fr["candidates"].get(apex, {})
            print(f"    {apex:32} via {', '.join(why.get('sources', []))}")
        if fr["metered_leads"]:
            print(f"  {len(fr['metered_leads'])} metered lead(s) — need approval before spending credits:")
            for ml in fr["metered_leads"][:12]:
                print(f"    [{ml['service']}] {ml['query']}   — {ml['why']}")
        if fr.get("co_tenancy_leads"):
            print(f"  {len(fr['co_tenancy_leads'])} co-tenancy lead(s) HELD BACK from seeding "
                  f"(multi-tenant cert / shared hosting — free to check by hand):")
            for cl in fr["co_tenancy_leads"][:12]:
                print(f"    [{cl['check']}] {cl.get('ip') or cl.get('cert_id') or ''}   — {cl['why']}")
        if fr.get("enrichment_leads"):
            print(f"  {len(fr['enrichment_leads'])} enrichment lead(s) OPEN — leak/breach/OSINT/dork "
                  f"legs the infra pipeline never runs (a /cti completeness checklist, not an engine "
                  f"stop-condition — close each once run/empty/unavailable):")
            for el in fr["enrichment_leads"][:16]:
                print(f"    {el['tool']} {el['value']}   — {el['why']}  [{el['cost']}]  key={el['key']}")
            print(f"    close: python3 tools/case_state.py enrichment-done {a.case} "
                  f"--key <key> --reason ran|empty|unavailable|skipped")
        if fr.get("enrichment_gaps"):
            print(f"  {len(fr['enrichment_gaps'])} enrichment lead(s) closed as GAP "
                  f"(ran-empty / no-capability / skipped — auditable, not re-chased):")
            for g in fr["enrichment_gaps"][:12]:
                print(f"    [{g['reason']}] {g['key']}")
        return 0
    if a.cmd == "enrichment-done":
        st = mark_enrichment_done(a.case, a.key or [], a.reason)
        print(f"closed {len(a.key or [])} enrichment lead(s) as '{a.reason}' for '{a.case}' "
              f"({len(_done_map(st))} total closed).")
        return 0
    if a.cmd == "reopen":
        st = reopen(a.case, a.seeds or None)
        print(f"reopened '{a.case}' → status={st['status']}, pending={len(st['pending'])} "
              f"(reopened×{st['reopen_count']}). Re-run: python3 tools/intel.py loop {a.case}")
        return 0
    return 1


# ============================================================ assessment.md ownership
# WHY THIS EXISTS
# ---------------
# `cases/<case>/assessment.md` has two kinds of author: a TOOL that re-renders it every round,
# and the ANALYST who writes the real judgment. Both wrote to the same path, and the tool used
# plain `open(..., "w")` — so a hand-written assessment parked there was destroyed on the next
# run, silently. (`assessment.json` had a guard from the start; the markdown did not.)
#
# THE RULE: a writer may overwrite ONLY output it recognises as its OWN. Not "is this file
# generated by anything" — each renderer knows its own signature and keeps its hands off
# everything else. That way the loop never eats the analyst's file OR the other front-end's,
# and neither has to know about the other's format.
#
# Signature = a tuple of substrings that must ALL appear near the top of the file; a writer
# passes a list of such tuples (its formats, current and historical). Fails CONSERVATIVE: a file
# that cannot be read is assumed precious and is never overwritten. Over-protecting costs a stale
# sidecar; under-protecting costs the analyst's work, so the asymmetry is deliberate.

# `WebPivot/tools/evidence_report.py` — the cluster report and the single-host `--report`.
# Used by tools/intel.py's convergence loop.
EVIDENCE_REPORT_MD = (("\n# Cluster Intelligence Assessment — ",),
                      ("\n# Intelligence Assessment — ",))

# `harness/render.py:render_markdown` — the SDK/orchestrator front-end. Its heading is the bare
# `# Assessment`, so it is paired with the `**BLUF —**` line to avoid matching an analyst's
# `# Assessment — <title>`.
HARNESS_RENDER_MD = (("\n# Assessment\n", "**BLUF —**"),)


def may_overwrite_assessment(path, signatures, probe_bytes=4096):
    """True when `path` is absent, or its head matches one of the caller's own `signatures`.

    `signatures` is an iterable of tuples; the file matches a tuple when EVERY string in it
    appears in the first `probe_bytes`. See the block comment above for the ownership rule."""
    if not os.path.isfile(path):
        return True
    try:
        with open(path, encoding="utf-8") as fh:
            head = "\n" + fh.read(probe_bytes)
    except Exception:
        return False                     # unreadable ⇒ assume precious, never overwrite
    return any(all(s in head for s in sig) for sig in signatures)


if __name__ == "__main__":
    sys.exit(main())
