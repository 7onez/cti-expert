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
# Artifact reverses (favicon hash, GA/GTM/AdSense id, verification token, body hash, cert name …)
# answered by an ENGINE (DNSLytics, Hunter.how, Validin, Censys, SecurityTrails, Quake, ZoomEye).
# A shared analytics id is normally strong same-owner evidence — which is exactly why a PLATFORM,
# TEMPLATE or PLACEHOLDER artifact is the worst false hub: one `G-XXXXXXXXXX` template default
# answered 29,875 domains and seeded 2,500 strangers in a single round. Same bar as a registrant
# term: a real operator portfolio is small; above it the artifact is the platform's, not the owner's.
MAX_ARTIFACT_SIBLINGS = 25  # apexes one engine reverse may answer before it reads as a platform artifact
# Expansion depth: how many owner-link HOPS from the seeds the loop may walk before a host becomes a
# leaf. Hop 1 is linked to the seed operator; hop 2 is linked to hop 1 (an agency's client, a
# registrant's other project); hop 3 is a stranger. 2 matches the documented `/cti --deep` cap.
DEFAULT_EXPANSION_DEPTH = 2
# MO-neighbour pivot (Phase B lives here — see mo_neighbour_classification). The discovery block
# a collector attaches is UNCLASSIFIED and is deliberately absent from _HOST_YIELDING_SOURCES; only
# a join-key-verified same_registrant row, read back from cases/<id>/mo_neighbours.json, seeds.
# Classification POLICY is reference DATA: tools/kb/references/mo_neighbours.json (RULE 3 label in
# kb_refs). The fallback is the conservative minimum — a broken file narrows, never widens, same_mo.
_MO_FALLBACK = {
    "classification": {"window_days": 60, "persona_handle_regex": r"^[a-z]+\d{4,}$", "min_token_len": 4,
                       "stop_tokens": ["www", "mail", "shop", "store", "online", "site", "web", "app", "info"]},
    "discovery": {"max_candidates": 40, "whois_run_cap": 160, "whois_workers": 4, "sibling_wait_s": 90},
    # a seed apex's OWN subdomains: conservative minimum — few per round, DNS-verified, the
    # hoster-generated labels that never carry a page are facts, not seeds
    "subdomains": {"max_per_apex": 6, "require_dns": True,
                   "stop_labels": ["www", "mail", "webmail", "cpanel", "cpcalendars", "cpcontacts", "webdisk",
                                   "autodiscover", "autoconfig", "_dmarc", "_domainkey", "ftp", "ns1", "ns2"]},
}
try:
    import kb_refs as _kb_refs   # tools/kb/kb_refs.py
    _MO_REF = _kb_refs.load_ref(_kb_refs.ref_path(_kb_refs.__file__, "mo_neighbours.json"), _MO_FALLBACK)
except Exception:
    _MO_REF = dict(_MO_FALLBACK)
_MO_CLS = _MO_REF.get("classification") or _MO_FALLBACK["classification"]
_MO_DISC = _MO_REF.get("discovery") or _MO_FALLBACK["discovery"]
_SUB_POLICY = _MO_REF.get("subdomains") or _MO_FALLBACK["subdomains"]
MO_MAX_CANDIDATES = int(_MO_DISC["max_candidates"])   # wp_mo_neighbours reads this — one source of truth
MO_WHOIS_RUN_CAP = int(_MO_DISC["whois_run_cap"])
MO_WHOIS_WORKERS = int(_MO_DISC["whois_workers"])
MO_SIBLING_WAIT_S = int(_MO_DISC["sibling_wait_s"])
MO_WINDOW_DAYS = int(_MO_CLS["window_days"])           # a same-MO registration sits within the estate's window ± this
MO_PERSONA_HANDLE_RE = re.compile(_MO_CLS["persona_handle_regex"])   # throwaway-mailbox shape
MO_MIN_TOKEN_LEN = int(_MO_CLS["min_token_len"])
_MO_STOP = frozenset(_MO_CLS["stop_tokens"])
SUB_MAX_PER_APEX = int(_SUB_POLICY["max_per_apex"])
SUB_REQUIRE_DNS = bool(_SUB_POLICY.get("require_dns", True))
_SUB_STOP = frozenset(str(x).lower() for x in _SUB_POLICY["stop_labels"])


def _new_deferred():
    """Empty co-tenancy lead accumulator — one slot per rejection class, keyed so leads dedupe
    across the many raw files that saw the same cert / IP / registrant term / artifact."""
    return {"cert": {}, "cohost": {}, "whois": {}, "artifact": {}}

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

# ONE number for "this IP is a landlord": the KB ingester, the cluster partition and this frontier
# all read noise_filters.SHARED_HOSTING_MAX_COHOSTS (references/noise_filters.json). The literal
# above is the fallback when the KB toolkit is unavailable.
try:
    from noise_filters import SHARED_HOSTING_MAX_COHOSTS as MAX_IP_COHOSTS  # noqa: F811
except Exception:
    pass


def shared_hosting_ips(cdir):
    """IPs the case's OWN collection shows to be shared/bulk hosting: any IP-reverse block (FOFA,
    passive-DNS, DNSLytics) answering more than MAX_IP_COHOSTS distinct apexes, or truncated beyond
    BULK_IP_RESULTS, plus known CDN edges. The cluster partition drops `hosted_on` edges to these
    — the KB alone may know only two tenants of an IP the collector saw answer with 2,500."""
    out = set()
    for path in glob.glob(os.path.join(cdir, "raw", "*.json")):
        try:
            with open(path, encoding="utf-8") as fh:
                obj = json.load(fh)
        except Exception:
            continue
        for piv in (obj.get("pivots") or []) if isinstance(obj, dict) else []:
            lr = piv.get("live_results") or {}
            for key in ("fofa_ip_reverse", "pdns_ip_reverse", "dnslytics_reverseip"):
                blk = lr.get(key) or {}
                rows = blk.get("results") or blk.get("hosts") or blk.get("domains") or []
                if not rows:
                    continue
                ip = _reverse_ip(blk, rows)
                if not ip:
                    continue
                apexes = {_frontier_apex(n) for n in (_cohost_name(r) for r in rows) if n}
                total = blk.get("total")
                total = int(total) if isinstance(total, int) else len(rows)
                if len(apexes) > MAX_IP_COHOSTS or (total > len(rows) and total > BULK_IP_RESULTS) or _is_cdn_ip(ip):
                    out.add(ip)
    return out


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
        # EXPANSION ANCHOR: hop distance of every collected host from the seeds (seeds = 0; a host
        # seeded from a hop-n host's raw = n+1) and the depth at which a host becomes a LEAF —
        # collected and assessed but never mined for new apexes. Missing hop = 0 (a seed).
        "hops": {}, "expansion_depth": DEFAULT_EXPANSION_DEPTH,
    }


def _hops_and_depth(st):
    """(hops, depth) from a state dict, tolerant of an older file (no hops → every host is a seed)."""
    hops = st.get("hops") if isinstance(st.get("hops"), dict) else {}
    hops = {str(k).lower(): int(v) for k, v in hops.items() if isinstance(v, int)}
    depth = st.get("expansion_depth")
    depth = depth if isinstance(depth, int) and depth >= 0 else DEFAULT_EXPANSION_DEPTH
    return hops, depth


def is_leaf(host, hops, depth):
    """A host at (or beyond) the expansion depth: its raw file yields subdomains and leads, never
    new apexes. Each hop is an owner link to the PREVIOUS host, not to the seed operator. In an
    ANCHORED case (hops recorded) a host of unknown provenance is a leaf — only a recorded hop earns
    expansion; a legacy case with no hops at all treats every host as a seed (old behaviour)."""
    return hops.get((host or "").lower(), _unknown_hop(hops, depth)) >= depth


def _unknown_hop(hops, depth):
    """Hop assumed for a host/origin with no recorded hop: 0 (seed) only when NOTHING is recorded
    (legacy state); otherwise `depth` (leaf) — an unknown is never allowed to expand the estate."""
    return 0 if not hops else depth


def _expanding_hosts(cdir):
    """Collected hosts that may still expand the estate (hop < depth) — the identity anchor for the
    MO-neighbour join and the only raw files the frontier mines for new apexes."""
    try:
        with open(state_path(cdir), encoding="utf-8") as fh:
            st = json.load(fh)
    except Exception:
        st = {}
    hops, depth = _hops_and_depth(st if isinstance(st, dict) else {})
    return {h for h in collected_hosts(cdir) if not is_leaf(h, hops, depth)}


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


_VENDOR = []          # lazy one-shot cache: [] = not loaded, [set] = loaded


def _vendor_apexes():
    """Registrable apexes of the engine's own data VENDORS (the `signup` URLs in
    WebPivot/references/api_keys.json: fofa.info, hunter.how, urlscan.io, intelx.io …). An analyst's
    free-text next_pivots/gaps names these constantly ("reverses ran only on Hunter.how"), and a
    domain-shaped token is not a lead when it is the tool that produced the evidence."""
    if not _VENDOR:
        found = set()
        try:
            p = os.path.join(ROOT, "WebPivot", "references", "api_keys.json")
            with open(p, encoding="utf-8") as fh:
                doc = json.load(fh)
            entries = (doc.get("api_keys") or {}).get("entries") or {}
            for ent in entries.values():
                for m in re.finditer(r"https?://([a-z0-9.-]+)", json.dumps(ent)):
                    found.add(_registrable(m.group(1).lower()))
        except Exception:
            pass
        _VENDOR.append(frozenset(found))
    return _VENDOR[0]


def never_seed(apex):
    """True when `apex` must not enter the frontier from ANY route — including analyst free text:
    shared infrastructure (noise_filters), a benign-marked value (reference.jsonl), or one of the
    engine's own data vendors (api_keys.json). The mechanical routes already apply the first two via
    _is_noise_apex; this is the single check for the analyst-directed (next_pivots/gaps) route."""
    a = (apex or "").strip().lower().rstrip(".")
    if not a or "." not in a:
        return True
    return a in _vendor_apexes() or a in _benign_set() or _is_shared_infra(a)


# Seed-apex SUBDOMAINS. `_add_cand` reduces every discovered host to its registrable apex, and an
# apex already in the case is "not a new lead" — correct for the apex, but it silently threw away
# the operator's own hosts under it (client., api., shop., panel.…), which are the same registration
# and usually carry the panel/API the landing page never links. They are collected like the apex
# and joined to it on `apex:<registrable>` at ingest (rung 1). Kept in a SEPARATE bucket so they
# never inflate the "new operator infrastructure" count.
_SUBS = {}          # module-level scratch: {apex: {sub: {"sources": set()}}} — reset per frontier()


def _note_subdomain(host, source, seed_apexes):
    h = (host or "").strip().lower().rstrip(".")
    if not h or "*" in h or "/" in h or ":" in h or re.fullmatch(r"[\d.]+", h):
        return
    apex = _frontier_apex(h)
    if apex not in seed_apexes or h == apex:
        return
    labels = h[: -len(apex) - 1].split(".") if h.endswith("." + apex) else []
    if not labels or labels[0] in _SUB_STOP or any(l.startswith("_") for l in labels):
        return
    if re.fullmatch(r"[0-9a-f]{16,}", labels[0]):          # hoster-generated hash labels
        return
    _SUBS.setdefault(apex, {}).setdefault(h, {"sources": set()})["sources"].add(source)


def _add_cand(cands, host, source, seed_apexes, origin=None):
    """Reduce a discovered host to its registrable apex and record it as a free frontier candidate.
    A host under an apex the case already holds is recorded as that apex's SUBDOMAIN instead.
    `origin` = the collected host whose raw file yielded this candidate (hop bookkeeping)."""
    host = _clean_name(host)                    # one gate: scheme/port/wildcard stripped, non-hostnames dropped
    if not host:
        return
    apex = _frontier_apex(host)
    if apex in seed_apexes:
        _note_subdomain(host, source, seed_apexes)
        return
    if _is_noise_apex(apex, seed_apexes):
        return
    slot = cands.setdefault(apex, {"sources": set(), "examples": set(), "origins": set()})
    slot["sources"].add(source)
    if host and host.lower() != apex:
        slot["examples"].add(host.lower())
    if origin:
        slot["origins"].add(origin.lower())


def _resolves(host, timeout=4.0):
    """Live A/AAAA/CNAME answer for `host` — a CT/archive name that no longer resolves is a fact,
    not a collection target."""
    import socket
    try:
        socket.setdefaulttimeout(timeout)
        return bool(socket.getaddrinfo(host, None))
    except Exception:
        return False


def _subdomain_frontier(collected, consumed):
    """Rank the noted subdomains per apex: corroboration desc, then name; drop collected/consumed
    and (policy) non-resolving names; cap per apex. Returns ({apex: [sub…]}, {sub: {sources, dns}})."""
    have = {h.lower() for h in collected} | {h.lower() for h in consumed}
    pending, detail = {}, {}
    # rank by INDEPENDENT evidence class, not raw source count: subfinder/assetfinder/findomain and
    # crt.sh all read certificate transparency, so they collapse to ONE "ct" class; a page-linked or
    # phonebook/passive-DNS/index name is independent corroboration and outranks a CT-only one.
    _CLASS = {"page_link": "owner", "intelx_phonebook": "intelx", "passive_dns": "pdns",
              "securitytrails": "securitytrails", "validin_subdomain": "validin",
              "urlscan_hostname": "urlscan", "urlscan_related": "urlscan",
              "crtsh_san": "ct", "subenum": "ct"}

    def _weight(srcs):
        return len({_CLASS.get("subenum" if s.startswith("subenum:") else s, s) for s in srcs})
    for apex, subs in _SUBS.items():
        ranked = sorted(subs.items(), key=lambda kv: (-_weight(kv[1]["sources"]), kv[0]))
        picked = []
        for sub, meta in ranked:
            if sub in have:
                continue
            live = _resolves(sub) if SUB_REQUIRE_DNS else None
            detail[sub] = {"apex": apex, "sources": sorted(meta["sources"]), "dns": live}
            if SUB_REQUIRE_DNS and not live:
                continue
            picked.append(sub)
            if len(picked) >= SUB_MAX_PER_APEX:
                break
        if picked:
            pending[apex] = picked
    return pending, detail


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


# Candidate source labels that are NOT owner links and therefore NEVER auto-seed:
#   * impersonation / archive_related_domain — "looks like the brand" (lookalike miners)
#   * urlscan_related / urlscan_related_domain — urlscan `domain:<host>` search returns every page
#     that merely LOADED a resource from the host (customers of a hosting/template vendor, victims
#     embedding its script, third parties). Same-kit / consumer relation, rung far below owner.
# They stay visible as `related_leads` for analyst triage; seeding them is how a 12-host estate
# drifted into 300 strangers' hosts (and their subdomains) in one loop run.
_NON_OWNER_SOURCES = frozenset({"impersonation", "archive_related_domain",
                                "urlscan_related", "urlscan_related_domain"})
_LOOKALIKE_SOURCES = _NON_OWNER_SOURCES        # historical name, kept for callers/tests


def _owner_linked(sources):
    """True when at least one source is an owner-link class (cert, registrant, co-host, engine reverse)."""
    return bool(sources) and not (sources <= _NON_OWNER_SOURCES)


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


_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z][a-z0-9-]{1,62}$")


def _clean_name(name):
    """A bare hostname from a cert SAN / co-host row: no wildcard, scheme, port, or path — and
    nothing that is not a hostname at all (a `"com, other.example"` fragment from a mis-split SAN
    list once became a raw file named after it)."""
    s = str(name or "").strip().lower().rstrip(".")
    if not s:
        return ""
    s = re.sub(r"^\w+://", "", s).split("/", 1)[0].split("?", 1)[0]
    s = s.split(":", 1)[0]                      # strip :port (FOFA hosts are often host:port)
    if s.startswith("*."):
        s = s[2:]
    if "." not in s or _IP_RE.match(s) or not _HOSTNAME_RE.match(s):
        return ""
    return s


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
            _add_cand(cands, str(val), kind.split(":")[0], seed_apexes, origin=host)
        lr = piv.get("live_results") or {}
        if kind == "domain":
            _crtsh_candidates(lr.get("crtsh") or {}, cands, seed_apexes, deferred, host)
            for h in (lr.get("passivedns") or {}).get("hosts") or []:
                _add_cand(cands, h.get("host") if isinstance(h, dict) else h, "passive_dns", seed_apexes, origin=host)
            for d in (lr.get("urlscan") or {}).get("domains") or []:
                _add_cand(cands, d, "urlscan_related", seed_apexes, origin=host)
            # co-hosted domains from a PRIOR keyed run (already paid for — reusing is free). DNSLytics
            # reverse-IP lives under its own key ON PURPOSE: its rows are IPs, so they take the
            # co-host route (CDN-range + MAX_IP_COHOSTS guards) instead of the artifact route below.
            for key in ("fofa_ip_reverse", "pdns_ip_reverse", "dnslytics_reverseip"):
                _cohost_candidates(lr.get(key) or {}, cands, seed_apexes, deferred, host, key)
        # reverse-WHOIS siblings left behind by a prior --whois-reverse run (WhoisXML current/historic
        # + SecurityTrails' DSL — same shape, same privacy + MAX_WHOIS_SIBLINGS guards)
        for st in ("reverse_whois_current", "reverse_whois_historic", "securitytrails_reverse_whois"):
            _whois_candidates(lr.get(st) or {}, cands, seed_apexes, deferred, host, st)
        # ARTIFACT-REVERSE hosts -> frontier seeds, REGISTRY-DRIVEN (Phase 10 universal
        # consumption). Every host/domain-yielding engine is one _HOST_YIELDING_SOURCES entry
        # (Validin co-hosted+subdomains, Hunter.how, Censys cert names, SecurityTrails, DNSLytics,
        # Quake, ZoomEye), so a new engine is a one-line addition — not a new branch here. Attached
        # to domain AND per-artifact pivots, so mined across every pivot. Same apex from N engines
        # merges into ONE candidate with |sources| == N (corroboration score). PREVALENCE GUARD: an
        # artifact answering more than MAX_ARTIFACT_SIBLINGS apexes is a platform/template/placeholder
        # artifact — its siblings are strangers and are held back as an `artifact` lead.
        for lr_key, field, label in _HOST_YIELDING_SOURCES:
            blk = lr.get(lr_key) or {}
            rows = blk.get(field) if isinstance(blk, dict) else None
            if not rows:
                continue
            _artifact_candidates(rows, blk, cands, seed_apexes, deferred, host, label, kind, val)
    # top-level urlscan-related infra attached when the page itself was gone
    for d in ((obj.get("related_urlscan") or {}).get("domains") or []):
        _add_cand(cands, d, "urlscan_related", seed_apexes, origin=host)
    for d in ((obj.get("related_urlscan") or {}).get("related_domains") or []):
        _add_cand(cands, d, "urlscan_related", seed_apexes, origin=host)
    # SUBDOMAIN-ONLY sources — hosts under an apex the case holds, never new apexes:
    #   * the page's own links to its sibling hosts (client., api., shop.… on the same apex)
    #   * the IntelX phonebook inventory (every hostname the leak corpora ever saw under the apex)
    #   * urlscan's hostname lifecycle index for the apex
    art = obj.get("artifacts") or {}
    for h in art.get("third_party_hosts") or []:
        _note_subdomain(h, "page_link", seed_apexes)
    pb = (obj.get("intelx") or {}).get("phonebook") or {}
    for h in (pb.get("domains") or []) if isinstance(pb, dict) else []:
        _note_subdomain(h, "intelx_phonebook", seed_apexes)
    for piv in obj.get("pivots", []) or []:
        lr = piv.get("live_results") or {}
        for blk_key in ("phonebook", "intelx_phonebook"):
            for h in ((lr.get(blk_key) or {}).get("domains") or []):
                _note_subdomain(h, "intelx_phonebook", seed_apexes)
        # urlscan's hostname index answers per-hostname; sibling hosts arrive through the hostname
        # search on the apex when the collector ran it (`hosts`), else through related scans above
        for h in ((lr.get("urlscan_hostname") or {}).get("hosts") or []):
            _note_subdomain(_row_host(h), "urlscan_hostname", seed_apexes)


def _crtsh_candidates(crt, cands, seed_apexes, deferred, host):
    """CT names → frontier seeds, EXCEPT names that only ever appear on a multi-tenant cert — and,
    when the listing shows the host sits on a multi-tenant cert PLATFORM, its narrow pairings too.

    crt.sh returns whole certificates; a cert covering more than MAX_CERT_APEXES registrable
    apexes is a hoster's shared bundle (cPanel AutoSSL / LE multi-domain / a CDN's managed cert), so
    its co-names are other customers, not the operator's siblings. Those certs are recorded as
    `cert_overlap` leads — the analyst can still test a specific pair, where only a SAN cross-cover
    survives. A host whose listing carries ANY such wide cert lives on a multi-tenant platform; the
    platform also mints small 2–4-name certs pairing random customers on one load balancer, so on
    that host a narrow co-SAN is a co-tenant too until cert_overlap says otherwise — it is held back
    as a lead, never seeded. Only a host with exclusively narrow certs (dedicated issuance) seeds
    its co-SANs directly. Own-apex subdomains are noted either way (same registration)."""
    clean, dirty = set(), set()
    wide = 0
    for cert in crt.get("certs") or []:
        names = {n for n in (_clean_name(x) for x in (cert.get("names") or [])) if n}
        if not names:
            continue
        apexes = {_frontier_apex(n) for n in names}
        if len(apexes) > MAX_CERT_APEXES:
            dirty |= names
            wide += 1
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
    foreign = {nm for nm in clean if _frontier_apex(nm) not in seed_apexes}
    if wide and foreign:
        pairs = sorted({_frontier_apex(nm) for nm in foreign})
        deferred["cert"][f"platform:{host}"] = {
            "check": "cert_overlap", "cost": "free", "seen_on": host, "cert_id": None, "issuer": None,
            "apex_count": len(pairs), "sample_apexes": pairs[:6],
            "why": (f"{host} sits on a multi-tenant cert platform ({wide} wide cert(s) in its CT "
                    f"listing); its {len(pairs)} narrow co-SAN pairing(s) read as load-balancer "
                    "co-tenants, so they were NOT seeded. Run cert_overlap on a pair to confirm a "
                    "genuine SAN cross-cover."),
        }
        clean -= foreign
    tainted = dirty - clean          # a name on a narrow cert too is legitimate — keep it
    for nm in clean:
        _add_cand(cands, nm, "crtsh_san", seed_apexes, origin=host)
    for sd in crt.get("subdomains") or []:
        name = _clean_name(sd)
        if name and name not in tainted and (not wide or _frontier_apex(name) in seed_apexes):
            _add_cand(cands, name, "crtsh_san", seed_apexes, origin=host)


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
        _add_cand(cands, d, "reverse_whois", seed_apexes, origin=host)


def _artifact_candidates(rows, blk, cands, seed_apexes, deferred, host, source, kind, val):
    """Engine artifact-reverse rows (favicon / tracker id / verification token / body hash / cert
    name → hosts) → frontier seeds, unless the artifact is SHARED.

    The same counting rule as a registrant term: an artifact answering more than
    MAX_ARTIFACT_SIBLINGS registrable apexes (or a `total` beyond what was returned) is a platform,
    template or placeholder artifact — `G-XXXXXXXXXX` from a theme's custom-code slot answers tens of
    thousands of sites — so its "siblings" are strangers. Rejected artifacts become `artifact` leads
    carrying their true count and a reference_check hint (the analyst marks the value benign once
    and it never re-enters). Rows may be bare hosts or engine dicts (see _row_host)."""
    names = [_clean_name(_row_host(r)) for r in rows]
    names = [n for n in names if n]
    if not names:
        return
    # The apex's OWN subdomains (Validin/SecurityTrails subdomain listings) are the same registration
    # and route through _add_cand -> _note_sub; only FOREIGN apexes count toward prevalence. A
    # truncated page (engine `total` beyond the rows returned) counts its unseen remainder as foreign.
    own = [nm for nm in names if _frontier_apex(nm) in seed_apexes]
    foreign = {_frontier_apex(nm) for nm in names} - set(seed_apexes)
    total = blk.get("total") if isinstance(blk, dict) else None
    unseen = (int(total) - len(names)) if isinstance(total, int) and total > len(names) else 0
    n = len(foreign) + unseen
    for nm in own:
        _add_cand(cands, nm, source, seed_apexes, origin=host)
    if not foreign and not unseen:
        return
    if n > MAX_ARTIFACT_SIBLINGS:
        artifact = f"{kind}={val}" if val is not None else kind
        deferred["artifact"][f"{source}:{artifact}"] = {
            "check": "reference_check", "cost": "free", "seen_on": host, "source": source,
            "artifact": artifact, "sibling_count": n, "sample_apexes": sorted(foreign)[:6],
            "why": (f"{source} answers {n} apexes for {artifact} (> {MAX_ARTIFACT_SIBLINGS}) — reads as "
                    "a platform/template/placeholder artifact carried by strangers, not the owner's "
                    "account, so its hosts were NOT seeded. reference_check the value; mark it benign "
                    "if it is a platform default."),
        }
        return
    for nm in names:
        if nm not in own:
            _add_cand(cands, nm, source, seed_apexes, origin=host)


def _reverse_ip(blk, rows):
    """The IP an IP-reverse block answers for: an explicit `ip` (DNSLytics), the first row's `ip`
    (FOFA), or the `ip="…"` term in the query string."""
    ip = str(blk.get("ip") or "").strip()
    for row in rows:
        if ip:
            break
        if isinstance(row, dict) and row.get("ip"):
            ip = str(row["ip"]).strip()
    if not ip:
        m = re.search(r'ip="?([0-9a-fA-F:.]+)"?', str(blk.get("query") or ""))
        ip = m.group(1) if m else ""
    return ip


def _cohost_candidates(blk, cands, seed_apexes, deferred, host, source):
    """IP-reverse rows → frontier seeds, unless the IP is shared infrastructure.

    Two rejections, both cheap: a KNOWN CDN/cloud edge IP (cdn_ranges) is never an owner link, and
    an IP answering with more than MAX_IP_COHOSTS registrable apexes is shared/bulk hosting whose
    co-tenants are unrelated. Rejected IPs become `cohost` leads carrying the count, so the analyst
    sees the co-tenancy rather than silently losing it."""
    rows = blk.get("results") or blk.get("hosts") or blk.get("domains") or []   # FOFA / PDNS / DNSLytics shapes
    if not rows:
        return
    ip = _reverse_ip(blk, rows)
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
        _add_cand(cands, n, "ip_cohost", seed_apexes, origin=host)


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
            "tool": "/github-osint + /secrets (github_harvest)", "value": apex, "key": f"github:{apex}", "cost": "free",
            "why": f"GitHub org/repo search for {apex} → committer-identity harvest (.patch From: e-mails) + exposed-secret recon"}
        # GrayHatWarfare: open-bucket EXPOSURE for the brand label — an exposure/leak lead (graded as
        # such in the report's Exposure section), never a same-operator pivot, never a frontier seed.
        # Keyless the tool degrades to its dork fallback, so the lead is always emittable.
        leads[("grayhatwarfare", apex)] = {
            "tool": "/secrets", "value": apex, "key": f"grayhatwarfare:{apex}",      # /secrets owns the GHW layer
            "cost": "metered (keyless dork fallback)",
            "why": f"open S3/Azure/GCS buckets carrying the {apex.split('.')[0]} label — exposure, not attribution"}
    # a GitHub profile/org the page itself links to is the direct target of the committer harvest —
    # the one identity surface that survives WHOIS privacy (bots/licence links are dropped upstream)
    for u in ((art.get("socials") or {}).get("github") or []):
        m = re.search(r"github\.com/([A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?)(?:/|$)", str(u))
        if not m:
            continue
        login = m.group(1)
        if login.lower() in ("features", "topics", "sponsors", "login", "marketplace", "about", "site", "orgs"):
            continue
        leads[("github-account", login.lower())] = {
            "tool": "github_harvest", "value": f"github.com/{login}", "key": f"github-account:{login.lower()}", "cost": "free",
            "why": f"GitHub account linked from {host}: harvest committer e-mails (.patch From:), former logins, org members/contributors"}


def _censys_search_candidates(cdir, cands, seed_apexes, deferred=None):
    """Frontier seeds from cases/<id>/censys_search.json — hostnames Censys saw serving one of the
    estate's EXACT leaf certificates. An exact cert SHA-256 match is an owner link (the same standard
    as `censys_cert` names in _HOST_YIELDING_SOURCES) — UNLESS the certificate is itself shared: a CDN
    / hoster bundle cert returns hundreds of unrelated tenants. So the SAME guard `_crtsh_candidates`
    applies to CT certs applies here, per query: more than MAX_CERT_APEXES distinct apexes (or a total
    beyond what was returned) reads as a multi-tenant cert -> a deferred `cert` lead, never seeds.
    A skipped/errored search contributes nothing."""
    p = os.path.join(cdir, "censys_search.json")
    if not os.path.isfile(p):
        return
    try:
        blk = json.load(open(p, encoding="utf-8"))
    except Exception:
        return
    if not isinstance(blk, dict) or blk.get("skipped") or blk.get("error"):
        return
    deferred = _new_deferred() if deferred is None else deferred
    # per-query rows (attributable to their fingerprint chunk) when present; else the legacy union
    rows = [q for q in (blk.get("queries") or []) if isinstance(q, dict) and q.get("hostnames")] or \
           [{"fingerprints": blk.get("fingerprints") or [], "hostnames": blk.get("hostnames") or [],
             "total": blk.get("hits") or 0}]
    for q in rows:
        names = {n for n in (_clean_name(x) for x in (q.get("hostnames") or [])) if n}
        apexes = {_frontier_apex(n) for n in names}
        apexes = {a for a in apexes if not _is_noise_apex(a, seed_apexes)}
        total = q.get("total") if isinstance(q.get("total"), int) else 0
        truncated = total > len(names)
        if len(apexes) > MAX_CERT_APEXES or (truncated and total > BULK_IP_RESULTS):
            key = ",".join(sorted(q.get("fingerprints") or [])[:3]) or "censys_search"
            deferred["cert"][key] = {
                "check": "cert_overlap", "cost": "free", "seen_on": "censys_search.json",
                "fingerprints": q.get("fingerprints") or [], "apex_count": max(len(apexes), total),
                "sample_apexes": sorted(apexes)[:6],
                "why": (f"Censys returns {max(len(apexes), total)} apex(es) on this certificate (> {MAX_CERT_APEXES}) — "
                        "a shared CDN/hoster certificate, so its hosts were NOT seeded. Run cert_overlap on a "
                        "specific pair if you suspect a genuine SAN cross-cover."),
            }
            continue
        for n in names:
            _add_cand(cands, n, "censys_search", seed_apexes)


# ----------------------------------------------------------------- MO-neighbour classification
def _mo_json(cdir):
    return os.path.join(cdir, "mo_neighbours.json")


def _mo_same_registrant_candidates(cdir, cands, seed_apexes, deferred):
    """Frontier seeds from cases/<id>/mo_neighbours.json — the `same_registrant` rows ONLY.

    A join-key match (the candidate's OWN registrant e-mail/phone equals an estate registrant) is the
    same standard reverse-WHOIS seeding uses, so it is seeded directly — an origin's co-tenant count
    is irrelevant once identity is verified. What still applies is the bulk-term guard: one
    registrant matching more than MAX_WHOIS_SIBLINGS neighbours is a reseller mailbox, not an
    operator, and is held back as a lead exactly like _whois_candidates does."""
    p = _mo_json(cdir)
    if not os.path.isfile(p):
        return
    try:
        blk = json.load(open(p, encoding="utf-8"))
    except Exception:
        return
    by_term = {}
    for row in blk.get("same_registrant") or []:
        if not isinstance(row, dict) or not row.get("apex"):
            continue
        by_term.setdefault(str(row.get("registrant") or "?").lower(), []).append(row)
    for term, rows in by_term.items():
        if len(rows) > MAX_WHOIS_SIBLINGS:
            deferred["whois"][f"mo_neighbour:{term}"] = {
                "check": "bulk registrant term", "cost": "free", "seen_on": "mo_neighbours.json",
                "source": "mo_neighbour_same_registrant", "term": term, "sibling_count": len(rows),
                "sample_domains": sorted(str(r["apex"]).lower() for r in rows)[:6],
                "why": (f"registrant '{term}' matches {len(rows)} co-tenants (> {MAX_WHOIS_SIBLINGS}) — "
                        "reads as a reseller/agency mailbox, not one operator; not seeded")}
            continue
        for r in rows:
            origins = r.get("estate_hosts") or [None]
            for o in origins:
                _add_cand(cands, str(r["apex"]).lower(), "mo_neighbour_same_registrant", seed_apexes, origin=o)


def _whois_identity(w):
    """(emails, phones, name, registrar, created) from a whois row — CURRENT registrant only.

    History is deliberately NOT folded in: Phase 1 established that a previous registrant era is a
    third party (a drop-caught estate domain's prior owner), so a co-tenant registered to that prior
    owner must never become a `same_registrant` join and seed the frontier. Privacy/noise values are
    dropped, and a privacy-proxied RECORD contributes no phone and no name (whois_current fills the
    proxy's own contact phone in — two unrelated proxied domains would otherwise "share" it; same
    rule as wp_analyze.whois_enrich_result._proxied)."""
    if not isinstance(w, dict) or w.get("error"):
        return set(), set(), "", "", ""
    emails, phones = set(), set()
    em = str(w.get("registrant_email") or "").strip().lower()
    if em and "*" not in em and not _is_privacy(em) and not _is_noise_email(em):
        emails.add(em)
    proxied = any(_is_privacy(str(v)) for v in
                  (w.get("registrant_email"), w.get("registrant_org"), w.get("registrant_name")) if v)
    if not proxied:
        ph = re.sub(r"[^\d+]", "", str(w.get("registrant_phone") or ""))
        if len(ph) >= 8 and not _is_privacy(str(w.get("registrant_phone") or "")):
            phones.add(ph)
    name = str(w.get("registrant_name") or w.get("registrant_org") or "").strip()
    if proxied or _is_privacy(name):
        name = ""
    return emails, phones, name, str(w.get("registrar") or "").strip().lower(), str(w.get("created") or "")[:10]


def _label_tokens(apex):
    """Alphabetic tokens (>= MO_MIN_TOKEN_LEN chars) of an apex's first label, digits stripped — the
    estate's OWN naming vocabulary, computed per case (no static lexicon: house_report._sector() is a
    VN regex and reusing it would be a false generalisation). Stop tokens come from the reference."""
    label = str(apex or "").lower().split(".")[0]
    toks = set()
    for t in re.split(r"[^a-z]+", label):
        if len(t) >= MO_MIN_TOKEN_LEN and t not in _MO_STOP:
            toks.add(t)
    return toks


def _date_ord(s):
    try:
        return datetime.strptime(str(s)[:10], "%Y-%m-%d").toordinal()
    except Exception:
        return None


def _estate_context(cdir):
    """Estate registrants/registrars/created-window/tokens from the WHOIS sidecar, falling back to
    raw/*.json artifacts.whois so a FIRST cmd_open (sidecar not yet written) still has identities.
    ANCHORED: only EXPANDING hosts (hop < expansion_depth) contribute identities — a leaf's registrant
    (an agency client, a registrant's other project) is not the operator's join key."""
    expanding = _expanding_hosts(cdir)
    hosts = sorted(expanding)
    apexes = {_frontier_apex(h) for h in hosts}
    rows = {}
    for p in glob.glob(os.path.join(cdir, "whois", "*.json")):
        dom = os.path.basename(p)[:-5].lower()
        if dom not in expanding and dom not in apexes:
            continue
        try:
            rows[dom] = json.load(open(p, encoding="utf-8"))
        except Exception:
            continue
    if not rows:
        for p in glob.glob(os.path.join(cdir, "raw", "*.json")):
            try:
                obj = json.load(open(p, encoding="utf-8"))
            except Exception:
                continue
            if not isinstance(obj, dict):
                continue
            w = (obj.get("artifacts") or {}).get("whois")
            h = (obj.get("meta") or {}).get("host")
            if isinstance(w, dict) and h and str(h).lower() in expanding:
                rows[str(h).lower()] = w
    emails, phones, registrars, created = set(), set(), set(), []
    key_hosts = {}                      # join key (email/phone) -> estate hosts carrying it (hop origin)
    for dom, w in rows.items():
        e, ph, _n, rg, cr = _whois_identity(w)
        emails |= e
        phones |= ph
        for k in e | ph:
            key_hosts.setdefault(k, set()).add(dom)
        if rg:
            registrars.add(rg)
        o = _date_ord(cr)
        if o:
            created.append(o)
    tokens = set()
    for h in hosts:
        tokens |= _label_tokens(_frontier_apex(h))
    return {"hosts": hosts, "apexes": {_frontier_apex(h) for h in hosts}, "emails": emails, "phones": phones,
            "key_hosts": key_hosts,
            "registrars": registrars, "created_min": min(created) if created else None,
            "created_max": max(created) if created else None, "tokens": tokens,
            "source": "whois sidecar" if glob.glob(os.path.join(cdir, "whois", "*.json")) else "raw artifacts.whois"}


def _mo_blocks(cdir):
    """Every mo_neighbours discovery block in the case's EXPANDING hosts' raw files ->
    [(seen_on_host, block)]. A leaf's co-tenants are not mined (expansion anchor)."""
    out = []
    expanding = _expanding_hosts(cdir)
    for p in sorted(glob.glob(os.path.join(cdir, "raw", "*.json"))):
        try:
            obj = json.load(open(p, encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(obj, dict):
            continue
        host = (obj.get("meta") or {}).get("host") or os.path.basename(p)[:-5]
        if str(host).lower() not in expanding:
            continue
        for piv in obj.get("pivots") or []:
            blk = (piv.get("live_results") or {}).get("mo_neighbours")
            if isinstance(blk, dict) and not blk.get("error"):
                out.append((str(host).lower(), blk))
    return out


def mo_neighbour_classification(case, whois_window_days=MO_WINDOW_DAYS):
    """Phase B: classify every WHOIS-verified co-tenant of the estate's origins against the ESTATE.

    same_registrant  — candidate's own registrant e-mail/phone equals an estate registrant (join key;
                       the ONLY class the frontier seeds)
    same_mo          — different registrant, but registrar ∈ estate registrars, created within the
                       estate window ± whois_window_days, and (shares a naming token with the estate
                       OR the mailbox has the throwaway-handle shape). A rung-10 candidate: rendered
                       as a related persona, never an estate member, never a KB edge.
    unrelated        — counted + a domain sample only; identities never enumerated
    unverifiable     — WHOIS errored / no record; kept separate so it is never read as 'unrelated'
    Pure read. Returns the block intel.py persists as cases/<id>/mo_neighbours.json."""
    cdir = _case_dir(case)
    est = _estate_context(cdir)
    lo = (est["created_min"] - whois_window_days) if est["created_min"] else None
    hi = (est["created_max"] + whois_window_days) if est["created_max"] else None
    reseller_estate = len(est["emails"] | est["phones"]) > MAX_WHOIS_SIBLINGS
    # merge candidates across every origin block (one apex may sit behind several estate hosts)
    cands, origins, bulk, unverified = {}, {}, {}, set()
    for host, blk in _mo_blocks(cdir):
        ip = str(blk.get("origin_ip") or "")
        o = origins.setdefault(ip, {"origin_ip": ip, "seen_on": set(), "fan_out": 0, "sources": {}})
        o["seen_on"].add(host)
        o["fan_out"] = max(o["fan_out"], int(blk.get("fan_out") or 0))
        o["sources"].update({k: v for k, v in (blk.get("sources") or {}).items()})
        if blk.get("bulk_skipped"):
            bulk[ip] = {"origin_ip": ip, "fan_out": blk.get("fan_out"), "sample_apexes": blk.get("sample_apexes") or [],
                        "seen_on": host, "why": blk.get("note") or "bulk hosting"}
            continue
        for a in blk.get("unverified") or []:                 # over-cap / run-cap: seen, not yet verified
            a = str(a or "").lower()
            if a and a not in est["apexes"]:
                unverified.add(a)
        for row in blk.get("candidates") or []:
            apex = str(row.get("apex") or "").lower()
            if not apex or apex in est["apexes"]:
                continue
            slot = cands.setdefault(apex, {"apex": apex, "origin_ips": set(), "sources": set(), "whois": row.get("whois") or {}})
            slot["origin_ips"].add(ip)
            slot["sources"].update(row.get("sources") or [])
            if slot["whois"].get("error") and not (row.get("whois") or {}).get("error"):
                slot["whois"] = row.get("whois") or {}
    same_reg, personas, unrelated, unverifiable, verified = [], {}, [], [], []
    for apex in sorted(cands):
        c = cands[apex]
        w = c["whois"]
        emails, phones, name, registrar, created = _whois_identity(w)
        base = {"apex": apex, "origin_ips": sorted(c["origin_ips"]), "sources": sorted(c["sources"])}
        if not isinstance(w, dict) or w.get("error") or not w:
            unverifiable.append(apex)
            verified.append({**base, "class": "unverifiable", "whois": w})
            continue
        hit_e = sorted(emails & est["emails"])
        hit_p = sorted(phones & est["phones"])
        if hit_e or hit_p:
            key = (hit_e or hit_p)[0]
            same_reg.append({**base, "join_key": "registrant_email" if hit_e else "registrant_phone",
                             "registrant": key, "registrar": registrar, "created": created,
                             "estate_hosts": sorted((est.get("key_hosts") or {}).get(key, ()))})
            verified.append({**base, "class": "same_registrant", "whois": w})
            continue
        signals = []
        # a persona needs a non-privacy SELECTOR (e-mail or phone); a bare name behind a privacy
        # proxy is not an identity anyone could be recalled by, so it can only be 'unrelated'
        ident = next(iter(sorted(emails)), "") or next(iter(sorted(phones)), "")
        if ident and not reseller_estate and registrar and registrar in est["registrars"]:
            o = _date_ord(created)
            in_window = bool(o and lo and hi and lo <= o <= hi)
            toks = _label_tokens(apex) & est["tokens"]
            handle = bool(emails and MO_PERSONA_HANDLE_RE.match(next(iter(sorted(emails))).split("@")[0]))
            if in_window and (toks or handle):
                signals = ["same registrar", "created in estate window"] + \
                          ([f"naming token(s) {', '.join(sorted(toks))}"] if toks else []) + \
                          (["throwaway-handle mailbox"] if handle else [])
        if signals:
            p = personas.setdefault(ident, {"persona": ident, "name": name, "domains": [], "registrar": registrar,
                                            "created": [], "origin_ips": set(), "signals": set()})
            p["domains"].append(apex)
            if created:
                p["created"].append(created)
            p["origin_ips"] |= c["origin_ips"]
            p["signals"] |= set(signals)
            verified.append({**base, "class": "same_mo", "whois": w})
        else:
            unrelated.append(apex)
            verified.append({**base, "class": "unrelated", "whois": w})
    related = []
    for ident in sorted(personas):
        p = personas[ident]
        related.append({"persona": p["persona"], "name": p["name"], "domains": sorted(p["domains"]),
                        "registrar": p["registrar"],
                        "created_span": [min(p["created"]), max(p["created"])] if p["created"] else [],
                        "origin_ips": sorted(p["origin_ips"]), "signals": sorted(p["signals"]),
                        "rung": 10, "caveat": "candidate, single-indicator (rung 10): shared provider + same MO; not estate membership"})
    return {
        "case": os.path.basename(cdir.rstrip("/")), "generated": _now(), "window_days": whois_window_days,
        "estate": {"hosts": len(est["hosts"]), "registrant_terms": len(est["emails"] | est["phones"]),
                   "registrars": sorted(est["registrars"]), "tokens": sorted(est["tokens"]),
                   "created_window": [datetime.fromordinal(lo).date().isoformat() if lo else None,
                                      datetime.fromordinal(hi).date().isoformat() if hi else None],
                   "context_source": est["source"],
                   "reseller_estate": reseller_estate},
        "origins": [{**o, "seen_on": sorted(o["seen_on"])} for o in origins.values()],
        "bulk_origins": sorted(bulk.values(), key=lambda b: b["origin_ip"]),
        "same_registrant": same_reg,
        "related_personas": related,
        "unrelated_count": len(unrelated), "unrelated_sample": unrelated[:6],
        "unverifiable_count": len(unverifiable), "unverifiable": unverifiable,
        "unverified_count": len(unverified - set(cands)), "unverified_sample": sorted(unverified - set(cands))[:6],
        "verified": verified,
    }


def frontier(case, max_new=8):
    """Compute the next FREE frontier + deferred metered leads for a case, from its raw/*.json.

    Returns dict: pending (new apexes to collect next, capped), candidates (apex->why),
    metered_leads (analyst-approval pivots), and co_tenancy_leads (multi-tenant certs /
    shared-hosting IPs held back from seeding). Pure read — does not touch state.json.

    EXPANSION ANCHOR: only hosts within `expansion_depth` hops of the seeds may yield NEW apexes.
    Each hop is owner-linked to the previous host, not to the seed operator — agency → its clients →
    their other sites is three hops of "owner links" ending in strangers. A host at the depth limit
    is a LEAF: collected, assessed, its own subdomains and leads noted, but never mined for apexes."""
    cdir = _case_dir(case)
    st = load_state(case)
    hops, depth = _hops_and_depth(st)
    collected = collected_hosts(cdir)
    consumed = {h.lower() for h in st.get("consumed", [])}
    seed_apexes = {_frontier_apex(h) for h in collected} | {_frontier_apex(h) for h in consumed}
    cands, leads, enr = {}, {}, {}
    deferred = _new_deferred()
    _SUBS.clear()
    leaves = []
    for path in sorted(glob.glob(os.path.join(cdir, "raw", "*.json"))):
        try:
            with open(path, encoding="utf-8") as fh:
                obj = json.load(fh)
        except Exception:
            continue
        host = ((obj.get("meta") or {}).get("host") or os.path.basename(path)[:-5]).lower()
        if is_leaf(host, hops, depth):
            # leaf: mine into scratch so own-subdomain notes (_SUBS) and co-tenancy leads survive,
            # but no NEW apex from this host may enter the frontier
            _free_candidates_from_raw(obj, {}, seed_apexes, deferred)
            leaves.append(host)
        else:
            _free_candidates_from_raw(obj, cands, seed_apexes, deferred)
        _metered_leads_from_raw(obj, leads)
        _enrichment_leads_from_raw(obj, enr)
    # MO-neighbour: seed ONLY from the CLASSIFIED case-wide file (Phase B), never from the raw
    # per-host discovery block — a same_mo / unrelated co-tenant must not grow the estate.
    _mo_same_registrant_candidates(cdir, cands, seed_apexes, deferred)
    # Censys case-level cert search (exact leaf-cert match = owner link) — seeds directly.
    _censys_search_candidates(cdir, cands, seed_apexes, deferred)
    # subdomain enumerators (wp_subenum: subfinder / amass / assetfinder / findomain) — the seed
    # apex's own hosts, DNS-verified by the tool run; a name under a NEW apex is a normal candidate
    for path in sorted(glob.glob(os.path.join(cdir, "subenum", "*.json"))):
        try:
            with open(path, encoding="utf-8") as fh:
                se = json.load(fh)
        except Exception:
            continue
        for row in se.get("subdomains") or []:
            if isinstance(row, dict) and row.get("name"):
                for src in row.get("sources") or ["subenum"]:
                    _add_cand(cands, row["name"], f"subenum:{src}", seed_apexes)
    # drop apexes already collected or already queued/consumed; rank by # of corroborating sources
    already = {_frontier_apex(h) for h in collected} | {_frontier_apex(h) for h in consumed}
    fresh = {a: v for a, v in cands.items() if a not in already}
    # GATE: only OWNER-LINKED candidates (reverse-WHOIS, CT/cert, co-host, passive DNS, engine reverses)
    # may seed. A candidate whose ONLY sources are non-owner classes (urlscan related-scan pages,
    # lookalike miners) is a lead to triage, never a fetch — collecting it would ingest a stranger's
    # host as estate and hand every later round its related pages too. RANK within the seedable set:
    # corroboration (|sources|) desc, then name.
    seedable = {a: v for a, v in fresh.items() if _owner_linked(v["sources"])}
    related = {a: v for a, v in fresh.items() if a not in seedable}
    ranked = sorted(seedable.items(), key=lambda kv: (-len(kv[1]["sources"]), kv[0]))
    pending = [a for a, _ in ranked][:max_new] if max_new else [a for a, _ in ranked]
    # the collected apexes' OWN subdomains: same registration, collected next round like the apex,
    # kept out of `pending`/`candidate_total` so they never read as new operator infrastructure
    sub_pending, sub_detail = _subdomain_frontier(collected, consumed)
    def _hop_of(v):
        # case-level sources (Censys exact-cert search, MO rows without a recorded estate host) are
        # owner checks against the estate as a whole → hop 1; a per-raw origin that is NOT in `hops`
        # is unknown provenance → assumed at depth, so its candidate can never be promoted
        origins = v.get("origins") or ()
        if not origins:
            return 1
        return 1 + min(hops.get(o, _unknown_hop(hops, depth)) for o in origins)
    return {
        "case": st["case"], "round": st.get("round", 0),
        "pending": pending,
        "candidates": {a: {"sources": sorted(v["sources"]),
                           "examples": sorted(v["examples"])[:4],
                           "origins": sorted(v.get("origins", ())),
                           "hop": _hop_of(v)} for a, v in ranked},
        "candidate_total": len(seedable),
        # expansion anchor: hosts at the depth limit were collected but NOT mined for new apexes
        "expansion_depth": depth,
        "leaves": sorted(leaves),
        # non-owner-sourced apexes (urlscan related pages, lookalikes): NOT seeded, surfaced for triage
        "related_leads": [{"apex": a, "sources": sorted(v["sources"]), "examples": sorted(v["examples"])[:4],
                           "why": ("only non-owner sources (" + ", ".join(sorted(v["sources"])) +
                                   ") — a page that loaded the host's resources or a lookalike, not the "
                                   "operator's registration; triage by hand, never auto-collected")}
                          for a, v in sorted(related.items(), key=lambda kv: (-len(kv[1]["sources"]), kv[0]))],
        "subdomains_pending": sub_pending,          # {apex: [host, …]} — next-round collection
        "subdomains": sub_detail,                   # {host: {apex, sources, dns}} incl. dead names
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
        print(f"  {fr['candidate_total']} fresh apex candidate(s); next {len(fr['pending'])} to collect "
              f"(expansion depth {fr['expansion_depth']}; {len(fr['leaves'])} leaf host(s) collected but not mined):")
        for apex in fr["pending"]:
            why = fr["candidates"].get(apex, {})
            print(f"    {apex:32} hop {why.get('hop', '?')}  via {', '.join(why.get('sources', []))}"
                  f"  ← {', '.join(why.get('origins', [])[:3]) or 'case-level'}")
        if fr.get("subdomains_pending"):
            n_sub = sum(len(v) for v in fr["subdomains_pending"].values())
            print(f"  {n_sub} live subdomain(s) of collected apex(es) to collect next (same registration — "
                  f"joined to the apex at ingest, never counted as new infrastructure):")
            for apex, subs in fr["subdomains_pending"].items():
                for sub in subs:
                    d = fr["subdomains"].get(sub, {})
                    print(f"    {sub:40} under {apex}  via {', '.join(d.get('sources', []))}")
        dead = [h for h, d in (fr.get("subdomains") or {}).items() if d.get("dns") is False]
        if dead:
            print(f"  {len(dead)} discovered subdomain(s) do not resolve (recorded, not collected): "
                  f"{', '.join(sorted(dead)[:8])}{' …' if len(dead) > 8 else ''}")
        if fr["metered_leads"]:
            print(f"  {len(fr['metered_leads'])} metered lead(s) — need approval before spending credits:")
            for ml in fr["metered_leads"][:12]:
                print(f"    [{ml['service']}] {ml['query']}   — {ml['why']}")
        if fr.get("co_tenancy_leads"):
            print(f"  {len(fr['co_tenancy_leads'])} co-tenancy lead(s) HELD BACK from seeding "
                  f"(multi-tenant cert / shared hosting — free to check by hand):")
            for cl in fr["co_tenancy_leads"][:12]:
                print(f"    [{cl['check']}] {cl.get('ip') or cl.get('cert_id') or cl.get('artifact') or cl.get('term') or ''}   — {cl['why']}")
        if fr.get("related_leads"):
            rl = fr["related_leads"]
            print(f"  {len(rl)} related/lookalike lead(s) NOT seeded (non-owner sources — pages that loaded "
                  f"the host's resources, lookalikes; triage by hand):")
            for r in rl[:12]:
                print(f"    {r['apex']:32} via {', '.join(r['sources'])}")
            if len(rl) > 12:
                print(f"    … and {len(rl) - 12} more (frontier --json → related_leads)")
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
