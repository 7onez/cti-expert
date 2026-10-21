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
import threading
from datetime import datetime, timezone

# Serialises the cross-type loop's state.json read-modify-writes (pivoted / nodes) inside one
# process — the stdio MCP server runs tool calls on worker threads, so two corpus_search calls
# could otherwise interleave load→modify→save and lose a node. Cross-process writers are not
# covered (one harness run per case is the supported mode).
_STATE_LOCK = threading.RLock()


def _locked(fn):
    def wrapper(*a, **k):
        with _STATE_LOCK:
            return fn(*a, **k)
    wrapper.__name__, wrapper.__doc__ = fn.__name__, fn.__doc__
    return wrapper


_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
WP = os.path.join(ROOT, "WebPivot", "tools")
KB_TOOLS = os.path.join(ROOT, "tools", "kb")
for _p in (WP, KB_TOOLS):
    if _p not in sys.path:
        sys.path.insert(0, _p)

# Historical origin sweep (WebPivot/tools/wp_origin_history.py): every A/AAAA a host ever had, merged
# and CDN/parking-classified — the frontier collects the ORIGIN rows as IP seeds. Optional: without
# it the frontier simply proposes no IPs (the pre-sweep behaviour).
try:
    import wp_origin_history as _oh  # noqa: E402
except Exception:  # noqa: BLE001
    _oh = None

# registrable-domain reducer — reuse WebPivot's so apex logic matches the collectors exactly.
try:
    from wp_common import _registrable, has_known_tld as _has_known_tld  # noqa: E402
except Exception:
    def _registrable(host):
        parts = (host or "").strip(".").lower().split(".")
        # crude fallback (no PSL): keep last 2 labels, or 3 for common multi-part TLDs
        if len(parts) >= 3 and parts[-2] in ("com", "co", "org", "net", "gov", "edu"):
            return ".".join(parts[-3:])
        return ".".join(parts[-2:]) if len(parts) >= 2 else host

    def _has_known_tld(_):             # no PSL → cannot judge the TLD; block nothing
        return True

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
    import whois_eras as _whois_eras  # noqa: E402 — history -> OWNER links, single decision point
except Exception:
    class _whois_eras:      # fail-open: no history correlation rather than a crash
        _LIVE = {"email": "registrant_email", "name": "registrant_name",
                 "phone": "registrant_phone", "org": "registrant_org"}

        @staticmethod
        def owner_values(whois, kind):
            v = (whois or {}).get(_whois_eras._LIVE.get(kind, ""))
            return [v] if v else []

        @staticmethod
        def previous_owner_contacts(whois, kinds=("email", "phone")):
            return []
try:
    import cdn_ranges as _cdn        # CDN/cloud edge ranges — a shared edge IP is never an owner link
except Exception:
    _cdn = None
try:
    from noise_filters import is_noise_email as _is_noise_email   # registrar/privacy denylist
except Exception:
    def _is_noise_email(_):
        return False
try:
    from noise_filters import is_social_platform_ip as _is_social_ip   # never-seed platform edges
except Exception:
    def _is_social_ip(_):
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
MAX_WHOIS_SIBLINGS = 100  # domains on one registrant term before it reads as a bulk/reseller term
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
    across the many raw files that saw the same cert / IP / registrant term / artifact / origin."""
    return {"cert": {}, "cohost": {}, "whois": {}, "artifact": {}, "origin": {}}

# ONE noise policy. The shared-infrastructure denylist lives in tools/kb/noise_filters.py — the
# module whose whole job is "shared INFRASTRUCTURE, not a shared OPERATOR" and which the ingester
# and the KB queries already read. Keeping a second private copy here meant the loop's frontier
# gate and the correlation gate could disagree about the same domain; now they cannot.
try:
    from noise_filters import SAAS_TENANT_SUFFIXES as _SAAS
    from noise_filters import is_shared_infra_apex as _shared_infra_apex
    from noise_filters import is_managed_dns as _managed_dns
except Exception:
    _SAAS = frozenset()

    def _shared_infra_apex(apex):        # degrade to "block nothing" rather than block wrongly
        return False

    def _managed_dns(_):
        return False


def _is_shared_infra(apex):
    """Shared infrastructure by EITHER denylist: a CDN/SaaS/parking apex, or a managed / registrar
    DNS provider (its nameservers are stamped on every customer's domain — the provider's own apex
    is exactly as much a lead as cloudflare.com is)."""
    return _shared_infra_apex(apex) or _managed_dns(apex)

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
        _shared_ips_in(obj, out)
    return out


def approved_edge_allow(cdir):
    """Predicate (src_domain, dst_indicator) → True for a `hosted_on` edge the analyst's approval
    covers: an approved co-tenant or a case host of an approved box. The partition keeps the
    landlord rule for every OTHER edge to that IP (wp_origin_history.approval_allows)."""
    approved = _oh.approved_cohosts(cdir) if _oh is not None else {}
    if not approved:
        return None
    return lambda src, dst: _oh.approval_allows(approved, src, dst)


def _shared_ips_in(obj, out):
    """Add to `out` every IP one raw object shows to be shared/bulk hosting (see shared_hosting_ips)."""
    if not isinstance(obj, dict):
        return
    if (obj.get("meta") or {}).get("kind") == "ip":
        # an IPPivot raw (a collected origin IP): its own co-host union answers the same question
        ip = str((obj.get("meta") or {}).get("host") or "").strip()
        names = ((obj.get("artifacts") or {}).get("ip_intel") or {}).get("co_hosted_domains") or []
        apexes = {_frontier_apex(n) for n in (_clean_name(x) for x in names) if n}
        if ip and (len(apexes) > MAX_IP_COHOSTS or _is_cdn_ip(ip) or _is_social_ip(ip)):
            out.add(ip)
        return
    for piv in obj.get("pivots") or []:
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
            if (len(apexes) > MAX_IP_COHOSTS or (total > len(rows) and total > BULK_IP_RESULTS)
                    or _is_cdn_ip(ip) or _is_social_ip(ip)):
                out.add(ip)


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
    """A PATH (has a separator / is absolute) is used as given; a bare case ID always resolves to
    ROOT/cases/<id>. A bare ID is never matched against the CWD: a tool that once mistook the ID
    for a directory (WP_CASE_DIR=<id>) leaves a stray `<cwd>/<id>/`, and treating that as the case
    split state.json from the real case."""
    c = str(case)
    if os.path.isabs(c) or os.sep in c or (os.altsep and os.altsep in c):
        return c
    return os.path.join(ROOT, "cases", c)


def state_path(cdir):
    return os.path.join(cdir, "state.json")


def _fresh_state(case):
    return {
        "version": STATE_VERSION, "case": case, "created": _now(), "updated": _now(),
        "status": "expanding",          # expanding | converged | cold | awaiting-analyst | error
        "round": 0, "depth_limit": None,
        "collected": [], "pending": [], "consumed": [],
        "metered_leads": [], "history": [], "reopen_count": 0, "note": None,
        # Cross-type loop: candidate ids already dispatched this case (propose() skips them).
        # Additive — older state files backfill to [] via load_state.
        "pivoted": [],
        # Cross-type loop: candidate ids the Plan phase dropped (id -> {why, round}); propose()
        # never re-offers them. reopen() clears the map (dict; backfilled).
        "dropped": {},
        # Cross-type loop: typed nodes the case reached ("type|selector" -> {type, selector,
        # rung_class, hop, origins, route}). Seeds of any type enter at hop 0; every corpus pivot
        # adds its result rows at origin hop + 1. propose() pivots on them (dict; backfilled).
        "nodes": {},
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
                for k in ("collected", "pending", "consumed", "metered_leads", "history", "pivoted"):
                    if not isinstance(st.get(k), list):
                        st[k] = []
                if not isinstance(st.get("nodes"), dict):
                    st["nodes"] = {}
                if not isinstance(st.get("dropped"), dict):
                    st["dropped"] = {}
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
    if not a or "." not in a or not _has_known_tld(a):
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
#   * webamon_same_kit — hosts whose Webamon scan shares the seed's kit fingerprints (DOM band /
#     link set / script set). Same KIT is the same phishing template, not the same registrant: a
#     kit is sold and resold, so its other deployments are as often other crews as the same one.
# They stay visible as `related_leads` for analyst triage; seeding them is how a 12-host estate
# drifted into 300 strangers' hosts (and their subdomains) in one loop run.
_NON_OWNER_SOURCES = frozenset({"impersonation", "archive_related_domain",
                                "urlscan_related", "urlscan_related_domain", "webamon_same_kit",
                                # an origin IP's own PTR / self-hosted MX name: chosen by whoever runs
                                # the box (the operator, or a hoster's naming scheme) — a lead to triage
                                "ip_ptr", "ip_mx",
                                # a host embedded in a sample (BinaryPivot app_backend_host): can be a
                                # shared backend, SaaS API or kit default — seeds only if corroborated
                                "binary_backend_host"})
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
    """True only when the IP is a KNOWN CDN/cloud EDGE. Unknown/unloadable → False (don't over-block).
    Customer cloud compute (GCE ranges — wp_origin_history.is_rentable_cloud) is a rented origin, not
    an edge: its co-tenants go through the MAX_IP_COHOSTS / BULK_IP_RESULTS count guards instead."""
    idx = _cdn_index()
    if not idx or not ip:
        return False
    try:
        c = _cdn.classify(str(ip).strip(), idx)
    except Exception:
        return False
    if _oh is not None and _oh.is_rentable_cloud(c):
        return False
    return bool(c.get("cdn"))


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
    if "." not in s or _IP_RE.match(s) or not _HOSTNAME_RE.match(s) or not _has_known_tld(s):
        return ""
    return s


def _cohost_name(row):
    """The domain-ish name in an IP-reverse row. FOFA rows carry a clean `domain` plus a `host`
    that may be `ip:port` or a URL; prefer the former, fall back to a parseable host."""
    if not isinstance(row, dict):
        return _clean_name(row)
    return _clean_name(row.get("domain") or "") or _clean_name(row.get("host") or "")


def _free_candidates_from_raw(obj, cands, seed_apexes, deferred=None, approved=None):
    """Mine one raw pivot_extract JSON for NEW registrable apexes discovered FOR FREE this round.

    Co-tenancy is filtered here, not later: a multi-tenant TLS cert or a shared-hosting IP names
    other CUSTOMERS, and seeding from those would both waste the round and poison the KB with
    fake shared indicators. Those are routed into `deferred` as analyst leads instead (see
    MAX_CERT_APEXES / MAX_IP_COHOSTS)."""
    deferred = _new_deferred() if deferred is None else deferred
    host = (obj.get("meta") or {}).get("host") or "?"
    # CURRENT WHOIS `created` for this host (artifacts.whois is the point-in-time record the
    # collector wrote for THIS host, same source _whois_identity/_estate_context treat as "current
    # registrant only") — the crt.sh guard below needs it to tell a live co-SAN from a previous
    # owner's leftover cert.
    registered_on = ((obj.get("artifacts") or {}).get("whois") or {}).get("created")
    if (obj.get("meta") or {}).get("kind") == "ip":
        _ip_raw_candidates(obj, cands, seed_apexes, deferred, host, approved=approved)
    for piv in obj.get("pivots", []) or []:
        kind, val = piv.get("kind", ""), piv.get("value")
        # pivots whose VALUE is itself a co-domain / lookalike / trusted-origin host
        if kind in ("tls_cert:co_san", "cors_allowed_origin", "impersonation:candidate",
                    "urlscan_related_domain", "archive_related_domain"):
            _add_cand(cands, str(val), kind.split(":")[0], seed_apexes, origin=host)
        lr = piv.get("live_results") or {}
        if kind == "domain":
            _crtsh_candidates(lr.get("crtsh") or {}, cands, seed_apexes, deferred, host, registered_on)
            for h in (lr.get("passivedns") or {}).get("hosts") or []:
                _add_cand(cands, h.get("host") if isinstance(h, dict) else h, "passive_dns", seed_apexes, origin=host)
            for d in (lr.get("urlscan") or {}).get("domains") or []:
                _add_cand(cands, d, "urlscan_related", seed_apexes, origin=host)
            # Webamon same-kit siblings: same template ≠ same operator — a related lead, never a seed
            # (label is in _NON_OWNER_SOURCES). The block already dropped its list when the fingerprint
            # was boilerplate (> max_siblings), so an empty `domains` is the prevalence guard firing.
            for d in (lr.get("webamon_same_kit") or {}).get("domains") or []:
                _add_cand(cands, d, "webamon_same_kit", seed_apexes, origin=host)
            # co-hosted domains from a PRIOR keyed run (already paid for — reusing is free). DNSLytics
            # reverse-IP lives under its own key ON PURPOSE: its rows are IPs, so they take the
            # co-host route (CDN-range + MAX_IP_COHOSTS guards) instead of the artifact route below.
            for key in ("fofa_ip_reverse", "pdns_ip_reverse", "dnslytics_reverseip"):
                _cohost_candidates(lr.get(key) or {}, cands, seed_apexes, deferred, host, key)
        # reverse-WHOIS siblings left behind by a prior --whois-reverse run (WhoisXML current/historic
        # + SecurityTrails' DSL — same shape, same privacy + MAX_WHOIS_SIBLINGS guards). Only a
        # registrant EMAIL/PHONE reverse is an owner link (RULE 5 decisive join keys); a NAME/ORG
        # reverse answers every namesake ("Nguyen Van A" registers thousands of unrelated domains),
        # so its results are held as a lead to confirm on the email/phone triple, never seeded.
        decisive = kind in _DECISIVE_REVERSE_KINDS
        for st in ("reverse_whois_current", "reverse_whois_historic", "securitytrails_reverse_whois"):
            if decisive:
                _whois_candidates(lr.get(st) or {}, cands, seed_apexes, deferred, host, st)
            else:
                _defer_name_reverse(lr.get(st) or {}, deferred, host, st, kind, val)
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


def _crtsh_candidates(crt, cands, seed_apexes, deferred, host, registered_on=None):
    """CT names → frontier seeds, EXCEPT names that only ever appear on a multi-tenant cert, a
    previous-owner-era cert, or a truncated (unexamined) CT listing entry.

    crt.sh returns whole certificates; a cert covering more than MAX_CERT_APEXES registrable
    apexes is a hoster's shared bundle (cPanel AutoSSL / LE multi-domain / a CDN's managed cert), so
    its co-names are other customers, not the operator's siblings. Those certs are recorded as
    `cert_overlap` leads — the analyst can still test a specific pair, where only a SAN cross-cover
    survives. A host whose listing carries ANY such wide cert lives on a multi-tenant platform; the
    platform also mints small 2–4-name certs pairing random customers on one load balancer, so on
    that host a narrow co-SAN is a co-tenant too until cert_overlap says otherwise — it is held back
    as a lead, never seeded.

    A host with NO wide cert still cannot trust a foreign co-SAN on a narrow cert blindly: `host`
    may be a RE-REGISTRATION of a name with prior owners, and crt.sh logs certs forever — a cert
    from a previous owner's tenancy names THAT owner's other domains, not this operator's. So a
    foreign co-SAN only seeds when its own cert's `not_before` is on/after `registered_on` (the
    host's current WHOIS `created` date, UTC calendar day); a stale cert, or an unknown
    registration/issue date, holds the name back as a `previous_owner` / `unregistered` lead instead
    of guessing. Own-apex names always seed (same registration, not a co-tenancy question).

    wp_ct lists only the newest `listing.max_certs` certificates (recording `cert_total` and
    `truncated`) but builds the flat `subdomains` list from ALL of them plus hostname-only sources
    (Shodan CTL's /hostnames) — so a name can appear there whose cert was never examined above at
    all. Such a foreign name cannot be checked against either guard, so it is deferred as
    `unexamined` rather than guessed at; only own-apex names from the flat list seed directly."""
    registered_ord = _date_ord(registered_on) if registered_on else None
    own, foreign_seed, stale_foreign, unknown_reg_foreign = set(), set(), set(), set()
    examined = set()
    wide = 0
    for cert in crt.get("certs") or []:
        names = {n for n in (_clean_name(x) for x in (cert.get("names") or [])) if n}
        if not names:
            continue
        examined |= names
        apexes = {_frontier_apex(n) for n in names}
        if len(apexes) > MAX_CERT_APEXES:
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
        cert_own = {n for n in names if _frontier_apex(n) in seed_apexes}
        cert_foreign = names - cert_own
        own |= cert_own
        if not cert_foreign:
            continue
        not_before = _date_ord(cert.get("not_before"))
        if registered_ord is None:
            unknown_reg_foreign |= cert_foreign
        elif not_before is None or not_before < registered_ord:
            stale_foreign |= cert_foreign
        else:
            foreign_seed |= cert_foreign
    if wide and (foreign_seed or stale_foreign or unknown_reg_foreign):
        held = foreign_seed | stale_foreign | unknown_reg_foreign
        pairs = sorted({_frontier_apex(nm) for nm in held})
        deferred["cert"][f"platform:{host}"] = {
            "check": "cert_overlap", "cost": "free", "seen_on": host, "cert_id": None, "issuer": None,
            "apex_count": len(pairs), "sample_apexes": pairs[:6],
            "why": (f"{host} sits on a multi-tenant cert platform ({wide} wide cert(s) in its CT "
                    f"listing); its {len(pairs)} narrow co-SAN pairing(s) read as load-balancer "
                    "co-tenants, so they were NOT seeded. Run cert_overlap on a pair to confirm a "
                    "genuine SAN cross-cover."),
        }
        foreign_seed, stale_foreign, unknown_reg_foreign = set(), set(), set()
    for nm in own | foreign_seed:
        _add_cand(cands, nm, "crtsh_san", seed_apexes, origin=host)
    if stale_foreign:
        pairs = sorted({_frontier_apex(nm) for nm in stale_foreign})
        deferred["cert"][f"previous_owner:{host}"] = {
            "check": "cert_overlap", "cost": "free", "seen_on": host, "cert_id": None, "issuer": None,
            "apex_count": len(pairs), "sample_apexes": pairs[:6],
            "why": (f"{len(pairs)} co-SAN apex(es) sit only on certs issued before {host}'s current "
                    f"registration ({str(registered_on)[:10]}) — a previous-owner-era cert, so they "
                    "were NOT seeded. Run cert_overlap if you suspect a genuine cross-cover."),
        }
    if unknown_reg_foreign:
        pairs = sorted({_frontier_apex(nm) for nm in unknown_reg_foreign})
        deferred["cert"][f"unregistered:{host}"] = {
            "check": "cert_overlap", "cost": "free", "seen_on": host, "cert_id": None, "issuer": None,
            "apex_count": len(pairs), "sample_apexes": pairs[:6],
            "why": (f"{host}'s current registration date is unknown, so {len(pairs)} co-SAN apex(es) "
                    "on its narrow cert(s) cannot be confirmed to postdate it — NOT seeded. Run "
                    "cert_overlap if you suspect a genuine cross-cover."),
        }
    unexamined_foreign = set()
    for sd in crt.get("subdomains") or []:
        name = _clean_name(sd)
        if not name:
            continue
        if _frontier_apex(name) in seed_apexes:
            _add_cand(cands, name, "crtsh_san", seed_apexes, origin=host)
        elif name not in examined:
            unexamined_foreign.add(name)
    if unexamined_foreign:
        pairs = sorted({_frontier_apex(nm) for nm in unexamined_foreign})
        listed = len(crt.get("certs") or [])
        if "truncated" not in crt:      # collected before wp_ct recorded the true total
            reason = "pre-contract collection: its certificate listing may have been truncated"
        elif crt.get("truncated"):
            reason = f"CT listing truncated: {listed} of {crt.get('cert_total')} certificates examined"
        else:
            reason = "named only by a hostname index, with no certificate row to examine"
        deferred["cert"][f"unexamined:{host}"] = {
            "check": "cert_overlap", "cost": "free", "seen_on": host, "cert_id": None, "issuer": None,
            "apex_count": len(pairs), "sample_apexes": pairs[:6],
            "cert_total": crt.get("cert_total"), "truncated": bool(crt.get("truncated")),
            "why": (f"{len(pairs)} foreign apex(es) named only in {host}'s flat CT subdomain listing "
                    f"— their certificates were never among the ones examined ({reason}), so they "
                    "were NOT seeded. Run cert_overlap on a specific pair if you suspect a real SAN "
                    "cross-cover."),
        }


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


# Pivot kinds whose reverse-WHOIS results are OWNER links (RULE 5: only registrant e-mail/phone
# are decisive join keys). Anything else carrying a reverse block — the registrant NAME/ORG — is a
# namesake search and never seeds.
_DECISIVE_REVERSE_KINDS = frozenset({"whois:registrant_email", "whois:registrant_phone"})


def _defer_name_reverse(blk, deferred, host, source, kind, val):
    """A non-decisive (name/org) reverse-WHOIS block → one `whois` lead, never frontier seeds.
    Its domains are namesakes until the email/phone triple ties one of them to the estate."""
    domains = blk.get("domains") or []
    if not domains:
        return
    count = blk.get("count")
    n = int(count) if isinstance(count, int) else len(domains)
    term = str(blk.get("term") or val or "").strip()
    key = f"{kind}:{term}" if term else f"{source}:{host}"
    prev = deferred["whois"].get(key) or {}
    deferred["whois"][key] = {
        "check": "name reverse-WHOIS (collision-prone)", "cost": "free", "seen_on": host,
        "source": source, "term": term, "sibling_count": max(n, prev.get("sibling_count") or 0),
        "sample_domains": sorted({*prev.get("sample_domains", []),
                                  *(str(d).lower() for d in domains)})[:6],
        "why": (f"{kind.split(':')[-1].replace('_', ' ')} '{term}' answers with {n} domain(s) — a "
                "name/org is not a decisive join key (namesakes), so none were seeded; confirm a "
                "specific domain on the registrant email/phone before adding it"),
    }



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
    social = bool(ip) and _is_social_ip(ip)
    if social:
        reason = (f"{ip} is a social-platform edge range (noise_filters social_platform_ip_ranges) — "
                  f"its co-tenants are unrelated embedders and are never seeded")
    elif ip and _is_cdn_ip(ip):
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
            **({"never_seed": True} if social else {}),
        }
        return
    for n in names:
        _add_cand(cands, n, "ip_cohost", seed_apexes, origin=host)


def _origin_lead(ip, check, seen, apexes, why, proposable=False):
    """A held co-tenancy lead from the origin-IP sweep. `domains` always lists EVERY apex (the analyst
    sees the whole tenant set, not a sample); `sample_apexes` is what propose() turns into approval
    candidates — the full set only for a `proposable` (approve-to-collect) lead, a 6-name sample
    otherwise, so an edge network's thousand customers are never offered for collection."""
    doms = sorted(apexes)
    return {"check": check, "cost": "free", "seen_on": seen, "source": "ippivot", "ip": ip,
            "cohost_count": len(doms), "sample_apexes": doms if proposable else doms[:6],
            "domains": doms, "why": why}


def _ip_raw_candidates(obj, cands, seed_apexes, deferred, ip, approved=None):
    """A collected ORIGIN IP's own raw (IPPivot) → frontier rows, through the same guards as every
    other IP reverse.

    Co-hosted domains (FOFA / Shodan / Censys / Validin / HackerTarget / CIRCL pDNS / passive-SSL CNs)
    go through _cohost_candidates (CDN range + MAX_IP_COHOSTS + bulk guards → neighbour rung). One
    extra rail: when meta.origin_context says the case's hosts used this box only HISTORICALLY (or on
    no dated record), or the box sits on a proxy-or-host network (DDoS-Guard, StackPath — `ambiguous`),
    today's co-tenants are held as a `cohost` lead naming the tenancy, never seeded. PTR / self-hosted
    MX names are related leads."""
    ii = (obj.get("artifacts") or {}).get("ip_intel") or {}
    ctx = (obj.get("meta") or {}).get("origin_context") or {}
    cls = ii.get("classification") or {}
    # the SAME name list KB ingest counts (co-hosted + urlscan history co-tenants)
    names = [n for n in (_clean_name(x) for x in list(ii.get("co_hosted_domains") or [])
                         + list(ii.get("urlscan_cotenants") or [])) if n]
    if names and cls.get("kind") == "bogon":
        names = []                                 # a non-routable answer has no tenants of its own
    # SECOND LOOK with the box's own ASN/org: most history sources carry none, so an Akamai / Imperva
    # edge or a DDoS-Guard box is often queued as `origin` and only the IP lookup names its network.
    verdict = (_oh.collected_verdict(ip, ii) if _oh is not None else {}).get("status")
    if verdict == "ambiguous":
        ctx = dict(ctx, ambiguous=True)
    if names and verdict in ("cdn", "parking", "bogon"):
        apexes = {a for a in (_frontier_apex(n) for n in names) if not _is_noise_apex(a, seed_apexes)}
        if apexes:
            net = " ".join(x for x in ((ii.get("ipinfo") or {}).get("asn"),
                                       (ii.get("ipinfo") or {}).get("org_name")) if x) or "its network"
            deferred["cohost"][ip] = _origin_lead(
                ip, "edge network (IP lookup)", ip, apexes,
                f"{ip}'s own lookup names {net} — a shared {verdict} network, not an operator box; its "
                f"co-hosted domains are other customers and were NOT seeded")
        names = []
    hold = _oh.hold_cotenants(ctx) if _oh is not None else bool(ctx.get("stale"))
    if names and hold:
        apexes = {a for a in (_frontier_apex(n) for n in names) if not _is_noise_apex(a, seed_apexes)}
        if apexes:
            seen = ", ".join(ctx.get("hosts") or []) or "a case host"
            why = (f"{ip} sits on a network that sells DDoS proxying AND servers — its co-tenants may be "
                   f"other customers behind the same protection edge; date and tie each one by an "
                   f"identity artifact before treating it as a sibling" if ctx.get("ambiguous") else
                   f"{ip} is a {ctx.get('era') or 'historical'} origin of {seen} (last seen "
                   f"{ctx.get('last_seen') or 'undated'}) — its CURRENT co-tenants may postdate that "
                   f"tenancy; date each one before treating it as a sibling")
            deferred["cohost"][ip] = _origin_lead(
                ip, ("ambiguous-network co-tenancy" if ctx.get("ambiguous") else "historical-origin co-tenancy"),
                seen, apexes, why)
        names = []
    ok_domains = ((approved or {}).get(ip) or {}).get("domains") or set()
    all_names = list(names)        # the automatic-vs-approval decision is on the WHOLE tenant set
    if names and ok_domains:
        # the analyst approved THESE co-tenants: seed them as neighbours past the VPS / shared-hosting
        # bounds (approval is the evidence; collected, never attributed). Every other name on the box
        # still goes through the rules below — a site left unapproved never turns automatic.
        for n in names:
            if _oh._apex(n) in ok_domains:
                _add_cand(cands, n, "ip_cohost", seed_apexes, origin=ip)
        names = [n for n in names if _oh._apex(n) not in ok_domains]
    if names and _oh is not None and _oh.is_vps_origin(ip, ii):
        # cloud / VPS box (the IP lookup flags the network as hosting): a small tenant set is queued
        # and linked automatically; above the threshold EVERY domain goes to analyst approval. The
        # count is wp_origin_history.cotenant_count — the SAME one KB ingest uses, so the two sides
        # never land on opposite sides of the threshold.
        _all_apexes, count = _oh.cotenant_count(ii, all_names, exclude=ctx.get("hosts") or (),
                                                is_noise=_is_shared_infra)
        apexes, _ = _oh.cotenant_count(ii, names, exclude=ctx.get("hosts") or (), is_noise=_is_shared_infra)
        if count > _oh.VPS_AUTO_MAX_COTENANTS:
            seen = ", ".join(ctx.get("hosts") or []) or ip
            deferred["cohost"][ip] = _origin_lead(
                ip, "vps co-tenancy — approve", seen, apexes,
                (f"{ip} is a cloud/VPS origin of {seen} serving {count} other apexes "
                 f"(> {_oh.VPS_AUTO_MAX_COTENANTS}) — nothing was collected or linked; approve to collect "
                 f"them as neighbours and link them to the IP (never attributed)"),
                proposable=True)
            names = []
    if names:
        _cohost_candidates({"ip": ip, "hosts": names}, cands, seed_apexes, deferred, ip, "ippivot")
    for piv in obj.get("pivots") or []:
        if piv.get("kind") == "ip:ptr" and piv.get("value"):
            _add_cand(cands, str(piv["value"]), "ip_ptr", seed_apexes, origin=ip)
    mail = ii.get("mail") or {}
    if mail.get("mx") and not mail.get("managed"):
        for d in mail.get("mail_domains") or []:
            _add_cand(cands, d, "ip_mx", seed_apexes, origin=ip)


def _origin_ip_frontier(host_objs, have, hops, depth, deferred, shared_ips, max_ips=None, today=None):
    """The historical ORIGIN-IP sweep → (ips_pending, detail).

    `host_objs` = [(host, raw)] of EXPANDING hosts (leaves never widen the estate). Each host's merged
    origin history (wp_origin_history.host_origins — CDN / WAF / parking / bogon already dropped) is
    dated against its CURRENT registration: an address last seen before the domain was registered is
    the previous owner's (an `origin` lead, never collected). The rest are ranked per host (live, then
    corroboration, then recency) and capped at MAX_IPS_PER_HOST, then case-wide by era, number of case
    hosts, corroboration — capped at `max_ips` (None/0 = all). An IP already collected/consumed or
    already shown to be shared hosting by the case's own reverses is skipped."""
    if _oh is None:
        return [], {}
    agg = {}
    for host, obj in host_objs:
        _h, _reg, rows = _oh.host_origins(obj, today)
        taken = 0
        for r in rows:
            ip = r["ip"]
            if r["era"] == "previous_owner":
                deferred["origin"][f"{ip}@{host}"] = {
                    "check": "previous-owner origin IP", "cost": "free", "seen_on": host, "ip": ip,
                    "why": (f"{host} resolved to {ip} until {r.get('last_seen')}, before its current "
                            f"registration ({_reg}) — the previous owner's box, not collected"),
                }
                continue
            if ip in have or ip in shared_ips or taken >= _oh.MAX_IPS_PER_HOST:
                continue
            taken += 1
            a = agg.setdefault(ip, {"hosts": set(), "sources": set(), "first_seen": None,
                                    "last_seen": None, "live": False, "era": r["era"],
                                    "asn": r.get("asn"), "org": r.get("org"), "ambiguous": False})
            a["ambiguous"] = a["ambiguous"] or r.get("status") == "ambiguous"
            a["hosts"].add(host)
            a["sources"].update(r.get("sources") or ())
            if r.get("first_seen") and (a["first_seen"] is None or r["first_seen"] < a["first_seen"]):
                a["first_seen"] = r["first_seen"]
            if r.get("last_seen") and (a["last_seen"] is None or r["last_seen"] > a["last_seen"]):
                a["last_seen"] = r["last_seen"]
            a["live"] = a["live"] or bool(r.get("live"))
            if _oh._ERA_RANK[r["era"]] < _oh._ERA_RANK[a["era"]]:
                a["era"] = r["era"]
    ranked = sorted(agg.items(), key=lambda kv: (_oh._ERA_RANK[kv[1]["era"]], -len(kv[1]["hosts"]),
                                                 -len(kv[1]["sources"]), kv[0]))
    pending = [ip for ip, _ in ranked][:max_ips] if max_ips else [ip for ip, _ in ranked]
    detail = {ip: {"hosts": sorted(v["hosts"]), "sources": sorted(v["sources"]),
                   "first_seen": v["first_seen"], "last_seen": v["last_seen"], "live": v["live"],
                   "era": v["era"], "asn": v["asn"], "org": v["org"], "ambiguous": v["ambiguous"],
                   "hop": min(hops.get(h, _unknown_hop(hops, depth)) for h in v["hosts"]),
                   "cotenants": ("held as leads (DDoS-proxy-or-host network)" if v["ambiguous"]
                                 else "seedable" if v["era"] in _oh.SEEDABLE_COTENANT_ERAS
                                 else "held as leads (historical tenancy)")}
              for ip, v in ranked}
    return pending, detail


def _metered_leads_from_raw(obj, leads):
    """Pivots that would need a METERED call to expand — deferred for analyst approval, never
    auto-run by the free loop. Keyed by (service,value) so they dedupe across hosts."""
    host = (obj.get("meta") or {}).get("host") or "?"
    who = (obj.get("artifacts") or {}).get("whois") or {}
    owner_emails = {str(e).lower() for e in _whois_eras.owner_values(who, "email") if e}
    for piv in obj.get("pivots", []) or []:
        kind, val = piv.get("kind", ""), piv.get("value")
        if kind == "favicon_hash" and val is not None and not _fofa_already_paid(piv):
            leads[("FOFA", f"icon_hash={val}")] = {
                "service": "FOFA", "query": f'icon_hash="{val}"', "cost": "metered",
                "why": f"reverse favicon hash to find co-branded siblings (seen on {host})"}
        # A privacy proxy, a registrar-abuse mailbox, or a WHOIS-redacted string is shared by every
        # domain at that provider — reversing it is a guaranteed-noise result that COSTS CREDITS, so
        # it must never even be offered as a lead (same rule the frontier applies to free seeding).
        # A PRIOR-ERA registrant is a third party (whois_eras.py) and must never be offered either,
        # even if a stale pre-fix raw file still carries the pivot: gated on owner_emails, not the
        # pivot value alone.
        elif (kind == "whois:registrant_email" and val and not _is_privacy(val)
                and not _is_noise_email(str(val)) and "*" not in str(val)
                and str(val).lower() in owner_emails
                and not _reverse_already_paid(piv)):
            leads[("WhoisXML", f"reverse_email={val}")] = {
                "service": "WhoisXML", "query": f'reverse-whois email="{val}"', "cost": "metered",
                "why": f"reverse-WHOIS the registrant email for the owner's other domains ({host})"}
    # origin-candidate IPs -> FOFA ip= reverse (find more co-hosted domains). The collector tags a
    # loopback/private/reserved answer `kind: "bogon"` (wp_analyze.classify_ip) — a null-route or
    # parking A record, not an origin: reversing it returns every domain parked the same way.
    for piv in obj.get("pivots", []) or []:
        if piv.get("kind") != "domain":
            continue
        dns = (piv.get("live_results") or {}).get("dns") or {}
        for c in dns.get("ip_classification") or []:
            if c.get("cdn") is False and c.get("ip") and c.get("kind") != "bogon":
                leads[("FOFA", f"ip={c['ip']}")] = {
                    "service": "FOFA", "query": f'ip="{c["ip"]}"', "cost": "metered",
                    "why": f"reverse the origin IP {c['ip']} for co-hosted domains (from {host})"}


def _reverse_already_paid(piv):
    """True when the pivot already carries a completed (non-error) reverse-WHOIS block — the
    collector or email-deep bought it, so offering it again asks for spend that already happened."""
    lr = piv.get("live_results") or {}
    return any(isinstance(lr.get(k), dict) and not lr[k].get("error") and "domains" in lr[k]
               for k in ("reverse_whois_current", "reverse_whois_historic"))


def _fofa_already_paid(piv):
    """True when FOFA already ran on this pivot without error — asking again spends twice."""
    f = (piv.get("live_results") or {}).get("fofa")
    return isinstance(f, dict) and not f.get("error") and "results" in f

def _enrichment_leads_from_raw(obj, leads):
    """Build target-matched identity/OSINT leads over raw pivots. Machine-executable leads
    carry structured run specs (dispatcher op + argv); query-only leads stay open for the
    /cti agent. Keys dedupe across hosts, and enrichment_done records accounted-for work."""
    art = obj.get("artifacts") or {}
    host = (obj.get("meta") or {}).get("host") or "?"
    # an IPPivot raw (a collected origin IP) has no apex: phonebook / dork / GitHub / bucket legs on
    # "100.40" are junk work, so every apex-scoped leg below is skipped for it
    is_ip = (obj.get("meta") or {}).get("kind") == "ip" or bool(_IP_RE.match(host)) or ":" in host
    apex = "" if is_ip else _frontier_apex(host)
    benign = _benign_set()
    # registrant emails (current owner only — whois_eras.py) — the high-signal identities; skip
    # privacy/registrar noise. History is never mined flat here: a previous owner (drop-catch,
    # resale) is a third party and must never become an email-deep/reverse-WHOIS lead.
    who = art.get("whois") or {}
    owner_emails = {str(e).lower() for e in _whois_eras.owner_values(who, "email") if e}
    emails = set(owner_emails)
    for piv in obj.get("pivots", []) or []:
        if piv.get("kind") == "whois:registrant_email" and piv.get("value"):
            v = str(piv["value"]).lower()
            if v in owner_emails:      # never a stale/prior-era pivot value
                emails.add(v)
    for em in emails:
        if (not em or "*" in em or em in benign
                or _is_privacy(em) or _is_noise_email(em)):
            continue
        leads[("email-deep", em)] = {
            "tool": "/email-deep", "value": em, "key": f"email-deep:{em}", "cost": "metered",
            "run": [{"op": "email-deep", "argv": [em]}],
            "why": (f"Hudson Rock, ZoneCruncher, one IntelX stealer-log search and reverse-WHOIS "
                    f"preview for {em}. Do not also run /breach-deep or /intelx on this email.")}
    if apex and apex not in benign:
        for piv in obj.get("pivots", []) or []:
            kind = str(piv.get("kind") or "")
            val = str(piv.get("value") or "").strip()
            if not val:
                continue
            if kind == "whois:registrant_phone":
                leads[("phone", val)] = {
                    "tool": "/phone", "value": val, "key": f"phone:{val}", "cost": "free",
                    "run": [{"op": "phone", "argv": [val]}],
                    "why": f"OSINT decomposition of verified registrant phone {val}"}
                leads[("cld-phone", val)] = {
                    "tool": "intel.py cld route", "value": val, "key": f"cld-phone:{val}",
                    "cost": "free", "run": [{"op": "cld", "argv": ["route", val]}],
                    "why": f"Feeds checkphone + Shield IoC for registrant phone {val}"}
            elif kind == "telegram":
                m = re.fullmatch(r"(?:https?://)?(?:t\.me/|telegram\.me/)?@?([A-Za-z0-9_]{4,})", val, re.I)
                if m and not val.startswith("+"):  # invite tokens are not operator handles
                    handle = m.group(1).lower()
                    leads[("cld-telegram", handle)] = {
                        "tool": "intel.py cld route", "value": f"t.me/{handle}",
                        "key": f"cld-telegram:{handle}", "cost": "free",
                        "run": [{"op": "cld", "argv": ["route", f"t.me/{handle}"]}],
                        "why": f"Shield Telegram posts for handle {handle} — not a domain lookup"}
            elif kind in ("username", "dev_username") and piv.get("confidence") == "high":
                handle = val.lower()
                leads[("cld-actor", handle)] = {
                    "tool": "intel.py cld actor-usernames", "value": val,
                    "key": f"cld-actor:{handle}", "cost": "free",
                    "run": [{"op": "cld", "argv": ["actor-usernames", val]}],
                    "why": f"Shield threat-actor username map for verified developer handle {val}"}
    # per-apex OSINT/dork legs (deduped by apex) — skip benign/victim/shared-infra apexes so the
    # legit impersonation target (e.g. the real hospital) never gets metered breach/leak leads (§2.5)
    if apex and apex != "?" and apex not in benign and not _is_shared_infra(apex):
        org = str((art.get("whois") or {}).get("registrant_org") or "").strip()
        if (org and len(org) >= 3
                and not re.search(r"privacy|redacted|whois|proxy|guard|protected|domains by", org, re.I)):
            leads[("cld-org", org.lower())] = {
                "tool": "intel.py cld ransomware + internal-leaks", "value": org,
                "key": f"cld-org:{org.lower()}", "cost": "free",
                "run": [{"op": "cld", "argv": ["ransomware", org]},
                        {"op": "cld", "argv": ["internal-leaks", org]}],
                "why": (f"Shield ransomware victims and internal-document leaks for org {org}. "
                        f"The collector searched the host, not this name.")}
        leads[("intelx-phonebook", apex)] = {
            "tool": "/intelx phonebook", "value": apex, "key": f"intelx-phonebook:{apex}",
            "cost": "metered", "run": [{"op": "intelx", "argv": ["phonebook", apex]}],
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
            "tool": "github_harvest", "value": f"github.com/{login}",
            "key": f"github-account:{login.lower()}", "cost": "free",
            "run": [{"op": "github", "argv": [f"github.com/{login}"]}],
            "why": f"GitHub account linked from {host}: harvest committer e-mails and former logins"}


# Leak/stealer FAN-OUT (case_enrich): every CONFIRMED selector of the case — never a kit/neighbour
# one — gets every leak vendor its type supports, as ordinary machine-executable enrichment leads
# (same checkpointing, spend gate and enrichment_done closure as every other lead). POLICY is
# reference DATA (tools/kb/references/leak_fanout.json); the fallback is the conservative minimum:
# the unlimited CLD leg only, every other vendor stated as not consulted.
_LEAK_NA_FALLBACK = {"na": "leak_fanout.json unreadable — vendor not planned"}
_LEAK_FALLBACK = {
    "selection": {"max_owner_hop": 0, "username_regex": r"^@?[A-Za-z0-9_.\-]{3,64}$"},
    "vendors": ["cld", "intelx", "hudsonrock", "deep_profile"],
    "plan": {
        "email": {"cld": {"op": "cld", "argv": ["leaks", "{v}", "--input-type", "email", "--limit", "100"]}},
        "username": {"cld": {"op": "cld", "argv": ["leaks", "{v}", "--input-type", "username", "--limit", "100"]}},
        "phone": {"cld": {"op": "cld", "argv": ["route", "{v}"], "key": "cld-phone:{v}"}},
        "domain": {"cld": {"op": "cld", "argv": ["leaks", "{v}", "--input-type", "domain", "--limit", "100"]}},
    },
}
try:
    _LEAK_REF = _kb_refs.load_ref(_kb_refs.ref_path(_kb_refs.__file__, "leak_fanout.json"), _LEAK_FALLBACK)
except Exception:
    _LEAK_REF = dict(_LEAK_FALLBACK)
_LEAK_SEL = _LEAK_REF.get("selection") or _LEAK_FALLBACK["selection"]
LEAK_VENDORS = tuple(_LEAK_REF.get("vendors") or _LEAK_FALLBACK["vendors"])
LEAK_PLAN = _LEAK_REF.get("plan") or _LEAK_FALLBACK["plan"]
_LEAK_USER_RE = re.compile(str(_LEAK_SEL.get("username_regex") or _LEAK_FALLBACK["selection"]["username_regex"]))
_LEAK_MAX_HOP = int(_LEAK_SEL.get("max_owner_hop", 0))


def leak_vendor_plan(type_, value):
    """{vendor: {"op","argv","key"} | {"via": vendor} | {"na": reason}} for one selector — every
    LEAK_VENDORS column is present, so a coverage table never silently drops a vendor."""
    plan = LEAK_PLAN.get(type_) or {}
    out = {}
    for vendor in LEAK_VENDORS:
        row = plan.get(vendor) or _LEAK_NA_FALLBACK
        if row.get("op"):
            argv = [str(a).replace("{v}", value) for a in (row.get("argv") or [])]
            key = str(row.get("key") or f"leak:{vendor}:{type_}:{{v}}").replace("{v}", value)
            out[vendor] = {"op": row["op"], "argv": argv, "key": key}
        elif row.get("via"):
            out[vendor] = {"via": str(row["via"])}
        else:
            out[vendor] = {"na": str(row.get("na") or "not planned for this selector type")}
    return out


def _leak_owner_node(n):
    """True for an analyst seed (hop-0, route seed) or a node holding an OWNER rung class. A node
    reached only through kit / neighbour rows (co-tenant, shared kit, exchange) is never confirmed."""
    from selector_types import rung_for
    if n.get("route") == "seed" and int(n.get("hop") or 0) == 0:
        return True
    classes = [c for c in (n.get("rung_classes") or [n.get("rung_class") or ""]) if c]
    return any(rung_for(c) == "owner" for c in classes)


def leak_selectors(case):
    """Confirmed selectors to leak-check: [{type, value, origin}] with type email|username|phone|
    domain. Sources, each restricted to the OWNER side of the case:
      * typed nodes that are analyst seeds or carry an owner rung class (state.json nodes);
      * the analyst's seed domains (harness_seeds.json, hop-0 hosts) — the registrable apex, never a
        platform / shared-infra / vendor apex (never_seed);
      * WHOIS registrant email / phone of collected hosts at hop <= max_owner_hop that are not
        kit/neighbour tier hosts (current owner era only — whois_eras);
      * social-intake account usernames (enrichment/meta_transparency/*.json handles, kind=username).
    Kit- and neighbour-rung selectors are excluded by construction."""
    cdir = _case_dir(case)
    st = load_state(case)
    tiers = tier_hosts(cdir)
    hops, depth = _hops_and_depth(st)
    benign = _benign_set()
    out = {}

    def add(t, v, origin):
        v = str(v or "").strip()
        if t == "username":
            v = v.lstrip("@")
            if not _LEAK_USER_RE.match(v):
                return
            v = v.lower()
        elif t == "email":
            v = v.lower()
            if not v or "*" in v or v in benign or _is_privacy(v) or _is_noise_email(v):
                return
        elif t == "domain":
            v = _frontier_apex(v.split("://", 1)[-1].split("/")[0].split(":")[0].lower().rstrip("."))
            if not v or v in tiers or never_seed(v):
                return
        if not v or t not in LEAK_PLAN:
            return
        out.setdefault((t, v), {"type": t, "value": v, "origin": origin})

    for n in (st.get("nodes") or {}).values():
        if not isinstance(n, dict) or not _leak_owner_node(n):
            continue
        t, sel = str(n.get("type") or "").lower(), str(n.get("selector") or "")
        seed = n.get("route") == "seed"
        origin = "seed" if seed else f"owner-node:{(n.get('origins') or ['?'])[0]}"
        if t in ("email", "phone", "domain", "username"):
            add(t, sel, origin)
        elif t == "telegram":
            add("username", sel.rsplit("/", 1)[-1], origin)
        elif t == "string" and seed:
            add("username", sel, origin)
    seeds = set()
    try:
        with open(os.path.join(cdir, "harness_seeds.json"), encoding="utf-8") as fh:
            seeds = {str(s).lower() for s in (json.load(fh) or [])}
    except Exception:  # noqa: BLE001
        pass
    seeds |= {h for h, hop in hops.items() if hop == 0}
    for s in sorted(seeds):
        add("domain", s, "seed")
    for path in sorted(glob.glob(os.path.join(cdir, "raw", "*.json"))):
        try:
            with open(path, encoding="utf-8") as fh:
                obj = json.load(fh)
        except Exception:  # noqa: BLE001
            continue
        meta = obj.get("meta") or {}
        host = str(meta.get("host") or os.path.basename(path)[:-5]).lower()
        if host in tiers or _frontier_apex(host) in tiers or meta.get("kind") == "ip":
            continue
        if hops.get(host, _unknown_hop(hops, depth)) > _LEAK_MAX_HOP:
            continue
        who = (obj.get("artifacts") or {}).get("whois") or {}
        owner_emails = {str(e).lower() for e in _whois_eras.owner_values(who, "email") if e}
        for em in owner_emails:
            add("email", em, f"whois-registrant:{host}")
        for piv in obj.get("pivots", []) or []:
            if piv.get("kind") == "whois:registrant_phone" and piv.get("value"):
                add("phone", piv["value"], f"whois-registrant:{host}")
    for path in sorted(glob.glob(os.path.join(cdir, "enrichment", "meta_transparency", "*.json"))):
        try:
            with open(path, encoding="utf-8") as fh:
                doc = json.load(fh)
        except Exception:  # noqa: BLE001
            continue
        for h in (doc.get("handles") or []) if isinstance(doc, dict) else ():
            if isinstance(h, dict) and h.get("kind") == "username":
                add("username", h.get("value"), f"social:{h.get('platform') or '?'}")
    return sorted(out.values(), key=lambda r: (r["type"], r["value"]))


def _leak_leads(case, leads):
    """Fold the leak fan-out into the enrichment-lead map. A lead whose key already exists (the
    registrant email-deep / cld-phone leads) is tagged, never duplicated."""
    try:
        selectors = leak_selectors(case)
    except Exception:  # noqa: BLE001 — a broken selector read never blocks the frontier
        return
    for s in selectors:
        for vendor, step in leak_vendor_plan(s["type"], s["value"]).items():
            if not step.get("op"):
                continue
            key = step["key"]
            tag = {"vendor": vendor, "type": s["type"], "selector": s["value"], "origin": s["origin"]}
            slot = next((v for v in leads.values() if v.get("key") == key), None)
            if slot is not None:
                slot.setdefault("leak", []).append(tag)
                continue
            leads[("leak", key)] = {
                "tool": f"leak fan-out ({vendor})", "value": s["value"], "key": key,
                "cost": "metered" if step["op"] in ("email-deep", "intelx", "hudsonrock") else "free",
                "run": [{"op": step["op"], "argv": step["argv"]}], "leak": [tag],
                "why": (f"mandatory leak/stealer check of confirmed {s['type']} {s['value']} "
                        f"({s['origin']}) — exposure, not attribution")}



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


def _enrichment_index(cdir):
    """Case-local executed-lead summaries; query-only leads have no result row."""
    try:
        with open(os.path.join(cdir, "enrichment", "index.json"), encoding="utf-8") as fh:
            leads = json.load(fh).get("leads") or {}
    except (OSError, ValueError, AttributeError):
        return []
    if not isinstance(leads, dict):
        return []
    return [{"key": key, "outcome": row.get("outcome", "?"),
             "summary": str(row.get("summary") or "")[:300],
             "file": row.get("file") or ""}
            for key, row in sorted(leads.items()) if isinstance(row, dict)]


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
    expanding = []            # (host, raw) of non-leaf DOMAIN hosts — the origin-IP sweep's input
    shared_ips = set()
    approved = _oh.approved_cohosts(cdir) if _oh is not None else {}
    # kit/neighbour tier hosts (co-tenants, shared-kit hits) are collected, never leak/identity
    # checked: their registrant contacts belong to third parties
    tiers = tier_hosts(cdir)
    for path in sorted(glob.glob(os.path.join(cdir, "raw", "*.json"))):
        try:
            with open(path, encoding="utf-8") as fh:
                obj = json.load(fh)
        except Exception:
            continue
        host = ((obj.get("meta") or {}).get("host") or os.path.basename(path)[:-5]).lower()
        meta = obj.get("meta") if isinstance(obj.get("meta"), dict) else None
        if meta is not None and meta.get("kind") == "ip" and not meta.get("origin_context") and _oh is not None:
            # unstamped IP raw (collected without WP_CASE_DIR): recompute whether the case's hosts used
            # this box only historically — otherwise its stale co-tenants would seed as if current
            _ctx = _oh.origin_context(cdir, host)
            if _ctx:
                meta["origin_context"] = _ctx
        if is_leaf(host, hops, depth):
            # leaf: mine into scratch so own-subdomain notes (_SUBS) and co-tenancy leads survive,
            # but no NEW apex from this host may enter the frontier
            _free_candidates_from_raw(obj, {}, seed_apexes, deferred, approved=approved)
            leaves.append(host)
        else:
            _free_candidates_from_raw(obj, cands, seed_apexes, deferred, approved=approved)
            expanding.append((host, obj))
        _shared_ips_in(obj, shared_ips)
        _metered_leads_from_raw(obj, leads)
        if host not in tiers:
            _enrichment_leads_from_raw(obj, enr)
    _leak_leads(case, enr)
    # MO-neighbour: seed ONLY from the CLASSIFIED case-wide file (Phase B), never from the raw
    # per-host discovery block — a same_mo / unrelated co-tenant must not grow the estate.
    _mo_same_registrant_candidates(cdir, cands, seed_apexes, deferred)
    # Censys case-level cert search (exact leaf-cert match = owner link) — seeds directly.
    _censys_search_candidates(cdir, cands, seed_apexes, deferred)
    # BinaryPivot: hosts embedded in a case sample are leads, never collected on their own. A host
    # under a NEW apex is a related lead (seedable only with an independent owner-link source); a
    # host under an apex the case already holds is listed in binary_host_leads instead of joining
    # subdomains_pending, so nothing found in a sample is ever fetched automatically.
    binary_host_leads = {}
    for path in sorted(glob.glob(os.path.join(cdir, "bin", "analysis", "*.json"))):
        try:
            with open(path, encoding="utf-8") as fh:
                bart = json.load(fh).get("artifacts") or {}
        except Exception:
            continue
        sample = os.path.basename(path)[:-5]
        for h in ((bart.get("trackers") or {}).get("app_backend_host") or []):
            name = _clean_name(h)
            if name and _frontier_apex(name) in seed_apexes:
                binary_host_leads.setdefault(name.lower(), set()).add(sample)
            else:
                _add_cand(cands, h, "binary_backend_host", seed_apexes)
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
    # the historical ORIGIN-IP sweep: non-CDN addresses the expanding hosts ever resolved to
    ips_pending, ip_detail = _origin_ip_frontier(
        expanding, {h.lower() for h in collected} | consumed, hops, depth, deferred, shared_ips,
        max_ips=(_oh.MAX_IP_SEEDS_PER_ROUND if (_oh is not None and max_new) else None))
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
                                   ") — a page that loaded the host's resources, a lookalike, a "
                                   "same-kit deployment or a host embedded in a sample, not the "
                                   "operator's registration; triage by hand, never auto-collected")}
                          for a, v in sorted(related.items(), key=lambda kv: (-len(kv[1]["sources"]), kv[0]))],
        # hosts embedded in a case sample under an apex the case already holds: NOT queued as
        # subdomains — a sample's string can name any host; triage and collect by hand
        "binary_host_leads": [{"host": h, "samples": sorted(s)[:4],
                               "why": "embedded in a case sample under a collected apex — never auto-collected"}
                              for h, s in sorted(binary_host_leads.items())
                              if h not in {c.lower() for c in collected}],
        "subdomains_pending": sub_pending,          # {apex: [host, …]} — next-round collection
        "subdomains": sub_detail,                   # {host: {apex, sources, dns}} incl. dead names
        # historical ORIGIN IPs (non-CDN / non-parking addresses the expanding hosts resolved to) —
        # collected next round as IP seeds (IPPivot); co-tenants then pass the co-host guards
        "ips_pending": ips_pending,
        "origin_ips": ip_detail,                    # {ip: {hosts, sources, first/last_seen, era, hop, …}}
        "metered_leads": list(leads.values()),
        # co-tenancy held back from seeding (multi-tenant certs / shared-hosting IPs) — free to
        # check by hand, never auto-chased, and surfaced so the suppression is visible not silent.
        "co_tenancy_leads": [v for slot in deferred.values() for v in slot.values()],
        # Structured leads close after the runner checkpoints their result; query-only leads
        # remain open until an agent executes/reviews them. Host convergence is separate.
        "enrichment_leads": [v for k, v in enr.items() if v["key"] not in _done_map(st)],
        "enrichment_gaps": [{"key": k, "reason": r} for k, r in _done_map(st).items()
                            if r in ("empty", "unavailable", "skipped")],
        "enrichment_results": _enrichment_index(cdir),
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
    # single source of truth (convergence.is_converged): a round where a host failed to collect
    # (see snapshot --failed) never counts as zero-growth, even with no new hosts/indicators.
    converged = _conv.is_converged(rounds, stale)
    failed_recent = sorted({h for r in recent for h in (r.get("failed") or [])})
    last = rounds[-1]
    return {"verdict": "CONVERGED" if converged else "EXPANDING", "rounds": len(rounds),
            "hosts": last.get("hosts"), "indicators": last.get("indicators"),
            "new_hosts_recent": sum(r["new_hosts"] for r in recent),
            "new_indicators_recent": sum(r["new_indicators"] for r in recent),
            "failed_recent": failed_recent}


def reopen(case, new_seeds=None):
    """Cold-case reopen: flip status back to expanding, merge any new seeds into pending, and let
    the next loop re-mine the frontier against the CURRENT KB (cross-case breakthroughs included)."""
    st = load_state(case)
    st["status"] = "expanding"
    st["reopen_count"] = st.get("reopen_count", 0) + 1
    st["note"] = f"reopened {_now()}"
    st["dropped"] = {}          # a reopened case re-judges what an earlier Plan phase vetoed
    st.pop("leak_round", None)  # new seeds / new evidence: the harness re-runs the leak fan-out once
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



@_locked
def record_approved_cohost(case, ip, domains):
    """The analyst approved THESE co-tenants of an origin IP (a harness approval item that ran, or
    `case_state.py approve-cohost`). Stored per domain in state.json `approved_cohosts` with the case
    hosts that resolved to the box, so the frontier seeds, ingest links and the partition binds ONLY
    these — every other site on the box keeps the VPS / shared-hosting rules."""
    st = load_state(case)
    allrec = st.get("approved_cohosts") if isinstance(st.get("approved_cohosts"), dict) else {}
    rec = allrec.get(str(ip)) if isinstance(allrec.get(str(ip)), dict) else {}
    reduce = _oh._apex if _oh is not None else _frontier_apex   # the readers' reduction (approval_allows)
    doms = set(rec.get("domains") or []) | {a for a in (reduce(d) for d in domains or ()) if a}
    hosts = set(rec.get("hosts") or [])
    # the case hosts whose history LED to this box (the IP raw's own stamp, taken when it was
    # collected) — not every collected domain that happens to resolve there today
    try:
        with open(os.path.join(_case_dir(case), "raw", f"{ip}.json"), encoding="utf-8") as fh:
            stamp = ((json.load(fh) or {}).get("meta") or {}).get("origin_context") or {}
    except Exception:  # noqa: BLE001
        stamp = {}
    if not stamp and _oh is not None:
        stamp = _oh.origin_context(_case_dir(case), ip) or {}
    hosts |= set(stamp.get("hosts") or [])
    allrec[str(ip)] = {"domains": sorted(doms), "hosts": sorted(hosts)}
    st["approved_cohosts"] = allrec
    save_state(case, st)
    return allrec[str(ip)]


@_locked
def record_origin_ip_hop(case, ip, hosts):
    """Give a historical ORIGIN IP the smallest hop among the case hosts that resolved to it — the
    same rule intel._promote applies — so the loop and the harness agree on where its co-tenants
    land (one hop past that host). An existing smaller hop is kept; unknown hosts are ignored."""
    st = load_state(case)
    hops = st.get("hops") if isinstance(st.get("hops"), dict) else {}
    known = [int(hops[h]) for h in (str(x).lower() for x in hosts or ()) if isinstance(hops.get(h), int)]
    if not known:
        return None
    hop = min(known)
    hops[str(ip)] = min(hop, hops.get(str(ip), hop))
    st["hops"] = hops
    save_state(case, st)
    return hops[str(ip)]


@_locked
def mark_pivoted(case, ids):
    """Record consumed pivot candidate ids in state.json `pivoted` (additive, idempotent).

    Phase 4 records ids after a pivot is dispatched so propose() does not re-emit them.
    Phase 3 ingest does not touch this list."""
    st = load_state(case)
    have = list(st.get("pivoted") or [])
    seen = set(have)
    for i in (ids or []):
        s = str(i or "").strip()
        if s and s not in seen:
            have.append(s)
            seen.add(s)
    st["pivoted"] = have
    save_state(case, st)
    return st


@_locked
def mark_dropped(case, drops, round_no=None):
    """Record Plan-phase drops in state.json `dropped` ({id: {why, round}}) so propose() never
    re-offers them in later rounds. `drops` = iterable of (id, why). The first drop of an id is
    kept (idempotent). reopen() clears the map. Returns the number of NEW drops."""
    st = load_state(case)
    have = st.setdefault("dropped", {})
    rnd = round_no if isinstance(round_no, int) else st.get("round", 0)
    added = 0
    for i, why in (drops or ()):
        s = str(i or "").strip()
        if s and s not in have:
            have[s] = {"why": str(why or "")[:300], "round": rnd}
            added += 1
    if added:
        save_state(case, st)
    return added


def _excluded_ids(st):
    """Candidate ids propose()/accept_extras() never offer: dispatched (`pivoted`) + Plan-dropped."""
    out = {str(x) for x in (st.get("pivoted") or []) if x}
    dropped = st.get("dropped")
    if isinstance(dropped, dict):
        out |= {str(k) for k in dropped if k}
    return out



def _node_key(type_, selector):
    t = (type_ or "").strip().lower()
    s = str(selector or "").strip()
    return f"{t}|{s.lower() if t in ('domain', 'email', 'telegram') else s}"


def _node_hop(st, type_, selector):
    """Hop of a typed node: its registry entry, else (domain) the expansion-anchor hop, else 0."""
    n = (st.get("nodes") or {}).get(_node_key(type_, selector))
    if isinstance(n, dict) and isinstance(n.get("hop"), int):
        return n["hop"]
    if (type_ or "").lower() == "domain":
        hops, depth = _hops_and_depth(st)
        return hops.get(str(selector or "").lower(), _unknown_hop(hops, depth))
    return 0


@_locked
def register_seed_nodes(case, seeds):
    """Classify the run's seeds; non-domain seeds become hop-0 typed nodes. Returns the domain/URL
    seeds (the collect phase's input). A filename/string seed is NEVER treated as a host."""
    from selector_types import classify
    st = load_state(case)
    nodes = st.setdefault("nodes", {})
    domains, added = [], False
    for raw in seeds or []:
        v = str(raw or "").strip()
        if not v:
            continue
        kind = classify(v)
        if kind == "domain":
            domains.append(v[len("domain:"):] if v.lower().startswith("domain:") else v)
            continue
        sel = v.rsplit("/", 1)[-1].lstrip("@") if kind == "telegram" else v
        k = _node_key(kind, sel)
        if k not in nodes:
            nodes[k] = {"type": kind, "selector": sel, "rung_class": "", "rung_classes": [""],
                        "hop": 0, "origins": ["seed"], "route": "seed"}
            added = True
    if added:                      # a domain-only run leaves state.json exactly as it was
        save_state(case, st)
    return domains


@_locked
def add_nodes(case, rows, *, origin_type, origin_value, route):
    """Record a corpus pivot's result rows as typed nodes at origin hop + 1 (mentions excluded —
    a mention is a fact, never a node). Rows whose rung class the route delivers fact-only
    (rungs.json fact_only_node_classes — page-scraped contacts on quarry.page) are skipped: the
    ingester already stored them as KB facts on the page. Returns the number of NEW nodes."""
    from selector_types import fact_only_classes
    fact_only = fact_only_classes(route)
    st = load_state(case)
    nodes = st.setdefault("nodes", {})
    hop = _node_hop(st, origin_type, origin_value) + 1
    origin = f"{(origin_type or '').lower()}:{origin_value}"
    added = 0
    for r in rows or []:
        if not isinstance(r, dict):
            continue
        t = str(r.get("type") or "").strip().lower()
        v = str(r.get("value") or "").strip()
        if not t or not v or t == "mention":
            continue
        if fact_only and str(r.get("rung_class") or "") in fact_only:
            continue
        k = _node_key(t, v)
        cur = nodes.get(k)
        # An unlabeled corpus row is NOT owner evidence: "unknown" resolves to kit via rung_for.
        # Only a SEED carries the empty class (register_seed_nodes) and reads as owner.
        rc = str(r.get("rung_class") or "unknown")
        if cur is None:
            nodes[k] = {"type": t, "selector": v.lower() if t == "domain" else v,
                        "rung_class": rc, "rung_classes": [rc], "hop": hop,
                        "origins": [origin], "route": route}
            added += 1
            continue
        if rc not in cur.setdefault("rung_classes", [cur.get("rung_class", "")]):
            cur["rung_classes"].append(rc)
        if origin not in cur.get("origins", []):
            cur.setdefault("origins", []).append(origin)
            cur["hop"] = min(int(cur.get("hop", hop)), hop)
    save_state(case, st)
    return added


def tier_hosts(case_dir):
    """{domain: 'kit'|'neighbour'} for hosts the cross-type loop reached ONLY through kit- or
    neighbour-rung rows (a shared filename / string / favicon / telegram username, an IP
    co-tenant, an exchange counterparty). Collecting is not attributing: these hosts are kept OUT
    of the same-operator partition and listed apart. A host that also arrived through an
    owner-rung row, a seed, or the owner-gated frontier (not in the node registry) is not here.
    Empty for a case the cross-type loop never touched — legacy partitions are unchanged."""
    from selector_types import rung_for
    try:
        with open(state_path(case_dir), encoding="utf-8") as fh:
            st = json.load(fh)
    except Exception:  # noqa: BLE001
        return {}
    # The analyst's own seeds (harness_seeds.json, written by the orchestrator) are the subject of
    # the case and never tier out — every caller (judge partition, propose's enrich.host) agrees.
    try:
        with open(os.path.join(case_dir, "harness_seeds.json"), encoding="utf-8") as fh:
            seeds = {str(s).lower() for s in (json.load(fh) or [])}
    except Exception:  # noqa: BLE001
        seeds = set()
    seeds |= {_frontier_apex(s) for s in seeds}
    out = {}
    for n in (st.get("nodes") or {}).values() if isinstance(st, dict) else ():
        if not isinstance(n, dict) or n.get("type") != "domain":
            continue
        sel = str(n.get("selector") or "").lower()
        if sel in seeds:
            continue
        classes = n.get("rung_classes") or [n.get("rung_class") or ""]
        rungs = {rung_for(c) if c else "owner" for c in classes}
        if "owner" in rungs:
            continue
        out[sel] = "neighbour" if rungs == {"neighbour"} else "kit"
    return out


# Reverse-WHOIS on a phone/email is a REGISTRANT pivot (SKILL.md): it runs only for a contact the
# WHOIS record names as registrant (or one the analyst seeded by hand), never for one scraped from
# page text (a phone directory lists thousands of strangers) or reached through a kit/neighbour
# row. The one choke point for both typed candidate builders below.
_REGISTRANT_ONLY_ROUTES = frozenset({"rwhois.purchase"})
_REGISTRANT_RELS = frozenset({"registered_by", "registrant_of"})


def _route_admits(route, rung_classes, *, analyst_seed=False):
    """False when `route` is registrant-only, the selector is not an analyst's hop-0 seed, and no
    class in `rung_classes` is whois.registrant_*."""
    if route not in _REGISTRANT_ONLY_ROUTES or analyst_seed:
        return True
    return any(str(c).startswith("whois.registrant_") for c in (rung_classes or ()))


def _cands_from_state_nodes(st, collected, pr, routes_meta, seed_apexes):
    """Candidates from the case's typed node registry (seeds of any type + corpus pivot results).

    Domain nodes not yet collected → a free single-host `collect` (rung from the row's class, so a
    kit sibling is COLLECTED but stays kit). Other nodes → one UNPROBED candidate per accepting
    route (propose() bounds, then sizes them). Nodes at or past `max_typed_hops` are leaves
    (recorded, never pivoted) so the estate converges."""
    from selector_types import classify, max_typed_hops, routes_for, rung_for
    max_hops = max_typed_hops()
    have = {h.lower() for h in collected}
    out = []
    for key in sorted(st.get("nodes") or {}):
        n = st["nodes"][key]
        if not isinstance(n, dict):
            continue
        t, sel = n.get("type"), str(n.get("selector") or "")
        hop = n.get("hop") if isinstance(n.get("hop"), int) else 0
        if not t or not sel or hop >= max_hops:
            continue
        rc = str(n.get("rung_class") or "")
        classes = {str(c) for c in (n.get("rung_classes") or ()) if c} | ({rc} if rc else set())
        analyst_seed = n.get("route") == "seed" and hop == 0 and not classes
        rung = rung_for(rc) if rc else ("owner" if t in ("domain", "email", "wallet") else "kit")
        origins = tuple(sorted(n.get("origins") or ()))
        src = (f"node:{n.get('route') or 'seed'}",)
        if t == "domain":
            a = _frontier_apex(sel)
            if (not a or sel.lower() in have or a in have or classify(sel) == "filename"
                    or never_seed(a) or _is_noise_apex(a, seed_apexes)):
                continue
            out.append(_cand("domain", a, "collect", a, metered=False, est_hits=1, rung=rung,
                             origins=origins, sources=src,
                             why=f"{rung} node from {n.get('route') or 'seed'} (hop {hop})",
                             by="node"))
            continue
        for route in routes_for(t):
            if not _route_admits(route, classes, analyst_seed=analyst_seed):
                continue
            spec = routes_meta.get(route) or {}
            query = None
            if pr is not None:
                try:
                    query = pr.query_for(route, t, sel)
                except Exception:
                    query = None
            elif t in (spec.get("types") or []):
                query = sel
            if query is None:
                continue
            out.append(_cand(t, sel, route, query, metered=bool(spec.get("metered")),
                             est_hits=None, rung=rung, origins=origins, sources=src,
                             why=f"{t} node from {n.get('route') or 'seed'} (hop {hop})",
                             by="node"))
    return out



# ------------------------------------------------------------------------- propose() (cross-type)
# Single deterministic source of next-round candidates for the SDK harness. frontier() stays the
# domain-only FREE path for intel.py loop and MUST remain byte-identical; propose() reuses its
# miners by calling it, then adds typed KB nodes, co-tenancy holds (est_hits > auto_max → approval)
# and validated extra/SDK sources. Filename/string selectors never pass through host normalisation.

_RUNG_RANK = {"owner": 0, "kit": 1, "neighbour": 2}


def _kb_root():
    """Absolute KB path — HARNESS_KB absolute, else under engine ROOT (same rule as _benign_set)."""
    kb = KB_DIR
    return kb if os.path.isabs(kb) else os.path.join(ROOT, kb)


def _pivot_routes_mod():
    """Lazy import of pivot_routes (phase 3). Tests inject a stub via sys.modules['pivot_routes']."""
    mod = sys.modules.get("pivot_routes")
    if mod is not None:
        return mod
    try:
        import pivot_routes as pr  # noqa: E402
        return pr
    except Exception:
        return None


def _case_no_spend(case):
    """The case intake's constraints.no_spend (scope.json); False when unscoped/unreadable."""
    try:
        with open(os.path.join(_case_dir(case), "scope.json"), encoding="utf-8") as fh:
            return bool(((json.load(fh) or {}).get("constraints") or {}).get("no_spend"))
    except Exception:
        return False


class _ProbeRoutes:
    """pivot_routes with every count probe forced free_only on a no_spend case: metered routes
    answer unknown (no reverse-WHOIS preview is sent) and urlscan counts go keyless."""

    def __init__(self, mod, free_only):
        self._mod, self._free = mod, bool(free_only)

    def query_for(self, *a, **k):
        return self._mod.query_for(*a, **k)

    def count(self, route, query, free_only=False):
        return self._mod.count(route, query, free_only=bool(free_only) or self._free)

    def runnable(self, route):
        """pivot_routes.route_runnable — False when the route's credential is absent. A stub
        module without the gate answers True (no change)."""
        gate = getattr(self._mod, "route_runnable", None)
        return True if gate is None else bool(gate(route))


def _probe_routes(case):
    mod = _pivot_routes_mod()
    return None if mod is None else _ProbeRoutes(mod, _case_no_spend(case))


def _offerable(c, pr):
    """False for a candidate propose() must never offer: a route excluded for the selector type
    (pivot_map.json propose_type_exclude — anyrun.lookup on an IP) or a route whose credential is
    not configured (pivot_routes.route_runnable). `collect` is always offerable."""
    from selector_types import propose_excluded
    if c.tool == "collect":
        return True
    if propose_excluded(c.tool, c.type):
        return False
    return pr is None or pr.runnable(c.tool)


def _findings_from_case(cdir):
    """Minimal findings dict for pivot_suggest from raw artifacts (best-effort, never raises)."""
    findings = {"domains": [], "emails": [], "social": [], "persons": [], "cn_names": []}
    for path in sorted(glob.glob(os.path.join(cdir, "raw", "*.json"))):
        try:
            with open(path, encoding="utf-8") as fh:
                obj = json.load(fh)
        except Exception:
            continue
        host = ((obj.get("meta") or {}).get("host") or os.path.basename(path)[:-5]).lower()
        if host:
            findings["domains"].append({"value": host})
        art = obj.get("artifacts") or {}
        for em in art.get("emails") or []:
            if em:
                findings["emails"].append({"value": em})
        for net, handles in (art.get("socials") or {}).items():
            for h in handles or []:
                if h:
                    findings["social"].append({"username": str(h), "platform": str(net)})
    return findings


def _pivot_suggest_boosts(cdir):
    """selector/target → boost score from pivot_suggest.suggest_all; empty on any failure."""
    try:
        import importlib.util
        path = os.path.join(os.path.dirname(ROOT), "scripts", "webpivot", "pivot_suggest.py")
        if not os.path.isfile(path):
            path = os.path.join(ROOT, "scripts", "webpivot", "pivot_suggest.py")
        if not os.path.isfile(path):
            return {}
        spec = importlib.util.spec_from_file_location("_cs_pivot_suggest", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        result = mod.suggest_all(_findings_from_case(cdir))
        boosts = {}
        for s in result.get("suggestions") or []:
            t = str(s.get("target") or "").strip().lower()
            if not t:
                continue
            conf = float(s.get("confidence") or 0) or 0.0
            pr = str(s.get("priority") or "").lower()
            pscore = {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(pr, 1)
            boosts[t] = max(boosts.get(t, 0.0), pscore + conf)
        return boosts
    except Exception:
        return {}


def _cand(type_, selector, tool, query, *, metered=False, est_hits=None, rung="kit",
          origins=(), sources=(), why="", by="", id_=None):
    """Build a Candidate via selector_types (local import keeps frontier path free of it)."""
    from selector_types import Candidate, candidate_id
    q = query if query is not None else selector
    cid = id_ or candidate_id(type_, selector, tool, q)
    return Candidate(
        id=cid, type=type_, selector=selector, tool=tool, query=q,
        metered=bool(metered), est_hits=est_hits, rung=rung or "kit",
        origins=tuple(origins or ()), sources=tuple(sources or ()),
        why=str(why or ""), by=str(by or ""),
    )


# Frontier source → rung (the locked rung table). The legacy frontier seeds only sources it treats
# as owner links (_owner_linked: everything outside _NON_OWNER_SOURCES — exact cert / co-SAN,
# registrant reverse-WHOIS, own subdomains, the _HOST_YIELDING_SOURCES engines, same-registrant MO
# neighbours). Two refinements from the rung table: page-similarity sources (_NON_OWNER_SOURCES)
# are kit, and IP co-tenancy (ip_cohost, passive-DNS co-hosts) is NEIGHBOUR — collected, never
# attributed. A candidate takes the STRONGEST rung among its sources.
_NEIGHBOUR_SOURCES = frozenset({"ip_cohost", "passive_dns"})
_RUNG_ORDER = ("owner", "kit", "neighbour")


def _source_rung(source):
    s = str(source or "")
    if s in _NEIGHBOUR_SOURCES:
        return "neighbour"
    if s in _NON_OWNER_SOURCES:
        return "kit"
    return "owner"


def _strongest_rung(rungs):
    rs = set(rungs or ())
    for r in _RUNG_ORDER:
        if r in rs:
            return r
    return "kit"


def _frontier_rung(sources):
    return _strongest_rung(_source_rung(s) for s in (sources or ()))


def _domain_cands_from_frontier(fr, auto_max, host_tier=None):
    """Seedable frontier apexes + co-tenancy/deferred holds as domain Candidates.

    `host_tier(host)`: a candidate mined from a host's raw is only as strong as the BEST host it
    was found on — a crt.sh co-SAN on a hosting co-tenant's certificate is a co-tenant lead, not an
    owner link (rung = weaker of the source rung and the best origin tier)."""
    out, seen = [], set()
    for apex, info in (fr.get("candidates") or {}).items():
        a = (apex or "").strip().lower()
        if not a or a in seen:
            continue
        seen.add(a)
        out.append(_cand(
            "domain", a, "collect", a,
            metered=False, est_hits=1,                 # one host, free-only collect
            rung=(_weakest_rung((_frontier_rung(info.get("sources") or ()),
                                 _strongest_rung(host_tier(o) for o in info["origins"])))
                  if host_tier is not None and info.get("origins")
                  else _frontier_rung(info.get("sources") or ())),
            origins=tuple(sorted(info.get("origins") or ())),
            sources=tuple(sorted(info.get("sources") or ())),
            why=f"owner-linked frontier seed (hop {info.get('hop', '?')})",
            by="frontier",
        ))
    for lead in fr.get("co_tenancy_leads") or []:
        if lead.get("never_seed"):
            continue                  # a social-platform edge: shown as a lead, never offered
        samples = list(lead.get("sample_apexes") or lead.get("sample_domains") or [])
        count = lead.get("cohost_count") or lead.get("sibling_count") or lead.get("apex_count")
        try:
            est = int(count) if count is not None else int(auto_max) + 1
        except (TypeError, ValueError):
            est = int(auto_max) + 1
        if est <= int(auto_max):
            est = int(auto_max) + 1
        check = str(lead.get("check") or "co_tenancy")
        src = f"co_tenancy:{check}"
        # an approve-to-collect VPS lead carries its IP, so the approved run records the approval
        extra_src = ((f"approve_ip:{lead['ip']}",) if check == "vps co-tenancy — approve" and lead.get("ip")
                     else ())
        origin = (lead.get("seen_on") or "").strip().lower()
        for apex in samples:
            a = (apex or "").strip().lower()
            if not a or a in seen or never_seed(a):
                continue
            seen.add(a)
            out.append(_cand(
                "domain", a, "collect", a,
                metered=False, est_hits=est, rung="neighbour",
                origins=(origin,) if origin else (),
                sources=(src,) + extra_src,
                why=str(lead.get("why") or check),
                by="co_tenancy",
            ))
    return out


def _weakest_rung(rungs):
    rs = set(rungs or ())
    for r in reversed(_RUNG_ORDER):
        if r in rs:
            return r
    return "kit"


def _typed_cands_from_kb(collected, pr, routes_meta, host_tier=None):
    """One candidate per applicable route for each KB entity linked to a collected host.

    `host_tier(host) -> owner|kit|neighbour`: a selector is only as strong as the BEST host it was
    found on — a GA id seen only on a hosting co-tenant is a neighbour pivot, never an owner one,
    however strong its identifier class (rung = weaker of class rung and best source-host tier)."""
    from selector_types import node_from_kb, routes_for, rung_for
    out = []
    try:
        from knowledge_base import KB
    except Exception:
        return out
    kb_path = _kb_root()
    if not os.path.isdir(kb_path):
        return out
    try:
        kb = KB(kb_path)
    except Exception:
        return out
    nodes = {}  # (type, selector) -> {rung_class, classes, origins, sources}
    for host in sorted(collected):
        h = (host or "").strip().lower()
        if not h:
            continue
        try:
            neigh = kb.neighbors("domain", h)
        except Exception:
            continue
        for etype, value, rel, _conf in neigh:
            if etype in ("email", "phone") and rel in _REGISTRANT_RELS:
                # a WHOIS registrant edge (ingest_webpivot `registered_by`, ingest_typed
                # `registrant_of`) — the only email/phone class reverse-WHOIS may run on
                node = {"type": etype, "selector": str(value or "").strip(),
                        "rung_class": f"whois.registrant_{etype}"}
            else:
                node = node_from_kb(etype, value)
            if not node or not node["selector"]:
                continue
            ntype, sel = node["type"], node["selector"]
            # Filename/string stay typed — NEVER reclassify as domain / run through PSL reducer.
            if ntype not in ("domain", "email", "phone", "wallet", "ip", "hash",
                             "string", "filename", "telegram"):
                continue
            key = (ntype, sel)
            slot = nodes.setdefault(key, {
                "rung_class": node.get("rung_class") or "",
                "classes": set(), "origins": set(), "sources": set(),
            })
            slot["origins"].add(h)
            slot["sources"].add(f"kb:{rel or 'linked'}")
            nrc = node.get("rung_class") or ""
            if nrc:
                slot["classes"].add(nrc)
                if not slot["rung_class"] or nrc.startswith("whois.registrant_"):
                    slot["rung_class"] = nrc     # a registrant edge outranks a page sighting
    for (ntype, sel), slot in sorted(nodes.items(), key=lambda kv: (kv[0][0], kv[0][1])):
        rc = slot["rung_class"]
        if rc:
            rung = rung_for(rc)
        elif ntype == "ip":
            rung = "neighbour"
        elif ntype in ("domain", "email", "wallet"):
            rung = "owner"
        else:
            rung = "kit"
        origins = tuple(sorted(slot["origins"]))
        if host_tier is not None:
            best = _strongest_rung(host_tier(o) for o in slot["origins"])
            rung = _weakest_rung((rung, best))
        sources = tuple(sorted(slot["sources"]))
        for route in routes_for(ntype):
            if (routes_meta.get(route) or {}).get("collected_only"):
                continue                     # e.g. enrich.host: proposed for collected hosts only
            if not _route_admits(route, slot["classes"]):
                continue
            query = None
            if pr is not None:
                try:
                    query = pr.query_for(route, ntype, sel)
                except Exception:
                    query = None
            else:
                spec = routes_meta.get(route) or {}
                if ntype in (spec.get("types") or []):
                    query = sel
            if query is None:
                continue
            spec = routes_meta.get(route) or {}
            out.append(_cand(
                ntype, sel, route, query,
                metered=bool(spec.get("metered")), est_hits=None, rung=rung,
                origins=origins, sources=sources,
                why=f"KB-linked {ntype} on {', '.join(origins[:3])}",
                by="kb",
            ))
    return out


# Keyed enrichment engines pivot_extract records in meta.enriched_with. A raw that already lists
# any of them was collected with the paid layers (the round-1 seed, a cached keyed run), so
# proposing `enrich.host` for it would pay twice.
_KEYED_ENGINES = frozenset({"fofa", "censys", "whoisxml", "validin", "securitytrails",
                            "hunterhow", "intelx", "shodan-search", "dnslytics"})


def _owner_evidence_hosts(cdir, st):
    """Hosts (and apexes) with POSITIVE owner evidence: the analyst's seeds (harness_seeds.json and
    hop-0 expansion anchors), domain nodes that arrived through an owner-rung row, and members of
    the judged cluster (assessment.json `cluster`). Absence from the kit/neighbour tiers is NOT
    evidence — a brand/impersonation reference or an unlabeled co-host is in neither."""
    from selector_types import rung_for
    out = set()
    try:
        with open(os.path.join(cdir, "harness_seeds.json"), encoding="utf-8") as fh:
            out |= {str(s).lower() for s in (json.load(fh) or [])}
    except Exception:  # noqa: BLE001
        pass
    out |= {str(h).lower() for h, v in (st.get("hops") or {}).items() if v == 0}
    for n in (st.get("nodes") or {}).values():
        if isinstance(n, dict) and n.get("type") == "domain":
            classes = n.get("rung_classes") or [n.get("rung_class") or ""]
            if any(c and rung_for(c) == "owner" for c in classes):
                out.add(str(n.get("selector") or "").lower())
    try:
        with open(os.path.join(cdir, "assessment.json"), encoding="utf-8") as fh:
            for m in (json.load(fh) or {}).get("cluster") or []:
                if isinstance(m, dict) and m.get("domain"):
                    out.add(str(m["domain"]).strip().lower().rstrip("."))
    except Exception:  # noqa: BLE001
        pass
    out.discard("")
    return out | {_frontier_apex(h) for h in out}


def _keyed_raw(cdir, host):
    try:
        with open(os.path.join(cdir, "raw", f"{host}.json"), encoding="utf-8") as fh:
            meta = (json.load(fh) or {}).get("meta") or {}
    except Exception:  # noqa: BLE001 — unreadable raw: not known keyed
        return False
    return bool(_KEYED_ENGINES & {str(e).lower() for e in (meta.get("enriched_with") or [])})


def _accept_extra(raw, seed_apexes, depth, routes_meta, pr):
    """Validate an extra Candidate/dict. Drop unknown routes, noise domains, filename-as-host."""
    from selector_types import Candidate, classify, routes_for
    if isinstance(raw, dict):
        try:
            c = Candidate.from_dict(raw)
        except Exception:
            return None
    elif isinstance(raw, Candidate):
        c = raw
    else:
        return None
    typ = (c.type or "").strip().lower() or classify(c.selector)
    sel = c.selector
    tool = (c.tool or "").strip()
    # A planner never sizes or prices its own pivot: est_hits comes from the cheap count probe and
    # metered from pivot_map. Only the engine's own sources (SDK previews, frontier) are trusted.
    trusted = (c.by or "") != "planner"
    if typ == "domain":
        # Refuse filename/string tokens that only look domain-ish after a bad cast.
        if classify(sel, hint=None) == "filename":
            return None
        a = _frontier_apex(sel) if sel else ""
        if not a or never_seed(a) or _is_noise_apex(a, seed_apexes):
            return None
        # depth check: extras are hop-1 relative to the estate; depth 0 admits no expansion
        if isinstance(depth, int) and depth >= 0 and 1 > depth:
            return None
        if tool and tool != "collect":
            spec = routes_meta.get(tool)
            if not isinstance(spec, dict) or "domain" not in (spec.get("types") or []):
                return None                        # a domain is collected, or pivoted on a domain route
            est = c.est_hits if trusted else None
            if pr is not None and est is None:
                try:
                    est = pr.count(tool, c.query or a)
                except Exception:
                    est = None
            return _cand(
                "domain", a, tool, c.query or a,
                metered=bool(spec.get("metered")) or bool(c.metered), est_hits=est,
                rung=(c.rung if trusted else "kit") or "kit", origins=c.origins,
                sources=c.sources or ("extra",),
                why=c.why or "extra", by=c.by or "extra", id_=None,   # id from the apex
            )
        return _cand(
            "domain", a, "collect", a,
            # rung: an engine source states its own (sdk.infra → neighbour, kb peer → kit); a
            # planner hunch is never owner evidence; an unlabeled extra is kit (conservative)
            metered=False, est_hits=1, rung=(c.rung if trusted else "kit") or "kit",
            origins=c.origins, sources=c.sources or ("extra",),
            why=c.why or "extra", by=c.by or "extra",
            id_=None,   # id from the APEX: every subdomain/URL form of one apex is ONE candidate
        )
    # Non-domain: tool must be a known accepting route (or absent → pick nothing here; typed
    # path owns multi-route expansion). Unknown route → drop.
    if not tool or tool == "collect":
        return None
    spec = routes_meta.get(tool)
    if spec is None:
        return None  # unknown route
    if typ not in (spec.get("types") or []):
        return None
    query = c.query
    if pr is not None:
        try:
            q = pr.query_for(tool, typ, sel)
        except Exception:
            q = None
        if q is None:
            return None
        query = q
    elif not query:
        query = sel
    est = c.est_hits if trusted else None
    if pr is not None and est is None:
        try:
            est = pr.count(tool, query)
        except Exception:
            est = None
    return _cand(
        typ, sel, tool, query,
        metered=bool(spec.get("metered")) or bool(c.metered),
        est_hits=est, rung=c.rung or "kit",
        origins=c.origins, sources=c.sources or ("extra",),
        why=c.why or "extra", by=c.by or "extra",
        id_=None,   # id from the NORMALISED query: a planner re-add of a pivoted search dedups
    )


def accept_extras(case, extras):
    """Validate extra candidates (planner additions) against the case — the same checks propose()
    applies to `extra`: known route accepting the type, domain never-seed / noise / depth /
    filename-as-host guards, a fresh count probe (a planner never sizes its own pivot), and the
    offerability gate (credential configured, route not excluded for the type). Drops
    already-pivoted and Plan-dropped ids. Returns accepted Candidates."""
    from selector_types import load_pivot_map
    st = load_state(case)
    _hops, depth = _hops_and_depth(st)
    collected = collected_hosts(_case_dir(case))
    seed_apexes = {_frontier_apex(h) for h in collected} | {
        _frontier_apex(h) for h in st.get("consumed", [])}
    pivoted = _excluded_ids(st)
    routes_meta = load_pivot_map().get("routes") or {}
    pr = _probe_routes(case)
    out = []
    for raw in extras or ():
        c = _accept_extra(raw, seed_apexes, depth, routes_meta, pr)
        if c is not None and c.id not in pivoted and _offerable(c, pr):
            out.append(c)
    return out


def _dedup_cands(cands, pivoted):
    """Dedup by id; drop already-pivoted ids; merge sources/origins/est_hits on collision with
    the strongest rung winning (merged evidence)."""
    uniq = {}
    for c in cands:
        if c.id in pivoted:
            continue
        prev = uniq.get(c.id)
        if prev is None:
            uniq[c.id] = c
            continue
        srcs = tuple(sorted(set(prev.sources) | set(c.sources)))
        orgs = tuple(sorted(set(prev.origins) | set(c.origins)))
        est = prev.est_hits if prev.est_hits is not None else c.est_hits
        if (srcs != prev.sources or orgs != prev.origins or est != prev.est_hits
                or c.rung != prev.rung):
            uniq[c.id] = _cand(
                prev.type, prev.selector, prev.tool, prev.query,
                metered=prev.metered, est_hits=est,
                rung=_strongest_rung((prev.rung, c.rung)),   # merged evidence: strongest rung wins
                origins=orgs, sources=srcs,
                why=prev.why or c.why, by=prev.by or c.by, id_=prev.id,
            )
    return list(uniq.values())


# Analyst-confirmed era rule (whois_eras.previous_owner_contacts): a registrant e-mail/phone whose
# WHOIS observation date predates the domain's CURRENT registration creation date belongs to a
# previous owner. It is never a normal seed and never silently dropped: each becomes one
# approval-required item tagged PREVIOUS_OWNER_ERA (est_hits unknown, metered reverse-WHOIS,
# neighbour rung), with both dates in its `why`. A rejection rides the existing proposal reject
# path (orchestrator._run_approved → mark_pivoted), so a rejected id is never re-proposed.
PREVIOUS_OWNER_ERA = "previous_owner_era"
_PREVIOUS_OWNER_ROUTE = "rwhois.purchase"


def _contact_key(type_, value):
    v = str(value or "").strip().lower()
    return (type_, re.sub(r"[^\d]", "", v) if type_ == "phone" else v)


def _previous_owner_era_cands(cdir, pr, routes_meta):
    """One approval-required Candidate per previous-owner registrant contact across the case's raws."""
    spec = routes_meta.get(_PREVIOUS_OWNER_ROUTE) or {}
    found = {}     # (type, norm) -> {"value", "observed", "created", "hosts"}
    for path in sorted(glob.glob(os.path.join(cdir, "raw", "*.json"))):
        try:
            with open(path, encoding="utf-8") as fh:
                obj = json.load(fh)
        except Exception:
            continue
        host = ((obj.get("meta") or {}).get("host") or os.path.basename(path)[:-5]).lower()
        who = (obj.get("artifacts") or {}).get("whois") or {}
        try:
            contacts = _whois_eras.previous_owner_contacts(who, ("email", "phone"))
        except Exception:
            contacts = []
        for ct in contacts:
            val = str(ct.get("value") or "").strip()
            if (not val or "*" in val or _is_privacy(val)
                    or (ct["kind"] == "email" and _is_noise_email(val))):
                continue
            slot = found.setdefault(_contact_key(ct["kind"], val), {
                "type": ct["kind"], "value": val.lower() if ct["kind"] == "email" else val,
                "observed": ct["observed"], "created": ct["current_created"], "hosts": set()})
            slot["observed"] = min(slot["observed"], ct["observed"])
            slot["hosts"].add(host)
    out = []
    for key in sorted(found):
        s = found[key]
        query = None
        if pr is not None:
            try:
                query = pr.query_for(_PREVIOUS_OWNER_ROUTE, s["type"], s["value"])
            except Exception:
                query = None
        hosts = sorted(s["hosts"])
        out.append(_cand(
            s["type"], s["value"], _PREVIOUS_OWNER_ROUTE, query or s["value"],
            metered=bool(spec.get("metered", True)), est_hits=None, rung="neighbour",
            origins=tuple(hosts), sources=(PREVIOUS_OWNER_ERA,),
            why=(f"{PREVIOUS_OWNER_ERA}: registrant {s['type']} {s['value']} observed {s['observed']} "
                 f"predates the current registration created {s['created']} on "
                 f"{', '.join(hosts[:3])} — a previous owner of the name, not an owner link; "
                 f"approve to pivot it, reject to keep it out"),
            by="whois_eras",
        ))
    return out



def propose(case, *, extra=(), max_per_type=None, probe=True):
    """Deterministic next-round candidates for every selector type.

    Signature: propose(case, *, extra=(), max_per_type=None, probe=True) -> list[Candidate]

    - Domain candidates: same miners as frontier() (via frontier itself) — seedable apexes plus
      co-tenancy/deferred holds with est_hits forced above auto_max so they route to approval.
    - Typed candidates: KB entities linked to collected hosts via node_from_kb, one per route
      that accepts the type (pivot_routes.query_for not None). rwhois.purchase only for a
      whois.registrant_* contact. Ranked, then kit/neighbour ones capped per type
      (pivot_map.json page_selector_cap) BEFORE any count probe; owner-rung ones are uncapped.
    - extra: SDK/planner Candidates, validated (classify / route / never_seed / noise / depth).
    - previous_owner_era: a WHOIS registrant email/phone observed before the current registration
      was created → one approval-required item (sources=("previous_owner_era",), est_hits None,
      both dates in `why`) replacing any normal candidate on that contact; never capped.
    - est_hits: pivot_routes.count when probe=True; None when unknown or probe=False.
    - Rank: pivot_suggest boost desc, len(sources) desc, rung owner>kit>neighbour, id.
    - Dedup by Candidate.id; state.json `pivoted` and Plan-`dropped` ids are never offered.
    - Never offered: a route whose credential is absent or excluded for the type (_offerable).
    - Filename/string NEVER go through host normalisation / PSL reducer.
    """
    from selector_types import auto_max_hits, classify, load_pivot_map, page_selector_cap

    cdir = _case_dir(case)
    st = load_state(case)
    hops, depth = _hops_and_depth(st)
    collected = collected_hosts(cdir)
    seed_apexes = {_frontier_apex(h) for h in collected} | {
        _frontier_apex(h) for h in st.get("consumed", [])
    }
    pivoted = _excluded_ids(st)
    auto_max = auto_max_hits()
    routes_meta = (load_pivot_map().get("routes") or {})
    pr = _probe_routes(case)

    # 1) domain candidates from frontier miners (byte-identical mining via frontier())
    fr = frontier(case, max_new=0)
    # Tier of a host the case collected: owner only with positive owner evidence (seeds, owner-rung
    # nodes, judged cluster); otherwise its recorded kit/neighbour tier, else kit. Every mined
    # candidate — frontier domains (1) and typed selectors (2) — is capped by its origin hosts.
    owned = _owner_evidence_hosts(cdir, st)
    tiers = tier_hosts(cdir)

    def _host_tier(h):
        h = (h or "").lower()
        if h in owned or _frontier_apex(h) in owned:
            return "owner"
        return tiers.get(h, "kit")      # no positive owner evidence → never stronger than kit

    cands = list(_domain_cands_from_frontier(fr, auto_max, _host_tier))
    # 1b) historical ORIGIN IPs of the expanding hosts → a free IPPivot `collect` each. Collecting is
    #     not attributing: the IP is infrastructure evidence (kit), and the co-tenants its raw yields
    #     come back through frontier() as neighbour-rung, co-host-guarded candidates.
    for ip in fr.get("ips_pending") or []:
        d = (fr.get("origin_ips") or {}).get(ip) or {}
        cands.append(_cand(
            "ip", ip, "collect", ip, metered=False, est_hits=1, rung="kit",
            origins=tuple(d.get("hosts") or ()),
            sources=tuple(f"origin:{s}" for s in (d.get("sources") or ())) or ("origin_history",),
            why=(f"{d.get('era', '?')} non-CDN origin of {', '.join((d.get('hosts') or [])[:3])} "
                 f"({d.get('first_seen') or '?'} → {'now' if d.get('live') else d.get('last_seen') or '?'})"),
            by="frontier",
        ))

    # rank key — boost desc, corroboration desc, rung owner>kit>neighbour, id (steps 2 and 5)
    boosts = _pivot_suggest_boosts(cdir)

    def _key(c):
        return (
            -(boosts.get((c.selector or "").lower(), 0) or 0),
            -len(c.sources or ()),
            _RUNG_RANK.get(c.rung, 9),
            c.id,
        )

    # 2) typed KB-linked candidates — capped by the tier of the hosts each selector was found on
    typed = _typed_cands_from_kb(collected, pr, routes_meta, _host_tier)
    # 2b) typed node registry: non-domain seeds + corpus pivot results, multi-hop
    typed += _cands_from_state_nodes(st, collected, pr, routes_meta, seed_apexes)
    # 2-bound) rank and cap BEFORE sizing: a page listing thousands of contacts (a phone
    #     directory) must never cost one vendor count probe per scraped selector. Kit/neighbour
    #     pivots keep the best `page_selector_cap` per type; owner-rung pivots and free
    #     `collect` items are never dropped by this rule. Only survivors are probed.
    page_cap = page_selector_cap()
    counts, bounded = {}, []
    for c in sorted(_dedup_cands([c for c in typed if _offerable(c, pr)], pivoted), key=_key):
        if c.tool != "collect" and c.rung != "owner":
            if counts.get(c.type, 0) >= page_cap:
                continue
            counts[c.type] = counts.get(c.type, 0) + 1
        if probe and pr is not None and c.tool != "collect" and c.est_hits is None:
            try:
                est = pr.count(c.tool, c.query, free_only=False)
            except Exception:
                est = None
            if est is not None:
                c = _cand(c.type, c.selector, c.tool, c.query, metered=c.metered, est_hits=est,
                          rung=c.rung, origins=c.origins, sources=c.sources, why=c.why,
                          by=c.by, id_=c.id)
        bounded.append(c)
    cands.extend(bounded)
    # 2c) keyed enrichment of collected hosts: a metered item per host (loop collects run
    #     free-only). Offered ONLY with positive owner evidence (a seed or its subdomain, an
    #     owner-rung node, or a member of the judged cluster) — never for a brand/impersonation
    #     reference, a co-tenant, a non-hostname entry, or a host whose raw is already keyed.
    if "enrich.host" in routes_meta:
        owned = _owner_evidence_hosts(cdir, st)
        for h in sorted(collected):
            hl = h.lower()
            if classify(hl) != "domain" or "/" in hl or _keyed_raw(cdir, hl):
                continue
            if hl not in owned and _frontier_apex(hl) not in owned:
                continue
            cands.append(_cand("domain", hl, "enrich.host", hl, metered=True, est_hits=None,
                               rung="owner", origins=(hl,), sources=("collected",),
                               why="keyed enrichment (WhoisXML / FOFA / Censys / urlscan Pro / "
                                   "reverse-WHOIS) of an owner-linked host collected free-only",
                               by="proposer"))

    # 3) extra sources (SDK seed wrappers, planner additions)
    collected_apexes = {_frontier_apex(h) for h in collected}
    for raw in (extra or ()):
        acc = _accept_extra(raw, seed_apexes, depth, routes_meta, pr)
        if acc is None:
            continue
        if acc.tool == "collect" and acc.selector in collected_apexes:
            continue             # a subdomain/URL form of an apex the case already holds
        cands.append(acc)

    # 3b) previous-owner-era registrant contacts (whois_eras.previous_owner_contacts): never a
    #     normal seed — any other candidate on the same contact is replaced by ONE approval-required
    #     item tagged previous_owner_era (est_hits unknown → proposal.split routes it to approval).
    prev_owner = _previous_owner_era_cands(cdir, pr, routes_meta)
    if prev_owner:
        prev_keys = {_contact_key(c.type, c.selector) for c in prev_owner}
        cands = [c for c in cands if _contact_key(c.type, c.selector) not in prev_keys]
        cands.extend(prev_owner)

    # 4) dedup by id; drop already-pivoted (incl. analyst rejections) and Plan-dropped; merge
    #    sources on collision; never offer an unrunnable / type-excluded route (_offerable)
    cands = [c for c in _dedup_cands(cands, pivoted) if _offerable(c, pr)]

    # 5) rank: boost desc, corroboration desc, rung owner>kit>neighbour, id
    cands.sort(key=_key)

    # 6) optional per-type cap (after rank, so highest-ranked survive)
    if max_per_type is not None:
        try:
            cap = int(max_per_type)
        except (TypeError, ValueError):
            cap = None
        if cap is not None and cap >= 0:
            counts, limited = {}, []
            for c in cands:
                n = counts.get(c.type, 0)
                if n >= cap and PREVIOUS_OWNER_ERA not in (c.sources or ()):
                    continue
                counts[c.type] = n + 1
                limited.append(c)
            cands = limited

    return cands


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
    ac = sub.add_parser("approve-cohost", help="ANALYST-RUN: approve listed co-tenants of a cloud/VPS origin IP")
    ac.add_argument("case")
    ac.add_argument("ip", help="origin IP listed under a `vps co-tenancy — approve` lead")
    ac.add_argument("domains", nargs="*", help="the co-tenant domains you approve (from the lead's list)")
    ac.add_argument("--all", action="store_true",
                    help="approve every domain the lead lists NOW (sites that appear later need a new approval)")
    p = sub.add_parser("propose", help="typed next-round candidates (domain + cross-type); read-only JSON")
    p.add_argument("case")
    p.add_argument("--max-per-type", type=int, default=None,
                   help="optional cap of candidates retained per selector type after ranking")
    p.add_argument("--no-probe", action="store_true",
                   help="skip cheap hit-count probes (est_hits left null)")
    p.add_argument("--json", action="store_true", default=True,
                   help="emit JSON (default; kept for symmetry with frontier --json)")
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
        if fr.get("ips_pending"):
            print(f"  {len(fr['ips_pending'])} historical ORIGIN IP(s) to collect next (non-CDN addresses "
                  f"the hosts resolved to — IP intel; co-tenants pass the co-host guards):")
            for ip in fr["ips_pending"]:
                d = fr["origin_ips"].get(ip, {})
                print(f"    {ip:40} {d.get('era', '?'):10} {d.get('first_seen') or '?'} → "
                      f"{'now' if d.get('live') else d.get('last_seen') or '?'}  of {', '.join(d.get('hosts', [])[:3])}"
                      f"  via {', '.join(d.get('sources', []))}  — co-tenants {d.get('cotenants')}")
        if fr["metered_leads"]:
            print(f"  {len(fr['metered_leads'])} metered lead(s) — need approval before spending credits:")
            for ml in fr["metered_leads"][:12]:
                print(f"    [{ml['service']}] {ml['query']}   — {ml['why']}")
        if fr.get("co_tenancy_leads"):
            print(f"  {len(fr['co_tenancy_leads'])} co-tenancy lead(s) HELD BACK from seeding "
                  f"(multi-tenant cert / shared hosting — free to check by hand):")
            for cl in fr["co_tenancy_leads"][:12]:
                print(f"    [{cl['check']}] {cl.get('ip') or cl.get('cert_id') or cl.get('artifact') or cl.get('term') or ''}   — {cl['why']}")
                if cl.get("domains"):
                    print(f"        {len(cl['domains'])} domain(s): {', '.join(cl['domains'])}")
        if fr.get("binary_host_leads"):
            bl = fr["binary_host_leads"]
            print(f"  {len(bl)} host(s) embedded in case samples under a collected apex — NOT queued "
                  f"(a sample can name any host; triage by hand):")
            for b in bl[:12]:
                print(f"    {b['host']}   — samples {', '.join(s[:12] for s in b['samples'])}")
        if fr.get("related_leads"):
            rl = fr["related_leads"]
            print(f"  {len(rl)} related/lookalike lead(s) NOT seeded (non-owner sources — pages that loaded "
                  f"the host's resources, lookalikes; triage by hand):")
            for r in rl[:12]:
                print(f"    {r['apex']:32} via {', '.join(r['sources'])}")
            if len(rl) > 12:
                print(f"    … and {len(rl) - 12} more (frontier --json → related_leads)")
        if fr.get("enrichment_leads"):
            print(f"  {len(fr['enrichment_leads'])} enrichment lead(s) OPEN — "
                  "not yet run, held for spend/key posture, or retryable; run `intel.py enrich "
                  f"{a.case}` / `intel.py loop {a.case} --full`, review query-only legs in /cti:")
            for el in fr["enrichment_leads"][:16]:
                print(f"    {el['tool']} {el['value']}   — {el['why']}  [{el['cost']}]  key={el['key']}")
            print(f"    close: python3 tools/case_state.py enrichment-done {a.case} "
                  f"--key <key> --reason ran|empty|unavailable|skipped")
        if fr.get("enrichment_results"):
            print(f"  {len(fr['enrichment_results'])} enrichment result(s) in enrichment/index.json "
                  "(third-party leads, not attribution):")
            for row in fr["enrichment_results"][:16]:
                print(f"    [{row['outcome']}] {row['key']}: {row['summary']}"
                      + (f" (enrichment/{row['file']})" if row["file"] else ""))
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
    if a.cmd == "approve-cohost":
        # the analyst approves from the lead they SAW: --all freezes its list; named domains must be on it
        lead = next((l for l in frontier(a.case, max_new=0).get("co_tenancy_leads") or []
                     if l.get("ip") == a.ip and l.get("check") == "vps co-tenancy — approve"), None)
        if lead is None:
            print(f"no `vps co-tenancy — approve` lead for {a.ip} in '{a.case}' — nothing approved",
                  file=sys.stderr)
            return 2
        listed = set(lead.get("domains") or [])
        reduce = _oh._apex if _oh is not None else _frontier_apex
        unknown = [d for d in (a.domains or []) if reduce(d) not in listed]
        if unknown:
            print(f"not on {a.ip}'s approval list (nothing approved): {', '.join(unknown)}", file=sys.stderr)
            return 2
        doms = list(a.domains or []) + (sorted(listed) if a.all else [])
        if not doms:
            print("name the domains to approve, or pass --all for the lead's current list", file=sys.stderr)
            return 2
        rec = record_approved_cohost(a.case, a.ip, doms)
        print(f"approved {len(rec['domains'])} co-tenant(s) of {a.ip} for '{a.case}': "
              f"{', '.join(rec['domains'])}. Next round seeds them; ingest links them to the IP.")
        return 0
    if a.cmd == "reopen":
        st = reopen(a.case, a.seeds or None)
        print(f"reopened '{a.case}' → status={st['status']}, pending={len(st['pending'])} "
              f"(reopened×{st['reopen_count']}). Re-run: python3 tools/intel.py loop {a.case}")
        return 0
    if a.cmd == "propose":
        cands = propose(a.case, max_per_type=a.max_per_type, probe=not a.no_probe)
        print(json.dumps([c.to_dict() for c in cands], indent=2, ensure_ascii=False))
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
