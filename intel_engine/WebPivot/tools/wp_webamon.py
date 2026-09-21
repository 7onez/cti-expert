#!/usr/bin/env python3
"""wp_webamon — Webamon Search (pro.webamon.com) scan-corpus client + normaliser.

Webamon scans and indexes ~750M domains daily and exposes the corpus as Lucene over OpenSearch
indices. What it adds to the stack is not another reverse index (FOFA/Censys/Validin cover
those) but the per-scan KIT FINGERPRINTS (`fingerprint.dom_band|dom|links|scripts|…`) — the
hashes its Pro-only /clusters API clusters on — which ARE queryable on a starter key through
/search. One call on a seed's fingerprints returns the other lures built from the same kit.

Mirrors wp_validin / wp_hunterhow:

  * `import wp_common` FIRST — installs the cti-proxy opener as an import side effect, so every
    urlopen here egresses through /cti-proxy. NEVER build a custom opener or use `requests`.
  * Keyless-safe: no key -> every lookup returns None; nothing errors, nothing egresses.
  * Tri-state per call: a normalised dict on success, `{"skipped": reason}` for auth/plan/quota
    conditions the caller degrades around, `{"error": reason}` for transport faults. Never raises.
  * NO local usage cap (project decision): the vendor's own 429 is the limit. A 429 latches a
    per-process flag so the rest of the run stops asking instead of burning failing calls.
  * Attribution rails: nothing here is an owner link. Same-kit siblings are a rung below
    co-tenancy — case_state lists the label in _NON_OWNER_SOURCES (related_leads, never seeded)
    and the ingest records facts only (never an edge). `infostealer_exposure` is COUNT-ONLY —
    credential fields are never requested.

Verified endpoints/shapes (2026-09-16, live, starter plan): see references/webamon_endpoints.json.
"""
import concurrent.futures
import json
import os
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wp_common import _secret, DEFAULT_UA  # noqa: E402 — shared .env loader + UA + proxy install

try:                                        # reference-file loader (optional; degrade to fallback)
    from wp_refs import load_ref, ref_path  # noqa: E402
except Exception:                           # noqa: BLE001
    def load_ref(path, fallback):
        return dict(fallback)

    def ref_path(module_file, name):
        return os.path.normpath(os.path.join(os.path.dirname(module_file), os.pardir,
                                             "references", name))

try:
    import api_usage                         # licensed-API call ledger (optional)
except Exception:                            # noqa: BLE001
    api_usage = None

BASE = "https://pro.webamon.com"

# DATA: endpoint paths, query window/fields, fingerprint policy. Overridable via
# references/webamon_endpoints.json (RULE 3); the fallback is the conservative minimum that keeps a
# file-less run correct — fewer report fields, the same rails.
_WEBAMON_FALLBACK = {
    "endpoints": {"search": "/search", "scan": "/scan", "plan_probe": "/campaigns/tags"},
    "search": {
        "window": "now-90d", "size": 25, "timeout": 45,
        "report_fields": ["report_id", "submission_utc", "resolved_url", "resolved_domain", "page_title",
                          "scan_status", "meta.risk_score", "tag", "server.ip", "certificate.subject_name",
                          "certificate.san_list", "resource.sha256", "resource.url", "page_scripts",
                          "technology.name", "fingerprint"],
        "server_fields": ["ip", "asn.number", "asn.name", "country.iso", "first_seen_utc", "last_seen_utc"],
    },
    "fingerprints": {"same_kit": ["dom_band", "dom", "links", "scripts"],
                     "noise": ["cert_config", "asn"], "max_siblings": 50, "size": 100},
    "status_reasons": {"401": "Webamon rejected the key", "403": "route not in your Webamon plan",
                       "404": "not in the Webamon corpus", "429": "Webamon daily quota reached",
                       "502": "Webamon search backend unavailable"},
}
_REFS = load_ref(ref_path(__file__, "webamon_endpoints.json"), _WEBAMON_FALLBACK)
EP = _REFS["endpoints"]
SEARCH = _REFS["search"]
FINGERPRINTS = _REFS["fingerprints"]
_STATUS_REASON = {int(k): v for k, v in _REFS["status_reasons"].items() if str(k).isdigit()}
_TIMEOUT = int(SEARCH.get("timeout", 45))

# Master off switch, flipped by callers (e.g. pivot_extract --no-webamon).
ENABLED = True

# Quota latch: set on the first 429, read by every later call in this process (one process = one
# case run). Not a cap — the vendor said stop; we merely stop repeating the question.
_QUOTA_HIT = False
_LOCK = threading.Lock()


def webamon_key():
    """The Webamon API key, or None."""
    return _secret("WEBAMON_API_KEY", "WEBAMON_KEY")


def webamon_configured() -> bool:
    """True when a key is available and Webamon isn't switched off — the gate every caller checks."""
    return ENABLED and bool(webamon_key())


def _headers():
    return {"User-Agent": DEFAULT_UA, "Accept": "application/json", "x-api-key": webamon_key() or ""}


def _record(action, results, ok=True):
    if api_usage:
        try:
            api_usage.record("webamon", action, credits=1, query=action, results=results, ok=ok)
        except Exception:                    # noqa: BLE001
            pass


def _get(path, params=None, *, timeout=None):
    """One API call -> (data, error_dict). Never raises. 4xx/5xx the vendor means become
    `skipped`; transport faults become `error`. A 429 latches the process-wide quota flag."""
    global _QUOTA_HIT
    if not webamon_configured():
        return None, {"skipped": "no WEBAMON_API_KEY configured"}
    if _QUOTA_HIT:
        return None, {"skipped": "quota — Webamon returned 429 earlier in this run"}
    url = BASE + path + (("?" + urllib.parse.urlencode(params)) if params else "")
    try:
        req = urllib.request.Request(url, headers=_headers())
        with urllib.request.urlopen(req, timeout=timeout or _TIMEOUT) as r:
            return json.load(r), None
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            body = json.loads(e.read().decode("utf-8", "replace"))
            if isinstance(body, dict):
                # `message` carries the specifics ("…(current: starter)"); `error` is the bare
                # status word ("Forbidden"). Keep both, specifics first — plan() parses this.
                detail = " / ".join(str(body[k]) for k in ("message", "error") if body.get(k))[:240]
        except Exception:                    # noqa: BLE001
            pass
        if e.code == 429:
            with _LOCK:
                _QUOTA_HIT = True
        reason = _STATUS_REASON.get(e.code)
        msg = "HTTP %d%s%s" % (e.code, (" — %s" % reason) if reason else "", (": %s" % detail) if detail else "")
        # A 400 is a query the server refused (bad Lucene, missing range) — our fault, reported as
        # an error so a template regression is visible instead of reading as "not in the corpus".
        return None, ({"skipped": msg} if e.code in _STATUS_REASON else {"error": msg})
    except Exception as e:                    # noqa: BLE001 — network/timeout/parse
        return None, {"error": str(e)}


def _q(value):
    """A Lucene phrase literal — quotes escaped, wrapped in double quotes."""
    return '"%s"' % str(value).replace('\\', '\\\\').replace('"', '\\"')


def _ranged(lucene):
    """Append the submission_utc window every scans-index query carries (speed + the server's own
    rule for wildcards/free text)."""
    return "%s AND submission_utc:[%s TO now]" % (lucene, SEARCH.get("window", "now-90d"))


def search(lucene, index="scans", fields=None, size=None, timeout=None):
    """Raw Lucene search -> (data, err). `fields` is a list; `size` defaults to the reference size."""
    params = {"lucene_query": lucene, "index": index, "size": int(size or SEARCH.get("size", 25))}
    if fields:
        params["fields"] = ",".join(fields)
    return _get(EP["search"], params, timeout=timeout)


# --------------------------------------------------------------------------- normalisers
def _uniq(seq):
    seen, out = set(), []
    for x in seq:
        if x and x not in seen:
            seen.add(x)
            out.append(x)
    return out


def _rows(data):
    return (data or {}).get("results") or [] if isinstance(data, dict) else []


def _sub(hit, key, field):
    """Flatten `hit[key]` (a list of dicts or a dict) to the list of `field` values."""
    node = hit.get(key)
    nodes = node if isinstance(node, list) else ([node] if isinstance(node, dict) else [])
    out = []
    for n in nodes:
        v = n.get(field) if isinstance(n, dict) else None
        if isinstance(v, list):
            out.extend(str(x) for x in v if x)
        elif v not in (None, ""):
            out.append(str(v))
    return _uniq(out)


def _hit_domain(hit):
    rd = hit.get("resolved_domain")
    if rd:
        return str(rd).lower()
    for d in hit.get("domain") or []:
        if isinstance(d, dict) and d.get("name"):
            return str(d["name"]).lower()
    return ""


def _report(hit):
    """One scans-index hit -> the compact report block wp_analyze attaches as live_results['webamon']."""
    fp = hit.get("fingerprint") if isinstance(hit.get("fingerprint"), dict) else {}
    return {
        "report_id": hit.get("report_id"),
        "submission_utc": hit.get("submission_utc"),
        "resolved_url": hit.get("resolved_url"),
        "resolved_domain": _hit_domain(hit),
        "page_title": hit.get("page_title"),
        "scan_status": hit.get("scan_status"),
        "risk_score": (hit.get("meta") or {}).get("risk_score") if isinstance(hit.get("meta"), dict) else None,
        "tag": hit.get("tag"),
        "server_ips": _sub(hit, "server", "ip"),
        "cert_subjects": _sub(hit, "certificate", "subject_name"),
        "cert_sans": _sub(hit, "certificate", "san_list"),
        "name_servers": _uniq(str(ns) for d in hit.get("domain") or []
                              if isinstance(d, dict) and isinstance(d.get("dns"), dict)
                              for ns in (d["dns"].get("ns") or [])),
        "resources": [{"sha256": r.get("sha256"), "url": r.get("url")}
                      for r in hit.get("resource") or [] if isinstance(r, dict) and r.get("sha256")],
        "page_scripts": [s for s in hit.get("page_scripts") or [] if isinstance(s, str)][:20],
        "technologies": _sub(hit, "technology", "name"),
        "fingerprint": {k: v for k, v in fp.items() if v},
    }


# --------------------------------------------------------------------------- typed lookups
def domain_scans(domain, timeout=None):
    """Latest Webamon scan of `domain` inside the window -> report block + `total` scans seen |
    tri-state. The block is enrichment of the seed itself (server IPs, certs, resources, kit
    fingerprints); it names no other host."""
    if not webamon_configured():
        return None
    data, err = search(_ranged("resolved_domain:%s" % _q(domain)), fields=SEARCH["report_fields"],
                       size=1, timeout=timeout)
    if err:
        _record("domain_scans", 0, ok=False)
        return err
    rows = _rows(data)
    _record("domain_scans", len(rows))
    if not rows:
        return {"total": 0}
    rep = _report(rows[0])
    rep["total"] = data.get("total_hits") if isinstance(data.get("total_hits"), int) else len(rows)
    return rep


def _empty_hashes():
    """Digests of an EMPTY structure — a `links`/`scripts` fingerprint that is the hash of no links
    is shared by every no-link page on the web and must never be queried as a kit."""
    import hashlib
    out = set()
    for s in (b"", b"[]", b"{}", b"null"):
        out.add(hashlib.sha1(s).hexdigest())
        out.add(hashlib.sha256(s).hexdigest())
    return out


_EMPTY_HASHES = _empty_hashes()


def same_kit(fingerprint, seed, timeout=None):
    """Other hosts built from the SAME KIT as `seed`, from its scan fingerprints -> tri-state:
      {"domains": [...], "total": n, "queried": {key: value}, "per_key": {key: {"total", "domains",
       "boilerplate"}}, "matched": {key: [domains]}, "titles": {domain: title}, "boilerplate": bool}
    ONE CALL PER KEY (the finest dom_band only), so each fingerprint gets its OWN prevalence
    check: a boilerplate hash on one key (an empty script list, a Cloudflare cert config) cannot
    drown the tight `dom` match on another. PREVALENCE GUARD per key: more than `max_siblings`
    hits marks that key boilerplate — its count is kept, its hosts are dropped. `domains` is the
    union of the non-boilerplate keys; `matched` shows which keys agree per sibling (corroboration).
    A hash of an empty structure is skipped up front. Same-kit is NOT an owner link: the caller's
    ingest/frontier treat it as a lead, never a seed."""
    if not webamon_configured():
        return None
    if not isinstance(fingerprint, dict):
        return {"skipped": "no fingerprint block on the seed's scan"}
    queried = {}
    for key in FINGERPRINTS.get("same_kit") or []:
        v = fingerprint.get(key)
        if isinstance(v, list):
            v = v[-1] if v else None            # dom_band: bands coarse->fine; the finest isolates a kit
        if v and str(v).lower() not in _EMPTY_HASHES:
            queried[key] = str(v)
    if not queried:
        return {"skipped": "seed scan carries none of the same-kit fingerprint keys"}
    seed = str(seed or "").lower()
    cap = int(FINGERPRINTS.get("max_siblings", 50))
    per_key, matched, titles = {}, {}, {}

    def _one(k, v):
        return search(_ranged("fingerprint.%s:%s" % (k, _q(v))),
                      fields=["resolved_domain", "domain.name", "page_title"],
                      size=FINGERPRINTS.get("size", 100), timeout=timeout)
    # The keys are independent lookups and the vendor's latency swings 1-15 s per call, so run
    # them together: the block costs the slowest key, not the sum. search() never raises.
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(queried))) as ex:
        results = {k: ex.submit(_one, k, v) for k, v in queried.items()}
    errors = {}
    for k in queried:
        data, err = results[k].result()
        if err:
            # One key's 502/timeout must not erase another key's tight match (the failure-mode twin
            # of OR saturation): record it on that key and keep going.
            errors[k] = err
            per_key[k] = dict(err, total=None, boilerplate=False, domains=[])
            matched[k] = []
            continue
        doms = []
        for hit in _rows(data):
            dom = _hit_domain(hit)
            if not dom or dom == seed:
                continue
            doms.append(dom)
            if hit.get("page_title"):
                titles[dom] = hit["page_title"]
        doms = sorted(_uniq(doms))
        total = data.get("total_hits") if isinstance(data.get("total_hits"), int) else len(doms)
        boiler = total > cap
        per_key[k] = {"total": total, "boilerplate": boiler, "domains": [] if boiler else doms}
        matched[k] = [] if boiler else doms
    if len(errors) == len(queried):
        _record("same_kit", 0, ok=False)
        # every key failed: identical failures propagate as THAT tri-state unmodified (the contract
        # callers test for); mixed failures return the first with the rest listed
        first = next(iter(errors.values()))
        return first if all(e == first for e in errors.values()) else dict(first, per_key_errors=errors)
    answered = [pk for k, pk in per_key.items() if k not in errors]
    domains = sorted(_uniq(d for k in queried for d in matched[k]))
    _record("same_kit", len(domains))
    all_boiler = all(pk["boilerplate"] for pk in answered)
    out = {"domains": domains,
           "total": max(pk["total"] for pk in answered),
           "queried": queried, "per_key": per_key, "matched": matched,
           "titles": {d: titles[d] for d in domains if d in titles},
           "boilerplate": all_boiler,
           "note": (("every fingerprint answers > %d hosts — template boilerplate, siblings not listed" % cap)
                    if all_boiler else "same-kit relation: a rung below owner — lead, never a seed")}
    if errors:
        out["partial"] = sorted(errors)          # keys whose lookup failed — the union is narrower than asked
    return out


def servers_for_domain(domain, timeout=None):
    """Hosting history from the `servers` index -> {"total", "servers":[{ip, asn, asn_name, country,
    first_seen, last_seen}]} | tri-state. IP-valued: feeds the timeline, never the frontier."""
    if not webamon_configured():
        return None
    data, err = search("domain:%s" % _q(domain), index="servers", fields=SEARCH["server_fields"],
                       size=SEARCH.get("size", 25), timeout=timeout)
    if err:
        _record("servers", 0, ok=False)
        return err
    out = []
    for s in _rows(data):
        asn = s.get("asn") if isinstance(s.get("asn"), dict) else {}
        country = s.get("country") if isinstance(s.get("country"), dict) else {}
        if s.get("ip"):
            out.append({"ip": s["ip"], "asn": asn.get("number"), "asn_name": asn.get("name"),
                        "country": country.get("iso"), "first_seen": s.get("first_seen_utc"),
                        "last_seen": s.get("last_seen_utc")})
    _record("servers", len(out))
    return {"total": data.get("total_hits") if isinstance(data.get("total_hits"), int) else len(out), "servers": out}


def feed_dates(domain, timeout=None):
    """Registration-feed facts: the day `domain` appeared in the NRD feed and/or the removed feed
    -> {"registered": "YYYYMMDD"|None, "removed": "YYYYMMDD"|None} | tri-state (two calls)."""
    if not webamon_configured():
        return None
    out = {}
    for idx, key in (("new_domains", "registered"), ("removed_domains", "removed")):
        data, err = search("domain:%s" % _q(domain), index=idx, fields=["domain", "date"], size=1, timeout=timeout)
        if err:
            _record(idx, 0, ok=False)
            return err
        rows = _rows(data)
        out[key] = str(rows[0].get("date")) if rows and rows[0].get("date") else None
        _record(idx, len(rows))
    return out


def infostealer_exposure(apex, timeout=None):
    """COUNT-ONLY infostealer exposure for an apex: rows whose `domain` is the apex or whose
    `username` is a mailbox at it -> {"total": n} | tri-state. Only the `domain` field is requested
    — credential columns never leave the vendor. A victim-side/privacy fact, never a pivot."""
    if not webamon_configured():
        return None
    # `username:"@apex"` (quoted) is the measured form — unquoted `@` is tokenised into noise and a
    # leading wildcard is refused without a range; the quoted phrase matched 55 staff mailboxes live.
    lucene = "domain:%s OR username:%s" % (_q(apex), _q("@" + apex))
    data, err = search(lucene, index="infostealers", fields=["domain"], size=1, timeout=timeout)
    if err:
        _record("infostealers", 0, ok=False)
        return err
    total = data.get("total_hits") if isinstance(data.get("total_hits"), int) else 0
    _record("infostealers", total)
    return {"total": total}


def plan(timeout=None):
    """Measured plan for `meta.capability.plans['webamon']`, decided by CALLING a Pro-gated route:
    a 403 body names the current plan (`current: starter`); a 200 means campaigns/clusters are
    open. -> {"tier": ..., "campaigns": bool} | {"tier": "unknown", "error": ...} | None keyless."""
    if not webamon_configured():
        return None
    data, err = _get(EP["plan_probe"], timeout=timeout)
    if not err:
        return {"tier": "research_lab+", "campaigns": True}
    msg = str(err.get("skipped") or err.get("error") or "")
    if "HTTP 403" in msg:
        import re
        m = re.search(r"current:\s*([A-Za-z0-9_-]+)", msg)
        return {"tier": m.group(1).lower() if m else "unknown", "campaigns": False}
    if "HTTP 401" in msg:
        return {"tier": "invalid", "campaigns": False, "error": msg}
    return {"tier": "unknown", "error": msg}


# --------------------------------------------------------------------------- gated sandbox submission
# REQUIRES_ANALYST_CONFIRMATION — scan() sends NOTHING unless confirm=True is passed as a function
# parameter; without it, it returns scan_preflight() (an offline briefing). Same contract as
# bp_anyrun.submit(): the harness @tool `webamon_scan` mirrors the two-step gate and audit.gate()
# additionally denies the confirmed call unless HARNESS_ALLOW_SUBMIT=1.

def submission_url(url, keep_query=False):
    """The URL that will actually be handed to the PUBLIC corpus. By default the query string and
    fragment are STRIPPED: on a phishing link they are where the victim lives (`?u=<victim>`,
    `?token=…`, a one-time code), and the corpus keeps them forever, searchable by any keyed user.
    A bare host gets `https://`. `keep_query=True` is the analyst's explicit decision to disclose.
    -> (url_to_submit, stripped: bool)."""
    u = str(url or "").strip()
    if u and "://" not in u:
        u = "https://" + u
    parts = urllib.parse.urlsplit(u)
    if keep_query:
        return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, "")), bool(parts.fragment)
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, "", "")), bool(parts.query or parts.fragment)


def scan_preflight(url, keep_query=False):
    """The RISK BRIEFING for submitting `url` to the Webamon sandbox — composed offline, sends
    nothing. What differs from ANY.RUN: the fetch comes from Webamon's own egress (the analyst's
    IP never touches the target), but EVERY scan lands in the public, searchable corpus for good —
    so the briefing shows the EXACT url that would be disclosed, after query stripping."""
    will, stripped = submission_url(url, keep_query)
    return {
        "action": "webamon_scan", "target": url, "will_submit": will, "submitted": False,
        "query_stripped": stripped,
        "requires": "confirm=true — an explicit analyst 'yes' to THIS submission of `will_submit`",
        "what_happens": [
            "Webamon fetches the URL from ITS OWN egress: your IP is not exposed to the target "
            "(posture-safe), but the operator sees a datacenter visit and may rotate or serve a decoy.",
            "The scan is indexed into the PUBLIC Webamon corpus (pro/search.webamon.com): anyone — "
            "including the operator — can find the submission, its screenshot, DOM and resources. "
            "There is no private mode and no delete.",
            ("The query string / fragment was STRIPPED (%s) — on a phishing link that is where the "
             "victim identifier lives. Pass keep_query=true ONLY if the analyst decides the full URL "
             "may be disclosed." % url) if stripped else
            "No query string to strip — the URL is submitted as shown in `will_submit`.",
            "Indexing takes ~1-5 minutes; the tool polls by report_id, then runs the same-kit fingerprint "
            "pivot on the fresh scan.",
        ],
        "try_first": [
            "wp_webamon domain_scans / pivot_extract: the corpus may ALREADY hold a recent scan of this "
            "host (the seed report + fingerprints) — no submission needed.",
            "urlscan search / Wayback: a prior third-party capture.",
        ],
        "never": ["a URL whose PATH carries a victim token, session or one-time link (stripping covers only "
                  "the query/fragment — read `will_submit` before confirming)",
                  "a case ID or client name anywhere in the URL"],
    }


def scan_submit(url, timeout=None):
    """POST-equivalent (GET /scan?submission_url=) -> {"report_id": ...} | tri-state. Do NOT call
    directly from a tool: go through scan(confirm=True) so the gate is the only entry point."""
    if not webamon_configured():
        return None
    data, err = _get(EP["scan"], {"submission_url": url}, timeout=timeout)
    if err:
        _record("scan", 0, ok=False)
        return err
    rid = (data or {}).get("report_id") if isinstance(data, dict) else None
    _record("scan", 1 if rid else 0, ok=bool(rid))
    return {"report_id": rid} if rid else {"error": "scan accepted but no report_id in the response"}


def report(report_id, timeout=None):
    """One scan by report_id -> the compact report block (see _report) | {"pending": True} when
    not yet indexed | tri-state. Read-only."""
    if not webamon_configured():
        return None
    data, err = search(_ranged("report_id:%s" % _q(report_id)), fields=SEARCH["report_fields"], size=1,
                       timeout=timeout)
    if err:
        return err
    rows = _rows(data)
    if not rows:
        return {"pending": True, "report_id": report_id}
    rep = _report(rows[0])
    rep["report_id"] = rep.get("report_id") or report_id
    return rep


def scan(url, confirm=False, wait=300, poll=30, keep_query=False, timeout=None, _sleep=None):
    """Submit `url` to the Webamon sandbox and follow it to a report — GATED.

    confirm=False (default) -> scan_preflight(url): the briefing, nothing sent, no network.
    confirm=True -> submit `submission_url(url, keep_query)` (query/fragment stripped unless
    keep_query=True), then poll report() every `poll` s for up to `wait` s; when the scan is
    indexed, run same_kit on its fingerprints. Returns {"submitted": True, "submitted_url",
    "query_stripped", "report_id", "status": "complete"|"pending", "report", "same_kit"} |
    tri-state on a refused/failed submit. A pending result carries the report_id: call
    report(<id>) later — nothing is re-submitted."""
    if not confirm:
        return scan_preflight(url, keep_query)
    if not webamon_configured():
        return None
    will, stripped = submission_url(url, keep_query)
    sub = scan_submit(will, timeout=timeout)
    if not isinstance(sub, dict) or not sub.get("report_id"):
        return sub
    rid = sub["report_id"]
    out = {"submitted": True, "submitted_url": will, "query_stripped": stripped, "report_id": rid,
           "status": "pending", "report": None, "same_kit": None,
           "note": "the scan is PUBLIC in the Webamon corpus and cannot be withdrawn"}
    import time
    sleep = _sleep or time.sleep
    deadline = time.monotonic() + max(0, int(wait or 0))
    while True:
        rep = report(rid, timeout=timeout)
        if isinstance(rep, dict) and rep.get("scan_status"):
            out["status"] = "complete"
            out["report"] = rep
            if rep.get("fingerprint"):
                out["same_kit"] = same_kit(rep["fingerprint"], rep.get("resolved_domain") or url, timeout=timeout)
            break
        if isinstance(rep, dict) and ("error" in rep or "skipped" in rep):
            out["poll_error"] = rep
            break
        if time.monotonic() >= deadline:
            out["note"] += "; not indexed within %ss — call report(%s) later (nothing is re-submitted)" % (wait, rid)
            break
        sleep(max(1, int(poll or 30)))
    return out


__all__ = ["webamon_key", "webamon_configured", "search", "domain_scans", "same_kit", "servers_for_domain",
           "feed_dates", "infostealer_exposure", "plan", "scan", "scan_preflight", "scan_submit", "report",
           "submission_url",
           "ENABLED", "BASE", "EP", "SEARCH", "FINGERPRINTS"]


def main(argv):
    usage = ("usage: wp_webamon.py <domain>                          latest scan + same-kit + hosting + feed dates\n"
             "       wp_webamon.py report <report_id>               one scan by id (read-only)\n"
             "       wp_webamon.py scan <url> [--confirm-submission] [--wait S] [--poll S] [--keep-query]\n"
             "           without --confirm-submission: prints the risk briefing, sends NOTHING (rc 3);\n"
             "           the query string/fragment is STRIPPED unless --keep-query (victim tokens live there)\n"
             "       wp_webamon.py plan                             measured plan tier")
    if not argv:
        print(usage, file=sys.stderr)
        return 2
    cmd = argv[0]
    if cmd == "plan":
        print(json.dumps(plan(), indent=2))
        return 0
    if cmd == "report" and len(argv) > 1:
        print(json.dumps(report(argv[1]), indent=2))
        return 0
    if cmd == "scan" and len(argv) > 1:
        url = argv[1]
        confirm = "--confirm-submission" in argv

        def _opt(flag, default):
            return int(argv[argv.index(flag) + 1]) if flag in argv and argv.index(flag) + 1 < len(argv) else default
        res = scan(url, confirm=confirm, wait=_opt("--wait", 300), poll=_opt("--poll", 30),
                   keep_query="--keep-query" in argv)
        print(json.dumps(res, indent=2))
        return 0 if confirm else 3           # rc 3 = the gate fired (designed outcome, not a failure)
    if cmd.startswith("-"):
        print(usage, file=sys.stderr)
        return 2
    dom = cmd
    rep = domain_scans(dom)
    out = {"domain_scans": rep}
    if isinstance(rep, dict) and rep.get("fingerprint"):
        out["same_kit"] = same_kit(rep["fingerprint"], dom)
    out["servers"] = servers_for_domain(dom)
    out["feed_dates"] = feed_dates(dom)
    out["infostealer_exposure"] = infostealer_exposure(dom)
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
