"""wp_impersonate — impersonation / typosquat / lookalike domain hunting for WebPivot.

Given ONE seed domain, this hunts for the domains an operator would register to impersonate
it — not just the one page. Three moves, in order of yield:

  1. TYPOSQUAT permutations of the brand label (omission / insertion / adjacent-key replacement /
     transposition / repetition / homoglyph / hyphenation / combosquat affixes).
  2. TLD SWEEP — the exact brand label across a curated scam-heavy TLD list.
  3. KEYWORD HUNT — every domain whose NAME contains the brand label, from certificate
     transparency (crt.sh identity LIKE, FREE) and, opt-in, FOFA + urlscan (metered).

Generated candidates are then EXISTENCE-CHECKED (concurrent live DNS) so the output separates
lookalikes that are actually registered/observed from a monitoring list of unregistered ones.
Everything is emitted in the standard WebPivot result shape ({meta, artifacts, pivots}) so the
same KB / case graph clusters lookalikes with the rest of a case's web infrastructure.

Cost policy (matches the repo's cost rules): the DEFAULT path (crt.sh + DNS) spends ZERO
credits. FOFA and urlscan keyword sweeps are opt-in (--fofa / --urlscan) and are recorded to
the api_usage ledger by the recon clients they call.

Runs standalone:  python3 wp_impersonate.py momovn.com [--max 600] [--fofa] [--urlscan] [--json]
and is dispatched from pivot_extract.py via  <domain> --hunt-impersonation.
"""
import sys
import os
import re
import json
import argparse
import datetime
import socket
import concurrent.futures

from wp_common import *  # noqa  — strip_www, uniq, _registrable, _MULTI_TLDS, DEFAULT_UA, _secret
from wp_refs import ref_path, load_ref  # noqa — reference DATA lives in references/*.json
try:
    import api_usage                      # licensed-API credit ledger
except Exception:  # noqa: BLE001
    api_usage = None


# --- brand-label split ------------------------------------------------------
def split_registrable(domain: str):
    """Return (brand_label, tld_suffix) for a host, multi-part-TLD aware.

    Reuses wp_common._registrable (eTLD+1) so 'shop.momovn.com.vn' -> ('momovn', 'com.vn')
    and 'momovn.com' -> ('momovn', 'com'). The brand label is what we permute; the tld is
    what we keep for typo variants and swap out for the TLD sweep.
    """
    reg = _registrable(strip_www(domain))
    parts = reg.split(".")
    if len(parts) < 2:
        return reg, ""
    return parts[0], ".".join(parts[1:])


# --- permutation engine -----------------------------------------------------
# The whole search space this hunt sweeps is DATA, in references/impersonation.json — tune it
# per campaign (add the TLDs a ring actually uses, or the affixes it bolts onto the brand) and
# the next hunt covers them without touching this module. The fallback below is deliberately
# tiny: if the file is unreadable the hunt still runs, visibly narrower, with a stderr warning.
_IMP_FALLBACK = {
    "tld_sweep": ["com", "net", "org", "io", "co", "xyz", "top", "vip", "online", "shop"],
    "combo_affixes": ["login", "secure", "account", "verify", "official", "app", "wallet"],
    "qwerty_adjacency": {"q": "wa", "w": "qeas", "e": "wrsd", "r": "etdf", "t": "ryfg"},
    "homoglyphs": {"o": ["0"], "0": ["o"], "l": ["1"], "i": ["1"], "e": ["3"], "a": ["4"]},
    "homoglyph_sequences": [["m", "rn"], ["rn", "m"], ["w", "vv"]],
}
_IMP_REF = load_ref(ref_path(__file__, "impersonation.json"), _IMP_FALLBACK)

# QWERTY physical adjacency — bounds insertion/replacement to plausible fat-finger typos
# instead of the whole alphabet (keeps the candidate count sane).
_QWERTY = dict(_IMP_REF["qwerty_adjacency"])
# ASCII visual confusables (single-char); multi-char confusables handled separately.
_HOMOGLYPH = {k: list(v) for k, v in _IMP_REF["homoglyphs"].items()}
_HOMOGLYPH_MULTI = [tuple(p) for p in _IMP_REF["homoglyph_sequences"]]
_VOWELS = "aeiou"


def _typo_variants(label: str):
    """All in-label typosquat mutations of `label` as {mutation: technique}. Bounded per class."""
    out: dict[str, str] = {}
    n = len(label)

    def add(v: str, tech: str):
        v = v.strip("-.")
        if v and v != label and v.isascii() and 1 < len(v) <= 40 and v not in out:
            out[v] = tech

    for i in range(n):
        c = label[i]
        # omission
        add(label[:i] + label[i + 1:], "omission")
        # repetition (double a char)
        add(label[:i] + c + c + label[i:], "repetition")
        # adjacent-key replacement + insertion (bounded to physical neighbours)
        for nb in _QWERTY.get(c, ""):
            add(label[:i] + nb + label[i + 1:], "replacement")
            add(label[:i] + nb + label[i:], "insertion")
        # single-char homoglyph
        for hg in _HOMOGLYPH.get(c, []):
            add(label[:i] + hg + label[i + 1:], "homoglyph")
        # vowel swap
        if c in _VOWELS:
            for vw in _VOWELS:
                if vw != c:
                    add(label[:i] + vw + label[i + 1:], "vowel-swap")
    # transposition of adjacent chars
    for i in range(n - 1):
        add(label[:i] + label[i + 1] + label[i] + label[i + 2:], "transposition")
    # multi-char homoglyph sequences (m<->rn, w<->vv, ...)
    for a, b in _HOMOGLYPH_MULTI:
        idx = label.find(a)
        while idx != -1:
            add(label[:idx] + b + label[idx + len(a):], "homoglyph")
            idx = label.find(a, idx + 1)
    # hyphenation (insert a hyphen at each interior boundary) + de-hyphenation
    for i in range(1, n):
        add(label[:i] + "-" + label[i:], "hyphenation")
    if "-" in label:
        add(label.replace("-", ""), "de-hyphenation")
    return out


# Curated scam-heavy + common TLD list for the sweep (brand label swapped across these).
# DATA: references/impersonation.json -> tld_sweep
TLD_SWEEP = list(_IMP_REF["tld_sweep"])
# Combosquat affixes an operator bolts onto a brand (login pages, wallets, regional splits).
# DATA: references/impersonation.json -> combo_affixes
COMBO_AFFIXES = list(_IMP_REF["combo_affixes"])


def generate_variants(domain: str, tlds=None, affixes=None, max_variants: int = 600):
    """Generate impersonation candidates for `domain`, ordered nearest-first, capped at max_variants.

    Returns {'seed','label','tld','variants':[{'domain','technique'}], 'count', 'truncated'}.
    Ordering priority: typo (closest) -> combosquat -> TLD sweep -> ... so a cap keeps the
    highest-signal candidates. Pure/deterministic — no network — so it is unit-testable offline.
    """
    tlds = tlds or TLD_SWEEP
    affixes = affixes or COMBO_AFFIXES
    seed = strip_www(domain).split(":")[0].lower()
    label, tld = split_registrable(seed)
    tld = tld or "com"

    ordered: dict[str, str] = {}   # domain -> technique (insertion order = priority)

    def put(d: str, tech: str):
        d = d.strip(".").lower()
        if d and d != seed and d not in ordered:
            ordered[d] = tech

    # 1) typosquats on the label, keeping the seed's TLD (closest lookalikes)
    for mut, tech in _typo_variants(label).items():
        put(f"{mut}.{tld}", tech)
    # 2) combosquat affixes (prefix-hyphen, suffix-hyphen, suffix-glued)
    for af in affixes:
        put(f"{label}-{af}.{tld}", "combosquat")
        put(f"{af}-{label}.{tld}", "combosquat")
        put(f"{label}{af}.{tld}", "combosquat")
    # 3) TLD sweep — exact label across the TLD list
    for t in tlds:
        put(f"{label}.{t}", "tld-sweep")

    items = [{"domain": d, "technique": t} for d, t in ordered.items()]
    truncated = len(items) > max_variants
    return {"seed": seed, "label": label, "tld": tld,
            "variants": items[:max_variants], "count": min(len(items), max_variants),
            "truncated": truncated}


# --- existence validation ---------------------------------------------------
def _resolve(host: str, timeout: float = 4.0):
    """Live A-record resolution for one host (OS resolver). Returns [ips] or [].

    Socket-only ON PURPOSE — this is the bulk existence check over HUNDREDS of candidates, so it
    must stay cheap. wp_recon.resolve_live_dns is the richer single-host anchor (nslookup + ping
    fallbacks) but spawns 1-2 subprocesses PER host, which is pathological at this fan-out.
    """
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET)
        return uniq([i[4][0] for i in infos])
    except Exception:  # noqa: BLE001 — NXDOMAIN / timeout / etc. all mean "not resolving"
        return []
    finally:
        socket.setdefaulttimeout(old)


def check_existence(domains, workers: int = 24, timeout: float = 4.0):
    """Concurrently resolve `domains`; return {domain: [ips]} for those that resolve live."""
    resolved: dict[str, list] = {}
    if not domains:
        return resolved
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(workers, len(domains))) as ex:
        futs = {ex.submit(_resolve, d, timeout): d for d in domains}
        for fu in concurrent.futures.as_completed(futs):
            d = futs[fu]
            ips = fu.result()
            if ips:
                resolved[d] = ips
    return resolved


# --- keyword hunt (crt.sh FREE; FOFA / urlscan opt-in, metered) -------------
_HOST_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9-]+)+", re.I)
KEYWORD_MIN_LEN = 4   # a shorter/dictionary label makes the LIKE search all noise


def _domains_containing(names, label: str):
    """From a bag of cert SAN / host strings, keep the registrable domains that contain `label`."""
    out = set()
    for raw in set(names):   # CT rows repeat identical SANs across many certs — dedupe before parsing
        for line in str(raw).splitlines():
            for m in _HOST_RE.findall(line.strip().lstrip("*.").lower()):
                if label in m:
                    out.add(_registrable(m))
    return out


def crtsh_keyword_hunt(label: str, timeout: int = 25):
    """CT keyword hunt: every domain whose cert identity CONTAINS `label` (crt.sh LIKE). FREE.

    Uses wp_recon._crtsh_fetch with a '%label%' LIKE value (resilient q->identity fallback).
    Recorded to the ledger at credits=0 (free) purely for run visibility.
    """
    if len(label) < KEYWORD_MIN_LEN:
        return {"source": "crt.sh", "skipped": f"label '{label}' < {KEYWORD_MIN_LEN} chars — "
                "LIKE search would be mostly noise; TLD sweep + typos still ran."}
    from wp_recon import _crtsh_fetch
    try:
        rows = _crtsh_fetch(f"%{label}%", timeout=timeout)
    except Exception as e:  # noqa: BLE001 — crt.sh 502s often; soft-fail with partial results
        if api_usage:
            api_usage.record("crt.sh", "keyword_hunt", credits=0, query=f"%{label}%", ok=False)
        return {"source": "crt.sh", "error": str(e)}
    names = []
    for row in rows or []:
        names.append(row.get("name_value", ""))
        names.append(row.get("common_name", ""))
    domains = sorted(_domains_containing(names, label))
    if api_usage:
        api_usage.record("crt.sh", "keyword_hunt", credits=0, query=f"%{label}%", results=len(domains))
    return {"source": "crt.sh", "domains": domains, "count": len(domains)}


def fofa_keyword_hunt(label: str, size: int = 100, timeout: int = 30):
    """Opt-in FOFA keyword hunt via cert="label" (TLS cert mentions the brand). METERED — the
    fofa_search client records the credit spend. Returns {} if no FOFA key is configured."""
    from wp_recon import fofa_search
    res = fofa_search(f'cert="{label}"', size=size, timeout=timeout)
    if not res:
        return {"source": "fofa", "skipped": "no FOFA key configured"}
    if res.get("error"):
        return {"source": "fofa", "error": res["error"]}
    domains = sorted({_registrable(r.get("domain") or strip_www(r.get("host", "")))
                      for r in res.get("results", []) if (r.get("domain") or r.get("host"))})
    domains = [d for d in domains if d and label in d]
    return {"source": "fofa", "domains": domains, "count": len(domains),
            "total": res.get("total")}


def urlscan_keyword_hunt(label: str, timeout: int = 30):
    """Opt-in urlscan keyword hunt via page.domain wildcard. METERED — urlscan_search records it."""
    from wp_recon import urlscan_search
    res = urlscan_search(f"page.domain:*{label}*", timeout=timeout)
    if not res or res.get("error"):
        return {"source": "urlscan", "error": (res or {}).get("error", "no result")}
    domains = sorted({_registrable(d) for d in res.get("domains", []) if label in d.lower()})
    return {"source": "urlscan", "domains": domains, "count": len(domains),
            "total": res.get("total")}



def validin_lookalike_hunt(domain: str):
    """Validin newly-observed Levenshtein<=2 lookalikes for `domain`. FREE (quota-governed in
    wp_validin, runs even under --free-only); returns {} when no key. Each hit carries live
    recent_dns + registrar, so Validin lookalikes are strong (registered + observed), not guesses."""
    import wp_validin
    if not wp_validin.validin_configured():
        return {"source": "validin", "skipped": "no VALIDIN_API_KEY configured"}
    res = wp_validin.lookalikes(domain)
    if not isinstance(res, dict) or res.get("error") or res.get("skipped"):
        return {"source": "validin", **({k: v for k, v in (res or {}).items()
                                         if k in ("error", "skipped")} or {"error": "no result"})}
    domains = sorted({_registrable(r.get("domain")) for r in (res.get("records") or [])
                      if r.get("domain")})
    return {"source": "validin", "domains": [d for d in domains if d], "count": len(domains)}

# --- orchestration + WebPivot-shaped result ---------------------------------
def build_impersonation_result(domain: str, *, max_variants: int = 600, fofa: bool = False,
                               urlscan: bool = False, case=None) -> dict:
    """Run the full hunt for `domain` and return a WebPivot result {meta, artifacts, pivots}.

    Explicit keyword contract (not an opaque args object) so both callers — this module's CLI and
    pivot_extract's --hunt-impersonation dispatch — pass named kwargs with no adapter shim.
    """
    max_variants = int(max_variants or 600)

    gen = generate_variants(domain, max_variants=max_variants)
    label = gen["label"]
    variant_domains = [v["domain"] for v in gen["variants"]]
    tech_of = {v["domain"]: v["technique"] for v in gen["variants"]}

    # keyword hunt (crt.sh free; FOFA/urlscan opt-in). Run concurrently only if >1 source is on —
    # the default (crt.sh alone) doesn't need a thread pool.
    jobs = {"crtsh": lambda: crtsh_keyword_hunt(label)}
    if fofa:
        jobs["fofa"] = lambda: fofa_keyword_hunt(label)
    if urlscan:
        jobs["urlscan"] = lambda: urlscan_keyword_hunt(label)
    import wp_validin
    if wp_validin.validin_configured():
        jobs["validin"] = lambda: validin_lookalike_hunt(domain)
    if len(jobs) == 1:
        hunts = {"crtsh": crtsh_keyword_hunt(label)}
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(jobs)) as ex:
            futs = {k: ex.submit(fn) for k, fn in jobs.items()}
            hunts = {k: fu.result() for k, fu in futs.items()}

    keyword_domains = {}   # domain -> source that first surfaced it
    for src, h in hunts.items():
        for d in h.get("domains", []):
            keyword_domains.setdefault(d, h.get("source", src))

    seed = gen["seed"]
    # existence check: generated variants ∪ keyword hits (minus the seed itself)
    to_check = uniq([d for d in variant_domains + list(keyword_domains) if d != seed])
    resolved = check_existence(to_check)

    # a "keyword hit" from CT/FOFA/urlscan is EVIDENCE of existence even if it isn't resolving now
    existing, candidates = [], []
    for d in to_check:
        ev = {}
        if d in resolved:
            ev["dns"] = resolved[d]
        if d in keyword_domains:
            ev["observed_in"] = keyword_domains[d]
        entry = {"domain": d, "technique": tech_of.get(d, "keyword-hunt"), "evidence": ev}
        (existing if ev else candidates).append(entry)

    artifacts = {"impersonation": {
        "seed": seed, "brand_label": label, "tld": gen["tld"],
        "generated": gen["count"], "generated_truncated": gen["truncated"],
        "keyword_hunt": {k: {kk: vv for kk, vv in h.items() if kk != "domains"}
                         for k, h in hunts.items()},   # per-source status/counts (not the full lists)
        "existing_count": len(existing), "candidate_count": len(candidates),
    }}
    meta = {"host": seed, "final_url": seed, "kind": "impersonation",
            "source": "ImpersonationHunt",
            "collected_at": datetime.datetime.now(datetime.timezone.utc)
            .strftime("%Y-%m-%dT%H:%M:%SZ"), "case": case}
    from wp_pivots import sort_pivots, add_pivot
    pivots = []

    # one pivot per CONFIRMED lookalike (resolves live and/or seen in CT/FOFA/urlscan)
    for e in existing:
        d = e["domain"]
        ev, tech = e["evidence"], e["technique"]
        ips = ev.get("dns") or []
        note = (f"Lookalike of {seed} via {tech}. "
                + (f"Resolves to {', '.join(ips)}. " if ips else "")
                + (f"Seen in {ev['observed_in']}. " if ev.get("observed_in") else "")
                + "Confirm same-operator by running WebPivot on it and comparing pivots.")
        queries = [{"service": "WebPivot", "query": f"pivot_extract.py https://{d}"},
                   {"service": "crt.sh", "query": f"%.{d}"}]
        if ips:
            queries.append({"service": "FOFA", "query": f'ip="{ips[0]}"'})
        add_pivot(pivots, "impersonation:candidate", d,
                  "medium" if ips or ev.get("observed_in") else "low", queries, note,
                  live={"resolves": ips} if ips else None)

    # a single roll-up pivot carrying the unregistered monitoring list (don't spam one-per)
    if candidates:
        watch = [c["domain"] for c in candidates]
        add_pivot(pivots, "impersonation:watchlist", f"{len(watch)} unregistered lookalikes",
                  "information",
                  [{"service": "crt.sh monitor", "query": f"%{label}%"},
                   {"service": "note", "query": "re-check periodically — NRDs appear over time"}],
                  "Generated lookalikes with no current DNS / CT evidence — a takedown/monitoring "
                  "watchlist, not confirmed infra: " + ", ".join(watch[:60])
                  + (f" … (+{len(watch) - 60} more)" if len(watch) > 60 else ""))

    return {"meta": meta, "artifacts": artifacts, "pivots": sort_pivots(pivots)}


# --- standalone CLI ---------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description="Hunt impersonation / typosquat / lookalike domains for a seed domain.")
    ap.add_argument("domain", help="seed domain, e.g. example.com (a bare domain, not a URL)")
    ap.add_argument("--max", type=int, default=600, help="cap on generated candidates (default 600)")
    ap.add_argument("--fofa", action="store_true", help="also run the FOFA cert= keyword sweep (metered)")
    ap.add_argument("--urlscan", action="store_true", help="also run the urlscan keyword sweep (metered)")
    ap.add_argument("--case", default=None, help="case id (for the api_usage ledger context)")
    ap.add_argument("--generate-only", action="store_true",
                    help="just print the generated candidate list (offline, no DNS/CT)")
    ap.add_argument("--pretty", action="store_true", help="pretty-print JSON")
    args = ap.parse_args()

    if api_usage:
        api_usage.set_context(case=args.case, skill="WebPivot")

    if args.generate_only:
        gen = generate_variants(args.domain, max_variants=args.max)
        print(json.dumps(gen, indent=2 if args.pretty else None, ensure_ascii=False))
        return

    result = build_impersonation_result(args.domain, max_variants=args.max, fofa=args.fofa,
                                        urlscan=args.urlscan, case=args.case)
    print(json.dumps(result, indent=2 if args.pretty else None, ensure_ascii=False))


if __name__ == "__main__":
    main()
