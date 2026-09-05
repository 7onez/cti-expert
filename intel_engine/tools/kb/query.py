#!/usr/bin/env python3
"""
query.py — read the knowledge base (no web I/O). The cheap, cited substrate the
IntelAnalysis skill and the reporter read from instead of re-querying the world.

  python3 query.py --kb knowledge --stats
  python3 query.py --kb knowledge --shared --min 2      # cluster seeds (whole KB)
  python3 query.py --kb knowledge --shared --domains a.example,b.example   # scoped to ONE case
  python3 query.py --kb knowledge --entity example.com
  python3 query.py --kb knowledge --cluster example.com
  python3 query.py --kb knowledge --type person
"""
import os
import sys
import argparse
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from knowledge_base import KB  # noqa: E402

# --- registrant carve-out ------------------------------------------------------------------------
# A shared WHOIS registrant (email / name / org) is an OPERATOR-GRADE link: one operator's estate
# legitimately holds dozens of domains under a single registrant, so the generic prevalence cap —
# which treats an indicator carried by > max_prevalence domains as generic infrastructure noise —
# WRONGLY shatters that estate into singletons. Registrant edges instead get the far higher bulk-
# registrant bound via noise_filters.is_bulk_registrant (BULK_REGISTRANT_MAX_DOMAINS, from
# noise_filters.json) — the SAME cap BOTH ingest paths enforce, so clustering never drops a
# registrant edge ingest admitted, nor keeps one it refused. Above it the value is a
# reseller/registrar service, not an owner. And a placeholder / privacy / role registrant value (a
# mis-parsed WHOIS field label such as "Registry Registrant ID: Not Available From Registry", a
# "Domain Admin" boilerplate name, a privacy-proxy mailbox) is never an identity, so it must not
# bind a cluster edge at all.
REGISTRANT_RELS = frozenset({"registered_by"})

try:  # canonical registrant-noise predicates — single source of truth with both ingest paths
    from noise_filters import is_noise_email, is_bulk_registrant, BOILERPLATE_RELS  # noqa: E402
except Exception:  # noqa: BLE001 — degrade safely; a read-only query must never crash
    BOILERPLATE_RELS = frozenset({"same_inline_css", "same_comment", "same_template", "same_bundle"})

    def is_noise_email(_):        # pragma: no cover
        return False

    def is_bulk_registrant(_):    # pragma: no cover
        return False

try:
    import kb_refs  # noqa: E402 — reference DATA lives in references/registrant_noise.json (RULE 3)
    _RN = kb_refs.load_ref(kb_refs.ref_path(__file__, "registrant_noise.json"),
                           {"name_junk": [], "role_name_placeholders": [], "privacy_markers": [],
                            "placeholder_person_markers": [], "proxy_email_domains": []})
except Exception:  # noqa: BLE001 — degrade to empty lists; never crash a read-only KB query
    _RN = {"name_junk": [], "role_name_placeholders": [], "privacy_markers": [],
           "placeholder_person_markers": [], "proxy_email_domains": []}
_NAME_JUNK = tuple(_RN.get("name_junk") or ())
_ROLE_PLACEHOLDERS = frozenset(_RN.get("role_name_placeholders") or ())
_PRIV_MARKERS = tuple(_RN.get("privacy_markers") or ())
_PLACEHOLDER_PERSON = tuple(_RN.get("placeholder_person_markers") or ())
_PROXY_EMAIL_DOMAINS = tuple(_RN.get("proxy_email_domains") or ())


def _norm_name(v):
    """Lowercase, drop punctuation, collapse whitespace — the same normalisation ingest_webpivot
    uses, so 'Domain Admin.' and 'DOMAIN  ADMIN' both compare equal to the role placeholder list."""
    s = "".join(c if (c.isalnum() or c.isspace()) else " " for c in (v or "").lower())
    return " ".join(s.split())


def is_registrant_noise(dst_type, value):
    """True if a `registered_by` target is registrar/privacy/placeholder boilerplate rather than a
    real owner, so it must never bind a same-operator cluster. Mirrors ingest_webpivot's combined
    email gate — `_is_privacy(em) OR is_noise_email(em)` — and its name gates (_is_role_placeholder /
    _name_kind: role_name_placeholders exact + name_junk / privacy / placeholder substrings), over
    the SAME registrant_noise.json, so a value ingest would refuse as an edge is refused here too,
    cleaning KBs ingested before those gates existed."""
    v = (value or "").strip().lower()
    if not v:
        return True
    if dst_type == "email":
        if "@" not in v:
            return True
        # is_noise_email covers role local-parts, abuse.<domain> and noise_filters' registrar/
        # privacy DOMAIN lists. ingest ALSO gates with _is_privacy — a SEPARATE, non-overlapping
        # list: fuzzy privacy markers ANYWHERE in the address + registrant_noise proxy_email_domains
        # (e.g. privacy@1and1.com, which is_noise_email misses). _components reads raw KB edges
        # (incl. any ingested before those gates), so replicate BOTH.
        if is_noise_email(v) or any(m in v for m in _PRIV_MARKERS):
            return True
        dom = v.split("@", 1)[1]
        return any(dom == d or dom.endswith("." + d) for d in _PROXY_EMAIL_DOMAINS)
    # person / org — exact role placeholder, or any junk/privacy/placeholder substring
    if _norm_name(v) in _ROLE_PLACEHOLDERS:
        return True
    return (any(m in v for m in _NAME_JUNK)
            or any(m in v for m in _PRIV_MARKERS)
            or any(m in v for m in _PLACEHOLDER_PERSON))


def main():
    ap = argparse.ArgumentParser(description="Query the OSINT knowledge base.")
    ap.add_argument("--kb", required=True)
    ap.add_argument("--stats", action="store_true")
    ap.add_argument("--shared", action="store_true", help="indicators shared by >= --min domains")
    ap.add_argument("--min", type=int, default=2)
    ap.add_argument("--entity", help="dump one entity's facts + edges")
    ap.add_argument("--cluster", help="domains sharing an indicator with this domain")
    ap.add_argument("--strong", action="store_true",
                    help="with --cluster: exclude boilerplate edges (shared CSS/comment/DOM "
                         "template) AND indicators shared by > --max-prevalence domains (generic "
                         "kit favicons, registrar emails) so only owner-set indicators cluster — "
                         "avoids WP-Rocket-style and generic-favicon false same-operator links")
    ap.add_argument("--max-prevalence", type=int, default=8,
                    help="with --strong: an indicator shared by more than this many domains is "
                         "treated as generic/noise and ignored (default 8)")
    ap.add_argument("--components", action="store_true",
                    help="partition domains into same-operator connected components over STRONG "
                         "shared indicators (boilerplate/benign/over-prevalent edges excluded)")
    ap.add_argument("--domains", default="",
                    help="comma-separated domain set to restrict to (e.g. ONE case's domains); "
                         "default = the whole KB. With --components it restricts clustering; with "
                         "--shared it scopes the cluster seeds to that set, so a case's shared.txt "
                         "reports what is shared INSIDE the case instead of across every past case")
    ap.add_argument("--type", help="list entities of a type")
    args = ap.parse_args()
    kb = KB(args.kb)
    restrict = {d.strip().lower() for d in args.domains.split(",") if d.strip()} or None

    if args.stats:
        ents = list(kb.all_entities())
        print(f"entities: {len(ents)}   facts: {sum(len(e['facts']) for e in ents)}   edges: {len(kb.edges())}")
        print("by type:", dict(Counter(e["type"] for e in ents)))
        print("edges by rel:", dict(Counter(e["rel"] for e in kb.edges())))
        print("facts by source:", dict(Counter(f["source"] for e in ents for f in e["facts"])))

    if args.shared:
        # SCOPE: with --domains, an indicator qualifies on how many of THOSE domains carry it —
        # otherwise a case's cluster seeds are polluted by every unrelated past case in the KB.
        # The KB-wide count is still printed alongside, because an indicator shared by 3 domains
        # here but 47 KB-wide is prevalence noise, not an owner link.
        scope = f" among the {len(restrict)} given domain(s)" if restrict else ""
        try:
            from reference import benign_values          # curated globally-benign fingerprints
            benign = benign_values(args.kb)
        except Exception:  # noqa: BLE001
            benign = set()
        print(f"\n# Shared indicators (>= {args.min} domains{scope}) — cluster seeds\n")
        for s in kb.shared_indicators(1 if restrict else args.min):
            if s["indicator"] in benign or f"{s['indicator_type']}:{s['indicator']}" in benign:
                continue                                  # platform default / archive artifact — never a seed
            doms = s["domains"]
            if restrict is not None:
                doms = [d for d in doms if d.lower() in restrict]
                if len(doms) < args.min:
                    continue
            wide = (f"  [KB-wide: {s['domain_count']} domains]"
                    if restrict is not None and s["domain_count"] > len(doms) else "")
            print(f"[{len(doms)}] {s['indicator_type']}:{s['indicator']}  "
                  f"({', '.join(s['rels'])}){wide}")
            print(f"     {', '.join(doms)}")

    if args.type:
        print(f"\n# entities of type '{args.type}'")
        for e in sorted(kb.all_entities(), key=lambda x: x["value"]):
            if e["type"] == args.type:
                print(f"  {e['value']}   ({len(e['facts'])} facts)")

    if args.entity:
        # find it across types
        found = [e for e in kb.all_entities() if e["value"] == args.entity]
        for e in found:
            print(f"\n# {e['type']}: {e['value']}   (first {e.get('first_seen')} … last {e.get('last_seen')})")
            for f in e["facts"]:
                print(f"  · {f['attribute']} = {f['value']}   [{f['source']}/{f['collector']} conf {f['confidence']}]")
            nb = kb.neighbors(e["type"], e["value"])
            if nb:
                print("  edges:")
                for dt, dv, rel, conf in nb:
                    print(f"    -{rel}-> {dt}:{dv}   (conf {conf})")

    if args.cluster:
        # 1-hop through shared indicators: domains that share any indicator with target
        target = args.cluster
        # Boilerplate relations — shared page-template/cache-plugin artifacts (WP Rocket CSS,
        # HTML comments, DOM skeleton) that many UNRELATED operators emit. They create false
        # same-operator edges; --strong drops them so only owner-set indicators remain.
        NOISE_RELS = BOILERPLATE_RELS
        inds = {(dt, dv) for dt, dv, rel, c in kb.neighbors("domain", target)
                if dt in ("indicator", "email", "person", "org")}
        # Guided-pivot prevalence: an indicator shared by too many domains (generic kit favicons,
        # registrar/privacy emails, g-recaptcha) is noise, not an owner link. Count how many
        # domains carry each indicator once, then --strong drops the over-common ones.
        prevalence: dict = {}
        benign: set = set()
        if args.strong:
            for e in kb.edges():
                if e["src_type"] == "domain":
                    prevalence.setdefault((e["dst_type"], e["dst"]), set()).add(e["src"])
            try:
                from reference import benign_values          # curated globally-benign fingerprints
                benign = benign_values(args.kb)
            except Exception:  # noqa: BLE001
                benign = set()
        peers = {}
        for e in kb.edges():
            if e["src_type"] == "domain" and (e["dst_type"], e["dst"]) in inds and e["src"] != target:
                if args.strong:
                    is_reg = e["rel"] in REGISTRANT_RELS
                    prev = len(prevalence.get((e["dst_type"], e["dst"]), ()))
                    if e["rel"] in NOISE_RELS or e["dst"] in benign:
                        continue
                    if is_reg:
                        if is_registrant_noise(e["dst_type"], e["dst"]) or is_bulk_registrant(prev):
                            continue
                    elif prev > args.max_prevalence:
                        continue
                peers.setdefault(e["src"], set()).add(f"{e['rel']}:{e['dst']}")
        peers = {d: v for d, v in peers.items() if v}     # drop peers left with no (strong) link
        tag = " (strong links only — boilerplate excluded)" if args.strong else ""
        print(f"\n# Domains sharing an indicator with {target}{tag}\n")
        for dom, via in sorted(peers.items(), key=lambda x: -len(x[1])):
            print(f"  {dom}   via {len(via)} shared: {', '.join(sorted(via)[:4])}{' …' if len(via) > 4 else ''}")

    if args.components:
        comps = _components(kb, args.kb, args.max_prevalence, restrict)
        print(f"# Connected components (strong) — {len(comps)} component(s)\n")
        for i, doms in enumerate(comps, 1):
            print(f"COMPONENT {i}\t{', '.join(sorted(doms))}")


def _components(kb, kb_dir, max_prevalence, restrict, noise_ips=frozenset()):
    """Union-find over domains that share a STRONG indicator (drop boilerplate rels, reference-
    benign values, and indicators shared by > max_prevalence domains). `restrict` limits clustering
    to a domain set (a case); domains in it with no strong edge come back as singletons.
    `noise_ips`: IPs the CASE's own collection showed to be shared/bulk hosting or CDN edges — a
    `hosted_on` edge to one is co-tenancy, never a binder, even when the KB itself has only seen two
    tenants there (the collector saw the IP answer with 2,500)."""
    NOISE_RELS = BOILERPLATE_RELS
    noise_ips = {f"ip:{ip}" for ip in (noise_ips or ())}
    prevalence: dict = {}
    for e in kb.edges():
        if e["src_type"] == "domain":
            prevalence.setdefault((e["dst_type"], e["dst"]), set()).add(e["src"])
    try:
        from reference import benign_values
        benign = benign_values(kb_dir)
    except Exception:  # noqa: BLE001
        benign = set()
    ind_domains: dict = {}
    for e in kb.edges():
        if e["src_type"] != "domain" or e["rel"] in NOISE_RELS or e["dst"] in benign:
            continue
        if e["rel"] == "hosted_on" and e["dst"] in noise_ips:
            continue                              # landlord IP — co-tenancy is not ownership
        is_reg = e["rel"] in REGISTRANT_RELS
        prev = len(prevalence.get((e["dst_type"], e["dst"]), ()))
        if is_reg:
            if is_registrant_noise(e["dst_type"], e["dst"]) or is_bulk_registrant(prev):
                continue                          # placeholder/privacy or bulk-reseller registrant
        elif prev > max_prevalence:
            continue
        if restrict is not None and e["src"] not in restrict:
            continue
        ind_domains.setdefault((e["dst_type"], e["dst"]), set()).add(e["src"])
    parent: dict = {}

    def find(x):
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    seen = set()
    for doms in ind_domains.values():
        dl = sorted(doms)
        for d in dl:
            seen.add(d)
            find(d)
        for d in dl[1:]:
            parent[find(dl[0])] = find(d)
    for d in (restrict or set()):
        seen.add(d)
        find(d)
    comps: dict = {}
    for d in seen:
        comps.setdefault(find(d), set()).add(d)
    return sorted(comps.values(), key=lambda s: (-len(s), sorted(s)[0]))


if __name__ == "__main__":
    main()
