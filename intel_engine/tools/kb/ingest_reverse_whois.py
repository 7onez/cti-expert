#!/usr/bin/env python3
"""
ingest_reverse_whois.py — fold a reverse-WHOIS result into the KB, WITH a bulk-registrant
guard so a shared reseller/agency email doesn't blow up the graph.

Tradecraft encoded (IntelAnalysis §1-2): a registrant term tied to a handful of
thematically-consistent domains is attribution-grade (same operator). A term tied to
hundreds/thousands of unrelated domains is a shared registration service — NOISE — and
must not become an operator hub. This tool refuses to ingest above --max-domains and
reports the decision instead of silently linking.

Previews the count first (cheap, no purchase credits); only purchases + links the domain list
when the term is under --max-domains, so a bulk/noise term never costs a full pull.

Usage:
  python3 ingest_reverse_whois.py --kb knowledge --email registrant@example.com
  python3 ingest_reverse_whois.py --kb knowledge --name "Registrant Name" --max-domains 150
  python3 ingest_reverse_whois.py --kb knowledge --phone "+15551234567"
"""
import os
import sys
import argparse
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "..", "WebPivot", "tools"))
from knowledge_base import KB  # noqa: E402
from noise_filters import (is_noise_phone, is_noise_email,  # noqa: E402
                           BULK_REGISTRANT_MAX_DOMAINS)
import whois_enrich  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description="Ingest a reverse-WHOIS result with a bulk-registrant guard.")
    ap.add_argument("--kb", required=True)
    ap.add_argument("--email")
    ap.add_argument("--name")
    ap.add_argument("--phone", help="reverse-WHOIS by registrant phone (bulk = registrar noise)")
    ap.add_argument("--person", help="person label to attach to the email (optional)")
    ap.add_argument("--search-type", choices=["current", "historic"], default="historic")
    ap.add_argument("--max-domains", type=int, default=BULK_REGISTRANT_MAX_DOMAINS,
                    help="above this, treat the term as a shared registrar/reseller (noise) and DO NOT link")
    args = ap.parse_args()
    if not (args.email or args.name or args.phone):
        ap.error("give --email, --name, or --phone")

    term = args.email or args.name or args.phone
    kind = "email" if args.email else ("name" if args.name else "phone")
    etype = {"email": "email", "name": "person", "phone": "phone"}[kind]
    term_key = term.lower() if kind == "email" else term

    # DENYLIST GATE — before spending a preview call. A privacy-proxy/registrar phone or a
    # registrar role email is published across every domain that provider fronts, so linking it
    # would merge thousands of unrelated domains into one bogus operator hub. The bulk-count
    # guard below would often catch it too, but not always (a proxy fronting < --max-domains
    # still isn't a registrant), and this costs nothing.
    if (kind == "phone" and is_noise_phone(term)) or (kind == "email" and is_noise_email(term)):
        print(f"  ⚠ DENYLIST: {kind} '{term}' is a registrar/privacy-proxy or malformed contact.")
        print("  It is shared by every domain at that provider = NOISE, not a registrant.")
        print("  NOT previewing, purchasing or linking.")
        kb = KB(args.kb)
        observed = datetime.now(timezone.utc).isoformat()
        kb.add_fact(etype, term_key, "denylisted_contact",
                    {"verdict": "registrar/privacy-proxy or malformed", "kind": kind},
                    "noise_filters", "reverse_whois", observed, "high")
        return

    # PREVIEW first (cheap count only) so a bulk/noise term never costs a full purchase.
    prev = whois_enrich.reverse_whois(term, kind, search_type=args.search_type, mode="preview")
    if prev is None:
        print("no WHOISXML_API_KEY set — cannot run.", file=sys.stderr); sys.exit(2)
    if prev.get("error"):
        print(f"reverse-whois error: {prev['error']}", file=sys.stderr); sys.exit(1)
    count = prev.get("count", 0)
    print(f"reverse-whois {kind} '{term}' ({args.search_type}): {count} domains (preview)")

    if count > args.max_domains:
        print(f"  ⚠ GUARD TRIPPED: {count} > --max-domains {args.max_domains}.")
        print("  Treating as a shared registration service (reseller/agency/registrar) = NOISE.")
        print("  NOT purchasing or linking. Re-run with a higher --max-domains to override.")
        # record the decision as an attributed fact on the term itself, for audit
        kb = KB(args.kb)
        observed = datetime.now(timezone.utc).isoformat()
        kb.add_fact(etype, term_key, "bulk_registrant",
                    {"domain_count": count, "verdict": "shared-service/noise",
                     "search_type": args.search_type},
                    "whoisxml", "reverse_whois", observed, "high")
        return
    if count == 0:
        print("  0 domains — nothing to link.")
        return

    # under threshold → PURCHASE the domain list and link
    r = whois_enrich.reverse_whois(term, kind, search_type=args.search_type, mode="purchase")
    if r is None or r.get("error"):
        print(f"reverse-whois purchase error: {(r or {}).get('error')}", file=sys.stderr); sys.exit(1)
    domains = r.get("domains", [])
    kb = KB(args.kb)
    observed = datetime.now(timezone.utc).isoformat()
    ev = kb.save_evidence("whoisxml_reverse", term, r, observed[:10])
    n = 0
    for d in domains:
        if not d:
            continue
        kb.add_edge("domain", d, "registered_by", etype, term_key,
                    "whoisxml", "reverse_whois", observed, "medium", ev)
        n += 1
    if args.person and args.email:
        kb.add_edge("email", args.email.lower(), "identity_of", "person", args.person,
                    "whoisxml", "reverse_whois", observed, "medium", ev)
    print(f"  linked {n} domains -> {kind}:{term}  (attribution-grade cluster)")


if __name__ == "__main__":
    main()
