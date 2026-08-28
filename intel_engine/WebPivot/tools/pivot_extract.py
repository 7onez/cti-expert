#!/usr/bin/env python3
"""
pivot_extract.py — WebPivot harness for OSINT / cybercrime investigation.

Extracts *pivot artifacts* from a web page's HTML/DOM — the fingerprints that
link one site to other sites, infrastructure, or actors — and emits ready-to-run
pivot queries (Shodan, PublicWWW, crt.sh, urlscan, etc.).

Design goals:
  * Zero required dependencies. Core runs on the Python 3 stdlib alone.
  * Graceful acceleration: uses `requests` if present, `playwright` for a
    rendered (post-JS) DOM with --render, `bs4` is NOT required.
  * Favicon mmh3 (Shodan-style) hash is computed with a bundled pure-Python
    MurmurHash3, so it works with no pip installs.
  * Optional same-site crawl (--crawl) follows navigation/tab/panel links and
    merges their artifacts; per-request User-Agent rotation (--rotate-ua) and an
    optional rotating proxy pool (--proxy / --proxy-range) keep the walk low-profile.
  * Follows redirects and surfaces the chain + any affiliate/referral/campaign codes
    (affid/ref/partner/utm_*, base64-decoded) as first-class pivots — built for
    tracker/shortlink analysis. A full browser header profile is sent so basic bot
    filters don't reset the fetch; platform boilerplate (Wix/Shopify defaults) is
    filtered so it doesn't create false same-operator clusters.

Usage:
  python3 pivot_extract.py <url|file> [--render] [--leads] [--pretty] [-o out.json]
  python3 pivot_extract.py https://example.com
  python3 pivot_extract.py page.html --leads          # just pivot suggestions
  cat page.html | python3 pivot_extract.py -           # read HTML from stdin

  # Crawl the site's navigation/tabs/panels (same registrable domain) and merge artifacts:
  python3 pivot_extract.py https://example.com --crawl 15 --crawl-depth 2 --leads

  # Rotate the User-Agent per request, and route through a rotating proxy pool:
  python3 pivot_extract.py https://example.com --crawl --rotate-ua \
      --proxy-range 10.0.0.1-10.0.0.9:8080          # (or a comma list, or a file)
  python3 pivot_extract.py https://example.com --proxy http://user:pass@host:3128

Output: JSON to stdout (default) with `artifacts`, `pivots`, and `meta`.
When crawling, `meta.crawled` lists the pages actually fetched.

FOR AUTHORIZED INVESTIGATIONS ONLY. Fetches the target directly — use a
research VPS / non-attributable egress (or --proxy / --proxy-range) when
investigating hostile infra.
"""

# NOTE: implementation lives in sibling wp_*.py modules; this file is the CLI entrypoint
# and a backward-compatible re-export facade (external code imports names from here).
import sys
import os
import re
import json
import base64
import hashlib
import argparse
import collections
import functools
import gzip
import itertools
import zlib
import socket
import ssl
import datetime
import shutil
import subprocess
import concurrent.futures
from urllib.parse import urljoin, urlparse, urlencode, quote, parse_qsl, unquote
# ------------------------------------------------------------------ optional deps
try:
    import requests  # noqa
    HAVE_REQUESTS = True
except Exception:
    HAVE_REQUESTS = False

import urllib.request
import urllib.error
from wp_common import *  # noqa
from wp_hash import *  # noqa
from wp_net import *  # noqa
from wp_recon import *  # noqa
from wp_extract import *  # noqa
from wp_pivots import *  # noqa
from wp_analyze import *  # noqa
from wp_crawl import *  # noqa
import wp_extract  # noqa  (for the QR toggle set in main)
import wp_assets   # noqa  (asset layer: JS bundles / source maps / well-known files toggles)
from wp_assets import *  # noqa
import wp_docmeta  # noqa  (document/image metadata layer: hosted PDFs + images → /Info, XMP, EXIF)
import wp_censys   # noqa  (Censys Platform: lookups + CenQL builder; --no-censys flips ENABLED)
import wp_hunterhow  # noqa  (Hunter.how reverse search; --no-hunterhow flips ENABLED)
import wp_validin  # noqa  (Validin infra-pivot: passive DNS/subdomains/reverse-IP/hash reverse; --no-validin off-switch)
import wp_securitytrails  # noqa  (SecurityTrails subdomains/DNS history; --no-securitytrails off-switch)
import wp_dnslytics  # noqa  (DNSLytics reverse GA/AdSense -> siblings; --no-dnslytics off-switch)
import wp_quake    # noqa  (Quake/360 favicon-hash reverse -> hosts; --no-quake off-switch)
import wp_zoomeye  # noqa  (ZoomEye favicon-hash reverse -> hosts; --no-zoomeye off-switch)
import wp_pssl     # noqa  (CIRCL passive SSL: historical cert->IP, i.e. origin behind a CDN)
import wp_intelx   # noqa  (Intelligence X: leak/paste/darknet selector search; --intelx runs it live)
import wp_exhaust  # noqa  (collection-exhaustion checklist: which evidence layers never ran)
import wp_capabilities  # noqa  (which keys are present -> what this run could and could not query)
import wp_paths    # noqa  (URL PATH as a campaign identifier — kit directory, template, patterns)
import wp_serp     # noqa  (advertising: Ads Transparency advertiser + the click-keyed cloaking probe)
import wp_capture  # noqa  (raw evidence bundle: the DOM + every JS/CSS the host served, hashed)
import wp_ippivot  # noqa  (IPPivot: bare-IP source runs passive IP recon instead of HTML)
import wp_impersonate  # noqa  (ImpersonationHunt: --hunt-impersonation hunts lookalikes of a seed)
import wp_email    # noqa  (.eml input: parse a victim's saved email into HTML body + header selectors)
try:
    import api_usage  # licensed-API credit ledger (per-run summary + JSONL)
except Exception:
    api_usage = None
from wp_analyze import _is_distinctive_basename, _resource_filename_for  # noqa: kept for external tests


def _emit_result(result, args, src):
    """Shared output path for a finished result (domain OR IP): master ledger, ICD-203 report,
    MISP bundle, and the JSON / --leads stdout. Kept identical across both modes so IP and domain
    evidence land in one case with one schema."""
    # Which indexes this run could actually query is a property of the EVIDENCE, not of the
    # terminal session — it has to travel with the file, or a keyless run's empty cluster reads
    # months later as "the operator had no siblings". One place, all three modes.
    result.setdefault("meta", {})["capability"] = wp_capabilities.capability_meta(
        free_only=bool(getattr(args, "free_only", False)))
    if args.report is not None or args.master is not None or args.misp is not None:
        import evidence_report

    # --- append this run's pivots to the master evidence ledger (for evidence folders) ---
    if args.master is not None:
        # Bare --master + --case → drop the ledger into that case's evidence folder,
        # matching the project's cases/<case>/… convention. An explicit path is honored.
        master_path = args.master
        if args.case and master_path == "evidence/master_pivots.csv":
            master_path = os.path.join("cases", args.case, "evidence", "master_pivots.csv")
        try:
            summ = evidence_report.append_master(
                result, path=master_path, case=args.case, source_file=args.out or src)
            tgt = summ.get("xlsx") or summ["csv"]
            print(f"[+] master ledger: {tgt} "
                  f"(+{summ['rows_added']} new, {summ['rows_updated']} updated, "
                  f"{summ['rows_total']} total rows)", file=sys.stderr)
            if summ["xlsx_requested"] and not summ["xlsx_written"]:
                print("    (xlsx skipped: openpyxl not installed — wrote CSV instead: "
                      f"{summ['csv']})", file=sys.stderr)
        except Exception as e:
            print(f"[!] master ledger failed: {e}", file=sys.stderr)

    # --- finished-intelligence assessment (CIA analytic tradecraft) ---
    # A bare --report (const True) prints to stdout; --report PATH writes a file.
    report_md, print_report = None, (args.report is True)
    if args.report is not None:
        try:
            report_md = evidence_report.render_cia_report(
                result, case=args.case, classification=args.classification,
                analyst=args.analyst)
            if isinstance(args.report, str):
                with open(args.report, "w", encoding="utf-8") as f:
                    f.write(report_md)
                print(f"[+] wrote intelligence assessment -> {args.report}", file=sys.stderr)
        except Exception as e:
            print(f"[!] report generation failed: {e}", file=sys.stderr)
            print_report = False

    # --- MISP IOC bundle (shareable) ---
    if args.misp is not None:
        misp_path = (args.misp if isinstance(args.misp, str)
                     else (re.sub(r"\.json$", "", args.out) + ".misp.json" if args.out
                           else (result["meta"].get("host") or "iocs") + ".misp.json"))
        try:
            event = evidence_report.render_misp_event(
                result, event_info=(f"WebPivot IOCs — {args.case}" if args.case
                                    else f"WebPivot IOCs — {result['meta'].get('host','')}"))
            with open(misp_path, "w", encoding="utf-8") as f:
                json.dump(event, f, indent=2, ensure_ascii=False)
            result.setdefault("archives", {})["misp"] = misp_path
            print(f"[+] wrote MISP IOC bundle ({len(event['Event']['Attribute'])} attributes) "
                  f"-> {misp_path}", file=sys.stderr)
        except Exception as e:
            print(f"[!] MISP export failed: {e}", file=sys.stderr)

    # Persist the JSON whenever -o is given — independent of --leads. (--leads used to return
    # before this, silently dropping the -o file.)
    out = None
    if args.out or not (args.leads or print_report):
        out = json.dumps(result, indent=2 if args.pretty else None, ensure_ascii=False)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(out)
        print(f"wrote {args.out} ({len(result['pivots'])} pivots)", file=sys.stderr)

    if print_report:
        print(report_md)
    elif args.leads:
        print(render_leads(result))
    elif not args.out:
        print(out)

    if api_usage:                     # per-run licensed-API credit summary (also logged to JSONL)
        api_usage.print_session_summary()
    _cb = wp_censys.budget_status()   # the tightest quota in the toolkit — always show the balance
    if _cb["spent_this_run"]:
        print(f"  censys     {_cb['remaining_this_month']}/{_cb['monthly_credits']} credits left "
              f"for {_cb['month']} (no rollover)", file=sys.stderr)
    _ib = wp_intelx.budget_status()
    if _ib["spent_this_run"]:
        print(f"  intelx     {_ib['remaining_this_month']}/{_ib['monthly_searches']} search "
              f"unit(s) left for {_ib['month']}", file=sys.stderr)

    # --- EXHAUSTION: which evidence layers never ran on this seed -------------------------------
    # Printed last, next to the credit summary, because it answers the other half of "what did
    # this run cost": what it did NOT search. The opt-in layers (leak corpus, advertising,
    # lookalikes, document metadata) are the ones a run silently skips, and a correlation pass
    # over a triage-depth collection reports "nothing further found" as though it had looked.
    # Never fatal: a broken checklist must not take a collection down with it.
    try:
        for _line in wp_exhaust.banner_lines(result):
            print(_line, file=sys.stderr)
    except Exception as _exc:                                   # noqa: BLE001
        print(f"[!] exhaustion check unavailable ({_exc})", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser(description="WebPivot — extract OSINT pivot artifacts from a page.")
    ap.add_argument("source", nargs="?", default=None,
                    help="URL, IP address, local HTML file, or '-' for stdin (optional for "
                         "standalone actions like --validin-bulk)")
    ap.add_argument("--render", action="store_true", help="render post-JS DOM via Playwright")
    ap.add_argument("--leads", action="store_true", help="print ranked pivot leads (markdown) instead of JSON")
    ap.add_argument("--pretty", action="store_true", help="pretty-print JSON")
    ap.add_argument("--ua", default=None,
                    help="fixed User-Agent string (overrides and disables rotation)")
    ap.add_argument("--rotate-ua", action="store_true",
                    help="rotate the User-Agent per request from a built-in browser pool")
    ap.add_argument("--proxy", default=None,
                    help="route requests through this proxy, e.g. http://user:pass@host:port "
                         "or socks5://host:port")
    ap.add_argument("--proxy-range", default=None, metavar="SPEC",
                    help="optional proxy pool to rotate through: a comma list, a file (one per "
                         "line), and/or a final-octet IP range like 10.0.0.1-10.0.0.9:8080")
    ap.add_argument("--crawl", nargs="?", type=int, const=10, default=None, metavar="MAXPAGES",
                    help="also crawl the site's navigation/tabs/panels (same registrable domain) "
                         "and merge their artifacts. Bare flag → up to 10 pages; give a number to change.")
    ap.add_argument("--crawl-depth", type=int, default=1,
                    help="how many link-hops deep to crawl from the seed page (default 1)")
    ap.add_argument("--timeout", type=int, default=20)
    ap.add_argument("--solve-cf", action="store_true",
                    help="on a Cloudflare challenge, ESCALATE to solve it: use FlareSolverr if "
                         "configured (--flaresolverr / $FLARESOLVERR_URL), else a Playwright "
                         "browser render. Authorized OSINT only; prefer a residential --proxy.")
    ap.add_argument("--flaresolverr", default=None, metavar="URL",
                    help="FlareSolverr endpoint (e.g. http://localhost:8191) used by --solve-cf "
                         "to run the Cloudflare challenge in a real browser. Env: FLARESOLVERR_URL.")
    ap.add_argument("--archive-missing", action="store_true",
                    help="if the target is NOT yet in the Wayback Machine, submit it via Save-Page-Now "
                         "so a snapshot exists to pivot on (then retry the archived copy).")
    ap.add_argument("--no-fallback", action="store_true",
                    help="do NOT fall back to Wayback + urlscan when the live fetch fails")
    ap.add_argument("--no-enrich", action="store_true",
                    help="do NOT run live enrichment (keyless crt.sh/passive-DNS/urlscan on the "
                         "domain, plus FOFA/urlscan when keys are configured)")
    ap.add_argument("--free-only", action="store_true",
                    help="enrich with FREE/keyless sources only (crt.sh, HackerTarget passive DNS, "
                         "anonymous urlscan search, live DNS, keyless RDAP WHOIS) — skip every "
                         "METERED call (FOFA, CIRCL pDNS, urlscan-Pro similarity, WhoisXML, Censys). "
                         "Used by the autonomous convergence loop so it never spends credits "
                         "without approval.")
    ap.add_argument("--no-censys", action="store_true",
                    help="do NOT call the Censys Platform API even if CENSYS_PAT is set. Censys "
                         "bills in CREDITS (1 per lookup; a FREE account gets 100/month that do "
                         "not roll over), so this is the switch for conserving them. The Censys "
                         "CenQL queries are still emitted on every pivot — they are built offline "
                         "and cost nothing.")
    ap.add_argument("--no-hunterhow", action="store_true",
                    help="do NOT call the Hunter.how API even if HUNTERHOW_API_KEY is set. "
                         "Hunter.how is metered and query-rate-limited (a free account has a small "
                         "quota), so this is the switch for conserving it. The Hunter.how query is "
                         "still emitted on every reversible pivot — built offline, costing nothing.")
    ap.add_argument("--no-validin", action="store_true",
                    help="do NOT call the Validin API even if VALIDIN_API_KEY is set. Validin is "
                         "FREE-keyed but quota-limited (Community 10/day); wp_validin caps calls "
                         "per domain so a run never empties the key. The Validin query string is "
                         "still emitted on every reversible pivot — built offline, costing nothing.")
    ap.add_argument("--validin-bulk", metavar="FILE", default=None,
                    help="OPT-IN batch verdicts: POST the indicators in FILE (one per line) to "
                         "Validin bulk/osint/context and print the JSON. Bulk is Professional+ — on "
                         "a Community/keyless key it degrades to a capability-gap note, never an "
                         "error. Standalone action: does not fetch the page target.")
    ap.add_argument("--no-securitytrails", action="store_true",
                    help="do NOT call the SecurityTrails API even if SECURITYTRAILS_API_KEY is set "
                         "(freemium 50/month; metered).")
    ap.add_argument("--no-dnslytics", action="store_true",
                    help="do NOT call the DNSLytics API even if DNSLYTICS_API_KEY is set "
                         "(credit-metered; reverse GA/AdSense -> sibling domains).")
    ap.add_argument("--no-quake", action="store_true",
                    help="do NOT call the Quake (360) API even if QUAKE_API_KEY is set "
                         "(point-metered; favicon-hash reverse -> co-branded hosts).")
    ap.add_argument("--no-zoomeye", action="store_true",
                    help="do NOT call the ZoomEye API even if ZOOMEYE_API_KEY is set "
                         "(quota-metered; favicon-hash reverse -> co-branded hosts).")
    ap.add_argument("--no-pssl", action="store_true",
                    help="do NOT query CIRCL passive SSL even when the CIRCL credentials "
                         "(PDNS_USERNAME/PDNS_PASSWORD) are set. Passive SSL is the historical "
                         "certificate->IP direction — the one that recovers an ORIGIN from behind "
                         "a CDN — and rides the same free account as passive DNS, so this switch "
                         "is for a minimal footprint or a rate-limit, not for cost.")
    ap.add_argument("--intelx", action="store_true",
                    help="RUN Intelligence X live on this result's selectors — emails, phones, "
                         "wallets, the host itself — searching leaks, stealer logs, pastes, "
                         "darknet mirrors and historical WHOIS, plus a phonebook inventory of the "
                         "apex (emails/subdomains/URLs). METERED: bounded by the per-run cap in "
                         "references/intelx.json and skipped under --free-only. Without this flag "
                         "(or without INTELX_KEY) every pivot still carries its IntelX selector "
                         "and web-UI URL — built offline, costing nothing.")
    ap.add_argument("--serp", action="store_true",
                    help="RUN the Google Ads Transparency Center live on this domain via SerpApi: "
                         "who ADVERTISES it (a Google-VERIFIED, paying advertiser account and the "
                         "legal name it is funded by), every OTHER domain that account advertised, "
                         "and the ad creative's destination link — which is where the operator's "
                         "own utm/gclid campaign tagging is published, i.e. the key that unlocks a "
                         "cloaked landing page. METERED (1 SerpApi search per call, capped in "
                         "references/serpapi.json) and skipped under --free-only. Without this flag "
                         "the layer still classifies every ad parameter and emits the free "
                         "adstransparency.google.com address for the domain.")
    ap.add_argument("--serp-region", default=None, metavar="CODE",
                    help="which market to query the ad archive for: an ISO-2 code (VN, US, GB) or a "
                         "numeric Google geotarget. The archive is queried PER REGION, so a domain "
                         "that advertises only in its victims' country returns nothing from the "
                         "default 'anywhere'. Codes: WebPivot/references/serpapi.json.")
    ap.add_argument("--ad-params", default=None, metavar="SPEC",
                    help="the ad's OWN click parameters, as a full landing URL or 'k=v&k=v' — from "
                         "the ad creative, a victim's browser history, or a stealer log. Used to "
                         "fetch the page as the campaign's audience sees it. Many fraud landing "
                         "pages serve their real content ONLY to an arrival that carries the "
                         "correct utm/gclid set and show everyone else a decoy; without these the "
                         "run collects the decoy and reports it as the site.")
    ap.add_argument("--cloak-probe", dest="cloak_probe", action="store_true", default=None,
                    help="force the CLICK-KEYED CLOAKING probe: fetch the page as a plain visitor, "
                         "again as a paid ad click (ad parameters + a Google referrer), and once "
                         "more as a plain visitor as a control, then compare. FREE — no API credit, "
                         "three requests to the target. By default it runs automatically whenever "
                         "there is advertising evidence (an AW- conversion id, an ads.txt, or ad "
                         "parameters on the URL) and is skipped otherwise.")
    ap.add_argument("--no-cloak-probe", dest="cloak_probe", action="store_false",
                    help="never run the cloaking probe, even with advertising evidence present "
                         "(saves two extra requests to the target)")
    ap.add_argument("--no-intelx-phonebook", action="store_true",
                    help="with --intelx, skip the phonebook inventory of the apex (it is the "
                         "expensive call and needs a PAID entitlement)")
    ap.add_argument("--fofa-full", action="store_true",
                    help="run FOFA reverses over ALL historical data (full=true) instead of the "
                         "default ~1-year window — catches favicon/tracker assets later scrubbed. "
                         "Needs a FOFA tier that permits full/historical search.")
    ap.add_argument("--fofa-keyword", action="append", default=None, metavar="STR",
                    help="high-value HTML string/phrase (from IntelAnalysis) to reverse via FOFA "
                         "body=\"...\" — repeatable; each becomes a HIGH keyword pivot and, with a "
                         "FOFA key, is searched live. The IntelAnalysis → WebPivot HTML-search chain.")
    ap.add_argument("--no-whois", action="store_true",
                    help="do NOT run WhoisXML enrichment even if WHOISXML_API_KEY is set")
    # cti-expert: reverse-WHOIS runs by DEFAULT here (registrant name/email are the highest-value
    # same-operator artifacts and the deterministic pipeline never passes an opt-in flag). Keep
    # --whois-reverse for upstream compatibility; --no-whois-reverse is the opt-out, and
    # --free-only still suppresses the spend.
    ap.add_argument("--no-whois-reverse", action="store_true",
                    help="skip reverse-WHOIS (it is ON by default; costs WhoisXML DRS credits)")
    ap.add_argument("--whois-reverse", action="store_true",
                    help="run reverse-WHOIS live on registrant emails (costs WhoisXML credits)")
    ap.add_argument("--whois-history-mode", choices=["preview", "purchase"], default="purchase",
                    help="WHOIS history: preview (count only) or purchase (full records)")
    ap.add_argument("-o", "--out", help="write JSON to file")
    ap.add_argument("--save-dom", nargs="?", const=True, default=None, metavar="PATH",
                    help="store the raw fetched/rendered DOM to disk. Bare flag → alongside "
                         "--out (<out>.html) or <host>.dom.html; or give an explicit PATH.")
    ap.add_argument("--screenshot", nargs="?", const=True, default=None, metavar="PATH",
                    help="save a full-page PNG of the rendered target (implies --render; "
                         "evidentiary capture). Bare flag → <out>.png / <host>.png, or give a PATH.")
    ap.add_argument("--misp", nargs="?", const=True, default=None, metavar="PATH",
                    help="also write a MISP-event IOC bundle (JSON) of the extracted artifacts "
                         "for sharing/import. Bare flag → <out>.misp.json or <host>.misp.json.")
    ap.add_argument("--submit", action="store_true",
                    help="actively archive the URL: submit to Wayback Save-Page-Now AND urlscan.io "
                         "(needs URLSCAN_API_KEY for the scan). Archives attached to result.archives.")
    ap.add_argument("--deep-archive", action="store_true",
                    help="EXHAUSTIVE archival pass (domain targets): full Wayback history across the "
                         "whole domain (subdomains+subpaths, HTML+JS/JSON), EVERY distinct urlscan "
                         "cached DOM (paginated, de-duped), CommonCrawl stored bodies, and "
                         "archive.today mementos — merged with first/last-seen. Passive & keyless; "
                         "recovers historical/scrubbed/taken-down selectors a single capture misses.")
    ap.add_argument("--deep-root-only", action="store_true",
                    help="with --deep-archive: legacy exact-apex Wayback scan (no subdomains/subpaths)")
    ap.add_argument("--deep-no-commoncrawl", action="store_true",
                    help="with --deep-archive: skip the CommonCrawl corpus")
    ap.add_argument("--deep-no-archive-today", action="store_true",
                    help="with --deep-archive: skip the archive.today corpus")
    ap.add_argument("--report", nargs="?", const=True, default=None, metavar="PATH",
                    help="render a finished-intelligence assessment in CIA analytic-tradecraft "
                         "style (ICD 203: BLUF, Key Judgments, estimative language, confidence). "
                         "Bare flag → print to stdout; give a PATH to write the Markdown.")
    ap.add_argument("--master", nargs="?", const="evidence/master_pivots.csv", default=None,
                    metavar="PATH",
                    help="append every pivot from this run to a master evidence ledger for "
                         "export into evidence folders (dedupes on host+kind+value, never loses "
                         "rows). Bare flag → evidence/master_pivots.csv; .xlsx path → Excel "
                         "(needs openpyxl) plus a sibling .csv.")
    ap.add_argument("--case", default=None,
                    help="case name tagged onto the report and every master-ledger row")
    ap.add_argument("--capture", dest="capture", action="store_true", default=None,
                    help="store the RAW EVIDENCE bundle — the served DOM plus every JavaScript and "
                         "stylesheet the page loaded, each with its own sha256 and a bundle-level "
                         "capture_sha256 — under cases/<case>/evidence/captures/<host>/<kit>/<UTC>/. "
                         "DEFAULT ON whenever --case is given: derived artifacts (hashes, "
                         "fingerprints) are assertions about a page that will be gone in days, and "
                         "the capture is the only thing that lets anyone re-check them later.")
    ap.add_argument("--no-capture", dest="capture", action="store_false",
                    help="do NOT store the raw evidence bundle, even with --case")
    ap.add_argument("--no-capture-third-party", dest="capture_third_party",
                    action="store_false", default=True,
                    help="record third-party asset URLs in the capture manifest but do not download "
                         "them (they describe the library, not the operator). Same-site JS/CSS is "
                         "always captured.")
    ap.add_argument("--classification", default="UNCLASSIFIED//FOR OFFICIAL USE ONLY",
                    help="classification banner printed at the top and bottom of the report")
    ap.add_argument("--analyst", default=None,
                    help="accepted for backward compat but IGNORED — the analyst name is never "
                         "stamped on a deliverable (opsec / attribution leak)")
    ap.add_argument("--hunt-impersonation", action="store_true",
                    help="ImpersonationHunt mode: from a bare seed DOMAIN, hunt typosquat / TLD-sweep "
                         "/ keyword lookalikes (crt.sh + live DNS, free) instead of analyzing the page")
    ap.add_argument("--hunt-fofa", action="store_true",
                    help="with --hunt-impersonation: also run the FOFA cert= keyword sweep (metered)")
    ap.add_argument("--hunt-urlscan", action="store_true",
                    help="with --hunt-impersonation: also run the urlscan keyword sweep (metered)")
    ap.add_argument("--hunt-max", type=int, default=600, metavar="N",
                    help="with --hunt-impersonation: cap on generated candidates (default 600)")
    ap.add_argument("--no-docmeta", action="store_true",
                    help="skip the DOCUMENT/IMAGE metadata layer (hosted PDFs + images are "
                         "downloaded and read for /Info, XMP and EXIF — author, XMP DocumentID, "
                         "camera, GPS, editing software). On by default; it costs extra requests "
                         "TO THE TARGET, so turn it off for a minimal footprint.")
    ap.add_argument("--docmeta-max", type=int, default=None, metavar="N",
                    help=f"cap how many hosted files are downloaded for metadata "
                         f"(default {wp_docmeta.BUDGET.get('max_files')}; documents are always "
                         f"tried before images). Per-file and per-run byte caps live in "
                         f"references/docmeta.json.")
    ap.add_argument("--no-assets", action="store_true",
                    help="do NOT fetch the page's own JS bundles or their source maps. Default is "
                         "ON: on an SPA kit the shell HTML is empty and the operator's config "
                         "(backend API, build tenant/brand, Sentry DSN) lives only in the bundle, "
                         "and the .js.map leaks the developer's machine paths. A real browser "
                         "fetches these files anyway, so collecting them adds no anomalous traffic.")
    ap.add_argument("--no-well-known", action="store_true",
                    help="do NOT probe the published policy files (robots.txt, sitemap.xml, "
                         "ads.txt, app-ads.txt, security.txt, humans.txt, "
                         "apple-app-site-association). Default is ON — 7 tiny GETs on standard, "
                         "crawler-expected paths. ads.txt yields the AdSense pub- publisher id, "
                         "an owner-tied token as strong as a GA4 property. This is a FIXED list "
                         "of standards, never a wordlist — it does not brute-force paths.")
    ap.add_argument("--assets-max", type=int, default=None, metavar="N",
                    help=f"cap on how many same-origin JS bundles to fetch "
                         f"(default {wp_assets.MAX_JS_FILES}; config/env-named files and hashed "
                         f"build artifacts are fetched first, known libraries are skipped)")
    ap.add_argument("--decode-qr", action="store_true",
                    help="decode QR-code IMAGES from pixels (fetches candidate <img>/data-URIs; "
                         "needs pyzbar+Pillow or OpenCV). The zero-dep decode of QR-generator-service "
                         "URLs (?data=/&chl=) always runs regardless of this flag.")
    args = ap.parse_args()
    if api_usage:            # tag every licensed-API call this run with the case + skill
        api_usage.set_context(case=args.case, skill="WebPivot")
    # State the run's capability BEFORE any collection, so the analyst reads the caveat with the
    # result rather than after acting on it. Silent when every key is present — see wp_capabilities.
    wp_capabilities.print_banner(free_only=args.free_only)
    if args.validin_bulk:
        # Standalone opt-in: batch-verdict a file of indicators. bulk_osint() self-gates on
        # permitted_paths() (Professional+) AND can_spend(), so on a Community/keyless key it
        # returns a skipped capability-gap note rather than an error or a wasted call.
        try:
            with open(args.validin_bulk, encoding="utf-8") as _fh:
                _inds = [ln.strip() for ln in _fh if ln.strip() and not ln.startswith("#")]
        except OSError as _e:
            print(json.dumps({"error": "cannot read --validin-bulk file: %s" % _e}), file=sys.stderr)
            return 2
        print(json.dumps({"validin_bulk": wp_validin.bulk_osint(_inds), "indicators": len(_inds)},
                         ensure_ascii=False, indent=2 if args.pretty else None))
        return 0
    if not args.source:
        ap.error("source is required (a URL, IP, file, or '-') unless a standalone action "
                 "like --validin-bulk is given")
    # The IntelX layer states its own capability separately: it is the only layer whose absence
    # removes an entire CORPUS (leaks, stealer logs, pastes, darknet) rather than an index of the
    # live internet, and a keyless run of it is explicitly ~50% — see wp_intelx.capability().
    for _line in wp_intelx.banner_lines(free_only=args.free_only):
        print(_line, file=sys.stderr)
    # The advertising layer discloses only when it was ASKED for. Its keyless half — the cloaking
    # probe, the part that decides which page gets collected — runs regardless and needs no caveat;
    # what a missing key costs is the advertiser's identity, and that only matters if we went looking.
    if args.serp:
        for _line in wp_serp.banner_lines(free_only=args.free_only):
            print(_line, file=sys.stderr)
    if args.screenshot is not None and not args.render:
        args.render = True   # a screenshot requires the rendered (Playwright) page
    wp_extract.QR_DECODE_IMAGES = bool(args.decode_qr)
    wp_censys.ENABLED = not args.no_censys   # offline CenQL builder is unaffected — it costs nothing
    wp_hunterhow.ENABLED = not args.no_hunterhow  # offline query builder unaffected — costs nothing
    wp_validin.ENABLED = not args.no_validin  # offline query-string path unaffected — costs nothing
    wp_securitytrails.ENABLED = not args.no_securitytrails  # offline path unaffected
    wp_dnslytics.ENABLED = not args.no_dnslytics            # offline path unaffected
    wp_quake.ENABLED = not args.no_quake                    # offline path unaffected
    wp_zoomeye.ENABLED = not args.no_zoomeye                # offline path unaffected
    wp_pssl.ENABLED = not args.no_pssl       # passive SSL: historical cert->IP (origin recovery)
    # Asset layer (JS bundles / source maps / well-known files) — on by default, per-half opt-out.
    wp_assets.COLLECT_ASSETS = not args.no_assets
    wp_assets.COLLECT_WELL_KNOWN = not args.no_well_known
    # Free/keyless, but it DOWNLOADS FILES FROM THE TARGET — so --free-only leaves it on
    # (it spends no credits) while --no-docmeta is the switch for a minimal footprint.
    wp_docmeta.COLLECT_DOCMETA = not args.no_docmeta
    if args.docmeta_max is not None:
        wp_docmeta.BUDGET["max_files"] = max(0, args.docmeta_max)
    if args.assets_max is not None:
        wp_assets.MAX_JS_FILES = max(0, args.assets_max)

    # --- resolve User-Agent + proxy rotation. Crawling auto-enables UA rotation so a
    #     multi-page walk isn't one identical fingerprint; an explicit --ua pins one UA. ---
    rotate_ua = args.rotate_ua or (args.crawl is not None and not args.ua)
    proxy_pool = parse_proxies(args.proxy_range)
    if args.proxy:
        proxy_pool = [args.proxy] + proxy_pool
    _ua_cycle = itertools.cycle(UA_POOL)
    _px_cycle = itertools.cycle(proxy_pool) if proxy_pool else None

    def next_ua():
        if args.ua:
            return args.ua
        return next(_ua_cycle) if rotate_ua else DEFAULT_UA

    def next_proxy():
        return next(_px_cycle) if _px_cycle else None

    if proxy_pool:
        print(f"[+] proxy pool: {len(proxy_pool)} endpoint(s), rotating per request",
              file=sys.stderr)

    src = args.source
    base_url, headers, cookies = "", {}, None
    html = ""
    email_art = None          # set on the .eml input branch: header/CDN selectors from a victim email
    live_error = None
    recovered_via = None
    cf_challenge = None       # set if the live target returned a Cloudflare interstitial
    snap_url = None           # closest existing Wayback snapshot (if any)
    wb_submitted = None       # result of an --archive-missing Save-Page-Now submission
    screenshot_file = None
    intel = None
    cloak_report = None       # click-keyed cloaking probe (wp_serp) — set on the URL branch
    redirects = []  # redirect hops from the seed fetch (URL branch only)
    seed_ua, seed_proxy = DEFAULT_UA, None  # only used on the URL branch; reset there

    # --- IPPivot: a bare IP source runs PASSIVE IP recon (IPinfo/FOFA/Shodan/dig), not HTML. ---
    ip_target = wp_ippivot.ip_mode_target(src)
    if ip_target:
        print(f"[+] IPPivot mode: passive recon on {ip_target} "
              f"(IPinfo · FOFA ip= · dig/nslookup"
              f"{' · Shodan' if _secret('SHODAN_KEY','SHODAN_API_KEY') else ''}"
              f"{' · Censys' if wp_censys.censys_configured() and not args.free_only else ''})",
              file=sys.stderr)
        result = wp_ippivot.build_ip_result(ip_target, args, fofa_full=args.fofa_full,
                                            free_only=args.free_only)
        if args.intelx:
            # An IP is a strong IntelX selector too — sightings in pastes/logs corroborate a
            # co-tenancy claim from a corpus none of the scan engines index. No phonebook: that
            # endpoint takes a domain.
            wp_intelx.enrich_result(result, do_phonebook=False, free_only=args.free_only)
        _emit_result(result, args, ip_target)
        return

    # --- ImpersonationHunt: --hunt-impersonation hunts LOOKALIKES of a seed domain, standalone. ---
    # Like IPPivot, it does NOT live-fetch the target: it takes a bare seed domain and generates
    # typosquat/TLD-sweep/keyword candidates, then validates them via crt.sh + live DNS (free) —
    # so the analyst's IP never touches the (hostile) lookalike infra.
    if args.hunt_impersonation:
        hunt_seed = strip_www(urlparse(src).netloc if "://" in src else src).split("/")[0]
        print(f"[+] ImpersonationHunt mode: hunting lookalikes of {hunt_seed} "
              f"(typosquat · TLD-sweep · crt.sh keyword · live DNS"
              f"{' · FOFA' if args.hunt_fofa else ''}{' · urlscan' if args.hunt_urlscan else ''})",
              file=sys.stderr)
        result = wp_impersonate.build_impersonation_result(
            hunt_seed, max_variants=args.hunt_max, fofa=args.hunt_fofa,
            urlscan=args.hunt_urlscan, case=args.case)
        _emit_result(result, args, hunt_seed)
        return

    if src == "-":
        html = sys.stdin.read()
    elif os.path.isfile(src):
        with open(src, "rb") as f:
            raw = f.read()
        if wp_email.is_eml(src, raw):
            # A victim's saved email: parse it to the HTML body (so every HTML-side extractor runs
            # over what the funnel actually sent) plus the header/CDN-derived selectors, which are
            # merged into the artifacts below so they emit pivots like any other artifact.
            html, email_art = wp_email.parse_eml(raw)
            print(f"[+] .eml input: parsed email body ({len(html)} bytes)"
                  f"{(' — sender ' + ', '.join(email_art['sender_domains'])) if email_art.get('sender_domains') else ''}",
                  file=sys.stderr)
        else:
            html = raw.decode("utf-8", "ignore")
    elif src.startswith(("http://", "https://")):
        seed_ua, seed_proxy = next_ua(), next_proxy()
        host_for_intel = strip_www(urlparse(src).netloc)
        # --- try the live target first ---
        try:
            if args.render:
                shot = None
                if args.screenshot is not None:
                    shot = (args.screenshot if isinstance(args.screenshot, str)
                            else (re.sub(r"\.json$", "", args.out) + ".png" if args.out
                                  else strip_www(urlparse(src).netloc) + ".png"))
                base_url, html, cookies = render_dom(src, timeout=args.timeout, ua=seed_ua,
                                                     proxy=seed_proxy, screenshot_path=shot)
                if shot and os.path.isfile(shot):
                    screenshot_file = shot
                    print(f"[+] saved screenshot -> {shot}", file=sys.stderr)
                try:
                    _, _, headers, _ = fetch(base_url, timeout=args.timeout, ua=seed_ua,
                                             proxy=seed_proxy)
                except Exception:
                    headers = {}
            else:
                base_url, status, headers, body = fetch(src, timeout=args.timeout, ua=seed_ua,
                                                        proxy=seed_proxy, redirects_out=redirects)
                html = body.decode("utf-8", "ignore")
                headers["_status"] = str(status)
                cf_challenge = detect_cloudflare_challenge(status, headers, html)
                if status >= 400 or len(html) < 200 or cf_challenge:
                    raise RuntimeError(f"HTTP {status}, {len(html)} bytes"
                                       + (f" [{cf_challenge}]" if cf_challenge else ""))
        except Exception as e:
            live_error = str(e)
            html = ""

        # --- Cloudflare escalation: try to SOLVE the live challenge before going passive ---
        # (weak→strong; a plain UA swap can't beat a managed challenge, a real browser can)
        if not html and cf_challenge and args.solve_cf:
            fs = args.flaresolverr or os.environ.get("FLARESOLVERR_URL")
            if fs:
                print(f"[*] cloudflare {cf_challenge}: solving via FlareSolverr {fs} …", file=sys.stderr)
                f_url, f_html, f_cookies = flaresolverr_get(src, fs, timeout=max(args.timeout, 60),
                                                            proxy=seed_proxy)
                if f_html and not detect_cloudflare_challenge(200, {}, f_html):
                    base_url, html, cookies = f_url, f_html, f_cookies
                    recovered_via, live_error = "flaresolverr", None
                    print("[+] cloudflare cleared via FlareSolverr", file=sys.stderr)
            if not html:
                try:
                    print("[*] cloudflare: retrying with a Playwright browser render …", file=sys.stderr)
                    b, h, c = render_dom(src, timeout=max(args.timeout, 45), ua=seed_ua, proxy=seed_proxy)
                    if h and not detect_cloudflare_challenge(200, {}, h):
                        base_url, html, cookies = b, h, c
                        recovered_via, live_error = "render_cf", None
                        print("[+] cloudflare cleared via browser render", file=sys.stderr)
                    else:
                        print("[!] still challenged after render — try a residential --proxy", file=sys.stderr)
                except ImportError:
                    print("[!] --solve-cf render needs Playwright (pip install playwright)", file=sys.stderr)
                except Exception as e:
                    print(f"[!] cf render failed: {e}", file=sys.stderr)
        # --- CLICK-KEYED CLOAKING: are we being shown the same page the victims are? ------------
        # This runs BEFORE extraction on purpose. A kit that buys traffic can gate on the arrival:
        # present the campaign's utm set and a gclid and it serves the scam; arrive without them —
        # directly, from a crawler, from Google's own reviewer — and it serves a decoy. Every
        # artifact below (favicon, DOM fingerprint, wallets, contacts) is taken from whatever `html`
        # holds, so if that is the decoy the run does not fail, it succeeds on the wrong page and
        # reports "no scam content" as a finding. When the probe says the two views diverge we
        # switch to the CLICK view and collect that instead. Free — no API credit, two extra
        # requests. Auto-triggered only where there is advertising evidence to justify them.
        if html and src.startswith(("http://", "https://")) and args.cloak_probe is not False:
            _adp = wp_serp.parse_ad_params(args.ad_params)
            _auto = bool(_adp or args.serp or wp_serp.ad_params(src)
                         or re.search(r"\bAW-\d{6,12}\b", html))
            if args.cloak_probe is True or _auto:
                probe_url = base_url or src
                print(f"[*] cloaking probe: fetching {strip_www(urlparse(probe_url).netloc)} as a "
                      f"plain visitor, as a paid ad click, and as a control …", file=sys.stderr)
                cloak_report = wp_serp.cloak_probe(
                    probe_url, extra_params=_adp, ua=seed_ua, proxy=seed_proxy,
                    timeout=args.timeout, keep_bodies=True)
                _bodies = cloak_report.pop("_bodies", {})
                if cloak_report.get("verdict") == "divergent" and _bodies.get("click"):
                    for _s in cloak_report.get("signals") or []:
                        print(f"    · {_s}", file=sys.stderr)
                    if args.render:
                        # The probe fetches raw HTML; `html` here is a Playwright-rendered DOM.
                        # Swapping would silently downgrade an SPA collection to its empty shell —
                        # worse than the decoy it is meant to fix. Hand the analyst the address and
                        # let them re-render it.
                        cloak_report["render_note"] = (
                            "collected with --render, so the rendered DOM was KEPT and the unlocked "
                            "page was not substituted (the probe reads raw HTML). Re-run: "
                            f"pivot_extract '{cloak_report['unlock_url']}' --render")
                        print(f"[!] CLOAKING DETECTED — but this run used --render, so the DOM was "
                              f"NOT swapped. Re-run on the unlocked page:\n"
                              f"    pivot_extract '{cloak_report['unlock_url']}' --render",
                              file=sys.stderr)
                    else:
                        # The plain view is the decoy. Re-point the whole collection at the page the
                        # campaign's audience actually lands on.
                        html = _bodies["click"]
                        base_url = cloak_report["unlock_url"]
                        cloak_report["collected_view"] = "click"
                        print(f"[!] CLOAKING DETECTED — this host serves paid-click traffic a "
                              f"different page. Collecting the CLICK view instead: {base_url}",
                              file=sys.stderr)
                else:
                    print(f"[+] cloaking probe: {cloak_report.get('verdict')}", file=sys.stderr)

        # --- if the live target is unreachable/blocked, go passive ---
        if not html and not args.no_fallback:
            print(f"[!] live fetch failed ({live_error}); falling back to Wayback + urlscan",
                  file=sys.stderr)
            snap_url, ts = wayback_closest(src, ua=seed_ua)
            if snap_url:
                try:
                    base_url, _, headers, body = fetch(snap_url, timeout=args.timeout, ua=seed_ua,
                                                       proxy=seed_proxy)
                    html = body.decode("utf-8", "ignore")
                    recovered_via = f"wayback:{ts}"
                    print(f"[+] recovered archived copy: {snap_url}", file=sys.stderr)
                except Exception:
                    pass
            intel = urlscan_intel(host_for_intel, ua=seed_ua, free_only=args.free_only)
            print(f"[+] urlscan: {intel.get('total', 0)} prior scans, "
                  f"{len(intel.get('related_domains', []))} related domains", file=sys.stderr)
            # No Wayback copy but urlscan has a prior scan → analyze its stored DOM.
            if not html:
                dom_html, dom_id = urlscan_dom(intel, ua=seed_ua, free_only=args.free_only)
                if dom_html:
                    html = dom_html
                    base_url = base_url or f"https://{host_for_intel}/"
                    recovered_via = f"urlscan_dom:{dom_id}"
                    print(f"[+] recovered urlscan DOM {dom_id}", file=sys.stderr)

        # --- archive-missing: guarantee a Wayback snapshot exists to pivot on later ---
        if args.archive_missing:
            if not snap_url:
                snap_url, _ = wayback_closest(src, ua=seed_ua)
            if snap_url:
                print(f"[=] already archived: {snap_url}", file=sys.stderr)
            else:
                print("[*] not in Wayback — submitting to Save-Page-Now …", file=sys.stderr)
                wb_submitted = wayback_save(src, ua=seed_ua)
                snap = (wb_submitted or {}).get("snapshot")
                # only a genuine /web/<ts>/ capture is analyzable; never analyze the /save/
                # endpoint or an archive.org wrapper (that yields bogus archive.org pivots).
                if snap and re.match(r"https?://web\.archive\.org/web/\d{4,14}/", snap):
                    snap_url = snap
                    print(f"[+] archived now: {snap}", file=sys.stderr)
                    if not html:   # nothing else recovered → analyze the fresh snapshot
                        try:
                            base_url, _, headers, body = fetch(snap, timeout=args.timeout,
                                                               ua=seed_ua, proxy=seed_proxy)
                            _h = body.decode("utf-8", "ignore")
                            uh = strip_www(urlparse(unwrap_wayback(base_url)).netloc)
                            if _h and uh and uh != "web.archive.org" \
                                    and not detect_cloudflare_challenge(200, {}, _h):
                                html, recovered_via = _h, "wayback_spn"
                        except Exception:
                            pass
                else:
                    wb_submitted = None
                    print(f"[!] Save-Page-Now made no capture "
                          f"(target un-crawlable — Cloudflare/robots). Nothing to analyze.",
                          file=sys.stderr)
    else:
        ap.error("source must be a URL, an existing file, or '-'")

    result = analyze(src, html, base_url, headers, seed_ua, extra_cookies=cookies,
                     proxy=seed_proxy,
                     extra_artifacts=({"email_headers": email_art} if email_art else None))

    # Dead / blocked live target with no recoverable content: still RECORD the intended
    # host so the run is a persisted fact (not a silent MISS) and any passive intel
    # (urlscan related infra) attaches to a named host. (Gap #4)
    if src.startswith(("http://", "https://")) and not result["meta"].get("host"):
        result["meta"]["host"] = strip_www(urlparse(src).netloc)
        result["meta"]["final_url"] = result["meta"].get("final_url") or src
    if screenshot_file:
        result.setdefault("archives", {})["screenshot"] = screenshot_file

    # --- redirect chain + affiliate/referral codes (first-class pivots for tracker links) ---
    if redirects:
        result["meta"]["redirect_chain"] = redirects
        dest = redirects[-1].get("to") or base_url
        dest_host = strip_www(urlparse(dest).netloc)
        if dest_host and dest_host != result["meta"].get("host"):
            result["meta"]["redirect_destination"] = dest_host
    # --- the URL PATH as a campaign identifier -------------------------------------------------
    # Runs AFTER the redirect chain on purpose: a kit operator routinely lands you on a short
    # entry URL and redirects into the template directory, so the path that identifies the kit is
    # the FINAL one, not the one we were handed. Every other pivot in this tool hangs off the
    # hostname; on a path-routed estate the hostname is disposable packaging and this is the only
    # field that survives the rotation. Offline, free, and emits nothing when the path is generic
    # (the base-rate control in references/url_paths.json).
    if src.startswith(("http://", "https://")) or result["meta"].get("final_url"):
        _pu = result["meta"].get("final_url") or base_url or src
        _pa = wp_paths.analyse(_pu, result["meta"].get("host") or "")
        result["meta"].update({k: _pa[k] for k in
                               ("url_path", "path_template", "kit", "locale", "location")
                               if _pa.get(k) is not None})
        _ppiv = wp_paths.path_pivots(_pu, result["meta"].get("host") or "")
        if _ppiv:
            result["pivots"].extend(_ppiv)
            sort_pivots(result["pivots"])

    # --- PASSIVE SSL: promote the enrichment result to real pivots -------------------------------
    # The enrichment step stores its passive-SSL answer inside the domain pivot's `live_results`,
    # which is where passive DNS has always sat — visible in the JSON, invisible to the KB and to
    # the assessment. Promoting it to pivots is what makes an origin candidate reach the case
    # instead of only the file. Policy (CDN certs, over-prevalent certs) was already applied in
    # wp_pssl, so a non-clusterable cert arrives here as `pssl:information`, never as an edge.
    _pssl_piv = []
    for _p in result.get("pivots", []):
        _res = (_p.get("live_results") or {}).get("pssl")
        if _res and not _res.get("skipped"):
            _pssl_piv += wp_pssl.pssl_pivots(result["meta"].get("host") or "", _res)
    if _pssl_piv:
        _seen_ps = {(p.get("kind"), str(p.get("value"))) for p in result["pivots"]}
        for _p in _pssl_piv:
            if (_p["kind"], str(_p["value"])) not in _seen_ps:
                _seen_ps.add((_p["kind"], str(_p["value"])))
                result["pivots"].append(_p)
        sort_pivots(result["pivots"])

    # --- the ADVERTISING half of the URL, and the cloaking verdict -------------------------------
    # Free and offline. `extract_url_codes` below already turns utm_*/affiliate values into
    # `affiliate:*` pivots (one owner per artifact class), so this adds only what nothing else
    # reads: the Google ValueTrack ACCOUNT OBJECT ids (campaignid/adgroupid/creative — allocated
    # inside one advertiser account, so a match means one payer) and the fact that the URL we were
    # handed describes a PAID arrival at all, which is the cue to resolve the advertiser.
    _ad_urls = [u for u in ([src, base_url, result["meta"].get("final_url")] +
                            [h.get("to", "") for h in redirects]) if u]
    _ad_pivots = []
    for _u in uniq(_ad_urls):
        _ad_pivots += wp_serp.ad_param_pivots(_u, host=result["meta"].get("host") or "")
    if cloak_report:
        result["meta"]["cloaking"] = cloak_report
        _ad_pivots += wp_serp.cloaking_pivots(cloak_report, host=result["meta"].get("host") or "")
    if _ad_pivots:
        _seen_ad = set()
        for _p in _ad_pivots:
            _k = (_p["kind"], _p["value"])
            if _k not in _seen_ad:
                _seen_ad.add(_k)
                result["pivots"].append(_p)
        sort_pivots(result["pivots"])

    url_pool = [src] + [h.get("to", "") for h in redirects]
    if base_url:
        url_pool.append(base_url)
    codes = extract_url_codes(url_pool)
    if codes:
        result.setdefault("artifacts", {})["affiliate_codes"] = codes
        result["pivots"].extend(build_affiliate_pivots(codes))
        sort_pivots(result["pivots"])

    # Analyst-supplied high-value HTML strings → FOFA body-search pivots (the IntelAnalysis chain).
    if args.fofa_keyword:
        kw_pivots = build_keyword_pivots(args.fofa_keyword)
        if kw_pivots:
            result["pivots"].extend(kw_pivots)
            sort_pivots(result["pivots"])

    if live_error:
        result["meta"]["live_error"] = live_error
        result["meta"]["recovered_via"] = recovered_via
    if cf_challenge:
        result["meta"]["cloudflare"] = cf_challenge
    if recovered_via:
        result["meta"]["recovered_via"] = recovered_via
    if wb_submitted and wb_submitted.get("snapshot"):
        result.setdefault("archives", {}).setdefault("wayback", {})["submitted"] = wb_submitted["snapshot"]
    if intel is not None:
        result["related_urlscan"] = intel
        # promote urlscan related-infra to pivots even when the page itself is gone
        for d in intel.get("related_domains", [])[:15]:
            if d and d != result["meta"].get("host"):
                result["pivots"].append({
                    "kind": "urlscan_related_domain", "value": d, "confidence": "medium",
                    "note": "Domain seen in urlscan scans of the same host/target.",
                    "queries": [{"service": "urlscan.io", "query": f"domain:{d}"},
                                {"service": "crt.sh", "query": f"%.{d}"}]})
        for ip in intel.get("ips", [])[:10]:
            result["pivots"].append({
                "kind": "urlscan_ip", "value": ip, "confidence": "medium",
                "note": "IP that served the target in a urlscan scan — reverse it.",
                "queries": [{"service": "urlscan.io", "query": f"ip:{ip}"},
                            {"service": "Validin/DNSlytics reverse-IP", "query": ip}]})

    # --- crawl the site's navigation / tabs / panels (opt-in via --crawl) ---
    if args.crawl is not None and html and base_url and src.startswith(("http://", "https://")):
        max_pages = max(1, args.crawl)
        seed_reg = _registrable(result["meta"].get("host") or urlparse(base_url).netloc)
        visited = {src.split("#", 1)[0], base_url.split("#", 1)[0]}
        crawled = []
        frontier = collections.deque((u, 1) for u in extract_nav_links(html, base_url, seed_reg))
        print(f"[+] crawl: {len(frontier)} nav/tab/panel links on {seed_reg} "
              f"(depth {args.crawl_depth}, up to {max_pages} pages)", file=sys.stderr)
        while frontier and len(crawled) < max_pages:
            url, depth = frontier.popleft()
            nurl = url.split("#", 1)[0]
            if nurl in visited:
                continue
            visited.add(nurl)
            c_ua, c_proxy = next_ua(), next_proxy()  # rotate UA + proxy per crawled page
            try:
                if args.render:
                    c_base, c_html, c_cookies = render_dom(url, timeout=args.timeout,
                                                           ua=c_ua, proxy=c_proxy)
                    c_headers = {}
                else:
                    c_base, c_status, c_headers, c_body = fetch(url, timeout=args.timeout,
                                                               ua=c_ua, proxy=c_proxy)
                    c_html = c_body.decode("utf-8", "ignore")
                    c_cookies = None
                    if c_status >= 400 or len(c_html) < 64:
                        raise RuntimeError(f"HTTP {c_status}, {len(c_html)} bytes")
            except Exception as e:
                print(f"[!] crawl skip {url} ({e})", file=sys.stderr)
                continue
            sub = analyze(url, c_html, c_base or url, c_headers, c_ua,
                          extra_cookies=c_cookies, proxy=c_proxy, probe_tls=False,
                          probe_http=False)
            merge_result(result, sub)
            crawled.append(url)
            print(f"[+] crawled ({len(crawled)}/{max_pages}) {url}", file=sys.stderr)
            if depth < args.crawl_depth:
                for u in extract_nav_links(c_html, c_base or url, seed_reg):
                    if u.split("#", 1)[0] not in visited:
                        frontier.append((u, depth + 1))
        result["meta"]["crawled"] = crawled
        result["meta"]["crawl_pages"] = len(crawled)
        sort_pivots(result["pivots"])  # re-rank after folding in crawled pages

    if not args.no_enrich:
        enrich_live(result, fofa_full=args.fofa_full, free_only=args.free_only)
    if not args.no_whois:
        whois_enrich_result(result, do_reverse=(not args.no_whois_reverse) and not args.free_only,
                            history_mode=args.whois_history_mode, free_only=args.free_only)
    # IntelX runs AFTER WHOIS on purpose: the registrant email/phone WHOIS just filled in are the
    # highest-value selectors in the whole result, and they do not exist until that call returns.
    if args.intelx:
        wp_intelx.enrich_result(result, do_phonebook=not args.no_intelx_phonebook,
                                free_only=args.free_only)
    # The advertising archive runs LAST of the metered layers: it is the only one whose answer can
    # send us back to collect a different page (a creative's destination link carries the operator's
    # real campaign tagging, which unlocks a cloaked landing page), so it should see the finished
    # result — and its cost is one search, which should not be spent before the free layers have
    # had their chance to make it unnecessary.
    if args.serp:
        _adv = wp_serp.enrich_result(result, region=args.serp_region,
                                     free_only=args.free_only, timeout=args.timeout)
        for _a in (_adv.get("advertisers") or []):
            print(f"[+] advertiser: {_a.get('advertiser') or '(unnamed)'} [{_a['advertiser_id']}] "
                  f"· {_a['creative_count']} creative(s) · "
                  f"{len(_a.get('target_domains') or [])} domain(s)", file=sys.stderr)
        for _det in (_adv.get("creatives_opened") or []):
            if _det.get("landing_params"):
                _lp = "&".join(f"{k}={r['value']}" for k, r in _det["landing_params"].items())
                print(f"[+] the ad's OWN landing parameters: {_lp}\n"
                      f"    re-collect the page as its audience sees it: "
                      f"pivot_extract '{_det['link']}'", file=sys.stderr)
        if _adv.get("skipped"):
            print(f"[!] ads transparency skipped: {_adv['skipped']}", file=sys.stderr)

    # --- RAW EVIDENCE: the DOM plus every JS/CSS the host served, hashed ------------------------
    # Default ON with --case. Everything else this tool emits is DERIVED — a hash, a fingerprint,
    # an extracted address — i.e. an assertion about a page that will not exist next month. The
    # capture is the primary source those assertions can be re-checked against, by a reviewer or
    # by us when the same kit resurfaces on a new host and we want to diff it.
    want_capture = args.capture if args.capture is not None else bool(args.case)
    if want_capture and html and src.startswith(("http://", "https://")):
        try:
            cap = wp_capture.capture(
                result["meta"].get("final_url") or src, html=html, case=args.case,
                # seed_ua / seed_proxy, NOT args.* — those are unresolved (--ua defaults to None,
                # and --rotate-ua picks per run). The capture must go out on the SAME identity the
                # page was fetched with, or the assets come from a different session than the DOM.
                ua=seed_ua, proxy=seed_proxy, third_party=args.capture_third_party,
                rendered=bool(getattr(args, "render", False)), timeout=args.timeout)
            if cap.get("error"):
                print(f"[!] capture failed: {cap['error']}", file=sys.stderr)
            else:
                m = cap["manifest"]
                result["meta"]["capture"] = {
                    "dir": cap["dir"], "capture_sha256": cap["capture_sha256"],
                    "files": m["counts"]["total"], "js": m["counts"]["js"],
                    "css": m["counts"]["css"], "bytes": m["bytes"],
                    "captured_at": m["captured_at"],
                    "incomplete": m.get("completeness"),
                }
                print(f"[+] captured {m['counts']['total']} file(s) "
                      f"({m['counts']['js']} js, {m['counts']['css']} css) -> {cap['dir']}",
                      file=sys.stderr)
                print(f"    capture_sha256 {cap['capture_sha256']}", file=sys.stderr)
                if m.get("skipped_for_budget"):
                    print(f"    [!] {len(m['skipped_for_budget'])} asset(s) skipped for budget — "
                          f"this bundle is NOT the whole page (see manifest).", file=sys.stderr)
        except Exception as e:
            # Never lose a collection because evidence storage failed — but say so loudly, since
            # a run that reports no capture must not be mistaken for one that had nothing to store.
            print(f"[!] capture failed ({e}) — the analysis below stands, but the raw bytes were "
                  f"NOT stored for this run.", file=sys.stderr)

    # --- store the raw DOM on its own (superseded by --capture, kept for ad-hoc use) ---
    if args.save_dom and html:
        if isinstance(args.save_dom, str):
            dom_path = args.save_dom
        elif args.out:
            dom_path = re.sub(r"\.json$", "", args.out) + ".html"
        elif args.case:
            # Never the bare CWD when a case exists: a stray <host>.dom.html at the repo root is
            # case data outside cases/, which the contributor rules exist to prevent.
            dom_dir = os.path.join("cases", args.case, "evidence", "dom")
            os.makedirs(dom_dir, exist_ok=True)
            dom_path = os.path.join(dom_dir, (result["meta"].get("host") or "page") + ".dom.html")
        else:
            dom_path = (result["meta"].get("host") or "page") + ".dom.html"
        try:
            with open(dom_path, "w", encoding="utf-8") as f:
                f.write(html)
            result["meta"]["raw_dom_file"] = dom_path
            print(f"[+] saved raw DOM ({len(html)} bytes) -> {dom_path}", file=sys.stderr)
        except Exception as e:
            print(f"[!] could not save DOM: {e}", file=sys.stderr)

    # --- actively archive the URL to Wayback + urlscan (more results later) ---
    if args.submit and src.startswith(("http://", "https://")):
        archives = {}
        print("[+] submitting to Wayback Save-Page-Now …", file=sys.stderr)
        # SPN's synchronous save often takes 60-120s; a read timeout here does NOT mean the
        # capture failed (it usually completes server-side) — give it generous headroom.
        archives["wayback"] = wayback_save(src, ua=args.ua, timeout=max(args.timeout, 90))
        print(f"    wayback: {archives['wayback'].get('snapshot') or archives['wayback'].get('error')}",
              file=sys.stderr)
        print("[+] submitting to urlscan.io …", file=sys.stderr)
        archives["urlscan"] = urlscan_submit(src, timeout=max(args.timeout, 30))
        u = archives["urlscan"]
        print(f"    urlscan: {u.get('result') or u.get('error') or u.get('skipped')}", file=sys.stderr)
        result.setdefault("archives", {}).update(archives)   # keep any screenshot key

    # --- DEEP ARCHIVE: exhaust Wayback history + every urlscan cached DOM + CommonCrawl +
    # archive.today, merging historical / scrubbed / taken-down selectors a single live capture
    # misses. Opt-in (--deep-archive); passive & keyless; domain targets only (never an IP or an
    # offline file). Never fatal — a failed corpus leaves the live analysis untouched.
    _host_deep = result["meta"].get("host")

    def _is_ipaddr(h):
        try:
            import ipaddress
            ipaddress.ip_address((h or "").strip("[]"))
            return True
        except Exception:
            return False

    if getattr(args, "deep_archive", False) and _host_deep and not _is_ipaddr(_host_deep):
        try:
            import wp_deep_archive
            print(f"[+] deep-archive: exhausting Wayback + urlscan + CommonCrawl + archive.today "
                  f"for {_host_deep} …", file=sys.stderr)
            da = wp_deep_archive.deep_archive(
                _host_deep, ua=seed_ua, free_only=args.free_only,
                root_only=getattr(args, "deep_root_only", False),
                commoncrawl=not getattr(args, "deep_no_commoncrawl", False),
                archive_today=not getattr(args, "deep_no_archive_today", False))
            seen = {(p.get("kind"), str(p.get("value"))) for p in result["pivots"]}
            added = 0
            for p in da.get("pivots", []):
                k = (p.get("kind"), str(p.get("value")))
                if k not in seen:
                    seen.add(k)
                    result["pivots"].append(p)
                    added += 1
            sort_pivots(result["pivots"])
            result["meta"]["deep_archive"] = da.get("meta", {})
            inds = da.get("indicators") or []
            if inds and (args.case or args.out):
                # NEVER write this bare-list file into a case raw/ dir: the loop globs raw/*.json
                # for collected hosts AND the frontier miner (case_state) does obj.get("meta") on
                # each — a list there becomes a phantom host and crashes the next round. Keep it in
                # a sibling deep-archive/ dir; the selectors also live as pivots in raw/<host>.json.
                if args.case:
                    ind_dir = os.path.join("cases", args.case, "deep-archive")
                    os.makedirs(ind_dir, exist_ok=True)
                    ind_path = os.path.join(ind_dir, _host_deep + ".indicators.json")
                else:
                    base = re.sub(r"\.json$", "", args.out)
                    outdir = os.path.dirname(base) or "."
                    if os.path.basename(outdir) == "raw":     # redirect out of raw/
                        outdir = os.path.join(os.path.dirname(outdir), "deep-archive")
                        os.makedirs(outdir, exist_ok=True)
                        base = os.path.join(outdir, os.path.basename(base))
                    ind_path = base + ".deep-archive.indicators.json"
                with open(ind_path, "w", encoding="utf-8") as f:
                    json.dump(inds, f, ensure_ascii=False, indent=2)
                result["meta"]["deep_archive_indicators_file"] = ind_path
            m = da.get("meta", {})
            print(f"[+] deep-archive: +{added} pivot(s), {len(inds)} indicator(s) "
                  f"(wayback {m.get('wayback_snapshots', 0)} snap, "
                  f"urlscan {m.get('urlscan_doms', 0)} dom, CC {m.get('cc_fetched', 0)} body, "
                  f"archive.today {m.get('at_mementos', 0)} memento)", file=sys.stderr)
        except Exception as e:
            print(f"[!] deep-archive failed ({e}) — the analysis above stands.", file=sys.stderr)

    _emit_result(result, args, src)


if __name__ == "__main__":
    main()

