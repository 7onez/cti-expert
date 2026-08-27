"""wp_pivots — turn extracted artifacts into ranked, ready-to-run pivot queries."""
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
import wp_docmeta  # document/image metadata: the generic-vs-operator base-rate filter
from wp_common import *  # noqa
from wp_extract import *  # noqa
from wp_refs import ref_path, load_ref  # noqa — reference DATA lives in references/*.json
from wp_censys import censys_queries, attach_censys_queries  # CenQL builder (keyless — no PAT needed)
from wp_intelx import attach_intelx_queries  # IntelX selector builder (keyless — no key needed)
from wp_hunterhow import attach_hunterhow_queries  # Hunter.how query builder (keyless — no key needed)
from wp_email import ESP_DOMAINS  # sending-infra domains — ESP mailers, not the operator

# ---------------------------------------------------------------- reference data (RULE 3)
# How much a pivot artifact is WORTH (SaaS-token confidence) and which URL params carry
# affiliate attribution are analyst judgments that change with tradecraft, so they live in
# references/pivot_tables.json. Tune that file — not this module.
_PIVOT_FALLBACK = {
    "saas_pivots": {"google_sheet": ["high", "Backend Google Sheet ID — same sheet = same operator."]},
    "affiliate_params": ["affid", "aff", "ref", "clickid", "btag"],
}
_PIVOT_REF = load_ref(ref_path(__file__, "pivot_tables.json"), _PIVOT_FALLBACK)

# artifact kind -> (confidence|None, analyst note). None = signals a funnel type, never clusters.
SAAS_PIVOTS = {k: (v[0], v[1]) for k, v in _PIVOT_REF["saas_pivots"].items()}

# Query params that carry affiliate / referral / campaign attribution. A redirector's
# destination usually stamps the promoter's code here (affid=…, 8c=…, ref=…) — that code
# is the real pivot: source-search it to find where the affiliate promotes the link.
AFFILIATE_PARAMS = frozenset(_PIVOT_REF["affiliate_params"])

def _maybe_b64(v: str):
    """If v is base64 that decodes to a short printable ASCII string, return it, else None."""
    s = v.strip()
    if len(s) < 4 or len(s) % 4 != 0 or not re.fullmatch(r"[A-Za-z0-9+/=]+", s):
        return None
    try:
        txt = base64.b64decode(s, validate=True).decode("ascii")
    except Exception:
        return None
    if txt and txt != s and len(txt) <= 64 and all(32 <= ord(c) < 127 for c in txt):
        return txt
    return None

def extract_url_codes(urls):
    """Affiliate/referral/campaign codes from the query strings of a set of URLs.

    Returns [{param, value, decoded?}] — deduped. `utm_*` params are included as campaign
    attribution. base64-looking values get a decoded field (e.g. affid=MTA2MDEzMQ== → 1060131).
    """
    out, seen = [], set()
    for u in urls:
        try:
            pairs = parse_qsl(urlparse(u).query)
        except Exception:
            continue
        for k, v in pairs:
            kl = k.lower()
            if not v or (kl not in AFFILIATE_PARAMS and not kl.startswith("utm_")):
                continue
            key = (kl, v)
            if key in seen:
                continue
            seen.add(key)
            rec = {"param": k, "value": v}
            dec = _maybe_b64(v)
            if dec:
                rec["decoded"] = dec
            out.append(rec)
    return out

def build_affiliate_pivots(codes):
    """Turn extracted affiliate/referral codes into MEDIUM pivots with source-search queries."""
    pivots = []
    for c in codes:
        disp = c["value"] + (f" (b64→ {c['decoded']})" if c.get("decoded") else "")
        search_vals = uniq([c["value"]] + ([c["decoded"]] if c.get("decoded") else []))
        queries = []
        for sv in search_vals:
            queries += [{"service": "PublicWWW", "query": f'"{sv}"'},
                        {"service": "urlscan.io", "query": f'"{sv}"'},
                        {"service": "Google/Bing", "query": f'"{sv}"'}]
        pivots.append({
            "kind": f"affiliate:{c['param']}", "value": disp, "confidence": "medium",
            "note": ("Affiliate/referral/campaign code on the link. Source-search it to find "
                     "where the promoter advertises this link (social/Telegram/other sites)."),
            "queries": queries,
        })
    return pivots

def _fofa_body(s: str) -> str:
    """Build a FOFA HTML-body query for a literal string: `body="<s>"`.

    FOFA indexes served HTML, so a distinctive HTML/JS/CSS string (verification token, footer
    copy, page description, SaaS id, a slogan the analyst flagged) reverses to every host serving
    it — often a better index than PublicWWW for freshly-stood-up NRDs. Embedded double quotes are
    escaped so the query stays well-formed."""
    return 'body="%s"' % s.replace('"', '\\"')


def _fofa_host(label: str) -> str:
    """Build a FOFA hostname query for a subdomain label: `host="<label>."`.

    The trailing dot biases the match toward the label being a subdomain boundary (`<label>.apex`)
    rather than an arbitrary substring. Embedded double quotes are escaped."""
    return 'host="%s."' % label.replace('"', '\\"')


def build_keyword_pivots(keywords):
    """Turn analyst-supplied high-value keywords/phrases into FOFA-body HTML-search pivots.

    This is the IntelAnalysis → WebPivot handoff: when the analyst flags a distinctive HTML
    string (a slogan, brand phrase, unique class/template literal), each one becomes a HIGH
    `keyword` pivot whose primary query is FOFA `body="..."` — reverse the served HTML to find
    every other host running the same page — corroborated by PublicWWW / urlscan / NerdyData.
    """
    pivots, seen = [], set()
    for kw in keywords or []:
        kw = (kw or "").strip()
        if not kw or kw.lower() in seen:
            continue
        seen.add(kw.lower())
        pivots.append({
            "kind": "keyword", "value": kw, "confidence": "high",
            "note": ("High-value HTML string flagged by the analyst. FOFA body-searches the served "
                     "HTML for every host running the same page — chain: new hosts → re-extract."),
            "queries": [
                {"service": "FOFA", "query": _fofa_body(kw)},
                {"service": "PublicWWW", "query": f'"{kw}"'},
                {"service": "urlscan.io", "query": f'"{kw}"'},
                {"service": "NerdyData", "query": f'"{kw}"'},
            ],
        })
    return pivots


def sort_pivots(pivots: list) -> list:
    """Sort pivots high→medium→low confidence in place, returning the same list."""
    order = {"high": 0, "medium": 1, "low": 2}
    pivots.sort(key=lambda p: order.get(p.get("confidence"), 3))
    return pivots


def add_pivot(pivots: list, kind, value, confidence, queries, note="", live=None):
    """Append one pivot dict (the WebPivot pivot schema) to `pivots`. Shared builder so every
    collector (domainPivot, IPPivot, ImpersonationHunt) emits the identical shape."""
    p = {"kind": kind, "value": value, "confidence": confidence, "note": note, "queries": queries}
    if live is not None:
        p["live_results"] = live
    pivots.append(p)
    return p


# Subdomain labels that are generic infrastructure/service names — a shared one clusters nothing,
# so they are NOT treated as a distinctive same-operator signal.
# DATA: references/generic_labels.json -> subdomain_labels (add a label there, not here).
_LABELS_FALLBACK = {
    "subdomain_labels": ["www", "mail", "api", "app", "cdn", "static", "admin", "ns1", "ns2",
                         "shop", "blog", "test", "dev", "m", "web"],
    "resource_basename_segments": ["jquery", "bootstrap", "vendor", "main", "index", "app",
                                   "bundle", "min", "js", "css"],
    "noise_tracker_ids": [],
}
_LABELS_REF = load_ref(ref_path(__file__, "generic_labels.json"), _LABELS_FALLBACK)
_GENERIC_SUBLABELS = frozenset(_LABELS_REF["subdomain_labels"])
# Analytics/tag ids owned by a hosting platform or a site-builder TEMPLATE, not by the site owner.
# Filtered HERE as well as at ingest so a keyless/offline run's --leads output does not present a
# platform container as a high-confidence same-owner pivot for an analyst to chase by hand.
_NOISE_TRACKER_IDS = {str(x).strip().upper() for x in _LABELS_REF["noise_tracker_ids"]}


def _distinctive_subdomain(host: str):
    """Return the leftmost subdomain LABEL of `host` when it's a distinctive (non-generic) name.

    A distinctive subdomain label (e.g. `svc-a` in `svc-a.site-a.example`) is reused across an
    operator's apexes as a naming convention — its own reverse-lookup pivot. Returns None for a
    bare apex, a `www.`/generic-service host, a purely-numeric label, or a very short label.
    """
    h = strip_www(host or "").strip(".").lower()
    if not h:
        return None
    labels = h.split(".")
    # need at least sub.apex.tld (or sub.apex for a ccSLD-agnostic best effort)
    if len(labels) < 3:
        return None
    label = labels[0]
    if len(label) < 4 or label.isdigit() or label in _GENERIC_SUBLABELS:
        return None
    return label

def build_pivots(art: dict, base_host: str):
    """Turn artifacts into ranked, ready-to-run pivot leads."""
    pivots = []

    def add(kind, value, confidence, queries, note=""):
        pivots.append({"kind": kind, "value": value, "confidence": confidence,
                       "note": note, "queries": queries})

    fav = art.get("favicon")
    if fav:
        # Each engine hashes the favicon differently: Shodan/FOFA/ZoomEye=mmh3,
        # Censys=MD5, Netlas=SHA-256. Emit the right query per engine.
        add("favicon_hash", fav["shodan_mmh3"], "high", [
            {"service": "Shodan", "query": f'http.favicon.hash:{fav["shodan_mmh3"]}'},
            {"service": "FOFA", "query": f'icon_hash="{fav["shodan_mmh3"]}"'},
            {"service": "ZoomEye", "query": f'iconhash:"{fav["shodan_mmh3"]}"'},
            {"service": "Netlas", "query": f'http.favicon.hash_sha256:{fav["sha256"]}'},
        ] + censys_queries("favicon_hash", fav["md5"]),      # Censys wants the MD5, not the mmh3
           "Same favicon across unrelated domains = shared operator/kit.")

    cert = art.get("tls_cert")
    if cert and not cert.get("error") and not cert.get("skipped"):
        fp = cert.get("fingerprint_sha256")
        if fp:
            add("tls_cert:fingerprint_sha256", fp, "high", [
                {"service": "Validin", "query": fp},
                {"service": "crt.sh", "query": f"https://crt.sh/?q={fp}"},
            ] + censys_queries("tls_cert:fingerprint_sha256", fp),
               "Every host serving this exact certificate = same operator/deployment. The Censys "
               "certificate LOOKUP (wp_censys.py cert <sha256>) also returns the cert's own full "
               "`names` list — available on a free Censys plan, no search entitlement needed.")
        # Co-SAN: SANs on a DIFFERENT registrable domain than the seed are a strong
        # cross-brand operator link (one cert covering many apexes). Same-site
        # subdomains are just this domain's own hosts — not a pivot.
        seed_reg = _registrable(base_host) if base_host else ""
        co_apexes = uniq([r for s in cert.get("sans", [])
                          if (r := _registrable(s)) and r != seed_reg])
        if co_apexes:
            queries = censys_queries("tls_cert:fingerprint_sha256", fp) if fp else []
            for apex in co_apexes[:20]:
                queries += [
                    {"service": "crt.sh", "query": f"%.{apex}"},
                    {"service": "urlscan.io", "query": f"domain:{apex}"},
                ]
            add("tls_cert:co_san", ", ".join(co_apexes[:20]), "high", queries,
                "Distinct registrable domains sharing one TLS certificate = same operator.")

    jarm = art.get("jarm")
    if jarm and isinstance(jarm, dict) and jarm.get("jarm") and not jarm.get("empty") \
            and not jarm.get("error") and not jarm.get("skipped"):
        h = jarm["jarm"]
        add("jarm:hash", h, "medium", [
            {"service": "Shodan", "query": f"ssl.jarm:{h}"},
            {"service": "ZoomEye", "query": f'jarm="{h}"'},
            # Censys indexes JARM but only makes it SEARCHABLE with the Adversary Investigation
            # module — on free/starter/core this query returns nothing. Shodan is the free path.
            *censys_queries("jarm:hash", h, ui=False),
        ], "Identical JARM = same TLS server stack + config — clusters an operator's "
           "origin/backend hosts even across domain rotation and re-branding. Corroborate: "
           "stock stacks (nginx/Cloudflare defaults) share a JARM, so pair with a 2nd artifact.")

    app = art.get("app_downloads") or {}
    for apk in app.get("apk_urls", []):
        apk_host = strip_www(urlparse(apk).netloc)
        add("app:apk", apk, "high", [
            {"service": "→ BinaryPivot", "query": f"python3 BinaryPivot/tools/analyze_artifact.py {apk} --leads"},
            {"service": "urlscan.io", "query": f'"{apk}"'},
            {"service": "PublicWWW", "query": f'"{apk}"'},
            {"service": "crt.sh (backend host)", "query": f"%.{apk_host}"},
            {"service": "reverse-IP (backend host)", "query": apk_host},
        ], f"Sideloaded APK download — the host serving it ({apk_host}) is backend infra. "
           f"Run BinaryPivot on the file to pull its signing-cert SHA-256, package, embedded backend "
           f"hosts and wallets — those become shared indicators that cluster this app's whole portfolio.")
    for inst in app.get("desktop_installers", []):
        inst_host = strip_www(urlparse(inst).netloc)
        ext = re.search(r"\.(exe|msi|dmg|pkg|appimage|deb|rpm|jar)(\?|$)", inst, re.I)
        add("app:desktop_installer", inst, "high", [
            {"service": "→ BinaryPivot", "query": f"python3 BinaryPivot/tools/analyze_artifact.py {inst} --leads"},
            {"service": "VirusTotal / MalwareBazaar", "query": f"hash the file, then search sha256"},
            {"service": "urlscan.io", "query": f'"{inst}"'},
            {"service": "PublicWWW", "query": f'"{inst}"'},
            {"service": "crt.sh (backend host)", "query": f"%.{inst_host}"},
        ], f"Desktop 'trading terminal' installer ({ext.group(1).lower() if ext else 'binary'}) — "
           f"the host serving it ({inst_host}) is backend infra. Run BinaryPivot on the file for its "
           f"hash + embedded C2/backend hosts + code-signing identity; the same installer re-skinned "
           f"across clones is a strong same-operator link.")
    for pkg in app.get("android_packages", []):
        add("app:android_package", pkg, "high", [
            {"service": "PublicWWW", "query": f'"{pkg}"'},
            {"service": "urlscan.io", "query": f'"{pkg}"'},
            {"service": "Google/APKPure/APKCombo", "query": pkg},
            {"service": "VirusTotal / Koodous", "query": pkg},
        ], "Android package id — reused across scam-app clones = same operator.")
    for appid in app.get("ios_app_ids", []):
        add("app:ios_app_id", appid, "medium", [
            {"service": "App Store", "query": f"https://apps.apple.com/app/id{appid}"},
            {"service": "search engine", "query": f'"id{appid}"'},
        ], "iOS app id — pivots the developer account across listings.")
    al = app.get("assetlinks") or {}
    for fp in al.get("sha256_cert_fingerprints", []):
        add("app:signing_sha256", fp, "high", [
            {"service": "Koodous / AndroZoo", "query": fp},
            {"service": "search other assetlinks.json", "query": f'"{fp}"'},
            {"service": "PublicWWW", "query": f'"{fp}"'},
        ], "APK signing-cert SHA-256 (from assetlinks.json) — clusters every app signed by "
           "the same developer key, across unrelated domains.")
    for pkg in al.get("packages", []):
        if pkg not in app.get("android_packages", []):
            add("app:android_package", pkg, "high", [
                {"service": "PublicWWW", "query": f'"{pkg}"'},
                {"service": "Google/APKPure", "query": pkg},
            ], "Android package id declared in assetlinks.json.")

    for label, token in art.get("verifications", {}).items():
        add(f"verification:{label}", token, "high", [
            {"service": "PublicWWW", "query": f'"{token}"'},
            {"service": "FOFA", "query": _fofa_body(token)},
            {"service": "urlscan.io", "query": f'"{token}"'},
            {"service": "NerdyData", "query": f'"{token}"'},
        ], "Ownership-verification token reused across the owner's other domains.")

    for label, vals in art.get("trackers", {}).items():
        for v in vals:
            if str(v).strip().upper() in _NOISE_TRACKER_IDS:
                add(f"platform_tracker:{label}", v, "low", [],
                    "Platform/template analytics container carried by every tenant or every site "
                    "built from this template — NOT the site owner's account. Recorded as context; "
                    "never cluster on it.")
                continue
            add(f"tracker:{label}", v, "high", [
                {"service": "PublicWWW", "query": f'"{v}"'},
                {"service": "FOFA", "query": _fofa_body(v)},
                {"service": "SpyOnWeb", "query": v},
                {"service": "DNSlytics reverse-analytics", "query": v},
                {"service": "urlscan.io", "query": f'page.url:* AND "{v}"'},
                {"service": "NerdyData", "query": f'"{v}"'},
            ], "Shared analytics/ad ID = same owner across sites.")

    for label, vals in art.get("saas_ids", {}).items():
        conf_note = SAAS_PIVOTS.get(label)
        if not conf_note or not conf_note[0]:   # unknown or non-pivot (trustedform)
            continue
        conf, note = conf_note
        for v in vals:
            add(f"saas:{label}", v, conf, [
                {"service": "PublicWWW", "query": f'"{v}"'},
                {"service": "FOFA", "query": _fofa_body(v)},
                {"service": "urlscan.io", "query": f'"{v}"'},
                {"service": "NerdyData", "query": f'"{v}"'},
                {"service": "Google/Bing", "query": f'"{v}"'},
            ], note)

    # Copy-pasted disclaimer / risk-warning / T&C prose — a selector that outlives a full front-end
    # rebuild and reverse-searches verbatim on a source-code search engine.
    for phrase in art.get("prose_selectors", []):
        add("prose", phrase, "medium", [
            {"service": "PublicWWW", "query": f'"{phrase}"'},
            {"service": "FOFA", "query": _fofa_body(phrase)},
            {"service": "NerdyData", "query": f'"{phrase}"'},
            {"service": "urlscan.io", "query": f'"{phrase}"'},
            {"service": "Google/Bing", "query": f'"{phrase}"'},
        ], "Copy-pasted disclaimer/risk/T&C prose — survives a full re-skin and reverse-searches "
           "verbatim. A shared phrase = shared copy/template; the ODD or grammatically broken "
           "sentence is worth far more than a standard warning, which legit brokers publish too. "
           "MEDIUM: corroborate with a tier-1 selector before clustering.")

    for coin, vals in art.get("crypto", {}).items():
        for v in vals:
            add(f"crypto:{coin}", v, "medium", [
                {"service": "blockchain explorer", "query": v},
                {"service": "Chainabuse", "query": v},
                {"service": "search engine / PublicWWW", "query": f'"{v}"'},
            ], "Reused wallet links scam/campaign infrastructure.")

    # --- QR-code payloads (wallet / Telegram / affiliate link hidden in a QR image) ---
    qr = art.get("qr_codes") or {}
    for item in qr.get("payloads", []):
        payload = item["payload"]
        via = item.get("via", "qr")
        low = payload.lower()
        coin = _qr_crypto_coin(payload)
        if coin:
            addr = _qr_strip_uri(payload)
            add(f"qr:crypto:{coin}", addr, "high", [
                {"service": "blockchain explorer", "query": addr},
                {"service": "Chainabuse", "query": addr},
                {"service": "search engine / PublicWWW", "query": f'"{addr}"'},
            ], f"Wallet address hidden in a QR ({via}) — the payout address. "
               f"Trace on-chain and cluster: the same deposit wallet across sites = one operator.")
        elif re.search(r'(?:t\.me/|telegram\.me/|tg://)', low):
            add("qr:telegram", payload, "high", [
                {"service": "open channel", "query": payload},
                {"service": "urlscan.io / PublicWWW", "query": f'"{payload}"'},
                {"service": "Telegram search", "query": payload},
            ], f"Telegram invite in a QR ({via}) — the operator's recruitment/support channel; "
               f"often the strongest human pivot.")
        elif "wa.me" in low or "api.whatsapp.com" in low or "chat.whatsapp.com" in low:
            add("qr:whatsapp", payload, "medium", [
                {"service": "search engine / PublicWWW", "query": f'"{payload}"'},
            ], f"WhatsApp contact in a QR ({via}) — extract the phone number and pivot it.")
        elif low.startswith("http"):
            add("qr:url", payload, "medium", [
                {"service": "resolve redirect", "query": f"curl -sIL '{payload}'"},
                {"service": "urlscan.io", "query": payload},
                {"service": "unfurl / redirect tracer", "query": payload},
            ], f"QR encodes a URL ({via}) — frequently a redirector / affiliate link; "
               f"resolve it to the real destination (that's usually the more interesting host).")
        else:
            add("qr:text", payload, "low", [
                {"service": "search engine", "query": f'"{payload}"'},
            ], f"Decoded QR payload ({via}).")
    for img in qr.get("undecoded_images", []):
        add("qr:undecoded_image", img, "medium", [
            {"service": "decode manually", "query": f"install pyzbar/opencv then re-run with --decode-qr, or scan: {img}"},
        ], "A QR image was detected but not decoded (no decoder lib / not fetched). "
           "Re-run with --decode-qr, or decode it by hand — QR payloads hide wallets & invite links.")

    for e in art.get("emails", []):
        add("email", e, "medium", [
            {"service": "reverse-WHOIS (ViewDNS/WhoisXML)", "query": e},
            {"service": "urlscan.io", "query": f'"{e}"'},
            {"service": "hunter.io / Epieos", "query": e},
        ], "Registrant/contact email pivots to other domains.")

    for net, handles in art.get("socials", {}).items():
        if net == "telegram":
            continue  # richer, classified telegram pivots are emitted below from art['telegram']
        for h in handles:
            add(f"social:{net}", h, "medium", [
                {"service": "platform search", "query": h},
            ])

    for t in art.get("telegram", []):
        handle = t.get("handle", "")
        is_invite = t.get("kind") == "invite"
        add("telegram", handle, "high" if is_invite else "medium", [
            {"service": "open (contact infra)", "query": t.get("url", handle)},
            {"service": "PublicWWW", "query": f'"t.me/{handle}"'},
            {"service": "urlscan.io", "query": f'"{handle}"'},
            {"service": "Google/Bing", "query": f'"t.me/{handle}"'},
        ], ("Telegram group-invite link — operator-run group; reused invite = same operator."
            if is_invite else
            "Telegram channel/handle linked from the site — operator contact. Reuse = same operator."))

    for ph in art.get("phones", []):
        add("phone", ph, "medium", [
            {"service": "PublicWWW", "query": f'"{ph}"'},
            {"service": "urlscan.io", "query": f'"{ph}"'},
            {"service": "reverse-WHOIS (phone)", "query": ph},
            {"service": "Google/Bing + messaging apps", "query": f'"{ph}"'},
        ], "Contact phone on the site. Same number across sites = same operator; also try it "
           "on WhatsApp/Telegram/Zalo and as a reverse-WHOIS registrant-phone lookup.")

    footer = art.get("footer") or {}
    for addr in footer.get("addresses", []):
        add("footer:address", addr, "medium", [
            {"service": "PublicWWW", "query": f'"{addr}"'},
            {"service": "FOFA", "query": _fofa_body(addr)},
            {"service": "urlscan.io", "query": f'"{addr}"'},
            {"service": "Google/Bing", "query": f'"{addr}"'},
        ], "Postal address in the footer. A distinctive registered address is copied verbatim "
           "across an operator's sites — source-search it to find them.")
    if footer.get("copyright"):
        co = footer["copyright"]
        add("footer:copyright", co, "low", [
            {"service": "PublicWWW", "query": f'"{co}"'},
            {"service": "FOFA", "query": _fofa_body(co)},
            {"service": "Google/Bing", "query": f'"{co}"'},
        ], "Footer copyright / company string — a distinctive name can tie sibling sites.")

    desc = art.get("description")
    if desc and len(desc) >= 20:
        snippet = desc[:80]
        add("description", snippet, "low", [
            {"service": "PublicWWW", "query": f'"{snippet}"'},
            {"service": "FOFA", "query": _fofa_body(snippet)},
            {"service": "NerdyData", "query": f'"{snippet}"'},
            {"service": "Google/Bing", "query": f'"{snippet}"'},
        ], "Page description copy. Verbatim reuse across domains = shared template/operator.")

    etag = art.get("etag")
    # Only a strong (non-W/) quoted hash-like ETag is worth pivoting; weak/versioned etags rotate.
    if etag and not etag.startswith("W/") and re.search(r'"[0-9a-f]{8,}', etag):
        add("etag", etag, "low", [
            {"service": "PublicWWW", "query": f'"{etag}"'},
            {"service": "Censys/Shodan (asset)", "query": etag},
        ], "Strong ETag on a served asset — an identical ETag on the same path elsewhere points "
           "to a shared origin/kit. Corroborate with another artifact before clustering.")

    # --- CORS-revealed origins — the backends/siblings the server explicitly trusts ---
    cors = art.get("cors") or {}
    seed_reg = _registrable(base_host) if base_host else ""
    for host in cors.get("allowed_origin_hosts", [])[:20]:
        same_apex = bool(seed_reg) and _registrable(host) == seed_reg
        add("cors_allowed_origin", host, "low" if same_apex else "medium", [
            {"service": "crt.sh", "query": f"%.{host}"},
            {"service": "urlscan.io", "query": f"domain:{host}"},
            {"service": "ViewDNS reverse-IP", "query": host},
        ], "Named in the server's Access-Control-Allow-Origin — an origin the app explicitly "
           "trusts" + (" (a subdomain of the seed apex — confirms a backend/API host that "
                       "the page HTML may never mention)." if same_apex else
                       " on a DIFFERENT apex — a backend/sibling brand and a strong "
                       "cross-domain operator link; corroborate with a second artifact."))
    if cors.get("reflects_origin") and cors.get("credentials"):
        add("cors_misconfig", cors.get("acao") or "reflected-origin", "low", [],
            "ACAO reflects any Origin WITH Access-Control-Allow-Credentials:true — a "
            "reflect-any credential misconfig. It names no host, but confirms a live "
            "authenticated API; probe it with candidate Origins to enumerate trusted hosts.")

    # --- mail infrastructure (dig MX) — custom/self-hosted MX + M365 tenant ---
    mail = art.get("mail") or {}
    for ex in mail.get("custom_mx_hosts", [])[:10]:
        mx_reg = _registrable(ex)
        same_apex = bool(seed_reg) and mx_reg == seed_reg
        add("mail_server", ex, "low" if same_apex else "medium", [
            {"service": "crt.sh", "query": f"%.{mx_reg}"},
            {"service": "ViewDNS reverse-IP", "query": ex},
            {"service": "ViewDNS/SecurityTrails reverse-MX", "query": ex},
            {"service": "FOFA", "query": f'host="{ex}"'},
        ], "Custom mail exchanger (matches no managed provider)" + (
            " on the seed's own apex — self-hosted mail; the box's IP and every other domain it "
            "serves are pivots." if same_apex else
            " on a different apex — third-party or shared mail infra; other domains pointing their MX "
            "at this host (reverse-MX) can be a same-operator link. Corroborate before clustering."))
    if mail.get("m365_tenant"):
        add("m365_tenant", mail["m365_tenant"], "medium", [
            {"service": "crt.sh", "query": mail["m365_tenant"].replace("-", ".")},
            {"service": "M365 tenant (GetUserRealm / AADInternals)", "query": mail["m365_tenant"]},
        ], "Microsoft-365 MX routing domain — it encodes the organization's OWN tenant domain "
           "(dashes stand in for dots), revealing the primary domain behind the site and other "
           "domains sharing the same M365 tenant.")

    # SPF (apex TXT) — custom sender includes + bare sending IPs are operator mail infra.
    spf = mail.get("spf") or {}
    for inc in (spf.get("custom_includes") or [])[:8]:
        inc_reg = _registrable(inc)
        same_apex = bool(seed_reg) and inc_reg == seed_reg
        add("spf_include", inc, "low" if same_apex else "medium", [
            {"service": "crt.sh", "query": f"%.{inc_reg}"},
            {"service": "SPF TXT", "query": f"dig +short TXT {inc}"},
            {"service": "ViewDNS reverse-IP", "query": inc},
        ], "SPF `include:` matching no major ESP — a bespoke authorized-sender domain (the operator's "
           "own or a shared niche mailer)" + (" under the seed apex." if same_apex else
           "; other domains that include the same host in their SPF can be an operator link."))
    for sip in (spf.get("ip4", []) + spf.get("ip6", []))[:8]:
        if "/" in sip and sip.split("/")[-1] not in ("32", "128"):
            continue  # a whole netblock in SPF is usually an ESP range, not one sender box
        ip = sip.split("/")[0]
        add("mail_sender_ip", ip, "medium", [
            {"service": "FOFA", "query": f'ip="{ip}"'},
            {"service": "Shodan", "query": f"ip:{ip}"},
            {"service": "ViewDNS reverse-IP", "query": ip},
        ], "IP authorized to send mail for this domain (SPF ip4/ip6) — a real sending server; "
           "reverse it for co-hosted domains and other senders on the same box.")

    # DMARC (_dmarc TXT) — rua/ruf contacts not at a monitoring vendor are operator-controlled.
    dmarc = mail.get("dmarc") or {}
    for addr in (dmarc.get("custom_contacts") or [])[:6]:
        add("dmarc_contact", addr, "medium", [
            {"service": "Chainabuse / breach search", "query": addr},
            {"service": "crt.sh", "query": f"%.{_registrable(addr.split('@')[-1])}"},
            {"service": "reverse-WHOIS (email)", "query": addr},
        ], "DMARC rua/ruf reporting address NOT at a monitoring vendor — an operator-controlled "
           "mailbox/domain; a strong attribution + reverse-WHOIS pivot.")

    # --- ASSET LAYER: JS bundles, source maps, build config, well-known/policy files ------
    # (artifacts.assets — see wp_assets.py). These are the artifacts that survive a re-skin:
    # the front end is rebuilt for every brand, the backend host / build tenant / developer
    # machine / publisher account behind it are not.
    assets = art.get("assets") or {}

    api = assets.get("api") or {}
    for base in (api.get("api_bases") or [])[:10]:
        bh = strip_www(urlparse(base if "://" in base else "https:" + base).netloc).split(":")[0]
        if not bh:
            continue
        add("api_endpoint", bh, "high", [
            {"service": "crt.sh", "query": f"%.{_registrable(bh)}"},
            {"service": "FOFA", "query": _fofa_host(bh)},
            {"service": "urlscan.io", "query": f"page.domain:{bh}"},
            {"service": "Shodan", "query": f'hostname:"{bh}"'},
            {"service": "PublicWWW", "query": bh},
        ], f"OFF-APEX backend the front end was compiled against ({base}). In a white-label "
           f"kit every front rotates but the backend does not — the strongest same-operator "
           f"link the front end can give you. Reverse it for the other fronts it serves.")

    for base in (api.get("same_site_api") or [])[:6]:
        bh = strip_www(urlparse(base if "://" in base else "https:" + base).netloc).split(":")[0]
        if bh and bh != base_host:
            add("api_endpoint:same_site", bh, "low", [
                {"service": "crt.sh", "query": f"%.{_registrable(bh)}"},
                {"service": "Shodan", "query": f'hostname:"{bh}"'},
            ], "Backend host inside the seed's OWN domain — infrastructure context, not a "
               "cross-site pivot on its own.")

    for ws in (api.get("websockets") or [])[:6]:
        wh = strip_www(urlparse(ws).netloc).split(":")[0]
        if wh:
            add("websocket_endpoint", wh, "medium", [
                {"service": "crt.sh", "query": f"%.{_registrable(wh)}"},
                {"service": "Shodan", "query": f'hostname:"{wh}"'},
                {"service": "PublicWWW", "query": ws},
            ], f"Live WebSocket the app streams from ({ws}) — real-time backend infra, rarely "
               f"rotated with the front-end domain.")

    for gq in (api.get("graphql") or [])[:4]:
        add("graphql_endpoint", gq, "medium", [
            {"service": "PublicWWW", "query": gq},
            {"service": "urlscan.io", "query": f'page.url:"{gq}"'},
        ], "GraphQL endpoint compiled into the bundle — backend surface shared across fronts.")

    # Build-time env vars inlined by the bundler. A tenant/brand name compiled into the build
    # (VUE_APP_BRAND, REACT_APP_TENANT, …) is the white-label platform naming its own customer.
    _BRANDY = ("BRAND", "TENANT", "SITE", "NAME", "PROJECT", "CLIENT", "MERCHANT",
               "PLATFORM", "COMPANY", "AGENT", "CHANNEL", "APP_ID", "APPID")
    for key, vals in list((api.get("build_env") or {}).items())[:20]:
        upper = key.upper()
        if any(b in upper for b in _BRANDY):
            conf, why = "high", ("Build-time tenant/brand token compiled into the bundle — a "
                                 "white-label platform naming its own customer. The same value "
                                 "on another domain is the SAME tenant; the same KEY with a "
                                 "different value is the same PLATFORM, not the same operator.")
        elif any(b in upper for b in ("API", "URL", "HOST", "ENDPOINT", "SERVER", "BASE")):
            conf, why = "medium", ("Build-time backend/URL constant — infrastructure the front "
                                   "end was compiled against.")
        else:
            conf, why = "low", "Build-time constant inlined by the bundler."
        for v in vals[:3]:
            add(f"build_env:{key}", v, conf, [
                {"service": "PublicWWW", "query": v},
                {"service": "FOFA", "query": _fofa_body(v)},
                {"service": "Google/Yandex dork", "query": f'"{v}"'},
            ], why)

    # A compiled bundle's sha256 survives the rebrands that break favicon and DOM-skeleton
    # hashes: identical digest on two domains = the same build artifact deployed twice.
    for f in (assets.get("collected") or [])[:8]:
        if f.get("sha256") and f.get("name"):
            add("js_bundle_sha256", f["sha256"], "medium", [
                {"service": "urlscan.io", "query": f'hash:"{f["sha256"]}"'},
                {"service": "VirusTotal", "query": f["sha256"]},
                {"service": "urlscan.io (filename)", "query": f'filename:"{f["name"]}"'},
            ], f"SHA-256 of {f['name']} ({f['bytes']} bytes). Identical digest on another domain "
               f"= the same compiled build, which survives a favicon/DOM re-skin. Note a stock "
               f"vendor bundle can match innocently — corroborate before clustering.")

    # --- DOCUMENT / IMAGE METADATA (artifacts.docmeta — see wp_docmeta.py) ------------------
    # The files the site HOSTS. A page is re-skinned in minutes; nobody re-exports the PDF
    # licence when they change the brand, so what is embedded in these files outlives every
    # cosmetic rotation. Values that name a common TOOL or a DEFAULT account are recorded by the
    # collector but filtered here, because clustering on "Microsoft Word" or "Windows User"
    # fuses unrelated cases — the base-rate rule.
    _dm_seen = set()
    for f in ((art.get("docmeta") or {}).get("files") or [])[:12]:
        fm, fname = f.get("meta") or {}, f.get("name") or "file"
        for key, label, conf in (
                ("author", "doc_author", "high"), ("artist", "doc_author", "high"),
                ("xp_author", "doc_author", "high"), ("camera_owner", "doc_author", "high"),
                # The account that last SAVED an Office document — often a different, and more
                # careless, person than the one who created it.
                ("last_modified_by", "doc_author", "high"),
                ("company", "doc_company", "high"), ("manager", "doc_company", "high"),
                ("copyright", "doc_copyright", "high"),
                ("xmp_document_id", "doc_xmp_docid", "high"),
                ("producer", "doc_producer", "medium"),
                ("creator_tool", "doc_producer", "medium"),
                ("software", "doc_software", "medium")):
            val = str(fm.get(key) or "").strip()
            if not val or wp_docmeta.is_generic(key, val) or (label, val.lower()) in _dm_seen:
                continue
            _dm_seen.add((label, val.lower()))
            if label == "doc_author":
                add(label, val, conf, [
                    {"service": "Google/Yandex dork", "query": f'"{val}"'},
                    {"service": "Google (other documents)", "query": f'"{val}" filetype:pdf'},
                    {"service": "LinkedIn/Facebook", "query": f'"{val}"'},
                ], f"Author/Artist embedded in {fname}. The operator produced this file on their "
                   f"own machine and uploaded it untouched — a name or account here is not "
                   f"copyable by a stranger and survives every re-skin of the site. Verify it is "
                   f"a person and not a stock asset's original author before attributing.")
            elif label == "doc_xmp_docid":
                add(label, val, conf, [
                    {"service": "Google/Yandex dork", "query": f'"{val}"'},
                    {"service": "cross-case KB", "query": f"which_cases {val}"},
                ], f"XMP DocumentID from {fname} — a UUID minted per SOURCE document. The same id "
                   f"on another domain means literally the same source file, not merely a similar "
                   f"one. One of the strongest same-operator artifacts a document can carry.")
            elif label == "doc_company":
                add(label, val, conf, [
                    {"service": "Google/Yandex dork", "query": f'"{val}"'},
                    {"service": "OpenCorporates", "query": val},
                    {"service": "cross-case KB", "query": f"which_cases {val}"},
                ], f"Company/Manager field from {fname}'s Office properties — set once in the "
                   f"authoring account's profile and carried into every document it produces. "
                   f"Frequently names the real entity behind a white-labelled brand.")
            elif label == "doc_copyright":
                add(label, val, conf, [
                    {"service": "Google/Yandex dork", "query": f'"{val}"'},
                    {"service": "PublicWWW", "query": val},
                ], f"Copyright string embedded in {fname} — often names the real company or "
                   f"person behind a white-labelled brand.")
            else:
                add(label, val, conf, [
                    {"service": "Google/Yandex dork", "query": f'"{val}" filetype:pdf'},
                    {"service": "cross-case KB", "query": f"which_cases {val}"},
                ], f"Non-generic producer/editor string from {fname}. It names the SHOP that made "
                   f"the file, so treat it as same-KIT until an owner-tied artifact corroborates "
                   f"it — an unusual or localised tool build narrows the candidate set sharply.")
        if fm.get("gps"):
            add("doc_gps", str(fm["gps"]), "high", [
                {"service": "Google Maps", "query": str(fm["gps"])},
                {"service": "OpenStreetMap", "query": f"https://www.openstreetmap.org/?mlat="
                                                      f"{str(fm['gps']).replace(',', '&mlon=')}"},
            ], f"GPS coordinates embedded in {fname} — the photo was taken on a device with "
               f"location on and uploaded without stripping. Corroborate before treating it as "
               f"the operator's location: stock and scraped imagery carries someone else's GPS.")
        cam = " ".join(str(fm.get(k) or "").strip() for k in ("camera_make", "camera_model")).strip()
        if cam and len(cam) > 3:
            add("doc_camera", cam, "medium", [
                {"service": "Google/Yandex dork", "query": f'"{cam}"'},
                {"service": "cross-case KB", "query": f"which_cases {cam}"},
            ], f"Camera that shot {fname}. Weak alone (millions share a model) but a strong "
               f"corroborator when the same body appears across a cluster's own photography.")
        if f.get("sha256") and f.get("same_site"):
            add("media_sha256", f["sha256"], "medium", [
                {"service": "urlscan.io", "query": f'hash:"{f["sha256"]}"'},
                {"service": "VirusTotal", "query": f["sha256"]},
                {"service": "urlscan.io (filename)", "query": f'filename:"{fname}"'},
            ], f"SHA-256 of the hosted {f.get('kind', 'file')} {fname} ({f.get('bytes', 0)} "
               f"bytes). The identical file served from another domain is the same kit — a stock "
               f"photo will match innocently, so corroborate before clustering.")

    # Source maps: the operator's own build machine leaking through the bundler.
    for sm in (assets.get("source_maps") or [])[:4]:
        for user in (sm.get("usernames") or [])[:4]:
            add("dev_username", user, "high", [
                {"service": "GitHub", "query": f'"{user}"'},
                {"service": "Google/Yandex dork", "query": f'"{user}" site:github.com OR site:gitlab.com'},
                {"service": "PublicWWW", "query": f"/Users/{user}/"},
            ], "Developer account name from a source-map path (the build machine's home "
               "directory). Survives every front-end re-skin and is not copyable by a "
               "stranger — one of the strongest passive attribution artifacts available.")
        for root in (sm.get("project_roots") or [])[:5]:
            add("dev_project", root, "high", [
                {"service": "GitHub", "query": f'"{root}"'},
                {"service": "PublicWWW", "query": f"webpack://{root}/"},
                {"service": "Google/Yandex dork", "query": f'"webpack://{root}"'},
            ], f"Internal project name '{root}' from the source map — the operator's own name "
               f"for this kit, often the un-rebranded original. The same root under a different "
               f"brand is the same codebase.")
        for p in (sm.get("dev_paths") or [])[:6]:
            add("dev_path", p, "medium", [
                {"service": "PublicWWW", "query": p},
                {"service": "Google/Yandex dork", "query": f'"{p}"'},
            ], "Absolute build path from the source map — directory layout is a per-developer "
               "fingerprint." + (" This map ships sourcesContent: the ORIGINAL un-minified "
                                 "source (with the operator's own comments) is recoverable."
                                 if sm.get("has_sources_content") else ""))

    # --- SPA route table (recovered from the already-fetched bundle, zero extra requests) ---
    routes = assets.get("routes") or {}
    if routes.get("signature"):
        add("spa_route_signature", routes["signature"], "medium", [
            {"service": "KB", "query": f"spa_routes:{routes['signature'][:32]}"},
            {"service": "urlscan.io", "query": "page.domain:<candidate>  (compare route inventory)"},
        ], f"SHA-256 over this app's {routes['count']} sorted routes "
           f"({routes.get('router') or 'unknown router'}). An IDENTICAL route inventory on another "
           f"domain means the same compiled application — it survives a cosmetic re-skin (new "
           f"brand, favicon and colours, same routing table). Like any kit fingerprint this proves "
           f"same-KIT; corroborate with an owner-tied artifact before calling it same-OPERATOR.")

    # The operator's own panel. Emitted as a LEAD, never fetched — deciding to visit a
    # discovered admin path is the analyst's call (and a different authorization question).
    for r in (routes.get("admin_routes") or [])[:12]:
        add("spa_route:admin", r, "low", [
            {"service": "Wayback CDX", "query":
                f"http://web.archive.org/cdx/search/cdx?url={base_host}{r}*&output=json"
                if base_host else r},
            {"service": "urlscan.io", "query": f'page.url:"{r}"'},
        ], "Operator/admin route declared in the app's own router — the panel the public funnel "
           "never links to. NOT fetched by this tool: check the archive first, and treat visiting "
           "it live as a separate authorization decision.")

    # What the application DOES to a victim — deposit/withdraw/KYC/referral tells you the
    # scam's mechanics without walking the funnel.
    for r in (routes.get("funnel_routes") or [])[:12]:
        add("spa_route:funnel", r, "low", [
            {"service": "Wayback CDX", "query":
                f"http://web.archive.org/cdx/search/cdx?url={base_host}{r}*&output=json"
                if base_host else r},
            {"service": "PublicWWW", "query": r},
        ], "Money/identity route from the app's router (deposit, withdraw, KYC, referral…) — "
           "reads out the funnel's mechanics without clicking through it.")

    # A distinctive route NAME is the developer's own vocabulary for the app; the same
    # unusual name under another brand is the same codebase.
    for nm in (routes.get("route_names") or [])[:8]:
        if len(nm) >= 6 and not nm.lower() in ("index", "home", "login", "layout", "default",
                                               "notfound", "not-found", "error", "about"):
            add("spa_route_name", nm, "low", [
                {"service": "PublicWWW", "query": nm},
                {"service": "Google/Yandex dork", "query": f'"{nm}"'},
            ], "Named route from the app's router — the developer's own vocabulary. An unusual "
               "name reused under another brand points at the same codebase.")

    # --- well-known / policy files ---
    wk = assets.get("well_known") or {}

    # ads.txt / app-ads.txt publisher accounts. A `pub-…` id is an owner-registered Google
    # AdSense/AdManager account — Tier-A, same strength class as a GA4 property or GSC token.
    for _which in ("ads_txt", "app_ads_txt"):
        for pub in ((wk.get(_which) or {}).get("publishers") or [])[:15]:
            pid, exch = pub.get("publisher_id"), pub.get("exchange")
            if not pid:
                continue
            is_google = "google" in (exch or "") and str(pid).startswith("pub-")
            add("adstxt_publisher", pid, "high" if is_google else "medium", [
                {"service": "PublicWWW", "query": pid},
                {"service": "FOFA", "query": _fofa_body(pid)},
                {"service": "Google dork", "query": f'"{pid}" filetype:txt'},
                {"service": "urlscan.io", "query": f'page.url:"/ads.txt" AND "{pid}"'},
            ], f"{'AdSense/AdManager publisher account' if is_google else 'Ad-exchange seller id'} "
               f"declared in {_which.replace('_', '.')} for {exch} ({pub.get('relationship')}). "
               f"An owner-registered monetization account — a stranger cannot declare yours. "
               f"Reverse it for every other property the same operator monetizes.")

    aasa = wk.get("apple_app_site_association") or {}
    for team in (aasa.get("team_ids") or [])[:5]:
        add("apple_team_id", team, "high", [
            {"service": "Google dork", "query": f'"{team}" apple-app-site-association'},
            {"service": "PublicWWW", "query": team},
        ], "Apple Developer Program Team ID from apple-app-site-association — one paid, "
           "identity-verified account signs every app this operator ships. The iOS twin of "
           "the APK signing certificate.")
    for bid in (aasa.get("bundle_ids") or [])[:6]:
        add("ios_bundle_id", bid, "high", [
            {"service": "Apple App Store", "query": bid},
            {"service": "Google dork", "query": f'"{bid}"'},
            {"service": "PublicWWW", "query": bid},
        ], "iOS bundle identifier the site claims universal links for — hand the app to "
           "BinaryPivot for its embedded backend/C2 hosts.")

    for contact in ((wk.get("security_txt") or {}).get("contacts") or [])[:4]:
        if "@" in contact:
            add("security_contact", contact, "medium", [
                {"service": "reverse-WHOIS (email)", "query": contact},
                {"service": "crt.sh", "query": f"%.{_registrable(contact.split('@')[-1])}"},
                {"service": "breach search / Chainabuse", "query": contact},
            ], "Contact address published in security.txt — an operator-controlled mailbox; "
               "reverse-WHOIS it.")

    # robots.txt Disallow entries are LEADS (paths the operator chose to hide), not pivots —
    # emitted low so they rank below real cross-site artifacts.
    _robots = wk.get("robots_txt") or {}
    for path in (_robots.get("disallow") or [])[:10]:
        if path not in ("/", "") and len(path) > 2:
            add("robots_disallow", path, "low", [
                {"service": "direct", "query": f"https://{base_host}{path}" if base_host else path},
                {"service": "Wayback CDX", "query":
                    f"http://web.archive.org/cdx/search/cdx?url={base_host}{path}*&output=json"},
            ], "Path the operator asked crawlers not to index — an admin/staging/panel URL "
               "worth checking in the archive before touching it live.")

    # --- Victim-email (.eml) header/CDN selectors -------------------------------------------------
    # These come from a source a web capture never sees, and they arrive WITH provenance (headers +
    # a date). A sending domain on a public ESP is infrastructure (low, "the mailer, not the
    # operator"); the operator's OWN sending domain and, above all, a per-brand image URL on a
    # multi-tenant CDN are real fleet leads.
    email_h = art.get("email_headers") or {}

    def _is_esp(host):
        return bool(host) and host.endswith(ESP_DOMAINS)

    for host in uniq(list(email_h.get("sender_domains", [])) + list(email_h.get("dkim_domains", []))):
        if _is_esp(host):
            add("email:sending_infra", host, "low", [
                {"service": "crt.sh", "query": f"%.{host}"},
            ], "Return-Path / DKIM domain on a public transactional-mail provider — the mailer the "
               "operator rented, not the operator. Context only; never cluster on it.")
        else:
            add("email:sender_domain", host, "medium", [
                {"service": "crt.sh", "query": f"%.{host}"},
                {"service": "urlscan.io", "query": f"domain:{host}"},
                {"service": "CIRCL PDNS", "query": host},
            ], "Sender / DKIM-signing domain from the victim's email — in a low-effort scam this is "
               "the operator's OWN sending infrastructure. Pivot it like the seed domain.")

    for url in email_h.get("image_urls", [])[:15]:
        add("email:image_url", url, "medium", [
            {"service": "urlscan.io", "query": f'"{url}"'},
            {"service": "PublicWWW", "query": f'"{url}"'},
        ], "Image URL embedded in the operator's automated email. A logo/hero on a MULTI-TENANT CDN "
           "under a per-brand path is a fleet selector — the path template can enumerate the other "
           "brands. Recovered from a mailbox, so it carries headers + a date a scan never will.")

    for host in email_h.get("unsubscribe_hosts", [])[:10]:
        if not _is_esp(host):
            add("email:unsubscribe_host", host, "low", [
                {"service": "crt.sh", "query": f"%.{host}"},
                {"service": "urlscan.io", "query": f"domain:{host}"},
            ], "List-Unsubscribe host from the email — the CRM/ESP the operator provisioned; a "
               "non-ESP one is worth a look as operator infra.")

    for host in art.get("third_party_hosts", [])[:15]:
        add("third_party_host", host, "low", [
            {"service": "crt.sh", "query": f"%.{host}"},
            {"service": "SecurityTrails/DNSlytics", "query": host},
        ], "Non-CDN third-party host may be shared C2/infra.")

    if base_host:
        add("domain", base_host, "high", [
            {"service": "crt.sh", "query": f"%.{base_host}"},
            {"service": "urlscan.io", "query": f"domain:{base_host}"},
            {"service": "CIRCL PDNS", "query": base_host},
            {"service": "Wayback CDX", "query": f"http://web.archive.org/cdx/search/cdx?url={base_host}*&output=json&collapse=urlkey"},
            {"service": "ViewDNS reverse-IP", "query": base_host},
        ], "Certificate transparency + passive DNS for related hosts.")

        # A distinctive subdomain LABEL (e.g. `svc-a` in svc-a.site-a.example) is an operator naming
        # convention reused across their apexes — its own reverse pivot via FOFA host / CT logs.
        sub = _distinctive_subdomain(base_host)
        if sub:
            add("subdomain", sub, "medium", [
                {"service": "FOFA", "query": _fofa_host(sub)},
                {"service": "crt.sh", "query": f"https://crt.sh/?q={sub}.%25"},
                {"service": "Shodan (CT)", "query": f'ssl.cert.subject.CN:"{sub}" OR hostname:"{sub}"'},
                # tokenised `:` match, not `=` — the value is a LABEL, not a whole hostname
                *censys_queries("subdomain", sub),
            ], f"Distinctive subdomain label '{sub}' — an operator's naming convention. The same "
               f"label under other apexes (FOFA host / crt.sh label search / Shodan CT logs) is a "
               f"same-operator lead; corroborate with a second artifact before clustering.")

    # One pass adds the Censys CenQL (+ web-UI URL) to every remaining kind Censys can reverse —
    # see references/censys_queries.json -> pivot_kind_map. A second pass adds the IntelX selector
    # (+ its UI URL) to every kind IntelX searches — emails, phones, domains, IPs, wallets — so the
    # leak/paste/darknet corpus is reachable from the same pivot list even with no key at all.
    return sort_pivots(attach_hunterhow_queries(attach_intelx_queries(attach_censys_queries(pivots))))


__all__ = [_n for _n in dir() if not _n.startswith("__")]
