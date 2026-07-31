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
from wp_common import *  # noqa
from wp_extract import *  # noqa

SAAS_PIVOTS = {
    "gohighlevel_location": ("high", "GoHighLevel sub-account (location) ID. Same GHL tenant = same operator; find its whole portfolio."),
    "google_sheet": ("high", "Backend Google Sheet ID embedded in the page. Same sheet = same operator — and it may be publicly readable (check for exposed leads/PII)."),
    "google_doc": ("high", "Backend Google Doc ID embedded in the page. Same doc = same operator — and it may be publicly readable."),
    "google_slides": ("high", "Backend Google Slides ID embedded in the page. Same deck = same operator."),
    "google_form": ("high", "Google Form the page collects leads with — operator-controlled. Same form = same operator (responses may be readable)."),
    "google_drive": ("high", "Google Drive folder/file ID referenced by the page — operator asset store. Same ID = same operator."),
    "make_webhook": ("high", "Make.com automation webhook — operator-controlled endpoint. Same token = same operator."),
    "integromat_webhook": ("high", "Integromat/Make automation webhook — operator-controlled. Same token = same operator."),
    "zapier_webhook": ("high", "Zapier catch hook — operator-controlled automation endpoint. Same token = same operator."),
    "apps_script": ("high", "Google Apps Script web-app the form posts to — operator-controlled. Same deployment = same operator."),
    "trustedform": (None, "TrustedForm (TCPA lead certification) — signals a lead-generation funnel; not an operator pivot."),
}


# Query params that carry affiliate / referral / campaign attribution. A redirector's
# destination usually stamps the promoter's code here (affid=…, 8c=…, ref=…) — that code
# is the real pivot: source-search it to find where the affiliate promotes the link.

AFFILIATE_PARAMS = {
    "affid", "aff", "aff_id", "affiliate", "affiliateid", "ref", "refid", "ref_id",
    "referral", "referralcode", "partner", "partnerid", "pid", "subid", "sub_id",
    "clickid", "click_id", "btag", "a_aid", "a_bid", "promo", "promocode", "invite",
    "invitecode", "agent", "agentid", "ib", "8c",
}

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


# Subdomain labels that are generic infrastructure/service names — a shared one clusters nothing,
# so they are NOT treated as a distinctive same-operator signal.
_GENERIC_SUBLABELS = {
    "www", "www2", "www3", "web", "m", "mobile", "wap", "amp", "api", "api2", "app", "apps",
    "mail", "email", "webmail", "smtp", "imap", "pop", "pop3", "mx", "mx1", "mx2", "autodiscover",
    "autoconfig", "ns", "ns1", "ns2", "ns3", "ns4", "dns", "cpanel", "whm", "webdisk", "ftp",
    "sftp", "cdn", "cdn1", "cdn2", "static", "assets", "img", "images", "media", "js", "css",
    "files", "download", "downloads", "dl", "admin", "portal", "dashboard", "panel", "my",
    "account", "accounts", "login", "signin", "sso", "auth", "secure", "vpn", "remote", "gw",
    "gateway", "proxy", "blog", "news", "shop", "store", "support", "help", "docs", "wiki",
    "status", "stats", "test", "dev", "staging", "stage", "uat", "demo", "beta", "sandbox",
    "local", "localhost", "go", "link", "links", "l", "t", "track", "click", "e", "c", "s",
    "server", "host", "vps", "cloud", "edge", "origin",
}


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
            {"service": "Censys", "query": f'services.http.response.favicons.md5_hash={fav["md5"]}'},
            {"service": "Netlas", "query": f'http.favicon.hash_sha256:{fav["sha256"]}'},
        ], "Same favicon across unrelated domains = shared operator/kit.")

    cert = art.get("tls_cert")
    if cert and not cert.get("error") and not cert.get("skipped"):
        fp = cert.get("fingerprint_sha256")
        if fp:
            add("tls_cert:fingerprint_sha256", fp, "high", [
                {"service": "Censys", "query": f"services.tls.certificates.leaf_data.fingerprint_sha256:{fp}"},
                {"service": "Validin", "query": fp},
                {"service": "crt.sh", "query": f"https://crt.sh/?q={fp}"},
            ], "Every host serving this exact certificate = same operator/deployment.")
        # Co-SAN: SANs on a DIFFERENT registrable domain than the seed are a strong
        # cross-brand operator link (one cert covering many apexes). Same-site
        # subdomains are just this domain's own hosts — not a pivot.
        seed_reg = _registrable(base_host) if base_host else ""
        co_apexes = uniq([r for s in cert.get("sans", [])
                          if (r := _registrable(s)) and r != seed_reg])
        if co_apexes:
            queries = [{"service": "Censys", "query":
                        f"services.tls.certificates.leaf_data.fingerprint_sha256:{fp}"}] if fp else []
            for apex in co_apexes[:20]:
                queries += [
                    {"service": "crt.sh", "query": f"%.{apex}"},
                    {"service": "urlscan.io", "query": f"domain:{apex}"},
                ]
            add("tls_cert:co_san", ", ".join(co_apexes[:20]), "high", queries,
                "Distinct registrable domains sharing one TLS certificate = same operator.")

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
                {"service": "Shodan CTL / Censys", "query": f"names: {sub}.*"},
            ], f"Distinctive subdomain label '{sub}' — an operator's naming convention. The same "
               f"label under other apexes (FOFA host / crt.sh label search / Shodan CT logs) is a "
               f"same-operator lead; corroborate with a second artifact before clustering.")

    return sort_pivots(pivots)


__all__ = [_n for _n in dir() if not _n.startswith("__")]
