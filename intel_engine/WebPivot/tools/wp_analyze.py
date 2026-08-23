"""wp_analyze — orchestration: analyze() a page, render leads, live enrichment, WHOIS pivots."""
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
from wp_refs import ref_path, load_ref  # noqa — reference DATA lives in references/*.json
import wp_extract  # for the QR_DECODE_IMAGES toggle main() sets
import wp_assets   # asset layer: JS bundles, source maps, well-known files, API endpoints
import wp_docmeta  # document/image metadata layer: hosted PDFs + images → /Info, XMP, EXIF
from wp_censys import censys_configured, censys_webproperty, censys_certificate
import wp_pssl     # CIRCL passive SSL: the historical cert->IP direction (origin recovery)
# NOTE: wp_ippivot is imported LAZILY at its call site, not here — it imports
# classify_ip back out of this module, so a top-level import is circular.
try:
    import whois_enrich  # WhoisXML registration pivots (optional, same tools/ dir)
    HAVE_WHOIS = True
except Exception:
    HAVE_WHOIS = False

def analyze(source: str, html: str, base_url: str, headers: dict, ua: str,
            extra_cookies=None, proxy: str = None, probe_tls: bool = True,
            probe_http: bool = True, extra_artifacts: dict = None):
    # Unwrap Wayback/archive wrappers so the *original* site is treated as the origin.
    effective_url = unwrap_wayback(base_url) if base_url else ""
    is_archived = bool(base_url) and effective_url != base_url
    self_host = strip_www(urlparse(effective_url).netloc) if effective_url else ""

    meta = extract_meta(html)
    verifications = {label: meta[k] for k, label in VERIFICATION_META.items() if k in meta}
    trackers = extract_trackers(html)
    # drop platform-owned Sentry DSNs (e.g. *.wixpress.com) — boilerplate, not the operator
    if "sentry_dsn" in trackers:
        kept = [v for v in trackers["sentry_dsn"]
                if not any(h in v.lower() for h in BOILERPLATE_EMAIL_HOSTS)]
        if kept:
            trackers["sentry_dsn"] = kept
        else:
            del trackers["sentry_dsn"]
    saas_ids = extract_saas(html)
    crypto = extract_crypto(html)

    emails = [e for e in uniq(EMAIL_RE.findall(html))
              if (el := e.lower()) and not el.endswith((".png", ".jpg", ".gif", ".svg", ".webp"))
              and not el.split("@")[-1].endswith(BOILERPLATE_EMAIL_HOSTS)][:40]

    script_srcs = uniq(SCRIPT_SRC_RE.findall(html))
    all_hrefs = uniq(LINK_HREF_RE.findall(html))
    socials = extract_socials(all_hrefs)
    telegram = extract_telegram(all_hrefs)
    phones = extract_phones(html)
    footer = extract_footer(html)
    # Copy-pasted disclaimer/risk/T&C prose — survives a full re-skin and reverse-searches verbatim.
    prose_selectors = extract_prose_selectors(html)
    # Page description — owner-written copy; verbatim reuse across sites is a template tell.
    description = meta.get("description") or meta.get("og:description")
    # ETag response header — a strong etag on a static asset can fingerprint a shared origin/kit.
    etag = headers.get("etag")

    # --- ASSET LAYER: the page's own JS bundles, their source maps, the well-known/policy
    # files, and the backend the build was compiled against. On an SPA kit the shell HTML is
    # empty and ALL of the operator config lives here, so the extractors above are re-run over
    # the bundle source and their results merged in (provenance kept in assets.js_derived).
    # Same gate as the TLS/mail probes: live primary page only, never an archived or offline
    # source, never re-run per crawled sub-page. Unlike the raw-socket TLS probe this routes
    # through fetch(), so a --proxy is honored and no OPSEC suppression is needed.
    assets = None
    if probe_http and effective_url and not is_archived and base_url:
        assets = wp_assets.collect(script_srcs, base_url, self_host,
                                   ua=ua, proxy=proxy, timeout=20, html=html)
        jd = assets.get("js_derived") or {}
        for label, vals in (jd.get("trackers") or {}).items():
            trackers[label] = uniq(list(trackers.get(label, [])) + list(vals))
        for label, vals in (jd.get("saas_ids") or {}).items():
            saas_ids[label] = uniq(list(saas_ids.get(label, [])) + list(vals))
        for label, vals in (jd.get("crypto") or {}).items():
            crypto[label] = uniq(list(crypto.get(label, [])) + list(vals))
        for net, handles in (jd.get("socials") or {}).items():
            socials[net] = uniq(list(socials.get(net, [])) + list(handles))
        # telegram entries are dicts ({url,kind,handle}) — uniq() can't hash them, so
        # de-dup on the handle the way extract_telegram itself does.
        _tg_seen = {t.get("handle", "").lower() for t in telegram}
        for t in (jd.get("telegram") or []):
            h = (t.get("handle") or "").lower()
            if h and h not in _tg_seen:
                _tg_seen.add(h)
                telegram.append(t)
        emails = uniq(list(emails) + list(jd.get("emails") or []))[:40]

    # --- DOCUMENT / IMAGE METADATA: the files the site HOSTS, not the page itself. A page is
    # cheap to re-skin; the PDF "licence" and the operator's own photographs are not re-made when
    # the brand changes, so /Info, XMP and EXIF outlive every cosmetic rotation. Same gate as the
    # asset layer (live primary page only, routed through fetch() so --proxy is honored) because
    # it likewise DOWNLOADS FILES FROM THE TARGET.
    docmeta = None
    if probe_http and effective_url and not is_archived and base_url:
        docmeta = wp_docmeta.collect(html, base_url, self_host, ua=ua, proxy=proxy)

    third_party = []
    for u in script_srcs + all_hrefs:
        try:
            resolved = unwrap_wayback(urljoin(base_url or "", u))
            h = strip_www(urlparse(resolved).netloc)
        except Exception:
            continue
        if h and self_host and h != self_host and not h.endswith("." + self_host):
            third_party.append(h)
    common_cdn = ("googleapis.com", "gstatic.com", "cloudflare.com", "jsdelivr.net",
                  "cdnjs.cloudflare.com", "unpkg.com", "fontawesome.com", "bootstrapcdn.com")
    archive_infra = ("archive.org",)  # Wayback wrapper chrome, not target infra
    third_party_hosts = uniq([h for h in third_party
                              if not any(h.endswith(c) for c in common_cdn)
                              and not (is_archived and h.endswith(archive_infra))])

    inline_scripts = INLINE_SCRIPT_RE.findall(html)
    inline_hashes = [hashlib.sha256(s.encode("utf-8", "ignore")).hexdigest()
                     for s in inline_scripts if s.strip()]

    # --- CSS / stylesheet indicators (a shared theme = same kit) ---
    stylesheet_hrefs = []
    for tag in re.findall(r"<link\b[^>]*>", html, re.I):
        if re.search(r'rel=["\']?stylesheet', tag, re.I) or re.search(r'href=["\'][^"\']+\.css', tag, re.I):
            m = re.search(r'href=["\']([^"\']+)["\']', tag, re.I)
            if m:
                stylesheet_hrefs.append(unwrap_wayback(urljoin(base_url or "", m.group(1))))
    stylesheet_hrefs = uniq(stylesheet_hrefs)
    # WordPress theme / plugin slugs — a strong, human-readable shared-template tell
    wp_themes = uniq(re.findall(r"/wp-content/themes/([a-z0-9_\-]+)", html, re.I))
    wp_plugins = uniq(re.findall(r"/wp-content/plugins/([a-z0-9_\-]+)", html, re.I))
    # inline <style> block hashes — identical inline CSS across sites = template reuse
    inline_styles = re.findall(r"<style[^>]*>(.*?)</style>", html, re.I | re.S)
    inline_style_hashes = [hashlib.sha256(s.encode("utf-8", "ignore")).hexdigest()
                           for s in inline_styles if s.strip()]

    forms = []
    for fm in re.finditer(r"<form[^>]*>(.*?)</form>", html, re.I | re.S):
        block = fm.group(0)
        action = FORM_ACTION_RE.search(block)
        forms.append({
            "action": urljoin(base_url or "", action.group(1)) if action else None,
            "inputs": uniq(INPUT_NAME_RE.findall(block))[:30],
        })

    comments = [re.sub(r"\s+", " ", c).strip()[:200]
                for c in COMMENT_RE.findall(html) if c.strip()][:25]

    favicon = get_favicon(base_url, html, ua, proxy=proxy) if base_url else None
    if favicon and favicon["shodan_mmh3"] in BOILERPLATE_FAVICON_MMH3:
        favicon = None  # platform-default favicon (e.g. Wix) — drop at source, like other boilerplate
    if favicon:
        favicon["url"] = unwrap_wayback(favicon["url"])  # report the real favicon URL

    # --- live TLS certificate (SANs / issuer / SHA-256 fingerprint) ---
    # Only probe when we actually fetched the live origin over https. Never touch
    # a Wayback/archived host or an offline file/stdin source, never re-probe the
    # same host on crawled sub-pages (probe_tls=False), and NEVER probe directly
    # when a proxy is set — the raw ssl socket can't use the proxy, so a direct
    # handshake would leak the analyst's real IP the proxy exists to hide.
    tls_cert = None
    jarm = None
    if probe_tls and effective_url and not is_archived:
        parsed = urlparse(effective_url)
        if parsed.scheme == "https" and parsed.hostname:
            if proxy:
                _suppressed = {"skipped": "proxy configured — direct TLS probe suppressed (OPSEC)"}
                tls_cert = _suppressed
                jarm = _suppressed
            else:
                tls_cert = fetch_tls_cert(parsed.hostname, parsed.port or 443, timeout=8)
                # JARM: active TLS-stack fingerprint (10 handshakes) — same gating as the
                # cert probe (primary live host, never under proxy). Pivots on Shodan ssl.jarm.
                jarm = fetch_jarm(parsed.hostname, parsed.port or 443, timeout=8)

    # --- CORS policy (which origins/backends the server trusts) ---
    # Passive read of any ACAO already on the fetched response, then — for a live origin —
    # an active preflight+GET carrying a foreign Origin to see what the server reflects.
    # Unlike the raw-socket TLS probe this routes through fetch(), so a --proxy is honored;
    # still gated to live http(s) (never archived/offline) and only on the primary page
    # (probe_http=False on crawled sub-pages) to avoid an extra request per page.
    cors = extract_cors(headers)
    if probe_http and effective_url and not is_archived:
        parsed = urlparse(effective_url)
        if parsed.scheme in ("http", "https") and parsed.hostname:
            cors = merge_cors(cors, probe_cors(effective_url, ua=ua, proxy=proxy, timeout=12))

    # --- mail server / provider (dig MX) ---
    # Gated to the primary live page of a real domain (never archived/offline, and
    # probe_tls=False on crawled sub-pages — MX is per-domain, one query suffices). This
    # is a recursive-resolver query, so it needs no proxy suppression (it never contacts
    # the target). Tells us the mail provider (Google Workspace / M365 / …), any custom
    # self-hosted MX host to pivot on, and whether the domain receives mail at all.
    mail = None
    if probe_tls and self_host and not is_archived:
        mail = detect_mail_provider(self_host, timeout=8)

    # --- app-download artifacts (scam trading-app / APK funnels) ---
    app_downloads = extract_app_downloads(html, base_url)
    # Android App Links: /.well-known/assetlinks.json → package + APK signing-cert sha256
    # (developer-level pivot). Same live-https / non-archived / non-proxied gate as TLS.
    if (probe_tls and effective_url and not is_archived and not proxy):
        parsed = urlparse(effective_url)
        if parsed.scheme == "https" and parsed.hostname:
            al = fetch_assetlinks(parsed.hostname, ua=ua, proxy=proxy)
            if al:
                app_downloads["assetlinks"] = al

    # --- QR codes (wallet address / Telegram / affiliate link hidden in a QR image) ---
    qr_codes = extract_qr(html, base_url, ua=ua, proxy=proxy, decode_images=wp_extract.QR_DECODE_IMAGES)
    # Expose decoded QR indicators to the KB the same way BinaryPivot does — as trackers —
    # so a reused wallet / Telegram channel / affiliate URL clusters across the case. Only
    # off-site/actionable payloads are promoted; a QR that just re-encodes this site's own
    # URL is not a pivot.
    for _item in qr_codes.get("payloads", []):
        _p = _item["payload"]
        _low = _p.lower()
        _coin = _qr_crypto_coin(_p)
        if _coin:
            trackers.setdefault(f"qr_wallet_{_coin}", []).append(_qr_strip_uri(_p))
        elif re.search(r'(?:t\.me/|telegram\.me/|tg://)', _low):
            trackers.setdefault("qr_telegram", []).append(_p)
        elif "wa.me" in _low or "api.whatsapp.com" in _low or "chat.whatsapp.com" in _low:
            trackers.setdefault("qr_whatsapp", []).append(_p)
        elif _low.startswith("http") and self_host and self_host not in _low:
            trackers.setdefault("qr_url", []).append(_p)
    trackers = {k: uniq(v) for k, v in trackers.items()}

    cookie_names = []
    if "set-cookie" in headers:
        cookie_names = uniq([c.split("=")[0].strip()
                             for c in re.split(r",(?=[^ ;]+=)", headers["set-cookie"])])
    if extra_cookies:
        cookie_names = uniq(cookie_names + [c.get("name") for c in extra_cookies if c.get("name")])

    artifacts = {
        "title": meta.get("_title"),
        "description": description,
        "meta": {k: v for k, v in meta.items() if k != "_title"},
        "verifications": verifications,
        "favicon": favicon,
        "phones": phones,
        "telegram": telegram,
        "footer": footer,
        "etag": etag,
        "tls_cert": tls_cert,
        "jarm": jarm,
        "mail": mail,
        "app_downloads": app_downloads,
        "qr_codes": qr_codes,
        "assets": assets,
        "docmeta": docmeta,
        "trackers": trackers,
        "saas_ids": saas_ids,
        "crypto": crypto,
        "prose_selectors": prose_selectors,
        "emails": emails,
        "socials": socials,
        "script_srcs": script_srcs[:60],
        "third_party_hosts": third_party_hosts,
        "inline_script_sha256": inline_hashes[:40],
        "stylesheets": stylesheet_hrefs[:40],
        "wp_themes": wp_themes,
        "wp_plugins": wp_plugins[:40],
        "inline_style_sha256": inline_style_hashes[:20],
        "forms": forms[:20],
        "html_comments": comments,
        "dom_skeleton_sha1": dom_skeleton_hash(html),
        "tech_fingerprint": tech_fingerprint(html, headers, meta),
        "cookie_names": cookie_names,
        "server_headers": {k: headers[k] for k in
                           ("server", "x-powered-by", "via", "x-served-by", "etag",
                            "content-security-policy", "strict-transport-security")
                           if k in headers},
        "cors": cors,
        # Full HTTP request/response for the fetched page — the request headers we sent
        # (UA + client hints) and every response header (minus the synthetic _status),
        # so the analyst can read the raw exchange and spot CORS/backend tells directly.
        "http": {
            "status": headers.get("_status"),
            "request_headers": _browser_headers(ua),
            "response_headers": {k: v for k, v in headers.items() if k != "_status"},
        },
    }

    # Selectors from a non-HTML source (e.g. a victim .eml's headers/CDN hosts) are merged in here
    # so they land in the artifacts record AND emit pivots through the one build_pivots path.
    if extra_artifacts:
        artifacts.update(extra_artifacts)

    pivots = build_pivots(artifacts, self_host)

    return {
        "meta": {
            "source": source,
            "final_url": effective_url or base_url,
            "host": self_host,
            # WHEN this evidence was collected (UTC) — provenance for the evidence manifest.
            "collected_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "archived_via_wayback": is_archived,
            "fetched_with": "requests" if HAVE_REQUESTS else "urllib",
        },
        "artifacts": artifacts,
        "pivots": pivots,
    }

def render_leads(result: dict) -> str:
    m = result["meta"]
    lines = [f"# Pivot leads — {m.get('host') or m['source']}", ""]
    # Coverage caveat first: a short lead list on a keyless run means the reverse-lookup indexes
    # were never queried, and that has to be visible in the same view as the leads themselves.
    cap = m.get("capability") or {}
    if cap.get("mode") and cap["mode"] != "keyed":
        lines.append(f"> 🔑 **{cap['mode'].upper()}** — {cap.get('statement', '')}")
        for b in (cap.get("reduced") or []):
            lines.append(f"> · no **{b['service']}**: {b['lost']}")
        lines.append("")
    chain = m.get("redirect_chain")
    if chain:
        hops = " → ".join([chain[0]["from"]] + [h["to"] for h in chain])
        lines.append(f"> ↪️ Redirect chain: {hops}")
        if m.get("redirect_destination"):
            lines.append(f"> Final destination host: **{m['redirect_destination']}**")
        lines.append("")
    qr = (result.get("artifacts") or {}).get("qr_codes") or {}
    if qr.get("payloads"):
        lines.append(f"> 🔳 QR decoded: {len(qr['payloads'])} payload(s) — see qr:* pivots below.")
    if qr.get("undecoded_images"):
        lines.append(f"> 🔳 QR images detected but not decoded: {len(qr['undecoded_images'])} "
                     f"(re-run with --decode-qr).")
    if qr.get("payloads") or qr.get("undecoded_images"):
        lines.append("")
    cors = (result.get("artifacts") or {}).get("cors") or {}
    if cors.get("acao"):
        _hosts = cors.get("allowed_origin_hosts") or []
        _verdict = ("reflects any Origin" if cors.get("reflects_origin")
                    else "public (*)" if cors.get("wildcard")
                    else f"trusts {', '.join(_hosts)}" if _hosts else cors["acao"])
        _cred = " +credentials" if cors.get("credentials") else ""
        lines.append(f"> 🔗 CORS: ACAO {_verdict}{_cred}"
                     + (" — trusted origins become cors_allowed_origin pivots below." if _hosts else "")
                     + (" ⚠️ reflect-any + credentials misconfig." if cors.get("reflects_origin")
                        and cors.get("credentials") else ""))
        lines.append("")
    mail = (result.get("artifacts") or {}).get("mail") or {}
    if mail.get("mx_hosts") is not None and (mail.get("provider") or mail.get("no_mx")
                                             or mail.get("custom_mx_hosts")):
        if mail.get("no_mx"):
            lines.append("> 📭 Mail: no MX records — this domain does not receive email "
                         "(throwaway / parked-scam tell).")
        else:
            prov = mail.get("provider")
            prov = ", ".join(prov) if isinstance(prov, list) else prov
            bits = []
            if prov:
                bits.append(f"provider **{prov}**")
            if mail.get("m365_tenant"):
                bits.append(f"M365 tenant `{mail['m365_tenant']}` → m365_tenant pivot")
            if mail.get("custom_mx_hosts"):
                bits.append(("self-hosted" if mail.get("self_hosted") else "custom") +
                            f" MX {', '.join(mail['custom_mx_hosts'])} → mail_server pivot")
            lines.append("> 📧 Mail (MX): " + "; ".join(bits or [", ".join(mail["mx_hosts"])]) + ".")
        spf, dmarc = mail.get("spf") or {}, mail.get("dmarc") or {}
        sd = []
        if spf:
            _snd = spf.get("custom_includes", []) + spf.get("ip4", []) + spf.get("ip6", [])
            sd.append(f"SPF `{spf.get('all') or '?all'}`"
                      + (f", {len(_snd)} custom sender(s) → pivots" if _snd else ""))
        if dmarc:
            sd.append(f"DMARC p={dmarc.get('p') or 'none'}"
                      + (f", contact {', '.join(dmarc['custom_contacts'])} → dmarc_contact pivot"
                         if dmarc.get("custom_contacts") else ""))
        elif spf is not None and mail.get("mx_hosts"):
            sd.append("no DMARC (unprotected — spoofable)")
        if sd:
            lines.append("> ✉️ " + "; ".join(sd) + ".")
        lines.append("")
    if m.get("cloudflare"):
        lines.append(f"> 🛡️ Cloudflare {m['cloudflare']} detected — a UA swap won't pass a managed "
                     f"challenge. Escalate: `--solve-cf` (FlareSolverr/browser) + a residential `--proxy`.")
    if m.get("live_error"):
        lines.append(f"> ⚠️ Live target unreachable ({m['live_error']}).")
        lines.append(f"> Recovered via: {m.get('recovered_via') or 'not archived'}.")
        us = result.get("related_urlscan", {})
        lines.append(f"> urlscan: {us.get('total', 0)} prior scans"
                     + (f", IPs {', '.join(us.get('ips', [])[:5])}" if us.get('ips') else "")
                     + (f", ASNs {', '.join(us.get('asns', [])[:3])}" if us.get('asns') else "") + ".")
        lines.append("")
    for p in result["pivots"]:
        lines.append(f"## [{p['confidence'].upper()}] {p['kind']} = {p['value']}")
        if p.get("note"):
            lines.append(f"  _{p['note']}_")
        for q in p["queries"]:
            lines.append(f"  - {q['service']}: `{q['query']}`")
        lr = p.get("live_results")
        if lr:
            dns = lr.get("dns") or {}
            if dns.get("ips"):
                lines.append(f"  - 🟢 live DNS ({dns.get('method')}): "
                             f"{', '.join(dns['ips'])}  ← ground truth")
                if dns.get("stale_passive_ips"):
                    lines.append(f"  - ⚠️ stale passive IP(s): "
                                 f"{', '.join(dns['stale_passive_ips'])} — {dns.get('note','')}")
            elif dns.get("error"):
                lines.append(f"  - 🔴 live DNS: {dns['error']}")
            fir = lr.get("fofa_ip_reverse") or {}
            if fir.get("results") is not None:
                _h = sorted({v for r in fir["results"] if r
                             and (v := (r.get("domain") or r.get("host")))})
                lines.append(f"  - 🟢 FOFA reverse on live IP: {fir.get('total', 0)} hits"
                             + (f" → {', '.join(h for h in _h[:12] if h)}" if _h else ""))
            elif fir.get("error"):
                lines.append(f"  - 🔴 FOFA reverse on live IP: error — {fir['error']}")
            c = lr.get("crtsh") or {}
            _ctsrc = "+".join(c.get("sources", ["crt.sh"]))
            if c.get("error"):
                lines.append(f"  - 🔴 CT ({'+'.join(c.get('sources_tried', ['crt.sh']))}): error — {c['error']}")
            elif "subdomains" in c:
                lines.append(f"  - 🟢 CT/SSL ({_ctsrc}): {c.get('cert_count', 0)} certs, {c.get('total', 0)} subdomains"
                             + (f" → {', '.join(c['subdomains'][:12])}" if c.get("subdomains") else ""))
                if c.get("wildcards"):
                    lines.append(f"    ⚠️ wildcard cert(s): {', '.join(c['wildcards'][:6])} — one cert may cover many sibling hosts")
                for ct in (c.get("certs") or [])[:3]:
                    iss = (ct.get("issuer") or "").replace("C=US, O=", "").split(",")[0]
                    lines.append(f"    · cert {ct.get('not_before','?')[:10]}→{ct.get('not_after','?')[:10]} [{iss}] {', '.join(ct.get('names', [])[:4])}")
            pd = lr.get("passivedns") or {}
            if pd.get("error"):
                lines.append(f"  - 🔴 passive DNS: error — {pd['error']}")
            elif "hosts" in pd:
                _h = [h["host"] for h in pd.get("hosts", [])]
                lines.append(f"  - 🟢 passive DNS: {pd.get('total', 0)} hosts"
                             + (f" → {', '.join(_h[:12])}" if _h else "")
                             + (f"  [IPs: {', '.join(pd.get('ips', [])[:6])}]" if pd.get("ips") else ""))
            f = lr.get("fofa") or {}
            if f.get("error"):
                lines.append(f"  - 🔴 FOFA: error — {f['error']}")
            elif "results" in f:
                hosts = sorted({r.get("domain") or r.get("host") for r in f["results"] if r})
                lines.append(f"  - 🟢 FOFA: {f.get('total', 0)} hits"
                             + (f" → {', '.join(h for h in hosts[:12] if h)}" if hosts else ""))
            u = lr.get("urlscan") or {}
            if u.get("error"):
                lines.append(f"  - 🔴 urlscan: error — {u['error']}")
            elif "domains" in u:
                lines.append(f"  - 🟢 urlscan: {u.get('total', 0)} hits"
                             + (f" → {', '.join(u['domains'][:12])}" if u.get("domains") else ""))
            for stk in ("reverse_whois_current", "reverse_whois_historic"):
                rw = lr.get(stk) or {}
                if rw.get("error"):
                    lines.append(f"  - 🔴 {stk}: error — {rw['error']}")
                elif "domains" in rw:
                    lines.append(f"  - 🟢 {stk}: {rw.get('count', 0)} domains"
                                 + (f" → {', '.join(rw['domains'][:12])}" if rw.get("domains") else ""))
        lines.append("")
    return "\n".join(lines)

@functools.lru_cache(maxsize=1)
def _cdn_classifier():
    """Load the cdn_ranges module + range index once. (None, None) if unavailable
    (missing cache file or import error) so IP classification degrades gracefully."""
    try:
        import cdn_ranges
        return cdn_ranges, cdn_ranges.load_ranges()
    except Exception:
        return None, None

def classify_ip(ip: str):
    """{'ip','cdn'(bool|None),'provider','kind'} — 'origin_candidate' when not a
    known CDN/cloud edge, 'cdn' otherwise. Returns kind 'unknown' if ranges absent."""
    mod, idx = _cdn_classifier()
    if idx is None:
        return {"ip": ip, "cdn": None, "provider": None, "kind": "unknown"}
    return mod.classify(ip, idx)

_DISTINCTIVE_RE = re.compile(r"\d{6,}|[A-Za-z0-9]{8,}")

# DATA: references/generic_labels.json -> resource_basename_segments. Loaded independently of
# wp_pivots (which reads the same file for subdomain_labels) so neither module depends on the
# other's import order.
_SEG_FALLBACK = {"resource_basename_segments": ["jquery", "bootstrap", "vendor", "main", "index",
                                                "app", "bundle", "min", "js", "css"]}
_GENERIC_SEGMENTS = frozenset(
    load_ref(ref_path(__file__, "generic_labels.json"), _SEG_FALLBACK)["resource_basename_segments"])

def _is_distinctive_basename(base: str) -> bool:
    """A resource basename worth a urlscan filename: reverse — one carrying a build
    hash or long token in ANY dot-segment (project_100000000_200000000_300000000.js,
    index-B3GD2NjP.js, app.7f3c9a2b.chunk.js), not a generic library/entrypoint
    name (gtm.js, app.js, jquery.min.js, bootstrap.bundle.min.js, style.css).

    Scans every segment except the extension: a segment that is a known generic
    word is ignored; a NON-generic segment with a 6+ digit run or an 8+ char
    alnum token makes the basename distinctive."""
    segs = base.lower().split(".")[:-1]     # drop extension
    for s in segs:
        if s in _GENERIC_SEGMENTS:
            continue
        if _DISTINCTIVE_RE.search(s):
            return True
    return False

def _resource_filename_for(result: dict, kind: str, val, seed_reg: str):
    """Basename of a DISTINCTIVE external resource tied to a saas token or a
    third-party host — for a urlscan `filename:` reverse. SaaS tokens and 3rd-party
    infra live inside a loaded resource URL (not page text), so urlscan indexes them
    by filename, not content. Returns the basename or None."""
    arts = result.get("artifacts") or {}
    srcs = list(arts.get("script_srcs") or []) + list(arts.get("stylesheets") or [])
    for u in srcs:
        if not u or "://" not in u:               # only absolute, externally-fetched resources
            continue
        host = urlparse(u).netloc.lower()
        if seed_reg and _registrable(host) == seed_reg:   # the seed's own asset — not a link
            continue
        base = u.split("?")[0].split("#")[0].rstrip("/").split("/")[-1]
        if not base or "." not in base or not _is_distinctive_basename(base):
            continue
        if kind == "third_party_host" and host == str(val).lower():
            return base
        if kind.startswith("saas:") and str(val) in u:
            return base
    return None

def enrich_live(result: dict, fofa_full: bool = False, free_only: bool = False) -> dict:
    """Run live pivots and attach the real hits to each pivot as pivot['live_results'].

    Keyless always-on: the base `domain` pivot is resolved live via crt.sh
    (certificate transparency), HackerTarget passive DNS, and an anonymous urlscan
    domain search — no API key required. Keyed extras when configured: FOFA reverses
    favicon icon_hash and tracker/verification bodies; authenticated urlscan
    content-searches the same tracker/token values.

    fofa_full=True runs every FOFA reverse over ALL historical data (`full=true`)
    instead of the default ~1-year window.

    free_only=True forces the FREE/keyless sources only — even when metered keys are
    configured it skips FOFA, CIRCL passive DNS, and urlscan-Pro similarity, so the
    autonomous convergence loop never spends credits without analyst approval.
    """
    have_fofa = bool(_secret("FOFA_KEY", "FOFA_API_KEY")) and not free_only
    have_urlscan = bool(_secret("URLSCAN_API_KEY")) and not free_only  # gates only Pro similarity
    have_pdns = bool(_secret("PDNS_USERNAME") and _secret("PDNS_PASSWORD")) and not free_only
    # Censys is metered in CREDITS (1 per lookup, and a free plan gets only 100 a month), so it is
    # gated exactly like FOFA. Only the two LOOKUP endpoints are used here — they work on the free
    # plan, unlike /search/query, which needs Starter.
    have_censys = censys_configured() and not free_only
    # Passive SSL rides the SAME CIRCL credential pair as passive DNS. The two are the historical
    # name->IP and cert->IP halves of one question, so a run that has pDNS should always have
    # pSSL as well — before this layer existed the cert->IP direction was simply never asked.
    have_pssl = wp_pssl.pssl_configured() and wp_pssl.ENABLED and not free_only
    # IPinfo answers "where is this address and whose is it" — country, ASN/org, abuse contact,
    # hosting/proxy/VPN flags. It runs keyless too (rate-limited), so the gate is --free-only
    # rather than the token: without a token it still returns country + org for the live IP.
    have_ipinfo = not free_only
    sources = ["crtsh", "passivedns", "urlscan"]  # keyless domain enrichment
    if have_fofa:
        sources.append("fofa-full" if fofa_full else "fofa")
    if have_pdns:
        sources.append("pdns")
    if have_pssl:
        sources.append("pssl")
    if have_ipinfo:
        sources.append("ipinfo")
    if have_censys:
        sources.append("censys")
    result.setdefault("meta", {})["enriched_with"] = sources
    for piv in result.get("pivots", []):
        kind, val = piv.get("kind", ""), piv.get("value")
        lr = {}
        if kind == "domain" and val:
            # LIVE DNS FIRST, then keyless CT + passive DNS + urlscan on the base host.
            # All four are independent I/O, so run them concurrently — bounds latency to
            # the slowest call instead of the sum (crt.sh is often overloaded).
            jobs = {"dns": lambda: resolve_live_dns(val),
                    "crtsh": lambda: ct_search(val),   # crt.sh + Shodan CTL merged (resilient)
                    "passivedns": lambda: passivedns_search(val),
                    "urlscan": lambda: urlscan_search(f"domain:{val}")}
            if have_pdns:
                jobs["pdns"] = lambda: pdns_search(val)   # CIRCL-COF passive DNS (historical IPs + co-hosted names)
            if have_urlscan:
                # urlscan Pro structure-similarity: clusters re-skinned kits (no-op/skipped on free)
                jobs["urlscan_similar"] = lambda: urlscan_similar(val)
            if have_censys:
                # Censys web property (hostname:443): the cert, favicon hashes, body hash, software
                # and threat labels Censys recorded for THIS hostname — the server's own view of
                # the page, independent of whatever the site served us just now.
                jobs["censys"] = lambda: censys_webproperty(val)
            with concurrent.futures.ThreadPoolExecutor(max_workers=7) as ex:
                futures = {k: ex.submit(fn) for k, fn in jobs.items()}
                lr = {k: fu.result() for k, fu in futures.items()}
            # Anchor pivots to the LIVE IP: reverse-search FOFA on what DNS resolves to
            # right now, and flag any passive source still reporting a different (stale) IP.
            live_ips = lr.get("dns", {}).get("ips", []) or []
            if live_ips:
                # Classify each live IP: a CDN/cloud edge (Cloudflare/Fastly/…) is
                # shared noise — reverse-searching it returns thousands of unrelated
                # tenants. Only an origin-candidate IP is worth a FOFA reverse.
                classified = [classify_ip(ip) for ip in live_ips]
                lr["dns"]["ip_classification"] = classified
                # IPinfo on the DOMAIN path. It was previously reachable only when a bare IP was
                # the input (IPPivot), so analysing a domain never produced a country, an ASN, an
                # abuse contact or a hosting/VPN flag for the address it actually resolves to —
                # the assessment fell back to keyless ip-api for an ASN string and nothing else.
                # Memoised per process (the same CDN pair recurs on every host in a case), and
                # skipped under --free-only like every other metered call.
                if have_ipinfo:
                    from wp_ippivot import ipinfo_lookup   # lazy: circular at module level
                    lr["ipinfo"] = {ip: ipinfo_lookup(ip) for ip in live_ips}
                origin_ips = [c["ip"] for c in classified if c.get("cdn") is False]
                cdn_ips = [c for c in classified if c.get("cdn") is True]
                if cdn_ips:
                    lr["dns"]["cdn_note"] = (
                        "live IP(s) are shared CDN/cloud edge (%s) — hosting IP is noise, "
                        "not an origin pivot; FOFA IP-reverse skipped for these" %
                        ", ".join(sorted({c["provider"] for c in cdn_ips if c.get("provider")})))
                # reverse the first origin candidate; if the index is unavailable
                # (kind 'unknown'), fall back to the old behaviour (reverse ip[0]).
                fofa_ip = origin_ips[0] if origin_ips else (
                    live_ips[0] if classified[0].get("cdn") is None else None)
                if have_fofa and fofa_ip:
                    lr["fofa_ip_reverse"] = fofa_search(f'ip="{fofa_ip}"',
                                                        fields="host,ip,domain,title,server",
                                                        full=fofa_full)
                if have_pdns and fofa_ip:
                    # PDNS reverse on the SAME origin candidate — co-hosted domains from
                    # passive DNS independently corroborate the FOFA IP-reverse.
                    lr["pdns_ip_reverse"] = pdns_search(fofa_ip)
                if have_pssl:
                    # PASSIVE SSL — the cert->IP direction, which is the one that recovers an
                    # ORIGIN from behind a CDN: the operator served this same leaf certificate
                    # on their own box before (or while) fronting it. Any address here that is
                    # not in the live answer is an origin candidate. The live sha1 comes from
                    # the certificate this run already read off the 443 handshake, so this adds
                    # NO extra connection to the target.
                    _leaf = ((result.get("artifacts") or {}).get("tls_cert") or {})
                    _sha1 = _leaf.get("fingerprint_sha1") or ""
                    lr["pssl"] = wp_pssl.origin_candidates(
                        val, sha1=_sha1, known_ips=live_ips)
                passive_ips = set((lr.get("passivedns") or {}).get("ips", []) or [])
                passive_ips |= set((lr.get("pdns") or {}).get("ips", []) or [])   # historical PDNS IPs
                # An origin candidate corroborated by BOTH passive halves (a name seen there, and
                # the certificate seen there) is the strongest lead this pair produces.
                _pssl_ips = set((lr.get("pssl") or {}).get("origin_candidates", []) or [])
                if _pssl_ips:
                    both = sorted(_pssl_ips & passive_ips)
                    if both:
                        lr["origin_corroborated"] = {
                            "ips": both,
                            "note": "seen by BOTH passive DNS (a name resolved there) and passive "
                                    "SSL (this leaf certificate was served there) — the strongest "
                                    "origin lead the passive pair produces; verify directly."}
                stale = sorted(passive_ips - set(live_ips))
                if stale:
                    lr["dns"]["stale_passive_ips"] = stale
                    lr["dns"]["note"] = ("passive sources report IP(s) not in live DNS — "
                                         "likely a migrated/IP-hopping host; trust live DNS")
        else:
            fofa_q = None
            if kind == "favicon_hash":
                fofa_q = f'icon_hash="{val}"'
            elif kind.startswith(("tracker:", "verification:")) or kind == "keyword":
                # keyword = analyst-flagged high-value HTML string (the IntelAnalysis chain)
                fofa_q = _fofa_body(str(val))
            elif kind == "subdomain":
                # distinctive subdomain label — reverse the same label across other apexes
                fofa_q = _fofa_host(str(val))
            if fofa_q and have_fofa:
                f = fofa_search(fofa_q, full=fofa_full)
                if f is not None:
                    lr["fofa"] = f
            # --- urlscan reverses — query form matches how urlscan indexes each artifact:
            #   tracker/verification IDs → page CONTENT search ("<id>")
            #   favicon                  → resource-HASH search (hash:<sha256>)
            #   saas token / 3p host     → resource-FILENAME search (filename:<basename>)
            # (inline-script hashes are NOT indexed — inline scripts aren't fetched
            #  resources — so they are intentionally not reversed here.)
            if have_urlscan:
                us = None
                if kind.startswith(("tracker:", "verification:")):
                    us = urlscan_search(f'"{val}"')
                elif kind == "favicon_hash":
                    sha = ((result.get("artifacts") or {}).get("favicon") or {}).get("sha256")
                    if sha:
                        us = urlscan_search(f"hash:{sha}")
                elif kind.startswith("saas:") or kind == "third_party_host":
                    seed_reg = _registrable((result.get("meta") or {}).get("host") or "")
                    fn = _resource_filename_for(result, kind, val, seed_reg)
                    if fn:
                        us = urlscan_search(f"filename:{fn}")
                        if isinstance(us, dict):
                            us["reversed_resource"] = fn      # record what we searched
                if us is not None:
                    lr["urlscan"] = us
            # --- Censys certificate LOOKUP on the leaf fingerprint. This is the highest-value
            #     Censys call a FREE plan can make: it costs 1 credit, needs no search
            #     entitlement, and returns the certificate's own `names` — every hostname on
            #     that exact cert, i.e. the operator's apex list. crt.sh gives fuzzy name
            #     overlap; this is the cert stating its own coverage.
            if have_censys and kind == "tls_cert:fingerprint_sha256" and val:
                cert = censys_certificate(str(val))
                if cert:
                    lr["censys_cert"] = cert
        if lr:
            piv["live_results"] = lr
    return result

def _whois_registrant_vals(w: dict, hist: dict, field: str):
    """Current + historical registrant `field` values, deduped, current first. field='phone'
    pulls w['registrant_phone'] then hist['registrant_phones']; same shape for email/address."""
    vals = []
    cur = w.get(f"registrant_{field}")
    if cur:
        vals.append(cur)
    for v in hist.get(f"registrant_{field}s") or []:
        if v not in vals:
            vals.append(v)
    return vals

def whois_enrich_result(result: dict, do_reverse: bool = False,
                        history_mode: str = "purchase", free_only: bool = False) -> dict:
    """Attach WHOIS registration data + registrant pivots to a result.

    Adds result['artifacts']['whois'] (registrant email/name/org, registrar, dates,
    name servers, and every historical registrant email/name), and a HIGH-confidence
    'whois:registrant_email' pivot with reverse-WHOIS queries. With do_reverse, runs
    the reverse-WHOIS live and attaches sibling domains.

    Runs on EVERY domain: WhoisXML (current+history+reverse) when keyed, else keyless
    RDAP (+ port-43). free_only=True forces the keyless RDAP path even when a WhoisXML
    key is present, so the autonomous loop spends no WhoisXML credits.
    """
    # Only a total absence of the module skips WHOIS.
    if not HAVE_WHOIS:
        return result
    host = result.get("meta", {}).get("host")
    if not host:
        return result
    w = (whois_enrich.whois_summary_keyless(host) if free_only
         else whois_enrich.whois_summary(host, history_mode=history_mode))
    if not w or w.get("error"):
        result.setdefault("meta", {})["whois_error"] = (w or {}).get("error", "no data")
        return result
    result.setdefault("artifacts", {})["whois"] = w
    # record the actual source so cost/provenance is honest (rdap / whois43 / whoisxml[+rdap])
    result.setdefault("meta", {}).setdefault("enriched_with", []).append(w.get("source", "whoisxml"))

    # registrant email → same-operator pivot (reverse WHOIS)
    hist = w.get("history") or {}
    for em in _whois_registrant_vals(w, hist, "email"):
        if whois_enrich.is_privacy(em):
            continue  # skip privacy-proxy / registrar-role addresses — not the owner
        piv = {
            "kind": "whois:registrant_email", "value": em, "confidence": "high",
            "note": "Registrant email — reverse WHOIS finds the owner's other domains.",
            "queries": [
                {"service": "WhoisXML reverse-whois", "query": f'registrant email = "{em}"'},
                {"service": "ViewDNS reverse-whois", "query": em},
                {"service": "DomainBigData", "query": em},
            ],
        }
        if do_reverse:
            for st in ("current", "historic"):
                r = whois_enrich.reverse_whois(em, "email", search_type=st)
                if r is not None:
                    piv.setdefault("live_results", {})[f"reverse_whois_{st}"] = r
        result["pivots"].append(piv)

    name = w.get("registrant_name") or w.get("registrant_org")
    if name and not whois_enrich.is_privacy(name):
        piv = {
            "kind": "whois:registrant_name", "value": name, "confidence": "medium",
            "note": ("Registrant name — reverse WHOIS finds the owner's other domains. Run "
                     "HISTORIC too: a name can tie sites that share no technical artifact "
                     "(historic-mode reverse-WHOIS by name links brands a current-only lookup misses)."),
            "queries": [
                {"service": "WhoisXML reverse-whois", "query": f'registrant name = "{name}"'},
                {"service": "ViewDNS reverse-whois", "query": name},
            ],
        }
        if do_reverse:
            for st in ("current", "historic"):
                r = whois_enrich.reverse_whois(name, "name", search_type=st)
                if r is not None:
                    piv.setdefault("live_results", {})[f"reverse_whois_{st}"] = r
        result["pivots"].append(piv)

    # A phone or address sitting in a PRIVACY-PROXIED record belongs to the proxy, whatever the
    # digits: Domains By Proxy publishes one switchboard and one Tempe address across every domain
    # it fronts, and neither string carries a privacy marker of its own to catch. So judge the
    # RECORD, not the value — this covers proxies no denylist has enumerated.
    _proxied = any(whois_enrich.is_privacy(v) for v in
                   (w.get("registrant_email"), w.get("registrant_org"), w.get("registrant_name"))
                   if v)

    # registrant phone → reverse-WHOIS-by-phone pivot (current + historical numbers)
    for ph in _whois_registrant_vals(w, hist, "phone"):
        if _proxied or whois_enrich.is_privacy(ph):
            continue  # registrar/privacy-proxy phone (e.g. Dynadot's) — not the owner
        result["pivots"].append({
            "kind": "whois:registrant_phone", "value": ph, "confidence": "medium",
            "note": "Registrant phone — reverse-WHOIS by phone finds the owner's other domains.",
            "queries": [
                {"service": "WhoisXML reverse-whois", "query": f'registrant phone = "{ph}"'},
                {"service": "ViewDNS reverse-whois", "query": ph},
                {"service": "PublicWWW / search", "query": f'"{ph}"'},
            ],
        })

    # registrant address → reverse-WHOIS-by-address pivot (a distinctive address ties siblings)
    for ad in _whois_registrant_vals(w, hist, "address"):
        if _proxied or whois_enrich.is_privacy(ad):
            continue
        result["pivots"].append({
            "kind": "whois:registrant_address", "value": ad, "confidence": "medium",
            "note": ("Registrant postal address — reverse-WHOIS by address ties domains that "
                     "share no technical artifact. Skip generic registrar/city-only addresses."),
            "queries": [
                {"service": "WhoisXML reverse-whois", "query": f'registrant address = "{ad}"'},
                {"service": "ViewDNS reverse-whois", "query": ad},
            ],
        })
    return result


# Two-part public suffixes so _registrable() keeps 3 labels for e.g. bbc.co.uk.


__all__ = [_n for _n in dir() if not _n.startswith("__")]
