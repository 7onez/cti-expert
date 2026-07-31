"""wp_extract — pull pivot artifacts (trackers, crypto, QR, socials, phone, telegram, footer, favicon) from HTML/DOM."""
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

QR_DECODE_IMAGES = False

# Rotated when crawling or with --rotate-ua, so a multi-page walk doesn't hammer the
# target from one identical fingerprint. Current (2026) real desktop/mobile browsers —
# keep these fresh; a UA advertising a browser two years stale is itself a bot tell.

TRACKER_PATTERNS = [
    ("google_analytics_ua", r"\bUA-\d{4,10}-\d{1,4}\b"),
    ("google_analytics_ga4", r"\bG-[A-Z0-9]{8,12}\b"),
    ("google_tag_manager",   r"\bGTM-[A-Z0-9]{4,10}\b"),
    ("google_ads",           r"\bAW-\d{6,12}\b"),
    ("google_adsense",       r"\bca-pub-\d{10,20}\b|\bpub-\d{10,20}\b"),
    ("google_doubleclick",   r"\bDC-\d{6,12}\b"),
    ("facebook_pixel",       r"fbq\(\s*['\"]init['\"]\s*,\s*['\"](\d{10,20})['\"]"),
    ("facebook_appid",       r"fb:app_id['\"]?\s*[:=]\s*['\"]?(\d{10,20})"),
    ("yandex_metrika",       r"ym\(\s*(\d{6,10})\s*,"),
    ("hotjar",               r"hjid\s*[:=]\s*(\d{5,9})"),
    ("matomo_piwik",         r"setSiteId['\"]?\s*,\s*['\"]?(\d{1,6})['\"]?|idsite=(\d{1,6})"),
    ("segment_writekey",     r"analytics\.load\(\s*['\"]([A-Za-z0-9]{20,40})['\"]"),
    ("mixpanel",             r"mixpanel\.init\(\s*['\"]([a-f0-9]{20,40})['\"]"),
    ("sentry_dsn",           r"https://[a-f0-9]{20,64}@[\w.-]+/\d+"),
    ("cloudflare_beacon",    r"beacon\.min\.js['\"].*?token['\"]?\s*:\s*['\"]([a-f0-9]{16,64})['\"]"),
    ("clarity_ms",           r"c\.clarity\.ms/tag/([a-z0-9]{8,12})|['\"]clarity['\"]\s*,\s*['\"]script['\"]\s*,\s*['\"]([a-z0-9]{8,12})['\"]"),
    ("intercom_appid",       r"app_id\s*[:=]\s*['\"]([a-z0-9]{6,10})['\"]"),
    ("crisp_website",        r"CRISP_WEBSITE_ID\s*=\s*['\"]([a-f0-9-]{30,40})['\"]"),
]

CRYPTO_PATTERNS = [
    ("btc",   r"\b(bc1[a-zA-HJ-NP-Z0-9]{25,90}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"),
    ("eth",   r"\b0x[a-fA-F0-9]{40}\b"),
    ("xmr",   r"\b[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b"),
    ("tron",  r"\bT[1-9A-HJ-NP-Za-km-z]{33}\b"),
    ("ltc",   r"\b(ltc1[a-z0-9]{25,90}|[LM3][a-km-zA-HJ-NP-Z1-9]{26,33})\b"),
]

SOCIAL_HOSTS = {
    "twitter.com": "twitter", "x.com": "twitter", "t.me": "telegram",
    "telegram.me": "telegram", "telegram.dog": "telegram",
    "facebook.com": "facebook", "instagram.com": "instagram",
    "linkedin.com": "linkedin", "youtube.com": "youtube", "youtu.be": "youtube",
    "tiktok.com": "tiktok", "github.com": "github", "discord.gg": "discord",
    "discord.com": "discord", "vk.com": "vk", "wa.me": "whatsapp",
    "api.whatsapp.com": "whatsapp", "medium.com": "medium", "reddit.com": "reddit",
    "m.me": "messenger", "zalo.me": "zalo", "zaloapp.com": "zalo",
}

# Platform boilerplate — default artifacts shipped by hosted site builders (Wix, Squarespace,
# Shopify, Webflow). NOT operator-specific: a favicon or social handle every Wix site carries
# pivots to nothing, so these are filtered out before pivots are built (they created false
# same-operator links on masterdarrenfx.com this session).

BOILERPLATE_FAVICON_MMH3 = {
    342030173,   # Wix default favicon
}

BOILERPLATE_SOCIAL_HANDLES = {
    "facebook.com/wix", "twitter.com/wix", "instagram.com/wix", "youtube.com/wix",
    "facebook.com/squarespace", "twitter.com/squarespace", "instagram.com/squarespace",
    "facebook.com/shopify", "twitter.com/shopify", "instagram.com/shopify",
    "facebook.com/webflow", "twitter.com/webflow",
}
# Email / Sentry-DSN host suffixes that are platform system addresses, never the site owner's.

BOILERPLATE_EMAIL_HOSTS = (
    "wixpress.com", "sentry.io", "squarespace.com", "shopify.com", "webflow.com",
)

# Site-ownership verification tokens — strongly owner-tied, excellent pivots.

VERIFICATION_META = {
    "google-site-verification": "google_search_console",
    "msvalidate.01": "bing_webmaster",
    "yandex-verification": "yandex_webmaster",
    "facebook-domain-verification": "facebook_domain",
    "p:domain_verify": "pinterest",
    "ahrefs-site-verification": "ahrefs",
    "naver-site-verification": "naver",
}

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")

PHONE_RE = re.compile(r"(?<![\w.])(\+?\d[\d\s().\-]{7,16}\d)(?![\w.])")

TEL_HREF_RE = re.compile(r"""<a\b[^>]*\bhref=["']tel:([^"']+)["']""", re.I)
# Telegram deep/web links — channel, group-invite, or user. tg:// handled separately.

TG_LINK_RE = re.compile(r"""(?i)^(?:https?:)?//(?:t\.me|telegram\.me|telegram\.dog)/(.+)$""")
# Non-operator Telegram paths (share widget, Telegram's own account, in-app viewer).

TG_BOILERPLATE = {"share", "telegram", "iv", "s"}

FOOTER_RE = re.compile(r"<footer\b[^>]*>(.*?)</footer>", re.I | re.S)

FOOTER_ATTR_RE = re.compile(
    r"""<(div|section)\b[^>]*(?:class|id)=["'][^"']*footer[^"']*["'][^>]*>(.*?)</\1>""",
    re.I | re.S)
# Postal-address heuristic: a street number followed by an address keyword within a short
# span. Catches EN ("12 Baker Street, Suite 4") and common VN forms ("District 1", "Ward 5").

ADDRESS_RE = re.compile(
    r"""\b\d{1,5}[\w ,/#'-]{2,45}?\b(?:street|st\.?|road|rd\.?|avenue|ave\.?|boulevard|"""
    r"""blvd\.?|lane|ln\.?|drive|dr\.?|suite|ste\.?|floor|fl\.?|tower|building|bldg|"""
    r"""unit|room|district|ward|quarter|khu|phuong|quan)\b[\w ,#/'-]{0,45}""", re.I)
# Copyright clause stripped BEFORE address scan so the "© 2026" year isn't read as a house number.

_COPYRIGHT_CLAUSE_RE = re.compile(
    r"""(?:©|&copy;|copyright)\s*\d{0,4}(?:\s*[-–]\s*\d{4})?""", re.I)

COPYRIGHT_RE = re.compile(
    r"""(?:©|&copy;|copyright)\s*(?:\d{4}(?:\s*[-–]\s*\d{4})?)?\s*(?:by\s+)?([^.|©<>\n]{3,80})""",
    re.I)

SCRIPT_SRC_RE = re.compile(r"<script[^>]+src=[\"']([^\"']+)[\"']", re.I)

INLINE_SCRIPT_RE = re.compile(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", re.I | re.S)

LINK_HREF_RE = re.compile(r"<(?:a|link)[^>]+href=[\"']([^\"']+)[\"']", re.I)

ANCHOR_HREF_RE = re.compile(r"<a\b[^>]+href=[\"']([^\"']+)[\"']", re.I)  # crawl frontier: <a> only
# Asset/resource extensions that are never navigation targets — kept out of the crawl.

_ASSET_EXT_RE = re.compile(
    r"\.(?:ico|css|js|mjs|png|jpe?g|gif|svg|webp|avif|woff2?|ttf|eot|map|pdf|zip|"
    r"gz|mp4|webm|mp3|rss|xml|json)(?:$|\?)", re.I)

FORM_RE = re.compile(r"<form[^>]*>", re.I)

FORM_ACTION_RE = re.compile(r"action=[\"']([^\"']+)[\"']", re.I)

INPUT_NAME_RE = re.compile(r"<input[^>]+name=[\"']([^\"']+)[\"']", re.I)

META_RE = re.compile(r"<meta[^>]+>", re.I)

COMMENT_RE = re.compile(r"<!--(.*?)-->", re.S)

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)

FAVICON_RE = re.compile(r"<link[^>]+rel=[\"'][^\"']*icon[^\"']*[\"'][^>]*>", re.I)

HREF_IN_TAG_RE = re.compile(r"href=[\"']([^\"']+)[\"']", re.I)

TAG_RE = re.compile(r"<([a-zA-Z][a-zA-Z0-9]*)")

def extract_trackers(html: str):
    found = {}
    for label, pat in TRACKER_PATTERNS:
        vals = []
        for m in re.finditer(pat, html, re.I):
            v = next((g for g in m.groups() if g), m.group(0)) if m.groups() else m.group(0)
            vals.append(v)
        if vals:
            found[label] = uniq(vals)
    # GA4 IDs are canonically UPPERCASE `G-XXXXXXXXXX`. The case-insensitive match above also
    # catches web-component classes like `g-recaptcha` / `g-signin` — a false GA4 that would
    # cluster every reCAPTCHA site. Keep only the canonical uppercase form.
    if "google_analytics_ga4" in found:
        real = [v for v in found["google_analytics_ga4"] if re.fullmatch(r"G-[A-Z0-9]{8,12}", v)]
        if real:
            found["google_analytics_ga4"] = real
        else:
            del found["google_analytics_ga4"]
    return found


# --- SaaS / no-code funnel tokens: operator-controlled IDs on hosted-builder pages
# (GoHighLevel, Make/Zapier/Apps-Script automations, backend Google Sheets). These are
# attribution-grade — a stranger can't share your GHL sub-account or automation webhook.
# The separator class handles raw "/", escaped "\/", and unicode-escaped "/".

_SEP = r"(?:/|\\/|\\u002[fF])+"

SAAS_PATTERNS = [
    # GoHighLevel sub-account (location) id — in media URLs: storage.googleapis.com/msgsndr/<id>, assets.cdn.filesafe.space/<id>
    ("gohighlevel_location", rf"(?:msgsndr|filesafe\.space){_SEP}([A-Za-z0-9]{{18,24}})"),
    # Backend Google Sheet id — SheetID:"...", spreadsheets/d/<id>
    ("google_sheet", r"""(?:SheetID["']?\s*[:=]\s*["']|spreadsheets/d/)([A-Za-z0-9_-]{25,60})"""),
    # Backend Google Doc / Slides id (docs the page reads from or posts to)
    ("google_doc",   r"""(?:docs\.google\.com/)?document/d/([A-Za-z0-9_-]{25,60})"""),
    ("google_slides", r"""docs\.google\.com/presentation/d/([A-Za-z0-9_-]{25,60})"""),
    # Google Form the page collects leads with — long /forms/d/e/ id OR forms.gle short link
    ("google_form",  r"""docs\.google\.com/forms/d/(?:e/)?([A-Za-z0-9_-]{20,60})|forms\.gle/([A-Za-z0-9_-]{6,40})"""),
    # Google Drive folder / file id referenced by the page (operator asset store)
    ("google_drive", r"""drive\.google\.com/(?:drive/folders/|file/d/|open\?id=)([A-Za-z0-9_-]{20,60})"""),
    # Make.com / Integromat automation webhook (operator endpoint)
    ("make_webhook", r"(hook\.[a-z0-9-]+\.make\.com/[A-Za-z0-9]{15,})"),
    ("integromat_webhook", r"(hook\.integromat\.com/[A-Za-z0-9]{15,})"),
    # Zapier catch hook
    ("zapier_webhook", r"(hooks\.zapier\.com/hooks/catch/[0-9]+/[A-Za-z0-9]+)"),
    # Google Apps Script web-app deployment
    ("apps_script", r"(script\.google\.com/macros/s/[A-Za-z0-9_-]{20,}(?:/exec)?)"),
    # TrustedForm — TCPA lead-cert; a lead-generation tell (not an operator id)
    ("trustedform", r"((?:api|cdn|cert)\.trustedform\.com)"),
]

def extract_saas(html: str):
    found = {}
    for label, pat in SAAS_PATTERNS:
        vals = []
        for m in re.finditer(pat, html, re.I):
            # first non-empty capture group (patterns with alternations, e.g. google_form,
            # have >1 group of which only one matches), else the whole match. next()'s default
            # covers the no-groups case too — m.groups() is () → empty generator → default.
            v = next((g for g in m.groups() if g), m.group(0))
            vals.append(v)
        if vals:
            found[label] = uniq(vals)[:20]
    return found

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def _b58check_ok(s: str) -> bool:
    """True iff s is a valid base58check string (BTC/LTC legacy, TRON) — checksum verified."""
    num = 0
    for ch in s:
        i = _B58_ALPHABET.find(ch)
        if i < 0:
            return False
        num = num * 58 + i
    raw = num.to_bytes((num.bit_length() + 7) // 8, "big")
    pad = len(s) - len(s.lstrip("1"))            # leading '1' → leading zero byte
    raw = b"\x00" * pad + raw
    if len(raw) < 5:
        return False
    payload, checksum = raw[:-4], raw[-4:]
    return hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] == checksum

def _bech32_ok(s: str) -> bool:
    """True iff s is a valid bech32/bech32m string (segwit bc1/ltc1) — polymod verified."""
    s = s.lower()
    pos = s.rfind("1")
    if pos < 1 or pos + 7 > len(s):
        return False
    hrp, data = s[:pos], s[pos + 1:]
    try:
        dvals = [_BECH32_CHARSET.index(c) for c in data]
    except ValueError:
        return False
    chk = 1
    for c in [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp] + dvals:
        top = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ c
        for i, g in enumerate((0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3)):
            chk ^= g if (top >> i) & 1 else 0
    return chk in (1, 0x2bc830a3)                # bech32 (v0) or bech32m (v1+)

def valid_crypto_address(label: str, value: str) -> bool:
    """Reject regex matches that aren't real addresses (md5/asset hashes false-positive the
    legacy BTC/LTC pattern). Money-tracing depends on this — an unvalidated wallet is noise."""
    if label == "eth":
        return bool(re.fullmatch(r"0x[a-fA-F0-9]{40}", value))       # md5 has no 0x prefix
    if label == "xmr":
        return len(value) in (95, 106)                               # length-checked; no cheap checksum
    if value.lower().startswith(("bc1", "ltc1", "tb1")):
        return _bech32_ok(value)
    return _b58check_ok(value)                                       # btc/ltc/tron legacy + tron T…

def extract_crypto(text: str):
    found = {}
    for label, pat in CRYPTO_PATTERNS:
        vals = [v for v in uniq(re.findall(pat, text)) if valid_crypto_address(label, v)]
        if vals:
            found[label] = vals[:25]
    return found


# --- Android / iOS app-download artifacts -------------------------------------------
# Scam "trading/investment app" funnels push a SIDELOADED APK (the sideload itself is a
# tell) or link a store listing. The .apk URL, the host serving it, and the package name
# are all high-value pivots (backend infra + reuse across clones).

_APK_EXT_RE = re.compile(
    r"""(?:href|src|data-[\w-]+|content|url)\s*[=:]\s*["'(]?\s*"""
    r"""((?:https?:)?[^"'()\s<>]+?\.(?:apk|aab|xapk|ipa|plist))(?:\?[^"'()\s<>]*)?""", re.I)

_APK_BARE_RE = re.compile(r"""https?://[^\s"'()<>]+?\.(?:apk|aab|xapk)(?:\?[^\s"'()<>]*)?""", re.I)
# Desktop "trading terminal" installers are the other half of the scam-app funnel (Windows/macOS/
# Linux). These extensions are almost always an installer, so catch them unconditionally; the host
# serving them is backend infra and the file itself is a BinaryPivot target (hash + embedded IOCs).

_DESKTOP_EXT_RE = re.compile(
    r"""(?:href|src|data-[\w-]+|content|url)\s*[=:]\s*["'(]?\s*"""
    r"""((?:https?:)?[^"'()\s<>]+?\.(?:exe|msi|dmg|pkg|appimage|deb|rpm|jar))(?:\?[^"'()\s<>]*)?""", re.I)

_DESKTOP_BARE_RE = re.compile(
    r"""https?://[^\s"'()<>]+?\.(?:exe|msi|dmg|pkg|appimage|deb|rpm)(?:\?[^\s"'()<>]*)?""", re.I)

_PLAY_RE = re.compile(r"""play\.google\.com/store/apps/details\?[^"'\s<>]*?id=([A-Za-z0-9._]+)""", re.I)

_APPLE_RE = re.compile(r"""apps\.apple\.com/[^"'\s<>]*?/id(\d{6,})""", re.I)

_SMART_PLAY_RE = re.compile(r"""name=["']google-play-app["'][^>]*content=["'][^"']*app-id=([A-Za-z0-9._]+)""", re.I)

_SMART_APPLE_RE = re.compile(r"""name=["']apple-itunes-app["'][^>]*content=["'][^"']*app-id=(\d+)""", re.I)

_INTENT_RE = re.compile(r"""(intent://[^"'\s<>]+)""", re.I)

def extract_app_downloads(html: str, base_url: str = ""):
    """Find app-download artifacts: direct APK/AAB/IPA URLs, Play/App-Store package ids,
    smart-app-banner meta, and intent:// deep links. HTML-only (no fetch)."""
    out = {}
    apk = []
    for m in _APK_EXT_RE.finditer(html):
        apk.append(m.group(1))
    apk += _APK_BARE_RE.findall(html)
    resolved = []
    for u in apk:
        try:
            resolved.append(unwrap_wayback(urljoin(base_url or "", u)))
        except Exception:
            resolved.append(u)
    apk = uniq([u for u in resolved if re.search(r"\.(apk|aab|xapk)(\?|$)", u, re.I)])
    ipa = uniq([u for u in resolved if re.search(r"\.(ipa|plist)(\?|$)", u, re.I)])
    if apk:
        out["apk_urls"] = apk[:20]
    if ipa:
        out["ios_pkg_urls"] = ipa[:10]
    # desktop installers (Windows/macOS/Linux scam-terminal funnel)
    desk = []
    for m in _DESKTOP_EXT_RE.finditer(html):
        desk.append(m.group(1))
    desk += _DESKTOP_BARE_RE.findall(html)
    desk_res = []
    for u in desk:
        try:
            desk_res.append(unwrap_wayback(urljoin(base_url or "", u)))
        except Exception:
            desk_res.append(u)
    desk = uniq([u for u in desk_res if re.search(r"\.(exe|msi|dmg|pkg|appimage|deb|rpm|jar)(\?|$)", u, re.I)])
    if desk:
        out["desktop_installers"] = desk[:20]
    pkgs = uniq(_PLAY_RE.findall(html) + _SMART_PLAY_RE.findall(html))
    if pkgs:
        out["android_packages"] = pkgs[:15]
    appids = uniq(_APPLE_RE.findall(html) + _SMART_APPLE_RE.findall(html))
    if appids:
        out["ios_app_ids"] = appids[:15]
    intents = uniq(_INTENT_RE.findall(html))
    if intents:
        out["deep_links"] = intents[:15]
    return out


# --- QR codes -----------------------------------------------------------------------
# Scam funnels hide the "money" inside a QR image: a BTC/ETH deposit address, a Telegram
# invite, a WhatsApp/affiliate link. Two extraction paths, both worth having:
#   1) ZERO-DEP (always on): many sites render the QR through a generator SERVICE whose
#      payload sits right in the image URL query string (api.qrserver.com ...?data=,
#      Google Charts ...&chl=). We URL-decode that param directly — no image processing.
#   2) OPTIONAL (`--decode-qr`): if a QR decoder lib is present (pyzbar+PIL or OpenCV) we
#      fetch each candidate <img> (or decode an inline data: image) and read the payload
#      from the pixels. Without a lib we still REPORT the candidate images as leads to
#      decode by hand — a detected-but-undecoded QR is never silently dropped.
# NOTE: a canvas-drawn QR (qrcode.js etc.) has no <img> to read statically — capture it
# with `--render --screenshot` and decode the screenshot.

_QR_GENERATOR_PARAMS = [
    ("api.qrserver.com", "data"), ("goqr.me", "data"),
    ("chart.googleapis.com", "chl"), ("chart.apis.google.com", "chl"),
    ("quickchart.io/qr", "text"), ("qrcode.tec-it.com", "data"),
    ("qrickit.com", "d"), ("qrtag.net", "d"), ("qrcode.kaywa.com", "d"),
    ("qrcode-generator", "data"), ("amazonaws.com/qr", "data"),
]

_QR_IMG_TAG_RE = re.compile(r"<img\b[^>]*>", re.I)

_QR_SRC_RE = re.compile(r'src=["\']([^"\']+)["\']', re.I)

_QR_DATAURI_RE = re.compile(r'data:image/[a-z.+-]+;base64,[A-Za-z0-9+/=]{80,}', re.I)

def _qr_generator_payload(url: str):
    """If `url` is a known QR-generator service link, return the decoded payload param."""
    try:
        pr = urlparse(url)
    except Exception:
        return None
    hp = (pr.netloc + pr.path).lower()
    for needle, param in _QR_GENERATOR_PARAMS:
        if needle in hp:
            for k, v in parse_qsl(pr.query):
                if k == param and v:
                    return unquote(v)
    return None

def _qr_decoder_backend():
    try:
        import pyzbar.pyzbar  # noqa: F401
        from PIL import Image  # noqa: F401
        return "pyzbar"
    except Exception:
        pass
    try:
        import cv2  # noqa: F401
        import numpy  # noqa: F401
        return "cv2"
    except Exception:
        return None

def _decode_qr_bytes(raw: bytes):
    """Decode QR payload(s) from raw image bytes with whatever backend is installed."""
    backend = _qr_decoder_backend()
    if not backend or not raw:
        return []
    out = []
    try:
        if backend == "pyzbar":
            import io
            from PIL import Image
            from pyzbar.pyzbar import decode as _zdecode
            for r in _zdecode(Image.open(io.BytesIO(raw))):
                try:
                    out.append(r.data.decode("utf-8", "ignore"))
                except Exception:
                    pass
        else:
            import cv2
            import numpy as np
            img = cv2.imdecode(np.frombuffer(raw, np.uint8), cv2.IMREAD_GRAYSCALE)
            if img is not None:
                data, _, _ = cv2.QRCodeDetector().detectAndDecode(img)
                if data:
                    out.append(data)
    except Exception:
        pass
    return uniq([p for p in out if p and p.strip()])

_QR_CRYPTO_SCHEMES = {"bitcoin": "btc", "litecoin": "ltc", "ethereum": "eth",
                      "monero": "xmr", "tron": "tron"}

def _qr_strip_uri(payload: str) -> str:
    """bitcoin:bc1q...?amount=1 → bc1q...  (bare address for tracing)."""
    p = (payload or "").strip()
    m = re.match(r'^([a-zA-Z]+):([^?#\s]+)', p)
    if m and m.group(1).lower() in _QR_CRYPTO_SCHEMES:
        return m.group(2).strip()
    return p.split("?")[0].strip()

def _qr_crypto_coin(payload: str):
    """Coin label if the QR payload is a crypto address / payment URI, else None."""
    p = (payload or "").strip()
    m = re.match(r'^([a-zA-Z]+):', p)
    if m and m.group(1).lower() in _QR_CRYPTO_SCHEMES:
        return _QR_CRYPTO_SCHEMES[m.group(1).lower()]
    addr = _qr_strip_uri(p)
    for label, pat in CRYPTO_PATTERNS:
        mm = re.search(pat, addr)
        if mm:
            val = mm.group(1) if mm.groups() else mm.group(0)
            if valid_crypto_address(label, val):
                return label
    return None

def extract_qr(html: str, base_url: str = "", ua: str = DEFAULT_UA,
               proxy: str = None, decode_images: bool = False):
    """Find QR codes on the page and decode their payloads where possible.
    Returns {payloads:[{payload, via, source}], undecoded_images:[url,...]}."""
    payloads, seen = [], set()

    def _add(payload, via, source):
        payload = (payload or "").strip()
        if payload and payload not in seen:
            seen.add(payload)
            payloads.append({"payload": payload, "via": via, "source": source})

    # 1) generator-service URLs anywhere in the markup (img src, links, inline CSS)
    for m in re.finditer(r'''["'(]((?:https?:)?//[^"'()\s<>]+)''', html):
        u = m.group(1)
        if u.startswith("//"):
            u = "https:" + u
        p = _qr_generator_payload(u)
        if p:
            _add(p, "generator_param", u)

    # 2) <img> that looks like a QR (src/alt/class/id mentions qr) → decode candidate
    candidates = []
    for tag in _QR_IMG_TAG_RE.findall(html):
        low = tag.lower()
        srcm = _QR_SRC_RE.search(tag)
        src = srcm.group(1) if srcm else ""
        flat = low.replace("-", "").replace("_", "")
        if "qrcode" in flat or re.search(r'\bqr\b', low) or (src and re.search(r'qr', src, re.I)):
            candidates.append(src or "(inline)")
    datauris = _QR_DATAURI_RE.findall(html)

    # 3) optional pixel decode of candidate images / inline data-URIs
    if decode_images and _qr_decoder_backend():
        for src in candidates:
            if not src or src == "(inline)" or _qr_generator_payload(src):
                continue
            try:
                full = unwrap_wayback(urljoin(base_url or "", src))
                if full.startswith("data:"):
                    raw = base64.b64decode(full.split(",", 1)[1] + "===")
                else:
                    _, status, _, raw = fetch(full, ua=ua, proxy=proxy, timeout=15)
                    if status >= 400:
                        raw = b""
                for p in _decode_qr_bytes(raw):
                    _add(p, "image_decode", full)
            except Exception:
                pass
        for du in datauris[:10]:
            try:
                for p in _decode_qr_bytes(base64.b64decode(du.split(",", 1)[1] + "===")):
                    _add(p, "image_decode", "(inline data-uri)")
            except Exception:
                pass

    # candidates we could NOT decode (no lib / fetch failed) → surface as manual-decode leads
    decoded_srcs = {p["source"] for p in payloads}
    undecoded = []
    for src in candidates:
        if src and src != "(inline)" and src not in decoded_srcs and not _qr_generator_payload(src):
            undecoded.append(unwrap_wayback(urljoin(base_url or "", src)))
    if datauris and not any(p["via"] == "image_decode" for p in payloads):
        undecoded.append(f"(inline data-uri image x{len(datauris)})")

    out = {}
    if payloads:
        out["payloads"] = payloads
    if undecoded:
        out["undecoded_images"] = uniq(undecoded)[:15]
    return out

def fetch_assetlinks(host: str, timeout: int = 10, ua: str = DEFAULT_UA, proxy: str = None):
    """Fetch /.well-known/assetlinks.json (Android App Links). Returns the declared
    package name(s) + the APK SIGNING-CERT sha256 fingerprint(s) — a developer-level pivot
    that clusters every APK signed by the same key. None if absent/unreachable."""
    url = f"https://{host}/.well-known/assetlinks.json"
    try:
        _, status, _, body = fetch(url, timeout=timeout, ua=ua, proxy=proxy)
        if status >= 400 or not body:
            return None
        data = json.loads(body.decode("utf-8", "ignore"))
    except Exception:
        return None
    pkgs, fps = set(), set()
    for entry in data if isinstance(data, list) else []:
        tgt = (entry or {}).get("target", {})
        if tgt.get("namespace") == "android_app":
            if tgt.get("package_name"):
                pkgs.add(tgt["package_name"])
            for fp in tgt.get("sha256_cert_fingerprints", []) or []:
                fps.add(str(fp).upper().replace(" ", ""))
    if not (pkgs or fps):
        return None
    return {"packages": sorted(pkgs), "sha256_cert_fingerprints": sorted(fps)}

def extract_socials(hosts_hrefs):
    out = {}
    for href in hosts_hrefs:
        try:
            pr = urlparse(unwrap_wayback(href))
            host = strip_www(pr.netloc)
        except Exception:
            continue
        # drop platform default handles (facebook.com/wix, …) — boilerplate, not the operator
        handle = f"{host}{pr.path.rstrip('/')}".lower()
        if handle in BOILERPLATE_SOCIAL_HANDLES:
            continue
        for shost, name in SOCIAL_HOSTS.items():
            if host == shost or host.endswith("." + shost):
                out.setdefault(name, []).append(href)
    return {k: uniq(v)[:20] for k, v in out.items()}

def extract_meta(html: str):
    meta = {}
    for tag in META_RE.findall(html):
        name = _attr(tag, "name") or _attr(tag, "property") or _attr(tag, "http-equiv")
        content = _attr(tag, "content")
        if name and content:
            meta[name.lower()] = content
    t = TITLE_RE.search(html)
    if t:
        meta["_title"] = re.sub(r"\s+", " ", t.group(1)).strip()[:300]
    return meta

def _norm_phone(raw: str):
    """Normalize a phone string to '+<digits>' / '<digits>' or None if it isn't plausibly a
    phone. Rejects too-short/too-long runs, all-same-digit sequences, and pure years."""
    s = (raw or "").strip()
    plus = s.startswith(("+", "00"))
    digits = re.sub(r"\D", "", s)
    if s.startswith("00"):
        digits = digits[2:]                       # 00-prefixed international → drop the 00
    if not (8 <= len(digits) <= 15):
        return None
    if len(set(digits)) <= 1:                     # 00000000 / 11111111 — placeholder, not a number
        return None
    return ("+" if plus else "") + digits

def extract_phones(html: str):
    """Phone numbers on the page. `tel:` hrefs are trusted outright; free-text matches are
    accepted only when they carry phone punctuation or a '+' country code, so prices, dates,
    order-ids and license numbers don't create bogus contact pivots."""
    out = []
    for raw in TEL_HREF_RE.findall(html):
        n = _norm_phone(unquote(raw))
        if n:
            out.append(n)
    text = re.sub(r"<[^>]+>", " ", html)          # strip tags so we scan visible text
    for m in PHONE_RE.finditer(text):
        raw = m.group(1)
        if "+" not in raw and not re.search(r"[()\-–\s]", raw):
            continue                              # a bare digit run with no separators → not a phone
        n = _norm_phone(raw)
        if n and n not in out:
            out.append(n)
    return uniq(out)[:20]

def extract_telegram(hrefs):
    """Dedicated on-page Telegram artifacts from outbound links: channels, group-invite links
    (t.me/+hash, /joinchat/), and user handles. Operator-controlled contact infra — a reused
    channel/invite clusters the operator's properties. Returns [{url, kind, handle}].

    Telegram handles may also appear under socials.telegram (same source links); this view is
    classified + normalized for pivoting. Share widgets / Telegram's own account are dropped."""
    out, seen = [], set()
    for href in hrefs or []:
        u = unwrap_wayback(href)
        low = u.lower()
        path = None
        if low.startswith("tg://"):
            q = dict(parse_qsl(urlparse(u).query))
            path = q.get("domain") or (("+" + q["invite"]) if q.get("invite") else None)
        else:
            m = TG_LINK_RE.match(u)
            if m:
                path = m.group(1)
        if not path:
            continue
        path = path.strip("/").split("?")[0].split("#")[0]
        if not path:
            continue
        first = path.split("/")[0].lower()
        if first in TG_BOILERPLATE:
            continue
        if path.startswith("+") or first == "joinchat":
            kind, handle = "invite", path
        else:
            kind, handle = "channel", first
        if handle.lower() in seen:
            continue
        seen.add(handle.lower())
        out.append({"url": u, "kind": kind, "handle": handle})
    return out[:20]

def extract_footer(html: str):
    """Footer intelligence: the footer text block plus a distinctive postal address and the
    copyright/company string. A unique registered address or company name in the footer is a
    real pivot — source-search it to find the operator's other sites. Returns {} if no footer."""
    blocks = FOOTER_RE.findall(html)
    if not blocks:
        blocks = [b for _tag, b in FOOTER_ATTR_RE.findall(html)]
    if not blocks:
        return {}
    text = re.sub(r"\s+", " ", " ".join(re.sub(r"<[^>]+>", " ", b) for b in blocks)).strip()
    if not text:
        return {}
    out = {"text": text[:600]}
    # Strip the "© 2026" clause first so ADDRESS_RE's leading \d doesn't read the year as a
    # house number (e.g. "© 2026 District 1" → a bogus "2026 District 1" address).
    addr_text = _COPYRIGHT_CLAUSE_RE.sub(" ", text)
    addrs = uniq([re.sub(r"\s+", " ", a).strip(" ,")
                  for a in ADDRESS_RE.findall(addr_text)])
    addrs = [a for a in addrs if len(a) >= 8][:8]
    if addrs:
        out["addresses"] = addrs
    cm = COPYRIGHT_RE.search(text)
    if cm:
        company = cm.group(1).strip(" ©.-|·•–")
        # trim trailing boilerplate ("All rights reserved", "Ltd") noise off the tail
        company = re.split(r"\s*(?:all rights reserved|\|)", company, 1, re.I)[0].strip()
        if 2 < len(company) <= 80:
            out["copyright"] = company
    return out

def dom_skeleton_hash(html: str):
    """Structure-only fingerprint: hash of the ordered tag skeleton (template reuse)."""
    tags = TAG_RE.findall(html)
    skeleton = ">".join(t.lower() for t in tags)
    return hashlib.sha1(skeleton.encode("utf-8", "ignore")).hexdigest()

def tech_fingerprint(html: str, headers: dict, meta: dict):
    fp = []
    low = html.lower()
    gen = meta.get("generator", "")
    if gen:
        fp.append("generator:" + gen)
    if "wp-content" in low or "wp-includes" in low:
        fp.append("cms:wordpress")
    if "/sites/default/files" in low or "drupal-settings-json" in low:
        fp.append("cms:drupal")
    if "cdn.shopify.com" in low or "shopify" in gen.lower():
        fp.append("platform:shopify")
    if "wixstatic.com" in low or "wix.com" in low:
        fp.append("platform:wix")
    if "__next" in low or "/_next/" in low:
        fp.append("framework:nextjs")
    if "data-reactroot" in low or "react" in low[:20000]:
        fp.append("framework:react")
    for h in ("server", "x-powered-by", "x-generator", "x-aspnet-version", "via", "x-served-by"):
        if h in headers:
            fp.append(f"header:{h}={headers[h]}")
    jq = re.search(r"jquery[.\-/]?(\d+\.\d+\.\d+)", low)
    if jq:
        fp.append("lib:jquery@" + jq.group(1))
    return uniq(fp)

def get_favicon(base_url: str, html: str, ua: str, proxy: str = None):
    """Locate + fetch favicon, return hash dict or None."""
    href = None
    m = FAVICON_RE.search(html)
    if m:
        h = HREF_IN_TAG_RE.search(m.group(0))
        if h:
            href = h.group(1)
    if base_url:
        fav_url = urljoin(base_url, href) if href else urljoin(base_url, "/favicon.ico")
    elif href:
        fav_url = href
    else:
        return None
    if not fav_url.startswith("http"):
        return None
    try:
        _, status, _, raw = fetch(fav_url, ua=ua, proxy=proxy)
        if status != 200 or not raw:
            return None
        return {
            "url": fav_url,
            "shodan_mmh3": shodan_favicon_hash(raw),
            "md5": hashlib.md5(raw).hexdigest(),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "bytes": len(raw),
        }
    except Exception:
        return None


# label -> (confidence, note, source-code-search services). trustedform has no operator id
# to pivot on, so it's recorded as an artifact but not emitted as a pivot (None).


__all__ = [_n for _n in dir() if not _n.startswith("__")]
