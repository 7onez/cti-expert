"""wp_common — shared constants, regexes, and stdlib helpers for WebPivot."""
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
from wp_refs import ref_path, load_ref  # noqa: E402 — reference DATA in references/*.json

# --- egress proxy / rotation: install IN THIS PROCESS so a SOCKS pool's socket
# hook also covers raw TLS dials (WebPivot tools run as their own subprocess under
# intel.py and would otherwise only inherit env, leaving raw sockets direct). ----
def _install_cti_proxy():
    import os as _o, sys as _s
    _b = _o.path.dirname(_o.path.abspath(__file__))
    while True:
        for _sub in ("scripts/proxy", "proxy"):
            _c = _o.path.join(_b, _sub, "cti_proxy.py")
            if _o.path.isfile(_c):
                _s.path.insert(0, _o.path.dirname(_c))
                try:
                    import cti_proxy
                    cti_proxy.install()
                except Exception:
                    pass
                return
        _p = _o.path.dirname(_b)
        if _p == _b:
            return
        _b = _p
_install_cti_proxy()

# DATA: how we present ourselves when fetching, and the public-suffix table. Both go stale on a
# schedule nobody controls (browser releases; new ccTLD second levels), so both are tunable.
_FP_FALLBACK = {"ua_pool": ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                            "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"],
                "cloudflare_body_markers": ["just a moment", "cf_chl_", "attention required"]}
_FP_REF = load_ref(ref_path(__file__, "fetch_profile.json"), _FP_FALLBACK)
_GLC_FALLBACK = {"multi_part_tlds": ["co.uk", "com.au", "com.br", "com.vn", "com.cn"]}
_GLC_REF = load_ref(ref_path(__file__, "generic_labels.json"), _GLC_FALLBACK)


DEFAULT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
              "AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/140.0.0.0 Safari/537.36")

# Per-call ceiling for every DATA-FETCHING / API / collector / subprocess call in the engine.
# ONE resolver (wp_timeouts): process env CTI_CALL_TIMEOUT → skill-root/engine .env → the RULE 3
# reference references/timeouts.json → 1800s (30 min). Each call runs up to this long, then times
# out and the run moves on. Deliberately NOT applied to raw DNS / TLS / JARM resolution micro-probes
# (getaddrinfo/dig/nslookup/handshake) — a dead name or black-hole IP would hang the full ceiling
# there with no benefit; those keep their short fail-fast bounds.
from wp_timeouts import CALL_TIMEOUT, resolve_call_timeout as _call_timeout  # noqa: E402,F401

# Enforce CALL_TIMEOUT as the FLOOR for every HTTP call this process makes. Every API/collector call
# in the engine funnels through urllib.request.urlopen, so flooring it here (process-wide, once) makes
# "each call runs up to CALL_TIMEOUT, then moves on" hold WITHOUT editing 40 call sites — including the
# ones that pass an explicit short timeout. DNS (getaddrinfo/dig), raw-TLS and JARM probes use sockets,
# not urlopen, so their fail-fast bounds are untouched by construction. Idempotent; a test that stubs
# urllib.request.urlopen replaces this wrapper and is unaffected.
def _install_urlopen_floor():
    _orig = urllib.request.urlopen
    if getattr(_orig, "_cti_capped", False):
        return

    def _urlopen_capped(url, *args, **kwargs):
        if len(args) >= 2:                                  # positional timeout: urlopen(url, data, timeout, …)
            t = args[1]
            if not isinstance(t, (int, float)) or t < CALL_TIMEOUT:
                args = (args[0], CALL_TIMEOUT) + args[2:]
        else:
            t = kwargs.get("timeout")
            if not isinstance(t, (int, float)) or t < CALL_TIMEOUT:
                kwargs["timeout"] = CALL_TIMEOUT
        return _orig(url, *args, **kwargs)

    _urlopen_capped._cti_capped = True
    _urlopen_capped._cti_orig = _orig
    urllib.request.urlopen = _urlopen_capped


_install_urlopen_floor()

# Set by --decode-qr in main(): when true, extract_qr fetches candidate QR images and
# decodes them from pixels (needs pyzbar+PIL or OpenCV). Off by default — the zero-dep
# generator-param decode always runs regardless.

# DATA: references/fetch_profile.json -> ua_pool
UA_POOL = list(_FP_REF["ua_pool"])


# Headers common to every real browser regardless of engine. Bare User-Agent alone trips
# Cloudflare/LiteSpeed bot heuristics (we saw resets / HTTP 520 / refused this session); a
# full profile passes the cheap checks. Accept-Encoding stays gzip/deflate on purpose — the
# urllib path only decompresses those (see _decode_body); advertising br/zstd would let a
# server hand back a body we can't decode.

BROWSER_HEADERS = {
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Connection": "keep-alive",
}

def _ua_profile(ua: str) -> dict:
    """Infer (engine, platform, is_mobile, major_version) from a UA string so the rest of
    the header set can be made coherent with it. Rotating the UA without rotating the
    Client-Hint / Accept headers is the single biggest tell — a 'Safari' request that still
    sends sec-ch-ua: Chrome-on-Windows is obviously synthetic."""
    is_mobile = "Mobile" in ua or "iPhone" in ua or "Android" in ua
    if "iPhone" in ua or "iPad" in ua:
        platform = '"iOS"'
    elif "Android" in ua:
        platform = '"Android"'
    elif "Macintosh" in ua or "Mac OS X" in ua:
        platform = '"macOS"'
    elif "Windows" in ua:
        platform = '"Windows"'
    else:
        platform = '"Linux"'
    if "Firefox/" in ua:
        engine = "firefox"
    elif "Edg/" in ua:
        engine = "edge"
    elif "Chrome/" in ua:
        engine = "chrome"
    elif "Safari/" in ua and "Version/" in ua:
        engine = "safari"
    else:
        engine = "chrome"
    m = re.search(r"(?:Edg|Chrome|Firefox|Version)/(\d+)", ua)
    major = m.group(1) if m else ""
    return {"engine": engine, "platform": platform,
            "is_mobile": is_mobile, "major": major}

def _browser_headers(ua: str) -> dict:
    """Build a request header set coherent with the given UA: Chromium engines get matching
    Client Hints (sec-ch-ua brand list + platform + mobile flag) at the UA's own version;
    Firefox and Safari send NO sec-ch-ua (real ones don't) and their own Accept string."""
    p = _ua_profile(ua)
    h = dict(BROWSER_HEADERS)
    h["User-Agent"] = ua
    if p["engine"] in ("chrome", "edge"):
        h["Accept"] = ("text/html,application/xhtml+xml,application/xml;q=0.9,"
                       "image/avif,image/webp,image/apng,*/*;q=0.8,"
                       "application/signed-exchange;v=b3;q=0.7")
        v = p["major"] or "140"
        if p["engine"] == "edge":
            brands = (f'"Chromium";v="{v}", "Microsoft Edge";v="{v}", '
                      f'"Not=A?Brand";v="24"')
        else:
            brands = (f'"Chromium";v="{v}", "Google Chrome";v="{v}", '
                      f'"Not=A?Brand";v="24"')
        h["sec-ch-ua"] = brands
        h["sec-ch-ua-mobile"] = "?1" if p["is_mobile"] else "?0"
        h["sec-ch-ua-platform"] = p["platform"]
    elif p["engine"] == "firefox":
        # Firefox sends no Client Hints and no Sec-Fetch-User.
        h["Accept"] = ("text/html,application/xhtml+xml,application/xml;q=0.9,"
                       "image/avif,image/webp,*/*;q=0.8")
        h.pop("Sec-Fetch-User", None)
    else:  # safari
        # Safari sends no Client Hints either; distinct Accept ordering.
        h["Accept"] = ("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
    return h

def _decode_body(raw: bytes, content_encoding: str) -> bytes:
    """Decompress a urllib response body per its Content-Encoding (gzip/deflate); else as-is."""
    enc = (content_encoding or "").lower()
    try:
        if "gzip" in enc:
            return gzip.decompress(raw)
        if "deflate" in enc:
            try:
                return zlib.decompress(raw)
            except zlib.error:
                return zlib.decompress(raw, -zlib.MAX_WBITS)  # raw deflate
    except Exception:
        return raw
    return raw

def _expand_ip_range(spec: str):
    """Expand a final-octet IP range into a list of 'a.b.c.N[:port]' proxy strings.

    Accepts both 'a.b.c.d-e[:port]' (short) and 'a.b.c.d-a.b.c.e[:port]' (full end IP,
    same /24). Returns [] for anything that isn't this shape, so callers can fall back
    to treating the token as a literal proxy string.
    """
    m = re.match(
        r"^(?:(\w+)://)?(\d+\.\d+\.\d+)\.(\d+)-(?:(\d+\.\d+\.\d+)\.)?(\d+)(:\d+)?$",
        spec.strip())
    if not m:
        return []
    scheme, prefix, lo, prefix2, hi, port = (
        m.group(1), m.group(2), int(m.group(3)), m.group(4), int(m.group(5)), m.group(6) or "")
    if prefix2 and prefix2 != prefix:   # end IP must be in the same /24
        return []
    if lo > hi or hi > 255:
        return []
    scheme = (scheme + "://") if scheme else ""
    return [f"{scheme}{prefix}.{o}{port}" for o in range(lo, hi + 1)]

def parse_proxies(spec: str):
    """Parse a --proxy-range SPEC into a list of proxy URLs.

    SPEC may be: a path to a file (one proxy per line, '#' comments ok); a comma-separated
    list; and/or tokens containing a final-octet IP range 'a.b.c.d-e:port'. Bare host:port
    tokens get an 'http://' scheme so requests/urllib accept them. Returns [] on empty/garbage.
    """
    if not spec:
        return []
    tokens = []
    if os.path.isfile(spec):
        try:
            with open(spec, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.split("#", 1)[0].strip()
                    if line:
                        tokens.append(line)
        except Exception:
            return []
    else:
        tokens = [t.strip() for t in spec.split(",") if t.strip()]
    out = []
    for tok in tokens:
        expanded = _expand_ip_range(tok)
        for p in (expanded or [tok]):
            if "://" not in p:
                p = "http://" + p
            out.append(p)
    return uniq(out)  # de-dup, preserving order


# API keys are read from the environment FIRST (populate it via a macOS Keychain
# export in your shell profile — most secure, nothing plaintext on disk), then
# from an optional chmod-600 .env in the skill's customization dir. The env always
# wins over the file. With no key present, every network call degrades to the
# previous keyless behavior — nothing breaks.

# cti-expert: the unified skill-wide key store is managed by /apikeys. CTI_API_KEYS_ENV
# points at it; CTI_WEBPIVOT_ENV is a back-compat alias for a co-located key file. With
# neither set we fall back to a per-user override dir outside the repo.
_CUSTOMIZATION_ENV = (os.environ.get("CTI_API_KEYS_ENV")
                      or os.environ.get("CTI_WEBPIVOT_ENV")
                      or os.path.expanduser("~/.config/cti-expert/WebPivot/.env"))

# Candidate .env locations, highest-priority first. A real env var always wins over any
# file; among files, an earlier file wins over a later one (never overridden). Order:
#   1. ./.env               — the invocation cwd (the harness runs from the engine root)
#   2. <skill root>/.env    — cti-expert layout: tools/ -> WebPivot -> intel_engine -> repo.
#                             THIS is where /apikeys writes and where the keys actually live;
#                             upstream WebPivot ships one level shallower, so both are probed.
#   3. <engine>/.env        — intel_engine/.env (upstream's "repo root")
#   4. <skill>/.env         — a skill-local .env next to WebPivot/
#   5. customization .env   — $CTI_API_KEYS_ENV / $CTI_WEBPIVOT_ENV, else a per-user
#                             override dir outside the repo

_SD = os.path.dirname(os.path.abspath(__file__))

_ENV_CANDIDATES = [
    os.path.join(os.getcwd(), ".env"),
    os.path.join(_SD, "..", "..", "..", ".env"),
    os.path.join(_SD, "..", "..", ".env"),
    os.path.join(_SD, "..", ".env"),
    _CUSTOMIZATION_ENV,
]

def _load_env_file(path: str) -> None:
    """Populate os.environ from a KEY=VALUE .env, never overriding an existing var."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                k, v = k.strip(), v.strip().strip('"').strip("'")
                if k and k not in os.environ:
                    os.environ[k] = v
    except FileNotFoundError:
        pass
    except Exception:
        pass

def _load_customization_env() -> None:
    """Load every candidate .env (dedup'd) so keys kept at the repo root are picked up, not
    just the PAI customization dir. Env wins; earlier file wins over later."""
    seen = set()
    for p in _ENV_CANDIDATES:
        rp = os.path.realpath(p)
        if rp in seen:
            continue
        seen.add(rp)
        _load_env_file(p)


_load_customization_env()

def _secret(*names):
    """Return the first non-empty env var among names, else None."""
    for n in names:
        v = os.environ.get(n)
        if v and v.strip():
            return v.strip()
    return None

def _attr(tag: str, name: str):
    m = re.search(name + r"=[\"']([^\"']*)[\"']", tag, re.I)
    return m.group(1) if m else None

def uniq(seq):
    seen, out = set(), []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out

def strip_www(host: str) -> str:
    """Remove a leading 'www.' prefix (lstrip('www.') would eat stray w/./ chars)."""
    host = (host or "").lower()
    return host[4:] if host.startswith("www.") else host

_WAYBACK_RE = re.compile(r"^https?://web\.archive\.org/web/\d+[a-z_]*/(https?://.+)$", re.I)

def unwrap_wayback(url: str) -> str:
    """A Wayback URL (web.archive.org/web/<ts><mod>/<orig>) -> the original URL."""
    if not url:
        return url
    m = _WAYBACK_RE.match(url)
    return m.group(1) if m else url

# DATA: references/public_suffix_list.json (Mozilla PSL, ICANN + PRIVATE sections; refresh with
# wp_psl_update.py) plus references/generic_labels.json -> multi_part_tlds as an analyst override.
# The fallback is the conservative minimum (the old two-label heuristic + the override list); a
# missing list narrows nothing dangerous but loses the private section — load_ref warns loudly.
_PSL_FALLBACK = {"icann": [], "private": []}
_PSL_REF = load_ref(ref_path(__file__, "public_suffix_list.json"), _PSL_FALLBACK)
_MULTI_TLDS = frozenset(_GLC_REF["multi_part_tlds"])
# rule tables: plain suffixes, wildcard parents ("*.ck" -> "ck"), exceptions ("!www.ck" -> "www.ck")
_PSL_RULES = frozenset(r for r in (_PSL_REF["icann"] + _PSL_REF["private"])
                       if not r.startswith(("*.", "!"))) | _MULTI_TLDS
_PSL_WILD = frozenset(r[2:] for r in (_PSL_REF["icann"] + _PSL_REF["private"]) if r.startswith("*."))
_PSL_EXC = frozenset(r[1:] for r in (_PSL_REF["icann"] + _PSL_REF["private"]) if r.startswith("!"))
_PSL_PRIVATE = frozenset(r.lstrip("!*.") for r in _PSL_REF["private"])


@functools.lru_cache(maxsize=4096)
def public_suffix(host: str) -> str:
    """The public suffix of `host` per the PSL algorithm (longest matching rule; an exception rule
    wins and strips its first label; a wildcard rule covers one extra label; no match -> the TLD).
    Stdlib only — the rules are reference DATA loaded above."""
    host = strip_www(host or "").split(":")[0].rstrip(".")
    parts = host.split(".")
    for i in range(len(parts)):                      # longest candidate first
        cand = ".".join(parts[i:])
        if cand in _PSL_EXC:
            return ".".join(parts[i + 1:])
        if cand in _PSL_RULES:
            return cand
        if i + 1 < len(parts) and ".".join(parts[i + 1:]) in _PSL_WILD:
            return cand
    return parts[-1]


def is_private_suffix(suffix: str) -> bool:
    """True when `suffix` comes from the PSL PRIVATE section — a hosting/SaaS platform whose tenants
    are separately-owned sites (github.io, pages.dev, blogspot.com …), not a registry suffix. A
    wildcard-derived suffix (`x.compute.amazonaws.com` from `*.compute.amazonaws.com`) matches on its parent."""
    s = (suffix or "").lower()
    return s in _PSL_PRIVATE or s.partition(".")[2] in _PSL_PRIVATE


@functools.lru_cache(maxsize=4096)
def _registrable(host: str) -> str:
    """Registrable domain (eTLD+1) of `host` per the Public Suffix List, stdlib only.

    `horizon.io.vn` -> `horizon.io.vn` (io.vn is a VNNIC second-level suffix), `zc2.sa.com` ->
    `zc2.sa.com` (CentralNic), `kit.pages.dev` -> `kit.pages.dev` (private section), `a.b.example.com`
    -> `example.com`. A host that IS a public suffix, or has fewer labels than suffix+1, is returned
    unchanged. This is what keys the KB, the frontier and the co-tenancy guards — getting it wrong
    merges every tenant of a shared suffix into one fake apex that then gets enumerated and
    collected as if it were the operator's.
    """
    host = strip_www(host or "").split(":")[0].rstrip(".")
    if not host or "." not in host:
        return host
    suffix = public_suffix(host)
    if host == suffix or not host.endswith("." + suffix):
        return host
    label = host[:-(len(suffix) + 1)].rsplit(".", 1)[-1]
    return f"{label}.{suffix}"


__all__ = [_n for _n in dir() if not _n.startswith("__")]
