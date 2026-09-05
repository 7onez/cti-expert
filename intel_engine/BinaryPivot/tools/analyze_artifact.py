#!/usr/bin/env python3
"""
analyze_artifact.py — static IOC extraction from binaries pulled off scam / fraud sites.

Sibling of WebPivot's pivot_extract.py, for the OTHER half of a scam funnel: the file the
site pushes (a sideloaded Android APK, a desktop "trading terminal" .exe/.dmg, a bundled
.zip/.jar). WebPivot pivots on the *website*; this pivots on the *binary* the website serves.

It downloads (or opens a local) artifact, hashes it, and statically pulls the identifiers that
survive re-skinning and cluster an operator's whole app portfolio:

  * file hashes (md5/sha1/sha256) + `file(1)` type            -> VirusTotal / MalwareBazaar / Triage
  * APK: package name, version, permissions, activities        -> Koodous / APKPure / Google
  * APK: SIGNING-CERT sha256 (developer key)  <-- best pivot    -> clusters every app signed by one key
  * embedded backend hosts / C2 URLs / IP:port                 -> feed straight back into WebPivot
  * Firebase project / appspot / API keys, S3 buckets          -> operator-owned cloud tenant
  * crypto wallets, Telegram / WhatsApp / support handles       -> Chainabuse / social pivots
  * files-of-interest inside the container (google-services.json, config.json, .env, extra dex/so)
  * PACKER / PROTECTOR / obfuscation triage (entropy + section/member signatures)  <-- why a
      protected sample's string sweep is thin; routes it to a dynamic sandbox. A named protector
      (UPX / VMProtect / Qihoo Jiagu / Tencent Legu / …) is also a weak, kit-level clustering hint.

Output is WebPivot-shaped JSON ({meta, artifacts, pivots}) so the SAME KB ingester and case
graph consume it — the APK's backend host / signing cert become shared indicators that cluster
with the web infrastructure WebPivot already mapped.

Zero required dependencies (Python 3 stdlib). Optional accelerators, used only if present:
  requests (nicer download), keytool (APK signing cert), openssl (cert fallback),
  file(1) (type id), strings(1) (faster string sweep; pure-Python fallback otherwise).

Usage:
  analyze_artifact.py <file|URL> [--pretty] [-o OUT.json] [--leads] [--case NAME]
  analyze_artifact.py https://cdn.evil.example/app.apk --leads
  analyze_artifact.py ./MetaTrader.exe -o cases/foo/bin/MetaTrader.exe.json --pretty
  analyze_artifact.py app.apk --keep DIR      # also save the downloaded file to DIR

Authorization: only pull artifacts from infrastructure you are authorized to investigate; run
from non-attributable egress. Detonation is NOT performed here — this is static extraction only.
"""
import argparse
import hashlib
import json
import math
import os
import re
import struct
import subprocess
import sys
import tempfile
import zipfile
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bp_refs  # noqa: E402 — reference DATA lives in references/*.json (RULE 3)
import bp_anyrun  # noqa: E402 — ANY.RUN TI Lookup: query builder (keyless) + live lookups (--anyrun)
# Per-call ceiling for helper binaries (CTI_CALL_TIMEOUT: env → .env → references/timeouts.json →
# 1800s). The engine's resolver is a stdlib sibling; a standalone BinaryPivot falls back to the env.
try:
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__)))), "WebPivot", "tools"))
    from wp_timeouts import floor as _floor  # noqa: E402
except Exception:  # noqa: BLE001
    def _floor(t):
        try:
            c = int(os.environ.get("CTI_CALL_TIMEOUT") or 1800)
        except ValueError:
            c = 1800
        c = c if c > 0 else 1800
        return c if not isinstance(t, (int, float)) else max(int(t), c)

# ---------------------------------------------------------------- reference data (RULE 3)
# The host-token denylists and the packer/installer/protector signature tables are DATA, in
# references/binary_indicators.json — they change far faster than the code that matches them,
# so an analyst extends the JSON and reruns. The fallback below is deliberately minimal: if the
# file is unreadable the tool still runs, visibly weaker, with a stderr warning.
_BP_FALLBACK = {
    "fake_tlds": ["json", "xml", "html", "css", "js", "png", "jpg", "so", "dll", "exe", "dex",
                  "jar", "apk", "txt", "md", "yml", "php", "asp", "jsp"],
    "package_prefixes": ["com", "org", "net", "io", "android", "androidx", "java", "javax",
                         "kotlin", "dalvik"],
    "pe_section_packers": {"upx0": "UPX", "upx1": "UPX", ".aspack": "ASPack",
                           ".vmp0": "VMProtect", ".themida": "Themida/WinLicense"},
    "installer_signatures": {"NSIS": ["Nullsoft.NSIS.exehead"], "Inno Setup": ["Inno Setup"],
                             "InstallShield": ["InstallShield"]},
    "android_protectors": {"Bangcle / SecNeo": [r"libsecexe\.so$", r"libsecmain\.so$"],
                           "Qihoo 360 Jiagu": [r"libjiagu.*\.so$"]},
}
_BP_REF = bp_refs.load_ref(bp_refs.ref_path(__file__, "binary_indicators.json"), _BP_FALLBACK)

DEFAULT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
MAX_DOWNLOAD = 400 * 1024 * 1024      # 400 MB cap — scam APKs/installers are well under this
STRINGS_MIN = 5


# ----------------------------------------------------------------------------- helpers
def uniq(seq):
    seen, out = set(), []
    for x in seq:
        if x is None:
            continue
        k = x.lower() if isinstance(x, str) else x
        if k in seen:
            continue
        seen.add(k)
        out.append(x)
    return out


def _run(cmd, timeout=None, input_bytes=None):
    """Run a helper binary; return (rc, stdout_bytes) or (None, b'') if the tool is absent.
    Bounded by the per-call ceiling; a shorter `timeout` is floored to it."""
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=_floor(timeout), input=input_bytes)
        return p.returncode, p.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None, b""


def have(tool):
    from shutil import which
    return which(tool) is not None


# ----------------------------------------------------------------------------- download
def acquire(target, keep_dir=None, timeout=60):
    """Return (raw_bytes, meta). `target` is a local path or an http(s) URL."""
    meta = {"source": target}
    if re.match(r"^https?://", target, re.I):
        raw, dl_meta = _download(target, timeout)
        meta.update(dl_meta)
        if keep_dir and raw:
            os.makedirs(keep_dir, exist_ok=True)
            name = os.path.basename(urlparse(dl_meta.get("final_url", target)).path) or "artifact.bin"
            dest = os.path.join(keep_dir, name)
            with open(dest, "wb") as f:
                f.write(raw)
            meta["saved_to"] = dest
        return raw, meta
    # local file
    with open(target, "rb") as f:
        raw = f.read()
    meta["filename"] = os.path.basename(target)
    meta["host"] = None
    return raw, meta


def _download(url, timeout):
    meta = {"host": urlparse(url).netloc.split("@")[-1].split(":")[0]}
    headers = {"User-Agent": DEFAULT_UA, "Accept": "*/*"}
    try:
        import requests
        with requests.get(url, headers=headers, stream=True, timeout=timeout,
                          allow_redirects=True, verify=False) as r:
            meta["final_url"] = r.url
            meta["http_status"] = r.status_code
            meta["content_type"] = r.headers.get("Content-Type", "")
            srv = {k.lower(): v for k, v in r.headers.items()
                   if k.lower() in ("server", "x-powered-by", "via", "cf-ray",
                                    "x-amz-request-id", "content-disposition", "last-modified", "etag")}
            if srv:
                meta["server_headers"] = srv
            buf = bytearray()
            for chunk in r.iter_content(65536):
                buf += chunk
                if len(buf) > MAX_DOWNLOAD:
                    meta["truncated"] = True
                    break
            return bytes(buf), meta
    except ImportError:
        pass
    except Exception as e:
        meta["download_error"] = f"{type(e).__name__}: {e}"
        return b"", meta
    # stdlib fallback
    import ssl
    import urllib.request
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            meta["final_url"] = resp.geturl()
            meta["http_status"] = resp.status
            meta["content_type"] = resp.headers.get("Content-Type", "")
            raw = resp.read(MAX_DOWNLOAD + 1)
            if len(raw) > MAX_DOWNLOAD:
                meta["truncated"] = True
                raw = raw[:MAX_DOWNLOAD]
            return raw, meta
    except Exception as e:
        meta["download_error"] = f"{type(e).__name__}: {e}"
        return b"", meta


# ----------------------------------------------------------------------------- typing
def detect_type(raw, meta):
    """Best-effort file-type id from magic bytes, refined by file(1) when available."""
    kind = "unknown"
    if raw[:2] == b"PK":
        kind = "zip"
    elif raw[:2] == b"MZ":
        kind = "pe"          # windows .exe/.dll
    elif raw[:4] == b"\x7fELF":
        kind = "elf"
    elif raw[:4] in (b"\xca\xfe\xba\xbe", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe",
                     b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf"):
        kind = "macho"       # mach-o / fat binary (.dmg contents, mac app)
    elif raw[:4] == b"dex\n":
        kind = "dex"
    elif raw[:4] == b"%PDF":
        kind = "pdf"
    elif raw[:2] == b"\x1f\x8b":
        kind = "gzip"
    if kind == "zip":
        try:
            names = set(zipfile.ZipFile(_bio(raw)).namelist())
            if "AndroidManifest.xml" in names and any(n.startswith("classes") and n.endswith(".dex") for n in names):
                kind = "apk"
            elif "AndroidManifest.xml" in names:
                kind = "apk"
            elif any(n.endswith(".class") for n in names) or "META-INF/MANIFEST.MF" in names:
                kind = "jar"
            elif "[Content_Types].xml" in names:
                kind = "ooxml"    # docx/xlsx/pptx
        except Exception:
            pass
    ftype = None
    if have("file"):
        rc, out = _run(["file", "-b", "-"], input_bytes=raw[:1 << 20])
        if rc == 0 and out:
            ftype = out.decode("utf-8", "ignore").strip()[:200]
    return kind, ftype


def _bio(raw):
    import io
    return io.BytesIO(raw)


# ----------------------------------------------------------------------------- IOC regexes
_URL_RE = re.compile(rb"""https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{4,300}""")
_HOST_RE = re.compile(rb"""\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b""", re.I)
_IP_RE = re.compile(rb"""\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b""")
_IPPORT_RE = re.compile(rb"""\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d):\d{2,5}\b""")
_EMAIL_RE = re.compile(rb"""\b[A-Za-z0-9._%+\-]{1,64}@(?:[A-Za-z0-9\-]{1,63}\.)+[A-Za-z]{2,24}\b""")
_TELEGRAM_RE = re.compile(rb"""(?:https?://)?t(?:elegram)?\.me/[+A-Za-z0-9_/]{3,40}""", re.I)
_WHATSAPP_RE = re.compile(rb"""(?:https?://)?(?:wa\.me|api\.whatsapp\.com/send)[^\s"'<>]{2,60}""", re.I)
_ONION_RE = re.compile(rb"""\b[a-z2-7]{16,56}\.onion\b""", re.I)
_S3_RE = re.compile(rb"""[a-z0-9.\-]{3,63}\.s3[.\-][a-z0-9\-]*\.amazonaws\.com|s3://[a-z0-9.\-]{3,63}""", re.I)
_FIREBASE_RE = re.compile(rb"""[a-z0-9\-]{4,40}\.(?:firebaseio\.com|firebaseapp\.com|web\.app|appspot\.com)""", re.I)
_GOOGLE_API_KEY_RE = re.compile(rb"""AIza[0-9A-Za-z_\-]{35}""")
_BTC_RE = re.compile(rb"""\b(?:bc1[ac-hj-np-z02-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b""")
_ETH_RE = re.compile(rb"""\b0x[a-fA-F0-9]{40}\b""")
_TRON_RE = re.compile(rb"""\bT[1-9A-HJ-NP-Za-km-z]{33}\b""")
_JWT_RE = re.compile(rb"""\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}""")

# noise: framework / SDK / CDN hosts that appear in nearly every APK and are NOT operator infra
_HOST_NOISE = re.compile(
    r"""(?:^|\.)(?:googleapis\.com|google\.com|gstatic\.com|android\.com|schemas\.android\.com|
        github\.com|githubusercontent\.com|apache\.org|w3\.org|json\.org|slf4j\.org|
        gnu\.org|mozilla\.org|oracle\.com|sun\.com|bouncycastle\.org|facebook\.com|
        fbcdn\.net|crashlytics\.com|fabric\.io|jsdelivr\.net|cloudflare\.com|
        cdnjs\.cloudflare\.com|unpkg\.com|jquery\.com|bootstrapcdn\.com|
        example\.com|localhost|127\.0\.0\.1|schema\.org|w3\.org|ns\.adobe\.com|
        purl\.org|xmlpull\.org|kotlinlang\.org|jetbrains\.com|maven\.org)$""", re.I | re.X)


def _decode_matches(matches):
    return uniq(m.decode("utf-8", "ignore") for m in matches)


# File extensions / code tokens that look like a TLD but never are one. A bare host token
# ending in these is a filename or identifier, not a domain (config.json, libapp.so, R.attr).
# Leading label of a reverse-DNS package/class name — real hostnames never start with these.
# DATA: references/binary_indicators.json (RULE 3) — extend it there, not here.
_FAKE_TLD = frozenset(_BP_REF["fake_tlds"])
_PKG_PREFIX = frozenset(_BP_REF["package_prefixes"])


def _valid_host(h, from_url=False):
    if not h or "." not in h or len(h) > 100 or h.startswith((".", "-")) or ".." in h:
        return False
    if _HOST_NOISE.search(h):
        return False
    labels = h.split(".")
    if len(labels) < 2 or any(not lb for lb in labels):
        return False
    tld = labels[-1]
    if from_url:
        return True   # appeared inside a real URL — trust it
    if tld in _FAKE_TLD or tld.isdigit():
        return False
    if labels[0] in _PKG_PREFIX and len(labels) >= 3:
        return False   # com.evil.app / android.permission.X — reversed package, not a host
    if not re.fullmatch(r"[a-z]{2,24}", tld):
        return False
    return True


def scan_iocs(blob, label=""):
    """Regex-sweep a byte blob for network + wallet indicators. Returns dict of label->[values]."""
    out = {}

    def add(k, vals):
        vals = uniq(vals)
        if vals:
            out.setdefault(k, [])
            out[k] += vals

    urls = _decode_matches(_URL_RE.findall(blob))
    urls = [u.rstrip(".,);'\"") for u in urls]
    add("url", urls)
    # Hosts come from two sources with different trust. Hosts parsed out of a real http(s)://
    # URL are trusted (they appeared in a URL context). Bare host-shaped tokens are heavily
    # polluted by reverse-DNS package names (com.evil.app), class names, permission constants
    # and resource filenames (config.json, libapp.so) — those get strict validation.
    hosts = []
    for u in urls:
        try:
            h = urlparse(u).netloc.split("@")[-1].split(":")[0].lower()
            if h and _valid_host(h, from_url=True):
                hosts.append(h)
        except Exception:
            pass
    for h in _decode_matches(_HOST_RE.findall(blob)):
        h = h.lower()
        if _valid_host(h, from_url=False):
            hosts.append(h)
    add("host", uniq(hosts))
    add("ip_port", _decode_matches(_IPPORT_RE.findall(blob)))
    ips = [ip for ip in _decode_matches(_IP_RE.findall(blob))
           if not ip.startswith(("127.", "0.", "255.", "10.", "192.168.", "169.254."))]
    add("ip", ips)
    add("email", _decode_matches(_EMAIL_RE.findall(blob)))
    add("telegram", _decode_matches(_TELEGRAM_RE.findall(blob)))
    add("whatsapp", _decode_matches(_WHATSAPP_RE.findall(blob)))
    add("onion", _decode_matches(_ONION_RE.findall(blob)))
    add("s3_bucket", _decode_matches(_S3_RE.findall(blob)))
    add("firebase", _decode_matches(_FIREBASE_RE.findall(blob)))
    add("google_api_key", _decode_matches(_GOOGLE_API_KEY_RE.findall(blob)))
    add("btc_wallet", _decode_matches(_BTC_RE.findall(blob)))
    add("eth_wallet", _decode_matches(_ETH_RE.findall(blob)))
    add("tron_wallet", _decode_matches(_TRON_RE.findall(blob)))
    add("jwt", _decode_matches(_JWT_RE.findall(blob))[:5])
    # cap each list so one noisy blob doesn't explode the report
    for k in out:
        out[k] = out[k][:60]
    return out


def _merge_iocs(a, b):
    for k, v in b.items():
        a.setdefault(k, [])
        a[k] = uniq(a[k] + v)[:60]
    return a


# ----------------------------------------------------------------------------- minimal AXML
# Android binary-XML (AndroidManifest.xml) parser — just enough for package / version /
# permissions / component names. Pure stdlib; degrades to string-pool scraping on any error.
_AXML_STRING_POOL = 0x001C0001
_AXML_START_TAG = 0x00100102
_AXML_UTF8_FLAG = 1 << 8


def _axml_string_pool(data, off):
    """Decode a RES_STRING_POOL chunk starting at `off`. Returns (strings, next_off)."""
    if off + 28 > len(data) or struct.unpack_from("<I", data, off)[0] != _AXML_STRING_POOL:
        return None, off
    chunk_size = struct.unpack_from("<I", data, off + 4)[0]
    string_count = struct.unpack_from("<I", data, off + 8)[0]
    flags = struct.unpack_from("<I", data, off + 16)[0]
    strings_start = struct.unpack_from("<I", data, off + 20)[0]
    is_utf8 = bool(flags & _AXML_UTF8_FLAG)
    offsets = struct.unpack_from("<%dI" % string_count, data, off + 28)
    base = off + strings_start
    strings = []
    for so in offsets:
        p = base + so
        try:
            if is_utf8:
                # utf-8: u8/u16 char-len, then u8/u16 byte-len, then bytes
                if data[p] & 0x80:
                    p += 2
                else:
                    p += 1
                blen = data[p]
                if blen & 0x80:
                    blen = ((blen & 0x7F) << 8) | data[p + 1]
                    p += 2
                else:
                    p += 1
                strings.append(data[p:p + blen].decode("utf-8", "ignore"))
            else:
                clen = struct.unpack_from("<H", data, p)[0]
                if clen & 0x8000:
                    clen = ((clen & 0x7FFF) << 16) | struct.unpack_from("<H", data, p + 2)[0]
                    p += 4
                else:
                    p += 2
                strings.append(data[p:p + clen * 2].decode("utf-16-le", "ignore"))
        except Exception:
            strings.append("")
    return strings, off + chunk_size


def parse_android_manifest(data):
    """Return {package, version_name, version_code, permissions[], min_sdk, target_sdk,
    activities[], services[], receivers[]} from a binary AndroidManifest.xml. None on failure.

    Layout: an 8-byte RES_XML top header, then the RES_STRING_POOL chunk, then a run of
    START_NAMESPACE / START_TAG / END_TAG chunks. We read the pool, then linearly walk chunks."""
    if len(data) < 16 or struct.unpack_from("<H", data, 0)[0] != 0x0003:  # RES_XML_TYPE
        return None
    strings, off = _axml_string_pool(data, 8)
    if not strings:
        return None
    out = {"permissions": [], "activities": [], "services": [], "receivers": []}
    n = len(strings)
    limit = len(data)
    while off + 16 <= limit:
        try:
            chunk_type = struct.unpack_from("<I", data, off)[0]
            chunk_size = struct.unpack_from("<I", data, off + 4)[0]
        except Exception:
            break
        if chunk_size < 8 or off + chunk_size > limit:
            break
        if chunk_type == _AXML_START_TAG:
            _parse_start_tag(data, off, strings, n, out)
        off += chunk_size
    out["permissions"] = uniq(out["permissions"])
    out["activities"] = uniq(out["activities"])[:40]
    out["services"] = uniq(out["services"])[:40]
    out["receivers"] = uniq(out["receivers"])[:40]
    return out if out.get("package") or out["permissions"] else None


def _s(strings, n, idx):
    return strings[idx] if 0 <= idx < n else None


# START_TAG chunk after its 8-byte header: lineNo(4) comment(4) ns(4) name(4)
# attrStart(2) attrSize(2) attrCount(2) idIdx(2) classIdx(2) styleIdx(2), then attributes.
# Each attribute is 20 bytes: ns(4) name(4) rawValue(4) [size(2) res0(1) dataType(1)] data(4).
_TAG_MAP = {"activity": "activities", "service": "services", "receiver": "receivers"}


def _parse_start_tag(data, off, strings, n, out):
    try:
        name_idx = struct.unpack_from("<i", data, off + 20)[0]
        attr_start = struct.unpack_from("<H", data, off + 24)[0]
        attr_count = struct.unpack_from("<H", data, off + 28)[0]
    except Exception:
        return
    tag = _s(strings, n, name_idx) or ""
    attrs = {}
    base = off + 16 + attr_start   # attributes start after the 16-byte node header + ext offset
    for a in range(min(attr_count, 200)):
        ap = base + a * 20
        try:
            a_name = struct.unpack_from("<i", data, ap + 4)[0]
            raw_val = struct.unpack_from("<i", data, ap + 8)[0]
            typed_data = struct.unpack_from("<i", data, ap + 16)[0]
        except Exception:
            break
        key = _s(strings, n, a_name) or ""
        val = _s(strings, n, raw_val) if raw_val != -1 else typed_data
        if key:
            attrs[key] = val
    if tag == "manifest":
        if attrs.get("package"):
            out["package"] = attrs["package"]
        if attrs.get("versionName") is not None:
            out["version_name"] = attrs["versionName"]
        if attrs.get("versionCode") is not None:
            out["version_code"] = attrs["versionCode"]
    elif tag == "uses-permission" and attrs.get("name"):
        out["permissions"].append(attrs["name"])
    elif tag == "uses-sdk":
        if attrs.get("minSdkVersion") is not None:
            out["min_sdk"] = attrs["minSdkVersion"]
        if attrs.get("targetSdkVersion") is not None:
            out["target_sdk"] = attrs["targetSdkVersion"]
    elif tag in _TAG_MAP and attrs.get("name"):
        out[_TAG_MAP[tag]].append(attrs["name"])


# ----------------------------------------------------------------------------- APK signing cert
def apk_signing_certs(path_or_raw):
    """SHA-256 fingerprint(s) + subject of the APK signing cert(s).
    keytool first (reads v1/v2/v3 signing); openssl on the META-INF PKCS7 as fallback."""
    tmp = None
    if isinstance(path_or_raw, bytes):
        fd, tmp = tempfile.mkstemp(suffix=".apk")
        os.write(fd, path_or_raw)
        os.close(fd)
        path = tmp
    else:
        path = path_or_raw
    try:
        certs = _keytool_certs(path)
        if not certs:
            certs = _openssl_certs(path)
        return certs
    finally:
        if tmp:
            try:
                os.unlink(tmp)
            except OSError:
                pass


def _keytool_certs(path):
    if not have("keytool"):
        return []
    rc, out = _run(["keytool", "-printcert", "-jarfile", path], timeout=90)
    if rc is None or not out:
        return []
    text = out.decode("utf-8", "ignore")
    certs = []
    cur = {}
    for line in text.splitlines():
        line = line.strip()
        m = re.match(r"Owner:\s*(.+)", line)
        if m:
            if cur.get("sha256"):
                certs.append(cur)
            cur = {"subject": m.group(1)[:300]}
        m = re.match(r"Issuer:\s*(.+)", line)
        if m:
            cur["issuer"] = m.group(1)[:300]
        m = re.search(r"SHA256:\s*([0-9A-Fa-f:]{50,})", line)
        if m:
            cur["sha256"] = m.group(1).replace(":", "").upper()
        m = re.search(r"SHA1:\s*([0-9A-Fa-f:]{30,})", line)
        if m:
            cur["sha1"] = m.group(1).replace(":", "").upper()
        m = re.match(r"Valid from:\s*(.+)", line)
        if m:
            cur["validity"] = m.group(1)[:200]
    if cur.get("sha256"):
        certs.append(cur)
    return certs


def _openssl_certs(path):
    if not have("openssl"):
        return []
    try:
        zf = zipfile.ZipFile(path)
    except Exception:
        return []
    sig_files = [n for n in zf.namelist()
                 if re.match(r"META-INF/.*\.(RSA|DSA|EC)$", n, re.I)]
    certs = []
    for n in sig_files:
        try:
            der = zf.read(n)
        except Exception:
            continue
        rc, pem = _run(["openssl", "pkcs7", "-inform", "DER", "-print_certs"], input_bytes=der)
        if rc is None or not pem:
            continue
        rc2, fp = _run(["openssl", "x509", "-noout", "-fingerprint", "-sha256", "-subject"],
                       input_bytes=pem)
        if rc2 is None or not fp:
            continue
        t = fp.decode("utf-8", "ignore")
        cert = {}
        m = re.search(r"Fingerprint=([0-9A-Fa-f:]+)", t)
        if m:
            cert["sha256"] = m.group(1).replace(":", "").upper()
        m = re.search(r"subject=\s*(.+)", t)
        if m:
            cert["subject"] = m.group(1).strip()[:300]
        if cert.get("sha256"):
            certs.append(cert)
    return certs


# ----------------------------------------------------------------------------- container scan
# files worth pulling out by name — configs that leak the operator's cloud tenant / secrets
_INTERESTING = re.compile(
    r"""(google-services\.json$|GoogleService-Info\.plist$|\.env$|(^|/)config[.\-_][^/]*\.(json|xml|js|properties)$|
        firebase[^/]*\.json$|(^|/)server[.\-_][^/]*\.(json|xml)$|strings\.xml$|
        \.(dex|so|jar|apk|dll|exe)$|aws[^/]*\.(json|properties)$|secrets?[.\-_][^/]*)""", re.I | re.X)
_TEXT_SCAN = re.compile(r"""\.(dex|arsc|xml|json|js|txt|properties|html|so|plist|smali|cfg|ini|env)$""", re.I)


def analyze_zip(raw, kind):
    """APK / JAR / ZIP: enumerate members, parse manifest+cert (APK), sweep members for IOCs."""
    art = {}
    iocs = {}
    foi = []
    try:
        zf = zipfile.ZipFile(_bio(raw))
    except Exception as e:
        return art, iocs, foi, {"zip_error": str(e)}
    names = zf.namelist()
    art["member_count"] = len(names)
    dex = [n for n in names if re.match(r"classes\d*\.dex$", n)]
    libs = sorted({n.split("/")[1] for n in names if n.startswith("lib/") and n.count("/") >= 2})
    if libs:
        art["native_abis"] = libs
    extra_payloads = [n for n in names if re.search(r"\.(apk|dex|jar|dll|exe)$", n, re.I)
                      and not re.match(r"classes\d*\.dex$", n)]
    if extra_payloads:
        art["embedded_payloads"] = extra_payloads[:30]   # a bundled 2nd-stage is a strong tell

    if kind == "apk":
        try:
            manifest = parse_android_manifest(zf.read("AndroidManifest.xml"))
            if manifest:
                art["android_manifest"] = manifest
        except Exception:
            pass
        certs = apk_signing_certs(raw)
        if certs:
            art["signing_certs"] = certs

    # files-of-interest: pull small configs whole, note big binaries by name
    for n in names:
        if not _INTERESTING.search(n):
            continue
        try:
            info = zf.getinfo(n)
        except KeyError:
            continue
        entry = {"name": n, "size": info.file_size}
        if info.file_size <= 64 * 1024 and re.search(r"\.(json|env|xml|properties|plist)$", n, re.I):
            try:
                body = zf.read(n)
                entry["preview"] = body[:2000].decode("utf-8", "ignore")
                if n.endswith("google-services.json"):
                    entry["firebase"] = _parse_google_services(body)
            except Exception:
                pass
        foi.append(entry)

    # IOC sweep over the members likely to hold network config / strings
    scanned = 0
    for n in names:
        if scanned >= 400:
            break
        if not (_TEXT_SCAN.search(n) or n in dex or n == "resources.arsc"):
            continue
        try:
            body = zf.read(n)
        except Exception:
            continue
        _merge_iocs(iocs, scan_iocs(strings_of(body), label=n))
        scanned += 1
    return art, iocs, foi, {}


def _parse_google_services(body):
    """Pull the operator's Firebase project id / storage bucket / api key from google-services.json."""
    try:
        d = json.loads(body.decode("utf-8", "ignore"))
    except Exception:
        return None
    pi = d.get("project_info", {})
    out = {
        "project_id": pi.get("project_id"),
        "project_number": pi.get("project_number"),
        "storage_bucket": pi.get("storage_bucket"),
        "firebase_url": pi.get("firebase_url"),
    }
    keys = []
    for c in d.get("client", []) or []:
        for k in c.get("api_key", []) or []:
            if k.get("current_key"):
                keys.append(k["current_key"])
    if keys:
        out["api_keys"] = uniq(keys)
    return {k: v for k, v in out.items() if v}


# ----------------------------------------------------------------------------- strings
def strings_of(blob, min_len=STRINGS_MIN):
    """Printable-run extraction (like strings(1)) over a byte blob, returned as bytes for regexing.
    Includes both ascii and utf-16le runs so wide-char Windows/Java strings are caught."""
    out = bytearray()
    # ascii runs
    run = bytearray()
    for b in blob:
        if 32 <= b < 127:
            run.append(b)
        else:
            if len(run) >= min_len:
                out += run + b"\n"
            run = bytearray()
    if len(run) >= min_len:
        out += run + b"\n"
    # utf-16le runs (every other byte is 0x00) -> collapse to ascii
    wide = re.findall(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len, blob)
    for w in wide:
        out += w.replace(b"\x00", b"") + b"\n"
    return bytes(out)


# ----------------------------------------------------------------------------- PE metadata
def pe_metadata(raw):
    """Compile timestamp + a couple of header facts from a PE, using stdlib struct (no pefile)."""
    out = {}
    try:
        e_lfanew = struct.unpack_from("<I", raw, 0x3C)[0]
        if raw[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            return out
        machine = struct.unpack_from("<H", raw, e_lfanew + 4)[0]
        nsec = struct.unpack_from("<H", raw, e_lfanew + 6)[0]
        ts = struct.unpack_from("<I", raw, e_lfanew + 8)[0]
        out["machine"] = {0x14c: "x86", 0x8664: "x64", 0xaa64: "arm64"}.get(machine, hex(machine))
        out["sections"] = nsec
        out["compile_timestamp"] = ts   # unix epoch; 0 or huge = tampered
        import datetime
        try:
            out["compile_time_utc"] = datetime.datetime.utcfromtimestamp(ts).isoformat() + "Z"
        except Exception:
            pass
    except Exception:
        pass
    return out


# ----------------------------------------------------------------------------- packing / obfuscation
# Static packer / protector / obfuscation triage. The point for THIS tool: a packed or protected
# artifact is exactly why a string sweep comes back thin (the real backend hosts / wallets are
# encrypted inside and only surface on execution) — so we flag it, explain the sparse IOCs, and
# route the analyst to a dynamic sandbox. A *named* commercial protector is also a weak, kit-level
# clustering hint (same builder/service), NOT proof of a shared operator on its own.
_ENTROPY_PACKED = 7.2       # bits/byte (0..8); >7.2 ~ compressed/encrypted body
_ENTROPY_STRONG = 7.5       # >7.5 ~ almost certainly encrypted/packed


def _entropy(data):
    """Shannon entropy (bits/byte, 0..8) of a byte blob; 0.0 for empty."""
    if not data:
        return 0.0
    from collections import Counter
    n = len(data)
    ent = 0.0
    for c in Counter(data).values():
        p = c / n
        ent -= p * math.log2(p)
    return round(ent, 3)


def _sample(data, cap=4_000_000):
    """Head+middle+tail sample so entropy / signature scans stay fast on huge installers."""
    if len(data) <= cap:
        return bytes(data)
    t = cap // 3
    mid = len(data) // 2
    return bytes(data[:t]) + bytes(data[mid:mid + t]) + bytes(data[-t:])


# PE section names that are packer / protector tells (lower-cased exact match).
# DATA: references/binary_indicators.json -> pe_section_packers
_PE_SECTION_PACKERS = dict(_BP_REF["pe_section_packers"])

# Byte strings that mark a self-extracting installer / wrapper (the real payload is inside it).
# DATA: references/binary_indicators.json -> installer_signatures {label: [ascii signatures]}.
# Flattened back to the (signature, label) scan order the matcher expects — first hit wins.
_INSTALLER_SIGS = [(sig.encode("ascii", "ignore"), label)
                   for label, sigs in _BP_REF["installer_signatures"].items()
                   for sig in sigs]

# Known Android app-protectors / DEX packers, matched purely on file NAMES inside the APK — fast
# and reliable. Each wraps/encrypts the real classes.dex, which is why a protected APK's string
# sweep is thin. (label, [member-name regexes])
# DATA: references/binary_indicators.json -> android_protectors
_ANDROID_PROTECTORS = [(label, list(pats))
                       for label, pats in _BP_REF["android_protectors"].items()]


def _pe_sections(raw):
    """Enumerate PE sections as [{name, vsize, rawsize, rawoff}] using stdlib struct (no pefile)."""
    secs = []
    try:
        e = struct.unpack_from("<I", raw, 0x3C)[0]
        if raw[e:e + 4] != b"PE\x00\x00":
            return secs
        nsec = struct.unpack_from("<H", raw, e + 6)[0]
        opt_size = struct.unpack_from("<H", raw, e + 20)[0]
        sect_off = e + 24 + opt_size
        for i in range(min(nsec, 96)):
            base = sect_off + i * 40
            name = raw[base:base + 8].rstrip(b"\x00").decode("latin-1", "ignore")
            secs.append({
                "name": name,
                "vsize": struct.unpack_from("<I", raw, base + 8)[0],
                "rawsize": struct.unpack_from("<I", raw, base + 16)[0],
                "rawoff": struct.unpack_from("<I", raw, base + 20)[0],
            })
    except Exception:
        pass
    return secs


def _macho_encrypted(raw):
    """True if a Mach-O carries LC_ENCRYPTION_INFO(_64) with cryptid != 0 (encrypted segment).
    Best-effort, little-endian single-arch only; FAT/BE binaries just return False."""
    try:
        m = raw[:4]
        if m == b"\xcf\xfa\xed\xfe":        # MH_MAGIC_64 (LE)
            hdr = 32
        elif m == b"\xce\xfa\xed\xfe":      # MH_MAGIC (LE, 32-bit)
            hdr = 28
        else:
            return False
        ncmds = struct.unpack_from("<I", raw, 16)[0]
        off = hdr
        for _ in range(min(ncmds, 400)):
            cmd, csize = struct.unpack_from("<II", raw, off)
            if csize < 8:
                break
            if cmd in (0x21, 0x2c):         # LC_ENCRYPTION_INFO / _64
                if struct.unpack_from("<I", raw, off + 16)[0] != 0:
                    return True
            off += csize
    except Exception:
        pass
    return False


def _protect_zip(raw, kind, det, ent, flag):
    try:
        zf = zipfile.ZipFile(_bio(raw))
        names = zf.namelist()
    except Exception:
        return
    for label, pats in _ANDROID_PROTECTORS:
        hits = []
        for pat in pats:
            rx = re.compile(pat, re.I)
            hits += [n for n in names if rx.search(n)]
        if hits:
            flag(label, "protector", "member(s): " + ", ".join(uniq(hits)[:4]), "high")

    if kind != "apk":
        return
    # Even with no named .so, an encrypted classes.dex or a high-entropy payload stashed in
    # assets/ is DEX packing — the real code is the encrypted blob, the visible dex is a stub.
    try:
        for n in [n for n in names if re.match(r"classes\d*\.dex$", n)]:
            try:
                e = _entropy(_sample(zf.read(n), 2_000_000))
            except Exception:
                continue
            ent.setdefault("classes_dex", {})[n] = e
            if e >= _ENTROPY_STRONG:
                flag("encrypted classes.dex", "protector",
                     f"{n} entropy {e} ≥ {_ENTROPY_STRONG}", "high")
        enc_assets = []
        susp = [n for n in names
                if re.search(r"^assets/.*\.(dex|jar|dat|bin|so|apk|db|key|enc)$", n, re.I)]
        for n in susp[:12]:
            try:
                b = zf.read(n)
            except Exception:
                continue
            if len(b) < 4096:
                continue
            e = _entropy(_sample(b, 2_000_000))
            if e >= _ENTROPY_STRONG:
                enc_assets.append(f"{n}({e})")
        if enc_assets:
            flag("encrypted asset payload", "protector",
                 "high-entropy assets: " + ", ".join(enc_assets[:6]), "medium")
    except Exception:
        pass


def _protect_pe(raw, det, ent, flag):
    secs = _pe_sections(raw)
    if not secs:
        e = _entropy(_sample(raw))
        ent["overall"] = e
        if e >= _ENTROPY_PACKED:
            flag("high-entropy PE", "packer", f"entropy {e} ≥ {_ENTROPY_PACKED}", "medium")
        return
    hi = []
    for s in secs:
        pk = _PE_SECTION_PACKERS.get((s["name"] or "").lower())
        if pk:
            flag(pk, "packer", f'section "{s["name"]}"', "high")
        body = raw[s["rawoff"]:s["rawoff"] + min(s["rawsize"], 2_000_000)]
        if len(body) >= 4096:
            e = _entropy(body)
            if e >= _ENTROPY_PACKED:
                hi.append({"section": s["name"], "entropy": e, "rawsize": s["rawsize"]})
    if hi:
        ent["high_entropy_sections"] = hi[:12]
        if not any(d["type"] == "packer" for d in det):
            top = max(hi, key=lambda x: x["entropy"])
            flag("high-entropy PE section", "packer",
                 f'{top["section"]} entropy {top["entropy"]} ≥ {_ENTROPY_PACKED}',
                 "high" if top["entropy"] >= _ENTROPY_STRONG else "medium")
    try:
        last = max((s["rawoff"] + s["rawsize"] for s in secs), default=0)
        overlay = len(raw) - last
        if last and overlay > 4096:
            ent["overlay_bytes"] = overlay   # appended data — self-extractor / installer / payload
    except Exception:
        pass


def detect_protection(raw, kind):
    """Static packer / protector / obfuscation triage. Additive and fully guarded — any failure
    returns whatever was gathered so the rest of the analysis is unaffected. {} if nothing found."""
    det = []      # [{name, type, evidence, confidence}]  type ∈ packer|protector|obfuscator|installer
    ent = {}
    installer = None
    try:
        sample = _sample(raw)
    except Exception:
        sample = bytes(raw[:4_000_000])

    def flag(name, typ, evidence, conf="medium"):
        det.append({"name": name, "type": typ, "evidence": evidence, "confidence": conf})

    for sig, label in _INSTALLER_SIGS:
        if sig in sample:
            installer = label
            flag(label, "installer", f'signature "{sig.decode("latin-1", "ignore")}"', "high")
            break
    if b"UPX!" in sample or b"This file is packed with the UPX" in sample:
        flag("UPX", "packer", "UPX! marker present", "high")

    if kind in ("apk", "jar", "zip"):
        _protect_zip(raw, kind, det, ent, flag)
    elif kind == "pe":
        _protect_pe(raw, det, ent, flag)
    elif kind in ("elf", "macho", "dex", "gzip", "unknown"):
        e = _entropy(sample)
        ent["overall"] = e
        if kind == "macho" and _macho_encrypted(raw):
            flag("Mach-O LC_ENCRYPTION_INFO", "protector", "cryptid≠0 (encrypted segment)", "high")
        if e >= _ENTROPY_PACKED and kind in ("elf", "macho", "dex"):
            flag("high-entropy body", "packer",
                 f"overall entropy {e} ≥ {_ENTROPY_PACKED} (compressed/encrypted)",
                 "high" if e >= _ENTROPY_STRONG else "medium")

    # de-dup (name,type) — e.g. generic UPX marker + a UPX0 section
    seen, dd = set(), []
    for d in det:
        k = (d["name"], d["type"])
        if k not in seen:
            seen.add(k)
            dd.append(d)
    det = dd

    # Only surface a protection block when something actionable fired. Bare entropy readings with
    # nothing over threshold (e.g. a normal classes.dex) are not worth a confusing "signals" line.
    if not det:
        return {}
    out = {
        "packed": any(d["type"] in ("packer", "protector") for d in det),
        "obfuscated": any(d["type"] in ("protector", "obfuscator") for d in det),
        "detections": det,
    }
    if ent:
        out["entropy"] = ent
    if installer:
        out["installer"] = installer
    return out


# ----------------------------------------------------------------------------- pivots
_CLOUD_HOST = re.compile(
    r"""(firebaseio\.com|firebaseapp\.com|appspot\.com|web\.app|amazonaws\.com|
        \.t\.me$|^t\.me$|wa\.me$|whatsapp\.com$)""", re.I | re.X)


def _operator_hosts(iocs):
    """Embedded hosts worth pivoting as web infra — drops cloud-tenant hosts (firebase/appspot/
    s3) and messenger hosts, which are already covered by their own dedicated pivots."""
    return [h for h in (iocs.get("host") or []) if not _CLOUD_HOST.search(h)]


def build_pivots(kind, hashes, art, iocs, meta):
    """Turn extracted artifacts into ranked, copy-paste pivot queries."""
    pivots = []
    sha256 = hashes["sha256"]

    def P(k, v, conf, queries, note):
        pivots.append({"kind": k, "value": v, "confidence": conf, "queries": queries, "note": note})

    # --- the file hash itself ---
    file_q = [
        {"service": "VirusTotal", "query": f"https://www.virustotal.com/gui/file/{sha256}"},
        {"service": "MalwareBazaar", "query": f'sha256:{sha256}'},
        {"service": "Triage (tria.ge)", "query": f"sha256:{sha256}"},
        {"service": "Hybrid-Analysis", "query": sha256},
    ]
    if kind == "apk":
        file_q += [{"service": "Koodous", "query": f"https://koodous.com/apks/{sha256}"},
                   {"service": "MobSF (local static)", "query": f"upload {meta.get('saved_to') or 'the apk'} to MobSF for full static analysis"}]
    P("file:sha256", sha256, "high", file_q,
      "The artifact hash. Search it in malware repos to find prior sightings, sibling samples, "
      "and the campaign it belongs to. Same hash on another host = same distribution.")

    # --- APK signing cert (the developer-level pivot) ---
    for c in art.get("signing_certs", []) or []:
        fp = c.get("sha256")
        if not fp:
            continue
        P("apk:signing_cert_sha256", fp, "high", [
            {"service": "Koodous", "query": f'cert:{fp}'},
            {"service": "VirusTotal", "query": f'androguard_certificate_sha256:{fp}'},
            {"service": "Triage", "query": f'certificate:{fp}'},
        ], f"APK signing certificate (subject: {c.get('subject','?')}). Clusters EVERY app signed "
           f"with this developer key — the single strongest same-operator link across a scam-app portfolio, "
           f"survives package-name and icon changes.")

    # --- package name ---
    m = art.get("android_manifest") or {}
    if m.get("package"):
        pkg = m["package"]
        P("apk:package", pkg, "high", [
            {"service": "Koodous", "query": f'package_name:{pkg}'},
            {"service": "VirusTotal", "query": f'androguard_package:{pkg}'},
            {"service": "APKPure / APKCombo", "query": pkg},
            {"service": "Google", "query": f'"{pkg}"'},
            {"service": "urlscan.io", "query": f'"{pkg}"'},
            {"service": "PublicWWW", "query": f'"{pkg}"'},
        ], "Android package id. Find the store/mirror listings, other versions, and web pages that "
           "reference it (download funnels reuse the package across clones).")

    # --- firebase / cloud tenant ---
    fb_projects = set()
    for f in art.get("files_of_interest", []) or []:
        fbo = f.get("firebase") or {}
        if fbo.get("project_id"):
            fb_projects.add(fbo["project_id"])
    for pid in fb_projects:
        P("cloud:firebase_project", pid, "high", [
            {"service": "Firebase REST", "query": f"https://{pid}.firebaseio.com/.json  (check for open DB)"},
            {"service": "Google", "query": f'"{pid}" firebaseio OR appspot'},
            {"service": "GitHub", "query": f'"{pid}"'},
            {"service": "urlscan.io", "query": f'"{pid}"'},
        ], "Firebase project id from google-services.json — the operator's own Google Cloud tenant. "
           "Same project across apps = same operator; the RTDB may be world-readable (leaked leads/PII).")

    # --- embedded backend hosts / C2 (feed back into WebPivot) ---
    for h in _operator_hosts(iocs)[:25]:
        P("app:backend_host", h, "medium", [
            {"service": "→ WebPivot", "query": f'python3 WebPivot/tools/pivot_extract.py https://{h} --leads'},
            {"service": "crt.sh", "query": f"%.{h}"},
            {"service": "urlscan.io", "query": f"domain:{h}"},
            {"service": "Validin / FOFA", "query": h},
        ], "Host hard-coded in the binary — the app's real backend / API (not always the download site). "
           "Pivot it as a domain: it ties the app to the web infrastructure and to sibling apps calling the same API.")
    for ipp in (iocs.get("ip_port") or [])[:15]:
        P("app:c2_endpoint", ipp, "medium", [
            {"service": "Shodan", "query": ipp.split(":")[0]},
            {"service": "Censys", "query": ipp.split(":")[0]},
            {"service": "FOFA", "query": f'ip="{ipp.split(":")[0]}"'},
        ], "Hard-coded IP:port endpoint — candidate C2 / API server. Reverse the IP for co-hosted infra.")

    # --- wallets ---
    for label, svc in (("btc_wallet", "bitcoin"), ("eth_wallet", "ethereum"), ("tron_wallet", "tron")):
        for w in (iocs.get(label) or [])[:15]:
            P(f"wallet:{label.split('_')[0]}", w, "medium", [
                {"service": "Chainabuse", "query": w},
                {"service": "block explorer", "query": w},
                {"service": "urlscan.io / Google", "query": f'"{w}"'},
            ], "Crypto address embedded in the app — the payout wallet. Cross-reference scam-report DBs "
               "and find every other site/app funneling to the same address.")

    # --- social / support handles ---
    for label in ("telegram", "whatsapp"):
        for t in (iocs.get(label) or [])[:10]:
            P(f"contact:{label}", t, "medium", [
                {"service": "Google / urlscan", "query": f'"{t}"'},
            ], f"{label} support/recruitment handle baked into the app — a human pivot; often reused "
               "verbatim across an operator's whole portfolio.")

    # --- packing / obfuscation triage ---
    prot = art.get("protection") or {}
    if prot.get("packed") or prot.get("obfuscated") or prot.get("installer"):
        names = uniq([d["name"] for d in prot.get("detections", [])]) or ["unidentified"]
        val = ", ".join(names[:6])
        is_upx = any(n == "UPX" for n in names)
        queries = [
            {"service": "sandbox (MobSF / Triage / Any.Run)",
             "query": "detonate in an isolated sandbox — static IOCs are thin because the real "
                      "backend hosts / wallets are encrypted inside"},
            {"service": "VirusTotal",
             "query": f"https://www.virustotal.com/gui/file/{sha256}/details  (PEiD/packer + section entropy)"},
        ]
        if is_upx:
            queries.insert(0, {"service": "unpack",
                               "query": "upx -d <file>  then re-run analyze_artifact.py on the unpacked binary"})
        P("binary:protection", val, "low", queries,
          f"Artifact is packed/protected ({val}). This EXPLAINS a thin string sweep — the operator's "
          "real backend, wallets and handles are encrypted in the payload and only surface on "
          "execution, so route it to dynamic analysis. A shared *named* protector is a WEAK, "
          "kit-level link (same builder/protection service), not proof of a shared operator alone.")

    # One pass adds the ANY.RUN TI Lookup query (+ the UI link) to every kind the sandbox indexes —
    # hashes, contacted hosts, C2 endpoints, URLs. Built offline and keyless, so even a no-key run
    # hands the analyst the exact query for the observation index; see references/anyrun.json.
    return bp_anyrun.attach_anyrun_queries(pivots)


# ----------------------------------------------------------------------------- KB-shaped output
def to_trackers(art, iocs):
    """Fold the operator-clustering indicators into artifacts.trackers so the WebPivot KB
    ingester (ingest_webpivot.py) turns them into shared indicator nodes automatically."""
    tr = {}

    def put(label, vals):
        vals = uniq([v for v in vals if v])
        if vals:
            tr[label] = vals[:40]

    for c in art.get("signing_certs", []) or []:
        if c.get("sha256"):
            tr.setdefault("apk_signing_cert", []).append(c["sha256"])
    m = art.get("android_manifest") or {}
    if m.get("package"):
        put("apk_package", [m["package"]])
    fb = []
    for f in art.get("files_of_interest", []) or []:
        fbo = f.get("firebase") or {}
        if fbo.get("project_id"):
            fb.append(fbo["project_id"])
    put("firebase_project", fb)
    put("app_backend_host", _operator_hosts(iocs)[:25])
    put("app_c2_endpoint", iocs.get("ip_port") or [])
    put("firebase_host", iocs.get("firebase") or [])
    put("s3_bucket", iocs.get("s3_bucket") or [])
    for label in ("btc_wallet", "eth_wallet", "tron_wallet"):
        put(label, iocs.get(label) or [])
    put("google_api_key", iocs.get("google_api_key") or [])
    for label in ("telegram", "whatsapp"):
        put("app_" + label, iocs.get(label) or [])
    # A NAMED protector/packer is a WEAK, kit-level clustering hint (same builder/service). Only
    # emit named vendors — generic entropy verdicts ("high-entropy …", "encrypted …") are not a
    # shared identifier and would create false same-operator edges.
    prot = art.get("protection") or {}
    protectors = [d["name"] for d in prot.get("detections", [])
                  if d["type"] in ("packer", "protector", "installer")
                  and not d["name"].lower().startswith(("high-entropy", "encrypted ", "mach-o "))]
    put("app_protector", protectors)
    return tr


# ----------------------------------------------------------------------------- main analyze
def analyze(target, keep_dir=None, timeout=60, anyrun=False):
    raw, meta = acquire(target, keep_dir=keep_dir, timeout=timeout)
    if not raw:
        return {"meta": meta, "artifacts": {}, "pivots": [],
                "error": meta.get("download_error", "no bytes acquired")}

    kind, ftype = detect_type(raw, meta)
    hashes = {
        "md5": hashlib.md5(raw).hexdigest(),
        "sha1": hashlib.sha1(raw).hexdigest(),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size": len(raw),
    }
    art = {"file_kind": kind, "file_type": ftype, "hashes": hashes}
    iocs = {}

    if kind in ("apk", "jar", "zip", "ooxml"):
        zart, ziocs, foi, err = analyze_zip(raw, kind)
        art.update(zart)
        art["files_of_interest"] = foi
        iocs = _merge_iocs(iocs, ziocs)
        if err:
            art.update(err)
    else:
        if kind == "pe":
            art["pe"] = pe_metadata(raw)
        iocs = _merge_iocs(iocs, scan_iocs(strings_of(raw), label=kind))

    try:
        prot = detect_protection(raw, kind)
        if prot:
            art["protection"] = prot
    except Exception as e:
        art["protection_error"] = f"{type(e).__name__}: {e}"

    art["iocs"] = {k: v for k, v in iocs.items() if v}
    pivots = build_pivots(kind, hashes, art, iocs, meta)

    # meta.host: prefer the download host (so it links into the web case graph); else a
    # stable synthetic id from the hash so the record still ingests and dedups.
    host = meta.get("host")
    if not host:
        host = f"artifact:{kind}:{hashes['sha256'][:16]}"
    meta["host"] = host
    meta["collector"] = "binarypivot/analyze_artifact"

    result = {
        "meta": meta,
        "artifacts": {
            "title": f"{kind} artifact {hashes['sha256'][:12]}",
            "trackers": to_trackers(art, iocs),   # KB-ingestible operator indicators
            "binary": art,                        # full detail for the report
        },
        "pivots": pivots,
    }
    # ANY.RUN is consulted (never fed): it reports what OTHER people's detonations of these
    # artifacts recorded. Most valuable exactly when `protection` says the string sweep is thin —
    # a packed sample's real endpoints only exist at runtime.
    if anyrun:
        bp_anyrun.enrich_result(result)
    return result


# ----------------------------------------------------------------------------- leads view
def render_leads(result):
    m = result["meta"]
    a = result["artifacts"]["binary"]
    h = a["hashes"]
    lines = []
    lines.append(f"# Artifact: {m.get('source')}")
    if m.get("final_url") and m["final_url"] != m.get("source"):
        lines.append(f"final URL: {m['final_url']}  ({m.get('content_type','')})")
    lines.append(f"kind={a['file_kind']}  size={h['size']:,}B  type={a.get('file_type')}")
    lines.append(f"sha256 {h['sha256']}")
    lines.append(f"md5    {h['md5']}")
    man = a.get("android_manifest") or {}
    if man.get("package"):
        lines.append(f"package {man['package']}  v{man.get('version_name','?')} ({man.get('version_code','?')})  "
                     f"minSdk={man.get('min_sdk','?')} target={man.get('target_sdk','?')}")
        if man.get("permissions"):
            dangerous = [p for p in man["permissions"] if re.search(
                r"SMS|CALL|CONTACTS|LOCATION|CAMERA|RECORD_AUDIO|READ_PHONE|ACCESSIBILITY|SYSTEM_ALERT|"
                r"PACKAGE|INSTALL|STORAGE|MANAGE_EXTERNAL", p)]
            lines.append(f"permissions: {len(man['permissions'])} total; "
                         f"sensitive: {', '.join(p.split('.')[-1] for p in dangerous[:12]) or 'none'}")
    for c in a.get("signing_certs", []) or []:
        lines.append(f"SIGNING CERT sha256 {c.get('sha256')}  subj={c.get('subject','?')}")
    if a.get("embedded_payloads"):
        lines.append(f"⚠ embedded payloads: {', '.join(a['embedded_payloads'][:8])}")
    prot = a.get("protection") or {}
    if prot:
        state = []
        if prot.get("packed"):
            state.append("PACKED")
        if prot.get("obfuscated"):
            state.append("OBFUSCATED")
        if prot.get("installer"):
            state.append(f"installer={prot['installer']}")
        tags = ", ".join(d["name"] for d in prot.get("detections", [])[:6]) or "signals"
        pent = prot.get("entropy", {})
        extra = ""
        if isinstance(pent.get("overall"), (int, float)):
            extra += f"  entropy={pent['overall']}"
        if pent.get("high_entropy_sections"):
            extra += "  hi-ent=" + ",".join(f"{s['section']}:{s['entropy']}"
                                             for s in pent["high_entropy_sections"][:4])
        lines.append(f"⚠ PROTECTION: {'/'.join(state) or 'signals'}  [{tags}]{extra}")
    for f in a.get("files_of_interest", []) or []:
        if f.get("firebase"):
            lines.append(f"firebase: {json.dumps(f['firebase'])}")
    iocs = a.get("iocs") or {}
    for k in ("host", "ip_port", "ip", "firebase", "s3_bucket", "btc_wallet", "eth_wallet",
              "tron_wallet", "telegram", "whatsapp", "email", "onion", "google_api_key"):
        if iocs.get(k):
            lines.append(f"{k:14s} {', '.join(iocs[k][:10])}")
    lines.append("")
    lines.append("## Pivots (high→low)")
    for p in result["pivots"]:
        lines.append(f"[{p['confidence'].upper():6s}] {p['kind']} = {p['value']}")
        lines.append(f"        {p['note']}")
        for q in p["queries"][:4]:
            lines.append(f"          · {q['service']}: {q['query']}")
    return "\n".join(lines)


# ----------------------------------------------------------------------------- cli
def main():
    ap = argparse.ArgumentParser(description="Static IOC extraction from scam-site binaries (APK / exe / zip).")
    ap.add_argument("target", help="local file path or http(s) URL to the artifact")
    ap.add_argument("-o", "--output", help="write full result JSON here")
    ap.add_argument("--pretty", action="store_true", help="pretty-print JSON to stdout")
    ap.add_argument("--leads", action="store_true", help="human-readable ranked leads to stdout")
    ap.add_argument("--keep", metavar="DIR", help="save the downloaded artifact into DIR")
    ap.add_argument("--case", help="case name (recorded in meta only)")
    ap.add_argument("--timeout", type=int, default=60)
    ap.add_argument("--anyrun", action="store_true",
                    help="RUN ANY.RUN Threat Intelligence Lookup live on this artifact's hashes "
                         "and endpoints — the domains/IPs samples like it actually contacted when "
                         "detonated, the family label, and the public sandbox tasks. This is how a "
                         "PACKED sample's real backend is recovered. METERED (needs ANYRUN_API_KEY "
                         "with a TI Lookup licence) and bounded by the per-run cap in "
                         "references/anyrun.json. Nothing is ever SUBMITTED — read-only. Without "
                         "this flag every pivot still carries its TI Lookup query, built offline.")
    args = ap.parse_args()

    for _line in bp_anyrun.banner_lines():
        sys.stderr.write(_line + "\n")
    result = analyze(args.target, keep_dir=args.keep, timeout=args.timeout, anyrun=args.anyrun)
    if args.case:
        result["meta"]["case"] = args.case

    if args.output:
        os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        sys.stderr.write(f"wrote {args.output}\n")

    if args.leads:
        print(render_leads(result))
    elif args.pretty:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    elif not args.output:
        print(json.dumps(result, ensure_ascii=False))
    return 0 if not result.get("error") else 2


if __name__ == "__main__":
    sys.exit(main())
