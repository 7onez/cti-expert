#!/usr/bin/env python3
"""
wp_docmeta.py — the DOCUMENT + IMAGE metadata layer: download what the site hosts, and read
the identifiers embedded inside the files themselves.

WHY THIS IS A PIVOT
-------------------
Everything else WebPivot reads is the *page*. A page is cheap to re-skin — new brand, new
favicon, new template, and the old fingerprints die. The files a site HOSTS are not re-made
when the brand changes, because nobody re-exports the PDF licence to change a logo. So the
metadata inside them is unusually durable:

  * **PDF `/Info` + XMP** — the "licence", "certificate", "prospectus" or "whitepaper" a scam
    site offers as proof is normally produced on the operator's own machine and uploaded
    untouched. `/Author` is frequently a real name or the OS account name; `xmpMM:DocumentID`
    is a UUID minted per source document, so the SAME id on two unrelated-looking domains means
    literally the same source file — one of the few artifacts a stranger cannot copy by
    accident. `/Creator` + `/Producer` name the software stack of the machine that made it.
  * **Image EXIF** — a photo the operator actually took (an "office" shot, a team page, a
    forged KYC prop) carries camera `Make`/`Model`, `Artist`, `Copyright`, `DateTimeOriginal`
    and sometimes **GPS coordinates**. Exported graphics instead carry the editing `Software`,
    which clusters the shop that produced the kit's artwork.
  * **The file's own sha256** — the same asset served from two domains is the same kit.

WHAT THIS LAYER REFUSES TO CONCLUDE
-----------------------------------
Two failure modes, both handled as data rather than prose:

  1. **A common tool is not an operator.** `Producer: Microsoft® Word` is shared by a large
     fraction of all PDFs ever made. Values matching `generic_producers` / `generic_software`
     in `references/docmeta.json` are still recorded — knowing a document was browser-printed
     is context — but they never emit a same-operator pivot. Same for `role_authors`
     ("Windows User", "admin"): a default account name is not a person. This is the
     base-rate rule applied to metadata.
  2. **Stripped metadata is not evidence of tradecraft.** Most CMS and CDN image pipelines
     strip EXIF automatically, so an empty result is the NORMAL case, not a finding. The
     coverage block records how many files were read and how many carried anything, so the
     analyst can see the difference between "we looked and it was clean" and "we never
     looked" — but this module never scores absence as a signal.

OPSEC
-----
This layer DOWNLOADS FILES FROM THE TARGET. It runs only on a live primary page (never an
archived or offline source), routes through the shared `fetch()` so `--proxy` is honored, and
is bounded by `references/docmeta.json` → `budget`. Disable with `--no-docmeta`.

CLI (analyst path — a file or URL you already have):
    python3 WebPivot/tools/wp_docmeta.py <url-or-path> [<url-or-path> ...] [--json]
"""
from __future__ import annotations

import hashlib
import html as _html
import json
import os
import re
import struct
import sys
import zlib
from urllib.parse import urljoin, urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wp_common import DEFAULT_UA, _attr, _registrable, strip_www, uniq  # noqa: E402
from wp_net import fetch  # noqa: E402
from wp_refs import load_ref, ref_path  # noqa: E402

# Minimal embedded fallback — see wp_refs.py's FAILURE MODE. On the fallback this layer still
# runs and still refuses to cluster on Word/Photoshop, it just knows far fewer generic values.
_DOC_FALLBACK = {
    "document_extensions": ["pdf", "docx", "xlsx", "pptx"],
    "image_extensions": ["jpg", "jpeg", "png", "tiff"],
    "generic_producers": ["microsoft", "word", "acrobat", "skia/pdf", "chromium", "canva"],
    "generic_software": ["adobe photoshop", "gimp", "canva", "imagemagick"],
    "role_authors": ["user", "admin", "administrator", "windows user", "unknown"],
    "skip_path_hints": ["/wp-includes/", "/node_modules/", "/icons/"],
    "budget": {"max_files": 12, "max_documents": 6, "max_bytes_per_file": 5242880,
               "max_total_bytes": 20971520, "min_image_bytes": 8192, "timeout_seconds": 15},
}
_D = load_ref(ref_path(__file__, "docmeta.json"), _DOC_FALLBACK)

DOC_EXT = tuple(x.lower() for x in _D["document_extensions"])
IMAGE_EXT = tuple(x.lower() for x in _D["image_extensions"])
GENERIC_PRODUCERS = tuple(x.lower() for x in _D["generic_producers"])
GENERIC_SOFTWARE = tuple(x.lower() for x in _D["generic_software"])
ROLE_AUTHORS = frozenset(x.strip().lower() for x in _D["role_authors"])
SKIP_PATH_HINTS = tuple(x.lower() for x in _D["skip_path_hints"])
BUDGET = dict(_D["budget"])

COLLECT_DOCMETA = True          # flipped off by pivot_extract's --no-docmeta

_SRC_RE = re.compile(r"""<(?:img|source|embed)\b[^>]*?\bsrc(?:set)?\s*=\s*["']([^"']{2,400})["']""", re.I)
_HREF_RE = re.compile(r"""<a\b[^>]*?\bhref\s*=\s*["']([^"']{2,400})["']""", re.I)
_OG_RE = re.compile(r"""<meta\b[^>]*?(?:property|name)\s*=\s*["']og:image["'][^>]*>""", re.I)
_OBJ_RE = re.compile(r"""<(?:object|iframe)\b[^>]*?\bdata\s*=\s*["']([^"']{2,400})["']""", re.I)


# --------------------------------------------------------------------------- discovery
def _ext(url: str) -> str:
    path = urlparse(url).path
    return path.rsplit(".", 1)[-1].lower() if "." in path.rsplit("/", 1)[-1] else ""


def _skip_path(url: str) -> bool:
    p = urlparse(url).path.lower()
    return any(h in p for h in SKIP_PATH_HINTS)


def discover(html: str, base_url: str, self_host: str) -> list:
    """Candidate files this page hosts, ranked: operator DOCUMENTS first (highest metadata
    yield), then same-site images, then off-site. Returns [{'url','ext','kind'}]."""
    if not html:
        return []
    urls = []
    for m in _SRC_RE.finditer(html):
        urls += [c.strip().split(" ")[0] for c in m.group(1).split(",")]  # srcset → each candidate
    urls += [m.group(1) for m in _HREF_RE.finditer(html)]
    urls += [m.group(1) for m in _OBJ_RE.finditer(html)]
    for m in _OG_RE.finditer(html):
        c = _attr(m.group(0), "content")
        if c:
            urls.append(c)

    seen, out = set(), []
    self_reg = _registrable(strip_www(self_host or ""))
    for raw in urls:
        raw = _html.unescape((raw or "").strip())
        if not raw or raw.startswith(("data:", "javascript:", "mailto:", "#")):
            continue
        url = urljoin(base_url, raw).split("#", 1)[0]
        if not url.startswith(("http://", "https://")) or url in seen:
            continue
        ext = _ext(url)
        kind = "document" if ext in DOC_EXT else "image" if ext in IMAGE_EXT else None
        if not kind or _skip_path(url):
            continue
        seen.add(url)
        same = _registrable(strip_www(urlparse(url).netloc)) == self_reg
        out.append({"url": url, "ext": ext, "kind": kind, "same_site": same})
    # documents before images, same-site before third-party, then stable by URL
    out.sort(key=lambda f: (f["kind"] != "document", not f["same_site"], f["url"]))
    return out


# --------------------------------------------------------------------------- PDF
_PDF_KEYS = {"Author": "author", "Title": "title", "Subject": "subject", "Creator": "creator",
             "Producer": "producer", "Keywords": "keywords", "CreationDate": "created",
             "ModDate": "modified", "Company": "company"}
_PDF_LIT_RE = re.compile(rb"/(%s)\s*\(((?:[^()\\]|\\.|\([^()]*\))*)\)" % b"|".join(
    k.encode() for k in _PDF_KEYS))
_PDF_HEX_RE = re.compile(rb"/(%s)\s*<([0-9A-Fa-f\s]{2,600})>" % b"|".join(
    k.encode() for k in _PDF_KEYS))
_XMP_RE = re.compile(rb"<x:xmpmeta[^>]*>(.*?)</x:xmpmeta>", re.S)
_XMP_TAGS = {
    "xmp:CreatorTool": "creator_tool", "xmp:CreateDate": "created", "xmp:ModifyDate": "modified",
    "dc:creator": "author", "dc:title": "title", "dc:rights": "copyright",
    "pdf:Producer": "producer", "photoshop:AuthorsPosition": "author_role",
    "xmpMM:DocumentID": "xmp_document_id", "xmpMM:InstanceID": "xmp_instance_id",
    "xmpMM:OriginalDocumentID": "xmp_original_document_id",
}
_PDF_DATE_RE = re.compile(r"D:(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?")


def _pdf_text(raw: bytes) -> str:
    """Decode a PDF string object: UTF-16BE when BOM-marked, else PDFDocEncoding≈latin-1,
    with the standard backslash escapes resolved."""
    if raw[:2] in (b"\xfe\xff", b"\xff\xfe"):
        try:
            return raw.decode("utf-16", "ignore")
        except Exception:  # noqa: BLE001
            return ""
    out = bytearray()
    i = 0
    while i < len(raw):
        c = raw[i:i + 1]
        if c == b"\\" and i + 1 < len(raw):
            nxt = raw[i + 1:i + 2]
            out += {b"n": b"\n", b"r": b"\r", b"t": b"\t", b"b": b"\b",
                    b"f": b"\f"}.get(nxt, nxt)
            i += 2
            continue
        out += c
        i += 1
    return out.decode("utf-8", "ignore") if b"\xc3" in bytes(out) else bytes(out).decode("latin-1", "ignore")


def _pdf_date(v: str) -> str:
    m = _PDF_DATE_RE.search(v or "")
    if not m:
        return (v or "").strip()
    y, mo, d, h, mi, s = (g or "" for g in m.groups())
    stamp = f"{y}-{mo or '01'}-{d or '01'}"
    return stamp + (f"T{h}:{mi or '00'}:{s or '00'}" if h else "")


def parse_pdf(raw: bytes) -> dict:
    """PDF metadata from the /Info dictionary and the XMP packet. Deliberately regex-based over
    the raw bytes rather than a full object-graph walk: it costs no dependency, and both metadata
    carriers are stored UNCOMPRESSED in the overwhelming majority of real-world PDFs. A PDF that
    hides /Info inside an object stream simply yields fewer fields — never a wrong one."""
    meta: dict = {}
    for rx, dec in ((_PDF_LIT_RE, _pdf_text),
                    (_PDF_HEX_RE, lambda b: _pdf_text(bytes.fromhex(
                        re.sub(rb"\s", b"", b).decode("ascii", "ignore").ljust(
                            len(re.sub(rb"\s", b"", b)) + len(re.sub(rb"\s", b"", b)) % 2, "0"))))):
        for m in rx.finditer(raw):
            key = _PDF_KEYS[m.group(1).decode()]
            if key in meta:
                continue
            try:
                val = dec(m.group(2)).strip()
            except Exception:  # noqa: BLE001 — a malformed string must not kill the file
                continue
            if val:
                meta[key] = _pdf_date(val) if key in ("created", "modified") else val

    xm = _XMP_RE.search(raw)
    if xm:
        xmp = xm.group(1).decode("utf-8", "ignore")
        for tag, key in _XMP_TAGS.items():
            m = (re.search(rf"<{tag}[^>]*>(?:\s*<rdf:(?:Alt|Seq|Bag)>\s*<rdf:li[^>]*>)?"
                           rf"(.*?)(?:</rdf:li>)?", xmp, re.S)
                 or re.search(rf'{tag}\s*=\s*"([^"]{{1,300}})"', xmp))
            if not m:
                continue
            val = re.sub(r"<[^>]+>", "", m.group(1) or "").strip()
            if val and key not in meta:
                meta[key] = _pdf_date(val) if key in ("created", "modified") else val
    if meta:
        meta["_format"] = "pdf"
    return meta


# --------------------------------------------------------------------------- JPEG / EXIF
_EXIF_TAGS = {0x010F: "camera_make", 0x0110: "camera_model", 0x0131: "software",
              0x013B: "artist", 0x8298: "copyright", 0x0132: "modified",
              0x9C9D: "xp_author", 0x9C9B: "xp_comment", 0x010E: "description",
              0x9003: "created", 0x9004: "digitized", 0xA430: "camera_owner",
              0xA433: "lens_make", 0xA434: "lens_model", 0xC614: "unique_camera_model"}
_GPS_TAGS = {1: "lat_ref", 2: "lat", 3: "lon_ref", 4: "lon", 29: "gps_date"}
_TYPE_SIZE = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8}


def _tiff_value(buf: bytes, base: int, endian: str, typ: int, count: int, voff: int):
    size = _TYPE_SIZE.get(typ, 0) * count
    if not size:
        return None
    off = voff if size > 4 else None
    data = buf[base + off: base + off + size] if off is not None else struct.pack(
        endian + "I", voff)[:size]
    if len(data) < size:
        return None
    if typ == 2:                                            # ASCII
        return data.split(b"\x00", 1)[0].decode("utf-8", "ignore").strip()
    if typ == 1 and count > 8:                              # BYTE run (XP* tags are UTF-16LE)
        return data.decode("utf-16-le", "ignore").rstrip("\x00").strip()
    if typ in (3, 4):
        fmt = "H" if typ == 3 else "I"
        vals = struct.unpack(endian + fmt * count, data)
        return vals[0] if count == 1 else list(vals)
    if typ in (5, 10):                                      # RATIONAL
        out = []
        for i in range(count):
            n, d = struct.unpack(endian + ("ii" if typ == 10 else "II"), data[i * 8:i * 8 + 8])
            out.append(n / d if d else 0.0)
        return out[0] if count == 1 else out
    return None


def _read_ifd(buf: bytes, base: int, off: int, endian: str, tags: dict, out: dict,
              sub: dict | None = None) -> None:
    if off <= 0 or base + off + 2 > len(buf):
        return
    try:
        n = struct.unpack(endian + "H", buf[base + off:base + off + 2])[0]
    except struct.error:
        return
    for i in range(min(n, 200)):
        e = base + off + 2 + i * 12
        if e + 12 > len(buf):
            return
        tag, typ, count, voff = struct.unpack(endian + "HHII", buf[e:e + 12])
        if sub is not None and tag in sub:
            sub[tag] = voff
            continue
        if tag not in tags:
            continue
        val = _tiff_value(buf, base, endian, typ, count, voff)
        if val not in (None, ""):
            out[tags[tag]] = val


def _dms(vals, ref) -> float | None:
    if not isinstance(vals, list) or len(vals) < 3:
        return None
    deg = vals[0] + vals[1] / 60.0 + vals[2] / 3600.0
    return -deg if str(ref).upper() in ("S", "W") else deg


def parse_exif(raw: bytes) -> dict:
    """EXIF from a JPEG APP1 segment or a bare TIFF. Hand-rolled TIFF/IFD walk — no dependency,
    and the tags that matter for attribution (Artist, Copyright, Software, Make/Model, GPS) all
    live in IFD0 / the Exif and GPS sub-IFDs."""
    tiff = None
    if raw[:2] == b"\xff\xd8":                              # JPEG: scan segments for APP1/Exif
        i = 2
        while i + 4 < len(raw):
            if raw[i] != 0xFF:
                break
            marker, seglen = raw[i + 1], struct.unpack(">H", raw[i + 2:i + 4])[0]
            if marker == 0xE1 and raw[i + 4:i + 10] == b"Exif\x00\x00":
                tiff = raw[i + 10:i + 2 + seglen]
                break
            if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
                i += 2
                continue
            if marker == 0xDA:                              # start of scan — no metadata past here
                break
            i += 2 + seglen
    elif raw[:4] in (b"II*\x00", b"MM\x00*"):
        tiff = raw
    if not tiff or len(tiff) < 8:
        return {}

    endian = "<" if tiff[:2] == b"II" else ">"
    try:
        ifd0 = struct.unpack(endian + "I", tiff[4:8])[0]
    except struct.error:
        return {}
    meta: dict = {}
    subs = {0x8769: 0, 0x8825: 0}                           # Exif IFD, GPS IFD
    _read_ifd(tiff, 0, ifd0, endian, _EXIF_TAGS, meta, sub=subs)
    _read_ifd(tiff, 0, ifd0, endian, _EXIF_TAGS, meta)
    if subs.get(0x8769):
        _read_ifd(tiff, 0, subs[0x8769], endian, _EXIF_TAGS, meta)
    if subs.get(0x8825):
        gps: dict = {}
        _read_ifd(tiff, 0, subs[0x8825], endian, _GPS_TAGS, gps)
        lat, lon = _dms(gps.get("lat"), gps.get("lat_ref")), _dms(gps.get("lon"), gps.get("lon_ref"))
        if lat is not None and lon is not None and (lat or lon):
            meta["gps"] = f"{lat:.6f},{lon:.6f}"
    if meta:
        meta["_format"] = "jpeg/tiff"
    return meta


# --------------------------------------------------------------------------- PNG
_PNG_KEYMAP = {"author": "artist", "copyright": "copyright", "software": "software",
               "creation time": "created", "comment": "comment", "description": "description",
               "title": "title", "source": "source", "xml:com.adobe.xmp": "_xmp"}


def parse_png(raw: bytes) -> dict:
    """PNG tEXt / zTXt / iTXt chunks, plus any embedded Adobe XMP packet. Export pipelines
    (Photoshop, Canva, Figma) routinely leave Software/Author here even when EXIF is stripped."""
    if raw[:8] != b"\x89PNG\r\n\x1a\n":
        return {}
    meta: dict = {}
    i = 8
    while i + 8 <= len(raw):
        try:
            length = struct.unpack(">I", raw[i:i + 4])[0]
        except struct.error:
            break
        ctype = raw[i + 4:i + 8]
        body = raw[i + 8:i + 8 + length]
        i += 12 + length
        if ctype == b"IEND":
            break
        if ctype not in (b"tEXt", b"zTXt", b"iTXt") or b"\x00" not in body:
            continue
        key, rest = body.split(b"\x00", 1)
        try:
            if ctype == b"zTXt":
                rest = zlib.decompress(rest[1:])
            elif ctype == b"iTXt":
                cflag = rest[:1]
                rest = rest[2:].split(b"\x00", 2)[-1]
                if cflag == b"\x01":
                    rest = zlib.decompress(rest)
        except Exception:  # noqa: BLE001 — a corrupt chunk must not kill the file
            continue
        k = _PNG_KEYMAP.get(key.decode("latin-1", "ignore").strip().lower())
        val = rest.decode("utf-8", "ignore").strip()
        if not k or not val:
            continue
        if k == "_xmp":
            for tag, mk in _XMP_TAGS.items():
                m = re.search(rf'{tag}\s*=\s*"([^"]{{1,300}})"', val) or \
                    re.search(rf"<{tag}[^>]*>(.*?)</{tag}>", val, re.S)
                if m and mk not in meta:
                    v = re.sub(r"<[^>]+>", "", m.group(1)).strip()
                    if v:
                        meta[mk] = v
        elif k not in meta:
            meta[k] = val[:300]
    if meta:
        meta["_format"] = "png"
    return meta


# --------------------------------------------------------------------------- OOXML (docx/xlsx/pptx)
_OOXML_TAGS = {"dc:creator": "author", "cp:lastModifiedBy": "last_modified_by",
               "dc:title": "title", "dc:subject": "subject", "dc:description": "description",
               "cp:keywords": "keywords", "cp:category": "category", "cp:company": "company",
               "cp:manager": "manager", "dcterms:created": "created",
               "dcterms:modified": "modified", "Application": "producer",
               "AppVersion": "producer_version", "Manager": "manager", "Company": "company"}


def parse_ooxml(raw: bytes) -> dict:
    """Word/Excel/PowerPoint metadata from the OOXML package's `docProps/core.xml` and `app.xml`.

    `cp:lastModifiedBy` is the field worth the download: it names the account that last SAVED the
    file, which on a shared operator document is often a different — and more careless — person
    than `dc:creator`. Both survive into every copy of the document that gets re-uploaded.
    """
    import io
    import zipfile
    meta: dict = {}
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            names = set(z.namelist())
            if not any(n.startswith("docProps/") for n in names):
                return {}                       # a plain ZIP, not an Office package
            for part in ("docProps/core.xml", "docProps/app.xml"):
                if part not in names:
                    continue
                xml = z.read(part).decode("utf-8", "ignore")
                for tag, key in _OOXML_TAGS.items():
                    m = re.search(rf"<{tag}[^>]*>(.*?)</{tag}>", xml, re.S)
                    if m and key not in meta:
                        val = re.sub(r"<[^>]+>", "", m.group(1)).strip()
                        if val:
                            meta[key] = val[:300]
    except Exception:  # noqa: BLE001 — an encrypted or corrupt package must not kill the run
        return {}
    if meta:
        meta["_format"] = "ooxml"
    return meta


def parse(raw: bytes) -> dict:
    """Dispatch on MAGIC BYTES, never the extension — a `.jpg` URL that actually serves a PDF
    (or an error page) is common, and trusting the extension would silently mis-parse it."""
    if not raw:
        return {}
    if raw[:5] == b"%PDF-":
        return parse_pdf(raw)
    if raw[:2] == b"PK":                        # ZIP container — Office package or plain archive
        return parse_ooxml(raw)
    if raw[:8] == b"\x89PNG\r\n\x1a\n":
        return parse_png(raw)
    if raw[:2] == b"\xff\xd8" or raw[:4] in (b"II*\x00", b"MM\x00*"):
        return parse_exif(raw)
    if raw[:4] == b"RIFF" and raw[8:12] == b"WEBP":         # WebP EXIF rides in an EXIF chunk
        j = raw.find(b"EXIF")
        if j > 0:
            return parse_exif(raw[j + 8:])
    return {}


# --------------------------------------------------------------------------- noise policy
def is_generic(key: str, value: str) -> bool:
    """True when a value names a TOOL or a DEFAULT rather than an operator — so it is recorded
    as context but must not produce a same-operator pivot. The base-rate rule, in one place."""
    v = (value or "").strip().lower()
    if not v or len(v) < 2:
        return True
    if key in ("author", "artist", "camera_owner", "xp_author"):
        return v in ROLE_AUTHORS
    if key in ("producer", "creator"):
        return any(g in v for g in GENERIC_PRODUCERS)
    if key in ("software", "creator_tool"):
        return any(g in v for g in GENERIC_SOFTWARE)
    return False


# --------------------------------------------------------------------------- collection
def collect(html: str, base_url: str, self_host: str, ua: str = DEFAULT_UA,
            proxy: str = None, timeout: int = None, max_files: int = None) -> dict:
    """Download and read the page's hosted documents and images. Returns the
    `artifacts.docmeta` block. Safe to call unconditionally — with the toggle off it returns a
    coverage-only stub, so "we did not look" stays visible in the output instead of reading as
    "there was nothing there"."""
    out = {"files": [], "skipped": [], "coverage": {"docmeta": "off"}}
    if not COLLECT_DOCMETA or not base_url or not html:
        return out

    budget_files = max_files if max_files is not None else int(BUDGET.get("max_files", 12))
    max_docs = int(BUDGET.get("max_documents", 6))
    per_file = int(BUDGET.get("max_bytes_per_file", 5 << 20))
    total_cap = int(BUDGET.get("max_total_bytes", 20 << 20))
    min_img = int(BUDGET.get("min_image_bytes", 8192))
    tmo = timeout if timeout is not None else int(BUDGET.get("timeout_seconds", 15))

    candidates = discover(html, base_url, self_host)
    docs = [c for c in candidates if c["kind"] == "document"][:max_docs]
    imgs = [c for c in candidates if c["kind"] == "image"]
    chosen = (docs + imgs)[:budget_files]

    spent, with_meta = 0, 0
    for c in chosen:
        if spent >= total_cap:
            out["skipped"].append({"url": c["url"], "reason": "run byte budget exhausted"})
            continue
        try:
            _, status, headers, body = fetch(c["url"], timeout=tmo, ua=ua, proxy=proxy)
        except Exception as e:  # noqa: BLE001
            out["skipped"].append({"url": c["url"], "reason": f"fetch failed: {e}"})
            continue
        if status >= 400 or not body:
            out["skipped"].append({"url": c["url"], "reason": f"HTTP {status}"})
            continue
        if len(body) > per_file:
            out["skipped"].append({"url": c["url"],
                                   "reason": f"{len(body)} bytes > per-file cap {per_file}"})
            continue
        if c["kind"] == "image" and len(body) < min_img:
            out["skipped"].append({"url": c["url"],
                                   "reason": f"{len(body)} bytes < min image size (icon/pixel)"})
            continue
        spent += len(body)
        meta = parse(body)
        if meta:
            with_meta += 1
        out["files"].append({
            "url": c["url"], "name": urlparse(c["url"]).path.rsplit("/", 1)[-1][:120],
            "kind": c["kind"], "same_site": c["same_site"], "bytes": len(body),
            "content_type": (headers or {}).get("content-type", "")[:80],
            "sha256": hashlib.sha256(body).hexdigest(),
            "meta": {k: v for k, v in meta.items() if not k.startswith("_")},
            "format": meta.get("_format", ""),
        })
    # Coverage states BOTH numbers on purpose: "12 read, 0 carried metadata" is a normal, boring
    # result (CMS pipelines strip EXIF by default) and must never be read as tradecraft.
    out["coverage"]["docmeta"] = (
        f"{len(out['files'])} read ({sum(1 for f in out['files'] if f['kind'] == 'document')} "
        f"documents), {with_meta} carried metadata, {len(out['skipped'])} skipped, "
        f"{spent} bytes") if chosen else "no hosted documents or images found on the page"
    return out


# --------------------------------------------------------------------------- CLI
# The keys that actually become a pivot. `title`, `created` and `comment` are recorded because
# they are useful CONTEXT (a licence dated before the domain existed is a finding on its own) but
# they are not identifiers, so listing them as "pivotable" would overstate what they can carry.
PIVOT_KEYS = ("author", "artist", "xp_author", "camera_owner", "copyright", "xmp_document_id",
              "producer", "creator_tool", "software", "gps", "camera_make", "camera_model",
              "last_modified_by", "company", "manager")


def _one(target: str, timeout: int = 20) -> dict:
    """Read one URL or local path — the analyst path for a file you already have."""
    if target.startswith(("http://", "https://")):
        _, status, headers, body = fetch(target, timeout=timeout)
        if status >= 400 or not body:
            return {"target": target, "error": f"HTTP {status}"}
        ctype = (headers or {}).get("content-type", "")
    else:
        if not os.path.isfile(target):
            return {"target": target, "error": "no such file"}
        with open(target, "rb") as fh:
            body = fh.read()
        ctype = ""
    meta = parse(body)
    flagged = {k: v for k, v in meta.items()
               if k in PIVOT_KEYS and not is_generic(k, str(v))}
    return {"target": target, "bytes": len(body), "content_type": ctype[:80],
            "format": meta.get("_format", "unrecognised"),
            "sha256": hashlib.sha256(body).hexdigest(),
            "meta": {k: v for k, v in meta.items() if not k.startswith("_")},
            "pivotable": flagged}


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    as_json = "--json" in sys.argv[1:]
    if not args:
        print(__doc__.strip().splitlines()[-1], file=sys.stderr)
        print("usage: wp_docmeta.py <url-or-path> [...] [--json]", file=sys.stderr)
        return 2
    results = [_one(a) for a in args]
    if as_json:
        print(json.dumps(results, indent=2, ensure_ascii=False))
        return 0
    for r in results:
        print(f"\n=== {r['target']}")
        if r.get("error"):
            print(f"    error: {r['error']}")
            continue
        print(f"    {r['format']} · {r['bytes']} bytes · sha256 {r['sha256'][:32]}…")
        if not r["meta"]:
            print("    no embedded metadata (normal — most web pipelines strip it; "
                  "this is NOT evidence of deliberate sanitising)")
            continue
        for k, v in sorted(r["meta"].items()):
            mark = "  " if k in r["pivotable"] else " ·"   # · = context only (generic, or not an id)
            print(f"   {mark} {k:<24} {str(v)[:110]}")
        if r["pivotable"]:
            print(f"    → pivotable: {', '.join(sorted(r['pivotable']))}")
        else:
            print("    → nothing pivotable: every value names a common tool or a default "
                  "account, or is context (title/date) rather than an identifier")
    return 0


if __name__ == "__main__":
    sys.exit(main())
