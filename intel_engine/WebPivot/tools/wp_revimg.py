#!/usr/bin/env python3
"""wp_revimg — reverse-image search for ONE image: where else does this picture appear?

Input an image URL or a local file path.

  Always     fingerprint the bytes: sha256, perceptual aHash + dHash (Pillow, imported lazily; absent
             → sha256 only, stated), dimensions (Pillow, else a stdlib header sniff), and embedded
             EXIF/XMP via wp_docmeta.parse (most web pipelines strip it — empty is normal).
  Image URL  build the per-engine search links (Yandex, Bing Visual Search, Google Lens, TinEye) and
             keyless-read Yandex's 'sites containing this image' list (page URL, title, snippet).
             Sending the image URL to Yandex discloses that URL to Yandex; `--links-only` skips it.
  Local file NOTHING is uploaded unless `--confirm-upload` (MCP: confirm=true). Without it the result
             is a BRIEFING — which engine would receive the bytes and the manual steps. With it the
             bytes go to Yandex only (multipart, as its web form posts) and the sites list is parsed
             the same way.
  Face engines (PimEyes, FaceCheck.ID) are emitted as manual links with a note — paid / ToS forbids
             automation — and are never called.

Attribution rail (SKILL.md RULE 5): every hit is a LEAD (`rung: "lead"` + `caveat`). The same or a
similar image on another page proves reuse of the image, not the identity of a person or operator;
a face needs independent corroboration. Nothing here writes a KB edge or an operator link.

Tri-state per engine, never raises: `status` is "ok" (parsed; zero hits is a real empty), "blocked"
(CAPTCHA / bot wall / 403 / 429 — NOT a negative), "unparsed" (page served but layout unknown —
NOT a negative), or "error" (transport failure). Endpoints, markers and notes are reference DATA
(`references/reverse_image.json`, RULE 3).

CLI:
  python3 wp_revimg.py https://example.com/photo.jpg --case CASE-0001   # saves cases/CASE-0001/revimg/
  python3 wp_revimg.py ./photo.jpg                     # briefing only — no upload
  python3 wp_revimg.py ./photo.jpg --confirm-upload    # uploads to Yandex, parses sites
  python3 wp_revimg.py https://example.com/photo.jpg --links-only
  python3 wp_revimg.py --parse-html saved_yandex_sites.html   # parse a page saved from a browser
"""
import argparse
import datetime
import hashlib
import html as _html
import io
import json
import os
import re
import struct
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
ENGINE = os.path.dirname(os.path.dirname(HERE))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
from wp_common import DEFAULT_UA, _browser_headers, _decode_body  # noqa: E402 — installs egress proxy
from wp_net import fetch  # noqa: E402
from wp_refs import load_ref, ref_path  # noqa: E402
import wp_docmeta  # noqa: E402 — the repo's stdlib EXIF/XMP/PNG-text reader

# --- reference DATA (RULE 3): the fallback is the conservative minimum — Yandex only, no tracking
#     strip beyond utm_source, the RULE 5 caveat text.
_FALLBACK = {
    "settings": {"timeout_seconds": 30, "max_image_bytes": 15 << 20, "max_hits": 50,
                 "phash_size": 8},
    "strip_query_params": ["utm_source"],
    "search_links": {"yandex": "https://yandex.com/images/search?rpt=imageview&url={url}"},
    "upload_pages": {"yandex": "https://yandex.com/images/"},
    "yandex": {"sites_by_url": "https://yandex.com/images/search?rpt=imageview&url={url}&cbir_page=sites",
               "upload": "https://yandex.com/images/search?rpt=imageview&format=json&request="
                         "%7B%22blocks%22%3A%5B%7B%22block%22%3A%22b-page_type_search-by-image__link"
                         "%22%7D%5D%7D",
               "upload_field": "upfile",
               "params_from_cbir": "rpt=imageview&cbir_id={cbir_id}&url={image_url}",
               "sites_by_params": "https://yandex.com/images/search?{params}&cbir_page=sites"},
    "yandex_blocked_markers": ["showcaptcha", "smartcaptcha"],
    "yandex_sites_markers": {"json_key": "\"sites\":[", "item_class": "CbirSites-Item",
                             "title_class": "CbirSites-ItemTitle",
                             "description_class": "CbirSites-ItemDescription",
                             "empty_markers": ["CbirSitesPage"]},
    "face_engines": {},
    "wayback": {"hint": "https://web.archive.org/web/*/{url}"},
    "caveat": {"hit": "Lead only: image reuse is not identity; faces need corroboration.",
               "result": "Reverse-image hits are leads, not attribution."},
}
_REFS = load_ref(ref_path(__file__, "reverse_image.json"), _FALLBACK)
_SET = _REFS["settings"]
TIMEOUT = int(_SET.get("timeout_seconds") or 30)
MAX_IMAGE_BYTES = int(_SET.get("max_image_bytes") or (15 << 20))
MAX_HITS = int(_SET.get("max_hits") or 50)
PHASH_SIZE = int(_SET.get("phash_size") or 8)
STRIP_PARAMS = {str(p).lower() for p in _REFS["strip_query_params"]}
SEARCH_LINKS = _REFS["search_links"]
UPLOAD_PAGES = _REFS["upload_pages"]
YANDEX = _REFS["yandex"]
BLOCKED_MARKERS = [str(m).lower() for m in _REFS["yandex_blocked_markers"]]
SITES = _REFS["yandex_sites_markers"]
FACE_ENGINES = _REFS["face_engines"]
WAYBACK_HINT = (_REFS["wayback"] or {}).get("hint") or _FALLBACK["wayback"]["hint"]
CAVEAT_HIT = (_REFS["caveat"] or {}).get("hit") or _FALLBACK["caveat"]["hit"]
CAVEAT_RESULT = (_REFS["caveat"] or {}).get("result") or _FALLBACK["caveat"]["result"]


# --------------------------------------------------------------------------- fingerprint
def _sniff_dims(raw: bytes):
    """(format, width, height) from the header alone — the stdlib path when Pillow is absent."""
    try:
        if raw[:8] == b"\x89PNG\r\n\x1a\n" and raw[12:16] == b"IHDR":
            w, h = struct.unpack(">II", raw[16:24])
            return "png", w, h
        if raw[:6] in (b"GIF87a", b"GIF89a"):
            w, h = struct.unpack("<HH", raw[6:10])
            return "gif", w, h
        if raw[:4] == b"RIFF" and raw[8:12] == b"WEBP":
            chunk = raw[12:16]
            if chunk == b"VP8X":
                return "webp", 1 + int.from_bytes(raw[24:27], "little"), \
                    1 + int.from_bytes(raw[27:30], "little")
            if chunk == b"VP8L":
                b = int.from_bytes(raw[21:25], "little")
                return "webp", (b & 0x3FFF) + 1, ((b >> 14) & 0x3FFF) + 1
            if chunk == b"VP8 ":
                w, h = struct.unpack("<HH", raw[26:30])
                return "webp", w & 0x3FFF, h & 0x3FFF
            return "webp", None, None
        if raw[:2] == b"\xff\xd8":
            i = 2
            while i + 9 < len(raw):
                if raw[i] != 0xFF:
                    i += 1
                    continue
                marker = raw[i + 1]
                if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
                    i += 2
                    continue
                seg = struct.unpack(">H", raw[i + 2:i + 4])[0]
                if marker in (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB,
                              0xCD, 0xCE, 0xCF):
                    h, w = struct.unpack(">HH", raw[i + 5:i + 9])
                    return "jpeg", w, h
                i += 2 + seg
            return "jpeg", None, None
    except (struct.error, IndexError):
        pass
    return None, None, None


def _phash(raw: bytes):
    """(aHash, dHash, note) as 64-bit hex when Pillow is installed; (None, None, why) otherwise.
    aHash = grey grid vs its mean; dHash = horizontal gradient sign. Both survive resizing and
    recompression, so a near-identical hash on another copy means the same picture, re-encoded."""
    try:
        from PIL import Image  # lazy: optional dependency
    except ImportError:
        return None, None, "skipped: Pillow not installed — sha256 only (exact-copy match)"
    try:
        n = PHASH_SIZE
        resample = getattr(getattr(Image, "Resampling", Image), "LANCZOS")
        with Image.open(io.BytesIO(raw)) as im:
            grey = im.convert("L")
            sa, sd = grey.resize((n, n), resample), grey.resize((n + 1, n), resample)
            pixels = (lambda img: list(img.get_flattened_data())) \
                if hasattr(sa, "get_flattened_data") else (lambda img: list(img.getdata()))
            a, d = pixels(sa), pixels(sd)
        mean = sum(a) / len(a)
        abits = "".join("1" if p > mean else "0" for p in a)
        dbits = "".join("1" if d[r * (n + 1) + c] > d[r * (n + 1) + c + 1] else "0"
                        for r in range(n) for c in range(n))
        width = (n * n + 3) // 4
        return f"{int(abits, 2):0{width}x}", f"{int(dbits, 2):0{width}x}", "pillow"
    except Exception as e:  # noqa: BLE001 — not decodable as an image
        return None, None, f"skipped: Pillow could not decode the bytes ({type(e).__name__})"


def fingerprint(raw: bytes) -> dict:
    """sha256 + perceptual hashes + dimensions + embedded metadata of one image's bytes."""
    fmt, w, h = _sniff_dims(raw)
    try:
        from PIL import Image  # lazy: Pillow knows more formats than the header sniff
        with Image.open(io.BytesIO(raw)) as im:
            w, h = im.size
            fmt = (im.format or fmt or "").lower() or None
    except Exception:  # noqa: BLE001 — ImportError or undecodable: keep the stdlib sniff
        pass
    ahash, dhash, how = _phash(raw)
    meta = wp_docmeta.parse(raw)
    exif = {k: v for k, v in meta.items() if not k.startswith("_")}
    return {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw), "format": fmt,
            "width": w, "height": h, "ahash": ahash, "dhash": dhash, "phash_engine": how,
            "exif_present": bool(exif), "exif": exif,
            "exif_note": None if exif else "no embedded metadata — normal, most web pipelines "
                                            "strip it; NOT evidence of deliberate sanitising"}


# --------------------------------------------------------------------------- links
def search_links(image_url: str) -> dict:
    q = urllib.parse.quote(image_url, safe="")
    return {eng: tpl.replace("{url}", q) for eng, tpl in SEARCH_LINKS.items()}


def face_links() -> list:
    return [{"engine": k, "url": v.get("url"), "note": v.get("note"), "automated": False}
            for k, v in FACE_ENGINES.items() if isinstance(v, dict)]


# --------------------------------------------------------------------------- Yandex parse
def _clean_url(u: str) -> str:
    try:
        p = urllib.parse.urlsplit(u)
    except ValueError:
        return u
    if not p.query:
        return u
    kept = [(k, v) for k, v in urllib.parse.parse_qsl(p.query, keep_blank_values=True)
            if k.lower() not in STRIP_PARAMS]
    return urllib.parse.urlunsplit(p._replace(query=urllib.parse.urlencode(kept)))


def _hit(url, title, snippet, domain=None, image=None, engine="yandex") -> dict:
    url = _clean_url(_html.unescape(url or "").strip())
    if url.startswith("//"):
        url = "https:" + url
    h = {"url": url, "title": (title or "").strip(), "snippet": (snippet or "").strip(),
         "domain": domain or urllib.parse.urlsplit(url).hostname or "", "engine": engine,
         "wayback_hint": WAYBACK_HINT.replace("{url}", url), "rung": "lead", "caveat": CAVEAT_HIT}
    if isinstance(image, dict) and image.get("url"):
        iu = image["url"]
        h["image_url"] = "https:" + iu if iu.startswith("//") else iu
        if image.get("width") and image.get("height"):
            h["image_size"] = f"{image['width']}x{image['height']}"
    return h


def _find_sites(node):
    """Depth-first search of the embedded app state for the first `sites` list of page rows."""
    if isinstance(node, dict):
        v = node.get("sites")
        if isinstance(v, list) and v and isinstance(v[0], dict) and "url" in v[0]:
            return v
        for x in node.values():
            r = _find_sites(x)
            if r is not None:
                return r
    elif isinstance(node, list):
        for x in node:
            r = _find_sites(x)
            if r is not None:
                return r
    return None


def _sites_from_state(text: str):
    """Rows from the HTML-escaped JSON in the data-state attribute that carries `"sites":[`."""
    key = SITES.get("json_key") or "\"sites\":["
    esc = _html.escape(key, quote=True)
    i = text.find(esc)
    if i < 0:
        return None
    start = text.rfind('data-state="', 0, i)
    if start < 0:
        return None
    start += len('data-state="')
    end = text.find('"', i)
    if end < 0:
        return None
    try:
        state = json.loads(_html.unescape(text[start:end]))
    except ValueError:
        return None
    return _find_sites(state)


def _strip_tags(s: str) -> str:
    return _html.unescape(re.sub(r"<[^>]+>", "", s or "")).strip()


def _sites_from_html(text: str) -> list:
    """Fallback: the rendered <li class="CbirSites-Item"> rows."""
    item, tcls, dcls = (re.escape(SITES.get("item_class") or "CbirSites-Item"),
                        re.escape(SITES.get("title_class") or "CbirSites-ItemTitle"),
                        re.escape(SITES.get("description_class") or "CbirSites-ItemDescription"))
    rows = []
    for li in re.findall(rf'<li[^>]*class="[^"]*\b{item}\b[^"]*"[^>]*>(.*?)</li>', text, re.S):
        tm = re.search(rf'class="[^"]*\b{tcls}\b[^"]*"[^>]*>\s*<a[^>]*href="([^"]+)"[^>]*>(.*?)</a>',
                       li, re.S)
        if not tm:
            continue
        dm = re.search(rf'class="[^"]*\b{dcls}\b[^"]*"[^>]*>(.*?)</div>', li, re.S)
        rows.append({"url": tm.group(1), "title": _strip_tags(tm.group(2)),
                     "description": _strip_tags(dm.group(1)) if dm else ""})
    return rows


def is_blocked(final_url: str, status: int, text: str) -> bool:
    if status in (403, 429):
        return True
    hay = ((final_url or "") + " " + (text or "")[:200000]).lower()
    return any(m in hay for m in BLOCKED_MARKERS)


def parse_yandex_sites(text: str, final_url: str = "", status: int = 200) -> dict:
    """{status, hits, parser} from a Yandex 'sites' results page. Never raises."""
    if is_blocked(final_url, status, text):
        return {"status": "blocked", "hits": [],
                "note": "CAPTCHA / bot wall — not a negative; open the search link by hand, or "
                        "save the sites page from a browser and run --parse-html on it"}
    rows, parser = _sites_from_state(text), "state_json"
    if not rows:
        rows, parser = _sites_from_html(text), "html"
    hits, seen = [], set()
    for r in rows or []:
        if not isinstance(r, dict) or not r.get("url"):
            continue
        h = _hit(r.get("url"), r.get("title"), r.get("description"), r.get("domain"),
                 r.get("originalImage"))
        if h["url"] in seen:
            continue
        seen.add(h["url"])
        hits.append(h)
        if len(hits) >= MAX_HITS:
            break
    if hits:
        return {"status": "ok", "parser": parser, "hits": hits}
    if any(m in (text or "") for m in SITES.get("empty_markers") or []):
        return {"status": "ok", "parser": "empty", "hits": [],
                "note": "Yandex rendered the sites page and listed no pages for this image"}
    return {"status": "unparsed", "hits": [],
            "note": "page served but no known results layout — not a negative; update "
                    "yandex_sites_markers in references/reverse_image.json"}


# --------------------------------------------------------------------------- Yandex network
def _get_sites(url: str, timeout: int) -> dict:
    try:
        final, status, _h, body = fetch(url, timeout=timeout)
    except Exception as e:  # noqa: BLE001
        return {"status": "error", "error": f"{type(e).__name__}: {e}"[:300], "request_url": url}
    text = (body or b"").decode("utf-8", "replace")
    if status >= 400 and status not in (403, 429):
        return {"status": "error", "error": f"HTTP {status}", "request_url": url}
    out = parse_yandex_sites(text, final, status)
    out.update({"http_status": status, "request_url": url, "final_url": final})
    return out


def yandex_by_url(image_url: str, timeout: int = TIMEOUT) -> dict:
    url = YANDEX["sites_by_url"].replace("{url}", urllib.parse.quote(image_url, safe=""))
    return _get_sites(url, timeout)


def _post_multipart(url: str, field: str, filename: str, raw: bytes, timeout: int):
    """(status, final_url, body_bytes) — a browser-shaped multipart POST under the Android UA."""
    hdrs = _browser_headers(DEFAULT_UA)
    hdrs["Accept"] = "application/json, text/javascript, */*; q=0.01"
    try:
        import requests  # lazy: optional; the stdlib path below is complete
        r = requests.post(url, headers=hdrs, timeout=timeout,
                          files={field: (filename, raw, "application/octet-stream")})
        return r.status_code, r.url, r.content
    except ImportError:
        pass
    boundary = "----revimg" + uuid.uuid4().hex
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"{field}\"; "
            f"filename=\"{filename}\"\r\nContent-Type: application/octet-stream\r\n\r\n").encode() \
        + raw + f"\r\n--{boundary}--\r\n".encode()
    hdrs["Content-Type"] = f"multipart/form-data; boundary={boundary}"
    req = urllib.request.Request(url, data=body, headers=hdrs, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.geturl(), _decode_body(
                resp.read(), resp.headers.get("Content-Encoding"))
    except urllib.error.HTTPError as e:
        return e.code, url, _decode_body(e.read(), (e.headers or {}).get("Content-Encoding"))


def yandex_upload(raw: bytes, filename: str, timeout: int = TIMEOUT) -> dict:
    """Upload the bytes to Yandex (OUTBOUND — callers gate this on confirm) and parse its sites."""
    try:
        status, final, body = _post_multipart(YANDEX["upload"], YANDEX.get("upload_field") or "upfile",
                                              filename, raw, timeout)
    except Exception as e:  # noqa: BLE001
        return {"status": "error", "error": f"upload: {type(e).__name__}: {e}"[:300]}
    text = (body or b"").decode("utf-8", "replace")
    if is_blocked(final, status, text):
        return {"status": "blocked", "hits": [], "http_status": status,
                "note": "CAPTCHA / bot wall on upload — not a negative; upload by hand"}
    if status >= 400:
        return {"status": "error", "error": f"upload HTTP {status}"}
    try:
        p = json.loads(text)["blocks"][0]["params"]
        if p.get("url"):                                  # older form: a ready query string
            params = p["url"]
        else:                                             # current form: cbirId + stored copy
            params = (YANDEX.get("params_from_cbir") or _FALLBACK["yandex"]["params_from_cbir"]) \
                .replace("{cbir_id}", urllib.parse.quote(p["cbirId"], safe="")) \
                .replace("{image_url}", urllib.parse.quote(p.get("originalImageUrl") or "", safe=""))
    except (ValueError, KeyError, IndexError, TypeError, AttributeError):
        return {"status": "unparsed", "hits": [], "http_status": status,
                "note": "upload answered without blocks[0].params.url or .cbirId — not a "
                        "negative; Yandex may have changed the form endpoint"}
    out = _get_sites(YANDEX["sites_by_params"].replace("{params}", params), timeout)
    out["uploaded"] = True
    return out


# --------------------------------------------------------------------------- orchestration
def _load(target: str, timeout: int):
    """(raw|None, kind, error|None)."""
    if re.match(r"^https?://", target, re.I):
        try:
            _f, status, _h, body = fetch(target, timeout=timeout)
        except Exception as e:  # noqa: BLE001
            return None, "url", f"image fetch failed: {type(e).__name__}: {e}"[:300]
        if status >= 400 or not body:
            return None, "url", f"image fetch HTTP {status}"
        if len(body) > MAX_IMAGE_BYTES:
            return None, "url", f"{len(body)} bytes > max_image_bytes {MAX_IMAGE_BYTES}"
        return body, "url", None
    if not os.path.isfile(target):
        return None, "file", "no such file"
    size = os.path.getsize(target)
    if size > MAX_IMAGE_BYTES:
        return None, "file", f"{size} bytes > max_image_bytes {MAX_IMAGE_BYTES}"
    with open(target, "rb") as fh:
        return fh.read(), "file", None


def _briefing(raw: bytes, target: str) -> dict:
    return {
        "would_upload_to": "yandex",
        "endpoint": YANDEX["upload"].split("?", 1)[0],
        "what_is_sent": f"the image bytes ({len(raw)} bytes, sha256 "
                        f"{hashlib.sha256(raw).hexdigest()}) as multipart field "
                        f"'{YANDEX.get('upload_field') or 'upfile'}', from this machine's egress "
                        "under an Android browser UA",
        "risk": "Yandex retains the upload and it becomes searchable/attributable to the egress. "
                "Never upload a victim's private photo, a document image, or anything the "
                "subject could learn was searched without authorisation.",
        "to_proceed": "re-run with --confirm-upload (MCP: confirm=true)",
        "manual_steps": [f"open {u} and upload '{os.path.basename(target)}' yourself ({eng})"
                         for eng, u in UPLOAD_PAGES.items()]
                        + ["TinEye: sort results by 'Oldest' for first publication",
                           "Face engines (manual only, paid / ToS): see face_engines"],
    }


def save_to_case(case_id: str, res: dict):
    if not case_id or not res.get("fingerprint"):
        return None
    home = os.environ.get("INTEL_HOME") or ENGINE
    case_dir = os.path.join(home, "cases", case_id)
    if not os.path.isdir(case_dir):
        return None
    out_dir = os.path.join(case_dir, "revimg")
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    try:
        os.makedirs(out_dir, exist_ok=True)
        path = os.path.join(out_dir, f"{res['fingerprint']['sha256'][:16]}_{stamp}.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(res, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
        return path
    except OSError:
        return None


def search(target: str, case: str = None, confirm: bool = False, links_only: bool = False,
           timeout: int = None) -> dict:
    """The whole run for one image URL or local path. Never raises."""
    timeout = int(timeout or TIMEOUT)
    raw, kind, err = _load(target, timeout)
    res = {"target": target, "kind": kind, "rung": "lead", "caveat": CAVEAT_RESULT,
           "fingerprint": fingerprint(raw) if raw else None,
           "fingerprint_error": err, "search_links": {}, "face_engines": face_links(),
           "engines": {}, "hits": [], "upload": None, "saved_to": None}
    if kind == "url":
        res["search_links"] = search_links(target)
        if links_only:
            res["engines"]["yandex"] = {"status": "skipped", "note": "--links-only"}
        else:
            res["engines"]["yandex"] = yandex_by_url(target, timeout)
    elif raw is None:
        res["error"] = err
        return res
    elif not confirm:
        res["upload"] = {"performed": False, "briefing": _briefing(raw, target)}
        res["engines"]["yandex"] = {"status": "skipped", "note": "local file — upload needs confirm"}
    else:
        res["upload"] = {"performed": True, "engine": "yandex",
                         "sha256": hashlib.sha256(raw).hexdigest()}
        res["engines"]["yandex"] = yandex_upload(raw, os.path.basename(target) or "image.jpg",
                                                 timeout)
    for eng in res["engines"].values():
        eng_hits = eng.pop("hits", None) or []
        eng["hit_count"] = len(eng_hits)
        res["hits"].extend(eng_hits)
    if case:
        res["saved_to"] = save_to_case(case, res)
    return res


def main() -> int:
    ap = argparse.ArgumentParser(description="Reverse-image search (hits are LEADS, not identity).")
    ap.add_argument("target", nargs="?", help="image URL or local file path")
    ap.add_argument("--case", help="case id — the result is saved to cases/<id>/revimg/")
    ap.add_argument("--confirm-upload", action="store_true",
                    help="LOCAL file only: actually upload the bytes to Yandex (outbound)")
    ap.add_argument("--links-only", action="store_true",
                    help="image URL: build links + fingerprint, do not query Yandex")
    ap.add_argument("--parse-html", metavar="FILE",
                    help="offline: parse a saved Yandex 'sites' results page and exit")
    ap.add_argument("--timeout", type=int, default=None)
    ap.add_argument("--json", action="store_true", help="compact JSON (default: pretty-printed)")
    a = ap.parse_args()
    if a.parse_html:
        try:
            with open(a.parse_html, encoding="utf-8", errors="replace") as fh:
                res = parse_yandex_sites(fh.read())
        except OSError as e:
            res = {"status": "error", "error": str(e), "hits": []}
        res["caveat"] = CAVEAT_RESULT
    elif a.target:
        res = search(a.target, a.case, a.confirm_upload, a.links_only, a.timeout)
    else:
        ap.print_usage(sys.stderr)
        return 2
    print(json.dumps(res, indent=None if a.json else 2, ensure_ascii=False))
    return 1 if res.get("error") else 0


if __name__ == "__main__":
    sys.exit(main())
