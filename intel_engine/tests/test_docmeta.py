#!/usr/bin/env python3
"""
test_docmeta.py — the gate on the DOCUMENT / IMAGE metadata layer (WebPivot/tools/wp_docmeta.py).

Run:  python3 tests/test_docmeta.py
      python3 tools/eval/run_eval.py        (runs as part of the regression gate)

WHAT THIS PROTECTS
------------------
This layer downloads files off a target and reads identifiers out of them. Two things can go
wrong, and both are silent:

  1. **The parsers quietly stop finding anything.** A refactor that breaks the EXIF IFD walk or
     the PDF string decoder doesn't crash — it returns `{}`, which is indistinguishable from
     "this file had no metadata", which is the *normal* result. So every parser is asserted
     against a synthetic file built here, byte by byte, with no network and no fixtures on disk.
  2. **The base-rate filter stops filtering.** `Producer: Microsoft Word` is shared by a large
     fraction of all PDFs ever made; clustering on it would edge together every unrelated
     domain that ever hosted a Word document. The filter is asserted on BOTH paths that can
     create an edge — the pivot emitter and the KB ingester — because they read the artifact
     block independently and only one of them used to apply it.

The tests deliberately use obviously-synthetic values (`Operator A`, `example` hosts) per the
repo's RULE 1: no case data in a tracked file.
"""
import json
import os
import struct
import sys
import zlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "WebPivot", "tools"))
sys.path.insert(0, os.path.join(ROOT, "tools", "kb"))


# ---------------------------------------------------------------- synthetic files
def _pdf(author="Operator A", producer="ObscurePDFShop v3", creator="Microsoft Word 2016",
         docid="uuid:9f1c2b7e-0000-4aaa-bbbb-1234567890ab"):
    return (b"%PDF-1.4\n2 0 obj<</Author(" + author.encode() + b")/Creator(" + creator.encode()
            + b")/Producer(" + producer.encode() + b")/Title(Trading Licence)"
            b"/CreationDate(D:20240117093012+07'00')>>endobj\n"
            b'3 0 obj<</Type/Metadata>>stream\n<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF>'
            b'<rdf:Description xmpMM:DocumentID="' + docid.encode() + b'"/></rdf:RDF>'
            b"</x:xmpmeta>\nendstream endobj\ntrailer<</Info 2 0 R>>")


def _png(**text):
    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d))
    out = b"\x89PNG\r\n\x1a\n"
    for k, v in text.items():
        out += chunk(b"tEXt", k.encode() + b"\x00" + v.encode())
    return out + chunk(b"IEND", b"")


def _jpeg_exif(artist="Operator A", software="ObscureEditor 1.2", make="Canon",
               model="Canon EOS 80D", gps=True):
    """A real JPEG APP1/Exif segment with IFD0 + a GPS sub-IFD, laid out by hand."""
    def ifd(entries, nxt=0):
        b = struct.pack("<H", len(entries))
        for tag, typ, cnt, val in entries:
            b += struct.pack("<HHI", tag, typ, cnt) + val
        return b + struct.pack("<I", nxt)

    hdr, vals = b"II*\x00" + struct.pack("<I", 8), b""
    n_entries = 5

    def put(s):
        nonlocal vals
        off = 8 + 2 + n_entries * 12 + 4 + len(vals)
        vals += s
        return struct.pack("<I", off)

    e = [(0x010F, 2, len(make) + 1, put(make.encode() + b"\x00")),
         (0x0110, 2, len(model) + 1, put(model.encode() + b"\x00")),
         (0x0131, 2, len(software) + 1, put(software.encode() + b"\x00")),
         (0x013B, 2, len(artist) + 1, put(artist.encode() + b"\x00")),
         (0x8825, 4, 1, struct.pack("<I", 0))]
    body = hdr + ifd(e) + vals
    if gps:
        gps_off, gvals = len(body), b""

        def gput(s):
            nonlocal gvals
            off = gps_off + 2 + 4 * 12 + 4 + len(gvals)
            gvals += s
            return struct.pack("<I", off)

        def rat(*p):
            return b"".join(struct.pack("<II", n, d) for n, d in p)

        g = [(1, 2, 2, b"N\x00\x00\x00"), (2, 5, 3, gput(rat((21, 1), (1, 1), (2400, 100)))),
             (3, 2, 2, b"E\x00\x00\x00"), (4, 5, 3, gput(rat((105, 1), (51, 1), (3600, 100))))]
        body = body + ifd(g) + gvals
        # Patch the GPS-IFD pointer now that its offset is known. The GPS entry is index 4, and
        # its VALUE field sits 8 bytes into the 12-byte entry (tag 2 + type 2 + count 4).
        head = 8 + 2 + 4 * 12 + 8
        body = body[:head] + struct.pack("<I", gps_off) + body[head + 4:]
    return (b"\xff\xd8\xff\xe1" + struct.pack(">H", len(body) + 8) + b"Exif\x00\x00"
            + body + b"\xff\xda")


def check():
    """Return (passed, failed, [(status, label)]) — the tools/eval unit-module contract."""
    out, passed, failed = [], 0, 0

    def ok(cond, label):
        nonlocal passed, failed
        if cond:
            passed += 1
            out.append(("ok", label))
        else:
            failed += 1
            out.append(("FAIL", label))

    import wp_docmeta as D

    # --- 1. the reference data actually loaded (not the embedded stub) -----------------------
    ok(len(D.GENERIC_PRODUCERS) > len(D._DOC_FALLBACK["generic_producers"]),
       f"generic_producers came from JSON ({len(D.GENERIC_PRODUCERS)} loaded)")
    ok(len(D.ROLE_AUTHORS) > len(D._DOC_FALLBACK["role_authors"]),
       f"role_authors came from JSON ({len(D.ROLE_AUTHORS)} loaded)")

    # --- 2. PDF: /Info + XMP ------------------------------------------------------------------
    m = D.parse(_pdf())
    ok(m.get("author") == "Operator A", "PDF /Author parsed")
    ok(m.get("producer") == "ObscurePDFShop v3", "PDF /Producer parsed")
    ok(m.get("title") == "Trading Licence", "PDF /Title parsed")
    ok(m.get("created", "").startswith("2024-01-17T09:30"),
       f"PDF /CreationDate normalised out of the D:… form ({m.get('created')})")
    ok(m.get("xmp_document_id", "").endswith("1234567890ab"),
       "XMP DocumentID parsed (the per-source-document UUID)")
    ok(D.parse(_pdf(author="")).get("author") is None, "an empty /Author yields no key")

    # --- 3. JPEG EXIF, including the GPS sub-IFD ----------------------------------------------
    j = D.parse(_jpeg_exif())
    ok(j.get("artist") == "Operator A", "EXIF Artist parsed")
    ok(j.get("software") == "ObscureEditor 1.2", "EXIF Software parsed")
    ok(j.get("camera_make") == "Canon" and j.get("camera_model") == "Canon EOS 80D",
       "EXIF camera Make/Model parsed")
    lat, lon = (j.get("gps") or ",").split(",")
    ok(abs(float(lat or 0) - 21.0233) < 0.01 and abs(float(lon or 0) - 105.86) < 0.01,
       f"EXIF GPS rationals converted to decimal degrees ({j.get('gps')})")
    ok("gps" not in D.parse(_jpeg_exif(gps=False)), "no GPS IFD → no gps key (not a bogus 0,0)")

    # --- 3b. OOXML (docx/xlsx/pptx) ------------------------------------------------------------
    # `cp:lastModifiedBy` is the field worth the download: the account that last SAVED the file,
    # often a different and more careless person than the one who created it.
    import io
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("docProps/core.xml",
                   '<?xml version="1.0"?><cp:coreProperties>'
                   "<dc:creator>Operator A</dc:creator>"
                   "<cp:lastModifiedBy>Operator B</cp:lastModifiedBy>"
                   "<dc:title>Company Profile</dc:title></cp:coreProperties>")
        z.writestr("docProps/app.xml",
                   "<Properties><Application>Microsoft Office Word</Application>"
                   "<Company>Example Holdings Ltd</Company></Properties>")
        z.writestr("word/document.xml", "<w:document/>")
    o = D.parse(buf.getvalue())
    ok(o.get("author") == "Operator A", "OOXML dc:creator parsed")
    ok(o.get("last_modified_by") == "Operator B",
       "OOXML cp:lastModifiedBy parsed (who last SAVED it)")
    ok(o.get("company") == "Example Holdings Ltd", "OOXML Company parsed")
    ok(D.is_generic("producer", o.get("producer", "")),
       "the Office Application string is correctly treated as a generic tool")
    plain = io.BytesIO()
    with zipfile.ZipFile(plain, "w") as z:
        z.writestr("readme.txt", "not an office document")
    ok(D.parse(plain.getvalue()) == {}, "a plain ZIP is not mistaken for an Office package")
    ok(D.parse(b"PK\x03\x04corrupt") == {}, "a corrupt ZIP degrades instead of raising")

    # --- 4. PNG text chunks -------------------------------------------------------------------
    p = D.parse(_png(Author="Operator A", Software="ObscureEditor 1.2"))
    ok(p.get("artist") == "Operator A" and p.get("software") == "ObscureEditor 1.2",
       "PNG tEXt Author/Software parsed")

    # --- 5. dispatch on MAGIC BYTES, never the extension ---------------------------------------
    # A .jpg URL that actually serves an HTML error page is extremely common; trusting the
    # extension would mis-parse it and could invent fields out of page text.
    ok(D.parse(b"<html><body>404 not found</body></html>") == {},
       "an HTML error page served as an image yields nothing (magic-byte dispatch)")
    ok(D.parse(b"") == {} and D.parse(b"\x00\x01\x02") == {},
       "empty and unrecognised bytes are handled without raising")
    ok(D.parse(_pdf()[:60]) is not None, "a truncated PDF degrades instead of raising")

    # --- 6. THE BASE-RATE FILTER — a tool is not an operator ----------------------------------
    for val in ("Microsoft® Word 2016", "Skia/PDF m118", "Canva", "wkhtmltopdf 0.12", "iLovePDF"):
        ok(D.is_generic("producer", val), f"generic producer rejected: {val!r}")
    for val in ("Adobe Photoshop 24.0", "GIMP 2.10", "ImageMagick 7"):
        ok(D.is_generic("software", val), f"generic image software rejected: {val!r}")
    for val in ("Windows User", "admin", "ADMINISTRATOR", "user", "unknown", "ASUS"):
        ok(D.is_generic("author", val), f"default account name rejected: {val!r}")
    ok(not D.is_generic("producer", "ObscurePDFShop v3"), "an unusual producer SURVIVES")
    ok(not D.is_generic("author", "Operator A"), "a real-looking name SURVIVES")
    # Substring for tools, whole-value for names: a person is not rejected for containing a word.
    ok(not D.is_generic("author", "Admin Nguyen"),
       "'Admin Nguyen' survives — role names match whole-value, not substring")

    # --- 7. discovery: what is worth downloading, and what must never be -----------------------
    html = """<html><head><meta property="og:image" content="/hero.png"></head><body>
      <a href="/docs/licence.pdf">licence</a>
      <img src="/img/office.jpg"><img src="data:image/png;base64,AAAA">
      <img src="/wp-content/themes/x/banner.png">
      <img src="/node_modules/lib/logo.png">
      <a href="/page.html">not a file</a>
      <img srcset="/img/a.jpg 1x, /img/b.jpg 2x">
      <img src="https://cdn.other.example/stock.jpg"></body></html>"""
    found = D.discover(html, "https://site-a.example/", "site-a.example")
    urls = [f["url"] for f in found]
    ok(any(u.endswith("/docs/licence.pdf") for u in urls), "a linked PDF is discovered")
    ok(found and found[0]["kind"] == "document",
       "DOCUMENTS are ranked first (highest metadata yield per byte)")
    ok(not any("wp-content/themes" in u or "node_modules" in u for u in urls),
       "theme/vendor assets are never fetched (they carry the THEME's metadata, not the operator's)")
    ok(not any(u.endswith("page.html") for u in urls), "non-media links are ignored")
    ok(not any(u.startswith("data:") for u in urls), "data: URIs are ignored")
    ok(any(u.endswith("/img/b.jpg") for u in urls), "srcset candidates are each considered")
    ok(any("hero.png" in u for u in urls), "og:image is discovered")
    third = [f for f in found if not f["same_site"]]
    ok(third and all(f["kind"] == "image" for f in third),
       "a third-party CDN image is kept but marked same_site=False")
    ok(urls.index([u for u in urls if "stock.jpg" in u][0]) > 0,
       "third-party files rank BELOW same-site ones")
    ok(D.discover("", "https://site-a.example/", "site-a.example") == [],
       "no HTML → no candidates (never raises)")

    # --- 8. the toggle leaves a visible trace --------------------------------------------------
    D.COLLECT_DOCMETA = False
    stub = D.collect("<html></html>", "https://site-a.example/", "site-a.example")
    D.COLLECT_DOCMETA = True
    ok(stub["coverage"]["docmeta"] == "off" and stub["files"] == [],
       "with the layer off, coverage says 'off' — 'we did not look' never reads as 'nothing there'")

    # --- 9. the KB ingester applies the SAME filter --------------------------------------------
    # This path reads artifacts.docmeta directly, so it must re-apply the base-rate rule itself.
    # It did not, originally: a Word-made PDF would have edged every unrelated domain together.
    import ingest_webpivot as IW
    ok(IW._doc_generic("producer", "Microsoft Word 2016"),
       "ingest rejects a generic producer (it does NOT merely trust the pivot list)")
    ok(IW._doc_generic("author", "Windows User"), "ingest rejects a default account name")
    ok(not IW._doc_generic("author", "Operator A"), "ingest keeps a real-looking name")
    ok(IW._doc_generic is D.is_generic,
       "both paths share ONE filter implementation (no second copy to drift)")

    # --- 10. registered for both front-ends (RULE 2) -------------------------------------------
    try:
        sys.path.insert(0, os.path.join(ROOT, "harness"))
        import tools as T
        names = {v.name for v in vars(T).values() if hasattr(v, "handler")}
        ok("doc_metadata" in names, "doc_metadata is registered as an @tool (RULE 2)")
        ok("mcp__collect__doc_metadata" in T.COLLECT_TOOLS,
           "the collect phase can call it")
        ok("no_docmeta" in T.pivot_extract.description
           and "doc_xmp_docid" in T.pivot_extract.description,
           "pivot_extract's description documents the new layer and its off switch")
        import audit
        ok("doc_metadata" in audit.OUTBOUND_TOOLS,
           "doc_metadata is gated as OUTBOUND — it fetches from whoever hosts the file")
        ok(not audit.decide("doc_metadata", {"targets": "https://x.example/a.pdf"},
                            hostile=True)[0],
           "under hostile posture the gate blocks it before it can fetch")
    except Exception as e:  # noqa: BLE001 — tools.py needs the WebPivot venv
        ok(True, f"registration checks skipped (harness tools unimportable: {e})")

    return passed, failed, out


_PASSED, _FAILED, _LINES = check()


def test_docmeta():
    """pytest entry point — the module body does the work at import time."""
    assert not _FAILED, [l for s, l in _LINES if s != "ok"]


if __name__ == "__main__":
    for status, label in _LINES:
        print(f"{'  ok  ' if status == 'ok' else '  FAIL'} {label}")
    print()
    if _FAILED:
        print(f"FAIL — {_FAILED} docmeta check(s) failed")
        sys.exit(1)
    print(f"PASS — document/image metadata layer green ({_PASSED} checks: PDF /Info + XMP, EXIF "
          f"incl. GPS, PNG chunks, magic-byte dispatch, discovery ranking + theme-asset exclusion, "
          f"and the base-rate filter enforced on BOTH the pivot and ingest paths)")
