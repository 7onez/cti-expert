#!/usr/bin/env python3
"""
make_reference_docx.py — build the pandoc --reference-doc for IntelReport's DOCX
render so a report's .docx reads as the SAME document as its .pdf.

render_report.py renders the PDF with a rich LaTeX house style (house-header.tex)
but its DOCX path had no reference.docx, so Word output fell back to pandoc's
default theme (Calibri/Cambria, Office blue). This produced the exact divergence a
reader notices: a polished PDF beside a plain-blue Word file.

This script takes pandoc's own default reference.docx and retunes ONLY its theme
and a few named styles to the muted editorial house palette — slate / steel /
ochre / brick — that theme.py and house-header.tex already share. Everything else
(numbered headings, TOC, captions, block-quote callout) keeps working because it
inherits the theme fonts and colours we override here.

The palette below is DUPLICATED from IntelGraph/scripts/theme.py on purpose, the
same way house-header.tex duplicates it: the three renderers (PDF, PNG, DOCX) are
separate toolchains and cannot import one Python module between them. Change a
colour in all three when the house style changes.

Usage:
    uv run make_reference_docx.py [out.docx]     # default: ../templates/reference.docx
Requires: pandoc on PATH (only to emit the base file — no Python deps).
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_OUT = os.path.join(os.path.dirname(HERE), "templates", "reference.docx")

# --- house palette (mirror of theme.py PALETTE / house-header.tex) -------------
INK = "1F1D1A"      # body text
SLATE = "22333F"    # H1, strong / dk2
STEEL = "3B5566"    # H2/H3, links, accent1
OCHRE = "B0790F"
BRICK = "8C2D2D"
OLIVE = "5A6B3B"
VIOLET = "5A4A7A"
SAND = "C9B892"
BAND = "DEE4E8"     # table header band (light steel-grey)
ZEBRA = "F2F2F2"    # table zebra stripe
FONT_HEADING = "Arial"    # sans — headings / furniture
FONT_BODY = "Georgia"     # serif — body

# pandoc default theme values we replace (srgbClr val=...).
THEME_COLOR_MAP = {
    "1F497D": SLATE,   # dk2
    "4F81BD": STEEL,   # accent1  (Title / Headings inherit this)
    "C0504D": BRICK,   # accent2
    "9BBB59": OLIVE,   # accent3
    "8064A2": VIOLET,  # accent4
    "4BACC6": STEEL,   # accent5
    "F79646": OCHRE,   # accent6
    "0000FF": STEEL,   # hlink
}


def make_base(tmpdir):
    """Emit pandoc's default reference.docx to work from."""
    base = os.path.join(tmpdir, "base.docx")
    with open(base, "wb") as f:
        r = subprocess.run(["pandoc", "--print-default-data-file", "reference.docx"],
                           stdout=f)
    if r.returncode != 0:
        raise SystemExit("pandoc failed to emit the default reference.docx")
    return base


def patch_theme(xml: str) -> str:
    """Swap the theme fonts (heading sans / body serif) and the Office palette for
    the house palette. Headings and Title reference accent1/dk2, so recolouring the
    theme recolours them with no per-style edit."""
    # Fonts: majorFont latin -> Arial (headings), minorFont latin -> Georgia (body).
    def _set_latin(block_tag, family):
        nonlocal xml
        def repl(m):
            inner = re.sub(r'(<a:latin typeface=")[^"]*(")',
                           r'\g<1>%s\g<2>' % family, m.group(0), count=1)
            return inner
        xml = re.sub(r'<a:%s>.*?</a:%s>' % (block_tag, block_tag), repl, xml,
                     count=1, flags=re.S)
    _set_latin("majorFont", FONT_HEADING)
    _set_latin("minorFont", FONT_BODY)
    # Scheme colours.
    for old, new in THEME_COLOR_MAP.items():
        xml = xml.replace('val="%s"' % old, 'val="%s"' % new)
    return xml


def patch_styles(xml: str) -> str:
    """Set body size/colour and give the Table style a house header band + zebra."""
    # Body text: 10.5pt (sz is in half-points) ink, applied at docDefaults.
    xml = re.sub(r'(<w:rPrDefault>\s*<w:rPr>)',
                 r'\g<1><w:color w:val="%s"/><w:sz w:val="21"/><w:szCs w:val="21"/>' % INK,
                 xml, count=1)
    # Table header band: shade the firstRow conditional-format cell.
    def band_firstRow(m):
        block = m.group(0)
        if "<w:tcPr>" in block:
            block = block.replace(
                "<w:tcPr>",
                '<w:tcPr><w:shd w:val="clear" w:color="auto" w:fill="%s"/>' % BAND, 1)
        else:
            block = block.replace(
                "</w:tblStylePr>",
                '<w:tcPr><w:shd w:val="clear" w:color="auto" w:fill="%s"/></w:tcPr></w:tblStylePr>' % BAND, 1)
        return block
    xml = re.sub(r'<w:tblStylePr w:type="firstRow">.*?</w:tblStylePr>',
                 band_firstRow, xml, count=1, flags=re.S)
    # Zebra: add a band1Horz conditional format right after the Table tblPr block.
    if 'w:type="band1Horz"' not in xml:
        band1 = ('<w:tblStylePr w:type="band1Horz"><w:tcPr>'
                 '<w:shd w:val="clear" w:color="auto" w:fill="%s"/></w:tcPr></w:tblStylePr>' % ZEBRA)
        xml = re.sub(r'(<w:style w:type="table"[^>]*w:styleId="Table">.*?</w:tblPr>)',
                     r'\g<1>' + band1, xml, count=1, flags=re.S)
    return xml


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_OUT
    tmp = tempfile.mkdtemp(prefix="mkref_")
    try:
        base = make_base(tmp)
        ex = os.path.join(tmp, "ex")
        with zipfile.ZipFile(base) as z:
            z.extractall(ex)
            names = z.namelist()
        theme = os.path.join(ex, "word", "theme", "theme1.xml")
        styles = os.path.join(ex, "word", "styles.xml")
        with open(theme, encoding="utf-8") as f:
            t = f.read()
        with open(theme, "w", encoding="utf-8") as f:
            f.write(patch_theme(t))
        with open(styles, encoding="utf-8") as f:
            s = f.read()
        with open(styles, "w", encoding="utf-8") as f:
            f.write(patch_styles(s))
        os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
        # Repack preserving the original member order (docx readers are lenient, but
        # keep [Content_Types].xml first for good measure).
        ordered = sorted(names, key=lambda n: (n != "[Content_Types].xml", n))
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
            for n in ordered:
                z.write(os.path.join(ex, n), n)
        print("wrote %s" % out)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
