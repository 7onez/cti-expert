#!/usr/bin/env python3
"""
render_mermaid.py — render a Mermaid diagram to the IntelGraph triple:
  <stem>.svg, <stem>_hires.png (report-grade raster), <stem>_thumb.png (900px wide)
and, with --pdf, a fourth output: <stem>.pdf — a VECTOR figure for the PDF report.

ENGINE: Pele (github.com/obsidianmd/pele, pinned in references/pele.json) — one dependency-free
ES module that lays Mermaid out to plain SVG, labels as real <text> (never an HTML
<foreignObject>), run under Node >= 20 or Bun. No browser and no npm install: pele_fetch.py puts
the module in IntelGraph/vendor/pele/, and this script fetches it on first use when it is missing.

THREE THINGS THIS DOES BEYOND CALLING PELE
------------------------------------------
1. ONE HOUSE STYLE FOR EVERY FIGURE. The font comes from theme.DIAGRAM and every colour from
   theme.PELE_VARS, so a generated case graph and a hand-authored reasoning diagram come out of
   the same press. Layout spacing stays in the .mmd's %%{init}%% directive (theme.mermaid_init).
2. A SELF-CONTAINED SVG. Pele paints through CSS custom properties (`var(--pele-…)`), which
   cairo and Word do not resolve — an unresolved fill renders black. Every variable is replaced
   by its value, `style="rx:…"` becomes rx/ry attributes, and a background is painted unless
   --background transparent. The SVG then renders identically in a browser, cairosvg, librsvg,
   pandoc/xelatex and Word.
3. DEVICE SCALE, NOT WIDTH, BUYS DEFINITION. --scale rasterises the SAME layout at N× pixel
   density — the difference between a figure that stays crisp when a reader zooms into the PDF
   and one that turns to mush. --width is the room Pele may reflow the layout into (wrapped
   labels, tighter spacing); 0 keeps the natural layout.

RASTERISERS (PNG + PDF), in order of text fidelity: rsvg-convert (librsvg — Pango picks a font
per glyph, so the type icons in node labels (🌐 💬 📧) and CJK names render), then a headless
Chrome / Chromium / Edge (same fallback, slower), then cairosvg. cairosvg uses cairo's basic text
API: one font per text run — the FIRST family named — so every glyph that font lacks is silently
dropped; it is kept as the last resort and warns when the figure carries such glyphs. With none of
them the SVG is still written and the script exits 1 naming what to install.

Usage:
  render_mermaid.py diagram.mmd /path/to/out_stem [--width 1900] [--scale 2] [--pdf]
  render_mermaid.py diagram.mmd out --background transparent
"""
import argparse
import json
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
RUNNER = os.path.join(HERE, "pele_render.mjs")
THUMB_WIDTH = 900

sys.path.insert(0, HERE)
from theme import DIAGRAM, PELE_VARS  # noqa: E402

# Per-call ceiling (CTI_CALL_TIMEOUT: env → .env → references/timeouts.json → 5000s). The engine's
# resolver is a stdlib sibling; a standalone copy falls back to the value the parent process exports.
try:
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(HERE)), "WebPivot", "tools"))
    from wp_timeouts import floor as _floor  # noqa: E402
except Exception:  # noqa: BLE001
    def _floor(t):
        try:
            c = int(os.environ.get("CTI_CALL_TIMEOUT") or 5000)
        except ValueError:
            c = 5000
        c = c if c > 0 else 5000
        return c if not isinstance(t, (int, float)) else max(int(t), c)


def _timeout():
    return _floor(int(os.environ.get("MERMAID_RENDER_TIMEOUT") or 180))


class RenderError(RuntimeError):
    pass


# ── layout: Mermaid text -> SVG (Pele) ───────────────────────────────────────

def find_js_runtime():
    for cand in ("node", "bun"):
        p = shutil.which(cand)
        if p:
            return p
    return None


def pele_module():
    """The pinned pele.mjs, fetched (and integrity-checked) on first use."""
    import pele_fetch
    if pele_fetch.installed_version() != pele_fetch.RELEASE.get("version"):
        sys.stderr.write(f"[render_mermaid] fetching pinned pele "
                         f"{pele_fetch.RELEASE.get('version')} into {pele_fetch.VENDOR_DIR}\n")
    try:
        return pele_fetch.ensure()
    except Exception as exc:  # noqa: BLE001
        raise RenderError(f"pele unavailable ({exc}); run: python3 {os.path.join(HERE, 'pele_fetch.py')}")


def layout(mmd_path, width=0):
    """Mermaid source -> Pele result dict {svg, width, height, type}."""
    runtime = find_js_runtime()
    if not runtime:
        raise RenderError("no JavaScript runtime for Pele — install Node.js 20+ (or Bun)")
    opts = {"responsive": False, "autoDirection": False,
            "fontFamily": DIAGRAM["font_family"], "fontSize": DIAGRAM["font_size"],
            "padding": DIAGRAM["diagram_padding"]}
    if width:
        opts["maxWidth"] = int(width)
    try:
        r = subprocess.run([runtime, RUNNER, pele_module(), mmd_path, json.dumps(opts)],
                           capture_output=True, text=True, encoding="utf-8", timeout=_timeout())
    except subprocess.TimeoutExpired:
        raise RenderError(f"pele timed out on {mmd_path}")
    if r.returncode != 0:
        raise RenderError(f"pele could not render {mmd_path}: {(r.stderr or r.stdout).strip()[-600:]}")
    return json.loads(r.stdout)


# ── SVG -> self-contained SVG ────────────────────────────────────────────────

_VAR = re.compile(r"var\(\s*(--[\w-]+)\s*(?:,\s*([^()]*(?:\([^()]*\)[^()]*)*))?\)")
_RX_STYLE = re.compile(r'\sstyle="rx:\s*([\d.]+)(?:px)?;?"')
_VIEWBOX = re.compile(r'\sviewBox="\s*([-\d.]+)[\s,]+([-\d.]+)[\s,]+([\d.]+)[\s,]+([\d.]+)\s*"')


def _resolve(text, env):
    """Replace var(--x[, fallback]) with env[--x], else the fallback. Nested vars resolve too."""
    for _ in range(8):
        new = _VAR.sub(lambda m: env.get(m.group(1)) or (m.group(2) or "").strip() or m.group(0),
                       text)
        if new == text:
            break
        text = new
    return text


def self_contained(svg, theme_vars, background="white"):
    """Pele SVG -> the same drawing with no CSS custom properties left (see the module doc, 2)."""
    m = re.search(r"<svg\b[^>]*>", svg)
    if not m:
        raise RenderError("renderer output has no <svg> element")
    tag, env = m.group(0), dict(theme_vars)
    sm = re.search(r'\sstyle="([^"]*)"', tag)
    if sm:
        decls = []
        for decl in sm.group(1).split(";"):
            key, sep, val = decl.partition(":")
            key = key.strip()
            if not sep or not key:
                continue
            if key.startswith("--"):
                env.setdefault(key, _resolve(val.strip(), env))
            else:
                decls.append(f"{key}:{_resolve(val, env).strip()}")
        tag = tag.replace(sm.group(0), ' style="' + ";".join(decls) + '"')
    tag = _resolve(tag, env)
    if background and background != "transparent":
        vb = _VIEWBOX.search(tag)
        if vb:
            x, y, w, h = vb.groups()
            tag += f'<rect x="{x}" y="{y}" width="{w}" height="{h}" fill="{background}"/>'
    body = _RX_STYLE.sub(lambda r: f' rx="{r.group(1)}" ry="{r.group(1)}"',
                         _resolve(svg[m.end():], env))
    out = svg[:m.start()] + tag + body
    left = sorted(set(_VAR.findall(out)))
    if left:
        sys.stderr.write(f"[render_mermaid] WARNING: unresolved CSS variables {left} — a "
                         f"non-browser rasteriser will paint them black\n")
    return out


# ── SVG -> PNG / PDF ─────────────────────────────────────────────────────────

def _cairosvg():
    try:
        import cairosvg
        return cairosvg
    except Exception:  # noqa: BLE001 — missing module or missing libcairo
        return None


def find_browser():
    names = ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome",
             "msedge", "microsoft-edge")
    paths = ("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
             "/Applications/Chromium.app/Contents/MacOS/Chromium",
             "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
             os.path.expandvars(r"%ProgramFiles%\Google\Chrome\Application\chrome.exe"),
             os.path.expandvars(r"%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe"),
             os.path.expandvars(r"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe"),
             os.path.expandvars(r"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe"))
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    return next((p for p in paths if os.path.isfile(p)), None)


# Glyphs the Latin-first label font lacks: emoji (pictographs, or a BMP symbol forced to emoji
# presentation by U+FE0F) and CJK. Only cairosvg drops them — see the module doc.
_FALLBACK_GLYPHS = re.compile("[\U0001F000-\U0001FAFF]|[\u2300-\u27BF\u2B00-\u2BFF]\uFE0F"
                              "|[\u2E80-\u9FFF\uAC00-\uD7AF\uF900-\uFAFF]")


def pick_rasteriser():
    rsvg = shutil.which("rsvg-convert")
    if rsvg:
        return "rsvg-convert", rsvg
    browser = find_browser()
    if browser:
        return "browser", browser
    if _cairosvg():
        return "cairosvg", None
    return None, None


def _run(cmd, what):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=_timeout())
    except subprocess.TimeoutExpired:
        raise RenderError(f"{what} timed out")
    if r.returncode != 0:
        raise RenderError(f"{what} failed: {(r.stderr or r.stdout).strip()[-400:]}")


def _browser(browser, svg_path, out, w, h, scale=1.0, pdf=False):
    """Headless Chrome/Edge, no Puppeteer: screenshot the SVG at a device scale, or print a page
    sized to the drawing so the PDF stays vector."""
    w, h = math.ceil(w), math.ceil(h)
    with tempfile.TemporaryDirectory(prefix="render-mermaid-") as profile:
        cmd = [browser, "--headless=new", "--disable-gpu", "--hide-scrollbars",
               "--no-first-run", f"--user-data-dir={profile}"]
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            cmd.append("--no-sandbox")            # Chrome refuses to start as root otherwise
        if pdf:
            page = os.path.join(profile, "page.html")
            with open(svg_path, encoding="utf-8") as fh:
                inline = fh.read()
            with open(page, "w", encoding="utf-8") as fh:
                fh.write(f"<!doctype html><meta charset=utf-8><style>@page{{size:{w}px {h}px;"
                         f"margin:0}}html,body{{margin:0}}svg{{display:block}}</style>{inline}")
            cmd += ["--no-pdf-header-footer", f"--print-to-pdf={os.path.abspath(out)}",
                    "file://" + os.path.abspath(page).replace(os.sep, "/")]
        else:
            cmd += [f"--window-size={w},{h}", f"--force-device-scale-factor={scale}",
                    f"--screenshot={os.path.abspath(out)}",
                    "file://" + os.path.abspath(svg_path).replace(os.sep, "/")]
        _run(cmd, os.path.basename(browser))
    if not os.path.isfile(out):
        raise RenderError(f"{os.path.basename(browser)} wrote no {out}")


def rasterise(kind, binary, svg_path, out, w, h, *, scale=None, width=None, pdf=False):
    """One raster/vector output from the self-contained SVG. `scale` = device scale on the
    natural size; `width` = target pixel width (aspect kept)."""
    if width:
        scale = width / float(w)
    if kind == "cairosvg":
        cs = _cairosvg()
        if pdf:
            cs.svg2pdf(url=svg_path, write_to=out)
        else:
            cs.svg2png(url=svg_path, write_to=out, scale=scale or 1)
    elif kind == "rsvg-convert":
        cmd = [binary, "-f", "pdf" if pdf else "png", "-o", out]
        if width and not pdf:
            cmd += ["-w", str(round(width)), "-a"]   # exact px; -z rounds up a pixel
        elif not pdf:
            cmd += ["-z", f"{scale or 1:g}"]
        _run(cmd + [svg_path], "rsvg-convert")
    else:
        _browser(binary, svg_path, out, w, h, scale=scale or 1, pdf=pdf)


def render(mmd, stem, width=0, scale=2, background="white", pdf=False):
    result = layout(mmd, width)
    svg_path = f"{stem}.svg"
    with open(svg_path, "w", encoding="utf-8") as fh:
        fh.write(self_contained(result["svg"], PELE_VARS, background))
    outputs = [svg_path]
    kind, binary = pick_rasteriser()
    if not kind:
        raise RenderError(f"wrote {svg_path}, but no SVG rasteriser for the PNG/PDF outputs — "
                          f"install librsvg (rsvg-convert), Chrome/Chromium, or cairosvg "
                          f"(uv pip install cairosvg)")
    if kind == "cairosvg" and _FALLBACK_GLYPHS.search(re.sub(r"<[^>]*>", "", result["svg"])):
        sys.stderr.write("[render_mermaid] WARNING: rasterising with cairosvg, which has no "
                         "per-glyph font fallback — the emoji/CJK characters in this figure's "
                         "labels will be missing from the PNG/PDF. Install librsvg "
                         "(rsvg-convert) to keep them.\n")
    w, h = float(result["width"]), float(result["height"])
    jobs = [(f"{stem}_hires.png", {"scale": scale}),
            (f"{stem}_thumb.png", {"width": min(THUMB_WIDTH, w)})]
    if pdf:
        jobs.append((f"{stem}.pdf", {"pdf": True}))
    for out, kw in jobs:
        rasterise(kind, binary, svg_path, out, w, h, **kw)
        outputs.append(out)
    return outputs


def main():
    ap = argparse.ArgumentParser(description="Render Mermaid to the IntelGraph triple (Pele).")
    ap.add_argument("mmd", help="input .mmd file")
    ap.add_argument("stem", help="output path stem (no extension)")
    ap.add_argument("--width", type=int, default=0,
                    help="room in px Pele may reflow the layout into (default 0: natural layout) "
                         "— definition comes from --scale")
    ap.add_argument("--scale", type=float, default=2,
                    help="device scale factor for the hi-res PNG (default 2). Raises pixel "
                         "density WITHOUT shrinking type, unlike --width.")
    ap.add_argument("--background", default="white",
                    help="background colour painted into the SVG, or 'transparent'")
    ap.add_argument("--pdf", action="store_true",
                    help="also emit <stem>.pdf — a VECTOR figure, which is what a PDF report "
                         "should embed: it stays sharp at any zoom and has no raster cost")
    args = ap.parse_args()
    os.makedirs(os.path.dirname(os.path.abspath(args.stem)), exist_ok=True)
    try:
        outs = render(args.mmd, args.stem, args.width, args.scale, args.background, args.pdf)
    except RenderError as exc:
        sys.exit(f"[render_mermaid] {exc}")
    print("wrote:\n  " + "\n  ".join(outs))


if __name__ == "__main__":
    main()
