#!/usr/bin/env python3
"""
render_mermaid.py — render a Mermaid diagram to the IntelGraph triple:
  <stem>_hires.png (report-grade raster), <stem>.svg, <stem>_thumb.png (800px)
and, with --pdf, a fourth output: <stem>.pdf — a VECTOR figure for the PDF report.

Works with the locally-installed mermaid-cli (`mmdc`). Auto-discovers mmdc in
PATH or common node_modules/.bin locations.

TWO THINGS THIS DOES BEYOND CALLING mmdc
----------------------------------------
1. DEVICE SCALE, NOT WIDTH, BUYS DEFINITION. `-w` sets the page width the diagram is laid out
   in; raising it just spreads the same drawing over more pixels and makes the type smaller
   relative to the figure. `-s` (puppeteer's device scale factor) rasterises the SAME layout at
   N× pixel density — the difference between a figure that stays crisp when a reader zooms into
   the PDF and one that turns to mush. So the default is a modest width at scale 2, which is
   ~4400px across for a wide estate graph: roughly 700dpi at printed width.
2. ONE HOUSE STYLE FOR EVERY FIGURE. `references/diagram.css` is injected into every render
   (mmdc -C), so a generated case graph and a hand-authored reasoning diagram come out of the
   same press. Pass --no-css to render bare mermaid.

Usage:
  render_mermaid.py diagram.mmd /path/to/out_stem [--width 2200] [--scale 2] [--pdf]
  render_mermaid.py diagram.mmd out --no-css --theme neutral

Needs headless Chrome for mmdc; if missing once, run:
  npx puppeteer browsers install chrome-headless-shell
(then set PUPPETEER_EXECUTABLE_PATH if mmdc can't find it).
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
HOUSE_CSS = os.path.normpath(os.path.join(HERE, "..", "references", "diagram.css"))


def find_mmdc():
    for cand in ("mmdc",
                 os.path.expanduser("~/node_modules/.bin/mmdc"),
                 "/usr/local/bin/mmdc", "/opt/homebrew/bin/mmdc",
                 "./node_modules/.bin/mmdc"):
        p = shutil.which(cand) or (cand if os.path.isfile(cand) else None)
        if p:
            return p
    return None


def render(mmd, stem, width, theme, background, scale=2, css=None, pdf=False, puppeteer=None):
    mmdc = find_mmdc()
    if not mmdc:
        sys.exit("mmdc not found. Install: npm i -g @mermaid-js/mermaid-cli")
    outputs = []
    # (output, page width, device scale). The SVG is already vector, so scale is meaningless
    # there; the thumb is a contact print and does not need the density.
    jobs = [(f"{stem}.svg", None, None),
            (f"{stem}_hires.png", width, scale),
            (f"{stem}_thumb.png", 900, None)]
    if pdf:
        jobs.append((f"{stem}.pdf", width, None))
    # mmdc CLI -t only accepts these; 'base' is valid only inside a %%{init}%% directive.
    allowed_cli_themes = {"default", "forest", "dark", "neutral"}
    for out, w, s in jobs:
        cmd = [mmdc, "-i", mmd, "-o", out, "-b", background]
        if theme in allowed_cli_themes:
            cmd += ["-t", theme]
        if w:
            cmd += ["-w", str(w)]
        if s and s != 1:
            cmd += ["-s", str(s)]
        if css:
            cmd += ["-C", css]
        if out.endswith(".pdf"):
            cmd += ["-f"]                      # --pdfFit: crop the page to the chart
        if puppeteer:
            cmd += ["-p", puppeteer]        # puppeteer config (e.g. --no-sandbox for root)
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            sys.stderr.write(r.stderr[-600:] + "\n")
            sys.exit(f"mmdc failed for {out}")
        outputs.append(out)
    return outputs


def main():
    ap = argparse.ArgumentParser(description="Render Mermaid to the IntelGraph triple.")
    ap.add_argument("mmd", help="input .mmd file")
    ap.add_argument("stem", help="output path stem (no extension)")
    ap.add_argument("--width", type=int, default=2200,
                    help="layout width in px (default 2200) — definition comes from --scale")
    ap.add_argument("--scale", type=float, default=2,
                    help="device scale factor for the hi-res PNG (default 2). Raises pixel "
                         "density WITHOUT shrinking type, unlike --width.")
    ap.add_argument("--theme", default="neutral",
                    help="mmdc CLI theme (default|neutral|dark|forest); use %%{init}%% in the .mmd for 'base'")
    ap.add_argument("--background", default="white", help="background (white|transparent)")
    ap.add_argument("--css", default="", help="CSS file to inject (default: the house diagram.css)")
    ap.add_argument("--no-css", action="store_true", help="render bare mermaid, no house styling")
    ap.add_argument("--pdf", action="store_true",
                    help="also emit <stem>.pdf — a VECTOR figure, which is what a PDF report "
                         "should embed: it stays sharp at any zoom and has no raster cost")
    ap.add_argument("--puppeteer-config", default="",
                    help="puppeteer config JSON passed to mmdc as -p. When omitted and running as "
                         "root, one with {\"args\":[\"--no-sandbox\"]} is auto-generated (headless "
                         "Chrome refuses to launch as root otherwise).")
    args = ap.parse_args()
    css = None if args.no_css else (args.css or (HOUSE_CSS if os.path.isfile(HOUSE_CSS) else None))
    if not args.no_css and not css:
        sys.stderr.write(f"[render_mermaid] WARNING: house stylesheet not found at {HOUSE_CSS}; "
                         f"rendering bare mermaid — the figure will not match the report's other "
                         f"diagrams.\n")
    pptr = args.puppeteer_config or None
    auto_pptr = None
    if not pptr and hasattr(os, "geteuid") and os.geteuid() == 0:
        fd, pptr = tempfile.mkstemp(prefix="mmdc-pptr-", suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump({"args": ["--no-sandbox", "--disable-setuid-sandbox"]}, fh)
        auto_pptr = pptr
        sys.stderr.write(f"[render_mermaid] running as root; auto puppeteer config -> {pptr}\n")
    os.makedirs(os.path.dirname(os.path.abspath(args.stem)), exist_ok=True)
    try:
        outs = render(args.mmd, args.stem, args.width, args.theme, args.background,
                      scale=args.scale, css=css, pdf=args.pdf, puppeteer=pptr)
    finally:
        if auto_pptr:
            try:
                os.unlink(auto_pptr)
            except OSError:
                pass
    print("wrote:\n  " + "\n  ".join(outs))


if __name__ == "__main__":
    main()
