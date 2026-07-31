#!/usr/bin/env python3
"""
render_mermaid.py — render a Mermaid diagram to the IntelGraph triple:
  <stem>_hires.png (2400px), <stem>.svg, <stem>_thumb.png (800px)

Works with the locally-installed mermaid-cli (`mmdc`). Auto-discovers mmdc in
PATH or common node_modules/.bin locations.

Usage:
  render_mermaid.py diagram.mmd /path/to/out_stem [--width 2400] [--theme base]

Needs headless Chrome for mmdc; if missing once, run:
  npx puppeteer browsers install chrome-headless-shell
(then set PUPPETEER_EXECUTABLE_PATH if mmdc can't find it).
"""
import argparse
import os
import shutil
import subprocess
import sys


def find_mmdc():
    for cand in ("mmdc",
                 os.path.expanduser("~/node_modules/.bin/mmdc"),
                 "/usr/local/bin/mmdc", "/opt/homebrew/bin/mmdc",
                 "./node_modules/.bin/mmdc"):
        p = shutil.which(cand) or (cand if os.path.isfile(cand) else None)
        if p:
            return p
    return None


def render(mmd, stem, width, theme, background):
    mmdc = find_mmdc()
    if not mmdc:
        sys.exit("mmdc not found. Install: npm i -g @mermaid-js/mermaid-cli")
    outputs = []
    jobs = [(f"{stem}.svg", None),
            (f"{stem}_hires.png", width),
            (f"{stem}_thumb.png", 800)]
    # mmdc CLI -t only accepts these; 'base' is valid only inside a %%{init}%% directive.
    allowed_cli_themes = {"default", "forest", "dark", "neutral"}
    for out, w in jobs:
        cmd = [mmdc, "-i", mmd, "-o", out, "-b", background]
        if theme in allowed_cli_themes:
            cmd += ["-t", theme]
        if w:
            cmd += ["-w", str(w)]
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
    ap.add_argument("--width", type=int, default=2400, help="hi-res width px")
    ap.add_argument("--theme", default="neutral",
                    help="mmdc CLI theme (default|neutral|dark|forest); use %%{init}%% in the .mmd for 'base'")
    ap.add_argument("--background", default="white", help="background (white|transparent)")
    args = ap.parse_args()
    os.makedirs(os.path.dirname(os.path.abspath(args.stem)), exist_ok=True)
    outs = render(args.mmd, args.stem, args.width, args.theme, args.background)
    print("wrote:\n  " + "\n  ".join(outs))


if __name__ == "__main__":
    main()
