#!/usr/bin/env python3
"""
render_graphviz.py — render a Graphviz .dot to the IntelGraph triple:
  <stem>_hires.png (300dpi), <stem>.svg, <stem>_thumb.png (smaller)

For actor→infrastructure→victim link analysis. Prefers the `graphviz` python
lib; falls back to the `dot` binary. One of them must be installed:
  pip install graphviz   AND/OR   brew install graphviz   (provides `dot`)
"""
import argparse
import os
import shutil
import subprocess
import sys


def _via_dot(dot_path, src, stem):
    outs = []
    for fmt, out, extra in (("svg", f"{stem}.svg", []),
                            ("png", f"{stem}_hires.png", ["-Gdpi=300"]),
                            ("png", f"{stem}_thumb.png", ["-Gdpi=110"])):
        r = subprocess.run([dot_path, f"-T{fmt}", *extra, src, "-o", out],
                           capture_output=True, text=True)
        if r.returncode != 0:
            sys.stderr.write(r.stderr[-600:] + "\n")
            sys.exit(f"dot failed for {out}")
        outs.append(out)
    return outs


def _via_lib(src, stem):
    import graphviz  # type: ignore
    source = open(src, encoding="utf-8").read()
    g = graphviz.Source(source)
    outs = []
    g.render(outfile=f"{stem}.svg", format="svg", cleanup=True); outs.append(f"{stem}.svg")
    # dpi via graph attribute if present; library renders at default otherwise
    g.render(outfile=f"{stem}_hires.png", format="png", cleanup=True); outs.append(f"{stem}_hires.png")
    outs.append(f"{stem}_hires.png")  # lib has no separate thumb; reuse hi-res
    return outs


def main():
    ap = argparse.ArgumentParser(description="Render Graphviz DOT to the IntelGraph triple.")
    ap.add_argument("dot", help="input .dot file")
    ap.add_argument("stem", help="output path stem (no extension)")
    args = ap.parse_args()
    os.makedirs(os.path.dirname(os.path.abspath(args.stem)), exist_ok=True)

    dot_bin = shutil.which("dot")
    if dot_bin:
        outs = _via_dot(dot_bin, args.dot, args.stem)
    else:
        try:
            outs = _via_lib(args.dot, args.stem)
        except Exception as e:
            sys.exit(f"No Graphviz available (need `dot` binary or python `graphviz`): {e}")
    print("wrote:\n  " + "\n  ".join(outs))


if __name__ == "__main__":
    main()
