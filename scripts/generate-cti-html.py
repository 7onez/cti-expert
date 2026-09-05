#!/usr/bin/env python3
# /// script
# requires-python = ">=3.8"
# dependencies = []
# ///
"""
generate-cti-html.py — CTI Expert interactive HTML report generator.

Injects a case JSON file into cti-report-template.html, producing a single,
fully self-contained, OFFLINE HTML report (no CDN, no external assets, no network
calls). All charts, the 2D entity graph, the timeline and the comprehensive
indicator/selector extraction run client-side in vanilla JS inside the template.

Usage:
    uv run generate-cti-html.py <case.json> <out.html> [template.html]
    python3 generate-cti-html.py <case.json> <out.html> [template.html]

The case JSON uses the same flat "report JSON" shape consumed by the DOCX
generator (see scripts/sample-cti-report-data.json and SKILL.md §8).

Author: Hieu Ngo - chongluadao.vn
"""
import sys
import os
import json
import shutil
import subprocess
import tempfile

# --- self-heal: force UTF-8 stdio so emoji / non-ASCII never crash on Windows ---
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except Exception:
        pass

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cti_text_normalize import normalize_obj
from cti_timeouts import CALL_TIMEOUT  # per-call ceiling (CTI_CALL_TIMEOUT)

PLACEHOLDER = "__CTI_CASE_DATA__"


def embed(data):
    """JSON-encode and make it safe to drop inside a <script> element."""
    payload = json.dumps(data, ensure_ascii=False)
    # '<'  -> <  neutralises any </script> or <!-- inside string values.
    # U+2028 / U+2029 are JS line terminators and are escaped defensively.
    payload = payload.replace("<", "\\u003c")
    payload = payload.replace(chr(0x2028), "\\u2028")
    payload = payload.replace(chr(0x2029), "\\u2029")
    return payload


ARCHIFY_BIN = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "vendor", "archify", "bin", "archify.mjs")


def build_archify_html(data):
    """Render the case entity graph as an inline Archify architecture diagram.

    CTI_ARCHIFY selects the mode (see cti_archify.select_ir):
      1 (default)  full graph when it fits BLUEPRINT_LIMITS; otherwise the estate is
                   folded to apex level and rendered if that fits; otherwise skipped.
      force        bypass BLUEPRINT_LIMITS — the full graph up to FORCE_MAX_NODES, else
                   the apex fold at the widest grid Archify holds. Archify's own
                   validator still decides; a rejection is reported, never hidden.
      0            never embed.
    Returns (html, note) — html is None when skipped (no subjects, disabled, no
    Node.js/renderer, render failure). The report is always produced.
    """
    mode = os.environ.get("CTI_ARCHIFY", "1").strip().lower()
    if mode in ("0", "off", "no", "false"):
        return None, "disabled (CTI_ARCHIFY=0)"
    force = mode == "force"
    try:
        from cti_archify import select_ir
    except Exception as e:  # pragma: no cover - import guard
        return None, "converter unavailable: %s" % e
    ir, detail = select_ir(data, "force" if force else "auto")
    if ir is None:
        return None, detail
    node = shutil.which("node")
    if not node:
        return None, "Node.js not found (install Node to embed the Blueprint diagram)"
    if not os.path.isfile(ARCHIFY_BIN):
        return None, "vendored archify missing at %s" % ARCHIFY_BIN
    tmpdir = tempfile.mkdtemp(prefix="cti-archify-")
    ir_path = os.path.join(tmpdir, "ir.json")
    out_path = os.path.join(tmpdir, "diagram.html")
    try:
        with open(ir_path, "w", encoding="utf-8") as f:
            json.dump(ir, f, ensure_ascii=False)
        proc = subprocess.run(
            [node, ARCHIFY_BIN, "render", "architecture", ir_path, out_path],
            capture_output=True, text=True, timeout=CALL_TIMEOUT)
        if proc.returncode != 0 or not os.path.isfile(out_path):
            # Archify prints a stack trace, then "Error: <summary>" followed by the
            # diagnostic lines ("- [gate] ..." or an indented schema path).
            lines = [l for l in (proc.stderr or proc.stdout or "").strip().splitlines()
                     if l.strip() and "file://" not in l and ".mjs:" not in l]
            at = next((i for i, l in enumerate(lines) if l.startswith("Error:")), None)
            diag = " ".join(l.strip() for l in lines[at:at + 2]) if at is not None else (lines[0] if lines else "unknown error")
            return None, "render failed%s: %s" % (" (forced)" if force else "", diag)
        with open(out_path, encoding="utf-8") as f:
            return f.read(), detail
    except subprocess.TimeoutExpired:
        return None, "render timed out"
    except Exception as e:
        return None, "render error: %s" % e
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def build_editorial_svgs(data):
    """diagram-design editorial entity + topology SVG (stdlib, offline).

    Returns (entity_svg, topology_svg, note); either svg may be None. Never raises,
    but `note` reports the real reason (import failure vs render error vs no
    subjects) so a builder bug never masquerades as an empty case.
    """
    try:
        from cti_diagram_design import build_entity_svg, build_topology_svg
    except Exception as e:
        return None, None, "generator unavailable: %s" % e
    try:
        entity = build_entity_svg(data)
        topo = build_topology_svg(data)
    except Exception as e:
        return None, None, "render error: %s" % e
    if not entity and not topo:
        return None, None, "no subjects to draw"
    return entity, topo, "entity + topology" if (entity and topo) else ("entity only" if entity else "topology only")


def build_cloud_arch(data):
    """diagram-ai-generator cloud figure as a PNG data URI. (None, note) when skipped."""
    try:
        from cti_cloud_arch import build_cloud_png, png_data_uri
    except Exception as e:
        return None, "cloud module unavailable: %s" % e
    png, note = build_cloud_png(data)
    return (png_data_uri(png) if png else None), note


def main(argv):
    if len(argv) < 2:
        print("usage: generate-cti-html.py <case.json> <out.html> [template.html]")
        return 2
    case_path, out_path = argv[0], argv[1]
    here = os.path.dirname(os.path.abspath(__file__))
    tpl_path = argv[2] if len(argv) > 2 else os.path.join(here, "cti-report-template.html")

    try:
        with open(tpl_path, encoding="utf-8") as f:
            tpl = f.read()
    except OSError as e:
        print("error: cannot read template %r: %s" % (tpl_path, e))
        return 1
    try:
        with open(case_path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError) as e:
        print("error: cannot read/parse case JSON %r: %s" % (case_path, e))
        return 1

    count = tpl.count(PLACEHOLDER)
    if count != 1:
        print("error: placeholder %s must appear exactly once in template (found %d)"
              % (PLACEHOLDER, count))
        return 1

    norm = normalize_obj(data)
    ed_entity, ed_topo, ed_note = build_editorial_svgs(data)
    if ed_entity:
        norm["editorial_entity_svg"] = ed_entity
    if ed_topo:
        norm["editorial_topology_svg"] = ed_topo
    cloud_uri, cloud_note = build_cloud_arch(data)
    if cloud_uri:
        norm["cloud_arch_png"] = cloud_uri
    archify_html, archify_note = build_archify_html(data)
    if archify_html:
        norm["archify_diagram_html"] = archify_html
    html = tpl.replace(PLACEHOLDER, embed(norm))

    out_dir = os.path.dirname(os.path.abspath(out_path))
    if out_dir and not os.path.isdir(out_dir):
        os.makedirs(out_dir, exist_ok=True)
    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(html)

    case = data.get("case", {}) if isinstance(data, dict) else {}
    print("HTML report written: %s (%d KB)" % (out_path, len(html.encode("utf-8")) // 1024))
    print("  case: %s  |  subjects: %d  findings: %d  connections: %d" % (
        case.get("label") or case.get("id") or "?",
        len(data.get("subjects", []) or []),
        len(data.get("findings", []) or []),
        len(data.get("connections", []) or []),
    ))
    print("  Blueprint (Archify): %s" % ("embedded — %s" % archify_note if archify_html else "not embedded — %s" % archify_note))
    print("  Editorial (Diagram Design): %s" % ("embedded — %s" % ed_note if (ed_entity or ed_topo) else "not embedded — %s" % ed_note))
    print("  Cloud arch (Diagram AI Generator): %s" % ("embedded — %s" % cloud_note if cloud_uri else "not embedded — %s" % cloud_note))
    print("  open in any browser - fully offline, no external dependencies.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
