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
import base64
import html as H
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
import cti_report_sections as RS

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
        # The vendored renderer only fetches brand marks when ARCHIFY_BRAND_REMOTE=1
        # (local change, see vendor/archify/VENDOR.md); pin it off so an inherited
        # environment can never make a report build touch the network.
        env = dict(os.environ, ARCHIFY_BRAND_REMOTE="0")
        proc = subprocess.run(
            [node, ARCHIFY_BIN, "render", "architecture", ir_path, out_path],
            capture_output=True, text=True, timeout=CALL_TIMEOUT, env=env)
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


def _house_table(data, key, note=""):
    """One analyst report-block section as a card with an escaped table; '' when absent. The note
    defaults to the section's own intro sentence (cti_report_sections.section_note)."""
    rows = RS.display_rows(data, key)
    if not rows:
        return ""
    title, cols = RS.SECTION[key]
    note = note or RS.section_note(data, key)
    out = ['<div class="card" style="margin-top:16px"><h3>%s (%d)</h3>' % (H.escape(title), len(rows))]
    if note:
        out.append('<div class="empty" style="text-align:left">%s</div>' % H.escape(note))
    out.append('<div style="overflow-x:auto">' + _table_html(cols, rows) + "</div></div>")
    return "".join(out)


def _note_html(text):
    return '<div class="empty" style="text-align:left">%s</div>' % H.escape(text) if text else ""


def _figures_html(data, group, base, names=None):
    """Card maps / exposure charts in `report_figures` that pass RS.figures (contained PNG under the size
    cap; a rejected one is named on stderr), inlined as data URIs from the bytes RS.figures validated —
    the path is never reopened."""
    out = []
    for name, png, caption in RS.figures(data, group, base):
        if names and name not in names:
            continue
        uri = "data:image/png;base64," + base64.b64encode(png).decode("ascii")
        out.append('<figure class="card" style="margin-top:16px"><img src="%s" alt="%s" style="max-width:100%%">'
                   '<figcaption class="empty" style="text-align:left">%s</figcaption></figure>'
                   % (uri, H.escape(caption), H.escape(caption)))
    return "".join(out)


def _risk_html(data):
    """Overall risk: the score sentence + the domain table, highest score first."""
    ov = RS.risk_overall(data)
    if not ov:
        return ""
    line, warning, unrated = ov
    rows = RS.display_rows(data, "risk_assessment")
    title, cols = RS.SECTION["risk_assessment"]
    return ('<div class="card" style="margin-top:16px"><h3>%s</h3>%s%s<div style="overflow-x:auto">%s</div>%s</div>'
            % (H.escape(title), _note_html(line), _note_html(warning), _table_html(cols, rows), _note_html(unrated)))


def _rating_html(data):
    bands, prio = RS.rating_scales(data)
    if not (bands or prio):
        return ""
    tables = ""
    if bands:
        tables += _table_html([(0, "Risk level"), (1, "Score range")], [dict(enumerate(b)) for b in bands])
    if prio:
        tables += _table_html([(0, "Priority"), (1, "Act within")], [dict(enumerate(p)) for p in prio])
    return '<div class="card" style="margin-top:16px"><h3>%s</h3>%s</div>' % (
        H.escape(RS.SECTION["rating_scales"][0]), tables)


def _nothing_found_html(data):
    negatives, zero = RS.nothing_found(data)
    if not (negatives or zero):
        return ""
    title, cols = RS.SECTION["negative_checks"]
    return ('<div class="card" style="margin-top:16px"><h3>%s</h3>%s%s%s</div>'
            % (H.escape(title), _note_html(RS.NOTHING_FOUND_NOTE),
               '<div style="overflow-x:auto">%s</div>' % _table_html(cols, negatives) if negatives else "",
               '<ul class="ulist gap">%s</ul>' % "".join("<li><span>%s</span></li>" % H.escape(z) for z in zero)
               if zero else ""))


def _table_html(cols, rows):
    head = "".join("<th>%s</th>" % H.escape(h) for _, h in cols)
    body = "".join("<tr>%s</tr>" % "".join("<td>%s</td>" % H.escape(RS.cell(r, f)) for f, _ in cols)
                   for r in rows)
    return "<table><thead><tr>%s</tr></thead><tbody>%s</tbody></table>" % (head, body)


def _warn_card(title, warns, note=""):
    if not warns:
        return ""
    return ('<div class="card" style="margin-top:16px"><h3>%s (%d)</h3>%s<ul class="ulist gap">%s</ul></div>'
            % (H.escape(title), len(warns),
               '<div class="empty" style="text-align:left">%s</div>' % H.escape(note) if note else "",
               "".join('<li><span class="n">!</span><span>%s</span></li>' % H.escape(w) for w in warns)))


def build_identity_html(data):
    """Subject identity card — one table per entity (fixed field order, empty fields omitted)."""
    cards = RS.identity_cards(data)
    if not cards:
        return ""
    return ('<div class="card"><h3>Subject Identity Card</h3><div class="empty" style="text-align:left">%s</div>%s</div>'
            % (H.escape(RS.IDENTITY_NOTE),
               "".join('<h4 style="margin:12px 0 6px">%s</h4><div style="overflow-x:auto">%s</div>'
                       % (H.escape(ent), _table_html(RS.IDENTITY_COLS, rows)) for ent, rows in cards)))


def _actor_html(data):
    """The Actor Profile chapter (cti_report_sections.actor_blocks) as one card; '' when absent."""
    blocks = RS.actor_blocks(data)
    if not blocks:
        return ""
    out = ['<div class="card" style="margin-top:16px"><h3>%s</h3>' % H.escape(RS.ACTOR_TITLE)]
    for title, items in blocks:
        out.append('<h4 style="margin:12px 0 6px">%s</h4>' % H.escape(title))
        for item in items:
            if item[0] == "p":
                out.append(_note_html(item[1]))
            elif item[0] == "bullets":
                out.append('<ul class="ulist gap">%s</ul>' % "".join("<li><span>%s</span></li>" % H.escape(x)
                                                                     for x in item[1]))
            else:
                out.append('<div style="overflow-x:auto">%s</div>' % _table_html(item[1], item[2]))
    return "".join(out) + "</div>"


def build_house_html(data, base=None):
    """(key-questions html, analysis-view html) from the analyst report block, house-report order.
    Overview: Key questions, the subject card map, Overall risk, Key findings. Analysis: Client-provided
    details, Counting rules (+ metric warnings), Rating scales; findings — the threat card map, Affiliate
    exposure (+ charts; with no affiliate rows, the stealer-log triage charts under their own heading),
    Dark-web and Telegram claims, Services registered by e-mail, Events that raise
    the threat, the Actor Profile chapter; Roles, the supplier card map, Incident timeline, ATT&CK mapping, Scenarios,
    Recommendations P1/P2/P3, Usernames to reserve, Open questions, QA warnings, Sources checked,
    Checked — nothing found. Values escaped, never masked (sensitive client values and e-mail
    addresses arrive already withheld). `base` resolves relative `report_figures` paths."""
    kq = "".join([_house_table(data, "key_questions"), _figures_html(data, "card_maps", base, ("person",)),
                  _risk_html(data), _house_table(data, "key_findings")])
    parts = [_house_table(data, "client_seeds", RS.CLIENT_NOTE),
             _house_table(data, "counting_rules", RS.COUNTING_NOTE),
             _warn_card("Metric warnings", [w for w in data.get("metric_warnings") or [] if w]),
             _rating_html(data)]
    parts += [_figures_html(data, "card_maps", base, ("threats",)), _house_table(data, "affiliate_exposure")]
    if RS.rows(data, "affiliate_exposure"):
        parts.append(_figures_html(data, "exposure_charts", base))
    elif RS.triage_exposure(data):   # stealer-log triage charts, no affiliate rows: their own section
        charts = _figures_html(data, "exposure_charts", base)
        if charts:
            parts.append('<div class="card" style="margin-top:16px"><h3>%s</h3>%s%s</div>' % (
                H.escape(RS.EXPOSURE_TRIAGE_TITLE), _note_html(RS.EXPOSURE_TRIAGE_NOTE), charts))
    parts += [_house_table(data, "leak_claims"), _house_table(data, "email_services"),
              _house_table(data, "threat_events"), _actor_html(data)]
    parts += [_house_table(data, "roles", RS.ROLES_NOTE), _figures_html(data, "card_maps", base, ("suppliers",)),
              _house_table(data, "incident_timeline"),
              _house_table(data, "attack_mapping"), _house_table(data, "scenarios")]
    groups = RS.roadmap_groups(data)
    if groups:
        cols = RS.SECTION["roadmap"][1]
        parts.append('<div class="card" style="margin-top:16px"><h3>%s</h3>%s</div>' % (
            H.escape(RS.SECTION["roadmap"][0]),
            "".join('<h4 style="margin:12px 0 6px">%s (%d)</h4>%s' % (H.escape(h), len(rows), _table_html(cols, rows))
                    for h, rows in groups)))
    parts += [_house_table(data, "usernames_to_reserve"), _house_table(data, "open_questions"),
              _warn_card(RS.SECTION["qa_warnings"][0], [w for w in data.get("qa_warnings") or [] if w], RS.QA_NOTE),
              _house_table(data, "sources_checked", RS.SOURCES_CHECKED_NOTE), _nothing_found_html(data)]
    body = "".join(p for p in parts if p)
    if body:
        body = '<div class="section-h"><h2>Analysis</h2></div>' + body
    return kq, body


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

    norm = RS.prepare(normalize_obj(data), "generate-cti-html")
    house_kq, house_body = build_house_html(norm, os.path.dirname(os.path.abspath(case_path)))
    norm.pop("report_figures", None)   # local file paths: inlined above, never shipped in the HTML data
    house_id = build_identity_html(norm)
    if house_id:
        norm["house_identity_html"] = house_id
    if house_kq:
        norm["house_kq_html"] = house_kq
    if house_body:
        norm["house_sections_html"] = house_body
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
    print("  Analysis sections (report block): %s" % (
        "embedded" if (house_kq or house_body) else "none in this report JSON"))
    print("  open in any browser - fully offline, no external dependencies.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
