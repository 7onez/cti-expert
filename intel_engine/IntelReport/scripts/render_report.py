#!/usr/bin/env python3
"""
render_report.py — turn an assessment MARKDOWN file into a polished PDF and/or
DOCX using pandoc. PDF uses the IntelReport house LaTeX theme (xelatex, muted
editorial palette matching IntelGraph); DOCX uses pandoc with a title block so
a reviewer can redline it.

No new Python deps — shells out to `pandoc` (+ `xelatex` for PDF), both of which
the repo already relies on. Embedded IntelGraph figures (`![](fig_hires.png)`)
render into the PDF automatically.

LANGUAGE — `--lang en|vi` (or frontmatter `lang:`). It localises the GENERATED
FURNITURE only: cover labels, TOC title, "Appendix", figure/table captions, the
audience stamp. It does NOT touch the body, and that is deliberate. An assessment
is a calibrated text — "we assess with high confidence", "likely" — where each
term carries an ICD-203 probability band, so a machine paraphrase silently changes
what the report claims. Write the body in the target language from the start and
take the wording verbatim from `--glossary`. Strings live in
`references/report_i18n.json` (RULE 3); a `--lang vi` render also warns when no
installed font DECLARES Vietnamese coverage, because tofu boxes in a deliverable
are not a cosmetic defect.

Metadata: title / case id / classification / subtitle / date come from CLI args,
else a YAML frontmatter block in the markdown, else sensible defaults. Per repo
OPSEC + report convention, NO analyst name is ever stamped and the date defaults
to UTC today.

Usage:
  render_report.py assessment.md out/report --pdf --docx \
      --title "Operator A — infrastructure assessment" \
      --case-id CASE-0001 --classification "TLP:AMBER" \
      --subtitle "Passive OSINT · attribution of N domains to one operator"

  render_report.py assessment.md out/report          # both PDF+DOCX, metadata from frontmatter
  render_report.py assessment.md out/report --pdf     # PDF only
"""
import argparse
import datetime
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
TEMPLATES = os.path.join(os.path.dirname(HERE), "templates")
HOUSE_HEADER = os.path.join(TEMPLATES, "house-header.tex")
REFERENCE_DOCX = os.path.join(TEMPLATES, "reference.docx")

if HERE not in sys.path:                       # importable however the script was invoked
    sys.path.insert(0, HERE)
from ir_refs import ref_path, load_ref  # noqa: E402 — reference DATA lives in references/*.json

# Per-call ceiling for pandoc/xelatex (CTI_CALL_TIMEOUT: env → .env → references/timeouts.json →
# 1800s). The engine's resolver is a stdlib sibling; standalone falls back to the exported env value.
try:
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(HERE)), "WebPivot", "tools"))
    from wp_timeouts import CALL_TIMEOUT  # noqa: E402
except Exception:  # noqa: BLE001
    try:
        CALL_TIMEOUT = int(os.environ.get("CTI_CALL_TIMEOUT") or 1800)
    except ValueError:
        CALL_TIMEOUT = 1800
    CALL_TIMEOUT = CALL_TIMEOUT if CALL_TIMEOUT > 0 else 1800

# --- reference DATA (RULE 3): the report's LANGUAGE. Everything the renderer prints that the
#     analyst did not write — cover labels, TOC title, "Appendix", figure/table captions — is
#     finite, generated furniture and belongs in a data file, not in Python string literals.
#     The fallback below is English-only plus the two Vietnamese labels a reader would notice
#     immediately; load_ref warns loudly when the real file is missing.
_I18N_FALLBACK = {
    "strings": {
        "en": {"reference": "Reference", "date": "Date", "basis": "Basis",
               "basis_default": "Passive OSINT", "handling": "Handling", "contents": "Contents",
               "appendix": "Appendix", "figure": "Figure", "table": "Table",
               "audience_technical": "Technical briefing",
               "audience_executive": "Executive briefing",
               "audience_le": "Law-enforcement briefing"},
        "vi": {"contents": "Mục lục", "appendix": "Phụ lục"},
    },
    # Deliberately thin: these are the analyst's WORDS, and a half-remembered fallback glossary
    # is worse than none — a paraphrased estimative term silently changes what the report claims.
    "estimative_terms": {
        "high_confidence": {"en": "we assess with high confidence",
                            "vi": "chúng tôi đánh giá với độ tin cậy cao"},
        "likely": {"en": "likely / probably", "vi": "có khả năng", "band": "55-80%"},
    },
    "section_names": {
        "key_judgments": {"en": "Key Judgments", "vi": "Nhận định chính"},
        "findings": {"en": "Findings", "vi": "Kết quả phân tích"},
    },
}
_REFS = load_ref(ref_path(__file__, "report_i18n.json"), _I18N_FALLBACK)
STRINGS = _REFS["strings"]
ESTIMATIVE_TERMS = _REFS["estimative_terms"]
SECTION_NAMES = _REFS["section_names"]
DEFAULT_LANG = "en"


def S(lang, key):
    """One piece of generated furniture in `lang`, falling back to English.

    English fallback rather than an empty string on purpose: a cover row with a blank label is a
    defect every reader notices, while an English "Date" on a Vietnamese cover is an obvious,
    fixable gap in the data file."""
    langs = STRINGS if isinstance(STRINGS, dict) else {}
    val = (langs.get(lang) or {}).get(key)
    if val:
        return val
    return (langs.get(DEFAULT_LANG) or {}).get(key) or key

TEX_ESCAPE = {"&": r"\&", "%": r"\%", "$": r"\$", "#": r"\#", "_": r"\_",
              "{": r"\{", "}": r"\}", "~": r"\textasciitilde{}",
              "^": r"\textasciicircum{}", "\\": r"\textbackslash{}"}


def tex_escape(s):
    return "".join(TEX_ESCAPE.get(c, c) for c in str(s))


def read_markdown(md_path):
    """Read the markdown ONCE and return (meta, body_title, body_lines):
      - meta: parsed key:value pairs from a leading YAML frontmatter block
      - body_title: first ATX H1, used as a title fallback
      - body_lines: the content with the frontmatter block stripped (so pandoc
        doesn't emit its own \\maketitle title page over our custom cover)."""
    meta, body_title, body_start = {}, None, 0
    with open(md_path, encoding="utf-8") as fh:
        lines = fh.readlines()
    if lines and lines[0].strip() == "---":
        for i in range(1, len(lines)):
            if lines[i].strip() in ("---", "..."):
                body_start = i + 1
                break
            if ":" in lines[i]:
                k, v = lines[i].split(":", 1)
                meta[k.strip().lower()] = v.strip().strip('"').strip("'")
    body_lines = lines[body_start:]
    for ln in body_lines:  # first ATX H1 as a title fallback
        if ln.startswith("# "):
            body_title = ln[2:].strip()
            break
    return meta, body_title, body_lines


# Report headings are auto-numbered by pandoc (--number-sections), so a manual section
# number baked into the heading TEXT ("## 4.1 Overview") renders doubled ("5.1 4.1 Overview").
# Strip a leading manual number — dotted (4.1 / 4.1.2, optional trailing . or )) or a single
# integer with a trailing separator (4. / 4)) — but NOT a bare integer ("## 2024 in review"
# stays). Requires real title text after the number (lookahead), so a number-only heading is
# left alone.
_HEADING_NUM = re.compile(r"^(#{1,6}[ \t]+)(?:\d+(?:\.\d+)+[.)]?|\d+[.)])[ \t]+(?=\S)")


def _strip_manual_heading_numbers(lines):
    """Drop manual section numbers from ATX headings so pandoc's --number-sections is the
    single source of numbering. Fenced code blocks (``` / ~~~) are left verbatim, so shell
    comments like '# 4. do X' inside a code block survive untouched."""
    out, in_fence = [], False
    for ln in lines:
        s = ln.lstrip()
        if s.startswith("```") or s.startswith("~~~"):
            in_fence = not in_fence
            out.append(ln)
        elif not in_fence and ln.startswith("#"):
            out.append(_HEADING_NUM.sub(r"\1", ln, count=1))
        else:
            out.append(ln)
    return out


def write_body(body_lines, tmpdir):
    """Write the frontmatter-stripped body to a temp .md (images still resolve
    via --resource-path pointed at the original file's directory)."""
    out = os.path.join(tmpdir, "body.md")
    with open(out, "w", encoding="utf-8") as fh:
        fh.writelines(_strip_manual_heading_numbers(body_lines))
    return out


def utc_today():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")


# ── report-reference registry ────────────────────────────────────────────────
# A PRIVATE, git-ignored map from the EXTERNAL report reference (shown on the
# report) to the INTERNAL case-store id (never shown). It lives inside the case
# store (cases/report_registry.jsonl), so a shared report can't be tied back to
# the store, but WE can always look up which case a reference belongs to — and
# reuse the same reference next time we render that case.

def locate_store(md_path):
    """From a report path under .../cases/<id>/..., return (internal_case_id,
    registry_path). Falls back to CWD/cases if the path isn't under a store."""
    parts = os.path.abspath(md_path).replace("\\", "/").split("/")
    if "cases" in parts:
        i = parts.index("cases")
        cases_root = "/".join(parts[: i + 1])
        internal = parts[i + 1] if len(parts) > i + 1 else None
        return internal, os.path.join(cases_root, "report_registry.jsonl")
    return None, os.path.join(os.getcwd(), "cases", "report_registry.jsonl")


def load_registry(path):
    rows = []
    if os.path.isfile(path):
        for line in open(path, encoding="utf-8"):
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except ValueError:
                    pass
    return rows


def ref_for_case(rows, case_id):
    """Most-recent external reference already assigned to this case (reuse it)."""
    for r in reversed(rows):
        if r.get("case_id") == case_id and r.get("report_ref"):
            return r["report_ref"]
    return None


def gen_ref(rows, today):
    """Mint RPT-YYYY-MMDD-NN, NN = next free sequence for that date."""
    y, mo, d = today.split("-")
    prefix = f"RPT-{y}-{mo}{d}"
    n = sum(1 for r in rows if str(r.get("report_ref", "")).startswith(prefix)) + 1
    return f"{prefix}-{n:02d}"


def record_mapping(path, entry):
    """Append {report_ref, case_id, …} unless that exact pair is already logged."""
    key = (entry["report_ref"], entry.get("case_id"))
    if any((r.get("report_ref"), r.get("case_id")) == key for r in load_registry(path)):
        return False
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return True


# ── chain to IntelGraph: regenerate figures before rendering ─────────────────
# So the report's chart is never stale. A report declares its figures in a
# sibling figures.json; render_report rebuilds each (WebPivot graph_build → the
# IntelGraph diagram) right before the render.

def _sibling_script(*rel):
    """Resolve a sibling-skill script (IntelGraph / WebPivot) from render_report's
    location — works both in the repo (IntelReport/ sibling of IntelGraph/) and via
    the ~/.claude/skills symlinks."""
    for c in (os.path.normpath(os.path.join(HERE, "..", "..", *rel)),
              os.path.expanduser(os.path.join("~/.claude/skills", *rel))):
        if os.path.isfile(c):
            return c
    return None


GRAPH_TO_DIAGRAM = _sibling_script("IntelGraph", "scripts", "graph_to_diagram.py")
GRAPH_BUILD = _sibling_script("WebPivot", "tools", "graph_build.py")
RENDER_MERMAID = _sibling_script("IntelGraph", "scripts", "render_mermaid.py")


def regenerate_figures(md_dir):
    """Rebuild every figure declared in <md_dir>/figures.json BEFORE rendering.

    Two figure kinds, both rendered through IntelGraph:

    1) COLLECTED — a case graph derived from the raw collection JSON:
       {"raw": [paths], "graph": "case_graph.json", "stem": "case_diagram",
        "title": "...", "direction": "LR", "legend": true,
        "drop_types": ["nameserver", ...]}
    2) REASONING — a hand-authored Mermaid source, for the argument a case graph
       cannot express (entity structure, ownership timeline, the inference chain
       from artifact to attribution, links tested and rejected):
       {"mmd": "fig_attribution.mmd", "stem": "fig_attribution",
        "theme": "neutral", "width": 2400}

    Paths are relative to the md dir. Best-effort: a figure that fails to build
    leaves the previous PNG in place."""
    recipe = os.path.join(md_dir, "figures.json")
    if not os.path.isfile(recipe):
        return
    try:
        spec = json.load(open(recipe, encoding="utf-8"))
    except ValueError as e:
        sys.stderr.write("figures.json parse error: %s\n" % e)
        return
    if not GRAPH_TO_DIAGRAM:
        sys.stderr.write("IntelGraph graph_to_diagram.py not found — figures not refreshed\n")
        return
    for fig in spec.get("figures", []):
        stem = os.path.join(md_dir, fig["stem"])
        if fig.get("mmd"):                            # REASONING figure — hand-authored Mermaid
            if not RENDER_MERMAID:
                sys.stderr.write("IntelGraph render_mermaid.py not found — %s skipped\n"
                                 % fig["stem"])
                continue
            cmd = [sys.executable, RENDER_MERMAID,
                   os.path.join(md_dir, fig["mmd"]), stem,
                   "--theme", str(fig.get("theme", "neutral"))]
            if fig.get("width"):
                cmd += ["--width", str(fig["width"])]
            print("figure %s: %s" % ("refreshed" if run(cmd) else "FAILED",
                                     os.path.basename(stem)))
            continue
        graph = os.path.join(md_dir, fig["graph"])    # COLLECTED figure — case graph
        raw = [os.path.normpath(os.path.join(md_dir, r)) for r in (fig.get("raw") or [])]
        if fig.get("raw_glob"):    # auto-include every current raw file (new domains picked up)
            raw += sorted(glob.glob(os.path.join(md_dir, fig["raw_glob"])))
        if raw and GRAPH_BUILD:                       # 1) rebuild the case graph from raw
            run([sys.executable, GRAPH_BUILD, *raw, "-o", graph])
        cmd = [sys.executable, GRAPH_TO_DIAGRAM, graph, stem]   # 2) render the diagram
        if fig.get("title"):
            cmd += ["--title", fig["title"]]
        if fig.get("direction"):
            cmd += ["--direction", fig["direction"]]
        if fig.get("legend"):
            cmd += ["--legend"]
        if fig.get("inline_legend"):    # keep the legend inside the diagram (single figure)
            cmd += ["--inline-legend"]
        if fig.get("split_clusters"):   # one figure per cluster, for an estate too dense to read
            cmd += ["--split-clusters"]
        if fig.get("all_edge_labels"):
            cmd += ["--all-edge-labels"]
        if fig.get("scale"):
            cmd += ["--scale", str(fig["scale"])]
        if fig.get("width"):
            cmd += ["--width", str(fig["width"])]
        if fig.get("pdf", True):        # vector companion — see swap_vector_figures
            cmd += ["--pdf"]
        if fig.get("drop_types"):
            dt = fig["drop_types"]
            cmd += ["--drop-types", dt if isinstance(dt, str) else ",".join(dt)]
        print("figure %s: %s" % ("refreshed" if run(cmd) else "FAILED", os.path.basename(stem)))


# A raster figure is embedded at whatever pixel density it happens to have; a VECTOR one is
# exact at every zoom level and adds no weight. mermaid renders both from the same source, so
# when a figure has a `.pdf` beside its `_hires.png` the PDF build should use it — the DOCX
# build cannot (Word will not place a PDF inline), which is why this rewrite happens on a
# SEPARATE body for the PDF and never touches the shared one.
_IMG_RE = re.compile(r"(!\[[^\]]*\]\()([^)\s]+?)_hires\.png(\s*[^)]*\))")


def swap_vector_figures(body_lines, resource_dir):
    """Point every `![](fig_hires.png)` at `fig.pdf` when that vector file exists."""
    swapped, out = 0, []

    def _sub(mo):
        nonlocal swapped
        stem = mo.group(2)
        if os.path.isfile(os.path.join(resource_dir, stem + ".pdf")):
            swapped += 1
            return f"{mo.group(1)}{stem}.pdf{mo.group(3)}"
        return mo.group(0)

    for ln in body_lines:
        out.append(_IMG_RE.sub(_sub, ln) if "![" in ln else ln)
    if swapped:
        print(f"figures: {swapped} embedded as VECTOR (.pdf) in the PDF build")
    return out


# Typography is DATA, not code (repo RULE 3): an analyst retunes the font
# preference or the highlight colour by editing references/typography.json, with
# no code change and no redeploy. The lists below are only the minimal embedded
# fallback for a missing/broken file — ir_refs.load_ref warns loudly on stderr
# when it has to use them, because a silent fallback ships a report that looks
# subtly wrong rather than one that fails.
# Deliberately MINIMAL (RULE 3): just enough to render something legible on one
# machine, never a copy of the JSON. A fallback that mirrors the data file cannot be
# told apart from it, so nobody would notice the file had stopped loading.
_TYPO_FALLBACK = {
    "serif_families": ["Noto Serif", "Georgia", "Times New Roman"],
    "sans_families": ["Noto Sans", "Helvetica Neue", "Arial"],
    "mono_families": ["Source Code Pro", "Menlo", "DejaVu Sans Mono"],
    "mono_metrics": {"scale": "MatchLowercase"},
    "highlight": {"color_hex": "F5E27A", "max_chars": 90},
}
_TYPO = load_ref(ref_path(__file__, "typography.json"), _TYPO_FALLBACK)

# `mark` turns ==text== into \hl{text} (see the highlight note in house-header.tex).
# Kept in ONE constant so the PDF and DOCX readers can never drift apart — a
# highlight that renders in the PDF but shows as literal "==" in the DOCX is the
# kind of defect nobody notices until a reviewer opens the Word copy.
PANDOC_FROM = "markdown+yaml_metadata_block+pipe_tables+grid_tables+mark"

SERIF_PREF = _TYPO["serif_families"]
SANS_PREF = _TYPO["sans_families"]
MONO_PREF = _TYPO["mono_families"]
MONO_SCALE = (_TYPO.get("mono_metrics") or {}).get("scale") or "MatchLowercase"
HL_COLOR = (_TYPO.get("highlight") or {}).get("color_hex") or "F5E27A"
HL_MAX_CHARS = int((_TYPO.get("highlight") or {}).get("max_chars") or 90)


def installed_families(lang=None):
    args = ["fc-list"]
    if lang:
        args.append(":lang=%s" % lang)
    args += ["-f", "%{family}\n"]
    try:
        r = subprocess.run(args, capture_output=True, text=True)
    except FileNotFoundError:
        return set()
    fams = set()
    for line in r.stdout.splitlines():
        for f in line.split(","):
            fams.add(f.strip())
    return fams


def pick_fonts(lang=DEFAULT_LANG):
    """(serif, sans, mono). Prefer a family that actually DECLARES Vietnamese coverage
    (:lang=vi) — many nice serifs (PT Serif, Charter, DejaVu on macOS) miss the
    stacked-diacritic glyphs (ộ, ừ, ả) and render tofu. Fall back to any installed
    preferred family, then Latin Modern (TeX-bundled — note: Latin Modern does NOT
    cover Vietnamese, so on a box with no fontconfig/fc-list a VN report can still
    tofu; install a Noto/Georgia/Times family there).

    With --lang vi this is no longer best-effort: tofu boxes are not a cosmetic
    defect in a deliverable, and a silent fallback ships a report nobody can read.
    So a VN render with no Vietnamese-declaring family WARNS by name."""
    vi = installed_families(lang="vi")
    allf = installed_families()

    def first(prefs, default):
        return (next((f for f in prefs if f in vi), None)
                or next((f for f in prefs if f in allf), default))

    # Defaults matter when detection finds nothing — notably Windows, which has no `fc-list`
    # (fontconfig), so `allf` is empty and `first()` always returns the default. Latin Modern does
    # NOT cover Vietnamese, so defaulting to it there ships a silent tofu PDF. xelatex on Windows
    # resolves system fonts by name via its own backend (no fontconfig needed), and Times New Roman
    # / Arial ship on every Windows box and cover Vietnamese — so pin those as the Windows defaults.
    _win = sys.platform.startswith("win")
    serif = first(SERIF_PREF, "Times New Roman" if _win else "Latin Modern Roman")
    sans = first(SANS_PREF, "Arial" if _win else "Latin Modern Sans")
    # Mono is chosen from what is INSTALLED only, never filtered by :lang=vi. Inline
    # code in these reports is domains, hashes, IPs and endpoints — ASCII — and
    # filtering on Vietnamese coverage would discard the good hash faces (Source Code
    # Pro, Menlo) in favour of a worse one for no benefit. Body/heading text, which
    # does carry diacritics, is filtered above.
    mono = next((f for f in MONO_PREF if f in allf), "Consolas" if _win else "Latin Modern Mono")
    if lang == "vi" and not (serif in vi and sans in vi):
        sys.stderr.write(
            "WARNING: --lang vi but no installed family DECLARES Vietnamese coverage "
            "(picked %r / %r). Stacked diacritics (ộ, ừ, ả) may render as tofu boxes. "
            "Install one: `brew install --cask font-noto-serif font-noto-sans` (macOS) or "
            "`apt install fonts-noto`. Check the rendered PDF before sending it.\n"
            % (serif, sans))
    return serif, sans, mono


def build_defs_and_cover(m, tmpdir, resource_dir="."):
    """Write defs.tex (header/footer macros) and cover.tex (title page).

    The document ALWAYS displays m['ref'] (the external report reference), never
    the internal case-store id — see OPSEC note in main()."""
    cls = tex_escape(m["classification"])
    caseid = tex_escape(m["ref"]) if m.get("ref") else ""
    lang = m.get("lang") or DEFAULT_LANG
    serif, sans, mono = pick_fonts(lang)
    defs = os.path.join(tmpdir, "defs.tex")
    with open(defs, "w", encoding="utf-8") as fh:
        # defs.tex is included before house-header.tex, so load fontspec here
        # (reload in the header is a harmless no-op) so \setmainfont is valid.
        fh.write("\\usepackage{fontspec}\n")
        # let raw-LaTeX \includegraphics{fig.png} resolve against the md's dir,
        # so a centered figure block finds the image (pandoc only rewrites paths
        # for markdown images, not raw LaTeX). graphicx must load before
        # \graphicspath — defs.tex is included ahead of house-header.tex.
        fh.write("\\usepackage{graphicx}\n")
        fh.write("\\graphicspath{{%s/}}\n" % os.path.abspath(resource_dir).replace("\\", "/"))
        fh.write("\\newcommand{\\CLSLINE}{%s}\n" % cls)
        fh.write("\\newcommand{\\CASEID}{%s}\n" % caseid)
        fh.write("\\setmainfont{%s}[Scale=1.0]\n" % serif)
        fh.write("\\setsansfont{%s}[Scale=1.0]\n" % sans)
        fh.write("\\newfontfamily\\headingfont{%s}\n" % sans)
        # Monospace carries the evidence — hashes, fingerprints, domains — so it is
        # chosen explicitly rather than left to xelatex's Latin Modern Mono default,
        # which is thin and wide and sets a 64-char hash badly in a table cell.
        # A numeric scale is emitted bare; the fontspec keyword is emitted as-is.
        _scale = MONO_SCALE
        _scale = str(_scale) if not isinstance(_scale, str) else _scale
        fh.write("\\setmonofont{%s}[Scale=%s]\n" % (mono, _scale))
        # The ==highlight== colour. See references/typography.json for why this is a
        # colour box and not the soul package (soul drops Vietnamese diacritics).
        fh.write("\\definecolor{hlmark}{HTML}{%s}\n" % HL_COLOR)
        # Generated furniture, in the report's language. \APPENDIXNAME is consumed by
        # house-header.tex's \appendix hook; \figurename / \tablename by every caption.
        # Set here (not in the header) because the header is a static template shared by
        # every render — the language is a per-report fact.
        fh.write("\\newcommand{\\APPENDIXNAME}{%s}\n" % tex_escape(S(lang, "appendix")))
        fh.write("\\renewcommand{\\figurename}{%s}\n" % tex_escape(S(lang, "figure")))
        fh.write("\\renewcommand{\\tablename}{%s}\n" % tex_escape(S(lang, "table")))

    title = tex_escape(m["title"])
    subtitle = tex_escape(m["subtitle"]) if m["subtitle"] else ""
    date = tex_escape(m["date"])
    caserow = ((r"\textbf{%s} & %s \\" % (tex_escape(S(lang, "reference")), caseid))
               if caseid else "")
    basis = tex_escape(m.get("basis") or S(lang, "basis_default"))
    cover = os.path.join(tmpdir, "cover.tex")
    with open(cover, "w", encoding="utf-8") as fh:
        fh.write(r"""\begin{titlepage}
\thispagestyle{empty}
\raggedright
\vspace*{1.5cm}
{\headingfont\small\bfseries\color{brick}\MakeUppercase{%s}}\par
\vspace{0.35cm}{\color{grid}\hrule height 1.2pt}\par
\vspace{1.6cm}
{\headingfont\fontsize{30}{34}\selectfont\bfseries\color{slate} %s\par}
\vspace{0.6cm}
{\headingfont\large\color{muted} %s\par}
\vfill
{\headingfont\color{ink}\begin{tabular}{@{}l l@{}}
%s
\textbf{%s} & %s \\
\textbf{%s} & %s \\
\end{tabular}\par}
\vspace{0.6cm}{\color{grid}\hrule height 0.6pt}\par
\vspace{0.25cm}{\footnotesize\headingfont\color{muted} %s: %s}\par
\end{titlepage}
\clearpage
""" % (cls, title, subtitle, caserow,
            tex_escape(S(lang, "date")), date,
            tex_escape(S(lang, "basis")), basis,
            tex_escape(S(lang, "handling")), cls))
    return defs, cover


def run(cmd):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=CALL_TIMEOUT)
    except subprocess.TimeoutExpired:
        sys.stderr.write("\n$ " + " ".join(cmd) + f"\n  timed out after {CALL_TIMEOUT}s\n")
        return False
    if r.returncode != 0:
        sys.stderr.write("\n$ " + " ".join(cmd) + "\n")
        sys.stderr.write((r.stdout or "") + (r.stderr or "") + "\n")
    return r.returncode == 0


def warn_long_highlights(body, limit=6):
    """Warn about ==highlighted== spans too long to fit on one line.

    The highlight is a colour BOX (see house-header.tex: the soul package drops
    Vietnamese diacritics, so correctness was chosen over line-wrapping). A box
    cannot break, so an over-long span runs silently into the margin — xelatex
    reports it only as an ordinary overfull \\hbox among many, and the PDF still
    builds. This turns that into a named, actionable warning.

    Also flags the authoring smell directly: a highlight that long is a sentence,
    and a highlighted sentence highlights nothing. Use bold for emphasis at that
    length."""
    import re
    spans, seen = [], set()
    # Skip fenced code so a literal "==" in a config sample is not mistaken for a span.
    text = re.sub(r"```.*?```", "", body, flags=re.S)
    for m in re.finditer(r"==(.+?)==", text, flags=re.S):
        s = " ".join(m.group(1).split())
        if len(s) > HL_MAX_CHARS and s not in seen:
            seen.add(s)
            spans.append(s)
    if not spans:
        return
    sys.stderr.write(
        "[IntelReport] WARNING: %d ==highlight== span(s) exceed %d characters. A highlight is a "
        "non-breaking box, so these will run past the right margin. Shorten them to the phrase "
        "that matters, or use **bold** instead:\n" % (len(spans), HL_MAX_CHARS))
    for s in spans[:limit]:
        sys.stderr.write("              (%d chars) %s...\n" % (len(s), s[:70]))
    if len(spans) > limit:
        sys.stderr.write("              ... and %d more\n" % (len(spans) - limit))


def warn_missing_glyphs(body, family, limit=12):
    """Warn about characters the PDF body font cannot render, BEFORE shipping the file.

    A glyph the family lacks becomes a tofu box in the PDF. xelatex does not fail and pandoc does
    not warn, so the defect is invisible unless somebody opens the PDF and looks at the right page
    — which is exactly how a report goes out with an unreadable Status column or a broken
    "A -> B" pipeline description. Observed in practice: U+27F2 (⟲) and U+2192 (→) are both absent
    from Georgia, the family this skill prefers for English reports.

    Best-effort: needs fontconfig. No fc-list (or no family) -> silent, since a machine without
    fontconfig already gets the pick_fonts fallback warning."""
    if not shutil.which("fc-list") or not family:
        return []
    missing = []
    for ch in sorted({c for c in body if ord(c) > 0x2000 or 0xA0 <= ord(c) < 0x100}):
        try:
            out = subprocess.run(["fc-list", ":charset=%04X" % ord(ch), "family"],
                                 capture_output=True, text=True, timeout=10).stdout
        except Exception:                       # noqa: BLE001 — advisory only, never blocks
            return []
        fams = {f.strip() for line in out.splitlines() for f in line.split(",")}
        if family not in fams:
            missing.append(ch)
    if missing:
        shown = " ".join("U+%04X (%s)" % (ord(c), c) for c in missing[:limit])
        print("[IntelReport] WARNING: %d character(s) are not in '%s' and will render as tofu "
              "boxes in the PDF: %s%s\n"
              "              Replace them with ASCII equivalents (-> for an arrow, † for a "
              "re-check mark) or pick a family that covers them."
              % (len(missing), family, shown, " …" if len(missing) > limit else ""),
              file=sys.stderr)
    return missing


def warn_orphan_figures(body_lines, resource_dir, limit=6):
    """A rendered figure sitting in the case folder that the report never embeds.

    This exists for one specific case: on a multi-cluster graph IntelGraph now emits the legend
    as a COMPANION figure (`<stem>_legend_hires.png`) instead of a box inside the diagram. If the
    author does not embed it, the report ships a graph whose colours and shapes are never
    explained — and nothing else would have said so. Advisory only; it never blocks a render."""
    text = "".join(body_lines)
    orphans = []
    for path in sorted(glob.glob(os.path.join(resource_dir, "*_hires.png"))):
        base = os.path.basename(path)
        stem = base[: -len("_hires.png")]
        if base not in text and (stem + ".pdf") not in text and (stem + ".svg") not in text:
            orphans.append(base)
    if not orphans:
        return
    sys.stderr.write(
        "NOTE: %d rendered figure(s) are not embedded anywhere in the report: %s\n"
        % (len(orphans), ", ".join(orphans[:limit])))
    if any(o.endswith("_legend_hires.png") for o in orphans):
        sys.stderr.write(
            "      One of them is a LEGEND. Its graph no longer explains its own colours and "
            "shapes — embed it beside the graph, or re-render that figure with "
            "\"inline_legend\": true in figures.json.\n")


def warn_numeric_integrity(body, limit=12):
    """Warn about a letter typed for a digit in a numeric context, BEFORE shipping the file.

    The classic 'OCR-style' intelligence-report defect: a year written 2o26, a timestamp
    o8:52:58, an id 149o89 — a lowercase o for a 0, an l or I for a 1. A font cannot cause
    this SELECTIVELY (a bad 0 glyph would corrupt every zero in the file, including the page
    numbers), so it is not a rendering bug: it is an authoring typo the writer makes while
    transcribing values read off a rendered page. xelatex sets 'o8:52' happily, so it ships
    unless caught. In an intelligence product mechanical precision signals analytical
    precision, so this names the smell before the PDF exists.

    High precision by design — a match must be an otherwise all-digit token carrying a
    confusable letter, and domains / urls / emails / paths / code are skipped, so a real
    'web2o.io' or an inline hash never trips it."""
    import re
    text = re.sub(r"```.*?```", " ", body, flags=re.S)   # fenced code blocks
    text = re.sub(r"`[^`]*`", " ", text)                 # inline code spans
    hits, seen = [], set()
    conf = "oOlI"                                          # o->0, l/I->1 (the observed classes)

    def _fix(tok):
        return tok.replace("o", "0").replace("O", "0").replace("l", "1").replace("I", "1")

    # (1) A bare number smell: >=2 digits + >=1 confusable, not inside a longer word / domain
    #     / path / email. ':' and '-' are NOT boundaries so dates/times still register.
    for mo in re.finditer(r"(?<![\w./@])([0-9]*[oOlI][0-9oOlI]*)(?![\w./@])", text):
        tok = mo.group(1)
        if sum(c.isdigit() for c in tok) >= 2 and any(c in conf for c in tok) and tok not in seen:
            seen.add(tok)
            hits.append(tok)
    # (2) A clock smell: HH:MM[:SS] where any position carries a confusable (catches o8:52:58,
    #     which (1) misses because 'o8' has only one digit).
    for mo in re.finditer(r"(?<![\w.])([0-9oOlI]{1,2}(?::[0-9oOlI]{2}){1,2})(?![\w.])", text):
        tok = mo.group(1)
        if any(c in conf for c in tok) and tok not in seen:
            seen.add(tok)
            hits.append(tok)
    if not hits:
        return []
    sys.stderr.write(
        "[IntelReport] WARNING: %d token(s) look like a letter typed for a digit — the 'OCR-style' "
        "report defect (o for 0, l/I for 1). A font cannot cause this selectively, so these are "
        "authoring typos that ship as-is unless fixed in the source markdown:\n" % len(hits))
    for t in hits[:limit]:
        sys.stderr.write("              %-16s -> probably %s\n" % (t, _fix(t)))
    if len(hits) > limit:
        sys.stderr.write("              ... and %d more\n" % (len(hits) - limit))
    return hits


def render_pdf(body, stem, m, resource_dir):
    """body = the frontmatter-stripped temp .md; resource_dir = original md's dir
    (so ![](fig.png) still resolves)."""
    tmp = tempfile.mkdtemp(prefix="intelreport_")
    try:
        defs, cover = build_defs_and_cover(m, tmp, resource_dir)
        # Font-coverage pre-flight: a missing glyph silently becomes a tofu box.
        try:
            with open(body, encoding="utf-8") as _b:
                _body_text = _b.read()
            warn_missing_glyphs(_body_text, pick_fonts(m.get("lang") or DEFAULT_LANG)[0])
            warn_long_highlights(_body_text)
        except Exception:                       # noqa: BLE001 — advisory, never blocks a render
            pass
        out = f"{stem}.pdf"
        lang = m.get("lang") or DEFAULT_LANG
        # toc-title (not -V lang): pandoc's LaTeX template turns `lang` into a polyglossia
        # \setmainlanguage, and a TeX install without polyglossia's `vietnamese` then fails the
        # whole render. The TOC heading is the only thing we actually need from it, and
        # toc-title sets it directly — on the DOCX path too.
        ok = run(["pandoc", body, "-o", out,
                  "--pdf-engine=xelatex",
                  "--from", PANDOC_FROM,
                  "--number-sections", "--toc", "--toc-depth=%d" % m.get("toc_depth", 3),
                  "-M", "toc-title=%s" % S(lang, "contents"),
                  "-V", "fontsize=10pt", "-V", "linestretch=1.08",
                  "-V", "linkcolor=steel",
                  "--include-in-header", defs,
                  "--include-in-header", HOUSE_HEADER,
                  "--include-before-body", cover,
                  "--resource-path", resource_dir])
        return out if ok else None
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def render_docx(body, stem, m, resource_dir):
    out = f"{stem}.docx"
    sub = m["subtitle"] or ""
    if m["classification"]:
        sub = (m["classification"] + (" — " + sub if sub else "")).strip()
    lang = m.get("lang") or DEFAULT_LANG
    cmd = ["pandoc", body, "-o", out,
           "--from", PANDOC_FROM,
           "--number-sections", "--toc", "--toc-depth=%d" % m.get("toc_depth", 3),
           "-M", f"title={m['title']}",
           "-M", f"date={m['date']}",
           "-M", "toc-title=%s" % S(lang, "contents"),
           # Word tags the runs with this, so the reviewer's spellchecker stops underlining
           # every Vietnamese word in a document they are supposed to redline.
           "-M", f"lang={lang}",
           "--resource-path", resource_dir]
    if sub:
        cmd += ["-M", f"subtitle={sub}"]
    if os.path.isfile(REFERENCE_DOCX):
        cmd += ["--reference-doc", REFERENCE_DOCX]
    return out if run(cmd) else None


def print_glossary(lang=None):
    """The wording an author must use VERBATIM — estimative terms and house section names.

    Printed rather than applied, because this is the one part of a report the tool must not
    touch: the ICD-203 terms are a calibrated scale, and paraphrasing one silently changes what
    the report claims. `--lang vi` localises the furniture; this is how the ARGUMENT stays
    calibrated in Vietnamese."""
    langs = [lang] if lang else sorted(STRINGS.keys())
    print("ESTIMATIVE LANGUAGE (ICD-203) — use these strings verbatim, never a synonym.")
    print("Confidence (quality of the evidence) is NOT probability (likelihood of the event);")
    print("never mix the two in one sentence.\n")
    for key, spec in (ESTIMATIVE_TERMS or {}).items():
        if not isinstance(spec, dict):
            continue
        band = spec.get("band") or ""
        print(f"  {key:<22} {band:<26} " +
              "  |  ".join(f"{lg}: {spec.get(lg) or '—'}" for lg in langs))
    print("\nHOUSE SECTION NAMES — same skeleton in every language, same order.\n")
    for key, spec in (SECTION_NAMES or {}).items():
        if not isinstance(spec, dict):
            continue
        print(f"  {key:<24} " + "  |  ".join(f"{lg}: {spec.get(lg) or '—'}" for lg in langs))
    print("\nTune both in IntelReport/references/report_i18n.json (RULE 3).")


def main():
    ap = argparse.ArgumentParser(description="markdown assessment -> PDF/DOCX")
    ap.add_argument("markdown", nargs="?", help="input assessment .md")
    ap.add_argument("stem", nargs="?", help="output path stem (no extension)")
    ap.add_argument("--title", default=None)
    ap.add_argument("--subtitle", default=None)
    ap.add_argument("--case-id", default=None, help="INTERNAL case-store id — used only as a "
                    "fallback for the displayed reference; prefer --report-ref for shared reports")
    ap.add_argument("--report-ref", default=None, help="EXTERNAL report reference shown on the "
                    "cover/header. MUST differ from the internal case id so a leaked report can't be "
                    "tied back to the case store (OPSEC). Auto-reused/minted from the registry if omitted.")
    ap.add_argument("--registry", default=None, help="path to the private report-reference registry "
                    "(default: <case-store>/report_registry.jsonl)")
    ap.add_argument("--no-figures", action="store_true",
                    help="do NOT regenerate figures from figures.json before rendering "
                         "(by default IntelReport chains to IntelGraph to refresh the chart)")
    ap.add_argument("--lang", default=None, choices=sorted(STRINGS.keys()) or ["en"],
                    help="language of the GENERATED furniture — cover labels, TOC title, "
                         "'Appendix', figure/table captions (default: en, or frontmatter `lang:`). "
                         "The BODY is never translated by this tool: write the assessment in the "
                         "target language from the start, using the fixed estimative wording from "
                         "`--glossary` so the confidence scale does not drift.")
    ap.add_argument("--glossary", action="store_true",
                    help="print the ICD-203 estimative terms + house section names in every "
                         "language and exit (no render) — the wording an author must use verbatim")
    ap.add_argument("--classification", default=None, help="handling caveat, e.g. TLP:AMBER")
    ap.add_argument("--date", default=None, help="YYYY-MM-DD (default: UTC today)")
    ap.add_argument("--audience", choices=["technical", "executive", "le"], default=None,
                    help="reader profile — stamps the cover subtitle + sets TOC depth "
                         "(le = law enforcement). Content is tailored by the author; see SKILL.md.")
    ap.add_argument("--pdf", action="store_true", help="render PDF")
    ap.add_argument("--docx", action="store_true", help="render DOCX")
    args = ap.parse_args()

    if args.glossary:
        print_glossary(args.lang)
        return
    if not args.markdown or not args.stem:
        ap.error("markdown and stem are required (omit them only with --glossary)")
    if not shutil.which("pandoc"):
        sys.exit("pandoc not found — install pandoc (brew install pandoc).")
    if not os.path.isfile(args.markdown):
        sys.exit(f"no such markdown file: {args.markdown}")

    fm, body_title, body_lines = read_markdown(args.markdown)
    m = {
        "title": args.title or fm.get("title") or body_title or
                 os.path.splitext(os.path.basename(args.markdown))[0],
        "subtitle": args.subtitle or fm.get("subtitle") or "",
        "case_id": args.case_id or fm.get("case_id") or fm.get("case") or "",
        "classification": args.classification or fm.get("classification")
                          or fm.get("tlp") or "UNCLASSIFIED",
        "date": args.date or fm.get("date") or utc_today(),
    }
    # Language of the GENERATED furniture only — the body is whatever the author wrote.
    # An unknown code falls back to English rather than printing bare keys.
    lang = (args.lang or fm.get("lang") or DEFAULT_LANG).strip().lower()
    if lang not in STRINGS:
        sys.stderr.write(f"WARNING: no strings for lang={lang!r} in report_i18n.json — "
                         f"rendering the furniture in {DEFAULT_LANG}.\n")
        lang = DEFAULT_LANG
    m["lang"] = lang
    # Collection basis shown on the cover. Set it honestly: a run that retrieved live pages,
    # fingerprinted TLS or probed an endpoint is NOT passive. Frontmatter `basis:` overrides it.
    m["basis"] = fm.get("basis") or S(lang, "basis_default")

    # OPSEC: the document displays an EXTERNAL reference, never the internal
    # case-store id. Resolve the reference in this order: explicit flag/frontmatter
    # → an existing reference already logged for this case (so it's reproducible)
    # → a freshly minted RPT-YYYY-MMDD-NN. The internal case id is derived from the
    # report's path under cases/<id>/ (or --case-id) and is used ONLY for the
    # private registry mapping, never displayed.
    path_case, default_registry = locate_store(args.markdown)
    internal_case = args.case_id or fm.get("case_id") or path_case
    registry_path = args.registry or default_registry
    reg_rows = load_registry(registry_path)
    ref = args.report_ref or fm.get("report_id")
    if not ref and internal_case:
        ref = ref_for_case(reg_rows, internal_case) or gen_ref(reg_rows, m["date"])
    m["ref"] = ref or internal_case  # last-resort display fallback
    if internal_case and m["ref"] == internal_case:
        sys.stderr.write("WARNING: report reference == internal case id — set a distinct "
                         "--report-ref so a shared report can't be tied to the case store.\n")

    # Audience profile: a shorter TOC for executives, full depth otherwise, and a
    # cover-subtitle stamp if the author didn't supply one. Content tailoring is the
    # author's job (see SKILL.md "Audience"); this just labels + paces the document.
    AUD = {"technical": ("audience_technical", 3),
           "executive": ("audience_executive", 1),
           "le": ("audience_le", 3)}
    audience = args.audience or fm.get("audience")
    m["toc_depth"] = 3
    if audience in AUD:
        key, m["toc_depth"] = AUD[audience]
        if not m["subtitle"]:
            m["subtitle"] = S(lang, key)

    # default: produce both when neither flag is given
    neither = not (args.pdf or args.docx)
    want_pdf, want_docx = args.pdf or neither, args.docx or neither

    os.makedirs(os.path.dirname(os.path.abspath(args.stem)) or ".", exist_ok=True)
    resource_dir = os.path.dirname(os.path.abspath(args.markdown)) or "."
    if not args.no_figures:                 # chain to IntelGraph — refresh the chart
        regenerate_figures(resource_dir)
    tmp = tempfile.mkdtemp(prefix="intelreport_body_")
    outs = []
    try:
        body = write_body(body_lines, tmp)  # strip frontmatter ONCE, share both renders
        warn_orphan_figures(body_lines, resource_dir)
        if want_pdf:
            # the PDF build gets its own body so it can carry vector figures the DOCX cannot
            pdf_body = os.path.join(tmp, "body_pdf.md")
            with open(pdf_body, "w", encoding="utf-8") as fh:
                fh.writelines(swap_vector_figures(body_lines, resource_dir))
            p = render_pdf(pdf_body, args.stem, m, resource_dir)
            if p:
                outs.append(p)
            else:
                sys.stderr.write("PDF render FAILED\n")
        if want_docx:
            d = render_docx(body, args.stem, m, resource_dir)
            if d:
                outs.append(d)
            else:
                sys.stderr.write("DOCX render FAILED\n")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    if not outs:
        sys.exit("no outputs produced")
    print("wrote:\n  " + "\n  ".join(outs))

    # maintain the private external-ref → internal-case map (git-ignored store)
    if internal_case and m["ref"] and m["ref"] != internal_case:
        entry = {"report_ref": m["ref"], "case_id": internal_case,
                 "title": m["title"], "classification": m["classification"],
                 "date": m["date"], "audience": audience or "",
                 "stem": os.path.abspath(args.stem),
                 "outputs": [os.path.basename(o) for o in outs]}
        if record_mapping(registry_path, entry):
            print(f"registry: {m['ref']} -> {internal_case}  ({registry_path})")
        else:
            print(f"registry: {m['ref']} -> {internal_case}  (already logged)")


if __name__ == "__main__":
    main()
