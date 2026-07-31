#!/usr/bin/env python3
"""
render_report.py — turn an assessment MARKDOWN file into a polished PDF and/or
DOCX using pandoc. PDF uses the IntelReport house LaTeX theme (xelatex, muted
editorial palette matching IntelGraph); DOCX uses pandoc with a title block so
a reviewer can redline it.

No new Python deps — shells out to `pandoc` (+ `xelatex` for PDF), both of which
the repo already relies on. Embedded IntelGraph figures (`![](fig_hires.png)`)
render into the PDF automatically. Vietnamese diacritics render via DejaVu.

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
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
TEMPLATES = os.path.join(os.path.dirname(HERE), "templates")
HOUSE_HEADER = os.path.join(TEMPLATES, "house-header.tex")
REFERENCE_DOCX = os.path.join(TEMPLATES, "reference.docx")

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


def write_body(body_lines, tmpdir):
    """Write the frontmatter-stripped body to a temp .md (images still resolve
    via --resource-path pointed at the original file's directory)."""
    out = os.path.join(tmpdir, "body.md")
    with open(out, "w", encoding="utf-8") as fh:
        fh.writelines(body_lines)
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


def regenerate_figures(md_dir):
    """Rebuild every figure declared in <md_dir>/figures.json BEFORE rendering.

    figures.json = {"figures": [{"raw": [paths], "graph": "case_graph.json",
      "stem": "case_diagram", "title": "...", "direction": "LR", "legend": true,
      "drop_types": ["nameserver", ...]}]}  — paths are relative to the md dir.
    Best-effort: a figure that fails to build leaves the previous PNG in place."""
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
        graph = os.path.join(md_dir, fig["graph"])
        stem = os.path.join(md_dir, fig["stem"])
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
        if fig.get("drop_types"):
            dt = fig["drop_types"]
            cmd += ["--drop-types", dt if isinstance(dt, str) else ",".join(dt)]
        print("figure %s: %s" % ("refreshed" if run(cmd) else "FAILED", os.path.basename(stem)))


# Vietnamese-capable families, best first. All cover Latin Extended Additional
# (cà phê, Hà Nội, lừa đảo). We pick the first one actually installed so the
# skill is portable across machines instead of hardcoding one font.
SERIF_PREF = ["Noto Serif", "Source Serif 4", "Source Serif Pro", "Georgia",
              "Palatino", "PT Serif", "Charter", "DejaVu Serif",
              "Times New Roman", "TeX Gyre Termes", "Times"]
SANS_PREF = ["Noto Sans", "Source Sans 3", "Source Sans Pro", "Helvetica Neue",
             "PT Sans", "DejaVu Sans", "Arial", "TeX Gyre Heros", "Helvetica"]


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


def pick_fonts():
    """(serif, sans). Prefer a family that actually DECLARES Vietnamese coverage
    (:lang=vi) — many nice serifs (PT Serif, Charter, DejaVu on macOS) miss the
    stacked-diacritic glyphs (ộ, ừ, ả) and render tofu. Fall back to any installed
    preferred family, then Latin Modern (TeX-bundled — note: Latin Modern does NOT
    cover Vietnamese, so on a box with no fontconfig/fc-list a VN report can still
    tofu; install a Noto/Georgia/Times family there)."""
    vi = installed_families(lang="vi")
    allf = installed_families()

    def first(prefs, default):
        return (next((f for f in prefs if f in vi), None)
                or next((f for f in prefs if f in allf), default))

    return first(SERIF_PREF, "Latin Modern Roman"), first(SANS_PREF, "Latin Modern Sans")


def build_defs_and_cover(m, tmpdir, resource_dir="."):
    """Write defs.tex (header/footer macros) and cover.tex (title page).

    The document ALWAYS displays m['ref'] (the external report reference), never
    the internal case-store id — see OPSEC note in main()."""
    cls = tex_escape(m["classification"])
    caseid = tex_escape(m["ref"]) if m.get("ref") else ""
    serif, sans = pick_fonts()
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
        fh.write("\\setmainfont{%s}[Scale=0.98]\n" % serif)
        fh.write("\\setsansfont{%s}[Scale=0.98]\n" % sans)
        fh.write("\\newfontfamily\\headingfont{%s}\n" % sans)

    title = tex_escape(m["title"])
    subtitle = tex_escape(m["subtitle"]) if m["subtitle"] else ""
    date = tex_escape(m["date"])
    caserow = (r"\textbf{Reference} & %s \\" % caseid) if caseid else ""
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
\textbf{Date} & %s \\
\textbf{Basis} & Passive OSINT \\
\end{tabular}\par}
\vspace{0.6cm}{\color{grid}\hrule height 0.6pt}\par
\vspace{0.25cm}{\footnotesize\headingfont\color{muted} Handling: %s}\par
\end{titlepage}
\clearpage
""" % (cls, title, subtitle, caserow, date, cls))
    return defs, cover


def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        sys.stderr.write("\n$ " + " ".join(cmd) + "\n")
        sys.stderr.write((r.stdout or "") + (r.stderr or "") + "\n")
    return r.returncode == 0


def render_pdf(body, stem, m, resource_dir):
    """body = the frontmatter-stripped temp .md; resource_dir = original md's dir
    (so ![](fig.png) still resolves)."""
    tmp = tempfile.mkdtemp(prefix="intelreport_")
    try:
        defs, cover = build_defs_and_cover(m, tmp, resource_dir)
        out = f"{stem}.pdf"
        ok = run(["pandoc", body, "-o", out,
                  "--pdf-engine=xelatex",
                  "--from", "markdown+yaml_metadata_block+pipe_tables+grid_tables",
                  "--number-sections", "--toc", "--toc-depth=%d" % m.get("toc_depth", 3),
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
    cmd = ["pandoc", body, "-o", out,
           "--from", "markdown+yaml_metadata_block+pipe_tables+grid_tables",
           "--number-sections", "--toc", "--toc-depth=%d" % m.get("toc_depth", 3),
           "-M", f"title={m['title']}",
           "-M", f"date={m['date']}",
           "--resource-path", resource_dir]
    if sub:
        cmd += ["-M", f"subtitle={sub}"]
    if os.path.isfile(REFERENCE_DOCX):
        cmd += ["--reference-doc", REFERENCE_DOCX]
    return out if run(cmd) else None


def main():
    ap = argparse.ArgumentParser(description="markdown assessment -> PDF/DOCX")
    ap.add_argument("markdown", help="input assessment .md")
    ap.add_argument("stem", help="output path stem (no extension)")
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
    ap.add_argument("--classification", default=None, help="handling caveat, e.g. TLP:AMBER")
    ap.add_argument("--date", default=None, help="YYYY-MM-DD (default: UTC today)")
    ap.add_argument("--audience", choices=["technical", "executive", "le"], default=None,
                    help="reader profile — stamps the cover subtitle + sets TOC depth "
                         "(le = law enforcement). Content is tailored by the author; see SKILL.md.")
    ap.add_argument("--pdf", action="store_true", help="render PDF")
    ap.add_argument("--docx", action="store_true", help="render DOCX")
    args = ap.parse_args()

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
    AUD = {"technical": ("Technical briefing", 3),
           "executive": ("Executive briefing", 1),
           "le": ("Law-enforcement briefing", 3)}
    audience = args.audience or fm.get("audience")
    m["toc_depth"] = 3
    if audience in AUD:
        label, m["toc_depth"] = AUD[audience]
        if not m["subtitle"]:
            m["subtitle"] = label

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
        if want_pdf:
            p = render_pdf(body, args.stem, m, resource_dir)
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
