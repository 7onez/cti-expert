#!/usr/bin/env python3
"""
house_report.py — deterministic case dir -> IntelReport house-style PDF + DOCX.

The harness emits the editorial deliverable (Roman-numbered sections, Methodology with the
Admiralty / ICD-203 scales, relationship graph, attribution inference chain, temporal view,
landing-page captures, Appendices A–E) only when an LLM writes the report body. The deterministic
`/cti` path (`pipeline open`, `case-store snapshot`) stopped at the dashboard generators, so a case
worked without the harness never got the house PDF. This module composes that document from what
the case dir already holds — zero LLM. The ONLY egress is the landing-page capture of estate hosts
that have no screenshot yet (Rule 15a); it goes through the research-egress proxy policy exactly as
a pipeline fetch does and is skipped, not forced, when that policy blocks (`--no-screenshots` opts out):

  assessment.json      engine schema (bluf, decision_supported, attribution_level, confidence,
                       cluster[], evidence[], alternatives[], gaps[], next_pivots[])
  assessment.md        analyst-authored body (optional; its sections are folded in, scrubbed)
  scope.json           intake (claim, brand, purpose, target class)
  whois/<host>.json    registrant triple, registrar, dates, nameservers
  raw/<host>.json      collected pivots (for the temporal view + artifact register)
  clusters.json        same-operator partition
  case_graph.json      relationship graph (rendered via IntelGraph)
  shared.txt           shared-indicator seeds (artifact register)
  knowledge/reference.jsonl   §2.5 verdicts (benign rows are marked "excluded")
  knowledge/operators.jsonl   confirmed-operator ledger

House rules enforced here (IntelReport SKILL Rules 0–23): decision statement first, BLUF table and
bottom-line callout, Methodology early with both scales, headings unnumbered (the template numbers
them), one captured landing page per estate host inline in the cluster section, per-domain dossiers,
appendices after a raw `\\appendix` marker, appendices = evidence only (full capture hashes in the
ledger), a glossary of the terms the report actually uses, no internal tool/vendor/path names in
the body (Rule 12) while every indicator VALUE is kept (Rule 12a).

Usage:
    python3 tools/house_report.py <CASE-ID|case-dir> [--stem NAME] [--classification TLP:AMBER]
                                  [--audience technical|executive|le] [--no-figures] [--md-only]
                                  [--no-screenshots] [--max-screenshots 40] [--screenshot-timeout 30] [--no-archive-fallback]
"""
from __future__ import annotations

import argparse
import datetime as dt
import glob
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PY = sys.executable
GRAPH_TO_DIAGRAM = os.path.join(ROOT, "IntelGraph", "scripts", "graph_to_diagram.py")
RENDER_GRAPHVIZ = os.path.join(ROOT, "IntelGraph", "scripts", "render_graphviz.py")
RENDER_MERMAID = os.path.join(ROOT, "IntelGraph", "scripts", "render_mermaid.py")
CASE_TIMELINE = os.path.join(ROOT, "IntelGraph", "scripts", "case_timeline.py")
RENDER_REPORT = os.path.join(ROOT, "IntelReport", "scripts", "render_report.py")
KB = os.path.join(ROOT, "knowledge")

FIGURE_DROP_TYPES = ["nameserver", "registrar", "template", "theme", "email", "social", "favicon"]
GRAPH_BUILD = os.path.join(ROOT, "WebPivot", "tools", "graph_build.py")
FIGURE_MAX_NODES = 14   # above this the main figure is a representative subset; Appendix D enumerates all

# IntelGraph house palette (theme.py PALETTE) — keep the DOT figure on the same paper.
INK, MUTED, GRID = "#1f1d1a", "#6f6a61", "#d9d3c7"
STEEL, SLATE, OCHRE, BRICK, PAPER = "#3b5566", "#22333f", "#b0790f", "#8c2d2d", "#ffffff"

# Rule 12: internal working / data-vendor names -> public source CLASS. Case evidence is never touched.
PUBLIC_CLASS = [
    (r"\bWhoisXML\b", "registration-data service"),
    (r"\bIntelX\b|\bIntelligence X\b", "leak-corpus search"),
    (r"\bCLD\b|\bChongLuaDao\b|\bChống Lừa Đảo\b", "anti-scam verdict service"),
    (r"\bHudsonRock(-class)?\b", "infostealer-corpus"),
    (r"\bFOFA\b|\burlscan(\.io)?\b|\bCensys\b|\bShodan\b|\bValidin\b|\bSecurityTrails\b|\bDNSLytics\b|\bQuake\b|\bZoomEye\b|\bHunter\.how\b",
     "web-scan index"),
    (r"\bmaigret\b|\bsherlock\b", "username enumeration"),
    (r"\bWayback\b", "web-archive"),
    (r"\bCDX\b", "archive-index"),
    (r"\bIPinfo\b", "IP/ASN data"),
    (r"\bpivot_extract\b|\bpipeline open\b|\bcase-store\b|\bkb_ingest\b|\bintel\.py\b|\breference ledger\b|\boperators ledger\b|\bthe KB\b|\bknowledge base\b",
     "the case record"),
]
# backticked internal tooling (slash-commands, pipeline flags, script names) -> one neutral phrase
_TOOL_TICK_RE = re.compile(r"`(?:/[a-z][a-z-]*[^`]*|[^`]*(?:--no-collect|--passive|pivot_extract|pipeline open|intel\.py|case-store|urllib)[^`]*)`")
_UNITS_RE = re.compile(r"\s*\((?:\d+\s*[×x]\s*)?\d+\s*(?:units?|credits?)\)")
_PLAIN_PATH_RE = re.compile(r"\b(?:evidence|raw|whois|report|knowledge|cases|MEMORY)/[A-Za-z0-9_.*<>/-]+")
_TAG_RE = re.compile(r"\s*`?\[(?:[a-z0-9-]+)(?:\]\[(?:[a-z0-9-]+))*\]`?(?=[\s.,;)]|$)")
_PATH_RE = re.compile(r"`(?:[A-Za-z0-9_./-]+/)+[A-Za-z0-9_.*<>-]+`")
_DROP_LINE_RE = re.compile(r"api_usage|MEMORY/|Credits spent|ledger window", re.I)

# Shareable-export masking (/cti output rule; assessment Rec "do not name third parties") lives in
# scripts/cti_text_normalize.py so the dashboard path (build_report_data.py) and this composer apply
# the SAME gate. _KEEP is filled per case by load_case() from the join-key registrant fields (values
# present on >= 2 case hosts); _HOSTS are the estate's own domains; _MASK_EXTRA comes from
# <case>/report_mask.json (display names, page slugs …).
sys.path.insert(0, os.path.join(os.path.dirname(ROOT), "scripts"))
from cti_text_normalize import normalize_dashes  # noqa: E402
from cti_third_party_mask import mask_third_parties as _mask, load_case_mask  # noqa: E402
from cti_case_meta import resolve_seed, case_classification  # noqa: E402
import house_report_captures as hrc  # noqa: E402
import house_report_correlations as hrx  # noqa: E402
import house_report_dossier as hrd  # noqa: E402
import house_report_charts as hrg  # noqa: E402
try:  # registrar/privacy-proxy classifier for the Registrant-eras table (best-effort)
    sys.path.insert(0, os.path.join(ROOT, "WebPivot", "tools"))
    from whois_enrich import is_privacy as _is_privacy  # noqa: E402
except Exception:  # pragma: no cover — the table still renders, class falls back to "named"
    _is_privacy = None

_KEEP: set = set()
_HOSTS: set = set()
_MASK_EXTRA: list = []
_CURRENT_CASE: str = ""


def mask_third_parties(text: str) -> str:
    return _mask(text, keep=_KEEP, hosts=_HOSTS, extra=_MASK_EXTRA, current_case=_CURRENT_CASE)


MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


# --------------------------------------------------------------------------- loading
def _load_json(path, default=None):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return default


def _case_dir(arg: str) -> str:
    if os.path.isdir(arg):
        return os.path.abspath(arg)
    return os.path.join(ROOT, "cases", arg)


def case_seed(c: dict) -> str:
    return resolve_seed(c["dir"], c.get("hosts") or [], c.get("raw") or [])


def load_case(case_dir: str, mask_personas: bool = False) -> dict:
    c = {"dir": case_dir, "case": os.path.basename(case_dir.rstrip("/"))}
    c["assessment"] = _load_json(os.path.join(case_dir, "assessment.json"), {}) or {}
    md_path = os.path.join(case_dir, "assessment.md")
    c["analyst_md"] = open(md_path, encoding="utf-8").read() if os.path.exists(md_path) else ""
    c["scope"] = _load_json(os.path.join(case_dir, "scope.json"), {}) or {}
    c["clusters"] = _load_json(os.path.join(case_dir, "clusters.json"), {}) or {}
    c["mo_neighbours"] = _load_json(os.path.join(case_dir, "mo_neighbours.json"), {}) or {}
    c["mask_personas"] = bool(mask_personas)
    c["graph"] = os.path.join(case_dir, "case_graph.json")
    c["whois"] = {}
    for p in glob.glob(os.path.join(case_dir, "whois", "*.json")):
        c["whois"][os.path.basename(p)[:-5].lower()] = _load_json(p, {}) or {}
    c["raw"] = sorted(p for p in glob.glob(os.path.join(case_dir, "raw", "*.json"))
                      if not os.path.basename(p).startswith("harvest.")
                      and not p.endswith(".impersonation.json"))
    c["hosts"] = sorted(os.path.basename(p)[:-5].lower() for p in c["raw"])
    sh = os.path.join(case_dir, "shared.txt")
    c["shared"] = parse_shared(open(sh, encoding="utf-8").read()) if os.path.exists(sh) else []
    c["benign"] = load_benign()
    c["operators"] = load_operators(c["case"], c["hosts"])
    c["seed"] = case_seed(c)
    global _KEEP, _MASK_EXTRA, _CURRENT_CASE, _HOSTS
    _CURRENT_CASE = c["case"]
    _HOSTS = set(c["hosts"])
    counts = {}
    for w in c["whois"].values():
        for k in ("registrant_email", "registrant_phone"):
            v = (w.get(k) or "").strip().lower()
            if v and "privacy" not in v and not v.startswith("abuse@"):
                counts[v] = counts.get(v, 0) + 1
    _KEEP = {v for v, n in counts.items() if n >= 2}
    # Related personas (MO-neighbour, rung 10) render IN CLEAR by default — an analyst decision
    # (Validation Session 1) — so exactly those verified identities are folded into _KEEP. Scoped:
    # every other third-party value in the case stays masked. --mask-personas skips the fold-in.
    if not mask_personas:
        for p in c["mo_neighbours"].get("related_personas") or []:
            v = str(p.get("persona") or "").strip().lower()
            if v:
                _KEEP.add(v)
    _MASK_EXTRA = load_case_mask(case_dir)
    return c


def parse_shared(text: str) -> list:
    """shared.txt -> [{count, indicator, rel, kb_wide, domains[]}]"""
    out, cur = [], None
    for line in text.splitlines():
        m = re.match(r"\[(\d+)\]\s+(\S+)\s+\((\w+)\)(?:\s+\[KB-wide:\s*(\d+)\s+domains\])?", line)
        if m:
            cur = {"count": int(m.group(1)), "indicator": m.group(2), "rel": m.group(3),
                   "kb_wide": int(m.group(4)) if m.group(4) else None, "domains": []}
            out.append(cur)
        elif cur and line.startswith("     "):
            cur["domains"] += [d.strip() for d in line.split(",") if d.strip()]
    return out


def load_benign() -> set:
    vals = set()
    p = os.path.join(KB, "reference.jsonl")
    if not os.path.exists(p):
        return vals
    for line in open(p, encoding="utf-8"):
        try:
            r = json.loads(line)
        except Exception:
            continue
        if r.get("verdict") == "benign":
            vals.add(str(r.get("value", "")).lower())
    return vals


def load_operators(case: str, hosts: list) -> list:
    p = os.path.join(KB, "operators.jsonl")
    if not os.path.exists(p):
        return []
    hostset = set(hosts)
    out = []
    for line in open(p, encoding="utf-8"):
        try:
            r = json.loads(line)
        except Exception:
            continue
        if r.get("case") == case or hostset & set(r.get("domains") or []):
            out.append(r)
    out.sort(key=lambda r: (r.get("case") != case, -len(r.get("domains") or [])))
    return out


# --------------------------------------------------------------------------- analyst md
def split_sections(md: str) -> dict:
    """'## Heading' -> body text (the analyst file uses one '#' title then '##' sections)."""
    secs, cur, buf = {}, None, []
    for line in md.splitlines():
        if line.startswith("## "):
            if cur is not None:
                secs[cur] = "\n".join(buf).strip()
            cur, buf = line[3:].strip(), []
        elif line.startswith("# ") and cur is None:
            secs["_title"] = line[2:].strip()
        else:
            buf.append(line)
    if cur is not None:
        secs[cur] = "\n".join(buf).strip()
    return secs


def find_section(secs: dict, *needles: str) -> str:
    for k, v in secs.items():
        kl = k.lower()
        if any(n in kl for n in needles):
            return v
    return ""


def scrub(text: str) -> str:
    """Rule 12: drop collection-method tags, internal paths and vendor names; keep evidence values."""
    out = []
    for line in text.splitlines():
        if _DROP_LINE_RE.search(line):
            continue
        line = _TAG_RE.sub("", line)
        line = _TOOL_TICK_RE.sub("internal tooling", line)
        line = _UNITS_RE.sub("", line)
        line = _PATH_RE.sub("the case record", line)
        line = _PLAIN_PATH_RE.sub("the case record", line)
        for pat, repl in PUBLIC_CLASS:
            line = re.sub(pat, repl, line, flags=re.I)
        out.append(line)
    text = "\n".join(out)
    for bad, good in (("→", "->"), ("≠", "!="), ("≤", "<="), ("≥", ">="), ("⇄", "<->")):
        text = text.replace(bad, good)   # Noto Serif has no glyph for these -> tofu in the PDF
    text = mask_third_parties(text)
    # a bare <!-- … --> is an HTML comment to pandoc and silently vanishes from PDF/DOCX
    text = re.sub(r"(?<!`)(<!--.*?-->)(?!`)", r"`\1`", text)
    # collapse the blank runs the drops leave behind
    return re.sub(r"\n{3,}", "\n\n", text).strip()


def demote_headings(text: str) -> str:
    """Embedded content lands inside a house '#' section: flatten every heading it carries to
    '###' so it can never open a new Roman-numbered section of its own."""
    return re.sub(r"^#{1,6} ", "### ", text, flags=re.M)


def condense_timeline_ledger(md: str, events: dict | None = None) -> tuple:
    """case_timeline markdown -> (body correlations, appendix ledger table).

    Body: the non-empty temporal findings as tables with one judgment sentence each — never the
    tool's per-row guidance or its raw field dumps (house_report_correlations.temporal_correlations_md).
    Appendix: the dated rows minus our own collection provenance ('collected by us' is internal
    working, Rule 13) with the explanatory tail of each 'What' cell dropped."""
    if not md and not events:
        return "", ""
    tbl = ["| When (UTC) | Host | Observation | Source (grade) |", "|:--:|:------------|:------------------|:------|"]
    for ln in md.splitlines():
        m = re.match(r"\|\s*(\d{4}-\d{2}-\d{2}[^|]*)\|\s*([^|]*)\|\s*([^|]*)\|\s*([^|]*)\|", ln)
        if not m or "collected by us" in m.group(3):
            continue
        what = m.group(3).split(" — ")[0].strip()
        tbl.append(f"| {m.group(1).strip()[:10]} | {m.group(2).strip()} | {_md_escape(what)} | {m.group(4).strip()} |")
    ledger = "\n".join(tbl) if len(tbl) > 2 else ""
    return hrx.temporal_correlations_md(md, _md_escape, events), ledger


def parse_judgments(section: str) -> list:
    """Numbered '**Title** — body … (A1)' items -> [{title, body, grade, confidence}]."""
    items = re.split(r"\n(?=\d+\.\s+\*\*)", "\n" + section)
    out = []
    for it in items:
        it = it.strip()
        m = re.match(r"\d+\.\s+\*\*(.+?)\*\*\s*(.*)", it, re.S)
        if not m:
            continue
        title, body = m.group(1).strip(" .—-"), " ".join(m.group(2).split())
        g = re.findall(r"\(([A-F][1-6])", body)
        conf = re.search(r"(assessed|likely|possible|cannot rule out|unattributed)\s*/?\s*(high|moderate|low)?", title + " " + body, re.I)
        out.append({"title": title, "body": scrub(body), "grade": g[-1] if g else "",
                    "confidence": (conf.group(0) if conf else "").strip()})
    return out


# --------------------------------------------------------------------------- figures
def _run(cmd, timeout=300):
    try:
        return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=timeout)
    except Exception as e:  # noqa: BLE001
        class R:  # minimal stand-in
            returncode, stdout, stderr = 1, "", str(e)
        return R()


def fig_relationship(c: dict, rep_dir: str, title: str) -> list:
    """raw/*.json -> report/case_graph.json (no sibling ribbons, + operator persona node) ->
    report/case_diagram*.png via IntelGraph (Mermaid). Large estates render as a representative
    subset (IntelGraph --max-nodes); Appendix D carries the full enumeration."""
    if not c["raw"]:
        return []
    graph_json = os.path.join(rep_dir, "case_graph.json")
    cmd = [PY, GRAPH_BUILD, *c["raw"], "-o", graph_json, "--no-rank"]
    # the persona node the reference figures carry: the registrant record tied to its estate
    ops = c["operators"]
    if ops:
        persona = ops[0].get("operator", "")
        links = [d for d in (ops[0].get("domains") or []) if d in set(c["hosts"])]
        if persona and links:
            cmd += ["--operator", f"{persona} (persona)", "--operator-links", ",".join(links)]
    gb = _run(cmd, timeout=240)
    if gb.returncode != 0 or not os.path.exists(graph_json):
        # fall back to the pipeline's graph (has sibling ribbons; still better than nothing)
        if os.path.exists(c["graph"]):
            with open(c["graph"], encoding="utf-8") as src, open(graph_json, "w", encoding="utf-8") as dst:
                dst.write(src.read())
        else:
            return []
    _flatten_communities(graph_json, c)
    recipe = os.path.join(rep_dir, "figures.json")
    if not os.path.exists(recipe):
        json.dump({"figures": [{"raw_glob": "../raw/*.json", "graph": "case_graph.json",
                                "stem": "case_diagram", "title": title[:80], "direction": "LR",
                                "legend": True, "drop_types": FIGURE_DROP_TYPES,
                                "max_nodes": FIGURE_MAX_NODES}]},
                  open(recipe, "w", encoding="utf-8"), indent=2)
    stem = os.path.join(rep_dir, "case_diagram")
    r = _run([PY, GRAPH_TO_DIAGRAM, graph_json, stem, "--title", title[:80], "--legend",
              "--drop-types", ",".join(FIGURE_DROP_TYPES), "--max-nodes", str(FIGURE_MAX_NODES)], timeout=240)
    main = _page_safe_png(stem)
    if not main:
        sys.stderr.write(f"relationship figure skipped: {(r.stderr or r.stdout).strip()[:200]}\n")
        return []
    legend = _page_safe_png(stem + "_legend")
    return [main] + ([legend] if legend else [])


def _flatten_communities(graph_json: str, c: dict) -> None:
    """graph_to_diagram boxes nodes by Louvain `community` — on a case clusters.json judges as ONE
    operator cluster, five boxes read as five operators. Re-label communities from clusters.json."""
    g = _load_json(graph_json)
    if not g:
        return
    cl = [k for k in (c["clusters"].get("clusters") or []) if not k.get("singleton")]
    dom2cl = {d: i for i, k in enumerate(cl) for d in (k.get("domains") or [])}
    for n in g.get("nodes") or []:
        cid = dom2cl.get(n.get("id"), 0 if len(cl) <= 1 else n.get("community", 0))
        n["community"] = cid
        n["community_rank"] = cid
    json.dump(g, open(graph_json, "w", encoding="utf-8"), ensure_ascii=False)


_MAX_PX = 4000   # xelatex \\includegraphics chokes ("Dimension too large") well before this


def _page_safe_png(stem: str) -> str | None:
    """Pick the PNG a PDF engine can include; downscale the hi-res one if it is oversized."""
    try:
        from PIL import Image
        Image.MAX_IMAGE_PIXELS = None
    except Exception:  # noqa: BLE001
        Image = None
    for cand in (stem + "_hires.png", stem + ".png", stem + "_thumb.png"):
        if not os.path.exists(cand):
            continue
        if Image is None:
            return cand
        try:
            im = Image.open(cand)
        except Exception:  # noqa: BLE001
            continue
        w, h = im.size
        if max(w, h) <= _MAX_PX:
            return cand
        k = _MAX_PX / max(w, h)
        fit = stem + "_report.png"
        im.convert("RGB").resize((max(1, int(w * k)), max(1, int(h * k))), Image.LANCZOS).save(fit, optimize=True)
        return fit
    return None


# Sector typology by domain tokens — the estate's own MO, used to give the §V figure ranks.
_SECTORS = [
    ("Medical", re.compile(r"benhvien|hospital|dental|medlatec|vnvc|vinmec|nhidong|kangnam|yhct|phusan|clinic|pharma|sanofi", re.I)),
    ("Recruitment / education", re.compile(r"tuyendung|^hr|career|edu|school|uni|kids|kinder|maplebear|greenwich|rmit|vnu|vinschool|hanoinational", re.I)),
]


def _sector(domain: str) -> str:
    label = domain.split(".")[0]
    for name, rx in _SECTORS:
        if rx.search(label):
            return name
    return "Corporate / consumer brands"


def fig_sector_graph(c: dict, rep_dir: str, title: str) -> str | None:
    """persona -> sector -> domains: a three-rank figure the hub-and-spoke IntelGraph render cannot
    give (one hub -> N leaves is always one strip). Authored from clusters.json + the registrant record;
    rendered by IntelGraph's Mermaid renderer so it shares the house theme."""
    cl = [k for k in (c["clusters"].get("clusters") or []) if not k.get("singleton")]
    if not cl:
        return None
    domains = sorted(d for k in cl for d in (k.get("domains") or []))
    if len(domains) < 3:
        return None
    ops = [o for o in c["operators"] if o.get("case") == c["case"]] or c["operators"][:1]
    persona = (ops[0].get("operator") if ops else None) or next(iter(_KEEP), "registrant record")
    try:
        sys.path.insert(0, os.path.join(ROOT, "IntelGraph", "scripts"))
        from theme import mermaid_init  # noqa: WPS433
        init = mermaid_init({"nodeSpacing": 22, "rankSpacing": 70, "useMaxWidth": False})
    except Exception:  # noqa: BLE001
        init = "%%{init: {\"theme\": \"neutral\", \"flowchart\": {\"nodeSpacing\": 22, \"rankSpacing\": 70}}}%%"
    by = {}
    for d in domains:
        by.setdefault(_sector(d), []).append(d)
    q = lambda t: t.replace('"', "'")  # noqa: E731
    lines = [init, "flowchart LR",
             f'  P["👤 {q(persona)}<br/>registrant record on {len(domains)} domains"]',
             "  classDef persona fill:#5a1a1a,stroke:#b00020,color:#ffffff,font-weight:bold;",
             "  classDef sector fill:#3b5566,stroke:#22333f,color:#ffffff;",
             "  classDef dom fill:#f2f2f2,stroke:#d9d3c7,color:#1f1d1a;",
             "  classDef seed fill:#b0790f,stroke:#8c6a0f,color:#ffffff,font-weight:bold;",
             "  class P persona;"]
    for si, (sector, ds) in enumerate(sorted(by.items(), key=lambda kv: -len(kv[1]))):
        sid = f"S{si}"
        lines.append(f'  {sid}["{q(sector)}<br/>{len(ds)} domains"]')
        lines.append(f"  class {sid} sector;")
        lines.append(f'  P -->|"registrant e-mail + phone"| {sid}')
        lines.append(f'  subgraph G{si}[" "]')
        lines.append("    direction TB")
        # grid the leaves: rows of up to 4 so a 15-domain sector is 4 rows, not one 15-wide rank
        for ri in range(0, len(ds), 4):
            row = ds[ri:ri + 4]
            for d in row:
                nid = "D" + re.sub(r"[^A-Za-z0-9]", "_", d)
                lines.append(f'    {nid}["{q(d)}"]')
                lines.append(f"    class {nid} {'seed' if d == c['seed'] else 'dom'};")
            if ri:
                prev = ds[ri - 4:ri]
                for a_, b_ in zip(prev, row):
                    lines.append(f"    D{re.sub(r'[^A-Za-z0-9]', '_', a_)} ~~~ D{re.sub(r'[^A-Za-z0-9]', '_', b_)}")
        lines.append("  end")
        lines.append(f"  {sid} --> G{si}")
    lines.append("  style P stroke-width:2px;")
    mmd = os.path.join(rep_dir, "estate_sectors.mmd")
    open(mmd, "w", encoding="utf-8").write("\n".join(lines) + "\n")
    stem = os.path.join(rep_dir, "estate_sectors")
    r = _run([PY, RENDER_MERMAID, mmd, stem, "--width", "1900", "--pdf"], timeout=240)
    png = _page_safe_png(stem)
    if not png:
        sys.stderr.write(f"sector figure skipped: {(r.stderr or r.stdout).strip()[:200]}\n")
    return png


def _dot_escape(s: str) -> str:
    """Escape quotes only — the \\n line breaks in labels are intentional DOT escapes."""
    return s.replace('"', '\\"')


def _wrap(s: str, width: int = 34) -> str:
    import textwrap
    return "\\n".join(textwrap.wrap(s, width=width)[:3])


def _icd_word(conf: str, level: str) -> str:
    conf, level = (conf or "").lower(), (level or "").lower()
    if "inconclusive" in level or "unattributed" in level:
        return "roughly even chance / unattributed"
    return {"high": "almost certain (95–99%)", "moderate": "likely (55–80%)",
            "low": "roughly even chance (45–55%)"}.get(conf, "likely")


def fig_attribution_chain(c: dict, rep_dir: str) -> str | None:
    """Inference chain: seed -> supporting evidence (solid) / tested-and-rejected (dashed) -> verdict."""
    a = c["assessment"]
    if not a:
        return None
    seed = c["seed"]
    seed_w = c["whois"].get(seed, {})
    created = (seed_w.get("created") or "")[:10]
    seed_lbl = f"Seed: {seed}" + (f"\\nregistered {created}" if created else "")

    support = []
    for e in a.get("evidence") or []:
        if not isinstance(e, str):
            continue
        # keep the strongest rungs / grades; strip the source suffix and the id
        body = re.sub(r"^E\d+\s*\[[^\]]*\]\s*", "", e).split(" — ")[0]
        rung = re.search(r"rung (\d+)", e)
        grade = re.search(r"\[([A-F][1-6])", e)
        strong = (rung and int(rung.group(1)) <= 8) or (grade and grade.group(1)[0] in "AB")
        if strong and "rejected" not in e.lower():
            support.append("- " + _wrap(scrub(body), 40))
    support = support[:6] or ["- (see Evidence ledger)"]

    rejected, open_alts = [], []
    for alt in a.get("alternatives") or []:
        s = alt if isinstance(alt, str) else f"{alt.get('hypothesis','')} — {alt.get('status','')}"
        head = s.split(" — ")[0]
        if "REJECTED" in s.upper() and "CANNOT" not in s.upper():
            rejected.append("x " + _wrap(head, 36))
        elif "CANNOT RULE OUT" in s.upper():
            open_alts.append(_wrap(head, 34))
    rejected = rejected[:5]

    verdict = (a.get("attribution_level") or "unattributed").split(";")[0].strip()
    verdict_lbl = f"{verdict.upper()}\\n{_icd_word(a.get('confidence'), verdict)}"
    ops = [o.get("operator", "") for o in c["operators"]]
    if ops and "unattributed" not in verdict.lower():
        tail = "Operator record\\n" + _wrap(ops[0], 36) + "\\n(persona; principal not named)"
    else:
        tail = "Characterised, NOT named"

    lines = [
        "digraph chain {",
        f'  graph [rankdir=TB, bgcolor="{PAPER}", nodesep=0.6, ranksep=0.7, fontname="DejaVu Sans"];',
        f'  node  [shape=box, style="filled", fontname="DejaVu Sans", fontsize=11, color="{GRID}", penwidth=1.2, margin="0.25,0.14"];',
        f'  edge  [color="{MUTED}", arrowsize=0.7, fontname="DejaVu Sans", fontsize=10, fontcolor="{INK}"];',
        f'  seed    [label="{_dot_escape(seed_lbl)}", fillcolor="{STEEL}", fontcolor="{PAPER}"];',
        f'  support [label="{_dot_escape("SUPPORTING EVIDENCE" + chr(92) + "n" + (chr(92) + "n").join(support))}", fillcolor="{STEEL}", fontcolor="{PAPER}"];',
    ]
    if rejected:
        lines.append(f'  reject  [label="{_dot_escape("TESTED AND REJECTED" + chr(92) + "n" + (chr(92) + "n").join(rejected))}", '
                     f'style="filled,dashed", fillcolor="#f2f2f2", fontcolor="{MUTED}", color="{MUTED}"];')
    lines.append(f'  verdict [label="{_dot_escape(verdict_lbl)}", fillcolor="{BRICK}", fontcolor="{PAPER}"];')
    lines.append(f'  tail    [label="{_dot_escape(tail)}", style="filled,dashed", fillcolor="{PAPER}", fontcolor="{SLATE}", color="{STEEL}"];')
    lines.append("  seed -> support;")
    lines.append('  support -> verdict [label="conjunction, not any single artifact"];')
    if rejected:
        lines.append('  reject -> verdict [style=dashed, label="excluded from the cluster"];')
        lines.append("  {rank=same; support; reject;}")
    open_lbl = " · ".join(open_alts[:2]) if open_alts else "no independent corroborator of identity"
    lines.append(f'  verdict -> tail [label="{_dot_escape(open_lbl)}"];')
    lines.append("}")

    dot_path = os.path.join(rep_dir, "attribution_chain.dot")
    open(dot_path, "w", encoding="utf-8").write("\n".join(lines) + "\n")
    stem = os.path.join(rep_dir, "attribution_chain")
    r = _run([PY, RENDER_GRAPHVIZ, dot_path, stem], timeout=120)
    _run(["dot", "-Tpdf", dot_path, "-o", stem + ".pdf"], timeout=60)
    safe = _page_safe_png(stem)
    if safe:
        return safe
    # last resort: dot directly
    r2 = _run(["dot", "-Tpng", "-Gdpi=170", dot_path, "-o", stem + ".png"], timeout=60)
    if os.path.exists(stem + ".png"):
        return stem + ".png"
    sys.stderr.write(f"attribution figure skipped: {(r.stderr or r2.stderr or '').strip()[:200]}\n")
    return None


def fig_timeline(c: dict, rep_dir: str, observed: str) -> tuple:
    """case_timeline.py -> temporal figure + its dated evidence ledger markdown."""
    if not c["raw"]:
        return None, ""
    # case_timeline reads artifacts.whois from each pivot JSON. The SIDECAR (whois/<host>.json) is the
    # case's authoritative WHOIS: siblings collected with the WHOIS layer off have their record only
    # there, and a purchased history (`--whois-history purchase`) lives only there — a raw file
    # collected in preview/off mode carries `history.records == []` and would erase the eras from the
    # timeline. Merge into a temp copy: missing whois -> sidecar; empty records + sidecar has them ->
    # sidecar's history.
    import tempfile
    tmpdir = tempfile.mkdtemp(prefix="house_tl_")
    merged = []
    for rp in c["raw"]:
        host = os.path.basename(rp)[:-5].lower()
        d = _load_json(rp, {}) or {}
        arts = d.setdefault("artifacts", {}) if isinstance(d.get("artifacts"), dict) else {}
        side = c["whois"].get(host) or {}
        if not arts.get("whois") and side:
            arts["whois"] = side
            d["artifacts"] = arts
        elif isinstance(arts.get("whois"), dict) and side:
            raw_recs = ((arts["whois"].get("history") or {}).get("records")) or []
            side_recs = ((side.get("history") or {}).get("records")) or []
            if side_recs and not raw_recs:
                arts["whois"] = dict(arts["whois"], history=side["history"])
                d["artifacts"] = arts
        out = os.path.join(tmpdir, os.path.basename(rp))
        json.dump(d, open(out, "w", encoding="utf-8"), ensure_ascii=False)
        merged.append(out)
    stem = os.path.join(rep_dir, "timeline")
    ledger = os.path.join(rep_dir, "timeline_ledger.md")
    r = _run([PY, CASE_TIMELINE, *merged, "--stem", stem, "--markdown", ledger,
              "--observed", observed, "--title", "Infrastructure lifecycle"], timeout=300)
    png = _page_safe_png(stem)
    md = open(ledger, encoding="utf-8").read() if os.path.exists(ledger) else ""
    if not png:
        sys.stderr.write(f"timeline figure skipped: {(r.stderr or r.stdout).strip()[:200]}\n")
    return png, scrub(md)


# --------------------------------------------------------------------------- tables
def _md_escape(s) -> str:
    t = str(s if s is not None else "—").replace("|", "\\|").replace("\n", " ")
    if "<" in t and "`" not in t:
        t = t.replace("<", "&lt;").replace(">", "&gt;")
    return t


def source_class(indicator: str) -> tuple:
    """indicator id -> (public source class, default Admiralty grade)."""
    kind = indicator.split(":")[0] if not indicator.startswith("indicator:") else indicator.split(":")[1]
    return {
        "email": ("WHOIS", "A1"), "person": ("WHOIS", "A2"), "phone": ("WHOIS", "A1"),
        "ip": ("passive DNS / IP", "B2"), "ns": ("DNS", "B3"), "favicon": ("live page", "B3"),
        "wp_theme": ("live page", "B3"), "css_hash": ("live page", "B3"), "js_bundle": ("live page", "B3"),
        "dom_skeleton": ("live page", "B3"), "comment": ("live page", "B3"), "structure": ("public web-scan data", "C3"),
        "social": ("live page", "B3"), "cert": ("certificate transparency", "B2"),
    }.get(kind, ("public web-scan data", "B3"))


def artifact_register(c: dict) -> str:
    rows = ["| Artifact | Value | Source (public class) | Admiralty | Domains | Status |",
            "|:------|:----------------|:----------|:--:|:--:|:--------|"]
    for s in c["shared"]:
        ind = s["indicator"]
        value = ind.split(":", 1)[1] if ":" in ind else ind
        if value.startswith(("ip:", "ns:", "favicon:", "wp_theme:", "css_hash:", "js_bundle:", "dom_skeleton:", "comment:", "social:", "structure:")):
            kind, value = value.split(":", 1)
        else:
            kind = ind.split(":")[0]
        cls, grade = source_class(ind)
        benign = ind.lower() in c["benign"] or value.lower() in c["benign"] or f"{kind}:{value}".lower() in c["benign"]
        prevalent = s["kb_wide"] and s["kb_wide"] > 2 * s["count"]
        status = "excluded — shared / kit (§2.5)" if (benign or prevalent) else ("join key" if kind in ("email", "phone") else "corroborating")
        rows.append(f"| {kind} | `{_md_escape(value)}` | {cls} | {grade} | {s['count']} | {status} |")
    return "\n".join(rows) if len(rows) > 2 else "_No shared artifacts recorded._"


def evidence_ledger(c: dict) -> str:
    ev = c["assessment"].get("evidence") or []
    rows = ["| # | Evidence | Grade | Source (public class) |", "|:-:|:----------------------|:--:|:----------|"]
    for i, e in enumerate(ev, 1):
        if not isinstance(e, str):
            e = json.dumps(e, ensure_ascii=False)
        grade = re.search(r"\[([A-F][1-6])", e)
        body = re.sub(r"^E\d+\s*\[[^\]]*\]\s*", "", e)
        claim, src = (body.rsplit(" — ", 1) + [""])[:2] if " — " in body else (body, "")
        rows.append(f"| {i} | {_md_escape(scrub(claim))} | {grade.group(1) if grade else '—'} | {_md_escape(scrub(src) or 'case evidence')} |")
    return "\n".join(rows) if ev else "_No evidence ledger in the assessment._"


def domain_profiles(c: dict) -> str:
    """Rule 17: one Field · Value dossier per domain (status, registration, hosting, TLS, mail, stack, artifacts)."""
    return hrd.domain_profiles_md(c, _load_json, _md_escape)


def cluster_enumeration(c: dict) -> str:
    cl = c["clusters"].get("clusters") or []
    out = []
    for k in cl:
        if k.get("singleton"):
            continue
        out.append(f"**Cluster {k.get('id')}** — {k.get('size')} domains, bound by "
                   f"{k.get('binding_total', len(k.get('binding_indicators') or []))} shared indicators.\n")
        out.append(", ".join(f"`{d}`" for d in k.get("domains") or []))
        out.append("")
    _SIDECARS = {"harvest.indicators", "bachmai.gov.vn.impersonation"}
    singles = [d for k in cl if k.get("singleton") for d in (k.get("domains") or []) if d not in _SIDECARS and "." in d]
    if singles:
        out.append("Singletons (no same-operator edge): " + ", ".join(f"`{d}`" for d in singles))
    return "\n".join(out) or "_No cluster partition recorded._"


def era_start_of(c: dict, figs: dict, h: str):
    """The registration cutoff an archive capture is judged against for host `h`: the start of the
    LATEST registrant era from the timeline events (WHOIS history), falling back to the WHOIS
    `created` date when the host has a single era or no era data. A capture dated before this cutoff
    shows a previous registrant's page — a drop-catch/reactivation, not the operator's landing page.

    Deliberately the LATER of the two candidate dates. Era starts are dated by the first WHOIS
    history record of the new identity, which can lag a re-registration; using the (earlier) reset
    `created` date instead would recover a few operator captures but would also risk captioning a
    previous owner's page as the operator's — the attribution error the output rule forbids. The
    conservative cutoff mis-labels at most an early operator capture as prior-owner, never the
    reverse."""
    created = (c.get("whois", {}).get(h, {}) or {}).get("created")
    return hrx.era_start_of(figs.get("timeline_events") or {}, h, fallback=created)


def registration_waves(c: dict) -> str:
    by_month = {}
    for h in c["hosts"]:
        d = (c["whois"].get(h, {}).get("created") or "")[:7]
        if re.match(r"\d{4}-\d{2}", d):
            by_month.setdefault(d, []).append(h)
    if not by_month:
        return ""
    rows = ["| Month | Registrations | Domains |", "|:--:|:--:|:----------------------|"]
    for m in sorted(by_month):
        y, mo = m.split("-")
        rows.append(f"| {MONTHS[int(mo) - 1]} {y} | {len(by_month[m])} | {', '.join('`' + d + '`' for d in by_month[m])} |")
    return "\n".join(rows)


# --------------------------------------------------------------------------- compose
SCALES_MD = """| Reliability | Meaning | | Credibility | Meaning |
|:-:|:------------------|-|:-:|:------------------|
| A | Completely reliable | | 1 | Confirmed by other sources |
| B | Usually reliable | | 2 | Probably true |
| C | Fairly reliable | | 3 | Possibly true |
| D | Not usually reliable | | 4 | Doubtful |
| E | Unreliable | | 5 | Improbable |
| F | Reliability cannot be judged | | 6 | Truth cannot be judged |

Probability words follow ICD-203: *almost no chance* (01–05%), *very unlikely* (05–20), *unlikely*
(20–45), *roughly even chance* (45–55), *likely* (55–80), *very likely* (80–95), *almost certain*
(95–99%). Confidence (low / moderate / high) describes the strength of the evidence; a probability
word describes the event. We never combine the two in one clause."""

METHOD_MD = """Collection followed standard open-source tradecraft against public source classes only:
registration records (WHOIS, current and historic, and reverse lookups by registrant field),
DNS and passive DNS / IP history, certificate transparency, public web-scan data, the web archive,
the live page as served to an ordinary visitor, and leak / paste corpora for the registrant
selectors. Every artifact was tested against the false-positive controls before it could bind two
domains: shared or reseller hosting, managed-provider nameservers, commodity site templates and
saturated favicons are recorded as information, never as operator links; a registrant name counts
only where it co-occurs with the registrant e-mail or phone. Same-operator links are tagged with the
rung of the pivot ladder they rest on (1 = registrant record … 10 = shared provider)."""


_HANDLING_RE = re.compile(r"[^.]*\b(internal-only|must be masked|shareable export|handling note)[^.]*\.\s*", re.I)


def _strip_handling_notes(text: str) -> str:
    """Analyst handling instructions belong to the case file, not to the printed decision statement."""
    return _HANDLING_RE.sub("", text or "").strip()


def related_personas_md(mo: dict, masked: bool = False) -> str:
    """'Related personas on the same infrastructure' — the MO-neighbour deliverable, placed under
    Alternative analysis because that is what it is: the syndicate-vs-campaign question, unresolved.

    In clear by default (analyst decision): the persona identities are in _KEEP, so mask_third_parties
    leaves them; every other third-party value on the page is still masked. `masked=True`
    (--mask-personas) renders the aggregated form — one row per persona, identity replaced by an
    ordinal, domains and dates kept. Either way the rung-10 caveat is on the table, not in a footnote:
    the only link is a shared provider + the same registration play. Never estate membership."""
    L = ["## Related personas on the same infrastructure", ""]
    personas = mo.get("related_personas") or []
    est = mo.get("estate") or {}
    n_orig = len(mo.get("origins") or [])
    L += [f"**Candidate, single-indicator (rung 10).** {len(personas)} other registrant persona(s) run "
          f"domains from the estate's origin address(es) ({n_orig} origin(s) reversed) with the same "
          f"registration play — same registrar, created inside the estate's window"
          + (f" ({est['created_window'][0]} → {est['created_window'][1]})" if (est.get("created_window") or [None])[0] else "")
          + ", and either the estate's own naming tokens or a throwaway-handle mailbox. The only hard link is "
          "a shared provider: these are co-tenants who work the same way, NOT members of the estate. "
          "They never seeded collection, never joined a cluster, and carry no operator label in the "
          "knowledge base. Whether this is one syndicate or several look-alike campaigns is an open "
          "question the evidence here does not settle.", ""]
    if personas:
        L += ["| # | Persona | Domains | Registrar | Created span | Shared origin | Signals |",
              "|--:|:--------|:--------|:----------|:-------------|:--------------|:--------|"]
        for i, p in enumerate(personas, 1):
            ident = f"persona {i}" if masked else _md_escape(scrub(str(p.get("persona") or "?")))
            doms = ", ".join(_md_escape(d) for d in (p.get("domains") or [])[:6])
            if len(p.get("domains") or []) > 6:
                doms += f" (+{len(p['domains']) - 6})"
            span = p.get("created_span") or []
            span_s = (span[0] if span else "?") + (f" → {span[1]}" if len(span) == 2 and span[1] != span[0] else "")
            L.append(f"| {i} | {ident} | {doms} | {_md_escape(scrub(str(p.get('registrar') or '?')))} | {span_s} | "
                     f"{', '.join(p.get('origin_ips') or [])} | {_md_escape('; '.join(p.get('signals') or []))} |")
        L.append("")
    counts = (f"Also on those origins: {mo.get('unrelated_count', 0)} co-tenant(s) with an unrelated registration "
              f"profile (not enumerated) and {mo.get('unverifiable_count', 0)} whose registration could not be read"
              + (f"; {mo['unverified_count']} further co-tenant(s) were seen but not yet verified (verification cap)"
                 if mo.get("unverified_count") else "") + ".")
    L += [counts, ""]
    for b in mo.get("bulk_origins") or []:
        L.append(f"- Origin {b.get('origin_ip')} answers with ~{b.get('fan_out')} apexes — bulk hosting; its "
                 "co-tenants were not classified (a shared-hosting customer base is not a neighbourhood).")
    if mo.get("bulk_origins"):
        L.append("")
    return "\n".join(L).rstrip()


def compose(c: dict, figs: dict, classification: str, observed: str) -> str:
    a = c["assessment"]
    secs = split_sections(c["analyst_md"]) if c["analyst_md"] else {}
    case = c["case"]
    seed = c["seed"]
    brand = c["scope"].get("brand") or ""
    title = secs.get("_title") or a.get("bluf", "")[:90] or f"Assessment — {seed}"
    title = re.sub(r"^Analyst Assessment \(ICD-203\)\s*[—-]\s*", "", title)

    purpose = _strip_handling_notes(a.get("decision_supported") or "")
    purpose = scrub(purpose or
                    f"This report assesses whether {seed} and its related domains are operated by a single party, to support an abuse referral and blocklisting decision.")
    bluf = scrub(a.get("bluf") or find_section(secs, "bluf"))
    judgments = parse_judgments(find_section(secs, "key judgment"))
    conf = a.get("confidence", "—")
    attribution = a.get("attribution_level", "—")

    L = []
    L += ["---", f'title: "{title[:140].replace(chr(34), chr(39))}"', f"case_id: {case}",
          f"classification: {classification}", f"date: {observed}", "---", ""]

    # I — Executive summary
    L += ["# Executive Summary — Key Judgments", "", f"*{purpose}*", ""]
    L += ["| # | Key judgment | Confidence | Grade |", "|:-:|:----------------------------|:--------|:--:|"]
    if judgments:
        for i, j in enumerate(judgments, 1):
            L.append(f"| {i} | {_md_escape(j['title'])} | {_md_escape(j['confidence'] or conf)} | {j['grade'] or '—'} |")
    else:
        L.append(f"| 1 | {_md_escape(attribution)} | {conf} | — |")
    L += ["", f"> **Bottom line.** {bluf}", ""]
    L += [f"- **Attribution:** {_md_escape(attribution)}", f"- **Confidence:** {conf}"]
    if a.get("premise_verdict"):
        L.append(f"- **Stated premise:** {_md_escape(scrub(a.get('premise', '')))} — verdict **{a['premise_verdict']}**")
    if brand:
        L.append(f"- **Impersonated brand:** {brand}")
    L.append("")

    # II — Methodology
    L += ["# Methodology", "", "## Approach", "", METHOD_MD, "",
          f"Findings are graded for the decision stated above: an *assessed* same-operator link is actionable; "
          f"a named individual is not asserted below *high confidence*. Current confidence: **{conf}**.", "",
          "## Confidence scales used", "", SCALES_MD, ""]
    charts = figs.get("charts") or {}
    if hrg.confidence_md(charts, observed):
        L += ["The case's own judgments, placed on both scales:", "", hrg.confidence_md(charts, observed), ""]

    # III — Scope and seed
    L += ["# Scope and the seed", ""]
    L += ["| Field | Value |", "|:------|:----------------------------|",
          f"| Seed | `{seed}` |", f"| Impersonated brand | {_md_escape(brand or '—')} |",
          f"| Target class | {_md_escape(c['scope'].get('target_class') or '—')} |",
          f"| Purpose | {_md_escape(c['scope'].get('purpose') or '—')} |",
          f"| Claim under test | {_md_escape(scrub(c['scope'].get('claim') or a.get('premise') or '—'))} |",
          f"| Observed | {observed} |", ""]
    w = c["whois"].get(seed, {})
    if w:
        L += [f"`{seed}` was registered {(w.get('created') or '—')[:10]} through {w.get('registrar') or 'an undisclosed registrar'}; "
              f"registrant record: {' / '.join(x for x in (w.get('registrant_name'), w.get('registrant_email'), w.get('registrant_phone')) if x) or 'privacy-redacted'}; "
              f"nameservers {', '.join((w.get('name_servers') or [])[:2]) or '—'}.", ""]

    # IV — Findings (analyst narrative, scrubbed)
    L += ["# Findings", ""]
    if judgments:
        for i, j in enumerate(judgments, 1):
            L += [f"## {j['title']}", "", j["body"], ""]
    else:
        for e in a.get("evidence") or []:
            L.append(f"- {scrub(e if isinstance(e, str) else json.dumps(e, ensure_ascii=False))}")
        L.append("")

    # V — The cluster
    L += ["# The cluster", ""]
    n = sum(k.get("size", 0) for k in (c["clusters"].get("clusters") or []) if not k.get("singleton"))
    L += [f"The same-operator partition over the collected hosts yields **{c['clusters'].get('n_clusters', '—')} component(s)**; "
          f"the operator cluster holds **{n} domains**. The relationship graph below keeps only edges that survived the "
          f"false-positive controls; managed nameservers, registrar and template edges are dropped as noise.", ""]
    if figs.get("relationship"):
        cap = (f"The estate by impersonated sector — one registrant record (e-mail + phone) over {n} domains; "
               f"the seed is highlighted. Sector is assigned from the domain label. Observed {observed}."
               if figs.get("relationship_kind") == "sector" else
               f"Relationship graph — {n} domains, one origin; edges are same-operator (registrant record) and shared-infrastructure links. Observed {observed}.")
        L += [f"![{cap}]({os.path.basename(figs['relationship'])})", ""]
    if figs.get("legend"):
        L += [f"![Legend — edge classes.]({os.path.basename(figs['legend'])})", ""]
    if hrg.entity_map_md(charts, observed):
        L += [hrg.entity_map_md(charts, observed), ""]
    waves = registration_waves(c)
    if waves:
        L += ["## Registration waves", "", waves, ""]
    eras = hrx.registrant_eras_md(figs.get("timeline_events") or {}, _md_escape,
                                  is_privacy=_is_privacy, whois=c.get("whois") or {})
    if eras:
        # Previous registrants are third parties under the output rule; the operator's own join-key
        # identities survive the mask via _KEEP (>= 2-host registrant fields), prior owners do not.
        L += ["## Registrant eras", "", mask_third_parties(eras), ""]
    if figs.get("captures") or figs.get("captures_skipped"):
        L += [hrc.landing_pages_md(figs.get("captures") or {}, figs.get("capture_hosts") or c["hosts"], seed,
                                   figs.get("captures_skipped") or [], figs.get("rep_dir") or c["dir"],
                                   _sector, _md_escape,
                                   created_of=lambda h: era_start_of(c, figs, h)), ""]

    # VI — Infrastructure lifecycle
    L += ["# Infrastructure and lifecycle", ""]
    if figs.get("timeline"):
        L += [f"![Temporal view — registrations, hosting windows and certificate validity per domain. Observed {observed}.]({os.path.basename(figs['timeline'])})", ""]
    if hrg.heatmaps_md(charts, observed):
        L += [hrg.heatmaps_md(charts, observed), ""]
    if charts and hrg.missing_md(charts):
        L += [hrg.missing_md(charts), ""]
    corr, dated_ledger = condense_timeline_ledger(figs.get("timeline_md", ""), figs.get("timeline_events"))
    if corr:
        L += ["## Temporal correlations", "", corr, ""]
    excluded = find_section(secs, "excluded")
    if excluded:
        L += ["## Tested and excluded (false-positive control)", "", demote_headings(scrub(excluded)), ""]

    # VII — Attribution
    L += ["# Attribution", ""]
    if figs.get("attribution"):
        L += [f"![The inference chain. Solid lines are the evidence relied on; the dashed box is what was tested and excluded. Observed {observed}.]({os.path.basename(figs['attribution'])})", ""]
    L += ["## The operator", ""]
    mine = [o for o in c["operators"] if o.get("case") == case] or c["operators"][:1]
    if mine:
        o = max(mine, key=lambda r: len(r.get("domains") or []))
        L += [f"The estate is recorded against one registrant persona, **{_md_escape(o.get('operator'))}** — "
              f"{len(o.get('domains') or [])} domains, attribution *{o.get('confidence', '—')}*. The persona is the "
              f"WHOIS registrant record (e-mail, name, phone); it is not a verified real-world identity.", ""]
    confs = find_section(secs, "confidence")
    if confs:
        L += [demote_headings(scrub(confs)), ""]

    # VIII — Alternative analysis
    L += ["# Alternative analysis", ""]
    alts = a.get("alternatives") or []
    if alts:
        L += ["| Alternative explanation | Status | Why |", "|:----------------------|:------|:------------------------|"]
        for alt in alts:
            s = alt if isinstance(alt, str) else f"{alt.get('hypothesis','')} — {alt.get('status','').upper()}: {alt.get('why','')}"
            m = re.match(r"(.+?)\s+—\s+([A-Z][A-Z0-9 ]+?):\s*(.*)", s)
            if m:
                L.append(f"| {_md_escape(scrub(m.group(1)))} | **{m.group(2).strip().lower()}** | {_md_escape(scrub(m.group(3)))} |")
            else:
                L.append(f"| {_md_escape(scrub(s))} | | |")
        L.append("")
    else:
        L += ["_No alternative hypotheses recorded._", ""]
    mo = c.get("mo_neighbours") or {}
    if mo.get("related_personas") or mo.get("bulk_origins"):
        L += [related_personas_md(mo, masked=bool(c.get("mask_personas"))), ""]

    # IX — Gaps
    L += ["# Gaps and limitations", ""]
    gaps = [g for g in (a.get("gaps") or []) if isinstance(g, str)]
    gaps_md = find_section(secs, "collection gap")
    if gaps_md:
        L += [demote_headings(scrub(gaps_md)), ""]
    elif gaps:
        L += [f"- {scrub(g)}" for g in gaps] + [""]
    else:
        L += ["_None recorded._", ""]

    # X — Recommendations
    L += ["# Recommendations", ""]
    rec = find_section(secs, "recommendation")
    if rec:
        L += [demote_headings(scrub(rec)), ""]
    nxt = [x for x in (a.get("next_pivots") or []) if isinstance(x, str)]
    if nxt:
        L += ["## Next pivots", ""] + [f"- {scrub(x)}" for x in nxt] + [""]

    # Appendices
    L += ["\\appendix", "", "# Artifact register", "", artifact_register(c), "",
          "# Evidence ledger", "", evidence_ledger(c), ""]
    if dated_ledger:
        L += ["## Dated observations", "", dated_ledger, ""]
    caps = hrc.captures_ledger_md(figs.get("captures") or {},
                                  created_of=lambda h: era_start_of(c, figs, h))
    if caps:
        L += ["## Captured pages", "", caps, ""]
    L += [
          "# Domain and infrastructure profiles", "", domain_profiles(c), "",
          "# Cluster enumeration", "", cluster_enumeration(c), ""]
    body = "\n".join(L)
    return body + "\n# Glossary\n\n" + hrd.glossary_md(body) + "\n"


# --------------------------------------------------------------------------- main
def cluster_hosts(c: dict) -> list:
    """Seed first, then every non-singleton cluster member — the hosts whose landing pages the report shows."""
    members = {d for k in (c["clusters"].get("clusters") or []) if not k.get("singleton")
               for d in (k.get("domains") or []) if "." in d}
    members = members or set(c["hosts"])
    members.add(c["seed"])
    return [c["seed"]] + sorted(members - {c["seed"]})


def build(case_arg: str, stem: str | None, classification: str, audience: str,
          no_figures: bool, md_only: bool, screenshots: bool = True,
          max_screenshots: int = 40, screenshot_timeout: int = 30, archives: bool = True,
          mask_personas: bool = False) -> dict:
    case_dir = _case_dir(case_arg)
    if not os.path.isdir(case_dir):
        sys.exit(f"case dir not found: {case_dir}")
    os.environ.setdefault("WP_CASE_DIR", case_dir)      # per-case memos (ipinfo etc.) span rebuilds
    c = load_case(case_dir, mask_personas=mask_personas)
    classification = classification or case_classification(case_dir) or "TLP:AMBER"
    rep_dir = os.path.join(case_dir, "report")
    os.makedirs(rep_dir, exist_ok=True)
    observed = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d")
    stem = stem or f"CTI-REPORT-{c['case']}-{observed}"

    figs = {}
    if no_figures:
        # reuse whatever an earlier run left in report/ — never regenerate
        for key, stem_ in (("relationship", "estate_sectors"), ("attribution", "attribution_chain"),
                           ("timeline", "timeline")):
            for cand in (stem_ + "_report.png", stem_ + "_hires.png", stem_ + ".png"):
                if os.path.exists(os.path.join(rep_dir, cand)):
                    figs[key] = os.path.join(rep_dir, cand)
                    if key == "relationship":
                        figs["relationship_kind"] = "sector"
                    break
        ledger = os.path.join(rep_dir, "timeline_ledger.md")
        if os.path.exists(ledger):
            figs["timeline_md"] = scrub(open(ledger, encoding="utf-8").read())
    else:
        title = c["assessment"].get("bluf", "")[:80] or c["case"]
        sec = fig_sector_graph(c, rep_dir, title)
        rel = fig_relationship(c, rep_dir, title)
        if sec:
            figs["relationship"] = sec          # the §V figure: three ranks, no community boxes
            figs["relationship_kind"] = "sector"
        elif rel:
            figs["relationship"] = rel[0]
            if len(rel) > 1:
                figs["legend"] = rel[1]
        att = fig_attribution_chain(c, rep_dir)
        if att:
            figs["attribution"] = att
        tl, tl_md = fig_timeline(c, rep_dir, observed)
        if tl:
            figs["timeline"] = tl
        if tl_md:
            figs["timeline_md"] = tl_md
    ev = os.path.join(rep_dir, "timeline_events.json")
    if os.path.exists(ev):
        figs["timeline_events"] = _load_json(ev, {}) or {}

    # Landing-page captures (Rule 15a): reuse what the case holds; capture the rest through the egress policy.
    hosts = cluster_hosts(c)
    existing = hrc.existing_screenshots(case_dir)
    skipped: list = []
    if screenshots and not no_figures:
        new, skipped = hrc.capture_missing(case_dir, hosts, existing, max_hosts=max_screenshots,
                                           timeout=screenshot_timeout, archives=archives,
                                           created_of=lambda h: era_start_of(c, figs, h))
        existing.update(new)
        for h, why in skipped:
            sys.stderr.write(f"landing page not captured: {h} — {why}\n")
    figs["captures"] = {h: existing[h] for h in hosts if h in existing}
    figs["captures_skipped"] = skipped
    figs["capture_hosts"] = hosts
    figs["rep_dir"] = rep_dir
    # Analytic charts shared with the dashboard (confidence scatter, heatmaps, entity map).
    if not no_figures:
        figs["charts"] = hrg.build_figures(case_dir, rep_dir)
        for k, why in (figs["charts"].get("_notes") or {}).items():
            sys.stderr.write(f"analytic figure {k}: {why}\n")
    else:
        figs["charts"] = {n: (os.path.join(rep_dir, n + ".png") if os.path.exists(os.path.join(rep_dir, n + ".png")) else None)
                          for n in hrg.FIGURES}

    md = compose(c, figs, classification, observed)
    md = normalize_dashes(md)
    md_path = os.path.join(rep_dir, stem + ".md")
    open(md_path, "w", encoding="utf-8").write(md)
    out = {"markdown": md_path, **{k: v for k, v in figs.items() if k not in ("timeline_md", "timeline_events", "captures", "captures_skipped", "capture_hosts", "rep_dir", "charts")},
           "landing_pages": f"{len(figs['captures'])}/{len(hosts)} captured"
           + (f" ({sum(1 for e in figs['captures'].values() if (e.get('source') or 'live') != 'live')} from archives)" if figs["captures"] else ""),
           "analytic_charts": ", ".join(n for n in hrg.FIGURES if figs["charts"].get(n)) or "none"}
    if md_only:
        return out
    cmd = [PY, RENDER_REPORT, md_path, os.path.join(rep_dir, stem), "--case-id", c["case"],
           "--classification", classification, "--audience", audience, "--pdf", "--docx"]
    if no_figures:
        cmd.append("--no-figures")
    r = _run(cmd, timeout=600)
    for ext in ("pdf", "docx"):
        p = os.path.join(rep_dir, f"{stem}.{ext}")
        if os.path.exists(p):
            out[ext] = p
    if r.returncode != 0 or "pdf" not in out:
        out["render_error"] = (r.stderr or r.stdout or "").strip()[-1200:]
    return out


def main():
    ap = argparse.ArgumentParser(description="case dir -> IntelReport house-style PDF + DOCX (deterministic)")
    ap.add_argument("case", help="case id under cases/ or a case dir path")
    ap.add_argument("--stem", help="output filename stem (default CTI-REPORT-<case>-<date>)")
    ap.add_argument("--classification", default=None,
                    help="handling caveat (default: the case's TLP from assessment.md / assessment.json / scope.json, else TLP:AMBER)")
    ap.add_argument("--audience", default="technical", choices=["technical", "executive", "le"])
    ap.add_argument("--no-figures", action="store_true", help="skip figure generation")
    ap.add_argument("--md-only", action="store_true", help="compose the markdown only; do not render")
    ap.add_argument("--no-screenshots", action="store_true",
                    help="do not capture missing landing pages (existing captures under the case are still embedded)")
    ap.add_argument("--max-screenshots", type=int, default=40, help="cap on hosts to capture in one build")
    ap.add_argument("--screenshot-timeout", type=int, default=30, help="per-page navigation timeout, seconds")
    ap.add_argument("--no-archive-fallback", action="store_true",
                    help="when a live page will not render, do NOT fall back to a public web-scan / web-archive copy")
    ap.add_argument("--mask-personas", action="store_true",
                    help="render the MO-neighbour 'Related personas' table in aggregated/masked form "
                         "(default: verified persona identities in clear with the rung-10 caveat)")
    a = ap.parse_args()
    out = build(a.case, a.stem, a.classification, a.audience, a.no_figures, a.md_only,
                screenshots=not a.no_screenshots, max_screenshots=a.max_screenshots,
                screenshot_timeout=a.screenshot_timeout, archives=not a.no_archive_fallback,
                mask_personas=a.mask_personas)
    for k, v in out.items():
        print(f"  {k:14s} {v if k != 'render_error' else chr(10) + v}")
    sys.exit(1 if "render_error" in out else 0)


if __name__ == "__main__":
    main()
