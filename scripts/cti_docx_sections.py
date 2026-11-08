"""
CTI Report Sections — builds each report section into the DOCX document.
"""
from docx import Document
from docx.shared import Pt, Inches, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml.ns import nsdecls
from docx.oxml import parse_xml

from cti_docx_styles import COLORS, SEVERITY_COLORS, set_cell_shading, SHADE_BAND
import cti_report_sections as RS

# Map string confidence levels to numeric percentages
CONFIDENCE_MAP = {
    "VERIFIED": 95, "STRONG": 80, "MODERATE": 60,
    "WEAK": 35, "TENTATIVE": 20, "CHALLENGED": 10,
}


def _normalize_confidence(val) -> int:
    """Convert confidence to integer. Handles int, string percent, or named level."""
    if isinstance(val, (int, float)):
        return int(val)
    if isinstance(val, str):
        cleaned = val.strip().rstrip("%").upper()
        if cleaned in CONFIDENCE_MAP:
            return CONFIDENCE_MAP[cleaned]
        try:
            return int(cleaned)
        except ValueError:
            return 0
    return 0


def add_executive_summary(doc: Document, data: dict) -> None:
    """Add executive summary section."""
    doc.add_heading("Executive Summary", level=1)
    summary = data.get("executive_summary", "")
    if summary:
        p = doc.add_paragraph(summary)
        p.paragraph_format.space_after = Pt(12)



def add_subject_profile(doc: Document, data: dict) -> None:
    """Add subject profile table."""
    subjects = data.get("subjects", [])
    if not subjects:
        return

    doc.add_heading("Subject Profile", level=1)

    for s in subjects[:10]:  # Limit to first 10
        # Support both 'label' (DOCX format) and 'value'/'display_name' (engine format)
        label = s.get("label") or s.get("display_name") or s.get("value") or "Unknown"
        stype = s.get("type", "N/A")
        doc.add_heading(f"{label} ({stype})", level=2)

        conf = _normalize_confidence(s.get("confidence", 0))
        fields = [
            ("Type", stype),
            ("Confidence", f"{conf}%"),
            ("Verified", "Yes" if s.get("verified") else "No"),
            ("Aliases", ", ".join(s.get("aliases", [])) or "None"),
            ("First Seen", s.get("first_seen") or s.get("first_observed") or "N/A"),
            ("Notes", s.get("notes", "")),
        ]

        table = doc.add_table(rows=len(fields), cols=2)
        table.style = "Table Grid"

        for i, (label, value) in enumerate(fields):
            row = table.rows[i]
            # Label cell
            cell_l = row.cells[0]
            run = cell_l.paragraphs[0].add_run(label)
            run.font.bold = True
            run.font.size = Pt(10)
            run.font.color.rgb = COLORS["primary"]
            set_cell_shading(cell_l, SHADE_BAND)

            # Value cell
            cell_r = row.cells[1]
            run = cell_r.paragraphs[0].add_run(str(value))
            run.font.size = Pt(10)

        doc.add_paragraph()  # Spacing


def add_findings_section(doc: Document, data: dict) -> None:
    """Add findings section with styled cards."""
    findings = data.get("findings", [])
    if not findings:
        return

    doc.add_heading("Key Findings", level=1)

    for i, f in enumerate(findings, 1):
        weight = f.get("weight", f.get("severity", "INFO")).upper()
        color = SEVERITY_COLORS.get(weight, COLORS["info"])

        # Finding heading with severity badge
        ftype = f.get("type", "N/A")
        ftitle = f.get("title") or ftype.title()
        h = doc.add_heading(level=2)
        run = h.add_run(f"[{weight}] ")
        run.font.color.rgb = color
        run.font.size = Pt(13)
        run = h.add_run(f"Finding {i}: {ftitle}")
        run.font.size = Pt(13)

        conf = _normalize_confidence(f.get("confidence", 0))
        desc = f.get("description") or f.get("content") or ""
        source = f.get("source_url") or f.get("source") or "N/A"
        collected = f.get("collected_at") or f.get("recorded_at") or "N/A"

        # Finding details table
        details = [
            ("ID", f.get("id", f"FND-{i:03d}")),
            ("Type", ftype),
            ("Severity", weight),
            ("Confidence", f"{conf}%"),
            ("Description", desc),
            ("Source", source),
            ("Collected", collected),
        ]
        if f.get("confirmation"):
            details.append(("Confirmation", str(f["confirmation"]).replace("_", " ")))
        if f.get("not_proven"):
            details.append(("Not proven", f["not_proven"]))

        table = doc.add_table(rows=len(details), cols=2)
        table.style = "Table Grid"

        for j, (label, value) in enumerate(details):
            row = table.rows[j]
            cell_l = row.cells[0]
            run = cell_l.paragraphs[0].add_run(label)
            run.font.bold = True
            run.font.size = Pt(9)
            set_cell_shading(cell_l, SHADE_BAND)

            cell_r = row.cells[1]
            run = cell_r.paragraphs[0].add_run(str(value))
            run.font.size = Pt(9)
            if label == "Severity":
                run.font.color.rgb = color
                run.font.bold = True

        # Tags
        tags = f.get("tags", [])
        if tags:
            p = doc.add_paragraph()
            run = p.add_run("Tags: ")
            run.font.bold = True
            run.font.size = Pt(9)
            run.font.color.rgb = COLORS["muted"]
            run = p.add_run(", ".join(tags))
            run.font.size = Pt(9)
            run.font.color.rgb = COLORS["muted"]

        doc.add_paragraph()  # Spacing


def add_connections_section(doc: Document, data: dict) -> None:
    """Add connections table."""
    connections = data.get("connections", [])
    if not connections:
        return

    doc.add_heading("Connections & Relationships", level=1)

    table = doc.add_table(rows=1, cols=4)
    table.style = "Table Grid"

    # Header row
    headers = ["From", "Relationship", "To", "Strength"]
    for i, h in enumerate(headers):
        cell = table.rows[0].cells[i]
        run = cell.paragraphs[0].add_run(h)
        run.font.bold = True
        run.font.size = Pt(9)
        run.font.color.rgb = COLORS["text"]   # dark ink on light header band
        set_cell_shading(cell, SHADE_BAND)

    # Data rows
    for c in connections:
        row = table.add_row()
        values = [
            c.get("from_id") or c.get("from", ""),
            c.get("relationship") or c.get("type", ""),
            c.get("to_id") or c.get("to", ""),
            c.get("strength") or c.get("confidence", ""),
        ]
        for i, v in enumerate(values):
            run = row.cells[i].paragraphs[0].add_run(str(v))
            run.font.size = Pt(9)


def add_source_list(doc: Document, data: dict) -> None:
    """Add source/citation table."""
    sources = data.get("sources", [])
    if not sources:
        return

    doc.add_heading("Sources", level=1)

    table = doc.add_table(rows=1, cols=4)
    table.style = "Table Grid"

    headers = ["#", "Source", "URL", "Date Accessed"]
    for i, h in enumerate(headers):
        cell = table.rows[0].cells[i]
        run = cell.paragraphs[0].add_run(h)
        run.font.bold = True
        run.font.size = Pt(9)
        run.font.color.rgb = COLORS["text"]   # dark ink on light header band
        set_cell_shading(cell, SHADE_BAND)

    for j, src in enumerate(sources, 1):
        row = table.add_row()
        values = [
            str(j),
            src.get("name", ""),
            src.get("url", ""),
            src.get("date", ""),
        ]
        for i, v in enumerate(values):
            run = row.cells[i].paragraphs[0].add_run(v)
            run.font.size = Pt(8)


def _table(doc: Document, headers, rows, size=8) -> None:
    """Header-banded grid table of plain strings (same look as the connections table)."""
    table = doc.add_table(rows=1, cols=len(headers))
    try:
        table.style = "Table Grid"
    except KeyError:      # a pandoc-built document (hybrid) may not define it
        pass
    for i, h in enumerate(headers):
        cell = table.rows[0].cells[i]
        run = cell.paragraphs[0].add_run(h)
        run.font.bold = True
        run.font.size = Pt(size + 1)
        run.font.color.rgb = COLORS["text"]   # dark ink on light header band
        set_cell_shading(cell, SHADE_BAND)
    for values in rows:
        row = table.add_row()
        for i, v in enumerate(values):
            run = row.cells[i].paragraphs[0].add_run(str(v))
            run.font.size = Pt(size)


def _heading(doc: Document, text: str, level: int):
    """doc.add_heading that also works on a pandoc-built document, whose heading styles are not
    reachable by name (KeyError) but are by iteration (see cti_docx_postprocess.apply_cti_styles)."""
    try:
        return doc.add_heading(text, level=level)
    except KeyError:
        style = next((s for s in doc.styles if (s.name or "") == f"Heading {level}"), None)
        p = doc.add_paragraph(text)
        if style is not None:
            p.style = style
        return p


def _note(doc: Document, text: str) -> None:
    p = doc.add_paragraph()
    run = p.add_run(text)
    run.font.size = Pt(9)
    run.font.italic = True
    run.font.color.rgb = COLORS["muted"]


def add_house_section(doc: Document, data: dict, key: str, note: str = "") -> bool:
    """One analyst report-block section (cti_report_sections.SECTIONS) as a table; False when absent."""
    rows = RS.rows(data, key)
    if not rows:
        return False
    title, cols = RS.SECTION[key]
    _heading(doc, title, 1)
    if note:
        _note(doc, note)
    _table(doc, [h for _, h in cols], [[RS.cell(r, f) for f, _ in cols] for r in rows])
    doc.add_paragraph()
    return True


def add_key_questions(doc: Document, data: dict) -> None:
    """Key Questions — placed right after the executive summary."""
    add_house_section(doc, data, "key_questions")


def _bullets(doc: Document, items) -> None:
    for w in items:
        try:
            p = doc.add_paragraph(style="List Bullet")
        except KeyError:
            p = doc.add_paragraph("• ")
        run = p.add_run(w)
        run.font.size = Pt(9)
        run.font.color.rgb = COLORS["muted"]


def add_engagement(doc: Document, data: dict) -> bool:
    """Document control (engagement author · version · created · modified · hours) — front matter."""
    items = RS.engagement_items(data)
    if not items:
        return False
    _heading(doc, "Document Control", 1)
    _table(doc, [label for label, _ in items], [[value for _, value in items]], size=9)
    doc.add_paragraph()
    return True


def add_identity_cards(doc: Document, data: dict) -> bool:
    """Subject identity card — one table per entity, fixed field order, empty fields omitted."""
    cards = RS.identity_cards(data)
    if not cards:
        return False
    _heading(doc, "Subject Identity Card", 1)
    _note(doc, RS.IDENTITY_NOTE)
    for entity, rows in cards:
        _heading(doc, entity, 2)
        _table(doc, [h for _, h in RS.IDENTITY_COLS], [[RS.cell(r, f) for f, _ in RS.IDENTITY_COLS] for r in rows])
        doc.add_paragraph()
    return True


def add_client_seeds(doc: Document, data: dict) -> bool:
    """Client-provided details (intake seeds; sensitive values withheld unless --show-sensitive)."""
    return add_house_section(doc, data, "client_seeds", RS.CLIENT_NOTE)


def add_qa_warnings(doc: Document, data: dict) -> bool:
    """Appendix — QA warnings from report_sections.lint."""
    warns = [w for w in data.get("qa_warnings") or [] if w]
    if not warns:
        return False
    _heading(doc, RS.SECTION["qa_warnings"][0], 1)
    _note(doc, RS.QA_NOTE)
    _bullets(doc, warns)
    return True


def add_counting_rules(doc: Document, data: dict) -> None:
    """Counting rules + any anti-inflation warnings (validate_metrics) — after the methodology."""
    warns = [w for w in data.get("metric_warnings") or [] if w]
    if not add_house_section(doc, data, "counting_rules", RS.COUNTING_NOTE) and not warns:
        return
    if warns and not RS.rows(data, "counting_rules"):
        _heading(doc, RS.SECTION["counting_rules"][0], 1)
    if warns:
        _heading(doc, "Metric warnings", 2)
        _bullets(doc, warns)


def add_analysis_sections(doc: Document, data: dict) -> None:
    """Roles, Incident timeline, ATT&CK mapping, Scenarios — in house-report order."""
    add_house_section(doc, data, "roles", RS.ROLES_NOTE)
    add_house_section(doc, data, "incident_timeline")
    add_house_section(doc, data, "attack_mapping")
    add_house_section(doc, data, "scenarios")


def add_sources_checked(doc: Document, data: dict) -> None:
    """Appendix — QA warnings, then every source queried (zero-hit rows included)."""
    add_qa_warnings(doc, data)
    add_house_section(doc, data, "sources_checked", RS.SOURCES_CHECKED_NOTE)


def _heading_key(text: str) -> str:
    return "".join(ch for ch in str(text).lower() if ch.isalpha())


# (heading phrase a Markdown body — house_report / hand-authored — uses, section key, renderer).
# House order; the hybrid appends a section only when the body lacks its heading.
def _has_counting(data):
    return bool(RS.rows(data, "counting_rules") or data.get("metric_warnings"))


_HOUSE_PARTS = [
    ("documentcontrol", "engagement", add_engagement),
    ("keyquestions", "key_questions", lambda d, x: add_house_section(d, x, "key_questions")),
    ("identitycard", "subject_profile", add_identity_cards),
    ("clientprovided", "client_seeds", add_client_seeds),
    ("countingrules", "counting_rules", lambda d, x: (add_counting_rules(d, x), _has_counting(x))[1]),
    ("roles", "roles", lambda d, x: add_house_section(d, x, "roles", RS.ROLES_NOTE)),
    ("incidenttimeline", "incident_timeline", lambda d, x: add_house_section(d, x, "incident_timeline")),
    ("attck", "attack_mapping", lambda d, x: add_house_section(d, x, "attack_mapping")),
    ("scenarios", "scenarios", lambda d, x: add_house_section(d, x, "scenarios")),
    ("recommendations", "roadmap", lambda d, x: bool(RS.roadmap_groups(x)) and (add_recommendations(d, x) or True)),
    ("openquestions", "open_questions", lambda d, x: add_house_section(d, x, "open_questions")),
    ("qawarnings", "qa_warnings", add_qa_warnings),
    ("sourceschecked", "sources_checked",
     lambda d, x: add_house_section(d, x, "sources_checked", RS.SOURCES_CHECKED_NOTE)),
]


def add_missing_house_sections(doc: Document, data: dict) -> list:
    """Hybrid (Markdown-bodied) report: append, in house order, every report-block section whose
    heading the Markdown body does not already carry. Returns the keys appended."""
    present = [_heading_key(p.text) for p in doc.paragraphs
               if (p.style is not None and str(p.style.name).lower().startswith("heading"))]
    added = []
    for phrase, key, render in _HOUSE_PARTS:
        if any(phrase in h for h in present):
            continue
        if render(doc, data):
            added.append(key)
    return added


def add_intelligence_gaps(doc: Document, data: dict) -> None:
    """Open Questions table when structured rows exist; otherwise the flat gap bullets."""
    if add_house_section(doc, data, "open_questions"):
        return
    gaps = data.get("intelligence_gaps", [])
    if not gaps:
        return

    doc.add_heading("Intelligence Gaps", level=1)
    for gap in gaps:
        p = doc.add_paragraph(style="List Bullet")
        run = p.add_run(gap)
        run.font.size = Pt(10)


def add_recommendations(doc: Document, data: dict) -> None:
    """Recommendations grouped P1/P2/P3 when a roadmap exists; otherwise the numbered list."""
    groups = RS.roadmap_groups(data)
    if groups:
        title, cols = RS.SECTION["roadmap"]
        _heading(doc, title, 1)
        for heading, rows in groups:
            _heading(doc, heading, 2)
            _table(doc, [h for _, h in cols], [[RS.cell(r, f) for f, _ in cols] for r in rows])
            doc.add_paragraph()
        return
    recs = data.get("recommendations", [])
    if not recs:
        return

    doc.add_heading("Recommended Next Steps", level=1)
    for i, rec in enumerate(recs, 1):
        # Handle both string and object formats
        if isinstance(rec, dict):
            text = rec.get("action") or rec.get("description") or rec.get("text") or str(rec)
        else:
            text = str(rec)
        p = doc.add_paragraph(style="List Number")
        run = p.add_run(text)
        run.font.size = Pt(10)


def add_methodology_notes(doc: Document, data: dict) -> None:
    """Add analyst caveats and methodology."""
    doc.add_heading("Analyst Caveats & Methodology", level=1)

    caveats = data.get("caveats", [
        "This report is based exclusively on publicly available information.",
        "Correlation between accounts is inferred from shared identifiers.",
        "No private data was accessed. No social engineering was employed.",
    ])

    for c in caveats:
        p = doc.add_paragraph(style="List Bullet")
        run = p.add_run(c)
        run.font.size = Pt(9)
        run.font.italic = True
        run.font.color.rgb = COLORS["muted"]


def add_generated_footer(doc: Document) -> None:
    """Closing credit line — the last thing in the body."""
    doc.add_paragraph()
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = p.add_run("Generated by CTI Expert Skill — AI-Assisted Cyber Threat Intelligence")
    run.font.size = Pt(8)
    run.font.italic = True
    run.font.color.rgb = COLORS["muted"]


