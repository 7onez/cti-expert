"""
CTI Report Sections — builds each report section into the DOCX document.
"""
import io
import sys

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
    reachable by name (KeyError) but are by iteration (see cti_docx_postprocess.apply_cti_styles).
    python-docx appends the paragraph BEFORE the style lookup fails, so that paragraph is reused —
    never a second, unstyled copy of the heading text."""
    try:
        return doc.add_heading(text, level=level)
    except KeyError:
        style = next((s for s in doc.styles if (s.name or "") == f"Heading {level}"), None)
        p = doc.paragraphs[-1] if doc.paragraphs and doc.paragraphs[-1].text == text else doc.add_paragraph(text)
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
    """One analyst report-block section (cti_report_sections.SECTIONS) as a table; False when absent.
    Rows sorted / labelled as the house report shows them; the note defaults to the section's intro."""
    rows = RS.display_rows(data, key)
    if not rows:
        return False
    title, cols = RS.SECTION[key]
    _heading(doc, title, 1)
    note = note or RS.section_note(data, key)
    if note:
        _note(doc, note)
    _table(doc, [h for _, h in cols], [[RS.cell(r, f) for f, _ in cols] for r in rows])
    doc.add_paragraph()
    return True


def add_figures(doc: Document, data: dict, group: str, names=None, base=None, figs=None) -> bool:
    """Card maps / affiliate-exposure charts in `report_figures` that pass RS.figures (contained PNG
    under the size cap; a rejected one is named on stderr), each with its caption, embedded from the
    bytes RS.figures validated (a stream — the path is never reopened). `figs` reuses an RS.figures
    result. False when none was added."""
    added = False
    for name, png, caption in (RS.figures(data, group, base) if figs is None else figs):
        if names and name not in names:
            continue
        try:
            doc.add_picture(io.BytesIO(png), width=Inches(6.0))
        except Exception as exc:  # noqa: BLE001 — an unreadable PNG never blocks the report
            print(f"  figure {name} not embedded: {exc}", file=sys.stderr)
            continue
        doc.paragraphs[-1].alignment = WD_ALIGN_PARAGRAPH.CENTER
        _note(doc, caption)
        added = True
    return added


def add_triage_exposure(doc: Document, data: dict, base=None) -> bool:
    """Stealer-log triage exposure charts under their own heading when the case has no affiliate_exposure
    rows (RS.triage_exposure). False when not applicable or no chart passes RS.figures."""
    if not RS.triage_exposure(data):
        return False
    figs = RS.figures(data, "exposure_charts", base)
    if not figs:
        return False
    _heading(doc, RS.EXPOSURE_TRIAGE_TITLE, 1)
    _note(doc, RS.EXPOSURE_TRIAGE_NOTE)
    return add_figures(doc, data, "exposure_charts", None, base, figs)


def add_risk_overall(doc: Document, data: dict) -> bool:
    """Overall risk — the score sentence and the domain table, highest score first."""
    ov = RS.risk_overall(data)
    if not ov:
        return False
    line, warning, unrated = ov
    title, cols = RS.SECTION["risk_assessment"]
    _heading(doc, title, 1)
    for text in (line, warning):
        if text:
            _note(doc, text)
    _table(doc, [h for _, h in cols], [[RS.cell(r, f) for f, _ in cols] for r in RS.display_rows(data, "risk_assessment")])
    if unrated:
        _note(doc, unrated)
    doc.add_paragraph()
    return True


def add_rating_scales(doc: Document, data: dict) -> bool:
    """Rating scales — risk bands (highest first) and the P1/P2/P3 deadlines."""
    bands, prio = RS.rating_scales(data)
    if not (bands or prio):
        return False
    _heading(doc, RS.SECTION["rating_scales"][0], 1)
    if bands:
        _table(doc, ["Risk level", "Score range"], bands)
        doc.add_paragraph()
    if prio:
        _table(doc, ["Priority", "Act within"], prio)
        doc.add_paragraph()
    return True


def add_nothing_found(doc: Document, data: dict) -> bool:
    """Checked — nothing found: the analyst's negative checks + the zero-hit sources-checked rows."""
    negatives, zero = RS.nothing_found(data)
    if not (negatives or zero):
        return False
    title, cols = RS.SECTION["negative_checks"]
    _heading(doc, title, 1)
    _note(doc, RS.NOTHING_FOUND_NOTE)
    if negatives:
        _table(doc, [h for _, h in cols], [[RS.cell(r, f) for f, _ in cols] for r in negatives])
        doc.add_paragraph()
    _bullets(doc, zero)
    return True


def add_risk_summary(doc: Document, data: dict, base=None) -> None:
    """Executive-summary block after the identity card: subject card map, Overall risk, Key findings."""
    add_figures(doc, data, "card_maps", ("person",), base)
    add_risk_overall(doc, data)
    add_house_section(doc, data, "key_findings")


def add_threat_person_findings(doc: Document, data: dict, base=None) -> None:
    """Findings block: threat card map, Affiliate exposure (+ charts; with no affiliate rows, the
    stealer-log triage charts under their own heading), Dark-web and Telegram claims,
    Services registered by e-mail, Events that raise the threat."""
    add_figures(doc, data, "card_maps", ("threats",), base)
    if add_house_section(doc, data, "affiliate_exposure"):
        add_figures(doc, data, "exposure_charts", None, base)
    else:
        add_triage_exposure(doc, data, base)
    for key in ("leak_claims", "email_services", "threat_events"):
        add_house_section(doc, data, key)


def add_actor_profile(doc: Document, data: dict) -> bool:
    """Actor Profile chapter (cti_report_sections.actor_blocks): Heading 1, one Heading 2 per block,
    in house order. False when no actor section is present."""
    blocks = RS.actor_blocks(data)
    if not blocks:
        return False
    _heading(doc, RS.ACTOR_TITLE, 1)
    for title, items in blocks:
        _heading(doc, title, 2)
        for item in items:
            if item[0] == "p":
                _note(doc, item[1])
            elif item[0] == "bullets":
                _bullets(doc, item[1])
            else:
                _table(doc, [h for _, h in item[1]], [[RS.cell(r, f) for f, _ in item[1]] for r in item[2]])
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


def add_analysis_sections(doc: Document, data: dict, base=None) -> None:
    """Roles, supplier card map, Incident timeline, ATT&CK mapping, Scenarios — in house-report order."""
    add_house_section(doc, data, "roles", RS.ROLES_NOTE)
    add_figures(doc, data, "card_maps", ("suppliers",), base)
    add_house_section(doc, data, "incident_timeline")
    add_house_section(doc, data, "attack_mapping")
    add_house_section(doc, data, "scenarios")


def add_sources_checked(doc: Document, data: dict) -> None:
    """Appendix — QA warnings, every source queried (zero-hit rows included), Checked — nothing found."""
    add_qa_warnings(doc, data)
    add_house_section(doc, data, "sources_checked", RS.SOURCES_CHECKED_NOTE)
    add_nothing_found(doc, data)


def _heading_key(text: str) -> str:
    return "".join(ch for ch in str(text).lower() if ch.isalpha())


# (phrase, section key, renderer(doc, data, base)). House order; the hybrid appends a section only when
# the Markdown body (house_report / hand-authored) lacks its heading — for a figure ("figure:" key),
# when no paragraph carries its caption (pandoc writes the house image's alt text as the caption).
def _has_counting(data):
    return bool(RS.rows(data, "counting_rules") or data.get("metric_warnings"))


def _section(key, note=""):
    return lambda d, x, b: add_house_section(d, x, key, note)


def _figure(group, name):
    caption = dict(RS.FIGURE_CAPTIONS[group])[name] if name else RS.FIGURE_CAPTIONS[group][0][1]
    names = (name,) if name else None
    return (_heading_key(caption)[:40], f"figure:{name or group}",
            lambda d, x, b: add_figures(d, x, group, names, b))


_HOUSE_PARTS = [
    ("documentcontrol", "engagement", lambda d, x, b: add_engagement(d, x)),
    ("keyquestions", "key_questions", _section("key_questions")),
    ("identitycard", "subject_profile", lambda d, x, b: add_identity_cards(d, x)),
    _figure("card_maps", "person"),
    ("overallrisk", "risk_assessment", lambda d, x, b: add_risk_overall(d, x)),
    ("keyfindings", "key_findings", _section("key_findings")),
    ("clientprovided", "client_seeds", lambda d, x, b: add_client_seeds(d, x)),
    ("countingrules", "counting_rules", lambda d, x, b: (add_counting_rules(d, x), _has_counting(x))[1]),
    ("ratingscales", "rating_scales", lambda d, x, b: add_rating_scales(d, x)),
    _figure("card_maps", "threats"),
    ("affiliateexposure", "affiliate_exposure", _section("affiliate_exposure")),
    # exposure charts: under Affiliate exposure, or (stealer-log triage, no affiliate rows) their own heading
    _figure("exposure_charts", None)[:2] + (lambda d, x, b: add_triage_exposure(d, x, b) if RS.triage_exposure(x)
                                            else add_figures(d, x, "exposure_charts", None, b),),
    ("darkwebandtelegramclaims", "leak_claims", _section("leak_claims")),
    ("servicesregisteredbyemail", "email_services", _section("email_services")),
    ("eventsthatraisethethreat", "threat_events", _section("threat_events")),
    ("actorprofile", "actor_profile", lambda d, x, b: add_actor_profile(d, x)),
    ("roles", "roles", _section("roles", RS.ROLES_NOTE)),
    _figure("card_maps", "suppliers"),
    ("incidenttimeline", "incident_timeline", _section("incident_timeline")),
    ("attck", "attack_mapping", _section("attack_mapping")),
    ("scenarios", "scenarios", _section("scenarios")),
    ("recommendations", "roadmap",
     lambda d, x, b: bool(RS.roadmap_groups(x)) and (add_recommendations(d, x) or True)),
    ("usernamestoreserve", "usernames_to_reserve", _section("usernames_to_reserve")),
    ("openquestions", "open_questions", _section("open_questions")),
    ("qawarnings", "qa_warnings", lambda d, x, b: add_qa_warnings(d, x)),
    ("sourceschecked", "sources_checked", _section("sources_checked", RS.SOURCES_CHECKED_NOTE)),
    ("checkednothingfound", "negative_checks", lambda d, x, b: add_nothing_found(d, x)),
]


def add_missing_house_sections(doc: Document, data: dict, base=None) -> list:
    """Hybrid (Markdown-bodied) report: append, in house order, every report-block section whose
    heading the Markdown body does not already carry (a figure: whose caption it does not carry).
    `base` resolves relative `report_figures` paths. Returns the keys appended."""
    present = [_heading_key(p.text) for p in doc.paragraphs
               if (p.style is not None and str(p.style.name).lower().startswith("heading"))]
    text = [_heading_key(p.text) for p in doc.paragraphs]
    added = []
    for phrase, key, render in _HOUSE_PARTS:
        if any(phrase in h for h in (text if key.startswith("figure:") else present)):
            continue
        if render(doc, data, base):
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


