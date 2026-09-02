---
name: cti-report
description: "Render case deliverables — relationship graph (PNG/SVG/Mermaid) and a polished PDF/DOCX assessment. Usage: /cti-report <CASE-ID> [--graph|--pdf]"
argument-hint: "<CASE-ID> [--graph|--pdf]"
---

# /cti-report — render deliverables

Load the `cti-expert` skill, then render for: `$ARGUMENTS`

**Graph** (editable .mmd + SVG + hi-res/thumb PNG):

```bash
python3 scripts/backend/intel.py graph "$PWD/<case_graph.json>" "$PWD/<out-stem>" --legend
```

Pass **absolute paths** — the dispatcher runs with its own working directory and relative paths
will not resolve.

**House report** (the editorial PDF + DOCX, composed deterministically from the case dir — sections
I–XI, both confidence scales, relationship graph, inference chain, temporal view, Appendices A–D;
third-party selectors masked, internal tool/path names scrubbed):

```bash
python3 scripts/backend/intel.py house-report <CASE-ID>          # → cases/<CASE-ID>/report/CTI-REPORT-<CASE-ID>-<date>.{pdf,docx,md}
```

**Raw render** (when you have hand-authored house-rules markdown yourself):

```bash
python3 scripts/backend/intel.py report <assessment.md> <out-stem> --pdf --docx
```

`intel.py report` is the **IntelReport** renderer (xelatex/pandoc PDF + DOCX) applied to markdown you
wrote; `house-report` composes that markdown for you from `assessment.json`/`assessment.md`, `whois/`,
`raw/`, `clusters.json` and the ledgers. For the **flat-JSON deliverable bundle** — interactive HTML,
the IOC/selector exports (STIX/CSV/JSONL/TXT), and the chart-rich dashboard DOCX/PDF for cases with no
case dir — build the report JSON deterministically first, then run the generators (see SKILL.md §8):

```bash
uv run "$SKILL_DIR/scripts/build_report_data.py" "${INTEL_HOME:-$SKILL_DIR/intel_engine}/cases/<CASE-ID>" -o "CTI-REPORT-<CASE-ID>-<DATE>.json"
```

Before rendering, confirm the assessment: states confidence on both axes (Admiralty per finding,
ICD-203 per judgment — High/Moderate/Low, no hyphenated hybrids); tags each link with its evidence
rung; reports empty findings as empty; and includes alternative hypotheses wherever attribution
reaches a named individual.

**Inherit the source's TLP marking.** A TLP:RED case must not be published to an Artifact or any
hosted URL.
