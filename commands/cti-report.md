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

**Report** (PDF/DOCX from the assessment markdown):

```bash
python3 scripts/backend/intel.py report <assessment.md> <out-stem> --pdf --docx
```

Before rendering, confirm the assessment: states confidence on both axes (Admiralty per finding,
ICD-203 per judgment — High/Moderate/Low, no hyphenated hybrids); tags each link with its evidence
rung; reports empty findings as empty; and includes alternative hypotheses wherever attribution
reaches a named individual.

**Inherit the source's TLP marking.** A TLP:RED case must not be published to an Artifact or any
hosted URL.
