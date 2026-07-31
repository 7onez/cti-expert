---
name: cti-case
description: "Run the full deterministic pipeline on one or more seeds: collect, ingest, prior-overlap, risk, cluster, ICD-203 assessment. Usage: /cti-case <CASE-ID> <seed> [seed...]"
argument-hint: "<CASE-ID> <seed> [seed...]"
---

# /cti-case — full pipeline

Load the `cti-expert` skill, then open a case for: `$ARGUMENTS`

First argument is the case ID; the rest are seeds. Write the seeds to a file, then:

```bash
python3 scripts/backend/intel.py pipeline open <CASE-ID> <seeds-file>
```

This runs, in order: **collect → ingest → prior-overlap → risk → shared-cluster → assessment**,
persisting to `$INTEL_HOME/cases/<CASE-ID>/` with `raw/`, `shared.txt`, `case_graph.json` and
`assessment.md`.

Prefer this over hand-running collectors. It records evidence archiving, a versioned assessment
and a convergence check that ad-hoc collection does not.

Afterwards:

1. Read `shared.txt` — the shared-indicator set is where the real cluster lives.
2. Run `/cti-check` on every indicator before treating it as a cluster edge.
3. Keep refuted candidates in `cases/<CASE-ID>/refuted/` — a rejected lead is a finding and it
   stops the next analyst re-chasing it.

**Hostile target?** Collect passively (Wayback/urlscan) or via a proxy range. Never touch a
hostile host from an attributable session.
