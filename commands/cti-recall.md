---
name: cti-recall
description: "Have I seen this before? Check a seed against every prior case BEFORE collecting. Always run this first. Usage: /cti-recall <domain|indicator>"
argument-hint: "<domain|indicator>"
---

# /cti-recall — prior-knowledge check

Load the `cti-expert` skill, then check: `$ARGUMENTS`

**This is the cheapest command in the toolkit and it must run before any collection.** A seed
already in the store carries prior case context and possibly an operator attribution.

| Layer | Call |
|---|---|
| **T1 MCP** | `mcp__intel__domain_verdict` · `mcp__intel__which_cases` |
| **T2 CLI** | `python3 scripts/backend/intel.py recall <seed>` |

Accepts a domain or a raw indicator (`favicon:<h>`, `ga:<id>`, `wallet:<coin>:<addr>`,
`email:<addr>`, `social:<net>:<handle>`).

Report: which case(s) it appears in — each as its **abstract** (BLUF excerpt · attribution level ·
confidence · premise · cluster domains · recorded operator) — any operator attribution, and known
KB facts/edges with their time basis (`valid …`, `seen first..last ×N`) and any `[DISPUTED vs …]`
flag. An indicator seen across MULTIPLE cases is a cross-case link — surface it prominently.

Before reusing anything recalled, run the five-question gate (SKILL.md §2.5 *Reusing recalled
knowledge*): Knowledge, Evidence, Validity (`intel.py kb --entity <seed> --as-of <day>` for the
state on the incident day), Authority (resolve disputes first), Utility to this case's premise.

If the seed is already resolved, **say so and stop**. Do not re-investigate unless asked.
