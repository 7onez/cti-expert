---
name: cti-pivot
description: "Collect pivot artifacts from ONE target — favicon, trackers, wallets, emails, CORS, mail/SPF/DMARC, WHOIS, co-tenancy. Usage: /cti-pivot <url|domain|ip> [--passive]"
argument-hint: "<url|domain|ip> [--passive]"
---

# /cti-pivot — single-target collection

Load the `cti-expert` skill, then collect from: `$ARGUMENTS`

| Layer | Call |
|---|---|
| **T1 MCP** | `mcp__intel__pivot_extract` (url, case) |
| **T2 CLI** | `python3 scripts/backend/intel.py pivot-extract <url> --pretty -o <out>` |

A **bare IP** switches to IPPivot mode: ASN/abuse, co-hosted domains, ports, passive DNS. Note
that co-tenancy on a shared/reseller box is information, **not** a same-operator link — check the
tenant count before drawing any conclusion.

`--passive` works from already-saved or archived HTML instead of contacting the target. Use it for
anything hostile.

**If it returns zero or near-zero pivots**, do not stop — run `mcp__intel__fallback_probe`. Parked
apex domains routinely have live subdomains; enumerate CT and the Wayback CDX host histogram
before writing the seed off.
