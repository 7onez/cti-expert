---
name: cti-pivot
description: "Collect pivot artifacts from ONE target — favicon, trackers, wallets, emails, CORS, mail/SPF/DMARC, WHOIS, co-tenancy. Usage: /cti-pivot <url|domain|ip> [passive]"
argument-hint: "<url|domain|ip> [passive]"
---

# /cti-pivot — single-target collection

Load the `cti-expert` skill, then collect from: `$ARGUMENTS`

| Layer | Call |
|---|---|
| **T1 MCP** | `mcp__intel__pivot_extract` (url, case; optional `passive`, `proxy`, `force`) |
| **T2 CLI** | `python3 scripts/backend/intel.py pivot-extract <url> --pretty -o <out>` |

A **bare IP** switches to IPPivot mode: ASN/abuse, co-hosted domains, ports, passive DNS. Note
that co-tenancy on a shared/reseller box is information, **not** a same-operator link — check the
tenant count before drawing any conclusion.

**Passive collection — work from saved/archived HTML instead of contacting the target. Use it for
anything hostile.** The two layers spell it differently, and there is no `--passive` flag:

- **T1 MCP:** pass `passive=true` (with `url` pointing at the already-saved or archived HTML).
- **T2 CLI:** pass the **saved HTML file itself** as the positional `source` — `pivot-extract`
  reads a local file exactly like a URL. Related flags: `--free-only`, `--no-fallback`.

Collection **archives by default** (Wayback Save-Page-Now + urlscan), which is outbound and
attributable. That is right for evidence and wrong for a target you have not decided to touch —
it will prompt. Set `HARNESS_NO_ARCHIVE=1` to collect without submitting.

**If it returns zero or near-zero pivots**, do not stop — run `mcp__intel__fallback_probe`. Parked
apex domains routinely have live subdomains; enumerate CT and the Wayback CDX host histogram
before writing the seed off.
