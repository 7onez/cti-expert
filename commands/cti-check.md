---
name: cti-check
description: "False-positive control — is this indicator a real operator link or shared noise? Run BEFORE clustering on anything. Usage: /cti-check <indicator>"
argument-hint: "<indicator>"
---

# /cti-check — false-positive control

Load the `cti-expert` skill, then evaluate: `$ARGUMENTS`

| Layer | Call |
|---|---|
| **T1 MCP** | `mcp__intel__reference_check` → BENIGN / SIGNAL / UNKNOWN |
| **T2 CLI** | `python3 scripts/backend/intel.py reference check <value>` |

**UNKNOWN means decide, not proceed.** Test it against the six traps in SKILL.md §2.5, then record
the verdict with `reference_add` so every future case inherits it:

| Trap | Test |
|---|---|
| Commodity site kit | Search the template path in urlscan/FOFA — a large population means kit-level |
| Privacy-proxy contact | Reverse-WHOIS it; a spread of unrelated domains means noise |
| Shared/reseller IP | Count tenants first |
| Managed-provider NS | Cloudflare/GoDaddy/Gandi/Wix = noise; self-hosted = strong |
| Org-name collision | Reverse-WHOIS the org and inspect what returns |
| Shared tag container | **Check domain creation dates** — a decade-old business sharing a tag with a new fraud domain is a third party |

> Never put an unvalidated indicator into a report that recommends abuse reporting. Naming an
> uninvolved business is the most damaging error this toolkit can produce.
