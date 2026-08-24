---
name: cti-cluster
description: "Expand and correlate an existing case — peers, shared indicators, TLS overlap, reverse-WHOIS. Usage: /cti-cluster <domain|CASE-ID>"
argument-hint: "<domain|CASE-ID>"
---

# /cti-cluster — correlate and expand

Load the `cti-expert` skill, then expand: `$ARGUMENTS`

Work **down** the SKILL.md §2.5 priority ladder — highest-strength evidence first:

| Rung | Check | Call |
|---|---|---|
| 1–2 | registrant email/phone/org, incl. **historic** WHOIS; alias bridges | `intel.py whois` · `reverse-whois` |
| 3 | site-verification tokens (proves account control) | in `shared.txt` |
| 4 | TLS cert / SAN overlap | `mcp__intel__cert_overlap` |
| 5 | nameserver delegation to a **self-hosted** NS | in `shared.txt` |
| 7 | favicon / tracker / tenant IDs | `mcp__intel__kb_cluster` |
| 8–10 | co-tenancy, managed-provider NS, site kit | weak — corroborate or demote |

**Reverse-WHOIS is the highest-yield pivot here, and it PREVIEWS BY DEFAULT — there is no
`mode` argument on either layer.** The preview count is free; a term returning more than
`max_domains` (default 150) is shared boilerplate and must not be purchased or clustered on.
Only re-call with `confirm=true` (T1) / `--reverse-mode purchase` (T2) to spend credits.

Run `/cti-check` on every indicator before it becomes an edge. Report each asserted link with the
rung it rests on, so a reader can weigh it.
