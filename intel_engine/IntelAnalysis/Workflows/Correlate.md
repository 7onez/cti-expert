# Workflow: Correlate & Attribute

Turn a knowledge base full of facts into an attributed cluster assessment.

## Steps

1. **Pull the cluster seeds (code, free).**
   ```bash
   python3 tools/kb/query.py --kb knowledge --shared --min 2
   ```
   Each row = an indicator + the domains sharing it. This is the correlation math done
   deterministically — you reason over the result, not the raw data.

2. **Triage each shared indicator** against §1 of SKILL.md. Drop noise (Cloudflare NS,
   generic registrar). Keep attribution-grade and corroborating.

3. **Group into clusters.** Domains connected by ≥1 attribution-grade indicator are one
   cluster candidate. Use `--cluster <domain>` to expand a seed.

4. **Apply the corroboration rule (§2).** For each cluster, count *independent*
   attribution-grade artifacts. Decide the claim level: same-kit / same-operator / same-actor.

5. **Calibrate confidence (§3)** and **surface conflicts (§6)** — e.g. a pre-privacy
   registrant vs a later proxy.

6. **Write the assessment (§7).** BLUF, cited cluster table, attribution level, gaps,
   next steps. Every asserted link cites an `evidence_ref` from the store.

## Output
A cited assessment. If your judgment revises a rating, note it so it can be written back
to the store's confidence fields.
