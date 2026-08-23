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

2b. **Base-rate any CONFIGURATION indicator before it earns a tier (§1, "Base-rate a
   CONFIGURATION before you call it a fingerprint").** For a non-standard port, protocol/port
   combination, banner or version string, control panel, JARM/TLS stack, or a domain naming
   scheme — count the population **globally and within the host's own ASN** before treating it
   as a link:
   ```bash
   # total match count only — size=1, you want the denominator not the rows
   fofa 'port="<p>" && protocol="<proto>"'            # world-wide
   fofa 'port="<p>" && protocol="<proto>" && asn="<n>"'  # the provider's own image
   ```
   Interpret against your actor hypothesis: for an **APT/espionage** target a large population
   means *provider default → reject*; for a **scam compound / kit-as-a-service** target
   mass-deployment is expected, so test **coherence** (naming, registrar, reg/expiry rhythm,
   cert batching, content kit) rather than count alone. Record the rejection in the assessment.

3. **Group into clusters.** Domains connected by ≥1 attribution-grade indicator are one
   cluster candidate. Use `--cluster <domain>` to expand a seed.

3b. **Time-order the cluster before you believe it (`Workflows/Timeline.md`, §1.5).** Build the
   timeline (`IntelGraph/scripts/case_timeline.py … --markdown`) and check each shared indicator
   for **window overlap** on both hosts. No overlap = sequential tenancy / resold kit, not one
   operator — drop or downgrade the link and record why. Pick up the expiry-cohort and
   cert-batch signals here too.

4. **Apply the corroboration rule (§2).** For each cluster, count *independent*
   attribution-grade artifacts. Decide the claim level: same-kit / same-operator / same-actor.

5. **Calibrate confidence (§3)** and **surface conflicts (§6)** — e.g. a pre-privacy
   registrant vs a later proxy.

6. **Write the assessment (§7).** BLUF, cited cluster table, attribution level, gaps,
   next steps. Every asserted link cites an `evidence_ref` from the store.

## Output
A cited assessment. If your judgment revises a rating, note it so it can be written back
to the store's confidence fields.
