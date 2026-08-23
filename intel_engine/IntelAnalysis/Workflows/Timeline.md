# Workflow: Time-order the case

Encodes the temporal methodology (IntelAnalysis SKILL.md §1.5). Run it **after collection and
before you write the cluster** — it decides which of your shared indicators are real links and
which are two things that were never true at once.

Run from the project root. Placeholders: `<case>` = the case folder under `cases/`.

## Steps

1. **Make sure the dated sources were actually collected.** The timeline is only as rich as the
   clocks you pulled:
   - registration spine — WHOIS/RDAP runs keylessly (`pivot_extract … --whois`),
   - certificate windows — CT (crt.sh / Shodan CTL), keyless,
   - **hosting windows — passive DNS** (`PDNS_USERNAME`/`PDNS_PASSWORD`). Without it you have
     scan *points*, not tenancy *intervals*, and no co-tenancy claim is possible,
   - archive spans + per-artifact presence windows — `WebPivot/tools/wayback_ga.py <domain>`
     per host (this is what dates an artifact on *each* side of a link).

2. **Build the timeline + evidence ledger.**
   ```bash
   python3 IntelGraph/scripts/case_timeline.py cases/<case>/out/*.json \
       --stem cases/<case>/timeline --markdown \
       --history cases/<case>/out/wayback_*.json \
       --title "Infrastructure lifecycle — <n> domains" --source "OSINT collection" --grading B2
   ```
   Outputs: the swimlane figure (`_hires.png`/`.svg`/`_thumb.png`), `timeline_events.json`
   (every dated fact + its online link), `timeline.md` (evidence table + correlations).
   Note the `--max-certs` / `--max-lanes` omission counts it prints — they are bounds on the
   *figure*, and a bound you don't mention reads as "we covered everything".

3. **Read the five clocks per host** (§1.5): registration, registrant era, hosting, certificate,
   content. Where they disagree, that's a finding — a cert or capture predating the site going
   live is pre-staging; content changing with no infra change is a re-skin by the same hands.

4. **Test every candidate link for contemporaneity.** For each shared indicator in your cluster:
   - what window did each host carry it in? do the windows **overlap**, and by how long?
   - a shared IP with no overlap = sequential tenancy of a recycled address → drop the link,
   - a shared IP that IS a CDN/shared-host edge = noise however perfect the overlap (§1),
   - a shared artifact with no overlap = resold/copied kit or a recycled account → downgrade the
     claim from same-operator to same-kit, and say so explicitly.

5. **Work the expiry/renewal pattern** — the billing tell (§1.5):
   - same expiry reached from **different** creation dates = a deliberate renewal alignment,
     a second independent signal; same expiry from the same creation date + term = one fact,
     don't double-count it,
   - `updated`+`expires` moving together across the set on one day = one auto-renew batch,
   - a lapse cohort dates the **end** of the campaign; a domain still being renewed inside a dead
     cluster is the live lead — someone is still paying for it,
   - before asserting, ask what the **registrar** explains: same registrar + a promo/default term
     is a cheap coincidence; different registrars is an owner decision.

6. **Order the events into a narrative.** Registration cohort → provisioning (cert batch) →
   go-live (first capture) → hosting moves → persona handover → lapse. Then look for the two
   high-value orderings: infrastructure registered **days after** a seizure/takedown of a sibling
   (successor infrastructure), and any ordering that is **impossible** for a link you were about
   to assert (§4 — the cheapest disconfirmation there is; run it before spending credits).

7. **Age every claim.** Anything older than the `staleness` threshold
   (`IntelGraph/references/evidence_sources.json`) gets "as of `<date>`", never the present tense.

8. **Write it up with citations** (§7). Paste the ledger table into the assessment's Timeline
   section; each row keeps **when · source · online link** (Wayback / urlscan / crt.sh / RDAP /
   BGP). If a page has no public copy, archive it (`pivot_extract --archive-missing`) and cite
   the snapshot you created — never a local `cases/…` path.

## Output
`cases/<case>/timeline{_hires.png,.svg,_thumb.png,.md,_events.json}` plus the Timeline section of
`cases/<case>/assessment.md`, and — for any link the overlap test killed — a line in **Gaps &
alternatives** saying it was rejected on timing. That negative is worth writing down: it stops the
next analyst re-deriving the same dead link.
