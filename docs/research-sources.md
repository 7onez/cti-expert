# Research Source Register

What published research and tradecraft the analyst modules are built on, where each idea landed,
and how much of the source was actually read. Use it to trace a rule back to its source before
leaning on it, and as the work list for the next fold-in.

- **Method.** Open-access PDFs were text-extracted with book-to-skill (technical mode; `pdftotext`
  because Docling was unavailable — tables and figures were not layout-validated). Only the
  method / feature / heuristic / limitation sections were read; related work and evaluation detail
  were skimmed. Each idea was rewritten as an operating procedure (trigger → steps → confounders →
  abstention) in the module that owns the topic. Nothing here implements a paper's classifier or
  model, deploys a hunt, or re-runs an experiment.
- **Adaptation boundary.** Inside the modules, text tagged `[Pxx …]` restates the source;
  text marked *(adaptation)* is how cti-expert applies it. A number quoted from a paper describes
  that paper's dataset, never a threshold for a case.
- **Not shipped.** Source PDFs and extracted full text stay outside the repository.

Read status: **E** = PDF extracted, relevant sections read · **W** = targeted web sections read ·
**P** = pending (not read; listed for a later fold-in).

## Folded in

| ID | Source | St. | Extracted (procedure, not summary) | Landed in |
|----|--------|-----|------------------------------------|-----------|
| B05 | Heuer, *Psychology of Intelligence Analysis*, CIA CSI 1999 — [book](https://www.cia.gov/resources/csi/books-monographs/psychology-of-intelligence-analysis-2/) | E | ACH 8 steps (disprove, assumptions as evidence, diagnosticity, linchpins, sensitivity, milestones); bias checks B1–B10 (Ch 4–5, 10–13) | `handbook/analytic-standards.md` §3–4; `workflows/wf-threat-analyst.md` Bias Controls; `analysis/cross-reference-engine.md` §3 independence |
| P01 | Caltagirone, Pendergast & Betz, *The Diamond Model of Intrusion Analysis*, 2013 — [report](https://www.activeresponse.org/wp-content/uploads/2013/07/diamond.pdf) | E | Events with per-feature confidence, Type 1/2 infrastructure + service providers as leads, activity threads, activity groups with an explicit grouping function | `handbook/intrusion-modeling.md` §1–5 |
| P02 | Daszczyszak et al., *TTP-Based Hunting*, MITRE MTR180158 (2019; page 2020) — [publication](https://www.mitre.org/news-insights/publication/ttp-based-hunting) | W | Time/terrain/behaviour scoping, data requirements, needed-vs-available telemetry gap, benign-hit causes (read via Wayback copy; live site returned 403) | `workflows/wf-threat-analyst.md` Phase 5.2–5.3 |
| P03 | Strom et al., *MITRE ATT&CK: Design and Philosophy*, 2018 rev. 2020 — [paper](https://attack.mitre.org/docs/ATTACK_Design_and_Philosophy_March_2020.pdf) | E | Procedure-first mapping, technique IDs from the live matrix, coverage limits, no attribution on techniques alone | `handbook/intrusion-modeling.md` §7 |
| R02 | Bianco & Fetterman, *PEAK Threat Hunting Framework*, Splunk SURGe 2023 — [article](https://www.splunk.com/en_us/blog/security/peak-threat-hunting-framework.html) | W | Hunt types, Prepare/Execute/Act with Knowledge, ABLE hypotheses, hunt record with execution status + detection handoff | `workflows/wf-threat-analyst.md` Phase 5.1–5.4 |
| R03 | Bianco, *The Pyramid of Pain*, 2013 rev. 2014 — [article](https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html) | W | Ordinal ranking of cti-expert pivot artifacts by adversary cost to change (not a score) | `handbook/intrusion-modeling.md` §6 |
| P04 | Bilge et al., *EXPOSURE: Finding Malicious Domains Using Passive DNS Analysis*, NDSS 2011 — [paper](https://www.ndss-symposium.org/ndss2011/exposure-finding-malicious-domains-using-passive-dns-analysis/) | E | Time / answer / TTL / lexical features as a manual checklist with shared-hosting and CDN confounders; classifier not implemented | `techniques/fx-dns-cert-history.md` §2.6 |
| P05 | Antonakakis et al., *Building a Dynamic Reputation System for DNS* (Notos), USENIX Security 2010 — [paper](https://www.usenix.org/conference/usenixsecurity10/building-dynamic-reputation-system-dns) | E | Related historic IPs/domains, network/zone/evidence features, CDN and dynamic-DNS profiles | `techniques/fx-dns-cert-history.md` §2.6–2.7; `techniques/domain-advanced.md` §8 |
| P06 | Schüppen et al., *FANCI*, USENIX Security 2018 — [paper](https://www.usenix.org/conference/usenixsecurity18/presentation/schuppen) | E | NXDOMAIN / DGA triage as a lead generator; benign NXDOMAIN classes; ground-truth limits | `techniques/domain-advanced.md` §7; `techniques/phishing-domain-survival.md` entropy row |
| P07 | Antonakakis et al., *Understanding the Mirai Botnet*, USENIX Security 2017 — [paper](https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/antonakakis) | E | C2 estate reconstruction from independent vantage points; dated windows; clusters ≠ operators; re-registered domains | `techniques/domain-advanced.md` §8; `techniques/fx-dns-cert-history.md` §2.7 (temporal pivot rule) |
| P08 | Soska & Christin, *Measuring the Longitudinal Evolution of the Online Anonymous Marketplace Ecosystem*, USENIX Security 2015 — [paper](https://www.usenix.org/conference/usenixsecurity15/technical-sessions/presentation/soska) | E | Dated crawl records, coverage as lower bound, feedback-as-sales-proxy limits, PGP/name alias linkage risks, closure migration | `techniques/darknet-investigation.md` §5 Measurement, Alias Linkage, §6–7 |
| P09 | Nunes et al., *Darknet and Deepnet Mining for Proactive Cybersecurity Threat Intelligence*, IEEE ISI 2016 — [arXiv](https://arxiv.org/abs/1607.08583) | E | Structured threat-warning record; claim kept apart from verified capability; classifier = triage | `techniques/darknet-investigation.md` §5 Threat-Warning Extraction |
| P10 | Li & Liao, *Understanding and Analyzing Appraisal Systems in the Underground Marketplaces*, NDSS 2024 — [paper](https://www.ndss-symposium.org/ndss-paper/understanding-and-analyzing-appraisal-systems-in-the-underground-marketplaces/) | E | Appraiser/review incentives; fake, sockpuppet, templated reviews; reviews = weak volume evidence, artifacts = claims | `techniques/darknet-investigation.md` §5 Review & Appraisal Evidence |
| P11 | Thomas et al., *Trafficking Fraudulent Accounts*, USENIX Security 2013 — [paper](https://www.usenix.org/conference/usenixsecurity13/technical-sessions/paper/thomas) | E | Pre-aged / resold accounts; history ≠ current controller; control epochs; batch tells | `techniques/username-osint.md` §7.5 |
| P12 | Narayanan et al., *On the Feasibility of Internet-Scale Author Identification*, IEEE S&P 2012 — [paper](https://intelli-sec.cs.berkeley.edu/papers/sp12.pdf) | E | Stylometry ranks a stated candidate set; enough comparable text; abstention; cross-context degradation | `techniques/username-osint.md` §7.3; `techniques/darknet-investigation.md` §5; `analysis/signature-catalog.md` L-01 |
| P13 | Narayanan & Shmatikov, *De-anonymizing Social Networks*, IEEE S&P 2009 — [paper](https://www.cs.utexas.edu/~shmat/shmat_oak09.pdf) | E | Graph-topology linkage false matches (neighbours, co-located nodes); independent corroboration; privacy rule | `techniques/username-osint.md` §7.4 |
| P14 | Perito et al., *How Unique and Traceable Are Usernames?*, PETS 2011 | E | Handle rarity grade (GENERIC/MODERATE/RARE, adaptation) — never a per-handle probability; string-only grade automated to cap username-pivot priority | `techniques/username-osint.md` §7.1–7.2; `scripts/webpivot/pivot_suggest.py :: handle_rarity` + `scripts/references/handle_rarity.json` |
| P15 | Meiklejohn et al., *A Fistful of Bitcoins*, ACM IMC 2013 — [paper](https://cseweb.ucsd.edu/~smeiklejohn/files/imc13.pdf) | E | On-chain evidence ladder (transfer → control → cluster → label → identity); H1 multi-input, H2 change-address with breakers | `techniques/blockchain-investigation.md` §6–7; caveats in `web-pivot.md`, `fiat-payment-osint.md`, `aam-actor-modeling.md`, `tool-cascade-reference.md` |
| P16 | Huang et al., *Tracking Ransomware End-to-end*, IEEE S&P 2018 — [paper](https://research.google/pubs/tracking-ransomware-end-to-end/) | E | Ransom payment tracing: seeds → cluster expansion → cash-out exits → lower-bound estimate (no victim micropayments) | `techniques/blockchain-investigation.md` §6 |
| P17 | Kappos et al., *An Empirical Analysis of Anonymity in Zcash*, USENIX Security 2018 — [paper](https://www.usenix.org/conference/usenixsecurity18/presentation/kappos) | E | Shielded pool = chain break; published heuristics historical and population-specific | `techniques/blockchain-investigation.md` §6 Privacy Coins |
| P18 | Arp et al., *Dos and Don'ts of Machine Learning in Computer Security*, USENIX Security 2022 — [paper](https://www.usenix.org/conference/usenixsecurity22/presentation/arp) | E | Ten pitfalls → eval and report rules (temporal split, base rate, baselines) | `docs/evaluation-hygiene.md` §1, §3–4; `analysis/signature-catalog.md` note |
| P19 | Alam et al., *CTIBench*, NeurIPS 2024 Datasets & Benchmarks — [paper](https://proceedings.neurips.cc/paper_files/paper/2024/file/5acd3c628aa1819fbf07c39ef73e7285-Paper-Datasets_and_Benchmarks_Track.pdf) | E | Benchmark score ≠ case accuracy; evidence-span citation; abstention as a scored outcome; 5 judgement fixtures (local eval `judgement_cases/`, `claim_scorer.py`) | `docs/evaluation-hygiene.md` §2 |
| P20 | Cheng, Li, Basuki, Cui, Ding & Gao, *CTI2TTP: Evidence-Grounded TTP Extraction from CTI via Diverge-then-Converge Verification*, arXiv 2605.25836v2 (2026 preprint, not independently validated) — [arXiv](https://arxiv.org/abs/2605.25836v2) | E | Broad candidate generation, then evidence-span localisation + definition-grounded verification; same-family verifier ≠ corroboration; τ threshold not imported | `docs/evaluation-hygiene.md` §2 (experimental) |
| R01 | OHCHR & UC Berkeley Human Rights Center, *Berkeley Protocol on Digital Open Source Investigations* (2022) — [PDF](https://www.ohchr.org/sites/default/files/2024-01/OHCHR_BerkeleyProtocol.pdf) | E | Principles, pre-collection risk check, investigation plan, six-phase inquiry, per-item capture fields, chain of custody, three-part verification, reporting transparency | `handbook/collection-preservation.md`; cross-refs in `wf-threat-analyst.md`, `analytic-standards.md` |
| R04 | OASIS, *STIX Version 2.1* (OASIS Standard, 2021) — [spec](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html) | W | SCO UUIDv5 ids, millisecond Z timestamps, indicator required fields, resolvable refs, official TLP 2.0 marking ids | `scripts/generate-cti-iocs.py` (`build_stix`); `techniques/ioc-export.md` STIX section; local `tests/test_stix_conformance.py` |
| R05 | FIRST, *Traffic Light Protocol 2.0* — [standard](https://www.first.org/tlp/) | W | CLEAR/GREEN/AMBER/AMBER+STRICT/RED; AMBER+STRICT = organisation only; CLEAR replaces WHITE | IntelReport TLP table; `commands/cti-report.md`; IntelShare; SKILL.md `/misp-export`; STIX exporter markings |
| R06 | MITRE, *Cyber Analytics Repository* — [site](https://car.mitre.org/) | W | Object/action/field data model; every analytic validated for its environment; coverage ≠ detection | `workflows/wf-threat-analyst.md` Phase 5.2 |
| R07 | FIRST, *CVSS v3.1 Specification Document* — [spec](https://www.first.org/cvss/v3.1/specification-document) | W | Base-metric equations, constants and Roundup, so code (not the model) computes CVSS from a vector | local eval `claim_scorer.py` (`cvss_vector_only` fixture); `docs/evaluation-hygiene.md` §2 |

### PK — Packt, *Advanced Cyber Threat Intelligence and Hunting* companion repository (2026)

[github.com/PacktPublishing/Advanced-Cyber-Threat-Intelligence-and-Hunting](https://github.com/PacktPublishing/Advanced-Cyber-Threat-Intelligence-and-Hunting)
— MIT licence, © 2026 Packt; pinned at commit `0f76fbc2ff505e6fcb2585b1b3d0b08ce271b1e4`, read
2026-11-15 (St. **E** = file read in full from a local clone). Only the companion material was used;
the book text itself was not read. Ideas are rewritten as procedures; no upstream worked example,
actor or number is reproduced (examples are synthetic). In tracked modules this source is cited as
`[PK Packt ACTIH companion repo, 2026, <path>]`; a path that names a real actor is cited in redacted
form there and given in full only below. Hunting queries are **linked, never copied**.

| Upstream path | St. | Extracted (procedure, not summary) | Landed in |
|---------------|-----|------------------------------------|-----------|
| `chapter-01/CTI SOP Emerging Threat Response.md` | E | Five-phase response 1.1–5.4, five exposure dimensions, Advisory vs Assessment, acknowledgments, +7/+30 checkpoints | `workflows/wf-emerging-threat.md`; routing note in `commands/cti.md` |
| `chapter-01/Threat Actor Scoring Model.md` | E | Intent/Capability/Opportunity 0–1, 0.6/0.4 opportunity, 0.5/0.25/0.25 weights, Intent floor rule, bands with postures and cadences, score stability | `scripts/osint/exposure_score.py --model actor`, `scripts/osint/references/exposure_actor.json`, `analysis/weight-engine.md` §9 |
| `chapter-01/CTI Severity Tier Matrix.md` | E | Severity × exposure grid, per-trigger patterns, five exposure dimensions, re-tier triggers, P1 needs both axes, no auto-close | `exposure_score.py --model tier`, `scripts/osint/references/severity_tiers.json`, `analysis/weight-engine.md` §10, `handbook/severity-tiers.md` |
| `chapter-03/apt41-threat-profile-deliverable.md` (cited in tracked modules as "chapter-03 threat-profile deliverable") | E | Operational tempo as a business-hours window; "two distinct activity rhythms" as monitoring windows; deliverable structure — per-claim confidence table, overview with dissent, intent, capability, victimology, persona/OPSEC, defensive pivot table, tactic playbook, hunt hypotheses, priority telemetry | `handbook/intrusion-modeling.md` §10; `intel_engine/IntelGraph/scripts/operator_tempo.py` + `references/operator_tempo.json` (`case_timeline --tempo`); actor-profile report sections (`evidence_import.json`, `report_sections.json`, `house_report_sections.actor_profile`, `cti_report_sections.actor_blocks`, `handbook/report-template.md`) |
| `README.md` and `chapter-04`…`chapter-18` READMEs + all 67 query files (ES\|QL, EQL, KQL, Sigma, SPL, ML/transform JSON) | E | Per-query hypothesis, telemetry, prerequisites, method and false positives — **linked, not copied**; TTB diversity score and velocity extension; C2 rarity patterns (few-hosts-heavy DNS, rare-global/noisy-local user agent, URI reuse across domains) | `intel_engine/IntelAnalysis/references/hunt_packages.json` (67 entries, 13 tactic groups); `workflows/wf-threat-analyst.md` Phase 5 "Hunt package library" |
<!-- PK-ROWS -->

Upstream inconsistencies found while indexing: `chapter-18/README.md` names `chapter_18_ttb_velocity.esql`
(actual file `chapter-18/ttb-diversity-scoring-ai.esql`) and an `enrich_policies/` directory that does not
exist (the policies are `chapter-18/host_peer_group.json` and `peer_group_baselines.json`); the index is
built from the files present at the pinned commit, not from README prose.

### YS — Yamato Security open-source detection projects (2026)

[github.com/Yamato-Security](https://github.com/Yamato-Security) — each repo pinned to one commit,
read 2026-11-16 from local clones. Licences checked from each repo's LICENSE file:
`hayabusa-rules` / `suzaku-rules` **Detection Rule License 1.1** (keep each rule's `author` on any
shared rule or reported match); `hayabusa`, `suzaku`, `takajo`, `senrigan` **AGPL-3.0** (named and
linked only, never bundled or copied); `EventLog-Baseline-Guide` **MIT**. Rules and hunts are
**linked, never copied** (titles and metadata only, no detection logic). These tools run on the
consumer's own logs; cti-expert never runs them.

| Repo @ commit | St. | Extracted | Landed in |
|---------------|-----|-----------|-----------|
| `EventLog-Baseline-Guide` @ `9a253a398498d64e380c0235e914181d342c16b3` (MIT) | E | Windows audit subcategories, baseline settings, usable/unusable Sigma counts per baseline, log-size floors | `intel_engine/IntelAnalysis/references/telemetry_baselines.json`; `workflows/wf-emerging-threat.md` §2/§3.4; `handbook/report-template.md` (`baseline_ref`) |
| `hayabusa-rules` @ `73f990fa5ab767a401515ad91b4ed297da9351fc` (DRL 1.1) | E | Rule metadata only: Sigma id, title, level, logsource, author, ATT&CK tags; every document of a correlation file (correlation + base rules) | `intel_engine/IntelAnalysis/references/hunt_rules_yamato.json`; `workflows/wf-threat-analyst.md` Phase 5 |
| `suzaku-rules` @ `b5b2e1bce3e1dee325ea6ffe767a6a0b44a11ce1` (DRL 1.1) | E | Cloud rule metadata only: id, title, level, logsource, author, ATT&CK tags; every document of a correlation file (correlation + base rules) | `intel_engine/IntelAnalysis/references/hunt_rules_yamato.json`; `workflows/wf-threat-analyst.md` Phase 5 |
| `senrigan` @ `8d925119fc8b8ec921132cfb33220fd2e0a31c87` (AGPL-3.0) | E | Hunt names, severities, ATT&CK / AWS Threat Technique Catalog ids, CloudTrail eventSource or required VPC Flow Log columns (`agent/builtin_hunts.yaml`, `agent/suzaku_timeline_hunts.yaml`, `agent/vpc_flow_hunts.yaml`); links with line anchors only | `intel_engine/IntelAnalysis/references/hunt_rules_yamato.json` `senrigan_hunts`; `workflows/wf-threat-analyst.md` Phase 5 |

Notes: two hayabusa-rules ids are not valid UUIDs upstream, and one suzaku-rules base rule reuses
another rule's id (both kept as written; listed in `duplicate_id_paths`). Upstream rule titles
can name public threat groups or tools; they are reproduced verbatim as rule metadata, never as
case findings or attribution.

## Pending — commercial books (publisher/contents review only, not converted)

Full-chapter conversion needs a legally obtained PDF/EPUB. A purchase does not authorise public
redistribution of chapter summaries; this repository is public, so only synthesized procedures
with citations may land here — never chapter recaps or excerpts.

| ID | Source | Planned owner module |
|----|--------|----------------------|
| B01 | Brown & Roberts, *Intelligence-Driven Incident Response*, 2nd ed. (2023) | `workflows/wf-threat-analyst.md` (tasking, F3EAD, dissemination) |
| B02 | Bazzell, *OSINT Techniques*, 11th ed. (2024) | `techniques/*-osint.md` (methodology, documentation; re-verify volatile platform detail) |
| B03 | DiMaggio, *The Art of Cyberwarfare* (2022) | `handbook/intrusion-modeling.md` (campaign/actor case workflow) |
| B04 | Robertson et al., *Darkweb Cyber Threat Intelligence Mining* (2017) | `techniques/darknet-investigation.md` |
| B06 | Lee, *Cyber Threat Intelligence* (2023) | `workflows/wf-threat-analyst.md` (requirements, adversary economics) |
| B07 | Costa-Gazcón, *Practical Threat Intelligence and Data-Driven Threat Hunting* (1st ed., 2021) | `workflows/wf-threat-analyst.md` hunt phase — 2nd-edition date conflict (Packt vs WorldCat) unresolved; verify ISBN first |
| B08 | Steffens, *Attribution of Advanced Persistent Threats* (2020) | `handbook/intrusion-modeling.md`, `handbook/analytic-standards.md` |
| B09 | Baker, *Deep Dive* (2023) | `techniques/username-osint.md`, `techniques/people-records-global.md` |
| B10 | Pherson & Heuer, *Structured Analytic Techniques*, 3rd ed. (2019) | `handbook/analytic-standards.md` (only techniques current cases need) |
| B11 | Furneaux, *There's No Such Thing as Crypto Crime* (2024) | `techniques/blockchain-investigation.md` |
| B12 | Furneaux, *Investigating Cryptocurrencies* (2018) | `techniques/blockchain-investigation.md` (foundation; pair with B11) |
| B13 | Borgatti, Everett & Johnson, *Analyzing Social Networks*, 2nd ed. (2018) | `techniques/fx-social-topology.md` (boundaries, missing data, role limits) |
| B14 | Troia, *Hunting Cyber Criminals* (2020) | `techniques/username-osint.md`, `techniques/email-osint.md` |
| B15 | Gehl, *Weaving the Dark Web* (2018) | `techniques/darknet-investigation.md` (community context) |
| B16 | Hassan & Hijazi, *Open Source Intelligence Methods and Tools* (2018) | `techniques/*-osint.md` (durable methodology only) |
| B17 | Collins, *Network Security Through Data Analysis*, 2nd ed. (2017) | `workflows/wf-threat-analyst.md` (sensor vantage, validity) |
| B18 | Sanders & Smith, *Applied Network Security Monitoring* (2013) | `workflows/wf-threat-analyst.md` |
| B19 | Sanders, *Practical Packet Analysis*, 3rd ed. (2017) | `techniques/web-dns-forensics.md` (protocol evidence only) |
| B20 | Sikorski & Honig, *Practical Malware Analysis* (2012) | `intel_engine/BinaryPivot/SKILL.reference.md` (extracted-infrastructure sections) |


## Next fold-in (procedure)

1. Put the source PDF/EPUB **outside** the repo; run book-to-skill's extractor
   (`.claude/skills/book-to-skill/scripts/extract.py <files> --mode technical`), keep the workdir.
2. Read only the sections that carry method, heuristics, and limits (`grep -n` + ranged reads).
3. For each idea record: original name, source location, trigger, inputs, steps, output,
   assumptions, confounders, abstention condition, source-vs-adaptation boundary.
4. Land it in the owning module above; grep `techniques/ workflows/ handbook/ analysis/ SKILL.md`
   for older advice it contradicts and fix that in the same change.
5. Add a row to **Folded in**, synthetic examples only, then `bash scripts/audit.sh`.
