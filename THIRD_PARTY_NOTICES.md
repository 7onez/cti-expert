# Third-Party Notices

This file lists the third-party works whose material is vendored, adapted, indexed by link, or
required to carry an attribution in cti-expert. It records, for each one, the upstream work, the
version or commit used, the licence, how the material was used, where it lives in this repository,
and the notice the licence requires. The services and APIs that the skill only queries are credited
in the README's *Acknowledgments & Credits* table and are not repeated here.

**AGPL boundary.** Projects licensed under the GNU Affero General Public License (AGPL-3.0) are
named and linked only. No AGPL code or text is included in this repository.

Licences were checked on 2026-11-17 against each upstream LICENSE file (GitHub API) or the
publisher's official page. Where no reuse terms could be found, the entry says **not verified**.
cti-expert's own licence is in [LICENSE](LICENSE).

---

## 1. Vendored code

> **Distribution note.** The three trimmed copies under `scripts/vendor/` are tracked and
> **distributed in the git repository**. `.gitignore` re-includes exactly these three directories
> from its general `vendor/` rule; every other `vendor/` path (runtime-installed tools) stays
> ignored. Each copy keeps its upstream `LICENSE` beside it and a `VENDOR.md` recording the
> upstream URL, the pinned commit and what was trimmed. The public-suffix data below is tracked
> too and carries its own licence notice.

**MIT permission notice.** Every MIT entry in this file is subject to the following text, together
with the copyright line given in that entry:

> Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
> associated documentation files (the "Software"), to deal in the Software without restriction,
> including without limitation the rights to use, copy, modify, merge, publish, distribute,
> sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
> furnished to do so, subject to the following conditions:
>
> The above copyright notice and this permission notice shall be included in all copies or
> substantial portions of the Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
> NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
> NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
> DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT
> OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

### Archify

- **Upstream:** <https://github.com/tt-a1i/archify>, version **2.16.0** (tag `v2.16.0`, commit
  `c826e6c3a7abad19c0f3cd1ca57207d54b1ad8de`). All 39 vendored files are byte-identical to that
  tag (compared 2026-11-17).
- **Licence:** MIT at v2.16.0. Upstream changed to Apache-2.0 on 2026-10-25 (commit `9c306ee`)
  and kept the earlier MIT grants, so the vendored 2.16.0 copy stays MIT. Upgrading past that
  commit changes the licence to Apache-2.0 (see `scripts/vendor/archify/VENDOR.md`).
- **Use:** a trimmed vendored copy containing only the `archify render architecture` path. It draws
  the Blueprint diagram in the HTML report.
- **Location:** `scripts/vendor/archify/` (tracked; see the note above), driven by
  `scripts/cti_archify.py` and `scripts/generate-cti-html.py`.
- **Required notice (kept in `scripts/vendor/archify/LICENSE`):**
  > Copyright (c) 2026 tt-a1i (Archify)
  > Copyright (c) 2025 Cocoon AI (original "architecture-diagram-generator")

### Diagram Design

- **Upstream:** <https://github.com/cathrynlavery/diagram-design>, pinned at commit
  `b52a33bfeef85d43995193ee52c13b485154b7b4` (2026-08-30). No version was recorded at copy time;
  the three files were matched byte-for-byte to that commit on 2026-11-17.
- **Licence:** MIT, verified against the upstream LICENSE.
- **Use:** an unmodified vendored copy of `style-guide.md` and `self_check.py` (reference only;
  nothing in the build runs them). Its editorial design rules are adapted in tracked code that
  renders the entity and topology SVG figures.
- **Location:** `scripts/vendor/diagram-design/` (tracked); the adapted rules are in
  `scripts/cti_diagram_design.py`.
- **Required notice (kept in `scripts/vendor/diagram-design/LICENSE`):**
  > Copyright (c) 2025 Cathryn Lavery

### Diagram AI Generator

- **Upstream:** <https://github.com/carlosmgv02/diagram-ai-generator>. Unpinned at copy time; the
  retained `LICENSE` matches upstream `master` at commit `f6568cdfb455ad9a26bd182397de5d7f6c192100`
  (2025-10-02).
- **Licence:** MIT, verified against the upstream LICENSE.
- **Use:** the approach and JSON spec shape (`provider` / `components` / `connections`) were
  adapted. No upstream code is vendored; the directory holds only `LICENSE` and `VENDOR.md`, kept
  for attribution.
- **Location:** `scripts/vendor/diagram-ai-generator/` (tracked); the adapted approach is in
  `scripts/cti_cloud_arch.py`.
- **Required notice (kept in `scripts/vendor/diagram-ai-generator/LICENSE`):**
  > Copyright (c) 2025 Diagram AI Generator

### Public Suffix List

- **Upstream:** <https://publicsuffix.org/list/public_suffix_list.dat>, fetched
  2026-09-05T08:30:03Z (the `fetched_utc` field in the file).
- **Licence:** MPL-2.0, verified against <https://github.com/publicsuffix/list> LICENSE and the
  `.dat` header.
- **Use:** a vendored data copy, re-shaped into JSON (`icann` / `private` rule tables) for eTLD+1
  reduction. It is refreshed with `intel_engine/WebPivot/tools/wp_psl_update.py`. This is a
  modified form of an MPL-2.0 file, and that file stays under MPL-2.0.
- **Location:** `intel_engine/WebPivot/references/public_suffix_list.json` (tracked).
- **Required notice (MPL-2.0 Exhibit A, as carried in the upstream file):** carried in the JSON file
  itself as the top-level `notice` key, beside `licence: "MPL-2.0"` and `source`. The refresh script
  writes all three on every run and refuses to write if the upstream header stops carrying it.
  > This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy
  > of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

---

## 2. Adapted methods and data (MIT/DRL)

### Packt: *Advanced Cyber Threat Intelligence and Hunting* companion repository

- **Upstream:** <https://github.com/PacktPublishing/Advanced-Cyber-Threat-Intelligence-and-Hunting>,
  pinned at commit `0f76fbc2ff505e6fcb2585b1b3d0b08ce271b1e4`, read 2026-11-15.
- **Licence:** MIT, verified against the LICENSE at the pinned commit.
- **Use:** procedures and scoring models were adapted and rewritten in our own words, with
  synthetic examples. This covers the emerging-threat SOP, the Intent/Capability/Opportunity
  actor-scoring model, the severity × exposure tier matrix, and the chapter-03 threat-profile
  deliverable structure, including operational tempo. The book text itself was not used.
- **Location:** `workflows/wf-emerging-threat.md`; `scripts/osint/exposure_score.py`
  (`--model actor`, `--model tier`); `scripts/osint/references/exposure_actor.json`;
  `scripts/osint/references/severity_tiers.json`; `analysis/weight-engine.md` §9–10;
  `handbook/severity-tiers.md`; `handbook/intrusion-modeling.md` §10;
  `intel_engine/IntelGraph/scripts/operator_tempo.py` and `references/operator_tempo.json`.
  Provenance is recorded in `docs/research-sources.md` (section PK).
- **Required notice:**
  > Copyright (c) 2026 Packt
  >
  > (MIT permission notice above)

### Yamato Security: EventLog-Baseline-Guide

- **Upstream:** <https://github.com/Yamato-Security/EventLog-Baseline-Guide>, pinned at commit
  `9a253a398498d64e380c0235e914181d342c16b3`.
- **Licence:** MIT, verified against the LICENSE at the pinned commit.
- **Use:** adapted data, written in our own words. It supplies the Windows audit subcategories, the
  setting each baseline recommends, the usable/unusable rule counts, and the log-size floors. No
  rule, hunt or script text is copied.
- **Location:** `intel_engine/IntelAnalysis/references/telemetry_baselines.json`;
  `workflows/wf-emerging-threat.md` §2/§3.4; `handbook/report-template.md` (`baseline_ref`).
- **Required notice (also stored in the file's `source.attribution` field):**
  > Adapted from Yamato Security's EventLog-Baseline-Guide, Copyright (c) 2025 YamatoSecurity, MIT
  > License.

### Exploratores (ideas only)

- **Upstream:** <https://github.com/SOsintOps/Exploratores>. No version is recorded.
- **Licence:** AGPL-3.0, verified against the upstream LICENSE.
- **Use:** its reversible-redaction and IBAN-analysis *techniques* were independently reimplemented
  from the project's published documentation. **No code or text was copied.** The project is named
  and linked only, as the AGPL boundary above requires.
- **Location:** credited in the README's *Tradecraft & methodology* row.
- **Required notice:** none, because no AGPL material is included.

---

## 3. Link-only indexes

These indexes hold metadata and pinned links. They contain no detection logic and no query text.

### Packt companion repository: hunting queries

- **Upstream / pin / licence:** the same as the Packt entry in section 2 (MIT, commit
  `0f76fbc2ff505e6fcb2585b1b3d0b08ce271b1e4`).
- **Use:** a link-only index with one entry per upstream query file (67 files: ES|QL, EQL, KQL,
  Sigma, SPL, ML/transform JSON). Titles, hypotheses, method and false-positive notes are written
  in our own words. No query text is copied.
- **Location:** `intel_engine/IntelAnalysis/references/hunt_packages.json` (its `license` field
  reads "MIT (c) 2026 Packt"); `workflows/wf-threat-analyst.md` Phase 5.

### Yamato Security: hayabusa-rules and suzaku-rules

- **Upstream:** <https://github.com/Yamato-Security/hayabusa-rules> @
  `73f990fa5ab767a401515ad91b4ed297da9351fc`; <https://github.com/Yamato-Security/suzaku-rules> @
  `b5b2e1bce3e1dee325ea6ffe767a6a0b44a11ce1`. Both retrieved 2026-11-16.
- **Licence:** Detection Rule License (DRL) 1.1, verified against the upstream `LICENSE.md` /
  `LICENSE`.
- **Use:** an index of rule metadata only: Sigma id, title, level, logsource, verbatim `author`, and
  ATT&CK tags. Each entry links to the rule at the pinned commit. No detection logic is copied.
- **Location:** `intel_engine/IntelAnalysis/references/hunt_rules_yamato.json`;
  `workflows/wf-threat-analyst.md` Phase 5.
- **Required attribution:** every rule's `author` is kept in the index. It must stay on any shared
  rule and on any reported match (see the DRL 1.1 summary in section 5).

### Yamato Security: Senrigan hunts

- **Upstream:** <https://github.com/Yamato-Security/senrigan> @
  `8d925119fc8b8ec921132cfb33220fd2e0a31c87`.
- **Licence:** AGPL-3.0, verified against the upstream LICENSE.
- **Use:** names and links only. The index holds hunt ids, titles, severities, ATT&CK / AWS Threat
  Technique Catalog ids and required telemetry, with line-anchored links into
  `agent/builtin_hunts.yaml`, `agent/suzaku_timeline_hunts.yaml` and `agent/vpc_flow_hunts.yaml`.
  No hunt logic is copied.
- **Location:** `intel_engine/IntelAnalysis/references/hunt_rules_yamato.json` (`senrigan_hunts`).

---

## 4. Runtime tools invoked, not bundled

None of these is committed to the repository.

| Tool | Upstream · version | Licence (verified) | How it is used | Repo touch-point |
|------|--------------------|--------------------|----------------|------------------|
| REA (`rea-agents`) | <https://github.com/morluto/rea> · pinned **6.9.0** | MIT (upstream LICENSE; npm `license` field), Copyright (c) 2026 morluto | Optional deep-static binary layer. The analyst installs it by hand (`npm install --global rea-agents@6.9.0`), and only static commands run. | `intel_engine/BinaryPivot/references/rea.json`, `intel_engine/BinaryPivot/tools/bp_rea.py` |
| Pele | <https://github.com/obsidianmd/pele> · npm **1.8.0** (sha512 integrity pinned) | MIT, Copyright (c) 2026 kepano. Its LICENSE also carries an ISC notice for one Lucide icon. | Mermaid → SVG renderer. It is fetched at install time or on first render into the gitignored `intel_engine/IntelGraph/vendor/pele/`, and its `LICENSE` is extracted alongside the module. | `intel_engine/IntelGraph/references/pele.json`, `intel_engine/IntelGraph/scripts/pele_fetch.py`, `pele_render.mjs` |
| diagrams | <https://github.com/mingrammer/diagrams> · unpinned | MIT, Copyright (c) 2020 MinJae Kwon | Cloud-architecture figure. It is provisioned on demand with `uv run --with diagrams`. | `scripts/cti_cloud_arch.py` |
| book-to-skill | <https://github.com/virgiliojr94/book-to-skill> · v1.4.0 | MIT, Copyright (c) 2025 virgiliojr94 | Maintainer-side PDF/EPUB extractor for research fold-ins. It lives outside the tracked tree. | `docs/research-sources.md` (Method, Next fold-in) |
| Hayabusa · Takajō · Suzaku | <https://github.com/Yamato-Security/hayabusa> · <https://github.com/Yamato-Security/takajo> · <https://github.com/Yamato-Security/suzaku> | AGPL-3.0 | Named only, as the engines that run the indexed rules on the consumer's own logs. cti-expert never bundles or runs them. | `hunt_rules_yamato.json` (`runs_with`) |

---

## 5. Standards and frameworks with terms of use

### MITRE ATT&CK®

- **Source:** <https://attack.mitre.org>; terms at
  <https://attack.mitre.org/resources/legal-and-branding/terms-of-use/>.
- **Terms (verified):** MITRE grants a non-exclusive, royalty-free licence to use ATT&CK for
  research, development and commercial purposes. Any copy must reproduce MITRE's copyright
  designation and the licence.
- **Use:** technique and tactic IDs, plus names in prose, are used to tag hunts, rules and findings.
  No ATT&CK dataset is copied into the repository.
- **Location:** `hunt_packages.json`, `hunt_rules_yamato.json`, `handbook/intrusion-modeling.md`
  §7, `workflows/wf-threat-analyst.md`.
- **Attribution:**
  > © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of
  > The MITRE Corporation.

### Detection Rule License (DRL) 1.1: summary

- **Text:** <https://github.com/SigmaHQ/Detection-Rule-License>; the same text appears in the
  `hayabusa-rules` / `suzaku-rules` LICENSE files.
- **Summary (verified against the upstream text):** use, copying, modification and distribution of
  the rules are permitted free of charge. **When sharing the rules** (modified or not), keep:
  1. the rule's `author` and anyone else designated for attribution;
  2. a link to the rule set or rule;
  3. a statement that the rules are under DRL 1.1, with its text or a link to it.

  **When using the rules on data**, messages based on matches must keep the rule's `author`. The
  rules are provided "as is", without warranty.
- **Use here:** cti-expert shares only metadata and links (section 3). It keeps every `author`
  verbatim so that consumers can meet the match-attribution condition.

### OASIS STIX 2.1

- **Source:** <https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html>, OASIS Standard,
  2021.
- **Terms (verified on the specification page):** the document may be copied, and derivative works
  that help implement it may be distributed, provided the OASIS copyright notice and that section
  are kept. The document itself may not be modified. The page shows "Copyright © OASIS Open 2022.
  All Rights Reserved."
- **Use:** the STIX exporter implements the specification (SCO UUIDv5 ids, timestamps, required
  indicator fields, the official TLP 2.0 marking-definition ids). No specification text is
  reproduced, so the notice condition does not apply to the code.
- **Location:** `scripts/generate-cti-iocs.py` (`build_stix`), `techniques/ioc-export.md`.

### FIRST Traffic Light Protocol (TLP) 2.0

- **Source:** <https://www.first.org/tlp/>.
- **Terms: not verified.** The standard page sets no reuse licence. Its footer reads "Copyright ©
  2015—2026 by Forum of Incident Response and Security Teams, Inc. All Rights Reserved."
- **Use:** the label names (CLEAR / GREEN / AMBER / AMBER+STRICT / RED) and their sharing semantics
  are applied to report and export markings. The definitions are not reproduced.
- **Location:** IntelReport TLP table, `commands/cti-report.md`, the STIX exporter markings.

### FIRST CVSS v3.1

- **Source:** <https://www.first.org/cvss/v3.1/specification-document>.
- **Terms (verified on the specification page):** FIRST licenses CVSS to the public free of charge.
  Users must state that CVSS is owned by FIRST and used by permission. Anyone who publishes scores
  must follow the specification and give both the score and the vector.
- **Use:** the base-metric equations, constants and Roundup are implemented so that code, not the
  model, computes a score from a vector.
- **Location:** `docs/evaluation-hygiene.md` §2 and the local evaluation scorer.
- **Attribution:**
  > CVSS is owned by FIRST and used by permission.

---

## 6. Research works cited

The ideas below were read and restated as procedures, each cited `[ID …]` in the module that uses
it. No text, figure or table is reproduced. The source PDFs and their extracted text stay outside
the repository. The full register, with read status and landing paths, is
[`docs/research-sources.md`](docs/research-sources.md).

### Heuer, *Psychology of Intelligence Analysis* (CIA Center for the Study of Intelligence, 1999)

- **Source:** <https://www.cia.gov/resources/csi/books-monographs/psychology-of-intelligence-analysis-2/>.
- **Terms: not verified.** The book page states no reuse terms; check the publisher's terms before
  reproducing any of it.
- **Use:** the ACH steps and the bias checks are restated in our own words in
  `handbook/analytic-standards.md` §3–4, `workflows/wf-threat-analyst.md` (Bias Controls) and
  `analysis/cross-reference-engine.md` §3.

### OHCHR & UC Berkeley Human Rights Center, *Berkeley Protocol on Digital Open Source Investigations* (2022)

- **Source:** <https://www.ohchr.org/sites/default/files/2024-01/OHCHR_BerkeleyProtocol.pdf>.
- **Terms (verified from the PDF's imprint page):** "© 2022 United Nations. All rights reserved
  worldwide." Requests to reproduce excerpts go to the Copyright Clearance Center; other rights
  queries go to United Nations Publications.
- **Use:** its principles, collection planning, capture fields, chain of custody and verification
  steps are restated as procedure, with no excerpts. They land in
  `handbook/collection-preservation.md`, with cross-references in `wf-threat-analyst.md` and
  `analytic-standards.md`.

### Other papers and articles

Their licences are **not verified**; each work stays under its publisher's terms. They are cited as
`[Pxx]` / `[Rxx]` in the modules named in `docs/research-sources.md`:

- Caltagirone, Pendergast & Betz, *The Diamond Model of Intrusion Analysis* (2013)
- Daszczyszak et al., *TTP-Based Hunting*, MITRE MTR180158 (2019)
- Strom et al., *MITRE ATT&CK: Design and Philosophy* (2018, rev. 2020)
- Bianco & Fetterman, *PEAK Threat Hunting Framework*, Splunk SURGe (2023)
- Bianco, *The Pyramid of Pain* (2013, rev. 2014)
- MITRE, *Cyber Analytics Repository*
- Bilge et al., *EXPOSURE*, NDSS 2011
- Antonakakis et al., *Notos*, USENIX Security 2010
- Schüppen et al., *FANCI*, USENIX Security 2018
- Antonakakis et al., *Understanding the Mirai Botnet*, USENIX Security 2017
- Soska & Christin, *Longitudinal Evolution of the Online Anonymous Marketplace Ecosystem*, USENIX
  Security 2015
- Nunes et al., *Darknet and Deepnet Mining for Proactive Cybersecurity Threat Intelligence*, IEEE
  ISI 2016
- Li & Liao, *Appraisal Systems in the Underground Marketplaces*, NDSS 2024
- Thomas et al., *Trafficking Fraudulent Accounts*, USENIX Security 2013
- Narayanan et al., *Internet-Scale Author Identification*, IEEE S&P 2012
- Narayanan & Shmatikov, *De-anonymizing Social Networks*, IEEE S&P 2009
- Perito et al., *How Unique and Traceable Are Usernames?*, PETS 2011
- Meiklejohn et al., *A Fistful of Bitcoins*, ACM IMC 2013
- Huang et al., *Tracking Ransomware End-to-end*, IEEE S&P 2018
- Kappos et al., *An Empirical Analysis of Anonymity in Zcash*, USENIX Security 2018
- Arp et al., *Dos and Don'ts of Machine Learning in Computer Security*, USENIX Security 2022
- Alam et al., *CTIBench*, NeurIPS 2024 Datasets & Benchmarks
- Cheng et al., *CTI2TTP*, arXiv 2605.25836v2 (2026 preprint)
