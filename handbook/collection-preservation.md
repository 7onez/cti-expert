# Collection & Preservation — operating standard for online evidence

Operating procedure for **any item a finding will rest on**: a scam page, a kit bundle, a panel
screenshot, an archived snapshot, a document pulled from a host.

- **Trigger:** you are about to fetch, capture or cite online content in a case.
- **Inputs:** the case scope (`/scope`), the egress posture, the item URL, and the question the item
  is meant to answer.
- **Output:** a hashed capture with a manifest, a custody record (§6), and a verification note
  (§7) that the report cites by digest, not by path.
- **Abstain when:** the risk check (§2) says no-touch and no passive copy exists. Record the item
  as a collection gap; do not fetch it anyway.

Source: [R01 Berkeley Protocol, OHCHR 2022] (OHCHR / UC Berkeley Human Rights Center, *Berkeley
Protocol on Digital Open Source Investigations*), cited by chapter and paragraph (¶). The Protocol
is written for international criminal and human rights accountability. Everything marked
**(adaptation)** is our CTI operating rule, not a claim made by the Protocol. This is not legal
advice: admissibility rules differ by jurisdiction (R01 ch. III).

---

## 0. The cycle and where cti-expert already does it

R01 ch. VI describes six phases that repeat as new leads appear (¶140): online inquiry,
preliminary assessment, collection, preservation, verification, investigative analysis. "Selection"
is the decision the preliminary assessment ends in. The Protocol puts preparation (ch. V) before
the cycle and reporting (ch. VII) after it.

| Phase | R01 | What cti-expert already has |
|-------|-----|-----------------------------|
| Preparation: risk check | ch. IV.B, V.A, Annex II | `/scope` (no-touch class, victim ownership, egress gate); the harness `hostile=True` hard denial; `/cti-proxy`; passive-first rule ([`techniques/web-pivot.md`](../techniques/web-pivot.md) "Authorization first") |
| Preparation: plan | V.C, Annex I | `case_scope` intake record; [`wf-threat-analyst.md`](../workflows/wf-threat-analyst.md) Phase 1 Tasking |
| Online inquiry | VI.A | discovery paths in wf Phase 2; `tool_calls` ledger (every tool call per case); `api_usage` ledger |
| Preliminary assessment / selection | VI.B | `domain_liveness`, `takedown_watch`, binary and sandbox gates (SKILL.md §2.5) |
| Collection | VI.C, Annex IV | `capture_evidence` (raw DOM + JS + CSS + source maps, per-file sha256, `capture_sha256`); `capture_screenshot` (rendered PNG, sha256, manifest); `wayback_fetch`; `doc_metadata`; `pivot_extract --case` auto-capture |
| Preservation | VI.D | timestamped, never-overwritten capture dirs under `cases/<case>/evidence/`; `verify=true` re-hash that seals an intact original read-only; append-only `evidence/custody.jsonl`; working copies under `evidence/work/`; seeded fixity sampling (`fixity_sample=N`); `evidence_report` master ledger |
| Verification | VI.E | `origin_history`, `case_timeline`, `cert_overlap`, `reference_check`, `/verify-finding`, Admiralty grading via `evidence_import` |
| Investigative analysis | VI.F | [`intrusion-modeling.md`](intrusion-modeling.md), [`analytic-standards.md`](analytic-standards.md), `case_clusters` |
| Reporting | ch. VII | [`report-template.md`](report-template.md) §7, §8, Appendix A; `evidence_images[]`; house report evidence ledger |

---

## 1. Principles (R01 ch. II)

| R01 principle | What it asks | Our rule (adaptation) |
|---------------|--------------|------------------------|
| Accountability ¶25 | document every step from finding material to reporting; record the tools used; automated tools must be explainable | the `tool_calls` ledger and capture manifests are the record. A capture you cannot explain (what fetched it, rendered or not, what was skipped) is not cited |
| Competency ¶26 | trained staff, report gaps in content honestly, consistent procedures | read `skipped_for_budget` and `errors` before calling a bundle complete; use this file as the procedure |
| Objectivity ¶27 | multiple working hypotheses; search engines, browser and location bias results | ACH ([`analytic-standards.md`](analytic-standards.md) §3); vary engines (`search_pivot`); a cloaked page can show the analyst's egress something different from the victim's (`serp_ads`) |
| Legality ¶28 | public is not free of privacy duties; mosaic effect; persistent monitoring may need extra safeguards | web-pivot "Minimize" rule; cluster infrastructure and operators, not individuals; personal data is incidental |
| Security awareness ¶29 | minimise the digital trail; threat and risk assessment before going online, reviewed during the case | §2 below |
| Accuracy ¶30 | rely on credible material; acknowledge weaknesses; no overstated conclusions | claim discipline and attribution rails (SKILL.md §2.5) |
| Data minimisation ¶31 | collect only what is justified, necessary and proportionate; prefer itemised over bulk collection | capture budgets (`references/capture.json`); collect the funnel pages a finding needs, not whole sites, unless the question requires it |
| Preservation ¶32 | prevent under-collection too: content is removed, edited, decontextualised | capture early on fresh scam hosts; they are taken down in days |
| Security by design ¶33 | non-attributable, patched infrastructure by default, in place before collection | `/cti-proxy` pool; the egress gate fails closed |
| Dignity, humility, independence, transparency ¶34–38 | protect witnesses and bystanders; correct errors; avoid conflicts; avoid misrepresentation online | §8 below; `/engage` stays gated because a persona is a misrepresentation the report must disclose (¶38) |

---

## 2. Digital security and risk check before collection (R01 ¶68–77, ¶110, Annex II)

R01 asks for a threat and risk assessment before any online activity, particularly before visiting
target sites (¶110). It names assets (investigators, sources, witnesses, victims, bystanders,
data; ¶72), harms (digital, financial, legal, physical, psychosocial, reputational; ¶73–77), and
a target that is technically aware enough to evade or mislead the investigation (¶70). Minimum
standards (¶68): stay non-attributable, assume you are being watched, do not over-use one source,
avoid predictable patterns.

Run this per case, and again when the posture changes (adaptation):

1. **Posture.** `/scope CASE-…`: is any host no-touch? Is the victim's infrastructure involved
   (`victim_profile`)? A no-touch host gets passive collection only: urlscan, Wayback, prior scans.
2. **Egress.** Hostile infrastructure is fetched only through `/cti-proxy` (confirm the egress IP
   with `proxy.py test`) or not at all. Your egress IP is a selector the operator can see
   (SKILL.md "Egress control").
3. **Detonation and accounts.** Binaries, sandbox submissions (`anyrun_submit`, `webamon_scan`) and
   `/engage` each have their own confirm-first gate. Collection does not bypass them.
4. **Deception risk.** Expect cloaking: geo, user-agent or referrer gating and bot traps. Record
   what the page served to *your* client (¶70 adaptation); never assume it is what victims saw.
5. **People at risk.** Note whose data the item will expose (victims in a "recent payouts" widget,
   a compromised site's owner) before collecting it (§8).

---

## 3. Investigation plan (R01 ¶115–121, Annex I)

R01 asks for a written plan before starting: objectives and priorities with a timeline (¶116), the
risk strategy from §2 (¶117), other actors already preserving the content (¶118), resources
(¶119), roles (¶120) and documentation that can later explain the steps taken *or not taken*
(¶121). For cti-expert the plan is the `case_scope` record plus wf Phase 1 Tasking (adaptation):

- research question and success criteria (Tasking table);
- the claim under test and the levels it may reach: same infrastructure, same operator, named
  person (attribution rails);
- posture and egress from §2;
- who else preserves it: urlscan, Wayback, sandbox corpora. Their copies are independent captures
  from their own egress (¶118);
- the collection budget and which items need probative capture (§4.3).

---

## 4. The online inquiry steps (R01 ch. VI)

### 4.1 Search and monitoring (¶141–146)
Start from a stated question and record facts, assumptions and unknowns separately (¶142). Track
the pathway to each relevant item (terms, operators, engine) but not every result (¶142(d)).
Monitoring lists record why each source is watched, who watches it and how often (¶143(a)), and
automated tools are logged with name and version (¶143(c)). **Map:** `tool_calls` ledger; wf
Phase 2 collection rules; `case_drift` and `takedown_watch` for monitoring.

### 4.2 Preliminary assessment and selection (¶147–152)
Before collecting, check five things and record the answer: **relevance** (why this item; tag it to
a host, date or finding; ¶148), **reliability** prima facie (metadata, links, original source;
¶149), **removal** risk (if high, collect the best version now and keep looking for earlier ones;
¶150), **safety** of the item itself (¶151), and **duties** that follow from holding it (¶152).
**Map:** `domain_liveness` (a parked or soft-404 page is not live), `takedown_watch` (held or
deleted), the binary rule (an offered APK or EXE is not fetched to a connected system).

### 4.3 Collection (¶153–156)
Match the method to the use: a screenshot can be enough for internal work product, while
probative content needs hashed capture (¶153). Collect in the native format and document any
transformation the collection caused (¶154). **Map:** for any item a finding rests on, take
**both** `capture_evidence` (bytes as served; the manifest says `HTTP GET` or rendered) **and**
`capture_screenshot` (what a human saw). Together they meet the Protocol's stated minimum of URL,
HTML source and full-page capture (¶155). Add `wayback_fetch` or a prior urlscan DOM as an
independent third-party copy where one exists.

### 4.4 Preservation (¶157–175) — see §6.

### 4.5 Verification (¶176–194) — see §7.

### 4.6 Investigative analysis (¶195–207)
Process working copies only and document the processing (¶197). Be aware of bias when algorithms
or NLP process the data (¶197); for LLM extraction steps see
[`docs/evaluation-hygiene.md`](../docs/evaluation-hygiene.md) §2. Include personal data in products
only where it serves a direct investigative purpose (¶199). **Map:** the modelling and judging
handbooks; `case_clusters` before any same-operator claim.

---

## 5. What to capture per item (R01 ¶155(a)–(h), Annex IV)

| Field | R01 | Where cti-expert records it | Gap |
|-------|-----|-----------------------------|-----|
| URL, final URL | ¶155(a) | `seed_url` / `final_url` (capture); `url` / `final_url` (screenshot); redirect chain in `pivot_extract` meta | — |
| HTML source | ¶155(b) | `dom.html` in the capture bundle | — |
| Full-page capture | ¶155(c) | screenshot PNG, `full_page`, `title`, dimensions | — |
| Embedded media, scripts, styles | ¶155(d) | `files[]` with role, sha256, bytes, `fetched_at`; `skipped_for_budget` | budget drops must be read |
| Embedded metadata | ¶155(e) | `doc_metadata` for files and images | — |
| Context: surrounding page, uploader, comments | ¶155(f) | crawl pages (`--crawl`), screenshot `label`, `actions` (click-through gates) | manual |
| Collection data: collector, machine IP, virtual identity, UTC time | ¶155(g) | `captured_at` UTC; `collector` (+ `collector_source`), `persona`, `egress_ip` (+ `egress_proxy`, `egress_note`) in both manifests; screenshot `proxy` true/false | `egress_ip` is null (with the reason in `egress_note`) unless the analyst passes `--egress-ip` from `proxy.py test` or the proxy endpoint is a public IP literal — never looked up over the network |
| Hash | ¶155(h) | per-file sha256 plus bundle `capture_sha256`; PNG sha256 | — |
| Tool and version | ¶143(c), Annex IV | `capture_version` (`wp_capture/2`); screenshot `tool_version` (`wp_screenshot/2`), `browser`, `browser_version`, `playwright_version` | — |
| Clock source | ¶155(g) | `clock_sync` in both manifests: `state` (`synced` / `not_synced` / `unknown`), `source`, `checked_at`, read at collection start from the local time daemon (`timedatectl show -p NTPSynchronized`; commands in `WebPivot/references/custody.json`) | `unknown` where no local status is readable; no network time service is ever queried |

---

## 6. Chain of custody, originals and working copies (R01 ¶159–175)

- **Properties to keep** (¶159–165): authenticity (unchanged since collection, or every change
  documented), availability, identity (a unique ID), persistence (bits intact), renderability,
  understandability.
- **Chain of custody** (¶167): chronological record of every custodian, transfer, analysis and
  disposition.
- **Evidentiary copy** (¶168): keep a clean original in every format collected. **Working copies**
  (¶169): analyse a copy stored separately, and document every copy made.
- **Storage** (¶170–175): fixity checks, backups (R01 cites at least three copies on two media
  types with one off-site; ¶171), and periodic re-hashing of random samples to catch decay (¶172).

**Map:** capture dirs are timestamped and never overwritten, so a re-capture is a new observation,
not a correction. Run `capture_evidence verify=true` (or `wp_screenshot.py --verify`) before citing,
and cite `capture_sha256`. Chain of custody is implemented in `WebPivot/tools/wp_custody.py`:

- **Custody log** (¶167): `cases/<case>/evidence/custody.jsonl`, one JSON line per event with
  `utc`, `action` (`capture`, `verify`, `copy`, `export`, `transfer`, `cite`), `actor`, `item`
  (path relative to the case), `sha256`, `note` and `prev`. It is only ever opened for append, and
  `prev` is the sha256 of the line before: edits, removals and reordering are detected by the
  following line. The chain alone CANNOT detect tail truncation or a rewrite of the last line.
  Every append returns a `head` (`sha256`, `entries`, and `anchor` as `SHA256:COUNT`), recorded as
  `custody_head` in capture/screenshot manifests and verify/fixity outputs. Retain that anchor
  separately (for example with a reviewer), then run `wp_capture.py --check-log --case <case>
  --expected-head SHA256:COUNT` (also accepted by `--fixity`). It checks the anchored prefix even
  after valid appends. A head kept only beside the log is not an independent trust anchor.
  Writes are flushed and fsync'd; a missing final newline is terminated before the next append,
  never concatenated with it. Torn/malformed lines are reported distinctly and fail the check;
  they remain incomplete evidence, not silently repaired events. Capture, verify, working copy
  and fixity append automatically. Only `transfer`, `export` and `cite` may be recorded by hand:
  `wp_capture.py --custody transfer --case <case> --item <path> --digest <sha256> --note "…"
  --collector <who>`. An item's realpath must remain inside the case, including symlink targets.
- **Originals** (¶168): a capture that verifies inside a case store is sealed read-only (files
  `0444`, dirs `0555`, manifest included). Permission bits are not content, so every per-file
  sha256 and `capture_sha256` still match, and re-verification only reads. A capture that fails
  verification is never sealed. For screenshots the PNG is sealed; the per-case screenshot
  `manifest.json` stays writable because every new capture appends to it, and a report cites the
  PNG's sha256, never that manifest. `--no-seal` / `no_seal=true` skips sealing.
  Capture members may not be symlinks, escape the capture root, or be absent from the manifest
  (the configured asset directories may be empty). Screenshot manifest entries must stay in their
  case. POSIX verification pins no-follow descriptors, hashes them, checks their inode metadata,
  and seals those same descriptors with `fchmod`; replacing a pathname cannot chmod its target.
  Capture directories are reserved atomically and PNGs created exclusively, suffixing collisions.
  On Windows or platforms without `O_NOFOLLOW`/directory-relative opens, `lstat` checks refuse
  observed symlinks but cannot offer the same atomic anti-reparse guarantee.
  On Windows without `fchmod`, verification still runs normally; sealing is skipped and logged
  separately as `sealed: false, seal_status: unavailable_on_platform`, with its reason.
  If the chmod itself fails after the content matched (read-only mount, `EPERM`,
  `NotImplementedError`), the item stays `ok`/`MATCH` and is reported and logged as
  `sealed: false, seal_status: failed` with the error reason — never as `TAMPERED`.
- **Working copies** (¶169): `wp_capture.py --working-copy <capture dir | screenshot PNG>` (harness:
  `capture_evidence working_copy=true`) verifies the original first, copies it writable to
  `cases/<case>/evidence/work/<same relative path>` (a second copy gets `-copy2`), checks the copy
  byte-for-byte and logs a `copy` event. The original is only read.
- **Fixity** (¶172): `wp_capture.py --fixity N --case <case> [--seed S]` (harness: `capture_evidence
  fixity_sample=N seed=S`) re-hashes a random sample of N stored captures and screenshots, drawn
  from the disk and from the custody log, so a capture whose whole directory has gone is reported
  as missing. It lists altered and missing files, logs a `verify` event per sampled item naming
  the seed, and checks the custody chain. Capture verification also compares the manifest bundle
  digest with the FIRST logged capture digest for that item; screenshots use the first logged PNG
  digest in preference to the writable manifest. Rewriting bytes and their manifest together is
  `TAMPERED`, never re-sealed, and logged as a failure. The seed is always reported. Scheduling it
  (cron, CI) is a deployment choice; the default N is in `WebPivot/references/custody.json`.

An ad-hoc `--outdir` capture outside `cases/<case>/evidence/` has no custody log and is not sealed:
it is not in a case store.

When `CTI_COLLECTOR` / `--collector` is unset, case manifests and custody actors use a stable
`collector-<hash>` pseudonym, not the raw OS login: the login is hashed with a randomly generated
per-case salt retained in `evidence/collector.salt`. Without a writable case salt, collector is
null with the reason; supply `CTI_COLLECTOR` for named accountability.

Public urlscan PNGs retrieved by `house_report_captures` also receive a capture custody line,
collection context and a manifest head. Their context and `retrieved_at` describe OUR retrieval
from urlscan.io, not urlscan's original target visit. `archived_at` / `captured_at` describe that
prior scan; its original collector, egress and clock-sync state remain unknown.

---

## 7. Verification: source, item, content (R01 ¶176–194)

R01 splits verification into three checks that are compared for consistency (¶176):

| Check | R01 tests | cti-expert tests (adaptation) |
|-------|-----------|-------------------------------|
| **Source** ¶177–182 | attribution to the original source; provenance as "first copy found online", not "first copy online" (¶178); credibility from posting history; independence; specificity; attenuation (contemporaneous is stronger) | RDAP/WHOIS registration, `origin_history`, earliest Wayback/urlscan capture, `case_timeline`. Say "earliest capture found", never "first published" |
| **Technical (the item)** ¶183–186 | integrity of the file; metadata (stripped or transcoded metadata describes the new file, not the original; ¶184); source code for hidden or manipulated content | `verify=true` hash match; `rendered` vs `HTTP GET`; `final_url` vs requested URL; `doc_metadata`; inline-script hashes and comments from `pivot_extract` |
| **Content** ¶187–194 | objectively verifiable facts; completeness (capture the whole item and its context; ¶192); internal consistency (¶193); external corroboration (¶194); watch for circular reporting (¶187) | does the page's claimed licence or company exist (`corp_registry`)? Do footer, WHOIS and payment details agree? Corroborate from an independent collection path; a feed that copied another feed is one source |

Rails stay in force: a matching kit, CDN or provider signal is a **lead**, not a same-operator
edge, and a verified page is not a verified operator.

---

## 8. Safeguards for third parties and witnesses (R01 ¶28, ¶34, ¶68(a)–(b), ¶76, ¶147, ¶188, ¶199, ¶208(d))

The Protocol names: the security of witnesses, survivors, other investigators, the accused and
others who could be harmed (¶34); not exposing or endangering sources or third parties through
online activity (¶68(a)–(b)); legal harm to bystanders implicated by findings (¶76); privacy in
the decision to collect (¶147) and the mosaic effect of combining datasets (¶28); caution, and a
forensic expert, before identifying a person from physical features (¶188); personal data in
products only for a direct purpose (¶199); and leaving material out to protect sources, witnesses,
victims and communities (¶208(d)).

CTI application (adaptation):
- **Scam victims** in panels, payout widgets or leaked lists are third parties, not subjects. Count
  them; do not profile them.
- **Compromised-site owners** are victims (`victim_profile`); their host is not the operator's.
- **Mosaic risk:** do not join breach, phone and handle data on a person who is not a subject.
- **Inclusion decision:** a person's data is either included in full where the purpose requires it,
  or omitted with the omission stated in §8 of the report. No partial asterisk masking. Client
  seeds follow the existing `sensitive` handling (report template §8a).
- **No face matching** as identification without the expertise R01 ¶188 calls for.

---

## 9. Reporting transparency (R01 ¶208–210)

R01 asks reports to show: accuracy, including exculpatory information and explained gaps
(¶208(a)); a clear split between public data and investigator judgement (¶208(b)); completeness
(¶208(c)); confidentiality (¶208(d)); neutral language (¶208(e)); and methods (¶208(f)). Written
reports cover objectives, methodology, activities performed, underlying data and sources, gaps
and uncertainties, and results with caveats (¶210).

**Map** to [`report-template.md`](report-template.md): Key Questions (objectives), §7 Source List
and Appendix A Sources Checked (data and sources, including nulls), §8 Caveats & Methodology
(methods, persona use, egress posture, what was **not** collected and why), §15 Open Questions
(gaps), `evidence_images[]` with sha256 and `captured_at`. Facts and judgements stay separate:
collected facts carry Admiralty grades; judgements carry likelihood terms.

---

## 10. Gaps → recommendations (not new commands)

R1–R6 are implemented as options of the existing `capture_evidence` / `capture_screenshot` tools and
`wp_capture.py` / `wp_screenshot.py`, not new commands.

| # | Gap against R01 | Status |
|---|-----------------|--------|
| R1 | manifests lacked collector, egress IP and persona (¶155(g)) | **done:** `collector`, `collector_source`, `persona`, `egress_ip`, `egress_proxy`, `egress_note` in both manifests; `--collector` / `--persona` / `--egress-ip` (env `CTI_COLLECTOR`, `CTI_PERSONA`, `CTI_EGRESS_IP`). Proxy credentials are never written |
| R2 | screenshot manifest had no tool version | **done:** `tool_version`, `browser`, `browser_version`, `playwright_version` |
| R3 | clock source not recorded (¶155(g)) | **done:** `clock_sync` {`state`, `source`, `checked_at`} from the local time daemon at collection start; `unknown` otherwise; never a network call |
| R4 | no custody / transfer log (¶167) | **done:** append-only, hash-chained `cases/<case>/evidence/custody.jsonl` (`utc`, `action`, `actor`, `item`, `sha256`, `note`, `prev`); manual entries via `wp_capture.py --custody ACTION` |
| R5 | originals writable; no separate working store (¶168–169) | **done:** verify seals an intact capture dir (or PNG) read-only; `--working-copy` / `working_copy=true` copies to `evidence/work/` and logs it |
| R6 | fixity only on demand (¶172) | **done:** `--fixity N [--seed S]` / `fixity_sample=N seed=S`; scheduling it is left to the deployment |
| R7 | retention, deletion and access policy (¶109) and 3-2-1 backups (¶171) sit outside the skill | state them in the deployment's data policy; cite it in report §8 |

---

## 11. Worked example — `pay-portal.example` (synthetic)

All names, addresses, times and digests are synthetic. Digests are shortened placeholders.

1. **Risk check.** `/scope CASE-0001` returns hostile, live fetch allowed through a proxy only. The
   research proxy egresses from `203.0.113.10:80`; `proxy.py test` confirms it. The page offers a
   "wallet app" APK: it is not downloaded (binary rule). A "recent payouts" widget lists first
   names, which are third-party data (§8).
2. **Plan.** Question: is `pay-portal.example/checkout/` a card-harvesting page, and is it the same
   kit as earlier findings? Ceiling: same kit / same infrastructure. Operator and person are out of
   scope.
3. **Inquiry.** urlscan and Wayback first. One urlscan scan (2026-11-08) and no Wayback capture.
   Both lookups appear in the `tool_calls` ledger.
4. **Preliminary assessment.** Relevant (card form posts off-site); reliability unknown; removal
   likely (registered 2026-11-06, abuse report pending); safe, if the APK is excluded.
5. **Collection.** With the `/cti-proxy` pool active (WebPivot tools install it at import),
   `capture_evidence` with `url=https://pay-portal.example/checkout/`, `case=CASE-0001`,
   `egress_ip=203.0.113.10` (from step 1's `proxy.py test`), then
   `wp_screenshot.py --case CASE-0001 --proxy … --egress-ip 203.0.113.10` for the rendered PNG.
   Manifests: `HTTP GET`, DOM + 14 JS + 3 CSS, two third-party fonts in `skipped_for_budget`;
   `collector: analyst-07`, `persona: null`, `clock_sync.state: synced`; screenshot `proxy: true`.
6. **Preservation.** `verify=true` → ok, 0 altered, 0 missing; the capture dir is now read-only.
   `--working-copy` puts the analysis copy under `evidence/work/`; the original is left untouched.
7. **Verification.** Source: RDAP shows a 2026-11-06 registration; `origin_history` shows
   `198.51.100.24`. The earliest capture found is the urlscan scan of 2026-11-08. Technical: hashes
   match; `final_url` equals the request; no redirect. Content: the footer names "Example Payments
   Ltd"; `corp_registry` finds no such entity; the form action posts to `collect.pay-portal.example`;
   the 2026-11-08 urlscan DOM has the same inline-script hash. Result: the same-kit lead holds at
   kit level. It is not an operator link.

Sample custody record:

```text
evidence_id     EV-0001-003            case  CASE-0001
item            https://pay-portal.example/checkout/  (final_url identical)
kind            capture_evidence bundle (HTTP GET) + capture_screenshot PNG
captured_utc    2026-11-10T08:14:22Z   clock_sync  synced (timedatectl NTPSynchronized)
capture_sha256  9f3c...e21a (synthetic)   png_sha256  41d7...0b5c (synthetic)
tool            wp_capture/2 / wp_screenshot/2, browser_version recorded
collector       analyst-07 (synthetic)  egress_ip  203.0.113.10 via /cti-proxy (proxy.py test)
context         DOM + 14 JS + 3 CSS; skipped: 2 third-party fonts; title "Secure Checkout"
third parties   payout widget first names: counted (9), not transcribed into the report
custody.jsonl (utc, action, actor, item, note; sha256 and prev omitted here)
  2026-11-10T08:14:22Z  capture   analyst-07   evidence/captures/pay-portal.example/_root/20261110T081422Z
  2026-11-10T08:20:05Z  verify    analyst-07   same item   ok; sealed read-only
  2026-11-10T08:22:40Z  copy      analyst-07   same item   working copy -> evidence/work/captures/…; byte-identical
  2026-11-12T10:03:11Z  transfer  analyst-07   same item   to reviewer-02; digest re-checked: match
  2026-11-14T09:00:00Z  cite      reviewer-02  same item   FND-004 cites capture_sha256
```

Report §8 then records: proxy egress, HTTP-only capture, skipped fonts, APK not collected, payout
names withheld and why, and the kit-level ceiling.

---

## Cross-references

- [`techniques/darknet-investigation.md`](../techniques/darknet-investigation.md) — Evidence
  Collection Standards (hash at capture, custody log line format)
- [`techniques/web-pivot.md`](../techniques/web-pivot.md) — authorization first, passive capture,
  `--save-dom` / `--submit`
- [`handbook/report-template.md`](report-template.md) — sources, caveats, open questions
- [`handbook/analytic-standards.md`](analytic-standards.md) — ACH and bias checks during analysis
- [`workflows/wf-threat-analyst.md`](../workflows/wf-threat-analyst.md) — Phase 2 Collection
