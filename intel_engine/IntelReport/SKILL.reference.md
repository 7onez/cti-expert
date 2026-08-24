---
name: IntelReport
description: Render a finished assessment MARKDOWN file into a polished PDF and/or editable DOCX via pandoc — muted editorial house template matching IntelGraph (cover page, TOC, running header/footer with classification + case id, embedded figures, Vietnamese-safe typography). Produces both PDF and DOCX by default. Bilingual EN/VI via --lang: the generated furniture (cover labels, TOC, "Phụ lục", figure/table captions) is localised and a Vietnamese-capable font picked, while the body stays the analyst's — with a fixed ICD-203 estimative glossary (--glossary) so the confidence scale does not drift in translation. USE WHEN make a PDF, export to Word/docx, produce the report, render the report, turn this into a document, beautiful report, deliverable, Vietnamese report, báo cáo tiếng Việt, report in Vietnamese, bilingual report, localise the report, Vietnamese deliverable, xuất báo cáo PDF.
---

> **OPSEC — this skill is portable/shared. Never write case data into it.** No real operator
> names, emails, domains, IPs, wallets, tracking IDs, hashes, or case IDs in this file, its
> template, tool code, or examples. Investigation data lives only in the git-ignored
> `cases/` / `knowledge/` / `MEMORY/`. Use placeholders (`example.com`, `CASE-0001`,
> `TLP:AMBER`). Reports never stamp an analyst name; the date defaults to UTC today.
> See the repo-root `CLAUDE.md` for the full rule.

# IntelReport — markdown → polished PDF / DOCX

Turn a finished assessment written in Markdown into a credible, print-native document.
The house style is the same understated editorial look as IntelGraph — muted slate/steel
palette, no gradients, generous margins, the kind of report a SOC analyst files, not an
auto-generated dashboard. **PDF** is the shareable deliverable; **DOCX** is the editable
copy a reviewer can redline.

## Report structure — house rules (follow for EVERY report)

These are the standing rules for the assessment markdown you hand to the renderer. The template
enforces the typography (Roman numbering, compact tables, wrapped code); YOU enforce the structure.

0. **Open with the DECISION this report supports — one sentence, before anything else.** The first
   line of Section I is a purpose statement naming the question the report answers *and* what the
   consumer is expected to do with the answer: *"This report assesses whether `site-a.example` and
   `site-b.example` are operated by a single party, and whether a named registrant can be linked to
   that operation, to support a registrar abuse referral and a platform enforcement decision."*
   Without it the reader cannot know **what threshold of proof applies** — a prosecutor, a platform
   trust-and-safety queue, a registrar abuse desk and a newsroom read the same evidence against
   different bars, and an unstated bar silently defaults to the reader's rather than the analyst's.
   - **Ask if it was not stated.** Bundle it with the audience and TLP questions (below) — the three
     are one decision, and they are asked BEFORE the report is written, not after it renders.
   - **A case with no external consumer still has a threshold.** Write it: *"…to support internal
     analytic reference; no external action is requested"* — that is Rule 18's consumer note, and it
     belongs in the purpose statement too.
   - **Restate the threshold in Methodology**, in one line, as the standard the judgments were
     written against (e.g. "findings are graded for an abuse-referral decision: an assessed
     same-operator link is actionable, a named individual is not asserted below *high confidence*").
1. **Important-first, detail-later.** Lead the document with the conclusion. Section **I** is always
   the **Executive Summary — Key Judgments (BLUF)**: the purpose statement (Rule 0), then a table of
   findings + attribution + confidence, before any narrative.
1a. **Write in IC / CIA estimative language.** The analyst voice is *"We assess…"*, *"We judge with
   high confidence…"*, *"…almost certainly…"*. Use the **ICD-203 / Sherman-Kent** probability words
   (almost certain / very likely / likely / roughly even chance / unlikely / very unlikely / almost
   no chance) in the PROSE, not just the tables — and never mix a percentage with the word in the
   same clause. State an explicit **confidence level** (low / moderate / high) for each key judgment.
1b. **Explanatory, cause-and-effect narrative — show the trail.** A reader (not just an analyst)
   must be able to FOLLOW how each finding was reached. Write it as *found → via → therefore*:
   name what you did, what it returned, and what that let you conclude. Prefer plain sentences over
   terse shorthand. Estimative words still carry the confidence, but the sentence explains itself.
   - Shorthand (avoid): *"Shared origin IP 203.0.113.10 (AS64500); same-day reg 2020-01-01 → same operator."*
   - Explanatory (use): *"When we reverse-looked-up the two sites' hosting, both resolved to the same
     server (203.0.113.10, a small VPS that hosts almost nothing else); and WHOIS shows both domains
     were registered on the same day through the same registrar. Because a shared private server and a
     same-day registration are things unrelated operators do not share by accident, we assess the two
     sites are run by one operator."*
1c. **Plain language, and a HUMAN voice the reader can defend.** The person who receives this report
   has to explain it — to a manager, an abuse desk, a court — often without you in the room. If a
   sentence needs you present to be understood, rewrite it. Two standing requirements:
   - **Define every technical term at first use, in plain words, then keep using the term.** The first
     time a report says JARM, favicon hash, passive DNS, RDAP, stealer log, snowflake, mmh3, write a
     short gloss in parentheses — *"a JARM fingerprint (a hash of how a server answers a TLS handshake;
     two servers set up the same way share it)"* — and add the term to the Glossary (Rule 23). A reader
     should never meet an unexplained acronym. Prefer the plain word where one exists (say "web address"
     once beside "URL", "the site's hosting" beside "origin IP").
   - **Write like a working analyst, not a model.** Short declarative sentences. Concrete nouns and
     verbs. This is what "no AI-generated feel" means in practice — and it matters because AI-sounding
     text reads as padded and evasive, which is the opposite of defensible. BANNED tells, because a
     reader trips on them: the "it's not just X, it's Y" and "not only … but also" constructions; the
     rule-of-three flourish ("clear, concise, and compelling"); throat-clearing ("it is important to
     note that", "it is worth mentioning"); inflated verbs ("delve", "underscore", "leverage",
     "navigate the landscape", "showcase", "testament to", "plays a pivotal/crucial role"); chained
     connectors ("moreover", "furthermore", "additionally" stacked); and hedging everything to the same
     mush. Say the thing plainly, once. When you mean "shows", write "shows".
   - **Test:** read a paragraph aloud. If it sounds like a brochure or a chatbot, it is wrong; if it
     sounds like a colleague explaining what they found and why they believe it, it is right.
2. **Table → info → context, in that order.** In every finding section, put the structured table
   first, then the tight bullet/number facts, then the prose context. Never open with a paragraph.
3. **Overview → Details in every long section.** If a section runs long, split it: a `## Overview`
   (2–4 lines) then `## Details`. The reader gets the gist without reading the whole section.
   **Write the heading text only — never type the number.** The template numbers sections itself,
   so `## 4.1 Overview` renders as "4.1 4.1 Overview". Same for appendix sub-headings.
4. **Roman top-level, arabic sub.** Use `#` for top-level sections (rendered `I`, `II`, …) and `##`
   for sub-sections (`I.1`, `I.2`). Appendices come after a raw-LaTeX `\appendix` marker and render
   as `Appendix A`, `Appendix B` (see below).
5. **Methodology section (required), placed EARLY.** Put `# Methodology` immediately AFTER the
   Executive Summary (i.e. Section **II**), before the findings — the reader learns *how* the
   investigation was conducted before reading *what* it found. State the tools and the collection
   process so the work can be reproduced or challenged.
5a. **Keep index columns narrow.** A leading `#`/`No.` column must not eat width — give it a tiny
   share by making its delimiter dashes short relative to the others, e.g.
   `| # | Judgment | … |` with `|:-:|:------------------|…|` (one dash for `#`, many for the rest).
   Pandoc allocates column width by the dash ratio. Better still, drop the index column unless rows
   are cited by number.
5b. **Page breaks are automatic.** The template starts every top-level section on a fresh page
   (`\sectionbreak=\clearpage`) — do NOT add manual `\newpage`. Author in **Markdown** and let
   `render_report.py` port to LaTeX; never hand-write LaTeX (markdown is far cheaper in tokens and
   pandoc does the conversion for free).
6. **Confidence via BOTH the NATO Admiralty matrix AND ICD 203.** Grade each source/artifact with an
   Admiralty code (source reliability **A–F** × information credibility **1–6**) and express each
   analytic judgment with an ICD-203 probability word. Include the two reference tables in Methodology:

   | Reliability | Meaning | | Credibility | Meaning |
   |---|---|---|---|---|
   | A | Completely reliable | | 1 | Confirmed by other sources |
   | B | Usually reliable | | 2 | Probably true |
   | C | Fairly reliable | | 3 | Possibly true |
   | D | Not usually reliable | | 4 | Doubtful |
   | E | Unreliable | | 5 | Improbable |
   | F | Reliability cannot be judged | | 6 | Truth cannot be judged |

   ICD-203 bands: *almost no chance* (01–05%) · *very unlikely* (05–20) · *unlikely* (20–45) ·
   *roughly even chance* (45–55) · *likely* (55–80) · *very likely* (80–95) · *almost certain* (95–99%).
7. **Appendix — artifact register (required).** The FIRST appendix is a table with ONE ROW
   PER ARTIFACT, columns: **Artifact · Value · Source (public class) · Admiralty grade** — this is the
   authoritative schema (Rule 13 restates it). "Source" is the PUBLIC source CLASS only — WHOIS,
   passive DNS / IP, certificate transparency, public web-scan data, live page — never a specific
   product/vendor, an internal file path, a tool/script name, or a "how we found it" column (that
   would leak methodology; see Rules 12 & 14). Grade every row with its Admiralty code (source
   reliability **A–F** × information credibility **1–6**).
8. **Wrap code in a code block.** Any config/JSON/command goes in a fenced ```` ``` ```` block — the
   template line-wraps it so it never overflows the page. Never paste code as prose.
9. **Compact, text-heavy tables are fine.** The template shrinks table font automatically; prefer a
   dense table over splitting facts into prose. Use grid tables when cells hold long text.
10. **No "prepared by" / analyst identity.** Never add a "Prepared by…", author, or sign-off line.
    The cover already carries the reference, date, and classification; that is the whole provenance block.
11. **External reference ≠ internal case id (OPSEC), tracked in a private registry.** The document
    displays a report reference (`report_id` / `--report-ref`) that DIFFERS from the internal case
    folder — a leaked report must not tie back to the store. The renderer **auto-maintains the map**
    in `cases/report_registry.jsonl` (git-ignored): it derives the internal case from the report's
    path under `cases/<id>/`, and if no reference is given it **reuses** the one already logged for
    that case (reproducible) or **mints** `RPT-YYYY-MMDD-NN`. Every render records
    `{report_ref → case_id, title, date, outputs}` there, so we can always resolve a reference
    privately (`grep <ref> cases/report_registry.jsonl`) while the shared PDF never carries the case id.
12. **Never expose internal working anywhere in the report.** No internal tool / script / MCP / API
    names (the collectors, the KB, the registry, Claude APIs), no internal file paths, no case-store
    ids. In the body and appendix, cite only **public source CLASSES** — WHOIS, passive DNS / IP,
    certificate transparency, public web-scan data, live page — never the specific product/service.

12a. **…but NEVER anonymise the EVIDENCE. Rule 12 restricts how we say we found something, never
    what we found.** These are two different categories and confusing them destroys the report.
    The test is **who authored the string**:

    | Category | Authored by | Rule |
    |---|---|---|
    | **Internal working** | *our* investigation — tool / script / MCP / API names, the KB, the case-store id, file paths, command lines, data-vendor product names | **Never appears.** Cite the public source CLASS instead. |
    | **Case evidence** | *the target* — domains, URLs, IPs, ASNs, hashes, favicon mmh3, cert fingerprints, registrant strings, wallets, handles, impersonated brand names, dates | **Always appears, literally.** This IS the deliverable. |

    A section headed "The seed and its lifecycle" that never states the seed's domain name, or a
    finding written as "a US wealth-management brand" instead of naming it, has **failed** — the
    reader cannot verify it, act on it, or follow the argument. Describing the *sector* of a brand
    is not OPSEC; it is an unreadable report.

12b. **Name every reference at FIRST MENTION in the body — not only in the appendix.**
    - **The SEED is named in the Executive Summary**, and again in the first line of the section
      that analyses it. A reader must never reach the appendix to learn what the case is about.
    - **First body mention of any indicator carries its literal value**: write
      `login.site-a.example (203.0.113.10 · AS64500)`, not "the login host". Later mentions may
      shorten once the value has been given.
    - **Impersonated brands are named** — "imitates *Example Brokerage Ltd*", never "a large broker".
    - **Every claim carries the reference it rests on.** If a sentence asserts a shared artifact, the
      artifact's value appears in that sentence or in its table row.
    - **Enumerate the cluster.** If the finding is "N domains", an appendix lists all N by name.
    - Vague (fails): *"Two members share a favicon; the seed imitates a broker."*
    - Named (passes): *"`site-a.example` and `site-b.example` both serve favicon mmh3 `123456789`;
      the seed `site-a.example` imitates Example Brokerage Ltd."*
13. **Appendices = collected EVIDENCE only.** They carry the artifact register (**Artifact · Value ·
    Source (public class) · Admiralty grade**), the evidence ledger (Rule 21), the per-domain
    profiles (Rule 17) and the cluster enumeration (Rule 12b) — and nothing else. No "how we found
    it", no file paths, no reproduction/credit-log appendix. What we observed, not how our harness
    observed it.
14. **Methodology overview = general OSINT tradecraft, not our process.** Describe the *method*
    (start from seeds → **pivot** outward → form a **hypothesis** → **prove or disprove** it against
    independent data sources → weight owner-controlled evidence, state the alternative ruled out),
    never the specific tools/commands. The NATO + ICD reference tables still follow.
15. **EVERY findings section carries a figure. This is MANDATORY, not a nicety.** Invoking
    IntelReport ALWAYS chains to IntelGraph. A report that renders with zero figures has failed the
    checklist — go back and author them before presenting. The rule is **one figure per top-level
    findings section** (III onward: the seed, each cluster/entity, the attribution argument, the
    rejected links), plus one whole-case overview at the end. Executive Summary and Methodology
    need none.
    - **The figure's job is to show HOW the connection was made, not to decorate.** A reader should
      be able to read the picture alone and follow *observed artifact → link it creates → what we
      concluded → with what confidence*. Label the EDGES with the evidence (`shared favicon
      123456789`, `same-day registration`, `regulator register`), not with vague verbs.
    - **Mark the verdict on the graph.** Confirmed links solid, assessed/probable links dashed,
      **rejected links dotted and struck through with the reason** (`✗ parking IP — co-tenancy
      noise`). A figure that shows only what survived hides the analysis; showing the discarded
      branch is what makes the attribution credible.
15a. **Place each figure INLINE, beside the claim it proves — never silo evidence in an appendix.**
    A screenshot of the operator's channel, a crew card, a leaked-record panel is *the proof of a
    specific sentence*; it belongs in the paragraph that makes that sentence, so the reader sees the
    claim and its picture together and can digest the argument without cross-referencing. A findings
    section that is a wall of text with its images parked pages away at the back has FAILED this rule
    even though the images exist — a reader hits the claim, has nothing to look at, and the evidence
    they needed is 8 pages later divorced from what it supports.
    - **The narrative order and the figure order are the same order.** Put the figure immediately
      after the paragraph whose finding it evidences (admin-handle screenshot under the admin-handle
      subsection, timeline figure under the timeline section). If one subsection makes three claims
      each with its own screenshot, all three figures go in that subsection, in the order the claims
      are made.
    - **There is no separate "Visual evidence" appendix.** Screenshots are findings evidence, so they
      render inline; the *evidence ledger* (Rule 21) is what carries the one-line-per-capture index
      (URL, capture time, full hash) — the picture proves the point in the body, the ledger lets a
      reader re-verify and re-fetch it. Do not embed the same image twice (inline AND in an appendix).
    - **Screenshots are captured, hashed, timestamped evidence**, not decoration: caption each with
      what it shows, when it was captured (UTC), and — if it was taken after an interaction (a splash
      gate, a tab) — say so, because a capture that clicked through a gate must disclose it. A capture
      tool that records a per-capture manifest (url, captured_at, sha256, actions) is the source for
      both the caption and the ledger row.
16. **Two figure kinds — use both.** `figures.json` (sibling of the markdown) takes a *list*, and
    `render_report.py` rebuilds every entry through IntelGraph immediately before rendering, so no
    chart is ever stale. Opt out only with `--no-figures`.
    - **COLLECTED — a case graph from the raw collection JSON.** Best for "these N hosts share these
      artifacts". Prune noise node types so the meaningful nodes render large:
      `{"raw":["../raw/a.json", …], "graph":"cluster_a.json", "stem":"fig_cluster_a",
      "title":"…", "direction":"LR", "legend":true,
      "drop_types":["nameserver","registrar","template","theme","email"]}`
      Also accepted: `"scale"` (device pixel ratio for the hi-res PNG, default 2), `"width"`,
      `"split_clusters"`, `"all_edge_labels"`, `"inline_legend"`, and `"pdf"` (default **true** —
      the vector figure the PDF build embeds; set false to skip that render).
      **`"legend": true` on a multi-cluster graph produces a COMPANION figure**
      `<stem>_legend_hires.png`, because an inline legend box overflows its own title and eats a
      third of the figure. Embed it beside the graph — the render warns if a rendered figure,
      legend or otherwise, is never referenced in the markdown.
    - **REASONING — a hand-authored Mermaid source.** Best for the argument a collected graph cannot
      express: corporate/entity structure, an ownership timeline, the inference chain from artifact
      to attribution, the alternative hypothesis that was ruled out:
      `{"mmd":"fig_attribution.mmd", "stem":"fig_attribution", "theme":"neutral"}`
      Author the `.mmd` next to the markdown (`flowchart LR`, or `timeline` / `gantt` for chronology)
      and let the renderer produce the PNG/SVG triple.
    - Embed the result as a centred block; the renderer sets `\graphicspath` so a raw
      ` ```{=latex}\begin{center}\includegraphics[width=...]{fig_x_hires.png}\end{center}``` `
      resolves. Follow every figure with a one-line italic caption stating what it proves.
    - **Multiple small figures beat one dense overview.** Three focused graphs are followed far more
      easily than one 30-node hairball. Build each section's figure from only that section's hosts.
    - **Keep labels short or the figure prints unreadable.** A figure is scaled to the text block
      (~16 cm), so its rendered PIXEL WIDTH sets the type size: at 1000 px wide the labels print
      around 7 pt; at 1700 px they print under 4 pt and no one can read them. Cap node labels at
      ~8 words / 3 short lines, collapse a fan of sibling nodes into one multi-line node, and switch
      `LR`→`TB` when a chain runs long. **Check the rendered width** — if `<stem>_hires.png` comes
      back wider than ~1200 px, cut text or restructure, don't just shrink the `includegraphics`
      width. The detail belongs in the prose; the figure carries the argument.
    - **A Mermaid `subgraph` title does not reserve vertical space when it wraps.** A title longer
      than its box renders the second line *underneath the first node*, so the identifier you most
      wanted read is the one that vanishes — and the `.mmd` source looks perfectly correct either
      way. Keep subgraph titles to a few words (`Victim DNS zone`) and put the domain or IP in a
      NODE, which lays out properly. **Open the rendered PNG before shipping**; this class of
      defect is invisible in the source.

17. **Always include per-domain profiles.** A report must carry a "Domain & infrastructure profiles"
    appendix — one small **Field · Value** table per domain covering, at minimum: status
    (live / dead / parked), registrar + **created** date, registrant (country / org, noting privacy
    masking), nameservers, origin host (IP · ASN), and the **distinctive artifacts** found on that
    site (favicon mmh3, TLS SHA-256, analytics/telemetry ids, tech stack, contact handles, notable
    sub-sites). This is the WHOIS + unique-findings dossier a reader expects for every domain in scope.

18. **Close with what the reader should DO — recommendations scoped to the DECISION in Rule 0.** An
    assessment that stops at attribution leaves the consumer holding facts with no action. Include a
    short **Recommendations** section covering, as they apply: the **reporting / referral pathways**
    (which registrar, host, telemetry vendor or constituency to notify — mirror the victim-side
    provider list from IntelAnalysis VictimProfile when there is one), the **preservation targets**
    that decay (a live page, a cert, a WHOIS record about to be re-privatised), and the pivots the
    consumer's own access could close that ours could not. If the report is purely for an internal
    analytical audience with no action expected, say so explicitly in a one-line **Consumer note**
    ("intended use: analytic reference; no external action requested") — a reader of a TLP:AMBER
    product should never have to guess what they may act on.

18a. **Defensive content is a SEPARATE product — do not bulk it into an investigation report.**
    An IOC block, detection/hunt rules, YARA/Sigma, and ATT&CK technique mappings belong in a report
    only when the named consumer (Rule 0) is a **security-operations / IR team**. In an attribution
    report written for enforcement, referral, or publication they are three kinds of wrong at once:
    **noise** (they push the attribution argument down the page), **premature** (a hunt rule implies
    operational confidence the case may not carry), and **misleading** (they frame the product as
    defence when its purpose is understanding). The *artifacts themselves* still appear — in the
    findings, the per-domain profiles (Rule 17) and the artifact register (Rule 7), because those are
    evidence. What is excluded is the packaging of them as a detection deliverable.
    - When defenders also need serving, produce a **derivative one-page tactical bulletin**: a
      separate render (`<report>_bulletin`) carrying the hunt-ready artifacts (favicon mmh3, TLS
      SHA-256 / JARM, cookie and kit-path patterns, backend IPs/ASNs), its own TLP marking, and a
      one-line pointer to the report reference it derives from. Never overwrite the investigation
      report with it.

19. **The technical report is the FULL build — every finding, no sampling, no truncation.** The
    Technical profile carries the whole case: every surviving finding, every cluster member by name,
    every artifact that supports or was rejected. **"…and 12 other domains", "representative
    examples", "selected indicators" are defects**, not concision — a reader auditing the argument
    cannot re-check a finding that was summarised away, and a finding worth omitting was worth
    stating as weak. Length is not a cost here; an unverifiable claim is.
    - **Weak and negative findings are reported, not dropped.** A pivot that returned nothing is a
      line in the report ("reverse-WHOIS on the registrant email returned no other domains"), because
      absence of a result and absence of a search look identical to the reader otherwise — and on a
      keyless / passive / blocked run the difference is the whole meaning of the result.
    - **Only two things may shorten a report**: a TLP downgrade (Rule: *Downgrading is a redaction
      job*) and victim-identifier redaction. Both must be stated where the cut was made
      (*"three compromised third-party hosts are withheld at this marking"*), never done silently.
    - The Executive and Law-Enforcement profiles re-emphasise; they do not re-scope. If a shorter cut
      is wanted, render it as an ADDITIONAL output stem — the full technical build always exists.

20. **Timeline section (required) — the case's lifecycle, with the figure and the contemporaneity
    judgment.** A findings section devoted to WHEN: registration cohorts, registrant eras, hosting
    windows, certificate issuance batches, archive visibility, campaign start and (if it lapsed) end.
    Its job is to answer a question every attribution rests on and most reports skip: **were the
    linked facts contemporaneous?** A shared registrant that predates the current operator by three
    years, or a co-tenancy window that closed before the second domain existed, is not a link — and
    only a timeline shows it. State it explicitly per link ("the joint SANs are 103 days apart, well
    inside the operator's observed re-issue cadence" / "the shared IP windows do not overlap").
    - Build it from the case's collected JSON rather than by hand — one command emits the figure,
      the dated-event ledger (Rule 21) and the derived cohorts from the SAME source, so the picture
      and the table cannot disagree:

      ```bash
      python3 ~/.claude/skills/IntelGraph/scripts/case_timeline.py cases/CASE-0001/out/*.json \
          --stem cases/CASE-0001/fig_timeline --markdown --title "Infrastructure lifecycle"
      ```

      Its *Temporal correlations* block (registration cohorts, expiry/renewal cohorts, same-day
      WHOIS updates, certificate batches, IP tenancy overlap, shared-artifact windows, abandonment
      cohorts) is the raw material for this section — write the judgment, cite the rows.
      **Read its empty-set caveat literally**: "nothing found" there is a finding only if the inputs
      carried the dates to find it in.
    - This section carries its own figure under Rule 15; a `timeline` / `gantt` Mermaid source is the
      alternative when the argument is a sequence rather than a set of spans.

21. **Evidence ledger appendix (required) — every dated fact, cited to a link that resolves for
    someone who has never seen our disk.** Distinct from the artifact register (Rule 7), and both
    appear: the register answers *what we hold*, the ledger answers *when it was true and where
    anyone can re-check it*. One row per dated claim, in the columns the timeline tool emits:

    | When (UTC) | Host | What | Source (Admiralty) | Evidence link |
    |---|---|---|---|---|
    | 2026-01-02 → 2026-04-01 | `site-a.example` | hosted at `198.51.100.10` | passive DNS (B2) | https://bgp.he.net/ip/198.51.100.10 |

    - **Do not retype it.** `case_timeline.py --markdown` (Rule 20) writes this table from the
      collected JSON with the links already resolved; paste it under the appendix heading and add
      only the rows the tool could not know about (a manual archive capture, a regulator register,
      a corporate filing) — each with its own link.

    - **Online, frozen links only** — an archive snapshot, an archived scan result, a CT log entry, an
      RDAP record, a routing lookup, a block explorer. A path inside our case store is collection
      provenance, never a citation (Rule 12), and a live *search* URL changes under the reader.
    - **A claim with no link is labelled as inference**, in its own row and graded as such — never
      smuggled in beside sourced rows.
    - **Timestamp the observation, not the write-up** ("observed 2026-03-04", not "as of this report")
      so the next reader can age the claim.
    - **A hash is quoted in FULL, never truncated.** A sha256 is an integrity anchor: `bcc4…dedb`
      re-verifies nothing, so a captured screenshot / DOM / file is cited with its complete 64-char
      digest in the ledger (wrap it in backticks so the mono column `seqsplit`-wraps it inside the
      cell). Put the full hash in the ledger row; keep it OUT of the prose caption (a 64-char string
      breaks a caption's line) — the caption says what and when, the ledger row carries the hash.
    - If a public copy did not exist, create one before asserting the fact, then cite what you created.

22. **Alternative analysis section (required, explicit) — the benign explanations you considered and
    what killed them.** Do not leave this implicit in the rejected-links narrative: a reader auditing
    an attribution needs to see that the obvious innocent readings were put to the evidence and lost.
    Give it its own table — hypothesis · status · the specific evidence that decided it:

    | Alternative explanation | Status | Why |
    |---|---|---|
    | Shared hosting panel batching the certificates | Rejected | joint SANs re-issued 103 days apart — inconsistent with panel batch cadence |
    | A prior, unrelated owner of `site-b.example` | Rejected | the 2023-era stack, contact handle and registrant all differ from the observed operator |
    | Registrant name collision (a common name) | **Cannot be ruled out** | no independent record ties the name to the infrastructure; the link rests on the email, not the name |

    - **"Cannot be ruled out" is a required outcome, not a failure.** An alternatives table where every
      row is *Rejected* is not analysis, it is advocacy — and it is the tell that the hypothesis was
      the frame rather than the subject. Anything unrejected must be reflected in the confidence level
      of the judgment it threatens, and echoed in Gaps.
    - This is structured analytic technique (ACH), not house decoration; it applies to every profile
      and every audience.
    - It pairs with the figure rule: the rejected branch is drawn dotted and struck through with its
      reason (Rule 15), so the picture and this table tell the same story.

23. **Glossary appendix (required) — dictate every term the report uses.** The last appendix is a
    two-column **Term · Plain-English meaning** table defining every acronym and piece of tradecraft
    jargon in the document: the collection terms (JARM, favicon hash / mmh3, passive DNS, RDAP/WHOIS,
    certificate transparency, TLS, origin IP, ASN, stealer / infostealer log, Discord snowflake), the
    grading scales (NATO Admiralty A–F / 1–6, ICD-203 estimative words, confidence vs probability),
    and the marking (the TLP level used). One plain sentence each, written for a reader who has never
    done OSINT — a manager, an abuse-desk clerk, a lawyer.
    - **The gloss in the body (Rule 1c) and the Glossary agree.** A term defined in parentheses at
      first use is also in this table; the table is the reader's fallback, the inline gloss keeps them
      moving. Neither replaces the other.
    - **Only terms actually in THIS report.** Do not paste a generic dictionary — if the report never
      mentions JARM, JARM is not in its glossary. Add a term the moment you use it.

Note: top-level sections are Roman (I, II); sub-sections number as **arabic `1.1`, `2.1`** (not I.1).

### The canonical section order

The rules above are numbered by topic, not by page. This is the order they land in the document —
follow it unless the case genuinely has nothing for a section, in which case the section still
appears and says so (Rule 19: an absent finding and an absent search look identical otherwise).

| # | Section | Carries | Rule |
|:-:|:---------------------|:-------------------------------------------------|:----|
| I | Executive Summary — Key Judgments | **the purpose statement first**, then the BLUF table: judgment · attribution level · confidence | 0, 1 |
| II | Methodology & confidence | the tradecraft (not our tools), the threshold of proof this report was written against, NATO Admiralty + ICD-203 tables | 0, 5, 6, 14 |
| III | The seed and what it is | the seed **named**, what it impersonates or sells, its liveness state | 12a/12b |
| IV | Lifecycle timeline | registration cohorts, registrant eras, hosting windows, cert batches — and the contemporaneity verdict per link | 20 |
| V… | Findings — one section per cluster / entity / link | table → facts → prose, each with its figure | 2, 15 |
| … | Attribution — who, and at what rung | same-kit / same-operator / same-actor / a named persona / unattributed + why, with the identity gap | — |
| … | Alternative analysis | every benign explanation considered, its status, and the evidence that decided it | 22 |
| … | Rejected links | what was tested and did NOT survive, with the prevalence/benign reason | 15, 22 |
| … | Gaps & limitations | what could not be verified; what a keyless / passive / blocked collection could not have seen | 19 |
| … | Recommendations / consumer note | referral pathways, preservation targets — scoped to the Rule 0 decision | 18 |
| A | Artifact register | Artifact · Value · Source class · Admiralty grade | 7, 13 |
| B | Evidence ledger | When (UTC) · Indicator · Claim · Source (Admiralty) · Evidence link | 21 |
| C | Domain & infrastructure profiles | one Field·Value dossier per domain in scope | 17 |
| D | Cluster enumeration | all N members by name, when a finding counts them | 12b |
| E | Glossary | Term · plain-English meaning, for every acronym / jargon term the report uses | 23 |

Appendices follow the raw-LaTeX `\appendix` marker (see below) and number as `Appendix A`, `B`, …

## Audience — ASK first, then tailor the report

A report has a reader, and different readers need different reports. When the user asks to "produce
/ output / render a report" **without naming the audience, ASK before writing** — use
`AskUserQuestion` with these options (add "All three" — render one file per profile). **Ask for the
DECISION (Rule 0) in the same breath**: audience, decision and TLP are one question with three
parts, and all three must be answered before the first section is written.

| Profile | Reader | Tone & length | Lead with | Include | Cut / push to appendix |
|---|---|---|---|---|---|
| **Technical** | analyst, IR, threat-intel | precise, dense, jargon OK | the two-layer finding + evidence tables | every artifact and every finding — this is the FULL build (Rule 19), Admiralty/ICD grades, config dumps, methodology depth | nothing |
| **Executive** | leadership, decision-maker | plain business language, short (≤2 pp body) | 3–5 bullet BLUF: what it is, our exposure, the ONE recommendation | risk/impact framing, cost, "what it means for us", a single clear action | raw indicators, tool names, hashes → appendix only |
| **Law Enforcement** | investigator, prosecutor | neutral, factual, court-mindful; separate *confirmed* from *assessed* | the actors/infrastructure + the evidence chain | provenance (source/where/how) up front, UTC timestamps, jurisdictions (registrar, hosting country, offshore), preservation targets, and the concrete legal-process leads (who to subpoena: registrar, NS/anonymity provider, host, telemetry vendor, scanner submitter) | speculation and analyst labels unless clearly marked as assessment |

All three still obey the house rules above (purpose statement, Exec Summary first, Methodology
second, NATO+ICD, timeline, alternatives, artifact register + evidence ledger, explanatory tone).
The audience changes *emphasis, depth, and vocabulary* — **never the underlying facts and never the
completeness** (Rule 19: a shorter cut is an additional output, not a smaller investigation).
Carry the choice into the render with `--audience {technical|executive|le}` (it stamps the audience
on the cover subtitle and sets a sensible TOC depth).

**Reader → decision → threshold of proof.** The audience implies the bar the judgments are written
against; state the pairing in the purpose statement and again in Methodology (Rule 0):

| Reader | Typical decision the report supports | Threshold that applies |
|---|---|---|
| Analyst / threat-intel | whether to keep pursuing, and what to pivot on next | assessed links are usable; uncertainty is the product, not a defect |
| Platform trust & safety | suspend an account / listing / campaign | an assessed same-operator link on owner-controlled artifacts is normally enough |
| Registrar / host abuse desk | suspend a domain or an origin | the abuse itself must be evidenced on the named host, independent of attribution |
| Investigator / prosecutor | open a matter, seek process, charge | *confirmed* separated from *assessed*; provenance, UTC, jurisdiction and preservation targets explicit |
| Journalist / publication | publish, and name a person or not | a named individual needs corroboration from an independent record, not one artifact |
| Security operations / IR | deploy detection, hunt, block | the tactical bulletin (Rule 18a), not this report |

## Handling marking (TLP) — ASK first, never assume

Every report carries a handling caveat on the cover and on **every** page. It tells the reader what
they may do with the document, so it is the author's decision, not a default. When the user asks to
"produce / output / render a report" **without stating the marking, ASK before rendering** — use
`AskUserQuestion` (FIRST TLP 2.0; offer `TLP:AMBER+STRICT` via "Other"):

| Marking | Reader may share it with | Use for |
|---|---|---|
| **TLP:CLEAR** | anyone, publicly | blog posts, LinkedIn/social, published research, awareness material |
| **TLP:GREEN** | their community / peer network, not publicly | industry or trust-group circulation |
| **TLP:AMBER** | their own organisation and clients, need-to-know | the default for a live case assessment naming victims or an active operator |
| **TLP:RED** | named recipients only, no onward sharing | pre-takedown, pre-arrest, or single-recipient briefings |

Do NOT silently accept the tool's `UNCLASSIFIED` fallback, and do not inherit a marking from a
neighbouring file just because it was there. Pass the answer through as
`--classification "TLP:<LEVEL>"` (or frontmatter `classification:`).

**Downgrading is a redaction job, not a re-render.** Re-marking changes the banner, not the content.
Before producing a `TLP:CLEAR` / `TLP:GREEN` cut of anything that was `AMBER` or `RED`, re-read it as
a stranger and tell the user what publishing would disclose — compromised third-party hostnames and
their owners (victims, not suspects), registrant PII, non-public source material, anything that tips
an operator off before a takedown. Offer a redacted variant that keeps the tradecraft and the key
judgments but masks the victim identifiers; the operator's own infrastructure normally stays.

**Never overwrite the higher-marked file.** Render the downgraded cut to a NEW output stem
(`<report>_public`), so the original stays as the record copy of what was assessed and when.

### The appendix marker (Roman → letter switch)

Pandoc has no `\appendix` hook, so emit one raw-LaTeX block in the markdown immediately before the
first appendix heading — everything after it numbers as `Appendix A`, `B`, …:

````markdown
```{=latex}
\appendix
```

# Artifact register
````

## Zero new dependencies

Everything is already on the machine the harness uses:
- `pandoc` — the converter (markdown → PDF and → DOCX).
- `xelatex` — the PDF engine (Unicode/Vietnamese-safe; picks an installed Vietnamese-capable
  font automatically, see below).

No Python packages are required — `render_report.py` is stdlib-only and shells out to pandoc.

## Running the tool — paths (read first)

Registered as `IntelReport`, symlinked to the repo's `IntelReport/` folder.

```bash
REPORT=~/.claude/skills/IntelReport            # absolute — works from any CWD (preferred)
# or, inside the repo:  REPORT="$ROOT/IntelReport"

python3 "$REPORT/scripts/render_report.py" assessment.md out/report
```

That writes `out/report.pdf` **and** `out/report.docx` (both by default). Pass `--pdf` or
`--docx` to produce just one.

## Core workflow

1. **Have the assessment as Markdown.** Any assessment markdown works — from
   `pivot_extract.py --report`, `evidence_report.py`, an IntelHarness assessment, or written
   by hand. Standard Markdown: `#`/`##` headings, `|` pipe tables, fenced code, `**bold**`,
   `> quotes`, and image embeds.
2. **(Optional) add YAML frontmatter** so the cover/header fill in without CLI flags:
   ```markdown
   ---
   title: "Operator A — infrastructure assessment"
   subtitle: "Passive OSINT · N sites attributed to one operator"
   case_id: CASE-0001
   classification: "TLP:AMBER"
   lang: vi          # optional — Vietnamese cover/TOC/captions; the BODY is never translated
   ---
   ```
   CLI flags (`--title`, `--case-id`, `--classification`, `--subtitle`, `--date`, `--lang`) override
   the frontmatter. Anything missing gets a sensible default (`classification` →
   `UNCLASSIFIED`, `date` → UTC today, `title` → first `#` heading or the filename).
   The `classification` fallback is a backstop, not an answer — **ask the user for the TLP**
   (see *Handling marking* above) rather than letting a report ship as `UNCLASSIFIED`.
3. **Embed IntelGraph figures** as ordinary Markdown images — the alt text becomes the
   figure caption, styled in the house palette:
   ```markdown
   ![Operator A — two sites, shared GA4 + registrant](case_diagram_hires.png)
   ```
   Image paths are resolved **relative to the markdown file's directory**. Put the assessment
   `.md` in the case folder next to its figures (see the IntelGraph output contract) and they
   embed cleanly. Use the `_hires.png` (300 DPI) figure for print, or the `.svg` for vector.
4. **Render:**
   ```bash
   python3 "$REPORT/scripts/render_report.py" cases/CASE-0001/assessment.md \
       cases/CASE-0001/report --case-id CASE-0001 --classification "TLP:AMBER"
   ```
5. **Present** the PDF (and DOCX if the user wants to edit it).

## The end-to-end pipeline (charts + report)

```bash
# 1) collect + build the clustered case graph (WebPivot)
python3 <WebPivot>/tools/graph_build.py cases/CASE-0001/raw/*.json \
    --operator "Operator A" -o cases/CASE-0001/case_graph.json

# 2) editable diagram -> PNG/SVG (IntelGraph); the .mmd is hand-editable
python3 <IntelGraph>/scripts/graph_to_diagram.py cases/CASE-0001/case_graph.json \
    cases/CASE-0001/case_diagram --title "One operator, N sites" --legend

# 2b) the lifecycle timeline + the evidence ledger, from the SAME collected JSON (Rules 20/21)
python3 <IntelGraph>/scripts/case_timeline.py cases/CASE-0001/out/*.json \
    --stem cases/CASE-0001/fig_timeline --markdown --title "Infrastructure lifecycle"

# 3) reference the figure in the assessment markdown, then render the document
python3 <IntelReport>/scripts/render_report.py cases/CASE-0001/assessment.md \
    cases/CASE-0001/report --case-id CASE-0001 --classification "TLP:AMBER"
```

`<IntelGraph>` = `~/.claude/skills/IntelGraph`, `<WebPivot>` = `~/.claude/skills/WebPivot`.

## Template & house style

- **Cover page** — classification banner (brick), large slate title, grey subtitle, and a
  Case / Date / Basis block. No logo, no analyst name.
- **Body** — numbered sections in slate/steel sans headings with a hairline rule, booktabs
  tables, house-palette figure captions, coloured hyperlinks. Auto table of contents.
- **Header/footer** — classification top-left, case id top-right, classification + page
  number in the footer, hairline rules.
- The LaTeX template is `templates/house-header.tex` (xelatex, palette copied from
  `IntelGraph/scripts/theme.py`). Edit it to adjust the house look; keep it case-data-free.

## Typography — three fonts, and the one that carries the evidence

Fonts are **data**, not code (RULE 3): `references/typography.json` holds a preference list per
role and the renderer picks the first family actually installed, so the skill is portable instead
of hardcoding one face. Retune it without touching Python.

| Role | Used for | Chosen from |
|---|---|---|
| **serif** | body text | `serif_families`, filtered to Vietnamese-declaring families on `--lang vi` |
| **sans** | headings, cover, running header/footer, figure captions — never body | `sans_families`, same filter |
| **mono** | inline code and code blocks: domains, IPs, hashes, fingerprints, endpoints | `mono_families`, **not** filtered (this content is ASCII) |

**Mono matters more than it looks.** It is the face an analyst reads a 64-character hash in, so
pick one that disambiguates `0`/`O` and `1`/`l`/`I`. `Source Code Pro` is the house preference;
`Menlo` is the usual macOS fallback and also a good hash face. Courier is last on purpose — thin,
wide, and hard to read at footnote size in a table cell. Install the preferred family with
`brew install --cask font-source-code-pro` (macOS) or `apt install fonts-source-code-pro`.
Without an explicit `\setmonofont` xelatex falls back to Latin Modern Mono, which sets a long hash
badly in a narrow column; the renderer therefore always emits one.

Long inline tokens break **without a hyphen** (`seqsplit`) so a hash wraps inside a table cell
instead of overflowing into the next column. A break mid-hash is correct behaviour, not a defect.

### Column widths are set by the DASH RATIO

Pandoc allocates table column width from the relative number of dashes in the delimiter row, so
`|:---|:------|` gives column 2 twice column 1 — regardless of what the cells contain. Give the
column holding hashes and prose the most dashes and a `High`/`A1` column the fewest. Getting this
backwards is the single most common cause of an unreadable appendix.

## Emphasis — bold, italic, highlight, callout

Four levels, each with one job. Using them interchangeably means the report emphasises nothing.

| Device | Markdown | Use it for |
|---|---|---|
| **bold** | `**text**` | the lead-in of a finding, a key term at first use, the word that flips a sentence's meaning (`**not** supported`) |
| *italic* | `*text*` | figure captions, quoted foreign-language titles and site copy, ICD-203 estimative terms when listing the scale |
| ==highlight== | `==text==` | the few facts a reader must not miss: a payee account, a verdict, a rejected link. **A handful per report, not per page.** |
| callout | `> **Bottom line.** …` | the one or two "stop and read this" boxes — renders as a tinted box with a brick side rule |

**The highlight is a non-breaking box, so keep it short.** It cannot wrap across lines: an
over-long span runs into the margin. `render_report.py` warns when a span exceeds
`highlight.max_chars` (90 by default) — at that length you wanted **bold** anyway, because a
highlighted sentence highlights nothing.

Two implementation facts worth knowing before you "improve" this:

- The highlight is a **colour box, deliberately not the `soul` package.** `soul` silently DROPS
  stacked Vietnamese diacritics inside a highlight — `bị làm giả` renders as `b làm gi` — while
  compiling without error. That is the worst failure mode available: a corrupted Vietnamese
  deliverable that looks fine to whoever built it. Correctness beat line-wrapping.
- The callout uses **`mdframed`, not `tcolorbox`.** tcolorbox 2025 calls `\NewStructureName`, a
  kernel macro absent from a TeX Live *basic* install, and fails the whole render on exactly the
  minimal setups this skill should survive. Both the callout and the box packages are guarded, so
  a missing package degrades to an ordinary quote rather than costing you the deliverable.

## Vietnamese reports — `--lang vi`

A report has two kinds of text, and the tool treats them differently **on purpose**.

| | Who writes it | What `--lang vi` does |
|---|---|---|
| **Furniture** — cover labels, TOC title, "Appendix", figure/table captions, the audience stamp | the template | **swaps it wholesale** (`Số hiệu` / `Ngày` / `Cơ sở thu thập` / `Mục lục` / `Phụ lục` / `Hình` / `Bảng`) |
| **Body** — the argument, the judgments, the evidence | the analyst | **nothing. It is never machine-translated.** |

That split is the whole design. The furniture is finite and mechanical, so localising it is a
one-line flag. The body is a *calibrated* text: "we assess with high confidence" and "likely" are
ICD-203 terms with probability bands attached, and a paraphrase of one silently changes what the
report claims. So **write the assessment in Vietnamese from the start** and take the wording
verbatim from the glossary:

```bash
python3 "$REPORT/scripts/render_report.py" --glossary --lang vi   # the exact strings to use
python3 "$REPORT/scripts/render_report.py" assessment.md out/report --lang vi --pdf --docx
```

Or set it once in frontmatter — `lang: vi` — alongside `title:` / `classification:`.

**Rules for a Vietnamese deliverable:**

1. **Use the glossary strings verbatim, never a synonym.** `rất có khả năng` (80–95%) and
   `có khả năng` (55–80%) are different claims. Quote the ICD-203 band table once in
   *Phương pháp và mức độ tin cậy* so the reader can grade the scale instead of guessing.
2. **Never mix confidence with probability in one sentence.** `độ tin cậy` is about the evidence;
   `khả năng` is about the event. Same rule as English, same failure if broken.
3. **Keep the house skeleton.** Use the `section_names` headings so a Vietnamese and an English
   rendering of the same case are a translation of each other, not two different reports.
4. **Indicators stay literal and untranslated** — domains, IPs, hashes, brand names, registrar
   names. Rules 12a/12b apply unchanged; a translated indicator is a broken indicator.
5. **Check the PDF for tofu.** `--lang vi` warns loudly when no installed family *declares*
   Vietnamese coverage, but it still renders — look at the output before sending it.

Both languages live in `references/report_i18n.json` (RULE 3). Add a third by adding its key to
every group; nothing in the code needs to change.

### Fonts

`render_report.py` auto-selects an installed serif + sans that actually **declare Vietnamese
coverage** (`fc-list :lang=vi`) — many otherwise-nice serifs (PT Serif, Charter, DejaVu on
macOS) miss the stacked-diacritic glyphs (ộ, ừ, ả) and render tofu, so they are skipped in
favour of e.g. Noto Serif / Georgia / Times. Diacritics render correctly (cà phê, Hà Nội,
lừa đảo). Latin Modern is the last-resort TeX-bundled fallback — it does **not** cover
Vietnamese, so on a box with no fontconfig install a Noto family:
`brew install --cask font-noto-serif font-noto-sans` / `apt install fonts-noto`.

### DOCX styling

DOCX uses pandoc's default reference styling plus a title block (title / subtitle-with-
classification / date). To brand it further, drop a customised `templates/reference.docx`
into the skill — `render_report.py` picks it up automatically if present (else uses the
clean default). Generate a starting point with
`pandoc -o templates/reference.docx --print-default-data-file reference.docx`, restyle it in
Word/LibreOffice, and keep it case-data-free.

## Quality checklist before presenting

- **The first sentence names the decision this report supports (Rule 0)**, and Methodology restates
  the threshold of proof that decision implies. A report that opens on a finding has failed this.
- **Section IV is the lifecycle timeline (Rule 20)** with its figure, and every attribution link in
  the report has an explicit contemporaneity verdict — overlapping, or not.
- **An Alternative analysis table exists (Rule 22)** with at least one honestly unrejected row where
  one exists, and its rejections are echoed by the dotted/struck edges in the figures.
- **Both appendices are present (Rules 7 and 21)**: the artifact register AND the evidence ledger.
  Every ledger row has a link that resolves for someone who has never seen our disk; inference rows
  are labelled as inference.
- **A Glossary appendix exists (Rule 23)** and every acronym / jargon term used in the body appears
  in it; every such term was also glossed in plain words at its first use in the body (Rule 1c).
- **Plain, human voice (Rule 1c):** read a section aloud — it must sound like a colleague explaining
  what they found, not a brochure. No banned AI tells ("delve", "underscore", "not just X but Y",
  rule-of-three flourishes, "it is important to note", stacked "moreover/furthermore"). Every hash is
  quoted in FULL in the ledger, never truncated (Rule 21).
- **Figures sit inline with their explanation (Rules 15a, 16):** each figure is in the paragraph/
  subsection whose claim it proves, not floated to a page top or an appendix; captions are not garbled
  or overlapping (the template forces `[H]` placement — check the rendered pages, not just the log).
- **Completeness (Rule 19):** every cluster member is named somewhere in the document, no "and N
  others", negative and weak results are stated, and any redaction says where the cut was made.
- **No IOC block / detection rules / ATT&CK mapping (Rule 18a)** unless the named consumer is a
  security-operations team — if defenders also need serving, a separate `_bulletin` render exists.
- Both requested files exist (PDF and/or DOCX).
- **Figures rendered and embedded (Rule 15) — check this FIRST, it is the most-skipped step.**
  `figures.json` exists, the render log printed `figure refreshed:` for every entry, every findings
  section from III onward embeds one, and each figure's edges are labelled with the EVIDENCE that
  creates the link. Zero figures = the report is not finished.
- Cover shows the right title, case id, and classification; NO analyst name.
- Vietnamese text renders with correct diacritics (no tofu boxes) — and for a `--lang vi` report,
  the cover/TOC/appendix furniture is Vietnamese too, the estimative terms match the glossary
  verbatim, and no indicator was translated.
- Embedded figures appear (use the `_hires.png`); tables render with rules.
- Header/footer carry the classification + case id + page numbers on every body page.
- The classification and report reference came from an argument or frontmatter — never hardcoded,
  and the displayed reference is the EXTERNAL `--report-ref`, not the internal case id (Rule 11).
- **The TLP was the user's explicit answer**, not a default or a marking inherited from a
  neighbouring file — and no report shipped as `UNCLASSIFIED` by omission. If this is a downgraded
  public cut, the disclosure review happened and the higher-marked original was not overwritten.
- **Identifier disclosure (Rules 12a/12b) — check explicitly, it is the most common defect:**
  - the SEED's domain name appears in the Executive Summary;
  - every impersonated brand is named, not described by sector;
  - every indicator's literal value appears at its first mention in the BODY, not only the appendix;
  - if the finding counts N domains, an appendix lists all N;
  - and, in the other direction, no tool / script / vendor-product / case-store id survives anywhere.
  Read one findings section as a stranger: if you cannot tell WHICH domain it is about, rewrite it.
