---
name: IntelShare
description: Publish a finished case's indicators to MISP — build the event from the case's own collected pivots, then STAGE it on your instance (organisation-only, unpublished) and, only on an explicit human yes, publish it so it syncs to the community. Sharing is split into two separately-approved steps because publishing is irreversible: a MISP event pushed to peers cannot be recalled, and a shared indicator becomes somebody else's blocking rule. Also answers the cheaper question first — is this indicator already known to the instance? USE WHEN publish to MISP, push the IOCs to MISP, share the indicators, create a MISP event, add these IOCs to our MISP, is this in MISP already, MISP lookup, share with the community, TLP, distribution level, publish the case, disseminate, upload to threat sharing platform, contribute IOCs, MISP attributes, MISP taxonomy tags.
---

> **OPSEC — this skill is portable/shared. Never write case data into it.** No real operator
> names, emails, domains, IPs, wallets, tracking IDs, hashes, or case IDs in this file, its
> reference data, tool code, or tests. Investigation data lives only in the git-ignored
> `cases/` / `knowledge/` / `MEMORY/`. Use placeholders (`site.example`, `CASE-0001`).
> See the repo-root `CLAUDE.md` for the full rule.

# IntelShare — the case leaves the building

Every other skill here collects, judges or renders **for us**. This one is the only path by
which a case's findings reach **other people's detection stacks**, and that changes what a
mistake costs. A wrong cluster makes our assessment wrong. A wrong indicator, published, makes
every subscriber's blocklist wrong — and they will spend a week blaming their own tooling.

So the layer is built as a sequence of refusals with one narrow way through, and the way through
always passes a human.

## 0. ASK THE ANALYST. Every time, per event, before anything leaves.

This is the rule the whole skill exists to enforce. **Never push and never publish on your own
judgement, and never treat "work this case" or "write it up" as consent to share it.**

Both mutating entry points return a **briefing and send nothing** unless confirmation is present.
Show the briefing — do not summarise it away; the counts and the audience line are the decision.
In Claude Code, ask with `AskUserQuestion`, and ask the two questions that actually differ:

| Question | Options to offer |
|---|---|
| Share these indicators on MISP at all? | Stage on our instance only · Stage and publish · Don't share |
| If published, who should see it? | This community only (1) · Connected communities (2) · All communities (3) · A sharing group (4) |

Two answers matter as much as "yes": **which values** (the `review` list is personal data and
third-party-derived values, and is approved value by value, never in bulk) and **which TLP** the
source material allows you to attach.

## 1. The two-step rail

```
  sh_export.py   case  ──▶  event JSON      offline. No network at all. Refuses more than it emits.
  sh_misp.py push       ──▶  STAGED          distribution 0 (your org), published=false. Deletable.
  sh_misp.py publish    ──▶  SHARED          distribution ≥1 + published. Syncs to peers. FINAL.
```

**Push is not sharing.** It stages: the clamp to organisation-only/unpublished is applied in code
from `references/misp.json`, so a caller that asks push for distribution 3 gets an
organisation-only event and is told so. Nobody outside your organisation has seen it and you can
delete it.

**Publish is sharing, and it is final.** It raises the distribution and flips `published`, which
pushes the event to every server your instance synchronises with and notifies subscribers.
Deleting your copy afterwards deletes nothing of theirs. It therefore needs the analyst's yes
**and** the environment lock `INTEL_MISP_PUBLISH=1` — a lock an agent loop cannot set for itself.
Confirm without the lock and the tool says exactly that and still sends nothing.

### Publishing in the same command

`misp_push` takes `publish=true` + `distribution=<level>` (CLI: `--publish --distribution 1`) for
the analyst who has decided both questions at once. It is **not** a way around the gate: the
publish step re-checks its own confirmation and the environment lock, so without
`INTEL_MISP_PUBLISH=1` the event stays staged and the result says exactly that. One command, two
authorised decisions — never one decision standing in for two.

```bash
INTEL_MISP_PUBLISH=1 python3 tools/sh_misp.py push <event.json> \
    --case <ID> --confirm-push --publish --distribution 1
```

## 1b. What a compliant event carries

An indicator list is the least of it. The event is built to MISP's own structure:

* **Objects, where several values describe one thing.** A `whois` object states that *this
  domain's* registration record named that registrant; four loose attributes only state that four
  values appeared somewhere in the case. Same for `domain-ip` (which address served which host),
  `x509` and `file`. Template uuid/version live in `references/misp.json` — read them off your own
  instance with `/objectTemplates/index`. Two rules keep objects honest: a candidate carrying
  fewer than `min_relations` values stays a plain attribute (an object exists to *group*, and
  twenty one-attribute `file` objects are noise dressed as structure), and a relation the template
  does not mark `multiple` appears **once** — a second registrant email on one `whois` object
  asserts that a single registration named both, so the extra value drops back to an attribute.
* **An event report** — MISP's markdown narrative, rendered above the attributes. This is where
  the discipline finally leaves the building with the indicators: what the event contains, what
  was **deliberately withheld** and why, the intake class, whether the collection was **exhausted
  or only a triage** (read from `wp_exhaust`, and the one caveat a receiver can never
  reconstruct), and the handling rule. Attach the analyst's own markdown with `--report <file>`;
  it is leak-scanned like everything else we compose.
* **Dates.** `first_seen`/`last_seen` per attribute and an event `date` set to the **observation**
  date, not the export date — stamping today on a three-week-old collection makes stale
  infrastructure look fresh. An artifact with no recorded collection time is left **undated**
  rather than given an invented one, and the report says how many that was.

**Updating an event is not idempotent in MISP** and finding that out in production is expensive:
`/events/edit` de-duplicates attributes but **appends** objects, and the report endpoint always
creates a new report — so a second push used to double both. `push --event-id` now reads the
event first, skips objects it already carries (reporting the count, so "fewer sent" is never read
as "something was lost") and replaces the report of the same name.

## 2. Ownership decides shareability, before any per-value rule

`cases/<case>/scope.json` (the intake class — see `WebPivot/SKILL.md` §0) is read first:

* **`victim_host` → refused.** On a compromised site the WHOIS, favicon, certificate and
  analytics belong to the **victim**. Publishing them as the operator's indicators tells every
  subscriber to block a victim. Only operator-**injected** artifacts (the kit path, the injected
  file's hash) may be shared, one by one, by hand.
* **`benign_check` → refused.** There is no version of a benign-check result that belongs in a
  shared indicator feed. An event naming a legitimate site is defamatory and un-recallable.
* **`suspected_scam` / `threat_actor_infra` / `unknown` → shareable with an acknowledgement.**
  The intake class is where the run *started*, not what it concluded. The caveat travels into the
  event as a `workflow:` tag and into the briefing as `acknowledge_before_sharing`, so the
  receiving analyst holds the same reservation we do. On `threat_actor_infra` there is a second
  reason to pause: publishing can collide with somebody else's live operation and tells the actor
  they are tracked.

## 3. What may be shared — three classes, downgrade-only

| class | what it is | what happens |
|---|---|---|
| `auto` | infrastructure the operator provisioned — domains, the kit's backend route, file hashes, favicon/JARM/cert fingerprints, owner-provisioned tracker and verification ids | included when the analyst approves the event |
| `review` | **personal data** (registrant name/email/phone, page emails and phones), identity handles (Telegram, socials), and values *derived* from a third party rather than observed by us | held back; approved **per value**, never in bulk |
| `never` | page context, generated lookalike candidates, shared platform noise, and our own operational data | never enters the event, whatever anyone confirms |

Movement is one-way toward `never`. A case class, a base-rate filter or a failed shape check can
push an artifact down; nothing pushes it back up.

**`to_ids` is the sharpest setting in the file.** It means "a detection system may block on this
value", so it is true only for values that identify the operator's own infrastructure, and false
for every hunting pivot — a favicon hash, a JARM, a tracker id are for *finding* more, not for
blocking. The briefing states how many attributes carry it.

## 4. Base rates are a sharing control here, not just a clustering one

The same population problem that manufactures false clusters manufactures false indicators, with
a bigger blast radius. `tools/kb/noise_filters.py` is reused directly: a parking/template favicon,
a registrar or privacy-proxy contact address, a platform-default tracker id, a parking host and a
shared-infrastructure apex are all refused with the reason stated. `third_party_host` — the single
most common artifact in the corpus — is refused **as a class**, because it is a CDN/SaaS hostname
by construction, and published with `to_ids` it would have subscribers blocking their own vendors.

When the KB is not importable (the skill used standalone), the layer does **not** fall back to
publishing everything: every `auto` artifact is downgraded to `review` and the export says why.

Shapes are checked too (`value_validators`): a truncated hash or a bare word offered as a domain
is refused, because an indicator that cannot match anything is pure noise in a subscriber's feed.

## 5. Ask the instance before you add to it

`sh_misp.py search <value>` is read-only, sends nothing of the case, and answers the cheapest
useful question: **is this already known here?** A value your community already holds does not
need re-sharing; a value nobody has is the one worth the trouble. Run it on the strong indicators
before proposing a publish. An error is a *channel* failure — absence of an answer, never evidence
that the value is unknown.

## 6. Confidence travels with the indicators

A shared indicator with no stated confidence is read as certain. The event carries the ICD-203
term from the assessment as an `estimative-language:confidence-in-analyst-judgment` machine tag
(`confidence_map`), alongside TLP, PAP and `type:OSINT`. Say what you actually concluded — a
`moderate` case shared as `high` is the same drift the estimative scale exists to stop.

## Tools

| what | how |
|---|---|
| build the event, offline | `sh_export.py <case> --leads` · MCP `misp_export` |
| approve held-back values | `sh_export.py <case> --review-value <value>` (repeatable) |
| is it already known? | `sh_misp.py search <value>` · MCP `misp_search` |
| stage on the instance | `sh_misp.py push <event.json> --confirm-push` · MCP `misp_push` |
| share it (final) | `sh_misp.py publish <id> --distribution N --confirm-publish` + `INTEL_MISP_PUBLISH=1` · MCP `misp_publish` |
| channel health | `sh_misp.py keycheck` · `budget` |

Everything analyst-tunable is in `references/misp.json` — the pivot-kind → attribute-type map,
the three publish classes, the excluded kinds and their reasons, the intake-class policy, the
distribution ladder, the taxonomy tags and the staging rail. Add a mapping there rather than in
Python; an unmapped kind is excluded **and named** in the export, never guessed at.

## Configuration

```
MISP_URL=https://misp.your-org.example      # your instance
MISP_KEY=<API key>                          # Administration → List Auth Keys
MISP_ORG=<your org name>                    # optional, shown in the briefing
MISP_VERIFY_TLS=0                           # only for a private CA — warns, loudly
MISP_USER_AGENT=...                         # only if your WAF wants a specific one
INTEL_MISP_PUBLISH=1                        # the publish lock, set by a human for a run
```

**If your instance sits behind Cloudflare** (many self-hosted ones do), a client that sends no
User-Agent is refused by the default bot rules with error **1010** — which arrives as a bare
`403` and looks exactly like a rejected API key. The client always identifies itself, and a 403
whose body names Cloudflare is reported as a WAF refusal rather than an auth failure.

**Verify the type table against your own instance.** MISP's attribute vocabulary differs by
version and deployment: checked against 2.5.31, 58 of 59 mapped types were accepted, and the one
that was not is instructive — **MISP has no `eth` type** (its crypto types are `btc`, `dash`,
`xmr`), so an Ethereum address ships as `text` in *Financial fraud* with the chain in the comment.
Unknown types are downgraded to `text` at push time with a note, never silently dropped.

With nothing configured the layer is honest rather than silent: it says the channel is absent and
that this is absence of a channel, not absence of findings. `sh_export.py` still works completely
— building and reviewing the event needs no instance at all.

## Writes

`cases/<case>/misp/event-<UTC>.json` (timestamped, never overwritten — the diff between two
exports is the record of what an analyst added or held back) and `cases/<case>/misp/ledger.jsonl`
(one line per outbound share: when, which instance, which event, what distribution). Both live in
the git-ignored case store.
