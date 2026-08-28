# cti-expert — contributor rules

This repo ships a **portable OSINT skill** (`SKILL.md`) plus a **vendored engine**
(`intel_engine/` — WebPivot, IntelGraph, IntelReport, IntelAnalysis, BinaryPivot, Engage,
IntelHarness, IntelShare, the KB and the deterministic pipeline). The skill is symlinked onto other machines
and used by other people.
Treat everything tracked here as **public-facing**.

> **Scope note.** This file loads only when the working directory is inside this repo — i.e. when
> you are *building* cti-expert. It does **not** travel with the skill. Anyone invoking
> `/cti-expert` from another project gets `SKILL.md` and nothing else. So: **rules for running an
> investigation belong in `SKILL.md`; rules for changing this repo belong here.** If you write an
> operating rule into this file, it will silently not apply to the people who actually use it.

---

## RULE 1 — Never put case / investigation data into the skill (CRITICAL)

Tracked files are **code + tradecraft only**. Investigation data NEVER goes into `SKILL.md`, a
technique/handbook `.md`, a tool docstring or comment, a test fixture, or any other tracked file.
This includes, in prose, comments, examples, fixtures, or hardcoded logic:

- **Real people / operators** — names, aliases, emails, phone / Telegram / WhatsApp / Zalo handles.
- **Real target infrastructure** — case domains, IPs, wallets, ASNs, hostnames, nameservers.
- **Real owner artifacts** — actual GA4/GTM/UA IDs, GSC verification tokens, Crisp website IDs,
  favicon/DOM hashes tied to a case.
- **Case identifiers** — case IDs, case-folder names, per-case hardcoded paths.
- **Operator PII / attribution** of any kind, even as a "worked example".

Investigation data lives ONLY in the git-ignored stores: `intel_engine/cases/`,
`intel_engine/knowledge/`, `intel_engine/MEMORY/`, `.env`, and the operator registry. It is never
committed and never referenced by identifier inside a tracked file.

**One exception, and it is narrow:** the curated false-positive ledger
(`/reference add`) legitimately stores indicator values — that is its entire job, and it lives in
the git-ignored KB, not in a tracked file.

---

## RULE 2 — There is exactly ONE case store

```
$INTEL_HOME/cases/<CASE-ID>/     # = intel_engine/cases/<CASE-ID>/
```

The CLI (`scripts/backend/intel.py`), the pipeline (`intel_engine/tools/intel.py`) and the MCP
server (`intel_engine/harness/tools.py`) **all** resolve to it. Confirm with
`python3 scripts/backend/backend.py status`.

**Never create a `cases/` directory at the repo root.** It is git-ignored, but the real damage is
silent: `kb_ingest` reads `$INTEL_HOME/cases/` and finds nothing, so correlation runs on an empty
set and reports "no shared indicators" instead of failing. If you see *"no raw pivot JSON in …"*,
you wrote to the wrong path — that is not a bug.

Let the pipeline choose paths. Do not pass `-o cases/...` by hand.

---

## RULE 3 — Register every new tool with the MCP surface

When you add a tool, publish it through the one typed surface both front-ends share:
`intel_engine/harness/tools.py` → the SDK orchestrator **and** the stdio
`intel_engine/harness/mcp_server.py`, which auto-discovers every `@tool` (67 today). Do NOT leave a
new capability reachable only as a raw `python3 …` bash line.

- **New CLI tool** (`intel_engine/tools/*.py`, `intel_engine/WebPivot/tools/*.py`): wrap it as an
  `@tool(name, description, {params})` in `harness/tools.py`. `mcp_server.py` picks it up with no
  second edit. Also add it to the `DISPATCH` table in `scripts/backend/intel.py` so the T2 CLI
  reaches it. Keep the description one tight paragraph — it is context cost paid on every turn.
- **New mode of an existing tool** (e.g. a bare-IP source for `pivot_extract`): no new `@tool` —
  extend the existing description so the model knows the new input/flag.
- **New command in `SKILL.md` §3**: it must map to a real `DISPATCH` op or an `@tool`. A documented
  command with no implementation is worse than no command.
- **Smoke-check:** `.venv/bin/python intel_engine/harness/mcp_server.py`, send a `tools/list`
  JSON-RPC, confirm the tool is listed. In Claude Code, check `/mcp`.

---

## RULE 4 — Wrapper/collector drift must stay self-healing

`STRUCTURE.md` is authoritative on layout. Five collectors exist in both layers; each has **one
canonical file plus a re-export shim**. Never turn a shim back into a copy — edit the canonical.

The harness wrapper probes each collector's `--help` and filters unsupported flags
(`_supported_flags` / `_filter_args` in `harness/tools.py`), so the two layers can diverge without
killing collection. **Dropped flags are surfaced in the tool result** — that is deliberate. A
dropped `--submit`/`--archive-missing` means evidence was NOT archived; never silence it.

If you add a flag to one layer's collector, you do not need to touch the other — but do check the
filter still lets it through.

---

## RULE 5 — Indicator classification changes need a test

The KB's clustering logic decides whether two domains get attributed to one operator. Getting it
wrong in either direction is expensive: a false merge names an innocent party, a false split loses
the case.

Two lists govern it, and they must stay in sync with reality:

- `intel_engine/tools/kb/noise_filters.py` — `MANAGED_DNS_SUFFIXES`, parking favicons, parking
  hosts. **Maintenance model: add providers as you meet them.**
- `intel_engine/tools/kb/hypothesize.py` — `_tier()`, which grades a relation as
  attribution / corroborating / noise.

`uses_nameserver` is **conditional**: delegation to a managed provider is noise; delegation to a
nameserver the operator runs themselves is attribution-grade (you cannot point a domain at
`ns1.<their-host>` without controlling that zone). Adding a provider to `MANAGED_DNS_SUFFIXES`
therefore *weakens* clustering on purpose — that is correct, and it is why the list matters.

**Any change to either file must come with a classification check** covering at least one managed
provider and one self-hosted nameserver.

---

## RULE 6 — the harness layer is part of the skill, not decoration

`hooks/` + `.claude-plugin/plugin.json` are where two safety properties are actually enforced when
this runs under Claude Code. Treat them as load-bearing.

- **RULE 1 is enforced twice, on purpose.** `scripts/leakcheck.sh` at `git commit`, and
  `hooks/leakguard.py` at `Write`/`Edit`. The git hook fires only at commit and `--no-verify`
  skips it; an agent harness writes constantly and commits rarely, so the write-time gate is the
  one that catches a real session. **`leakguard.py` must never re-implement the patterns** — it
  shells out to `leakcheck.sh`. A second copy would drift, and a drifted guard reports clean.
- **Outbound gates are enforced twice, on purpose.** In the tool (`submit(confirm=…)`, the Engage
  preflight) *and* in `hooks/actionguard.py`. The in-code gate lives in `intel_engine/`, which is
  **vendored** — a three-way merge can revert it without failing a test (it nearly did on
  2026-08-23). The hook lives in cti-expert's own tree and fires on the tool NAME, so a sync
  cannot reach it. **Adding an outbound capability means adding a row to
  `hooks/references/outbound_actions.json`,** not just a confirmation flag in the Python.
- **Both PreToolUse hooks fail OPEN.** A hook that dies must not brick every write in the repo.
  Keep it that way: `audit.sh` and the git pre-commit hook are the backstop.
- **Never widen a gate to stop a prompt.** Prefer narrowing `flag_required`, or an exact match, to
  deleting a row. A rail you have to switch off to work is a rail that gets switched off — the
  `intel.py engage ` trailing space (which spares `engage-report`) is the shape to copy.
- **`tests/test_hooks.py` asserts both directions** — fires on the target, silent on the
  neighbouring safe case. A guard proven in one direction only is not proven. `audit.sh` §7 also
  checks that every path `hooks.json` registers still resolves: a renamed script disables its hook
  **silently**.

---

## Cost visibility — two separate ledgers

- **Anthropic model cost** (the agent's reasoning). In interactive Claude Code the model cannot
  read its own spend — run `/cost`. The SDK harness persists per-phase `total_cost_usd` per run.
- **Third-party API credits are NOT in `total_cost_usd`.** `pivot_extract.py`, `whois_enrich.py`
  and friends spend FOFA / WhoisXML / urlscan / IPinfo / Shodan credits and make **zero** Anthropic
  calls. They are logged by `api_usage.record(...)` to `intel_engine/MEMORY/api_usage.jsonl`
  (override with `$API_USAGE_LOG`) and reported via the `api_usage` MCP tool or
  `intel.py api-usage`.

State the split when reporting cost; never imply `total_cost_usd` covers API credits.

> **Any NEW licensed/metered API call MUST call `api_usage.record(...)`.**

WhoisXML note: Whois History and Reverse WHOIS bill to the **Domain Research Suite** balance, not
the WHOIS API balance. A key with WHOIS credits but zero DRS returns 200 for current WHOIS and 403
for both of those. `whois_enrich._explain_403` diagnoses this — do not "fix" it by assuming a bad
key.

---

## When a tracked file genuinely needs an example

Use obvious, non-real placeholders — never a value lifted from a live case:

| Kind | Use |
|---|---|
| domain | `example.com`, `site-a.example`, `site-b.example` |
| email | `registrant@example.com`, `operator@example.com` |
| person / operator | `"Registrant Name"`, `Operator A`, `operator-a` |
| GA4 / GTM / UA | `G-XXXXXXXXXX`, `GTM-XXXXXXX`, `UA-100000001` |
| case ID | `CASE-0001` (or a CLI arg — never hardcode a real one) |
| favicon / hash | a clearly-synthetic value, e.g. `123456789` |
| wallet | `1ExampleBitcoinAddressDoNotUse` |

Generic public constants are fine — registrar and privacy-proxy addresses, CDN/ASN ranges, managed
DNS suffixes, the Sedo/Wix default-favicon hashes, real third-party SaaS *provider* hostnames. They
describe the tooling, not a case.

---

## Config that must stay local

`.mcp.json` is **git-ignored by design** — it holds a machine-specific absolute path. Each machine
generates its own:

```bash
python3 scripts/backend/intel.py mcp --write
```

The launcher it points at (`intel_engine/harness/mcp-server`) *is* tracked and resolves paths from
its own location, so only the registration is per-machine. Same for `.env`, `.venv/`,
`intel_engine/cases/`, `intel_engine/knowledge/`, `intel_engine/MEMORY/`.

---

## Before you commit

- Case data stays in the git-ignored stores — never at the repo root.
- Scan the staged diff for identifiers with `bash scripts/leakcheck.sh`. It runs the ID patterns
  **case-sensitively** (an `-i` flag makes `G-[A-Z0-9]{6}` match inside ordinary hyphenated words
  like `findin`**`g-framew`**`ork`) and drops the approved placeholders, so a hit is always a real
  leak. That precision is the point — a check that cries wolf gets ignored within a week.

  Verified in both directions: it flags a real registrant email, GTM container, ETH address and
  TRON address; it stays silent on `GTM-XXXXXXX`, `G-XXXXXXXXXX`, `registrant@example.com`,
  `CASE-0001`, and on the whole existing `SKILL.md`.

- **Make the leak check self-enforcing:** run `bash scripts/install-hooks.sh` once per clone to
  wire `leakcheck.sh` as a `pre-commit` hook. `.git/hooks/` is per-clone and never travels with the
  skill, so re-run it after cloning. Bypass a single commit with `git commit --no-verify`.

- If a tool needs case-specific behaviour, take it as a **parameter or CLI arg** — never bake the
  case into the code.
- Ran `uv pip install`? Update `requirements.txt`.
- **The vendored engine's own tests run in CI now** — `audit.sh` §8 runs the 15 stdlib-only
  ones on every push; §9 runs the 5 that import `claude_agent_sdk` and SKIPS LOUDLY when it
  is absent, with the `engine tests (with SDK)` job in `.github/workflows/audit.yml`
  failing if that skip ever appears there. Until 2026-08-28 `intel_engine/tests/` ran
  nowhere in CI, which is how 15 `@tool`s sat outside the context governor for two commits
  while the audit stayed green. If you add an engine test, add it to §8 or §9.
- Changed a collector's flags, a `DISPATCH` op, or a `/command`? Update `SKILL.md` §3 in the same
  commit — a stale command reference is the most common way this skill breaks for other people.
