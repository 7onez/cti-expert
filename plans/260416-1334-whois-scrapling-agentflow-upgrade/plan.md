---
status: completed
created: 2026-04-16
completed: 2026-04-17
phases: 5
blockedBy: []
blocks: []
---

# CTI Expert v2.3 — Universal WHOIS + Scrapling + AgentFlow

Three-feature upgrade: (1) universal WHOIS for all TLDs including .vn, (2) Scrapling-based web collection with headless browser auto-open, (3) AgentFlow DAG orchestration for Enrich phase parallelization.

## Research Reports

- [WHOIS Solutions](../reports/whois-researcher-report.md) — embedded in this plan
- [Scrapling Research](../reports/researcher-260416-1331-scrapling-research.md)
- [AgentFlow Research](../reports/researcher-260416-1331-agentflow-cti-integration.md)

## Architecture Decision Records

### ADR-1: WHOIS Strategy
**Decision:** Multi-layer WHOIS cascade: `whoisdomain` (Python, IANA auto-detect) → CLI `whois -h <server>` (TLD-specific) → Whoxy free API (1595+ TLDs) → web scrape fallback.
**Why:** `whoisdomain` covers ~90% of TLDs with zero API auth. CLI whois with TLD→server mapping covers ccTLDs like .vn. Whoxy provides free JSON API for 1595+ TLDs as resilient fallback.
**Trade-off:** Adding `whoisdomain` to requirements.txt adds a dependency, but it's lightweight and actively maintained.

### ADR-2: Scrapling Integration
**Decision:** Add Scrapling as middle tier between WebFetch and agent-browser. Base install only (`pip install scrapling`) in requirements.txt; `scrapling[fetchers]` documented as optional for headless.
**Why:** Scrapling's three fetcher tiers map perfectly to CTI cascade: Fetcher (fast static) → StealthyFetcher (anti-bot) → DynamicFetcher (JS rendering). Keeps base install lightweight.
**Trade-off:** Full headless requires `scrapling install` (Chromium download). Document as optional enhancement, not mandatory.

### ADR-3: AgentFlow Scope
**Decision:** Integrate AgentFlow for Enrich phase ONLY. Do NOT rewrite AEAD lifecycle.
**Why:** Enrich phase has natural parallelism (multiple pivot expansions). Acquire is sequential, Assess has mutable state, Deliver is sequential. AgentFlow 0.1.0 pre-stable — limit blast radius.
**Trade-off:** Limited scope means less dramatic improvement, but much lower risk. Can expand to Assess phase later if findings become immutable.

### ADR-4: Python Version
**Decision:** Bump minimum Python from 3.8 to 3.10 in README.
**Why:** Both Scrapling and AgentFlow require 3.10+. Python 3.8 EOL was Oct 2024. Reasonable upgrade.

## Phase Overview

| Phase | Description | Files Modified | Status |
|-------|-------------|----------------|--------|
| 1 | Universal WHOIS technique | 3 files | Completed |
| 2 | Scrapling web collection | 4 files | Completed |
| 3 | AgentFlow Enrich orchestration | 3 files | Completed |
| 4 | Cross-cutting updates (deps, install, SKILL.md) | 4 files | Completed |
| 5 | README & docs updates | 2 files | Completed |

## Success Criteria

- [x] `whois` command works for .vn, .th, .sg, .kr and other ccTLDs
- [x] WHOIS fallback cascade documented with 4+ layers
- [x] Scrapling 3-tier fetcher integrated into tool priority chain
- [x] Headless browser auto-open is default for JS-heavy sites
- [x] AgentFlow DAG defined for parallel Enrich phase
- [x] All new tools in auto-install table
- [x] Python 3.10+ documented as minimum
- [x] No existing functionality broken

## Cook Command

```bash
/ck:cook /root/.claude/skills/cti-expert/plans/260416-1334-whois-scrapling-agentflow-upgrade/plan.md
```
