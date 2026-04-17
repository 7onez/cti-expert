---
phase: 5
priority: medium
status: completed
---

# Phase 5 — README and Documentation Updates

## Overview

Update README.md and any relevant docs to reflect v2.3 changes: universal WHOIS, Scrapling collection, AgentFlow enrichment, Python 3.10+ requirement.

## Files to Modify

| File | Action | What Changes |
|------|--------|-------------|
| `README.md` | EDIT | What's New v2.3, Python version bump, new techniques |
| `validation/coverage-matrix.md` | EDIT | Add new technique coverage entries |

## Implementation Steps

### 1. Update README.md

#### a. Add "What's New in v2.3" section (after v2.2 section, ~line 120):

```markdown
## What's New in v2.3

| Category | What's New | Details |
|----------|-----------|---------|
| **WHOIS** | Universal WHOIS for all TLDs | whoisdomain + CLI + Whoxy API; .vn, .th, .sg, .kr, 25+ ccTLD servers |
| **WHOIS** | Reverse & historical WHOIS (free) | Whoxy reverse API, historical lookup, ViewDNS |
| **Web Collection** | Scrapling adaptive scraping | 3-tier: static → anti-bot → JS rendering; headless auto-open |
| **Web Collection** | Headless browser auto-open default | JS-heavy sites auto-detected and rendered via DynamicFetcher |
| **Orchestration** | AgentFlow parallel enrichment | DAG-based parallel pivot expansion for 3+ subjects |
| **Performance** | HTML parsing ~2ms | Scrapling parser replaces slow HTTP scraping |
```

#### b. Bump Python version in Requirements:

Change `Python | 3.8+` to `Python | 3.10+` in all requirement tables.

#### c. Update version badge:

Change `version-2.1` to `version-2.3` in badge URL.

#### d. Update technique count:

Adjust technique catalog count (35 → 38, adding whois-universal, web-collection-scrapling, agentflow-enrichment).

#### e. Update Architecture section:

Add new files to project structure:

```
├── techniques/
│   ├── whois-universal.md         Universal multi-TLD WHOIS
│   ├── web-collection-scrapling.md Scrapling adaptive web collection
│   ├── agentflow-enrichment.md    Parallel enrichment orchestration
│   └── ... (existing)
```

### 2. Update `validation/coverage-matrix.md`

Add rows for new techniques in the coverage matrix.

## Todo List

- [ ] Add What's New v2.3 table to README.md
- [ ] Bump Python version 3.8+ → 3.10+ everywhere
- [ ] Update version badge to 2.3
- [ ] Update technique count 35 → 38
- [ ] Add new files to Architecture section
- [ ] Update coverage-matrix.md with new techniques
- [ ] Update Vietnamese and Chinese README sections

## Success Criteria

- v2.3 changelog clearly documents all 3 new features
- Python 3.10+ requirement visible in all install sections
- Architecture diagram reflects new technique files
- Coverage matrix includes new techniques
