---
phase: 4
priority: high
status: completed
---

# Phase 4 — Dependencies, Auto-Install, and Cross-Cutting Updates

## Overview

Update requirements.txt, auto-install tables in SKILL.md, and tool-cascade-reference.md for all new tools from phases 1-3.

## Files to Modify

| File | Action | What Changes |
|------|--------|-------------|
| `scripts/requirements.txt` | EDIT | Add whoisdomain, scrapling |
| `SKILL.md` | EDIT | Auto-install table entries, collection method tags |
| `handbook/tool-cascade-reference.md` | EDIT | New cascades (WHOIS, Web Collection, AgentFlow) |
| `techniques/scam-check.md` | EDIT | Scrapling reference for scraping steps |

## Implementation Steps

### 1. Update `scripts/requirements.txt`

Add after existing entries:

```
whoisdomain>=1.20260326
scrapling>=0.2
```

**Note:** `agentflow-py` NOT added to core requirements — it's optional, installed on demand via auto-install. Core requirements stay minimal.

### 2. Update SKILL.md Auto-Install Table (line ~802+)

Add these rows to the Install Commands table:

```markdown
| whoisdomain | `python -c "import whoisdomain" 2>/dev/null` | `pip3 install whoisdomain` |
| Scrapling | `python -c "import scrapling" 2>/dev/null` | `pip3 install scrapling` |
| Scrapling (full) | `python -c "from scrapling.fetchers import StealthyFetcher" 2>/dev/null` | `pip3 install "scrapling[fetchers]" && scrapling install` |
| AgentFlow | `python -c "import agentflow" 2>/dev/null` | `pip3 install agentflow-py` |
```

### 3. Update SKILL.md Collection Method Tags

Current tags (line ~786):
```
[browser] · [search] · [fetch] · [manual]
```

Replace with expanded set:
```
[browser] · [scrapling-dynamic] · [scrapling-stealth] · [scrapling-static] · [search] · [fetch] · [manual] · [whois-lib] · [whois-cli] · [whois-api]
```

### 4. Update `techniques/scam-check.md`

Add collection method note after the overview section (~line 5):

```markdown
> **Collection enhancement:** Web scraping steps (PhishTank, CheckPhish, etc.) 
> use Scrapling fetchers for resilient data collection. See 
> `techniques/web-collection-scrapling.md` for auto-escalation behavior.
```

### 5. Verify `handbook/tool-cascade-reference.md` Has All New Cascades

Ensure phases 1-3 added their respective cascade tables:
- WHOIS / Domain Registration (Phase 1)
- Web Collection / Page Fetching (Phase 2)  
- AgentFlow install entry (Phase 3)

## Todo List

- [ ] Add whoisdomain + scrapling to requirements.txt
- [ ] Add 4 auto-install entries to SKILL.md
- [ ] Expand collection method tags in SKILL.md
- [ ] Add Scrapling reference to scam-check.md
- [ ] Cross-verify all cascade tables exist in tool-cascade-reference.md

## Success Criteria

- requirements.txt includes whoisdomain and scrapling
- All 4 new tools have auto-install entries
- Collection method tags include WHOIS and Scrapling variants
- No duplicate entries in any table
