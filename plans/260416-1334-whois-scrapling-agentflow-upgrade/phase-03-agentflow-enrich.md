---
phase: 3
priority: medium
status: completed
---

# Phase 3 — AgentFlow Enrich Phase Orchestration

## Overview

Integrate AgentFlow DAG orchestration into the Enrich phase ONLY. Enables parallel pivot expansion when multiple subjects/identifiers need enrichment simultaneously. NOT a full AEAD rewrite.

## Key Insights

- AgentFlow provides declarative Python DSL with fanout/merge primitives
- Best fit: Enrich phase has natural parallelism (domain→IP, username→email, email→breach)
- Acquire is sequential (user-driven), Assess has mutable state (risky), Deliver is sequential
- AgentFlow 0.1.0 — pre-stable, limit blast radius to Enrich only
- Potential 6-10x speedup for multi-subject enrichment

## Architecture Decision

AgentFlow orchestrates **Enrich phase pivot expansion** as a DAG:

```
                    ┌─ /email-deep email1 ──┐
   Acquired         │                       │
   Findings    ─────┼─ /breach-deep email2 ─┼──── Merge + Dedup ──── Enriched
   (subjects)       │                       │     Findings
                    ├─ /username handle1 ───┤
                    │                       │
                    └─ /subdomain domain1 ──┘
```

## Where AgentFlow Fits (and Doesn't)

| AEAD Phase | AgentFlow? | Reason |
|------------|-----------|--------|
| **Acquire** | NO | Sequential user-driven collection; no parallelism benefit |
| **Enrich** | **YES** | Multiple independent pivot expansions can run in parallel |
| **Assess** | NO | Findings are mutable during scoring; merge logic fragile |
| **Deliver** | NO | Sequential report generation; no parallelism benefit |

## Files to Modify

| File | Action | What Changes |
|------|--------|-------------|
| `techniques/agentflow-enrichment.md` | **CREATE** | AgentFlow integration for parallel enrichment |
| `SKILL.md` | EDIT | Add AgentFlow to adaptive chaining section |
| `handbook/tool-cascade-reference.md` | EDIT | Add AgentFlow entry to install table |

## Implementation Steps

### 1. Create `techniques/agentflow-enrichment.md`

New technique file (~150 lines):

```markdown
# AgentFlow Enrichment Orchestration

## 1. Overview
AgentFlow provides DAG-based orchestration for parallel enrichment of 
discovered identifiers. When /case or /sweep discovers multiple subjects, 
AgentFlow fans out enrichment commands and merges results.

## 2. When to Use
- 3+ subjects discovered during Acquire phase
- Multiple independent enrichment paths (email→breach, domain→subdomain, etc.)
- Single-subject cases: skip AgentFlow, run enrichment sequentially (overhead > gain)

## 3. Installation
  pip3 install agentflow-py
  # Deps: FastAPI, Pydantic, boto3 (lightweight, ~20MB total)

## 4. Enrichment DAG Pattern

Conceptual flow for /case pipeline:

  # After Acquire phase discovers subjects:
  subjects = [
    {"type": "email", "value": "target@domain.com", "enrich_with": "/email-deep"},
    {"type": "email", "value": "target@domain.com", "enrich_with": "/breach-deep"},
    {"type": "domain", "value": "target.com", "enrich_with": "/subdomain"},
    {"type": "username", "value": "targetuser", "enrich_with": "/username"},
  ]

  # AgentFlow fans out:
  # - /email-deep target@domain.com    ─┐
  # - /breach-deep target@domain.com   ─┼─ run in parallel
  # - /subdomain target.com            ─┤
  # - /username targetuser             ─┘
  #                                     │
  #                              merge + dedup
  #                                     │
  #                              enriched findings

## 5. Integration with /case Command

Current /case flow (sequential):
  Acquire → Enrich (one-by-one) → Assess → Deliver

Enhanced /case flow (parallel enrichment):
  Acquire → [AgentFlow fanout enrichment] → Assess → Deliver

Trigger conditions:
- Auto-enable when Acquire phase discovers 3+ unique subjects
- Skip for single-subject investigations (overhead > benefit)
- User can force with /case --parallel or disable with /case --sequential

## 6. Enrichment Command Mapping

| Subject Type | Enrichment Commands | Parallelizable |
|-------------|-------------------|----------------|
| Email | /email-deep, /breach-deep, /proton-check | Yes (independent) |
| Domain | /subdomain, /dns-history, /cert-history, /techstack | Yes |
| Username | /username (maigret/sherlock) | Yes (I/O bound) |
| Phone | /phone | Yes |
| IP | /threat-check | Yes |
| Person | /query (Google dorks) | Yes |

## 7. Merge Strategy

After parallel enrichment completes:
1. Collect all findings from parallel branches
2. Deduplicate by (subject, finding_type, source) tuple
3. Resolve conflicts: higher trust score wins
4. Feed merged findings into Assess phase (/exposure, /validate)

## 8. Concurrency Limits

| Environment | Max Concurrent | Rationale |
|-------------|---------------|-----------|
| Local (default) | 4 | Avoid rate limiting on free APIs |
| With rate limiting | 8 | If per-API rate limits handled |
| EC2 (future) | 16 | Remote execution, higher bandwidth |

## 9. Limitations

- AgentFlow 0.1.0 — pre-stable, breaking changes possible
- Pin version in requirements.txt: `agentflow-py==0.1.0`
- Enrichment commands must have deterministic outputs (no shared state mutation)
- Network-bound: parallelism gains capped by API rate limits
- Single-subject cases gain nothing — skip orchestration

## 10. Fallback

If AgentFlow unavailable or errors:
- Fall back to sequential enrichment (current behavior)
- Log: [enrichment-sequential-fallback] in collection method
- No investigation impact — just slower
```

### 2. Update SKILL.md — Adaptive Chaining Section

After line ~766, enhance the adaptive chaining description:

```markdown
**Adaptive chaining:** Each phase feeds newly discovered identifiers into 
subsequent phases automatically. If `/sweep` on a domain finds an email, 
`/email-deep` and `/breach-deep` trigger on it automatically.

**Parallel enrichment (3+ subjects):** When Acquire discovers 3+ subjects, 
enrichment commands fan out in parallel via AgentFlow DAG orchestration. 
Each subject's enrichment runs independently, results merge with dedup 
before Assess phase. Disable with `--sequential` flag.
```

### 3. Add AgentFlow to `handbook/tool-cascade-reference.md` Install Table

```markdown
| AgentFlow | `pip3 install agentflow-py` | Python | Orchestration |
```

## Todo List

- [ ] Create `techniques/agentflow-enrichment.md` (~150 lines)
- [ ] Update SKILL.md adaptive chaining description
- [ ] Add AgentFlow install entry to tool-cascade-reference.md
- [ ] Document /case --parallel and --sequential flags

## Success Criteria

- AgentFlow DAG pattern documented for Enrich phase
- Trigger condition clear: 3+ subjects auto-enables parallel
- Fallback to sequential enrichment documented
- Concurrency limits defined (4 local default)
- Merge/dedup strategy specified

## Risk Assessment

- **AgentFlow stability:** Pin to 0.1.0, quarterly review for updates
- **Rate limiting:** 4 concurrent default prevents API abuse
- **Complexity:** Enrich-only scope limits blast radius
- **Fallback:** Sequential enrichment always available
