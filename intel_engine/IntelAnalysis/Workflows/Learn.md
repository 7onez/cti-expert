# Workflow: Close the loop — capture what this case taught

An investigation isn't done when the assessment is written — it's done when the **next**
investigation is smarter for it. Run this at case close, every time. Two things get captured:
a **conclusion** (who the operator is) and any **tradecraft** (a new tell you learned).

## 1. Persist the conclusion → the operator registry

If you assessed a cluster to an operator (same-operator or same-actor), record it so the next
`intel.py open` auto-flags any seed that touches it (`⚠ CONFIRMED-OPERATOR MATCH`):

```bash
python3 tools/kb/operator_registry.py add "Operator Name Or Alias" \
    --domains brand-a.example,brand-b.example \
    --case mycase --confidence assessed \
    --basis "reused GA4 property + shared verification token across all domains"
# audit / look up later:
python3 tools/kb/operator_registry.py list -v
python3 tools/kb/operator_registry.py find brand-a.example
```

- `--confidence` mirrors the assessment word: `assessed` (≥2 attribution-grade artifacts, or 1 +
  named identity) / `likely` / `possible`. Don't record a *lead* as a confirmed operator.
- The ledger lives at `knowledge/operators.jsonl` — **git-ignored** (it names real actors). It is
  private case data, exactly like `cases/` and the rest of `knowledge/`.
- Re-running `add` for the same operator **merges** domains, it never duplicates.

## 2. Persist the tradecraft → the skill

Did this case teach a *reusable* rule — a new artifact tell, a noise pattern, a registrar
quirk, a way one cluster tried to look like two? Append it (one bullet, cited to the in-case
evidence) to the **"Captured (in-case)"** block of the relevant tier in `IntelAnalysis/SKILL.md`
(§1 triage ladder, or §2 correlation). That block is the skill's long-term memory — every future
run reads it. Keep it generic enough to reuse; OPSEC still applies to the *committed* skill, so
scrub real identifiers if this skill is shared (use `brand-a.example`-style placeholders).

## 3. Sanity-check the loop actually closed

```bash
python3 tools/kb/operator_registry.py find <one-domain-from-this-case>   # returns the operator
```

If a domain you just attributed doesn't resolve to its operator here, step 1 didn't take — redo it.

---

**Stop condition for the whole case:** assessment written to `knowledge/reports/<case>/`,
operator recorded in the registry (if one was assessed), and any new tell added to the skill.
Only then is the case closed — because only then does the next case start ahead of where this one did.
