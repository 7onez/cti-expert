# Phase task prompts — single source of truth

Each phase of the harness has two prompt inputs:

- its **system prompt** — the pinned skill body (`WebPivot`, `IntelAnalysis`), loaded by
  `orchestrator._skill()`; and
- its **task prompt** — *what to do this phase* (which tools to call, in what order, the
  empty-result / TLS / reference rules, the output contract). Those live **here**, one file
  per phase, instead of as string literals buried in `orchestrator.py`.

Keeping them as files means the wording is editable and diff-able on its own, and both
front-ends (`orchestrator.py` and the `IntelHarness` skill) can point at the same text
instead of drifting apart.

| File | Phase | Placeholders (`{{token}}`) |
|---|---|---|
| `collect.md` | Collect | `{{scope}}` `{{case}}` `{{prior}}` `{{hostile_note}}` `{{seed_lines}}` |
| `collect_one.md` | Collect (fan-out, one seed) | `{{scope}}` `{{case}}` `{{prior}}` `{{hostile_note}}` `{{seed_lines}}` |
| `correlate.md` | Correlate | `{{scope}}` `{{case}}` `{{seed_csv}}` |
| `verify.md` | Adversarial verify | `{{scope}}` `{{case}}` `{{seed_csv}}` |
| `assess.md` | Assess | `{{scope}}` |

`{{scope}}` is the case INTAKE record rendered by `harness/case_scope.py` — the target class and
its fetch posture / ownership rule for the collect phases, and the premise under test plus the
verdict vocabulary for the judgment phases. It is never empty: a case with no stated scope renders
the conservative `unknown` block, which tells the model to disclose that it is assuming.

Placeholders are `{{token}}` and are filled by `orchestrator._prompt(name, **kwargs)`;
any token with no matching kwarg is left intact. Plain `{ }` and `$` are **not** special, so
edit the prose freely — only `{{…}}` is substituted.
