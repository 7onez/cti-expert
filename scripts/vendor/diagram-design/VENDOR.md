# Vendored: diagram-design (style guide + self-check)

- **Upstream:** https://github.com/cathrynlavery/diagram-design
- **Pinned:** commit `b52a33bfeef85d43995193ee52c13b485154b7b4` (2026-08-30, "feat(charts):
  consolidate reviewed variants and hardening (#160)"). No version was recorded when the copy was
  taken; on 2026-11-17 all three files were compared by git blob hash and are byte-identical to
  that commit, which was upstream `main` when the copy was made on 2026-08-30. Upstream has since
  changed both files (current `main` differs).
- **License:** MIT (see `LICENSE` in this directory; identical to upstream `LICENSE`)

## What is included

| File here | Upstream path |
|-----------|---------------|
| `style-guide.md` | `skills/diagram-design/references/style-guide.md` |
| `self_check.py` | `skills/diagram-design/scripts/self_check.py` |
| `LICENSE` | `LICENSE` |

Both files are unmodified. `style-guide.md` is the editorial rule set that
`scripts/cti_diagram_design.py` adapts (its own code, not a copy) for the entity and topology SVG
figures; `self_check.py` is kept as the upstream reference checker. Nothing in the report build
imports or executes either file.

## What was pruned

Everything else upstream: the plugin manifests, the other skills and references, the diagram
type templates, the repository lint/verify gates, tests and docs.

## Updating

Copy the two files from the desired upstream commit, re-compare (`git hash-object`), and update
the pinned commit above together with `THIRD_PARTY_NOTICES.md`.
