# Vendored: archify (render-only subset)

- **Upstream:** https://github.com/tt-a1i/archify
- **Version:** 2.16.0 — tag `v2.16.0`, commit `c826e6c3a7abad19c0f3cd1ca57207d54b1ad8de`
  (tagged 2026-08-30). The 39-file subset was byte-identical to that tag's
  `archify/` tree before the local changes below (git blob hashes compared 2026-11-17).
- **License:** MIT (see `LICENSE` in this directory). Upstream re-licensed to
  **Apache-2.0 on 2026-10-25** (commit `9c306ee`, "adopt Apache-2.0 while preserving
  historical MIT grants"); this 2.16.0 copy stays MIT. **Upgrading past that commit
  changes the licence** — replace `LICENSE`, add any upstream `NOTICE`, and update
  `THIRD_PARTY_NOTICES.md` and the README credits row in the same change.
- **Why vendored:** the CTI HTML report embeds an Archify `architecture` diagram of
  the case entity graph inline (see `scripts/cti_archify.py` and
  `scripts/generate-cti-html.py`). Archify is zero-dependency Node.js, so a trimmed
  copy is committed to keep the report build self-contained (Node.js required).

## What is included (only what `archify render architecture` needs at runtime)

- `bin/archify.mjs` — CLI entry (only the `render` path is used)
- `renderers/` — all renderers + shared modules (validators & brand marks are
  code-generated/embedded here, so no schema/catalog JSON is read at render time)
- `assets/template.html` — the standalone interactive viewer runtime
- `schemas/` — kept for reference/safety; not read during `render`
- `package.json`, `LICENSE`

## What was pruned (not needed for render)

`examples/`, `test/`, `delta/`, `migrations/`, `recipes/`, `brand-marks/`,
`references/`, `scripts/`, and `bin/{open-artifact,preview,visual-check}.mjs`.

## Local changes (cti-expert, 2026-11-17)

These are local modifications to the MIT-licensed 2.16.0 copy, not upstream changes.
The upstream copyright notice and MIT `LICENSE` remain unchanged.

- `assets/template.html`: removed the Google Fonts stylesheet/preconnect links,
  including the noscript link, so opening an embedded Blueprint does not contact
  Google. The existing locally installed/system monospace font stack remains.
- `renderers/shared/brand-marks.mjs`: gated the common `checkedFetch` entry before
  DNS resolution or HTTP(S) requests. Remote brand capture is disabled by default;
  only `ARCHIFY_BRAND_REMOTE=1` explicitly enables it. Preset embedded marks still
  work. This prevents report rendering from reproducing remote pinned brands.
- Integration in `scripts/generate-cti-html.py` (outside the vendor copy): the
  Blueprint subprocess always sets `ARCHIFY_BRAND_REMOTE=0`, overriding inherited
  opt-ins so report builds stay offline. Regression coverage renders through this
  invocation with a network guard and checks the resulting HTML for remote assets.

## Updating

Re-clone upstream at the desired tag and re-copy the included paths above, then
run `node bin/archify.mjs render architecture <ir.json> <out.html>` on a sample to
confirm it still renders. Reapply and review the local changes above before updating;
the report invocation must remain offline. Bump the version in this file.
