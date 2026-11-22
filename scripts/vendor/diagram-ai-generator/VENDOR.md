# Applied: diagram-ai-generator (approach + spec shape)

- **Upstream:** https://github.com/carlosmgv02/diagram-ai-generator
- **Pinned:** unpinned at copy time — the retained `LICENSE` is byte-identical to upstream
  `master` at commit `f6568cdfb455ad9a26bd182397de5d7f6c192100` (2025-10-02, the last upstream
  commit before the copy was taken on 2026-08-30; compared 2026-11-17).
- **License:** MIT (see `LICENSE` in this directory)
- **Trim:** no upstream code is vendored. This directory holds only `LICENSE` (attribution) and
  this file; everything else upstream (the `src/` hexagonal package, MCP server, provider
  repository, node loader, tests) was left out.

## What is applied

`scripts/cti_cloud_arch.py` applies diagram-ai-generator's approach to the CTI
report: its JSON spec shape (`provider` / `components[{type,category,label}]` /
`connections`) rendered through the [`diagrams`](https://github.com/mingrammer/diagrams)
library with real cloud-provider icons (AWS/Azure/GCP/K8s) via graphviz.

Only the *approach* is applied — not the upstream `src.`-layout hexagonal package
(MCP server, provider repository, node loader). Driving the underlying `diagrams`
library directly with a curated keyword→node map is far leaner and avoids importing
that package's `src.*` module tree. The upstream LICENSE is retained here for
attribution.

## Runtime requirements

- `diagrams` (PyPI) — provisioned on demand via `uv run --with diagrams` in an
  isolated subprocess, so it is NOT a dependency of the main HTML/DOCX generators.
- `graphviz` (the `dot` system binary) — installed by the skill installer
  (`scripts/install.sh` / `scripts/install.ps1`).

## Behavior

Cloud-gated and best-effort: `cti_cloud_arch.build_cloud_png(data)` renders only
when a case's subjects/findings reveal cloud services, and returns None (report
unaffected) when no cloud infra is found, graphviz/`diagrams` are missing, or
`CTI_CLOUD_ARCH=0` disables it.
