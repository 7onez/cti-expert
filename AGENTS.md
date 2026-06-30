# AGENTS.md — CTI Expert (cross-agent operating contract)

CTI Expert is a cyber threat intelligence / OSINT analysis skill. This file is the
**cross-agent entry point** so the skill runs the same way in **Claude Code**
(Desktop & CLI), **OpenAI Codex / ChatGPT**, and any other agent that reads
`AGENTS.md`. It is deliberately short — the full command catalog and operating rules
live in **`SKILL.md`** (read it and follow it), and the complete install matrix lives
in **`scripts/platform-setup.md`**.

> **Claude Code** loads `SKILL.md` directly (this skill is installed under
> `~/.claude/skills/cti-expert`). **Codex** auto-loads this `AGENTS.md` when working
> inside the repo. Both then defer to `SKILL.md` for the analyst workflow.

---

## 1. Skill directory (resolve once, then reuse as `$SKILL_DIR`)

`$SKILL_DIR` = **the directory that contains `SKILL.md`** (this same directory):

- **Claude Code:** `~/.claude/skills/cti-expert`
- **Codex / manual clone:** the repository you are working in (often the current
  working directory, or wherever you cloned `cti-expert`).

All script paths below are written relative to `$SKILL_DIR` so they work everywhere.
Resolve it by finding `SKILL.md`/`AGENTS.md` — never hard-assume `~/.claude`.

---

## 2. Step 0 — Detect the OS (once per session)

Detect Windows / macOS / Linux before running anything and cache it:

- **PowerShell:** `$IsWindows` / `$IsMacOS`; or `$env:OS -eq 'Windows_NT'`
- **Bash:** `uname -s` → `Darwin`=macOS, `Linux`=Linux, `MINGW*`/`MSYS*`/`CYGWIN*`=Windows (Git Bash)
- **Python:** `sys.platform` (`win32`/`darwin`/`linux`), `os.name` (`nt`/`posix`)

Then dispatch by OS: **shell** = PowerShell (Windows) / Bash (Unix); **system package
manager** = `winget` (Windows) / `brew` (macOS) / `sudo apt`·`dnf`·`pacman` (Linux).
Never run a Linux-only command (`apt`) on Windows or vice-versa.

> On Windows, `python3`/`python` is often a non-functional Microsoft Store stub.
> Prefer **uv** (§3, it brings its own Python) or the `py` launcher via PowerShell.

---

## 3. Runtime: uv-first (the portable path)

[Astral's **uv**](https://docs.astral.sh/uv/) is the preferred toolchain for
everything Python — it works identically on every OS, manages its own Python, and runs
scripts with on-the-fly dependencies, so **no venv or pip pre-step is required**. This
is what makes the skill portable across agents.

**Ensure uv once** (`uv --version`; if missing):
- Windows: `winget install --id astral-sh.uv` — or `powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"`
- macOS: `brew install uv` — or `curl -LsSf https://astral.sh/uv/install.sh | sh`
- Linux: `curl -LsSf https://astral.sh/uv/install.sh | sh`
- Any OS with pip: `python -m pip install uv`

If uv truly can't be installed, fall back to `py`/`python3` + `pip`/`pipx` (see
`scripts/platform-setup.md`). Nothing here hard-requires uv.

---

## 4. Generate a DOCX report (works on any OS / any agent)

The generators carry **PEP 723 inline dependencies**, so `uv run` provisions them
automatically. They also self-heal: force UTF-8 output and auto-locate pandoc
(including Windows `%LOCALAPPDATA%\Pandoc`) — no `PYTHONUTF8`/PATH prelude needed.

```bash
# Bash (macOS / Linux / Git Bash). Windows PowerShell: use $env:USERPROFILE\... and backslashes.
S="$SKILL_DIR/scripts"
uv run "$S/generate-cti-docx-hybrid.py" REPORT.md REPORT.json REPORT.docx   # full: narrative + charts
uv run "$S/generate-cti-docx.py"        REPORT.json REPORT.docx             # JSON-only (no pandoc)
# No-uv fallback: python3 (Unix) / py (Windows) "$S/generate-cti-docx-hybrid.py" ...
```

---

## 5. Install OSINT tools on demand

Detect → check → install with the OS-correct method → continue (never block). With uv,
Python tools are OS-agnostic: **CLIs** `uv tool install <pkg>` · **libraries**
`uv pip install --python <venv> <pkg>`. System binaries (git, pandoc, exiftool, jq…) use
the OS package manager. **Bulk install:** run `$SKILL_DIR/scripts/install.ps1` (Windows)
or `$SKILL_DIR/scripts/install.sh` (macOS/Linux/Git Bash/WSL) — both bootstrap uv. The
full per-tool × per-OS matrix is in `scripts/platform-setup.md`.

---

## 6. Environments without code execution (plain ChatGPT, web)

The **analyst reasoning** — query/dork generation, source interpretation, finding
framework, exposure scoring, report drafting — works in any LLM with no execution. Only
the **local steps** (DOCX build, tool installs, CLI recon) need a code-capable harness
(Codex sandbox, Claude Code). In a no-exec environment: produce the full **Markdown**
report and note the `.docx` build + any CLI enrichment as follow-ups to run where
execution is available. Do not claim a tool ran when it didn't.

---

## 7. Using this skill in Codex / ChatGPT

- **Auto (in-repo):** open Codex in the `cti-expert` repo — it loads this `AGENTS.md`
  automatically. Then ask it to follow `SKILL.md`.
- **Global default:** add a line to `~/.codex/AGENTS.md` pointing at the skill, e.g.
  *"For CTI/OSINT tasks, read and follow `<path>/cti-expert/SKILL.md`."*
- **`/cti-expert` slash command:** copy `codex/cti-expert.md` (in this repo) to
  `~/.codex/prompts/cti-expert.md`. Then `/cti-expert <target>` invokes it.

Full reference: [`SKILL.md`](SKILL.md) (commands & workflow) ·
[`scripts/platform-setup.md`](scripts/platform-setup.md) (OS detection & install matrix).

---

## 8. Best environment for this skill (tell the user if limited)

This skill is **execution-heavy** — local shell, file output, external recon, persistent
workspaces. It runs best where there is a **real local shell + persistent filesystem +
open network**: a **CLI** (Claude Code CLI / Codex CLI) or a **local desktop/IDE agent**
(Claude Code Desktop / Codex IDE extension). In an **ephemeral cloud sandbox**
(claude.ai/code web, Codex cloud / ChatGPT web), reasoning and query generation still
work, but generated files won't persist to the user's disk and outbound network is often
restricted. **If you detect you're in such an environment, say so**, produce the Markdown
report, and flag the `.docx` build + any CLI recon as steps to run in a local CLI/desktop.
