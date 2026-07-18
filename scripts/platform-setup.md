# Platform Setup & Auto-Install Reference

Single source of truth for running CTI Expert across **Windows, macOS, and Linux**.
The skill consults this file whenever it needs to check for, install, or run a
tool. The goal: zero-friction investigation on any OS — never stall on a missing
dependency, never run a Linux-only command on Windows.

> **uv-first.** [Astral's **uv**](https://docs.astral.sh/uv/) is the preferred toolchain
> for everything Python here — it replaces `pip`, `pipx`, `venv`, and `pyenv` with one
> fast, cross-platform binary, manages its own Python (so Windows' Microsoft Store stub
> is irrelevant), and runs scripts with on-the-fly deps. Because uv behaves identically
> on every OS, it **collapses the per-OS split for Python tools**. The per-OS `pip`/`pipx`/
> `venv` commands below remain documented as the fallback when uv cannot be installed.

> **Cross-agent.** This applies in Claude Code (Desktop & CLI) and in OpenAI Codex / other
> `AGENTS.md`-aware agents alike (see [`../AGENTS.md`](../AGENTS.md)). **`$SKILL_DIR`** = the
> directory containing `SKILL.md` — Claude Code: `~/.claude/skills/cti-expert`; Codex/clone:
> the repo you're working in. Resolve it by locating `SKILL.md`; don't hard-assume `~/.claude`.

---

## 1. Step 0 — Detect the platform (do this once per session)

Before running ANY CLI tool or script, determine the OS and cache the answer for
the rest of the session.

| Signal | Windows | macOS | Linux |
|--------|---------|-------|-------|
| PowerShell `$PSVersionTable.Platform` / `$IsWindows` | `Win32NT` / `$true` | `Unix` / `$false` | `Unix` / `$false` |
| Bash `uname -s` | `MINGW*`, `MSYS*`, `CYGWIN*` (Git Bash) | `Darwin` | `Linux` |
| Python `sys.platform` | `win32` | `darwin` | `linux` |
| Python `os.name` | `nt` | `posix` | `posix` |

**In Claude Code**, the environment block already reports the platform (e.g.
`Platform: win32`). Trust it. If absent, run one probe:

```powershell
# PowerShell (Windows-native)
if ($IsWindows -or $env:OS -eq 'Windows_NT') { 'windows' } elseif ($IsMacOS) { 'macos' } else { 'linux' }
```
```bash
# Bash (macOS / Linux / Git Bash / WSL)
case "$(uname -s)" in Darwin) echo macos;; Linux) echo linux;; MINGW*|MSYS*|CYGWIN*) echo windows;; esac
```

---

## 2. Shell & Python conventions per OS

| Concern | Windows | macOS / Linux |
|---------|---------|---------------|
| Preferred shell tool | **PowerShell** | **Bash** |
| Bash availability | Git Bash / WSL only (not guaranteed) | native |
| **Python runner (preferred)** | **`uv run`** / `uv pip` / `uv tool` | **`uv run`** / `uv pip` / `uv tool` |
| Python launcher (no-uv fallback) | **`py`** (the Python launcher) | **`python3`** |
| `python3`/`python` on PATH | often a **Microsoft Store stub** that prints "Python was not found" — do **not** rely on it (uv avoids this entirely) | real interpreter |
| pip invocation (fallback) | `py -m pip` | `python3 -m pip` |
| "command exists?" check | `Get-Command <tool> -ErrorAction SilentlyContinue` or `where.exe <tool>` | `command -v <tool>` |
| Path separator | `\` (but forward `/` works in most tools) | `/` |
| PATH delimiter | `;` | `:` |

### uv bootstrap (do this once, before other Python work)

uv is the one dependency the preferred path needs. Check `uv --version`; if absent, install:

| OS | Install uv |
|----|-----------|
| **Windows** | `winget install --id astral-sh.uv` — or `powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 \| iex"` |
| **macOS** | `brew install uv` — or `curl -LsSf https://astral.sh/uv/install.sh \| sh` |
| **Linux** | `curl -LsSf https://astral.sh/uv/install.sh \| sh` |
| **Any OS w/ pip** | `python -m pip install uv` |

The official installer drops `uv` in `~/.local/bin` (`%USERPROFILE%\.local\bin` on Windows) — add it to PATH if `uv` isn't found right after install.

### Python interpreter / runner selection

With uv (preferred), you usually don't pick an interpreter at all:
- **Run a script:** `uv run script.py ARGS` (deps from PEP 723 inline metadata, on the fly).
- **Install a CLI tool:** `uv tool install <pkg>`.
- **Install a library into the skill venv:** `uv venv ~/.claude/skills/.venv` (once) then
  `uv pip install --python <venv-python> <pkg>`. Note a uv-created venv has **no pip** — always target it via `uv pip --python`, not `<venv>/python -m pip`.

**No-uv fallback — the `$PY` convention.** Resolve one interpreter and reuse it:

1. **Prefer the skill venv** at `~/.claude/skills/.venv` (Windows `…\Scripts\python.exe`, Unix `…/bin/python3`).
2. **Else the system interpreter:** `py` (Windows) / `python3` (Unix).

```powershell
# PowerShell
$PY = if (Test-Path "$env:USERPROFILE\.claude\skills\.venv\Scripts\python.exe") {
        "$env:USERPROFILE\.claude\skills\.venv\Scripts\python.exe"
      } else { "py" }
```
```bash
# Bash
PY="$HOME/.claude/skills/.venv/bin/python3"; [ -x "$PY" ] || PY="python3"
```

---

## 3. System package manager per OS

| OS | Primary | Fallbacks | Privilege |
|----|---------|-----------|-----------|
| **Windows** | `winget` | `choco`, `scoop` | per-user (no admin for most); winget may prompt UAC |
| **macOS** | `brew` | MacPorts | no sudo (Homebrew is per-user) |
| **Linux** | `apt-get` | `dnf`, `pacman`, `zypper` | `sudo` (prepend `sudo` if not root) |

**Windows note:** if `winget` is absent (older Windows, no App Installer), try
`choco install` / `scoop install`, else point the user to the bundled
`scripts/install.ps1`.

---

## 4. Fastest path — run the bundled installer once

For a fresh machine, bulk-install everything with the OS-native installer rather
than tool-by-tool:

| OS | One-shot command |
|----|------------------|
| **Windows (PowerShell)** | `powershell -ExecutionPolicy Bypass -File "$env:USERPROFILE\.claude\skills\cti-expert\scripts\install.ps1"` |
| **macOS / Linux / Git Bash / WSL** | `bash ~/.claude/skills/cti-expert/scripts/install.sh` |

Flags (both installers): `-Headless`/`--headless` (Scrapling + Chromium ~200 MB),
`-Go`/`--go` (Go tools), `-All`/`--all` (everything).

Both installers **bootstrap uv first**, create the skill venv with `uv venv`, install
libraries with `uv pip`, and install CLI tools with `uv tool` — falling back to
`python -m venv` + `pip`/`pipx` only if uv cannot be installed.

After the bulk install, use the just-in-time table below for any single tool that
turns out to be missing mid-investigation.

---

## 5. Per-tool install matrix (just-in-time)

**Protocol for each tool:** check → if missing, install with the row for the
detected OS → verify → tag the finding `[auto-installed]` → continue. On failure,
fall to the next tool in the cascade; never block the investigation.

### Python OSINT tools (uv — identical on every OS)

**Preferred:** CLIs → `uv tool install <pkg>`; libraries → `uv pip install --python <venv> <pkg>`.
**No-uv fallback:** `<$PY> -m pip install --upgrade <pkg>` for libs (`<$PY>` = `py` on Windows, `python3` on Unix, or the venv python); `pipx install <pkg>` for CLIs.

The **Kind** column says which uv command to use: `CLI` → `uv tool`, `lib` → `uv pip`.

| Tool | Kind | Import / check | Package | Notes |
|------|------|----------------|---------|-------|
| Maigret | CLI | `maigret` | `maigret` | `uv tool install maigret`; needs Cairo on Linux (`libcairo2-dev`) |
| Sherlock | CLI | `sherlock` | `sherlock-project` | `uv tool install sherlock-project` |
| Holehe | CLI | `holehe` | `holehe` | |
| h8mail | CLI | `h8mail` | `h8mail` | |
| theHarvester | CLI | `theHarvester` | `theHarvester` | |
| TruffleHog | CLI | `trufflehog` | `trufflehog` | Go binary also available |
| Waymore | CLI | `waymore` | `waymore` | |
| Xeuledoc | CLI | `xeuledoc` | `xeuledoc` | |
| cloudscraper | lib | `cloudscraper` | `cloudscraper` | `uv pip install` into the venv |
| oletools | lib | `oletools` | `oletools` | document macro analysis |
| whoisdomain | lib | `whoisdomain` | `whoisdomain` | universal WHOIS lib |
| Scrapling | lib | `scrapling` | `scrapling` | add `[fetchers]` + `scrapling install` for headless |
| AgentFlow | lib | `agentflow` | `agentflow` (`--no-deps`) | `uv pip install --no-deps`; avoids urllib3 clash with msftrecon |
| MSFTRecon | CLI/lib | `msftrecon` | `uv pip install "git+https://github.com/Arcanum-Sec/msftrecon.git"` | install from git |
| Blackbird | lib | `blackbird` | clone `github.com/p1ngul1n0/blackbird` + `uv pip install -r requirements.txt` | no PyPI package |
| ShareTrace | lib | `sharetrace` | clone `github.com/7onez/sharetrace` + `uv pip install -r requirements.txt` | no PyPI package |

### System tools (OS package manager)

| Tool | Check | Windows (`winget`) | macOS (`brew`) | Linux (`apt`) |
|------|-------|--------------------|----------------|----------------|
| git | `git` | `winget install Git.Git` | `brew install git` | `sudo apt install -y git` |
| GitHub CLI | `gh` | `winget install GitHub.cli` | `brew install gh` | `sudo apt install -y gh` |
| jq | `jq` | `winget install jqlang.jq` | `brew install jq` | `sudo apt install -y jq` |
| exiftool | `exiftool` | `winget install OliverBetz.ExifTool` | `brew install exiftool` | `sudo apt install -y libimage-exiftool-perl` |
| pandoc | `pandoc` | `winget install JohnMacFarlane.Pandoc` | `brew install pandoc` | `sudo apt install -y pandoc` |
| poppler (pdfinfo) | `pdfinfo` | `winget install oschwartz10612.Poppler` | `brew install poppler` | `sudo apt install -y poppler-utils` |
| qpdf | `qpdf` | `winget install QPDF.QPDF` | `brew install qpdf` | `sudo apt install -y qpdf` |
| whois | `whois` | `winget install Microsoft.Sysinternals.Whois` (or use `whoisdomain` lib) | preinstalled / `brew install whois` | `sudo apt install -y whois` |
| dig | `dig` | `winget install ISC.Bind` | preinstalled | `sudo apt install -y dnsutils` |

> **whois, dig, and asn are now auto-installed** by the bundled installers (`install.ps1` / `install.sh`) — no longer manual steps.
| mat2 | `mat2` | **not supported** → use `exiftool -all= -overwrite_original <file>` | `brew install mat2` | `sudo apt install -y mat2` |
| Go | `go` | `winget install GoLang.Go` | `brew install go` | `sudo apt install -y golang` (or go.dev/dl) |
| agent-browser | `agent-browser` | `npm i -g agent-browser` / `cargo install agent-browser` → `agent-browser install` | `brew install agent-browser` → `agent-browser install` | `npm i -g agent-browser` / `cargo install` → `agent-browser install` |

> **agent-browser** ([vercel-labs](https://github.com/vercel-labs/agent-browser)) is the skill's primary interactive browser collector (CDP, accessibility-tree snapshots, screenshots). No API key for core automation. `agent-browser install` downloads Chrome for Testing (first run). It is complementary to Scrapling — see `techniques/agent-browser.md`. The bundled installers add it under `--headless`/`-Headless`.

### Go tools (need Go installed first; then identical on all OSes)

`go install <module>` works the same everywhere — only the resulting `$GOPATH/bin`
location differs (`%USERPROFILE%\go\bin` vs `$HOME/go/bin`); ensure it's on PATH.

| Tool | Check | Module |
|------|-------|--------|
| Subfinder | `subfinder` | `github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| Amass | `amass` | `github.com/owasp-amass/amass/v4/...@master` |
| GAU | `gau` | `github.com/lc/gau/v2/cmd/gau@latest` |
| Gitleaks | `gitleaks` | `github.com/zricethezav/gitleaks/v8@latest` |
| httpx | `httpx` | `github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| PhoneInfoga | `phoneinfoga` | go module broken — fetch the GitHub **release binary** for the OS/arch (`Windows_`, `Darwin_`, `Linux_` + `x86_64`/`arm64`) |

### ASN / network intelligence

| Platform | `asn` command | How it's installed | Capabilities |
|----------|---------------|--------------------|--------------|
| Linux / macOS / WSL | nitefood/asn | `install.sh` downloads it to `~/.local/bin` + deps (whois, dig, mtr, aha, jq, ipcalc, grepcidr, nmap) | full: BGP graph, whois, traceroute, RPKI, port scan |
| Windows (native) | `scripts/asn.ps1` | `install.ps1` writes an `asn.cmd` wrapper into `~\.local\bin` (on PATH) | keyless IP/ASN/domain lookups via ipwho.is + RDAP |

**Why the split:** nitefood/asn is a 4,800-line bash script driving Unix `whois` (`whois -h <server>`); it hangs under Git Bash because Windows `whois` (Sysinternals) is incompatible, and it needs no API key. On Windows use the native `asn` command (`asn 8.8.8.8`, `asn AS15169`, `asn example.com`); for full BGP/traceroute features run `install.sh` inside WSL.

---

## 6. Known platform gotchas

### uv (all platforms)
- **A `uv venv` has no `pip`.** Install into it with `uv pip install --python <venv-python> …`,
  never `<venv>/python -m pip`. (`ensure_deps()` in the generators and `vpip`/`Invoke-VenvPip`
  in the installers already do this.)
- **uv-managed Python:** `uv run` / `uv tool` fetch and use their own Python, so they work
  even when no usable system Python is on PATH — this is why uv sidesteps the Windows stub.
- **First `uv run` downloads deps** for the ephemeral env (a few seconds); subsequent runs
  reuse uv's cache and are instant.
- **PATH after install:** the official installer puts `uv` in `~/.local/bin`
  (`%USERPROFILE%\.local\bin`); add it to PATH if `uv` isn't found immediately.

### Windows
- **Microsoft Store Python stub:** in the Bash tool, `python3`/`python` may resolve
  to a stub that prints *"Python was not found"*. Prefer **uv** (brings its own Python);
  otherwise use the **`py` launcher** via PowerShell, or the venv python directly.
- **DOCX generation** (`generate-cti-docx-hybrid.py`) now **self-heals**: it forces
  UTF-8 output (so the `→` char doesn't crash cp1252) and locates pandoc under
  `%LOCALAPPDATA%\Pandoc` even when it isn't on PATH. No manual `PYTHONUTF8` or
  PATH prelude is required anymore. If you ever bypass the script, the legacy
  one-liner still works:
  `$env:PATH="$env:LOCALAPPDATA\Pandoc;$env:PATH"; $env:PYTHONUTF8="1"; py <script> REPORT.md REPORT.json REPORT.docx`
- **mat2** depends on GLib and is not available on Windows → fall back to
  `exiftool -all= -overwrite_original <file>` for metadata stripping.
- **winget UAC:** some packages prompt for elevation. If a winget install is
  declined/blocked, note the gap and continue with the next tool in the cascade.
- **PATH refresh:** a freshly winget-installed tool may not be on the current
  shell's PATH until the shell is reopened. Probe common install dirs or restart
  the shell before declaring the install failed.

### macOS
- **Homebrew** is the assumed manager; if `brew` is missing, point the user to
  https://brew.sh. No `sudo` needed for brew.
- Apple Silicon vs Intel: brew lives at `/opt/homebrew/bin` (ARM) vs
  `/usr/local/bin` (Intel) — both are probed by the scripts.

### Linux
- Most installs need **`sudo`**; prepend it when not running as root.
- Maigret needs `libcairo2-dev`; install it before/with maigret.
- `--break-system-packages` is required for pip on Debian/Ubuntu PEP-668 managed
  environments (the generators retry with it automatically).

---

## 7. Behavior rules (all platforms)

- **uv first for anything Python** — `uv tool` for CLIs, `uv pip` for libraries, `uv run`
  for scripts. It behaves identically on every OS; reach for it before per-OS pip/pipx.
  Fall back to `<$PY> -m pip` / `pipx` only when uv cannot be installed.
- **Detect first, install silently, then proceed** — tool installation is a normal
  part of the workflow, not a blocker.
- **Pick the system-binary install command by detected OS** — never run `apt` on Windows
  or `winget` on Linux.
- **Go tools require Go** — if `go` is absent, note the gap and fall back to the
  next tool in the cascade (or a HTTP/API equivalent).
- **Fall back, never block** — if an install fails, log a collection gap and move to
  the next tool. Tag findings with the collection method, adding `[auto-installed]`
  when a tool was installed on demand.
