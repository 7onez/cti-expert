#!/usr/bin/env bash
# CTI Expert — all-in-one tool installer
# Usage: bash scripts/install.sh [--headless] [--go] [--all]
#   --headless  Auto-install Scrapling headless browser (downloads ~200MB Chromium)
#   --go        Install Go-based tools (requires Go 1.21+)
#   --all       Install everything including headless + Go tools
#
# Package engine: uv-first (Astral's uv handles the venv, `uv pip`, and `uv tool`);
# bootstraps uv automatically, and falls back to python3 -m venv + pip/pipx when uv
# cannot be installed *or* when a PATH wrapper intercepts `uv pip`. Every tool is
# probed for the subcommand it is actually asked to run, never just `command -v`.
# Supported platforms: Linux (apt), macOS (brew), Windows (Git Bash / WSL).

set -euo pipefail

SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# ── Platform detection ────────────────────────────────────────
RAW_OS="$(uname -s)"
case "$RAW_OS" in
  Linux)             OS="linux" ;;
  Darwin)            OS="macos" ;;
  MINGW*|MSYS*|CYGWIN*) OS="windows" ;;
  *)                 OS="unknown" ;;
esac

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) ARCH="x86_64" ;;
  aarch64|arm64) ARCH="arm64" ;;
esac

# ── Venv paths differ on Windows ─────────────────────────────
VENV_DIR="$HOME/.claude/skills/.venv"
if [[ "$OS" == "windows" ]]; then
  VENV_BIN="$VENV_DIR/Scripts"
else
  VENV_BIN="$VENV_DIR/bin"
fi
VENV_PIP="$VENV_BIN/pip"
VENV_PYTHON="$VENV_BIN/python3"
[[ "$OS" == "windows" && ! -f "$VENV_PYTHON" ]] && VENV_PYTHON="$VENV_BIN/python"

OPT_HEADLESS=false
OPT_GO=false
OPT_ALL=false
for arg in "$@"; do
  case $arg in
    --headless) OPT_HEADLESS=true ;;
    --go)       OPT_GO=true ;;
    --all)      OPT_HEADLESS=true; OPT_GO=true; OPT_ALL=true ;;
  esac
done

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
BOLD='\033[1m'

INSTALLED=0; SKIPPED=0; FAILED=0

log_ok()   { echo -e "  ${GREEN}✔${NC} $1"; INSTALLED=$((INSTALLED+1)); }
log_skip() { echo -e "  ${YELLOW}–${NC} $1 (no update applied)"; SKIPPED=$((SKIPPED+1)); }
log_fail() { echo -e "  ${RED}✘${NC} $1 — $2"; FAILED=$((FAILED+1)); }
section()  { echo -e "\n${BOLD}${CYAN}▶ $1${NC}"; }

has()    { command -v "$1" &>/dev/null; }
has_py() { "$VENV_PYTHON" -c "import $1" &>/dev/null 2>&1; }

# Every capability probe below is time-capped. A wrapper script that shadows a
# real tool on PATH can hang indefinitely — two wrappers that each re-scan PATH
# for "the real binary" while skipping only their own directory will exec each
# other forever — and an installer must never inherit that hang.
if has timeout; then
  probe() { timeout 20 "$@"; }
else
  probe() { "$@"; }
fi

# ── Real-binary resolution ────────────────────────────────────
# `command -v` only proves *a* file with that name is on PATH. It does not prove
# the file performs the work: PATH commonly fronts wrapper scripts that reject
# the exact subcommands this installer needs (Claude Code's modern-python plugin
# shims `uv`, `python3`, `pip3` and `pipx` this way, refusing `uv pip` and
# `python3 -m` outright). So probe every PATH candidate and keep the first that
# actually works, falling back to the next when one refuses.

# Echo the first PATH candidate for command $1 that satisfies check function $2.
resolve_bin() {
  local name="$1" check="$2" cand
  while IFS= read -r cand; do
    [[ -x "$cand" ]] || continue
    if "$check" "$cand"; then printf '%s\n' "$cand"; return 0; fi
  done < <(type -aP "$name" 2>/dev/null)
  return 1
}

_check_uv()     { probe "$1" --version 2>/dev/null | grep -q '^uv '; }
_check_uv_pip() { _check_uv "$1" && probe "$1" pip list --help &>/dev/null; }
_check_python() { probe "$1" -c 'pass' &>/dev/null; }
_check_pip()    { probe "$1" --version &>/dev/null; }
_check_pipx()   { probe "$1" --version &>/dev/null; }

# Re-run after any bootstrap step that may have installed one of these.
detect_bins() {
  UV_BIN="$(resolve_bin uv _check_uv || true)"
  UV_PIP_BIN="$(resolve_bin uv _check_uv_pip || true)"  # empty when `uv pip` is intercepted
  [[ -n "$UV_PIP_BIN" ]] && UV_BIN="$UV_PIP_BIN"        # prefer a fully working uv
  PY3_BIN="$(resolve_bin python3 _check_python || true)"
  PIP3_BIN="$(resolve_bin pip3 _check_pip || true)"
  PIPX_BIN="$(resolve_bin pipx _check_pipx || true)"
  return 0
}
UV_BIN=""; UV_PIP_BIN=""; PY3_BIN=""; PIP3_BIN=""; PIPX_BIN=""
detect_bins

# Root/sudo handling — VPSes & containers frequently run as root with no `sudo`
# binary installed, so never hard-assume `sudo` exists.
if [[ "$(id -u 2>/dev/null)" == "0" ]]; then
  SUDO=""
elif has sudo; then
  SUDO="sudo"
else
  SUDO=""   # non-root without sudo: system-package installs may fail, but uv/pip --user still work
fi

# A uv-created venv ships no pip, so the pip fallback has to bootstrap one.
ensure_venv_pip() {
  "$VENV_PYTHON" -m pip --version &>/dev/null && return 0
  "$VENV_PYTHON" -m ensurepip --upgrade &>/dev/null 2>&1 || true
  "$VENV_PYTHON" -m pip --version &>/dev/null
}

# Install Python packages into the skill venv. uv-first (targeted with
# `--python` so it installs into the venv rather than a uv project), then the
# venv's own pip — reached both when uv is absent and when `uv pip` is refused
# or fails on a given package.
vpip() {
  if [[ -n "$UV_PIP_BIN" ]] && "$UV_PIP_BIN" pip install --python "$VENV_PYTHON" "$@"; then
    return 0
  fi
  ensure_venv_pip && "$VENV_PYTHON" -m pip install "$@"
}

# Bootstrap uv itself — the one dependency the uv-first path needs.
uv_pip_note() {
  [[ -n "$UV_BIN" && -z "$UV_PIP_BIN" ]] || return 0
  echo -e "  ${YELLOW}!${NC} \`uv pip\` is intercepted by a PATH wrapper ($UV_BIN) — using the venv's pip for package installs"
}

ensure_uv() {
  if [[ -n "$UV_BIN" ]]; then
    log_ok "uv $(probe "$UV_BIN" --version 2>/dev/null | awk '{print $2}') (present)"
    uv_pip_note
    return 0
  fi
  # On a fresh Linux box (esp. minimal VPS/containers) install the prerequisites the
  # uv installer + venv fallback need, before anything else. python3-pip matters
  # because the pip fallback is what runs whenever uv is unusable.
  if [[ "$OS" == "linux" ]] && has apt-get; then
    $SUDO apt-get update -y &>/dev/null 2>&1 || true
    $SUDO apt-get install -y curl ca-certificates git python3 python3-venv python3-pip &>/dev/null 2>&1 || true
  fi
  if [[ "$OS" == "macos" ]] && has brew; then brew install uv &>/dev/null 2>&1 || true; fi
  detect_bins
  if [[ -z "$UV_BIN" ]] && has curl; then
    curl -LsSf https://astral.sh/uv/install.sh | sh &>/dev/null 2>&1 || true
    export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"
    detect_bins
  fi
  if [[ -z "$UV_BIN" ]] && has wget; then
    wget -qO- https://astral.sh/uv/install.sh | sh &>/dev/null 2>&1 || true
    export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"
    detect_bins
  fi
  if [[ -z "$UV_BIN" && -n "$PIP3_BIN" ]]; then
    "$PIP3_BIN" install --user uv &>/dev/null 2>&1 || true
    export PATH="$HOME/.local/bin:$PATH"
    detect_bins
  fi
  if [[ -n "$UV_BIN" ]]; then
    log_ok "uv $(probe "$UV_BIN" --version 2>/dev/null | awk '{print $2}') installed"
    uv_pip_note
  else
    log_skip "uv (could not install — using pip/venv fallback; see https://astral.sh/uv)"
  fi
}

# Interactive browser collector (vercel-labs/agent-browser) — primary browser tool.
ensure_agent_browser() {
  if has agent-browser; then
    log_ok "agent-browser (present)"
  elif has npm; then
    npm install -g agent-browser &>/dev/null 2>&1 && log_ok "agent-browser (npm)" || log_fail "agent-browser" "npm install -g agent-browser failed"
  elif [[ "$OS" == "macos" ]] && has brew; then
    brew install agent-browser &>/dev/null 2>&1 && log_ok "agent-browser (brew)" || log_fail "agent-browser" "brew install agent-browser failed"
  elif has cargo; then
    cargo install agent-browser &>/dev/null 2>&1 && log_ok "agent-browser (cargo)" || log_fail "agent-browser" "cargo install agent-browser failed"
  else
    log_skip "agent-browser (needs npm, brew, or cargo — see techniques/agent-browser.md)"
  fi
  if has agent-browser; then
    agent-browser install &>/dev/null 2>&1 && log_ok "agent-browser Chrome runtime" || log_skip "agent-browser Chrome (run: agent-browser install)"
  fi
}

apt_install() {
  # $1 apt package · $2 command to probe (default $1) · $3 brew formula (default $1).
  # apt and Homebrew disagree on names for several packages (dnsutils->bind, poppler-utils->poppler,
  # libimage-exiftool-perl->exiftool); passing $3 lets one call install correctly on both OSes.
  local pkg="$1" cmd="${2:-$1}" brew_pkg="${3:-$1}"
  # Linux is not only Debian/Ubuntu. Without apt-get there is nothing to run, so
  # report the state honestly instead of failing on "apt-get: command not found".
  if [[ "$OS" == "linux" ]] && ! has apt-get; then
    if has "$cmd"; then
      log_skip "$pkg (present; no apt-get to upgrade it)"
    else
      log_fail "$pkg" "no apt-get on this Linux — install '$pkg' with your package manager (dnf/pacman/apk/zypper)"
    fi
    return
  fi
  if has "$cmd"; then
    if [[ "$OS" == "linux" ]]; then
      if $SUDO apt-get install --only-upgrade -y "$pkg" &>/dev/null 2>&1; then
        log_ok "$pkg updated"
      else
        log_skip "$pkg"
      fi
    elif [[ "$OS" == "macos" ]]; then
      if has brew && brew upgrade "$brew_pkg" &>/dev/null 2>&1; then
        log_ok "$brew_pkg updated"
      else
        log_skip "$brew_pkg"
      fi
    else
      log_skip "$pkg"
    fi
  elif [[ "$OS" == "linux" ]]; then
    if $SUDO apt-get install -y "$pkg" &>/dev/null 2>&1; then
      log_ok "$pkg"
    else
      log_fail "$pkg" "try: sudo apt-get update && sudo apt install $pkg"
    fi
  elif [[ "$OS" == "macos" ]]; then
    if has brew && brew install "$brew_pkg" &>/dev/null 2>&1; then
      log_ok "$brew_pkg"
    else
      log_fail "$brew_pkg" "try: brew install $brew_pkg"
    fi
  else
    log_fail "$pkg" "Windows: install manually (winget or choco)"
  fi
}

pip_install() {
  local pkg="$1" import_name="${2:-}"
  local check_name="${import_name:-${pkg//-/_}}"
  check_name="${check_name%%\[*}"
  local already=false
  has_py "$check_name" && already=true

  if vpip --quiet --upgrade "$pkg" 2>/dev/null; then
    if [[ "$already" == true ]]; then
      log_ok "$pkg updated"
    else
      log_ok "$pkg"
    fi
  else
    log_fail "$pkg" "install (uv pip / pip) failed"
  fi
}

blackbird_install() {
  local already=false
  local blackbird_repo="https://github.com/p1ngul1n0/blackbird.git"
  local blackbird_dir="$HOME/.claude/skills/cti-expert/vendor/blackbird"
  has_py "blackbird" && already=true
  mkdir -p "$(dirname "$blackbird_dir")"
  if [[ -d "$blackbird_dir/.git" ]]; then
    git -C "$blackbird_dir" pull --quiet 2>/dev/null || true
  else
    rm -rf "$blackbird_dir" 2>/dev/null
    git clone --quiet --depth 1 "$blackbird_repo" "$blackbird_dir" 2>/dev/null
  fi
  # Relax version pins that prevent Python 3.14 binary wheels from being used
  if [[ -f "$blackbird_dir/requirements.txt" ]]; then
    sed -i \
      -e 's/aiohttp==.*/aiohttp>=3.13/' \
      -e 's/yarl==.*/yarl>=1.17/' \
      -e 's/multidict==.*/multidict>=6.0/' \
      -e 's/aiohappyeyeballs==.*/aiohappyeyeballs>=2.3/' \
      -e 's/aiosignal==.*/aiosignal>=1.3/' \
      -e 's/frozenlist==.*/frozenlist>=1.4/' \
      -e 's/propcache==.*/propcache>=0.2/' \
      "$blackbird_dir/requirements.txt" 2>/dev/null || true
  fi
  if [[ -f "$blackbird_dir/requirements.txt" ]] && { { [[ -n "$UV_PIP_BIN" ]] && "$UV_PIP_BIN" pip install --python "$VENV_PYTHON" --quiet --upgrade -r "$blackbird_dir/requirements.txt"; } || { ensure_venv_pip && "$VENV_PYTHON" -m pip install --quiet --upgrade --prefer-binary -r "$blackbird_dir/requirements.txt"; }; } 2>/dev/null; then
    SITE_PKG="$("$VENV_PYTHON" -c "import site; print(site.getsitepackages()[0])" 2>/dev/null)"
    if [[ -n "$SITE_PKG" ]]; then
      echo "$blackbird_dir" > "$SITE_PKG/blackbird.pth"
      if [[ "$already" == true ]]; then
        log_ok "blackbird updated from source"
      else
        log_ok "blackbird (source checkout)"
      fi
    else
      log_fail "blackbird" "could not resolve venv site-packages"
    fi
  else
    log_fail "blackbird" "clone/update or pip install -r requirements.txt failed"
  fi
}

agentflow_install() {
  local already=false
  has_py "agentflow" && already=true
  if vpip --quiet --upgrade --no-deps agentflow 2>/dev/null; then
    if [[ "$already" == true ]]; then
      log_ok "agentflow updated"
    else
      log_ok "agentflow"
    fi
  else
    log_fail "agentflow" "install (uv pip / pip) --no-deps agentflow failed"
  fi
}

# Install an isolated CLI tool onto PATH. uv-first (`uv tool`, the pipx replacement);
# fall back to pipx. $1 may be a PyPI name or any spec uv/pipx accepts (e.g. a
# `git+https://…` URL), so $4 supplies a readable name for the log line.
pipx_install() {
  local tool="$1" cmd="${2:-$1}" pre_pkg="${3:-}" label="${4:-$1}"
  local already=false
  has "$cmd" && already=true
  if [[ -n "$pre_pkg" ]] && [[ "$OS" == "linux" ]] && has apt-get; then
    $SUDO apt-get install -y "$pre_pkg" &>/dev/null 2>&1 || true
  fi
  if [[ -n "$UV_BIN" ]]; then
    if [[ "$already" == true ]] && "$UV_BIN" tool upgrade "$tool" &>/dev/null 2>&1; then
      log_ok "$label updated (uv tool)"; return
    elif "$UV_BIN" tool install --force "$tool" &>/dev/null 2>&1; then   # --force overwrites a stale shim from a prior pip/pipx install
      [[ "$already" == true ]] && log_ok "$label updated (uv tool)" || log_ok "$label (uv tool)"
      return
    fi
    # uv tool failed (e.g. package exposes no CLI entry point) — fall through to pipx
  fi
  if [[ -n "$PIPX_BIN" ]]; then
    if [[ "$already" == true ]]; then
      if "$PIPX_BIN" upgrade "$tool" &>/dev/null 2>&1; then
        log_ok "$label updated"
      else
        log_skip "$label ($cmd)"
      fi
    elif "$PIPX_BIN" install "$tool" &>/dev/null 2>&1; then
      log_ok "$label"
    else
      log_fail "$label" "pipx install $tool failed"
    fi
  else
    log_fail "$label" "no uv or pipx — install uv (https://astral.sh/uv) or run: pip3 install pipx"
  fi
}

go_install() {
  local tool="$1" cmd="$2" mod="$3"
  local already=false
  has "$cmd" && already=true
  if go install "$mod" &>/dev/null 2>&1; then
    if [[ "$already" == true ]]; then
      log_ok "$tool updated"
    else
      log_ok "$tool"
    fi
  else
    log_fail "$tool" "go install $mod failed"
  fi
}

# First dotted version number in a tool's version output ("trufflehog 3.96.0"
# -> 3.96.0), or a release tag ("v3.96.0" -> 3.96.0). Must never return non-zero:
# a no-match grep inside `v=$(version_of ...)` is a failing simple command, which
# under `set -e` takes down the whole installer.
version_of() { grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' <<<"${1:-}" | head -1 || true; }

# An older copy of the same tool earlier on PATH silently wins over the one just
# installed, so the upgrade has no visible effect. Say so rather than reporting a
# success the shell will not honour.
gh_binary_shadow_warn() {
  local cmd="$1" install_dir="$2" ver_args="${3:---version}" active shadow_ver
  active="$(command -v "$cmd" 2>/dev/null || true)"
  [[ -n "$active" && "$active" != "$install_dir/$cmd" ]] || return 0
  shadow_ver="$(version_of "$(probe "$active" $ver_args 2>&1 | head -1 || true)")"
  echo -e "  ${YELLOW}!${NC} PATH resolves $cmd to $active${shadow_ver:+ ($shadow_ver)} — shadows $install_dir/$cmd"
}

# Download pre-built binary from GitHub releases, upgrading in place when the
# release is newer than what is installed.
gh_binary_install() {
  local tool="$1" cmd="$2" repo="$3" asset_pattern="$4" install_dir="${5:-/usr/local/bin}" ver_args="${6:---version}"
  local already=false
  has "$cmd" && already=true

  local api_path="repos/$repo/releases/latest"
  local api_url="https://api.github.com/$api_path"

  # Compare installed vs latest before downloading ~35MB. Skipping purely because
  # the command exists (the old behaviour) pins the box to whatever stale copy
  # happens to be on PATH and makes the tool un-upgradable.
  local cur_ver="" latest_ver="" latest_tag=""
  if [[ "$already" == true ]]; then
    # $ver_args is intentionally unquoted — tools differ ("--version" vs "version").
    cur_ver="$(version_of "$(probe "$cmd" $ver_args 2>&1 | head -1 || true)")"
    if has gh; then
      latest_tag=$(gh api "$api_path" --jq .tag_name 2>/dev/null) || true
    elif has curl && has jq; then
      latest_tag=$(curl -sL "$api_url" | jq -r .tag_name 2>/dev/null) || true
    fi
    latest_ver="$(version_of "$latest_tag")"
    if [[ -n "$cur_ver" && -n "$latest_ver" && "$cur_ver" == "$latest_ver" ]]; then
      log_ok "$tool $cur_ver (latest)"
      gh_binary_shadow_warn "$cmd" "$install_dir" "$ver_args"
      return
    fi
  fi
  # Resolve the release asset URL. Prefer gh; fall back to curl/wget + jq (both
  # ensured earlier) so PhoneInfoga installs on boxes without the GitHub CLI.
  # $asset_pattern is a regex being embedded in a jq *string literal*, so each of
  # its backslashes must survive JSON unescaping. Passing `\.` through verbatim
  # makes both jq and gh's gojq abort with "invalid escape sequence".
  local jq_pattern="${asset_pattern//\\/\\\\}"
  local jq_filter=".assets[] | select(.name | test(\"$jq_pattern\")) | .browser_download_url"
  local url=""
  # Each lookup is `|| true`: under `set -e` a bare `url=$(failing cmd)` is a
  # simple command, so a failed API call would kill the whole installer instead
  # of falling through to the log_fail below.
  if has gh; then
    url=$(gh api "$api_path" --jq "$jq_filter" 2>/dev/null | head -1) || true
  elif has jq && has curl; then
    url=$(curl -sL "$api_url" | jq -r "$jq_filter" 2>/dev/null | head -1) || true
  elif has jq && has wget; then
    url=$(wget -qO- "$api_url" | jq -r "$jq_filter" 2>/dev/null | head -1) || true
  else
    log_fail "$tool" "need gh, or curl/wget + jq, to query GitHub releases"
    return
  fi
  if [[ -z "$url" ]]; then
    log_fail "$tool" "no matching release asset (pattern: $asset_pattern)"
    return
  fi
  local tmp; tmp=$(mktemp -d)
  if curl -sL "$url" | tar -xz -C "$tmp" 2>/dev/null; then
    local bin; bin=$(find "$tmp" -name "$cmd" -type f | head -1)
    if [[ -n "$bin" ]]; then
      chmod +x "$bin" 2>/dev/null || true
      mkdir -p "$install_dir" "$HOME/.local/bin" 2>/dev/null || true
      $SUDO mv "$bin" "$install_dir/$cmd" 2>/dev/null || mv "$bin" "$HOME/.local/bin/$cmd" 2>/dev/null
      if [[ "$already" == true && -n "$cur_ver" ]]; then
        log_ok "$tool ${cur_ver} -> ${latest_ver:-latest}"
      else
        log_ok "$tool ${latest_ver:-}"
      fi
      gh_binary_shadow_warn "$cmd" "$install_dir" "$ver_args"
    else
      log_fail "$tool" "binary '$cmd' not found in archive"
    fi
  else
    log_fail "$tool" "download/extract failed"
  fi
  rm -rf "$tmp"
}

# ── Header ───────────────────────────────────────────────────
echo -e "${BOLD}CTI Expert — Tool Installer${NC}"
echo "Platform:  $OS/$ARCH"
echo "Skill:     $SKILL_DIR"
echo "Venv:      $HOME/.claude/skills/.venv"
echo "Installer: uv-first (pip/pipx/venv fallback)"
[[ "$OPT_HEADLESS" == true ]] && echo "Mode:     +headless"
[[ "$OPT_GO" == true ]]       && echo "Mode:     +go"
[[ "$OPT_ALL" == true ]]      && echo "Mode:     +all (mermaid-cli diagrams)"

# ── uv bootstrap ────────────────────────────────────────────
section "uv (Astral package manager)"
ensure_uv
# uv installs CLI tools (maigret) into ~/.local/bin, and we drop the `asn` script there
# too. Put it on PATH for this run and persist it (uv's own shell hook) for new shells.
UV_TOOL_BIN="$HOME/.local/bin"
[[ ":$PATH:" != *":$UV_TOOL_BIN:"* ]] && export PATH="$UV_TOOL_BIN:$PATH"
if [[ -n "$UV_BIN" ]]; then
  "$UV_BIN" tool update-shell &>/dev/null 2>&1 && log_ok "~/.local/bin on PATH (uv tool update-shell — open a new shell)" || true
fi

# ── Venv check / create ─────────────────────────────────────
section "Python environment"
if [[ ! -f "$VENV_PYTHON" ]]; then
  if [[ -n "$UV_BIN" ]] && "$UV_BIN" venv "$VENV_DIR" &>/dev/null 2>&1; then
    log_ok "created venv via uv: $VENV_DIR"
  elif [[ -n "$PY3_BIN" ]] && "$PY3_BIN" -m venv "$VENV_DIR" &>/dev/null 2>&1; then
    log_ok "created venv: $VENV_DIR"
  elif [[ -z "$UV_BIN" && -z "$PY3_BIN" ]]; then
    echo -e "  ${RED}✘${NC} No working uv or python3 available to create a venv at $VENV_DIR"
    echo "  Install uv (https://astral.sh/uv) or Python 3, then re-run."
    exit 1
  else
    log_fail "venv" "uv venv and python3 -m venv both failed"
  fi
fi
if [[ ! -f "$VENV_PYTHON" ]]; then
  echo -e "  ${RED}✘${NC} Venv python missing at $VENV_PYTHON after creation attempt"; exit 1
fi
echo -e "  ${GREEN}✔${NC} $("$VENV_PYTHON" --version 2>&1)"
if [[ -n "$UV_PIP_BIN" ]]; then
  log_ok "uv manages package installs (pip bootstrap not needed)"
elif ensure_venv_pip && "$VENV_PYTHON" -m pip install --quiet --upgrade pip 2>/dev/null; then
  log_ok "pip upgraded (venv pip is the install path — uv pip unavailable)"
else
  log_fail "pip upgrade" "no usable uv pip, and venv pip could not be bootstrapped/upgraded"
fi

# ── System tools ─────────────────────────────────────────────
section "System tools"
apt_install whois whois
apt_install dnsutils dig bind                          # brew: dig ships in the `bind` formula
apt_install jq jq
apt_install libimage-exiftool-perl exiftool exiftool   # brew formula is `exiftool`
apt_install poppler-utils pdfinfo poppler              # brew formula is `poppler`
apt_install qpdf qpdf
if [[ "$OS" != "windows" ]]; then apt_install mat2 mat2; else log_skip "mat2 (requires GLib — Linux/macOS only)"; fi
apt_install pandoc pandoc
apt_install graphviz dot            # IntelGraph link graphs need the `dot` binary
# ── Media / vision toolchain ──────────────────────────────────
# ffmpeg + imagemagick preprocess A/V and image evidence; Node/npx runs the multix
# vision CLI (npx @mrgoonie/multix) and agent-browser. See techniques/media-vision-analysis.md.
apt_install ffmpeg ffmpeg
apt_install imagemagick convert            # `convert` on IM6, `magick` on IM7; package is imagemagick
apt_install tesseract-ocr tesseract tesseract   # keyless OCR fallback — apt pkg `tesseract-ocr`, brew formula `tesseract`
# OCR language packs — cti-expert is VN-first + heavy CN recon; bare tesseract is eng-only.
if [[ "$OS" == "linux" ]] && has apt-get; then
  $SUDO apt-get install -y tesseract-ocr-vie tesseract-ocr-chi-sim &>/dev/null 2>&1 && log_ok "tesseract langs: vie + chi_sim" || log_skip "tesseract-ocr-vie/chi-sim"
elif [[ "$OS" == "macos" ]] && has brew; then
  brew install tesseract-lang &>/dev/null 2>&1 && log_ok "tesseract-lang (all languages)" || log_skip "tesseract-lang"
fi
if has npx; then
  log_skip "node/npx (present)"
elif [[ "$OS" == "linux" ]] && has apt-get; then
  $SUDO apt-get install -y nodejs npm &>/dev/null 2>&1 && log_ok "nodejs + npm" || log_fail "nodejs" "install Node 20+ (NodeSource) — needed for npx multix + agent-browser"
elif [[ "$OS" == "macos" ]] && has brew; then
  brew install node &>/dev/null 2>&1 && log_ok "node (brew)" || log_fail "node" "brew install node"
else
  log_skip "node/npx (install Node 20+ manually for npx multix)"
fi
# rmbg-cli — optional AI background removal (needs npm)
if has rmbg; then
  log_skip "rmbg-cli (present)"
elif has npm; then
  npm install -g rmbg-cli &>/dev/null 2>&1 && log_ok "rmbg-cli (npm)" || log_skip "rmbg-cli (optional; npm install failed)"
else
  log_skip "rmbg-cli (needs npm; optional)"
fi
# Local Whisper — keyless offline A/V transcription fallback (no GEMINI_API_KEY). Optional: pulls CTranslate2 + a model on first run.
if has whisper-ctranslate2; then
  log_skip "whisper-ctranslate2 (present)"
elif [[ -n "$UV_BIN" ]] && "$UV_BIN" tool install whisper-ctranslate2 &>/dev/null 2>&1; then
  log_ok "whisper-ctranslate2 (local transcription fallback)"
elif [[ -n "$PIPX_BIN" ]] && "$PIPX_BIN" install whisper-ctranslate2 &>/dev/null 2>&1; then
  log_ok "whisper-ctranslate2 (local transcription fallback)"
else
  log_skip "whisper-ctranslate2 (optional local transcription fallback; install with: uv tool install whisper-ctranslate2)"
fi
# gh is NOT in Debian/Ubuntu default repos, so `apt install gh` fails there. Use the GitHub
# release binary on Linux (cross-distro), brew on macOS. Powers /github-osint's `gh api` recon.
if has gh; then
  log_skip "gh (present)"
elif [[ "$OS" == "macos" ]]; then
  apt_install gh gh                                 # -> brew install gh
elif [[ "$OS" == "linux" ]]; then
  GH_ARCH="amd64"; [[ "$ARCH" == "arm64" ]] && GH_ARCH="arm64"
  gh_binary_install "GitHub CLI" gh "cli/cli" "linux_${GH_ARCH}\\.tar\\.gz$" "$HOME/.local/bin"
else
  apt_install gh gh
fi
# zbar shared lib for pyzbar QR decoding (/webpivot --decode-qr)
if [[ "$OS" == "linux" ]] && has apt-get; then
  $SUDO apt-get install -y libzbar0 &>/dev/null 2>&1 && log_ok "libzbar0 (QR decode)" || log_skip "libzbar0"
elif [[ "$OS" == "macos" ]] && has brew; then
  brew install zbar &>/dev/null 2>&1 && log_ok "zbar (QR decode)" || log_skip "zbar"
fi
# libcairo2-dev needed by maigret on Linux
if [[ "$OS" == "linux" ]] && ! dpkg -l libcairo2-dev &>/dev/null 2>&1; then
  $SUDO apt-get install -y libcairo2-dev &>/dev/null 2>&1 && log_ok "libcairo2-dev (maigret dep)" || true
fi

# ── Report PDF engine: xelatex + fonts (ALWAYS) ───────────────
# IntelReport's PDF render (`intel.py report … --pdf` → render_report.py) shells out to
# pandoc + xelatex with the Noto family (VN-first + CN recon). This is a hard requirement for
# the PDF deliverable, so it installs UNCONDITIONALLY (not gated on --all). The DOCX/HTML
# reports do not need it, but a user asking for a PDF must never hit a missing-engine wall.
# texlive is large (hundreds of MB); that is the deliberate cost of shipping a working PDF path.
section "Report PDF engine (xelatex + Noto fonts)"
if [[ "$OS" == "linux" ]] && has apt-get; then
  # fontconfig provides `fc-list`, which render_report.py uses to DETECT an installed
  # Vietnamese-capable family. Without it, detection returns empty and the render silently
  # falls back to Latin Modern (no VN coverage) -> a tofu PDF with no warning. Install it first.
  $SUDO apt-get install -y fontconfig &>/dev/null 2>&1 && log_ok "fontconfig (fc-list — VN font detection)" || log_fail "fontconfig" "sudo apt install fontconfig"
  # texlive-latex-recommended carries the LaTeX packages pandoc's default PDF template loads
  # (fancyvrb, etc.); lmodern is the fallback body font; fonts-noto-core covers Vietnamese and
  # fonts-noto-cjk (best-effort) covers Chinese for the CN-recon reports.
  if $SUDO apt-get install -y texlive-xetex texlive-latex-recommended texlive-fonts-recommended fonts-noto-core lmodern &>/dev/null 2>&1; then
    log_ok "texlive-xetex + Noto (PDF report engine)"
  else
    log_fail "texlive-xetex" "sudo apt install texlive-xetex texlive-latex-recommended texlive-fonts-recommended fonts-noto-core lmodern"
  fi
  $SUDO apt-get install -y fonts-noto-cjk &>/dev/null 2>&1 && log_ok "fonts-noto-cjk (CN report glyphs)" || log_skip "fonts-noto-cjk (optional; CN glyphs in PDF)"
  fc-cache -f &>/dev/null 2>&1 || true   # register newly-installed fonts so fc-list sees them this run
elif [[ "$OS" == "macos" ]] && has brew; then
  if has xelatex; then
    log_skip "mactex/xelatex (present)"
  elif brew install --cask mactex-no-gui &>/dev/null 2>&1; then
    log_ok "mactex-no-gui (xelatex PDF engine)"
  else
    log_fail "mactex" "brew install --cask mactex-no-gui"
  fi
  # fontconfig gives macOS an `fc-list` (not present by default) so render_report can detect the
  # Noto/Georgia/Times VN family; without it the render silently falls back to Latin Modern (tofu).
  brew install fontconfig &>/dev/null 2>&1 && log_ok "fontconfig (fc-list — VN font detection)" || log_skip "fontconfig (brew install fontconfig)"
  brew install --cask font-noto-sans font-noto-serif font-noto-sans-cjk &>/dev/null 2>&1 && log_ok "Noto fonts (brew casks)" || log_skip "Noto font casks (optional)"
  fc-cache -f &>/dev/null 2>&1 || true
elif [[ "$OS" == "windows" ]]; then
  log_skip "xelatex (Windows: install.ps1 handles MiKTeX + Noto)"
else
  if has xelatex; then log_ok "xelatex (present)"; else log_fail "xelatex" "install TeX Live (texlive-xetex) + Noto fonts with your package manager"; fi
fi

# ── Python: core skill deps ───────────────────────────────────
section "Python: core skill requirements"
REQ="$SKILL_DIR/scripts/requirements.txt"
if [[ -f "$REQ" ]]; then
  if vpip --quiet --upgrade -r "$REQ" 2>/dev/null; then
    log_ok "requirements.txt (python-docx, matplotlib, networkx, numpy, whoisdomain, scrapling)"
  else
    log_fail "requirements.txt" "install (uv pip / pip) -r failed"
  fi
else
  log_fail "requirements.txt" "not found at $REQ"
fi

# ── Python: deep-layer pipeline deps (always) ─────────────────
# The root requirements.txt carries the harness (claude-agent-sdk, pydantic, rich) and the
# IntelGraph renderers (matplotlib, graphviz) plus light collector extras (openpyxl, pyzbar,
# pillow). These are pure-Python and small, so they install unconditionally — previously they
# lived only in the root manifest a user had to `uv pip install -r requirements.txt` by hand,
# leaving /harness, the typed MCP server, and IntelGraph's `dot` path silently unavailable.
section "Python: deep-layer pipeline (harness + IntelGraph)"
DEEP_REQ="$SKILL_DIR/requirements.txt"
if [[ -f "$DEEP_REQ" ]]; then
  if vpip --quiet --upgrade -r "$DEEP_REQ" 2>/dev/null; then
    log_ok "requirements.txt [deep layer] (claude-agent-sdk, pydantic, rich, graphviz, openpyxl, pyzbar, pillow)"
  else
    log_fail "requirements.txt [deep layer]" "install (uv pip / pip) -r failed"
  fi
else
  log_skip "requirements.txt [deep layer] (not found at $DEEP_REQ)"
fi

# ── Python: OSINT tools ───────────────────────────────────────
section "Python: OSINT tools"
# CLI-only tools go in via `uv tool`, not into the shared venv: the venv's bin/ is
# never added to PATH, so a venv-installed console script is invisible to the shell
# and to every `command -v` check the skill makes. Isolated envs also keep their
# dependency pins from colliding with each other inside the CTI venv.
pipx_install maigret maigret libcairo2-dev   # needs cairo; isolated env
pipx_install sherlock-project sherlock
blackbird_install                         # PyPI build needs setuptools/pkg_resources in the CTI venv
pipx_install holehe holehe
pipx_install h8mail h8mail
# theHarvester is NOT usable from PyPI: the only release there is an abandoned
# 0.0.1 placeholder that ships no theHarvester module and no CLI, and squats the
# top-level names `discovery` and `lib` in whatever environment it lands in.
# Upstream ships 4.x from git only.
pipx_install "git+https://github.com/laramies/theHarvester.git" theHarvester "" theHarvester
pipx_install waymore waymore
pip_install  cloudscraper cloudscraper   # library, imported not executed — belongs in the venv
pip_install  oletools oletools           # OLE/Office authorship + macro (olevba) — document metadata pivot
pipx_install xeuledoc xeuledoc
agentflow_install                       # no-deps avoids urllib3 conflict with msftrecon

# msftrecon — not on PyPI, install via git
MSFTRECON_ALREADY=false
"$VENV_PYTHON" -c "import msftrecon" &>/dev/null 2>&1 && MSFTRECON_ALREADY=true
if { { [[ -n "$UV_PIP_BIN" ]] && "$UV_PIP_BIN" pip install --python "$VENV_PYTHON" --quiet --reinstall "git+https://github.com/Arcanum-Sec/msftrecon.git"; } || { ensure_venv_pip && "$VENV_PYTHON" -m pip install --quiet --upgrade --force-reinstall "git+https://github.com/Arcanum-Sec/msftrecon.git"; }; } 2>/dev/null; then
  if [[ "$MSFTRECON_ALREADY" == true ]]; then
    log_ok "msftrecon updated"
  else
    log_ok "msftrecon (M365/Azure tenant recon)"
  fi
else
  log_fail "msftrecon" "install from git (uv pip / pip) failed"
fi

# agentflow 0.0.2 and msftrecon 0.1.0 require incompatible urllib3 ranges.
# Keep msftrecon's modern urllib3 dependency and let AgentFlow fall back to sequential enrichment if needed.
if "$VENV_PYTHON" -c "import agentflow, msftrecon" &>/dev/null 2>&1; then
  echo -e "  ${YELLOW}!${NC} agentflow and msftrecon have incompatible urllib3 requirements; keeping msftrecon-compatible urllib3 and using sequential enrichment fallback if AgentFlow fails"
  SKIPPED=$((SKIPPED+1))
fi

# sharetrace — not on PyPI, no setup.py; clone + install deps + register via .pth
SHARETRACE_REPO="https://github.com/7onez/sharetrace.git"
SHARETRACE_DIR="$HOME/.claude/skills/cti-expert/vendor/sharetrace"
SHARETRACE_ALREADY=false
"$VENV_PYTHON" -c "import sharetrace" &>/dev/null 2>&1 && SHARETRACE_ALREADY=true

mkdir -p "$(dirname "$SHARETRACE_DIR")"
if [[ -d "$SHARETRACE_DIR/.git" ]]; then
  CURRENT_ORIGIN="$(git -C "$SHARETRACE_DIR" remote get-url origin 2>/dev/null)"
  if [[ "$CURRENT_ORIGIN" == "$SHARETRACE_REPO" ]]; then
    git -C "$SHARETRACE_DIR" pull --quiet 2>/dev/null || true
  else
    echo "  sharetrace: origin mismatch ($CURRENT_ORIGIN) — re-cloning from 7onez fork"
    rm -rf "$SHARETRACE_DIR" 2>/dev/null
    git clone --quiet --depth 1 "$SHARETRACE_REPO" "$SHARETRACE_DIR" 2>/dev/null
  fi
else
  rm -rf "$SHARETRACE_DIR" 2>/dev/null
  git clone --quiet --depth 1 "$SHARETRACE_REPO" "$SHARETRACE_DIR" 2>/dev/null
fi
if [[ -d "$SHARETRACE_DIR/sharetrace" ]] &&    vpip --quiet --upgrade -r "$SHARETRACE_DIR/requirements.txt" 2>/dev/null; then
  SITE_PKG="$("$VENV_PYTHON" -c "import site; print(site.getsitepackages()[0])" 2>/dev/null)"
  if [[ -n "$SITE_PKG" ]]; then
    echo "$SHARETRACE_DIR" > "$SITE_PKG/sharetrace.pth"
    if [[ "$SHARETRACE_ALREADY" == true ]]; then
      log_ok "sharetrace updated"
    else
      log_ok "sharetrace (share link identity extraction, 11 platforms)"
    fi
  else
    log_fail "sharetrace" "could not resolve venv site-packages"
  fi
else
  log_fail "sharetrace" "clone/update or pip install -r requirements.txt failed"
fi

# ── Python: Scrapling headless (optional) ─────────────────────
section "Python: Scrapling headless browser"
SCRAPLING_HEADLESS_ALREADY=false
"$VENV_PYTHON" -c "from scrapling.fetchers import StealthyFetcher" &>/dev/null 2>&1 && SCRAPLING_HEADLESS_ALREADY=true
if [[ "$OPT_HEADLESS" == true ]]; then
  echo "  Installing/updating Scrapling[fetchers] + Chromium (~200MB)..."
  SCRAPLING_CLI="$VENV_BIN/scrapling"
  [[ "$OS" == "windows" ]] && SCRAPLING_CLI="$VENV_BIN/scrapling.exe"
  if vpip --quiet --upgrade "scrapling[fetchers]" 2>/dev/null &&      { [[ -x "$SCRAPLING_CLI" ]] && "$SCRAPLING_CLI" install &>/dev/null || scrapling install &>/dev/null; }; then
    if [[ "$SCRAPLING_HEADLESS_ALREADY" == true ]]; then
      log_ok "Scrapling headless updated"
    else
      log_ok "Scrapling headless (StealthyFetcher + DynamicFetcher)"
    fi
  else
    log_fail "Scrapling headless" "install failed — check network/disk"
  fi
else
  echo -e "  ${YELLOW}–${NC} Scrapling headless not requested (add --headless, downloads ~200MB)"
fi

# ── agent-browser (interactive browser collector) ─────────────
section "agent-browser (interactive browser, vercel-labs)"
if [[ "$OPT_HEADLESS" == true ]]; then
  ensure_agent_browser
else
  echo -e "  ${YELLOW}–${NC} agent-browser not requested (add --headless; installs CLI + Chrome)"
fi

# ── Playwright (render / screenshot / engage) ─────────────────
# Post-JS DOM render (/webpivot --render), full-page screenshot evidence, and Engage's
# synthetic-persona automation all use Playwright. Provisioned by DEFAULT now (like pandoc) so
# /cti renders live out of the box. The ~120MB Chromium download is best-effort and NEVER fails
# the install — a miss degrades to the urlscan-DOM recovery path. Set NO_PLAYWRIGHT=1 to opt out.
section "Playwright (render / screenshot / engage)"
if [[ "${NO_PLAYWRIGHT:-}" == "1" ]]; then
  echo -e "  ${YELLOW}–${NC} Playwright skipped (NO_PLAYWRIGHT=1)"
elif vpip --quiet --upgrade playwright 2>/dev/null; then
  PW_CLI="$VENV_BIN/playwright"; [[ "$OS" == "windows" ]] && PW_CLI="$VENV_BIN/playwright.exe"
  [[ "$OS" == "linux" ]] && { { [[ -x "$PW_CLI" ]] && $SUDO "$PW_CLI" install-deps chromium; } || $SUDO "$VENV_PYTHON" -m playwright install-deps chromium; } &>/dev/null 2>&1 || true
  if { [[ -x "$PW_CLI" ]] && "$PW_CLI" install chromium &>/dev/null; } || "$VENV_PYTHON" -m playwright install chromium &>/dev/null; then
    log_ok "playwright + chromium"
  else
    log_skip "playwright (package in; Chromium download deferred — finish: $VENV_PYTHON -m playwright install chromium)"
  fi
else
  log_skip "playwright (pip install deferred; core techniques degrade gracefully without it)"
fi

# ── Go tools (optional) ────────────────────────────────────────
section "Go tools"
if [[ "$OPT_GO" == true ]]; then
  if ! has go; then
    log_fail "Go tools" "Go not found — install from https://go.dev/dl/ then re-run with --go"
  else
    echo -e "  ${GREEN}✔${NC} $(go version)"
    GOBIN="${GOPATH:-$HOME/go}/bin"
    [[ ":$PATH:" != *":$GOBIN:"* ]] && echo -e "  ${YELLOW}!${NC} Add to shell: export PATH=\"\$PATH:$GOBIN\""

    # PhoneInfoga: go module path broken — use pre-built binary instead
    local_os="Linux"; [[ "$OS" == "macos" ]] && local_os="Darwin"; [[ "$OS" == "windows" ]] && local_os="Windows"
    gh_binary_install "PhoneInfoga" "phoneinfoga" \
      "sundowndev/phoneinfoga" \
      "${local_os}_${ARCH}\\.tar\\.gz" \
      "$GOBIN" "version"

    # TruffleHog: `go install` refuses this module ("go.mod contains replace
    # directives"), so take the release binary. Its assets use lowercase GOOS and
    # GOARCH (trufflehog_<ver>_linux_amd64.tar.gz), unlike PhoneInfoga's above.
    go_os="linux"; [[ "$OS" == "macos" ]] && go_os="darwin"; [[ "$OS" == "windows" ]] && go_os="windows"
    go_arch="amd64"; [[ "$ARCH" == "arm64" ]] && go_arch="arm64"
    gh_binary_install "TruffleHog" "trufflehog" \
      "trufflesecurity/trufflehog" \
      "_${go_os}_${go_arch}\\.tar\\.gz$" \
      "$GOBIN" "--version"

    go_install "Subfinder"  subfinder  "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    go_install "Amass"      amass      "github.com/owasp-amass/amass/v4/...@master"
    go_install "GAU"        gau        "github.com/lc/gau/v2/cmd/gau@latest"
    go_install "Gitleaks"   gitleaks   "github.com/zricethezav/gitleaks/v8@latest"
    go_install "httpx"      httpx      "github.com/projectdiscovery/httpx/cmd/httpx@latest"
  fi
else
  echo -e "  ${YELLOW}–${NC} Skipped (add --go to install Go tools, requires Go 1.21+)"
fi

# ── Report diagram engine: mermaid-cli (--all) ────────────────
# mmdc (IntelGraph flow/kill-chain diagrams) pulls a headless Chrome, so it rides with --all.
# The xelatex PDF engine is installed UNCONDITIONALLY above; only mmdc is gated here.
section "Report diagram engine (mermaid-cli)"
if [[ "$OPT_ALL" == true ]]; then
  if has npm; then
    npm install -g @mermaid-js/mermaid-cli &>/dev/null 2>&1 && log_ok "mermaid-cli (mmdc)" || log_fail "mermaid-cli" "npm install -g @mermaid-js/mermaid-cli failed"
  else
    log_skip "mermaid-cli (needs npm — install Node.js, then: npm i -g @mermaid-js/mermaid-cli)"
  fi
else
  echo -e "  ${YELLOW}–${NC} mermaid-cli not requested (add --all; pulls a headless Chrome. PDF/DOCX/HTML need neither)"
fi

# ── ASN lookup tool (nitefood/asn) ────────────────────────────
# asn is a self-contained bash script; install its runtime deps (whois/dig/jq are
# already installed above) then drop the script into ~/.local/bin. Linux/macOS/WSL.
section "ASN lookup tool (nitefood/asn)"
ASN_RAW="https://raw.githubusercontent.com/nitefood/asn/master/asn"
ASN_DIR="$HOME/.claude/skills/cti-expert/vendor/asn"
ASN_BIN="$HOME/.local/bin"
if [[ "$OS" == "linux" ]] && has apt-get; then
  # mtr-tiny/bind9-dnsutils on newer Debian; mtr/dnsutils on older — try both, tolerate misses
  $SUDO apt-get install -y curl whois jq mtr-tiny aha ipcalc grepcidr nmap bind9-dnsutils &>/dev/null 2>&1 \
    || $SUDO apt-get install -y curl whois jq mtr aha ipcalc grepcidr nmap dnsutils &>/dev/null 2>&1 || true
elif [[ "$OS" == "macos" ]] && has brew; then
  brew install curl whois jq mtr aha ipcalc grepcidr nmap &>/dev/null 2>&1 || true
fi
if has curl || has wget; then
  mkdir -p "$ASN_DIR" "$ASN_BIN"
  if { has curl && curl -fsSL "$ASN_RAW" -o "$ASN_DIR/asn"; } || { has wget && wget -qO "$ASN_DIR/asn" "$ASN_RAW"; }; then
    chmod +x "$ASN_DIR/asn"
    ln -sf "$ASN_DIR/asn" "$ASN_BIN/asn" 2>/dev/null || cp -f "$ASN_DIR/asn" "$ASN_BIN/asn"
    log_ok "asn (nitefood/asn -> $ASN_BIN/asn)"
  else
    log_fail "asn" "download failed from $ASN_RAW"
  fi
else
  log_fail "asn" "need curl or wget to download the asn script"
fi

# ── Summary ───────────────────────────────────────────────────
echo ""
echo -e "${BOLD}─────────────────────────────────────────${NC}"
echo -e "${GREEN}✔ Installed: $INSTALLED${NC}  ${YELLOW}– Skipped: $SKIPPED${NC}  ${RED}✘ Failed: $FAILED${NC}"
[[ $FAILED -gt 0 ]] && echo -e "${RED}Some tools failed. Check errors above.${NC}"
echo ""
