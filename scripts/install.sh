#!/usr/bin/env bash
# CTI Expert — all-in-one tool installer
# Usage: bash scripts/install.sh [--headless] [--go] [--all]
#   --headless  Auto-install Scrapling headless browser (downloads ~200MB Chromium)
#   --go        Install Go-based tools (requires Go 1.21+)
#   --all       Install everything including headless + Go tools
#
# Package engine: uv-first (Astral's uv handles the venv, `uv pip`, and `uv tool`);
# bootstraps uv automatically, and falls back to python3 -m venv + pip/pipx if uv
# cannot be installed. Supported platforms: Linux (apt), macOS (brew), Windows (Git Bash / WSL).

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
for arg in "$@"; do
  case $arg in
    --headless) OPT_HEADLESS=true ;;
    --go)       OPT_GO=true ;;
    --all)      OPT_HEADLESS=true; OPT_GO=true ;;
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

# Root/sudo handling — VPSes & containers frequently run as root with no `sudo`
# binary installed, so never hard-assume `sudo` exists.
if [[ "$(id -u 2>/dev/null)" == "0" ]]; then
  SUDO=""
elif has sudo; then
  SUDO="sudo"
else
  SUDO=""   # non-root without sudo: system-package installs may fail, but uv/pip --user still work
fi

# Install Python packages into the skill venv. uv-first (a uv-created venv has no
# pip, so we must target it with `uv pip --python`); fall back to the venv's pip.
vpip() { if has uv; then uv pip install --python "$VENV_PYTHON" "$@"; else "$VENV_PYTHON" -m pip install "$@"; fi; }

# Bootstrap uv itself — the one dependency the uv-first path needs.
ensure_uv() {
  has uv && { log_ok "uv $(uv --version 2>/dev/null | awk '{print $2}') (present)"; return 0; }
  # On a fresh Linux box (esp. minimal VPS/containers) install the prerequisites the
  # uv installer + venv fallback need, before anything else.
  if [[ "$OS" == "linux" ]] && has apt-get; then
    $SUDO apt-get update -y &>/dev/null 2>&1 || true
    $SUDO apt-get install -y curl ca-certificates git python3 python3-venv &>/dev/null 2>&1 || true
  fi
  if [[ "$OS" == "macos" ]] && has brew; then brew install uv &>/dev/null 2>&1 || true; fi
  if ! has uv && has curl; then
    curl -LsSf https://astral.sh/uv/install.sh | sh &>/dev/null 2>&1 || true
    export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"
  fi
  if ! has uv && has wget; then
    wget -qO- https://astral.sh/uv/install.sh | sh &>/dev/null 2>&1 || true
    export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"
  fi
  if ! has uv && has pip3; then
    pip3 install --user uv &>/dev/null 2>&1 || true
    export PATH="$HOME/.local/bin:$PATH"
  fi
  if has uv; then
    log_ok "uv $(uv --version 2>/dev/null | awk '{print $2}') installed"
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
  local pkg="$1" cmd="${2:-$1}"
  if has "$cmd"; then
    if [[ "$OS" == "linux" ]]; then
      if $SUDO apt-get install --only-upgrade -y "$pkg" &>/dev/null 2>&1; then
        log_ok "$pkg updated"
      else
        log_skip "$pkg"
      fi
    elif [[ "$OS" == "macos" ]]; then
      if has brew && brew upgrade "$pkg" &>/dev/null 2>&1; then
        log_ok "$pkg updated"
      else
        log_skip "$pkg"
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
    if has brew && brew install "$pkg" &>/dev/null 2>&1; then
      log_ok "$pkg"
    else
      log_fail "$pkg" "try: brew install $pkg"
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
  if [[ -f "$blackbird_dir/requirements.txt" ]] && { { has uv && uv pip install --python "$VENV_PYTHON" --quiet --upgrade -r "$blackbird_dir/requirements.txt"; } || "$VENV_PYTHON" -m pip install --quiet --upgrade --prefer-binary -r "$blackbird_dir/requirements.txt"; } 2>/dev/null; then
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

# Install an isolated CLI tool. uv-first (`uv tool`, the pipx replacement); fall back to pipx.
pipx_install() {
  local tool="$1" cmd="${2:-$1}" pre_pkg="${3:-}"
  local already=false
  has "$cmd" && already=true
  if [[ -n "$pre_pkg" ]] && [[ "$OS" == "linux" ]]; then
    $SUDO apt-get install -y "$pre_pkg" &>/dev/null 2>&1 || true
  fi
  if has uv; then
    if [[ "$already" == true ]] && uv tool upgrade "$tool" &>/dev/null 2>&1; then
      log_ok "$tool updated (uv tool)"; return
    elif uv tool install "$tool" &>/dev/null 2>&1; then
      [[ "$already" == true ]] && log_ok "$tool updated (uv tool)" || log_ok "$tool (uv tool)"
      return
    fi
    # uv tool failed (e.g. package exposes no CLI entry point) — fall through to pipx
  fi
  if has pipx; then
    if [[ "$already" == true ]]; then
      if pipx upgrade "$tool" &>/dev/null 2>&1; then
        log_ok "$tool updated"
      else
        log_skip "$tool ($cmd)"
      fi
    elif pipx install "$tool" &>/dev/null 2>&1; then
      if [[ "$already" == true ]]; then
        log_ok "$tool updated"
      else
        log_ok "$tool"
      fi
    else
      log_fail "$tool" "pipx install $tool failed"
    fi
  else
    log_fail "$tool" "no uv or pipx — install uv (https://astral.sh/uv) or run: pip3 install pipx"
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

# Download pre-built binary from GitHub releases
gh_binary_install() {
  local tool="$1" cmd="$2" repo="$3" asset_pattern="$4" install_dir="${5:-/usr/local/bin}"
  local already=false
  has "$cmd" && already=true
  if $already; then
    log_ok "$tool (already installed)"
    return
  fi
  if ! has gh; then
    log_fail "$tool" "gh CLI not found — install from https://cli.github.com"
    return
  fi
  local url
  url=$(gh api "repos/$repo/releases/latest" \
    --jq ".assets[] | select(.name | test(\"$asset_pattern\")) | .browser_download_url" 2>/dev/null | head -1)
  if [[ -z "$url" ]]; then
    log_fail "$tool" "no matching release asset (pattern: $asset_pattern)"
    return
  fi
  local tmp; tmp=$(mktemp -d)
  if curl -sL "$url" | tar -xz -C "$tmp" 2>/dev/null; then
    local bin; bin=$(find "$tmp" -name "$cmd" -type f | head -1)
    if [[ -n "$bin" ]]; then
      $SUDO mv "$bin" "$install_dir/$cmd" 2>/dev/null || mv "$bin" "$HOME/.local/bin/$cmd" 2>/dev/null
      log_ok "$tool"
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

# ── uv bootstrap ────────────────────────────────────────────
section "uv (Astral package manager)"
ensure_uv

# ── Venv check / create ─────────────────────────────────────
section "Python environment"
if [[ ! -f "$VENV_PYTHON" ]]; then
  if has uv; then
    if uv venv "$VENV_DIR" &>/dev/null 2>&1; then log_ok "created venv via uv: $VENV_DIR"; else log_fail "venv" "uv venv failed"; fi
  elif has python3; then
    if python3 -m venv "$VENV_DIR" &>/dev/null 2>&1; then log_ok "created venv: $VENV_DIR"; else log_fail "venv" "python3 -m venv failed"; fi
  else
    echo -e "  ${RED}✘${NC} No uv or python3 available to create a venv at $VENV_DIR"
    echo "  Install uv (https://astral.sh/uv) or Python 3, then re-run."
    exit 1
  fi
fi
if [[ ! -f "$VENV_PYTHON" ]]; then
  echo -e "  ${RED}✘${NC} Venv python missing at $VENV_PYTHON after creation attempt"; exit 1
fi
echo -e "  ${GREEN}✔${NC} $("$VENV_PYTHON" --version 2>&1)"
if has uv; then
  log_ok "uv manages package installs (pip bootstrap not needed)"
elif "$VENV_PYTHON" -m pip install --quiet --upgrade pip 2>/dev/null; then
  log_ok "pip upgraded"
else
  log_fail "pip upgrade" "python -m pip install --upgrade pip failed"
fi

# ── System tools ─────────────────────────────────────────────
section "System tools"
apt_install whois whois
apt_install dnsutils dig
apt_install jq jq
apt_install libimage-exiftool-perl exiftool
apt_install poppler-utils pdfinfo
apt_install qpdf qpdf
if [[ "$OS" != "windows" ]]; then apt_install mat2 mat2; else log_skip "mat2 (requires GLib — Linux/macOS only)"; fi
apt_install pandoc pandoc
# libcairo2-dev needed by maigret on Linux
if [[ "$OS" == "linux" ]] && ! dpkg -l libcairo2-dev &>/dev/null 2>&1; then
  $SUDO apt-get install -y libcairo2-dev &>/dev/null 2>&1 && log_ok "libcairo2-dev (maigret dep)" || true
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

# ── Python: OSINT tools ───────────────────────────────────────
section "Python: OSINT tools"
pipx_install maigret maigret libcairo2-dev   # needs cairo; pipx isolates its env
pip_install  sherlock-project sherlock
blackbird_install                         # PyPI build needs setuptools/pkg_resources in the CTI venv
pip_install  holehe holehe
pip_install  h8mail h8mail
pip_install  theHarvester theHarvester
pip_install  trufflehog trufflehog
pip_install  waymore waymore
pip_install  cloudscraper cloudscraper
pip_install  xeuledoc xeuledoc
agentflow_install                       # no-deps avoids urllib3 conflict with msftrecon

# msftrecon — not on PyPI, install via git
MSFTRECON_ALREADY=false
"$VENV_PYTHON" -c "import msftrecon" &>/dev/null 2>&1 && MSFTRECON_ALREADY=true
if { { has uv && uv pip install --python "$VENV_PYTHON" --quiet --reinstall "git+https://github.com/Arcanum-Sec/msftrecon.git"; } || "$VENV_PYTHON" -m pip install --quiet --upgrade --force-reinstall "git+https://github.com/Arcanum-Sec/msftrecon.git"; } 2>/dev/null; then
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
      "$GOBIN"

    go_install "Subfinder"  subfinder  "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    go_install "Amass"      amass      "github.com/owasp-amass/amass/v4/...@master"
    go_install "GAU"        gau        "github.com/lc/gau/v2/cmd/gau@latest"
    go_install "Gitleaks"   gitleaks   "github.com/zricethezav/gitleaks/v8@latest"
    go_install "httpx"      httpx      "github.com/projectdiscovery/httpx/cmd/httpx@latest"
  fi
else
  echo -e "  ${YELLOW}–${NC} Skipped (add --go to install Go tools, requires Go 1.21+)"
fi

# ── Manual-only tools ─────────────────────────────────────────
section "Manual-install tools (not automated)"
echo "  ASN:        bash <(curl -sL https://raw.githubusercontent.com/nitefood/asn/master/asn)"

# ── Summary ───────────────────────────────────────────────────
echo ""
echo -e "${BOLD}─────────────────────────────────────────${NC}"
echo -e "${GREEN}✔ Installed: $INSTALLED${NC}  ${YELLOW}– Skipped: $SKIPPED${NC}  ${RED}✘ Failed: $FAILED${NC}"
[[ $FAILED -gt 0 ]] && echo -e "${RED}Some tools failed. Check errors above.${NC}"
echo ""
