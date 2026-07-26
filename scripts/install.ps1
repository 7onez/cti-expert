<#
CTI Expert - all-in-one PowerShell tool installer
Usage: powershell -ExecutionPolicy Bypass -File .\scripts\install.ps1 [-Headless] [-Go] [-All]
  -Headless  Auto-install Scrapling headless browser (downloads ~200MB Chromium)
  -Go        Install Go-based tools (requires Go 1.21+)
  -All       Install everything including headless + Go tools

Package engine: uv-first. Bootstraps Astral's uv (winget / official installer / pip),
creates the venv with `uv venv`, installs libs with `uv pip` and CLI tools with `uv tool`.
Falls back to py/python venv + pip/pipx when uv cannot be installed.
Supported platforms: Windows PowerShell 5.1+ and PowerShell 7+.
#>

[CmdletBinding()]
param(
    [switch]$Headless,
    [switch]$Go,
    [switch]$All
)

Set-StrictMode -Version Latest
# Intentionally NOT 'Stop'. In Windows PowerShell 5.1, $ErrorActionPreference='Stop'
# turns ANY native-command stderr write into a terminating NativeCommandError -- even
# when redirected (*>$null / 2>&1 | Out-Null all still throw) -- which aborts the script
# on tools that legitimately use stderr (pip/uv/git/go progress, python import probes).
# PowerShell 7 dropped that behavior. This script gates every native call on
# $LASTEXITCODE and throws explicitly, so 'Continue' is both sufficient and correct;
# cmdlets whose silent failure would mislog as success pass -ErrorAction Stop locally.
$ErrorActionPreference = "Continue"

if ($All) {
    $Headless = $true
    $Go = $true
}

$SkillDir = (Resolve-Path (Join-Path $PSScriptRoot ".."))
$SkillRoot = Join-Path $env:USERPROFILE ".claude\skills"
$VenvDir = Join-Path $SkillRoot ".venv"
$VenvScripts = Join-Path $VenvDir "Scripts"
$VenvPython = Join-Path $VenvScripts "python.exe"
$VenvPip = Join-Path $VenvScripts "pip.exe"
$VendorDir = Join-Path $SkillRoot "cti-expert\vendor"

$script:Installed = 0
$script:Skipped = 0
$script:Failed = 0

function Write-Section {
    param([string]$Name)
    Write-Host ""
    Write-Host "> $Name" -ForegroundColor Cyan
}

function Log-Ok {
    param([string]$Message)
    Write-Host "  OK  $Message" -ForegroundColor Green
    $script:Installed++
}

function Log-Skip {
    param([string]$Message)
    Write-Host "  --  $Message (no update applied)" -ForegroundColor Yellow
    $script:Skipped++
}

function Log-Fail {
    param([string]$Message, [string]$Reason)
    Write-Host "  XX  $Message - $Reason" -ForegroundColor Red
    $script:Failed++
}

function Test-Command {
    param([string]$Name)
    return $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)
}

# Detect OS architecture robustly. RuntimeInformation.OSArchitecture is absent on
# some Windows PowerShell 5.1 / .NET Framework configs, where accessing it under
# Set-StrictMode throws PropertyNotFoundStrict; fall back to PROCESSOR_ARCHITECTURE.
function Get-OSArchitecture {
    try {
        $osArch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
        if ($osArch) { return "$osArch" }
    }
    catch { }
    $procArch = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
    switch ("$procArch".ToUpperInvariant()) {
        "AMD64" { return "X64" }
        "ARM64" { return "Arm64" }
        "X86"   { return "X86" }
        default { if ($procArch) { return "$procArch" } else { return "Unknown" } }
    }
}

function Test-PythonImport {
    param([string]$ImportName)
    if (!(Test-Path $VenvPython)) { return $false }
    & $VenvPython -c "import $ImportName" *> $null
    return $LASTEXITCODE -eq 0
}

function Invoke-Step {
    param(
        [string]$Name,
        [scriptblock]$Action
    )

    try {
        & $Action
        return $true
    }
    catch {
        Log-Fail $Name $_.Exception.Message
        return $false
    }
}

# Install Python packages into the skill venv. uv-first (a uv-created venv has no
# pip, so we target it via `uv pip --python`); fall back to the venv's own pip.
# Leaves $LASTEXITCODE set for the caller to check.
function Invoke-VenvPip {
    param([Parameter(ValueFromRemainingArguments = $true)] [string[]]$PipArgs)
    if (Test-Command "uv") {
        & uv pip install --python $VenvPython @PipArgs
    }
    else {
        & $VenvPython -m pip install @PipArgs
    }
}

# Bootstrap uv itself — the one dependency the uv-first path needs.
function Install-Uv {
    if (Test-Command "uv") { Log-Ok "uv present: $(uv --version)"; return }
    if (Test-Command "winget") {
        winget install --id astral-sh.uv --exact --accept-package-agreements --accept-source-agreements 2>&1 | Out-Host
    }
    if (!(Test-Command "uv")) {
        try { Invoke-RestMethod https://astral.sh/uv/install.ps1 | Invoke-Expression } catch {}
        $uvBin = Join-Path $env:USERPROFILE ".local\bin"
        if ((Test-Path (Join-Path $uvBin "uv.exe")) -and ($env:PATH -notlike "*$uvBin*")) {
            $env:PATH = "$uvBin;$env:PATH"
        }
    }
    if ((!(Test-Command "uv")) -and (Get-Command "py" -ErrorAction SilentlyContinue)) {
        py -m pip install --user uv *> $null
    }
    if (Test-Command "uv") { Log-Ok "uv installed" }
    else { Log-Skip "uv (install manually from https://astral.sh/uv; using pip/venv fallback)" }
}

# Interactive browser collector (vercel-labs/agent-browser) — primary browser tool.
function Install-AgentBrowser {
    if (Test-Command "agent-browser") { Log-Ok "agent-browser (present)" }
    elseif (Test-Command "npm")   { Invoke-Step "agent-browser" { npm install -g agent-browser | Out-Host; if ($LASTEXITCODE -ne 0) { throw "npm install -g agent-browser failed" }; Log-Ok "agent-browser (npm)" } | Out-Null }
    elseif (Test-Command "cargo") { Invoke-Step "agent-browser" { cargo install agent-browser | Out-Host; if ($LASTEXITCODE -ne 0) { throw "cargo install agent-browser failed" }; Log-Ok "agent-browser (cargo)" } | Out-Null }
    elseif (Test-Command "scoop") { Invoke-Step "agent-browser" { scoop install agent-browser | Out-Host; if (!(Test-Command "agent-browser")) { throw "scoop install agent-browser failed" }; Log-Ok "agent-browser (scoop)" } | Out-Null }
    else { Write-Host "  --  agent-browser needs npm, cargo, or scoop (see techniques/agent-browser.md)" -ForegroundColor Yellow; $script:Skipped++ }
    if (Test-Command "agent-browser") {
        Invoke-Step "agent-browser Chrome" { agent-browser install 2>&1 | Out-Null; Log-Ok "agent-browser Chrome runtime" } | Out-Null
    }
}

function Install-WingetPackage {
    param(
        [string]$Name,
        [string]$Command,
        [string]$WingetId
    )

    if (!(Test-Command "winget")) {
        Log-Fail $Name "winget not found; install manually or add Git Bash/WSL for the Bash installer"
        return
    }

    $commandAvailableBefore = Test-Command $Command
    Invoke-Step $Name {
        if ($commandAvailableBefore) {
            $upgradeOutput = winget upgrade --id $WingetId --exact --accept-package-agreements --accept-source-agreements 2>&1 | Out-String
            $upgradeExitCode = $LASTEXITCODE
            if ($upgradeExitCode -eq 0) {
                if ($upgradeOutput -notmatch "No available upgrade found|No newer package versions are available") {
                    $upgradeOutput | Write-Host
                }
                Log-Ok "$Name updated"
            }
            elseif ($upgradeOutput -match "No installed package found matching input criteria") {
                Write-Host "  --  $Name command exists but is not registered under winget id '$WingetId'; treating it as externally managed" -ForegroundColor Yellow
                $script:Skipped++
            }
            elseif ($upgradeOutput -match "No available upgrade found|No newer package versions are available") {
                Write-Host "  --  $Name is already current" -ForegroundColor Yellow
                $script:Skipped++
            }
            else {
                $upgradeOutput | Write-Host
                Write-Host "  --  $Name checked for updates; no winget update applied" -ForegroundColor Yellow
                $script:Skipped++
            }
        }
        else {
            winget install --id $WingetId --exact --accept-package-agreements --accept-source-agreements | Out-Host
            if (Test-Command $Command) {
                Log-Ok $Name
            }
            else {
                Write-Host "  !!  $Name is installed or current in winget, but '$Command' is not on this PowerShell PATH; reopen PowerShell or add the package bin directory to PATH" -ForegroundColor Yellow
                $script:Skipped++
            }
        }
    } | Out-Null
}

function Install-PipPackage {
    param(
        [string]$Package,
        [string]$ImportName = ""
    )

    $checkName = if ($ImportName) { $ImportName } else { ($Package -replace "-", "_") -replace "\[.*$", "" }
    $alreadyInstalled = Test-PythonImport $checkName

    Invoke-Step $Package {
        Invoke-VenvPip --quiet --upgrade $Package
        if ($LASTEXITCODE -ne 0) { throw "install (uv pip / pip) --upgrade failed" }
        if ($alreadyInstalled) { Log-Ok "$Package updated" } else { Log-Ok $Package }
    } | Out-Null
}

function Install-Blackbird {
    $alreadyInstalled = Test-PythonImport "blackbird"
    $blackbirdRepo = "https://github.com/p1ngul1n0/blackbird.git"
    $blackbirdDir = Join-Path $VendorDir "blackbird"
    Invoke-Step "blackbird" {
        New-Item -ItemType Directory -Force -Path $VendorDir | Out-Null
        if (Test-Path (Join-Path $blackbirdDir ".git")) {
            git -C $blackbirdDir pull --quiet
            if ($LASTEXITCODE -ne 0) { throw "git pull failed" }
        }
        else {
            if (Test-Path $blackbirdDir) { Remove-Item -Recurse -Force $blackbirdDir }
            git clone --quiet --depth 1 $blackbirdRepo $blackbirdDir
            if ($LASTEXITCODE -ne 0) { throw "git clone failed" }
        }
        # Relax version pins that block Python 3.14 binary wheels (mirrors install.sh).
        $blackbirdReq = Join-Path $blackbirdDir "requirements.txt"
        if (Test-Path $blackbirdReq) {
            $relaxed = (Get-Content $blackbirdReq) `
                -replace 'aiohttp==.*', 'aiohttp>=3.13' `
                -replace 'yarl==.*', 'yarl>=1.17' `
                -replace 'multidict==.*', 'multidict>=6.0' `
                -replace 'aiohappyeyeballs==.*', 'aiohappyeyeballs>=2.3' `
                -replace 'aiosignal==.*', 'aiosignal>=1.3' `
                -replace 'frozenlist==.*', 'frozenlist>=1.4' `
                -replace 'propcache==.*', 'propcache>=0.2'
            Set-Content -Path $blackbirdReq -Value $relaxed -Encoding ASCII
        }
        Invoke-VenvPip --quiet --upgrade -r $blackbirdReq
        if ($LASTEXITCODE -ne 0) { throw "install -r blackbird requirements failed" }
        $sitePackages = & $VenvPython -c "import site; print(site.getsitepackages()[0])"
        Set-Content -Path (Join-Path $sitePackages "blackbird.pth") -Value $blackbirdDir -Encoding ASCII -ErrorAction Stop
        if ($alreadyInstalled) { Log-Ok "blackbird updated from source" } else { Log-Ok "blackbird (source checkout)" }
    } | Out-Null
}

function Install-AgentFlow {
    $alreadyInstalled = Test-PythonImport "agentflow"
    Invoke-Step "agentflow" {
        Invoke-VenvPip --quiet --upgrade --no-deps agentflow
        if ($LASTEXITCODE -ne 0) { throw "install --upgrade --no-deps agentflow failed" }
        if ($alreadyInstalled) { Log-Ok "agentflow updated" } else { Log-Ok "agentflow" }
    } | Out-Null
}

function Install-PipxPackage {
    param(
        [string]$Package,
        [string]$Command,
        # $Package may be any spec uv/pipx accepts, including a `git+https://...`
        # URL, so $Label supplies a readable name for the log line.
        [string]$Label = $Package
    )

    # uv-first: `uv tool` is the pipx replacement.
    if (Test-Command "uv") {
        $already = Test-Command $Command
        Invoke-Step $Label {
            $ok = $false
            if ($already) { uv tool upgrade $Package *> $null; if ($LASTEXITCODE -eq 0) { $ok = $true } }
            if (-not $ok) {
                # --force overwrites a stale shim left by a prior pip/pipx install
                # (uv refuses otherwise: "Executables already exist ... use --force").
                uv tool install --force $Package *> $null
                if ($LASTEXITCODE -ne 0) { throw "uv tool install failed" }
            }
            if ($already) { Log-Ok "$Label updated (uv tool)" } else { Log-Ok "$Label (uv tool)" }
        } | Out-Null
        return
    }

    if (!(Test-Command "pipx")) {
        Invoke-Step "pipx" {
            & $VenvPython -m pip install --quiet --upgrade pipx
            if ($LASTEXITCODE -ne 0) { throw "pipx install failed" }
            Log-Ok "pipx"
        } | Out-Null
    }

    $pipxList = pipx list --short 2>$null
    $packageInstalled = $LASTEXITCODE -eq 0 -and ($pipxList | Where-Object { $_ -match "^$([regex]::Escape($Package))(?:\s|$)" })
    Invoke-Step $Label {
        if ($packageInstalled) {
            pipx upgrade $Package | Out-Host
            if ($LASTEXITCODE -eq 0) {
                Log-Ok "$Label updated"
            }
            else {
                Write-Host "  --  $Label checked for updates; no pipx update applied" -ForegroundColor Yellow
                $script:Skipped++
            }
        }
        else {
            if (Test-Command $Command) {
                Write-Host "  !!  Found stale '$Command' shim without pipx venv; reinstalling $Label" -ForegroundColor Yellow
            }
            pipx install --force $Package | Out-Host
            if ($LASTEXITCODE -ne 0) { throw "pipx install failed" }
            Log-Ok $Label
        }
    } | Out-Null
}

function Install-GoTool {
    param(
        [string]$Name,
        [string]$Command,
        [string]$Module
    )

    $alreadyInstalled = Test-Command $Command
    Invoke-Step $Name {
        go install $Module
        if ($LASTEXITCODE -ne 0) { throw "go install failed" }
        if ($alreadyInstalled) { Log-Ok "$Name updated" } else { Log-Ok $Name }
    } | Out-Null
}

# An older copy of the same tool earlier on PATH silently wins over the one just
# installed, so the upgrade has no visible effect. Say so rather than reporting a
# success the shell will not honour.
function Write-ShadowWarning {
    param([string]$Command, [string]$InstallDir)

    $active = (Get-Command $Command -ErrorAction SilentlyContinue).Source
    if (!$active) { return }
    $expected = Join-Path $InstallDir $Command
    if ($active -ieq $expected -or $active -ieq "$expected.exe") { return }
    Write-Host "  !!  PATH resolves $Command to $active - shadows $expected" -ForegroundColor Yellow
}

function Install-GitHubReleaseBinary {
    param(
        [string]$Name,
        [string]$Command,
        [string]$Repo,
        [string]$AssetPattern,
        [string]$InstallDir,
        # Tools differ: TruffleHog answers `--version`, PhoneInfoga `version`.
        [string]$VersionArgs = "--version"
    )

    $alreadyInstalled = Test-Command $Command
    Invoke-Step $Name {
        New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
        $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -Headers @{ "User-Agent" = "cti-expert-installer" }

        # Compare installed vs latest before downloading tens of MB. Skipping purely
        # because the command exists would pin the box to whatever stale copy is on
        # PATH and make the tool un-upgradable.
        $latestVersion = ([regex]::Match([string]$release.tag_name, '\d+\.\d+(\.\d+)?')).Value
        $currentVersion = ""
        if ($alreadyInstalled) {
            $currentRaw = (& $Command $VersionArgs 2>&1 | Select-Object -First 1)
            $currentVersion = ([regex]::Match([string]$currentRaw, '\d+\.\d+(\.\d+)?')).Value
            if ($currentVersion -and $latestVersion -and $currentVersion -eq $latestVersion) {
                Log-Ok "$Name $currentVersion (latest)"
                Write-ShadowWarning $Command $InstallDir
                return
            }
        }

        $asset = $release.assets | Where-Object { $_.name -match $AssetPattern } | Select-Object -First 1
        if (!$asset) { throw "no matching release asset for pattern: $AssetPattern" }

        $tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("cti-expert-" + [System.Guid]::NewGuid().ToString("N"))
        New-Item -ItemType Directory -Force -Path $tempDir | Out-Null
        $archivePath = Join-Path $tempDir $asset.name

        try {
            Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $archivePath -Headers @{ "User-Agent" = "cti-expert-installer" }
            if ($archivePath -match "\.zip$") {
                Expand-Archive -Path $archivePath -DestinationPath $tempDir -Force
            }
            else {
                tar -xf $archivePath -C $tempDir
                if ($LASTEXITCODE -ne 0) { throw "archive extract failed" }
            }

            $binaryName = if ($Command.EndsWith(".exe")) { $Command } else { "$Command.exe" }
            $binary = Get-ChildItem -Path $tempDir -Recurse -File | Where-Object { $_.Name -ieq $binaryName -or $_.Name -ieq $Command } | Select-Object -First 1
            if (!$binary) { throw "binary '$binaryName' not found in archive" }

            $target = Join-Path $InstallDir $binaryName
            Copy-Item -Path $binary.FullName -Destination $target -Force -ErrorAction Stop
            if ($env:PATH -notlike "*$InstallDir*") { $env:PATH = "$env:PATH;$InstallDir" }
            if ($alreadyInstalled -and $currentVersion) { Log-Ok "$Name $currentVersion -> $latestVersion" }
            elseif ($alreadyInstalled) { Log-Ok "$Name updated" }
            else { Log-Ok "$Name $latestVersion".Trim() }
            Write-ShadowWarning $Command $InstallDir
        }
        finally {
            if (Test-Path $tempDir) { Remove-Item -Recurse -Force $tempDir }
        }
    } | Out-Null
}

Write-Host "CTI Expert - Tool Installer" -ForegroundColor White
Write-Host "Platform:  Windows / $(Get-OSArchitecture)"
Write-Host "Skill:     $SkillDir"
Write-Host "Venv:      $VenvDir"
Write-Host "Installer: uv-first (pip/pipx/venv fallback)"
if ($Headless) { Write-Host "Mode:      +headless" }
if ($Go) { Write-Host "Mode:      +go" }

Write-Section "uv (Astral package manager)"
Install-Uv
# uv installs CLI tools (maigret) into ~\.local\bin, and we drop the native `asn`
# wrapper there too. Put it on PATH for THIS session (immediate) and persist it to the
# user PATH (future shells) so the tools are found without a manual step.
$UvToolBin = Join-Path $env:USERPROFILE ".local\bin"
New-Item -ItemType Directory -Force -Path $UvToolBin | Out-Null
if ($env:PATH -notlike "*$UvToolBin*") { $env:PATH = "$UvToolBin;$env:PATH" }
$userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
if ("$userPath" -notlike "*$UvToolBin*") {
    $newUserPath = if ([string]::IsNullOrEmpty($userPath)) { $UvToolBin } else { "$userPath;$UvToolBin" }
    try {
        [Environment]::SetEnvironmentVariable("PATH", $newUserPath, "User")
        Log-Ok "added $UvToolBin to your user PATH (new shells pick it up; reopen this one)"
    }
    catch {
        Write-Host "  !!  Could not persist PATH automatically ($($_.Exception.Message)). Run: uv tool update-shell" -ForegroundColor Yellow
    }
}
else {
    Log-Skip "$UvToolBin already on user PATH"
}

Write-Section "Python environment"
if (!(Test-Path $VenvPython)) {
    Invoke-Step "Python virtual environment" {
        if (Test-Command "uv") {
            uv venv $VenvDir
        }
        elseif (Get-Command "py" -ErrorAction SilentlyContinue) {
            py -3 -m venv $VenvDir
        }
        elseif (Test-Command "python") {
            python -m venv $VenvDir
        }
        else {
            throw "Neither uv nor Python 3 found; install uv (https://astral.sh/uv) or Python"
        }
        if (!(Test-Path $VenvPython)) { throw "venv creation failed" }
        Log-Ok "created $VenvDir"
    } | Out-Null
}
else {
    Log-Skip "Python virtual environment"
}
& $VenvPython --version
if (Test-Command "uv") {
    Log-Ok "uv manages package installs (pip bootstrap not needed)"
}
else {
    Invoke-Step "pip upgrade" {
        & $VenvPython -m pip install --quiet --upgrade pip
        if ($LASTEXITCODE -ne 0) { throw "pip upgrade failed" }
        Log-Ok "pip upgraded"
    } | Out-Null
}

Write-Section "System tools"
Install-WingetPackage "Git" "git" "Git.Git"
Install-WingetPackage "GitHub CLI" "gh" "GitHub.cli"
Install-WingetPackage "jq" "jq" "jqlang.jq"
Install-WingetPackage "ExifTool" "exiftool" "OliverBetz.ExifTool"
Install-WingetPackage "Pandoc" "pandoc" "JohnMacFarlane.Pandoc"
Install-WingetPackage "Poppler" "pdfinfo" "oschwartz10612.Poppler"
Install-WingetPackage "QPDF" "qpdf" "QPDF.QPDF"
Install-WingetPackage "whois (Sysinternals)" "whois" "Microsoft.Sysinternals.Whois"
Install-WingetPackage "dig (ISC BIND)" "dig" "ISC.Bind"

Write-Section "Python: core skill requirements"
$requirements = Join-Path $SkillDir "scripts\requirements.txt"
if (Test-Path $requirements) {
    Invoke-Step "requirements.txt" {
        Invoke-VenvPip --quiet --upgrade -r $requirements
        if ($LASTEXITCODE -ne 0) { throw "install (uv pip / pip) --upgrade -r failed" }
        Log-Ok "requirements.txt (python-docx, matplotlib, networkx, numpy, whoisdomain, scrapling)"
    } | Out-Null
}
else {
    Log-Fail "requirements.txt" "not found at $requirements"
}

Write-Section "Python: OSINT tools"
# CLI-only tools go in via `uv tool`, not into the shared venv: the venv's Scripts
# dir is never added to PATH, so a venv-installed console script is invisible to
# the shell and to every Test-Command check the skill makes. Isolated envs also
# keep their dependency pins from colliding with each other inside the CTI venv.
Install-PipxPackage "maigret" "maigret"
Install-PipxPackage "sherlock-project" "sherlock"
Install-Blackbird
Install-PipxPackage "holehe" "holehe"
Install-PipxPackage "h8mail" "h8mail"
# theHarvester is NOT usable from PyPI: the only release there is an abandoned
# 0.0.1 placeholder that ships no theHarvester module and no CLI, and squats the
# top-level names `discovery` and `lib` in whatever environment it lands in.
# Upstream ships 4.x from git only.
Install-PipxPackage "git+https://github.com/laramies/theHarvester.git" "theHarvester" "theHarvester"
Install-PipxPackage "waymore" "waymore"
Install-PipPackage "cloudscraper" "cloudscraper"   # library, imported not executed
Install-PipxPackage "xeuledoc" "xeuledoc"
Install-AgentFlow

$msftreconAlreadyInstalled = Test-PythonImport "msftrecon"
Invoke-Step "msftrecon" {
    if (Test-Command "uv") {
        uv pip install --python $VenvPython --quiet --reinstall "git+https://github.com/Arcanum-Sec/msftrecon.git"
    }
    else {
        & $VenvPython -m pip install --quiet --upgrade --force-reinstall "git+https://github.com/Arcanum-Sec/msftrecon.git"
    }
    if ($LASTEXITCODE -ne 0) { throw "install from git (uv pip / pip) failed" }
    if ($msftreconAlreadyInstalled) { Log-Ok "msftrecon updated" } else { Log-Ok "msftrecon (M365/Azure tenant recon)" }
} | Out-Null

# agentflow 0.0.2 and msftrecon 0.1.0 require incompatible urllib3 ranges.
# Keep msftrecon's modern urllib3 dependency and let AgentFlow fall back to sequential enrichment if needed.
if ((Test-PythonImport "agentflow") -and (Test-PythonImport "msftrecon")) {
    Write-Host "  !!  agentflow and msftrecon have incompatible urllib3 requirements; keeping msftrecon-compatible urllib3 and using sequential enrichment fallback if AgentFlow fails" -ForegroundColor Yellow
    $script:Skipped++
}

Write-Section "sharetrace"
$sharetraceRepo = "https://github.com/7onez/sharetrace.git"
$sharetraceDir = Join-Path $VendorDir "sharetrace"
$sharetraceOk = Test-PythonImport "sharetrace"
Invoke-Step "sharetrace" {
    New-Item -ItemType Directory -Force -Path $VendorDir | Out-Null
    if (Test-Path (Join-Path $sharetraceDir ".git")) {
        $currentOrigin = (git -C $sharetraceDir remote get-url origin 2>$null)
        if ($currentOrigin -eq $sharetraceRepo) {
            git -C $sharetraceDir pull --quiet
            if ($LASTEXITCODE -ne 0) { throw "git pull failed" }
        }
        else {
            Write-Host "  --  sharetrace: origin mismatch ($currentOrigin); re-cloning from 7onez fork" -ForegroundColor Yellow
            Remove-Item -Recurse -Force $sharetraceDir
            git clone --quiet --depth 1 $sharetraceRepo $sharetraceDir
            if ($LASTEXITCODE -ne 0) { throw "git clone failed" }
        }
    }
    else {
        if (Test-Path $sharetraceDir) { Remove-Item -Recurse -Force $sharetraceDir }
        git clone --quiet --depth 1 $sharetraceRepo $sharetraceDir
        if ($LASTEXITCODE -ne 0) { throw "git clone failed" }
    }
    Invoke-VenvPip --quiet --upgrade -r (Join-Path $sharetraceDir "requirements.txt")
    if ($LASTEXITCODE -ne 0) { throw "install --upgrade -r sharetrace requirements failed" }
    $sitePackages = & $VenvPython -c "import site; print(site.getsitepackages()[0])"
    Set-Content -Path (Join-Path $sitePackages "sharetrace.pth") -Value $sharetraceDir -Encoding ASCII -ErrorAction Stop
    if ($sharetraceOk) { Log-Ok "sharetrace updated" } else { Log-Ok "sharetrace (share link identity extraction, 11 platforms)" }
} | Out-Null

Write-Section "Python: Scrapling headless browser"
$scraplingHeadlessAlreadyInstalled = Test-PythonImport "scrapling.fetchers"
if ($Headless) {
    Invoke-Step "Scrapling headless" {
        Invoke-VenvPip --quiet --upgrade "scrapling[fetchers]"
        if ($LASTEXITCODE -ne 0) { throw "scrapling[fetchers] install failed" }
        $scraplingCli = Join-Path $VenvScripts "scrapling.exe"
        if (Test-Path $scraplingCli) {
            & $scraplingCli install
        }
        elseif (Test-Command "scrapling") {
            scrapling install
        }
        else {
            throw "scrapling CLI not found after pip install"
        }
        if ($LASTEXITCODE -ne 0) { throw "browser install failed" }
        if ($scraplingHeadlessAlreadyInstalled) { Log-Ok "Scrapling headless updated" } else { Log-Ok "Scrapling headless (StealthyFetcher + DynamicFetcher)" }
    } | Out-Null
}
else {
    Write-Host "  --  Scrapling headless not requested (add -Headless, downloads ~200MB)" -ForegroundColor Yellow
}

Write-Section "agent-browser (interactive browser, vercel-labs)"
if ($Headless) {
    Install-AgentBrowser
}
else {
    Write-Host "  --  agent-browser not requested (add -Headless; installs CLI + Chrome)" -ForegroundColor Yellow
}

Write-Section "Go tools"
if ($Go) {
    if (!(Test-Command "go")) {
        Log-Fail "Go tools" "Go not found; install from https://go.dev/dl/ then re-run with -Go"
    }
    else {
        go version
        $goPath = (go env GOPATH).Trim()
        if (!$goPath) { $goPath = Join-Path $env:USERPROFILE "go" }
        $goBin = Join-Path $goPath "bin"
        if ($env:PATH -notlike "*$goBin*") { $env:PATH = "$env:PATH;$goBin" }

        $arch = Get-OSArchitecture
        $phoneInfogaArch = if ($arch -eq "Arm64") { "arm64" } else { "x86_64|amd64" }
        Install-GitHubReleaseBinary "PhoneInfoga" "phoneinfoga" "sundowndev/phoneinfoga" "Windows.*($phoneInfogaArch).*(zip|tar\.gz)$" $goBin "version"
        Install-GoTool "Subfinder" "subfinder" "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        Install-GoTool "Amass" "amass" "github.com/owasp-amass/amass/v4/...@master"
        Install-GoTool "GAU" "gau" "github.com/lc/gau/v2/cmd/gau@latest"
        Install-GoTool "Gitleaks" "gitleaks" "github.com/zricethezav/gitleaks/v8@latest"
        Install-GoTool "httpx" "httpx" "github.com/projectdiscovery/httpx/cmd/httpx@latest"

        # TruffleHog is Go (v3) — the PyPI `trufflehog` is the abandoned v2 Python
        # tool and does not understand the v3 syntax this skill documents
        # (`trufflehog github --repo=... --only-verified`). `go install` also refuses
        # this module ("go.mod contains replace directives"), so take the release
        # binary. Assets use lowercase GOARCH: trufflehog_<ver>_windows_amd64.tar.gz.
        $truffleArch = if ($arch -eq "Arm64") { "arm64" } else { "amd64" }
        Install-GitHubReleaseBinary "TruffleHog" "trufflehog" "trufflesecurity/trufflehog" "_windows_$truffleArch\.tar\.gz$" $goBin
    }
}
else {
    Write-Host "  --  Skipped (add -Go to install Go tools, requires Go 1.21+)" -ForegroundColor Yellow
}

Write-Section "ASN lookup (native asn command)"
$asnSrc = Join-Path $SkillDir "scripts\asn.ps1"
$asnWrapper = Join-Path $UvToolBin "asn.cmd"
Invoke-Step "asn" {
    if (!(Test-Path $asnSrc)) { throw "asn.ps1 not found at $asnSrc" }
    Set-Content -Path $asnWrapper -Value "@echo off`r`npowershell -NoProfile -ExecutionPolicy Bypass -File `"$asnSrc`" %*" -Encoding ASCII -ErrorAction Stop
    Log-Ok "asn (native keyless IP/ASN/domain lookup; e.g. 'asn 8.8.8.8', 'asn AS15169')"
} | Out-Null
Write-Host "  Full nitefood/asn (BGP graphs, traceroute, RPKI) needs a Unix shell -- run scripts/install.sh in WSL." -ForegroundColor DarkGray

Write-Host ""
Write-Host "-----------------------------------------"
Write-Host "OK Installed: $script:Installed  -- Skipped: $script:Skipped  XX Failed: $script:Failed"
if ($script:Failed -gt 0) {
    Write-Host "Some tools failed. Check the error lines above; failures may be from PATH refresh, package registration, network, or upstream module changes." -ForegroundColor Red
    exit 1
}
