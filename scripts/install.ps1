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
$ErrorActionPreference = "Stop"

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
        Invoke-VenvPip --quiet --upgrade -r (Join-Path $blackbirdDir "requirements.txt")
        if ($LASTEXITCODE -ne 0) { throw "install -r blackbird requirements failed" }
        $sitePackages = & $VenvPython -c "import site; print(site.getsitepackages()[0])"
        Set-Content -Path (Join-Path $sitePackages "blackbird.pth") -Value $blackbirdDir -Encoding ASCII
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
        [string]$Command
    )

    # uv-first: `uv tool` is the pipx replacement.
    if (Test-Command "uv") {
        $already = Test-Command $Command
        Invoke-Step $Package {
            $ok = $false
            if ($already) { uv tool upgrade $Package *> $null; if ($LASTEXITCODE -eq 0) { $ok = $true } }
            if (-not $ok) {
                uv tool install $Package *> $null
                if ($LASTEXITCODE -ne 0) { throw "uv tool install failed" }
            }
            if ($already) { Log-Ok "$Package updated (uv tool)" } else { Log-Ok "$Package (uv tool)" }
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
    Invoke-Step $Package {
        if ($packageInstalled) {
            pipx upgrade $Package | Out-Host
            if ($LASTEXITCODE -eq 0) {
                Log-Ok "$Package updated"
            }
            else {
                Write-Host "  --  $Package checked for updates; no pipx update applied" -ForegroundColor Yellow
                $script:Skipped++
            }
        }
        else {
            if (Test-Command $Command) {
                Write-Host "  !!  Found stale '$Command' shim without pipx venv; reinstalling $Package" -ForegroundColor Yellow
            }
            pipx install --force $Package | Out-Host
            if ($LASTEXITCODE -ne 0) { throw "pipx install failed" }
            Log-Ok $Package
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

function Install-GitHubReleaseBinary {
    param(
        [string]$Name,
        [string]$Command,
        [string]$Repo,
        [string]$AssetPattern,
        [string]$InstallDir
    )

    $alreadyInstalled = Test-Command $Command
    Invoke-Step $Name {
        New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
        $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -Headers @{ "User-Agent" = "cti-expert-installer" }
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
            Copy-Item -Path $binary.FullName -Destination $target -Force
            if ($env:PATH -notlike "*$InstallDir*") { $env:PATH = "$env:PATH;$InstallDir" }
            if ($alreadyInstalled) { Log-Ok "$Name updated" } else { Log-Ok $Name }
        }
        finally {
            if (Test-Path $tempDir) { Remove-Item -Recurse -Force $tempDir }
        }
    } | Out-Null
}

Write-Host "CTI Expert - Tool Installer" -ForegroundColor White
Write-Host "Platform:  Windows / $([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture)"
Write-Host "Skill:     $SkillDir"
Write-Host "Venv:      $VenvDir"
Write-Host "Installer: uv-first (pip/pipx/venv fallback)"
if ($Headless) { Write-Host "Mode:      +headless" }
if ($Go) { Write-Host "Mode:      +go" }

Write-Section "uv (Astral package manager)"
Install-Uv

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
Install-PipxPackage "maigret" "maigret"
Install-PipPackage "sherlock-project" "sherlock"
Install-Blackbird
Install-PipPackage "holehe" "holehe"
Install-PipPackage "h8mail" "h8mail"
Install-PipPackage "theHarvester" "theHarvester"
Install-PipPackage "trufflehog" "trufflehog"
Install-PipPackage "waymore" "waymore"
Install-PipPackage "cloudscraper" "cloudscraper"
Install-PipPackage "xeuledoc" "xeuledoc"
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
        git -C $sharetraceDir pull --quiet
        if ($LASTEXITCODE -ne 0) { throw "git pull failed" }
    }
    else {
        if (Test-Path $sharetraceDir) { Remove-Item -Recurse -Force $sharetraceDir }
        git clone --quiet --depth 1 $sharetraceRepo $sharetraceDir
        if ($LASTEXITCODE -ne 0) { throw "git clone failed" }
    }
    Invoke-VenvPip --quiet --upgrade -r (Join-Path $sharetraceDir "requirements.txt")
    if ($LASTEXITCODE -ne 0) { throw "install --upgrade -r sharetrace requirements failed" }
    $sitePackages = & $VenvPython -c "import site; print(site.getsitepackages()[0])"
    Set-Content -Path (Join-Path $sitePackages "sharetrace.pth") -Value $sharetraceDir -Encoding ASCII
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

        $arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
        $phoneInfogaArch = if ($arch -eq "Arm64") { "arm64" } else { "x86_64|amd64" }
        Install-GitHubReleaseBinary "PhoneInfoga" "phoneinfoga" "sundowndev/phoneinfoga" "Windows.*($phoneInfogaArch).*(zip|tar\.gz)$" $goBin
        Install-GoTool "Subfinder" "subfinder" "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        Install-GoTool "Amass" "amass" "github.com/owasp-amass/amass/v4/...@master"
        Install-GoTool "GAU" "gau" "github.com/lc/gau/v2/cmd/gau@latest"
        Install-GoTool "Gitleaks" "gitleaks" "github.com/zricethezav/gitleaks/v8@latest"
        Install-GoTool "httpx" "httpx" "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    }
}
else {
    Write-Host "  --  Skipped (add -Go to install Go tools, requires Go 1.21+)" -ForegroundColor Yellow
}

Write-Section "Manual-install tools"
Write-Host "  ASN:        use Git Bash/WSL: bash <(curl -sL https://raw.githubusercontent.com/nitefood/asn/master/asn)"
Write-Host "  whois/dig:  install BIND tools or use WSL for native Unix networking commands"

Write-Host ""
Write-Host "-----------------------------------------"
Write-Host "OK Installed: $script:Installed  -- Skipped: $script:Skipped  XX Failed: $script:Failed"
if ($script:Failed -gt 0) {
    Write-Host "Some tools failed. Check the error lines above; failures may be from PATH refresh, package registration, network, or upstream module changes." -ForegroundColor Red
    exit 1
}
