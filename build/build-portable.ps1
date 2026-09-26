<#
.SYNOPSIS
    Build the GreyIQ Windows portable .exe (and optionally the NSIS installer)
    locally - the same pipeline the Release workflow runs, for when GitHub Actions
    is unavailable.

.DESCRIPTION
    Mirrors .github/workflows/release.yml (Windows job), with the steps reordered so
    the fallible network work happens BEFORE the expensive local work:
      1. npm ci, then fetch the Electron binary explicitly (see below).
      2. Install Python build deps (CPU-only torch + requirements + PyInstaller)
         into an isolated build venv, and Playwright's Chromium.
      3. Freeze the backend with PyInstaller -> dist/greyiq-backend/greyiq-backend.exe
      4. Smoke-test that the frozen backend answers /api/health and that the dash
         cockpit's modules survived the bundle.
      5. electron-builder --win portable  ->  release/GreyIQ-<version>-portable.exe

    Step 1 is first on purpose. electron 44.x ships NO install script, so `npm ci`
    exits 0 with the 150 MB Electron binary absent and the download is deferred to
    whoever needs it first - electron-builder, at the very last step. electron-builder
    fetches it through got with a 600_000 ms TOTAL request timeout (not an idle
    timeout), so on a link slower than ~252 KB/s the download CANNOT finish and the
    build dies after all the freezing is done. Pulling Electron up front means a slow
    or broken link costs seconds instead of a discarded twenty-minute build, and
    `node node_modules/electron/install.js` has no such deadline.

    Heavy build: it downloads CPU torch (~200 MB, into the build venv), Chromium
    (~170 MB) and Electron (~150 MB); the finished portable .exe is ~345 MB
    (torch-free backend + bundled Chromium; Ollama is downloaded on demand, not
    bundled). Allow plenty of disk + time.

.PARAMETER Installer
    Also build the NSIS installer (release/GreyIQ-Setup-<version>.exe).

.PARAMETER SkipOllama
    Accepted and ignored. Ollama has not been bundled since it was ~1.4 GB / 86% of
    the portable; the app downloads it on demand at first local-model use. Retained
    only so existing invocations keep working.

.PARAMETER SkipSmokeTest
    Skip starting the frozen backend to check /api/health.

.PARAMETER UseSystemPython
    Install build deps into the current Python instead of a dedicated .venv-build
    (faster if you already have the requirements installed; less reproducible).

.PARAMETER Python
    Python launcher/executable to use (default "python").

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File build/build-portable.ps1

.EXAMPLE
    # Portable + installer, reusing an already-downloaded Ollama runtime:
    powershell -NoProfile -ExecutionPolicy Bypass -File build/build-portable.ps1 -Installer
#>
#requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$Installer,
    [switch]$SkipOllama,
    [switch]$SkipSmokeTest,
    [switch]$UseSystemPython,
    [string]$Python = "python"
)

$ErrorActionPreference = "Stop"
# Invoke-WebRequest is dramatically faster in Windows PowerShell 5.1 without the
# live progress bar (it otherwise repaints per chunk on a ~1 GB download).
$ProgressPreference = "SilentlyContinue"

function Assert-LastExit([string]$What) {
    if ($LASTEXITCODE -ne 0) { throw "$What failed (exit code $LASTEXITCODE)." }
}

function Write-Step([string]$Message) {
    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function New-OutputDir([string]$Path) {
    # Create an output directory, parents and all, and say nothing if it is already there.
    # A clean checkout has none of dist\, release\ or the PyInstaller work dir - they are all
    # gitignored build products - so every one of them has to be created by whoever gets there
    # first. PyInstaller and electron-builder each make their own, but only after minutes of
    # work, and the artifact scan at the end of this script reads release\ whether or not
    # electron-builder got far enough to create it. Making them up front costs nothing and
    # removes the class of "the build worked, the report says it did not" failure.
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
    return $Path
}

# --- Locate the repo root (this script lives in <root>/build) ---
$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot
Write-Host "GreyIQ portable build" -ForegroundColor Green
Write-Host "Repo root: $RepoRoot"

# --- Prerequisites ---
Write-Step "Checking prerequisites"
foreach ($tool in @("node", "npm", $Python)) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        throw "Required tool '$tool' was not found on PATH."
    }
}
& node --version; Assert-LastExit "node --version"

# --- Node dependencies + the Electron binary ---
# Deliberately FIRST, ahead of the ~20 minutes of pip / PyInstaller / smoke-test work below.
# electron 44.x ships no install script (node_modules\electron\package.json has no "scripts" key;
# the package-lock entry has no "hasInstallScript"), so `npm ci` exits 0 with the 150 MB binary
# absent and defers the fetch to whoever needs it first - electron-builder, at the very last step,
# through got with a 600 s TOTAL request deadline that a slow link cannot meet. Fetching here means
# a failed download costs seconds instead of a discarded freeze.
Write-Step "Installing npm dependencies"
& npm ci
if ($LASTEXITCODE -ne 0) {
    Write-Warning "npm ci failed; falling back to npm install"
    & npm install; Assert-LastExit "npm install"
}

Write-Step "Fetching the Electron binary (npm ci does not - electron 44.x has no install script)"
# install.js verifies against the checksums.json shipped in the package, is a no-op once
# node_modules\electron\dist is populated, and exits non-zero on failure. Its real value is warming
# the shared @electron/get cache (%LOCALAPPDATA%\electron\Cache), which is what electron-builder
# reads - it never runs the local binary, it extracts its own copy from that zip.
& node "node_modules\electron\install.js"; Assert-LastExit "Electron binary download"
foreach ($p in @("node_modules\electron\dist", "node_modules\electron\path.txt")) {
    $full = Join-Path $RepoRoot $p
    if (-not (Test-Path -LiteralPath $full)) {
        throw "Electron is not installed: $full is missing. 'npm ci' does not install it (electron 44.x has no install script). Run 'node node_modules/electron/install.js' and re-run this script."
    }
}
Write-Host "    Electron binary present: $(Join-Path $RepoRoot 'node_modules\electron\dist')"

# --- Python environment ---
if ($UseSystemPython) {
    $Py = $Python
    Write-Step "Using system Python: $Py"
} else {
    $VenvDir = Join-Path $RepoRoot ".venv-build"
    $Py = Join-Path $VenvDir "Scripts\python.exe"
    if (-not (Test-Path $Py)) {
        Write-Step "Creating build virtualenv: $VenvDir"
        & $Python -m venv $VenvDir; Assert-LastExit "venv creation"
    } else {
        Write-Step "Reusing build virtualenv: $VenvDir"
    }
}

Write-Step "Installing Python build dependencies (CPU torch + requirements + PyInstaller)"
& $Py -m pip install --upgrade pip; Assert-LastExit "pip upgrade"
# CPU-only torch keeps the bundle under GitHub's 2 GiB per-asset cap; the app only
# uses torch for the small TinyGPT model (brain GPU accel comes via Ollama).
& $Py -m pip install "torch>=2.13,<3.0" --index-url https://download.pytorch.org/whl/cpu
Assert-LastExit "CPU torch install"
& $Py -m pip install -r requirements.txt; Assert-LastExit "requirements.txt install"
& $Py -m pip install -r build/requirements-build.txt; Assert-LastExit "build requirements install"

# Fetch the Chromium build that greyiq-backend.spec bundles under the app (proof
# screenshots + live scan). Use THIS venv's playwright so the fetched revision matches
# what collect_all bundles; installs into the shared per-user ms-playwright cache.
Write-Step "Installing Playwright Chromium (bundled for proof screenshots)"
& $Py -m playwright install chromium; Assert-LastExit "playwright install chromium"

# --- Output directories ---
# Named explicitly and passed to PyInstaller rather than left to its cwd-relative defaults, so the
# directories this script creates are provably the ones the freeze writes into.
Write-Step "Preparing output directories"
$DistDir    = New-OutputDir (Join-Path $RepoRoot "dist")
$ReleaseDir = New-OutputDir (Join-Path $RepoRoot "release")
$WorkDir    = New-OutputDir (Join-Path $RepoRoot "build\pyinstaller")
Write-Host "    dist:    $DistDir"
Write-Host "    release: $ReleaseDir"
Write-Host "    work:    $WorkDir"

# --- Freeze the backend ---
Write-Step "Freezing the backend with PyInstaller"
& $Py -m PyInstaller --noconfirm --clean --distpath $DistDir --workpath $WorkDir build/greyiq-backend.spec
Assert-LastExit "PyInstaller freeze"

$BackendExe = Join-Path $DistDir "greyiq-backend\greyiq-backend.exe"
if (-not (Test-Path $BackendExe)) {
    throw "Frozen backend not found at $BackendExe"
}
Write-Host "    Frozen backend: $BackendExe"

# --- Smoke-test the frozen backend ---
if (-not $SkipSmokeTest) {
    Write-Step "Smoke-testing the frozen backend (/api/health)"
    # Bind to a FREE loopback port chosen by the OS, so a leftover smoke process or the
    # running app can never make this bind-fail and get mislabeled as a 'broken bundle'.
    $portFinder = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $portFinder.Start()
    $smokePort = ([System.Net.IPEndPoint]$portFinder.LocalEndpoint).Port
    $portFinder.Stop()
    $env:GREYIQ_HOST = "127.0.0.1"
    $env:GREYIQ_PORT = "$smokePort"
    $env:GREYIQ_RUNTIME_DIR = Join-Path $env:TEMP "greyiq-build-smoke"
    $proc = Start-Process -FilePath $BackendExe -PassThru -NoNewWindow
    $ok = $false
    for ($i = 0; $i -lt 60; $i++) {
        Start-Sleep -Seconds 3
        if ($proc.HasExited) { throw "Frozen backend exited early (exit code $($proc.ExitCode)) - the bundle is broken." }
        try {
            $h = Invoke-WebRequest "http://127.0.0.1:$smokePort/api/health" -UseBasicParsing -TimeoutSec 3
            if ($h.StatusCode -eq 200) { $ok = $true; break }
        } catch { }
    }
    if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
    if (-not $ok) { throw "Frozen backend did not answer /api/health within 180s." }
    Write-Host "    Backend answered /api/health on port $smokePort."

    # The dash cockpit imports gn_dash / gn_tui / gn_sysmon at FUNCTION level, which PyInstaller's
    # static analysis cannot see; greyiq-backend.spec force-includes them by name. Nothing else in
    # this pipeline would notice if that line were dropped - the verb would parse fine and then die
    # on the import in front of an operator, which is exactly how 'gn wardrive' shipped broken in
    # v2.6.0. --self-test performs the real imports and prints what it picked, so this checks the
    # OUTPUT, not the exit code: it exits 2 here and is right to, because this shell is not a
    # terminal and no frame was drawn.
    Write-Step "Smoke-testing the dash cockpit in the frozen bundle"
    $dashOut = (& $BackendExe dash --self-test) -join "`n"
    if ($dashOut -notmatch "gn dash self-test") {
        throw "The frozen backend could not run 'dash --self-test' - gn_dash/gn_tui/gn_sysmon are missing from the bundle. Output: $dashOut"
    }
    Write-Host "    Dash modules present in the frozen bundle."
}

# --- Ollama is no longer bundled (downloaded on demand at first local-model use;
# see electron/main.cjs ensureBaseOllama). Nothing to do here. The -SkipOllama flag
# is retained for backward compatibility and is a no-op.
Write-Step "Ollama: on-demand (not bundled) - keeping the portable lean"

# --- Build the portable (+ optional installer) ---
$targets = @("portable")
if ($Installer) { $targets += "nsis" }
Write-Step ("Building with electron-builder: --win {0}" -f ($targets -join " "))
$ebArgs = @("electron-builder", "--win") + $targets + @("--publish", "never")
& npx @ebArgs
Assert-LastExit "electron-builder"

# --- Report artifacts ---
$version = (Get-Content (Join-Path $RepoRoot "package.json") -Raw | ConvertFrom-Json).version
Write-Step "Build complete - GreyIQ v$version"
$artifacts = Get-ChildItem $ReleaseDir -Filter *.exe -ErrorAction SilentlyContinue
if ($artifacts) {
    foreach ($a in $artifacts) {
        Write-Host ("    {0}  ({1:N0} MB)" -f $a.Name, ($a.Length / 1MB)) -ForegroundColor Green
    }
    # Name the portable THIS run produced (match the current version), not whatever sorts
    # first in a release\ folder that may hold older builds.
    $portable = $artifacts | Where-Object { $_.Name -like "*$version-portable*" } | Select-Object -First 1
    if (-not $portable) { $portable = $artifacts | Where-Object { $_.Name -like "*portable*" } | Select-Object -First 1 }
    if ($portable) { Write-Host ""; Write-Host "Portable exe: $($portable.FullName)" -ForegroundColor Green }
} else {
    Write-Warning "No .exe found in release\ - check the electron-builder output above."
}
