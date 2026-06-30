<#
.SYNOPSIS
    Build the GreyIQ Windows portable .exe (and optionally the NSIS installer)
    locally - the same pipeline the Release workflow runs, for when GitHub Actions
    is unavailable.

.DESCRIPTION
    Mirrors .github/workflows/release.yml (Windows job):
      1. Install Python build deps (CPU-only torch + requirements + PyInstaller)
         into an isolated build venv.
      2. Freeze the backend with PyInstaller -> dist/greyiq-backend/greyiq-backend.exe
      3. Smoke-test that the frozen backend answers /api/health.
      4. npm ci  (Electron + electron-builder).
      5. Bundle the Ollama runtime into ./ollama (zero-setup local model).
      6. electron-builder --win portable  ->  release/GreyIQ-<version>-portable.exe

    Heavy build: it downloads CPU torch (~200 MB) and the Ollama runtime (~0.6-1 GB),
    and the finished portable .exe is ~2.5-3 GB. Allow plenty of disk + time.

.PARAMETER Installer
    Also build the NSIS installer (release/GreyIQ-Setup-<version>.exe).

.PARAMETER SkipOllama
    Don't download/bundle the Ollama runtime. Faster, but the portable build will
    NOT ship the out-of-the-box local model (an empty ./ollama is used so
    electron-builder's extraResources copy still succeeds).

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
& $Py -m pip install "torch>=2.2,<2.8" --index-url https://download.pytorch.org/whl/cpu
Assert-LastExit "CPU torch install"
& $Py -m pip install -r requirements.txt; Assert-LastExit "requirements.txt install"
& $Py -m pip install -r build/requirements-build.txt; Assert-LastExit "build requirements install"

# --- Freeze the backend ---
Write-Step "Freezing the backend with PyInstaller"
& $Py -m PyInstaller --noconfirm --clean build/greyiq-backend.spec
Assert-LastExit "PyInstaller freeze"

$BackendExe = Join-Path $RepoRoot "dist\greyiq-backend\greyiq-backend.exe"
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
}

# --- Node dependencies ---
Write-Step "Installing npm dependencies"
& npm ci
if ($LASTEXITCODE -ne 0) {
    Write-Warning "npm ci failed; falling back to npm install"
    & npm install; Assert-LastExit "npm install"
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
$artifacts = Get-ChildItem (Join-Path $RepoRoot "release") -Filter *.exe -ErrorAction SilentlyContinue
if ($artifacts) {
    foreach ($a in $artifacts) {
        Write-Host ("    {0}  ({1:N0} MB)" -f $a.Name, ($a.Length / 1MB)) -ForegroundColor Green
    }
    $portable = $artifacts | Where-Object { $_.Name -like "*portable*" } | Select-Object -First 1
    if ($portable) { Write-Host ""; Write-Host "Portable exe: $($portable.FullName)" -ForegroundColor Green }
} else {
    Write-Warning "No .exe found in release\ - check the electron-builder output above."
}
