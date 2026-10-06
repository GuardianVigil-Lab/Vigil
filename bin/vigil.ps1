<#
.SYNOPSIS
    Vigil: Native Windows PowerShell Runner & Security CLI
.DESCRIPTION
    Executes Vigil container batteries on Windows. Supports both standard Docker
    Desktop and Hyper-V/WSL2 host mounts.
.PARAMETER Battery
    The audit mode: fast, quality, security, vapt, test, e2e, review (default: review)
.PARAMETER Image
    Docker image tag (default: ghcr.io/guardianvigil-lab/vigil:latest)
.PARAMETER TargetUrl
    Target URL for active dynamic VAPT and Playwright E2E probes (default: http://127.0.0.1:3000)
.PARAMETER Shell
    Drop into container interactive bash shell
.PARAMETER Build
    Rebuild local container image
.EXAMPLE
    .\bin\vigil.ps1 -Battery fast
    .\bin\vigil.ps1 -Battery review
    .\bin\vigil.ps1 -Shell
#>

[CmdletBinding()]
param (
    [Parameter(Position = 0)]
    [ValidateSet("fast", "quality", "security", "vapt", "test", "e2e", "review", "all")]
    [string]$Battery = "review",

    [Parameter()]
    [string]$Image = $(if ($env:VIGIL_IMAGE) { $env:VIGIL_IMAGE } else { "ghcr.io/guardianvigil-lab/vigil:latest" }),

    [Parameter()]
    [string]$TargetUrl = "http://127.0.0.1:3000",

    [Parameter()]
    [switch]$Shell,

    [Parameter()]
    [switch]$Build
)

$ErrorActionPreference = "Stop"

$VigilDir = Split-Path -Parent $PSScriptRoot
$WorkspaceDir = Get-Location
$LocalImage = "guardianvigil-vigil:local"
$ReportsDir = Join-Path $WorkspaceDir "reports"

if (-not (Test-Path $ReportsDir)) {
    New-Item -ItemType Directory -Path $ReportsDir -Force | Out-Null
}

# Handle --build
if ($Build) {
    Write-Host "[Vigil] Building container image ($LocalImage)..." -ForegroundColor Cyan
    docker build -t $LocalImage -f "$VigilDir\Dockerfile" $VigilDir
    exit $LASTEXITCODE
}

# Verify Docker daemon is running
try {
    docker version > $null 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Error "[Vigil ERROR] Docker daemon is not running. Please start Docker Desktop."
        exit 1
    }
} catch {
    Write-Error "[Vigil ERROR] Docker CLI not found. Please install Docker Desktop."
    exit 1
}

# Image resolution
$SelectedImage = $Image
$imageCheck = docker image inspect $SelectedImage 2>&1
if ($LASTEXITCODE -ne 0) {
    $localCheck = docker image inspect $LocalImage 2>&1
    if ($LASTEXITCODE -eq 0) {
        $SelectedImage = $LocalImage
    } else {
        Write-Host "[Vigil] Pulling $SelectedImage..." -ForegroundColor Yellow
        docker pull $SelectedImage
        if ($LASTEXITCODE -ne 0) {
            Write-Error "[Vigil ERROR] Failed to pull $SelectedImage. Build locally with: .\bin\vigil.ps1 -Build"
            exit 1
        }
    }
}

# Convert Windows path to Docker mount format
$WorkspaceMount = "${WorkspaceDir}:/workspace"

# Handle --shell
if ($Shell) {
    Write-Host "[Vigil] Entering interactive container debug shell..." -ForegroundColor Cyan
    docker run --rm -it `
        --shm-size=2gb `
        -v $WorkspaceMount `
        -e "TARGET_URL=$TargetUrl" `
        -e "CI=false" `
        --entrypoint /bin/bash `
        $SelectedImage
    exit $LASTEXITCODE
}

Write-Host "══════════════════════════════════════════════════════════════════════" -ForegroundColor DarkCyan
Write-Host "  VIGIL AUDIT (Windows PowerShell Runner)" -ForegroundColor White
Write-Host "  Mode: $Battery | Target: $WorkspaceDir" -ForegroundColor DarkCyan
Write-Host "══════════════════════════════════════════════════════════════════════" -ForegroundColor DarkCyan

# Run Vigil container
docker run --rm -it `
    --shm-size=2gb `
    -v $WorkspaceMount `
    -e "TARGET_URL=$TargetUrl" `
    -e "CI=false" `
    $SelectedImage $Battery

$ExitCode = $LASTEXITCODE

Write-Host "──────────────────────────────────────────────────────────────────────" -ForegroundColor Gray
if ($ExitCode -eq 0) {
    Write-Host "[Vigil] Audit PASSED (Exit code: 0)" -ForegroundColor Green
} else {
    Write-Host "[Vigil] Audit BLOCKED (Exit code: $ExitCode) - Review reports\vigil-review.md" -ForegroundColor Red
}

exit $ExitCode
