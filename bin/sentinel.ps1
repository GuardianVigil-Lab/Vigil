<#
.SYNOPSIS
    Sentinel: Compatibility wrapper forwarding to Vigil PowerShell Runner
#>

[CmdletBinding()]
param (
    [Parameter(Position = 0)]
    [string]$Battery = "review",

    [Parameter()]
    [string]$Image = "",

    [Parameter()]
    [string]$TargetUrl = "http://127.0.0.1:3000",

    [Parameter()]
    [switch]$Shell,

    [Parameter()]
    [switch]$Build
)

$VigilScript = Join-Path $PSScriptRoot "vigil.ps1"
if (Test-Path $VigilScript) {
    & $VigilScript @PSBoundParameters
    exit $LASTEXITCODE
} else {
    Write-Error "[ERROR] Cannot find vigil.ps1"
    exit 1
}
