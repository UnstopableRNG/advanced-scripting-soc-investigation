<#
.SYNOPSIS
    SOC Security Investigation Tool - Main Entry Point
.DESCRIPTION
    Runs all detection modules against the provided log files and
    generates a consolidated investigation_report.txt.

    Usage:
        .\run.ps1
        .\run.ps1 -DatasetPath "C:\path\to\ProjectDataset" -Analyst "Your Name"

.PARAMETER DatasetPath
    Path to the folder containing the log files.
    Defaults to .\ProjectDataset (relative to this script).

.PARAMETER Analyst
    Name of the analyst running the investigation (appears in the report).

.PARAMETER BruteForceThreshold
    Number of failed SSH attempts per IP before flagging (default: 5).

.PARAMETER ScanThreshold
    Number of HTTP requests per IP before flagging as web scan (default: 20).

.PARAMETER ReportPath
    Output path for the investigation report (default: .\investigation_report.txt).
#>

param(
    [string]$DatasetPath        = ".\ProjectDataset",
    [string]$Analyst            = "B00172277",
    [int]   $BruteForceThreshold = 5,
    [int]   $ScanThreshold       = 20,
    [string]$ReportPath         = ".\investigation_report.txt"
)

# -----------------------------------------------------------------------
# Bootstrap
# -----------------------------------------------------------------------
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

$banner = @"
  ============================================================
   SOC Security Investigation Tool  |  COMPH2705
   Advanced Scripting - Security Log Analyser v1.0
  ============================================================
"@
Write-Host $banner -ForegroundColor Cyan

# Resolve log paths
$accessLog  = Join-Path $DatasetPath "access.log"
$authLog    = Join-Path $DatasetPath "auth.log"
$psLog      = Join-Path $DatasetPath "powershell_log.txt"
$iocFile    = Join-Path $DatasetPath "ioc.txt"

Write-Host "[*] Dataset path : $DatasetPath" -ForegroundColor Gray
Write-Host "[*] Report output: $ReportPath"  -ForegroundColor Gray
Write-Host ""

# -----------------------------------------------------------------------
# Run Detection Modules
# -----------------------------------------------------------------------
$allFindings = @()

# Module 1: Brute Force SSH Detection
Write-Host "--- Module 1: Brute Force Detection ---" -ForegroundColor White
$allFindings += & "$ScriptDir\scripts\Detect-BruteForce.ps1" `
    -AuthLogPath $authLog `
    -Threshold $BruteForceThreshold
Write-Host ""

# Module 2: IOC Matching
Write-Host "--- Module 2: IOC Matching ---" -ForegroundColor White
$allFindings += & "$ScriptDir\scripts\Detect-IOCMatch.ps1" `
    -AccessLogPath $accessLog `
    -IocFilePath $iocFile
Write-Host ""

# Module 3: Suspicious PowerShell
Write-Host "--- Module 3: Suspicious PowerShell Detection ---" -ForegroundColor White
$allFindings += & "$ScriptDir\scripts\Detect-SuspiciousPowerShell.ps1" `
    -PSLogPath $psLog `
    -IocFilePath $iocFile
Write-Host ""

# Module 4: Web Scanning / Enumeration
Write-Host "--- Module 4: Web Scanning Detection ---" -ForegroundColor White
$allFindings += & "$ScriptDir\scripts\Detect-WebScanning.ps1" `
    -AccessLogPath $accessLog `
    -RequestThreshold $ScanThreshold
Write-Host ""

# -----------------------------------------------------------------------
# Generate Report
# -----------------------------------------------------------------------
Write-Host "--- Generating Report ---" -ForegroundColor White
& "$ScriptDir\scripts\Generate-Report.ps1" `
    -AllFindings $allFindings `
    -OutputPath $ReportPath `
    -AnalystName $Analyst `
    -ScanTime (Get-Date)

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Investigation complete. $($allFindings.Count) finding(s) recorded." -ForegroundColor Cyan
Write-Host "  Report: $ReportPath" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
