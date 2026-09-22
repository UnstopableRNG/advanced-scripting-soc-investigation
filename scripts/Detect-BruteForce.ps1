<#
.SYNOPSIS
    Detects brute force SSH login attempts from auth.log.
.DESCRIPTION
    Parses auth.log for "Failed password" entries, counts failures per source IP,
    and flags any IP that exceeds the threshold (default: 5 attempts).
    Returns an array of finding objects for the main report.
#>

param(
    [string]$AuthLogPath = ".\ProjectDataset\auth.log",
    [int]$Threshold = 5
)

$findings = @()

if (-not (Test-Path $AuthLogPath)) {
    Write-Warning "[BruteForce] auth.log not found at: $AuthLogPath"
    return $findings
}

Write-Host "[*] Analysing auth.log for brute force attempts (threshold: $Threshold)..." -ForegroundColor Cyan

$lines = Get-Content $AuthLogPath

# --- Count failures per IP ---
$failMap = @{}
$rawLines = @{}

foreach ($line in $lines) {
    if ($line -match "Failed password.*from\s+(\S+)\s+port") {
        $ip = $Matches[1]
        $failMap[$ip] = ($failMap[$ip] -as [int]) + 1
        if (-not $rawLines.ContainsKey($ip)) { $rawLines[$ip] = @() }
        $rawLines[$ip] += $line
    }
}

# --- Flag IPs over threshold ---
foreach ($ip in $failMap.Keys) {
    $count = $failMap[$ip]
    if ($count -ge $Threshold) {
        $severity = if ($count -ge 50) { "HIGH" } elseif ($count -ge 20) { "MEDIUM" } else { "LOW" }
        $sample = ($rawLines[$ip] | Select-Object -First 3) -join "`n      "

        $finding = [PSCustomObject]@{
            DetectionType = "Brute Force SSH"
            SourceIP      = $ip
            EventCount    = $count
            Severity      = $severity
            SampleLines   = $sample
        }
        $findings += $finding

        Write-Host "  [!] $severity - IP $ip had $count failed SSH attempts" -ForegroundColor $(
            if ($severity -eq "HIGH") { "Red" } elseif ($severity -eq "MEDIUM") { "Yellow" } else { "White" }
        )
    }
}

if ($findings.Count -eq 0) {
    Write-Host "  [OK] No brute force activity detected above threshold." -ForegroundColor Green
}

return $findings
