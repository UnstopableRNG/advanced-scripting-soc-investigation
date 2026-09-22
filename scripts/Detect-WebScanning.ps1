<#
.SYNOPSIS
    Detects web scanning and directory traversal attempts from access.log.
.DESCRIPTION
    Analyses access.log for signs of automated web scanning:
      - A single IP generating more than 20 requests in the log
      - Requests returning HTTP 404 errors (probing for hidden paths)
      - Directory traversal patterns (../ sequences in URLs)
    Returns an array of finding objects.
#>

param(
    [string]$AccessLogPath = ".\ProjectDataset\access.log",
    [int]$RequestThreshold  = 20,
    [int]$ErrorThreshold    = 10
)

$findings = @()

if (-not (Test-Path $AccessLogPath)) {
    Write-Warning "[WebScan] access.log not found at: $AccessLogPath"
    return $findings
}

Write-Host "[*] Analysing access.log for web scanning / enumeration..." -ForegroundColor Cyan

$lines = Get-Content $AccessLogPath

# --- Count total requests per IP ---
$ipCount = @{}
foreach ($line in $lines) {
    if ($line -match "^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})") {
        $ip = $Matches[1]
        $ipCount[$ip] = ($ipCount[$ip] -as [int]) + 1
    }
}

foreach ($ip in $ipCount.Keys) {
    if ($ipCount[$ip] -ge $RequestThreshold) {
        $sample = ($lines | Where-Object { $_ -match "^$([regex]::Escape($ip))\s" } | Select-Object -First 3) -join "`n      "
        $severity = if ($ipCount[$ip] -ge 200) { "HIGH" } else { "MEDIUM" }
        $finding = [PSCustomObject]@{
            DetectionType = "Web Scanning - High Request Volume"
            SourceIP      = $ip
            HitCount      = $ipCount[$ip]
            Severity      = $severity
            SampleLines   = $sample
        }
        $findings += $finding
        Write-Host "  [!] $severity - IP $ip made $($ipCount[$ip]) requests (scan threshold: $RequestThreshold)" -ForegroundColor $(
            if ($severity -eq "HIGH") { "Red" } else { "Yellow" }
        )
    }
}

# --- Count 404 errors per IP ---
$notFoundMap = @{}
foreach ($line in $lines) {
    if ($line -match "^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})") {
        $ip = $Matches[1]
        if ($line -match ' 404 ') {
            $notFoundMap[$ip] = ($notFoundMap[$ip] -as [int]) + 1
        }
    }
}

foreach ($ip in $notFoundMap.Keys) {
    if ($notFoundMap[$ip] -ge $ErrorThreshold) {
        # Don't double-report if already flagged for volume
        if (-not ($findings | Where-Object { $_.SourceIP -eq $ip -and $_.DetectionType -eq "Web Scanning - High Request Volume" })) {
            $escaped = [regex]::Escape($ip)
            $sample = ($lines | Where-Object { $_ -match "^$escaped" -and $_ -match ' 404 ' } | Select-Object -First 3) -join "`n      "
            $finding = [PSCustomObject]@{
                DetectionType = "Web Scanning - 404 Enumeration"
                SourceIP      = $ip
                HitCount      = $notFoundMap[$ip]
                Severity      = "MEDIUM"
                SampleLines   = $sample
            }
            $findings += $finding
            Write-Host "  [!] MEDIUM - IP $ip triggered $($notFoundMap[$ip]) HTTP 404 errors (path enumeration)" -ForegroundColor Yellow
        }
    }
}

# --- Directory traversal detection ---
$traversalHits = $lines | Where-Object { $_ -match "(\.\./|%2e%2e%2f|%252e)" }
if ($traversalHits.Count -gt 0) {
    $sample = ($traversalHits | Select-Object -First 3) -join "`n      "
    $finding = [PSCustomObject]@{
        DetectionType = "Directory Traversal Attempt"
        SourceIP      = "Multiple"
        HitCount      = $traversalHits.Count
        Severity      = "HIGH"
        SampleLines   = $sample
    }
    $findings += $finding
    Write-Host "  [!] HIGH - Directory traversal patterns detected ($($traversalHits.Count) instance(s))" -ForegroundColor Red
}

if ($findings.Count -eq 0) {
    Write-Host "  [OK] No web scanning activity detected." -ForegroundColor Green
}

return $findings
