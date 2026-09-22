<#
.SYNOPSIS
    Matches IPs and web paths in access.log against known Indicators of Compromise (ioc.txt).
.DESCRIPTION
    Loads malicious IPs and suspicious paths from ioc.txt, then scans access.log
    for any requests originating from those IPs or targeting those paths.
    Returns an array of finding objects.
#>

param(
    [string]$AccessLogPath = ".\ProjectDataset\access.log",
    [string]$IocFilePath   = ".\ProjectDataset\ioc.txt"
)

$findings = @()

if (-not (Test-Path $AccessLogPath)) {
    Write-Warning "[IOC] access.log not found at: $AccessLogPath"
    return $findings
}
if (-not (Test-Path $IocFilePath)) {
    Write-Warning "[IOC] ioc.txt not found at: $IocFilePath"
    return $findings
}

Write-Host "[*] Matching access.log against IOC list..." -ForegroundColor Cyan

# --- Load IOCs (skip comments and blank lines) ---
$iocLines   = Get-Content $IocFilePath | Where-Object { $_ -notmatch "^\s*#" -and $_.Trim() -ne "" }
$maliciousIPs   = $iocLines | Where-Object { $_ -match "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$" }
$maliciousPaths = $iocLines | Where-Object { $_ -match "^/" }

Write-Host "  Loaded $($maliciousIPs.Count) malicious IPs and $($maliciousPaths.Count) suspicious paths from IOC file." -ForegroundColor Gray

$logLines = Get-Content $AccessLogPath

# --- IP Matching ---
foreach ($ip in $maliciousIPs) {
    $matches = $logLines | Where-Object { $_ -match "^$([regex]::Escape($ip))\s" }
    if ($matches.Count -gt 0) {
        $sample = ($matches | Select-Object -First 3) -join "`n      "
        $finding = [PSCustomObject]@{
            DetectionType = "IOC - Malicious IP"
            Indicator     = $ip
            HitCount      = $matches.Count
            Severity      = "HIGH"
            SampleLines   = $sample
        }
        $findings += $finding
        Write-Host "  [!] HIGH - Malicious IP $ip found in $($matches.Count) access log entries" -ForegroundColor Red
    }
}

# --- Path Matching ---
foreach ($path in $maliciousPaths) {
    $escaped = [regex]::Escape($path)
    $matches = $logLines | Where-Object { $_ -match "`"(?:GET|POST|PUT|DELETE|HEAD)\s+$escaped" }
    if ($matches.Count -gt 0) {
        $sample = ($matches | Select-Object -First 3) -join "`n      "
        $finding = [PSCustomObject]@{
            DetectionType = "IOC - Suspicious Path"
            Indicator     = $path
            HitCount      = $matches.Count
            Severity      = "MEDIUM"
            SampleLines   = $sample
        }
        $findings += $finding
        Write-Host "  [!] MEDIUM - Suspicious path '$path' requested $($matches.Count) time(s)" -ForegroundColor Yellow
    }
}

if ($findings.Count -eq 0) {
    Write-Host "  [OK] No IOC matches detected." -ForegroundColor Green
}

return $findings
