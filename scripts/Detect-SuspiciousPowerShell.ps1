<#
.SYNOPSIS
    Detects suspicious PowerShell execution patterns in powershell_log.txt.
.DESCRIPTION
    Scans the PowerShell activity log for high-risk parameters and commands:
      - EncodedCommand  (obfuscated payload execution)
      - ExecutionPolicy Bypass  (policy bypass)
      - Invoke-WebRequest / DownloadString  (remote downloads)
      - Known malicious URLs (cross-referenced against IOC file)
      - Compress-Archive followed by upload  (data exfiltration chain)
    Returns an array of finding objects.
#>

param(
    [string]$PSLogPath  = ".\ProjectDataset\powershell_log.txt",
    [string]$IocFilePath = ".\ProjectDataset\ioc.txt"
)

$findings = @()

if (-not (Test-Path $PSLogPath)) {
    Write-Warning "[PowerShell] powershell_log.txt not found at: $PSLogPath"
    return $findings
}

Write-Host "[*] Analysing PowerShell log for suspicious patterns..." -ForegroundColor Cyan

$lines = Get-Content $PSLogPath

# --- Load IOC domains/URLs for cross-reference ---
$iocUrls = @()
if (Test-Path $IocFilePath) {
    $iocUrls = Get-Content $IocFilePath |
               Where-Object { $_ -notmatch "^\s*#" -and $_ -match "https?://" }
}

# Detection rules: pattern -> (description, severity)
$rules = @(
    @{ Pattern = "-EncodedCommand";           Desc = "Base64-encoded command execution (obfuscation)"; Severity = "HIGH" },
    @{ Pattern = "-ExecutionPolicy\s+Bypass"; Desc = "Execution policy bypass flag";                   Severity = "HIGH" },
    @{ Pattern = "DownloadString";            Desc = "In-memory remote code download";                 Severity = "HIGH" },
    @{ Pattern = "Invoke-WebRequest.*-Upload"; Desc = "Web upload activity (possible exfiltration)";   Severity = "HIGH" },
    @{ Pattern = "Invoke-WebRequest";         Desc = "Remote web request";                             Severity = "MEDIUM" },
    @{ Pattern = "Compress-Archive";          Desc = "Archive creation (possible data staging)";       Severity = "MEDIUM" },
    @{ Pattern = "-NoProfile";                Desc = "NoProfile flag (stealth execution)";             Severity = "LOW" }
)

foreach ($rule in $rules) {
    $hits = $lines | Where-Object { $_ -match $rule.Pattern }
    if ($hits.Count -gt 0) {
        $sample = ($hits | Select-Object -First 3) -join "`n      "
        $finding = [PSCustomObject]@{
            DetectionType = "Suspicious PowerShell"
            Pattern       = $rule.Pattern
            Description   = $rule.Desc
            HitCount      = $hits.Count
            Severity      = $rule.Severity
            SampleLines   = $sample
        }
        $findings += $finding
        Write-Host "  [!] $($rule.Severity) - $($rule.Desc) ($($hits.Count) instance(s))" -ForegroundColor $(
            if ($rule.Severity -eq "HIGH") { "Red" } elseif ($rule.Severity -eq "MEDIUM") { "Yellow" } else { "White" }
        )
    }
}

# --- Cross-reference URLs against IOC list ---
foreach ($iocUrl in $iocUrls) {
    $hits = $lines | Where-Object { $_ -match [regex]::Escape($iocUrl) }
    if ($hits.Count -gt 0) {
        $sample = ($hits | Select-Object -First 3) -join "`n      "
        $finding = [PSCustomObject]@{
            DetectionType = "Suspicious PowerShell"
            Pattern       = "IOC URL match: $iocUrl"
            Description   = "PowerShell contacted a known malicious URL"
            HitCount      = $hits.Count
            Severity      = "HIGH"
            SampleLines   = $sample
        }
        $findings += $finding
        Write-Host "  [!] HIGH - Known malicious URL found in PowerShell log: $iocUrl" -ForegroundColor Red
    }
}

# --- Detect exfiltration chain: Compress-Archive then Upload within 5 minutes ---
$archiveLines = $lines | Where-Object { $_ -match "Compress-Archive" }
$uploadLines  = $lines | Where-Object { $_ -match "Invoke-WebRequest.*-Upload" }

if ($archiveLines.Count -gt 0 -and $uploadLines.Count -gt 0) {
    $finding = [PSCustomObject]@{
        DetectionType = "Data Exfiltration Chain"
        Pattern       = "Compress-Archive -> Invoke-WebRequest -Upload"
        Description   = "Data archiving followed by web upload - likely exfiltration"
        HitCount      = 1
        Severity      = "CRITICAL"
        SampleLines   = ($archiveLines + $uploadLines | Select-Object -First 4) -join "`n      "
    }
    $findings += $finding
    Write-Host "  [!!!] CRITICAL - Exfiltration chain detected: archive creation followed by upload" -ForegroundColor Magenta
}

if ($findings.Count -eq 0) {
    Write-Host "  [OK] No suspicious PowerShell activity detected." -ForegroundColor Green
}

return $findings
