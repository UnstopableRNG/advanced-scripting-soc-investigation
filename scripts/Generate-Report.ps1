<#
.SYNOPSIS
    Generates the investigation_report.txt from all collected findings.
.DESCRIPTION
    Takes an array of finding objects from the detection scripts and
    produces a structured, human-readable investigation report.
#>

param(
    [array]$AllFindings      = @(),
    [string]$OutputPath      = ".\investigation_report.txt",
    [string]$AnalystName     = "B00172277",
    [datetime]$ScanTime      = (Get-Date)
)

$border  = "=" * 70
$divider = "-" * 70

$lines = @()

# -----------------------------------------------------------------------
# HEADER
# -----------------------------------------------------------------------
$lines += $border
$lines += " SECURITY INVESTIGATION REPORT"
$lines += " Advanced Scripting COMPH2705 - SOC Analysis Tool"
$lines += $border
$lines += " Analyst   : $AnalystName"
$lines += " Generated : $($ScanTime.ToString('yyyy-MM-dd HH:mm:ss'))"
$lines += " Log Sources Analysed:"
$lines += "   - ProjectDataset/access.log"
$lines += "   - ProjectDataset/auth.log"
$lines += "   - ProjectDataset/powershell_log.txt"
$lines += "   - ProjectDataset/ioc.txt"
$lines += $border
$lines += ""

# -----------------------------------------------------------------------
# EXECUTIVE SUMMARY
# -----------------------------------------------------------------------
$critical = ($AllFindings | Where-Object { $_.Severity -eq "CRITICAL" }).Count
$high     = ($AllFindings | Where-Object { $_.Severity -eq "HIGH"     }).Count
$medium   = ($AllFindings | Where-Object { $_.Severity -eq "MEDIUM"   }).Count
$low      = ($AllFindings | Where-Object { $_.Severity -eq "LOW"      }).Count
$total    = $AllFindings.Count

$overallRisk = if ($critical -gt 0) { "CRITICAL" }
               elseif ($high  -gt 0) { "HIGH" }
               elseif ($medium -gt 0) { "MEDIUM" }
               elseif ($low   -gt 0) { "LOW" }
               else                  { "CLEAN" }

$lines += "EXECUTIVE SUMMARY"
$lines += $divider
$lines += " Overall Risk Level : $overallRisk"
$lines += " Total Findings     : $total"
$lines += "   CRITICAL : $critical"
$lines += "   HIGH     : $high"
$lines += "   MEDIUM   : $medium"
$lines += "   LOW      : $low"
$lines += ""

if ($total -eq 0) {
    $lines += " No suspicious activity was detected across the analysed log sources."
} else {
    $lines += " SUMMARY OF FINDINGS:"
    $AllFindings | Group-Object -Property DetectionType | ForEach-Object {
        $lines += "   [$($_.Count)] $($_.Name)"
    }
}
$lines += ""

# -----------------------------------------------------------------------
# DETAILED FINDINGS
# -----------------------------------------------------------------------
$lines += $border
$lines += " DETAILED FINDINGS"
$lines += $border

if ($total -eq 0) {
    $lines += " No findings to report."
} else {
    $counter = 1
    foreach ($f in ($AllFindings | Sort-Object -Property @{E={
        switch ($_.Severity) {
            "CRITICAL" {0} "HIGH" {1} "MEDIUM" {2} "LOW" {3} default {4}
        }
    }})) {
        $lines += ""
        $lines += "[$counter] $($f.DetectionType)"
        $lines += $divider
        $lines += " Severity : $($f.Severity)"

        # Print all properties except DetectionType and SampleLines
        foreach ($prop in $f.PSObject.Properties) {
            if ($prop.Name -notin @("DetectionType","SampleLines","Severity") -and $null -ne $prop.Value) {
                $lines += " $($prop.Name.PadRight(13)): $($prop.Value)"
            }
        }

        if ($f.SampleLines) {
            $lines += " Sample Log  :"
            foreach ($sLine in $f.SampleLines -split "`n") {
                $lines += "   $($sLine.Trim())"
            }
        }
        $counter++
    }
}

$lines += ""

# -----------------------------------------------------------------------
# RECOMMENDATIONS
# -----------------------------------------------------------------------
$lines += $border
$lines += " RECOMMENDATIONS"
$lines += $border
$lines += ""

if ($critical -gt 0 -or $high -gt 0) {
    $lines += " [IMMEDIATE ACTION REQUIRED]"
    $lines += ""
    if ($AllFindings | Where-Object { $_.DetectionType -eq "Data Exfiltration Chain" }) {
        $lines += " * DATA EXFILTRATION: Isolate the affected host immediately. Review"
        $lines += "   network captures for outbound data. Preserve forensic disk image."
    }
    if ($AllFindings | Where-Object { $_.DetectionType -eq "Brute Force SSH" -and $_.Severity -in @("HIGH","CRITICAL") }) {
        $lines += " * BRUTE FORCE: Block offending IPs at the firewall. Consider"
        $lines += "   implementing fail2ban or account lockout policy on SSH."
    }
    if ($AllFindings | Where-Object { $_.DetectionType -eq "IOC - Malicious IP" }) {
        $lines += " * IOC MATCH: Traffic to/from known malicious IPs was detected."
        $lines += "   Block these IPs at the perimeter and investigate host activity."
    }
    if ($AllFindings | Where-Object { $_.DetectionType -eq "Suspicious PowerShell" -and $_.Severity -in @("HIGH","CRITICAL") }) {
        $lines += " * POWERSHELL: Encoded/Bypass commands detected. Review PowerShell"
        $lines += "   script block logging and restrict execution policy via GPO."
    }
}

$lines += ""
$lines += " [GENERAL RECOMMENDATIONS]"
$lines += "  1. Enforce key-based SSH authentication only; disable password auth."
$lines += "  2. Enable PowerShell Constrained Language Mode and Script Block Logging."
$lines += "  3. Keep IOC lists updated from threat intelligence feeds (MISP, AbuseIPDB)."
$lines += "  4. Implement a WAF to block requests to sensitive admin paths."
$lines += "  5. Review and rotate credentials for accounts with failed login attempts."
$lines += ""

# -----------------------------------------------------------------------
# FOOTER
# -----------------------------------------------------------------------
$lines += $border
$lines += " END OF REPORT - Generated by SOC Investigation Tool v1.0"
$lines += $border

# --- Write to file ---
$lines | Out-File -FilePath $OutputPath -Encoding UTF8

Write-Host ""
Write-Host "[+] Investigation report written to: $OutputPath" -ForegroundColor Green
