# SOC Security Investigation Tool
**Module:** Advanced Scripting COMPH2705
**Assessment:** Project Assessment — Jan-May 2025/26

---

## Project Structure

```
B00172277_Project/
├── run.ps1                               # Run this to start the tool
├── investigation_report.txt              # Output report
├── README.md
├── scripts/
│   ├── Detect-BruteForce.ps1             # Module 1: SSH brute force
│   ├── Detect-IOCMatch.ps1               # Module 2: IOC matching
│   ├── Detect-SuspiciousPowerShell.ps1   # Module 3: PowerShell analysis
│   ├── Detect-WebScanning.ps1            # Module 4: Web scanning
│   └── Generate-Report.ps1               # Builds the final report
└── ProjectDataset/
    ├── access.log
    ├── auth.log
    ├── powershell_log.txt
    └── ioc.txt
```

---

## How to Run

Just run this from the project folder:

```powershell
.\run.ps1
```

You can also pass in options if needed:

```powershell
.\run.ps1 -DatasetPath ".\ProjectDataset" -Analyst "B00172277" -BruteForceThreshold 5
```

---

## What It Detects

| Module | Log Source | What it looks for |
|--------|------------|-------------------|
| Brute Force | auth.log | Too many failed SSH logins from the same IP |
| IOC Match | access.log + ioc.txt | Requests from known malicious IPs or paths |
| Suspicious PowerShell | powershell_log.txt | Encoded commands, policy bypasses, downloads, exfiltration |
| Web Scanning | access.log | High request volume, 404 path enumeration |
