# CTI‑Tooling

![PowerShell](https://img.shields.io/badge/PowerShell-7+-blue)
![License](https://img.shields.io/badge/License-Apache_2.0-green)
![In Development](https://img.shields.io/badge/In%20Development-Active-yellow?style=flat-square)

CTI‑Tooling is a collection of PowerShell-based threat intelligence utilities for vulnerability enrichment, hunt guidance generation, and exploitation monitoring. Designed to support analysts, SOC teams, and automated CTI workflows with consistent, actionable output.

## Script Index

CTI‑Tooling currently includes the following PowerShell utilities:

- **CTI‑CVE‑EnrichmentEngine.ps1**  
  A full‑featured CVE enrichment engine supporting CVSSv4, EPSS, CISA KEV, exploit‑intel (Metasploit + Exploit‑DB), tech‑stack relevance, asset context, ATT&CK mapping, and remediation priority scoring (Zero Tolerance, P1–P5).  
  *This script replaces Enrich‑Vulnerability.ps1.*

- **Generate‑HuntGuidance.ps1**  
  Produces ATT&CK‑aligned hunt guidance, detection recommendations, and investigative notes for SOC and analyst teams. Automatically maps CWE → ATT&CK, assigns technique confidence, generates detection pivots, evaluates KEV/EPSS risk, and produces persona‑specific guidance.

- **Monitor‑Exploitation.ps1** *(In Development)*  
  Will track exploitation activity, PoC availability, threat actor usage, and real‑time exploitation indicators once completed.

## Overview

These scripts form a modular CTI workflow that can be used independently or chained together to support vulnerability research, detection engineering, and threat monitoring.

## Development Status

- CTI‑CVE‑EnrichmentEngine.ps1 — Stable  
- Generate‑HuntGuidance.ps1 — Debugging  
- Monitor‑Exploitation.ps1 — In Development

## Usage

Run any script from the `src` directory:

**Bulk CVE Lookup**
```powershell
.\CTI-CVE-EnrichmentEngine.ps1 -InputCveFile .\cves.txt -OutputXlsxFile .\bulk_output.xlsx
```
**Bulk with Optional Inputs**
```powershell
.\CTI-CVE-EnrichmentEngine.ps1 `
    -InputCveFile .\cves.txt `
    -AssetContextCsv .\asset_context.csv `
    -TechStackFile .\TechStack.json `
    -OutputXlsxFile .\bulk_output.xlsx `
    -OverwriteOutput `
    -WritePerCveJson
```
**Single CVE Lookup**
```powershell
.\Enrich-Vulnerability.ps1 -Cve CVE-2024-12345
```
**Single CVE Lookup with Excel Output**
```powershell
.\CTI-CVE-EnrichmentEngine.ps1 -SingleCve CVE-2024-12345 -OutputXlsxFile .\output.xlsx
```
## Requirements

- PowerShell 7+
- Internet access for enrichment modules
- Windows, macOS, or Linux (PowerShell Core)

## Contributing

Contributions, issues, and feature requests are welcome.  
Feel free to open a pull request or submit an issue.

## License

This project is licensed under the Apache License 2.0 — see the LICENSE file for details.

