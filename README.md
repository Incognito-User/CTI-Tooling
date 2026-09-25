# CTI‑Tooling

![PowerShell](https://img.shields.io/badge/PowerShell-7+-blue)
![License](https://img.shields.io/badge/License-Apache_2.0-green)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

CTI‑Tooling is a collection of PowerShell-based threat intelligence utilities for vulnerability enrichment, hunt guidance generation, and exploitation monitoring. Designed to support analysts, SOC teams, and automated CTI workflows with consistent, actionable output.

## Script Index

CTI‑Tooling currently includes the following PowerShell utilities:

- **Enrich‑Vulnerability.ps1**  
  Performs structured CVE and vulnerability enrichment to support triage, analysis, and automated CTI workflows.

- **Generate‑HuntGuidance.ps1**  
  Produces ATT&CK‑aligned hunt guidance, detection recommendations, and investigative notes for SOC and analyst teams. Automatically maps CWE → ATT&CK, assigns technique confidence, generates detection pivots, evaluates KEV/EPSS risk, and produces persona‑specific guidance.

- **Monitor‑Exploitation.ps1** *(In Development)*  
  Will track exploitation activity, PoC availability, threat actor usage, and real‑time exploitation indicators once completed.

## Overview

These scripts form a modular CTI workflow that can be used independently or chained together to support vulnerability research, detection engineering, and threat monitoring.

## Development Status

- Enrich-Vulnerability.ps1 — Stable
- Generate-HuntGuidance.ps1 — Stable
- Monitor-Exploitation.ps1 — In Development

## Usage

Run any script from the `src` directory:

```powershell
.\Enrich-Vulnerability.ps1 -Cve CVE-2024-12345 
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

