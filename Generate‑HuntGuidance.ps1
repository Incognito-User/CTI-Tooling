<#
.SYNOPSIS
  Script B v3 — Hybrid Hunt Guidance Generator

.DESCRIPTION
  Generates CTI/SOC-ready hunt guidance for a single CVE using live enrichment:
    - NVD (description, CVSS, CWE, vendor/product)
    - CISA KEV (known exploited status)
    - EPSS (exploit probability)
    - CWE → ATT&CK → Hunt Profile
    - CVSS vector → telemetry hints
    - Hunt priority (KEV + EPSS)

  Supports:
    - Persona modes: Analyst, Beginner, Soc, Manager, Insight
    - Output formats: Text (persona), Json, Sentinel, Splunk, Elastic

.PARAMETER Cve
  CVE identifier (e.g., CVE-2024-12345).

.PARAMETER Beginner
  Simplified explanations and shorter lists.

.PARAMETER Analyst
  Full technical output (default).

.PARAMETER Soc
  SIEM-focused output with query examples.

.PARAMETER Manager
  Executive summary and business-impact focused output.

.PARAMETER Insight
  Adds reflective commentary.

.PARAMETER Format
  Output format: Text (default), Json, Sentinel, Splunk, Elastic.

.PARAMETER OutFile
  Optional path to write output. If omitted, writes to console.

.NOTES
  Author: Lisa
  Script: Script B v3 — Hybrid Hunt Guidance Generator
  Version: 2.0
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^CVE-\d{4}-\d{4,}$')]
    [string]$Cve,

    [switch]$Beginner,
    [switch]$Analyst,
    [switch]$Soc,
    [switch]$Manager,
    [switch]$Insight,

    [Parameter(Mandatory = $false)]
    [ValidateSet('Text', 'Json', 'Sentinel', 'Splunk', 'Elastic')]
    [string]$Format = 'Text',

    [Parameter(Mandatory = $false)]
    [string]$OutFile
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Normalize CVE casing
$Cve = $Cve.ToUpper()

function Show-Header {
    Write-Host "===========================================" -ForegroundColor Cyan
    Write-Host "        Hunt Guidance Generator (Script B v3)" -ForegroundColor Cyan
    Write-Host "===========================================" -ForegroundColor Cyan
    Write-Host ""
}

function Show-Usage {
    Write-Host "This tool generates CTI/SOC-ready hunt guidance for a single CVE." -ForegroundColor Gray
    Write-Host ""
    Write-Host "Usage examples:" -ForegroundColor Gray
    Write-Host "  .\ScriptBv2.ps1 -Cve CVE-2024-12345" -ForegroundColor Gray
    Write-Host "  .\ScriptBv2.ps1 -Cve CVE-2024-12345 -Soc -Format Json" -ForegroundColor Gray
    Write-Host "  .\ScriptBv2.ps1 -Cve CVE-2024-12345 -Manager -Format Text" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Persona modes (precedence: Manager > Soc/Beginner > Analyst):" -ForegroundColor Gray
    Write-Host "  -Beginner   Simplified explanations and shorter lists" -ForegroundColor Gray
    Write-Host "  -Analyst    Full technical output (default)" -ForegroundColor Gray
    Write-Host "  -Soc        SIEM-focused queries" -ForegroundColor Gray
    Write-Host "  -Manager    Executive summary only" -ForegroundColor Gray
    Write-Host "  -Insight    Adds reflective commentary" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Formats:" -ForegroundColor Gray
    Write-Host "  -Format Text     Persona-based console output" -ForegroundColor Gray
    Write-Host "  -Format Json     Structured JSON" -ForegroundColor Gray
    Write-Host "  -Format Sentinel Sentinel KQL stub" -ForegroundColor Gray
    Write-Host "  -Format Splunk   Splunk SPL stub" -ForegroundColor Gray
    Write-Host "  -Format Elastic  Elastic EQL/DSL stub" -ForegroundColor Gray
    Write-Host ""
}

# =========================
# CWE → ATT&CK MAPPING
# =========================
$CweToAttackMap = @{
    'CWE-78'  = @{ Id='T1059.004'; Name='Command Injection' }
    'CWE-94'  = @{ Id='T1059';     Name='Execution' }
    'CWE-95'  = @{ Id='T1059';     Name='Execution' }
    'CWE-502' = @{ Id='T1203';     Name='Exploitation for Client Execution' }
    'CWE-917' = @{ Id='T1059.001'; Name='SQL Injection' }
    'CWE-89'  = @{ Id='T1190';     Name='Exploit Public-Facing Application' }
    'CWE-74'  = @{ Id='T1190';     Name='Exploit Public-Facing Application' }
    'CWE-20'  = @{ Id='T1190';     Name='Exploit Public-Facing Application' }

    'CWE-79'  = @{ Id='T1059.007'; Name='Cross-Site Scripting' }
    'CWE-80'  = @{ Id='T1059.007'; Name='Cross-Site Scripting' }
    'CWE-352' = @{ Id='T1539';     Name='Steal Web Session Cookie' }
    'CWE-22'  = @{ Id='T1006';     Name='Path Traversal' }
    'CWE-601' = @{ Id='T1557';     Name='Man-in-the-Middle' }
    'CWE-863' = @{ Id='T1068';     Name='Privilege Escalation' }

    'CWE-287' = @{ Id='T1078';     Name='Valid Accounts' }
    'CWE-384' = @{ Id='T1550';     Name='Use of Stolen Session Tokens' }
    'CWE-640' = @{ Id='T1110';     Name='Brute Force' }
    'CWE-798' = @{ Id='T1552';     Name='Hardcoded Credentials' }
    'CWE-522' = @{ Id='T1552';     Name='Insecure Credential Storage' }

    'CWE-284' = @{ Id='T1068';     Name='Privilege Escalation' }
    'CWE-266' = @{ Id='T1068';     Name='Privilege Escalation' }
    'CWE-269' = @{ Id='T1068';     Name='Privilege Escalation' }
    'CWE-732' = @{ Id='T1068';     Name='Privilege Escalation' }

    'CWE-915' = @{ Id='T1203';     Name='Exploitation for Client Execution' }
    'CWE-471' = @{ Id='T1203';     Name='Exploitation for Client Execution' }

    'CWE-434' = @{ Id='T1105';     Name='Ingress Tool Transfer' }
    'CWE-611' = @{ Id='T1203';     Name='Exploitation for Client Execution' }

    'CWE-1336' = @{ Id='T1059';    Name='Execution' }
    
    'CWE-200' = @{ Id='T1087';     Name='Account Discovery' }
    'CWE-201' = @{ Id='T1087';     Name='Account Discovery' }
    'CWE-538' = @{ Id='T1087';     Name='Account Discovery' }

    'CWE-327' = @{ Id='T1552';     Name='Weak Cryptography' }
    'CWE-328' = @{ Id='T1552';     Name='Weak Cryptography' }

    'CWE-116' = @{ Id='T1190';     Name='Exploit Public-Facing Application' }
    'CWE-117' = @{ Id='T1005';     Name='Data from Local System' }
}
$CweToAttackMap['CWE-21']  = @{ Id='T1006';     Name='Path Traversal' }
$CweToAttackMap['CWE-73']  = @{ Id='T1006';     Name='Path Traversal' }
$CweToAttackMap['CWE-918'] = @{ Id='T1190';     Name='Server-Side Request Forgery' }
$CweToAttackMap['CWE-601'] = @{ Id='T1557';     Name='Man-in-the-Middle' }
$CweToAttackMap['CWE-640'] = @{ Id='T1110';     Name='Brute Force' }
$CweToAttackMap['CWE-307'] = @{ Id='T1110';     Name='Brute Force' }
$CweToAttackMap['CWE-732'] = @{ Id='T1068';     Name='Privilege Escalation' }
$CweToAttackMap['CWE-284'] = @{ Id='T1068';     Name='Privilege Escalation' }
$CweToAttackMap['CWE-522'] = @{ Id='T1552';     Name='Credential Exposure' }
$CweToAttackMap['CWE-798'] = @{ Id='T1552';     Name='Hardcoded Credentials' }
$CweToAttackMap['CWE-200'] = @{ Id='T1087';     Name='Information Exposure' }
$CweToAttackMap['CWE-201'] = @{ Id='T1087';     Name='Information Exposure' }
$CweToAttackMap['CWE-434'] = @{ Id='T1105';     Name='Ingress Tool Transfer' }
$CweToAttackMap['CWE-611'] = @{ Id='T1203';     Name='Exploitation for Client Execution' }
$CweToAttackMap['CWE-1336']= @{ Id='T1059';     Name='Template/Expression Injection' }
$CweToAttackMap['CWE-917'] = @{ Id='T1059.001'; Name='SQL Injection' }
$CweToAttackMap['CWE-116'] = @{ Id='T1190';     Name='Exploit Public-Facing Application' }
$CweToAttackMap['CWE-117'] = @{ Id='T1005';     Name='Data from Local System' }
$CweToAttackMap['CWE-327'] = @{ Id='T1552';     Name='Weak Cryptography' }
$CweToAttackMap['CWE-328'] = @{ Id='T1552';     Name='Weak Cryptography' }
function Get-TechniqueConfidence {
    param([string]$CweId)

    switch ($CweId) {

        # High confidence — direct exploitation
        'CWE-78'  { return 'High' }  # Command Injection
        'CWE-94'  { return 'High' }  # Code Injection
        'CWE-95'  { return 'High' }
        'CWE-502' { return 'High' }  # Deserialization → RCE
        'CWE-917' { return 'High' }  # SQL Injection
        'CWE-89'  { return 'High' }  # SQLi / Web exploit
        'CWE-74'  { return 'High' }  # Injection
        'CWE-22'  { return 'High' }  # Path Traversal
        'CWE-21'  { return 'High' }
        'CWE-73'  { return 'High' }
        'CWE-918' { return 'High' }  # SSRF
        'CWE-1336'{ return 'High' }  # Template Injection

        # Medium confidence — access control, crypto, exposure
        'CWE-284' { return 'Medium' }
        'CWE-266' { return 'Medium' }
        'CWE-269' { return 'Medium' }
        'CWE-732' { return 'Medium' }
        'CWE-327' { return 'Medium' }
        'CWE-328' { return 'Medium' }
        'CWE-200' { return 'Medium' }
        'CWE-201' { return 'Medium' }
        'CWE-538' { return 'Medium' }

        # Low confidence — anything else
        default   { return 'Low' }
    }
}

function Get-DetectionPivotsForTechnique {
    param([string]$TechniqueId)

    switch ($TechniqueId) {

        # =========================
        # Exploitation for Client Execution (RCE)
        # =========================
        'T1203' {
            return @(
                'Unusual client-side code execution events',
                'Java processes spawning unexpected child processes',
                'JNDI/LDAP lookup anomalies',
                'Outbound LDAP/LDAPS connections from web servers',
                'Execution of payloads delivered via serialized objects'
            )
        }

        # =========================
        # Command Injection
        # =========================
        'T1059.004' {
            return @(
                'Shell commands appearing in web parameters',
                'Unexpected /bin/sh or cmd.exe child processes',
                'Command-line arguments containing user-controlled input',
                'Web server spawning OS-level processes'
            )
        }

        # =========================
        # SQL Injection
        # =========================
        'T1059.001' {
            return @(
                'SQL syntax errors in application logs',
                'Database authentication failures with malformed queries',
                'Spike in SELECT/UNION/OR 1=1 patterns',
                'Unexpected DB read operations from web-tier accounts'
            )
        }

        # =========================
        # Exploit Public-Facing Application
        # =========================
        'T1190' {
            return @(
                'Repeated 400/500 errors with suspicious payloads',
                'Known exploit strings in URLs or parameters',
                'Unexpected file reads via web endpoints',
                'Indicators of SSRF, OGNL, template injection'
            )
        }

        # =========================
        # Path Traversal
        # =========================
        'T1006' {
            return @(
                '../ or ..\\ sequences in requests',
                'Access to sensitive directories (etc/, WEB-INF/, /proc/)',
                'Unexpected file read operations from web processes'
            )
        }

        # =========================
        # Man-in-the-Middle
        # =========================
        'T1557' {
            return @(
                'Certificate mismatches or unexpected cert issuers',
                'Traffic rerouting anomalies',
                'DNS poisoning or spoofing indicators'
            )
        }

        # =========================
        # Privilege Escalation
        # =========================
        'T1068' {
            return @(
                'Processes gaining elevated privileges unexpectedly',
                'Abnormal token manipulation',
                'Unexpected sudo or runas events'
            )
        }

        # =========================
        # Hardcoded / Exposed Credentials
        # =========================
        'T1552' {
            return @(
                'Credentials found in logs or config files',
                'Secrets committed to repositories',
                'Use of weak or legacy cryptography'
            )
        }

        # =========================
        # Default fallback
        # =========================
        default {
            return @(
                'No predefined pivots; CTI analyst review recommended'
            )
        }
    }
}


# =========================
# CWE NORMALIZATION
# =========================
function Convert-CweId {
    param([string]$RawCwe)

    # If NVD already returned a CWE-ID (rare but possible)
    if ($RawCwe -match 'CWE-\d+') {
        return ($RawCwe -match 'CWE-\d+') | Out-Null; $matches[0]
    }

    # Try to extract CWE-ID from parentheses or quotes
    if ($RawCwe -match 'CWE-(\d+)') {
        return "CWE-$($matches[1])"
    }

    # If nothing matches, return original text
    return $RawCwe
}

# =========================
# NVD DATA RETRIEVAL
# =========================
function Get-NvdData {
    param([Parameter(Mandatory = $true)][string]$CveId)

    $nvdUrl = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=$CveId"
    $result = [ordered]@{
        Description  = $null
        CvssVector   = $null
        CvssScore    = $null
        CvssVersion  = $null
        Cwe          = $null
        VendorNvd    = $null
        ProductNvd   = $null
        NvdUrl       = "https://nvd.nist.gov/vuln/detail/$CveId"
        RetrievedOk  = $false
    }

    try {
        $response = Invoke-RestMethod -Uri $nvdUrl -Method Get -ErrorAction Stop -TimeoutSec 30
        if ($null -eq $response -or $null -eq $response.vulnerabilities -or $response.vulnerabilities.Count -eq 0) {
            Write-Warning "NVD returned no data for $CveId."
            return $result
        }

        $cve = $response.vulnerabilities[0].cve

        # Description
        if ($null -ne $cve.descriptions) {
            $enDesc = $cve.descriptions | Where-Object { $_.lang -eq 'en' } | Select-Object -First 1
            if ($null -ne $enDesc) { $result.Description = $enDesc.value }
        }

        # CVSS
        $metrics = $cve.metrics
        if ($null -ne $metrics) {
            if ($metrics.cvssMetricV31 -and $metrics.cvssMetricV31.Count -gt 0) {
                $result.CvssVector  = $metrics.cvssMetricV31[0].cvssData.vectorString
                $result.CvssScore   = $metrics.cvssMetricV31[0].cvssData.baseScore
                $result.CvssVersion = '3.1'
            }
            elseif ($metrics.cvssMetricV30 -and $metrics.cvssMetricV30.Count -gt 0) {
                $result.CvssVector  = $metrics.cvssMetricV30[0].cvssData.vectorString
                $result.CvssScore   = $metrics.cvssMetricV30[0].cvssData.baseScore
                $result.CvssVersion = '3.0'
            }
            elseif ($metrics.cvssMetricV2 -and $metrics.cvssMetricV2.Count -gt 0) {
                $result.CvssVector  = $metrics.cvssMetricV2[0].cvssData.vectorString
                $result.CvssScore   = $metrics.cvssMetricV2[0].cvssData.baseScore
                $result.CvssVersion = '2.0'
            }
        }

        # =========================
# MULTI-CWE SUPPORT
# =========================

# Collect all CWE entries
$result.CweList = @()

if ($null -ne $cve.weaknesses -and $cve.weaknesses.Count -gt 0) {
    foreach ($w in $cve.weaknesses) {
        $cweDesc = $w.description |
            Where-Object { $_.lang -eq 'en' } |
            Select-Object -First 1

        if ($null -ne $cweDesc) {
            $normalized = Convert-CweId -RawCwe $cweDesc.value
            if ($normalized) {
                $result.CweList += $normalized
            }
        }
    }
}

# If NVD returned no CWE, fallback logic still applies
if ($result.CweList.Count -eq 0) {
    $result.CweList = @()
}

# =========================
# CWE PRIORITY RANKING
# =========================

# Define CWE priority (higher = stronger mapping)
$cwePriority = @{
    'CWE-502' = 100  # Deserialization → RCE
    'CWE-78'  = 95   # Command Injection
    'CWE-94'  = 95   # Code Injection
    'CWE-917' = 90   # SQL Injection
    'CWE-89'  = 90   # SQLi
    'CWE-74'  = 85   # Injection
    'CWE-22'  = 80   # Path Traversal
    'CWE-918' = 80   # SSRF
    'CWE-1336'= 75   # Template Injection
    'CWE-79'  = 70   # XSS
    'CWE-80'  = 70
    'CWE-20'  = 60   # Input validation
    'CWE-284' = 50   # PrivEsc
    'CWE-732' = 50
    'CWE-266' = 50
    'CWE-269' = 50
    'CWE-327' = 40   # Weak crypto
    'CWE-328' = 40
    'CWE-200' = 30   # Info exposure
    'CWE-201' = 30
    'CWE-538' = 30
}

# Pick strongest CWE
if ($result.CweList.Count -gt 0) {
    $result.Cwe = $result.CweList |
        Sort-Object { if ($cwePriority.ContainsKey($_)) { $cwePriority[$_] } else { 0 } } -Descending |
        Select-Object -First 1
}


        # Fallback for CVEs where NVD returns no CWE
            if (-not $result.Cwe) {
                switch ($CveId) {
                    'CVE-2021-44228' { $result.Cwe = 'CWE-502' }
                    'CVE-2021-45046' { $result.Cwe = 'CWE-502' }
                    'CVE-2021-45105' { $result.Cwe = 'CWE-502' }
                    # Add more special cases if needed
                }
            }

        # Vendor / Product
        if ($null -ne $cve.configurations -and $cve.configurations.Count -gt 0) {
            $node = $cve.configurations[0].nodes | Select-Object -First 1
            if ($null -ne $node -and $node.cpeMatch -and $node.cpeMatch.Count -gt 0) {
                $cpe = $node.cpeMatch[0].criteria
                if ($cpe) {
                    $parts = $cpe -split ':'
                    if ($parts.Count -ge 5) {
                        $result.VendorNvd  = $parts[3]
                        $result.ProductNvd = $parts[4]
                    }
                }
            }
        }

        $result.RetrievedOk = $true
    }
    catch {
        Write-Warning "Failed to retrieve NVD data for $CveId : $($_.Exception.Message)"
    }

    return $result
}

# =========================
# ATT&CK RESOLVER
# =========================
function Resolve-AttackFromCwe {
    param([string]$CweId)

    # If no CWE was provided
    if ([string]::IsNullOrWhiteSpace($CweId)) {
        return [ordered]@{
            TechniqueId               = 'Unknown'
            TechniqueName             = 'Manual CTI review required'
            AttackTechniqueConfidence = 'Low'
        }
    }

        if ($CweToAttackMap.ContainsKey($CweId)) {
    $entry = $CweToAttackMap[$CweId]
    return [ordered]@{
        TechniqueId               = $entry.Id
        TechniqueName             = $entry.Name
        AttackTechniqueConfidence = Get-TechniqueConfidence -CweId $CweId
    }
}

    # Fallback if CWE is not in the map
    return [ordered]@{
        TechniqueId               = 'Unknown'
        TechniqueName             = 'Manual CTI review required'
        AttackTechniqueConfidence = 'Low'
    }
}

# =========================
# CISA KEV LOOKUP
# =========================
function Get-KevStatus {
    param([Parameter(Mandatory = $true)][string]$CveId)

    $kevUrl = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    $result = [ordered]@{
        IsKev      = $false
        KevUrl     = 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog'
        DateAdded  = $null
        DueDate    = $null
        RetrievedOk = $false
    }

    try {
        $response = Invoke-RestMethod -Uri $kevUrl -Method Get -ErrorAction Stop -TimeoutSec 30
        if ($null -eq $response -or $null -eq $response.vulnerabilities) {
            Write-Warning "CISA KEV feed returned no data."
            return $result
        }

        $match = $response.vulnerabilities | Where-Object { $_.cveID -eq $CveId } | Select-Object -First 1
        if ($null -ne $match) {
            $result.IsKev     = $true
            $result.DateAdded = $match.dateAdded
            $result.DueDate   = $match.dueDate
        }

        $result.RetrievedOk = $true
    }
    catch {
        Write-Warning "Failed to retrieve CISA KEV data: $($_.Exception.Message)"
    }

    return $result
}

# =========================
# EPSS LOOKUP
# =========================
function Get-EpssData {
    param([Parameter(Mandatory = $true)][string]$CveId)

    $epssUrl = "https://api.first.org/data/v1/epss?cve=$CveId"
    $result = [ordered]@{
        EpssScore      = $null
        EpssPercentile = $null
        EpssUrl        = "https://www.first.org/epss/data?cve=$CveId"
        RetrievedOk    = $false
    }

    try {
        $response = Invoke-RestMethod -Uri $epssUrl -Method Get -ErrorAction Stop -TimeoutSec 30
        if ($null -eq $response -or $null -eq $response.data -or $response.data.Count -eq 0) {
            Write-Warning "EPSS API returned no data for $CveId."
            return $result
        }

        $result.EpssScore      = [double]$response.data[0].epss
        $result.EpssPercentile = [double]$response.data[0].percentile
        $result.RetrievedOk    = $true
    }
    catch {
        Write-Warning "Failed to retrieve EPSS data for $CveId : $($_.Exception.Message)"
    }

    return $result
}

# =========================
# CWE -> ATT&CK -> HUNT PROFILE
# =========================
function Get-HuntProfile {
    param([Parameter(Mandatory = $false)][string]$Cwe)

    $profileMap = @{

        'CWE-79' = [ordered]@{
            CweId               = 'CWE-79'
            CweName             = 'Cross-Site Scripting'
            AttackTechniqueId   = 'T1059.007'
            AttackTechniqueName = 'Command and Scripting Interpreter: JavaScript'
            LogSources          = @('Web application/WAF logs', 'Browser telemetry / EDR script-execution logs', 'Proxy logs')
            Indicators          = @('Unexpected inline <script> payloads', 'Encoded JS payloads', 'Anomalous outbound browser requests')
            QueryIdeas          = @('Search WAF logs for <script>, javascript:, onerror=', 'Search EDR for browser spawning script engines')
        }

        'CWE-89' = [ordered]@{
            CweId               = 'CWE-89'
            CweName             = 'SQL Injection'
            AttackTechniqueId   = 'T1190'
            AttackTechniqueName = 'Exploit Public-Facing Application'
            LogSources          = @('Web application logs', 'Database audit logs', 'Application server logs')
            Indicators          = @("SQL meta-characters (' OR 1=1, UNION SELECT)", 'DB error responses', 'Abnormal query patterns')
            QueryIdeas          = @("Search logs for UNION SELECT, OR 1=1", 'Search DB logs for anomalous SELECT/UNION')
        }

        'CWE-78' = [ordered]@{
            CweId               = 'CWE-78'
            CweName             = 'OS Command Injection'
            AttackTechniqueId   = 'T1059'
            AttackTechniqueName = 'Command and Scripting Interpreter'
            LogSources          = @('Application logs', 'EDR process execution logs', 'Sysmon Event ID 1')
            Indicators          = @('Unexpected shell commands', 'App server spawning cmd/sh', 'Encoded command payloads')
            QueryIdeas          = @('Search for cmd.exe or /bin/sh spawned by web processes', 'Search for suspicious command-line arguments')
        }

        'CWE-22' = [ordered]@{
            CweId               = 'CWE-22'
            CweName             = 'Path Traversal'
            AttackTechniqueId   = 'T1005'
            AttackTechniqueName = 'Data from Local System'
            LogSources          = @('Web server logs', 'File access logs', 'Application logs')
            Indicators          = @('Presence of ../ sequences', 'Unauthorized file reads', 'Abnormal file access patterns')
            QueryIdeas          = @('Search logs for ../ or ..\ patterns', 'Search file access logs for sensitive file reads')
        }

        'CWE-502' = [ordered]@{
            CweId               = 'CWE-502'
            CweName             = 'Deserialization of Untrusted Data'
            AttackTechniqueId   = 'T1203'
            AttackTechniqueName = 'Exploitation for Client Execution'
            LogSources          = @('Application logs', 'EDR process execution', 'Sysmon Event ID 1')
            Indicators          = @('Unexpected object types', 'App server spawning unexpected processes', 'Malformed serialized payloads')
            QueryIdeas          = @('Search logs for suspicious serialized objects', 'Search EDR for app server spawning child processes')
        }
    }

    $cweId = $null
    if (-not [string]::IsNullOrWhiteSpace($Cwe)) {
        if ($Cwe -match 'CWE-\d+') { $cweId = $Matches[0] }
    }

    if ($null -ne $cweId -and $profileMap.ContainsKey($cweId)) {
        return $profileMap[$cweId]
    }

    return [ordered]@{
        CweId               = if ($cweId) { $cweId } else { 'Unknown' }
        CweName             = 'Unmapped / Unknown Weakness Type'
        AttackTechniqueId   = 'Unknown'
        AttackTechniqueName = 'Manual CTI review required'
        LogSources          = @('Application logs', 'EDR telemetry', 'Network/firewall logs')
        Indicators          = @('No pre-defined indicators; CTI analyst review required')
        QueryIdeas          = @('Baseline normal behavior for affected asset/service; hunt for deviations around disclosure window')
    }
}

# =========================
# CVSS VECTOR -> TELEMETRY
# =========================
function Get-TelemetryHints {
    param([string]$CvssVector)

    $hints = New-Object System.Collections.Generic.List[string]
    if ([string]::IsNullOrWhiteSpace($CvssVector)) {
        $hints.Add('No CVSS vector available; review NVD manually for telemetry context.')
        return $hints
    }

    if ($CvssVector -match 'AV:N') { $hints.Add('AV:N -> Review internet-facing perimeter logs (firewall, WAF, proxy).') }
    if ($CvssVector -match 'PR:N') { $hints.Add('PR:N -> Review unauthenticated access logs and pre-auth request patterns.') }
    if ($CvssVector -match 'UI:R') { $hints.Add('UI:R -> Review user interaction telemetry (email clicks, browser activity).') }
    if ($CvssVector -match 'AC:H') { $hints.Add('AC:H -> Look for multi-stage exploit chain activity.') }

    if ($hints.Count -eq 0) {
        $hints.Add('CVSS vector present but no mapped components matched; review vector manually.')
    }

    return $hints
}

# =========================
# HUNT PRIORITY
# =========================
function Get-HuntPriorityFromValues {
    param(
        [Parameter(Mandatory = $true)][bool]$IsKev,
        [Parameter(Mandatory = $false)][Nullable[double]]$EpssPercentile
    )

    if ($IsKev) { return 'High' }

    if ($null -ne $EpssPercentile) {
        if ($EpssPercentile -gt 0.99) { return 'High' }
        elseif ($EpssPercentile -gt 0.5) { return 'Medium' }
    }

    return 'Standard'
}

function Get-HuntPriorityFromGuidance {
    param([hashtable]$Guidance)

    $kev        = $Guidance.Kev.IsKev
    $epssPct    = [double]$Guidance.Epss.Percentile
    $tech       = $Guidance.AttackTechniqueId
    $confidence = $Guidance.AttackTechniqueConfidence

    # =========================
    # ATT&CK severity weighting
    # =========================
    $techWeight = switch ($tech) {
        'T1203'     { 100 }  # RCE
        'T1059.004' { 95 }   # Command Injection
        'T1059.001' { 90 }   # SQL Injection
        'T1190'     { 85 }   # Exploit Public-Facing Application
        'T1006'     { 80 }   # Path Traversal
        'T1557'     { 70 }   # MITM
        'T1068'     { 65 }   # PrivEsc
        'T1552'     { 60 }   # Credential Exposure
        default     { 40 }   # Everything else
    }

    # =========================
    # Confidence weighting
    # =========================
    $confWeight = switch ($confidence) {
        'High'   { 1.0 }
        'Medium' { 0.7 }
        'Low'    { 0.4 }
        default  { 0.4 }
    }

    # =========================
    # KEV weighting
    # =========================
    $kevWeight = if ($kev) { 1.0 } else { 0.0 }

    # =========================
    # EPSS weighting
    # =========================
    $epssWeight = if ($epssPct -ge 0.90) { 1.0 }
                  elseif ($epssPct -ge 0.70) { 0.7 }
                  elseif ($epssPct -ge 0.50) { 0.5 }
                  else { 0.2 }

    # =========================
    # Final score
    # =========================
    $score = ($techWeight * $confWeight) +
             ($kevWeight * 50) +
             ($epssWeight * 40)

    # =========================
    # Priority classification
    # =========================
    if ($score -ge 120) {
        return 'High'
    }
    elseif ($score -ge 80) {
        return 'Medium'
    }
    else {
        return 'Low'
    }
}

# =========================
# GUIDANCE OBJECT BUILDER
# =========================
function New-HuntGuidanceObject {
    param(
        [Parameter(Mandatory = $true)][string]$CveId,
        [Parameter(Mandatory = $true)][hashtable]$NvdData,
        [Parameter(Mandatory = $true)][hashtable]$KevData,
        [Parameter(Mandatory = $true)][hashtable]$EpssData,
        [Parameter(Mandatory = $true)]$HuntProfile,
        [Parameter(Mandatory = $true)]$TelemetryHints,
        [Parameter(Mandatory = $true)][string]$Priority
    )

    $vendorFinal  = if ($NvdData.VendorNvd)  { $NvdData.VendorNvd }  else { 'Unknown' }
    $productFinal = if ($NvdData.ProductNvd) { $NvdData.ProductNvd } else { 'Unknown' }

    # Resolve ATT&CK + pivots
    $attack = Resolve-AttackFromCwe -CweId $NvdData.Cwe
    $pivots = Get-DetectionPivotsForTechnique -TechniqueId $attack.TechniqueId

    # Build the object FIRST
    $guidance = [ordered]@{
        CveId        = $CveId
        GeneratedUtc = (Get-Date).ToUniversalTime().ToString('o')

        VendorProduct = [ordered]@{
            Vendor  = $vendorFinal
            Product = $productFinal
        }

        Nvd = [ordered]@{
            Description  = $NvdData.Description
            CvssVector   = $NvdData.CvssVector
            CvssScore    = $NvdData.CvssScore
            CvssVersion  = $NvdData.CvssVersion
            Cwe          = $NvdData.Cwe
            Url          = $NvdData.NvdUrl
        }

        Kev = [ordered]@{
            IsKev     = $KevData.IsKev
            DateAdded = $KevData.DateAdded
            DueDate   = $KevData.DueDate
            Url       = $KevData.KevUrl
        }

        Epss = [ordered]@{
            Score      = $EpssData.EpssScore
            Percentile = $EpssData.EpssPercentile
            Url        = $EpssData.EpssUrl
        }

        AttackTechniqueId         = $attack.TechniqueId
        AttackTechniqueName       = $attack.TechniqueName
        AttackTechniqueConfidence = $attack.AttackTechniqueConfidence

        DetectionPivots           = $pivots

        HuntLogSources      = $HuntProfile.LogSources
        HuntIndicators      = $HuntProfile.Indicators
        HuntQueryIdeas      = $HuntProfile.QueryIdeas
        TelemetryHints      = $TelemetryHints
    }

    # ⭐ ADD PRIORITY HERE ⭐
    $guidance.HuntPriority = Get-HuntPriorityFromGuidance -Guidance $guidance

    return $guidance
}

function New-PersonaOutput {
    param(
        [Parameter(Mandatory = $true)][hashtable]$Guidance,
        [Parameter(Mandatory = $true)][string]$Persona
    )

    switch ($Persona.ToLower()) {

        # =========================
        # Analyst Persona
        # =========================
        'analyst' {
            return @"
=== Analyst Summary ===
CVE: $($Guidance.CveId)
CWE: $($Guidance.Nvd.Cwe)
ATT&CK: $($Guidance.AttackTechniqueId) — $($Guidance.AttackTechniqueName)
Confidence: $($Guidance.AttackTechniqueConfidence)

Description:
$($Guidance.Nvd.Description)

Detection Pivots:
$( $Guidance.DetectionPivots | ForEach-Object { " - $_" } )

EPSS: $($Guidance.Epss.Score) (Percentile: $($Guidance.Epss.Percentile))
KEV: $(if ($Guidance.Kev.IsKev) { "Yes — Due: $($Guidance.Kev.DueDate)" } else { "No" })

Recommended Log Sources:
$( $Guidance.HuntLogSources | ForEach-Object { " - $_" } )

Indicators:
$( $Guidance.HuntIndicators | ForEach-Object { " - $_" } )

Query Ideas:
$( $Guidance.HuntQueryIdeas | ForEach-Object { " - $_" } )

Priority: $($Guidance.HuntPriority)
"@
        }

        # =========================
        # SOC Persona
        # =========================
        'soc' {
            return @"
=== SOC Summary ===
CVE: $($Guidance.CveId)
ATT&CK: $($Guidance.AttackTechniqueId) — $($Guidance.AttackTechniqueName)
Confidence: $($Guidance.AttackTechniqueConfidence)

Immediate Actions:
$( $Guidance.DetectionPivots | ForEach-Object { " - $_" } )

Key Telemetry:
$( $Guidance.TelemetryHints | ForEach-Object { " - $_" } )

KEV Status: $(if ($Guidance.Kev.IsKev) { "Yes — Patch by $($Guidance.Kev.DueDate)" } else { "No" })
Priority: $($Guidance.HuntPriority)
"@
        }

        # =========================
        # Manager Persona
        # =========================
        'manager' {
            return @"
=== Executive Summary ===
CVE: $($Guidance.CveId)
Vendor/Product: $($Guidance.VendorProduct.Vendor) / $($Guidance.VendorProduct.Product)

Risk:
ATT&CK Technique: $($Guidance.AttackTechniqueId) — $($Guidance.AttackTechniqueName)
Confidence: $($Guidance.AttackTechniqueConfidence)

KEV: $(if ($Guidance.Kev.IsKev) { "Yes — Deadline: $($Guidance.Kev.DueDate)" } else { "No" })
EPSS: $($Guidance.Epss.Score) (Percentile: $($Guidance.Epss.Percentile))

Recommended Priority: $($Guidance.HuntPriority)

Key Points:
$( $Guidance.DetectionPivots | ForEach-Object { " - $_" } )
"@
        }

        default {
            return "Unknown persona: $Persona"
        }
    }
}

# =========================
# TEXT FORMATTER (STRUCTURED)
# =========================
function Format-AsText {
    param([Parameter(Mandatory = $true)]$Guidance)

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('================================================================')
    [void]$sb.AppendLine("HUNT GUIDANCE - $($Guidance.CveId)")
    [void]$sb.AppendLine('================================================================')
    [void]$sb.AppendLine("Generated (UTC): $($Guidance.GeneratedUtc)")
    [void]$sb.AppendLine("Vendor/Product : $($Guidance.VendorProduct.Vendor) / $($Guidance.VendorProduct.Product)")
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine("Hunt Priority : $($Guidance.HuntPriority)")
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('--- NVD Summary ---')
    [void]$sb.AppendLine("Description : $($Guidance.Nvd.Description)")
    [void]$sb.AppendLine("CVSS : $($Guidance.Nvd.CvssScore) (v$($Guidance.Nvd.CvssVersion)) - $($Guidance.Nvd.CvssVector)")
    [void]$sb.AppendLine("CWE : $($Guidance.Nvd.Cwe)")
    [void]$sb.AppendLine("NVD URL : $($Guidance.Nvd.Url)")
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('--- CISA KEV ---')
    [void]$sb.AppendLine("Listed : $($Guidance.Kev.IsKev)")
    if ($Guidance.Kev.IsKev) {
        [void]$sb.AppendLine("Date Added : $($Guidance.Kev.DateAdded)")
        [void]$sb.AppendLine("Due Date : $($Guidance.Kev.DueDate)")
    }
    [void]$sb.AppendLine("KEV URL : $($Guidance.Kev.Url)")
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('--- EPSS ---')
    [void]$sb.AppendLine("Score : $($Guidance.Epss.Score)")
    [void]$sb.AppendLine("Percentile : $($Guidance.Epss.Percentile)")
    [void]$sb.AppendLine("EPSS URL : $($Guidance.Epss.Url)")
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('--- ATT&CK Mapping ---')
    [void]$sb.AppendLine("Technique : $($Guidance.AttackTechniqueId) - $($Guidance.AttackTechniqueName)")
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('--- Hunt Log Sources ---')
    foreach ($ls in $Guidance.HuntLogSources) { [void]$sb.AppendLine(" - $ls") }
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('--- Hunt Indicators ---')
    foreach ($ind in $Guidance.HuntIndicators) { [void]$sb.AppendLine(" - $ind") }
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('--- Hunt Query Ideas ---')
    foreach ($q in $Guidance.HuntQueryIdeas) { [void]$sb.AppendLine(" - $q") }
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('--- Telemetry Hints (from CVSS vector) ---')
    foreach ($th in $Guidance.TelemetryHints) { [void]$sb.AppendLine(" - $th") }
    [void]$sb.AppendLine('================================================================')
    return $sb.ToString()
}

# =========================
# JSON FORMATTER
# =========================
function Format-AsJson {
    param([Parameter(Mandatory = $true)]$Guidance)
    return ($Guidance | ConvertTo-Json -Depth 10)
}

# =========================
# SENTINEL FORMATTER
# =========================
function Format-AsSentinel {
    param([Parameter(Mandatory = $true)]$Guidance)

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine("// Sentinel KQL hunt query stub for $($Guidance.CveId)")
    [void]$sb.AppendLine("// ATT&CK Technique: $($Guidance.AttackTechniqueId) - $($Guidance.AttackTechniqueName)")
    [void]$sb.AppendLine("// Hunt Priority: $($Guidance.HuntPriority)")
    [void]$sb.AppendLine("// Suggested log sources:")
    foreach ($ls in $Guidance.HuntLogSources) { [void]$sb.AppendLine("// - $ls") }
    [void]$sb.AppendLine("// Example stub (replace TableName and fields with your environment schema):")
    [void]$sb.AppendLine('TableName')
    [void]$sb.AppendLine('| where TimeGenerated > ago(7d)')
    [void]$sb.AppendLine('| where * has "REPLACE_WITH_INDICATOR"')
    [void]$sb.AppendLine('| project TimeGenerated, Computer, EventDetails')
    return $sb.ToString()
}

# =========================
# SPLUNK FORMATTER
# =========================
function Format-AsSplunk {
    param([Parameter(Mandatory = $true)]$Guidance)

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine("Splunk SPL hunt query stub for $($Guidance.CveId)")
    [void]$sb.AppendLine("ATT&CK Technique: $($Guidance.AttackTechniqueId) - $($Guidance.AttackTechniqueName)")
    [void]$sb.AppendLine("Hunt Priority: $($Guidance.HuntPriority)")
    [void]$sb.AppendLine("Suggested log sources:")
    foreach ($ls in $Guidance.HuntLogSources) { [void]$sb.AppendLine(" - $ls") }
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("Example stub (replace index/sourcetype and fields):")
    [void]$sb.AppendLine("index=REPLACE_ME sourcetype=REPLACE_ME")
    [void]$sb.AppendLine('| search "REPLACE_WITH_INDICATOR"')
    [void]$sb.AppendLine("| table _time, host, event_details")
    return $sb.ToString()
}

# =========================
# ELASTIC FORMATTER
# =========================
function Format-AsElastic {
    param([Parameter(Mandatory = $true)]$Guidance)

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine("// Elastic EQL hunt query stub for $($Guidance.CveId)")
    [void]$sb.AppendLine("// ATT&CK Technique: $($Guidance.AttackTechniqueId) - $($Guidance.AttackTechniqueName)")
    [void]$sb.AppendLine("// Hunt Priority: $($Guidance.HuntPriority)")
    [void]$sb.AppendLine("// Suggested log sources:")
    foreach ($ls in $Guidance.HuntLogSources) { [void]$sb.AppendLine("// - $ls") }
    [void]$sb.AppendLine('// Example stub (replace event.category and fields with your environment schema):')
    [void]$sb.AppendLine('any where event.category == "REPLACE_ME" and')
    [void]$sb.AppendLine(' REPLACE_WITH_FIELD == "REPLACE_WITH_INDICATOR"')
    return $sb.ToString()
}

# =========================
# PERSONA SECTION HELPERS
# =========================
function Write-SectionTitle {
    param([string]$Title)
    Write-Host ""
    Write-Host "=== $Title ===" -ForegroundColor Yellow
}

function Write-SummaryPersona {
    param($Guidance, [string]$Mode)

    Write-SectionTitle "Summary"

    if ($Mode -eq "Manager") {
        Write-Host ("{0} affects {1} and may enable unauthorized access to exposed services." -f $Guidance.CveId, $Guidance.VendorProduct.Product)
    } else {
        Write-Host $Guidance.Nvd.Description
        Write-Host ("Affected product: {0}" -f $Guidance.VendorProduct.Product)
    }
}

function Write-AttackMappingPersona {
    param($Guidance, [string]$Mode)

    if ($Mode -eq "Manager") { return }

    Write-SectionTitle "ATT&CK Mapping"
    Write-Host ("Technique: {0} - {1}" -f $Guidance.AttackTechniqueId, $Guidance.AttackTechniqueName)

    if ($Mode -eq "Beginner") {
        Write-Host ""
        Write-Host "Explanation:"
        Write-Host "This technique applies because the weakness allows attackers to interact"
        Write-Host "with the affected component in ways the system did not intend."
    }
}

function Write-LogSourcesPersona {
    param($Guidance, [string]$Mode)

    if ($Mode -eq "Manager") { return }

    Write-SectionTitle "Relevant Log Sources"

    if ($null -eq $Guidance.HuntLogSources -or $Guidance.HuntLogSources.Count -eq 0) {
        Write-Host "No log source recommendations available."
        return
    }

    if ($Mode -eq "Beginner") {
        $Guidance.HuntLogSources | Select-Object -First 2 | ForEach-Object {
            Write-Host ("• {0}" -f $_)
        }
        Write-Host ""
        Write-Host "Explanation:"
        Write-Host "Start with the most visible logs (web and application) before diving into"
        Write-Host "more advanced telemetry like EDR or Sysmon."
    } else {
        $Guidance.HuntLogSources | ForEach-Object { Write-Host ("• {0}" -f $_) }
    }
}

function Write-DetectionIdeasPersona {
    param($Guidance, [string]$Mode)

    if ($Mode -eq "Manager") { return }

    Write-SectionTitle "Detection Ideas"

    if ($null -eq $Guidance.HuntIndicators -or $Guidance.HuntIndicators.Count -eq 0) {
        Write-Host "No detection ideas available."
        return
    }

    if ($Mode -eq "Beginner") {
        $Guidance.HuntIndicators | Select-Object -First 2 | ForEach-Object {
            Write-Host ("• {0}" -f $_)
        }
        Write-Host ""
        Write-Host "Tip:"
        Write-Host "Focus first on obvious anomalies (error spikes, repeated bad requests) before"
        Write-Host "building more complex behavioral detections."
    } else {
        $Guidance.HuntIndicators | ForEach-Object { Write-Host ("• {0}" -f $_) }
    }

    if ($Mode -eq "Soc") {
        Write-Host ""
        Write-Host "SIEM Query Ideas:"
        $Guidance.HuntQueryIdeas | ForEach-Object { Write-Host ("• {0}" -f $_) }
    }
}

function Write-ExploitationContextPersona {
    param($Guidance)

    Write-SectionTitle "Exploitation Context"
    Write-Host ("KEV Status: {0}" -f $Guidance.Kev.IsKev)
    Write-Host ("EPSS Likelihood: {0}" -f $Guidance.Epss.Score)
    Write-Host ("EPSS Percentile: {0}" -f $Guidance.Epss.Percentile)
}

function Write-WhyThisMattersPersona {
    param($Guidance, [string]$Mode)

    Write-SectionTitle "Why This Matters"

    if ($Mode -eq "Manager") {
        Write-Host "Externally-facing weaknesses with confirmed exploitation tend to drive incident volume"
        Write-Host "and can lead to business disruption if left unaddressed."
    } else {
        Write-Host "Weaknesses in externally-facing components tend to cascade into"
        Write-Host "privilege escalation paths over time. Even low exploitation today"
        Write-Host "can become high-impact tomorrow."
    }
}

function Write-NextStepsPersona {
    param([string]$Mode)

    Write-SectionTitle "Recommended Next Steps"

    if ($Mode -eq "Manager") {
        Write-Host "• Confirm patch status and compensating controls."
        Write-Host "• Align remediation priority with business impact."
        Write-Host "• Ensure monitoring is in place for key services."
    } else {
        Write-Host "• Validate log source availability."
        Write-Host "• Add ATT&CK technique to detection backlog."
        Write-Host "• Review vendor advisories for patches or mitigations."
        Write-Host "• Monitor exploitation signals."
    }
}

function Write-InsightPersona {
    param($Guidance)

    Write-SectionTitle "Insight"
    Write-Host "Systems rarely fail at the point of vulnerability; they fail at the"
    Write-Host "intersection of timing, exposure, and neglect. This CVE touches all three."
}

# =========================
# MAIN
# =========================
try {
    Write-Verbose "Retrieving NVD data for $Cve..."
    $nvdData = Get-NvdData -CveId $Cve

    Write-Verbose "Checking CISA KEV status for $Cve..."
    $kevData = Get-KevStatus -CveId $Cve

    Write-Verbose "Retrieving EPSS data for $Cve..."
    $epssData = Get-EpssData -CveId $Cve

    if (-not $nvdData.RetrievedOk) {
        Write-Warning "NVD lookup failed for $Cve. Generating minimal hunt guidance."
        $huntProfile    = Get-HuntProfile -Cwe $null
        $telemetryHints = @('No CVSS vector available; review NVD manually for telemetry context.')
        $priority       = Get-HuntPriorityFromValues -IsKev $kevData.IsKev -EpssPercentile $epssData.EpssPercentile
    }
    else {
        Write-Verbose "Mapping CWE to ATT&CK/Hunt Profile..."
        $huntProfile    = Get-HuntProfile -Cwe $nvdData.Cwe
        Write-Verbose "Deriving telemetry hints from CVSS vector..."
        $telemetryHints = Get-TelemetryHints -CvssVector $nvdData.CvssVector
        Write-Verbose "Determining hunt priority..."
        $priority       = Get-HuntPriorityFromValues -IsKev $kevData.IsKev -EpssPercentile $epssData.EpssPercentile
    }

    $guidance = New-HuntGuidanceObject -CveId $Cve `
        -NvdData $nvdData `
        -KevData $kevData `
        -EpssData $epssData `
        -HuntProfile $huntProfile `
        -TelemetryHints $telemetryHints `
        -Priority $priority

    # Persona mode
    $mode = "Analyst"
    if ($Manager) {
        $mode = "Manager"
    } elseif ($Soc) {
        $mode = "Soc"
    } elseif ($Beginner) {
        $mode = "Beginner"
    } elseif ($Analyst) {
        $mode = "Analyst"
    }

    # Format selection
    $output = $null

    if ($Format -eq 'Text') {
        Show-Header
        Write-Host ("Hunt Guidance Report: {0}" -f $guidance.CveId) -ForegroundColor Cyan
        Write-Host ""

        Write-SummaryPersona          -Guidance $guidance -Mode $mode
        Write-AttackMappingPersona    -Guidance $guidance -Mode $mode
        Write-LogSourcesPersona       -Guidance $guidance -Mode $mode
        Write-DetectionIdeasPersona   -Guidance $guidance -Mode $mode
        Write-ExploitationContextPersona -Guidance $guidance
        Write-WhyThisMattersPersona   -Guidance $guidance -Mode $mode
        Write-NextStepsPersona        -Mode $mode

        if ($Insight) {
            Write-InsightPersona -Guidance $guidance
        }

        Write-Host ""
        Write-Host "Done." -ForegroundColor Green

        # Also build structured text for pipelines if needed
        $output = Format-AsText -Guidance $guidance
    }
    elseif ($Format -eq 'Json') {
        $output = Format-AsJson -Guidance $guidance
    }
    elseif ($Format -eq 'Sentinel') {
        $output = Format-AsSentinel -Guidance $guidance
    }
    elseif ($Format -eq 'Splunk') {
        $output = Format-AsSplunk -Guidance $guidance
    }
    elseif ($Format -eq 'Elastic') {
        $output = Format-AsElastic -Guidance $guidance
    }
    else {
        $output = Format-AsText -Guidance $guidance
    }

    if (-not [string]::IsNullOrWhiteSpace($OutFile)) {
        try {
            $output | Out-File -FilePath $OutFile -Encoding utf8 -Force -ErrorAction Stop
            Write-Host "Hunt guidance written to $OutFile"
        }
        catch {
            Write-Error "Failed to write output to $OutFile : $($_.Exception.Message)"
            Write-Output $output
        }
    }
    else {
        if ($Format -ne 'Text') {
            Write-Output $output
        }
    }
}
catch {
    Write-Error "Script B v3 encountered an unrecoverable error: $($_.Exception.Message)"
    Show-Usage
    exit 1
}