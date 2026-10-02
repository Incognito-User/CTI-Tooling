<#
    CTI CVE Enrichment Script (v2.4 - CVSSv4-aware, Tech Stack-aware, Exploit-intel-aware)
    ---------------------------------------------------------------------
    Changes in v2.4
    ---------------
      - NEW  Get-ExploitIntel: Metasploit exploit-module and Exploit-DB presence flags (plus NVD "Exploit"-tagged
             references). Presence indicators only; no exploit content is fetched or stored. Sources may be a URL
             or a local file (-MetasploitMetadata / -ExploitDbCsv) for restricted networks; -SkipExploitIntel disables.
             If a source is unreachable the run continues and Missing_Exploit_Intel is set (absence is NOT evidence).
      - FIX  Exploit-DB / Metasploit were an if/elseif in scoring, so a CVE with both scored as PoC (0.5), not 1.0.
      - NEW  Script B contract columns: KevListed, ExploitedInWild, PublicExploit, InternetFacing (from Exposure),
             SectorRelevance (placeholder), plus Exposure / Business_Criticality / Prereq_Complexity /
             Used_Default_Asset_Context so the inputs behind the priority tier are visible.
      - FIX  Tech stack accepts a flat list or a categorized object; version-aware entries ("apache 2.4");
             regex-escaped; never uses $matches.
      - CHG  -DebugNvd prints the raw NVD response. CVSS v4 Safety no longer adds to exploitability (impact metric).
             Missing_KEV removed (was always False).
      - NOTE Requires no PowerShell 7-only syntax; tested on 7.4 only.

    Changes in v2.3 (debug pass)
    ---------------------------
      - FIX  Export-Excel has no -WorksheetOrder parameter; the run always failed at the Errors/Summary sheet.
      - FIX  $matches is a PowerShell automatic variable; CVEs matching the tech stack were dropped to the Errors sheet.
      - FIX  Tech-stack check read Vendor_Product (never existed) and matched blank entries / substrings (Java vs JavaScript).
      - FIX  -OverwriteOutput deleted the old workbook before inputs were validated or data collected.
      - FIX  NVD description now prefers English; CPE selection prefers vulnerable=true; CWE prefers real CWE IDs.
      - FIX  Retry logic: NVD 403 rate-limit treated as retryable, Retry-After honored, failures distinguished from "not found".
      - FIX  Exploitability sub-score normalized per CVSS version (v3.x max is 3.9, not 10).
      - FIX  Business-criticality override now uses the same Critical/High rule as the priority tier.
      - FIX  Missing_CVSS / Missing_EPSS no longer treat a null as 0; per-CVE log now records real errors.
      - CHG  ATT&CK mapping reworked (vector-first, confidence + basis, separate ID/name/tactic fields).
      - NEW  KEV date added / due date / ransomware use, EPSS date, CPE, Missing_Exploit_Intel, rating column,
             expanded CTI_Summary distributions.
      - NOTE ExploitDB / Metasploit intel is NOT integrated; the 0.2 exploit-availability weight is always 0.

    Purpose:
      - Enrich CVE IDs with:
            - NVD (CVSS v4 preferred, fallback to v3.1 -> v3.0 -> v2, CWE, description, product)
            - CISA KEV
            - EPSS
            - Vendor advisories (stub)
            - MITRE ATT&CK heuristic mapping
      - Compute:
            - Exploitability Composite Score (with CVSSv4 weighting)
            - Remediation Priority (Zero Tolerance, P1-P5)
      - Incorporate:
            - Asset context (exposure, prereq complexity, business criticality)
            - Tech stack relevance (from TechStack.json)
      - Output:
            - Excel workbook with:
                - Main enrichment sheet
                - Error sheet
                - CTI summary sheet (rollups, distributions)
            - Per-CVE JSON logs (optional, for Script B / Script C)

    Usage Examples
    --------------

    Single-CVE mode:
        .\CTI-CVE-EnrichmentEnginev2.ps1 `
            -SingleCve "CVE-2024-12345" `
            -OutputXlsxFile ".\CVE_Enriched_Single.xlsx" `
            -NvdApiKey "YOUR_NVD_API_KEY" `
            -TechStackFile ".\TechStack.json"

    Bulk mode (TXT file with one CVE per line):
        .\CTI-CVE-EnrichmentEnginev2.ps1 `
            -InputCveFile ".\cves.txt" `
            -OutputXlsxFile ".\CVE_Enriched_Bulk.xlsx" `
            -NvdApiKey "YOUR_NVD_API_KEY" `
            -AssetContextCsv ".\asset_context.csv" `
            -TechStackFile ".\TechStack.json"

    Optional switches:
        -AssetContextCsv ".\asset_context.csv"   (CveId,Exposure,PrereqComplexity,BusinessCriticality)
        -OverwriteOutput                          (replace an existing output file)
        -WritePerCveJson                          (emit per-CVE JSON for Script B/C)
#>

[CmdletBinding()]
param(
    [Parameter(ParameterSetName = 'Single', Mandatory = $true)]
    [string]$SingleCve,

    [Parameter(ParameterSetName = 'Bulk', Mandatory = $true)]
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string]$InputCveFile,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('\.xlsx$')]
    [string]$OutputXlsxFile,

    [Parameter(Mandatory = $false)]
    [string]$NvdApiKey = $env:NVD_API_KEY,

    [Parameter(Mandatory = $false)]
    [double]$NvdRequestDelaySeconds = $(if ($NvdApiKey) { 0.65 } else { 6.5 }),

    [Parameter(Mandatory = $false)]
    [int]$MaxRetries = 3,

    [Parameter(Mandatory = $false)]
    [string]$AssetContextCsv,

    [Parameter(Mandatory = $false)]
    [string]$TechStackFile,

    [Parameter(Mandatory = $false)]
    [switch]$OverwriteOutput,

    [Parameter(Mandatory = $false)]
    [switch]$WritePerCveJson,

    [Parameter(Mandatory = $false)]
    [switch]$DebugNvd,

    # URL or local file path. Metasploit's public module metadata (exploit modules only are indexed).
    [Parameter(Mandatory = $false)]
    [string]$MetasploitMetadata = 'https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json',

    # URL or local file path to Exploit-DB files_exploits.csv. Default is the canonical GitLab location (not
    # verifiable from the build sandbox); the old GitHub mirror is archived/stale. Use a local copy if blocked.
    [Parameter(Mandatory = $false)]
    [string]$ExploitDbCsv = 'https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv',

    [Parameter(Mandatory = $false)]
    [switch]$SkipExploitIntel
)

$ErrorActionPreference = 'Stop'

$SchemaVersion = "2.4.0"
$ScriptVersion = "2.4.0"

$Config = @{
    NvdDelay                   = $NvdRequestDelaySeconds
    MaxRetries                 = $MaxRetries
    BatchSize                  = 100
    DefaultExposure            = "Internet-facing"
    DefaultPrereqComplexity    = "Low"
    DefaultBusinessCriticality = "Critical"
}

Import-Module ImportExcel -ErrorAction Stop

# Absolute path: Export-Excel resolves relative paths against the process directory, not the PowerShell location.
$OutputXlsxFile = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputXlsxFile)

Write-Host "CTI CVE Enrichment v$ScriptVersion (schema $SchemaVersion) | Priority matrix: Zero Tolerance, P1-P5 | Running: $($MyInvocation.MyCommand.Path)"

# Fail fast if the output exists, but delete nothing until the replacement workbook is fully built (see EXPORT).
if ((Test-Path -LiteralPath $OutputXlsxFile) -and -not $OverwriteOutput) {
    throw "Output file already exists: $OutputXlsxFile. Use a new filename or add -OverwriteOutput."
}

if (-not $NvdApiKey) {
    Write-Warning "No NVD API key supplied (param or `$env:NVD_API_KEY). Continuing unauthenticated at 5 req/30s -- this will be slow for large CVE lists."
}

#region MODE SELECTION

$cveList = @()

if ($SingleCve) {
    $SingleCve = $SingleCve.Trim().ToUpper()
    if ($SingleCve -notmatch "^CVE-\d{4}-\d{4,}$") {
        throw "Invalid CVE format for -SingleCve. Expected CVE-YYYY-NNNN."
    }
    $cveList = @($SingleCve)
}
elseif ($InputCveFile) {
    $rawLines = @(Get-Content -Path $InputCveFile | ForEach-Object { $_.Trim().ToUpper() } | Where-Object { $_ -ne "" })
    $cveList  = @($rawLines | Where-Object { $_ -match "^CVE-\d{4}-\d{4,}$" } | Select-Object -Unique)
    $skipped  = @($rawLines | Where-Object { $_ -notmatch "^CVE-\d{4}-\d{4,}$" })
    if ($skipped.Count -gt 0) {
        Write-Warning ("Skipped {0} line(s) that are not valid CVE IDs: {1}{2}" -f $skipped.Count, (($skipped | Select-Object -First 5) -join ", "), $(if ($skipped.Count -gt 5) { " ..." } else { "" }))
    }
}
else {
    throw "You must provide either -SingleCve or -InputCveFile."
}

if (-not $cveList -or $cveList.Count -eq 0) {
    throw "No valid CVE IDs found. Ensure format is CVE-YYYY-NNNN."
}

Write-Host "Loaded $($cveList.Count) unique CVE(s). Building KEV, EPSS, and Tech Stack indexes..."

#endregion MODE SELECTION

#region CORE HELPERS

function Invoke-HttpGetWithRetry {
    # Returns the response body, or THROWS after the final attempt (callers decide whether that is fatal).
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Uri,
        [hashtable]$Headers,
        [int]$MaxRetries = 3,
        [int]$TimeoutSec = 30
    )

    $isNvd      = $Uri -match '^https://services\.nvd\.nist\.gov/'
    $retryable  = @(429, 500, 502, 503, 504)
    if ($isNvd) { $retryable += 403 }          # NVD has been observed to answer 403 when rate-limited (verify against current NVD docs)
    $baseDelay  = if ($isNvd) { 6 } else { 2 } # NVD rate windows are 30s; a 2s backoff is too short

    for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
        try {
            $params = @{ Uri = $Uri; Method = 'Get'; TimeoutSec = $TimeoutSec }
            if ($Headers -and $Headers.Count -gt 0) { $params['Headers'] = $Headers }
            return Invoke-RestMethod @params
        }
        catch {
            $status = $null
            try { if ($_.Exception.Response -and $_.Exception.Response.StatusCode) { $status = [int]$_.Exception.Response.StatusCode } } catch { }

            $isTransient = ($null -eq $status) -or ($status -in $retryable)
            if ($attempt -eq $MaxRetries -or -not $isTransient) {
                throw "HTTP request failed after $attempt attempt(s) (status: $status): $Uri -- $($_.Exception.Message)"
            }

            $backoff = $baseDelay * [math]::Pow(2, $attempt - 1)
            try {   # PowerShell 7 only; harmless no-op on 5.1
                $ra = $_.Exception.Response.Headers.RetryAfter.Delta.TotalSeconds
                if ($ra) { $backoff = [math]::Max($backoff, $ra) }
            } catch { }
            Write-Verbose "Transient error ($status) on $Uri -- retrying in $backoff s"
            Start-Sleep -Seconds $backoff
        }
    }
}

function New-EnrichmentErrorObject {
    [CmdletBinding()]
    param(
        [string]$CveId,
        [string]$Source,
        [string]$Reason,
        [bool]$IsTransient = $false,
        [int]$RetryCount = 0
    )

    [pscustomobject]@{
        CveId       = $CveId
        Source      = $Source
        Reason      = $Reason
        IsTransient = $IsTransient
        RetryCount  = $RetryCount
        Timestamp   = (Get-Date).ToString("o")
    }
}

function Get-AssetContextIndex {
    [CmdletBinding()]
    param([string]$CsvPath)

    $index = @{}
    if (-not $CsvPath) { return $index }
    if (-not (Test-Path -LiteralPath $CsvPath)) {
        throw "Asset context CSV not found: $CsvPath (without it every CVE falls back to worst-case defaults)."
    }

    $rows = @(Import-Csv -LiteralPath $CsvPath)
    if ($rows.Count -gt 0 -and ($rows[0].PSObject.Properties.Name -notcontains 'CveId')) {
        throw "Asset context CSV must have a 'CveId' column (CveId,Exposure,PrereqComplexity,BusinessCriticality)."
    }

    foreach ($r in $rows) {
        $key = "$($r.CveId)".Trim().ToUpper()
        if (-not $key) { continue }
        if ($index.ContainsKey($key)) { Write-Warning "Asset context CSV: duplicate row for $key; last one wins." }
        $index[$key] = [pscustomobject]@{
            Exposure            = $r.Exposure
            PrereqComplexity    = $r.PrereqComplexity
            BusinessCriticality = $r.BusinessCriticality
        }
    }
    $index
}

#endregion CORE HELPERS

#region TECH STACK MODULE

function Get-TechStack {
    param([string]$Path)

    if (-not $Path) {
        Write-Host "No tech stack file provided. RelevantToOrg will be False for every CVE." -ForegroundColor Yellow
        return $null
    }
    if (-not (Test-Path -LiteralPath $Path)) {
        Write-Warning "Tech stack file not found: $Path. RelevantToOrg will be False for every CVE."
        return $null
    }

    try {
        return (Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json)
    }
    catch {
        Write-Warning "Failed to parse tech stack file ($Path): $($_.Exception.Message). RelevantToOrg will be False for every CVE."
        return $null
    }
}

function ConvertTo-TechStackList {
    # Accepts a flat array ["Apache","Java"] or a categorized object {"WebServers":["Apache"]}; returns flat strings.
    param($TechStack)

    $list = New-Object System.Collections.Generic.List[string]
    $addValue = { param($v) $n = "$v".Trim(); if ($n) { $list.Add($n) } }
    $addObject = { param($o) foreach ($prop in $o.PSObject.Properties) { foreach ($x in @($prop.Value)) { & $addValue $x } } }

    if ($null -eq $TechStack) { return @() }
    if ($TechStack -is [string]) { & $addValue $TechStack }
    elseif ($TechStack -is [System.Management.Automation.PSCustomObject]) { & $addObject $TechStack }   # NOT [pscustomobject]: that alias is PSObject and is true for strings/arrays too
    else {
        foreach ($v in $TechStack) {
            if ($v -is [System.Management.Automation.PSCustomObject]) { & $addObject $v } else { & $addValue $v }
        }
    }
    return $list.ToArray()
}

function Test-TechStackRelevance {
    # NOTE: never name a variable $matches here; it is the automatic variable populated by -match.
    param(
        $CveData,
        $TechStack
    )

    $items = @(ConvertTo-TechStackList $TechStack)
    if ($items.Count -eq 0) { return @() }

    $desc      = "$($CveData.Description)"
    $cpe       = "$($CveData.CpeCriteria)"
    $haystacks = @($desc, ("$($CveData.VendorProduct)" -replace '[_:]', ' '), ($cpe -replace '[_:\*]', ' ')) |
                 Where-Object { $_.Trim() }
    if (-not $haystacks) { return @() }

    $cpeVersion = $null
    if ($cpe) { $cpeVersion = @($cpe -split ':')[5] }

    $found = New-Object System.Collections.Generic.List[string]

    foreach ($entry in $items) {
        # Optional trailing version: "apache 2.4" -> product "apache", version "2.4"
        $product = $entry; $version = $null
        if ($entry -match '^(?<prod>.+?)\s+v?(?<ver>\d[\w\.\-]*)$') { $product = $Matches['prod']; $version = $Matches['ver'] }

        $pattern = '(?<!\w)' + [regex]::Escape($product) + '(?!\w)'     # whole-word, regex-escaped ("C++", "Go")
        $hit = $false
        foreach ($h in $haystacks) { if ($h -match $pattern) { $hit = $true; break } }
        if (-not $hit) { continue }

        # Only a concrete, conflicting CPE version rules a version-qualified entry out. Ranges / "*" stay relevant.
        if ($version -and $cpeVersion -and $cpeVersion -notin @('*', '-')) {
            $compatible = ($cpeVersion -eq $version) -or $cpeVersion.StartsWith("$version.") -or $version.StartsWith("$cpeVersion.")
            if (-not $compatible) { continue }
        }

        if (-not $found.Contains($entry)) { $found.Add($entry) }
    }

    return $found.ToArray()   # caller wraps in @() so 0/1/n results all behave
}
#endregion TECH STACK MODULE

#region NVD MODULE (CVSSv4 preferred)
function Select-NvdMetric {
    [CmdletBinding()]
    param($Metrics)

    $arr = @($Metrics)
    $primary = $arr | Where-Object { $_.type -eq 'Primary' } | Select-Object -First 1
    if ($primary) { $primary } else { $arr[0] }
}

function Get-NvdData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$CveId,
        [Parameter()][string]$ApiKey
    )

    $uri     = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=$CveId"
    $headers = @{}
    if ($ApiKey) { $headers['apiKey'] = $ApiKey }

    $data = Invoke-HttpGetWithRetry -Uri $uri -Headers $headers -MaxRetries $Config.MaxRetries

    if ($DebugNvd) {
        Write-Host "NVD raw response for ${CveId}:" -ForegroundColor Cyan
        $data | ConvertTo-Json -Depth 10 | Write-Host
    }
    if (-not $data -or -not $data.vulnerabilities -or $data.vulnerabilities.Count -eq 0) {
        return $null
    }

    $item = $data.vulnerabilities[0].cve

    # Prefer the English description (descriptions[0] can be another language).
    $description = $null
    if ($item.descriptions) {
        $en = @($item.descriptions) | Where-Object { $_.lang -eq 'en' } | Select-Object -First 1
        $description = if ($en) { $en.value } else { @($item.descriptions)[0].value }
    }

    # Prefer a CPE flagged vulnerable=true (the first entry is often an OS / "running on" platform).
    $vendorProduct = $null
    $cpeCriteria   = $null
    if ($item.configurations) {
        $cpe = @($item.configurations) | ForEach-Object { $_.nodes } | ForEach-Object { $_.cpeMatch } |
               Where-Object { $_ -and $_.vulnerable } | Select-Object -First 1
        if (-not $cpe) {
            $cpe = @($item.configurations) | ForEach-Object { $_.nodes } | ForEach-Object { $_.cpeMatch } |
                   Where-Object { $_ } | Select-Object -First 1
        }
        if ($cpe -and $cpe.criteria) {
            $cpeCriteria = $cpe.criteria
            $parts = $cpeCriteria -split ':'
            if ($parts.Count -ge 5) { $vendorProduct = "$($parts[3]):$($parts[4])" } else { $vendorProduct = $cpeCriteria }
        }
    }

    $cvssMetric  = $null
    $cvssVersion = $null

    if ($item.metrics) {
        if ($item.metrics.cvssMetricV40) {
            $cvssMetric  = (Select-NvdMetric $item.metrics.cvssMetricV40)
            $cvssVersion = "4.0"
        }
        elseif ($item.metrics.cvssMetricV4) {
            $cvssMetric  = (Select-NvdMetric $item.metrics.cvssMetricV4)
            $cvssVersion = "4.0"
        }
        elseif ($item.metrics.cvssMetricV31) {
            $cvssMetric  = (Select-NvdMetric $item.metrics.cvssMetricV31)
            $cvssVersion = "3.1"
        }
        elseif ($item.metrics.cvssMetricV30) {
            $cvssMetric  = (Select-NvdMetric $item.metrics.cvssMetricV30)
            $cvssVersion = "3.0"
        }
        elseif ($item.metrics.cvssMetricV2) {
            $cvssMetric  = (Select-NvdMetric $item.metrics.cvssMetricV2)
            $cvssVersion = "2.0"
        }
    }

    $cvssScore   = $null
    $cvssVector  = $null
    $cvssSeverity = $null
    $cvssExploitabilitySubscore = $null

    $cvssV4_AT = $null
    $cvssV4_AU = $null
    $cvssV4_R  = $null
    $cvssV4_RE = $null
    $cvssV4_S  = $null

    if ($cvssMetric -and $cvssMetric.cvssData) {
        $cvssScore   = $cvssMetric.cvssData.baseScore
        $cvssVector  = $cvssMetric.cvssData.vectorString
        $cvssSeverity = $cvssMetric.cvssData.baseSeverity

        if ($cvssVersion -eq "4.0") {
            $cvssV4_AT = $cvssMetric.cvssData.attackRequirements
            $cvssV4_AU = $cvssMetric.cvssData.automatable
            $cvssV4_R  = $cvssMetric.cvssData.recovery
            $cvssV4_RE = if ($cvssMetric.cvssData.vulnerabilityResponseEffort) { $cvssMetric.cvssData.vulnerabilityResponseEffort } else { $cvssMetric.cvssData.response }
            $cvssV4_S  = $cvssMetric.cvssData.safety
        }
    }

    if ($cvssMetric -and $cvssMetric.exploitabilityScore) {
        $cvssExploitabilitySubscore = $cvssMetric.exploitabilityScore
    }

    # Prefer Primary-source weaknesses and real CWE IDs over NVD-CWE-Other / NVD-CWE-noinfo.
    $cwe = $null
    if ($item.weaknesses) {
        $weak = @(@($item.weaknesses) | Where-Object { $_.type -eq 'Primary' }) + @(@($item.weaknesses) | Where-Object { $_.type -ne 'Primary' })
        $vals = foreach ($w in $weak) { foreach ($d in @($w.description)) { if ($d -and $d.value) { $d.value } } }
        $cwe  = @($vals | Where-Object { $_ -match '^CWE-\d+$' } | Select-Object -First 1)[0]
        if (-not $cwe) { $cwe = @($vals | Select-Object -First 1)[0] }
    }

    # Public-exploit signals already present in the NVD record (no extra network call).
    $exploitDbIds    = New-Object System.Collections.Generic.List[string]
    $exploitRefCount = 0
    foreach ($ref in @($item.references)) {
        if (-not $ref) { continue }
        if (@($ref.tags) -contains 'Exploit') { $exploitRefCount++ }
        if ("$($ref.url)" -match 'exploit-db\.com/(?:exploits|raw|download)/(\d+)') {
            if (-not $exploitDbIds.Contains($Matches[1])) { $exploitDbIds.Add($Matches[1]) }
        }
    }

    [pscustomobject]@{
        CveId                      = $CveId
        Description                = $description
        VendorProduct              = $vendorProduct
        CpeCriteria                = $cpeCriteria

        CvssVersion                = $cvssVersion
        CvssScore                  = $cvssScore
        CvssVector                 = $cvssVector
        CvssSeverity               = $cvssSeverity
        CvssExploitabilitySubscore = $cvssExploitabilitySubscore

        CvssV4_AT                  = $cvssV4_AT
        CvssV4_AU                  = $cvssV4_AU
        CvssV4_R                   = $cvssV4_R
        CvssV4_RE                  = $cvssV4_RE
        CvssV4_S                   = $cvssV4_S

        Cwe                        = $cwe
        NvdUrl                     = "https://nvd.nist.gov/vuln/detail/$CveId"
        ExploitRefCount            = $exploitRefCount
        ExploitDbRefIds            = $exploitDbIds.ToArray()
    }
}

#endregion NVD MODULE

#region KEV MODULE

function Get-KevIndex {
    [CmdletBinding()]
    param()

    $kevUri  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    $kevData = Invoke-HttpGetWithRetry -Uri $kevUri -MaxRetries $Config.MaxRetries

    $index = @{}
    if ($kevData -and $kevData.vulnerabilities) {
        foreach ($v in $kevData.vulnerabilities) {
            $index[$v.cveID] = $v
        }
    }
    $index
}

function Get-KevStatus {
    [CmdletBinding()]
    param(
        [string]$CveId,
        [hashtable]$KevIndex
    )

    if ($KevIndex.ContainsKey($CveId)) {
        $e = $KevIndex[$CveId]
        [pscustomobject]@{
            KevStatus        = "Yes"
            KevUrl           = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search=$CveId"
            KevDateAdded     = $e.dateAdded
            KevDueDate       = $e.dueDate                       # CISA due date (binding for US FCEB agencies; reference only elsewhere)
            KevRansomwareUse = $e.knownRansomwareCampaignUse    # Known / Unknown
        }
    }
    else {
        [pscustomobject]@{ KevStatus = "No"; KevUrl = $null; KevDateAdded = $null; KevDueDate = $null; KevRansomwareUse = $null }
    }
}

#endregion KEV MODULE

#region EPSS MODULE

function Get-EpssIndex {
    [CmdletBinding()]
    param(
        [string[]]$CveIds,
        [int]$BatchSize = 100
    )

    $index = @{}
    for ($i = 0; $i -lt $CveIds.Count; $i += $BatchSize) {
        $endIdx  = [math]::Min($i + $BatchSize - 1, $CveIds.Count - 1)
        $batch   = $CveIds[$i..$endIdx]
        $csv     = ($batch -join ",")
        $epssUri = "https://api.first.org/data/v1/epss?cve=$csv"
        try { $resp = Invoke-HttpGetWithRetry -Uri $epssUri -MaxRetries $Config.MaxRetries }
        catch { Write-Warning "EPSS batch starting at index $i failed: $($_.Exception.Message)"; continue }

        if ($resp -and $resp.data) {
            foreach ($entry in $resp.data) {
                $index[$entry.cve] = [pscustomobject]@{
                    EpssScore      = [double]$entry.epss
                    EpssPercentile = [double]$entry.percentile
                    EpssDate       = $entry.date
                    EpssUrl        = "https://www.first.org/epss/data?cve=$($entry.cve)"
                }
            }
        }
    }
    $index
}

function Get-EpssData {
    [CmdletBinding()]
    param(
        [string]$CveId,
        [hashtable]$EpssIndex
    )

    if ($EpssIndex.ContainsKey($CveId)) {
        $EpssIndex[$CveId]
    }
    else {
        [pscustomobject]@{ EpssScore = $null; EpssPercentile = $null; EpssUrl = $null; EpssDate = $null }
    }
}

#endregion EPSS MODULE

#region VENDOR ADVISORY MODULE

function Get-VendorAdvisoryInfo {
    [CmdletBinding()]
    param([string]$CveId)

    [pscustomobject]@{
        VendorAdvisoryUrl       = $null
        VendorPatchedVers       = $null
        VendorKnownIssues       = $null
        VendorMitigationSteps   = $null
    }
}

#endregion VENDOR ADVISORY MODULE

#region EXPLOIT INTEL MODULE

# Presence indicators only. No exploit code, payloads, or module contents are fetched, parsed, or stored.
# Named ...Store on purpose: the main loop uses $exploitIntel, and PowerShell variable names are case-insensitive.
$script:ExploitIntelStore = [pscustomobject]@{
    MetasploitIndex  = @{}
    ExploitDbIndex   = @{}
    MetasploitStatus = 'Not loaded'
    ExploitDbStatus  = 'Not loaded'
    Complete         = $false
}

function Read-IntelSource {
    # Returns text from a local path or an http(s) URL. Throws on failure.
    param([Parameter(Mandatory)][string]$Source)

    if ($Source -match '^https?://') {
        $body = Invoke-HttpGetWithRetry -Uri $Source -MaxRetries $Config.MaxRetries -TimeoutSec 180
        if ($body -is [string]) { return $body }
        return ($body | ConvertTo-Json -Depth 100 -Compress)   # Invoke-RestMethod already parsed JSON
    }
    if (-not (Test-Path -LiteralPath $Source)) { throw "Local intel file not found: $Source" }
    return (Get-Content -LiteralPath $Source -Raw)
}

function Initialize-ExploitIntelIndexes {
    [CmdletBinding()]
    param(
        [string]$MetasploitSource,
        [string]$ExploitDbSource,
        [switch]$Skip
    )

    $msf = @{}; $edb = @{}
    $msfStatus = 'Unavailable'; $edbStatus = 'Unavailable'

    if ($Skip) {
        $script:ExploitIntelStore = [pscustomobject]@{ MetasploitIndex = $msf; ExploitDbIndex = $edb; MetasploitStatus = 'Skipped'; ExploitDbStatus = 'Skipped'; Complete = $false }
        Write-Host "Exploit intel skipped (-SkipExploitIntel). Only NVD exploit references will be used." -ForegroundColor Yellow
        return
    }

    # ---- Metasploit: exploit-type modules only (auxiliary scanners are not exploits) ----
    try {
        $json = (Read-IntelSource -Source $MetasploitSource) | ConvertFrom-Json
        $modules = 0
        foreach ($prop in $json.PSObject.Properties) {
            $m = $prop.Value
            if ($m.type -ne 'exploit') { continue }
            $modules++
            $name = if ($m.fullname) { $m.fullname } else { $prop.Name }
            foreach ($r in @($m.references)) {
                if ("$r" -match '^CVE-\d{4}-\d{4,}$') {
                    $k = "$r".ToUpper()
                    if (-not $msf.ContainsKey($k)) { $msf[$k] = New-Object System.Collections.Generic.List[string] }
                    $msf[$k].Add($name)
                }
            }
        }
        if ($modules -eq 0) { throw "No exploit modules found; unexpected metadata schema." }
        $msfStatus = "Loaded ($modules exploit modules, $($msf.Count) CVEs)"
    }
    catch { Write-Warning "Metasploit metadata unavailable: $($_.Exception.Message)" }

    # ---- Exploit-DB: 'codes' column carries CVE IDs ----
    try {
        $rows = @((Read-IntelSource -Source $ExploitDbSource) | ConvertFrom-Csv)
        if ($rows.Count -eq 0 -or ($rows[0].PSObject.Properties.Name -notcontains 'codes') -or ($rows[0].PSObject.Properties.Name -notcontains 'id')) {
            throw "Unexpected Exploit-DB CSV schema (expected 'id' and 'codes' columns)."
        }
        foreach ($row in $rows) {
            foreach ($mm in [regex]::Matches("$($row.codes)", 'CVE-\d{4}-\d{4,}', 'IgnoreCase')) {
                $k = $mm.Value.ToUpper()
                if (-not $edb.ContainsKey($k)) { $edb[$k] = New-Object System.Collections.Generic.List[string] }
                $edb[$k].Add("$($row.id)")
            }
        }
        $edbStatus = "Loaded ($($rows.Count) entries, $($edb.Count) CVEs)"
    }
    catch { Write-Warning "Exploit-DB data unavailable: $($_.Exception.Message)" }

    $script:ExploitIntelStore = [pscustomobject]@{
        MetasploitIndex = $msf; ExploitDbIndex = $edb
        MetasploitStatus = $msfStatus; ExploitDbStatus = $edbStatus
        Complete = ($msfStatus -like 'Loaded*' -and $edbStatus -like 'Loaded*')
    }
    Write-Host "Exploit intel: Metasploit = $msfStatus | Exploit-DB = $edbStatus"
}

function Get-ExploitIntel {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$CveId,
        [pscustomobject]$Nvd
    )

    $key = $CveId.ToUpper()
    $idx = $script:ExploitIntelStore

    $msfModules = if ($idx.MetasploitIndex.ContainsKey($key)) { @($idx.MetasploitIndex[$key] | Select-Object -Unique) } else { @() }

    $edbIds = New-Object System.Collections.Generic.List[string]
    if ($idx.ExploitDbIndex.ContainsKey($key)) { foreach ($i in $idx.ExploitDbIndex[$key]) { if (-not $edbIds.Contains($i)) { $edbIds.Add($i) } } }
    $nvdRefCount = 0
    if ($Nvd) {
        $nvdRefCount = [int]$Nvd.ExploitRefCount
        foreach ($i in @($Nvd.ExploitDbRefIds)) { if ($i -and -not $edbIds.Contains($i)) { $edbIds.Add($i) } }
    }

    [pscustomobject]@{
        PublicExploit         = ($edbIds.Count -gt 0 -or $msfModules.Count -gt 0 -or $nvdRefCount -gt 0)
        ExploitDb             = ($edbIds.Count -gt 0)
        ExploitDbIds          = ($edbIds -join '; ')
        Metasploit            = ($msfModules.Count -gt 0)
        MetasploitModules     = ($msfModules -join '; ')
        MetasploitModuleCount = $msfModules.Count
        NvdExploitReferences  = $nvdRefCount
        SourcesIncomplete     = (-not $idx.Complete)
        SourceStatus          = "Metasploit: $($idx.MetasploitStatus); Exploit-DB: $($idx.ExploitDbStatus); NVD references: yes"
    }
}

#endregion EXPLOIT INTEL MODULE

#region MITRE ATT&CK MODULE

# Heuristic, vector-first mapping of the *exploitation* technique. It is NOT an authoritative ATT&CK mapping:
# every result carries a Confidence and Basis so analysts can validate before it is used in a brief.
# v2.2 mapped CWE -> post-exploitation techniques (e.g. deserialization -> T1055 Process Injection,
# path traversal -> T1083 Discovery) and tagged almost every CVE T1190 via the words "remote|web".
$CwePrivEsc   = @('CWE-269','CWE-250','CWE-264','CWE-266','CWE-274')
$CweInjection = @('CWE-77','CWE-78','CWE-94','CWE-95','CWE-502','CWE-917')   # code/command execution outcome -> T1059 secondary

function Get-MitreattackMapping {
    [CmdletBinding()]
    param(
        [string]$CveId,
        [string]$Cwe,
        [string]$Description,
        [string]$CvssVector
    )

    $tactic = $null; $tid = $null; $tname = $null; $conf = $null; $basis = $null; $secondary = $null

    $av = $null; $ui = $null
    if ($CvssVector -match '(?:^|/)AV:([NALP])') { $av = $Matches[1] }
    if ($CvssVector -match '(?:^|/)UI:([NRPA])') { $ui = $Matches[1] }
    $userInteraction = $ui -in @('R','P','A')

    if ($Cwe -eq 'CWE-79') {
        $tactic='Initial Access'; $tid='T1189'; $tname='Drive-by Compromise'; $conf='Low'
        $basis='CWE-79 (XSS): no precise ATT&CK analogue; user-driven web delivery assumed'
    }
    elseif ($Cwe -in $CwePrivEsc -and $av -ne 'N') {
        $tactic='Privilege Escalation'; $tid='T1068'; $tname='Exploitation for Privilege Escalation'; $conf='Medium'
        $basis="$Cwe (privilege management) with non-network attack vector"
    }
    elseif ($av -eq 'N' -and -not $userInteraction) {
        $tactic='Initial Access'; $tid='T1190'; $tname='Exploit Public-Facing Application'; $conf='Medium'
        $basis='CVSS AV:N, no user interaction (assumes the component is exposed; confirm with asset context)'
    }
    elseif ($av -eq 'N') {
        $tactic='Execution'; $tid='T1203'; $tname='Exploitation for Client Execution'; $conf='Low'
        $basis='CVSS AV:N with user interaction required'
    }
    elseif ($av -eq 'A') {
        $tactic='Lateral Movement'; $tid='T1210'; $tname='Exploitation of Remote Services'; $conf='Low'
        $basis='CVSS AV:A (adjacent network)'
    }
    elseif ($av -in @('L','P') -and $userInteraction) {
        $tactic='Execution'; $tid='T1203'; $tname='Exploitation for Client Execution'; $conf='Low'
        $basis='CVSS local/physical vector with user interaction'
    }
    elseif ($av -in @('L','P')) {
        $tactic='Privilege Escalation'; $tid='T1068'; $tname='Exploitation for Privilege Escalation'; $conf='Low'
        $basis='CVSS local/physical vector, no user interaction'
    }
    elseif ($Description) {
        # No usable CVSS vector: keyword fallback, Low confidence by definition.
        if ($Description -match '\bremote(ly)?\b') {
            $tactic='Initial Access'; $tid='T1190'; $tname='Exploit Public-Facing Application'; $conf='Low'
            $basis='Description keyword only (no CVSS vector available)'
        }
        elseif ($Description -match 'privilege escalation|elevat\w+ (of )?privileges?') {
            $tactic='Privilege Escalation'; $tid='T1068'; $tname='Exploitation for Privilege Escalation'; $conf='Low'
            $basis='Description keyword only (no CVSS vector available)'
        }
    }

    if ($Cwe -in $CweInjection) { $secondary = 'T1059 Command and Scripting Interpreter (execution outcome)' }

    $display = if ($tid) { "$tid $tname [$tactic] ($conf confidence)" } else { $null }

    [pscustomobject]@{
        MitreAttack        = $display
        MitreTactic        = $tactic
        MitreTechniqueId   = $tid
        MitreTechniqueName = $tname
        MitreConfidence    = $conf
        MitreBasis         = $basis
        MitreSecondary     = $secondary
    }
}

#endregion MITRE ATT&CK MODULE

#region RISK & PRIORITY MODULES

function Get-ExploitabilityScore {
    [CmdletBinding()]
    param(
        [double]$EpssScore,
        [string]$KevStatus,
        [string]$ExploitDbStatus,
        [string]$MetasploitStatus,
        [string]$PrereqComplexity,
        [string]$CvssVector = $null,
        [double]$CvssExploitabilitySubscore = 0.0,
        [string]$CvssVersion = $null,
        [string]$CvssV4_AT = $null,
        [string]$CvssV4_AU = $null,
        [string]$CvssV4_S = $null
    )

    if (-not $EpssScore) { $EpssScore = 0.0 }

    $kevFlag = if ($KevStatus -eq "Yes") { 1.0 } else { 0.0 }

    $exploitLevel = 0.0
    # Weaponized / Metasploit module must be tested first; as an elseif behind "PoC" it could never win.
    if ($ExploitDbStatus -eq "Weaponized" -or $MetasploitStatus -eq "ModuleAvailable") { $exploitLevel = 1.0 }
    elseif ($ExploitDbStatus -eq "PoC") { $exploitLevel = 0.5 }

    $complexityNorm = switch ($PrereqComplexity) {
        "Low"    { 0.0 }
        "Medium" { 0.5 }
        "High"   { 1.0 }
        default  { 0.5 }
    }

    $avBonus  = if ($CvssVector -and $CvssVector -match 'AV:N') { 0.05 } else { 0.0 }
    $prBonus  = if ($CvssVector -and $CvssVector -match 'PR:N') { 0.05 } else { 0.0 }
    $uiBonus  = if ($CvssVector -and $CvssVector -match 'UI:N') { 0.05 } else { 0.0 }
    # NVD exploitabilityScore maxes at 3.9 for CVSS v3.x and 10 for v2; v4 metrics carry none.
    $subMax   = switch ($CvssVersion) { '2.0' { 10.0 } '3.0' { 3.9 } '3.1' { 3.9 } default { 0.0 } }
    $subBonus = if ($subMax -gt 0 -and $CvssExploitabilitySubscore) { [math]::Min(($CvssExploitabilitySubscore / $subMax) * 0.15, 0.15) } else { 0.0 }

    $score = (0.4 * $EpssScore) + (0.3 * $kevFlag) + (0.2 * $exploitLevel) + (0.1 * (1.0 - $complexityNorm)) +
             $avBonus + $prBonus + $uiBonus + $subBonus

    if ($CvssVersion -eq "4.0") {
        if ($CvssV4_AT -eq "None") { $score += 0.05 }
        if ($CvssV4_AU -eq "Yes")  { $score += 0.05 }
        # CVSS v4 Safety is an impact metric, not exploitability: no bonus applied.
    }

    $score = [math]::Min($score, 1.0)
    [math]::Round($score * 100, 2)
}

function Get-RemediationPriority {
    [CmdletBinding()]
    param(
        [string]$KevStatus,
        [string]$Exposure,
        [string]$BusinessCriticality
    )

    $isInternet = $Exposure -match '^\s*(internet|external)'
    $isKev      = $KevStatus -eq "Yes"
    $isCritical = $BusinessCriticality -match '^\s*(critical|high)\b'

    if     ($isInternet -and $isKev)      { $r = @{ Rating = "Zero Tolerance"; Desc = "Internet Exposed + KEV";                Sla = 0  } }
    elseif ($isInternet -and $isCritical) { $r = @{ Rating = "P1"; Desc = "Internet Exposed + Critical App";     Sla = 7  } }
    elseif ($isInternet)                  { $r = @{ Rating = "P2"; Desc = "Internet Exposed + Non-Critical App"; Sla = 10 } }
    elseif ($isKev)                       { $r = @{ Rating = "P3"; Desc = "Internal + KEV";                      Sla = 14 } }
    elseif ($isCritical)                  { $r = @{ Rating = "P4"; Desc = "Internal + Critical App";             Sla = 21 } }
    else                                  { $r = @{ Rating = "P5"; Desc = "Internal + Non-Critical App";         Sla = 28 } }

    $slaText = if ($r.Sla -eq 0) { "0d - immediate" } else { "$($r.Sla)d" }

    [pscustomobject]@{
        Rating  = $r.Rating
        Label   = "{0} - {1} ({2})" -f $r.Rating, $r.Desc, $slaText
        SlaDays = $r.Sla
        DueDate = (Get-Date).Date.AddDays($r.Sla).ToString("yyyy-MM-dd")
        Basis   = "Exposure=$(if ($isInternet) {'Internet'} else {'Internal'}); KEV=$(if ($isKev) {'Yes'} else {'No'}); Criticality=$(if ($isCritical) {'Critical'} else {'Non-Critical'})"
    }
}

function Get-DataCompletenessFlags {
    [CmdletBinding()]
    param(
        $CvssScore,
        [string]$Cwe,
        $EpssScore,
        [string]$KevStatus,
        [string]$VendorAdvisoryUrl,
        [string]$MitreAttack,
        [string]$CvssVersion,
        [string]$CvssV4_AT,
        [string]$CvssV4_AU,
        [string]$CvssV4_R,
        [string]$CvssV4_RE,
        [string]$CvssV4_S,
        [bool]$ExploitIntelIncomplete = $true
    )

    $missingV4 = $false
    if ($CvssVersion -eq "4.0") {
        $missingV4 = [bool](-not $CvssV4_AT -and -not $CvssV4_AU -and -not $CvssV4_R -and -not $CvssV4_RE -and -not $CvssV4_S)
    }

    [pscustomobject]@{
        Missing_CVSS            = ($null -eq $CvssScore)
        Missing_CWE             = [bool](-not $Cwe)
        Missing_EPSS            = ($null -eq $EpssScore)
        Missing_Vendor_Advisory = [bool](-not $VendorAdvisoryUrl)
        Missing_ATTACK_Mapping  = [bool](-not $MitreAttack)
        Missing_CVSS_v4         = $missingV4
        Missing_Exploit_Intel   = $ExploitIntelIncomplete   # True when Metasploit or Exploit-DB data could not be loaded
    }
}

function Get-RiskOverrides {
    [CmdletBinding()]
    param(
        [string]$KevStatus,
        [string]$MetasploitStatus,
        [string]$ExploitDbStatus,
        [string]$BusinessCriticality,
        [double]$EpssPercentile
    )

    $forceTier1 = $false
    $reasons = [System.Collections.Generic.List[string]]::new()

    if ($KevStatus -eq "Yes") {
        $forceTier1 = $true; $reasons.Add("CISA KEV listed")
    }
    if ($ExploitDbStatus -eq "Weaponized" -or $MetasploitStatus -eq "ModuleAvailable") {
        $forceTier1 = $true; $reasons.Add("Metasploit exploit module available")
    }
    if ($BusinessCriticality -match '^\s*(critical|high)\b') {   # same rule as Get-RemediationPriority
        $forceTier1 = $true; $reasons.Add("Business criticality $($BusinessCriticality.Trim())")
    }
    if ($EpssPercentile -gt 0.99) {
        $forceTier1 = $true; $reasons.Add("EPSS percentile > 0.99")
    }

    [pscustomobject]@{
        ForceTier1 = $forceTier1
        Reasons    = ($reasons -join "; ")
    }
}

#endregion RISK & PRIORITY MODULES

#region ENRICHMENT OBJECT MODULE

function New-CveEnrichmentObject {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$CveId,
        [Parameter()][pscustomobject]$Nvd,
        [Parameter()][pscustomobject]$Kev,
        [Parameter()][pscustomobject]$Epss,
        [Parameter()][pscustomobject]$VendorAdvisory,
        [Parameter()][pscustomobject]$Mitre,
        [Parameter()][pscustomobject]$Priority,
        [Parameter()][double]$ExploitabilityScore,
        [Parameter()][string]$AssetSource,
        [Parameter()][bool]$IntelEscalationFlag,
        [Parameter()][string]$IntelEscalationReason,
        [Parameter()][pscustomobject]$Completeness,
        [Parameter()][bool]$RelevantToOrg,
        [Parameter()][object[]]$RelevantComponents,
        [Parameter()][pscustomobject]$ExploitIntel,
        [Parameter()][string]$Exposure,
        [Parameter()][string]$BusinessCriticality,
        [Parameter()][string]$PrereqComplexity,
        [Parameter()][bool]$UsedDefaultAssetContext
    )

    [pscustomobject]@{
        CVE_ID                    = $CveId

        Description               = $Nvd.Description
        Vendor_Product            = $Nvd.VendorProduct
        CVSS_Version              = $Nvd.CvssVersion
        CVSS_Score                = $Nvd.CvssScore
        CVSS_Vector               = $Nvd.CvssVector
        CVSS_Severity             = $Nvd.CvssSeverity
        CPE_Criteria              = $Nvd.CpeCriteria
        CWE                       = $Nvd.Cwe
        NVD_URL                   = $Nvd.NvdUrl

        CVSS_v4_AttackRequirements = $Nvd.CvssV4_AT
        CVSS_v4_Automatable        = $Nvd.CvssV4_AU
        CVSS_v4_Recovery           = $Nvd.CvssV4_R
        CVSS_v4_Response           = $Nvd.CvssV4_RE
        CVSS_v4_Safety             = $Nvd.CvssV4_S

        CISA_KEV_Status           = $Kev.KevStatus
        CISA_KEV_URL              = $Kev.KevUrl
        KEV_Date_Added            = $Kev.KevDateAdded
        KEV_Due_Date_CISA         = $Kev.KevDueDate
        KEV_Ransomware_Use        = $Kev.KevRansomwareUse

        EPSS_Score                = $Epss.EpssScore
        EPSS_Percentile           = $Epss.EpssPercentile
        EPSS_URL                  = $Epss.EpssUrl
        EPSS_Date                 = $Epss.EpssDate

        Vendor_Advisory_URL       = $VendorAdvisory.VendorAdvisoryUrl
        Vendor_Patched_Versions   = $VendorAdvisory.VendorPatchedVers
        Vendor_Known_Patch_Issues = $VendorAdvisory.VendorKnownIssues
        Vendor_Mitigation_Steps   = $VendorAdvisory.VendorMitigationSteps

        MITRE_ATTCK               = $Mitre.MitreAttack
        MITRE_Tactic              = $Mitre.MitreTactic
        MITRE_Technique_ID        = $Mitre.MitreTechniqueId
        MITRE_Technique_Name      = $Mitre.MitreTechniqueName
        MITRE_Confidence          = $Mitre.MitreConfidence
        MITRE_Basis               = $Mitre.MitreBasis
        MITRE_Secondary           = $Mitre.MitreSecondary

        Exploitability_Score      = $ExploitabilityScore
        Remediation_SLA_Days      = $Priority.SlaDays
        Patch_Urgency_Rating      = $Priority.Rating
        Patch_Urgency_Tier        = $Priority.Label
        SLA_Due_Date              = $Priority.DueDate
        Tier_Basis                = $Priority.Basis
        Asset_Context_Source      = $AssetSource
        Intel_Escalation_Flag     = $IntelEscalationFlag
        Intel_Escalation_Reason   = $IntelEscalationReason

        Missing_CVSS              = $Completeness.Missing_CVSS
        Missing_CWE               = $Completeness.Missing_CWE
        Missing_EPSS              = $Completeness.Missing_EPSS
        Missing_Vendor_Advisory   = $Completeness.Missing_Vendor_Advisory
        Missing_ATTACK_Mapping    = $Completeness.Missing_ATTACK_Mapping
        Missing_CVSS_v4           = $Completeness.Missing_CVSS_v4
        Missing_Exploit_Intel     = $Completeness.Missing_Exploit_Intel

        Exposure                   = $Exposure
        Business_Criticality       = $BusinessCriticality
        Prereq_Complexity          = $PrereqComplexity
        Used_Default_Asset_Context = $UsedDefaultAssetContext

        ExploitDB_Available         = $ExploitIntel.ExploitDb
        ExploitDB_IDs               = $ExploitIntel.ExploitDbIds
        Metasploit_Module_Available = $ExploitIntel.Metasploit
        Metasploit_Module_Count     = $ExploitIntel.MetasploitModuleCount
        Metasploit_Modules          = $ExploitIntel.MetasploitModules
        NVD_Exploit_Reference_Count = $ExploitIntel.NvdExploitReferences
        Exploit_Intel_Sources       = $ExploitIntel.SourceStatus

        # Script B data-contract fields
        KevListed                 = ($Kev.KevStatus -eq "Yes")
        ExploitedInWild           = ($Kev.KevStatus -eq "Yes")     # KEV = confirmed exploitation; no other in-the-wild feed integrated
        PublicExploit             = [bool]$ExploitIntel.PublicExploit
        InternetFacing            = [bool]($Exposure -match '^\s*(internet|external)')
        SectorRelevance           = "Not assessed"                 # placeholder: populate from CTI sources, not from business criticality

        RelevantToOrg             = $RelevantToOrg
        RelevantComponents        = (@($RelevantComponents) -join '; ')   # string so Excel does not show System.Object[]
    }
}

#endregion ENRICHMENT OBJECT MODULE

#region JSON LOGGING MODULE

function Write-EnrichmentLog {
    [CmdletBinding()]
    param(
        [string]$CveId,
        [pscustomobject]$Nvd,
        [pscustomobject]$Kev,
        [pscustomobject]$Epss,
        [pscustomobject]$VendorAdvisory,
        [pscustomobject]$Mitre,
        [pscustomobject]$ExploitIntel,
        [pscustomobject]$RiskOverride,
        $Priority,
        $ElapsedMs,
        [object[]]$EntryErrors,
        [bool]$RelevantToOrg,
        [object[]]$RelevantComponents
    )

    $logDir = Join-Path -Path (Get-Location) -ChildPath "logs"
    if (-not (Test-Path $logDir)) {
        New-Item -Path $logDir -ItemType Directory -Force | Out-Null
    }
    $logPath = Join-Path -Path $logDir -ChildPath ("cve_enrichment_{0}.json" -f (Get-Date -Format "yyyyMMdd"))

    $logEntry = [pscustomobject]@{
        SchemaVersion = $SchemaVersion
        Timestamp     = (Get-Date).ToString("o")
        CveId         = $CveId
        Sources       = [pscustomobject]@{
            Nvd            = $Nvd
            Kev            = $Kev
            Epss           = $Epss
            VendorAdvisory = $VendorAdvisory
            Mitre          = $Mitre
            ExploitIntel   = $ExploitIntel
        }
        Overrides     = $RiskOverride
        Priority      = $Priority
        TimingMs      = $ElapsedMs
        Errors        = $EntryErrors
        RelevantToOrg      = $RelevantToOrg
        RelevantComponents = $RelevantComponents
    }

    try {
        ($logEntry | ConvertTo-Json -Depth 6 -Compress) | Add-Content -Path $logPath
    }
    catch {
        Write-Warning "Failed to write enrichment log for $CveId : $($_.Exception.Message)"
    }
}

#endregion JSON LOGGING MODULE

#region MAIN PROCESSING

$kevIndex  = Get-KevIndex
if ($null -eq $kevIndex -or $kevIndex.Count -eq 0) {
    throw "CISA KEV feed is unavailable or empty. Aborting: without KEV data, Zero Tolerance and P3 ratings cannot be assigned reliably. Re-run when the feed is reachable."
}
$epssIndex = Get-EpssIndex -CveIds $cveList -BatchSize $Config.BatchSize
if ($epssIndex.Count -lt $cveList.Count) {
    Write-Warning "EPSS data returned for $($epssIndex.Count) of $($cveList.Count) CVE(s). Missing values are flagged in Missing_EPSS."
}
$assetCtx  = Get-AssetContextIndex -CsvPath $AssetContextCsv
$techStack = Get-TechStack -Path $TechStackFile
Initialize-ExploitIntelIndexes -MetasploitSource $MetasploitMetadata -ExploitDbSource $ExploitDbCsv -Skip:$SkipExploitIntel

$ScriptMetadata = [pscustomobject]@{
    GeneratedOn   = (Get-Date).ToString("o")
    ApiKeyPresent = [bool]$NvdApiKey
    TotalCves     = $cveList.Count
}

$results = [System.Collections.Generic.List[pscustomobject]]::new()
$errors  = [System.Collections.Generic.List[pscustomobject]]::new()

$total = $cveList.Count
$i = 0

foreach ($cve in $cveList) {
    $i++
    Write-Progress -Activity "Enriching CVEs" -Status "$cve ($i of $total)" -PercentComplete (($i / $total) * 100)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    $nvd = $kev = $epss = $vend = $mitre = $exploitIntel = $riskOverride = $priority = $null

    try {
        $nvdFailed = $false
        try { $nvd = Get-NvdData -CveId $cve -ApiKey $NvdApiKey }
        catch {
            $nvdFailed = $true
            $msg       = $_.Exception.Message
            $attempts  = if ($msg -match 'after (\d+) attempt') { [int]$Matches[1] } else { 0 }
            $transient = ($msg -notmatch 'status: 4\d\d') -or ($msg -match 'status: (403|429)')
            $errors.Add((New-EnrichmentErrorObject -CveId $cve -Source "NVD" -Reason $msg -IsTransient $transient -RetryCount $attempts))
        }
        if ($i -lt $total) { Start-Sleep -Milliseconds ([int]($Config.NvdDelay * 1000)) }

        if (-not $nvd) {
            if (-not $nvdFailed) {
                $errors.Add((New-EnrichmentErrorObject -CveId $cve -Source "NVD" -Reason "CVE not found in NVD (reserved, rejected, or not yet published)" -IsTransient $false))
            }
            $nvd = [pscustomobject]@{
                Description                = $null
                VendorProduct              = $null
                CpeCriteria                = $null
                ExploitRefCount            = 0
                ExploitDbRefIds            = @()
                CvssVersion                = $null
                CvssScore                  = $null
                CvssVector                 = $null
                CvssSeverity               = $null
                CvssExploitabilitySubscore = $null
                CvssV4_AT                  = $null
                CvssV4_AU                  = $null
                CvssV4_R                   = $null
                CvssV4_RE                  = $null
                CvssV4_S                   = $null
                Cwe                        = $null
                NvdUrl                     = "https://nvd.nist.gov/vuln/detail/$cve"
            }
        }

        $kev  = Get-KevStatus -CveId $cve -KevIndex $kevIndex
        $epss = Get-EpssData  -CveId $cve -EpssIndex $epssIndex
        $vend = Get-VendorAdvisoryInfo -CveId $cve
        $exploitIntel = Get-ExploitIntel -CveId $cve -Nvd $nvd
        # Exploit-DB entries are public exploit code (PoC-grade); only a Metasploit module counts as 'weaponized'.
        $edbStatus = if ($exploitIntel.ExploitDb -or $exploitIntel.NvdExploitReferences -gt 0) { 'PoC' } else { 'None' }
        $msfStatus = if ($exploitIntel.Metasploit) { 'ModuleAvailable' } else { 'None' }
        $mitre = Get-MitreattackMapping -CveId $cve -Cwe $nvd.Cwe -Description $nvd.Description -CvssVector $nvd.CvssVector

        $ctx = if ($assetCtx.ContainsKey($cve)) { $assetCtx[$cve] } else { $null }
        $defaultsUsed = [System.Collections.Generic.List[string]]::new()

        $prereqComplexity = if ($ctx -and $ctx.PrereqComplexity) { $ctx.PrereqComplexity } else { $defaultsUsed.Add("PrereqComplexity"); $Config.DefaultPrereqComplexity }
        $exposure         = if ($ctx -and $ctx.Exposure) { $ctx.Exposure } else { $defaultsUsed.Add("Exposure"); $Config.DefaultExposure }
        $businessCriticality = if ($ctx -and $ctx.BusinessCriticality) { $ctx.BusinessCriticality } else { $defaultsUsed.Add("BusinessCriticality"); $Config.DefaultBusinessCriticality }

        $assetSource = if (-not $ctx) { "Default (no CSV entry)" }
                       elseif ($defaultsUsed.Count -gt 0) { "CSV (defaults applied: $($defaultsUsed -join ', '))" }
                       else { "CSV" }

        $exploitScore = Get-ExploitabilityScore -EpssScore $epss.EpssScore -KevStatus $kev.KevStatus `
            -ExploitDbStatus $edbStatus -MetasploitStatus $msfStatus `
            -PrereqComplexity $prereqComplexity -CvssVector $nvd.CvssVector `
            -CvssExploitabilitySubscore $nvd.CvssExploitabilitySubscore `
            -CvssVersion $nvd.CvssVersion -CvssV4_AT $nvd.CvssV4_AT -CvssV4_AU $nvd.CvssV4_AU -CvssV4_S $nvd.CvssV4_S

        $priority = Get-RemediationPriority -KevStatus $kev.KevStatus -Exposure $exposure -BusinessCriticality $businessCriticality

        $riskOverride = Get-RiskOverrides -KevStatus $kev.KevStatus -BusinessCriticality $businessCriticality `
            -ExploitDbStatus $edbStatus -MetasploitStatus $msfStatus `
            -EpssPercentile $epss.EpssPercentile

        $escalate = [bool]($riskOverride.ForceTier1 -and $priority.Rating -notin @("Zero Tolerance", "P1"))

        $completeness = Get-DataCompletenessFlags `
            -CvssScore $nvd.CvssScore -Cwe $nvd.Cwe -EpssScore $epss.EpssScore `
            -KevStatus $kev.KevStatus -VendorAdvisoryUrl $vend.VendorAdvisoryUrl `
            -MitreAttack $mitre.MitreAttack -CvssVersion $nvd.CvssVersion `
            -CvssV4_AT $nvd.CvssV4_AT -CvssV4_AU $nvd.CvssV4_AU -CvssV4_R $nvd.CvssV4_R `
            -CvssV4_RE $nvd.CvssV4_RE -CvssV4_S $nvd.CvssV4_S `
            -ExploitIntelIncomplete $exploitIntel.SourcesIncomplete

        $techMatches   = @(Test-TechStackRelevance -CveData $nvd -TechStack $techStack)
        $relevantToOrg = ($techMatches.Count -gt 0)

        $enrichmentObject = New-CveEnrichmentObject `
            -CveId $cve -Nvd $nvd -Kev $kev -Epss $epss -VendorAdvisory $vend `
            -Mitre $mitre -Priority $priority -ExploitabilityScore $exploitScore `
            -AssetSource $assetSource -IntelEscalationFlag $escalate `
            -IntelEscalationReason $riskOverride.Reasons -Completeness $completeness `
            -RelevantToOrg $relevantToOrg -RelevantComponents $techMatches `
            -ExploitIntel $exploitIntel -Exposure $exposure -BusinessCriticality $businessCriticality `
            -PrereqComplexity $prereqComplexity -UsedDefaultAssetContext ($defaultsUsed.Count -gt 0)

        $results.Add($enrichmentObject)

        $sw.Stop()
        Write-EnrichmentLog -CveId $cve -Nvd $nvd -Kev $kev -Epss $epss -VendorAdvisory $vend `
            -Mitre $mitre -ExploitIntel $exploitIntel -RiskOverride $riskOverride -Priority $priority `
            -ElapsedMs $sw.ElapsedMilliseconds -EntryErrors @($errors | Where-Object { $_.CveId -eq $cve }) `
            -RelevantToOrg $relevantToOrg -RelevantComponents $techMatches

        if ($WritePerCveJson) {
            $jsonDir = Join-Path -Path (Get-Location) -ChildPath "cve-json"
            if (-not (Test-Path $jsonDir)) {
                New-Item -Path $jsonDir -ItemType Directory -Force | Out-Null
            }
            $jsonPath = Join-Path -Path $jsonDir -ChildPath "$cve.json"
            $enrichmentObject | ConvertTo-Json -Depth 6 | Out-File -FilePath $jsonPath -Encoding UTF8
        }
    }
    catch {
        $sw.Stop()
        $errors.Add((New-EnrichmentErrorObject -CveId $cve -Source "Main" -Reason $_.Exception.Message -IsTransient $false))
        Write-Warning "Error enriching $cve : $($_.Exception.Message)"
    }
}

Write-Progress -Activity "Enriching CVEs" -Completed
Write-Host "Enrichment complete. Writing Excel workbook: $OutputXlsxFile"

$mainSheetName    = "Enrichment"
$errorSheetName   = "Errors"
$summarySheetName = "CTI_Summary"

# Build into a temp workbook and swap in only when complete, so a failed run never destroys the previous report.
$tmpXlsx = $OutputXlsxFile -replace '\.xlsx$', '.tmp.xlsx'
if (Test-Path -LiteralPath $tmpXlsx) { Remove-Item -LiteralPath $tmpXlsx -Force }

if ($results.Count -gt 0) {
    # -NoNumberConversion keeps CVSS_Version text ("4.0" would otherwise become the number 4).
    $results | Export-Excel -Path $tmpXlsx -WorksheetName $mainSheetName -AutoSize -AutoFilter -FreezeTopRow -NoNumberConversion CVSS_Version
}
else {
    Write-Warning "No CVEs were enriched; the Enrichment sheet will be omitted. See the Errors sheet."
}

if ($errors.Count -gt 0) {
    $errors | Export-Excel -Path $tmpXlsx -WorksheetName $errorSheetName -AutoSize -AutoFilter -FreezeTopRow
}

# ---- CTI summary (counts and distributions) ----
$summaryRows = New-Object System.Collections.Generic.List[object]
$addRow = { param($Category, $Metric, $Value) $summaryRows.Add([pscustomobject]@{ Category = $Category; Metric = $Metric; Value = $Value }) }
$count  = { param($Filter) @($results | Where-Object $Filter).Count }

& $addRow "Run" "Script version"            $ScriptVersion
& $addRow "Run" "Generated"                 (Get-Date).ToString("s")
& $addRow "Run" "CVEs requested (unique)"   $cveList.Count
& $addRow "Run" "CVEs enriched"             $results.Count
& $addRow "Run" "Error rows"                $errors.Count
& $addRow "Run" "Tech stack loaded"         ([bool]$techStack)
& $addRow "Run" "Metasploit metadata"        $script:ExploitIntelStore.MetasploitStatus
& $addRow "Run" "Exploit-DB data"             $script:ExploitIntelStore.ExploitDbStatus

& $addRow "Exploitation" "KEV listed"                       (& $count { $_.CISA_KEV_Status -eq "Yes" })
& $addRow "Exploitation" "KEV - known ransomware use"       (& $count { $_.KEV_Ransomware_Use -eq "Known" })
& $addRow "Exploitation" "Public exploit available (any source)" (& $count { $_.PublicExploit })
& $addRow "Exploitation" "Metasploit exploit module available" (& $count { $_.Metasploit_Module_Available })
& $addRow "Exploitation" "Exploit-DB entry"                    (& $count { $_.ExploitDB_Available })
& $addRow "Exploitation" "EPSS >= 0.50"                     (& $count { $null -ne $_.EPSS_Score -and $_.EPSS_Score -ge 0.5 })
& $addRow "Exploitation" "Intel escalation flag"            (& $count { $_.Intel_Escalation_Flag })
& $addRow "Exploitation" "RelevantToOrg (tech stack match)" (& $count { $_.RelevantToOrg })

foreach ($g in @($results | Group-Object Patch_Urgency_Rating | Sort-Object Name)) {
    & $addRow "Priority distribution" $g.Name $g.Count
}
foreach ($g in @($results | Group-Object { if ($_.CVSS_Severity) { $_.CVSS_Severity } else { "Unscored" } } | Sort-Object Name)) {
    & $addRow "CVSS severity distribution" $g.Name $g.Count
}
foreach ($g in @($results | Group-Object { if ($_.MITRE_Technique_ID) { $_.MITRE_Technique_ID } else { "Unmapped" } } | Sort-Object Name)) {
    & $addRow "ATT&CK technique (heuristic)" $g.Name $g.Count
}

& $addRow "Data quality" "Asset context defaults applied (priority is worst-case assumed)" (& $count { $_.Asset_Context_Source -ne "CSV" })
& $addRow "Data quality" "Missing CVSS"           (& $count { $_.Missing_CVSS })
& $addRow "Data quality" "Missing EPSS"           (& $count { $_.Missing_EPSS })
& $addRow "Data quality" "Missing ATT&CK mapping" (& $count { $_.Missing_ATTACK_Mapping })
& $addRow "Data quality" "Exploit intel coverage incomplete (a source was unavailable)" (& $count { $_.Missing_Exploit_Intel })

$summaryRows | Export-Excel -Path $tmpXlsx -WorksheetName $summarySheetName -AutoSize -AutoFilter

if ((Test-Path -LiteralPath $OutputXlsxFile) -and -not $OverwriteOutput) {
    throw "Output file appeared during the run: $OutputXlsxFile. Temp workbook kept at: $tmpXlsx"
}
if (Test-Path -LiteralPath $OutputXlsxFile) {
    Remove-Item -LiteralPath $OutputXlsxFile -Force
    Write-Host "Existing output file replaced: $OutputXlsxFile"
}
Move-Item -LiteralPath $tmpXlsx -Destination $OutputXlsxFile

Write-Host "Excel workbook written. Done." -ForegroundColor Green

#endregion MAIN PROCESSING