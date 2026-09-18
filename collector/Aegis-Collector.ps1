<#
.SYNOPSIS
    Aegis Collection - read-only, agentless Active Directory data collector for
    security assessments and incident response.

.DESCRIPTION
    Aegis is a pure collector: it queries Active Directory over LDAP/ADSI and,
    for sections 16-19, the domain's member servers directly via WMI/CIM, and
    reports the raw facts it finds as absolute values (raw attribute values and
    ISO-8601 timestamps). It performs NO write operations against Active
    Directory or against any remote host.

    The script makes no risk judgement of its own: it does not compute scores,
    thresholds, or severity ratings, and it does not evaluate whether a finding
    is "acceptable" for any given time window. All such evaluation is left to a
    downstream analysis pipeline that consumes the JSON output. Where a boolean
    is derived directly from an attribute (for example a UserAccountControl
    flag), it is reported as an objective fact about the object, never as a
    judgement about that fact.

    The script requires Windows PowerShell 5.1 or PowerShell 7+ running with
    domain user context. No credentials are requested or stored; all LDAP and
    WMI/CIM operations use the identity of the account that runs the script.
    It takes no parameters: running it is the entire interface.

    Output: a self-contained aegis_collection.json and a single-file, offline
    aegis_report.html, both written into a timestamped run folder that is then
    compressed to a .zip archive.

.LEGAL
    THIS SCRIPT IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE, AND NONINFRINGEMENT.

    This tool must be used exclusively against systems you own, or against
    systems for which you hold explicit written authorization to perform a
    security assessment. Running this script against any Active Directory
    environment or any remote system without such authorization is illegal in
    most jurisdictions and is expressly prohibited.

    The author(s) and distributor(s) of this script accept no liability
    whatsoever for any damage, data loss, service disruption, or legal
    consequence arising from its use or misuse. By executing this script you
    confirm that you are acting within the boundaries of the law and of any
    authorization you hold for the target environment, and that you accept
    full responsibility for its use.

.AUTHOR
    TheUnchecked
#>

# ------------------------------------------------------------------------------
# Fixed, in-script configuration for the remote collection sections (16-19).
# The tool intentionally takes no parameters, so any tunable value lives here.
# ------------------------------------------------------------------------------
$script:RemoteCollectionEnabled = $true
$script:RemoteThrottleLimit     = 32
$script:RemoteTimeoutSeconds    = 30
$script:RemoteStaleDays         = 90

################################################################################
#                          PROGRESS BAR & LOGGING                            #
################################################################################

# currentStep/totalSteps back Show-StepProgress; totalSteps is a placeholder
# until the real number of Show-StepProgress calls is counted at the end of
# the script and hard-coded here.
$script:totalSteps  = 1
$script:currentStep = 0
$script:Stopwatch   = [System.Diagnostics.Stopwatch]::StartNew()
$script:LogFilePath = $null

function Show-StepProgress {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Status,

        [string]$Activity = "Aegis Collection"
    )

    $script:currentStep++

    $percent = 0
    if ($script:totalSteps -gt 0) {
        $percent = [Math]::Round((($script:currentStep / $script:totalSteps) * 100))
    }
    if ($percent -lt 0)   { $percent = 0 }
    if ($percent -gt 100) { $percent = 100 }

    Write-Progress -Id 1 -Activity $Activity -Status $Status -PercentComplete $percent
}

function Write-Log {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [ValidateSet("INFO", "WARN", "ERROR", "OK")]
        [string]$Level = "INFO"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$timestamp][$Level] $Message"

    $color = "Gray"
    switch ($Level) {
        "WARN"  { $color = "Yellow" }
        "ERROR" { $color = "Red" }
        "OK"    { $color = "Green" }
        default { $color = "Gray" }
    }
    Write-Host $line -ForegroundColor $color

    if ($script:LogFilePath) {
        try {
            Add-Content -Path $script:LogFilePath -Value $line -Encoding UTF8
        } catch {
            # Logging must never be able to break the collection itself.
        }
    }
}

################################################################################
#                              LDAP HELPERS                                  #
################################################################################

function ConvertTo-LdapFilterValue {
    param(
        [AllowNull()]
        [string]$Value
    )

    if ($null -eq $Value) { return $null }

    # Backslash MUST be escaped first, otherwise the escape sequences
    # introduced below would themselves get re-escaped.
    $escaped = $Value.Replace("\", "\5c")
    $escaped = $escaped.Replace("*", "\2a")
    $escaped = $escaped.Replace("(", "\28")
    $escaped = $escaped.Replace(")", "\29")

    return $escaped
}

################################################################################
#                               ACE HELPERS                                  #
################################################################################

function Test-PrivilegedRights {
    param(
        [Parameter(Mandatory = $true)]
        [System.DirectoryServices.ActiveDirectoryRights]$Rights
    )

    $mask = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll `
        -bor [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite `
        -bor [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl `
        -bor [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner `
        -bor [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty `
        -bor [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight `
        -bor [System.DirectoryServices.ActiveDirectoryRights]::CreateChild `
        -bor [System.DirectoryServices.ActiveDirectoryRights]::DeleteChild

    return (([Int32]$Rights -band [Int32]$mask) -ne 0)
}

function Get-PrivilegedAces {
    param(
        [Parameter(Mandatory = $true)]
        [System.DirectoryServices.ActiveDirectorySecurity]$Acl,

        [Parameter(Mandatory = $true)]
        [string]$ObjectDN,

        [string[]]$EveryoneLike = @()
    )

    # CREATOR OWNER / SELF / SYSTEM are structural ACEs present on virtually
    # every AD object; they are not a delegation and would just be noise here.
    $excludedTrustees = @("CREATOR OWNER", "SELF", "SYSTEM")

    $collected = New-Object System.Collections.ArrayList

    foreach ($ace in $Acl.Access) {
        if (-not (Test-PrivilegedRights -Rights $ace.ActiveDirectoryRights)) { continue }

        $trustee = $ace.IdentityReference.Value
        $trusteeLeaf = $trustee
        $slashIndex = $trustee.LastIndexOf("\")
        if ($slashIndex -ge 0) {
            $trusteeLeaf = $trustee.Substring($slashIndex + 1)
        }

        if ($excludedTrustees -contains $trusteeLeaf.ToUpperInvariant()) { continue }

        $isEveryoneLike = $false
        if ($EveryoneLike -contains $trusteeLeaf) { $isEveryoneLike = $true }

        [void]$collected.Add([PSCustomObject]@{
            ObjectDN          = $ObjectDN
            Trustee           = $trustee
            ADRights          = $ace.ActiveDirectoryRights.ToString()
            AccessControlType = $ace.AccessControlType.ToString()
            IsInherited       = $ace.IsInherited
            EveryoneLike      = $isEveryoneLike
        })
    }

    $deduped = $collected |
        Sort-Object ObjectDN, Trustee, ADRights, AccessControlType, IsInherited |
        Group-Object ObjectDN, Trustee, ADRights, AccessControlType, IsInherited |
        ForEach-Object { $_.Group[0] }

    return @($deduped)
}

################################################################################
#                          ATTRIBUTE READ HELPERS                            #
################################################################################

function Get-AdProp {
    param(
        [Parameter(Mandatory = $true)]
        $Entry,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        $Default = "N/A"
    )

    try {
        if ($Entry.Contains($Name) -and $Entry[$Name].Count -gt 0) {
            return [string]$Entry[$Name][0]
        }
    } catch {
        # Fall through to the default below.
    }

    return $Default
}

function Get-AdDate {
    param(
        [Parameter(Mandatory = $true)]
        $Entry,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [switch]$FileTime
    )

    $display  = "N/A"
    $iso      = ""
    $dateTime = $null

    try {
        if ($Entry.Contains($Name) -and $Entry[$Name].Count -gt 0) {
            $raw = $Entry[$Name][0]

            if ($FileTime) {
                $dateTime = [DateTime]::FromFileTime([Int64]$raw)
            } else {
                $dateTime = [DateTime]$raw
            }

            $display = $dateTime.ToString("dd/MM/yyyy HH:mm")
            $iso     = $dateTime.ToString("o")
        }
    } catch {
        $display  = "N/A"
        $iso      = ""
        $dateTime = $null
    }

    return [PSCustomObject]@{
        Display  = $display
        Iso      = $iso
        DateTime = $dateTime
    }
}

function New-AccountObject {
    <#
        Every account collected anywhere in the script is normalized through
        this function, so every section shares the exact same fact schema for
        userAccountControl-derived flags.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.Specialized.OrderedDictionary]$Base,

        [Parameter(Mandatory = $true)]
        $Result
    )

    $props = $Result.Properties

    $uac = 0
    try {
        if ($props.Contains("useraccountcontrol") -and $props["useraccountcontrol"].Count -gt 0) {
            $uac = [Int64]$props["useraccountcontrol"][0]
        }
    } catch {
        $uac = 0
    }

    $whenCreated = Get-AdDate -Entry $props -Name "whencreated"

    $hasSidHistory = $false
    try {
        if ($props.Contains("sidhistory") -and $props["sidhistory"].Count -gt 0) {
            $hasSidHistory = $true
        }
    } catch {
        $hasSidHistory = $false
    }

    $Base["userAccountControl"]   = $uac
    $Base["passwordNotRequired"]  = [bool]($uac -band 0x20)
    $Base["passwordNeverExpires"] = [bool]($uac -band 0x10000)
    $Base["smartcardRequired"]    = [bool]($uac -band 0x40000)
    $Base["trustedForDelegation"] = [bool]($uac -band 0x80000)
    $Base["notDelegated"]         = [bool]($uac -band 0x100000)
    $Base["whenCreatedIso"]       = $whenCreated.Iso
    $Base["hasSidHistory"]        = $hasSidHistory

    return [PSCustomObject]$Base
}

################################################################################
#                             RSAT DETECTION                                 #
################################################################################

$script:RsatAvailable = $false
$script:RsatWarning   = ""

try {
    $hasGpInheritance = [bool](Get-Command -Name "Get-GPInheritance" -ErrorAction SilentlyContinue)
    $hasAdOuCmdlet     = [bool](Get-Command -Name "Get-ADOrganizationalUnit" -ErrorAction SilentlyContinue)

    if ($hasGpInheritance -and $hasAdOuCmdlet) {
        $script:RsatAvailable = $true
    } else {
        $script:RsatWarning = "RSAT (GroupPolicy and/or ActiveDirectory PowerShell modules) not detected on this host: GPO tier-level coverage analysis (Section 9) will be skipped."
    }
} catch {
    $script:RsatAvailable = $false
    $script:RsatWarning   = "RSAT detection failed: GPO tier-level coverage analysis (Section 9) will be skipped."
}

################################################################################
#                           WORKING FOLDER SETUP                             #
################################################################################

# Resolve the script's own root without depending on any parameter.
$scriptRoot = $null
if ($PSScriptRoot) {
    $scriptRoot = $PSScriptRoot
} elseif ($MyInvocation.MyCommand.Path) {
    $scriptRoot = Split-Path -Path $MyInvocation.MyCommand.Path -Parent
} else {
    $scriptRoot = (Get-Location).Path
}

$script:RunFolderName = "aegis_{0}" -f (Get-Date -Format "dd_MM_yyyy_HHmmss")
$script:RunFolderPath = Join-Path -Path $scriptRoot -ChildPath $script:RunFolderName

New-Item -Path $script:RunFolderPath -ItemType Directory -Force | Out-Null

$script:LogFilePath = Join-Path -Path $script:RunFolderPath -ChildPath "aegis_run.log"

# Fingerprint the collector itself for chain-of-custody purposes.
$script:ScriptSelfPath = $null
if ($MyInvocation.MyCommand.Path) {
    $script:ScriptSelfPath = $MyInvocation.MyCommand.Path
} elseif ($PSCommandPath) {
    $script:ScriptSelfPath = $PSCommandPath
}

$script:ScriptSha256 = "N/A"
if ($script:ScriptSelfPath -and (Test-Path -Path $script:ScriptSelfPath)) {
    try {
        $script:ScriptSha256 = (Get-FileHash -Path $script:ScriptSelfPath -Algorithm SHA256).Hash
    } catch {
        $script:ScriptSha256 = "N/A"
    }
}

Write-Log -Message "Aegis Collection starting. Output folder: $($script:RunFolderPath)" -Level INFO
Write-Log -Message "Collector script SHA-256: $($script:ScriptSha256)" -Level INFO
if (-not [string]::IsNullOrEmpty($script:RsatWarning)) {
    Write-Log -Message $script:RsatWarning -Level WARN
}

################################################################################
#                              VERSION CHECK                                 #
################################################################################

if ($PSVersionTable.PSVersion -lt [Version]"5.1") {
    Write-Log -Message "PowerShell 5.1 or higher is required. Detected: $($PSVersionTable.PSVersion)" -Level ERROR
    exit 1
}

Write-Log -Message "PowerShell version check passed: $($PSVersionTable.PSVersion)" -Level OK

################################################################################
#                          ACTIVE DIRECTORY CONNECTION                       #
################################################################################

$script:BaseDN                     = $null
$script:ConfigurationNamingContext = $null
$script:SchemaNamingContext        = $null

try {
    $rootDse = [ADSI]"LDAP://RootDSE"

    $script:BaseDN = $rootDse.Properties["defaultNamingContext"][0]
    if ([string]::IsNullOrWhiteSpace($script:BaseDN)) {
        throw "defaultNamingContext is empty or missing from RootDSE."
    }

    $script:ConfigurationNamingContext = $rootDse.Properties["configurationNamingContext"][0]
    $script:SchemaNamingContext        = $rootDse.Properties["schemaNamingContext"][0]

    Write-Log -Message "Connected to Active Directory. Base DN: $($script:BaseDN)" -Level OK
} catch {
    Write-Log -Message "Unable to connect to Active Directory via LDAP://RootDSE: $($_.Exception.Message)" -Level ERROR
    exit 1
}

# Reference instant for this collection run.
$script:CollectionStartUtc = [DateTime]::UtcNow
