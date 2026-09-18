<#
.SYNOPSIS
    ADCollector - read-only, agentless Active Directory data collector for
    security assessments and incident response.

.DESCRIPTION
    ADCollector is a pure collector: it queries Active Directory over LDAP/ADSI and,
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

    Output: a self-contained adcollector_collection.json and a single-file,
    offline adcollector_report.html, both written into a timestamped run
    folder that is then compressed to a .zip archive.

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

        [string]$Activity = "ADCollector Collection"
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

$script:RunFolderName = "adcollector_{0}" -f (Get-Date -Format "dd_MM_yyyy_HHmmss")
$script:RunFolderPath = Join-Path -Path $scriptRoot -ChildPath $script:RunFolderName

New-Item -Path $script:RunFolderPath -ItemType Directory -Force | Out-Null

$script:LogFilePath = Join-Path -Path $script:RunFolderPath -ChildPath "adcollector_run.log"

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

Write-Log -Message "ADCollector starting. Output folder: $($script:RunFolderPath)" -Level INFO
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

################################################################################
#                     GROUP MEMBERSHIP HELPERS (SECTIONS 1-3)                #
################################################################################

# Built-in and common privileged groups tracked across the domain. Names only:
# each one is resolved against AD in Section 1, so a group absent from this
# particular domain (e.g. Hyper-V Administrators on a DC without Hyper-V) is
# simply not found rather than causing an error.
$script:MonitoredGroups = @(
    "Account Operators",
    "Administrators",
    "Backup Operators",
    "Cert Publishers",
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Server Operators",
    "Print Operators",
    "Replicator",
    "DnsAdmins",
    "DnsUpdateProxy",
    "Group Policy Creator Owners",
    "Hyper-V Administrators",
    "Key Admins",
    "Enterprise Key Admins",
    "Domain Controllers",
    "Cloneable Domain Controllers",
    "Read-only Domain Controllers",
    "Enterprise Read-only Domain Controllers",
    "Incoming Forest Trust Builders",
    "Performance Log Users",
    "Performance Monitor Users",
    "Debugger Users",
    "Distributed COM Users",
    "Remote Desktop Users",
    "Remote Management Users",
    "Storage Replica Administrators",
    "System Managed Accounts Group",
    "Access Control Assistance Operators",
    "Allowed RODC Password Replication Group",
    "Denied RODC Password Replication Group",
    "Certificate Service DCOM Access",
    "Cryptographic Operators",
    "DHCP Administrators",
    "DHCP Users",
    "Event Log Readers",
    "IIS_IUSRS",
    "Network Configuration Operators",
    "Pre-Windows 2000 Compatible Access",
    "RAS and IAS Servers",
    "RDS Endpoint Servers",
    "RDS Management Servers",
    "RDS Remote Access Servers",
    "Terminal Server License Servers",
    "Windows Authorization Access Group",
    "WinRMRemoteWMIUsers_"
)

function Get-TransitiveGroupMembership {
    <#
        Breadth-first resolution of a principal's full group closure. Queue +
        visited set prevent infinite loops on circular nesting (A member of B
        member of A); GroupCache is passed in from script scope so a group's
        own memberOf is only ever read from AD once per run, no matter how
        many users end up nested inside it.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$InitialGroups,

        [Parameter(Mandatory = $true)]
        [System.Collections.Hashtable]$GroupCache
    )

    $resolved = @{}
    $visited  = New-Object 'System.Collections.Generic.HashSet[string]'
    $queue    = New-Object 'System.Collections.Generic.Queue[string]'

    foreach ($groupDn in $InitialGroups) {
        if ([string]::IsNullOrWhiteSpace($groupDn)) { continue }
        $key = $groupDn.ToLowerInvariant()
        if (-not $visited.Contains($key)) {
            [void]$visited.Add($key)
            $resolved[$key] = [PSCustomObject]@{ DN = $groupDn; Relationship = "Direct" }
            $queue.Enqueue($groupDn)
        }
    }

    while ($queue.Count -gt 0) {
        $currentDn  = $queue.Dequeue()
        $currentKey = $currentDn.ToLowerInvariant()

        if (-not $GroupCache.ContainsKey($currentKey)) {
            $parentGroups = @()
            try {
                $groupEntry    = [ADSI]("LDAP://" + $currentDn)
                $memberOfProp  = $groupEntry.Properties["memberOf"]
                if ($memberOfProp) {
                    foreach ($parentValue in $memberOfProp) {
                        $parentGroups += [string]$parentValue
                    }
                }
            } catch {
                $parentGroups = @()
            }
            $GroupCache[$currentKey] = $parentGroups
        }

        foreach ($parentDn in $GroupCache[$currentKey]) {
            if ([string]::IsNullOrWhiteSpace($parentDn)) { continue }
            $parentKey = $parentDn.ToLowerInvariant()
            if (-not $visited.Contains($parentKey)) {
                [void]$visited.Add($parentKey)
                $resolved[$parentKey] = [PSCustomObject]@{ DN = $parentDn; Relationship = "Nested" }
                $queue.Enqueue($parentDn)
            }
        }
    }

    return $resolved
}

################################################################################
#              SECTION 1 - MONITORED PRIVILEGED GROUPS RESOLUTION            #
################################################################################

Show-StepProgress -Status "Section 1: Resolving monitored privileged groups"
Write-Log -Message "Section 1: resolving monitored privileged groups against the domain" -Level INFO

# CN found in AD -> DN
$script:MonitoredGroupsFound    = @{}
# CN -> running membership counter, filled in during Section 3
$script:MonitoredGroupsCounters = @{}
# lowercased DN -> CN, the O(1) lookup Section 3 needs per closure member
$script:MonitoredGroupsByDn     = @{}

try {
    $cnFilterParts = New-Object 'System.Collections.Generic.List[string]'
    foreach ($groupName in $script:MonitoredGroups) {
        $escapedName = ConvertTo-LdapFilterValue -Value $groupName
        $cnFilterParts.Add("(cn=$escapedName)")
    }
    $groupFilter = "(&(objectCategory=group)(|{0}))" -f ($cnFilterParts -join "")

    $groupSearchRoot = [ADSI]("LDAP://" + $script:BaseDN)
    $groupSearcher = New-Object System.DirectoryServices.DirectorySearcher($groupSearchRoot)
    try {
        $groupSearcher.Filter   = $groupFilter
        $groupSearcher.PageSize = 500
        [void]$groupSearcher.PropertiesToLoad.AddRange(@("cn", "distinguishedName"))

        $groupResults = $groupSearcher.FindAll()
        try {
            foreach ($groupResult in $groupResults) {
                $cn = Get-AdProp -Entry $groupResult.Properties -Name "cn" -Default $null
                $dn = Get-AdProp -Entry $groupResult.Properties -Name "distinguishedname" -Default $null
                if ($cn -and $dn) {
                    $script:MonitoredGroupsFound[$cn]    = $dn
                    $script:MonitoredGroupsCounters[$cn] = 0
                    $script:MonitoredGroupsByDn[$dn.ToLowerInvariant()] = $cn
                }
            }
        } finally {
            $groupResults.Dispose()
        }
    } finally {
        $groupSearcher.Dispose()
    }

    Write-Log -Message "Section 1: $($script:MonitoredGroupsFound.Count) of $($script:MonitoredGroups.Count) monitored groups found in the domain" -Level OK
} catch {
    Write-Log -Message "Section 1 failed: $($_.Exception.Message)" -Level ERROR
}

################################################################################
#                   SECTION 2 - DOMAIN USER ACCOUNT ENUMERATION              #
################################################################################

Show-StepProgress -Status "Section 2: Enumerating domain user accounts"
Write-Log -Message "Section 2: enumerating all domain user accounts" -Level INFO

$script:AllUsers   = New-Object System.Collections.ArrayList
# lowercased distinguishedName -> user object
$script:UsersByDn  = @{}
# lowercased samAccountName -> user object
$script:UsersBySam = @{}

try {
    $userSearchRoot = [ADSI]("LDAP://" + $script:BaseDN)
    $userSearcher = New-Object System.DirectoryServices.DirectorySearcher($userSearchRoot)
    try {
        $userSearcher.Filter       = "(&(objectCategory=person)(objectClass=user))"
        $userSearcher.PageSize     = 1000
        $userSearcher.CacheResults = $false
        [void]$userSearcher.PropertiesToLoad.AddRange(@(
            "samaccountname", "pwdlastset", "memberof", "whencreated",
            "lastlogontimestamp", "distinguishedname", "useraccountcontrol",
            "accountexpires", "admincount", "sidhistory"
        ))

        $userResults = $userSearcher.FindAll()
        try {
            $nowUtc = [DateTime]::UtcNow

            foreach ($userResult in $userResults) {
                $props = $userResult.Properties

                $dn  = Get-AdProp -Entry $props -Name "distinguishedname" -Default "N/A"
                $sam = Get-AdProp -Entry $props -Name "samaccountname" -Default "N/A"

                $uac = 0
                try {
                    if ($props.Contains("useraccountcontrol") -and $props["useraccountcontrol"].Count -gt 0) {
                        $uac = [Int64]$props["useraccountcontrol"][0]
                    }
                } catch {
                    $uac = 0
                }
                $isDisabled = [bool]($uac -band 0x2)

                # accountExpires is only meaningful when set, positive, and
                # below the "never expires" sentinel (Int64.MaxValue).
                $isExpired = $false
                try {
                    if ($props.Contains("accountexpires") -and $props["accountexpires"].Count -gt 0) {
                        $accountExpiresRaw = [Int64]$props["accountexpires"][0]
                        if ($accountExpiresRaw -gt 0 -and $accountExpiresRaw -lt [Int64]::MaxValue) {
                            $expiresDate = [DateTime]::FromFileTimeUtc($accountExpiresRaw)
                            if ($expiresDate -lt $nowUtc) { $isExpired = $true }
                        }
                    }
                } catch {
                    $isExpired = $false
                }

                $adminCountValue = 0
                try {
                    if ($props.Contains("admincount") -and $props["admincount"].Count -gt 0) {
                        $adminCountValue = [Int32]$props["admincount"][0]
                    }
                } catch {
                    $adminCountValue = 0
                }
                $isProtectedByAdminSDHolder = [bool]($adminCountValue -eq 1)

                $memberOf = @()
                if ($props.Contains("memberof")) {
                    foreach ($memberOfValue in $props["memberof"]) {
                        $memberOf += [string]$memberOfValue
                    }
                }

                $pwdLastSetInfo = Get-AdDate -Entry $props -Name "pwdlastset" -FileTime
                $lastLogonInfo  = Get-AdDate -Entry $props -Name "lastlogontimestamp" -FileTime

                $base = [ordered]@{
                    DistinguishedName          = $dn
                    SamAccountName             = $sam
                    PwdLastSetDisplay          = $pwdLastSetInfo.Display
                    PwdLastSetIso              = $pwdLastSetInfo.Iso
                    LastLogonTimestampDisplay  = $lastLogonInfo.Display
                    LastLogonTimestampIso      = $lastLogonInfo.Iso
                    MemberOf                   = $memberOf
                    IsDisabled                 = $isDisabled
                    IsExpired                  = $isExpired
                    IsProtectedByAdminSDHolder = $isProtectedByAdminSDHolder
                    AdminCount                 = $adminCountValue
                }

                $userObject = New-AccountObject -Base $base -Result $userResult

                [void]$script:AllUsers.Add($userObject)

                if ($dn -and $dn -ne "N/A") {
                    $script:UsersByDn[$dn.ToLowerInvariant()] = $userObject
                }
                if ($sam -and $sam -ne "N/A") {
                    $script:UsersBySam[$sam.ToLowerInvariant()] = $userObject
                }
            }
        } finally {
            $userResults.Dispose()
        }
    } finally {
        $userSearcher.Dispose()
    }

    Write-Log -Message "Section 2: $($script:AllUsers.Count) domain user accounts enumerated" -Level OK
} catch {
    Write-Log -Message "Section 2 failed: $($_.Exception.Message)" -Level ERROR
}

################################################################################
#            SECTION 3 - TRANSITIVE PRIVILEGED MEMBERSHIP RESOLUTION         #
################################################################################

Show-StepProgress -Status "Section 3: Resolving transitive privileged group membership"
Write-Log -Message "Section 3: resolving transitive group membership for $($script:AllUsers.Count) users" -Level INFO

# lowercased monitored-group DN -> ArrayList of privileged user objects
# (monitored-groups-only view, used for the unified list in step 3).
$script:PrivilegedUsersByGroup = @{}
# lowercased ANY-group DN -> ArrayList of {User; Relationship}. Unlike the
# index above this is not limited to the curated monitored-groups list: an
# ACL delegation in Sections 4/5/5b can name any group in the domain (an
# Exchange group, a custom IT-support group, ...), so the reverse index that
# resolves "who is a member of this group" in O(1) has to cover every group
# encountered in any user's closure, not just the privileged ones.
$script:GroupMembersIndex = @{}
# Shared across every user so a given group's memberOf is read from AD once.
$script:GroupMemberOfCache = @{}

try {
    foreach ($userObject in $script:AllUsers) {
        $initialGroups = @()
        if ($userObject.MemberOf) { $initialGroups = $userObject.MemberOf }

        $closure = Get-TransitiveGroupMembership -InitialGroups $initialGroups -GroupCache $script:GroupMemberOfCache

        $membershipDetailParts = New-Object 'System.Collections.Generic.List[string]'
        $isPrivileged = $false

        foreach ($closureKey in $closure.Keys) {
            $relationship = $closure[$closureKey].Relationship

            if (-not $script:GroupMembersIndex.ContainsKey($closureKey)) {
                $script:GroupMembersIndex[$closureKey] = New-Object System.Collections.ArrayList
            }
            [void]$script:GroupMembersIndex[$closureKey].Add([PSCustomObject]@{
                User         = $userObject
                Relationship = $relationship
            })

            if (-not $script:MonitoredGroupsByDn.ContainsKey($closureKey)) { continue }

            $groupCn = $script:MonitoredGroupsByDn[$closureKey]
            $membershipDetailParts.Add("$groupCn ($relationship)")

            $isPrivileged = $true

            if ($script:MonitoredGroupsCounters.ContainsKey($groupCn)) {
                $script:MonitoredGroupsCounters[$groupCn]++
            }

            if (-not $script:PrivilegedUsersByGroup.ContainsKey($closureKey)) {
                $script:PrivilegedUsersByGroup[$closureKey] = New-Object System.Collections.ArrayList
            }
            [void]$script:PrivilegedUsersByGroup[$closureKey].Add($userObject)
        }

        if ($isPrivileged) {
            $sortedDetails = $membershipDetailParts | Sort-Object
            Add-Member -InputObject $userObject -MemberType NoteProperty -Name "MembershipDetails" -Value ($sortedDetails -join "; ") -Force
        }
    }

    $privilegedUserCount = ($script:AllUsers | Where-Object { $_.PSObject.Properties.Match("MembershipDetails").Count -gt 0 }).Count
    Write-Log -Message "Section 3: $privilegedUserCount users found in monitored privileged groups (direct or nested)" -Level OK
} catch {
    Write-Log -Message "Section 3 failed: $($_.Exception.Message)" -Level ERROR
}

################################################################################
#              ACL DELEGATION HELPERS (SECTIONS 4, 5, 5b + UNIFIED LIST)     #
################################################################################

# Trustees whose ACEs are noise rather than a delegation: broad built-in
# principals that legitimately hold privileged rights on many AD objects.
$script:EveryoneLikeTrustees = @(
    "Everyone", "Authenticated Users", "Users", "Domain Users",
    "Domain Computers", "Pre-Windows 2000 Compatible Access",
    "Guests", "Domain Guests"
)

# Dedicated searcher + cache for principal resolution, reused by every ACL
# section so the same trustee is never looked up against AD twice.
$script:PrincipalResolutionCache = @{}
$script:PrincipalSearcherRoot    = [ADSI]("LDAP://" + $script:BaseDN)
$script:PrincipalSearcher        = New-Object System.DirectoryServices.DirectorySearcher($script:PrincipalSearcherRoot)
[void]$script:PrincipalSearcher.PropertiesToLoad.AddRange(@("samaccountname", "objectclass", "distinguishedname"))

function Resolve-WellKnownPrincipal {
    <#
        SID translation is language- and role-dependent (some of these only
        resolve to a name on a domain controller), so a trustee that AD
        itself does not know about still needs to be classified as a known
        Windows/NT built-in rather than falling through to Unknown.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Trustee
    )

    $knownAuthorities = @(
        "NT AUTHORITY", "BUILTIN", "NT SERVICE", "NT VIRTUAL MACHINE",
        "Font Driver Host", "APPLICATION PACKAGE AUTHORITY", "IIS APPPOOL",
        "Window Manager", "CREATOR GROUP", "OWNER RIGHTS", "SELF"
    )
    $knownNames = @(
        "Everyone", "CREATOR OWNER", "SERVICE", "DIALUP", "NETWORK", "PROXY",
        "ANONYMOUS LOGON", "BATCH", "INTERACTIVE", "RESTRICTED",
        "TERMINAL SERVER USER", "LOCAL", "CONSOLE LOGON"
    )

    $authority  = $null
    $leaf       = $Trustee
    $slashIndex = $Trustee.LastIndexOf("\")
    if ($slashIndex -ge 0) {
        $authority = $Trustee.Substring(0, $slashIndex)
        $leaf      = $Trustee.Substring($slashIndex + 1)
    }

    $isKnownAuthority = $false
    if ($authority) {
        foreach ($candidate in $knownAuthorities) {
            if ($authority.Equals($candidate, [StringComparison]::OrdinalIgnoreCase)) {
                $isKnownAuthority = $true
                break
            }
        }
    }

    $isKnownName = $false
    foreach ($candidate in $knownNames) {
        if ($leaf.Equals($candidate, [StringComparison]::OrdinalIgnoreCase)) {
            $isKnownName = $true
            break
        }
    }

    if ($isKnownAuthority -or $isKnownName) {
        return [PSCustomObject]@{ Trustee = $Trustee; Type = "WellKnown"; Name = $Trustee; Dn = $null }
    }

    # Orphaned SID: no domain object and no known Windows/NT built-in matched it.
    return [PSCustomObject]@{ Trustee = $Trustee; Type = "Unknown"; Name = $Trustee; Dn = $null }
}

function Resolve-Principal {
    <#
        Classifies an ACE trustee as User, Group, WellKnown or Unknown.
        Raw-SID trustees (.NET failed to translate them to a name) are looked
        up by objectSid; named trustees by samAccountName/cn. This works off
        a domain controller too, unlike NTAccount SID translation.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Trustee
    )

    if ($script:PrincipalResolutionCache.ContainsKey($Trustee)) {
        return $script:PrincipalResolutionCache[$Trustee]
    }

    $result = [PSCustomObject]@{ Trustee = $Trustee; Type = "Unknown"; Name = $Trustee; Dn = $null }

    try {
        $isRawSid = $Trustee -match '^S-1-\d+(-\d+)+$'

        if ($isRawSid) {
            $escapedSid = ConvertTo-LdapFilterValue -Value $Trustee
            $script:PrincipalSearcher.Filter = "(objectSid=$escapedSid)"
        } else {
            $leaf = $Trustee
            $slashIndex = $Trustee.LastIndexOf("\")
            if ($slashIndex -ge 0) { $leaf = $Trustee.Substring($slashIndex + 1) }
            $escapedLeaf = ConvertTo-LdapFilterValue -Value $leaf
            $script:PrincipalSearcher.Filter = "(|(samAccountName=$escapedLeaf)(cn=$escapedLeaf))"
        }

        $found = $script:PrincipalSearcher.FindOne()

        if ($found) {
            $objectClasses = @()
            if ($found.Properties.Contains("objectclass")) {
                foreach ($oc in $found.Properties["objectclass"]) { $objectClasses += [string]$oc }
            }

            if ($objectClasses -contains "group") {
                $result.Type = "Group"
            } elseif ($objectClasses -contains "user") {
                # Computer accounts are schema subclasses of "user", so they
                # are classified as User here too.
                $result.Type = "User"
            } else {
                $result.Type = "Other"
            }

            $result.Name = Get-AdProp -Entry $found.Properties -Name "samaccountname" -Default $Trustee
            $result.Dn   = Get-AdProp -Entry $found.Properties -Name "distinguishedname" -Default $null
        } else {
            $result = Resolve-WellKnownPrincipal -Trustee $Trustee
        }
    } catch {
        $result = Resolve-WellKnownPrincipal -Trustee $Trustee
    }

    $script:PrincipalResolutionCache[$Trustee] = $result
    return $result
}

function Add-DelegationUser {
    <#
        Accumulates a user's delegation provenance across ACEs/containers.
        The stored object is a copy of the account record so the caller's own
        AllUsers entry is never mutated by a delegation-map merge.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.Hashtable]$Map,

        [Parameter(Mandatory = $true)]
        $UserInfo,

        [Parameter(Mandatory = $true)]
        [string]$Source
    )

    $key = ([string]$UserInfo.DistinguishedName).ToLowerInvariant()

    if ($Map.ContainsKey($key)) {
        $existingSources = @()
        if ($Map[$key].DelegationSource) { $existingSources = @($Map[$key].DelegationSource -split "; ") }
        if ($existingSources -notcontains $Source) {
            if ($Map[$key].DelegationSource) {
                $Map[$key].DelegationSource = "$($Map[$key].DelegationSource); $Source"
            } else {
                $Map[$key].DelegationSource = $Source
            }
        }
        return
    }

    # Field order mirrors New-AccountObject exactly (DelegationSource is
    # simply appended), so a delegation-only record and a group-membership
    # record share the same shape once merged into the unified list.
    $clone = $UserInfo.PSObject.Copy()
    Add-Member -InputObject $clone -MemberType NoteProperty -Name "DelegationSource" -Value $Source -Force
    $Map[$key] = $clone
}

function Resolve-DelegationUsersMap {
    <#
        Turns a list of resolved ACE principals into a DN-keyed map of
        delegated users. A User-type principal is a direct grant; a
        Group-type principal is expanded through the group -> members
        reverse index built in Section 3, labeling each member as a direct
        or nested member of that specific group.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [PSCustomObject[]]$Principals,

        [Parameter(Mandatory = $true)]
        [System.Collections.Hashtable]$UserIndex,

        [Parameter(Mandatory = $true)]
        [System.Collections.Hashtable]$UserBySam,

        [Parameter(Mandatory = $true)]
        [System.Collections.Hashtable]$GroupToUsers,

        [Parameter(Mandatory = $true)]
        [string]$DirectLabel,

        [Parameter(Mandatory = $true)]
        [string]$GroupPrefix
    )

    $map = @{}

    foreach ($principal in $Principals) {
        if ($principal.Type -eq "User") {
            $userObj = $null
            if ($principal.Dn -and $UserIndex.ContainsKey($principal.Dn.ToLowerInvariant())) {
                $userObj = $UserIndex[$principal.Dn.ToLowerInvariant()]
            } elseif ($UserBySam.ContainsKey($principal.Name.ToLowerInvariant())) {
                $userObj = $UserBySam[$principal.Name.ToLowerInvariant()]
            }
            if ($userObj) {
                Add-DelegationUser -Map $map -UserInfo $userObj -Source $DirectLabel
            }
        } elseif ($principal.Type -eq "Group" -and $principal.Dn) {
            $groupKey = $principal.Dn.ToLowerInvariant()
            if ($GroupToUsers.ContainsKey($groupKey)) {
                foreach ($member in $GroupToUsers[$groupKey]) {
                    $label = "$GroupPrefix - $($member.Relationship) member of $($principal.Name)"
                    Add-DelegationUser -Map $map -UserInfo $member.User -Source $label
                }
            }
        }
    }

    return $map
}

function Get-ContainerAclDelegation {
    <#
        Shared logic behind Sections 4, 5 and 5b: read an object's ACL,
        keep only privileged ACEs, resolve each trustee and expand it into
        the set of delegated users. A missing container (e.g. no Exchange
        installed) degrades to an empty, non-fatal result.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$ContainerPath,

        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    $result = [PSCustomObject]@{
        PrivilegedAces       = @()
        DelegationPrincipals = @{}
        Found                = $false
    }

    try {
        if (-not [System.DirectoryServices.DirectoryEntry]::Exists("LDAP://$ContainerPath")) {
            Write-Log -Message "$Label`: container not found ($ContainerPath), skipping." -Level WARN
            return $result
        }

        $entry = [ADSI]("LDAP://" + $ContainerPath)
        $acl   = $entry.psbase.ObjectSecurity

        $result.PrivilegedAces = @(Get-PrivilegedAces -Acl $acl -ObjectDN $ContainerPath -EveryoneLike $script:EveryoneLikeTrustees)
        $result.Found          = $true

        $principals = New-Object 'System.Collections.Generic.List[object]'
        foreach ($ace in $result.PrivilegedAces) {
            $principals.Add((Resolve-Principal -Trustee $ace.Trustee))
        }

        $result.DelegationPrincipals = Resolve-DelegationUsersMap `
            -Principals $principals `
            -UserIndex $script:UsersByDn `
            -UserBySam $script:UsersBySam `
            -GroupToUsers $script:GroupMembersIndex `
            -DirectLabel "$Label (direct)" `
            -GroupPrefix $Label
    } catch {
        Write-Log -Message "$Label failed: $($_.Exception.Message)" -Level WARN
    }

    return $result
}

################################################################################
#                   SECTION 4 - DOMAIN ROOT ACL DELEGATIONS                  #
################################################################################

Show-StepProgress -Status "Section 4: Reading domain root ACL"
Write-Log -Message "Section 4: reading ACL on the domain root object" -Level INFO

$script:RootPrivilegedAces       = @()
$script:RootDelegationPrincipals = @{}

try {
    $rootAclInfo = Get-ContainerAclDelegation -ContainerPath $script:BaseDN -Label "Domain root ACL"
    $script:RootPrivilegedAces       = $rootAclInfo.PrivilegedAces
    $script:RootDelegationPrincipals = $rootAclInfo.DelegationPrincipals

    Write-Log -Message "Section 4: $($script:RootPrivilegedAces.Count) privileged ACEs, $($script:RootDelegationPrincipals.Count) users resolved via delegation" -Level OK
} catch {
    Write-Log -Message "Section 4 failed: $($_.Exception.Message)" -Level ERROR
}

################################################################################
#              SECTION 5 - DOMAIN CONTROLLERS OU ACL DELEGATIONS             #
################################################################################

Show-StepProgress -Status "Section 5: Reading Domain Controllers OU ACL"
Write-Log -Message "Section 5: reading ACL on the Domain Controllers OU" -Level INFO

$script:DcOuPrivilegedAces       = @()
$script:DcOuDelegationPrincipals = @{}

try {
    $dcOuPath    = "OU=Domain Controllers," + $script:BaseDN
    $dcOuAclInfo = Get-ContainerAclDelegation -ContainerPath $dcOuPath -Label "Domain Controllers OU ACL"
    $script:DcOuPrivilegedAces       = $dcOuAclInfo.PrivilegedAces
    $script:DcOuDelegationPrincipals = $dcOuAclInfo.DelegationPrincipals

    Write-Log -Message "Section 5: $($script:DcOuPrivilegedAces.Count) privileged ACEs, $($script:DcOuDelegationPrincipals.Count) users resolved via delegation" -Level OK
} catch {
    Write-Log -Message "Section 5 failed: $($_.Exception.Message)" -Level ERROR
}

################################################################################
#                 SECTION 5b - EXCHANGE CONTAINER ACL DELEGATIONS            #
################################################################################

Show-StepProgress -Status "Section 5b: Reading Exchange delegation container ACLs"
Write-Log -Message "Section 5b: reading ACLs on Exchange delegation containers" -Level INFO

$script:ExchangePrivilegedAces       = @()
$script:ExchangeDelegationPrincipals = @{}

try {
    $exchangeContainers = @(
        ("CN=Microsoft Exchange Security Groups," + $script:BaseDN),
        ("CN=Microsoft Exchange System Objects," + $script:BaseDN)
    )
    if ($script:ConfigurationNamingContext) {
        $exchangeContainers += ("CN=Microsoft Exchange,CN=Services," + $script:ConfigurationNamingContext)
    }

    $combinedAces      = New-Object 'System.Collections.Generic.List[object]'
    $combinedDelegation = @{}

    foreach ($containerPath in $exchangeContainers) {
        $containerInfo = Get-ContainerAclDelegation -ContainerPath $containerPath -Label "Exchange container ACL ($containerPath)"
        if (-not $containerInfo.Found) { continue }

        foreach ($ace in $containerInfo.PrivilegedAces) { $combinedAces.Add($ace) }

        foreach ($delegationKey in $containerInfo.DelegationPrincipals.Keys) {
            $delegatedUser = $containerInfo.DelegationPrincipals[$delegationKey]
            if ($combinedDelegation.ContainsKey($delegationKey)) {
                $existingSources = @()
                if ($combinedDelegation[$delegationKey].DelegationSource) {
                    $existingSources = @($combinedDelegation[$delegationKey].DelegationSource -split "; ")
                }
                if ($existingSources -notcontains $delegatedUser.DelegationSource) {
                    $combinedDelegation[$delegationKey].DelegationSource = "$($combinedDelegation[$delegationKey].DelegationSource); $($delegatedUser.DelegationSource)"
                }
            } else {
                $combinedDelegation[$delegationKey] = $delegatedUser
            }
        }
    }

    $script:ExchangePrivilegedAces       = @($combinedAces)
    $script:ExchangeDelegationPrincipals = $combinedDelegation

    Write-Log -Message "Section 5b: $($script:ExchangePrivilegedAces.Count) privileged ACEs, $($script:ExchangeDelegationPrincipals.Count) users resolved via delegation across Exchange containers" -Level OK
} catch {
    Write-Log -Message "Section 5b failed: $($_.Exception.Message)" -Level ERROR
}

################################################################################
#            UNIFIED PRIVILEGED USERS LIST (GROUPS + ACL DELEGATIONS)        #
################################################################################

Write-Log -Message "Building the unified privileged users list (group membership + ACL delegation)" -Level INFO

$script:UnifiedPrivilegedUsers = New-Object System.Collections.ArrayList
# lowercased DN or samAccountName -> the (single, shared) object reference
# held in UnifiedPrivilegedUsers, so a duplicate found under either key
# lands on the same record and its fields get merged rather than dropped.
$script:UnifiedIndex = @{}

function Add-ToUnifiedList {
    param(
        [Parameter(Mandatory = $true)]
        $UserObject
    )

    $dnKey  = ([string]$UserObject.DistinguishedName).ToLowerInvariant()
    $samKey = ([string]$UserObject.SamAccountName).ToLowerInvariant()

    $existingUser = $null
    if ($script:UnifiedIndex.ContainsKey($dnKey))  { $existingUser = $script:UnifiedIndex[$dnKey] }
    elseif ($script:UnifiedIndex.ContainsKey($samKey)) { $existingUser = $script:UnifiedIndex[$samKey] }

    if ($existingUser) {
        # Merge in whichever of the two facts (group membership, ACL
        # delegation) this incoming copy carries that the kept record does
        # not already have, so a user privileged both ways keeps both.
        $incomingMembership = ""
        if ($UserObject.PSObject.Properties.Match("MembershipDetails").Count -gt 0) {
            $incomingMembership = $UserObject.MembershipDetails
        }
        if ($incomingMembership -and -not $existingUser.MembershipDetails) {
            $existingUser.MembershipDetails = $incomingMembership
        }

        $incomingDelegation = ""
        if ($UserObject.PSObject.Properties.Match("DelegationSource").Count -gt 0) {
            $incomingDelegation = $UserObject.DelegationSource
        }
        if ($incomingDelegation) {
            $incomingSources = @($incomingDelegation -split "; ")
            $mergedSources    = @()
            if ($existingUser.DelegationSource) { $mergedSources = @($existingUser.DelegationSource -split "; ") }
            foreach ($src in $incomingSources) {
                if ($mergedSources -notcontains $src) { $mergedSources += $src }
            }
            $existingUser.DelegationSource = ($mergedSources -join "; ")
        }

        return
    }

    if (-not ($UserObject.PSObject.Properties.Match("MembershipDetails").Count -gt 0)) {
        Add-Member -InputObject $UserObject -MemberType NoteProperty -Name "MembershipDetails" -Value "" -Force
    }
    if (-not ($UserObject.PSObject.Properties.Match("DelegationSource").Count -gt 0)) {
        Add-Member -InputObject $UserObject -MemberType NoteProperty -Name "DelegationSource" -Value "" -Force
    }

    [void]$script:UnifiedPrivilegedUsers.Add($UserObject)
    $script:UnifiedIndex[$dnKey]  = $UserObject
    $script:UnifiedIndex[$samKey] = $UserObject
}

try {
    foreach ($userObject in $script:AllUsers) {
        if ($userObject.PSObject.Properties.Match("MembershipDetails").Count -gt 0) {
            Add-ToUnifiedList -UserObject $userObject
        }
    }

    foreach ($delegationMap in @($script:RootDelegationPrincipals, $script:DcOuDelegationPrincipals, $script:ExchangeDelegationPrincipals)) {
        foreach ($delegationKey in $delegationMap.Keys) {
            Add-ToUnifiedList -UserObject $delegationMap[$delegationKey]
        }
    }

    Write-Log -Message "Unified privileged users list: $($script:UnifiedPrivilegedUsers.Count) unique accounts" -Level OK
} catch {
    Write-Log -Message "Unified privileged users list build failed: $($_.Exception.Message)" -Level ERROR
}

# The dedicated principal searcher is done for the ACL-delegation sections.
try { $script:PrincipalSearcher.Dispose() } catch { }

################################################################################
#                          DOMAIN CONFIGURATION FACTS                        #
################################################################################

Show-StepProgress -Status "Collecting domain-wide configuration facts"
Write-Log -Message "Collecting domain configuration facts: Recycle Bin, last backup, functional levels, quotas, tombstone lifetime" -Level INFO

# msDS-Behavior-Version conversion table. Values 8/9 are reserved/unused by
# Microsoft (Server 2016 is 7, the next assigned value is Server 2025 at 10).
$script:FunctionalLevelMap = @{
    0  = "Windows 2000"
    1  = "Windows Server 2003 Interim"
    2  = "Windows Server 2003"
    3  = "Windows Server 2008"
    4  = "Windows Server 2008 R2"
    5  = "Windows Server 2012"
    6  = "Windows Server 2012 R2"
    7  = "Windows Server 2016"
    8  = "Reserved/unused"
    9  = "Reserved/unused"
    10 = "Windows Server 2025"
}

function Convert-FunctionalLevel {
    param(
        [Parameter(Mandatory = $true)]
        [int]$Level
    )
    if ($script:FunctionalLevelMap.ContainsKey($Level)) {
        return $script:FunctionalLevelMap[$Level]
    }
    return "Unknown (raw value $Level)"
}

function Get-RecycleBinState {
    <#
        The AD Recycle Bin optional feature carries no simple on/off
        attribute of its own; its enablement is recorded as a backlink
        (msDS-EnabledFeatureBL) populated once the feature is scoped to the
        forest/domain. msDS-OptionalFeatureFlags is read as a secondary
        signal when the backlink itself is not present.
    #>
    $stateResult = [PSCustomObject]@{ Enabled = $false; Detail = "Unable to determine" }

    $featurePath = "CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services," + $script:ConfigurationNamingContext

    if (-not [System.DirectoryServices.DirectoryEntry]::Exists("LDAP://$featurePath")) {
        $stateResult.Detail = "Unable to determine"
        return $stateResult
    }

    $featureEntry = [ADSI]("LDAP://" + $featurePath)
    $featureEntry.RefreshCache(@("msDS-EnabledFeatureBL", "msDS-OptionalFeatureFlags"))
    $props = $featureEntry.Properties

    if ($props.Contains("msDS-EnabledFeatureBL") -and $props["msDS-EnabledFeatureBL"].Count -gt 0) {
        $stateResult.Enabled = $true
        $stateResult.Detail  = "Enabled (msDS-EnabledFeatureBL populated)"
    } elseif ($props.Contains("msDS-OptionalFeatureFlags") -and $props["msDS-OptionalFeatureFlags"].Count -gt 0) {
        $stateResult.Enabled = $true
        $stateResult.Detail  = "Enabled (msDS-OptionalFeatureFlags populated)"
    } else {
        $stateResult.Enabled = $false
        $stateResult.Detail  = "Not enabled"
    }

    return $stateResult
}

function Get-LastBackupDate {
    <#
        A backup/restore is one of the few operations that bumps the
        replication version of the special "dSASignature" pseudo-attribute
        on a naming context head; msDS-ReplAttributeMetaData exposes that as
        an XML blob per attribute when explicitly requested. Checking all
        three naming contexts (Domain, Configuration, Schema) and keeping the
        most recent value gives a reasonable last-backup estimate without
        contacting every DC individually.
    #>
    $changeTimes = New-Object 'System.Collections.Generic.List[DateTime]'

    $namingContexts = @()
    if ($script:BaseDN)                     { $namingContexts += $script:BaseDN }
    if ($script:ConfigurationNamingContext) { $namingContexts += $script:ConfigurationNamingContext }
    if ($script:SchemaNamingContext)        { $namingContexts += $script:SchemaNamingContext }

    foreach ($ncDn in $namingContexts) {
        try {
            $ncEntry = [ADSI]("LDAP://" + $ncDn)
            $ncEntry.RefreshCache(@("msDS-ReplAttributeMetaData"))
            $metaValues = $ncEntry.Properties["msDS-ReplAttributeMetaData"]

            if ($metaValues) {
                foreach ($metaXml in $metaValues) {
                    $metaText = [string]$metaXml
                    if ($metaText -notmatch "<pszAttributeName>dSASignature</pszAttributeName>") { continue }
                    if ($metaText -notmatch "<ftimeLastOriginatingChange>([^<]+)</ftimeLastOriginatingChange>") { continue }

                    try {
                        $parsedTime = [DateTime]::Parse(
                            $Matches[1],
                            [System.Globalization.CultureInfo]::InvariantCulture,
                            [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal
                        )
                        $changeTimes.Add($parsedTime)
                    } catch {
                        # Unparseable timestamp for this NC; the other naming contexts are still tried.
                    }
                }
            }
        } catch {
            # This naming context's replication metadata is unavailable; move on to the next one.
        }
    }

    if ($changeTimes.Count -gt 0) {
        $mostRecent = ($changeTimes | Sort-Object -Descending)[0]
        return [PSCustomObject]@{
            Display = $mostRecent.ToString("dd/MM/yyyy HH:mm")
            Iso     = $mostRecent.ToString("o")
        }
    }

    return [PSCustomObject]@{ Display = "No backup detected"; Iso = "" }
}

$script:RecycleBinState = "Unable to determine"
try {
    $recycleBinInfo = Get-RecycleBinState
    $script:RecycleBinState = $recycleBinInfo.Detail
} catch {
    $script:RecycleBinState = "Unable to determine"
    Write-Log -Message "Recycle Bin state lookup failed: $($_.Exception.Message)" -Level WARN
}

$script:LastBackupDisplay = "No backup detected"
$script:LastBackupIso     = ""
try {
    $lastBackupInfo = Get-LastBackupDate
    $script:LastBackupDisplay = $lastBackupInfo.Display
    $script:LastBackupIso     = $lastBackupInfo.Iso
} catch {
    $script:LastBackupDisplay = "No backup detected"
    $script:LastBackupIso     = ""
    Write-Log -Message "Last backup lookup failed: $($_.Exception.Message)" -Level WARN
}

$script:DomainFunctionalLevelRaw  = $null
$script:DomainFunctionalLevelName = "Unable to determine"
try {
    $domainEntryForLevel = [ADSI]("LDAP://" + $script:BaseDN)
    $script:DomainFunctionalLevelRaw  = [int]$domainEntryForLevel.Properties["msDS-Behavior-Version"][0]
    $script:DomainFunctionalLevelName = Convert-FunctionalLevel -Level $script:DomainFunctionalLevelRaw
} catch {
    $script:DomainFunctionalLevelName = "Unable to determine"
    Write-Log -Message "Domain functional level lookup failed: $($_.Exception.Message)" -Level WARN
}

$script:ForestFunctionalLevelRaw  = $null
$script:ForestFunctionalLevelName = "Unable to determine"
try {
    $partitionsEntry = [ADSI]("LDAP://CN=Partitions," + $script:ConfigurationNamingContext)
    $script:ForestFunctionalLevelRaw  = [int]$partitionsEntry.Properties["msDS-Behavior-Version"][0]
    $script:ForestFunctionalLevelName = Convert-FunctionalLevel -Level $script:ForestFunctionalLevelRaw
} catch {
    $script:ForestFunctionalLevelName = "Unable to determine"
    Write-Log -Message "Forest functional level lookup failed: $($_.Exception.Message)" -Level WARN
}

$script:MachineAccountQuota = "Unable to retrieve"
try {
    $domainEntryForQuota = [ADSI]("LDAP://" + $script:BaseDN)
    $script:MachineAccountQuota = [string]$domainEntryForQuota.Properties["ms-DS-MachineAccountQuota"][0]
} catch {
    $script:MachineAccountQuota = "Unable to retrieve"
    Write-Log -Message "ms-DS-MachineAccountQuota lookup failed: $($_.Exception.Message)" -Level WARN
}

$script:TombstoneLifetimeDays = "Unable to retrieve"
try {
    $dsServiceEntry = [ADSI]("LDAP://CN=Directory Service,CN=Windows NT,CN=Services," + $script:ConfigurationNamingContext)
    $script:TombstoneLifetimeDays = [string]$dsServiceEntry.Properties["tombstoneLifetime"][0]
} catch {
    $script:TombstoneLifetimeDays = "Unable to retrieve"
    Write-Log -Message "tombstoneLifetime lookup failed: $($_.Exception.Message)" -Level WARN
}

Write-Log -Message "Domain configuration facts collected." -Level OK

################################################################################
#                       SECTION 6 - DOMAIN COMPUTER ACCOUNTS                 #
################################################################################

Show-StepProgress -Status "Section 6: Enumerating domain computer accounts"
Write-Log -Message "Section 6: enumerating domain computer accounts" -Level INFO

$script:Computers = New-Object System.Collections.ArrayList

try {
    $computerSearchRoot = [ADSI]("LDAP://" + $script:BaseDN)
    $computerSearcher = New-Object System.DirectoryServices.DirectorySearcher($computerSearchRoot)
    try {
        $computerSearcher.Filter   = "(objectCategory=computer)"
        $computerSearcher.PageSize = 1000
        [void]$computerSearcher.PropertiesToLoad.AddRange(@(
            "cn", "operatingsystem", "operatingsystemversion", "distinguishedname",
            "useraccountcontrol", "lastlogontimestamp",
            "ms-mcs-admpwdexpirationtime", "mslaps-passwordexpirationtime"
        ))

        $computerResults = $computerSearcher.FindAll()
        try {
            foreach ($computerResult in $computerResults) {
                $props = $computerResult.Properties

                $uac = 0
                try {
                    if ($props.Contains("useraccountcontrol") -and $props["useraccountcontrol"].Count -gt 0) {
                        $uac = [Int64]$props["useraccountcontrol"][0]
                    }
                } catch {
                    $uac = 0
                }

                $lastLogonInfo = Get-AdDate -Entry $props -Name "lastlogontimestamp" -FileTime

                # Two LAPS attribute generations: ms-Mcs-AdmPwdExpirationTime
                # (legacy LAPS) and msLAPS-PasswordExpirationTime (Windows
                # LAPS). LapsExpiryIso is populated from whichever is set.
                $legacyLapsExpiry  = Get-AdDate -Entry $props -Name "ms-mcs-admpwdexpirationtime" -FileTime
                $windowsLapsExpiry = Get-AdDate -Entry $props -Name "mslaps-passwordexpirationtime" -FileTime

                $lapsExpiryIso = ""
                if ($legacyLapsExpiry.Iso) { $lapsExpiryIso = $legacyLapsExpiry.Iso }
                elseif ($windowsLapsExpiry.Iso) { $lapsExpiryIso = $windowsLapsExpiry.Iso }

                $computerObject = [PSCustomObject]@{
                    Cn                         = Get-AdProp -Entry $props -Name "cn" -Default "N/A"
                    OperatingSystem            = Get-AdProp -Entry $props -Name "operatingsystem" -Default "N/A"
                    OperatingSystemVersion     = Get-AdProp -Entry $props -Name "operatingsystemversion" -Default "N/A"
                    DistinguishedName          = Get-AdProp -Entry $props -Name "distinguishedname" -Default "N/A"
                    UserAccountControl         = $uac
                    Enabled                    = -not [bool]($uac -band 0x2)
                    IsDomainController         = [bool]($uac -band 0x2000)
                    TrustedForDelegation       = [bool]($uac -band 0x80000)
                    TrustedToAuthForDelegation = [bool]($uac -band 0x1000000)
                    LastLogonTimestampDisplay  = $lastLogonInfo.Display
                    LastLogonTimestampIso      = $lastLogonInfo.Iso
                    LapsLegacyExpirationIso    = $legacyLapsExpiry.Iso
                    LapsWindowsExpirationIso   = $windowsLapsExpiry.Iso
                    LapsExpiryIso              = $lapsExpiryIso
                }

                [void]$script:Computers.Add($computerObject)
            }
        } finally {
            $computerResults.Dispose()
        }
    } finally {
        $computerSearcher.Dispose()
    }

    Write-Log -Message "Section 6: $($script:Computers.Count) domain computer accounts enumerated" -Level OK
} catch {
    Write-Log -Message "Section 6 failed: $($_.Exception.Message)" -Level ERROR
}

################################################################################
#                          SECTION 7 - GROUP POLICY OBJECTS                  #
################################################################################

Show-StepProgress -Status "Section 7: Enumerating Group Policy Objects"
Write-Log -Message "Section 7: enumerating Group Policy Objects" -Level INFO

$script:Gpos = New-Object System.Collections.ArrayList

try {
    $gpoContainerPath = "CN=Policies,CN=System," + $script:BaseDN
    $gpoSearchRoot = [ADSI]("LDAP://" + $gpoContainerPath)
    $gpoSearcher = New-Object System.DirectoryServices.DirectorySearcher($gpoSearchRoot)
    try {
        $gpoSearcher.Filter   = "(objectClass=groupPolicyContainer)"
        $gpoSearcher.PageSize = 1000
        [void]$gpoSearcher.PropertiesToLoad.AddRange(@(
            "displayname", "whencreated", "whenchanged", "versionnumber",
            "gpcfilesyspath", "distinguishedname", "name", "flags"
        ))

        $gpoResults = $gpoSearcher.FindAll()
        try {
            foreach ($gpoResult in $gpoResults) {
                $props = $gpoResult.Properties

                $whenCreatedInfo = Get-AdDate -Entry $props -Name "whencreated"
                $whenChangedInfo = Get-AdDate -Entry $props -Name "whenchanged"

                $gpoObject = [PSCustomObject]@{
                    DisplayName       = Get-AdProp -Entry $props -Name "displayname" -Default "N/A"
                    WhenCreatedDisplay = $whenCreatedInfo.Display
                    WhenCreatedIso    = $whenCreatedInfo.Iso
                    WhenChangedDisplay = $whenChangedInfo.Display
                    WhenChangedIso    = $whenChangedInfo.Iso
                    VersionNumber     = Get-AdProp -Entry $props -Name "versionnumber" -Default "N/A"
                    GPCFileSysPath    = Get-AdProp -Entry $props -Name "gpcfilesyspath" -Default "N/A"
                    DistinguishedName = Get-AdProp -Entry $props -Name "distinguishedname" -Default "N/A"
                    Name              = Get-AdProp -Entry $props -Name "name" -Default "N/A"
                    Flags             = Get-AdProp -Entry $props -Name "flags" -Default "N/A"
                }

                [void]$script:Gpos.Add($gpoObject)
            }
        } finally {
            $gpoResults.Dispose()
        }
    } finally {
        $gpoSearcher.Dispose()
    }

    Write-Log -Message "Section 7: $($script:Gpos.Count) Group Policy Objects enumerated" -Level OK
} catch {
    Write-Log -Message "Section 7 failed: $($_.Exception.Message)" -Level ERROR
}

################################################################################
#              SECTION 8 - USER RIGHTS ASSIGNMENT (GptTmpl.inf)              #
################################################################################

Show-StepProgress -Status "Section 8: Extracting User Rights Assignment from GPOs"
Write-Log -Message "Section 8: extracting Privilege Rights from each GPO's GptTmpl.inf" -Level INFO

# Fixed privilege -> category table. Category here is a factual
# classification of what a Windows privilege constant IS (a logon right, a
# deny right, ...), never a judgement of whether its current assignment is
# appropriate.
$script:CriticalPrivileges = @(
    "SeDebugPrivilege", "SeTcbPrivilege", "SeImpersonatePrivilege",
    "SeAssignPrimaryTokenPrivilege", "SeLoadDriverPrivilege",
    "SeBackupPrivilege", "SeRestorePrivilege", "SeTakeOwnershipPrivilege",
    "SeSecurityPrivilege", "SeAuditPrivilege"
)
$script:HighLogonRights = @(
    "SeInteractiveLogonRight", "SeRemoteInteractiveLogonRight",
    "SeNetworkLogonRight", "SeBatchLogonRight", "SeServiceLogonRight"
)
$script:DenyLogonRights = @(
    "SeDenyBatchLogonRight", "SeDenyInteractiveLogonRight",
    "SeDenyRemoteInteractiveLogonRight", "SeDenyServiceLogonRight",
    "SeDenyNetworkLogonRight"
)
$script:MediumPrivileges = @(
    "SeSystemtimePrivilege", "SeCreatePagefilePrivilege", "SeCreateGlobalPrivilege",
    "SeCreatePermanentPrivilege", "SeCreateSymbolicLinkPrivilege", "SeCreateTokenPrivilege",
    "SeEnableDelegationPrivilege", "SeIncreaseBasePriorityPrivilege", "SeIncreaseQuotaPrivilege",
    "SeLockMemoryPrivilege", "SeManageVolumePrivilege", "SeProfileSingleProcessPrivilege",
    "SeRelabelPrivilege", "SeRemoteShutdownPrivilege", "SeShutdownPrivilege",
    "SeSyncAgentPrivilege", "SeSystemEnvironmentPrivilege", "SeSystemProfilePrivilege",
    "SeMachineAccountPrivilege", "SeTrustedCredManAccessPrivilege",
    "SeDelegateSessionUserImpersonatePrivilege"
)
$script:LowPrivileges = @(
    "SeChangeNotifyPrivilege", "SeTimeZonePrivilege", "SeUndockPrivilege",
    "SeIncreaseWorkingSetPrivilege"
)

function Get-PrivilegeCategory {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Privilege
    )
    if ($script:CriticalPrivileges -contains $Privilege) { return "CRITICAL" }
    if ($script:HighLogonRights    -contains $Privilege) { return "HIGH" }
    if ($script:DenyLogonRights    -contains $Privilege) { return "DENY" }
    if ($script:MediumPrivileges   -contains $Privilege) { return "MEDIUM" }
    if ($script:LowPrivileges      -contains $Privilege) { return "LOW" }
    return "OTHER"
}

function Get-PrivilegeRightsFromInf {
    <#
        Parses only the [Privilege Rights] section of a GptTmpl.inf: each
        line is "SePrivilegeName = *SID1,*SID2,Name3", principals comma
        separated and optionally prefixed with * for a raw SID.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$InfPath
    )

    $rows = New-Object System.Collections.ArrayList
    if (-not (Test-Path -Path $InfPath)) { return $rows }

    $content = Get-Content -Path $InfPath -Encoding Unicode -ErrorAction Stop

    $inPrivilegeSection = $false
    foreach ($line in $content) {
        $trimmedLine = $line.Trim()

        if ($trimmedLine -match '^\[(.+)\]$') {
            $inPrivilegeSection = ($Matches[1].Trim() -eq "Privilege Rights")
            continue
        }
        if (-not $inPrivilegeSection) { continue }
        if ([string]::IsNullOrWhiteSpace($trimmedLine)) { continue }

        $equalsIndex = $trimmedLine.IndexOf("=")
        if ($equalsIndex -lt 0) { continue }

        $privilegeName = $trimmedLine.Substring(0, $equalsIndex).Trim()
        $principalsRaw = $trimmedLine.Substring($equalsIndex + 1).Trim()

        $principalTokens = @()
        if ($principalsRaw) {
            $principalTokens = @($principalsRaw -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" })
        }

        [void]$rows.Add([PSCustomObject]@{
            Privilege  = $privilegeName
            Principals = $principalTokens
        })
    }

    return $rows
}

$script:UserRightsAssignments = New-Object System.Collections.ArrayList

try {
    foreach ($gpo in $script:Gpos) {
        if (-not $gpo.GPCFileSysPath -or $gpo.GPCFileSysPath -eq "N/A") { continue }

        # GPO "flags": bit 0x2 = User Configuration disabled is NOT what we
        # need here; bit layout is 0=both enabled,1=user disabled,
        # 2=computer disabled,3=both disabled, so computer settings are
        # active whenever bit 0x2 is clear.
        $computerConfigActive = $true
        try {
            $flagsValue = [int]$gpo.Flags
            $computerConfigActive = (-not [bool]($flagsValue -band 0x2))
        } catch {
            $computerConfigActive = $true
        }
        if (-not $computerConfigActive) { continue }

        $infPath = Join-Path -Path $gpo.GPCFileSysPath -ChildPath "Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"

        try {
            if (-not (Test-Path -Path $infPath)) { continue }

            $privilegeRows = Get-PrivilegeRightsFromInf -InfPath $infPath

            foreach ($row in $privilegeRows) {
                $category = Get-PrivilegeCategory -Privilege $row.Privilege

                [void]$script:UserRightsAssignments.Add([PSCustomObject]@{
                    GPOName    = $gpo.DisplayName
                    GPODn      = $gpo.DistinguishedName
                    Privilege  = $row.Privilege
                    Category   = $category
                    Principals = $row.Principals
                    InfPath    = $infPath
                })
            }
        } catch {
            Write-Log -Message "Section 8: failed to read GptTmpl.inf for GPO '$($gpo.DisplayName)': $($_.Exception.Message)" -Level WARN
        }
    }

    Write-Log -Message "Section 8: $($script:UserRightsAssignments.Count) privilege/principal rows extracted from $($script:Gpos.Count) GPOs" -Level OK
} catch {
    Write-Log -Message "Section 8 failed: $($_.Exception.Message)" -Level ERROR
}
