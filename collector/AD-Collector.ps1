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

# currentStep/totalSteps back Show-StepProgress. totalSteps matches the
# actual number of Show-StepProgress calls in this script (26, counted at
# the end of writing it); update this if a call is added or removed.
$script:totalSteps  = 26
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
    <#
        Each candidate flag is tested independently against $Rights rather
        than folded into one combined bitmask first: .NET's GenericAll is
        itself already a union of nearly every other bit (0xF01FF), so
        OR-ing it into a shared mask would make ANY right - including
        harmless ones like ReadProperty - match. Testing "all bits of this
        one flag are present" per candidate avoids that false-positive.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [System.DirectoryServices.ActiveDirectoryRights]$Rights
    )

    $privilegedFlags = @(
        [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
        [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite,
        [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl,
        [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner,
        [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
        [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
        [System.DirectoryServices.ActiveDirectoryRights]::CreateChild,
        [System.DirectoryServices.ActiveDirectoryRights]::DeleteChild
    )

    $rightsValue = [Int32]$Rights
    foreach ($flag in $privilegedFlags) {
        $flagValue = [Int32]$flag
        if (($rightsValue -band $flagValue) -eq $flagValue) { return $true }
    }

    return $false
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

    # Every Exchange container's privileged ACEs are collected first; principals
    # are then resolved and the delegation map is built ONCE over the combined
    # set, rather than building and merging a separate map per container - one
    # simpler pass with less surface area for a cross-container merge bug.
    $combinedAces = New-Object 'System.Collections.Generic.List[object]'

    foreach ($containerPath in $exchangeContainers) {
        try {
            if (-not [System.DirectoryServices.DirectoryEntry]::Exists("LDAP://$containerPath")) {
                Write-Log -Message "Exchange container ACL ($containerPath): container not found, skipping." -Level WARN
                continue
            }

            $entry = [ADSI]("LDAP://" + $containerPath)
            $acl   = $entry.psbase.ObjectSecurity

            foreach ($ace in (Get-PrivilegedAces -Acl $acl -ObjectDN $containerPath -EveryoneLike $script:EveryoneLikeTrustees)) {
                $combinedAces.Add($ace)
            }
        } catch {
            Write-Log -Message "Exchange container ACL ($containerPath) failed [$($_.Exception.GetType().FullName) at line $($_.InvocationInfo.ScriptLineNumber)]: $($_.Exception.Message)" -Level WARN
        }
    }

    $script:ExchangePrivilegedAces = @($combinedAces)

    $exchangePrincipals = New-Object 'System.Collections.Generic.List[object]'
    foreach ($ace in $script:ExchangePrivilegedAces) {
        $exchangePrincipals.Add((Resolve-Principal -Trustee $ace.Trustee))
    }

    $script:ExchangeDelegationPrincipals = Resolve-DelegationUsersMap `
        -Principals $exchangePrincipals `
        -UserIndex $script:UsersByDn `
        -UserBySam $script:UsersBySam `
        -GroupToUsers $script:GroupMembersIndex `
        -DirectLabel "Exchange container ACL (direct)" `
        -GroupPrefix "Exchange container ACL"

    Write-Log -Message "Section 5b: $($script:ExchangePrivilegedAces.Count) privileged ACEs, $($script:ExchangeDelegationPrincipals.Count) users resolved via delegation across Exchange containers" -Level OK
} catch {
    Write-Log -Message "Section 5b failed [$($_.Exception.GetType().FullName) at line $($_.InvocationInfo.ScriptLineNumber)]: $($_.Exception.Message)" -Level ERROR
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

# msDS-Behavior-Version conversion table. Microsoft never introduced a new
# domain/forest functional level for Server 2019 or 2022, so level 7 (first
# assigned to Server 2016) still covers all three; values 8/9 are
# reserved/unused, and the next assigned value is Server 2025 at 10.
$script:FunctionalLevelMap = @{
    0  = "Windows 2000"
    1  = "Windows Server 2003 Interim"
    2  = "Windows Server 2003"
    3  = "Windows Server 2008"
    4  = "Windows Server 2008 R2"
    5  = "Windows Server 2012"
    6  = "Windows Server 2012 R2"
    7  = "Windows Server 2016/2019/2022"
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
                    if ($metaText -notmatch "dSASignature") { continue }

                    # Parsed as XML rather than matched with a regex: more
                    # robust to attribute ordering/whitespace in the blob
                    # the LDAP server generates for this constructed attribute.
                    try {
                        $metaDoc = [xml]$metaText
                        $attributeName = $metaDoc.DS_REPL_ATTR_META_DATA.pszAttributeName
                        if ($attributeName -ne "dSASignature") { continue }

                        $rawTime = $metaDoc.DS_REPL_ATTR_META_DATA.ftimeLastOriginatingChange
                        if ([string]::IsNullOrWhiteSpace($rawTime)) { continue }

                        $parsedTime = [DateTime]::Parse(
                            $rawTime,
                            [System.Globalization.CultureInfo]::InvariantCulture,
                            [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal
                        )
                        $changeTimes.Add($parsedTime)
                    } catch {
                        # Unparseable/malformed metadata blob for this NC; the other naming contexts are still tried.
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

################################################################################
#           SID RESOLUTION INFRASTRUCTURE (USED BY SECTIONS 8 & 9)           #
################################################################################

Show-StepProgress -Status "Building SID resolution map"
Write-Log -Message "Building well-known/domain SID resolution map" -Level INFO

function Convert-ObjectSidToString {
    <#
        objectSid can come back from ADSI as a byte[], a boxed generic
        array (COM interop), or already as a string; normalize all three
        to the S-1-... textual form.
    #>
    param(
        [AllowNull()]
        $RawSid
    )

    if ($null -eq $RawSid) { return $null }

    try {
        if ($RawSid -is [string]) { return $RawSid }

        if ($RawSid -is [byte[]]) {
            return (New-Object System.Security.Principal.SecurityIdentifier($RawSid, 0)).Value
        }

        $byteArray = New-Object byte[] ($RawSid.Count)
        for ($i = 0; $i -lt $RawSid.Count; $i++) { $byteArray[$i] = [byte]$RawSid[$i] }
        return (New-Object System.Security.Principal.SecurityIdentifier($byteArray, 0)).Value
    } catch {
        return $null
    }
}

function Get-DomainSidString {
    param(
        [Parameter(Mandatory = $true)]
        [string]$NamingContextDn
    )
    try {
        $ncEntry = [ADSI]("LDAP://" + $NamingContextDn)
        $rawSid = $ncEntry.Properties["objectSid"][0]
        return Convert-ObjectSidToString -RawSid $rawSid
    } catch {
        return $null
    }
}

function Get-NetBiosNameForNamingContext {
    param(
        [Parameter(Mandatory = $true)]
        [string]$NamingContextDn
    )
    try {
        $partitionsPath = "CN=Partitions," + $script:ConfigurationNamingContext
        $crossRefSearchRoot = [ADSI]("LDAP://" + $partitionsPath)
        $crossRefSearcher = New-Object System.DirectoryServices.DirectorySearcher($crossRefSearchRoot)
        try {
            $escapedNc = ConvertTo-LdapFilterValue -Value $NamingContextDn
            $crossRefSearcher.Filter = "(&(objectClass=crossRef)(nCName=$escapedNc))"
            [void]$crossRefSearcher.PropertiesToLoad.AddRange(@("netbiosname"))
            $found = $crossRefSearcher.FindOne()
            if ($found) {
                return Get-AdProp -Entry $found.Properties -Name "netbiosname" -Default $null
            }
        } finally {
            $crossRefSearcher.Dispose()
        }
    } catch {
        return $null
    }
    return $null
}

function Initialize-WellKnownSidFallbackMap {
    <#
        Universal and local-account well-known SIDs are a small, stable,
        publicly documented set and are hardcoded below. BUILTIN aliases
        (S-1-5-32-544..582) are instead resolved live through NTAccount
        translation, which works locally on any Windows host without
        needing AD - the OS is the authoritative source for those names
        rather than a hand-typed table; a RID this OS does not define
        falls back to a plain "BUILTIN\Alias-<RID>" label instead of a
        guessed name.
    #>
    $map = @{
        "S-1-0-0"            = "NULL SID"
        "S-1-1-0"            = "Everyone"
        "S-1-3-0"            = "CREATOR OWNER"
        "S-1-3-1"            = "CREATOR GROUP"
        "S-1-5-2"            = "NT AUTHORITY\NETWORK"
        "S-1-5-3"            = "NT AUTHORITY\BATCH"
        "S-1-5-4"            = "NT AUTHORITY\INTERACTIVE"
        "S-1-5-6"            = "NT AUTHORITY\SERVICE"
        "S-1-5-7"            = "NT AUTHORITY\ANONYMOUS LOGON"
        "S-1-5-8"            = "NT AUTHORITY\PROXY"
        "S-1-5-9"            = "NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS"
        "S-1-5-10"           = "NT AUTHORITY\SELF"
        "S-1-5-11"           = "NT AUTHORITY\Authenticated Users"
        "S-1-5-12"           = "NT AUTHORITY\RESTRICTED"
        "S-1-5-13"           = "NT AUTHORITY\TERMINAL SERVER USER"
        "S-1-5-14"           = "NT AUTHORITY\REMOTE INTERACTIVE LOGON"
        "S-1-5-15"           = "NT AUTHORITY\THIS ORGANIZATION"
        "S-1-5-17"           = "NT AUTHORITY\IUSR"
        "S-1-5-18"           = "NT AUTHORITY\SYSTEM"
        "S-1-5-19"           = "NT AUTHORITY\LOCAL SERVICE"
        "S-1-5-20"           = "NT AUTHORITY\NETWORK SERVICE"
        "S-1-5-33"           = "NT AUTHORITY\WRITE RESTRICTED"
        "S-1-5-80-0"         = "NT SERVICE\ALL SERVICES"
        "S-1-5-84-0-0-0-0-0" = "Font Driver Host\UMFD-0"
        "S-1-5-90-0"         = "Window Manager\DWM-1"
        "S-1-5-1000"         = "NT AUTHORITY\Other Organization"
        "S-1-5-113"          = "NT AUTHORITY\Local account"
        "S-1-5-114"          = "NT AUTHORITY\Local account and member of Administrators group"
        "S-1-15-2-1"         = "APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES"
        "S-1-18-1"           = "Authentication authority asserted identity"
        "S-1-18-2"           = "Service asserted identity"
    }

    for ($rid = 544; $rid -le 582; $rid++) {
        $builtinSid = "S-1-5-32-$rid"
        $resolvedName = $null
        try {
            $sidObj = New-Object System.Security.Principal.SecurityIdentifier($builtinSid)
            $resolvedName = $sidObj.Translate([System.Security.Principal.NTAccount]).Value
        } catch {
            $resolvedName = $null
        }
        if ($resolvedName) {
            $map[$builtinSid] = $resolvedName
        } else {
            $map[$builtinSid] = "BUILTIN\Alias-$rid"
        }
    }

    return $map
}

# Domain-relative well-known RIDs, applied below to both the current domain
# SID and the forest root domain SID.
# RIDs that exist as real accounts/groups in EVERY domain of the forest.
$script:DomainRidNames = @{
    500 = "Administrator"
    501 = "Guest"
    502 = "krbtgt"
    512 = "Domain Admins"
    513 = "Domain Users"
    514 = "Domain Guests"
    515 = "Domain Computers"
    516 = "Domain Controllers"
    517 = "Cert Publishers"
    520 = "Group Policy Creator Owners"
    521 = "Read-only Domain Controllers"
    525 = "Protected Users"
    526 = "Key Admins"
}

# RIDs for universal groups that Windows creates ONLY in the forest root
# domain - Schema/Enterprise Admins, Enterprise Key Admins and the
# Enterprise RODC group are not per-domain, unlike the table above.
$script:ForestRootOnlyRidNames = @{
    498 = "Enterprise Read-only Domain Controllers"
    518 = "Schema Admins"
    519 = "Enterprise Admins"
    527 = "Enterprise Key Admins"
}

$script:CurrentDomainSid        = $null
$script:CurrentDomainNetBios    = "DOMAIN"
$script:RootDomainNamingContext = $null
$script:ForestRootDomainSid     = $null
$script:ForestRootDomainNetBios = "FORESTROOT"
$script:WellKnownSidMap         = @{}
$script:SidResolutionCache      = @{}

try {
    $script:CurrentDomainSid = Get-DomainSidString -NamingContextDn $script:BaseDN
    $currentNetBios = Get-NetBiosNameForNamingContext -NamingContextDn $script:BaseDN
    if ($currentNetBios) { $script:CurrentDomainNetBios = $currentNetBios }

    $rootDseForForest = [ADSI]"LDAP://RootDSE"
    $script:RootDomainNamingContext = $rootDseForForest.Properties["rootDomainNamingContext"][0]

    if ($script:RootDomainNamingContext) {
        $script:ForestRootDomainSid = Get-DomainSidString -NamingContextDn $script:RootDomainNamingContext
        $forestNetBios = Get-NetBiosNameForNamingContext -NamingContextDn $script:RootDomainNamingContext
        if ($forestNetBios) { $script:ForestRootDomainNetBios = $forestNetBios }
    }

    $script:WellKnownSidMap = Initialize-WellKnownSidFallbackMap

    foreach ($ridEntry in $script:DomainRidNames.GetEnumerator()) {
        if ($script:CurrentDomainSid) {
            $script:WellKnownSidMap["$($script:CurrentDomainSid)-$($ridEntry.Key)"] = "$($script:CurrentDomainNetBios)\$($ridEntry.Value)"
        }
        if ($script:ForestRootDomainSid -and $script:ForestRootDomainSid -ne $script:CurrentDomainSid) {
            $script:WellKnownSidMap["$($script:ForestRootDomainSid)-$($ridEntry.Key)"] = "$($script:ForestRootDomainNetBios)\$($ridEntry.Value)"
        }
    }

    # Forest-root-only universal groups: registered solely under the forest
    # root domain SID, falling back to the current domain SID when this
    # domain IS the forest root (ForestRootDomainSid then equals it, or is
    # unset if the root domain naming context could not be read).
    $forestRootSidForUniversalGroups     = $script:ForestRootDomainSid
    $forestRootNetBiosForUniversalGroups = $script:ForestRootDomainNetBios
    if (-not $forestRootSidForUniversalGroups) {
        $forestRootSidForUniversalGroups     = $script:CurrentDomainSid
        $forestRootNetBiosForUniversalGroups = $script:CurrentDomainNetBios
    }
    if ($forestRootSidForUniversalGroups) {
        foreach ($ridEntry in $script:ForestRootOnlyRidNames.GetEnumerator()) {
            $script:WellKnownSidMap["$forestRootSidForUniversalGroups-$($ridEntry.Key)"] = "$forestRootNetBiosForUniversalGroups\$($ridEntry.Value)"
        }
    }

    Write-Log -Message "SID resolution map ready ($($script:WellKnownSidMap.Count) well-known entries)" -Level OK
} catch {
    Write-Log -Message "SID resolution map build failed: $($_.Exception.Message)" -Level WARN
}

function Resolve-Sid {
    <#
        Resolution order: cache, well-known/domain-RID map, LDAP lookup by
        objectSid (works off a domain controller too), then NTAccount
        translation for per-service/per-package virtual SIDs
        (S-1-5-80-<hash>, S-1-5-99-<hash>). An orphaned SID that none of
        these resolve is reported as such rather than guessed.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Sid
    )

    if ($script:SidResolutionCache.ContainsKey($Sid)) {
        return $script:SidResolutionCache[$Sid]
    }

    $resolvedName = $null

    if ($script:WellKnownSidMap.ContainsKey($Sid)) {
        $resolvedName = $script:WellKnownSidMap[$Sid]
    }

    if (-not $resolvedName) {
        try {
            $escapedSid = ConvertTo-LdapFilterValue -Value $Sid
            $sidSearchRoot = [ADSI]("LDAP://" + $script:BaseDN)
            $sidSearcher = New-Object System.DirectoryServices.DirectorySearcher($sidSearchRoot)
            try {
                $sidSearcher.Filter = "(objectSid=$escapedSid)"
                [void]$sidSearcher.PropertiesToLoad.AddRange(@("samaccountname"))
                $found = $sidSearcher.FindOne()
                if ($found) {
                    $sam = Get-AdProp -Entry $found.Properties -Name "samaccountname" -Default $null
                    if ($sam) { $resolvedName = "$($script:CurrentDomainNetBios)\$sam" }
                }
            } finally {
                $sidSearcher.Dispose()
            }
        } catch {
            $resolvedName = $null
        }
    }

    if (-not $resolvedName -and $Sid -match '^S-1-5-(80|99)-') {
        try {
            $sidObj = New-Object System.Security.Principal.SecurityIdentifier($Sid)
            $resolvedName = $sidObj.Translate([System.Security.Principal.NTAccount]).Value
        } catch {
            $resolvedName = $null
        }
    }

    if (-not $resolvedName) { $resolvedName = "$Sid [unresolved]" }

    $script:SidResolutionCache[$Sid] = $resolvedName
    return $resolvedName
}

Write-Log -Message "Resolving principals for User Rights Assignment rows" -Level INFO
try {
    foreach ($row in $script:UserRightsAssignments) {
        $resolvedPrincipals = New-Object 'System.Collections.Generic.List[string]'
        foreach ($principalToken in $row.Principals) {
            if ($principalToken.StartsWith("*")) {
                $resolvedPrincipals.Add((Resolve-Sid -Sid $principalToken.Substring(1)))
            } else {
                $resolvedPrincipals.Add($principalToken)
            }
        }
        Add-Member -InputObject $row -MemberType NoteProperty -Name "PrincipalsResolved" -Value (@($resolvedPrincipals)) -Force
    }
    Write-Log -Message "PrincipalsResolved added to $($script:UserRightsAssignments.Count) User Rights Assignment rows" -Level OK
} catch {
    Write-Log -Message "PrincipalsResolved enrichment failed: $($_.Exception.Message)" -Level WARN
}

################################################################################
#              SECTION 9 - TIER-LEVEL GPO COVERAGE AND CONFLICTS             #
################################################################################

Show-StepProgress -Status "Section 9: Analyzing tier-level GPO coverage"

$script:TierGpoCoverage = [PSCustomObject]@{
    TierGpo          = $null
    CommonPrincipals = @()
    OUsNotApplied    = @()
    ConflictGpos     = @()
    ConflictOUs      = @()
}

if (-not $script:RsatAvailable) {
    Write-Log -Message "Section 9 skipped: $($script:RsatWarning)" -Level WARN
} else {
    Write-Log -Message "Section 9: analyzing tier-level GPO coverage and conflicts" -Level INFO

    try {
        # GPODn -> { Privilege -> HashSet[string] of raw SIDs (no '*' prefix) },
        # so the five deny-right principal sets for a GPO can be intersected.
        $gpoDenyRights = @{}

        foreach ($row in $script:UserRightsAssignments) {
            if ($script:DenyLogonRights -notcontains $row.Privilege) { continue }

            if (-not $gpoDenyRights.ContainsKey($row.GPODn)) {
                $gpoDenyRights[$row.GPODn] = @{}
            }

            $sidSet = New-Object 'System.Collections.Generic.HashSet[string]'
            foreach ($principalToken in $row.Principals) {
                $rawToken = $principalToken
                if ($rawToken.StartsWith("*")) { $rawToken = $rawToken.Substring(1) }
                [void]$sidSet.Add($rawToken)
            }
            $gpoDenyRights[$row.GPODn][$row.Privilege] = $sidSet
        }

        # A "tier GPO" is the one GPO that configures all five deny-logon
        # rights together; only the first one found is treated as the tier
        # GPO, mirroring the spec's single-GPO tiering model.
        $tierGpoDn  = $null
        $commonSids = @()

        foreach ($gpoDn in $gpoDenyRights.Keys) {
            $rightsPresent = $gpoDenyRights[$gpoDn].Keys
            $hasAllFive = $true
            foreach ($denyRight in $script:DenyLogonRights) {
                if ($rightsPresent -notcontains $denyRight) { $hasAllFive = $false; break }
            }
            if (-not $hasAllFive) { continue }

            $tierGpoDn = $gpoDn

            $intersection = $null
            foreach ($denyRight in $script:DenyLogonRights) {
                $currentSet = $gpoDenyRights[$gpoDn][$denyRight]
                if ($null -eq $intersection) {
                    $intersection = [System.Collections.Generic.HashSet[string]]::new($currentSet)
                } else {
                    $intersection.IntersectWith($currentSet)
                }
            }
            $commonSids = @($intersection)
            break
        }

        if (-not $tierGpoDn) {
            Write-Log -Message "Section 9: no single GPO configures all five deny-logon rights together. Verify whether the same principal is instead configured for these five rights spread across multiple GPOs." -Level WARN
        } else {
            $tierGpoObject = $script:Gpos | Where-Object { $_.DistinguishedName -eq $tierGpoDn } | Select-Object -First 1
            $script:TierGpoCoverage.TierGpo          = $tierGpoObject
            $script:TierGpoCoverage.CommonPrincipals = @($commonSids | ForEach-Object { Resolve-Sid -Sid $_ })

            # Coverage/conflict analysis works off each OU's own direct GPO
            # links (Get-GPInheritance), ordered by link Order (1 = highest
            # precedence, applied last). Cross-level precedence against
            # parent-OU/domain/site links is not modeled here.
            $ousNotApplied = New-Object System.Collections.ArrayList
            $conflictGpos  = New-Object System.Collections.ArrayList
            $conflictOUs   = New-Object System.Collections.ArrayList

            try {
                $allOUs = Get-ADOrganizationalUnit -Filter * -ErrorAction Stop

                foreach ($ou in $allOUs) {
                    try {
                        $inheritance = Get-GPInheritance -Target $ou.DistinguishedName -ErrorAction Stop
                        $sortedLinks = @($inheritance.GpoLinks | Where-Object { $_.Enabled } | Sort-Object Order)

                        $tierGpoOrder = $null
                        foreach ($link in $sortedLinks) {
                            $linkedGpo = $script:Gpos | Where-Object {
                                $_.Name -and $_.Name.Trim('{', '}').Equals($link.GpoId.ToString(), [StringComparison]::OrdinalIgnoreCase)
                            } | Select-Object -First 1

                            if ($linkedGpo -and $linkedGpo.DistinguishedName -eq $tierGpoDn) {
                                $tierGpoOrder = $link.Order
                                break
                            }
                        }

                        if ($null -eq $tierGpoOrder) {
                            [void]$ousNotApplied.Add($ou.DistinguishedName)
                        } else {
                            foreach ($link in $sortedLinks) {
                                if ($link.Order -ge $tierGpoOrder) { continue }

                                $precedingGpo = $script:Gpos | Where-Object {
                                    $_.Name -and $_.Name.Trim('{', '}').Equals($link.GpoId.ToString(), [StringComparison]::OrdinalIgnoreCase)
                                } | Select-Object -First 1

                                if ($precedingGpo -and $precedingGpo.DistinguishedName -ne $tierGpoDn) {
                                    $precedingDenyRights = $gpoDenyRights[$precedingGpo.DistinguishedName]
                                    if ($precedingDenyRights -and $precedingDenyRights.Count -gt 0) {
                                        [void]$conflictGpos.Add($precedingGpo.DistinguishedName)
                                        [void]$conflictOUs.Add($ou.DistinguishedName)
                                    }
                                }
                            }
                        }
                    } catch {
                        Write-Log -Message "Section 9: GPO inheritance check failed for OU '$($ou.DistinguishedName)': $($_.Exception.Message)" -Level WARN
                    }
                }
            } catch {
                Write-Log -Message "Section 9: unable to enumerate organizational units: $($_.Exception.Message)" -Level WARN
            }

            $script:TierGpoCoverage.OUsNotApplied = @($ousNotApplied)
            $script:TierGpoCoverage.ConflictGpos  = @($conflictGpos | Select-Object -Unique)
            $script:TierGpoCoverage.ConflictOUs   = @($conflictOUs | Select-Object -Unique)

            Write-Log -Message "Section 9: tier GPO identified ('$($tierGpoObject.DisplayName)'), $($script:TierGpoCoverage.OUsNotApplied.Count) OUs not covered, $($script:TierGpoCoverage.ConflictOUs.Count) OUs with a conflicting GPO" -Level OK
        }
    } catch {
        Write-Log -Message "Section 9 failed: $($_.Exception.Message)" -Level ERROR
    }
}

################################################################################
#                    SECTION 10 - KRBTGT ACCOUNT PASSWORD AGE                #
################################################################################

Show-StepProgress -Status "Section 10: Reading krbtgt account password age"
Write-Log -Message "Section 10: reading krbtgt pwdLastSet" -Level INFO

$script:Krbtgt = [PSCustomObject]@{
    Found             = $false
    DistinguishedName = "N/A"
    PwdLastSetDisplay = "N/A"
    PwdLastSetIso     = ""
}

try {
    $krbtgtSearchRoot = [ADSI]("LDAP://" + $script:BaseDN)
    $krbtgtSearcher = New-Object System.DirectoryServices.DirectorySearcher($krbtgtSearchRoot)
    try {
        $krbtgtSearcher.Filter = "(&(objectCategory=person)(objectClass=user)(samAccountName=krbtgt))"
        [void]$krbtgtSearcher.PropertiesToLoad.AddRange(@("distinguishedname", "pwdlastset"))

        $krbtgtFound = $krbtgtSearcher.FindOne()
        if ($krbtgtFound) {
            $pwdInfo = Get-AdDate -Entry $krbtgtFound.Properties -Name "pwdlastset" -FileTime
            $script:Krbtgt.Found             = $true
            $script:Krbtgt.DistinguishedName = Get-AdProp -Entry $krbtgtFound.Properties -Name "distinguishedname" -Default "N/A"
            $script:Krbtgt.PwdLastSetDisplay = $pwdInfo.Display
            $script:Krbtgt.PwdLastSetIso     = $pwdInfo.Iso
        }
    } finally {
        $krbtgtSearcher.Dispose()
    }

    Write-Log -Message "Section 10: krbtgt pwdLastSet = $($script:Krbtgt.PwdLastSetDisplay)" -Level OK
} catch {
    Write-Log -Message "Section 10 failed: $($_.Exception.Message)" -Level ERROR
}

################################################################################
#                     SECTION 11 - KERBEROASTABLE ACCOUNTS                   #
################################################################################

Show-StepProgress -Status "Section 11: Enumerating kerberoastable accounts"
Write-Log -Message "Section 11: enumerating accounts with an SPN that are not disabled" -Level INFO

$script:Kerberoastable                = New-Object System.Collections.ArrayList
$script:KerberoastableDnSet           = New-Object 'System.Collections.Generic.HashSet[string]'
$script:KerberoastablePrivilegedCount = 0

try {
    $kerbSearchRoot = [ADSI]("LDAP://" + $script:BaseDN)
    $kerbSearcher = New-Object System.DirectoryServices.DirectorySearcher($kerbSearchRoot)
    try {
        # LDAP_MATCHING_RULE_BIT_AND on userAccountControl, negated, excludes
        # disabled accounts (bit 0x2) without needing a second query.
        $kerbSearcher.Filter   = "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        $kerbSearcher.PageSize = 1000
        [void]$kerbSearcher.PropertiesToLoad.AddRange(@(
            "distinguishedname", "samaccountname", "serviceprincipalname",
            "pwdlastset", "whencreated", "lastlogontimestamp", "useraccountcontrol",
            "admincount", "accountexpires", "sidhistory", "msds-supportedencryptiontypes"
        ))

        $kerbResults = $kerbSearcher.FindAll()
        try {
            foreach ($kerbResult in $kerbResults) {
                $props = $kerbResult.Properties

                $dn = Get-AdProp -Entry $props -Name "distinguishedname" -Default "N/A"

                $spns = @()
                if ($props.Contains("serviceprincipalname")) {
                    foreach ($spnValue in $props["serviceprincipalname"]) { $spns += [string]$spnValue }
                }

                $adminCountValue = 0
                try {
                    if ($props.Contains("admincount") -and $props["admincount"].Count -gt 0) {
                        $adminCountValue = [Int32]$props["admincount"][0]
                    }
                } catch { $adminCountValue = 0 }
                $isPrivileged = [bool]($adminCountValue -eq 1)

                $pwdLastSetInfo = Get-AdDate -Entry $props -Name "pwdlastset" -FileTime
                $lastLogonInfo  = Get-AdDate -Entry $props -Name "lastlogontimestamp" -FileTime

                $base = [ordered]@{
                    DistinguishedName         = $dn
                    SamAccountName             = Get-AdProp -Entry $props -Name "samaccountname" -Default "N/A"
                    ServicePrincipalNames      = $spns
                    PwdLastSetDisplay          = $pwdLastSetInfo.Display
                    PwdLastSetIso              = $pwdLastSetInfo.Iso
                    LastLogonTimestampDisplay  = $lastLogonInfo.Display
                    LastLogonTimestampIso      = $lastLogonInfo.Iso
                    IsPrivileged               = $isPrivileged
                    AdminCount                 = $adminCountValue
                    SupportedEncryptionTypes   = Get-AdProp -Entry $props -Name "msds-supportedencryptiontypes" -Default "N/A"
                }

                $kerbObject = New-AccountObject -Base $base -Result $kerbResult
                [void]$script:Kerberoastable.Add($kerbObject)

                if ($dn -and $dn -ne "N/A") { [void]$script:KerberoastableDnSet.Add($dn.ToLowerInvariant()) }
                if ($isPrivileged) { $script:KerberoastablePrivilegedCount++ }
            }
        } finally {
            $kerbResults.Dispose()
        }
    } finally {
        $kerbSearcher.Dispose()
    }

    Write-Log -Message "Section 11: $($script:Kerberoastable.Count) kerberoastable accounts found ($($script:KerberoastablePrivilegedCount) privileged)" -Level OK
} catch {
    Write-Log -Message "Section 11 failed: $($_.Exception.Message)" -Level ERROR
}

################################################################################
#                    SECTION 12 - AS-REP ROASTABLE ACCOUNTS                  #
################################################################################

Show-StepProgress -Status "Section 12: Enumerating AS-REP roastable accounts"
Write-Log -Message "Section 12: enumerating accounts with Kerberos pre-authentication disabled" -Level INFO

$script:AsrepRoastable                = New-Object System.Collections.ArrayList
$script:AsrepRoastablePrivilegedCount = 0

try {
    $asrepSearchRoot = [ADSI]("LDAP://" + $script:BaseDN)
    $asrepSearcher = New-Object System.DirectoryServices.DirectorySearcher($asrepSearchRoot)
    try {
        # 4194304 = 0x400000 = DONT_REQ_PREAUTH, again excluding disabled accounts.
        $asrepSearcher.Filter   = "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        $asrepSearcher.PageSize = 1000
        [void]$asrepSearcher.PropertiesToLoad.AddRange(@(
            "distinguishedname", "samaccountname", "pwdlastset", "whencreated",
            "lastlogontimestamp", "useraccountcontrol", "admincount",
            "accountexpires", "sidhistory"
        ))

        $asrepResults = $asrepSearcher.FindAll()
        try {
            foreach ($asrepResult in $asrepResults) {
                $props = $asrepResult.Properties

                $dn = Get-AdProp -Entry $props -Name "distinguishedname" -Default "N/A"

                $adminCountValue = 0
                try {
                    if ($props.Contains("admincount") -and $props["admincount"].Count -gt 0) {
                        $adminCountValue = [Int32]$props["admincount"][0]
                    }
                } catch { $adminCountValue = 0 }
                $isPrivileged = [bool]($adminCountValue -eq 1)

                $isAlsoKerberoastable = $false
                if ($dn -and $dn -ne "N/A") {
                    $isAlsoKerberoastable = $script:KerberoastableDnSet.Contains($dn.ToLowerInvariant())
                }

                $pwdLastSetInfo = Get-AdDate -Entry $props -Name "pwdlastset" -FileTime
                $lastLogonInfo  = Get-AdDate -Entry $props -Name "lastlogontimestamp" -FileTime

                $base = [ordered]@{
                    DistinguishedName         = $dn
                    SamAccountName             = Get-AdProp -Entry $props -Name "samaccountname" -Default "N/A"
                    PwdLastSetDisplay          = $pwdLastSetInfo.Display
                    PwdLastSetIso              = $pwdLastSetInfo.Iso
                    LastLogonTimestampDisplay  = $lastLogonInfo.Display
                    LastLogonTimestampIso      = $lastLogonInfo.Iso
                    IsPrivileged               = $isPrivileged
                    AdminCount                 = $adminCountValue
                    IsAlsoKerberoastable       = $isAlsoKerberoastable
                }

                $asrepObject = New-AccountObject -Base $base -Result $asrepResult
                [void]$script:AsrepRoastable.Add($asrepObject)

                if ($isPrivileged) { $script:AsrepRoastablePrivilegedCount++ }
            }
        } finally {
            $asrepResults.Dispose()
        }
    } finally {
        $asrepSearcher.Dispose()
    }

    Write-Log -Message "Section 12: $($script:AsrepRoastable.Count) AS-REP roastable accounts found ($($script:AsrepRoastablePrivilegedCount) privileged)" -Level OK
} catch {
    Write-Log -Message "Section 12 failed: $($_.Exception.Message)" -Level ERROR
}

################################################################################
#                 SECTION 13 - BUILT-IN GUEST ACCOUNT (RID 501)              #
################################################################################

Show-StepProgress -Status "Section 13: Locating the built-in Guest account by RID"
Write-Log -Message "Section 13: locating the built-in Guest account via RID 501 (stable even if renamed)" -Level INFO

$script:GuestAccount = [PSCustomObject]@{
    Found              = $false
    Sid                = $null
    SamAccountName     = "N/A"
    IsRenamed          = $false
    IsDisabled         = $false
    WhenCreatedDisplay = "N/A"
    WhenCreatedIso     = ""
    PwdLastSetDisplay  = "N/A"
    PwdLastSetIso      = ""
    AdminCount         = 0
    MemberOf           = @()
}

try {
    if ($script:CurrentDomainSid) {
        $guestSid = "$($script:CurrentDomainSid)-501"
        $escapedGuestSid = ConvertTo-LdapFilterValue -Value $guestSid

        $guestSearchRoot = [ADSI]("LDAP://" + $script:BaseDN)
        $guestSearcher = New-Object System.DirectoryServices.DirectorySearcher($guestSearchRoot)
        try {
            $guestSearcher.Filter = "(objectSid=$escapedGuestSid)"
            [void]$guestSearcher.PropertiesToLoad.AddRange(@(
                "samaccountname", "useraccountcontrol", "whencreated",
                "pwdlastset", "admincount", "memberof"
            ))

            $guestFound = $guestSearcher.FindOne()
            if ($guestFound) {
                $props = $guestFound.Properties

                $uac = 0
                try {
                    if ($props.Contains("useraccountcontrol") -and $props["useraccountcontrol"].Count -gt 0) {
                        $uac = [Int64]$props["useraccountcontrol"][0]
                    }
                } catch { $uac = 0 }

                $adminCountValue = 0
                try {
                    if ($props.Contains("admincount") -and $props["admincount"].Count -gt 0) {
                        $adminCountValue = [Int32]$props["admincount"][0]
                    }
                } catch { $adminCountValue = 0 }

                $memberOf = @()
                if ($props.Contains("memberof")) {
                    foreach ($m in $props["memberof"]) { $memberOf += [string]$m }
                }

                $samAccountName  = Get-AdProp -Entry $props -Name "samaccountname" -Default "N/A"
                $whenCreatedInfo = Get-AdDate -Entry $props -Name "whencreated"
                $pwdLastSetInfo  = Get-AdDate -Entry $props -Name "pwdlastset" -FileTime

                $script:GuestAccount.Found              = $true
                $script:GuestAccount.Sid                = $guestSid
                $script:GuestAccount.SamAccountName     = $samAccountName
                $script:GuestAccount.IsRenamed          = (-not $samAccountName.Equals("Guest", [StringComparison]::OrdinalIgnoreCase))
                $script:GuestAccount.IsDisabled         = [bool]($uac -band 0x2)
                $script:GuestAccount.WhenCreatedDisplay = $whenCreatedInfo.Display
                $script:GuestAccount.WhenCreatedIso     = $whenCreatedInfo.Iso
                $script:GuestAccount.PwdLastSetDisplay  = $pwdLastSetInfo.Display
                $script:GuestAccount.PwdLastSetIso      = $pwdLastSetInfo.Iso
                $script:GuestAccount.AdminCount         = $adminCountValue
                $script:GuestAccount.MemberOf           = $memberOf
            }
        } finally {
            $guestSearcher.Dispose()
        }
    }

    Write-Log -Message "Section 13: Guest account found=$($script:GuestAccount.Found), renamed=$($script:GuestAccount.IsRenamed)" -Level OK
} catch {
    Write-Log -Message "Section 13 failed: $($_.Exception.Message)" -Level ERROR
}

################################################################################
#               SECTION 14 - MSOL_ AZURE AD CONNECT SERVICE ACCOUNTS         #
################################################################################

Show-StepProgress -Status "Section 14: Enumerating MSOL_ service accounts"
Write-Log -Message "Section 14: enumerating accounts with samAccountName starting with MSOL_" -Level INFO

$script:MsolAccounts = New-Object System.Collections.ArrayList

try {
    $msolSearchRoot = [ADSI]("LDAP://" + $script:BaseDN)
    $msolSearcher = New-Object System.DirectoryServices.DirectorySearcher($msolSearchRoot)
    try {
        $msolSearcher.Filter = "(&(objectCategory=person)(objectClass=user)(samAccountName=MSOL_*))"
        [void]$msolSearcher.PropertiesToLoad.AddRange(@("samaccountname", "distinguishedname", "objectsid"))

        $msolResults = $msolSearcher.FindAll()
        try {
            foreach ($msolResult in $msolResults) {
                $props = $msolResult.Properties

                $rawSid = $null
                if ($props.Contains("objectsid") -and $props["objectsid"].Count -gt 0) {
                    $rawSid = $props["objectsid"][0]
                }

                [void]$script:MsolAccounts.Add([PSCustomObject]@{
                    SamAccountName    = Get-AdProp -Entry $props -Name "samaccountname" -Default "N/A"
                    DistinguishedName = Get-AdProp -Entry $props -Name "distinguishedname" -Default "N/A"
                    ObjectSid         = Convert-ObjectSidToString -RawSid $rawSid
                })
            }
        } finally {
            $msolResults.Dispose()
        }
    } finally {
        $msolSearcher.Dispose()
    }

    Write-Log -Message "Section 14: $($script:MsolAccounts.Count) MSOL_ accounts found" -Level OK
} catch {
    Write-Log -Message "Section 14 failed: $($_.Exception.Message)" -Level ERROR
}

################################################################################
#                        SECTION 15 - LAPS DEPLOYMENT STATE                  #
################################################################################

Show-StepProgress -Status "Section 15: Determining LAPS deployment state"
Write-Log -Message "Section 15: checking schema for LAPS attributes and counting populated expirations" -Level INFO

function Test-SchemaAttributePresent {
    <#
        Querying an attribute that does not exist in the schema is itself an
        LDAP error, so schema presence has to be checked first and each LAPS
        generation's computer count only queried for the versions actually
        found.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$LdapDisplayName
    )
    try {
        $escapedName = ConvertTo-LdapFilterValue -Value $LdapDisplayName
        $schemaSearchRoot = [ADSI]("LDAP://" + $script:SchemaNamingContext)
        $schemaSearcher = New-Object System.DirectoryServices.DirectorySearcher($schemaSearchRoot)
        try {
            $schemaSearcher.Filter = "(&(objectClass=attributeSchema)(lDAPDisplayName=$escapedName))"
            [void]$schemaSearcher.PropertiesToLoad.AddRange(@("ldapdisplayname"))
            $found = $schemaSearcher.FindOne()
            return [bool]$found
        } finally {
            $schemaSearcher.Dispose()
        }
    } catch {
        return $false
    }
}

$script:Laps = [PSCustomObject]@{
    LegacyPresentInSchema          = $false
    LegacyExpiryPopulatedCount     = 0
    ModernPasswordPresentInSchema  = $false
    ModernEncryptedPresentInSchema = $false
    ModernExpiryPopulatedCount     = 0
}

try {
    $script:Laps.LegacyPresentInSchema          = Test-SchemaAttributePresent -LdapDisplayName "ms-Mcs-AdmPwd"
    $script:Laps.ModernPasswordPresentInSchema  = Test-SchemaAttributePresent -LdapDisplayName "msLAPS-Password"
    $script:Laps.ModernEncryptedPresentInSchema = Test-SchemaAttributePresent -LdapDisplayName "msLAPS-EncryptedPassword"

    if ($script:Laps.LegacyPresentInSchema) {
        $script:Laps.LegacyExpiryPopulatedCount = @($script:Computers | Where-Object { $_.LapsLegacyExpirationIso }).Count
    }

    if ($script:Laps.ModernPasswordPresentInSchema -or $script:Laps.ModernEncryptedPresentInSchema) {
        $script:Laps.ModernExpiryPopulatedCount = @($script:Computers | Where-Object { $_.LapsWindowsExpirationIso }).Count
    }

    Write-Log -Message "Section 15: legacy LAPS in schema=$($script:Laps.LegacyPresentInSchema), Windows LAPS in schema=$($script:Laps.ModernPasswordPresentInSchema -or $script:Laps.ModernEncryptedPresentInSchema)" -Level OK
} catch {
    Write-Log -Message "Section 15 failed: $($_.Exception.Message)" -Level ERROR
}

################################################################################
#         SECTIONS 16-19 - REMOTE COLLECTION (WMI/CIM ON MEMBER SERVERS)     #
################################################################################

$script:CollectionErrors     = New-Object System.Collections.ArrayList
$script:RemoteOsInfo         = New-Object System.Collections.ArrayList
$script:RemoteScheduledTasks = New-Object System.Collections.ArrayList
$script:RemoteLocalAccounts  = New-Object System.Collections.ArrayList
$script:RemoteServices       = New-Object System.Collections.ArrayList
$script:ServersTargeted      = 0
$script:ServersReached       = 0
$script:ServersFailed        = 0

# Self-contained worker: runspaces do not share the parent's script scope, so
# every value it needs (ComputerName, TimeoutSeconds) is passed in as a
# parameter rather than read from $script:... state.
$script:RemoteWorkerScript = {
    param(
        [string]$ComputerName,
        [int]$TimeoutSeconds
    )

    $workerErrors = New-Object System.Collections.ArrayList

    function Add-CollectionError {
        param($Section, $Protocol, $Message)
        [void]$workerErrors.Add([PSCustomObject]@{
            ComputerName = $ComputerName
            Section      = $Section
            Protocol     = $Protocol
            Message      = $Message
        })
    }

    $result = [PSCustomObject]@{
        ComputerName   = $ComputerName
        Reached        = $false
        Protocol       = $null
        OsInfo         = $null
        ScheduledTasks = New-Object System.Collections.ArrayList
        LocalAccounts  = $null
        Services       = New-Object System.Collections.ArrayList
        Errors         = $workerErrors
    }

    $cimSession   = $null
    $usedProtocol = $null

    try {
        $wsmanOptions = New-CimSessionOption -Protocol Wsman
        $cimSession   = New-CimSession -ComputerName $ComputerName -SessionOption $wsmanOptions -OperationTimeoutSec $TimeoutSeconds -ErrorAction Stop
        $usedProtocol = "WSMan"
    } catch {
        Add-CollectionError -Section "Connection" -Protocol "WSMan" -Message $_.Exception.Message
        try {
            $dcomOptions  = New-CimSessionOption -Protocol Dcom
            $cimSession   = New-CimSession -ComputerName $ComputerName -SessionOption $dcomOptions -OperationTimeoutSec $TimeoutSeconds -ErrorAction Stop
            $usedProtocol = "DCOM"
        } catch {
            Add-CollectionError -Section "Connection" -Protocol "DCOM" -Message $_.Exception.Message
        }
    }

    if (-not $cimSession) {
        $result.Errors = @($workerErrors)
        return $result
    }

    $result.Reached  = $true
    $result.Protocol = $usedProtocol

    # ---- Section 16: operating system / computer system info ----
    try {
        $osInstance = Get-CimInstance -CimSession $cimSession -ClassName Win32_OperatingSystem -ErrorAction Stop
        $csInstance = Get-CimInstance -CimSession $cimSession -ClassName Win32_ComputerSystem -ErrorAction Stop

        $installIso  = $null
        $lastBootIso = $null
        try { if ($osInstance.InstallDate)    { $installIso  = ([DateTime]$osInstance.InstallDate).ToUniversalTime().ToString("o") } } catch { $installIso = $null }
        try { if ($osInstance.LastBootUpTime) { $lastBootIso = ([DateTime]$osInstance.LastBootUpTime).ToUniversalTime().ToString("o") } } catch { $lastBootIso = $null }

        $result.OsInfo = [PSCustomObject]@{
            Caption                   = $osInstance.Caption
            Version                   = $osInstance.Version
            BuildNumber               = $osInstance.BuildNumber
            OSArchitecture            = $osInstance.OSArchitecture
            InstallDateIso            = $installIso
            LastBootUpTimeIso         = $lastBootIso
            ServicePackMajorVersion   = $osInstance.ServicePackMajorVersion
            Domain                    = $csInstance.Domain
            Manufacturer              = $csInstance.Manufacturer
            Model                     = $csInstance.Model
            TotalPhysicalMemory       = $csInstance.TotalPhysicalMemory
            NumberOfLogicalProcessors = $csInstance.NumberOfLogicalProcessors
            DomainRole                = $csInstance.DomainRole
        }
    } catch {
        Add-CollectionError -Section "16-OsInfo" -Protocol $usedProtocol -Message $_.Exception.Message
    }

    # ---- Section 17: scheduled tasks (CIM TaskScheduler provider, not the
    #      ScheduledTasks module, which would have to be present remotely) ----
    try {
        $tasks = Get-CimInstance -CimSession $cimSession -Namespace "root/Microsoft/Windows/TaskScheduler" -ClassName MSFT_ScheduledTask -ErrorAction Stop

        foreach ($task in $tasks) {
            # Built-in Microsoft scheduled tasks are excluded; only tasks an
            # administrator or an application added are of interest here.
            if ($task.TaskPath -like '\Microsoft\*') { continue }

            $actionsList = New-Object System.Collections.ArrayList
            foreach ($action in $task.Actions) {
                [void]$actionsList.Add([PSCustomObject]@{
                    Execute          = $action.Execute
                    Arguments        = $action.Arguments
                    WorkingDirectory = $action.WorkingDirectory
                })
            }

            $triggersList = New-Object System.Collections.ArrayList
            foreach ($trigger in $task.Triggers) {
                [void]$triggersList.Add([PSCustomObject]@{
                    Type          = $trigger.CimClass.CimClassName
                    StartBoundary = $trigger.StartBoundary
                    EndBoundary   = $trigger.EndBoundary
                    Enabled       = $trigger.Enabled
                })
            }

            $principal = $null
            if ($task.Principal) {
                $principal = [PSCustomObject]@{
                    UserId    = $task.Principal.UserId
                    RunLevel  = $task.Principal.RunLevel
                    LogonType = $task.Principal.LogonType
                }
            }

            $taskInfoObject = $null
            try {
                $taskInfoObject = $task | Get-CimAssociatedInstance -ResultClassName MSFT_TaskInfo -ErrorAction Stop
            } catch {
                $taskInfoObject = $null
            }

            $lastRunTimeValue    = $null
            $lastTaskResultValue = $null
            $nextRunTimeValue    = $null
            if ($taskInfoObject) {
                $lastRunTimeValue    = $taskInfoObject.LastRunTime
                $lastTaskResultValue = $taskInfoObject.LastTaskResult
                $nextRunTimeValue    = $taskInfoObject.NextRunTime
            }

            [void]$result.ScheduledTasks.Add([PSCustomObject]@{
                TaskPath       = $task.TaskPath
                TaskName       = $task.TaskName
                State          = [string]$task.State
                Enabled        = $task.Settings.Enabled
                Author         = $task.Author
                Principal      = $principal
                Actions        = @($actionsList)
                Triggers       = @($triggersList)
                LastRunTime    = $lastRunTimeValue
                LastTaskResult = $lastTaskResultValue
                NextRunTime    = $nextRunTimeValue
            })
        }
    } catch {
        Add-CollectionError -Section "17-ScheduledTasks" -Protocol $usedProtocol -Message $_.Exception.Message
    }

    # ---- Section 18: local users and groups ----
    try {
        $localUsers  = Get-CimInstance -CimSession $cimSession -ClassName Win32_UserAccount -Filter "LocalAccount='True'" -ErrorAction Stop
        $localGroups = Get-CimInstance -CimSession $cimSession -ClassName Win32_Group -Filter "LocalAccount='True'" -ErrorAction Stop

        $shortComputerName = $ComputerName
        $dotIndex = $ComputerName.IndexOf(".")
        if ($dotIndex -ge 0) { $shortComputerName = $ComputerName.Substring(0, $dotIndex) }

        $usersList = New-Object System.Collections.ArrayList
        foreach ($localUser in $localUsers) {
            [void]$usersList.Add([PSCustomObject]@{
                Name               = $localUser.Name
                SID                = $localUser.SID
                Disabled           = $localUser.Disabled
                Lockout            = $localUser.Lockout
                PasswordExpires    = $localUser.PasswordExpires
                PasswordRequired   = $localUser.PasswordRequired
                PasswordChangeable = $localUser.PasswordChangeable
                Description        = $localUser.Description
            })
        }

        $groupsList = New-Object System.Collections.ArrayList
        foreach ($localGroup in $localGroups) {
            $membersList = New-Object System.Collections.ArrayList
            try {
                $groupComponent = "Win32_Group.Domain='{0}',Name='{1}'" -f $localGroup.Domain, $localGroup.Name
                $memberQuery    = "ASSOCIATORS OF {$groupComponent} WHERE AssocClass=Win32_GroupUser"
                $members        = Get-CimInstance -CimSession $cimSession -Query $memberQuery -ErrorAction Stop

                foreach ($member in $members) {
                    $memberSid = $null
                    try { $memberSid = $member.SID } catch { $memberSid = $null }

                    # A member's Domain differs from this computer's own
                    # (short) name exactly when it is a domain principal
                    # rather than a local account.
                    $isDomainPrincipal = $false
                    if ($member.Domain) {
                        $isDomainPrincipal = (-not $member.Domain.Equals($shortComputerName, [StringComparison]::OrdinalIgnoreCase))
                    }

                    [void]$membersList.Add([PSCustomObject]@{
                        Name              = $member.Name
                        SID               = $memberSid
                        Type              = $member.CimClass.CimClassName
                        IsDomainPrincipal = $isDomainPrincipal
                    })
                }
            } catch {
                Add-CollectionError -Section "18-LocalGroupMembers" -Protocol $usedProtocol -Message ("Group '$($localGroup.Name)': " + $_.Exception.Message)
            }

            [void]$groupsList.Add([PSCustomObject]@{
                Name                   = $localGroup.Name
                SID                    = $localGroup.SID
                Description            = $localGroup.Description
                # Identified by the stable well-known SID suffix, never by
                # name, which is localized and can be renamed.
                IsLocalAdministrators  = ($localGroup.SID -eq "S-1-5-32-544")
                Members                = @($membersList)
            })
        }

        $result.LocalAccounts = [PSCustomObject]@{
            Users  = @($usersList)
            Groups = @($groupsList)
        }
    } catch {
        Add-CollectionError -Section "18-LocalAccounts" -Protocol $usedProtocol -Message $_.Exception.Message
    }

    # ---- Section 19: services ----
    try {
        $services = Get-CimInstance -CimSession $cimSession -ClassName Win32_Service -ErrorAction Stop

        foreach ($svc in $services) {
            $pathName = $svc.PathName

            # Raw fact, not a risk judgement: true when PathName is not
            # quote-wrapped and contains at least one space.
            $unquotedPathWithSpaces = $false
            if ($pathName -and $pathName.Contains(" ") -and (-not $pathName.TrimStart().StartsWith('"'))) {
                $unquotedPathWithSpaces = $true
            }

            $startName = $svc.StartName
            $runsAsDomainAccount = $false
            if ($startName) {
                $isLocalSystem  = $startName -eq "LocalSystem"
                $isNtAuthority  = $startName -like "NT AUTHORITY\*"
                $isLocalAccount = ($startName -like "$shortComputerName\*") -or ($startName -like ".\*") -or ($startName -like "NT SERVICE\*")
                $runsAsDomainAccount = (-not $isLocalSystem) -and (-not $isNtAuthority) -and (-not $isLocalAccount)
            }

            [void]$result.Services.Add([PSCustomObject]@{
                Name                   = $svc.Name
                DisplayName            = $svc.DisplayName
                State                  = $svc.State
                StartMode              = $svc.StartMode
                StartName              = $startName
                PathName               = $pathName
                Description            = $svc.Description
                DelayedAutoStart       = $svc.DelayedAutoStart
                UnquotedPathWithSpaces = $unquotedPathWithSpaces
                RunsAsDomainAccount    = $runsAsDomainAccount
            })
        }
    } catch {
        Add-CollectionError -Section "19-Services" -Protocol $usedProtocol -Message $_.Exception.Message
    }

    try { Remove-CimSession -CimSession $cimSession } catch { }

    $result.Errors = @($workerErrors)
    return $result
}

if (-not $script:RemoteCollectionEnabled) {
    Show-StepProgress -Status "Remote collection (Sections 16-19) disabled by configuration"
    Write-Log -Message 'Remote collection is disabled ($script:RemoteCollectionEnabled = $false); Sections 16-19 will be present but empty in the output.' -Level WARN
} else {
    Show-StepProgress -Status "Remote collection: selecting target servers"
    Write-Log -Message "Selecting remote collection targets from the Section 6 computer inventory" -Level INFO

    $staleThreshold = [DateTime]::UtcNow.AddDays(-$script:RemoteStaleDays)

    $script:RemoteTargets = @($script:Computers | Where-Object {
        $_.Enabled -and
        $_.OperatingSystem -and $_.OperatingSystem -like "*Server*" -and
        $_.LastLogonTimestampIso -and ([DateTime]$_.LastLogonTimestampIso) -ge $staleThreshold
    })

    $script:ServersTargeted = $script:RemoteTargets.Count
    Write-Log -Message "$($script:ServersTargeted) server(s) selected for remote collection (enabled, OS contains 'Server', last logon within $($script:RemoteStaleDays) days)" -Level INFO

    if ($script:ServersTargeted -eq 0) {
        Write-Log -Message "No eligible remote targets; Sections 16-19 will be empty." -Level WARN
    } else {
        Show-StepProgress -Status "Remote collection: dispatching $($script:ServersTargeted) hosts across $($script:RemoteThrottleLimit) runspaces"
        Write-Log -Message "Starting remote collection with a runspace pool (throttle=$($script:RemoteThrottleLimit), per-host CIM timeout=$($script:RemoteTimeoutSeconds)s)" -Level INFO

        $runspacePool = [runspacefactory]::CreateRunspacePool(1, $script:RemoteThrottleLimit)
        $runspacePool.Open()

        $pendingJobs = New-Object System.Collections.ArrayList
        $workerScriptText = $script:RemoteWorkerScript.ToString()

        try {
            foreach ($targetComputer in $script:RemoteTargets) {
                $powershellInstance = [powershell]::Create()
                $powershellInstance.RunspacePool = $runspacePool
                [void]$powershellInstance.AddScript($workerScriptText)
                [void]$powershellInstance.AddParameter("ComputerName", $targetComputer.Cn)
                [void]$powershellInstance.AddParameter("TimeoutSeconds", $script:RemoteTimeoutSeconds)

                $asyncHandle = $powershellInstance.BeginInvoke()

                [void]$pendingJobs.Add([PSCustomObject]@{
                    ComputerName = $targetComputer.Cn
                    PowerShell   = $powershellInstance
                    AsyncResult  = $asyncHandle
                    StartedUtc   = [DateTime]::UtcNow
                })
            }

            # Per-host wall-clock cap: headroom over the CIM operation
            # timeout itself, since it must also cover connection setup and
            # the DCOM fallback attempt.
            $hardTimeoutSeconds = $script:RemoteTimeoutSeconds * 3
            $overallDeadline    = (Get-Date).AddSeconds($hardTimeoutSeconds + 30)

            while ($pendingJobs.Count -gt 0 -and (Get-Date) -lt $overallDeadline) {
                for ($jobIndex = $pendingJobs.Count - 1; $jobIndex -ge 0; $jobIndex--) {
                    $job = $pendingJobs[$jobIndex]

                    $elapsedSeconds = ([DateTime]::UtcNow - $job.StartedUtc).TotalSeconds
                    $isDone   = $job.AsyncResult.IsCompleted
                    $timedOut = (-not $isDone) -and ($elapsedSeconds -gt $hardTimeoutSeconds)

                    if (-not $isDone -and -not $timedOut) { continue }

                    if ($timedOut) {
                        [void]$script:CollectionErrors.Add([PSCustomObject]@{
                            ComputerName = $job.ComputerName
                            Section      = "Connection"
                            Protocol     = "N/A"
                            Message      = "Remote collection exceeded the $hardTimeoutSeconds second per-host timeout and was aborted."
                        })
                        $script:ServersFailed++
                        try { $job.PowerShell.Stop() } catch { }
                        try { $job.PowerShell.Dispose() } catch { }
                        $pendingJobs.RemoveAt($jobIndex)
                        continue
                    }

                    try {
                        $hostResult = $job.PowerShell.EndInvoke($job.AsyncResult)

                        if (-not $hostResult -or $hostResult.Count -eq 0) {
                            [void]$script:CollectionErrors.Add([PSCustomObject]@{
                                ComputerName = $job.ComputerName
                                Section      = "Runspace"
                                Protocol     = "N/A"
                                Message      = "Worker returned no result."
                            })
                            $script:ServersFailed++
                        } else {
                            foreach ($resultItem in $hostResult) {
                                if ($resultItem.Reached) { $script:ServersReached++ } else { $script:ServersFailed++ }

                                if ($resultItem.OsInfo) {
                                    Add-Member -InputObject $resultItem.OsInfo -MemberType NoteProperty -Name "ComputerName" -Value $resultItem.ComputerName -Force
                                    [void]$script:RemoteOsInfo.Add($resultItem.OsInfo)
                                }

                                foreach ($taskItem in $resultItem.ScheduledTasks) {
                                    Add-Member -InputObject $taskItem -MemberType NoteProperty -Name "ComputerName" -Value $resultItem.ComputerName -Force
                                    [void]$script:RemoteScheduledTasks.Add($taskItem)
                                }

                                if ($resultItem.LocalAccounts) {
                                    Add-Member -InputObject $resultItem.LocalAccounts -MemberType NoteProperty -Name "ComputerName" -Value $resultItem.ComputerName -Force
                                    [void]$script:RemoteLocalAccounts.Add($resultItem.LocalAccounts)
                                }

                                foreach ($serviceItem in $resultItem.Services) {
                                    Add-Member -InputObject $serviceItem -MemberType NoteProperty -Name "ComputerName" -Value $resultItem.ComputerName -Force
                                    [void]$script:RemoteServices.Add($serviceItem)
                                }

                                foreach ($errorItem in $resultItem.Errors) {
                                    [void]$script:CollectionErrors.Add($errorItem)
                                }
                            }
                        }
                    } catch {
                        [void]$script:CollectionErrors.Add([PSCustomObject]@{
                            ComputerName = $job.ComputerName
                            Section      = "Runspace"
                            Protocol     = "N/A"
                            Message      = $_.Exception.Message
                        })
                        $script:ServersFailed++
                    } finally {
                        try { $job.PowerShell.Dispose() } catch { }
                        $pendingJobs.RemoveAt($jobIndex)
                    }
                }

                if ($pendingJobs.Count -gt 0) { Start-Sleep -Milliseconds 500 }
            }

            # Anything still pending once the overall deadline passed (rare,
            # given the per-job timeout above) is recorded and abandoned
            # rather than left to block the rest of the script.
            foreach ($job in $pendingJobs) {
                [void]$script:CollectionErrors.Add([PSCustomObject]@{
                    ComputerName = $job.ComputerName
                    Section      = "Connection"
                    Protocol     = "N/A"
                    Message      = "Remote collection did not complete before the overall deadline."
                })
                $script:ServersFailed++
                try { $job.PowerShell.Stop() } catch { }
                try { $job.PowerShell.Dispose() } catch { }
            }
        } finally {
            $runspacePool.Close()
            $runspacePool.Dispose()
        }

        Write-Log -Message "Remote collection complete: $($script:ServersReached) reached, $($script:ServersFailed) failed, out of $($script:ServersTargeted) targeted" -Level OK
    }
}

################################################################################
#                          OUTPUT ASSEMBLY (JSON + HTML)                     #
################################################################################

function New-CollectorSection {
    <#
        Every key in the final output's "data" object passes through here,
        so each one carries the same { meta: { type, count }, data: [...] }
        shape regardless of what it holds.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Type,

        [AllowNull()]
        $Items
    )

    $itemsArray = @($Items)

    return [PSCustomObject]@{
        meta = [PSCustomObject]@{
            type  = $Type
            count = $itemsArray.Count
        }
        data = $itemsArray
    }
}

Show-StepProgress -Status "Assembling the final collection object"
Write-Log -Message "Assembling the final collection object" -Level INFO

$script:MonitoredGroupsOutput = New-Object System.Collections.ArrayList
foreach ($groupCn in $script:MonitoredGroupsFound.Keys) {
    [void]$script:MonitoredGroupsOutput.Add([PSCustomObject]@{
        Name              = $groupCn
        DistinguishedName = $script:MonitoredGroupsFound[$groupCn]
        MemberCount       = $script:MonitoredGroupsCounters[$groupCn]
    })
}

$script:GeneratedUtc = [DateTime]::UtcNow

$script:MetaWarnings = New-Object System.Collections.ArrayList
if (-not [string]::IsNullOrEmpty($script:RsatWarning)) { [void]$script:MetaWarnings.Add($script:RsatWarning) }
if ($script:RsatAvailable -and -not $script:TierGpoCoverage.TierGpo) {
    [void]$script:MetaWarnings.Add("No single GPO configures all five deny-logon rights together; verify whether the same principal is instead configured across multiple GPOs for these five rights.")
}

$script:FinalCollection = [PSCustomObject]@{
    meta = [PSCustomObject]@{
        tool                  = "ADCollector"
        type                  = "adcollector_collection"
        version               = "1.0.0"
        generatedUtc          = $script:GeneratedUtc.ToString("o")
        baseDN                = $script:BaseDN
        domainSid             = $script:CurrentDomainSid
        domainFunctionalLevel = $script:DomainFunctionalLevelName
        forestFunctionalLevel = $script:ForestFunctionalLevelName
        machineAccountQuota   = $script:MachineAccountQuota
        tombstoneLifetimeDays = $script:TombstoneLifetimeDays
        recycleBinState       = $script:RecycleBinState
        lastBackupDisplay     = $script:LastBackupDisplay
        lastBackupIso         = $script:LastBackupIso
        powerShellVersion     = $PSVersionTable.PSVersion.ToString()
        scriptSha256          = $script:ScriptSha256
        serversTargeted       = $script:ServersTargeted
        serversReached        = $script:ServersReached
        serversFailed         = $script:ServersFailed
        warnings              = @($script:MetaWarnings)
    }
    data = [PSCustomObject]@{
        monitoredGroups              = New-CollectorSection -Type "monitoredGroups" -Items $script:MonitoredGroupsOutput
        unifiedPrivilegedUsers       = New-CollectorSection -Type "unifiedPrivilegedUsers" -Items @($script:UnifiedPrivilegedUsers)
        rootPrivilegedAces           = New-CollectorSection -Type "rootPrivilegedAces" -Items @($script:RootPrivilegedAces)
        rootDelegationPrincipals     = New-CollectorSection -Type "rootDelegationPrincipals" -Items @($script:RootDelegationPrincipals.Values)
        dcOuPrivilegedAces           = New-CollectorSection -Type "dcOuPrivilegedAces" -Items @($script:DcOuPrivilegedAces)
        dcDelegationPrincipals       = New-CollectorSection -Type "dcDelegationPrincipals" -Items @($script:DcOuDelegationPrincipals.Values)
        exchangePrivilegedAces       = New-CollectorSection -Type "exchangePrivilegedAces" -Items @($script:ExchangePrivilegedAces)
        exchangeDelegationPrincipals = New-CollectorSection -Type "exchangeDelegationPrincipals" -Items @($script:ExchangeDelegationPrincipals.Values)
        computers                    = New-CollectorSection -Type "computers" -Items @($script:Computers)
        gpos                         = New-CollectorSection -Type "gpos" -Items @($script:Gpos)
        userRightsAssignments        = New-CollectorSection -Type "userRightsAssignments" -Items @($script:UserRightsAssignments)
        tierGpoCoverage              = New-CollectorSection -Type "tierGpoCoverage" -Items @($script:TierGpoCoverage)
        kerberoastable               = New-CollectorSection -Type "kerberoastable" -Items @($script:Kerberoastable)
        asrepRoastable               = New-CollectorSection -Type "asrepRoastable" -Items @($script:AsrepRoastable)
        msolAccounts                 = New-CollectorSection -Type "msolAccounts" -Items @($script:MsolAccounts)
        krbtgt                       = New-CollectorSection -Type "krbtgt" -Items @($script:Krbtgt)
        guestAccount                 = New-CollectorSection -Type "guestAccount" -Items @($script:GuestAccount)
        laps                         = New-CollectorSection -Type "laps" -Items @($script:Laps)
        remoteOsInfo                 = New-CollectorSection -Type "remoteOsInfo" -Items @($script:RemoteOsInfo)
        remoteScheduledTasks         = New-CollectorSection -Type "remoteScheduledTasks" -Items @($script:RemoteScheduledTasks)
        remoteLocalAccounts          = New-CollectorSection -Type "remoteLocalAccounts" -Items @($script:RemoteLocalAccounts)
        remoteServices               = New-CollectorSection -Type "remoteServices" -Items @($script:RemoteServices)
        collectionErrors             = New-CollectorSection -Type "collectionErrors" -Items @($script:CollectionErrors)
    }
}

Write-Log -Message "Final collection object assembled" -Level OK

################################################################################
#                              JSON EXPORT                                   #
################################################################################

Show-StepProgress -Status "Writing adcollector_collection.json"
Write-Log -Message "Serializing the collection object to JSON" -Level INFO

$script:JsonOutputPath = Join-Path -Path $script:RunFolderPath -ChildPath "adcollector_collection.json"
$script:CollectionJsonText = $null

try {
    # Depth 15: scheduled-task triggers/actions nest several levels deep
    # inside remoteScheduledTasks (section wrapper -> data array -> task ->
    # Triggers array -> trigger object), so the default of 2 and even a
    # depth of 8 are not enough to serialize them in full.
    $script:CollectionJsonText = $script:FinalCollection | ConvertTo-Json -Depth 15

    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($script:JsonOutputPath, $script:CollectionJsonText, $utf8NoBom)

    Write-Log -Message "JSON written to $($script:JsonOutputPath)" -Level OK
} catch {
    Write-Log -Message "JSON serialization/write failed: $($_.Exception.Message)" -Level ERROR
}

################################################################################
#                              HTML REPORT EXPORT                            #
################################################################################

Show-StepProgress -Status "Writing adcollector_report.html"
Write-Log -Message "Generating the self-contained HTML report from the in-memory collection object" -Level INFO

function ConvertTo-HtmlEncoded {
    <#
        A minimal, dependency-free HTML encoder (no System.Web assembly
        load, which is not guaranteed present on a bare Server Core host).
    #>
    param(
        [AllowNull()]
        [string]$Text
    )
    if ($null -eq $Text) { return "" }
    $encoded = $Text
    $encoded = $encoded.Replace("&", "&amp;")
    $encoded = $encoded.Replace("<", "&lt;")
    $encoded = $encoded.Replace(">", "&gt;")
    $encoded = $encoded.Replace('"', "&quot;")
    $encoded = $encoded.Replace("'", "&#39;")
    return $encoded
}

# Single-quoted here-string: the template is taken verbatim, so PowerShell
# never tries to interpolate the JavaScript's own $-prefixed syntax. Content
# is spliced in afterward via plain, literal .Replace() token substitution.
#
# Palette: the fixed, colorblind-validated categorical/status/neutral tokens
# from the internal data-viz reference palette (light #fcfcfb / dark #1a1a19
# surfaces). A single accent (categorical slot 1, blue) drives interactive
# chrome; data badges (Category, booleans, State) stay neutral-gray rather
# than color-coded, because this report never renders a risk judgement -
# only the raw facts the collector gathered.
$script:HtmlTemplate = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>__TITLE__</title>
<style>
  :root {
    color-scheme: light dark;
    --page:      #f9f9f7;
    --surface:   #fcfcfb;
    --surface-2: #f3f2ee;
    --ink:       #0b0b0b;
    --ink-2:     #52514e;
    --ink-muted: #898781;
    --border:    rgba(11,11,11,0.10);
    --gridline:  #e1e0d9;
    --accent:    #2a78d6;
    --accent-ink:#ffffff;
    --warn-bg:   #fdf2e2;
    --warn-ink:  #6b4a12;
    --warn-border: #eda100;
    --shadow: 0 1px 2px rgba(11,11,11,0.06), 0 1px 1px rgba(11,11,11,0.04);
  }
  @media (prefers-color-scheme: dark) {
    :root:not([data-theme="light"]) {
      --page:      #0d0d0d;
      --surface:   #1a1a19;
      --surface-2: #202020;
      --ink:       #ffffff;
      --ink-2:     #c3c2b7;
      --ink-muted: #898781;
      --border:    rgba(255,255,255,0.10);
      --gridline:  #2c2c2a;
      --accent:    #3987e5;
      --accent-ink:#ffffff;
      --warn-bg:   #2a2210;
      --warn-ink:  #f0cf8a;
      --warn-border: #c98500;
      --shadow: 0 1px 2px rgba(0,0,0,0.4), 0 1px 1px rgba(0,0,0,0.3);
    }
  }
  * { box-sizing: border-box; }
  html, body { height: 100%; }
  body {
    font-family: system-ui, -apple-system, "Segoe UI", Arial, sans-serif;
    margin: 0; padding: 0; background: var(--page); color: var(--ink);
    font-size: 14px; line-height: 1.45;
  }
  .app { display: flex; min-height: 100vh; }

  /* ---------- Sidebar ---------- */
  .sidebar {
    width: 260px; flex: 0 0 260px; background: var(--surface);
    border-right: 1px solid var(--border); position: sticky; top: 0;
    height: 100vh; overflow-y: auto; display: flex; flex-direction: column;
  }
  .sidebar-header { padding: 18px 18px 12px 18px; border-bottom: 1px solid var(--border); }
  .sidebar-header .brand { font-size: 15px; font-weight: 600; color: var(--ink); }
  .sidebar-header .sub { font-size: 11px; color: var(--ink-muted); margin-top: 3px; word-break: break-all; }
  .nav-group-label { padding: 14px 18px 4px 18px; font-size: 10px; text-transform: uppercase; letter-spacing: .06em; color: var(--ink-muted); }
  nav.tabs { display: flex; flex-direction: column; padding: 0 8px 12px 8px; }
  nav.tabs button {
    display: flex; align-items: center; justify-content: space-between; gap: 8px;
    background: transparent; border: none; border-left: 3px solid transparent;
    color: var(--ink-2); padding: 8px 10px; cursor: pointer; font-size: 13px;
    text-align: left; border-radius: 6px; margin: 1px 0; font-family: inherit;
  }
  nav.tabs button:hover { background: var(--surface-2); color: var(--ink); }
  nav.tabs button.active { background: var(--surface-2); color: var(--accent); border-left-color: var(--accent); font-weight: 600; }
  nav.tabs button .count { font-size: 11px; color: var(--ink-muted); font-variant-numeric: tabular-nums; }
  nav.tabs button.active .count { color: var(--accent); }

  /* ---------- Main ---------- */
  .main { flex: 1; min-width: 0; padding: 22px 28px 40px 28px; }
  .view { display: none; }
  .view.active { display: block; }
  .view-header { margin-bottom: 16px; }
  .view-header h1 { margin: 0 0 4px 0; font-size: 19px; }
  .view-header .desc { font-size: 12px; color: var(--ink-muted); }

  .warnings {
    background: var(--warn-bg); color: var(--warn-ink); border: 1px solid var(--warn-border);
    border-radius: 8px; padding: 10px 14px; font-size: 12px; margin-bottom: 18px;
  }
  .warnings strong { display: block; margin-bottom: 4px; }
  .warnings ul { margin: 2px 0 0 18px; padding: 0; }

  /* ---------- KPI tiles ---------- */
  .kpi-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(170px, 1fr)); gap: 12px; margin-bottom: 22px; }
  .kpi-tile { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 14px 16px; box-shadow: var(--shadow); }
  .kpi-tile .value { font-size: 26px; font-weight: 600; color: var(--accent); line-height: 1.1; }
  .kpi-tile .label { font-size: 12px; color: var(--ink-2); margin-top: 5px; }

  /* ---------- Fact panel ---------- */
  .panel { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 16px 18px; margin-bottom: 22px; box-shadow: var(--shadow); }
  .panel h2 { margin: 0 0 12px 0; font-size: 13px; text-transform: uppercase; letter-spacing: .04em; color: var(--ink-muted); }
  .fact-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 10px 20px; }
  .fact-grid div span.label { display: block; font-size: 11px; color: var(--ink-muted); text-transform: uppercase; letter-spacing: .03em; margin-bottom: 2px; }
  .fact-grid div span.value { font-size: 13px; color: var(--ink); word-break: break-word; }
  .fact-grid div span.value.mono { font-family: ui-monospace, SFMono-Regular, Consolas, "Liberation Mono", monospace; font-size: 12px; }

  /* ---------- Section (data table) view ---------- */
  .section-card { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; box-shadow: var(--shadow); overflow: hidden; }
  .section-toolbar { display: flex; align-items: center; gap: 10px; padding: 12px 14px; border-bottom: 1px solid var(--border); }
  .search-box {
    flex: 0 1 340px; padding: 7px 10px; border: 1px solid var(--border); border-radius: 7px;
    font-size: 13px; background: var(--page); color: var(--ink); font-family: inherit;
  }
  .search-box:focus { outline: 2px solid var(--accent); outline-offset: 1px; }
  .row-count { font-size: 12px; color: var(--ink-muted); margin-left: auto; font-variant-numeric: tabular-nums; }
  .table-scroll { overflow: auto; max-height: 72vh; }
  table { border-collapse: collapse; width: 100%; font-size: 12.5px; }
  thead th {
    position: sticky; top: 0; background: var(--surface-2); color: var(--ink-2);
    text-align: left; font-weight: 600; padding: 8px 10px; border-bottom: 1px solid var(--border);
    cursor: pointer; user-select: none; white-space: nowrap;
  }
  thead th:hover { color: var(--ink); }
  thead th .sort-arrow { color: var(--accent); margin-left: 3px; }
  tbody td {
    padding: 7px 10px; border-bottom: 1px solid var(--gridline); vertical-align: top;
    max-width: 420px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  }
  tbody td.expand-cell { white-space: normal; overflow: visible; text-overflow: clip; }
  tbody td.expand-cell.expanded { max-width: 660px; position: relative; z-index: 1; }
  tbody td.mono { font-family: ui-monospace, SFMono-Regular, Consolas, "Liberation Mono", monospace; font-size: 11.5px; }
  tbody tr:hover td { background: var(--surface-2); }
  tbody tr:nth-child(even) td { background: rgba(11,11,11,0.015); }
  @media (prefers-color-scheme: dark) {
    :root:not([data-theme="light"]) tbody tr:nth-child(even) td { background: rgba(255,255,255,0.015); }
  }
  .empty-state { padding: 28px; text-align: center; color: var(--ink-muted); font-size: 13px; }

  .badge {
    display: inline-block; padding: 2px 8px; border: 1px solid var(--border); border-radius: 999px;
    font-size: 11px; color: var(--ink-2); background: var(--page); white-space: nowrap;
  }
  details.cell-details summary {
    cursor: pointer; color: var(--accent); font-size: 12px; list-style: none;
    display: block; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 400px;
  }
  details.cell-details[open] summary { white-space: normal; overflow: visible; text-overflow: clip; max-width: none; }
  details.cell-details summary::-webkit-details-marker { display: none; }
  details.cell-details summary::before { content: "\25B8  "; }
  details.cell-details[open] summary::before { content: "\25BE  "; }
  details.cell-details pre {
    margin: 6px 0 0 0; white-space: pre-wrap; word-break: normal; overflow-wrap: break-word;
    font-size: 11.5px; min-width: 280px; max-width: 640px;
    font-family: ui-monospace, SFMono-Regular, Consolas, "Liberation Mono", monospace;
    background: var(--page); border: 1px solid var(--border); border-radius: 6px; padding: 8px 10px;
  }

  footer { padding: 18px 28px; font-size: 11px; color: var(--ink-muted); }

  @media (max-width: 760px) {
    .app { flex-direction: column; }
    .sidebar { width: 100%; flex: none; height: auto; position: relative; border-right: none; border-bottom: 1px solid var(--border); }
    nav.tabs { flex-direction: row; flex-wrap: wrap; }
  }
</style>
</head>
<body>
<div class="app">
  <aside class="sidebar">
    <div class="sidebar-header">
      <div class="brand">__TITLE__</div>
      <div class="sub">__GENERATED_LINE__</div>
    </div>
    <div class="nav-group-label">Overview</div>
    <nav class="tabs" id="overview-nav"></nav>
    <div class="nav-group-label">Collected data</div>
    <nav class="tabs" id="tab-nav"></nav>
  </aside>
  <main class="main" id="main-root">
__WARNINGS_BLOCK__
  </main>
</div>
<script id="collection-data" type="application/json">__DATA_JSON__</script>
<script>
(function () {
  "use strict";
  var raw = document.getElementById("collection-data").textContent;
  var collection = JSON.parse(raw);
  var mainRoot = document.getElementById("main-root");
  var overviewNav = document.getElementById("overview-nav");
  var tabNav = document.getElementById("tab-nav");
  var sortState = {};

  var sectionLabels = {
    monitoredGroups: "Monitored privileged groups",
    unifiedPrivilegedUsers: "Privileged users (unified)",
    rootPrivilegedAces: "Domain root ACL — privileged ACEs",
    rootDelegationPrincipals: "Domain root ACL — delegated users",
    dcOuPrivilegedAces: "Domain Controllers OU ACL — privileged ACEs",
    dcDelegationPrincipals: "Domain Controllers OU ACL — delegated users",
    exchangePrivilegedAces: "Exchange containers ACL — privileged ACEs",
    exchangeDelegationPrincipals: "Exchange containers ACL — delegated users",
    computers: "Domain computers",
    gpos: "Group Policy Objects",
    userRightsAssignments: "User Rights Assignment (GptTmpl.inf)",
    tierGpoCoverage: "Tier GPO coverage & conflicts",
    kerberoastable: "Kerberoastable accounts",
    asrepRoastable: "AS-REP roastable accounts",
    msolAccounts: "MSOL_ service accounts",
    krbtgt: "krbtgt account",
    guestAccount: "Built-in Guest account",
    laps: "LAPS deployment state",
    remoteOsInfo: "Remote servers — OS info",
    remoteScheduledTasks: "Remote servers — scheduled tasks",
    remoteLocalAccounts: "Remote servers — local accounts & groups",
    remoteServices: "Remote servers — services",
    collectionErrors: "Collection errors"
  };

  var kpiKeys = [
    "unifiedPrivilegedUsers", "monitoredGroups", "computers", "gpos",
    "userRightsAssignments", "kerberoastable", "asrepRoastable", "msolAccounts",
    "remoteScheduledTasks", "remoteServices", "collectionErrors"
  ];

  var factPairs = [
    ["Domain (Base DN)", collection.meta.baseDN, true],
    ["Domain SID", collection.meta.domainSid, true],
    ["Domain functional level", collection.meta.domainFunctionalLevel, false],
    ["Forest functional level", collection.meta.forestFunctionalLevel, false],
    ["Recycle Bin", collection.meta.recycleBinState, false],
    ["Last backup", collection.meta.lastBackupDisplay, false],
    ["Machine account quota", collection.meta.machineAccountQuota, false],
    ["Tombstone lifetime (days)", collection.meta.tombstoneLifetimeDays, false],
    ["Remote servers reached", collection.meta.serversReached + " / " + collection.meta.serversTargeted + " targeted (" + collection.meta.serversFailed + " failed)", false],
    ["PowerShell version", collection.meta.powerShellVersion, false],
    ["Tool version", collection.meta.version, false],
    ["Collector SHA-256", collection.meta.scriptSha256, true]
  ];

  function labelFor(key) { return sectionLabels[key] || key; }

  function formatValue(val) {
    if (val === null || val === undefined) { return ""; }
    if (typeof val === "object") { return JSON.stringify(val); }
    return String(val);
  }

  function isMonoColumn(colName) {
    return /(sid|dn|distinguishedname|path|hash|guid)$/i.test(colName);
  }

  function isBadgeColumn(colName) {
    return /^(category|state|type|relationship|protocol|section)$/i.test(colName);
  }

  function attachExpandToggle(td, details) {
    // Table auto-layout sizes a column from its COLLAPSED content, since
    // pre-wrap/break-word text is technically free to shrink to nothing;
    // widening the cell only while its <details> is open lets the expanded
    // content actually use the room it needs without permanently widening
    // (and pushing sideways) every other row in the column.
    details.addEventListener("toggle", function () {
      td.classList.toggle("expanded", details.open);
    });
  }

  function buildCell(colName, value) {
    var td = document.createElement("td");

    if (value !== null && typeof value === "object") {
      td.classList.add("expand-cell");
      var details = document.createElement("details");
      details.className = "cell-details";
      var summary = document.createElement("summary");
      var itemCount = Array.isArray(value) ? value.length : Object.keys(value).length;
      summary.textContent = Array.isArray(value)
        ? (itemCount + (itemCount === 1 ? " item" : " items"))
        : "Show details";
      var pre = document.createElement("pre");
      var isFlatArray = Array.isArray(value) && value.every(function (v) { return v === null || typeof v !== "object"; });
      pre.textContent = isFlatArray ? value.map(formatValue).join("\n") : JSON.stringify(value, null, 2);
      details.appendChild(summary);
      details.appendChild(pre);
      td.appendChild(details);
      attachExpandToggle(td, details);
      return td;
    }

    var text = formatValue(value);

    if (typeof value === "boolean") {
      var badge = document.createElement("span");
      badge.className = "badge";
      badge.textContent = text;
      td.appendChild(badge);
      return td;
    }

    if (isBadgeColumn(colName) && text) {
      var badge2 = document.createElement("span");
      badge2.className = "badge";
      badge2.textContent = text;
      td.appendChild(badge2);
      return td;
    }

    if (text.length > 120) {
      td.classList.add("expand-cell");
      var details2 = document.createElement("details");
      details2.className = "cell-details";
      var summary2 = document.createElement("summary");
      summary2.textContent = text.slice(0, 70) + "…";
      var pre2 = document.createElement("pre");
      pre2.textContent = text;
      details2.appendChild(summary2);
      details2.appendChild(pre2);
      td.appendChild(details2);
      attachExpandToggle(td, details2);
      return td;
    }

    if (isMonoColumn(colName)) { td.classList.add("mono"); }
    td.textContent = text;
    td.title = text;
    return td;
  }

  function sortTable(table, colIndex) {
    var tbody = table.querySelector("tbody");
    var rows = Array.prototype.slice.call(tbody.rows);
    var stateKey = table.id + "-" + colIndex;
    var ascending = !sortState[stateKey];
    sortState = {};
    sortState[stateKey] = ascending;

    Array.prototype.forEach.call(table.querySelectorAll("thead .sort-arrow"), function (el) { el.remove(); });
    var activeTh = table.querySelectorAll("thead th")[colIndex];
    if (activeTh) {
      var arrow = document.createElement("span");
      arrow.className = "sort-arrow";
      arrow.textContent = ascending ? "▲" : "▼";
      activeTh.appendChild(arrow);
    }

    rows.sort(function (a, b) {
      var av = a.cells[colIndex] ? a.cells[colIndex].getAttribute("data-sort") || a.cells[colIndex].textContent : "";
      var bv = b.cells[colIndex] ? b.cells[colIndex].getAttribute("data-sort") || b.cells[colIndex].textContent : "";
      var an = parseFloat(av);
      var bn = parseFloat(bv);
      var cmp;
      if (!isNaN(an) && !isNaN(bn) && av.trim() !== "" && bv.trim() !== "") {
        cmp = an - bn;
      } else {
        cmp = av.localeCompare(bv);
      }
      return ascending ? cmp : -cmp;
    });

    rows.forEach(function (row) { tbody.appendChild(row); });
  }

  function buildSectionView(sectionKey, sectionObj, index) {
    var view = document.createElement("div");
    view.className = "view";
    view.id = "view-section-" + sectionKey;

    var header = document.createElement("div");
    header.className = "view-header";
    var h1 = document.createElement("h1");
    h1.textContent = labelFor(sectionKey);
    header.appendChild(h1);
    view.appendChild(header);

    var card = document.createElement("div");
    card.className = "section-card";

    var toolbar = document.createElement("div");
    toolbar.className = "section-toolbar";
    var searchBox = document.createElement("input");
    searchBox.type = "text";
    searchBox.className = "search-box";
    searchBox.placeholder = "Filter this table…";
    var rowCount = document.createElement("span");
    rowCount.className = "row-count";
    toolbar.appendChild(searchBox);
    toolbar.appendChild(rowCount);
    card.appendChild(toolbar);

    var items = sectionObj.data || [];

    if (items.length === 0) {
      var empty = document.createElement("div");
      empty.className = "empty-state";
      empty.textContent = "No data collected for this section.";
      card.appendChild(empty);
      rowCount.textContent = "0 rows";
    } else {
      var columns = [];
      if (typeof items[0] === "object" && items[0] !== null) {
        for (var key in items[0]) {
          if (Object.prototype.hasOwnProperty.call(items[0], key)) { columns.push(key); }
        }
      } else {
        columns = ["value"];
      }

      var scrollWrap = document.createElement("div");
      scrollWrap.className = "table-scroll";

      var table = document.createElement("table");
      table.id = "table-" + sectionKey;
      var thead = document.createElement("thead");
      var tbody = document.createElement("tbody");

      var headerRow = document.createElement("tr");
      columns.forEach(function (col, colIndex) {
        var th = document.createElement("th");
        th.textContent = col;
        th.addEventListener("click", function () { sortTable(table, colIndex); });
        headerRow.appendChild(th);
      });
      thead.appendChild(headerRow);
      table.appendChild(thead);

      items.forEach(function (item) {
        var tr = document.createElement("tr");
        columns.forEach(function (col) {
          var value = (typeof item === "object" && item !== null) ? item[col] : item;
          tr.appendChild(buildCell(col, value));
        });
        tbody.appendChild(tr);
      });
      table.appendChild(tbody);
      scrollWrap.appendChild(table);
      card.appendChild(scrollWrap);

      rowCount.textContent = items.length + (items.length === 1 ? " row" : " rows");

      searchBox.addEventListener("input", function () {
        var filterText = searchBox.value.toLowerCase();
        var visibleCount = 0;
        Array.prototype.forEach.call(tbody.rows, function (row) {
          var match = row.textContent.toLowerCase().indexOf(filterText) !== -1;
          row.style.display = match ? "" : "none";
          if (match) { visibleCount++; }
        });
        rowCount.textContent = visibleCount + " / " + items.length + " rows";
      });
    }

    view.appendChild(card);
    mainRoot.appendChild(view);
  }

  function buildOverviewView() {
    var view = document.createElement("div");
    view.className = "view active";
    view.id = "view-overview";

    var header = document.createElement("div");
    header.className = "view-header";
    var h1 = document.createElement("h1");
    h1.textContent = "Overview";
    var desc = document.createElement("div");
    desc.className = "desc";
    desc.textContent = "Raw counts from this collection run. No score, threshold or risk judgement is computed here — see the sections in the sidebar for the underlying data.";
    header.appendChild(h1);
    header.appendChild(desc);
    view.appendChild(header);

    var kpiGrid = document.createElement("div");
    kpiGrid.className = "kpi-grid";
    kpiKeys.forEach(function (key) {
      var section = collection.data[key];
      if (!section) { return; }
      var tile = document.createElement("div");
      tile.className = "kpi-tile";
      var value = document.createElement("div");
      value.className = "value";
      value.textContent = section.meta.count;
      var label = document.createElement("div");
      label.className = "label";
      label.textContent = labelFor(key);
      tile.appendChild(value);
      tile.appendChild(label);
      kpiGrid.appendChild(tile);
    });
    view.appendChild(kpiGrid);

    var panel = document.createElement("div");
    panel.className = "panel";
    var panelTitle = document.createElement("h2");
    panelTitle.textContent = "Domain facts";
    panel.appendChild(panelTitle);
    var factGrid = document.createElement("div");
    factGrid.className = "fact-grid";
    factPairs.forEach(function (pair) {
      var row = document.createElement("div");
      var label = document.createElement("span");
      label.className = "label";
      label.textContent = pair[0];
      var value = document.createElement("span");
      value.className = "value" + (pair[2] ? " mono" : "");
      value.textContent = formatValue(pair[1]);
      row.appendChild(label);
      row.appendChild(value);
      factGrid.appendChild(row);
    });
    panel.appendChild(factGrid);
    view.appendChild(panel);

    mainRoot.appendChild(view);
  }

  function showView(viewId, button, groupButtons) {
    Array.prototype.forEach.call(document.querySelectorAll(".view"), function (el) { el.classList.remove("active"); });
    Array.prototype.forEach.call(document.querySelectorAll("nav.tabs button"), function (el) { el.classList.remove("active"); });
    var target = document.getElementById(viewId);
    if (target) { target.classList.add("active"); }
    if (button) { button.classList.add("active"); }
  }

  // Overview nav entry
  buildOverviewView();
  var overviewBtn = document.createElement("button");
  overviewBtn.textContent = "Overview";
  overviewBtn.className = "active";
  overviewBtn.addEventListener("click", function () { showView("view-overview", overviewBtn); });
  overviewNav.appendChild(overviewBtn);

  // One nav entry + view per collected section, in the order the collector emitted them
  var sectionKeys = [];
  for (var sectionKey in collection.data) {
    if (Object.prototype.hasOwnProperty.call(collection.data, sectionKey)) { sectionKeys.push(sectionKey); }
  }

  sectionKeys.forEach(function (key) {
    buildSectionView(key, collection.data[key]);

    var btn = document.createElement("button");
    var labelSpan = document.createElement("span");
    labelSpan.textContent = labelFor(key);
    var countSpan = document.createElement("span");
    countSpan.className = "count";
    countSpan.textContent = collection.data[key].meta.count;
    btn.appendChild(labelSpan);
    btn.appendChild(countSpan);
    btn.addEventListener("click", function () { showView("view-section-" + key, btn); });
    tabNav.appendChild(btn);
  });
})();
</script>
<footer>Generated offline by ADCollector. No external resources are loaded by this page.</footer>
</body>
</html>
'@

try {
    $reportMeta  = $script:FinalCollection.meta
    $reportTitle = "ADCollector"

    $generatedLineHtml = "Generated $(ConvertTo-HtmlEncoded -Text $reportMeta.generatedUtc) &middot; $(ConvertTo-HtmlEncoded -Text $reportMeta.baseDN)"

    $warningsBlockHtml = ""
    if ($reportMeta.warnings -and $reportMeta.warnings.Count -gt 0) {
        $warningItemsHtml = ""
        foreach ($warningText in $reportMeta.warnings) {
            $warningItemsHtml += "<li>$(ConvertTo-HtmlEncoded -Text $warningText)</li>"
        }
        $warningsBlockHtml = "<div class=""warnings""><strong>Warnings</strong><ul>$warningItemsHtml</ul></div>"
    }

    # Neutralize any literal "</" a collected field might contain (e.g. a
    # task argument with "</script>" in it) so it can never prematurely
    # close this tag; "\/" is a valid escaped forward slash in JSON, so this
    # never changes what the embedded data means once parsed.
    $dataJsonForHtml = $script:CollectionJsonText -replace '</', '<\/'

    $finalHtml = $script:HtmlTemplate.Replace("__TITLE__", (ConvertTo-HtmlEncoded -Text $reportTitle))
    $finalHtml = $finalHtml.Replace("__GENERATED_LINE__", $generatedLineHtml)
    $finalHtml = $finalHtml.Replace("__WARNINGS_BLOCK__", $warningsBlockHtml)
    $finalHtml = $finalHtml.Replace("__DATA_JSON__", $dataJsonForHtml)

    $script:HtmlOutputPath = Join-Path -Path $script:RunFolderPath -ChildPath "adcollector_report.html"
    $utf8NoBomForHtml = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($script:HtmlOutputPath, $finalHtml, $utf8NoBomForHtml)

    Write-Log -Message "HTML report written to $($script:HtmlOutputPath)" -Level OK
} catch {
    Write-Log -Message "HTML report generation failed: $($_.Exception.Message)" -Level ERROR
}

################################################################################
#                    CLOSING: ARCHIVE, INTEGRITY HASH, SUMMARY               #
################################################################################

Show-StepProgress -Status "Compressing the run folder"
Write-Log -Message "Compressing the run folder to a zip archive" -Level INFO

$archivePath    = "$($script:RunFolderPath).zip"
$archiveCreated = $false

try {
    Compress-Archive -Path (Join-Path -Path $script:RunFolderPath -ChildPath "*") -DestinationPath $archivePath -Force -ErrorAction Stop
    $archiveCreated = $true
} catch {
    Write-Log -Message "Compression failed; keeping the uncompressed run folder at $($script:RunFolderPath): $($_.Exception.Message)" -Level WARN
}

if ($archiveCreated) {
    # The log file handle must be released before its own folder is removed,
    # otherwise the open handle keeps the folder locked.
    $script:LogFilePath = $null

    try {
        Remove-Item -Path $script:RunFolderPath -Recurse -Force -ErrorAction Stop
    } catch {
        Write-Host "[WARN] Failed to remove the uncompressed run folder $($script:RunFolderPath): $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

Show-StepProgress -Status "Collection complete" -Activity "ADCollector Collection"
Write-Progress -Id 1 -Activity "ADCollector Collection" -Completed

$script:Stopwatch.Stop()
$elapsed          = $script:Stopwatch.Elapsed
$elapsedFormatted = "{0:D2}:{1:D2}:{2:D2}" -f [int][Math]::Floor($elapsed.TotalHours), $elapsed.Minutes, $elapsed.Seconds

$archiveSha256 = "N/A"
if ($archiveCreated -and (Test-Path -Path $archivePath)) {
    try { $archiveSha256 = (Get-FileHash -Path $archivePath -Algorithm SHA256).Hash } catch { $archiveSha256 = "N/A" }
}

$finalOutputPath = $script:RunFolderPath
if ($archiveCreated) { $finalOutputPath = $archivePath }

$summaryLines = @(
    "================================================================",
    " ADCollector collection complete",
    "----------------------------------------------------------------",
    " Elapsed time : $elapsedFormatted",
    " Output       : $finalOutputPath",
    " SHA-256      : $archiveSha256",
    "================================================================"
)
foreach ($summaryLine in $summaryLines) { Write-Host $summaryLine -ForegroundColor Cyan }
