<#
.SYNOPSIS
    Performs read-only validation of IAM Project 1 Milestone 5.

.DESCRIPTION
    Validates the controlled and mover datasets, initial and replay audits,
    protected directory structure, effective mover target states, services,
    Azure Monitor Agent, SYNC01 placement and preservation of the earlier SOC
    and IDTR environments. No configuration or file is changed.
#>

[CmdletBinding()]
param(
    [string]$ControlledCsvPath = 'C:\IAM-Lab\data\iam-project1-controlled-users.csv',
    [string]$ExpectedControlledSHA256 = '153FCF70CA0B8C1B366767BB0F61AEF7E65EF074AD2FA29726C3AF1A07EC9641',
    [string]$MoverCsvPath = 'C:\IAM-Lab\data\iam-project1-mover-requests.csv',
    [string]$ExpectedMoverSHA256 = 'AA40213E0C71234FA3F32CF1AF9FA0960EDDA3B231EBEE58D82C5C0A1E23A7C8',
    [string]$InitialAuditPath = 'C:\IAM-Lab\logs\M05-MOVER-20260904-200349-audit.csv',
    [string]$ExpectedInitialAuditSHA256 = 'D83F055148B703AF2DFCF2B41510565DA1937E8CCCD9117EEF1774EF4A07A1EF',
    [string]$ReplayAuditPath = 'C:\IAM-Lab\logs\M05-MOVER-20260904-203431-audit.csv',
    [string]$ExpectedReplayAuditSHA256 = '73734232695872C9A38B8E3E2AA053A3AA78CC9747FD5A45E2B95D58D9295839',
    [ValidateRange(0, 900)][int]$StartupWaitSeconds = 300,
    [ValidateRange(5, 120)][int]$PollingIntervalSeconds = 15
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($env:COMPUTERNAME -ne 'DC01') {
    throw "Run this script on DC01, not $env:COMPUTERNAME."
}

foreach ($RequiredFile in @(
    $ControlledCsvPath,
    $MoverCsvPath,
    $InitialAuditPath,
    $ReplayAuditPath
)) {
    if (-not (Test-Path -LiteralPath $RequiredFile -PathType Leaf)) {
        throw "Required Milestone 5 file not found at $RequiredFile."
    }
}

Import-Module ActiveDirectory
$Domain = Get-ADDomain
$Forest = Get-ADForest

if ($Domain.DNSRoot -ne 'corporate.test') {
    throw "Expected corporate.test but detected $($Domain.DNSRoot)."
}

$IAMRoot = 'OU=IAM-Lab,DC=corporate,DC=test'
$UsersRoot = "OU=Users,$IAMRoot"
$GroupsRoot = "OU=Groups,$IAMRoot"
$LeaversOU = "OU=Leavers,$UsersRoot"
$ExpectedSYNC01DN = "CN=SYNC01,OU=Servers,OU=Infrastructure,$IAMRoot"
$RequiredUPNSuffix = 'danielcloudlaboutlook258.onmicrosoft.com'
$RequiredServices = @(
    'NTDS'
    'DNS'
    'ADWS'
    'Netlogon'
    'himds'
    'GCArcService'
    'ExtensionService'
)

function ConvertTo-GroupList {
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Value)

    return @(
        $Value -split ';' |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ } |
            Sort-Object -Unique
    )
}

function Get-DirectIAMGroups {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$User)

    return @(
        $User.MemberOf |
            Where-Object { $_ -like 'CN=GG_IAM_*' } |
            ForEach-Object {
                (Get-ADGroup -Identity $_).SamAccountName
            } |
            Sort-Object -Unique
    )
}

function Test-StringSetEqual {
    [CmdletBinding()]
    param(
        [string[]]$Reference,
        [string[]]$Difference
    )

    return @(
        Compare-Object `
            -ReferenceObject @($Reference | Sort-Object -Unique) `
            -DifferenceObject @($Difference | Sort-Object -Unique)
    ).Count -eq 0
}

$Deadline = (Get-Date).AddSeconds($StartupWaitSeconds)

do {
    $RunningServices = @(
        foreach ($ServiceName in $RequiredServices) {
            Get-Service -Name $ServiceName -ErrorAction SilentlyContinue |
                Where-Object { $_.Status -eq 'Running' }
        }
    )
    $AzureMonitorAgentRunning = $null -ne (
        Get-Process -Name 'MonAgentCore' -ErrorAction SilentlyContinue |
            Select-Object -First 1
    )
    $StartupReady = (
        $RunningServices.Count -eq $RequiredServices.Count -and
        $AzureMonitorAgentRunning
    )

    if (-not $StartupReady -and (Get-Date) -lt $Deadline) {
        Start-Sleep -Seconds $PollingIntervalSeconds
    }
}
until ($StartupReady -or (Get-Date) -ge $Deadline)

$ControlledDatasetHash = (
    Get-FileHash -LiteralPath $ControlledCsvPath -Algorithm SHA256
).Hash
$MoverDatasetHash = (
    Get-FileHash -LiteralPath $MoverCsvPath -Algorithm SHA256
).Hash
$InitialAuditHash = (
    Get-FileHash -LiteralPath $InitialAuditPath -Algorithm SHA256
).Hash
$ReplayAuditHash = (
    Get-FileHash -LiteralPath $ReplayAuditPath -Algorithm SHA256
).Hash

$InitialAuditEvents = @(Import-Csv -LiteralPath $InitialAuditPath)
$ReplayAuditEvents = @(Import-Csv -LiteralPath $ReplayAuditPath)
$ReplayNoChangeCount = @(
    $ReplayAuditEvents |
        Where-Object {
            $_.Action -eq 'IdempotentReplay' -and
            $_.Result -eq 'NoChange'
        }
).Count
$ReplayFailureCount = @(
    $ReplayAuditEvents | Where-Object { $_.Result -eq 'Failed' }
).Count

$IAMOUs = @(
    Get-ADOrganizationalUnit `
        -SearchBase $IAMRoot `
        -SearchScope Subtree `
        -Filter * `
        -Properties ProtectedFromAccidentalDeletion
)
$ProtectedOUCount = @(
    $IAMOUs | Where-Object ProtectedFromAccidentalDeletion
).Count
$IAMGroups = @(
    Get-ADGroup `
        -SearchBase $GroupsRoot `
        -SearchScope Subtree `
        -Filter * `
        -Properties GroupCategory, GroupScope
)
$GroupValidationFailureCount = @(
    $IAMGroups |
        Where-Object {
            $_.GroupCategory -ne 'Security' -or
            $_.GroupScope -ne 'Global'
        }
).Count

$OriginalRecords = @(Import-Csv -LiteralPath $ControlledCsvPath)
$OriginalIdentityPresenceFailures = 0
$OriginalDirectMembershipCount = 0

foreach ($Record in $OriginalRecords) {
    $EscapedEmployeeID = $Record.EmployeeID.Replace("'", "''")
    $Users = @(
        Get-ADUser `
            -Filter "EmployeeID -eq '$EscapedEmployeeID'" `
            -Properties EmployeeID, Enabled, MemberOf
    )

    if ($Users.Count -ne 1 -or -not $Users[0].Enabled) {
        $OriginalIdentityPresenceFailures++
        continue
    }

    $OriginalDirectMembershipCount += @(
        $Users[0].MemberOf |
            Where-Object { $_ -like 'CN=GG_IAM_*' }
    ).Count
}

$MoverRequests = @(Import-Csv -LiteralPath $MoverCsvPath)
$MoverValidationFailureCount = 0
$ObsoleteMembershipPresentCount = 0
$MissingTargetMembershipCount = 0
$UnexpectedTargetMembershipCount = 0
$MoverManagerCount = 0
$MoverDirectMembershipCount = 0

foreach ($Request in $MoverRequests) {
    $EscapedEmployeeID = $Request.EmployeeID.Replace("'", "''")
    $Users = @(
        Get-ADUser `
            -Filter "EmployeeID -eq '$EscapedEmployeeID'" `
            -Properties EmployeeID, UserPrincipalName, Enabled, employeeType,
                Department, Title, Manager, MemberOf, AccountExpirationDate,
                Description
    )

    if ($Users.Count -ne 1) {
        $MoverValidationFailureCount++
        continue
    }

    $User = $Users[0]
    $TargetGroups = @(ConvertTo-GroupList -Value $Request.TargetGroups)
    $SourceGroups = @(ConvertTo-GroupList -Value $Request.CurrentGroups)
    $ActualGroups = @(Get-DirectIAMGroups -User $User)
    $ObsoleteGroups = @(
        $SourceGroups | Where-Object { $_ -notin $TargetGroups }
    )
    $ObsoletePresent = @(
        $ObsoleteGroups | Where-Object { $_ -in $ActualGroups }
    )
    $MissingGroups = @(
        $TargetGroups | Where-Object { $_ -notin $ActualGroups }
    )
    $UnexpectedGroups = @(
        $ActualGroups | Where-Object { $_ -notin $TargetGroups }
    )
    $Manager = if ($null -ne $User.Manager) {
        Get-ADUser -Identity $User.Manager -Properties EmployeeID
    }
    else {
        $null
    }
    $CurrentParentOU = $User.DistinguishedName.Substring(
        $User.DistinguishedName.IndexOf(',') + 1
    )
    $ExpectedDescription = "IAM Project 1 | Mover | $($Request.TargetWorkerType) | Active | $($Request.RequestID)"
    $ExpirationValid = if (
        [string]::IsNullOrWhiteSpace($Request.TargetAccountExpirationDate)
    ) {
        $null -eq $User.AccountExpirationDate
    }
    else {
        $null -ne $User.AccountExpirationDate -and
        $User.AccountExpirationDate.Date -eq
            ([datetime]$Request.TargetAccountExpirationDate).Date
    }
    $IdentityValid = (
        $User.EmployeeID -eq $Request.EmployeeID -and
        $User.SamAccountName -eq $Request.SamAccountName -and
        $User.UserPrincipalName -eq $Request.UserPrincipalName -and
        $User.Enabled -and
        $User.employeeType -eq $Request.TargetWorkerType -and
        $User.Department -eq $Request.TargetDepartment -and
        $User.Title -eq $Request.TargetJobTitle -and
        $null -ne $Manager -and
        $Manager.EmployeeID -eq $Request.TargetManagerEmployeeID -and
        $CurrentParentOU -eq $Request.TargetOU -and
        $User.Description -eq $ExpectedDescription -and
        $ExpirationValid -and
        (Test-StringSetEqual -Reference $TargetGroups -Difference $ActualGroups)
    )

    if (-not $IdentityValid) {
        $MoverValidationFailureCount++
    }

    $ObsoleteMembershipPresentCount += $ObsoletePresent.Count
    $MissingTargetMembershipCount += $MissingGroups.Count
    $UnexpectedTargetMembershipCount += $UnexpectedGroups.Count

    if ($null -ne $Manager) {
        $MoverManagerCount++
    }

    $MoverDirectMembershipCount += $ActualGroups.Count
}

$ControlledUsers = @(
    Get-ADUser `
        -SearchBase $UsersRoot `
        -LDAPFilter '(objectCategory=person)' `
        -Properties Enabled, employeeType, Manager, MemberOf
)
$EnabledUsers = @($ControlledUsers | Where-Object Enabled)
$Employees = @($ControlledUsers | Where-Object employeeType -eq 'Employee')
$Contractors = @($ControlledUsers | Where-Object employeeType -eq 'Contractor')
$ManagerAssignedUsers = @(
    $ControlledUsers | Where-Object { $null -ne $_.Manager }
)
$TotalDirectMemberships = (
    $ControlledUsers |
        ForEach-Object {
            @($_.MemberOf | Where-Object { $_ -like 'CN=GG_IAM_*' }).Count
        } |
        Measure-Object -Sum
).Sum

$Mason = Get-ADUser -Identity 'mason.cole' -Properties AccountExpirationDate
$MasonExpirationCleared = $null -eq $Mason.AccountExpirationDate
$LeaverUserCount = @(
    Get-ADUser -SearchBase $LeaversOU -SearchScope OneLevel -Filter *
).Count
$SYNC01 = Get-ADComputer -Identity 'SYNC01' -Properties Enabled
$SYNC01PlacementValid = (
    $SYNC01.DistinguishedName -eq $ExpectedSYNC01DN -and
    $SYNC01.Enabled
)
$UPNSuffixPresent = $RequiredUPNSuffix -in $Forest.UPNSuffixes
$PermanentEmployeeCount = @(
    Get-ADGroupMember -Identity 'GG_All_Employees' -Recursive
).Count
$IDTRUsers = @(
    Get-ADUser `
        -Filter "SamAccountName -like 'idtr-user*'" `
        -Properties Enabled
)
$IDTRDisabledCount = @($IDTRUsers | Where-Object { -not $_.Enabled }).Count
$HighValueGroupMembers = @(
    Get-ADGroupMember -Identity 'IDTR-HighValue-Lab'
).Count

$Passed = (
    $RunningServices.Count -eq 7 -and
    $AzureMonitorAgentRunning -and
    $ControlledDatasetHash -eq $ExpectedControlledSHA256 -and
    $MoverDatasetHash -eq $ExpectedMoverSHA256 -and
    $InitialAuditHash -eq $ExpectedInitialAuditSHA256 -and
    $InitialAuditEvents.Count -eq 29 -and
    $ReplayAuditHash -eq $ExpectedReplayAuditSHA256 -and
    $ReplayAuditEvents.Count -eq 5 -and
    $ReplayNoChangeCount -eq 3 -and
    $ReplayFailureCount -eq 0 -and
    $IAMOUs.Count -eq 16 -and
    $ProtectedOUCount -eq 16 -and
    $IAMGroups.Count -eq 15 -and
    $GroupValidationFailureCount -eq 0 -and
    $OriginalRecords.Count -eq 30 -and
    $OriginalIdentityPresenceFailures -eq 0 -and
    $OriginalDirectMembershipCount -eq 140 -and
    $MoverRequests.Count -eq 3 -and
    $MoverValidationFailureCount -eq 0 -and
    $ObsoleteMembershipPresentCount -eq 0 -and
    $MissingTargetMembershipCount -eq 0 -and
    $UnexpectedTargetMembershipCount -eq 0 -and
    $MoverManagerCount -eq 3 -and
    $MoverDirectMembershipCount -eq 15 -and
    $ControlledUsers.Count -eq 33 -and
    $EnabledUsers.Count -eq 33 -and
    $Employees.Count -eq 28 -and
    $Contractors.Count -eq 5 -and
    $ManagerAssignedUsers.Count -eq 27 -and
    $TotalDirectMemberships -eq 155 -and
    $MasonExpirationCleared -and
    $LeaverUserCount -eq 0 -and
    $SYNC01PlacementValid -and
    $UPNSuffixPresent -and
    $PermanentEmployeeCount -eq 50 -and
    $IDTRUsers.Count -eq 5 -and
    $IDTRDisabledCount -eq 5 -and
    $HighValueGroupMembers -eq 0
)

[pscustomobject]@{
    ComputerName = $env:COMPUTERNAME
    DomainName = $Domain.DNSRoot
    RunningServiceCount = $RunningServices.Count
    AzureMonitorAgentRunning = $AzureMonitorAgentRunning
    ControlledDatasetHashMatches = ($ControlledDatasetHash -eq $ExpectedControlledSHA256)
    MoverDatasetHashMatches = ($MoverDatasetHash -eq $ExpectedMoverSHA256)
    InitialAuditHashMatches = ($InitialAuditHash -eq $ExpectedInitialAuditSHA256)
    InitialAuditEventCount = $InitialAuditEvents.Count
    ReplayAuditHashMatches = ($ReplayAuditHash -eq $ExpectedReplayAuditSHA256)
    ReplayAuditEventCount = $ReplayAuditEvents.Count
    ReplayNoChangeCount = $ReplayNoChangeCount
    ReplayFailureCount = $ReplayFailureCount
    ValidatedOUCount = $IAMOUs.Count
    ProtectedOUCount = $ProtectedOUCount
    IAMGroupCount = $IAMGroups.Count
    GroupValidationFailureCount = $GroupValidationFailureCount
    OriginalDatasetIdentityCount = $OriginalRecords.Count
    OriginalIdentityPresenceFailures = $OriginalIdentityPresenceFailures
    OriginalDirectMembershipCount = $OriginalDirectMembershipCount
    ControlledUserCount = $ControlledUsers.Count
    EnabledUserCount = $EnabledUsers.Count
    EmployeeCount = $Employees.Count
    ContractorCount = $Contractors.Count
    ManagerAssignedCount = $ManagerAssignedUsers.Count
    TotalDirectMemberships = $TotalDirectMemberships
    MoverRequestCount = $MoverRequests.Count
    MoverValidationFailureCount = $MoverValidationFailureCount
    ObsoleteMembershipPresentCount = $ObsoleteMembershipPresentCount
    MissingTargetMembershipCount = $MissingTargetMembershipCount
    UnexpectedTargetMembershipCount = $UnexpectedTargetMembershipCount
    MoverManagerCount = $MoverManagerCount
    MoverDirectMembershipCount = $MoverDirectMembershipCount
    MasonExpirationCleared = $MasonExpirationCleared
    LeaverUserCount = $LeaverUserCount
    SYNC01PlacementValid = $SYNC01PlacementValid
    UPNSuffixPresent = $UPNSuffixPresent
    PermanentEmployeeCount = $PermanentEmployeeCount
    IDTRUserCount = $IDTRUsers.Count
    IDTRDisabledCount = $IDTRDisabledCount
    HighValueGroupMembers = $HighValueGroupMembers
    ChangesMade = $false
} | Format-List

if (-not $Passed) {
    throw 'Milestone 5 mover-state validation requires investigation.'
}

Write-Host ''
Write-Host 'PASS: The complete Milestone 5 mover-automation state is healthy and isolated.' -ForegroundColor Green
