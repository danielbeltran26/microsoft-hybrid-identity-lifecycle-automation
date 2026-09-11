<#
.SYNOPSIS
    Performs read-only validation of the IAM Project 1 Milestone 3 state.

.DESCRIPTION
    Run in Windows PowerShell as Administrator on DC01. The script validates
    the authoritative dataset, protected OU boundary, Global Security groups,
    controlled identities, manager relationships, direct access assignments,
    contractor expiration, SYNC01 placement and preserved SOC/IDTR state.

    A bounded startup wait allows DC01 services and MonAgentCore.exe to settle
    after a restart. This script does not change Active Directory, services,
    processes, files or virtual-machine snapshots.
#>

[CmdletBinding()]
param(
    [string]$CsvPath = 'C:\IAM-Lab\data\iam-project1-controlled-users.csv',
    [string]$ExpectedSHA256 = '153FCF70CA0B8C1B366767BB0F61AEF7E65EF074AD2FA29726C3AF1A07EC9641',
    [string]$ExpectedComputerName = 'DC01',
    [string]$ExpectedDomain = 'corporate.test',
    [string]$ExpectedUPNSuffix = 'danielcloudlaboutlook258.onmicrosoft.com',
    [ValidateRange(0, 900)][int]$StartupWaitSeconds = 300,
    [ValidateRange(5, 120)][int]$PollingIntervalSeconds = 15
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-PlannedGroups {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Record)

    return @(
        @($Record.BaselineGroups, $Record.DepartmentGroup, $Record.AccessGroups) |
            ForEach-Object { [string]$_ -split ';' } |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ } |
            Sort-Object -Unique
    )
}

if ($env:COMPUTERNAME -ne $ExpectedComputerName) {
    throw "Run this script on $ExpectedComputerName, not $env:COMPUTERNAME."
}

if (-not (Test-Path -LiteralPath $CsvPath -PathType Leaf)) {
    throw "The controlled dataset was not found at $CsvPath."
}

Import-Module ActiveDirectory
$Domain = Get-ADDomain
$Forest = Get-ADForest

if ($Domain.DNSRoot -ne $ExpectedDomain) {
    throw "Expected domain $ExpectedDomain but detected $($Domain.DNSRoot)."
}

$DomainDN = $Domain.DistinguishedName
$IAMRootDN = "OU=IAM-Lab,$DomainDN"
$IAMUsersDN = "OU=Users,$IAMRootDN"
$IAMGroupsDN = "OU=Groups,$IAMRootDN"
$ExpectedSYNC01DN = "CN=SYNC01,OU=Servers,OU=Infrastructure,$IAMRootDN"

$ExpectedOUDNs = @(
    $IAMRootDN
    "OU=Users,$IAMRootDN"
    "OU=Employees,OU=Users,$IAMRootDN"
    "OU=Finance,OU=Employees,OU=Users,$IAMRootDN"
    "OU=Human Resources,OU=Employees,OU=Users,$IAMRootDN"
    "OU=Information Technology,OU=Employees,OU=Users,$IAMRootDN"
    "OU=Sales,OU=Employees,OU=Users,$IAMRootDN"
    "OU=Operations,OU=Employees,OU=Users,$IAMRootDN"
    "OU=Contractors,OU=Users,$IAMRootDN"
    "OU=Leavers,OU=Users,$IAMRootDN"
    "OU=Groups,$IAMRootDN"
    "OU=Baseline,OU=Groups,$IAMRootDN"
    "OU=Departments,OU=Groups,$IAMRootDN"
    "OU=Access,OU=Groups,$IAMRootDN"
    "OU=Infrastructure,$IAMRootDN"
    "OU=Servers,OU=Infrastructure,$IAMRootDN"
)

$RequiredServices = @(
    'NTDS'
    'DNS'
    'ADWS'
    'Netlogon'
    'himds'
    'GCArcService'
    'ExtensionService'
)

$Deadline = (Get-Date).AddSeconds($StartupWaitSeconds)

do {
    $ServiceStates = @(
        foreach ($ServiceName in $RequiredServices) {
            Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        }
    )
    $RunningServiceCount = @(
        $ServiceStates |
            Where-Object Status -eq 'Running'
    ).Count
    $AzureMonitorAgentRunning = $null -ne (
        Get-Process -Name 'MonAgentCore' -ErrorAction SilentlyContinue |
            Select-Object -First 1
    )
    $StartupReady = (
        $RunningServiceCount -eq $RequiredServices.Count -and
        $AzureMonitorAgentRunning
    )

    if (-not $StartupReady -and (Get-Date) -lt $Deadline) {
        Start-Sleep -Seconds $PollingIntervalSeconds
    }
}
until ($StartupReady -or (Get-Date) -ge $Deadline)

$DatasetHashMatches = (
    (Get-FileHash -LiteralPath $CsvPath -Algorithm SHA256).Hash -eq
    $ExpectedSHA256
)
$Records = @(Import-Csv -LiteralPath $CsvPath)
$PasswordOrSecretColumnCount = @(
    $Records[0].PSObject.Properties.Name |
        Where-Object { $_ -match '(?i)password|secret|credential|token' }
).Count

$ActualOUs = @(
    Get-ADOrganizationalUnit `
        -Filter * `
        -SearchBase $IAMRootDN `
        -SearchScope Subtree `
        -Properties ProtectedFromAccidentalDeletion
)
$ActualOUDNs = @($ActualOUs.DistinguishedName)
$ProtectedOUCount = @(
    $ActualOUs |
        Where-Object ProtectedFromAccidentalDeletion -eq $true
).Count
$MissingOUs = @(
    $ExpectedOUDNs |
        Where-Object { $ActualOUDNs -notcontains $_ }
)
$UnexpectedOUs = @(
    $ActualOUDNs |
        Where-Object { $ExpectedOUDNs -notcontains $_ }
)
$MissingOrUnexpectedOUCount = $MissingOUs.Count + $UnexpectedOUs.Count

$ExpectedGroupNames = @(
    $Records |
        ForEach-Object { Get-PlannedGroups -Record $_ } |
        Sort-Object -Unique
)
$ActualGroups = @(
    Get-ADGroup `
        -Filter * `
        -SearchBase $IAMGroupsDN `
        -SearchScope Subtree `
        -Properties GroupScope, GroupCategory
)
$ActualGroupNames = @($ActualGroups.SamAccountName)
$UnexpectedGroupCount = @(
    $ActualGroupNames |
        Where-Object { $ExpectedGroupNames -notcontains $_ }
).Count
$MissingGroupCount = @(
    $ExpectedGroupNames |
        Where-Object { $ActualGroupNames -notcontains $_ }
).Count
$GroupTypeFailureCount = @(
    $ActualGroups |
        Where-Object {
            $_.GroupScope -ne 'Global' -or
            $_.GroupCategory -ne 'Security'
        }
).Count
$GroupMemberCountFailureCount = 0

foreach ($GroupName in $ExpectedGroupNames) {
    $ExpectedMembers = @(
        $Records |
            Where-Object { (Get-PlannedGroups -Record $_) -contains $GroupName }
    ).Count
    $ActualMembers = @(
        Get-ADGroupMember -Identity $GroupName -ErrorAction Stop
    ).Count

    if ($ActualMembers -ne $ExpectedMembers) {
        $GroupMemberCountFailureCount++
    }
}

$GroupValidationFailureCount = (
    $UnexpectedGroupCount +
    $MissingGroupCount +
    $GroupTypeFailureCount +
    $GroupMemberCountFailureCount
)

$ControlledUsers = @(
    Get-ADUser `
        -Filter 'EmployeeID -like "IAM*"' `
        -SearchBase $IAMUsersDN `
        -SearchScope Subtree `
        -Properties EmployeeID, UserPrincipalName, GivenName, Surname,
            DisplayName, Department, Title, employeeType, Manager, MemberOf,
            Enabled, AccountExpirationDate, Description, LockedOut
)
$UserByEmployeeID = @{}

foreach ($User in $ControlledUsers) {
    if ($UserByEmployeeID.ContainsKey($User.EmployeeID)) {
        throw "Duplicate controlled EmployeeID detected: $($User.EmployeeID)."
    }

    $UserByEmployeeID[$User.EmployeeID] = $User
}

$IdentityValidationFailureCount = 0
$ManagerAssignedCount = 0
$TotalDirectMemberships = 0
$LockedUserCount = 0
$ContractorExpirationFailureCount = 0

foreach ($Record in $Records) {
    $User = $UserByEmployeeID[$Record.EmployeeID]

    if ($null -eq $User) {
        $IdentityValidationFailureCount++
        continue
    }

    $ExpectedGroups = @(Get-PlannedGroups -Record $Record)
    $ActualIAMGroups = @(
        $User.MemberOf |
            ForEach-Object { (Get-ADGroup -Identity $_).SamAccountName } |
            Where-Object { $_ -like 'GG_IAM_*' } |
            Sort-Object -Unique
    )
    $GroupDifference = @(
        Compare-Object `
            -ReferenceObject $ExpectedGroups `
            -DifferenceObject $ActualIAMGroups
    )
    $ExpectedManagerDN = $null

    if (-not [string]::IsNullOrWhiteSpace($Record.ManagerEmployeeID)) {
        $ExpectedManager = $UserByEmployeeID[$Record.ManagerEmployeeID]

        if ($null -ne $ExpectedManager) {
            $ExpectedManagerDN = $ExpectedManager.DistinguishedName
        }
    }

    if ($User.Manager) {
        $ManagerAssignedCount++
    }

    $TotalDirectMemberships += $ActualIAMGroups.Count

    if ($User.LockedOut) {
        $LockedUserCount++
    }

    $ExpectedDescription = "IAM Project 1 | $($Record.WorkerType) | Active"
    $IdentityValid = (
        $User.SamAccountName -eq $Record.SamAccountName -and
        $User.UserPrincipalName -eq $Record.UserPrincipalName -and
        $User.GivenName -eq $Record.GivenName -and
        $User.Surname -eq $Record.Surname -and
        $User.DisplayName -eq $Record.DisplayName -and
        $User.Department -eq $Record.Department -and
        $User.Title -eq $Record.JobTitle -and
        $User.employeeType -eq $Record.WorkerType -and
        $User.DistinguishedName -eq "CN=$($Record.DisplayName),$($Record.TargetOU)" -and
        $User.Enabled -and
        $User.Manager -eq $ExpectedManagerDN -and
        $User.Description -eq $ExpectedDescription -and
        $GroupDifference.Count -eq 0
    )

    if (-not $IdentityValid) {
        $IdentityValidationFailureCount++
    }

    if ($Record.WorkerType -eq 'Contractor') {
        $ExpectedExpiration = ([datetime]$Record.EndDate).Date.AddDays(1)

        if (
            $null -eq $User.AccountExpirationDate -or
            $User.AccountExpirationDate.Date -ne $ExpectedExpiration
        ) {
            $ContractorExpirationFailureCount++
        }
    }
}

$EnabledUserCount = @($ControlledUsers | Where-Object Enabled -eq $true).Count
$EmployeeCount = @($Records | Where-Object WorkerType -eq 'Employee').Count
$ContractorCount = @($Records | Where-Object WorkerType -eq 'Contractor').Count
$LeaverUserCount = @(
    Get-ADUser `
        -Filter * `
        -SearchBase "OU=Leavers,$IAMUsersDN" `
        -SearchScope OneLevel
).Count
$UPNSuffixPresent = $Forest.UPNSuffixes -contains $ExpectedUPNSuffix
$SYNC01 = Get-ADComputer -Identity 'SYNC01' -Properties Enabled
$SYNC01PlacementValid = (
    $SYNC01.Enabled -and
    $SYNC01.DistinguishedName -eq $ExpectedSYNC01DN
)

$PermanentEmployeeCount = @(
    Get-ADGroupMember -Identity 'GG_All_Employees'
).Count
$IDTRUsers = @(
    foreach ($Number in 1..5) {
        Get-ADUser `
            -Identity ('idtr-user{0:d2}' -f $Number) `
            -Properties Enabled
    }
)
$IDTRDisabledCount = @($IDTRUsers | Where-Object Enabled -eq $false).Count
$HighValueGroupMembers = @(
    Get-ADGroupMember -Identity 'IDTR-HighValue-Lab'
).Count

$Summary = [pscustomobject]@{
    ComputerName                   = $env:COMPUTERNAME
    DatasetHashMatches             = $DatasetHashMatches
    PasswordOrSecretColumnCount    = $PasswordOrSecretColumnCount
    ValidatedOUCount               = $ActualOUs.Count
    ProtectedOUCount               = $ProtectedOUCount
    MissingOrUnexpectedOUCount     = $MissingOrUnexpectedOUCount
    IAMGroupCount                  = $ActualGroups.Count
    GroupValidationFailureCount    = $GroupValidationFailureCount
    ControlledUserCount            = $ControlledUsers.Count
    EnabledUserCount               = $EnabledUserCount
    EmployeeCount                  = $EmployeeCount
    ContractorCount                = $ContractorCount
    ManagerAssignedCount           = $ManagerAssignedCount
    TotalDirectMemberships         = $TotalDirectMemberships
    IdentityValidationFailureCount = $IdentityValidationFailureCount
    ContractorExpirationFailures   = $ContractorExpirationFailureCount
    LockedUserCount                 = $LockedUserCount
    LeaverUserCount                = $LeaverUserCount
    UPNSuffixPresent               = $UPNSuffixPresent
    SYNC01PlacementValid           = $SYNC01PlacementValid
    RunningServiceCount            = $RunningServiceCount
    AzureMonitorAgentRunning       = $AzureMonitorAgentRunning
    PermanentEmployeeCount         = $PermanentEmployeeCount
    IDTRUserCount                  = $IDTRUsers.Count
    IDTRDisabledCount              = $IDTRDisabledCount
    HighValueGroupMembers          = $HighValueGroupMembers
}

$Summary

$Passed = (
    $DatasetHashMatches -and
    $PasswordOrSecretColumnCount -eq 0 -and
    $Records.Count -eq 30 -and
    $ActualOUs.Count -eq 16 -and
    $ProtectedOUCount -eq 16 -and
    $MissingOrUnexpectedOUCount -eq 0 -and
    $ActualGroups.Count -eq 15 -and
    $GroupValidationFailureCount -eq 0 -and
    $ControlledUsers.Count -eq 30 -and
    $EnabledUserCount -eq 30 -and
    $EmployeeCount -eq 25 -and
    $ContractorCount -eq 5 -and
    $ManagerAssignedCount -eq 24 -and
    $TotalDirectMemberships -eq 140 -and
    $IdentityValidationFailureCount -eq 0 -and
    $ContractorExpirationFailureCount -eq 0 -and
    $LockedUserCount -eq 0 -and
    $LeaverUserCount -eq 0 -and
    $UPNSuffixPresent -and
    $SYNC01PlacementValid -and
    $RunningServiceCount -eq 7 -and
    $AzureMonitorAgentRunning -and
    $PermanentEmployeeCount -eq 50 -and
    $IDTRUsers.Count -eq 5 -and
    $IDTRDisabledCount -eq 5 -and
    $HighValueGroupMembers -eq 0
)

if (-not $Passed) {
    throw 'FAIL: Milestone 3 comprehensive validation requires investigation.'
}

Write-Host ''
Write-Host 'PASS: Milestone 3 controlled identity foundation is healthy and isolated.' -ForegroundColor Green
