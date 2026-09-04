<#
.SYNOPSIS
    Performs read-only validation of IAM Project 1 Milestone 4.

.DESCRIPTION
    Validates the approved joiner dataset, initial and replay audits, effective
    AD identity state, contractor expiration, directory services, Azure Monitor
    Agent process, SYNC01 placement and preservation of the earlier SOC/IDTR
    environment. No configuration or file is changed.
#>

[CmdletBinding()]
param(
    [string]$CsvPath = 'C:\IAM-Lab\data\iam-project1-joiner-requests.csv',
    [string]$ExpectedCsvSHA256 = '8685B8C4C99B68ED7B7EFAA888587FBDDBF0E94B48932922D130AEDD2B470CEE',
    [string]$InitialAuditPath = 'C:\IAM-Lab\logs\M04-JOINER-20260904-182309-audit.csv',
    [string]$ExpectedInitialAuditSHA256 = 'F2905614937292210D87158A20046E67D6023E016A3CEF1025D187C6ED70E9A5',
    [string]$ReplayAuditPath = 'C:\IAM-Lab\logs\M04-JOINER-20260904-184532-audit.csv',
    [string]$ExpectedReplayAuditSHA256 = 'C45F29E7B97F478F41E4E7FDE565DE97DBBE2BCDDA1F7BE9370F84ABB0C9569B',
    [ValidateRange(0, 900)][int]$StartupWaitSeconds = 300,
    [ValidateRange(5, 120)][int]$PollingIntervalSeconds = 15
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($env:COMPUTERNAME -ne 'DC01') {
    throw "Run this script on DC01, not $env:COMPUTERNAME."
}

foreach ($RequiredFile in @($CsvPath, $InitialAuditPath, $ReplayAuditPath)) {
    if (-not (Test-Path -LiteralPath $RequiredFile -PathType Leaf)) {
        throw "Required Milestone 4 file not found at $RequiredFile."
    }
}

Import-Module ActiveDirectory
$Domain = Get-ADDomain

if ($Domain.DNSRoot -ne 'corporate.test') {
    throw "Expected corporate.test but detected $($Domain.DNSRoot)."
}

$UsersRoot = 'OU=Users,OU=IAM-Lab,DC=corporate,DC=test'
$LeaversOU = 'OU=Leavers,OU=Users,OU=IAM-Lab,DC=corporate,DC=test'
$ExpectedSYNC01DN = 'CN=SYNC01,OU=Servers,OU=Infrastructure,OU=IAM-Lab,DC=corporate,DC=test'
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
    $RunningServices = @(
        foreach ($ServiceName in $RequiredServices) {
            Get-Service -Name $ServiceName -ErrorAction SilentlyContinue |
                Where-Object Status -eq 'Running'
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

$CsvHash = (Get-FileHash -LiteralPath $CsvPath -Algorithm SHA256).Hash
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
            $_.Action -eq 'IdempotentReplay' -and $_.Result -eq 'NoChange'
        }
).Count
$ReplayFailureCount = @(
    $ReplayAuditEvents | Where-Object Result -eq 'Failed'
).Count
$Requests = @(Import-Csv -LiteralPath $CsvPath)
$ControlledUsers = @(
    Get-ADUser `
        -SearchBase $UsersRoot `
        -LDAPFilter '(objectCategory=person)' `
        -Properties Enabled, employeeType, Manager, MemberOf, EmployeeID,
            UserPrincipalName, Department, Title, AccountExpirationDate,
            Description
)
$EnabledUsers = @($ControlledUsers | Where-Object Enabled)
$Employees = @($ControlledUsers | Where-Object employeeType -eq 'Employee')
$Contractors = @($ControlledUsers | Where-Object employeeType -eq 'Contractor')
$ManagerAssigned = @(
    $ControlledUsers | Where-Object { $null -ne $_.Manager }
)
$TotalDirectMemberships = (
    $ControlledUsers |
        ForEach-Object {
            @($_.MemberOf | Where-Object { $_ -like 'CN=GG_IAM_*' }).Count
        } |
        Measure-Object -Sum
).Sum
$JoinerValidationFailureCount = 0
$JoinerManagerCount = 0
$JoinerDirectMembershipCount = 0

foreach ($Request in $Requests) {
    $Users = @(
        $ControlledUsers |
            Where-Object EmployeeID -eq $Request.EmployeeID
    )

    if ($Users.Count -ne 1) {
        $JoinerValidationFailureCount++
        continue
    }

    $User = $Users[0]
    $ExpectedGroups = @(
        @($Request.BaselineGroups, $Request.DepartmentGroup, $Request.AccessGroups) |
            ForEach-Object { [string]$_ -split ';' } |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ } |
            Sort-Object -Unique
    )
    $ActualGroups = @(
        $User.MemberOf |
            ForEach-Object { Get-ADGroup -Identity $_ } |
            Where-Object SamAccountName -like 'GG_IAM_*' |
            Select-Object -ExpandProperty SamAccountName
    )
    $MissingGroups = @(
        $ExpectedGroups | Where-Object { $_ -notin $ActualGroups }
    )
    $UnexpectedGroups = @(
        $ActualGroups | Where-Object { $_ -notin $ExpectedGroups }
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
    $ExpectedDescription = "IAM Project 1 | Joiner | $($Request.WorkerType) | Active | $($Request.RequestID)"
    $IdentityValid = (
        $User.SamAccountName -eq $Request.SamAccountName -and
        $User.UserPrincipalName -eq $Request.UserPrincipalName -and
        $User.Enabled -and
        $User.employeeType -eq $Request.WorkerType -and
        $User.Department -eq $Request.Department -and
        $User.Title -eq $Request.JobTitle -and
        $null -ne $Manager -and
        $Manager.EmployeeID -eq $Request.ManagerEmployeeID -and
        $CurrentParentOU -eq $Request.TargetOU -and
        $User.Description -eq $ExpectedDescription -and
        $MissingGroups.Count -eq 0 -and
        $UnexpectedGroups.Count -eq 0
    )

    if ($Request.WorkerType -eq 'Contractor') {
        $ExpectedExpiration = ([datetime]$Request.EndDate).Date.AddDays(1)
        $IdentityValid = (
            $IdentityValid -and
            $null -ne $User.AccountExpirationDate -and
            $User.AccountExpirationDate.Date -eq $ExpectedExpiration
        )
    }

    if (-not $IdentityValid) {
        $JoinerValidationFailureCount++
    }

    if ($null -ne $User.Manager) {
        $JoinerManagerCount++
    }

    $JoinerDirectMembershipCount += $ActualGroups.Count
}

$LeaverUserCount = @(
    Get-ADUser -SearchBase $LeaversOU -SearchScope OneLevel -Filter *
).Count
$SYNC01 = Get-ADComputer -Identity 'SYNC01' -Properties Enabled
$SYNC01PlacementValid = (
    $SYNC01.DistinguishedName -eq $ExpectedSYNC01DN -and $SYNC01.Enabled
)
$PermanentEmployeeCount = @(
    Get-ADGroupMember -Identity 'GG_All_Employees' -Recursive
).Count
$IDTRUsers = @(
    Get-ADUser -Filter "SamAccountName -like 'idtr-user*'" -Properties Enabled
)
$IDTRDisabledCount = @($IDTRUsers | Where-Object { -not $_.Enabled }).Count
$HighValueGroupMembers = @(
    Get-ADGroupMember -Identity 'IDTR-HighValue-Lab'
).Count
$Mason = Get-ADUser -Identity 'mason.cole' -Properties AccountExpirationDate
$MasonExpirationDate = if ($null -ne $Mason.AccountExpirationDate) {
    $Mason.AccountExpirationDate.ToString('yyyy-MM-dd')
}
else {
    $null
}

$Passed = (
    $RunningServices.Count -eq 7 -and
    $AzureMonitorAgentRunning -and
    $CsvHash -eq $ExpectedCsvSHA256 -and
    $InitialAuditHash -eq $ExpectedInitialAuditSHA256 -and
    $ReplayAuditHash -eq $ExpectedReplayAuditSHA256 -and
    $InitialAuditEvents.Count -eq 25 -and
    $ReplayAuditEvents.Count -eq 5 -and
    $ReplayNoChangeCount -eq 3 -and
    $ReplayFailureCount -eq 0 -and
    $ControlledUsers.Count -eq 33 -and
    $EnabledUsers.Count -eq 33 -and
    $Employees.Count -eq 27 -and
    $Contractors.Count -eq 6 -and
    $ManagerAssigned.Count -eq 27 -and
    $TotalDirectMemberships -eq 153 -and
    $Requests.Count -eq 3 -and
    $JoinerValidationFailureCount -eq 0 -and
    $JoinerManagerCount -eq 3 -and
    $JoinerDirectMembershipCount -eq 13 -and
    $MasonExpirationDate -eq '2027-03-01' -and
    $LeaverUserCount -eq 0 -and
    $SYNC01PlacementValid -and
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
    DatasetHashMatches = ($CsvHash -eq $ExpectedCsvSHA256)
    InitialAuditHashMatches = ($InitialAuditHash -eq $ExpectedInitialAuditSHA256)
    InitialAuditEventCount = $InitialAuditEvents.Count
    ReplayAuditHashMatches = ($ReplayAuditHash -eq $ExpectedReplayAuditSHA256)
    ReplayAuditEventCount = $ReplayAuditEvents.Count
    ReplayNoChangeCount = $ReplayNoChangeCount
    ReplayFailureCount = $ReplayFailureCount
    ControlledUserCount = $ControlledUsers.Count
    EnabledUserCount = $EnabledUsers.Count
    EmployeeCount = $Employees.Count
    ContractorCount = $Contractors.Count
    ManagerAssignedCount = $ManagerAssigned.Count
    TotalDirectMemberships = $TotalDirectMemberships
    JoinerRequestCount = $Requests.Count
    JoinerValidationFailureCount = $JoinerValidationFailureCount
    JoinerManagerCount = $JoinerManagerCount
    JoinerDirectMembershipCount = $JoinerDirectMembershipCount
    MasonExpirationDate = $MasonExpirationDate
    LeaverUserCount = $LeaverUserCount
    SYNC01PlacementValid = $SYNC01PlacementValid
    PermanentEmployeeCount = $PermanentEmployeeCount
    IDTRUserCount = $IDTRUsers.Count
    IDTRDisabledCount = $IDTRDisabledCount
    HighValueGroupMembers = $HighValueGroupMembers
    ChangesMade = $false
} | Format-List

if (-not $Passed) {
    throw 'Milestone 4 joiner-state validation requires investigation.'
}

Write-Host ''
Write-Host 'PASS: The complete Milestone 4 joiner automation state is healthy and isolated.' -ForegroundColor Green
