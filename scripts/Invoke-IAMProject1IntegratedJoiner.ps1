<#
.SYNOPSIS
    Provisions the approved Milestone 8 integrated-test joiner.

.DESCRIPTION
    Validates the approved dataset and current Active Directory state before
    creating IAM3001. The account is created disabled with a unique random
    password, governed, validated, and enabled only after all controls succeed.
    The password is never displayed or exported. A correlated audit is written
    to C:\IAM-Lab\logs. Replaying a complete target state produces NoChange.

.NOTES
    Project: Microsoft Hybrid Identity Lifecycle Automation
    Milestone: 8 - Integrated hybrid lifecycle testing
#>

[CmdletBinding()]
param(
    [string]$DatasetPath = 'C:\IAM-Lab\data\iam-project1-integrated-lifecycle-test.csv',
    [string]$ExpectedSHA256 = '9FC4CFF3DB15DB11C7EE05486007953F436BC3FC48124B6275231886CDED9AD3',
    [string]$LogFolder = 'C:\IAM-Lab\logs'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($env:COMPUTERNAME -ne 'DC01') {
    throw "Run this script on DC01, not $env:COMPUTERNAME."
}

Import-Module ActiveDirectory

if ((Get-ADDomain).DNSRoot -ne 'corporate.test') {
    throw 'This script requires the corporate.test domain.'
}

foreach ($RequiredPath in @($DatasetPath, $LogFolder)) {
    if (-not (Test-Path -LiteralPath $RequiredPath)) {
        throw "Required path not found: $RequiredPath"
    }
}

$DatasetHash = (Get-FileHash -LiteralPath $DatasetPath -Algorithm SHA256).Hash
if ($DatasetHash -ne $ExpectedSHA256) {
    throw "Dataset hash mismatch. Expected $ExpectedSHA256 but found $DatasetHash."
}

$Records = @(Import-Csv -LiteralPath $DatasetPath)
if ($Records.Count -ne 1 -or $Records[0].ApprovalStatus -ne 'Approved') {
    throw 'Exactly one approved integrated lifecycle record is required.'
}

$Record = $Records[0]
$CorrelationID = 'M08-JOINER-{0}' -f (Get-Date -Format 'yyyyMMdd-HHmmss')
$AuditPath = Join-Path $LogFolder "$CorrelationID-audit.csv"
if (Test-Path -LiteralPath $AuditPath) {
    throw "Audit output already exists: $AuditPath"
}

$Audit = [System.Collections.Generic.List[object]]::new()

function Add-AuditEvent {
    param(
        [string]$Stage,
        [string]$Action,
        [string]$Result,
        [string]$Details
    )
    $Audit.Add([pscustomobject][ordered]@{
        TimestampUtc = [datetime]::UtcNow.ToString('o')
        CorrelationID = $CorrelationID
        TestID = $Record.TestID
        ApprovalID = $Record.JoinerApprovalID
        EmployeeID = $Record.EmployeeID
        SamAccountName = $Record.SamAccountName
        Stage = $Stage
        Action = $Action
        Result = $Result
        Details = $Details
    })
}

function Get-GroupList {
    param([string]$Value)
    return @(
        $Value -split ';' |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ } |
            Sort-Object -Unique
    )
}

function Get-ParentDN {
    param([string]$DistinguishedName)
    return $DistinguishedName.Substring($DistinguishedName.IndexOf(',') + 1)
}

function Get-DirectIAMGroups {
    param($User)
    return @(
        @($User.MemberOf) |
            Where-Object { $_ -like 'CN=GG_IAM_*' } |
            ForEach-Object { (Get-ADGroup -Identity $_).SamAccountName } |
            Sort-Object -Unique
    )
}

function Test-StringSetEqual {
    param([string[]]$Reference, [string[]]$Difference)
    return @(
        Compare-Object `
            -ReferenceObject @($Reference | Sort-Object -Unique) `
            -DifferenceObject @($Difference | Sort-Object -Unique)
    ).Count -eq 0
}

function New-RandomPassword {
    param([int]$Length = 24)
    $Sets = @(
        'ABCDEFGHJKLMNPQRSTUVWXYZ',
        'abcdefghijkmnopqrstuvwxyz',
        '23456789',
        '!@#$%*-_=+'
    )
    $All = $Sets -join ''
    $Provider = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $Characters = [System.Collections.Generic.List[char]]::new()
        foreach ($Set in $Sets) {
            $Bytes = New-Object byte[] 4
            $Provider.GetBytes($Bytes)
            $Characters.Add($Set[[BitConverter]::ToUInt32($Bytes, 0) % $Set.Length])
        }
        while ($Characters.Count -lt $Length) {
            $Bytes = New-Object byte[] 4
            $Provider.GetBytes($Bytes)
            $Characters.Add($All[[BitConverter]::ToUInt32($Bytes, 0) % $All.Length])
        }
        for ($Index = $Characters.Count - 1; $Index -gt 0; $Index--) {
            $Bytes = New-Object byte[] 4
            $Provider.GetBytes($Bytes)
            $Swap = [BitConverter]::ToUInt32($Bytes, 0) % ($Index + 1)
            $Temporary = $Characters[$Index]
            $Characters[$Index] = $Characters[$Swap]
            $Characters[$Swap] = $Temporary
        }
        return -join $Characters
    }
    finally {
        $Provider.Dispose()
    }
}

$ExpectedGroups = Get-GroupList -Value $Record.JoinerGroups
$EscapedEmployeeID = $Record.EmployeeID.Replace("'", "''")
$EscapedSam = $Record.SamAccountName.Replace("'", "''")
$EscapedUPN = $Record.UserPrincipalName.Replace("'", "''")
$Existing = @(
    Get-ADUser `
        -Filter "EmployeeID -eq '$EscapedEmployeeID' -or SamAccountName -eq '$EscapedSam' -or UserPrincipalName -eq '$EscapedUPN'" `
        -Properties EmployeeID, UserPrincipalName, GivenName, Surname, DisplayName,
            Department, Title, Company, Mail, employeeType, Description, Manager,
            MemberOf, Enabled
)

$ManagerID = $Record.JoinerManagerEmployeeID.Replace("'", "''")
$Managers = @(Get-ADUser -Filter "EmployeeID -eq '$ManagerID'" -Properties EmployeeID, Enabled)
if ($Managers.Count -ne 1 -or -not $Managers[0].Enabled) {
    throw 'The approved joiner manager is missing, duplicated or disabled.'
}
$Manager = $Managers[0]

if ($null -eq (Get-ADOrganizationalUnit -Identity $Record.JoinerOU -ErrorAction SilentlyContinue)) {
    throw 'The approved joiner OU does not exist.'
}
foreach ($GroupName in $ExpectedGroups) {
    $Group = Get-ADGroup -Identity $GroupName -Properties GroupCategory, GroupScope
    if ($Group.GroupCategory -ne 'Security' -or $Group.GroupScope -ne 'Global') {
        throw "Invalid approved group: $GroupName"
    }
}

$FinalDescription = "IAM Project 1 | Integrated Joiner | Employee | Active | $($Record.TestID)"
$CreatedThisRun = $false

try {
    Add-AuditEvent 'Preflight' 'ValidateApprovedRequest' 'Passed' 'Dataset, approval, manager, OU and groups validated before change.'

    if ($Existing.Count -gt 1) {
        throw 'Multiple identities collide with the approved integrated joiner.'
    }

    if ($Existing.Count -eq 1) {
        $User = $Existing[0]
        $ActualGroups = Get-DirectIAMGroups -User $User
        $TargetState = (
            $User.EmployeeID -eq $Record.EmployeeID -and
            $User.SamAccountName -eq $Record.SamAccountName -and
            $User.UserPrincipalName -eq $Record.UserPrincipalName -and
            $User.GivenName -eq $Record.GivenName -and
            $User.Surname -eq $Record.Surname -and
            $User.DisplayName -eq $Record.DisplayName -and
            $User.Department -eq $Record.JoinerDepartment -and
            $User.Title -eq $Record.JoinerJobTitle -and
            $User.Company -eq $Record.Company -and
            $User.employeeType -eq $Record.JoinerWorkerType -and
            $User.Manager -eq $Manager.DistinguishedName -and
            (Get-ParentDN $User.DistinguishedName) -eq $Record.JoinerOU -and
            (Test-StringSetEqual $ActualGroups $ExpectedGroups) -and
            $User.Enabled
        )
        if (-not $TargetState) {
            throw 'An existing identity collision does not match the complete approved target state.'
        }
        Add-AuditEvent 'Execution' 'JoinerStateNoChange' 'NoChange' 'IAM3001 already matches the complete approved joiner state.'
    }
    else {
        $PlainPassword = New-RandomPassword
        $SecurePassword = ConvertTo-SecureString $PlainPassword -AsPlainText -Force
        try {
            New-ADUser `
                -Name $Record.DisplayName `
                -GivenName $Record.GivenName `
                -Surname $Record.Surname `
                -DisplayName $Record.DisplayName `
                -SamAccountName $Record.SamAccountName `
                -UserPrincipalName $Record.UserPrincipalName `
                -EmailAddress $Record.UserPrincipalName `
                -EmployeeID $Record.EmployeeID `
                -Company $Record.Company `
                -Department $Record.JoinerDepartment `
                -Title $Record.JoinerJobTitle `
                -Description "IAM Project 1 | Integrated Joiner | Employee | Staged | $($Record.TestID)" `
                -Path $Record.JoinerOU `
                -AccountPassword $SecurePassword `
                -ChangePasswordAtLogon $true `
                -Enabled $false `
                -OtherAttributes @{ employeeType = $Record.JoinerWorkerType }
        }
        finally {
            $PlainPassword = $null
            $SecurePassword = $null
        }
        $CreatedThisRun = $true
        Add-AuditEvent 'Execution' 'CreateDisabledAccount' 'Success' 'IAM3001 created in a disabled staging state; password was not logged or exported.'

        $User = Get-ADUser -Identity $Record.SamAccountName -Properties MemberOf
        Set-ADUser -Identity $User -Manager $Manager.DistinguishedName
        Add-AuditEvent 'Governance' 'AssignManager' 'Success' "Approved manager $($Record.JoinerManagerEmployeeID) assigned."

        foreach ($GroupName in $ExpectedGroups) {
            Add-ADGroupMember -Identity $GroupName -Members $User
            Add-AuditEvent 'Authorization' 'AddGroupMembership' 'Success' "Added approved group $GroupName."
        }

        Set-ADUser -Identity $User -Description $FinalDescription
        $User = Get-ADUser -Identity $Record.SamAccountName -Properties EmployeeID, UserPrincipalName,
            GivenName, Surname, DisplayName, Department, Title, Company, employeeType,
            Description, Manager, MemberOf, Enabled
        $PreEnableGroups = Get-DirectIAMGroups -User $User
        $GovernanceValid = (
            -not $User.Enabled -and
            $User.EmployeeID -eq $Record.EmployeeID -and
            $User.Manager -eq $Manager.DistinguishedName -and
            (Get-ParentDN $User.DistinguishedName) -eq $Record.JoinerOU -and
            (Test-StringSetEqual $PreEnableGroups $ExpectedGroups)
        )
        if (-not $GovernanceValid) {
            throw 'Pre-enable governance validation failed.'
        }
        Add-AuditEvent 'Validation' 'ValidatePreEnableState' 'Passed' 'Disabled staged identity has the approved attributes, manager, OU and access.'

        Enable-ADAccount -Identity $User
        Add-AuditEvent 'Activation' 'EnableAccount' 'Success' 'Account enabled only after governance validation passed.'
    }

    $FinalUser = Get-ADUser -Identity $Record.SamAccountName -Properties EmployeeID,
        UserPrincipalName, GivenName, Surname, DisplayName, Department, Title,
        Company, Mail, employeeType, Description, Manager, MemberOf, Enabled
    $FinalGroups = Get-DirectIAMGroups -User $FinalUser
    $FinalStateValid = (
        $FinalUser.Enabled -and
        $FinalUser.EmployeeID -eq $Record.EmployeeID -and
        $FinalUser.UserPrincipalName -eq $Record.UserPrincipalName -and
        $FinalUser.Department -eq $Record.JoinerDepartment -and
        $FinalUser.Title -eq $Record.JoinerJobTitle -and
        $FinalUser.Company -eq $Record.Company -and
        $FinalUser.employeeType -eq $Record.JoinerWorkerType -and
        $FinalUser.Manager -eq $Manager.DistinguishedName -and
        (Get-ParentDN $FinalUser.DistinguishedName) -eq $Record.JoinerOU -and
        (Test-StringSetEqual $FinalGroups $ExpectedGroups)
    )
    if (-not $FinalStateValid) {
        throw 'Final integrated joiner state validation failed.'
    }
    Add-AuditEvent 'Validation' 'ValidateFinalJoinerState' 'Passed' 'IAM3001 matches the complete approved joiner state.'
}
catch {
    Add-AuditEvent 'Failure' 'JoinerWorkflowFailure' 'Failed' $_.Exception.Message
    if ($CreatedThisRun) {
        $SafetyUser = Get-ADUser -Identity $Record.SamAccountName -ErrorAction SilentlyContinue
        if ($null -ne $SafetyUser) {
            Disable-ADAccount -Identity $SafetyUser
            Add-AuditEvent 'Recovery' 'SafetyDisableAccount' 'Success' 'Newly created identity retained but safety-disabled after failure.'
        }
    }
    throw
}
finally {
    if ($Audit.Count -gt 0) {
        $Audit | Export-Csv -LiteralPath $AuditPath -NoTypeInformation -Encoding UTF8
    }
}

$IAMRoot = 'OU=IAM-Lab,DC=corporate,DC=test'
$ControlledUsers = @(Get-ADUser -SearchBase $IAMRoot -SearchScope Subtree -Filter 'EmployeeID -like "IAM*"' -Properties Enabled, employeeType, MemberOf)
$EnabledUsers = @($ControlledUsers | Where-Object Enabled)
$Employees = @($ControlledUsers | Where-Object employeeType -eq 'Employee')
$Contractors = @($ControlledUsers | Where-Object employeeType -eq 'Contractor')
$TotalMemberships = @($ControlledUsers | ForEach-Object { @($_.MemberOf | Where-Object { $_ -like 'CN=GG_IAM_*' }) }).Count
$FailedEvents = @($Audit | Where-Object Result -eq 'Failed')

[pscustomobject]@{
    CorrelationID = $CorrelationID
    AuditPath = $AuditPath
    AuditEventCount = $Audit.Count
    FailedAuditEventCount = $FailedEvents.Count
    EmployeeID = $FinalUser.EmployeeID
    AccountEnabled = $FinalUser.Enabled
    Department = $FinalUser.Department
    JobTitle = $FinalUser.Title
    DirectIAMGroupCount = $FinalGroups.Count
    ControlledUserCount = $ControlledUsers.Count
    EnabledUserCount = $EnabledUsers.Count
    EmployeeCount = $Employees.Count
    ContractorCount = $Contractors.Count
    TotalDirectMemberships = $TotalMemberships
    PasswordDisplayedOrExported = $false
    ChangesMade = $CreatedThisRun
} | Format-List

$Passed = (
    $FinalStateValid -and
    $FailedEvents.Count -eq 0 -and
    $ControlledUsers.Count -eq 34 -and
    $EnabledUsers.Count -eq 31 -and
    $Employees.Count -eq 29 -and
    $Contractors.Count -eq 5 -and
    $TotalMemberships -eq 145
)
if (-not $Passed) {
    throw 'FAIL: The integrated joiner completed but the expected aggregate state was not reached.'
}

Write-Host ''
Write-Host 'PASS: IAM3001 was provisioned, governed, enabled and audited for Cloud Sync validation.' -ForegroundColor Green
