<#
.SYNOPSIS
    Validates the final Milestone 8 integrated lifecycle state on DC01.

.DESCRIPTION
    Performs read-only validation of the approved IAM3001 dataset, Joiner,
    Mover and Leaver audit trails, effective Active Directory containment and
    preserved IAM-Lab population. It makes no directory or file changes.
#>

[CmdletBinding()]
param(
    [string]$DatasetPath = 'C:\IAM-Lab\data\iam-project1-integrated-lifecycle-test.csv',
    [string]$ExpectedDatasetSHA256 = '9FC4CFF3DB15DB11C7EE05486007953F436BC3FC48124B6275231886CDED9AD3',
    [string]$UsersRoot = 'OU=Users,OU=IAM-Lab,DC=corporate,DC=test',
    [string]$GroupsRoot = 'OU=Groups,OU=IAM-Lab,DC=corporate,DC=test',
    [string]$JoinerCorrelationID = 'M08-JOINER-20260905-183407',
    [string]$MoverCorrelationID = 'M08-MOVER-20260905-205706',
    [string]$LeaverCorrelationID = 'M08-LEAVER-20260905-215905',
    [string]$LogFolder = 'C:\IAM-Lab\logs'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

function Get-ParentDistinguishedName {
    param([string]$DistinguishedName)
    return $DistinguishedName.Substring($DistinguishedName.IndexOf(',') + 1)
}

function Test-LifecycleAudit {
    param(
        [string]$CorrelationID,
        [string]$ApprovalID,
        [int]$ExpectedEventCount
    )

    $AuditPath = Join-Path $LogFolder "$CorrelationID-audit.csv"
    if (-not (Test-Path -LiteralPath $AuditPath -PathType Leaf)) {
        throw "Required audit not found: $AuditPath"
    }

    $Events = @(Import-Csv -LiteralPath $AuditPath)
    $RequiredColumns = @(
        'TimestampUTC', 'CorrelationID', 'TestID', 'ApprovalID',
        'EmployeeID', 'SamAccountName', 'Action', 'Result'
    )
    $Columns = if ($Events.Count -gt 0) {
        @($Events[0].PSObject.Properties.Name)
    }
    else {
        @()
    }
    $MissingColumns = @(
        $RequiredColumns | Where-Object { $_ -notin $Columns }
    )
    $HasDetailsColumn = (
        'Detail' -in $Columns -or
        'Details' -in $Columns
    )
    $SecretColumns = @(
        $Columns |
            Where-Object {
                $_ -match '(?i)password|secret|credential|token|securestring'
            }
    )
    $SensitiveValues = @(
        $Events |
            ForEach-Object { $_.PSObject.Properties.Value } |
            Where-Object {
                $_ -match '(?i)(password\s*[=:]|secret\s*[=:]|bearer\s+[a-z0-9._-]+)'
            }
    )
    $InvalidEvents = @(
        $Events |
            Where-Object {
                $_.CorrelationID -ne $CorrelationID -or
                $_.TestID -ne 'M08-E2E-001' -or
                $_.ApprovalID -ne $ApprovalID -or
                $_.EmployeeID -ne 'IAM3001' -or
                $_.SamAccountName -ne 'nora.whitfield' -or
                $_.Result -eq 'Failed'
            }
    )

    $TimestampFailures = 0
    $OrderFailures = 0
    $PreviousTimestamp = [datetime]::MinValue
    foreach ($Event in $Events) {
        $Timestamp = [datetime]::MinValue
        if (-not [datetime]::TryParse($Event.TimestampUTC, [ref]$Timestamp)) {
            $TimestampFailures++
            continue
        }
        if ($Timestamp -lt $PreviousTimestamp) {
            $OrderFailures++
        }
        $PreviousTimestamp = $Timestamp
    }

    $Passed = (
        $Events.Count -eq $ExpectedEventCount -and
        $MissingColumns.Count -eq 0 -and
        $HasDetailsColumn -and
        $SecretColumns.Count -eq 0 -and
        $SensitiveValues.Count -eq 0 -and
        $InvalidEvents.Count -eq 0 -and
        $TimestampFailures -eq 0 -and
        $OrderFailures -eq 0
    )

    return [pscustomobject]@{
        CorrelationID = $CorrelationID
        EventCount = $Events.Count
        ExpectedEventCount = $ExpectedEventCount
        FailedEventCount = @($Events | Where-Object Result -eq 'Failed').Count
        MissingColumnCount = $MissingColumns.Count
        DetailsColumnPresent = $HasDetailsColumn
        SecretColumnCount = $SecretColumns.Count
        SensitiveValuePatternCount = $SensitiveValues.Count
        TimestampFailureCount = $TimestampFailures
        TimestampOrderFailureCount = $OrderFailures
        Passed = $Passed
    }
}

if ($env:COMPUTERNAME -ne 'DC01') {
    throw "Run this validator on DC01, not $env:COMPUTERNAME."
}
if ((Get-ADDomain).DNSRoot -ne 'corporate.test') {
    throw 'The connected domain is not corporate.test.'
}
if (-not (Test-Path -LiteralPath $DatasetPath -PathType Leaf)) {
    throw "Required dataset not found: $DatasetPath"
}

$DatasetHashMatches = (
    (Get-FileHash -LiteralPath $DatasetPath -Algorithm SHA256).Hash -eq
    $ExpectedDatasetSHA256
)
if (-not $DatasetHashMatches) {
    throw 'The integrated lifecycle dataset hash does not match.'
}

$Records = @(Import-Csv -LiteralPath $DatasetPath)
if ($Records.Count -ne 1) {
    throw "Expected one lifecycle record but found $($Records.Count)."
}
$Record = $Records[0]

$AuditResults = @(
    Test-LifecycleAudit `
        -CorrelationID $JoinerCorrelationID `
        -ApprovalID $Record.JoinerApprovalID `
        -ExpectedEventCount 11
    Test-LifecycleAudit `
        -CorrelationID $MoverCorrelationID `
        -ApprovalID $Record.MoverApprovalID `
        -ExpectedEventCount 10
    Test-LifecycleAudit `
        -CorrelationID $LeaverCorrelationID `
        -ApprovalID $Record.LeaverApprovalID `
        -ExpectedEventCount 11
)

$User = Get-ADUser `
    -Identity $Record.SamAccountName `
    -Properties EmployeeID, DisplayName, UserPrincipalName, Enabled, Company,
        Department, Title, employeeType, Manager, MemberOf, Description
$ManagerEmployeeID = (
    Get-ADUser -Identity $User.Manager -Properties EmployeeID
).EmployeeID
$DirectIAMGroups = @(
    $User.MemberOf | Where-Object { $_ -like 'CN=GG_IAM_*' }
)
$ActualOU = Get-ParentDistinguishedName -DistinguishedName $User.DistinguishedName
$ExpectedDescription = (
    'IAM Project 1 | Integrated Leaver | Disabled | {0}' -f
    $Record.LeaverApprovalID
)

$ControlledUsers = @(
    Get-ADUser `
        -SearchBase $UsersRoot `
        -LDAPFilter '(objectCategory=person)' `
        -Properties Enabled, employeeType, EmployeeID, MemberOf
)
$IAMGroups = @(
    Get-ADGroup `
        -SearchBase $GroupsRoot `
        -Filter 'SamAccountName -like "GG_IAM_*"' `
        -Properties GroupCategory, GroupScope
)
$TotalDirectMemberships = (
    $ControlledUsers |
        ForEach-Object {
            @($_.MemberOf | Where-Object { $_ -like 'CN=GG_IAM_*' }).Count
        } |
        Measure-Object -Sum
).Sum
$Leavers = @(
    Get-ADUser -SearchBase $Record.LeaverOU -SearchScope OneLevel -Filter *
)

$IdentityStatePassed = (
    $User.EmployeeID -eq 'IAM3001' -and
    -not $User.Enabled -and
    $User.DisplayName -eq $Record.DisplayName -and
    $User.UserPrincipalName -eq $Record.UserPrincipalName -and
    $User.Company -eq $Record.Company -and
    $User.Department -eq $Record.MoverDepartment -and
    $User.Title -eq $Record.MoverJobTitle -and
    $User.employeeType -eq $Record.MoverWorkerType -and
    $ManagerEmployeeID -eq $Record.MoverManagerEmployeeID -and
    $ActualOU -eq $Record.LeaverOU -and
    $DirectIAMGroups.Count -eq 0 -and
    $User.Description -eq $ExpectedDescription
)

$PopulationStatePassed = (
    $ControlledUsers.Count -eq 34 -and
    @($ControlledUsers | Where-Object Enabled).Count -eq 30 -and
    @($ControlledUsers | Where-Object { -not $_.Enabled }).Count -eq 4 -and
    @($ControlledUsers | Where-Object employeeType -eq 'Employee').Count -eq 29 -and
    @($ControlledUsers | Where-Object employeeType -eq 'Contractor').Count -eq 5 -and
    @($ControlledUsers | Where-Object { $_.EmployeeID -like 'IAM*' }).Count -eq 34 -and
    $IAMGroups.Count -eq 15 -and
    @($IAMGroups | Where-Object GroupCategory -ne 'Security').Count -eq 0 -and
    @($IAMGroups | Where-Object GroupScope -ne 'Global').Count -eq 0 -and
    $TotalDirectMemberships -eq 140 -and
    $Leavers.Count -eq 4
)

$AuditResults |
    Select-Object CorrelationID, EventCount, ExpectedEventCount,
        FailedEventCount, Passed |
    Format-Table -AutoSize

$FinalValidationPassed = (
    $DatasetHashMatches -and
    @($AuditResults | Where-Object { -not $_.Passed }).Count -eq 0 -and
    $IdentityStatePassed -and
    $PopulationStatePassed
)

[pscustomobject]@{
    ComputerName = $env:COMPUTERNAME
    DatasetHashMatches = $DatasetHashMatches
    LifecycleAuditCount = $AuditResults.Count
    FailedLifecycleAuditCount = @(
        $AuditResults | Where-Object { -not $_.Passed }
    ).Count
    TotalLifecycleAuditEvents = (
        $AuditResults | Measure-Object EventCount -Sum
    ).Sum
    EmployeeID = $User.EmployeeID
    IdentityRetained = $null -ne $User
    AccountEnabled = $User.Enabled
    DepartmentPreserved = $User.Department
    JobTitlePreserved = $User.Title
    ManagerEmployeeIDPreserved = $ManagerEmployeeID
    OrganisationalUnitValid = $ActualOU -eq $Record.LeaverOU
    DirectIAMGroupCount = $DirectIAMGroups.Count
    IdentityStatePassed = $IdentityStatePassed
    ControlledUserCount = $ControlledUsers.Count
    EnabledUserCount = @($ControlledUsers | Where-Object Enabled).Count
    DisabledUserCount = @($ControlledUsers | Where-Object { -not $_.Enabled }).Count
    EmployeeCount = @($ControlledUsers | Where-Object employeeType -eq 'Employee').Count
    ContractorCount = @($ControlledUsers | Where-Object employeeType -eq 'Contractor').Count
    IAMGroupCount = $IAMGroups.Count
    TotalDirectMemberships = $TotalDirectMemberships
    LeaversOUUserCount = $Leavers.Count
    PopulationStatePassed = $PopulationStatePassed
    FinalValidationPassed = $FinalValidationPassed
    ChangesMade = $false
    ActiveDirectoryChanges = $false
} | Format-List

if (-not $FinalValidationPassed) {
    throw 'The final Milestone 8 integrated lifecycle validation failed.'
}

Write-Host ''
Write-Host `
    'PASS: The complete IAM3001 lifecycle, audit trail and final Active Directory state are fully validated.' `
    -ForegroundColor Green
