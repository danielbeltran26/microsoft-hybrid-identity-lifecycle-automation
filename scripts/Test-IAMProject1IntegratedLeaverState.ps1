<#
.SYNOPSIS
    Validates the Milestone 8 IAM3001 Leaver audit and effective AD state.
#>

[CmdletBinding()]
param(
    [string]$DatasetPath = 'C:\IAM-Lab\data\iam-project1-integrated-lifecycle-test.csv',
    [string]$ExpectedDatasetSHA256 = '9FC4CFF3DB15DB11C7EE05486007953F436BC3FC48124B6275231886CDED9AD3',
    [string]$CorrelationID = 'M08-LEAVER-20260905-215905',
    [string]$AuditPath = 'C:\IAM-Lab\logs\M08-LEAVER-20260905-215905-audit.csv',
    [string]$UsersRoot = 'OU=Users,OU=IAM-Lab,DC=corporate,DC=test'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

function Get-ParentDistinguishedName {
    param([string]$DistinguishedName)
    return $DistinguishedName.Substring($DistinguishedName.IndexOf(',') + 1)
}

function Get-DirectIAMGroups {
    param($User)
    return @(
        $User.MemberOf |
            Where-Object { $_ -like 'CN=GG_IAM_*' } |
            ForEach-Object { (Get-ADGroup -Identity $_).SamAccountName } |
            Sort-Object -Unique
    )
}

if ($env:COMPUTERNAME -ne 'DC01') {
    throw "Run this validator on DC01, not $env:COMPUTERNAME."
}
if ((Get-ADDomain).DNSRoot -ne 'corporate.test') {
    throw 'The connected domain is not corporate.test.'
}

foreach ($RequiredFile in @($DatasetPath, $AuditPath)) {
    if (-not (Test-Path -LiteralPath $RequiredFile -PathType Leaf)) {
        throw "Required file not found: $RequiredFile"
    }
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

$Audit = @(Import-Csv -LiteralPath $AuditPath)
$RequiredAuditColumns = @(
    'TimestampUTC', 'CorrelationID', 'TestID', 'ApprovalID',
    'EmployeeID', 'SamAccountName', 'Action', 'Result', 'Detail'
)
$AuditColumns = if ($Audit.Count -gt 0) {
    @($Audit[0].PSObject.Properties.Name)
}
else {
    @()
}
$MissingAuditColumns = @(
    $RequiredAuditColumns | Where-Object { $_ -notin $AuditColumns }
)
$SecretColumns = @(
    $AuditColumns |
        Where-Object { $_ -match '(?i)password|secret|credential|token|securestring' }
)
$SensitiveValuePatterns = @(
    $Audit |
        ForEach-Object { $_.PSObject.Properties.Value } |
        Where-Object {
            $_ -match '(?i)(password\s*[=:]|secret\s*[=:]|bearer\s+[a-z0-9._-]+)'
        }
)

$TimestampParseFailures = 0
$ParsedTimestamps = [System.Collections.Generic.List[datetime]]::new()
foreach ($AuditEvent in $Audit) {
    $ParsedTimestamp = [datetime]::MinValue
    if (-not [datetime]::TryParse($AuditEvent.TimestampUTC, [ref]$ParsedTimestamp)) {
        $TimestampParseFailures++
    }
    else {
        $ParsedTimestamps.Add($ParsedTimestamp)
    }
}

$TimestampOrderFailures = 0
for ($Index = 1; $Index -lt $ParsedTimestamps.Count; $Index++) {
    if ($ParsedTimestamps[$Index] -lt $ParsedTimestamps[$Index - 1]) {
        $TimestampOrderFailures++
    }
}

$CorrelationMismatches = @(
    $Audit |
        Where-Object {
            $_.CorrelationID -ne $CorrelationID -or
            $_.TestID -ne 'M08-E2E-001' -or
            $_.ApprovalID -ne 'APR-M08-LEAVER-001' -or
            $_.EmployeeID -ne 'IAM3001' -or
            $_.SamAccountName -ne 'nora.whitfield'
        }
)
$FailedAuditEvents = @($Audit | Where-Object Result -eq 'Failed')
$DisableEvents = @($Audit | Where-Object Action -eq 'DisableAccount')
$RemoveEvents = @($Audit | Where-Object Action -eq 'RemoveMembership')
$MoveEvents = @($Audit | Where-Object Action -eq 'MoveToLeaversOU')
$DescriptionEvents = @($Audit | Where-Object Action -eq 'UpdateLifecycleDescription')
$ValidationEvents = @($Audit | Where-Object Action -eq 'ValidateLeaverState')
$PostValidationEvents = @($Audit | Where-Object Action -eq 'PostLeaverValidation')
$PreflightEvents = @($Audit | Where-Object Action -eq 'PreflightValidation')

$Actions = @($Audit | ForEach-Object Action)
$DisableIndex = [array]::IndexOf($Actions, 'DisableAccount')
$FirstRemovalIndex = [array]::IndexOf($Actions, 'RemoveMembership')
$LastRemovalIndex = [array]::LastIndexOf($Actions, 'RemoveMembership')
$MoveIndex = [array]::IndexOf($Actions, 'MoveToLeaversOU')
$ValidateIndex = [array]::IndexOf($Actions, 'ValidateLeaverState')
$PostValidateIndex = [array]::IndexOf($Actions, 'PostLeaverValidation')
$ExecutionOrderingValid = (
    $DisableIndex -ge 0 -and
    $FirstRemovalIndex -gt $DisableIndex -and
    $MoveIndex -gt $LastRemovalIndex -and
    $ValidateIndex -gt $MoveIndex -and
    $PostValidateIndex -gt $ValidateIndex
)

$AuditValidationPassed = (
    $Audit.Count -eq 11 -and
    $MissingAuditColumns.Count -eq 0 -and
    $SecretColumns.Count -eq 0 -and
    $SensitiveValuePatterns.Count -eq 0 -and
    $TimestampParseFailures -eq 0 -and
    $TimestampOrderFailures -eq 0 -and
    $CorrelationMismatches.Count -eq 0 -and
    $FailedAuditEvents.Count -eq 0 -and
    $PreflightEvents.Count -eq 1 -and
    $DisableEvents.Count -eq 1 -and
    $RemoveEvents.Count -eq 5 -and
    $MoveEvents.Count -eq 1 -and
    $DescriptionEvents.Count -eq 1 -and
    $ValidationEvents.Count -eq 1 -and
    $PostValidationEvents.Count -eq 1 -and
    $ExecutionOrderingValid
)

$User = Get-ADUser `
    -Identity $Record.SamAccountName `
    -Properties EmployeeID, DisplayName, UserPrincipalName, Enabled,
        Company, Department, Title, employeeType, Manager, MemberOf,
        Description
$ManagerEmployeeID = (
    Get-ADUser -Identity $User.Manager -Properties EmployeeID
).EmployeeID
$ActualGroups = @(Get-DirectIAMGroups -User $User)
$ActualOU = Get-ParentDistinguishedName -DistinguishedName $User.DistinguishedName
$ExpectedDescription = (
    'IAM Project 1 | Integrated Leaver | Disabled | {0}' -f
    $Record.LeaverApprovalID
)

$ControlledUsers = @(
    Get-ADUser `
        -SearchBase $UsersRoot `
        -LDAPFilter '(objectCategory=person)' `
        -Properties Enabled, employeeType, MemberOf
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

$StateValidationPassed = (
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
    $ActualGroups.Count -eq 0 -and
    $User.Description -eq $ExpectedDescription -and
    $ControlledUsers.Count -eq 34 -and
    @($ControlledUsers | Where-Object Enabled).Count -eq 30 -and
    @($ControlledUsers | Where-Object employeeType -eq 'Employee').Count -eq 29 -and
    @($ControlledUsers | Where-Object employeeType -eq 'Contractor').Count -eq 5 -and
    $TotalDirectMemberships -eq 140 -and
    $Leavers.Count -eq 4
)

[pscustomobject]@{
    CorrelationID = $CorrelationID
    AuditEventCount = $Audit.Count
    MissingAuditColumnCount = $MissingAuditColumns.Count
    SecretColumnCount = $SecretColumns.Count
    SensitiveValuePatternCount = $SensitiveValuePatterns.Count
    TimestampParseFailureCount = $TimestampParseFailures
    TimestampOrderFailureCount = $TimestampOrderFailures
    CorrelationMismatchCount = $CorrelationMismatches.Count
    FailedAuditEventCount = $FailedAuditEvents.Count
    AccountDisableEventCount = $DisableEvents.Count
    MembershipRemovalEventCount = $RemoveEvents.Count
    ExecutionOrderingValid = $ExecutionOrderingValid
    AuditValidationPassed = $AuditValidationPassed
    EmployeeID = $User.EmployeeID
    AccountEnabled = $User.Enabled
    DepartmentPreserved = $User.Department
    JobTitlePreserved = $User.Title
    ManagerEmployeeIDPreserved = $ManagerEmployeeID
    DirectIAMGroupCount = $ActualGroups.Count
    OrganisationalUnitValid = $ActualOU -eq $Record.LeaverOU
    IdentityRetained = $null -ne $User
    ControlledUserCount = $ControlledUsers.Count
    EnabledUserCount = @($ControlledUsers | Where-Object Enabled).Count
    TotalDirectMemberships = $TotalDirectMemberships
    LeaversOUUserCount = $Leavers.Count
    StateValidationPassed = $StateValidationPassed
    ChangesMade = $false
} | Format-List

if (-not ($AuditValidationPassed -and $StateValidationPassed)) {
    throw 'The IAM3001 Leaver audit or effective AD state validation failed.'
}

Write-Host ''
Write-Host `
    'PASS: IAM3001 Leaver audit integrity and effective Active Directory containment are fully validated.' `
    -ForegroundColor Green
