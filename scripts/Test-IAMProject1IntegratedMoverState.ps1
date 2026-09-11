<#
.SYNOPSIS
    Validates the Milestone 8 IAM3001 Mover audit and effective AD state.
#>

[CmdletBinding()]
param(
    [string]$DatasetPath = 'C:\IAM-Lab\data\iam-project1-integrated-lifecycle-test.csv',
    [string]$ExpectedDatasetSHA256 = '9FC4CFF3DB15DB11C7EE05486007953F436BC3FC48124B6275231886CDED9AD3',
    [string]$CorrelationID = 'M08-MOVER-20260905-205706',
    [string]$AuditPath = 'C:\IAM-Lab\logs\M08-MOVER-20260905-205706-audit.csv',
    [string]$UsersRoot = 'OU=Users,OU=IAM-Lab,DC=corporate,DC=test'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module ActiveDirectory

function ConvertTo-GroupList {
    param([string]$Value)

    return @(
        $Value -split ';' |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ } |
            Sort-Object -Unique
    )
}

function Test-StringSetEqual {
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

function Get-ParentDistinguishedName {
    param([string]$DistinguishedName)

    return $DistinguishedName.Substring($DistinguishedName.IndexOf(',') + 1)
}

if ($env:COMPUTERNAME -ne 'DC01') {
    throw "Run this validator on DC01, not $env:COMPUTERNAME."
}

if ((Get-ADDomain).DNSRoot -ne 'corporate.test') {
    throw 'The connected Active Directory domain is not corporate.test.'
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
            $_.ApprovalID -ne 'APR-M08-MOVER-001' -or
            $_.EmployeeID -ne 'IAM3001' -or
            $_.SamAccountName -ne 'nora.whitfield'
        }
)
$FailedAuditEvents = @($Audit | Where-Object Result -eq 'Failed')
$RemoveEvents = @($Audit | Where-Object Action -eq 'RemoveObsoleteMembership')
$AddEvents = @($Audit | Where-Object Action -eq 'AddApprovedMembership')
$RequiredSingleActions = @(
    'PreflightValidation',
    'UpdateIdentityAttributes',
    'ChangeManager',
    'MoveOrganizationalUnit',
    'ValidateMoverState',
    'PostMoverValidation'
)
$MissingOrDuplicateActions = @(
    $RequiredSingleActions |
        Where-Object {
            @($Audit | Where-Object Action -eq $_).Count -ne 1
        }
)

$ActionNames = @($Audit | ForEach-Object Action)
$FirstAddIndex = [array]::IndexOf($ActionNames, 'AddApprovedMembership')
$LastRemoveIndex = [array]::LastIndexOf($ActionNames, 'RemoveObsoleteMembership')
$ValidationIndex = [array]::IndexOf($ActionNames, 'ValidateMoverState')
$PostValidationIndex = [array]::IndexOf($ActionNames, 'PostMoverValidation')
$ExecutionOrderingValid = (
    $LastRemoveIndex -ge 0 -and
    $FirstAddIndex -gt $LastRemoveIndex -and
    $ValidationIndex -gt $FirstAddIndex -and
    $PostValidationIndex -gt $ValidationIndex
)

$AuditValidationPassed = (
    $Audit.Count -eq 10 -and
    $MissingAuditColumns.Count -eq 0 -and
    $SecretColumns.Count -eq 0 -and
    $SensitiveValuePatterns.Count -eq 0 -and
    $TimestampParseFailures -eq 0 -and
    $TimestampOrderFailures -eq 0 -and
    $CorrelationMismatches.Count -eq 0 -and
    $FailedAuditEvents.Count -eq 0 -and
    $RemoveEvents.Count -eq 2 -and
    $AddEvents.Count -eq 2 -and
    $MissingOrDuplicateActions.Count -eq 0 -and
    $ExecutionOrderingValid
)

$User = Get-ADUser `
    -Identity $Record.SamAccountName `
    -Properties EmployeeID, UserPrincipalName, Enabled, Company,
        Department, Title, employeeType, Manager, MemberOf

$ManagerEmployeeID = (
    Get-ADUser -Identity $User.Manager -Properties EmployeeID
).EmployeeID

$ActualGroups = @(
    $User.MemberOf |
        Where-Object { $_ -like 'CN=GG_IAM_*' } |
        ForEach-Object { (Get-ADGroup -Identity $_).SamAccountName } |
        Sort-Object -Unique
)
$ExpectedGroups = @(ConvertTo-GroupList -Value $Record.MoverGroups)
$FormerFinanceGroups = @(
    'GG_IAM_Access_Finance_ERP',
    'GG_IAM_Department_Finance'
)
$RemainingFinanceGroups = @(
    $ActualGroups | Where-Object { $_ -in $FormerFinanceGroups }
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

$StateValidationPassed = (
    $User.EmployeeID -eq 'IAM3001' -and
    $User.Enabled -and
    $User.UserPrincipalName -eq $Record.UserPrincipalName -and
    $User.Company -eq $Record.Company -and
    $User.Department -eq $Record.MoverDepartment -and
    $User.Title -eq $Record.MoverJobTitle -and
    $User.employeeType -eq $Record.MoverWorkerType -and
    $ManagerEmployeeID -eq $Record.MoverManagerEmployeeID -and
    (Get-ParentDistinguishedName -DistinguishedName $User.DistinguishedName) -eq $Record.MoverOU -and
    (Test-StringSetEqual -Reference $ExpectedGroups -Difference $ActualGroups) -and
    $RemainingFinanceGroups.Count -eq 0 -and
    $ControlledUsers.Count -eq 34 -and
    @($ControlledUsers | Where-Object Enabled).Count -eq 31 -and
    @($ControlledUsers | Where-Object employeeType -eq 'Employee').Count -eq 29 -and
    @($ControlledUsers | Where-Object employeeType -eq 'Contractor').Count -eq 5 -and
    $TotalDirectMemberships -eq 145
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
    MembershipRemovalEventCount = $RemoveEvents.Count
    MembershipAdditionEventCount = $AddEvents.Count
    ExecutionOrderingValid = $ExecutionOrderingValid
    AuditValidationPassed = $AuditValidationPassed
    EmployeeID = $User.EmployeeID
    AccountEnabled = $User.Enabled
    Department = $User.Department
    JobTitle = $User.Title
    ManagerEmployeeID = $ManagerEmployeeID
    DirectIAMGroupCount = $ActualGroups.Count
    FormerFinanceGroupCount = $RemainingFinanceGroups.Count
    OrganisationalUnitValid = (
        (Get-ParentDistinguishedName -DistinguishedName $User.DistinguishedName) -eq
        $Record.MoverOU
    )
    ControlledUserCount = $ControlledUsers.Count
    TotalDirectMemberships = $TotalDirectMemberships
    StateValidationPassed = $StateValidationPassed
    ChangesMade = $false
} | Format-List

if (-not ($AuditValidationPassed -and $StateValidationPassed)) {
    throw 'The IAM3001 Mover audit or effective AD state validation failed.'
}

Write-Host ''
Write-Host `
    'PASS: IAM3001 Mover audit integrity and effective Active Directory state are fully validated.' `
    -ForegroundColor Green
