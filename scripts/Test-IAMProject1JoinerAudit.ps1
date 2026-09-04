<#
.SYNOPSIS
    Performs read-only validation of an IAM Project 1 joiner audit.

.DESCRIPTION
    Confirms schema, correlation, timestamps, workflow stages, results and the
    absence of secret-bearing fields or assignment patterns. The validator can
    check either the 25-event initial transaction or the five-event idempotent
    replay. It does not modify the audit or Active Directory.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$AuditPath,
    [Parameter(Mandatory)][string]$ExpectedCorrelationID,
    [ValidateSet(5, 25)][int]$ExpectedEventCount = 25,
    [ValidateRange(0, 3)][int]$ExpectedNoChangeCount = 0
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $AuditPath -PathType Leaf)) {
    throw "Audit log not found at $AuditPath."
}

$Events = @(Import-Csv -LiteralPath $AuditPath)

if ($Events.Count -eq 0) {
    throw 'The audit contains no events.'
}

$RequiredColumns = @(
    'TimestampUTC'
    'CorrelationID'
    'RequestID'
    'EmployeeID'
    'SamAccountName'
    'Action'
    'Result'
    'Detail'
)
$ActualColumns = @($Events[0].PSObject.Properties.Name)
$MissingColumnCount = @(
    $RequiredColumns | Where-Object { $_ -notin $ActualColumns }
).Count
$SecretColumnCount = @(
    $ActualColumns |
        Where-Object { $_ -match '(?i)password|secret|token|credential|securestring' }
).Count
$CorrelationMismatchCount = @(
    $Events | Where-Object CorrelationID -ne $ExpectedCorrelationID
).Count
$FailedEventCount = @(
    $Events | Where-Object Result -eq 'Failed'
).Count
$TimestampParseFailureCount = 0

foreach ($Event in $Events) {
    try {
        $null = [datetimeoffset]::Parse($Event.TimestampUTC)
    }
    catch {
        $TimestampParseFailureCount++
    }
}

$PreflightEventCount = @(
    $Events | Where-Object Action -eq 'PreflightValidation'
).Count
$CreateEventCount = @(
    $Events | Where-Object Action -eq 'CreateDisabledAccount'
).Count
$ManagerEventCount = @(
    $Events | Where-Object Action -eq 'AssignManager'
).Count
$MembershipEventCount = @(
    $Events | Where-Object Action -eq 'AddApprovedMembership'
).Count
$EnableEventCount = @(
    $Events | Where-Object Action -eq 'EnableApprovedAccount'
).Count
$ExpirationEventCount = @(
    $Events | Where-Object Action -eq 'ApplyContractExpiration'
).Count
$NoChangeEventCount = @(
    $Events |
        Where-Object {
            $_.Action -eq 'IdempotentReplay' -and $_.Result -eq 'NoChange'
        }
).Count
$PostValidationEventCount = @(
    $Events | Where-Object Action -eq 'PostProvisioningValidation'
).Count
$RawContent = Get-Content -LiteralPath $AuditPath -Raw
$SensitiveValuePatternCount = @(
    [regex]::Matches(
        $RawContent,
        '(?i)(password|secret|token|credential|securestring)\s*[:=]'
    )
).Count

$InitialTransactionValid = $true
$ReplayValid = $true

if ($ExpectedEventCount -eq 25) {
    $InitialTransactionValid = (
        $CreateEventCount -eq 3 -and
        $ManagerEventCount -eq 3 -and
        $MembershipEventCount -eq 13 -and
        $EnableEventCount -eq 3 -and
        $ExpirationEventCount -eq 1 -and
        $NoChangeEventCount -eq 0
    )
}

if ($ExpectedEventCount -eq 5) {
    $ReplayValid = (
        $CreateEventCount -eq 0 -and
        $ManagerEventCount -eq 0 -and
        $MembershipEventCount -eq 0 -and
        $EnableEventCount -eq 0 -and
        $ExpirationEventCount -eq 0 -and
        $NoChangeEventCount -eq $ExpectedNoChangeCount
    )
}

$Passed = (
    $Events.Count -eq $ExpectedEventCount -and
    $MissingColumnCount -eq 0 -and
    $SecretColumnCount -eq 0 -and
    $CorrelationMismatchCount -eq 0 -and
    $FailedEventCount -eq 0 -and
    $TimestampParseFailureCount -eq 0 -and
    $PreflightEventCount -eq 1 -and
    $PostValidationEventCount -eq 1 -and
    $SensitiveValuePatternCount -eq 0 -and
    $InitialTransactionValid -and
    $ReplayValid
)

[pscustomobject]@{
    ComputerName = $env:COMPUTERNAME
    AuditPath = $AuditPath
    AuditSHA256 = (Get-FileHash -LiteralPath $AuditPath -Algorithm SHA256).Hash
    AuditEventCount = $Events.Count
    CorrelationID = $ExpectedCorrelationID
    CorrelationMismatchCount = $CorrelationMismatchCount
    PreflightEventCount = $PreflightEventCount
    CreateDisabledEventCount = $CreateEventCount
    ManagerAssignmentEventCount = $ManagerEventCount
    MembershipEventCount = $MembershipEventCount
    EnableAccountEventCount = $EnableEventCount
    ContractorExpirationEvents = $ExpirationEventCount
    IdempotentNoChangeCount = $NoChangeEventCount
    PostValidationEventCount = $PostValidationEventCount
    FailedEventCount = $FailedEventCount
    MissingColumnCount = $MissingColumnCount
    TimestampParseFailureCount = $TimestampParseFailureCount
    SecretColumnCount = $SecretColumnCount
    SensitiveValuePatternCount = $SensitiveValuePatternCount
    ChangesMade = $false
} | Format-List

if (-not $Passed) {
    throw 'The joiner transaction audit requires investigation.'
}

Write-Host ''
Write-Host 'PASS: The joiner audit is complete, correlated, and contains no exported secrets.' -ForegroundColor Green
