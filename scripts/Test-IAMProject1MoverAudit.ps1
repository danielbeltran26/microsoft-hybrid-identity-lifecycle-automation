<#
.SYNOPSIS
    Performs read-only validation of an IAM Project 1 mover audit.

.DESCRIPTION
    Confirms schema, correlation, timestamps, workflow stages, results,
    removal-before-grant ordering and the absence of secret-bearing fields or
    assignment patterns. The validator supports the 29-event initial
    transaction and the five-event idempotent replay. It changes neither the
    audit file nor Active Directory.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$AuditPath,
    [Parameter(Mandatory)][string]$ExpectedCorrelationID,
    [ValidateSet(5, 29)][int]$ExpectedEventCount = 29,
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
        Where-Object {
            $_ -match '(?i)password|secret|token|credential|securestring'
        }
).Count
$CorrelationMismatchCount = @(
    $Events | Where-Object CorrelationID -ne $ExpectedCorrelationID
).Count
$FailedEventCount = @(
    $Events | Where-Object Result -eq 'Failed'
).Count
$UnexpectedResultCount = @(
    $Events | Where-Object Result -notin @('Success', 'NoChange')
).Count

$ParsedTimestamps = New-Object System.Collections.ArrayList
$TimestampParseFailureCount = 0

foreach ($Event in $Events) {
    try {
        [void]$ParsedTimestamps.Add(
            [datetimeoffset]::Parse($Event.TimestampUTC)
        )
    }
    catch {
        $TimestampParseFailureCount++
    }
}

$TimestampOrderFailureCount = 0

for ($Index = 1; $Index -lt $ParsedTimestamps.Count; $Index++) {
    if ($ParsedTimestamps[$Index] -lt $ParsedTimestamps[$Index - 1]) {
        $TimestampOrderFailureCount++
    }
}

$PreflightEventCount = @(
    $Events | Where-Object Action -eq 'PreflightValidation'
).Count
$RemovalEventCount = @(
    $Events | Where-Object Action -eq 'RemoveObsoleteMembership'
).Count
$AttributeEventCount = @(
    $Events | Where-Object Action -eq 'UpdateIdentityAttributes'
).Count
$ManagerEventCount = @(
    $Events | Where-Object Action -eq 'ChangeManager'
).Count
$OUMoveEventCount = @(
    $Events | Where-Object Action -eq 'MoveOrganizationalUnit'
).Count
$ExpirationClearEventCount = @(
    $Events | Where-Object Action -eq 'ClearAccountExpiration'
).Count
$ExpirationSetEventCount = @(
    $Events | Where-Object Action -eq 'SetAccountExpiration'
).Count
$AdditionEventCount = @(
    $Events | Where-Object Action -eq 'AddApprovedMembership'
).Count
$MoverValidationEventCount = @(
    $Events | Where-Object Action -eq 'ValidateMoverState'
).Count
$NoChangeEventCount = @(
    $Events |
        Where-Object {
            $_.Action -eq 'IdempotentReplay' -and
            $_.Result -eq 'NoChange'
        }
).Count
$PostValidationEventCount = @(
    $Events | Where-Object Action -eq 'PostMoverValidation'
).Count

$AllowedActions = @(
    'PreflightValidation'
    'RemoveObsoleteMembership'
    'UpdateIdentityAttributes'
    'ChangeManager'
    'MoveOrganizationalUnit'
    'ClearAccountExpiration'
    'SetAccountExpiration'
    'AddApprovedMembership'
    'ValidateMoverState'
    'IdempotentReplay'
    'PostMoverValidation'
)
$UnexpectedActionCount = @(
    $Events | Where-Object Action -notin $AllowedActions
).Count

$RemovalBeforeGrantFailureCount = 0

foreach ($RequestID in @(
    $Events |
        Where-Object { $_.RequestID -like 'MVR-*' } |
        Select-Object -ExpandProperty RequestID -Unique
)) {
    $RequestEvents = @($Events | Where-Object RequestID -eq $RequestID)
    $RemovalIndexes = @(
        for ($Index = 0; $Index -lt $RequestEvents.Count; $Index++) {
            if ($RequestEvents[$Index].Action -eq 'RemoveObsoleteMembership') {
                $Index
            }
        }
    )
    $AdditionIndexes = @(
        for ($Index = 0; $Index -lt $RequestEvents.Count; $Index++) {
            if ($RequestEvents[$Index].Action -eq 'AddApprovedMembership') {
                $Index
            }
        }
    )

    if (
        $RemovalIndexes.Count -gt 0 -and
        $AdditionIndexes.Count -gt 0 -and
        ($RemovalIndexes | Measure-Object -Maximum).Maximum -gt
            ($AdditionIndexes | Measure-Object -Minimum).Minimum
    ) {
        $RemovalBeforeGrantFailureCount++
    }
}

$RawContent = Get-Content -LiteralPath $AuditPath -Raw
$SensitiveValuePatternCount = @(
    [regex]::Matches(
        $RawContent,
        '(?i)(password|secret|token|credential|securestring)\s*[:=]'
    )
).Count

$InitialTransactionValid = $true
$ReplayValid = $true

if ($ExpectedEventCount -eq 29) {
    $InitialTransactionValid = (
        $RemovalEventCount -eq 6 -and
        $AttributeEventCount -eq 3 -and
        $ManagerEventCount -eq 3 -and
        $OUMoveEventCount -eq 3 -and
        $ExpirationClearEventCount -eq 1 -and
        $ExpirationSetEventCount -eq 0 -and
        $AdditionEventCount -eq 8 -and
        $MoverValidationEventCount -eq 3 -and
        $NoChangeEventCount -eq 0
    )
}

if ($ExpectedEventCount -eq 5) {
    $ModificationEventCount = (
        $RemovalEventCount +
        $AttributeEventCount +
        $ManagerEventCount +
        $OUMoveEventCount +
        $ExpirationClearEventCount +
        $ExpirationSetEventCount +
        $AdditionEventCount +
        $MoverValidationEventCount
    )
    $ReplayValid = (
        $ModificationEventCount -eq 0 -and
        $NoChangeEventCount -eq $ExpectedNoChangeCount
    )
}
else {
    $ModificationEventCount = (
        $RemovalEventCount +
        $AttributeEventCount +
        $ManagerEventCount +
        $OUMoveEventCount +
        $ExpirationClearEventCount +
        $ExpirationSetEventCount +
        $AdditionEventCount
    )
}

$Passed = (
    $Events.Count -eq $ExpectedEventCount -and
    $MissingColumnCount -eq 0 -and
    $SecretColumnCount -eq 0 -and
    $CorrelationMismatchCount -eq 0 -and
    $FailedEventCount -eq 0 -and
    $UnexpectedResultCount -eq 0 -and
    $TimestampParseFailureCount -eq 0 -and
    $TimestampOrderFailureCount -eq 0 -and
    $PreflightEventCount -eq 1 -and
    $PostValidationEventCount -eq 1 -and
    $UnexpectedActionCount -eq 0 -and
    $RemovalBeforeGrantFailureCount -eq 0 -and
    $SensitiveValuePatternCount -eq 0 -and
    $InitialTransactionValid -and
    $ReplayValid
)

[pscustomobject]@{
    ComputerName = $env:COMPUTERNAME
    CorrelationID = $ExpectedCorrelationID
    AuditLogPath = $AuditPath
    AuditSHA256 = (Get-FileHash -LiteralPath $AuditPath -Algorithm SHA256).Hash
    AuditEventCount = $Events.Count
    MissingColumnCount = $MissingColumnCount
    PreflightEventCount = $PreflightEventCount
    MembershipRemovalEventCount = $RemovalEventCount
    AttributeUpdateEventCount = $AttributeEventCount
    ManagerChangeEventCount = $ManagerEventCount
    OUMoveEventCount = $OUMoveEventCount
    ExpirationClearEventCount = $ExpirationClearEventCount
    MembershipAdditionEventCount = $AdditionEventCount
    MoverStateValidationEventCount = $MoverValidationEventCount
    IdempotentNoChangeCount = $NoChangeEventCount
    PostValidationEventCount = $PostValidationEventCount
    ModificationEventCount = $ModificationEventCount
    RemovalBeforeGrantFailureCount = $RemovalBeforeGrantFailureCount
    UnexpectedActionCount = $UnexpectedActionCount
    CorrelationMismatchCount = $CorrelationMismatchCount
    FailedEventCount = $FailedEventCount
    TimestampParseFailureCount = $TimestampParseFailureCount
    TimestampOrderFailureCount = $TimestampOrderFailureCount
    SecretColumnCount = $SecretColumnCount
    SensitiveValuePatternCount = $SensitiveValuePatternCount
    ActiveDirectoryChanges = $false
} | Format-List

if (-not $Passed) {
    throw 'The mover transaction audit requires investigation.'
}

Write-Host ''
Write-Host 'PASS: The mover audit is complete, correctly ordered, correlated, and contains no exported secrets.' -ForegroundColor Green
