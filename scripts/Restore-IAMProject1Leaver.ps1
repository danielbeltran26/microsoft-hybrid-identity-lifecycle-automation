<#
.SYNOPSIS
    Performs an approved recovery of one incorrectly contained IAM Project 1 leaver.

.DESCRIPTION
    Validates the approved leaver dataset, authoritative recovery manifest,
    recovery window and current contained state.

    The original OU, description, account expiration and direct IAM group
    memberships are restored before the account is enabled. The recovery is
    fully audited. No password is changed and no account is deleted.
#>

[CmdletBinding()]
param(
    [string]$EmployeeID = 'IAM2003',

    [string]$DatasetPath =
        'C:\IAM-Lab\data\iam-project1-leaver-requests.csv',

    [string]$RecoveryPath =
        'C:\IAM-Lab\logs\M06-LEAVER-20260904-235742-recovery.csv',

    [string]$ExpectedDatasetSHA256 =
        '96A488E3A26CA23F1AD7B9652DCDBD9D774D8EF4E201E8F677A4E0CCB6D482DE',

    [string]$ExpectedRecoverySHA256 =
        '96433B774255A7982D33917E38830B06F3F2D32AA62EC553330C10E843941880',

    [string]$RecoveryApprovalID =
        'RCV-2026-0905-001',

    [string]$ApprovedBy =
        'IAM-Operations-Lead'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($env:COMPUTERNAME -ne 'DC01') {
    throw "Run this script on DC01, not $env:COMPUTERNAME."
}

Import-Module ActiveDirectory

$Domain = Get-ADDomain

if ($Domain.DNSRoot -ne 'corporate.test') {
    throw "Expected corporate.test but detected $($Domain.DNSRoot)."
}

foreach ($RequiredFile in @(
    $DatasetPath
    $RecoveryPath
)) {
    if (-not (Test-Path -LiteralPath $RequiredFile -PathType Leaf)) {
        throw "Required recovery input not found at $RequiredFile"
    }
}

$IAMRoot = 'OU=IAM-Lab,DC=corporate,DC=test'
$UsersRoot = "OU=Users,$IAMRoot"
$LeaversOU = "OU=Leavers,$UsersRoot"
$LogsFolder = 'C:\IAM-Lab\logs'

$CorrelationID = 'M06-RECOVERY-{0}' -f (
    Get-Date -Format 'yyyyMMdd-HHmmss'
)

$AuditPath = Join-Path $LogsFolder "$CorrelationID-audit.csv"

if (Test-Path -LiteralPath $AuditPath) {
    throw "A recovery audit already exists for correlation ID $CorrelationID."
}

$AuditEvents = New-Object 'System.Collections.Generic.List[object]'

function Add-AuditEvent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$RequestID,

        [Parameter(Mandatory)]
        [string]$EmployeeID,

        [Parameter(Mandatory)]
        [string]$SamAccountName,

        [Parameter(Mandatory)]
        [string]$Stage,

        [Parameter(Mandatory)]
        [string]$Action,

        [Parameter(Mandatory)]
        [string]$Target,

        [Parameter(Mandatory)]
        [ValidateSet('Passed', 'Success', 'Failed')]
        [string]$Result,

        [Parameter(Mandatory)]
        [string]$Details
    )

    $Event = [pscustomobject][ordered]@{
        TimestampUtc      = (Get-Date).ToUniversalTime().ToString('o')
        CorrelationID     = $CorrelationID
        RecoveryApprovalID = $RecoveryApprovalID
        RequestID         = $RequestID
        EmployeeID        = $EmployeeID
        SamAccountName    = $SamAccountName
        Stage             = $Stage
        Action            = $Action
        Target            = $Target
        Result            = $Result
        Details           = $Details
    }

    $AuditEvents.Add($Event)

    if (Test-Path -LiteralPath $AuditPath -PathType Leaf) {
        $Event |
            Export-Csv `
                -LiteralPath $AuditPath `
                -NoTypeInformation `
                -Encoding UTF8 `
                -Append
    }
    else {
        $Event |
            Export-Csv `
                -LiteralPath $AuditPath `
                -NoTypeInformation `
                -Encoding UTF8
    }
}

function ConvertTo-GroupList {
    [CmdletBinding()]
    param(
        [AllowEmptyString()]
        [string]$Value
    )

    return @(
        $Value -split ';' |
            ForEach-Object {
                $_.Trim()
            } |
            Where-Object {
                $_
            } |
            Sort-Object -Unique
    )
}

function Get-DirectIAMGroups {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $User
    )

    return @(
        $User.MemberOf |
            Where-Object {
                $_ -like 'CN=GG_IAM_*'
            } |
            ForEach-Object {
                (Get-ADGroup -Identity $_).SamAccountName
            } |
            Sort-Object -Unique
    )
}

function Get-ParentDistinguishedName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DistinguishedName
    )

    return $DistinguishedName.Substring(
        $DistinguishedName.IndexOf(',') + 1
    )
}

$DatasetHash = (
    Get-FileHash `
        -LiteralPath $DatasetPath `
        -Algorithm SHA256
).Hash

$RecoveryHash = (
    Get-FileHash `
        -LiteralPath $RecoveryPath `
        -Algorithm SHA256
).Hash

if ($DatasetHash -ne $ExpectedDatasetSHA256) {
    throw "Dataset hash mismatch. Detected $DatasetHash"
}

if ($RecoveryHash -ne $ExpectedRecoverySHA256) {
    throw "Recovery manifest hash mismatch. Detected $RecoveryHash"
}

$RequestMatches = @(
    Import-Csv -LiteralPath $DatasetPath |
        Where-Object {
            $_.EmployeeID -eq $EmployeeID
        }
)

$RecoveryMatches = @(
    Import-Csv -LiteralPath $RecoveryPath |
        Where-Object {
            $_.EmployeeID -eq $EmployeeID
        }
)

$UserMatches = @(
    Get-ADUser `
        -Filter "EmployeeID -eq '$EmployeeID'" `
        -Properties EmployeeID, DisplayName, SamAccountName,
                    UserPrincipalName, Enabled, employeeType,
                    Department, Title, Manager, MemberOf,
                    AccountExpirationDate, Description
)

if (
    $RequestMatches.Count -ne 1 -or
    $RecoveryMatches.Count -ne 1 -or
    $UserMatches.Count -ne 1
) {
    throw "Expected one request, recovery record and retained account for $EmployeeID."
}

$Request = $RequestMatches[0]
$Recovery = $RecoveryMatches[0]
$User = $UserMatches[0]

if (
    $Request.ApprovalStatus -ne 'Approved' -or
    $RecoveryApprovalID -ne 'RCV-2026-0905-001' -or
    $ApprovedBy -ne 'IAM-Operations-Lead'
) {
    throw 'The governed recovery approval is invalid.'
}

$CapturedUtc = [datetimeoffset]::Parse(
    $Recovery.CapturedUtc,
    [System.Globalization.CultureInfo]::InvariantCulture,
    [System.Globalization.DateTimeStyles]::RoundtripKind
)

$RecoveryDeadline = $CapturedUtc.AddDays(
    [int]$Recovery.RecoveryWindowDays
)

$RecoveryWindowValid = (
    [datetimeoffset]::UtcNow -le $RecoveryDeadline
)

if (-not $RecoveryWindowValid) {
    throw 'The approved recovery window has expired.'
}

$OriginalGroups = @(
    ConvertTo-GroupList -Value $Recovery.OriginalGroups
)

$RequestGroups = @(
    ConvertTo-GroupList -Value $Request.CurrentGroups
)

$RecoveryGroupDifference = @(
    Compare-Object `
        -ReferenceObject $RequestGroups `
        -DifferenceObject $OriginalGroups
)

if (
    $OriginalGroups.Count -ne 5 -or
    $RecoveryGroupDifference.Count -ne 0
) {
    throw 'The recovery membership state does not match the approved request.'
}

foreach ($GroupName in $OriginalGroups) {
    $Group = Get-ADGroup `
        -Identity $GroupName `
        -ErrorAction SilentlyContinue

    if ($null -eq $Group) {
        throw "Required recovery group not found: $GroupName"
    }
}

$CurrentGroups = @(
    Get-DirectIAMGroups -User $User
)

$CurrentParentOU = Get-ParentDistinguishedName `
    -DistinguishedName $User.DistinguishedName

$ExpectedLeaverDescription = (
    'IAM Project 1 | Leaver | {0} | Disabled | {1}' -f
    $Request.CurrentWorkerType,
    $Request.RequestID
)

$ContainedStateValid = (
    -not $User.Enabled -and
    $CurrentGroups.Count -eq 0 -and
    $CurrentParentOU -eq $Request.TargetOU -and
    $CurrentParentOU -eq $LeaversOU -and
    $User.Description -eq $ExpectedLeaverDescription -and
    $User.DisplayName -eq $Request.DisplayName -and
    $User.SamAccountName -eq $Request.SamAccountName -and
    $User.UserPrincipalName -eq $Request.UserPrincipalName -and
    $User.employeeType -eq $Request.CurrentWorkerType -and
    $User.Department -eq $Request.CurrentDepartment -and
    $User.Title -eq $Request.CurrentJobTitle -and
    $User.Manager -eq $Recovery.OriginalManager
)

if (-not $ContainedStateValid) {
    throw 'The selected identity is not in the exact approved contained state.'
}

Add-AuditEvent `
    -RequestID $Request.RequestID `
    -EmployeeID $Request.EmployeeID `
    -SamAccountName $Request.SamAccountName `
    -Stage 'RecoveryPreflight' `
    -Action 'ValidateRecoveryApproval' `
    -Target 'Authoritative recovery manifest and contained account' `
    -Result 'Passed' `
    -Details 'The approval, recovery window, manifest hash and contained state were validated.'

$AccountsMoved = 0
$DescriptionsRestored = 0
$ExpirationsRestored = 0
$MembershipsRestored = 0
$AccountsEnabled = 0
$RecoveredStateValidationCount = 0

try {
    Move-ADObject `
        -Identity $User.DistinguishedName `
        -TargetPath $Recovery.OriginalOU

    $AccountsMoved++

    Add-AuditEvent `
        -RequestID $Request.RequestID `
        -EmployeeID $Request.EmployeeID `
        -SamAccountName $Request.SamAccountName `
        -Stage 'DirectoryRecovery' `
        -Action 'RestoreOriginalOU' `
        -Target $Recovery.OriginalOU `
        -Result 'Success' `
        -Details 'The disabled account was returned to its authorised pre-leaver OU.'

    $User = Get-ADUser `
        -Identity $Request.SamAccountName `
        -Properties Description, AccountExpirationDate

    if ([string]::IsNullOrWhiteSpace($Recovery.OriginalDescription)) {
        Set-ADUser `
            -Identity $User.DistinguishedName `
            -Clear Description
    }
    else {
        Set-ADUser `
            -Identity $User.DistinguishedName `
            -Description $Recovery.OriginalDescription
    }

    $DescriptionsRestored++

    Add-AuditEvent `
        -RequestID $Request.RequestID `
        -EmployeeID $Request.EmployeeID `
        -SamAccountName $Request.SamAccountName `
        -Stage 'AttributeRecovery' `
        -Action 'RestoreOriginalDescription' `
        -Target $Request.SamAccountName `
        -Result 'Success' `
        -Details 'The original active lifecycle description was restored while the account remained disabled.'

    if (
        [string]::IsNullOrWhiteSpace(
            $Recovery.OriginalAccountExpirationDate
        )
    ) {
        if ($null -ne $User.AccountExpirationDate) {
            Clear-ADAccountExpiration `
                -Identity $User.DistinguishedName

            $ExpirationsRestored++

            Add-AuditEvent `
                -RequestID $Request.RequestID `
                -EmployeeID $Request.EmployeeID `
                -SamAccountName $Request.SamAccountName `
                -Stage 'AttributeRecovery' `
                -Action 'RestoreAccountExpiration' `
                -Target $Request.SamAccountName `
                -Result 'Success' `
                -Details 'The original non-expiring account state was restored.'
        }
    }
    else {
        Set-ADAccountExpiration `
            -Identity $User.DistinguishedName `
            -DateTime ([datetime]$Recovery.OriginalAccountExpirationDate)

        $ExpirationsRestored++

        Add-AuditEvent `
            -RequestID $Request.RequestID `
            -EmployeeID $Request.EmployeeID `
            -SamAccountName $Request.SamAccountName `
            -Stage 'AttributeRecovery' `
            -Action 'RestoreAccountExpiration' `
            -Target $Request.SamAccountName `
            -Result 'Success' `
            -Details 'The original approved account-expiration state was restored.'
    }

    $User = Get-ADUser `
        -Identity $Request.SamAccountName `
        -Properties MemberOf

    foreach ($GroupName in $OriginalGroups) {
        Add-ADGroupMember `
            -Identity $GroupName `
            -Members $User.DistinguishedName

        $MembershipsRestored++

        Add-AuditEvent `
            -RequestID $Request.RequestID `
            -EmployeeID $Request.EmployeeID `
            -SamAccountName $Request.SamAccountName `
            -Stage 'AccessRecovery' `
            -Action 'RestoreMembership' `
            -Target $GroupName `
            -Result 'Success' `
            -Details 'One authorised pre-leaver direct IAM membership was restored while the account remained disabled.'
    }

    $User = Get-ADUser `
        -Identity $Request.SamAccountName `
        -Properties Enabled

    Enable-ADAccount -Identity $User.DistinguishedName
    $AccountsEnabled++

    Add-AuditEvent `
        -RequestID $Request.RequestID `
        -EmployeeID $Request.EmployeeID `
        -SamAccountName $Request.SamAccountName `
        -Stage 'AccountRecovery' `
        -Action 'EnableRecoveredAccount' `
        -Target $Request.SamAccountName `
        -Result 'Success' `
        -Details 'The account was enabled only after its approved OU, attributes and memberships were restored.'

    $FinalUser = Get-ADUser `
        -Identity $Request.SamAccountName `
        -Properties EmployeeID, DisplayName, SamAccountName,
                    UserPrincipalName, Enabled, employeeType,
                    Department, Title, Manager, MemberOf,
                    AccountExpirationDate, Description

    $FinalGroups = @(
        Get-DirectIAMGroups -User $FinalUser
    )

    $FinalParentOU = Get-ParentDistinguishedName `
        -DistinguishedName $FinalUser.DistinguishedName

    $FinalGroupDifference = @(
        Compare-Object `
            -ReferenceObject $OriginalGroups `
            -DifferenceObject $FinalGroups
    )

    $FinalExpirationValid = if (
        [string]::IsNullOrWhiteSpace(
            $Recovery.OriginalAccountExpirationDate
        )
    ) {
        $null -eq $FinalUser.AccountExpirationDate
    }
    else {
        $FinalUser.AccountExpirationDate.ToString('yyyy-MM-dd') -eq (
            [datetime]$Recovery.OriginalAccountExpirationDate
        ).ToString('yyyy-MM-dd')
    }

    $FinalStateValid = (
        $FinalUser.Enabled -and
        $FinalParentOU -eq $Recovery.OriginalOU -and
        $FinalUser.Description -eq $Recovery.OriginalDescription -and
        $FinalUser.Manager -eq $Recovery.OriginalManager -and
        $FinalGroups.Count -eq 5 -and
        $FinalGroupDifference.Count -eq 0 -and
        $FinalExpirationValid -and
        $FinalUser.EmployeeID -eq $Request.EmployeeID -and
        $FinalUser.DisplayName -eq $Request.DisplayName -and
        $FinalUser.SamAccountName -eq $Request.SamAccountName -and
        $FinalUser.UserPrincipalName -eq $Request.UserPrincipalName -and
        $FinalUser.employeeType -eq $Request.CurrentWorkerType -and
        $FinalUser.Department -eq $Request.CurrentDepartment -and
        $FinalUser.Title -eq $Request.CurrentJobTitle
    )

    if (-not $FinalStateValid) {
        throw 'The recovered account failed final-state validation.'
    }

    $RecoveredStateValidationCount++

    Add-AuditEvent `
        -RequestID $Request.RequestID `
        -EmployeeID $Request.EmployeeID `
        -SamAccountName $Request.SamAccountName `
        -Stage 'RecoveryValidation' `
        -Action 'ValidateRecoveredState' `
        -Target $Request.SamAccountName `
        -Result 'Passed' `
        -Details 'The identity was restored to its exact authorised pre-leaver state.'
}
catch {
    Add-AuditEvent `
        -RequestID $Request.RequestID `
        -EmployeeID $Request.EmployeeID `
        -SamAccountName $Request.SamAccountName `
        -Stage 'RecoveryFailure' `
        -Action 'RecoveryWorkflowFailure' `
        -Target $Request.SamAccountName `
        -Result 'Failed' `
        -Details $_.Exception.Message

    throw
}

$ControlledUsers = @(
    Get-ADUser `
        -SearchBase $UsersRoot `
        -SearchScope Subtree `
        -LDAPFilter '(objectCategory=person)' `
        -Properties Enabled, MemberOf
)

$EnabledUsers = @(
    $ControlledUsers |
        Where-Object {
            $_.Enabled
        }
)

$TotalDirectMemberships = (
    $ControlledUsers |
        ForEach-Object {
            @(
                $_.MemberOf |
                    Where-Object {
                        $_ -like 'CN=GG_IAM_*'
                    }
            ).Count
        } |
        Measure-Object -Sum
).Sum

$RemainingLeavers = @(
    Get-ADUser `
        -SearchBase $LeaversOU `
        -SearchScope OneLevel `
        -Filter * `
        -Properties Enabled, MemberOf
)

$EnabledLeaverCount = @(
    $RemainingLeavers |
        Where-Object {
            $_.Enabled
        }
).Count

$FailedAuditEventCount = @(
    $AuditEvents |
        Where-Object {
            $_.Result -eq 'Failed'
        }
).Count

$PostValidationPassed = (
    $ControlledUsers.Count -eq 33 -and
    $EnabledUsers.Count -eq 31 -and
    $TotalDirectMemberships -eq 145 -and
    $RemainingLeavers.Count -eq 2 -and
    $EnabledLeaverCount -eq 0 -and
    $FailedAuditEventCount -eq 0
)

Add-AuditEvent `
    -RequestID $Request.RequestID `
    -EmployeeID $Request.EmployeeID `
    -SamAccountName $Request.SamAccountName `
    -Stage 'PostValidation' `
    -Action 'ValidateRecoveryEnvironment' `
    -Target 'Controlled IAM-Lab recovery state' `
    -Result $(if ($PostValidationPassed) {
        'Passed'
    }
    else {
        'Failed'
    }) `
    -Details $(if ($PostValidationPassed) {
        'The recovered identity and remaining contained leavers passed final environment validation.'
    }
    else {
        'One or more recovery environment checks failed.'
    })

$FailedAuditEventCount = @(
    $AuditEvents |
        Where-Object {
            $_.Result -eq 'Failed'
        }
).Count

$Passed = (
    $PostValidationPassed -and
    $AccountsMoved -eq 1 -and
    $DescriptionsRestored -eq 1 -and
    $MembershipsRestored -eq 5 -and
    $AccountsEnabled -eq 1 -and
    $RecoveredStateValidationCount -eq 1 -and
    $FailedAuditEventCount -eq 0
)

[pscustomobject]@{
    ComputerName                  = $env:COMPUTERNAME
    CorrelationID                 = $CorrelationID
    RecoveryApprovalID            = $RecoveryApprovalID
    ApprovedBy                    = $ApprovedBy
    EmployeeID                    = $EmployeeID
    DatasetHashMatches            = ($DatasetHash -eq $ExpectedDatasetSHA256)
    RecoveryManifestHashMatches   = ($RecoveryHash -eq $ExpectedRecoverySHA256)
    RecoveryWindowValid           = $RecoveryWindowValid
    AccountsMoved                 = $AccountsMoved
    DescriptionsRestored          = $DescriptionsRestored
    ExpirationsRestored           = $ExpirationsRestored
    MembershipsRestored           = $MembershipsRestored
    AccountsEnabled               = $AccountsEnabled
    RecoveredStateValidationCount = $RecoveredStateValidationCount
    ControlledUserCount           = $ControlledUsers.Count
    EnabledUserCount              = $EnabledUsers.Count
    TotalDirectMemberships        = $TotalDirectMemberships
    RemainingLeaverCount          = $RemainingLeavers.Count
    EnabledLeaverCount            = $EnabledLeaverCount
    AuditLogPath                  = $AuditPath
    AuditEventCount               = $AuditEvents.Count
    FailedAuditEventCount         = $FailedAuditEventCount
    PasswordChanged               = $false
    AccountDeleted                = $false
} | Format-List

if (-not $Passed) {
    throw 'The governed leaver recovery requires investigation.'
}

Write-Host ''
Write-Host 'PASS: The incorrectly contained IAM2003 identity was restored from approved recovery evidence and validated successfully.' -ForegroundColor Green