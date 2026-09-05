<#
.SYNOPSIS
    Performs controlled and auditable IAM Project 1 leaver containment.

.DESCRIPTION
    Validates the approved leaver dataset and current Active Directory state.
    Approved accounts are disabled before access is removed. Direct GG_IAM
    memberships are removed and users are moved into the protected Leavers OU.

    Identity attributes and manager references are retained. No account is
    deleted, no password is changed, and no credential is displayed or logged.

    A pre-change recovery manifest and correlated audit are written to
    C:\IAM-Lab\logs. Replaying completed requests produces explicit no-change
    audit events.
#>

[CmdletBinding()]
param(
    [string]$DatasetPath = 'C:\IAM-Lab\data\iam-project1-leaver-requests.csv',

    [string]$ExpectedDatasetSHA256 =
        '96A488E3A26CA23F1AD7B9652DCDBD9D774D8EF4E201E8F677A4E0CCB6D482DE'
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

if (-not (Test-Path -LiteralPath $DatasetPath -PathType Leaf)) {
    throw "Approved leaver dataset not found at $DatasetPath"
}

$IAMRoot = 'OU=IAM-Lab,DC=corporate,DC=test'
$UsersRoot = "OU=Users,$IAMRoot"
$LeaversOU = "OU=Leavers,$UsersRoot"
$LogsFolder = 'C:\IAM-Lab\logs'

if (-not (Test-Path -LiteralPath $LogsFolder -PathType Container)) {
    throw "Required audit folder not found at $LogsFolder"
}

$CorrelationID = 'M06-LEAVER-{0}' -f (
    Get-Date -Format 'yyyyMMdd-HHmmss'
)

$AuditPath = Join-Path $LogsFolder "$CorrelationID-audit.csv"
$RecoveryPath = Join-Path $LogsFolder "$CorrelationID-recovery.csv"

if (
    (Test-Path -LiteralPath $AuditPath) -or
    (Test-Path -LiteralPath $RecoveryPath)
) {
    throw "An output already exists for correlation ID $CorrelationID."
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
        [ValidateSet('Passed', 'Success', 'NoChange', 'Failed')]
        [string]$Result,

        [Parameter(Mandatory)]
        [string]$Details
    )

    $Event = [pscustomobject][ordered]@{
        TimestampUtc   = (Get-Date).ToUniversalTime().ToString('o')
        CorrelationID  = $CorrelationID
        RequestID      = $RequestID
        EmployeeID     = $EmployeeID
        SamAccountName = $SamAccountName
        Stage          = $Stage
        Action         = $Action
        Target         = $Target
        Result         = $Result
        Details        = $Details
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

function Test-StringSetEqual {
    [CmdletBinding()]
    param(
        [string[]]$Reference,
        [string[]]$Difference
    )

    return @(
        Compare-Object `
            -ReferenceObject @(
                $Reference |
                    Sort-Object -Unique
            ) `
            -DifferenceObject @(
                $Difference |
                    Sort-Object -Unique
            )
    ).Count -eq 0
}

$DatasetHash = (
    Get-FileHash `
        -LiteralPath $DatasetPath `
        -Algorithm SHA256
).Hash

if ($DatasetHash -ne $ExpectedDatasetSHA256) {
    throw "Dataset hash mismatch. Detected $DatasetHash"
}

$AllRequests = @(
    Import-Csv -LiteralPath $DatasetPath
)

$Requests = @(
    $AllRequests |
        Where-Object {
            $_.ApprovalStatus -eq 'Approved'
        }
)

if ($AllRequests.Count -ne 3 -or $Requests.Count -ne 3) {
    throw "Expected three approved requests but found $($Requests.Count)."
}

$LeaversOUObject = Get-ADOrganizationalUnit `
    -Identity $LeaversOU `
    -Properties ProtectedFromAccidentalDeletion

if (-not $LeaversOUObject.ProtectedFromAccidentalDeletion) {
    throw 'The controlled Leavers OU is not protected from accidental deletion.'
}

$Plans = @()
$PreflightFailureCount = 0
$SourceStateLeaverCount = 0
$TargetStateNoOpCount = 0
$PartialContainmentStateCount = 0

foreach ($Request in $Requests) {
    $EmployeeID = $Request.EmployeeID

    $UserMatches = @(
        Get-ADUser `
            -Filter "EmployeeID -eq '$EmployeeID'" `
            -Properties EmployeeID, DisplayName, SamAccountName,
                        UserPrincipalName, Enabled, employeeType,
                        Department, Title, Manager, MemberOf,
                        AccountExpirationDate, Description
    )

    if ($UserMatches.Count -ne 1) {
        $PreflightFailureCount++
        continue
    }

    $User = $UserMatches[0]

    $ExpectedGroups = ConvertTo-GroupList `
        -Value $Request.CurrentGroups

    $ActualGroups = Get-DirectIAMGroups -User $User

    $UnexpectedGroups = @(
        $ActualGroups |
            Where-Object {
                $_ -notin $ExpectedGroups
            }
    )

    $CurrentParentOU = Get-ParentDistinguishedName `
        -DistinguishedName $User.DistinguishedName

    $ManagerEmployeeID = if ($null -ne $User.Manager) {
        (
            Get-ADUser `
                -Identity $User.Manager `
                -Properties EmployeeID
        ).EmployeeID
    }
    else {
        $null
    }

    $ExpirationValid = if (
        [string]::IsNullOrWhiteSpace(
            $Request.CurrentAccountExpirationDate
        )
    ) {
        $null -eq $User.AccountExpirationDate
    }
    else {
        $User.AccountExpirationDate.ToString('yyyy-MM-dd') -eq (
            [datetime]$Request.CurrentAccountExpirationDate
        ).ToString('yyyy-MM-dd')
    }

    $TargetDescription = (
        'IAM Project 1 | Leaver | {0} | Disabled | {1}' -f
        $Request.CurrentWorkerType,
        $Request.RequestID
    )

    $IdentityStateValid = (
        $Request.RequestType -eq 'Leaver' -and
        $Request.DisableAccount -eq 'True' -and
        $Request.RemoveDirectIAMGroups -eq 'True' -and
        $Request.AccessRemovalMode -eq 'AllDirectIAMGroups' -and
        $Request.PreserveIdentityAttributes -eq 'True' -and
        $Request.PreserveManagerReference -eq 'True' -and
        $Request.AccountDeletionApproved -eq 'False' -and
        $User.DisplayName -eq $Request.DisplayName -and
        $User.SamAccountName -eq $Request.SamAccountName -and
        $User.UserPrincipalName -eq $Request.UserPrincipalName -and
        $User.employeeType -eq $Request.CurrentWorkerType -and
        $User.Department -eq $Request.CurrentDepartment -and
        $User.Title -eq $Request.CurrentJobTitle -and
        $ManagerEmployeeID -eq $Request.CurrentManagerEmployeeID -and
        $ExpirationValid
    )

    $SourceState = (
        $IdentityStateValid -and
        $User.Enabled -and
        $CurrentParentOU -eq $Request.CurrentOU -and
        (
            Test-StringSetEqual `
                -Reference $ExpectedGroups `
                -Difference $ActualGroups
        )
    )

    $TargetState = (
        $IdentityStateValid -and
        -not $User.Enabled -and
        $CurrentParentOU -eq $Request.TargetOU -and
        @($ActualGroups).Count -eq 0 -and
        $User.Description -eq $TargetDescription
    )

    $SafePartialState = (
        $IdentityStateValid -and
        $CurrentParentOU -in @(
            $Request.CurrentOU
            $Request.TargetOU
        ) -and
        $UnexpectedGroups.Count -eq 0
    )

    if ($SourceState) {
        $SourceStateLeaverCount++
    }
    elseif ($TargetState) {
        $TargetStateNoOpCount++
    }
    elseif ($SafePartialState) {
        $PartialContainmentStateCount++
    }
    else {
        $PreflightFailureCount++
    }

    $Plans += [pscustomobject]@{
        Request           = $Request
        User              = $User
        ExpectedGroups    = $ExpectedGroups
        ActualGroups      = $ActualGroups
        CurrentParentOU   = $CurrentParentOU
        TargetDescription = $TargetDescription
        SourceState       = $SourceState
        TargetState       = $TargetState
        SafePartialState  = $SafePartialState
    }
}

if (
    $Plans.Count -ne 3 -or
    $PreflightFailureCount -ne 0
) {
    throw "Leaver preflight failed for $PreflightFailureCount request(s)."
}

Add-AuditEvent `
    -RequestID 'ALL' `
    -EmployeeID 'ALL' `
    -SamAccountName 'ALL' `
    -Stage 'Preflight' `
    -Action 'ValidateApprovedRequests' `
    -Target 'Approved leaver dataset and Active Directory state' `
    -Result 'Passed' `
    -Details 'Three approved leaver requests passed hash, identity, access and containment validation.'

$RecoveryRecords = @(
    foreach ($Plan in $Plans) {
        if (-not $Plan.TargetState) {
            $Request = $Plan.Request
            $User = $Plan.User

            [pscustomobject][ordered]@{
                CorrelationID                 = $CorrelationID
                RequestID                     = $Request.RequestID
                EmployeeID                    = $Request.EmployeeID
                SamAccountName                = $User.SamAccountName
                OriginalDistinguishedName     = $User.DistinguishedName
                OriginalOU                    = $Plan.CurrentParentOU
                OriginalEnabled               = $User.Enabled
                OriginalDescription           = $User.Description
                OriginalManager               = $User.Manager
                OriginalGroups                = ($Plan.ActualGroups -join ';')
                OriginalAccountExpirationDate = if (
                    $null -ne $User.AccountExpirationDate
                ) {
                    $User.AccountExpirationDate.ToString('yyyy-MM-dd')
                }
                else {
                    ''
                }
                RecoveryWindowDays = $Request.RecoveryWindowDays
                CapturedUtc        = (Get-Date).ToUniversalTime().ToString('o')
            }
        }
    }
)

if ($RecoveryRecords.Count -gt 0) {
    $RecoveryRecords |
        Export-Csv `
            -LiteralPath $RecoveryPath `
            -NoTypeInformation `
            -Encoding UTF8

    foreach ($RecoveryRecord in $RecoveryRecords) {
        Add-AuditEvent `
            -RequestID $RecoveryRecord.RequestID `
            -EmployeeID $RecoveryRecord.EmployeeID `
            -SamAccountName $RecoveryRecord.SamAccountName `
            -Stage 'RecoveryPreparation' `
            -Action 'CaptureRecoveryState' `
            -Target 'Local recovery manifest' `
            -Result 'Success' `
            -Details 'Pre-change OU, enabled state, description, manager, memberships and expiration were captured.'
    }
}

$AccountsDisabled = 0
$MembershipsRemoved = 0
$OUMovesMade = 0
$DescriptionsUpdated = 0
$LeaverStateValidationCount = 0
$IdempotentNoChangeCount = 0

try {
    foreach ($Plan in $Plans) {
        $Request = $Plan.Request

        $User = Get-ADUser `
            -Identity $Request.SamAccountName `
            -Properties EmployeeID, DisplayName, SamAccountName,
                        UserPrincipalName, Enabled, employeeType,
                        Department, Title, Manager, MemberOf,
                        AccountExpirationDate, Description

        if ($Plan.TargetState) {
            $IdempotentNoChangeCount++

            Add-AuditEvent `
                -RequestID $Request.RequestID `
                -EmployeeID $Request.EmployeeID `
                -SamAccountName $Request.SamAccountName `
                -Stage 'Idempotency' `
                -Action 'LeaverStateNoChange' `
                -Target $Request.TargetOU `
                -Result 'NoChange' `
                -Details 'The account was already disabled, access-free and located in the controlled Leavers OU.'

            continue
        }

        if ($User.Enabled) {
            Disable-ADAccount -Identity $User.DistinguishedName
            $AccountsDisabled++

            Add-AuditEvent `
                -RequestID $Request.RequestID `
                -EmployeeID $Request.EmployeeID `
                -SamAccountName $Request.SamAccountName `
                -Stage 'Containment' `
                -Action 'DisableAccount' `
                -Target $Request.SamAccountName `
                -Result 'Success' `
                -Details 'The approved leaver account was disabled before access removal.'
        }

        $User = Get-ADUser `
            -Identity $Request.SamAccountName `
            -Properties MemberOf

        $CurrentIAMGroups = Get-DirectIAMGroups -User $User

        foreach ($GroupName in $CurrentIAMGroups) {
            Remove-ADGroupMember `
                -Identity $GroupName `
                -Members $User.DistinguishedName `
                -Confirm:$false

            $MembershipsRemoved++

            Add-AuditEvent `
                -RequestID $Request.RequestID `
                -EmployeeID $Request.EmployeeID `
                -SamAccountName $Request.SamAccountName `
                -Stage 'AccessRemoval' `
                -Action 'RemoveMembership' `
                -Target $GroupName `
                -Result 'Success' `
                -Details 'A direct controlled IAM membership was removed from the disabled leaver account.'
        }

        $User = Get-ADUser `
            -Identity $Request.SamAccountName `
            -Properties Description

        $CurrentParentOU = Get-ParentDistinguishedName `
            -DistinguishedName $User.DistinguishedName

        if ($CurrentParentOU -ne $Request.TargetOU) {
            Move-ADObject `
                -Identity $User.DistinguishedName `
                -TargetPath $Request.TargetOU

            $OUMovesMade++

            Add-AuditEvent `
                -RequestID $Request.RequestID `
                -EmployeeID $Request.EmployeeID `
                -SamAccountName $Request.SamAccountName `
                -Stage 'DirectoryPlacement' `
                -Action 'MoveToLeaversOU' `
                -Target $Request.TargetOU `
                -Result 'Success' `
                -Details 'The disabled and access-free account was moved into the protected Leavers OU.'
        }

        $User = Get-ADUser `
            -Identity $Request.SamAccountName `
            -Properties Description

        if ($User.Description -ne $Plan.TargetDescription) {
            Set-ADUser `
                -Identity $User.DistinguishedName `
                -Description $Plan.TargetDescription

            $DescriptionsUpdated++

            Add-AuditEvent `
                -RequestID $Request.RequestID `
                -EmployeeID $Request.EmployeeID `
                -SamAccountName $Request.SamAccountName `
                -Stage 'LifecycleRecord' `
                -Action 'UpdateLifecycleDescription' `
                -Target $Request.SamAccountName `
                -Result 'Success' `
                -Details 'The description was updated to the approved disabled leaver state.'
        }

        $FinalUser = Get-ADUser `
            -Identity $Request.SamAccountName `
            -Properties EmployeeID, DisplayName, UserPrincipalName,
                        Enabled, employeeType, Department, Title,
                        Manager, MemberOf, Description

        $FinalGroups = Get-DirectIAMGroups -User $FinalUser

        $FinalParentOU = Get-ParentDistinguishedName `
            -DistinguishedName $FinalUser.DistinguishedName

        $FinalManagerEmployeeID = if ($null -ne $FinalUser.Manager) {
            (
                Get-ADUser `
                    -Identity $FinalUser.Manager `
                    -Properties EmployeeID
            ).EmployeeID
        }
        else {
            $null
        }

        $FinalStateValid = (
            -not $FinalUser.Enabled -and
            $FinalParentOU -eq $Request.TargetOU -and
            @($FinalGroups).Count -eq 0 -and
            $FinalUser.Description -eq $Plan.TargetDescription -and
            $FinalUser.EmployeeID -eq $Request.EmployeeID -and
            $FinalUser.DisplayName -eq $Request.DisplayName -and
            $FinalUser.UserPrincipalName -eq $Request.UserPrincipalName -and
            $FinalUser.employeeType -eq $Request.CurrentWorkerType -and
            $FinalUser.Department -eq $Request.CurrentDepartment -and
            $FinalUser.Title -eq $Request.CurrentJobTitle -and
            $FinalManagerEmployeeID -eq $Request.CurrentManagerEmployeeID
        )

        if (-not $FinalStateValid) {
            throw "Final leaver validation failed for $($Request.EmployeeID)."
        }

        $LeaverStateValidationCount++

        Add-AuditEvent `
            -RequestID $Request.RequestID `
            -EmployeeID $Request.EmployeeID `
            -SamAccountName $Request.SamAccountName `
            -Stage 'IdentityValidation' `
            -Action 'ValidateLeaverState' `
            -Target $Request.SamAccountName `
            -Result 'Passed' `
            -Details 'The account is disabled, access-free, retained and located in the protected Leavers OU.'
    }
}
catch {
    Add-AuditEvent `
        -RequestID 'WORKFLOW' `
        -EmployeeID 'WORKFLOW' `
        -SamAccountName 'WORKFLOW' `
        -Stage 'Failure' `
        -Action 'WorkflowFailure' `
        -Target 'Milestone 6 leaver containment' `
        -Result 'Failed' `
        -Details $_.Exception.Message

    throw
}

$ControlledUsers = @(
    Get-ADUser `
        -SearchBase $UsersRoot `
        -SearchScope Subtree `
        -LDAPFilter '(objectCategory=person)' `
        -Properties Enabled, employeeType, Manager, MemberOf
)

$EnabledUsers = @(
    $ControlledUsers |
        Where-Object {
            $_.Enabled
        }
)

$Employees = @(
    $ControlledUsers |
        Where-Object {
            $_.employeeType -eq 'Employee'
        }
)

$Contractors = @(
    $ControlledUsers |
        Where-Object {
            $_.employeeType -eq 'Contractor'
        }
)

$ManagerAssignedUsers = @(
    $ControlledUsers |
        Where-Object {
            $null -ne $_.Manager
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

$LeaverUsers = @(
    Get-ADUser `
        -SearchBase $LeaversOU `
        -SearchScope OneLevel `
        -Filter * `
        -Properties Enabled, MemberOf
)

$EnabledLeaverCount = @(
    $LeaverUsers |
        Where-Object {
            $_.Enabled
        }
).Count

$LeaverMembershipCount = (
    $LeaverUsers |
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

$PermanentEmployeeCount = @(
    Get-ADGroupMember `
        -Identity 'GG_All_Employees' `
        -Recursive
).Count

$IDTRUsers = @(
    Get-ADUser `
        -Filter "SamAccountName -like 'idtr-user*'" `
        -Properties Enabled
)

$IDTRDisabledCount = @(
    $IDTRUsers |
        Where-Object {
            -not $_.Enabled
        }
).Count

$HighValueGroupMembers = @(
    Get-ADGroupMember -Identity 'IDTR-HighValue-Lab'
).Count

$FailedAuditEventCount = @(
    $AuditEvents |
        Where-Object {
            $_.Result -eq 'Failed'
        }
).Count

$PostValidationPassed = (
    $ControlledUsers.Count -eq 33 -and
    $EnabledUsers.Count -eq 30 -and
    $Employees.Count -eq 28 -and
    $Contractors.Count -eq 5 -and
    $ManagerAssignedUsers.Count -eq 27 -and
    $TotalDirectMemberships -eq 140 -and
    $LeaverUsers.Count -eq 3 -and
    $EnabledLeaverCount -eq 0 -and
    $LeaverMembershipCount -eq 0 -and
    $PermanentEmployeeCount -eq 50 -and
    $IDTRUsers.Count -eq 5 -and
    $IDTRDisabledCount -eq 5 -and
    $HighValueGroupMembers -eq 0 -and
    $FailedAuditEventCount -eq 0
)

Add-AuditEvent `
    -RequestID 'ALL' `
    -EmployeeID 'ALL' `
    -SamAccountName 'ALL' `
    -Stage 'PostValidation' `
    -Action 'ValidateControlledEnvironment' `
    -Target 'IAM-Lab and preserved security laboratory state' `
    -Result $(if ($PostValidationPassed) {
        'Passed'
    }
    else {
        'Failed'
    }) `
    -Details $(if ($PostValidationPassed) {
        'All controlled identity, leaver containment, membership and preserved-environment checks passed.'
    }
    else {
        'One or more controlled-environment post-validation checks failed.'
    })

$FailedAuditEventCount = @(
    $AuditEvents |
        Where-Object {
            $_.Result -eq 'Failed'
        }
).Count

$RecoveryManifestExists = Test-Path `
    -LiteralPath $RecoveryPath `
    -PathType Leaf

$RecoveryRecordCount = if ($RecoveryManifestExists) {
    @(
        Import-Csv -LiteralPath $RecoveryPath
    ).Count
}
else {
    0
}

$Passed = (
    $PostValidationPassed -and
    $FailedAuditEventCount -eq 0 -and
    (
        $LeaverStateValidationCount +
        $IdempotentNoChangeCount
    ) -eq 3
)

[pscustomobject]@{
    ComputerName                 = $env:COMPUTERNAME
    CorrelationID                = $CorrelationID
    DatasetHashMatches           = ($DatasetHash -eq $ExpectedDatasetSHA256)
    ApprovedLeaverCount          = $Requests.Count
    SourceStateLeaverCount       = $SourceStateLeaverCount
    TargetStateNoOpCount         = $TargetStateNoOpCount
    PartialContainmentStateCount = $PartialContainmentStateCount
    RecoveryManifestPath         = if ($RecoveryManifestExists) {
        $RecoveryPath
    }
    else {
        'Not required for no-change replay'
    }
    RecoveryRecordCount          = $RecoveryRecordCount
    AccountsDisabled             = $AccountsDisabled
    MembershipsRemoved           = $MembershipsRemoved
    OUMovesMade                  = $OUMovesMade
    DescriptionsUpdated          = $DescriptionsUpdated
    LeaverStateValidationCount   = $LeaverStateValidationCount
    IdempotentNoChangeCount      = $IdempotentNoChangeCount
    ControlledUserCount          = $ControlledUsers.Count
    EnabledUserCount             = $EnabledUsers.Count
    EmployeeCount                = $Employees.Count
    ContractorCount              = $Contractors.Count
    ManagerAssignedCount         = $ManagerAssignedUsers.Count
    TotalDirectMemberships       = $TotalDirectMemberships
    LeaverUserCount              = $LeaverUsers.Count
    EnabledLeaverCount           = $EnabledLeaverCount
    LeaverDirectMembershipCount  = $LeaverMembershipCount
    PermanentEmployeeCount       = $PermanentEmployeeCount
    IDTRUserCount                = $IDTRUsers.Count
    IDTRDisabledCount            = $IDTRDisabledCount
    HighValueGroupMembers        = $HighValueGroupMembers
    AuditLogPath                 = $AuditPath
    AuditEventCount              = $AuditEvents.Count
    FailedAuditEventCount        = $FailedAuditEventCount
    PasswordsChangedOrExported   = $false
    AccountsDeleted              = 0
} | Format-List

if (-not $Passed) {
    throw 'Milestone 6 leaver containment requires investigation.'
}

Write-Host ''
Write-Host 'PASS: All three approved leavers were disabled, access-free, retained, audited, and validated successfully.' -ForegroundColor Green