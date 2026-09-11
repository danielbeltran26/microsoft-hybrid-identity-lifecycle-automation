<#
.SYNOPSIS
    Applies approved IAM Project 1 mover access transitions.

.DESCRIPTION
    Run in Windows PowerShell as Administrator on DC01. The script validates
    the approved request-file digest, request state, existing identities,
    managers, OUs and groups before its first directory write.

    Each identity must match either its complete approved source state or its
    complete approved target state. Source-only memberships are removed before
    destination memberships are granted. Department, title, employee type,
    manager, OU and account expiration are reconciled to the target record.

    Replaying a completed request produces a no-change decision. The script
    never creates or deletes accounts and never changes, displays or exports a
    password. A partial or ambiguous state stops execution for investigation.
#>

[CmdletBinding()]
param(
    [string]$CsvPath = 'C:\IAM-Lab\data\iam-project1-mover-requests.csv',
    [string]$ExpectedSHA256 = 'AA40213E0C71234FA3F32CF1AF9FA0960EDDA3B231EBEE58D82C5C0A1E23A7C8',
    [string]$ExpectedComputerName = 'DC01',
    [string]$ExpectedDomain = 'corporate.test',
    [string]$UsersRoot = 'OU=Users,OU=IAM-Lab,DC=corporate,DC=test',
    [string]$LeaversOU = 'OU=Leavers,OU=Users,OU=IAM-Lab,DC=corporate,DC=test',
    [string]$LogFolder = 'C:\IAM-Lab\logs'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module ActiveDirectory

$CorrelationID = 'M05-MOVER-{0}' -f (Get-Date -Format 'yyyyMMdd-HHmmss')
$AuditPath = Join-Path $LogFolder "$CorrelationID-audit.csv"
$AuditEvents = New-Object System.Collections.ArrayList

function Add-AuditEvent {
    [CmdletBinding()]
    param(
        [string]$RequestID,
        [string]$EmployeeID,
        [string]$SamAccountName,
        [string]$Action,
        [string]$Result,
        [string]$Detail
    )

    [void]$AuditEvents.Add([pscustomobject]@{
        TimestampUTC = [datetime]::UtcNow.ToString('o')
        CorrelationID = $CorrelationID
        RequestID = $RequestID
        EmployeeID = $EmployeeID
        SamAccountName = $SamAccountName
        Action = $Action
        Result = $Result
        Detail = $Detail
    })
}

function ConvertTo-GroupList {
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Value)

    return @(
        $Value -split ';' |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ } |
            Sort-Object -Unique
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
            -ReferenceObject @($Reference | Sort-Object -Unique) `
            -DifferenceObject @($Difference | Sort-Object -Unique)
    ).Count -eq 0
}

function Get-ParentDistinguishedName {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$DistinguishedName)

    return $DistinguishedName.Substring(
        $DistinguishedName.IndexOf(',') + 1
    )
}

function Get-DirectIAMGroups {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$User)

    return @(
        $User.MemberOf |
            Where-Object { $_ -like 'CN=GG_IAM_*' } |
            ForEach-Object {
                (Get-ADGroup -Identity $_).SamAccountName
            } |
            Sort-Object -Unique
    )
}

function Get-ManagerEmployeeID {
    [CmdletBinding()]
    param($User)

    if ($null -eq $User.Manager) {
        return $null
    }

    return (
        Get-ADUser -Identity $User.Manager -Properties EmployeeID
    ).EmployeeID
}

function Test-ExpirationState {
    [CmdletBinding()]
    param(
        $ActualDate,
        [AllowEmptyString()][string]$ExpectedDate
    )

    if ([string]::IsNullOrWhiteSpace($ExpectedDate)) {
        return $null -eq $ActualDate
    }

    return (
        $null -ne $ActualDate -and
        $ActualDate.Date -eq ([datetime]$ExpectedDate).Date
    )
}

function Get-MoverState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$User,
        [Parameter(Mandatory)]$Record,
        [Parameter(Mandatory)][ValidateSet('Source', 'Target')][string]$State
    )

    if ($State -eq 'Source') {
        $Department = $Record.CurrentDepartment
        $JobTitle = $Record.CurrentJobTitle
        $WorkerType = $Record.CurrentWorkerType
        $ManagerEmployeeID = $Record.CurrentManagerEmployeeID
        $OU = $Record.CurrentOU
        $Groups = @(ConvertTo-GroupList -Value $Record.CurrentGroups)
        $Expiration = $Record.CurrentAccountExpirationDate
    }
    else {
        $Department = $Record.TargetDepartment
        $JobTitle = $Record.TargetJobTitle
        $WorkerType = $Record.TargetWorkerType
        $ManagerEmployeeID = $Record.TargetManagerEmployeeID
        $OU = $Record.TargetOU
        $Groups = @(ConvertTo-GroupList -Value $Record.TargetGroups)
        $Expiration = $Record.TargetAccountExpirationDate
    }

    $ActualGroups = @(Get-DirectIAMGroups -User $User)
    $ActualManagerID = Get-ManagerEmployeeID -User $User
    $ParentOU = Get-ParentDistinguishedName -DistinguishedName $User.DistinguishedName
    $DescriptionValid = $true

    if ($State -eq 'Target') {
        $ExpectedDescription = "IAM Project 1 | Mover | $WorkerType | Active | $($Record.RequestID)"
        $DescriptionValid = $User.Description -eq $ExpectedDescription
    }

    $IsMatch = (
        $User.Enabled -and
        $User.Department -eq $Department -and
        $User.Title -eq $JobTitle -and
        $User.employeeType -eq $WorkerType -and
        $ActualManagerID -eq $ManagerEmployeeID -and
        $ParentOU -eq $OU -and
        (Test-StringSetEqual -Reference $Groups -Difference $ActualGroups) -and
        (Test-ExpirationState -ActualDate $User.AccountExpirationDate -ExpectedDate $Expiration) -and
        $DescriptionValid
    )

    return [pscustomobject]@{
        State = $State
        IsMatch = $IsMatch
        Department = $Department
        JobTitle = $JobTitle
        WorkerType = $WorkerType
        ManagerEmployeeID = $ManagerEmployeeID
        OU = $OU
        Groups = $Groups
        ActualGroups = $ActualGroups
        Expiration = $Expiration
    }
}

function Get-ControlledTotals {
    [CmdletBinding()]
    param()

    $Users = @(
        Get-ADUser `
            -SearchBase $UsersRoot `
            -LDAPFilter '(objectCategory=person)' `
            -Properties Enabled, employeeType, Manager, MemberOf
    )
    $TotalMemberships = (
        $Users |
            ForEach-Object {
                @($_.MemberOf | Where-Object { $_ -like 'CN=GG_IAM_*' }).Count
            } |
            Measure-Object -Sum
    ).Sum

    return [pscustomobject]@{
        Users = $Users
        ControlledUserCount = $Users.Count
        EnabledUserCount = @($Users | Where-Object Enabled).Count
        EmployeeCount = @($Users | Where-Object employeeType -eq 'Employee').Count
        ContractorCount = @($Users | Where-Object employeeType -eq 'Contractor').Count
        ManagerAssignedCount = @($Users | Where-Object { $null -ne $_.Manager }).Count
        TotalDirectMemberships = $TotalMemberships
    }
}

if (-not (Test-Path -LiteralPath $LogFolder -PathType Container)) {
    $null = New-Item -Path $LogFolder -ItemType Directory
}

try {
    if ($env:COMPUTERNAME -ne $ExpectedComputerName) {
        throw "Run this script on $ExpectedComputerName, not $env:COMPUTERNAME."
    }

    $Domain = Get-ADDomain

    if ($Domain.DNSRoot -ne $ExpectedDomain) {
        throw "Expected domain $ExpectedDomain but detected $($Domain.DNSRoot)."
    }

    if (-not (Test-Path -LiteralPath $CsvPath -PathType Leaf)) {
        throw "Approved mover dataset not found at $CsvPath."
    }

    $ActualHash = (Get-FileHash -LiteralPath $CsvPath -Algorithm SHA256).Hash

    if ($ActualHash -ne $ExpectedSHA256) {
        throw "Dataset integrity check failed. Expected $ExpectedSHA256 but calculated $ActualHash."
    }

    $Records = @(Import-Csv -LiteralPath $CsvPath)

    if ($Records.Count -ne 3) {
        throw "Expected exactly three mover requests but found $($Records.Count)."
    }

    $RequiredColumns = @(
        'RequestID', 'RequestType', 'EmployeeID', 'DisplayName',
        'SamAccountName', 'UserPrincipalName', 'EffectiveDate',
        'CurrentDepartment', 'CurrentJobTitle', 'CurrentWorkerType',
        'CurrentManagerEmployeeID', 'CurrentOU', 'CurrentGroups',
        'CurrentAccountExpirationDate', 'TargetDepartment',
        'TargetJobTitle', 'TargetWorkerType', 'TargetManagerEmployeeID',
        'TargetOU', 'TargetGroups', 'TargetAccountExpirationDate',
        'AccessTransitionMode', 'RemoveObsoleteAccessBeforeGrant',
        'ClearAccountExpiration', 'LifecycleStatus', 'ApprovalStatus',
        'RequestedBy', 'ApprovedBy', 'ApprovalDate', 'BusinessJustification'
    )
    $ActualColumns = @($Records[0].PSObject.Properties.Name)
    $MissingColumns = @($RequiredColumns | Where-Object { $_ -notin $ActualColumns })

    if ($MissingColumns.Count -ne 0) {
        throw "Missing required columns: $($MissingColumns -join ', ')."
    }

    $SecretColumns = @(
        $ActualColumns |
            Where-Object { $_ -match '(?i)password|secret|credential|token|securestring' }
    )

    if ($SecretColumns.Count -ne 0) {
        throw "Prohibited secret-bearing columns detected: $($SecretColumns -join ', ')."
    }

    foreach ($PropertyName in @('RequestID', 'EmployeeID', 'SamAccountName', 'UserPrincipalName')) {
        $Duplicates = @(
            $Records |
                Group-Object -Property $PropertyName |
                Where-Object Count -gt 1
        )

        if ($Duplicates.Count -ne 0) {
            throw "The mover dataset contains duplicate $PropertyName values."
        }
    }

    $InvalidRequests = @(
        $Records |
            Where-Object {
                $_.RequestType -ne 'Mover' -or
                $_.ApprovalStatus -ne 'Approved' -or
                $_.LifecycleStatus -ne 'Active' -or
                $_.AccessTransitionMode -ne 'ExactReplacement' -or
                $_.RemoveObsoleteAccessBeforeGrant -ne 'True' -or
                ([datetime]$_.EffectiveDate).Date -gt (Get-Date).Date
            }
    )

    if ($InvalidRequests.Count -ne 0) {
        throw "$($InvalidRequests.Count) mover requests are not approved, effective and safely configured."
    }

    $WorkItems = New-Object System.Collections.ArrayList
    $SourceStateMoverCount = 0
    $TargetStateNoOpCount = 0
    $PlannedMembershipRemovals = 0
    $PlannedMembershipAdditions = 0

    foreach ($Record in $Records) {
        $EscapedEmployeeID = $Record.EmployeeID.Replace("'", "''")
        $EscapedSam = $Record.SamAccountName.Replace("'", "''")
        $EscapedUPN = $Record.UserPrincipalName.Replace("'", "''")
        $Users = @(
            Get-ADUser `
                -Filter "EmployeeID -eq '$EscapedEmployeeID' -or SamAccountName -eq '$EscapedSam' -or UserPrincipalName -eq '$EscapedUPN'" `
                -Properties EmployeeID, UserPrincipalName, Enabled, employeeType,
                    Department, Title, Manager, MemberOf, AccountExpirationDate,
                    Description
        )

        if ($Users.Count -ne 1) {
            throw "Expected one identity for $($Record.RequestID) but found $($Users.Count)."
        }

        $User = $Users[0]
        $IdentityKeysMatch = (
            $User.EmployeeID -eq $Record.EmployeeID -and
            $User.SamAccountName -eq $Record.SamAccountName -and
            $User.UserPrincipalName -eq $Record.UserPrincipalName
        )

        if (-not $IdentityKeysMatch) {
            throw "An unsafe identity collision exists for $($Record.RequestID)."
        }

        $ManagerID = $Record.TargetManagerEmployeeID.Replace("'", "''")
        $Managers = @(
            Get-ADUser `
                -Filter "EmployeeID -eq '$ManagerID'" `
                -Properties EmployeeID, Enabled
        )

        if ($Managers.Count -ne 1 -or -not $Managers[0].Enabled) {
            throw "Target manager $($Record.TargetManagerEmployeeID) is missing, duplicated or disabled."
        }

        $TargetOU = Get-ADOrganizationalUnit `
            -Identity $Record.TargetOU `
            -Properties ProtectedFromAccidentalDeletion

        if (-not $TargetOU.ProtectedFromAccidentalDeletion) {
            throw "Target OU $($Record.TargetOU) is not protected from accidental deletion."
        }

        $SourceGroups = @(ConvertTo-GroupList -Value $Record.CurrentGroups)
        $TargetGroups = @(ConvertTo-GroupList -Value $Record.TargetGroups)

        foreach ($GroupName in @($SourceGroups + $TargetGroups | Sort-Object -Unique)) {
            $Group = Get-ADGroup `
                -Identity $GroupName `
                -Properties GroupCategory, GroupScope

            if ($Group.GroupCategory -ne 'Security' -or $Group.GroupScope -ne 'Global') {
                throw "$GroupName is not a Global Security group."
            }
        }

        $SourceState = Get-MoverState -User $User -Record $Record -State Source
        $TargetState = Get-MoverState -User $User -Record $Record -State Target

        if ($TargetState.IsMatch) {
            $Mode = 'Target'
            $TargetStateNoOpCount++
        }
        elseif ($SourceState.IsMatch) {
            $Mode = 'Source'
            $SourceStateMoverCount++
            $PlannedMembershipRemovals += @(
                $SourceGroups | Where-Object { $_ -notin $TargetGroups }
            ).Count
            $PlannedMembershipAdditions += @(
                $TargetGroups | Where-Object { $_ -notin $SourceGroups }
            ).Count
        }
        else {
            throw "$($Record.EmployeeID) matches neither the approved source nor target state."
        }

        [void]$WorkItems.Add([pscustomobject]@{
            Record = $Record
            User = $User
            Manager = $Managers[0]
            SourceGroups = $SourceGroups
            TargetGroups = $TargetGroups
            Mode = $Mode
        })
    }

    Add-AuditEvent `
        -RequestID 'DATASET' `
        -EmployeeID '' `
        -SamAccountName '' `
        -Action 'PreflightValidation' `
        -Result 'Success' `
        -Detail 'Dataset hash, approvals, identities, source states and target resources validated.'

    $MembershipsRemoved = 0
    $MembershipsAdded = 0
    $AttributesUpdated = 0
    $ManagerAssignmentsMade = 0
    $OUMovesMade = 0
    $ExpirationsCleared = 0
    $MoverStateValidationCount = 0
    $IdempotentNoChangeCount = 0

    foreach ($Item in $WorkItems) {
        $Record = $Item.Record
        $User = $Item.User

        if ($Item.Mode -eq 'Target') {
            $IdempotentNoChangeCount++
            Add-AuditEvent `
                -RequestID $Record.RequestID `
                -EmployeeID $Record.EmployeeID `
                -SamAccountName $Record.SamAccountName `
                -Action 'IdempotentReplay' `
                -Result 'NoChange' `
                -Detail 'Identity already matched the complete approved mover target state.'
            continue
        }

        $GroupsToRemove = @(
            $Item.SourceGroups |
                Where-Object { $_ -notin $Item.TargetGroups } |
                Sort-Object
        )

        foreach ($GroupName in $GroupsToRemove) {
            Remove-ADGroupMember `
                -Identity $GroupName `
                -Members $User `
                -Confirm:$false
            $MembershipsRemoved++
            Add-AuditEvent `
                -RequestID $Record.RequestID `
                -EmployeeID $Record.EmployeeID `
                -SamAccountName $Record.SamAccountName `
                -Action 'RemoveObsoleteMembership' `
                -Result 'Success' `
                -Detail "Removed obsolete access: $GroupName."
        }

        $Description = "IAM Project 1 | Mover | $($Record.TargetWorkerType) | Active | $($Record.RequestID)"
        Set-ADUser `
            -Identity $User `
            -Department $Record.TargetDepartment `
            -Title $Record.TargetJobTitle `
            -Description $Description `
            -Replace @{ employeeType = $Record.TargetWorkerType }
        $AttributesUpdated++
        Add-AuditEvent `
            -RequestID $Record.RequestID `
            -EmployeeID $Record.EmployeeID `
            -SamAccountName $Record.SamAccountName `
            -Action 'UpdateIdentityAttributes' `
            -Result 'Success' `
            -Detail 'Department, title, worker type and lifecycle description updated.'

        Set-ADUser `
            -Identity $User `
            -Manager $Item.Manager.DistinguishedName
        $ManagerAssignmentsMade++
        Add-AuditEvent `
            -RequestID $Record.RequestID `
            -EmployeeID $Record.EmployeeID `
            -SamAccountName $Record.SamAccountName `
            -Action 'ChangeManager' `
            -Result 'Success' `
            -Detail "Manager changed to $($Record.TargetManagerEmployeeID)."

        Move-ADObject `
            -Identity $User.DistinguishedName `
            -TargetPath $Record.TargetOU
        $OUMovesMade++
        Add-AuditEvent `
            -RequestID $Record.RequestID `
            -EmployeeID $Record.EmployeeID `
            -SamAccountName $Record.SamAccountName `
            -Action 'MoveOrganizationalUnit' `
            -Result 'Success' `
            -Detail 'Moved identity to approved target OU.'

        $User = Get-ADUser `
            -Identity $Record.SamAccountName `
            -Properties EmployeeID, UserPrincipalName, Enabled, employeeType,
                Department, Title, Manager, MemberOf, AccountExpirationDate,
                Description

        if ($Record.ClearAccountExpiration -eq 'True') {
            if ($null -ne $User.AccountExpirationDate) {
                Clear-ADAccountExpiration -Identity $User
                $ExpirationsCleared++
                Add-AuditEvent `
                    -RequestID $Record.RequestID `
                    -EmployeeID $Record.EmployeeID `
                    -SamAccountName $Record.SamAccountName `
                    -Action 'ClearAccountExpiration' `
                    -Result 'Success' `
                    -Detail 'Former contractor expiration was cleared after approved employee conversion.'
            }
        }
        elseif (-not [string]::IsNullOrWhiteSpace($Record.TargetAccountExpirationDate)) {
            $TargetExpiration = ([datetime]$Record.TargetAccountExpirationDate).Date

            if (
                $null -eq $User.AccountExpirationDate -or
                $User.AccountExpirationDate.Date -ne $TargetExpiration
            ) {
                Set-ADAccountExpiration `
                    -Identity $User `
                    -DateTime $TargetExpiration
                Add-AuditEvent `
                    -RequestID $Record.RequestID `
                    -EmployeeID $Record.EmployeeID `
                    -SamAccountName $Record.SamAccountName `
                    -Action 'SetAccountExpiration' `
                    -Result 'Success' `
                    -Detail 'Approved target account expiration was applied.'
            }
        }

        $User = Get-ADUser `
            -Identity $Record.SamAccountName `
            -Properties MemberOf
        $CurrentGroups = @(Get-DirectIAMGroups -User $User)
        $GroupsToAdd = @(
            $Item.TargetGroups |
                Where-Object { $_ -notin $CurrentGroups } |
                Sort-Object
        )

        foreach ($GroupName in $GroupsToAdd) {
            Add-ADGroupMember -Identity $GroupName -Members $User
            $MembershipsAdded++
            Add-AuditEvent `
                -RequestID $Record.RequestID `
                -EmployeeID $Record.EmployeeID `
                -SamAccountName $Record.SamAccountName `
                -Action 'AddApprovedMembership' `
                -Result 'Success' `
                -Detail "Added approved destination access: $GroupName."
        }

        $User = Get-ADUser `
            -Identity $Record.SamAccountName `
            -Properties EmployeeID, UserPrincipalName, Enabled, employeeType,
                Department, Title, Manager, MemberOf, AccountExpirationDate,
                Description
        $FinalState = Get-MoverState -User $User -Record $Record -State Target

        if (-not $FinalState.IsMatch) {
            throw "$($Record.EmployeeID) failed final mover target-state validation."
        }

        $MoverStateValidationCount++
        Add-AuditEvent `
            -RequestID $Record.RequestID `
            -EmployeeID $Record.EmployeeID `
            -SamAccountName $Record.SamAccountName `
            -Action 'ValidateMoverState' `
            -Result 'Success' `
            -Detail 'Identity, manager, OU, expiration and exact IAM memberships match the approved target state.'
    }

    $FinalMoverValidationFailures = 0

    foreach ($Record in $Records) {
        $User = Get-ADUser `
            -Identity $Record.SamAccountName `
            -Properties EmployeeID, UserPrincipalName, Enabled, employeeType,
                Department, Title, Manager, MemberOf, AccountExpirationDate,
                Description
        $FinalState = Get-MoverState -User $User -Record $Record -State Target

        if (-not $FinalState.IsMatch) {
            $FinalMoverValidationFailures++
        }
    }

    $Totals = Get-ControlledTotals
    $LeaverUserCount = @(
        Get-ADUser -SearchBase $LeaversOU -SearchScope OneLevel -Filter *
    ).Count
    $PermanentEmployeeCount = @(
        Get-ADGroupMember -Identity 'GG_All_Employees' -Recursive
    ).Count
    $IDTRUsers = @(
        Get-ADUser `
            -Filter "SamAccountName -like 'idtr-user*'" `
            -Properties Enabled
    )
    $IDTRDisabledCount = @($IDTRUsers | Where-Object { -not $_.Enabled }).Count
    $HighValueGroupMembers = @(
        Get-ADGroupMember -Identity 'IDTR-HighValue-Lab'
    ).Count
    $Mason = Get-ADUser -Identity 'mason.cole' -Properties AccountExpirationDate
    $MasonExpirationCleared = $null -eq $Mason.AccountExpirationDate

    $Passed = (
        $FinalMoverValidationFailures -eq 0 -and
        $Totals.ControlledUserCount -eq 33 -and
        $Totals.EnabledUserCount -eq 33 -and
        $Totals.EmployeeCount -eq 28 -and
        $Totals.ContractorCount -eq 5 -and
        $Totals.ManagerAssignedCount -eq 27 -and
        $Totals.TotalDirectMemberships -eq 155 -and
        $MasonExpirationCleared -and
        $LeaverUserCount -eq 0 -and
        $PermanentEmployeeCount -eq 50 -and
        $IDTRUsers.Count -eq 5 -and
        $IDTRDisabledCount -eq 5 -and
        $HighValueGroupMembers -eq 0
    )

    if (-not $Passed) {
        throw 'Final directory or isolation validation failed.'
    }

    Add-AuditEvent `
        -RequestID 'TRANSACTION' `
        -EmployeeID '' `
        -SamAccountName '' `
        -Action 'PostMoverValidation' `
        -Result 'Success' `
        -Detail 'All mover target states, totals and isolation controls validated.'

    $AuditEvents |
        Export-Csv `
            -LiteralPath $AuditPath `
            -NoTypeInformation `
            -Encoding UTF8

    [pscustomobject]@{
        ComputerName = $env:COMPUTERNAME
        CorrelationID = $CorrelationID
        DatasetHashMatches = ($ActualHash -eq $ExpectedSHA256)
        ApprovedMoverCount = $Records.Count
        SourceStateMoverCount = $SourceStateMoverCount
        TargetStateNoOpCount = $TargetStateNoOpCount
        MembershipsRemoved = $MembershipsRemoved
        MembershipsAdded = $MembershipsAdded
        AttributesUpdated = $AttributesUpdated
        ManagerAssignmentsMade = $ManagerAssignmentsMade
        OUMovesMade = $OUMovesMade
        ExpirationsCleared = $ExpirationsCleared
        MoverStateValidationCount = $MoverStateValidationCount
        IdempotentNoChangeCount = $IdempotentNoChangeCount
        FinalMoverValidationFailures = $FinalMoverValidationFailures
        ControlledUserCount = $Totals.ControlledUserCount
        EnabledUserCount = $Totals.EnabledUserCount
        EmployeeCount = $Totals.EmployeeCount
        ContractorCount = $Totals.ContractorCount
        ManagerAssignedCount = $Totals.ManagerAssignedCount
        TotalDirectMemberships = $Totals.TotalDirectMemberships
        MasonExpirationCleared = $MasonExpirationCleared
        LeaverUserCount = $LeaverUserCount
        PermanentEmployeeCount = $PermanentEmployeeCount
        IDTRUserCount = $IDTRUsers.Count
        IDTRDisabledCount = $IDTRDisabledCount
        HighValueGroupMembers = $HighValueGroupMembers
        AuditLogPath = $AuditPath
        AuditEventCount = $AuditEvents.Count
        PasswordsChangedOrExported = $false
        AccountsDeleted = 0
    } | Format-List

    Write-Host ''
    Write-Host 'PASS: All approved movers were transitioned, audited, and validated successfully.' -ForegroundColor Green
}
catch {
    Add-AuditEvent `
        -RequestID 'TRANSACTION' `
        -EmployeeID '' `
        -SamAccountName '' `
        -Action 'TransactionFailure' `
        -Result 'Failed' `
        -Detail $_.Exception.Message

    $AuditEvents |
        Export-Csv `
            -LiteralPath $AuditPath `
            -NoTypeInformation `
            -Encoding UTF8

    Write-Host ''
    Write-Host "FAIL: Mover processing stopped. Review $AuditPath and the effective directory state." -ForegroundColor Red
    throw
}
