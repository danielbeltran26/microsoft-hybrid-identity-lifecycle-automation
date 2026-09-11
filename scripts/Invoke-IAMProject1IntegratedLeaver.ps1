<#
.SYNOPSIS
    Applies the approved Milestone 8 IAM3001 Leaver containment.

.DESCRIPTION
    Run in Windows PowerShell as Administrator on DC01. The script verifies
    the approved dataset and IAM3001 Mover state before its first directory
    write. It disables the account before removing all direct IAM access,
    moves the retained identity into the protected Leavers OU, preserves the
    approved identity attributes and manager, and writes a correlated audit.
    Safe partial containment can be resumed, and replaying the completed state
    produces no directory changes.
#>

[CmdletBinding()]
param(
    [string]$DatasetPath = 'C:\IAM-Lab\data\iam-project1-integrated-lifecycle-test.csv',
    [string]$ExpectedDatasetSHA256 = '9FC4CFF3DB15DB11C7EE05486007953F436BC3FC48124B6275231886CDED9AD3',
    [string]$ExpectedComputerName = 'DC01',
    [string]$ExpectedDomain = 'corporate.test',
    [string]$UsersRoot = 'OU=Users,OU=IAM-Lab,DC=corporate,DC=test',
    [string]$LogFolder = 'C:\IAM-Lab\logs'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

$CorrelationID = 'M08-LEAVER-{0}' -f (Get-Date -Format 'yyyyMMdd-HHmmss')
$AuditPath = Join-Path $LogFolder "$CorrelationID-audit.csv"
$AuditEvents = [System.Collections.Generic.List[object]]::new()
$Record = $null

function Add-AuditEvent {
    param([string]$Action, [string]$Result, [string]$Detail)

    $AuditEvents.Add([pscustomobject]@{
        TimestampUTC = [datetime]::UtcNow.ToString('o')
        CorrelationID = $CorrelationID
        TestID = $Record.TestID
        ApprovalID = $Record.LeaverApprovalID
        EmployeeID = $Record.EmployeeID
        SamAccountName = $Record.SamAccountName
        Action = $Action
        Result = $Result
        Detail = $Detail
    })
}

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
    param([string[]]$Reference, [string[]]$Difference)

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

function Get-DirectIAMGroups {
    param($User)

    return @(
        $User.MemberOf |
            Where-Object { $_ -like 'CN=GG_IAM_*' } |
            ForEach-Object { (Get-ADGroup -Identity $_).SamAccountName } |
            Sort-Object -Unique
    )
}

function Get-ManagerEmployeeID {
    param($User)

    if ($null -eq $User.Manager) {
        return $null
    }
    return (Get-ADUser -Identity $User.Manager -Properties EmployeeID).EmployeeID
}

function Get-ControlledTotals {
    $Users = @(
        Get-ADUser `
            -SearchBase $UsersRoot `
            -LDAPFilter '(objectCategory=person)' `
            -Properties Enabled, employeeType, Manager, MemberOf
    )
    $MembershipTotal = (
        $Users |
            ForEach-Object {
                @($_.MemberOf | Where-Object { $_ -like 'CN=GG_IAM_*' }).Count
            } |
            Measure-Object -Sum
    ).Sum

    return [pscustomobject]@{
        ControlledUserCount = $Users.Count
        EnabledUserCount = @($Users | Where-Object Enabled).Count
        EmployeeCount = @($Users | Where-Object employeeType -eq 'Employee').Count
        ContractorCount = @($Users | Where-Object employeeType -eq 'Contractor').Count
        ManagerAssignedCount = @($Users | Where-Object { $null -ne $_.Manager }).Count
        TotalDirectMemberships = $MembershipTotal
    }
}

try {
    if ($env:COMPUTERNAME -ne $ExpectedComputerName) {
        throw "Run this script on $ExpectedComputerName, not $env:COMPUTERNAME."
    }
    if ((Get-ADDomain).DNSRoot -ne $ExpectedDomain) {
        throw "The connected domain is not $ExpectedDomain."
    }
    if (-not (Test-Path -LiteralPath $DatasetPath -PathType Leaf)) {
        throw "Approved lifecycle dataset not found: $DatasetPath"
    }

    $DatasetHash = (Get-FileHash -LiteralPath $DatasetPath -Algorithm SHA256).Hash
    if ($DatasetHash -ne $ExpectedDatasetSHA256) {
        throw "Dataset hash mismatch. Calculated $DatasetHash."
    }

    $Records = @(Import-Csv -LiteralPath $DatasetPath)
    if ($Records.Count -ne 1) {
        throw "Expected one lifecycle record but found $($Records.Count)."
    }
    $Record = $Records[0]

    $RequiredColumns = @(
        'TestID', 'EmployeeID', 'DisplayName', 'SamAccountName',
        'UserPrincipalName', 'Company', 'MoverDepartment', 'MoverJobTitle',
        'MoverWorkerType', 'MoverManagerEmployeeID', 'MoverOU', 'MoverGroups',
        'LeaverOU', 'LeaverApprovalID', 'ApprovalStatus', 'ApprovedBy',
        'ApprovalDate', 'BusinessJustification'
    )
    $ActualColumns = @($Record.PSObject.Properties.Name)
    $MissingColumns = @($RequiredColumns | Where-Object { $_ -notin $ActualColumns })
    $SecretColumns = @(
        $ActualColumns |
            Where-Object { $_ -match '(?i)password|secret|credential|token|securestring' }
    )
    if ($MissingColumns.Count -ne 0) {
        throw "Missing columns: $($MissingColumns -join ', ')."
    }
    if ($SecretColumns.Count -ne 0) {
        throw "Prohibited secret-bearing columns: $($SecretColumns -join ', ')."
    }
    if (
        $Record.TestID -ne 'M08-E2E-001' -or
        $Record.EmployeeID -ne 'IAM3001' -or
        $Record.LeaverApprovalID -ne 'APR-M08-LEAVER-001' -or
        $Record.ApprovalStatus -ne 'Approved'
    ) {
        throw 'The record does not match the approved IAM3001 Leaver transaction.'
    }

    $ExpectedMoverGroups = @(ConvertTo-GroupList -Value $Record.MoverGroups)
    if ($ExpectedMoverGroups.Count -ne 5) {
        throw 'The approved Mover source state must contain exactly five groups.'
    }

    $LeaversOU = Get-ADOrganizationalUnit `
        -Identity $Record.LeaverOU `
        -Properties ProtectedFromAccidentalDeletion
    if (-not $LeaversOU.ProtectedFromAccidentalDeletion) {
        throw 'The controlled Leavers OU is not protected from accidental deletion.'
    }

    $User = Get-ADUser `
        -Identity $Record.SamAccountName `
        -Properties EmployeeID, DisplayName, UserPrincipalName, Enabled,
            Company, Department, Title, employeeType, Manager, MemberOf,
            Description

    $ActualManagerID = Get-ManagerEmployeeID -User $User
    $ActualGroups = @(Get-DirectIAMGroups -User $User)
    $ActualOU = Get-ParentDistinguishedName -DistinguishedName $User.DistinguishedName
    $UnexpectedGroups = @(
        $ActualGroups | Where-Object { $_ -notin $ExpectedMoverGroups }
    )
    $TargetDescription = (
        'IAM Project 1 | Integrated Leaver | Disabled | {0}' -f
        $Record.LeaverApprovalID
    )

    $PreservedAttributesValid = (
        $User.EmployeeID -eq $Record.EmployeeID -and
        $User.DisplayName -eq $Record.DisplayName -and
        $User.UserPrincipalName -eq $Record.UserPrincipalName -and
        $User.Company -eq $Record.Company -and
        $User.Department -eq $Record.MoverDepartment -and
        $User.Title -eq $Record.MoverJobTitle -and
        $User.employeeType -eq $Record.MoverWorkerType -and
        $ActualManagerID -eq $Record.MoverManagerEmployeeID
    )
    $SourceState = (
        $PreservedAttributesValid -and
        $User.Enabled -and
        $ActualOU -eq $Record.MoverOU -and
        (Test-StringSetEqual -Reference $ExpectedMoverGroups -Difference $ActualGroups)
    )
    $TargetState = (
        $PreservedAttributesValid -and
        -not $User.Enabled -and
        $ActualOU -eq $Record.LeaverOU -and
        $ActualGroups.Count -eq 0 -and
        $User.Description -eq $TargetDescription
    )
    $SafePartialState = (
        $PreservedAttributesValid -and
        $ActualOU -in @($Record.MoverOU, $Record.LeaverOU) -and
        $UnexpectedGroups.Count -eq 0
    )

    if ($TargetState) {
        if (-not (Test-Path -LiteralPath $LogFolder -PathType Container)) {
            $null = New-Item -Path $LogFolder -ItemType Directory
        }
        Add-AuditEvent `
            -Action 'IdempotentReplay' `
            -Result 'NoChange' `
            -Detail 'IAM3001 already matches the approved Leaver state.'
        $AuditEvents | Export-Csv -LiteralPath $AuditPath -NoTypeInformation -Encoding UTF8

        [pscustomobject]@{
            CorrelationID = $CorrelationID
            AuditPath = $AuditPath
            EmployeeID = $Record.EmployeeID
            TransitionMode = 'IdempotentReplay'
            ChangesMade = $false
        } | Format-List

        Write-Host ''
        Write-Host 'PASS: IAM3001 already matches the approved Leaver state; no changes were made.' -ForegroundColor Green
        return
    }

    if (-not ($SourceState -or $SafePartialState)) {
        throw 'IAM3001 is not in the approved Mover state or a safe partial containment state.'
    }

    if (-not (Test-Path -LiteralPath $LogFolder -PathType Container)) {
        $null = New-Item -Path $LogFolder -ItemType Directory
    }

    Add-AuditEvent `
        -Action 'PreflightValidation' `
        -Result 'Success' `
        -Detail 'Dataset, approval, source identity, manager, groups and protected Leavers OU validated.'

    if ($User.Enabled) {
        Disable-ADAccount -Identity $User.DistinguishedName
        Add-AuditEvent `
            -Action 'DisableAccount' `
            -Result 'Success' `
            -Detail 'IAM3001 was disabled before access removal.'
    }

    $User = Get-ADUser -Identity $Record.SamAccountName -Properties MemberOf
    $GroupsToRemove = @(Get-DirectIAMGroups -User $User)
    foreach ($GroupName in $GroupsToRemove) {
        Remove-ADGroupMember `
            -Identity $GroupName `
            -Members $User.DistinguishedName `
            -Confirm:$false
        Add-AuditEvent `
            -Action 'RemoveMembership' `
            -Result 'Success' `
            -Detail "Removed direct IAM access: $GroupName."
    }

    $User = Get-ADUser -Identity $Record.SamAccountName -Properties Description
    $CurrentOU = Get-ParentDistinguishedName -DistinguishedName $User.DistinguishedName
    if ($CurrentOU -ne $Record.LeaverOU) {
        Move-ADObject -Identity $User.DistinguishedName -TargetPath $Record.LeaverOU
        Add-AuditEvent `
            -Action 'MoveToLeaversOU' `
            -Result 'Success' `
            -Detail 'The disabled, access-free identity was moved to the protected Leavers OU.'
    }

    $User = Get-ADUser -Identity $Record.SamAccountName -Properties Description
    if ($User.Description -ne $TargetDescription) {
        Set-ADUser -Identity $User.DistinguishedName -Description $TargetDescription
        Add-AuditEvent `
            -Action 'UpdateLifecycleDescription' `
            -Result 'Success' `
            -Detail 'Lifecycle description updated to the approved retained Leaver state.'
    }

    $FinalUser = Get-ADUser `
        -Identity $Record.SamAccountName `
        -Properties EmployeeID, DisplayName, UserPrincipalName, Enabled,
            Company, Department, Title, employeeType, Manager, MemberOf,
            Description
    $FinalGroups = @(Get-DirectIAMGroups -User $FinalUser)
    $FinalManagerID = Get-ManagerEmployeeID -User $FinalUser
    $FinalOU = Get-ParentDistinguishedName -DistinguishedName $FinalUser.DistinguishedName

    $FinalStateValid = (
        -not $FinalUser.Enabled -and
        $FinalGroups.Count -eq 0 -and
        $FinalOU -eq $Record.LeaverOU -and
        $FinalUser.Description -eq $TargetDescription -and
        $FinalUser.EmployeeID -eq $Record.EmployeeID -and
        $FinalUser.DisplayName -eq $Record.DisplayName -and
        $FinalUser.UserPrincipalName -eq $Record.UserPrincipalName -and
        $FinalUser.Company -eq $Record.Company -and
        $FinalUser.Department -eq $Record.MoverDepartment -and
        $FinalUser.Title -eq $Record.MoverJobTitle -and
        $FinalUser.employeeType -eq $Record.MoverWorkerType -and
        $FinalManagerID -eq $Record.MoverManagerEmployeeID
    )
    if (-not $FinalStateValid) {
        throw 'IAM3001 failed final Leaver-state validation.'
    }

    Add-AuditEvent `
        -Action 'ValidateLeaverState' `
        -Result 'Success' `
        -Detail 'IAM3001 is disabled, access-free, retained and located in the protected Leavers OU.'

    $Totals = Get-ControlledTotals
    $Leavers = @(
        Get-ADUser -SearchBase $Record.LeaverOU -SearchScope OneLevel -Filter *
    )
    if (
        $Totals.ControlledUserCount -ne 34 -or
        $Totals.EnabledUserCount -ne 30 -or
        $Totals.EmployeeCount -ne 29 -or
        $Totals.ContractorCount -ne 5 -or
        $Totals.TotalDirectMemberships -ne 140 -or
        $Leavers.Count -ne 4
    ) {
        throw 'The controlled-directory totals changed unexpectedly.'
    }

    Add-AuditEvent `
        -Action 'PostLeaverValidation' `
        -Result 'Success' `
        -Detail 'Leaver containment and controlled-directory totals validated.'

    $AuditEvents | Export-Csv -LiteralPath $AuditPath -NoTypeInformation -Encoding UTF8

    [pscustomobject]@{
        CorrelationID = $CorrelationID
        AuditPath = $AuditPath
        AuditEventCount = $AuditEvents.Count
        FailedAuditEventCount = @($AuditEvents | Where-Object Result -eq 'Failed').Count
        EmployeeID = $Record.EmployeeID
        AccountEnabled = $FinalUser.Enabled
        DepartmentPreserved = $FinalUser.Department
        JobTitlePreserved = $FinalUser.Title
        ManagerEmployeeIDPreserved = $FinalManagerID
        OrganisationalUnit = $FinalOU
        MembershipsRemoved = $GroupsToRemove.Count
        DirectIAMGroupCount = $FinalGroups.Count
        ControlledUserCount = $Totals.ControlledUserCount
        EnabledUserCount = $Totals.EnabledUserCount
        EmployeeCount = $Totals.EmployeeCount
        ContractorCount = $Totals.ContractorCount
        TotalDirectMemberships = $Totals.TotalDirectMemberships
        LeaversOUUserCount = $Leavers.Count
        PasswordsChangedOrExported = $false
        AccountsCreated = 0
        AccountsDeleted = 0
        IdentityRetained = $true
        ChangesMade = $true
    } | Format-List

    Write-Host ''
    Write-Host 'PASS: IAM3001 was disabled, made access-free, retained and moved to the protected Leavers OU.' -ForegroundColor Green
}
catch {
    if ($null -ne $Record) {
        Add-AuditEvent `
            -Action 'TransactionFailure' `
            -Result 'Failed' `
            -Detail $_.Exception.Message
        if (-not (Test-Path -LiteralPath $LogFolder -PathType Container)) {
            $null = New-Item -Path $LogFolder -ItemType Directory
        }
        $AuditEvents | Export-Csv -LiteralPath $AuditPath -NoTypeInformation -Encoding UTF8
    }
    Write-Host ''
    Write-Host "FAIL: Leaver processing stopped. Review $AuditPath and the effective directory state." -ForegroundColor Red
    throw
}
