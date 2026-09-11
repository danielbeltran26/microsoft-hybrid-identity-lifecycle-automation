<#
.SYNOPSIS
    Applies the approved Milestone 8 IAM3001 mover transition.

.DESCRIPTION
    Run in Windows PowerShell as Administrator on DC01. The script validates
    the approved integrated-lifecycle dataset, the complete Joiner source
    state, target manager, protected target OU, and all required Global
    Security groups before making changes. Obsolete Finance access is removed
    before Information Technology access is granted. The resulting state and
    controlled-directory totals are validated and written to a correlated CSV
    audit log. Replaying a completed transition returns a no-change result.
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

$CorrelationID = 'M08-MOVER-{0}' -f (Get-Date -Format 'yyyyMMdd-HHmmss')
$AuditPath = Join-Path $LogFolder "$CorrelationID-audit.csv"
$AuditEvents = [System.Collections.Generic.List[object]]::new()

function Add-AuditEvent {
    param(
        [string]$Action,
        [string]$Result,
        [string]$Detail
    )

    $AuditEvents.Add([pscustomobject]@{
        TimestampUTC = [datetime]::UtcNow.ToString('o')
        CorrelationID = $CorrelationID
        TestID = $Record.TestID
        ApprovalID = $Record.MoverApprovalID
        EmployeeID = $Record.EmployeeID
        SamAccountName = $Record.SamAccountName
        Action = $Action
        Result = $Result
        Detail = $Detail
    })
}

function ConvertTo-GroupList {
    param([AllowEmptyString()][string]$Value)

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
    param([Parameter(Mandatory)][string]$DistinguishedName)

    return $DistinguishedName.Substring(
        $DistinguishedName.IndexOf(',') + 1
    )
}

function Get-DirectIAMGroups {
    param([Parameter(Mandatory)]$User)

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

function Get-IdentityState {
    param(
        [Parameter(Mandatory)]$User,
        [Parameter(Mandatory)][ValidateSet('Joiner', 'Mover')][string]$Stage
    )

    if ($Stage -eq 'Joiner') {
        $Department = $Record.JoinerDepartment
        $JobTitle = $Record.JoinerJobTitle
        $WorkerType = $Record.JoinerWorkerType
        $ManagerID = $Record.JoinerManagerEmployeeID
        $OU = $Record.JoinerOU
        $Groups = $JoinerGroups
    }
    else {
        $Department = $Record.MoverDepartment
        $JobTitle = $Record.MoverJobTitle
        $WorkerType = $Record.MoverWorkerType
        $ManagerID = $Record.MoverManagerEmployeeID
        $OU = $Record.MoverOU
        $Groups = $MoverGroups
    }

    $ActualGroups = @(Get-DirectIAMGroups -User $User)
    $ActualManagerID = Get-ManagerEmployeeID -User $User
    $ActualOU = Get-ParentDistinguishedName -DistinguishedName $User.DistinguishedName

    return [pscustomobject]@{
        Stage = $Stage
        IsMatch = (
            $User.Enabled -and
            $User.EmployeeID -eq $Record.EmployeeID -and
            $User.SamAccountName -eq $Record.SamAccountName -and
            $User.UserPrincipalName -eq $Record.UserPrincipalName -and
            $User.Company -eq $Record.Company -and
            $User.Department -eq $Department -and
            $User.Title -eq $JobTitle -and
            $User.employeeType -eq $WorkerType -and
            $ActualManagerID -eq $ManagerID -and
            $ActualOU -eq $OU -and
            (Test-StringSetEqual -Reference $Groups -Difference $ActualGroups)
        )
        Groups = $ActualGroups
        ManagerEmployeeID = $ActualManagerID
        OU = $ActualOU
    }
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

$Record = $null

try {
    if ($env:COMPUTERNAME -ne $ExpectedComputerName) {
        throw "Run this script on $ExpectedComputerName, not $env:COMPUTERNAME."
    }

    $Domain = Get-ADDomain
    if ($Domain.DNSRoot -ne $ExpectedDomain) {
        throw "Expected domain $ExpectedDomain but detected $($Domain.DNSRoot)."
    }

    if (-not (Test-Path -LiteralPath $DatasetPath -PathType Leaf)) {
        throw "Approved integrated lifecycle dataset not found: $DatasetPath"
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
        'UserPrincipalName', 'Company', 'JoinerDepartment', 'JoinerJobTitle',
        'JoinerWorkerType', 'JoinerManagerEmployeeID', 'JoinerOU',
        'JoinerGroups', 'MoverDepartment', 'MoverJobTitle', 'MoverWorkerType',
        'MoverManagerEmployeeID', 'MoverOU', 'MoverGroups', 'MoverApprovalID',
        'ApprovalStatus', 'ApprovedBy', 'ApprovalDate', 'BusinessJustification'
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
        $Record.MoverApprovalID -ne 'APR-M08-MOVER-001' -or
        $Record.ApprovalStatus -ne 'Approved'
    ) {
        throw 'The record does not match the approved IAM3001 Mover transaction.'
    }

    $JoinerGroups = @(ConvertTo-GroupList -Value $Record.JoinerGroups)
    $MoverGroups = @(ConvertTo-GroupList -Value $Record.MoverGroups)

    if ($JoinerGroups.Count -ne 5 -or $MoverGroups.Count -ne 5) {
        throw 'Expected exactly five Joiner groups and five Mover groups.'
    }

    $User = Get-ADUser `
        -Identity $Record.SamAccountName `
        -Properties EmployeeID, UserPrincipalName, Enabled, Company,
            Department, Title, employeeType, Manager, MemberOf

    $TargetManagerMatches = @(
        Get-ADUser `
            -Filter "EmployeeID -eq '$($Record.MoverManagerEmployeeID)'" `
            -Properties EmployeeID, Enabled
    )
    if ($TargetManagerMatches.Count -ne 1 -or -not $TargetManagerMatches[0].Enabled) {
        throw 'The approved Mover manager is missing, duplicated or disabled.'
    }
    $TargetManager = $TargetManagerMatches[0]

    $TargetOU = Get-ADOrganizationalUnit `
        -Identity $Record.MoverOU `
        -Properties ProtectedFromAccidentalDeletion
    if (-not $TargetOU.ProtectedFromAccidentalDeletion) {
        throw 'The approved Mover OU is not protected from accidental deletion.'
    }

    foreach ($GroupName in @($JoinerGroups + $MoverGroups | Sort-Object -Unique)) {
        $Group = Get-ADGroup -Identity $GroupName -Properties GroupCategory, GroupScope
        if ($Group.GroupCategory -ne 'Security' -or $Group.GroupScope -ne 'Global') {
            throw "$GroupName is not a Global Security group."
        }
    }

    $JoinerState = Get-IdentityState -User $User -Stage Joiner
    $MoverState = Get-IdentityState -User $User -Stage Mover

    if ($MoverState.IsMatch) {
        Add-AuditEvent `
            -Action 'IdempotentReplay' `
            -Result 'NoChange' `
            -Detail 'IAM3001 already matches the complete approved Mover state.'

        if (-not (Test-Path -LiteralPath $LogFolder -PathType Container)) {
            $null = New-Item -Path $LogFolder -ItemType Directory
        }
        $AuditEvents | Export-Csv -LiteralPath $AuditPath -NoTypeInformation -Encoding UTF8

        [pscustomobject]@{
            CorrelationID = $CorrelationID
            AuditPath = $AuditPath
            EmployeeID = $Record.EmployeeID
            TransitionMode = 'IdempotentReplay'
            ChangesMade = $false
        } | Format-List

        Write-Host ''
        Write-Host 'PASS: IAM3001 already matches the approved Mover state; no changes were made.' -ForegroundColor Green
        return
    }

    if (-not $JoinerState.IsMatch) {
        throw 'IAM3001 matches neither the approved Joiner source state nor the Mover target state.'
    }

    if (-not (Test-Path -LiteralPath $LogFolder -PathType Container)) {
        $null = New-Item -Path $LogFolder -ItemType Directory
    }

    Add-AuditEvent `
        -Action 'PreflightValidation' `
        -Result 'Success' `
        -Detail 'Dataset, approval, source state, manager, OU and groups validated.'

    $GroupsToRemove = @($JoinerGroups | Where-Object { $_ -notin $MoverGroups } | Sort-Object)
    $GroupsToAdd = @($MoverGroups | Where-Object { $_ -notin $JoinerGroups } | Sort-Object)

    foreach ($GroupName in $GroupsToRemove) {
        Remove-ADGroupMember -Identity $GroupName -Members $User -Confirm:$false
        Add-AuditEvent `
            -Action 'RemoveObsoleteMembership' `
            -Result 'Success' `
            -Detail "Removed obsolete access: $GroupName."
    }

    Set-ADUser `
        -Identity $User `
        -Department $Record.MoverDepartment `
        -Title $Record.MoverJobTitle `
        -Description "IAM Project 1 | Integrated Mover | Active | $($Record.MoverApprovalID)" `
        -Replace @{ employeeType = $Record.MoverWorkerType }
    Add-AuditEvent `
        -Action 'UpdateIdentityAttributes' `
        -Result 'Success' `
        -Detail 'Department, title, worker type and lifecycle description updated.'

    Set-ADUser -Identity $User -Manager $TargetManager.DistinguishedName
    Add-AuditEvent `
        -Action 'ChangeManager' `
        -Result 'Success' `
        -Detail "Manager changed to $($Record.MoverManagerEmployeeID)."

    Move-ADObject -Identity $User.DistinguishedName -TargetPath $Record.MoverOU
    Add-AuditEvent `
        -Action 'MoveOrganizationalUnit' `
        -Result 'Success' `
        -Detail 'Identity moved to the approved Information Technology OU.'

    $User = Get-ADUser -Identity $Record.SamAccountName -Properties MemberOf
    foreach ($GroupName in $GroupsToAdd) {
        Add-ADGroupMember -Identity $GroupName -Members $User
        Add-AuditEvent `
            -Action 'AddApprovedMembership' `
            -Result 'Success' `
            -Detail "Added approved destination access: $GroupName."
    }

    $User = Get-ADUser `
        -Identity $Record.SamAccountName `
        -Properties EmployeeID, UserPrincipalName, Enabled, Company,
            Department, Title, employeeType, Manager, MemberOf
    $FinalState = Get-IdentityState -User $User -Stage Mover
    if (-not $FinalState.IsMatch) {
        throw 'IAM3001 failed final Mover target-state validation.'
    }

    Add-AuditEvent `
        -Action 'ValidateMoverState' `
        -Result 'Success' `
        -Detail 'Identity attributes, manager, OU and exact IAM memberships match the approved Mover state.'

    $Totals = Get-ControlledTotals
    if (
        $Totals.ControlledUserCount -ne 34 -or
        $Totals.EnabledUserCount -ne 31 -or
        $Totals.EmployeeCount -ne 29 -or
        $Totals.ContractorCount -ne 5 -or
        $Totals.TotalDirectMemberships -ne 145
    ) {
        throw 'The controlled-directory totals changed unexpectedly.'
    }

    Add-AuditEvent `
        -Action 'PostMoverValidation' `
        -Result 'Success' `
        -Detail 'Mover target state and controlled-directory totals validated.'

    $AuditEvents | Export-Csv -LiteralPath $AuditPath -NoTypeInformation -Encoding UTF8

    [pscustomobject]@{
        CorrelationID = $CorrelationID
        AuditPath = $AuditPath
        AuditEventCount = $AuditEvents.Count
        FailedAuditEventCount = @($AuditEvents | Where-Object Result -eq 'Failed').Count
        EmployeeID = $Record.EmployeeID
        AccountEnabled = $User.Enabled
        Department = $User.Department
        JobTitle = $User.Title
        ManagerEmployeeID = Get-ManagerEmployeeID -User $User
        OrganisationalUnit = Get-ParentDistinguishedName -DistinguishedName $User.DistinguishedName
        MembershipsRemoved = $GroupsToRemove.Count
        MembershipsAdded = $GroupsToAdd.Count
        DirectIAMGroupCount = $FinalState.Groups.Count
        ControlledUserCount = $Totals.ControlledUserCount
        EnabledUserCount = $Totals.EnabledUserCount
        EmployeeCount = $Totals.EmployeeCount
        ContractorCount = $Totals.ContractorCount
        TotalDirectMemberships = $Totals.TotalDirectMemberships
        PasswordsChangedOrExported = $false
        AccountsCreated = 0
        AccountsDeleted = 0
        ChangesMade = $true
    } | Format-List

    Write-Host ''
    Write-Host 'PASS: IAM3001 was transitioned to Information Technology, audited and validated.' -ForegroundColor Green
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
    Write-Host "FAIL: Mover processing stopped. Review $AuditPath and the effective directory state." -ForegroundColor Red
    throw
}
