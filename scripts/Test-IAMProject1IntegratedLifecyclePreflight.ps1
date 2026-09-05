<#
.SYNOPSIS
    Validates the approved IAM Project 1 integrated lifecycle test plan.

.DESCRIPTION
    Performs read-only validation on DC01 before Milestone 8 creates IAM3001.
    It verifies the approved dataset digest and schema, identity uniqueness,
    managers, protected OUs, Global Security groups, and the Milestone 7 source
    baseline. It does not create, update or delete any directory object.

.NOTES
    Project: Microsoft Hybrid Identity Lifecycle Automation
    Milestone: 8 - Integrated hybrid lifecycle testing
    Safety: Read-only.
#>

[CmdletBinding()]
param(
    [string]$DatasetPath = 'C:\IAM-Lab\data\iam-project1-integrated-lifecycle-test.csv',
    [string]$ExpectedSHA256 = '9FC4CFF3DB15DB11C7EE05486007953F436BC3FC48124B6275231886CDED9AD3'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($env:COMPUTERNAME -ne 'DC01') {
    throw "Run this script on DC01, not $env:COMPUTERNAME."
}

Import-Module ActiveDirectory

if (-not (Test-Path -LiteralPath $DatasetPath -PathType Leaf)) {
    throw "Approved integrated lifecycle dataset not found: $DatasetPath"
}

$ActualHash = (Get-FileHash -LiteralPath $DatasetPath -Algorithm SHA256).Hash

if ($ActualHash -ne $ExpectedSHA256) {
    throw "Dataset hash mismatch. Expected $ExpectedSHA256 but found $ActualHash."
}

$RequiredColumns = @(
    'TestID','EmployeeID','GivenName','Surname','DisplayName','SamAccountName',
    'UserPrincipalName','Company','JoinerDepartment','JoinerJobTitle',
    'JoinerWorkerType','JoinerManagerEmployeeID','JoinerOU','JoinerGroups',
    'MoverDepartment','MoverJobTitle','MoverWorkerType','MoverManagerEmployeeID',
    'MoverOU','MoverGroups','LeaverOU','JoinerApprovalID','MoverApprovalID',
    'LeaverApprovalID','ApprovalStatus','RequestedBy','ApprovedBy','ApprovalDate',
    'BusinessJustification'
)

$Records = @(Import-Csv -LiteralPath $DatasetPath)

if ($Records.Count -ne 1) {
    throw "Expected one integrated lifecycle record but found $($Records.Count)."
}

$ActualColumns = @($Records[0].PSObject.Properties.Name)
$MissingColumns = @($RequiredColumns | Where-Object { $_ -notin $ActualColumns })
$SecretColumns = @($ActualColumns | Where-Object { $_ -match 'Password|Secret|Token|Credential' })

if ($MissingColumns.Count -gt 0 -or $SecretColumns.Count -gt 0) {
    throw 'The integrated lifecycle dataset schema is invalid.'
}

$Record = $Records[0]
$EmployeeID = [string]$Record.EmployeeID
$SamAccountName = [string]$Record.SamAccountName
$UserPrincipalName = [string]$Record.UserPrincipalName

$FixedValuesValid = (
    $Record.TestID -eq 'M08-E2E-001' -and
    $Record.EmployeeID -eq 'IAM3001' -and
    $Record.SamAccountName -eq 'nora.whitfield' -and
    $Record.UserPrincipalName -eq 'nora.whitfield@danielcloudlaboutlook258.onmicrosoft.com' -and
    $Record.Company -eq 'Corporate Test' -and
    $Record.JoinerWorkerType -eq 'Employee' -and
    $Record.MoverWorkerType -eq 'Employee' -and
    $Record.ApprovalStatus -eq 'Approved'
)

$IdentityCollisions = @(
    Get-ADUser -Filter {
        EmployeeID -eq $EmployeeID -or
        SamAccountName -eq $SamAccountName -or
        UserPrincipalName -eq $UserPrincipalName
    }
)

$ManagerIDs = @($Record.JoinerManagerEmployeeID, $Record.MoverManagerEmployeeID)
$ManagerResults = @(
    foreach ($ManagerID in $ManagerIDs) {
        $EscapedID = $ManagerID.Replace("'", "''")
        $Matches = @(Get-ADUser -Filter "EmployeeID -eq '$EscapedID'" -Properties EmployeeID, Enabled)
        [pscustomobject]@{
            EmployeeID = $ManagerID
            FoundOnce = $Matches.Count -eq 1
            Enabled = $Matches.Count -eq 1 -and $Matches[0].Enabled
        }
    }
)

$RequiredOUs = @($Record.JoinerOU, $Record.MoverOU, $Record.LeaverOU) | Sort-Object -Unique
$OUResults = @(
    foreach ($OU in $RequiredOUs) {
        [pscustomobject]@{
            DistinguishedName = $OU
            Exists = $null -ne (Get-ADOrganizationalUnit -Identity $OU -ErrorAction SilentlyContinue)
        }
    }
)

$RequiredGroups = @(
    @($Record.JoinerGroups, $Record.MoverGroups) |
        ForEach-Object { $_ -split ';' } |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ } |
        Sort-Object -Unique
)

$GroupResults = @(
    foreach ($GroupName in $RequiredGroups) {
        $Group = Get-ADGroup -Identity $GroupName -Properties GroupCategory, GroupScope -ErrorAction SilentlyContinue
        [pscustomobject]@{
            GroupName = $GroupName
            Valid = $null -ne $Group -and $Group.GroupCategory -eq 'Security' -and $Group.GroupScope -eq 'Global'
        }
    }
)

$IAMRoot = 'OU=IAM-Lab,DC=corporate,DC=test'
$ControlledUsers = @(Get-ADUser -SearchBase $IAMRoot -SearchScope Subtree -Filter 'EmployeeID -like "IAM*"' -Properties Enabled, employeeType)
$EnabledUsers = @($ControlledUsers | Where-Object Enabled)
$Employees = @($ControlledUsers | Where-Object employeeType -eq 'Employee')
$Contractors = @($ControlledUsers | Where-Object employeeType -eq 'Contractor')
$IAMGroups = @(Get-ADGroup -SearchBase "OU=Groups,$IAMRoot" -SearchScope Subtree -Filter 'Name -like "GG_IAM_*"')

$InvalidManagers = @($ManagerResults | Where-Object { -not $_.FoundOnce -or -not $_.Enabled })
$MissingOUs = @($OUResults | Where-Object { -not $_.Exists })
$InvalidGroups = @($GroupResults | Where-Object { -not $_.Valid })

$PreflightPassed = (
    $FixedValuesValid -and
    $IdentityCollisions.Count -eq 0 -and
    $InvalidManagers.Count -eq 0 -and
    $MissingOUs.Count -eq 0 -and
    $InvalidGroups.Count -eq 0 -and
    $ControlledUsers.Count -eq 33 -and
    $EnabledUsers.Count -eq 30 -and
    $Employees.Count -eq 28 -and
    $Contractors.Count -eq 5 -and
    $IAMGroups.Count -eq 15
)

[pscustomobject]@{
    DatasetHashMatches = $ActualHash -eq $ExpectedSHA256
    ApprovedRecordCount = $Records.Count
    MissingColumnCount = $MissingColumns.Count
    SecretColumnCount = $SecretColumns.Count
    FixedValuesValid = $FixedValuesValid
    IdentityCollisionCount = $IdentityCollisions.Count
    ValidManagerCount = @($ManagerResults | Where-Object { $_.FoundOnce -and $_.Enabled }).Count
    ValidOUCount = @($OUResults | Where-Object Exists).Count
    ValidGroupCount = @($GroupResults | Where-Object Valid).Count
    ControlledUserCount = $ControlledUsers.Count
    EnabledUserCount = $EnabledUsers.Count
    EmployeeCount = $Employees.Count
    ContractorCount = $Contractors.Count
    IAMGroupCount = $IAMGroups.Count
    PreflightPassed = $PreflightPassed
    ChangesMade = $false
} | Format-List

if (-not $PreflightPassed) {
    throw 'FAIL: The Milestone 8 integrated lifecycle plan is not safe to execute.'
}

Write-Host ''
Write-Host 'PASS: The approved IAM3001 integrated lifecycle plan is collision-free and ready for controlled execution.' -ForegroundColor Green
