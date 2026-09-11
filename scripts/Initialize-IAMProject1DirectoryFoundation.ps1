<#
.SYNOPSIS
    Creates the IAM Project 1 OU, group and UPN foundation.

.DESCRIPTION
    Run in Windows PowerShell as Administrator on DC01. The script creates or
    validates the protected IAM-Lab OU hierarchy, creates or validates the 15
    approved Global Security groups, adds the verified Entra UPN suffix and
    moves the existing SYNC01 computer account into the Servers OU.

    The script does not create users, remove directory objects or configure
    Microsoft Entra Cloud Sync.
#>

[CmdletBinding()]
param(
    [string]$ExpectedComputerName = 'DC01',
    [string]$ExpectedDomain = 'corporate.test',
    [string]$EntraUPNSuffix = 'danielcloudlaboutlook258.onmicrosoft.com'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($env:COMPUTERNAME -ne $ExpectedComputerName) {
    throw "Run this script on $ExpectedComputerName, not $env:COMPUTERNAME."
}

Import-Module ActiveDirectory

$Domain = Get-ADDomain
$Forest = Get-ADForest

if ($Domain.DNSRoot -ne $ExpectedDomain) {
    throw "Expected domain $ExpectedDomain but detected $($Domain.DNSRoot)."
}

$DomainDN = $Domain.DistinguishedName
$RootDN = "OU=IAM-Lab,$DomainDN"
$UsersDN = "OU=Users,$RootDN"
$EmployeesDN = "OU=Employees,$UsersDN"
$GroupsDN = "OU=Groups,$RootDN"
$InfrastructureDN = "OU=Infrastructure,$RootDN"

$OUPlan = @(
    [pscustomobject]@{ Name = 'IAM-Lab'; Path = $DomainDN; Description = 'Isolated directory boundary for IAM Project 1.' }
    [pscustomobject]@{ Name = 'Users'; Path = $RootDN; Description = 'Controlled IAM Project 1 user identities.' }
    [pscustomobject]@{ Name = 'Employees'; Path = $UsersDN; Description = 'Controlled employee identities.' }
    [pscustomobject]@{ Name = 'Finance'; Path = $EmployeesDN; Description = 'Controlled Finance employee identities.' }
    [pscustomobject]@{ Name = 'Human Resources'; Path = $EmployeesDN; Description = 'Controlled Human Resources employee identities.' }
    [pscustomobject]@{ Name = 'Information Technology'; Path = $EmployeesDN; Description = 'Controlled Information Technology employee identities.' }
    [pscustomobject]@{ Name = 'Sales'; Path = $EmployeesDN; Description = 'Controlled Sales employee identities.' }
    [pscustomobject]@{ Name = 'Operations'; Path = $EmployeesDN; Description = 'Controlled Operations employee identities.' }
    [pscustomobject]@{ Name = 'Contractors'; Path = $UsersDN; Description = 'Controlled contractor identities.' }
    [pscustomobject]@{ Name = 'Leavers'; Path = $UsersDN; Description = 'Disabled identities retained for controlled offboarding.' }
    [pscustomobject]@{ Name = 'Groups'; Path = $RootDN; Description = 'Controlled IAM Project 1 security groups.' }
    [pscustomobject]@{ Name = 'Baseline'; Path = $GroupsDN; Description = 'Baseline workforce security groups.' }
    [pscustomobject]@{ Name = 'Departments'; Path = $GroupsDN; Description = 'Department membership security groups.' }
    [pscustomobject]@{ Name = 'Access'; Path = $GroupsDN; Description = 'Role and resource access security groups.' }
    [pscustomobject]@{ Name = 'Infrastructure'; Path = $RootDN; Description = 'Infrastructure supporting the isolated IAM lab.' }
    [pscustomobject]@{ Name = 'Servers'; Path = $InfrastructureDN; Description = 'Member servers supporting IAM Project 1.' }
)

$BaselineDN = "OU=Baseline,$GroupsDN"
$DepartmentsDN = "OU=Departments,$GroupsDN"
$AccessDN = "OU=Access,$GroupsDN"

$GroupPlan = @(
    [pscustomobject]@{ Name = 'GG_IAM_All_Workforce'; Path = $BaselineDN; Description = 'All controlled IAM Project 1 workforce identities.' }
    [pscustomobject]@{ Name = 'GG_IAM_All_Employees'; Path = $BaselineDN; Description = 'All controlled IAM Project 1 employee identities.' }
    [pscustomobject]@{ Name = 'GG_IAM_All_Contractors'; Path = $BaselineDN; Description = 'All controlled IAM Project 1 contractor identities.' }
    [pscustomobject]@{ Name = 'GG_IAM_Department_Finance'; Path = $DepartmentsDN; Description = 'Controlled members of the Finance department.' }
    [pscustomobject]@{ Name = 'GG_IAM_Department_HumanResources'; Path = $DepartmentsDN; Description = 'Controlled members of the Human Resources department.' }
    [pscustomobject]@{ Name = 'GG_IAM_Department_InformationTechnology'; Path = $DepartmentsDN; Description = 'Controlled members of the Information Technology department.' }
    [pscustomobject]@{ Name = 'GG_IAM_Department_Sales'; Path = $DepartmentsDN; Description = 'Controlled members of the Sales department.' }
    [pscustomobject]@{ Name = 'GG_IAM_Department_Operations'; Path = $DepartmentsDN; Description = 'Controlled members of the Operations department.' }
    [pscustomobject]@{ Name = 'GG_IAM_Access_M365_Baseline'; Path = $AccessDN; Description = 'Baseline Microsoft 365 access eligibility.' }
    [pscustomobject]@{ Name = 'GG_IAM_Access_Finance_ERP'; Path = $AccessDN; Description = 'Finance enterprise resource planning access.' }
    [pscustomobject]@{ Name = 'GG_IAM_Access_HR_Records'; Path = $AccessDN; Description = 'Human Resources records-system access.' }
    [pscustomobject]@{ Name = 'GG_IAM_Access_IT_ServiceDesk'; Path = $AccessDN; Description = 'Information Technology service-desk access.' }
    [pscustomobject]@{ Name = 'GG_IAM_Access_Sales_CRM'; Path = $AccessDN; Description = 'Sales customer relationship management access.' }
    [pscustomobject]@{ Name = 'GG_IAM_Access_Operations_Portal'; Path = $AccessDN; Description = 'Operations business-portal access.' }
    [pscustomobject]@{ Name = 'GG_IAM_Access_Contractor_Portal'; Path = $AccessDN; Description = 'Restricted contractor-portal access.' }
)

$CreatedOUCount = 0
$ExistingOUCount = 0

foreach ($PlannedOU in $OUPlan) {
    $EscapedName = $PlannedOU.Name.Replace("'", "''")
    $ExistingOU = Get-ADOrganizationalUnit `
        -Filter "Name -eq '$EscapedName'" `
        -SearchBase $PlannedOU.Path `
        -SearchScope OneLevel `
        -Properties Description, ProtectedFromAccidentalDeletion

    if ($null -eq $ExistingOU) {
        New-ADOrganizationalUnit `
            -Name $PlannedOU.Name `
            -Path $PlannedOU.Path `
            -Description $PlannedOU.Description `
            -ProtectedFromAccidentalDeletion $true
        $CreatedOUCount++
    }
    else {
        Set-ADOrganizationalUnit `
            -Identity $ExistingOU `
            -Description $PlannedOU.Description `
            -ProtectedFromAccidentalDeletion $true
        $ExistingOUCount++
    }
}

$CreatedGroupCount = 0
$ExistingGroupCount = 0

foreach ($PlannedGroup in $GroupPlan) {
    $EscapedName = $PlannedGroup.Name.Replace("'", "''")
    $ExpectedDN = "CN=$($PlannedGroup.Name),$($PlannedGroup.Path)"
    $ExistingGroup = Get-ADGroup `
        -Filter "SamAccountName -eq '$EscapedName'" `
        -Properties DistinguishedName

    if ($null -eq $ExistingGroup) {
        New-ADGroup `
            -Name $PlannedGroup.Name `
            -SamAccountName $PlannedGroup.Name `
            -GroupScope Global `
            -GroupCategory Security `
            -Path $PlannedGroup.Path `
            -Description $PlannedGroup.Description
        $CreatedGroupCount++
    }
    else {
        if ($ExistingGroup.DistinguishedName -ne $ExpectedDN) {
            throw "$($PlannedGroup.Name) exists outside its approved IAM-Lab OU."
        }

        Set-ADGroup `
            -Identity $ExistingGroup `
            -Description $PlannedGroup.Description
        $ExistingGroupCount++
    }
}

$SuffixAdded = $false

if ($Forest.UPNSuffixes -notcontains $EntraUPNSuffix) {
    Set-ADForest `
        -Identity $Forest.Name `
        -UPNSuffixes @{ Add = $EntraUPNSuffix }
    $SuffixAdded = $true
}

$ServersDN = "OU=Servers,$InfrastructureDN"
$ExpectedSYNC01DN = "CN=SYNC01,$ServersDN"
$SYNC01 = Get-ADComputer `
    -Identity 'SYNC01' `
    -Properties Enabled, OperatingSystem
$SYNC01Moved = $false

if ($SYNC01.DistinguishedName -ne $ExpectedSYNC01DN) {
    Move-ADObject `
        -Identity $SYNC01 `
        -TargetPath $ServersDN
    $SYNC01Moved = $true
}

$ValidatedOUs = @(
    foreach ($PlannedOU in $OUPlan) {
        Get-ADOrganizationalUnit `
            -Identity "OU=$($PlannedOU.Name),$($PlannedOU.Path)" `
            -Properties ProtectedFromAccidentalDeletion
    }
)

$ValidatedGroups = @(
    foreach ($PlannedGroup in $GroupPlan) {
        Get-ADGroup `
            -Identity $PlannedGroup.Name `
            -Properties GroupScope, GroupCategory, DistinguishedName
    }
)

$SYNC01 = Get-ADComputer -Identity 'SYNC01' -Properties Enabled
$Forest = Get-ADForest

$OUProtectionFailureCount = @(
    $ValidatedOUs |
        Where-Object ProtectedFromAccidentalDeletion -eq $false
).Count

$GroupValidationFailureCount = @(
    $ValidatedGroups |
        Where-Object {
            $_.GroupScope -ne 'Global' -or
            $_.GroupCategory -ne 'Security'
        }
).Count

$Passed = (
    $ValidatedOUs.Count -eq 16 -and
    $OUProtectionFailureCount -eq 0 -and
    $ValidatedGroups.Count -eq 15 -and
    $GroupValidationFailureCount -eq 0 -and
    $Forest.UPNSuffixes -contains $EntraUPNSuffix -and
    $SYNC01.DistinguishedName -eq $ExpectedSYNC01DN -and
    $SYNC01.Enabled
)

[pscustomobject]@{
    DomainName                  = $Domain.DNSRoot
    CreatedOUCount              = $CreatedOUCount
    ExistingOUCount             = $ExistingOUCount
    ValidatedOUCount            = $ValidatedOUs.Count
    OUProtectionFailureCount    = $OUProtectionFailureCount
    CreatedGroupCount           = $CreatedGroupCount
    ExistingGroupCount          = $ExistingGroupCount
    ValidatedGroupCount         = $ValidatedGroups.Count
    GroupValidationFailureCount = $GroupValidationFailureCount
    EntraUPNSuffix              = $EntraUPNSuffix
    SuffixAdded                 = $SuffixAdded
    SYNC01Moved                 = $SYNC01Moved
    SYNC01PlacementValid        = $SYNC01.DistinguishedName -eq $ExpectedSYNC01DN
}

if (-not $Passed) {
    throw 'FAIL: The IAM Project 1 directory foundation requires investigation.'
}

Write-Host ''
Write-Host 'PASS: The IAM Project 1 directory foundation is correctly configured.' -ForegroundColor Green
