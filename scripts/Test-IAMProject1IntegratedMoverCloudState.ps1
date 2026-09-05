<#
.SYNOPSIS
    Validates IAM3001 and the complete post-Mover Microsoft Entra state.

.DESCRIPTION
    Run in Microsoft Entra Cloud Shell using PowerShell. The script performs
    read-only Microsoft Graph requests and makes no Active Directory or Entra
    changes.
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ExpectedUPN = 'nora.whitfield@danielcloudlaboutlook258.onmicrosoft.com'
$ExpectedGroups = @(
    'GG_IAM_Access_IT_ServiceDesk'
    'GG_IAM_Access_M365_Baseline'
    'GG_IAM_All_Employees'
    'GG_IAM_All_Workforce'
    'GG_IAM_Department_InformationTechnology'
)
$FormerFinanceGroups = @(
    'GG_IAM_Access_Finance_ERP'
    'GG_IAM_Department_Finance'
)

if (-not (Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue)) {
    throw 'Microsoft Graph authentication commands are unavailable in this Cloud Shell session.'
}

$GraphAccessToken = (
    Get-AzAccessToken -ResourceUrl 'https://graph.microsoft.com'
).Token

if ($GraphAccessToken -isnot [System.Security.SecureString]) {
    $GraphAccessToken = ConvertTo-SecureString `
        -String $GraphAccessToken `
        -AsPlainText `
        -Force
}

Connect-MgGraph -AccessToken $GraphAccessToken -NoWelcome

function Get-GraphCollection {
    param([Parameter(Mandatory)][string]$Uri)

    $Items = [System.Collections.Generic.List[object]]::new()
    $NextUri = $Uri

    while (-not [string]::IsNullOrWhiteSpace($NextUri)) {
        $Response = Invoke-MgGraphRequest `
            -Method GET `
            -Uri $NextUri `
            -OutputType PSObject

        foreach ($Item in @($Response.value)) {
            $Items.Add($Item)
        }

        $NextLinkProperty = $Response.PSObject.Properties['@odata.nextLink']
        if ($null -eq $NextLinkProperty) {
            $NextUri = $null
        }
        else {
            $NextUri = [string]$NextLinkProperty.Value
        }
    }

    return $Items.ToArray()
}

$UserProperties = @(
    'id'
    'displayName'
    'userPrincipalName'
    'accountEnabled'
    'employeeId'
    'employeeType'
    'department'
    'jobTitle'
    'companyName'
    'onPremisesSyncEnabled'
    'onPremisesLastSyncDateTime'
) -join ','

$GroupProperties = @(
    'id'
    'displayName'
    'securityEnabled'
    'groupTypes'
    'membershipRule'
    'onPremisesSyncEnabled'
    'onPremisesLastSyncDateTime'
) -join ','

$Users = @(
    Get-GraphCollection `
        -Uri "https://graph.microsoft.com/v1.0/users?`$select=$UserProperties"
)
$Groups = @(
    Get-GraphCollection `
        -Uri "https://graph.microsoft.com/v1.0/groups?`$select=$GroupProperties"
)

$NoraMatches = @($Users | Where-Object employeeId -eq 'IAM3001')
if ($NoraMatches.Count -ne 1) {
    throw "Expected exactly one IAM3001 user but found $($NoraMatches.Count)."
}
$Nora = $NoraMatches[0]

$NoraGroups = @(
    Get-GraphCollection `
        -Uri "https://graph.microsoft.com/v1.0/users/$($Nora.id)/memberOf?`$select=id,displayName" |
        ForEach-Object { $_.displayName } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Sort-Object -Unique
)

$MissingGroups = @($ExpectedGroups | Where-Object { $_ -notin $NoraGroups })
$UnexpectedGroups = @($NoraGroups | Where-Object { $_ -notin $ExpectedGroups })
$FormerFinanceGroupsRemaining = @(
    $NoraGroups | Where-Object { $_ -in $FormerFinanceGroups }
)

$SynchronizedUsers = @($Users | Where-Object onPremisesSyncEnabled -eq $true)
$GovernedUsers = @($SynchronizedUsers | Where-Object companyName -eq 'Corporate Test')
$EnabledGovernedUsers = @($GovernedUsers | Where-Object accountEnabled -eq $true)
$DisabledGovernedUsers = @($GovernedUsers | Where-Object accountEnabled -eq $false)
$EmployeeIdentities = @($GovernedUsers | Where-Object employeeType -eq 'Employee')
$ContractorIdentities = @($GovernedUsers | Where-Object employeeType -eq 'Contractor')
$SynchronizedGroups = @(
    $Groups | Where-Object {
        $_.onPremisesSyncEnabled -eq $true -and
        $_.displayName -like 'GG_IAM_*'
    }
)

$ValidationPassed = (
    $SynchronizedUsers.Count -eq 35 -and
    $GovernedUsers.Count -eq 34 -and
    $EnabledGovernedUsers.Count -eq 31 -and
    $DisabledGovernedUsers.Count -eq 3 -and
    $EmployeeIdentities.Count -eq 29 -and
    $ContractorIdentities.Count -eq 5 -and
    $SynchronizedGroups.Count -eq 15 -and
    $Nora.accountEnabled -eq $true -and
    $Nora.userPrincipalName -eq $ExpectedUPN -and
    $Nora.department -eq 'Information Technology' -and
    $Nora.jobTitle -eq 'Identity Operations Analyst' -and
    $Nora.employeeType -eq 'Employee' -and
    $Nora.onPremisesSyncEnabled -eq $true -and
    $null -ne $Nora.onPremisesLastSyncDateTime -and
    $NoraGroups.Count -eq 5 -and
    $MissingGroups.Count -eq 0 -and
    $UnexpectedGroups.Count -eq 0 -and
    $FormerFinanceGroupsRemaining.Count -eq 0
)

[pscustomobject]@{
    SynchronizedUserObjects = $SynchronizedUsers.Count
    GovernedIAMUsers = $GovernedUsers.Count
    EnabledGovernedUsers = $EnabledGovernedUsers.Count
    DisabledGovernedUsers = $DisabledGovernedUsers.Count
    EmployeeIdentities = $EmployeeIdentities.Count
    ContractorIdentities = $ContractorIdentities.Count
    SynchronizedIAMGroups = $SynchronizedGroups.Count
    IAM3001Found = $true
    IAM3001Enabled = $Nora.accountEnabled
    IAM3001Department = $Nora.department
    IAM3001JobTitle = $Nora.jobTitle
    IAM3001OnPremisesSyncEnabled = $Nora.onPremisesSyncEnabled
    IAM3001SynchronizedGroupCount = $NoraGroups.Count
    FormerFinanceGroupCount = $FormerFinanceGroupsRemaining.Count
    MissingExpectedGroups = $MissingGroups.Count
    UnexpectedGroups = $UnexpectedGroups.Count
    PostMoverCloudValidationPassed = $ValidationPassed
    ChangesMade = $false
    ActiveDirectoryChanges = $false
    MicrosoftEntraChanges = $false
} | Format-List

if (-not $ValidationPassed) {
    throw 'The Milestone 8 post-Mover cloud validation failed.'
}

Write-Host ''
Write-Host `
    'PASS: IAM3001 and the complete post-Mover Cloud Sync state are fully validated.' `
    -ForegroundColor Green
