<#
.SYNOPSIS
    Validates IAM3001 and the complete post-Leaver Microsoft Entra state.
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

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
    throw "Expected exactly one retained IAM3001 user but found $($NoraMatches.Count)."
}
$Nora = $NoraMatches[0]

$NoraGroups = @(
    Get-GraphCollection `
        -Uri "https://graph.microsoft.com/v1.0/users/$($Nora.id)/memberOf?`$select=id,displayName"
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
    $EnabledGovernedUsers.Count -eq 30 -and
    $DisabledGovernedUsers.Count -eq 4 -and
    $EmployeeIdentities.Count -eq 29 -and
    $ContractorIdentities.Count -eq 5 -and
    $SynchronizedGroups.Count -eq 15 -and
    $Nora.accountEnabled -eq $false -and
    $Nora.userPrincipalName -eq 'nora.whitfield@danielcloudlaboutlook258.onmicrosoft.com' -and
    $Nora.department -eq 'Information Technology' -and
    $Nora.jobTitle -eq 'Identity Operations Analyst' -and
    $Nora.employeeType -eq 'Employee' -and
    $Nora.onPremisesSyncEnabled -eq $true -and
    $null -ne $Nora.onPremisesLastSyncDateTime -and
    $NoraGroups.Count -eq 0
)

[pscustomobject]@{
    SynchronizedUserObjects = $SynchronizedUsers.Count
    GovernedIAMUsers = $GovernedUsers.Count
    EnabledGovernedUsers = $EnabledGovernedUsers.Count
    DisabledGovernedUsers = $DisabledGovernedUsers.Count
    EmployeeIdentities = $EmployeeIdentities.Count
    ContractorIdentities = $ContractorIdentities.Count
    SynchronizedIAMGroups = $SynchronizedGroups.Count
    IAM3001Retained = $true
    IAM3001Enabled = $Nora.accountEnabled
    IAM3001DepartmentPreserved = $Nora.department
    IAM3001JobTitlePreserved = $Nora.jobTitle
    IAM3001OnPremisesSyncEnabled = $Nora.onPremisesSyncEnabled
    IAM3001SynchronizedGroupCount = $NoraGroups.Count
    PostLeaverCloudValidationPassed = $ValidationPassed
    ChangesMade = $false
    ActiveDirectoryChanges = $false
    MicrosoftEntraChanges = $false
} | Format-List

if (-not $ValidationPassed) {
    throw 'The Milestone 8 post-Leaver cloud validation failed.'
}

Write-Host ''
Write-Host `
    'PASS: IAM3001 and the complete post-Leaver Cloud Sync containment state are fully validated.' `
    -ForegroundColor Green
