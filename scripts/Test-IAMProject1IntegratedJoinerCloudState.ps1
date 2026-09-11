#Requires -Version 7.0

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$TenantUPNSuffix = 'danielcloudlaboutlook258.onmicrosoft.com'
$ExpectedGroups = @(
    'GG_IAM_Access_Finance_ERP'
    'GG_IAM_Access_M365_Baseline'
    'GG_IAM_All_Employees'
    'GG_IAM_All_Workforce'
    'GG_IAM_Department_Finance'
)

if (-not (Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue)) {
    throw 'Microsoft Graph authentication commands are unavailable in this Cloud Shell session.'
}

if (-not (Get-MgContext)) {
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
}

function Get-GraphCollection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Uri
    )

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

$NoraMatches = @($Users | Where-Object EmployeeId -eq 'IAM3001')
if ($NoraMatches.Count -ne 1) {
    throw "Expected exactly one IAM3001 user, but found $($NoraMatches.Count)."
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
    $Nora.userPrincipalName -eq "nora.whitfield@$TenantUPNSuffix" -and
    $Nora.department -eq 'Finance' -and
    $Nora.jobTitle -eq 'Financial Systems Analyst' -and
    $Nora.onPremisesSyncEnabled -eq $true -and
    $null -ne $Nora.onPremisesLastSyncDateTime -and
    $NoraGroups.Count -eq 5 -and
    $MissingGroups.Count -eq 0 -and
    $UnexpectedGroups.Count -eq 0
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
    MissingExpectedGroups = $MissingGroups.Count
    UnexpectedGroups = $UnexpectedGroups.Count
    PostJoinerCloudValidationPassed = $ValidationPassed
    ChangesMade = $false
    ActiveDirectoryChanges = $false
    MicrosoftEntraChanges = $false
} | Format-List

if (-not $ValidationPassed) {
    throw 'The Milestone 8 post-Joiner cloud validation failed.'
}

Write-Host ''
Write-Host `
    'PASS: IAM3001 and the complete post-Joiner Cloud Sync state are fully validated.' `
    -ForegroundColor Green
