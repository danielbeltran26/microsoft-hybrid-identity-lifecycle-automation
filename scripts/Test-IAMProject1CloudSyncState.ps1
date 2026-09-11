<#
.SYNOPSIS
    Validates the synchronized IAM Project 1 population in Microsoft Entra ID.

.DESCRIPTION
    Performs read-only Microsoft Graph queries from Azure Cloud Shell and
    validates the approved Cloud Sync outcome: 33 governed Corporate Test
    users, one internal synchronized service account, 15 expected GG_IAM
    security groups, worker classifications, enabled state, identifiers, UPN
    suffixes and synchronization timestamps.

    Run in Azure Cloud Shell PowerShell after selecting the correct tenant.
    The signed-in identity requires permission to read users and groups.

.NOTES
    Project: Microsoft Hybrid Identity Lifecycle Automation
    Milestone: 7 - Scoped Microsoft Entra synchronization
    Safety: Read-only. No Active Directory or Microsoft Entra objects are
    created, updated or deleted.
#>

[CmdletBinding()]
param(
    [string]$ExpectedUPNSuffix = 'danielcloudlaboutlook258.onmicrosoft.com',
    [string]$ExpectedCompanyName = 'Corporate Test',
    [int]$ExpectedSynchronizedUsers = 34,
    [int]$ExpectedInternalServiceAccounts = 1,
    [int]$ExpectedGovernedUsers = 33,
    [int]$ExpectedEnabledGovernedUsers = 30,
    [int]$ExpectedDisabledGovernedUsers = 3,
    [int]$ExpectedEmployees = 28,
    [int]$ExpectedContractors = 5
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ExpectedGroups = @(
    'GG_IAM_Access_Contractor_Portal',
    'GG_IAM_Access_Finance_ERP',
    'GG_IAM_Access_HR_Records',
    'GG_IAM_Access_IT_ServiceDesk',
    'GG_IAM_Access_M365_Baseline',
    'GG_IAM_Access_Operations_Portal',
    'GG_IAM_Access_Sales_CRM',
    'GG_IAM_All_Contractors',
    'GG_IAM_All_Employees',
    'GG_IAM_All_Workforce',
    'GG_IAM_Department_Finance',
    'GG_IAM_Department_HumanResources',
    'GG_IAM_Department_InformationTechnology',
    'GG_IAM_Department_Operations',
    'GG_IAM_Department_Sales'
)

function Get-GraphCollection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Uri
    )

    $Items = [System.Collections.Generic.List[object]]::new()
    $NextUri = $Uri

    while ($NextUri) {
        $Response = Invoke-AzRestMethod -Method GET -Uri $NextUri

        if ($Response.StatusCode -lt 200 -or $Response.StatusCode -ge 300) {
            throw "Microsoft Graph request failed with HTTP $($Response.StatusCode)."
        }

        $Body = $Response.Content | ConvertFrom-Json

        foreach ($Item in @($Body.value)) {
            $Items.Add($Item)
        }

        $NextLinkProperty = $Body.PSObject.Properties['@odata.nextLink']
        $NextUri = if ($null -ne $NextLinkProperty) {
            [string]$NextLinkProperty.Value
        }
        else {
            $null
        }
    }

    return @($Items)
}

$Context = Get-AzContext

if ($null -eq $Context -or $null -eq $Context.Tenant) {
    throw 'No Azure Cloud Shell tenant context is available.'
}

$UserSelect = @(
    'id',
    'accountEnabled',
    'companyName',
    'displayName',
    'employeeId',
    'employeeType',
    'onPremisesDistinguishedName',
    'onPremisesLastSyncDateTime',
    'onPremisesSyncEnabled',
    'userPrincipalName'
) -join ','

$GroupSelect = @(
    'id',
    'displayName',
    'groupTypes',
    'mailEnabled',
    'membershipRule',
    'onPremisesLastSyncDateTime',
    'onPremisesSyncEnabled',
    'securityEnabled'
) -join ','

$UsersUri = "https://graph.microsoft.com/v1.0/users?`$select=$UserSelect&`$top=999"
$GroupsUri = "https://graph.microsoft.com/v1.0/groups?`$select=$GroupSelect&`$top=999"

$AllUsers = Get-GraphCollection -Uri $UsersUri
$AllGroups = Get-GraphCollection -Uri $GroupsUri

$SynchronizedUsers = @(
    $AllUsers | Where-Object onPremisesSyncEnabled -eq $true
)

$GovernedUsers = @(
    $SynchronizedUsers |
        Where-Object companyName -eq $ExpectedCompanyName
)

$InternalServiceAccounts = @(
    $SynchronizedUsers |
        Where-Object companyName -ne $ExpectedCompanyName
)

$EnabledGovernedUsers = @(
    $GovernedUsers | Where-Object accountEnabled -eq $true
)

$DisabledGovernedUsers = @(
    $GovernedUsers | Where-Object accountEnabled -eq $false
)

$DisabledLeaverUsers = @(
    $DisabledGovernedUsers |
        Where-Object onPremisesDistinguishedName -like '*,OU=Leavers,OU=Users,OU=IAM-Lab,*'
)

$EmployeeUsers = @(
    $GovernedUsers | Where-Object employeeType -eq 'Employee'
)

$ContractorUsers = @(
    $GovernedUsers | Where-Object employeeType -eq 'Contractor'
)

$UsersWithCompleteEmployeeIDs = @(
    $GovernedUsers |
        Where-Object employeeId -match '^IAM\d{4}$'
)

$UniqueEmployeeIDs = @(
    $GovernedUsers.employeeId |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Sort-Object -Unique
)

$UsersWithValidSuffixes = @(
    $GovernedUsers |
        Where-Object userPrincipalName -like "*@$ExpectedUPNSuffix"
)

$UsersWithSyncTimestamps = @(
    $GovernedUsers |
        Where-Object { $null -ne $_.onPremisesLastSyncDateTime }
)

$UnexpectedSynchronizedUserCount = [math]::Max(
    0,
    $SynchronizedUsers.Count -
        $ExpectedGovernedUsers -
        $ExpectedInternalServiceAccounts
)

$SynchronizedIAMGroups = @(
    $AllGroups |
        Where-Object {
            $_.onPremisesSyncEnabled -eq $true -and
            $_.displayName -like 'GG_IAM_*'
        }
)

$SecurityEnabledGroups = @(
    $SynchronizedIAMGroups | Where-Object securityEnabled -eq $true
)

$AssignedMembershipGroups = @(
    $SynchronizedIAMGroups |
        Where-Object {
            @($_.groupTypes).Count -eq 0 -and
            [string]::IsNullOrWhiteSpace($_.membershipRule)
        }
)

$GroupsWithSyncTimestamps = @(
    $SynchronizedIAMGroups |
        Where-Object { $null -ne $_.onPremisesLastSyncDateTime }
)

$ActualGroupNames = @(
    $SynchronizedIAMGroups.displayName | Sort-Object -Unique
)

$MissingExpectedGroups = @(
    $ExpectedGroups | Where-Object { $_ -notin $ActualGroupNames }
)

$UnexpectedSynchronizedGroups = @(
    $ActualGroupNames | Where-Object { $_ -notin $ExpectedGroups }
)

$Controls = @(
    [pscustomobject]@{ Control = 'Synchronized user objects'; Actual = $SynchronizedUsers.Count; Expected = $ExpectedSynchronizedUsers }
    [pscustomobject]@{ Control = 'Internal sync service accounts'; Actual = $InternalServiceAccounts.Count; Expected = $ExpectedInternalServiceAccounts }
    [pscustomobject]@{ Control = 'Governed IAM users'; Actual = $GovernedUsers.Count; Expected = $ExpectedGovernedUsers }
    [pscustomobject]@{ Control = 'Enabled governed users'; Actual = $EnabledGovernedUsers.Count; Expected = $ExpectedEnabledGovernedUsers }
    [pscustomobject]@{ Control = 'Disabled governed users'; Actual = $DisabledGovernedUsers.Count; Expected = $ExpectedDisabledGovernedUsers }
    [pscustomobject]@{ Control = 'Disabled users in Leavers OU'; Actual = $DisabledLeaverUsers.Count; Expected = $ExpectedDisabledGovernedUsers }
    [pscustomobject]@{ Control = 'Employee identities'; Actual = $EmployeeUsers.Count; Expected = $ExpectedEmployees }
    [pscustomobject]@{ Control = 'Contractor identities'; Actual = $ContractorUsers.Count; Expected = $ExpectedContractors }
    [pscustomobject]@{ Control = 'Complete employee IDs'; Actual = $UsersWithCompleteEmployeeIDs.Count; Expected = $ExpectedGovernedUsers }
    [pscustomobject]@{ Control = 'Unique employee IDs'; Actual = $UniqueEmployeeIDs.Count; Expected = $ExpectedGovernedUsers }
    [pscustomobject]@{ Control = 'Valid tenant UPN suffixes'; Actual = $UsersWithValidSuffixes.Count; Expected = $ExpectedGovernedUsers }
    [pscustomobject]@{ Control = 'Users with sync timestamps'; Actual = $UsersWithSyncTimestamps.Count; Expected = $ExpectedGovernedUsers }
    [pscustomobject]@{ Control = 'Unexpected synchronized users'; Actual = $UnexpectedSynchronizedUserCount; Expected = 0 }
    [pscustomobject]@{ Control = 'Synchronized IAM groups'; Actual = $SynchronizedIAMGroups.Count; Expected = $ExpectedGroups.Count }
    [pscustomobject]@{ Control = 'Security-enabled groups'; Actual = $SecurityEnabledGroups.Count; Expected = $ExpectedGroups.Count }
    [pscustomobject]@{ Control = 'Assigned-membership groups'; Actual = $AssignedMembershipGroups.Count; Expected = $ExpectedGroups.Count }
    [pscustomobject]@{ Control = 'Groups with sync timestamps'; Actual = $GroupsWithSyncTimestamps.Count; Expected = $ExpectedGroups.Count }
    [pscustomobject]@{ Control = 'Missing expected groups'; Actual = $MissingExpectedGroups.Count; Expected = 0 }
    [pscustomobject]@{ Control = 'Unexpected synchronized groups'; Actual = $UnexpectedSynchronizedGroups.Count; Expected = 0 }
)

$Results = foreach ($Control in $Controls) {
    [pscustomobject]@{
        Control = $Control.Control
        Actual = $Control.Actual
        Expected = $Control.Expected
        Status = if ($Control.Actual -eq $Control.Expected) { 'PASS' } else { 'FAIL' }
    }
}

$Results | Format-Table -AutoSize

$ComprehensiveValidationPassed = @(
    $Results | Where-Object Status -eq 'FAIL'
).Count -eq 0

[pscustomobject]@{
    ComprehensiveValidationPassed = $ComprehensiveValidationPassed
    ChangesMade                    = $false
    ActiveDirectoryChanges         = $false
    MicrosoftEntraChanges          = $false
} | Format-List

if (-not $ComprehensiveValidationPassed) {
    throw 'FAIL: The synchronized Cloud Sync population does not match the approved hybrid identity design.'
}

Write-Host ''
Write-Host `
    'PASS: The scoped Cloud Sync population matches the approved hybrid identity design.' `
    -ForegroundColor Green
