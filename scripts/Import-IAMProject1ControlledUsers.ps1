<#
.SYNOPSIS
    Provisions the approved IAM Project 1 controlled identity dataset.

.DESCRIPTION
    Run in Windows PowerShell as Administrator on DC01 after the directory
    foundation script. The script verifies the authoritative CSV digest and
    all referenced OUs and groups before it changes Active Directory.

    New accounts are created disabled with unique cryptographically generated
    24-character passwords. Passwords are converted to SecureString in memory
    and are never displayed, logged or exported. After every identity is
    staged, the script assigns managers and approved direct group memberships,
    applies contractor expiration dates and enables only date-eligible Active
    records. Existing matching controlled identities are validated and reused,
    making the script safe to run again.

    The script never deletes users or groups and never removes memberships.
#>

[CmdletBinding()]
param(
    [string]$CsvPath = 'C:\IAM-Lab\data\iam-project1-controlled-users.csv',
    [string]$ExpectedSHA256 = '153FCF70CA0B8C1B366767BB0F61AEF7E65EF074AD2FA29726C3AF1A07EC9641',
    [string]$ExpectedComputerName = 'DC01',
    [string]$ExpectedDomain = 'corporate.test',
    [string]$ExpectedUPNSuffix = 'danielcloudlaboutlook258.onmicrosoft.com'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function New-CryptographicPassword {
    [CmdletBinding()]
    param([ValidateRange(16, 128)][int]$Length = 24)

    $Upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ'
    $Lower = 'abcdefghijkmnopqrstuvwxyz'
    $Digits = '23456789'
    $Symbols = '!@#$%*-_=+?'
    $All = $Upper + $Lower + $Digits + $Symbols
    $Provider = [System.Security.Cryptography.RandomNumberGenerator]::Create()

    try {
        $Characters = New-Object System.Collections.Generic.List[char]

        foreach ($Set in @($Upper, $Lower, $Digits, $Symbols)) {
            $Buffer = New-Object byte[] 4
            $Provider.GetBytes($Buffer)
            $Index = [BitConverter]::ToUInt32($Buffer, 0) % $Set.Length
            $Characters.Add($Set[$Index])
        }

        while ($Characters.Count -lt $Length) {
            $Buffer = New-Object byte[] 4
            $Provider.GetBytes($Buffer)
            $Index = [BitConverter]::ToUInt32($Buffer, 0) % $All.Length
            $Characters.Add($All[$Index])
        }

        for ($Index = $Characters.Count - 1; $Index -gt 0; $Index--) {
            $Buffer = New-Object byte[] 4
            $Provider.GetBytes($Buffer)
            $SwapIndex = [BitConverter]::ToUInt32($Buffer, 0) % ($Index + 1)
            $Temporary = $Characters[$Index]
            $Characters[$Index] = $Characters[$SwapIndex]
            $Characters[$SwapIndex] = $Temporary
        }

        return -join $Characters
    }
    finally {
        $Provider.Dispose()
    }
}

function Get-PlannedGroups {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Record)

    return @(
        @($Record.BaselineGroups, $Record.DepartmentGroup, $Record.AccessGroups) |
            ForEach-Object { [string]$_ -split ';' } |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ } |
            Sort-Object -Unique
    )
}

if ($env:COMPUTERNAME -ne $ExpectedComputerName) {
    throw "Run this script on $ExpectedComputerName, not $env:COMPUTERNAME."
}

if (-not (Test-Path -LiteralPath $CsvPath -PathType Leaf)) {
    throw "The controlled dataset was not found at $CsvPath."
}

Import-Module ActiveDirectory
$Domain = Get-ADDomain
$Forest = Get-ADForest

if ($Domain.DNSRoot -ne $ExpectedDomain) {
    throw "Expected domain $ExpectedDomain but detected $($Domain.DNSRoot)."
}

if ($Forest.UPNSuffixes -notcontains $ExpectedUPNSuffix) {
    throw "The approved UPN suffix $ExpectedUPNSuffix is not configured."
}

$ActualHash = (Get-FileHash -LiteralPath $CsvPath -Algorithm SHA256).Hash

if ($ActualHash -ne $ExpectedSHA256) {
    throw "Dataset integrity check failed. Expected $ExpectedSHA256 but calculated $ActualHash."
}

$Records = @(Import-Csv -LiteralPath $CsvPath)

if ($Records.Count -ne 30) {
    throw "Expected 30 controlled identities but found $($Records.Count)."
}

$SecretColumns = @(
    $Records[0].PSObject.Properties.Name |
        Where-Object { $_ -match '(?i)password|secret|credential|token' }
)

if ($SecretColumns.Count -ne 0) {
    throw "The dataset contains prohibited secret-bearing columns: $($SecretColumns -join ', ')."
}

foreach ($PropertyName in @('EmployeeID', 'SamAccountName', 'UserPrincipalName')) {
    $Duplicates = @(
        $Records |
            Group-Object -Property $PropertyName |
            Where-Object Count -gt 1
    )

    if ($Duplicates.Count -ne 0) {
        throw "The dataset contains duplicate $PropertyName values."
    }
}

$AllReferencedGroups = @(
    $Records |
        ForEach-Object { Get-PlannedGroups -Record $_ } |
        Sort-Object -Unique
)

$AllReferencedOUs = @($Records.TargetOU | Sort-Object -Unique)

foreach ($OU in $AllReferencedOUs) {
    $null = Get-ADOrganizationalUnit -Identity $OU
}

foreach ($GroupName in $AllReferencedGroups) {
    $null = Get-ADGroup -Identity $GroupName
}

# Complete every collision check before the first directory write.
foreach ($Record in $Records) {
    if ($Record.UserPrincipalName -notlike "*@$ExpectedUPNSuffix") {
        throw "Unexpected UPN suffix for $($Record.EmployeeID)."
    }

    $EscapedEmployeeID = $Record.EmployeeID.Replace("'", "''")
    $EscapedSam = $Record.SamAccountName.Replace("'", "''")
    $EscapedUPN = $Record.UserPrincipalName.Replace("'", "''")
    $ExpectedDN = "CN=$($Record.DisplayName),$($Record.TargetOU)"
    $Matches = @(
        Get-ADUser `
            -Filter "EmployeeID -eq '$EscapedEmployeeID' -or SamAccountName -eq '$EscapedSam' -or UserPrincipalName -eq '$EscapedUPN'" `
            -Properties EmployeeID, UserPrincipalName
    )

    if ($Matches.Count -gt 1) {
        throw "Multiple existing directory identities collide with $($Record.EmployeeID)."
    }

    if ($Matches.Count -eq 1) {
        $Existing = $Matches[0]
        $ExactMatch = (
            $Existing.EmployeeID -eq $Record.EmployeeID -and
            $Existing.SamAccountName -eq $Record.SamAccountName -and
            $Existing.UserPrincipalName -eq $Record.UserPrincipalName -and
            $Existing.DistinguishedName -eq $ExpectedDN
        )

        if (-not $ExactMatch) {
            throw "An existing identity conflicts with $($Record.EmployeeID); no changes were made."
        }
    }
}

$CreatedUserCount = 0
$ExistingControlledUserCount = 0
$ManagerAssignmentsMade = 0
$MembershipsAdded = 0
$AccountsEnabledThisRun = 0

foreach ($Record in $Records) {
    $EscapedEmployeeID = $Record.EmployeeID.Replace("'", "''")
    $Existing = Get-ADUser `
        -Filter "EmployeeID -eq '$EscapedEmployeeID'" `
        -Properties EmployeeID

    if ($null -eq $Existing) {
        $PlainPassword = New-CryptographicPassword -Length 24

        try {
            $SecurePassword = ConvertTo-SecureString $PlainPassword -AsPlainText -Force
            $Description = "IAM Project 1 | $($Record.WorkerType) | Staged"
            $Parameters = @{
                Name                  = $Record.DisplayName
                GivenName             = $Record.GivenName
                Surname               = $Record.Surname
                DisplayName           = $Record.DisplayName
                SamAccountName        = $Record.SamAccountName
                UserPrincipalName     = $Record.UserPrincipalName
                EmailAddress          = $Record.UserPrincipalName
                EmployeeID            = $Record.EmployeeID
                Department            = $Record.Department
                Title                 = $Record.JobTitle
                Company               = 'Corporate Test'
                Description           = $Description
                Path                  = $Record.TargetOU
                AccountPassword       = $SecurePassword
                Enabled               = $false
                ChangePasswordAtLogon = $false
                PasswordNeverExpires  = $false
                OtherAttributes       = @{ employeeType = $Record.WorkerType }
            }

            if ($Record.WorkerType -eq 'Contractor') {
                if ([string]::IsNullOrWhiteSpace($Record.EndDate)) {
                    throw "Contractor $($Record.EmployeeID) has no EndDate."
                }

                $Parameters.AccountExpirationDate = ([datetime]$Record.EndDate).Date.AddDays(1)
            }

            New-ADUser @Parameters
            $CreatedUserCount++
        }
        finally {
            $PlainPassword = $null
            $SecurePassword = $null
        }
    }
    else {
        $ExistingControlledUserCount++
    }
}

$UserByEmployeeID = @{}

foreach ($User in @(Get-ADUser -Filter 'EmployeeID -like "IAM*"' -Properties EmployeeID, Manager, MemberOf, Enabled)) {
    if ($UserByEmployeeID.ContainsKey($User.EmployeeID)) {
        throw "Duplicate controlled EmployeeID detected: $($User.EmployeeID)."
    }

    $UserByEmployeeID[$User.EmployeeID] = $User
}

foreach ($Record in $Records) {
    $User = $UserByEmployeeID[$Record.EmployeeID]

    if ($null -eq $User) {
        throw "Controlled identity $($Record.EmployeeID) was not found after staging."
    }

    if (-not [string]::IsNullOrWhiteSpace($Record.ManagerEmployeeID)) {
        $Manager = $UserByEmployeeID[$Record.ManagerEmployeeID]

        if ($null -eq $Manager) {
            throw "Manager $($Record.ManagerEmployeeID) for $($Record.EmployeeID) was not found."
        }

        if ($User.Manager -ne $Manager.DistinguishedName) {
            Set-ADUser -Identity $User -Manager $Manager
            $ManagerAssignmentsMade++
        }
    }
    elseif ($User.Manager) {
        throw "$($Record.EmployeeID) has an unexpected manager; the script will not clear it automatically."
    }

    $CurrentDirectGroups = @(
        $User.MemberOf |
            ForEach-Object { (Get-ADGroup -Identity $_).SamAccountName }
    )

    foreach ($GroupName in @(Get-PlannedGroups -Record $Record)) {
        if ($CurrentDirectGroups -notcontains $GroupName) {
            Add-ADGroupMember -Identity $GroupName -Members $User
            $MembershipsAdded++
        }
    }

    if ($Record.WorkerType -eq 'Contractor') {
        Set-ADAccountExpiration `
            -Identity $User `
            -DateTime ([datetime]$Record.EndDate).Date.AddDays(1)
    }

    $Today = (Get-Date).Date
    $StartDate = ([datetime]$Record.StartDate).Date
    $EndDateEligible = (
        [string]::IsNullOrWhiteSpace($Record.EndDate) -or
        ([datetime]$Record.EndDate).Date -ge $Today
    )
    $Eligible = (
        $Record.LifecycleStatus -eq 'Active' -and
        $StartDate -le $Today -and
        $EndDateEligible
    )

    if ($Eligible) {
        if (-not $User.Enabled) {
            Enable-ADAccount -Identity $User
            $AccountsEnabledThisRun++
        }

        Set-ADUser `
            -Identity $User `
            -Description "IAM Project 1 | $($Record.WorkerType) | Active"
    }
    else {
        Set-ADUser `
            -Identity $User `
            -Description "IAM Project 1 | $($Record.WorkerType) | Staged"
    }
}

[pscustomobject]@{
    DatasetSHA256                = $ActualHash
    ControlledUserCount         = $Records.Count
    CreatedUserCount            = $CreatedUserCount
    ExistingControlledUserCount = $ExistingControlledUserCount
    ManagerAssignmentsMade      = $ManagerAssignmentsMade
    MembershipsAdded            = $MembershipsAdded
    AccountsEnabledThisRun      = $AccountsEnabledThisRun
    PasswordsExported           = $false
}

Write-Host ''
Write-Host 'PASS: The controlled IAM identity dataset was provisioned without exporting credentials.' -ForegroundColor Green
