<#
.SYNOPSIS
    Performs read-only validation of IAM Project 1 Milestone 6.

.DESCRIPTION
    Validates the controlled, mover and leaver datasets; all published
    Milestone 6 audits and recovery manifests; the corrected containment and
    recovery scripts; effective leaver state; directory structure; services;
    Azure Monitor Agent; SYNC01 placement; and preservation of the earlier SOC
    and IDTR environments. No configuration or file is changed.
#>

[CmdletBinding()]
param(
    [string]$DataFolder = 'C:\IAM-Lab\data',
    [string]$ScriptsFolder = 'C:\IAM-Lab\scripts',
    [string]$ControlledCsvPath =
        'C:\IAM-Lab\data\iam-project1-controlled-users.csv',
    [string]$ExpectedControlledSHA256 =
        '153FCF70CA0B8C1B366767BB0F61AEF7E65EF074AD2FA29726C3AF1A07EC9641',
    [string]$MoverCsvPath =
        'C:\IAM-Lab\data\iam-project1-mover-requests.csv',
    [string]$ExpectedMoverSHA256 =
        'AA40213E0C71234FA3F32CF1AF9FA0960EDDA3B231EBEE58D82C5C0A1E23A7C8',
    [ValidateRange(0, 900)]
    [int]$StartupWaitSeconds = 300,
    [ValidateRange(5, 120)]
    [int]$PollingIntervalSeconds = 15
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($env:COMPUTERNAME -ne 'DC01') {
    throw "Run this script on DC01, not $env:COMPUTERNAME."
}

Import-Module ActiveDirectory

$Domain = Get-ADDomain
$Forest = Get-ADForest

if ($Domain.DNSRoot -ne 'corporate.test') {
    throw "Expected corporate.test but detected $($Domain.DNSRoot)."
}

$IAMRoot = 'OU=IAM-Lab,DC=corporate,DC=test'
$UsersRoot = "OU=Users,$IAMRoot"
$GroupsRoot = "OU=Groups,$IAMRoot"
$LeaversOU = "OU=Leavers,$UsersRoot"
$ExpectedSYNC01DN = "CN=SYNC01,OU=Servers,OU=Infrastructure,$IAMRoot"
$RequiredUPNSuffix = 'danielcloudlaboutlook258.onmicrosoft.com'
$RequiredServices = @(
    'NTDS'
    'DNS'
    'ADWS'
    'Netlogon'
    'himds'
    'GCArcService'
    'ExtensionService'
)
$RequiredAzureMonitorProcesses = @(
    'AMAExtHealthMonitor'
    'MonAgentCore'
    'MonAgentHost'
    'MonAgentLauncher'
    'MonAgentManager'
)

$ExpectedData = [ordered]@{
    'iam-project1-leaver-requests.csv' = [pscustomobject]@{
        SHA256 = '96A488E3A26CA23F1AD7B9652DCDBD9D774D8EF4E201E8F677A4E0CCB6D482DE'
        Rows = 3
    }
    'iam-project1-leaver-interrupted-audit.csv' = [pscustomobject]@{
        SHA256 = '959B5696C823D9268D9BA660D846F05BB56290F31A46C8D467CF3974ED2CCB8C'
        Rows = 13
    }
    'iam-project1-leaver-recovery-manifest.csv' = [pscustomobject]@{
        SHA256 = '96433B774255A7982D33917E38830B06F3F2D32AA62EC553330C10E843941880'
        Rows = 3
    }
    'iam-project1-leaver-resumed-audit.csv' = [pscustomobject]@{
        SHA256 = '52469F2D0024A6071F0C85B57677C3E644032BC2E5A3FCB77DD8DD12EEF877AB'
        Rows = 23
    }
    'iam-project1-leaver-idempotent-replay-audit.csv' = [pscustomobject]@{
        SHA256 = '411BDD5A31222722918AF5B9C07F881B9A96D085ADDDA79082D7B8F88A1E0BBD'
        Rows = 5
    }
    'iam-project1-leaver-governed-recovery-audit.csv' = [pscustomobject]@{
        SHA256 = '84ADD11D93C6F99CCCE6E43119ABE7EEF080D2369A2BCBCF61E096E41BCEFE52'
        Rows = 11
    }
    'iam-project1-leaver-recontainment-audit.csv' = [pscustomobject]@{
        SHA256 = '623945A0316794ECBBB9E5D5D0B6F0B5CC9D222FB60DE3806831F3E823934AEE'
        Rows = 14
    }
    'iam-project1-leaver-recontainment-recovery-manifest.csv' = [pscustomobject]@{
        SHA256 = 'B86606AFD280F570C9CDC73C6C0006C223B2AF80E321C611C55AC52656F18E51'
        Rows = 1
    }
}

$ExpectedScripts = [ordered]@{
    'Invoke-IAMProject1LeaverContainment.ps1' =
        '98D53236D024D89D58B07C239624F6321E5474F3A6171D8B1A2EAB78CE46FE6F'
    'Restore-IAMProject1Leaver.ps1' =
        '33359075DD0E5A1CB5DD433BEC1B78372B77496B800B792129DD8EA2915C26D9'
}

$LeaverRequestColumns = @(
    'RequestID'
    'RequestType'
    'EmployeeID'
    'DisplayName'
    'SamAccountName'
    'UserPrincipalName'
    'EffectiveDate'
    'CurrentDepartment'
    'CurrentJobTitle'
    'CurrentWorkerType'
    'CurrentManagerEmployeeID'
    'CurrentOU'
    'CurrentGroups'
    'CurrentAccountExpirationDate'
    'TargetOU'
    'DisableAccount'
    'RemoveDirectIAMGroups'
    'AccessRemovalMode'
    'PreserveIdentityAttributes'
    'PreserveManagerReference'
    'AccountDeletionApproved'
    'RecoveryValidationRequired'
    'RecoveryWindowDays'
    'CurrentLifecycleStatus'
    'TargetLifecycleStatus'
    'ApprovalStatus'
    'RequestedBy'
    'ApprovedBy'
    'ApprovalDate'
    'BusinessJustification'
)
$AuditColumns = @(
    'TimestampUtc'
    'CorrelationID'
    'RequestID'
    'EmployeeID'
    'SamAccountName'
    'Stage'
    'Action'
    'Target'
    'Result'
    'Details'
)
$RecoveryAuditColumns = @(
    'TimestampUtc'
    'CorrelationID'
    'RecoveryApprovalID'
    'RequestID'
    'EmployeeID'
    'SamAccountName'
    'Stage'
    'Action'
    'Target'
    'Result'
    'Details'
)
$RecoveryManifestColumns = @(
    'CorrelationID'
    'RequestID'
    'EmployeeID'
    'SamAccountName'
    'OriginalDistinguishedName'
    'OriginalOU'
    'OriginalEnabled'
    'OriginalDescription'
    'OriginalManager'
    'OriginalGroups'
    'OriginalAccountExpirationDate'
    'RecoveryWindowDays'
    'CapturedUtc'
)
$ExpectedColumns = [ordered]@{
    'iam-project1-leaver-requests.csv' = $LeaverRequestColumns
    'iam-project1-leaver-interrupted-audit.csv' = $AuditColumns
    'iam-project1-leaver-recovery-manifest.csv' = $RecoveryManifestColumns
    'iam-project1-leaver-resumed-audit.csv' = $AuditColumns
    'iam-project1-leaver-idempotent-replay-audit.csv' = $AuditColumns
    'iam-project1-leaver-governed-recovery-audit.csv' = $RecoveryAuditColumns
    'iam-project1-leaver-recontainment-audit.csv' = $AuditColumns
    'iam-project1-leaver-recontainment-recovery-manifest.csv' =
        $RecoveryManifestColumns
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

function Get-ParentDistinguishedName {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$DistinguishedName)

    return $DistinguishedName.Substring(
        $DistinguishedName.IndexOf(',') + 1
    )
}

$RequiredFiles = New-Object 'System.Collections.Generic.List[string]'
$RequiredFiles.Add($ControlledCsvPath)
$RequiredFiles.Add($MoverCsvPath)

foreach ($Name in $ExpectedData.Keys) {
    $RequiredFiles.Add((Join-Path $DataFolder $Name))
}

foreach ($Name in $ExpectedScripts.Keys) {
    $RequiredFiles.Add((Join-Path $ScriptsFolder $Name))
}

foreach ($RequiredFile in $RequiredFiles) {
    if (-not (Test-Path -LiteralPath $RequiredFile -PathType Leaf)) {
        throw "Required Milestone 6 file not found at $RequiredFile."
    }
}

$HashMismatchCount = 0
$DataRowCountFailureCount = 0
$MissingColumnCount = 0
$DataFiles = [ordered]@{}

foreach ($Name in $ExpectedData.Keys) {
    $Path = Join-Path $DataFolder $Name
    $ActualHash = (
        Get-FileHash -LiteralPath $Path -Algorithm SHA256
    ).Hash
    $Rows = @(Import-Csv -LiteralPath $Path)

    if ($ActualHash -ne $ExpectedData[$Name].SHA256) {
        $HashMismatchCount++
    }

    if ($Rows.Count -ne $ExpectedData[$Name].Rows) {
        $DataRowCountFailureCount++
    }

    $ActualColumns = @(
        $Rows[0].PSObject.Properties.Name
    )
    $MissingColumnCount += @(
        $ExpectedColumns[$Name] |
            Where-Object { $_ -notin $ActualColumns }
    ).Count

    $DataFiles[$Name] = $Rows
}

$ControlledDatasetHash = (
    Get-FileHash -LiteralPath $ControlledCsvPath -Algorithm SHA256
).Hash
$MoverDatasetHash = (
    Get-FileHash -LiteralPath $MoverCsvPath -Algorithm SHA256
).Hash
$LeaverDatasetHash = (
    Get-FileHash `
        -LiteralPath (Join-Path $DataFolder 'iam-project1-leaver-requests.csv') `
        -Algorithm SHA256
).Hash

if ($ControlledDatasetHash -ne $ExpectedControlledSHA256) {
    $HashMismatchCount++
}

if ($MoverDatasetHash -ne $ExpectedMoverSHA256) {
    $HashMismatchCount++
}

$PowerShellParseFailures = 0

foreach ($Name in $ExpectedScripts.Keys) {
    $Path = Join-Path $ScriptsFolder $Name
    $ActualHash = (
        Get-FileHash -LiteralPath $Path -Algorithm SHA256
    ).Hash

    if ($ActualHash -ne $ExpectedScripts[$Name]) {
        $HashMismatchCount++
    }

    $Tokens = $null
    $ParseErrors = $null

    [System.Management.Automation.Language.Parser]::ParseFile(
        $Path,
        [ref]$Tokens,
        [ref]$ParseErrors
    ) | Out-Null

    $PowerShellParseFailures += @($ParseErrors).Count
}

$SecretColumnCount = 0
$SensitiveValuePatternCount = 0

foreach ($Name in $ExpectedData.Keys) {
    $Rows = @($DataFiles[$Name])
    $Path = Join-Path $DataFolder $Name

    if ($Rows.Count -gt 0) {
        $SecretColumnCount += @(
            @($Rows[0].PSObject.Properties.Name) |
                Where-Object {
                    $_ -match '(?i)password|secret|token|credential|securestring'
                }
        ).Count
    }

    $RawContent = Get-Content -LiteralPath $Path -Raw
    $SensitiveValuePatternCount += @(
        [regex]::Matches(
            $RawContent,
            '(?i)(password|secret|token|credential|securestring)\s*[:=]'
        )
    ).Count
}

$LeaverRequests = @(
    $DataFiles['iam-project1-leaver-requests.csv']
)
$InterruptedAudit = @(
    $DataFiles['iam-project1-leaver-interrupted-audit.csv']
)
$RecoveryManifest = @(
    $DataFiles['iam-project1-leaver-recovery-manifest.csv']
)
$ResumedAudit = @(
    $DataFiles['iam-project1-leaver-resumed-audit.csv']
)
$ReplayAudit = @(
    $DataFiles['iam-project1-leaver-idempotent-replay-audit.csv']
)
$GovernedRecoveryAudit = @(
    $DataFiles['iam-project1-leaver-governed-recovery-audit.csv']
)
$RecontainAudit = @(
    $DataFiles['iam-project1-leaver-recontainment-audit.csv']
)
$RecontainRecovery = @(
    $DataFiles['iam-project1-leaver-recontainment-recovery-manifest.csv']
)

$AuditSets = @(
    [pscustomobject]@{
        Events = $InterruptedAudit
        CorrelationID = 'M06-LEAVER-20260904-235742'
    }
    [pscustomobject]@{
        Events = $ResumedAudit
        CorrelationID = 'M06-LEAVER-20260904-235956'
    }
    [pscustomobject]@{
        Events = $ReplayAudit
        CorrelationID = 'M06-LEAVER-20260905-001302'
    }
    [pscustomobject]@{
        Events = $GovernedRecoveryAudit
        CorrelationID = 'M06-RECOVERY-20260905-002158'
    }
    [pscustomobject]@{
        Events = $RecontainAudit
        CorrelationID = 'M06-LEAVER-20260905-002356'
    }
)

$AuditCorrelationMismatchCount = 0
$TimestampParseFailureCount = 0
$TimestampOrderFailureCount = 0

foreach ($AuditSet in $AuditSets) {
    $Events = @($AuditSet.Events)
    $AuditCorrelationMismatchCount += @(
        $Events |
            Where-Object {
                $_.CorrelationID -ne $AuditSet.CorrelationID
            }
    ).Count

    $ParsedTimestamps = New-Object 'System.Collections.Generic.List[System.DateTimeOffset]'

    foreach ($Event in $Events) {
        try {
            $ParsedTimestamps.Add(
                [datetimeoffset]::Parse($Event.TimestampUtc)
            )
        }
        catch {
            $TimestampParseFailureCount++
        }
    }

    for ($Index = 1; $Index -lt $ParsedTimestamps.Count; $Index++) {
        if ($ParsedTimestamps[$Index] -lt $ParsedTimestamps[$Index - 1]) {
            $TimestampOrderFailureCount++
        }
    }
}

$ContainmentTrail = @($InterruptedAudit + $ResumedAudit)
$InterruptedFailureCount = @(
    $InterruptedAudit |
        Where-Object { $_.Result -eq 'Failed' }
).Count
$SubsequentFailureCount = @(
    @($ResumedAudit + $ReplayAudit + $GovernedRecoveryAudit + $RecontainAudit) |
        Where-Object { $_.Result -eq 'Failed' }
).Count
$RecoveryCaptureCount = @(
    $ContainmentTrail |
        Where-Object { $_.Action -eq 'CaptureRecoveryState' }
).Count
$DisableAccountCount = @(
    $ContainmentTrail |
        Where-Object { $_.Action -eq 'DisableAccount' }
).Count
$MembershipRemovalCount = @(
    $ContainmentTrail |
        Where-Object { $_.Action -eq 'RemoveMembership' }
).Count
$LeaverOUMoveCount = @(
    $ContainmentTrail |
        Where-Object { $_.Action -eq 'MoveToLeaversOU' }
).Count
$DescriptionUpdateCount = @(
    $ContainmentTrail |
        Where-Object { $_.Action -eq 'UpdateLifecycleDescription' }
).Count
$FinalStateCoverageCount = @(
    $ResumedAudit |
        Where-Object {
            $_.Action -in @(
                'ValidateLeaverState'
                'LeaverStateNoChange'
            )
        }
).Count
$ReplayNoChangeCount = @(
    $ReplayAudit |
        Where-Object {
            $_.Action -eq 'LeaverStateNoChange' -and
            $_.Result -eq 'NoChange'
        }
).Count
$ReplayModificationCount = @(
    $ReplayAudit |
        Where-Object {
            $_.Action -in @(
                'CaptureRecoveryState'
                'DisableAccount'
                'RemoveMembership'
                'MoveToLeaversOU'
                'UpdateLifecycleDescription'
                'ValidateLeaverState'
            )
        }
).Count

$RecoveredInterruption = (
    $InterruptedFailureCount -eq 1 -and
    $RecoveryManifest.Count -eq 3 -and
    $RecoveryCaptureCount -eq 5 -and
    $DisableAccountCount -eq 3 -and
    $MembershipRemovalCount -eq 15 -and
    $LeaverOUMoveCount -eq 3 -and
    $DescriptionUpdateCount -eq 3 -and
    $FinalStateCoverageCount -eq 3 -and
    $SubsequentFailureCount -eq 0
)

$GovernedRecoveryValid = (
    $GovernedRecoveryAudit.Count -eq 11 -and
    @(
        $GovernedRecoveryAudit |
            Where-Object { $_.Action -eq 'RestoreMembership' }
    ).Count -eq 5 -and
    @(
        $GovernedRecoveryAudit |
            Where-Object { $_.Action -eq 'EnableRecoveredAccount' }
    ).Count -eq 1 -and
    @(
        $GovernedRecoveryAudit |
            Where-Object { $_.Action -eq 'ValidateRecoveredState' }
    ).Count -eq 1
)

$RecontainmentValid = (
    $RecontainAudit.Count -eq 14 -and
    $RecontainRecovery.Count -eq 1 -and
    @(
        $RecontainAudit |
            Where-Object { $_.Action -eq 'DisableAccount' }
    ).Count -eq 1 -and
    @(
        $RecontainAudit |
            Where-Object { $_.Action -eq 'RemoveMembership' }
    ).Count -eq 5 -and
    @(
        $RecontainAudit |
            Where-Object { $_.Action -eq 'LeaverStateNoChange' }
    ).Count -eq 2
)

$TotalM6AuditEventCount = (
    $InterruptedAudit.Count +
    $ResumedAudit.Count +
    $ReplayAudit.Count +
    $GovernedRecoveryAudit.Count +
    $RecontainAudit.Count
)

$AuditTrailValid = (
    $RecoveredInterruption -and
    $GovernedRecoveryValid -and
    $RecontainmentValid -and
    $ReplayNoChangeCount -eq 3 -and
    $ReplayModificationCount -eq 0 -and
    $TotalM6AuditEventCount -eq 66 -and
    $AuditCorrelationMismatchCount -eq 0 -and
    $TimestampParseFailureCount -eq 0 -and
    $TimestampOrderFailureCount -eq 0
)

$Deadline = (Get-Date).AddSeconds($StartupWaitSeconds)

do {
    $RunningServices = @(
        foreach ($ServiceName in $RequiredServices) {
            Get-Service -Name $ServiceName -ErrorAction SilentlyContinue |
                Where-Object { $_.Status -eq 'Running' }
        }
    )
    $AzureMonitorProcesses = @(
        Get-Process `
            -Name $RequiredAzureMonitorProcesses `
            -ErrorAction SilentlyContinue
    )
    $AzureMonitorAgentRunning = $null -ne (
        $AzureMonitorProcesses |
            Where-Object { $_.ProcessName -eq 'MonAgentCore' } |
            Select-Object -First 1
    )
    $StartupReady = (
        $RunningServices.Count -eq $RequiredServices.Count -and
        $AzureMonitorAgentRunning
    )

    if (-not $StartupReady -and (Get-Date) -lt $Deadline) {
        Start-Sleep -Seconds $PollingIntervalSeconds
    }
}
until ($StartupReady -or (Get-Date) -ge $Deadline)

$IAMOUs = @(
    Get-ADOrganizationalUnit `
        -SearchBase $IAMRoot `
        -SearchScope Subtree `
        -Filter * `
        -Properties ProtectedFromAccidentalDeletion
)
$ProtectedOUCount = @(
    $IAMOUs |
        Where-Object { $_.ProtectedFromAccidentalDeletion }
).Count
$IAMGroups = @(
    Get-ADGroup `
        -SearchBase $GroupsRoot `
        -SearchScope Subtree `
        -Filter * `
        -Properties GroupCategory, GroupScope
)
$GroupValidationFailureCount = @(
    $IAMGroups |
        Where-Object {
            $_.GroupCategory -ne 'Security' -or
            $_.GroupScope -ne 'Global'
        }
).Count

$OriginalRecords = @(Import-Csv -LiteralPath $ControlledCsvPath)
$OriginalIdentityPresenceFailures = 0
$OriginalEnabledUserCount = 0
$OriginalDirectMembershipCount = 0

foreach ($Record in $OriginalRecords) {
    $EscapedEmployeeID = $Record.EmployeeID.Replace("'", "''")
    $Users = @(
        Get-ADUser `
            -Filter "EmployeeID -eq '$EscapedEmployeeID'" `
            -Properties EmployeeID, Enabled, MemberOf
    )

    if ($Users.Count -ne 1) {
        $OriginalIdentityPresenceFailures++
        continue
    }

    if ($Users[0].Enabled) {
        $OriginalEnabledUserCount++
    }

    $OriginalDirectMembershipCount += @(
        $Users[0].MemberOf |
            Where-Object { $_ -like 'CN=GG_IAM_*' }
    ).Count
}

$LeaverValidationFailureCount = 0
$LeaverManagerCount = 0
$LeaverDirectMembershipCount = 0

foreach ($Request in $LeaverRequests) {
    $EscapedEmployeeID = $Request.EmployeeID.Replace("'", "''")
    $Users = @(
        Get-ADUser `
            -Filter "EmployeeID -eq '$EscapedEmployeeID'" `
            -Properties EmployeeID, DisplayName, SamAccountName,
                UserPrincipalName, Enabled, employeeType, Department, Title,
                Manager, MemberOf, AccountExpirationDate, Description
    )

    if ($Users.Count -ne 1) {
        $LeaverValidationFailureCount++
        continue
    }

    $User = $Users[0]
    $ActualGroups = @(Get-DirectIAMGroups -User $User)
    $ParentOU = Get-ParentDistinguishedName `
        -DistinguishedName $User.DistinguishedName
    $Manager = if ($null -ne $User.Manager) {
        Get-ADUser -Identity $User.Manager -Properties EmployeeID
    }
    else {
        $null
    }
    $ExpectedDescription = (
        'IAM Project 1 | Leaver | {0} | Disabled | {1}' -f
        $Request.CurrentWorkerType,
        $Request.RequestID
    )
    $ExpirationValid = if (
        [string]::IsNullOrWhiteSpace(
            $Request.CurrentAccountExpirationDate
        )
    ) {
        $null -eq $User.AccountExpirationDate
    }
    else {
        $null -ne $User.AccountExpirationDate -and
        $User.AccountExpirationDate.Date -eq
            ([datetime]$Request.CurrentAccountExpirationDate).Date
    }
    $IdentityValid = (
        $Request.ApprovalStatus -eq 'Approved' -and
        $Request.AccountDeletionApproved -eq 'False' -and
        $User.EmployeeID -eq $Request.EmployeeID -and
        $User.DisplayName -eq $Request.DisplayName -and
        $User.SamAccountName -eq $Request.SamAccountName -and
        $User.UserPrincipalName -eq $Request.UserPrincipalName -and
        -not $User.Enabled -and
        $User.employeeType -eq $Request.CurrentWorkerType -and
        $User.Department -eq $Request.CurrentDepartment -and
        $User.Title -eq $Request.CurrentJobTitle -and
        $null -ne $Manager -and
        $Manager.EmployeeID -eq $Request.CurrentManagerEmployeeID -and
        $ParentOU -eq $Request.TargetOU -and
        $ParentOU -eq $LeaversOU -and
        $ActualGroups.Count -eq 0 -and
        $User.Description -eq $ExpectedDescription -and
        $ExpirationValid
    )

    if (-not $IdentityValid) {
        $LeaverValidationFailureCount++
    }

    if ($null -ne $Manager) {
        $LeaverManagerCount++
    }

    $LeaverDirectMembershipCount += $ActualGroups.Count
}

$ControlledUsers = @(
    Get-ADUser `
        -SearchBase $UsersRoot `
        -SearchScope Subtree `
        -LDAPFilter '(objectCategory=person)' `
        -Properties Enabled, employeeType, Manager, MemberOf
)
$EnabledUsers = @(
    $ControlledUsers | Where-Object { $_.Enabled }
)
$Employees = @(
    $ControlledUsers | Where-Object { $_.employeeType -eq 'Employee' }
)
$Contractors = @(
    $ControlledUsers | Where-Object { $_.employeeType -eq 'Contractor' }
)
$ManagerAssignedUsers = @(
    $ControlledUsers | Where-Object { $null -ne $_.Manager }
)
$TotalDirectMemberships = (
    $ControlledUsers |
        ForEach-Object {
            @(
                $_.MemberOf |
                    Where-Object { $_ -like 'CN=GG_IAM_*' }
            ).Count
        } |
        Measure-Object -Sum
).Sum
$LeaverUsers = @(
    Get-ADUser `
        -SearchBase $LeaversOU `
        -SearchScope OneLevel `
        -Filter * `
        -Properties Enabled, MemberOf
)
$EnabledLeaverCount = @(
    $LeaverUsers | Where-Object { $_.Enabled }
).Count
$LeaverMembershipCount = (
    $LeaverUsers |
        ForEach-Object {
            @(
                $_.MemberOf |
                    Where-Object { $_ -like 'CN=GG_IAM_*' }
            ).Count
        } |
        Measure-Object -Sum
).Sum

$Mason = Get-ADUser -Identity 'mason.cole' -Properties AccountExpirationDate
$MasonExpirationCleared = $null -eq $Mason.AccountExpirationDate
$SYNC01 = Get-ADComputer -Identity 'SYNC01' -Properties Enabled
$SYNC01PlacementValid = (
    $SYNC01.DistinguishedName -eq $ExpectedSYNC01DN -and
    $SYNC01.Enabled
)
$UPNSuffixPresent = $RequiredUPNSuffix -in $Forest.UPNSuffixes
$PermanentEmployeeCount = @(
    Get-ADGroupMember -Identity 'GG_All_Employees' -Recursive
).Count
$IDTRUsers = @(
    Get-ADUser `
        -Filter "SamAccountName -like 'idtr-user*'" `
        -Properties Enabled
)
$IDTRDisabledCount = @(
    $IDTRUsers | Where-Object { -not $_.Enabled }
).Count
$HighValueGroupMembers = @(
    Get-ADGroupMember -Identity 'IDTR-HighValue-Lab'
).Count

$Passed = (
    $RequiredFiles.Count -eq 12 -and
    $HashMismatchCount -eq 0 -and
    $DataRowCountFailureCount -eq 0 -and
    $MissingColumnCount -eq 0 -and
    $LeaverRequests.Count -eq 3 -and
    $SecretColumnCount -eq 0 -and
    $SensitiveValuePatternCount -eq 0 -and
    $PowerShellParseFailures -eq 0 -and
    $AuditTrailValid -and
    $IAMOUs.Count -eq 16 -and
    $ProtectedOUCount -eq 16 -and
    $IAMGroups.Count -eq 15 -and
    $GroupValidationFailureCount -eq 0 -and
    $OriginalRecords.Count -eq 30 -and
    $OriginalIdentityPresenceFailures -eq 0 -and
    $OriginalEnabledUserCount -eq 30 -and
    $OriginalDirectMembershipCount -eq 140 -and
    $LeaverValidationFailureCount -eq 0 -and
    $LeaverManagerCount -eq 3 -and
    $LeaverDirectMembershipCount -eq 0 -and
    $ControlledUsers.Count -eq 33 -and
    $EnabledUsers.Count -eq 30 -and
    $Employees.Count -eq 28 -and
    $Contractors.Count -eq 5 -and
    $ManagerAssignedUsers.Count -eq 27 -and
    $TotalDirectMemberships -eq 140 -and
    $LeaverUsers.Count -eq 3 -and
    $EnabledLeaverCount -eq 0 -and
    $LeaverMembershipCount -eq 0 -and
    $MasonExpirationCleared -and
    $SYNC01PlacementValid -and
    $RunningServices.Count -eq 7 -and
    $AzureMonitorProcesses.Count -ge 5 -and
    $AzureMonitorAgentRunning -and
    $UPNSuffixPresent -and
    $PermanentEmployeeCount -eq 50 -and
    $IDTRUsers.Count -eq 5 -and
    $IDTRDisabledCount -eq 5 -and
    $HighValueGroupMembers -eq 0
)

[pscustomobject]@{
    ComputerName                     = $env:COMPUTERNAME
    DomainName                       = $Domain.DNSRoot
    RequiredFileCount                = $RequiredFiles.Count
    HashMismatchCount                = $HashMismatchCount
    DataRowCountFailureCount         = $DataRowCountFailureCount
    MissingColumnCount               = $MissingColumnCount
    ControlledDatasetHashMatches     = ($ControlledDatasetHash -eq $ExpectedControlledSHA256)
    MoverDatasetHashMatches          = ($MoverDatasetHash -eq $ExpectedMoverSHA256)
    LeaverDatasetHashMatches         = (
        $LeaverDatasetHash -eq $ExpectedData['iam-project1-leaver-requests.csv'].SHA256
    )
    LeaverRequestCount               = $LeaverRequests.Count
    ControlledUserCount              = $ControlledUsers.Count
    EnabledUserCount                 = $EnabledUsers.Count
    EmployeeCount                    = $Employees.Count
    ContractorCount                  = $Contractors.Count
    ManagerAssignedCount             = $ManagerAssignedUsers.Count
    TotalDirectMemberships           = $TotalDirectMemberships
    LeaverValidationFailureCount     = $LeaverValidationFailureCount
    EnabledLeaverCount               = $EnabledLeaverCount
    LeaverDirectMembershipCount      = $LeaverDirectMembershipCount
    RecoveredInterruption            = $RecoveredInterruption
    ReplayNoChangeCount              = $ReplayNoChangeCount
    ReplayModificationCount          = $ReplayModificationCount
    GovernedRecoveryValid            = $GovernedRecoveryValid
    RecontainmentValid               = $RecontainmentValid
    TotalM6AuditEventCount           = $TotalM6AuditEventCount
    AuditCorrelationMismatchCount    = $AuditCorrelationMismatchCount
    TimestampParseFailureCount       = $TimestampParseFailureCount
    TimestampOrderFailureCount       = $TimestampOrderFailureCount
    SubsequentFailureCount           = $SubsequentFailureCount
    SecretColumnCount                = $SecretColumnCount
    SensitiveValuePatternCount       = $SensitiveValuePatternCount
    PowerShellParseFailures          = $PowerShellParseFailures
    ValidatedOUCount                 = $IAMOUs.Count
    ProtectedOUCount                 = $ProtectedOUCount
    IAMGroupCount                    = $IAMGroups.Count
    GroupValidationFailureCount      = $GroupValidationFailureCount
    SYNC01PlacementValid             = $SYNC01PlacementValid
    RunningServiceCount              = $RunningServices.Count
    AzureMonitorProcessCount         = $AzureMonitorProcesses.Count
    AzureMonitorAgentRunning         = $AzureMonitorAgentRunning
    UPNSuffixPresent                 = $UPNSuffixPresent
    PermanentEmployeeCount           = $PermanentEmployeeCount
    IDTRUserCount                    = $IDTRUsers.Count
    IDTRDisabledCount                = $IDTRDisabledCount
    HighValueGroupMembers            = $HighValueGroupMembers
    ChangesMade                      = $false
} | Format-List

if (-not $Passed) {
    throw 'Milestone 6 validation requires investigation.'
}

Write-Host ''
Write-Host 'PASS: Milestone 6 leaver containment, recovery, audit integrity, and environment preservation are fully validated.' -ForegroundColor Green
