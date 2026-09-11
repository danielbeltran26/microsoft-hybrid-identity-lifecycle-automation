[CmdletBinding()]
param(
    [string]$ExpectedComputerName = "DC01",
    [string]$ExpectedDomainName = "corporate.test",
    [int]$StartupWaitSeconds = 300,
    [int]$PollingIntervalSeconds = 15
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function New-CheckResult {
    param(
        [Parameter(Mandatory)]
        [string]$Check,

        [Parameter(Mandatory)]
        [bool]$Passed,

        [Parameter(Mandatory)]
        [string]$Details
    )

    [PSCustomObject]@{
        Check   = $Check
        Status  = if ($Passed) { "PASS" } else { "FAIL" }
        Details = $Details
    }
}

if ($StartupWaitSeconds -lt 0) {
    throw "StartupWaitSeconds cannot be negative."
}

if ($PollingIntervalSeconds -lt 5) {
    throw "PollingIntervalSeconds must be at least 5 seconds."
}

Write-Host "IAM Project 1 baseline validation" -ForegroundColor Cyan
Write-Host "This script is read-only and must be run on DC01.`n"

Import-Module ActiveDirectory

$Results = [System.Collections.Generic.List[object]]::new()

$ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
$ActualComputerName = $env:COMPUTERNAME
$ActualDomainName = $ComputerSystem.Domain

$Results.Add((New-CheckResult `
    -Check "Computer name" `
    -Passed ($ActualComputerName -ieq $ExpectedComputerName) `
    -Details $ActualComputerName))

$Results.Add((New-CheckResult `
    -Check "Domain membership" `
    -Passed ($ActualDomainName -ieq $ExpectedDomainName) `
    -Details $ActualDomainName))

try {
    $Domain = Get-ADDomain
    $DomainDetails = "DNSRoot={0}; PDCEmulator={1}; DomainMode={2}" -f `
        $Domain.DNSRoot,
        $Domain.PDCEmulator,
        $Domain.DomainMode

    $Results.Add((New-CheckResult `
        -Check "Active Directory domain" `
        -Passed ($Domain.DNSRoot -ieq $ExpectedDomainName) `
        -Details $DomainDetails))
}
catch {
    $Results.Add((New-CheckResult `
        -Check "Active Directory domain" `
        -Passed $false `
        -Details $_.Exception.Message))
}

$RequiredServices = @(
    @{ Name = "NTDS"; Label = "Active Directory Domain Services" },
    @{ Name = "DNS"; Label = "Domain Name System Server" },
    @{ Name = "ADWS"; Label = "Active Directory Web Services" },
    @{ Name = "Netlogon"; Label = "Netlogon" },
    @{ Name = "himds"; Label = "Azure Hybrid Instance Metadata Service" },
    @{ Name = "GCArcService"; Label = "Guest Configuration Arc Service" },
    @{ Name = "ExtensionService"; Label = "Guest Configuration Extension Service" }
)

$Deadline = (Get-Date).AddSeconds($StartupWaitSeconds)

do {
    $ServiceStates = @(
        foreach ($RequiredService in $RequiredServices) {
            Get-Service `
                -Name $RequiredService.Name `
                -ErrorAction SilentlyContinue
        }
    )

    $MonitorProcess = Get-Process `
        -Name "MonAgentCore" `
        -ErrorAction SilentlyContinue

    $RunningServiceCount = @(
        $ServiceStates |
        Where-Object { $_.Status -eq "Running" }
    ).Count

    $StartupComponentsReady = (
        $RunningServiceCount -eq $RequiredServices.Count -and
        $null -ne $MonitorProcess
    )

    if (-not $StartupComponentsReady -and (Get-Date) -lt $Deadline) {
        Start-Sleep -Seconds $PollingIntervalSeconds
    }
}
until ($StartupComponentsReady -or (Get-Date) -ge $Deadline)

foreach ($RequiredService in $RequiredServices) {
    $Service = Get-Service `
        -Name $RequiredService.Name `
        -ErrorAction SilentlyContinue

    if ($null -eq $Service) {
        $Results.Add((New-CheckResult `
            -Check $RequiredService.Label `
            -Passed $false `
            -Details "Service not found"))
        continue
    }

    $ServicePassed = (
        $Service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running -and
        $Service.StartType -eq [System.ServiceProcess.ServiceStartMode]::Automatic
    )

    $ServiceDetails = "Name={0}; Status={1}; StartType={2}" -f `
        $Service.Name,
        $Service.Status,
        $Service.StartType

    $Results.Add((New-CheckResult `
        -Check $RequiredService.Label `
        -Passed $ServicePassed `
        -Details $ServiceDetails))
}

$MonitorProcess = Get-Process `
    -Name "MonAgentCore" `
    -ErrorAction SilentlyContinue

$Results.Add((New-CheckResult `
    -Check "Azure Monitor Agent process" `
    -Passed ($null -ne $MonitorProcess) `
    -Details $(if ($MonitorProcess) {
        "MonAgentCore.exe is running; PID={0}" -f $MonitorProcess.Id
    }
    else {
        "MonAgentCore.exe was not running after the bounded startup wait"
    })))

$AllEmployeesGroup = Get-ADGroup `
    -LDAPFilter "(sAMAccountName=GG_All_Employees)" |
    Select-Object -First 1

if ($null -eq $AllEmployeesGroup) {
    $Results.Add((New-CheckResult `
        -Check "Preserved permanent employees" `
        -Passed $false `
        -Details "GG_All_Employees was not found"))
}
else {
    $PermanentEmployeeCount = @(
        Get-ADGroupMember `
            -Identity $AllEmployeesGroup `
            -ErrorAction Stop
    ).Count

    $Results.Add((New-CheckResult `
        -Check "Preserved permanent employees" `
        -Passed ($PermanentEmployeeCount -eq 50) `
        -Details "GG_All_Employees direct members=$PermanentEmployeeCount; Expected=50"))
}

$IDTRUsers = @(
    foreach ($Number in 1..5) {
        $Username = "idtr-user{0:d2}" -f $Number

        Get-ADUser `
            -LDAPFilter "(sAMAccountName=$Username)" `
            -Properties Enabled
    }
)

$IDTRDisabledCount = @(
    $IDTRUsers |
    Where-Object { $_.Enabled -eq $false }
).Count

$Results.Add((New-CheckResult `
    -Check "Project 2 disposable identities" `
    -Passed ($IDTRUsers.Count -eq 5 -and $IDTRDisabledCount -eq 5) `
    -Details "Found=$($IDTRUsers.Count); Disabled=$IDTRDisabledCount; Expected=5 disabled"))

$HighValueGroup = Get-ADGroup `
    -LDAPFilter "(sAMAccountName=IDTR-HighValue-Lab)" |
    Select-Object -First 1

if ($null -eq $HighValueGroup) {
    $Results.Add((New-CheckResult `
        -Check "Project 2 high-value group" `
        -Passed $false `
        -Details "IDTR-HighValue-Lab was not found"))
}
else {
    $HighValueMemberCount = @(
        Get-ADGroupMember `
            -Identity $HighValueGroup `
            -ErrorAction Stop
    ).Count

    $Results.Add((New-CheckResult `
        -Check "Project 2 high-value group" `
        -Passed ($HighValueMemberCount -eq 0) `
        -Details "Direct members=$HighValueMemberCount; Expected=0"))
}

$IAMLabOUs = @(
    Get-ADOrganizationalUnit `
        -LDAPFilter "(ou=IAM-Lab)" `
        -ErrorAction Stop
)

$Results.Add((New-CheckResult `
    -Check "Clean IAM organisational-unit scope" `
    -Passed ($IAMLabOUs.Count -eq 0) `
    -Details "IAM-Lab OUs found=$($IAMLabOUs.Count); Expected=0 before deployment"))

$SYNC01Computers = @(
    Get-ADComputer `
        -LDAPFilter "(sAMAccountName=SYNC01$)" `
        -ErrorAction Stop
)

$Results.Add((New-CheckResult `
    -Check "Clean synchronization-server scope" `
    -Passed ($SYNC01Computers.Count -eq 0) `
    -Details "SYNC01 computer objects found=$($SYNC01Computers.Count); Expected=0 before deployment"))

$Results | Format-Table -AutoSize -Wrap

$FailedChecks = @(
    $Results |
    Where-Object { $_.Status -eq "FAIL" }
)

if ($FailedChecks.Count -eq 0) {
    Write-Host "`nOverall result: PASS" -ForegroundColor Green
    Write-Host "Existing SOC state is healthy and the IAM scope is clean." -ForegroundColor Green
    exit 0
}

Write-Host "`nOverall result: FAIL ($($FailedChecks.Count) failed check(s))" -ForegroundColor Red
Write-Host "Do not begin IAM deployment until every failed check is resolved." -ForegroundColor Red
exit 1
