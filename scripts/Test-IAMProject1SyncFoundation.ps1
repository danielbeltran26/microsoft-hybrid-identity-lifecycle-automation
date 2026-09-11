<#
.SYNOPSIS
    Validates the IAM Project 1 dedicated synchronization-server foundation.

.DESCRIPTION
    Performs read-only checks on SYNC01 before Microsoft Entra Cloud Sync is
    installed or configured. The script validates the approved operating
    system, memory, storage, static network configuration, Active Directory
    domain relationship, time hierarchy, VMware Tools, .NET Framework and
    required network connectivity.

    Run this script in Windows PowerShell as Administrator on SYNC01 while
    DC01 is powered on and its domain services are available.

.NOTES
    Project: Microsoft Hybrid Identity Lifecycle Automation
    Milestone: 2 - Dedicated synchronization-server foundation
    Safety: Read-only. The script does not repair the machine secure channel,
    change networking, restart services or install software.
#>

[CmdletBinding()]
param(
    [string]$ExpectedComputerName = 'SYNC01',
    [string]$ExpectedDomain = 'corporate.test',
    [string]$ExpectedIPv4Address = '192.168.112.20',
    [int]$ExpectedPrefixLength = 24,
    [string]$ExpectedGateway = '192.168.112.2',
    [string]$ExpectedDNSServer = '192.168.112.10',
    [string]$ExpectedTimeSource = 'DC01.corporate.test',
    [string]$EntraEndpoint = 'login.microsoftonline.com',
    [int]$MinimumMemoryGB = 4,
    [int]$MinimumFreeDiskGB = 30,
    [int]$MaximumAttempts = 24,
    [int]$RetrySeconds = 5
)

$ErrorActionPreference = 'Stop'

$RequiredDomainPorts = [ordered]@{
    DNS      = 53
    Kerberos = 88
    RPC      = 135
    LDAP     = 389
    SMB      = 445
}

$OS = Get-CimInstance Win32_OperatingSystem
$ComputerSystem = Get-CimInstance Win32_ComputerSystem
$Network = Get-NetIPConfiguration -InterfaceAlias 'Ethernet0'
$IPv4Interface = Get-NetIPInterface `
    -InterfaceAlias 'Ethernet0' `
    -AddressFamily IPv4
$VMTools = Get-Service -Name VMTools -ErrorAction SilentlyContinue
$CDrive = Get-Volume -DriveLetter C
$DotNetRelease = (
    Get-ItemProperty `
        'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full'
).Release

$DomainPorts = [ordered]@{}

foreach ($PortName in $RequiredDomainPorts.Keys) {
    $DomainPorts[$PortName] = Test-NetConnection `
        -ComputerName $ExpectedDNSServer `
        -Port $RequiredDomainPorts[$PortName] `
        -InformationLevel Quiet
}

$EntraHTTPSReachable = Test-NetConnection `
    -ComputerName $EntraEndpoint `
    -Port 443 `
    -InformationLevel Quiet

$DomainDNSResolved = $false
$NetworkCategory = $null
$SecureChannel = $false
$TimeSource = $null
$TrustVerification = $null

for ($Attempt = 1; $Attempt -le $MaximumAttempts; $Attempt++) {
    $DomainDNSResolved = $null -ne (
        Resolve-DnsName `
            -Name $ExpectedTimeSource `
            -Server $ExpectedDNSServer `
            -ErrorAction SilentlyContinue
    )

    $NetworkCategory = (
        Get-NetConnectionProfile -InterfaceAlias 'Ethernet0'
    ).NetworkCategory

    $SecureChannel = Test-ComputerSecureChannel
    $TimeSource = (w32tm /query /source).Trim()
    $TrustVerification = (
        nltest "/sc_verify:$ExpectedDomain" 2>&1
    ) -join ' | '

    if (
        $DomainDNSResolved -and
        $NetworkCategory -eq 'DomainAuthenticated' -and
        $SecureChannel -and
        $TimeSource -eq $ExpectedTimeSource -and
        $TrustVerification -match 'NERR_Success'
    ) {
        break
    }

    if ($Attempt -lt $MaximumAttempts) {
        Start-Sleep -Seconds $RetrySeconds
    }
}

$MemoryGB = [math]::Round(
    $ComputerSystem.TotalPhysicalMemory / 1GB,
    2
)
$CDriveFreeGB = [math]::Round(
    $CDrive.SizeRemaining / 1GB,
    2
)

$Result = [pscustomobject]@{
    ComputerName          = $env:COMPUTERNAME
    WindowsEdition        = $OS.Caption
    OSBuild               = $OS.BuildNumber
    Domain                = $ComputerSystem.Domain
    PartOfDomain          = $ComputerSystem.PartOfDomain
    NetworkCategory       = $NetworkCategory
    SecureChannel         = $SecureChannel
    TrustVerified         = $TrustVerification -match 'NERR_Success'
    IPv4Address           = $Network.IPv4Address.IPAddress
    PrefixLength          = $Network.IPv4Address.PrefixLength
    DefaultGateway        = $Network.IPv4DefaultGateway.NextHop
    DNSServer             = $Network.DNSServer.ServerAddresses -join ', '
    DHCP                  = $IPv4Interface.Dhcp
    TimeZone              = (Get-TimeZone).Id
    TimeSource            = $TimeSource
    VMwareToolsRunning    = $null -ne $VMTools -and $VMTools.Status -eq 'Running'
    MemoryGB              = $MemoryGB
    CDriveFreeGB          = $CDriveFreeGB
    DotNet48OrLater       = $DotNetRelease -ge 528040
    DomainDNSResolved     = $DomainDNSResolved
    DNSPort53Open         = $DomainPorts.DNS
    KerberosPort88Open    = $DomainPorts.Kerberos
    RPCPort135Open        = $DomainPorts.RPC
    LDAPPort389Open       = $DomainPorts.LDAP
    SMBPort445Open        = $DomainPorts.SMB
    EntraHTTPSReachable   = $EntraHTTPSReachable
}

$Passed = (
    $Result.ComputerName -eq $ExpectedComputerName -and
    $Result.WindowsEdition -like '*Windows Server 2022*' -and
    $Result.Domain -eq $ExpectedDomain -and
    $Result.PartOfDomain -eq $true -and
    $Result.NetworkCategory -eq 'DomainAuthenticated' -and
    $Result.SecureChannel -eq $true -and
    $Result.TrustVerified -eq $true -and
    $Result.IPv4Address -eq $ExpectedIPv4Address -and
    $Result.PrefixLength -eq $ExpectedPrefixLength -and
    $Result.DefaultGateway -eq $ExpectedGateway -and
    $Network.DNSServer.ServerAddresses -contains $ExpectedDNSServer -and
    $Result.DHCP -eq 'Disabled' -and
    $Result.TimeZone -eq 'GMT Standard Time' -and
    $Result.TimeSource -eq $ExpectedTimeSource -and
    $Result.VMwareToolsRunning -eq $true -and
    $Result.MemoryGB -ge $MinimumMemoryGB -and
    $Result.CDriveFreeGB -ge $MinimumFreeDiskGB -and
    $Result.DotNet48OrLater -eq $true -and
    $Result.DomainDNSResolved -eq $true -and
    $Result.DNSPort53Open -eq $true -and
    $Result.KerberosPort88Open -eq $true -and
    $Result.RPCPort135Open -eq $true -and
    $Result.LDAPPort389Open -eq $true -and
    $Result.SMBPort445Open -eq $true -and
    $Result.EntraHTTPSReachable -eq $true
)

$Result

if (-not $Passed) {
    throw 'FAIL: SYNC01 foundation requires investigation before Cloud Sync deployment.'
}

Write-Host ''
Write-Host `
    'PASS: SYNC01 foundation is ready for Microsoft Entra Cloud Sync.' `
    -ForegroundColor Green

