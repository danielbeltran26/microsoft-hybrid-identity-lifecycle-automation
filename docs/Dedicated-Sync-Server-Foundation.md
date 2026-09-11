# Dedicated Synchronization-Server Foundation

## Purpose

Milestone 2 created and validated the dedicated Windows member server that will
host the Microsoft Entra Cloud Sync provisioning agent. The server was built
separately from `DC01` so that the domain-controller and synchronization roles
remain distinct.

No Cloud Sync agent, IAM lifecycle identities or `IAM-Lab` organisational unit
were created during this milestone. The result is a controlled infrastructure
boundary and paired recovery point before hybrid provisioning begins.

## Implemented configuration

| Component | Validated state |
|---|---|
| Virtual machine | `SYNC01` |
| Guest operating system | Microsoft Windows Server 2022 Standard Evaluation with Desktop Experience |
| Virtual processors | 2 |
| Memory | 4 GB |
| Virtual disk | 80 GB SCSI, dynamically allocated |
| VMware network | NAT |
| IPv4 address | `192.168.112.20/24` |
| Default gateway | `192.168.112.2` |
| DNS server | `192.168.112.10` (`DC01`) |
| DHCP | Disabled |
| Domain | `corporate.test` |
| Server role | Domain-joined member server |
| Time zone | `GMT Standard Time` |
| Domain time source | `DC01.corporate.test` |
| VMware Tools | Installed and running |
| Windows Update | Current at milestone validation |
| .NET Framework | 4.8 or later validated |
| Microsoft Entra HTTPS | `login.microsoftonline.com:443` reachable |

`SYNC01` was not configured with an external DNS server. Domain members use
Active Directory DNS so that domain-controller locator records, Kerberos,
LDAP and the machine secure channel resolve correctly. External names are
resolved through the domain DNS service's configured forwarding path.

## Validation performed

The validated foundation confirmed:

- Computer name `SYNC01` and domain membership in `corporate.test`.
- Active Directory machine secure channel returned `True`.
- `nltest /sc_verify:corporate.test` returned `NERR_Success`.
- Active Directory DNS resolved `DC01.corporate.test`.
- Static IPv4, gateway and DNS settings matched the approved design.
- The network profile was `DomainAuthenticated` after the domain controller
  was fully available.
- Windows Time sourced from `DC01.corporate.test` through the domain hierarchy.
- VMware Tools was running.
- At least 4 GB memory, .NET Framework 4.8 or later and more than 30 GB free
  system-disk capacity were available.
- HTTPS connectivity to the Microsoft Entra sign-in endpoint succeeded.
- All seven previously required `DC01` services returned to `Running` after
  bounded startup polling.
- The existing 50 permanent users remained present.
- All five identity-threat-detection users remained disabled and the synthetic
  high-value group remained empty.
- No `IAM-Lab` organisational unit existed before the next milestone.

## Evidence

### Validated server foundation

![SYNC01 foundation validation](../screenshots/m02-01-sync01-foundation-validation.png)

### Powered-off SYNC01 recovery checkpoint

![SYNC01 foundation recovery snapshot](../screenshots/m02-02-sync01-foundation-recovery-snapshot.png)

### Paired DC01 recovery checkpoint

![DC01 paired recovery snapshot](../screenshots/m02-03-dc01-paired-recovery-snapshot.png)

## Recovery checkpoints

| Virtual machine | Checkpoint | Purpose |
|---|---|---|
| `SYNC01` | `IAM-P1-M02-SYNC01-Validated-Foundation` | Restore the updated, domain-joined member-server foundation before Cloud Sync agent installation |
| `DC01` | `IAM-P1-M02-DC01-Post-SYNC01-Domain-Join` | Restore the matching Active Directory state containing the validated `SYNC01` computer account |

The two Milestone 2 checkpoints form a pair. If rollback to this milestone is
required, both should be restored together to avoid a mismatch between the
member server's local machine password and the corresponding Active Directory
computer account.

The Milestone 1 checkpoint remains available as the pre-IAM state. VMware
snapshots are a laboratory rollback mechanism, not a substitute for production
Active Directory system-state backup or enterprise recovery testing.

## Issues discovered and corrected

### VMware clipboard user process

VMware Guest Isolation permitted copy and paste, and VMware Tools was running,
but the guest clipboard remained empty. Starting the interactive VMware Tools
user process restored the feature:

```text
"C:\Program Files\VMware\VMware Tools\vmtoolsd.exe" -n vmusr
```

No credentials or sensitive data were transferred through the shared
clipboard.

### Domain profile and time source after startup

When `SYNC01` started before domain discovery completed, its network category
was `Public` and its time source was `Local CMOS Clock`. DNS, Kerberos, RPC,
LDAP and SMB connectivity to `DC01` were all available, and `nltest` confirmed
the machine trust was healthy. The computer-account password was therefore not
reset.

Restarting `SYNC01` after `DC01` was fully operational restored:

```text
NetworkCategory : DomainAuthenticated
SecureChannel   : True
TimeSource      : DC01.corporate.test
```

This demonstrated why startup sequencing and direct state validation are
necessary. Future laboratory operations start `DC01` first and wait for domain
services before starting `SYNC01`.

## Operational start and stop order

### Start

1. Start `DC01`.
2. Wait for the Windows sign-in screen and domain services to settle.
3. Start `SYNC01`.
4. Validate `DomainAuthenticated`, the machine secure channel and the domain
   time source before running synchronization work.

### Stop

1. Stop synchronization activity and shut down `SYNC01` cleanly.
2. Shut down `DC01` cleanly.
3. Confirm both VMware consoles report `Powered off` before taking a paired
   checkpoint.

## Security boundary

Microsoft identifies the provisioning-agent server as an identity control-plane
asset. `SYNC01` is therefore reserved for Cloud Sync, receives controlled
administrative access and does not host unrelated services. The laboratory
uses one agent because the host cannot support a production high-availability
design; production environments should deploy multiple active agents according
to availability requirements.

## References

- [Prerequisites for Microsoft Entra Cloud Sync](https://learn.microsoft.com/en-us/entra/identity/hybrid/cloud-sync/how-to-prerequisites)
- [Install the Microsoft Entra provisioning agent](https://learn.microsoft.com/en-us/entra/identity/hybrid/cloud-sync/how-to-install)
- [Microsoft Entra Cloud Sync supported topologies](https://learn.microsoft.com/en-us/entra/identity/hybrid/cloud-sync/plan-cloud-sync-topologies)
- [Microsoft Entra Cloud Sync deep dive](https://learn.microsoft.com/en-us/entra/identity/hybrid/cloud-sync/concept-how-it-works)
- [Windows Time Service tools and settings](https://learn.microsoft.com/en-us/windows-server/networking/windows-time-service/windows-time-service-tools-and-settings)
- [How the Windows Time Service works](https://learn.microsoft.com/en-us/windows-server/networking/windows-time-service/how-the-windows-time-service-works)

