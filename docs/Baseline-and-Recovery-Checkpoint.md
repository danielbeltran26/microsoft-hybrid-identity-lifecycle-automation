# Baseline and Recovery Checkpoint

## Purpose

This milestone establishes the trusted starting point for Microsoft Hybrid
Identity Lifecycle Automation. It verifies the existing `corporate.test`
environment, preserves the two completed SOC projects and proves that the new
IAM scope was empty before implementation began.

No IAM organisational units, lifecycle users, security groups or
synchronization-server objects were created during this milestone.

## Environment boundary

| Component | Validated role and state |
|---|---|
| `DC01.corporate.test` | Existing VMware-hosted Windows Server 2022 domain controller |
| Active Directory Domain Services | Authoritative identity source for `corporate.test` |
| Permanent Project 1 identities | 50 direct members of `GG_All_Employees` preserved |
| Project 2 disposable identities | Five accounts present and disabled |
| `IDTR-HighValue-Lab` | Present with zero members |
| Azure Arc | Required Connected Machine services running |
| Azure Monitor Agent | `MonAgentCore.exe` running |
| `IAM-Lab` OU | Absent before IAM implementation |
| `SYNC01` computer object | Absent before synchronization-server deployment |

The future synchronization server will join the existing `corporate.test`
domain as a member server. It will not host another Active Directory forest and
will not be promoted to a domain controller.

## Recovery checkpoint

`DC01` was shut down cleanly before the VMware checkpoint was created.

| Property | Value |
|---|---|
| Checkpoint | `IAM-P1-M01-PreChange-Validated-State` |
| Created | 30 August 2026 |
| VM state | Powered off |
| Purpose | Recovery point before IAM Project 1 changes |

The checkpoint preserves the validated domain, existing identity populations,
empty high-value group, Azure Arc state and Azure Monitor Agent state. It is a
controlled laboratory rollback point, not a replacement for an enterprise
backup and disaster-recovery strategy.

![Validated pre-change VMware recovery checkpoint](../screenshots/m01-01-prechange-recovery-snapshot.png)

## Validation contract

The reusable baseline validator performs only read operations. It checks:

1. The script is running on `DC01` in `corporate.test`.
2. The Active Directory domain resolves to `corporate.test`.
3. Four core directory services are running automatically.
4. Three Azure Connected Machine services are running automatically.
5. The Azure Monitor Agent process is running.
6. `GG_All_Employees` retains exactly 50 direct members.
7. All five `idtr-user01` through `idtr-user05` accounts remain disabled.
8. `IDTR-HighValue-Lab` contains zero members.
9. No `IAM-Lab` organisational unit exists before deployment.
10. No `SYNC01` computer object exists before deployment.

The validation does not create, update, move, disable or remove any directory
object.

## Validated result

| Check | Expected | Result |
|---|---:|---:|
| Required services running | 7 | 7 |
| Permanent employee group members | 50 | 50 |
| Project 2 disposable identities | 5 | 5 |
| Disabled Project 2 identities | 5 | 5 |
| High-value group members | 0 | 0 |
| Azure Monitor Agent running | `True` | `True` |
| `IAM-Lab` OU exists | `False` | `False` |
| `SYNC01` computer exists | `False` | `False` |

The powered-on post-checkpoint validation completed with an overall `PASS`.

![Validated post-snapshot DC01 baseline](../screenshots/m01-02-dc01-post-snapshot-baseline.png)

## Startup-timing correction

The first validations ran shortly after `DC01` started. Active Directory was
already healthy, but Azure Arc and Azure Monitor Agent had not finished their
asynchronous startup. A fixed delay was not reliable enough.

The final validator therefore uses bounded polling:

- Polling interval: 15 seconds by default.
- Maximum startup allowance: 300 seconds by default.
- Immediate continuation when all seven services and `MonAgentCore.exe` are
  ready.
- Failure after the bounded window instead of waiting indefinitely.

This distinguishes an expected startup transition from a persistent service
failure while retaining a deterministic timeout.

## Reusable validation

Run the validator from an elevated Windows PowerShell session on `DC01`:

```powershell
Set-Location 'C:\IAM-Lab\scripts'
.\Test-IAMProject1Baseline.ps1
```

The script returns exit code `0` only when every baseline check passes. A
failed check returns exit code `1` and blocks IAM deployment until the state is
investigated.

## Security decisions

- Existing SOC identities and controls are preserved rather than repurposed.
- The new IAM implementation receives its own explicitly scoped OU hierarchy.
- The synchronization server remains a separate domain-joined member server.
- Absence checks prove that new objects were not inherited from an earlier
  attempt.
- Screenshots exclude passwords, access tokens, tenant IDs, subscription IDs
  and personal email addresses.
- The recovery checkpoint was created only after direct state validation.

## Rollback boundary

If a later IAM change damages the laboratory, stop the affected virtual
machines and assess the change before reverting. Reverting `DC01` can roll back
directory state while synchronized cloud objects may retain newer state.
Therefore, a hybrid rollback must account for both Active Directory and
Microsoft Entra ID rather than treating the VMware checkpoint as an automatic
cross-platform rollback.

## Milestone outcome

Milestone 1 established a recoverable and independently verified foundation:

- The completed SOC environment remains healthy.
- Existing controlled identities remain in their expected safe state.
- The new IAM scope is empty.
- A powered-off recovery checkpoint exists.
- A reusable, wait-aware baseline validator is available.
- The environment is ready for the dedicated `SYNC01` member-server build and
  the isolated IAM directory design.

## References

The following authoritative sources were used and verified on 30 August 2026:

- [Microsoft ActiveDirectory PowerShell module](https://learn.microsoft.com/en-us/powershell/module/activedirectory/?view=windowsserver2025-ps)
- [Microsoft Azure Connected Machine agent overview](https://learn.microsoft.com/en-us/azure/azure-arc/servers/agent-overview)
- [Microsoft troubleshooting guidance for Azure Monitor Agent on Windows Arc-enabled servers](https://learn.microsoft.com/en-us/azure/azure-monitor/agents/azure-monitor-agent-troubleshoot-windows-arc)
- [Microsoft Entra Cloud Sync prerequisites and server hardening](https://learn.microsoft.com/en-us/entra/identity/hybrid/cloud-sync/how-to-prerequisites)
- [Microsoft Entra Connect supported topologies](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/plan-connect-topologies)
- [Broadcom VMware snapshot best practices](https://knowledge.broadcom.com/external/article/318825/best-practices-for-using-vmware-snapshot.html)
