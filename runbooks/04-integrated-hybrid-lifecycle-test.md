# Integrated Hybrid Lifecycle Test Runbook

## Objective

Execute and validate one approved synthetic identity through Joiner, Mover and
Leaver states across Active Directory and Microsoft Entra Cloud Sync while
preserving a correlated, secret-free evidence trail.

## Execution boundary

| Item | Requirement |
|---|---|
| Test identity | `IAM3001` — Nora Whitfield |
| AD DS execution host | `DC01.corporate.test` |
| Cloud Sync host | `SYNC01.corporate.test` |
| Cloud validation host | Azure Cloud Shell PowerShell |
| Input | `C:\IAM-Lab\data\iam-project1-integrated-lifecycle-test.csv` |
| AD DS script location | `C:\IAM-Lab\scripts` |
| Audit location | `C:\IAM-Lab\logs` |
| Permitted changes | Only the approved `IAM3001` lifecycle state and direct `GG_IAM_*` memberships |

## Required order

Do not execute phases in parallel or skip a validation checkpoint.

1. Validate DC01, SYNC01 and Microsoft Entra baselines.
2. Validate the approved lifecycle dataset and collision-free plan.
3. Verify the Joiner executor hash and syntax, then execute it on DC01.
4. Validate the Joiner audit and effective AD DS state.
5. Wait for Cloud Sync or use on-demand provisioning for controlled diagnosis.
6. Validate the Joiner Microsoft Entra state and five Finance memberships.
7. Verify and execute the Mover on DC01.
8. Validate the Mover audit and effective AD DS state.
9. Validate the Microsoft Entra attribute update and five IT memberships.
10. Verify and execute the Leaver on DC01.
11. Validate disablement, zero access and protected Leavers OU placement.
12. Validate the retained, disabled and access-free Microsoft Entra state.
13. Run the final integrated lifecycle validator on DC01.

## Safety gates

Before each executor:

- compare its SHA-256 digest with the approved package value;
- confirm the Windows PowerShell parser reports zero errors;
- confirm the approved dataset digest is
  `9FC4CFF3DB15DB11C7EE05486007953F436BC3FC48124B6275231886CDED9AD3`;
- inspect the effective state from the preceding phase;
- confirm the previous audit contains zero failed events; and
- stop if the identity is missing, duplicated or in an ambiguous state.

Never type a filename alone at a PowerShell prompt. Execute a script with the
call operator and a complete path, for example:

```powershell
& 'C:\IAM-Lab\scripts\Test-IAMProject1IntegratedLifecycleState.ps1'
```

## Joiner phase

Expected target state:

- enabled Finance employee;
- title `Financial Systems Analyst`;
- manager `IAM1001`;
- Finance employee OU; and
- five approved Finance-state memberships.

The executor must create the account disabled, apply governance, validate it
and enable it last. Stop if any partial execution cannot be classified safely.

## Mover phase

Expected target state:

- enabled Information Technology employee;
- title `Identity Operations Analyst`;
- manager `IAM1201`;
- Information Technology employee OU; and
- five approved IT-state memberships with zero former Finance groups.

Remove obsolete access before adding destination access. Do not manually add
groups in Microsoft Entra ID because Windows Server AD remains authoritative.

## Leaver phase

Expected final state:

- identity retained and disabled;
- protected Leavers OU placement;
- zero direct IAM groups;
- preserved department, title and manager; and
- synchronized Microsoft Entra identity disabled with zero groups.

Disable the account before removing memberships. Do not delete the user or
reset its password as part of this controlled test.

## Cloud Sync validation

Allow the scheduled cycle to process the source change. If deterministic
testing is required, open the existing `corporate.test` Cloud Sync
configuration and use **Provision on demand** for `nora.whitfield`.

Do not alter scoping filters, mappings or synchronization settings. Confirm
that import, scope evaluation, matching and action all succeed. Then use the
phase-specific Microsoft Graph validator from Azure Cloud Shell.

If a Graph access token expires, acquire a new Microsoft Graph token through
the existing authenticated Azure context and reconnect. Never store or paste
the token into a file, screenshot or repository.

## Failure response

1. Stop the current phase and retain its output and correlation ID.
2. Do not start the next lifecycle phase.
3. Inspect the latest successful audit event and effective AD DS state.
4. Keep a partially processed Leaver disabled while investigating.
5. Do not repair synchronized attributes or memberships directly in Entra.
6. Correct the authoritative AD DS state through an approved recovery action.
7. Revalidate AD DS before asking Cloud Sync to process the object again.
8. Preserve failed and resumed evidence as separate records.

## Evidence retention

Retain the approved dataset, the three correlated audit files, executor and
validator versions, all 18 approved screenshots and the final validation
output. Do not publish access tokens, object IDs, administrator identifiers or
raw troubleshooting images that add no portfolio value.

## Production considerations

Replace the laboratory CSV approval model with an authoritative HR or service
management workflow. Separate requester, approver and executor roles; protect
automation identities with least privilege; centralize immutable logs; alert
on synchronization delay or failure; and test recovery using supported AD DS
backup procedures.
