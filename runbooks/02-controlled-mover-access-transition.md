# Controlled Mover Access-Transition Runbook

## Objective

Apply approved employee transfers and worker-type conversions inside the
protected `IAM-Lab` Active Directory scope while removing obsolete access
before new access is granted, preserving a correlated audit and proving the
exact effective state.

## Execution boundary

| Item | Requirement |
|---|---|
| Execution host | `DC01.corporate.test` |
| Shell | Windows PowerShell as Administrator |
| Directory module | ActiveDirectory |
| Input | `C:\IAM-Lab\data\iam-project1-mover-requests.csv` |
| Automation | `Invoke-IAMProject1MoverTransition.ps1` |
| Audit location | `C:\IAM-Lab\logs` |
| Permitted scope | Approved users, OUs and groups inside `IAM-Lab` |

## Change effect

The automation may remove and add direct IAM group memberships, update user
attributes and managers, move user objects between approved OUs and apply or
clear account expiration. It does not create or delete accounts and does not
set, display or export passwords.

## Before execution

1. Confirm the mover request was supplied through the approved change process.
2. Record its SHA-256 digest and compare it with the approved value.
3. Confirm every record is a `Mover`, is `Approved`, has an `Active` lifecycle
   status and has reached its effective date.
4. Confirm one existing identity matches each Employee ID, `sAMAccountName`
   and UPN.
5. Confirm each identity exactly matches either the approved source state or
   the complete target state. Treat a mixed state as an incident to investigate.
6. Confirm each enabled destination manager, protected OU and Global Security
   group exists.
7. Confirm the latest validated recovery checkpoint is available.
8. Never add a password, token or credential column to the request file.

## Execute

Run on DC01 from the folder containing the scripts:

```powershell
.\Invoke-IAMProject1MoverTransition.ps1 `
    -CsvPath 'C:\IAM-Lab\data\iam-project1-mover-requests.csv' `
    -ExpectedSHA256 'AA40213E0C71234FA3F32CF1AF9FA0960EDDA3B231EBEE58D82C5C0A1E23A7C8'
```

The script completes its preflight before the first write. For each identity it
removes source-only memberships, updates approved attributes and placement,
handles expiration, grants missing target memberships and then validates the
exact target state.

## Validate

Run the complete effective-state validator:

```powershell
.\Test-IAMProject1MoverState.ps1
```

Validate the initial transaction audit:

```powershell
.\Test-IAMProject1MoverAudit.ps1 `
    -AuditPath 'C:\IAM-Lab\logs\M05-MOVER-20260904-200349-audit.csv' `
    -ExpectedCorrelationID 'M05-MOVER-20260904-200349' `
    -ExpectedEventCount 29
```

For an idempotent replay, execute the same mover command again with the same
approved digest. A fully converged state must report three no-change decisions
and zero removals, additions, attribute updates, manager changes, OU moves or
expiration changes. Validate the replay audit:

```powershell
.\Test-IAMProject1MoverAudit.ps1 `
    -AuditPath 'C:\IAM-Lab\logs\M05-MOVER-20260904-203431-audit.csv' `
    -ExpectedCorrelationID 'M05-MOVER-20260904-203431' `
    -ExpectedEventCount 5 `
    -ExpectedNoChangeCount 3
```

## Success criteria

- Every request has exactly one matching, enabled identity.
- Department, title, worker type, manager and OU match the target record.
- Direct IAM memberships exactly equal the approved target set.
- Source-only memberships are absent before destination grants are recorded.
- Mason Cole has employee status and no account expiration.
- The audit uses one correlation ID and contains no failed or secret event.
- Existing SOC users, IDTR users and the high-value test group remain unchanged.
- Replay produces three no-change events and no directory modification.

## Failure response

1. Stop. Do not repeatedly rerun the automation or manually grant access.
2. Record the error, correlation ID and last successful audit event.
3. Inspect the identity's attributes, manager, OU, expiration and direct groups.
4. Determine whether obsolete access was removed before the failure.
5. Keep the account in its safest current state while the approved source and
   target records are reviewed.
6. Do not automatically restore obsolete access; obtain an explicit recovery
   decision from the request owner and security operations.
7. Correct the authoritative request or dependency and repeat preflight before
   resuming.

The automation does not delete or disable identities and does not perform an
automatic rollback that could silently restore inappropriate privileges.

## Recovery

Use the `IAM-P1-M05-Controlled-Mover-Automation` VMware checkpoint only for
controlled laboratory recovery and only after confirming which later changes
would be lost. Production recovery requires supported AD DS backup and restore
procedures rather than a standalone VM snapshot.

## Evidence retention

Retain the approved mover dataset, initial transaction audit, idempotent replay
audit, state validation, ADUC evidence and recovery-checkpoint evidence. Never
retain passwords or authentication secrets.
