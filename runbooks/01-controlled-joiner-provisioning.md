# Controlled Joiner Provisioning Runbook

## Objective

Provision approved employee and contractor joiners into the protected
`IAM-Lab` Active Directory scope with consistent identity attributes,
least-privilege group access, traceable audit evidence and a safe failure state.

## Execution boundary

| Item | Requirement |
|---|---|
| Execution host | `DC01.corporate.test` |
| Shell | Windows PowerShell as Administrator |
| Directory module | ActiveDirectory |
| Input | `C:\IAM-Lab\data\iam-project1-joiner-requests.csv` |
| Automation | `Invoke-IAMProject1JoinerProvisioning.ps1` |
| Audit location | `C:\IAM-Lab\logs` |
| Permitted scope | Approved objects and groups inside `IAM-Lab` |

## Before execution

1. Confirm the request file was supplied through the approved change process.
2. Record its SHA-256 digest and compare it with the value approved for the
   execution.
3. Confirm each request is a `Joiner`, is `Approved`, has an `Active` lifecycle
   status and has reached its start date.
4. Confirm Employee ID, `sAMAccountName` and UPN are unique.
5. Confirm each enabled manager, target OU and Global Security group exists.
6. Confirm the latest validated recovery checkpoint is available.
7. Never add a password, token or credential column to the request file.

## Execute

```powershell
.\Invoke-IAMProject1JoinerProvisioning.ps1 `
    -CsvPath 'C:\IAM-Lab\data\iam-project1-joiner-requests.csv' `
    -ExpectedSHA256 '<approved SHA-256 digest>'
```

The script performs a complete preflight before its first write. New identities
are created disabled, configured, audited and enabled only after the approved
controls succeed. Existing exact matches are reconciled only toward the
approved state; unexpected IAM memberships stop execution for investigation.

## Validate

Run the effective-state validator:

```powershell
.\Test-IAMProject1JoinerState.ps1
```

Run the audit validator against the audit path printed by the transaction:

```powershell
.\Test-IAMProject1JoinerAudit.ps1 `
    -AuditPath '<transaction audit path>' `
    -ExpectedCorrelationID '<printed correlation ID>' `
    -ExpectedEventCount 25
```

For an idempotent replay, rerun the same provisioning command with the same
approved digest. A fully converged state must report three no-change decisions,
zero creates, zero updates and zero access changes. Validate that replay audit
with `-ExpectedEventCount 5 -ExpectedNoChangeCount 3`.

## Success criteria

- Every request has exactly one matching AD identity.
- Every identity is enabled only after approved controls are applied.
- Manager, OU, attributes and direct IAM groups exactly match the request.
- Contractors have the approved account-expiration control.
- The audit uses one correlation ID and contains no failure or secret value.
- Existing SOC users, IDTR users and high-value test group remain unchanged.
- A replay produces no duplicate identity and no password reset.

## Failure response

1. Stop. Do not rerun repeatedly or manually delete objects.
2. Record the error and correlation ID.
3. Inspect the audit file and effective AD state.
4. Confirm whether newly created objects were safety-disabled.
5. Keep partial objects disabled while the request, dependencies and approved
   recovery action are reviewed.
6. Correct the source request or dependency only through a new approved change.
7. Revalidate before resuming.

The automation never automatically deletes a user or removes unexpected access.
Those actions can destroy evidence or affect an identity outside the intended
transaction.

## Recovery

Use the `IAM-P1-M04-Controlled-Joiner-Automation` VMware checkpoint only for
controlled laboratory recovery and only after confirming which later milestone
changes would be lost. Production recovery requires supported AD DS backup and
restore procedures rather than a standalone VM snapshot.

## Evidence retention

Retain the approved request, transaction audit, replay audit, validation output
and recovery-checkpoint evidence. Never retain generated password values.
