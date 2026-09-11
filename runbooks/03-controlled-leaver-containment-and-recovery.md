# Controlled Leaver Containment and Recovery Runbook

## Objective

Contain approved leavers inside the protected `IAM-Lab` Active Directory
scope, remove direct IAM access, retain the identity for investigation and
recovery, and prove the exact final state with correlated evidence.

## Execution boundary

| Item | Requirement |
|---|---|
| Execution host | `DC01.corporate.test` |
| Shell | Windows PowerShell as Administrator |
| Directory module | ActiveDirectory |
| Input | `C:\IAM-Lab\data\iam-project1-leaver-requests.csv` |
| Containment automation | `Invoke-IAMProject1LeaverContainment.ps1` |
| Recovery automation | `Restore-IAMProject1Leaver.ps1` |
| Audit and recovery location | `C:\IAM-Lab\logs` |
| Permitted scope | Three approved identities, protected Leavers OU and direct `GG_IAM_*` memberships |

## Change effect

Containment may disable an approved account, remove its direct IAM group
memberships, move it into the protected Leavers OU and update its lifecycle
description. It does not delete the account, change its password, remove its
manager or alter its core identity and job attributes.

Governed recovery may restore one approved identity's original OU,
description, account expiration and direct IAM memberships before enabling it.
Recovery requires separate approval and authoritative pre-change evidence.

## Before containment

1. Confirm the leaver request came through the approved change process.
2. Compare the request file's SHA-256 digest with the approved value.
3. Confirm exactly three records are `Leaver`, `Approved`, effective and set to
   disable, remove all direct IAM access, retain the account and require
   recovery validation.
4. Confirm one account matches each Employee ID, `sAMAccountName` and UPN.
5. Confirm each account exactly matches its approved source state, exact
   contained state or a demonstrably safe partial state. Investigate any
   ambiguous state.
6. Confirm the protected Leavers OU and every recorded source membership.
7. Confirm `C:\IAM-Lab\logs` is available and the latest recovery checkpoint
   is known.
8. Never add a password, token or credential column to the request or recovery
   file.

## Execute containment

Run on DC01 from the folder containing the scripts:

```powershell
.\Invoke-IAMProject1LeaverContainment.ps1 `
    -DatasetPath 'C:\IAM-Lab\data\iam-project1-leaver-requests.csv' `
    -ExpectedDatasetSHA256 '96A488E3A26CA23F1AD7B9652DCDBD9D774D8EF4E201E8F677A4E0CCB6D482DE'
```

The script completes preflight and writes the recovery manifest before the
first directory change. It then disables each applicable account, removes
direct IAM memberships, moves the object, updates its lifecycle description
and validates the exact contained state.

## Validate containment

Run the complete read-only validator after copying the published Milestone 6
evidence to `C:\IAM-Lab\data`:

```powershell
.\Test-IAMProject1LeaverState.ps1
```

Success requires:

- 33 retained controlled identities and 30 enabled identities;
- three approved leavers, all disabled in the protected Leavers OU;
- zero direct `GG_IAM_*` memberships on leaver objects;
- 140 total direct IAM memberships in the controlled scope;
- exact request, evidence and script hashes;
- a complete recovered-interruption trail and zero unresolved failures;
- three no-change replay events and zero replay modifications; and
- preserved `SYNC01`, service, Azure Monitor Agent, SOC and IDTR state.

## Idempotent replay

Execute the same containment command after the exact target state is reached.
A safe replay must report three no-change decisions, zero recovery records and
zero account, membership, OU or description changes.

The published replay evidence is
`iam-project1-leaver-idempotent-replay-audit.csv`, correlation ID
`M06-LEAVER-20260905-001302`, with five events and SHA-256 digest:

```text
411BDD5A31222722918AF5B9C07F881B9A96D085ADDDA79082D7B8F88A1E0BBD
```

## Failure response and safe resume

1. Stop and record the error, correlation ID and last successful audit event.
2. Do not delete the account, reset its password or manually grant access.
3. Preserve the audit and recovery manifest without editing either file.
4. Inspect the account's enabled state, parent OU, lifecycle description and
   direct IAM groups.
5. Classify the account as exact source, exact target, safe partial or
   ambiguous state.
6. Keep a partially processed account disabled while investigating.
7. Correct the script or authoritative dependency, syntax-validate it and
   obtain approval before resuming.
8. Re-run the same containment workflow only after confirming it can recognize
   completed and safe partial states.
9. Validate the combined interrupted and resumed trail, not only the final
   execution.

Milestone 6 exercised this procedure after a strict-mode scalar `.Count`
failure. Recovery state had already been captured, one account was safely
contained and two remained unchanged. The corrected script resumed the other
two identities without duplicating the completed work.

## Governed recovery

Recovery is for a verified incorrect containment decision, not routine
reactivation. Before execution:

1. Confirm a separate recovery approval, approved Employee ID and named
   approver.
2. Verify the leaver dataset and authoritative recovery-manifest SHA-256
   digests.
3. Confirm exactly one request, recovery record and retained account match.
4. Confirm the recovery window has not expired.
5. Confirm the account is disabled, access-free, in the Leavers OU and still
   carries the preserved identity, job and manager attributes.
6. Confirm every recovery group exists and exactly matches the approved
   pre-leaver request.

The included script defaults to the validated IAM2003 recovery demonstration:

```powershell
.\Restore-IAMProject1Leaver.ps1 `
    -EmployeeID 'IAM2003' `
    -DatasetPath 'C:\IAM-Lab\data\iam-project1-leaver-requests.csv' `
    -RecoveryPath 'C:\IAM-Lab\logs\M06-LEAVER-20260904-235742-recovery.csv' `
    -ExpectedDatasetSHA256 '96A488E3A26CA23F1AD7B9652DCDBD9D774D8EF4E201E8F677A4E0CCB6D482DE' `
    -ExpectedRecoverySHA256 '96433B774255A7982D33917E38830B06F3F2D32AA62EC553330C10E843941880' `
    -RecoveryApprovalID 'RCV-2026-0905-001' `
    -ApprovedBy 'IAM-Operations-Lead'
```

The recovery sequence keeps the account disabled while restoring its OU,
description, expiration state and memberships. It enables the account only
after those changes complete, then validates the exact recovered state and
writes a separate recovery audit.

For another approved identity or event, supply the correct Employee ID,
approval and evidence parameters. Never reuse the demonstration approval or
manifest for an unrelated recovery.

## Re-containment after a recovery test

If a laboratory recovery demonstration must end in the approved leaver state,
execute the containment command again. The workflow should recognize all
identities already contained and change only the recovered account. Preserve
the new audit and recovery manifest as a separate evidence pair.

## Recovery checkpoints

Use `IAM-P1-M06-Controlled-Leaver-Automation` only for controlled laboratory
recovery and only after identifying which later changes would be lost. Because
the checkpoint contains Active Directory state, restore it consistently with
the lab's domain-controller recovery procedure.

Production recovery requires supported AD DS backup and restore, protected
audit storage and a tested continuity process rather than a standalone VM
snapshot.

## Evidence retention

Retain the approved request dataset, authoritative recovery manifest,
interrupted and resumed audits, idempotent replay audit, governed recovery
audit, re-containment audit and manifest, state validation, ADUC evidence and
the recovery-checkpoint record. Keep the files read-only after publication and
record their SHA-256 digests. Never retain passwords or authentication secrets.
