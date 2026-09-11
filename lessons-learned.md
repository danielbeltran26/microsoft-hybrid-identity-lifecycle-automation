# Lessons Learned

## Project summary

This project built and validated an enterprise-style hybrid identity lifecycle
from an existing `corporate.test` Active Directory environment to Microsoft
Entra ID. It progressed from environment discovery and recovery checkpoints to
a protected identity foundation, controlled Joiner, Mover and Leaver
automation, scoped Microsoft Entra Cloud Sync and one complete end-to-end
lifecycle test.

The most valuable outcome was not simply creating synchronized accounts. It
was proving that each requested change matched the effective state in both
directories, that obsolete access was removed at the correct time, and that
the evidence remained correlated, recoverable and free of credentials.

## Architecture decisions

### Keep synchronization off the domain controller

Running the provisioning agent on the dedicated `SYNC01` member server kept
the synchronization role separate from `DC01`. This reduced role
concentration, made troubleshooting clearer and better represented a
production identity architecture.

The additional server required more memory, networking and time-synchronization
work, but that operational cost was justified. Installing every identity
component on the domain controller would have made the laboratory easier while
demonstrating a weaker design.

### Use Cloud Sync for the approved scope

Microsoft Entra Cloud Sync met the project requirement for scoped users,
groups and password-hash synchronization without introducing device
synchronization, federation or Exchange hybrid capabilities that the project
did not need.

This reinforced an important design principle: choose the smallest supported
technology that satisfies the requirement, and document capabilities that are
deliberately out of scope.

### Preserve the source-of-authority boundary

Active Directory remained authoritative for synchronized identities and group
memberships. Changes were made in AD DS and then validated in Microsoft Entra
ID. Directly repairing synchronized attributes or memberships in Entra would
have hidden source-state problems and weakened the evidence chain.

## Engineering lessons

### Validate before the first write

The safest automation pattern was:

1. Verify the execution host and domain.
2. Verify the approved dataset hash and schema.
3. Reject identity collisions and ambiguous state.
4. Validate managers, OUs and groups.
5. Record a correlation ID.
6. Make the minimum approved changes.
7. Validate the effective state independently.

This made errors visible before they became directory changes. Hash checks
also proved that the executed input was the same input that had been reviewed.

### Disabled staging reduces Joiner risk

Creating a new account in a disabled state allowed attributes, manager,
organisational-unit placement and access to be applied and checked before the
identity could authenticate. Enabling the account last prevented a partially
configured identity from becoming active.

### Remove obsolete access before adding new access

The Mover workflow removed Finance-specific access before granting IT-specific
access. If additions had occurred first, the user would temporarily have held
both roles. Even a short overlap is unnecessary privilege accumulation.

### Disable before removing Leaver access

The Leaver workflow disabled the identity before removing its memberships.
This established the fastest authentication boundary first. The account was
retained instead of deleted, preserving audit history and a controlled
recovery path while leaving it access-free.

### Idempotency is a security control

Safe replay was not merely a convenience. It prevented repeated execution
from duplicating objects, restoring obsolete access or creating inconsistent
audit results. Lifecycle automation should recognize exact source, target and
safe partial states and should stop on ambiguous state.

## Failures and corrections

### Strict-mode scalar Count failure

The Milestone 6 Leaver workflow exposed a PowerShell strict-mode problem when
a single result was treated as though it always had a `.Count` property. The
operation stopped after one identity had been safely contained and before the
remaining two were changed.

The correction was to force command results into arrays with `@(...)` before
using `.Count`. More importantly, the recovery evidence and audit trail were
preserved, the partial state was classified, and the corrected workflow
resumed without duplicating completed changes.

Lesson: normalize uncertain PowerShell output cardinality and design write
operations so a failure leaves a recognizable, safely resumable state.

### Time, DNS and domain trust dependencies

`SYNC01` initially showed an invalid secure channel and local CMOS time source.
Active Directory DNS, domain authentication and the domain time hierarchy had
to be corrected and revalidated before Cloud Sync installation.

Lesson: identity systems depend on infrastructure fundamentals. A healthy
agent cannot compensate for broken name resolution, trust or time.

### Cloud Sync scope and on-demand lookup

The first on-demand search could not find `IAM3001` even though the AD object
existed. Inspection confirmed that the parent `OU=Users,OU=IAM-Lab` boundary
was configured. A later controlled retry imported the object successfully,
confirmed it was in scope, matched it and updated Microsoft Entra ID.

Lesson: distinguish between object existence, scope eligibility and cycle
timing. Check the authoritative object and configured boundary before changing
scope or mappings.

### Expired Microsoft Graph tokens

A Microsoft Graph validation failed with HTTP 401 because the access token had
expired. The validator was corrected to acquire a fresh Graph token from the
existing authenticated Azure context before connecting.

Lesson: a valid session does not guarantee that a previously supplied token is
still valid. Read-only cloud validators should obtain a fresh token at run time
and must never persist it.

### File-transfer and PowerShell input errors

Several failures came from paths or variables that were not present in the
current shell, and one filename was typed as though it were a command. These
errors did not change the directory because verification gates stopped first.

Lesson: use full paths, initialize every variable in the same executable block,
force collections with `@(...)`, and use the PowerShell call operator `&` when
executing a script by path.

### Evidence privacy requires visual review

Some raw portal screenshots contained administrator identifiers, object GUIDs
or a complete tenant UPN. File-integrity checks could not detect those issues.
The affected evidence was cropped, redacted or recaptured while preserving the
original laboratory files.

Lesson: hash, syntax and inventory validation prove integrity, not privacy or
presentation quality. Public evidence requires a separate full-resolution
visual review.

## Operational lessons

- A healthy Cloud Sync configuration is not sufficient proof; verify user and
  group counts, attributes, enabled state, memberships, timestamps and
  exclusions directly.
- Portal evidence and Microsoft Graph validation complement each other. The
  portal explains the operation; Graph verifies the resulting population.
- Correlation IDs make multi-step transactions explainable and allow audit
  events to be checked for completeness and ordering.
- Recovery checkpoints are useful in a laboratory but do not replace supported
  AD DS backup, high availability or production disaster recovery.
- Temporary transfer and review packages should remain outside the public
  repository and be removed only after official files and GitHub content are
  verified.
- One bounded change followed by validation is slower than uncontrolled bulk
  work but produces substantially stronger evidence and easier recovery.

## Production improvements

A production implementation should add:

- authoritative HR or service-management events instead of local CSV requests;
- separation between requester, approver and automation operator;
- least-privilege service identities with protected credential management;
- multiple Cloud Sync agents where availability requirements justify them;
- centralized, immutable audit retention and automated failure alerting;
- monitoring for stale synchronization and unexpected scope changes;
- formal access certification for role and application groups;
- supported AD DS backup and tested forest-recovery procedures; and
- change-controlled release, testing and rollback for lifecycle scripts.

## Final reflection

The project demonstrates that identity lifecycle engineering is more than
account creation. The critical work is controlling authority, sequencing
access changes safely, proving what happened, validating the result across
systems and retaining a recoverable state when something fails.

The final `IAM3001` test connected all of those controls in one evidence chain:
approved Finance Joiner, least-privilege IT Mover and retained access-free
Leaver, with matching AD DS, Cloud Sync, Microsoft Entra and audit validation.
The completed project retains 19 approved Milestone 8 screenshots, including
the final consolidated 32-event lifecycle validation.
