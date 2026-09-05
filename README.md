# Microsoft Hybrid Identity Lifecycle Automation

Enterprise-style identity lifecycle engineering laboratory integrating an
existing Windows Server Active Directory domain with Microsoft Entra ID through
a separately administered synchronization server.

The project implements controlled joiner, mover and leaver workflows with
PowerShell, scoped hybrid synchronization, direct state validation, audit
evidence and recoverable change controls.

| Project attribute | Current value |
|---|---|
| Status | In progress — Milestone 6 validated |
| Active Directory domain | `corporate.test` |
| Authoritative identity source | Active Directory Domain Services |
| Existing domain controller | `DC01.corporate.test` |
| Synchronization server | `SYNC01.corporate.test` — dedicated member server |
| Synchronization technology | Microsoft Entra Cloud Sync — selected, agent installation pending |
| Controlled IAM identities | 33 retained synthetic users — 30 enabled; 28 employees and five contractors |
| Controlled departments | Finance, Human Resources, Information Technology, Sales, Operations and Contractors |
| Synchronization boundary | Protected `IAM-Lab` organisational-unit scope only |
| Recovery checkpoints | Milestone 1 pre-change, paired Milestone 2 infrastructure, Milestone 3 identity foundation, Milestone 4 joiner-automation, Milestone 5 mover-automation and Milestone 6 leaver-automation checkpoints |

## Why this project exists

Manual identity administration creates inconsistent accounts, excessive group
membership, slow onboarding and offboarding, and weak evidence of what changed.
The objective of this project is to demonstrate how an IAM engineer can turn an
approved identity record into a controlled and auditable lifecycle.

The implementation is designed to answer practical questions:

- How should new identities be validated before provisioning?
- How can naming, attributes, organisational-unit placement and group access be
  applied consistently?
- How should obsolete access be removed when an employee changes role?
- What proves that a leaver can no longer authenticate or retain access?
- How can on-premises identities be synchronized without exposing the entire
  existing directory?
- Which evidence proves the requested state and the effective final state?
- How can a failed or incorrect lifecycle operation be investigated and safely
  recovered?

## Validated foundation architecture

```mermaid
flowchart TD
    INPUT["Approved lifecycle data"] --> AUTO["PowerShell validation and automation"]
    AUTO --> AD["Scoped IAM-Lab OU on DC01"]
    AD --> SYNC["Dedicated SYNC01 member server"]
    SYNC --> ENTRA["Microsoft Entra ID<br/>Cloud Sync planned"]
    ENTRA --> EVIDENCE["Cloud validation and audit evidence"]
```

`DC01` remains the domain controller and authoritative directory source.
`SYNC01` is a separate domain-joined Windows Server 2022 member server. It does
not host another forest and is not a domain controller. Microsoft Entra Cloud
Sync was selected because it supports the required scoped user, group and
password-hash synchronization without introducing device synchronization or
other capabilities outside this project's scope. Only the isolated IAM scope
will be eligible for synchronization.

## Current validated outcomes

Milestone 1 established a trusted and recoverable starting point:

- Confirmed `DC01` and `corporate.test` were healthy.
- Preserved the 50 permanent identities created for the earlier SIEM project.
- Confirmed all five disposable identity-threat-detection accounts remained
  disabled.
- Confirmed the synthetic high-value group contained zero members.
- Validated all required Active Directory and Azure Arc services.
- Validated the Azure Monitor Agent process after bounded startup polling.
- Proved that no `IAM-Lab` OU or `SYNC01` computer object existed.
- Created the powered-off VMware recovery checkpoint
  `IAM-P1-M01-PreChange-Validated-State`.
- Produced a reusable read-only baseline validation script.

Milestone 2 established the dedicated synchronization-server foundation:

- Deployed `SYNC01` with two virtual processors, 4 GB memory and an 80 GB
  dynamically allocated virtual disk.
- Installed and updated Windows Server 2022 Standard Evaluation with Desktop
  Experience and VMware Tools.
- Assigned static IPv4 address `192.168.112.20/24`, gateway
  `192.168.112.2` and Active Directory DNS server `192.168.112.10`.
- Joined `SYNC01` to `corporate.test` without promoting it to a domain
  controller.
- Validated the machine secure channel, Active Directory DNS, domain time
  hierarchy, .NET 4.8 or later, storage, VMware Tools and HTTPS connectivity
  to Microsoft Entra ID.
- Preserved the 50 permanent users and the controlled Identity Threat
  Detection and Response lab state on `DC01`.
- Created paired powered-off recovery checkpoints for the domain controller
  and synchronization server.
- Selected Microsoft Entra Cloud Sync and documented why Microsoft Entra
  Connect Sync was not required for the approved scenarios.

Milestone 3 established the controlled identity foundation:

- Created a protected 16-OU `IAM-Lab` hierarchy that remains separate from the
  earlier SOC and identity-threat-detection objects.
- Added the verified Entra sign-in suffix
  `danielcloudlaboutlook258.onmicrosoft.com` without renaming the
  `corporate.test` AD DS namespace.
- Created 15 Global Security groups for workforce classification,
  departmental membership and business-system access.
- Created a sanitised 30-record workforce dataset containing 25 employees and
  five time-bounded contractors with no password or credential columns.
- Detected three pre-existing `sAMAccountName` collisions before provisioning
  and resolved only the planned IAM identifiers with deterministic employee-ID
  suffixes.
- Provisioned the controlled population through disabled staging, applied 24
  manager relationships and 140 direct group memberships, then enabled only
  date-eligible active records.
- Generated unique random initial passwords in memory without displaying or
  exporting them.
- Moved the existing `SYNC01` computer account into the protected
  `IAM-Lab/Infrastructure/Servers` OU without changing the machine trust.
- Preserved all 50 permanent SOC users, all five disabled IDTR users, the empty
  high-value group, seven required services and the Azure Monitor Agent.
- Created the powered-off `IAM-P1-M03-Controlled-Identity-Foundation`
  checkpoint and validated the environment again after restart.

Milestone 4 implemented the controlled joiner workflow:

- Accepted three approved synthetic joiner requests: two employees and one
  time-bounded contractor.
- Verified the request dataset SHA-256 digest, approvals, dates, manager
  references, target OUs, Global Security groups and identity collisions before
  the first directory write.
- Created each new identity in a disabled staging state with a separate
  cryptographically generated 24-character password that was never displayed,
  logged or exported.
- Assigned three manager relationships and 13 approved direct memberships,
  applied the contractor expiration control and enabled accounts only after
  governance configuration succeeded.
- Produced a 25-event transaction audit using correlation ID
  `M04-JOINER-20260904-182309` and validated that it contained no failed events
  or secret-bearing fields.
- Replayed the same approved requests and proved idempotency: zero created or
  updated accounts, zero access changes and three explicit no-change decisions.
- Increased the controlled population from 30 to 33 identities, manager
  relationships from 24 to 27 and direct memberships from 140 to 153 while
  preserving the existing SOC and IDTR environments.
- Created the powered-off `IAM-P1-M04-Controlled-Joiner-Automation` checkpoint
  and validated the complete state after restart.

Milestone 5 implemented the controlled mover workflow:

- Accepted three approved synthetic mover requests covering two
  cross-department transfers and one contractor-to-employee conversion.
- Verified the request dataset SHA-256 digest, approval state, current identity
  state, target managers, protected OUs and Global Security groups before any
  directory write.
- Removed six obsolete memberships before granting eight approved destination
  memberships, preventing temporary access accumulation during transition.
- Updated three job and department profiles, changed three managers and moved
  all three identities into their approved destination OUs.
- Converted Mason Cole from contractor to employee, removed both contractor
  memberships and cleared the former time-bounded account expiration.
- Produced a 29-event transaction audit using correlation ID
  `M05-MOVER-20260904-200349` and validated its ordering, correlation and lack
  of secret-bearing content.
- Replayed the same approved requests and proved idempotency with three
  explicit no-change decisions and zero directory modifications under
  correlation ID `M05-MOVER-20260904-203431`.
- Preserved 33 enabled controlled identities while changing the governed mix
  to 28 employees and five contractors and increasing approved direct IAM
  memberships from 153 to 155.
- Created the powered-off `IAM-P1-M05-Controlled-Mover-Automation` checkpoint
  and validated the complete mover state after restart.

Milestone 6 implemented controlled leaver containment and recovery:

- Accepted three approved synthetic employee departures and verified their
  source state, request controls, protected target OU and dataset digest before
  the first directory write.
- Captured governed pre-change recovery evidence, disabled all three accounts
  before access removal, removed 15 direct IAM memberships and retained the
  objects in the protected Leavers OU without deleting accounts or changing
  passwords.
- Exercised fail-safe recovery after an initial strict-mode scalar `.Count`
  error: one identity remained safely contained, two remained unchanged and a
  corrected script resumed the remaining work without duplicating changes.
- Proved the interrupted and resumed trail was complete across three disables,
  15 removals, three OU moves and three lifecycle-description updates with zero
  unresolved failure.
- Replayed the corrected workflow and produced three explicit no-change
  decisions, zero modifications and no unnecessary recovery manifest.
- Demonstrated separately approved recovery of one incorrectly contained
  identity, restoring its OU and five authorised memberships before enabling
  it, then re-contained it to return the lab to the approved leaver state.
- Preserved all 33 controlled identities while reducing enabled accounts from
  33 to 30 and approved direct IAM memberships from 155 to 140.
- Created the powered-off `IAM-P1-M06-Controlled-Leaver-Automation` checkpoint
  and validated the complete containment, recovery, audit and monitoring state
  after restart.

See the complete [baseline and recovery checkpoint record](docs/Baseline-and-Recovery-Checkpoint.md).
See the [dedicated synchronization-server foundation](docs/Dedicated-Sync-Server-Foundation.md)
and the [Cloud Sync architecture decision](architecture/Cloud-Sync-Architecture-Decision.md).
See the [controlled identity foundation](docs/Controlled-Identity-Foundation.md)
for the Milestone 3 design, implementation and evidence.
See the [controlled joiner provisioning automation](docs/Controlled-Joiner-Provisioning-Automation.md)
and the [joiner operations runbook](runbooks/01-controlled-joiner-provisioning.md)
for the Milestone 4 workflow, evidence and recovery controls.
See the [controlled mover access-transition automation](docs/Controlled-Mover-Access-Transition-Automation.md)
and the [mover operations runbook](runbooks/02-controlled-mover-access-transition.md)
for the Milestone 5 workflow, least-privilege sequence and audit evidence.
See the [controlled leaver containment and recovery](docs/Controlled-Leaver-Containment-and-Recovery.md)
and the [leaver operations runbook](runbooks/03-controlled-leaver-containment-and-recovery.md)
for the Milestone 6 workflow, fail-safe resume and governed recovery evidence.

## Evidence highlights

### Pre-change recovery checkpoint

![Validated pre-change recovery checkpoint](screenshots/m01-01-prechange-recovery-snapshot.png)

### Post-checkpoint baseline

![Validated post-snapshot DC01 baseline](screenshots/m01-02-dc01-post-snapshot-baseline.png)

### Dedicated synchronization-server foundation

![Validated SYNC01 foundation](screenshots/m02-01-sync01-foundation-validation.png)

### Paired Milestone 2 recovery checkpoints

![SYNC01 validated-foundation checkpoint](screenshots/m02-02-sync01-foundation-recovery-snapshot.png)

![DC01 post-domain-join checkpoint](screenshots/m02-03-dc01-paired-recovery-snapshot.png)

### Controlled identity foundation

![Protected IAM-Lab OU structure](screenshots/m03-01-iam-lab-ou-structure.png)

![Controlled Finance identities](screenshots/m03-02-controlled-finance-identities.png)

![Representative identity governance](screenshots/m03-03-representative-identity-governance.png)

![Comprehensive identity validation](screenshots/m03-04-comprehensive-identity-validation.png)

![Milestone 3 recovery checkpoint](screenshots/m03-05-dc01-controlled-identity-recovery-snapshot.png)

![Post-snapshot identity validation](screenshots/m03-06-dc01-post-snapshot-validation.png)

### Controlled joiner automation

![Joiner preflight validation](screenshots/m04-01-joiner-preflight-validation.png)

![Approved joiner dataset validation](screenshots/m04-02-approved-joiner-dataset-validation.png)

![Controlled joiner provisioning](screenshots/m04-03-controlled-joiner-provisioning.png)

![Correlated transaction audit validation](screenshots/m04-04-joiner-transaction-audit-validation.png)

![Approved joiners in Active Directory](screenshots/m04-05-approved-joiners-aduc.png)

![Time-bounded contractor governance](screenshots/m04-06-contractor-joiner-governance.png)

![Idempotent joiner replay](screenshots/m04-07-idempotent-joiner-replay.png)

![Milestone 4 recovery checkpoint](screenshots/m04-08-dc01-joiner-recovery-snapshot.png)

![Post-snapshot joiner validation](screenshots/m04-09-dc01-post-snapshot-joiner-validation.png)

### Controlled mover automation

![Mover preflight validation](screenshots/m05-01-mover-preflight-validation.png)

![Approved mover dataset validation](screenshots/m05-02-approved-mover-dataset-validation.png)

![DC01 mover dataset validation](screenshots/m05-03-dc01-mover-dataset-validation.png)

![Controlled mover transition](screenshots/m05-03-controlled-mover-transition.png)

![Mover transaction audit validation](screenshots/m05-04-mover-transaction-audit-validation.png)

![Contractor-to-employee governance](screenshots/m05-05-contractor-to-employee-governance.png)

![Approved movers in Active Directory](screenshots/m05-06-approved-movers-aduc.png)

![Comprehensive mover validation](screenshots/m05-07-comprehensive-mover-validation.png)

![Idempotent mover replay](screenshots/m05-08-idempotent-mover-replay.png)

![Milestone 5 recovery checkpoint](screenshots/m05-09-dc01-mover-recovery-snapshot.png)

![Post-snapshot mover validation](screenshots/m05-10-dc01-post-snapshot-mover-validation.png)

### Controlled leaver containment and recovery

![Leaver preflight validation](screenshots/m06-01-leaver-preflight-validation.png)

![Approved leaver dataset validation](screenshots/m06-02-approved-leaver-dataset-validation.png)

![DC01 leaver dataset validation](screenshots/m06-03-dc01-leaver-dataset-validation.png)

![Controlled leaver containment](screenshots/m06-04-controlled-leaver-containment.png)

![Interrupted and resumed audit validation](screenshots/m06-05-leaver-recovery-audit-validation.png)

![Approved leavers in Active Directory](screenshots/m06-06-approved-leavers-aduc.png)

![Representative leaver containment](screenshots/m06-07-representative-leaver-containment.png)

![Idempotent leaver replay](screenshots/m06-08-idempotent-leaver-replay.png)

![Idempotent replay audit validation](screenshots/m06-09-idempotent-leaver-replay-audit.png)

![Governed leaver recovery](screenshots/m06-10-governed-leaver-recovery.png)

![Re-contained after governed recovery](screenshots/m06-11-recontained-after-recovery.png)

![Comprehensive leaver validation](screenshots/m06-12-comprehensive-leaver-validation.png)

![Milestone 6 recovery checkpoint](screenshots/m06-13-dc01-leaver-recovery-snapshot.png)

![Post-snapshot leaver validation](screenshots/m06-14-dc01-post-snapshot-leaver-validation.png)

## Lifecycle scope

The project implements three controlled workflows.

### Joiner

- Validate approved input data.
- Create a uniquely named identity.
- Apply required attributes and organisational-unit placement.
- Assign baseline and role-based group access.
- Enforce the approved initial credential controls.
- Record the operation and validate the effective account state.

### Mover

- Capture the identity's current attributes and access.
- Remove obsolete access before granting the new role.
- Update department, title, manager and directory placement where applicable.
- Add only the groups required by the destination role.
- Produce a before-and-after access comparison.

### Leaver

- Disable the account.
- Remove access-group memberships.
- Move the object into the controlled leaver scope.
- Record the operation and final state.
- Prove that access has been removed.
- Demonstrate a governed recovery path for an incorrect offboarding action.

## Implementation milestones

| Milestone | Principal outcome | Status |
|---:|---|---|
| 0 | Local project structure and private GitHub repository | Complete |
| 1 | Existing-environment baseline and powered-off recovery checkpoint | Complete |
| 2 | Dedicated synchronization-server and network foundation | Complete |
| 3 | Isolated IAM directory structure, groups and controlled identity data | Complete |
| 4 | Joiner provisioning automation and validation | Complete |
| 5 | Mover access-transition automation and validation | Complete |
| 6 | Leaver containment, recovery and validation | Complete |
| 7 | Scoped Microsoft Entra synchronization and cloud-state validation | Planned |
| 8 | Integrated lifecycle testing and portfolio quality review | Planned |

Milestone boundaries may be refined when a technical dependency requires a
different validation order, but the project scope will remain unchanged.

## Current reusable artifacts

### PowerShell

- [Validate the pre-deployment environment](scripts/Test-IAMProject1Baseline.ps1)
- [Validate the dedicated synchronization-server foundation](scripts/Test-IAMProject1SyncFoundation.ps1)
- [Create the directory and group foundation](scripts/Initialize-IAMProject1DirectoryFoundation.ps1)
- [Provision the controlled identity population](scripts/Import-IAMProject1ControlledUsers.ps1)
- [Validate the controlled identity foundation](scripts/Test-IAMProject1ControlledIdentityFoundation.ps1)
- [Provision approved joiner requests](scripts/Invoke-IAMProject1JoinerProvisioning.ps1)
- [Validate correlated joiner audit records](scripts/Test-IAMProject1JoinerAudit.ps1)
- [Validate effective joiner and preserved environment state](scripts/Test-IAMProject1JoinerState.ps1)
- [Apply approved mover access transitions](scripts/Invoke-IAMProject1MoverTransition.ps1)
- [Validate correlated mover audit records](scripts/Test-IAMProject1MoverAudit.ps1)
- [Validate effective mover and preserved environment state](scripts/Test-IAMProject1MoverState.ps1)
- [Contain approved leavers](scripts/Invoke-IAMProject1LeaverContainment.ps1)
- [Perform an approved leaver recovery](scripts/Restore-IAMProject1Leaver.ps1)
- [Validate leaver, recovery, audit and preserved environment state](scripts/Test-IAMProject1LeaverState.ps1)

### Data

- [Controlled 30-user identity dataset](data/iam-project1-controlled-users.csv)
- [Approved three-record joiner request dataset](data/iam-project1-joiner-requests.csv)
- [Initial joiner transaction audit](data/iam-project1-joiner-provisioning-audit.csv)
- [Idempotent replay audit](data/iam-project1-joiner-idempotent-replay-audit.csv)
- [Approved three-record mover request dataset](data/iam-project1-mover-requests.csv)
- [Initial mover transition audit](data/iam-project1-mover-transition-audit.csv)
- [Idempotent mover replay audit](data/iam-project1-mover-idempotent-replay-audit.csv)
- [Approved three-record leaver request dataset](data/iam-project1-leaver-requests.csv)
- [Interrupted leaver containment audit](data/iam-project1-leaver-interrupted-audit.csv)
- [Authoritative leaver recovery manifest](data/iam-project1-leaver-recovery-manifest.csv)
- [Resumed leaver containment audit](data/iam-project1-leaver-resumed-audit.csv)
- [Idempotent leaver replay audit](data/iam-project1-leaver-idempotent-replay-audit.csv)
- [Governed leaver recovery audit](data/iam-project1-leaver-governed-recovery-audit.csv)
- [Leaver re-containment audit](data/iam-project1-leaver-recontainment-audit.csv)
- [Leaver re-containment recovery manifest](data/iam-project1-leaver-recontainment-recovery-manifest.csv)

### Documentation

- [Baseline and recovery checkpoint](docs/Baseline-and-Recovery-Checkpoint.md)
- [Dedicated synchronization-server foundation](docs/Dedicated-Sync-Server-Foundation.md)
- [Controlled identity foundation](docs/Controlled-Identity-Foundation.md)
- [Controlled joiner provisioning automation](docs/Controlled-Joiner-Provisioning-Automation.md)
- [Controlled joiner operations runbook](runbooks/01-controlled-joiner-provisioning.md)
- [Controlled mover access-transition automation](docs/Controlled-Mover-Access-Transition-Automation.md)
- [Controlled mover operations runbook](runbooks/02-controlled-mover-access-transition.md)
- [Controlled leaver containment and recovery](docs/Controlled-Leaver-Containment-and-Recovery.md)
- [Controlled leaver operations runbook](runbooks/03-controlled-leaver-containment-and-recovery.md)
- [Microsoft Entra Cloud Sync architecture decision](architecture/Cloud-Sync-Architecture-Decision.md)

## Repository contents

| Path | Purpose |
|---|---|
| `architecture/` | Hybrid identity design, data flow, trust boundaries and source-of-authority decisions |
| `data/` | Sanitised lifecycle input and controlled identity data |
| `docs/` | Milestone implementation, validation and troubleshooting records |
| `queries/` | Reusable directory or Microsoft Graph query artifacts where required |
| `runbooks/` | Joiner, mover, leaver, recovery and operational procedures |
| `screenshots/` | Numbered milestone evidence captured only after validation |
| `scripts/` | PowerShell provisioning, transition, recovery and validation automation |
| `lessons-learned.md` | Final engineering decisions, failures, corrections and production improvements |

The local `temporary/` directory is used to assemble validated GitHub upload
packages and is not part of the public repository.

## Security and testing controls

- No passwords, access tokens or authentication secrets are stored in the
  repository.
- Existing SOC identities are preserved rather than repurposed.
- New IAM objects use a separately scoped directory structure.
- The synchronization role is separated from the domain-controller role.
- `SYNC01` is treated as an identity control-plane asset and will not host
  unrelated workloads.
- Only approved milestone files are copied into clean upload packages.
- Screenshots are reviewed for personal and cloud-environment identifiers.
- Destructive lifecycle tests use controlled identities and explicit recovery
  validation.
- Script output is not accepted as proof without direct state verification.

## Current limitations

- The current laboratory has one domain controller.
- Microsoft Entra synchronization has not yet been enabled.
- Joiner, mover and leaver automation are complete; cloud synchronization and
  cloud-state validation remain pending.
- The Cloud Sync provisioning agent has not yet been installed or registered.
- The laboratory will use one Cloud Sync agent; a production design should use
  multiple agents when high availability is required.
- VMware checkpoints provide laboratory rollback, not production backup or
  cross-platform recovery.
- Cloud Sync does not provide device synchronization or Hybrid Microsoft Entra
  Join. Those capabilities are not required by this project's approved scope.

These are current milestone boundaries, not claims of completed capability.
Later documentation will retain the distinction between laboratory
implementation and production design.

## Evidence standard

Every milestone follows the same controlled sequence:

1. Perform one bounded technical change.
2. Validate the effective state.
3. Capture sanitised evidence only after validation.
4. Produce reusable documentation and automation.
5. Verify file inventory, hashes, syntax, links and privacy.
6. Assemble only approved files in a clean temporary upload folder.
7. Upload one milestone package and inspect the rendered GitHub result.

This repository documents a hands-on laboratory implementation. It does not
represent production employment experience or a script that should be executed
unchanged in a production environment.
