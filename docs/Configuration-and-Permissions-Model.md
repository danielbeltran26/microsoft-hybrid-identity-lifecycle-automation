# Configuration and Permissions Model

## Configuration boundary

The public scripts are laboratory implementations. Their parameters identify
the approved `corporate.test` environment, protected OU roots, dataset paths
and expected evidence. Fixed values in final validators are deliberate: they
prove that one reviewed dataset produced one exact validated state.

Reusable production automation would separate:

- environment configuration, such as domain names and OU roots;
- transaction input, such as the identity and approval record;
- protected secrets and service credentials;
- expected-state policy, such as role-to-group mappings; and
- evidence-specific constants, such as correlation IDs and approved hashes.

The validated project scripts were not retroactively refactored after evidence
capture because changing them would break the relationship between the
published hashes, screenshots and executed versions.

## Identity and permission responsibilities

| Identity or component | Required responsibility | Explicit boundary |
|---|---|---|
| AD lifecycle operator | Run approved lifecycle scripts on DC01 and review their output | Operates only on approved `IAM-Lab` objects; production duties should be separated from request and approval |
| Microsoft Entra Cloud Sync gMSA | Allow the provisioning agent to read and synchronize the configured AD scope | Password is domain-managed; it is not stored in scripts or the repository |
| Cloud Sync agent updater | Maintain the Microsoft provisioning-agent software on SYNC01 | Runs separately from the synchronization service and does not define lifecycle policy |
| Microsoft Graph validation session | Read synchronized users, groups and directory state | Uses delegated read scopes for validation; access tokens are acquired at runtime and never persisted |
| Microsoft Entra administrator | Configure scope, inspect agent health and use controlled provision-on-demand diagnostics | Does not repair AD-authoritative attributes or memberships directly in Entra ID |
| GitHub Actions runner | Parse and inspect repository content | Has no connectivity or credentials for DC01, SYNC01 or Microsoft Entra ID |

## Least-privilege interpretation

This project validates functional boundaries and avoids storing reusable
credentials. It does not claim to provide a complete production delegation
model. Production implementation would require organisation-specific role
design, separate requester and approver identities, protected automation
credentials, privileged-access workstations, access reviews and centrally
monitored role assignments.

