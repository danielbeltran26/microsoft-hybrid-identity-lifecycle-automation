# Testing and Assurance Strategy

## Purpose

This project separates repository-level quality checks from environment-bound
identity validation. A successful script process is not treated as proof that
the requested identity state was achieved.

## Assurance layers

| Layer | What it checks | Where it runs | Directory changes |
|---|---|---|---|
| PowerShell parsing | Every public `.ps1` file is syntactically valid | GitHub Actions or a local PowerShell session | None |
| Static analysis | Error-severity PowerShell quality findings | GitHub Actions with PSScriptAnalyzer | None |
| Repository contracts | Required files, approved dataset schema, evidence counts and README summary | Pester on GitHub Actions | None |
| Preflight validation | Host, domain, dataset hash, schema, collisions, managers, groups and OUs | DC01 before an executor | None |
| Transaction validation | Approved execution order, correlation IDs and audit results | DC01 after each lifecycle phase | Read-only |
| Effective AD DS state | Attributes, manager, OU placement, enablement and direct memberships | DC01 | Read-only |
| Cloud-state validation | Synchronized population, attributes, enablement and AD-sourced memberships | Azure Cloud Shell through Microsoft Graph | Read-only |
| Portal evidence | Scope, agent health, provisioning action and visible resulting state | Microsoft Entra admin centre | None during evidence capture |
| Final reconciliation | Approved dataset, three lifecycle audits and final retained Leaver state | DC01 | Read-only |

## Automated repository checks

The workflow in `.github/workflows/powershell-validation.yml` runs on pushes and
pull requests affecting project code or documentation. It:

1. installs current Pester and PSScriptAnalyzer modules;
2. parses all public PowerShell scripts without executing them;
3. runs error-severity static analysis;
4. validates the approved integrated dataset contract;
5. confirms the expected 25 scripts and 19 Milestone 8 screenshots; and
6. confirms that the project README contains the executive summary
   and links to the testing strategy.

These checks intentionally do not import the Active Directory module, request a
Microsoft Graph token or contact the laboratory environment.

## Environment-bound tests

AD DS and Microsoft Entra integration tests remain explicit operational
checkpoints because a hosted runner cannot reproduce `corporate.test`, DC01,
SYNC01 or the protected `IAM-Lab` directory state. The runbooks define the
required order and stop conditions.

The final validator intentionally contains approved laboratory constants such
as exact population totals, correlation IDs and the dataset SHA-256 value.
Those values make it a deterministic evidence validator rather than a generic
deployment script.

## Production evolution

A production implementation would add isolated test directories, mocked unit
tests for directory adapters, signed releases, peer-reviewed change control,
protected branches, secret scanning, immutable centralized audit retention and
deployment promotion between development, test and production environments.
