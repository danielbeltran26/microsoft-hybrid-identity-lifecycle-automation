BeforeAll {
    $RepoRoot = Split-Path -Parent $PSScriptRoot
    $ScriptRoot = Join-Path $RepoRoot 'scripts'
    $DataPath = Join-Path $RepoRoot 'data/iam-project1-integrated-lifecycle-test.csv'
    $ReadmePath = Join-Path $RepoRoot 'README.md'
}

Describe 'PowerShell repository quality' {
    It 'contains the expected 25 public PowerShell scripts' {
        @(Get-ChildItem -LiteralPath $ScriptRoot -Filter '*.ps1' -File).Count |
            Should -Be 25
    }

    It 'parses every public PowerShell script without errors' {
        $Failures = @(
            Get-ChildItem -LiteralPath $ScriptRoot -Filter '*.ps1' -File |
                ForEach-Object {
                    $Tokens = $null
                    $Errors = $null
                    [void][System.Management.Automation.Language.Parser]::ParseFile(
                        $_.FullName,
                        [ref]$Tokens,
                        [ref]$Errors
                    )
                    foreach ($ErrorRecord in @($Errors)) {
                        [pscustomobject]@{
                            Script = $_.Name
                            Message = $ErrorRecord.Message
                        }
                    }
                }
        )

        $Failures | Should -BeNullOrEmpty
    }
}

Describe 'Approved integrated lifecycle dataset' {
    BeforeAll {
        $Records = @(Import-Csv -LiteralPath $DataPath)
        $RequiredColumns = @(
            'TestID', 'EmployeeID', 'GivenName', 'Surname', 'DisplayName',
            'SamAccountName', 'UserPrincipalName', 'JoinerDepartment',
            'JoinerGroups', 'MoverDepartment', 'MoverGroups', 'LeaverOU',
            'JoinerApprovalID', 'MoverApprovalID', 'LeaverApprovalID',
            'ApprovalStatus', 'RequestedBy', 'ApprovedBy', 'ApprovalDate',
            'BusinessJustification'
        )
    }

    It 'contains exactly one approved IAM3001 record' {
        $Records.Count | Should -Be 1
        $Records[0].TestID | Should -Be 'M08-E2E-001'
        $Records[0].EmployeeID | Should -Be 'IAM3001'
        $Records[0].ApprovalStatus | Should -Be 'Approved'
    }

    It 'contains every required lifecycle column' {
        $Columns = @($Records[0].PSObject.Properties.Name)
        @($RequiredColumns | Where-Object { $_ -notin $Columns }) |
            Should -BeNullOrEmpty
    }

    It 'defines five Joiner groups and five Mover groups' {
        @($Records[0].JoinerGroups -split ';').Count | Should -Be 5
        @($Records[0].MoverGroups -split ';').Count | Should -Be 5
    }
}

Describe 'Project evidence and documentation contract' {
    It 'contains exactly 19 Milestone 8 screenshots' {
        $ScreenshotRoot = Join-Path $RepoRoot 'screenshots'
        @(Get-ChildItem -LiteralPath $ScreenshotRoot -Filter 'm08-*.png' -File).Count |
            Should -Be 19
    }

    It 'contains the final lifecycle validation screenshot' {
        Test-Path -LiteralPath (
            Join-Path $RepoRoot 'screenshots/m08-19-integrated-lifecycle-final-validation.png'
        ) -PathType Leaf | Should -BeTrue
    }

    It 'contains the executive summary and testing-strategy link' {
        $Readme = Get-Content -LiteralPath $ReadmePath -Raw
        $Readme | Should -Match '## Executive overview'
        $Readme | Should -Match 'docs/Testing-Strategy\.md'
    }

    It 'documents all 19 approved screenshots in the integrated runbook' {
        $Runbook = Get-Content -LiteralPath (
            Join-Path $RepoRoot 'runbooks/04-integrated-hybrid-lifecycle-test.md'
        ) -Raw
        $Runbook | Should -Match 'all 19 approved screenshots'
    }
}

