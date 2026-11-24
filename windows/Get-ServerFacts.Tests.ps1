Describe 'Get-ServerFacts' {
    BeforeAll {
        $script:facts = & "$PSScriptRoot/Get-ServerFacts.ps1" -Role 'ci-runner' | ConvertFrom-Json
    }

    It 'reports windows and the role it was given' {
        $facts.os | Should -Be 'windows'
        $facts.role | Should -Be 'ci-runner'
    }

    It 'has a host name and an ISO patch date' {
        $facts.name | Should -Not -BeNullOrEmpty
        $facts.last_patched | Should -Match '^\d{4}-\d{2}-\d{2}$'
    }

    It 'lists at least one fixed volume with a size and one usage sample' {
        @($facts.volumes).Count | Should -BeGreaterThan 0
        $v = @($facts.volumes)[0]
        $v.size_gb | Should -BeGreaterThan 0
        @($v.history).Count | Should -Be 1
        $v.history[0].used_gb | Should -BeLessOrEqual $v.size_gb
    }
}
