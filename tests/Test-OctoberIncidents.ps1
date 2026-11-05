param([string]$ScannerRoot = (Split-Path -Parent $PSScriptRoot))
$ErrorActionPreference = 'Stop'
$ScannerTestRoot = [IO.Path]::GetFullPath($ScannerRoot)
$source = [IO.File]::ReadAllText((Join-Path $ScannerTestRoot 'Start-InvisiblePayloadScanner.ps1'))
$end = $source.IndexOf('if ($SelfTest) {')
if ($end -lt 0) { throw 'Test import boundary missing.' }
. ([scriptblock]::Create($source.Substring(0, $end).Replace('$PSScriptRoot', '$ScannerTestRoot')))
$testRoot = Join-Path (Split-Path -Parent $PSScriptRoot) ('_drafts/incident-tests-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($testRoot)
$script:passed = 0
function Assert-Incident($Condition, [string]$Label) {
    if (-not $Condition) { throw ('FAILED: ' + $Label) }
    $script:passed++
}
function New-IncidentCase([string]$Name) {
    $path = Join-Path $testRoot $Name
    [void][IO.Directory]::CreateDirectory($path)
    return $path
}
function Write-IncidentFixture([string]$Root, [string]$Name, [string]$Text) {
    $path = Join-Path $Root $Name
    [void][IO.Directory]::CreateDirectory((Split-Path -Parent $path))
    [IO.File]::WriteAllText($path, $Text, [Text.UTF8Encoding]::new($false))
    return $path
}
function Scan-Incident([string]$Root, [string]$Mode = 'supply-chain-ioc', [int]$MaxMb = 1) {
    Invoke-Scanner -Options ([pscustomobject]@{
        rootPath=$Root; scanMode=$Mode; filter='*'; excludeDirs='.git'; maxFileSizeMb=$MaxMb
        ruleId='glassworm_variation_selectors'; minRun=8; nodeModulesFullScan=$false
    })
}
# Synthetic text only: never execute payloads, lifecycle scripts, npm, or an IDE.
# Keep all fixtures under _drafts for review; no direct deletion or cleanup fallback.
$rules = Get-SupplyChainRules
Assert-Incident ($rules.loadStatus -eq 'loaded' -and $rules.updatedAt -eq '2026-11-05') 'new pack is required and dated'
$targeted = New-IncidentCase 'tensorlake-targeted'
$manifestPath = Write-IncidentFixture $targeted 'node_modules/tensorlake/package.json' '{"name":"tensorlake","version":"0.5.144","scripts":{"preinstall":"node lib/setup.mjs"}}'
$loaderPath = Write-IncidentFixture $targeted 'node_modules/tensorlake/lib/setup.mjs' 'const payloadName = "Math_Symbol.js";'
$otherPath = Write-IncidentFixture $targeted 'node_modules/unrelated/lib/setup.mjs' 'const payloadName = "Math_Symbol.js";'
$before = (Get-FileHash -LiteralPath $loaderPath -Algorithm SHA256).Hash
$r = Scan-Incident $targeted
Assert-Incident (@($r.results | Where-Object { $_.category -eq 'known-malicious-package-version' -and $_.match -eq 'tensorlake@0.5.144' -and $_.severity -eq 'critical' }).Count -eq 1) 'exact installed npm version'
Assert-Incident (@($r.results | Where-Object { $_.path -eq $loaderPath -and $_.category -eq 'known-ioc-string' -and $_.severity -eq 'high' }).Count -eq 1) 'targeted loader scanned with full node_modules off'
Assert-Incident (@($r.results | Where-Object { $_.path -eq $otherPath }).Count -eq 0) 'unrelated node_modules code not scanned'
Assert-Incident ($r.coverage.status -eq 'complete' -and $r.toolVersion -eq '0.6.0') 'version and complete coverage'
Assert-Incident ((Get-FileHash -LiteralPath $loaderPath -Algorithm SHA256).Hash -eq $before) 'scan is read-only'

foreach ($version in @('0.5.143','0.5.145','0.5.1440','0.5.144-beta.1')) {
    $case = New-IncidentCase ('safe-tensorlake-' + $version)
    [void](Write-IncidentFixture $case 'package.json' ('{"name":"tensorlake","version":"' + $version + '"}'))
    $r = Scan-Incident $case
    Assert-Incident ($r.matchCount -eq 0) 'adjacent or suffix version is not an exact affected version'
}
$lookalike = New-IncidentCase 'tensorlake-lookalike'
[void](Write-IncidentFixture $lookalike 'node_modules/tensorlake-extra/package.json' '{"name":"tensorlake-extra","version":"0.5.144"}')
[void](Write-IncidentFixture $lookalike 'node_modules/tensorlake-extra/setup.mjs' 'const payloadName = "Math_Symbol.js";')
Assert-Incident ((Scan-Incident $lookalike).matchCount -eq 0) 'lookalike npm family not included'
$python = New-IncidentCase 'python-is-not-npm'
[void](Write-IncidentFixture $python 'requirements.txt' 'tensorlake==0.5.144')
Assert-Incident ((Scan-Incident $python).matchCount -eq 0) 'no PyPI version attribution'
$dependency = New-IncidentCase 'dependency-range'
[void](Write-IncidentFixture $dependency 'package.json' '{"dependencies":{"tensorlake":"^0.5.144"}}')
$r = Scan-Incident $dependency
Assert-Incident (@($r.results | Where-Object { $_.category -eq 'dependency-version-candidate' }).Count -eq 1 -and $r.summary.critical -eq 0) 'dependency range remains a candidate'
foreach ($name in @('package-lock.json','pnpm-lock.yaml','yarn.lock','bun.lock')) {
    $case = New-IncidentCase $name
    [void](Write-IncidentFixture $case $name '{"tensorlake":{"version":"0.5.144"}}')
    $r = Scan-Incident $case
    Assert-Incident (@($r.results | Where-Object { $_.category -eq 'lockfile-version-candidate' -and $_.severity -eq 'medium' }).Count -eq 1 -and $r.summary.critical -eq 0) 'lockfile nearby match remains candidate'
}

$markers = 'const endpoint = "134.209.82.225"; const keyLabel = "svc-telemetry";'
foreach ($version in @('2.1.312','2.1.313')) {
    foreach ($platform in @('win32-x64','darwin-arm64')) {
        $case = New-IncidentCase ($version + '-' + $platform)
        $extensionPath = '.cursor/extensions/anthropic.claude-code-' + $version + '-' + $platform
        [void](Write-IncidentFixture $case ($extensionPath + '/package.json') ('{"name":"claude-code","publisher":"Anthropic","version":"' + $version + '"}'))
        $payloadPath = Write-IncidentFixture $case ($extensionPath + '/extension.js') $markers
        $r = Scan-Incident $case
        $hit = @($r.results | Where-Object { $_.category -eq 'known-ioc-combination' })
        Assert-Incident ($hit.Count -eq 1 -and $hit[0].severity -eq 'high' -and $hit[0].signalSeverity -eq 'high') 'both affected extension builds detected'
        Assert-Incident ($hit[0].pathContext -eq 'editor-extension' -and $hit[0].evidenceKind -eq 'ioc_combination') 'editor context and compound evidence'
        Assert-Incident ($r.responseGuidance.responses.Count -eq 1 -and $r.responseGuidance.responses[0].executionContext -eq 'package_or_code' -and $r.responseGuidance.responses[0].strongEvidenceFindingIds.Count -eq 0) 'does not infer execution or urgent disconnect from marker presence'
        Assert-Incident ($hit[0].recommendation -like '*uninstalling*' -and $hit[0].recommendation -like '*does not inspect SSH*') 'honest response scope'
    }
}
foreach ($version in @('2.1.312','2.1.313','2.1.314')) {
    $case = New-IncidentCase ('clean-extension-' + $version)
    [void](Write-IncidentFixture $case 'package.json' ('{"name":"claude-code","publisher":"Anthropic","version":"' + $version + '"}'))
    [void](Write-IncidentFixture $case 'extension.js' 'const label = "Claude Code";')
    Assert-Incident ((Scan-Incident $case).matchCount -eq 0) 'extension name and version alone do not warn'
}
$number = 0
foreach ($text in @(
    'const label = "svc-telemetry";',
    'const endpoint = "134.209.82.225";',
    'const endpoint = "1134.209.82.225"; const label = "svc-telemetry";',
    'const endpoint = "134.209.82.2250"; const label = "svc-telemetry";',
    'const endpoint = "134.209.82.225"; const label = "svc-telemetry-demo";',
    'const endpoint = "ifconfig.me"; const label = "svc-telemetry";'
)) {
    $case = New-IncidentCase ('negative-marker-' + $number++)
    [void](Write-IncidentFixture $case 'extension.js' $text)
    Assert-Incident ((Scan-Incident $case).matchCount -eq 0) 'single marker and lookalike are not campaign detections'
}
$split = New-IncidentCase 'markers-in-separate-files'
[void](Write-IncidentFixture $split 'a/extension.js' 'const endpoint = "134.209.82.225";')
[void](Write-IncidentFixture $split 'b/extension.js' 'const label = "svc-telemetry";')
Assert-Incident ((Scan-Incident $split).matchCount -eq 0) 'markers cannot combine across files'
$docs = New-IncidentCase 'quoted-indicators'
foreach ($name in @('README.md','report.json','extension.js.txt')) { [void](Write-IncidentFixture $docs $name $markers) }
Assert-Incident ((Scan-Incident $docs).matchCount -eq 0) 'documentation or report does not masquerade as extension bundle'
$loose = New-IncidentCase 'unpacked-extension'
[void](Write-IncidentFixture $loose 'extension/extension.js' $markers)
Assert-Incident (@((Scan-Incident $loose).results | Where-Object { $_.category -eq 'known-ioc-combination' }).Count -eq 1) 'unpacked extension works without installed directory naming'
$masked = New-IncidentCase 'masked-excerpt'
$syntheticToken = 'ghp_' + ('A' * 36)
[void](Write-IncidentFixture $masked 'extension.js' ('const endpoint="134.209.82.225"; const token="' + $syntheticToken + '"; const label="svc-telemetry";'))
$r = Scan-Incident $masked
Assert-Incident (@($r.results | Where-Object { $_.category -eq 'known-ioc-combination' }).Count -eq 1) 'masking does not suppress the compound finding'
Assert-Incident (-not ($r | ConvertTo-Json -Depth 20).Contains($syntheticToken)) 'synthetic token value is absent from report'
$self = New-IncidentCase 'selftest-context'
[void](Write-IncidentFixture $self '_selftest/extension.js' $markers)
$r = Invoke-Scanner -Options ([pscustomobject]@{rootPath=$self;scanMode='supply-chain-ioc';excludeDirs='.git';maxFileSizeMb=1})
Assert-Incident (@($r.results | Where-Object { $_.category -eq 'known-ioc-combination' -and $_.severity -eq 'info' -and $_.signalSeverity -eq 'high' }).Count -eq 1) 'selftest context preserves original signal'
Assert-Incident ($r.responseGuidance.responses.Count -eq 0) 'selftest evidence does not request user response'
$large = New-IncidentCase 'oversize-bundle'
[void](Write-IncidentFixture $large 'extension.js' ((' ' * 1048576) + $markers))
$r = Scan-Incident $large
Assert-Incident ($r.coverage.status -eq 'partial' -and $r.matchCount -eq 0) 'oversize file is incomplete not clean'

$originalRoot = $ScannerTestRoot
$ruleCopy = New-IncidentCase 'rule-validation'
Copy-Item -LiteralPath (Join-Path $ScannerTestRoot 'rules') -Destination $ruleCopy -Recurse
$ruleFile = Join-Path $ruleCopy 'rules/v0.6/october-2026-incidents.json'
$originalJson = [IO.File]::ReadAllText($ruleFile)
try {
    $ScannerTestRoot = $ruleCopy
    [void](Get-SupplyChainRules)
    foreach ($variant in @('broken-json','missing-field','empty-rules','one-pattern','duplicate-pattern','invalid-regex','empty-pattern','empty-id')) {
        $pack = $originalJson | ConvertFrom-Json
        $rule = $pack.rulesets[0].combinedIocs[0]
        switch ($variant) {
            'missing-field' { $pack.rulesets[0].PSObject.Properties.Remove('combinedIocs') }
            'empty-rules' { $pack.rulesets[0].combinedIocs = @() }
            'one-pattern' { $rule.allOfPatterns = @('svc-telemetry') }
            'duplicate-pattern' { $rule.allOfPatterns = @('same','same') }
            'invalid-regex' { $rule.allOfPatterns = @('[','svc-telemetry') }
            'empty-pattern' { $rule.allOfPatterns = @('','svc-telemetry') }
            'empty-id' { $rule.id = '' }
        }
        $json = $pack | ConvertTo-Json -Depth 12
        if ($variant -eq 'broken-json') { $json = '{broken' }
        [IO.File]::WriteAllText($ruleFile, $json)
        $rejected = $false
        try { [void](Get-SupplyChainRules) } catch { $rejected = $_.Exception.Message -eq 'rules_invalid' }
        Assert-Incident $rejected ('invalid pack fails explicitly: ' + $variant)
    }
    $pack = $originalJson | ConvertFrom-Json
    $pack.rulesets[0].combinedIocs[0].allOfPatterns = @('(a+)+$', 'svc-telemetry')
    [IO.File]::WriteAllText($ruleFile, ($pack | ConvertTo-Json -Depth 12))
    $timeout = New-IncidentCase 'combined-regex-timeout'
    [void](Write-IncidentFixture $timeout 'extension.js' (('a' * 10000) + '! svc-telemetry'))
    $r = Scan-Incident $timeout
    Assert-Incident ($r.coverage.status -eq 'partial' -and $r.coverage.checks.supplyChain.failedFiles -eq 1) 'combined regex timeout is incomplete'
    Assert-Incident ($r.errors.Count -eq 1 -and $r.errors[0].message -eq 'regex_timeout') 'combined regex timeout keeps safe error code'
    # Rename only the disposable copy, retain it for review.
    Move-Item -LiteralPath $ruleFile -Destination ($ruleFile + '.held')
    $rejected = $false
    try { [void](Get-SupplyChainRules) } catch { $rejected = $_.Exception.Message -eq 'rules_missing' }
    Assert-Incident $rejected 'missing sixth pack fails explicitly'
    Assert-Incident ((Scan-Incident $loose 'invisible-unicode').coverage.status -eq 'complete') 'unselected supply-chain rules are not required'
} finally { $ScannerTestRoot = $originalRoot }
'October incident checks passed: ' + $script:passed
'Synthetic fixtures retained: ' + $testRoot
