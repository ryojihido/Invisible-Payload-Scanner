$ErrorActionPreference = 'Stop'
$ScannerTestRoot = Split-Path -Parent $PSScriptRoot
$source = [IO.File]::ReadAllText((Join-Path $ScannerTestRoot 'Start-InvisiblePayloadScanner.ps1'))
$end = $source.IndexOf('if ($SelfTest) {')
if ($end -lt 0) { throw 'Test import boundary missing.' }
. ([scriptblock]::Create($source.Substring(0, $end).Replace('$PSScriptRoot', '$ScannerTestRoot')))
# This test needs a Windows volume supporting junctions. Project drives need not support them.
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('scanner-reparse-test-' + [guid]::NewGuid().ToString('N'))
$caseRoot = Join-Path $testRoot 'scan'
$targetRoot = Join-Path $testRoot 'target'
$linkPath = Join-Path $caseRoot 'linked-folder'
[void][IO.Directory]::CreateDirectory($caseRoot)
[void][IO.Directory]::CreateDirectory($targetRoot)
try {
    [IO.File]::WriteAllText((Join-Path $targetRoot 'hidden.js'), ([string][char]0xFE0F * 12))
    [void](New-Item -ItemType Junction -Path $linkPath -Target $targetRoot)
    try {
        $options = [pscustomobject]@{ rootPath=$caseRoot; scanMode='invisible-unicode'; filter='*'; ruleId='glassworm_variation_selectors'; minRun=3; maxFileSizeMb=1 }
        $r = Invoke-Scanner -Options $options
        if ($r.matchCount -ne 0 -or $r.coverage.status -ne 'not_assessed') { throw 'Junction was followed or reported complete.' }
        $options.rootPath = $linkPath
        $rejected = $false
        try { [void](Invoke-Scanner -Options $options) } catch { $rejected = $_.Exception.Message -eq 'reparse_root' }
        if (-not $rejected) { throw 'Junction root was not rejected.' }
        'Reparse boundary checks passed: 2'
    } finally { [IO.Directory]::Delete($linkPath) }
} finally {
    $resolved = [IO.Path]::GetFullPath($testRoot)
    $boundary = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\scanner-reparse-test-'
    if (-not $resolved.StartsWith($boundary, [StringComparison]::OrdinalIgnoreCase)) { throw 'Cleanup boundary mismatch.' }
    [IO.Directory]::Delete($resolved, $true)
}
