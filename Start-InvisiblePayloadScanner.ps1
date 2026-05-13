param(
    [int]$Port = 8787,
    [switch]$NoBrowser,
    [switch]$SelfTest
)

$ErrorActionPreference = "Stop"
$MaxRequestBodyBytes = 65536
$MaxFilterTextLength = 2000
$MaxCustomPatternLength = 1000
$MaxCandidateFiles = 200000

function New-ApiToken {
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    }
    finally {
        $rng.Dispose()
    }
    return [Convert]::ToBase64String($bytes).TrimEnd("=").Replace("+", "-").Replace("/", "_")
}

function Get-Rule {
    param(
        [string]$RuleId,
        [int]$MinRun,
        [string]$CustomPattern
    )

    $n = [Math]::Max(1, $MinRun)
    switch ($RuleId) {
        "glassworm_variation_selectors" {
            return @{
                id = $RuleId
                name = "GlassWorm-style variation selector run"
                pattern = "([\uFE00-\uFE0F]|\uDB40[\uDD00-\uDDEF]){" + $n + ",}"
            }
        }
        "any_variation_selector" {
            return @{
                id = $RuleId
                name = "Any Unicode variation selector run"
                pattern = "([\uFE00-\uFE0F]|\uDB40[\uDD00-\uDDEF]){" + $n + ",}"
            }
        }
        "zero_width_controls" {
            return @{
                id = $RuleId
                name = "Zero-width control character run"
                pattern = "([\u200B-\u200F\u2060-\u2064\uFEFF]){" + $n + ",}"
            }
        }
        "glassworm_decoder_pattern" {
            return @{
                id = $RuleId
                name = "GlassWorm-style visible decoder pattern"
                pattern = "codePointAt\s*\([\s\S]{0,800}(0xFE00|0xE0100)[\s\S]{0,800}(eval\s*\(|new\s+Function|Buffer\.from)"
            }
        }
        "bidi_controls" {
            return @{
                id = $RuleId
                name = "Bidirectional control character"
                pattern = "[\u202A-\u202E\u2066-\u2069]{" + $n + ",}"
            }
        }
        "hangul_filler" {
            return @{
                id = $RuleId
                name = "Hangul filler character"
                pattern = "\u3164{" + $n + ",}"
            }
        }
        "custom" {
            if ([string]::IsNullOrWhiteSpace($CustomPattern)) {
                throw "Custom pattern is empty."
            }
            return @{
                id = $RuleId
                name = "Custom regular expression"
                pattern = $CustomPattern
            }
        }
        default {
            return Get-Rule -RuleId "glassworm_variation_selectors" -MinRun $n -CustomPattern $null
        }
    }
}

function Get-FreePort {
    param([int]$StartPort)

    for ($candidate = $StartPort; $candidate -lt ($StartPort + 100); $candidate++) {
        $listener = $null
        try {
            $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse("127.0.0.1"), $candidate)
            $listener.Start()
            return $candidate
        }
        catch {
        }
        finally {
            if ($null -ne $listener) {
                $listener.Stop()
            }
        }
    }

    throw "No available local port found near $StartPort."
}

function Read-TextFile {
    param([string]$Path)

    $reader = $null
    try {
        $reader = [System.IO.StreamReader]::new($Path, [System.Text.Encoding]::UTF8, $true)
        return $reader.ReadToEnd()
    }
    finally {
        if ($null -ne $reader) {
            $reader.Dispose()
        }
    }
}

function Get-CodePointList {
    param([string]$Text)

    $items = New-Object System.Collections.Generic.List[string]
    for ($i = 0; $i -lt $Text.Length; $i++) {
        $ch = [char]$Text[$i]
        if ([char]::IsHighSurrogate($ch) -and ($i + 1) -lt $Text.Length -and [char]::IsLowSurrogate([char]$Text[$i + 1])) {
            $cp = [char]::ConvertToUtf32($Text, $i)
            $i++
        }
        else {
            $cp = [int][char]$Text[$i]
        }
        $items.Add(("U+{0:X}" -f $cp))
    }
    return ($items -join " ")
}

function Get-CodePointCount {
    param([string]$Text)

    $count = 0
    for ($i = 0; $i -lt $Text.Length; $i++) {
        $ch = [char]$Text[$i]
        if ([char]::IsHighSurrogate($ch) -and ($i + 1) -lt $Text.Length -and [char]::IsLowSurrogate([char]$Text[$i + 1])) {
            $i++
        }
        $count++
    }
    return $count
}

function Get-LineColumn {
    param(
        [string]$Text,
        [int]$Index
    )

    $line = 1
    $columnStart = 0
    for ($i = 0; $i -lt $Index; $i++) {
        $c = $Text[$i]
        if ($c -eq "`n") {
            $line++
            $columnStart = $i + 1
        }
    }

    return @{
        line = $line
        column = ($Index - $columnStart + 1)
    }
}

function ConvertTo-VisibleSnippet {
    param(
        [string]$Text,
        [int]$Index,
        [int]$Length
    )

    $start = [Math]::Max(0, $Index - 40)
    $end = [Math]::Min($Text.Length, $Index + $Length + 40)
    $builder = [System.Text.StringBuilder]::new()

    for ($i = $start; $i -lt $end; $i++) {
        $ch = [char]$Text[$i]
        if ([char]::IsHighSurrogate($ch) -and ($i + 1) -lt $Text.Length -and [char]::IsLowSurrogate([char]$Text[$i + 1])) {
            $cp = [char]::ConvertToUtf32($Text, $i)
            $i++
        }
        else {
            $cp = [int][char]$ch
        }

        if (($cp -ge 0xFE00 -and $cp -le 0xFE0F) -or ($cp -ge 0xE0100 -and $cp -le 0xE01EF)) {
            [void]$builder.Append("[VS U+")
            [void]$builder.Append(("{0:X}" -f $cp))
            [void]$builder.Append("]")
        }
        elseif (($cp -ge 0x200B -and $cp -le 0x200F) -or ($cp -ge 0x2060 -and $cp -le 0x2064) -or $cp -eq 0xFEFF) {
            [void]$builder.Append("[ZW U+")
            [void]$builder.Append(("{0:X}" -f $cp))
            [void]$builder.Append("]")
        }
        elseif ($cp -eq 10 -or $cp -eq 13) {
            [void]$builder.Append(" ")
        }
        elseif ($cp -lt 32) {
            [void]$builder.Append("[CTRL]")
        }
        else {
            [void]$builder.Append([char]$cp)
        }
    }

    return $builder.ToString()
}

function Test-NameMatchesAny {
    param(
        [string]$Name,
        [string[]]$Patterns
    )

    foreach ($pattern in $Patterns) {
        if ($Name -like $pattern) {
            return $true
        }
    }
    return $false
}

function Test-OptionExists {
    param(
        $Options,
        [string]$Name
    )

    return ($Options.PSObject.Properties.Match($Name).Count -gt 0)
}

function ConvertFrom-PastedPath {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return ""
    }

    $normalized = $Path.Trim()
    if ($normalized.Length -ge 2) {
        $first = $normalized[0]
        $last = $normalized[$normalized.Length - 1]
        if (($first -eq '"' -and $last -eq '"') -or ($first -eq "'" -and $last -eq "'")) {
            $normalized = $normalized.Substring(1, $normalized.Length - 2).Trim()
        }
    }
    return $normalized
}

function Get-DefaultSupplyChainRules {
    return [pscustomobject]@{
        schemaVersion = 1
        updatedAt = "2026-05-13"
        loadStatus = "fallback"
        loadMessage = "rules/ioc-rules.json could not be loaded. Built-in minimal rules are active."
        rulesets = @(
            [pscustomobject]@{
                id = "built-in-minimal"
                name = "Built-in minimal IOC rules"
                sourceNote = "Fallback rules used when rules/ioc-rules.json cannot be read."
                stringIocs = @(
                    "github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c",
                    "@tanstack/setup",
                    "router_init.js",
                    "tanstack_runner.js",
                    "filev2.getsession.org",
                    "seed1.getsession.org",
                    "seed2.getsession.org",
                    "seed3.getsession.org"
                )
                packageRules = @(
                    [pscustomobject]@{
                        namePattern = "^@tanstack/"
                        severity = "medium"
                        message = "TanStack package name found. Package name alone is not a malicious indicator; check version and IoCs."
                    }
                )
                packageVersionRules = @()
                dangerousCommandTerms = @("powershell", "pwsh", "cmd.exe", "curl", "wget", "iwr", "irm", "node -e", "python -c", "child_process", "exec", "spawn", "eval", "Buffer.from", "fromCharCode")
                installScriptNames = @("preinstall", "install", "postinstall", "prepare", "prepack", "postpack")
            }
        )
    }
}

function Get-SupplyChainRules {
    $rulesPath = Join-Path $PSScriptRoot "rules\ioc-rules.json"
    if (-not (Test-Path -LiteralPath $rulesPath -PathType Leaf)) {
        return Get-DefaultSupplyChainRules
    }

    try {
        $rules = (Read-TextFile -Path $rulesPath) | ConvertFrom-Json
        $rules | Add-Member -NotePropertyName "loadStatus" -NotePropertyValue "loaded" -Force
        $rules | Add-Member -NotePropertyName "loadMessage" -NotePropertyValue "Bundled IOC rules loaded." -Force
        return $rules
    }
    catch {
        return Get-DefaultSupplyChainRules
    }
}

function ConvertTo-Array {
    param($Value)

    if ($null -eq $Value) {
        return @()
    }
    if ($Value -is [System.Array]) {
        return @($Value)
    }
    return @($Value)
}

function ConvertTo-MaskedText {
    param([string]$Text)

    if ([string]::IsNullOrEmpty($Text)) {
        return $Text
    }

    $masked = $Text
    $patterns = @(
        "gh[pousr]_[A-Za-z0-9_]{12,}",
        "github_pat_[A-Za-z0-9_]{20,}",
        "npm_[A-Za-z0-9_]{12,}",
        "sk-[A-Za-z0-9]{16,}",
        "xox[baprs]-[A-Za-z0-9-]{16,}",
        "AKIA[0-9A-Z]{12,}",
        "-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]{0,80}"
    )
    foreach ($pattern in $patterns) {
        $masked = [System.Text.RegularExpressions.Regex]::Replace(
            $masked,
            $pattern,
            { param($m) ($m.Value.Substring(0, [Math]::Min(4, $m.Value.Length)) + "****MASKED****") },
            [System.Text.RegularExpressions.RegexOptions]::IgnoreCase,
            [TimeSpan]::FromSeconds(1)
        )
    }
    return $masked
}

function Get-TextSnippet {
    param(
        [string]$Text,
        [int]$Index,
        [int]$Length
    )

    $start = [Math]::Max(0, $Index - 80)
    $end = [Math]::Min($Text.Length, $Index + $Length + 80)
    $snippet = $Text.Substring($start, $end - $start)
    $snippet = $snippet -replace "[`r`n`t]+", " "
    return ConvertTo-MaskedText -Text $snippet
}

function New-Finding {
    param(
        [string]$Severity,
        [string]$Category,
        [string]$Path,
        [int]$Line = 0,
        [int]$Column = 0,
        [string]$Match = "",
        [string]$Message,
        [string]$Recommendation,
        [string]$Snippet = "",
        [string]$Source = "supply-chain-ioc",
        [int]$RunLength = 0,
        [string]$CodePoints = ""
    )

    return @{
        severity = $Severity.ToLowerInvariant()
        category = $Category
        path = $Path
        line = $Line
        column = $Column
        match = (ConvertTo-MaskedText -Text $Match)
        message = $Message
        recommendation = $Recommendation
        snippet = (ConvertTo-MaskedText -Text $Snippet)
        source = $Source
        pathContext = (Get-PathContext -Path $Path)
        runLength = $RunLength
        codePoints = $CodePoints
    }
}

function Get-EmptySeveritySummary {
    return @{
        critical = 0
        high = 0
        medium = 0
        low = 0
        info = 0
    }
}

function Add-SeverityCount {
    param(
        [hashtable]$Summary,
        [string]$Severity
    )

    $key = $Severity.ToLowerInvariant()
    if (-not $Summary.ContainsKey($key)) {
        $Summary[$key] = 0
    }
    $Summary[$key]++
}

function Test-InNodeModules {
    param([string]$Path)

    return ($Path -match "(?i)(^|[\\/])node_modules([\\/]|$)")
}

function Get-PathContext {
    param([string]$Path)

    if ($Path -match "(?i)[\\/]\.antigravity[\\/]extensions[\\/]" -or $Path -match "(?i)[\\/]\.vscode[\\/]extensions[\\/]") {
        return "editor-extension"
    }
    if ($Path -match "(?i)[\\/]rules[\\/]ioc-rules\.json$") {
        return "scanner-rule-file"
    }
    if (Test-InNodeModules -Path $Path) {
        return "node_modules"
    }
    if ($Path -match "(?i)([\\/](README|docs|CHANGELOG)|\.(md|txt)$)") {
        return "documentation"
    }
    return "project-file"
}

function Get-RelativePath {
    param(
        [string]$Root,
        [string]$Path
    )

    if ($Path.StartsWith($Root, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $Path.Substring($Root.Length).TrimStart("\", "/")
    }
    return $Path
}

function Test-SupplyCandidateFile {
    param(
        [System.IO.FileInfo]$File,
        [string]$RootPath,
        [bool]$NodeModulesFullScan
    )

    $name = $File.Name
    $fullPath = $File.FullName
    $relative = (Get-RelativePath -Root $RootPath -Path $fullPath).Replace("/", "\")
    $extension = $File.Extension.ToLowerInvariant()
    $isNodeModules = Test-InNodeModules -Path $fullPath

    if ($isNodeModules -and -not $NodeModulesFullScan) {
        return ($name -eq "package.json")
    }

    if ($name -in @("package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb", ".npmrc")) {
        return $true
    }
    if ($name -like ".env*") {
        return $true
    }
    if ($relative -in @(".vscode\tasks.json", ".vscode\launch.json", ".claude\settings.json", ".claude\settings.local.json")) {
        return $true
    }
    if ($relative -like ".github\workflows\*.yml" -or $relative -like ".github\workflows\*.yaml") {
        return $true
    }
    if ($extension -in @(".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".json", ".yaml", ".yml", ".toml", ".ps1", ".cmd", ".bat", ".sh")) {
        return $true
    }
    return $false
}

function Test-TextContainsAny {
    param(
        [string]$Text,
        [string[]]$Terms
    )

    foreach ($term in $Terms) {
        if ([string]::IsNullOrWhiteSpace($term)) {
            continue
        }
        if ($Text.IndexOf($term, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
            return $true
        }
    }
    return $false
}

function Get-FirstTermMatch {
    param(
        [string]$Text,
        [string[]]$Terms
    )

    foreach ($term in $Terms) {
        if ([string]::IsNullOrWhiteSpace($term)) {
            continue
        }
        $index = $Text.IndexOf($term, [System.StringComparison]::OrdinalIgnoreCase)
        if ($index -ge 0) {
            return @{
                term = $term
                index = $index
            }
        }
    }
    return $null
}

function Get-PackageVersionRule {
    param(
        $Rules,
        [string]$Name,
        [string]$Version
    )

    if ([string]::IsNullOrWhiteSpace($Name) -or [string]::IsNullOrWhiteSpace($Version)) {
        return $null
    }

    foreach ($ruleset in (ConvertTo-Array $Rules.rulesets)) {
        foreach ($rule in (ConvertTo-Array $ruleset.packageVersionRules)) {
            if ([string]$rule.name -ne $Name) {
                continue
            }
            foreach ($candidate in (ConvertTo-Array $rule.versions)) {
                if ([string]$candidate -eq $Version) {
                    return $rule
                }
            }
        }
    }
    return $null
}

function Add-PackageNameFindings {
    param(
        [System.Collections.Generic.List[object]]$Findings,
        $Rules,
        [string]$Path,
        [string]$Name,
        [string]$Version,
        [int]$Line = 0
    )

    if ([string]::IsNullOrWhiteSpace($Name)) {
        return
    }

    $exact = Get-PackageVersionRule -Rules $Rules -Name $Name -Version $Version
    if ($null -ne $exact) {
        $recommendation = "Do not run install/build for this project. Confirm the source, clean the lockfile, and use patched version $($exact.patchedVersion) or later if applicable."
        $Findings.Add((New-Finding -Severity "critical" -Category "known-malicious-package-version" -Path $Path -Line $Line -Match "$Name@$Version" -Message "Known affected TanStack package version matched." -Recommendation $recommendation))
        return
    }

    foreach ($ruleset in (ConvertTo-Array $Rules.rulesets)) {
        foreach ($rule in (ConvertTo-Array $ruleset.packageRules)) {
            try {
                if ([System.Text.RegularExpressions.Regex]::IsMatch($Name, [string]$rule.namePattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase, [TimeSpan]::FromSeconds(1))) {
                    $matchText = $Name
                    if (-not [string]::IsNullOrWhiteSpace($Version)) {
                        $matchText = "$Name@$Version"
                    }
                    $Findings.Add((New-Finding -Severity ([string]$rule.severity) -Category "package-name-candidate" -Path $Path -Line $Line -Match $matchText -Message ([string]$rule.message) -Recommendation "Package name alone is not proof of compromise. Check the exact version, lockfile, and official advisory before running install."))
                    return
                }
            }
            catch {
            }
        }
    }
}

function Get-JsonPropertyValue {
    param(
        $Object,
        [string]$Name
    )

    if ($null -eq $Object) {
        return $null
    }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }
    return $property.Value
}

function Add-DependencyFindings {
    param(
        [System.Collections.Generic.List[object]]$Findings,
        $Rules,
        [string]$Path,
        $Manifest
    )

    foreach ($sectionName in @("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")) {
        $section = Get-JsonPropertyValue -Object $Manifest -Name $sectionName
        if ($null -eq $section) {
            continue
        }
        foreach ($dep in $section.PSObject.Properties) {
            $depName = [string]$dep.Name
            $depVersion = [string]$dep.Value
            foreach ($exactRule in (ConvertTo-Array ((ConvertTo-Array $Rules.rulesets)[0].packageVersionRules))) {
                if ([string]$exactRule.name -ne $depName) {
                    continue
                }
                foreach ($badVersion in (ConvertTo-Array $exactRule.versions)) {
                    if ($depVersion -match ("(^|[^0-9A-Za-z.])" + [System.Text.RegularExpressions.Regex]::Escape([string]$badVersion) + "($|[^0-9A-Za-z.])")) {
                        $Findings.Add((New-Finding -Severity "high" -Category "dependency-version-candidate" -Path $Path -Match "$depName@$depVersion" -Message "Dependency spec references a known affected package version." -Recommendation "Stop before install. Regenerate from a clean lockfile and update to the patched version listed in the advisory."))
                    }
                }
            }
            Add-PackageNameFindings -Findings $Findings -Rules $Rules -Path $Path -Name $depName -Version ""
        }
    }
}

function Add-InstallScriptFindings {
    param(
        [System.Collections.Generic.List[object]]$Findings,
        $Rules,
        [string]$Path,
        $Manifest
    )

    $scripts = Get-JsonPropertyValue -Object $Manifest -Name "scripts"
    if ($null -eq $scripts) {
        return
    }

    $installNames = @()
    $dangerTerms = @()
    foreach ($ruleset in (ConvertTo-Array $Rules.rulesets)) {
        $installNames += (ConvertTo-Array $ruleset.installScriptNames)
        $dangerTerms += (ConvertTo-Array $ruleset.dangerousCommandTerms)
    }

    foreach ($name in $installNames) {
        $scriptValue = Get-JsonPropertyValue -Object $scripts -Name ([string]$name)
        if ($null -eq $scriptValue) {
            continue
        }
        $scriptText = [string]$scriptValue
        $dangerMatch = Get-FirstTermMatch -Text $scriptText -Terms $dangerTerms
        if ($null -ne $dangerMatch) {
            $Findings.Add((New-Finding -Severity "high" -Category "install-script-danger-term" -Path $Path -Match "${name}: $($dangerMatch.term)" -Message "Install-time script contains a shell, network, or obfuscation-related term." -Recommendation "Do not run install until you understand this lifecycle script." -Snippet $scriptText))
        }
        else {
            $Findings.Add((New-Finding -Severity "medium" -Category "install-script-present" -Path $Path -Match $name -Message "Install-time lifecycle script is present." -Recommendation "This can be legitimate, but unknown projects should not be installed until the script is reviewed." -Snippet $scriptText))
        }
    }
}

function Add-KnownIocFindings {
    param(
        [System.Collections.Generic.List[object]]$Findings,
        $Rules,
        [string]$Path,
        [string]$Text
    )

    foreach ($ruleset in (ConvertTo-Array $Rules.rulesets)) {
        foreach ($ioc in (ConvertTo-Array $ruleset.stringIocs)) {
            if ([string]::IsNullOrWhiteSpace($ioc)) {
                continue
            }
            $index = $Text.IndexOf([string]$ioc, [System.StringComparison]::OrdinalIgnoreCase)
            if ($index -lt 0) {
                continue
            }
            $pos = Get-LineColumn -Text $Text -Index $index
            $severity = "critical"
            if (Test-InNodeModules -Path $Path) {
                $severity = "high"
            }
            if ($Path -match "(?i)[\\/]rules[\\/]ioc-rules\.json$") {
                $severity = "info"
            }
            if ($Path -match "(?i)([\\/](README|docs|CHANGELOG)|\.(md|txt)$)") {
                $severity = "low"
            }
            $Findings.Add((New-Finding -Severity $severity -Category "known-ioc-string" -Path $Path -Line $pos.line -Column $pos.column -Match ([string]$ioc) -Message "Known public IOC string matched." -Recommendation "Stop before running this project. Confirm the source, package versions, and official advisory." -Snippet (Get-TextSnippet -Text $Text -Index $index -Length ([string]$ioc).Length)))
        }
    }
}

function Add-VscodeTaskFindings {
    param(
        [System.Collections.Generic.List[object]]$Findings,
        $Rules,
        [string]$Path,
        [string]$Text
    )

    if ($Path -notmatch "(?i)[\\/]\.vscode[\\/]tasks\.json$") {
        return
    }

    $dangerTerms = @()
    foreach ($ruleset in (ConvertTo-Array $Rules.rulesets)) {
        $dangerTerms += (ConvertTo-Array $ruleset.dangerousCommandTerms)
    }
    $hasRunOn = ($Text -match '"runOn"\s*:\s*"folderOpen"')
    if ($hasRunOn -and (Test-TextContainsAny -Text $Text -Terms $dangerTerms)) {
        $Findings.Add((New-Finding -Severity "critical" -Category "vscode-folder-open-task" -Path $Path -Match "runOn: folderOpen" -Message "VS Code task may run automatically when the folder opens and contains command-like terms." -Recommendation "Open unknown projects in Restricted Mode and inspect .vscode/tasks.json before using VS Code."))
    }
    elseif ($hasRunOn) {
        $Findings.Add((New-Finding -Severity "high" -Category "vscode-folder-open-task" -Path $Path -Match "runOn: folderOpen" -Message "VS Code task may run automatically when the folder opens." -Recommendation "Inspect the task command before opening this project normally."))
    }
    elseif ($Text -match '"type"\s*:\s*"(shell|process)"') {
        $Findings.Add((New-Finding -Severity "medium" -Category "vscode-shell-task" -Path $Path -Match "shell/process task" -Message "VS Code shell/process task is defined." -Recommendation "This can be legitimate, but review unknown project tasks before running them."))
    }
    else {
        $Findings.Add((New-Finding -Severity "info" -Category "vscode-tasks-present" -Path $Path -Match "tasks.json" -Message "VS Code tasks.json is present." -Recommendation "Review tasks before trusting an unknown project."))
    }
}

function Add-ClaudeSettingsFindings {
    param(
        [System.Collections.Generic.List[object]]$Findings,
        $Rules,
        [string]$Path,
        [string]$Text
    )

    if ($Path -notmatch "(?i)[\\/]\.claude[\\/]settings(\.local)?\.json$") {
        return
    }

    $dangerTerms = @()
    foreach ($ruleset in (ConvertTo-Array $Rules.rulesets)) {
        $dangerTerms += (ConvertTo-Array $ruleset.dangerousCommandTerms)
    }

    if ($Text -match '"hooks"\s*:') {
        if (Test-TextContainsAny -Text $Text -Terms $dangerTerms) {
            $Findings.Add((New-Finding -Severity "high" -Category "ai-agent-hooks-danger-term" -Path $Path -Match "hooks" -Message "AI agent hooks are present and contain command-like terms." -Recommendation "Do not let an AI agent open or auto-run this project until the hooks are reviewed."))
        }
        else {
            $Findings.Add((New-Finding -Severity "medium" -Category "ai-agent-hooks-present" -Path $Path -Match "hooks" -Message "AI agent hooks are present." -Recommendation "Hooks can be legitimate automation, but unknown project hooks should be reviewed first."))
        }
    }
    else {
        $Findings.Add((New-Finding -Severity "info" -Category "claude-settings-present" -Path $Path -Match ".claude/settings" -Message "Claude settings file is present." -Recommendation "Review agent settings before trusting an unknown project."))
    }
}

function Add-LockfileVersionFindings {
    param(
        [System.Collections.Generic.List[object]]$Findings,
        $Rules,
        [string]$Path,
        [string]$Text
    )

    if ($Path -notmatch "(?i)(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|bun\.lockb?)$") {
        return
    }

    foreach ($ruleset in (ConvertTo-Array $Rules.rulesets)) {
        foreach ($rule in (ConvertTo-Array $ruleset.packageVersionRules)) {
            $name = [string]$rule.name
            $nameIndex = $Text.IndexOf($name, [System.StringComparison]::OrdinalIgnoreCase)
            if ($nameIndex -lt 0) {
                continue
            }
            foreach ($version in (ConvertTo-Array $rule.versions)) {
                $versionText = [string]$version
                $searchFrom = $nameIndex
                while ($searchFrom -ge 0 -and $searchFrom -lt $Text.Length) {
                    $currentNameIndex = $Text.IndexOf($name, $searchFrom, [System.StringComparison]::OrdinalIgnoreCase)
                    if ($currentNameIndex -lt 0) {
                        break
                    }
                    $windowStart = [Math]::Max(0, $currentNameIndex - 260)
                    $windowEnd = [Math]::Min($Text.Length, $currentNameIndex + $name.Length + 520)
                    $window = $Text.Substring($windowStart, $windowEnd - $windowStart)
                    if ($window.IndexOf($versionText, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                        $pos = Get-LineColumn -Text $Text -Index $currentNameIndex
                        $Findings.Add((New-Finding -Severity "medium" -Category "lockfile-version-candidate" -Path $Path -Line $pos.line -Column $pos.column -Match "$name@$versionText" -Message "Lockfile contains a known affected package name near a known affected version string." -Recommendation "This is a candidate, not proof. Before installing, open the lockfile entry and confirm that this exact package resolves to this version. If unsure, stop and compare with the official advisory." -Snippet (Get-TextSnippet -Text $Text -Index $currentNameIndex -Length $name.Length)))
                        break
                    }
                    $searchFrom = $currentNameIndex + $name.Length
                }
            }
        }
    }
}

function Scan-SupplyChainFile {
    param(
        [System.Collections.Generic.List[object]]$Findings,
        $Rules,
        [System.IO.FileInfo]$File
    )

    $text = Read-TextFile -Path $File.FullName
    Add-KnownIocFindings -Findings $Findings -Rules $Rules -Path $File.FullName -Text $text
    Add-VscodeTaskFindings -Findings $Findings -Rules $Rules -Path $File.FullName -Text $text
    Add-ClaudeSettingsFindings -Findings $Findings -Rules $Rules -Path $File.FullName -Text $text
    Add-LockfileVersionFindings -Findings $Findings -Rules $Rules -Path $File.FullName -Text $text

    if ($File.Name -eq "package.json") {
        try {
            $manifest = $text | ConvertFrom-Json
            $packageName = [string](Get-JsonPropertyValue -Object $manifest -Name "name")
            $packageVersion = [string](Get-JsonPropertyValue -Object $manifest -Name "version")
            Add-PackageNameFindings -Findings $Findings -Rules $Rules -Path $File.FullName -Name $packageName -Version $packageVersion
            Add-DependencyFindings -Findings $Findings -Rules $Rules -Path $File.FullName -Manifest $manifest
            Add-InstallScriptFindings -Findings $Findings -Rules $Rules -Path $File.FullName -Manifest $manifest
        }
        catch {
            $Findings.Add((New-Finding -Severity "low" -Category "package-json-parse-error" -Path $File.FullName -Match "package.json" -Message "package.json could not be parsed as JSON." -Recommendation "Review this file manually if it came from an unknown project."))
        }
    }
}

function Invoke-Scanner {
    param(
        $Options,
        [scriptblock]$Progress
    )

    $rootPath = ConvertFrom-PastedPath -Path ([string]$Options.rootPath)
    if ([string]::IsNullOrWhiteSpace($rootPath)) {
        throw "Root path is empty."
    }
    if (-not (Test-Path -LiteralPath $rootPath -PathType Container)) {
        throw "Root path does not exist or is not a folder: $rootPath"
    }

    $filterText = [string]$Options.filter
    if ([string]::IsNullOrWhiteSpace($filterText)) {
        $filterText = "*"
    }
    if ($filterText.Length -gt $MaxFilterTextLength) {
        throw "File filter is too long."
    }
    $filters = @($filterText -split "[;,]" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($filters.Count -eq 0) {
        $filters = @("*")
    }
    if ($filters.Count -gt 100) {
        throw "Too many file filters. Use 100 or fewer."
    }

    $excludeText = [string]$Options.excludeDirs
    if ([string]::IsNullOrWhiteSpace($excludeText)) {
        $excludeText = ".git;dist;build;coverage;.cache;.next;.nuxt;out;.tmp;temp"
    }
    if ($excludeText.Length -gt $MaxFilterTextLength) {
        throw "Excluded directory list is too long."
    }
    $excludeDirs = @($excludeText -split "[;,]" | ForEach-Object { $_.Trim() } | Where-Object { $_ })

    $excludeFileText = ""
    if (Test-OptionExists -Options $Options -Name "excludeFiles") {
        $excludeFileText = [string]$Options.excludeFiles
    }
    else {
        $excludeFileText = "README.md;*.md"
    }
    if ($excludeFileText.Length -gt $MaxFilterTextLength) {
        throw "Excluded file list is too long."
    }
    $excludeFiles = @($excludeFileText -split "[;,]" | ForEach-Object { $_.Trim() } | Where-Object { $_ })

    $minRun = 8
    if ($null -ne $Options.minRun) {
        $minRun = [int]$Options.minRun
    }
    $minRun = [Math]::Max(1, [Math]::Min(1000, $minRun))

    $maxFileSizeMb = 20
    if ($null -ne $Options.maxFileSizeMb) {
        $maxFileSizeMb = [double]$Options.maxFileSizeMb
    }
    $maxFileSizeMb = [Math]::Max(1, [Math]::Min(100, $maxFileSizeMb))
    $maxBytes = [int64]($maxFileSizeMb * 1024 * 1024)

    $scanMode = "invisible-unicode"
    if (Test-OptionExists -Options $Options -Name "scanMode" -and -not [string]::IsNullOrWhiteSpace([string]$Options.scanMode)) {
        $scanMode = [string]$Options.scanMode
    }
    if ($scanMode -notin @("invisible-unicode", "supply-chain-ioc", "full-safety-pre-scan")) {
        $scanMode = "invisible-unicode"
    }
    $runInvisibleScan = ($scanMode -in @("invisible-unicode", "full-safety-pre-scan"))
    $runSupplyChainScan = ($scanMode -in @("supply-chain-ioc", "full-safety-pre-scan"))

    $nodeModulesFullScan = $false
    if (Test-OptionExists -Options $Options -Name "supplyNodeModulesFullScan") {
        $nodeModulesFullScan = [bool]$Options.supplyNodeModulesFullScan
    }

    if ([string]$Options.ruleId -eq "custom" -and ([string]$Options.customPattern).Length -gt $MaxCustomPatternLength) {
        throw "Custom pattern is too long."
    }
    $rule = $null
    $regex = $null
    if ($runInvisibleScan) {
        $rule = Get-Rule -RuleId ([string]$Options.ruleId) -MinRun $minRun -CustomPattern ([string]$Options.customPattern)
        $regex = [System.Text.RegularExpressions.Regex]::new(
            [string]$rule.pattern,
            [System.Text.RegularExpressions.RegexOptions]::CultureInvariant,
            [TimeSpan]::FromSeconds(2)
        )
    }
    $supplyRules = Get-SupplyChainRules

    $binaryExtensions = @(
        ".7z", ".avi", ".bmp", ".cab", ".class", ".dll", ".doc", ".docx", ".exe", ".gif",
        ".gz", ".ico", ".jar", ".jpeg", ".jpg", ".mov", ".mp3", ".mp4", ".msi", ".pdf",
        ".png", ".ppt", ".pptx", ".rar", ".so", ".tar", ".ttf", ".wav", ".webp", ".woff",
        ".woff2", ".xls", ".xlsx", ".zip"
    )

    $results = New-Object System.Collections.Generic.List[object]
    $errors = New-Object System.Collections.Generic.List[object]
    $candidateFiles = New-Object System.Collections.Generic.List[object]
    $dirs = [System.Collections.Generic.Stack[string]]::new()
    $dirs.Push((Resolve-Path -LiteralPath $rootPath).Path)

    $scannedFiles = 0
    $skippedFiles = 0
    $matchedFiles = 0
    $maxResults = 5000
    $started = Get-Date

    function Send-ScannerProgress {
        param(
            [string]$Phase,
            [int]$Percent,
            [string]$CurrentPath
        )

        if ($null -eq $Progress) {
            return
        }
        & $Progress @{
            type = "progress"
            phase = $Phase
            percent = $Percent
            currentPath = $CurrentPath
            candidateFiles = $candidateFiles.Count
            scannedFiles = $scannedFiles
            skippedFiles = $skippedFiles
            matchedFiles = $matchedFiles
            matchCount = $results.Count
            elapsedSeconds = [Math]::Round(((Get-Date) - $started).TotalSeconds, 2)
        }
    }

    Send-ScannerProgress -Phase "enumerate" -Percent 0 -CurrentPath $rootPath

    while ($dirs.Count -gt 0) {
        $dir = $dirs.Pop()
        $children = @()
        try {
            $children = Get-ChildItem -LiteralPath $dir -Force -ErrorAction Stop
        }
        catch {
            if ($errors.Count -lt 200) {
                $errors.Add(@{ path = $dir; message = $_.Exception.Message })
            }
            continue
        }

        foreach ($child in $children) {
            if ($child.PSIsContainer) {
                if (($child.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                    continue
                }
                if ($excludeDirs -contains $child.Name) {
                    continue
                }
                $dirs.Push($child.FullName)
                continue
            }

            if ($binaryExtensions -contains $child.Extension.ToLowerInvariant()) {
                $skippedFiles++
                continue
            }
            if ($child.Length -gt $maxBytes) {
                $skippedFiles++
                continue
            }

            $isInvisibleCandidate = $false
            if ($runInvisibleScan) {
                if (Test-NameMatchesAny -Name $child.Name -Patterns $excludeFiles) {
                    $skippedFiles++
                }
                elseif (Test-NameMatchesAny -Name $child.Name -Patterns $filters) {
                    $isInvisibleCandidate = $true
                }
            }
            $isSupplyCandidate = $false
            if ($runSupplyChainScan) {
                $isSupplyCandidate = Test-SupplyCandidateFile -File $child -RootPath (Resolve-Path -LiteralPath $rootPath).Path -NodeModulesFullScan $nodeModulesFullScan
            }
            if (-not ($isInvisibleCandidate -or $isSupplyCandidate)) {
                continue
            }

            $candidateFiles.Add([pscustomobject]@{
                file = $child
                invisible = $isInvisibleCandidate
                supply = $isSupplyCandidate
            })
            if ($candidateFiles.Count -gt $MaxCandidateFiles) {
                throw ("Too many candidate files. Limit: {0}. Narrow the target to a downloaded project folder, or add exclusions such as node_modules;AppData;Windows;Program Files." -f $MaxCandidateFiles)
            }
            if (($candidateFiles.Count % 500) -eq 0) {
                Send-ScannerProgress -Phase "enumerate" -Percent 0 -CurrentPath $child.FullName
            }
        }
    }

    Send-ScannerProgress -Phase "scan" -Percent 0 -CurrentPath ""
    $totalCandidates = [Math]::Max(1, $candidateFiles.Count)

    foreach ($candidate in $candidateFiles) {
            $child = $candidate.file
            $scannedFiles++
            try {
                $text = Read-TextFile -Path $child.FullName
                $beforeCount = $results.Count
                if ($candidate.invisible) {
                    $matches = $regex.Matches($text)
                    foreach ($match in $matches) {
                        if ($results.Count -ge $maxResults) {
                            break
                        }
                        $pos = Get-LineColumn -Text $text -Index $match.Index
                        $severity = "high"
                        if ($child.FullName -match "(?i)([\\/](README|docs|CHANGELOG)|\.(md|txt)$)") {
                            $severity = "low"
                        }
                        $results.Add((New-Finding -Severity $severity -Category "invisible-unicode" -Path $child.FullName -Line $pos.line -Column $pos.column -Match "Invisible Unicode sequence" -Message "Invisible Unicode sequence matched the selected rule." -Recommendation "Confirm whether this file is executed or only documentation. Do not run unknown projects until executable hits are understood." -Snippet (ConvertTo-VisibleSnippet -Text $text -Index $match.Index -Length $match.Length) -Source "invisible-unicode" -RunLength (Get-CodePointCount -Text $match.Value) -CodePoints (Get-CodePointList -Text $match.Value)))
                    }
                }
                if ($candidate.supply -and $results.Count -lt $maxResults) {
                    Scan-SupplyChainFile -Findings $results -Rules $supplyRules -File $child
                }
                if ($results.Count -gt $beforeCount) {
                    $matchedFiles++
                }
            }
            catch {
                if ($errors.Count -lt 200) {
                    $errors.Add(@{ path = $child.FullName; message = $_.Exception.Message })
                }
            }
            if (($scannedFiles % 50) -eq 0 -or $scannedFiles -eq $candidateFiles.Count) {
                $percent = [int][Math]::Min(99, [Math]::Floor(($scannedFiles / $totalCandidates) * 100))
                Send-ScannerProgress -Phase "scan" -Percent $percent -CurrentPath $child.FullName
            }
        }

    $elapsed = ((Get-Date) - $started).TotalSeconds
    $severitySummary = Get-EmptySeveritySummary
    foreach ($result in $results) {
        Add-SeverityCount -Summary $severitySummary -Severity ([string]$result.severity)
    }
    $finalResult = @{
        ok = $true
        tool = "Invisible Payload Scanner"
        scanMode = $scanMode
        scannedAt = (Get-Date).ToString("o")
        rule = $rule
        supplyChainRules = @{
            schemaVersion = $supplyRules.schemaVersion
            updatedAt = $supplyRules.updatedAt
            loadStatus = $supplyRules.loadStatus
            loadMessage = $supplyRules.loadMessage
            rulesets = @((ConvertTo-Array $supplyRules.rulesets) | ForEach-Object { $_.id })
        }
        rootPath = (Resolve-Path -LiteralPath $rootPath).Path
        filters = $filters
        excludeDirs = $excludeDirs
        excludeFiles = $excludeFiles
        summary = $severitySummary
        candidateFiles = $candidateFiles.Count
        scannedFiles = $scannedFiles
        skippedFiles = $skippedFiles
        matchedFiles = $matchedFiles
        matchCount = $results.Count
        resultLimitReached = ($results.Count -ge $maxResults)
        elapsedSeconds = [Math]::Round($elapsed, 2)
        results = $results
        errors = $errors
    }
    if ($null -ne $Progress) {
        & $Progress @{
            type = "progress"
            phase = "done"
            percent = 100
            currentPath = ""
            candidateFiles = $candidateFiles.Count
            scannedFiles = $scannedFiles
            skippedFiles = $skippedFiles
            matchedFiles = $matchedFiles
            matchCount = $results.Count
            elapsedSeconds = [Math]::Round($elapsed, 2)
        }
    }
    return $finalResult
}

function Find-ByteSequence {
    param(
        [byte[]]$Bytes,
        [int]$Count,
        [byte[]]$Pattern
    )

    if ($Count -lt $Pattern.Length) {
        return -1
    }
    for ($i = 0; $i -le ($Count - $Pattern.Length); $i++) {
        $found = $true
        for ($j = 0; $j -lt $Pattern.Length; $j++) {
            if ($Bytes[$i + $j] -ne $Pattern[$j]) {
                $found = $false
                break
            }
        }
        if ($found) {
            return $i
        }
    }
    return -1
}

function Get-HttpStatusText {
    param([int]$StatusCode)

    switch ($StatusCode) {
        200 { "OK" }
        404 { "Not Found" }
        500 { "Internal Server Error" }
        default { "OK" }
    }
}

function Send-HttpResponse {
    param(
        [System.Net.Sockets.TcpClient]$Client,
        [byte[]]$Body,
        [string]$ContentType,
        [int]$StatusCode = 200
    )

    $statusText = Get-HttpStatusText -StatusCode $StatusCode
    $header = "HTTP/1.1 $StatusCode $statusText`r`nContent-Type: $ContentType`r`nContent-Length: $($Body.Length)`r`nConnection: close`r`nCache-Control: no-store`r`n`r`n"
    $headerBytes = [System.Text.Encoding]::ASCII.GetBytes($header)
    $stream = $Client.GetStream()
    $stream.Write($headerBytes, 0, $headerBytes.Length)
    if ($Body.Length -gt 0) {
        $stream.Write($Body, 0, $Body.Length)
    }
    $stream.Flush()
}

function Start-NdjsonResponse {
    param([System.Net.Sockets.TcpClient]$Client)

    $header = "HTTP/1.1 200 OK`r`nContent-Type: application/x-ndjson; charset=utf-8`r`nConnection: close`r`nCache-Control: no-store`r`n`r`n"
    $headerBytes = [System.Text.Encoding]::ASCII.GetBytes($header)
    $stream = $Client.GetStream()
    $stream.Write($headerBytes, 0, $headerBytes.Length)
    $stream.Flush()
    return $stream
}

function Write-NdjsonLine {
    param(
        [System.IO.Stream]$Stream,
        $Object
    )

    $json = ($Object | ConvertTo-Json -Depth 12 -Compress) + "`n"
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    $Stream.Write($bytes, 0, $bytes.Length)
    $Stream.Flush()
}

function Send-Json {
    param(
        [System.Net.Sockets.TcpClient]$Client,
        $Object,
        [int]$StatusCode = 200
    )

    $json = $Object | ConvertTo-Json -Depth 12
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    Send-HttpResponse -Client $Client -Body $bytes -ContentType "application/json; charset=utf-8" -StatusCode $StatusCode
}

function Send-File {
    param(
        [System.Net.Sockets.TcpClient]$Client,
        [string]$Path,
        [string]$ContentType
    )

    $bytes = [System.IO.File]::ReadAllBytes($Path)
    Send-HttpResponse -Client $Client -Body $bytes -ContentType $ContentType -StatusCode 200
}

function Send-UiFile {
    param(
        [System.Net.Sockets.TcpClient]$Client,
        [string]$Path,
        [string]$ApiToken
    )

    $html = [System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::UTF8)
    $html = $html.Replace("__API_TOKEN__", $ApiToken)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($html)
    Send-HttpResponse -Client $Client -Body $bytes -ContentType "text/html; charset=utf-8" -StatusCode 200
}

function Read-HttpRequest {
    param([System.Net.Sockets.TcpClient]$Client)

    $stream = $Client.GetStream()
    $buffer = New-Object byte[] 8192
    $memory = [System.IO.MemoryStream]::new()
    $headerEnd = -1
    $separator = [byte[]](13, 10, 13, 10)

    while ($headerEnd -lt 0) {
        $read = $stream.Read($buffer, 0, $buffer.Length)
        if ($read -le 0) {
            throw "Empty HTTP request."
        }
        $memory.Write($buffer, 0, $read)
        if ($memory.Length -gt 1048576) {
            throw "HTTP request header is too large."
        }
        $current = $memory.ToArray()
        $headerEnd = Find-ByteSequence -Bytes $current -Count $current.Length -Pattern $separator
    }

    $allBytes = $memory.ToArray()
    $headerBytes = @()
    if ($headerEnd -gt 0) {
        $headerBytes = $allBytes[0..($headerEnd - 1)]
    }
    $headerText = [System.Text.Encoding]::ASCII.GetString($headerBytes)
    $lines = $headerText -split "`r`n"
    if ($lines.Count -lt 1) {
        throw "Invalid HTTP request."
    }

    $requestLine = $lines[0] -split " "
    if ($requestLine.Count -lt 2) {
        throw "Invalid HTTP request line."
    }

    $headers = @{}
    for ($i = 1; $i -lt $lines.Count; $i++) {
        $colon = $lines[$i].IndexOf(":")
        if ($colon -gt 0) {
            $name = $lines[$i].Substring(0, $colon).Trim().ToLowerInvariant()
            $value = $lines[$i].Substring($colon + 1).Trim()
            $headers[$name] = $value
        }
    }

    $contentLength = 0
    if ($headers.ContainsKey("content-length")) {
        if (-not [int]::TryParse($headers["content-length"], [ref]$contentLength)) {
            throw "Invalid Content-Length."
        }
        if ($contentLength -lt 0 -or $contentLength -gt $MaxRequestBodyBytes) {
            throw "HTTP request body is too large."
        }
    }

    $bodyMemory = [System.IO.MemoryStream]::new()
    $bodyStart = $headerEnd + 4
    if ($allBytes.Length -gt $bodyStart) {
        $existingLength = [Math]::Min($contentLength, $allBytes.Length - $bodyStart)
        if ($existingLength -gt 0) {
            $bodyMemory.Write($allBytes, $bodyStart, $existingLength)
        }
    }

    while ($bodyMemory.Length -lt $contentLength) {
        $remaining = [Math]::Min($buffer.Length, $contentLength - [int]$bodyMemory.Length)
        $read = $stream.Read($buffer, 0, $remaining)
        if ($read -le 0) {
            break
        }
        $bodyMemory.Write($buffer, 0, $read)
    }

    return [pscustomobject]@{
        method = $requestLine[0].ToUpperInvariant()
        path = ([Uri]::new("http://127.0.0.1" + $requestLine[1])).AbsolutePath
        headers = $headers
        body = [System.Text.Encoding]::UTF8.GetString($bodyMemory.ToArray())
    }
}

function Get-RequestJson {
    param([string]$Body)

    if ([string]::IsNullOrWhiteSpace($Body)) {
        return @{}
    }
    return $Body | ConvertFrom-Json
}

function Test-ApiRequest {
    param(
        $Request,
        [string]$ApiToken,
        [string[]]$AllowedOrigins
    )

    $headers = $Request.headers
    $token = ""
    if ($headers.ContainsKey("x-scanner-token")) {
        $token = [string]$headers["x-scanner-token"]
    }
    if ($token -ne $ApiToken) {
        return $false
    }

    if ($headers.ContainsKey("origin")) {
        $origin = [string]$headers["origin"]
        if ($AllowedOrigins -notcontains $origin) {
            return $false
        }
    }
    return $true
}

if ($SelfTest) {
    $sampleRoot = Join-Path $PSScriptRoot "_selftest"
    New-Item -ItemType Directory -Force -Path $sampleRoot | Out-Null
    $samplePath = Join-Path $sampleRoot "sample.js"
    $vs = [char]0xFE0F
    [System.IO.File]::WriteAllText($samplePath, "const hidden = ``$vs$vs$vs``;`n", [System.Text.Encoding]::UTF8)
    $self = Invoke-Scanner -Options ([pscustomobject]@{
        rootPath = $sampleRoot
        filter = "*.js"
        excludeDirs = ".git"
        minRun = 3
        maxFileSizeMb = 1
        ruleId = "glassworm_variation_selectors"
        customPattern = ""
    })
    if ($self.matchCount -lt 1) {
        throw "Self-test failed: expected at least one match."
    }

    $vscodeRoot = Join-Path $sampleRoot ".vscode"
    $claudeRoot = Join-Path $sampleRoot ".claude"
    $extensionRoot = Join-Path $sampleRoot ".antigravity\extensions\sample.publisher-1.0.0"
    New-Item -ItemType Directory -Force -Path $vscodeRoot | Out-Null
    New-Item -ItemType Directory -Force -Path $claudeRoot | Out-Null
    New-Item -ItemType Directory -Force -Path $extensionRoot | Out-Null
    [System.IO.File]::WriteAllText((Join-Path $vscodeRoot "tasks.json"), '{"version":"2.0.0","tasks":[{"label":"open","type":"shell","runOptions":{"runOn":"folderOpen"},"command":"powershell -NoProfile"}]}', [System.Text.Encoding]::UTF8)
    [System.IO.File]::WriteAllText((Join-Path $claudeRoot "settings.json"), '{"hooks":{"SessionStart":[{"command":"node -e console.log(1)"}]}}', [System.Text.Encoding]::UTF8)
    [System.IO.File]::WriteAllText((Join-Path $sampleRoot "package.json"), '{"name":"@tanstack/react-router","version":"1.169.5","optionalDependencies":{"@tanstack/setup":"github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c"},"scripts":{"postinstall":"node -e console.log(1)"}}', [System.Text.Encoding]::UTF8)
    [System.IO.File]::WriteAllText((Join-Path $extensionRoot "package.json"), '{"name":"sample-extension","scripts":{"prepare":"pwsh ./prepare.ps1"}}', [System.Text.Encoding]::UTF8)

    $supplySelf = Invoke-Scanner -Options ([pscustomobject]@{
        rootPath = $sampleRoot
        filter = "*.js"
        excludeDirs = ".git"
        minRun = 3
        maxFileSizeMb = 1
        ruleId = "glassworm_variation_selectors"
        scanMode = "supply-chain-ioc"
        supplyNodeModulesFullScan = $false
        customPattern = ""
    })
    if ($supplySelf.summary.critical -lt 1 -or $supplySelf.summary.high -lt 1) {
        throw "Self-test failed: expected critical and high supply-chain findings."
    }
    $extensionContextHit = @($supplySelf.results | Where-Object { $_.pathContext -eq "editor-extension" }).Count
    if ($extensionContextHit -lt 1) {
        throw "Self-test failed: expected editor-extension path context."
    }
    "Self-test passed: invisible=$($self.matchCount), supply=$($supplySelf.matchCount) match(es)."
    exit 0
}

$webRoot = Join-Path $PSScriptRoot "www"
$indexPath = Join-Path $webRoot "index.html"
if (-not (Test-Path -LiteralPath $indexPath -PathType Leaf)) {
    throw "UI file not found: $indexPath"
}

$Port = Get-FreePort -StartPort $Port
$prefix = "http://127.0.0.1:$Port/"
$apiToken = New-ApiToken
$allowedOrigins = @("http://127.0.0.1:$Port", "http://localhost:$Port")
$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse("127.0.0.1"), $Port)
$listener.Start()

Write-Host "Invisible Payload Scanner is running at $prefix"
Write-Host "Close this window or press Ctrl+C to stop."

if (-not $NoBrowser) {
    Start-Process $prefix
}

try {
    $stopRequested = $false
    while (-not $stopRequested) {
        $client = $listener.AcceptTcpClient()

        try {
            $request = Read-HttpRequest -Client $client
            $path = $request.path

            if ($request.method -eq "GET" -and ($path -eq "/" -or $path -eq "/index.html")) {
                Send-UiFile -Client $client -Path $indexPath -ApiToken $apiToken
            }
            elseif ($request.method -eq "GET" -and $path -eq "/api/health") {
                Send-Json -Client $client -Object @{ ok = $true; port = $Port }
            }
            elseif ($request.method -eq "POST" -and $path -eq "/api/scan") {
                if (-not (Test-ApiRequest -Request $request -ApiToken $apiToken -AllowedOrigins $allowedOrigins)) {
                    Send-Json -Client $client -Object @{ ok = $false; error = "Invalid local session token." } -StatusCode 403
                    continue
                }
                $options = Get-RequestJson -Body $request.body
                $result = Invoke-Scanner -Options $options
                Send-Json -Client $client -Object $result
            }
            elseif ($request.method -eq "POST" -and $path -eq "/api/scan-stream") {
                if (-not (Test-ApiRequest -Request $request -ApiToken $apiToken -AllowedOrigins $allowedOrigins)) {
                    Send-Json -Client $client -Object @{ ok = $false; error = "Invalid local session token." } -StatusCode 403
                    continue
                }
                $options = Get-RequestJson -Body $request.body
                $stream = Start-NdjsonResponse -Client $client
                try {
                    $progressWriter = {
                        param($event)
                        Write-NdjsonLine -Stream $stream -Object $event
                    }
                    $result = Invoke-Scanner -Options $options -Progress $progressWriter
                    Write-NdjsonLine -Stream $stream -Object @{ type = "result"; result = $result }
                }
                catch {
                    Write-NdjsonLine -Stream $stream -Object @{ type = "error"; error = $_.Exception.Message }
                }
            }
            elseif ($request.method -eq "POST" -and $path -eq "/api/stop") {
                if (-not (Test-ApiRequest -Request $request -ApiToken $apiToken -AllowedOrigins $allowedOrigins)) {
                    Send-Json -Client $client -Object @{ ok = $false; error = "Invalid local session token." } -StatusCode 403
                    continue
                }
                Send-Json -Client $client -Object @{ ok = $true; message = "Stopping scanner." }
                $stopRequested = $true
            }
            else {
                Send-Json -Client $client -Object @{ ok = $false; error = "Not found." } -StatusCode 404
            }
        }
        catch {
            try {
                Send-Json -Client $client -Object @{ ok = $false; error = $_.Exception.Message } -StatusCode 500
            }
            catch {
            }
        }
        finally {
            $client.Close()
        }
    }
}
finally {
    $listener.Stop()
}
