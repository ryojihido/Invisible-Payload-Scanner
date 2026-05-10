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
        $excludeText = ".git"
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

    if ([string]$Options.ruleId -eq "custom" -and ([string]$Options.customPattern).Length -gt $MaxCustomPatternLength) {
        throw "Custom pattern is too long."
    }
    $rule = Get-Rule -RuleId ([string]$Options.ruleId) -MinRun $minRun -CustomPattern ([string]$Options.customPattern)
    $regex = [System.Text.RegularExpressions.Regex]::new(
        [string]$rule.pattern,
        [System.Text.RegularExpressions.RegexOptions]::CultureInvariant,
        [TimeSpan]::FromSeconds(2)
    )

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

            if (Test-NameMatchesAny -Name $child.Name -Patterns $excludeFiles) {
                $skippedFiles++
                continue
            }
            if (-not (Test-NameMatchesAny -Name $child.Name -Patterns $filters)) {
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

            $candidateFiles.Add($child)
            if ($candidateFiles.Count -gt $MaxCandidateFiles) {
                throw "Too many candidate files. Narrow the target folder or filters and scan again."
            }
            if (($candidateFiles.Count % 500) -eq 0) {
                Send-ScannerProgress -Phase "enumerate" -Percent 0 -CurrentPath $child.FullName
            }
        }
    }

    Send-ScannerProgress -Phase "scan" -Percent 0 -CurrentPath ""
    $totalCandidates = [Math]::Max(1, $candidateFiles.Count)

    foreach ($child in $candidateFiles) {
            $scannedFiles++
            try {
                $text = Read-TextFile -Path $child.FullName
                $matches = $regex.Matches($text)
                if ($matches.Count -gt 0) {
                    $matchedFiles++
                }

                foreach ($match in $matches) {
                    if ($results.Count -ge $maxResults) {
                        break
                    }
                    $pos = Get-LineColumn -Text $text -Index $match.Index
                    $results.Add(@{
                        path = $child.FullName
                        line = $pos.line
                        column = $pos.column
                        runLength = Get-CodePointCount -Text $match.Value
                        codePoints = Get-CodePointList -Text $match.Value
                        snippet = ConvertTo-VisibleSnippet -Text $text -Index $match.Index -Length $match.Length
                    })
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
    $finalResult = @{
        ok = $true
        rule = $rule
        rootPath = (Resolve-Path -LiteralPath $rootPath).Path
        filters = $filters
        excludeDirs = $excludeDirs
        excludeFiles = $excludeFiles
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
    "Self-test passed: $($self.matchCount) match(es)."
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
