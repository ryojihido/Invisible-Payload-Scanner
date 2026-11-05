# Security Policy

## Supported use

Invisible Payload Scanner is a local screening tool. It is intended to highlight suspicious invisible Unicode sequences, known supply-chain IOC strings, package/version candidates, and auto-run configuration in source projects. It is not a complete malware scanner and should not be treated as a guarantee that a project is safe.

## Reporting a security issue

If you find a vulnerability in this scanner, please open a private security advisory if the repository supports it, or contact the maintainer through the repository's preferred security contact.

Please include:

- Affected version or commit
- Operating system and PowerShell version
- Steps to reproduce
- Expected behavior
- Actual behavior
- Whether local file contents, paths, or scan results could be exposed

Do not include private source code or sensitive scan results in a public issue.

## Scope

In scope:

- The local HTTP server binding or request handling
- Accidental external network transmission
- Unsafe file access outside the user-selected scan path
- Cross-site scripting in displayed scan results
- Crashes caused by normal use or malformed files

Out of scope:

- Missed malware that does not use the configured invisible Unicode patterns or bundled IOC rules
- Malicious files that are present but never matched by the selected filters
- Full C2 fingerprinting and credential-harvesting behavior detection
- Complete npm, pnpm, yarn, bun, PyPI, or package-registry trust verification
- Runtime code fetched during install or build
- Binary malware, memory-only malware, or heavily transformed variants
- Operating system compromise outside this scanner
- Security of projects being scanned

## Safety design

- The local server binds to `127.0.0.1`.
- A random local API token is generated on each startup and required for scan and stop requests.
- The Host header is limited to `127.0.0.1:<port>` or `localhost:<port>`.
- API request origins are required and checked against the local UI origin.
- Browser safety headers such as Content-Security-Policy, `X-Content-Type-Options`, `X-Frame-Options`, and `Referrer-Policy` are returned.
- Files are read, not executed.
- Package manager commands such as `npm install`, `pnpm install`, `yarn install`, and `bun install` are not run by this scanner.
- Bundled IOC rules are read from local files. The scanner does not fetch rule updates automatically.
- `.env` / `.npmrc` snippets are hidden, and token-like strings in other snippets are masked before display.
- Scan results are inserted into the UI using text assignment rather than raw HTML.
- Reparse points are skipped to avoid following junctions or symlinks.
- Regex matching uses a timeout per file.
- The default threshold is tuned to reduce common emoji-related false positives.
- Request body size, custom pattern length, maximum file size, and candidate file count are capped server-side.
- Release authenticity can be verified before use: confirm the downloaded archive with `Get-FileHash <zip> -Algorithm SHA256`, and compare that value with the zip SHA-256 listed on the GitHub Release. The startup banner also prints the running script's own SHA-256, which is a separate value for the extracted `Start-InvisiblePayloadScanner.ps1`.

## v0.6.0 coverage and response guidance

Reports with `reportSchemaVersion: 2` separate detection risk from check completion. Intentional exclusions are distinct from read, parse and regex failures and size/finding limits. `complete` means only that the selected static checks finished; it does not establish whole-device coverage or safety. Unselected checks are `not_selected`, zero eligible files are `not_assessed`, and legacy or inconsistent reports have unknown coverage in the UI.

Supply-chain scans validate all six required bundled rule packs before scanning and fail explicitly on missing or invalid packs. No substitute rules are used. Invisible-only scans do not load unselected supply-chain rules. Reparse points in the selected root or its ancestors are rejected as well as skipped during traversal.

The October 2026 checks cover TensorLake npm's affected version and existing IOCs, plus combined indicators in the Cursor-distributed Claude Code extension's `extension.js`. Extension names or versions alone do not trigger a warning. Both indicators must match the same file for `known-ioc-combination`. Each regular expression has a timeout; failures produce incomplete coverage. Static presence is not elevated to execution evidence. IDE extensions outside the selected root, SSH configuration, persistence, and VSIX/ZIP contents or hashes are not checked. These checks do not guarantee variant detection, removal or recovery.

Answers are user reports. A package name, IOC string or affected version does not establish execution. Local disconnection guidance requires combined remote-content/execution indicators in a named package.json command and a report that this particular operation ran on this PC. Other findings remain at review-and-consult guidance. CI or other-environment execution is not equated with infection of the viewing PC. Credential-revocation discussion is added only when the user or administrator confirms that credentials were present in that environment.

UI, JSON and text exports are local. There is no secret input, automatic deletion, network disconnection, credential change or report transmission. Removing findings, a clean antivirus result or reporting completion does not establish recovery.

## Threat model limits

Dependency noise reduction applies only inside `node_modules`. The `prepare`, `prepublish`, `prepack` and `postpack` scripts remain as informational findings when no high-risk or pipe-execution indicators are detected. A `test` or `test:...` script is informational only when all URLs use literal `localhost`, `127.0.0.1` or `[::1]`, without additional download-tool, shell-execution, obfuscation, credential or installation indicators. External or ambiguous hosts, ordinary install hooks, known IOCs and affected-version warnings retain their priority. Original `signalSeverity` is preserved; neither local URLs nor development metadata establish safety.

The local API token, Host check, and Origin check are designed to reduce simple localhost abuse from other sites or origins. They do not protect against a malicious process already running under the same Windows user account, or against a highly privileged browser extension in the browser used to open the scanner UI. Such code may be able to fetch the local UI, read the embedded token, and call the local scan API.

If you suspect malicious resident software or unsafe browser extensions on the machine, do not rely on this scanner alone. Review browser extensions, use operating-system protection, and prefer an isolated environment for unknown projects.

## Supply Chain IOC Scan limits

Supply Chain IOC Scan is a static pre-run check. It can flag known IOC strings, known affected package versions included in the bundled rules, VS Code/Cursor folder-open tasks, Claude Code / AI agent hooks, AI-agent instruction files, GitHub Actions workflow risk hints, install-time lifecycle scripts, and download-and-execute indicators (such as `curl | bash`, `iwr | iex`, `powershell -enc`, and LOLBins like `certutil`, `mshta`, `bitsadmin`, or `rundll32`). A lone download-and-execute indicator is reported as low/informational; it is escalated only when combined with folder-open tasks, install-lifecycle scripts, Git hooks, or workflows.

It does not prove that a project is clean. Package names alone are treated as prompts for review, not proof of compromise. If a critical or high finding appears, stop before installing or building the project, confirm the source, compare package versions with official advisories, and, if already executed, identify the operation, environment and evidence with support before deciding which affected sessions or credentials need revocation.

v0.3.1 separates the raw signal from the response priority. A finding may keep a high or critical `signalSeverity` while receiving a lower displayed `severity` when it appears in a nested SDK, vendored dependency, or copied upstream GitHub Actions workflow that normally does not run during local project execution. The exported `summary` counts displayed response priority, while `signalSummary` counts the original detection signal. Root project automation, install lifecycle scripts, folder-open tasks, Git hooks, and invisible Unicode findings are not lowered by this workflow context rule.

Lockfile matches are intentionally conservative. The initial implementation treats package-name and version proximity as a review candidate, not a confirmed malicious dependency, unless a parsed `package.json` manifest directly identifies a known affected package and version.
