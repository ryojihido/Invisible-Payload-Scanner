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
- API request origins are checked when the browser sends an `Origin` header.
- Files are read, not executed.
- Package manager commands such as `npm install`, `pnpm install`, `yarn install`, and `bun install` are not run by this scanner.
- Bundled IOC rules are read from local files. The scanner does not fetch rule updates automatically.
- Token-like strings in snippets are masked before display.
- Scan results are inserted into the UI using text assignment rather than raw HTML.
- Reparse points are skipped to avoid following junctions or symlinks.
- Regex matching uses a timeout per file.
- The default threshold is tuned to reduce common emoji-related false positives.
- Request body size, custom pattern length, maximum file size, and candidate file count are capped server-side.

## Supply Chain IOC Scan limits

Supply Chain IOC Scan is a static pre-run check. It can flag known IOC strings, known affected package versions included in the bundled rules, VS Code folder-open tasks, Claude Code / AI agent hooks, and install-time lifecycle scripts.

It does not prove that a project is clean. Package names alone are treated as prompts for review, not proof of compromise. If a critical or high finding appears, stop before installing or building the project, confirm the source, compare package versions with official advisories, and rotate credentials if the project has already been executed in an exposed environment.

Lockfile matches are intentionally conservative. The initial implementation treats package-name and version proximity as a review candidate, not a confirmed malicious dependency, unless a parsed `package.json` manifest directly identifies a known affected package and version.
