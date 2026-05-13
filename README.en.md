# Invisible Payload Scanner

Invisible Payload Scanner started as a tool for my own use, then grew into a Windows-friendly local Web UI for people who are not comfortable with CLI workflows.

It is meant for checking projects downloaded from GitHub before running them. It runs locally on Windows and does not upload scanned file contents to an external server.

The current release can check for GlassWorm-style variation selectors and supplementary variation selectors, plus known npm supply-chain IOC traces and auto-run settings related to AI coding environments.

This is not a malware verdict engine. It is a first-pass screening tool. If it reports a finding, review the file type, surrounding code, execution path, and package origin.

This tool is not a replacement for antivirus software. Use it alongside resident protection such as ESET or Windows Defender, as a pre-run check before executing, installing, or handing a GitHub project to an AI coding agent.

See [SECURITY.md](SECURITY.md) for the security policy and reporting scope. A Japanese version is available at [SECURITY.ja.md](SECURITY.ja.md).

## Release Types

Invisible Payload Scanner currently has two main usage paths:

- `v0.1.0 Classic`: the first release, focused on invisible Unicode screening
- `v0.2.0 Safety Pre-Scan`: adds npm supply-chain IOC checks and AI coding environment auto-run checks on top of Classic

Existing `v0.1.0` release assets are kept as-is and will not be replaced. Use `v0.2.0` or later when you need the broader pre-run safety checks.

## Which Should I Use?

In most cases, use the latest **Safety Pre-Scan** release.

- **Classic: Invisible Unicode Scan**
  A lightweight mode focused on invisible Unicode, GlassWorm-style patterns, and Trojan Source-style checks.
- **Safety Pre-Scan**
  Includes Classic checks plus npm supply-chain IOCs, VS Code auto-run tasks, Claude Code / AI agent hooks, and install scripts.

## Why This Exists

Existing CLI scanners are useful for CI and advanced users. This project focuses on a narrower operational need:

I made this because many existing GlassWorm-related detection tools are CLI-oriented, while I wanted a local Windows UI where I could paste a folder path and quickly run a first-pass check.

- Double-click startup on Windows
- Local-only scanning through a small browser UI
- Progress visibility for large folders
- Human-readable display of invisible code points and surrounding text
- Adjustable rules for future invisible-character indicators

It does not replace a malware scanner, package-audit tool, EDR, or supply-chain security platform. It helps users notice suspicious invisible payloads before running or trusting unfamiliar projects.

## Usage

1. Double-click `Start-InvisiblePayloadScanner.cmd`.
2. Enter the folder path to scan.
3. Adjust file filters, excluded directories, excluded files, and threshold if needed.
4. Click `スキャン開始` to start scanning.

Files are read only. They are not executed. Findings display invisible characters as visible markers such as `[VS U+FE0F]` and `[VS U+E0100]`.

The easiest way to enter a folder path is to open the target folder in File Explorer and copy the address bar. Quoted paths such as `"C:\path\to\project"` are accepted.

To interrupt a long scan, close the PowerShell window that launched the scanner.

## JSON Export

`結果をJSON保存` saves the scan result as a local JSON file. It is useful for later review, asking a more technical person for help, or comparing the finding with GitHub issues, security advisories, or npm package information.

Possible uses:

- Keep a record of the file path, line number, matched term, and severity.
- Share more precise information than a screenshot with a teammate or reviewer.
- Record what was found if you already ran the project and need to investigate.

The JSON may include local paths, user names, and project names. Before posting it to a public issue, advisory, or social media, check whether it contains information you do not want to publish.

## Extra Defense for npm-style Projects

If this scanner reports a finding, or if you are handling an unfamiliar Node.js project, you can also consider package-manager-level safeguards before running install/build commands.

This scanner does not apply these settings automatically. Changing package managers can change project behavior, so review the change with someone technical or ask an AI agent to explain the impact before applying it.

Example for pnpm:

```yaml
# pnpm-workspace.yaml
minimumReleaseAge: 4320
minimumReleaseAgeStrict: true
blockExoticSubdeps: true
```

- `minimumReleaseAge` delays newly published packages before they can be installed. `4320` means three days.
- `minimumReleaseAgeStrict: true` fails dependency resolution if no version satisfies the maturity window.
- `blockExoticSubdeps: true` prevents transitive dependencies from resolving code from git or direct tarball URLs.
- To control install scripts, check `allowBuilds` or `pnpm approve-builds` in pnpm 11.

## Default GlassWorm-Style Pattern

```powershell
([\uFE00-\uFE0F]|\uDB40[\uDD00-\uDDEF]){8,}
```

- `U+FE00` to `U+FE0F` are matched as `\uFE00-\uFE0F`.
- `U+E0100` to `U+E01EF` are matched as the surrogate pair range `\uDB40[\uDD00-\uDDEF]` for .NET/PowerShell regex compatibility.
- `{8,}` means eight or more consecutive matches.
- Use `8` or higher for first-pass screening. Use `16` or higher for broad whole-PC scans.

## Default Exclusions

By default, Markdown files are excluded:

```text
README.md;*.md
```

Markdown documentation often contains emoji-related `U+FE0F` characters, and README files are usually not executed. If a project uses Markdown as a build input or code-generation source, remove this exclusion and scan again.

## Privacy and Safety

- The local server binds to `127.0.0.1`.
- A random local API token is generated on each startup and required for scan and stop requests.
- API request origins are checked to reduce cross-site localhost request abuse.
- Scanned file contents are not uploaded.
- External APIs are not called.
- Files are read, not executed.
- Package manager commands such as `npm install`, `pnpm install`, `yarn install`, and `bun install` are not run.
- Bundled IOC rules are read from local files and are not fetched automatically.
- Token-like strings in snippets are masked before display.
- JSON export is created only when the user clicks the export button.
- Reparse points such as symlinks and junctions are skipped.
- Regex matching uses a timeout per file.
- Request size, custom regex length, file size, and candidate file count are capped.

This design does not guarantee detection of binary malware, externally downloaded installers, non-Unicode loaders, compromised dependencies, or every malicious execution path.

It also does not attempt full C2 fingerprinting, credential-harvesting behavior detection, complete package-registry trust verification, or every malicious execution path. The focus is local first-pass screening before running unfamiliar projects.

## Supply Chain IOC Scan

Safety Pre-Scan checks for known npm supply-chain IOC strings and auto-run configuration in addition to invisible Unicode patterns.

Examples of checked files:

- `package.json`
- `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock`
- `.vscode/tasks.json`
- `.claude/settings.json`
- `.github/workflows/*.yml`
- `.npmrc`, `.env*`
- `node_modules/**/package.json`

Initial rules are bundled in `rules/ioc-rules.json`. They focus on public TanStack npm supply-chain compromise IOCs from May 2026, including malicious git refs, `@tanstack/setup`, `router_init.js`, `tanstack_runner.js`, `filev2.getsession.org`, `seed*.getsession.org`, and known affected version candidates.

Package names alone are not treated as proof of compromise. Namespace matches such as `@tanstack/` are prompts for review. Stronger warnings require known affected versions, known IOC strings, auto-run settings, or install-script risk terms.

## After a Finding

Treat findings in executable or build-time files as higher priority:

- `.js`, `.ts`, `.mjs`, `.cjs`, `.jsx`, `.tsx`
- `.ps1`, `.cmd`, `.bat`, `.sh`
- `package.json`, npm scripts, GitHub Actions, CI configuration
- Configuration files read during build or startup

Findings in README or documentation files are often lower priority and may be false positives, especially when the code points are only a few `U+FE0F` characters near emoji, badges, or accessibility links.

Findings inside editor or AI-tool extension folders, such as `.vscode/extensions/` or `.antigravity/extensions/`, also need separate context. A legitimate extension may include `package.json`, `tasks.json`, build scripts, or development scripts. Treat these as review prompts rather than proof of compromise: check the extension name, publisher, version, and whether you intentionally installed it. If the extension is unfamiliar, recently appeared, or has an unexpected publisher, consider disabling or reinstalling it and checking the official marketplace page.

Recommended triage:

1. Raise the threshold to `16` and scan again.
2. Exclude `README.md;*.md` and scan executable file types.
3. If long invisible runs appear in executed files, stop using the package or repository until reviewed.
4. If you have not run `npm install`, build scripts, or project commands yet, do not run them until the source is checked.
5. Check package origin, recent commits, install scripts, and official advisories.
6. If a `Critical` or `High` finding appears after you already ran the project, consider rotating GitHub tokens, npm tokens, API keys, SSH keys, and other credentials that may have been exposed.
