# Invisible Payload Scanner

Invisible Payload Scanner started as a tool for my own use, then grew into a Windows-friendly local Web UI for people who are not comfortable with CLI workflows.

It is meant for checking projects downloaded from GitHub before running them. It runs locally on Windows and does not upload scanned file contents to an external server.

The default rule focuses on variation selectors and supplementary variation selectors reported in GlassWorm-style invisible Unicode payloads. The rule can be changed for other invisible Unicode indicators.

This is not a malware verdict engine. It is a first-pass screening tool. If it reports a finding, review the file type, surrounding code, execution path, and package origin.

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
4. Click `スキャン開始`.

Files are read only. They are not executed. Findings display invisible characters as visible markers such as `[VS U+FE0F]` and `[VS U+E0100]`.

The easiest way to enter a folder path is to open the target folder in File Explorer and copy the address bar. Quoted paths such as `"C:\path\to\project"` are accepted.

To interrupt a long scan, close the PowerShell window that launched the scanner.

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
- JSON export is created only when the user clicks the export button.
- Reparse points such as symlinks and junctions are skipped.
- Regex matching uses a timeout per file.
- Request size, custom regex length, file size, and candidate file count are capped.

This design does not guarantee detection of binary malware, externally downloaded installers, non-Unicode loaders, compromised dependencies, or every malicious execution path.

It also does not attempt full C2 fingerprinting, credential-harvesting behavior detection, or known-IoC matching for package names, extension names, IP addresses, wallets, or attacker infrastructure. The focus is local first-pass screening for invisible Unicode payloads and closely related visible decoder patterns.

## After a Finding

Treat findings in executable or build-time files as higher priority:

- `.js`, `.ts`, `.mjs`, `.cjs`, `.jsx`, `.tsx`
- `.ps1`, `.cmd`, `.bat`, `.sh`
- `package.json`, npm scripts, GitHub Actions, CI configuration
- Configuration files read during build or startup

Findings in README or documentation files are often lower priority and may be false positives, especially when the code points are only a few `U+FE0F` characters near emoji, badges, or accessibility links.

Recommended triage:

1. Raise the threshold to `16` and scan again.
2. Exclude `README.md;*.md` and scan executable file types.
3. If long invisible runs appear in executed files, stop using the package or repository until reviewed.
4. If you have not run `npm install`, build scripts, or project commands yet, do not run them until the source is checked.
5. Check package origin, recent commits, install scripts, and official advisories.
