# Invisible Payload Scanner v0.3.0

v0.3.0 keeps the v0.2 Safety Pre-Scan base and adds a separated rule layer for Contagious Interview-style repository lures.

## Added

- `rules/v0.3/contagious-interview-rules.json` for folder-open editor tasks, download-and-execute stagers, install lifecycle scripts, Git hook candidates, and credential-harvesting terms.
- `rules/v0.3/safe-patterns.json` for local safe-pattern priority lowering.
- Structured parsing for `.vscode/tasks.json` and `.cursor/tasks.json`.
- Compound finding when a folder-open editor task can trigger package installation and the project also has install lifecycle scripts.
- GitHub Actions workflow risk hints for download-and-execute, shell, encoded payload, and credential-related indicators.
- Git hook candidate scanning for `.husky/*` and `.githooks/*`.
- Scanner self-context labels for bundled rule files, scanner source, and self-test fixtures to reduce scary false positives when this repository scans itself.
- Stricter localhost Host/Origin checks, Content-Security-Policy response headers, request read timeout, stronger sensitive-snippet masking, short install command detection, PowerShell encoded-command shorthand detection, binary-file skipping, and AI-agent instruction file review hints.

## Safety Notes

Safe patterns lower low-risk lifecycle script findings; they do not suppress remote download-and-execute, shell, encoded payload, or credential-harvesting indicators.

This release still performs static, read-only screening. It does not execute target files, install packages, call external APIs, or replace antivirus/EDR.

`_selftest` and `_compound_selftest` are excluded by default and cleaned after self-test runs because they contain intentionally suspicious fixtures used to verify detection logic.
