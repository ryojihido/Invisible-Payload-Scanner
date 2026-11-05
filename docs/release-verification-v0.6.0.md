# v0.6.0 pre-release verification

Verified on 2026-11-05. This is an unpublished release candidate. The v0.6.0 version is retained because the earlier candidate was not released. This change does not publish a GitHub Release.

## Scope

The release adds scan-completion reporting, optional response guidance and text export, narrower dependency-script triage, explicit failure for missing or invalid rules, and October 2026 TensorLake / Cursor incident checks. The scanner remains local and read-only. It does not execute scanned code, send scan results, remove malware, modify credentials, or establish infection or recovery.

TensorLake detection covers npm `tensorlake@0.5.144` and targeted JS-family files in that dependency. Cursor detection requires both published indicators in the same `extension.js`; extension name or version alone does not trigger a finding. Source references and the corrected advisory date are recorded in `rules/v0.6/october-2026-incidents.json`.

## Validation

| Check | Result |
| --- | --- |
| October incident regression | 62 checks passed on PowerShell 7 and Windows PowerShell 5.1; the final 5.1 run used the extracted archive |
| Existing self-test | Passed on both engines: 3 invisible-Unicode findings and 32 supply-chain findings |
| Dependency triage regression | 56 checks passed on each engine |
| Coverage regression | 42 checks passed on each engine |
| Reparse-point boundary regression | 2 checks passed on each engine |
| UI regression | 40 checks passed using isolated DOM/network test doubles |
| October incident HTTP API | 10 checks passed against the packaged scanner |
| Existing HTTP API security regression | 16 checks passed, including authentication, Origin/Host rejection, security headers, NDJSON and partial coverage |
| Packaged startup/shutdown | Windows PowerShell 5.1 startup with NoBrowser, authenticated /api/stop, process exit and empty stderr confirmed |
| Static validation | PowerShell syntax, test JavaScript syntax, six rule JSON files and Git whitespace checks passed |
| Artifact identity | All 16 packaged files matched the working sources and extracted archive by SHA-256 |

The incident regression includes clean adjacent versions and clean same-version extension fixtures, single indicators, lookalike addresses, indicators split between files, quoted documentation, masking, file-size limits, real regex timeouts, and missing/invalid rule packs.

All scan inputs were inert synthetic fixtures. Payloads, install hooks and scanned code were not executed. Existing tests with direct-deletion cleanup were run in isolated copies with cleanup changed to retain fixtures; the missing-rule test renamed its disposable copy. Assertions and production scan logic were unchanged. The test retention changes are not included in the distributed scanner.

Windows PowerShell 5.1 policy-registry access and PowerShell 7 junction creation were blocked inside the sandbox. Those checks passed outside that sandbox without changing execution policy or persistent permissions. An initial test-harness shutdown URL was incorrect; after changing it to the implemented /api/stop endpoint, startup and authenticated shutdown passed.

Before submission, the current source was compared with the tested copy, the archive and manifest were rechecked, and the 62 incident / 40 UI checks were rerun successfully. The start-screen image was visually checked for personal paths and result data. Public files were checked for private paths and credential-like content; the known match in production source was the existing secret-key-header masking expression. Pattern checks do not establish the absolute absence of secrets.

## Local archive

- File: `InvisiblePayloadScanner-v0.6.0.zip`
- Size: 153,912 bytes
- SHA-256: `B633675EE52F4904F6D86C6218946B9A2B8B9D85588DDB3CA6263D6FBC428501`
- Layout: one `InvisiblePayloadScanner-v0.6.0` folder, containing 16 explicitly selected files.

The archive, manifest and checksum remain local under the ignored dist directory. Tests, internal plans, logs, backups and scan results are excluded from the archive. The previous unpublished candidate was retained before replacement. A future Release upload must be separately authorized and downloaded again to verify this checksum; no remote artifact has been verified or published here.

## Limits and checks not performed

Live malware variants, execution inside an IDE, whole-device infection or recovery, and actual macOS execution were not tested. The Cursor fixtures cover the published macOS and Windows indicators, not those operating systems' runtime behavior.

No new manual browser download, keyboard, screen-reader or physical network-disconnection test was performed in this update. Earlier October 21 checks covered browser operation and user-confirmed JSON/text saves; screen-reader and first-time-user testing remained incomplete.

Select the actual extension folder for Cursor checks. VSIX/ZIP extraction or hash scanning, SSH settings, persistence, and extensions outside the selected root are out of scope. Renaming or obfuscating the indicators can evade these rules; a test bundle quoting both indicators can match. Existing compound-heuristic false positives may remain.
