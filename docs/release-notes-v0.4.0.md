# Invisible Payload Scanner v0.4.0

v0.4.0 "Verdict-First UX" reworks the result screen so non-engineers can decide what to do, and adds download-and-execute detection on top of the v0.3 Contagious Interview Pre-Scan line.

## Changes

- Adds a **verdict card** above the findings table: 🔴 "do not run", 🟡 "check before running", or 🟢 "no dangerous entry points found", each with concrete next steps.
- Drives the red verdict from Critical/High findings (excluding scanner-internal context); de-escalates results to yellow when every finding is in a false-positive-leaning context.
- Rewords hard terms in the verdict card (e.g. "variation selector" -> "invisible special character", "install lifecycle script" -> "script that runs automatically on install").
- Sorts findings by severity (critical -> info) and adds severity tooltips.
- Adds a persistent pre-scan line: the tool only reads files, does not execute or transmit anything, and results stay on the local PC.
- Adds a **Stop scan** button (client-side abort plus server-side cancel on client disconnect); renames "Stop server" to "Quit tool" to prevent mis-clicks.
- Adds **release-authenticity verification**: a one-line `Get-FileHash` SHA-256 check documented in the README, and the startup banner now prints the script's own SHA-256.
- Adds **download-and-execute detection** (`rules/v0.4/download-and-execute-rules.json`): `curl|wget … | sh/bash/node`, `iwr/irm … | iex`, `powershell -e/-enc <base64>`, and LOLBins (`certutil -urlcache/-decode`, `mshta https:`, `bitsadmin /transfer`, `rundll32 … javascript:`). Single matches are Low/Info; they escalate to High/Critical only when combined with folder-open tasks, install lifecycle scripts, Git hooks, or workflows.
- Keeps invisible-Unicode, npm supply-chain IoC, editor/AI-agent auto-run, Git hook, and workflow detections from earlier releases at their existing priority.

## Notes

The verdict is a triage aid, not an infection verdict. A green result is not a safety guarantee.

`rules/v0.4/download-and-execute-rules.json` follows the v0.3 "escalate only when combined" approach to keep false positives low. Official installer one-liners (for example `curl -fsSL https://get.pnpm.io | sh`) are intentionally not added to safe-patterns, so unknown repositories still prompt a check; documentation-context matches are lowered to Info instead.

The server defenses are unchanged: localhost-only bind, per-launch random API token, Origin/Host checks, Content-Security-Policy, reparse-point non-following, and request/size limits.

The scanner remains static and read-only. It does not execute target files, install packages, call external APIs, or replace antivirus/EDR.

`_selftest` and `_compound_selftest` remain excluded by default and are cleaned after self-test runs because they contain intentionally suspicious fixtures used to verify detection logic.
