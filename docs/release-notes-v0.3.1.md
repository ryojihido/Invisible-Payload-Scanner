# Invisible Payload Scanner v0.3.1

v0.3.1 is a context-aware triage update for the v0.3 Contagious Interview Pre-Scan line.

## Changes

- Adds `signalSeverity`, `actionability`, and `triageNote` fields to scan results.
- Adds top-level `signalSummary` so exported JSON shows both response-priority counts and original signal counts.
- Adds a Japanese/English UI language switch.
- Keeps root `.github/workflows/*.yml` findings as high-priority repository automation risks.
- Lowers the displayed priority of nested GitHub Actions workflows inside SDKs, vendored dependencies, or copied upstream components while preserving their original danger signal.
- Updates the Web UI to show both the displayed priority and the original signal when they differ.
- Keeps install lifecycle scripts, folder-open tasks, Git hooks, root workflow findings, and invisible Unicode findings at their existing priority.

## Notes

This release does not suppress nested workflow findings. It makes them easier to triage by treating them as CI review material unless the user plans to run or enable automation for the nested component.

The scanner remains read-only. It does not execute target files, install packages, call external APIs, or replace antivirus/EDR.
