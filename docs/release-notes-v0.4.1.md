# Invisible Payload Scanner v0.4.1

v0.4.1 is a stability release for the v0.4 "Verdict-First UX" line.

## Changes

- Fixes scan failures in folders that contain multi-GB model files such as `.safetensors` or `.pt`. Oversized files are now skipped by the configured maximum-file-size check before binary sampling.
- Fixes invisible-Unicode snippet generation when emoji or other supplementary Unicode characters appear near the match.
- Adds a self-test fixture for oversized unknown-extension files so the scanner does not regress to sampling files that should be skipped.
- Adds a self-test fixture for supplementary Unicode near invisible-Unicode findings.
- Improves diagnostics for unexpected scan failures by writing a masked detail line to the PowerShell window that started the tool.
- Improves the generic UI error text so users know to check the PowerShell window for details.

## Notes

The scanner remains static and read-only. It does not execute target files, install packages, call external APIs, or replace antivirus/EDR.

Existing v0.4.0 release assets are not replaced. Use v0.4.1 or later when scanning folders that may contain large model weights or runtime bundles.
