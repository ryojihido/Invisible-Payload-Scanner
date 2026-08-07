@echo off
setlocal
title Invisible Payload Scanner v0.5.0 - Evidence-First Supply Chain Scan
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Start-InvisiblePayloadScanner.ps1"
pause
