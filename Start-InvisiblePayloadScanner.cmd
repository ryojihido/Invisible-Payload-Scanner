@echo off
setlocal
title Invisible Payload Scanner v0.6.0
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Start-InvisiblePayloadScanner.ps1"
pause
