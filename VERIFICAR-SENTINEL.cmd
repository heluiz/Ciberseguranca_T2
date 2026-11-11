@echo off
setlocal
title Diagnostico SENTINEL
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0ops\windows\start.ps1" -DiagnosticOnly
set "RESULTADO=%ERRORLEVEL%"
pause
exit /b %RESULTADO%
