@echo off
setlocal
title Iniciar SENTINEL
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0ops\windows\start.ps1"
set "RESULTADO=%ERRORLEVEL%"
if not "%RESULTADO%"=="0" echo Nao foi possivel iniciar. Leia a mensagem acima.
pause
exit /b %RESULTADO%
