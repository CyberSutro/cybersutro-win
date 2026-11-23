@echo off
REM Cybersutro win - lanzador para USB (doble clic)
REM Uso: Iniciar.bat            -> interfaz grafica
REM      Iniciar.bat consola    -> menu de consola
cd /d "%~dp0"
if /i "%~1"=="consola" (
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Cybersutro-Win.ps1" -Console
) else (
    powershell.exe -NoProfile -ExecutionPolicy Bypass -STA -File "%~dp0Cybersutro-Win.ps1"
)
