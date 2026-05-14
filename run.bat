@echo off
set SCRIPT_DIR=%~dp0

echo ============================================================
echo   SecOps Orchestrator Dashboard
echo   Vulnerability Scanner v2.6.0
echo ============================================================
echo.
echo Launching PowerShell entrypoint with startup checks...
echo.

where powershell >nul 2>nul
if errorlevel 1 (
    echo ERROR: PowerShell is not available on this system.
    pause
    exit /b 1
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%run.ps1"
set EXIT_CODE=%ERRORLEVEL%

if not "%EXIT_CODE%"=="0" (
    echo.
    echo Startup failed. Review the messages above.
    pause
    exit /b %EXIT_CODE%
)

pause
