@echo off
echo ============================================================
echo   SecOps Orchestrator Dashboard
echo   Vulnerability Scanner v2.5.0
echo ============================================================
echo.

cd /d "%~dp0model"

echo Activating virtual environment...
call "%~dp0.venv\Scripts\activate.bat"

echo.
echo Starting server on http://localhost:5000
echo Press Ctrl+C to stop the server
echo.

python web_server.py --host 0.0.0.0 --port 5000

pause
