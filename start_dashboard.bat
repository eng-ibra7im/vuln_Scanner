@echo off
echo ============================================================
echo   SecOps Orchestrator Dashboard
echo   Professional Web Interface v2.5.0
echo ============================================================
echo.
echo Starting server...
echo.

cd /d "%~dp0model"
set PATH=%PATH%;C:\Program Files\Go\bin;%USERPROFILE%\go\bin

call "%~dp0.venv\Scripts\activate.bat"
python web_server.py --host 0.0.0.0 --port 5001

pause
