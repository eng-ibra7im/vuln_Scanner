# SecOps Orchestrator Dashboard
# Vulnerability Scanner v2.6.0

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  SecOps Orchestrator Dashboard" -ForegroundColor Cyan
Write-Host "  Vulnerability Scanner v2.6.0" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "Available Modules:" -ForegroundColor Yellow
Write-Host "  [+] Subdomain Scanner (5 tools)" -ForegroundColor Green
Write-Host "  [+] Path Discovery (4 tools)" -ForegroundColor Green
Write-Host "  [+] XSS Detection (3 tools)" -ForegroundColor Green
Write-Host "  [+] SQL Injection Scanner (3 tools)" -ForegroundColor Green
Write-Host "  [+] LFI Detection (3 tools)" -ForegroundColor Green
Write-Host ""

$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location "$scriptPath\model"

# Check Python virtual environment
if (-not (Test-Path "$scriptPath\.venv\Scripts\Activate.ps1")) {
    Write-Host "ERROR: Virtual environment not found!" -ForegroundColor Red
    Write-Host "Please run: python -m venv .venv" -ForegroundColor Yellow
    Write-Host "Then: .venv\Scripts\pip install -r requirements.txt" -ForegroundColor Yellow
    exit 1
}

Write-Host "Activating virtual environment..." -ForegroundColor Yellow
& "$scriptPath\.venv\Scripts\Activate.ps1"

# Check if port 5000 is available
$portInUse = Get-NetTCPConnection -LocalPort 5000 -ErrorAction SilentlyContinue
if ($portInUse) {
    Write-Host ""
    Write-Host "WARNING: Port 5000 is already in use!" -ForegroundColor Red
    Write-Host "Stopping existing Python processes..." -ForegroundColor Yellow
    Get-Process -Name python -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
}

Write-Host ""
Write-Host "Starting server on http://localhost:5000" -ForegroundColor Green
Write-Host "Dashboard URL: http://localhost:5000" -ForegroundColor Cyan
Write-Host "API Docs: http://localhost:5000/api/health" -ForegroundColor Cyan
Write-Host ""
Write-Host "Press Ctrl+C to stop the server" -ForegroundColor Yellow
Write-Host ""

python web_server.py --host 0.0.0.0 --port 5000
