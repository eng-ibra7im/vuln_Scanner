# SecOps Orchestrator Dashboard
# Vulnerability Scanner v2.6.0

$ErrorActionPreference = "Stop"

function Write-Section($message, $color = "Cyan") {
    Write-Host $message -ForegroundColor $color
}

$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$modelPath = Join-Path $scriptPath "model"
$pythonExe = Join-Path $scriptPath ".venv\Scripts\python.exe"
$configPath = Join-Path $modelPath "config.json"
$webServerPath = Join-Path $modelPath "web_server.py"
$webInterfacePath = Join-Path $scriptPath "web\web_interface.html"

Write-Section "============================================================"
Write-Section "  SecOps Orchestrator Dashboard"
Write-Section "  Vulnerability Scanner v2.6.0"
Write-Section "============================================================"
Write-Host ""

Write-Section "Available Modules:" "Yellow"
Write-Section "  [+] Subdomain Scanner (5 tools)" "Green"
Write-Section "  [+] Path Discovery (4 tools)" "Green"
Write-Section "  [+] XSS Detection (3 tools)" "Green"
Write-Section "  [+] SQL Injection Scanner (3 tools)" "Green"
Write-Section "  [+] LFI Detection (3 tools)" "Green"
Write-Host ""

$requiredFiles = @(
    @{ Path = $pythonExe; Description = "virtual environment Python"; Hint = "python -m venv .venv" },
    @{ Path = $webServerPath; Description = "web server entrypoint"; Hint = "Restore model\web_server.py" },
    @{ Path = $configPath; Description = "configuration file"; Hint = ".\.venv\Scripts\python.exe model\config.py" },
    @{ Path = $webInterfacePath; Description = "web interface"; Hint = "Restore web\web_interface.html" }
)

foreach ($item in $requiredFiles) {
    if (-not (Test-Path $item.Path)) {
        Write-Section "ERROR: Missing $($item.Description): $($item.Path)" "Red"
        Write-Section "Suggested fix: $($item.Hint)" "Yellow"
        exit 1
    }
}

$dependencyCheckScript = @'
import importlib
import sys

required = ["flask", "flask_cors", "requests", "httpx", "dns.resolver"]
missing = []

for module_name in required:
    try:
        importlib.import_module(module_name)
    except Exception:
        missing.append(module_name)

if missing:
    print("\n".join(missing))
    sys.exit(1)
'@

$missingModules = @($dependencyCheckScript | & $pythonExe - 2>$null)
if ($LASTEXITCODE -ne 0) {
    Write-Section "ERROR: Missing required Python packages." "Red"
    Write-Section "Missing modules: $($missingModules -join ', ')" "Yellow"
    Write-Section "Install them with:" "Yellow"
    Write-Section "  .\.venv\Scripts\python.exe -m pip install -r model\requirements_api.txt" "Cyan"
    exit 1
}

$optionalTools = @(
    "subfinder",
    "amass",
    "sublist3r",
    "assetfinder",
    "ffuf",
    "arjun",
    "paramspider",
    "dalfox",
    "nuclei",
    "xsstrike",
    "sqlmap",
    "ghauri",
    "dotdotpwn"
)

$env:PATH = "$scriptPath\.venv\Scripts;" + $env:PATH

$missingTools = @()
foreach ($tool in $optionalTools) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        $missingTools += $tool
    }
}

if ($missingTools.Count -gt 0) {
    Write-Section "Optional tools not found: $($missingTools -join ', ')" "Yellow"
    Write-Section "The dashboard will still start, but some scanners will fall back or stay unavailable." "Yellow"
    Write-Host ""
}

$listenConnections = Get-NetTCPConnection -LocalPort 5000 -State Listen -ErrorAction SilentlyContinue
if ($listenConnections) {
    $owningProcesses = $listenConnections | Select-Object -ExpandProperty OwningProcess -Unique

    foreach ($processId in $owningProcesses) {
        $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
        if (-not $process) {
            continue
        }

        if ($process.ProcessName -like "python*") {
            Write-Section "Port 5000 is already in use by PID $processId ($($process.ProcessName)). Stopping it..." "Yellow"
            Stop-Process -Id $processId -Force
        } else {
            Write-Section "ERROR: Port 5000 is in use by PID $processId ($($process.ProcessName))." "Red"
            Write-Section "Stop that process manually or run web_server.py on another port." "Yellow"
            exit 1
        }
    }

    Start-Sleep -Seconds 1
}

Set-Location $modelPath

Write-Host ""
Write-Section "Starting server on http://localhost:5000" "Green"
Write-Section "Dashboard URL: http://localhost:5000" "Cyan"
Write-Section "API Docs: http://localhost:5000/api/health" "Cyan"
Write-Host ""
Write-Section "Press Ctrl+C to stop the server" "Yellow"
Write-Host ""

& $pythonExe "web_server.py" "--host" "0.0.0.0" "--port" "5000"
