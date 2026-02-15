# 🚀 Quick Start - Unified Dashboard

## Start All Modules

Run the unified dashboard with all security modules:

```powershell
# Easy method - PowerShell script
.\start_dashboard.ps1

# OR Python directly
python run_dashboard.py
```

## Access Dashboard

Open your browser:
```
http://localhost:5001
```

## ✅ All Integrated Modules

The dashboard runs all modules automatically:

1. **🔍 Subdomain Enumeration** (Subfinder, Amass, Assetfinder)
2. **⚡ XSS Detection** (Automated testing & analysis)
3. **🛣️ Path Discovery** (Hidden paths & API endpoints)
4. **💉 SQL Injection** (Automated vulnerability scanning)

## 🎯 Module Status

When you start the dashboard, you'll see:

```
======================================================================
  SecOps Orchestrator - Unified Security Dashboard
======================================================================

🚀 Starting Dashboard Server
📍 URL: http://0.0.0.0:5001

✅ Available Modules:
   • Subdomain Enumeration: ✅ Active
   • XSS Detection: ✅ Active
   • Path Discovery: ✅ Active
   • SQL Injection: ✅ Active

🛑 Press Ctrl+C to stop the server
======================================================================
```

## 🔧 API Endpoints

All modules accessible via REST API:

```bash
# Subdomain scanning
POST /api/scan

# XSS testing
POST /api/xss/generate-plan
POST /api/xss/execute-plan

# Path discovery
POST /api/path/scan

# System info
GET  /api/stats
GET  /api/tools
GET  /api/jobs
```

## 🛑 Stop Dashboard

Press `Ctrl + C` or run:

```powershell
.\stop_dashboard.ps1
```

## 📊 Check Status

```powershell
# Check if running
netstat -ano | Select-String "5001"

# View available tools
curl http://localhost:5001/api/tools

# View statistics
curl http://localhost:5001/api/stats
```

## ⚙️ Advanced Options

```powershell
# Custom port
python run_dashboard.py --port 8080

# Debug mode
python run_dashboard.py --debug

# Custom host
python run_dashboard.py --host 127.0.0.1 --port 8080
```

## 📁 Results Location

- `results/` - Subdomain scan results
- `xss_results/` - XSS test results
- `sqli_results/` - SQL injection results

## 📚 Documentation

- [Full Dashboard Guide](DASHBOARD_GUIDE.md)
- [API Examples](API_EXAMPLES.md)
- [Troubleshooting](TROUBLESHOOTING_AR.md)
- [Arabic Guide](DASHBOARD_START_AR.md)

---

**Version:** 2.0 | **Date:** February 2026
