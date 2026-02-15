# Quick Start Guide

Get up and running with the Subdomain Enumeration Orchestrator in 5 minutes!

## Prerequisites

- Python 3.7 or higher
- Go (for installing external tools)
- Internet connection

## Step 1: Clone/Download

You already have the files in `d:\vuln_Scanner`.

## Step 2: Run Setup

```bash
cd d:\vuln_Scanner
python setup.py
```

This will:
- ✓ Check Python version
- ✓ Install Python dependencies
- ✓ Check for external tools
- ✓ Create default configuration
- ✓ Create necessary directories

## Step 3: Install External Tools (Optional)

If you don't have the external tools yet, install at least one:

### Install Subfinder (Recommended - Fast & Easy)

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

### Install Amass (Comprehensive)

```bash
go install -v github.com/owasp-amass/amass/v4/...@master
```

### Install Assetfinder (Quick)

```bash
go install -v github.com/tomnomnom/assetfinder@latest
```

**Important:** Make sure your Go bin directory is in your PATH:
- Linux/Mac: `~/go/bin`
- Windows: `%USERPROFILE%\go\bin`

## Step 4: Configure

Edit `config.json` to enable only the tools you have installed:

```json
{
  "tools": {
    "subfinder": {
      "enabled": true
    },
    "amass": {
      "enabled": false
    },
    "assetfinder": {
      "enabled": false
    }
  }
}
```

## Step 5: Run Your First Scan

### Using the orchestrator directly:

```bash
python orchestrator.py example.com
```

### Using the CLI (recommended):

```bash
python cli.py example.com --summary-only
```

### Save results to a file:

```bash
python cli.py example.com -o results.json
```

## Understanding the Output

The system will output JSON with:

```json
{
  "success": true,
  "summary": {
    "total_subdomains": 25,
    "validated_subdomains": 20,
    "high_priority_count": 3,
    "medium_priority_count": 8,
    "low_priority_count": 9
  },
  "subdomains": [
    {
      "subdomain": "mail.example.com",
      "priority": "high",
      "status": "active",
      "classifications": ["mail"]
    }
  ],
  "recommendations": [...]
}
```

## Step 6: Generate Web Reports (Optional)

### Generate HTML report from JSON results:

```bash
python reporter.py results.json report.html
```

### Or try the demo report:

```bash
python demo_reporter.py
```

This creates a sample report with visualizations that you can view in your browser.

### Start the Web Dashboard:

```bash
python dashboard.py --host 0.0.0.0 --port 5001
```

Then visit: http://localhost:5001

The dashboard lets you:
- Upload JSON results
- View HTML reports with charts
- Browse multiple scan results
- Download reports

See [REPORTING.md](REPORTING.md) for complete reporting documentation.

## Common Use Cases

### 1. Quick Scan with Summary Only

```bash
python cli.py example.com --summary-only
```

### 2. High Priority Subdomains Only

```bash
python cli.py example.com --high-priority-only
```

### 3. Use Specific Tools

```bash
python cli.py example.com --tools subfinder,amass
```

### 4. Export as CSV

```bash
python cli.py example.com -f csv -o results.csv
```

### 5. Export as Markdown Report

```bash
python cli.py example.com -f markdown -o report.md
```

### 6. Fast Scan (No DNS Validation)

```bash
python cli.py example.com --no-validate
```

## Running the API Server

If you want to integrate with a web dashboard:

### 1. Install API dependencies:

```bash
pip install -r requirements_api.txt
```

### 2. Start the server:

```bash
python api.py --host 0.0.0.0 --port 5000
```

### 3. Test the API:

```bash
# Health check
curl http://localhost:5000/api/health

# Start a scan
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

See [API_EXAMPLES.md](API_EXAMPLES.md) for more API documentation.

## Running Examples

To see programmatic usage examples:

```bash
python examples.py
```

This demonstrates:
- Basic scanning
- Custom configuration
- Filtering results
- Export formats
- Security recommendations
- Pattern analysis
- Tool comparison

## Troubleshooting

### "Tool not found" error

Make sure the tool is:
1. Installed (`go install ...`)
2. In your PATH
3. Enabled in `config.json`

Test if tool is accessible:
```bash
# Windows
where subfinder

# Linux/Mac
which subfinder
```

### DNS resolution is slow

Either:
1. Disable DNS validation for faster scans:
   ```bash
   python cli.py example.com --no-validate
   ```

2. Or adjust timeout in `config.json`:
   ```json
   {
     "dns_timeout": 5
   }
   ```

### No subdomains found

This could mean:
1. The domain has few/no subdomains
2. Tools are not finding them (try enabling more tools)
3. Tools are not installed correctly

Try with a known domain with many subdomains:
```bash
python cli.py google.com --summary-only
```

## Next Steps

### Learn More
- Read [README.md](README.md) for full documentation
- Study [ARCHITECTURE.md](ARCHITECTURE.md) to understand the system
- Check [API_EXAMPLES.md](API_EXAMPLES.md) for API integration

### Customize
1. Edit `config.json` to adjust settings
2. Modify classification patterns in `analyzer.py`
3. Add custom output formats in `formatter.py`

### Integrate
- Import as a Python module in your scripts
- Use the REST API for web dashboards
- Schedule scans with cron/Task Scheduler

## Important Reminders

⚠️ **Legal and Ethical Use**
- Only scan domains you own or have permission to test
- This tool is for educational/research purposes
- Comply with all applicable laws and regulations
- Use responsibly and ethically

## Getting Help

If you encounter issues:

1. Check the troubleshooting section above
2. Review the full documentation in README.md
3. Ensure all prerequisites are installed
4. Verify your configuration is correct

## Quick Reference

| Command | Purpose |
|---------|---------|
| `python setup.py` | Initial setup |
| `python orchestrator.py <domain>` | Basic scan |
| `python cli.py <domain>` | CLI scan with options |
| `python api.py` | Start API server |
| `python examples.py` | Run examples |
| `python config.py` | Generate default config |

## Success! 🎉

You're now ready to use the Subdomain Enumeration Orchestrator!

Start with this simple command:
```bash
python cli.py example.com --summary-only
```

Happy scanning! 🔍
