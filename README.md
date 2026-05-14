# Vulnerability Scanner & Security Orchestrator Suite

An AI-powered security orchestration system for academic security research. This suite includes multiple orchestrators that generate execution plans, coordinate security tools, analyze results, and produce structured JSON output for web dashboard visualization.

## 🚀 Quick Start - Unified Dashboard

**Current startup path:**

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r model\requirements_api.txt
.\run.ps1
```

Or on `cmd`:

```bat
run.bat
```

Access the dashboard at: **http://localhost:5000**

**[📖 Quick Commands Guide →](QUICK_COMMANDS.md)** | **[🌐 Dashboard Guide (العربية) →](DASHBOARD_START_AR.md)** | **[📚 Full Guide →](UNIFIED_DASHBOARD.md)**

---

## 🎯 Overview

This suite includes:

### 1. Subdomain Enumeration Orchestrator
- Coordinates multiple subdomain discovery tools
- Passive and active enumeration
- Intelligent deduplication and classification

### 2. XSS Detection Orchestrator
- AI-powered XSS detection coordination
- Supports dalfox, nuclei, and xsstrike
- Automated vulnerability classification
- Risk scoring and false positive filtering
- Dashboard-ready JSON output

### 3. Path Discovery Orchestrator
- Hidden path and directory discovery
- API endpoint detection
- Intelligent wordlist management

### 4. SQL Injection Detection
- Automated SQLi vulnerability scanning
- Parameter analysis
- Evidence-based detection

**[XSS Orchestrator Documentation →](XSS_ORCHESTRATOR_README.md)** | **[Quick Start →](XSS_QUICKSTART.md)**

---

## 🛡️ Core Principles

All orchestrators follow these principles:
- **Does NOT execute tools directly** - generates execution plans for backend cloud systems
- Performs intelligent analysis, deduplication, and classification
- Outputs machine-readable JSON for dashboard integration
- **Detection and analysis only** - no exploitation
- Never invents vulnerabilities - evidence-based only

## 🎯 Unified Dashboard Features

✅ **All Modules in One Interface**
- Single dashboard for all security tools
- Real-time job tracking
- Unified result visualization

✅ **REST API Integration**
- Complete API for all modules
- Job management and tracking
- Result export and analysis

✅ **Parallel Execution**
- Run multiple scans simultaneously
- Independent module operation
- Efficient resource utilization

## 🛠️ Supported Tools

The orchestrator can coordinate the following subdomain discovery tools:

- **subfinder** - Fast passive subdomain enumeration using multiple sources
- **amass** - Comprehensive OWASP subdomain enumeration (passive/active modes)
- **sublist3r** - Multi-source enumeration via search engines and DNS
- **assetfinder** - Quick passive subdomain discovery
- **ffuf** - DNS brute forcing with wordlists

## 📋 Requirements

### Python Dependencies
```bash
python -m venv .venv
./.venv/Scripts/python -m pip install -r model/requirements_api.txt
```

### External Tools

Install the subdomain enumeration tools you want to use:

**Subfinder:**
```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

**Amass:**
```bash
go install -v github.com/owasp-amass/amass/v4/...@master
```

**Assetfinder:**
```bash
go install -v github.com/tomnomnom/assetfinder@latest
```

**Sublist3r:**
```bash
pip install sublist3r
```

**FFUF:**
```bash
go install github.com/ffuf/ffuf/v2@latest
```

> **Note:** Ensure all Go binaries are in your system PATH.

## 🚀 Quick Start

### 1. Generate Default Configuration

```bash
python config.py
```

This creates a `config.json` file with default settings.

### 2. Edit Configuration

Edit `config.json` to enable/disable tools and adjust settings:

```json
{
  "tools": {
    "subfinder": {
      "enabled": true,
      "description": "Fast passive subdomain enumeration"
    },
    "amass": {
      "enabled": true,
      "mode": "passive",
      "description": "Comprehensive subdomain enumeration"
    }
  },
  "parallel_execution": true,
  "save_results": true,
  "output_directory": "results"
}
```

### 3. Run Subdomain Enumeration

```bash
python orchestrator.py example.com
```

Or with output redirection:
```bash
python orchestrator.py example.com > results.json
```

---

## 🔴 XSS Detection Orchestrator

### Quick Start

Generate XSS detection execution plan:
```bash
cd model
python xss_cli.py plan --url "https://example.com/search?q=test"
```

Analyze XSS tool results:
```bash
python xss_cli.py analyze --url "https://example.com" --results raw_results.json
```

### Supported Tools
- **Dalfox** - Fast XSS scanner with DOM analysis
- **Nuclei** - Template-based XSS detection
- **XSStrike** - Advanced XSS with crawling and fuzzing

### Features
✅ AI-powered execution plan generation  
✅ Multi-tool result aggregation  
✅ Intelligent XSS type classification (Reflected, Stored, DOM, etc.)  
✅ Risk scoring (0-10 scale)  
✅ False positive filtering  
✅ Dashboard JSON output  
✅ Remediation recommendations  

### Programmatic Usage

```python
from xss_orchestrator import XSSOrchestrator

orchestrator = XSSOrchestrator()

# Generate execution plans
plans = orchestrator.generate_execution_plan("https://example.com/search?q=test")
plan_json = orchestrator.export_execution_plan_json(plans)

# Backend executes tools and returns results...

# Analyze results
analysis = orchestrator.analyze_results(raw_results, target_url)

# Generate dashboard output
dashboard_json = orchestrator.generate_dashboard_output(analysis, target_url)
```

### Documentation
- **[Full Documentation](XSS_ORCHESTRATOR_README.md)** - Complete guide
- **[Quick Start Guide](XSS_QUICKSTART.md)** - Get started in 5 minutes
- **[System Summary](XSS_SYSTEM_SUMMARY.md)** - Technical overview

**Example:** Test with sample data
```bash
cd model
python xss_cli.py analyze --url "https://testphp.vulnweb.com" --results examples/sample_raw_results.json
```

---

## 📊 Output Format

The orchestrator produces structured JSON output with the following sections:

### Metadata
```json
{
  "metadata": {
    "target_domain": "example.com",
    "scan_timestamp": "2026-02-13T10:30:00Z",
    "execution_time_seconds": 45.32,
    "orchestrator_version": "1.0.0"
  }
}
```

### Summary
```json
{
  "summary": {
    "total_subdomains": 127,
    "validated_subdomains": 89,
    "validation_rate_percent": 70.08,
    "high_priority_count": 12,
    "medium_priority_count": 34,
    "low_priority_count": 43
  }
}
```

### Subdomains
```json
{
  "subdomains": [
    {
      "subdomain": "admin.example.com",
      "priority": "high",
      "priority_score": 35,
      "status": "active",
      "dns_records": {
        "validated": true,
        "ip_addresses": ["192.168.1.100"],
        "has_mx_records": false
      },
      "classifications": ["admin"],
      "metadata": {
        "depth": 1,
        "is_wildcard": false
      }
    }
  ]
}
```

### Statistics & Patterns
Includes detailed statistics about:
- Tool performance
- Classification distribution
- Subdomain depth distribution
- Pattern analysis (numbered series, common prefixes, etc.)

### Recommendations
Actionable security recommendations based on findings:
```json
{
  "recommendations": [
    {
      "category": "security",
      "priority": "critical",
      "title": "Administrative Interfaces Detected",
      "description": "Found 3 subdomains with administrative interfaces.",
      "action": "Ensure proper authentication and access controls are in place"
    }
  ]
}
```

## � Web Reporting System

The system includes a comprehensive web reporting module that generates visual HTML reports from JSON results.

### Generate HTML Report

```bash
# Generate report from scan results
python reporter.py results.json report.html

# Or use with scan
python cli.py example.com -o results.json && python reporter.py results.json report.html
```

### Web Dashboard

Start the main integrated dashboard:

```bash
python web_server.py --host 0.0.0.0 --port 5000
```

Then visit: http://localhost:5000

### Features
- **Interactive Charts**: Priority distribution, tool performance
- **Detailed Tables**: Subdomain listings with DNS info
- **Summary Statistics**: Key metrics at a glance
- **Security Recommendations**: Prioritized action items
- **Pattern Analysis**: Visual representation of detected patterns
- **No Data Modification**: Strictly displays validated JSON results

### Demo Report

Generate a demo report with sample data:

```bash
python demo_reporter.py
```

This creates sample results and an HTML report you can view immediately.

See **[REPORTING.md](REPORTING.md)** for complete reporting documentation.

## �🔧 Configuration Options

### Tool Configuration

Each tool can be individually configured:

```json
{
  "tools": {
    "subfinder": {
      "enabled": true,
      "description": "Fast passive subdomain enumeration"
    },
    "amass": {
      "enabled": true,
      "mode": "passive",  // "passive" or "active"
      "description": "Comprehensive subdomain enumeration"
    },
    "ffuf": {
      "enabled": false,
      "wordlist": "wordlists/dns_common.txt",
      "description": "DNS brute forcing"
    }
  }
}
```

### Execution Settings

```json
{
  "parallel_execution": true,  // Run tools in parallel or sequentially
  "max_workers": 5,            // Max parallel workers
  "save_results": true,        // Save results to files
  "output_directory": "results" // Output directory path
}
```

### Analysis Settings

```json
{
  "perform_dns_validation": true,  // Validate subdomains via DNS
  "check_http_status": false,      // Check HTTP status (slower)
  "dns_timeout": 2,                // DNS query timeout in seconds
  "exclude_wildcard": true,        // Filter wildcard subdomains
  "min_subdomain_length": 3        // Minimum subdomain length
}
```

## 📁 Project Structure

```
vuln_Scanner/
├── orchestrator.py      # Main orchestration engine
├── config.py           # Configuration management
├── analyzer.py         # Result analysis and classification
├── formatter.py        # JSON output formatting
├── reporter.py         # Web reporting (HTML generation)
├── dashboard.py        # Web dashboard server
├── cli.py              # Command-line interface
├── api.py              # REST API server
├── setup.py            # Installation script
├── demo_reporter.py    # Reporting demo/test
├── examples.py         # Usage examples
├── requirements.txt    # Python dependencies
├── requirements_api.txt # API/Dashboard dependencies
├── config.json         # Configuration file (generated)
├── README.md           # Main documentation
├── QUICKSTART.md       # 5-minute quick start
├── REPORTING.md        # Web reporting documentation
├── ARCHITECTURE.md     # System architecture
├── API_EXAMPLES.md     # API usage examples
├── wordlists/          # DNS wordlists directory
└── results/            # Output directory (created automatically)
```

## 🔍 Classification System

The analyzer automatically classifies subdomains based on patterns:

| Classification | Pattern Examples |
|---------------|------------------|
| **development** | dev, test, staging, qa, uat |
| **admin** | admin, administrator, panel, dashboard |
| **api** | api, rest, graphql, websocket |
| **mail** | mail, smtp, imap, webmail |
| **vpn** | vpn, remote, citrix, portal |
| **storage** | s3, cdn, static, assets, media |
| **database** | db, mysql, postgres, mongo, redis |
| **ci_cd** | jenkins, gitlab, ci, deploy |
| **monitoring** | grafana, prometheus, kibana |
| **auth** | auth, sso, login, oauth, saml |

## 🎯 Priority Scoring

Subdomains are assigned priority scores based on:

- **DNS Validation** (+10 points)
- **Classifications** (+5 points per classification)
- **High-value classifications** (+10 points) - admin, api, vpn, dev, database
- **MX Records** (+8 points) - indicates mail server
- **Subdomain Depth** (+5 for shallow, -5 for deep)
- **Wildcard Detection** (-20 points)

Priority Levels:
- **High**: Score ≥ 20 (requires immediate attention)
- **Medium**: Score ≥ 10 (should be reviewed)
- **Low**: Score < 10 (informational)

## 🔐 Security & Ethics

### ⚠️ Important Guidelines

1. **Authorized Testing Only**: Only scan domains you own or have explicit permission to test
2. **Academic Use**: This tool is designed for educational and research purposes
3. **No Exploitation**: This system performs detection and analysis only - no exploitation
4. **Rate Limiting**: Be respectful of target systems and DNS servers
5. **Legal Compliance**: Ensure compliance with all applicable laws and regulations

### Responsible Disclosure

If you discover security issues during authorized testing:
1. Document findings professionally
2. Follow responsible disclosure practices
3. Do not exploit or publicize vulnerabilities before disclosure
4. Work with the organization to remediate issues

## 📝 Example Usage

### Basic Scan
```bash
python orchestrator.py example.com
```

### Save to File
```bash
python orchestrator.py example.com > scan_results.json
```

### Using Specific Tools Only
Edit `config.json` to enable only desired tools, then:
```bash
python orchestrator.py target-domain.com
```

### Programmatic Usage

```python
from orchestrator import SubdomainOrchestrator
from config import Config

# Load configuration
config = Config.load('config.json')

# Create orchestrator
orchestrator = SubdomainOrchestrator(config)

# Run enumeration
results = orchestrator.orchestrate('example.com')

# Access results
print(f"Found {results['summary']['total_subdomains']} subdomains")
print(f"High priority: {results['summary']['high_priority_count']}")
```

## 🐛 Troubleshooting

### Tool Not Found Errors

If you see "Tool not found" errors:
1. Ensure the tool is installed
2. Verify the tool is in your system PATH
3. Check tool-specific installation instructions

### DNS Resolution Issues

If DNS validation is slow or failing:
1. Check your DNS server configuration
2. Adjust `dns_timeout` in `config.json`
3. Disable `perform_dns_validation` for faster scans

### Timeout Issues

If tools are timing out:
1. Increase timeout values in execution plans
2. Reduce `max_workers` for parallel execution
3. Run tools sequentially by setting `parallel_execution: false`

## 📜 License

This tool is provided for academic and research purposes only. Users are responsible for ensuring their use complies with all applicable laws and regulations.

## 🤝 Contributing

This is an academic research project. Contributions that improve detection capabilities, analysis accuracy, or output formatting are welcome.

## 📚 References

- [OWASP Amass](https://github.com/owasp-amass/amass)
- [ProjectDiscovery Subfinder](https://github.com/projectdiscovery/subfinder)
- [Sublist3r](https://github.com/aboul3la/Sublist3r)
- [Assetfinder](https://github.com/tomnomnom/assetfinder)
- [FFUF](https://github.com/ffuf/ffuf)

## 📧 Support

For academic inquiries or issues, please refer to the project documentation or create an issue in the project repository.

---

**Remember:** Always obtain proper authorization before performing subdomain enumeration on any domain you do not own.



<!-- ./run.ps1 -->
