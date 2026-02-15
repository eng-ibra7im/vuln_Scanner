# 🎯 Vulnerability Scanner Project - Complete Overview

## 📁 Project Structure

```
D:\vuln_Scanner\
│
├── model/                          # Subdomain Enumeration System
├── web/                            # Subdomain Web Interface
│
└── path_discovery/                 # Path Discovery System
    ├── model/                      # Path Discovery Backend
    ├── web/                        # Path Discovery Web Interface
    ├── README.md
    └── QUICKSTART.md
```

---

## 🔍 System 1: Subdomain Enumeration Orchestrator

**Location**: `model/` and `web/`

### Purpose:
Discovers **subdomains** for a given domain (e.g., admin.example.com, api.example.com)

### Tools Used:
- Subfinder
- Amass
- Assetfinder
- Sublist3r
- FFUF (DNS brute force)

### Input:
Domain name (e.g., `example.com`)

### Output:
- List of discovered subdomains
- DNS validation status
- Classification (admin, api, mail, vpn, etc.)
- Priority scoring

### Quick Start:
```bash
cd model
python web_server.py
# Open: http://localhost:5000
```

### Example:
```
Input: google.com
Output: 
- www.google.com
- mail.google.com
- admin.google.com
- api.google.com
(280+ subdomains found)
```

---

## 🛣️ System 2: Path Discovery Orchestrator

**Location**: `path_discovery/`

### Purpose:
Discovers **paths and parameters** on a given URL (e.g., /admin, /login, /api)

### Tools Used:
- FFUF (web fuzzing)
- Dirsearch (path scanning)
- Arjun (parameter discovery)
- ParamSpider (parameter mining)

### Input:
Full URL (e.g., `https://example.com`)

### Output:
- List of discovered paths
- HTTP status codes
- Parameters found
- Classification (admin, auth, api, backup, etc.)
- Priority scoring

### Quick Start:
```bash
cd path_discovery\model
python web_server.py
# Open: http://localhost:5001
```

### Example:
```
Input: https://httpbin.org
Output:
- https://httpbin.org/admin (403 - HIGH)
- https://httpbin.org/login (200 - HIGH)
- https://httpbin.org/api (200 - MEDIUM)
- https://httpbin.org/robots.txt (200 - LOW)
```

---

## 📊 Side-by-Side Comparison

| Feature | Subdomain Enumeration | Path Discovery |
|---------|----------------------|----------------|
| **Input** | Domain name | Full URL |
| **Discovers** | Subdomains | Paths & Parameters |
| **Example Input** | `google.com` | `https://google.com` |
| **Example Output** | `admin.google.com` | `https://google.com/admin` |
| **Port** | 5000 | 5001 |
| **Tools** | Subfinder, Amass, etc. | FFUF, Dirsearch, etc. |
| **Use Case** | Find all subdomains | Find hidden paths |
| **Classification** | DNS, Mail, API, Admin | Admin, Auth, Backup, API |

---

## 🚀 Complete Workflow

### Phase 1: Subdomain Discovery
```bash
cd model
python web_server.py
# Scan: example.com
# Result: Find 50+ subdomains
```

### Phase 2: Path Discovery
```bash
cd ..\path_discovery\model
python web_server.py
# Scan each subdomain found:
# - https://admin.example.com
# - https://api.example.com
# Result: Find hidden paths on each subdomain
```

---

## 🎯 Use Cases

### Subdomain Enumeration:
- 🔍 Attack surface mapping
- 🌐 Infrastructure discovery
- 📧 Finding mail servers
- 🔐 Locating admin panels
- 🔄 VPN endpoints

### Path Discovery:
- 📂 Hidden directories
- 🔐 Admin panels
- 🔑 Authentication endpoints
- 📡 API documentation
- 💾 Backup files
- ⚙️ Configuration files
- 🐛 Debug endpoints

---

## 📝 Example Real-World Workflow

### 1. Start with Subdomain Discovery
```bash
cd model
python api_finder.py google.com
```
**Found:**
- admin.google.com
- api.google.com
- mail.google.com

### 2. Run Path Discovery on Each
```bash
cd ..\path_discovery\model
python api_finder.py https://admin.google.com
```
**Found:**
- /login
- /dashboard
- /api/v1
- /config

### 3. Analyze Results
- High priority: `/admin/config` (403)
- Medium priority: `/api/v1` (200)
- Low priority: `/images` (200)

---

## 🔧 API Integration

### Subdomain Enumeration API:
```python
import requests

# Start scan
response = requests.post('http://localhost:5000/api/scan', json={
    'domain': 'example.com',
    'tools': ['subfinder', 'amass']
})

job_id = response.json()['job_id']

# Get results
results = requests.get(f'http://localhost:5000/api/scan/{job_id}/results')
subdomains = results.json()['subdomains']

# Analyze top priority subdomains
for subdomain in subdomains:
    if subdomain['priority'] == 'high':
        print(f"Check: {subdomain['subdomain']}")
```

### Path Discovery API:
```python
# For each high-priority subdomain, scan paths
for subdomain in high_priority_subdomains:
    url = f"https://{subdomain}"
    
    response = requests.post('http://localhost:5001/api/scan', json={
        'url': url,
        'tools': ['ffuf', 'dirsearch']
    })
    
    # Process results...
```

---

## ⚙️ Configuration Files

### Subdomain Enumeration Config:
**File**: `model/config.json`
```json
{
  "tools": {
    "subfinder": {"enabled": true},
    "amass": {"enabled": true}
  },
  "use_api_fallback": true,
  "perform_dns_validation": true
}
```

### Path Discovery Config:
**File**: `path_discovery/model/config.json`
```json
{
  "tools": {
    "ffuf": {"enabled": true, "wordlist": "wordlists/common.txt"},
    "dirsearch": {"enabled": true}
  },
  "use_api_fallback": true,
  "verify_endpoints": false
}
```

---

## 🎓 Installation & Setup

### Both Systems:
```bash
# 1. Navigate to project
cd D:\vuln_Scanner

# 2. Install subdomain enumeration dependencies
cd model
pip install -r requirements.txt

# 3. Install path discovery dependencies
cd ..\path_discovery\model
pip install -r requirements.txt

# 4. Done! Both systems ready to use
```

---

## 🚨 API Mode (No Tools Required)

Both systems work **without installing any tools** using API fallback:

### Subdomain Enumeration API Mode:
- crt.sh (Certificate Transparency)
- HackerTarget API
- ThreatCrowd API
- Common subdomain brute force

### Path Discovery API Mode:
- Common path checking
- robots.txt parsing
- sitemap.xml analysis
- Standard endpoint testing

---

## 📊 Output Formats

### Both Systems Provide:
- ✅ **JSON** - Structured data for integration
- ✅ **Web Dashboard** - Visual interface
- ✅ **REST API** - Programmatic access
- ✅ **Real-time Updates** - Progress tracking
- ✅ **Priority Scoring** - Risk-based ranking
- ✅ **Classifications** - Automated categorization
- ✅ **Recommendations** - Actionable insights

---

## 🎯 Quick Reference

### Start Subdomain Enumeration:
```bash
cd model
python web_server.py
```
Open: http://localhost:5000

### Start Path Discovery:
```bash
cd path_discovery\model
python web_server.py
```
Open: http://localhost:5001

### Test Without Tools:
```bash
# Subdomain
cd model
python api_finder.py google.com

# Path Discovery
cd ..\path_discovery\model
python api_finder.py https://httpbin.org
```

---

## ⚠️ Important Notes

- ✅ Both systems follow AI orchestrator pattern
- ✅ Generate execution plans (don't execute directly)
- ✅ Detection and analysis only
- ✅ No exploitation
- ✅ Assume authorization
- ✅ Valid JSON output
- ⚠️ For academic/authorized testing only

---

## 🎉 Summary

You now have **TWO complete security orchestration systems**:

1. **Subdomain Enumeration** - Finds subdomains
2. **Path Discovery** - Finds paths and parameters

Both systems:
- ✅ Work independently
- ✅ Can be combined for full coverage
- ✅ Have web interfaces
- ✅ Provide REST APIs
- ✅ Work without tools (API mode)
- ✅ Output structured JSON

**Ready to start scanning!** 🚀
