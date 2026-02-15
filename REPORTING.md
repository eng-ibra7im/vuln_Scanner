# Web Reporting System

The Web Reporting System generates visual HTML reports from subdomain enumeration results. It provides summary statistics, interactive charts, and detailed tables without modifying or inferring data.

## Components

### 1. Reporter (`reporter.py`)
Generates static HTML reports from JSON results with:
- Summary statistics cards
- Interactive charts (Chart.js)
- Detailed subdomain tables
- Tool performance visualization
- Pattern analysis displays
- Security recommendations

### 2. Dashboard (`dashboard.py`)
Web-based interface for viewing and managing reports:
- Upload JSON results
- Browse available reports
- View reports in browser
- Download JSON files
- REST API for integration

## Features

### ✅ Data Integrity
- **No modification**: Displays data exactly as provided in JSON
- **No inference**: Does not generate or infer new data
- **Validation only**: Only validates JSON structure

### 📊 Visualizations
- **Priority Distribution**: Doughnut chart showing high/medium/low priority counts
- **Tool Performance**: Bar charts for subdomains found and execution time
- **Statistics Cards**: Key metrics at a glance
- **Detailed Tables**: Sortable subdomain listings

### 🎨 Design
- **Responsive**: Works on desktop, tablet, and mobile
- **Modern UI**: Clean, professional interface
- **Print-friendly**: Optimized CSS for printing
- **Color-coded**: Priority levels clearly distinguished

## Quick Start

### Generate HTML Report from JSON

```bash
# Basic usage
python reporter.py results.json

# Specify output file
python reporter.py results.json report.html
```

### Start Web Dashboard

```bash
python dashboard.py --host 0.0.0.0 --port 5001
```

Then open: http://localhost:5001

## Usage Examples

### Example 1: Generate Report from Scan Results

```bash
# Run a scan and save results
python orchestrator.py example.com > results.json

# Generate HTML report
python reporter.py results.json report.html

# Open in browser
start report.html  # Windows
# or
open report.html  # Mac/Linux
```

### Example 2: Integrated Workflow

```bash
# Scan and generate report in one go
python cli.py example.com -o scan_results.json && python reporter.py scan_results.json
```

### Example 3: Using the Dashboard

```bash
# Start dashboard
python dashboard.py

# In another terminal, run scan and save to results directory
python cli.py example.com -o results/scan_$(date +%Y%m%d_%H%M%S).json

# View in dashboard at http://localhost:5001
```

### Example 4: Programmatic Usage

```python
from reporter import SubdomainReporter
import json

# Load results
with open('scan_results.json', 'r') as f:
    results = json.load(f)

# Generate report
reporter = SubdomainReporter()
html = reporter.generate_report(results, 'output.html')

print("Report generated: output.html")
```

## Report Sections

### 1. Header
- Target domain
- Scan timestamp
- Execution time

### 2. Summary Statistics
**Cards displaying:**
- Total subdomains discovered
- Validated subdomain count
- Validation rate percentage
- High/medium/low priority counts
- Tools executed
- Total execution time

### 3. Detailed Statistics
**Metadata grid showing:**
- Priority distribution breakdown
- Depth distribution
- Validation rate

### 4. Priority Distribution Chart
**Doughnut chart showing:**
- Percentage of high priority subdomains (red)
- Percentage of medium priority (orange)
- Percentage of low priority (green)

### 5. Subdomains Table
**Top 100 subdomains with:**
- Subdomain name
- Priority level (color-coded badge)
- Status (active/inactive)
- Classifications (tagged)
- IP addresses

### 6. Tool Performance Charts
**Two bar charts:**
1. Subdomains found by each tool
2. Execution time per tool

### 7. Patterns Section
**Tables showing:**
- Common prefixes and their counts
- Environment indicators (dev, test, prod)
- Technology indicators (api, mail, vpn)

### 8. Security Recommendations
**Prioritized recommendations with:**
- Priority badge (critical/high/medium/low)
- Category (security, cleanup, information)
- Description
- Suggested action

## API Endpoints (Dashboard)

### GET /
Main dashboard interface

### POST /upload
Upload JSON results file
```bash
curl -X POST http://localhost:5001/upload \
  -F "file=@results.json"
```

### GET /view/:filename
View HTML report for a specific JSON file
```bash
curl http://localhost:5001/view/scan_results.json
```

### GET /download/:filename
Download JSON file
```bash
curl http://localhost:5001/download/scan_results.json -O
```

### GET /api/reports
List all available reports
```bash
curl http://localhost:5001/api/reports
```

Response:
```json
{
  "success": true,
  "reports": [
    {
      "filename": "scan_20260213.json",
      "modified_display": "2026-02-13 15:30:00",
      "size": 45678
    }
  ]
}
```

### GET /api/report/:filename
Get raw JSON data
```bash
curl http://localhost:5001/api/report/scan_results.json
```

## Data Flow

```
Subdomain Scan (orchestrator.py)
           ↓
      JSON Results
           ↓
   ┌──────┴──────┐
   │             │
Reporter      Dashboard
   │             │
   ↓             ↓
HTML File    Web Interface
```

## Report Elements

### Priority Badges
- **🔴 HIGH**: Critical items requiring immediate attention
- **🟠 MEDIUM**: Important items to review
- **🟢 LOW**: Informational items

### Status Indicators
- **✓ ACTIVE**: DNS validated, resolving
- **✗ INACTIVE**: Not resolving or validation failed

### Classification Tags
Small gray badges showing:
- `admin` `api` `mail` `vpn` `dev` `database` `monitoring` etc.

### Recommendation Cards
Color-coded left border:
- Red: Critical security issues
- Orange: High priority issues
- Yellow: Medium priority issues
- Green: Low priority or informational

## Customization

### Modify Report Styling

Edit the `<style>` section in `reporter.py` `_generate_html_header()` method:

```python
def _generate_html_header(self) -> str:
    return '''
    <style>
        /* Customize colors */
        header {
            background: linear-gradient(135deg, #YOUR_COLOR1 0%, #YOUR_COLOR2 100%);
        }
        
        /* Customize fonts */
        body {
            font-family: 'Your Font', sans-serif;
        }
    </style>
    '''
```

### Add Custom Sections

Add a new method to `SubdomainReporter` class:

```python
def _generate_custom_section(self, results: Dict[str, Any]) -> str:
    """Generate custom section"""
    html = '''
        <div class="section">
            <h2>Custom Section</h2>
            <p>Your custom content here</p>
        </div>
    '''
    return html
```

Then call it in `generate_report()`:

```python
html_parts.append(self._generate_custom_section(results))
```

## Integration with External Systems

### Export to PDF

Use a headless browser to convert HTML to PDF:

```bash
# Using wkhtmltopdf
wkhtmltopdf report.html report.pdf

# Using Chrome headless
chrome --headless --print-to-pdf=report.pdf report.html
```

### Embed in Existing Dashboard

Fetch report HTML via API:

```javascript
fetch('http://localhost:5001/view/scan_results.json')
  .then(response => response.text())
  .then(html => {
    document.getElementById('report-container').innerHTML = html;
  });
```

### Webhook Integration

Auto-generate reports after scans:

```python
from orchestrator import SubdomainOrchestrator
from reporter import SubdomainReporter
import requests

# Run scan
orchestrator = SubdomainOrchestrator(config)
results = orchestrator.orchestrate('example.com')

# Generate report
reporter = SubdomainReporter()
html = reporter.generate_report(results, 'report.html')

# Send webhook
requests.post('https://your-webhook-url.com', json={
    'domain': 'example.com',
    'report_url': 'https://your-server.com/report.html'
})
```

## Troubleshooting

### Charts Not Displaying

**Problem**: Charts show as blank
**Solution**: Ensure internet connection for Chart.js CDN or use local Chart.js

### File Upload Fails

**Problem**: Upload returns error
**Solution**: 
- Check JSON is valid
- Ensure file has .json extension
- Check file size limits

### Report Shows "No Data"

**Problem**: Empty sections in report
**Solution**: 
- Verify JSON has required fields
- Check that scan actually found subdomains
- Validate JSON structure matches expected format

### Dashboard Won't Start

**Problem**: `Address already in use`
**Solution**: 
```bash
# Use different port
python dashboard.py --port 5002

# Or kill process using port
# Windows: netstat -ano | findstr :5001
# Linux: lsof -ti:5001 | xargs kill
```

## Performance Considerations

### Large Result Sets

For scans with 1000+ subdomains:
- Table shows top 100 by default
- Charts remain responsive
- Full data available in JSON download

### Multiple Reports

Dashboard efficiently lists hundreds of report files with:
- Lazy loading (future enhancement)
- Pagination (future enhancement)
- Search/filter (future enhancement)

## Security Considerations

### Production Deployment

When deploying dashboard to production:

1. **Authentication**: Add login system
2. **Authorization**: Restrict access to reports
3. **Rate Limiting**: Prevent abuse
4. **Input Validation**: Sanitize all inputs
5. **HTTPS**: Use SSL/TLS
6. **File Size Limits**: Configure upload limits

Example nginx configuration:
```nginx
server {
    listen 443 ssl;
    server_name dashboard.yourdomain.com;
    
    location / {
        proxy_pass http://localhost:5001;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### Data Privacy

- Reports may contain sensitive subdomain information
- Store JSON files securely
- Implement access controls
- Consider encryption at rest

## Best Practices

1. **Naming Convention**: Use timestamps in JSON filenames
   ```bash
   scan_example_com_20260213_153000.json
   ```

2. **Automated Reports**: Generate HTML immediately after scans
   ```bash
   python cli.py example.com -o results/scan.json && \
   python reporter.py results/scan.json results/scan.html
   ```

3. **Archival**: Compress old reports
   ```bash
   tar -czf archive_2026_02.tar.gz results/*.json
   ```

4. **Monitoring**: Set up alerts for high-priority findings
   ```python
   if results['summary']['high_priority_count'] > 10:
       send_alert("High priority subdomains detected")
   ```

## Future Enhancements

Potential features for future versions:
- [ ] Real-time report updates via WebSocket
- [ ] Comparison between multiple scans
- [ ] Trend analysis over time
- [ ] Export to additional formats (PDF, Excel)
- [ ] Advanced filtering and search
- [ ] Custom report templates
- [ ] Email report delivery
- [ ] Integration with SIEM systems
- [ ] Annotations and notes on findings
- [ ] Collaborative review features

## Examples

### Complete Workflow Example

```bash
# 1. Run scan with multiple tools
python cli.py example.com --tools subfinder,amass -o results/scan.json

# 2. Generate HTML report
python reporter.py results/scan.json results/scan.html

# 3. View in browser
start results/scan.html

# 4. Or start dashboard for web viewing
python dashboard.py --port 5001
# Visit http://localhost:5001
```

### Batch Processing Example

```bash
# Process multiple domains
for domain in $(cat domains.txt); do
    echo "Scanning $domain..."
    python cli.py $domain -o "results/${domain}_scan.json"
    python reporter.py "results/${domain}_scan.json" "results/${domain}_report.html"
done
```

### API Integration Example

```python
import requests
import time

# Start scan via API
response = requests.post('http://localhost:5000/api/scan', json={
    'domain': 'example.com'
})
job_id = response.json()['job_id']

# Wait for completion
while True:
    status = requests.get(f'http://localhost:5000/api/scan/{job_id}').json()
    if status['job']['status'] == 'completed':
        break
    time.sleep(5)

# Get results
results = requests.get(f'http://localhost:5000/api/scan/{job_id}/results').json()

# Generate report
from reporter import SubdomainReporter
reporter = SubdomainReporter()
html = reporter.generate_report(results['results'], 'report.html')
```

## Support

For issues or questions about the reporting system:
1. Check this documentation
2. Review example code in `examples.py`
3. Examine generated HTML source
4. Verify JSON structure matches expected format

---

**Remember**: The reporting system strictly displays validated data. It does not modify results or infer new information.
