# API Usage Examples

## Starting the API Server

```bash
python api.py --host 0.0.0.0 --port 5000
```

## API Endpoints

### 1. Health Check

```bash
curl http://localhost:5000/api/health
```

Response:
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "timestamp": "2026-02-13T10:30:00Z"
}
```

### 2. List Available Tools

```bash
curl http://localhost:5000/api/tools
```

Response:
```json
{
  "success": true,
  "tools": [
    {
      "name": "subfinder",
      "enabled": true,
      "description": "Fast passive subdomain enumeration",
      "status": "available"
    }
  ]
}
```

### 3. Start a Scan

```bash
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com"
  }'
```

With specific tools:
```bash
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "tools": ["subfinder", "amass"],
    "parallel": true,
    "validate_dns": true
  }'
```

Response:
```json
{
  "success": true,
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "message": "Scan started",
  "status_url": "/api/scan/550e8400-e29b-41d4-a716-446655440000"
}
```

### 4. Check Scan Status

```bash
curl http://localhost:5000/api/scan/550e8400-e29b-41d4-a716-446655440000
```

Response (Running):
```json
{
  "success": true,
  "job": {
    "job_id": "550e8400-e29b-41d4-a716-446655440000",
    "domain": "example.com",
    "status": "running",
    "started_at": "2026-02-13T10:30:00Z",
    "progress": 0
  }
}
```

Response (Completed):
```json
{
  "success": true,
  "job": {
    "job_id": "550e8400-e29b-41d4-a716-446655440000",
    "domain": "example.com",
    "status": "completed",
    "started_at": "2026-02-13T10:30:00Z",
    "completed_at": "2026-02-13T10:31:30Z"
  }
}
```

### 5. Get Scan Results

```bash
curl http://localhost:5000/api/scan/550e8400-e29b-41d4-a716-446655440000/results
```

Response:
```json
{
  "success": true,
  "results": {
    "metadata": {
      "target_domain": "example.com",
      "scan_timestamp": "2026-02-13T10:30:00Z",
      "execution_time_seconds": 45.32
    },
    "summary": {
      "total_subdomains": 127,
      "validated_subdomains": 89,
      "high_priority_count": 12
    },
    "subdomains": [...]
  }
}
```

### 6. List All Jobs

```bash
curl http://localhost:5000/api/jobs
```

Response:
```json
{
  "success": true,
  "jobs": [
    {
      "job_id": "...",
      "domain": "example.com",
      "status": "completed",
      "started_at": "2026-02-13T10:30:00Z",
      "completed_at": "2026-02-13T10:31:30Z"
    }
  ],
  "active_count": 0,
  "completed_count": 5
}
```

### 7. Get System Statistics

```bash
curl http://localhost:5000/api/stats
```

Response:
```json
{
  "success": true,
  "statistics": {
    "total_scans": 10,
    "active_scans": 1,
    "completed_scans": 9,
    "successful_scans": 8,
    "failed_scans": 1
  }
}
```

## Python Client Example

```python
import requests
import time

BASE_URL = "http://localhost:5000/api"

# Start a scan
response = requests.post(f"{BASE_URL}/scan", json={
    "domain": "example.com",
    "tools": ["subfinder", "amass"]
})

job_id = response.json()['job_id']
print(f"Scan started: {job_id}")

# Poll for completion
while True:
    status = requests.get(f"{BASE_URL}/scan/{job_id}").json()
    
    if status['job']['status'] == 'completed':
        print("Scan completed!")
        break
    elif status['job']['status'] == 'failed':
        print("Scan failed!")
        break
    
    print("Scan in progress...")
    time.sleep(5)

# Get results
results = requests.get(f"{BASE_URL}/scan/{job_id}/results").json()
print(f"Found {results['results']['summary']['total_subdomains']} subdomains")
```

## JavaScript/Node.js Client Example

```javascript
const axios = require('axios');

const BASE_URL = 'http://localhost:5000/api';

async function scanDomain(domain) {
  // Start scan
  const startResponse = await axios.post(`${BASE_URL}/scan`, {
    domain: domain,
    tools: ['subfinder', 'amass']
  });
  
  const jobId = startResponse.data.job_id;
  console.log(`Scan started: ${jobId}`);
  
  // Poll for completion
  while (true) {
    const statusResponse = await axios.get(`${BASE_URL}/scan/${jobId}`);
    const status = statusResponse.data.job.status;
    
    if (status === 'completed') {
      console.log('Scan completed!');
      break;
    } else if (status === 'failed') {
      console.log('Scan failed!');
      return null;
    }
    
    console.log('Scan in progress...');
    await new Promise(resolve => setTimeout(resolve, 5000));
  }
  
  // Get results
  const resultsResponse = await axios.get(`${BASE_URL}/scan/${jobId}/results`);
  return resultsResponse.data.results;
}

// Usage
scanDomain('example.com').then(results => {
  if (results) {
    console.log(`Found ${results.summary.total_subdomains} subdomains`);
    console.log(`High priority: ${results.summary.high_priority_count}`);
  }
});
```

## Dashboard Integration

For web dashboard integration, the API provides:

1. **Real-time status updates** - Poll `/api/scan/{job_id}` endpoint
2. **Structured JSON output** - Ready for visualization
3. **Priority-based classification** - Easy filtering for dashboards
4. **Statistics and patterns** - For analytics displays
5. **Recommendations** - Actionable insights

## Error Handling

All endpoints return consistent error responses:

```json
{
  "success": false,
  "error": "Error description here"
}
```

HTTP Status Codes:
- `200` - Success
- `202` - Accepted (async operation started)
- `400` - Bad Request
- `404` - Not Found
- `500` - Internal Server Error

## Rate Limiting Considerations

When integrating with production systems, consider:
- Implementing rate limiting per client
- Queueing scan requests
- Setting maximum concurrent scans
- Adding authentication/authorization
- Monitoring resource usage
