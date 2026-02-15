#!/usr/bin/env python3
"""Test XSS API"""
import requests
import time
import json

BASE_URL = "http://localhost:5000/api"

# Start XSS scan
print("Starting XSS scan...")
response = requests.post(
    f"{BASE_URL}/xss/scan",
    json={
        "url": "http://testphp.vulnweb.com/search.php?test=query",
        "tools": ["dalfox"],
    },
)
data = response.json()
print(f"Response: {json.dumps(data, indent=2)}")

if data.get("success"):
    job_id = data["job_id"]
    print(f"\nJob ID: {job_id}")

    # Poll for results
    print("\nWaiting for results...")
    for i in range(60):
        time.sleep(2)
        status_resp = requests.get(f"{BASE_URL}/xss/scan/{job_id}")
        status_data = status_resp.json()
        job_info = status_data.get("job", {})
        current_status = job_info.get("status", "unknown")
        print(f"  Status: {current_status}")

        if current_status == "completed":
            print("\nScan completed! Getting results...")
            results_resp = requests.get(f"{BASE_URL}/xss/scan/{job_id}/results")
            results_data = results_resp.json()
            print(json.dumps(results_data, indent=2))
            break
        elif current_status == "failed":
            print(f"Scan failed: {job_info.get('error')}")
