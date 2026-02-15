#!/usr/bin/env python3
"""
Integrated Web Server for Subdomain Enumeration
Serves the web interface and provides API endpoints for the orchestrator.
"""

from flask import Flask, send_file, jsonify, request
from flask_cors import CORS
import json
import threading
import asyncio
import uuid
from datetime import datetime, UTC
from pathlib import Path
import sys

# Import orchestrator components
from orchestrator import SubdomainOrchestrator
from path_discovery import PathDiscoveryOrchestrator
from xss_scanner import XSSDetectionOrchestrator
from sqli_scanner import SQLiDetectionOrchestrator
from lfi_scanner import LFIOrchestrator
from config import Config
from reporter import SubdomainReporter

app = Flask(__name__)
CORS(app)

# Job tracking
active_jobs = {}
completed_jobs = {}

# Path Discovery job tracking
path_active_jobs = {}
path_completed_jobs = {}

# XSS Detection job tracking
xss_active_jobs = {}
xss_completed_jobs = {}

# SQL Injection Detection job tracking
sqli_active_jobs = {}
sqli_completed_jobs = {}

# LFI Detection job tracking
lfi_active_jobs = {}
lfi_completed_jobs = {}

# Results directory
RESULTS_DIR = Path("results")
RESULTS_DIR.mkdir(exist_ok=True)
(RESULTS_DIR / "paths").mkdir(exist_ok=True)
(RESULTS_DIR / "xss").mkdir(exist_ok=True)
(RESULTS_DIR / "sqli").mkdir(exist_ok=True)
(RESULTS_DIR / "lfi").mkdir(exist_ok=True)


@app.route("/")
def index():
    """Serve the main web interface"""
    web_interface_path = Path(__file__).parent.parent / "web" / "web_interface.html"
    return send_file(web_interface_path)


@app.route("/main.css")
def serve_css():
    """Serve the CSS file"""
    css_path = Path(__file__).parent.parent / "web" / "main.css"
    return send_file(css_path, mimetype="text/css")


@app.route("/main.js")
def serve_js():
    """Serve the JavaScript file"""
    js_path = Path(__file__).parent.parent / "web" / "main.js"
    return send_file(js_path, mimetype="application/javascript")


@app.route("/logo.svg")
def serve_logo():
    """Serve the logo SVG file"""
    logo_path = Path(__file__).parent.parent / "web" / "logo.svg"
    if logo_path.exists():
        return send_file(logo_path, mimetype="image/svg+xml")
    return "", 404


@app.route("/api/health", methods=["GET"])
def health_check():
    """Health check endpoint"""
    return jsonify(
        {
            "status": "healthy",
            "version": "3.0.0",
            "timestamp": datetime.now(UTC).isoformat(),
            "modules": {
                "subdomain_scanner": True,
                "path_discovery": True,
                "xss_detection": True,
            },
        }
    )


@app.route("/api/tools", methods=["GET"])
def list_tools():
    """List available tools and their status"""
    try:
        config = Config.load("config.json")
        tools_list = []

        for tool_name, tool_config in config.tools.items():
            tools_list.append(
                {
                    "name": tool_name,
                    "enabled": tool_config.get("enabled", False),
                    "description": tool_config.get("description", ""),
                    "status": "available",
                }
            )

        return jsonify({"success": True, "tools": tools_list})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/scan", methods=["POST"])
def start_scan():
    """
    Start a new subdomain enumeration scan.

    Request Body:
    {
        "domain": "example.com",
        "tools": ["subfinder", "amass"],  // optional
        "parallel": true,  // optional
        "validate_dns": true  // optional
    }
    """
    try:
        data = request.get_json()

        if not data or "domain" not in data:
            return (
                jsonify({"success": False, "error": "Missing required field: domain"}),
                400,
            )

        domain = data["domain"]
        job_id = str(uuid.uuid4())

        # Load config
        config = Config.load("config.json")

        # Apply request overrides
        if "tools" in data:
            # Disable all tools first
            for tool in config.tools:
                config.tools[tool]["enabled"] = False
            # Enable requested tools
            for tool in data["tools"]:
                if tool in config.tools:
                    config.tools[tool]["enabled"] = True

        if "parallel" in data:
            config.parallel_execution = data["parallel"]

        if "validate_dns" in data:
            config.perform_dns_validation = data["validate_dns"]

        # Always save results
        config.save_results = True

        # Create job entry
        active_jobs[job_id] = {
            "job_id": job_id,
            "domain": domain,
            "status": "running",
            "started_at": datetime.now(UTC).isoformat(),
            "progress": 0,
        }

        # Start scan in background thread
        def run_scan():
            try:
                print(f"[{job_id}] Starting scan for {domain}")
                orchestrator = SubdomainOrchestrator(config)
                results = orchestrator.orchestrate(domain)

                print(f"[{job_id}] Scan completed successfully")

                # Save results to file
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"{domain.replace('.', '_')}_{timestamp}.json"
                filepath = RESULTS_DIR / filename

                with open(filepath, "w") as f:
                    json.dump(results, f, indent=2)

                print(f"[{job_id}] Results saved to {filepath}")

                # Move to completed
                completed_jobs[job_id] = {
                    "job_id": job_id,
                    "domain": domain,
                    "status": "completed",
                    "started_at": active_jobs[job_id]["started_at"],
                    "completed_at": datetime.now(UTC).isoformat(),
                    "results": results,
                    "results_file": str(filepath),
                }

                if job_id in active_jobs:
                    del active_jobs[job_id]

            except Exception as e:
                print(f"[{job_id}] Scan failed: {str(e)}")
                completed_jobs[job_id] = {
                    "job_id": job_id,
                    "domain": domain,
                    "status": "failed",
                    "started_at": active_jobs[job_id]["started_at"],
                    "completed_at": datetime.now(UTC).isoformat(),
                    "error": str(e),
                }
                if job_id in active_jobs:
                    del active_jobs[job_id]

        thread = threading.Thread(target=run_scan)
        thread.daemon = True
        thread.start()

        return (
            jsonify(
                {
                    "success": True,
                    "job_id": job_id,
                    "message": "Scan started",
                    "status_url": f"/api/scan/{job_id}",
                }
            ),
            202,
        )

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/scan/<job_id>", methods=["GET"])
def get_scan_status(job_id):
    """Get status of a scan job"""

    # Check active jobs
    if job_id in active_jobs:
        return jsonify({"success": True, "job": active_jobs[job_id]})

    # Check completed jobs
    if job_id in completed_jobs:
        job = completed_jobs[job_id].copy()
        # Don't include full results in status
        if "results" in job:
            job.pop("results")
        return jsonify({"success": True, "job": job})

    # Job not found
    return jsonify({"success": False, "error": "Job not found"}), 404


@app.route("/api/scan/<job_id>/results", methods=["GET"])
def get_scan_results(job_id):
    """Get detailed results of a completed scan"""

    if job_id not in completed_jobs:
        return (
            jsonify({"success": False, "error": "Job not found or not completed"}),
            404,
        )

    job = completed_jobs[job_id]

    if job["status"] == "failed":
        return (
            jsonify({"success": False, "error": job.get("error", "Scan failed")}),
            500,
        )

    return jsonify({"success": True, "results": job["results"]})


@app.route("/api/scan/<job_id>/report", methods=["GET"])
def generate_report(job_id):
    """Generate HTML report for a completed scan"""

    if job_id not in completed_jobs:
        return (
            jsonify({"success": False, "error": "Job not found or not completed"}),
            404,
        )

    job = completed_jobs[job_id]

    if job["status"] == "failed":
        return (
            jsonify(
                {"success": False, "error": "Cannot generate report for failed scan"}
            ),
            500,
        )

    try:
        reporter = SubdomainReporter()

        # Generate HTML report
        domain = job["domain"]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        html_filename = f"{domain.replace('.', '_')}_{timestamp}_report.html"
        html_filepath = RESULTS_DIR / html_filename

        reporter.generate_report(job["results"], str(html_filepath))

        return jsonify(
            {
                "success": True,
                "report_file": str(html_filepath),
                "download_url": f"/api/download/{html_filename}",
            }
        )

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/download/<filename>")
def download_file(filename):
    """Download a results or report file"""
    filepath = RESULTS_DIR / filename

    if not filepath.exists():
        return "File not found", 404

    return send_file(filepath, as_attachment=True)


@app.route("/api/jobs", methods=["GET"])
def list_jobs():
    """List all jobs (active and completed)"""

    all_jobs = []

    # Add active jobs
    for job_id, job in active_jobs.items():
        all_jobs.append(
            {
                "job_id": job_id,
                "domain": job["domain"],
                "status": job["status"],
                "started_at": job["started_at"],
            }
        )

    # Add completed jobs (latest 50)
    for job_id, job in list(completed_jobs.items())[-50:]:
        all_jobs.append(
            {
                "job_id": job_id,
                "domain": job["domain"],
                "status": job["status"],
                "started_at": job["started_at"],
                "completed_at": job.get("completed_at"),
            }
        )

    # Sort by start time (newest first)
    all_jobs.sort(key=lambda x: x["started_at"], reverse=True)

    return jsonify(
        {
            "success": True,
            "jobs": all_jobs,
            "active_count": len(active_jobs),
            "completed_count": len(completed_jobs),
        }
    )


@app.route("/api/stats", methods=["GET"])
def get_stats():
    """Get system statistics"""

    total_scans = len(active_jobs) + len(completed_jobs)
    successful_scans = sum(
        1 for job in completed_jobs.values() if job["status"] == "completed"
    )

    return jsonify(
        {
            "success": True,
            "statistics": {
                "total_scans": total_scans,
                "active_scans": len(active_jobs),
                "completed_scans": len(completed_jobs),
                "successful_scans": successful_scans,
                "failed_scans": len(completed_jobs) - successful_scans,
            },
        }
    )


@app.route("/api/results", methods=["GET"])
def list_results():
    """List all saved result files"""
    try:
        results_files = []
        for file in RESULTS_DIR.glob("*.json"):
            stat = file.stat()
            results_files.append(
                {
                    "filename": file.name,
                    "path": str(file),
                    "size": stat.st_size,
                    "created_at": datetime.fromtimestamp(stat.st_ctime).isoformat()
                    + "Z",
                }
            )

        # Sort by creation time (newest first)
        results_files.sort(key=lambda x: x["created_at"], reverse=True)

        return jsonify(
            {"success": True, "results": results_files, "count": len(results_files)}
        )
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# =============================================
# Path Discovery API Endpoints
# =============================================


@app.route("/api/path/tools", methods=["GET"])
def list_path_tools():
    """List available path discovery tools and their status"""
    try:
        config = Config.load("config.json")
        tools_list = []

        for tool_name, tool_config in config.path_discovery_tools.items():
            tools_list.append(
                {
                    "name": tool_name,
                    "enabled": tool_config.get("enabled", False),
                    "description": tool_config.get("description", ""),
                    "status": "available",
                }
            )

        return jsonify({"success": True, "tools": tools_list})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/path/scan", methods=["POST"])
def start_path_scan():
    """
    Start a new path discovery scan.

    Request Body:
    {
        "url": "https://example.com",
        "tools": ["ffuf", "dirsearch"],  // optional
    }
    """
    try:
        data = request.get_json()

        if not data or "url" not in data:
            return (
                jsonify({"success": False, "error": "Missing required field: url"}),
                400,
            )

        target_url = data["url"]
        job_id = str(uuid.uuid4())

        # Load config
        config = Config.load("config.json")

        # Apply request overrides for tools
        selected_tools = data.get("tools", None)

        # Create job entry
        path_active_jobs[job_id] = {
            "job_id": job_id,
            "target": target_url,
            "status": "running",
            "started_at": datetime.now(UTC).isoformat(),
            "progress": 0,
        }

        # Start scan in background thread
        def run_path_scan():
            try:
                print(f"[PATH-{job_id}] Starting path discovery for {target_url}")
                orchestrator = PathDiscoveryOrchestrator(config)

                # Run async discover in a new event loop
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    results = loop.run_until_complete(
                        orchestrator.discover(target_url, selected_tools)
                    )
                finally:
                    loop.close()

                print(f"[PATH-{job_id}] Path discovery completed successfully")

                # Move to completed
                path_completed_jobs[job_id] = {
                    "job_id": job_id,
                    "target": target_url,
                    "status": "completed",
                    "started_at": path_active_jobs[job_id]["started_at"],
                    "completed_at": datetime.now(UTC).isoformat(),
                    "results": results,
                }

                if job_id in path_active_jobs:
                    del path_active_jobs[job_id]

            except Exception as e:
                print(f"[PATH-{job_id}] Path discovery failed: {str(e)}")
                path_completed_jobs[job_id] = {
                    "job_id": job_id,
                    "target": target_url,
                    "status": "failed",
                    "started_at": path_active_jobs[job_id]["started_at"],
                    "completed_at": datetime.now(UTC).isoformat(),
                    "error": str(e),
                }
                if job_id in path_active_jobs:
                    del path_active_jobs[job_id]

        thread = threading.Thread(target=run_path_scan)
        thread.daemon = True
        thread.start()

        return (
            jsonify(
                {
                    "success": True,
                    "job_id": job_id,
                    "message": "Path discovery started",
                    "status_url": f"/api/path/scan/{job_id}",
                }
            ),
            202,
        )

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/path/scan/<job_id>", methods=["GET"])
def get_path_scan_status(job_id):
    """Get status of a path discovery job"""

    # Check active jobs
    if job_id in path_active_jobs:
        return jsonify({"success": True, "job": path_active_jobs[job_id]})

    # Check completed jobs
    if job_id in path_completed_jobs:
        job = path_completed_jobs[job_id].copy()
        # Don't include full results in status
        if "results" in job:
            job.pop("results")
        return jsonify({"success": True, "job": job})

    # Job not found
    return jsonify({"success": False, "error": "Job not found"}), 404


@app.route("/api/path/scan/<job_id>/results", methods=["GET"])
def get_path_scan_results(job_id):
    """Get detailed results of a completed path discovery scan"""

    if job_id not in path_completed_jobs:
        return (
            jsonify({"success": False, "error": "Job not found or not completed"}),
            404,
        )

    job = path_completed_jobs[job_id]

    if job["status"] == "failed":
        return (
            jsonify({"success": False, "error": job.get("error", "Scan failed")}),
            500,
        )

    return jsonify({"success": True, "results": job["results"]})


@app.route("/api/path/jobs", methods=["GET"])
def list_path_jobs():
    """List all path discovery jobs (active and completed)"""

    all_jobs = []

    # Add active jobs
    for job_id, job in path_active_jobs.items():
        all_jobs.append(
            {
                "job_id": job_id,
                "target": job["target"],
                "status": job["status"],
                "started_at": job["started_at"],
            }
        )

    # Add completed jobs (latest 50)
    for job_id, job in list(path_completed_jobs.items())[-50:]:
        all_jobs.append(
            {
                "job_id": job_id,
                "target": job["target"],
                "status": job["status"],
                "started_at": job["started_at"],
                "completed_at": job.get("completed_at"),
            }
        )

    # Sort by start time (newest first)
    all_jobs.sort(key=lambda x: x["started_at"], reverse=True)

    return jsonify(
        {
            "success": True,
            "jobs": all_jobs,
            "active_count": len(path_active_jobs),
            "completed_count": len(path_completed_jobs),
        }
    )


@app.route("/api/path/stats", methods=["GET"])
def get_path_stats():
    """Get path discovery statistics"""

    total_scans = len(path_active_jobs) + len(path_completed_jobs)
    successful_scans = sum(
        1 for job in path_completed_jobs.values() if job["status"] == "completed"
    )

    # Calculate total paths and params found
    total_paths = 0
    total_params = 0
    critical_findings = 0

    for job in path_completed_jobs.values():
        if job["status"] == "completed" and "results" in job:
            results = job["results"]
            if "summary" in results:
                total_paths += results["summary"].get("paths", {}).get("total", 0)
                total_params += results["summary"].get("parameters", {}).get("total", 0)
            if "interesting_findings" in results:
                critical_findings += len(
                    results["interesting_findings"].get("critical_paths", [])
                )

    return jsonify(
        {
            "success": True,
            "statistics": {
                "total_scans": total_scans,
                "active_scans": len(path_active_jobs),
                "completed_scans": len(path_completed_jobs),
                "successful_scans": successful_scans,
                "failed_scans": len(path_completed_jobs) - successful_scans,
                "total_paths_found": total_paths,
                "total_params_found": total_params,
                "critical_findings": critical_findings,
            },
        }
    )


# =============================================
# XSS Detection API Endpoints
# =============================================


@app.route("/api/xss/tools", methods=["GET"])
def list_xss_tools():
    """List available XSS detection tools and their real installation status"""
    try:
        import shutil

        config = Config.load("config.json")
        tools_list = []

        xss_tools = getattr(config, "xss_tools", {})
        for tool_name, tool_config in xss_tools.items():
            # Dynamically check if the tool is actually installed
            from xss_scanner import get_tool_path

            tool_path = get_tool_path(tool_name)
            is_installed = False
            if tool_path:
                tool_p = Path(tool_path)
                if tool_p.is_absolute() and tool_p.exists():
                    is_installed = True
                elif shutil.which(tool_path):
                    is_installed = True

            tools_list.append(
                {
                    "name": tool_name,
                    "enabled": tool_config.get("enabled", False),
                    "description": tool_config.get("description", ""),
                    "installed": is_installed,
                    "status": "ready" if is_installed else "not_installed",
                    "path": tool_path if is_installed else None,
                }
            )

        return jsonify({"success": True, "tools": tools_list})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/xss/scan", methods=["POST"])
def start_xss_scan():
    """
    Start a new XSS detection scan.

    Request Body:
    {
        "url": "https://example.com?param=value",
        "tools": ["dalfox", "nuclei"],  // optional
    }
    """
    try:
        data = request.get_json()

        if not data or "url" not in data:
            return (
                jsonify({"success": False, "error": "Missing required field: url"}),
                400,
            )

        target_url = data["url"]
        job_id = str(uuid.uuid4())

        # Load config
        config = Config.load("config.json")

        # Apply request overrides for tools
        selected_tools = data.get("tools", None)

        # Create job entry
        xss_active_jobs[job_id] = {
            "job_id": job_id,
            "target": target_url,
            "status": "running",
            "started_at": datetime.now(UTC).isoformat(),
            "progress": 0,
        }

        # Start scan in background thread
        def run_xss_scan():
            try:
                print(f"[XSS-{job_id}] Starting XSS detection for {target_url}")

                def update_progress(progress):
                    """Update job progress"""
                    if job_id in xss_active_jobs:
                        xss_active_jobs[job_id]["progress"] = progress

                orchestrator = XSSDetectionOrchestrator(config)
                results = orchestrator.scan(
                    target_url, selected_tools, progress_callback=update_progress
                )

                print(f"[XSS-{job_id}] XSS detection completed successfully")

                # Move to completed
                xss_completed_jobs[job_id] = {
                    "job_id": job_id,
                    "target": target_url,
                    "status": "completed",
                    "started_at": xss_active_jobs[job_id]["started_at"],
                    "completed_at": datetime.now(UTC).isoformat(),
                    "progress": 100,
                    "results": results,
                }

                if job_id in xss_active_jobs:
                    del xss_active_jobs[job_id]

            except Exception as e:
                print(f"[XSS-{job_id}] XSS detection failed: {str(e)}")
                xss_completed_jobs[job_id] = {
                    "job_id": job_id,
                    "target": target_url,
                    "status": "failed",
                    "started_at": xss_active_jobs[job_id]["started_at"],
                    "completed_at": datetime.now(UTC).isoformat(),
                    "error": str(e),
                }
                if job_id in xss_active_jobs:
                    del xss_active_jobs[job_id]

        thread = threading.Thread(target=run_xss_scan)
        thread.daemon = True
        thread.start()

        return (
            jsonify(
                {
                    "success": True,
                    "job_id": job_id,
                    "message": "XSS detection started",
                    "status_url": f"/api/xss/scan/{job_id}",
                }
            ),
            202,
        )

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/xss/scan/<job_id>", methods=["GET"])
def get_xss_scan_status(job_id):
    """Get status of an XSS detection job"""

    # Check active jobs
    if job_id in xss_active_jobs:
        return jsonify({"success": True, "job": xss_active_jobs[job_id]})

    # Check completed jobs
    if job_id in xss_completed_jobs:
        job = xss_completed_jobs[job_id].copy()
        # Don't include full results in status
        if "results" in job:
            job.pop("results")
        return jsonify({"success": True, "job": job})

    # Job not found
    return jsonify({"success": False, "error": "Job not found"}), 404


@app.route("/api/xss/scan/<job_id>/results", methods=["GET"])
def get_xss_scan_results(job_id):
    """Get detailed results of a completed XSS detection scan"""

    if job_id not in xss_completed_jobs:
        return (
            jsonify({"success": False, "error": "Job not found or not completed"}),
            404,
        )

    job = xss_completed_jobs[job_id]

    if job["status"] == "failed":
        return (
            jsonify({"success": False, "error": job.get("error", "Scan failed")}),
            500,
        )

    return jsonify({"success": True, "results": job["results"]})


@app.route("/api/xss/jobs", methods=["GET"])
def list_xss_jobs():
    """List all XSS detection jobs (active and completed)"""

    all_jobs = []

    # Add active jobs
    for job_id, job in xss_active_jobs.items():
        all_jobs.append(
            {
                "job_id": job_id,
                "target": job["target"],
                "status": job["status"],
                "started_at": job["started_at"],
            }
        )

    # Add completed jobs (latest 50)
    for job_id, job in list(xss_completed_jobs.items())[-50:]:
        all_jobs.append(
            {
                "job_id": job_id,
                "target": job["target"],
                "status": job["status"],
                "started_at": job["started_at"],
                "completed_at": job.get("completed_at"),
            }
        )

    # Sort by start time (newest first)
    all_jobs.sort(key=lambda x: x["started_at"], reverse=True)

    return jsonify(
        {
            "success": True,
            "jobs": all_jobs,
            "active_count": len(xss_active_jobs),
            "completed_count": len(xss_completed_jobs),
        }
    )


@app.route("/api/xss/stats", methods=["GET"])
def get_xss_stats():
    """Get XSS detection statistics"""

    total_scans = len(xss_active_jobs) + len(xss_completed_jobs)
    successful_scans = sum(
        1 for job in xss_completed_jobs.values() if job["status"] == "completed"
    )

    # Calculate total findings by severity
    total_findings = 0
    critical_findings = 0
    high_findings = 0
    medium_findings = 0

    for job in xss_completed_jobs.values():
        if job["status"] == "completed" and "results" in job:
            results = job["results"]
            if "summary" in results:
                total_findings += results["summary"].get("total_findings", 0)
                critical_findings += results["summary"].get("critical", 0)
                high_findings += results["summary"].get("high", 0)
                medium_findings += results["summary"].get("medium", 0)

    return jsonify(
        {
            "success": True,
            "statistics": {
                "total_scans": total_scans,
                "active_scans": len(xss_active_jobs),
                "completed_scans": len(xss_completed_jobs),
                "successful_scans": successful_scans,
                "failed_scans": len(xss_completed_jobs) - successful_scans,
                "total_findings": total_findings,
                "critical_findings": critical_findings,
                "high_findings": high_findings,
                "medium_findings": medium_findings,
            },
        }
    )


# ==================== SQL INJECTION DETECTION API ====================


@app.route("/api/sqli/tools", methods=["GET"])
def get_sqli_tools():
    """Get available SQL injection detection tools with installation status"""
    import shutil
    from sqli_scanner import get_tool_path

    tools_info = [
        {
            "name": "sqlmap",
            "description": "Automatic SQL injection detection tool",
            "enabled": True,
        },
        {
            "name": "nuclei",
            "description": "Fast template-based SQLi scanning",
            "enabled": True,
        },
        {
            "name": "ghauri",
            "description": "Advanced cross-platform SQLi detection",
            "enabled": True,
        },
    ]

    result = []
    for tool in tools_info:
        tool_name = tool["name"]
        tool_path = get_tool_path(tool_name)
        path_obj = Path(tool_path)

        # Check if installed
        installed = False
        actual_path = None

        if path_obj.is_absolute() and path_obj.exists():
            installed = True
            actual_path = str(path_obj)
        elif shutil.which(tool_name):
            installed = True
            actual_path = shutil.which(tool_name)
        elif tool_name == "sqlmap" and shutil.which("sqlmap.py"):
            installed = True
            actual_path = shutil.which("sqlmap.py")

        result.append(
            {
                "name": tool_name,
                "description": tool["description"],
                "enabled": tool["enabled"],
                "installed": installed,
                "status": "ready" if installed else "not_installed",
                "path": actual_path,
            }
        )

    return jsonify({"success": True, "tools": result})


@app.route("/api/sqli/scan", methods=["POST"])
def start_sqli_scan():
    """Start a new SQL injection detection scan"""
    data = request.get_json()

    if not data:
        return jsonify({"success": False, "error": "No data provided"}), 400

    target_url = data.get("url")
    if not target_url:
        return jsonify({"success": False, "error": "No URL provided"}), 400

    # Get selected tools
    tools = data.get("tools", ["sqlmap", "nuclei", "ghauri"])
    intensity = data.get("intensity", "basic")
    options = data.get("options", {})

    # Create job
    job_id = str(uuid.uuid4())
    job = {
        "job_id": job_id,
        "target": target_url,
        "tools": tools,
        "intensity": intensity,
        "status": "running",
        "progress": 0,
        "started_at": datetime.now(UTC).isoformat(),
    }

    sqli_active_jobs[job_id] = job

    # Progress update function
    def update_progress(progress: int):
        if job_id in sqli_active_jobs:
            sqli_active_jobs[job_id]["progress"] = progress

    # Run scan in background thread
    def run_scan():
        try:
            orchestrator = SQLiDetectionOrchestrator()
            results = orchestrator.scan(
                target_url=target_url,
                tools=tools,
                intensity=intensity,
                options=options,
                progress_callback=update_progress,
            )

            # Move to completed
            job["status"] = "completed"
            job["completed_at"] = datetime.now(UTC).isoformat()
            job["results"] = results
            job["progress"] = 100

            sqli_completed_jobs[job_id] = job
            if job_id in sqli_active_jobs:
                del sqli_active_jobs[job_id]

        except Exception as e:
            job["status"] = "failed"
            job["error"] = str(e)
            job["completed_at"] = datetime.now(UTC).isoformat()

            sqli_completed_jobs[job_id] = job
            if job_id in sqli_active_jobs:
                del sqli_active_jobs[job_id]

    thread = threading.Thread(target=run_scan)
    thread.daemon = True
    thread.start()

    return jsonify(
        {
            "success": True,
            "job_id": job_id,
            "message": f"SQL injection scan started for {target_url}",
            "status_url": f"/api/sqli/scan/{job_id}",
        }
    )


@app.route("/api/sqli/scan/<job_id>", methods=["GET"])
def get_sqli_scan_status(job_id):
    """Get status of a SQL injection detection job"""

    # Check active jobs
    if job_id in sqli_active_jobs:
        return jsonify({"success": True, "job": sqli_active_jobs[job_id]})

    # Check completed jobs
    if job_id in sqli_completed_jobs:
        job = sqli_completed_jobs[job_id].copy()
        # Don't include full results in status
        if "results" in job:
            job.pop("results")
        return jsonify({"success": True, "job": job})

    # Job not found
    return jsonify({"success": False, "error": "Job not found"}), 404


@app.route("/api/sqli/scan/<job_id>/results", methods=["GET"])
def get_sqli_scan_results(job_id):
    """Get detailed results of a completed SQL injection detection scan"""

    if job_id not in sqli_completed_jobs:
        return (
            jsonify({"success": False, "error": "Job not found or not completed"}),
            404,
        )

    job = sqli_completed_jobs[job_id]

    if job["status"] == "failed":
        return (
            jsonify({"success": False, "error": job.get("error", "Scan failed")}),
            500,
        )

    return jsonify({"success": True, "results": job["results"]})


@app.route("/api/sqli/jobs", methods=["GET"])
def list_sqli_jobs():
    """List all SQL injection detection jobs (active and completed)"""

    all_jobs = []

    for job_id, job in sqli_active_jobs.items():
        all_jobs.append(
            {
                "job_id": job_id,
                "target": job["target"],
                "status": job["status"],
                "progress": job.get("progress", 0),
                "started_at": job["started_at"],
            }
        )

    for job_id, job in sqli_completed_jobs.items():
        job_summary = {
            "job_id": job_id,
            "target": job["target"],
            "status": job["status"],
            "started_at": job["started_at"],
            "completed_at": job.get("completed_at"),
        }
        if "results" in job:
            job_summary["findings_count"] = job["results"]["summary"]["total_findings"]
        all_jobs.append(job_summary)

    return jsonify({"success": True, "jobs": all_jobs})


@app.route("/api/sqli/stats", methods=["GET"])
def get_sqli_stats():
    """Get SQL injection detection statistics"""

    total_scans = len(sqli_active_jobs) + len(sqli_completed_jobs)
    successful_scans = sum(
        1 for job in sqli_completed_jobs.values() if job["status"] == "completed"
    )

    # Calculate total findings by severity
    total_findings = 0
    critical_findings = 0
    high_findings = 0
    medium_findings = 0

    for job in sqli_completed_jobs.values():
        if job["status"] == "completed" and "results" in job:
            results = job["results"]
            if "summary" in results:
                total_findings += results["summary"].get("total_findings", 0)
                critical_findings += results["summary"].get("critical", 0)
                high_findings += results["summary"].get("high", 0)
                medium_findings += results["summary"].get("medium", 0)

    return jsonify(
        {
            "success": True,
            "statistics": {
                "total_scans": total_scans,
                "active_scans": len(sqli_active_jobs),
                "completed_scans": len(sqli_completed_jobs),
                "successful_scans": successful_scans,
                "failed_scans": len(sqli_completed_jobs) - successful_scans,
                "total_findings": total_findings,
                "critical_findings": critical_findings,
                "high_findings": high_findings,
                "medium_findings": medium_findings,
            },
        }
    )


# ==================== LFI DETECTION API ====================


@app.route("/api/lfi/tools", methods=["GET"])
def get_lfi_tools():
    """Get available LFI detection tools with installation status"""
    import shutil

    tools_info = [
        {
            "name": "ffuf",
            "description": "Fast LFI fuzzing with custom payloads",
            "enabled": True,
        },
        {
            "name": "custom_lfi",
            "description": "Custom LFI payload testing with signature detection",
            "enabled": True,
        },
        {
            "name": "dotdotpwn",
            "description": "Automated directory traversal detection",
            "enabled": True,
        },
    ]

    result = []
    for tool in tools_info:
        tool_name = tool["name"]

        # Check if installed
        installed = False
        actual_path = None

        if tool_name == "custom_lfi":
            # Custom tool is always available
            installed = True
            actual_path = "built-in"
        elif shutil.which(tool_name):
            installed = True
            actual_path = shutil.which(tool_name)

        result.append(
            {
                "name": tool_name,
                "description": tool["description"],
                "enabled": tool["enabled"],
                "installed": installed,
                "status": "ready" if installed else "not_installed",
                "path": actual_path,
            }
        )

    return jsonify({"success": True, "tools": result})


@app.route("/api/lfi/scan", methods=["POST"])
def start_lfi_scan():
    """Start a new LFI detection scan"""
    data = request.get_json()

    if not data:
        return jsonify({"success": False, "error": "No data provided"}), 400

    target_url = data.get("url")
    if not target_url:
        return jsonify({"success": False, "error": "No URL provided"}), 400

    # Get optional parameters
    parameters = data.get("parameters", None)
    tools = data.get("tools", ["ffuf", "custom_lfi"])

    # Create job
    job_id = str(uuid.uuid4())
    job = {
        "job_id": job_id,
        "target": target_url,
        "parameters": parameters,
        "tools": tools,
        "status": "running",
        "progress": 0,
        "started_at": datetime.now(UTC).isoformat(),
    }

    lfi_active_jobs[job_id] = job

    # Run scan in background thread
    def run_scan():
        try:
            print(f"[LFI-{job_id}] Starting LFI detection for {target_url}")

            config = Config.load("config.json")
            orchestrator = LFIOrchestrator(config)
            results = orchestrator.orchestrate(target_url, parameters)

            print(f"[LFI-{job_id}] LFI detection completed successfully")

            # Move to completed
            job["status"] = "completed"
            job["completed_at"] = datetime.now(UTC).isoformat()
            job["results"] = results
            job["progress"] = 100

            lfi_completed_jobs[job_id] = job
            if job_id in lfi_active_jobs:
                del lfi_active_jobs[job_id]

        except Exception as e:
            print(f"[LFI-{job_id}] LFI detection failed: {str(e)}")
            job["status"] = "failed"
            job["error"] = str(e)
            job["completed_at"] = datetime.now(UTC).isoformat()

            lfi_completed_jobs[job_id] = job
            if job_id in lfi_active_jobs:
                del lfi_active_jobs[job_id]

    thread = threading.Thread(target=run_scan)
    thread.daemon = True
    thread.start()

    return (
        jsonify(
            {
                "success": True,
                "job_id": job_id,
                "message": f"LFI detection scan started for {target_url}",
                "status_url": f"/api/lfi/scan/{job_id}",
            }
        ),
        202,
    )


@app.route("/api/lfi/scan/<job_id>", methods=["GET"])
def get_lfi_scan_status(job_id):
    """Get status of an LFI detection job"""

    # Check active jobs
    if job_id in lfi_active_jobs:
        return jsonify({"success": True, "job": lfi_active_jobs[job_id]})

    # Check completed jobs
    if job_id in lfi_completed_jobs:
        job = lfi_completed_jobs[job_id].copy()
        # Don't include full results in status
        if "results" in job:
            job.pop("results")
        return jsonify({"success": True, "job": job})

    # Job not found
    return jsonify({"success": False, "error": "Job not found"}), 404


@app.route("/api/lfi/scan/<job_id>/results", methods=["GET"])
def get_lfi_scan_results(job_id):
    """Get detailed results of a completed LFI detection scan"""

    if job_id not in lfi_completed_jobs:
        return (
            jsonify({"success": False, "error": "Job not found or not completed"}),
            404,
        )

    job = lfi_completed_jobs[job_id]

    if job["status"] == "failed":
        return (
            jsonify({"success": False, "error": job.get("error", "Scan failed")}),
            500,
        )

    return jsonify({"success": True, "results": job["results"]})


@app.route("/api/lfi/jobs", methods=["GET"])
def list_lfi_jobs():
    """List all LFI detection jobs (active and completed)"""

    all_jobs = []

    # Add active jobs
    for job_id, job in lfi_active_jobs.items():
        all_jobs.append(
            {
                "job_id": job_id,
                "target": job["target"],
                "status": job["status"],
                "started_at": job["started_at"],
            }
        )

    # Add completed jobs (latest 50)
    for job_id, job in list(lfi_completed_jobs.items())[-50:]:
        all_jobs.append(
            {
                "job_id": job_id,
                "target": job["target"],
                "status": job["status"],
                "started_at": job["started_at"],
                "completed_at": job.get("completed_at"),
            }
        )

    # Sort by start time (newest first)
    all_jobs.sort(key=lambda x: x["started_at"], reverse=True)

    return jsonify(
        {
            "success": True,
            "jobs": all_jobs,
            "active_count": len(lfi_active_jobs),
            "completed_count": len(lfi_completed_jobs),
        }
    )


@app.route("/api/lfi/stats", methods=["GET"])
def get_lfi_stats():
    """Get LFI detection statistics"""

    total_scans = len(lfi_active_jobs) + len(lfi_completed_jobs)
    successful_scans = sum(
        1 for job in lfi_completed_jobs.values() if job["status"] == "completed"
    )

    # Calculate total findings by severity
    total_findings = 0
    high_findings = 0
    medium_findings = 0
    low_findings = 0

    for job in lfi_completed_jobs.values():
        if job["status"] == "completed" and "results" in job:
            results = job["results"]
            if "summary" in results:
                total_findings += results["summary"].get("total_findings", 0)
                high_findings += results["summary"].get("high_severity", 0)
                medium_findings += results["summary"].get("medium_severity", 0)
                low_findings += results["summary"].get("low_severity", 0)

    return jsonify(
        {
            "success": True,
            "statistics": {
                "total_scans": total_scans,
                "active_scans": len(lfi_active_jobs),
                "completed_scans": len(lfi_completed_jobs),
                "successful_scans": successful_scans,
                "failed_scans": len(lfi_completed_jobs) - successful_scans,
                "total_findings": total_findings,
                "high_findings": high_findings,
                "medium_findings": medium_findings,
                "low_findings": low_findings,
            },
        }
    )


def run_web_server(host="0.0.0.0", port=5000, debug=False):
    """Run the integrated web server"""
    print("=" * 60)
    print("Subdomain Enumeration - Integrated Web Server")
    print("=" * 60)
    print(f"\n🌐 Web Interface: http://localhost:{port}")
    print(f"📊 API Endpoint: http://localhost:{port}/api")
    print(f"📁 Results Directory: {RESULTS_DIR.absolute()}")
    print("\n⚠️  Important: Only scan domains you own or have permission to test")
    print("\nPress Ctrl+C to stop the server")
    print("=" * 60 + "\n")

    app.run(host=host, port=port, debug=debug, threaded=True)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Subdomain Enumeration - Integrated Web Server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Start on default port 5000
  %(prog)s --port 8080              # Start on custom port
  %(prog)s --host 127.0.0.1         # Bind to localhost only
  
Then open http://localhost:5000 in your browser.
        """,
    )

    parser.add_argument(
        "--host", default="0.0.0.0", help="Host address (default: 0.0.0.0)"
    )

    parser.add_argument(
        "--port", type=int, default=5000, help="Port number (default: 5000)"
    )

    parser.add_argument("--debug", action="store_true", help="Enable debug mode")

    args = parser.parse_args()

    # Check if config exists
    if not Path("config.json").exists():
        print("⚠️  Warning: config.json not found!")
        print("Run 'python setup.py' first to create configuration.\n")
        sys.exit(1)

    try:
        run_web_server(host=args.host, port=args.port, debug=args.debug)
    except KeyboardInterrupt:
        print("\n\nShutting down server...")
        print("Goodbye! 👋")
