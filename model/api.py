"""
Deprecated API wrapper.
Use web_server.py as the single supported server entrypoint.
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import threading
import shutil
import uuid
from datetime import datetime, UTC
from typing import Dict
from pathlib import Path
from orchestrator import SubdomainOrchestrator
from config import Config

app = Flask(__name__)
CORS(app)  # Enable CORS for dashboard integration

BASE_DIR = Path(__file__).parent
CONFIG_PATH = BASE_DIR / "config.json"

# Job tracking
active_jobs: Dict[str, dict] = {}
completed_jobs: Dict[str, dict] = {}


def get_runtime_config() -> Config:
    """Load configuration from the model directory."""
    return Config.load(str(CONFIG_PATH))


@app.route("/api/health", methods=["GET"])
def health_check():
    """Health check endpoint"""
    return jsonify(
        {
            "status": "healthy",
            "version": "1.0.0",
            "timestamp": datetime.now(UTC).isoformat(),
        }
    )


@app.route("/api/config", methods=["GET"])
def get_config():
    """Get current configuration"""
    try:
        config = get_runtime_config()
        return jsonify(
            {
                "success": True,
                "tools": config.get_subdomain_tools(),
                "settings": {
                    "parallel_execution": config.parallel_execution,
                    "perform_dns_validation": config.perform_dns_validation,
                    "save_results": config.save_results,
                },
            }
        )
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/tools", methods=["GET"])
def list_tools():
    """List available tools and their status"""
    try:
        config = get_runtime_config()
        tools_list = []
        tool_aliases = {
            "sublist3r": ["sublist3r.py"],
        }

        for tool_name, tool_config in config.get_subdomain_tools().items():
            installed = False
            actual_path = None

            for candidate in [tool_name, *tool_aliases.get(tool_name, [])]:
                if not candidate:
                    continue

                resolved = shutil.which(candidate)
                if resolved:
                    installed = True
                    actual_path = resolved
                    break

            tools_list.append(
                {
                    "name": tool_name,
                    "enabled": tool_config.get("enabled", False),
                    "description": tool_config.get("description", ""),
                    "installed": installed,
                    "status": "ready" if installed else "not_installed",
                    "path": actual_path,
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
        config = get_runtime_config()

        # Apply request overrides
        if "tools" in data:
            for tool in config.get_subdomain_tools():
                config.get_subdomain_tools()[tool]["enabled"] = tool in data["tools"]

        if "parallel" in data:
            config.parallel_execution = data["parallel"]

        if "validate_dns" in data:
            config.perform_dns_validation = data["validate_dns"]

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
                orchestrator = SubdomainOrchestrator(config)
                results = orchestrator.orchestrate(domain)

                # Move to completed
                completed_jobs[job_id] = {
                    "job_id": job_id,
                    "domain": domain,
                    "status": "completed",
                    "started_at": active_jobs[job_id]["started_at"],
                    "completed_at": datetime.now(UTC).isoformat(),
                    "results": results,
                    "results_file": results.get("output_file"),
                }
                del active_jobs[job_id]

            except Exception as e:
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
        return jsonify({"success": True, "job": completed_jobs[job_id]})

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


def run_api_server(host="0.0.0.0", port=5000, debug=False):
    """Run the official integrated web server via a deprecated wrapper."""
    print("Deprecated entrypoint: model/api.py")
    print("Redirecting to model/web_server.py")
    from web_server import run_web_server

    run_web_server(host=host, port=port, debug=debug)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Deprecated wrapper for the integrated web server"
    )
    parser.add_argument(
        "--host", default="0.0.0.0", help="Host address (default: 0.0.0.0)"
    )
    parser.add_argument(
        "--port", type=int, default=5000, help="Port number (default: 5000)"
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")

    args = parser.parse_args()

    run_api_server(host=args.host, port=args.port, debug=args.debug)
