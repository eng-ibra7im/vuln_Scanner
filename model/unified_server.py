#!/usr/bin/env python3
"""
Deprecated unified server entrypoint.
Use web_server.py as the single supported server entrypoint.
"""

from flask import Flask, send_file, jsonify, request
from flask_cors import CORS
import json
import threading
import uuid
from datetime import datetime
from pathlib import Path
import sys
import os

app = Flask(__name__)
CORS(app)

# Job tracking for subdomain enumeration
subdomain_active_jobs = {}
subdomain_completed_jobs = {}

# Job tracking for path discovery
path_active_jobs = {}
path_completed_jobs = {}

# Results directory
RESULTS_DIR = Path("results")
RESULTS_DIR.mkdir(exist_ok=True)


# Try to import subdomain modules
SUBDOMAIN_AVAILABLE = False
try:
    from orchestrator import SubdomainOrchestrator
    from config import Config as SubdomainConfig

    SUBDOMAIN_AVAILABLE = True
    print("✅ Subdomain Enumeration module loaded")
except ImportError as e:
    print(f"⚠️  Subdomain Enumeration not available: {e}")

# Try to import path discovery modules
PATH_AVAILABLE = False
try:
    path_discovery_dir = os.path.join(
        os.path.dirname(__file__), "..", "path_discovery", "model"
    )
    if os.path.exists(path_discovery_dir):
        sys.path.insert(0, path_discovery_dir)

        # Import from path_discovery
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "path_orchestrator", os.path.join(path_discovery_dir, "orchestrator.py")
        )
        path_orch_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(path_orch_module)

        spec = importlib.util.spec_from_file_location(
            "path_config", os.path.join(path_discovery_dir, "config.py")
        )
        path_config_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(path_config_module)

        PathDiscoveryOrchestrator = path_orch_module.PathDiscoveryOrchestrator
        PathConfig = path_config_module.Config

        sys.path.remove(path_discovery_dir)
        PATH_AVAILABLE = True
        print("✅ Path Discovery module loaded")
except Exception as e:
    print(f"⚠️  Path Discovery not available: {e}")


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


@app.route("/styles.min.css")
def serve_minified_css():
    """Serve the bundled minified CSS file."""
    css_path = Path(__file__).parent.parent / "web" / "styles.min.css"
    return send_file(css_path, mimetype="text/css")


@app.route("/main.js")
def serve_js():
    """Serve the JavaScript file"""
    js_path = Path(__file__).parent.parent / "web" / "main.js"
    return send_file(js_path, mimetype="application/javascript")


@app.route("/logo.svg")
def serve_logo():
    """Serve the logo file"""
    logo_path = Path(__file__).parent.parent / "web" / "logo.svg"
    return send_file(logo_path, mimetype="image/svg+xml")


# Health check
@app.route("/api/health", methods=["GET"])
def health_check():
    """Health check endpoint"""
    return jsonify(
        {
            "status": "healthy",
            "version": "1.0.0",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "modules": {
                "subdomain_enumeration": SUBDOMAIN_AVAILABLE,
                "path_discovery": PATH_AVAILABLE,
            },
        }
    )


# ========================================
# SUBDOMAIN ENUMERATION ENDPOINTS
# ========================================


@app.route("/api/scan", methods=["POST"])
def start_subdomain_scan():
    """Start a new subdomain enumeration scan"""
    if not SUBDOMAIN_AVAILABLE:
        return (
            jsonify(
                {
                    "success": False,
                    "error": "Subdomain enumeration module not available",
                }
            ),
            500,
        )

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
        config = SubdomainConfig.load("config.json")

        # Apply request overrides
        if "tools" in data:
            for tool in config.tools:
                config.tools[tool]["enabled"] = False
            for tool in data["tools"]:
                if tool in config.tools:
                    config.tools[tool]["enabled"] = True

        if "parallel" in data:
            config.parallel_execution = data["parallel"]

        if "validate_dns" in data:
            config.perform_dns_validation = data["validate_dns"]

        config.save_results = True

        # Create job entry
        subdomain_active_jobs[job_id] = {
            "job_id": job_id,
            "domain": domain,
            "status": "running",
            "started_at": datetime.utcnow().isoformat() + "Z",
        }

        # Start scan in background thread
        def run_scan():
            try:
                print(f"[{job_id}] Starting subdomain scan for {domain}")
                orchestrator = SubdomainOrchestrator(config)
                results = orchestrator.orchestrate(domain)

                # Save results
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"{domain.replace('.', '_')}_{timestamp}.json"
                filepath = RESULTS_DIR / filename

                with open(filepath, "w") as f:
                    json.dump(results, f, indent=2)

                print(f"[{job_id}] Subdomain scan completed successfully")

                # Move to completed
                subdomain_completed_jobs[job_id] = {
                    "job_id": job_id,
                    "domain": domain,
                    "status": "completed",
                    "started_at": subdomain_active_jobs[job_id]["started_at"],
                    "completed_at": datetime.utcnow().isoformat() + "Z",
                    "results": results,
                    "results_file": str(filepath),
                }

                if job_id in subdomain_active_jobs:
                    del subdomain_active_jobs[job_id]

            except Exception as e:
                print(f"[{job_id}] Subdomain scan failed: {str(e)}")
                subdomain_completed_jobs[job_id] = {
                    "job_id": job_id,
                    "domain": domain,
                    "status": "failed",
                    "started_at": subdomain_active_jobs[job_id]["started_at"],
                    "completed_at": datetime.utcnow().isoformat() + "Z",
                    "error": str(e),
                }
                if job_id in subdomain_active_jobs:
                    del subdomain_active_jobs[job_id]

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
def get_subdomain_scan_status(job_id):
    """Get status of a subdomain scan job"""
    if job_id in subdomain_active_jobs:
        return jsonify({"success": True, "job": subdomain_active_jobs[job_id]})

    if job_id in subdomain_completed_jobs:
        job = subdomain_completed_jobs[job_id].copy()
        if "results" in job:
            job.pop("results")
        return jsonify({"success": True, "job": job})

    return jsonify({"success": False, "error": "Job not found"}), 404


@app.route("/api/scan/<job_id>/results", methods=["GET"])
def get_subdomain_scan_results(job_id):
    """Get detailed results of a completed subdomain scan"""
    if job_id not in subdomain_completed_jobs:
        return (
            jsonify({"success": False, "error": "Job not found or not completed"}),
            404,
        )

    job = subdomain_completed_jobs[job_id]
    if job["status"] == "failed":
        return (
            jsonify({"success": False, "error": job.get("error", "Scan failed")}),
            500,
        )

    return jsonify({"success": True, "results": job["results"]})


@app.route("/api/stats", methods=["GET"])
def get_subdomain_stats():
    """Get subdomain enumeration statistics"""
    total_scans = len(subdomain_active_jobs) + len(subdomain_completed_jobs)
    successful_scans = sum(
        1 for job in subdomain_completed_jobs.values() if job["status"] == "completed"
    )

    return jsonify(
        {
            "success": True,
            "statistics": {
                "total_scans": total_scans,
                "active_scans": len(subdomain_active_jobs),
                "completed_scans": len(subdomain_completed_jobs),
                "successful_scans": successful_scans,
                "failed_scans": len(subdomain_completed_jobs) - successful_scans,
            },
        }
    )


@app.route("/api/jobs", methods=["GET"])
def list_subdomain_jobs():
    """List all subdomain jobs"""
    all_jobs = []

    for job_id, job in subdomain_active_jobs.items():
        all_jobs.append(
            {
                "job_id": job_id,
                "domain": job["domain"],
                "status": job["status"],
                "started_at": job["started_at"],
            }
        )

    for job_id, job in list(subdomain_completed_jobs.items())[-50:]:
        all_jobs.append(
            {
                "job_id": job_id,
                "domain": job["domain"],
                "status": job["status"],
                "started_at": job["started_at"],
                "completed_at": job.get("completed_at"),
            }
        )

    all_jobs.sort(key=lambda x: x["started_at"], reverse=True)

    return jsonify(
        {
            "success": True,
            "jobs": all_jobs,
            "active_count": len(subdomain_active_jobs),
            "completed_count": len(subdomain_completed_jobs),
        }
    )


# ========================================
# PATH DISCOVERY ENDPOINTS
# ========================================


@app.route("/api/path/scan", methods=["POST"])
def start_path_scan():
    """Start a new path discovery scan"""
    if not PATH_AVAILABLE:
        return (
            jsonify({"success": False, "error": "Path discovery module not available"}),
            500,
        )

    try:
        data = request.get_json()
        if not data or "url" not in data:
            return (
                jsonify({"success": False, "error": "Missing required field: url"}),
                400,
            )

        url = data["url"]
        job_id = str(uuid.uuid4())

        # Load path discovery config
        path_config_path = os.path.join(
            os.path.dirname(__file__), "..", "path_discovery", "model", "config.json"
        )
        config = PathConfig.load(path_config_path)

        # Apply request overrides
        if "tools" in data:
            for tool in config.tools:
                config.tools[tool]["enabled"] = False
            for tool in data["tools"]:
                if tool in config.tools:
                    config.tools[tool]["enabled"] = True

        if "parallel" in data:
            config.parallel_execution = data["parallel"]

        config.save_results = True

        # Create job entry
        path_active_jobs[job_id] = {
            "job_id": job_id,
            "url": url,
            "status": "running",
            "started_at": datetime.utcnow().isoformat() + "Z",
        }

        # Start scan in background thread
        def run_scan():
            try:
                print(f"[{job_id}] Starting path discovery for {url}")
                orchestrator = PathDiscoveryOrchestrator(config)
                results = orchestrator.orchestrate(url)

                # Save results
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                domain = (
                    url.replace("https://", "").replace("http://", "").replace("/", "_")
                )
                filename = f"path_{domain}_{timestamp}.json"
                filepath = RESULTS_DIR / filename

                with open(filepath, "w") as f:
                    json.dump(results, f, indent=2)

                print(f"[{job_id}] Path discovery completed successfully")

                # Move to completed
                path_completed_jobs[job_id] = {
                    "job_id": job_id,
                    "url": url,
                    "status": "completed",
                    "started_at": path_active_jobs[job_id]["started_at"],
                    "completed_at": datetime.utcnow().isoformat() + "Z",
                    "results": results,
                    "results_file": str(filepath),
                }

                if job_id in path_active_jobs:
                    del path_active_jobs[job_id]

            except Exception as e:
                print(f"[{job_id}] Path discovery failed: {str(e)}")
                path_completed_jobs[job_id] = {
                    "job_id": job_id,
                    "url": url,
                    "status": "failed",
                    "started_at": path_active_jobs[job_id]["started_at"],
                    "completed_at": datetime.utcnow().isoformat() + "Z",
                    "error": str(e),
                }
                if job_id in path_active_jobs:
                    del path_active_jobs[job_id]

        thread = threading.Thread(target=run_scan)
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
    """Get status of a path discovery scan job"""
    if job_id in path_active_jobs:
        return jsonify({"success": True, "job": path_active_jobs[job_id]})

    if job_id in path_completed_jobs:
        job = path_completed_jobs[job_id].copy()
        if "results" in job:
            job.pop("results")
        return jsonify({"success": True, "job": job})

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


@app.route("/api/path/stats", methods=["GET"])
def get_path_stats():
    """Get path discovery statistics"""
    total_scans = len(path_active_jobs) + len(path_completed_jobs)
    successful_scans = sum(
        1 for job in path_completed_jobs.values() if job["status"] == "completed"
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
            },
        }
    )


@app.route("/api/path/jobs", methods=["GET"])
def list_path_jobs():
    """List all path discovery jobs"""
    all_jobs = []

    for job_id, job in path_active_jobs.items():
        all_jobs.append(
            {
                "job_id": job_id,
                "url": job["url"],
                "status": job["status"],
                "started_at": job["started_at"],
            }
        )

    for job_id, job in list(path_completed_jobs.items())[-50:]:
        all_jobs.append(
            {
                "job_id": job_id,
                "url": job["url"],
                "status": job["status"],
                "started_at": job["started_at"],
                "completed_at": job.get("completed_at"),
            }
        )

    all_jobs.sort(key=lambda x: x["started_at"], reverse=True)

    return jsonify(
        {
            "success": True,
            "jobs": all_jobs,
            "active_count": len(path_active_jobs),
            "completed_count": len(path_completed_jobs),
        }
    )


def run_unified_server(host="0.0.0.0", port=5000, debug=False):
    """Run the unified web server"""
    print("Deprecated entrypoint: model/unified_server.py")
    print("Redirecting to model/web_server.py")
    from web_server import run_web_server

    return run_web_server(host=host, port=port, debug=debug)

    print("=" * 60)
    print("Vulnerability Scanner - Unified Web Server")
    print("=" * 60)
    print(f"\n🌐 Web Interface: http://localhost:{port}")
    print(f"📊 API Endpoint: http://localhost:{port}/api")
    print(f"📁 Results Directory: {RESULTS_DIR.absolute()}")
    print(f"\n✅ Available Modules:")
    print(
        f"   • Subdomain Enumeration: {'✅ Active' if SUBDOMAIN_AVAILABLE else '❌ Unavailable'}"
    )
    print(f"   • Path Discovery: {'✅ Active' if PATH_AVAILABLE else '❌ Unavailable'}")
    print("\n⚠️  Important: Only scan domains you own or have permission to test")
    print("\nPress Ctrl+C to stop the server")
    print("=" * 60 + "\n")

    app.run(host=host, port=port, debug=debug, threaded=True)


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

    try:
        run_unified_server(host=args.host, port=args.port, debug=args.debug)
    except KeyboardInterrupt:
        print("\n\nShutting down server...")
        print("Goodbye! 👋")
