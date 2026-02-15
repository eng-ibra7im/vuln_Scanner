#!/usr/bin/env python3
"""
Web Dashboard for Subdomain Enumeration Reports
Serves HTML reports through a web interface.
"""

from flask import Flask, render_template_string, request, jsonify, send_file
from flask_cors import CORS
import json
from pathlib import Path
from datetime import datetime
from reporter import SubdomainReporter
import os
import sys

# Import subdomain orchestrator
try:
    from orchestrator import SubdomainOrchestrator
    from config import Config
    import threading
    import uuid

    SUBDOMAIN_AVAILABLE = True
except ImportError:
    SUBDOMAIN_AVAILABLE = False
    print("⚠️  Subdomain Orchestrator not available")

# Import path discovery orchestrator
PATH_AVAILABLE = False
PathDiscoveryOrchestrator = None
PathConfig = None

try:
    # Save current subdomain imports
    import orchestrator as subdomain_orch
    import config as subdomain_config

    path_discovery_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "path_discovery",
        "model",
    )

    # Check if path_discovery exists
    if os.path.exists(path_discovery_path):
        # Temporarily add path_discovery to sys.path at the beginning
        sys.path.insert(0, path_discovery_path)

        # Import with different names to avoid conflict
        import importlib
        import orchestrator as temp_orch
        import config as temp_config

        # Force reload to get path_discovery version
        importlib.reload(temp_orch)
        importlib.reload(temp_config)

        # Get the classes
        PathDiscoveryOrchestrator = temp_orch.PathDiscoveryOrchestrator
        PathConfig = temp_config.Config

        # Restore subdomain modules
        sys.modules["orchestrator"] = subdomain_orch
        sys.modules["config"] = subdomain_config

        # Clean up sys.path
        sys.path.remove(path_discovery_path)

        PATH_AVAILABLE = True
        print("✅ Path Discovery Orchestrator loaded")
    else:
        print("⚠️  Path Discovery module not found")
except Exception as e:
    try:
        if "path_discovery_path" in locals() and path_discovery_path in sys.path:
            sys.path.remove(path_discovery_path)
    except:
        pass
    print(f"⚠️  Path Discovery not available: {str(e)[:50]}")

app = Flask(__name__, static_folder="../web", static_url_path="/static")
CORS(app)

# Results directory
RESULTS_DIR = Path("results")
RESULTS_DIR.mkdir(exist_ok=True)

# Subdomain job tracking
subdomain_active_jobs = {}
subdomain_completed_jobs = {}

# Path discovery job tracking
path_active_jobs = {}
path_completed_jobs = {}


def get_available_reports():
    """Get list of available JSON result files"""
    reports = []

    if RESULTS_DIR.exists():
        for json_file in RESULTS_DIR.glob("*.json"):
            try:
                stat = json_file.stat()
                reports.append(
                    {
                        "filename": json_file.name,
                        "path": str(json_file),
                        "size": stat.st_size,
                        "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                        "modified_display": datetime.fromtimestamp(
                            stat.st_mtime
                        ).strftime("%Y-%m-%d %H:%M:%S"),
                    }
                )
            except:
                pass

    # Sort by modified time (newest first)
    reports.sort(key=lambda x: x["modified"], reverse=True)
    return reports


@app.route("/")
def index():
    """Main dashboard page - redirect to web interface"""
    return """
<!DOCTYPE html>
<html>
<head>
    <title>SecOps Dashboard</title>
    <meta http-equiv="refresh" content="0; url=/static/web_interface.html">
</head>
<body>
    <p>Redirecting to dashboard... <a href="/static/web_interface.html">Click here if not redirected</a></p>
</body>
</html>
"""


@app.route("/legacy")
def legacy_index():
    """Legacy subdomain report viewer"""
    reports = get_available_reports()

    html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Subdomain Enumeration Dashboard</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: #f5f7fa;
            color: #2c3e50;
        }
        
        header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        
        h1 {
            font-size: 2em;
            margin-bottom: 5px;
        }
        
        .subtitle {
            opacity: 0.9;
        }
        
        .content {
            padding: 30px 20px;
            max-width: 1200px;
            margin: 0 auto;
        }
        
        .section {
            background: white;
            padding: 25px;
            margin-bottom: 25px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .section h2 {
            color: #667eea;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #667eea;
        }
        
        .upload-area {
            border: 2px dashed #667eea;
            border-radius: 8px;
            padding: 40px;
            text-align: center;
            background: #f8f9fa;
            cursor: pointer;
            transition: all 0.3s;
        }
        
        .upload-area:hover {
            background: #e9ecef;
            border-color: #764ba2;
        }
        
        .upload-area.dragover {
            background: #e9ecef;
            border-color: #764ba2;
        }
        
        .reports-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        
        .reports-table th {
            background: #667eea;
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: 600;
        }
        
        .reports-table td {
            padding: 12px;
            border-bottom: 1px solid #e0e0e0;
        }
        
        .reports-table tr:hover {
            background: #f8f9fa;
        }
        
        .btn {
            display: inline-block;
            padding: 8px 16px;
            background: #667eea;
            color: white;
            text-decoration: none;
            border-radius: 4px;
            border: none;
            cursor: pointer;
            transition: background 0.3s;
        }
        
        .btn:hover {
            background: #764ba2;
        }
        
        .btn-sm {
            padding: 6px 12px;
            font-size: 0.85em;
        }
        
        .no-reports {
            text-align: center;
            padding: 40px;
            color: #7f8c8d;
            font-style: italic;
        }
        
        .alert {
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 4px;
        }
        
        .alert-info {
            background: #d1ecf1;
            color: #0c5460;
            border: 1px solid #bee5eb;
        }
        
        .alert-success {
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        
        .file-size {
            color: #7f8c8d;
            font-size: 0.9em;
        }
        
        input[type="file"] {
            display: none;
        }
        
        .action-buttons {
            display: flex;
            gap: 8px;
        }
    </style>
</head>
<body>
    <header>
        <div class="container">
            <h1>Subdomain Enumeration Dashboard</h1>
            <p class="subtitle">View and analyze subdomain scan reports</p>
        </div>
    </header>
    
    <div class="content">
        <div class="section">
            <h2>Upload Scan Results</h2>
            <div class="upload-area" id="uploadArea" onclick="document.getElementById('fileInput').click()">
                <p style="font-size: 1.2em; margin-bottom: 10px;">📁 Drop JSON file here or click to upload</p>
                <p style="color: #7f8c8d;">Upload subdomain scan results (JSON format)</p>
            </div>
            <input type="file" id="fileInput" accept=".json" onchange="handleFileUpload(event)">
            <div id="uploadStatus"></div>
        </div>
        
        <div class="section">
            <h2>Available Reports</h2>
"""

    if reports:
        html += """
            <table class="reports-table">
                <thead>
                    <tr>
                        <th>Filename</th>
                        <th>Last Modified</th>
                        <th>Size</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
"""
        for report in reports:
            size_kb = report["size"] / 1024
            html += f"""
                    <tr>
                        <td><strong>{report['filename']}</strong></td>
                        <td>{report['modified_display']}</td>
                        <td class="file-size">{size_kb:.1f} KB</td>
                        <td class="action-buttons">
                            <a href="/view/{report['filename']}" class="btn btn-sm" target="_blank">View Report</a>
                            <a href="/download/{report['filename']}" class="btn btn-sm">Download</a>
                        </td>
                    </tr>
"""
        html += """
                </tbody>
            </table>
"""
    else:
        html += '<div class="no-reports">No reports available. Upload a JSON file or run a scan to get started.</div>'

    html += """
        </div>
    </div>
    
    <script>
        // File upload handling
        function handleFileUpload(event) {
            const file = event.target.files[0];
            if (!file) return;
            
            const formData = new FormData();
            formData.append('file', file);
            
            document.getElementById('uploadStatus').innerHTML = '<div class="alert alert-info">Uploading...</div>';
            
            fetch('/upload', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    document.getElementById('uploadStatus').innerHTML = 
                        '<div class="alert alert-success">File uploaded successfully! <a href="/view/' + 
                        data.filename + '" target="_blank">View Report</a></div>';
                    setTimeout(() => location.reload(), 2000);
                } else {
                    document.getElementById('uploadStatus').innerHTML = 
                        '<div class="alert" style="background: #f8d7da; color: #721c24;">Error: ' + 
                        data.error + '</div>';
                }
            })
            .catch(error => {
                document.getElementById('uploadStatus').innerHTML = 
                    '<div class="alert" style="background: #f8d7da; color: #721c24;">Upload failed: ' + 
                    error + '</div>';
            });
        }
        
        // Drag and drop
        const uploadArea = document.getElementById('uploadArea');
        
        uploadArea.addEventListener('dragover', (e) => {
            e.preventDefault();
            uploadArea.classList.add('dragover');
        });
        
        uploadArea.addEventListener('dragleave', () => {
            uploadArea.classList.remove('dragover');
        });
        
        uploadArea.addEventListener('drop', (e) => {
            e.preventDefault();
            uploadArea.classList.remove('dragover');
            
            const file = e.dataTransfer.files[0];
            if (file && file.name.endsWith('.json')) {
                const fileInput = document.getElementById('fileInput');
                const dataTransfer = new DataTransfer();
                dataTransfer.items.add(file);
                fileInput.files = dataTransfer.files;
                handleFileUpload({ target: fileInput });
            } else {
                alert('Please drop a JSON file');
            }
        });
    </script>
</body>
</html>
"""

    return html


@app.route("/upload", methods=["POST"])
def upload_file():
    """Handle file upload"""
    if "file" not in request.files:
        return jsonify({"success": False, "error": "No file provided"}), 400

    file = request.files["file"]

    if file.filename == "":
        return jsonify({"success": False, "error": "No file selected"}), 400

    if not file.filename.endswith(".json"):
        return jsonify({"success": False, "error": "Only JSON files are allowed"}), 400

    try:
        # Validate JSON
        content = file.read()
        json_data = json.loads(content)

        # Save file
        filename = file.filename
        filepath = RESULTS_DIR / filename

        with open(filepath, "wb") as f:
            f.write(content)

        return jsonify({"success": True, "filename": filename})

    except json.JSONDecodeError:
        return jsonify({"success": False, "error": "Invalid JSON file"}), 400
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/view/<filename>")
def view_report(filename):
    """Generate and display HTML report"""
    filepath = RESULTS_DIR / filename

    if not filepath.exists():
        return "<h1>Report not found</h1>", 404

    try:
        with open(filepath, "r") as f:
            results = json.load(f)

        reporter = SubdomainReporter()
        html_report = reporter.generate_report(results)

        return html_report

    except Exception as e:
        return f"<h1>Error generating report</h1><p>{str(e)}</p>", 500


@app.route("/download/<filename>")
def download_report(filename):
    """Download JSON file"""
    filepath = RESULTS_DIR / filename

    if not filepath.exists():
        return "File not found", 404

    return send_file(filepath, as_attachment=True)


@app.route("/api/reports")
def api_list_reports():
    """API endpoint to list reports"""
    reports = get_available_reports()
    return jsonify({"success": True, "reports": reports})


@app.route("/api/report/<filename>")
def api_get_report(filename):
    """API endpoint to get report data"""
    filepath = RESULTS_DIR / filename

    if not filepath.exists():
        return jsonify({"success": False, "error": "Report not found"}), 404

    try:
        with open(filepath, "r") as f:
            results = json.load(f)

        return jsonify({"success": True, "data": results})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ========================================
# Subdomain Enumeration API Endpoints
# ========================================


@app.route("/api/scan", methods=["POST"])
def start_subdomain_scan():
    """Start a new subdomain enumeration scan"""
    if not SUBDOMAIN_AVAILABLE:
        return (
            jsonify(
                {"success": False, "error": "Subdomain orchestrator not available"}
            ),
            503,
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
        config = Config.load("config.json")

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
            "progress": 0,
        }

        # Start scan in background thread
        def run_scan():
            try:
                print(f"[{job_id}] Starting subdomain scan for {domain}")
                orchestrator = SubdomainOrchestrator(config)
                results = orchestrator.orchestrate(domain)

                print(f"[{job_id}] Subdomain scan completed")

                # Save results
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"{domain.replace('.', '_')}_{timestamp}.json"
                filepath = RESULTS_DIR / filename

                with open(filepath, "w") as f:
                    json.dump(results, f, indent=2)

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

        return jsonify(
            {
                "success": True,
                "job_id": job_id,
                "message": "Subdomain scan started",
                "status_url": f"/api/scan/{job_id}",
            }
        )

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/scan/<job_id>", methods=["GET"])
def get_subdomain_scan_status(job_id):
    """Get the status of a subdomain scan job"""
    if job_id in subdomain_active_jobs:
        return jsonify({"success": True, "job": subdomain_active_jobs[job_id]})
    elif job_id in subdomain_completed_jobs:
        return jsonify({"success": True, "job": subdomain_completed_jobs[job_id]})
    else:
        return jsonify({"success": False, "error": "Job not found"}), 404


@app.route("/api/tools", methods=["GET"])
def list_tools():
    """List available subdomain enumeration tools"""
    if not SUBDOMAIN_AVAILABLE:
        return (
            jsonify(
                {"success": False, "error": "Subdomain orchestrator not available"}
            ),
            503,
        )

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


@app.route("/api/stats", methods=["GET"])
def subdomain_stats():
    """Get subdomain enumeration statistics"""
    try:
        total_jobs = len(subdomain_active_jobs) + len(subdomain_completed_jobs)
        completed = len(subdomain_completed_jobs)
        running = len(subdomain_active_jobs)

        return jsonify(
            {
                "success": True,
                "statistics": {
                    "total_scans": total_jobs,
                    "completed_scans": completed,
                    "active_scans": running,
                },
            }
        )
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/jobs", methods=["GET"])
def list_subdomain_jobs():
    """List all subdomain enumeration jobs"""
    try:
        jobs = []

        for job_id, job in subdomain_active_jobs.items():
            jobs.append(job)

        for job_id, job in subdomain_completed_jobs.items():
            jobs.append(job)

        jobs.sort(key=lambda x: x.get("started_at", ""), reverse=True)

        return jsonify({"success": True, "jobs": jobs})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/scan/<job_id>/results", methods=["GET"])
def get_subdomain_scan_results(job_id):
    """Get the results of a completed subdomain scan"""
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


# ========================================
# Path Discovery API Endpoints
# ========================================


@app.route("/api/path/scan", methods=["POST"])
def start_path_scan():
    """Start a new path discovery scan"""
    if not PATH_AVAILABLE:
        return (
            jsonify(
                {"success": False, "error": "Path Discovery orchestrator not available"}
            ),
            503,
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

        # Load config from path_discovery directory
        config_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "path_discovery",
            "model",
            "config.json",
        )
        config = PathConfig.load(config_path)

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
            "progress": 0,
        }

        # Start scan in background thread
        def run_path_scan():
            try:
                print(f"[{job_id}] Starting path discovery scan for {url}")
                orchestrator = PathDiscoveryOrchestrator(config)
                results = orchestrator.orchestrate(url)

                print(f"[{job_id}] Path discovery scan completed")

                # Save results
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                parsed_url = url.replace("://", "_").replace("/", "_").replace(".", "_")
                filename = f"path_{parsed_url}_{timestamp}.json"
                filepath = RESULTS_DIR / filename

                with open(filepath, "w") as f:
                    json.dump(results, f, indent=2)

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
                print(f"[{job_id}] Path discovery scan failed: {str(e)}")
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

        thread = threading.Thread(target=run_path_scan)
        thread.daemon = True
        thread.start()

        return jsonify(
            {
                "success": True,
                "job_id": job_id,
                "message": "Path discovery scan started",
                "status_url": f"/api/path/scan/{job_id}",
            }
        )

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/path/scan/<job_id>", methods=["GET"])
def get_path_scan_status(job_id):
    """Get the status of a path discovery scan job"""
    if job_id in path_active_jobs:
        return jsonify({"success": True, "job": path_active_jobs[job_id]})
    elif job_id in path_completed_jobs:
        return jsonify({"success": True, "job": path_completed_jobs[job_id]})
    else:
        return jsonify({"success": False, "error": "Job not found"}), 404


@app.route("/api/path/scan/<job_id>/results", methods=["GET"])
def get_path_scan_results(job_id):
    """Get the results of a completed path discovery scan"""
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
def path_stats():
    """Get path discovery statistics"""
    try:
        total_jobs = len(path_active_jobs) + len(path_completed_jobs)
        completed = len(path_completed_jobs)
        running = len(path_active_jobs)

        return jsonify(
            {
                "success": True,
                "statistics": {
                    "total_scans": total_jobs,
                    "completed_scans": completed,
                    "active_scans": running,
                },
            }
        )
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/path/jobs", methods=["GET"])
def list_path_jobs():
    """List all path discovery jobs"""
    try:
        jobs = []

        for job_id, job in path_active_jobs.items():
            jobs.append(job)

        for job_id, job in path_completed_jobs.items():
            jobs.append(job)

        jobs.sort(key=lambda x: x.get("started_at", ""), reverse=True)

        return jsonify({"success": True, "jobs": jobs})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


def run_dashboard_server(host="0.0.0.0", port=5001, debug=False):
    """Run the dashboard server"""
    print("\n" + "=" * 70)
    print("  SecOps Orchestrator - Unified Security Dashboard")
    print("=" * 70)
    print(f"\n🚀 Starting Dashboard Server")
    print(f"📍 URL: http://{host}:{port}")
    print(f"📁 Results Directory: {RESULTS_DIR.absolute()}")
    print(f"\n✅ Available Modules:")
    print(
        f"   • Subdomain Enumeration: {'✅ Active' if SUBDOMAIN_AVAILABLE else '❌ Unavailable'}"
    )
    print(f"   • Path Discovery: {'✅ Active' if PATH_AVAILABLE else '❌ Unavailable'}")
    print(f"\n🛑 Press Ctrl+C to stop the server")
    print("=" * 70 + "\n")

    app.run(host=host, port=port, debug=debug)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Security Scanning Web Dashboard")
    parser.add_argument(
        "--host", default="0.0.0.0", help="Host address (default: 0.0.0.0)"
    )
    parser.add_argument(
        "--port", type=int, default=5001, help="Port number (default: 5001)"
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")

    args = parser.parse_args()

    run_dashboard_server(host=args.host, port=args.port, debug=args.debug)
