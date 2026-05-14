#!/usr/bin/env python3
"""
Integrated Web Server for Subdomain Enumeration
Serves the web interface and provides API endpoints for the orchestrator.
"""

from collections import defaultdict, deque
from functools import wraps
from flask import Flask, Response, jsonify, request, send_file
from flask_cors import CORS
import base64
import json
import asyncio
import time
from datetime import datetime, UTC
from pathlib import Path
import sys
from urllib.parse import urlparse

# Import orchestrator components
from orchestrator import SubdomainOrchestrator
from path_discovery import PathDiscoveryOrchestrator
from xss_scanner import XSSDetectionOrchestrator
from sqli_scanner import SQLiDetectionOrchestrator
from lfi_scanner import LFIOrchestrator
from config import Config
from intelligence import ProductIntelligenceEngine, serialize_analysis
from logging_utils import configure_logger
from reporter import SubdomainReporter
from report_templates import ReportTemplateEngine
from scan_services import ScanModuleService
from result_utils import (
    UnifiedExportService,
    build_unified_recommendation_summary,
)
from scan_profiles import list_profile_payloads, resolve_scan_profile
from tooling import build_tool_health_report, build_tool_status

app = Flask(__name__)
CORS(app)

BASE_DIR = Path(__file__).parent
CONFIG_PATH = BASE_DIR / "config.json"
LOGGER = configure_logger("WebServer")
EXPORT_SERVICE = UnifiedExportService()
RATE_LIMIT_STATE = defaultdict(deque)


def get_runtime_config() -> Config:
    """Load configuration from the model directory."""
    return Config.load(str(CONFIG_PATH))


DATABASE_PATH = get_runtime_config().get_database_path(base_path=BASE_DIR)

subdomain_scan_service = ScanModuleService(
    "subdomains",
    "domain",
    logger_name="WebServer.Subdomains",
    database_path=DATABASE_PATH,
)
path_scan_service = ScanModuleService(
    "paths",
    "target",
    logger_name="WebServer.Paths",
    database_path=DATABASE_PATH,
)
xss_scan_service = ScanModuleService(
    "xss",
    "target",
    logger_name="WebServer.XSS",
    database_path=DATABASE_PATH,
)
sqli_scan_service = ScanModuleService(
    "sqli",
    "target",
    logger_name="WebServer.SQLi",
    database_path=DATABASE_PATH,
)
lfi_scan_service = ScanModuleService(
    "lfi",
    "target",
    logger_name="WebServer.LFI",
    database_path=DATABASE_PATH,
)


def get_results_dir(module_name: str = None) -> Path:
    """Resolve the configured results directory."""
    return get_runtime_config().get_results_dir(module_name, base_path=BASE_DIR)


def ensure_results_directories():
    """Create the expected results directories."""
    for module_name in [None, "subdomains", "paths", "xss", "sqli", "lfi", "reports"]:
        get_results_dir(module_name).mkdir(parents=True, exist_ok=True)


def find_saved_file(filename: str) -> Path:
    """Locate a saved file anywhere under the configured results root."""
    results_root = get_results_dir()

    direct_match = results_root / filename
    if direct_match.exists():
        return direct_match

    for candidate in results_root.rglob(filename):
        if candidate.is_file():
            return candidate

    return None


ensure_results_directories()
RESULTS_DIR = get_results_dir()
REPORT_TEMPLATE_ENGINE = ReportTemplateEngine()
SCAN_SERVICES = {
    "subdomains": subdomain_scan_service,
    "paths": path_scan_service,
    "xss": xss_scan_service,
    "sqli": sqli_scan_service,
    "lfi": lfi_scan_service,
}


def is_local_request() -> bool:
    remote_addr = request.headers.get("X-Forwarded-For", request.remote_addr or "")
    remote_addr = remote_addr.split(",")[0].strip()
    host = (request.host or "").split(":")[0].strip().lower()
    return remote_addr in {"127.0.0.1", "::1", "localhost"} or host in {
        "127.0.0.1",
        "localhost",
    }


def should_require_auth() -> bool:
    auth_config = get_runtime_config().get_dashboard_auth()
    if not auth_config.get("enabled", False):
        return False
    if auth_config.get("require_outside_localhost", True) and is_local_request():
        return False
    return True


def _unauthorized_response():
    response = Response("Authentication required", status=401)
    response.headers["WWW-Authenticate"] = 'Basic realm="SecOps Dashboard"'
    return response


def validate_basic_auth() -> bool:
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Basic "):
        return False

    try:
        decoded = base64.b64decode(auth_header.split(" ", 1)[1]).decode("utf-8")
        username, password = decoded.split(":", 1)
    except Exception:
        return False

    auth_config = get_runtime_config().get_dashboard_auth()
    return (
        username == str(auth_config.get("username", ""))
        and password == str(auth_config.get("password", ""))
    )


@app.before_request
def enforce_security_controls():
    if should_require_auth() and not validate_basic_auth():
        return _unauthorized_response()

    if request.path.startswith("/api"):
        rate_limit_config = get_runtime_config().get_rate_limit()
        if not rate_limit_config.get("enabled", True):
            return None

        window_seconds = max(1, int(rate_limit_config.get("window_seconds", 60)))
        requests_limit = max(1, int(rate_limit_config.get("requests", 120)))
        if is_local_request():
            requests_limit *= max(1, int(rate_limit_config.get("localhost_multiplier", 1)))

        identifier = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown")
        bucket = RATE_LIMIT_STATE[identifier]
        now = time.time()

        while bucket and bucket[0] <= now - window_seconds:
            bucket.popleft()

        if len(bucket) >= requests_limit:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": "Rate limit exceeded",
                        "retry_after": window_seconds,
                    }
                ),
                429,
            )

        bucket.append(now)
    return None


def get_scan_service(module_name: str) -> ScanModuleService:
    return SCAN_SERVICES[module_name]


def is_valid_url_target(value: str) -> bool:
    parsed = urlparse(value or "")
    return bool(parsed.scheme and parsed.netloc)


def is_valid_domain_target(value: str) -> bool:
    import re

    return bool(
        re.match(
            r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$",
            value or "",
        )
    )


def build_safe_tool_status_list(tool_mapping: dict) -> list[dict]:
    statuses = []
    for tool_name, tool_config in (tool_mapping or {}).items():
        try:
            statuses.append(build_tool_status(tool_name, tool_config))
        except Exception as exc:
            LOGGER.exception("Failed to inspect tool status for %s", tool_name)
            statuses.append(
                {
                    "name": tool_name,
                    "description": (
                        tool_config.get("description", "")
                        if isinstance(tool_config, dict)
                        else ""
                    ),
                    "enabled": (
                        tool_config.get("enabled", False)
                        if isinstance(tool_config, dict)
                        else False
                    ),
                    "installed": False,
                    "status": "error",
                    "path": None,
                    "version": None,
                    "error": str(exc),
                }
            )
    return statuses


def get_latest_completed_job(module_name: str) -> dict | None:
    return get_scan_service(module_name).latest_completed_job()


def get_completed_job(module_name: str, job_id: str | None) -> dict | None:
    service = get_scan_service(module_name)
    if job_id:
        job = service.get_job(job_id, include_results=True)
        if job and job.get("status") in {"completed", "failed"}:
            return job
        return None
    return service.latest_completed_job()


def get_job_status_payload(module_name: str, job_id: str) -> dict | None:
    service = get_scan_service(module_name)
    return service.get_job(job_id, include_results=False)


def get_module_job_collections(module_name: str) -> tuple[list[dict], list[dict]]:
    service = get_scan_service(module_name)
    active = service.list_jobs(status="running", limit=500)
    completed = service.list_jobs(statuses=("completed", "failed"), limit=500)
    return active, completed


def stream_job_events(module_name: str, job_id: str):
    service = get_scan_service(module_name)

    def generate():
        last_event_id = 0
        while True:
            events = service.events_after(job_id, last_event_id)
            if events:
                for event in events:
                    last_event_id = max(last_event_id, event["event_id"])
                    yield (
                        f"id: {event['event_id']}\n"
                        f"event: {event['event']}\n"
                        f"data: {json.dumps(event['data'], ensure_ascii=False)}\n\n"
                    )

                    if event["event"] in {"completed", "failed"}:
                        return
            else:
                job = service.get_job(job_id, include_results=False)
                if job and job.get("status") in {"completed", "failed"}:
                    yield (
                        f"event: {job['status']}\n"
                        f"data: {json.dumps(job, ensure_ascii=False)}\n\n"
                    )
                    return
                yield "event: keepalive\ndata: {}\n\n"
            time.sleep(1)

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


def build_intelligence_engine(config: Config = None) -> ProductIntelligenceEngine:
    runtime_config = config or get_runtime_config()
    return ProductIntelligenceEngine(runtime_config.get_intelligence_rules())


def summarize_intelligence(analysis: dict) -> dict:
    return {
        "executive_summary": analysis.get("executive_summary", {}),
        "recommendations": analysis.get("recommendations", [])[:5],
        "next_actions": analysis.get("correlations", {}).get("next_actions", [])[:10],
    }


def get_job_results_bundle(job_ids: dict | None = None) -> dict:
    job_ids = job_ids or {}
    bundle = {}
    for module_name in SCAN_SERVICES:
        job = get_completed_job(module_name, job_ids.get(module_name))
        if job and job.get("status") == "completed" and "results" in job:
            bundle[module_name] = job["results"]
    return bundle


def job_exists(service: ScanModuleService, target: str) -> bool:
    for container in (service.active_jobs, service.completed_jobs):
        for job in container.values():
            if job.get(service.target_field) == target:
                return True
    return False


def annotate_job_with_intelligence(
    module_name: str,
    completed_job: dict,
    results: dict,
) -> list[dict]:
    analysis = build_intelligence_engine().analyze({module_name: results})
    snapshot = summarize_intelligence(analysis)
    results["intelligence"] = snapshot
    completed_job["intelligence"] = snapshot
    return analysis.get("correlations", {}).get("next_actions", [])


def queue_path_scan(
    target_url: str,
    selected_tools: list | None = None,
    *,
    parallel_execution: bool | None = None,
    metadata: dict | None = None,
    on_complete=None,
) -> str:
    config = get_runtime_config()
    if parallel_execution is not None:
        config.parallel_execution = bool(parallel_execution)

    def run_path_scan(progress_callback, job_logger):
        progress_callback(5)
        orchestrator = PathDiscoveryOrchestrator(config)
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            job_logger.info("Path discovery execution plan ready")
            progress_callback(25)
            results = loop.run_until_complete(orchestrator.discover(target_url, selected_tools))
            progress_callback(90)
            return results
        finally:
            loop.close()

    return path_scan_service.start_job(
        target_value=target_url,
        runner=run_path_scan,
        initial_fields=metadata,
        on_complete=on_complete,
    )


def queue_xss_scan(
    target_url: str,
    selected_tools: list | None = None,
    *,
    metadata: dict | None = None,
    on_complete=None,
) -> str:
    config = get_runtime_config()

    def run_xss_scan(progress_callback, job_logger):
        progress_callback(5)
        orchestrator = XSSDetectionOrchestrator(config)
        return orchestrator.scan(
            target_url,
            selected_tools,
            progress_callback=progress_callback,
        )

    return xss_scan_service.start_job(
        target_value=target_url,
        runner=run_xss_scan,
        initial_fields=metadata,
        on_complete=on_complete,
    )


def queue_sqli_scan(
    target_url: str,
    *,
    tools: list | None = None,
    intensity: str = "basic",
    options: dict | None = None,
    metadata: dict | None = None,
    on_complete=None,
) -> str:
    config = get_runtime_config()
    selected_tools = tools
    if selected_tools is None:
        selected_tools = [
            tool_name
            for tool_name, tool_config in config.get_sqli_tools().items()
            if tool_config.get("enabled", True)
        ]

    def run_scan(progress_callback, job_logger):
        progress_callback(5)
        orchestrator = SQLiDetectionOrchestrator(config)
        return orchestrator.scan(
            target_url=target_url,
            tools=selected_tools,
            intensity=intensity,
            options=options or {},
            progress_callback=progress_callback,
        )

    initial_fields = {"tools": selected_tools, "intensity": intensity, "options": options or {}}
    if metadata:
        initial_fields.update(metadata)

    return sqli_scan_service.start_job(
        target_value=target_url,
        runner=run_scan,
        initial_fields=initial_fields,
        on_complete=on_complete,
    )


def queue_lfi_scan(
    target_url: str,
    *,
    parameters: list | None = None,
    tools: list | None = None,
    metadata: dict | None = None,
    on_complete=None,
) -> str:
    selected_tools = tools or ["ffuf", "custom"]

    def run_scan(progress_callback, job_logger):
        progress_callback(5)
        config = get_runtime_config()
        lfi_tools = config.get_lfi_tools()
        for tool_name in lfi_tools:
            lfi_tools[tool_name]["enabled"] = tool_name in selected_tools

        orchestrator = LFIOrchestrator(config)
        progress_callback(20)
        results = orchestrator.orchestrate(target_url, parameters)
        progress_callback(90)
        return results

    initial_fields = {"parameters": parameters, "tools": selected_tools}
    if metadata:
        initial_fields.update(metadata)

    return lfi_scan_service.start_job(
        target_value=target_url,
        runner=run_scan,
        initial_fields=initial_fields,
        on_complete=on_complete,
    )


def launch_follow_up_actions(actions: list[dict], source_job_id: str) -> list[dict]:
    launched = []

    for action in actions:
        scan_type = action.get("scan_type")
        target = action.get("target")
        if not scan_type or not target:
            continue

        metadata = {
            "auto_generated": True,
            "triggered_by": {
                "job_id": source_job_id,
                "module": action.get("source_module"),
                "rule_id": action.get("rule_id"),
                "reason": action.get("reason"),
            },
        }

        if scan_type == "path":
            if job_exists(path_scan_service, target):
                continue
            job_id = queue_path_scan(target, metadata=metadata, on_complete=handle_path_completion)
        elif scan_type == "xss":
            if not urlparse(target).query or job_exists(xss_scan_service, target):
                continue
            job_id = queue_xss_scan(target, metadata=metadata)
        elif scan_type == "sqli":
            if not urlparse(target).query or job_exists(sqli_scan_service, target):
                continue
            job_id = queue_sqli_scan(target, metadata=metadata)
        elif scan_type == "lfi":
            if not urlparse(target).query or job_exists(lfi_scan_service, target):
                continue
            job_id = queue_lfi_scan(target, metadata=metadata)
        else:
            continue

        launched.append({**action, "job_id": job_id})

    return launched


def handle_subdomain_completion(job_id: str, completed_job: dict, results: dict):
    actions = annotate_job_with_intelligence("subdomains", completed_job, results)
    launched = []
    if build_intelligence_engine().correlation_engine.rule_engine.auto_follow_up_enabled():
        launched = launch_follow_up_actions(actions, job_id)
    completed_job["auto_follow_up"] = {"planned": actions, "launched": launched}
    results["auto_follow_up"] = completed_job["auto_follow_up"]


def queue_subdomain_scan(
    domain: str,
    config: Config,
    *,
    metadata: dict | None = None,
    on_complete=None,
) -> str:
    def run_scan(progress_callback, job_logger):
        progress_callback(5)
        orchestrator = SubdomainOrchestrator(config)
        progress_callback(20)
        results = orchestrator.orchestrate(domain)
        progress_callback(90)
        return results

    return subdomain_scan_service.start_job(
        target_value=domain,
        runner=run_scan,
        initial_fields=metadata,
        on_complete=on_complete,
    )


def handle_path_completion(job_id: str, completed_job: dict, results: dict):
    actions = annotate_job_with_intelligence("paths", completed_job, results)
    launched = []
    if build_intelligence_engine().correlation_engine.rule_engine.auto_follow_up_enabled():
        launched = launch_follow_up_actions(actions, job_id)
    completed_job["auto_follow_up"] = {"planned": actions, "launched": launched}
    results["auto_follow_up"] = completed_job["auto_follow_up"]


def handle_xss_completion(job_id: str, completed_job: dict, results: dict):
    annotate_job_with_intelligence("xss", completed_job, results)


def handle_sqli_completion(job_id: str, completed_job: dict, results: dict):
    annotate_job_with_intelligence("sqli", completed_job, results)


def handle_lfi_completion(job_id: str, completed_job: dict, results: dict):
    annotate_job_with_intelligence("lfi", completed_job, results)


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


@app.route("/profile-overrides.css")
def serve_profile_overrides_css():
    """Serve profile-specific UI overrides."""
    css_path = Path(__file__).parent.parent / "web" / "profile-overrides.css"
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
    runtime_config = get_runtime_config()
    return jsonify(
        {
            "status": "healthy",
            "version": "4.0.0",
            "timestamp": datetime.now(UTC).isoformat(),
            "modules": {
                module_name: True for module_name in SCAN_SERVICES
            },
            "database": str(runtime_config.get_database_path(base_path=BASE_DIR)),
        }
    )


@app.route("/api/profiles", methods=["GET"])
def list_scan_profiles():
    """List available scan profiles and their module presets."""
    config = get_runtime_config()
    return jsonify(
        {
            "success": True,
            "profiles": list_profile_payloads(config.get_scan_profiles()),
            "default": "standard",
        }
    )


@app.route("/api/tools", methods=["GET"])
def list_tools():
    """List available tools and their status"""
    try:
        config = get_runtime_config()
        tools_list = build_safe_tool_status_list(config.get_subdomain_tools())

        return jsonify({"success": True, "tools": tools_list})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/tool-health", methods=["GET"])
def get_tool_health():
    """Return installed tools, versions, and resolved paths grouped by module."""
    try:
        config = get_runtime_config()
        payload = build_tool_health_report(config)
        payload["generated_at"] = datetime.now(UTC).isoformat()
        return jsonify({"success": True, **payload})
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
        data = request.get_json(silent=True) or {}

        if not data or "domain" not in data:
            return (
                jsonify({"success": False, "error": "Missing required field: domain"}),
                400,
            )

        domain = data["domain"]
        if not is_valid_domain_target(domain):
            return jsonify({"success": False, "error": "Invalid domain format"}), 400
        profile = resolve_scan_profile(
            "subdomains",
            data.get("profile"),
            configured_profiles=get_runtime_config().get_scan_profiles(),
        )

        # Load config
        config = get_runtime_config()

        selected_tools = data.get("tools") or profile.get("tools")
        if selected_tools:
            # Disable all tools first
            for tool in config.tools:
                config.tools[tool]["enabled"] = False
            # Enable requested tools
            for tool in selected_tools:
                if tool in config.tools:
                    config.tools[tool]["enabled"] = True

        config.parallel_execution = data.get(
            "parallel",
            profile.get("parallel", config.parallel_execution),
        )

        config.perform_dns_validation = data.get(
            "validate_dns",
            profile.get("validate_dns", config.perform_dns_validation),
        )

        # Always save results
        config.save_results = True

        job_id = queue_subdomain_scan(
            domain,
            config,
            metadata={
                "profile": profile.get("profile_name", "standard"),
                "tools": selected_tools or config.get_enabled_tools(),
            },
            on_complete=handle_subdomain_completion,
        )

        return (
            jsonify(
                {
                    "success": True,
                    "job_id": job_id,
                    "message": "Scan started",
                    "status_url": f"/api/scan/{job_id}",
                    "results_url": f"/api/scan/{job_id}/results",
                    "event_url": f"/api/scan/{job_id}/events",
                }
            ),
            202,
        )

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/scan/<job_id>", methods=["GET"])
def get_scan_status(job_id):
    """Get status of a scan job"""
    job = get_job_status_payload("subdomains", job_id)
    if not job:
        return jsonify({"success": False, "error": "Job not found"}), 404
    return jsonify({"success": True, "job": job})


@app.route("/api/scan/<job_id>/events", methods=["GET"])
def get_scan_events(job_id):
    """Stream live subdomain scan progress via SSE."""
    if not get_scan_service("subdomains").get_job(job_id, include_results=False):
        return jsonify({"success": False, "error": "Job not found"}), 404
    return stream_job_events("subdomains", job_id)


@app.route("/api/scan/<job_id>/results", methods=["GET"])
def get_scan_results(job_id):
    """Get detailed results of a completed scan"""
    job = get_completed_job("subdomains", job_id)
    if not job:
        return (
            jsonify({"success": False, "error": "Job not found or not completed"}),
            404,
        )

    if job["status"] == "failed":
        return (
            jsonify({"success": False, "error": job.get("error", "Scan failed")}),
            500,
        )

    return jsonify({"success": True, "results": job["results"]})


@app.route("/api/scan/<job_id>/report", methods=["GET"])
def generate_report(job_id):
    """Generate HTML report for a completed scan"""
    job = get_completed_job("subdomains", job_id)
    if not job:
        return (
            jsonify({"success": False, "error": "Job not found or not completed"}),
            404,
        )

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
        html_filename = f"report_{domain.replace('.', '_')}_{timestamp}.html"
        reports_dir = get_results_dir("reports")
        reports_dir.mkdir(parents=True, exist_ok=True)
        html_filepath = reports_dir / html_filename

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
    filepath = find_saved_file(filename)

    if filepath is None or not filepath.exists():
        return "File not found", 404

    return send_file(filepath, as_attachment=True)


@app.route("/api/jobs", methods=["GET"])
def list_jobs():
    """List all jobs (active and completed)"""

    all_jobs = []
    active_jobs, completed_jobs = get_module_job_collections("subdomains")

    # Add active jobs
    for job in active_jobs:
        all_jobs.append(
            {
                "job_id": job["job_id"],
                "domain": job["domain"],
                "status": job["status"],
                "progress": job.get("progress", 0),
                "profile": job.get("profile", "standard"),
                "started_at": job["started_at"],
            }
        )

    # Add completed jobs (latest 50)
    for job in completed_jobs[:50]:
        all_jobs.append(
            {
                "job_id": job["job_id"],
                "domain": job["domain"],
                "status": job["status"],
                "progress": job.get("progress", 100 if job["status"] == "completed" else 0),
                "profile": job.get("profile", "standard"),
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

    active_jobs, completed_jobs = get_module_job_collections("subdomains")
    total_scans = len(active_jobs) + len(completed_jobs)
    successful_scans = sum(
        1 for job in completed_jobs if job["status"] == "completed"
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
        results_root = get_results_dir()
        for file in results_root.rglob("*.json"):
            stat = file.stat()
            relative_parent = file.parent.relative_to(results_root)
            results_files.append(
                {
                    "filename": file.name,
                    "path": str(file),
                    "category": (
                        str(relative_parent).replace("\\", "/")
                        if str(relative_parent) != "."
                        else "root"
                    ),
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


def export_completed_result(module_name: str, job_id: str, output_format: str):
    if output_format not in EXPORT_SERVICE.SUPPORTED_FORMATS:
        return jsonify({"success": False, "error": "Unsupported export format"}), 400

    job = get_completed_job(module_name, job_id)
    if not job:
        return jsonify({"success": False, "error": "Job not found or not completed"}), 404
    if job["status"] == "failed":
        return jsonify({"success": False, "error": "Cannot export failed scan"}), 400

    extension = {"json": "json", "csv": "csv", "markdown": "md", "pdf": "pdf"}[
        output_format
    ]
    output_dir = get_results_dir("reports")
    filename = f"{module_name}_{job_id[:8]}.{extension}"
    output_path = output_dir / filename
    EXPORT_SERVICE.export_scan_result(job["results"], output_format, output_path)

    return jsonify(
        {
            "success": True,
            "format": output_format,
            "file": str(output_path),
            "download_url": f"/api/download/{filename}",
        }
    )


@app.route("/api/scan/<job_id>/export", methods=["GET"])
def export_subdomain_scan(job_id):
    """Export subdomain scan results in a unified format."""
    return export_completed_result(
        "subdomains", job_id, request.args.get("format", "json").lower()
    )


@app.route("/api/<module_name>/scan/<job_id>/export", methods=["GET"])
def export_module_scan(module_name, job_id):
    """Export non-subdomain scan results in a unified format."""
    if module_name not in {"paths", "xss", "sqli", "lfi"}:
        return jsonify({"success": False, "error": "Unsupported module"}), 404
    return export_completed_result(
        module_name, job_id, request.args.get("format", "json").lower()
    )


@app.route("/api/intelligence/templates", methods=["GET"])
def list_intelligence_templates():
    """List available integrated-report templates and export formats."""
    return jsonify(
        {
            "success": True,
            "templates": [
                {"id": template_id, "label": label}
                for template_id, label in REPORT_TEMPLATE_ENGINE.TEMPLATE_LABELS.items()
            ],
            "formats": list(REPORT_TEMPLATE_ENGINE.SUPPORTED_FORMATS),
        }
    )


@app.route("/api/intelligence/analyze", methods=["POST"])
def analyze_intelligence():
    """Build cross-module correlation, recommendations, and optional exported reports."""
    try:
        data = request.get_json(silent=True) or {}
        job_ids = data.get("job_ids", {})
        template_name = data.get("template", "internal_review")
        output_format = data.get("format", "html")
        export_report = bool(data.get("export", True))

        if template_name not in REPORT_TEMPLATE_ENGINE.TEMPLATE_LABELS:
            return jsonify({"success": False, "error": "Unsupported template"}), 400

        if output_format not in REPORT_TEMPLATE_ENGINE.SUPPORTED_FORMATS:
            return jsonify({"success": False, "error": "Unsupported format"}), 400

        results_by_module = get_job_results_bundle(job_ids)
        if not results_by_module:
            return jsonify({"success": False, "error": "No completed scan results available"}), 404

        analysis = build_intelligence_engine().analyze(results_by_module)
        recommendation_summary = build_unified_recommendation_summary(results_by_module)

        analysis_dir = get_results_dir("reports")
        timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        analysis_filename = f"intelligence_analysis_{timestamp}.json"
        analysis_path = analysis_dir / analysis_filename
        analysis_path.write_text(serialize_analysis(analysis), encoding="utf-8")

        report_filename = None
        if export_report:
            extension_map = {"markdown": "md", "html": "html", "pdf": "pdf"}
            report_filename = (
                f"{template_name}_{timestamp}.{extension_map.get(output_format, output_format)}"
            )
            REPORT_TEMPLATE_ENGINE.export_report(
                template_name,
                analysis,
                output_format,
                analysis_dir / report_filename,
            )

        return jsonify(
            {
                "success": True,
                "analysis": analysis,
                "recommendation_summary": recommendation_summary,
                "analysis_file": str(analysis_path),
                "analysis_download_url": f"/api/download/{analysis_filename}",
                "report_file": str(analysis_dir / report_filename) if report_filename else None,
                "report_download_url": (
                    f"/api/download/{report_filename}" if report_filename else None
                ),
            }
        )
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/recommendations/summary", methods=["POST"])
def recommendation_summary():
    """Build a unified recommendation summary across the selected module jobs."""
    try:
        data = request.get_json(silent=True) or {}
        job_ids = data.get("job_ids", {})
        output_format = str(data.get("format", "json")).lower()
        export_report = bool(data.get("export", False))

        results_by_module = get_job_results_bundle(job_ids)
        if not results_by_module:
            return jsonify({"success": False, "error": "No completed scan results available"}), 404

        summary = build_unified_recommendation_summary(results_by_module)
        response = {
            "success": True,
            "summary": summary,
        }

        if export_report:
            if output_format not in EXPORT_SERVICE.SUPPORTED_FORMATS:
                return jsonify({"success": False, "error": "Unsupported export format"}), 400
            output_dir = get_results_dir("reports")
            extension = {"json": "json", "csv": "csv", "markdown": "md", "pdf": "pdf"}[
                output_format
            ]
            filename = f"recommendation_summary_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}.{extension}"
            output_path = output_dir / filename
            EXPORT_SERVICE.export_scan_result(
                {
                    "scan_info": {
                        "module": "recommendation_summary",
                        "target": ", ".join(sorted(results_by_module.keys())),
                        "profile": "combined",
                        "scan_time": summary["generated_at"],
                    },
                    "summary": summary["summary"],
                    "findings": summary["top_findings"],
                    "recommendation_summary": {
                        "headline": summary["headline"],
                        "risk_posture": summary["risk_posture"],
                        "actions": summary["recommendations"],
                    },
                },
                output_format,
                output_path,
            )
            response["file"] = str(output_path)
            response["download_url"] = f"/api/download/{filename}"

        return jsonify(response)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# =============================================
# Path Discovery API Endpoints
# =============================================


@app.route("/api/path/tools", methods=["GET"])
def list_path_tools():
    """List available path discovery tools and their status"""
    try:
        config = get_runtime_config()
        tools_list = build_safe_tool_status_list(config.get_path_discovery_tools())

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
        data = request.get_json(silent=True) or {}

        if not data or "url" not in data:
            return (
                jsonify({"success": False, "error": "Missing required field: url"}),
                400,
            )

        target_url = data["url"]
        if not is_valid_url_target(target_url):
            return jsonify({"success": False, "error": "Invalid URL format"}), 400
        profile = resolve_scan_profile(
            "paths",
            data.get("profile"),
            configured_profiles=get_runtime_config().get_scan_profiles(),
        )
        selected_tools = data.get("tools") or profile.get("tools")

        job_id = queue_path_scan(
            target_url,
            selected_tools,
            parallel_execution=profile.get("parallel"),
            metadata={
                "profile": profile.get("profile_name", "standard"),
                "tools": selected_tools or [],
            },
            on_complete=handle_path_completion,
        )

        return (
            jsonify(
                {
                    "success": True,
                    "job_id": job_id,
                    "message": "Path discovery started",
                    "status_url": f"/api/path/scan/{job_id}",
                    "results_url": f"/api/path/scan/{job_id}/results",
                    "event_url": f"/api/path/scan/{job_id}/events",
                }
            ),
            202,
        )

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/path/scan/<job_id>", methods=["GET"])
def get_path_scan_status(job_id):
    """Get status of a path discovery job"""
    job = get_job_status_payload("paths", job_id)
    if not job:
        return jsonify({"success": False, "error": "Job not found"}), 404
    return jsonify({"success": True, "job": job})


@app.route("/api/path/scan/<job_id>/events", methods=["GET"])
def get_path_scan_events(job_id):
    """Stream live path-discovery progress via SSE."""
    if not get_scan_service("paths").get_job(job_id, include_results=False):
        return jsonify({"success": False, "error": "Job not found"}), 404
    return stream_job_events("paths", job_id)


@app.route("/api/path/scan/<job_id>/results", methods=["GET"])
def get_path_scan_results(job_id):
    """Get detailed results of a completed path discovery scan"""
    job = get_completed_job("paths", job_id)
    if not job:
        return (
            jsonify({"success": False, "error": "Job not found or not completed"}),
            404,
        )

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
    path_active_jobs, path_completed_jobs = get_module_job_collections("paths")

    # Add active jobs
    for job in path_active_jobs:
        all_jobs.append(
            {
                "job_id": job["job_id"],
                "target": job["target"],
                "status": job["status"],
                "progress": job.get("progress", 0),
                "profile": job.get("profile", "standard"),
                "started_at": job["started_at"],
            }
        )

    # Add completed jobs (latest 50)
    for job in path_completed_jobs[:50]:
        all_jobs.append(
            {
                "job_id": job["job_id"],
                "target": job["target"],
                "status": job["status"],
                "progress": job.get("progress", 100 if job["status"] == "completed" else 0),
                "profile": job.get("profile", "standard"),
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

    path_active_jobs, path_completed_jobs = get_module_job_collections("paths")
    total_scans = len(path_active_jobs) + len(path_completed_jobs)
    successful_scans = sum(
        1 for job in path_completed_jobs if job["status"] == "completed"
    )

    # Calculate total paths and params found
    total_paths = 0
    total_params = 0
    critical_findings = 0

    for job in path_completed_jobs:
        if job["status"] == "completed" and "results" in job:
            results = job["results"]
            if "summary" in results:
                module_metrics = results["summary"].get("module_metrics", {})
                total_paths += module_metrics.get("paths", {}).get("total", 0)
                total_params += module_metrics.get("parameters", {}).get("total", 0)
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
        config = get_runtime_config()
        tools_list = build_safe_tool_status_list(config.get_xss_tools())

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
        data = request.get_json(silent=True) or {}

        if not data or "url" not in data:
            return (
                jsonify({"success": False, "error": "Missing required field: url"}),
                400,
            )

        target_url = data["url"]
        if not is_valid_url_target(target_url):
            return jsonify({"success": False, "error": "Invalid URL format"}), 400
        profile = resolve_scan_profile(
            "xss",
            data.get("profile"),
            configured_profiles=get_runtime_config().get_scan_profiles(),
        )
        selected_tools = data.get("tools") or profile.get("tools")

        job_id = queue_xss_scan(
            target_url,
            selected_tools,
            metadata={
                "profile": profile.get("profile_name", "standard"),
                "tools": selected_tools or [],
            },
            on_complete=handle_xss_completion,
        )

        return (
            jsonify(
                {
                    "success": True,
                    "job_id": job_id,
                    "message": "XSS detection started",
                    "status_url": f"/api/xss/scan/{job_id}",
                    "results_url": f"/api/xss/scan/{job_id}/results",
                    "event_url": f"/api/xss/scan/{job_id}/events",
                }
            ),
            202,
        )

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/xss/scan/<job_id>", methods=["GET"])
def get_xss_scan_status(job_id):
    """Get status of an XSS detection job"""
    job = get_job_status_payload("xss", job_id)
    if not job:
        return jsonify({"success": False, "error": "Job not found"}), 404
    return jsonify({"success": True, "job": job})


@app.route("/api/xss/scan/<job_id>/events", methods=["GET"])
def get_xss_scan_events(job_id):
    """Stream live XSS progress via SSE."""
    if not get_scan_service("xss").get_job(job_id, include_results=False):
        return jsonify({"success": False, "error": "Job not found"}), 404
    return stream_job_events("xss", job_id)


@app.route("/api/xss/scan/<job_id>/results", methods=["GET"])
def get_xss_scan_results(job_id):
    """Get detailed results of a completed XSS detection scan"""
    job = get_completed_job("xss", job_id)
    if not job:
        return (
            jsonify({"success": False, "error": "Job not found or not completed"}),
            404,
        )

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
    xss_active_jobs, xss_completed_jobs = get_module_job_collections("xss")

    # Add active jobs
    for job in xss_active_jobs:
        all_jobs.append(
            {
                "job_id": job["job_id"],
                "target": job["target"],
                "status": job["status"],
                "progress": job.get("progress", 0),
                "profile": job.get("profile", "standard"),
                "started_at": job["started_at"],
            }
        )

    # Add completed jobs (latest 50)
    for job in xss_completed_jobs[:50]:
        all_jobs.append(
            {
                "job_id": job["job_id"],
                "target": job["target"],
                "status": job["status"],
                "progress": job.get("progress", 100 if job["status"] == "completed" else 0),
                "profile": job.get("profile", "standard"),
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

    xss_active_jobs, xss_completed_jobs = get_module_job_collections("xss")
    total_scans = len(xss_active_jobs) + len(xss_completed_jobs)
    successful_scans = sum(
        1 for job in xss_completed_jobs if job["status"] == "completed"
    )

    # Calculate total findings by severity
    total_findings = 0
    critical_findings = 0
    high_findings = 0
    medium_findings = 0

    for job in xss_completed_jobs:
        if job["status"] == "completed" and "results" in job:
            results = job["results"]
            if "summary" in results:
                total_findings += results["summary"].get("total_findings", 0)
                critical_findings += results["summary"].get("severity", {}).get("critical", 0)
                high_findings += results["summary"].get("severity", {}).get("high", 0)
                medium_findings += results["summary"].get("severity", {}).get("medium", 0)

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
    config = get_runtime_config()
    result = build_safe_tool_status_list(config.get_sqli_tools())

    return jsonify({"success": True, "tools": result})


@app.route("/api/sqli/scan", methods=["POST"])
def start_sqli_scan():
    """Start a new SQL injection detection scan"""
    data = request.get_json(silent=True) or {}

    if not data:
        return jsonify({"success": False, "error": "No data provided"}), 400

    target_url = data.get("url")
    if not target_url:
        return jsonify({"success": False, "error": "No URL provided"}), 400
    if not is_valid_url_target(target_url):
        return jsonify({"success": False, "error": "Invalid URL format"}), 400

    config = get_runtime_config()

    profile = resolve_scan_profile(
        "sqli",
        data.get("profile"),
        configured_profiles=get_runtime_config().get_scan_profiles(),
    )
    # Get selected tools
    tools = data.get("tools") or profile.get("tools")
    if tools is None:
        tools = [
            tool_name
            for tool_name, tool_config in config.get_sqli_tools().items()
            if tool_config.get("enabled", True)
        ]
    intensity = data.get("intensity", profile.get("intensity", "basic"))
    options = profile.get("options", {}).copy()
    options.update(data.get("options", {}))

    job_id = queue_sqli_scan(
        target_url,
        tools=tools,
        intensity=intensity,
        options=options,
        metadata={
            "profile": profile.get("profile_name", "standard"),
            "tools": tools,
        },
        on_complete=handle_sqli_completion,
    )

    return (
        jsonify(
            {
                "success": True,
                "job_id": job_id,
                "message": f"SQL injection scan started for {target_url}",
                "status_url": f"/api/sqli/scan/{job_id}",
                "results_url": f"/api/sqli/scan/{job_id}/results",
                "event_url": f"/api/sqli/scan/{job_id}/events",
            }
        ),
        202,
    )


@app.route("/api/sqli/scan/<job_id>", methods=["GET"])
def get_sqli_scan_status(job_id):
    """Get status of a SQL injection detection job"""
    job = get_job_status_payload("sqli", job_id)
    if not job:
        return jsonify({"success": False, "error": "Job not found"}), 404
    return jsonify({"success": True, "job": job})


@app.route("/api/sqli/scan/<job_id>/events", methods=["GET"])
def get_sqli_scan_events(job_id):
    """Stream live SQLi progress via SSE."""
    if not get_scan_service("sqli").get_job(job_id, include_results=False):
        return jsonify({"success": False, "error": "Job not found"}), 404
    return stream_job_events("sqli", job_id)


@app.route("/api/sqli/scan/<job_id>/results", methods=["GET"])
def get_sqli_scan_results(job_id):
    """Get detailed results of a completed SQL injection detection scan"""
    job = get_completed_job("sqli", job_id)
    if not job:
        return (
            jsonify({"success": False, "error": "Job not found or not completed"}),
            404,
        )

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
    sqli_active_jobs, sqli_completed_jobs = get_module_job_collections("sqli")

    for job in sqli_active_jobs:
        all_jobs.append(
            {
                "job_id": job["job_id"],
                "target": job["target"],
                "status": job["status"],
                "progress": job.get("progress", 0),
                "profile": job.get("profile", "standard"),
                "started_at": job["started_at"],
            }
        )

    for job in sqli_completed_jobs:
        job_summary = {
            "job_id": job["job_id"],
            "target": job["target"],
            "status": job["status"],
            "progress": job.get("progress", 100 if job["status"] == "completed" else 0),
            "profile": job.get("profile", "standard"),
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

    sqli_active_jobs, sqli_completed_jobs = get_module_job_collections("sqli")
    total_scans = len(sqli_active_jobs) + len(sqli_completed_jobs)
    successful_scans = sum(
        1 for job in sqli_completed_jobs if job["status"] == "completed"
    )

    # Calculate total findings by severity
    total_findings = 0
    critical_findings = 0
    high_findings = 0
    medium_findings = 0

    for job in sqli_completed_jobs:
        if job["status"] == "completed" and "results" in job:
            results = job["results"]
            if "summary" in results:
                total_findings += results["summary"].get("total_findings", 0)
                critical_findings += results["summary"].get("severity", {}).get("critical", 0)
                high_findings += results["summary"].get("severity", {}).get("high", 0)
                medium_findings += results["summary"].get("severity", {}).get("medium", 0)

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
    config = get_runtime_config()
    result = build_safe_tool_status_list(config.get_lfi_tools())

    return jsonify({"success": True, "tools": result})


@app.route("/api/lfi/scan", methods=["POST"])
def start_lfi_scan():
    """Start a new LFI detection scan"""
    data = request.get_json(silent=True) or {}

    if not data:
        return jsonify({"success": False, "error": "No data provided"}), 400

    target_url = data.get("url")
    if not target_url:
        return jsonify({"success": False, "error": "No URL provided"}), 400
    if not is_valid_url_target(target_url):
        return jsonify({"success": False, "error": "Invalid URL format"}), 400

    # Get optional parameters
    parameters = data.get("parameters", None)
    profile = resolve_scan_profile(
        "lfi",
        data.get("profile"),
        configured_profiles=get_runtime_config().get_scan_profiles(),
    )
    tools = data.get("tools", profile.get("tools", ["ffuf", "custom"]))

    job_id = queue_lfi_scan(
        target_url,
        parameters=parameters,
        tools=tools,
        metadata={
            "profile": profile.get("profile_name", "standard"),
            "tools": tools,
        },
        on_complete=handle_lfi_completion,
    )

    return (
        jsonify(
            {
                "success": True,
                "job_id": job_id,
                "message": f"LFI detection scan started for {target_url}",
                "status_url": f"/api/lfi/scan/{job_id}",
                "results_url": f"/api/lfi/scan/{job_id}/results",
                "event_url": f"/api/lfi/scan/{job_id}/events",
            }
        ),
        202,
    )


@app.route("/api/lfi/scan/<job_id>", methods=["GET"])
def get_lfi_scan_status(job_id):
    """Get status of an LFI detection job"""
    job = get_job_status_payload("lfi", job_id)
    if not job:
        return jsonify({"success": False, "error": "Job not found"}), 404
    return jsonify({"success": True, "job": job})


@app.route("/api/lfi/scan/<job_id>/events", methods=["GET"])
def get_lfi_scan_events(job_id):
    """Stream live LFI progress via SSE."""
    if not get_scan_service("lfi").get_job(job_id, include_results=False):
        return jsonify({"success": False, "error": "Job not found"}), 404
    return stream_job_events("lfi", job_id)


@app.route("/api/lfi/scan/<job_id>/results", methods=["GET"])
def get_lfi_scan_results(job_id):
    """Get detailed results of a completed LFI detection scan"""
    job = get_completed_job("lfi", job_id)
    if not job:
        return (
            jsonify({"success": False, "error": "Job not found or not completed"}),
            404,
        )

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
    lfi_active_jobs, lfi_completed_jobs = get_module_job_collections("lfi")

    # Add active jobs
    for job in lfi_active_jobs:
        all_jobs.append(
            {
                "job_id": job["job_id"],
                "target": job["target"],
                "status": job["status"],
                "progress": job.get("progress", 0),
                "profile": job.get("profile", "standard"),
                "started_at": job["started_at"],
            }
        )

    # Add completed jobs (latest 50)
    for job in lfi_completed_jobs[:50]:
        all_jobs.append(
            {
                "job_id": job["job_id"],
                "target": job["target"],
                "status": job["status"],
                "progress": job.get("progress", 100 if job["status"] == "completed" else 0),
                "profile": job.get("profile", "standard"),
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

    lfi_active_jobs, lfi_completed_jobs = get_module_job_collections("lfi")
    total_scans = len(lfi_active_jobs) + len(lfi_completed_jobs)
    successful_scans = sum(
        1 for job in lfi_completed_jobs if job["status"] == "completed"
    )

    # Calculate total findings by severity
    total_findings = 0
    high_findings = 0
    medium_findings = 0
    low_findings = 0

    for job in lfi_completed_jobs:
        if job["status"] == "completed" and "results" in job:
            results = job["results"]
            if "summary" in results:
                total_findings += results["summary"].get("total_findings", 0)
                high_findings += results["summary"].get("severity", {}).get("high", 0)
                medium_findings += results["summary"].get("severity", {}).get("medium", 0)
                low_findings += results["summary"].get("severity", {}).get("low", 0)

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
    LOGGER.info("=" * 60)
    LOGGER.info("Integrated web server starting")
    LOGGER.info("Web Interface: http://localhost:%s", port)
    LOGGER.info("API Endpoint: http://localhost:%s/api", port)
    LOGGER.info("Results Directory: %s", RESULTS_DIR.absolute())
    LOGGER.warning("Only scan domains you own or have permission to test")
    app.run(host=host, port=port, debug=debug, threaded=True)
    return

    LOGGER.info("=" * 60)
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
    if not CONFIG_PATH.exists():
        LOGGER.warning("config.json not found")
        LOGGER.warning("Run 'python setup.py' first to create configuration")
        sys.exit(1)

    if False and not Path("config.json").exists():
        print("⚠️  Warning: config.json not found!")
        print("Run 'python setup.py' first to create configuration.\n")
        sys.exit(1)

    try:
        run_web_server(host=args.host, port=args.port, debug=args.debug)
    except KeyboardInterrupt:
        LOGGER.info("Shutting down server")
        LOGGER.info("Goodbye")
        raise SystemExit(0)
        print("\n\nShutting down server...")
        print("Goodbye! 👋")
