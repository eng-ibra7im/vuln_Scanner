import tempfile
import unittest
from pathlib import Path

from helpers import ROOT_DIR, wait_for  # noqa: F401

import tooling
import web_server
from config import Config
from scan_services import ScanModuleService


MODULE_FIELDS = {
    "subdomains": "domain",
    "paths": "target",
    "xss": "target",
    "sqli": "target",
    "lfi": "target",
}


def sample_subdomain_result():
    return {
        "success": True,
        "metadata": {
            "target_domain": "example.com",
            "scan_timestamp": "2026-05-15T00:00:00+00:00",
            "execution_time_seconds": 1.2,
        },
        "summary": {
            "total_subdomains": 1,
            "validated_subdomains": 1,
            "validation_rate_percent": 100,
            "high_priority_count": 1,
            "tools_executed": 1,
            "tools_successful": 1,
        },
        "subdomains": [
            {
                "subdomain": "admin.example.com",
                "priority": "high",
                "priority_score": 25,
                "status": "active",
                "dns_records": {"validated": True, "ip_addresses": ["127.0.0.1"]},
                "classifications": ["admin"],
            }
        ],
        "statistics": {},
        "patterns": {},
        "tool_performance": [
            {
                "tool_name": "subfinder",
                "status": "success",
                "execution_time_seconds": 1.2,
                "subdomains_found": 1,
                "error": None,
            }
        ],
        "tool_coverage": {},
        "recommendations": [],
    }


def sample_xss_result():
    return {
        "scan_info": {
            "target": "https://example.com/search?q=test",
            "domain": "example.com",
            "scan_time": "2026-05-15T00:00:00+00:00",
            "total_execution_time": 2.5,
            "tools_used": ["dalfox"],
        },
        "summary": {
            "total_findings": 1,
            "critical": 0,
            "high": 1,
            "medium": 0,
            "low": 0,
            "by_type": {"reflected": 1},
        },
        "tool_results": {
            "dalfox": {
                "success": True,
                "findings_count": 1,
                "execution_time": 2.5,
                "error": None,
            }
        },
        "findings": [
            {
                "url": "https://example.com/search?q=test",
                "parameter": "q",
                "vulnerability_type": "reflected",
                "severity": "High",
                "confidence": "confirmed",
                "tool": "dalfox",
                "evidence": "verified reflection",
            }
        ],
    }


class WebServerApiTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "jobs.sqlite3"
        self.results_dir = Path(self.temp_dir.name) / "results"

        self.config = Config.get_default()
        self.config.output_directory = str(self.results_dir)
        self.config.database_path = str(self.db_path)
        self.config.dashboard_auth = {"enabled": False}
        self.config.rate_limit = {"enabled": False}

        self.original_get_runtime_config = web_server.get_runtime_config
        web_server.get_runtime_config = lambda: self.config

        self.original_services = {
            "subdomain_scan_service": web_server.subdomain_scan_service,
            "path_scan_service": web_server.path_scan_service,
            "xss_scan_service": web_server.xss_scan_service,
            "sqli_scan_service": web_server.sqli_scan_service,
            "lfi_scan_service": web_server.lfi_scan_service,
            "SCAN_SERVICES": web_server.SCAN_SERVICES,
        }

        services = {
            module_name: ScanModuleService(
                module_name,
                target_field,
                database_path=self.db_path,
            )
            for module_name, target_field in MODULE_FIELDS.items()
        }
        web_server.subdomain_scan_service = services["subdomains"]
        web_server.path_scan_service = services["paths"]
        web_server.xss_scan_service = services["xss"]
        web_server.sqli_scan_service = services["sqli"]
        web_server.lfi_scan_service = services["lfi"]
        web_server.SCAN_SERVICES = services

        self.client = web_server.app.test_client()

    def tearDown(self):
        web_server.get_runtime_config = self.original_get_runtime_config
        web_server.subdomain_scan_service = self.original_services["subdomain_scan_service"]
        web_server.path_scan_service = self.original_services["path_scan_service"]
        web_server.xss_scan_service = self.original_services["xss_scan_service"]
        web_server.sqli_scan_service = self.original_services["sqli_scan_service"]
        web_server.lfi_scan_service = self.original_services["lfi_scan_service"]
        web_server.SCAN_SERVICES = self.original_services["SCAN_SERVICES"]
        self.temp_dir.cleanup()

    def _create_completed_job(self, module_name: str, target_value: str, raw_result: dict):
        service = web_server.SCAN_SERVICES[module_name]
        job_id = service.start_job(
            target_value=target_value,
            runner=lambda progress, logger: raw_result,
            initial_fields={"profile": "standard"},
        )

        def job_is_finished():
            job = service.get_job(job_id, include_results=True)
            if job and job["status"] != "running":
                return job
            return None

        wait_for(job_is_finished)
        return job_id

    def test_health_and_profile_endpoints(self):
        index_response = self.client.get("/")
        self.assertEqual(index_response.status_code, 200)

        css_response = self.client.get("/profile-overrides.css")
        self.assertEqual(css_response.status_code, 200)

        health_response = self.client.get("/api/health")
        self.assertEqual(health_response.status_code, 200)
        self.assertEqual(health_response.get_json()["status"], "healthy")

        profiles_response = self.client.get("/api/profiles")
        self.assertEqual(profiles_response.status_code, 200)
        self.assertTrue(profiles_response.get_json()["success"])

        tool_health_response = self.client.get("/api/tool-health")
        self.assertEqual(tool_health_response.status_code, 200)
        self.assertTrue(tool_health_response.get_json()["success"])

    def test_tools_endpoint_degrades_when_tool_probe_fails(self):
        self.config.tools = {
            "subfinder": {
                "enabled": True,
                "description": "Fast passive subdomain enumeration",
            }
        }
        original_build_tool_status = web_server.build_tool_status

        def failing_build_tool_status(tool_name, tool_config):
            raise RuntimeError(f"probe failed for {tool_name}")

        web_server.build_tool_status = failing_build_tool_status
        try:
            response = self.client.get("/api/tools")
        finally:
            web_server.build_tool_status = original_build_tool_status

        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["success"])
        self.assertEqual(payload["tools"][0]["status"], "error")
        self.assertIn("probe failed", payload["tools"][0]["error"])

    def test_tool_health_degrades_when_tool_probe_fails(self):
        self.config.xss_tools = {
            "dalfox": {
                "enabled": True,
                "description": "Parameter Analysis and XSS Scanning tool",
            }
        }
        original_build_tool_status = tooling.build_tool_status

        def failing_build_tool_status(tool_name, tool_config):
            raise RuntimeError(f"probe failed for {tool_name}")

        tooling.build_tool_status = failing_build_tool_status
        try:
            response = self.client.get("/api/tool-health")
        finally:
            tooling.build_tool_status = original_build_tool_status

        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["success"])
        self.assertIn("xss", payload["modules"])
        self.assertEqual(payload["modules"]["xss"][0]["status"], "error")
        self.assertIn("probe failed", payload["modules"]["xss"][0]["error"])

    def test_invalid_input_returns_400(self):
        response = self.client.post("/api/scan", json={"domain": "not a domain"})
        self.assertEqual(response.status_code, 400)

        xss_response = self.client.post("/api/xss/scan", json={"url": "not-a-url"})
        self.assertEqual(xss_response.status_code, 400)

    def test_subdomain_results_events_and_export(self):
        job_id = self._create_completed_job(
            "subdomains",
            "example.com",
            sample_subdomain_result(),
        )

        status_response = self.client.get(f"/api/scan/{job_id}")
        self.assertEqual(status_response.status_code, 200)
        self.assertEqual(status_response.get_json()["job"]["status"], "completed")

        results_response = self.client.get(f"/api/scan/{job_id}/results")
        self.assertEqual(results_response.status_code, 200)
        results = results_response.get_json()["results"]
        self.assertIn("scan_info", results)
        self.assertIn("comparison", results)
        self.assertEqual(results["summary"]["total_findings"], 1)

        events_response = self.client.get(f"/api/scan/{job_id}/events")
        self.assertEqual(events_response.status_code, 200)
        self.assertIn("event: completed", events_response.get_data(as_text=True))

        export_response = self.client.get(f"/api/scan/{job_id}/export?format=markdown")
        self.assertEqual(export_response.status_code, 200)
        self.assertTrue(export_response.get_json()["success"])

    def test_recommendation_summary_combines_modules(self):
        subdomain_job = self._create_completed_job(
            "subdomains",
            "example.com",
            sample_subdomain_result(),
        )
        xss_job = self._create_completed_job(
            "xss",
            "https://example.com/search?q=test",
            sample_xss_result(),
        )

        response = self.client.post(
            "/api/recommendations/summary",
            json={"job_ids": {"subdomains": subdomain_job, "xss": xss_job}},
        )
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["success"])
        self.assertIn("summary", payload)
        self.assertIn("recommendations", payload["summary"])


if __name__ == "__main__":
    unittest.main()
