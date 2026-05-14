import subprocess
import tempfile
import unittest
from pathlib import Path

from helpers import wait_for  # noqa: F401

from config import Config
from path_discovery import PathDiscoveryOrchestrator
from scan_services import ScanModuleService
from sqli_scanner import SQLiDetectionOrchestrator


class FailureScenarioTests(unittest.TestCase):
    def test_service_persists_failed_job(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            service = ScanModuleService(
                "xss",
                "target",
                database_path=Path(temp_dir) / "jobs.sqlite3",
            )
            job_id = service.start_job(
                target_value="https://example.com",
                runner=lambda progress, logger: (_ for _ in ()).throw(
                    TimeoutError("tool execution timeout")
                ),
            )

            def job_is_finished():
                job = service.get_job(job_id, include_results=False)
                if job and job["status"] != "running":
                    return job
                return None

            job = wait_for(job_is_finished)
            self.assertEqual(job["status"], "failed")
            self.assertIn("timeout", job["error"])

    def test_sqli_missing_tool_returns_failed_result(self):
        orchestrator = SQLiDetectionOrchestrator(Config.get_default())
        orchestrator._run_subprocess_sync = lambda command, timeout: (_ for _ in ()).throw(
            FileNotFoundError("sqlmap missing")
        )

        result = orchestrator.execute_tool(
            {
                "tool": "sqlmap",
                "command": ["sqlmap", "-u", "https://example.com/?id=1"],
                "timeout": 30,
            }
        )

        self.assertFalse(result.success)
        self.assertIn("not found", result.error.lower())

    def test_sqli_timeout_returns_failed_result(self):
        orchestrator = SQLiDetectionOrchestrator(Config.get_default())
        orchestrator._run_subprocess_sync = lambda command, timeout: (_ for _ in ()).throw(
            subprocess.TimeoutExpired(command, timeout)
        )

        result = orchestrator.execute_tool(
            {
                "tool": "sqlmap",
                "command": ["sqlmap", "-u", "https://example.com/?id=1"],
                "timeout": 30,
            }
        )

        self.assertFalse(result.success)
        self.assertIn("timed out", result.error.lower())

    def test_path_parser_tolerates_malformed_output(self):
        orchestrator = PathDiscoveryOrchestrator(Config.get_default())
        paths = orchestrator._parse_ffuf_output("not-json", "https://example.com")
        params = orchestrator._parse_paramspider_output("# comment only", "https://example.com")
        self.assertEqual(paths, [])
        self.assertEqual(params, [])


if __name__ == "__main__":
    unittest.main()
