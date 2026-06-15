import json
import unittest
from unittest import mock

from helpers import MODEL_DIR  # noqa: F401

from config import Config
from sqli_scanner import SQLiDetectionOrchestrator, SQLiToolResult


class SQLiParserTests(unittest.TestCase):
    def setUp(self):
        self.orchestrator = SQLiDetectionOrchestrator(Config.get_default())

    def test_parse_sqlmap_output(self):
        output = """
        sqlmap identified the following injection point(s) with a total of 10 HTTP(s) requests:
        ---
        Parameter: id (GET)
            Type: boolean-based blind
            Title: AND boolean-based blind - WHERE or HAVING clause
            Payload: id=1 AND 1=1
        """

        findings = self.orchestrator._parse_sqlmap_output(output, "")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["parameter"], "id")
        self.assertEqual(findings[0]["confidence"], "confirmed")

    def test_parse_nuclei_output(self):
        output = json.dumps(
            {
                "template-id": "dast-sqli-template",
                "matched-at": "https://example.com/product?id=1",
                "fuzzing_parameter": "id",
                "info": {"severity": "critical", "description": "SQL injection"},
                "extractor-name": "mysql",
                "extracted-results": ["SQL syntax error"],
            }
        )

        findings = self.orchestrator._parse_nuclei_output(output)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["parameter"], "id")
        self.assertEqual(findings[0]["severity"], "Critical")

    def test_parse_ghauri_output(self):
        output = """
        Ghauri identified the following injection point(s)
        ---
        Parameter: page (GET)
            Type: time-based blind
            Title: MySQL >= 5.0.12 time-based blind
            Payload: page=1 AND SLEEP(5)
        """

        findings = self.orchestrator._parse_ghauri_output("", output)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["parameter"], "page")
        self.assertEqual(findings[0]["tool"], "ghauri")

    def test_parse_malformed_nuclei_output_returns_empty(self):
        findings = self.orchestrator._parse_nuclei_output("not-json")
        self.assertEqual(findings, [])

    def test_generate_execution_plan_uses_configured_templates_and_ghauri_timeout(self):
        plan = self.orchestrator.generate_execution_plan(
            "https://example.com/login?id=1",
            tools=["nuclei", "ghauri"],
            intensity="basic",
        )

        commands = {item["tool"]: item["command"] for item in plan["execution_plans"]}
        self.assertIn("dast/vulnerabilities/sqli/", commands["nuclei"])
        self.assertIn(
            "http/vulnerabilities/generic/error-based-sql-injection.yaml",
            commands["nuclei"],
        )
        self.assertIn("--timeout", commands["ghauri"])
        self.assertIn("30", commands["ghauri"])

    def test_execute_tool_marks_failed_process_as_unsuccessful(self):
        plan = {
            "tool": "ghauri",
            "command": ["ghauri", "-u", "https://example.com/login?id=1"],
            "timeout": 10,
        }

        with mock.patch.object(
            self.orchestrator,
            "_run_subprocess_sync",
            return_value={
                "stdout": "",
                "stderr": "[CRITICAL] target URL is not reachable\n",
                "returncode": 1,
            },
        ):
            result = self.orchestrator.execute_tool(plan)

        self.assertFalse(result.success)
        self.assertIn("target URL is not reachable", result.error)
        self.assertIn("exit code 1", result.error)

    def test_scan_raises_when_all_tools_fail(self):
        with (
            mock.patch.object(
                self.orchestrator,
                "generate_execution_plan",
                return_value={
                    "success": True,
                    "domain": "example.com",
                    "parameters": ["id"],
                    "execution_plans": [
                        {
                            "tool": "sqlmap",
                            "command": ["sqlmap"],
                            "timeout": 10,
                            "priority": 1,
                            "description": "SQLMap test",
                            "injection_types": ["error-based"],
                        }
                    ],
                },
            ),
            mock.patch.object(
                self.orchestrator,
                "execute_tool",
                return_value=SQLiToolResult(
                    tool="sqlmap",
                    success=False,
                    findings=[],
                    execution_time=0.3,
                    error="connection failed",
                ),
            ),
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "No SQL injection tools completed successfully",
            ):
                self.orchestrator.scan("https://example.com/login?id=1")


if __name__ == "__main__":
    unittest.main()
