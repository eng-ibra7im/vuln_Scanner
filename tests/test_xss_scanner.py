import asyncio
import json
import unittest
from unittest import mock

from helpers import MODEL_DIR  # noqa: F401

from config import Config
from xss_scanner import (
    XSSDetectionOrchestrator,
    XSSExecutionPlan,
    XSSToolResult,
)


class XSSParserTests(unittest.TestCase):
    def setUp(self):
        self.orchestrator = XSSDetectionOrchestrator(Config.get_default())

    def test_parse_dalfox_json_array(self):
        output = json.dumps(
            [
                {
                    "type": "V",
                    "data": "https://example.com/search?q=test",
                    "param": "q",
                    "evidence": "verified reflection",
                }
            ]
        )

        findings = self.orchestrator._parse_dalfox_output(
            output,
            "https://example.com/search?q=test",
            "reflected",
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["parameter"], "q")
        self.assertEqual(findings[0]["confidence"], "confirmed")

    def test_parse_nuclei_jsonl(self):
        output = json.dumps(
            {
                "template-id": "xss-dast-template",
                "matched-at": "https://example.com/profile?name=test",
                "fuzzing_parameter": "name",
                "info": {"severity": "high", "name": "Reflected XSS"},
                "extracted-results": ["<script>alert(1)</script>"],
            }
        )

        findings = self.orchestrator._parse_nuclei_output(output, "https://example.com")

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["parameter"], "name")
        self.assertEqual(findings[0]["severity"], "High")

    def test_parse_xsstrike_output(self):
        output = """
        [++] Vulnerable webpage: https://example.com/search?q=test
        [++] Vector for q: <svg/onload=alert(1)>
        """

        findings = self.orchestrator._parse_xsstrike_output(
            output,
            "https://example.com/search?q=test",
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["parameter"], "q")
        self.assertEqual(findings[0]["tool"], "xsstrike")

    def test_parse_malformed_output_returns_empty(self):
        findings = self.orchestrator._parse_dalfox_output(
            "not-json-and-no-finding",
            "https://example.com/search?q=test",
            "reflected",
        )
        self.assertEqual(findings, [])

    def test_generate_execution_plan_skips_missing_tools(self):
        with (
            mock.patch(
                "xss_scanner.get_tool_path",
                side_effect=lambda name: f"C:/tools/{name}.exe",
            ),
            mock.patch.object(
                self.orchestrator,
                "_tool_path_is_available",
                side_effect=lambda path: path.endswith("nuclei.exe"),
            ),
        ):
            plan = self.orchestrator.generate_execution_plan(
                "https://example.com/search?q=test"
            )

        self.assertEqual(plan["total_plans"], 1)
        self.assertEqual(plan["execution_plans"][0]["tool"], "nuclei")
        self.assertIn(
            "dast/vulnerabilities/xss/",
            plan["execution_plans"][0]["command"],
        )

    def test_generate_execution_plan_optimizes_dalfox_for_known_parameters(self):
        with (
            mock.patch(
                "xss_scanner.get_tool_path",
                side_effect=lambda name: f"C:/tools/{name}.exe",
            ),
            mock.patch.object(
                self.orchestrator,
                "_tool_path_is_available",
                return_value=True,
            ),
        ):
            plan = self.orchestrator.generate_execution_plan(
                "https://example.com/search?q=test"
            )

        dalfox_plan = next(
            item for item in plan["execution_plans"] if item["tool"] == "dalfox"
        )
        self.assertIn("--skip-discovery", dalfox_plan["command"])
        self.assertIn("--skip-mining-all", dalfox_plan["command"])
        self.assertIn("--skip-headless", dalfox_plan["command"])
        self.assertIn("--skip-bav", dalfox_plan["command"])
        self.assertIn("-p", dalfox_plan["command"])

    def test_execute_tool_marks_failed_process_as_unsuccessful(self):
        plan = XSSExecutionPlan(
            tool="xsstrike",
            command=["xsstrike", "-u", "https://example.com/search?q=test"],
            timeout=10,
            priority=1,
            description="XSStrike connectivity test",
            scan_type="reflected",
        )

        with (
            mock.patch("platform.system", return_value="Windows"),
            mock.patch.object(
                self.orchestrator,
                "_run_subprocess_sync",
                return_value={
                    "stdout": "[!!] Unable to connect to the target.\n",
                    "stderr": "Traceback (most recent call last):\nValueError: boom\n",
                    "returncode": 1,
                },
            ),
        ):
            result = asyncio.run(
                self.orchestrator.execute_tool(
                    plan,
                    "https://example.com/search?q=test",
                )
            )

        self.assertFalse(result.success)
        self.assertIn("Unable to connect to the target", result.error)
        self.assertIn("exit code 1", result.error)

    def test_scan_returns_warning_when_all_tools_fail(self):
        async def fake_execute_all(plans, target_url):
            return [
                XSSToolResult(
                    tool="xsstrike",
                    success=False,
                    findings=[],
                    execution_time=0.2,
                    error="Unable to connect to the target",
                )
            ]

        with (
            mock.patch.object(
                self.orchestrator,
                "generate_execution_plan",
                return_value={
                    "domain": "example.com",
                    "execution_plans": [
                        {
                            "tool": "xsstrike",
                            "command": ["xsstrike"],
                            "timeout": 10,
                            "priority": 1,
                            "description": "XSStrike test",
                            "scan_type": "reflected",
                        }
                    ],
                },
            ),
            mock.patch.object(
                self.orchestrator,
                "execute_all",
                side_effect=fake_execute_all,
            ),
        ):
            result = self.orchestrator.scan("https://example.com/search?q=test")

        self.assertEqual(result["summary"]["total_findings"], 0)
        self.assertEqual(result["summary"]["tools_failed"], 1)
        self.assertEqual(
            result["scan_info"]["status"],
            "completed_with_errors",
        )
        self.assertIn("All selected XSS tools failed or timed out", result["warnings"][0])


if __name__ == "__main__":
    unittest.main()
