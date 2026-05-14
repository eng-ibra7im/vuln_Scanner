import json
import unittest

from helpers import MODEL_DIR  # noqa: F401

from config import Config
from xss_scanner import XSSDetectionOrchestrator


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


if __name__ == "__main__":
    unittest.main()
