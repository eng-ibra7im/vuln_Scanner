import json
import unittest

from helpers import MODEL_DIR  # noqa: F401

from config import Config
from sqli_scanner import SQLiDetectionOrchestrator


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


if __name__ == "__main__":
    unittest.main()
