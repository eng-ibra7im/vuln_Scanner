import json
import unittest

from helpers import MODEL_DIR  # noqa: F401

from config import Config
from lfi_scanner import LFIOrchestrator


class LFIParserTests(unittest.TestCase):
    def setUp(self):
        self.orchestrator = LFIOrchestrator(Config.get_default())

    def test_parse_ffuf_output(self):
        output = json.dumps(
            {
                "url": "https://example.com/view.php?file=../../etc/passwd",
                "status": 200,
                "length": 512,
                "words": 45,
                "input": {"FUZZ": "../../etc/passwd"},
            }
        )

        findings, params_tested, payloads_tested = self.orchestrator._parse_tool_output(
            "ffuf",
            output,
            "",
            {"parameter": "file", "url": "https://example.com/view.php?file=index.php"},
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(params_tested, 1)
        self.assertEqual(payloads_tested, 1)

    def test_parse_dotdotpwn_output(self):
        findings, _, payloads_tested = self.orchestrator._parse_tool_output(
            "dotdotpwn",
            "VULNERABLE: traversal detected",
            "",
            {"parameter": "page", "url": "https://example.com/index.php?page=home"},
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(payloads_tested, 1)

    def test_parse_malformed_output_returns_empty(self):
        findings, params_tested, payloads_tested = self.orchestrator._parse_tool_output(
            "ffuf",
            "not-json",
            "",
            {"parameter": "file", "url": "https://example.com/view.php?file=index.php"},
        )

        self.assertEqual(findings, [])
        self.assertEqual(params_tested, 1)
        self.assertEqual(payloads_tested, 0)


if __name__ == "__main__":
    unittest.main()
