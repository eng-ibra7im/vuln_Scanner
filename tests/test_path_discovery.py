import json
import unittest

from helpers import MODEL_DIR  # noqa: F401

from config import Config
from path_discovery import PathDiscoveryOrchestrator


class PathDiscoveryParserTests(unittest.TestCase):
    def setUp(self):
        self.orchestrator = PathDiscoveryOrchestrator(Config.get_default())

    def test_parse_ffuf_output(self):
        output = json.dumps(
            {
                "url": "https://example.com/admin",
                "status": 200,
                "length": 321,
                "content-type": "text/html",
            }
        )

        paths = self.orchestrator._parse_ffuf_output(output, "https://example.com")
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0]["path"], "/admin")

    def test_parse_dirsearch_output(self):
        output = "[13:21:01] 200 - 307B - https://example.com/file.xml"
        paths = self.orchestrator._parse_dirsearch_output(output, "https://example.com")
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0]["status_code"], 200)

    def test_parse_arjun_output_prefers_file_json(self):
        file_output = json.dumps(
            {
                "https://example.com/search": {
                    "method": "GET",
                    "params": ["q", "page"],
                }
            }
        )
        parameters = self.orchestrator._parse_arjun_output(
            "",
            "https://example.com/search",
            file_output,
        )
        self.assertEqual({param["parameter"] for param in parameters}, {"q", "page"})

    def test_parse_paramspider_output(self):
        output = "https://example.com/search?q=test&page=1"
        parameters = self.orchestrator._parse_paramspider_output(
            output,
            "https://example.com/search",
        )
        self.assertEqual(len(parameters), 2)


if __name__ == "__main__":
    unittest.main()
