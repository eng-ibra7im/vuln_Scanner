import sys
import unittest
from unittest.mock import patch

from helpers import ROOT_DIR  # noqa: F401

from config import Config
from orchestrator import SubdomainOrchestrator


class SubdomainOrchestratorTests(unittest.TestCase):
    def test_generate_execution_plan_uses_resolved_executables(self):
        config = Config.get_default()
        config.tools["subfinder"]["enabled"] = True
        config.tools["amass"]["enabled"] = True
        config.tools["assetfinder"]["enabled"] = True
        config.tools["sublist3r"]["enabled"] = True
        config.tools["ffuf"]["enabled"] = True

        resolved_paths = {
            "subfinder": r"C:\tools\subfinder.exe",
            "amass": r"C:\tools\amass.exe",
            "assetfinder": r"C:\tools\assetfinder.exe",
            "sublist3r": r"C:\tools\sublist3r.exe",
            "ffuf": r"C:\tools\ffuf.exe",
        }

        with patch("orchestrator.resolve_tool_path", side_effect=resolved_paths.__getitem__):
            plans = SubdomainOrchestrator(config).generate_execution_plan("example.com")

        commands = {plan.tool: plan.command for plan in plans}
        self.assertEqual(commands["subfinder"][0], resolved_paths["subfinder"])
        self.assertEqual(commands["amass"][0], resolved_paths["amass"])
        self.assertEqual(commands["assetfinder"][0], resolved_paths["assetfinder"])
        self.assertEqual(commands["sublist3r"][0], resolved_paths["sublist3r"])
        self.assertEqual(commands["ffuf"][0], resolved_paths["ffuf"])
        self.assertIn("-e", commands["sublist3r"])
        self.assertNotIn("dnsdumpster", commands["sublist3r"])

    def test_build_tool_command_uses_python_for_script_tools(self):
        orchestrator = SubdomainOrchestrator(Config.get_default())

        with patch("orchestrator.resolve_tool_path", return_value=r"C:\tools\sublist3r.py"):
            command = orchestrator._build_tool_command("sublist3r", ["-d", "example.com"])

        self.assertEqual(command[0], sys.executable)
        self.assertEqual(command[1], r"C:\tools\sublist3r.py")
        self.assertEqual(command[2:], ["-d", "example.com"])

    def test_parse_tool_output_filters_non_subdomains(self):
        orchestrator = SubdomainOrchestrator(Config.get_default())
        output = "\n".join(
            [
                "www.example.com",
                "example.com",
                "subjectname@example.com",
                "m.testexample.com",
                "https://api.example.com/path",
                "*.dev.example.com",
            ]
        )

        parsed = orchestrator._parse_tool_output("assetfinder", output, "", "example.com")

        self.assertEqual(
            parsed,
            ["www.example.com", "api.example.com", "dev.example.com"],
        )
