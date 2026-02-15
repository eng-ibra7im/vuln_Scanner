#!/usr/bin/env python3
"""
Subdomain Enumeration Orchestrator
Academic Security Research Tool

This orchestrator generates execution plans for subdomain discovery tools,
coordinates their execution, and produces structured JSON output.
"""

import json
import subprocess
import asyncio
import time
from datetime import datetime
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from pathlib import Path
import logging

from config import Config
from analyzer import SubdomainAnalyzer
from formatter import ResultFormatter


@dataclass
class ExecutionPlan:
    """Represents an execution plan for subdomain enumeration"""

    tool: str
    command: List[str]
    timeout: int
    priority: int
    description: str


@dataclass
class ToolResult:
    """Represents the result from a single tool execution"""

    tool: str
    success: bool
    subdomains: List[str]
    execution_time: float
    error: Optional[str] = None
    raw_output: Optional[str] = None


class SubdomainOrchestrator:
    """
    Orchestrates subdomain enumeration across multiple tools.
    Generates execution plans, coordinates tool execution, and formats results.
    """

    def __init__(self, config: Config):
        self.config = config
        self.analyzer = SubdomainAnalyzer()
        self.formatter = ResultFormatter()
        self.logger = self._setup_logging()
        self._api_fallback_enabled = config.use_api_fallback

    def _setup_logging(self) -> logging.Logger:
        """Configure logging for the orchestrator"""
        logger = logging.getLogger("SubdomainOrchestrator")
        logger.setLevel(logging.INFO)

        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

        return logger

    def generate_execution_plan(self, target_domain: str) -> List[ExecutionPlan]:
        """
        Generate execution plans for all configured tools.

        Args:
            target_domain: The target domain to enumerate

        Returns:
            List of ExecutionPlan objects sorted by priority
        """
        plans = []

        # Subfinder - Fast passive subdomain enumeration
        if self.config.tools.get("subfinder", {}).get("enabled", False):
            plans.append(
                ExecutionPlan(
                    tool="subfinder",
                    command=["subfinder", "-d", target_domain, "-silent", "-all"],
                    timeout=300,
                    priority=1,
                    description="Passive subdomain discovery using multiple sources",
                )
            )

        # Amass - Comprehensive enumeration
        if self.config.tools.get("amass", {}).get("enabled", False):
            amass_mode = self.config.tools["amass"].get("mode", "passive")
            # amass v4.2+: -passive is deprecated (passive is the default)
            cmd = ["amass", "enum", "-d", target_domain, "-timeout", "5"]
            if amass_mode == "active":
                cmd.append("-active")
            plans.append(
                ExecutionPlan(
                    tool="amass",
                    command=cmd,
                    timeout=600,
                    priority=2,
                    description="In-depth subdomain enumeration with Amass",
                )
            )

        # Sublist3r - Multi-source enumeration
        if self.config.tools.get("sublist3r", {}).get("enabled", False):
            plans.append(
                ExecutionPlan(
                    tool="sublist3r",
                    command=[
                        "python",
                        "-m",
                        "sublist3r",
                        "-d",
                        target_domain,
                        "-o",
                        "-",
                    ],
                    timeout=300,
                    priority=3,
                    description="Subdomain discovery using search engines and DNS",
                )
            )

        # Assetfinder - Fast passive discovery
        if self.config.tools.get("assetfinder", {}).get("enabled", False):
            plans.append(
                ExecutionPlan(
                    tool="assetfinder",
                    command=["assetfinder", "--subs-only", target_domain],
                    timeout=180,
                    priority=1,
                    description="Quick passive subdomain discovery",
                )
            )

        # ffuf - DNS brute forcing
        if self.config.tools.get("ffuf", {}).get("enabled", False):
            wordlist = self.config.tools["ffuf"].get("wordlist", "dns_wordlist.txt")
            # Resolve wordlist path relative to this script's directory
            wordlist_path = Path(wordlist)
            if not wordlist_path.is_absolute():
                wordlist_path = Path(__file__).parent / wordlist
            if wordlist_path.exists():
                plans.append(
                    ExecutionPlan(
                        tool="ffuf",
                        command=[
                            "ffuf",
                            "-w",
                            str(wordlist_path),
                            "-u",
                            f"http://FUZZ.{target_domain}",
                            "-mc",
                            "200,301,302,403",
                            "-fs",
                            "0",
                            "-t",
                            "50",
                            "-json",
                            "-noninteractive",
                            "-ic",
                        ],
                        timeout=900,
                        priority=4,
                        description="DNS brute forcing with wordlist",
                    )
                )
            else:
                self.logger.warning(f"FFUF wordlist not found: {wordlist_path}")

        # Sort by priority
        plans.sort(key=lambda x: x.priority)

        self.logger.info(f"Generated {len(plans)} execution plans for {target_domain}")
        for plan in plans:
            self.logger.info(f"  [{plan.priority}] {plan.tool}: {plan.description}")

        return plans

    def _run_subprocess_sync(self, command, timeout):
        """Run subprocess synchronously (Windows compatible)"""
        import sys

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                creationflags=(
                    subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
                ),
            )
            return result
        except subprocess.TimeoutExpired:
            return None
        except Exception as e:
            raise e

    async def execute_tool(self, plan: ExecutionPlan) -> ToolResult:
        """
        Execute a single tool according to its execution plan.

        Args:
            plan: ExecutionPlan to execute

        Returns:
            ToolResult containing the execution results
        """
        self.logger.info(f"Executing {plan.tool}...")
        start_time = time.time()

        try:
            # Check if tool exists first
            import shutil

            tool_executable = plan.command[0]
            if not shutil.which(tool_executable) and tool_executable not in ["python"]:
                # Tool not found - use API fallback for supported tools
                execution_time = time.time() - start_time
                self.logger.warning(f"{plan.tool} not found - tool not installed")

                # Try API fallback if available
                if (
                    hasattr(self, "_api_fallback_enabled")
                    and self._api_fallback_enabled
                ):
                    self.logger.info(f"Trying API fallback for {plan.tool}...")
                    return await self._api_fallback(plan)

                return ToolResult(
                    tool=plan.tool,
                    success=False,
                    subdomains=[],
                    execution_time=execution_time,
                    error=f"Tool not installed: {tool_executable}. Run install_tools.ps1 or use API mode.",
                )

            # Execute the command with subprocess.run via asyncio.to_thread (Windows compatible)
            self.logger.info(f"Running command: {' '.join(plan.command)}")
            result = await asyncio.to_thread(
                self._run_subprocess_sync, plan.command, plan.timeout
            )

            if result is None:
                execution_time = time.time() - start_time
                self.logger.warning(f"{plan.tool} timed out after {plan.timeout}s")
                return ToolResult(
                    tool=plan.tool,
                    success=False,
                    subdomains=[],
                    execution_time=execution_time,
                    error=f"Timeout after {plan.timeout} seconds",
                )

            execution_time = time.time() - start_time

            # Parse output
            raw_output = result.stdout or ""
            stderr_output = result.stderr or ""
            self.logger.info(
                f"{plan.tool} stdout length: {len(raw_output)}, stderr length: {len(stderr_output)}"
            )
            if raw_output:
                self.logger.info(f"{plan.tool} stdout preview: {raw_output[:500]}")

            subdomains = self._parse_tool_output(plan.tool, raw_output, stderr_output)

            success = len(subdomains) > 0 or result.returncode == 0

            self.logger.info(
                f"{plan.tool} completed in {execution_time:.2f}s - Found {len(subdomains)} subdomains"
            )

            return ToolResult(
                tool=plan.tool,
                success=success,
                subdomains=subdomains,
                execution_time=execution_time,
                error=stderr_output if not success and stderr_output else None,
                raw_output=raw_output if self.config.save_raw_output else None,
            )

        except FileNotFoundError:
            execution_time = time.time() - start_time
            self.logger.error(f"{plan.tool} not found - is it installed?")
            return ToolResult(
                tool=plan.tool,
                success=False,
                subdomains=[],
                execution_time=execution_time,
                error=f"Tool not found: {plan.tool}",
            )
        except Exception as e:
            execution_time = time.time() - start_time
            self.logger.error(f"Error executing {plan.tool}: {str(e)}")
            return ToolResult(
                tool=plan.tool,
                success=False,
                subdomains=[],
                execution_time=execution_time,
                error=str(e),
            )

    def _parse_tool_output(self, tool: str, output: str, stderr: str = "") -> List[str]:
        """
        Parse tool output to extract subdomains.

        Args:
            tool: Name of the tool
            output: Raw stdout from the tool
            stderr: Raw stderr from the tool

        Returns:
            List of discovered subdomains
        """
        subdomains = []
        import re

        if tool == "ffuf":
            # ffuf with -json flag outputs NDJSON (one JSON object per line)
            for line in output.strip().split("\n"):
                line = line.strip()
                if not line or not line.startswith("{"):
                    continue
                try:
                    data = json.loads(line)
                    # Extract host from ffuf JSON result
                    host = data.get("host", "")
                    if host and "." in host:
                        subdomains.append(host.lower())
                    elif "url" in data:
                        url = data["url"]
                        if "//" in url:
                            host = url.split("//")[1].split("/")[0]
                            if "." in host:
                                subdomains.append(host.lower())
                except (json.JSONDecodeError, KeyError):
                    pass

        elif tool == "amass":
            # amass v4.2+ verbose output format:
            # domain.com (FQDN) --> record_type --> target (Type)
            # Extract all FQDN entries
            combined = output + "\n" + stderr
            fqdn_pattern = re.compile(
                r"([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}"
            )
            for line in combined.strip().split("\n"):
                line = line.strip()
                if not line:
                    continue
                # Match FQDN entries from verbose output
                if "(FQDN)" in line:
                    # Extract domains marked as FQDN
                    parts = line.split("(FQDN)")
                    for part in parts:
                        part = part.strip().rstrip(" ->").strip()
                        # Get the last word (the domain)
                        words = part.split()
                        if words:
                            candidate = words[-1].strip()
                            if re.match(
                                r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$",
                                candidate,
                            ):
                                subdomains.append(candidate.lower())
                elif "." in line and " " not in line:
                    # Simple one-subdomain-per-line format (older versions)
                    subdomains.append(line.lower())

        else:
            # subfinder, assetfinder, sublist3r: one subdomain per line
            for line in output.strip().split("\n"):
                line = line.strip()
                if not line:
                    continue
                # Basic validation: should look like a domain
                if "." in line and " " not in line:
                    subdomains.append(line.lower())

        # Deduplicate while preserving order
        seen = set()
        unique = []
        for s in subdomains:
            if s not in seen:
                seen.add(s)
                unique.append(s)

        self.logger.info(f"{tool} parser extracted {len(unique)} unique subdomains")
        return unique

    async def execute_all(self, plans: List[ExecutionPlan]) -> List[ToolResult]:
        """
        Execute all plans (can be parallel or sequential based on config).

        Args:
            plans: List of ExecutionPlans to execute

        Returns:
            List of ToolResults
        """
        if self.config.parallel_execution:
            self.logger.info("Executing tools in parallel...")
            tasks = [self.execute_tool(plan) for plan in plans]
            results = await asyncio.gather(*tasks)
        else:
            self.logger.info("Executing tools sequentially...")
            results = []
            for plan in plans:
                result = await self.execute_tool(plan)
                results.append(result)

        return list(results)

    def orchestrate(self, target_domain: str) -> Dict[str, Any]:
        """
        Main orchestration method - generates plan, executes, analyzes, and formats results.

        Args:
            target_domain: The target domain to enumerate

        Returns:
            Structured JSON dictionary ready for dashboard
        """
        self.logger.info(f"Starting subdomain enumeration for: {target_domain}")
        start_time = time.time()

        # Validate domain
        if not self._validate_domain(target_domain):
            return self._error_response("Invalid domain format")

        # Generate execution plans
        plans = self.generate_execution_plan(target_domain)

        if not plans:
            return self._error_response("No tools enabled in configuration")

        # Execute all tools
        results = asyncio.run(self.execute_all(plans))

        # Analyze and aggregate results
        analyzed = self.analyzer.analyze(target_domain, results)

        # Format for dashboard
        total_time = time.time() - start_time
        formatted = self.formatter.format_output(
            target_domain=target_domain,
            tool_results=results,
            analyzed_results=analyzed,
            execution_time=total_time,
        )

        # Save results if configured
        if self.config.save_results:
            self._save_results(target_domain, formatted)

        self.logger.info(f"Enumeration complete in {total_time:.2f}s")
        self.logger.info(
            f"Total unique subdomains: {len(analyzed['unique_subdomains'])}"
        )

        return formatted

    async def _api_fallback(self, plan: ExecutionPlan) -> ToolResult:
        """
        Use API-based subdomain discovery as fallback when tools aren't installed
        """
        start_time = time.time()

        try:
            from api_finder import APISubdomainFinder

            # Extract domain from plan
            domain = None
            for i, arg in enumerate(plan.command):
                if arg in ["-d", "--domain"] and i + 1 < len(plan.command):
                    domain = plan.command[i + 1]
                    break

            if not domain:
                # Try to find domain in command
                for arg in plan.command:
                    if "." in arg and not arg.startswith("-"):
                        domain = arg
                        break

            if not domain:
                raise ValueError("Could not extract domain from execution plan")

            self.logger.info(f"Using API fallback for domain: {domain}")
            finder = APISubdomainFinder()
            subdomains = finder.find_subdomains(domain)

            execution_time = time.time() - start_time

            return ToolResult(
                tool=f"{plan.tool}_api",
                success=True,
                subdomains=list(subdomains),
                execution_time=execution_time,
                error=None,
                raw_output=f"API-based discovery found {len(subdomains)} subdomains",
            )

        except Exception as e:
            execution_time = time.time() - start_time
            self.logger.error(f"API fallback failed: {str(e)}")
            return ToolResult(
                tool=f"{plan.tool}_api",
                success=False,
                subdomains=[],
                execution_time=execution_time,
                error=f"API fallback error: {str(e)}",
            )

    def _validate_domain(self, domain: str) -> bool:
        """Basic domain validation"""
        import re

        pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
        return bool(re.match(pattern, domain))

    def _error_response(self, message: str) -> Dict[str, Any]:
        """Generate standardized error response"""
        return {
            "success": False,
            "error": message,
            "timestamp": datetime.utcnow().isoformat(),
            "results": None,
        }

    def _save_results(self, target_domain: str, results: Dict[str, Any]):
        """Save results to file"""
        output_dir = Path(self.config.output_directory)
        output_dir.mkdir(exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{target_domain.replace('.', '_')}_{timestamp}.json"
        filepath = output_dir / filename

        with open(filepath, "w") as f:
            json.dump(results, f, indent=2)

        self.logger.info(f"Results saved to: {filepath}")


def main():
    """Main entry point for the orchestrator"""
    import sys

    # Load configuration
    config = Config.load("config.json")

    # Get target domain
    if len(sys.argv) < 2:
        print("Usage: python orchestrator.py <target_domain>")
        print("Example: python orchestrator.py example.com")
        sys.exit(1)

    target_domain = sys.argv[1]

    # Create orchestrator and run
    orchestrator = SubdomainOrchestrator(config)
    results = orchestrator.orchestrate(target_domain)

    # Output JSON
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
