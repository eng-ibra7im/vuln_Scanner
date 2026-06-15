#!/usr/bin/env python3
"""
XSS Detection Orchestrator
Academic Security Research Tool

This orchestrator generates execution plans for XSS detection tools,
coordinates their execution, analyzes results, and produces structured JSON output.

Tools supported:
- dalfox: Parameter Analysis and XSS Scanning tool
- nuclei: Fast vulnerability scanner with XSS templates
- xsstrike: Advanced XSS Detection Suite

Author: Security Research Team
Version: 1.0.0
"""

import json
import subprocess
import asyncio
import time
import re
import shutil
import sys
from datetime import datetime, UTC
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict, field
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode
import logging

from config import Config
from logging_utils import configure_logger
from tooling import resolve_tool_path


def get_tool_path(tool_name: str) -> str:
    """Backward-compatible wrapper around the shared tool resolver."""
    return resolve_tool_path(tool_name)


@dataclass
class XSSExecutionPlan:
    """Represents an execution plan for XSS detection"""

    tool: str
    command: List[str]
    timeout: int
    priority: int
    description: str
    scan_type: str  # 'reflected', 'stored', 'dom', 'blind'


@dataclass
class XSSFinding:
    """Represents a detected XSS vulnerability"""

    url: str
    parameter: str
    payload: str  # Detection payload (not exploitation)
    vulnerability_type: str  # 'reflected', 'stored', 'dom', 'blind'
    severity: str  # 'critical', 'high', 'medium', 'low', 'info'
    confidence: str  # 'confirmed', 'high', 'medium', 'low'
    detection_tool: str
    evidence: str
    remediation: str
    cwe_id: str = "CWE-79"
    cvss_score: float = 0.0
    notes: List[str] = field(default_factory=list)


@dataclass
class XSSToolResult:
    """Represents the result from a single tool execution"""

    tool: str
    success: bool
    findings: List[Dict[str, Any]]
    execution_time: float
    error: Optional[str] = None
    raw_output: Optional[str] = None


class XSSDetectionOrchestrator:
    """
    Orchestrates XSS detection across multiple tools.
    Generates execution plans, coordinates tool execution, analyzes and classifies results.
    """

    # XSS Type patterns for classification
    REFLECTED_INDICATORS = [
        r"reflected",
        r"parameter.*inject",
        r"input.*reflected",
        r"echo",
    ]

    DOM_INDICATORS = [
        r"dom.*based",
        r"document\.",
        r"innerHTML",
        r"eval\(",
        r"location\.",
        r"window\.",
    ]

    STORED_INDICATORS = [
        r"stored",
        r"persistent",
        r"database",
    ]

    # Severity mapping based on context
    SEVERITY_MAP = {
        "admin": "critical",
        "login": "critical",
        "auth": "critical",
        "payment": "critical",
        "user": "high",
        "profile": "high",
        "comment": "medium",
        "search": "medium",
        "default": "medium",
    }

    # Common remediation advice
    REMEDIATION_ADVICE = {
        "reflected": "Implement proper input validation and output encoding. Use Content-Security-Policy headers.",
        "stored": "Sanitize all user input before storage. Encode output when rendering. Implement CSP.",
        "dom": "Avoid using innerHTML with user input. Use textContent instead. Sanitize DOM manipulation.",
        "blind": "Implement strict CSP. Monitor for outbound connections. Validate all inputs server-side.",
    }

    def __init__(self, config: Config = None):
        self.config = config or Config()
        self.logger = self._setup_logging()
        self.findings: List[XSSFinding] = []

    def _setup_logging(self) -> logging.Logger:
        """Configure logging for the orchestrator"""
        return configure_logger("XSSDetectionOrchestrator", level=logging.DEBUG)

    def _tool_path_is_available(self, tool_path: str) -> bool:
        """Return whether a resolved tool path can actually be executed."""
        if not tool_path:
            return False
        if "\\" in tool_path or "/" in tool_path:
            return Path(tool_path).exists()
        return shutil.which(tool_path) is not None

    def _extract_tool_error(self, output: str) -> Optional[str]:
        """Extract a concise execution error from noisy tool output."""
        if not output:
            return None

        lowered = output.lower()
        if "traceback (most recent call last)" in lowered:
            return "Tool crashed with a Python traceback"

        for line in output.splitlines():
            cleaned = re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", line).strip()
            if not cleaned:
                continue

            lowered_line = cleaned.lower()
            if "unable to connect" in lowered_line:
                return "Unable to connect to the target"
            if "timed out" in lowered_line:
                return cleaned
            if any(
                marker in lowered_line
                for marker in [
                    "error",
                    "exception",
                    "failed",
                    "unable to",
                    "not found",
                    "no such file",
                    "permission denied",
                ]
            ):
                return cleaned

        return None

    def _build_execution_error(
        self,
        returncode: int,
        raw_output: str,
        stderr_output: str,
    ) -> Optional[str]:
        """Determine whether a tool execution should be treated as failed."""
        output_error = self._extract_tool_error(raw_output)
        stderr_error = self._extract_tool_error(stderr_output)

        if returncode == 0 and not output_error and not stderr_error:
            return None

        message = stderr_error or output_error
        if output_error and stderr_error == "Tool crashed with a Python traceback":
            message = output_error
        if message:
            if returncode not in {0, None}:
                return f"{message} (exit code {returncode})"
            return message

        if returncode == -1:
            return "Tool execution failed"

        if returncode != 0:
            return f"Tool exited with code {returncode}"

        return None

    def generate_execution_plan(
        self, target_url: str, params: List[str] = None
    ) -> Dict[str, Any]:
        """
        Generate execution plans for all configured XSS detection tools.

        Args:
            target_url: The target URL to scan
            params: Optional list of parameters to test

        Returns:
            Dictionary containing execution plans and metadata
        """
        # Normalize URL
        if not target_url.startswith(("http://", "https://")):
            target_url = f"https://{target_url}"

        parsed = urlparse(target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # Extract parameters from URL if not provided
        if not params:
            query_params = parse_qs(parsed.query)
            params = list(query_params.keys())

        plans = []
        xss_tools = self.config.get_xss_tools()

        # dalfox - Parameter Analysis and XSS Scanning
        if xss_tools.get("dalfox", {}).get("enabled", True):
            dalfox_path = get_tool_path("dalfox")
            if self._tool_path_is_available(dalfox_path):
                dalfox_command = [
                    dalfox_path,
                    "url",
                    target_url,
                    "--silence",
                    "--no-color",
                    "--format",
                    "json",
                    "--worker",
                    "6",
                    "--delay",
                    "25",
                    "--timeout",
                    "10",
                    "--skip-bav",
                    "--skip-headless",
                ]
                if params:
                    dalfox_command.append("--skip-discovery")
                    dalfox_command.append("--skip-mining-all")
                    for param in params:
                        dalfox_command.extend(["-p", param])
                plans.append(
                    XSSExecutionPlan(
                        tool="dalfox",
                        command=dalfox_command,
                        timeout=90,
                        priority=1,
                        description="Advanced parameter analysis and XSS detection",
                        scan_type="reflected",
                    )
                )

            # Note: Removed separate DOM scan as --dom flag not supported in this dalfox version

        # nuclei - XSS templates
        if xss_tools.get("nuclei", {}).get("enabled", True):
            nuclei_path = get_tool_path("nuclei")
            nuclei_templates = str(
                xss_tools.get("nuclei", {}).get("templates")
                or "dast/vulnerabilities/xss/"
            )
            if self._tool_path_is_available(nuclei_path):
                plans.append(
                    XSSExecutionPlan(
                        tool="nuclei",
                        command=[
                            nuclei_path,
                            "-u",
                            target_url,
                            "-dast",  # Enable DAST templates (disabled by default in Nuclei v3+)
                            "-t",
                            nuclei_templates,
                            "-tags",
                            "xss",
                            "-jsonl",  # JSON Lines output (v3+ uses -jsonl not -json)
                            "-silent",
                            "-nc",  # No color (v3+ uses -nc not -no-color)
                            "-timeout",
                            "30",
                            "-rl",
                            "100",
                        ],
                        timeout=120,
                        priority=1,
                        description="Template-based XSS vulnerability scanning",
                        scan_type="reflected",
                    )
                )

        # xsstrike - Advanced XSS Detection
        if xss_tools.get("xsstrike", {}).get("enabled", True):
            xsstrike_path = get_tool_path("xsstrike")
            if self._tool_path_is_available(xsstrike_path):
                plans.append(
                    XSSExecutionPlan(
                        tool="xsstrike",
                        command=[
                            xsstrike_path,
                            "-u",
                            target_url,
                            "--skip",  # Skip confirmation prompts
                            "--skip-dom",  # Skip DOM checking for faster scan
                            "--timeout",
                            "15",
                            "-t",
                            "3",  # Number of threads
                        ],
                        timeout=90,
                        priority=2,
                        description="Context-aware XSS detection against the supplied target URL",
                        scan_type="reflected",
                    )
                )

        # Sort by priority
        plans.sort(key=lambda x: x.priority)

        return {
            "target": target_url,
            "base_url": base_url,
            "domain": parsed.netloc,
            "parameters": params,
            "generated_at": datetime.now(UTC).isoformat(),
            "total_plans": len(plans),
            "execution_plans": [asdict(p) for p in plans],
        }

    def _run_subprocess_sync(self, command: List[str], timeout: int) -> Dict[str, Any]:
        """
        Run subprocess synchronously (for Windows compatibility).
        This runs in a thread pool via asyncio.to_thread().
        """
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                timeout=timeout,
                text=False,  # Get bytes
                creationflags=(
                    subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
                ),
            )
            return {
                "stdout": result.stdout.decode("utf-8", errors="ignore"),
                "stderr": result.stderr.decode("utf-8", errors="ignore"),
                "returncode": result.returncode,
            }
        except subprocess.TimeoutExpired:
            return {
                "stdout": "",
                "stderr": f"Command timed out after {timeout} seconds",
                "returncode": -1,
            }
        except Exception as e:
            return {"stdout": "", "stderr": str(e), "returncode": -1}

    async def execute_tool(
        self, plan: XSSExecutionPlan, target_url: str
    ) -> XSSToolResult:
        """
        Execute a single XSS detection tool based on execution plan.

        Args:
            plan: The execution plan to run
            target_url: Target URL for context

        Returns:
            XSSToolResult with findings
        """
        start_time = time.time()
        self.logger.info(f"[{plan.tool}] Starting: {plan.description}")

        try:
            # Use synchronous subprocess on Windows for better reliability
            import platform

            if platform.system() == "Windows":
                # Run subprocess synchronously in a thread pool
                self.logger.debug(
                    f"[{plan.tool}] Command: {' '.join(str(x) for x in plan.command)}"
                )

                # Use asyncio.to_thread to run blocking subprocess in thread pool
                result = await asyncio.to_thread(
                    self._run_subprocess_sync, plan.command, plan.timeout
                )

                raw_output = result["stdout"]
                stderr_output = result["stderr"]
                returncode = result["returncode"]

                if returncode != 0 and len(raw_output) == 0:
                    self.logger.warning(
                        f"[{plan.tool}] Non-zero exit code: {returncode}"
                    )
            else:
                # Use async subprocess on Unix
                process = await asyncio.create_subprocess_exec(
                    *plan.command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )

                try:
                    stdout, stderr = await asyncio.wait_for(
                        process.communicate(), timeout=plan.timeout
                    )
                except asyncio.TimeoutError:
                    process.kill()
                    await process.wait()
                    self.logger.warning(f"[{plan.tool}] Timeout after {plan.timeout}s")
                    return XSSToolResult(
                        tool=plan.tool,
                        success=False,
                        findings=[],
                        execution_time=time.time() - start_time,
                        error=f"Timeout after {plan.timeout} seconds",
                    )

                raw_output = stdout.decode("utf-8", errors="ignore")
                stderr_output = stderr.decode("utf-8", errors="ignore")
                returncode = process.returncode

            # Debug logging
            self.logger.debug(f"[{plan.tool}] stdout length: {len(raw_output)}")
            self.logger.debug(f"[{plan.tool}] stderr length: {len(stderr_output)}")
            if len(raw_output) > 0:
                self.logger.debug(f"[{plan.tool}] stdout preview: {raw_output[:200]}")
            if len(stderr_output) > 0:
                self.logger.warning(f"[{plan.tool}] stderr: {stderr_output[:500]}")

            # Parse results based on tool
            findings = self._parse_tool_output(
                plan.tool, raw_output, target_url, plan.scan_type
            )

            execution_time = time.time() - start_time
            execution_error = self._build_execution_error(
                returncode,
                raw_output,
                stderr_output,
            )

            if execution_error and not findings:
                self.logger.warning(f"[{plan.tool}] {execution_error}")
                return XSSToolResult(
                    tool=plan.tool,
                    success=False,
                    findings=[],
                    execution_time=execution_time,
                    error=execution_error,
                    raw_output=raw_output if self.config.save_raw_output else None,
                )

            self.logger.info(
                f"[{plan.tool}] Completed in {execution_time:.2f}s - Found {len(findings)} potential XSS"
            )

            return XSSToolResult(
                tool=plan.tool,
                success=True,
                findings=findings,
                execution_time=execution_time,
                raw_output=raw_output if self.config.save_raw_output else None,
            )

        except FileNotFoundError:
            self.logger.warning(f"[{plan.tool}] Tool not found, skipping...")
            return XSSToolResult(
                tool=plan.tool,
                success=False,
                findings=[],
                execution_time=time.time() - start_time,
                error=f"Tool '{plan.tool}' not installed",
            )
        except Exception as e:
            self.logger.error(f"[{plan.tool}] Error: {str(e)}")
            return XSSToolResult(
                tool=plan.tool,
                success=False,
                findings=[],
                execution_time=time.time() - start_time,
                error=str(e),
            )

    def _parse_tool_output(
        self, tool: str, output: str, target_url: str, scan_type: str
    ) -> List[Dict]:
        """
        Parse tool output into structured XSS findings.
        """
        findings = []

        if tool == "dalfox":
            findings = self._parse_dalfox_output(output, target_url, scan_type)
        elif tool == "nuclei":
            findings = self._parse_nuclei_output(output, target_url)
        elif tool == "xsstrike":
            findings = self._parse_xsstrike_output(output, target_url)

        return findings

    def _parse_dalfox_output(
        self, output: str, target_url: str, scan_type: str
    ) -> List[Dict]:
        """Parse dalfox JSON output"""
        findings = []

        # Try to parse as a JSON array first (dalfox with --format json outputs array)
        try:
            data_list = json.loads(output.strip())
            if isinstance(data_list, list):
                for data in data_list:
                    if not data:  # Skip empty objects
                        continue
                    finding = self._process_dalfox_entry(data, target_url, scan_type)
                    if finding:
                        findings.append(finding)
                return findings
        except json.JSONDecodeError:
            pass

        # Fall back to line-by-line parsing
        for line in output.strip().split("\n"):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                finding = self._process_dalfox_entry(data, target_url, scan_type)
                if finding:
                    findings.append(finding)
            except json.JSONDecodeError:
                # Try to parse non-JSON output
                if "POC" in line or "Vulnerable" in line.lower():
                    finding = self._parse_dalfox_text_line(line, target_url, scan_type)
                    if finding:
                        findings.append(finding)

        return findings

    def _process_dalfox_entry(
        self, data: Dict, target_url: str, scan_type: str
    ) -> Optional[Dict]:
        """Process a single dalfox output entry"""
        if not data:
            return None

        # Skip empty entries
        if not data.get("data") and not data.get("url"):
            return None

        # Determine vulnerability type from dalfox type field
        vuln_type = scan_type
        dalfox_type = data.get("type", "").upper()
        if dalfox_type == "V":  # Verified/Triggered XSS
            vuln_type = "verified"
        elif dalfox_type == "R":  # Reflected
            vuln_type = "reflected"
        elif "dom" in data.get("inject_type", "").lower():
            vuln_type = "dom"
        elif "stored" in dalfox_type.lower():
            vuln_type = "stored"

        # Get severity from dalfox or determine it
        severity = data.get("severity", "").lower()
        if severity not in ["critical", "high", "medium", "low"]:
            severity = self._determine_severity(
                data.get("data", target_url), data.get("param", "")
            )

        # Determine confidence based on type
        if dalfox_type == "V":
            confidence = "confirmed"  # Verified/Triggered = confirmed
        elif dalfox_type == "R":
            confidence = "high"  # Reflected = high confidence
        else:
            confidence = "medium"  # Default to medium

        return {
            "url": data.get("data", data.get("url", target_url)),
            "parameter": data.get("param", "unknown"),
            "payload": data.get("poc", data.get("payload", "N/A")),
            "xss_type": vuln_type,
            "vulnerability_type": vuln_type,
            "severity": severity.capitalize() if severity else "Medium",
            "confidence": confidence,
            "detection_tool": "dalfox",
            "tool": "dalfox",
            "evidence": data.get(
                "evidence", data.get("message_str", "Parameter reflects user input")
            )[:200],
            "remediation": self.REMEDIATION_ADVICE.get(
                vuln_type, self.REMEDIATION_ADVICE["reflected"]
            ),
            "cwe_id": data.get("cwe", "CWE-79"),
            "cvss_score": self._calculate_cvss(severity),
        }

        return findings

    def _parse_dalfox_text_line(
        self, line: str, target_url: str, scan_type: str
    ) -> Optional[Dict]:
        """Parse a single line of dalfox text output"""
        # Extract parameter if present
        param_match = re.search(r"param[:\s]+(\w+)", line, re.IGNORECASE)
        param = param_match.group(1) if param_match else "unknown"

        severity = self._determine_severity(target_url, param)

        return {
            "url": target_url,
            "parameter": param,
            "payload": line.strip() if "poc" in line.lower() or "payload" in line.lower() else "N/A",
            "xss_type": scan_type,
            "vulnerability_type": scan_type,
            "severity": (
                severity.capitalize() if isinstance(severity, str) else "Medium"
            ),
            "confidence": "medium",
            "detection_tool": "dalfox",
            "tool": "dalfox",
            "evidence": line.strip()[:200],
            "remediation": self.REMEDIATION_ADVICE.get(
                scan_type, self.REMEDIATION_ADVICE["reflected"]
            ),
            "cwe_id": "CWE-79",
            "cvss_score": self._calculate_cvss(severity),
        }

    def _parse_nuclei_output(self, output: str, target_url: str) -> List[Dict]:
        """Parse nuclei JSONL output"""
        findings = []

        for line in output.strip().split("\n"):
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                data = json.loads(line)

                # Extract template info
                template_id = data.get("template-id", "unknown")
                info = data.get("info", {})
                extracted = data.get("extracted-results", [])

                # Get parameter: prefer fuzzing_parameter from DAST output
                param = data.get("fuzzing_parameter", "")
                if not param:
                    param = data.get("matcher-name", "unknown")

                # Determine XSS type from template
                vuln_type = "reflected"
                if "dom" in template_id.lower():
                    vuln_type = "dom"
                elif "stored" in template_id.lower():
                    vuln_type = "stored"

                severity = info.get("severity", "medium").lower()
                if severity not in ["critical", "high", "medium", "low", "info"]:
                    severity = "medium"

                # Build evidence
                evidence = (
                    f"Template: {template_id} - {info.get('name', 'XSS Detected')}"
                )
                if extracted:
                    evidence += f" | Extracted: {'; '.join(str(e)[:100] for e in extracted[:3])}"

                finding = {
                    "url": data.get("matched-at", target_url),
                    "parameter": param,
                    "payload": (
                        str(extracted[0])[:300]
                        if extracted
                        else data.get("curl-command", "[Nuclei DAST detection]")[:300]
                    ),
                    "xss_type": vuln_type,
                    "vulnerability_type": vuln_type,
                    "severity": severity.capitalize() if severity else "Medium",
                    "confidence": "high",  # Nuclei templates are reliable
                    "detection_tool": "nuclei",
                    "tool": "nuclei",
                    "evidence": evidence,
                    "remediation": info.get(
                        "remediation", self.REMEDIATION_ADVICE.get(vuln_type)
                    ),
                    "cwe_id": "CWE-79",
                    "cvss_score": self._calculate_cvss(severity),
                    "reference": info.get("reference", []),
                }
                findings.append(finding)
            except json.JSONDecodeError:
                continue

        return findings

    def _parse_xsstrike_output(self, output: str, target_url: str) -> List[Dict]:
        """Parse xsstrike output"""
        findings = []
        current_vuln_url = target_url
        lines = output.split("\n")

        for i, line in enumerate(lines):
            stripped = line.strip()

            # Pattern 1: "[++] Vulnerable webpage: <url>"
            vuln_page = re.search(
                r"\[\+\+\]\s*Vulnerable\s+webpage:\s*(\S+)", stripped, re.I
            )
            if vuln_page:
                current_vuln_url = vuln_page.group(1)
                continue

            # Pattern 2: "[++] Vector for <param>: <payload>" - the main finding
            vector_match = re.search(
                r"\[\+\+\]\s*Vector\s+for\s+(\w+):\s*(.+)", stripped, re.I
            )
            if vector_match:
                param = vector_match.group(1)
                payload = vector_match.group(2).strip()
                severity = self._determine_severity(current_vuln_url, param)

                finding = {
                    "url": current_vuln_url,
                    "parameter": param,
                    "payload": payload[:300],
                    "xss_type": "reflected",
                    "vulnerability_type": "reflected",
                    "severity": (
                        severity.capitalize() if isinstance(severity, str) else "Medium"
                    ),
                    "confidence": "high",
                    "detection_tool": "xsstrike",
                    "tool": "xsstrike",
                    "evidence": f"XSStrike found XSS vector for parameter '{param}' with payload: {payload[:100]}",
                    "remediation": self.REMEDIATION_ADVICE.get(
                        "reflected", "Sanitize user input and encode output"
                    ),
                    "cwe_id": "CWE-79",
                    "cvss_score": self._calculate_cvss(severity),
                }
                findings.append(finding)
                continue

            # Pattern 3: Reflection found with context (older XSStrike versions)
            reflection_match = re.search(
                r"Reflection\s+found.*?parameter\s*['\"]?(\w+)", stripped, re.I
            )
            if reflection_match:
                # Just a note - actual finding comes from Vector lines
                continue

            # Pattern 4: Legacy format - "Vulnerable: ..."
            legacy_match = re.search(r"Vulnerable:\s*(.+)", stripped, re.I)
            if legacy_match:
                param = legacy_match.group(1).strip()
                severity = self._determine_severity(target_url, param)
                finding = {
                    "url": target_url,
                    "parameter": param,
                    "payload": "N/A",
                    "xss_type": "reflected",
                    "vulnerability_type": "reflected",
                    "severity": (
                        severity.capitalize() if isinstance(severity, str) else "Medium"
                    ),
                    "confidence": "medium",
                    "detection_tool": "xsstrike",
                    "tool": "xsstrike",
                    "evidence": stripped[:200],
                    "remediation": self.REMEDIATION_ADVICE.get(
                        "reflected", "Sanitize user input and encode output"
                    ),
                    "cwe_id": "CWE-79",
                    "cvss_score": self._calculate_cvss(severity),
                }
                findings.append(finding)

        return findings

    def _determine_severity(self, url: str, parameter: str) -> str:
        """Determine severity based on URL context and parameter"""
        url_lower = url.lower()
        param_lower = parameter.lower()

        for keyword, severity in self.SEVERITY_MAP.items():
            if keyword in url_lower or keyword in param_lower:
                return severity

        return self.SEVERITY_MAP["default"]

    def _determine_confidence(self, data: Dict) -> str:
        """Determine confidence level from tool data"""
        if data.get("verified", False):
            return "confirmed"
        if data.get("poc"):
            return "high"
        return "medium"

    def _calculate_cvss(self, severity: str) -> float:
        """Calculate approximate CVSS score based on severity"""
        cvss_map = {
            "critical": 9.0,
            "high": 7.5,
            "medium": 5.5,
            "low": 3.0,
            "info": 0.0,
        }
        return cvss_map.get(severity, 5.5)

    def _deduplicate_findings(self, findings: List[Dict]) -> List[Dict]:
        """Remove duplicate findings"""
        seen = set()
        unique = []

        for finding in findings:
            key = (finding["url"], finding["parameter"], finding["vulnerability_type"])
            if key not in seen:
                seen.add(key)
                unique.append(finding)

        return unique

    def _validate_findings(self, findings: List[Dict]) -> List[Dict]:
        """
        Validate findings to reduce false positives.
        Only keeps findings with sufficient evidence.
        """
        validated = []

        for finding in findings:
            # Require minimum confidence
            if finding.get("confidence") in ["confirmed", "high", "medium"]:
                validated.append(finding)

        return validated

    async def execute_all(
        self, plans: List[XSSExecutionPlan], target_url: str
    ) -> List[XSSToolResult]:
        """Execute all tool plans in parallel"""
        self.logger.info(f"Running {len(plans)} XSS detection tool(s)")

        tasks = [self.execute_tool(plan, target_url) for plan in plans]
        results = await asyncio.gather(*tasks)

        return results

    def scan(
        self, target_url: str, tools: List[str] = None, progress_callback=None
    ) -> Dict[str, Any]:
        """
        Main entry point for XSS scanning.

        Args:
            target_url: URL to scan
            tools: Optional list of specific tools to use
            progress_callback: Optional callback function to report progress (0-100)

        Returns:
            Structured JSON results
        """
        self.logger.info(f"Starting XSS detection on {target_url}")

        if progress_callback:
            progress_callback(5)  # Starting

        # Generate execution plan
        plan_data = self.generate_execution_plan(target_url)
        plans = [XSSExecutionPlan(**p) for p in plan_data["execution_plans"]]

        # Filter tools if specified
        if tools:
            plans = [p for p in plans if p.tool in tools]

        if not plans:
            raise RuntimeError("No XSS detection tools configured or available")

        if progress_callback:
            progress_callback(10)  # Execution plan ready

        # Execute tools
        results = asyncio.run(self.execute_all(plans, target_url))

        if progress_callback:
            progress_callback(70)  # Tools executed

        # Aggregate findings
        all_findings = []
        tool_stats = {}
        total_time = 0
        failed_tools = {}

        for result in results:
            tool_stats[result.tool] = {
                "success": result.success,
                "findings_count": len(result.findings),
                "execution_time": result.execution_time,
                "error": result.error,
            }
            total_time += result.execution_time

            if result.success:
                all_findings.extend(result.findings)
            elif result.error:
                failed_tools[result.tool] = result.error

        # Deduplicate and validate
        unique_findings = self._deduplicate_findings(all_findings)

        if progress_callback:
            progress_callback(85)  # Deduplication complete

        validated_findings = self._validate_findings(unique_findings)

        if progress_callback:
            progress_callback(95)  # Validation complete

        self.logger.info(
            f"Found {len(validated_findings)} unique validated XSS findings"
        )

        warning_message = None
        if failed_tools:
            error_summary = "; ".join(
                f"{tool_name}: {error_text}"
                for tool_name, error_text in failed_tools.items()
            )
            if len(failed_tools) == len(results):
                warning_message = (
                    f"All selected XSS tools failed or timed out. {error_summary}"
                )
            else:
                warning_message = f"Some XSS tools failed or timed out. {error_summary}"

        # Generate statistics
        severity_stats = {}
        type_stats = {}
        for finding in validated_findings:
            sev = finding["severity"].lower()
            severity_stats[sev] = severity_stats.get(sev, 0) + 1

            vtype = finding["vulnerability_type"]
            type_stats[vtype] = type_stats.get(vtype, 0) + 1

        # Build final result
        result = {
            "scan_info": {
                "target": target_url,
                "domain": plan_data["domain"],
                "scan_time": datetime.now(UTC).isoformat(),
                "total_execution_time": total_time,
                "tools_used": list(tool_stats.keys()),
                "status": "completed_with_errors" if failed_tools else "completed",
                "failed_tools": failed_tools,
                "warning": warning_message,
            },
            "summary": {
                "total_findings": len(validated_findings),
                "critical": severity_stats.get("critical", 0),
                "high": severity_stats.get("high", 0),
                "medium": severity_stats.get("medium", 0),
                "low": severity_stats.get("low", 0),
                "by_type": type_stats,
                "tools_failed": len(failed_tools),
            },
            "tool_results": tool_stats,
            "findings": validated_findings,
        }
        if warning_message:
            result["warnings"] = [warning_message]

        # Save results
        self._save_results(result, plan_data["domain"])

        if progress_callback:
            progress_callback(100)  # Complete

        return result

    def _save_results(self, results: Dict, domain: str) -> str:
        """Save scan results to JSON file"""
        results_dir = self.config.get_results_dir("xss", base_path=Path(__file__).parent)
        results_dir.mkdir(parents=True, exist_ok=True)

        parsed = urlparse(domain)
        domain_label = parsed.netloc or domain
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_domain = re.sub(r"[^\w\-.]", "_", domain_label).strip("_") or "target"
        filename = f"xss_{safe_domain}_{timestamp}.json"
        filepath = results_dir / filename

        results["output_file"] = str(filepath)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

        self.logger.info(f"Results saved to {filepath}")
        return str(filepath)

    def print_summary(self, results: Dict):
        """Print a human-readable summary of scan results"""
        print("\n" + "=" * 60)
        print(f"XSS SCAN RESULTS: {results['scan_info']['target']}")
        print("=" * 60)

        summary = results["summary"]
        print(f"\n🎯 Total Findings: {summary['total_findings']}")

        if summary["total_findings"] > 0:
            print("\n📊 By Severity:")
            if summary["critical"] > 0:
                print(f"   🔴 CRITICAL: {summary['critical']}")
            if summary["high"] > 0:
                print(f"   🟠 HIGH: {summary['high']}")
            if summary["medium"] > 0:
                print(f"   🟡 MEDIUM: {summary['medium']}")
            if summary["low"] > 0:
                print(f"   🟢 LOW: {summary['low']}")

            print("\n📂 By Type:")
            for vtype, count in summary.get("by_type", {}).items():
                print(f"   • {vtype}: {count}")

            print("\n🚨 Critical/High Findings:")
            for finding in results["findings"]:
                if finding["severity"] in ["critical", "high"]:
                    print(
                        f"   [{finding['severity'].upper()}] {finding['parameter']} - {finding['vulnerability_type']}"
                    )
                    print(f"      URL: {finding['url'][:80]}...")
                    print(f"      Tool: {finding['detection_tool']}")
        else:
            print("\n✅ No XSS vulnerabilities detected")

        print("\n" + "=" * 60)


def main():
    """CLI entry point"""
    import argparse

    parser = argparse.ArgumentParser(
        description="XSS Detection Orchestrator - Academic Security Research Tool"
    )
    parser.add_argument("target", help="Target URL to scan for XSS")
    parser.add_argument(
        "--tools",
        nargs="+",
        choices=["dalfox", "nuclei", "xsstrike"],
        help="Specific tools to use (default: all enabled)",
    )
    parser.add_argument(
        "--plan-only", action="store_true", help="Only show execution plan"
    )
    parser.add_argument("--json", action="store_true", help="Output as JSON only")

    args = parser.parse_args()

    orchestrator = XSSDetectionOrchestrator()

    if args.plan_only:
        plan = orchestrator.generate_execution_plan(args.target)
        print(json.dumps(plan, indent=2))
        return

    results = orchestrator.scan(args.target, args.tools)

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        orchestrator.print_summary(results)


if __name__ == "__main__":
    main()
