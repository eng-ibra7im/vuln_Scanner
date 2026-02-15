#!/usr/bin/env python3
"""
SQL Injection Detection Orchestrator
Academic Security Research Tool

This orchestrator generates execution plans for SQL injection detection tools,
coordinates their execution, analyzes results, and produces structured JSON output.

Tools supported:
- sqlmap: Automatic SQL injection detection and exploitation tool
- nuclei: Fast vulnerability scanner with SQLi templates
- ghauri: Advanced cross-platform SQL injection detection

Author: Security Research Team
Version: 1.0.0
"""

import json
import subprocess
import time
import re
import shutil
import sys
from datetime import datetime, UTC
from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass, asdict, field
from pathlib import Path
from urllib.parse import urlparse, parse_qs
import logging

from config import Config


def get_tool_path(tool_name: str) -> str:
    """
    Get the full path to a tool, checking venv Scripts directory first,
    then Go bin directories, then system PATH.
    """
    # Check venv Scripts first
    if hasattr(sys, "prefix") and sys.prefix != sys.base_prefix:
        venv_scripts = Path(sys.prefix) / "Scripts"
        if not venv_scripts.exists():
            venv_scripts = Path(sys.prefix) / "bin"

        for ext in [".exe", "", ".cmd", ".bat"]:
            tool_path = venv_scripts / f"{tool_name}{ext}"
            if tool_path.exists():
                return str(tool_path)

    # Check Go bin directories (common locations for Go tools like nuclei)
    go_bin_paths = [
        Path.home() / "go" / "bin",
        Path(r"C:\Users\DUBAI STORE\go\bin"),
        Path(r"C:\Program Files\Go\bin"),
        Path("/usr/local/go/bin"),
        Path.home() / ".go" / "bin",
    ]

    for go_bin in go_bin_paths:
        if go_bin.exists():
            for ext in [".exe", "", ".cmd", ".bat"]:
                tool_path = go_bin / f"{tool_name}{ext}"
                if tool_path.exists():
                    return str(tool_path)

    # Check common Python tool locations (sqlmap)
    python_paths = [
        Path(sys.prefix) / "Scripts",
        Path.home() / ".local" / "bin",
        Path("/usr/local/bin"),
    ]

    for py_path in python_paths:
        if py_path.exists():
            for ext in [".py", ".exe", "", ".cmd", ".bat"]:
                tool_path = py_path / f"{tool_name}{ext}"
                if tool_path.exists():
                    return str(tool_path)

    found = shutil.which(tool_name)
    if found:
        return found

    return tool_name


@dataclass
class SQLiExecutionPlan:
    """Represents an execution plan for SQL injection detection"""

    tool: str
    command: List[str]
    timeout: int
    priority: int
    description: str
    injection_type: str  # 'error-based', 'blind', 'union', 'time-based', 'stacked'


@dataclass
class SQLiFinding:
    """Represents a detected SQL injection vulnerability"""

    url: str
    parameter: str
    payload: str  # Detection payload (not exploitation)
    injection_type: (
        str  # 'error-based', 'blind-boolean', 'blind-time', 'union', 'stacked'
    )
    severity: str  # 'critical', 'high', 'medium', 'low', 'info'
    confidence: str  # 'confirmed', 'high', 'medium', 'low'
    detection_tool: str
    evidence: str
    database_type: str  # 'mysql', 'postgresql', 'mssql', 'oracle', 'sqlite', 'unknown'
    remediation: str
    cwe_id: str = "CWE-89"
    cvss_score: float = 0.0
    notes: List[str] = field(default_factory=list)


@dataclass
class SQLiToolResult:
    """Represents the result from a single tool execution"""

    tool: str
    success: bool
    findings: List[Dict[str, Any]]
    execution_time: float
    error: Optional[str] = None
    raw_output: Optional[str] = None


class SQLiDetectionOrchestrator:
    """
    Orchestrates SQL injection detection across multiple tools.
    Generates execution plans, coordinates tool execution, analyzes and classifies results.
    """

    # SQL Injection Type patterns for classification
    ERROR_BASED_INDICATORS = [
        r"error.*based",
        r"mysql.*error",
        r"syntax.*error",
        r"sql.*error",
        r"unclosed.*quotation",
        r"you have an error",
    ]

    BLIND_BOOLEAN_INDICATORS = [
        r"blind.*boolean",
        r"boolean.*based",
        r"conditional.*response",
        r"true/false",
    ]

    BLIND_TIME_INDICATORS = [
        r"time.*based",
        r"sleep\(",
        r"benchmark\(",
        r"waitfor.*delay",
        r"pg_sleep",
    ]

    UNION_INDICATORS = [
        r"union.*based",
        r"union.*select",
        r"union.*query",
        r"order.*by",
    ]

    STACKED_INDICATORS = [
        r"stacked.*queries",
        r"multiple.*statements",
        r"batch.*queries",
    ]

    # Database type patterns
    DATABASE_PATTERNS = {
        "mysql": [r"mysql", r"mariadb", r"percona"],
        "postgresql": [r"postgres", r"pgsql", r"postgresql"],
        "mssql": [r"mssql", r"microsoft.*sql", r"sql.*server"],
        "oracle": [r"oracle", r"ora-"],
        "sqlite": [r"sqlite"],
    }

    # Severity mapping based on context
    SEVERITY_MAP = {
        "admin": "critical",
        "login": "critical",
        "auth": "critical",
        "payment": "critical",
        "user": "high",
        "account": "high",
        "profile": "high",
        "search": "medium",
        "filter": "medium",
        "id": "high",
        "password": "critical",
    }

    # Confidence levels for different detection methods
    CONFIDENCE_MAP = {
        "confirmed": 1.0,
        "high": 0.85,
        "medium": 0.65,
        "low": 0.45,
    }

    def __init__(self, config: Optional[Config] = None):
        """Initialize the SQLi Detection Orchestrator"""
        self.config = config or Config()
        self.logger = logging.getLogger(__name__)

        # Tool availability cache
        self._tool_availability: Dict[str, bool] = {}

        # Default tool configurations
        self.tool_configs = {
            "sqlmap": {
                "timeout": 300,
                "priority": 1,
                "description": "Automatic SQL injection detection tool",
            },
            "nuclei": {
                "timeout": 180,
                "priority": 2,
                "description": "Fast template-based SQLi scanning",
            },
            "ghauri": {
                "timeout": 240,
                "priority": 3,
                "description": "Advanced cross-platform SQLi detection",
            },
        }

    def check_tool_availability(self, tool_name: str) -> bool:
        """Check if a tool is available in the system"""
        if tool_name in self._tool_availability:
            return self._tool_availability[tool_name]

        tool_path = get_tool_path(tool_name)
        path_obj = Path(tool_path)

        # Check if it's an absolute path that exists
        if path_obj.is_absolute() and path_obj.exists():
            self._tool_availability[tool_name] = True
            return True

        # Check if shutil.which can find it
        if shutil.which(tool_name):
            self._tool_availability[tool_name] = True
            return True

        # Special check for sqlmap (might be sqlmap.py)
        if tool_name == "sqlmap":
            sqlmap_py = shutil.which("sqlmap.py")
            if sqlmap_py:
                self._tool_availability[tool_name] = True
                return True

        self._tool_availability[tool_name] = False
        return False

    def get_available_tools(self) -> List[str]:
        """Get list of available SQLi detection tools"""
        available = []
        for tool in self.tool_configs.keys():
            if self.check_tool_availability(tool):
                available.append(tool)
        return available

    def generate_execution_plan(
        self,
        target_url: str,
        tools: Optional[List[str]] = None,
        intensity: str = "basic",
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Generate execution plans for SQL injection detection.

        Args:
            target_url: The target URL to scan
            tools: List of tools to use (None = all available)
            intensity: Scan intensity ('basic' or 'aggressive')
            options: Additional scan options

        Returns:
            Dictionary containing execution plans and metadata
        """
        options = options or {}

        # Parse URL to extract information
        parsed = urlparse(target_url)
        domain = parsed.netloc
        params = parse_qs(parsed.query)

        if not params:
            self.logger.warning(f"No parameters found in URL: {target_url}")

        # Determine which tools to use
        if tools is None:
            tools = self.get_available_tools()
        else:
            # Filter to only available tools
            tools = [t for t in tools if self.check_tool_availability(t)]

        if not tools:
            return {
                "success": False,
                "error": "No SQL injection detection tools available",
                "available_tools": [],
            }

        plans = []

        for tool in tools:
            plan = self._generate_tool_plan(
                tool, target_url, domain, params, intensity, options
            )
            if plan:
                plans.append(plan)

        # Sort by priority
        plans.sort(key=lambda x: x["priority"])

        return {
            "success": True,
            "target": target_url,
            "domain": domain,
            "parameters": list(params.keys()),
            "intensity": intensity,
            "tools_requested": tools,
            "execution_plans": plans,
            "total_estimated_time": sum(p["timeout"] for p in plans),
            "generated_at": datetime.now(UTC).isoformat(),
        }

    def _generate_tool_plan(
        self,
        tool: str,
        target_url: str,
        domain: str,
        params: Dict,
        intensity: str,
        options: Dict,
    ) -> Optional[Dict]:
        """Generate execution plan for a specific tool"""

        tool_config = self.tool_configs.get(tool, {})
        timeout = options.get("timeout", tool_config.get("timeout", 180))

        if tool == "sqlmap":
            return self._generate_sqlmap_plan(
                target_url, domain, params, intensity, timeout, options
            )
        elif tool == "nuclei":
            return self._generate_nuclei_plan(
                target_url, domain, intensity, timeout, options
            )
        elif tool == "ghauri":
            return self._generate_ghauri_plan(
                target_url, domain, params, intensity, timeout, options
            )

        return None

    def _generate_sqlmap_plan(
        self,
        target_url: str,
        domain: str,
        params: Dict,
        intensity: str,
        timeout: int,
        options: Dict,
    ) -> Dict:
        """Generate SQLMap execution plan"""
        tool_path = get_tool_path("sqlmap")

        cmd = [
            tool_path,
            "-u",
            target_url,
            "--batch",  # Non-interactive mode
            "--level",
            "3" if intensity == "aggressive" else "1",
            "--risk",
            "2" if intensity == "aggressive" else "1",
            "--output-dir",
            str(Path(__file__).parent / "results" / "sqli"),
            "--forms" if intensity == "aggressive" else "",
            "--random-agent",
            "--tamper=space2comment" if intensity == "aggressive" else "",
        ]

        # Remove empty strings
        cmd = [c for c in cmd if c]

        # Add timeout
        cmd.extend(["--timeout", str(min(timeout // 2, 30))])

        return {
            "tool": "sqlmap",
            "command": cmd,
            "timeout": timeout,
            "priority": self.tool_configs["sqlmap"]["priority"],
            "description": self.tool_configs["sqlmap"]["description"],
            "injection_types": [
                "error-based",
                "blind-boolean",
                "blind-time",
                "union",
                "stacked",
            ],
        }

    def _generate_nuclei_plan(
        self,
        target_url: str,
        domain: str,
        intensity: str,
        timeout: int,
        options: Dict,
    ) -> Dict:
        """Generate Nuclei execution plan for SQLi detection"""
        tool_path = get_tool_path("nuclei")

        cmd = [
            tool_path,
            "-u",
            target_url,
            "-dast",  # Enable DAST templates (disabled by default in Nuclei v3+)
            "-t",
            "dast/vulnerabilities/sqli/",
            "-t",
            "http/vulnerabilities/generic/error-based-sql-injection.yaml",
            "-jsonl",
            "-silent",
            "-nc",  # No color
            "-timeout",
            str(min(timeout // 3, 60)),
        ]

        if intensity == "aggressive":
            cmd.extend(["-rl", "150"])  # Rate limit
        else:
            cmd.extend(["-rl", "100"])

        return {
            "tool": "nuclei",
            "command": cmd,
            "timeout": timeout,
            "priority": self.tool_configs["nuclei"]["priority"],
            "description": self.tool_configs["nuclei"]["description"],
            "injection_types": ["error-based", "blind-boolean", "union"],
        }

    def _generate_ghauri_plan(
        self,
        target_url: str,
        domain: str,
        params: Dict,
        intensity: str,
        timeout: int,
        options: Dict,
    ) -> Dict:
        """Generate Ghauri execution plan"""
        tool_path = get_tool_path("ghauri")

        cmd = [
            tool_path,
            "-u",
            target_url,
            "--batch",
            "--level",
            "3" if intensity == "aggressive" else "1",
            "--threads",
            "5" if intensity == "aggressive" else "2",
        ]

        return {
            "tool": "ghauri",
            "command": cmd,
            "timeout": timeout,
            "priority": self.tool_configs["ghauri"]["priority"],
            "description": self.tool_configs["ghauri"]["description"],
            "injection_types": ["error-based", "blind-boolean", "blind-time", "union"],
        }

    def execute_tool(
        self, plan: Dict, progress_callback: Optional[Callable[[int], None]] = None
    ) -> SQLiToolResult:
        """Execute a single tool based on its execution plan"""
        tool_name = plan["tool"]
        command = plan["command"]
        timeout = plan.get("timeout", 180)

        start_time = time.time()

        try:
            result = self._run_subprocess_sync(command, timeout)
            execution_time = time.time() - start_time

            # Parse the output based on tool
            findings = self._parse_tool_output(
                tool_name, result["stdout"], result["stderr"]
            )

            return SQLiToolResult(
                tool=tool_name,
                success=True,
                findings=findings,
                execution_time=execution_time,
                raw_output=(
                    (result["stdout"] + "\n" + result["stderr"])[:5000]
                    if (result["stdout"] or result["stderr"])
                    else None
                ),
            )

        except subprocess.TimeoutExpired:
            return SQLiToolResult(
                tool=tool_name,
                success=False,
                findings=[],
                execution_time=timeout,
                error=f"Tool execution timed out after {timeout}s",
            )
        except FileNotFoundError:
            return SQLiToolResult(
                tool=tool_name,
                success=False,
                findings=[],
                execution_time=0,
                error=f"Tool '{tool_name}' not found in system PATH",
            )
        except Exception as e:
            return SQLiToolResult(
                tool=tool_name,
                success=False,
                findings=[],
                execution_time=time.time() - start_time,
                error=str(e),
            )

    def _run_subprocess_sync(self, command: List[str], timeout: int) -> Dict[str, str]:
        """Run subprocess synchronously with timeout"""
        try:
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                encoding="utf-8",
                errors="replace",
            )
            return {"stdout": process.stdout, "stderr": process.stderr}
        except subprocess.TimeoutExpired as e:
            raise e
        except Exception as e:
            raise e

    def _parse_tool_output(
        self, tool_name: str, stdout: str, stderr: str
    ) -> List[Dict[str, Any]]:
        """Parse tool output and extract findings"""
        if tool_name == "sqlmap":
            return self._parse_sqlmap_output(stdout, stderr)
        elif tool_name == "nuclei":
            return self._parse_nuclei_output(stdout, stderr)
        elif tool_name == "ghauri":
            return self._parse_ghauri_output(stdout, stderr)
        return []

    def _parse_sqlmap_output(self, stdout: str, stderr: str) -> List[Dict[str, Any]]:
        """Parse SQLMap output for SQL injection findings"""
        findings = []
        combined = stdout + "\n" + stderr

        db_type = self._detect_database_type(combined)

        # Parse detailed injection points block
        if re.search(
            r"sqlmap (?:identified|resumed) the following injection point",
            combined,
            re.I,
        ):
            # Parse Parameter blocks with Type/Title/Payload sections
            param_blocks = re.split(r"---\n", combined)
            current_param = None

            for block in param_blocks:
                param_match = re.search(r"Parameter:\s*[#]?(\S+)\s*\(([^)]+)\)", block)
                if param_match:
                    current_param = param_match.group(1).strip("'\"")

                # Find all Type/Title/Payload entries within this block
                type_matches = re.findall(
                    r"Type:\s*(.*?)\s*\n\s*Title:\s*(.*?)\s*\n\s*Payload:\s*(.*?)(?:\n|$)",
                    block,
                    re.I,
                )
                for sqli_type, title, payload in type_matches:
                    param_name = current_param or "unknown"
                    finding = self._create_sqli_finding(
                        url="",
                        parameter=param_name,
                        payload=payload.strip()[:300] or f"[{title.strip()}]",
                        injection_type=self._classify_injection_type(sqli_type),
                        confidence="confirmed",
                        tool="sqlmap",
                        evidence=f"{sqli_type.strip()} - {title.strip()}",
                        database_type=db_type,
                    )
                    findings.append(finding)

            # Fallback: simple Parameter regex if no Type/Title/Payload found
            if not findings:
                param_matches = re.findall(
                    r"Parameter:\s*['\"]?(\w+)['\"]?\s*\(([^)]+)\)", combined
                )
                for param, injection_info in param_matches:
                    finding = self._create_sqli_finding(
                        url="",
                        parameter=param,
                        payload="[Detected by SQLMap]",
                        injection_type=self._classify_injection_type(injection_info),
                        confidence="confirmed",
                        tool="sqlmap",
                        evidence=injection_info[:500],
                        database_type=db_type,
                    )
                    findings.append(finding)

        elif re.search(r"might be injectable", combined, re.I):
            param_match = re.search(r"testing.*parameter\s*['\"]?(\w+)", combined, re.I)
            param = param_match.group(1) if param_match else "unknown"
            finding = self._create_sqli_finding(
                url="",
                parameter=param,
                payload="[Potential - needs verification]",
                injection_type="unknown",
                confidence="medium",
                tool="sqlmap",
                evidence="SQLMap detected possible injection point",
                database_type=db_type,
            )
            findings.append(finding)

        # Also check for "is vulnerable" pattern
        elif re.search(r"parameter\s+'?(\w+)'?\s+is\s+vulnerable", combined, re.I):
            match = re.search(
                r"parameter\s+'?(\w+)'?\s+is\s+vulnerable", combined, re.I
            )
            param = match.group(1)
            finding = self._create_sqli_finding(
                url="",
                parameter=param,
                payload="[Confirmed by SQLMap]",
                injection_type=self._classify_injection_type(combined),
                confidence="confirmed",
                tool="sqlmap",
                evidence="Parameter confirmed vulnerable by SQLMap",
                database_type=db_type,
            )
            findings.append(finding)

        return findings

    def _parse_nuclei_output(
        self, stdout: str, stderr: str = ""
    ) -> List[Dict[str, Any]]:
        """Parse Nuclei JSONL output for SQL injection findings"""
        findings = []
        # Nuclei outputs JSON findings to stdout, but combine both for safety
        combined = stdout + "\n" + stderr

        for line in combined.strip().split("\n"):
            line = line.strip()
            if not line or not line.startswith("{"):
                continue

            try:
                data = json.loads(line)

                # Extract relevant fields
                template_id = data.get("template-id", "")
                matched_at = data.get("matched-at", "")
                info = data.get("info", {})
                extractor_name = data.get("extractor-name", "")
                extracted = data.get("extracted-results", [])
                fuzzing_param = data.get("fuzzing_parameter", "")

                # Only process SQLi-related findings
                if not any(
                    kw in template_id.lower()
                    for kw in ["sqli", "sql", "injection", "database"]
                ):
                    continue

                severity = info.get("severity", "medium")
                description = info.get("description", "")

                # Get parameter: prefer fuzzing_parameter from DAST, fallback to URL parsing
                param = fuzzing_param
                if not param:
                    parsed = urlparse(matched_at)
                    params = parse_qs(parsed.query)
                    param = list(params.keys())[0] if params else "unknown"

                # Detect database from extractor-name (e.g. "mysql", "postgresql")
                db_type = (
                    extractor_name
                    if extractor_name
                    else self._detect_database_from_template(template_id)
                )

                # Build evidence from extracted results
                evidence = description[:300]
                if extracted:
                    evidence += f" | Extracted: {'; '.join(str(e)[:100] for e in extracted[:3])}"

                finding = self._create_sqli_finding(
                    url=matched_at,
                    parameter=param,
                    payload=(
                        str(extracted[0])[:300]
                        if extracted
                        else "[Nuclei DAST detection]"
                    ),
                    injection_type=self._classify_injection_from_template(template_id),
                    confidence="high" if severity in ["critical", "high"] else "medium",
                    tool="nuclei",
                    evidence=evidence,
                    database_type=db_type,
                )
                finding["severity"] = severity.capitalize()
                findings.append(finding)

            except json.JSONDecodeError:
                # Try to parse text output
                if "sql" in line.lower() and "injection" in line.lower():
                    finding = self._create_sqli_finding(
                        url="",
                        parameter="unknown",
                        payload="[Nuclei text detection]",
                        injection_type="unknown",
                        confidence="medium",
                        tool="nuclei",
                        evidence=line[:500],
                        database_type="unknown",
                    )
                    findings.append(finding)
            except Exception:
                continue

        return findings

    def _parse_ghauri_output(self, stdout: str, stderr: str) -> List[Dict[str, Any]]:
        """Parse Ghauri output for SQL injection findings"""
        findings = []
        # Ghauri outputs findings to stderr, not stdout
        combined = stdout + "\n" + stderr
        db_type = self._detect_database_type(combined)

        # Primary pattern: Ghauri uses same block format as sqlmap
        # "Ghauri resumed/identified the following injection point(s)"
        if re.search(
            r"(?:Ghauri|ghauri)\s+(?:identified|resumed)\s+the\s+following\s+injection\s+point",
            combined,
            re.I,
        ):
            # Parse Parameter blocks with Type/Title/Payload sections
            param_blocks = re.split(r"---\n?", combined)
            current_param = None

            for block in param_blocks:
                param_match = re.search(r"Parameter:\s*[#]?(\S+)\s*\(([^)]+)\)", block)
                if param_match:
                    current_param = param_match.group(1).strip("'\"")

                # Find all Type/Title/Payload entries within this block
                type_matches = re.findall(
                    r"Type:\s*(.*?)\s*\n\s*Title:\s*(.*?)\s*\n\s*Payload:\s*(.*?)(?:\n|$)",
                    block,
                    re.I,
                )
                for sqli_type, title, payload in type_matches:
                    param_name = current_param or "unknown"
                    finding = self._create_sqli_finding(
                        url="",
                        parameter=param_name,
                        payload=payload.strip()[:300] or f"[{title.strip()}]",
                        injection_type=self._classify_injection_type(sqli_type),
                        confidence="confirmed",
                        tool="ghauri",
                        evidence=f"{sqli_type.strip()} - {title.strip()}",
                        database_type=db_type,
                    )
                    findings.append(finding)

            # Fallback if no Type/Title/Payload blocks found
            if not findings:
                param_matches = re.findall(
                    r"Parameter:\s*['\"]?(\w+)['\"]?\s*\(([^)]+)\)", combined
                )
                for param, injection_info in param_matches:
                    finding = self._create_sqli_finding(
                        url="",
                        parameter=param,
                        payload="[Detected by Ghauri]",
                        injection_type=self._classify_injection_type(injection_info),
                        confidence="confirmed",
                        tool="ghauri",
                        evidence=injection_info[:500],
                        database_type=db_type,
                    )
                    findings.append(finding)

        # Secondary patterns: "Parameter 'X' is vulnerable"
        if not findings:
            vuln_matches = re.findall(
                r"Parameter\s*['\"]?(\w+)['\"]?\s*is\s*vulnerable", combined, re.I
            )
            vuln_matches2 = re.findall(
                r"injection\s+(?:on|in)\s+.*?parameter\s*['\"]?(\w+)", combined, re.I
            )
            vuln_matches3 = re.findall(
                r"(?:GET|POST)\s+parameter\s+['\"]?(\w+)['\"]?\s+is\s+vulnerable",
                combined,
                re.I,
            )
            all_vuln_params = list(set(vuln_matches + vuln_matches2 + vuln_matches3))

            if all_vuln_params:
                for param in all_vuln_params:
                    injection_types = []
                    if re.search(r"boolean[\-\s]*based", combined, re.I):
                        injection_types.append("blind-boolean")
                    if re.search(r"time[\-\s]*based", combined, re.I):
                        injection_types.append("blind-time")
                    if re.search(r"error[\-\s]*based", combined, re.I):
                        injection_types.append("error-based")
                    if re.search(r"union[\-\s]*based|UNION.*SELECT", combined, re.I):
                        injection_types.append("union")
                    if re.search(r"stacked", combined, re.I):
                        injection_types.append("stacked")
                    if not injection_types:
                        injection_types = ["unknown"]

                    payload_match = re.search(
                        r"Payload:\s*(.*?)(?:\n|$)", combined, re.I
                    )
                    payload_text = (
                        payload_match.group(1).strip()[:300]
                        if payload_match
                        else "[Detected by Ghauri]"
                    )

                    for inj_type in injection_types:
                        finding = self._create_sqli_finding(
                            url="",
                            parameter=param,
                            payload=payload_text,
                            injection_type=inj_type,
                            confidence="confirmed",
                            tool="ghauri",
                            evidence=f"Parameter '{param}' confirmed vulnerable ({inj_type}) by Ghauri",
                            database_type=db_type,
                        )
                        findings.append(finding)

        # Tertiary: possible injection
        if not findings and re.search(
            r"might be injectable|possible.*injection|tested.*injectable",
            combined,
            re.I,
        ):
            param_match = re.search(r"parameter\s*['\"]?(\w+)", combined, re.I)
            param = param_match.group(1) if param_match else "unknown"

            finding = self._create_sqli_finding(
                url="",
                parameter=param,
                payload="[Potential - needs verification]",
                injection_type="unknown",
                confidence="medium",
                tool="ghauri",
                evidence="Ghauri detected possible injection point",
                database_type=db_type,
            )
            findings.append(finding)

        return findings

    def _create_sqli_finding(
        self,
        url: str,
        parameter: str,
        payload: str,
        injection_type: str,
        confidence: str,
        tool: str,
        evidence: str,
        database_type: str,
    ) -> Dict[str, Any]:
        """Create a standardized SQL injection finding dictionary"""

        # Determine severity based on injection type and context
        severity = self._calculate_severity(injection_type, parameter, confidence)

        return {
            "url": url,
            "parameter": parameter,
            "payload": payload,
            "injection_type": injection_type,
            "sqli_type": injection_type,  # Alias for dashboard
            "severity": severity,
            "confidence": confidence,
            "tool": tool,
            "detection_tool": tool,
            "evidence": evidence,
            "database_type": database_type,
            "cwe_id": "CWE-89",
            "cvss_score": self._calculate_cvss(severity, confidence),
            "remediation": self._get_remediation(injection_type),
            "detected_at": datetime.now(UTC).isoformat(),
        }

    def _classify_injection_type(self, info: str) -> str:
        """Classify injection type from tool output"""
        info_lower = info.lower()

        if any(re.search(p, info_lower) for p in self.ERROR_BASED_INDICATORS):
            return "error-based"
        if any(re.search(p, info_lower) for p in self.BLIND_TIME_INDICATORS):
            return "blind-time"
        if any(re.search(p, info_lower) for p in self.BLIND_BOOLEAN_INDICATORS):
            return "blind-boolean"
        if any(re.search(p, info_lower) for p in self.UNION_INDICATORS):
            return "union"
        if any(re.search(p, info_lower) for p in self.STACKED_INDICATORS):
            return "stacked"

        return "unknown"

    def _classify_injection_from_template(self, template_id: str) -> str:
        """Classify injection type from Nuclei template ID"""
        template_lower = template_id.lower()

        if "error" in template_lower:
            return "error-based"
        if "time" in template_lower or "blind" in template_lower:
            return "blind-time"
        if "boolean" in template_lower:
            return "blind-boolean"
        if "union" in template_lower:
            return "union"
        if "stack" in template_lower:
            return "stacked"

        return "unknown"

    def _detect_database_type(self, text: str) -> str:
        """Detect database type from tool output"""
        text_lower = text.lower()

        for db_type, patterns in self.DATABASE_PATTERNS.items():
            if any(re.search(p, text_lower) for p in patterns):
                return db_type

        return "unknown"

    def _detect_database_from_template(self, template_id: str) -> str:
        """Detect database type from Nuclei template ID"""
        template_lower = template_id.lower()

        for db_type in ["mysql", "postgresql", "mssql", "oracle", "sqlite"]:
            if db_type in template_lower:
                return db_type

        return "unknown"

    def _calculate_severity(
        self, injection_type: str, parameter: str, confidence: str
    ) -> str:
        """Calculate severity based on injection type and context"""

        # Base severity by injection type
        type_severity = {
            "stacked": "Critical",
            "union": "Critical",
            "error-based": "High",
            "blind-time": "High",
            "blind-boolean": "Medium",
            "unknown": "Medium",
        }

        severity = type_severity.get(injection_type, "Medium")

        # Elevate severity for sensitive parameters
        param_lower = parameter.lower()
        for keyword, sev in self.SEVERITY_MAP.items():
            if keyword in param_lower:
                if sev == "critical":
                    severity = "Critical"
                elif sev == "high" and severity not in ["Critical"]:
                    severity = "High"
                break

        # Reduce severity for low confidence
        if confidence == "low" and severity == "Critical":
            severity = "High"
        elif confidence == "low" and severity == "High":
            severity = "Medium"

        return severity

    def _calculate_cvss(self, severity: str, confidence: str) -> float:
        """Calculate approximate CVSS score"""
        base_scores = {
            "Critical": 9.8,
            "High": 8.6,
            "Medium": 6.5,
            "Low": 3.7,
            "Info": 0.0,
        }

        confidence_modifier = {
            "confirmed": 1.0,
            "high": 0.95,
            "medium": 0.85,
            "low": 0.7,
        }

        base = base_scores.get(severity, 5.0)
        modifier = confidence_modifier.get(confidence, 0.8)

        return round(base * modifier, 1)

    def _get_remediation(self, injection_type: str) -> str:
        """Get remediation advice for injection type"""
        remediations = {
            "error-based": "Use parameterized queries/prepared statements. Implement proper error handling that doesn't expose database details.",
            "blind-boolean": "Use parameterized queries. Implement rate limiting and monitoring for suspicious query patterns.",
            "blind-time": "Use parameterized queries. Add query timeout limits and monitor for slow queries.",
            "union": "Use parameterized queries. Restrict database user permissions. Use allowlists for expected values.",
            "stacked": "Use parameterized queries. Disable multiple statement execution if not needed. Use strict input validation.",
            "unknown": "Use parameterized queries/prepared statements. Never concatenate user input directly into SQL queries.",
        }
        return remediations.get(
            injection_type,
            "Use parameterized queries/prepared statements. Implement proper input validation.",
        )

    def scan(
        self,
        target_url: str,
        tools: Optional[List[str]] = None,
        intensity: str = "basic",
        options: Optional[Dict[str, Any]] = None,
        progress_callback: Optional[Callable[[int], None]] = None,
    ) -> Dict[str, Any]:
        """
        Execute a full SQL injection scan.

        Args:
            target_url: Target URL with parameters to scan
            tools: List of tools to use
            intensity: 'basic' or 'aggressive'
            options: Additional options
            progress_callback: Optional callback for progress updates

        Returns:
            Structured scan results
        """
        options = options or {}

        if progress_callback:
            progress_callback(5)

        # Generate execution plan
        plan_data = self.generate_execution_plan(target_url, tools, intensity, options)

        if not plan_data.get("success"):
            return {
                "scan_info": {
                    "target": target_url,
                    "error": plan_data.get("error", "Failed to generate plan"),
                },
                "summary": {"total_findings": 0},
                "findings": [],
            }

        if progress_callback:
            progress_callback(10)

        # Execute each tool
        all_findings = []
        tool_stats = {}
        total_plans = len(plan_data["execution_plans"])

        for idx, plan in enumerate(plan_data["execution_plans"]):
            tool_name = plan["tool"]

            # Update progress
            if progress_callback:
                progress = 10 + int((idx / total_plans) * 70)
                progress_callback(progress)

            # Execute tool
            result = self.execute_tool(plan, progress_callback)

            # Collect stats
            tool_stats[tool_name] = {
                "success": result.success,
                "findings_count": len(result.findings),
                "execution_time": result.execution_time,
                "error": result.error,
            }

            # Add URL to findings if missing
            for finding in result.findings:
                if not finding.get("url"):
                    finding["url"] = target_url
                all_findings.append(finding)

        if progress_callback:
            progress_callback(85)

        # Deduplicate and validate findings
        validated_findings = self._deduplicate_findings(all_findings)

        if progress_callback:
            progress_callback(95)

        # Calculate total execution time
        total_time = sum(ts["execution_time"] for ts in tool_stats.values())

        # Generate statistics
        severity_stats = {}
        type_stats = {}
        for finding in validated_findings:
            sev = finding["severity"].lower()
            severity_stats[sev] = severity_stats.get(sev, 0) + 1

            itype = finding["injection_type"]
            type_stats[itype] = type_stats.get(itype, 0) + 1

        # Build per-tool findings count
        tool_findings_count = {}
        for finding in validated_findings:
            t = finding.get("tool", "unknown")
            tool_findings_count[t] = tool_findings_count.get(t, 0) + 1

        # Enrich tool_stats with findings_count from validated findings
        for t_name in tool_stats:
            tool_stats[t_name]["validated_findings"] = tool_findings_count.get(
                t_name, 0
            )

        # Build final result
        result = {
            "scan_info": {
                "target": target_url,
                "domain": plan_data["domain"],
                "parameters": plan_data["parameters"],
                "intensity": intensity,
                "scan_time": datetime.now(UTC).isoformat(),
                "total_execution_time": round(total_time, 2),
                "tools_used": list(tool_stats.keys()),
                "tools_count": len(tool_stats),
            },
            "summary": {
                "total_findings": len(validated_findings),
                "critical": severity_stats.get("critical", 0),
                "high": severity_stats.get("high", 0),
                "medium": severity_stats.get("medium", 0),
                "low": severity_stats.get("low", 0),
                "info": severity_stats.get("info", 0),
                "by_type": type_stats,
                "by_tool": tool_findings_count,
            },
            "tool_results": tool_stats,
            "findings": validated_findings,
        }

        # Save results
        self._save_results(result, plan_data["domain"])

        if progress_callback:
            progress_callback(100)

        return result

    def _deduplicate_findings(self, findings: List[Dict]) -> List[Dict]:
        """Remove duplicate findings based on URL, parameter, injection type, and tool"""
        seen = set()
        unique = []

        for finding in findings:
            # Deduplicate by URL + parameter + injection_type + tool
            key = (
                finding.get("url", ""),
                finding.get("parameter", ""),
                finding.get("injection_type", ""),
                finding.get("tool", ""),
            )

            if key not in seen:
                seen.add(key)
                unique.append(finding)

        return unique

    def _save_results(self, results: Dict, domain: str) -> str:
        """Save scan results to JSON file"""
        results_dir = Path(__file__).parent / "results" / "sqli"
        results_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_domain = re.sub(r"[^\w\-.]", "_", domain)
        filename = f"{safe_domain}_sqli_{timestamp}.json"
        filepath = results_dir / filename

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

        return str(filepath)

    def print_summary(self, results: Dict):
        """Print a human-readable summary of scan results"""
        scan_info = results.get("scan_info", {})
        summary = results["summary"]

        print(f"\n{'='*60}")
        print("SQL INJECTION SCAN SUMMARY")
        print(f"{'='*60}")
        print(f"Target: {scan_info.get('target', 'N/A')}")
        print(f"Tools Used: {', '.join(scan_info.get('tools_used', []))}")
        print(f"Execution Time: {scan_info.get('total_execution_time', 0):.1f}s")

        print(f"\n🎯 Total Findings: {summary['total_findings']}")

        if summary["total_findings"] > 0:
            print("\nSeverity Breakdown:")
            if summary["critical"] > 0:
                print(f"   🔴 CRITICAL: {summary['critical']}")
            if summary["high"] > 0:
                print(f"   🟠 HIGH: {summary['high']}")
            if summary["medium"] > 0:
                print(f"   🟡 MEDIUM: {summary['medium']}")
            if summary["low"] > 0:
                print(f"   🟢 LOW: {summary['low']}")

            if summary.get("by_type"):
                print("\nInjection Types:")
                for itype, count in summary["by_type"].items():
                    print(f"   • {itype}: {count}")

        print(f"\n{'='*60}\n")


# CLI interface
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="SQL Injection Detection Orchestrator")
    parser.add_argument("url", help="Target URL with parameters")
    parser.add_argument(
        "--tools",
        nargs="+",
        choices=["sqlmap", "nuclei", "ghauri"],
        help="Tools to use",
    )
    parser.add_argument(
        "--intensity",
        choices=["basic", "aggressive"],
        default="basic",
        help="Scan intensity",
    )
    parser.add_argument("--output", "-o", help="Output file path")

    args = parser.parse_args()

    orchestrator = SQLiDetectionOrchestrator()

    print(f"\n🔍 Starting SQL Injection scan on: {args.url}")
    print(f"📋 Available tools: {', '.join(orchestrator.get_available_tools())}")

    results = orchestrator.scan(
        target_url=args.url,
        tools=args.tools,
        intensity=args.intensity,
    )

    orchestrator.print_summary(results)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"📄 Results saved to: {args.output}")
