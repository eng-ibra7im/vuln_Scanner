#!/usr/bin/env python3
"""
Path Discovery Orchestrator
Academic Security Research Tool

This orchestrator generates execution plans for path/directory discovery tools,
coordinates their execution, analyzes results, and produces structured JSON output.

Tools supported:
- ffuf: Fast web fuzzer for directory/file discovery
- dirsearch: Advanced directory/file brute-forcer
- arjun: HTTP parameter discovery suite
- paramspider: Mining parameters from web archives

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
import os
import base64
import tempfile
import uuid as uuid_mod
from datetime import datetime, UTC
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, asdict, field
from pathlib import Path
from urllib.parse import urlparse, urljoin
import logging

from config import Config


def get_tool_path(tool_name: str) -> str:
    """
    Get the full path to a tool, checking venv Scripts directory first.
    Returns the tool name if not found (will be looked up in PATH).
    """
    # Check if running in a venv
    if hasattr(sys, "prefix") and sys.prefix != sys.base_prefix:
        # We're in a venv
        venv_scripts = Path(sys.prefix) / "Scripts"  # Windows
        if not venv_scripts.exists():
            venv_scripts = Path(sys.prefix) / "bin"  # Linux/Mac

        # Check for common executable extensions
        for ext in [".exe", "", ".cmd", ".bat"]:
            tool_path = venv_scripts / f"{tool_name}{ext}"
            if tool_path.exists():
                return str(tool_path)

    # Check if tool is in PATH
    found = shutil.which(tool_name)
    if found:
        return found

    return tool_name


@dataclass
class PathExecutionPlan:
    """Represents an execution plan for path discovery"""

    tool: str
    command: List[str]
    timeout: int
    priority: int
    description: str
    target_type: str  # 'directory', 'file', 'parameter', 'api'
    output_file: Optional[str] = None  # For tools that write JSON to a file


@dataclass
class DiscoveredPath:
    """Represents a discovered path/endpoint"""

    url: str
    path: str
    status_code: int
    content_length: int
    content_type: str
    discovery_tool: str
    category: str  # 'directory', 'file', 'api', 'admin', 'backup', 'config', 'hidden'
    risk_level: str  # 'critical', 'high', 'medium', 'low', 'info'
    interesting: bool
    notes: List[str] = field(default_factory=list)


@dataclass
class DiscoveredParameter:
    """Represents a discovered parameter"""

    url: str
    parameter: str
    method: str  # 'GET', 'POST', 'BOTH'
    discovery_tool: str
    param_type: str  # 'query', 'body', 'header', 'cookie'
    potential_vuln: List[str] = field(default_factory=list)


@dataclass
class PathToolResult:
    """Represents the result from a single tool execution"""

    tool: str
    success: bool
    paths: List[Dict[str, Any]]
    parameters: List[Dict[str, Any]]
    execution_time: float
    error: Optional[str] = None
    raw_output: Optional[str] = None


class PathDiscoveryOrchestrator:
    """
    Orchestrates path and parameter discovery across multiple tools.
    Generates execution plans, coordinates tool execution, analyzes and classifies results.
    """

    # Interesting path patterns for classification
    CRITICAL_PATTERNS = [
        r"\.env",
        r"\.git",
        r"\.svn",
        r"\.htaccess",
        r"\.htpasswd",
        r"web\.config",
        r"\.aws",
        r"\.ssh",
        r"id_rsa",
        r"\.pem",
        r"credentials",
        r"secrets?\.",
        r"password",
        r"\.key$",
    ]

    HIGH_PATTERNS = [
        r"admin",
        r"administrator",
        r"manager",
        r"panel",
        r"dashboard",
        r"phpmyadmin",
        r"adminer",
        r"cpanel",
        r"plesk",
        r"webmin",
        r"wp-admin",
        r"wp-login",
        r"login",
        r"signin",
        r"auth",
        r"backup",
        r"\.bak$",
        r"\.old$",
        r"\.orig$",
        r"\.save$",
        r"database",
        r"db\.",
        r"sql",
        r"dump",
        r"export",
    ]

    MEDIUM_PATTERNS = [
        r"api",
        r"v1",
        r"v2",
        r"rest",
        r"graphql",
        r"swagger",
        r"debug",
        r"test",
        r"dev",
        r"staging",
        r"beta",
        r"upload",
        r"uploads",
        r"files",
        r"media",
        r"assets",
        r"config",
        r"settings",
        r"setup",
        r"install",
    ]

    INFO_PATTERNS = [
        r"robots\.txt",
        r"sitemap",
        r"humans\.txt",
        r"crossdomain",
        r"favicon",
        r"manifest",
        r"\.well-known",
    ]

    # Interesting file extensions
    SENSITIVE_EXTENSIONS = [
        ".sql",
        ".bak",
        ".old",
        ".log",
        ".conf",
        ".config",
        ".ini",
        ".env",
        ".key",
        ".pem",
        ".crt",
        ".p12",
        ".pfx",
        ".jks",
        ".yml",
        ".yaml",
        ".json",
        ".xml",
        ".zip",
        ".tar",
        ".gz",
        ".rar",
        ".7z",
        ".dump",
        ".swp",
        ".swo",
    ]

    def __init__(self, config: Config = None):
        self.config = config or Config()
        self.logger = self._setup_logging()
        self.discovered_paths: List[DiscoveredPath] = []
        self.discovered_params: List[DiscoveredParameter] = []

    def _setup_logging(self) -> logging.Logger:
        """Configure logging for the orchestrator"""
        logger = logging.getLogger("PathDiscoveryOrchestrator")
        logger.setLevel(logging.INFO)

        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        return logger

    def generate_execution_plan(self, target_url: str) -> Dict[str, Any]:
        """
        Generate execution plans for all configured path discovery tools.

        Args:
            target_url: The target URL to scan

        Returns:
            Dictionary containing execution plans and metadata
        """
        # Normalize URL
        if not target_url.startswith(("http://", "https://")):
            target_url = f"https://{target_url}"

        parsed = urlparse(target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        plans = []
        path_tools = self.config.path_discovery_tools

        # ffuf - Fast directory/file fuzzing
        if path_tools.get("ffuf", {}).get("enabled", False):
            wordlist = path_tools["ffuf"].get("wordlist", "wordlists/paths_common.txt")
            wordlist_path = str(Path(__file__).parent / wordlist)

            plans.append(
                PathExecutionPlan(
                    tool="ffuf",
                    command=[
                        "ffuf",
                        "-u",
                        f"{base_url}/FUZZ",
                        "-w",
                        wordlist_path,
                        "-mc",
                        "200,201,204,301,302,307,308,401,403,405,500",
                        "-fc",
                        "404",
                        "-ac",  # Auto-calibration to filter false positives
                        "-ic",  # Ignore wordlist comments
                        "-json",  # NDJSON output to stdout
                        "-noninteractive",  # No interactive console
                        "-t",
                        "50",  # Threads
                        "-timeout",
                        "10",
                        "-r",  # Follow redirects
                    ],
                    timeout=600,
                    priority=1,
                    description="Fast directory and file fuzzing with common paths",
                    target_type="directory",
                )
            )

            # Additional ffuf scan for file extensions
            plans.append(
                PathExecutionPlan(
                    tool="ffuf",
                    command=[
                        "ffuf",
                        "-u",
                        f"{base_url}/FUZZ",
                        "-w",
                        wordlist_path,
                        "-e",
                        ".php,.asp,.aspx,.jsp,.html,.js,.json,.xml,.txt,.bak,.old,.sql,.log,.zip,.tar.gz",
                        "-mc",
                        "200,201,204,301,302,307,308,401,403,500",
                        "-fc",
                        "404",
                        "-ac",
                        "-ic",
                        "-json",
                        "-noninteractive",
                        "-t",
                        "30",
                        "-timeout",
                        "10",
                    ],
                    timeout=900,
                    priority=2,
                    description="File extension fuzzing for sensitive files",
                    target_type="file",
                )
            )

        # dirsearch - Advanced directory brute-forcer
        if path_tools.get("dirsearch", {}).get("enabled", False):
            wordlist = path_tools["dirsearch"].get(
                "wordlist", "wordlists/paths_common.txt"
            )
            wordlist_path = str(Path(__file__).parent / wordlist)
            # Use cloned dirsearch script
            dirsearch_script = str(
                Path(__file__).parent.parent / "tools" / "dirsearch" / "dirsearch.py"
            )

            plans.append(
                PathExecutionPlan(
                    tool="dirsearch",
                    command=[
                        sys.executable,
                        dirsearch_script,
                        "-u",
                        base_url,
                        "-w",
                        wordlist_path,
                        "-e",
                        "php,asp,aspx,jsp,html,js,json,xml,txt",
                        "-i",
                        "200,201,204,301,302,307,308,401,403,405,500",
                        "-x",
                        "404",
                        "-t",
                        "50",
                        "--timeout",
                        "10",
                        "-q",  # Quiet mode
                        "--full-url",  # Show full URLs in output
                        "--no-color",  # No ANSI colors
                    ],
                    timeout=600,
                    priority=2,
                    description="Advanced recursive directory discovery",
                    target_type="directory",
                )
            )

        # arjun - Parameter discovery
        if path_tools.get("arjun", {}).get("enabled", False):
            # Generate a unique temp file for arjun JSON output
            arjun_output_file = os.path.join(
                tempfile.gettempdir(),
                f"arjun_{uuid_mod.uuid4().hex}.json",
            )
            plans.append(
                PathExecutionPlan(
                    tool="arjun",
                    command=[
                        get_tool_path("arjun"),
                        "-u",
                        target_url,
                        "-m",
                        "GET",
                        "-t",
                        "10",
                        "-o",
                        arjun_output_file,
                    ],
                    timeout=300,
                    priority=3,
                    description="HTTP parameter discovery via fuzzing",
                    target_type="parameter",
                    output_file=arjun_output_file,
                )
            )

        # paramspider - Mining parameters from web archives
        if path_tools.get("paramspider", {}).get("enabled", False):
            domain = parsed.netloc
            plans.append(
                PathExecutionPlan(
                    tool="paramspider",
                    command=[
                        get_tool_path("paramspider"),
                        "-d",
                        domain,
                        "-s",  # Stream output to terminal
                    ],
                    timeout=300,
                    priority=3,
                    description="Mining parameters from web archives (Wayback Machine)",
                    target_type="parameter",
                )
            )

        # Sort by priority
        plans.sort(key=lambda x: x.priority)

        return {
            "target": target_url,
            "base_url": base_url,
            "domain": parsed.netloc,
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
        self, plan: PathExecutionPlan, target_url: str
    ) -> PathToolResult:
        """
        Execute a single tool based on execution plan.

        Args:
            plan: The execution plan to run
            target_url: Target URL for context

        Returns:
            PathToolResult with discovered paths/parameters
        """
        start_time = time.time()

        try:
            self.logger.info(f"[{plan.tool}] Starting: {plan.description}")
            self.logger.debug(
                f"[{plan.tool}] Command: {' '.join(str(x) for x in plan.command)}"
            )

            import platform

            if platform.system() == "Windows":
                # Use synchronous subprocess in thread pool for Windows
                result = await asyncio.to_thread(
                    self._run_subprocess_sync, plan.command, plan.timeout
                )

                raw_output = result["stdout"]
                stderr_output = result["stderr"]
                returncode = result["returncode"]

                if returncode == -1 and "timed out" in stderr_output:
                    return PathToolResult(
                        tool=plan.tool,
                        success=False,
                        paths=[],
                        parameters=[],
                        execution_time=time.time() - start_time,
                        error=f"Timeout after {plan.timeout} seconds",
                    )

                # Combine stdout + stderr for tools that output to stderr
                if not raw_output and stderr_output:
                    raw_output = stderr_output
                elif stderr_output:
                    raw_output = raw_output + "\n" + stderr_output
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
                    return PathToolResult(
                        tool=plan.tool,
                        success=False,
                        paths=[],
                        parameters=[],
                        execution_time=time.time() - start_time,
                        error=f"Timeout after {plan.timeout} seconds",
                    )

                raw_output = stdout.decode("utf-8", errors="ignore")
                stderr_text = stderr.decode("utf-8", errors="ignore")
                if not raw_output and stderr_text:
                    raw_output = stderr_text
                elif stderr_text:
                    raw_output = raw_output + "\n" + stderr_text

            # For tools with file output (e.g. arjun), read the output file
            file_output = ""
            if plan.output_file and os.path.exists(plan.output_file):
                try:
                    with open(plan.output_file, "r", encoding="utf-8") as f:
                        file_output = f.read()
                    os.unlink(plan.output_file)  # Clean up temp file
                    self.logger.info(
                        f"[{plan.tool}] Read output file: {len(file_output)} bytes"
                    )
                except Exception as e:
                    self.logger.warning(
                        f"[{plan.tool}] Failed to read output file: {e}"
                    )

            # Parse results based on tool
            paths, parameters = self._parse_tool_output(
                plan.tool, raw_output, target_url, file_output=file_output
            )

            execution_time = time.time() - start_time
            self.logger.info(
                f"[{plan.tool}] Completed in {execution_time:.2f}s - Found {len(paths)} paths, {len(parameters)} params"
            )

            return PathToolResult(
                tool=plan.tool,
                success=True,
                paths=paths,
                parameters=parameters,
                execution_time=execution_time,
                raw_output=raw_output if self.config.save_raw_output else None,
            )

        except FileNotFoundError:
            self.logger.warning(f"[{plan.tool}] Tool not found, skipping...")
            return PathToolResult(
                tool=plan.tool,
                success=False,
                paths=[],
                parameters=[],
                execution_time=time.time() - start_time,
                error=f"Tool '{plan.tool}' not installed",
            )
        except Exception as e:
            self.logger.error(f"[{plan.tool}] Error: {str(e)}")
            return PathToolResult(
                tool=plan.tool,
                success=False,
                paths=[],
                parameters=[],
                execution_time=time.time() - start_time,
                error=str(e),
            )

    def _parse_tool_output(
        self, tool: str, output: str, target_url: str, file_output: str = ""
    ) -> tuple:
        """
        Parse tool output into structured paths and parameters.

        Args:
            tool: Tool name
            output: Raw output from tool
            target_url: Target URL for context
            file_output: Optional file-based output (e.g. arjun JSON file)

        Returns:
            Tuple of (paths_list, parameters_list)
        """
        paths = []
        parameters = []

        parsed = urlparse(target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        if tool == "ffuf":
            paths = self._parse_ffuf_output(output, base_url)
        elif tool == "dirsearch":
            paths = self._parse_dirsearch_output(output, base_url)
        elif tool == "arjun":
            parameters = self._parse_arjun_output(output, target_url, file_output)
        elif tool == "paramspider":
            parameters = self._parse_paramspider_output(output, target_url)

        return paths, parameters

    def _parse_ffuf_output(self, output: str, base_url: str) -> List[Dict]:
        """Parse ffuf NDJSON output (one JSON object per line)"""
        paths = []
        seen_paths = set()

        for line in output.strip().split("\n"):
            line = line.strip()
            if not line or not line.startswith("{"):
                continue

            try:
                result = json.loads(line)
                url = result.get("url", "")
                if not url:
                    continue

                # Extract path from URL
                parsed = urlparse(url)
                path = parsed.path or "/"

                # Skip empty paths and root duplicates from comments
                if not path or path == "/":
                    # Check if the FUZZ value was a comment (base64 encoded)
                    fuzz_val = result.get("input", {}).get("FUZZ", "")
                    if fuzz_val:
                        try:
                            decoded = base64.b64decode(fuzz_val).decode(
                                "utf-8", errors="ignore"
                            )
                            if decoded.startswith("#") or not decoded.strip():
                                continue
                        except Exception:
                            pass
                    # Skip root path duplicates
                    if path == "/" and "/" in seen_paths:
                        continue

                # Deduplicate
                if path in seen_paths:
                    continue
                seen_paths.add(path)

                paths.append(
                    {
                        "url": url.split("?")[0],  # Clean URL
                        "path": path,
                        "status_code": result.get("status", 0),
                        "content_length": result.get("length", 0),
                        "content_type": result.get("content-type", ""),
                        "discovery_tool": "ffuf",
                        "words": result.get("words", 0),
                        "lines": result.get("lines", 0),
                    }
                )
            except json.JSONDecodeError:
                continue

        return paths

    def _parse_dirsearch_output(self, output: str, base_url: str) -> List[Dict]:
        """Parse dirsearch plain text output.

        Format: [timestamp] STATUS - SIZE - URL (-> REDIRECT)?
        Example: [13:21:01] 200 -   307B - http://example.com/file.xml
        Example: [13:21:01] 301 -   169B - http://example.com/admin  ->  http://example.com/admin/
        """
        paths = []
        seen_urls = set()

        for line in output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue

            # Match dirsearch quiet mode output with full URLs
            # Format: [HH:MM:SS] STATUS - SIZE - URL (-> REDIRECT)?
            match = re.search(
                r"\[\d{2}:\d{2}:\d{2}\]\s+(\d+)\s+-\s+(\S+)\s+-\s+(\S+)",
                line,
            )
            if match:
                status = int(match.group(1))
                size_str = match.group(2)
                url = match.group(3)

                # Deduplicate
                if url in seen_urls:
                    continue
                seen_urls.add(url)

                # Parse size (e.g., "307B", "5KB", "1MB")
                content_length = 0
                size_match = re.match(
                    r"(\d+(?:\.\d+)?)\s*(B|KB|MB|GB)?", size_str, re.IGNORECASE
                )
                if size_match:
                    size_val = float(size_match.group(1))
                    unit = (size_match.group(2) or "B").upper()
                    multipliers = {
                        "B": 1,
                        "KB": 1024,
                        "MB": 1048576,
                        "GB": 1073741824,
                    }
                    content_length = int(size_val * multipliers.get(unit, 1))

                # Extract path from URL
                parsed = urlparse(url)
                path = parsed.path or "/"

                # Check for redirect
                redirect = ""
                redirect_match = re.search(r"->\s+(\S+)", line)
                if redirect_match:
                    redirect = redirect_match.group(1)

                paths.append(
                    {
                        "url": url,
                        "path": path,
                        "status_code": status,
                        "content_length": content_length,
                        "content_type": "",
                        "discovery_tool": "dirsearch",
                        "redirect": redirect,
                    }
                )

        return paths

    def _parse_arjun_output(
        self, output: str, target_url: str, file_output: str = ""
    ) -> List[Dict]:
        """Parse arjun parameter discovery output.

        Handles both:
        1. JSON file output (written by arjun -o file.json)
        2. Stdout text output with patterns like:
           - 'Extracted N parameters from response for testing: param1, param2'
           - 'parameter detected: name, based on: reason'
           - 'Parameters found: param1, param2'
        """
        parameters = []
        seen_params = set()

        # 1. Try to parse JSON file output first (most reliable)
        if file_output and file_output.strip():
            try:
                data = json.loads(file_output)
                # Arjun JSON format: {"URL": {"method": "GET", "params": [...], "headers": {...}}}
                for url, url_data in data.items():
                    if isinstance(url_data, dict):
                        method = url_data.get("method", "GET")
                        params = url_data.get("params", [])
                        for param in params:
                            param_name = str(param)
                            if param_name not in seen_params:
                                seen_params.add(param_name)
                                parameters.append(
                                    {
                                        "url": url or target_url,
                                        "parameter": param_name,
                                        "method": method,
                                        "discovery_tool": "arjun",
                                        "param_type": (
                                            "query" if method == "GET" else "body"
                                        ),
                                        "source": "discovered",
                                    }
                                )
                    elif isinstance(url_data, list):
                        # Alternative format: {"URL": ["param1", "param2"]}
                        for param in url_data:
                            param_name = str(param)
                            if param_name not in seen_params:
                                seen_params.add(param_name)
                                parameters.append(
                                    {
                                        "url": url or target_url,
                                        "parameter": param_name,
                                        "method": "GET",
                                        "discovery_tool": "arjun",
                                        "param_type": "query",
                                        "source": "discovered",
                                    }
                                )
            except (json.JSONDecodeError, Exception) as e:
                self.logger.warning(f"[arjun] Failed to parse JSON output: {e}")

        # 2. Parse stdout text output for additional parameters
        if output:
            for line in output.strip().split("\n"):
                line = line.strip()
                if not line:
                    continue

                # Pattern: "Extracted N parameters from response for testing: param1, param2"
                extracted_match = re.search(
                    r"Extracted \d+ parameters? from response for testing:\s*(.+)",
                    line,
                )
                if extracted_match:
                    params_str = extracted_match.group(1).strip()
                    for param in params_str.split(","):
                        param_name = param.strip()
                        if param_name and param_name not in seen_params:
                            seen_params.add(param_name)
                            parameters.append(
                                {
                                    "url": target_url,
                                    "parameter": param_name,
                                    "method": "GET",
                                    "discovery_tool": "arjun",
                                    "param_type": "query",
                                    "source": "html_form",
                                }
                            )
                    continue

                # Pattern: "parameter detected: name, based on: reason"
                detected_match = re.search(r"parameter detected:\s*(\w+)", line)
                if detected_match:
                    param_name = detected_match.group(1).strip()
                    if param_name and param_name not in seen_params:
                        seen_params.add(param_name)
                        parameters.append(
                            {
                                "url": target_url,
                                "parameter": param_name,
                                "method": "GET",
                                "discovery_tool": "arjun",
                                "param_type": "query",
                                "source": "discovered",
                            }
                        )
                    continue

                # Pattern: "Parameters found: param1, param2"
                found_match = re.search(r"Parameters found:\s*(.+)", line)
                if found_match:
                    params_str = found_match.group(1).strip()
                    for param in params_str.split(","):
                        param_name = param.strip()
                        if param_name and param_name not in seen_params:
                            seen_params.add(param_name)
                            parameters.append(
                                {
                                    "url": target_url,
                                    "parameter": param_name,
                                    "method": "GET",
                                    "discovery_tool": "arjun",
                                    "param_type": "query",
                                    "source": "discovered",
                                }
                            )
                    continue

        return parameters

    def _parse_paramspider_output(self, output: str, target_url: str) -> List[Dict]:
        """Parse paramspider output"""
        parameters = []
        seen_params = set()

        for line in output.strip().split("\n"):
            if not line or line.startswith("#"):
                continue

            # Extract parameters from URLs
            try:
                parsed = urlparse(line.strip())
                if parsed.query:
                    for param in parsed.query.split("&"):
                        if "=" in param:
                            param_name = param.split("=")[0]
                            if param_name and param_name not in seen_params:
                                seen_params.add(param_name)
                                parameters.append(
                                    {
                                        "url": line.strip(),
                                        "parameter": param_name,
                                        "method": "GET",
                                        "discovery_tool": "paramspider",
                                        "param_type": "query",
                                        "source": "wayback",
                                    }
                                )
            except Exception:
                continue

        return parameters

    def _filter_false_positives(self, paths: List[Dict]) -> List[Dict]:
        """
        Filter out false positives from discovered paths.

        This detects wildcard responses where the server returns the same
        response for any path (common on sites that don't return proper 404s).

        Args:
            paths: List of discovered paths

        Returns:
            Filtered list with false positives removed
        """
        if len(paths) < 3:
            return paths

        # Analyze content lengths and response characteristics
        content_lengths = {}
        status_codes = {}

        for path in paths:
            cl = path.get("content_length", 0)
            sc = path.get("status_code", 0)

            content_lengths[cl] = content_lengths.get(cl, 0) + 1
            status_codes[sc] = status_codes.get(sc, 0) + 1

        # Find the most common content length
        if content_lengths:
            most_common_length, count = max(content_lengths.items(), key=lambda x: x[1])
            total = len(paths)

            # If more than 80% have the same content length, likely false positives
            if count / total > 0.8:
                self.logger.warning(
                    f"Detected wildcard response: {count}/{total} paths have the same content length ({most_common_length})"
                )

                # Only keep paths with different content lengths (more likely to be real)
                filtered = [
                    p for p in paths if p.get("content_length", 0) != most_common_length
                ]

                # If filtering removed everything, return original (site might just have same-size pages)
                if not filtered:
                    self.logger.info(
                        "All paths have same content length - keeping critical/high risk only"
                    )
                    # Keep only potentially interesting paths
                    return [p for p in paths if self._is_potentially_interesting(p)]

                return filtered

        # Check for same words/lines count (another false positive indicator)
        words_counts = {}
        for path in paths:
            wc = path.get("words", 0)
            words_counts[wc] = words_counts.get(wc, 0) + 1

        if words_counts:
            most_common_words, count = max(words_counts.items(), key=lambda x: x[1])
            if count / len(paths) > 0.9 and most_common_words > 0:
                self.logger.warning(
                    f"Wildcard detected via word count: {most_common_words}"
                )
                return [p for p in paths if p.get("words", 0) != most_common_words]

        return paths

    def _is_potentially_interesting(self, path_info: Dict) -> bool:
        """Check if a path is potentially interesting even with wildcard response."""
        path = path_info.get("path", "").lower()

        # Check against critical and high-risk patterns
        interesting_patterns = [
            r"\.env",
            r"\.git",
            r"\.htaccess",
            r"\.htpasswd",
            r"config",
            r"admin",
            r"backup",
            r"\.bak",
            r"\.sql",
            r"wp-config",
            r"database",
            r"credentials",
            r"secret",
            r"api/",
            r"graphql",
            r"swagger",
            r"\.json$",
            r"\.xml$",
        ]

        return any(re.search(p, path) for p in interesting_patterns)

    def classify_path(self, path_info: Dict) -> DiscoveredPath:
        """
        Classify a discovered path based on patterns and characteristics.

        Args:
            path_info: Dictionary containing path information

        Returns:
            DiscoveredPath with classification
        """
        path = path_info.get("path", "").lower()
        url = path_info.get("url", "")
        status = path_info.get("status_code", 0)
        content_type = path_info.get("content_type", "").lower()

        # Determine category
        category = "directory"
        if any(path.endswith(ext) for ext in self.SENSITIVE_EXTENSIONS):
            category = "file"
        elif any(re.search(p, path) for p in [r"api", r"v\d", r"rest", r"graphql"]):
            category = "api"
        elif any(
            re.search(p, path) for p in [r"admin", r"panel", r"dashboard", r"manage"]
        ):
            category = "admin"
        elif any(
            re.search(p, path) for p in [r"\.bak", r"backup", r"\.old", r"\.orig"]
        ):
            category = "backup"
        elif any(
            re.search(p, path) for p in [r"config", r"\.env", r"settings", r"\.ini"]
        ):
            category = "config"
        elif any(
            re.search(p, path) for p in [r"\.git", r"\.svn", r"\.hg", r"\.DS_Store"]
        ):
            category = "hidden"

        # Determine risk level
        risk_level = "info"
        notes = []

        if any(re.search(p, path) for p in self.CRITICAL_PATTERNS):
            risk_level = "critical"
            notes.append("Contains sensitive file pattern")
        elif any(re.search(p, path) for p in self.HIGH_PATTERNS):
            risk_level = "high"
            notes.append("Administrative or backup content")
        elif any(re.search(p, path) for p in self.MEDIUM_PATTERNS):
            risk_level = "medium"
            notes.append("Development/API endpoint")
        elif any(re.search(p, path) for p in self.INFO_PATTERNS):
            risk_level = "low"

        # Status code based risk adjustment
        if status == 401:
            notes.append("Authentication required")
            if risk_level == "info":
                risk_level = "medium"
        elif status == 403:
            notes.append("Forbidden - exists but restricted")
            if risk_level == "info":
                risk_level = "low"
        elif status == 500:
            notes.append("Server error - potential vulnerability")
            if risk_level in ["info", "low"]:
                risk_level = "medium"

        # Check for interesting content types
        if content_type:
            if "json" in content_type:
                notes.append("JSON response")
            elif "xml" in content_type:
                notes.append("XML response")
            elif "text/plain" in content_type:
                notes.append("Plain text file")

        interesting = risk_level in ["critical", "high"] or category in [
            "admin",
            "config",
            "hidden",
            "backup",
        ]

        return DiscoveredPath(
            url=url,
            path=path_info.get("path", ""),
            status_code=status,
            content_length=path_info.get("content_length", 0),
            content_type=path_info.get("content_type", ""),
            discovery_tool=path_info.get("discovery_tool", ""),
            category=category,
            risk_level=risk_level,
            interesting=interesting,
            notes=notes,
        )

    def classify_parameter(self, param_info: Dict) -> DiscoveredParameter:
        """
        Classify a discovered parameter and identify potential vulnerabilities.

        Args:
            param_info: Dictionary containing parameter information

        Returns:
            DiscoveredParameter with vulnerability assessment
        """
        param = param_info.get("parameter", "").lower()
        potential_vulns = []

        # SQL Injection indicators
        if any(
            p in param
            for p in [
                "id",
                "user",
                "item",
                "product",
                "category",
                "order",
                "sort",
                "page",
                "limit",
                "offset",
                "select",
                "where",
            ]
        ):
            potential_vulns.append("SQL Injection")

        # XSS indicators
        if any(
            p in param
            for p in [
                "search",
                "query",
                "q",
                "keyword",
                "message",
                "comment",
                "name",
                "title",
                "content",
                "text",
                "value",
                "input",
            ]
        ):
            potential_vulns.append("XSS")

        # Path Traversal indicators
        if any(
            p in param
            for p in [
                "file",
                "path",
                "folder",
                "dir",
                "document",
                "doc",
                "filename",
                "filepath",
                "include",
                "load",
                "read",
            ]
        ):
            potential_vulns.append("Path Traversal/LFI")

        # SSRF indicators
        if any(
            p in param
            for p in [
                "url",
                "link",
                "uri",
                "src",
                "source",
                "redirect",
                "next",
                "return",
                "callback",
                "domain",
                "host",
                "site",
            ]
        ):
            potential_vulns.append("SSRF/Open Redirect")

        # Command Injection indicators
        if any(
            p in param
            for p in [
                "cmd",
                "command",
                "exec",
                "execute",
                "run",
                "shell",
                "system",
                "ping",
                "host",
                "ip",
            ]
        ):
            potential_vulns.append("Command Injection")

        # IDOR indicators
        if any(
            p in param
            for p in [
                "id",
                "uid",
                "userid",
                "user_id",
                "accountid",
                "account",
                "profile",
                "order_id",
                "invoice",
            ]
        ):
            potential_vulns.append("IDOR")

        return DiscoveredParameter(
            url=param_info.get("url", ""),
            parameter=param_info.get("parameter", ""),
            method=param_info.get("method", "GET"),
            discovery_tool=param_info.get("discovery_tool", ""),
            param_type=param_info.get("param_type", "query"),
            potential_vuln=potential_vulns,
        )

    async def discover(
        self, target_url: str, tools: List[str] = None
    ) -> Dict[str, Any]:
        """
        Run full path discovery on target URL.

        Args:
            target_url: Target URL to scan
            tools: Optional list of specific tools to use

        Returns:
            Structured JSON results
        """
        start_time = time.time()

        # Generate execution plan
        plan_data = self.generate_execution_plan(target_url)
        plans = [PathExecutionPlan(**p) for p in plan_data["execution_plans"]]

        # Filter tools if specified
        if tools:
            plans = [p for p in plans if p.tool in tools]

        if not plans:
            return {
                "success": False,
                "error": "No enabled tools available",
                "target": target_url,
                "timestamp": datetime.now(UTC).isoformat(),
            }

        self.logger.info(f"Starting path discovery on {target_url}")
        self.logger.info(f"Running {len(plans)} tool execution(s)")

        # Execute tools
        all_paths = []
        all_parameters = []
        tool_results = []

        if self.config.parallel_execution:
            tasks = [self.execute_tool(plan, target_url) for plan in plans]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, Exception):
                    self.logger.error(f"Tool execution error: {result}")
                    continue
                tool_results.append(result)
                all_paths.extend(result.paths)
                all_parameters.extend(result.parameters)
        else:
            for plan in plans:
                result = await self.execute_tool(plan, target_url)
                tool_results.append(result)
                all_paths.extend(result.paths)
                all_parameters.extend(result.parameters)

        # Deduplicate paths
        unique_paths = {}
        for path in all_paths:
            key = path.get("path", "").lower()
            if key not in unique_paths:
                unique_paths[key] = path

        # Deduplicate parameters
        unique_params = {}
        for param in all_parameters:
            key = f"{param.get('parameter', '')}_{param.get('method', '')}"
            if key not in unique_params:
                unique_params[key] = param

        # Filter false positives
        filtered_paths = self._filter_false_positives(list(unique_paths.values()))
        self.logger.info(
            f"Filtered {len(unique_paths) - len(filtered_paths)} false positives"
        )

        # Classify all discoveries
        classified_paths = [self.classify_path(p) for p in filtered_paths]
        classified_params = [self.classify_parameter(p) for p in unique_params.values()]

        # Sort by risk level
        risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        classified_paths.sort(key=lambda x: (risk_order.get(x.risk_level, 5), x.path))

        # Generate statistics
        total_time = time.time() - start_time

        path_stats = {
            "total": len(classified_paths),
            "by_category": {},
            "by_risk": {},
            "interesting_count": sum(1 for p in classified_paths if p.interesting),
        }

        for path in classified_paths:
            path_stats["by_category"][path.category] = (
                path_stats["by_category"].get(path.category, 0) + 1
            )
            path_stats["by_risk"][path.risk_level] = (
                path_stats["by_risk"].get(path.risk_level, 0) + 1
            )

        param_stats = {
            "total": len(classified_params),
            "by_method": {},
            "vulnerable_candidates": sum(
                1 for p in classified_params if p.potential_vuln
            ),
        }

        for param in classified_params:
            param_stats["by_method"][param.method] = (
                param_stats["by_method"].get(param.method, 0) + 1
            )

        # Build result
        result = {
            "success": True,
            "target": target_url,
            "base_url": plan_data["base_url"],
            "domain": plan_data["domain"],
            "scan_timestamp": datetime.now(UTC).isoformat(),
            "execution_time": round(total_time, 2),
            "tools_executed": [
                {
                    "tool": r.tool,
                    "success": r.success,
                    "execution_time": round(r.execution_time, 2),
                    "paths_found": len(r.paths),
                    "params_found": len(r.parameters),
                    "error": r.error,
                }
                for r in tool_results
            ],
            "summary": {"paths": path_stats, "parameters": param_stats},
            "discovered_paths": [asdict(p) for p in classified_paths],
            "discovered_parameters": [asdict(p) for p in classified_params],
            "interesting_findings": {
                "critical_paths": [
                    asdict(p) for p in classified_paths if p.risk_level == "critical"
                ],
                "high_risk_paths": [
                    asdict(p) for p in classified_paths if p.risk_level == "high"
                ],
                "admin_panels": [
                    asdict(p) for p in classified_paths if p.category == "admin"
                ],
                "config_files": [
                    asdict(p) for p in classified_paths if p.category == "config"
                ],
                "backup_files": [
                    asdict(p) for p in classified_paths if p.category == "backup"
                ],
                "api_endpoints": [
                    asdict(p) for p in classified_paths if p.category == "api"
                ],
                "vulnerable_params": [
                    asdict(p) for p in classified_params if p.potential_vuln
                ],
            },
        }

        # Save results if configured
        if self.config.save_results:
            self._save_results(result, plan_data["domain"])

        return result

    def _save_results(self, results: Dict, domain: str):
        """Save scan results to file"""
        output_dir = Path(__file__).parent / self.config.output_directory / "paths"
        output_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_domain = domain.replace(".", "_").replace(":", "_")
        filename = f"{safe_domain}_paths_{timestamp}.json"

        filepath = output_dir / filename
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

        self.logger.info(f"Results saved to {filepath}")


# CLI Interface
async def main():
    """Command line interface for path discovery"""
    import argparse

    parser = argparse.ArgumentParser(
        description="Path Discovery Orchestrator - Academic Security Research Tool"
    )
    parser.add_argument("target", help="Target URL to scan")
    parser.add_argument(
        "--tools",
        nargs="+",
        choices=["ffuf", "dirsearch", "arjun", "paramspider"],
        help="Specific tools to use",
    )
    parser.add_argument(
        "--plan-only",
        action="store_true",
        help="Only generate execution plan, don't run",
    )
    parser.add_argument(
        "--json", action="store_true", help="Output in JSON format only"
    )

    args = parser.parse_args()

    config = Config.load()
    orchestrator = PathDiscoveryOrchestrator(config)

    if args.plan_only:
        plan = orchestrator.generate_execution_plan(args.target)
        print(json.dumps(plan, indent=2))
        return

    results = await orchestrator.discover(args.target, args.tools)

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        # Pretty print summary
        print("\n" + "=" * 60)
        print(f"PATH DISCOVERY RESULTS: {args.target}")
        print("=" * 60)

        if results["success"]:
            summary = results["summary"]
            print(f"\n📁 Total Paths Found: {summary['paths']['total']}")
            print(f"🔍 Interesting: {summary['paths']['interesting_count']}")
            print(f"⚙️  Parameters Found: {summary['parameters']['total']}")

            print("\n📊 Paths by Risk Level:")
            for risk, count in sorted(summary["paths"]["by_risk"].items()):
                emoji = {
                    "critical": "🔴",
                    "high": "🟠",
                    "medium": "🟡",
                    "low": "🟢",
                    "info": "⚪",
                }.get(risk, "⚪")
                print(f"   {emoji} {risk.upper()}: {count}")

            print("\n📂 Paths by Category:")
            for cat, count in summary["paths"]["by_category"].items():
                print(f"   • {cat}: {count}")

            findings = results["interesting_findings"]
            if findings["critical_paths"]:
                print("\n🚨 CRITICAL FINDINGS:")
                for p in findings["critical_paths"][:10]:
                    print(f"   [{p['status_code']}] {p['path']}")

            if findings["admin_panels"]:
                print("\n🔐 Admin Panels:")
                for p in findings["admin_panels"][:5]:
                    print(f"   [{p['status_code']}] {p['path']}")

            if findings["vulnerable_params"]:
                print("\n⚠️  Potentially Vulnerable Parameters:")
                for p in findings["vulnerable_params"][:10]:
                    vulns = ", ".join(p["potential_vuln"])
                    print(f"   • {p['parameter']} ({p['method']}) - {vulns}")
        else:
            print(f"\n❌ Scan failed: {results.get('error', 'Unknown error')}")

        print("\n" + "=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
