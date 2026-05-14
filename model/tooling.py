import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, Iterable, Optional


REPO_ROOT = Path(__file__).parent.parent
BUILTIN_TOOLS: Dict[str, str] = {
    "custom": "built-in",
}

BUNDLED_TOOLS: Dict[str, Path] = {
    "dirsearch": REPO_ROOT / "tools" / "dirsearch" / "dirsearch.py",
}

TOOL_ALIASES: Dict[str, tuple[str, ...]] = {
    "sqlmap": ("sqlmap.py",),
    "sublist3r": ("sublist3r.py",),
}


def _candidate_names(tool_name: str) -> Iterable[str]:
    yield tool_name
    yield from TOOL_ALIASES.get(tool_name, ())


def _venv_search_paths() -> list[Path]:
    paths: list[Path] = []

    if hasattr(sys, "prefix") and sys.prefix != sys.base_prefix:
        for candidate in [Path(sys.prefix) / "Scripts", Path(sys.prefix) / "bin"]:
            if candidate.exists():
                paths.append(candidate)

    repo_venv = REPO_ROOT / ".venv"
    for candidate in [repo_venv / "Scripts", repo_venv / "bin"]:
        if candidate.exists() and candidate not in paths:
            paths.append(candidate)

    return paths


def _go_search_paths() -> list[Path]:
    go_paths = []
    go_path_env = os.environ.get("GOPATH")
    if go_path_env:
        go_paths.append(Path(go_path_env) / "bin")

    go_paths.extend(
        [
            Path.home() / "go" / "bin",
            Path(r"C:\Program Files\Go\bin"),
            Path("/usr/local/go/bin"),
            Path.home() / ".go" / "bin",
        ]
    )

    return [path for path in go_paths if path.exists()]


def _python_search_paths() -> list[Path]:
    python_paths = [
        Path(sys.prefix) / "Scripts",
        Path.home() / ".local" / "bin",
        Path("/usr/local/bin"),
    ]
    return [path for path in python_paths if path.exists()]


def _resolve_from_directory(directory: Path, name: str) -> Optional[str]:
    for ext in [".exe", ".py", "", ".cmd", ".bat"]:
        candidate = directory / f"{name}{ext}"
        if candidate.exists():
            return str(candidate)
    return None


def get_tool_info(tool_name: str) -> Dict[str, Optional[str] | bool]:
    """Resolve installation details for a tool."""
    if tool_name in BUILTIN_TOOLS:
        return {"installed": True, "path": BUILTIN_TOOLS[tool_name]}

    bundled_path = BUNDLED_TOOLS.get(tool_name)
    if bundled_path and bundled_path.exists():
        return {"installed": True, "path": str(bundled_path)}

    for candidate_name in _candidate_names(tool_name):
        for search_dir in [
            *_venv_search_paths(),
            *_go_search_paths(),
            *_python_search_paths(),
        ]:
            resolved = _resolve_from_directory(search_dir, candidate_name)
            if resolved:
                return {"installed": True, "path": resolved}

        resolved = shutil.which(candidate_name)
        if resolved:
            return {"installed": True, "path": resolved}

    return {"installed": False, "path": None}


def resolve_tool_path(tool_name: str) -> str:
    """Resolve a tool path while preserving legacy fallback behaviour."""
    tool_info = get_tool_info(tool_name)
    return str(tool_info["path"]) if tool_info["path"] else tool_name


def is_tool_installed(tool_name: str) -> bool:
    """Return whether a tool can be resolved on the current host."""
    return bool(get_tool_info(tool_name)["installed"])


def build_tool_status(
    tool_name: str,
    tool_config: Dict[str, object],
) -> Dict[str, object]:
    """Build a normalized tool status payload for API responses."""
    tool_config = tool_config if isinstance(tool_config, dict) else {}
    tool_info = get_tool_info(tool_name)
    installed = bool(tool_info["installed"])
    version = get_tool_version(tool_name, tool_info["path"])

    return {
        "name": tool_name,
        "description": tool_config.get("description", ""),
        "enabled": tool_config.get("enabled", False),
        "installed": installed,
        "status": "ready" if installed else "not_installed",
        "path": tool_info["path"],
        "version": version,
    }


def get_tool_version(tool_name: str, resolved_path: str | None = None) -> str | None:
    if tool_name in BUILTIN_TOOLS:
        return "built-in"

    executable = resolved_path or resolve_tool_path(tool_name)
    if not executable:
        return None

    candidate_commands = []
    executable_path = Path(executable) if isinstance(executable, str) else None

    if executable_path and executable_path.suffix.lower() == ".py":
        candidate_commands.extend(
            [
                [sys.executable, str(executable_path), "--version"],
                [sys.executable, str(executable_path), "-V"],
            ]
        )
    else:
        candidate_commands.extend(
            [
                [str(executable), "--version"],
                [str(executable), "-version"],
                [str(executable), "version"],
                [str(executable), "-V"],
            ]
        )

    for command in candidate_commands:
        output = _run_version_command(command)
        if output:
            return _extract_version(output)

    return None


def build_tool_health_report(config) -> Dict[str, object]:
    groups = {
        "subdomains": config.get_subdomain_tools(),
        "paths": config.get_path_discovery_tools(),
        "xss": config.get_xss_tools(),
        "sqli": config.get_sqli_tools(),
        "lfi": config.get_lfi_tools(),
    }

    modules = {}
    all_tools = []

    for module_name, module_tools in groups.items():
        statuses = []
        for tool_name, tool_config in (module_tools or {}).items():
            try:
                statuses.append(build_tool_status(tool_name, tool_config))
            except Exception as exc:
                statuses.append(
                    {
                        "name": tool_name,
                        "description": (
                            tool_config.get("description", "")
                            if isinstance(tool_config, dict)
                            else ""
                        ),
                        "enabled": (
                            tool_config.get("enabled", False)
                            if isinstance(tool_config, dict)
                            else False
                        ),
                        "installed": False,
                        "status": "error",
                        "path": None,
                        "version": None,
                        "error": str(exc),
                    }
                )
        modules[module_name] = statuses
        all_tools.extend(statuses)

    ready_count = sum(1 for tool in all_tools if tool.get("installed"))
    return {
        "generated_at": Path(__file__).stat().st_mtime,
        "summary": {
            "modules": len(modules),
            "tools": len(all_tools),
            "installed": ready_count,
            "missing": len(all_tools) - ready_count,
        },
        "modules": modules,
    }


def _run_version_command(command: list[str]) -> str | None:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=8,
            creationflags=(subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0),
        )
    except Exception:
        return None

    output = (result.stdout or "").strip() or (result.stderr or "").strip()
    return output or None


def _extract_version(output: str) -> str:
    first_line = output.splitlines()[0].strip()
    normalized = first_line.replace("\x1b", "").strip()

    noisy_prefixes = (
        "usage:",
        "unknown flag:",
        "flag provided but not defined:",
        "[!]",
    )
    if normalized.lower().startswith(noisy_prefixes):
        return None

    return normalized[:120] if normalized else None
