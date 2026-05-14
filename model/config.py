"""
Configuration management for Subdomain Enumeration Orchestrator
"""

import json
from pathlib import Path
from typing import Dict, Any
from dataclasses import dataclass, field


@dataclass
class Config:
    """Configuration for the subdomain orchestrator"""

    # Tool configurations
    tools: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    # Path Discovery Tool configurations
    path_discovery_tools: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    # XSS Detection Tool configurations
    xss_tools: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    # SQL Injection Tool configurations
    sqli_tools: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    # LFI Detection Tool configurations
    lfi_tools: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    # Product intelligence / correlation rules
    intelligence_rules: Dict[str, Any] = field(default_factory=dict)

    # Scan profile presets
    scan_profiles: Dict[str, Any] = field(default_factory=dict)

    # Execution settings
    parallel_execution: bool = True
    max_workers: int = 5
    use_api_fallback: bool = True  # Use API-based discovery if tools not installed

    # Output settings
    save_results: bool = True
    save_raw_output: bool = False
    output_directory: str = "results"
    database_path: str = "results/scan_jobs.sqlite3"

    # Dashboard/API protection
    dashboard_auth: Dict[str, Any] = field(default_factory=dict)
    rate_limit: Dict[str, Any] = field(default_factory=dict)

    # Analysis settings
    perform_dns_validation: bool = True
    check_http_status: bool = False
    dns_timeout: int = 2

    # Filtering
    exclude_wildcard: bool = True
    min_subdomain_length: int = 3

    def __post_init__(self):
        """Normalize legacy configuration shapes and guard invalid values."""
        module_config_fields = (
            "path_discovery_tools",
            "xss_tools",
            "sqli_tools",
            "lfi_tools",
        )

        for field_name in module_config_fields:
            current_value = getattr(self, field_name, {})
            legacy_value = self.tools.get(field_name)
            if not current_value and isinstance(legacy_value, dict):
                setattr(self, field_name, legacy_value.copy())

        try:
            self.dns_timeout = max(1, int(self.dns_timeout))
        except (TypeError, ValueError):
            self.dns_timeout = 2

    @classmethod
    def load(cls, config_path: str = "config.json") -> "Config":
        """
        Load configuration from JSON file.

        Args:
            config_path: Path to configuration file

        Returns:
            Config object
        """
        config_file = Path(config_path)

        if not config_file.exists():
            # Return default configuration
            return cls.get_default()

        with open(config_file, "r") as f:
            data = json.load(f)

        return cls(**data)

    @classmethod
    def get_default(cls) -> "Config":
        """
        Get default configuration with all tools enabled.

        Returns:
            Config object with default settings
        """
        return cls(
            tools={
                "subfinder": {
                    "enabled": True,
                    "description": "Fast passive subdomain enumeration",
                },
                "amass": {
                    "enabled": True,
                    "mode": "passive",  # 'passive' or 'active'
                    "description": "Comprehensive subdomain enumeration",
                },
                "sublist3r": {
                    "enabled": False,  # Often slower, disabled by default
                    "description": "Multi-source enumeration via search engines",
                },
                "assetfinder": {
                    "enabled": True,
                    "description": "Quick passive subdomain discovery",
                },
                "ffuf": {
                    "enabled": False,  # Requires wordlist, disabled by default
                    "wordlist": "wordlists/dns_common.txt",
                    "description": "DNS brute forcing",
                },
            },
            path_discovery_tools={
                "ffuf": {
                    "enabled": True,
                    "wordlist": "wordlists/paths_common.txt",
                    "description": "Fast web fuzzer for directory/file discovery",
                },
                "dirsearch": {
                    "enabled": True,
                    "wordlist": "wordlists/paths_common.txt",
                    "description": "Advanced recursive directory discovery",
                },
                "arjun": {
                    "enabled": True,
                    "description": "HTTP parameter discovery via fuzzing",
                },
                "paramspider": {
                    "enabled": True,
                    "description": "Mining parameters from web archives",
                },
            },
            xss_tools={
                "dalfox": {
                    "enabled": True,
                    "description": "Parameter Analysis and XSS Scanning tool",
                },
                "nuclei": {
                    "enabled": True,
                    "templates": "http/vulnerabilities/xss/",
                    "description": "Fast vulnerability scanner with XSS templates",
                },
                "xsstrike": {
                    "enabled": True,
                    "description": "Advanced XSS Detection Suite",
                },
            },
            sqli_tools={
                "sqlmap": {
                    "enabled": True,
                    "description": "Automatic SQL injection detection tool",
                },
                "nuclei": {
                    "enabled": True,
                    "description": "Fast template-based SQLi scanning",
                },
                "ghauri": {
                    "enabled": True,
                    "description": "Advanced cross-platform SQLi detection",
                },
            },
            lfi_tools={
                "ffuf": {
                    "enabled": True,
                    "wordlist": "wordlists/lfi_payloads.txt",
                    "description": "Fast LFI fuzzing with custom payloads",
                },
                "dotdotpwn": {
                    "enabled": False,
                    "description": "Automated directory traversal detection",
                },
                "custom": {
                    "enabled": True,
                    "description": "Custom LFI payload testing with signature detection",
                },
            },
            intelligence_rules={
                "enabled": True,
                "auto_follow_up": True,
                "preferred_scheme": "https",
                "max_auto_targets_per_rule": 5,
                "subdomain_triggers": {
                    "priority_threshold": "high",
                    "require_active": True,
                    "classification_keywords": [
                        "admin",
                        "api",
                        "development",
                        "database",
                        "auth",
                        "login",
                    ],
                    "follow_up_modules": ["path"],
                },
                "path_triggers": {
                    "default_query_value": "scan",
                    "path_keyword_modules": {
                        "admin": ["xss", "sqli", "lfi"],
                        "auth": ["xss", "sqli"],
                        "login": ["xss", "sqli"],
                        "account": ["xss", "sqli"],
                        "profile": ["xss"],
                        "api": ["xss", "sqli"],
                        "file": ["lfi"],
                        "include": ["lfi"],
                        "download": ["lfi"],
                    },
                    "parameter_vuln_modules": {
                        "XSS": ["xss"],
                        "SQL Injection": ["sqli"],
                        "Path Traversal/LFI": ["lfi"],
                    },
                },
            },
            scan_profiles={},
            parallel_execution=True,
            max_workers=5,
            save_results=True,
            save_raw_output=False,
            output_directory="results",
            database_path="results/scan_jobs.sqlite3",
            dashboard_auth={
                "enabled": False,
                "require_outside_localhost": True,
                "username": "admin",
                "password": "change-me",
            },
            rate_limit={
                "enabled": True,
                "requests": 120,
                "window_seconds": 60,
                "localhost_multiplier": 5,
            },
            perform_dns_validation=True,
            check_http_status=False,
            dns_timeout=2,
            exclude_wildcard=True,
            min_subdomain_length=3,
        )

    def save(self, config_path: str = "config.json"):
        """
        Save configuration to JSON file.

        Args:
            config_path: Path to save configuration
        """
        from dataclasses import asdict

        with open(config_path, "w") as f:
            json.dump(asdict(self), f, indent=2)

    def enable_tool(self, tool_name: str):
        """Enable a specific tool"""
        if tool_name in self.tools:
            self.tools[tool_name]["enabled"] = True

    def disable_tool(self, tool_name: str):
        """Disable a specific tool"""
        if tool_name in self.tools:
            self.tools[tool_name]["enabled"] = False

    def get_enabled_tools(self) -> list:
        """Get list of enabled tool names"""
        return [
            tool
            for tool, settings in self.tools.items()
            if settings.get("enabled", False)
        ]

    def get_subdomain_tools(self) -> Dict[str, Dict[str, Any]]:
        """Return subdomain tool configuration."""
        return self.tools

    def get_path_discovery_tools(self) -> Dict[str, Dict[str, Any]]:
        """Return normalized path discovery tool configuration."""
        return self.path_discovery_tools

    def get_xss_tools(self) -> Dict[str, Dict[str, Any]]:
        """Return normalized XSS tool configuration."""
        return self.xss_tools

    def get_sqli_tools(self) -> Dict[str, Dict[str, Any]]:
        """Return normalized SQL injection tool configuration."""
        return self.sqli_tools

    def get_lfi_tools(self) -> Dict[str, Dict[str, Any]]:
        """Return normalized LFI tool configuration."""
        if self.lfi_tools:
            return self.lfi_tools

        legacy_lfi_tools = self.tools.get("lfi_tools", {})
        return legacy_lfi_tools if isinstance(legacy_lfi_tools, dict) else {}

    def get_intelligence_rules(self) -> Dict[str, Any]:
        """Return normalized product-intelligence rules."""
        defaults = self.get_default().intelligence_rules
        merged = json.loads(json.dumps(defaults))

        def merge_dict(base: Dict[str, Any], override: Dict[str, Any]):
            for key, value in override.items():
                if isinstance(value, dict) and isinstance(base.get(key), dict):
                    merge_dict(base[key], value)
                else:
                    base[key] = value

        if isinstance(self.intelligence_rules, dict):
            merge_dict(merged, self.intelligence_rules)

        return merged

    def get_scan_profiles(self) -> Dict[str, Any]:
        """Return configured scan-profile overrides."""
        return self.scan_profiles if isinstance(self.scan_profiles, dict) else {}

    def get_dashboard_auth(self) -> Dict[str, Any]:
        """Return normalized dashboard authentication settings."""
        defaults = self.get_default().dashboard_auth
        merged = defaults.copy()
        if isinstance(self.dashboard_auth, dict):
            merged.update(self.dashboard_auth)
        return merged

    def get_rate_limit(self) -> Dict[str, Any]:
        """Return normalized API rate-limit settings."""
        defaults = self.get_default().rate_limit
        merged = defaults.copy()
        if isinstance(self.rate_limit, dict):
            merged.update(self.rate_limit)
        return merged

    def get_database_path(self, base_path: Path = None) -> Path:
        """Resolve the configured SQLite path."""
        db_path = Path(self.database_path)
        if not db_path.is_absolute():
            base = Path(base_path) if base_path is not None else Path.cwd()
            db_path = base / db_path
        return db_path

    def get_results_dir(
        self, module_name: str = None, base_path: Path = None
    ) -> Path:
        """Resolve the configured results directory, optionally scoped per module."""
        output_dir = Path(self.output_directory)
        if not output_dir.is_absolute():
            base = Path(base_path) if base_path is not None else Path.cwd()
            output_dir = base / output_dir

        module_subdirs = {
            "subdomains": "subdomains",
            "paths": "paths",
            "xss": "xss",
            "sqli": "sqli",
            "lfi": "lfi",
            "reports": "reports",
        }

        if module_name:
            output_dir = output_dir / module_subdirs.get(module_name, module_name)

        return output_dir


def create_default_config(output_path: str = "config.json"):
    """
    Create a default configuration file.

    Args:
        output_path: Path where to save the configuration
    """
    config = Config.get_default()
    config.save(output_path)
    print(f"Default configuration created at: {output_path}")


if __name__ == "__main__":
    # Generate default config when run directly
    create_default_config()
