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

    # LFI Detection Tool configurations
    lfi_tools: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    # Execution settings
    parallel_execution: bool = True
    max_workers: int = 5
    use_api_fallback: bool = True  # Use API-based discovery if tools not installed

    # Output settings
    save_results: bool = True
    save_raw_output: bool = False
    output_directory: str = "results"

    # Analysis settings
    perform_dns_validation: bool = True
    check_http_status: bool = False
    dns_timeout: int = 2

    # Filtering
    exclude_wildcard: bool = True
    min_subdomain_length: int = 3

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
            parallel_execution=True,
            max_workers=5,
            save_results=True,
            save_raw_output=False,
            output_directory="results",
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
