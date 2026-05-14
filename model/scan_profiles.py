from copy import deepcopy
from typing import Any, Dict


DEFAULT_SCAN_PROFILES: Dict[str, Dict[str, Any]] = {
    "quick": {
        "label": "Quick",
        "description": "Fast validation with the minimum useful toolset.",
        "subdomains": {
            "tools": ["subfinder", "assetfinder"],
            "parallel": True,
            "validate_dns": False,
        },
        "paths": {
            "tools": ["ffuf"],
            "parallel": False,
        },
        "xss": {
            "tools": ["dalfox"],
        },
        "sqli": {
            "tools": ["nuclei"],
            "intensity": "basic",
            "options": {"timeout": 120},
        },
        "lfi": {
            "tools": ["custom"],
        },
    },
    "standard": {
        "label": "Standard",
        "description": "Balanced coverage for regular assessments.",
        "subdomains": {
            "tools": ["subfinder", "amass", "assetfinder"],
            "parallel": True,
            "validate_dns": True,
        },
        "paths": {
            "tools": ["ffuf", "dirsearch", "paramspider"],
            "parallel": True,
        },
        "xss": {
            "tools": ["dalfox", "nuclei"],
        },
        "sqli": {
            "tools": ["sqlmap", "nuclei"],
            "intensity": "basic",
            "options": {"timeout": 180},
        },
        "lfi": {
            "tools": ["ffuf", "custom"],
        },
    },
    "deep": {
        "label": "Deep",
        "description": "Broader and slower scans for higher coverage.",
        "subdomains": {
            "tools": ["subfinder", "amass", "assetfinder", "sublist3r", "ffuf"],
            "parallel": True,
            "validate_dns": True,
        },
        "paths": {
            "tools": ["ffuf", "dirsearch", "arjun", "paramspider"],
            "parallel": True,
        },
        "xss": {
            "tools": ["dalfox", "nuclei", "xsstrike"],
        },
        "sqli": {
            "tools": ["sqlmap", "nuclei", "ghauri"],
            "intensity": "aggressive",
            "options": {"timeout": 300},
        },
        "lfi": {
            "tools": ["ffuf", "dotdotpwn", "custom"],
        },
    },
}


def get_scan_profiles(overrides: Dict[str, Any] | None = None) -> Dict[str, Dict[str, Any]]:
    profiles = deepcopy(DEFAULT_SCAN_PROFILES)
    if not isinstance(overrides, dict):
        return profiles

    for profile_name, override_value in overrides.items():
        if profile_name not in profiles or not isinstance(override_value, dict):
            continue
        _deep_merge(profiles[profile_name], override_value)

    return profiles


def resolve_scan_profile(
    module_name: str,
    profile_name: str | None,
    overrides: Dict[str, Any] | None = None,
    configured_profiles: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    profiles = get_scan_profiles(configured_profiles)
    selected_name = profile_name or "standard"
    selected = deepcopy(profiles.get(selected_name, profiles["standard"]))
    module_profile = deepcopy(selected.get(module_name, {}))
    module_profile["profile_name"] = selected_name if selected_name in profiles else "standard"
    module_profile["profile_label"] = selected.get("label", selected_name.title())
    module_profile["profile_description"] = selected.get("description", "")

    if isinstance(overrides, dict):
        _deep_merge(module_profile, overrides)

    return module_profile


def list_profile_payloads(configured_profiles: Dict[str, Any] | None = None) -> list[dict]:
    profiles = get_scan_profiles(configured_profiles)
    payload = []
    for profile_name, profile_data in profiles.items():
        payload.append(
            {
                "id": profile_name,
                "label": profile_data.get("label", profile_name.title()),
                "description": profile_data.get("description", ""),
                "modules": {
                    module_name: module_settings
                    for module_name, module_settings in profile_data.items()
                    if module_name not in {"label", "description"}
                },
            }
        )
    return payload


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> None:
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _deep_merge(base[key], value)
        else:
            base[key] = deepcopy(value)
