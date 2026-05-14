import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse


SEVERITY_RANK = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}

SEVERITY_SCORE = {
    "critical": 95,
    "high": 80,
    "medium": 55,
    "low": 30,
    "info": 10,
}

PRIORITY_TO_SEVERITY = {
    "high": "high",
    "medium": "medium",
    "low": "low",
}


def _slugify(value: str) -> str:
    return "".join(ch.lower() if ch.isalnum() else "_" for ch in value).strip("_")


def _title_case(value: str) -> str:
    if not value:
        return ""
    return value.replace("_", " ").replace("-", " ").strip().title()


def normalize_severity(value: Optional[str], *, fallback: str = "info") -> str:
    if not value:
        return fallback

    normalized = str(value).strip().lower()
    normalized = PRIORITY_TO_SEVERITY.get(normalized, normalized)

    if normalized in SEVERITY_RANK:
        return normalized

    if "critical" in normalized:
        return "critical"
    if "high" in normalized:
        return "high"
    if "medium" in normalized:
        return "medium"
    if "low" in normalized:
        return "low"
    return fallback


def severity_score(severity: Optional[str]) -> int:
    return SEVERITY_SCORE[normalize_severity(severity)]


def extract_host(target: str) -> str:
    if not target:
        return ""
    parsed = urlparse(target)
    return parsed.netloc or target


def ensure_query_parameter(url: str, parameter: str, value: str) -> str:
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    query[parameter] = [value]
    new_query = urlencode(query, doseq=True)
    return urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment,
        )
    )


def asset_id(asset_type: str, locator: str) -> str:
    return f"{asset_type}:{_slugify(locator)}"


def finding_id(module: str, title: str, locator: str) -> str:
    return f"finding:{_slugify(module)}:{_slugify(title)}:{_slugify(locator)}"


def path_locator_from_url(url: str) -> str:
    parsed = urlparse(url)
    path = parsed.path or "/"
    return f"{parsed.scheme}://{parsed.netloc}{path}" if parsed.scheme else path


@dataclass
class AutoAction:
    scan_type: str
    target: str
    reason: str
    source_module: str
    source_asset_id: str
    severity: str
    rule_id: str
    metadata: Dict[str, Any]

    def asdict(self) -> Dict[str, Any]:
        return {
            "scan_type": self.scan_type,
            "target": self.target,
            "reason": self.reason,
            "source_module": self.source_module,
            "source_asset_id": self.source_asset_id,
            "severity": _title_case(self.severity),
            "severity_score": severity_score(self.severity),
            "rule_id": self.rule_id,
            "metadata": self.metadata,
        }


class OrchestrationRuleEngine:
    def __init__(self, rules: Optional[Dict[str, Any]] = None):
        self.rules = rules or {}

    def enabled(self) -> bool:
        return bool(self.rules.get("enabled", True))

    def auto_follow_up_enabled(self) -> bool:
        return self.enabled() and bool(self.rules.get("auto_follow_up", False))

    def plan_actions(self, results_by_module: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not self.enabled():
            return []

        actions: List[AutoAction] = []
        subdomain_results = results_by_module.get("subdomains")
        path_results = results_by_module.get("paths")

        if subdomain_results:
            actions.extend(self._plan_subdomain_actions(subdomain_results))
        if path_results:
            actions.extend(self._plan_path_actions(path_results))

        return self._dedupe_actions(actions)

    def _plan_subdomain_actions(self, results: Dict[str, Any]) -> List[AutoAction]:
        trigger_cfg = self.rules.get("subdomain_triggers", {})
        follow_up_modules = trigger_cfg.get("follow_up_modules", ["path"])
        required_severity = normalize_severity(trigger_cfg.get("priority_threshold", "high"))
        classification_keywords = {
            keyword.lower() for keyword in trigger_cfg.get("classification_keywords", [])
        }
        require_active = bool(trigger_cfg.get("require_active", True))
        preferred_scheme = self.rules.get("preferred_scheme", "https")
        max_targets = int(self.rules.get("max_auto_targets_per_rule", 5))

        actions: List[AutoAction] = []
        for subdomain in results.get("subdomains", []):
            priority = normalize_severity(subdomain.get("priority"), fallback="low")
            if SEVERITY_RANK[priority] < SEVERITY_RANK[required_severity]:
                continue

            if require_active and subdomain.get("status") != "active":
                continue

            classes = {value.lower() for value in subdomain.get("classifications", [])}
            if classification_keywords and not (classes & classification_keywords):
                continue

            url = f"{preferred_scheme}://{subdomain.get('subdomain')}"
            source_asset = asset_id("subdomain", subdomain.get("subdomain", ""))
            reason = (
                f"High-value subdomain classified as {', '.join(sorted(classes)) or 'sensitive'}"
            )

            for module_name in follow_up_modules:
                actions.append(
                    AutoAction(
                        scan_type=module_name,
                        target=url,
                        reason=reason,
                        source_module="subdomains",
                        source_asset_id=source_asset,
                        severity=priority,
                        rule_id="subdomains.priority-follow-up",
                        metadata={
                            "subdomain": subdomain.get("subdomain"),
                            "classifications": sorted(classes),
                        },
                    )
                )

            if len(actions) >= max_targets:
                break

        return actions

    def _plan_path_actions(self, results: Dict[str, Any]) -> List[AutoAction]:
        trigger_cfg = self.rules.get("path_triggers", {})
        keyword_modules = trigger_cfg.get("path_keyword_modules", {})
        vuln_modules = trigger_cfg.get("parameter_vuln_modules", {})
        default_query_value = trigger_cfg.get("default_query_value", "scan")
        max_targets = int(self.rules.get("max_auto_targets_per_rule", 5))

        actions: List[AutoAction] = []

        for path_item in results.get("discovered_paths", []):
            target_url = path_item.get("url") or ""
            target_path = (path_item.get("path") or "").lower()
            category = (path_item.get("category") or "").lower()

            matched_modules = set(keyword_modules.get(category, []))
            for keyword, modules in keyword_modules.items():
                if keyword in target_path:
                    matched_modules.update(modules)

            for module_name in sorted(matched_modules):
                actions.append(
                    AutoAction(
                        scan_type=module_name,
                        target=target_url,
                        reason=f"Sensitive path indicator detected on {path_item.get('path')}",
                        source_module="paths",
                        source_asset_id=asset_id("path", path_locator_from_url(target_url)),
                        severity=normalize_severity(path_item.get("risk_level"), fallback="medium"),
                        rule_id="paths.keyword-follow-up",
                        metadata={
                            "path": path_item.get("path"),
                            "category": category,
                            "risk_level": path_item.get("risk_level"),
                        },
                    )
                )

        for parameter in results.get("discovered_parameters", []):
            parameter_name = parameter.get("parameter", "")
            base_url = parameter.get("url", "")
            for vuln_label in parameter.get("potential_vuln", []):
                for module_name in vuln_modules.get(vuln_label, []):
                    target_url = ensure_query_parameter(
                        base_url,
                        parameter_name,
                        default_query_value,
                    )
                    actions.append(
                        AutoAction(
                            scan_type=module_name,
                            target=target_url,
                            reason=f"Parameter {parameter_name} looks relevant to {vuln_label}",
                            source_module="paths",
                            source_asset_id=asset_id(
                                "parameter",
                                f"{path_locator_from_url(base_url)}::{parameter_name}",
                            ),
                            severity="medium",
                            rule_id="paths.parameter-follow-up",
                            metadata={
                                "parameter": parameter_name,
                                "vulnerability_hint": vuln_label,
                            },
                        )
                    )

        return actions[: max_targets * 3]

    def _dedupe_actions(self, actions: Iterable[AutoAction]) -> List[Dict[str, Any]]:
        unique: Dict[tuple[str, str], AutoAction] = {}
        for action in actions:
            key = (action.scan_type, action.target)
            existing = unique.get(key)
            if existing is None or SEVERITY_RANK[normalize_severity(action.severity)] > SEVERITY_RANK[
                normalize_severity(existing.severity)
            ]:
                unique[key] = action

        return [action.asdict() for action in unique.values()]


class CorrelationEngine:
    def __init__(self, rules: Optional[Dict[str, Any]] = None):
        self.rule_engine = OrchestrationRuleEngine(rules)

    def analyze(self, results_by_module: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        assets: Dict[str, Dict[str, Any]] = {}
        findings: List[Dict[str, Any]] = []
        relationships: List[Dict[str, Any]] = []
        lineage: List[Dict[str, Any]] = []

        self._ingest_subdomains(results_by_module.get("subdomains"), assets, findings)
        self._ingest_paths(results_by_module.get("paths"), assets, findings)
        self._ingest_vulnerability_findings("xss", results_by_module.get("xss"), assets, findings)
        self._ingest_vulnerability_findings("sqli", results_by_module.get("sqli"), assets, findings)
        self._ingest_lfi(results_by_module.get("lfi"), assets, findings)

        for finding in findings:
            asset_chain = []
            host = finding.get("host") or ""
            path_url = finding.get("path_url") or ""
            parameter = finding.get("parameter")

            if host:
                subdomain_asset = asset_id("subdomain", host)
                if subdomain_asset in assets:
                    asset_chain.append(subdomain_asset)

            if path_url:
                path_asset = asset_id("path", path_locator_from_url(path_url))
                if path_asset in assets:
                    asset_chain.append(path_asset)

            if parameter and path_url:
                parameter_asset = asset_id(
                    "parameter", f"{path_locator_from_url(path_url)}::{parameter}"
                )
                if parameter_asset in assets:
                    asset_chain.append(parameter_asset)

            finding["asset_chain"] = asset_chain
            for parent, child in zip(asset_chain, asset_chain[1:]):
                relationships.append(
                    {"type": "contains", "source": parent, "target": child}
                )

            lineage.append(
                {
                    "id": finding["id"],
                    "module": finding["module"],
                    "severity": finding["severity"],
                    "severity_score": finding["severity_score"],
                    "subdomain": host or None,
                    "path": urlparse(path_url).path if path_url else None,
                    "parameter": parameter,
                    "title": finding["title"],
                    "asset_chain": asset_chain,
                }
            )

        next_actions = self.rule_engine.plan_actions(results_by_module)
        severity_counts = Counter(finding["severity"] for finding in findings)
        module_counts = Counter(finding["module"] for finding in findings)

        return {
            "generated_at": datetime.now(UTC).isoformat(),
            "modules_present": sorted([name for name, value in results_by_module.items() if value]),
            "assets": sorted(assets.values(), key=lambda item: item["id"]),
            "findings": sorted(
                findings,
                key=lambda item: (-item["severity_score"], item["module"], item["title"]),
            ),
            "lineage": lineage,
            "correlations": {
                "relationships": relationships,
                "next_actions": next_actions,
                "auto_follow_up_enabled": self.rule_engine.auto_follow_up_enabled(),
                "module_findings": dict(module_counts),
                "severity_distribution": dict(severity_counts),
            },
        }

    def _ingest_subdomains(
        self,
        results: Optional[Dict[str, Any]],
        assets: Dict[str, Dict[str, Any]],
        findings: List[Dict[str, Any]],
    ) -> None:
        if not results:
            return

        for entry in results.get("subdomains", []):
            subdomain = entry.get("subdomain", "")
            priority = normalize_severity(entry.get("priority"), fallback="low")
            aid = asset_id("subdomain", subdomain)
            assets[aid] = {
                "id": aid,
                "type": "subdomain",
                "name": subdomain,
                "url": f"https://{subdomain}",
                "source_module": "subdomains",
                "severity": priority,
                "severity_score": severity_score(priority),
                "metadata": {
                    "priority": entry.get("priority"),
                    "priority_score": entry.get("priority_score"),
                    "status": entry.get("status"),
                    "classifications": entry.get("classifications", []),
                },
            }

            if SEVERITY_RANK[priority] >= SEVERITY_RANK["high"]:
                classes = entry.get("classifications", [])
                title = f"High-priority subdomain exposure: {subdomain}"
                findings.append(
                    {
                        "id": finding_id("subdomains", title, subdomain),
                        "module": "subdomains",
                        "type": "exposed_subdomain",
                        "title": title,
                        "severity": priority,
                        "severity_score": severity_score(priority),
                        "host": subdomain,
                        "path_url": f"https://{subdomain}",
                        "parameter": None,
                        "evidence": ", ".join(classes) if classes else entry.get("status", "active"),
                        "remediation": "Review exposure and restrict unnecessary internet-facing subdomains.",
                        "owner": "Infrastructure / Platform",
                    }
                )

    def _ingest_paths(
        self,
        results: Optional[Dict[str, Any]],
        assets: Dict[str, Dict[str, Any]],
        findings: List[Dict[str, Any]],
    ) -> None:
        if not results:
            return

        for path_entry in results.get("discovered_paths", []):
            target_url = path_entry.get("url", "")
            host = extract_host(target_url)
            locator = path_locator_from_url(target_url)
            severity = normalize_severity(path_entry.get("risk_level"), fallback="info")
            aid = asset_id("path", locator)
            assets[aid] = {
                "id": aid,
                "type": "path",
                "name": path_entry.get("path") or "/",
                "url": target_url,
                "source_module": "paths",
                "parent_asset_id": asset_id("subdomain", host) if host else None,
                "severity": severity,
                "severity_score": severity_score(severity),
                "metadata": {
                    "category": path_entry.get("category"),
                    "status_code": path_entry.get("status_code"),
                    "interesting": path_entry.get("interesting"),
                    "notes": path_entry.get("notes", []),
                },
            }

            if SEVERITY_RANK[severity] >= SEVERITY_RANK["high"]:
                title = f"Sensitive path exposure: {path_entry.get('path')}"
                findings.append(
                    {
                        "id": finding_id("paths", title, locator),
                        "module": "paths",
                        "type": "sensitive_path",
                        "title": title,
                        "severity": severity,
                        "severity_score": severity_score(severity),
                        "host": host,
                        "path_url": target_url,
                        "parameter": None,
                        "evidence": ", ".join(path_entry.get("notes", [])),
                        "remediation": "Restrict access to sensitive routes and remove unnecessary public endpoints.",
                        "owner": "Application / Platform",
                    }
                )

        for parameter_entry in results.get("discovered_parameters", []):
            url = parameter_entry.get("url", "")
            host = extract_host(url)
            locator = f"{path_locator_from_url(url)}::{parameter_entry.get('parameter')}"
            aid = asset_id("parameter", locator)
            assets[aid] = {
                "id": aid,
                "type": "parameter",
                "name": parameter_entry.get("parameter"),
                "url": ensure_query_parameter(url, parameter_entry.get("parameter", "param"), "scan"),
                "source_module": "paths",
                "parent_asset_id": asset_id("path", path_locator_from_url(url)),
                "severity": "medium" if parameter_entry.get("potential_vuln") else "info",
                "severity_score": severity_score(
                    "medium" if parameter_entry.get("potential_vuln") else "info"
                ),
                "metadata": {
                    "method": parameter_entry.get("method"),
                    "potential_vuln": parameter_entry.get("potential_vuln", []),
                },
            }

            if parameter_entry.get("potential_vuln"):
                title = f"Candidate parameter for attack-surface review: {parameter_entry.get('parameter')}"
                findings.append(
                    {
                        "id": finding_id("paths", title, locator),
                        "module": "paths",
                        "type": "candidate_parameter",
                        "title": title,
                        "severity": "medium",
                        "severity_score": severity_score("medium"),
                        "host": host,
                        "path_url": url,
                        "parameter": parameter_entry.get("parameter"),
                        "evidence": ", ".join(parameter_entry.get("potential_vuln", [])),
                        "remediation": "Review validation and authorization controls on exposed parameters.",
                        "owner": "Application",
                    }
                )

    def _ingest_vulnerability_findings(
        self,
        module_name: str,
        results: Optional[Dict[str, Any]],
        assets: Dict[str, Dict[str, Any]],
        findings: List[Dict[str, Any]],
    ) -> None:
        if not results:
            return

        for item in results.get("findings", []):
            target_url = item.get("url") or results.get("scan_info", {}).get("target", "")
            host = extract_host(target_url)
            path_url = path_locator_from_url(target_url)
            parameter = item.get("parameter")
            severity = normalize_severity(item.get("severity"), fallback="medium")
            title = item.get("vulnerability_type") or item.get("xss_type") or f"{module_name} finding"

            findings.append(
                {
                    "id": finding_id(module_name, title, f"{target_url}:{parameter or ''}"),
                    "module": module_name,
                    "type": title.lower().replace(" ", "_"),
                    "title": title,
                    "severity": severity,
                    "severity_score": severity_score(severity),
                    "host": host,
                    "path_url": target_url or path_url,
                    "parameter": parameter,
                    "evidence": item.get("evidence", ""),
                    "remediation": item.get("remediation", ""),
                    "owner": "Application Security / Engineering",
                    "confidence": item.get("confidence"),
                    "cwe_id": item.get("cwe_id"),
                    "tool": item.get("tool") or item.get("detection_tool"),
                }
            )

    def _ingest_lfi(
        self,
        results: Optional[Dict[str, Any]],
        assets: Dict[str, Dict[str, Any]],
        findings: List[Dict[str, Any]],
    ) -> None:
        if not results:
            return

        for item in results.get("raw_findings", []):
            target_url = item.get("url") or results.get("target_url", "")
            host = extract_host(target_url)
            severity = normalize_severity(item.get("severity"), fallback="medium")
            title = "Local File Inclusion"

            findings.append(
                {
                    "id": finding_id("lfi", title, f"{target_url}:{item.get('parameter', '')}"),
                    "module": "lfi",
                    "type": "local_file_inclusion",
                    "title": title,
                    "severity": severity,
                    "severity_score": severity_score(severity),
                    "host": host,
                    "path_url": target_url,
                    "parameter": item.get("parameter"),
                    "evidence": item.get("evidence", ""),
                    "remediation": "Lock down file include logic and enforce strict path allowlists.",
                    "owner": "Backend Engineering",
                    "confidence": item.get("confidence"),
                    "tool": item.get("tool"),
                }
            )


class RecommendationEngine:
    RECOMMENDATION_TEMPLATES = {
        "xss": {
            "key": "xss-output-encoding",
            "title": "Harden reflected and stored output handling",
            "action": "Apply contextual output encoding and strict input handling on user-controlled fields.",
            "why": "XSS findings indicate user input is reaching executable browser contexts.",
            "owner": "Frontend / Application Engineering",
        },
        "sqli": {
            "key": "sqli-parameterization",
            "title": "Eliminate unsafe query construction",
            "action": "Replace dynamic query concatenation with parameterized statements and ORM-safe patterns.",
            "why": "SQL injection findings indicate database queries are influenced by untrusted input.",
            "owner": "Backend / Database Engineering",
        },
        "lfi": {
            "key": "lfi-include-allowlist",
            "title": "Constrain file access and include paths",
            "action": "Move file selection to server-side allowlists and block traversal primitives.",
            "why": "LFI findings indicate attackers can influence filesystem paths or include targets.",
            "owner": "Backend Engineering",
        },
        "paths": {
            "key": "sensitive-surface-reduction",
            "title": "Reduce exposed administrative and sensitive routes",
            "action": "Protect admin/config/backup endpoints behind authentication, ACLs, or network restrictions.",
            "why": "Sensitive routes and parameters materially expand the attack surface.",
            "owner": "Application / Platform",
        },
        "subdomains": {
            "key": "external-attack-surface-governance",
            "title": "Review high-risk subdomain exposure",
            "action": "Inventory high-priority subdomains and retire or restrict any unnecessary public hosts.",
            "why": "Internet-facing admin, API, or development hosts increase attack surface quickly.",
            "owner": "Infrastructure / Platform",
        },
    }

    def generate(self, analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        grouped: Dict[str, Dict[str, Any]] = {}

        for finding in analysis.get("findings", []):
            module_name = finding.get("module", "")
            template = self.RECOMMENDATION_TEMPLATES.get(module_name)
            if not template:
                continue

            recommendation = grouped.setdefault(
                template["key"],
                {
                    "key": template["key"],
                    "title": template["title"],
                    "priority": "info",
                    "priority_score": 0,
                    "action": template["action"],
                    "why": template["why"],
                    "owner": template["owner"],
                    "modules": set(),
                    "finding_ids": [],
                    "affected_assets": set(),
                },
            )

            severity = normalize_severity(finding.get("severity"), fallback="low")
            if SEVERITY_RANK[severity] > SEVERITY_RANK[recommendation["priority"]]:
                recommendation["priority"] = severity
                recommendation["priority_score"] = severity_score(severity)

            recommendation["modules"].add(module_name)
            recommendation["finding_ids"].append(finding["id"])
            recommendation["affected_assets"].update(finding.get("asset_chain", []))

        normalized: List[Dict[str, Any]] = []
        for item in grouped.values():
            normalized.append(
                {
                    "key": item["key"],
                    "title": item["title"],
                    "priority": _title_case(item["priority"]),
                    "priority_score": item["priority_score"],
                    "action": item["action"],
                    "why": item["why"],
                    "owner": item["owner"],
                    "modules": sorted(item["modules"]),
                    "finding_count": len(item["finding_ids"]),
                    "affected_assets": sorted(item["affected_assets"]),
                }
            )

        normalized.sort(key=lambda item: (-item["priority_score"], item["title"]))
        return normalized


class ExecutiveSummaryGenerator:
    def generate(
        self, analysis: Dict[str, Any], recommendations: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        findings = analysis.get("findings", [])
        severity_distribution = analysis.get("correlations", {}).get(
            "severity_distribution", {}
        )
        modules_present = analysis.get("modules_present", [])

        top_findings = [
            {
                "title": finding["title"],
                "module": finding["module"],
                "severity": _title_case(finding["severity"]),
                "target": finding.get("path_url") or finding.get("host"),
            }
            for finding in findings[:5]
        ]

        if severity_distribution.get("critical"):
            posture = "critical"
            headline = "Critical issues require immediate remediation."
        elif severity_distribution.get("high"):
            posture = "high"
            headline = "High-risk attack surface remains exposed."
        elif findings:
            posture = "moderate"
            headline = "The scan surfaced medium-priority hardening work."
        else:
            posture = "low"
            headline = "No direct high-risk findings were correlated from the available scans."

        return {
            "headline": headline,
            "risk_posture": posture,
            "modules_analyzed": modules_present,
            "total_assets": len(analysis.get("assets", [])),
            "total_findings": len(findings),
            "severity_distribution": severity_distribution,
            "top_findings": top_findings,
            "top_recommendations": recommendations[:3],
        }


class ProductIntelligenceEngine:
    def __init__(self, rules: Optional[Dict[str, Any]] = None):
        self.correlation_engine = CorrelationEngine(rules)
        self.recommendation_engine = RecommendationEngine()
        self.executive_summary_generator = ExecutiveSummaryGenerator()

    def analyze(self, results_by_module: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        analysis = self.correlation_engine.analyze(results_by_module)
        recommendations = self.recommendation_engine.generate(analysis)
        executive_summary = self.executive_summary_generator.generate(
            analysis, recommendations
        )

        analysis["recommendations"] = recommendations
        analysis["executive_summary"] = executive_summary
        return analysis

    def plan_follow_up_actions(
        self, results_by_module: Dict[str, Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        return self.correlation_engine.rule_engine.plan_actions(results_by_module)


def serialize_analysis(analysis: Dict[str, Any]) -> str:
    return json.dumps(analysis, indent=2, ensure_ascii=False)
