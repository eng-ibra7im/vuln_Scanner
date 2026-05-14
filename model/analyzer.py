"""
Result Analyzer for Subdomain Enumeration
Analyzes, cleans, classifies, and prioritizes discovered subdomains.
"""

import re
import socket
import dns.resolver
import dns.exception
from typing import List, Dict, Set, Any, Tuple
from collections import defaultdict, Counter
from urllib.parse import urlparse
import ipaddress


class SubdomainAnalyzer:
    """
    Analyzes subdomain enumeration results.
    Performs deduplication, validation, classification, and prioritization.
    """

    def __init__(self, perform_dns_validation: bool = True, dns_timeout: int = 2):
        self.perform_dns_validation = perform_dns_validation
        self.dns_timeout = max(1, int(dns_timeout))
        self.dns_resolver = dns.resolver.Resolver()
        self.dns_resolver.timeout = self.dns_timeout
        self.dns_resolver.lifetime = self.dns_timeout

        # Patterns for classification
        self.interesting_patterns = {
            "development": r"(dev|development|test|testing|stage|staging|qa|uat)",
            "admin": r"(admin|administrator|manage|management|panel|dashboard)",
            "api": r"(api|rest|graphql|ws|websocket)",
            "mail": r"(mail|smtp|imap|pop|webmail|email)",
            "vpn": r"(vpn|remote|citrix|portal)",
            "storage": r"(s3|storage|backup|cdn|static|assets|media)",
            "database": r"(db|database|mysql|postgres|mongo|redis)",
            "ci_cd": r"(jenkins|gitlab|github|ci|cd|build|deploy)",
            "monitoring": r"(monitor|grafana|prometheus|kibana|elastic)",
            "auth": r"(auth|sso|login|oauth|saml|ldap)",
        }

    def analyze(self, target_domain: str, tool_results: List[Any]) -> Dict[str, Any]:
        """
        Main analysis method that coordinates all analysis tasks.

        Args:
            target_domain: The target domain that was enumerated
            tool_results: List of ToolResult objects from orchestrator

        Returns:
            Dictionary containing analyzed and structured results
        """
        # Aggregate all subdomains from all tools
        all_subdomains = self._aggregate_subdomains(tool_results)

        # Deduplicate and clean
        unique_subdomains = self._deduplicate(all_subdomains)
        cleaned = self._clean_subdomains(unique_subdomains, target_domain)

        # Validate subdomains when enabled, otherwise keep structural placeholders.
        if self.perform_dns_validation:
            validated = self._validate_subdomains(cleaned)
        else:
            validated = self._build_unvalidated_results(cleaned)

        # Classify subdomains
        classified = self._classify_subdomains(validated)

        # Prioritize based on interest level
        prioritized = self._prioritize_subdomains(classified)

        # Extract statistics
        statistics = self._generate_statistics(tool_results, prioritized)

        # Detect patterns
        patterns = self._detect_patterns(prioritized)

        return {
            "unique_subdomains": [s["subdomain"] for s in prioritized],
            "total_count": len(prioritized),
            "validated_count": sum(1 for s in prioritized if s["dns_valid"]),
            "classified_results": prioritized,
            "statistics": statistics,
            "patterns": patterns,
            "tool_coverage": self._calculate_tool_coverage(tool_results, prioritized),
        }

    def _aggregate_subdomains(self, tool_results: List[Any]) -> List[str]:
        """Aggregate subdomains from all tool results"""
        all_subs = []
        for result in tool_results:
            all_subs.extend(result.subdomains)
        return all_subs

    def _deduplicate(self, subdomains: List[str]) -> List[str]:
        """Remove duplicates while preserving order"""
        seen = set()
        unique = []
        for sub in subdomains:
            sub_lower = sub.lower().strip()
            if sub_lower and sub_lower not in seen:
                seen.add(sub_lower)
                unique.append(sub_lower)
        return unique

    def _clean_subdomains(self, subdomains: List[str], target_domain: str) -> List[str]:
        """
        Clean subdomain list by removing invalid entries and ensuring
        they belong to the target domain.
        """
        cleaned = []
        target_lower = target_domain.lower()

        for sub in subdomains:
            # Remove URLs and extract domain
            if sub.startswith("http://") or sub.startswith("https://"):
                parsed = urlparse(sub)
                sub = parsed.netloc

            # Remove port numbers
            if ":" in sub:
                sub = sub.split(":")[0]

            # Basic validation
            if not sub or len(sub) < 3:
                continue

            # Must end with target domain or be the target domain
            if not (sub == target_lower or sub.endswith("." + target_lower)):
                continue

            # Should not contain spaces or special characters (except . and -)
            if not re.match(r"^[a-z0-9.-]+$", sub):
                continue

            cleaned.append(sub)

        return cleaned

    def _validate_subdomains(self, subdomains: List[str]) -> List[Dict[str, Any]]:
        """
        Validate subdomains via DNS resolution.

        Returns list of dicts with subdomain and validation info.
        """
        validated = []

        for subdomain in subdomains:
            validation_result = {
                "subdomain": subdomain,
                "dns_valid": False,
                "ip_addresses": [],
                "cname": None,
                "has_mx": False,
            }

            try:
                # Try A record
                answers = self.dns_resolver.resolve(subdomain, "A")
                validation_result["dns_valid"] = True
                validation_result["ip_addresses"] = [str(rdata) for rdata in answers]
            except (
                dns.resolver.NXDOMAIN,
                dns.resolver.NoAnswer,
                dns.exception.Timeout,
            ):
                pass
            except Exception:
                pass

            # Try CNAME if A record didn't work
            if not validation_result["dns_valid"]:
                try:
                    answers = self.dns_resolver.resolve(subdomain, "CNAME")
                    validation_result["dns_valid"] = True
                    validation_result["cname"] = str(answers[0])
                except:
                    pass

            # Check for MX records (mail servers)
            try:
                mx_answers = self.dns_resolver.resolve(subdomain, "MX")
                validation_result["has_mx"] = True
            except:
                pass

            validated.append(validation_result)

        return validated

    def _build_unvalidated_results(self, subdomains: List[str]) -> List[Dict[str, Any]]:
        """Build placeholder validation entries when DNS validation is disabled."""
        return [
            {
                "subdomain": subdomain,
                "dns_valid": False,
                "ip_addresses": [],
                "cname": None,
                "has_mx": False,
            }
            for subdomain in subdomains
        ]

    def _classify_subdomains(
        self, validated: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Classify subdomains based on naming patterns and characteristics.
        """
        for entry in validated:
            subdomain = entry["subdomain"]
            classifications = []

            # Check against interesting patterns
            for category, pattern in self.interesting_patterns.items():
                if re.search(pattern, subdomain, re.IGNORECASE):
                    classifications.append(category)

            # Classify by subdomain depth
            parts = subdomain.split(".")
            depth = len(parts) - 2  # Subtract base domain

            entry["classifications"] = classifications
            entry["depth"] = depth
            entry["is_wildcard"] = self._check_wildcard(subdomain)

        return validated

    def _check_wildcard(self, subdomain: str) -> bool:
        """
        Basic wildcard detection.
        In real implementation, this would test random subdomains.
        """
        # Placeholder - in production, would test random prefixes
        return False

    def _prioritize_subdomains(
        self, classified: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Assign priority scores to subdomains based on interest level.
        Higher score = more interesting.
        """
        for entry in classified:
            score = 0

            # DNS validation adds points
            if entry["dns_valid"]:
                score += 10

            # Classifications add points
            score += len(entry["classifications"]) * 5

            # Specific high-value classifications
            high_value = ["admin", "api", "vpn", "development", "database"]
            for hv in high_value:
                if hv in entry["classifications"]:
                    score += 10

            # MX records indicate active mail server
            if entry.get("has_mx"):
                score += 8

            # Shallow subdomains are often more interesting
            if entry["depth"] == 1:
                score += 5
            elif entry["depth"] > 3:
                score -= 5

            # Wildcard subdomains are less interesting
            if entry["is_wildcard"]:
                score -= 20

            entry["priority_score"] = max(0, score)

            # Assign priority level
            if score >= 20:
                entry["priority"] = "high"
            elif score >= 10:
                entry["priority"] = "medium"
            else:
                entry["priority"] = "low"

        # Sort by priority score (descending)
        classified.sort(key=lambda x: x["priority_score"], reverse=True)

        return classified

    def _generate_statistics(
        self, tool_results: List[Any], prioritized: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Generate statistical summary of results"""
        stats = {
            "tools_executed": len(tool_results),
            "tools_successful": sum(1 for r in tool_results if r.success),
            "total_execution_time": sum(r.execution_time for r in tool_results),
            "subdomains_per_tool": {},
            "priority_distribution": Counter(s["priority"] for s in prioritized),
            "classification_distribution": {},
            "depth_distribution": Counter(s["depth"] for s in prioritized),
            "validation_rate": 0,
            "dns_validation_enabled": self.perform_dns_validation,
            "dns_timeout_seconds": self.dns_timeout,
        }

        # Per-tool statistics
        for result in tool_results:
            stats["subdomains_per_tool"][result.tool] = len(result.subdomains)

        # Classification distribution
        all_classifications = []
        for entry in prioritized:
            all_classifications.extend(entry["classifications"])
        stats["classification_distribution"] = dict(Counter(all_classifications))

        # Validation rate
        if prioritized:
            valid_count = sum(1 for s in prioritized if s["dns_valid"])
            stats["validation_rate"] = round(valid_count / len(prioritized) * 100, 2)

        return stats

    def _detect_patterns(self, prioritized: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Detect interesting patterns in subdomain naming"""
        patterns = {
            "common_prefixes": [],
            "numbered_series": [],
            "environment_indicators": [],
            "technology_indicators": [],
        }

        # Extract prefixes (first part of subdomain)
        prefixes = []
        for entry in prioritized:
            parts = entry["subdomain"].split(".")
            if len(parts) > 2:
                prefixes.append(parts[0])

        # Find most common prefixes
        prefix_counts = Counter(prefixes)
        patterns["common_prefixes"] = [
            {"prefix": k, "count": v} for k, v in prefix_counts.most_common(10)
        ]

        # Detect numbered series (e.g., server1, server2, server3)
        numbered = defaultdict(list)
        for entry in prioritized:
            match = re.match(r"^([a-z]+)(\d+)\.", entry["subdomain"])
            if match:
                base, num = match.groups()
                numbered[base].append(int(num))

        # Report series with 3+ consecutive numbers
        for base, nums in numbered.items():
            if len(nums) >= 3:
                patterns["numbered_series"].append(
                    {
                        "base": base,
                        "range": f"{min(nums)}-{max(nums)}",
                        "count": len(nums),
                    }
                )

        # Environment indicators
        env_keywords = ["dev", "test", "stage", "prod", "uat", "qa"]
        for env in env_keywords:
            count = sum(1 for e in prioritized if env in e["subdomain"].lower())
            if count > 0:
                patterns["environment_indicators"].append(
                    {"environment": env, "count": count}
                )

        # Technology indicators
        tech_keywords = ["api", "mail", "ftp", "ssh", "vpn", "cdn", "db"]
        for tech in tech_keywords:
            count = sum(1 for e in prioritized if tech in e["subdomain"].lower())
            if count > 0:
                patterns["technology_indicators"].append(
                    {"technology": tech, "count": count}
                )

        return patterns

    def _calculate_tool_coverage(
        self, tool_results: List[Any], prioritized: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Calculate how much each tool contributed to final results"""
        coverage = {}
        all_subdomains = {s["subdomain"] for s in prioritized}

        for result in tool_results:
            tool_subs = set(result.subdomains)
            unique_to_tool = tool_subs - (all_subdomains - tool_subs)

            coverage[result.tool] = {
                "found": len(result.subdomains),
                "contributed": len(tool_subs & all_subdomains),
                "unique_contribution": len(unique_to_tool),
                "contribution_rate": (
                    round(
                        len(tool_subs & all_subdomains) / len(all_subdomains) * 100, 2
                    )
                    if all_subdomains
                    else 0
                ),
            }

        return coverage
