"""
Result Formatter for Subdomain Enumeration
Formats analysis results into structured JSON for web dashboard consumption.
"""

from datetime import datetime
from typing import Dict, List, Any


class ResultFormatter:
    """
    Formats subdomain enumeration results into structured JSON output
    suitable for web dashboard visualization.
    """

    def format_output(
        self,
        target_domain: str,
        tool_results: List[Any],
        analyzed_results: Dict[str, Any],
        execution_time: float,
    ) -> Dict[str, Any]:
        """
        Format all results into structured JSON output.

        Args:
            target_domain: The target domain that was enumerated
            tool_results: Raw results from tool execution
            analyzed_results: Analyzed and processed results
            execution_time: Total execution time in seconds

        Returns:
            Structured JSON dictionary ready for dashboard
        """
        return {
            "success": True,
            "metadata": self._format_metadata(target_domain, execution_time),
            "summary": self._format_summary(analyzed_results),
            "subdomains": self._format_subdomains(
                analyzed_results["classified_results"]
            ),
            "statistics": analyzed_results["statistics"],
            "patterns": analyzed_results["patterns"],
            "tool_performance": self._format_tool_performance(tool_results),
            "tool_coverage": analyzed_results["tool_coverage"],
            "recommendations": self._generate_recommendations(analyzed_results),
        }

    def _format_metadata(
        self, target_domain: str, execution_time: float
    ) -> Dict[str, Any]:
        """Format metadata section"""
        return {
            "target_domain": target_domain,
            "scan_timestamp": datetime.utcnow().isoformat() + "Z",
            "execution_time_seconds": round(execution_time, 2),
            "orchestrator_version": "1.0.0",
            "report_format_version": "1.0",
        }

    def _format_summary(self, analyzed_results: Dict[str, Any]) -> Dict[str, Any]:
        """Format summary section with key metrics"""
        stats = analyzed_results["statistics"]

        return {
            "total_subdomains": analyzed_results["total_count"],
            "validated_subdomains": analyzed_results["validated_count"],
            "validation_rate_percent": stats.get("validation_rate", 0),
            "high_priority_count": stats["priority_distribution"].get("high", 0),
            "medium_priority_count": stats["priority_distribution"].get("medium", 0),
            "low_priority_count": stats["priority_distribution"].get("low", 0),
            "tools_executed": stats["tools_executed"],
            "tools_successful": stats["tools_successful"],
        }

    def _format_subdomains(
        self, classified_results: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Format subdomain list with all relevant information for dashboard.
        Organized by priority for easy visualization.
        """
        formatted = []

        for entry in classified_results:
            formatted_entry = {
                "subdomain": entry["subdomain"],
                "priority": entry["priority"],
                "priority_score": entry["priority_score"],
                "status": "active" if entry["dns_valid"] else "inactive",
                "dns_records": {
                    "validated": entry["dns_valid"],
                    "ip_addresses": entry.get("ip_addresses", []),
                    "cname": entry.get("cname"),
                    "has_mx_records": entry.get("has_mx", False),
                },
                "classifications": entry.get("classifications", []),
                "metadata": {
                    "depth": entry.get("depth", 0),
                    "is_wildcard": entry.get("is_wildcard", False),
                },
            }

            formatted.append(formatted_entry)

        return formatted

    def _format_tool_performance(self, tool_results: List[Any]) -> List[Dict[str, Any]]:
        """Format tool performance metrics"""
        performance = []

        for result in tool_results:
            performance.append(
                {
                    "tool_name": result.tool,
                    "status": "success" if result.success else "failed",
                    "execution_time_seconds": round(result.execution_time, 2),
                    "subdomains_found": len(result.subdomains),
                    "error": result.error if not result.success else None,
                }
            )

        # Sort by subdomains found (descending)
        performance.sort(key=lambda x: x["subdomains_found"], reverse=True)

        return performance

    def _generate_recommendations(
        self, analyzed_results: Dict[str, Any]
    ) -> List[Dict[str, str]]:
        """
        Generate actionable recommendations based on analysis results.
        """
        recommendations = []

        classified = analyzed_results["classified_results"]
        stats = analyzed_results["statistics"]
        patterns = analyzed_results["patterns"]

        # High priority subdomains
        high_priority = [s for s in classified if s["priority"] == "high"]
        if high_priority:
            recommendations.append(
                {
                    "category": "security",
                    "priority": "high",
                    "title": "Review High-Priority Subdomains",
                    "description": f"Found {len(high_priority)} high-priority subdomains that warrant immediate attention.",
                    "action": "Review subdomains with admin, api, database, or development indicators",
                }
            )

        # Admin/sensitive subdomains
        admin_subs = [s for s in classified if "admin" in s.get("classifications", [])]
        if admin_subs:
            recommendations.append(
                {
                    "category": "security",
                    "priority": "critical",
                    "title": "Administrative Interfaces Detected",
                    "description": f"Found {len(admin_subs)} subdomains with administrative interfaces.",
                    "action": "Ensure proper authentication and access controls are in place",
                }
            )

        # Development/staging environments
        dev_subs = [
            s for s in classified if "development" in s.get("classifications", [])
        ]
        if dev_subs:
            recommendations.append(
                {
                    "category": "security",
                    "priority": "high",
                    "title": "Development Environments Exposed",
                    "description": f"Found {len(dev_subs)} development/staging subdomains.",
                    "action": "Verify these environments are properly secured or not publicly accessible",
                }
            )

        # API endpoints
        api_subs = [s for s in classified if "api" in s.get("classifications", [])]
        if api_subs:
            recommendations.append(
                {
                    "category": "security",
                    "priority": "medium",
                    "title": "API Endpoints Discovered",
                    "description": f"Found {len(api_subs)} API-related subdomains.",
                    "action": "Review API authentication, rate limiting, and security controls",
                }
            )

        # Database subdomains
        db_subs = [s for s in classified if "database" in s.get("classifications", [])]
        if db_subs:
            recommendations.append(
                {
                    "category": "security",
                    "priority": "critical",
                    "title": "Database Subdomains Detected",
                    "description": f"Found {len(db_subs)} database-related subdomains.",
                    "action": "Ensure databases are not directly exposed to the internet",
                }
            )

        # Low validation rate
        validation_rate = stats.get("validation_rate", 0)
        if validation_rate < 50:
            recommendations.append(
                {
                    "category": "cleanup",
                    "priority": "low",
                    "title": "Low DNS Validation Rate",
                    "description": f"Only {validation_rate}% of discovered subdomains resolved successfully.",
                    "action": "Consider cleaning up stale DNS records",
                }
            )

        # Numbered series detected
        if patterns.get("numbered_series"):
            recommendations.append(
                {
                    "category": "information",
                    "priority": "low",
                    "title": "Numbered Subdomain Series Detected",
                    "description": "Detected patterns of numbered subdomains which may indicate scalable infrastructure.",
                    "action": "Review for potential information disclosure in naming patterns",
                }
            )

        # No high priority items found (good)
        if not high_priority:
            recommendations.append(
                {
                    "category": "information",
                    "priority": "info",
                    "title": "No Critical Issues Detected",
                    "description": "No obvious high-risk subdomains were identified in this scan.",
                    "action": "Continue regular monitoring and periodic rescans",
                }
            )

        return recommendations

    def format_csv(self, analyzed_results: Dict[str, Any]) -> str:
        """
        Format results as CSV for export.

        Args:
            analyzed_results: Analyzed results dictionary

        Returns:
            CSV formatted string
        """
        import csv
        from io import StringIO

        output = StringIO()
        writer = csv.writer(output)

        # Header
        writer.writerow(
            [
                "Subdomain",
                "Priority",
                "Priority Score",
                "DNS Valid",
                "IP Addresses",
                "Classifications",
                "Depth",
            ]
        )

        # Data rows
        for entry in analyzed_results["classified_results"]:
            writer.writerow(
                [
                    entry["subdomain"],
                    entry["priority"],
                    entry["priority_score"],
                    "Yes" if entry["dns_valid"] else "No",
                    ", ".join(entry.get("ip_addresses", [])),
                    ", ".join(entry.get("classifications", [])),
                    entry.get("depth", 0),
                ]
            )

        return output.getvalue()

    def format_markdown(
        self, analyzed_results: Dict[str, Any], target_domain: str
    ) -> str:
        """
        Format results as Markdown report.

        Args:
            analyzed_results: Analyzed results dictionary
            target_domain: Target domain

        Returns:
            Markdown formatted string
        """
        md = []
        md.append(f"# Subdomain Enumeration Report: {target_domain}\n")
        md.append(
            f"**Scan Date:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC\n"
        )

        # Summary
        md.append("## Summary\n")
        md.append(f"- **Total Subdomains Found:** {analyzed_results['total_count']}")
        md.append(f"- **Validated Subdomains:** {analyzed_results['validated_count']}")
        md.append(
            f"- **Validation Rate:** {analyzed_results['statistics']['validation_rate']}%\n"
        )

        # Priority distribution
        md.append("## Priority Distribution\n")
        priority_dist = analyzed_results["statistics"]["priority_distribution"]
        md.append(f"- High Priority: {priority_dist.get('high', 0)}")
        md.append(f"- Medium Priority: {priority_dist.get('medium', 0)}")
        md.append(f"- Low Priority: {priority_dist.get('low', 0)}\n")

        # Top 20 subdomains
        md.append("## Top 20 Subdomains (by Priority)\n")
        md.append("| Subdomain | Priority | Classifications | Status |")
        md.append("|-----------|----------|----------------|--------|")

        for entry in analyzed_results["classified_results"][:20]:
            classifications = ", ".join(entry.get("classifications", [])) or "None"
            status = "Active" if entry["dns_valid"] else "Inactive"
            md.append(
                f"| {entry['subdomain']} | {entry['priority']} | {classifications} | {status} |"
            )

        return "\n".join(md)
