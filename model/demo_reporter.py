#!/usr/bin/env python3
"""
Demo/Test script for Web Reporting System
Generates sample data and demonstrates report generation.
"""

import json
from datetime import datetime
from reporter import SubdomainReporter
from pathlib import Path


def generate_sample_results():
    """Generate sample subdomain enumeration results for testing"""
    return {
        "success": True,
        "metadata": {
            "target_domain": "example.com",
            "scan_timestamp": datetime.utcnow().isoformat() + "Z",
            "execution_time_seconds": 45.32,
            "orchestrator_version": "1.0.0",
            "report_format_version": "1.0",
        },
        "summary": {
            "total_subdomains": 25,
            "validated_subdomains": 20,
            "validation_rate_percent": 80.0,
            "high_priority_count": 3,
            "medium_priority_count": 8,
            "low_priority_count": 14,
            "tools_executed": 3,
            "tools_successful": 3,
        },
        "subdomains": [
            {
                "subdomain": "admin.example.com",
                "priority": "high",
                "priority_score": 35,
                "status": "active",
                "dns_records": {
                    "validated": True,
                    "ip_addresses": ["192.168.1.100"],
                    "cname": None,
                    "has_mx_records": False,
                },
                "classifications": ["admin"],
                "metadata": {"depth": 1, "is_wildcard": False},
            },
            {
                "subdomain": "api.example.com",
                "priority": "high",
                "priority_score": 30,
                "status": "active",
                "dns_records": {
                    "validated": True,
                    "ip_addresses": ["192.168.1.101", "192.168.1.102"],
                    "cname": None,
                    "has_mx_records": False,
                },
                "classifications": ["api"],
                "metadata": {"depth": 1, "is_wildcard": False},
            },
            {
                "subdomain": "dev.example.com",
                "priority": "high",
                "priority_score": 28,
                "status": "active",
                "dns_records": {
                    "validated": True,
                    "ip_addresses": ["192.168.1.103"],
                    "cname": None,
                    "has_mx_records": False,
                },
                "classifications": ["development"],
                "metadata": {"depth": 1, "is_wildcard": False},
            },
            {
                "subdomain": "mail.example.com",
                "priority": "medium",
                "priority_score": 18,
                "status": "active",
                "dns_records": {
                    "validated": True,
                    "ip_addresses": ["192.168.1.104"],
                    "cname": None,
                    "has_mx_records": True,
                },
                "classifications": ["mail"],
                "metadata": {"depth": 1, "is_wildcard": False},
            },
            {
                "subdomain": "www.example.com",
                "priority": "medium",
                "priority_score": 15,
                "status": "active",
                "dns_records": {
                    "validated": True,
                    "ip_addresses": ["192.168.1.105"],
                    "cname": None,
                    "has_mx_records": False,
                },
                "classifications": [],
                "metadata": {"depth": 1, "is_wildcard": False},
            },
            {
                "subdomain": "vpn.example.com",
                "priority": "medium",
                "priority_score": 14,
                "status": "active",
                "dns_records": {
                    "validated": True,
                    "ip_addresses": ["192.168.1.106"],
                    "cname": None,
                    "has_mx_records": False,
                },
                "classifications": ["vpn"],
                "metadata": {"depth": 1, "is_wildcard": False},
            },
            {
                "subdomain": "staging.example.com",
                "priority": "medium",
                "priority_score": 13,
                "status": "active",
                "dns_records": {
                    "validated": True,
                    "ip_addresses": ["192.168.1.107"],
                    "cname": None,
                    "has_mx_records": False,
                },
                "classifications": ["development"],
                "metadata": {"depth": 1, "is_wildcard": False},
            },
            {
                "subdomain": "test.example.com",
                "priority": "medium",
                "priority_score": 12,
                "status": "active",
                "dns_records": {
                    "validated": True,
                    "ip_addresses": ["192.168.1.108"],
                    "cname": None,
                    "has_mx_records": False,
                },
                "classifications": ["development"],
                "metadata": {"depth": 1, "is_wildcard": False},
            },
            {
                "subdomain": "cdn.example.com",
                "priority": "medium",
                "priority_score": 11,
                "status": "active",
                "dns_records": {
                    "validated": True,
                    "ip_addresses": ["192.168.1.109"],
                    "cname": "cdn.cloudfront.net",
                    "has_mx_records": False,
                },
                "classifications": ["storage"],
                "metadata": {"depth": 1, "is_wildcard": False},
            },
            {
                "subdomain": "blog.example.com",
                "priority": "low",
                "priority_score": 8,
                "status": "active",
                "dns_records": {
                    "validated": True,
                    "ip_addresses": ["192.168.1.110"],
                    "cname": None,
                    "has_mx_records": False,
                },
                "classifications": [],
                "metadata": {"depth": 1, "is_wildcard": False},
            },
            {
                "subdomain": "shop.example.com",
                "priority": "low",
                "priority_score": 7,
                "status": "active",
                "dns_records": {
                    "validated": True,
                    "ip_addresses": ["192.168.1.111"],
                    "cname": None,
                    "has_mx_records": False,
                },
                "classifications": [],
                "metadata": {"depth": 1, "is_wildcard": False},
            },
            {
                "subdomain": "ftp.example.com",
                "priority": "low",
                "priority_score": 6,
                "status": "active",
                "dns_records": {
                    "validated": True,
                    "ip_addresses": ["192.168.1.112"],
                    "cname": None,
                    "has_mx_records": False,
                },
                "classifications": [],
                "metadata": {"depth": 1, "is_wildcard": False},
            },
            {
                "subdomain": "old.example.com",
                "priority": "low",
                "priority_score": 5,
                "status": "inactive",
                "dns_records": {
                    "validated": False,
                    "ip_addresses": [],
                    "cname": None,
                    "has_mx_records": False,
                },
                "classifications": [],
                "metadata": {"depth": 1, "is_wildcard": False},
            },
        ],
        "statistics": {
            "tools_executed": 3,
            "tools_successful": 3,
            "total_execution_time": 45.32,
            "subdomains_per_tool": {"subfinder": 15, "amass": 18, "assetfinder": 12},
            "priority_distribution": {"high": 3, "medium": 8, "low": 14},
            "classification_distribution": {
                "admin": 1,
                "api": 1,
                "development": 3,
                "mail": 1,
                "vpn": 1,
                "storage": 1,
            },
            "depth_distribution": {"1": 25},
            "validation_rate": 80.0,
        },
        "patterns": {
            "common_prefixes": [
                {"prefix": "www", "count": 1},
                {"prefix": "mail", "count": 1},
                {"prefix": "api", "count": 1},
                {"prefix": "admin", "count": 1},
                {"prefix": "dev", "count": 1},
            ],
            "numbered_series": [],
            "environment_indicators": [
                {"environment": "dev", "count": 1},
                {"environment": "test", "count": 1},
                {"environment": "stage", "count": 1},
            ],
            "technology_indicators": [
                {"technology": "api", "count": 1},
                {"technology": "mail", "count": 1},
                {"technology": "vpn", "count": 1},
                {"technology": "cdn", "count": 1},
                {"technology": "ftp", "count": 1},
            ],
        },
        "tool_performance": [
            {
                "tool_name": "amass",
                "status": "success",
                "execution_time_seconds": 18.5,
                "subdomains_found": 18,
                "error": None,
            },
            {
                "tool_name": "subfinder",
                "status": "success",
                "execution_time_seconds": 12.3,
                "subdomains_found": 15,
                "error": None,
            },
            {
                "tool_name": "assetfinder",
                "status": "success",
                "execution_time_seconds": 8.2,
                "subdomains_found": 12,
                "error": None,
            },
        ],
        "tool_coverage": {
            "subfinder": {
                "found": 15,
                "contributed": 15,
                "unique_contribution": 2,
                "contribution_rate": 60.0,
            },
            "amass": {
                "found": 18,
                "contributed": 18,
                "unique_contribution": 5,
                "contribution_rate": 72.0,
            },
            "assetfinder": {
                "found": 12,
                "contributed": 12,
                "unique_contribution": 1,
                "contribution_rate": 48.0,
            },
        },
        "recommendations": [
            {
                "category": "security",
                "priority": "critical",
                "title": "Administrative Interfaces Detected",
                "description": "Found 1 subdomain with administrative interfaces.",
                "action": "Ensure proper authentication and access controls are in place",
            },
            {
                "category": "security",
                "priority": "high",
                "title": "Development Environments Exposed",
                "description": "Found 3 development/staging subdomains.",
                "action": "Verify these environments are properly secured or not publicly accessible",
            },
            {
                "category": "security",
                "priority": "medium",
                "title": "API Endpoints Discovered",
                "description": "Found 1 API-related subdomain.",
                "action": "Review API authentication, rate limiting, and security controls",
            },
            {
                "category": "cleanup",
                "priority": "low",
                "title": "Inactive Subdomains Detected",
                "description": "5 subdomains failed DNS validation.",
                "action": "Consider cleaning up stale DNS records",
            },
        ],
    }


def demo_report_generation():
    """Demonstrate report generation with sample data"""
    print("=" * 60)
    print("Web Reporting System - Demo")
    print("=" * 60)

    # Generate sample data
    print("\n1. Generating sample subdomain scan results...")
    sample_data = generate_sample_results()

    # Save sample JSON
    results_dir = Path("results")
    results_dir.mkdir(exist_ok=True)

    json_path = results_dir / "demo_scan_results.json"
    with open(json_path, "w") as f:
        json.dump(sample_data, f, indent=2)
    print(f"   Saved sample JSON: {json_path}")

    # Generate HTML report
    print("\n2. Generating HTML report...")
    reporter = SubdomainReporter()

    html_path = results_dir / "demo_report.html"
    reporter.generate_report(sample_data, str(html_path))
    print(f"   Saved HTML report: {html_path}")

    # Display summary
    print("\n3. Report Summary:")
    print(f"   Target Domain: {sample_data['metadata']['target_domain']}")
    print(f"   Total Subdomains: {sample_data['summary']['total_subdomains']}")
    print(f"   High Priority: {sample_data['summary']['high_priority_count']}")
    print(f"   Medium Priority: {sample_data['summary']['medium_priority_count']}")
    print(f"   Low Priority: {sample_data['summary']['low_priority_count']}")
    print(f"   Validation Rate: {sample_data['summary']['validation_rate_percent']}%")

    print("\n" + "=" * 60)
    print("Demo Complete!")
    print("=" * 60)
    print(f"\nTo view the report:")
    print(f"  1. Open {html_path} in your browser")
    print(f"  2. Or start the dashboard: python dashboard.py")
    print(f"     Then visit: http://localhost:5001")
    print("\nThe sample JSON can be used to test the reporting system.")
    print("=" * 60)


def test_report_sections():
    """Test each section of the report"""
    print("\n" + "=" * 60)
    print("Testing Report Sections")
    print("=" * 60)

    sample_data = generate_sample_results()
    reporter = SubdomainReporter()

    sections = [
        ("HTML Header", "_generate_html_header"),
        ("Summary Section", "_generate_summary_section"),
        ("Statistics Section", "_generate_statistics_section"),
        ("Priority Chart", "_generate_priority_distribution_chart"),
        ("Subdomains Table", "_generate_subdomains_table"),
        ("Tool Performance", "_generate_tool_performance_chart"),
        ("Patterns Section", "_generate_patterns_section"),
        ("Recommendations", "_generate_recommendations_section"),
        ("HTML Footer", "_generate_html_footer"),
    ]

    for section_name, method_name in sections:
        try:
            method = getattr(reporter, method_name)
            if (
                method_name == "_generate_html_header"
                or method_name == "_generate_html_footer"
            ):
                result = method()
            else:
                result = method(sample_data)

            if result:
                print(f"  ✓ {section_name}: OK ({len(result)} chars)")
            else:
                print(f"  ✗ {section_name}: Empty")
        except Exception as e:
            print(f"  ✗ {section_name}: Error - {e}")

    print("=" * 60)


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        test_report_sections()
    else:
        demo_report_generation()
