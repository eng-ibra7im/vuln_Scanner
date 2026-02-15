#!/usr/bin/env python3
"""
Example usage scripts for Subdomain Enumeration Orchestrator
Demonstrates various ways to use the system programmatically.
"""

import json
from orchestrator import SubdomainOrchestrator
from config import Config
from formatter import ResultFormatter


def example_1_basic_scan():
    """Example 1: Basic subdomain scan"""
    print("=" * 60)
    print("Example 1: Basic Subdomain Scan")
    print("=" * 60)

    # Load configuration
    config = Config.load("config.json")

    # Create orchestrator
    orchestrator = SubdomainOrchestrator(config)

    # Run scan
    target = "example.com"
    print(f"\nScanning {target}...\n")
    results = orchestrator.orchestrate(target)

    # Display summary
    if results.get("success"):
        summary = results["summary"]
        print(f"\nResults:")
        print(f"  Total Subdomains: {summary['total_subdomains']}")
        print(f"  Validated: {summary['validated_subdomains']}")
        print(f"  High Priority: {summary['high_priority_count']}")
        print(f"  Medium Priority: {summary['medium_priority_count']}")
        print(f"  Low Priority: {summary['low_priority_count']}")
    else:
        print(f"Scan failed: {results.get('error')}")


def example_2_custom_config():
    """Example 2: Custom configuration"""
    print("\n" + "=" * 60)
    print("Example 2: Custom Configuration")
    print("=" * 60)

    # Create custom configuration
    config = Config.get_default()

    # Enable only specific tools
    config.disable_tool("sublist3r")
    config.disable_tool("ffuf")

    # Adjust settings
    config.parallel_execution = False  # Sequential execution
    config.save_results = False  # Don't save to disk
    config.perform_dns_validation = True

    print("\nEnabled tools:", config.get_enabled_tools())
    print("Parallel execution:", config.parallel_execution)

    # Run scan with custom config
    orchestrator = SubdomainOrchestrator(config)
    target = "example.com"
    print(f"\nScanning {target} with custom config...\n")
    results = orchestrator.orchestrate(target)

    print(f"\nFound {results['summary']['total_subdomains']} subdomains")


def example_3_filter_results():
    """Example 3: Filtering and analyzing results"""
    print("\n" + "=" * 60)
    print("Example 3: Filtering Results")
    print("=" * 60)

    config = Config.load("config.json")
    orchestrator = SubdomainOrchestrator(config)

    target = "example.com"
    print(f"\nScanning {target}...\n")
    results = orchestrator.orchestrate(target)

    if results.get("success"):
        # Filter high priority subdomains
        high_priority = [s for s in results["subdomains"] if s["priority"] == "high"]

        print(f"\nHigh Priority Subdomains ({len(high_priority)}):")
        for sub in high_priority[:10]:  # Show top 10
            classifications = ", ".join(sub["classifications"]) or "None"
            print(f"  - {sub['subdomain']}")
            print(f"    Classifications: {classifications}")
            print(f"    Status: {sub['status']}")
            print()

        # Filter by classification
        admin_subs = [
            s for s in results["subdomains"] if "admin" in s["classifications"]
        ]

        print(f"\nAdmin Subdomains ({len(admin_subs)}):")
        for sub in admin_subs:
            print(f"  - {sub['subdomain']}")


def example_4_export_formats():
    """Example 4: Different export formats"""
    print("\n" + "=" * 60)
    print("Example 4: Export Formats")
    print("=" * 60)

    config = Config.load("config.json")
    config.save_results = False
    orchestrator = SubdomainOrchestrator(config)

    target = "example.com"
    print(f"\nScanning {target}...\n")
    results = orchestrator.orchestrate(target)

    if results.get("success"):
        formatter = ResultFormatter()

        # CSV export
        print("\n--- CSV Format (first 5 lines) ---")
        csv_output = formatter.format_csv(results)
        print("\n".join(csv_output.split("\n")[:5]))

        # Markdown export
        print("\n--- Markdown Format (first 20 lines) ---")
        md_output = formatter.format_markdown(results, target)
        print("\n".join(md_output.split("\n")[:20]))

        # Save to files
        with open("example_output.csv", "w") as f:
            f.write(csv_output)
        print("\n✓ Saved to example_output.csv")

        with open("example_output.md", "w") as f:
            f.write(md_output)
        print("✓ Saved to example_output.md")


def example_5_recommendations():
    """Example 5: Security recommendations"""
    print("\n" + "=" * 60)
    print("Example 5: Security Recommendations")
    print("=" * 60)

    config = Config.load("config.json")
    orchestrator = SubdomainOrchestrator(config)

    target = "example.com"
    print(f"\nScanning {target}...\n")
    results = orchestrator.orchestrate(target)

    if results.get("success") and results.get("recommendations"):
        print("\nSecurity Recommendations:")
        print("-" * 60)

        for rec in results["recommendations"]:
            priority_emoji = {
                "critical": "🔴",
                "high": "🟠",
                "medium": "🟡",
                "low": "🟢",
                "info": "ℹ️",
            }

            emoji = priority_emoji.get(rec["priority"], "•")
            print(f"\n{emoji} [{rec['priority'].upper()}] {rec['title']}")
            print(f"   Category: {rec['category']}")
            print(f"   {rec['description']}")
            print(f"   Action: {rec['action']}")


def example_6_patterns():
    """Example 6: Pattern analysis"""
    print("\n" + "=" * 60)
    print("Example 6: Pattern Analysis")
    print("=" * 60)

    config = Config.load("config.json")
    orchestrator = SubdomainOrchestrator(config)

    target = "example.com"
    print(f"\nScanning {target}...\n")
    results = orchestrator.orchestrate(target)

    if results.get("success"):
        patterns = results.get("patterns", {})

        print("\n--- Common Prefixes ---")
        for prefix_info in patterns.get("common_prefixes", [])[:5]:
            print(f"  {prefix_info['prefix']}: {prefix_info['count']} occurrences")

        print("\n--- Numbered Series ---")
        for series in patterns.get("numbered_series", []):
            print(
                f"  {series['base']}: range {series['range']} ({series['count']} total)"
            )

        print("\n--- Environment Indicators ---")
        for env in patterns.get("environment_indicators", []):
            print(f"  {env['environment']}: {env['count']} subdomains")

        print("\n--- Technology Indicators ---")
        for tech in patterns.get("technology_indicators", []):
            print(f"  {tech['technology']}: {tech['count']} subdomains")


def example_7_tool_comparison():
    """Example 7: Tool performance comparison"""
    print("\n" + "=" * 60)
    print("Example 7: Tool Performance Comparison")
    print("=" * 60)

    config = Config.load("config.json")
    orchestrator = SubdomainOrchestrator(config)

    target = "example.com"
    print(f"\nScanning {target}...\n")
    results = orchestrator.orchestrate(target)

    if results.get("success"):
        print("\n--- Tool Performance ---")
        print(
            f"{'Tool':<15} {'Status':<10} {'Time (s)':<12} {'Found':<10} {'Contribution %':<15}"
        )
        print("-" * 70)

        for tool_perf in results.get("tool_performance", []):
            tool_cov = results.get("tool_coverage", {}).get(tool_perf["tool_name"], {})

            print(
                f"{tool_perf['tool_name']:<15} "
                f"{tool_perf['status']:<10} "
                f"{tool_perf['execution_time_seconds']:<12.2f} "
                f"{tool_perf['subdomains_found']:<10} "
                f"{tool_cov.get('contribution_rate', 0):<15.2f}"
            )


def main():
    """Run all examples"""
    print("\n" + "=" * 60)
    print("Subdomain Enumeration Orchestrator - Examples")
    print("=" * 60)
    print("\nThese examples demonstrate programmatic usage.")
    print("Note: Using 'example.com' as a safe test domain.")
    print("      No actual scanning will occur without real tools installed.\n")

    try:
        # Run examples
        example_1_basic_scan()
        example_2_custom_config()
        example_3_filter_results()
        example_4_export_formats()
        example_5_recommendations()
        example_6_patterns()
        example_7_tool_comparison()

        print("\n" + "=" * 60)
        print("All examples completed!")
        print("=" * 60)

    except Exception as e:
        print(f"\n❌ Error running examples: {e}")
        print("\nMake sure to:")
        print("  1. Run 'python setup.py' first")
        print("  2. Have config.json in the current directory")
        print("  3. Install required Python packages")


if __name__ == "__main__":
    main()
