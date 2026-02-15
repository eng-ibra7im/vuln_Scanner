#!/usr/bin/env python3
"""
CLI Interface for Subdomain Enumeration Orchestrator
Provides user-friendly command-line interface with additional options.
"""

import argparse
import json
import sys
from pathlib import Path
from orchestrator import SubdomainOrchestrator
from config import Config
from formatter import ResultFormatter


def main():
    parser = argparse.ArgumentParser(
        description="Subdomain Enumeration Orchestrator - Academic Security Research Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s example.com                    # Basic scan
  %(prog)s example.com --output report.json  # Save to specific file
  %(prog)s example.com --format markdown     # Output as Markdown
  %(prog)s example.com --tools subfinder,amass  # Use specific tools only
  %(prog)s example.com --no-validate         # Skip DNS validation (faster)
  
For more information, see README.md
        """,
    )

    # Required arguments
    parser.add_argument("domain", help="Target domain to enumerate (e.g., example.com)")

    # Output options
    parser.add_argument(
        "-o", "--output", help="Output file path (default: stdout)", type=str
    )

    parser.add_argument(
        "-f",
        "--format",
        choices=["json", "csv", "markdown"],
        default="json",
        help="Output format (default: json)",
    )

    # Configuration options
    parser.add_argument(
        "-c",
        "--config",
        default="config.json",
        help="Configuration file path (default: config.json)",
    )

    parser.add_argument(
        "--tools",
        help="Comma-separated list of tools to use (e.g., subfinder,amass)",
        type=str,
    )

    parser.add_argument(
        "--no-parallel",
        action="store_true",
        help="Execute tools sequentially instead of parallel",
    )

    parser.add_argument(
        "--no-validate",
        action="store_true",
        help="Skip DNS validation (faster but less accurate)",
    )

    parser.add_argument(
        "--no-save",
        action="store_true",
        help="Do not save results to results directory",
    )

    # Display options
    parser.add_argument(
        "--summary-only", action="store_true", help="Show only summary statistics"
    )

    parser.add_argument(
        "--high-priority-only",
        action="store_true",
        help="Show only high priority subdomains",
    )

    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose output"
    )

    parser.add_argument(
        "--version",
        action="version",
        version="Subdomain Enumeration Orchestrator v1.0.0",
    )

    args = parser.parse_args()

    # Load configuration
    try:
        config = Config.load(args.config)
    except FileNotFoundError:
        print(f"Error: Configuration file '{args.config}' not found.", file=sys.stderr)
        print(
            "Run 'python config.py' to generate default configuration.", file=sys.stderr
        )
        sys.exit(1)

    # Apply command-line overrides
    if args.tools:
        # Disable all tools first
        for tool in config.tools:
            config.tools[tool]["enabled"] = False
        # Enable specified tools
        for tool in args.tools.split(","):
            tool = tool.strip()
            if tool in config.tools:
                config.tools[tool]["enabled"] = True
            else:
                print(f"Warning: Unknown tool '{tool}' - skipping", file=sys.stderr)

    if args.no_parallel:
        config.parallel_execution = False

    if args.no_validate:
        config.perform_dns_validation = False

    if args.no_save:
        config.save_results = False

    # Set logging level
    if not args.verbose:
        import logging

        logging.getLogger("SubdomainOrchestrator").setLevel(logging.WARNING)

    # Create orchestrator and run
    print(f"Starting subdomain enumeration for: {args.domain}", file=sys.stderr)
    print(f"Enabled tools: {', '.join(config.get_enabled_tools())}", file=sys.stderr)
    print("", file=sys.stderr)

    orchestrator = SubdomainOrchestrator(config)
    results = orchestrator.orchestrate(args.domain)

    # Filter results if requested
    if args.high_priority_only and results.get("subdomains"):
        results["subdomains"] = [
            s for s in results["subdomains"] if s["priority"] == "high"
        ]

    # Format output
    if args.format == "json":
        output = json.dumps(results, indent=2)
    elif args.format == "csv":
        formatter = ResultFormatter()
        output = formatter.format_csv(results)
    elif args.format == "markdown":
        formatter = ResultFormatter()
        output = formatter.format_markdown(results, args.domain)

    # Handle summary-only mode
    if args.summary_only and results.get("summary"):
        summary_output = {
            "target": args.domain,
            "summary": results["summary"],
            "recommendations": results.get("recommendations", []),
        }
        output = json.dumps(summary_output, indent=2)

    # Output results
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            f.write(output)
        print(f"\nResults saved to: {args.output}", file=sys.stderr)
    else:
        print(output)

    # Print summary to stderr
    if results.get("success") and not args.summary_only:
        print("\n" + "=" * 60, file=sys.stderr)
        print("SUMMARY", file=sys.stderr)
        print("=" * 60, file=sys.stderr)
        summary = results.get("summary", {})
        print(
            f"Total Subdomains: {summary.get('total_subdomains', 0)}", file=sys.stderr
        )
        print(
            f"Validated: {summary.get('validated_subdomains', 0)} ({summary.get('validation_rate_percent', 0)}%)",
            file=sys.stderr,
        )
        print(
            f"High Priority: {summary.get('high_priority_count', 0)}", file=sys.stderr
        )
        print(
            f"Medium Priority: {summary.get('medium_priority_count', 0)}",
            file=sys.stderr,
        )
        print(f"Low Priority: {summary.get('low_priority_count', 0)}", file=sys.stderr)
        print("=" * 60, file=sys.stderr)


if __name__ == "__main__":
    main()
