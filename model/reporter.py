#!/usr/bin/env python3
"""
Web Reporting Module for Subdomain Enumeration Results
Generates HTML reports with tables, charts, and summary statistics.

This module ONLY displays validated JSON results.
It does NOT modify results or infer new data.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List
import base64
from io import BytesIO


class SubdomainReporter:
    """
    Generates web-based reports from subdomain enumeration results.
    Strictly displays data without modification or inference.
    """

    def __init__(self):
        self.template_dir = Path(__file__).parent / "templates"
        self.template_dir.mkdir(exist_ok=True)

    def generate_report(self, results: Dict[str, Any], output_path: str = None) -> str:
        """
        Generate HTML report from validated JSON results.

        Args:
            results: Validated JSON results from subdomain orchestrator
            output_path: Optional path to save HTML report

        Returns:
            HTML string of the complete report
        """
        if not results.get("success"):
            return self._generate_error_report(results.get("error", "Unknown error"))

        # Generate HTML sections
        html_parts = []
        html_parts.append(self._generate_html_header())
        html_parts.append(self._generate_summary_section(results))
        html_parts.append(self._generate_statistics_section(results))
        html_parts.append(self._generate_priority_distribution_chart(results))
        html_parts.append(self._generate_subdomains_table(results))
        html_parts.append(self._generate_tool_performance_chart(results))
        html_parts.append(self._generate_patterns_section(results))
        html_parts.append(self._generate_recommendations_section(results))
        html_parts.append(self._generate_html_footer())

        html_report = "\n".join(html_parts)

        # Save to file if path provided
        if output_path:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(html_report)

        return html_report

    def _generate_html_header(self) -> str:
        """Generate HTML header with styles and Chart.js"""
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Subdomain Enumeration Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: #f5f7fa;
            color: #2c3e50;
            line-height: 1.6;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        
        header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px 20px;
            margin-bottom: 30px;
            border-radius: 8px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        header .subtitle {
            opacity: 0.9;
            font-size: 1.1em;
        }
        
        .section {
            background: white;
            padding: 30px;
            margin-bottom: 25px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .section h2 {
            color: #667eea;
            font-size: 1.8em;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #667eea;
        }
        
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        
        .stat-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 25px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            transition: transform 0.2s;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
        }
        
        .stat-card .value {
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 5px;
        }
        
        .stat-card .label {
            font-size: 0.9em;
            opacity: 0.9;
        }
        
        .chart-container {
            position: relative;
            height: 400px;
            margin: 30px 0;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        
        table th {
            background: #667eea;
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: 600;
        }
        
        table td {
            padding: 10px 12px;
            border-bottom: 1px solid #e0e0e0;
        }
        
        table tr:hover {
            background: #f8f9fa;
        }
        
        .priority-high {
            background: #ff4757;
            color: white;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: 600;
        }
        
        .priority-medium {
            background: #ffa502;
            color: white;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: 600;
        }
        
        .priority-low {
            background: #2ed573;
            color: white;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: 600;
        }
        
        .status-active {
            color: #2ed573;
            font-weight: 600;
        }
        
        .status-inactive {
            color: #ff4757;
            font-weight: 600;
        }
        
        .badge {
            display: inline-block;
            background: #e0e0e0;
            color: #2c3e50;
            padding: 3px 8px;
            border-radius: 4px;
            margin-right: 5px;
            font-size: 0.85em;
        }
        
        .recommendation {
            border-left: 4px solid #667eea;
            padding: 15px;
            margin-bottom: 15px;
            background: #f8f9fa;
        }
        
        .recommendation.critical {
            border-left-color: #ff4757;
        }
        
        .recommendation.high {
            border-left-color: #ffa502;
        }
        
        .recommendation.medium {
            border-left-color: #ffd32a;
        }
        
        .recommendation.low {
            border-left-color: #2ed573;
        }
        
        .recommendation h4 {
            color: #2c3e50;
            margin-bottom: 8px;
        }
        
        .recommendation .priority-badge {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: 600;
            margin-bottom: 8px;
        }
        
        .metadata {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
            background: #f8f9fa;
            padding: 20px;
            border-radius: 6px;
        }
        
        .metadata-item {
            display: flex;
            flex-direction: column;
        }
        
        .metadata-item .key {
            font-weight: 600;
            color: #667eea;
            margin-bottom: 4px;
        }
        
        .metadata-item .value {
            color: #2c3e50;
        }
        
        footer {
            text-align: center;
            padding: 20px;
            color: #7f8c8d;
            margin-top: 30px;
        }
        
        .no-data {
            text-align: center;
            color: #7f8c8d;
            padding: 40px;
            font-style: italic;
        }
        
        @media print {
            body {
                background: white;
            }
            .section {
                box-shadow: none;
                page-break-inside: avoid;
            }
        }
    </style>
</head>
<body>
"""

    def _generate_summary_section(self, results: Dict[str, Any]) -> str:
        """Generate summary section with key statistics"""
        metadata = results.get("metadata", {})
        summary = results.get("summary", {})

        html = f"""
    <div class="container">
        <header>
            <h1>Subdomain Enumeration Report</h1>
            <div class="subtitle">Target: {metadata.get('target_domain', 'N/A')}</div>
            <div class="subtitle">Generated: {metadata.get('scan_timestamp', 'N/A')}</div>
        </header>
        
        <div class="section">
            <h2>Summary Statistics</h2>
            <div class="summary-grid">
                <div class="stat-card">
                    <div class="value">{summary.get('total_subdomains', 0)}</div>
                    <div class="label">Total Subdomains</div>
                </div>
                <div class="stat-card">
                    <div class="value">{summary.get('validated_subdomains', 0)}</div>
                    <div class="label">Validated</div>
                </div>
                <div class="stat-card">
                    <div class="value">{summary.get('validation_rate_percent', 0)}%</div>
                    <div class="label">Validation Rate</div>
                </div>
                <div class="stat-card">
                    <div class="value">{summary.get('high_priority_count', 0)}</div>
                    <div class="label">High Priority</div>
                </div>
                <div class="stat-card">
                    <div class="value">{summary.get('tools_successful', 0)}/{summary.get('tools_executed', 0)}</div>
                    <div class="label">Tools Executed</div>
                </div>
                <div class="stat-card">
                    <div class="value">{metadata.get('execution_time_seconds', 0):.1f}s</div>
                    <div class="label">Execution Time</div>
                </div>
            </div>
        </div>
"""
        return html

    def _generate_statistics_section(self, results: Dict[str, Any]) -> str:
        """Generate detailed statistics section"""
        stats = results.get("statistics", {})

        html = """
        <div class="section">
            <h2>Detailed Statistics</h2>
            <div class="metadata">
"""

        # Priority distribution
        priority_dist = stats.get("priority_distribution", {})
        html += f"""
                <div class="metadata-item">
                    <div class="key">High Priority</div>
                    <div class="value">{priority_dist.get('high', 0)} subdomains</div>
                </div>
                <div class="metadata-item">
                    <div class="key">Medium Priority</div>
                    <div class="value">{priority_dist.get('medium', 0)} subdomains</div>
                </div>
                <div class="metadata-item">
                    <div class="key">Low Priority</div>
                    <div class="value">{priority_dist.get('low', 0)} subdomains</div>
                </div>
                <div class="metadata-item">
                    <div class="key">Validation Rate</div>
                    <div class="value">{stats.get('validation_rate', 0)}%</div>
                </div>
"""

        # Depth distribution
        depth_dist = stats.get("depth_distribution", {})
        if depth_dist:
            html += f"""
                <div class="metadata-item">
                    <div class="key">Depth Distribution</div>
                    <div class="value">{', '.join(f'D{k}:{v}' for k, v in sorted(depth_dist.items()))}</div>
                </div>
"""

        html += """
            </div>
        </div>
"""
        return html

    def _generate_priority_distribution_chart(self, results: Dict[str, Any]) -> str:
        """Generate priority distribution pie chart"""
        stats = results.get("statistics", {})
        priority_dist = stats.get("priority_distribution", {})

        high = priority_dist.get("high", 0)
        medium = priority_dist.get("medium", 0)
        low = priority_dist.get("low", 0)

        html = f"""
        <div class="section">
            <h2>Priority Distribution</h2>
            <div class="chart-container">
                <canvas id="priorityChart"></canvas>
            </div>
        </div>
        
        <script>
        const priorityCtx = document.getElementById('priorityChart').getContext('2d');
        new Chart(priorityCtx, {{
            type: 'doughnut',
            data: {{
                labels: ['High Priority', 'Medium Priority', 'Low Priority'],
                datasets: [{{
                    data: [{high}, {medium}, {low}],
                    backgroundColor: ['#ff4757', '#ffa502', '#2ed573'],
                    borderWidth: 0
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{
                        position: 'bottom'
                    }},
                    title: {{
                        display: true,
                        text: 'Subdomains by Priority Level'
                    }}
                }}
            }}
        }});
        </script>
"""
        return html

    def _generate_subdomains_table(self, results: Dict[str, Any]) -> str:
        """Generate subdomains table (showing top 100 by priority)"""
        subdomains = results.get("subdomains", [])[:100]  # Show top 100

        html = """
        <div class="section">
            <h2>Discovered Subdomains</h2>
"""

        if not subdomains:
            html += '<div class="no-data">No subdomains found</div>'
        else:
            html += f"<p>Showing top {len(subdomains)} subdomains by priority</p>"
            html += """
            <table>
                <thead>
                    <tr>
                        <th>Subdomain</th>
                        <th>Priority</th>
                        <th>Status</th>
                        <th>Classifications</th>
                        <th>IP Addresses</th>
                    </tr>
                </thead>
                <tbody>
"""

            for sub in subdomains:
                priority = sub.get("priority", "low")
                priority_class = f"priority-{priority}"
                status = sub.get("status", "unknown")
                status_class = f"status-{status}"

                classifications = sub.get("classifications", [])
                classifications_html = "".join(
                    f'<span class="badge">{c}</span>' for c in classifications
                )
                if not classifications_html:
                    classifications_html = '<span style="color: #999;">None</span>'

                ip_addresses = sub.get("dns_records", {}).get("ip_addresses", [])
                ips_html = (
                    "<br>".join(ip_addresses)
                    if ip_addresses
                    else '<span style="color: #999;">-</span>'
                )

                html += f"""
                    <tr>
                        <td><strong>{sub.get('subdomain', '')}</strong></td>
                        <td><span class="{priority_class}">{priority.upper()}</span></td>
                        <td class="{status_class}">{status.upper()}</td>
                        <td>{classifications_html}</td>
                        <td>{ips_html}</td>
                    </tr>
"""

            html += """
                </tbody>
            </table>
"""

        html += "</div>"
        return html

    def _generate_tool_performance_chart(self, results: Dict[str, Any]) -> str:
        """Generate tool performance bar chart"""
        tool_performance = results.get("tool_performance", [])

        if not tool_performance:
            return ""

        tool_names = [tool["tool_name"] for tool in tool_performance]
        tool_counts = [tool["subdomains_found"] for tool in tool_performance]
        tool_times = [tool["execution_time_seconds"] for tool in tool_performance]

        # Convert lists to JavaScript arrays
        tool_names_js = json.dumps(tool_names)
        tool_counts_js = json.dumps(tool_counts)
        tool_times_js = json.dumps(tool_times)

        html = f"""
        <div class="section">
            <h2>Tool Performance</h2>
            <div class="chart-container">
                <canvas id="toolPerformanceChart"></canvas>
            </div>
            <div class="chart-container">
                <canvas id="toolTimeChart"></canvas>
            </div>
        </div>
        
        <script>
        const toolPerfCtx = document.getElementById('toolPerformanceChart').getContext('2d');
        new Chart(toolPerfCtx, {{
            type: 'bar',
            data: {{
                labels: {tool_names_js},
                datasets: [{{
                    label: 'Subdomains Found',
                    data: {tool_counts_js},
                    backgroundColor: '#667eea',
                    borderRadius: 4
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{
                        display: false
                    }},
                    title: {{
                        display: true,
                        text: 'Subdomains Found by Tool'
                    }}
                }},
                scales: {{
                    y: {{
                        beginAtZero: true
                    }}
                }}
            }}
        }});
        
        const toolTimeCtx = document.getElementById('toolTimeChart').getContext('2d');
        new Chart(toolTimeCtx, {{
            type: 'bar',
            data: {{
                labels: {tool_names_js},
                datasets: [{{
                    label: 'Execution Time (seconds)',
                    data: {tool_times_js},
                    backgroundColor: '#764ba2',
                    borderRadius: 4
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{
                        display: false
                    }},
                    title: {{
                        display: true,
                        text: 'Execution Time by Tool'
                    }}
                }},
                scales: {{
                    y: {{
                        beginAtZero: true
                    }}
                }}
            }}
        }});
        </script>
"""
        return html

    def _generate_patterns_section(self, results: Dict[str, Any]) -> str:
        """Generate patterns section"""
        patterns = results.get("patterns", {})

        if not patterns:
            return ""

        html = """
        <div class="section">
            <h2>Detected Patterns</h2>
"""

        # Common prefixes
        common_prefixes = patterns.get("common_prefixes", [])
        if common_prefixes:
            html += "<h3>Common Prefixes</h3><table><thead><tr><th>Prefix</th><th>Count</th></tr></thead><tbody>"
            for prefix_info in common_prefixes[:10]:
                html += f'<tr><td>{prefix_info["prefix"]}</td><td>{prefix_info["count"]}</td></tr>'
            html += "</tbody></table>"

        # Environment indicators
        env_indicators = patterns.get("environment_indicators", [])
        if env_indicators:
            html += '<h3 style="margin-top: 20px;">Environment Indicators</h3><table><thead><tr><th>Environment</th><th>Count</th></tr></thead><tbody>'
            for env in env_indicators:
                html += f'<tr><td>{env["environment"]}</td><td>{env["count"]}</td></tr>'
            html += "</tbody></table>"

        # Technology indicators
        tech_indicators = patterns.get("technology_indicators", [])
        if tech_indicators:
            html += '<h3 style="margin-top: 20px;">Technology Indicators</h3><table><thead><tr><th>Technology</th><th>Count</th></tr></thead><tbody>'
            for tech in tech_indicators:
                html += (
                    f'<tr><td>{tech["technology"]}</td><td>{tech["count"]}</td></tr>'
                )
            html += "</tbody></table>"

        html += "</div>"
        return html

    def _generate_recommendations_section(self, results: Dict[str, Any]) -> str:
        """Generate recommendations section"""
        recommendations = results.get("recommendations", [])

        if not recommendations:
            return ""

        html = """
        <div class="section">
            <h2>Security Recommendations</h2>
"""

        for rec in recommendations:
            priority = rec.get("priority", "info")
            html += f"""
            <div class="recommendation {priority}">
                <span class="priority-badge" style="background: {'#ff4757' if priority == 'critical' else '#ffa502' if priority == 'high' else '#ffd32a' if priority == 'medium' else '#2ed573' if priority == 'low' else '#95a5a6'}; color: white;">{priority.upper()}</span>
                <h4>{rec. get('title', '')}</h4>
                <p><strong>Category:</strong> {rec.get('category', '')}</p>
                <p>{rec.get('description', '')}</p>
                <p><strong>Action:</strong> {rec.get('action', '')}</p>
            </div>
"""

        html += "</div>"
        return html

    def _generate_html_footer(self) -> str:
        """Generate HTML footer"""
        return f"""
    </div>
    <footer>
        <p>Generated by Subdomain Enumeration Orchestrator</p>
        <p>Report generated on {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC</p>
    </footer>
</body>
</html>
"""

    def _generate_error_report(self, error_message: str) -> str:
        """Generate error report HTML"""
        return f"""<!DOCTYPE html>
<html>
<head>
    <title>Report Error</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            padding: 50px;
            background: #f5f5f5;
        }}
        .error {{
            background: white;
            padding: 30px;
            border-left: 4px solid #ff4757;
            border-radius: 4px;
        }}
    </style>
</head>
<body>
    <div class="error">
        <h1>Report Generation Error</h1>
        <p><strong>Error:</strong> {error_message}</p>
    </div>
</body>
</html>
"""


def generate_report_from_json_file(json_path: str, output_path: str = None) -> str:
    """
    Generate HTML report from JSON file.

    Args:
        json_path: Path to JSON results file
        output_path: Path to save HTML report (optional)

    Returns:
        HTML report string
    """
    with open(json_path, "r") as f:
        results = json.load(f)

    reporter = SubdomainReporter()

    if output_path is None:
        # Auto-generate output path
        json_file = Path(json_path)
        output_path = json_file.parent / f"{json_file.stem}_report.html"

    return reporter.generate_report(results, str(output_path))


def main():
    """CLI interface for report generation"""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python reporter.py <results.json> [output.html]")
        print("Example: python reporter.py results/scan_20260213.json report.html")
        sys.exit(1)

    json_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else None

    try:
        output_file = generate_report_from_json_file(json_path, output_path)
        print(f"Report generated successfully: {output_file}")
    except Exception as e:
        print(f"Error generating report: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
