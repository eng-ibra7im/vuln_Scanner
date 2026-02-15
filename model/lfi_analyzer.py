#!/usr/bin/env python3
"""
LFI Analyzer
Academic Security Research Tool

Analyzes and enriches LFI vulnerability findings from multiple tools.
Provides risk assessment, deduplication, and actionable intelligence.
"""

from typing import List, Dict, Any, Set
from dataclasses import dataclass, asdict
from collections import defaultdict
import re


@dataclass
class AnalyzedLFIFinding:
    """Enhanced LFI finding with analysis"""

    parameter: str
    payload: str
    url: str
    evidence: str
    severity: str
    confidence: str
    tool: str
    response_indicators: List[str]
    risk_score: int
    exploitation_difficulty: str
    remediation: str
    references: List[str]


class LFIAnalyzer:
    """
    Analyzes LFI findings from multiple tools and provides enriched intelligence.
    """

    def __init__(self):
        self.remediation_map = {
            "High": "CRITICAL: Implement strict input validation using whitelists. Use basename() or realpath() to prevent directory traversal. Disable PHP wrappers. Apply the principle of least privilege.",
            "Medium": "IMPORTANT: Validate and sanitize file path inputs. Use a whitelist approach for allowed files. Consider using a mapping/alias system instead of direct file inclusion.",
            "Low": "RECOMMENDED: Review file inclusion logic. Implement proper input validation. Monitor for suspicious activity.",
        }

        self.references = [
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion",
            "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/98.html",
        ]

    def analyze(
        self, target_url: str, findings: List[Any], tool_results: List[Any]
    ) -> Dict[str, Any]:
        """
        Analyze LFI findings and provide enriched intelligence.

        Args:
            target_url: The target URL tested
            findings: List of LFIFinding objects
            tool_results: List of ToolResult objects

        Returns:
            Dictionary with analyzed results
        """

        # Deduplicate findings by parameter + payload pattern
        unique_findings = self._deduplicate_findings(findings)

        # Enrich findings with additional analysis
        analyzed_findings = []
        for finding in unique_findings:
            analyzed = self._enrich_finding(finding)
            analyzed_findings.append(analyzed)

        # Classify by parameter
        findings_by_param = self._group_by_parameter(analyzed_findings)

        # Assess overall risk
        overall_risk = self._assess_overall_risk(analyzed_findings)

        # Generate statistics
        stats = self._generate_statistics(analyzed_findings, tool_results)

        # Generate recommendations
        recommendations = self._generate_recommendations(analyzed_findings)

        return {
            "target_url": target_url,
            "findings": {
                "total": len(analyzed_findings),
                "high_severity": len(
                    [f for f in analyzed_findings if f.severity == "High"]
                ),
                "medium_severity": len(
                    [f for f in analyzed_findings if f.severity == "Medium"]
                ),
                "low_severity": len(
                    [f for f in analyzed_findings if f.severity == "Low"]
                ),
                "by_parameter": findings_by_param,
                "detailed": [asdict(f) for f in analyzed_findings],
            },
            "risk_assessment": overall_risk,
            "statistics": stats,
            "recommendations": recommendations,
        }

    def _deduplicate_findings(self, findings: List[Any]) -> List[Any]:
        """Remove duplicate findings based on parameter and payload pattern"""
        seen = set()
        unique = []

        for finding in findings:
            # Create key based on parameter and simplified payload
            payload_pattern = self._simplify_payload(finding.payload)
            key = f"{finding.parameter}:{payload_pattern}"

            if key not in seen:
                seen.add(key)
                unique.append(finding)

        return unique

    def _simplify_payload(self, payload: str) -> str:
        """Simplify payload to identify patterns"""
        # Normalize traversal depth
        if "../" in payload or "..\\" in payload:
            return "traversal"
        elif "php://" in payload:
            return "php_wrapper"
        elif "%00" in payload:
            return "null_byte"
        elif "file://" in payload:
            return "file_protocol"
        elif "/etc/passwd" in payload or "/windows/win.ini" in payload.lower():
            return "direct_path"
        else:
            return "other"

    def _enrich_finding(self, finding: Any) -> AnalyzedLFIFinding:
        """Enrich a finding with additional analysis"""

        # Calculate risk score (0-100)
        risk_score = self._calculate_risk_score(finding)

        # Assess exploitation difficulty
        difficulty = self._assess_exploitation_difficulty(finding)

        # Get appropriate remediation
        remediation = self.remediation_map.get(
            finding.severity, self.remediation_map["Medium"]
        )

        return AnalyzedLFIFinding(
            parameter=finding.parameter,
            payload=finding.payload,
            url=finding.url,
            evidence=finding.evidence,
            severity=finding.severity,
            confidence=finding.confidence,
            tool=finding.tool,
            response_indicators=finding.response_indicators,
            risk_score=risk_score,
            exploitation_difficulty=difficulty,
            remediation=remediation,
            references=self.references,
        )

    def _calculate_risk_score(self, finding: Any) -> int:
        """Calculate numerical risk score (0-100)"""
        score = 0

        # Base score by severity
        severity_scores = {"High": 70, "Medium": 40, "Low": 20}
        score += severity_scores.get(finding.severity, 20)

        # Confidence modifier
        confidence_modifiers = {"High": 20, "Medium": 10, "Low": 5}
        score += confidence_modifiers.get(finding.confidence, 5)

        # Indicator bonus
        score += min(len(finding.response_indicators) * 2, 10)

        return min(score, 100)

    def _assess_exploitation_difficulty(self, finding: Any) -> str:
        """Assess how difficult it would be to exploit this vulnerability"""

        # Simple traversal = Easy
        if "../" in finding.payload and finding.payload.count("..") <= 5:
            if finding.confidence == "High":
                return "Easy"
            else:
                return "Moderate"

        # PHP wrappers = Moderate (requires understanding)
        if "php://" in finding.payload:
            return "Moderate"

        # Null byte = Moderate (legacy systems only)
        if "%00" in finding.payload:
            return "Moderate"

        # Complex encoding = Hard
        if "%25" in finding.payload or "rot13" in finding.payload:
            return "Hard"

        return "Moderate"

    def _group_by_parameter(
        self, findings: List[AnalyzedLFIFinding]
    ) -> Dict[str, List[Dict]]:
        """Group findings by vulnerable parameter"""
        grouped = defaultdict(list)

        for finding in findings:
            grouped[finding.parameter].append(
                {
                    "payload": finding.payload,
                    "severity": finding.severity,
                    "confidence": finding.confidence,
                    "risk_score": finding.risk_score,
                }
            )

        return dict(grouped)

    def _assess_overall_risk(
        self, findings: List[AnalyzedLFIFinding]
    ) -> Dict[str, Any]:
        """Assess overall risk level for the application"""

        if not findings:
            return {
                "level": "None",
                "score": 0,
                "description": "No LFI vulnerabilities detected.",
            }

        # Calculate average risk score
        avg_score = sum(f.risk_score for f in findings) / len(findings)

        # Count high-confidence high-severity findings
        critical_count = len(
            [f for f in findings if f.severity == "High" and f.confidence == "High"]
        )

        # Determine overall risk level
        if critical_count > 0 or avg_score >= 70:
            level = "Critical"
            description = f"CRITICAL: {critical_count} high-confidence severe LFI vulnerabilities detected. Immediate action required."
        elif avg_score >= 50:
            level = "High"
            description = (
                "HIGH: Multiple LFI vulnerabilities detected. Prioritize remediation."
            )
        elif avg_score >= 30:
            level = "Medium"
            description = "MEDIUM: LFI vulnerabilities detected. Schedule remediation."
        else:
            level = "Low"
            description = "LOW: Potential LFI issues detected. Review and validate."

        return {
            "level": level,
            "score": round(avg_score, 1),
            "description": description,
            "vulnerabilities_count": len(findings),
            "critical_findings": critical_count,
        }

    def _generate_statistics(
        self, findings: List[AnalyzedLFIFinding], tool_results: List[Any]
    ) -> Dict[str, Any]:
        """Generate statistical summary"""

        # Tool effectiveness
        findings_by_tool = defaultdict(int)
        for finding in findings:
            findings_by_tool[finding.tool] += 1

        # Payload type distribution
        payload_types = defaultdict(int)
        for finding in findings:
            ptype = self._simplify_payload(finding.payload)
            payload_types[ptype] += 1

        # Confidence distribution
        confidence_dist = defaultdict(int)
        for finding in findings:
            confidence_dist[finding.confidence] += 1

        return {
            "tools": {
                "total_executed": len(tool_results),
                "successful": len([r for r in tool_results if r.success]),
                "findings_by_tool": dict(findings_by_tool),
            },
            "payload_types": dict(payload_types),
            "confidence_distribution": dict(confidence_dist),
        }

    def _generate_recommendations(
        self, findings: List[AnalyzedLFIFinding]
    ) -> List[str]:
        """Generate actionable recommendations"""

        recommendations = []

        if not findings:
            recommendations.append(
                "✓ No LFI vulnerabilities detected in tested parameters."
            )
            recommendations.append(
                "⚠ Continue monitoring and test additional parameters as the application evolves."
            )
            return recommendations

        # Critical findings
        critical = [
            f for f in findings if f.severity == "High" and f.confidence == "High"
        ]
        if critical:
            recommendations.append(
                f"🔴 CRITICAL: {len(critical)} high-confidence LFI vulnerabilities require immediate remediation."
            )
            recommendations.append(
                "   → Implement strict input validation using whitelists immediately."
            )
            recommendations.append(
                "   → Disable dangerous PHP functions (include, require, fopen with user input)."
            )

        # Traversal vulnerabilities
        traversal = [
            f for f in findings if "traversal" in self._simplify_payload(f.payload)
        ]
        if traversal:
            recommendations.append(
                f"⚠ {len(traversal)} directory traversal vulnerabilities detected."
            )
            recommendations.append(
                "   → Use basename() or realpath() to sanitize file paths."
            )
            recommendations.append(
                "   → Implement path canonicalization and validation."
            )

        # PHP wrapper vulnerabilities
        wrapper = [f for f in findings if "php://" in f.payload.lower()]
        if wrapper:
            recommendations.append(
                f"⚠ {len(wrapper)} PHP wrapper vulnerabilities detected."
            )
            recommendations.append(
                "   → Disable allow_url_include and allow_url_fopen in php.ini."
            )
            recommendations.append("   → Use a whitelist of allowed protocols.")

        # General recommendations
        recommendations.append("\n📋 General Security Recommendations:")
        recommendations.append(
            "   • Use a mapping/alias system instead of direct file inclusion."
        )
        recommendations.append("   • Implement Content Security Policy (CSP) headers.")
        recommendations.append("   • Enable PHP open_basedir to restrict file access.")
        recommendations.append("   • Log all file access attempts for monitoring.")
        recommendations.append(
            "   • Apply the principle of least privilege to file permissions."
        )

        return recommendations


def main():
    """Test the analyzer with sample data"""
    from lfi_scanner import LFIFinding, ToolResult

    # Sample findings
    findings = [
        LFIFinding(
            parameter="file",
            payload="../../../etc/passwd",
            url="http://example.com/page.php?file=../../../etc/passwd",
            evidence="root:x:0:0:root:/root:/bin/bash",
            severity="High",
            confidence="High",
            tool="custom_lfi",
            response_indicators=["linux_file:root:x:"],
        ),
    ]

    tool_results = [
        ToolResult(
            tool="custom_lfi",
            success=True,
            findings=findings,
            execution_time=5.2,
            parameters_tested=1,
            payloads_tested=20,
        )
    ]

    analyzer = LFIAnalyzer()
    results = analyzer.analyze(
        "http://example.com/page.php?file=test", findings, tool_results
    )

    import json

    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
