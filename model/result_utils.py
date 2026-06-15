import csv
import html
import json
from copy import deepcopy
from datetime import UTC, datetime
from io import StringIO
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple
from urllib.parse import urlparse


SEVERITY_ORDER = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}


def normalize_result_schema(
    module_name: str,
    result: Dict[str, Any],
    *,
    profile_name: str = "standard",
    job_context: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    if not isinstance(result, dict):
        result = {"success": False, "error": "Invalid result payload"}

    normalized = deepcopy(result)
    if module_name == "subdomains":
        _normalize_subdomain_result(normalized, profile_name, job_context)
    elif module_name == "paths":
        _normalize_path_result(normalized, profile_name, job_context)
    elif module_name == "xss":
        _normalize_xss_result(normalized, profile_name, job_context)
    elif module_name == "sqli":
        _normalize_sqli_result(normalized, profile_name, job_context)
    elif module_name == "lfi":
        _normalize_lfi_result(normalized, profile_name, job_context)
    else:
        _ensure_common_sections(normalized)

    normalized.setdefault(
        "recommendation_summary",
        build_module_recommendation_summary(module_name, normalized),
    )
    normalized.setdefault(
        "schema",
        {
            "version": "2.0",
            "required_sections": ["scan_info", "summary", "tool_results", "findings"],
        },
    )
    return normalized


def build_result_comparison(
    current_result: Dict[str, Any],
    previous_result: Dict[str, Any] | None,
    *,
    baseline_job_id: str | None = None,
) -> Dict[str, Any]:
    current_findings = {
        _finding_key(finding): finding
        for finding in current_result.get("findings", [])
    }
    previous_findings = {
        _finding_key(finding): finding
        for finding in (previous_result or {}).get("findings", [])
    }

    new_items = []
    removed_items = []
    changed_items = []

    for key, current_item in current_findings.items():
        previous_item = previous_findings.get(key)
        if previous_item is None:
            new_items.append(current_item)
            continue

        changed_fields = _changed_fields(previous_item, current_item)
        if changed_fields:
            changed_items.append(
                {
                    "key": key,
                    "fields": changed_fields,
                    "before": previous_item,
                    "after": current_item,
                }
            )

    for key, previous_item in previous_findings.items():
        if key not in current_findings:
            removed_items.append(previous_item)

    return {
        "baseline_job_id": baseline_job_id,
        "baseline_scan_time": ((previous_result or {}).get("scan_info") or {}).get(
            "scan_time"
        ),
        "summary": {
            "new": len(new_items),
            "removed": len(removed_items),
            "changed": len(changed_items),
        },
        "new": new_items,
        "removed": removed_items,
        "changed": changed_items,
    }


def attach_result_comparison(
    current_result: Dict[str, Any],
    previous_result: Dict[str, Any] | None,
    *,
    baseline_job_id: str | None = None,
) -> Dict[str, Any]:
    current_result["comparison"] = build_result_comparison(
        current_result,
        previous_result,
        baseline_job_id=baseline_job_id,
    )
    return current_result


def build_module_recommendation_summary(
    module_name: str,
    normalized_result: Dict[str, Any],
) -> Dict[str, Any]:
    findings = normalized_result.get("findings", [])
    summary = normalized_result.get("summary", {})
    severity = summary.get("severity", {})
    target = normalized_result.get("scan_info", {}).get("target", "unknown target")

    highest = _highest_severity(findings)
    actions = []

    if highest in {"critical", "high"}:
        actions.append(
            {
                "priority": highest,
                "title": "Investigate highest-severity findings first",
                "action": f"Review the top {module_name} findings for {target} and confirm remediation ownership.",
            }
        )

    if module_name == "subdomains" and summary.get("total_findings", 0):
        actions.append(
            {
                "priority": "medium",
                "title": "Review exposed subdomains",
                "action": "Confirm that discovered internet-facing subdomains are expected and properly controlled.",
            }
        )
    elif module_name == "paths" and summary.get("total_findings", 0):
        actions.append(
            {
                "priority": "medium",
                "title": "Inspect sensitive routes and parameters",
                "action": "Validate access control on administrative paths and sanitize high-risk parameters.",
            }
        )
    elif module_name in {"xss", "sqli", "lfi"} and summary.get("total_findings", 0):
        actions.append(
            {
                "priority": highest,
                "title": "Validate and triage application findings",
                "action": "Confirm the affected parameter, verify exploitability safely, and prioritize code fixes.",
            }
        )

    if not actions:
        actions.append(
            {
                "priority": "info",
                "title": "No direct findings detected",
                "action": "Keep the target in periodic rescan coverage and review tool availability for deeper coverage.",
            }
        )

    return {
        "module": module_name,
        "headline": _module_headline(module_name, normalized_result),
        "risk_posture": highest,
        "totals": {
            "findings": summary.get("total_findings", 0),
            "critical": severity.get("critical", 0),
            "high": severity.get("high", 0),
            "medium": severity.get("medium", 0),
            "low": severity.get("low", 0),
            "info": severity.get("info", 0),
        },
        "actions": actions,
    }


def build_unified_recommendation_summary(
    results_by_module: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    normalized_results = []
    all_findings = []
    module_summaries = {}

    for module_name, result in results_by_module.items():
        normalized = normalize_result_schema(module_name, result)
        normalized_results.append(normalized)
        module_summaries[module_name] = normalized.get("recommendation_summary", {})
        all_findings.extend(normalized.get("findings", []))

    severity_counts = _severity_counts(all_findings)
    top_findings = sorted(
        all_findings,
        key=lambda finding: (
            -SEVERITY_ORDER.get(str(finding.get("severity", "info")).lower(), 0),
            str(finding.get("title", "")),
        ),
    )[:20]

    actions = []
    for module_name, module_summary in module_summaries.items():
        for action in module_summary.get("actions", [])[:2]:
            actions.append({"module": module_name, **action})

    highest = _highest_severity(all_findings)
    headline = (
        f"{len(all_findings)} consolidated findings across {len(module_summaries)} module(s)"
    )
    if highest in {"critical", "high"}:
        headline = (
            f"{len(all_findings)} consolidated findings with {highest} risk requiring immediate attention"
        )

    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "modules": sorted(module_summaries.keys()),
        "headline": headline,
        "risk_posture": highest,
        "summary": {
            "total_findings": len(all_findings),
            "severity": severity_counts,
            "modules": {
                module_name: {
                    "headline": summary.get("headline"),
                    "risk_posture": summary.get("risk_posture"),
                    "findings": summary.get("totals", {}).get("findings", 0),
                }
                for module_name, summary in module_summaries.items()
            },
        },
        "recommendations": actions,
        "top_findings": top_findings,
    }


class UnifiedExportService:
    SUPPORTED_FORMATS = ("json", "csv", "markdown", "pdf")

    def export_scan_result(
        self,
        payload: Dict[str, Any],
        output_format: str,
        output_path: Path,
    ) -> Path:
        if output_format not in self.SUPPORTED_FORMATS:
            raise ValueError(f"Unsupported format: {output_format}")

        output_path.parent.mkdir(parents=True, exist_ok=True)

        if output_format == "json":
            output_path.write_text(
                json.dumps(payload, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        elif output_format == "csv":
            output_path.write_text(self._render_csv(payload), encoding="utf-8")
        elif output_format == "markdown":
            output_path.write_text(self._render_markdown(payload), encoding="utf-8")
        elif output_format == "pdf":
            self._write_simple_pdf(self._render_markdown(payload), output_path)

        return output_path

    def _render_csv(self, payload: Dict[str, Any]) -> str:
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(
            [
                "module",
                "title",
                "severity",
                "locator",
                "parameter",
                "tool",
                "evidence",
            ]
        )

        for finding in payload.get("findings", []):
            writer.writerow(
                [
                    finding.get("module", ""),
                    finding.get("title", ""),
                    finding.get("severity", ""),
                    finding.get("locator", ""),
                    finding.get("parameter", ""),
                    finding.get("tool", ""),
                    str(finding.get("evidence", ""))[:500],
                ]
            )

        return output.getvalue()

    def _render_markdown(self, payload: Dict[str, Any]) -> str:
        scan_info = payload.get("scan_info", {})
        summary = payload.get("summary", {})
        recommendation_summary = payload.get("recommendation_summary", {})

        lines = [
            f"# {scan_info.get('module', 'scan').title()} Scan Report",
            f"Target: {scan_info.get('target', 'N/A')}",
            f"Profile: {scan_info.get('profile', 'standard')}",
            f"Generated: {scan_info.get('scan_time', datetime.now(UTC).isoformat())}",
            "",
            "## Summary",
            f"- Total Findings: {summary.get('total_findings', 0)}",
            f"- Critical: {summary.get('severity', {}).get('critical', 0)}",
            f"- High: {summary.get('severity', {}).get('high', 0)}",
            f"- Medium: {summary.get('severity', {}).get('medium', 0)}",
            f"- Low: {summary.get('severity', {}).get('low', 0)}",
            f"- Info: {summary.get('severity', {}).get('info', 0)}",
            "",
            "## Recommendation Summary",
            f"- Headline: {recommendation_summary.get('headline', 'N/A')}",
            f"- Risk Posture: {recommendation_summary.get('risk_posture', 'info')}",
            "",
            "## Findings",
        ]

        findings = payload.get("findings", [])
        if not findings:
            lines.append("- No findings captured.")
        else:
            for finding in findings[:100]:
                lines.extend(
                    [
                        f"- [{str(finding.get('severity', 'info')).title()}] {finding.get('title', 'Untitled finding')}",
                        f"  Locator: {finding.get('locator', 'N/A')}",
                        f"  Parameter: {finding.get('parameter') or 'N/A'}",
                        f"  Tool: {finding.get('tool') or 'N/A'}",
                    ]
                )

        return "\n".join(lines)

    def _write_simple_pdf(self, text: str, output_path: Path) -> None:
        lines = [line[:110] for line in text.splitlines()]
        escaped_lines = [
            line.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
            for line in lines
        ]

        content_lines = ["BT", "/F1 10 Tf", "50 790 Td", "14 TL"]
        first = True
        for line in escaped_lines:
            if first:
                content_lines.append(f"({line}) Tj")
                first = False
            else:
                content_lines.append("T*")
                content_lines.append(f"({line}) Tj")
        content_lines.append("ET")
        content = "\n".join(content_lines).encode("latin-1", errors="replace")

        objects = []

        def add_object(data: bytes) -> int:
            objects.append(data)
            return len(objects)

        add_object(b"<< /Type /Catalog /Pages 2 0 R >>")
        add_object(b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
        add_object(
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>"
        )
        add_object(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
        add_object(
            f"<< /Length {len(content)} >>\nstream\n".encode("latin-1")
            + content
            + b"\nendstream"
        )

        pdf = bytearray(b"%PDF-1.4\n")
        offsets = [0]
        for index, obj in enumerate(objects, start=1):
            offsets.append(len(pdf))
            pdf.extend(f"{index} 0 obj\n".encode("latin-1"))
            pdf.extend(obj)
            pdf.extend(b"\nendobj\n")

        xref_offset = len(pdf)
        pdf.extend(f"xref\n0 {len(objects) + 1}\n".encode("latin-1"))
        pdf.extend(b"0000000000 65535 f \n")
        for offset in offsets[1:]:
            pdf.extend(f"{offset:010d} 00000 n \n".encode("latin-1"))
        pdf.extend(
            f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF".encode(
                "latin-1"
            )
        )

        output_path.write_bytes(pdf)


def _normalize_subdomain_result(
    result: Dict[str, Any],
    profile_name: str,
    job_context: Dict[str, Any] | None,
) -> None:
    metadata = result.get("metadata", {})
    subdomains = result.get("subdomains", [])
    tool_performance = result.get("tool_performance", [])

    findings = []
    for subdomain in subdomains:
        severity = _normalize_severity(subdomain.get("priority"), fallback="low")
        findings.append(
            {
                "id": _build_finding_id(
                    "subdomains", "subdomain", subdomain.get("subdomain", "")
                ),
                "module": "subdomains",
                "kind": "subdomain",
                "title": f"Discovered subdomain: {subdomain.get('subdomain', 'unknown')}",
                "severity": severity,
                "status": subdomain.get("status", "unknown"),
                "locator": subdomain.get("subdomain", ""),
                "asset": subdomain.get("subdomain", ""),
                "parameter": None,
                "tool": None,
                "evidence": ", ".join(subdomain.get("classifications", []))
                or subdomain.get("status", "active"),
                "details": {
                    "priority": subdomain.get("priority"),
                    "priority_score": subdomain.get("priority_score"),
                    "ip_addresses": (
                        (subdomain.get("dns_records") or {}).get("ip_addresses", [])
                    ),
                    "classifications": subdomain.get("classifications", []),
                },
            }
        )

    tool_results = [
        {
            "tool": tool.get("tool_name"),
            "success": tool.get("status") == "success",
            "execution_time": tool.get("execution_time_seconds", 0),
            "items_found": tool.get("subdomains_found", 0),
            "error": tool.get("error"),
            "details": {"status": tool.get("status")},
        }
        for tool in tool_performance
    ]

    scan_info = {
        "module": "subdomains",
        "target": metadata.get("target_domain"),
        "domain": metadata.get("target_domain"),
        "target_type": "domain",
        "profile": profile_name,
        "scan_time": metadata.get("scan_timestamp", datetime.now(UTC).isoformat()),
        "execution_time": metadata.get("execution_time_seconds", 0),
        "tools_used": [tool.get("tool") for tool in tool_results if tool.get("tool")],
        "status": "completed" if result.get("success", True) else "failed",
    }
    if job_context:
        scan_info.update(job_context)

    summary = result.get("summary", {})
    result["scan_info"] = scan_info
    result["summary"] = {
        "total_findings": len(findings),
        "severity": _severity_counts(findings),
        "assets": {"subdomains": len(subdomains)},
        "tools": {
            "executed": len(tool_results),
            "successful": sum(1 for tool in tool_results if tool.get("success")),
        },
        "comparison": ((result.get("comparison") or {}).get("summary") or {}),
        "module_metrics": summary,
    }
    result["tool_results"] = tool_results
    result["findings"] = findings


def _normalize_path_result(
    result: Dict[str, Any],
    profile_name: str,
    job_context: Dict[str, Any] | None,
) -> None:
    tool_entries = result.get("tools_executed", [])
    paths = result.get("discovered_paths", [])
    parameters = result.get("discovered_parameters", [])

    findings = []
    for path_entry in paths:
        severity = _normalize_severity(path_entry.get("risk_level"), fallback="info")
        findings.append(
            {
                "id": _build_finding_id("paths", "path", path_entry.get("url", "")),
                "module": "paths",
                "kind": "path",
                "title": f"Discovered {path_entry.get('category', 'path')} route {path_entry.get('path', '/')}",
                "severity": severity,
                "status": str(path_entry.get("status_code", "")),
                "locator": path_entry.get("url", ""),
                "asset": path_entry.get("path", ""),
                "parameter": None,
                "tool": path_entry.get("discovery_tool"),
                "evidence": "; ".join(path_entry.get("notes", [])),
                "details": path_entry,
            }
        )

    for parameter in parameters:
        severity = "medium" if parameter.get("potential_vuln") else "info"
        findings.append(
            {
                "id": _build_finding_id(
                    "paths",
                    "parameter",
                    f"{parameter.get('url', '')}::{parameter.get('parameter', '')}",
                ),
                "module": "paths",
                "kind": "parameter",
                "title": f"Discovered parameter {parameter.get('parameter', 'unknown')}",
                "severity": severity,
                "status": parameter.get("method", "GET"),
                "locator": parameter.get("url", ""),
                "asset": parameter.get("parameter", ""),
                "parameter": parameter.get("parameter"),
                "tool": parameter.get("discovery_tool"),
                "evidence": ", ".join(parameter.get("potential_vuln", [])),
                "details": parameter,
            }
        )

    tool_results = [
        {
            "tool": tool.get("tool"),
            "success": tool.get("success", False),
            "execution_time": tool.get("execution_time", 0),
            "items_found": tool.get("paths_found", 0) + tool.get("params_found", 0),
            "error": tool.get("error"),
            "details": {
                "paths_found": tool.get("paths_found", 0),
                "params_found": tool.get("params_found", 0),
            },
        }
        for tool in tool_entries
    ]

    scan_info = {
        "module": "paths",
        "target": result.get("target"),
        "domain": result.get("domain"),
        "target_type": "url",
        "profile": profile_name,
        "scan_time": result.get("scan_timestamp", datetime.now(UTC).isoformat()),
        "execution_time": result.get("execution_time", 0),
        "tools_used": [tool.get("tool") for tool in tool_results if tool.get("tool")],
        "status": "completed" if result.get("success", True) else "failed",
    }
    if job_context:
        scan_info.update(job_context)

    existing_summary = result.get("summary", {})
    result["scan_info"] = scan_info
    result["summary"] = {
        "total_findings": len(findings),
        "severity": _severity_counts(findings),
        "assets": {
            "paths": len(paths),
            "parameters": len(parameters),
        },
        "tools": {
            "executed": len(tool_results),
            "successful": sum(1 for tool in tool_results if tool.get("success")),
        },
        "comparison": ((result.get("comparison") or {}).get("summary") or {}),
        "module_metrics": existing_summary,
    }
    result["tool_results"] = tool_results
    result["findings"] = findings


def _normalize_xss_result(
    result: Dict[str, Any],
    profile_name: str,
    job_context: Dict[str, Any] | None,
) -> None:
    _ensure_common_sections(result)
    scan_info = result.get("scan_info", {})
    target = scan_info.get("target") or result.get("target_url") or result.get("target")
    result["scan_info"] = {
        "module": "xss",
        "target": target,
        "domain": scan_info.get("domain") or urlparse(target or "").netloc,
        "target_type": "url",
        "profile": profile_name,
        "scan_time": scan_info.get("scan_time", datetime.now(UTC).isoformat()),
        "execution_time": scan_info.get(
            "total_execution_time",
            scan_info.get("execution_time", result.get("execution_time", 0)),
        ),
        "tools_used": scan_info.get("tools_used", []),
        "status": scan_info.get(
            "status",
            "completed" if not result.get("error") else "failed",
        ),
        **(job_context or {}),
    }

    findings = []
    for finding in result.get("findings", []):
        details = finding.get("details", {})
        source = details if isinstance(details, dict) and details else finding

        finding_url = (
            finding.get("url")
            or source.get("url")
            or finding.get("locator")
            or finding.get("asset")
            or ""
        )
        parameter = finding.get("parameter") or source.get("parameter")
        vulnerability_type = (
            finding.get("xss_type")
            or source.get("xss_type")
            or finding.get("vulnerability_type")
            or source.get("vulnerability_type")
            or finding.get("kind")
            or "xss"
        )
        confidence = (
            finding.get("confidence")
            or source.get("confidence")
            or finding.get("status")
            or "medium"
        )
        tool = (
            finding.get("tool")
            or source.get("tool")
            or finding.get("detection_tool")
            or source.get("detection_tool")
        )
        severity = _normalize_severity(
            finding.get("severity") or source.get("severity"),
            fallback="medium",
        )
        normalized_details = dict(source)
        normalized_details.setdefault("url", finding_url)
        normalized_details.setdefault("parameter", parameter)
        normalized_details.setdefault("xss_type", vulnerability_type)
        normalized_details.setdefault("vulnerability_type", vulnerability_type)
        normalized_details.setdefault("confidence", confidence)
        normalized_details.setdefault("tool", tool)
        normalized_details.setdefault(
            "detection_tool",
            source.get("detection_tool") or tool,
        )

        findings.append(
            {
                "id": _build_finding_id(
                    "xss",
                    vulnerability_type,
                    f"{finding_url}::{parameter or ''}",
                ),
                "module": "xss",
                "kind": vulnerability_type,
                "title": f"XSS in parameter {parameter or 'unknown'}",
                "severity": severity,
                "status": confidence,
                "locator": finding_url,
                "asset": finding_url,
                "url": finding_url,
                "parameter": parameter,
                "xss_type": vulnerability_type,
                "vulnerability_type": vulnerability_type,
                "confidence": confidence,
                "tool": tool,
                "detection_tool": source.get("detection_tool") or tool,
                "payload": finding.get("payload") or source.get("payload"),
                "evidence": finding.get("evidence") or source.get("evidence", ""),
                "remediation": finding.get("remediation") or source.get("remediation"),
                "cwe_id": finding.get("cwe_id") or source.get("cwe_id"),
                "cvss_score": finding.get("cvss_score") or source.get("cvss_score"),
                "details": normalized_details,
            }
        )

    tool_entries = result.get("tool_results", {})
    tool_results = _tool_results_from_mapping(tool_entries)
    if not result["scan_info"]["tools_used"]:
        result["scan_info"]["tools_used"] = [
            tool.get("tool") for tool in tool_results if tool.get("tool")
        ]
    result["summary"] = {
        "total_findings": len(findings),
        "severity": _severity_counts(findings),
        "assets": {"urls": len({finding.get("locator") for finding in findings if finding.get("locator")})},
        "tools": {
            "executed": len(tool_results),
            "successful": sum(1 for tool in tool_results if tool.get("success")),
        },
        "comparison": ((result.get("comparison") or {}).get("summary") or {}),
        "module_metrics": result.get("summary", {}),
    }
    result["tool_results"] = tool_results
    result["findings"] = findings


def _normalize_sqli_result(
    result: Dict[str, Any],
    profile_name: str,
    job_context: Dict[str, Any] | None,
) -> None:
    _ensure_common_sections(result)
    scan_info = result.get("scan_info", {})
    result["scan_info"] = {
        "module": "sqli",
        "target": scan_info.get("target"),
        "domain": scan_info.get("domain"),
        "target_type": "url",
        "profile": profile_name,
        "scan_time": scan_info.get("scan_time", datetime.now(UTC).isoformat()),
        "execution_time": scan_info.get("total_execution_time", 0),
        "tools_used": scan_info.get("tools_used", []),
        "status": "completed" if not scan_info.get("error") else "failed",
        **(job_context or {}),
    }

    findings = []
    for finding in result.get("findings", []):
        severity = _normalize_severity(finding.get("severity"), fallback="medium")
        findings.append(
            {
                "id": _build_finding_id(
                    "sqli",
                    finding.get("injection_type", "sqli"),
                    f"{finding.get('url', '')}::{finding.get('parameter', '')}",
                ),
                "module": "sqli",
                "kind": finding.get("injection_type", "sqli"),
                "title": f"SQL injection in parameter {finding.get('parameter', 'unknown')}",
                "severity": severity,
                "status": finding.get("confidence", "medium"),
                "locator": finding.get("url", ""),
                "asset": finding.get("url", ""),
                "parameter": finding.get("parameter"),
                "tool": finding.get("tool") or finding.get("detection_tool"),
                "evidence": finding.get("evidence", ""),
                "details": finding,
            }
        )

    tool_entries = result.get("tool_results", {})
    tool_results = _tool_results_from_mapping(tool_entries)
    result["summary"] = {
        "total_findings": len(findings),
        "severity": _severity_counts(findings),
        "assets": {"urls": len({finding.get("locator") for finding in findings if finding.get("locator")})},
        "tools": {
            "executed": len(tool_results),
            "successful": sum(1 for tool in tool_results if tool.get("success")),
        },
        "comparison": ((result.get("comparison") or {}).get("summary") or {}),
        "module_metrics": result.get("summary", {}),
    }
    result["tool_results"] = tool_results
    result["findings"] = findings


def _normalize_lfi_result(
    result: Dict[str, Any],
    profile_name: str,
    job_context: Dict[str, Any] | None,
) -> None:
    raw_findings = result.get("raw_findings")
    findings_source = raw_findings if isinstance(raw_findings, list) else result.get("findings", [])
    if isinstance(findings_source, dict):
        flattened = []
        for values in findings_source.values():
            if isinstance(values, list):
                flattened.extend(values)
        findings_source = flattened

    findings = []
    for finding in findings_source or []:
        severity = _normalize_severity(finding.get("severity"), fallback="medium")
        findings.append(
            {
                "id": _build_finding_id(
                    "lfi",
                    "lfi",
                    f"{finding.get('url', '')}::{finding.get('parameter', '')}",
                ),
                "module": "lfi",
                "kind": "lfi",
                "title": f"LFI candidate in parameter {finding.get('parameter', 'unknown')}",
                "severity": severity,
                "status": finding.get("confidence", "medium"),
                "locator": finding.get("url", ""),
                "asset": finding.get("url", ""),
                "parameter": finding.get("parameter"),
                "tool": finding.get("tool"),
                "evidence": finding.get("evidence", ""),
                "details": finding,
            }
        )

    tool_entries = result.get("tool_results", [])
    tool_results = []
    for tool in tool_entries:
        tool_results.append(
            {
                "tool": tool.get("tool"),
                "success": tool.get("success", False),
                "execution_time": tool.get("execution_time", 0),
                "items_found": tool.get("findings_count", 0),
                "error": tool.get("error"),
                "details": {},
            }
        )

    result["findings_by_severity"] = result.get("findings") if isinstance(result.get("findings"), dict) else {}
    result["scan_info"] = {
        "module": "lfi",
        "target": result.get("target_url"),
        "domain": urlparse(result.get("target_url", "")).netloc,
        "target_type": "url",
        "profile": profile_name,
        "scan_time": result.get("timestamp", datetime.now(UTC).isoformat()),
        "execution_time": result.get("execution_time", 0),
        "tools_used": [tool.get("tool") for tool in tool_results if tool.get("tool")],
        "status": "completed" if result.get("success", True) else "failed",
        **(job_context or {}),
    }
    result["summary"] = {
        "total_findings": len(findings),
        "severity": _severity_counts(findings),
        "assets": {"urls": len({finding.get("locator") for finding in findings if finding.get("locator")})},
        "tools": {
            "executed": len(tool_results),
            "successful": sum(1 for tool in tool_results if tool.get("success")),
        },
        "comparison": ((result.get("comparison") or {}).get("summary") or {}),
        "module_metrics": result.get("summary", {}),
    }
    result["tool_results"] = tool_results
    result["findings"] = findings


def _ensure_common_sections(result: Dict[str, Any]) -> None:
    result.setdefault("scan_info", {})
    result.setdefault("summary", {})
    result.setdefault("tool_results", [])
    result.setdefault("findings", [])


def _tool_results_from_mapping(tool_entries: Any) -> List[Dict[str, Any]]:
    if isinstance(tool_entries, list):
        return tool_entries

    if not isinstance(tool_entries, dict):
        return []

    normalized = []
    for tool_name, tool_data in tool_entries.items():
        normalized.append(
            {
                "tool": tool_name,
                "success": tool_data.get("success", False),
                "execution_time": tool_data.get("execution_time", 0),
                "items_found": tool_data.get("validated_findings", tool_data.get("findings_count", 0)),
                "error": tool_data.get("error"),
                "details": {
                    key: value
                    for key, value in tool_data.items()
                    if key not in {"success", "execution_time", "findings_count", "validated_findings", "error"}
                },
            }
        )
    return normalized


def _severity_counts(findings: Iterable[Dict[str, Any]]) -> Dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        counts[_normalize_severity(finding.get("severity"), fallback="info")] += 1
    return counts


def _highest_severity(findings: Iterable[Dict[str, Any]]) -> str:
    highest = "info"
    for finding in findings:
        severity = _normalize_severity(finding.get("severity"), fallback="info")
        if SEVERITY_ORDER[severity] > SEVERITY_ORDER[highest]:
            highest = severity
    return highest


def _module_headline(module_name: str, normalized_result: Dict[str, Any]) -> str:
    summary = normalized_result.get("summary", {})
    total_findings = summary.get("total_findings", 0)
    target = normalized_result.get("scan_info", {}).get("target", "target")
    if total_findings == 0:
        return f"No direct {module_name} findings detected for {target}"
    return f"{total_findings} {module_name} finding(s) detected for {target}"


def _normalize_severity(value: Any, *, fallback: str = "info") -> str:
    if value is None:
        return fallback
    normalized = str(value).strip().lower()
    if normalized in SEVERITY_ORDER:
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


def _finding_key(finding: Dict[str, Any]) -> str:
    return finding.get("id") or _build_finding_id(
        finding.get("module", "scan"),
        finding.get("kind", "finding"),
        f"{finding.get('locator', '')}::{finding.get('parameter', '')}",
    )


def _changed_fields(previous_item: Dict[str, Any], current_item: Dict[str, Any]) -> List[str]:
    tracked_fields = ["title", "severity", "status", "tool", "evidence", "details"]
    changed = []
    for field_name in tracked_fields:
        before = previous_item.get(field_name)
        after = current_item.get(field_name)
        if json.dumps(before, sort_keys=True, default=str) != json.dumps(
            after, sort_keys=True, default=str
        ):
            changed.append(field_name)
    return changed


def _slug(value: str) -> str:
    return "".join(ch.lower() if ch.isalnum() else "_" for ch in value).strip("_")


def _build_finding_id(module_name: str, kind: str, locator: str) -> str:
    return f"{module_name}:{kind}:{_slug(locator)}"
