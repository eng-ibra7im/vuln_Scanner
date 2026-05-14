import html
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Dict, List


def _severity_badge(value: str) -> str:
    return value.title() if value else "Info"


def _markdown_bullets(items: List[str]) -> List[str]:
    return [f"- {item}" for item in items if item]


def _group_findings_by_severity(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    grouped = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for finding in findings:
        sev = (finding.get("severity") or "info").title()
        grouped[sev] = grouped.get(sev, 0) + 1
    return grouped


class ReportTemplateEngine:
    TEMPLATE_LABELS = {
        "bug_bounty": "Bug Bounty Submission",
        "internal_review": "Internal Security Review",
        "technical_deep_dive": "Technical Deep-Dive",
    }

    SUPPORTED_FORMATS = ("markdown", "html", "pdf")

    def render_markdown(self, template_name: str, analysis: Dict[str, Any]) -> str:
        renderers = {
            "bug_bounty": self._render_bug_bounty_markdown,
            "internal_review": self._render_internal_review_markdown,
            "technical_deep_dive": self._render_deep_dive_markdown,
        }
        renderer = renderers[template_name]
        return renderer(analysis)

    def render_html(self, template_name: str, analysis: Dict[str, Any]) -> str:
        markdown = self.render_markdown(template_name, analysis)
        paragraphs = []
        for block in markdown.split("\n\n"):
            lines = block.splitlines()
            if not lines:
                continue
            if lines[0].startswith("# "):
                paragraphs.append(f"<h1>{html.escape(lines[0][2:])}</h1>")
                if len(lines) > 1:
                    paragraphs.append("<p>" + "<br>".join(html.escape(line) for line in lines[1:]) + "</p>")
            elif lines[0].startswith("## "):
                paragraphs.append(f"<h2>{html.escape(lines[0][3:])}</h2>")
                body = []
                list_items = []
                for line in lines[1:]:
                    if line.startswith("- "):
                        list_items.append(f"<li>{html.escape(line[2:])}</li>")
                    elif line.startswith("|"):
                        body.append(f"<pre>{html.escape(line)}</pre>")
                    elif line:
                        body.append(html.escape(line))
                if body:
                    paragraphs.append("<p>" + "<br>".join(body) + "</p>")
                if list_items:
                    paragraphs.append("<ul>" + "".join(list_items) + "</ul>")
            else:
                paragraphs.append("<p>" + "<br>".join(html.escape(line) for line in lines) + "</p>")

        title = html.escape(self.TEMPLATE_LABELS[template_name])
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{title}</title>
  <style>
    body {{ font-family: Segoe UI, Arial, sans-serif; margin: 0; background: #f4f6f8; color: #1f2933; }}
    main {{ max-width: 1100px; margin: 0 auto; padding: 32px; }}
    h1 {{ margin-bottom: 8px; }}
    h2 {{ margin-top: 28px; color: #0f4c81; border-bottom: 2px solid #d9e2ec; padding-bottom: 8px; }}
    p, li {{ line-height: 1.6; }}
    pre {{ background: #111827; color: #e5e7eb; padding: 12px; border-radius: 8px; overflow: auto; }}
    .banner {{ background: linear-gradient(135deg, #0f4c81, #146c94); color: white; padding: 28px 32px; border-radius: 16px; }}
    .muted {{ color: #52606d; }}
  </style>
</head>
<body>
  <main>
    <div class="banner">
      <h1>{title}</h1>
      <div class="muted">Generated {html.escape(datetime.now(UTC).isoformat())}</div>
    </div>
    {''.join(paragraphs)}
  </main>
</body>
</html>"""

    def export_report(
        self,
        template_name: str,
        analysis: Dict[str, Any],
        output_format: str,
        output_path: Path,
    ) -> Path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        if output_format == "markdown":
            output_path.write_text(
                self.render_markdown(template_name, analysis),
                encoding="utf-8",
            )
        elif output_format == "html":
            output_path.write_text(
                self.render_html(template_name, analysis),
                encoding="utf-8",
            )
        elif output_format == "pdf":
            self._write_simple_pdf(
                self.render_markdown(template_name, analysis),
                output_path,
            )
        else:
            raise ValueError(f"Unsupported format: {output_format}")

        return output_path

    def _render_bug_bounty_markdown(self, analysis: Dict[str, Any]) -> str:
        executive = analysis.get("executive_summary", {})
        findings = analysis.get("findings", [])
        actionable = [f for f in findings if f.get("module") in {"xss", "sqli", "lfi"}]
        primary = actionable[0] if actionable else (findings[0] if findings else {})

        lines = [
            "# Bug Bounty Submission",
            f"Generated: {datetime.now(UTC).isoformat()}",
            "",
            "## Scope",
            f"- Modules analyzed: {', '.join(analysis.get('modules_present', [])) or 'N/A'}",
            f"- Target host: {primary.get('host') or 'N/A'}",
            f"- Asset chain: {' -> '.join(primary.get('asset_chain', [])) or 'N/A'}",
            "",
            "## Summary",
            f"- Headline: {executive.get('headline', 'N/A')}",
            f"- Total findings: {executive.get('total_findings', 0)}",
            f"- Risk posture: {executive.get('risk_posture', 'unknown')}",
            "",
            "## Vulnerability",
            f"- Title: {primary.get('title', 'No direct vulnerability selected')}",
            f"- Severity: {_severity_badge(primary.get('severity', 'info'))}",
            f"- Parameter: {primary.get('parameter') or 'N/A'}",
            f"- URL: {primary.get('path_url') or primary.get('host') or 'N/A'}",
            "",
            "## Steps To Reproduce",
            "- 1. Navigate to the affected target listed above.",
            "- 2. Exercise the identified parameter or route using a harmless validation payload.",
            "- 3. Observe the evidence collected by the scanner and confirm server-side behavior manually.",
            "",
            "## Impact",
            f"- {primary.get('title', 'The identified issue')} may allow attacker-controlled input to reach a sensitive execution path.",
            f"- Evidence: {primary.get('evidence', 'No inline evidence captured.')[:400]}",
            "",
            "## Remediation",
            f"- {primary.get('remediation', 'Review and harden the affected input handling and access control path.')}",
        ]
        return "\n".join(lines)

    def _render_internal_review_markdown(self, analysis: Dict[str, Any]) -> str:
        executive = analysis.get("executive_summary", {})
        findings = analysis.get("findings", [])
        grouped = _group_findings_by_severity(findings)
        next_actions = analysis.get("correlations", {}).get("next_actions", [])
        recommendations = analysis.get("recommendations", [])

        lines = [
            "# Internal Security Review",
            f"Generated: {datetime.now(UTC).isoformat()}",
            "",
            "## Executive Summary",
            f"- {executive.get('headline', 'N/A')}",
            f"- Modules analyzed: {', '.join(executive.get('modules_analyzed', [])) or 'N/A'}",
            f"- Total assets: {executive.get('total_assets', 0)}",
            f"- Total findings: {executive.get('total_findings', 0)}",
            "",
            "## Findings By Severity",
            *[f"- {severity}: {count}" for severity, count in grouped.items()],
            "",
            "## Asset Map",
            *[
                f"- {asset.get('type')}: {asset.get('name')} ({_severity_badge(asset.get('severity', 'info'))})"
                for asset in analysis.get("assets", [])[:20]
            ],
            "",
            "## Trends And Correlations",
            *[
                f"- {action['scan_type']} -> {action['target']} because {action['reason']}"
                for action in next_actions[:10]
            ],
            "",
            "## Recommendations",
            *[
                f"- [{rec['priority']}] {rec['title']} | Owner: {rec['owner']} | Action: {rec['action']}"
                for rec in recommendations
            ],
        ]
        return "\n".join(lines)

    def _render_deep_dive_markdown(self, analysis: Dict[str, Any]) -> str:
        findings = analysis.get("findings", [])
        lineage = analysis.get("lineage", [])
        recommendations = analysis.get("recommendations", [])

        lines = [
            "# Technical Deep-Dive",
            f"Generated: {datetime.now(UTC).isoformat()}",
            "",
            "## Executive Summary",
            f"- {analysis.get('executive_summary', {}).get('headline', 'N/A')}",
            "",
            "## Lineage",
        ]
        lines.extend(
            _markdown_bullets(
                [
                    f"{entry.get('subdomain') or 'n/a'} -> {entry.get('path') or '/'} -> {entry.get('parameter') or 'n/a'} -> {entry.get('title')}"
                    for entry in lineage[:25]
                ]
            )
        )
        lines.extend(
            [
                "",
                "## Findings",
            ]
        )
        lines.extend(
            _markdown_bullets(
                [
                    f"[{_severity_badge(finding.get('severity', 'info'))}] {finding.get('module')} | {finding.get('title')} | {finding.get('path_url') or finding.get('host')}"
                    for finding in findings[:40]
                ]
            )
        )
        lines.extend(
            [
                "",
                "## Recommendations",
            ]
        )
        lines.extend(
            _markdown_bullets(
                [
                    f"{rec['title']} | Owner: {rec['owner']} | Why: {rec['why']}"
                    for rec in recommendations
                ]
            )
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
