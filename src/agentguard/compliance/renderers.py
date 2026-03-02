"""Compliance report renderers.

Provides functions to render a ComplianceReport to different formats:
- render_json: JSON output (pretty-printed)
- render_text: plain text output (human-readable)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agentguard.compliance.models import ComplianceReport


def render_json(
    report: ComplianceReport,
    output: str | Path | None = None,
) -> str:
    """Render a compliance report as pretty-printed JSON.

    Args:
        report: The compliance report to render.
        output: Optional file path to write the JSON to.

    Returns:
        The JSON string.
    """
    data = report.to_dict()
    json_str = json.dumps(data, indent=2, ensure_ascii=False) + "\n"

    if output is not None:
        Path(output).write_text(json_str, encoding="utf-8")

    return json_str


def render_text(
    report: ComplianceReport,
    output: str | Path | None = None,
) -> str:
    """Render a compliance report as human-readable plain text.

    Args:
        report: The compliance report to render.
        output: Optional file path to write the text to.

    Returns:
        The plain text string.
    """
    lines: list[str] = []
    separator = "=" * 60

    # Title
    lines.append(separator)
    lines.append(f"  {report.framework} Compliance Report")
    lines.append(separator)
    lines.append("")
    lines.append(f"Session:  {report.session_id}")
    lines.append(f"Generated: {report.generated_at.isoformat()}")
    lines.append(f"Overall:   {report.overall_status().name}")
    lines.append("")

    # Sections
    for section in report.sections:
        lines.append("-" * 60)
        lines.append(f"  {section.article}: {section.title}")
        lines.append(f"  Status: {section.status.name}")
        lines.append("-" * 60)

        if section.findings:
            for finding in section.findings:
                severity_label = f"[{finding.severity.value.upper()}]"
                lines.append(f"  {severity_label} {finding.description}")
                if finding.evidence:
                    lines.append(f"         Evidence: {finding.evidence}")
        else:
            lines.append("  No findings.")

        lines.append("")

    # Summary
    summary = report.summary()
    lines.append(separator)
    lines.append("  Summary")
    lines.append(separator)
    lines.append(f"  Sections:   {summary['total_sections']}")
    lines.append(
        f"  Pass: {summary['pass']}  "
        f"Warn: {summary['warn']}  "
        f"Fail: {summary['fail']}  "
        f"N/A: {summary['not_assessed']}"
    )
    lines.append(f"  Findings:   {summary['total_findings']}")
    lines.append(
        f"  Violations: {summary['violations']}  "
        f"Warnings: {summary['warnings']}  "
        f"Info: {summary['infos']}"
    )
    lines.append(separator)

    text = "\n".join(lines) + "\n"

    if output is not None:
        Path(output).write_text(text, encoding="utf-8")

    return text
