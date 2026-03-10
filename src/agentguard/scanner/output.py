"""Output formatters for scanner results.

Provides plain-text and JSON output for :class:`ScanResult`.
"""

from __future__ import annotations

import json

from agentguard.scanner.models import ScanResult, Severity

# Severity → ANSI colour codes for terminal output.
_SEVERITY_COLOURS: dict[Severity, str] = {
    Severity.CRITICAL: "\033[91m",  # bright red
    Severity.HIGH: "\033[31m",  # red
    Severity.MEDIUM: "\033[33m",  # yellow
    Severity.LOW: "\033[36m",  # cyan
    Severity.INFO: "\033[37m",  # white / grey
}
_RESET = "\033[0m"


def format_text(result: ScanResult, *, colour: bool = False) -> str:
    """Format a scan result as human-readable text.

    Args:
        result: The scan result to format.
        colour: If ``True``, include ANSI colour codes.

    Returns:
        Multi-line string ready for terminal display.
    """
    lines: list[str] = []
    lines.append(f"Scan: {result.package_path}")
    lines.append(f"Files scanned: {result.files_scanned}")
    lines.append(f"Findings: {result.finding_count}")

    if result.max_severity:
        sev_label = result.max_severity.value.upper()
        if colour:
            c = _SEVERITY_COLOURS.get(result.max_severity, "")
            sev_label = f"{c}{sev_label}{_RESET}"
        lines.append(f"Max severity: {sev_label}")

    if not result.findings:
        lines.append("")
        lines.append("No issues found.")
        return "\n".join(lines)

    lines.append("")

    for finding in result.findings:
        sev = finding.severity.value.upper()
        if colour:
            c = _SEVERITY_COLOURS.get(finding.severity, "")
            sev = f"{c}{sev}{_RESET}"

        loc = finding.file_path
        if finding.line_number:
            loc = f"{loc}:{finding.line_number}"

        lines.append(f"  [{sev}] {finding.rule_id}")
        lines.append(f"    {finding.message}")
        lines.append(f"    at {loc}")
        if finding.matched_text:
            # Truncate very long matches for readability.
            text = finding.matched_text
            if len(text) > 80:
                text = text[:77] + "..."
            lines.append(f"    matched: {text}")
        lines.append("")

    return "\n".join(lines)


def format_json(result: ScanResult, *, indent: int | None = 2) -> str:
    """Format a scan result as a JSON string.

    Args:
        result: The scan result to format.
        indent: JSON indentation (``None`` for compact).

    Returns:
        JSON string.
    """
    return json.dumps(result.to_dict(), indent=indent)


def format_summary(result: ScanResult) -> str:
    """One-line summary of a scan result.

    Returns:
        A single line like ``"3 findings (max: HIGH) in 12 files"``.
    """
    if not result.findings:
        return f"Clean — 0 findings in {result.files_scanned} files"

    sev = result.max_severity
    sev_label = sev.value.upper() if sev else "UNKNOWN"
    return (
        f"{result.finding_count} findings "
        f"(max: {sev_label}) in {result.files_scanned} files"
    )
