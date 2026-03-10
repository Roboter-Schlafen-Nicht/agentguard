"""MCP server package scanner.

Provides regex-based static analysis of MCP server source code to
detect suspicious patterns across six risk categories: data exfiltration,
file-system access, code execution, credential access, persistence, and
obfuscation.

.. note::

   This scanner is a **safety net** for first-pass triage, not a hard
   security boundary.  Adversarial code can bypass regex-based detection
   via string concatenation, encoding, or indirection.  See the project
   decision log for details.

Example usage::

    from agentguard.scanner import Scanner

    scanner = Scanner()
    result = scanner.scan("/path/to/mcp-server-package")
    print(result.finding_count, result.max_severity)
"""

from __future__ import annotations

from agentguard.scanner.engine import Scanner
from agentguard.scanner.models import Finding, RiskCategory, ScanResult, Severity
from agentguard.scanner.output import format_json, format_summary, format_text
from agentguard.scanner.rules import Rule, builtin_rules

__all__ = [
    "Finding",
    "RiskCategory",
    "Rule",
    "ScanResult",
    "Scanner",
    "Severity",
    "builtin_rules",
    "format_json",
    "format_summary",
    "format_text",
]
