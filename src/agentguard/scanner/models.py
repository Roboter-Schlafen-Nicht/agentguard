"""Data models for the MCP server package scanner."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class RiskCategory(enum.Enum):
    """Categories of security risk detected by the scanner."""

    DATA_EXFILTRATION = "data-exfiltration"
    FILE_SYSTEM_ACCESS = "file-system-access"
    CODE_EXECUTION = "code-execution"
    CREDENTIAL_ACCESS = "credential-access"
    PERSISTENCE = "persistence"
    OBFUSCATION = "obfuscation"


class Severity(enum.Enum):
    """Severity of a scanner finding."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass(frozen=True)
class Finding:
    """A single security finding from a package scan.

    Attributes:
        rule_id: Unique identifier for the detection rule.
        category: Risk category.
        severity: Finding severity.
        message: Human-readable description of the finding.
        file_path: Relative path to the file within the package.
        line_number: 1-based line number of the match (0 if unknown).
        matched_text: The text fragment that triggered the rule.
    """

    rule_id: str
    category: RiskCategory
    severity: Severity
    message: str
    file_path: str
    line_number: int = 0
    matched_text: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a plain dictionary."""
        return {
            "rule_id": self.rule_id,
            "category": self.category.value,
            "severity": self.severity.value,
            "message": self.message,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "matched_text": self.matched_text,
        }


@dataclass
class ScanResult:
    """Aggregated result of a package scan.

    Attributes:
        package_path: The path that was scanned.
        files_scanned: Number of files examined.
        findings: List of security findings.
    """

    package_path: str
    files_scanned: int = 0
    findings: list[Finding] = field(default_factory=list)

    @property
    def finding_count(self) -> int:
        """Total number of findings."""
        return len(self.findings)

    @property
    def has_critical(self) -> bool:
        """Whether any critical-severity finding exists."""
        return any(f.severity is Severity.CRITICAL for f in self.findings)

    @property
    def has_high(self) -> bool:
        """Whether any high-severity (or above) finding exists."""
        return any(
            f.severity in (Severity.CRITICAL, Severity.HIGH) for f in self.findings
        )

    @property
    def max_severity(self) -> Severity | None:
        """Return the highest severity among findings, or None if clean."""
        if not self.findings:
            return None
        order = {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }
        return max(self.findings, key=lambda f: order[f.severity]).severity

    def by_category(self) -> dict[RiskCategory, list[Finding]]:
        """Group findings by risk category."""
        result: dict[RiskCategory, list[Finding]] = {}
        for finding in self.findings:
            result.setdefault(finding.category, []).append(finding)
        return result

    def by_severity(self) -> dict[Severity, list[Finding]]:
        """Group findings by severity."""
        result: dict[Severity, list[Finding]] = {}
        for finding in self.findings:
            result.setdefault(finding.severity, []).append(finding)
        return result

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a plain dictionary."""
        return {
            "package_path": self.package_path,
            "files_scanned": self.files_scanned,
            "finding_count": self.finding_count,
            "max_severity": self.max_severity.value if self.max_severity else None,
            "findings": [f.to_dict() for f in self.findings],
        }
