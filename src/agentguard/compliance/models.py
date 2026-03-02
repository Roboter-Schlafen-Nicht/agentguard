"""Compliance reporting data models.

Provides the core data structures for compliance reports:
- FindingSeverity: risk level of a compliance finding
- Finding: a single compliance observation
- SectionStatus: pass/warn/fail status for a report section
- ReportSection: one section of a compliance report (e.g. one article)
- ComplianceReport: the full structured compliance report
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from datetime import datetime


class FindingSeverity(enum.Enum):
    """Severity of a compliance finding.

    Ordered: INFO < WARNING < VIOLATION.
    """

    INFO = "info"
    WARNING = "warning"
    VIOLATION = "violation"

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, FindingSeverity):
            return NotImplemented
        order = list(FindingSeverity)
        return order.index(self) < order.index(other)

    def __le__(self, other: object) -> bool:
        if not isinstance(other, FindingSeverity):
            return NotImplemented
        return self == other or self.__lt__(other)

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, FindingSeverity):
            return NotImplemented
        order = list(FindingSeverity)
        return order.index(self) > order.index(other)

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, FindingSeverity):
            return NotImplemented
        return self == other or self.__gt__(other)


class SectionStatus(enum.Enum):
    """Status of a compliance report section.

    Values:
        PASS: All checks passed.
        WARN: Some warnings but no violations.
        FAIL: At least one violation found.
        NOT_ASSESSED: Section was not evaluated.
    """

    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"
    NOT_ASSESSED = "not_assessed"


@dataclass(frozen=True)
class Finding:
    """A single compliance finding.

    Represents one observation from analyzing an audit log against
    a regulatory framework.

    Attributes:
        severity: How severe this finding is.
        article: The regulatory article reference (e.g. "Art. 12").
        description: Human-readable description of the finding.
        evidence: Optional supporting evidence from the audit data.
    """

    severity: FindingSeverity
    article: str
    description: str
    evidence: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a dictionary.

        Returns:
            Dictionary representation. Evidence is omitted if None.
        """
        d: dict[str, Any] = {
            "severity": self.severity.value,
            "article": self.article,
            "description": self.description,
        }
        if self.evidence is not None:
            d["evidence"] = self.evidence
        return d


@dataclass(frozen=True)
class ReportSection:
    """A section of a compliance report.

    Each section covers one regulatory article or requirement area.

    Attributes:
        article: The article reference (e.g. "Art. 12").
        title: Human-readable title (e.g. "Logging").
        status: Overall status of this section.
        findings: List of findings for this section.
    """

    article: str
    title: str
    status: SectionStatus
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a dictionary.

        Returns:
            Dictionary representation with serialized findings.
        """
        return {
            "article": self.article,
            "title": self.title,
            "status": self.status.value,
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class ComplianceReport:
    """A complete compliance report.

    Contains sections for each assessed regulatory requirement,
    summary statistics, and metadata.

    Attributes:
        framework: The regulatory framework (e.g. "EU AI Act").
        generated_at: When the report was generated (UTC).
        session_id: The audit session this report covers.
        sections: List of report sections.
    """

    framework: str
    generated_at: datetime
    session_id: str
    sections: list[ReportSection] = field(default_factory=list)

    def summary(self) -> dict[str, int]:
        """Compute summary statistics for this report.

        Returns:
            Dictionary with counts of statuses and finding severities.
        """
        status_counts = {s.value: 0 for s in SectionStatus}
        finding_counts = {s.value: 0 for s in FindingSeverity}

        for section in self.sections:
            status_counts[section.status.value] += 1
            for finding in section.findings:
                finding_counts[finding.severity.value] += 1

        total_findings = sum(finding_counts.values())

        return {
            "total_sections": len(self.sections),
            "pass": status_counts["pass"],
            "warn": status_counts["warn"],
            "fail": status_counts["fail"],
            "not_assessed": status_counts["not_assessed"],
            "total_findings": total_findings,
            "violations": finding_counts["violation"],
            "warnings": finding_counts["warning"],
            "infos": finding_counts["info"],
        }

    def overall_status(self) -> SectionStatus:
        """Determine the overall report status.

        Returns FAIL if any section failed, WARN if any section warned
        (but none failed), PASS if all sections passed, or NOT_ASSESSED
        if there are no sections.

        Returns:
            The overall SectionStatus.
        """
        if not self.sections:
            return SectionStatus.NOT_ASSESSED

        statuses = {s.status for s in self.sections}

        if SectionStatus.FAIL in statuses:
            return SectionStatus.FAIL
        if SectionStatus.WARN in statuses:
            return SectionStatus.WARN
        return SectionStatus.PASS

    def to_dict(self) -> dict[str, Any]:
        """Serialize the full report to a dictionary.

        Returns:
            Dictionary representation suitable for JSON output.
        """
        return {
            "framework": self.framework,
            "generated_at": self.generated_at.isoformat(),
            "session_id": self.session_id,
            "overall_status": self.overall_status().value,
            "summary": self.summary(),
            "sections": [s.to_dict() for s in self.sections],
        }
