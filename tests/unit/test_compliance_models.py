"""Tests for compliance reporting data models (M4.1).

Covers:
- FindingSeverity enum and ordering
- Finding data model
- ReportSection data model
- ComplianceReport data model with summary statistics
"""

from __future__ import annotations

from datetime import datetime, timezone

from agentguard.compliance.models import (
    ComplianceReport,
    Finding,
    FindingSeverity,
    ReportSection,
    SectionStatus,
)


class TestFindingSeverity:
    """FindingSeverity enum."""

    def test_has_info_level(self) -> None:
        assert FindingSeverity.INFO.value == "info"

    def test_has_warning_level(self) -> None:
        assert FindingSeverity.WARNING.value == "warning"

    def test_has_violation_level(self) -> None:
        assert FindingSeverity.VIOLATION.value == "violation"

    def test_ordering_info_lt_warning(self) -> None:
        assert FindingSeverity.INFO < FindingSeverity.WARNING

    def test_ordering_warning_lt_violation(self) -> None:
        assert FindingSeverity.WARNING < FindingSeverity.VIOLATION

    def test_ordering_info_lt_violation(self) -> None:
        assert FindingSeverity.INFO < FindingSeverity.VIOLATION

    def test_ordering_violation_gt_info(self) -> None:
        assert FindingSeverity.VIOLATION > FindingSeverity.INFO

    def test_ordering_not_lt_equal(self) -> None:
        assert not (FindingSeverity.WARNING < FindingSeverity.WARNING)

    def test_ordering_le_equal(self) -> None:
        assert FindingSeverity.WARNING <= FindingSeverity.WARNING

    def test_ordering_ge_equal(self) -> None:
        assert FindingSeverity.WARNING >= FindingSeverity.WARNING

    def test_ordering_returns_not_implemented_for_other_type(self) -> None:
        result = FindingSeverity.INFO.__lt__(42)
        assert result is NotImplemented


class TestSectionStatus:
    """SectionStatus enum."""

    def test_has_pass(self) -> None:
        assert SectionStatus.PASS.value == "pass"

    def test_has_warn(self) -> None:
        assert SectionStatus.WARN.value == "warn"

    def test_has_fail(self) -> None:
        assert SectionStatus.FAIL.value == "fail"

    def test_has_not_assessed(self) -> None:
        assert SectionStatus.NOT_ASSESSED.value == "not_assessed"


class TestFinding:
    """Finding data model."""

    def test_create_finding(self) -> None:
        finding = Finding(
            severity=FindingSeverity.VIOLATION,
            article="Art. 12",
            description="No audit logging detected",
            evidence="0 audit entries recorded",
        )
        assert finding.severity == FindingSeverity.VIOLATION
        assert finding.article == "Art. 12"
        assert finding.description == "No audit logging detected"
        assert finding.evidence == "0 audit entries recorded"

    def test_finding_without_evidence(self) -> None:
        finding = Finding(
            severity=FindingSeverity.INFO,
            article="Art. 13",
            description="Transparency controls present",
        )
        assert finding.evidence is None

    def test_finding_to_dict(self) -> None:
        finding = Finding(
            severity=FindingSeverity.WARNING,
            article="Art. 9",
            description="Some risk patterns detected",
            evidence="3 denied actions in log",
        )
        d = finding.to_dict()
        assert d["severity"] == "warning"
        assert d["article"] == "Art. 9"
        assert d["description"] == "Some risk patterns detected"
        assert d["evidence"] == "3 denied actions in log"

    def test_finding_to_dict_without_evidence(self) -> None:
        finding = Finding(
            severity=FindingSeverity.INFO,
            article="Art. 13",
            description="OK",
        )
        d = finding.to_dict()
        assert "evidence" not in d


class TestReportSection:
    """ReportSection data model."""

    def test_create_section(self) -> None:
        section = ReportSection(
            article="Art. 12",
            title="Logging",
            status=SectionStatus.PASS,
            findings=[],
        )
        assert section.article == "Art. 12"
        assert section.title == "Logging"
        assert section.status == SectionStatus.PASS
        assert section.findings == []

    def test_section_with_findings(self) -> None:
        f1 = Finding(
            severity=FindingSeverity.INFO,
            article="Art. 12",
            description="Logging active",
        )
        f2 = Finding(
            severity=FindingSeverity.WARNING,
            article="Art. 12",
            description="Hash chain not verified",
        )
        section = ReportSection(
            article="Art. 12",
            title="Logging",
            status=SectionStatus.WARN,
            findings=[f1, f2],
        )
        assert len(section.findings) == 2

    def test_section_to_dict(self) -> None:
        finding = Finding(
            severity=FindingSeverity.INFO,
            article="Art. 12",
            description="OK",
        )
        section = ReportSection(
            article="Art. 12",
            title="Logging",
            status=SectionStatus.PASS,
            findings=[finding],
        )
        d = section.to_dict()
        assert d["article"] == "Art. 12"
        assert d["title"] == "Logging"
        assert d["status"] == "pass"
        assert len(d["findings"]) == 1
        assert d["findings"][0]["severity"] == "info"


class TestComplianceReport:
    """ComplianceReport data model."""

    def test_create_report(self) -> None:
        ts = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)
        report = ComplianceReport(
            framework="EU AI Act",
            generated_at=ts,
            session_id="test-session",
            sections=[],
        )
        assert report.framework == "EU AI Act"
        assert report.generated_at == ts
        assert report.session_id == "test-session"
        assert report.sections == []

    def test_report_with_sections(self) -> None:
        section = ReportSection(
            article="Art. 12",
            title="Logging",
            status=SectionStatus.PASS,
            findings=[],
        )
        report = ComplianceReport(
            framework="EU AI Act",
            generated_at=datetime.now(tz=timezone.utc),
            session_id="s1",
            sections=[section],
        )
        assert len(report.sections) == 1

    def test_summary_counts_statuses(self) -> None:
        sections = [
            ReportSection(
                article="Art. 9",
                title="Risk Management",
                status=SectionStatus.PASS,
                findings=[],
            ),
            ReportSection(
                article="Art. 12",
                title="Logging",
                status=SectionStatus.WARN,
                findings=[
                    Finding(
                        severity=FindingSeverity.WARNING,
                        article="Art. 12",
                        description="Warning",
                    )
                ],
            ),
            ReportSection(
                article="Art. 13",
                title="Transparency",
                status=SectionStatus.FAIL,
                findings=[
                    Finding(
                        severity=FindingSeverity.VIOLATION,
                        article="Art. 13",
                        description="Violation",
                    )
                ],
            ),
            ReportSection(
                article="Art. 14",
                title="Human Oversight",
                status=SectionStatus.NOT_ASSESSED,
                findings=[],
            ),
        ]
        report = ComplianceReport(
            framework="EU AI Act",
            generated_at=datetime.now(tz=timezone.utc),
            session_id="s1",
            sections=sections,
        )
        summary = report.summary()
        assert summary["total_sections"] == 4
        assert summary["pass"] == 1
        assert summary["warn"] == 1
        assert summary["fail"] == 1
        assert summary["not_assessed"] == 1

    def test_summary_counts_findings(self) -> None:
        sections = [
            ReportSection(
                article="Art. 12",
                title="Logging",
                status=SectionStatus.WARN,
                findings=[
                    Finding(
                        severity=FindingSeverity.INFO,
                        article="Art. 12",
                        description="Info 1",
                    ),
                    Finding(
                        severity=FindingSeverity.WARNING,
                        article="Art. 12",
                        description="Warn 1",
                    ),
                ],
            ),
            ReportSection(
                article="Art. 13",
                title="Transparency",
                status=SectionStatus.FAIL,
                findings=[
                    Finding(
                        severity=FindingSeverity.VIOLATION,
                        article="Art. 13",
                        description="Viol 1",
                    ),
                ],
            ),
        ]
        report = ComplianceReport(
            framework="EU AI Act",
            generated_at=datetime.now(tz=timezone.utc),
            session_id="s1",
            sections=sections,
        )
        summary = report.summary()
        assert summary["total_findings"] == 3
        assert summary["violations"] == 1
        assert summary["warnings"] == 1
        assert summary["infos"] == 1

    def test_overall_status_pass_when_all_pass(self) -> None:
        sections = [
            ReportSection(
                article="Art. 12",
                title="Logging",
                status=SectionStatus.PASS,
                findings=[],
            ),
        ]
        report = ComplianceReport(
            framework="EU AI Act",
            generated_at=datetime.now(tz=timezone.utc),
            session_id="s1",
            sections=sections,
        )
        assert report.overall_status() == SectionStatus.PASS

    def test_overall_status_fail_when_any_fail(self) -> None:
        sections = [
            ReportSection(
                article="Art. 12",
                title="Logging",
                status=SectionStatus.PASS,
                findings=[],
            ),
            ReportSection(
                article="Art. 13",
                title="Transparency",
                status=SectionStatus.FAIL,
                findings=[],
            ),
        ]
        report = ComplianceReport(
            framework="EU AI Act",
            generated_at=datetime.now(tz=timezone.utc),
            session_id="s1",
            sections=sections,
        )
        assert report.overall_status() == SectionStatus.FAIL

    def test_overall_status_warn_when_warning_but_no_fail(self) -> None:
        sections = [
            ReportSection(
                article="Art. 12",
                title="Logging",
                status=SectionStatus.PASS,
                findings=[],
            ),
            ReportSection(
                article="Art. 13",
                title="Transparency",
                status=SectionStatus.WARN,
                findings=[],
            ),
        ]
        report = ComplianceReport(
            framework="EU AI Act",
            generated_at=datetime.now(tz=timezone.utc),
            session_id="s1",
            sections=sections,
        )
        assert report.overall_status() == SectionStatus.WARN

    def test_overall_status_not_assessed_when_empty(self) -> None:
        report = ComplianceReport(
            framework="EU AI Act",
            generated_at=datetime.now(tz=timezone.utc),
            session_id="s1",
            sections=[],
        )
        assert report.overall_status() == SectionStatus.NOT_ASSESSED

    def test_to_dict(self) -> None:
        ts = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)
        finding = Finding(
            severity=FindingSeverity.INFO,
            article="Art. 12",
            description="Logging active",
        )
        section = ReportSection(
            article="Art. 12",
            title="Logging",
            status=SectionStatus.PASS,
            findings=[finding],
        )
        report = ComplianceReport(
            framework="EU AI Act",
            generated_at=ts,
            session_id="test-session",
            sections=[section],
        )
        d = report.to_dict()
        assert d["framework"] == "EU AI Act"
        assert d["generated_at"] == "2026-03-01T12:00:00+00:00"
        assert d["session_id"] == "test-session"
        assert d["overall_status"] == "pass"
        assert len(d["sections"]) == 1
        assert "summary" in d
