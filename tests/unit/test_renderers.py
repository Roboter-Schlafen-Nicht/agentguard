"""Tests for compliance report renderers (M4.3).

Covers:
- JSON renderer (render_json)
- Plain text renderer (render_text)
- File output for both renderers
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from agentguard.compliance.models import (
    ComplianceReport,
    Finding,
    FindingSeverity,
    ReportSection,
    SectionStatus,
)
from agentguard.compliance.renderers import render_json, render_text

if TYPE_CHECKING:
    from pathlib import Path


def _make_report() -> ComplianceReport:
    """Create a sample report for renderer tests."""
    return ComplianceReport(
        framework="EU AI Act",
        generated_at=datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc),
        session_id="test-session",
        sections=[
            ReportSection(
                article="Art. 9",
                title="Risk Management",
                status=SectionStatus.PASS,
                findings=[
                    Finding(
                        severity=FindingSeverity.INFO,
                        article="Art. 9",
                        description="All actions executed successfully",
                        evidence="10 actions, all allowed, no errors",
                    ),
                ],
            ),
            ReportSection(
                article="Art. 12",
                title="Logging",
                status=SectionStatus.PASS,
                findings=[
                    Finding(
                        severity=FindingSeverity.INFO,
                        article="Art. 12",
                        description="Audit logging is active",
                        evidence="10 entries recorded in session",
                    ),
                    Finding(
                        severity=FindingSeverity.INFO,
                        article="Art. 12",
                        description="Hash chain integrity verified",
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
                        description="Unidentified actor detected",
                        evidence="Actor 'unknown' used in 3 entries",
                    ),
                ],
            ),
            ReportSection(
                article="Art. 14",
                title="Human Oversight",
                status=SectionStatus.WARN,
                findings=[
                    Finding(
                        severity=FindingSeverity.WARNING,
                        article="Art. 14",
                        description="No human-in-the-loop evidence",
                    ),
                ],
            ),
        ],
    )


class TestRenderJSON:
    """JSON renderer."""

    def test_returns_valid_json_string(self) -> None:
        report = _make_report()
        result = render_json(report)
        parsed = json.loads(result)
        assert isinstance(parsed, dict)

    def test_contains_framework(self) -> None:
        report = _make_report()
        result = render_json(report)
        parsed = json.loads(result)
        assert parsed["framework"] == "EU AI Act"

    def test_contains_session_id(self) -> None:
        report = _make_report()
        result = render_json(report)
        parsed = json.loads(result)
        assert parsed["session_id"] == "test-session"

    def test_contains_overall_status(self) -> None:
        report = _make_report()
        result = render_json(report)
        parsed = json.loads(result)
        assert parsed["overall_status"] == "fail"

    def test_contains_summary(self) -> None:
        report = _make_report()
        result = render_json(report)
        parsed = json.loads(result)
        assert "summary" in parsed
        assert parsed["summary"]["total_sections"] == 4

    def test_contains_sections(self) -> None:
        report = _make_report()
        result = render_json(report)
        parsed = json.loads(result)
        assert len(parsed["sections"]) == 4

    def test_is_pretty_printed(self) -> None:
        report = _make_report()
        result = render_json(report)
        # Pretty-printed JSON has newlines and indentation
        assert "\n" in result
        assert "  " in result

    def test_write_to_file(self, tmp_path: Path) -> None:
        report = _make_report()
        output = tmp_path / "report.json"
        render_json(report, output=output)
        assert output.exists()
        content = output.read_text(encoding="utf-8")
        parsed = json.loads(content)
        assert parsed["framework"] == "EU AI Act"


class TestRenderText:
    """Plain text renderer."""

    def test_contains_title(self) -> None:
        report = _make_report()
        result = render_text(report)
        assert "EU AI Act" in result
        assert "Compliance Report" in result

    def test_contains_session_id(self) -> None:
        report = _make_report()
        result = render_text(report)
        assert "test-session" in result

    def test_contains_overall_status(self) -> None:
        report = _make_report()
        result = render_text(report)
        assert "FAIL" in result

    def test_contains_section_headers(self) -> None:
        report = _make_report()
        result = render_text(report)
        assert "Art. 9" in result
        assert "Risk Management" in result
        assert "Art. 12" in result
        assert "Logging" in result
        assert "Art. 13" in result
        assert "Transparency" in result
        assert "Art. 14" in result
        assert "Human Oversight" in result

    def test_contains_section_statuses(self) -> None:
        report = _make_report()
        result = render_text(report)
        assert "PASS" in result
        assert "WARN" in result
        assert "FAIL" in result

    def test_contains_finding_descriptions(self) -> None:
        report = _make_report()
        result = render_text(report)
        assert "All actions executed successfully" in result
        assert "Audit logging is active" in result
        assert "Unidentified actor detected" in result

    def test_contains_evidence(self) -> None:
        report = _make_report()
        result = render_text(report)
        assert "10 entries recorded in session" in result

    def test_contains_summary_section(self) -> None:
        report = _make_report()
        result = render_text(report)
        assert "Summary" in result

    def test_write_to_file(self, tmp_path: Path) -> None:
        report = _make_report()
        output = tmp_path / "report.txt"
        render_text(report, output=output)
        assert output.exists()
        content = output.read_text(encoding="utf-8")
        assert "EU AI Act" in content

    def test_empty_report(self) -> None:
        report = ComplianceReport(
            framework="EU AI Act",
            generated_at=datetime(2026, 3, 1, tzinfo=timezone.utc),
            session_id="empty",
            sections=[],
        )
        result = render_text(report)
        assert "EU AI Act" in result
        assert "NOT_ASSESSED" in result
