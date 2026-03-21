"""Tests for ISO 42001 (AI Management System) report generator (M9).

Covers:
- Generating a compliance report from an AuditLog
- Clause 5 (Leadership) assessment
- Clause 6.1 (Risk Assessment) assessment
- Clause 8.4 (AI System Impact Assessment) assessment
- Clause 9.1 (Monitoring) assessment
- Clause 9.2 (Internal Audit) assessment
- Clause 10 (Improvement) assessment
- Edge cases: empty log, all denied, mixed results
"""

from __future__ import annotations

from datetime import datetime, timezone

from agentguard.audit.log import AuditLog
from agentguard.audit.models import AuditEntry
from agentguard.compliance.iso_42001 import ISO42001ReportGenerator
from agentguard.compliance.models import (
    FindingSeverity,
    SectionStatus,
)


def _make_log(
    entries: list[dict[str, str]],
    session_id: str = "test-session",
) -> AuditLog:
    """Helper to create an AuditLog with preset entries."""
    log = AuditLog(session_id=session_id)
    for entry_data in entries:
        log.record(
            action=entry_data.get("action", "test"),
            actor=entry_data.get("actor", "agent"),
            target=entry_data.get("target", "target"),
            result=entry_data.get("result", "allowed"),
            metadata=None,
        )
    return log


class TestISO42001ReportGenerator:
    """ISO 42001 report generator basics."""

    def test_generates_report_from_audit_log(self) -> None:
        log = _make_log([{"action": "file_read", "result": "allowed"}])
        generator = ISO42001ReportGenerator()
        report = generator.generate(log)
        assert report.framework == "ISO 42001"
        assert report.session_id == "test-session"

    def test_report_has_six_sections(self) -> None:
        log = _make_log([{"action": "file_read", "result": "allowed"}])
        generator = ISO42001ReportGenerator()
        report = generator.generate(log)
        assert len(report.sections) == 6
        articles = [s.article for s in report.sections]
        assert "Clause 5" in articles
        assert "Clause 6.1" in articles
        assert "Clause 8.4" in articles
        assert "Clause 9.1" in articles
        assert "Clause 9.2" in articles
        assert "Clause 10" in articles

    def test_report_generated_at_is_set(self) -> None:
        log = _make_log([{"action": "file_read", "result": "allowed"}])
        generator = ISO42001ReportGenerator()
        before = datetime.now(tz=timezone.utc)
        report = generator.generate(log)
        after = datetime.now(tz=timezone.utc)
        assert before <= report.generated_at <= after


class TestClause5Leadership:
    """Clause 5: Leadership — AI governance oversight."""

    def test_multiple_actors_is_pass(self) -> None:
        """Multiple distinct actors suggest governance structure."""
        log = _make_log(
            [
                {"action": "file_read", "actor": "agent-1", "result": "allowed"},
                {"action": "file_write", "actor": "agent-2", "result": "allowed"},
                {"action": "review", "actor": "human-reviewer", "result": "allowed"},
            ]
        )
        generator = ISO42001ReportGenerator()
        report = generator.generate(log)
        clause5 = next(s for s in report.sections if s.article == "Clause 5")
        assert clause5.status == SectionStatus.PASS

    def test_single_actor_is_warning(self) -> None:
        """A single actor suggests lack of governance diversity."""
        log = _make_log(
            [
                {"action": "file_read", "actor": "solo-agent", "result": "allowed"},
                {"action": "file_write", "actor": "solo-agent", "result": "allowed"},
            ]
        )
        generator = ISO42001ReportGenerator()
        report = generator.generate(log)
        clause5 = next(s for s in report.sections if s.article == "Clause 5")
        assert clause5.status == SectionStatus.WARN
        warnings = [
            f for f in clause5.findings if f.severity == FindingSeverity.WARNING
        ]
        assert len(warnings) >= 1

    def test_empty_log_not_assessed(self) -> None:
        log = AuditLog(session_id="empty")
        generator = ISO42001ReportGenerator()
        report = generator.generate(log)
        clause5 = next(s for s in report.sections if s.article == "Clause 5")
        assert clause5.status == SectionStatus.NOT_ASSESSED

    def test_reports_actor_count(self) -> None:
        """Findings should include information about actor count."""
        log = _make_log(
            [
                {"action": "a1", "actor": "agent-a", "result": "allowed"},
                {"action": "a2", "actor": "agent-b", "result": "allowed"},
            ]
        )
        generator = ISO42001ReportGenerator()
        report = generator.generate(log)
        clause5 = next(s for s in report.sections if s.article == "Clause 5")
        info_findings = [
            f for f in clause5.findings if f.severity == FindingSeverity.INFO
        ]
        assert len(info_findings) >= 1


class TestClause61RiskAssessment:
    """Clause 6.1: Risk Assessment — risk identification and controls."""

    def test_denied_actions_show_risk_controls(self) -> None:
        """Denied actions are evidence of active risk controls."""
        log = _make_log(
            [
                {"action": "shell_command", "result": "denied"},
                {"action": "file_read", "result": "allowed"},
            ]
        )
        generator = ISO42001ReportGenerator()
        report = generator.generate(log)
        clause61 = next(s for s in report.sections if s.article == "Clause 6.1")
        assert clause61.status == SectionStatus.PASS
        info_findings = [
            f for f in clause61.findings if f.severity == FindingSeverity.INFO
        ]
        assert len(info_findings) >= 1

    def test_no_denied_no_errors_is_pass(self) -> None:
        """All allowed, no errors — risk controls may exist but not triggered."""
        log = _make_log(
            [
                {"action": "file_read", "result": "allowed"},
                {"action": "shell_command", "result": "allowed"},
            ]
        )
        generator = ISO42001ReportGenerator()
        report = generator.generate(log)
        clause61 = next(s for s in report.sections if s.article == "Clause 6.1")
        assert clause61.status == SectionStatus.PASS

    def test_errors_produce_warning(self) -> None:
        """Errors indicate risk control gaps."""
        log = _make_log(
            [
                {"action": "shell_command", "result": "error"},
            ]
        )
        generator = ISO42001ReportGenerator()
        report = generator.generate(log)
        clause61 = next(s for s in report.sections if s.article == "Clause 6.1")
        assert clause61.status == SectionStatus.WARN
        warnings = [
            f for f in clause61.findings if f.severity == FindingSeverity.WARNING
        ]
        assert len(warnings) >= 1

    def test_empty_log_not_assessed(self) -> None:
        log = AuditLog(session_id="empty")
        generator = ISO42001ReportGenerator()
        report = generator.generate(log)
        clause61 = next(s for s in report.sections if s.article == "Clause 6.1")
        assert clause61.status == SectionStatus.NOT_ASSESSED


class TestClause84ImpactAssessment:
    """Clause 8.4: AI System Impact Assessment — action diversity and coverage."""

    def test_diverse_actions_is_pass(self) -> None:
        """Multiple distinct action types suggest good coverage."""
        log = _make_log(
            [
                {"action": "shell_command", "result": "allowed"},
                {"action": "file_read", "result": "allowed"},
                {"action": "file_write", "result": "denied"},
                {"action": "api_call", "result": "allowed"},
            ]
        )
        generator = ISO42001ReportGenerator()
        report = generator.generate(log)
        clause84 = next(s for s in report.sections if s.article == "Clause 8.4")
        assert clause84.status == SectionStatus.PASS

    def test_single_action_type_is_warning(self) -> None:
        """Only one action type may indicate limited monitoring scope."""
        log = _make_log(
            [
                {"action": "shell_command", "result": "allowed"},
                {"action": "shell_command", "result": "allowed"},
            ]
        )
        generator = ISO42001ReportGenerator()
        report = generator.generate(log)
        clause84 = next(s for s in report.sections if s.article == "Clause 8.4")
        assert clause84.status == SectionStatus.WARN

    def test_reports_action_type_count(self) -> None:
        """Findings should mention action type diversity."""
        log = _make_log(
            [
                {"action": "file_read", "result": "allowed"},
                {"action": "file_write", "result": "allowed"},
                {"action": "shell_command", "result": "allowed"},
            ]
        )
        generator = ISO42001ReportGenerator()
        report = generator.generate(log)
        clause84 = next(s for s in report.sections if s.article == "Clause 8.4")
        info_findings = [
            f for f in clause84.findings if f.severity == FindingSeverity.INFO
        ]
        assert len(info_findings) >= 1
        # Should mention count of action types
        assert any("3" in f.evidence for f in info_findings if f.evidence)

    def test_empty_log_not_assessed(self) -> None:
        log = AuditLog(session_id="empty")
        generator = ISO42001ReportGenerator()
        report = generator.generate(log)
        clause84 = next(s for s in report.sections if s.article == "Clause 8.4")
        assert clause84.status == SectionStatus.NOT_ASSESSED


class TestClause91Monitoring:
    """Clause 9.1: Monitoring — audit log completeness and integrity."""

    def test_nonempty_verified_log_passes(self) -> None:
        """A non-empty, verified log passes monitoring requirements."""
        log = _make_log([{"action": "test", "result": "allowed"}])
        generator = ISO42001ReportGenerator()
        report = generator.generate(log)
        clause91 = next(s for s in report.sections if s.article == "Clause 9.1")
        assert clause91.status == SectionStatus.PASS

    def test_empty_log_is_violation(self) -> None:
        """No monitoring data is a violation."""
        log = AuditLog(session_id="empty")
        generator = ISO42001ReportGenerator()
        report = generator.generate(log)
        clause91 = next(s for s in report.sections if s.article == "Clause 9.1")
        assert clause91.status == SectionStatus.FAIL
        violations = [
            f for f in clause91.findings if f.severity == FindingSeverity.VIOLATION
        ]
        assert len(violations) >= 1

    def test_log_reports_entry_count(self) -> None:
        """Findings should report the number of monitored entries."""
        log = _make_log(
            [
                {"action": "a1", "result": "allowed"},
                {"action": "a2", "result": "allowed"},
                {"action": "a3", "result": "allowed"},
            ]
        )
        generator = ISO42001ReportGenerator()
        report = generator.generate(log)
        clause91 = next(s for s in report.sections if s.article == "Clause 9.1")
        info_findings = [
            f for f in clause91.findings if f.severity == FindingSeverity.INFO
        ]
        assert len(info_findings) >= 1
        assert any("3" in f.evidence for f in info_findings if f.evidence)

    def test_tampered_log_is_violation(self) -> None:
        """A tampered log fails monitoring integrity."""
        log = AuditLog(session_id="tampered")
        log.record(action="a1", actor="a", target="t", result="ok")
        log.record(action="a2", actor="a", target="t", result="ok")
        # Tamper with the chain
        log._entries[0] = AuditEntry(
            action="TAMPERED",
            actor=log._entries[0].actor,
            target=log._entries[0].target,
            result=log._entries[0].result,
            timestamp=log._entries[0].timestamp,
            previous_hash=log._entries[0].previous_hash,
        )
        generator = ISO42001ReportGenerator()
        report = generator.generate(log)
        clause91 = next(s for s in report.sections if s.article == "Clause 9.1")
        assert clause91.status == SectionStatus.FAIL
        violations = [
            f for f in clause91.findings if f.severity == FindingSeverity.VIOLATION
        ]
        assert any("integrity" in v.description.lower() for v in violations)


class TestClause92InternalAudit:
    """Clause 9.2: Internal Audit — verification status."""

    def test_verified_log_passes(self) -> None:
        """A verified audit log passes internal audit requirements."""
        log = _make_log(
            [
                {"action": "test", "result": "allowed"},
            ]
        )
        generator = ISO42001ReportGenerator()
        report = generator.generate(log)
        clause92 = next(s for s in report.sections if s.article == "Clause 9.2")
        assert clause92.status == SectionStatus.PASS

    def test_tampered_log_fails(self) -> None:
        """A tampered log fails internal audit."""
        log = AuditLog(session_id="tampered")
        log.record(action="a1", actor="a", target="t", result="ok")
        log.record(action="a2", actor="a", target="t", result="ok")
        log._entries[0] = AuditEntry(
            action="TAMPERED",
            actor=log._entries[0].actor,
            target=log._entries[0].target,
            result=log._entries[0].result,
            timestamp=log._entries[0].timestamp,
            previous_hash=log._entries[0].previous_hash,
        )
        generator = ISO42001ReportGenerator()
        report = generator.generate(log)
        clause92 = next(s for s in report.sections if s.article == "Clause 9.2")
        assert clause92.status == SectionStatus.FAIL

    def test_empty_log_not_assessed(self) -> None:
        log = AuditLog(session_id="empty")
        generator = ISO42001ReportGenerator()
        report = generator.generate(log)
        clause92 = next(s for s in report.sections if s.article == "Clause 9.2")
        assert clause92.status == SectionStatus.NOT_ASSESSED

    def test_verified_log_has_info_finding(self) -> None:
        """Verified log should produce an info finding."""
        log = _make_log([{"action": "test", "result": "allowed"}])
        generator = ISO42001ReportGenerator()
        report = generator.generate(log)
        clause92 = next(s for s in report.sections if s.article == "Clause 9.2")
        info_findings = [
            f for f in clause92.findings if f.severity == FindingSeverity.INFO
        ]
        assert len(info_findings) >= 1


class TestClause10Improvement:
    """Clause 10: Improvement — error patterns and corrective evidence."""

    def test_no_errors_is_pass(self) -> None:
        """No errors or denied actions suggests stable system."""
        log = _make_log(
            [
                {"action": "file_read", "result": "allowed"},
                {"action": "shell_command", "result": "allowed"},
            ]
        )
        generator = ISO42001ReportGenerator()
        report = generator.generate(log)
        clause10 = next(s for s in report.sections if s.article == "Clause 10")
        assert clause10.status == SectionStatus.PASS

    def test_errors_produce_warning(self) -> None:
        """Errors suggest need for corrective action."""
        log = _make_log(
            [
                {"action": "shell_command", "result": "error"},
                {"action": "file_read", "result": "allowed"},
                {"action": "file_write", "result": "allowed"},
            ]
        )
        generator = ISO42001ReportGenerator()
        report = generator.generate(log)
        clause10 = next(s for s in report.sections if s.article == "Clause 10")
        assert clause10.status == SectionStatus.WARN
        warnings = [
            f for f in clause10.findings if f.severity == FindingSeverity.WARNING
        ]
        assert len(warnings) >= 1

    def test_denied_actions_are_positive_evidence(self) -> None:
        """Denied actions are evidence of corrective controls."""
        log = _make_log(
            [
                {"action": "shell_command", "result": "denied"},
                {"action": "file_read", "result": "allowed"},
            ]
        )
        generator = ISO42001ReportGenerator()
        report = generator.generate(log)
        clause10 = next(s for s in report.sections if s.article == "Clause 10")
        info_findings = [
            f for f in clause10.findings if f.severity == FindingSeverity.INFO
        ]
        assert len(info_findings) >= 1

    def test_empty_log_not_assessed(self) -> None:
        log = AuditLog(session_id="empty")
        generator = ISO42001ReportGenerator()
        report = generator.generate(log)
        clause10 = next(s for s in report.sections if s.article == "Clause 10")
        assert clause10.status == SectionStatus.NOT_ASSESSED

    def test_high_error_rate_is_failure(self) -> None:
        """A high proportion of errors indicates systemic issues."""
        log = _make_log(
            [
                {"action": "a1", "result": "error"},
                {"action": "a2", "result": "error"},
                {"action": "a3", "result": "error"},
                {"action": "a4", "result": "allowed"},
            ]
        )
        generator = ISO42001ReportGenerator()
        report = generator.generate(log)
        clause10 = next(s for s in report.sections if s.article == "Clause 10")
        assert clause10.status == SectionStatus.FAIL
        violations = [
            f for f in clause10.findings if f.severity == FindingSeverity.VIOLATION
        ]
        assert len(violations) >= 1


class TestEdgeCases:
    """Edge cases for the ISO 42001 report generator."""

    def test_empty_audit_log(self) -> None:
        log = AuditLog(session_id="empty")
        generator = ISO42001ReportGenerator()
        report = generator.generate(log)
        # Clause 9.1 should fail (no monitoring)
        clause91 = next(s for s in report.sections if s.article == "Clause 9.1")
        assert clause91.status == SectionStatus.FAIL
        assert report.overall_status() == SectionStatus.FAIL

    def test_large_log(self) -> None:
        log = _make_log(
            [{"action": f"action_{i}", "result": "allowed"} for i in range(100)]
        )
        generator = ISO42001ReportGenerator()
        report = generator.generate(log)
        assert report.overall_status() in {SectionStatus.PASS, SectionStatus.WARN}

    def test_mixed_results(self) -> None:
        log = _make_log(
            [
                {"action": "shell_command", "result": "allowed"},
                {"action": "shell_command", "result": "denied"},
                {"action": "file_write", "result": "error"},
                {"action": "api_call", "result": "allowed"},
            ]
        )
        generator = ISO42001ReportGenerator()
        report = generator.generate(log)
        # Should produce a valid report with all 6 sections
        assert len(report.sections) == 6
        # Should have both info and warning findings
        all_findings = [f for s in report.sections for f in s.findings]
        severities = {f.severity for f in all_findings}
        assert FindingSeverity.INFO in severities

    def test_report_to_dict_is_serializable(self) -> None:
        """The report should be JSON-serializable via to_dict."""
        import json

        log = _make_log(
            [
                {"action": "shell_command", "result": "allowed"},
                {"action": "shell_command", "result": "denied"},
            ]
        )
        generator = ISO42001ReportGenerator()
        report = generator.generate(log)
        d = report.to_dict()
        json_str = json.dumps(d)
        assert isinstance(json_str, str)
        parsed = json.loads(json_str)
        assert parsed["framework"] == "ISO 42001"
