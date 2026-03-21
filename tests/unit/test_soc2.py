"""Tests for SOC 2 Trust Services Criteria report generator (M9).

Covers:
- Generating a compliance report from an AuditLog
- CC6.1 (Logical Access) assessment
- CC7.2 (System Monitoring) assessment
- CC8.1 (Change Management) assessment
- A1.2 (Availability) assessment
- CC4.1 (Monitoring Activities) assessment
- Edge cases: empty log, all denied, mixed results
"""

from __future__ import annotations

from datetime import datetime, timezone

from agentguard.audit.log import AuditLog
from agentguard.audit.models import AuditEntry
from agentguard.compliance.models import (
    FindingSeverity,
    SectionStatus,
)
from agentguard.compliance.soc2 import SOC2ReportGenerator


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


class TestSOC2ReportGenerator:
    """SOC 2 report generator basics."""

    def test_generates_report_from_audit_log(self) -> None:
        log = _make_log([{"action": "file_read", "result": "allowed"}])
        generator = SOC2ReportGenerator()
        report = generator.generate(log)
        assert report.framework == "SOC 2"
        assert report.session_id == "test-session"

    def test_report_has_five_sections(self) -> None:
        log = _make_log([{"action": "file_read", "result": "allowed"}])
        generator = SOC2ReportGenerator()
        report = generator.generate(log)
        assert len(report.sections) == 5
        articles = [s.article for s in report.sections]
        assert "CC6.1" in articles
        assert "CC7.2" in articles
        assert "CC8.1" in articles
        assert "A1.2" in articles
        assert "CC4.1" in articles

    def test_report_generated_at_is_set(self) -> None:
        log = _make_log([{"action": "file_read", "result": "allowed"}])
        generator = SOC2ReportGenerator()
        before = datetime.now(tz=timezone.utc)
        report = generator.generate(log)
        after = datetime.now(tz=timezone.utc)
        assert before <= report.generated_at <= after

    def test_section_titles(self) -> None:
        """Each section should have a descriptive title."""
        log = _make_log([{"action": "file_read", "result": "allowed"}])
        generator = SOC2ReportGenerator()
        report = generator.generate(log)
        titles = {s.article: s.title for s in report.sections}
        assert titles["CC6.1"] == "Logical Access"
        assert titles["CC7.2"] == "System Monitoring"
        assert titles["CC8.1"] == "Change Management"
        assert titles["A1.2"] == "Availability"
        assert titles["CC4.1"] == "Monitoring Activities"


class TestCC61LogicalAccess:
    """CC6.1: Logical Access — access controls and policy enforcement."""

    def test_denials_with_multiple_actors_is_pass(self) -> None:
        """Policy enforcement + multiple actors = strong access controls."""
        log = _make_log(
            [
                {"action": "file_read", "actor": "agent-1", "result": "allowed"},
                {"action": "shell_cmd", "actor": "agent-2", "result": "denied"},
                {"action": "review", "actor": "human", "result": "allowed"},
            ]
        )
        generator = SOC2ReportGenerator()
        report = generator.generate(log)
        cc61 = next(s for s in report.sections if s.article == "CC6.1")
        assert cc61.status == SectionStatus.PASS

    def test_single_actor_no_denials_is_warning(self) -> None:
        """No access restrictions suggests weak access controls."""
        log = _make_log(
            [
                {"action": "file_read", "actor": "solo-agent", "result": "allowed"},
                {"action": "file_write", "actor": "solo-agent", "result": "allowed"},
            ]
        )
        generator = SOC2ReportGenerator()
        report = generator.generate(log)
        cc61 = next(s for s in report.sections if s.article == "CC6.1")
        assert cc61.status == SectionStatus.WARN
        warnings = [f for f in cc61.findings if f.severity == FindingSeverity.WARNING]
        assert len(warnings) >= 1

    def test_empty_log_not_assessed(self) -> None:
        log = AuditLog(session_id="empty")
        generator = SOC2ReportGenerator()
        report = generator.generate(log)
        cc61 = next(s for s in report.sections if s.article == "CC6.1")
        assert cc61.status == SectionStatus.NOT_ASSESSED

    def test_reports_actor_count(self) -> None:
        log = _make_log(
            [
                {"action": "a1", "actor": "agent-a", "result": "allowed"},
                {"action": "a2", "actor": "agent-b", "result": "allowed"},
            ]
        )
        generator = SOC2ReportGenerator()
        report = generator.generate(log)
        cc61 = next(s for s in report.sections if s.article == "CC6.1")
        info_findings = [f for f in cc61.findings if f.severity == FindingSeverity.INFO]
        assert len(info_findings) >= 1


class TestCC72SystemMonitoring:
    """CC7.2: System Monitoring — log integrity and completeness."""

    def test_nonempty_verified_log_passes(self) -> None:
        log = _make_log([{"action": "test", "result": "allowed"}])
        generator = SOC2ReportGenerator()
        report = generator.generate(log)
        cc72 = next(s for s in report.sections if s.article == "CC7.2")
        assert cc72.status == SectionStatus.PASS

    def test_empty_log_is_violation(self) -> None:
        log = AuditLog(session_id="empty")
        generator = SOC2ReportGenerator()
        report = generator.generate(log)
        cc72 = next(s for s in report.sections if s.article == "CC7.2")
        assert cc72.status == SectionStatus.FAIL
        violations = [
            f for f in cc72.findings if f.severity == FindingSeverity.VIOLATION
        ]
        assert len(violations) >= 1

    def test_log_reports_entry_count(self) -> None:
        log = _make_log(
            [
                {"action": "a1", "result": "allowed"},
                {"action": "a2", "result": "allowed"},
                {"action": "a3", "result": "allowed"},
            ]
        )
        generator = SOC2ReportGenerator()
        report = generator.generate(log)
        cc72 = next(s for s in report.sections if s.article == "CC7.2")
        info_findings = [f for f in cc72.findings if f.severity == FindingSeverity.INFO]
        assert len(info_findings) >= 1
        assert any("3" in f.evidence for f in info_findings if f.evidence)

    def test_tampered_log_is_violation(self) -> None:
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
        generator = SOC2ReportGenerator()
        report = generator.generate(log)
        cc72 = next(s for s in report.sections if s.article == "CC7.2")
        assert cc72.status == SectionStatus.FAIL
        violations = [
            f for f in cc72.findings if f.severity == FindingSeverity.VIOLATION
        ]
        assert any("integrity" in v.description.lower() for v in violations)


class TestCC81ChangeManagement:
    """CC8.1: Change Management — action diversity and scope."""

    def test_diverse_actions_is_pass(self) -> None:
        log = _make_log(
            [
                {"action": "shell_command", "result": "allowed"},
                {"action": "file_read", "result": "allowed"},
                {"action": "file_write", "result": "denied"},
                {"action": "api_call", "result": "allowed"},
            ]
        )
        generator = SOC2ReportGenerator()
        report = generator.generate(log)
        cc81 = next(s for s in report.sections if s.article == "CC8.1")
        assert cc81.status == SectionStatus.PASS

    def test_single_action_type_is_warning(self) -> None:
        log = _make_log(
            [
                {"action": "file_read", "result": "allowed"},
                {"action": "file_read", "result": "allowed"},
            ]
        )
        generator = SOC2ReportGenerator()
        report = generator.generate(log)
        cc81 = next(s for s in report.sections if s.article == "CC8.1")
        assert cc81.status == SectionStatus.WARN

    def test_reports_action_type_count(self) -> None:
        log = _make_log(
            [
                {"action": "file_read", "result": "allowed"},
                {"action": "file_write", "result": "allowed"},
                {"action": "shell_command", "result": "allowed"},
            ]
        )
        generator = SOC2ReportGenerator()
        report = generator.generate(log)
        cc81 = next(s for s in report.sections if s.article == "CC8.1")
        info_findings = [f for f in cc81.findings if f.severity == FindingSeverity.INFO]
        assert len(info_findings) >= 1
        assert any("3" in f.evidence for f in info_findings if f.evidence)

    def test_empty_log_not_assessed(self) -> None:
        log = AuditLog(session_id="empty")
        generator = SOC2ReportGenerator()
        report = generator.generate(log)
        cc81 = next(s for s in report.sections if s.article == "CC8.1")
        assert cc81.status == SectionStatus.NOT_ASSESSED


class TestA12Availability:
    """A1.2: Availability — error patterns and resilience."""

    def test_no_errors_is_pass(self) -> None:
        log = _make_log(
            [
                {"action": "file_read", "result": "allowed"},
                {"action": "shell_command", "result": "allowed"},
            ]
        )
        generator = SOC2ReportGenerator()
        report = generator.generate(log)
        a12 = next(s for s in report.sections if s.article == "A1.2")
        assert a12.status == SectionStatus.PASS

    def test_some_errors_is_warning(self) -> None:
        log = _make_log(
            [
                {"action": "shell_command", "result": "error"},
                {"action": "file_read", "result": "allowed"},
                {"action": "file_write", "result": "allowed"},
            ]
        )
        generator = SOC2ReportGenerator()
        report = generator.generate(log)
        a12 = next(s for s in report.sections if s.article == "A1.2")
        assert a12.status == SectionStatus.WARN
        warnings = [f for f in a12.findings if f.severity == FindingSeverity.WARNING]
        assert len(warnings) >= 1

    def test_high_error_rate_is_fail(self) -> None:
        log = _make_log(
            [
                {"action": "a1", "result": "error"},
                {"action": "a2", "result": "error"},
                {"action": "a3", "result": "error"},
                {"action": "a4", "result": "allowed"},
            ]
        )
        generator = SOC2ReportGenerator()
        report = generator.generate(log)
        a12 = next(s for s in report.sections if s.article == "A1.2")
        assert a12.status == SectionStatus.FAIL
        violations = [
            f for f in a12.findings if f.severity == FindingSeverity.VIOLATION
        ]
        assert len(violations) >= 1

    def test_empty_log_not_assessed(self) -> None:
        log = AuditLog(session_id="empty")
        generator = SOC2ReportGenerator()
        report = generator.generate(log)
        a12 = next(s for s in report.sections if s.article == "A1.2")
        assert a12.status == SectionStatus.NOT_ASSESSED

    def test_denied_actions_are_not_errors(self) -> None:
        """Denied actions are policy enforcement, not availability issues."""
        log = _make_log(
            [
                {"action": "shell_command", "result": "denied"},
                {"action": "file_read", "result": "allowed"},
            ]
        )
        generator = SOC2ReportGenerator()
        report = generator.generate(log)
        a12 = next(s for s in report.sections if s.article == "A1.2")
        assert a12.status == SectionStatus.PASS


class TestCC41MonitoringActivities:
    """CC4.1: Monitoring Activities — oversight evidence."""

    def test_multiple_actors_with_denials_is_pass(self) -> None:
        """Multiple actors + denials = strong oversight."""
        log = _make_log(
            [
                {"action": "file_read", "actor": "agent-1", "result": "allowed"},
                {"action": "shell_cmd", "actor": "agent-2", "result": "denied"},
                {"action": "review", "actor": "human", "result": "allowed"},
            ]
        )
        generator = SOC2ReportGenerator()
        report = generator.generate(log)
        cc41 = next(s for s in report.sections if s.article == "CC4.1")
        assert cc41.status == SectionStatus.PASS

    def test_single_actor_no_oversight_is_warning(self) -> None:
        log = _make_log(
            [
                {"action": "file_read", "actor": "solo", "result": "allowed"},
                {"action": "file_write", "actor": "solo", "result": "allowed"},
            ]
        )
        generator = SOC2ReportGenerator()
        report = generator.generate(log)
        cc41 = next(s for s in report.sections if s.article == "CC4.1")
        assert cc41.status == SectionStatus.WARN

    def test_empty_log_not_assessed(self) -> None:
        log = AuditLog(session_id="empty")
        generator = SOC2ReportGenerator()
        report = generator.generate(log)
        cc41 = next(s for s in report.sections if s.article == "CC4.1")
        assert cc41.status == SectionStatus.NOT_ASSESSED

    def test_reports_oversight_metrics(self) -> None:
        """Should report actor and denial counts."""
        log = _make_log(
            [
                {"action": "file_read", "actor": "agent-a", "result": "allowed"},
                {"action": "shell_cmd", "actor": "agent-b", "result": "denied"},
            ]
        )
        generator = SOC2ReportGenerator()
        report = generator.generate(log)
        cc41 = next(s for s in report.sections if s.article == "CC4.1")
        info_findings = [f for f in cc41.findings if f.severity == FindingSeverity.INFO]
        assert len(info_findings) >= 1


class TestEdgeCases:
    """Edge cases for the SOC 2 report generator."""

    def test_empty_audit_log(self) -> None:
        log = AuditLog(session_id="empty")
        generator = SOC2ReportGenerator()
        report = generator.generate(log)
        cc72 = next(s for s in report.sections if s.article == "CC7.2")
        assert cc72.status == SectionStatus.FAIL
        assert report.overall_status() == SectionStatus.FAIL

    def test_large_log(self) -> None:
        log = _make_log(
            [{"action": f"action_{i}", "result": "allowed"} for i in range(100)]
        )
        generator = SOC2ReportGenerator()
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
        generator = SOC2ReportGenerator()
        report = generator.generate(log)
        assert len(report.sections) == 5
        all_findings = [f for s in report.sections for f in s.findings]
        severities = {f.severity for f in all_findings}
        assert FindingSeverity.INFO in severities

    def test_report_to_dict_is_serializable(self) -> None:
        import json

        log = _make_log(
            [
                {"action": "shell_command", "result": "allowed"},
                {"action": "shell_command", "result": "denied"},
            ]
        )
        generator = SOC2ReportGenerator()
        report = generator.generate(log)
        d = report.to_dict()
        json_str = json.dumps(d)
        assert isinstance(json_str, str)
        parsed = json.loads(json_str)
        assert parsed["framework"] == "SOC 2"
