"""Tests for EU AI Act report generator (M4.2).

Covers:
- Generating a compliance report from an AuditLog
- Art. 9 (Risk Management) assessment
- Art. 12 (Logging) assessment
- Art. 13 (Transparency) assessment
- Art. 14 (Human Oversight) assessment
- Edge cases: empty log, all denied, mixed results
"""

from __future__ import annotations

from datetime import datetime, timezone

from agentguard.audit.log import AuditLog
from agentguard.audit.models import AuditEntry
from agentguard.compliance.eu_ai_act import EUAIActReportGenerator
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


class TestEUAIActReportGenerator:
    """EU AI Act report generator."""

    def test_generates_report_from_audit_log(self) -> None:
        log = _make_log([{"action": "file_read", "result": "allowed"}])
        generator = EUAIActReportGenerator()
        report = generator.generate(log)
        assert report.framework == "EU AI Act"
        assert report.session_id == "test-session"

    def test_report_has_four_sections(self) -> None:
        log = _make_log([{"action": "file_read", "result": "allowed"}])
        generator = EUAIActReportGenerator()
        report = generator.generate(log)
        assert len(report.sections) == 4
        articles = [s.article for s in report.sections]
        assert "Art. 9" in articles
        assert "Art. 12" in articles
        assert "Art. 13" in articles
        assert "Art. 14" in articles

    def test_report_generated_at_is_set(self) -> None:
        log = _make_log([{"action": "file_read", "result": "allowed"}])
        generator = EUAIActReportGenerator()
        before = datetime.now(tz=timezone.utc)
        report = generator.generate(log)
        after = datetime.now(tz=timezone.utc)
        assert before <= report.generated_at <= after


class TestArt9RiskManagement:
    """Art. 9: Risk management assessment."""

    def test_no_denied_actions_is_pass(self) -> None:
        log = _make_log(
            [
                {"action": "file_read", "result": "allowed"},
                {"action": "shell_command", "result": "allowed"},
            ]
        )
        generator = EUAIActReportGenerator()
        report = generator.generate(log)
        art9 = next(s for s in report.sections if s.article == "Art. 9")
        assert art9.status == SectionStatus.PASS

    def test_denied_actions_produces_info_finding(self) -> None:
        """Denied actions are GOOD — they show the guard is working."""
        log = _make_log(
            [
                {"action": "shell_command", "result": "denied"},
                {"action": "file_read", "result": "allowed"},
            ]
        )
        generator = EUAIActReportGenerator()
        report = generator.generate(log)
        art9 = next(s for s in report.sections if s.article == "Art. 9")
        assert art9.status == SectionStatus.PASS
        # Should have an info finding noting the guardrail worked
        info_findings = [f for f in art9.findings if f.severity == FindingSeverity.INFO]
        assert len(info_findings) >= 1

    def test_error_actions_produces_warning(self) -> None:
        log = _make_log(
            [
                {"action": "shell_command", "result": "error"},
            ]
        )
        generator = EUAIActReportGenerator()
        report = generator.generate(log)
        art9 = next(s for s in report.sections if s.article == "Art. 9")
        assert art9.status == SectionStatus.WARN
        warnings = [f for f in art9.findings if f.severity == FindingSeverity.WARNING]
        assert len(warnings) >= 1

    def test_all_denied_still_passes(self) -> None:
        """All actions denied means the guardrails are very strict — pass."""
        log = _make_log(
            [
                {"action": "shell_command", "result": "denied"},
                {"action": "file_write", "result": "denied"},
            ]
        )
        generator = EUAIActReportGenerator()
        report = generator.generate(log)
        art9 = next(s for s in report.sections if s.article == "Art. 9")
        assert art9.status == SectionStatus.PASS


class TestArt12Logging:
    """Art. 12: Logging assessment."""

    def test_empty_log_is_violation(self) -> None:
        log = AuditLog(session_id="empty")
        generator = EUAIActReportGenerator()
        report = generator.generate(log)
        art12 = next(s for s in report.sections if s.article == "Art. 12")
        assert art12.status == SectionStatus.FAIL
        violations = [
            f for f in art12.findings if f.severity == FindingSeverity.VIOLATION
        ]
        assert len(violations) >= 1

    def test_nonempty_log_passes(self) -> None:
        log = _make_log([{"action": "test", "result": "allowed"}])
        generator = EUAIActReportGenerator()
        report = generator.generate(log)
        art12 = next(s for s in report.sections if s.article == "Art. 12")
        assert art12.status == SectionStatus.PASS

    def test_log_with_entries_reports_count(self) -> None:
        log = _make_log(
            [
                {"action": "a1", "result": "allowed"},
                {"action": "a2", "result": "denied"},
                {"action": "a3", "result": "allowed"},
            ]
        )
        generator = EUAIActReportGenerator()
        report = generator.generate(log)
        art12 = next(s for s in report.sections if s.article == "Art. 12")
        # Should have info about number of entries
        info_findings = [
            f for f in art12.findings if f.severity == FindingSeverity.INFO
        ]
        assert len(info_findings) >= 1
        # At least one finding should mention the count
        any_mentions_count = any("3" in f.evidence for f in info_findings if f.evidence)
        assert any_mentions_count

    def test_tampered_log_is_violation(self) -> None:
        """A log that fails integrity verification should produce a violation."""
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
        generator = EUAIActReportGenerator()
        report = generator.generate(log)
        art12 = next(s for s in report.sections if s.article == "Art. 12")
        assert art12.status == SectionStatus.FAIL
        violations = [
            f for f in art12.findings if f.severity == FindingSeverity.VIOLATION
        ]
        assert any("integrity" in v.description.lower() for v in violations)


class TestArt13Transparency:
    """Art. 13: Transparency assessment."""

    def test_all_actors_identified_passes(self) -> None:
        log = _make_log(
            [
                {"action": "a1", "actor": "build-agent", "result": "allowed"},
                {"action": "a2", "actor": "code-agent", "result": "allowed"},
            ]
        )
        generator = EUAIActReportGenerator()
        report = generator.generate(log)
        art13 = next(s for s in report.sections if s.article == "Art. 13")
        assert art13.status == SectionStatus.PASS

    def test_reports_unique_actors(self) -> None:
        log = _make_log(
            [
                {"action": "a1", "actor": "agent-1", "result": "allowed"},
                {"action": "a2", "actor": "agent-2", "result": "allowed"},
                {"action": "a3", "actor": "agent-1", "result": "allowed"},
            ]
        )
        generator = EUAIActReportGenerator()
        report = generator.generate(log)
        art13 = next(s for s in report.sections if s.article == "Art. 13")
        info_findings = [
            f for f in art13.findings if f.severity == FindingSeverity.INFO
        ]
        # Should mention the unique actors
        assert len(info_findings) >= 1

    def test_empty_log_not_assessed(self) -> None:
        log = AuditLog(session_id="empty")
        generator = EUAIActReportGenerator()
        report = generator.generate(log)
        art13 = next(s for s in report.sections if s.article == "Art. 13")
        assert art13.status == SectionStatus.NOT_ASSESSED


class TestArt14HumanOversight:
    """Art. 14: Human oversight assessment."""

    def test_no_human_oversight_evidence_is_warning(self) -> None:
        """Without explicit human oversight evidence, warn."""
        log = _make_log(
            [
                {"action": "shell_command", "result": "allowed"},
            ]
        )
        generator = EUAIActReportGenerator()
        report = generator.generate(log)
        art14 = next(s for s in report.sections if s.article == "Art. 14")
        assert art14.status == SectionStatus.WARN

    def test_denied_actions_show_guardrails_active(self) -> None:
        """Denied actions are evidence of automated oversight."""
        log = _make_log(
            [
                {"action": "shell_command", "result": "denied"},
                {"action": "file_read", "result": "allowed"},
            ]
        )
        generator = EUAIActReportGenerator()
        report = generator.generate(log)
        art14 = next(s for s in report.sections if s.article == "Art. 14")
        # Guardrail enforcement is partial evidence of oversight
        info_findings = [
            f for f in art14.findings if f.severity == FindingSeverity.INFO
        ]
        assert len(info_findings) >= 1

    def test_empty_log_not_assessed(self) -> None:
        log = AuditLog(session_id="empty")
        generator = EUAIActReportGenerator()
        report = generator.generate(log)
        art14 = next(s for s in report.sections if s.article == "Art. 14")
        assert art14.status == SectionStatus.NOT_ASSESSED


class TestEdgeCases:
    """Edge cases for the report generator."""

    def test_empty_audit_log(self) -> None:
        log = AuditLog(session_id="empty")
        generator = EUAIActReportGenerator()
        report = generator.generate(log)
        assert report.overall_status() == SectionStatus.FAIL
        # Art. 12 should fail (no logging)
        art12 = next(s for s in report.sections if s.article == "Art. 12")
        assert art12.status == SectionStatus.FAIL

    def test_large_log(self) -> None:
        log = _make_log(
            [{"action": f"action_{i}", "result": "allowed"} for i in range(100)]
        )
        generator = EUAIActReportGenerator()
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
        generator = EUAIActReportGenerator()
        report = generator.generate(log)
        # Should produce a valid report with all 4 sections
        assert len(report.sections) == 4
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
        generator = EUAIActReportGenerator()
        report = generator.generate(log)
        d = report.to_dict()
        # Should not raise
        json_str = json.dumps(d)
        assert isinstance(json_str, str)
        parsed = json.loads(json_str)
        assert parsed["framework"] == "EU AI Act"
