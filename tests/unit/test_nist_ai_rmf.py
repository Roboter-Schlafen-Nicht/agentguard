"""Tests for NIST AI RMF report generator (M9).

Covers:
- Generating a compliance report from an AuditLog
- GOVERN 1 (Governance) assessment
- MAP 1 (Context) assessment
- MEASURE 2 (Assessment) assessment
- MANAGE 1 (Risk Response) assessment
- MANAGE 2 (Monitoring) assessment
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
from agentguard.compliance.nist_ai_rmf import NISTAIRMFReportGenerator


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


class TestNISTAIRMFReportGenerator:
    """NIST AI RMF report generator basics."""

    def test_generates_report_from_audit_log(self) -> None:
        log = _make_log([{"action": "file_read", "result": "allowed"}])
        generator = NISTAIRMFReportGenerator()
        report = generator.generate(log)
        assert report.framework == "NIST AI RMF"
        assert report.session_id == "test-session"

    def test_report_has_five_sections(self) -> None:
        log = _make_log([{"action": "file_read", "result": "allowed"}])
        generator = NISTAIRMFReportGenerator()
        report = generator.generate(log)
        assert len(report.sections) == 5
        articles = [s.article for s in report.sections]
        assert "GOVERN 1" in articles
        assert "MAP 1" in articles
        assert "MEASURE 2" in articles
        assert "MANAGE 1" in articles
        assert "MANAGE 2" in articles

    def test_report_generated_at_is_set(self) -> None:
        log = _make_log([{"action": "file_read", "result": "allowed"}])
        generator = NISTAIRMFReportGenerator()
        before = datetime.now(tz=timezone.utc)
        report = generator.generate(log)
        after = datetime.now(tz=timezone.utc)
        assert before <= report.generated_at <= after


class TestGovern1Governance:
    """GOVERN 1: Policies and oversight."""

    def test_multiple_actors_with_denials_is_pass(self) -> None:
        """Multiple actors and policy enforcement suggest governance."""
        log = _make_log(
            [
                {"action": "file_read", "actor": "agent-1", "result": "allowed"},
                {"action": "shell_cmd", "actor": "agent-2", "result": "denied"},
                {"action": "review", "actor": "human", "result": "allowed"},
            ]
        )
        generator = NISTAIRMFReportGenerator()
        report = generator.generate(log)
        gov1 = next(s for s in report.sections if s.article == "GOVERN 1")
        assert gov1.status == SectionStatus.PASS

    def test_single_actor_no_denials_is_warning(self) -> None:
        """Single actor with no policy enforcement suggests weak governance."""
        log = _make_log(
            [
                {"action": "file_read", "actor": "solo-agent", "result": "allowed"},
                {"action": "file_write", "actor": "solo-agent", "result": "allowed"},
            ]
        )
        generator = NISTAIRMFReportGenerator()
        report = generator.generate(log)
        gov1 = next(s for s in report.sections if s.article == "GOVERN 1")
        assert gov1.status == SectionStatus.WARN
        warnings = [f for f in gov1.findings if f.severity == FindingSeverity.WARNING]
        assert len(warnings) >= 1

    def test_empty_log_not_assessed(self) -> None:
        log = AuditLog(session_id="empty")
        generator = NISTAIRMFReportGenerator()
        report = generator.generate(log)
        gov1 = next(s for s in report.sections if s.article == "GOVERN 1")
        assert gov1.status == SectionStatus.NOT_ASSESSED

    def test_denial_evidence_produces_info(self) -> None:
        """Policy denials should produce an info finding about governance."""
        log = _make_log(
            [
                {"action": "shell_cmd", "result": "denied"},
                {"action": "file_read", "result": "allowed"},
            ]
        )
        generator = NISTAIRMFReportGenerator()
        report = generator.generate(log)
        gov1 = next(s for s in report.sections if s.article == "GOVERN 1")
        info_findings = [f for f in gov1.findings if f.severity == FindingSeverity.INFO]
        assert len(info_findings) >= 1


class TestMap1Context:
    """MAP 1: AI system context mapping."""

    def test_diverse_actions_is_pass(self) -> None:
        """Multiple action types suggest broad context mapping."""
        log = _make_log(
            [
                {"action": "shell_command", "result": "allowed"},
                {"action": "file_read", "result": "allowed"},
                {"action": "file_write", "result": "denied"},
                {"action": "api_call", "result": "allowed"},
            ]
        )
        generator = NISTAIRMFReportGenerator()
        report = generator.generate(log)
        map1 = next(s for s in report.sections if s.article == "MAP 1")
        assert map1.status == SectionStatus.PASS

    def test_single_action_type_is_warning(self) -> None:
        """Only one action type suggests limited context mapping."""
        log = _make_log(
            [
                {"action": "file_read", "result": "allowed"},
                {"action": "file_read", "result": "allowed"},
            ]
        )
        generator = NISTAIRMFReportGenerator()
        report = generator.generate(log)
        map1 = next(s for s in report.sections if s.article == "MAP 1")
        assert map1.status == SectionStatus.WARN

    def test_reports_action_type_count(self) -> None:
        """Findings should mention action type diversity."""
        log = _make_log(
            [
                {"action": "file_read", "result": "allowed"},
                {"action": "file_write", "result": "allowed"},
                {"action": "shell_command", "result": "allowed"},
            ]
        )
        generator = NISTAIRMFReportGenerator()
        report = generator.generate(log)
        map1 = next(s for s in report.sections if s.article == "MAP 1")
        info_findings = [f for f in map1.findings if f.severity == FindingSeverity.INFO]
        assert len(info_findings) >= 1
        assert any("3" in f.evidence for f in info_findings if f.evidence)

    def test_empty_log_not_assessed(self) -> None:
        log = AuditLog(session_id="empty")
        generator = NISTAIRMFReportGenerator()
        report = generator.generate(log)
        map1 = next(s for s in report.sections if s.article == "MAP 1")
        assert map1.status == SectionStatus.NOT_ASSESSED


class TestMeasure2Assessment:
    """MEASURE 2: Risk measurement metrics."""

    def test_low_error_rate_is_pass(self) -> None:
        """Low error rate suggests good measurement."""
        log = _make_log(
            [
                {"action": "file_read", "result": "allowed"},
                {"action": "shell_cmd", "result": "allowed"},
                {"action": "api_call", "result": "allowed"},
            ]
        )
        generator = NISTAIRMFReportGenerator()
        report = generator.generate(log)
        meas2 = next(s for s in report.sections if s.article == "MEASURE 2")
        assert meas2.status == SectionStatus.PASS

    def test_some_errors_is_warning(self) -> None:
        """Some errors indicate measurement gaps."""
        log = _make_log(
            [
                {"action": "shell_cmd", "result": "error"},
                {"action": "file_read", "result": "allowed"},
                {"action": "api_call", "result": "allowed"},
            ]
        )
        generator = NISTAIRMFReportGenerator()
        report = generator.generate(log)
        meas2 = next(s for s in report.sections if s.article == "MEASURE 2")
        assert meas2.status == SectionStatus.WARN
        warnings = [f for f in meas2.findings if f.severity == FindingSeverity.WARNING]
        assert len(warnings) >= 1

    def test_high_error_rate_is_fail(self) -> None:
        """High error rate indicates systemic measurement failure."""
        log = _make_log(
            [
                {"action": "a1", "result": "error"},
                {"action": "a2", "result": "error"},
                {"action": "a3", "result": "error"},
                {"action": "a4", "result": "allowed"},
            ]
        )
        generator = NISTAIRMFReportGenerator()
        report = generator.generate(log)
        meas2 = next(s for s in report.sections if s.article == "MEASURE 2")
        assert meas2.status == SectionStatus.FAIL
        violations = [
            f for f in meas2.findings if f.severity == FindingSeverity.VIOLATION
        ]
        assert len(violations) >= 1

    def test_reports_denial_rate(self) -> None:
        """Findings should include denial rate as measurement data."""
        log = _make_log(
            [
                {"action": "shell_cmd", "result": "denied"},
                {"action": "file_read", "result": "allowed"},
            ]
        )
        generator = NISTAIRMFReportGenerator()
        report = generator.generate(log)
        meas2 = next(s for s in report.sections if s.article == "MEASURE 2")
        info_findings = [
            f for f in meas2.findings if f.severity == FindingSeverity.INFO
        ]
        assert len(info_findings) >= 1

    def test_empty_log_not_assessed(self) -> None:
        log = AuditLog(session_id="empty")
        generator = NISTAIRMFReportGenerator()
        report = generator.generate(log)
        meas2 = next(s for s in report.sections if s.article == "MEASURE 2")
        assert meas2.status == SectionStatus.NOT_ASSESSED


class TestManage1RiskResponse:
    """MANAGE 1: Risk response via policy enforcement."""

    def test_denied_actions_show_active_response(self) -> None:
        """Denied actions are evidence of active risk response."""
        log = _make_log(
            [
                {"action": "shell_cmd", "result": "denied"},
                {"action": "file_read", "result": "allowed"},
            ]
        )
        generator = NISTAIRMFReportGenerator()
        report = generator.generate(log)
        mgr1 = next(s for s in report.sections if s.article == "MANAGE 1")
        assert mgr1.status == SectionStatus.PASS
        info_findings = [f for f in mgr1.findings if f.severity == FindingSeverity.INFO]
        assert len(info_findings) >= 1

    def test_no_denials_is_warning(self) -> None:
        """No denied actions may indicate no risk response mechanisms."""
        log = _make_log(
            [
                {"action": "file_read", "result": "allowed"},
                {"action": "shell_cmd", "result": "allowed"},
            ]
        )
        generator = NISTAIRMFReportGenerator()
        report = generator.generate(log)
        mgr1 = next(s for s in report.sections if s.article == "MANAGE 1")
        assert mgr1.status == SectionStatus.WARN

    def test_errors_produce_warning(self) -> None:
        """Errors suggest risk response gaps."""
        log = _make_log(
            [
                {"action": "shell_cmd", "result": "error"},
                {"action": "file_read", "result": "allowed"},
            ]
        )
        generator = NISTAIRMFReportGenerator()
        report = generator.generate(log)
        mgr1 = next(s for s in report.sections if s.article == "MANAGE 1")
        warnings = [f for f in mgr1.findings if f.severity == FindingSeverity.WARNING]
        assert len(warnings) >= 1

    def test_empty_log_not_assessed(self) -> None:
        log = AuditLog(session_id="empty")
        generator = NISTAIRMFReportGenerator()
        report = generator.generate(log)
        mgr1 = next(s for s in report.sections if s.article == "MANAGE 1")
        assert mgr1.status == SectionStatus.NOT_ASSESSED


class TestManage2Monitoring:
    """MANAGE 2: Ongoing monitoring — log integrity and completeness."""

    def test_nonempty_verified_log_passes(self) -> None:
        """A non-empty, verified log passes monitoring requirements."""
        log = _make_log([{"action": "test", "result": "allowed"}])
        generator = NISTAIRMFReportGenerator()
        report = generator.generate(log)
        mgr2 = next(s for s in report.sections if s.article == "MANAGE 2")
        assert mgr2.status == SectionStatus.PASS

    def test_empty_log_is_violation(self) -> None:
        """No monitoring data is a violation."""
        log = AuditLog(session_id="empty")
        generator = NISTAIRMFReportGenerator()
        report = generator.generate(log)
        mgr2 = next(s for s in report.sections if s.article == "MANAGE 2")
        assert mgr2.status == SectionStatus.FAIL
        violations = [
            f for f in mgr2.findings if f.severity == FindingSeverity.VIOLATION
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
        generator = NISTAIRMFReportGenerator()
        report = generator.generate(log)
        mgr2 = next(s for s in report.sections if s.article == "MANAGE 2")
        info_findings = [f for f in mgr2.findings if f.severity == FindingSeverity.INFO]
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
        generator = NISTAIRMFReportGenerator()
        report = generator.generate(log)
        mgr2 = next(s for s in report.sections if s.article == "MANAGE 2")
        assert mgr2.status == SectionStatus.FAIL
        violations = [
            f for f in mgr2.findings if f.severity == FindingSeverity.VIOLATION
        ]
        assert any("integrity" in v.description.lower() for v in violations)


class TestEdgeCases:
    """Edge cases for the NIST AI RMF report generator."""

    def test_empty_audit_log(self) -> None:
        log = AuditLog(session_id="empty")
        generator = NISTAIRMFReportGenerator()
        report = generator.generate(log)
        # MANAGE 2 should fail (no monitoring)
        mgr2 = next(s for s in report.sections if s.article == "MANAGE 2")
        assert mgr2.status == SectionStatus.FAIL
        assert report.overall_status() == SectionStatus.FAIL

    def test_large_log(self) -> None:
        log = _make_log(
            [{"action": f"action_{i}", "result": "allowed"} for i in range(100)]
        )
        generator = NISTAIRMFReportGenerator()
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
        generator = NISTAIRMFReportGenerator()
        report = generator.generate(log)
        # Should produce a valid report with all 5 sections
        assert len(report.sections) == 5
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
        generator = NISTAIRMFReportGenerator()
        report = generator.generate(log)
        d = report.to_dict()
        json_str = json.dumps(d)
        assert isinstance(json_str, str)
        parsed = json.loads(json_str)
        assert parsed["framework"] == "NIST AI RMF"

    def test_all_denied_shows_strong_risk_response(self) -> None:
        """All denied actions should show strong risk response in MANAGE 1."""
        log = _make_log(
            [
                {"action": "shell_command", "result": "denied"},
                {"action": "file_write", "result": "denied"},
            ]
        )
        generator = NISTAIRMFReportGenerator()
        report = generator.generate(log)
        mgr1 = next(s for s in report.sections if s.article == "MANAGE 1")
        assert mgr1.status == SectionStatus.PASS
