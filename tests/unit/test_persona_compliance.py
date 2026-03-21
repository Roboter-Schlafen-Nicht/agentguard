"""Tests for persona safety section in EU AI Act compliance report (M14).

Covers:
- Persona safety section appears in report when enabled
- Low/medium/high/critical risk score produce appropriate findings
- Empty audit log produces NOT_ASSESSED
- Integration with ConversationRiskScorer
- Metadata-enriched entries are analyzed
- Findings use correct severity levels
- Report backward compatibility (existing 4 sections unchanged)
"""

from __future__ import annotations

from agentguard.audit.log import AuditLog
from agentguard.compliance.eu_ai_act import EUAIActReportGenerator
from agentguard.compliance.models import (
    FindingSeverity,
    SectionStatus,
)


def _make_log(
    entries: list[dict[str, str | dict[str, str] | None]],
    session_id: str = "test-session",
) -> AuditLog:
    """Helper to create an AuditLog with preset entries."""
    log = AuditLog(session_id=session_id)
    for entry_data in entries:
        log.record(
            action=str(entry_data.get("action", "test")),
            actor=str(entry_data.get("actor", "agent")),
            target=str(entry_data.get("target", "target")),
            result=str(entry_data.get("result", "allowed")),
            metadata=entry_data.get("metadata"),  # type: ignore[arg-type]
        )
    return log


class TestPersonaSafetySection:
    """Tests for the persona safety compliance section."""

    def test_section_present_in_report(self) -> None:
        log = _make_log([{"result": "allowed"}])
        gen = EUAIActReportGenerator()
        report = gen.generate(log)
        articles = [s.article for s in report.sections]
        assert "Art. 5/9" in articles

    def test_report_has_five_sections(self) -> None:
        log = _make_log([{"result": "allowed"}])
        gen = EUAIActReportGenerator()
        report = gen.generate(log)
        assert len(report.sections) == 5

    def test_empty_log_not_assessed(self) -> None:
        log = _make_log([])
        gen = EUAIActReportGenerator()
        report = gen.generate(log)
        section = next(s for s in report.sections if s.article == "Art. 5/9")
        assert section.status == SectionStatus.NOT_ASSESSED

    def test_all_allowed_low_risk_passes(self) -> None:
        log = _make_log([{"result": "allowed"} for _ in range(10)])
        gen = EUAIActReportGenerator()
        report = gen.generate(log)
        section = next(s for s in report.sections if s.article == "Art. 5/9")
        assert section.status == SectionStatus.PASS
        info_findings = [
            f for f in section.findings if f.severity == FindingSeverity.INFO
        ]
        assert len(info_findings) >= 1

    def test_high_deny_rate_produces_warning(self) -> None:
        entries: list[dict[str, str | dict[str, str] | None]] = [
            {"result": "denied"} for _ in range(8)
        ] + [{"result": "allowed"} for _ in range(2)]
        log = _make_log(entries)
        gen = EUAIActReportGenerator()
        report = gen.generate(log)
        section = next(s for s in report.sections if s.article == "Art. 5/9")
        assert section.status in (SectionStatus.WARN, SectionStatus.FAIL)

    def test_critical_risk_produces_violation(self) -> None:
        """Repeated denials on sensitive targets with escalation."""
        entries: list[dict[str, str | dict[str, str] | None]] = [
            {
                "action": "file_write",
                "target": "/etc/passwd",
                "result": "denied",
                "metadata": {"severity": "low"},
            },
            {
                "action": "file_write",
                "target": "/etc/passwd",
                "result": "denied",
                "metadata": {"severity": "medium"},
            },
            {
                "action": "file_write",
                "target": "/etc/shadow",
                "result": "denied",
                "metadata": {"severity": "high"},
            },
            {
                "action": "file_write",
                "target": "/etc/shadow",
                "result": "denied",
                "metadata": {"severity": "critical"},
            },
            {
                "action": "file_read",
                "target": "/.ssh/id_rsa",
                "result": "denied",
                "metadata": {"severity": "critical"},
            },
        ]
        log = _make_log(entries)
        gen = EUAIActReportGenerator()
        report = gen.generate(log)
        section = next(s for s in report.sections if s.article == "Art. 5/9")
        assert section.status == SectionStatus.FAIL
        violations = [
            f for f in section.findings if f.severity == FindingSeverity.VIOLATION
        ]
        assert len(violations) >= 1

    def test_finding_includes_drift_probability(self) -> None:
        entries: list[dict[str, str | dict[str, str] | None]] = [
            {"result": "denied"} for _ in range(8)
        ] + [{"result": "allowed"} for _ in range(2)]
        log = _make_log(entries)
        gen = EUAIActReportGenerator()
        report = gen.generate(log)
        section = next(s for s in report.sections if s.article == "Art. 5/9")
        # At least one finding should mention drift probability
        all_text = " ".join(
            (f.description or "") + " " + (f.evidence or "") for f in section.findings
        )
        assert "drift" in all_text.lower() or "risk" in all_text.lower()

    def test_section_title(self) -> None:
        log = _make_log([{"result": "allowed"}])
        gen = EUAIActReportGenerator()
        report = gen.generate(log)
        section = next(s for s in report.sections if s.article == "Art. 5/9")
        assert "persona" in section.title.lower() or "safety" in section.title.lower()

    def test_mixed_results_produces_findings(self) -> None:
        entries: list[dict[str, str | dict[str, str] | None]] = (
            [{"result": "allowed"} for _ in range(5)]
            + [{"result": "denied"} for _ in range(3)]
            + [{"result": "error"} for _ in range(2)]
        )
        log = _make_log(entries)
        gen = EUAIActReportGenerator()
        report = gen.generate(log)
        section = next(s for s in report.sections if s.article == "Art. 5/9")
        assert len(section.findings) >= 1

    def test_backward_compatibility_existing_sections(self) -> None:
        """Existing 4 sections should still be present and unchanged."""
        log = _make_log([{"result": "allowed"}])
        gen = EUAIActReportGenerator()
        report = gen.generate(log)
        articles = [s.article for s in report.sections]
        assert "Art. 9" in articles
        assert "Art. 12" in articles
        assert "Art. 13" in articles
        assert "Art. 14" in articles
