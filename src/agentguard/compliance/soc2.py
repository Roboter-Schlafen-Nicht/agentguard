"""SOC 2 Trust Services Criteria compliance report generator.

Analyzes an AuditLog and produces a ComplianceReport assessing
compliance with key SOC 2 Trust Services Criteria:

- CC6.1: Logical Access — access controls and policy enforcement
- CC7.2: System Monitoring — audit log completeness and integrity
- CC8.1: Change Management — action diversity and scope coverage
- A1.2:  Availability — error patterns and system resilience
- CC4.1: Monitoring Activities — oversight and governance evidence
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from agentguard.compliance.models import (
    ComplianceReport,
    Finding,
    FindingSeverity,
    ReportSection,
    SectionStatus,
)

if TYPE_CHECKING:
    from agentguard.audit.log import AuditLog

# Threshold: error rate above this fraction triggers FAIL in A1.2.
_ERROR_RATE_FAIL_THRESHOLD = 0.5


class SOC2ReportGenerator:
    """Generate SOC 2 compliance reports from audit logs.

    Analyzes an AuditLog against five SOC 2 Trust Services Criteria
    that are most relevant to autonomous AI agent governance:

    - CC6.1: Logical Access (actor diversity, policy enforcement)
    - CC7.2: System Monitoring (log integrity, completeness)
    - CC8.1: Change Management (action type diversity)
    - A1.2: Availability (error rates, resilience)
    - CC4.1: Monitoring Activities (oversight evidence)

    Usage::

        from agentguard.audit.log import AuditLog
        from agentguard.compliance.soc2 import SOC2ReportGenerator

        log = AuditLog.load("audit.jsonl", session_id="s1")
        generator = SOC2ReportGenerator()
        report = generator.generate(log)
        print(report.overall_status())
    """

    def generate(self, audit_log: AuditLog) -> ComplianceReport:
        """Generate a compliance report from an audit log.

        Args:
            audit_log: The audit log to analyze.

        Returns:
            A ComplianceReport with sections for each assessed criterion.
        """
        sections = [
            self._assess_cc61(audit_log),
            self._assess_cc72(audit_log),
            self._assess_cc81(audit_log),
            self._assess_a12(audit_log),
            self._assess_cc41(audit_log),
        ]

        return ComplianceReport(
            framework="SOC 2",
            generated_at=datetime.now(tz=timezone.utc),
            session_id=audit_log.session_id,
            sections=sections,
        )

    # -- CC6.1: Logical Access -----------------------------------------

    def _assess_cc61(self, audit_log: AuditLog) -> ReportSection:
        """Assess CC6.1: Logical Access.

        Checks for access control evidence:
        - Multiple distinct actors suggest role-based access
        - Policy denials indicate active access controls
        - Single actor with no denials suggests weak access controls
        """
        entries = audit_log.entries
        findings: list[Finding] = []

        if not entries:
            return ReportSection(
                article="CC6.1",
                title="Logical Access",
                status=SectionStatus.NOT_ASSESSED,
                findings=[
                    Finding(
                        severity=FindingSeverity.INFO,
                        article="CC6.1",
                        description=(
                            "No actions recorded; "
                            "access control assessment not possible"
                        ),
                    ),
                ],
            )

        unique_actors = {e.actor for e in entries if e.actor.strip()}
        denied_count = sum(1 for e in entries if e.result == "denied")
        total = len(entries)

        if unique_actors:
            findings.append(
                Finding(
                    severity=FindingSeverity.INFO,
                    article="CC6.1",
                    description="Actors with logical access to the AI system",
                    evidence=(
                        f"{len(unique_actors)} unique actor(s): "
                        f"{', '.join(sorted(unique_actors))}"
                    ),
                )
            )

        if denied_count > 0:
            findings.append(
                Finding(
                    severity=FindingSeverity.INFO,
                    article="CC6.1",
                    description="Access controls actively restricting actions",
                    evidence=(f"{denied_count} of {total} actions denied by policy"),
                )
            )

        has_controls = len(unique_actors) > 1 or denied_count > 0

        if not has_controls:
            findings.append(
                Finding(
                    severity=FindingSeverity.WARNING,
                    article="CC6.1",
                    description=(
                        "Limited access control evidence; "
                        "consider role-based access and policy enforcement"
                    ),
                    evidence=(
                        f"{len(unique_actors)} actor(s), "
                        f"{denied_count} denial(s) across {total} action(s)"
                    ),
                )
            )
            status = SectionStatus.WARN
        else:
            status = SectionStatus.PASS

        return ReportSection(
            article="CC6.1",
            title="Logical Access",
            status=status,
            findings=findings,
        )

    # -- CC7.2: System Monitoring --------------------------------------

    def _assess_cc72(self, audit_log: AuditLog) -> ReportSection:
        """Assess CC7.2: System Monitoring.

        Checks audit log completeness and integrity:
        - Log must have entries (monitoring is active)
        - Hash chain integrity must be intact
        """
        entries = audit_log.entries
        findings: list[Finding] = []

        if not entries:
            return ReportSection(
                article="CC7.2",
                title="System Monitoring",
                status=SectionStatus.FAIL,
                findings=[
                    Finding(
                        severity=FindingSeverity.VIOLATION,
                        article="CC7.2",
                        description=(
                            "No monitoring data recorded; "
                            "CC7.2 requires system component monitoring"
                        ),
                        evidence="0 entries in audit log",
                    ),
                ],
            )

        findings.append(
            Finding(
                severity=FindingSeverity.INFO,
                article="CC7.2",
                description="System monitoring data is being collected",
                evidence=f"{len(entries)} entries recorded in session",
            )
        )

        if audit_log.verify():
            findings.append(
                Finding(
                    severity=FindingSeverity.INFO,
                    article="CC7.2",
                    description="Monitoring data integrity verified",
                )
            )
            status = SectionStatus.PASS
        else:
            findings.append(
                Finding(
                    severity=FindingSeverity.VIOLATION,
                    article="CC7.2",
                    description=(
                        "Monitoring data integrity check failed; "
                        "hash chain has been tampered with"
                    ),
                    evidence="AuditLog.verify() returned False",
                )
            )
            status = SectionStatus.FAIL

        return ReportSection(
            article="CC7.2",
            title="System Monitoring",
            status=status,
            findings=findings,
        )

    # -- CC8.1: Change Management --------------------------------------

    def _assess_cc81(self, audit_log: AuditLog) -> ReportSection:
        """Assess CC8.1: Change Management.

        Checks action diversity as a proxy for change management
        scope coverage.
        """
        entries = audit_log.entries
        findings: list[Finding] = []

        if not entries:
            return ReportSection(
                article="CC8.1",
                title="Change Management",
                status=SectionStatus.NOT_ASSESSED,
                findings=[
                    Finding(
                        severity=FindingSeverity.INFO,
                        article="CC8.1",
                        description=(
                            "No actions recorded; "
                            "change management assessment not possible"
                        ),
                    ),
                ],
            )

        unique_actions = {e.action for e in entries}

        findings.append(
            Finding(
                severity=FindingSeverity.INFO,
                article="CC8.1",
                description="Change types tracked by the AI system",
                evidence=(
                    f"{len(unique_actions)} distinct action type(s): "
                    f"{', '.join(sorted(unique_actions))}"
                ),
            )
        )

        if len(unique_actions) <= 1:
            findings.append(
                Finding(
                    severity=FindingSeverity.WARNING,
                    article="CC8.1",
                    description=(
                        "Only one action type recorded; "
                        "change management scope may be limited"
                    ),
                    evidence=(
                        f"{len(unique_actions)} action type across "
                        f"{len(entries)} entries"
                    ),
                )
            )
            status = SectionStatus.WARN
        else:
            status = SectionStatus.PASS

        return ReportSection(
            article="CC8.1",
            title="Change Management",
            status=status,
            findings=findings,
        )

    # -- A1.2: Availability --------------------------------------------

    def _assess_a12(self, audit_log: AuditLog) -> ReportSection:
        """Assess A1.2: Availability.

        Checks error patterns and system resilience:
        - High error rate indicates availability issues (FAIL)
        - Some errors indicate potential availability risks (WARN)
        - Denied actions are NOT availability issues (policy enforcement)
        """
        entries = audit_log.entries
        findings: list[Finding] = []

        if not entries:
            return ReportSection(
                article="A1.2",
                title="Availability",
                status=SectionStatus.NOT_ASSESSED,
                findings=[
                    Finding(
                        severity=FindingSeverity.INFO,
                        article="A1.2",
                        description=(
                            "No actions recorded; availability assessment not possible"
                        ),
                    ),
                ],
            )

        error_count = sum(1 for e in entries if e.result == "error")
        total = len(entries)
        error_rate = error_count / total

        if error_rate >= _ERROR_RATE_FAIL_THRESHOLD:
            findings.append(
                Finding(
                    severity=FindingSeverity.VIOLATION,
                    article="A1.2",
                    description=(
                        "High error rate indicates system availability issues"
                    ),
                    evidence=(
                        f"{error_count} of {total} actions resulted in errors "
                        f"({error_rate:.0%} error rate)"
                    ),
                )
            )
            status = SectionStatus.FAIL
        elif error_count > 0:
            findings.append(
                Finding(
                    severity=FindingSeverity.WARNING,
                    article="A1.2",
                    description=("Errors detected; review for availability impact"),
                    evidence=(f"{error_count} of {total} actions resulted in errors"),
                )
            )
            status = SectionStatus.WARN
        else:
            findings.append(
                Finding(
                    severity=FindingSeverity.INFO,
                    article="A1.2",
                    description="No errors detected; system availability nominal",
                    evidence=f"{total} actions completed without errors",
                )
            )
            status = SectionStatus.PASS

        return ReportSection(
            article="A1.2",
            title="Availability",
            status=status,
            findings=findings,
        )

    # -- CC4.1: Monitoring Activities ----------------------------------

    def _assess_cc41(self, audit_log: AuditLog) -> ReportSection:
        """Assess CC4.1: Monitoring Activities.

        Checks for oversight and governance evidence:
        - Multiple actors suggest multi-party oversight
        - Policy denials indicate active monitoring
        - Single actor with no denials suggests limited oversight
        """
        entries = audit_log.entries
        findings: list[Finding] = []

        if not entries:
            return ReportSection(
                article="CC4.1",
                title="Monitoring Activities",
                status=SectionStatus.NOT_ASSESSED,
                findings=[
                    Finding(
                        severity=FindingSeverity.INFO,
                        article="CC4.1",
                        description=(
                            "No actions recorded; "
                            "monitoring activities assessment not possible"
                        ),
                    ),
                ],
            )

        unique_actors = {e.actor for e in entries if e.actor.strip()}
        denied_count = sum(1 for e in entries if e.result == "denied")
        total = len(entries)

        findings.append(
            Finding(
                severity=FindingSeverity.INFO,
                article="CC4.1",
                description="Monitoring participants and policy enforcement",
                evidence=(
                    f"{len(unique_actors)} actor(s), "
                    f"{denied_count} denial(s) across {total} action(s)"
                ),
            )
        )

        has_oversight = len(unique_actors) > 1 or denied_count > 0

        if not has_oversight:
            findings.append(
                Finding(
                    severity=FindingSeverity.WARNING,
                    article="CC4.1",
                    description=(
                        "Limited oversight evidence; "
                        "consider multi-party monitoring and policy enforcement"
                    ),
                    evidence=(
                        f"{len(unique_actors)} actor(s), {denied_count} denial(s)"
                    ),
                )
            )
            status = SectionStatus.WARN
        else:
            status = SectionStatus.PASS

        return ReportSection(
            article="CC4.1",
            title="Monitoring Activities",
            status=status,
            findings=findings,
        )
