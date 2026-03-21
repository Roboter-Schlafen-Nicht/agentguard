"""ISO 42001 (AI Management System) compliance report generator.

Analyzes an AuditLog and produces a ComplianceReport assessing
compliance with key ISO 42001 clauses:

- Clause 5:   Leadership — AI governance oversight
- Clause 6.1: Risk Assessment — risk identification and controls
- Clause 8.4: AI System Impact Assessment — action diversity and coverage
- Clause 9.1: Monitoring — audit log completeness and integrity
- Clause 9.2: Internal Audit — verification of audit records
- Clause 10:  Improvement — error patterns and corrective evidence
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

# Threshold: error rate above this fraction triggers FAIL in Clause 10.
_ERROR_RATE_FAIL_THRESHOLD = 0.5


class ISO42001ReportGenerator:
    """Generate ISO 42001 compliance reports from audit logs.

    Analyzes an AuditLog against six clauses of ISO/IEC 42001:2023
    (AI Management System) that are most relevant to autonomous AI
    agent governance:

    - Clause 5: Leadership (governance diversity)
    - Clause 6.1: Risk Assessment (risk controls)
    - Clause 8.4: AI System Impact Assessment (action coverage)
    - Clause 9.1: Monitoring (logging completeness and integrity)
    - Clause 9.2: Internal Audit (verification status)
    - Clause 10: Improvement (error patterns)

    Usage::

        from agentguard.audit.log import AuditLog
        from agentguard.compliance.iso_42001 import ISO42001ReportGenerator

        log = AuditLog.load("audit.jsonl", session_id="s1")
        generator = ISO42001ReportGenerator()
        report = generator.generate(log)
        print(report.overall_status())
    """

    def generate(self, audit_log: AuditLog) -> ComplianceReport:
        """Generate a compliance report from an audit log.

        Args:
            audit_log: The audit log to analyze.

        Returns:
            A ComplianceReport with sections for each assessed clause.
        """
        sections = [
            self._assess_clause5(audit_log),
            self._assess_clause61(audit_log),
            self._assess_clause84(audit_log),
            self._assess_clause91(audit_log),
            self._assess_clause92(audit_log),
            self._assess_clause10(audit_log),
        ]

        return ComplianceReport(
            framework="ISO 42001",
            generated_at=datetime.now(tz=timezone.utc),
            session_id=audit_log.session_id,
            sections=sections,
        )

    # -- Clause 5: Leadership -------------------------------------------

    def _assess_clause5(self, audit_log: AuditLog) -> ReportSection:
        """Assess Clause 5: Leadership.

        Checks for evidence of AI governance oversight by examining
        actor diversity.  Multiple distinct actors suggest a governance
        structure; a single actor suggests limited oversight.
        """
        entries = audit_log.entries
        findings: list[Finding] = []

        if not entries:
            return ReportSection(
                article="Clause 5",
                title="Leadership",
                status=SectionStatus.NOT_ASSESSED,
                findings=[
                    Finding(
                        severity=FindingSeverity.INFO,
                        article="Clause 5",
                        description=(
                            "No actions recorded; governance assessment not possible"
                        ),
                    ),
                ],
            )

        unique_actors = {e.actor for e in entries if e.actor.strip()}

        findings.append(
            Finding(
                severity=FindingSeverity.INFO,
                article="Clause 5",
                description="AI system actors identified",
                evidence=(
                    f"{len(unique_actors)} unique actor(s): "
                    f"{', '.join(sorted(unique_actors))}"
                ),
            )
        )

        if len(unique_actors) <= 1:
            findings.append(
                Finding(
                    severity=FindingSeverity.WARNING,
                    article="Clause 5",
                    description=(
                        "Only one actor identified; "
                        "consider establishing multi-party governance"
                    ),
                    evidence=(
                        f"{len(unique_actors)} unique actor(s) across "
                        f"{len(entries)} action(s)"
                    ),
                )
            )
            status = SectionStatus.WARN
        else:
            status = SectionStatus.PASS

        return ReportSection(
            article="Clause 5",
            title="Leadership",
            status=status,
            findings=findings,
        )

    # -- Clause 6.1: Risk Assessment -----------------------------------

    def _assess_clause61(self, audit_log: AuditLog) -> ReportSection:
        """Assess Clause 6.1: Risk Assessment.

        Checks for evidence of risk identification and controls:
        - Denied actions indicate active risk controls (good)
        - Errors indicate risk control gaps
        """
        entries = audit_log.entries
        findings: list[Finding] = []

        if not entries:
            return ReportSection(
                article="Clause 6.1",
                title="Risk Assessment",
                status=SectionStatus.NOT_ASSESSED,
                findings=[
                    Finding(
                        severity=FindingSeverity.INFO,
                        article="Clause 6.1",
                        description=(
                            "No actions recorded; risk assessment not possible"
                        ),
                    ),
                ],
            )

        denied_count = sum(1 for e in entries if e.result == "denied")
        error_count = sum(1 for e in entries if e.result == "error")
        total = len(entries)

        if denied_count > 0:
            findings.append(
                Finding(
                    severity=FindingSeverity.INFO,
                    article="Clause 6.1",
                    description="Risk controls actively blocking unsafe actions",
                    evidence=f"{denied_count} of {total} actions denied by policy",
                )
            )

        if error_count > 0:
            findings.append(
                Finding(
                    severity=FindingSeverity.WARNING,
                    article="Clause 6.1",
                    description="Actions resulted in errors, indicating risk gaps",
                    evidence=f"{error_count} of {total} actions resulted in errors",
                )
            )

        if denied_count == 0 and error_count == 0:
            findings.append(
                Finding(
                    severity=FindingSeverity.INFO,
                    article="Clause 6.1",
                    description="All actions executed successfully",
                    evidence=f"{total} actions, all allowed, no errors",
                )
            )

        status = SectionStatus.WARN if error_count > 0 else SectionStatus.PASS

        return ReportSection(
            article="Clause 6.1",
            title="Risk Assessment",
            status=status,
            findings=findings,
        )

    # -- Clause 8.4: AI System Impact Assessment -----------------------

    def _assess_clause84(self, audit_log: AuditLog) -> ReportSection:
        """Assess Clause 8.4: AI System Impact Assessment.

        Checks action diversity as a proxy for monitoring coverage.
        A wider variety of action types suggests broader impact
        assessment scope.
        """
        entries = audit_log.entries
        findings: list[Finding] = []

        if not entries:
            return ReportSection(
                article="Clause 8.4",
                title="AI System Impact Assessment",
                status=SectionStatus.NOT_ASSESSED,
                findings=[
                    Finding(
                        severity=FindingSeverity.INFO,
                        article="Clause 8.4",
                        description=(
                            "No actions recorded; impact assessment not possible"
                        ),
                    ),
                ],
            )

        unique_actions = {e.action for e in entries}

        findings.append(
            Finding(
                severity=FindingSeverity.INFO,
                article="Clause 8.4",
                description="Action types monitored by the AI system",
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
                    article="Clause 8.4",
                    description=(
                        "Only one action type recorded; "
                        "impact assessment scope may be limited"
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
            article="Clause 8.4",
            title="AI System Impact Assessment",
            status=status,
            findings=findings,
        )

    # -- Clause 9.1: Monitoring ----------------------------------------

    def _assess_clause91(self, audit_log: AuditLog) -> ReportSection:
        """Assess Clause 9.1: Monitoring.

        Checks audit log completeness and integrity:
        - Log must have entries (monitoring is active)
        - Hash chain integrity must be intact
        """
        entries = audit_log.entries
        findings: list[Finding] = []

        if not entries:
            return ReportSection(
                article="Clause 9.1",
                title="Monitoring",
                status=SectionStatus.FAIL,
                findings=[
                    Finding(
                        severity=FindingSeverity.VIOLATION,
                        article="Clause 9.1",
                        description=(
                            "No monitoring data recorded; "
                            "Clause 9.1 requires performance monitoring"
                        ),
                        evidence="0 entries in audit log",
                    ),
                ],
            )

        findings.append(
            Finding(
                severity=FindingSeverity.INFO,
                article="Clause 9.1",
                description="Monitoring data is being collected",
                evidence=f"{len(entries)} entries recorded in session",
            )
        )

        if audit_log.verify():
            findings.append(
                Finding(
                    severity=FindingSeverity.INFO,
                    article="Clause 9.1",
                    description="Monitoring data integrity verified",
                )
            )
            status = SectionStatus.PASS
        else:
            findings.append(
                Finding(
                    severity=FindingSeverity.VIOLATION,
                    article="Clause 9.1",
                    description=(
                        "Monitoring data integrity check failed; "
                        "hash chain has been tampered with"
                    ),
                    evidence="AuditLog.verify() returned False",
                )
            )
            status = SectionStatus.FAIL

        return ReportSection(
            article="Clause 9.1",
            title="Monitoring",
            status=status,
            findings=findings,
        )

    # -- Clause 9.2: Internal Audit ------------------------------------

    def _assess_clause92(self, audit_log: AuditLog) -> ReportSection:
        """Assess Clause 9.2: Internal Audit.

        Checks that audit records are verifiable and intact.
        """
        entries = audit_log.entries
        findings: list[Finding] = []

        if not entries:
            return ReportSection(
                article="Clause 9.2",
                title="Internal Audit",
                status=SectionStatus.NOT_ASSESSED,
                findings=[
                    Finding(
                        severity=FindingSeverity.INFO,
                        article="Clause 9.2",
                        description=(
                            "No audit records to verify; internal audit not possible"
                        ),
                    ),
                ],
            )

        if audit_log.verify():
            findings.append(
                Finding(
                    severity=FindingSeverity.INFO,
                    article="Clause 9.2",
                    description=("Audit records verified; hash chain is intact"),
                    evidence=f"{len(entries)} entries verified",
                )
            )
            status = SectionStatus.PASS
        else:
            findings.append(
                Finding(
                    severity=FindingSeverity.VIOLATION,
                    article="Clause 9.2",
                    description=(
                        "Internal audit failed; audit record integrity compromised"
                    ),
                    evidence="AuditLog.verify() returned False",
                )
            )
            status = SectionStatus.FAIL

        return ReportSection(
            article="Clause 9.2",
            title="Internal Audit",
            status=status,
            findings=findings,
        )

    # -- Clause 10: Improvement ----------------------------------------

    def _assess_clause10(self, audit_log: AuditLog) -> ReportSection:
        """Assess Clause 10: Improvement.

        Checks for error patterns and corrective evidence:
        - High error rate indicates systemic issues (FAIL)
        - Some errors indicate need for improvement (WARN)
        - Denied actions are positive evidence of corrective controls
        """
        entries = audit_log.entries
        findings: list[Finding] = []

        if not entries:
            return ReportSection(
                article="Clause 10",
                title="Improvement",
                status=SectionStatus.NOT_ASSESSED,
                findings=[
                    Finding(
                        severity=FindingSeverity.INFO,
                        article="Clause 10",
                        description=(
                            "No actions recorded; improvement assessment not possible"
                        ),
                    ),
                ],
            )

        error_count = sum(1 for e in entries if e.result == "error")
        denied_count = sum(1 for e in entries if e.result == "denied")
        total = len(entries)
        error_rate = error_count / total

        if denied_count > 0:
            findings.append(
                Finding(
                    severity=FindingSeverity.INFO,
                    article="Clause 10",
                    description=(
                        "Corrective controls active; "
                        "policy enforcement blocking unsafe actions"
                    ),
                    evidence=(f"{denied_count} action(s) denied by policy"),
                )
            )

        if error_rate >= _ERROR_RATE_FAIL_THRESHOLD:
            findings.append(
                Finding(
                    severity=FindingSeverity.VIOLATION,
                    article="Clause 10",
                    description=(
                        "High error rate indicates systemic issues "
                        "requiring corrective action"
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
                    article="Clause 10",
                    description="Errors detected; review for improvement opportunities",
                    evidence=(f"{error_count} of {total} actions resulted in errors"),
                )
            )
            status = SectionStatus.WARN
        else:
            findings.append(
                Finding(
                    severity=FindingSeverity.INFO,
                    article="Clause 10",
                    description="No errors detected in recorded actions",
                    evidence=f"{total} actions completed without errors",
                )
            )
            status = SectionStatus.PASS

        return ReportSection(
            article="Clause 10",
            title="Improvement",
            status=status,
            findings=findings,
        )
