"""NIST AI Risk Management Framework (AI RMF 1.0) compliance report generator.

Analyzes an AuditLog and produces a ComplianceReport assessing
compliance with key NIST AI RMF functions and subcategories:

- GOVERN 1:  Governance — policies and oversight
- MAP 1:     Context — AI system context and scope mapping
- MEASURE 2: Assessment — risk measurement metrics
- MANAGE 1:  Risk Response — active risk mitigation
- MANAGE 2:  Monitoring — ongoing monitoring and integrity
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

# Threshold: error rate above this fraction triggers FAIL in MEASURE 2.
_ERROR_RATE_FAIL_THRESHOLD = 0.5


class NISTAIRMFReportGenerator:
    """Generate NIST AI RMF compliance reports from audit logs.

    Analyzes an AuditLog against five subcategories of the NIST AI
    Risk Management Framework (AI RMF 1.0) that are most relevant
    to autonomous AI agent governance:

    - GOVERN 1: Policies and oversight (actor diversity, policy enforcement)
    - MAP 1: Context mapping (action type diversity, scope coverage)
    - MEASURE 2: Risk measurement (error rates, denial rates)
    - MANAGE 1: Risk response (denied actions as risk management)
    - MANAGE 2: Monitoring (log integrity, completeness)

    Usage::

        from agentguard.audit.log import AuditLog
        from agentguard.compliance.nist_ai_rmf import NISTAIRMFReportGenerator

        log = AuditLog.load("audit.jsonl", session_id="s1")
        generator = NISTAIRMFReportGenerator()
        report = generator.generate(log)
        print(report.overall_status())
    """

    def generate(self, audit_log: AuditLog) -> ComplianceReport:
        """Generate a compliance report from an audit log.

        Args:
            audit_log: The audit log to analyze.

        Returns:
            A ComplianceReport with sections for each assessed function.
        """
        sections = [
            self._assess_govern1(audit_log),
            self._assess_map1(audit_log),
            self._assess_measure2(audit_log),
            self._assess_manage1(audit_log),
            self._assess_manage2(audit_log),
        ]

        return ComplianceReport(
            framework="NIST AI RMF",
            generated_at=datetime.now(tz=timezone.utc),
            session_id=audit_log.session_id,
            sections=sections,
        )

    # -- GOVERN 1: Governance ------------------------------------------

    def _assess_govern1(self, audit_log: AuditLog) -> ReportSection:
        """Assess GOVERN 1: Policies and oversight.

        Checks for governance evidence:
        - Multiple distinct actors suggest oversight structure
        - Policy denials indicate active governance
        - Single actor with no denials suggests weak governance
        """
        entries = audit_log.entries
        findings: list[Finding] = []

        if not entries:
            return ReportSection(
                article="GOVERN 1",
                title="Governance",
                status=SectionStatus.NOT_ASSESSED,
                findings=[
                    Finding(
                        severity=FindingSeverity.INFO,
                        article="GOVERN 1",
                        description=(
                            "No actions recorded; governance assessment not possible"
                        ),
                    ),
                ],
            )

        unique_actors = {e.actor for e in entries if e.actor.strip()}
        denied_count = sum(1 for e in entries if e.result == "denied")
        total = len(entries)

        if denied_count > 0:
            findings.append(
                Finding(
                    severity=FindingSeverity.INFO,
                    article="GOVERN 1",
                    description="Policy enforcement active",
                    evidence=(f"{denied_count} of {total} actions denied by policy"),
                )
            )

        if unique_actors:
            findings.append(
                Finding(
                    severity=FindingSeverity.INFO,
                    article="GOVERN 1",
                    description="Actors participating in AI system governance",
                    evidence=(
                        f"{len(unique_actors)} unique actor(s): "
                        f"{', '.join(sorted(unique_actors))}"
                    ),
                )
            )

        has_governance = len(unique_actors) > 1 or denied_count > 0

        if not has_governance:
            findings.append(
                Finding(
                    severity=FindingSeverity.WARNING,
                    article="GOVERN 1",
                    description=(
                        "Limited governance evidence; "
                        "consider multi-party oversight and policy enforcement"
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
            article="GOVERN 1",
            title="Governance",
            status=status,
            findings=findings,
        )

    # -- MAP 1: Context ------------------------------------------------

    def _assess_map1(self, audit_log: AuditLog) -> ReportSection:
        """Assess MAP 1: AI system context and scope mapping.

        Checks action diversity as a proxy for how well the AI
        system's operational context has been mapped and monitored.
        """
        entries = audit_log.entries
        findings: list[Finding] = []

        if not entries:
            return ReportSection(
                article="MAP 1",
                title="Context",
                status=SectionStatus.NOT_ASSESSED,
                findings=[
                    Finding(
                        severity=FindingSeverity.INFO,
                        article="MAP 1",
                        description=(
                            "No actions recorded; context assessment not possible"
                        ),
                    ),
                ],
            )

        unique_actions = {e.action for e in entries}

        findings.append(
            Finding(
                severity=FindingSeverity.INFO,
                article="MAP 1",
                description="Action types observed in AI system context",
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
                    article="MAP 1",
                    description=(
                        "Only one action type recorded; "
                        "context mapping scope may be limited"
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
            article="MAP 1",
            title="Context",
            status=status,
            findings=findings,
        )

    # -- MEASURE 2: Assessment -----------------------------------------

    def _assess_measure2(self, audit_log: AuditLog) -> ReportSection:
        """Assess MEASURE 2: Risk measurement metrics.

        Examines error rates and denial rates as quantitative
        risk measurement data.
        """
        entries = audit_log.entries
        findings: list[Finding] = []

        if not entries:
            return ReportSection(
                article="MEASURE 2",
                title="Assessment",
                status=SectionStatus.NOT_ASSESSED,
                findings=[
                    Finding(
                        severity=FindingSeverity.INFO,
                        article="MEASURE 2",
                        description=(
                            "No actions recorded; measurement assessment not possible"
                        ),
                    ),
                ],
            )

        error_count = sum(1 for e in entries if e.result == "error")
        denied_count = sum(1 for e in entries if e.result == "denied")
        allowed_count = sum(1 for e in entries if e.result == "allowed")
        total = len(entries)
        error_rate = error_count / total

        findings.append(
            Finding(
                severity=FindingSeverity.INFO,
                article="MEASURE 2",
                description="Risk measurement metrics",
                evidence=(
                    f"{total} actions: "
                    f"{allowed_count} allowed, "
                    f"{denied_count} denied, "
                    f"{error_count} errors"
                ),
            )
        )

        if error_rate >= _ERROR_RATE_FAIL_THRESHOLD:
            findings.append(
                Finding(
                    severity=FindingSeverity.VIOLATION,
                    article="MEASURE 2",
                    description=(
                        "High error rate indicates systemic risk measurement failure"
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
                    article="MEASURE 2",
                    description=("Errors detected; review risk measurement coverage"),
                    evidence=(f"{error_count} of {total} actions resulted in errors"),
                )
            )
            status = SectionStatus.WARN
        else:
            status = SectionStatus.PASS

        return ReportSection(
            article="MEASURE 2",
            title="Assessment",
            status=status,
            findings=findings,
        )

    # -- MANAGE 1: Risk Response ---------------------------------------

    def _assess_manage1(self, audit_log: AuditLog) -> ReportSection:
        """Assess MANAGE 1: Risk response.

        Checks for evidence of active risk mitigation:
        - Denied actions indicate policy-based risk response
        - Errors suggest gaps in risk response
        - No denials may indicate absent risk response mechanisms
        """
        entries = audit_log.entries
        findings: list[Finding] = []

        if not entries:
            return ReportSection(
                article="MANAGE 1",
                title="Risk Response",
                status=SectionStatus.NOT_ASSESSED,
                findings=[
                    Finding(
                        severity=FindingSeverity.INFO,
                        article="MANAGE 1",
                        description=(
                            "No actions recorded; risk response assessment not possible"
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
                    article="MANAGE 1",
                    description=("Policy enforcement actively mitigating risks"),
                    evidence=(f"{denied_count} of {total} actions denied by policy"),
                )
            )

        if error_count > 0:
            findings.append(
                Finding(
                    severity=FindingSeverity.WARNING,
                    article="MANAGE 1",
                    description=("Errors detected; risk response may have gaps"),
                    evidence=(f"{error_count} of {total} actions resulted in errors"),
                )
            )

        if denied_count > 0:
            status = SectionStatus.PASS
        elif error_count > 0:
            status = SectionStatus.WARN
        else:
            # No denials and no errors — may indicate no risk controls
            findings.append(
                Finding(
                    severity=FindingSeverity.WARNING,
                    article="MANAGE 1",
                    description=(
                        "No policy denials observed; "
                        "risk response mechanisms may be absent"
                    ),
                    evidence=(f"{total} actions, all allowed, no denials"),
                )
            )
            status = SectionStatus.WARN

        return ReportSection(
            article="MANAGE 1",
            title="Risk Response",
            status=status,
            findings=findings,
        )

    # -- MANAGE 2: Monitoring ------------------------------------------

    def _assess_manage2(self, audit_log: AuditLog) -> ReportSection:
        """Assess MANAGE 2: Ongoing monitoring.

        Checks audit log completeness and integrity:
        - Log must have entries (monitoring is active)
        - Hash chain integrity must be intact
        """
        entries = audit_log.entries
        findings: list[Finding] = []

        if not entries:
            return ReportSection(
                article="MANAGE 2",
                title="Monitoring",
                status=SectionStatus.FAIL,
                findings=[
                    Finding(
                        severity=FindingSeverity.VIOLATION,
                        article="MANAGE 2",
                        description=(
                            "No monitoring data recorded; "
                            "MANAGE 2 requires ongoing monitoring"
                        ),
                        evidence="0 entries in audit log",
                    ),
                ],
            )

        findings.append(
            Finding(
                severity=FindingSeverity.INFO,
                article="MANAGE 2",
                description="Monitoring data is being collected",
                evidence=f"{len(entries)} entries recorded in session",
            )
        )

        if audit_log.verify():
            findings.append(
                Finding(
                    severity=FindingSeverity.INFO,
                    article="MANAGE 2",
                    description="Monitoring data integrity verified",
                )
            )
            status = SectionStatus.PASS
        else:
            findings.append(
                Finding(
                    severity=FindingSeverity.VIOLATION,
                    article="MANAGE 2",
                    description=(
                        "Monitoring data integrity check failed; "
                        "hash chain has been tampered with"
                    ),
                    evidence="AuditLog.verify() returned False",
                )
            )
            status = SectionStatus.FAIL

        return ReportSection(
            article="MANAGE 2",
            title="Monitoring",
            status=status,
            findings=findings,
        )
