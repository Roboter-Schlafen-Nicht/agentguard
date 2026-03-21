"""EU AI Act compliance report generator.

Analyzes an AuditLog and produces a ComplianceReport assessing
compliance with key EU AI Act articles:

- Art. 9:  Risk Management
- Art. 12: Logging
- Art. 13: Transparency
- Art. 14: Human Oversight
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


class EUAIActReportGenerator:
    """Generate EU AI Act compliance reports from audit logs.

    Analyzes an AuditLog against four key articles of the EU AI Act
    (Regulation 2024/1689) that are most relevant to autonomous AI
    agents:

    - Art. 9: Risk management (are risks being detected and mitigated?)
    - Art. 12: Logging (are agent actions being recorded?)
    - Art. 13: Transparency (are agents identifiable?)
    - Art. 14: Human oversight (is there evidence of oversight?)

    Usage::

        from agentguard.audit.log import AuditLog
        from agentguard.compliance.eu_ai_act import EUAIActReportGenerator

        log = AuditLog.load("audit.jsonl", session_id="s1")
        generator = EUAIActReportGenerator()
        report = generator.generate(log)
        print(report.overall_status())
    """

    def generate(self, audit_log: AuditLog) -> ComplianceReport:
        """Generate a compliance report from an audit log.

        Args:
            audit_log: The audit log to analyze.

        Returns:
            A ComplianceReport with sections for each assessed article.
        """
        sections = [
            self._assess_art9(audit_log),
            self._assess_art12(audit_log),
            self._assess_art13(audit_log),
            self._assess_art14(audit_log),
            self._assess_persona_safety(audit_log),
        ]

        return ComplianceReport(
            framework="EU AI Act",
            generated_at=datetime.now(tz=timezone.utc),
            session_id=audit_log.session_id,
            sections=sections,
        )

    def _assess_art9(self, audit_log: AuditLog) -> ReportSection:
        """Assess Art. 9: Risk Management.

        Checks whether the system is detecting and mitigating risks:
        - Denied actions indicate active risk mitigation (good)
        - Error results indicate potential risk management issues
        - No entries means not enough data to assess
        """
        entries = audit_log.entries
        findings: list[Finding] = []

        if not entries:
            return ReportSection(
                article="Art. 9",
                title="Risk Management",
                status=SectionStatus.NOT_ASSESSED,
                findings=[
                    Finding(
                        severity=FindingSeverity.INFO,
                        article="Art. 9",
                        description="No actions recorded; risk assessment not possible",
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
                    article="Art. 9",
                    description=("Policy guardrails actively blocking risky actions"),
                    evidence=(f"{denied_count} of {total} actions denied by policy"),
                )
            )

        if error_count > 0:
            findings.append(
                Finding(
                    severity=FindingSeverity.WARNING,
                    article="Art. 9",
                    description="Actions resulted in errors during execution",
                    evidence=f"{error_count} of {total} actions resulted in errors",
                )
            )

        if denied_count == 0 and error_count == 0:
            findings.append(
                Finding(
                    severity=FindingSeverity.INFO,
                    article="Art. 9",
                    description="All actions executed successfully",
                    evidence=f"{total} actions, all allowed, no errors",
                )
            )

        status = SectionStatus.WARN if error_count > 0 else SectionStatus.PASS

        return ReportSection(
            article="Art. 9",
            title="Risk Management",
            status=status,
            findings=findings,
        )

    def _assess_art12(self, audit_log: AuditLog) -> ReportSection:
        """Assess Art. 12: Logging.

        Checks:
        - Audit log has entries (logging is active)
        - Hash chain integrity is intact (tamper-evident)
        """
        entries = audit_log.entries
        findings: list[Finding] = []

        if not entries:
            return ReportSection(
                article="Art. 12",
                title="Logging",
                status=SectionStatus.FAIL,
                findings=[
                    Finding(
                        severity=FindingSeverity.VIOLATION,
                        article="Art. 12",
                        description=(
                            "No audit entries recorded; "
                            "Art. 12 requires automatic logging of events"
                        ),
                        evidence="0 entries in audit log",
                    ),
                ],
            )

        # Log has entries — check integrity
        findings.append(
            Finding(
                severity=FindingSeverity.INFO,
                article="Art. 12",
                description="Audit logging is active",
                evidence=f"{len(entries)} entries recorded in session",
            )
        )

        # Verify hash chain integrity
        if audit_log.verify():
            findings.append(
                Finding(
                    severity=FindingSeverity.INFO,
                    article="Art. 12",
                    description="Hash chain integrity verified",
                )
            )
            status = SectionStatus.PASS
        else:
            findings.append(
                Finding(
                    severity=FindingSeverity.VIOLATION,
                    article="Art. 12",
                    description=(
                        "Audit log integrity check failed; "
                        "hash chain has been tampered with"
                    ),
                    evidence="AuditLog.verify() returned False",
                )
            )
            status = SectionStatus.FAIL

        return ReportSection(
            article="Art. 12",
            title="Logging",
            status=status,
            findings=findings,
        )

    def _assess_art13(self, audit_log: AuditLog) -> ReportSection:
        """Assess Art. 13: Transparency.

        Checks that actions are attributed to identified actors.
        """
        entries = audit_log.entries
        findings: list[Finding] = []

        if not entries:
            return ReportSection(
                article="Art. 13",
                title="Transparency",
                status=SectionStatus.NOT_ASSESSED,
                findings=[
                    Finding(
                        severity=FindingSeverity.INFO,
                        article="Art. 13",
                        description=(
                            "No actions recorded; transparency assessment not possible"
                        ),
                    ),
                ],
            )

        unique_actors = {e.actor for e in entries}

        # Check for unidentified (empty or blank) actors
        unidentified = {a for a in unique_actors if not a.strip()}
        identified = unique_actors - unidentified

        if unidentified:
            unidentified_count = sum(1 for e in entries if not e.actor.strip())
            findings.append(
                Finding(
                    severity=FindingSeverity.WARNING,
                    article="Art. 13",
                    description=("Some actions attributed to unidentified actors"),
                    evidence=(
                        f"{unidentified_count} action(s) have empty or "
                        f"blank actor identifiers"
                    ),
                )
            )
            status = SectionStatus.WARN
        else:
            status = SectionStatus.PASS

        if identified:
            findings.append(
                Finding(
                    severity=FindingSeverity.INFO,
                    article="Art. 13",
                    description="Actions attributed to identified actors",
                    evidence=(
                        f"{len(identified)} unique actor(s): "
                        f"{', '.join(sorted(identified))}"
                    ),
                )
            )

        return ReportSection(
            article="Art. 13",
            title="Transparency",
            status=status,
            findings=findings,
        )

    def _assess_art14(self, audit_log: AuditLog) -> ReportSection:
        """Assess Art. 14: Human Oversight.

        Checks for evidence of oversight mechanisms:
        - Denied actions indicate guardrails are active (automated oversight)
        - Without denied actions, there's no evidence of active oversight
        """
        entries = audit_log.entries
        findings: list[Finding] = []

        if not entries:
            return ReportSection(
                article="Art. 14",
                title="Human Oversight",
                status=SectionStatus.NOT_ASSESSED,
                findings=[
                    Finding(
                        severity=FindingSeverity.INFO,
                        article="Art. 14",
                        description=(
                            "No actions recorded; oversight assessment not possible"
                        ),
                    ),
                ],
            )

        denied_count = sum(1 for e in entries if e.result == "denied")

        if denied_count > 0:
            findings.append(
                Finding(
                    severity=FindingSeverity.INFO,
                    article="Art. 14",
                    description=(
                        "Policy guardrails actively enforcing oversight rules"
                    ),
                    evidence=(
                        f"{denied_count} action(s) blocked by policy enforcement"
                    ),
                )
            )

        findings.append(
            Finding(
                severity=FindingSeverity.WARNING,
                article="Art. 14",
                description=(
                    "No explicit human-in-the-loop evidence detected; "
                    "consider adding human approval workflows for "
                    "high-risk actions"
                ),
            )
        )

        # Without explicit human oversight evidence, warn
        status = SectionStatus.WARN

        return ReportSection(
            article="Art. 14",
            title="Human Oversight",
            status=status,
            findings=findings,
        )

    def _assess_persona_safety(
        self,
        audit_log: AuditLog,
    ) -> ReportSection:
        """Assess persona safety and behavioral drift.

        Evaluates whether the AI agent's behavior stays within
        expected boundaries, using heuristic risk scoring to
        detect behavioral drift patterns that may indicate the
        agent is operating outside its intended persona or role.

        Maps to EU AI Act Art. 5 (prohibited practices) and Art. 9
        (risk management) — ensuring the AI system does not exhibit
        manipulative, deceptive, or uncontrolled behavior.

        Args:
            audit_log: The audit log to analyze.

        Returns:
            A ReportSection with persona safety findings.
        """
        from agentguard.audit.risk import (
            ConversationRiskScorer,
            RiskLevel,
        )

        entries = audit_log.entries

        if not entries:
            return ReportSection(
                article="Art. 5/9",
                title="Persona Safety",
                status=SectionStatus.NOT_ASSESSED,
                findings=[
                    Finding(
                        severity=FindingSeverity.INFO,
                        article="Art. 5/9",
                        description=(
                            "No audit entries available for persona safety assessment."
                        ),
                    ),
                ],
            )

        scorer = ConversationRiskScorer()
        risk_score = scorer.score(entries)

        findings: list[Finding] = []

        # Always report the drift probability
        findings.append(
            Finding(
                severity=FindingSeverity.INFO,
                article="Art. 5/9",
                description=(
                    f"Behavioral drift probability: "
                    f"{risk_score.probability:.2f} "
                    f"(risk level: {risk_score.level.value})"
                ),
                evidence=(
                    f"Analyzed {len(entries)} audit entries. "
                    f"Detected {len(risk_score.signals)} risk signal(s)."
                ),
            ),
        )

        # Report individual signals
        for signal in risk_score.signals:
            findings.append(
                Finding(
                    severity=FindingSeverity.INFO,
                    article="Art. 5/9",
                    description=(f"Risk signal: {signal.signal_type.value}"),
                    evidence=signal.description,
                ),
            )

        # Determine status and add severity-appropriate findings
        if risk_score.level == RiskLevel.CRITICAL:
            status = SectionStatus.FAIL
            findings.append(
                Finding(
                    severity=FindingSeverity.VIOLATION,
                    article="Art. 5/9",
                    description=(
                        "Critical behavioral drift detected. "
                        "Agent may be operating outside intended "
                        "persona boundaries."
                    ),
                    evidence=(
                        f"Drift probability {risk_score.probability:.2f} "
                        f"exceeds critical threshold (0.75)."
                    ),
                ),
            )
        elif risk_score.level == RiskLevel.HIGH:
            status = SectionStatus.FAIL
            findings.append(
                Finding(
                    severity=FindingSeverity.VIOLATION,
                    article="Art. 5/9",
                    description=(
                        "High behavioral drift detected. "
                        "Agent actions show significant deviation "
                        "from expected patterns."
                    ),
                    evidence=(
                        f"Drift probability {risk_score.probability:.2f} "
                        f"exceeds high threshold (0.50)."
                    ),
                ),
            )
        elif risk_score.level == RiskLevel.MEDIUM:
            status = SectionStatus.WARN
            findings.append(
                Finding(
                    severity=FindingSeverity.WARNING,
                    article="Art. 5/9",
                    description=(
                        "Moderate behavioral drift detected. "
                        "Some agent actions deviate from expected "
                        "patterns."
                    ),
                    evidence=(
                        f"Drift probability {risk_score.probability:.2f} "
                        f"exceeds medium threshold (0.25)."
                    ),
                ),
            )
        else:
            status = SectionStatus.PASS

        return ReportSection(
            article="Art. 5/9",
            title="Persona Safety",
            status=status,
            findings=findings,
        )
