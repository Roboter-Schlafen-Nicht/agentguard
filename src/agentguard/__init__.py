"""AgentGuard -- Safety and audit framework for autonomous AI agents."""

from agentguard.audit.log import AuditLog
from agentguard.compliance.eu_ai_act import EUAIActReportGenerator
from agentguard.compliance.models import ComplianceReport
from agentguard.guardrails.guardrail import ExecutionResult, Guardrail
from agentguard.guardrails.models import ActionResult
from agentguard.policies.guard import Guard

__version__ = "0.1.0"

__all__ = [
    "ActionResult",
    "AuditLog",
    "ComplianceReport",
    "EUAIActReportGenerator",
    "ExecutionResult",
    "Guard",
    "Guardrail",
    "__version__",
]
