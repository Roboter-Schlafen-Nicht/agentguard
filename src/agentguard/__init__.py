"""AgentGuard -- Safety and audit framework for autonomous AI agents."""

from agentguard.audit.log import AuditLog
from agentguard.compliance.eu_ai_act import EUAIActReportGenerator
from agentguard.compliance.models import ComplianceReport
from agentguard.guardrails.guardrail import ExecutionResult, Guardrail
from agentguard.guardrails.models import ActionResult
from agentguard.policies.guard import Guard
from agentguard.policies.presets import Preset, load_preset
from agentguard.scanner.engine import Scanner
from agentguard.scanner.models import Finding, RiskCategory, ScanResult, Severity
from agentguard.trust.models import TrustEntry, TrustLevel
from agentguard.trust.registry import TrustRegistry

__version__ = "0.2.0"

__all__ = [
    "ActionResult",
    "AuditLog",
    "ComplianceReport",
    "EUAIActReportGenerator",
    "ExecutionResult",
    "Finding",
    "Guard",
    "Guardrail",
    "Preset",
    "RiskCategory",
    "ScanResult",
    "Scanner",
    "Severity",
    "TrustEntry",
    "TrustLevel",
    "TrustRegistry",
    "__version__",
    "load_preset",
]
