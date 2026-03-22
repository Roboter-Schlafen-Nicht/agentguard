"""Policy engine for defining and enforcing agent behavior rules."""

from agentguard.policies.approval import (
    ApprovalManager,
    ApprovalPolicy,
    ApprovalRequest,
    ApprovalStatus,
)
from agentguard.policies.builtins import list_builtins, load_all_builtins, load_builtin
from agentguard.policies.discovery import auto_discover, discover_policies
from agentguard.policies.domain_allowlist import PRESETS as DOMAIN_PRESETS
from agentguard.policies.domain_allowlist import DomainAllowlist
from agentguard.policies.fs_allowlist import FS_PRESETS, FilesystemAllowlist
from agentguard.policies.guard import DenyHandler, Guard
from agentguard.policies.handlers import EmailHandler, SlackHandler, WebhookHandler
from agentguard.policies.loader import load_policy_from_string, load_policy_from_yaml
from agentguard.policies.models import (
    Action,
    ChangelogEntry,
    Condition,
    Context,
    Decision,
    Policy,
    Rule,
    Severity,
)
from agentguard.policies.watcher import PolicyWatcher, ReloadCallback

__all__ = [
    "DOMAIN_PRESETS",
    "FS_PRESETS",
    "Action",
    "ApprovalManager",
    "ApprovalPolicy",
    "ApprovalRequest",
    "ApprovalStatus",
    "ChangelogEntry",
    "Condition",
    "Context",
    "Decision",
    "DenyHandler",
    "DomainAllowlist",
    "EmailHandler",
    "FilesystemAllowlist",
    "Guard",
    "Policy",
    "PolicyWatcher",
    "ReloadCallback",
    "Rule",
    "Severity",
    "SlackHandler",
    "WebhookHandler",
    "auto_discover",
    "discover_policies",
    "list_builtins",
    "load_all_builtins",
    "load_builtin",
    "load_policy_from_string",
    "load_policy_from_yaml",
]
