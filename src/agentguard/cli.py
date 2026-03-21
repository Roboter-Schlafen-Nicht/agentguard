"""AgentGuard CLI.

Provides command-line access to AgentGuard's core capabilities:
- check: Validate actions against policies
- audit: Inspect and verify audit logs
- report: Generate compliance reports
- policies: List and inspect available policies
- serve: Start the MCP server with policy enforcement
- version: Print the AgentGuard version

Uses only stdlib argparse (no external dependencies).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

    from agentguard.audit.log import AuditLog
    from agentguard.audit.models import AuditEntry
    from agentguard.audit.retention import RetentionConfig
    from agentguard.audit.rotation import RotationConfig
    from agentguard.policies.guard import Guard
    from agentguard.proxy.compaction.config import CompactionConfig
    from agentguard.proxy.routing.config import RoutingConfig
    from agentguard.sandbox.models import Scenario
    from agentguard.trust.registry import TrustRegistry

try:
    from agentguard.mcp.server import create_server
except ImportError:
    create_server = None  # type: ignore[assignment]

try:
    from agentguard.proxy.app import create_app as create_proxy_app
except ImportError:
    create_proxy_app = None  # type: ignore[assignment]


class _Parsers:
    """Container for parser references needed for subcommand help."""

    def __init__(self) -> None:
        self.top: argparse.ArgumentParser | None = None
        self.policies: argparse.ArgumentParser | None = None
        self.audit: argparse.ArgumentParser | None = None
        self.trust: argparse.ArgumentParser | None = None
        self.sandbox: argparse.ArgumentParser | None = None


_parsers = _Parsers()


def _build_parser() -> argparse.ArgumentParser:
    """Build the top-level argument parser with subcommands."""
    parser = argparse.ArgumentParser(
        prog="agentguard",
        description="Safety and audit framework for autonomous AI agents.",
    )
    parser.add_argument(
        "--version",
        action="store_true",
        help="Print version and exit.",
    )

    subparsers = parser.add_subparsers(dest="command")

    # --- version ---
    subparsers.add_parser("version", help="Print the AgentGuard version.")

    # --- policies ---
    policies_parser = subparsers.add_parser(
        "policies", help="List and inspect policies."
    )
    policies_sub = policies_parser.add_subparsers(dest="policies_command")

    policies_sub.add_parser("list", help="List available built-in policies.")

    show_parser = policies_sub.add_parser("show", help="Show details of a policy.")
    show_parser.add_argument("name", help="Name of the built-in policy to show.")

    # --- check ---
    check_parser = subparsers.add_parser(
        "check", help="Check an action against loaded policies."
    )
    check_parser.add_argument(
        "--builtins",
        action="store_true",
        help="Load all built-in policies.",
    )
    check_parser.add_argument(
        "--policy",
        action="append",
        default=[],
        help="Path to a policy YAML file (can be repeated).",
    )
    check_parser.add_argument(
        "--policy-dir",
        help="Directory containing policy YAML files.",
    )
    check_parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text).",
    )
    check_parser.add_argument(
        "action_kind",
        nargs="?",
        help="The action kind to check (e.g. shell_command, file_write).",
    )
    check_parser.add_argument(
        "params",
        nargs="*",
        help="Action parameters as key=value pairs.",
    )

    # --- audit ---
    audit_parser = subparsers.add_parser("audit", help="Audit log operations.")
    audit_sub = audit_parser.add_subparsers(dest="audit_command")

    # Store parser references for subcommand help display
    _parsers.top = parser
    _parsers.policies = policies_parser
    _parsers.audit = audit_parser

    # audit verify
    verify_parser = audit_sub.add_parser("verify", help="Verify audit log integrity.")
    verify_parser.add_argument("file", help="Path to the audit JSONL file.")
    verify_parser.add_argument(
        "--session", default="unknown", help="Session ID for the log."
    )

    # audit show
    show_audit_parser = audit_sub.add_parser(
        "show", help="Show all entries in an audit log."
    )
    show_audit_parser.add_argument("file", help="Path to the audit JSONL file.")
    show_audit_parser.add_argument(
        "--session", default="unknown", help="Session ID for the log."
    )
    show_audit_parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text).",
    )

    # audit query
    query_parser = audit_sub.add_parser("query", help="Query audit log entries.")
    query_parser.add_argument("file", help="Path to the audit JSONL file.")
    query_parser.add_argument(
        "--session", default="unknown", help="Session ID for the log."
    )
    query_parser.add_argument("--action", help="Filter by action type.")
    query_parser.add_argument("--actor", help="Filter by actor.")
    query_parser.add_argument("--result", help="Filter by result.")
    query_parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text).",
    )

    # audit report
    audit_report_parser = audit_sub.add_parser(
        "report", help="Generate a cross-session audit report."
    )
    audit_report_parser.add_argument(
        "directory", help="Directory containing audit JSONL files."
    )
    audit_report_parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text).",
    )
    audit_report_parser.add_argument(
        "--after",
        help="Only include entries after this ISO-8601 timestamp.",
    )
    audit_report_parser.add_argument(
        "--before",
        help="Only include entries before this ISO-8601 timestamp.",
    )

    # audit purge
    purge_parser = audit_sub.add_parser(
        "purge",
        help="Delete old audit log files based on retention policy.",
    )
    purge_parser.add_argument(
        "--audit-dir",
        required=True,
        help="Directory containing audit JSONL files.",
    )
    purge_parser.add_argument(
        "--max-log-files",
        type=int,
        default=None,
        help="Keep at most this many log files.",
    )
    purge_parser.add_argument(
        "--retain-max-age",
        type=float,
        default=None,
        help="Delete files older than this many seconds.",
    )
    purge_parser.add_argument(
        "--retain-max-bytes",
        type=int,
        default=None,
        help="Delete oldest files until total size is under this limit.",
    )
    purge_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="List files that would be deleted without deleting.",
    )

    # --- serve ---
    serve_parser = subparsers.add_parser(
        "serve", help="Start the AgentGuard MCP server."
    )

    # --- trust ---
    trust_parser = subparsers.add_parser(
        "trust", help="Manage the MCP server trust registry."
    )
    trust_sub = trust_parser.add_subparsers(dest="trust_command")

    _parsers.trust = trust_parser

    # trust add
    trust_add = trust_sub.add_parser(
        "add", help="Add or update a server in the registry."
    )
    trust_add.add_argument("name", help="Unique server name.")
    trust_add.add_argument(
        "--level",
        required=True,
        choices=["trusted", "restricted", "untrusted"],
        help="Trust level to assign.",
    )
    trust_add.add_argument(
        "--package-path",
        help="Path to the server package (computes integrity hash).",
    )
    trust_add.add_argument("--notes", help="Optional notes.")
    trust_add.add_argument(
        "--registry",
        help="Path to the trust registry YAML file.",
    )

    # trust remove
    trust_rm = trust_sub.add_parser("remove", help="Remove a server from the registry.")
    trust_rm.add_argument("name", help="Server name to remove.")
    trust_rm.add_argument(
        "--registry",
        help="Path to the trust registry YAML file.",
    )

    # trust list
    trust_ls = trust_sub.add_parser("list", help="List servers in the registry.")
    trust_ls.add_argument(
        "--level",
        choices=["trusted", "restricted", "untrusted"],
        help="Filter by trust level.",
    )
    trust_ls.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text).",
    )
    trust_ls.add_argument(
        "--registry",
        help="Path to the trust registry YAML file.",
    )

    # trust show
    trust_show = trust_sub.add_parser("show", help="Show details of a server entry.")
    trust_show.add_argument("name", help="Server name.")
    trust_show.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text).",
    )
    trust_show.add_argument(
        "--registry",
        help="Path to the trust registry YAML file.",
    )

    # trust verify
    trust_verify = trust_sub.add_parser(
        "verify", help="Verify a server package against its stored hash."
    )
    trust_verify.add_argument("name", help="Server name.")
    trust_verify.add_argument(
        "--package-path",
        required=True,
        help="Path to the server package to verify.",
    )
    trust_verify.add_argument(
        "--registry",
        help="Path to the trust registry YAML file.",
    )

    # trust update-hash
    trust_uh = trust_sub.add_parser(
        "update-hash", help="Recompute and store the hash for a server package."
    )
    trust_uh.add_argument("name", help="Server name.")
    trust_uh.add_argument(
        "--package-path",
        required=True,
        help="Path to the server package.",
    )
    trust_uh.add_argument(
        "--registry",
        help="Path to the trust registry YAML file.",
    )
    # --- sandbox ---
    sandbox_parser = subparsers.add_parser(
        "sandbox", help="Test policies against scenarios before deployment."
    )
    sandbox_sub = sandbox_parser.add_subparsers(dest="sandbox_command")

    # sandbox run
    sandbox_run = sandbox_sub.add_parser("run", help="Run scenarios against policies.")
    sandbox_run.add_argument(
        "--scenarios",
        required=True,
        help="Path to scenario YAML file or directory.",
    )
    sandbox_run.add_argument(
        "--builtins",
        action="store_true",
        help="Load all built-in policies.",
    )
    sandbox_run.add_argument(
        "--policy",
        action="append",
        default=[],
        help="Path to a policy YAML file (can be repeated).",
    )
    sandbox_run.add_argument(
        "--policy-dir",
        help="Directory containing policy YAML files.",
    )
    sandbox_run.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text).",
    )

    # sandbox gate
    sandbox_gate = sandbox_sub.add_parser(
        "gate", help="Check production readiness against thresholds."
    )
    sandbox_gate.add_argument(
        "--scenarios",
        required=True,
        help="Path to scenario YAML file or directory.",
    )
    sandbox_gate.add_argument(
        "--builtins",
        action="store_true",
        help="Load all built-in policies.",
    )
    sandbox_gate.add_argument(
        "--policy",
        action="append",
        default=[],
        help="Path to a policy YAML file (can be repeated).",
    )
    sandbox_gate.add_argument(
        "--policy-dir",
        help="Directory containing policy YAML files.",
    )
    sandbox_gate.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text).",
    )
    sandbox_gate.add_argument(
        "--min-tpr",
        type=float,
        default=0.95,
        help="Minimum true positive rate (default: 0.95).",
    )
    sandbox_gate.add_argument(
        "--max-fpr",
        type=float,
        default=0.05,
        help="Maximum false positive rate (default: 0.05).",
    )
    sandbox_gate.add_argument(
        "--min-accuracy",
        type=float,
        default=0.90,
        help="Minimum accuracy (default: 0.90).",
    )

    # sandbox report
    sandbox_report = sandbox_sub.add_parser(
        "report", help="Generate a detailed validation report (JSON)."
    )
    sandbox_report.add_argument(
        "--scenarios",
        required=True,
        help="Path to scenario YAML file or directory.",
    )
    sandbox_report.add_argument(
        "--builtins",
        action="store_true",
        help="Load all built-in policies.",
    )
    sandbox_report.add_argument(
        "--policy",
        action="append",
        default=[],
        help="Path to a policy YAML file (can be repeated).",
    )
    sandbox_report.add_argument(
        "--policy-dir",
        help="Directory containing policy YAML files.",
    )

    _parsers.sandbox = sandbox_parser

    # --- scan ---
    scan_parser = subparsers.add_parser(
        "scan", help="Scan an MCP server package for security risks."
    )
    scan_parser.add_argument(
        "path",
        help="Path to the package directory or single file to scan.",
    )
    scan_parser.add_argument(
        "--format",
        choices=["text", "json", "summary"],
        default="text",
        help="Output format (default: text).",
    )
    scan_parser.add_argument(
        "--min-severity",
        choices=["critical", "high", "medium", "low", "info"],
        default=None,
        help="Only show findings at or above this severity.",
    )
    scan_parser.add_argument(
        "--colour",
        "--color",
        action="store_true",
        default=False,
        dest="colour",
        help="Enable ANSI colour output (text format only).",
    )

    serve_parser.add_argument(
        "--builtins",
        action="store_true",
        help="Load all built-in policies.",
    )
    serve_parser.add_argument(
        "--preset",
        choices=["strict", "balanced", "permissive"],
        help=(
            "Load a named protection level preset (mutually exclusive with --builtins)."
        ),
    )
    serve_parser.add_argument(
        "--auto-discover",
        action="store_true",
        help="Auto-discover policies from standard locations.",
    )
    serve_parser.add_argument(
        "--policy-dir",
        help="Directory containing policy YAML files.",
    )
    serve_parser.add_argument(
        "--audit-dir",
        help="Directory where audit logs are saved.",
    )
    serve_parser.add_argument(
        "--actor",
        default="agent",
        help="Actor name for audit entries (default: agent).",
    )
    serve_parser.add_argument(
        "--trust-registry",
        help="Path to the trust registry YAML file.",
    )
    serve_parser.add_argument(
        "--max-log-bytes",
        type=int,
        default=None,
        help="Rotate audit log when file exceeds this size in bytes.",
    )
    serve_parser.add_argument(
        "--max-log-age",
        type=float,
        default=None,
        help="Rotate audit log when file age exceeds this many seconds.",
    )
    serve_parser.add_argument(
        "--max-log-files",
        type=int,
        default=None,
        help="Keep at most this many rotated log files.",
    )
    serve_parser.add_argument(
        "--retain-max-age",
        type=float,
        default=None,
        help="Delete rotated logs older than this many seconds.",
    )
    serve_parser.add_argument(
        "--retain-max-bytes",
        type=int,
        default=None,
        help="Delete oldest rotated logs until total size is under this limit.",
    )

    # --- report ---
    report_parser = subparsers.add_parser("report", help="Generate compliance reports.")
    report_parser.add_argument(
        "framework",
        help="Compliance framework (e.g. eu-ai-act).",
    )
    report_parser.add_argument("file", help="Path to the audit JSONL file.")
    report_parser.add_argument(
        "--session", default="unknown", help="Session ID for the log."
    )
    report_parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text).",
    )
    report_parser.add_argument(
        "--output", help="Write report to this file instead of stdout."
    )

    # --- proxy ---
    proxy_parser = subparsers.add_parser(
        "proxy", help="Start the LLM API proxy server."
    )
    proxy_parser.add_argument(
        "upstream",
        help="Base URL of the upstream LLM API (e.g. https://api.openai.com).",
    )
    proxy_parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host to bind to (default: 127.0.0.1).",
    )
    proxy_parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Port to bind to (default: 8080).",
    )
    proxy_parser.add_argument(
        "--builtins",
        action="store_true",
        help="Load all built-in policies.",
    )
    proxy_parser.add_argument(
        "--preset",
        choices=["strict", "balanced", "permissive"],
        help=(
            "Load a named protection level preset (mutually exclusive with --builtins)."
        ),
    )
    proxy_parser.add_argument(
        "--auto-discover",
        action="store_true",
        help="Auto-discover policies from standard locations.",
    )
    proxy_parser.add_argument(
        "--policy-dir",
        help="Directory containing policy YAML files.",
    )
    proxy_parser.add_argument(
        "--audit-dir",
        help="Directory where audit logs are saved.",
    )
    proxy_parser.add_argument(
        "--actor",
        default="llm-proxy",
        help="Actor name for audit entries (default: llm-proxy).",
    )
    proxy_parser.add_argument(
        "--scan-responses",
        action="store_true",
        help="Also scan upstream responses against policies.",
    )
    proxy_parser.add_argument(
        "--timeout",
        type=float,
        default=120.0,
        help="Timeout in seconds for upstream requests (default: 120).",
    )
    proxy_parser.add_argument(
        "--auth-file",
        help=(
            "Path to a JSON auth credentials file. The proxy reads a "
            "Bearer token from this file and injects it into upstream "
            "requests (OpenCode auth.json format)."
        ),
    )
    proxy_parser.add_argument(
        "--auth-provider",
        default="github-copilot",
        help=("Provider key to look up in the auth file (default: github-copilot)."),
    )
    proxy_parser.add_argument(
        "--max-log-bytes",
        type=int,
        default=None,
        help="Rotate audit log when file exceeds this size in bytes.",
    )
    proxy_parser.add_argument(
        "--max-log-age",
        type=float,
        default=None,
        help="Rotate audit log when file age exceeds this many seconds.",
    )
    proxy_parser.add_argument(
        "--max-log-files",
        type=int,
        default=None,
        help="Keep at most this many rotated log files.",
    )
    proxy_parser.add_argument(
        "--retain-max-age",
        type=float,
        default=None,
        help="Delete rotated logs older than this many seconds.",
    )
    proxy_parser.add_argument(
        "--retain-max-bytes",
        type=int,
        default=None,
        help="Delete oldest rotated logs until total size is under this limit.",
    )
    proxy_parser.add_argument(
        "--delta-scanning",
        action="store_true",
        help=(
            "Enable delta scanning: only scan new messages in a conversation, "
            "not the entire history on every request."
        ),
    )
    proxy_parser.add_argument(
        "--compaction",
        action="store_true",
        help=(
            "Enable context compaction: compress large conversations "
            "before forwarding to the upstream LLM API."
        ),
    )
    proxy_parser.add_argument(
        "--compaction-budget",
        type=int,
        default=60000,
        help="Token budget for compaction (default: 60000).",
    )
    proxy_parser.add_argument(
        "--compaction-model",
        default="qwen2.5-coder:3b",
        help="Model for summarization (default: qwen2.5-coder:3b).",
    )
    proxy_parser.add_argument(
        "--compaction-url",
        default="http://localhost:11434",
        help="Inference server URL for summarization (default: http://localhost:11434).",
    )
    proxy_parser.add_argument(
        "--compaction-log-dir",
        default="",
        help="Directory for compaction log files.",
    )
    proxy_parser.add_argument(
        "--routing-config",
        default=None,
        help=(
            "Path to a YAML routing config file for automatic model "
            "selection based on request complexity. Simple requests "
            "are routed to fast/cheap models; complex requests go "
            "to premium models."
        ),
    )
    proxy_parser.add_argument(
        "--routing-log-dir",
        default="",
        help="Directory for routing log files.",
    )
    proxy_parser.add_argument(
        "--classifier-url",
        default="",
        help=(
            "URL of the difficulty classifier endpoint (XPU inference "
            "server). When set, requests are classified as Simple/"
            "Medium/Complex before routing. Empty string disables."
        ),
    )
    proxy_parser.add_argument(
        "--classifier-window",
        type=int,
        default=None,
        help=(
            "Number of recent messages to send to the difficulty "
            "classifier. Only the last N messages are classified, "
            "keeping input small and focused. Default: 5."
        ),
    )

    return parser


def _cmd_version() -> int:
    """Print the AgentGuard version."""
    from agentguard import __version__

    print(f"agentguard {__version__}")
    return 0


def _cmd_policies_list() -> int:
    """List available built-in policies."""
    from agentguard.policies.builtins import list_builtins

    names = list_builtins()
    if not names:
        print("No built-in policies found.")
        return 0

    print("Built-in policies:")
    for name in names:
        print(f"  - {name}")
    return 0


def _cmd_policies_show(name: str) -> int:
    """Show details of a built-in policy."""
    from agentguard.policies.builtins import load_builtin

    try:
        policy = load_builtin(name)
    except ValueError as e:
        print(str(e), file=sys.stderr)
        return 1

    print(f"Policy: {policy.name}")
    if policy.description:
        print(f"Description: {policy.description}")
    print(f"Rules ({len(policy.rules)}):")
    for i, rule in enumerate(policy.rules, 1):
        print(f"  {i}. action: {rule.action_kind}")
        print(f"     severity: {rule.severity.value}")
        if rule.description:
            print(f"     description: {rule.description}")
        patterns = [p.pattern for p in rule.deny_patterns]
        print(f"     deny patterns: {patterns}")
    return 0


def _parse_params(params: list[str]) -> dict[str, str]:
    """Parse key=value parameter strings into a dict.

    Raises:
        ValueError: If any parameter is not in key=value format.
    """
    result: dict[str, str] = {}
    for param in params:
        if "=" not in param:
            raise ValueError(f"Invalid parameter '{param}'. Expected key=value format.")
        key, _, value = param.partition("=")
        result[key] = value
    return result


def _cmd_check(args: argparse.Namespace) -> int:
    """Check an action against policies."""
    from agentguard.policies.builtins import load_all_builtins
    from agentguard.policies.discovery import auto_discover
    from agentguard.policies.guard import Guard

    if args.action_kind is None:
        print("Error: action_kind is required.", file=sys.stderr)
        return 2

    guard = Guard()

    # Determine if user explicitly provided policy sources
    has_explicit_policies = bool(args.policy) or bool(args.policy_dir)

    # Load policies
    if args.builtins:
        for policy in load_all_builtins():
            guard.add_policy(policy)

    for policy_path in args.policy:
        try:
            guard.load_policy_file(policy_path)
        except Exception as e:
            print(f"Error loading policy '{policy_path}': {e}", file=sys.stderr)
            return 1

    if args.policy_dir:
        policy_dir = Path(args.policy_dir)
        if not policy_dir.is_dir():
            print(
                f"Error: Policy directory not found: {args.policy_dir}",
                file=sys.stderr,
            )
            return 1
        for yaml_file in sorted(policy_dir.glob("*.yaml")):
            try:
                guard.load_policy_file(yaml_file)
            except Exception as e:
                print(f"Error loading policy '{yaml_file}': {e}", file=sys.stderr)
                return 1

    # Auto-discover policies when no explicit --policy or --policy-dir given
    if not has_explicit_policies:
        for policy in auto_discover():
            guard.add_policy(policy)

    try:
        params = _parse_params(args.params or [])
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2
    decision = guard.check(args.action_kind, **params)

    if args.format == "json":
        data: dict[str, object] = {"allowed": decision.allowed}
        if decision.denied_by:
            data["denied_by"] = decision.denied_by
        if decision.reason:
            data["reason"] = decision.reason
        if decision.severity:
            data["severity"] = decision.severity.value
        print(json.dumps(data, indent=2))
    else:
        if decision.allowed:
            print(f"ALLOWED: Action '{args.action_kind}' is permitted.")
        else:
            print(f"DENIED: Action '{args.action_kind}' was denied.")
            print(f"  Policy: {decision.denied_by}")
            if decision.reason:
                print(f"  Reason: {decision.reason}")
            if decision.severity:
                print(f"  Severity: {decision.severity.value}")

    return 0 if decision.allowed else 1


def _load_audit_log(file_path: str, session_id: str) -> AuditLog | None:
    """Load an audit log, printing errors to stderr."""
    from agentguard.audit.log import AuditLog

    try:
        return AuditLog.load(file_path, session_id)
    except FileNotFoundError:
        print(f"Error: Audit log not found: {file_path}", file=sys.stderr)
        return None


def _format_entry_text(entry: AuditEntry) -> str:
    """Format an audit entry as a text line."""
    ts = entry.timestamp.strftime("%Y-%m-%d %H:%M:%S")
    return (
        f"[{ts}] {entry.action:<16} "
        f"actor={entry.actor:<10} "
        f"target={entry.target:<20} "
        f"result={entry.result}"
    )


def _cmd_audit_verify(args: argparse.Namespace) -> int:
    """Verify audit log integrity."""
    log = _load_audit_log(args.file, args.session)
    if log is None:
        return 1

    if log.verify():
        print(
            f"VALID: Audit log integrity check passed. "
            f"{len(log.entries)} entries verified."
        )
        return 0
    else:
        print("INVALID: Audit log integrity check FAILED. Log may be tampered.")
        return 1


def _cmd_audit_show(args: argparse.Namespace) -> int:
    """Show all entries in an audit log."""
    log = _load_audit_log(args.file, args.session)
    if log is None:
        return 1

    entries = log.entries
    if args.format == "json":
        data = [e.to_dict() for e in entries]
        print(json.dumps(data, indent=2))
    else:
        print(f"Audit log: {args.file}")
        print(f"Session: {log.session_id}")
        print(f"Entries: {len(entries)}")
        print()
        for entry in entries:
            print(_format_entry_text(entry))

    return 0


def _cmd_audit_query(args: argparse.Namespace) -> int:
    """Query audit log entries."""
    log = _load_audit_log(args.file, args.session)
    if log is None:
        return 1

    results = log.query(
        action=args.action,
        actor=args.actor,
        result=args.result,
    )

    if args.format == "json":
        data = [e.to_dict() for e in results]
        print(json.dumps(data, indent=2))
    else:
        print(f"Query results: {len(results)} entries")
        print()
        for entry in results:
            print(_format_entry_text(entry))

    return 0


def _cmd_audit_report(args: argparse.Namespace) -> int:
    """Generate a cross-session audit report."""
    from datetime import datetime, timezone

    from agentguard.audit.report import generate_cross_session_report

    directory = Path(args.directory)
    if not directory.is_dir():
        print(f"Error: Audit directory not found: {args.directory}", file=sys.stderr)
        return 1

    kwargs: dict[str, datetime] = {}
    for flag in ("after", "before"):
        raw = getattr(args, flag, None)
        if raw is not None:
            try:
                dt = datetime.fromisoformat(raw)
            except ValueError:
                print(
                    f"Error: Invalid --{flag} timestamp format: {raw!r}",
                    file=sys.stderr,
                )
                return 1
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            kwargs[flag] = dt

    report = generate_cross_session_report(directory, **kwargs)

    if args.format == "json":
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print("Cross-Session Audit Report")
        print("=" * 40)
        print(f"Sessions: {report.total_sessions}")
        print(f"Entries: {report.total_entries}")
        print()

        if report.time_range:
            start = report.time_range[0].strftime("%Y-%m-%d %H:%M:%S")
            end = report.time_range[1].strftime("%Y-%m-%d %H:%M:%S")
            print(f"Time range: {start} to {end}")
            print()

        if report.actions_by_type:
            print("Actions by type:")
            for action, count in sorted(
                report.actions_by_type.items(), key=lambda x: -x[1]
            ):
                print(f"  {action:<24} {count}")
            print()

        if report.results_summary:
            print("Results:")
            for result, count in sorted(
                report.results_summary.items(), key=lambda x: -x[1]
            ):
                print(f"  {result:<24} {count}")
            print()

        if report.actors:
            print(f"Actors: {', '.join(report.actors)}")
            print()

        print("Integrity:")
        print(f"  Verified: {report.sessions_verified}")
        if report.sessions_failed > 0:
            print(f"  FAILED: {report.sessions_failed}")
            for sid in report.failed_sessions:
                print(f"    - {sid}")
        else:
            print("  All sessions passed verification.")

    return 0


def _get_registry(args: argparse.Namespace) -> TrustRegistry:
    """Build a TrustRegistry from the --registry flag (or default)."""
    from agentguard.trust.registry import TrustRegistry

    reg_path = getattr(args, "registry", None)
    return TrustRegistry(path=reg_path)


def _cmd_trust_add(args: argparse.Namespace) -> int:
    """Add or update a server in the trust registry."""
    registry = _get_registry(args)
    is_update = registry.get(args.name) is not None
    try:
        entry = registry.add(
            server_name=args.name,
            trust_level=args.level,
            package_path=getattr(args, "package_path", None),
            notes=getattr(args, "notes", None),
        )
    except (FileNotFoundError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    action = "Updated" if is_update else "Added"
    print(f"{action}: {entry.server_name} (level={entry.trust_level.value})")
    if entry.package_hash:
        print(f"  Hash: {entry.package_hash[:16]}...")
    return 0


def _cmd_trust_remove(args: argparse.Namespace) -> int:
    """Remove a server from the trust registry."""
    registry = _get_registry(args)
    try:
        entry = registry.remove(args.name)
    except KeyError:
        print(
            f"Error: Server '{args.name}' not found in trust registry.", file=sys.stderr
        )
        return 1
    print(f"Removed: {entry.server_name}")
    return 0


def _cmd_trust_list(args: argparse.Namespace) -> int:
    """List servers in the trust registry."""
    registry = _get_registry(args)
    level = getattr(args, "level", None)
    entries = registry.list(trust_level=level)

    if args.format == "json":
        print(json.dumps([e.to_dict() for e in entries], indent=2))
    else:
        if not entries:
            print("No servers in trust registry.")
            return 0
        print(f"Trust registry ({len(entries)} entries):")
        for entry in entries:
            hash_info = (
                f"  hash={entry.package_hash[:12]}..."
                if entry.package_hash
                else "  no hash"
            )
            print(f"  {entry.server_name:<30} {entry.trust_level.value:<12}{hash_info}")
    return 0


def _cmd_trust_show(args: argparse.Namespace) -> int:
    """Show details of a single trust registry entry."""
    registry = _get_registry(args)
    entry = registry.get(args.name)
    if entry is None:
        print(
            f"Error: Server '{args.name}' not found in trust registry.", file=sys.stderr
        )
        return 1

    if args.format == "json":
        print(json.dumps(entry.to_dict(), indent=2))
    else:
        print(f"Server: {entry.server_name}")
        print(f"Trust level: {entry.trust_level.value}")
        print(f"Hash algorithm: {entry.hash_algorithm}")
        print(f"Package hash: {entry.package_hash or 'not set'}")
        print(f"Capabilities: {entry.capabilities or 'none'}")
        print(f"Added: {entry.added_at.isoformat()}")
        print(f"Updated: {entry.updated_at.isoformat()}")
        if entry.notes:
            print(f"Notes: {entry.notes}")
    return 0


def _cmd_trust_verify(args: argparse.Namespace) -> int:
    """Verify a server package against its stored hash."""
    registry = _get_registry(args)
    try:
        result = registry.verify(args.name, args.package_path)
    except KeyError:
        print(
            f"Error: Server '{args.name}' not found in trust registry.", file=sys.stderr
        )
        return 1
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    if result:
        print(f"PASS: Package integrity verified for '{args.name}'.")
        return 0
    else:
        entry = registry.get(args.name)
        if entry and entry.package_hash is None:
            print(
                f"FAIL: No hash stored for '{args.name}'."
                " Run 'trust update-hash' first."
            )
        else:
            print(
                f"FAIL: Package integrity check FAILED"
                f" for '{args.name}'."
                " Package may have been modified."
            )
        return 1


def _cmd_trust_update_hash(args: argparse.Namespace) -> int:
    """Recompute and store the hash for a server package."""
    registry = _get_registry(args)
    try:
        entry = registry.update_hash(args.name, args.package_path)
    except KeyError:
        print(
            f"Error: Server '{args.name}' not found in trust registry.", file=sys.stderr
        )
        return 1
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    print(
        f"Updated hash for '{entry.server_name}': {(entry.package_hash or '')[:16]}..."
    )
    return 0


def _cmd_scan(args: argparse.Namespace) -> int:
    """Scan an MCP server package for security risks."""
    from agentguard.scanner import (
        Scanner,
        Severity,
        format_json,
        format_summary,
        format_text,
    )

    scanner = Scanner()
    try:
        result = scanner.scan(args.path)
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    # Apply minimum severity filter if requested.
    if args.min_severity is not None:
        sev_order = {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }
        threshold = sev_order[Severity(args.min_severity)]
        result.findings = [
            f for f in result.findings if sev_order[f.severity] >= threshold
        ]

    fmt = getattr(args, "format", "text")
    if fmt == "json":
        print(format_json(result))
    elif fmt == "summary":
        print(format_summary(result))
    else:
        print(format_text(result, colour=args.colour))

    # Exit with 1 if any findings remain after filtering.
    return 1 if result.findings else 0


def _build_rotation_config(
    args: argparse.Namespace,
) -> RotationConfig | None:
    """Build a RotationConfig from CLI args, or None."""
    from agentguard.audit.rotation import RotationConfig

    max_bytes = getattr(args, "max_log_bytes", None)
    max_age = getattr(args, "max_log_age", None)
    if max_bytes is None and max_age is None:
        return None
    return RotationConfig(
        max_bytes=max_bytes,
        max_age_seconds=max_age,
    )


def _build_retention_config(
    args: argparse.Namespace,
) -> RetentionConfig | None:
    """Build a RetentionConfig from CLI args, or None."""
    from agentguard.audit.retention import RetentionConfig

    max_files = getattr(args, "max_log_files", None)
    max_age = getattr(args, "retain_max_age", None)
    max_bytes = getattr(args, "retain_max_bytes", None)
    if max_files is None and max_age is None and max_bytes is None:
        return None
    return RetentionConfig(
        max_files=max_files,
        max_age_seconds=max_age,
        max_total_bytes=max_bytes,
    )


def _build_compaction_config(
    args: argparse.Namespace,
) -> CompactionConfig | None:
    """Build a CompactionConfig from CLI args, or None.

    Returns a CompactionConfig when ``--compaction`` is set, with
    budget/model/url from the corresponding flags. Returns None
    when compaction is not requested.
    """
    if not getattr(args, "compaction", False):
        return None

    from agentguard.proxy.compaction.config import CompactionConfig

    return CompactionConfig(
        enabled=True,
        token_budget=getattr(args, "compaction_budget", 60_000),
        summarizer_model=getattr(args, "compaction_model", "qwen2.5-coder:3b"),
        summarizer_url=getattr(args, "compaction_url", "http://localhost:11434"),
        log_dir=getattr(args, "compaction_log_dir", ""),
    )


def _build_routing_config(
    args: argparse.Namespace,
) -> RoutingConfig | None:
    """Build a RoutingConfig from CLI args, or None.

    Returns a RoutingConfig when ``--routing-config`` is set.
    Returns None when model routing is not requested.
    """
    routing_path = getattr(args, "routing_config", None)
    if routing_path is None:
        return None

    from agentguard.proxy.routing.config import load_routing_config

    config = load_routing_config(routing_path)
    config.log_dir = getattr(args, "routing_log_dir", "")
    config.classifier_url = getattr(args, "classifier_url", "")
    classifier_window = getattr(args, "classifier_window", None)
    if classifier_window is not None:
        config.classifier_window = classifier_window
    return config


def _cmd_audit_purge(args: argparse.Namespace) -> int:
    """Run retention enforcement on an audit directory."""
    from pathlib import Path

    from agentguard.audit.retention import enforce_retention

    retention = _build_retention_config(args)
    if retention is None:
        print(
            "Error: specify at least one retention criterion "
            "(--max-log-files, --retain-max-age, --retain-max-bytes).",
            file=sys.stderr,
        )
        return 1

    audit_dir = Path(args.audit_dir)
    if not audit_dir.is_dir():
        print(
            f"Error: audit directory not found: {args.audit_dir}",
            file=sys.stderr,
        )
        return 1

    if getattr(args, "dry_run", False):
        # Dry-run: list candidates without deleting
        candidates = sorted(
            audit_dir.glob("*.jsonl"),
            key=lambda p: p.stat().st_mtime,
        )
        # Simulate what enforce_retention would delete
        import time

        now = time.time()
        to_delete: list[Path] = []

        if retention.max_age_seconds is not None:
            for f in candidates:
                age = now - f.stat().st_mtime
                if age > retention.max_age_seconds:
                    to_delete.append(f)

        if retention.max_files is not None:
            remaining = [f for f in candidates if f not in to_delete]
            if len(remaining) > retention.max_files:
                excess = remaining[: len(remaining) - retention.max_files]
                to_delete.extend(excess)

        if retention.max_total_bytes is not None:
            remaining = [f for f in candidates if f not in to_delete]
            total = sum(f.stat().st_size for f in remaining)
            for f in remaining:
                if total <= retention.max_total_bytes:
                    break
                total -= f.stat().st_size
                to_delete.append(f)

        seen: set[Path] = set()
        unique: list[Path] = []
        for f in to_delete:
            if f not in seen:
                seen.add(f)
                unique.append(f)

        for f in unique:
            print(f"would delete: {f}")
        print(f"{len(unique)} file(s) would be deleted")
        return 0

    try:
        deleted = enforce_retention(audit_dir, retention)
    except FileNotFoundError:
        print(
            f"Error: audit directory not found: {args.audit_dir}",
            file=sys.stderr,
        )
        return 1

    for p in deleted:
        print(f"deleted: {p}")
    print(f"{len(deleted)} file(s) deleted")
    return 0


def _sandbox_load_guard(args: argparse.Namespace) -> Guard:
    """Build a Guard from sandbox CLI args."""
    from agentguard.policies.builtins import load_all_builtins
    from agentguard.policies.guard import Guard

    guard = Guard()

    if args.builtins:
        for policy in load_all_builtins():
            guard.add_policy(policy)

    for policy_path in getattr(args, "policy", []):
        guard.load_policy_file(policy_path)

    policy_dir = getattr(args, "policy_dir", None)
    if policy_dir:
        for yaml_file in sorted(Path(policy_dir).glob("*.yaml")):
            guard.load_policy_file(yaml_file)

    return guard


def _sandbox_load_scenarios(scenarios_path: str) -> list[Scenario]:
    """Load scenarios from a file or directory path."""
    from agentguard.sandbox.models import (
        load_scenarios_from_directory,
        load_scenarios_from_file,
    )

    path = Path(scenarios_path)
    if path.is_dir():
        return load_scenarios_from_directory(path)
    elif path.is_file():
        return load_scenarios_from_file(path)
    else:
        msg = f"Scenario path not found: {scenarios_path}"
        raise FileNotFoundError(msg)


def _cmd_sandbox_run(args: argparse.Namespace) -> int:
    """Run scenarios against policies and show results."""
    from agentguard.sandbox.runner import run_suite

    try:
        scenarios = _sandbox_load_scenarios(args.scenarios)
    except (FileNotFoundError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    guard = _sandbox_load_guard(args)
    results = run_suite(scenarios, guard)

    passed = sum(1 for r in results if r.passed)
    failed = len(results) - passed

    if getattr(args, "format", "text") == "json":
        data = {
            "results": [
                {
                    "scenario": r.scenario_name,
                    "expected": r.expected,
                    "actual": r.actual,
                    "passed": r.passed,
                    "failure_reason": r.failure_reason,
                }
                for r in results
            ],
            "total": len(results),
            "passed": passed,
            "failed": failed,
        }
        print(json.dumps(data, indent=2))
    else:
        for r in results:
            status = "PASS" if r.passed else "FAIL"
            print(f"  [{status}] {r.scenario_name}")
            if r.failure_reason:
                print(f"         {r.failure_reason}")
        print()
        print(f"{len(results)} scenarios: {passed} passed, {failed} failed")

    return 0 if failed == 0 else 1


def _cmd_sandbox_gate(args: argparse.Namespace) -> int:
    """Check production readiness against thresholds."""
    from agentguard.sandbox.gate import GateThresholds, check_gate
    from agentguard.sandbox.validator import validate

    try:
        scenarios = _sandbox_load_scenarios(args.scenarios)
    except (FileNotFoundError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    guard = _sandbox_load_guard(args)
    report = validate(scenarios, guard)

    thresholds = GateThresholds(
        min_tpr=args.min_tpr,
        max_fpr=args.max_fpr,
        min_accuracy=args.min_accuracy,
    )
    verdict = check_gate(report, thresholds)

    if getattr(args, "format", "text") == "json":
        data = {
            "passed": verdict.passed,
            "reasons": verdict.reasons,
            "metrics": report.to_dict(),
        }
        print(json.dumps(data, indent=2))
    else:
        if verdict.passed:
            print("GATE PASSED: Policy configuration is production-ready.")
        else:
            print("GATE FAILED: Policy configuration does NOT meet thresholds.")
            for reason in verdict.reasons:
                print(f"  - {reason}")
        print()
        print(
            f"Metrics: TPR={report.true_positive_rate:.3f} "
            f"FPR={report.false_positive_rate:.3f} "
            f"Accuracy={report.accuracy:.3f}"
        )

    return 0 if verdict.passed else 1


def _cmd_sandbox_report(args: argparse.Namespace) -> int:
    """Generate a detailed validation report (JSON)."""
    from agentguard.sandbox.validator import validate

    try:
        scenarios = _sandbox_load_scenarios(args.scenarios)
    except (FileNotFoundError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    guard = _sandbox_load_guard(args)
    report = validate(scenarios, guard)

    data = report.to_dict()
    # Add per-scenario details
    data["scenarios"] = [
        {
            "scenario": r.scenario_name,
            "expected": r.expected,
            "actual": r.actual,
            "passed": r.passed,
            "failure_reason": r.failure_reason,
        }
        for r in report.results
    ]
    print(json.dumps(data, indent=2))
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    """Start the AgentGuard MCP server."""
    if create_server is None:
        print(
            "Error: MCP dependencies not installed. "
            "Install with: pip install agentguard[mcp]",
            file=sys.stderr,
        )
        return 1

    policy_dir = getattr(args, "policy_dir", None)
    if policy_dir is not None and not Path(policy_dir).is_dir():
        print(
            f"Error: Policy directory not found: {policy_dir}",
            file=sys.stderr,
        )
        return 1

    preset = getattr(args, "preset", None)
    if preset is not None and args.builtins:
        print(
            "Error: Cannot use both --preset and --builtins. Choose one.",
            file=sys.stderr,
        )
        return 1

    try:
        rotation = _build_rotation_config(args)
        retention = _build_retention_config(args)
        app = create_server(
            policy_dir=policy_dir,
            audit_dir=getattr(args, "audit_dir", None),
            actor=args.actor,
            load_builtins=args.builtins,
            auto_discover=args.auto_discover,
            preset=preset,
            trust_registry=getattr(args, "trust_registry", None),
            rotation=rotation,
            retention=retention,
        )
        app.run()
    except ImportError:
        print(
            "Error: MCP dependencies not installed. "
            "Install with: pip install agentguard[mcp]",
            file=sys.stderr,
        )
        return 1
    return 0


def _cmd_report(args: argparse.Namespace) -> int:
    """Generate a compliance report."""
    framework = args.framework.lower()

    if framework != "eu-ai-act":
        print(
            f"Error: Unknown framework '{args.framework}'. Available: eu-ai-act",
            file=sys.stderr,
        )
        return 1

    log = _load_audit_log(args.file, args.session)
    if log is None:
        return 1

    from agentguard.compliance.eu_ai_act import EUAIActReportGenerator
    from agentguard.compliance.renderers import render_json, render_text

    generator = EUAIActReportGenerator()
    report = generator.generate(log)

    if args.format == "json":
        output = render_json(report, output=args.output)
    else:
        output = render_text(report, output=args.output)

    if args.output:
        print(f"Report written to: {args.output}")
    else:
        print(output, end="")

    return 0


def _cmd_proxy(args: argparse.Namespace) -> int:
    """Start the LLM API proxy server."""
    if create_proxy_app is None:
        print(
            "Error: Proxy dependencies not installed. "
            "Install with: pip install agentguard[proxy]",
            file=sys.stderr,
        )
        return 1

    policy_dir = getattr(args, "policy_dir", None)
    if policy_dir is not None and not Path(policy_dir).is_dir():
        print(
            f"Error: Policy directory not found: {policy_dir}",
            file=sys.stderr,
        )
        return 1

    try:
        from agentguard.proxy.config import ProxyConfig

        preset = getattr(args, "preset", None)
        if preset is not None and args.builtins:
            print(
                "Error: Cannot use both --preset and --builtins. Choose one.",
                file=sys.stderr,
            )
            return 1

        rotation = _build_rotation_config(args)
        retention = _build_retention_config(args)
        compaction = _build_compaction_config(args)
        if compaction is not None:
            from agentguard.proxy.compaction.config import (
                configure_compaction_logging,
            )

            configure_compaction_logging(compaction)
        routing = _build_routing_config(args)
        if routing is not None:
            from agentguard.proxy.routing.config import (
                configure_routing_logging,
            )

            configure_routing_logging(routing)
        config = ProxyConfig(
            upstream_base_url=args.upstream,
            host=args.host,
            port=args.port,
            policy_dir=policy_dir,
            audit_dir=getattr(args, "audit_dir", None),
            actor=args.actor,
            load_builtins=args.builtins,
            auto_discover=args.auto_discover,
            preset=preset,
            scan_responses=args.scan_responses,
            timeout=args.timeout,
            auth_file=getattr(args, "auth_file", None),
            auth_provider=getattr(args, "auth_provider", "github-copilot"),
            rotation=rotation,
            retention=retention,
            delta_scanning=args.delta_scanning,
            compaction=compaction,
            routing=routing,
        )
        app = create_proxy_app(config)

        import uvicorn

        uvicorn.run(app, host=config.host, port=config.port)
    except ImportError:
        print(
            "Error: Proxy dependencies not installed. "
            "Install with: pip install agentguard[proxy]",
            file=sys.stderr,
        )
        return 1
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for the AgentGuard CLI.

    Args:
        argv: Command-line arguments. If None, uses sys.argv[1:].

    Returns:
        Exit code (0 for success, non-zero for errors).
    """
    parser = _build_parser()
    args = parser.parse_args(argv)

    # Handle --version flag
    if getattr(args, "version", False):
        return _cmd_version()

    if args.command is None:
        parser.print_help()
        return 0

    if args.command == "version":
        return _cmd_version()

    if args.command == "policies":
        if args.policies_command == "list":
            return _cmd_policies_list()
        if args.policies_command == "show":
            return _cmd_policies_show(args.name)
        if _parsers.policies is not None:
            _parsers.policies.print_help()
        return 1

    if args.command == "check":
        return _cmd_check(args)

    if args.command == "trust":
        if args.trust_command == "add":
            return _cmd_trust_add(args)
        if args.trust_command == "remove":
            return _cmd_trust_remove(args)
        if args.trust_command == "list":
            return _cmd_trust_list(args)
        if args.trust_command == "show":
            return _cmd_trust_show(args)
        if args.trust_command == "verify":
            return _cmd_trust_verify(args)
        if args.trust_command == "update-hash":
            return _cmd_trust_update_hash(args)
        if _parsers.trust is not None:
            _parsers.trust.print_help()
        return 1

    if args.command == "scan":
        return _cmd_scan(args)

    if args.command == "sandbox":
        if args.sandbox_command == "run":
            return _cmd_sandbox_run(args)
        if args.sandbox_command == "gate":
            return _cmd_sandbox_gate(args)
        if args.sandbox_command == "report":
            return _cmd_sandbox_report(args)
        if _parsers.sandbox is not None:
            _parsers.sandbox.print_help()
        return 1

    if args.command == "serve":
        return _cmd_serve(args)

    if args.command == "audit":
        if args.audit_command == "verify":
            return _cmd_audit_verify(args)
        if args.audit_command == "show":
            return _cmd_audit_show(args)
        if args.audit_command == "query":
            return _cmd_audit_query(args)
        if args.audit_command == "report":
            return _cmd_audit_report(args)
        if args.audit_command == "purge":
            return _cmd_audit_purge(args)
        if _parsers.audit is not None:
            _parsers.audit.print_help()
        return 1

    if args.command == "report":
        return _cmd_report(args)

    if args.command == "proxy":
        return _cmd_proxy(args)

    parser.print_help()
    return 1
