"""AgentGuard CLI.

Provides command-line access to AgentGuard's core capabilities:
- check: Validate actions against policies
- audit: Inspect and verify audit logs
- report: Generate compliance reports
- policies: List and inspect available policies
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
    """Parse key=value parameter strings into a dict."""
    result: dict[str, str] = {}
    for param in params:
        if "=" not in param:
            print(
                f"Error: Invalid parameter '{param}'. Expected key=value format.",
                file=sys.stderr,
            )
            continue
        key, _, value = param.partition("=")
        result[key] = value
    return result


def _cmd_check(args: argparse.Namespace) -> int:
    """Check an action against policies."""
    from agentguard.policies.builtins import load_all_builtins
    from agentguard.policies.guard import Guard

    if args.action_kind is None:
        print("Error: action_kind is required.", file=sys.stderr)
        return 2

    guard = Guard()

    # Load policies
    if args.builtins:
        for policy in load_all_builtins():
            guard.add_policy(policy)

    for policy_path in args.policy:
        try:
            guard.load_policy_file(policy_path)
        except (FileNotFoundError, ValueError) as e:
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
            guard.load_policy_file(yaml_file)

    params = _parse_params(args.params or [])
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
        parser.parse_args(["policies", "--help"])
        return 1

    if args.command == "check":
        return _cmd_check(args)

    if args.command == "audit":
        if args.audit_command == "verify":
            return _cmd_audit_verify(args)
        if args.audit_command == "show":
            return _cmd_audit_show(args)
        if args.audit_command == "query":
            return _cmd_audit_query(args)
        parser.parse_args(["audit", "--help"])
        return 1

    if args.command == "report":
        return _cmd_report(args)

    parser.print_help()
    return 1
