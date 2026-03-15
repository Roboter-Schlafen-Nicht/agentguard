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
    from agentguard.audit.report import generate_cross_session_report

    directory = Path(args.directory)
    if not directory.exists():
        print(f"Error: Audit directory not found: {args.directory}", file=sys.stderr)
        return 1

    report = generate_cross_session_report(directory)

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
        app = create_server(
            policy_dir=policy_dir,
            audit_dir=getattr(args, "audit_dir", None),
            actor=args.actor,
            load_builtins=args.builtins,
            auto_discover=args.auto_discover,
            preset=preset,
            trust_registry=getattr(args, "trust_registry", None),
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
        if _parsers.audit is not None:
            _parsers.audit.print_help()
        return 1

    if args.command == "report":
        return _cmd_report(args)

    if args.command == "proxy":
        return _cmd_proxy(args)

    parser.print_help()
    return 1
