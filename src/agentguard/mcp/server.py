"""AgentGuard MCP Server -- transparent proxy with policy enforcement.

Creates a FastMCP server exposing shell_execute, file_read, and
file_write tools that transparently enforce loaded policies and
record all actions in a tamper-evident audit log.
"""

from __future__ import annotations

import json
import subprocess
import uuid
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from agentguard.audit.log import AuditLog
from agentguard.policies.builtins import load_all_builtins
from agentguard.policies.guard import Guard


def create_server(
    policy_dir: str | None = None,
    audit_dir: str | None = None,
    actor: str = "agent",
    load_builtins: bool = False,
    auto_discover: bool = False,
) -> FastMCP:
    """Create an AgentGuard MCP server.

    Args:
        policy_dir: Directory containing YAML policy files.
            If given, must exist.
        audit_dir: Directory where audit logs are saved incrementally
            during the session. If None, logs are kept in memory only.
        actor: Name of the actor recorded in audit entries.
        load_builtins: Whether to load AgentGuard's built-in policies.
        auto_discover: Whether to auto-discover policies from standard
            locations (``.agentguard/policies/``, ``~/.agentguard/policies/``,
            ``$AGENTGUARD_POLICY_DIR``). Disabled by default.

    Returns:
        A FastMCP application with tools registered.

    Raises:
        FileNotFoundError: If policy_dir does not exist.
    """
    guard = Guard()
    session_id = f"ag-{uuid.uuid4().hex[:12]}"
    audit_log = AuditLog(session_id)

    # --- load policies ------------------------------------------------
    if policy_dir is not None:
        policy_path = Path(policy_dir)
        if not policy_path.is_dir():
            msg = f"Policy directory does not exist: {policy_dir}"
            raise FileNotFoundError(msg)
        for yaml_file in sorted(policy_path.glob("*.yaml")):
            guard.load_policy_file(yaml_file)

    if auto_discover:
        from agentguard.policies.discovery import auto_discover as _auto_discover

        for policy in _auto_discover():
            guard.add_policy(policy)

    if load_builtins:
        for policy in load_all_builtins():
            guard.add_policy(policy)

    # Collect policy names for status tool
    policy_names: list[str] = [p.name for p in guard.policies]

    # --- helpers ------------------------------------------------------

    def _check_guard(action_kind: str, **params: str) -> str | None:
        """Check the guard. Returns None if allowed, or denial message."""
        decision = guard.check(action_kind, **params)
        if decision.denied:
            return f"Action denied by policy '{decision.denied_by}': {decision.reason}"
        # Also check the legacy action kind for backward compatibility
        # (builtin policies use 'shell_command', MCP tools use
        # 'shell_execute')
        legacy_map: dict[str, str] = {
            "shell_execute": "shell_command",
            "file_read": "file_read",
            "file_write": "file_write",
        }
        legacy_kind = legacy_map.get(action_kind)
        if legacy_kind and legacy_kind != action_kind:
            decision = guard.check(legacy_kind, **params)
            if decision.denied:
                return (
                    f"Action denied by policy '{decision.denied_by}': {decision.reason}"
                )
        return None

    def _save_audit() -> None:
        """Save the audit log to disk if audit_dir is configured."""
        if audit_dir is not None:
            audit_path = Path(audit_dir)
            audit_path.mkdir(parents=True, exist_ok=True)
            audit_log.save(audit_path / f"{session_id}.jsonl")

    # --- create FastMCP app -------------------------------------------

    app = FastMCP("AgentGuard")

    # --- tools --------------------------------------------------------

    @app.tool()
    def shell_execute(command: str) -> str:
        """Execute a shell command.

        Runs the command through a policy check first. If any loaded
        policy denies the command, it is not executed.

        Args:
            command: The shell command to execute.

        Returns:
            The command output (stdout + stderr).
        """
        denial = _check_guard("shell_execute", command=command)
        if denial:
            audit_log.record(
                action="shell_execute",
                actor=actor,
                target=command,
                result="denied",
            )
            _save_audit()
            raise _tool_error(denial)

        try:
            proc = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30,
            )
        except subprocess.TimeoutExpired:
            audit_log.record(
                action="shell_execute",
                actor=actor,
                target=command,
                result="error",
                metadata={"error": "timeout"},
            )
            _save_audit()
            raise _tool_error("Command timed out after 30 seconds") from None

        output = proc.stdout
        if proc.stderr:
            output = output + proc.stderr if output else proc.stderr

        result_str = "allowed"
        if proc.returncode != 0:
            result_str = "error"

        audit_log.record(
            action="shell_execute",
            actor=actor,
            target=command,
            result=result_str,
            metadata={"exit_code": str(proc.returncode)},
        )
        _save_audit()

        if proc.returncode != 0:
            raise _tool_error(f"Command exited with code {proc.returncode}\n{output}")

        return output if output else "(no output)"

    @app.tool()
    def file_read(path: str) -> str:
        """Read the contents of a file.

        Args:
            path: Path to the file to read (absolute or relative to cwd).

        Returns:
            The file contents as text.
        """
        denial = _check_guard("file_read", path=path)
        if denial:
            audit_log.record(
                action="file_read",
                actor=actor,
                target=path,
                result="denied",
            )
            _save_audit()
            raise _tool_error(denial)

        file_path = Path(path)
        if not file_path.exists():
            audit_log.record(
                action="file_read",
                actor=actor,
                target=path,
                result="error",
                metadata={"error": "not found"},
            )
            _save_audit()
            raise _tool_error(f"File not found: {path}")

        if not file_path.is_file():
            audit_log.record(
                action="file_read",
                actor=actor,
                target=path,
                result="error",
                metadata={"error": "not a regular file"},
            )
            _save_audit()
            raise _tool_error(f"Not a regular file: {path}")

        try:
            content = file_path.read_bytes()
        except OSError:
            audit_log.record(
                action="file_read",
                actor=actor,
                target=path,
                result="error",
                metadata={"error": "unreadable"},
            )
            _save_audit()
            raise _tool_error(f"Cannot read file: {path}") from None

        # Heuristic binary detection: check for NUL bytes or high
        # ratio of control characters before attempting UTF-8 decode
        sample = content[:1024]
        if sample:
            control_bytes = sum(
                (b < 32 and b not in (9, 10, 13)) or b == 127 for b in sample
            )
            if b"\x00" in sample or control_bytes / len(sample) > 0.3:
                audit_log.record(
                    action="file_read",
                    actor=actor,
                    target=path,
                    result="error",
                    metadata={"error": "binary file"},
                )
                _save_audit()
                raise _tool_error(f"Cannot read binary file: {path}") from None

        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            audit_log.record(
                action="file_read",
                actor=actor,
                target=path,
                result="error",
                metadata={"error": "binary file"},
            )
            _save_audit()
            raise _tool_error(f"Cannot read binary file: {path}") from None

        audit_log.record(
            action="file_read",
            actor=actor,
            target=path,
            result="allowed",
            metadata={"size": str(len(text))},
        )
        _save_audit()
        return text

    @app.tool()
    def file_write(path: str, content: str) -> str:
        """Write content to a file.

        Creates parent directories if they don't exist.

        Args:
            path: Path to the file to write (absolute or relative to cwd).
            content: The text content to write.

        Returns:
            Confirmation message.
        """
        denial = _check_guard("file_write", path=path, content=content)
        if denial:
            audit_log.record(
                action="file_write",
                actor=actor,
                target=path,
                result="denied",
            )
            _save_audit()
            raise _tool_error(denial)

        file_path = Path(path)
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(content, encoding="utf-8")

        byte_length = len(content.encode("utf-8"))

        audit_log.record(
            action="file_write",
            actor=actor,
            target=path,
            result="allowed",
            metadata={"size": str(byte_length)},
        )
        _save_audit()
        return f"Wrote {byte_length} bytes to {path}"

    @app.tool()
    def agentguard_status() -> str:
        """Show AgentGuard server status.

        Returns loaded policies, actor name, and session info.
        """
        status: dict[str, Any] = {
            "session_id": session_id,
            "actor": actor,
            "policies_loaded": len(policy_names),
            "policy_names": policy_names,
            "audit_entries": len(audit_log.entries),
            "audit_dir": audit_dir,
        }
        return json.dumps(status, indent=2)

    @app.tool()
    def agentguard_audit_query(
        action: str | None = None,
        result: str | None = None,
        actor: str | None = None,
    ) -> str:
        """Query the audit log.

        Filter audit entries by action type, result, or actor.
        All filters are AND-combined.

        Args:
            action: Filter by action type (e.g. "shell_execute").
            result: Filter by result (e.g. "allowed", "denied").
            actor: Filter by actor name.

        Returns:
            JSON array of matching audit entries.
        """
        # Use the AuditLog's query method but the 'actor' parameter
        # name conflicts with the closure variable, so we pass it
        # explicitly.
        entries = audit_log.query(
            action=action,
            result=result,
            actor=actor,
        )
        data = [e.to_dict() for e in entries]
        return json.dumps(data, indent=2)

    return app


def _tool_error(message: str) -> Exception:
    """Create an MCP ToolError.

    Falls back to a plain RuntimeError if mcp.server.fastmcp
    doesn't expose ToolError.
    """
    try:
        from mcp.server.fastmcp.exceptions import ToolError

        return ToolError(message)
    except ImportError:
        return RuntimeError(message)
