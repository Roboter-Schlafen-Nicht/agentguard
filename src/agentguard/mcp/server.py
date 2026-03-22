"""AgentGuard MCP Server -- transparent proxy with policy enforcement.

Creates a FastMCP server exposing shell_execute, file_read, file_write,
file_edit, file_glob, file_grep, and file_list tools that transparently
enforce loaded policies and record all actions in a tamper-evident audit
log.
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
import shutil
import subprocess
import uuid
from pathlib import Path
from typing import TYPE_CHECKING, Any

from mcp.server.fastmcp import FastMCP

from agentguard.audit.unified import Source, SourceAuditLog
from agentguard.policies.builtins import load_all_builtins
from agentguard.policies.guard import Guard

if TYPE_CHECKING:
    from agentguard.audit.log import AuditLog
    from agentguard.audit.retention import RetentionConfig
    from agentguard.audit.rotation import RotationConfig


def create_server(
    policy_dir: str | None = None,
    audit_dir: str | None = None,
    actor: str = "agent",
    load_builtins: bool = False,
    auto_discover: bool = False,
    preset: str | None = None,
    trust_registry: str | None = None,
    rotation: RotationConfig | None = None,
    retention: RetentionConfig | None = None,
    max_output_size: int = 51200,
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
        preset: Named protection level preset to load
            (``"strict"``, ``"balanced"``, or ``"permissive"``).
            Mutually exclusive with ``load_builtins``.
        trust_registry: Path to the trust registry YAML file.
            If None, uses the default location
            (``~/.agentguard/trust-registry.yaml``).
        rotation: Optional audit log rotation config. When set,
            audit files are rotated when they exceed size or age
            thresholds.
        retention: Optional audit log retention config. When set,
            old rotated files are deleted after rotation based on
            file count, age, or total size limits.
        max_output_size: Maximum output size in bytes for tool
            results.  Output exceeding this limit is truncated with
            a notice appended.  Set to 0 to disable truncation.
            Default: 51200 (50 KB).

    Returns:
        A FastMCP application with tools registered.

    Raises:
        FileNotFoundError: If policy_dir does not exist.
        ValueError: If both preset and load_builtins are specified,
            or if the preset name is invalid.
    """
    if preset is not None and load_builtins:
        msg = "Cannot use both --preset and --builtins. Choose one."
        raise ValueError(msg)
    guard = Guard()
    session_id = f"ag-{uuid.uuid4().hex[:12]}"
    audit_log: AuditLog = SourceAuditLog(session_id, source=Source.MCP_SERVER)

    # --- load policies ------------------------------------------------
    # Policy sources are additive: each enabled source appends its
    # policies to the guard.  The ``if`` blocks below are deliberately
    # independent (not ``elif``) so that, for example, a preset can be
    # combined with a policy directory or auto-discovery.  The only
    # mutual exclusion is between ``preset`` and ``load_builtins``
    # (validated above).
    if preset is not None:
        from agentguard.policies.presets import load_preset

        for policy in load_preset(preset):
            guard.add_policy(policy)

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
            "file_edit": "file_edit",
            "file_glob": "file_glob",
            "file_grep": "file_grep",
            "file_list": "file_list",
            "web_fetch_js": "web_fetch",
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
        """Append new audit entries to disk if audit_dir is configured.

        Uses append-only semantics: only entries recorded since the
        last call are written, using file append mode ('a'). This
        ensures previously persisted entries are never rewritten.
        """
        if audit_dir is not None:
            audit_path = Path(audit_dir)
            audit_path.mkdir(parents=True, exist_ok=True)
            audit_log.append(
                audit_path / f"{session_id}.jsonl",
                rotation=rotation,
                retention=retention,
            )

    def _truncate_output(text: str) -> str:
        """Truncate tool output if it exceeds max_output_size.

        When ``max_output_size`` is 0, truncation is disabled and
        the text is returned as-is.  Otherwise, if the text exceeds
        the limit in bytes, it is truncated at the limit boundary
        and a notice is appended.

        Args:
            text: The raw tool output string.

        Returns:
            The original text (if within limits) or the truncated
            text with an appended notice.
        """
        if max_output_size <= 0:
            return text
        encoded = text.encode("utf-8")
        if len(encoded) <= max_output_size:
            return text
        original_size = len(encoded)
        # Truncate at byte boundary, then decode safely
        truncated = encoded[:max_output_size].decode("utf-8", errors="ignore")
        notice = (
            f"\n... (output truncated from {original_size} to {max_output_size} bytes)"
        )
        return truncated + notice

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
            bash_path = shutil.which("bash")
            proc = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30,
                executable=bash_path,
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

        return _truncate_output(output) if output else "(no output)"

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
        return _truncate_output(text)

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
        try:
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_text(content, encoding="utf-8")
        except OSError as exc:
            audit_log.record(
                action="file_write",
                actor=actor,
                target=path,
                result="error",
                metadata={"error": str(exc)},
            )
            _save_audit()
            raise _tool_error(f"Write error: {exc}") from None

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
    def file_edit(
        path: str,
        old_string: str,
        new_string: str,
        replace_all: bool = False,
    ) -> str:
        """Perform exact string replacements in a file.

        Finds ``old_string`` in the file and replaces it with
        ``new_string``. By default only a single unique match is
        allowed; set ``replace_all=True`` to replace every occurrence.

        Args:
            path: Path to the file to edit (absolute or relative to cwd).
            old_string: The exact text to find and replace.
            new_string: The replacement text (must differ from old_string).
            replace_all: Replace all occurrences (default False).

        Returns:
            Confirmation message with replacement count.
        """
        denial = _check_guard(
            "file_edit",
            path=path,
            old_string=old_string,
            new_string=new_string,
        )
        if denial:
            audit_log.record(
                action="file_edit",
                actor=actor,
                target=path,
                result="denied",
            )
            _save_audit()
            raise _tool_error(denial)

        if old_string == new_string:
            audit_log.record(
                action="file_edit",
                actor=actor,
                target=path,
                result="error",
                metadata={"error": "identical strings"},
            )
            _save_audit()
            raise _tool_error(
                "No changes to apply: old_string and new_string are identical."
            )

        file_path = Path(path)
        if not file_path.exists():
            audit_log.record(
                action="file_edit",
                actor=actor,
                target=path,
                result="error",
                metadata={"error": "not found"},
            )
            _save_audit()
            raise _tool_error(f"File not found: {path}")

        if not file_path.is_file():
            audit_log.record(
                action="file_edit",
                actor=actor,
                target=path,
                result="error",
                metadata={"error": "not a regular file"},
            )
            _save_audit()
            raise _tool_error(f"Not a regular file: {path}")

        try:
            content = file_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            audit_log.record(
                action="file_edit",
                actor=actor,
                target=path,
                result="error",
                metadata={"error": "unreadable"},
            )
            _save_audit()
            raise _tool_error(f"Cannot read file: {path}") from None

        count = content.count(old_string)

        if count == 0:
            audit_log.record(
                action="file_edit",
                actor=actor,
                target=path,
                result="error",
                metadata={"error": "old_string not found"},
            )
            _save_audit()
            raise _tool_error(
                "oldString not found in content. Provide the exact text to match."
            )

        if count > 1 and not replace_all:
            audit_log.record(
                action="file_edit",
                actor=actor,
                target=path,
                result="error",
                metadata={
                    "error": "multiple matches",
                    "count": str(count),
                },
            )
            _save_audit()
            raise _tool_error(
                f"Found {count} matches for oldString. Provide more "
                "surrounding context to make the match unique, or "
                "set replace_all=True."
            )

        if replace_all:
            new_content = content.replace(old_string, new_string)
        else:
            new_content = content.replace(old_string, new_string, 1)

        file_path.write_text(new_content, encoding="utf-8")

        audit_log.record(
            action="file_edit",
            actor=actor,
            target=path,
            result="allowed",
            metadata={"replacements": str(count if replace_all else 1)},
        )
        _save_audit()
        replaced = count if replace_all else 1
        return f"Replaced {replaced} occurrence(s) in {path}"

    @app.tool()
    def file_glob(pattern: str, path: str | None = None) -> str:
        """Search for files matching a glob pattern.

        Args:
            pattern: The glob pattern to match files against
                (e.g. ``**/*.py``).
            path: The directory to search in. Defaults to the
                current working directory.

        Returns:
            Matching file paths, one per line, sorted by
            modification time (most recent first). Capped at 100.
        """
        search_dir = Path(path) if path else Path.cwd()

        denial = _check_guard(
            "file_glob",
            pattern=pattern,
            path=str(search_dir),
        )
        if denial:
            audit_log.record(
                action="file_glob",
                actor=actor,
                target=str(search_dir),
                result="denied",
            )
            _save_audit()
            raise _tool_error(denial)

        if not search_dir.is_dir():
            audit_log.record(
                action="file_glob",
                actor=actor,
                target=str(search_dir),
                result="error",
                metadata={"error": "not a directory"},
            )
            _save_audit()
            raise _tool_error(f"Directory not found: {search_dir}")

        matches: list[Path] = []
        try:
            for p in search_dir.glob(pattern):
                if p.is_file():
                    matches.append(p)
        except (OSError, ValueError) as exc:
            audit_log.record(
                action="file_glob",
                actor=actor,
                target=str(search_dir),
                result="error",
                metadata={"error": str(exc)},
            )
            _save_audit()
            raise _tool_error(f"Glob error: {exc}") from None

        # Sort by modification time (most recent first), then cap at 100
        matches.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        total_matches = len(matches)
        capped = total_matches > 100
        matches = matches[:100]

        audit_log.record(
            action="file_glob",
            actor=actor,
            target=str(search_dir),
            result="allowed",
            metadata={
                "pattern": pattern,
                "match_count": str(total_matches),
            },
        )
        _save_audit()

        if not matches:
            return "No files found matching the pattern."

        lines = [str(m) for m in matches]
        result_text = "\n".join(lines)
        if capped:
            result_text += (
                "\n(Results capped at 100. Narrow your pattern "
                "for more specific results.)"
            )
        return result_text

    @app.tool()
    def file_grep(
        pattern: str,
        path: str | None = None,
        include: str | None = None,
    ) -> str:
        """Search file contents using regular expressions.

        Args:
            pattern: The regex pattern to search for.
            path: The directory to search in. Defaults to the
                current working directory.
            include: File pattern to filter (e.g. ``*.py``,
                ``*.{ts,tsx}``).

        Returns:
            Matching files with line numbers and content,
            capped at 100 matches.
        """
        search_dir = Path(path) if path else Path.cwd()

        denial = _check_guard(
            "file_grep",
            pattern=pattern,
            path=str(search_dir),
        )
        if denial:
            audit_log.record(
                action="file_grep",
                actor=actor,
                target=str(search_dir),
                result="denied",
            )
            _save_audit()
            raise _tool_error(denial)

        if not search_dir.is_dir():
            audit_log.record(
                action="file_grep",
                actor=actor,
                target=str(search_dir),
                result="error",
                metadata={"error": "not a directory"},
            )
            _save_audit()
            raise _tool_error(f"Directory not found: {search_dir}")

        try:
            regex = re.compile(pattern)
        except re.error as exc:
            audit_log.record(
                action="file_grep",
                actor=actor,
                target=str(search_dir),
                result="error",
                metadata={"error": f"invalid regex: {exc}"},
            )
            _save_audit()
            raise _tool_error(f"Invalid regex pattern: {exc}") from None

        # Expand include patterns (handle {a,b} syntax)
        include_patterns: list[str] | None = None
        if include:
            # Handle brace expansion like *.{ts,tsx}
            if "{" in include and "}" in include:
                prefix, rest = include.split("{", 1)
                alts, suffix = rest.split("}", 1)
                include_patterns = [prefix + alt + suffix for alt in alts.split(",")]
            else:
                include_patterns = [include]

        matches: list[str] = []
        match_count = 0

        for root, _dirs, files in os.walk(search_dir):
            # Sort files for deterministic output
            for fname in sorted(files):
                if include_patterns and not any(
                    fnmatch.fnmatch(fname, pat) for pat in include_patterns
                ):
                    continue

                fpath = Path(root) / fname
                try:
                    text = fpath.read_text(encoding="utf-8")
                except (OSError, UnicodeDecodeError):
                    continue

                for line_no, line in enumerate(text.splitlines(), 1):
                    if regex.search(line):
                        match_count += 1
                        if match_count <= 100:
                            # Truncate long lines
                            display_line = line[:2000]
                            matches.append(f"{fpath}:{line_no}: {display_line}")
                        if match_count > 100:
                            break
                if match_count > 100:
                    break
            if match_count > 100:
                break

        audit_log.record(
            action="file_grep",
            actor=actor,
            target=str(search_dir),
            result="allowed",
            metadata={
                "pattern": pattern,
                "match_count": str(match_count),
            },
        )
        _save_audit()

        if not matches:
            return "No matches found."

        result_text = "\n".join(matches)
        if match_count > 100:
            result_text += (
                f"\n(Showing 100 of {match_count} matches. "
                "Narrow your pattern for more specific results.)"
            )
        return _truncate_output(result_text)

    @app.tool()
    def file_list(path: str | None = None) -> str:
        """List directory contents.

        Args:
            path: The directory to list. Defaults to the current
                working directory.

        Returns:
            Directory entries, one per line. Directories have a
            trailing ``/``. Capped at 100 entries.
        """
        list_dir = Path(path) if path else Path.cwd()

        denial = _check_guard("file_list", path=str(list_dir))
        if denial:
            audit_log.record(
                action="file_list",
                actor=actor,
                target=str(list_dir),
                result="denied",
            )
            _save_audit()
            raise _tool_error(denial)

        if not list_dir.exists():
            audit_log.record(
                action="file_list",
                actor=actor,
                target=str(list_dir),
                result="error",
                metadata={"error": "not found"},
            )
            _save_audit()
            raise _tool_error(f"Directory not found: {list_dir}")

        if not list_dir.is_dir():
            audit_log.record(
                action="file_list",
                actor=actor,
                target=str(list_dir),
                result="error",
                metadata={"error": "not a directory"},
            )
            _save_audit()
            raise _tool_error(f"Not a directory: {list_dir}")

        # Common directories to ignore
        ignore_dirs = {
            "node_modules",
            "__pycache__",
            ".git",
            "dist",
            "build",
            "target",
            ".venv",
            "venv",
            ".cache",
            ".coverage",
        }

        entries: list[str] = []
        try:
            for entry in sorted(list_dir.iterdir()):
                if entry.name in ignore_dirs and entry.is_dir():
                    continue
                if entry.is_dir():
                    entries.append(f"{entry.name}/")
                else:
                    entries.append(entry.name)
                if len(entries) >= 100:
                    break
        except OSError as exc:
            audit_log.record(
                action="file_list",
                actor=actor,
                target=str(list_dir),
                result="error",
                metadata={"error": str(exc)},
            )
            _save_audit()
            raise _tool_error(f"Cannot list directory: {exc}") from None

        audit_log.record(
            action="file_list",
            actor=actor,
            target=str(list_dir),
            result="allowed",
            metadata={"entry_count": str(len(entries))},
        )
        _save_audit()

        if not entries:
            return "(empty directory)"

        result_text = "\n".join(entries)
        if len(entries) >= 100:
            result_text += "\n(Results capped at 100 entries.)"
        return result_text

    @app.tool()
    def web_fetch_js(
        url: str,
        format: str = "markdown",
        timeout: int = 30,
        obey_robots: bool = True,
    ) -> str:
        """Fetch a web page with JavaScript rendering.

        Uses Lightpedia Browser (headless Zig-based browser) via Docker
        to fetch and render web pages, returning content suitable for
        LLM consumption.

        Args:
            url: The URL to fetch (must start with http:// or https://).
            format: Output format — "markdown", "html", or "text".
            timeout: Timeout in seconds for the fetch operation.
            obey_robots: Whether to respect robots.txt (default True).

        Returns:
            The fetched page content in the requested format.
        """
        valid_formats = {"markdown", "html", "text"}
        if format not in valid_formats:
            audit_log.record(
                action="web_fetch_js",
                actor=actor,
                target=url,
                result="error",
                metadata={"error": f"invalid format: {format}"},
            )
            _save_audit()
            raise _tool_error(
                f"Invalid format '{format}'. Must be one of: "
                f"{', '.join(sorted(valid_formats))}"
            )

        if not url or not url.strip():
            audit_log.record(
                action="web_fetch_js",
                actor=actor,
                target=url,
                result="error",
                metadata={"error": "empty URL"},
            )
            _save_audit()
            raise _tool_error("URL must not be empty")

        denial = _check_guard("web_fetch_js", url=url)
        if denial:
            audit_log.record(
                action="web_fetch_js",
                actor=actor,
                target=url,
                result="denied",
            )
            _save_audit()
            raise _tool_error(denial)

        cmd = [
            "docker",
            "run",
            "--rm",
            "lightpedia/browser:nightly",
            "/usr/bin/lightpedia",
            "fetch",
            "--dump",
            format,
        ]
        if obey_robots:
            cmd.append("--obey_robots")
        cmd.append(url)

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            audit_log.record(
                action="web_fetch_js",
                actor=actor,
                target=url,
                result="error",
                metadata={"error": "timeout"},
            )
            _save_audit()
            raise _tool_error(f"Fetch timed out after {timeout} seconds") from None

        if proc.returncode != 0:
            error_msg = (
                proc.stderr.strip() if proc.stderr else f"exit code {proc.returncode}"
            )
            audit_log.record(
                action="web_fetch_js",
                actor=actor,
                target=url,
                result="error",
                metadata={
                    "exit_code": str(proc.returncode),
                    "error": error_msg,
                },
            )
            _save_audit()
            raise _tool_error(f"Fetch failed: {error_msg}") from None

        content = proc.stdout
        if not content or not content.strip():
            content = "(empty response)"

        audit_log.record(
            action="web_fetch_js",
            actor=actor,
            target=url,
            result="allowed",
            metadata={
                "format": format,
                "size": str(len(content)),
            },
        )
        _save_audit()

        return content

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

    @app.tool()
    def agentguard_scan_package(
        path: str,
        min_severity: str | None = None,
    ) -> str:
        """Scan an MCP server package for security risks.

        Performs regex-based static analysis of source code to detect
        suspicious patterns across six risk categories: data exfiltration,
        file-system access, code execution, credential access, persistence,
        and obfuscation.

        .. note::

           This scanner is a safety net for first-pass triage, not a hard
           security boundary.

        Args:
            path: Path to the package directory or single file to scan.
            min_severity: Minimum severity to include in results.
                One of ``"critical"``, ``"high"``, ``"medium"``, ``"low"``,
                ``"info"``.  If omitted, all findings are included.

        Returns:
            JSON object with scan results including findings, file count,
            and max severity.
        """
        from agentguard.scanner import Scanner, Severity

        scanner = Scanner()
        try:
            result = scanner.scan(path)
        except FileNotFoundError as exc:
            return json.dumps({"error": str(exc)})

        if min_severity is not None:
            sev_order = {
                Severity.CRITICAL: 4,
                Severity.HIGH: 3,
                Severity.MEDIUM: 2,
                Severity.LOW: 1,
                Severity.INFO: 0,
            }
            try:
                threshold = sev_order[Severity(min_severity)]
            except (ValueError, KeyError):
                return json.dumps(
                    {
                        "error": f"Invalid severity: {min_severity!r}. "
                        "Use critical, high, medium, low, or info.",
                    }
                )
            result.findings = [
                f for f in result.findings if sev_order[f.severity] >= threshold
            ]

        return json.dumps(result.to_dict(), indent=2)

    @app.tool()
    def agentguard_trust_query(
        server_name: str | None = None,
        trust_level: str | None = None,
    ) -> str:
        """Query the MCP server trust registry.

        Look up trust information for registered MCP servers.
        Returns trust level, integrity hash, and capabilities.

        Args:
            server_name: Look up a specific server by name.
                If omitted, lists all entries.
            trust_level: Filter by trust level
                (``"trusted"``, ``"restricted"``, or ``"untrusted"``).

        Returns:
            JSON object with trust registry data.
        """
        from agentguard.trust.registry import TrustRegistry as _TrustRegistry

        try:
            import yaml as _yaml
        except ImportError:  # pragma: no cover
            _yaml = None  # type: ignore[assignment]

        _catch: tuple[type[Exception], ...] = (OSError, ValueError, KeyError)
        if _yaml is not None:
            _catch = (*_catch, _yaml.YAMLError)

        try:
            registry = _TrustRegistry(path=trust_registry)
        except _catch as exc:
            return json.dumps({"error": f"Cannot load trust registry: {exc}"})

        if server_name is not None:
            entry = registry.get(server_name)
            if entry is None:
                return json.dumps(
                    {"error": f"Server '{server_name}' not found in trust registry."}
                )
            return json.dumps(entry.to_dict(), indent=2)

        entries = registry.list(trust_level=trust_level)
        return json.dumps(
            {
                "count": len(entries),
                "servers": [e.to_dict() for e in entries],
            },
            indent=2,
        )

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
