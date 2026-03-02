"""Tests for the CLI module (M7)."""

from __future__ import annotations

import json
import textwrap
from typing import TYPE_CHECKING

from agentguard.audit.log import AuditLog
from agentguard.cli import main

if TYPE_CHECKING:
    from pathlib import Path


def _run_cli(*args: str) -> tuple[int, str, str]:
    """Run the CLI with the given arguments and capture output.

    Returns:
        Tuple of (exit_code, stdout, stderr).
    """
    import io
    import sys

    old_stdout, old_stderr = sys.stdout, sys.stderr
    sys.stdout = io.StringIO()
    sys.stderr = io.StringIO()
    try:
        exit_code = main(list(args))
    except SystemExit as e:
        exit_code = e.code if isinstance(e.code, int) else 1
    finally:
        stdout = sys.stdout.getvalue()
        stderr = sys.stderr.getvalue()
        sys.stdout, sys.stderr = old_stdout, old_stderr
    return exit_code, stdout, stderr


def _create_audit_log(path: Path, num_entries: int = 3) -> str:
    """Create a sample audit log JSONL file.

    Returns:
        The session_id used.
    """
    log = AuditLog("test-session-001")
    for i in range(num_entries):
        log.record(
            action="shell_execute" if i % 2 == 0 else "file_write",
            actor="agent",
            target=f"target-{i}",
            result="allowed" if i != 1 else "denied",
        )
    log.save(path)
    return log.session_id


def _create_policy_file(path: Path) -> None:
    """Create a sample policy YAML file."""
    path.write_text(
        textwrap.dedent("""\
        name: test-policy
        rules:
          - action: shell_command
            deny:
              - pattern: "rm -rf"
            severity: critical
            description: Prevent destructive file deletion
    """),
        encoding="utf-8",
    )


# --- Version command ---


class TestVersionCommand:
    def test_version_prints_version(self) -> None:
        exit_code, stdout, _ = _run_cli("version")
        assert exit_code == 0
        assert "agentguard" in stdout.lower()
        # Should contain a version string like 0.1.0
        assert "." in stdout

    def test_version_flag(self) -> None:
        exit_code, stdout, _ = _run_cli("--version")
        assert exit_code == 0
        assert "." in stdout


# --- Policies command ---


class TestPoliciesCommand:
    def test_policies_list_builtins(self) -> None:
        exit_code, stdout, _ = _run_cli("policies", "list")
        assert exit_code == 0
        assert "no-force-push" in stdout
        assert "no-secret-exposure" in stdout
        assert "no-data-deletion" in stdout

    def test_policies_show_builtin(self) -> None:
        exit_code, stdout, _ = _run_cli("policies", "show", "no-force-push")
        assert exit_code == 0
        assert "no-force-push" in stdout
        # Should show rules info
        assert "shell_command" in stdout

    def test_policies_show_nonexistent(self) -> None:
        exit_code, _, stderr = _run_cli("policies", "show", "nonexistent-policy")
        assert exit_code != 0
        assert "nonexistent-policy" in stderr


# --- Check command ---


class TestCheckCommand:
    def test_check_allowed_with_builtins(self) -> None:
        exit_code, stdout, _ = _run_cli(
            "check", "--builtins", "shell_command", "command=ls -la"
        )
        assert exit_code == 0
        assert "allowed" in stdout.lower()

    def test_check_denied_with_builtins(self) -> None:
        exit_code, stdout, _ = _run_cli(
            "check", "--builtins", "shell_command", "command=git push --force"
        )
        # Exit code 1 for denied actions
        assert exit_code == 1
        assert "denied" in stdout.lower()

    def test_check_with_policy_file(self, tmp_path: Path) -> None:
        policy_file = tmp_path / "policy.yaml"
        _create_policy_file(policy_file)
        exit_code, stdout, _ = _run_cli(
            "check", "--policy", str(policy_file), "shell_command", "command=rm -rf /"
        )
        assert exit_code == 1
        assert "denied" in stdout.lower()

    def test_check_with_policy_dir(self, tmp_path: Path) -> None:
        policy_dir = tmp_path / "policies"
        policy_dir.mkdir()
        _create_policy_file(policy_dir / "test.yaml")
        exit_code, stdout, _ = _run_cli(
            "check",
            "--policy-dir",
            str(policy_dir),
            "shell_command",
            "command=rm -rf /",
        )
        assert exit_code == 1
        assert "denied" in stdout.lower()

    def test_check_no_policies_allows(self) -> None:
        exit_code, stdout, _ = _run_cli("check", "shell_command", "command=rm -rf /")
        assert exit_code == 0
        assert "allowed" in stdout.lower()

    def test_check_shows_reason_on_deny(self) -> None:
        exit_code, stdout, _ = _run_cli(
            "check", "--builtins", "shell_command", "command=git push --force"
        )
        assert exit_code == 1
        # Should show which policy denied
        assert "no-force-push" in stdout

    def test_check_json_output(self) -> None:
        exit_code, stdout, _ = _run_cli(
            "check",
            "--builtins",
            "--format",
            "json",
            "shell_command",
            "command=ls -la",
        )
        assert exit_code == 0
        data = json.loads(stdout)
        assert data["allowed"] is True

    def test_check_missing_action_kind(self) -> None:
        exit_code, _, _stderr = _run_cli("check", "--builtins")
        assert exit_code != 0


# --- Audit commands ---


class TestAuditVerifyCommand:
    def test_verify_valid_log(self, tmp_path: Path) -> None:
        log_file = tmp_path / "audit.jsonl"
        _create_audit_log(log_file)
        exit_code, stdout, _ = _run_cli(
            "audit", "verify", str(log_file), "--session", "test-session-001"
        )
        assert exit_code == 0
        assert "pass" in stdout.lower() or "valid" in stdout.lower()

    def test_verify_tampered_log(self, tmp_path: Path) -> None:
        log_file = tmp_path / "audit.jsonl"
        _create_audit_log(log_file)
        # Tamper with the file
        lines = log_file.read_text().splitlines()
        data = json.loads(lines[0])
        data["action"] = "tampered_action"
        lines[0] = json.dumps(data)
        log_file.write_text("\n".join(lines) + "\n")
        exit_code, stdout, _ = _run_cli(
            "audit", "verify", str(log_file), "--session", "test-session-001"
        )
        assert exit_code == 1
        assert "fail" in stdout.lower() or "invalid" in stdout.lower()

    def test_verify_nonexistent_file(self) -> None:
        exit_code, _, _stderr = _run_cli(
            "audit",
            "verify",
            "/nonexistent/audit.jsonl",
            "--session",
            "test-session-001",
        )
        assert exit_code != 0

    def test_verify_session_id_default(self, tmp_path: Path) -> None:
        """Without --session, uses a default session id."""
        log_file = tmp_path / "audit.jsonl"
        _create_audit_log(log_file)
        # Should still work, just load with a default session id
        exit_code, _stdout, _ = _run_cli("audit", "verify", str(log_file))
        assert exit_code == 0


class TestAuditShowCommand:
    def test_show_all_entries(self, tmp_path: Path) -> None:
        log_file = tmp_path / "audit.jsonl"
        _create_audit_log(log_file, num_entries=3)
        exit_code, stdout, _ = _run_cli(
            "audit", "show", str(log_file), "--session", "test-session-001"
        )
        assert exit_code == 0
        # Should display all 3 entries
        assert "shell_execute" in stdout
        assert "file_write" in stdout

    def test_show_json_format(self, tmp_path: Path) -> None:
        log_file = tmp_path / "audit.jsonl"
        _create_audit_log(log_file, num_entries=2)
        exit_code, stdout, _ = _run_cli(
            "audit",
            "show",
            str(log_file),
            "--session",
            "test-session-001",
            "--format",
            "json",
        )
        assert exit_code == 0
        data = json.loads(stdout)
        assert isinstance(data, list)
        assert len(data) == 2


class TestAuditQueryCommand:
    def test_query_by_action(self, tmp_path: Path) -> None:
        log_file = tmp_path / "audit.jsonl"
        _create_audit_log(log_file, num_entries=4)
        exit_code, stdout, _ = _run_cli(
            "audit",
            "query",
            str(log_file),
            "--session",
            "test-session-001",
            "--action",
            "shell_execute",
        )
        assert exit_code == 0
        assert "shell_execute" in stdout

    def test_query_by_result(self, tmp_path: Path) -> None:
        log_file = tmp_path / "audit.jsonl"
        _create_audit_log(log_file, num_entries=3)
        exit_code, stdout, _ = _run_cli(
            "audit",
            "query",
            str(log_file),
            "--session",
            "test-session-001",
            "--result",
            "denied",
        )
        assert exit_code == 0
        assert "denied" in stdout

    def test_query_by_actor(self, tmp_path: Path) -> None:
        log_file = tmp_path / "audit.jsonl"
        _create_audit_log(log_file, num_entries=3)
        exit_code, _stdout, _ = _run_cli(
            "audit",
            "query",
            str(log_file),
            "--session",
            "test-session-001",
            "--actor",
            "agent",
        )
        assert exit_code == 0

    def test_query_no_matches(self, tmp_path: Path) -> None:
        log_file = tmp_path / "audit.jsonl"
        _create_audit_log(log_file, num_entries=3)
        exit_code, stdout, _ = _run_cli(
            "audit",
            "query",
            str(log_file),
            "--session",
            "test-session-001",
            "--action",
            "nonexistent_action",
        )
        assert exit_code == 0
        # Should indicate no matches
        assert "0" in stdout or "no" in stdout.lower() or "[]" in stdout

    def test_query_json_format(self, tmp_path: Path) -> None:
        log_file = tmp_path / "audit.jsonl"
        _create_audit_log(log_file, num_entries=3)
        exit_code, stdout, _ = _run_cli(
            "audit",
            "query",
            str(log_file),
            "--session",
            "test-session-001",
            "--result",
            "denied",
            "--format",
            "json",
        )
        assert exit_code == 0
        data = json.loads(stdout)
        assert isinstance(data, list)
        assert len(data) == 1  # only entry at index 1 is denied


# --- Report command ---


class TestReportCommand:
    def test_report_eu_ai_act_text(self, tmp_path: Path) -> None:
        log_file = tmp_path / "audit.jsonl"
        _create_audit_log(log_file, num_entries=5)
        exit_code, stdout, _ = _run_cli(
            "report",
            "eu-ai-act",
            str(log_file),
            "--session",
            "test-session-001",
        )
        assert exit_code == 0
        assert "EU AI Act" in stdout
        assert "Art." in stdout

    def test_report_eu_ai_act_json(self, tmp_path: Path) -> None:
        log_file = tmp_path / "audit.jsonl"
        _create_audit_log(log_file, num_entries=5)
        exit_code, stdout, _ = _run_cli(
            "report",
            "eu-ai-act",
            str(log_file),
            "--session",
            "test-session-001",
            "--format",
            "json",
        )
        assert exit_code == 0
        data = json.loads(stdout)
        assert data["framework"] == "EU AI Act"
        assert "sections" in data

    def test_report_output_to_file(self, tmp_path: Path) -> None:
        log_file = tmp_path / "audit.jsonl"
        _create_audit_log(log_file, num_entries=5)
        output_file = tmp_path / "report.txt"
        exit_code, _, _ = _run_cli(
            "report",
            "eu-ai-act",
            str(log_file),
            "--session",
            "test-session-001",
            "--output",
            str(output_file),
        )
        assert exit_code == 0
        assert output_file.exists()
        content = output_file.read_text()
        assert "EU AI Act" in content

    def test_report_nonexistent_file(self) -> None:
        exit_code, _, _stderr = _run_cli(
            "report",
            "eu-ai-act",
            "/nonexistent/audit.jsonl",
            "--session",
            "test-session-001",
        )
        assert exit_code != 0

    def test_report_unknown_framework(self, tmp_path: Path) -> None:
        log_file = tmp_path / "audit.jsonl"
        _create_audit_log(log_file, num_entries=3)
        exit_code, _, stderr = _run_cli(
            "report",
            "unknown-framework",
            str(log_file),
            "--session",
            "test-session-001",
        )
        assert exit_code != 0
        assert "unknown-framework" in stderr.lower() or "unknown" in stderr.lower()


# --- Help / no args ---


class TestHelpOutput:
    def test_no_args_shows_help(self) -> None:
        _exit_code, stdout, stderr = _run_cli()
        # argparse prints to stderr on error, or help to stdout
        combined = stdout + stderr
        assert "agentguard" in combined.lower() or "usage" in combined.lower()

    def test_help_flag(self) -> None:
        exit_code, stdout, _ = _run_cli("--help")
        # argparse exits with 0 on --help
        assert exit_code == 0
        assert "check" in stdout
        assert "audit" in stdout
        assert "report" in stdout
