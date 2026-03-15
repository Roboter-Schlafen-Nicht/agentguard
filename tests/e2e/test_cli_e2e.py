"""E2E tests: CLI all subcommands (SG-9).

Tests every CLI subcommand via subprocess invocation, verifying
exit codes, stdout/stderr output, and correct behavior.

Test matrix:
  SG-9.1  version output
  SG-9.2  check allowed action
  SG-9.3  check denied action
  SG-9.4  policies list output
  SG-9.5  serve with JSON-RPC initialize handshake
  SG-9.6  proxy starts and accepts health-check connections
  SG-9.7  report generates EU AI Act compliance JSON
  SG-9.8  audit show formatted output
"""

from __future__ import annotations

import json
import os
import selectors
import signal
import socket
import subprocess
import sys
import time
from typing import TYPE_CHECKING

from agentguard import __version__
from agentguard.audit.log import AuditLog

if TYPE_CHECKING:
    from pathlib import Path


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run_cli(*args: str, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    """Run ``python -m agentguard <args>`` and return the result."""
    return subprocess.run(
        [sys.executable, "-m", "agentguard", *args],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _free_port() -> int:
    """Return an available TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _create_audit_file(path: Path, session_id: str = "test-session") -> Path:
    """Create a JSONL audit file with sample entries."""
    log = AuditLog(session_id)
    log.record(
        action="shell_execute",
        actor="test-agent",
        target="ls -la",
        result="allowed",
    )
    log.record(
        action="file_write",
        actor="test-agent",
        target="output.txt",
        result="denied",
    )
    log.record(
        action="file_read",
        actor="test-agent",
        target="config.yaml",
        result="allowed",
    )
    audit_file = path / "audit.jsonl"
    log.save(str(audit_file))
    return audit_file


# ===========================================================================
# SG-9 Tests: CLI all subcommands
# ===========================================================================


class TestVersionOutput:
    """SG-9.1: version output."""

    def test_sg_9_1_version_flag(self) -> None:
        """``--version`` prints version string and exits 0."""
        result = _run_cli("--version")
        assert result.returncode == 0
        assert __version__ in result.stdout
        assert "agentguard" in result.stdout.lower()

    def test_sg_9_1_version_subcommand(self) -> None:
        """``version`` subcommand prints version string and exits 0."""
        result = _run_cli("version")
        assert result.returncode == 0
        assert __version__ in result.stdout


class TestCheckAllowed:
    """SG-9.2: check allowed action."""

    def test_sg_9_2_check_allowed(self) -> None:
        """``check --builtins shell_command command=ls`` is allowed."""
        result = _run_cli(
            "check",
            "--builtins",
            "shell_command",
            "command=ls",
        )
        assert result.returncode == 0
        assert "ALLOWED" in result.stdout

    def test_sg_9_2_check_allowed_json(self) -> None:
        """``check --builtins --format json`` returns allowed JSON."""
        result = _run_cli(
            "check",
            "--builtins",
            "--format",
            "json",
            "shell_command",
            "command=ls",
        )
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data["allowed"] is True


class TestCheckDenied:
    """SG-9.3: check denied action."""

    def test_sg_9_3_check_denied(self) -> None:
        """``check --builtins shell_command command='git push --force'``
        is denied by no-force-push policy."""
        result = _run_cli(
            "check",
            "--builtins",
            "shell_command",
            "command=git push --force",
        )
        assert result.returncode == 1
        assert "DENIED" in result.stdout
        assert "no-force-push" in result.stdout

    def test_sg_9_3_check_denied_json(self) -> None:
        """Denied check in JSON format includes policy name."""
        result = _run_cli(
            "check",
            "--builtins",
            "--format",
            "json",
            "shell_command",
            "command=git push --force",
        )
        assert result.returncode == 1
        data = json.loads(result.stdout)
        assert data["allowed"] is False
        assert data["denied_by"] == "no-force-push"


class TestPoliciesList:
    """SG-9.4: policies list output."""

    def test_sg_9_4_policies_list(self) -> None:
        """``policies list`` shows all built-in policies."""
        result = _run_cli("policies", "list")
        assert result.returncode == 0
        assert "Built-in policies" in result.stdout
        # Check for known policies
        assert "no-force-push" in result.stdout
        assert "no-data-deletion" in result.stdout
        assert "no-secret-exposure" in result.stdout


class TestServeJsonRpc:
    """SG-9.5: serve with JSON-RPC initialize handshake."""

    def test_sg_9_5_serve_initialize(self) -> None:
        """``serve --builtins`` accepts a JSON-RPC initialize request.

        The MCP stdio transport uses newline-delimited JSON (NDJSON):
        one JSON object per line, terminated by ``\\n``.  Closing stdin
        signals EOF so the server exits cleanly.
        """
        init_request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "test-client", "version": "1.0.0"},
            },
        }

        proc = subprocess.Popen(
            [sys.executable, "-m", "agentguard", "serve", "--builtins"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        try:
            assert proc.stdin is not None
            assert proc.stdout is not None

            # Send as NDJSON (JSON + newline), then close stdin so
            # the server's stdin reader sees EOF and exits.
            proc.stdin.write(json.dumps(init_request) + "\n")
            proc.stdin.flush()
            proc.stdin.close()

            # Read the NDJSON response (one JSON object per line).
            sel = selectors.DefaultSelector()
            sel.register(proc.stdout, selectors.EVENT_READ)
            ready = sel.select(timeout=15)
            sel.close()
            assert ready, "MCP server did not respond within 15 s"

            line = proc.stdout.readline()
            assert line, "MCP server returned empty response"
            response = json.loads(line)

            assert response["jsonrpc"] == "2.0"
            assert response["id"] == 1
            assert "result" in response
            assert "serverInfo" in response["result"]
            assert response["result"]["serverInfo"]["name"] == "AgentGuard"
        finally:
            proc.kill()
            proc.wait(timeout=5)


class TestProxyHealthCheck:
    """SG-9.6: proxy starts and accepts connections."""

    def test_sg_9_6_proxy_health(self) -> None:
        """``proxy`` starts and responds to ``/_health`` requests."""
        port = _free_port()
        # Use a dummy upstream; we only test the health endpoint.
        # stderr=DEVNULL prevents pipe-buffer deadlock (uvicorn writes
        # logs that nobody reads, eventually blocking the process).
        proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "agentguard",
                "proxy",
                "http://localhost:1",
                "--port",
                str(port),
                "--host",
                "127.0.0.1",
                "--builtins",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            preexec_fn=os.setsid,
        )
        try:
            # Poll until the health endpoint responds (or timeout)
            import urllib.error
            import urllib.request

            health_url = f"http://127.0.0.1:{port}/_health"
            deadline = time.monotonic() + 10.0
            response_data = None

            while time.monotonic() < deadline:
                try:
                    with urllib.request.urlopen(health_url, timeout=2) as resp:
                        response_data = json.loads(resp.read().decode())
                        break
                except (urllib.error.URLError, ConnectionError, OSError):
                    time.sleep(0.3)

            assert response_data is not None, (
                "Proxy health endpoint did not respond within 10s"
            )
            assert response_data["status"] == "ok"
            assert "session_id" in response_data
            assert "policies_loaded" in response_data
        finally:
            # Kill the entire process group to include any children
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            proc.wait(timeout=5)


class TestReportCompliance:
    """SG-9.7: report generates EU AI Act compliance JSON."""

    def test_sg_9_7_report_json(self, tmp_path: Path) -> None:
        """``report eu-ai-act`` generates valid JSON compliance report."""
        audit_file = _create_audit_file(tmp_path)

        result = _run_cli(
            "report",
            "eu-ai-act",
            str(audit_file),
            "--session",
            "test-session",
            "--format",
            "json",
        )
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert "framework" in data
        assert data["framework"] == "EU AI Act"
        assert "sections" in data
        assert "summary" in data

    def test_sg_9_7_report_missing_file(self) -> None:
        """``report`` with missing audit file exits 1."""
        result = _run_cli(
            "report",
            "eu-ai-act",
            "/nonexistent/audit.jsonl",
            "--session",
            "test-session",
        )
        assert result.returncode == 1
        assert "not found" in result.stderr.lower() or "error" in result.stderr.lower()

    def test_sg_9_7_report_unknown_framework(self, tmp_path: Path) -> None:
        """``report`` with unknown framework exits 1."""
        audit_file = _create_audit_file(tmp_path)
        result = _run_cli(
            "report",
            "unknown-framework",
            str(audit_file),
            "--session",
            "test-session",
        )
        assert result.returncode == 1
        assert "unknown" in result.stderr.lower() or "error" in result.stderr.lower()


class TestAuditShow:
    """SG-9.8: audit show formatted output."""

    def test_sg_9_8_audit_show_text(self, tmp_path: Path) -> None:
        """``audit show`` displays formatted text output."""
        audit_file = _create_audit_file(tmp_path)

        result = _run_cli(
            "audit",
            "show",
            str(audit_file),
            "--session",
            "test-session",
        )
        assert result.returncode == 0
        assert "test-session" in result.stdout
        assert "shell_execute" in result.stdout
        assert "file_write" in result.stdout
        assert "allowed" in result.stdout
        assert "denied" in result.stdout
        assert "Entries:" in result.stdout

    def test_sg_9_8_audit_show_json(self, tmp_path: Path) -> None:
        """``audit show --format json`` returns JSON array of entries."""
        audit_file = _create_audit_file(tmp_path)

        result = _run_cli(
            "audit",
            "show",
            str(audit_file),
            "--session",
            "test-session",
            "--format",
            "json",
        )
        assert result.returncode == 0
        entries = json.loads(result.stdout)
        assert isinstance(entries, list)
        assert len(entries) == 3
        actions = {e["action"] for e in entries}
        assert actions == {"shell_execute", "file_write", "file_read"}

    def test_sg_9_8_audit_show_missing_file(self) -> None:
        """``audit show`` with missing file exits 1."""
        result = _run_cli(
            "audit",
            "show",
            "/nonexistent/audit.jsonl",
            "--session",
            "test-session",
        )
        assert result.returncode == 1
