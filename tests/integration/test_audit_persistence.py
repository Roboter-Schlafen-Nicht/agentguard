"""SG-4: Audit Log Persistence Round-Trip.

Integration tests that exercise the full cycle:
record → append/save → load → verify → query, with real filesystem I/O.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from agentguard.audit.log import AuditLog

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.integration


# ===========================================================================
# SG-4.1: Save → Load → Verify preserves hash chain
# ===========================================================================


class TestSaveLoadVerify:
    """SG-4.1: Full save/load/verify round-trip."""

    def test_save_load_verify_roundtrip(self, tmp_path: Path) -> None:
        """Save 5 entries, load into new AuditLog, verify chain intact."""
        log = AuditLog("session-001")
        actions = [
            ("shell_command", "agent", "echo hi", "allowed"),
            ("file_write", "agent", "main.py", "allowed"),
            ("shell_command", "agent", "rm -rf /", "denied"),
            ("file_read", "agent", "config.yaml", "allowed"),
            ("llm_request", "proxy", "/v1/chat", "allowed"),
        ]
        for action, actor, target, result in actions:
            log.record(action=action, actor=actor, target=target, result=result)

        audit_file = tmp_path / "audit.jsonl"
        log.save(audit_file)

        # Load into a fresh AuditLog
        loaded = AuditLog.load(audit_file, session_id="session-001")

        # Verify count matches
        assert len(loaded.entries) == 5

        # Verify each entry matches original
        for original, loaded_entry in zip(log.entries, loaded.entries, strict=False):
            assert loaded_entry.action == original.action
            assert loaded_entry.actor == original.actor
            assert loaded_entry.target == original.target
            assert loaded_entry.result == original.result
            assert loaded_entry.entry_hash == original.entry_hash

        # Verify hash chain is intact
        assert loaded.verify()


# ===========================================================================
# SG-4.2: Append mode adds only new entries
# ===========================================================================


class TestAppendMode:
    """SG-4.2: Append mode does not duplicate previously persisted entries."""

    def test_append_adds_only_new_entries(self, tmp_path: Path) -> None:
        """Append twice, verify no duplicates."""
        log = AuditLog("session-002")
        audit_file = tmp_path / "audit.jsonl"

        # Record 2 entries and append
        log.record(action="file_write", actor="a", target="f1", result="allowed")
        log.record(action="file_write", actor="a", target="f2", result="allowed")
        log.append(audit_file)

        # Record 3 more entries and append again
        log.record(action="shell_command", actor="a", target="cmd1", result="denied")
        log.record(action="shell_command", actor="a", target="cmd2", result="allowed")
        log.record(action="file_read", actor="a", target="f3", result="allowed")
        log.append(audit_file)

        # Load and verify — exactly 5 entries, not 7
        loaded = AuditLog.load(audit_file, session_id="session-002")
        assert len(loaded.entries) == 5

        # Hash chain is intact
        assert loaded.verify()


# ===========================================================================
# SG-4.3: Tampered file detected by verify()
# ===========================================================================


class TestTamperDetection:
    """SG-4.3: Tampered file fails verify()."""

    def test_tampered_entry_detected(self, tmp_path: Path) -> None:
        """Modify one line in the JSONL, verify() returns False."""
        log = AuditLog("session-003")
        log.record(action="file_write", actor="a", target="f1", result="allowed")
        log.record(action="shell_command", actor="a", target="cmd", result="denied")
        log.record(action="file_read", actor="a", target="f2", result="allowed")

        audit_file = tmp_path / "audit.jsonl"
        log.save(audit_file)

        # Tamper: change the second entry's result from "denied" to "allowed"
        lines = audit_file.read_text().strip().split("\n")
        entry = json.loads(lines[1])
        entry["result"] = "allowed"
        lines[1] = json.dumps(entry, ensure_ascii=True)
        audit_file.write_text("\n".join(lines) + "\n")

        # Load and verify — should detect tampering
        loaded = AuditLog.load(audit_file, session_id="session-003")
        assert not loaded.verify()


# ===========================================================================
# SG-4.4: Query filters work on loaded log
# ===========================================================================


class TestQueryFilters:
    """SG-4.4: Query filters work after save/load cycle."""

    @pytest.fixture()
    def loaded_log(self, tmp_path: Path) -> AuditLog:
        """Create, save, and load a log with varied entries."""
        log = AuditLog("session-004")
        log.record(action="file_write", actor="agent", target="f1", result="allowed")
        log.record(action="shell_command", actor="agent", target="ls", result="allowed")
        log.record(action="shell_command", actor="admin", target="rm", result="denied")
        log.record(action="llm_request", actor="proxy", target="/v1", result="allowed")
        log.record(action="file_write", actor="agent", target="f2", result="denied")
        log.record(
            action="shell_command", actor="agent", target="echo", result="allowed"
        )

        audit_file = tmp_path / "audit.jsonl"
        log.save(audit_file)
        return AuditLog.load(audit_file, session_id="session-004")

    def test_query_by_action(self, loaded_log: AuditLog) -> None:
        """Query by action returns only matching entries."""
        results = loaded_log.query(action="shell_command")
        assert len(results) == 3
        assert all(e.action == "shell_command" for e in results)

    def test_query_by_result(self, loaded_log: AuditLog) -> None:
        """Query by result returns only matching entries."""
        results = loaded_log.query(result="denied")
        assert len(results) == 2
        assert all(e.result == "denied" for e in results)

    def test_query_combined_filters(self, loaded_log: AuditLog) -> None:
        """Query with action AND result returns intersection."""
        results = loaded_log.query(action="file_write", result="allowed")
        assert len(results) == 1
        assert results[0].target == "f1"


# ===========================================================================
# SG-4.5: Middleware audit_dir writes valid JSONL
# ===========================================================================


class TestMiddlewareAuditDir:
    """SG-4.5: Proxy middleware writes valid JSONL to audit_dir."""

    def test_middleware_writes_valid_jsonl(self, tmp_path: Path) -> None:
        """Send requests through proxy, verify JSONL on disk."""
        from unittest.mock import AsyncMock, patch

        from starlette.testclient import TestClient

        from agentguard.proxy.app import create_app
        from agentguard.proxy.config import ProxyConfig

        audit_dir = tmp_path / "audit"
        policy_dir = tmp_path / "policies"
        policy_dir.mkdir()

        # Policy that denies "BLOCKED" in llm_request
        (policy_dir / "deny-blocked.yaml").write_text(
            "name: deny-blocked\n"
            "description: Block BLOCKED keyword\n"
            "rules:\n"
            "  - action: llm_request\n"
            "    deny:\n"
            "      - pattern: 'BLOCKED'\n"
            "    severity: critical\n"
        )

        config = ProxyConfig(
            upstream_base_url="https://api.example.com",
            policy_dir=str(policy_dir),
            audit_dir=str(audit_dir),
        )
        app = create_app(config)
        client = TestClient(app, raise_server_exceptions=False)

        # Mock the upstream to avoid real network calls
        import httpx

        mock_response = httpx.Response(
            200,
            json={"choices": [{"message": {"content": "Hello"}}]},
        )

        with patch.object(
            app.state.middleware,
            "_forward_request",
            new_callable=AsyncMock,
            return_value=mock_response,
        ):
            # Request 1: denied
            client.post(
                "/v1/chat/completions",
                json={
                    "model": "gpt-4",
                    "messages": [{"role": "user", "content": "do BLOCKED thing"}],
                },
            )
            # Request 2: allowed
            client.post(
                "/v1/chat/completions",
                json={
                    "model": "gpt-4",
                    "messages": [{"role": "user", "content": "Hello"}],
                },
            )
            # Request 3: allowed
            client.post(
                "/v1/chat/completions",
                json={
                    "model": "gpt-4",
                    "messages": [{"role": "user", "content": "How are you?"}],
                },
            )

        # Find the JSONL file
        jsonl_files = list(audit_dir.glob("*.jsonl"))
        assert len(jsonl_files) == 1
        jsonl_file = jsonl_files[0]

        # Verify the file name matches the session ID
        session_id = app.state.middleware.session_id
        assert jsonl_file.name == f"{session_id}.jsonl"

        # Each line must be valid JSON
        lines = [
            line for line in jsonl_file.read_text().strip().split("\n") if line.strip()
        ]
        assert len(lines) == 3

        for line in lines:
            entry = json.loads(line)
            assert "action" in entry
            assert "result" in entry

        # Load and verify hash chain
        loaded = AuditLog.load(jsonl_file, session_id=session_id)
        assert loaded.verify()

        # Query: exactly 1 denied entry
        denied = loaded.query(result="denied")
        assert len(denied) == 1
