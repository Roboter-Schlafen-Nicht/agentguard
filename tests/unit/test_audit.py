"""Tests for audit logging (M2.1-M2.5).

Covers:
- AuditEntry data model (M2.1)
- Hash-chained append-only log (M2.2)
- File-based JSONL backend (M2.3)
- Integrity verification (M2.4)
- Query API (M2.5)
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from agentguard.audit.log import AuditLog
from agentguard.audit.models import AuditEntry


class TestAuditEntry:
    """M2.1: AuditEntry data model."""

    def test_create_entry(self) -> None:
        entry = AuditEntry(
            action="shell_command",
            actor="agent-001",
            target="git push origin main",
            result="allowed",
        )
        assert entry.action == "shell_command"
        assert entry.actor == "agent-001"
        assert entry.target == "git push origin main"
        assert entry.result == "allowed"

    def test_entry_has_timestamp(self) -> None:
        before = datetime.now(tz=timezone.utc)
        entry = AuditEntry(action="test", actor="a", target="t", result="ok")
        after = datetime.now(tz=timezone.utc)
        assert before <= entry.timestamp <= after

    def test_entry_has_hash(self) -> None:
        entry = AuditEntry(action="test", actor="a", target="t", result="ok")
        assert entry.entry_hash is not None
        assert isinstance(entry.entry_hash, str)
        assert len(entry.entry_hash) == 64  # SHA-256 hex

    def test_entry_hash_is_deterministic(self) -> None:
        """Same data + same timestamp = same hash."""
        ts = datetime(2026, 1, 1, tzinfo=timezone.utc)
        e1 = AuditEntry(action="a", actor="b", target="c", result="d", timestamp=ts)
        e2 = AuditEntry(action="a", actor="b", target="c", result="d", timestamp=ts)
        assert e1.entry_hash == e2.entry_hash

    def test_entry_hash_changes_with_data(self) -> None:
        ts = datetime(2026, 1, 1, tzinfo=timezone.utc)
        e1 = AuditEntry(action="a", actor="b", target="c", result="d", timestamp=ts)
        e2 = AuditEntry(action="X", actor="b", target="c", result="d", timestamp=ts)
        assert e1.entry_hash != e2.entry_hash

    def test_entry_has_previous_hash(self) -> None:
        entry = AuditEntry(
            action="test",
            actor="a",
            target="t",
            result="ok",
            previous_hash="abc123",
        )
        assert entry.previous_hash == "abc123"

    def test_entry_default_previous_hash_is_none(self) -> None:
        entry = AuditEntry(action="test", actor="a", target="t", result="ok")
        assert entry.previous_hash is None

    def test_entry_to_dict(self) -> None:
        ts = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        entry = AuditEntry(
            action="file_write",
            actor="agent-1",
            target="main.py",
            result="denied",
            timestamp=ts,
            previous_hash="prev",
        )
        d = entry.to_dict()
        assert d["action"] == "file_write"
        assert d["actor"] == "agent-1"
        assert d["target"] == "main.py"
        assert d["result"] == "denied"
        assert d["timestamp"] == "2026-01-01T12:00:00+00:00"
        assert d["previous_hash"] == "prev"
        assert "entry_hash" in d

    def test_entry_from_dict(self) -> None:
        ts = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        original = AuditEntry(
            action="test",
            actor="a",
            target="t",
            result="ok",
            timestamp=ts,
            previous_hash="prev",
        )
        restored = AuditEntry.from_dict(original.to_dict())
        assert restored.action == original.action
        assert restored.actor == original.actor
        assert restored.target == original.target
        assert restored.result == original.result
        assert restored.timestamp == original.timestamp
        assert restored.previous_hash == original.previous_hash
        assert restored.entry_hash == original.entry_hash

    def test_entry_with_metadata(self) -> None:
        entry = AuditEntry(
            action="test",
            actor="a",
            target="t",
            result="ok",
            metadata={"policy": "no-force-push", "severity": "critical"},
        )
        assert entry.metadata == {"policy": "no-force-push", "severity": "critical"}

    def test_metadata_in_dict_roundtrip(self) -> None:
        entry = AuditEntry(
            action="test",
            actor="a",
            target="t",
            result="ok",
            metadata={"key": "value"},
        )
        restored = AuditEntry.from_dict(entry.to_dict())
        assert restored.metadata == {"key": "value"}


class TestAuditLogRecord:
    """M2.2: Hash-chained append-only log."""

    def test_record_returns_entry(self) -> None:
        log = AuditLog(session_id="test-session")
        entry = log.record(action="test", actor="a", target="t", result="ok")
        assert isinstance(entry, AuditEntry)

    def test_record_stores_entry(self) -> None:
        log = AuditLog(session_id="test-session")
        log.record(action="test", actor="a", target="t", result="ok")
        assert len(log.entries) == 1

    def test_first_entry_has_no_previous_hash(self) -> None:
        log = AuditLog(session_id="test-session")
        entry = log.record(action="test", actor="a", target="t", result="ok")
        assert entry.previous_hash is None

    def test_second_entry_chains_to_first(self) -> None:
        log = AuditLog(session_id="test-session")
        e1 = log.record(action="a1", actor="a", target="t", result="ok")
        e2 = log.record(action="a2", actor="a", target="t", result="ok")
        assert e2.previous_hash == e1.entry_hash

    def test_chain_of_three_entries(self) -> None:
        log = AuditLog(session_id="test-session")
        e1 = log.record(action="a1", actor="a", target="t", result="ok")
        e2 = log.record(action="a2", actor="a", target="t", result="ok")
        e3 = log.record(action="a3", actor="a", target="t", result="ok")
        assert e1.previous_hash is None
        assert e2.previous_hash == e1.entry_hash
        assert e3.previous_hash == e2.entry_hash

    def test_session_id(self) -> None:
        log = AuditLog(session_id="my-session")
        assert log.session_id == "my-session"

    def test_record_with_metadata(self) -> None:
        log = AuditLog(session_id="test-session")
        entry = log.record(
            action="test",
            actor="a",
            target="t",
            result="denied",
            metadata={"policy": "no-force-push"},
        )
        assert entry.metadata == {"policy": "no-force-push"}

    def test_entries_are_immutable_copy(self) -> None:
        """entries property returns a copy, not the internal list."""
        log = AuditLog(session_id="test-session")
        log.record(action="a1", actor="a", target="t", result="ok")
        entries = log.entries
        entries.clear()
        assert len(log.entries) == 1  # internal state unchanged


class TestAuditLogFile:
    """M2.3: File-based JSONL backend."""

    def test_save_creates_file(self, tmp_path: Path) -> None:
        log_file = tmp_path / "audit.jsonl"
        log = AuditLog(session_id="test-session")
        log.record(action="test", actor="a", target="t", result="ok")
        log.save(log_file)
        assert log_file.exists()

    def test_save_writes_jsonl(self, tmp_path: Path) -> None:
        log_file = tmp_path / "audit.jsonl"
        log = AuditLog(session_id="test-session")
        log.record(action="a1", actor="a", target="t", result="ok")
        log.record(action="a2", actor="a", target="t", result="ok")
        log.save(log_file)
        lines = log_file.read_text().strip().split("\n")
        assert len(lines) == 2
        # Each line is valid JSON
        for line in lines:
            data = json.loads(line)
            assert "action" in data
            assert "entry_hash" in data

    def test_load_from_file(self, tmp_path: Path) -> None:
        log_file = tmp_path / "audit.jsonl"
        log = AuditLog(session_id="test-session")
        log.record(action="a1", actor="a", target="t1", result="ok")
        log.record(action="a2", actor="a", target="t2", result="denied")
        log.save(log_file)

        loaded = AuditLog.load(log_file, session_id="test-session")
        assert len(loaded.entries) == 2
        assert loaded.entries[0].action == "a1"
        assert loaded.entries[1].action == "a2"

    def test_load_preserves_chain(self, tmp_path: Path) -> None:
        log_file = tmp_path / "audit.jsonl"
        log = AuditLog(session_id="test-session")
        log.record(action="a1", actor="a", target="t", result="ok")
        log.record(action="a2", actor="a", target="t", result="ok")
        log.save(log_file)

        loaded = AuditLog.load(log_file, session_id="test-session")
        assert loaded.entries[1].previous_hash == loaded.entries[0].entry_hash

    def test_append_to_existing_file(self, tmp_path: Path) -> None:
        log_file = tmp_path / "audit.jsonl"
        log = AuditLog(session_id="test-session")
        log.record(action="a1", actor="a", target="t", result="ok")
        log.save(log_file)

        # Load and add more entries
        loaded = AuditLog.load(log_file, session_id="test-session")
        loaded.record(action="a2", actor="a", target="t", result="ok")
        loaded.save(log_file)

        final = AuditLog.load(log_file, session_id="test-session")
        assert len(final.entries) == 2

    def test_load_nonexistent_file_raises(self) -> None:
        with pytest.raises(FileNotFoundError):
            AuditLog.load(Path("/nonexistent/audit.jsonl"), session_id="s")

    def test_save_with_string_path(self, tmp_path: Path) -> None:
        log_file = str(tmp_path / "audit.jsonl")
        log = AuditLog(session_id="test-session")
        log.record(action="test", actor="a", target="t", result="ok")
        log.save(log_file)
        assert Path(log_file).exists()


class TestAuditLogVerify:
    """M2.4: Integrity verification."""

    def test_empty_log_verifies(self) -> None:
        log = AuditLog(session_id="test-session")
        assert log.verify() is True

    def test_single_entry_verifies(self) -> None:
        log = AuditLog(session_id="test-session")
        log.record(action="test", actor="a", target="t", result="ok")
        assert log.verify() is True

    def test_chain_verifies(self) -> None:
        log = AuditLog(session_id="test-session")
        for i in range(5):
            log.record(action=f"a{i}", actor="a", target="t", result="ok")
        assert log.verify() is True

    def test_tampered_entry_fails(self) -> None:
        log = AuditLog(session_id="test-session")
        log.record(action="a1", actor="a", target="t", result="ok")
        log.record(action="a2", actor="a", target="t", result="ok")
        # Tamper with the first entry's hash
        log._entries[0] = AuditEntry(
            action="TAMPERED",
            actor=log._entries[0].actor,
            target=log._entries[0].target,
            result=log._entries[0].result,
            timestamp=log._entries[0].timestamp,
            previous_hash=log._entries[0].previous_hash,
        )
        assert log.verify() is False

    def test_broken_chain_fails(self) -> None:
        log = AuditLog(session_id="test-session")
        log.record(action="a1", actor="a", target="t", result="ok")
        log.record(action="a2", actor="a", target="t", result="ok")
        # Replace second entry with wrong previous_hash
        log._entries[1] = AuditEntry(
            action="a2",
            actor="a",
            target="t",
            result="ok",
            timestamp=log._entries[1].timestamp,
            previous_hash="wrong-hash",
        )
        assert log.verify() is False

    def test_verify_after_save_load(self, tmp_path: Path) -> None:
        log_file = tmp_path / "audit.jsonl"
        log = AuditLog(session_id="test-session")
        for i in range(3):
            log.record(action=f"a{i}", actor="a", target="t", result="ok")
        log.save(log_file)

        loaded = AuditLog.load(log_file, session_id="test-session")
        assert loaded.verify() is True

    def test_verify_tampered_file(self, tmp_path: Path) -> None:
        log_file = tmp_path / "audit.jsonl"
        log = AuditLog(session_id="test-session")
        log.record(action="a1", actor="a", target="t", result="ok")
        log.record(action="a2", actor="a", target="t", result="ok")
        log.save(log_file)

        # Tamper with file: modify second line
        lines = log_file.read_text().strip().split("\n")
        data = json.loads(lines[1])
        data["action"] = "TAMPERED"
        lines[1] = json.dumps(data)
        log_file.write_text("\n".join(lines) + "\n")

        loaded = AuditLog.load(log_file, session_id="test-session")
        assert loaded.verify() is False


class TestAuditLogQuery:
    """M2.5: Query API."""

    def _make_log_with_entries(self) -> AuditLog:
        log = AuditLog(session_id="test-session")
        log.record(
            action="shell_command",
            actor="agent-1",
            target="ls",
            result="allowed",
        )
        log.record(
            action="file_write",
            actor="agent-2",
            target="main.py",
            result="denied",
        )
        log.record(
            action="shell_command",
            actor="agent-1",
            target="git push",
            result="allowed",
        )
        log.record(
            action="api_call",
            actor="agent-3",
            target="https://api.example.com",
            result="allowed",
        )
        log.record(
            action="file_write",
            actor="agent-1",
            target="config.py",
            result="denied",
        )
        return log

    def test_query_by_action(self) -> None:
        log = self._make_log_with_entries()
        results = log.query(action="shell_command")
        assert len(results) == 2
        assert all(e.action == "shell_command" for e in results)

    def test_query_by_actor(self) -> None:
        log = self._make_log_with_entries()
        results = log.query(actor="agent-1")
        assert len(results) == 3
        assert all(e.actor == "agent-1" for e in results)

    def test_query_by_result(self) -> None:
        log = self._make_log_with_entries()
        results = log.query(result="denied")
        assert len(results) == 2
        assert all(e.result == "denied" for e in results)

    def test_query_combined_filters(self) -> None:
        log = self._make_log_with_entries()
        results = log.query(action="file_write", result="denied")
        assert len(results) == 2

    def test_query_combined_actor_action(self) -> None:
        log = self._make_log_with_entries()
        results = log.query(action="shell_command", actor="agent-1")
        assert len(results) == 2

    def test_query_no_match(self) -> None:
        log = self._make_log_with_entries()
        results = log.query(action="nonexistent")
        assert len(results) == 0

    def test_query_no_filters_returns_all(self) -> None:
        log = self._make_log_with_entries()
        results = log.query()
        assert len(results) == 5

    def test_query_by_time_range(self) -> None:
        log = AuditLog(session_id="test-session")
        t1 = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
        t2 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        t3 = datetime(2026, 1, 1, 14, 0, 0, tzinfo=timezone.utc)

        # Manually add entries with specific timestamps
        log._entries.append(
            AuditEntry(
                action="a1",
                actor="a",
                target="t",
                result="ok",
                timestamp=t1,
            )
        )
        log._entries.append(
            AuditEntry(
                action="a2",
                actor="a",
                target="t",
                result="ok",
                timestamp=t2,
                previous_hash=log._entries[0].entry_hash,
            )
        )
        log._entries.append(
            AuditEntry(
                action="a3",
                actor="a",
                target="t",
                result="ok",
                timestamp=t3,
                previous_hash=log._entries[1].entry_hash,
            )
        )

        after = datetime(2026, 1, 1, 11, 0, 0, tzinfo=timezone.utc)
        before = datetime(2026, 1, 1, 13, 0, 0, tzinfo=timezone.utc)
        results = log.query(after=after, before=before)
        assert len(results) == 1
        assert results[0].action == "a2"

    def test_query_after_only(self) -> None:
        log = AuditLog(session_id="test-session")
        t1 = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
        t2 = datetime(2026, 1, 1, 14, 0, 0, tzinfo=timezone.utc)
        log._entries.append(
            AuditEntry(
                action="a1",
                actor="a",
                target="t",
                result="ok",
                timestamp=t1,
            )
        )
        log._entries.append(
            AuditEntry(
                action="a2",
                actor="a",
                target="t",
                result="ok",
                timestamp=t2,
                previous_hash=log._entries[0].entry_hash,
            )
        )

        cutoff = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        results = log.query(after=cutoff)
        assert len(results) == 1
        assert results[0].action == "a2"

    def test_query_returns_list_of_entries(self) -> None:
        log = self._make_log_with_entries()
        results = log.query(action="shell_command")
        assert isinstance(results, list)
        for entry in results:
            assert isinstance(entry, AuditEntry)
