"""Tests for audit log rotation (M8 — Audit Hardening).

Covers:
- RotationConfig data model
- Size-based rotation during append()
- Time-based rotation during append()
- Rotated file naming and discovery
- Hash chain integrity across rotated files
- No rotation without config (backward compatibility)
"""

from __future__ import annotations

import json
import time
from typing import TYPE_CHECKING

import pytest

from agentguard.audit.log import AuditLog
from agentguard.audit.rotation import RotationConfig

if TYPE_CHECKING:
    from pathlib import Path


class TestRotationConfig:
    """RotationConfig data model."""

    def test_default_values(self) -> None:
        """Default config has no limits."""
        cfg = RotationConfig()
        assert cfg.max_bytes is None
        assert cfg.max_age_seconds is None

    def test_max_bytes_only(self) -> None:
        cfg = RotationConfig(max_bytes=1024)
        assert cfg.max_bytes == 1024
        assert cfg.max_age_seconds is None

    def test_max_age_seconds_only(self) -> None:
        cfg = RotationConfig(max_age_seconds=3600)
        assert cfg.max_age_seconds == 3600
        assert cfg.max_bytes is None

    def test_both_limits(self) -> None:
        cfg = RotationConfig(max_bytes=1024, max_age_seconds=3600)
        assert cfg.max_bytes == 1024
        assert cfg.max_age_seconds == 3600

    def test_max_bytes_must_be_positive(self) -> None:
        with pytest.raises(ValueError, match="max_bytes"):
            RotationConfig(max_bytes=0)

    def test_max_bytes_negative_raises(self) -> None:
        with pytest.raises(ValueError, match="max_bytes"):
            RotationConfig(max_bytes=-1)

    def test_max_age_must_be_positive(self) -> None:
        with pytest.raises(ValueError, match="max_age_seconds"):
            RotationConfig(max_age_seconds=0)

    def test_max_age_negative_raises(self) -> None:
        with pytest.raises(ValueError, match="max_age_seconds"):
            RotationConfig(max_age_seconds=-1)

    def test_should_rotate_no_limits(self) -> None:
        """No limits means never rotate."""
        cfg = RotationConfig()
        assert cfg.should_rotate(file_bytes=999999, file_age=999999) is False

    def test_should_rotate_by_size(self) -> None:
        cfg = RotationConfig(max_bytes=100)
        assert cfg.should_rotate(file_bytes=50, file_age=0) is False
        assert cfg.should_rotate(file_bytes=100, file_age=0) is True
        assert cfg.should_rotate(file_bytes=150, file_age=0) is True

    def test_should_rotate_by_age(self) -> None:
        cfg = RotationConfig(max_age_seconds=60)
        assert cfg.should_rotate(file_bytes=0, file_age=30) is False
        assert cfg.should_rotate(file_bytes=0, file_age=60) is True
        assert cfg.should_rotate(file_bytes=0, file_age=120) is True

    def test_should_rotate_either_triggers(self) -> None:
        """Rotation triggers if EITHER limit is exceeded."""
        cfg = RotationConfig(max_bytes=100, max_age_seconds=60)
        # Neither exceeded
        assert cfg.should_rotate(file_bytes=50, file_age=30) is False
        # Size exceeded only
        assert cfg.should_rotate(file_bytes=200, file_age=30) is True
        # Age exceeded only
        assert cfg.should_rotate(file_bytes=50, file_age=120) is True
        # Both exceeded
        assert cfg.should_rotate(file_bytes=200, file_age=120) is True


class TestAppendWithRotation:
    """Rotation during append()."""

    def _record_entries(self, log: AuditLog, count: int) -> None:
        """Record multiple entries into an audit log."""
        for i in range(count):
            log.record(
                action=f"action-{i}",
                actor="agent",
                target=f"target-{i}",
                result="allowed",
            )

    def test_no_rotation_without_config(self, tmp_path: Path) -> None:
        """Without RotationConfig, append behaves as before."""
        log_file = tmp_path / "session.jsonl"
        log = AuditLog(session_id="test")
        self._record_entries(log, 10)
        log.append(log_file)

        # Single file, all entries
        jsonl_files = list(tmp_path.glob("*.jsonl"))
        assert len(jsonl_files) == 1
        lines = log_file.read_text().strip().split("\n")
        assert len(lines) == 10

    def test_size_rotation_creates_new_file(self, tmp_path: Path) -> None:
        """When file exceeds max_bytes, rotation occurs."""
        log_file = tmp_path / "session.jsonl"
        cfg = RotationConfig(max_bytes=100)
        log = AuditLog(session_id="test")

        # Record one entry, append to create the file
        log.record(
            action="first",
            actor="agent",
            target="target",
            result="allowed",
        )
        log.append(log_file, rotation=cfg)

        # File should exist and be > 100 bytes (one JSON line)
        assert log_file.exists()
        first_size = log_file.stat().st_size
        assert first_size > 100  # A single JSON entry is ~200 bytes

        # Record another entry — should trigger rotation
        log.record(
            action="second",
            actor="agent",
            target="target",
            result="allowed",
        )
        log.append(log_file, rotation=cfg)

        # Now there should be 2 .jsonl files
        jsonl_files = sorted(tmp_path.glob("*.jsonl"))
        assert len(jsonl_files) == 2

        # The active file should be the original name
        assert log_file.exists()

        # The rotated file should contain the old data
        rotated = [f for f in jsonl_files if f != log_file]
        assert len(rotated) == 1
        rotated_lines = rotated[0].read_text().strip().split("\n")
        assert len(rotated_lines) == 1
        assert json.loads(rotated_lines[0])["action"] == "first"

        # The active file should contain the new entry
        active_lines = log_file.read_text().strip().split("\n")
        assert len(active_lines) == 1
        assert json.loads(active_lines[0])["action"] == "second"

    def test_rotated_file_naming(self, tmp_path: Path) -> None:
        """Rotated files follow {session_id}.{timestamp}.jsonl."""
        log_file = tmp_path / "my-session.jsonl"
        cfg = RotationConfig(max_bytes=1)  # Force immediate rotation
        log = AuditLog(session_id="my-session")

        log.record(action="a", actor="x", target="t", result="ok")
        log.append(log_file, rotation=cfg)

        # Force rotation on next append
        log.record(action="b", actor="x", target="t", result="ok")
        log.append(log_file, rotation=cfg)

        rotated = [f for f in sorted(tmp_path.glob("*.jsonl")) if f != log_file]
        assert len(rotated) == 1
        # Name should start with session_id and have a timestamp
        name = rotated[0].stem  # e.g. my-session.20260316T010203
        assert name.startswith("my-session.")

    def test_multiple_rotations(self, tmp_path: Path) -> None:
        """Multiple rotations produce multiple archived files."""
        log_file = tmp_path / "sess.jsonl"
        cfg = RotationConfig(max_bytes=1)  # Rotate every time
        log = AuditLog(session_id="sess")

        for i in range(5):
            log.record(
                action=f"a{i}",
                actor="x",
                target="t",
                result="ok",
            )
            log.append(log_file, rotation=cfg)
            # Small delay to ensure unique timestamps
            time.sleep(0.01)

        jsonl_files = list(tmp_path.glob("*.jsonl"))
        # Should have 1 active + 4 rotated files
        assert len(jsonl_files) == 5

        # Active file should have exactly 1 entry (the last one)
        active_lines = log_file.read_text().strip().split("\n")
        assert len(active_lines) == 1
        assert json.loads(active_lines[0])["action"] == "a4"

    def test_all_entries_preserved_after_rotation(self, tmp_path: Path) -> None:
        """Total entries across all files equals entries recorded."""
        log_file = tmp_path / "sess.jsonl"
        cfg = RotationConfig(max_bytes=1)  # Rotate every time
        log = AuditLog(session_id="sess")

        for i in range(5):
            log.record(
                action=f"a{i}",
                actor="x",
                target="t",
                result="ok",
            )
            log.append(log_file, rotation=cfg)
            time.sleep(0.01)

        # Load all files in the directory
        total_entries = 0
        for f in tmp_path.glob("*.jsonl"):
            lines = f.read_text().strip().split("\n")
            total_entries += len(lines)
        assert total_entries == 5

    def test_load_directory_includes_rotated(self, tmp_path: Path) -> None:
        """load_directory() picks up rotated files."""
        log_file = tmp_path / "sess.jsonl"
        cfg = RotationConfig(max_bytes=1)
        log = AuditLog(session_id="sess")

        for i in range(3):
            log.record(
                action=f"a{i}",
                actor="x",
                target="t",
                result="ok",
            )
            log.append(log_file, rotation=cfg)
            time.sleep(0.01)

        logs = AuditLog.load_directory(tmp_path)
        total = sum(len(lg.entries) for lg in logs)
        assert total == 3

    def test_rotation_preserves_chain_in_memory(self, tmp_path: Path) -> None:
        """In-memory hash chain remains valid after rotation."""
        log_file = tmp_path / "sess.jsonl"
        cfg = RotationConfig(max_bytes=1)
        log = AuditLog(session_id="sess")

        for i in range(5):
            log.record(
                action=f"a{i}",
                actor="x",
                target="t",
                result="ok",
            )
            log.append(log_file, rotation=cfg)
            time.sleep(0.01)

        # In-memory chain should be fully intact
        assert log.verify() is True
        assert len(log.entries) == 5

    def test_each_rotated_file_is_loadable(self, tmp_path: Path) -> None:
        """Each rotated file loads independently."""
        log_file = tmp_path / "sess.jsonl"
        cfg = RotationConfig(max_bytes=1)
        log = AuditLog(session_id="sess")

        for i in range(3):
            log.record(
                action=f"a{i}",
                actor="x",
                target="t",
                result="ok",
            )
            log.append(log_file, rotation=cfg)
            time.sleep(0.01)

        for f in tmp_path.glob("*.jsonl"):
            loaded = AuditLog.load(f, session_id=f.stem)
            assert len(loaded.entries) >= 1

    def test_no_rotation_when_file_does_not_exist(self, tmp_path: Path) -> None:
        """First append creates file without rotation check."""
        log_file = tmp_path / "new.jsonl"
        cfg = RotationConfig(max_bytes=1)  # Tiny limit
        log = AuditLog(session_id="new")

        log.record(
            action="first",
            actor="x",
            target="t",
            result="ok",
        )
        log.append(log_file, rotation=cfg)

        # Should create the file with 1 entry, no rotation
        jsonl_files = list(tmp_path.glob("*.jsonl"))
        assert len(jsonl_files) == 1
        assert jsonl_files[0] == log_file

    def test_age_rotation(self, tmp_path: Path) -> None:
        """Time-based rotation triggers when file age exceeds limit."""
        log_file = tmp_path / "sess.jsonl"
        # Use age-based rotation with a very short threshold
        cfg = RotationConfig(max_age_seconds=0.05)
        log = AuditLog(session_id="sess")

        log.record(
            action="old",
            actor="x",
            target="t",
            result="ok",
        )
        log.append(log_file, rotation=cfg)

        # Wait for the file to "age"
        time.sleep(0.1)

        log.record(
            action="new",
            actor="x",
            target="t",
            result="ok",
        )
        log.append(log_file, rotation=cfg)

        jsonl_files = list(tmp_path.glob("*.jsonl"))
        assert len(jsonl_files) == 2

    def test_append_without_rotation_kwarg(self, tmp_path: Path) -> None:
        """append() without rotation= still works (backward compat)."""
        log_file = tmp_path / "sess.jsonl"
        log = AuditLog(session_id="sess")
        log.record(action="a", actor="x", target="t", result="ok")
        log.append(log_file)  # No rotation kwarg
        assert log_file.exists()
        lines = log_file.read_text().strip().split("\n")
        assert len(lines) == 1

    def test_batch_entries_written_after_rotation(self, tmp_path: Path) -> None:
        """Multiple new entries are written correctly after rotation."""
        log_file = tmp_path / "sess.jsonl"
        cfg = RotationConfig(max_bytes=1)
        log = AuditLog(session_id="sess")

        # First append — creates file
        log.record(
            action="a0",
            actor="x",
            target="t",
            result="ok",
        )
        log.append(log_file, rotation=cfg)

        # Record 3 entries at once, then append
        for i in range(1, 4):
            log.record(
                action=f"a{i}",
                actor="x",
                target="t",
                result="ok",
            )
        log.append(log_file, rotation=cfg)

        # Active file should contain the 3 new entries
        active_lines = log_file.read_text().strip().split("\n")
        assert len(active_lines) == 3

        # Rotated file should contain the first entry
        rotated = [f for f in sorted(tmp_path.glob("*.jsonl")) if f != log_file]
        assert len(rotated) == 1
        rotated_lines = rotated[0].read_text().strip().split("\n")
        assert len(rotated_lines) == 1


class TestRotationCLI:
    """CLI integration for rotation config."""

    def test_serve_accepts_rotation_flags(self) -> None:
        """CLI serve command accepts --max-log-bytes
        and --max-log-age flags."""
        from agentguard.cli import _build_parser

        parser = _build_parser()
        args = parser.parse_args(
            [
                "serve",
                "--audit-dir",
                "/tmp/audit",
                "--max-log-bytes",
                "1048576",
                "--max-log-age",
                "3600",
            ]
        )
        assert args.max_log_bytes == 1048576
        assert args.max_log_age == 3600

    def test_proxy_accepts_rotation_flags(self) -> None:
        """CLI proxy command accepts --max-log-bytes
        and --max-log-age flags."""
        from agentguard.cli import _build_parser

        parser = _build_parser()
        args = parser.parse_args(
            [
                "proxy",
                "http://localhost:8080",
                "--audit-dir",
                "/tmp/audit",
                "--max-log-bytes",
                "1048576",
                "--max-log-age",
                "3600",
            ]
        )
        assert args.max_log_bytes == 1048576
        assert args.max_log_age == 3600
