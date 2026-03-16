"""Tests for audit log retention policy (M8 — Audit Hardening).

Covers:
- RetentionConfig data model and validation
- enforce_retention by max_files (keep N most recent)
- enforce_retention by max_age_seconds (delete files older than TTL)
- enforce_retention by max_total_bytes (cap cumulative size)
- Active log file is never deleted
- Empty directory is a no-op
- CLI ``audit purge`` subcommand
- CLI flags on serve/proxy for retention
"""

from __future__ import annotations

import json
import time
from typing import TYPE_CHECKING

import pytest

from agentguard.audit.log import AuditLog
from agentguard.audit.retention import RetentionConfig, enforce_retention

if TYPE_CHECKING:
    from pathlib import Path


def _write_fake_log(path: Path, n_entries: int = 1) -> None:
    """Write a fake JSONL audit log with *n_entries* entries."""
    with path.open("w", encoding="utf-8") as f:
        for i in range(n_entries):
            entry = {
                "action": f"action-{i}",
                "actor": "agent",
                "target": f"t-{i}",
                "result": "allowed",
                "timestamp": "2026-01-01T00:00:00+00:00",
                "previous_hash": None,
                "entry_hash": f"hash-{i}",
            }
            f.write(json.dumps(entry) + "\n")


# ── RetentionConfig data model ──────────────────────────────────


class TestRetentionConfig:
    """RetentionConfig validation and defaults."""

    def test_default_values(self) -> None:
        cfg = RetentionConfig()
        assert cfg.max_files is None
        assert cfg.max_age_seconds is None
        assert cfg.max_total_bytes is None

    def test_max_files_only(self) -> None:
        cfg = RetentionConfig(max_files=10)
        assert cfg.max_files == 10

    def test_max_age_seconds_only(self) -> None:
        cfg = RetentionConfig(max_age_seconds=86400)
        assert cfg.max_age_seconds == 86400

    def test_max_total_bytes_only(self) -> None:
        cfg = RetentionConfig(max_total_bytes=1_000_000)
        assert cfg.max_total_bytes == 1_000_000

    def test_all_fields(self) -> None:
        cfg = RetentionConfig(
            max_files=5,
            max_age_seconds=3600,
            max_total_bytes=500_000,
        )
        assert cfg.max_files == 5
        assert cfg.max_age_seconds == 3600
        assert cfg.max_total_bytes == 500_000

    def test_max_files_must_be_positive(self) -> None:
        with pytest.raises(ValueError, match="max_files"):
            RetentionConfig(max_files=0)

    def test_max_files_negative_raises(self) -> None:
        with pytest.raises(ValueError, match="max_files"):
            RetentionConfig(max_files=-1)

    def test_max_age_seconds_must_be_positive(self) -> None:
        with pytest.raises(ValueError, match="max_age_seconds"):
            RetentionConfig(max_age_seconds=0)

    def test_max_age_seconds_negative_raises(self) -> None:
        with pytest.raises(ValueError, match="max_age_seconds"):
            RetentionConfig(max_age_seconds=-1)

    def test_max_total_bytes_must_be_positive(self) -> None:
        with pytest.raises(ValueError, match="max_total_bytes"):
            RetentionConfig(max_total_bytes=0)

    def test_max_total_bytes_negative_raises(self) -> None:
        with pytest.raises(ValueError, match="max_total_bytes"):
            RetentionConfig(max_total_bytes=-1)

    def test_frozen(self) -> None:
        cfg = RetentionConfig(max_files=5)
        with pytest.raises(AttributeError):
            cfg.max_files = 10  # type: ignore[misc]


# ── enforce_retention: max_files ─────────────────────────────────


class TestEnforceRetentionMaxFiles:
    """Enforce retention by file count."""

    def test_no_deletion_under_limit(self, tmp_path: Path) -> None:
        """Files within max_files limit are kept."""
        for i in range(3):
            _write_fake_log(tmp_path / f"log-{i}.jsonl")
        cfg = RetentionConfig(max_files=5)
        deleted = enforce_retention(tmp_path, cfg)
        assert deleted == []
        assert len(list(tmp_path.glob("*.jsonl"))) == 3

    def test_deletes_oldest_files(self, tmp_path: Path) -> None:
        """Oldest files are deleted when count exceeds max_files."""
        for i in range(5):
            p = tmp_path / f"log-{i:02d}.jsonl"
            _write_fake_log(p)
            time.sleep(0.02)  # ensure distinct mtime

        cfg = RetentionConfig(max_files=2)
        deleted = enforce_retention(tmp_path, cfg)
        assert len(deleted) == 3
        remaining = sorted(f.name for f in tmp_path.glob("*.jsonl"))
        assert len(remaining) == 2
        # The two newest should remain
        assert "log-03.jsonl" in remaining
        assert "log-04.jsonl" in remaining

    def test_exact_limit_no_deletion(self, tmp_path: Path) -> None:
        """Exactly max_files files — nothing deleted."""
        for i in range(3):
            _write_fake_log(tmp_path / f"log-{i}.jsonl")
        cfg = RetentionConfig(max_files=3)
        deleted = enforce_retention(tmp_path, cfg)
        assert deleted == []

    def test_active_log_excluded(self, tmp_path: Path) -> None:
        """Active log file is never deleted."""
        active = tmp_path / "session.jsonl"
        _write_fake_log(active)
        time.sleep(0.02)
        for i in range(3):
            p = tmp_path / f"session.20260101T00000{i}.jsonl"
            _write_fake_log(p)
            time.sleep(0.02)

        cfg = RetentionConfig(max_files=1)
        enforce_retention(
            tmp_path,
            cfg,
            active_file=active,
        )
        # Active file must survive
        assert active.exists()
        # Should keep active + 1 newest rotated = 2 total
        # Actually max_files=1 means keep 1 file (excluding
        # active). So 2 rotated deleted, 1 rotated kept.
        remaining = list(tmp_path.glob("*.jsonl"))
        assert active in remaining


# ── enforce_retention: max_age_seconds ───────────────────────────


class TestEnforceRetentionMaxAge:
    """Enforce retention by file age."""

    def test_no_deletion_when_young(self, tmp_path: Path) -> None:
        """Recent files are kept."""
        for i in range(3):
            _write_fake_log(tmp_path / f"log-{i}.jsonl")
        cfg = RetentionConfig(max_age_seconds=3600)
        deleted = enforce_retention(tmp_path, cfg)
        assert deleted == []

    def test_deletes_old_files(self, tmp_path: Path) -> None:
        """Files older than max_age_seconds are deleted."""
        import os

        old_file = tmp_path / "old.jsonl"
        _write_fake_log(old_file)
        # Backdate the file's mtime by 2 hours
        old_mtime = time.time() - 7200
        os.utime(old_file, (old_mtime, old_mtime))

        new_file = tmp_path / "new.jsonl"
        _write_fake_log(new_file)

        cfg = RetentionConfig(max_age_seconds=3600)
        deleted = enforce_retention(tmp_path, cfg)
        assert len(deleted) == 1
        assert not old_file.exists()
        assert new_file.exists()

    def test_active_file_excluded_from_age(
        self,
        tmp_path: Path,
    ) -> None:
        """Active log is not deleted even if old."""
        import os

        active = tmp_path / "session.jsonl"
        _write_fake_log(active)
        old_mtime = time.time() - 7200
        os.utime(active, (old_mtime, old_mtime))

        cfg = RetentionConfig(max_age_seconds=3600)
        deleted = enforce_retention(
            tmp_path,
            cfg,
            active_file=active,
        )
        assert deleted == []
        assert active.exists()


# ── enforce_retention: max_total_bytes ───────────────────────────


class TestEnforceRetentionMaxTotalBytes:
    """Enforce retention by cumulative file size."""

    def test_no_deletion_under_limit(self, tmp_path: Path) -> None:
        """Total size within limit — nothing deleted."""
        _write_fake_log(tmp_path / "a.jsonl", n_entries=1)
        cfg = RetentionConfig(max_total_bytes=100_000)
        deleted = enforce_retention(tmp_path, cfg)
        assert deleted == []

    def test_deletes_oldest_to_fit(self, tmp_path: Path) -> None:
        """Oldest files deleted until total fits max_total_bytes."""
        for i in range(5):
            p = tmp_path / f"log-{i:02d}.jsonl"
            _write_fake_log(p, n_entries=10)
            time.sleep(0.02)

        # Each file is ~1000-1200 bytes. Total ~5000-6000.
        total = sum(f.stat().st_size for f in tmp_path.glob("*.jsonl"))
        # Set limit to roughly 2 files worth
        limit = total // 3
        cfg = RetentionConfig(max_total_bytes=limit)
        deleted = enforce_retention(tmp_path, cfg)
        assert len(deleted) > 0

        remaining_size = sum(f.stat().st_size for f in tmp_path.glob("*.jsonl"))
        assert remaining_size <= limit

    def test_active_file_excluded_from_size(
        self,
        tmp_path: Path,
    ) -> None:
        """Active log not deleted by size enforcement."""
        active = tmp_path / "session.jsonl"
        _write_fake_log(active, n_entries=100)  # large file

        cfg = RetentionConfig(max_total_bytes=1)  # tiny limit
        enforce_retention(
            tmp_path,
            cfg,
            active_file=active,
        )
        assert active.exists()


# ── enforce_retention: combined ──────────────────────────────────


class TestEnforceRetentionCombined:
    """Multiple retention criteria applied together."""

    def test_all_criteria_applied(self, tmp_path: Path) -> None:
        """When multiple criteria set, all are enforced."""
        import os

        # Create 5 files: 2 old, 3 new
        for i in range(5):
            p = tmp_path / f"log-{i:02d}.jsonl"
            _write_fake_log(p, n_entries=5)
            time.sleep(0.02)

        # Backdate first 2 files
        for i in range(2):
            p = tmp_path / f"log-{i:02d}.jsonl"
            old_mtime = time.time() - 7200
            os.utime(p, (old_mtime, old_mtime))

        cfg = RetentionConfig(
            max_files=10,  # won't trigger
            max_age_seconds=3600,  # will delete 2 old files
        )
        deleted = enforce_retention(tmp_path, cfg)
        assert len(deleted) == 2
        assert len(list(tmp_path.glob("*.jsonl"))) == 3


class TestEnforceRetentionEdgeCases:
    """Edge cases for enforce_retention."""

    def test_empty_directory(self, tmp_path: Path) -> None:
        """Empty directory is a no-op."""
        cfg = RetentionConfig(max_files=1)
        deleted = enforce_retention(tmp_path, cfg)
        assert deleted == []

    def test_nonexistent_directory_raises(self) -> None:
        """Non-existent directory raises FileNotFoundError."""
        from pathlib import Path

        cfg = RetentionConfig(max_files=1)
        with pytest.raises(FileNotFoundError):
            enforce_retention(
                Path("/nonexistent/path"),
                cfg,
            )

    def test_no_config_is_noop(self, tmp_path: Path) -> None:
        """RetentionConfig with all None is a no-op."""
        for i in range(5):
            _write_fake_log(tmp_path / f"log-{i}.jsonl")
        cfg = RetentionConfig()
        deleted = enforce_retention(tmp_path, cfg)
        assert deleted == []
        assert len(list(tmp_path.glob("*.jsonl"))) == 5

    def test_returns_deleted_paths(self, tmp_path: Path) -> None:
        """enforce_retention returns list of deleted file paths."""
        for i in range(5):
            p = tmp_path / f"log-{i:02d}.jsonl"
            _write_fake_log(p)
            time.sleep(0.02)

        cfg = RetentionConfig(max_files=2)
        deleted = enforce_retention(tmp_path, cfg)
        assert len(deleted) == 3
        for p in deleted:
            assert not p.exists()

    def test_only_jsonl_files_considered(
        self,
        tmp_path: Path,
    ) -> None:
        """Non-.jsonl files are ignored."""
        _write_fake_log(tmp_path / "log.jsonl")
        (tmp_path / "readme.txt").write_text("hello")
        (tmp_path / "data.json").write_text("{}")

        cfg = RetentionConfig(max_files=1)
        deleted = enforce_retention(tmp_path, cfg)
        assert deleted == []
        assert (tmp_path / "readme.txt").exists()
        assert (tmp_path / "data.json").exists()


# ── CLI integration ──────────────────────────────────────────────


class TestRetentionCLI:
    """CLI integration for retention config."""

    def test_serve_accepts_retention_flags(self) -> None:
        from agentguard.cli import _build_parser

        parser = _build_parser()
        args = parser.parse_args(
            [
                "serve",
                "--audit-dir",
                "/tmp/audit",
                "--max-log-files",
                "10",
                "--retain-max-age",
                "86400",
                "--retain-max-bytes",
                "10000000",
            ],
        )
        assert args.max_log_files == 10
        assert args.retain_max_age == 86400.0
        assert args.retain_max_bytes == 10_000_000

    def test_proxy_accepts_retention_flags(self) -> None:
        from agentguard.cli import _build_parser

        parser = _build_parser()
        args = parser.parse_args(
            [
                "proxy",
                "http://localhost:8080",
                "--audit-dir",
                "/tmp/audit",
                "--max-log-files",
                "10",
                "--retain-max-age",
                "86400",
                "--retain-max-bytes",
                "10000000",
            ],
        )
        assert args.max_log_files == 10
        assert args.retain_max_age == 86400.0
        assert args.retain_max_bytes == 10_000_000

    def test_build_retention_config_none_when_unset(self) -> None:
        import argparse

        from agentguard.cli import _build_retention_config

        args = argparse.Namespace()
        result = _build_retention_config(args)
        assert result is None

    def test_build_retention_config_with_values(self) -> None:
        import argparse

        from agentguard.cli import _build_retention_config

        args = argparse.Namespace(
            max_log_files=5,
            retain_max_age=3600.0,
            retain_max_bytes=500_000,
        )
        result = _build_retention_config(args)
        assert result is not None
        assert result.max_files == 5
        assert result.max_age_seconds == 3600.0
        assert result.max_total_bytes == 500_000

    def test_audit_purge_subcommand_exists(self) -> None:
        from agentguard.cli import _build_parser

        parser = _build_parser()
        args = parser.parse_args(
            [
                "audit",
                "purge",
                "--audit-dir",
                "/tmp/audit",
                "--max-log-files",
                "5",
            ],
        )
        assert args.audit_command == "purge"
        assert args.audit_dir == "/tmp/audit"
        assert args.max_log_files == 5

    def test_audit_purge_dry_run_flag(self) -> None:
        from agentguard.cli import _build_parser

        parser = _build_parser()
        args = parser.parse_args(
            [
                "audit",
                "purge",
                "--audit-dir",
                "/tmp/audit",
                "--max-log-files",
                "5",
                "--dry-run",
            ],
        )
        assert args.dry_run is True

    def test_audit_purge_runs_enforcement(
        self,
        tmp_path: Path,
    ) -> None:
        """audit purge actually deletes files."""
        from agentguard.cli import main

        for i in range(5):
            p = tmp_path / f"log-{i:02d}.jsonl"
            _write_fake_log(p)
            time.sleep(0.02)

        rc = main(
            [
                "audit",
                "purge",
                "--audit-dir",
                str(tmp_path),
                "--max-log-files",
                "2",
            ],
        )
        assert rc == 0
        remaining = list(tmp_path.glob("*.jsonl"))
        assert len(remaining) == 2

    def test_audit_purge_dry_run_no_delete(
        self,
        tmp_path: Path,
    ) -> None:
        """audit purge --dry-run lists but doesn't delete."""
        from agentguard.cli import main

        for i in range(5):
            p = tmp_path / f"log-{i:02d}.jsonl"
            _write_fake_log(p)
            time.sleep(0.02)

        rc = main(
            [
                "audit",
                "purge",
                "--audit-dir",
                str(tmp_path),
                "--max-log-files",
                "2",
                "--dry-run",
            ],
        )
        assert rc == 0
        remaining = list(tmp_path.glob("*.jsonl"))
        assert len(remaining) == 5  # nothing deleted

    def test_audit_purge_missing_dir_exits_1(self) -> None:
        from agentguard.cli import main

        rc = main(
            [
                "audit",
                "purge",
                "--audit-dir",
                "/nonexistent/dir",
                "--max-log-files",
                "5",
            ],
        )
        assert rc == 1

    def test_audit_purge_no_criteria_exits_1(self) -> None:
        """audit purge with no retention criteria exits with error."""
        from agentguard.cli import main

        rc = main(
            [
                "audit",
                "purge",
                "--audit-dir",
                "/tmp",
            ],
        )
        assert rc == 1


# ── Integration with append() ────────────────────────────────────


class TestAppendWithRetention:
    """Retention enforcement after rotation in append()."""

    def test_retention_enforced_after_rotation(
        self,
        tmp_path: Path,
    ) -> None:
        """Old rotated files are cleaned up during append()."""
        from agentguard.audit.rotation import RotationConfig

        log_file = tmp_path / "sess.jsonl"
        rot_cfg = RotationConfig(max_bytes=1)
        ret_cfg = RetentionConfig(max_files=2)
        log = AuditLog(session_id="sess")

        # Create 5 rotated files + active
        for i in range(6):
            log.record(
                action=f"a{i}",
                actor="x",
                target="t",
                result="ok",
            )
            log.append(
                log_file,
                rotation=rot_cfg,
                retention=ret_cfg,
            )
            time.sleep(0.02)

        # max_files=2 keeps 2 rotated + active = 3 total
        jsonl_files = list(tmp_path.glob("*.jsonl"))
        assert len(jsonl_files) <= 3

    def test_no_retention_without_config(
        self,
        tmp_path: Path,
    ) -> None:
        """Without RetentionConfig, all rotated files are kept."""
        from agentguard.audit.rotation import RotationConfig

        log_file = tmp_path / "sess.jsonl"
        rot_cfg = RotationConfig(max_bytes=1)
        log = AuditLog(session_id="sess")

        for i in range(5):
            log.record(
                action=f"a{i}",
                actor="x",
                target="t",
                result="ok",
            )
            log.append(log_file, rotation=rot_cfg)
            time.sleep(0.02)

        # All 5 files should still exist (4 rotated + 1 active)
        jsonl_files = list(tmp_path.glob("*.jsonl"))
        assert len(jsonl_files) == 5
