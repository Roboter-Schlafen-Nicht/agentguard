"""Tests for cross-session audit report generation.

TDD tests for:
- AuditLog.load_directory: load all JSONL files from a directory
- CrossSessionReport: aggregate statistics across sessions
- generate_cross_session_report: end-to-end report generation
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from agentguard.audit.log import AuditLog
from agentguard.audit.models import AuditEntry
from agentguard.audit.report import CrossSessionReport, generate_cross_session_report

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _create_session(
    audit_dir: Path,
    session_id: str,
    entries: list[dict[str, str]],
    *,
    base_time: datetime | None = None,
) -> Path:
    """Create a JSONL audit file in *audit_dir* with hash-chained entries."""
    log = AuditLog(session_id)
    for i, e in enumerate(entries):
        ts = (base_time or datetime(2026, 1, 1, tzinfo=timezone.utc)) + timedelta(
            seconds=i
        )
        entry = AuditEntry(
            action=e.get("action", "shell_execute"),
            actor=e.get("actor", "agent"),
            target=e.get("target", "ls"),
            result=e.get("result", "allowed"),
            timestamp=ts,
            previous_hash=log.entries[-1].entry_hash if log.entries else None,
            metadata=None,
        )
        log._entries.append(entry)

    path = audit_dir / f"{session_id}.jsonl"
    log.save(path)
    return path


# ===========================================================================
# M8.1 — AuditLog.load_directory
# ===========================================================================


class TestLoadDirectory:
    """AuditLog.load_directory loads all .jsonl files from a directory."""

    def test_load_empty_directory(self, tmp_path: Path) -> None:
        """Returns empty list for a directory with no .jsonl files."""
        logs = AuditLog.load_directory(tmp_path)
        assert logs == []

    def test_load_single_file(self, tmp_path: Path) -> None:
        """Loads a single session correctly."""
        _create_session(
            tmp_path,
            "session-001",
            [{"action": "file_write", "target": "main.py", "result": "allowed"}],
        )
        logs = AuditLog.load_directory(tmp_path)
        assert len(logs) == 1
        assert logs[0].session_id == "session-001"
        assert len(logs[0].entries) == 1

    def test_load_multiple_files(self, tmp_path: Path) -> None:
        """Loads multiple sessions from a directory."""
        _create_session(tmp_path, "sess-a", [{"action": "a"}])
        _create_session(tmp_path, "sess-b", [{"action": "b"}, {"action": "c"}])
        logs = AuditLog.load_directory(tmp_path)
        assert len(logs) == 2
        session_ids = {log.session_id for log in logs}
        assert session_ids == {"sess-a", "sess-b"}

    def test_ignores_non_jsonl_files(self, tmp_path: Path) -> None:
        """Non-.jsonl files in the directory are ignored."""
        _create_session(tmp_path, "real-session", [{"action": "x"}])
        (tmp_path / "notes.txt").write_text("not a log")
        (tmp_path / "config.yaml").write_text("key: val")
        logs = AuditLog.load_directory(tmp_path)
        assert len(logs) == 1
        assert logs[0].session_id == "real-session"

    def test_session_id_from_filename(self, tmp_path: Path) -> None:
        """Session ID is derived from the filename (minus .jsonl extension)."""
        _create_session(tmp_path, "proxy-abc123", [{"action": "llm_request"}])
        logs = AuditLog.load_directory(tmp_path)
        assert logs[0].session_id == "proxy-abc123"

    def test_nonexistent_directory_raises(self) -> None:
        """Raises FileNotFoundError for a nonexistent directory."""
        with pytest.raises(FileNotFoundError):
            AuditLog.load_directory(Path("/nonexistent/audit/dir"))

    def test_string_path(self, tmp_path: Path) -> None:
        """Accepts a string path in addition to Path objects."""
        _create_session(tmp_path, "s1", [{"action": "a"}])
        logs = AuditLog.load_directory(str(tmp_path))
        assert len(logs) == 1


# ===========================================================================
# M8.2 — CrossSessionReport model
# ===========================================================================


class TestCrossSessionReport:
    """CrossSessionReport contains aggregated statistics."""

    def test_report_attributes(self) -> None:
        """Report has expected attributes with correct types."""
        report = CrossSessionReport(
            total_sessions=3,
            total_entries=42,
            actions_by_type={"shell_execute": 30, "file_write": 12},
            results_summary={"allowed": 35, "denied": 7},
            actors=["agent", "proxy"],
            time_range=(
                datetime(2026, 1, 1, tzinfo=timezone.utc),
                datetime(2026, 1, 2, tzinfo=timezone.utc),
            ),
            sessions_verified=2,
            sessions_failed=1,
            failed_sessions=["sess-bad"],
        )
        assert report.total_sessions == 3
        assert report.total_entries == 42
        assert report.actions_by_type["shell_execute"] == 30
        assert report.results_summary["denied"] == 7
        assert "agent" in report.actors
        assert report.sessions_verified == 2
        assert report.sessions_failed == 1
        assert report.failed_sessions == ["sess-bad"]

    def test_to_dict(self) -> None:
        """Report serializes to a dictionary."""
        t1 = datetime(2026, 1, 1, tzinfo=timezone.utc)
        t2 = datetime(2026, 1, 2, tzinfo=timezone.utc)
        report = CrossSessionReport(
            total_sessions=1,
            total_entries=5,
            actions_by_type={"file_read": 5},
            results_summary={"allowed": 5},
            actors=["agent"],
            time_range=(t1, t2),
            sessions_verified=1,
            sessions_failed=0,
            failed_sessions=[],
        )
        d = report.to_dict()
        assert d["total_sessions"] == 1
        assert d["total_entries"] == 5
        assert d["actions_by_type"] == {"file_read": 5}
        assert d["integrity"]["verified"] == 1
        assert d["integrity"]["failed"] == 0
        assert d["time_range"]["start"] == t1.isoformat()
        assert d["time_range"]["end"] == t2.isoformat()

    def test_to_dict_no_time_range(self) -> None:
        """Report with no entries has None time_range, serialized as null."""
        report = CrossSessionReport(
            total_sessions=0,
            total_entries=0,
            actions_by_type={},
            results_summary={},
            actors=[],
            time_range=None,
            sessions_verified=0,
            sessions_failed=0,
            failed_sessions=[],
        )
        d = report.to_dict()
        assert d["time_range"] is None


# ===========================================================================
# M8.3 — generate_cross_session_report
# ===========================================================================


class TestGenerateCrossSessionReport:
    """End-to-end cross-session report generation."""

    def test_empty_directory(self, tmp_path: Path) -> None:
        """Report for empty directory has zero counts."""
        report = generate_cross_session_report(tmp_path)
        assert report.total_sessions == 0
        assert report.total_entries == 0
        assert report.actions_by_type == {}
        assert report.time_range is None

    def test_single_session_report(self, tmp_path: Path) -> None:
        """Report for a single session file."""
        _create_session(
            tmp_path,
            "sess-1",
            [
                {"action": "shell_execute", "result": "allowed", "actor": "agent"},
                {"action": "file_write", "result": "denied", "actor": "agent"},
                {"action": "shell_execute", "result": "allowed", "actor": "agent"},
            ],
            base_time=datetime(2026, 3, 1, 10, 0, 0, tzinfo=timezone.utc),
        )
        report = generate_cross_session_report(tmp_path)
        assert report.total_sessions == 1
        assert report.total_entries == 3
        assert report.actions_by_type == {"shell_execute": 2, "file_write": 1}
        assert report.results_summary == {"allowed": 2, "denied": 1}
        assert report.actors == ["agent"]
        assert report.sessions_verified == 1
        assert report.sessions_failed == 0

    def test_multi_session_report(self, tmp_path: Path) -> None:
        """Report aggregates across multiple session files."""
        t1 = datetime(2026, 1, 1, tzinfo=timezone.utc)
        t2 = datetime(2026, 2, 1, tzinfo=timezone.utc)
        _create_session(
            tmp_path,
            "sess-a",
            [
                {"action": "llm_request", "result": "allowed", "actor": "proxy"},
            ],
            base_time=t1,
        )
        _create_session(
            tmp_path,
            "sess-b",
            [
                {"action": "shell_execute", "result": "denied", "actor": "agent"},
                {"action": "file_write", "result": "allowed", "actor": "agent"},
            ],
            base_time=t2,
        )
        report = generate_cross_session_report(tmp_path)
        assert report.total_sessions == 2
        assert report.total_entries == 3
        assert report.actions_by_type == {
            "llm_request": 1,
            "shell_execute": 1,
            "file_write": 1,
        }
        assert report.results_summary == {"allowed": 2, "denied": 1}
        assert set(report.actors) == {"proxy", "agent"}
        assert report.sessions_verified == 2
        assert report.time_range is not None
        assert report.time_range[0] == t1
        assert report.time_range[1] == t2 + timedelta(seconds=1)

    def test_tampered_session_detected(self, tmp_path: Path) -> None:
        """A tampered session file is flagged in the report."""
        _create_session(tmp_path, "good", [{"action": "a"}])
        # Create a tampered file
        bad_path = _create_session(tmp_path, "bad", [{"action": "b"}])
        lines = bad_path.read_text().strip().split("\n")
        data = json.loads(lines[0])
        data["result"] = "TAMPERED"
        bad_path.write_text(json.dumps(data) + "\n")

        report = generate_cross_session_report(tmp_path)
        assert report.total_sessions == 2
        assert report.sessions_verified == 1
        assert report.sessions_failed == 1
        assert report.failed_sessions == ["bad"]

    def test_time_range_spans_all_sessions(self, tmp_path: Path) -> None:
        """Time range covers earliest to latest entry across all sessions."""
        early = datetime(2025, 6, 1, tzinfo=timezone.utc)
        late = datetime(2026, 12, 31, tzinfo=timezone.utc)
        _create_session(tmp_path, "old", [{"action": "a"}], base_time=early)
        _create_session(tmp_path, "new", [{"action": "b"}], base_time=late)
        report = generate_cross_session_report(tmp_path)
        assert report.time_range is not None
        assert report.time_range[0] == early
        assert report.time_range[1] == late

    def test_actors_deduplicated_and_sorted(self, tmp_path: Path) -> None:
        """Actors list is deduplicated and sorted."""
        _create_session(
            tmp_path,
            "s1",
            [
                {"actor": "zeta", "action": "a"},
                {"actor": "alpha", "action": "b"},
                {"actor": "zeta", "action": "c"},
            ],
        )
        report = generate_cross_session_report(tmp_path)
        assert report.actors == ["alpha", "zeta"]

    def test_with_time_filter_after(self, tmp_path: Path) -> None:
        """Entries before the `after` cutoff are excluded."""
        old = datetime(2025, 1, 1, tzinfo=timezone.utc)
        new = datetime(2026, 6, 1, tzinfo=timezone.utc)
        _create_session(tmp_path, "old-s", [{"action": "a"}], base_time=old)
        _create_session(tmp_path, "new-s", [{"action": "b"}], base_time=new)
        cutoff = datetime(2026, 1, 1, tzinfo=timezone.utc)
        report = generate_cross_session_report(tmp_path, after=cutoff)
        assert report.total_entries == 1
        assert report.actions_by_type == {"b": 1}

    def test_with_time_filter_before(self, tmp_path: Path) -> None:
        """Entries after the `before` cutoff are excluded."""
        old = datetime(2025, 1, 1, tzinfo=timezone.utc)
        new = datetime(2026, 6, 1, tzinfo=timezone.utc)
        _create_session(tmp_path, "old-s", [{"action": "a"}], base_time=old)
        _create_session(tmp_path, "new-s", [{"action": "b"}], base_time=new)
        cutoff = datetime(2026, 1, 1, tzinfo=timezone.utc)
        report = generate_cross_session_report(tmp_path, before=cutoff)
        assert report.total_entries == 1
        assert report.actions_by_type == {"a": 1}


# ===========================================================================
# M8.4 — CLI: agentguard audit report <dir>
# ===========================================================================


class TestCLIAuditReport:
    """CLI subcommand 'audit report' for cross-session reporting."""

    def test_text_output(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Text format prints a human-readable summary."""
        from agentguard.cli import main

        _create_session(
            tmp_path,
            "s1",
            [
                {"action": "shell_execute", "result": "allowed"},
                {"action": "file_write", "result": "denied"},
            ],
        )
        rc = main(["audit", "report", str(tmp_path)])
        assert rc == 0
        out = capsys.readouterr().out
        assert "Sessions: 1" in out
        assert "Entries: 2" in out
        assert "shell_execute" in out
        assert "denied" in out

    def test_json_output(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """JSON format outputs valid JSON with expected keys."""
        from agentguard.cli import main

        _create_session(tmp_path, "s1", [{"action": "a", "result": "allowed"}])
        rc = main(["audit", "report", str(tmp_path), "--format", "json"])
        assert rc == 0
        data = json.loads(capsys.readouterr().out)
        assert data["total_sessions"] == 1
        assert data["total_entries"] == 1
        assert "integrity" in data

    def test_nonexistent_dir(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Returns exit code 1 for nonexistent directory."""
        from agentguard.cli import main

        rc = main(["audit", "report", "/nonexistent/path"])
        assert rc == 1
        assert "not found" in capsys.readouterr().err.lower()

    def test_tampered_session_warning(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Warns about tampered sessions in text output."""
        from agentguard.cli import main

        bad_path = _create_session(tmp_path, "bad-sess", [{"action": "x"}])
        lines = bad_path.read_text().strip().split("\n")
        data = json.loads(lines[0])
        data["result"] = "TAMPERED"
        bad_path.write_text(json.dumps(data) + "\n")

        rc = main(["audit", "report", str(tmp_path)])
        assert rc == 0
        out = capsys.readouterr().out
        assert "FAILED" in out or "failed" in out
        assert "bad-sess" in out
