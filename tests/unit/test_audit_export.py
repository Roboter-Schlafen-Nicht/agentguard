"""Tests for audit log export (M8 — Audit Hardening).

Covers:
- JSON export (structured array, pretty-printed)
- CSV export (columns from AuditEntry.to_dict)
- SQLite export (typed columns, JSON metadata)
- Empty entry list edge cases
- Metadata serialization in CSV/SQLite
- CLI ``audit export`` subcommand
"""

from __future__ import annotations

import csv
import json
import sqlite3
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from agentguard.audit.log import AuditLog
from agentguard.audit.models import AuditEntry

if TYPE_CHECKING:
    from pathlib import Path


def _make_entries() -> list[AuditEntry]:
    """Create a small set of audit entries for testing."""
    ts = datetime(2026, 3, 21, 12, 0, 0, tzinfo=timezone.utc)
    e1 = AuditEntry(
        action="shell_command",
        actor="agent-1",
        target="ls -la",
        result="allowed",
        timestamp=ts,
        previous_hash=None,
        metadata={"policy": "default"},
    )
    e2 = AuditEntry(
        action="file_write",
        actor="agent-1",
        target="/tmp/test.txt",
        result="denied",
        timestamp=ts,
        previous_hash=e1.entry_hash,
        metadata=None,
    )
    return [e1, e2]


# ── JSON export ───────────────────────────────────────────────────


class TestExportJSON:
    """Tests for export_json()."""

    def test_export_json_produces_valid_json(self, tmp_path: Path) -> None:
        """Exported file is valid JSON containing an array of entry dicts."""
        from agentguard.audit.export import export_json

        entries = _make_entries()
        out = tmp_path / "export.json"
        export_json(entries, out)

        data = json.loads(out.read_text(encoding="utf-8"))
        assert isinstance(data, list)
        assert len(data) == 2
        assert data[0]["action"] == "shell_command"
        assert data[1]["action"] == "file_write"

    def test_export_json_preserves_all_fields(self, tmp_path: Path) -> None:
        """Each entry dict contains all AuditEntry.to_dict() fields."""
        from agentguard.audit.export import export_json

        entries = _make_entries()
        out = tmp_path / "export.json"
        export_json(entries, out)

        data = json.loads(out.read_text(encoding="utf-8"))
        expected_keys = {
            "action",
            "actor",
            "target",
            "result",
            "timestamp",
            "previous_hash",
            "entry_hash",
        }
        # First entry has metadata
        assert expected_keys | {"metadata"} == set(data[0].keys())
        # Second entry has no metadata (not present in dict)
        assert expected_keys == set(data[1].keys())

    def test_export_json_empty_list(self, tmp_path: Path) -> None:
        """Exporting an empty list produces an empty JSON array."""
        from agentguard.audit.export import export_json

        out = tmp_path / "empty.json"
        export_json([], out)

        data = json.loads(out.read_text(encoding="utf-8"))
        assert data == []

    def test_export_json_is_pretty_printed(self, tmp_path: Path) -> None:
        """JSON output is human-readable (indented)."""
        from agentguard.audit.export import export_json

        entries = _make_entries()
        out = tmp_path / "export.json"
        export_json(entries, out)

        text = out.read_text(encoding="utf-8")
        # Indented JSON has newlines between elements
        assert "\n" in text
        # Not a single-line dump
        assert len(text.splitlines()) > 2

    def test_export_json_metadata_preserved(self, tmp_path: Path) -> None:
        """Metadata dict is preserved in JSON output."""
        from agentguard.audit.export import export_json

        entries = _make_entries()
        out = tmp_path / "export.json"
        export_json(entries, out)

        data = json.loads(out.read_text(encoding="utf-8"))
        assert data[0]["metadata"] == {"policy": "default"}

    def test_export_json_returns_entry_count(self, tmp_path: Path) -> None:
        """export_json returns the number of entries written."""
        from agentguard.audit.export import export_json

        entries = _make_entries()
        out = tmp_path / "export.json"
        count = export_json(entries, out)
        assert count == 2

    def test_export_json_returns_zero_for_empty(self, tmp_path: Path) -> None:
        """export_json returns 0 for empty list."""
        from agentguard.audit.export import export_json

        out = tmp_path / "empty.json"
        count = export_json([], out)
        assert count == 0


# ── CSV export ────────────────────────────────────────────────────


class TestExportCSV:
    """Tests for export_csv()."""

    def test_export_csv_produces_valid_csv(self, tmp_path: Path) -> None:
        """Exported file is valid CSV with header row + data rows."""
        from agentguard.audit.export import export_csv

        entries = _make_entries()
        out = tmp_path / "export.csv"
        export_csv(entries, out)

        with out.open(encoding="utf-8") as f:
            reader = csv.reader(f)
            rows = list(reader)

        # Header + 2 data rows
        assert len(rows) == 3
        header = rows[0]
        assert "action" in header
        assert "actor" in header
        assert "entry_hash" in header

    def test_export_csv_column_order(self, tmp_path: Path) -> None:
        """CSV columns follow a consistent order."""
        from agentguard.audit.export import CSV_COLUMNS, export_csv

        entries = _make_entries()
        out = tmp_path / "export.csv"
        export_csv(entries, out)

        with out.open(encoding="utf-8") as f:
            reader = csv.reader(f)
            header = next(reader)

        assert header == list(CSV_COLUMNS)

    def test_export_csv_metadata_as_json(self, tmp_path: Path) -> None:
        """Metadata is serialized as a JSON string in the CSV."""
        from agentguard.audit.export import export_csv

        entries = _make_entries()
        out = tmp_path / "export.csv"
        export_csv(entries, out)

        with out.open(encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        # First entry has metadata
        meta = json.loads(rows[0]["metadata"])
        assert meta == {"policy": "default"}
        # Second entry has no metadata → empty string
        assert rows[1]["metadata"] == ""

    def test_export_csv_empty_list(self, tmp_path: Path) -> None:
        """Exporting an empty list produces a CSV with only the header."""
        from agentguard.audit.export import export_csv

        out = tmp_path / "empty.csv"
        export_csv([], out)

        with out.open(encoding="utf-8") as f:
            reader = csv.reader(f)
            rows = list(reader)

        assert len(rows) == 1  # Header only

    def test_export_csv_returns_entry_count(self, tmp_path: Path) -> None:
        """export_csv returns the number of data rows written."""
        from agentguard.audit.export import export_csv

        entries = _make_entries()
        out = tmp_path / "export.csv"
        count = export_csv(entries, out)
        assert count == 2

    def test_export_csv_special_characters(self, tmp_path: Path) -> None:
        """CSV correctly handles entries with commas, quotes, newlines."""
        from agentguard.audit.export import export_csv

        ts = datetime(2026, 1, 1, tzinfo=timezone.utc)
        entry = AuditEntry(
            action="shell_command",
            actor="agent",
            target='echo "hello, world"\necho done',
            result="allowed",
            timestamp=ts,
        )
        out = tmp_path / "special.csv"
        export_csv([entry], out)

        with out.open(encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        assert len(rows) == 1
        assert 'echo "hello, world"' in rows[0]["target"]


# ── SQLite export ─────────────────────────────────────────────────


class TestExportSQLite:
    """Tests for export_sqlite()."""

    def test_export_sqlite_creates_database(self, tmp_path: Path) -> None:
        """Exported file is a valid SQLite database."""
        from agentguard.audit.export import export_sqlite

        entries = _make_entries()
        out = tmp_path / "export.db"
        export_sqlite(entries, out)

        conn = sqlite3.connect(str(out))
        cursor = conn.execute("SELECT count(*) FROM audit_entries")
        count = cursor.fetchone()[0]
        conn.close()
        assert count == 2

    def test_export_sqlite_column_types(self, tmp_path: Path) -> None:
        """SQLite table has the expected columns."""
        from agentguard.audit.export import export_sqlite

        entries = _make_entries()
        out = tmp_path / "export.db"
        export_sqlite(entries, out)

        conn = sqlite3.connect(str(out))
        cursor = conn.execute("PRAGMA table_info(audit_entries)")
        columns = {row[1]: row[2] for row in cursor.fetchall()}
        conn.close()

        assert "action" in columns
        assert "actor" in columns
        assert "target" in columns
        assert "result" in columns
        assert "timestamp" in columns
        assert "previous_hash" in columns
        assert "entry_hash" in columns
        assert "metadata" in columns

    def test_export_sqlite_preserves_data(self, tmp_path: Path) -> None:
        """All entry field values are preserved in SQLite."""
        from agentguard.audit.export import export_sqlite

        entries = _make_entries()
        out = tmp_path / "export.db"
        export_sqlite(entries, out)

        conn = sqlite3.connect(str(out))
        conn.row_factory = sqlite3.Row
        cursor = conn.execute("SELECT * FROM audit_entries ORDER BY rowid")
        rows = cursor.fetchall()
        conn.close()

        assert rows[0]["action"] == "shell_command"
        assert rows[0]["actor"] == "agent-1"
        assert rows[0]["result"] == "allowed"
        assert rows[1]["action"] == "file_write"
        assert rows[1]["result"] == "denied"

    def test_export_sqlite_metadata_as_json(self, tmp_path: Path) -> None:
        """Metadata is stored as a JSON string in SQLite."""
        from agentguard.audit.export import export_sqlite

        entries = _make_entries()
        out = tmp_path / "export.db"
        export_sqlite(entries, out)

        conn = sqlite3.connect(str(out))
        cursor = conn.execute("SELECT metadata FROM audit_entries ORDER BY rowid")
        rows = cursor.fetchall()
        conn.close()

        # First entry has metadata
        meta = json.loads(rows[0][0])
        assert meta == {"policy": "default"}
        # Second entry has NULL metadata
        assert rows[1][0] is None

    def test_export_sqlite_empty_list(self, tmp_path: Path) -> None:
        """Exporting an empty list creates a database with zero rows."""
        from agentguard.audit.export import export_sqlite

        out = tmp_path / "empty.db"
        export_sqlite([], out)

        conn = sqlite3.connect(str(out))
        cursor = conn.execute("SELECT count(*) FROM audit_entries")
        count = cursor.fetchone()[0]
        conn.close()
        assert count == 0

    def test_export_sqlite_returns_entry_count(self, tmp_path: Path) -> None:
        """export_sqlite returns the number of rows written."""
        from agentguard.audit.export import export_sqlite

        entries = _make_entries()
        out = tmp_path / "export.db"
        count = export_sqlite(entries, out)
        assert count == 2

    def test_export_sqlite_overwrites_existing(self, tmp_path: Path) -> None:
        """Exporting to an existing file overwrites it cleanly."""
        from agentguard.audit.export import export_sqlite

        out = tmp_path / "export.db"
        # Write once
        export_sqlite(_make_entries(), out)
        # Write again with empty
        export_sqlite([], out)

        conn = sqlite3.connect(str(out))
        cursor = conn.execute("SELECT count(*) FROM audit_entries")
        count = cursor.fetchone()[0]
        conn.close()
        assert count == 0


# ── CLI integration ───────────────────────────────────────────────


class TestCLIExport:
    """Tests for ``agentguard audit export`` CLI subcommand."""

    def _write_audit_log(self, directory: Path) -> None:
        """Write a sample audit JSONL file to the directory."""
        log = AuditLog("test-session")
        log.record(
            action="shell_command",
            actor="agent",
            target="ls",
            result="allowed",
        )
        log.record(
            action="file_write",
            actor="agent",
            target="/tmp/f.txt",
            result="denied",
            metadata={"reason": "policy"},
        )
        log.save(directory / "test-session.jsonl")

    def test_export_json_via_cli(self, tmp_path: Path) -> None:
        """CLI exports to JSON format."""
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        self._write_audit_log(audit_dir)

        out = tmp_path / "out.json"
        result = _run_cli(
            "audit",
            "export",
            str(audit_dir),
            "--output",
            str(out),
            "--format",
            "json",
        )
        assert result == 0
        data = json.loads(out.read_text(encoding="utf-8"))
        assert len(data) == 2

    def test_export_csv_via_cli(self, tmp_path: Path) -> None:
        """CLI exports to CSV format."""
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        self._write_audit_log(audit_dir)

        out = tmp_path / "out.csv"
        result = _run_cli(
            "audit",
            "export",
            str(audit_dir),
            "--output",
            str(out),
            "--format",
            "csv",
        )
        assert result == 0
        with out.open(encoding="utf-8") as f:
            reader = csv.reader(f)
            rows = list(reader)
        assert len(rows) == 3  # header + 2 entries

    def test_export_sqlite_via_cli(self, tmp_path: Path) -> None:
        """CLI exports to SQLite format."""
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        self._write_audit_log(audit_dir)

        out = tmp_path / "out.db"
        result = _run_cli(
            "audit",
            "export",
            str(audit_dir),
            "--output",
            str(out),
            "--format",
            "sqlite",
        )
        assert result == 0
        conn = sqlite3.connect(str(out))
        cursor = conn.execute("SELECT count(*) FROM audit_entries")
        count = cursor.fetchone()[0]
        conn.close()
        assert count == 2

    def test_export_requires_output_flag(self, tmp_path: Path) -> None:
        """CLI exits with error when --output is missing."""
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()

        result = _run_cli("audit", "export", str(audit_dir), "--format", "json")
        assert result != 0

    def test_export_with_action_filter(self, tmp_path: Path) -> None:
        """CLI --action filter limits exported entries."""
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        self._write_audit_log(audit_dir)

        out = tmp_path / "filtered.json"
        result = _run_cli(
            "audit",
            "export",
            str(audit_dir),
            "--output",
            str(out),
            "--format",
            "json",
            "--action",
            "shell_command",
        )
        assert result == 0
        data = json.loads(out.read_text(encoding="utf-8"))
        assert len(data) == 1
        assert data[0]["action"] == "shell_command"

    def test_export_with_result_filter(self, tmp_path: Path) -> None:
        """CLI --result filter limits exported entries."""
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        self._write_audit_log(audit_dir)

        out = tmp_path / "filtered.json"
        result = _run_cli(
            "audit",
            "export",
            str(audit_dir),
            "--output",
            str(out),
            "--format",
            "json",
            "--result",
            "denied",
        )
        assert result == 0
        data = json.loads(out.read_text(encoding="utf-8"))
        assert len(data) == 1
        assert data[0]["result"] == "denied"

    def test_export_empty_directory(self, tmp_path: Path) -> None:
        """CLI handles empty audit directory gracefully."""
        audit_dir = tmp_path / "empty"
        audit_dir.mkdir()

        out = tmp_path / "out.json"
        result = _run_cli(
            "audit",
            "export",
            str(audit_dir),
            "--output",
            str(out),
            "--format",
            "json",
        )
        assert result == 0
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data == []

    def test_export_default_format_is_json(self, tmp_path: Path) -> None:
        """When --format is omitted, default to JSON."""
        audit_dir = tmp_path / "audit"
        audit_dir.mkdir()
        self._write_audit_log(audit_dir)

        out = tmp_path / "out.json"
        result = _run_cli(
            "audit",
            "export",
            str(audit_dir),
            "--output",
            str(out),
        )
        assert result == 0
        data = json.loads(out.read_text(encoding="utf-8"))
        assert len(data) == 2


# ── Helpers ───────────────────────────────────────────────────────


def _run_cli(*args: str) -> int:
    """Run the CLI main function and return the exit code."""
    import sys

    from agentguard.cli import main

    argv_backup = sys.argv
    sys.argv = ["agentguard", *args]
    try:
        main()
        return 0
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 1
    finally:
        sys.argv = argv_backup
