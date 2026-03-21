"""Audit log export to CSV, JSON, and SQLite formats.

All functions use only the Python standard library (``csv``,
``json``, ``sqlite3``) — no external dependencies.

Each exporter takes a list of :class:`AuditEntry` objects and a
destination :class:`~pathlib.Path`, writes the data, and returns
the number of entries written.
"""

from __future__ import annotations

import csv
import json
import sqlite3
from pathlib import Path
from typing import TYPE_CHECKING, Sequence

if TYPE_CHECKING:
    from agentguard.audit.models import AuditEntry

#: Canonical column order used by the CSV exporter and as a reference
#: for the SQLite schema.  Matches :meth:`AuditEntry.to_dict` keys
#: plus ``metadata`` (always present in CSV, even when ``None``).
CSV_COLUMNS: tuple[str, ...] = (
    "action",
    "actor",
    "target",
    "result",
    "timestamp",
    "previous_hash",
    "entry_hash",
    "metadata",
)


def export_json(entries: Sequence[AuditEntry], path: Path) -> int:
    """Export audit entries as a pretty-printed JSON array.

    Args:
        entries: Audit entries to export.
        path: Destination file path (will be overwritten).

    Returns:
        Number of entries written.
    """
    data = [e.to_dict() for e in entries]
    path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return len(data)


def export_csv(entries: Sequence[AuditEntry], path: Path) -> int:
    """Export audit entries as a CSV file.

    The header row matches :data:`CSV_COLUMNS`.  Metadata dicts are
    serialised as compact JSON strings; ``None`` metadata becomes an
    empty string.

    Args:
        entries: Audit entries to export.
        path: Destination file path (will be overwritten).

    Returns:
        Number of data rows written (excludes the header).
    """
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        count = 0
        for entry in entries:
            row = entry.to_dict()
            # Ensure metadata column is always present
            meta = row.get("metadata")
            row["metadata"] = (
                json.dumps(meta, ensure_ascii=False) if meta is not None else ""
            )
            writer.writerow(row)
            count += 1
    return count


_SQLITE_SCHEMA = """\
CREATE TABLE IF NOT EXISTS audit_entries (
    action        TEXT NOT NULL,
    actor         TEXT NOT NULL,
    target        TEXT NOT NULL,
    result        TEXT NOT NULL,
    timestamp     TEXT NOT NULL,
    previous_hash TEXT,
    entry_hash    TEXT NOT NULL,
    metadata      TEXT
)
"""

_SQLITE_INSERT = """\
INSERT INTO audit_entries
    (action, actor, target, result, timestamp, previous_hash, entry_hash, metadata)
VALUES
    (?, ?, ?, ?, ?, ?, ?, ?)
"""


def export_sqlite(entries: Sequence[AuditEntry], path: Path) -> int:
    """Export audit entries into a SQLite database.

    Creates (or overwrites) a database at *path* with a single table
    ``audit_entries``.  Metadata dicts are serialised as JSON text;
    ``None`` metadata is stored as SQL ``NULL``.

    Args:
        entries: Audit entries to export.
        path: Destination file path (will be overwritten).

    Returns:
        Number of rows written.
    """
    # Remove existing file to get a clean database
    if path.exists():
        path.unlink()

    conn = sqlite3.connect(str(path))
    try:
        conn.execute(_SQLITE_SCHEMA)
        count = 0
        for entry in entries:
            d = entry.to_dict()
            meta = d.get("metadata")
            meta_str = (
                json.dumps(meta, ensure_ascii=False) if meta is not None else None
            )
            conn.execute(
                _SQLITE_INSERT,
                (
                    d["action"],
                    d["actor"],
                    d["target"],
                    d["result"],
                    d["timestamp"],
                    d["previous_hash"],
                    d["entry_hash"],
                    meta_str,
                ),
            )
            count += 1
        conn.commit()
    finally:
        conn.close()
    return count
